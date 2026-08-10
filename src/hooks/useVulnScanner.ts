import { useCallback, useRef } from "react";
import type { Dispatch } from "react";
import type { AppAction, AppState } from "./usePEFile";
import type { DisasmFunction, } from "../disasm/types";
import { disasmWorker } from "../workers/disasmClient";
import { streamChat } from "../llm/client";
import { parseScanResponse, toScanFinding } from "../llm/responseSchema";
import { hasApiKey, loadSettings } from "../llm/settings";
import { SYSTEM_PROMPT_VULN_SCAN } from "../llm/prompt";
import { getDisplayName } from "./usePEFile";
import type { PEFile } from "../pe/types";
import { analyzeStackFrame } from "../disasm/stack";
import { inferSignature } from "../disasm/signatures";

async function decompileFunc(
  fn: DisasmFunction,
  pe: PEFile,
  functions: DisasmFunction[],
  renames: Record<number, string>,
): Promise<string | null> {
  const textSection = pe.sections.find(
    s => s.name === ".text" || (s.characteristics & 0x20000000) !== 0,
  );
  if (!textSection) return null;

  const baseAddr = pe.optionalHeader.imageBase + textSection.virtualAddress;
  const offset = fn.address - baseAddr;
  if (offset < 0 || offset + fn.size > textSection.sizeOfRawData) return null;

  try {
    const sectionBytes = new Uint8Array(pe.buffer, textSection.pointerToRawData, textSection.sizeOfRawData);
    const funcBytes = sectionBytes.subarray(offset, offset + fn.size);
    const instructions = await disasmWorker.disassemble(funcBytes, fn.address, pe.is64);
    if (instructions.length === 0) return null;

    const xrefMap = await disasmWorker.buildTypedXrefMap(instructions);
    const sf = analyzeStackFrame(fn, instructions, pe.is64);
    const sig = inferSignature(fn, instructions, pe.is64);
    const funcEntries: [number, { name: string; address: number }][] =
      functions.map(f => [f.address, { name: getDisplayName(f, renames), address: f.address }]);
    const result = await disasmWorker.decompileFunction(
      fn, instructions, xrefMap, sf, sig, pe.is64,
      new Map(funcEntries), pe.runtimeFunctions,
    );
    return result.code;
  } catch {
    return null;
  }
}

const DANGEROUS_APIS = new Set([
  "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
  "WriteProcessMemory", "ReadProcessMemory", "CreateRemoteThread",
  "NtCreateThread", "NtWriteVirtualMemory", "NtAllocateVirtualMemory",
  "CreateProcess", "CreateProcessA", "CreateProcessW",
  "ShellExecute", "ShellExecuteA", "ShellExecuteW", "WinExec",
  "OpenProcess", "NtOpenProcess", "SetWindowsHookEx", "SetWindowsHookExA", "SetWindowsHookExW",
  "LoadLibrary", "LoadLibraryA", "LoadLibraryW",
  "GetProcAddress", "NtMapViewOfSection", "MapViewOfFile",
  "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt", "BCryptDecrypt",
]);

export function useVulnScanner(state: AppState, dispatch: Dispatch<AppAction>) {
  const abortRef = useRef<AbortController | null>(null);
  const scanningRef = useRef(false);

  /**
   * Replace the in-flight request, aborting whatever it superseded. Overwriting
   * `abortRef` without this left the previous request streaming into nothing.
   */
  const beginRequest = useCallback(() => {
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;
    return controller;
  }, []);

  /**
   * Scan one function.
   *
   * `bulkSignal` is passed only when this runs inside `scanSuspicious`. Its
   * presence means two things: the call joins the bulk scan's lifetime instead of
   * replacing `abortRef` (which would cancel the very loop that invoked it), and
   * the surrounding loop owns the AI_SCAN_START/COMPLETE bracket so this call must
   * not open one of its own.
   */
  const scanFunction = useCallback(async (
    fn: DisasmFunction,
    bulkSignal?: AbortSignal,
  ): Promise<void> => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const pe = state.peFile;
    if (!pe) return;

    const standalone = bulkSignal === undefined;
    const signal = bulkSignal ?? beginRequest().signal;
    if (standalone) dispatch({ type: "AI_SCAN_START", total: 1 });

    const code = await decompileFunc(fn, pe, state.functions, state.renames);
    if (signal.aborted) return;
    if (!code) {
      // Not a model failure, but still not a clean result — the user must not
      // read "we could not decompile this" as "no vulnerabilities here".
      dispatch({ type: "AI_SCAN_FAILED", error: `${getDisplayName(fn, state.renames)}: could not be decompiled` });
      if (standalone) dispatch({ type: "AI_SCAN_COMPLETE" });
      return;
    }

    const funcName = getDisplayName(fn, state.renames);
    const prompt = `Function: ${funcName} at 0x${fn.address.toString(16).toUpperCase()}\n\n${code}`;
    const config = loadSettings();

    let result: string;
    try {
      result = await new Promise<string>((resolve, reject) => {
        let acc = "";
        streamChat(
          [{ role: "user", content: prompt }],
          SYSTEM_PROMPT_VULN_SCAN,
          config,
          signal,
          {
            onToken: (accumulated) => { acc = accumulated; },
            onDone: () => resolve(acc),
            onError: (err) => reject(new Error(err)),
          },
          "vuln-scan",
        );
      });
    } catch (err) {
      if (signal.aborted) return;
      dispatch({
        type: "AI_SCAN_FAILED",
        error: `${funcName}: ${err instanceof Error ? err.message : "scan request failed"}`,
      });
      if (standalone) dispatch({ type: "AI_SCAN_COMPLETE" });
      return;
    }

    if (signal.aborted) return;

    const parsed = parseScanResponse(result);
    if (!parsed.ok) {
      dispatch({ type: "AI_SCAN_FAILED", error: `${funcName}: ${parsed.error}` });
      if (standalone) dispatch({ type: "AI_SCAN_COMPLETE" });
      return;
    }

    // Dispatched even when the model found nothing, so a clean function counts as
    // scanned rather than looking like a function that was never reached.
    const findings = parsed.value.map(item => toScanFinding(item, fn.address, funcName));
    dispatch({ type: "AI_SCAN_ADD", findings });
    if (standalone) dispatch({ type: "AI_SCAN_COMPLETE" });
  }, [state.peFile, state.functions, state.renames, dispatch, beginRequest]);

  const scanSuspicious = useCallback(async () => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const pe = state.peFile;
    if (!pe || scanningRef.current) return;

    scanningRef.current = true;
    const controller = beginRequest();

    // Build set of functions calling dangerous APIs
    const suspiciousFuncs = new Set<number>();

    // From anomaly-flagged functions (if they reference addresses)
    // From import xrefs: find functions that reference dangerous APIs
    if (state.importXrefs) {
      for (const imp of pe.imports) {
        for (let i = 0; i < imp.functions.length; i++) {
          const funcName = imp.functions[i].replace(/[AW]$/, "");
          if (DANGEROUS_APIS.has(funcName) || DANGEROUS_APIS.has(imp.functions[i])) {
            const iatAddr = imp.iatAddresses[i];
            const refs = state.importXrefs.get(iatAddr);
            if (refs) {
              for (const refAddr of refs) {
                // Find containing function
                for (const fn of state.functions) {
                  if (refAddr >= fn.address && refAddr < fn.address + fn.size) {
                    suspiciousFuncs.add(fn.address);
                    break;
                  }
                }
              }
            }
          }
        }
      }
    }

    const targets = state.functions.filter(f => suspiciousFuncs.has(f.address)).slice(0, 20);

    // Opens the run: clears findings and any error left over from a previous scan.
    dispatch({ type: "AI_SCAN_START", total: targets.length });

    try {
      for (const fn of targets) {
        if (controller.signal.aborted) break;
        // Share this scan's signal so one cancel stops the whole run, and so the
        // per-function call does not abort the loop by replacing abortRef.
        await scanFunction(fn, controller.signal);
      }
    } finally {
      scanningRef.current = false;
      // A cancelled run stays in "scanning" rather than claiming a result it
      // never produced; the next AI_SCAN_START resets it.
      if (!controller.signal.aborted) dispatch({ type: "AI_SCAN_COMPLETE" });
    }
  }, [state.peFile, state.functions, state.importXrefs, dispatch, scanFunction, beginRequest]);

  const cancelScan = useCallback(() => {
    abortRef.current?.abort();
    abortRef.current = null;
    scanningRef.current = false;
  }, []);

  return { scanFunction, scanSuspicious, cancelScan };
}
