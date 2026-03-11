import { useCallback, useRef } from "react";
import type { Dispatch } from "react";
import type { AppAction, AppState } from "./usePEFile";
import type { AIScanFinding } from "../llm/types";
import type { DisasmFunction, Instruction } from "../disasm/types";
import { disasmWorker } from "../workers/disasmClient";
import { streamChat } from "../llm/client";
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

  const scanFunction = useCallback(async (fn: DisasmFunction) => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const pe = state.peFile;
    if (!pe) return;

    const controller = new AbortController();
    abortRef.current = controller;

    const code = await decompileFunc(fn, pe, state.functions, state.renames);
    if (!code) return;

    const funcName = getDisplayName(fn, state.renames);
    const prompt = `Function: ${funcName} at 0x${fn.address.toString(16).toUpperCase()}\n\n${code}`;
    const config = loadSettings();

    const result = await new Promise<string>((resolve, reject) => {
      let acc = "";
      streamChat(
        [{ role: "user", content: prompt }],
        SYSTEM_PROMPT_VULN_SCAN,
        config,
        controller.signal,
        {
          onToken: (accumulated) => { acc = accumulated; },
          onDone: () => resolve(acc),
          onError: (err) => reject(new Error(err)),
        },
      );
    });

    try {
      const jsonStr = result.replace(/```json?\n?/g, "").replace(/```/g, "").trim();
      const parsed = JSON.parse(jsonStr);
      if (Array.isArray(parsed)) {
        const findings: AIScanFinding[] = parsed.map(item => ({
          severity: item.severity ?? "info",
          title: item.title ?? "Unknown",
          description: item.description ?? "",
          functionAddress: fn.address,
          functionName: funcName,
          remediation: item.remediation ?? "",
          source: "ai-scan" as const,
        }));
        if (findings.length > 0) {
          dispatch({ type: "AI_SCAN_ADD", findings });
        }
      }
    } catch { /* skip parse error */ }
  }, [state.peFile, state.functions, state.renames, dispatch]);

  const scanSuspicious = useCallback(async () => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const pe = state.peFile;
    if (!pe || scanningRef.current) return;

    scanningRef.current = true;
    const controller = new AbortController();
    abortRef.current = controller;

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

    dispatch({ type: "AI_SCAN_CLEAR" });

    const targets = state.functions.filter(f => suspiciousFuncs.has(f.address));
    for (const fn of targets.slice(0, 20)) {
      if (controller.signal.aborted) break;
      await scanFunction(fn);
    }

    scanningRef.current = false;
  }, [state.peFile, state.functions, state.importXrefs, state.renames, dispatch, scanFunction]);

  const cancelScan = useCallback(() => {
    abortRef.current?.abort();
    scanningRef.current = false;
  }, []);

  return { scanFunction, scanSuspicious, cancelScan };
}
