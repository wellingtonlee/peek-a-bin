import { useCallback, useRef } from "react";
import type { Dispatch } from "react";
import type { AppAction, AppState } from "./usePEFile";
import type { BatchRenameResult } from "../llm/types";
import type { DisasmFunction, Instruction } from "../disasm/types";
import { disasmWorker } from "../workers/disasmClient";
import { streamChat } from "../llm/client";
import { hasApiKey, loadSettings } from "../llm/settings";
import { SYSTEM_PROMPT_BATCH_RENAME } from "../llm/prompt";
import { getDisplayName } from "./usePEFile";
import type { PEFile } from "../pe/types";
import { analyzeStackFrame } from "../disasm/stack";
import { inferSignature } from "../disasm/signatures";

const BATCH_SIZE = 6;
const MAX_LINES_PER_FUNC = 100;

async function decompileOne(
  fn: DisasmFunction,
  pe: PEFile,
  instructions: Instruction[],
  functions: DisasmFunction[],
  renames: Record<number, string>,
): Promise<string | null> {
  try {
    const xrefMap = await disasmWorker.buildTypedXrefMap(instructions);
    const sf = analyzeStackFrame(fn, instructions, pe.is64);
    const sig = inferSignature(fn, instructions, pe.is64);
    const funcEntries: [number, { name: string; address: number }][] =
      functions.map(f => [f.address, { name: getDisplayName(f, renames), address: f.address }]);
    const result = await disasmWorker.decompileFunction(
      fn, instructions, xrefMap, sf, sig, pe.is64,
      new Map(funcEntries),
      pe.runtimeFunctions,
    );
    return result.code;
  } catch {
    return null;
  }
}

export function useBatchRename(state: AppState, dispatch: Dispatch<AppAction>) {
  const abortRef = useRef<AbortController | null>(null);

  const startBatchRename = useCallback(async () => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const pe = state.peFile;
    if (!pe) return;

    // Find text section for disassembly
    const textSection = pe.sections.find(
      s => s.name === ".text" || (s.characteristics & 0x20000000) !== 0,
    );
    if (!textSection) return;

    const bufferEl = document.querySelector("[data-pe-buffer]");
    // We don't have direct buffer access; work through worker

    // Collect unnamed functions
    const unnamed = state.functions.filter(fn => {
      if (state.renames[fn.address]) return false;
      if (fn.name.startsWith("thunk_")) return false;
      if (fn.size <= 16) return false;
      return true;
    });

    if (unnamed.length === 0) return;

    dispatch({ type: "BATCH_RENAME_START", total: unnamed.length });

    const controller = new AbortController();
    abortRef.current = controller;

    try {
      // Phase 1: Disassemble + decompile each function
      const decompiled: { fn: DisasmFunction; code: string }[] = [];
      const baseAddr = pe.optionalHeader.imageBase + textSection.virtualAddress;

      for (let i = 0; i < unnamed.length; i++) {
        if (controller.signal.aborted) return;
        dispatch({ type: "BATCH_RENAME_PROGRESS", done: i });

        const fn = unnamed[i];
        const offset = fn.address - baseAddr;
        if (offset < 0 || offset + fn.size > textSection.sizeOfRawData) continue;

        try {
          // Disassemble this function's bytes
          const sectionBytes = new Uint8Array(
            pe.buffer, textSection.pointerToRawData, textSection.sizeOfRawData,
          );
          const funcBytes = sectionBytes.subarray(offset, offset + fn.size);
          const instructions = await disasmWorker.disassemble(funcBytes, fn.address, pe.is64);
          if (instructions.length === 0) continue;

          const code = await decompileOne(fn, pe, instructions, state.functions, state.renames);
          if (code) {
            const lines = code.split("\n").slice(0, MAX_LINES_PER_FUNC);
            decompiled.push({ fn, code: lines.join("\n") });
          }
        } catch { /* skip */ }
      }

      if (decompiled.length === 0 || controller.signal.aborted) {
        dispatch({ type: "BATCH_RENAME_ERROR", error: "No functions could be decompiled" });
        return;
      }

      // Phase 2: Send in batches to LLM
      const allResults: BatchRenameResult[] = [];
      const config = loadSettings();

      // Update status to running
      dispatch({ type: "BATCH_RENAME_PROGRESS", done: 0 });

      for (let b = 0; b < decompiled.length; b += BATCH_SIZE) {
        if (controller.signal.aborted) return;
        const batch = decompiled.slice(b, b + BATCH_SIZE);

        const prompt = batch.map(({ fn, code }) => {
          const name = getDisplayName(fn, state.renames);
          return `=== Function at 0x${fn.address.toString(16).toUpperCase()} (${name}) ===\n${code}`;
        }).join("\n\n");

        const result = await new Promise<string>((resolve, reject) => {
          let acc = "";
          streamChat(
            [{ role: "user", content: prompt }],
            SYSTEM_PROMPT_BATCH_RENAME,
            config,
            controller.signal,
            {
              onToken: (accumulated) => { acc = accumulated; },
              onDone: () => resolve(acc),
              onError: (err) => reject(new Error(err)),
            },
          );
        });

        // Parse JSON from response
        try {
          const jsonStr = result.replace(/```json?\n?/g, "").replace(/```/g, "").trim();
          const parsed = JSON.parse(jsonStr);
          if (Array.isArray(parsed)) {
            for (const item of parsed) {
              const addr = typeof item.address === "string"
                ? parseInt(item.address.replace(/^0x/i, ""), 16)
                : item.address;
              if (isNaN(addr) || !item.suggestedName) continue;
              const batchFn = batch.find(b => b.fn.address === addr);
              allResults.push({
                address: addr,
                currentName: batchFn
                  ? getDisplayName(batchFn.fn, state.renames)
                  : `sub_${addr.toString(16)}`,
                suggestedName: item.suggestedName,
                confidence: typeof item.confidence === "number" ? item.confidence : 0.5,
                reasoning: item.reasoning ?? "",
                accepted: null,
              });
            }
          }
        } catch { /* skip parse errors */ }

        dispatch({ type: "BATCH_RENAME_PROGRESS", done: b + batch.length });
      }

      if (allResults.length === 0) {
        dispatch({ type: "BATCH_RENAME_ERROR", error: "No rename suggestions could be parsed" });
      } else {
        dispatch({ type: "BATCH_RENAME_DONE", results: allResults });
      }
    } catch (err) {
      if (!controller.signal.aborted) {
        dispatch({ type: "BATCH_RENAME_ERROR", error: err instanceof Error ? err.message : "Batch rename failed" });
      }
    }
  }, [state.peFile, state.functions, state.renames, dispatch]);

  const cancelBatchRename = useCallback(() => {
    abortRef.current?.abort();
    dispatch({ type: "BATCH_RENAME_DISMISS" });
  }, [dispatch]);

  return { startBatchRename, cancelBatchRename };
}
