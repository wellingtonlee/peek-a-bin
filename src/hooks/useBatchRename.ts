import { useCallback, useRef } from "react";
import type { Dispatch } from "react";
import type { AppAction, AppState } from "./usePEFile";
import type { BatchRenameResult } from "../llm/types";
import type { DisasmFunction } from "../disasm/types";
import { streamChat } from "../llm/client";
import { parseBatchRenameResponse, toBatchRenameResult } from "../llm/responseSchema";
import { hasApiKey, loadSettings } from "../llm/settings";
import { SYSTEM_PROMPT_BATCH_RENAME } from "../llm/prompt";
import { decompileForLLM } from "../llm/decompileForLLM";
import { getDisplayName } from "./usePEFile";
import { findCodeSection } from "../pe/sections";

const BATCH_SIZE = 6;
const MAX_LINES_PER_FUNC = 100;

export function useBatchRename(state: AppState, dispatch: Dispatch<AppAction>) {
  const abortRef = useRef<AbortController | null>(null);

  const startBatchRename = useCallback(async () => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const pe = state.peFile;
    if (!pe) return;

    // Located here rather than left to decompileForLLM so a binary with no code
    // section bails out before BATCH_RENAME_START opens a modal it cannot fill.
    const textSection = findCodeSection(pe.sections);
    if (!textSection) return;

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

    // Abort any previous run before taking over the ref — overwriting it left the
    // earlier request streaming with nobody listening and nobody able to cancel it.
    abortRef.current?.abort();
    const controller = new AbortController();
    abortRef.current = controller;

    try {
      // Phase 1: Disassemble + decompile each function
      const decompiled: { fn: DisasmFunction; code: string }[] = [];

      for (let i = 0; i < unnamed.length; i++) {
        if (controller.signal.aborted) return;
        dispatch({ type: "BATCH_RENAME_PROGRESS", done: i });

        const fn = unnamed[i];
        const code = await decompileForLLM(fn, pe, state.functions, state.renames, {
          section: textSection,
          maxLines: MAX_LINES_PER_FUNC,
        });
        if (code) decompiled.push({ fn, code });
      }

      if (decompiled.length === 0 || controller.signal.aborted) {
        dispatch({ type: "BATCH_RENAME_ERROR", error: "No functions could be decompiled" });
        return;
      }

      // Phase 2: Send in batches to LLM
      const allResults: BatchRenameResult[] = [];
      const parseFailures: string[] = [];
      const config = loadSettings();

      // Leave the decompile phase — this is what makes the modal switch from
      // "Decompiling functions…" to "Generating names…".
      dispatch({ type: "BATCH_RENAME_PROGRESS", done: 0, phase: "running" });

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
            "batch-rename",
          );
        });

        const parsed = parseBatchRenameResponse(result);
        if (parsed.ok) {
          for (const item of parsed.value) {
            const batchFn = batch.find(entry => entry.fn.address === item.address);
            const currentName = batchFn
              ? getDisplayName(batchFn.fn, state.renames)
              : `sub_${item.address.toString(16)}`;
            allResults.push(toBatchRenameResult(item, currentName));
          }
        } else {
          // A malformed batch used to vanish into an empty catch, so a run that
          // parsed nothing reported the same "no suggestions" as a clean run.
          parseFailures.push(parsed.error);
        }

        dispatch({ type: "BATCH_RENAME_PROGRESS", done: b + batch.length });
      }

      if (allResults.length === 0) {
        dispatch({
          type: "BATCH_RENAME_ERROR",
          error: parseFailures.length > 0
            ? `No rename suggestions could be parsed — ${parseFailures[0]}`
            : "No rename suggestions could be parsed",
        });
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
