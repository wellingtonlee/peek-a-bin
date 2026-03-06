import { useReducer, useRef, useCallback, useMemo, useEffect } from "react";
import type { DecompileTab, DecompileTabsState, HighLevelEngine } from "../decompile/types";
import { tabsReducer, initialTabsState } from "../decompile/types";
import { disasmWorker } from "../workers/disasmClient";
import { GhidraClient } from "../decompile/ghidraClient";
import { decompileWithWasm } from "../decompile/wasmDecompiler";
import { hasApiKey, loadSettings, loadDecompileServer } from "../llm/settings";
import { streamEnhance } from "../llm/client";
import { SYSTEM_PROMPT_EXPLAIN } from "../llm/prompt";
import { analyzeStackFrame } from "../disasm/stack";
import { inferSignature } from "../disasm/signatures";
import { getDisplayName } from "./usePEFile";
import type { DisasmFunction, Instruction, Xref } from "../disasm/types";
import type { PEFile } from "../pe/types";

interface UseDecompileTabsArgs {
  currentFunc: DisasmFunction | null;
  pe: PEFile | null;
  instructions: Instruction[];
  xrefMap: Map<number, Xref[]>;
  iatMap: Map<number, { lib: string; func: string }>;
  functions: DisasmFunction[];
  renames: Record<number, string>;
  buildFunctionAsm: () => string;
}

export interface UseDecompileTabsResult {
  tabsState: DecompileTabsState;
  setActiveTab: (tab: DecompileTab) => void;
  triggerTab: (tab: DecompileTab) => void;
  triggerAI: (mode: "enhance" | "explain") => void;
  cancelAI: () => void;
  highlightLines: Set<number>;
  handleLineClick: (lineNum: number) => void;
  resetForNewFunc: () => void;
  activeCode: string;
  activeLoading: boolean;
  activeError: string;
  activeLineMap: Map<number, number>;
  syncDisabled: boolean;
}

export function useDecompileTabs({
  currentFunc,
  pe,
  instructions,
  xrefMap,
  iatMap,
  functions,
  renames,
  buildFunctionAsm,
}: UseDecompileTabsArgs): UseDecompileTabsResult {
  const [tabsState, dispatch] = useReducer(tabsReducer, undefined, initialTabsState);

  // Per-tab, per-function caches: Map<funcAddr, {code, lineMap}>
  const lowCache = useRef(new Map<number, { code: string; lineMap: Map<number, number> }>());
  const highCache = useRef(new Map<number, { code: string; lineMap: Map<number, number>; engine?: HighLevelEngine }>());
  const aiCache = useRef(new Map<number, { code: string; lineMap: Map<number, number> }>());

  const abortRef = useRef<AbortController | null>(null);
  const ghidraProjectRef = useRef<string | null>(null);

  // Clear caches when PE changes
  const prevPeRef = useRef<PEFile | null>(null);
  useEffect(() => {
    if (pe !== prevPeRef.current) {
      prevPeRef.current = pe;
      lowCache.current.clear();
      highCache.current.clear();
      aiCache.current.clear();
      ghidraProjectRef.current = null;
      dispatch({ type: "RESET_FUNC" });
    }
  }, [pe]);

  const decompileLow = useCallback(async () => {
    if (!currentFunc || !pe || instructions.length === 0) return;
    const addr = currentFunc.address;

    const cached = lowCache.current.get(addr);
    if (cached) {
      dispatch({ type: "LOAD_OK", tab: "low", code: cached.code, lineMap: cached.lineMap });
      return;
    }

    dispatch({ type: "BEGIN_LOAD", tab: "low" });
    try {
      const sf = analyzeStackFrame(currentFunc, instructions, pe.is64);
      const sig = inferSignature(currentFunc, instructions, pe.is64);
      const funcEntries: [number, { name: string; address: number }][] = [];
      for (const fn of functions) {
        funcEntries.push([fn.address, { name: getDisplayName(fn, renames), address: fn.address }]);
      }
      const result = await disasmWorker.decompileFunction(
        currentFunc, instructions, xrefMap, sf, sig, pe.is64,
        iatMap, pe.strings ?? new Map(), new Map(funcEntries),
      );
      lowCache.current.set(addr, result);
      dispatch({ type: "LOAD_OK", tab: "low", code: result.code, lineMap: result.lineMap });
    } catch (err: any) {
      dispatch({ type: "LOAD_ERR", tab: "low", error: err?.message ?? String(err) });
    }
  }, [currentFunc, pe, instructions, xrefMap, iatMap, functions, renames]);

  const decompileHigh = useCallback(async () => {
    if (!currentFunc || !pe) return;
    const addr = currentFunc.address;

    const cached = highCache.current.get(addr);
    if (cached) {
      dispatch({ type: "LOAD_OK", tab: "high", code: cached.code, lineMap: cached.lineMap, engine: cached.engine });
      return;
    }

    const serverSettings = loadDecompileServer();
    dispatch({ type: "BEGIN_LOAD", tab: "high" });

    if (serverSettings.enabled) {
      try {
        const client = new GhidraClient(serverSettings.ghidraUrl, serverSettings.apiKey || undefined);

        // Upload binary if not already uploaded
        if (!ghidraProjectRef.current) {
          const uploadResult = await client.uploadBinary(new Uint8Array(pe.buffer));
          ghidraProjectRef.current = uploadResult.projectId;
        }

        const result = await client.decompileFunction(ghidraProjectRef.current, addr, pe.is64);
        const lineMap = new Map(result.lineMap);
        highCache.current.set(addr, { code: result.code, lineMap, engine: "ghidra" });
        dispatch({ type: "LOAD_OK", tab: "high", code: result.code, lineMap, engine: "ghidra" });
      } catch (err: any) {
        dispatch({ type: "LOAD_ERR", tab: "high", error: `Ghidra: ${err?.message ?? String(err)}` });
      }
    } else {
      // Fallback to WASM decompiler (stub)
      try {
        const result = await decompileWithWasm(new Uint8Array(pe.buffer), addr, pe.is64);
        const lineMap = new Map(result.lineMap);
        const engine = result.engine as HighLevelEngine;
        highCache.current.set(addr, { code: result.code, lineMap, engine });
        dispatch({ type: "LOAD_OK", tab: "high", code: result.code, lineMap, engine });
      } catch (err: any) {
        dispatch({ type: "LOAD_ERR", tab: "high", error: err?.message ?? String(err) });
      }
    }
  }, [currentFunc, pe]);

  const triggerAI = useCallback((mode: "enhance" | "explain") => {
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    // Use best available source: high-level if ready, else low-level
    const source = tabsState.high.ready ? tabsState.high.code : tabsState.low.code;
    if (!source) return;

    abortRef.current?.abort();
    dispatch({ type: "AI_MODE", mode });
    dispatch({ type: "SET_TAB", tab: "ai" });
    dispatch({ type: "BEGIN_LOAD", tab: "ai" });

    const config = loadSettings();
    const controller = new AbortController();
    abortRef.current = controller;

    const input = mode === "enhance" && config.enhanceSource === "assembly"
      ? buildFunctionAsm()
      : source;

    const systemPrompt = mode === "explain" ? SYSTEM_PROMPT_EXPLAIN : undefined;

    streamEnhance(input, config, controller.signal, {
      onToken: (accumulated) => {
        if (mode === "explain") {
          const commented = accumulated.split("\n").map((l) => `// ${l}`).join("\n");
          dispatch({ type: "AI_TOKEN", accumulated: commented + "\n\n" + source });
        } else {
          dispatch({ type: "AI_TOKEN", accumulated });
        }
      },
      onDone: () => dispatch({ type: "AI_DONE" }),
      onError: (error) => {
        dispatch({ type: "LOAD_ERR", tab: "ai", error });
      },
    }, systemPrompt);
  }, [tabsState.high.ready, tabsState.high.code, tabsState.low.code, buildFunctionAsm]);

  const cancelAI = useCallback(() => {
    abortRef.current?.abort();
    // If we had partial content, mark as done (keep partial). Otherwise reset.
    if (tabsState.ai.code) {
      dispatch({ type: "AI_DONE" });
    } else {
      dispatch({ type: "LOAD_ERR", tab: "ai", error: "" });
    }
  }, [tabsState.ai.code]);

  const setActiveTab = useCallback((tab: DecompileTab) => {
    dispatch({ type: "SET_TAB", tab });
  }, []);

  const triggerTab = useCallback((tab: DecompileTab) => {
    dispatch({ type: "SET_TAB", tab });
    if (tab === "low") decompileLow();
    else if (tab === "high") decompileHigh();
    // AI tab doesn't auto-trigger — user picks enhance/explain
  }, [decompileLow, decompileHigh]);

  const resetForNewFunc = useCallback(() => {
    abortRef.current?.abort();
    dispatch({ type: "RESET_FUNC" });
  }, []);

  // Active tab derived state
  const activeTab = tabsState[tabsState.activeTab];
  const activeCode = activeTab.code;
  const activeLoading = activeTab.loading;
  const activeError = activeTab.error;
  const activeLineMap = activeTab.lineMap;

  // Sync is disabled for AI tab
  const syncDisabled = tabsState.activeTab === "ai";

  // Highlight lines from active tab's lineMap
  const addrToLines = useMemo(() => {
    const m = new Map<number, number[]>();
    for (const [line, addr] of activeLineMap) {
      const arr = m.get(addr);
      if (arr) arr.push(line);
      else m.set(addr, [line]);
    }
    return m;
  }, [activeLineMap]);

  const highlightLines = useMemo(() => {
    if (syncDisabled || activeLineMap.size === 0) return new Set<number>();
    return new Set<number>();
  }, [syncDisabled, activeLineMap]);

  const handleLineClick = useCallback((lineNum: number) => {
    if (syncDisabled) return;
    // Caller provides dispatch to SET_ADDRESS — we return the addr
    // This is handled in DisassemblyView which wraps this
    void lineNum;
  }, [syncDisabled]);

  return {
    tabsState,
    setActiveTab,
    triggerTab,
    triggerAI,
    cancelAI,
    highlightLines,
    handleLineClick,
    resetForNewFunc,
    activeCode,
    activeLoading,
    activeError,
    activeLineMap,
    syncDisabled,
  };
}
