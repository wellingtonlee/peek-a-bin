import { useEffect, useRef, useMemo, useCallback, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch, getDisplayName } from "../hooks/usePEFile";
import { useSortedFuncs, useContainingFunc, useSectionInfo } from "../hooks/useDerivedState";
import { useDisassemblyRows, binarySearchRows, rowAddress } from "../hooks/useDisassemblyRows";
import { useDisassemblySearch } from "../hooks/useDisassemblySearch";
import type { DisplayRow } from "../hooks/useDisassemblyRows";
import type { CrossSectionResult } from "../hooks/useDisassemblySearch";
import { disasmWorker } from "../workers/disasmClient";
import type { Instruction, DisasmFunction, Xref } from "../disasm/types";
import type { SectionHeader } from "../pe/types";
import { CallPanel } from "./CallPanel";
import { buildIATLookup, parseOperandTargets } from "../disasm/operands";
import { JumpArrows } from "./JumpArrows";
import { InstructionDetail } from "./InstructionDetail";
import { DisassemblyMinimap } from "./DisassemblyMinimap";
import { analyzeStackFrame } from "../disasm/stack";
import { MNEMONIC_HINTS } from "../disasm/mnemonics";
import { CFGView } from "./CFGView";
import { inferSignature, type FunctionSignature } from "../disasm/signatures";
import { Breadcrumbs } from "./Breadcrumbs";
import { rvaToFileOffset } from "../pe/parser";
import { XrefPanel } from "./XrefPanel";
import { DecompileView } from "./DecompileView";
import { ResizeHandle } from "./ResizeHandle";
import { BottomPanelContainer } from "./BottomPanelContainer";
import { useDecompileTabs } from "../hooks/useDecompileTabs";
import type { PEFile } from "../pe/types";
import { canonReg } from "../disasm/decompile/ir";
import { ColoredOperand, mnemonicClass, parseBranchTarget } from "./shared";
import { buildCFG, layoutCFG } from "../disasm/cfg";
import { useSetGraphOverview } from "../hooks/useGraphOverview";

// Register family map: canonical → all members
const REG_FAMILIES: Record<string, string[]> = {
  rax: ["rax", "eax", "ax", "al", "ah"],
  rbx: ["rbx", "ebx", "bx", "bl", "bh"],
  rcx: ["rcx", "ecx", "cx", "cl", "ch"],
  rdx: ["rdx", "edx", "dx", "dl", "dh"],
  rsi: ["rsi", "esi", "si", "sil"],
  rdi: ["rdi", "edi", "di", "dil"],
  rbp: ["rbp", "ebp", "bp", "bpl"],
  rsp: ["rsp", "esp", "sp", "spl"],
};
for (let i = 8; i <= 15; i++) {
  REG_FAMILIES[`r${i}`] = [`r${i}`, `r${i}d`, `r${i}w`, `r${i}b`];
}

function buildRegFamily(canon: string): Set<string> {
  return new Set(REG_FAMILIES[canon] ?? [canon]);
}

function formatRangeCopy(
  range: { start: number; end: number },
  rows: DisplayRow[],
  pe: PEFile | null,
  renames: Record<number, string>,
  comments: Record<number, string>,
): string {
  const lo = Math.min(range.start, range.end);
  const hi = Math.max(range.start, range.end);
  const aw = pe?.is64 ? 16 : 8;
  const lines: string[] = [];
  for (let i = lo; i <= hi; i++) {
    const row = rows[i];
    if (!row) continue;
    if (row.kind === "label") {
      const name = getDisplayName(row.fn, renames);
      lines.push(`; ──── ${name} ────`);
    } else if (row.kind === "insn") {
      const insn = row.insn;
      const addrHex = insn.address.toString(16).toUpperCase().padStart(aw, "0");
      const bytesHex = Array.from(insn.bytes).map(b => b.toString(16).toUpperCase().padStart(2, "0")).join(" ").padEnd(24);
      const mnem = insn.mnemonic.padEnd(8);
      const ops = insn.opStr;
      const c = insn.comment ? `  ; ${insn.comment}` : "";
      const uc = comments[insn.address] ? `  ; ${comments[insn.address]}` : "";
      lines.push(`${addrHex}  ${bytesHex}  ${mnem}${ops}${c}${uc}`);
    } else if (row.kind === "data") {
      const item = row.item;
      const addrHex = item.address.toString(16).toUpperCase().padStart(aw, "0");
      let value = "";
      if (item.directive === "dup") {
        value = `${item.dupCount} dup(${item.dupByte === 0 ? "0" : `0x${item.dupByte!.toString(16)}`})`;
      } else if (item.directive === "db" && item.stringValue != null) {
        value = `"${item.stringValue}", 0`;
      } else if ((item.directive === "dd" || item.directive === "dq") && item.pointerTarget != null) {
        value = `0x${item.pointerTarget.toString(16).toUpperCase()}`;
      } else {
        value = Array.from(item.bytes).map(b => b.toString(16).toUpperCase().padStart(2, "0") + "h").join(", ");
      }
      const c = item.pointerLabel ? `  ; ${item.pointerLabel}` : item.stringValue ? `  ; ${item.stringType ?? ""}` : "";
      const uc = comments[item.address] ? `  ; ${comments[item.address]}` : "";
      lines.push(`${addrHex}  ${item.directive.padEnd(8)}${value}${c}${uc}`);
    }
  }
  return lines.join("\n");
}

// XrefPopupState removed — replaced by XrefPanel with scoped filter

// --- Context menu ---
interface ContextMenuState {
  x: number;
  y: number;
  insn: Instruction;
}

export function DisassemblyView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const suppressScrollRef = useRef(false);

  // Sorted functions for binary search
  const sortedFuncs = useSortedFuncs();
  // Find current function for call panel
  const currentFunc = useContainingFunc(undefined, sortedFuncs);
  const sectionInfo = useSectionInfo();

  // Core row computation hook
  const {
    instructions,
    rows,
    funcMap,
    xrefMap,
    typedXrefMap,
    loopHeaders,
    loops,
    bookmarkSet,
    disassembling,
    disasmError,
    isExecutable,
  } = useDisassemblyRows(currentFunc);

  const currentIndex = useMemo(() => {
    if (rows.length === 0) return 0;
    return binarySearchRows(rows, state.currentAddress);
  }, [rows, state.currentAddress]);

  const commentAddrSet = useMemo(() => new Set(
    Object.keys(state.comments).filter(k => state.comments[Number(k)]).map(Number)
  ), [state.comments]);

  // Search hook
  const search = useDisassemblySearch(rows, currentIndex);

  // Local UI states
  const [copiedAddr, setCopiedAddr] = useState<number | null>(null);
  const [ctxMenu, setCtxMenu] = useState<ContextMenuState | null>(null);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [xrefScopeAddress, setXrefScopeAddress] = useState<number | null>(null);
  const [renamingLabel, setRenamingLabel] = useState<{ address: number; value: string } | null>(null);
  const [editingComment, setEditingComment] = useState<{ address: number; value: string } | null>(null);
  const [showCallPanel, setShowCallPanel] = useState(false);
  const [insnFilter, setInsnFilter] = useState<"all" | "calls" | "jumps" | "stringrefs" | "suspicious">("all");
  const [selectionRange, setSelectionRange] = useState<{ start: number; end: number } | null>(null);
  const [lastClickedRow, setLastClickedRow] = useState<number | null>(null);
  const [showArrows, setShowArrows] = useState(true);
  const [showDetail, setShowDetail] = useState(false);
  const [showMinimap, setShowMinimap] = useState(true);
  const [viewMode, setViewMode] = useState<"linear" | "graph">(() => {
    try {
      const v = localStorage.getItem("peek-a-bin:view-mode");
      if (v === "graph") return "graph";
    } catch {}
    return "linear";
  });
  const [graphPan, setGraphPan] = useState({ x: 0, y: 0 });
  const [graphZoom, setGraphZoom] = useState(0.8);
  const [collapsedBlocks, setCollapsedBlocks] = useState<Set<number>>(new Set());
  const [restorePanZoom, setRestorePanZoom] = useState<{ pan: { x: number; y: number }; zoom: number } | null>(null);
  const navViewStateMapRef = useRef<Map<number, { viewMode: "linear" | "graph"; graphPan: { x: number; y: number }; graphZoom: number }>>(new Map());
  const cfgContainerRef = useRef<HTMLDivElement>(null);
  const [showExportMenu, setShowExportMenu] = useState(false);
  const [showXrefPanel, setShowXrefPanel] = useState(false);
  const [showGraphSearch, setShowGraphSearch] = useState(false);
  const [graphSearchQuery, setGraphSearchQuery] = useState("");
  const [graphSearchMatches, setGraphSearchMatches] = useState<number[]>([]);
  const [graphSearchIdx, setGraphSearchIdx] = useState(0);
  const graphSearchInputRef = useRef<HTMLInputElement>(null);
  const [highlightedReg, setHighlightedReg] = useState<string | null>(null);
  const [showDecompile, setShowDecompile] = useState(false);
  const [reCenterTrigger, setReCenterTrigger] = useState(0);
  const [scrollSyncEnabled, setScrollSyncEnabled] = useState(() => {
    try { return localStorage.getItem("peek-a-bin:scroll-sync") !== "false"; } catch { return true; }
  });
  const [scrollSyncAddr, setScrollSyncAddr] = useState<number | null>(null);
  const scrollSyncTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [showBytes, setShowBytes] = useState(() => {
    try { return localStorage.getItem("peek-a-bin:show-bytes") !== "false"; } catch { return true; }
  });
  const [decompileWidth, setDecompileWidth] = useState(() => {
    try {
      const v = localStorage.getItem("peek-a-bin:decompile-width");
      if (v) { const n = parseInt(v, 10); if (n >= 100) return n; }
    } catch {}
    return 500;
  });

  // Register highlight family set
  const highlightRegs = useMemo(() => {
    if (!highlightedReg) return null;
    return buildRegFamily(highlightedReg);
  }, [highlightedReg]);

  const handleRegClick = useCallback((regName: string) => {
    const canon = canonReg(regName);
    setHighlightedReg((prev) => prev === canon ? null : canon);
  }, []);

  // Build IAT lookup map from imports
  const iatMap = useMemo(() => {
    if (!pe) return new Map<number, { lib: string; func: string }>();
    return buildIATLookup(pe.imports);
  }, [pe]);

  // Loop body map: insn address → max loop depth
  const loopBodyMap = useMemo(() => {
    const m = new Map<number, number>();
    for (const loop of loops) {
      if (loop.bodyAddrs) {
        for (const addr of loop.bodyAddrs) {
          const existing = m.get(addr) ?? 0;
          m.set(addr, Math.max(existing, loop.depth + 1));
        }
      }
    }
    return m;
  }, [loops]);

  // Function signature inference
  const currentFuncSig = useMemo((): FunctionSignature | null => {
    if (!currentFunc || instructions.length === 0 || !pe) return null;
    return inferSignature(currentFunc, instructions, pe.is64);
  }, [currentFunc, instructions, pe]);

  // Lazy per-label signature cache (only compute for visible labels)
  const sigCacheRef = useRef<{ insnsId: Instruction[]; cache: Map<number, FunctionSignature> }>({ insnsId: [], cache: new Map() });
  if (sigCacheRef.current.insnsId !== instructions) {
    sigCacheRef.current = { insnsId: instructions, cache: new Map() };
  }
  const getSigForFunc = (fn: DisasmFunction): FunctionSignature | null => {
    if (!pe || instructions.length === 0) return null;
    const cached = sigCacheRef.current.cache.get(fn.address);
    if (cached) return cached;
    const sig = inferSignature(fn, instructions, pe.is64);
    if (sig.paramCount > 0) sigCacheRef.current.cache.set(fn.address, sig);
    return sig.paramCount > 0 ? sig : null;
  };

  // Stack frame analysis (lazy, only when detail panel is open)
  const stackFrame = useMemo(() => {
    if (!showDetail || !currentFunc || instructions.length === 0) return null;
    return analyzeStackFrame(currentFunc, instructions, pe?.is64 ?? true);
  }, [showDetail, currentFunc, instructions, pe?.is64]);

  // Current instruction for detail panel
  const curInsnForDetail = useMemo((): Instruction | null => {
    if (!showDetail || instructions.length === 0) return null;
    let lo = 0, hi = instructions.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (instructions[mid].address === state.currentAddress) return instructions[mid];
      if (instructions[mid].address < state.currentAddress) lo = mid + 1; else hi = mid - 1;
    }
    return instructions[Math.min(lo, instructions.length - 1)];
  }, [showDetail, instructions, state.currentAddress]);

  const SUSPICIOUS_MNEMONICS = useMemo(() => new Set(["int", "sysenter", "syscall", "in", "out", "rdtsc", "cpuid"]), []);

  const matchesFilter = useCallback((row: DisplayRow): boolean => {
    if (insnFilter === "all") return true;
    if (row.kind !== "insn") return true; // labels/separators always match
    const insn = row.insn;
    switch (insnFilter) {
      case "calls": return insn.mnemonic === "call";
      case "jumps": return insn.mnemonic === "jmp" || insn.mnemonic.startsWith("j");
      case "stringrefs": return insn.comment != null || state.comments[insn.address] != null;
      case "suspicious": return SUSPICIOUS_MNEMONICS.has(insn.mnemonic);
      default: return true;
    }
  }, [insnFilter, state.comments, SUSPICIOUS_MNEMONICS]);

  const filterMatchCount = useMemo(() => {
    if (insnFilter === "all") return 0;
    let count = 0;
    for (const row of rows) {
      if (row.kind === "insn" && matchesFilter(row)) count++;
    }
    return count;
  }, [rows, insnFilter, matchesFilter]);

  const isSelected = useCallback((rowIndex: number): boolean => {
    if (!selectionRange) return false;
    const lo = Math.min(selectionRange.start, selectionRange.end);
    const hi = Math.max(selectionRange.start, selectionRange.end);
    return rowIndex >= lo && rowIndex <= hi;
  }, [selectionRange]);

  const rowHeight = 20;
  const sepHeight = 12;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) => rows[index]?.kind === "separator" ? sepHeight : rowHeight,
    overscan: 50,
  });

  // Scroll-driven sync: update scrollSyncAddr from visible center instruction
  useEffect(() => {
    if (!scrollSyncEnabled || !showDecompile || viewMode !== "linear") return;
    const el = parentRef.current;
    if (!el) return;
    const handler = () => {
      clearTimeout(scrollSyncTimerRef.current);
      scrollSyncTimerRef.current = setTimeout(() => {
        const vItems = virtualizer.getVirtualItems();
        if (vItems.length === 0) return;
        // Pick center item
        const centerItem = vItems[Math.floor(vItems.length / 2)];
        const row = rows[centerItem.index];
        if (row && row.kind === "insn") {
          setScrollSyncAddr(row.insn.address);
        } else if (row && row.kind === "data") {
          setScrollSyncAddr(row.item.address);
        }
      }, 100);
    };
    el.addEventListener("scroll", handler, { passive: true });
    return () => {
      el.removeEventListener("scroll", handler);
      clearTimeout(scrollSyncTimerRef.current);
    };
  }, [scrollSyncEnabled, showDecompile, viewMode, rows, virtualizer]);

  // Persist viewMode
  useEffect(() => {
    try { localStorage.setItem("peek-a-bin:view-mode", viewMode); } catch {}
  }, [viewMode]);

  // Clear restorePanZoom after it's consumed by CFGView
  useEffect(() => {
    if (restorePanZoom) setRestorePanZoom(null);
  }, [restorePanZoom]);

  // Window-level Space handler so toggle works regardless of focus
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key !== " ") return;
      const tag = (e.target as HTMLElement)?.tagName?.toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;
      if (search.showSearch) return;
      if (!currentFunc) return;
      e.preventDefault();
      setViewMode(v => v === "graph" ? "linear" : "graph");
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [search.showSearch, currentFunc]);

  // Reset collapsed blocks on function change
  useEffect(() => {
    setCollapsedBlocks(new Set());
  }, [currentFunc?.address]);

  const handleToggleCollapse = useCallback((blockId: number) => {
    setCollapsedBlocks(prev => {
      const next = new Set(prev);
      if (next.has(blockId)) next.delete(blockId);
      else next.add(blockId);
      return next;
    });
  }, []);

  useEffect(() => {
    if (viewMode === "linear" && suppressScrollRef.current) {
      suppressScrollRef.current = false;
      return;
    }
    if (viewMode === "linear" && rows.length > 0 && currentIndex >= 0) {
      virtualizer.scrollToIndex(currentIndex, { align: "center" });
    }
  }, [currentIndex, rows.length, viewMode]);

  // Dispatch current instruction & block info for status bar
  useEffect(() => {
    const row = rows[currentIndex];
    if (row && row.kind === "insn") {
      dispatch({ type: "SET_CURRENT_INSTRUCTION", instruction: { bytes: Array.from(row.insn.bytes), size: row.insn.size } });
      // Find block range from rows with same blockIdx
      const blockIdx = row.blockIdx;
      let startAddr = row.insn.address, endAddr = row.insn.address;
      for (let i = currentIndex; i >= 0; i--) {
        const r = rows[i];
        if (!r || r.kind !== "insn" || r.blockIdx !== blockIdx) break;
        startAddr = r.insn.address;
      }
      for (let i = currentIndex; i < rows.length; i++) {
        const r = rows[i];
        if (!r || r.kind !== "insn" || r.blockIdx !== blockIdx) break;
        endAddr = r.insn.address + r.insn.size;
      }
      dispatch({ type: "SET_CURRENT_BLOCK", block: { startAddr, endAddr } });
    } else {
      dispatch({ type: "SET_CURRENT_INSTRUCTION", instruction: null });
      dispatch({ type: "SET_CURRENT_BLOCK", block: null });
    }
  }, [currentIndex, rows, dispatch]);

  // Sticky function header: find label row index for current function
  const currentFuncLabelIndex = useMemo(() => {
    if (!currentFunc) return -1;
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i];
      if (r.kind === "label" && r.fn.address === currentFunc.address) return i;
    }
    return -1;
  }, [rows, currentFunc]);

  // Dismiss context menu / export menu on click outside or Escape
  useEffect(() => {
    if (!ctxMenu && !showExportMenu) return;
    const dismiss = () => { setCtxMenu(null); setShowExportMenu(false); };
    const keyDismiss = (e: KeyboardEvent) => { if (e.key === "Escape") dismiss(); };
    window.addEventListener("click", dismiss);
    window.addEventListener("keydown", keyDismiss);
    return () => {
      window.removeEventListener("click", dismiss);
      window.removeEventListener("keydown", keyDismiss);
    };
  }, [ctxMenu, showExportMenu]);

  // Listen for show-xrefs event from sidebar context menu
  useEffect(() => {
    const handler = (e: Event) => {
      const addr = (e as CustomEvent).detail?.address;
      if (typeof addr === "number") {
        setXrefScopeAddress(addr);
        setShowXrefPanel(true);
      }
    };
    window.addEventListener("peek-a-bin:show-xrefs", handler);
    return () => window.removeEventListener("peek-a-bin:show-xrefs", handler);
  }, []);

  // Mouse back/forward buttons (works in both linear and graph modes)
  useEffect(() => {
    const el = cfgContainerRef.current;
    if (!el) return;
    const handler = (e: MouseEvent) => {
      if (e.button === 3) { e.preventDefault(); dispatch({ type: "NAV_BACK" }); }
      if (e.button === 4) { e.preventDefault(); dispatch({ type: "NAV_FORWARD" }); }
    };
    el.addEventListener("mouseup", handler);
    return () => el.removeEventListener("mouseup", handler);
  }, [dispatch]);

  // Focus cfgContainerRef when entering graph mode so hotkeys work
  useEffect(() => {
    if (viewMode === "graph") cfgContainerRef.current?.focus();
  }, [viewMode]);

  // Forward clicks inside graph container to focus so hotkeys fire
  useEffect(() => {
    const el = cfgContainerRef.current;
    if (!el || viewMode !== "graph") return;
    const handler = () => el.focus();
    el.addEventListener("mousedown", handler);
    return () => el.removeEventListener("mousedown", handler);
  }, [viewMode]);

  // Build CFG block map for graph keyboard navigation (lazy, only called when needed)
  const buildCFGForNav = useCallback(() => {
    if (!currentFunc) return null;
    const cfg = buildCFG(currentFunc, instructions, typedXrefMap, disasmWorker.jumpTables);
    const navBlocks = new Map<number, (typeof cfg)[0]>();
    const addrToBlock = new Map<number, number>();
    for (const b of cfg) {
      navBlocks.set(b.id, b);
      for (const insn of b.insns) addrToBlock.set(insn.address, b.id);
    }
    return { navBlocks, addrToBlock };
  }, [currentFunc, instructions, typedXrefMap]);

  // Graph search: compute matches when query changes
  const handleGraphSearch = useCallback((query: string) => {
    setGraphSearchQuery(query);
    if (!query || instructions.length === 0) {
      setGraphSearchMatches([]);
      setGraphSearchIdx(0);
      return;
    }
    // Support /regex/ and /regex/i syntax
    let matcher: (text: string) => boolean;
    const regexMatch = query.match(/^\/(.+)\/([i]?)$/);
    if (regexMatch) {
      try {
        const rx = new RegExp(regexMatch[1], regexMatch[2]);
        matcher = (text) => rx.test(text);
      } catch {
        matcher = (text) => text.toLowerCase().includes(query.toLowerCase());
      }
    } else {
      const q = query.toLowerCase();
      matcher = (text) => text.toLowerCase().includes(q);
    }
    const matches: number[] = [];
    for (const insn of instructions) {
      const text = `${insn.mnemonic} ${insn.opStr}`;
      if (matcher(text)) matches.push(insn.address);
    }
    setGraphSearchMatches(matches);
    setGraphSearchIdx(0);
    if (matches.length > 0) {
      setCollapsedBlocks(new Set());
      dispatch({ type: "SET_ADDRESS", address: matches[0] });
    }
  }, [instructions, dispatch]);

  const graphSearchNextMatch = useCallback(() => {
    if (graphSearchMatches.length === 0) return;
    const next = (graphSearchIdx + 1) % graphSearchMatches.length;
    setGraphSearchIdx(next);
    dispatch({ type: "SET_ADDRESS", address: graphSearchMatches[next] });
  }, [graphSearchMatches, graphSearchIdx, dispatch]);

  const graphSearchPrevMatch = useCallback(() => {
    if (graphSearchMatches.length === 0) return;
    const prev = (graphSearchIdx - 1 + graphSearchMatches.length) % graphSearchMatches.length;
    setGraphSearchIdx(prev);
    dispatch({ type: "SET_ADDRESS", address: graphSearchMatches[prev] });
  }, [graphSearchMatches, graphSearchIdx, dispatch]);

  const closeGraphSearch = useCallback(() => {
    setShowGraphSearch(false);
    setGraphSearchQuery("");
    setGraphSearchMatches([]);
    setGraphSearchIdx(0);
  }, []);

  // Graph search match sets for CFGView highlighting
  const graphSearchMatchSet = useMemo(() => new Set(graphSearchMatches), [graphSearchMatches]);
  const graphSearchCurrentMatch = graphSearchMatches[graphSearchIdx] ?? undefined;

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (search.showSearch && e.key === "Escape") {
        search.resetSearch();
        parentRef.current?.focus();
        return;
      }

      if (e.key === "Escape") {
        if (highlightedReg) { setHighlightedReg(null); return; }
        if (showShortcuts) { setShowShortcuts(false); return; }
        if (ctxMenu) { setCtxMenu(null); return; }
        if (selectionRange) { setSelectionRange(null); return; }
        // Pop breadcrumb if available, else navigate back
        if (state.callStack.length > 0) {
          const last = state.callStack[state.callStack.length - 1];
          if (last.viewSnapshot) {
            setViewMode(last.viewSnapshot.viewMode);
            setRestorePanZoom({ pan: last.viewSnapshot.graphPan, zoom: last.viewSnapshot.graphZoom });
          }
          dispatch({ type: "SET_ADDRESS", address: last.address });
          dispatch({ type: "POP_CALL_STACK", index: state.callStack.length - 1 });
          return;
        }
        // NAV_BACK: restore view state if saved
        {
          const destAddr = state.historyIndex > 0 ? state.addressHistory[state.historyIndex - 1] : undefined;
          if (destAddr !== undefined) {
            const saved = navViewStateMapRef.current.get(destAddr);
            if (saved) {
              setViewMode(saved.viewMode);
              setRestorePanZoom({ pan: saved.graphPan, zoom: saved.graphZoom });
            }
          }
        }
        dispatch({ type: "NAV_BACK" });
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key === "c") {
        if (selectionRange) {
          e.preventDefault();
          navigator.clipboard.writeText(formatRangeCopy(selectionRange, rows, pe, state.renames, state.comments));
          return;
        }
      }

      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA"
      )
        return;

      // Space handled by window-level effect

      // 0: zoom-to-fit in graph mode
      if (e.key === "0" && viewMode === "graph") {
        e.preventDefault();
        const el = cfgContainerRef.current;
        if (el) {
          // CFGView sets __zoomToFit on the first child with overflow-hidden
          const cfgEl = el.querySelector('.cfg-container') as any;
          if (cfgEl?.__zoomToFit) cfgEl.__zoomToFit();
        }
        return;
      }

      if (e.key === "?") {
        e.preventDefault();
        e.stopPropagation();
        setShowShortcuts((v) => !v);
        return;
      }

      if (e.key === ";") {
        e.preventDefault();
        const existing = state.comments[state.currentAddress] ?? "";
        setEditingComment({ address: state.currentAddress, value: existing });
        return;
      }

      if (e.key === "x" || e.key === "X") {
        e.preventDefault();
        setShowCallPanel((v) => !v);
        return;
      }

      if (e.key === "r" || e.key === "R") {
        e.preventDefault();
        setShowXrefPanel((v) => !v);
        return;
      }

      if (e.key === "i" || e.key === "I") {
        e.preventDefault();
        setShowDetail((v) => !v);
        return;
      }

      if (e.key === "d" || e.key === "D") {
        e.preventDefault();
        handleDecompileToggle();
        return;
      }

      if (e.key === "b" || e.key === "B") {
        e.preventDefault();
        dispatch({ type: "TOGGLE_BOOKMARK" });
        return;
      }

      // Enter: follow branch target of current instruction
      if (e.key === "Enter") {
        e.preventDefault();
        const curRow = rows[currentIndex];
        if (curRow && curRow.kind === "insn") {
          const target = parseBranchTarget(curRow.insn.mnemonic, curRow.insn.opStr);
          if (target !== null) {
            const targetFn = funcMap.get(target);
            const vs = { viewMode, graphPan, graphZoom };
            if (currentFunc) {
              dispatch({ type: "PUSH_CALL_STACK", address: state.currentAddress, name: getDisplayName(currentFunc, state.renames), viewSnapshot: vs });
            }
            navViewStateMapRef.current.set(state.currentAddress, vs);

            // Auto-switch to linear when navigating to non-executable section from graph
            if (viewMode === "graph" && pe) {
              const rva = target - pe.optionalHeader.imageBase;
              const sec = pe.sections.find(s => rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize);
              if (sec && !(sec.characteristics & 0x20000000)) {
                setViewMode("linear");
              }
            }

            dispatch({ type: "SET_ADDRESS", address: target });
          }
        }
        return;
      }

      // N: rename function containing current address
      if (e.key === "n" || e.key === "N") {
        e.preventDefault();
        if (currentFunc) {
          setRenamingLabel({ address: currentFunc.address, value: getDisplayName(currentFunc, state.renames) });
          // Scroll to the function label
          const labelIdx = rows.findIndex((r) => r.kind === "label" && r.fn.address === currentFunc.address);
          if (labelIdx >= 0) {
            virtualizer.scrollToIndex(labelIdx, { align: "center" });
          }
        }
        return;
      }

      if (e.key === "g" || e.key === "G") {
        e.preventDefault();
        const addrInput = document.querySelector<HTMLInputElement>(
          'input[placeholder*="address"]'
        );
        addrInput?.focus();
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key === "f") {
        e.preventDefault();
        if (viewMode === "graph") {
          setShowGraphSearch(true);
          setTimeout(() => graphSearchInputRef.current?.focus(), 0);
        } else {
          search.setShowSearch(true);
          setTimeout(() => searchInputRef.current?.focus(), 0);
        }
        return;
      }

      if (e.key === "/") {
        e.preventDefault();
        if (viewMode === "graph") {
          setShowGraphSearch(true);
          setTimeout(() => graphSearchInputRef.current?.focus(), 0);
        } else {
          search.setShowSearch(true);
          setTimeout(() => searchInputRef.current?.focus(), 0);
        }
        return;
      }

      // Graph mode arrow key navigation
      if (viewMode === "graph" && (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Tab")) {
        e.preventDefault();
        // Build block data from CFG
        const cfg = buildCFGForNav();
        if (!cfg) return;
        const { navBlocks, addrToBlock } = cfg;
        const curBlockId = addrToBlock.get(state.currentAddress);
        if (curBlockId === undefined) return;
        const curBlock = navBlocks.get(curBlockId);
        if (!curBlock) return;

        if (e.key === "Tab") {
          // Cycle through successor blocks
          if (curBlock.succs.length > 0) {
            const succBlock = navBlocks.get(curBlock.succs[0]);
            if (succBlock) dispatch({ type: "SET_ADDRESS", address: succBlock.startAddr });
          }
          return;
        }

        const insnIdx = curBlock.insns.findIndex((insn: Instruction) => insn.address === state.currentAddress);
        if (e.key === "ArrowDown") {
          if (insnIdx < curBlock.insns.length - 1) {
            dispatch({ type: "SET_ADDRESS", address: curBlock.insns[insnIdx + 1].address });
          } else if (curBlock.succs.length > 0) {
            // Move to fallthrough successor (last in succs for conditional, first otherwise)
            const ftIdx = curBlock.succs.length > 1 ? curBlock.succs.length - 1 : 0;
            const succBlock = navBlocks.get(curBlock.succs[ftIdx]);
            if (succBlock) dispatch({ type: "SET_ADDRESS", address: succBlock.startAddr });
          }
        } else if (e.key === "ArrowUp") {
          if (insnIdx > 0) {
            dispatch({ type: "SET_ADDRESS", address: curBlock.insns[insnIdx - 1].address });
          } else if (curBlock.preds.length > 0) {
            const predBlock = navBlocks.get(curBlock.preds[0]);
            if (predBlock) dispatch({ type: "SET_ADDRESS", address: predBlock.insns[predBlock.insns.length - 1].address });
          }
        }
        return;
      }

      const scrollAmount =
        e.key === "PageUp" || e.key === "PageDown" ? 40 : 1;

      if (e.key === "ArrowDown" || e.key === "PageDown") {
        e.preventDefault();
        const newIdx = Math.min(currentIndex + scrollAmount, rows.length - 1);
        const addr = rowAddress(rows[newIdx]);
        if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
      }

      if (e.key === "ArrowUp" || e.key === "PageUp") {
        e.preventDefault();
        const newIdx = Math.max(currentIndex - scrollAmount, 0);
        const addr = rowAddress(rows[newIdx]);
        if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
      }
    },
    [currentIndex, rows, dispatch, search, showShortcuts, ctxMenu, state.currentAddress, state.comments, selectionRange, state.renames, pe, currentFunc, virtualizer, funcMap, state.callStack, viewMode, graphPan, graphZoom, state.addressHistory, state.historyIndex],
  );

  const handleAddressClick = useCallback(
    (address: number) => {
      const vs = { viewMode, graphPan, graphZoom };
      // Always save view state for back-navigation (not just function targets)
      navViewStateMapRef.current.set(state.currentAddress, vs);

      if (currentFunc) {
        dispatch({ type: "PUSH_CALL_STACK", address: state.currentAddress, name: getDisplayName(currentFunc, state.renames), viewSnapshot: vs });
      }

      // Auto-switch to linear when navigating to non-executable section from graph
      if (viewMode === "graph" && pe) {
        const rva = address - pe.optionalHeader.imageBase;
        const sec = pe.sections.find(s => rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize);
        if (sec && !(sec.characteristics & 0x20000000)) {
          setViewMode("linear");
        }
      }

      dispatch({ type: "SET_ADDRESS", address });
    },
    [dispatch, currentFunc, state.currentAddress, state.renames, viewMode, graphPan, graphZoom, pe],
  );

  const handleDoubleClickAddr = useCallback(
    (address: number) => {
      const hex = "0x" + address.toString(16).toUpperCase();
      navigator.clipboard.writeText(hex).then(() => {
        setCopiedAddr(address);
        setTimeout(() => setCopiedAddr(null), 1000);
      });
    },
    [],
  );

  const handleDoubleClickInsn = useCallback(
    (insn: Instruction) => {
      const text = `${insn.mnemonic} ${insn.opStr}`;
      navigator.clipboard.writeText(text);
    },
    [],
  );

  // Context menu actions
  const ctxCopyAddr = useCallback(() => {
    if (!ctxMenu) return;
    navigator.clipboard.writeText("0x" + ctxMenu.insn.address.toString(16).toUpperCase());
    setCtxMenu(null);
  }, [ctxMenu]);

  const ctxCopyInsn = useCallback(() => {
    if (!ctxMenu) return;
    navigator.clipboard.writeText(`${ctxMenu.insn.mnemonic} ${ctxMenu.insn.opStr}`);
    setCtxMenu(null);
  }, [ctxMenu]);

  const ctxCopyBytes = useCallback(() => {
    if (!ctxMenu) return;
    const hex = Array.from(ctxMenu.insn.bytes).map((b) => b.toString(16).padStart(2, "0")).join(" ");
    navigator.clipboard.writeText(hex);
    setCtxMenu(null);
  }, [ctxMenu]);

  const ctxGoTo = useCallback(() => {
    if (!ctxMenu) return;
    const target = parseBranchTarget(ctxMenu.insn.mnemonic, ctxMenu.insn.opStr);
    const addrInput = document.querySelector<HTMLInputElement>(
      'input[placeholder*="address"]'
    );
    if (addrInput) {
      addrInput.focus();
      const prefill = target !== null ? "0x" + target.toString(16) : ctxMenu.insn.opStr;
      addrInput.value = prefill;
      addrInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
    setCtxMenu(null);
  }, [ctxMenu]);

  const ctxShowInHex = useCallback(() => {
    if (!ctxMenu || !pe) return;
    const rva = ctxMenu.insn.address - pe.optionalHeader.imageBase;
    const fileOffset = rvaToFileOffset(rva, pe.sections);
    if (fileOffset >= 0) {
      dispatch({ type: "SET_ADDRESS", address: ctxMenu.insn.address });
      dispatch({ type: "SET_TAB", tab: "hex" });
    }
    setCtxMenu(null);
  }, [ctxMenu, pe, dispatch]);

  const ctxToggleBookmark = useCallback(() => {
    if (!ctxMenu) return;
    dispatch({ type: "TOGGLE_BOOKMARK", address: ctxMenu.insn.address });
    setCtxMenu(null);
  }, [ctxMenu, dispatch]);

  const ctxAddComment = useCallback(() => {
    if (!ctxMenu) return;
    const existing = state.comments[ctxMenu.insn.address] ?? "";
    setEditingComment({ address: ctxMenu.insn.address, value: existing });
    setCtxMenu(null);
  }, [ctxMenu, state.comments]);

  const ctxCopyComment = useCallback(() => {
    if (!ctxMenu) return;
    const comment = state.comments[ctxMenu.insn.address] || ctxMenu.insn.comment;
    if (comment) navigator.clipboard.writeText(comment);
    setCtxMenu(null);
  }, [ctxMenu, state.comments]);

  const ctxRenameFunction = useCallback(() => {
    if (!ctxMenu) return;
    // Find the function that owns this instruction
    const addr = ctxMenu.insn.address;
    const fn = funcMap.get(addr);
    if (fn) {
      setRenamingLabel({ address: fn.address, value: getDisplayName(fn, state.renames) });
    }
    setCtxMenu(null);
  }, [ctxMenu, funcMap, state.renames]);

  const ctxFollowTarget = useCallback(() => {
    if (!ctxMenu) return;
    const target = parseBranchTarget(ctxMenu.insn.mnemonic, ctxMenu.insn.opStr);
    if (target !== null) handleAddressClick(target);
    setCtxMenu(null);
  }, [ctxMenu, handleAddressClick]);

  const ctxShowXrefs = useCallback(() => {
    if (!ctxMenu) return;
    setShowXrefPanel(true);
    setCtxMenu(null);
  }, [ctxMenu]);

  // Xref count map for context menu
  const xrefCountMap = useMemo(() => {
    const m = new Map<number, number>();
    for (const [addr, xrefs] of typedXrefMap) {
      m.set(addr, xrefs.length);
    }
    return m;
  }, [typedXrefMap]);

  const handleContextMenu = useCallback(
    (e: React.MouseEvent, insn: Instruction) => {
      e.preventDefault();
      const container = viewMode === "graph" ? cfgContainerRef.current : parentRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const rawX = e.clientX - rect.left;
      const rawY = e.clientY - rect.top;
      const popW = 180, popH = 300;
      const maxX = rect.width - popW - 8;
      const maxY = rect.height - popH - 8;
      setCtxMenu({
        x: Math.max(0, Math.min(rawX + (viewMode === "linear" ? container.scrollLeft : 0), viewMode === "linear" ? maxX + container.scrollLeft : maxX)),
        y: Math.max(0, Math.min(rawY + (viewMode === "linear" ? container.scrollTop : 0), viewMode === "linear" ? maxY + container.scrollTop : maxY)),
        insn,
      });
    },
    [viewMode],
  );

  // Build assembly text for current function (used by AI enhancement)
  const buildFunctionAsm = useCallback((): string => {
    if (!currentFunc || !pe) return "";
    const aw = pe.is64 ? 16 : 8;
    const endAddr = currentFunc.address + currentFunc.size;
    const name = getDisplayName(currentFunc, state.renames);
    const lines: string[] = [`; ──── ${name} ────`];
    for (const row of rows) {
      if (row.kind !== "insn") continue;
      if (row.insn.address < currentFunc.address) continue;
      if (row.insn.address >= endAddr) break;
      const insn = row.insn;
      const addrHex = insn.address.toString(16).toUpperCase().padStart(aw, "0");
      const comment = insn.comment ? `  ; ${insn.comment}` : "";
      const uc = state.comments[insn.address] ? `  ; ${state.comments[insn.address]}` : "";
      lines.push(`  ${addrHex}  ${insn.mnemonic} ${insn.opStr}${comment}${uc}`);
    }
    return lines.join("\n");
  }, [currentFunc, pe, rows, state.renames, state.comments]);

  // Decompile tabs hook
  const decompile = useDecompileTabs({
    currentFunc,
    pe,
    instructions,
    xrefMap: typedXrefMap,
    iatMap,
    functions: state.functions,
    renames: state.renames,
    buildFunctionAsm,
  });

  const handleDecompileToggle = useCallback(() => {
    if (showDecompile) {
      setShowDecompile(false);
      return;
    }
    if (!currentFunc || !pe || instructions.length === 0) return;
    setShowDecompile(true);
    // Trigger the active tab (defaults to "low")
    decompile.triggerTab(decompile.tabsState.activeTab);
    // Re-center graph after layout adjusts for the decompile panel
    if (viewMode === "graph") {
      requestAnimationFrame(() => setReCenterTrigger((c) => c + 1));
    }
  }, [showDecompile, currentFunc, pe, instructions, decompile, viewMode]);

  // Re-decompile when function changes while panel is open
  const prevDecompFuncRef = useRef<number | null>(null);
  useEffect(() => {
    if (!showDecompile || !currentFunc) return;
    if (prevDecompFuncRef.current === currentFunc.address) return;
    prevDecompFuncRef.current = currentFunc.address;
    decompile.resetForNewFunc();
    decompile.triggerTab(decompile.tabsState.activeTab);
  }, [showDecompile, currentFunc?.address, decompile]);

  // Decompiler ↔ ASM sync maps
  const addrToLines = useMemo(() => {
    const m = new Map<number, number[]>();
    for (const [line, addr] of decompile.activeLineMap) {
      const arr = m.get(addr);
      if (arr) arr.push(line);
      else m.set(addr, [line]);
    }
    return m;
  }, [decompile.activeLineMap]);

  // Use scrollSyncAddr when scroll-sync is active and decompile panel is open, otherwise use currentAddress
  const syncAddr = (scrollSyncEnabled && showDecompile && scrollSyncAddr !== null) ? scrollSyncAddr : state.currentAddress;

  const decompileHighlightLines = useMemo(() => {
    if (decompile.activeLineMap.size === 0 || decompile.syncDisabled) return new Set<number>();
    const lines = addrToLines.get(syncAddr);
    if (lines) return new Set(lines);
    if (!currentFunc) return new Set<number>();
    const funcStart = currentFunc.address;
    const funcEnd = funcStart + currentFunc.size;
    let bestAddr = -1;
    for (const addr of addrToLines.keys()) {
      if (addr <= syncAddr && addr >= funcStart && addr < funcEnd) {
        if (addr > bestAddr) bestAddr = addr;
      }
    }
    if (bestAddr >= 0) return new Set(addrToLines.get(bestAddr)!);
    return new Set<number>();
  }, [addrToLines, syncAddr, decompile.syncDisabled, decompile.activeLineMap.size, currentFunc]);

  const handleDecompileLineClick = useCallback((lineNum: number) => {
    if (decompile.syncDisabled) return;
    const addr = decompile.activeLineMap.get(lineNum);
    if (addr !== undefined) {
      dispatch({ type: "SET_ADDRESS", address: addr });
    }
  }, [decompile.activeLineMap, decompile.syncDisabled, dispatch]);

  const handleExportAsm = useCallback((mode: "function" | "section") => {
    setShowExportMenu(false);
    const aw = pe?.is64 ? 16 : 8;
    const lines: string[] = [];

    if (mode === "function" && currentFunc) {
      const endAddr = currentFunc.address + currentFunc.size;
      const name = getDisplayName(currentFunc, state.renames);
      lines.push(`; ──── ${name} ────`);
      for (const row of rows) {
        if (row.kind === "insn") {
          if (row.insn.address < currentFunc.address) continue;
          if (row.insn.address >= endAddr) break;
          const insn = row.insn;
          const addrHex = insn.address.toString(16).toUpperCase().padStart(aw, "0");
          const comment = insn.comment ? `  ; ${insn.comment}` : "";
          const userComment = state.comments[insn.address] ? `  ; ${state.comments[insn.address]}` : "";
          lines.push(`  ${addrHex}  ${insn.mnemonic} ${insn.opStr}${comment}${userComment}`);
        } else if (row.kind === "label") {
          if (row.fn.address >= currentFunc.address && row.fn.address < endAddr && row.fn.address !== currentFunc.address) {
            lines.push(`\n; ──── ${getDisplayName(row.fn, state.renames)} ────`);
          }
        }
      }
    } else {
      // Entire section
      const totalLines = rows.filter(r => r.kind === "insn").length;
      if (totalLines > 50000 && !confirm(`This will export ${totalLines.toLocaleString()} lines. Continue?`)) return;
      for (const row of rows) {
        if (row.kind === "label") {
          const name = getDisplayName(row.fn, state.renames);
          lines.push(`\n; ──── ${name} ────`);
        } else if (row.kind === "insn") {
          const insn = row.insn;
          const addrHex = insn.address.toString(16).toUpperCase().padStart(aw, "0");
          const comment = insn.comment ? `  ; ${insn.comment}` : "";
          const userComment = state.comments[insn.address] ? `  ; ${state.comments[insn.address]}` : "";
          lines.push(`  ${addrHex}  ${insn.mnemonic} ${insn.opStr}${comment}${userComment}`);
        }
      }
    }

    const text = lines.join("\n");
    const blob = new Blob([text], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const label = mode === "function" && currentFunc
      ? getDisplayName(currentFunc, state.renames).replace(/[^a-zA-Z0-9_]/g, "_")
      : sectionInfo?.name ?? "section";
    a.href = url;
    a.download = `${state.fileName ?? "export"}_${label}.asm`;
    a.click();
    URL.revokeObjectURL(url);
  }, [pe, currentFunc, rows, state.renames, state.comments, state.fileName, sectionInfo]);

  // Compute graph layout blocks/edges for minimap (only in graph mode)
  const { graphBlocksForMinimap, graphEdgesForMinimap } = useMemo(() => {
    if (viewMode !== "graph" || !currentFunc) return { graphBlocksForMinimap: undefined, graphEdgesForMinimap: undefined };
    const cfg = buildCFG(currentFunc, instructions, typedXrefMap, disasmWorker.jumpTables);
    const layout = layoutCFG(cfg);
    return { graphBlocksForMinimap: layout.blocks, graphEdgesForMinimap: layout.edges };
  }, [viewMode, currentFunc, instructions, typedXrefMap]);

  // Publish graph data to sidebar overview context
  const setGraphOverview = useSetGraphOverview();
  useEffect(() => {
    if (viewMode !== "graph" || !graphBlocksForMinimap || !graphEdgesForMinimap) {
      setGraphOverview(null);
      return;
    }
    const container = cfgContainerRef.current;
    if (!container) { setGraphOverview(null); return; }
    setGraphOverview({
      blocks: graphBlocksForMinimap,
      edges: graphEdgesForMinimap,
      pan: graphPan,
      zoom: graphZoom,
      viewport: { width: container.clientWidth, height: container.clientHeight },
      onPanTo: setGraphPan,
      currentAddress: state.currentAddress,
    });
  }, [viewMode, graphBlocksForMinimap, graphEdgesForMinimap, graphPan, graphZoom, state.currentAddress, setGraphOverview]);

  // Clear graph overview on unmount
  useEffect(() => {
    return () => setGraphOverview(null);
  }, [setGraphOverview]);

  if (!pe) return null;

  if (disassembling) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400 text-sm">
        <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        Disassembling...
      </div>
    );
  }

  if (disasmError) {
    return (
      <div className="p-4 text-red-400 text-sm">
        Disassembly error: {disasmError}
      </div>
    );
  }

  if (!state.disasmReady) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400 text-sm">
        <svg className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
          <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
        </svg>
        Loading disassembly engine...
      </div>
    );
  }

  if (!sectionInfo) {
    return (
      <div className="p-4 text-gray-400 text-sm">
        Address 0x{state.currentAddress.toString(16)} is not within any section.
      </div>
    );
  }

  const addrWidth = pe.is64 ? 16 : 8;
  const sectionBaseVA = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;
  const sectionEndVA = sectionBaseVA + sectionInfo.virtualSize;

  return (
    <div className="flex flex-col h-full">
      {/* Section header bar */}
      <div className="flex items-center gap-3 px-4 py-1 bg-gray-800/50 border-b border-gray-700 text-xs text-gray-400 shrink-0">
        <span className="font-semibold text-gray-300">{sectionInfo.name}</span>
        <span>
          VA: 0x{sectionBaseVA.toString(16).toUpperCase()} – 0x{sectionEndVA.toString(16).toUpperCase()}
        </span>
        <span>Size: 0x{sectionInfo.virtualSize.toString(16).toUpperCase()}</span>
        <span>{isExecutable ? `${instructions.length.toLocaleString()} instructions` : "data section"}</span>
        {isExecutable && (<>
        <select
          value={insnFilter}
          onChange={(e) => setInsnFilter(e.target.value as typeof insnFilter)}
          className="px-1.5 py-0.5 bg-gray-800 border border-gray-600 rounded text-gray-200 text-[10px]"
        >
          <option value="all">All</option>
          <option value="calls">Calls</option>
          <option value="jumps">Jumps</option>
          <option value="stringrefs">String refs</option>
          <option value="suspicious">Suspicious</option>
        </select>
        {insnFilter !== "all" && (
          <span className="text-gray-500 text-[10px]">({filterMatchCount} matches)</span>
        )}
        </>)}
        <div className="flex items-center gap-1 ml-2">
          <button
            onClick={() => setShowArrows((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showArrows ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
          >
            Arrows
          </button>
          {viewMode === "linear" && (
          <button
            onClick={() => setShowMinimap((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showMinimap ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
          >
            Map
          </button>
          )}
          <button
            onClick={() => {
              setShowBytes((v) => {
                const next = !v;
                try { localStorage.setItem("peek-a-bin:show-bytes", String(next)); } catch {}
                return next;
              });
            }}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showBytes ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
            title="Toggle bytes column"
          >
            Bytes
          </button>
          <button
            onClick={() => setViewMode(v => v === "graph" ? "linear" : "graph")}
            disabled={!currentFunc || !isExecutable}
            className={`px-1.5 py-0.5 rounded text-[10px] ${viewMode === "graph" ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"} disabled:opacity-30`}
            title="Toggle graph view (Space)"
          >
            Graph
          </button>
          <button
            onClick={handleDecompileToggle}
            disabled={!currentFunc || !isExecutable}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showDecompile ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"} disabled:opacity-30`}
            title="Decompile current function (D)"
          >
            Decompile
          </button>
          <button
            onClick={() => setShowXrefPanel((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showXrefPanel ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
            title="Toggle cross-reference panel (R)"
          >
            Xrefs
          </button>
          <div className="relative">
            <button
              onClick={() => setShowExportMenu((v) => !v)}
              className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600"
              title="Export disassembly as .asm file"
            >
              Export
            </button>
            {showExportMenu && (
              <div className="absolute top-full left-0 mt-0.5 bg-gray-800 border border-gray-600 rounded shadow-xl z-50 text-[10px] min-w-[140px]">
                <button
                  onClick={() => handleExportAsm("function")}
                  disabled={!currentFunc}
                  className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200 disabled:opacity-30 disabled:cursor-default"
                >
                  Current function
                </button>
                <button
                  onClick={() => handleExportAsm("section")}
                  className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
                >
                  Entire section
                </button>
              </div>
            )}
          </div>
        </div>
        <div className="flex-1" />
        {search.showSearch && (
          <div className="flex items-center gap-1">
            <input
              ref={searchInputRef}
              type="text"
              value={search.searchQuery}
              onChange={(e) => {
                const value = e.target.value;
                search.setSearchQuery(value);
                clearTimeout(search.searchDebounceRef.current);
                search.searchDebounceRef.current = setTimeout(() => search.handleSearch(value), 150);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  clearTimeout(search.searchDebounceRef.current);
                  if (e.shiftKey) search.handleSearchPrev();
                  else if (search.searchMatches.length > 0) search.handleSearchNext();
                  else search.handleSearch(search.searchQuery);
                }
                if (e.key === "Escape") {
                  clearTimeout(search.searchDebounceRef.current);
                  search.resetSearch();
                  parentRef.current?.focus();
                }
                e.stopPropagation();
              }}
              placeholder="Search... (/regex/)"
              title={search.searchRegexError ? "Invalid regex" : "Substring search, or /regex/ for regex"}
              className={`w-48 px-2 py-0.5 bg-gray-800 border rounded text-gray-200 placeholder-gray-500 focus:outline-none ${
                search.searchRegexError ? "border-red-500" : "border-gray-600 focus:border-blue-500"
              }`}
            />
            {search.searchMatches.length > 0 && (
              <span className="text-gray-500 text-[10px]">
                {search.searchMatchIdx + 1}/{search.searchMatches.length}
              </span>
            )}
            {search.searchRegexError && (
              <span className="text-red-400 text-[10px]">Invalid regex</span>
            )}
            {search.searchQuery && !search.searchRegexError && search.searchMatches.length === 0 && !search.crossResults && (
              <span className="text-red-400 text-[10px]">No matches</span>
            )}
            <button
              onClick={search.handleSearchPrev}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
              title="Previous (Shift+Enter)"
            >
              ▲
            </button>
            <button
              onClick={search.handleSearchNext}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
              title="Next (Enter)"
            >
              ▼
            </button>
            <button
              onClick={() => {
                search.resetSearch();
                parentRef.current?.focus();
              }}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
            >
              ✕
            </button>
            <div className="relative group">
              <button className="px-1 py-0.5 text-gray-500 hover:text-gray-300 text-[10px]">?</button>
              <div className="hidden group-hover:block absolute right-0 top-full mt-1 w-56 px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-[10px] text-gray-300 z-50 shadow-lg whitespace-normal">
                Substring match by default. Use <span className="text-blue-400">/pattern/</span> for regex, <span className="text-blue-400">/pattern/i</span> for case-insensitive.
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Grouped search results */}
      {search.showSearch && search.searchMatchGroups.length > 1 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs max-h-40 overflow-auto">
          <div className="text-gray-400 mb-1">{search.searchMatches.length} matches in {search.searchMatchGroups.length} functions:</div>
          {search.searchMatchGroups.map((g) => (
            <button
              key={g.funcAddr}
              onClick={() => dispatch({ type: "SET_ADDRESS", address: g.funcAddr })}
              className="block w-full text-left hover:bg-gray-700/50 rounded px-1 py-0.5 truncate"
            >
              <span className="text-blue-400">{g.funcName}</span>{" "}
              <span className="text-gray-500">({g.matches.length})</span>
            </button>
          ))}
        </div>
      )}

      {/* Cross-section search prompt */}
      {search.showSearch && search.searchQuery && search.searchMatches.length === 0 && !search.crossResults && !search.crossSearching && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs flex items-center gap-2">
          <span className="text-gray-400">No matches in {sectionInfo.name}.</span>
          <button
            onClick={search.handleCrossSearch}
            className="text-blue-400 hover:text-blue-300 hover:underline"
          >
            Search all sections?
          </button>
        </div>
      )}

      {/* Cross-section search loading */}
      {search.crossSearching && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs text-gray-400 flex items-center gap-2">
          <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Searching all sections...
        </div>
      )}

      {/* Cross-section search results */}
      {search.crossResults && search.crossResults.length > 0 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs max-h-40 overflow-auto">
          <div className="text-gray-400 mb-1">{search.crossResults.length} result{search.crossResults.length !== 1 ? "s" : ""} in other sections:</div>
          {search.crossResults.map((r: CrossSectionResult, i: number) => (
            <button
              key={i}
              onClick={() => {
                dispatch({ type: "SET_ADDRESS", address: r.address });
                search.resetSearch();
              }}
              className="block w-full text-left hover:bg-gray-700/50 rounded px-1 py-0.5 truncate"
            >
              <span className="text-gray-500">[{r.section.name}]</span>{" "}
              <span className="text-blue-400">0x{r.address.toString(16).toUpperCase()}</span>{" "}
              <span className="text-gray-300">{r.text}</span>
            </button>
          ))}
        </div>
      )}
      {search.crossResults && search.crossResults.length === 0 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs text-gray-500">
          No matches found in any section.
        </div>
      )}

      {/* Breadcrumb trail */}
      <Breadcrumbs />

      {/* Disassembly content */}
      <div className="flex flex-1 overflow-hidden" ref={cfgContainerRef} tabIndex={0} onKeyDown={handleKeyDown}>
      {viewMode === "linear" ? (
      <div
        ref={parentRef}
        className="flex-1 overflow-auto leading-5 focus:outline-none relative"
        style={{ fontSize: 'var(--mono-font-size)', '--col-addr': pe.is64 ? '18ch' : '10ch' } as React.CSSProperties}
        tabIndex={0}
      >
        {/* Sticky function header */}
        {currentFunc && currentFuncLabelIndex >= 0 && (() => {
          const vItems = virtualizer.getVirtualItems();
          const firstVisible = vItems.length > 0 ? vItems[0].index : 0;
          if (currentFuncLabelIndex < firstVisible) {
            const name = getDisplayName(currentFunc, state.renames);
            return (
              <div
                className="sticky top-0 left-0 right-0 z-10 bg-gray-900/95 border-b border-gray-700/50 px-4 py-0.5 text-xs text-gray-300 cursor-pointer hover:text-white font-mono"
                onClick={() => virtualizer.scrollToIndex(currentFuncLabelIndex, { align: "start" })}
                title="Click to scroll to function header"
              >
                ▸ {name}
              </div>
            );
          }
          return null;
        })()}
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
            paddingLeft: showArrows && isExecutable ? "40px" : undefined,
          }}
        >
          {showArrows && isExecutable && (
            <JumpArrows
              visibleItems={virtualizer.getVirtualItems()}
              rows={rows}
              funcMap={funcMap}
              currentFuncAddr={currentFunc?.address ?? null}
              currentAddress={state.currentAddress}
              rowHeight={rowHeight}
            />
          )}
          {virtualizer.getVirtualItems().map((vItem) => {
            const row = rows[vItem.index];
            if (!row) return null;

            if (row.kind === "separator") {
              return (
                <div
                  key={`sep-${vItem.index}`}
                  data-index={vItem.index}
                  className="flex items-center"
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: `${sepHeight}px`,
                    transform: `translateY(${vItem.start}px)`,
                    padding: "0 var(--row-px)",
                  }}
                >
                  <div className="w-full border-t border-gray-700/20" style={{ margin: "0 1rem" }} />
                </div>
              );
            }

            if (row.kind === "data") {
              const item = row.item;
              const addrHex = item.address.toString(16).toUpperCase().padStart(addrWidth, "0");
              const bytesHex = Array.from(item.bytes.slice(0, 8)).map(b => b.toString(16).padStart(2, "0")).join(" ");
              const isCurrentAddr = item.address === state.currentAddress;
              const isBookmarked = bookmarkSet.has(item.address);

              let directiveStr: React.ReactNode;
              let commentStr: React.ReactNode = null;

              if (item.directive === "dup") {
                directiveStr = <span className="text-gray-500">{item.dupCount} dup({item.dupByte === 0 ? "0" : `0x${item.dupByte!.toString(16)}`})</span>;
              } else if (item.directive === "db" && item.stringValue != null) {
                const escaped = item.stringValue.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t");
                directiveStr = <span className="text-green-400">"{escaped}", 0</span>;
                if (item.stringType) commentStr = <span className="text-gray-500 ml-4">; {item.stringType}</span>;
              } else if ((item.directive === "dd" || item.directive === "dq") && item.pointerTarget != null) {
                directiveStr = (
                  <span
                    className="text-blue-400 cursor-pointer hover:underline"
                    onClick={(e) => { e.stopPropagation(); handleAddressClick(item.pointerTarget!); }}
                  >
                    0x{item.pointerTarget.toString(16).toUpperCase()}
                  </span>
                );
                if (item.pointerLabel) commentStr = <span className="text-gray-500 ml-4">; {item.pointerLabel}</span>;
              } else {
                const hexStr = Array.from(item.bytes).map(b => b.toString(16).toUpperCase().padStart(2, "0") + "h").join(", ");
                directiveStr = <span>{hexStr}</span>;
                const ascii = Array.from(item.bytes).map(b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".").join("");
                commentStr = <span className="text-gray-500 ml-4">; {ascii}</span>;
              }

              const userComment = state.comments[item.address];

              return (
                <div
                  key={vItem.index}
                  data-index={vItem.index}
                  className={`disasm-row group disasm-grid-data${!showBytes ? " hide-bytes" : ""} ${isCurrentAddr ? "bg-blue-900/30" : ""}`}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: `${rowHeight}px`,
                    transform: `translateY(${vItem.start}px)`,
                    padding: `0 var(--row-px)`,
                  }}
                  onClick={() => {
                    suppressScrollRef.current = true;
                    dispatch({ type: "SET_ADDRESS", address: item.address });
                  }}
                >
                  <span className="text-center">
                    {isBookmarked && <span className="text-yellow-300">★</span>}
                  </span>
                  <span className="disasm-address">{addrHex}</span>
                  {showBytes && <span className="disasm-bytes truncate">{bytesHex}</span>}
                  <span className="text-cyan-400">{item.directive}</span>
                  <span>{directiveStr}</span>
                  <span className="truncate flex items-center gap-1">
                    {commentStr}
                    {userComment && <span className="disasm-user-comment truncate max-w-xs">; {userComment}</span>}
                  </span>
                </div>
              );
            }

            if (row.kind === "label") {
              const displayName = getDisplayName(row.fn, state.renames);
              const xrefs = typedXrefMap.get(row.fn.address);
              const xrefCount = xrefs?.length ?? 0;
              const isBookmarked = bookmarkSet.has(row.fn.address);

              if (renamingLabel && renamingLabel.address === row.fn.address) {
                return (
                  <div
                    key={`label-${vItem.index}`}
                    data-index={vItem.index}
                    className="flex items-center func-label text-[11px] font-mono border-t border-gray-700/50"
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: `${rowHeight}px`,
                      transform: `translateY(${vItem.start}px)`,
                      paddingTop: "var(--label-pad-top)",
                      paddingLeft: "var(--row-px)",
                      paddingRight: "var(--row-px)",
                    }}
                  >
                    <span className="mr-1">; ────</span>
                    <input
                      autoFocus
                      className="bg-gray-800 border border-blue-500 rounded px-1 text-yellow-300 text-[11px] font-mono outline-none w-48"
                      value={renamingLabel.value}
                      onChange={(e) => setRenamingLabel({ ...renamingLabel, value: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
                          const val = renamingLabel.value.trim();
                          if (val && val !== row.fn.name) {
                            dispatch({ type: "RENAME_FUNCTION", address: renamingLabel.address, name: val });
                          } else if (!val || val === row.fn.name) {
                            dispatch({ type: "CLEAR_RENAME", address: renamingLabel.address });
                          }
                          setRenamingLabel(null);
                        }
                        if (e.key === "Escape") setRenamingLabel(null);
                        e.stopPropagation();
                      }}
                      onBlur={() => setRenamingLabel(null)}
                    />
                    <span className="ml-1">────</span>
                  </div>
                );
              }

              return (
                <div
                  key={`label-${vItem.index}`}
                  data-index={vItem.index}
                  className="flex items-center func-label text-[11px] font-mono border-t border-gray-700/50"
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: `${rowHeight}px`,
                    transform: `translateY(${vItem.start}px)`,
                    paddingTop: "var(--label-pad-top)",
                    paddingLeft: "var(--row-px)",
                    paddingRight: "var(--row-px)",
                  }}
                  onDoubleClick={() => setRenamingLabel({ address: row.fn.address, value: displayName })}
                >
                  {isBookmarked && <span className="text-yellow-300 mr-1">★</span>}
                  <span>; ──── {displayName}{(() => {
                    const sig = getSigForFunc(row.fn);
                    return sig ? ` (${sig.convention}, ${sig.paramCount} param${sig.paramCount !== 1 ? "s" : ""})` : "";
                  })()} ────</span>
                  {xrefCount > 0 && (() => {
                    const counts: Record<string, number> = {};
                    for (const x of xrefs!) {
                      counts[x.type] = (counts[x.type] ?? 0) + 1;
                    }
                    const parts: string[] = [];
                    if (counts.call) parts.push(`${counts.call} call${counts.call > 1 ? "s" : ""}`);
                    if (counts.jmp) parts.push(`${counts.jmp} jmp`);
                    if (counts.branch) parts.push(`${counts.branch} branch`);
                    if (counts.data) parts.push(`${counts.data} data`);
                    const label = parts.length > 0 ? parts.join(", ") : `${xrefCount} xref${xrefCount !== 1 ? "s" : ""}`;
                    return (
                      <span
                        className="ml-2 text-gray-500 hover:text-blue-400 cursor-pointer"
                        onClick={(e) => {
                          e.stopPropagation();
                          setXrefScopeAddress(row.fn.address);
                          setShowXrefPanel(true);
                        }}
                      >
                        ({label})
                      </span>
                    );
                  })()}
                </div>
              );
            }

            const insn = row.insn;
            const bytesHex = Array.from(insn.bytes)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(" ");

            const isBookmarked = bookmarkSet.has(insn.address);
            const isLoopHeader = loopHeaders.has(insn.address);
            const loopDepth = loopHeaders.get(insn.address);
            const bodyDepth = loopBodyMap.get(insn.address);
            const isCurrentAddr = insn.address === state.currentAddress;
            const isSearchMatch =
              search.searchMatches.length > 0 &&
              search.searchMatchIdx >= 0 &&
              search.searchMatches[search.searchMatchIdx] === vItem.index;
            const rowSelected = isSelected(vItem.index);
            const isDimmed = insnFilter !== "all" && !matchesFilter(row);
            const isGapFill = insn.source === 'gap-fill';

            const operandTargets = pe ? parseOperandTargets(
              insn,
              pe.optionalHeader.imageBase,
              pe.optionalHeader.imageBase + pe.optionalHeader.sizeOfImage,
              iatMap,
            ) : [];

            // Build tooltip data for operand addresses
            let tooltipData: Map<number, string> | undefined;
            if (operandTargets.length > 0 && pe) {
              for (const t of operandTargets) {
                const addr = t.address;
                // Check IAT (imports)
                const iat = iatMap.get(addr);
                if (iat) {
                  if (!tooltipData) tooltipData = new Map();
                  tooltipData.set(addr, `Import: ${iat.lib}!${iat.func}`);
                  continue;
                }
                // Check strings
                const str = pe.strings?.get(addr);
                if (str) {
                  if (!tooltipData) tooltipData = new Map();
                  const preview = str.length > 60 ? str.slice(0, 60) + "..." : str;
                  tooltipData.set(addr, `"${preview}"`);
                  continue;
                }
                // Check functions
                const fn = state.functions.find(f => f.address === addr);
                if (fn) {
                  if (!tooltipData) tooltipData = new Map();
                  tooltipData.set(addr, `Function: ${getDisplayName(fn, state.renames)}`);
                  continue;
                }
                // Section lookup
                if (pe.sections) {
                  const rva = addr - pe.optionalHeader.imageBase;
                  for (const sec of pe.sections) {
                    if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
                      if (!tooltipData) tooltipData = new Map();
                      tooltipData.set(addr, `${sec.name} +0x${(rva - sec.virtualAddress).toString(16)}`);
                      break;
                    }
                  }
                }
              }
            }

            // Loop border styling: header takes priority, then body depth
            let borderStyle: string | undefined;
            if (isLoopHeader) {
              borderStyle = "2px solid #eab308"; // gold
            } else if (bodyDepth !== undefined) {
              if (bodyDepth >= 3) borderStyle = "2px solid rgba(239, 68, 68, 0.3)"; // red-500/30
              else if (bodyDepth === 2) borderStyle = "2px solid rgba(249, 115, 22, 0.3)"; // orange-500/30
              else borderStyle = "2px solid rgba(234, 179, 8, 0.3)"; // yellow-500/30
            }

            return (
              <div
                key={vItem.index}
                data-index={vItem.index}
                className={`disasm-row group disasm-grid${!showBytes ? " hide-bytes" : ""} ${
                  isSearchMatch
                    ? "bg-yellow-900/30"
                    : rowSelected
                      ? "bg-indigo-900/25"
                      : isCurrentAddr
                        ? "bg-blue-900/30"
                        : ""
                } ${isDimmed ? "opacity-30" : isGapFill ? "opacity-50" : ""}`}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: `${rowHeight}px`,
                  transform: `translateY(${vItem.start}px)`,
                  borderLeft: borderStyle,
                  padding: `0 var(--row-px)`,
                }}
                title={isLoopHeader ? `Loop header (depth ${loopDepth})` : bodyDepth !== undefined ? `Loop body (depth ${bodyDepth})` : undefined}
                onContextMenu={(e) => handleContextMenu(e, insn)}
                onClick={(e) => {
                  if (e.shiftKey) {
                    e.preventDefault();
                    const anchor = lastClickedRow ?? currentIndex;
                    setSelectionRange({ start: anchor, end: vItem.index });
                  } else {
                    setSelectionRange(null);
                    setLastClickedRow(vItem.index);
                    suppressScrollRef.current = true;
                    dispatch({ type: "SET_ADDRESS", address: insn.address });
                  }
                }}
              >
                <span className="text-right pr-1 flex items-center justify-end gap-0.5">
                  {isBookmarked && <span className="text-yellow-300">★</span>}
                  {(() => {
                    const xrefs = typedXrefMap.get(insn.address);
                    if (!xrefs || xrefs.length === 0 || funcMap.has(insn.address)) return null;
                    return (
                      <span
                        className="text-gray-600 hover:text-blue-400 cursor-pointer text-[9px]"
                        onClick={(e) => {
                          e.stopPropagation();
                          setXrefScopeAddress(insn.address);
                          setShowXrefPanel(true);
                        }}
                      >
                        ×{xrefs.length}
                      </span>
                    );
                  })()}
                </span>
                <span
                  className={`disasm-address cursor-pointer hover:text-blue-400 ${
                    copiedAddr === insn.address ? "text-green-400" : ""
                  }`}
                  onClick={() => handleAddressClick(insn.address)}
                  onDoubleClick={() => handleDoubleClickAddr(insn.address)}
                >
                  {insn.address
                    .toString(16)
                    .toUpperCase()
                    .padStart(addrWidth, "0")}
                </span>
                {showBytes && (
                  <span className="disasm-bytes truncate">
                    {bytesHex}
                  </span>
                )}
                <span
                  className={`disasm-mnemonic ${mnemonicClass(insn.mnemonic)}`}
                  title={MNEMONIC_HINTS[insn.mnemonic]}
                  onDoubleClick={() => handleDoubleClickInsn(insn)}
                >
                  {insn.mnemonic}
                </span>
                <span
                  className="disasm-operands overflow-hidden"
                  onDoubleClick={() => handleDoubleClickInsn(insn)}
                >
                  <ColoredOperand
                    opStr={insn.opStr}
                    targets={operandTargets}
                    onNavigate={handleAddressClick}
                    highlightRegs={highlightRegs}
                    onRegClick={handleRegClick}
                    tooltipData={tooltipData}
                  />
                </span>
                <span className="truncate flex items-center gap-1">
                  {insn.comment ? (
                    <span
                      className="disasm-comment truncate max-w-xs"
                      title={insn.comment.length > 60 ? insn.comment : undefined}
                    >
                      ; {insn.comment}
                    </span>
                  ) : insn.mnemonic === 'jmp' && (() => {
                    for (const t of operandTargets) {
                      const targetFn = funcMap.get(t.address);
                      if (targetFn && targetFn.address !== currentFunc?.address) {
                        return (
                          <span className="disasm-comment truncate max-w-xs">
                            ; tail call → {getDisplayName(targetFn, state.renames)}
                          </span>
                        );
                      }
                    }
                    return null;
                  })()}
                  {editingComment && editingComment.address === insn.address ? (
                    <span className="shrink-0">
                      <textarea
                        autoFocus
                        rows={1}
                        className="bg-gray-900/80 border border-blue-500 ring-1 ring-blue-500/50 rounded px-1.5 py-0.5 text-[#6ee7b7] text-xs font-mono outline-none w-64 resize-none align-middle"
                        placeholder="Add comment..."
                        value={editingComment.value}
                        onChange={(e) => setEditingComment({ ...editingComment, value: e.target.value })}
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && !e.shiftKey) {
                            e.preventDefault();
                            const val = editingComment.value.trim();
                            if (val) {
                              dispatch({ type: "SET_COMMENT", address: editingComment.address, text: val });
                            } else {
                              dispatch({ type: "DELETE_COMMENT", address: editingComment.address });
                            }
                            setEditingComment(null);
                          }
                          if (e.key === "Escape") setEditingComment(null);
                          e.stopPropagation();
                        }}
                        onBlur={() => setEditingComment(null)}
                      />
                    </span>
                  ) : state.comments[insn.address] ? (
                    <span
                      className="disasm-user-comment truncate max-w-xs"
                      title={state.comments[insn.address]}
                    >
                      ; {state.comments[insn.address].includes("\n") ? state.comments[insn.address].split("\n")[0] + " [...]" : state.comments[insn.address]}
                    </span>
                  ) : isCurrentAddr && !insn.comment ? (
                    <span className="text-gray-600 text-[10px] opacity-0 group-hover:opacity-100 transition-opacity select-none">
                      press ; to comment
                    </span>
                  ) : null}
                </span>
              </div>
            );
          })}

          {/* Context menu */}
          {ctxMenu && (() => {
            const branchTarget = parseBranchTarget(ctxMenu.insn.mnemonic, ctxMenu.insn.opStr);
            const xrefCount = xrefCountMap.get(ctxMenu.insn.address) ?? 0;
            const hasComment = !!(state.comments[ctxMenu.insn.address] || ctxMenu.insn.comment);
            const isFuncHead = funcMap.has(ctxMenu.insn.address);
            const menuItem = (label: string, onClick: () => void, hint?: string) => (
              <button onClick={onClick} className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200 flex items-center justify-between">
                <span>{label}</span>
                {hint && <span className="text-gray-500 text-[9px] ml-4">{hint}</span>}
              </button>
            );
            const sep = <div className="border-t border-gray-800 my-0.5" />;
            return (
              <div
                className="absolute z-50 backdrop-blur-sm bg-gray-900/95 border border-gray-700 rounded-lg shadow-xl py-1 text-xs min-w-[200px]"
                style={{ left: ctxMenu.x, top: ctxMenu.y }}
                onClick={(e) => e.stopPropagation()}
              >
                {menuItem("Copy address", ctxCopyAddr)}
                {menuItem("Copy instruction", ctxCopyInsn)}
                {menuItem("Copy bytes", ctxCopyBytes)}
                {sep}
                {branchTarget !== null && menuItem("Follow target", ctxFollowTarget, "Enter")}
                {xrefCount > 0 && menuItem(`Show xrefs (${xrefCount})`, ctxShowXrefs, "R")}
                {(branchTarget !== null || xrefCount > 0) && sep}
                {menuItem("Go to address...", ctxGoTo, "G")}
                {menuItem("Show in Hex", ctxShowInHex)}
                {sep}
                {menuItem("Toggle bookmark", ctxToggleBookmark, "B")}
                {menuItem("Add/Edit comment", ctxAddComment, ";")}
                {hasComment && menuItem("Copy comment", ctxCopyComment)}
                {isFuncHead && menuItem("Rename function", ctxRenameFunction, "N")}
                {selectionRange && (() => {
                  const lo = Math.min(selectionRange.start, selectionRange.end);
                  const hi = Math.max(selectionRange.start, selectionRange.end);
                  const count = hi - lo + 1;
                  return (
                    <>
                      {sep}
                      {menuItem(`Copy selected (${count} rows)`, () => {
                        navigator.clipboard.writeText(formatRangeCopy(selectionRange, rows, pe, state.renames, state.comments));
                        setCtxMenu(null);
                      })}
                    </>
                  );
                })()}
              </div>
            );
          })()}

        </div>
      </div>
      ) : currentFunc ? (
      <CFGView
        func={currentFunc}
        instructions={instructions}
        typedXrefMap={typedXrefMap}
        jumpTables={disasmWorker.jumpTables}
        currentAddress={state.currentAddress}
        pe={pe}
        onNavigate={(addr) => {
          suppressScrollRef.current = true;
          dispatch({ type: "SET_ADDRESS", address: addr });
        }}
        onAddressClick={handleAddressClick}
        onDoubleClickAddr={handleDoubleClickAddr}
        onContextMenu={handleContextMenu}
        onRegClick={handleRegClick}
        highlightRegs={highlightRegs}
        copiedAddr={copiedAddr}
        editingComment={editingComment}
        onEditComment={setEditingComment}
        comments={state.comments}
        renames={state.renames}
        bookmarkSet={bookmarkSet}
        iatMap={iatMap}
        pan={graphPan}
        zoom={graphZoom}
        onPanChange={setGraphPan}
        onZoomChange={setGraphZoom}
        collapsedBlocks={collapsedBlocks}
        onToggleCollapse={handleToggleCollapse}
        onCommentSubmit={(addr, text) => dispatch({ type: "SET_COMMENT", address: addr, text })}
        onCommentDelete={(addr) => dispatch({ type: "DELETE_COMMENT", address: addr })}
        restorePanZoom={restorePanZoom}
        reCenterTrigger={reCenterTrigger}
        searchMatches={showGraphSearch ? graphSearchMatchSet : undefined}
        currentSearchMatch={showGraphSearch ? graphSearchCurrentMatch : undefined}
        onNavBack={() => {
          if (state.callStack.length > 0) {
            const last = state.callStack[state.callStack.length - 1];
            if (last.viewSnapshot) {
              setViewMode(last.viewSnapshot.viewMode);
              setRestorePanZoom({ pan: last.viewSnapshot.graphPan, zoom: last.viewSnapshot.graphZoom });
            }
            dispatch({ type: "SET_ADDRESS", address: last.address });
            dispatch({ type: "POP_CALL_STACK", index: state.callStack.length - 1 });
          } else {
            const destAddr = state.historyIndex > 0 ? state.addressHistory[state.historyIndex - 1] : undefined;
            if (destAddr !== undefined) {
              const saved = navViewStateMapRef.current.get(destAddr);
              if (saved) {
                setViewMode(saved.viewMode);
                setRestorePanZoom({ pan: saved.graphPan, zoom: saved.graphZoom });
              }
            }
            dispatch({ type: "NAV_BACK" });
          }
        }}
      />
      ) : (
        <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
          No function selected
        </div>
      )}
      {/* Context menu (graph mode) */}
      {viewMode === "graph" && ctxMenu && (() => {
        const branchTarget = parseBranchTarget(ctxMenu.insn.mnemonic, ctxMenu.insn.opStr);
        const xrefCount = xrefCountMap.get(ctxMenu.insn.address) ?? 0;
        const hasComment = !!(state.comments[ctxMenu.insn.address] || ctxMenu.insn.comment);
        const isFuncHead = funcMap.has(ctxMenu.insn.address);
        const menuItem = (label: string, onClick: () => void, hint?: string) => (
          <button onClick={onClick} className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200 flex items-center justify-between">
            <span>{label}</span>
            {hint && <span className="text-gray-500 text-[9px] ml-4">{hint}</span>}
          </button>
        );
        const sep = <div className="border-t border-gray-800 my-0.5" />;
        return (
          <div
            className="absolute z-50 backdrop-blur-sm bg-gray-900/95 border border-gray-700 rounded-lg shadow-xl py-1 text-xs min-w-[200px]"
            style={{ left: ctxMenu.x, top: ctxMenu.y }}
            onClick={(e) => e.stopPropagation()}
          >
            {menuItem("Copy address", ctxCopyAddr)}
            {menuItem("Copy instruction", ctxCopyInsn)}
            {menuItem("Copy bytes", ctxCopyBytes)}
            {sep}
            {branchTarget !== null && menuItem("Follow target", ctxFollowTarget, "Enter")}
            {xrefCount > 0 && menuItem(`Show xrefs (${xrefCount})`, ctxShowXrefs, "R")}
            {(branchTarget !== null || xrefCount > 0) && sep}
            {menuItem("Go to address...", ctxGoTo, "G")}
            {menuItem("Show in Hex", ctxShowInHex)}
            {sep}
            {menuItem("Toggle bookmark", ctxToggleBookmark, "B")}
            {menuItem("Add/Edit comment", ctxAddComment, ";")}
            {hasComment && menuItem("Copy comment", ctxCopyComment)}
            {isFuncHead && menuItem("Rename function", ctxRenameFunction, "N")}
          </div>
        );
      })()}
      {/* Graph search overlay */}
      {showGraphSearch && viewMode === "graph" && (
        <div className="absolute top-3 left-1/2 -translate-x-1/2 z-40 bg-gray-800 border border-gray-600 rounded-lg shadow-xl px-3 py-2 flex items-center gap-2 text-xs">
          <input
            ref={graphSearchInputRef}
            type="text"
            value={graphSearchQuery}
            onChange={(e) => handleGraphSearch(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") {
                if (e.shiftKey) graphSearchPrevMatch();
                else graphSearchNextMatch();
              }
              if (e.key === "Escape") closeGraphSearch();
              e.stopPropagation();
            }}
            placeholder="Search instructions... (/regex/i)"
            className="w-56 px-2 py-1 bg-gray-900 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 text-[11px]"
          />
          <span className="text-gray-400 text-[10px] min-w-[60px] text-center">
            {graphSearchMatches.length > 0
              ? `${graphSearchIdx + 1}/${graphSearchMatches.length}`
              : graphSearchQuery ? "0 matches" : ""}
          </span>
          <button
            onClick={graphSearchPrevMatch}
            disabled={graphSearchMatches.length === 0}
            className="text-gray-400 hover:text-white disabled:opacity-30 px-1"
            title="Previous match (Shift+Enter)"
          >
            ▲
          </button>
          <button
            onClick={graphSearchNextMatch}
            disabled={graphSearchMatches.length === 0}
            className="text-gray-400 hover:text-white disabled:opacity-30 px-1"
            title="Next match (Enter)"
          >
            ▼
          </button>
          <button
            onClick={closeGraphSearch}
            className="text-gray-500 hover:text-white px-1"
            title="Close (Escape)"
          >
            ✕
          </button>
        </div>
      )}
      {showMinimap && viewMode === "linear" && (
        <DisassemblyMinimap
          rows={rows}
          bookmarkSet={bookmarkSet}
          searchMatches={search.searchMatches}
          viewportStartIdx={virtualizer.range?.startIndex ?? 0}
          viewportEndIdx={virtualizer.range?.endIndex ?? 0}
          loopRanges={loops}
          onScrollTo={(idx) => {
            virtualizer.scrollToIndex(idx, { align: "center" });
            const addr = rowAddress(rows[idx]);
            if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
          }}
          mode="linear"
          currentAddress={state.currentAddress}
          commentAddrs={commentAddrSet}
        />
      )}
      {showDecompile && (
        <>
          <ResizeHandle
            orientation="horizontal"
            onResize={(delta) => {
              // Negative delta = dragging left = panel grows
              setDecompileWidth((prev) => {
                const newW = Math.max(100, prev - delta);
                return newW;
              });
            }}
            onResizeEnd={() => {
              try { localStorage.setItem("peek-a-bin:decompile-width", String(decompileWidth)); } catch {}
            }}
          />
          <div className="shrink-0" style={{ width: decompileWidth }}>
            <DecompileView
              code={decompile.activeCode}
              loading={decompile.activeLoading}
              error={decompile.activeError}
              activeTab={decompile.tabsState.activeTab}
              onTabChange={(tab) => decompile.triggerTab(tab)}
              highLevelEngine={decompile.tabsState.high.engine}
              aiMode={decompile.tabsState.aiMode}
              onEnhance={() => decompile.triggerAI("enhance")}
              onExplain={() => decompile.triggerAI("explain")}
              onCancelAI={decompile.cancelAI}
              onNavigate={(addr) => dispatch({ type: "SET_ADDRESS", address: addr })}
              onClose={() => setShowDecompile(false)}
              highlightLines={decompileHighlightLines}
              onLineClick={handleDecompileLineClick}
              syncDisabled={decompile.syncDisabled}
              scrollSyncEnabled={scrollSyncEnabled}
              onScrollSyncToggle={() => {
                setScrollSyncEnabled((v) => {
                  const next = !v;
                  try { localStorage.setItem("peek-a-bin:scroll-sync", String(next)); } catch {}
                  if (!next) setScrollSyncAddr(null);
                  return next;
                });
              }}
              comments={state.comments}
              lineMap={decompile.activeLineMap}
              editingComment={editingComment}
              onEditComment={setEditingComment}
              onCommitComment={(addr, text) => dispatch({ type: "SET_COMMENT", address: addr, text })}
              onDeleteComment={(addr) => dispatch({ type: "DELETE_COMMENT", address: addr })}
            />
          </div>
        </>
      )}
      </div>{/* end flex wrapper for content + minimap */}

      {/* Tabbed bottom panels */}
      <BottomPanelContainer
        panels={[
          {
            id: "calls",
            label: "Calls",
            visible: showCallPanel && !!currentFunc,
            onClose: () => setShowCallPanel(false),
            content: currentFunc ? (
              <CallPanel
                func={currentFunc}
                xrefMap={xrefMap}
                instructions={instructions}
                functions={state.functions}
                renames={state.renames}
                onNavigate={(addr) => dispatch({ type: "SET_ADDRESS", address: addr })}
                onClose={() => setShowCallPanel(false)}
              />
            ) : null,
          },
          {
            id: "detail",
            label: "Detail",
            visible: showDetail && isExecutable,
            onClose: () => setShowDetail(false),
            content: curInsnForDetail ? (
              <InstructionDetail
                insn={curInsnForDetail}
                typedXrefMap={typedXrefMap}
                funcMap={funcMap}
                iatMap={iatMap}
                renames={state.renames}
                sortedFuncs={sortedFuncs}
                onNavigate={(addr) => dispatch({ type: "SET_ADDRESS", address: addr })}
                onClose={() => setShowDetail(false)}
                stackFrame={stackFrame}
                signature={currentFuncSig}
              />
            ) : null,
          },
          {
            id: "xrefs",
            label: "Xrefs",
            visible: showXrefPanel,
            onClose: () => { setShowXrefPanel(false); setXrefScopeAddress(null); },
            content: (
              <XrefPanel
                typedXrefMap={typedXrefMap}
                funcMap={funcMap}
                sortedFuncs={sortedFuncs}
                pe={pe}
                onNavigate={(addr) => dispatch({ type: "SET_ADDRESS", address: addr })}
                onClose={() => { setShowXrefPanel(false); setXrefScopeAddress(null); }}
                scopeAddress={xrefScopeAddress}
                currentFuncAddr={currentFunc?.address ?? null}
                currentFuncEnd={currentFunc ? currentFunc.address + currentFunc.size : null}
                currentInsnAddr={state.currentAddress}
              />
            ),
          },
        ]}
      />

      {/* Shortcut legend overlay */}
      {showShortcuts && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/40" onClick={() => setShowShortcuts(false)}>
          <div
            className="bg-gray-800 border border-gray-600 rounded-lg shadow-xl p-4 text-xs max-w-sm"
            onClick={(e) => e.stopPropagation()}
          >
            <h3 className="text-sm font-semibold text-gray-200 mb-3">Keyboard Shortcuts</h3>
            <table className="w-full">
              <tbody>
                {([
                  ["Space", "Toggle linear / graph view"],
                  ["G", "Go to address (focus address bar)"],
                  ["/ or Ctrl+F", "Search in disassembly"],
                  ["Enter", "Follow branch / next search result"],
                  ["Shift+Enter", "Previous search result"],
                  ["N", "Rename current function"],
                  ["Esc", "Navigate back"],
                  [";", "Add/edit comment (disassembly + pseudocode)"],
                  ["I", "Toggle instruction detail panel"],
                  ["X", "Toggle callers/callees panel"],
                  ["R", "Toggle cross-reference panel"],
                  ["D", "Toggle decompile panel"],
                  ["B", "Toggle bookmark at current address"],
                  ["0", "Zoom-to-fit (graph mode)"],
                  ["Tab", "Cycle successor blocks (graph mode)"],
                  ["Ctrl+P", "Command palette"],
                  ["Ctrl+Z", "Undo annotation"],
                  ["Ctrl+Shift+Z", "Redo annotation"],
                  ["↑ / ↓", "Navigate instructions"],
                  ["PgUp / PgDn", "Scroll 40 instructions"],
                  ["1–7", "Switch tabs"],
                  ["Alt+← / Alt+→", "Navigate back / forward"],
                  ["?", "Toggle this help"],
                  ["Double-click addr", "Copy address"],
                  ["Double-click label", "Rename function"],
                  ["Shift+Click", "Select range of instructions"],
                  ["Ctrl/Cmd+C", "Copy selected instructions"],
                  ["Right-click", "Context menu"],
                ] as [string, string][]).map(([key, desc]) => (
                  <tr key={key} className="border-b border-gray-700/50">
                    <td className="py-1 pr-4 text-blue-400 font-mono whitespace-nowrap">{key}</td>
                    <td className="py-1 text-gray-300">{desc}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="mt-3 text-gray-500 text-center">Press ? or Esc to close</div>
          </div>
        </div>
      )}
    </div>
  );
}
