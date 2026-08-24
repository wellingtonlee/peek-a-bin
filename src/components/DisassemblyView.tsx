import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { archForMachine } from "../disasm/arch";
import { buildCFG, layoutCFG } from "../disasm/cfg";
import { canonReg } from "../disasm/decompile/ir";
import { type FunctionSignature, inferSignature } from "../disasm/signatures";
import { arm64UnwindContext, stackFrameFor } from "../disasm/stackFrame";
import type { DisasmFunction, Instruction } from "../disasm/types";
import { useAIChat } from "../hooks/useAIChat";
import { useDecompileTabs } from "../hooks/useDecompileTabs";
import { useContainingFunc, useSectionInfo, useSortedFuncs } from "../hooks/useDerivedState";
import { useDisassemblyKeyboard } from "../hooks/useDisassemblyKeyboard";
import type { DisplayRow } from "../hooks/useDisassemblyRows";
import { binarySearchRows, rowAddress, useDisassemblyRows } from "../hooks/useDisassemblyRows";
import { useDisassemblySearch } from "../hooks/useDisassemblySearch";
import { useDismissOnOutsideClick } from "../hooks/useDismissOnOutsideClick";
import { useSetGraphOverview } from "../hooks/useGraphOverview";
import { useGraphSearch } from "../hooks/useGraphSearch";
import { type ContextMenuState, useInsnContextMenu } from "../hooks/useInsnContextMenu";
import { getDisplayName, useAppDispatch, useAppState } from "../hooks/usePEFile";
import { useVulnScanner } from "../hooks/useVulnScanner";
import { isAddressOutsideCode } from "../pe/sections";
import type { PEFile } from "../pe/types";
import { disasmWorker } from "../workers/disasmClient";
import { AIChatPanel } from "./AIChatPanel";
import { analysisNotice, VIEW_TAB_LABELS } from "./analysisNotice";
import { BottomPanelContainer } from "./BottomPanelContainer";
import { Breadcrumbs } from "./Breadcrumbs";
import { CallPanel } from "./CallPanel";
import { CFGView } from "./CFGView";
import { DecompileView } from "./DecompileView";
import { DisassemblyMinimap } from "./DisassemblyMinimap";
import { DataRow, InsnRow, LabelRow, SeparatorRow } from "./DisassemblyRows";
import { DisassemblyToolbar } from "./DisassemblyToolbar";
import { InsnContextMenu } from "./InsnContextMenu";
import { InstructionDetail } from "./InstructionDetail";
import { JumpArrows } from "./JumpArrows";
import { ResizeHandle } from "./ResizeHandle";
import { XrefPanel } from "./XrefPanel";

const _SUSPICIOUS_MNEMONICS = new Set([
  "int",
  "sysenter",
  "syscall",
  "in",
  "out",
  "rdtsc",
  "cpuid",
]);

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
      const bytesHex = Array.from(insn.bytes)
        .map((b) => b.toString(16).toUpperCase().padStart(2, "0"))
        .join(" ")
        .padEnd(24);
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
      } else if (
        (item.directive === "dd" || item.directive === "dq") &&
        item.pointerTarget != null
      ) {
        value = `0x${item.pointerTarget.toString(16).toUpperCase()}`;
      } else {
        value = Array.from(item.bytes)
          .map((b) => b.toString(16).toUpperCase().padStart(2, "0") + "h")
          .join(", ");
      }
      const c = item.pointerLabel
        ? `  ; ${item.pointerLabel}`
        : item.stringValue
          ? `  ; ${item.stringType ?? ""}`
          : "";
      const uc = comments[item.address] ? `  ; ${comments[item.address]}` : "";
      lines.push(`${addrHex}  ${item.directive.padEnd(8)}${value}${c}${uc}`);
    }
  }
  return lines.join("\n");
}

// XrefPopupState removed — replaced by XrefPanel with scoped filter

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
  const currentFunc = useContainingFunc();
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

  const commentAddrSet = useMemo(
    () =>
      new Set(
        Object.keys(state.comments)
          .filter((k) => state.comments[Number(k)])
          .map(Number),
      ),
    [state.comments],
  );

  // Search hook
  const search = useDisassemblySearch(rows, currentIndex);

  // Local UI states
  const [copiedAddr, setCopiedAddr] = useState<number | null>(null);
  const [ctxMenu, setCtxMenu] = useState<ContextMenuState | null>(null);
  const [xrefScopeAddress, setXrefScopeAddress] = useState<number | null>(null);
  const [renamingLabel, setRenamingLabel] = useState<{ address: number; value: string } | null>(
    null,
  );
  const [editingComment, setEditingComment] = useState<{ address: number; value: string } | null>(
    null,
  );
  const [showCallPanel, setShowCallPanel] = useState(false);
  const [insnFilter, setInsnFilter] = useState<
    "all" | "calls" | "jumps" | "stringrefs" | "suspicious"
  >("all");
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
  const [restorePanZoom, setRestorePanZoom] = useState<{
    pan: { x: number; y: number };
    zoom: number;
  } | null>(null);
  const navViewStateMapRef = useRef<
    Map<
      number,
      { viewMode: "linear" | "graph"; graphPan: { x: number; y: number }; graphZoom: number }
    >
  >(new Map());
  const cfgContainerRef = useRef<HTMLDivElement>(null);
  // Only one of the two context-menu render sites is mounted at a time.
  const ctxMenuRef = useRef<HTMLDivElement>(null);
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
    try {
      return localStorage.getItem("peek-a-bin:scroll-sync") !== "false";
    } catch {
      return true;
    }
  });
  const [scrollSyncAddr, setScrollSyncAddr] = useState<number | null>(null);
  const scrollSyncTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [showBytes, setShowBytes] = useState(() => {
    try {
      return localStorage.getItem("peek-a-bin:show-bytes") !== "false";
    } catch {
      return true;
    }
  });
  const [decompileWidth, setDecompileWidth] = useState(() => {
    try {
      const v = localStorage.getItem("peek-a-bin:decompile-width");
      if (v) {
        const n = parseInt(v, 10);
        if (n >= 100) return n;
      }
    } catch {}
    return 500;
  });

  // AI Chat panel
  const [showChat, setShowChat] = useState(false);
  const [chatWidth, setChatWidth] = useState(() => {
    try {
      const v = localStorage.getItem("peek-a-bin:chat-width");
      if (v) {
        const n = parseInt(v, 10);
        if (n >= 200) return n;
      }
    } catch {}
    return 380;
  });

  // Listen for chat toggle events from toolbar
  useEffect(() => {
    const handler = () => setShowChat((v) => !v);
    window.addEventListener("peek-a-bin:open-chat", handler);
    return () => window.removeEventListener("peek-a-bin:open-chat", handler);
  }, []);

  // Register highlight family set
  const highlightRegs = useMemo(() => {
    if (!highlightedReg) return null;
    return buildRegFamily(highlightedReg);
  }, [highlightedReg]);

  const handleRegClick = useCallback((regName: string) => {
    const canon = canonReg(regName);
    setHighlightedReg((prev) => (prev === canon ? null : canon));
  }, []);

  const iatMap = state.iatMap;

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

  // Function signature inference.
  //
  // The architecture is what selects the grammar; `pe.is64` is only the width
  // within the x86 one, and it is true for an ARM64 image too. Before this was
  // threaded, every A64 function reported `fastcall, 0 params` here and
  // `InstructionDetail` rendered it (peek-a-bin-56q item 1).
  const currentFuncSig = useMemo((): FunctionSignature | null => {
    if (!currentFunc || instructions.length === 0 || !pe) return null;
    return inferSignature(
      currentFunc,
      instructions,
      archForMachine(pe.coffHeader.machine),
      pe.is64,
    );
  }, [currentFunc, instructions, pe]);

  // Lazy per-label signature cache (only compute for visible labels)
  const sigCacheRef = useRef<{ insnsId: Instruction[]; cache: Map<number, FunctionSignature> }>({
    insnsId: [],
    cache: new Map(),
  });
  if (sigCacheRef.current.insnsId !== instructions) {
    sigCacheRef.current = { insnsId: instructions, cache: new Map() };
  }
  const getSigForFunc = (fn: DisasmFunction): FunctionSignature | null => {
    if (!pe || instructions.length === 0) return null;
    const cached = sigCacheRef.current.cache.get(fn.address);
    if (cached) return cached;
    const sig = inferSignature(fn, instructions, archForMachine(pe.coffHeader.machine), pe.is64);
    if (sig === null) return null;
    if (sig.paramCount > 0) sigCacheRef.current.cache.set(fn.address, sig);
    return sig.paramCount > 0 ? sig : null;
  };

  // Stack frame analysis (lazy, only when detail panel is open)
  const stackFrame = useMemo(() => {
    if (!showDetail || !currentFunc || instructions.length === 0) return null;
    // `archForMachine(undefined)` is the documented "the caller never told us"
    // default and answers x86, which is what the `pe?.is64 ?? true` beside it
    // has always assumed.
    //
    // `stackFrameFor` rather than `analyzeStackFrame` because this panel is the
    // one surface an ARM64 frame can reach: the A64 grammar reads the frame out
    // of `.pdata`, and without the unwind context it would answer null for
    // every A64 function exactly as before (peek-a-bin-hof0).
    return stackFrameFor(
      currentFunc,
      instructions,
      archForMachine(pe?.coffHeader.machine),
      pe?.is64 ?? true,
      pe ? arm64UnwindContext(pe) : undefined,
    );
  }, [showDetail, currentFunc, instructions, pe]);

  // Current instruction for detail panel
  const curInsnForDetail = useMemo((): Instruction | null => {
    if (!showDetail || instructions.length === 0) return null;
    let lo = 0,
      hi = instructions.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (instructions[mid].address === state.currentAddress) return instructions[mid];
      if (instructions[mid].address < state.currentAddress) lo = mid + 1;
      else hi = mid - 1;
    }
    return instructions[Math.min(lo, instructions.length - 1)];
  }, [showDetail, instructions, state.currentAddress]);

  const SUSPICIOUS_MNEMONICS = _SUSPICIOUS_MNEMONICS;

  const matchesFilter = useCallback(
    (row: DisplayRow): boolean => {
      if (insnFilter === "all") return true;
      if (row.kind !== "insn") return true; // labels/separators always match
      const insn = row.insn;
      switch (insnFilter) {
        case "calls":
          return insn.mnemonic === "call";
        case "jumps":
          return insn.mnemonic === "jmp" || insn.mnemonic.startsWith("j");
        case "stringrefs":
          return insn.comment != null || state.comments[insn.address] != null;
        case "suspicious":
          return SUSPICIOUS_MNEMONICS.has(insn.mnemonic);
        default:
          return true;
      }
    },
    [insnFilter, state.comments],
  );

  const filterMatchCount = useMemo(() => {
    if (insnFilter === "all") return 0;
    let count = 0;
    for (const row of rows) {
      if (row.kind === "insn" && matchesFilter(row)) count++;
    }
    return count;
  }, [rows, insnFilter, matchesFilter]);

  const isSelected = useCallback(
    (rowIndex: number): boolean => {
      if (!selectionRange) return false;
      const lo = Math.min(selectionRange.start, selectionRange.end);
      const hi = Math.max(selectionRange.start, selectionRange.end);
      return rowIndex >= lo && rowIndex <= hi;
    },
    [selectionRange],
  );

  const rowHeight = 20;
  const sepHeight = 12;

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) => (rows[index]?.kind === "separator" ? sepHeight : rowHeight),
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
    try {
      localStorage.setItem("peek-a-bin:view-mode", viewMode);
    } catch {}
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
      setViewMode((v) => (v === "graph" ? "linear" : "graph"));
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [search.showSearch, currentFunc]);

  // Reset collapsed blocks on function change.
  //
  // The dependency is deliberately a key the body never reads: the effect
  // exists precisely to fire when the containing function changes. Dropping it
  // to satisfy the rule would run the reset once and never again, leaving the
  // previous function's collapsed block IDs applied to the new graph.
  // biome-ignore lint/correctness/useExhaustiveDependencies: currentFunc?.address is the change key this effect is triggered by, not a value it reads.
  useEffect(() => {
    setCollapsedBlocks(new Set());
  }, [currentFunc?.address]);

  const handleToggleCollapse = useCallback((blockId: number) => {
    setCollapsedBlocks((prev) => {
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
    // useVirtualizer holds its instance in useState, so `virtualizer` is a
    // stable reference for the component's lifetime and adding it here cannot
    // make this effect re-fire.
  }, [currentIndex, rows.length, viewMode, virtualizer]);

  // Dispatch current instruction & block info for status bar
  useEffect(() => {
    const row = rows[currentIndex];
    if (row && row.kind === "insn") {
      dispatch({
        type: "SET_CURRENT_INSTRUCTION",
        instruction: { bytes: Array.from(row.insn.bytes), size: row.insn.size },
      });
      // Find block range from rows with same blockIdx
      const blockIdx = row.blockIdx;
      let startAddr = row.insn.address,
        endAddr = row.insn.address;
      for (let i = currentIndex; i >= 0; i--) {
        const r = rows[i];
        if (r?.kind !== "insn" || r.blockIdx !== blockIdx) break;
        startAddr = r.insn.address;
      }
      for (let i = currentIndex; i < rows.length; i++) {
        const r = rows[i];
        if (r?.kind !== "insn" || r.blockIdx !== blockIdx) break;
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

  // Dismiss context menu / export menu on click outside or Escape.
  // Clicks inside the menu are ignored via ctxMenuRef rather than being stopped
  // from propagating by a handler on the menu div. The export menu has no ref of
  // its own, so a click on one of its items both runs the item and closes it.
  useDismissOnOutsideClick({
    active: ctxMenu !== null || showExportMenu,
    ref: ctxMenuRef,
    onDismiss: () => {
      setCtxMenu(null);
      setShowExportMenu(false);
    },
    event: "click",
    target: "window",
    dismissOnEscape: true,
    dismissIfRefMissing: true,
  });

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
      if (e.button === 3) {
        e.preventDefault();
        dispatch({ type: "NAV_BACK" });
      }
      if (e.button === 4) {
        e.preventDefault();
        dispatch({ type: "NAV_FORWARD" });
      }
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

  const {
    handleGraphSearch,
    graphSearchNextMatch,
    graphSearchPrevMatch,
    closeGraphSearch,
    graphSearchMatchSet,
    graphSearchCurrentMatch,
  } = useGraphSearch({
    instructions,
    dispatch,
    setCollapsedBlocks,
    graphSearchMatches,
    graphSearchIdx,
    setShowGraphSearch,
    setGraphSearchQuery,
    setGraphSearchMatches,
    setGraphSearchIdx,
  });

  const { decompileToggleRef, handleKeyDown } = useDisassemblyKeyboard({
    search,
    parentRef,
    searchInputRef,
    graphSearchInputRef,
    cfgContainerRef,
    navViewStateMapRef,
    highlightedReg,
    setHighlightedReg,
    ctxMenu,
    setCtxMenu,
    selectionRange,
    setSelectionRange,
    setViewMode,
    setRestorePanZoom,
    setEditingComment,
    setRenamingLabel,
    setShowCallPanel,
    setShowXrefPanel,
    setShowDetail,
    setShowGraphSearch,
    dispatch,
    rows,
    pe,
    currentIndex,
    currentFunc,
    virtualizer,
    viewMode,
    graphPan,
    graphZoom,
    currentAddress: state.currentAddress,
    comments: state.comments,
    renames: state.renames,
    callStack: state.callStack,
    addressHistory: state.addressHistory,
    historyIndex: state.historyIndex,
    buildCFGForNav,
    formatRangeCopy,
  });

  const handleAddressClick = useCallback(
    (address: number) => {
      const vs = { viewMode, graphPan, graphZoom };
      // Always save view state for back-navigation (not just function targets)
      navViewStateMapRef.current.set(state.currentAddress, vs);

      if (currentFunc) {
        dispatch({
          type: "PUSH_CALL_STACK",
          address: state.currentAddress,
          name: getDisplayName(currentFunc, state.renames),
          viewSnapshot: vs,
        });
      }

      // Auto-switch to linear when navigating to non-executable section from graph
      if (
        viewMode === "graph" &&
        pe &&
        isAddressOutsideCode(pe.sections, pe.optionalHeader.imageBase, address)
      ) {
        setViewMode("linear");
      }

      dispatch({ type: "SET_ADDRESS", address });
    },
    [dispatch, currentFunc, state.currentAddress, state.renames, viewMode, graphPan, graphZoom, pe],
  );

  const handleDoubleClickAddr = useCallback((address: number) => {
    const hex = "0x" + address.toString(16).toUpperCase();
    navigator.clipboard.writeText(hex).then(() => {
      setCopiedAddr(address);
      setTimeout(() => setCopiedAddr(null), 1000);
    });
  }, []);

  const handleDoubleClickInsn = useCallback((insn: Instruction) => {
    const text = `${insn.mnemonic} ${insn.opStr}`;
    navigator.clipboard.writeText(text);
  }, []);

  // Context menu actions
  const {
    actions: ctxActions,
    xrefCountMap,
    handleContextMenu,
  } = useInsnContextMenu({
    ctxMenu,
    setCtxMenu,
    pe,
    dispatch,
    comments: state.comments,
    renames: state.renames,
    funcMap,
    typedXrefMap,
    setEditingComment,
    setRenamingLabel,
    setShowXrefPanel,
    handleAddressClick,
    viewMode,
    cfgContainerRef,
    parentRef,
  });

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
    functions: state.functions,
    renames: state.renames,
    buildFunctionAsm,
  });

  // AI Chat — use decompile code as context
  const aiChat = useAIChat(pe ?? null, state.fileName, decompile.activeCode || null);

  // Vuln scanner (for context menu "scan" action)
  const vulnScanner = useVulnScanner(state, dispatch);

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

  // Keep the D-key handler pointing at the current toggle. Assigned during
  // render rather than in an effect: a keypress can be handled before effects
  // flush, and a stale ref there would reintroduce exactly the bug this fixes.
  decompileToggleRef.current = handleDecompileToggle;

  // Re-decompile when function changes while panel is open
  const prevDecompFuncRef = useRef<number | null>(null);
  useEffect(() => {
    if (!showDecompile || !currentFunc) return;
    if (prevDecompFuncRef.current === currentFunc.address) return;
    prevDecompFuncRef.current = currentFunc.address;
    decompile.resetForNewFunc();
    decompile.triggerTab(decompile.tabsState.activeTab);
    // `currentFunc` rather than `currentFunc?.address`: the body reads both, and
    // useContainingFunc returns the element out of the sorted function array, so
    // the reference is unchanged while the address stays inside the same
    // function. prevDecompFuncRef still guards the body against a re-run.
  }, [showDecompile, currentFunc, decompile]);

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
  const syncAddr =
    scrollSyncEnabled && showDecompile && scrollSyncAddr !== null
      ? scrollSyncAddr
      : state.currentAddress;

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

  const handleDecompileLineClick = useCallback(
    (lineNum: number) => {
      if (decompile.syncDisabled) return;
      const addr = decompile.activeLineMap.get(lineNum);
      if (addr !== undefined) {
        dispatch({ type: "SET_ADDRESS", address: addr });
      }
    },
    [decompile.activeLineMap, decompile.syncDisabled, dispatch],
  );

  const handleExportAsm = useCallback(
    (mode: "function" | "section") => {
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
            const userComment = state.comments[insn.address]
              ? `  ; ${state.comments[insn.address]}`
              : "";
            lines.push(`  ${addrHex}  ${insn.mnemonic} ${insn.opStr}${comment}${userComment}`);
          } else if (row.kind === "label") {
            if (
              row.fn.address >= currentFunc.address &&
              row.fn.address < endAddr &&
              row.fn.address !== currentFunc.address
            ) {
              lines.push(`\n; ──── ${getDisplayName(row.fn, state.renames)} ────`);
            }
          }
        }
      } else {
        // Entire section
        const totalLines = rows.filter((r) => r.kind === "insn").length;
        if (
          totalLines > 50000 &&
          !confirm(`This will export ${totalLines.toLocaleString()} lines. Continue?`)
        )
          return;
        for (const row of rows) {
          if (row.kind === "label") {
            const name = getDisplayName(row.fn, state.renames);
            lines.push(`\n; ──── ${name} ────`);
          } else if (row.kind === "insn") {
            const insn = row.insn;
            const addrHex = insn.address.toString(16).toUpperCase().padStart(aw, "0");
            const comment = insn.comment ? `  ; ${insn.comment}` : "";
            const userComment = state.comments[insn.address]
              ? `  ; ${state.comments[insn.address]}`
              : "";
            lines.push(`  ${addrHex}  ${insn.mnemonic} ${insn.opStr}${comment}${userComment}`);
          }
        }
      }

      const text = lines.join("\n");
      const blob = new Blob([text], { type: "text/plain" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      const label =
        mode === "function" && currentFunc
          ? getDisplayName(currentFunc, state.renames).replace(/[^a-zA-Z0-9_]/g, "_")
          : (sectionInfo?.name ?? "section");
      a.href = url;
      a.download = `${state.fileName ?? "export"}_${label}.asm`;
      a.click();
      URL.revokeObjectURL(url);
    },
    [pe, currentFunc, rows, state.renames, state.comments, state.fileName, sectionInfo],
  );

  // Compute graph layout blocks/edges for minimap (only in graph mode)
  const { graphBlocksForMinimap, graphEdgesForMinimap } = useMemo(() => {
    if (viewMode !== "graph" || !currentFunc)
      return { graphBlocksForMinimap: undefined, graphEdgesForMinimap: undefined };
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
    if (!container) {
      setGraphOverview(null);
      return;
    }
    setGraphOverview({
      blocks: graphBlocksForMinimap,
      edges: graphEdgesForMinimap,
      pan: graphPan,
      zoom: graphZoom,
      viewport: { width: container.clientWidth, height: container.clientHeight },
      onPanTo: setGraphPan,
      currentAddress: state.currentAddress,
    });
  }, [
    viewMode,
    graphBlocksForMinimap,
    graphEdgesForMinimap,
    graphPan,
    graphZoom,
    state.currentAddress,
    setGraphOverview,
  ]);

  // Clear graph overview on unmount
  useEffect(() => {
    return () => setGraphOverview(null);
  }, [setGraphOverview]);

  if (!pe) return null;

  // Ahead of the spinner and of `disasmError`, both of which depend on the
  // worker having answered. The machine type is known the moment the file
  // parses, so this states the case immediately rather than after a round trip
  // — and, more to the point, it means nothing here can ever render a screen of
  // x86 decoded out of ARM bytes, however the worker's `configure` and this
  // view's disassemble request happen to interleave.
  const archNotice = analysisNotice({
    machine: pe.coffHeader.machine,
    phase: state.analysisPhase,
    error: state.error,
    engineError: state.disasmFailed,
  });
  // "No executable section" joins it: both are permanent properties of the file
  // rather than faults, both withhold exactly this panel and nothing else, and
  // the heading below states both correctly. Without this arm the tab the user
  // is actually looking at fell through to "Address 0x… is not within any
  // section", which is true and explains nothing (peek-a-bin-bo3b). The failure
  // and partial-detection kinds are still deliberately excluded — neither is a
  // reason to replace the panel. So is the timeout: a stage cut off by the
  // request watchdog may have left this panel *complete*, since `buildAllXrefs`
  // is the last stage of App's chain, so replacing it would delete a real
  // disassembly in order to explain its absence — and where the panel is instead
  // empty, the view's own request has its own message two branches down. Unlike
  // peek-a-bin-b3jn there is nothing to contradict either: the engine is alive,
  // so neither the `!state.disasmReady` spinner below nor the tab bar's claims
  // anything is still loading (peek-a-bin-meai).
  // "Engine unavailable" joins the two file properties for the same reason they
  // joined each other: this panel can never populate in that state either, and
  // the alternative was the `!state.disasmReady` spinner three branches down,
  // which says "Loading engine..." forever (peek-a-bin-b3jn). The heading has to
  // move with it — the engine failing is not a property of the image.
  if (
    archNotice?.kind === "unsupported-arch" ||
    archNotice?.kind === "no-code-section" ||
    archNotice?.kind === "engine-unavailable"
  ) {
    return (
      <div className="p-6 max-w-2xl text-sm">
        <h2
          className={`font-semibold mb-2 ${archNotice.isFault ? "text-red-400" : "text-amber-400"}`}
        >
          {archNotice.kind === "engine-unavailable"
            ? "No disassembly: the engine did not load"
            : "No disassembly for this image"}
        </h2>
        <p className="text-gray-300 mb-4">{archNotice.detail}</p>
        <p className="text-gray-500 mb-2">Still available:</p>
        <div className="flex flex-wrap gap-2">
          {archNotice.availableTabs.map((tab) => (
            <button
              key={tab}
              type="button"
              onClick={() => dispatch({ type: "SET_TAB", tab })}
              className="px-2 py-1 rounded border border-gray-700 text-gray-300 hover:border-blue-500 hover:text-blue-400 text-xs"
            >
              {VIEW_TAB_LABELS[tab]}
            </button>
          ))}
        </div>
      </div>
    );
  }

  if (disassembling) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400 text-sm">
        <svg aria-hidden="true" className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
            fill="none"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
          />
        </svg>
        Disassembling...
      </div>
    );
  }

  if (disasmError) {
    return <div className="p-4 text-red-400 text-sm">Disassembly error: {disasmError}</div>;
  }

  if (!state.disasmReady) {
    return (
      <div className="flex items-center justify-center h-full text-gray-400 text-sm">
        <svg aria-hidden="true" className="animate-spin h-5 w-5 mr-2" viewBox="0 0 24 24">
          <circle
            className="opacity-25"
            cx="12"
            cy="12"
            r="10"
            stroke="currentColor"
            strokeWidth="4"
            fill="none"
          />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
          />
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

  // Plain functions, not hooks — these are recreated on every render exactly as
  // the inline arrow functions they replace were. Do not wrap in useCallback:
  // that would insert a hook after the early returns above.
  const handleRowSelect = (address: number) => {
    suppressScrollRef.current = true;
    dispatch({ type: "SET_ADDRESS", address });
  };
  const handleShowXrefs = (address: number) => {
    setXrefScopeAddress(address);
    setShowXrefPanel(true);
  };

  const sectionBaseVA = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;
  const sectionEndVA = sectionBaseVA + sectionInfo.virtualSize;

  return (
    <div className="flex flex-col h-full">
      <DisassemblyToolbar
        sectionInfo={sectionInfo}
        sectionBaseVA={sectionBaseVA}
        sectionEndVA={sectionEndVA}
        isExecutable={isExecutable}
        instructions={instructions}
        insnFilter={insnFilter}
        setInsnFilter={setInsnFilter}
        filterMatchCount={filterMatchCount}
        showArrows={showArrows}
        setShowArrows={setShowArrows}
        showMinimap={showMinimap}
        setShowMinimap={setShowMinimap}
        showBytes={showBytes}
        setShowBytes={setShowBytes}
        viewMode={viewMode}
        setViewMode={setViewMode}
        currentFunc={currentFunc}
        showDecompile={showDecompile}
        handleDecompileToggle={handleDecompileToggle}
        showXrefPanel={showXrefPanel}
        setShowXrefPanel={setShowXrefPanel}
        showExportMenu={showExportMenu}
        setShowExportMenu={setShowExportMenu}
        handleExportAsm={handleExportAsm}
        search={search}
        searchInputRef={searchInputRef}
        parentRef={parentRef}
        dispatch={dispatch}
      />

      {/* Breadcrumb trail */}
      <Breadcrumbs />

      {/* Disassembly content */}
      {/* tabIndex={-1}: focus is moved here programmatically (on entering graph mode, on
          row click, on navigation) rather than by tabbing — see the focus() calls above.
          Global hotkeys are bound on window, so keyboard users lose nothing. */}
      {/* role="application": this pane defines its own single-key shortcuts
          (G, R, Space, Enter, ";" ...), so screen readers should forward keys
          rather than intercept them for browse mode. */}
      <div
        role="application"
        aria-label="Disassembly viewer"
        className="flex flex-1 overflow-hidden"
        ref={cfgContainerRef}
        tabIndex={-1}
        onKeyDown={handleKeyDown}
      >
        {viewMode === "linear" ? (
          <div
            ref={parentRef}
            className="flex-1 overflow-auto leading-5 focus:outline-none relative"
            style={
              {
                fontSize: "var(--mono-font-size)",
                "--col-addr": pe.is64 ? "18ch" : "10ch",
              } as React.CSSProperties
            }
            tabIndex={-1}
          >
            {/* Sticky function header */}
            {currentFunc &&
              currentFuncLabelIndex >= 0 &&
              (() => {
                const vItems = virtualizer.getVirtualItems();
                const firstVisible = vItems.length > 0 ? vItems[0].index : 0;
                if (currentFuncLabelIndex < firstVisible) {
                  const name = getDisplayName(currentFunc, state.renames);
                  return (
                    <button
                      type="button"
                      className="sticky top-0 left-0 right-0 z-10 w-full text-left bg-gray-900/95 border-b border-gray-700/50 px-4 py-0.5 text-xs text-gray-300 cursor-pointer hover:text-white font-mono"
                      onClick={() =>
                        virtualizer.scrollToIndex(currentFuncLabelIndex, { align: "start" })
                      }
                      title="Click to scroll to function header"
                    >
                      ▸ {name}
                    </button>
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
                    <SeparatorRow
                      key={`sep-${vItem.index}`}
                      index={vItem.index}
                      start={vItem.start}
                      height={sepHeight}
                    />
                  );
                }

                if (row.kind === "data") {
                  return (
                    <DataRow
                      key={vItem.index}
                      item={row.item}
                      index={vItem.index}
                      start={vItem.start}
                      rowHeight={rowHeight}
                      addrWidth={addrWidth}
                      currentAddress={state.currentAddress}
                      bookmarkSet={bookmarkSet}
                      showBytes={showBytes}
                      comments={state.comments}
                      onAddressClick={handleAddressClick}
                      onRowClick={handleRowSelect}
                    />
                  );
                }

                if (row.kind === "label") {
                  return (
                    <LabelRow
                      key={`label-${vItem.index}`}
                      fn={row.fn}
                      index={vItem.index}
                      start={vItem.start}
                      rowHeight={rowHeight}
                      renames={state.renames}
                      typedXrefMap={typedXrefMap}
                      bookmarkSet={bookmarkSet}
                      renamingLabel={renamingLabel}
                      setRenamingLabel={setRenamingLabel}
                      dispatch={dispatch}
                      getSigForFunc={getSigForFunc}
                      onShowXrefs={handleShowXrefs}
                    />
                  );
                }

                return (
                  <InsnRow
                    key={vItem.index}
                    row={row}
                    index={vItem.index}
                    start={vItem.start}
                    rowHeight={rowHeight}
                    addrWidth={addrWidth}
                    pe={pe}
                    iatMap={iatMap}
                    functions={state.functions}
                    renames={state.renames}
                    comments={state.comments}
                    currentAddress={state.currentAddress}
                    currentFunc={currentFunc}
                    currentIndex={currentIndex}
                    funcMap={funcMap}
                    typedXrefMap={typedXrefMap}
                    bookmarkSet={bookmarkSet}
                    loopHeaders={loopHeaders}
                    loopBodyMap={loopBodyMap}
                    searchMatches={search.searchMatches}
                    searchMatchIdx={search.searchMatchIdx}
                    isSelected={isSelected}
                    insnFilter={insnFilter}
                    matchesFilter={matchesFilter}
                    showBytes={showBytes}
                    copiedAddr={copiedAddr}
                    highlightRegs={highlightRegs}
                    lastClickedRow={lastClickedRow}
                    editingComment={editingComment}
                    setEditingComment={setEditingComment}
                    setSelectionRange={setSelectionRange}
                    setLastClickedRow={setLastClickedRow}
                    onShowXrefs={handleShowXrefs}
                    onAddressClick={handleAddressClick}
                    onDoubleClickAddr={handleDoubleClickAddr}
                    onDoubleClickInsn={handleDoubleClickInsn}
                    onRegClick={handleRegClick}
                    onContextMenu={handleContextMenu}
                    onRowClick={handleRowSelect}
                    dispatch={dispatch}
                  />
                );
              })}

              {/* Context menu */}
              {ctxMenu && (
                <InsnContextMenu
                  ctxMenu={ctxMenu}
                  menuRef={ctxMenuRef}
                  actions={ctxActions}
                  xrefCountMap={xrefCountMap}
                  comments={state.comments}
                  funcMap={funcMap}
                  setCtxMenu={setCtxMenu}
                  scanFunction={vulnScanner.scanFunction}
                  selectionRange={selectionRange}
                  rows={rows}
                  pe={pe}
                  renames={state.renames}
                  formatRangeCopy={formatRangeCopy}
                />
              )}
            </div>
          </div>
        ) : currentFunc ? (
          <CFGView
            func={currentFunc}
            instructions={instructions}
            typedXrefMap={typedXrefMap}
            jumpTables={disasmWorker.jumpTables}
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
            pan={graphPan}
            zoom={graphZoom}
            onPanChange={setGraphPan}
            onZoomChange={setGraphZoom}
            collapsedBlocks={collapsedBlocks}
            onToggleCollapse={handleToggleCollapse}
            restorePanZoom={restorePanZoom}
            reCenterTrigger={reCenterTrigger}
            searchMatches={showGraphSearch ? graphSearchMatchSet : undefined}
            currentSearchMatch={showGraphSearch ? graphSearchCurrentMatch : undefined}
          />
        ) : (
          <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
            No function selected
          </div>
        )}
        {/* Context menu (graph mode) */}
        {viewMode === "graph" && ctxMenu && (
          <InsnContextMenu
            ctxMenu={ctxMenu}
            menuRef={ctxMenuRef}
            actions={ctxActions}
            xrefCountMap={xrefCountMap}
            comments={state.comments}
            funcMap={funcMap}
            setCtxMenu={setCtxMenu}
            scanFunction={vulnScanner.scanFunction}
            selectionRange={null}
            rows={rows}
            pe={pe}
            renames={state.renames}
            formatRangeCopy={formatRangeCopy}
          />
        )}
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
                : graphSearchQuery
                  ? "0 matches"
                  : ""}
            </span>
            <button
              type="button"
              onClick={graphSearchPrevMatch}
              disabled={graphSearchMatches.length === 0}
              className="text-gray-400 hover:text-white disabled:opacity-30 px-1"
              title="Previous match (Shift+Enter)"
            >
              ▲
            </button>
            <button
              type="button"
              onClick={graphSearchNextMatch}
              disabled={graphSearchMatches.length === 0}
              className="text-gray-400 hover:text-white disabled:opacity-30 px-1"
              title="Next match (Enter)"
            >
              ▼
            </button>
            <button
              type="button"
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
                try {
                  localStorage.setItem("peek-a-bin:decompile-width", String(decompileWidth));
                } catch {}
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
                    try {
                      localStorage.setItem("peek-a-bin:scroll-sync", String(next));
                    } catch {}
                    if (!next) setScrollSyncAddr(null);
                    return next;
                  });
                }}
                comments={state.comments}
                lineMap={decompile.activeLineMap}
                editingComment={editingComment}
                onEditComment={setEditingComment}
                onCommitComment={(addr, text) =>
                  dispatch({ type: "SET_COMMENT", address: addr, text })
                }
                onDeleteComment={(addr) => dispatch({ type: "DELETE_COMMENT", address: addr })}
              />
            </div>
          </>
        )}
        {showChat && (
          <>
            <ResizeHandle
              orientation="horizontal"
              onResize={(delta) => {
                setChatWidth((prev) => Math.max(200, prev - delta));
              }}
              onResizeEnd={() => {
                try {
                  localStorage.setItem("peek-a-bin:chat-width", String(chatWidth));
                } catch {}
              }}
            />
            <div className="shrink-0" style={{ width: chatWidth }}>
              <AIChatPanel
                chat={aiChat}
                onClose={() => setShowChat(false)}
                onRename={(address, name) => dispatch({ type: "RENAME_FUNCTION", address, name })}
              />
            </div>
          </>
        )}
      </div>
      {/* end flex wrapper for content + minimap */}

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
            onClose: () => {
              setShowXrefPanel(false);
              setXrefScopeAddress(null);
            },
            content: (
              <XrefPanel
                typedXrefMap={typedXrefMap}
                funcMap={funcMap}
                sortedFuncs={sortedFuncs}
                pe={pe}
                onNavigate={(addr) => dispatch({ type: "SET_ADDRESS", address: addr })}
                onClose={() => {
                  setShowXrefPanel(false);
                  setXrefScopeAddress(null);
                }}
                scopeAddress={xrefScopeAddress}
                currentFuncAddr={currentFunc?.address ?? null}
                currentFuncEnd={currentFunc ? currentFunc.address + currentFunc.size : null}
                currentInsnAddr={state.currentAddress}
              />
            ),
          },
        ]}
      />
    </div>
  );
}
