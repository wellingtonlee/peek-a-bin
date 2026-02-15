import { useEffect, useRef, useMemo, useCallback, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch, getDisplayName } from "../hooks/usePEFile";
import { disasmEngine } from "../disasm/engine";
import { disasmWorker } from "../workers/disasmClient";
import type { Instruction, DisasmFunction, Xref } from "../disasm/types";
import type { SectionHeader } from "../pe/types";
import { CallPanel } from "./CallPanel";
import { buildIATLookup, parseOperandTargets } from "../disasm/operands";
import { JumpArrows } from "./JumpArrows";
import { InstructionDetail } from "./InstructionDetail";
import { DisassemblyMinimap } from "./DisassemblyMinimap";
import { analyzeStackFrame } from "../disasm/stack";
import { CFGView } from "./CFGView";
import { buildCFG, detectLoops } from "../disasm/cfg";
import { inferSignature, type FunctionSignature } from "../disasm/signatures";
import { Breadcrumbs } from "./Breadcrumbs";

interface XrefPopupState {
  x: number;
  y: number;
  targetAddr: number;
  sources: Xref[];
}

type DisplayRow =
  | { kind: "label"; fn: DisasmFunction }
  | { kind: "insn"; insn: Instruction; blockIdx: number }
  | { kind: "separator" };

function rowAddress(row: DisplayRow): number | null {
  if (row.kind === "insn") return row.insn.address;
  if (row.kind === "label") return row.fn.address;
  return null;
}

function binarySearchRows(rows: DisplayRow[], address: number): number {
  let lo = 0;
  let hi = rows.length - 1;
  let best = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const row = rows[mid];
    const rowAddr = rowAddress(row);
    if (rowAddr === null) {
      hi = mid - 1;
      continue;
    }
    if (rowAddr <= address) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

function parseBranchTarget(mnemonic: string, opStr: string): number | null {
  if (
    mnemonic === "call" ||
    mnemonic === "jmp" ||
    mnemonic.startsWith("j")
  ) {
    const m = opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (m) return parseInt(m[1], 16);
  }
  return null;
}

// --- Syntax coloring for operands ---
interface OpToken { text: string; cls: string }

const REG_NAMES = new Set([
  "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15",
  "eax","ebx","ecx","edx","esi","edi","ebp","esp",
  "ax","bx","cx","dx","si","di","bp","sp",
  "al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl",
  "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
  "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
  "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
  "cs","ds","es","fs","gs","ss",
  "rip","eip","ip",
  "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
  "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
  "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
]);

function tokenizeOperand(opStr: string): OpToken[] {
  if (!opStr) return [];
  const tokens: OpToken[] = [];
  // regex: memory brackets, hex immediates, register names, other
  const re = /(\[|\])|(\b0x[0-9a-fA-F]+\b)|(\b[a-z][a-z0-9]{1,4}\b)|([^[\]a-z0-9]+|[0-9]+)/gi;
  let m: RegExpExecArray | null;
  let inBracket = false;
  while ((m = re.exec(opStr)) !== null) {
    const full = m[0];
    if (full === "[") {
      inBracket = true;
      tokens.push({ text: "[", cls: "text-purple-400" });
    } else if (full === "]") {
      inBracket = false;
      tokens.push({ text: "]", cls: "text-purple-400" });
    } else if (m[2]) {
      // hex immediate
      tokens.push({ text: full, cls: inBracket ? "text-purple-400" : "text-yellow-300" });
    } else if (m[3] && REG_NAMES.has(full.toLowerCase())) {
      tokens.push({ text: full, cls: inBracket ? "text-purple-400" : "text-cyan-400" });
    } else {
      tokens.push({ text: full, cls: inBracket ? "text-purple-400" : "" });
    }
  }
  return tokens;
}

interface ClickableTarget {
  address: number;
  display?: string;
}

function ColoredOperand({ opStr, targets, onNavigate }: {
  opStr: string;
  targets?: ClickableTarget[];
  onNavigate?: (addr: number) => void;
}) {
  const tokens = useMemo(() => tokenizeOperand(opStr), [opStr]);

  // Build a map of hex string → target for clickable tokens
  const targetMap = useMemo(() => {
    if (!targets || targets.length === 0) return null;
    const m = new Map<string, ClickableTarget>();
    for (const t of targets) {
      // Match "0x" + hex representation (case-insensitive)
      const hexStr = "0x" + t.address.toString(16);
      m.set(hexStr.toLowerCase(), t);
    }
    return m;
  }, [targets]);

  return (
    <>
      {tokens.map((t, i) => {
        // Check if this hex token is a navigable target
        if (targetMap && onNavigate && t.text.startsWith("0x")) {
          const target = targetMap.get(t.text.toLowerCase());
          if (target) {
            return (
              <span
                key={i}
                className="text-blue-400 underline cursor-pointer hover:text-blue-300"
                onClick={(e) => { e.stopPropagation(); onNavigate(target.address); }}
                title={target.display || `Go to 0x${target.address.toString(16).toUpperCase()}`}
              >
                {t.text}
              </span>
            );
          }
        }
        return t.cls ? <span key={i} className={t.cls}>{t.text}</span> : <span key={i}>{t.text}</span>;
      })}
    </>
  );
}

// Mnemonic coloring
function mnemonicClass(m: string): string {
  if (m === "call") return "text-green-400 font-semibold";
  if (m === "ret" || m === "retn") return "text-red-400 font-semibold";
  if (m === "nop" || m === "int3") return "text-gray-600 font-semibold";
  if (m === "jmp" || m.startsWith("j")) return "text-orange-400 font-semibold";
  if (m === "push" || m === "pop") return "text-blue-300 font-semibold";
  return "font-semibold";
}

// --- Context menu ---
interface ContextMenuState {
  x: number;
  y: number;
  insn: Instruction;
}

// --- Cross-section search result ---
interface CrossSectionResult {
  section: SectionHeader;
  address: number;
  text: string;
}

export function DisassemblyView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);
  const [instructions, setInstructions] = useState<Instruction[]>([]);
  const [disasmError, setDisasmError] = useState<string | null>(null);
  const [disassembling, setDisassembling] = useState(false);
  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchMatches, setSearchMatches] = useState<number[]>([]);
  const [searchMatchIdx, setSearchMatchIdx] = useState(-1);
  const [copiedAddr, setCopiedAddr] = useState<number | null>(null);
  const [ctxMenu, setCtxMenu] = useState<ContextMenuState | null>(null);
  const [showShortcuts, setShowShortcuts] = useState(false);
  const [crossResults, setCrossResults] = useState<CrossSectionResult[] | null>(null);
  const [crossSearching, setCrossSearching] = useState(false);
  const [xrefPopup, setXrefPopup] = useState<XrefPopupState | null>(null);
  const [renamingLabel, setRenamingLabel] = useState<{ address: number; value: string } | null>(null);
  const [editingComment, setEditingComment] = useState<{ address: number; value: string } | null>(null);
  const [showCallPanel, setShowCallPanel] = useState(false);
  const [insnFilter, setInsnFilter] = useState<"all" | "calls" | "jumps" | "stringrefs" | "suspicious">("all");
  const [selectionRange, setSelectionRange] = useState<{ start: number; end: number } | null>(null);
  const [lastClickedRow, setLastClickedRow] = useState<number | null>(null);
  const [showBlocks, setShowBlocks] = useState(false);
  const [showArrows, setShowArrows] = useState(true);
  const [showDetail, setShowDetail] = useState(false);
  const [showMinimap, setShowMinimap] = useState(true);
  const [showCFG, setShowCFG] = useState(false);

  // Build IAT lookup map from imports
  const iatMap = useMemo(() => {
    if (!pe) return new Map<number, { lib: string; func: string }>();
    return buildIATLookup(pe.imports);
  }, [pe]);

  // Find which section contains the current address
  const sectionInfo = useMemo(() => {
    if (!pe) return null;
    const rva = state.currentAddress - pe.optionalHeader.imageBase;
    for (const sec of pe.sections) {
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
        return sec;
      }
    }
    return null;
  }, [pe, state.currentAddress]);

  // Disassemble the current section (off main thread via worker)
  useEffect(() => {
    if (!pe || !sectionInfo || !state.disasmReady) return;

    let cancelled = false;
    setDisassembling(true);

    const sectionBytes = new Uint8Array(
      pe.buffer,
      sectionInfo.pointerToRawData,
      sectionInfo.sizeOfRawData,
    );
    const baseAddr = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;

    disasmWorker.disassemble(sectionBytes, baseAddr, pe.is64)
      .then((result) => {
        if (!cancelled) {
          setInstructions(result);
          setDisasmError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setDisasmError(e instanceof Error ? e.message : "Disassembly failed");
          setInstructions([]);
        }
      })
      .finally(() => {
        if (!cancelled) setDisassembling(false);
      });

    return () => { cancelled = true; };
  }, [pe, sectionInfo, state.disasmReady]);

  // Build funcMap for O(1) lookup
  const funcMap = useMemo(() => {
    const m = new Map<number, DisasmFunction>();
    for (const fn of state.functions) m.set(fn.address, fn);
    return m;
  }, [state.functions]);

  // Build typed xref map (off main thread via worker)
  const [typedXrefMap, setTypedXrefMap] = useState<Map<number, Xref[]>>(new Map());
  useEffect(() => {
    if (instructions.length === 0) {
      setTypedXrefMap(new Map());
      return;
    }
    let cancelled = false;
    disasmWorker.buildTypedXrefMap(instructions).then((map) => {
      if (!cancelled) setTypedXrefMap(map);
    });
    return () => { cancelled = true; };
  }, [instructions]);

  // Legacy xref map (address -> source addresses) for compatibility with CallPanel, JumpArrows, etc.
  const xrefMap = useMemo(() => {
    const m = new Map<number, number[]>();
    for (const [addr, xrefs] of typedXrefMap) {
      m.set(addr, xrefs.map((x) => x.from));
    }
    return m;
  }, [typedXrefMap]);

  // Bookmark address set for O(1) lookup
  const bookmarkSet = useMemo(() => {
    const s = new Set<number>();
    for (const b of state.bookmarks) s.add(b.address);
    return s;
  }, [state.bookmarks]);

  // Sorted functions for binary search
  const sortedFuncs = useMemo(() => {
    return [...state.functions].sort((a, b) => a.address - b.address);
  }, [state.functions]);

  // Find current function for call panel
  const currentFunc = useMemo((): DisasmFunction | null => {
    const addr = state.currentAddress;
    let lo = 0;
    let hi = sortedFuncs.length - 1;
    let best: DisasmFunction | null = null;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const fn = sortedFuncs[mid];
      if (fn.address <= addr) {
        if (addr < fn.address + fn.size) best = fn;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return best;
  }, [state.currentAddress, sortedFuncs]);

  // Loop detection for current function
  const loopHeaders = useMemo(() => {
    if (!currentFunc || instructions.length === 0 || typedXrefMap.size === 0) return new Map<number, number>();
    const blocks = buildCFG(currentFunc, instructions, typedXrefMap);
    const loops = detectLoops(blocks);
    const m = new Map<number, number>();
    for (const loop of loops) m.set(loop.headerAddr, loop.depth);
    return m;
  }, [currentFunc, instructions, typedXrefMap]);

  // Function signature inference
  const currentFuncSig = useMemo((): FunctionSignature | null => {
    if (!currentFunc || instructions.length === 0 || !pe) return null;
    return inferSignature(currentFunc, instructions, pe.is64);
  }, [currentFunc, instructions, pe]);

  // Build a map of function address -> signature for labels
  const funcSigMap = useMemo(() => {
    if (instructions.length === 0 || !pe) return new Map<number, FunctionSignature>();
    const m = new Map<number, FunctionSignature>();
    for (const fn of state.functions) {
      const sig = inferSignature(fn, instructions, pe.is64);
      if (sig.paramCount > 0) m.set(fn.address, sig);
    }
    return m;
  }, [instructions, state.functions, pe]);

  // Stack frame analysis (lazy, only when detail panel is open)
  const stackFrame = useMemo(() => {
    if (!showDetail || !currentFunc || instructions.length === 0) return null;
    return analyzeStackFrame(currentFunc, instructions, pe?.is64 ?? true);
  }, [showDetail, currentFunc, instructions, pe?.is64]);

  // Build display rows (with basic block separators and block indices)
  const rows: DisplayRow[] = useMemo(() => {
    const result: DisplayRow[] = [];
    const separatorMnemonics = new Set(["ret", "retn", "jmp", "int3"]);
    const branchMnemonics = new Set(["ret", "retn", "jmp", "int3"]);
    let blockIdx = 0;
    let prevWasBranch = false;
    for (let i = 0; i < instructions.length; i++) {
      const insn = instructions[i];
      const fn = funcMap.get(insn.address);
      if (fn) {
        blockIdx++;
        prevWasBranch = false;
        result.push({ kind: "label", fn });
      }
      // Start new block if: this address is a branch target (xref exists), or previous was branch/ret
      if (prevWasBranch || (xrefMap.has(insn.address) && !fn)) {
        blockIdx++;
      }
      result.push({ kind: "insn", insn, blockIdx });
      const mn = insn.mnemonic;
      prevWasBranch = branchMnemonics.has(mn) || (mn.startsWith("j") && mn !== "jmp");
      // Insert separator after ret/retn/jmp/int3, unless next instruction is a function label
      if (separatorMnemonics.has(mn)) {
        const next = instructions[i + 1];
        if (next && !funcMap.has(next.address)) {
          result.push({ kind: "separator" });
        }
      }
    }
    return result;
  }, [instructions, funcMap, xrefMap]);

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

  const currentIndex = useMemo(() => {
    if (rows.length === 0) return 0;
    return binarySearchRows(rows, state.currentAddress);
  }, [rows, state.currentAddress]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: (index) => rows[index]?.kind === "separator" ? 8 : 20,
    overscan: 50,
  });

  useEffect(() => {
    if (rows.length > 0 && currentIndex >= 0) {
      virtualizer.scrollToIndex(currentIndex, { align: "center" });
    }
  }, [currentIndex, rows.length]);

  // Dismiss context menu / xref popup on click outside or Escape
  useEffect(() => {
    if (!ctxMenu && !xrefPopup) return;
    const dismiss = () => { setCtxMenu(null); setXrefPopup(null); };
    const keyDismiss = (e: KeyboardEvent) => { if (e.key === "Escape") dismiss(); };
    window.addEventListener("click", dismiss);
    window.addEventListener("keydown", keyDismiss);
    return () => {
      window.removeEventListener("click", dismiss);
      window.removeEventListener("keydown", keyDismiss);
    };
  }, [ctxMenu, xrefPopup]);

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (showSearch && e.key === "Escape") {
        setShowSearch(false);
        setSearchQuery("");
        setSearchMatches([]);
        setSearchMatchIdx(-1);
        setCrossResults(null);
        parentRef.current?.focus();
        return;
      }

      if (e.key === "Escape") {
        if (showShortcuts) { setShowShortcuts(false); return; }
        if (ctxMenu) { setCtxMenu(null); return; }
        if (selectionRange) { setSelectionRange(null); return; }
        // Pop breadcrumb if available, else navigate back
        if (state.callStack.length > 0) {
          const last = state.callStack[state.callStack.length - 1];
          dispatch({ type: "SET_ADDRESS", address: last.address });
          dispatch({ type: "POP_CALL_STACK", index: state.callStack.length - 1 });
          return;
        }
        dispatch({ type: "NAV_BACK" });
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key === "c") {
        if (selectionRange) {
          e.preventDefault();
          const lo = Math.min(selectionRange.start, selectionRange.end);
          const hi = Math.max(selectionRange.start, selectionRange.end);
          const lines: string[] = [];
          for (let i = lo; i <= hi; i++) {
            const row = rows[i];
            if (!row) continue;
            if (row.kind === "label") {
              const name = getDisplayName(row.fn, state.renames);
              lines.push(`\n; ──── ${name} ────`);
            } else if (row.kind === "insn") {
              const insn = row.insn;
              const aw = pe?.is64 ? 16 : 8;
              const addrHex = insn.address.toString(16).toUpperCase().padStart(aw, "0");
              const comment = insn.comment ? `  ; ${insn.comment}` : "";
              const userComment = state.comments[insn.address] ? `  ; ${state.comments[insn.address]}` : "";
              lines.push(`  ${addrHex}  ${insn.mnemonic} ${insn.opStr}${comment}${userComment}`);
            }
          }
          navigator.clipboard.writeText(lines.join("\n"));
          return;
        }
      }

      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA"
      )
        return;

      if (e.key === "?") {
        e.preventDefault();
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

      if (e.key === "i" || e.key === "I") {
        e.preventDefault();
        setShowDetail((v) => !v);
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
            if (targetFn) {
              dispatch({ type: "PUSH_CALL_STACK", address: state.currentAddress, name: getDisplayName(currentFunc ?? targetFn, state.renames) });
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
        setShowSearch(true);
        setTimeout(() => searchInputRef.current?.focus(), 0);
        return;
      }

      if (e.key === "/") {
        e.preventDefault();
        setShowSearch(true);
        setTimeout(() => searchInputRef.current?.focus(), 0);
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
    [currentIndex, rows, dispatch, showSearch, showShortcuts, ctxMenu, state.currentAddress, state.comments, selectionRange, state.renames, pe, currentFunc, virtualizer, funcMap, state.callStack],
  );

  // Search logic
  const handleSearch = useCallback(
    (query: string, direction: 1 | -1 = 1) => {
      setCrossResults(null);
      if (!query) {
        setSearchMatches([]);
        setSearchMatchIdx(-1);
        return;
      }
      const q = query.toLowerCase();
      const matches: number[] = [];
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (row.kind === "label") {
          const name = getDisplayName(row.fn, state.renames);
          if (name.toLowerCase().includes(q)) matches.push(i);
        } else if (row.kind === "insn") {
          const insn = row.insn;
          const userComment = state.comments[insn.address] ?? "";
          const text = `${insn.address.toString(16)} ${insn.mnemonic} ${insn.opStr} ${insn.comment || ""} ${userComment}`;
          if (text.toLowerCase().includes(q)) matches.push(i);
        }
      }
      setSearchMatches(matches);
      if (matches.length > 0) {
        let idx = matches.findIndex((m) => m >= currentIndex);
        if (idx === -1) idx = 0;
        if (direction === -1) {
          idx = idx - 1;
          if (idx < 0) idx = matches.length - 1;
        }
        setSearchMatchIdx(idx);
        const matchAddr = rowAddress(rows[matches[idx]]);
        if (matchAddr !== null) {
          dispatch({ type: "SET_ADDRESS", address: matchAddr });
        }
      } else {
        setSearchMatchIdx(-1);
      }
    },
    [rows, currentIndex, dispatch, state.renames, state.comments],
  );

  const handleSearchNext = useCallback(() => {
    if (searchMatches.length === 0) return;
    const next = (searchMatchIdx + 1) % searchMatches.length;
    setSearchMatchIdx(next);
    const addr = rowAddress(rows[searchMatches[next]]);
    if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
  }, [searchMatches, searchMatchIdx, rows, dispatch]);

  const handleSearchPrev = useCallback(() => {
    if (searchMatches.length === 0) return;
    const prev = (searchMatchIdx - 1 + searchMatches.length) % searchMatches.length;
    setSearchMatchIdx(prev);
    const addr = rowAddress(rows[searchMatches[prev]]);
    if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
  }, [searchMatches, searchMatchIdx, rows, dispatch]);

  // Cross-section search
  const handleCrossSearch = useCallback(() => {
    if (!pe || !searchQuery || crossSearching) return;
    setCrossSearching(true);
    const q = searchQuery.toLowerCase();
    const results: CrossSectionResult[] = [];

    setTimeout(() => {
      for (const sec of pe.sections) {
        if (sec === sectionInfo) continue; // already searched current
        try {
          const bytes = new Uint8Array(pe.buffer, sec.pointerToRawData, sec.sizeOfRawData);
          const base = pe.optionalHeader.imageBase + sec.virtualAddress;
          const insns = disasmEngine.disassemble(bytes, base, pe.is64, pe.strings);
          for (const insn of insns) {
            const text = `${insn.mnemonic} ${insn.opStr} ${insn.comment || ""}`;
            if (text.toLowerCase().includes(q)) {
              results.push({ section: sec, address: insn.address, text: text.trim() });
              if (results.length >= 100) break;
            }
          }
        } catch { /* skip bad sections */ }
        if (results.length >= 100) break;
      }
      setCrossResults(results);
      setCrossSearching(false);
    }, 0);
  }, [pe, searchQuery, sectionInfo, crossSearching]);

  const handleAddressClick = useCallback(
    (address: number) => {
      // Push breadcrumb when clicking into a function target
      const targetFn = funcMap.get(address);
      if (targetFn && currentFunc) {
        dispatch({ type: "PUSH_CALL_STACK", address: state.currentAddress, name: getDisplayName(currentFunc, state.renames) });
      }
      dispatch({ type: "SET_ADDRESS", address });
    },
    [dispatch, funcMap, currentFunc, state.currentAddress, state.renames],
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

  const handleContextMenu = useCallback(
    (e: React.MouseEvent, insn: Instruction) => {
      e.preventDefault();
      const container = parentRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      setCtxMenu({
        x: e.clientX - rect.left + container.scrollLeft,
        y: e.clientY - rect.top + container.scrollTop,
        insn,
      });
    },
    [],
  );

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
        <span>{instructions.length.toLocaleString()} instructions</span>
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
        <div className="flex items-center gap-1 ml-2">
          <button
            onClick={() => setShowBlocks((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showBlocks ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
          >
            Blocks
          </button>
          <button
            onClick={() => setShowArrows((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showArrows ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
          >
            Arrows
          </button>
          <button
            onClick={() => setShowMinimap((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showMinimap ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
          >
            Map
          </button>
          <button
            onClick={() => setShowCFG(true)}
            disabled={!currentFunc}
            className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600 disabled:opacity-30"
            title="Show control flow graph for current function"
          >
            CFG
          </button>
        </div>
        <div className="flex-1" />
        {showSearch && (
          <div className="flex items-center gap-1">
            <input
              ref={searchInputRef}
              type="text"
              value={searchQuery}
              onChange={(e) => {
                setSearchQuery(e.target.value);
                handleSearch(e.target.value);
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  if (e.shiftKey) handleSearchPrev();
                  else if (searchMatches.length > 0) handleSearchNext();
                  else handleSearch(searchQuery);
                }
                if (e.key === "Escape") {
                  setShowSearch(false);
                  setSearchQuery("");
                  setSearchMatches([]);
                  setSearchMatchIdx(-1);
                  setCrossResults(null);
                  parentRef.current?.focus();
                }
                e.stopPropagation();
              }}
              placeholder="Search..."
              className="w-48 px-2 py-0.5 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
            />
            {searchMatches.length > 0 && (
              <span className="text-gray-500 text-[10px]">
                {searchMatchIdx + 1}/{searchMatches.length}
              </span>
            )}
            {searchQuery && searchMatches.length === 0 && !crossResults && (
              <span className="text-red-400 text-[10px]">No matches</span>
            )}
            <button
              onClick={handleSearchPrev}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
              title="Previous (Shift+Enter)"
            >
              ▲
            </button>
            <button
              onClick={handleSearchNext}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
              title="Next (Enter)"
            >
              ▼
            </button>
            <button
              onClick={() => {
                setShowSearch(false);
                setSearchQuery("");
                setSearchMatches([]);
                setSearchMatchIdx(-1);
                setCrossResults(null);
                parentRef.current?.focus();
              }}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
            >
              ✕
            </button>
          </div>
        )}
      </div>

      {/* Cross-section search prompt */}
      {showSearch && searchQuery && searchMatches.length === 0 && !crossResults && !crossSearching && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs flex items-center gap-2">
          <span className="text-gray-400">No matches in {sectionInfo.name}.</span>
          <button
            onClick={handleCrossSearch}
            className="text-blue-400 hover:text-blue-300 hover:underline"
          >
            Search all sections?
          </button>
        </div>
      )}

      {/* Cross-section search loading */}
      {crossSearching && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs text-gray-400 flex items-center gap-2">
          <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Searching all sections...
        </div>
      )}

      {/* Cross-section search results */}
      {crossResults && crossResults.length > 0 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs max-h-40 overflow-auto">
          <div className="text-gray-400 mb-1">{crossResults.length} result{crossResults.length !== 1 ? "s" : ""} in other sections:</div>
          {crossResults.map((r, i) => (
            <button
              key={i}
              onClick={() => {
                dispatch({ type: "SET_ADDRESS", address: r.address });
                setCrossResults(null);
                setShowSearch(false);
                setSearchQuery("");
                setSearchMatches([]);
                setSearchMatchIdx(-1);
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
      {crossResults && crossResults.length === 0 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs text-gray-500">
          No matches found in any section.
        </div>
      )}

      {/* Breadcrumb trail */}
      <Breadcrumbs />

      {/* Disassembly content */}
      <div className="flex flex-1 overflow-hidden">
      <div
        ref={parentRef}
        className="flex-1 overflow-auto text-xs leading-5 focus:outline-none"
        tabIndex={0}
        onKeyDown={handleKeyDown}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
            paddingLeft: showArrows ? "40px" : undefined,
          }}
        >
          {showArrows && (
            <JumpArrows
              visibleItems={virtualizer.getVirtualItems()}
              rows={rows}
              funcMap={funcMap}
              currentFuncAddr={currentFunc?.address ?? null}
              currentAddress={state.currentAddress}
              rowHeight={20}
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
                  className="flex items-center px-4"
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: "8px",
                    transform: `translateY(${vItem.start}px)`,
                  }}
                >
                  <div className="w-full border-t border-dashed border-gray-700/40" />
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
                    className="flex items-center px-4 text-yellow-400 text-[11px] font-mono border-t border-gray-700/50"
                    style={{
                      position: "absolute",
                      top: 0,
                      left: 0,
                      width: "100%",
                      height: "20px",
                      transform: `translateY(${vItem.start}px)`,
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
                  className="flex items-center px-4 text-yellow-400 text-[11px] font-mono border-t border-gray-700/50"
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    width: "100%",
                    height: "20px",
                    transform: `translateY(${vItem.start}px)`,
                  }}
                  onDoubleClick={() => setRenamingLabel({ address: row.fn.address, value: displayName })}
                >
                  {isBookmarked && <span className="text-yellow-300 mr-1">★</span>}
                  <span>; ──── {displayName}{(() => {
                    const sig = funcSigMap.get(row.fn.address);
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
                          const rect = (e.target as HTMLElement).getBoundingClientRect();
                          const container = parentRef.current;
                          if (!container) return;
                          const cRect = container.getBoundingClientRect();
                          setXrefPopup({
                            x: rect.left - cRect.left + container.scrollLeft,
                            y: rect.bottom - cRect.top + container.scrollTop,
                            targetAddr: row.fn.address,
                            sources: xrefs!,
                          });
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
            const isCurrentAddr = insn.address === state.currentAddress;
            const isSearchMatch =
              searchMatches.length > 0 &&
              searchMatchIdx >= 0 &&
              searchMatches[searchMatchIdx] === vItem.index;
            const rowSelected = isSelected(vItem.index);
            const isDimmed = insnFilter !== "all" && !matchesFilter(row);

            const operandTargets = pe ? parseOperandTargets(
              insn,
              pe.optionalHeader.imageBase,
              pe.optionalHeader.imageBase + pe.optionalHeader.sizeOfImage,
              iatMap,
            ) : [];

            return (
              <div
                key={vItem.index}
                data-index={vItem.index}
                className={`disasm-row flex px-4 ${
                  isSearchMatch
                    ? "bg-yellow-900/30"
                    : rowSelected
                      ? "bg-indigo-900/25"
                      : isCurrentAddr
                        ? "bg-blue-900/30"
                        : showBlocks && row.blockIdx % 2 === 1
                          ? "bg-gray-800/15"
                          : ""
                } ${isDimmed ? "opacity-30" : ""}`}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: "20px",
                  transform: `translateY(${vItem.start}px)`,
                  borderLeft: isLoopHeader ? "2px solid #eab308" : undefined,
                }}
                title={isLoopHeader ? `Loop header (depth ${loopDepth})` : undefined}
                onContextMenu={(e) => handleContextMenu(e, insn)}
                onClick={(e) => {
                  if (e.shiftKey) {
                    e.preventDefault();
                    const anchor = lastClickedRow ?? currentIndex;
                    setSelectionRange({ start: anchor, end: vItem.index });
                  } else {
                    setSelectionRange(null);
                    setLastClickedRow(vItem.index);
                  }
                }}
              >
                <span className="w-4 shrink-0 text-center">
                  {isBookmarked && <span className="text-yellow-300">★</span>}
                </span>
                <span
                  className={`disasm-address w-36 shrink-0 cursor-pointer hover:text-blue-400 ${
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
                <span className="disasm-bytes w-44 shrink-0 truncate">
                  {bytesHex}
                </span>
                <span
                  className={`disasm-mnemonic w-16 shrink-0 ${mnemonicClass(insn.mnemonic)}`}
                  onDoubleClick={() => handleDoubleClickInsn(insn)}
                >
                  {insn.mnemonic}
                </span>
                <span
                  className="disasm-operands flex-1"
                  onDoubleClick={() => handleDoubleClickInsn(insn)}
                >
                  <ColoredOperand
                    opStr={insn.opStr}
                    targets={operandTargets}
                    onNavigate={handleAddressClick}
                  />
                </span>
                {insn.comment && (
                  <span
                    className="disasm-comment ml-4 truncate max-w-xs"
                    title={insn.comment.length > 60 ? insn.comment : undefined}
                  >
                    ; {insn.comment}
                  </span>
                )}
                {editingComment && editingComment.address === insn.address ? (
                  <span className="ml-2 shrink-0">
                    <input
                      autoFocus
                      className="bg-gray-800 border border-blue-500 rounded px-1 text-[#6ee7b7] text-xs font-mono outline-none w-48"
                      value={editingComment.value}
                      onChange={(e) => setEditingComment({ ...editingComment, value: e.target.value })}
                      onKeyDown={(e) => {
                        if (e.key === "Enter") {
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
                  <span className="disasm-user-comment ml-2 truncate max-w-xs" title={state.comments[insn.address]}>
                    ; {state.comments[insn.address]}
                  </span>
                ) : null}
              </div>
            );
          })}

          {/* Context menu */}
          {ctxMenu && (
            <div
              className="absolute z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs min-w-[180px]"
              style={{ left: ctxMenu.x, top: ctxMenu.y }}
              onClick={(e) => e.stopPropagation()}
            >
              <button onClick={ctxCopyAddr} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                Copy address
              </button>
              <button onClick={ctxCopyInsn} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                Copy instruction
              </button>
              <button onClick={ctxCopyBytes} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                Copy bytes
              </button>
              <div className="border-t border-gray-700 my-0.5" />
              <button onClick={ctxGoTo} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                Go to address...
              </button>
              <div className="border-t border-gray-700 my-0.5" />
              <button onClick={ctxToggleBookmark} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                Toggle bookmark
              </button>
              <button onClick={ctxAddComment} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                Add/Edit comment
              </button>
              {ctxMenu && funcMap.has(ctxMenu.insn.address) && (
                <button onClick={ctxRenameFunction} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                  Rename function
                </button>
              )}
              {selectionRange && (() => {
                const lo = Math.min(selectionRange.start, selectionRange.end);
                const hi = Math.max(selectionRange.start, selectionRange.end);
                const count = hi - lo + 1;
                return (
                  <>
                    <div className="border-t border-gray-700 my-0.5" />
                    <button
                      onClick={() => {
                        const lines: string[] = [];
                        for (let i = lo; i <= hi; i++) {
                          const r = rows[i];
                          if (!r) continue;
                          if (r.kind === "label") {
                            const name = getDisplayName(r.fn, state.renames);
                            lines.push(`\n; ──── ${name} ────`);
                          } else if (r.kind === "insn") {
                            const ins = r.insn;
                            const aw = pe?.is64 ? 16 : 8;
                            const ah = ins.address.toString(16).toUpperCase().padStart(aw, "0");
                            const c = ins.comment ? `  ; ${ins.comment}` : "";
                            const uc = state.comments[ins.address] ? `  ; ${state.comments[ins.address]}` : "";
                            lines.push(`  ${ah}  ${ins.mnemonic} ${ins.opStr}${c}${uc}`);
                          }
                        }
                        navigator.clipboard.writeText(lines.join("\n"));
                        setCtxMenu(null);
                      }}
                      className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
                    >
                      Copy selected ({count} rows)
                    </button>
                  </>
                );
              })()}
            </div>
          )}

          {/* Xref popup */}
          {xrefPopup && (
            <div
              className="absolute z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs min-w-[220px] max-h-60 overflow-auto"
              style={{ left: xrefPopup.x, top: xrefPopup.y }}
              onClick={(e) => e.stopPropagation()}
            >
              <div className="px-3 py-1 text-gray-400 border-b border-gray-700">
                Xrefs to 0x{xrefPopup.targetAddr.toString(16).toUpperCase()}
              </div>
              {xrefPopup.sources.map((xref, i) => {
                const typeColors: Record<string, string> = {
                  call: "text-green-400",
                  jmp: "text-red-400",
                  branch: "text-orange-400",
                  data: "text-purple-400",
                };
                const typeLabels: Record<string, string> = {
                  call: "C",
                  jmp: "J",
                  branch: "B",
                  data: "D",
                };
                return (
                  <button
                    key={i}
                    className="w-full text-left px-3 py-1.5 hover:bg-gray-700 font-mono flex items-center gap-2"
                    onClick={() => {
                      dispatch({ type: "SET_ADDRESS", address: xref.from });
                      setXrefPopup(null);
                    }}
                  >
                    <span className={`${typeColors[xref.type] ?? "text-gray-400"} text-[10px] font-semibold w-3`}>
                      {typeLabels[xref.type] ?? "?"}
                    </span>
                    <span className="text-blue-400">
                      0x{xref.from.toString(16).toUpperCase()}
                    </span>
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
      {showMinimap && (
        <DisassemblyMinimap
          rows={rows}
          bookmarkSet={bookmarkSet}
          searchMatches={searchMatches}
          viewportStartIdx={virtualizer.range?.startIndex ?? 0}
          viewportEndIdx={virtualizer.range?.endIndex ?? 0}
          onScrollTo={(idx) => {
            virtualizer.scrollToIndex(idx, { align: "center" });
            const addr = rowAddress(rows[idx]);
            if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
          }}
        />
      )}
      </div>{/* end flex wrapper for content + minimap */}

      {/* Call panel */}
      {showCallPanel && currentFunc && (
        <CallPanel
          func={currentFunc}
          xrefMap={xrefMap}
          instructions={instructions}
          functions={state.functions}
          renames={state.renames}
          onNavigate={(addr) => dispatch({ type: "SET_ADDRESS", address: addr })}
          onClose={() => setShowCallPanel(false)}
        />
      )}

      {/* Instruction detail panel */}
      {showDetail && (() => {
        // Binary search for current instruction
        let curInsn: Instruction | null = null;
        let lo = 0, hi = instructions.length - 1;
        while (lo <= hi) {
          const mid = (lo + hi) >>> 1;
          if (instructions[mid].address === state.currentAddress) { curInsn = instructions[mid]; break; }
          if (instructions[mid].address < state.currentAddress) lo = mid + 1;
          else hi = mid - 1;
        }
        if (!curInsn && instructions.length > 0) {
          // Use closest
          const idx = Math.min(lo, instructions.length - 1);
          curInsn = instructions[idx];
        }
        return curInsn ? (
          <InstructionDetail
            insn={curInsn}
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
        ) : null;
      })()}

      {/* CFG overlay */}
      {showCFG && currentFunc && (
        <CFGView
          func={currentFunc}
          instructions={instructions}
          typedXrefMap={typedXrefMap}
          currentAddress={state.currentAddress}
          onNavigate={(addr) => dispatch({ type: "SET_ADDRESS", address: addr })}
          onClose={() => setShowCFG(false)}
        />
      )}

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
                  ["G", "Go to address (focus address bar)"],
                  ["/ or Ctrl+F", "Search in disassembly"],
                  ["Enter", "Follow branch / next search result"],
                  ["Shift+Enter", "Previous search result"],
                  ["N", "Rename current function"],
                  ["Esc", "Navigate back"],
                  [";", "Add/edit comment at current address"],
                  ["I", "Toggle instruction detail panel"],
                  ["X", "Toggle callers/callees panel"],
                  ["B", "Toggle bookmark at current address"],
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
