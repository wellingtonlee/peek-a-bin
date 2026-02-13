import { useEffect, useRef, useMemo, useCallback, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch, getDisplayName } from "../hooks/usePEFile";
import { disasmEngine } from "../disasm/engine";
import type { Instruction, DisasmFunction } from "../disasm/types";
import type { SectionHeader } from "../pe/types";

interface XrefPopupState {
  x: number;
  y: number;
  targetAddr: number;
  sources: number[];
}

type DisplayRow =
  | { kind: "label"; fn: DisasmFunction }
  | { kind: "insn"; insn: Instruction }
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

function ColoredOperand({ opStr }: { opStr: string }) {
  const tokens = useMemo(() => tokenizeOperand(opStr), [opStr]);
  return (
    <>
      {tokens.map((t, i) => (
        t.cls ? <span key={i} className={t.cls}>{t.text}</span> : <span key={i}>{t.text}</span>
      ))}
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

  // Disassemble the current section
  useEffect(() => {
    if (!pe || !sectionInfo || !state.disasmReady) return;

    setDisassembling(true);
    const timer = setTimeout(() => {
      try {
        const sectionBytes = new Uint8Array(
          pe.buffer,
          sectionInfo.pointerToRawData,
          sectionInfo.sizeOfRawData,
        );
        const baseAddr = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;
        const result = disasmEngine.disassemble(
          sectionBytes,
          baseAddr,
          pe.is64,
          pe.strings,
        );
        setInstructions(result);
        setDisasmError(null);
      } catch (e) {
        setDisasmError(e instanceof Error ? e.message : "Disassembly failed");
        setInstructions([]);
      } finally {
        setDisassembling(false);
      }
    }, 0);
    return () => clearTimeout(timer);
  }, [pe, sectionInfo, state.disasmReady]);

  // Build funcMap for O(1) lookup
  const funcMap = useMemo(() => {
    const m = new Map<number, DisasmFunction>();
    for (const fn of state.functions) m.set(fn.address, fn);
    return m;
  }, [state.functions]);

  // Build xref map
  const xrefMap = useMemo(() => {
    if (instructions.length === 0) return new Map<number, number[]>();
    return disasmEngine.buildXrefMap(instructions);
  }, [instructions]);

  // Bookmark address set for O(1) lookup
  const bookmarkSet = useMemo(() => {
    const s = new Set<number>();
    for (const b of state.bookmarks) s.add(b.address);
    return s;
  }, [state.bookmarks]);

  // Build display rows (with basic block separators)
  const rows: DisplayRow[] = useMemo(() => {
    const result: DisplayRow[] = [];
    const separatorMnemonics = new Set(["ret", "retn", "jmp", "int3"]);
    for (let i = 0; i < instructions.length; i++) {
      const insn = instructions[i];
      const fn = funcMap.get(insn.address);
      if (fn) {
        result.push({ kind: "label", fn });
      }
      result.push({ kind: "insn", insn });
      // Insert separator after ret/retn/jmp/int3, unless next instruction is a function label
      if (separatorMnemonics.has(insn.mnemonic)) {
        const next = instructions[i + 1];
        if (next && !funcMap.has(next.address)) {
          result.push({ kind: "separator" });
        }
      }
    }
    return result;
  }, [instructions, funcMap]);

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
        (document.activeElement as HTMLElement)?.blur();
        return;
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

      if (e.key === "b" || e.key === "B") {
        e.preventDefault();
        dispatch({ type: "TOGGLE_BOOKMARK" });
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
    [currentIndex, rows, dispatch, showSearch, showShortcuts, ctxMenu],
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
          const text = `${insn.address.toString(16)} ${insn.mnemonic} ${insn.opStr} ${insn.comment || ""}`;
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
    [rows, currentIndex, dispatch, state.renames],
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
      dispatch({ type: "SET_ADDRESS", address });
    },
    [dispatch],
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

      {/* Disassembly content */}
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
          }}
        >
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
              const xrefs = xrefMap.get(row.fn.address);
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
                  <span>; ──── {displayName} ────</span>
                  {xrefCount > 0 && (
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
                      ({xrefCount} xref{xrefCount !== 1 ? "s" : ""})
                    </span>
                  )}
                </div>
              );
            }

            const insn = row.insn;
            const bytesHex = Array.from(insn.bytes)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(" ");

            const isBookmarked = bookmarkSet.has(insn.address);
            const isCurrentAddr = insn.address === state.currentAddress;
            const isSearchMatch =
              searchMatches.length > 0 &&
              searchMatchIdx >= 0 &&
              searchMatches[searchMatchIdx] === vItem.index;

            const branchTarget = parseBranchTarget(insn.mnemonic, insn.opStr);

            return (
              <div
                key={vItem.index}
                data-index={vItem.index}
                className={`disasm-row flex px-4 ${
                  isSearchMatch
                    ? "bg-yellow-900/30"
                    : isCurrentAddr
                      ? "bg-blue-900/30"
                      : ""
                }`}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: "20px",
                  transform: `translateY(${vItem.start}px)`,
                }}
                onContextMenu={(e) => handleContextMenu(e, insn)}
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
                {branchTarget !== null ? (
                  <span
                    className="disasm-operands flex-1 text-blue-400 underline cursor-pointer hover:text-blue-300"
                    onClick={() =>
                      dispatch({
                        type: "SET_ADDRESS",
                        address: branchTarget,
                      })
                    }
                    onDoubleClick={() => handleDoubleClickInsn(insn)}
                  >
                    {insn.opStr}
                  </span>
                ) : (
                  <span
                    className="disasm-operands flex-1"
                    onDoubleClick={() => handleDoubleClickInsn(insn)}
                  >
                    <ColoredOperand opStr={insn.opStr} />
                  </span>
                )}
                {insn.comment && (
                  <span
                    className="disasm-comment ml-4 truncate max-w-xs"
                    title={insn.comment.length > 60 ? insn.comment : undefined}
                  >
                    ; {insn.comment}
                  </span>
                )}
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
              {ctxMenu && funcMap.has(ctxMenu.insn.address) && (
                <button onClick={ctxRenameFunction} className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200">
                  Rename function
                </button>
              )}
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
              {xrefPopup.sources.map((src, i) => (
                <button
                  key={i}
                  className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-blue-400 font-mono"
                  onClick={() => {
                    dispatch({ type: "SET_ADDRESS", address: src });
                    setXrefPopup(null);
                  }}
                >
                  0x{src.toString(16).toUpperCase()}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

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
                  ["Enter", "Next search result"],
                  ["Shift+Enter", "Previous search result"],
                  ["B", "Toggle bookmark at current address"],
                  ["↑ / ↓", "Navigate instructions"],
                  ["PgUp / PgDn", "Scroll 40 instructions"],
                  ["1–7", "Switch tabs"],
                  ["Alt+← / Alt+→", "Navigate back / forward"],
                  ["?", "Toggle this help"],
                  ["Esc", "Dismiss / blur"],
                  ["Double-click addr", "Copy address"],
                  ["Double-click label", "Rename function"],
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
