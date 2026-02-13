import { useEffect, useRef, useMemo, useCallback, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import { disasmEngine } from "../disasm/engine";
import type { Instruction, DisasmFunction } from "../disasm/types";

type DisplayRow =
  | { kind: "label"; fn: DisasmFunction }
  | { kind: "insn"; insn: Instruction };

function binarySearchRows(rows: DisplayRow[], address: number): number {
  let lo = 0;
  let hi = rows.length - 1;
  let best = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const row = rows[mid];
    const rowAddr =
      row.kind === "insn" ? row.insn.address : row.fn.address;
    if (rowAddr <= address) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

// Parse branch/call target address from operand
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
    // Use setTimeout to allow paint of "Disassembling..." before blocking
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

  // Build display rows with label rows inserted before function starts
  const rows: DisplayRow[] = useMemo(() => {
    const result: DisplayRow[] = [];
    for (const insn of instructions) {
      const fn = funcMap.get(insn.address);
      if (fn) {
        result.push({ kind: "label", fn });
      }
      result.push({ kind: "insn", insn });
    }
    return result;
  }, [instructions, funcMap]);

  // Binary search for currentIndex
  const currentIndex = useMemo(() => {
    if (rows.length === 0) return 0;
    return binarySearchRows(rows, state.currentAddress);
  }, [rows, state.currentAddress]);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 20,
    overscan: 50,
  });

  // Scroll to current address when it changes
  useEffect(() => {
    if (rows.length > 0 && currentIndex >= 0) {
      virtualizer.scrollToIndex(currentIndex, { align: "center" });
    }
  }, [currentIndex, rows.length]);

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (showSearch && e.key === "Escape") {
        setShowSearch(false);
        setSearchQuery("");
        setSearchMatches([]);
        setSearchMatchIdx(-1);
        parentRef.current?.focus();
        return;
      }

      if (e.key === "Escape") {
        (document.activeElement as HTMLElement)?.blur();
        return;
      }

      // Don't handle keys if focused on input
      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA"
      )
        return;

      if (e.key === "g" || e.key === "G") {
        e.preventDefault();
        // Focus the address bar input
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
        const newIdx = Math.min(
          currentIndex + scrollAmount,
          rows.length - 1,
        );
        const row = rows[newIdx];
        if (row) {
          const addr =
            row.kind === "insn" ? row.insn.address : row.fn.address;
          dispatch({ type: "SET_ADDRESS", address: addr });
        }
      }

      if (e.key === "ArrowUp" || e.key === "PageUp") {
        e.preventDefault();
        const newIdx = Math.max(currentIndex - scrollAmount, 0);
        const row = rows[newIdx];
        if (row) {
          const addr =
            row.kind === "insn" ? row.insn.address : row.fn.address;
          dispatch({ type: "SET_ADDRESS", address: addr });
        }
      }
    },
    [currentIndex, rows, dispatch, showSearch],
  );

  // Search logic
  const handleSearch = useCallback(
    (query: string, direction: 1 | -1 = 1) => {
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
          if (row.fn.name.toLowerCase().includes(q)) matches.push(i);
        } else {
          const insn = row.insn;
          const text = `${insn.address.toString(16)} ${insn.mnemonic} ${insn.opStr} ${insn.comment || ""}`;
          if (text.toLowerCase().includes(q)) matches.push(i);
        }
      }
      setSearchMatches(matches);
      if (matches.length > 0) {
        // Find first match at or after currentIndex
        let idx = matches.findIndex((m) => m >= currentIndex);
        if (idx === -1) idx = 0;
        if (direction === -1) {
          idx = idx - 1;
          if (idx < 0) idx = matches.length - 1;
        }
        setSearchMatchIdx(idx);
        const matchRow = rows[matches[idx]];
        if (matchRow) {
          const addr =
            matchRow.kind === "insn"
              ? matchRow.insn.address
              : matchRow.fn.address;
          dispatch({ type: "SET_ADDRESS", address: addr });
        }
      } else {
        setSearchMatchIdx(-1);
      }
    },
    [rows, currentIndex, dispatch],
  );

  const handleSearchNext = useCallback(() => {
    if (searchMatches.length === 0) return;
    const next = (searchMatchIdx + 1) % searchMatches.length;
    setSearchMatchIdx(next);
    const matchRow = rows[searchMatches[next]];
    if (matchRow) {
      const addr =
        matchRow.kind === "insn"
          ? matchRow.insn.address
          : matchRow.fn.address;
      dispatch({ type: "SET_ADDRESS", address: addr });
    }
  }, [searchMatches, searchMatchIdx, rows, dispatch]);

  const handleSearchPrev = useCallback(() => {
    if (searchMatches.length === 0) return;
    const prev =
      (searchMatchIdx - 1 + searchMatches.length) % searchMatches.length;
    setSearchMatchIdx(prev);
    const matchRow = rows[searchMatches[prev]];
    if (matchRow) {
      const addr =
        matchRow.kind === "insn"
          ? matchRow.insn.address
          : matchRow.fn.address;
      dispatch({ type: "SET_ADDRESS", address: addr });
    }
  }, [searchMatches, searchMatchIdx, rows, dispatch]);

  const handleAddressClick = useCallback(
    (address: number) => {
      dispatch({ type: "SET_ADDRESS", address });
    },
    [dispatch],
  );

  // Double-click to copy
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
            {searchQuery && searchMatches.length === 0 && (
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
                parentRef.current?.focus();
              }}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
            >
              ✕
            </button>
          </div>
        )}
      </div>

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

            if (row.kind === "label") {
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
                  ; ──── {row.fn.name} ────
                </div>
              );
            }

            const insn = row.insn;
            const bytesHex = Array.from(insn.bytes)
              .map((b) => b.toString(16).padStart(2, "0"))
              .join(" ");

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
              >
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
                  className="disasm-mnemonic w-16 shrink-0 font-semibold"
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
                    {insn.opStr}
                  </span>
                )}
                {insn.comment && (
                  <span className="disasm-comment ml-4 truncate max-w-xs">
                    ; {insn.comment}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
