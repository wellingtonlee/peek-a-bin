import { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { useAppState, useAppDispatch, getDisplayName } from "../hooks/usePEFile";
import type { DisasmFunction } from "../disasm/types";
import { fuzzyMatch } from "../utils/fuzzyMatch";

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

interface ResultItem {
  category: "Functions" | "Imports" | "Exports" | "Strings";
  label: string;
  address: number;
  tab?: "disassembly" | "imports" | "exports" | "strings";
}

const CAP = 15;

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIdx(0);
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const sortedFuncs = useMemo(() => {
    return [...state.functions].sort((a, b) => a.address - b.address);
  }, [state.functions]);

  const results = useMemo((): ResultItem[] => {
    if (!pe || !query) return [];
    const items: ResultItem[] = [];

    // Functions
    let count = 0;
    for (const fn of sortedFuncs) {
      if (count >= CAP) break;
      const name = getDisplayName(fn, state.renames);
      if (fuzzyMatch(query, name)) {
        items.push({ category: "Functions", label: name, address: fn.address, tab: "disassembly" });
        count++;
      }
    }

    // Imports
    count = 0;
    if (pe.imports) {
      for (const imp of pe.imports) {
        if (count >= CAP) break;
        for (let fi = 0; fi < imp.functions.length; fi++) {
          if (count >= CAP) break;
          const funcName = imp.functions[fi];
          const label = `${imp.libraryName}!${funcName}`;
          if (fuzzyMatch(query, label)) {
            const addr = imp.iatAddresses[fi] ?? 0;
            items.push({ category: "Imports", label, address: addr, tab: "imports" });
            count++;
          }
        }
      }
    }

    // Exports
    count = 0;
    if (pe.exports) {
      for (const exp of pe.exports) {
        if (count >= CAP) break;
        if (fuzzyMatch(query, exp.name)) {
          const addr = pe.optionalHeader.imageBase + exp.address;
          items.push({ category: "Exports", label: exp.name, address: addr, tab: "exports" });
          count++;
        }
      }
    }

    // Strings
    count = 0;
    if (pe.strings) {
      for (const [addr, str] of pe.strings) {
        if (count >= CAP) break;
        if (fuzzyMatch(query, str)) {
          items.push({ category: "Strings", label: str.length > 80 ? str.substring(0, 77) + "..." : str, address: addr, tab: "strings" });
          count++;
        }
      }
    }

    return items;
  }, [pe, query, sortedFuncs, state.renames]);

  useEffect(() => {
    setSelectedIdx(0);
  }, [results.length]);

  const handleSelect = useCallback((item: ResultItem) => {
    dispatch({ type: "SET_ADDRESS", address: item.address });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
    onClose();
  }, [dispatch, onClose]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setSelectedIdx((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setSelectedIdx((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter" && results.length > 0) {
      e.preventDefault();
      handleSelect(results[selectedIdx]);
    } else if (e.key === "Escape") {
      e.preventDefault();
      onClose();
    }
  }, [results, selectedIdx, handleSelect, onClose]);

  // Scroll selected into view
  useEffect(() => {
    const container = listRef.current;
    if (!container) return;
    const el = container.querySelector(`[data-idx="${selectedIdx}"]`);
    if (el) el.scrollIntoView({ block: "nearest" });
  }, [selectedIdx]);

  if (!open) return null;

  // Group results by category for display
  let currentCategory = "";

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/50"
      onClick={onClose}
    >
      <div
        className="w-[600px] bg-gray-800 border border-gray-600 rounded-lg shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="p-3 border-b border-gray-700">
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search functions, imports, exports, strings..."
            className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>
        <div ref={listRef} className="max-h-[400px] overflow-auto">
          {query && results.length === 0 && (
            <div className="px-4 py-8 text-center text-gray-500 text-sm">No results</div>
          )}
          {!query && (
            <div className="px-4 py-8 text-center text-gray-500 text-sm">
              Type to search across functions, imports, exports, and strings
            </div>
          )}
          {results.map((item, i) => {
            const showHeader = item.category !== currentCategory;
            currentCategory = item.category;
            return (
              <div key={`${item.category}-${item.address}-${i}`}>
                {showHeader && (
                  <div className="px-4 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider bg-gray-800/80 sticky top-0">
                    {item.category}
                  </div>
                )}
                <button
                  data-idx={i}
                  className={`w-full text-left px-4 py-1.5 flex items-center gap-3 text-xs ${
                    i === selectedIdx
                      ? "bg-blue-600/30 text-white"
                      : "text-gray-300 hover:bg-gray-700/50"
                  }`}
                  onClick={() => handleSelect(item)}
                  onMouseEnter={() => setSelectedIdx(i)}
                >
                  <span className="text-gray-500 font-mono text-[10px] w-28 shrink-0">
                    0x{item.address.toString(16).toUpperCase()}
                  </span>
                  <span className="truncate">{item.label}</span>
                </button>
              </div>
            );
          })}
        </div>
        <div className="px-4 py-2 border-t border-gray-700 text-[10px] text-gray-500 flex items-center gap-4">
          <span><kbd className="px-1 py-0.5 bg-gray-700 rounded">Enter</kbd> navigate</span>
          <span><kbd className="px-1 py-0.5 bg-gray-700 rounded">Up/Down</kbd> select</span>
          <span><kbd className="px-1 py-0.5 bg-gray-700 rounded">Esc</kbd> close</span>
        </div>
      </div>
    </div>
  );
}
