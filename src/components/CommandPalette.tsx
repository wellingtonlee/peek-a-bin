import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSortedFuncs } from "../hooks/useDerivedState";
import { getDisplayName, useAppDispatch, useAppState } from "../hooks/usePEFile";
import { fuzzyMatch } from "../utils/fuzzyMatch";
import { activeDescendantId, optionId } from "./listboxIds";
import { Modal } from "./Modal";

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

interface ResultItem {
  category: "Functions" | "Imports" | "Exports" | "Strings" | "AI Commands";
  label: string;
  address: number;
  tab?: "disassembly" | "imports" | "exports" | "strings";
  action?: string;
}

const CAP = 15;

/**
 * Only one palette is ever mounted, so a module constant is enough and keeps
 * the id stable across renders — `aria-activedescendant` points at it by value,
 * and an id that changed per render would leave a dangling reference.
 */
const LISTBOX_ID = "command-palette-results";

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Focusing the search field is Modal's job now (via initialFocusRef) — it runs
  // on mount, which is the same moment, without the setTimeout(0) trampoline.
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIdx(0);
    }
  }, [open]);

  const sortedFuncs = useSortedFuncs();

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
          items.push({
            category: "Strings",
            label: str.length > 80 ? str.substring(0, 77) + "..." : str,
            address: addr,
            tab: "strings",
          });
          count++;
        }
      }
    }

    // AI Commands
    const aiCommands = [
      { label: "AI: Open Chat", action: "peek-a-bin:open-chat" },
      { label: "AI: Batch Rename Functions", action: "peek-a-bin:batch-rename" },
      { label: "AI: Generate Analysis Report", action: "peek-a-bin:generate-report" },
      { label: "AI: Scan Suspicious Functions", action: "peek-a-bin:ai-scan" },
    ];
    for (const cmd of aiCommands) {
      if (fuzzyMatch(query, cmd.label) || cmd.label.toLowerCase().includes(query.toLowerCase())) {
        items.push({ category: "AI Commands", label: cmd.label, address: 0, action: cmd.action });
      }
    }

    return items;
  }, [pe, query, sortedFuncs, state.renames]);

  // results.length is a change key the body never reads: the selection resets
  // whenever the result set changes size. Removing it would reset the highlight
  // only on mount, leaving it pointing past the end of a shorter result list.
  // biome-ignore lint/correctness/useExhaustiveDependencies: results.length is the change key this reset effect is triggered by, not a value it reads.
  useEffect(() => {
    setSelectedIdx(0);
  }, [results.length]);

  const handleSelect = useCallback(
    (item: ResultItem) => {
      if (item.action) {
        window.dispatchEvent(new CustomEvent(item.action));
        onClose();
        return;
      }
      dispatch({ type: "SET_ADDRESS", address: item.address });
      dispatch({ type: "SET_TAB", tab: item.tab ?? "disassembly" });
      onClose();
    },
    [dispatch, onClose],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIdx((i) => Math.min(i + 1, results.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIdx((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter" && results.length > 0) {
        e.preventDefault();
        handleSelect(results[selectedIdx]);
      }
      // Escape is not handled here — it bubbles to Modal, which closes the dialog.
    },
    [results, selectedIdx, handleSelect],
  );

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
    <Modal
      // Named by a string rather than by a heading: the palette opens straight
      // onto its search field and has no visible title to point `labelledBy` at.
      // Adding one purely to be referenced would change the dialog for everyone
      // to satisfy an attribute.
      label="Command palette"
      onClose={onClose}
      placement="top"
      initialFocusRef={inputRef}
      className="w-[600px] shadow-2xl overflow-hidden"
    >
      <div className="p-3 border-b border-gray-700">
        {/* A combobox owning a listbox, not a text field next to buttons.
            Focus stays here while the arrow keys move selectedIdx, and
            aria-activedescendant is what tells a screen reader which row is
            selected — previously the highlight was purely visual and was
            never announced. */}
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          aria-expanded={results.length > 0}
          aria-controls={LISTBOX_ID}
          aria-activedescendant={activeDescendantId(LISTBOX_ID, selectedIdx, results.length)}
          aria-autocomplete="list"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search functions, imports, exports, strings..."
          className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>
      <div
        ref={listRef}
        id={LISTBOX_ID}
        role="listbox"
        aria-label="Search results"
        className="max-h-[400px] overflow-auto"
      >
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
            <div key={`${item.category}-${item.address}-${i}`} role="presentation">
              {showHeader && (
                <div
                  role="presentation"
                  className="px-4 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider bg-gray-800/80 sticky top-0"
                >
                  {item.category}
                </div>
              )}
              {/* An option, not a button. As a button every one of these (up to
                  60) sat in the tab order, so Tab from the search field walked
                  the whole result list and the modal focus trap cycled through
                  all of it. Keyboard activation lives on the input, which is
                  where focus actually is. */}
              {/* biome-ignore lint/a11y/useKeyWithClickEvents: arrow keys and Enter are handled by the combobox input that owns this listbox via aria-activedescendant; focus never reaches the option itself. */}
              <div
                id={optionId(LISTBOX_ID, i)}
                role="option"
                aria-selected={i === selectedIdx}
                // -1, not absent: programmatically focusable so the rule that
                // an interactive role must be reachable is satisfied honestly,
                // while staying out of the sequential tab order, which is the
                // whole point of the aria-activedescendant pattern.
                tabIndex={-1}
                data-idx={i}
                className={`w-full text-left px-4 py-1.5 flex items-center gap-3 text-xs cursor-pointer ${
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
              </div>
            </div>
          );
        })}
      </div>
      <div className="px-4 py-2 border-t border-gray-700 text-[10px] text-gray-500 flex items-center gap-4">
        <span>
          <kbd className="px-1 py-0.5 bg-gray-700 rounded">Enter</kbd> navigate
        </span>
        <span>
          <kbd className="px-1 py-0.5 bg-gray-700 rounded">Up/Down</kbd> select
        </span>
        <span>
          <kbd className="px-1 py-0.5 bg-gray-700 rounded">Esc</kbd> close
        </span>
      </div>
    </Modal>
  );
}
