import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { useAppState, useAppDispatch, getDisplayName, type ViewTab, type Bookmark } from "../hooks/usePEFile";
import { useSortedFuncs } from "../hooks/useDerivedState";
import { fuzzyMatch } from "../utils/fuzzyMatch";

const TABS: { id: ViewTab; label: string }[] = [
  { id: "disassembly", label: "Disassembly" },
  { id: "headers", label: "Headers" },
  { id: "sections", label: "Sections" },
  { id: "imports", label: "Imports" },
  { id: "exports", label: "Exports" },
  { id: "hex", label: "Hex" },
  { id: "strings", label: "Strings" },
];

const TAB_KEYS: Record<string, ViewTab> = {
  "1": "disassembly",
  "2": "headers",
  "3": "sections",
  "4": "imports",
  "5": "exports",
  "6": "hex",
  "7": "strings",
};

interface Suggestion {
  label: string;
  address: number;
  category: "function" | "export";
}

export function AddressBar() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const [input, setInput] = useState("");
  const [invalid, setInvalid] = useState(false);
  const invalidTimer = useRef<ReturnType<typeof setTimeout>>(undefined);
  const [suggestions, setSuggestions] = useState<Suggestion[]>([]);
  const [suggestionIdx, setSuggestionIdx] = useState(-1);
  const [showSuggestions, setShowSuggestions] = useState(false);
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const containerRef = useRef<HTMLDivElement>(null);

  const sortedFuncs = useSortedFuncs();

  const exports = useMemo(() => {
    if (!state.peFile) return [];
    return state.peFile.exports.map((e) => ({
      name: e.name,
      address: state.peFile!.optionalHeader.imageBase + e.address,
    }));
  }, [state.peFile]);

  const computeSuggestions = useCallback((query: string) => {
    if (!query || query.length < 1) {
      setSuggestions([]);
      setShowSuggestions(false);
      return;
    }

    const results: Suggestion[] = [];

    // Match functions (cap 5)
    let count = 0;
    for (const fn of sortedFuncs) {
      if (count >= 5) break;
      const name = getDisplayName(fn, state.renames);
      if (fuzzyMatch(query, name)) {
        results.push({ label: name, address: fn.address, category: "function" });
        count++;
      }
    }

    // Match exports (cap 3)
    count = 0;
    for (const exp of exports) {
      if (count >= 3) break;
      if (fuzzyMatch(query, exp.name)) {
        // Avoid duplicates
        if (!results.some((r) => r.address === exp.address)) {
          results.push({ label: exp.name, address: exp.address, category: "export" });
          count++;
        }
      }
    }

    setSuggestions(results.slice(0, 8));
    setSuggestionIdx(-1);
    setShowSuggestions(results.length > 0);
  }, [sortedFuncs, exports, state.renames]);

  const handleInputChange = useCallback((value: string) => {
    setInput(value);
    clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => computeSuggestions(value), 80);
  }, [computeSuggestions]);

  const selectSuggestion = useCallback((s: Suggestion) => {
    dispatch({ type: "SET_ADDRESS", address: s.address });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
    setInput("");
    setSuggestions([]);
    setShowSuggestions(false);
    setInvalid(false);
  }, [dispatch]);

  const handleGo = useCallback(() => {
    // If a suggestion is selected, use it
    if (showSuggestions && suggestionIdx >= 0 && suggestionIdx < suggestions.length) {
      selectSuggestion(suggestions[suggestionIdx]);
      return;
    }

    const cleaned = input.replace(/^0[xX]/, "");
    const addr = parseInt(cleaned, 16);
    if (!isNaN(addr) && cleaned.length > 0) {
      dispatch({ type: "SET_ADDRESS", address: addr });
      dispatch({ type: "SET_TAB", tab: "disassembly" });
      setInput("");
      setInvalid(false);
      setShowSuggestions(false);
    } else {
      setInvalid(true);
      clearTimeout(invalidTimer.current);
      invalidTimer.current = setTimeout(() => setInvalid(false), 1000);
    }
  }, [input, dispatch, showSuggestions, suggestionIdx, suggestions, selectSuggestion]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (showSuggestions && suggestions.length > 0) {
        if (e.key === "ArrowDown") {
          e.preventDefault();
          setSuggestionIdx((i) => Math.min(i + 1, suggestions.length - 1));
          return;
        }
        if (e.key === "ArrowUp") {
          e.preventDefault();
          setSuggestionIdx((i) => Math.max(i - 1, 0));
          return;
        }
        if (e.key === "Enter") {
          e.preventDefault();
          if (suggestionIdx >= 0) {
            selectSuggestion(suggestions[suggestionIdx]);
          } else {
            handleGo();
          }
          return;
        }
        if (e.key === "Escape") {
          setShowSuggestions(false);
          setSuggestions([]);
          return;
        }
      } else {
        if (e.key === "Enter") { handleGo(); return; }
        if (e.key === "Escape") { (e.target as HTMLElement).blur(); return; }
      }
    },
    [handleGo, showSuggestions, suggestions, suggestionIdx, selectSuggestion],
  );

  // Close suggestions when clicking outside
  useEffect(() => {
    if (!showSuggestions) return;
    const handler = (e: MouseEvent) => {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setShowSuggestions(false);
      }
    };
    document.addEventListener("mousedown", handler);
    return () => document.removeEventListener("mousedown", handler);
  }, [showSuggestions]);

  const handleReset = useCallback(() => {
    dispatch({ type: "RESET" });
  }, [dispatch]);

  const importInputRef = useRef<HTMLInputElement>(null);

  const handleExport = useCallback(() => {
    const data = {
      fileName: state.fileName,
      exportedAt: new Date().toISOString(),
      bookmarks: state.bookmarks,
      renames: state.renames,
      comments: state.comments,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.fileName ?? "annotations"}.annotations.json`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state.fileName, state.bookmarks, state.renames, state.comments]);

  const handleImport = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const data = JSON.parse(reader.result as string);
        const bookmarks: Bookmark[] = Array.isArray(data.bookmarks) ? data.bookmarks : [];
        const renames: Record<number, string> = data.renames && typeof data.renames === "object" ? data.renames : {};
        const comments: Record<number, string> = data.comments && typeof data.comments === "object" ? data.comments : {};
        dispatch({ type: "IMPORT_ANNOTATIONS", bookmarks, renames, comments });
      } catch { /* ignore bad JSON */ }
    };
    reader.readAsText(file);
    e.target.value = "";
  }, [dispatch]);

  // Global keyboard shortcuts for tab switching and nav
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (document.activeElement?.tagName ?? "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;

      const tab = TAB_KEYS[e.key];
      if (tab) {
        e.preventDefault();
        dispatch({ type: "SET_TAB", tab });
        return;
      }

      if (e.altKey && e.key === "ArrowLeft") {
        e.preventDefault();
        dispatch({ type: "NAV_BACK" });
        return;
      }
      if (e.altKey && e.key === "ArrowRight") {
        e.preventDefault();
        dispatch({ type: "NAV_FORWARD" });
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key === "z" && !e.shiftKey) {
        e.preventDefault();
        dispatch({ type: "UNDO_ANNOTATION" });
        return;
      }
      if ((e.ctrlKey || e.metaKey) && (e.key === "Z" || (e.key === "z" && e.shiftKey))) {
        e.preventDefault();
        dispatch({ type: "REDO_ANNOTATION" });
        return;
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [dispatch]);

  const canGoBack = state.historyIndex > 0;
  const canGoForward = state.historyIndex < state.addressHistory.length - 1;

  return (
    <div className="flex items-center gap-1 px-3 py-1.5 bg-gray-900 border-b border-gray-700 text-sm">
      <button
        onClick={handleReset}
        className="px-2 py-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors"
        title="Load new file"
      >
        Open
      </button>

      <div className="w-px h-5 bg-gray-700 mx-1" />

      {/* Back / Forward */}
      <button
        onClick={() => dispatch({ type: "NAV_BACK" })}
        disabled={!canGoBack}
        className="px-1.5 py-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors disabled:opacity-30 disabled:cursor-default"
        title="Back (Alt+Left)"
      >
        ◀
      </button>
      <button
        onClick={() => dispatch({ type: "NAV_FORWARD" })}
        disabled={!canGoForward}
        className="px-1.5 py-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors disabled:opacity-30 disabled:cursor-default"
        title="Forward (Alt+Right)"
      >
        ▶
      </button>

      <div className="w-px h-5 bg-gray-700 mx-1" />

      {/* Undo / Redo */}
      <button
        onClick={() => dispatch({ type: "UNDO_ANNOTATION" })}
        disabled={state.annotationUndoStack.length === 0}
        className="px-1.5 py-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors disabled:opacity-30 disabled:cursor-default text-xs"
        title="Undo annotation (Ctrl+Z)"
      >
        Undo
      </button>
      <button
        onClick={() => dispatch({ type: "REDO_ANNOTATION" })}
        disabled={state.annotationRedoStack.length === 0}
        className="px-1.5 py-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded transition-colors disabled:opacity-30 disabled:cursor-default text-xs"
        title="Redo annotation (Ctrl+Shift+Z)"
      >
        Redo
      </button>

      <div className="w-px h-5 bg-gray-700 mx-1" />

      {TABS.map((tab, i) => (
        <button
          key={tab.id}
          onClick={() => dispatch({ type: "SET_TAB", tab: tab.id })}
          className={`px-2.5 py-1 rounded transition-colors ${
            state.activeTab === tab.id
              ? "bg-blue-600 text-white"
              : "text-gray-400 hover:text-white hover:bg-gray-700"
          }`}
          title={`${tab.label} (${i + 1})`}
        >
          {tab.label}
        </button>
      ))}

      <div className="flex-1" />

      {!state.disasmReady && (
        <span className="text-yellow-500 text-xs mr-2 flex items-center gap-1">
          <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Loading engine...
        </span>
      )}

      <span className="text-gray-500 text-xs mr-2">
        VA: 0x{state.currentAddress.toString(16).toUpperCase().padStart(state.peFile?.is64 ? 16 : 8, "0")}
      </span>

      {/* Address input with autocomplete */}
      <div ref={containerRef} className="relative">
        <input
          type="text"
          value={input}
          onChange={(e) => handleInputChange(e.target.value)}
          onKeyDown={handleKeyDown}
          onFocus={() => { if (suggestions.length > 0) setShowSuggestions(true); }}
          placeholder="Go to address (hex)..."
          className={`w-48 px-2 py-1 bg-gray-800 border rounded text-gray-200 placeholder-gray-500 text-xs focus:outline-none focus:border-blue-500 transition-colors ${
            invalid ? "border-red-500" : "border-gray-600"
          }`}
        />
        {showSuggestions && suggestions.length > 0 && (
          <div className="absolute top-full left-0 mt-0.5 w-72 bg-gray-800 border border-gray-600 rounded shadow-xl z-50 max-h-52 overflow-auto">
            {suggestions.map((s, i) => (
              <button
                key={`${s.address}-${i}`}
                className={`w-full text-left px-2 py-1.5 text-xs flex items-center gap-2 ${
                  i === suggestionIdx ? "bg-blue-600/30 text-white" : "text-gray-300 hover:bg-gray-700/50"
                }`}
                onMouseDown={(e) => { e.preventDefault(); selectSuggestion(s); }}
                onMouseEnter={() => setSuggestionIdx(i)}
              >
                <span className="text-gray-500 font-mono text-[10px] w-24 shrink-0">
                  0x{s.address.toString(16).toUpperCase()}
                </span>
                <span className="truncate">{s.label}</span>
                <span className="ml-auto text-gray-600 text-[9px]">{s.category}</span>
              </button>
            ))}
          </div>
        )}
      </div>
      <button
        onClick={handleGo}
        className="px-2 py-1 bg-gray-700 text-gray-300 hover:bg-gray-600 rounded text-xs"
      >
        Go
      </button>

      <div className="w-px h-5 bg-gray-700 mx-1" />

      <button
        onClick={handleExport}
        className="px-2 py-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded text-xs transition-colors"
        title="Export annotations (bookmarks, renames, comments)"
      >
        Export
      </button>
      <button
        onClick={() => importInputRef.current?.click()}
        className="px-2 py-1 text-gray-400 hover:text-white hover:bg-gray-700 rounded text-xs transition-colors"
        title="Import annotations from JSON file"
      >
        Import
      </button>
      <input
        ref={importInputRef}
        type="file"
        accept=".json"
        className="hidden"
        onChange={handleImport}
      />
    </div>
  );
}
