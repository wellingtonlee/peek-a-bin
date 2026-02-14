import { useState, useCallback, useRef, useEffect } from "react";
import { useAppState, useAppDispatch, type ViewTab, type Bookmark } from "../hooks/usePEFile";

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

export function AddressBar() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const [input, setInput] = useState("");
  const [invalid, setInvalid] = useState(false);
  const invalidTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const handleGo = useCallback(() => {
    const cleaned = input.replace(/^0[xX]/, "");
    const addr = parseInt(cleaned, 16);
    if (!isNaN(addr) && cleaned.length > 0) {
      dispatch({ type: "SET_ADDRESS", address: addr });
      dispatch({ type: "SET_TAB", tab: "disassembly" });
      setInput("");
      setInvalid(false);
    } else {
      setInvalid(true);
      clearTimeout(invalidTimer.current);
      invalidTimer.current = setTimeout(() => setInvalid(false), 1000);
    }
  }, [input, dispatch]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") handleGo();
      if (e.key === "Escape") (e.target as HTMLElement).blur();
    },
    [handleGo],
  );

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
    // Reset input so same file can be re-imported
    e.target.value = "";
  }, [dispatch]);

  // Global keyboard shortcuts for tab switching and nav
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      const tag = (document.activeElement?.tagName ?? "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;

      // Tab shortcuts 1-6
      const tab = TAB_KEYS[e.key];
      if (tab) {
        e.preventDefault();
        dispatch({ type: "SET_TAB", tab });
        return;
      }

      // Alt+Left/Right for navigation history
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

      <input
        type="text"
        value={input}
        onChange={(e) => setInput(e.target.value)}
        onKeyDown={handleKeyDown}
        placeholder="Go to address (hex)..."
        className={`w-48 px-2 py-1 bg-gray-800 border rounded text-gray-200 placeholder-gray-500 text-xs focus:outline-none focus:border-blue-500 transition-colors ${
          invalid ? "border-red-500" : "border-gray-600"
        }`}
      />
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
