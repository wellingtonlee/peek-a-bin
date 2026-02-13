import { useState, useCallback, useRef } from "react";
import { useAppState, useAppDispatch, type ViewTab } from "../hooks/usePEFile";

const TABS: { id: ViewTab; label: string }[] = [
  { id: "disassembly", label: "Disassembly" },
  { id: "headers", label: "Headers" },
  { id: "sections", label: "Sections" },
  { id: "imports", label: "Imports" },
  { id: "exports", label: "Exports" },
  { id: "hex", label: "Hex" },
];

export function AddressBar() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const [input, setInput] = useState("");
  const [invalid, setInvalid] = useState(false);
  const invalidTimer = useRef<ReturnType<typeof setTimeout>>(undefined);

  const handleGo = useCallback(() => {
    // Strip 0x/0X prefix before parsing
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

      {TABS.map((tab) => (
        <button
          key={tab.id}
          onClick={() => dispatch({ type: "SET_TAB", tab: tab.id })}
          className={`px-2.5 py-1 rounded transition-colors ${
            state.activeTab === tab.id
              ? "bg-blue-600 text-white"
              : "text-gray-400 hover:text-white hover:bg-gray-700"
          }`}
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
    </div>
  );
}
