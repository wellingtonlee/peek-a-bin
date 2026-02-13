import { useAppState, useAppDispatch } from "../hooks/usePEFile";

export function Sidebar() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  if (!pe) return null;

  return (
    <aside className="w-56 bg-gray-900 border-r border-gray-700 flex flex-col overflow-hidden text-xs">
      {/* Sections */}
      <div className="p-2 border-b border-gray-700">
        <h3 className="text-gray-400 uppercase tracking-wider text-[10px] mb-1.5 font-semibold">
          Sections
        </h3>
        <ul className="space-y-0.5">
          {pe.sections.map((sec, i) => (
            <li key={i}>
              <button
                onClick={() => {
                  dispatch({ type: "SET_SELECTED_SECTION", index: i });
                  dispatch({
                    type: "SET_ADDRESS",
                    address: pe.optionalHeader.imageBase + sec.virtualAddress,
                  });
                  dispatch({ type: "SET_TAB", tab: "disassembly" });
                }}
                className="w-full text-left px-2 py-1 rounded hover:bg-gray-800 transition-colors flex justify-between"
              >
                <span className="text-gray-200">{sec.name}</span>
                <span className="text-gray-500">
                  {(sec.virtualSize >>> 0).toString(16)}
                </span>
              </button>
            </li>
          ))}
        </ul>
      </div>

      {/* Functions */}
      <div className="flex-1 overflow-auto p-2">
        <h3 className="text-gray-400 uppercase tracking-wider text-[10px] mb-1.5 font-semibold">
          Functions ({state.functions.length})
        </h3>
        <ul className="space-y-0.5">
          {state.functions.map((fn, i) => (
            <li key={i}>
              <button
                onClick={() => {
                  dispatch({ type: "SET_ADDRESS", address: fn.address });
                  dispatch({ type: "SET_TAB", tab: "disassembly" });
                }}
                className="w-full text-left px-2 py-1 rounded hover:bg-gray-800 transition-colors truncate text-gray-300"
                title={`${fn.name} @ 0x${fn.address.toString(16)}`}
              >
                {fn.name}
              </button>
            </li>
          ))}
        </ul>
      </div>

      {/* Info */}
      <div className="p-2 border-t border-gray-700 text-gray-500">
        <div>{pe.is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)"}</div>
        <div>{pe.sections.length} sections</div>
        <div>{pe.imports.length} imports</div>
      </div>
    </aside>
  );
}
