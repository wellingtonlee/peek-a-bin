import { useAppState, useAppDispatch } from "../hooks/usePEFile";

export function Breadcrumbs() {
  const state = useAppState();
  const dispatch = useAppDispatch();

  if (state.callStack.length === 0) return null;

  return (
    <div className="flex items-center gap-0.5 px-4 py-0.5 bg-gray-800/60 border-b border-gray-700/50 text-[10px] text-gray-400 overflow-x-auto shrink-0">
      {state.callStack.map((entry, i) => (
        <span key={`${entry.address}-${i}`} className="flex items-center gap-0.5 shrink-0">
          {i > 0 && <span className="text-gray-600 mx-0.5">&rsaquo;</span>}
          <button
            className="hover:text-blue-400 hover:underline truncate max-w-[140px]"
            onClick={() => {
              dispatch({ type: "SET_ADDRESS", address: entry.address });
              dispatch({ type: "POP_CALL_STACK", index: i });
            }}
            title={`0x${entry.address.toString(16).toUpperCase()} - ${entry.name}`}
          >
            {entry.name}
          </button>
        </span>
      ))}
    </div>
  );
}
