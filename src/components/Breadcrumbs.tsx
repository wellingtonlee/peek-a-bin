import { useAppState, useAppDispatch, getDisplayName } from "../hooks/usePEFile";
import { useContainingFunc, useSectionInfo } from "../hooks/useDerivedState";

export function Breadcrumbs() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const containingFunc = useContainingFunc();
  const sectionInfo = useSectionInfo();

  if (!pe) return null;

  const sectionVA = sectionInfo ? pe.optionalHeader.imageBase + sectionInfo.virtualAddress : null;
  const funcName = containingFunc ? getDisplayName(containingFunc, state.renames) : null;

  // Don't render if we have nothing useful to show
  if (!sectionInfo && !funcName && state.callStack.length === 0) return null;

  return (
    <div className="flex items-center gap-0.5 px-4 py-0.5 bg-gray-800/60 border-b border-gray-700/50 text-[10px] text-gray-400 overflow-x-auto shrink-0">
      {/* Section node */}
      {sectionInfo && (
        <span className="flex items-center gap-0.5 shrink-0">
          <button
            className="hover:text-blue-400 hover:underline truncate max-w-[140px]"
            onClick={() => {
              if (sectionVA !== null) {
                dispatch({ type: "CLEAR_CALL_STACK" });
                dispatch({ type: "SET_ADDRESS", address: sectionVA });
              }
            }}
            title={`0x${sectionVA?.toString(16).toUpperCase() ?? "?"} – ${sectionInfo.name}`}
          >
            {sectionInfo.name}
          </button>
        </span>
      )}

      {/* Function node */}
      {funcName && containingFunc && (
        <span className="flex items-center gap-0.5 shrink-0">
          <span className="text-gray-600 mx-0.5">&rsaquo;</span>
          <button
            className="hover:text-blue-400 hover:underline truncate max-w-[140px]"
            onClick={() => {
              dispatch({ type: "CLEAR_CALL_STACK" });
              dispatch({ type: "SET_ADDRESS", address: containingFunc.address });
            }}
            title={`0x${containingFunc.address.toString(16).toUpperCase()} – ${funcName}`}
          >
            {funcName}
          </button>
        </span>
      )}

      {/* Call stack entries */}
      {state.callStack.map((entry, i) => (
        <span key={`${entry.address}-${i}`} className="flex items-center gap-0.5 shrink-0">
          <span className="text-gray-600 mx-0.5">&rsaquo;</span>
          <button
            className="hover:text-blue-400 hover:underline truncate max-w-[140px]"
            onClick={() => {
              dispatch({ type: "SET_ADDRESS", address: entry.address });
              dispatch({ type: "POP_CALL_STACK", index: i });
            }}
            title={`0x${entry.address.toString(16).toUpperCase()} – ${entry.name}`}
          >
            {entry.name}
          </button>
        </span>
      ))}
    </div>
  );
}
