import { useRef, useState, useEffect, useCallback } from "react";
import { useAppState, useAppDispatch, getDisplayName } from "../hooks/usePEFile";
import { useContainingFunc, useSectionInfo } from "../hooks/useDerivedState";

export function Breadcrumbs() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const containingFunc = useContainingFunc();
  const sectionInfo = useSectionInfo();
  const scrollRef = useRef<HTMLDivElement>(null);
  const [fades, setFades] = useState({ left: false, right: false });

  const updateFades = useCallback(() => {
    const el = scrollRef.current;
    if (!el) return;
    setFades({
      left: el.scrollLeft > 2,
      right: el.scrollLeft < el.scrollWidth - el.clientWidth - 2,
    });
  }, []);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    el.addEventListener("scroll", updateFades, { passive: true });
    const ro = new ResizeObserver(updateFades);
    ro.observe(el);
    updateFades();
    return () => {
      el.removeEventListener("scroll", updateFades);
      ro.disconnect();
    };
  }, [updateFades]);

  // Auto-scroll to end when call stack changes
  useEffect(() => {
    const el = scrollRef.current;
    if (el) el.scrollLeft = el.scrollWidth;
  }, [state.callStack.length]);

  if (!pe) return null;

  const sectionVA = sectionInfo ? pe.optionalHeader.imageBase + sectionInfo.virtualAddress : null;
  const funcName = containingFunc ? getDisplayName(containingFunc, state.renames) : null;

  // Don't render if we have nothing useful to show
  if (!sectionInfo && !funcName && state.callStack.length === 0) return null;

  return (
    <div className="relative shrink-0">
      {fades.left && (
        <div
          className="absolute left-0 top-0 bottom-0 w-8 z-10 pointer-events-none"
          style={{ background: "linear-gradient(to right, var(--panel-bg, rgb(31 41 55 / 0.6)), transparent)" }}
        />
      )}
      {fades.right && (
        <div
          className="absolute right-0 top-0 bottom-0 w-8 z-10 pointer-events-none"
          style={{ background: "linear-gradient(to left, var(--panel-bg, rgb(31 41 55 / 0.6)), transparent)" }}
        />
      )}
      <div
        ref={scrollRef}
        className="flex items-center gap-0.5 px-4 py-0.5 bg-gray-800/60 border-b border-gray-700/50 text-[10px] text-gray-400 overflow-x-auto shrink-0"
        style={{ scrollbarWidth: "none" }}
      >
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
    </div>
  );
}
