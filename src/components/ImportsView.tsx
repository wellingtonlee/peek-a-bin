import { useCallback, useMemo, useRef, useState } from "react";
import { getApiRiskTag } from "../analysis/driver";
import { useDismissOnOutsideClick } from "../hooks/useDismissOnOutsideClick";
import { useAppDispatch, useAppState } from "../hooks/usePEFile";
import { parseOrdinalImport, resolveOrdinal } from "../pe/ordinalTables";
import { clampPopup } from "../utils/clampPopup";

interface XrefPopupState {
  x: number;
  y: number;
  funcName: string;
  sources: number[];
}

export function ImportsView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const filterTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleFilterChange = useCallback((value: string) => {
    setFilterInput(value);
    clearTimeout(filterTimerRef.current);
    filterTimerRef.current = setTimeout(() => setFilter(value), 250);
  }, []);
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const importXrefs = state.importXrefs;
  const [xrefPopup, setXrefPopup] = useState<XrefPopupState | null>(null);
  const popupRef = useRef<HTMLDivElement>(null);

  // Dismiss popup. Clicks inside the popup are ignored by the hook's ref check
  // rather than being stopped from propagating by a handler on the popup div.
  useDismissOnOutsideClick({
    active: xrefPopup !== null,
    ref: popupRef,
    onDismiss: () => setXrefPopup(null),
    event: "click",
    target: "window",
    dismissOnEscape: true,
    dismissIfRefMissing: true,
  });

  const filtered = useMemo(() => {
    if (!pe) return [];
    return pe.imports
      .map((imp) => ({
        ...imp,
        functions: imp.functions
          .map((fn, idx) => {
            // An import that names no function carries only an ordinal, and for
            // the DLLs pefile's `ordlookup` covers the ordinal IS a name — this
            // is the same lookup `computeImphash` makes, through the same
            // function, so the two cannot disagree about what ws2_32!115 is.
            //
            // Resolved HERE rather than at the point of render, so that the name
            // a reader sees is also the name they can search for: a user typing
            // "socket" is looking for the import, not for the string
            // "Ordinal_23". `ordinal` is kept beside it because the resolved
            // name is INFERRED FROM A TABLE and not read out of the file, and
            // the row says so.
            const ord = parseOrdinalImport(fn);
            const resolved = ord === null ? undefined : resolveOrdinal(imp.libraryName, ord);
            return {
              name: resolved ?? fn,
              ordinal: resolved ? ord : null,
              iatAddr: imp.iatAddresses[idx] ?? 0,
            };
          })
          .filter((f) => f.name.toLowerCase().includes(filter.toLowerCase())),
      }))
      .filter(
        (imp) =>
          imp.functions.length > 0 || imp.libraryName.toLowerCase().includes(filter.toLowerCase()),
      );
  }, [pe, filter]);

  const totalFunctions = useMemo(() => {
    if (!pe) return 0;
    return pe.imports.reduce((sum, imp) => sum + imp.functions.length, 0);
  }, [pe]);

  const filteredFuncCount = useMemo(
    () => filtered.reduce((sum, imp) => sum + imp.functions.length, 0),
    [filtered],
  );

  if (!pe) return null;

  const toggleCollapse = (lib: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(lib)) next.delete(lib);
      else next.add(lib);
      return next;
    });
  };

  return (
    <div className="p-4 text-xs overflow-auto h-full relative">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Imports ({pe.imports.length} libraries, {totalFunctions} functions)
        </h2>
        <input
          type="text"
          value={filterInput}
          onChange={(e) => handleFilterChange(e.target.value)}
          placeholder="Filter..."
          className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        {filter && (
          <span className="text-gray-500 text-[11px]">
            {filteredFuncCount} match{filteredFuncCount !== 1 ? "es" : ""} in {filtered.length}{" "}
            librar{filtered.length !== 1 ? "ies" : "y"}
          </span>
        )}
        <div className="flex-1" />
        {!importXrefs ? (
          <span className="text-[10px] text-gray-500 flex items-center gap-1">
            <svg aria-hidden="true" className="animate-spin h-3 w-3" viewBox="0 0 24 24">
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
                fill="none"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
            Xrefs loading...
          </span>
        ) : (
          <span className="text-[10px] text-green-400">Xrefs loaded</span>
        )}
      </div>

      <div className="space-y-1">
        {filtered.map((imp, i) => {
          const isCollapsed = collapsed.has(imp.libraryName);
          return (
            <div key={i}>
              <button
                type="button"
                onClick={() => toggleCollapse(imp.libraryName)}
                className="flex items-center gap-1.5 text-yellow-400 font-semibold hover:text-yellow-300 py-0.5"
              >
                <span className="text-[10px] text-gray-500 w-3 inline-block">
                  {isCollapsed ? "\u25B6" : "\u25BC"}
                </span>
                {imp.libraryName}
                <span className="text-gray-500 font-normal text-[10px]">
                  ({imp.functions.length})
                </span>
              </button>
              {!isCollapsed && (
                <ul className="ml-6 space-y-0.5">
                  {imp.functions.map((fn, j) => {
                    const xrefCount = importXrefs?.get(fn.iatAddr)?.length ?? 0;
                    return (
                      <li key={j} className="text-gray-300 flex items-center gap-2">
                        <span>{fn.name}</span>
                        {/* The name came from a table, not from the file. Said
                            on the row rather than left to the reader, because an
                            ordinal import and a named one are different facts
                            about the binary and a packer may have chosen the
                            ordinal deliberately. */}
                        {fn.ordinal !== null && (
                          <span
                            className="text-gray-500 text-[10px]"
                            title={`Imported by ordinal ${fn.ordinal}; the name comes from pefile's ordlookup table, not from the file`}
                          >
                            #{fn.ordinal}
                          </span>
                        )}
                        {state.driverInfo?.isDriver &&
                          (() => {
                            const risk = getApiRiskTag(fn.name);
                            if (!risk) return null;
                            return (
                              <span
                                className={`px-1 py-0.5 rounded text-[9px] font-medium ${risk.colorClass}`}
                              >
                                {risk.category}
                              </span>
                            );
                          })()}
                        {importXrefs && xrefCount > 0 && (
                          <button
                            type="button"
                            className="inline text-gray-500 cursor-pointer hover:text-blue-400 text-[10px]"
                            onClick={(e) => {
                              e.stopPropagation();
                              const rect = (e.target as HTMLElement).getBoundingClientRect();
                              const clamped = clampPopup(rect.left, rect.bottom, 220, 240);
                              setXrefPopup({
                                x: clamped.x,
                                y: clamped.y,
                                funcName: fn.name,
                                sources: importXrefs.get(fn.iatAddr)!,
                              });
                            }}
                          >
                            ({xrefCount} xref{xrefCount !== 1 ? "s" : ""})
                          </button>
                        )}
                        {importXrefs && xrefCount === 0 && (
                          <span className="text-gray-700 text-[10px]">(0 xrefs)</span>
                        )}
                      </li>
                    );
                  })}
                </ul>
              )}
            </div>
          );
        })}
      </div>

      {/* Xref popup */}
      {xrefPopup && (
        <div
          ref={popupRef}
          className="fixed z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs min-w-[220px] max-h-60 overflow-auto"
          style={{ left: xrefPopup.x, top: xrefPopup.y }}
        >
          <div className="px-3 py-1 text-gray-400 border-b border-gray-700">
            Xrefs to {xrefPopup.funcName}
          </div>
          {xrefPopup.sources.map((src, i) => (
            <button
              type="button"
              key={i}
              className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-blue-400 font-mono"
              onClick={() => {
                dispatch({ type: "SET_ADDRESS", address: src });
                dispatch({ type: "SET_TAB", tab: "disassembly" });
                setXrefPopup(null);
              }}
            >
              0x{src.toString(16).toUpperCase()}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
