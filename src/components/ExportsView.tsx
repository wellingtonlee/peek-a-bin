import { useState, useMemo, useCallback, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";

type SortKey = "ordinal" | "name" | "address";
type SortDir = "asc" | "desc";

export function ExportsView() {
  const { peFile: pe } = useAppState();
  const dispatch = useAppDispatch();
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const filterTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleFilterChange = useCallback((value: string) => {
    setFilterInput(value);
    clearTimeout(filterTimerRef.current);
    filterTimerRef.current = setTimeout(() => setFilter(value), 250);
  }, []);
  const [sortKey, setSortKey] = useState<SortKey>("ordinal");
  const [sortDir, setSortDir] = useState<SortDir>("asc");
  const parentRef = useRef<HTMLDivElement>(null);

  if (!pe) return null;

  const imageBase = pe.optionalHeader.imageBase;

  const filtered = useMemo(() => {
    let exps = pe.exports.filter(
      (exp) =>
        exp.name.toLowerCase().includes(filter.toLowerCase()) ||
        exp.ordinal.toString().includes(filter) ||
        (imageBase + exp.address).toString(16).toLowerCase().includes(filter.toLowerCase()),
    );
    exps = [...exps].sort((a, b) => {
      let cmp = 0;
      if (sortKey === "ordinal") cmp = a.ordinal - b.ordinal;
      else if (sortKey === "name") cmp = a.name.localeCompare(b.name);
      else cmp = a.address - b.address;
      return sortDir === "asc" ? cmp : -cmp;
    });
    return exps;
  }, [pe.exports, filter, sortKey, sortDir, imageBase]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortDir(sortDir === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortDir("asc");
    }
  };

  const sortIndicator = (key: SortKey) =>
    sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "";

  const handleNavigate = (rva: number) => {
    dispatch({ type: "SET_ADDRESS", address: imageBase + rva });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
  };

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 20,
  });

  return (
    <div className="p-4 text-xs h-full flex flex-col">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Exports ({pe.exports.length})
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
            {filtered.length} match{filtered.length !== 1 ? "es" : ""}
          </span>
        )}
      </div>

      {filtered.length === 0 ? (
        <p className="text-gray-500">
          {pe.exports.length === 0
            ? "No exports found in this binary."
            : "No exports match the filter."}
        </p>
      ) : (
        <>
          {/* Sticky header */}
          <div className="flex text-gray-400 border-b border-gray-700 pb-1 mb-1 select-none shrink-0">
            <div
              className="w-16 shrink-0 cursor-pointer hover:text-gray-200"
              onClick={() => toggleSort("ordinal")}
            >
              Ordinal{sortIndicator("ordinal")}
            </div>
            <div
              className="flex-1 cursor-pointer hover:text-gray-200"
              onClick={() => toggleSort("name")}
            >
              Name{sortIndicator("name")}
            </div>
            <div
              className="w-32 shrink-0 cursor-pointer hover:text-gray-200"
              onClick={() => toggleSort("address")}
            >
              VA{sortIndicator("address")}
            </div>
          </div>

          {/* Virtualized rows */}
          <div ref={parentRef} className="flex-1 overflow-auto">
            <div
              style={{
                height: `${virtualizer.getTotalSize()}px`,
                width: "100%",
                position: "relative",
              }}
            >
              {virtualizer.getVirtualItems().map((vItem) => {
                const exp = filtered[vItem.index];
                if (!exp) return null;
                return (
                  <div
                    key={vItem.index}
                    className="absolute left-0 w-full flex items-center hover:bg-gray-800/50"
                    style={{
                      top: 0,
                      height: "28px",
                      transform: `translateY(${vItem.start}px)`,
                    }}
                  >
                    <div className="w-16 shrink-0 text-gray-400">{exp.ordinal}</div>
                    <div className="flex-1 text-gray-200 truncate">{exp.name}</div>
                    <div className="w-32 shrink-0">
                      <button
                        onClick={() => handleNavigate(exp.address)}
                        className="text-blue-400 hover:text-blue-300 hover:underline cursor-pointer"
                      >
                        0x{(imageBase + exp.address).toString(16).toUpperCase()}
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
