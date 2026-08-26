import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useMemo, useRef, useState } from "react";
import { useAppDispatch, useAppState } from "../hooks/usePEFile";

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

  // Every hook must run before the `!pe` early return below, otherwise the hook
  // count changes between renders and React throws on the transition.
  const imageBase = pe?.optionalHeader.imageBase ?? 0;

  const filtered = useMemo(() => {
    if (!pe) return [];
    let exps = pe.exports.filter(
      (exp) =>
        exp.name.toLowerCase().includes(filter.toLowerCase()) ||
        (exp.forwarder?.toLowerCase().includes(filter.toLowerCase()) ?? false) ||
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
  }, [pe, filter, sortKey, sortDir, imageBase]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 20,
  });

  if (!pe) return null;

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

  return (
    <div className="p-4 text-xs h-full flex flex-col">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">Exports ({pe.exports.length})</h2>
        {/* THE ADMISSION, ON THE COUNT — the same shape `ImportsView` carries
            for `importsTruncated`. A list cannot hold a truncation marker the
            way a string can, so the count is where it goes, because the count
            is the sentence a reader actually reads: without this the heading
            above describes a smaller file entirely plausibly, which is the
            narrower answer wearing a complete one's shape. See `parseExports`. */}
        {pe.exportsTruncated && (
          <span
            className="text-yellow-400 text-[11px]"
            title="The export table could not be read whole: a walk stopped at its bound rather than at its declared count, or a name ran past its limit."
          >
            Incomplete &mdash; the table was cut short
          </span>
        )}
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
            <button
              type="button"
              className="w-16 shrink-0 text-left cursor-pointer hover:text-gray-200"
              onClick={() => toggleSort("ordinal")}
            >
              Ordinal{sortIndicator("ordinal")}
            </button>
            <button
              type="button"
              className="flex-1 text-left cursor-pointer hover:text-gray-200"
              onClick={() => toggleSort("name")}
            >
              Name{sortIndicator("name")}
            </button>
            <button
              type="button"
              className="w-32 shrink-0 text-left cursor-pointer hover:text-gray-200"
              onClick={() => toggleSort("address")}
            >
              VA{sortIndicator("address")}
            </button>
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
                    <div
                      className={`flex-1 truncate ${exp.byOrdinal ? "text-gray-400 italic" : "text-gray-200"}`}
                    >
                      {exp.name}
                      {exp.forwarder && <span className="text-purple-400"> → {exp.forwarder}</span>}
                    </div>
                    <div className="w-32 shrink-0">
                      {exp.forwarder ? (
                        // A forwarder's address is an RVA into the export
                        // directory's string blob, not code — nothing to jump to.
                        <span className="text-gray-500">forwarded</span>
                      ) : (
                        <button
                          type="button"
                          onClick={() => handleNavigate(exp.address)}
                          className="text-blue-400 hover:text-blue-300 hover:underline cursor-pointer"
                        >
                          0x{(imageBase + exp.address).toString(16).toUpperCase()}
                        </button>
                      )}
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
