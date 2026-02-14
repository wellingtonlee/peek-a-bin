import { useState, useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";

type SortKey = "address" | "length";
type EncodingFilter = "all" | "ascii" | "utf16le";

interface StringEntry {
  address: number;
  value: string;
  encoding: "ascii" | "utf16le";
}

export function StringsView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const [filter, setFilter] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("address");
  const [encodingFilter, setEncodingFilter] = useState<EncodingFilter>("all");

  const allStrings = useMemo((): StringEntry[] => {
    if (!pe) return [];
    const entries: StringEntry[] = [];
    pe.strings.forEach((value, address) => {
      const encoding = pe.stringTypes?.get(address) ?? "ascii";
      entries.push({ address, value, encoding });
    });
    entries.sort((a, b) => a.address - b.address);
    return entries;
  }, [pe]);

  const filtered = useMemo(() => {
    let result = allStrings;
    if (encodingFilter !== "all") {
      result = result.filter((s) => s.encoding === encodingFilter);
    }
    if (filter) {
      const q = filter.toLowerCase();
      result = result.filter(
        (s) =>
          s.value.toLowerCase().includes(q) ||
          s.address.toString(16).toLowerCase().includes(q),
      );
    }
    if (sortKey === "length") {
      result = [...result].sort((a, b) => b.value.length - a.value.length);
    }
    return result;
  }, [allStrings, filter, sortKey, encodingFilter]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 24,
    overscan: 30,
  });

  if (!pe) return null;

  const addrWidth = pe.is64 ? 16 : 8;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-3 px-4 py-1.5 bg-gray-800/50 border-b border-gray-700 text-xs text-gray-400 shrink-0">
        <span className="font-semibold text-gray-300">Strings</span>
        <span>{filtered.length.toLocaleString()}{filter ? ` / ${allStrings.length.toLocaleString()}` : ""} strings</span>
        <div className="flex-1" />
        {(["all", "ascii", "utf16le"] as EncodingFilter[]).map((enc) => (
          <button
            key={enc}
            onClick={() => setEncodingFilter(enc)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${
              encodingFilter === enc
                ? "bg-blue-600 text-white"
                : "text-gray-500 hover:text-gray-300"
            }`}
          >
            {enc === "all" ? "All" : enc === "ascii" ? "ASCII" : "UTF-16"}
          </button>
        ))}
        <button
          onClick={() => setSortKey(sortKey === "address" ? "length" : "address")}
          className="text-gray-500 hover:text-gray-300 px-1"
          title={sortKey === "address" ? "Sort: by address" : "Sort: by length"}
        >
          {sortKey === "address" ? "Addr" : "Len"}
        </button>
        <input
          type="text"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          placeholder="Filter strings..."
          className="w-56 px-2 py-0.5 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      <div ref={parentRef} className="flex-1 overflow-auto text-xs">
        {/* Table header */}
        <div className="sticky top-0 z-10 flex items-center px-4 py-1 bg-gray-900 border-b border-gray-700 text-gray-500 font-semibold">
          <span className="w-36 shrink-0">VA</span>
          <span className="w-16 shrink-0 text-right pr-4">Length</span>
          <span className="w-8 shrink-0">Enc</span>
          <span className="flex-1">String</span>
        </div>

        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((vItem) => {
            const entry = filtered[vItem.index];
            if (!entry) return null;
            return (
              <div
                key={vItem.index}
                className="flex items-center px-4 hover:bg-blue-900/20"
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: "24px",
                  transform: `translateY(${vItem.start}px)`,
                }}
              >
                <span
                  className="w-36 shrink-0 text-blue-400 cursor-pointer hover:text-blue-300 hover:underline font-mono"
                  onClick={() => {
                    dispatch({ type: "SET_ADDRESS", address: entry.address });
                    dispatch({ type: "SET_TAB", tab: "disassembly" });
                  }}
                >
                  {entry.address.toString(16).toUpperCase().padStart(addrWidth, "0")}
                </span>
                <span className="w-16 shrink-0 text-right pr-4 text-gray-500">
                  {entry.value.length}
                </span>
                <span className="w-8 shrink-0 text-gray-600 text-[10px]">
                  {entry.encoding === "utf16le" ? "U16" : "ASC"}
                </span>
                <span className="flex-1 text-green-400 truncate font-mono" title={entry.value}>
                  {entry.value}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
