import { useState, useMemo, useRef, useCallback } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import type { Xref, DisasmFunction } from "../disasm/types";
import type { PEFile } from "../pe/types";
import { binarySearchFunc } from "../hooks/useDerivedState";

type XrefType = "call" | "jmp" | "branch" | "data";
type SortKey = "from" | "to" | "type";

interface FlatXref {
  type: XrefType;
  fromAddr: number;
  toAddr: number;
  fromFuncName: string;
  toFuncName: string;
}

interface XrefPanelProps {
  typedXrefMap: Map<number, Xref[]>;
  funcMap: Map<number, DisasmFunction>;
  sortedFuncs: DisasmFunction[];
  pe: PEFile;
  onNavigate: (addr: number) => void;
  onClose: () => void;
}

export function XrefPanel({
  typedXrefMap,
  funcMap,
  sortedFuncs,
  pe,
  onNavigate,
  onClose,
}: XrefPanelProps) {
  const parentRef = useRef<HTMLDivElement>(null);
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const filterTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleFilterChange = useCallback((value: string) => {
    setFilterInput(value);
    clearTimeout(filterTimerRef.current);
    filterTimerRef.current = setTimeout(() => setFilter(value), 250);
  }, []);

  const [typeFilter, setTypeFilter] = useState<Set<XrefType>>(new Set(["call", "jmp", "branch", "data"]));
  const [sortKey, setSortKey] = useState<SortKey>("from");
  const [sortAsc, setSortAsc] = useState(true);

  const toggleType = (t: XrefType) => {
    setTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  };

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc((v) => !v);
    else { setSortKey(key); setSortAsc(true); }
  };

  // Flatten xref map into sorted, resolved entries
  const allXrefs = useMemo((): FlatXref[] => {
    const result: FlatXref[] = [];
    for (const [toAddr, xrefs] of typedXrefMap) {
      const toFn = funcMap.get(toAddr) ?? binarySearchFunc(sortedFuncs, toAddr);
      const toName = toFn?.name ?? "";
      for (const xref of xrefs) {
        const fromFn = binarySearchFunc(sortedFuncs, xref.from);
        result.push({
          type: xref.type as XrefType,
          fromAddr: xref.from,
          toAddr,
          fromFuncName: fromFn?.name ?? "",
          toFuncName: toName,
        });
      }
    }
    return result;
  }, [typedXrefMap, funcMap, sortedFuncs]);

  const filtered = useMemo(() => {
    let items = allXrefs.filter((x) => typeFilter.has(x.type));
    if (filter) {
      const q = filter.toLowerCase();
      items = items.filter(
        (x) =>
          x.fromAddr.toString(16).includes(q) ||
          x.toAddr.toString(16).includes(q) ||
          x.fromFuncName.toLowerCase().includes(q) ||
          x.toFuncName.toLowerCase().includes(q),
      );
    }
    items.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "from") cmp = a.fromAddr - b.fromAddr;
      else if (sortKey === "to") cmp = a.toAddr - b.toAddr;
      else cmp = a.type.localeCompare(b.type);
      return sortAsc ? cmp : -cmp;
    });
    return items;
  }, [allXrefs, typeFilter, filter, sortKey, sortAsc]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 30,
  });

  const typeColors: Record<string, string> = {
    call: "text-green-400",
    jmp: "text-red-400",
    branch: "text-orange-400",
    data: "text-purple-400",
  };

  const sortIndicator = (key: SortKey) =>
    sortKey === key ? (sortAsc ? " ▲" : " ▼") : "";

  return (
    <div className="border-t border-theme panel-bg text-xs flex flex-col" style={{ height: 200 }}>
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1 border-b border-gray-700 shrink-0">
        <span className="text-gray-300 font-semibold text-[11px]">
          Cross-References ({filtered.length}/{allXrefs.length})
        </span>
        <div className="flex items-center gap-1 ml-2">
          {(["call", "jmp", "branch", "data"] as XrefType[]).map((t) => (
            <button
              key={t}
              onClick={() => toggleType(t)}
              className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                typeFilter.has(t)
                  ? t === "call" ? "bg-green-800 text-green-300"
                    : t === "jmp" ? "bg-red-800 text-red-300"
                    : t === "branch" ? "bg-orange-800 text-orange-300"
                    : "bg-purple-800 text-purple-300"
                  : "bg-gray-800 text-gray-600"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
        <input
          type="text"
          value={filterInput}
          onChange={(e) => handleFilterChange(e.target.value)}
          placeholder="Filter addresses/names..."
          className="ml-2 px-1.5 py-0.5 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 text-[10px] w-40"
        />
        <div className="flex-1" />
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-white px-1"
        >
          ✕
        </button>
      </div>

      {/* Column headers */}
      <div className="flex items-center px-3 py-0.5 border-b border-gray-800 text-gray-500 text-[10px] select-none shrink-0">
        <div
          className="w-12 shrink-0 cursor-pointer hover:text-gray-300"
          onClick={() => toggleSort("type")}
        >
          Type{sortIndicator("type")}
        </div>
        <div
          className="w-32 shrink-0 cursor-pointer hover:text-gray-300"
          onClick={() => toggleSort("from")}
        >
          From{sortIndicator("from")}
        </div>
        <div className="w-36 shrink-0">Function</div>
        <div
          className="w-32 shrink-0 cursor-pointer hover:text-gray-300"
          onClick={() => toggleSort("to")}
        >
          To{sortIndicator("to")}
        </div>
        <div className="flex-1">Target</div>
      </div>

      {/* Virtualized list */}
      <div ref={parentRef} className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <div className="p-3 text-gray-500 text-center">
            {allXrefs.length === 0 ? "No cross-references found." : "No xrefs match the current filters."}
          </div>
        ) : (
          <div
            style={{
              height: `${virtualizer.getTotalSize()}px`,
              width: "100%",
              position: "relative",
            }}
          >
            {virtualizer.getVirtualItems().map((vItem) => {
              const x = filtered[vItem.index];
              if (!x) return null;
              return (
                <div
                  key={vItem.index}
                  className="absolute left-0 w-full flex items-center px-3 hover:bg-gray-800/50 cursor-pointer"
                  style={{
                    top: 0,
                    height: "22px",
                    transform: `translateY(${vItem.start}px)`,
                  }}
                  onClick={() => onNavigate(x.fromAddr)}
                >
                  <div className={`w-12 shrink-0 font-semibold text-[10px] ${typeColors[x.type] ?? "text-gray-400"}`}>
                    {x.type}
                  </div>
                  <div className="w-32 shrink-0 font-mono text-blue-400">
                    0x{x.fromAddr.toString(16).toUpperCase()}
                  </div>
                  <div className="w-36 shrink-0 text-gray-400 truncate" title={x.fromFuncName}>
                    {x.fromFuncName || "---"}
                  </div>
                  <div className="w-32 shrink-0 font-mono text-gray-300">
                    0x{x.toAddr.toString(16).toUpperCase()}
                  </div>
                  <div className="flex-1 text-gray-400 truncate" title={x.toFuncName}>
                    {x.toFuncName || "---"}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
