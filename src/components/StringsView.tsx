import { useState, useMemo, useRef, useEffect, useCallback } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import { disasmWorker } from "../workers/disasmClient";

type SortKey = "address" | "length";
type EncodingFilter = "all" | "ascii" | "utf16le";

interface StringEntry {
  address: number;
  value: string;
  encoding: "ascii" | "utf16le";
}

interface XrefPopupState {
  x: number;
  y: number;
  address: number;
  sources: number[];
}

export function StringsView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const filterTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleFilterChange = useCallback((value: string) => {
    setFilterInput(value);
    clearTimeout(filterTimerRef.current);
    filterTimerRef.current = setTimeout(() => setFilter(value), 250);
  }, []);
  const [sortKey, setSortKey] = useState<SortKey>("address");
  const [encodingFilter, setEncodingFilter] = useState<EncodingFilter>("all");
  const [stringXrefs, setStringXrefs] = useState<Map<number, number[]> | null>(null);
  const [xrefLoading, setXrefLoading] = useState(false);
  const [xrefPopup, setXrefPopup] = useState<XrefPopupState | null>(null);

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

  // Dismiss xref popup on click outside or Escape
  useEffect(() => {
    if (!xrefPopup) return;
    const dismiss = () => setXrefPopup(null);
    const keyDismiss = (e: KeyboardEvent) => { if (e.key === "Escape") dismiss(); };
    window.addEventListener("click", dismiss);
    window.addEventListener("keydown", keyDismiss);
    return () => {
      window.removeEventListener("click", dismiss);
      window.removeEventListener("keydown", keyDismiss);
    };
  }, [xrefPopup]);

  const handleLoadXrefs = useCallback(() => {
    if (!pe || xrefLoading) return;
    setXrefLoading(true);

    (async () => {
      try {
        const stringAddrs = new Set(pe.strings.keys());
        const allInsns: import("../disasm/types").Instruction[] = [];
        for (const sec of pe.sections) {
          if ((sec.characteristics & 0x20000000) === 0 && sec.name !== ".text") continue;
          try {
            const bytes = new Uint8Array(pe.buffer, sec.pointerToRawData, sec.sizeOfRawData);
            const base = pe.optionalHeader.imageBase + sec.virtualAddress;
            const insns = await disasmWorker.disassemble(bytes, base, pe.is64);
            allInsns.push(...insns);
          } catch { /* skip */ }
        }
        // Build data xref map inline
        const xrefs = new Map<number, number[]>();
        for (const insn of allInsns) {
          const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
          if (ripMatch) {
            const sign = ripMatch[1] === '+' ? 1 : -1;
            const disp = parseInt(ripMatch[2], 16);
            const target = insn.address + insn.size + sign * disp;
            if (stringAddrs.has(target)) {
              let arr = xrefs.get(target);
              if (!arr) { arr = []; xrefs.set(target, arr); }
              arr.push(insn.address);
            }
          }
          const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
          if (addrMatches) {
            for (const addrStr of addrMatches) {
              const addr = parseInt(addrStr, 16);
              if (stringAddrs.has(addr)) {
                let arr = xrefs.get(addr);
                if (!arr) { arr = []; xrefs.set(addr, arr); }
                arr.push(insn.address);
              }
            }
          }
        }
        setStringXrefs(xrefs);
      } catch { /* ignore */ }
      setXrefLoading(false);
    })();
  }, [pe, xrefLoading]);

  if (!pe) return null;

  const addrWidth = pe.is64 ? 16 : 8;

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-3 px-4 py-1.5 bg-gray-800/50 border-b border-gray-700 text-xs text-gray-400 shrink-0">
        <span className="font-semibold text-gray-300">Strings</span>
        <span>{filtered.length.toLocaleString()}{filterInput ? ` / ${allStrings.length.toLocaleString()}` : ""} strings</span>
        <div className="flex-1" />
        {!stringXrefs && (
          <button
            onClick={handleLoadXrefs}
            disabled={xrefLoading}
            className="px-2 py-0.5 rounded text-[10px] bg-gray-700 text-gray-300 hover:bg-gray-600 disabled:opacity-50"
          >
            {xrefLoading ? (
              <span className="flex items-center gap-1">
                <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
                </svg>
                Loading...
              </span>
            ) : "Load xrefs"}
          </button>
        )}
        {stringXrefs && (
          <span className="text-[10px] text-green-400">Xrefs loaded</span>
        )}
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
          value={filterInput}
          onChange={(e) => handleFilterChange(e.target.value)}
          placeholder="Filter strings..."
          className="w-56 px-2 py-0.5 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>

      <div ref={parentRef} className="flex-1 overflow-auto text-xs relative">
        {/* Table header */}
        <div className="sticky top-0 z-10 flex items-center px-4 py-1 bg-gray-900 border-b border-gray-700 text-gray-500 font-semibold">
          <span className="w-36 shrink-0">VA</span>
          <span className="w-16 shrink-0 text-right pr-4">Length</span>
          <span className="w-12 shrink-0 text-right pr-4">Xrefs</span>
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
            const xrefCount = stringXrefs?.get(entry.address)?.length ?? 0;
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
                <span className="w-12 shrink-0 text-right pr-4">
                  {stringXrefs ? (
                    xrefCount > 0 ? (
                      <span
                        className="text-gray-400 cursor-pointer hover:text-blue-400"
                        onClick={(e) => {
                          e.stopPropagation();
                          const rect = (e.target as HTMLElement).getBoundingClientRect();
                          const container = parentRef.current;
                          if (!container) return;
                          const cRect = container.getBoundingClientRect();
                          setXrefPopup({
                            x: rect.left - cRect.left + container.scrollLeft,
                            y: rect.bottom - cRect.top + container.scrollTop,
                            address: entry.address,
                            sources: stringXrefs.get(entry.address)!,
                          });
                        }}
                      >
                        {xrefCount}
                      </span>
                    ) : (
                      <span className="text-gray-600">&mdash;</span>
                    )
                  ) : (
                    <span className="text-gray-700">&mdash;</span>
                  )}
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

        {/* Xref popup */}
        {xrefPopup && (
          <div
            className="absolute z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs min-w-[220px] max-h-60 overflow-auto"
            style={{ left: xrefPopup.x, top: xrefPopup.y }}
            onClick={(e) => e.stopPropagation()}
          >
            <div className="px-3 py-1 text-gray-400 border-b border-gray-700">
              Xrefs to 0x{xrefPopup.address.toString(16).toUpperCase()}
            </div>
            {xrefPopup.sources.map((src, i) => (
              <button
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
    </div>
  );
}
