import { useMemo, useRef, useState, useCallback, useEffect } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import { DataInspector } from "./DataInspector";

const BYTES_PER_ROW = 16;

function parseBytePattern(input: string): (number | null)[] | null {
  const parts = input.trim().split(/\s+/);
  if (parts.length === 0 || (parts.length === 1 && parts[0] === "")) return null;
  const bytes: (number | null)[] = [];
  for (const p of parts) {
    if (p === "??" || p === "?") { bytes.push(null); continue; }
    const v = parseInt(p, 16);
    if (isNaN(v) || v < 0 || v > 255) return null;
    bytes.push(v);
  }
  return bytes.length > 0 ? bytes : null;
}

function findBytePatternMatches(
  data: Uint8Array,
  pattern: (number | null)[],
): number[] {
  const matches: number[] = [];
  if (pattern.length === 0) return matches;
  const end = data.length - pattern.length;
  outer: for (let i = 0; i <= end; i++) {
    for (let j = 0; j < pattern.length; j++) {
      if (pattern[j] !== null && data[i + j] !== pattern[j]) continue outer;
    }
    matches.push(i);
    if (matches.length >= 1000) break;
  }
  return matches;
}

export function HexView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const [goToInput, setGoToInput] = useState("");
  const [byteSearch, setByteSearch] = useState("");
  const [byteMatches, setByteMatches] = useState<Set<number>>(new Set());
  const [matchCount, setMatchCount] = useState(0);
  const [selectedOffset, setSelectedOffset] = useState<number | null>(null);

  const sectionInfo = useMemo(() => {
    if (!pe) return null;
    const rva = state.currentAddress - pe.optionalHeader.imageBase;
    for (const sec of pe.sections) {
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
        return sec;
      }
    }
    return pe.sections[0] ?? null;
  }, [pe, state.currentAddress]);

  const sectionBytes = useMemo(() => {
    if (!pe || !sectionInfo) return null;
    return new Uint8Array(
      pe.buffer,
      sectionInfo.pointerToRawData,
      sectionInfo.sizeOfRawData,
    );
  }, [pe, sectionInfo]);

  const rowCount = sectionBytes
    ? Math.ceil(sectionBytes.length / BYTES_PER_ROW)
    : 0;

  const baseAddress = pe && sectionInfo
    ? pe.optionalHeader.imageBase + sectionInfo.virtualAddress
    : 0;

  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 20,
    overscan: 30,
  });

  // Compute row index for current address
  const currentRowIdx = useMemo(() => {
    if (!sectionBytes || !pe || !sectionInfo) return -1;
    const offset = state.currentAddress - baseAddress;
    if (offset < 0 || offset >= sectionBytes.length) return -1;
    return Math.floor(offset / BYTES_PER_ROW);
  }, [state.currentAddress, baseAddress, sectionBytes, pe, sectionInfo]);

  // Scroll to current address row
  useEffect(() => {
    if (currentRowIdx >= 0) {
      virtualizer.scrollToIndex(currentRowIdx, { align: "center" });
    }
  }, [currentRowIdx]);

  // Byte pattern search
  useEffect(() => {
    if (!sectionBytes || !byteSearch.trim()) {
      setByteMatches(new Set());
      setMatchCount(0);
      return;
    }
    const pattern = parseBytePattern(byteSearch);
    if (!pattern) {
      setByteMatches(new Set());
      setMatchCount(0);
      return;
    }
    const offsets = findBytePatternMatches(sectionBytes, pattern);
    const s = new Set<number>();
    for (const off of offsets) {
      for (let j = 0; j < pattern.length; j++) s.add(off + j);
    }
    setByteMatches(s);
    setMatchCount(offsets.length);
  }, [sectionBytes, byteSearch]);

  const handleGoTo = useCallback(() => {
    if (!pe || !sectionInfo) return;
    const cleaned = goToInput.replace(/^0[xX]/, "");
    const val = parseInt(cleaned, 16);
    if (isNaN(val)) return;
    // Treat as VA if large enough, else as section offset
    const addr = val >= baseAddress ? val : baseAddress + val;
    dispatch({ type: "SET_ADDRESS", address: addr });
    setGoToInput("");
  }, [goToInput, pe, sectionInfo, baseAddress, dispatch]);

  const handleAddressClick = useCallback(
    (addr: number) => {
      dispatch({ type: "SET_ADDRESS", address: addr });
    },
    [dispatch],
  );

  const addrWidth = pe?.is64 ? 16 : 8;

  if (!pe || !sectionBytes) {
    return (
      <div className="p-4 text-gray-400 text-sm">No section data to display.</div>
    );
  }

  return (
    <div className="flex flex-col h-full text-xs">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-700 bg-gray-900 flex-wrap">
        <span className="text-gray-400">Section:</span>
        <select
          value={sectionInfo?.name ?? ""}
          onChange={(e) => {
            const sec = pe.sections.find((s) => s.name === e.target.value);
            if (sec) {
              dispatch({
                type: "SET_ADDRESS",
                address: pe.optionalHeader.imageBase + sec.virtualAddress,
              });
            }
          }}
          className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200"
        >
          {pe.sections.map((sec, i) => (
            <option key={i} value={sec.name}>
              {sec.name} (0x{sec.sizeOfRawData.toString(16)})
            </option>
          ))}
        </select>

        <div className="w-px h-4 bg-gray-700 mx-1" />

        <input
          type="text"
          value={goToInput}
          onChange={(e) => setGoToInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleGoTo();
            if (e.key === "Escape") (e.target as HTMLElement).blur();
          }}
          placeholder="Go to offset..."
          className="w-32 px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />

        <div className="w-px h-4 bg-gray-700 mx-1" />

        <input
          type="text"
          value={byteSearch}
          onChange={(e) => setByteSearch(e.target.value)}
          placeholder="Byte search (e.g. 4D 5A ?? 00)..."
          className="w-44 px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        {byteSearch && matchCount > 0 && (
          <span className="text-gray-500 text-[10px]">
            {matchCount} match{matchCount !== 1 ? "es" : ""}
          </span>
        )}
        {byteSearch && matchCount === 0 && parseBytePattern(byteSearch) && (
          <span className="text-red-400 text-[10px]">No matches</span>
        )}
      </div>

      {/* Header */}
      <div className="flex px-4 py-1 border-b border-gray-800 text-gray-500 bg-gray-900/50">
        <span style={{ width: `${addrWidth + 2}ch` }}>Offset</span>
        <span className="flex-1 ml-2">
          {Array.from({ length: BYTES_PER_ROW }, (_, i) =>
            i.toString(16).toUpperCase().padStart(2, "0"),
          ).join(" ")}
        </span>
        <span className="ml-4" style={{ width: `${BYTES_PER_ROW}ch` }}>
          ASCII
        </span>
      </div>

      {/* Hex rows */}
      <div ref={parentRef} className="flex-1 overflow-auto">
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((vItem) => {
            const offset = vItem.index * BYTES_PER_ROW;
            const rowBytes = sectionBytes.slice(offset, offset + BYTES_PER_ROW);
            const addr = baseAddress + offset;
            const isCurrentRow = vItem.index === currentRowIdx;

            const hexParts: string[] = [];
            const asciiParts: string[] = [];
            const highlightByte: boolean[] = [];

            for (let i = 0; i < BYTES_PER_ROW; i++) {
              if (i < rowBytes.length) {
                const b = rowBytes[i];
                hexParts.push(b.toString(16).padStart(2, "0"));
                asciiParts.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".");
                highlightByte.push(byteMatches.has(offset + i));
              } else {
                hexParts.push("  ");
                asciiParts.push(" ");
                highlightByte.push(false);
              }
            }

            const hasHighlight = highlightByte.some(Boolean);

            return (
              <div
                key={vItem.index}
                className={`flex px-4 disasm-row ${
                  isCurrentRow ? "bg-blue-900/30" : ""
                }`}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: "20px",
                  lineHeight: "20px",
                  transform: `translateY(${vItem.start}px)`,
                }}
              >
                <span
                  className="disasm-address cursor-pointer hover:text-blue-400"
                  style={{ width: `${addrWidth + 2}ch` }}
                  onClick={() => handleAddressClick(addr)}
                >
                  {addr.toString(16).toUpperCase().padStart(addrWidth, "0")}
                </span>
                <span className="hex-byte ml-2 flex-1">
                  {hexParts.map((h, i) => {
                    const byteOffset = offset + i;
                    const isSelected = selectedOffset === byteOffset;
                    const isHighlighted = highlightByte[i];
                    let cls = "";
                    if (isSelected) cls = "ring-1 ring-blue-500 rounded-sm bg-blue-900/40";
                    else if (isHighlighted) cls = "bg-yellow-600/50 text-yellow-200";
                    return (
                      <span key={i}>
                        {i > 0 ? " " : ""}
                        <span
                          className={`cursor-pointer ${cls}`}
                          onClick={() => i < rowBytes.length && setSelectedOffset(byteOffset)}
                        >
                          {h}
                        </span>
                      </span>
                    );
                  })}
                </span>
                <span className="hex-ascii ml-4" style={{ width: `${BYTES_PER_ROW}ch` }}>
                  {asciiParts.map((c, i) => {
                    const byteOffset = offset + i;
                    const isSelected = selectedOffset === byteOffset;
                    const isHighlighted = highlightByte[i];
                    let cls = "";
                    if (isSelected) cls = "ring-1 ring-blue-500 rounded-sm bg-blue-900/40";
                    else if (isHighlighted) cls = "bg-yellow-600/50 text-yellow-200";
                    return (
                      <span key={i} className={cls}>
                        {c}
                      </span>
                    );
                  })}
                </span>
              </div>
            );
          })}
        </div>
      </div>

      {/* Data Inspector */}
      {selectedOffset !== null && sectionBytes && (
        <DataInspector
          offset={selectedOffset}
          bytes={sectionBytes}
          baseAddress={baseAddress}
        />
      )}
    </div>
  );
}
