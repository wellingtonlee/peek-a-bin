import { useMemo, useRef } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";

const BYTES_PER_ROW = 16;

export function HexView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);

  const sectionInfo = useMemo(() => {
    if (!pe) return null;
    const rva = state.currentAddress - pe.optionalHeader.imageBase;
    for (const sec of pe.sections) {
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
        return sec;
      }
    }
    // Default to first section
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

  const addrWidth = pe?.is64 ? 16 : 8;

  if (!pe || !sectionBytes) {
    return (
      <div className="p-4 text-gray-400 text-sm">No section data to display.</div>
    );
  }

  return (
    <div className="flex flex-col h-full text-xs">
      {/* Section selector */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-gray-700 bg-gray-900">
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

            const hexParts: string[] = [];
            const asciiParts: string[] = [];

            for (let i = 0; i < BYTES_PER_ROW; i++) {
              if (i < rowBytes.length) {
                const b = rowBytes[i];
                hexParts.push(b.toString(16).padStart(2, "0"));
                asciiParts.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".");
              } else {
                hexParts.push("  ");
                asciiParts.push(" ");
              }
            }

            return (
              <div
                key={vItem.index}
                className="flex px-4 disasm-row"
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
                <span className="disasm-address" style={{ width: `${addrWidth + 2}ch` }}>
                  {addr.toString(16).toUpperCase().padStart(addrWidth, "0")}
                </span>
                <span className="hex-byte ml-2 flex-1">
                  {hexParts.join(" ")}
                </span>
                <span className="hex-ascii ml-4" style={{ width: `${BYTES_PER_ROW}ch` }}>
                  {asciiParts.join("")}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
