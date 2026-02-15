import { useMemo, useRef, useState, useCallback, useEffect } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import { DataInspector } from "./DataInspector";
import { computeEntropyBlocks } from "../utils/entropy";

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

function entropyColor(entropy: number): string {
  // blue(0) -> yellow(4) -> red(8)
  if (entropy <= 4) {
    const t = entropy / 4;
    const r = Math.round(t * 255);
    const g = Math.round(t * 255);
    const b = Math.round((1 - t) * 255);
    return `rgb(${r},${g},${b})`;
  } else {
    const t = (entropy - 4) / 4;
    const r = 255;
    const g = Math.round((1 - t) * 255);
    const b = 0;
    return `rgb(${r},${g},${b})`;
  }
}

export function HexView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [goToInput, setGoToInput] = useState("");
  const [byteSearch, setByteSearch] = useState("");
  const [byteMatches, setByteMatches] = useState<Set<number>>(new Set());
  const [matchCount, setMatchCount] = useState(0);
  const [selectedOffset, setSelectedOffset] = useState<number | null>(null);
  const [editingByte, setEditingByte] = useState<number | null>(null);
  const [editValue, setEditValue] = useState("");
  const [showEntropy, setShowEntropy] = useState(false);
  const [showDiff, setShowDiff] = useState(false);
  const [entropyTooltip, setEntropyTooltip] = useState<{ x: number; blockIdx: number; offset: number; endOffset: number; value: number } | null>(null);

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

  const entropyBlocks = useMemo(() => {
    if (!sectionBytes) return [];
    return computeEntropyBlocks(sectionBytes);
  }, [sectionBytes]);

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

  // Draw entropy canvas
  useEffect(() => {
    if (!showEntropy || !canvasRef.current || entropyBlocks.length === 0) return;
    const canvas = canvasRef.current;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const w = canvas.clientWidth;
    canvas.width = w;
    canvas.height = 12;
    ctx.clearRect(0, 0, w, 12);
    const blockWidth = Math.max(2, w / entropyBlocks.length);
    for (let i = 0; i < entropyBlocks.length; i++) {
      ctx.fillStyle = entropyColor(entropyBlocks[i]);
      ctx.fillRect(i * blockWidth, 0, Math.ceil(blockWidth), 12);
    }
  }, [showEntropy, entropyBlocks]);

  const handleGoTo = useCallback(() => {
    if (!pe || !sectionInfo) return;
    const cleaned = goToInput.replace(/^0[xX]/, "");
    const val = parseInt(cleaned, 16);
    if (isNaN(val)) return;
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

  const handleEntropyClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!canvasRef.current || entropyBlocks.length === 0 || !sectionBytes) return;
    const rect = canvasRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const blockWidth = rect.width / entropyBlocks.length;
    const blockIdx = Math.floor(x / blockWidth);
    if (blockIdx >= 0 && blockIdx < entropyBlocks.length) {
      const offset = blockIdx * 256;
      const rowIdx = Math.floor(offset / BYTES_PER_ROW);
      virtualizer.scrollToIndex(rowIdx, { align: "center" });
      dispatch({ type: "SET_ADDRESS", address: baseAddress + offset });
    }
  }, [entropyBlocks, sectionBytes, baseAddress, dispatch, virtualizer]);

  const handleEntropyMouse = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (!canvasRef.current || entropyBlocks.length === 0 || !sectionBytes) {
      setEntropyTooltip(null);
      return;
    }
    const rect = canvasRef.current.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const blockWidth = rect.width / entropyBlocks.length;
    const blockIdx = Math.floor(x / blockWidth);
    if (blockIdx >= 0 && blockIdx < entropyBlocks.length) {
      const offset = blockIdx * 256;
      const endOffset = Math.min(offset + 256, sectionBytes.length);
      setEntropyTooltip({ x: e.clientX - rect.left, blockIdx, offset, endOffset, value: entropyBlocks[blockIdx] });
    } else {
      setEntropyTooltip(null);
    }
  }, [entropyBlocks, sectionBytes]);

  const handleDownload = useCallback(() => {
    if (!pe || state.hexPatches.size === 0) return;
    const patched = pe.buffer.slice(0);
    const view = new Uint8Array(patched);
    state.hexPatches.forEach((value, offset) => {
      if (offset < view.length) view[offset] = value;
    });
    const blob = new Blob([patched], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = (state.fileName ?? "binary") + ".patched.exe";
    a.click();
    URL.revokeObjectURL(url);
  }, [pe, state.hexPatches, state.fileName]);

  const getByteValue = useCallback((localOffset: number): number => {
    if (!sectionInfo || !sectionBytes) return 0;
    const fileOffset = sectionInfo.pointerToRawData + localOffset;
    if (state.hexPatches.has(fileOffset)) return state.hexPatches.get(fileOffset)!;
    return sectionBytes[localOffset];
  }, [sectionInfo, sectionBytes, state.hexPatches]);

  const isPatched = useCallback((localOffset: number): boolean => {
    if (!sectionInfo) return false;
    return state.hexPatches.has(sectionInfo.pointerToRawData + localOffset);
  }, [sectionInfo, state.hexPatches]);

  const getOriginalByte = useCallback((localOffset: number): number => {
    if (!sectionBytes) return 0;
    return sectionBytes[localOffset];
  }, [sectionBytes]);

  // Build sorted patches list for diff table
  const patchesList = useMemo(() => {
    if (!sectionInfo || !sectionBytes || !pe) return [];
    const list: { fileOffset: number; localOffset: number; original: number; patched: number; address: number; sectionName: string }[] = [];
    state.hexPatches.forEach((patched, fileOffset) => {
      const localOffset = fileOffset - sectionInfo.pointerToRawData;
      if (localOffset >= 0 && localOffset < sectionBytes.length) {
        list.push({
          fileOffset,
          localOffset,
          original: sectionBytes[localOffset],
          patched,
          address: baseAddress + localOffset,
          sectionName: sectionInfo.name,
        });
      }
    });
    list.sort((a, b) => a.fileOffset - b.fileOffset);
    return list;
  }, [state.hexPatches, sectionInfo, sectionBytes, baseAddress, pe]);

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

        <div className="w-px h-4 bg-gray-700 mx-1" />

        <button
          onClick={() => setShowEntropy((v) => !v)}
          className={`px-2 py-1 rounded text-[10px] ${showEntropy ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
        >
          Entropy
        </button>

        {state.hexPatches.size > 0 && (
          <>
            <div className="w-px h-4 bg-gray-700 mx-1" />
            <span className="text-orange-400 text-[10px]">Patches: {state.hexPatches.size}</span>
            <button
              onClick={() => setShowDiff((v) => !v)}
              className={`px-2 py-1 rounded text-[10px] ${showDiff ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
            >
              Diff
            </button>
            <button
              onClick={() => dispatch({ type: "CLEAR_PATCHES" })}
              className="px-2 py-1 rounded text-[10px] bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              Clear
            </button>
            <button
              onClick={handleDownload}
              className="px-2 py-1 rounded text-[10px] bg-green-700 text-white hover:bg-green-600"
            >
              Download
            </button>
          </>
        )}
      </div>

      {/* Entropy bar */}
      {showEntropy && entropyBlocks.length > 0 && (
        <div className="relative px-4 py-0.5 bg-gray-900/50 border-b border-gray-800">
          <canvas
            ref={canvasRef}
            className="w-full cursor-pointer"
            style={{ height: "12px" }}
            onClick={handleEntropyClick}
            onMouseMove={handleEntropyMouse}
            onMouseLeave={() => setEntropyTooltip(null)}
          />
          {entropyTooltip && (
            <div
              className="absolute z-30 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-[10px] text-gray-300 pointer-events-none"
              style={{ left: Math.min(entropyTooltip.x, 300), top: 18 }}
            >
              Block {entropyTooltip.blockIdx} | 0x{entropyTooltip.offset.toString(16)}-0x{entropyTooltip.endOffset.toString(16)} | Entropy: {entropyTooltip.value.toFixed(2)}
            </div>
          )}
        </div>
      )}

      {/* Patches diff table */}
      {showDiff && patchesList.length > 0 && (
        <div className="px-4 py-2 bg-gray-900/80 border-b border-gray-700 max-h-32 overflow-auto">
          <div className="text-gray-400 text-[10px] font-semibold mb-1">Patches ({patchesList.length})</div>
          <table className="w-full text-[10px] font-mono">
            <thead>
              <tr className="text-gray-500">
                <th className="text-left pr-3">File Offset</th>
                <th className="text-left pr-3">Original</th>
                <th className="text-left pr-3">Patched</th>
                <th className="text-left">Section+Offset</th>
              </tr>
            </thead>
            <tbody>
              {patchesList.map((p) => (
                <tr
                  key={p.fileOffset}
                  className="hover:bg-gray-800 cursor-pointer"
                  onClick={() => {
                    dispatch({ type: "SET_ADDRESS", address: p.address });
                  }}
                >
                  <td className="pr-3 text-blue-400">0x{p.fileOffset.toString(16).toUpperCase()}</td>
                  <td className="pr-3 text-gray-400 line-through">0x{p.original.toString(16).toUpperCase().padStart(2, "0")}</td>
                  <td className="pr-3 text-red-400 font-bold">0x{p.patched.toString(16).toUpperCase().padStart(2, "0")}</td>
                  <td className="text-gray-500">{p.sectionName}+0x{p.localOffset.toString(16).toUpperCase()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

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
            const addr = baseAddress + offset;
            const isCurrentRow = vItem.index === currentRowIdx;
            const rowLen = Math.min(BYTES_PER_ROW, sectionBytes.length - offset);

            const hexParts: string[] = [];
            const asciiParts: string[] = [];
            const highlightByte: boolean[] = [];
            const patchedByte: boolean[] = [];

            for (let i = 0; i < BYTES_PER_ROW; i++) {
              if (i < rowLen) {
                const b = getByteValue(offset + i);
                hexParts.push(b.toString(16).padStart(2, "0"));
                asciiParts.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".");
                highlightByte.push(byteMatches.has(offset + i));
                patchedByte.push(isPatched(offset + i));
              } else {
                hexParts.push("  ");
                asciiParts.push(" ");
                highlightByte.push(false);
                patchedByte.push(false);
              }
            }

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
                    const fileOffset = sectionInfo ? sectionInfo.pointerToRawData + byteOffset : -1;
                    const isSelected = selectedOffset === byteOffset;
                    const isHighlighted = highlightByte[i];
                    const isPatch = patchedByte[i];
                    const isEditing = editingByte === fileOffset;

                    if (isEditing) {
                      return (
                        <span key={i}>
                          {i > 0 ? " " : ""}
                          <input
                            autoFocus
                            className="w-5 bg-gray-700 border border-blue-500 rounded-sm text-center text-red-400 font-bold outline-none text-xs"
                            value={editValue}
                            maxLength={2}
                            onChange={(e) => setEditValue(e.target.value.replace(/[^0-9a-fA-F]/g, "").slice(0, 2))}
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                const val = parseInt(editValue, 16);
                                if (!isNaN(val) && val >= 0 && val <= 255) {
                                  dispatch({ type: "PATCH_BYTE", offset: fileOffset, value: val });
                                }
                                setEditingByte(null);
                                setEditValue("");
                              }
                              if (e.key === "Escape") {
                                setEditingByte(null);
                                setEditValue("");
                              }
                              e.stopPropagation();
                            }}
                            onBlur={() => { setEditingByte(null); setEditValue(""); }}
                          />
                        </span>
                      );
                    }

                    let cls = isPatch ? "text-red-400 font-bold" : "";
                    if (isSelected) cls = "ring-1 ring-blue-500 rounded-sm bg-blue-900/40";
                    else if (isHighlighted) cls = "bg-yellow-600/50 text-yellow-200";
                    else if (isPatch) cls = "text-red-400 font-bold";

                    const origByte = getOriginalByte(offset + i);
                    const origHex = origByte.toString(16).padStart(2, "0");
                    const showOrig = showDiff && isPatch;
                    const tooltipText = showOrig ? `Original: 0x${origHex.toUpperCase()} → Patched: 0x${h.toUpperCase()}` : undefined;

                    return (
                      <span key={i} title={tooltipText}>
                        {i > 0 ? " " : ""}
                        {showOrig && (
                          <span className="text-gray-600 text-[8px] line-through">{origHex}</span>
                        )}
                        <span
                          className={`cursor-pointer ${cls}`}
                          onClick={() => i < rowLen && setSelectedOffset(byteOffset)}
                          onDoubleClick={() => {
                            if (i < rowLen && sectionInfo) {
                              const fo = sectionInfo.pointerToRawData + byteOffset;
                              setEditingByte(fo);
                              setEditValue(h);
                            }
                          }}
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
                    const isPatch = patchedByte[i];
                    let cls = "";
                    if (isSelected) cls = "ring-1 ring-blue-500 rounded-sm bg-blue-900/40";
                    else if (isHighlighted) cls = "bg-yellow-600/50 text-yellow-200";
                    else if (isPatch) cls = "text-red-400 font-bold";
                    const origChar = showDiff && isPatch ? (() => {
                      const ob = getOriginalByte(offset + i);
                      return ob >= 0x20 && ob <= 0x7e ? String.fromCharCode(ob) : ".";
                    })() : null;
                    return (
                      <span key={i} className={cls}>
                        {origChar && <span className="text-gray-600 text-[8px] line-through">{origChar}</span>}
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
