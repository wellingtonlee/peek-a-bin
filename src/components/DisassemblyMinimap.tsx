import { useRef, useEffect, useCallback, useState, useMemo } from "react";
import type { DisasmFunction } from "../disasm/types";
import type { Loop } from "../disasm/cfg";

type DisplayRow =
  | { kind: "label"; fn: DisasmFunction }
  | { kind: "insn"; insn: { address: number }; blockIdx: number }
  | { kind: "separator" };

interface DisassemblyMinimapProps {
  rows: DisplayRow[];
  bookmarkSet: Set<number>;
  searchMatches: number[];
  viewportStartIdx: number;
  viewportEndIdx: number;
  loopRanges?: Loop[];
  onScrollTo: (rowIdx: number) => void;
}

export function DisassemblyMinimap({
  rows,
  bookmarkSet,
  searchMatches,
  viewportStartIdx,
  viewportEndIdx,
  loopRanges,
  onScrollTo,
}: DisassemblyMinimapProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [tooltip, setTooltip] = useState<{ y: number; text: string } | null>(null);

  const searchMatchSet = useRef(new Set<number>());
  useEffect(() => {
    searchMatchSet.current = new Set(searchMatches);
  }, [searchMatches]);

  // Build a row index → loop depth map for the minimap
  const loopRowMap = useMemo(() => {
    if (!loopRanges || loopRanges.length === 0 || rows.length === 0) return null;
    // Build address → row index lookup
    const addrToRowIdx = new Map<number, number>();
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (row.kind === "insn") addrToRowIdx.set(row.insn.address, i);
    }
    const m = new Map<number, number>(); // row index → max depth
    for (const loop of loopRanges) {
      if (!loop.bodyAddrs) continue;
      const depth = loop.depth + 1;
      for (const addr of loop.bodyAddrs) {
        const idx = addrToRowIdx.get(addr);
        if (idx !== undefined) {
          m.set(idx, Math.max(m.get(idx) ?? 0, depth));
        }
      }
    }
    return m;
  }, [loopRanges, rows]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || rows.length === 0) return;

    const height = container.clientHeight;
    const width = 20;
    canvas.width = width;
    canvas.height = height;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    ctx.clearRect(0, 0, width, height);

    const rowsPerPixel = Math.max(1, rows.length / height);

    // Draw rows
    for (let y = 0; y < height; y++) {
      const startRow = Math.floor(y * rowsPerPixel);
      const endRow = Math.min(Math.floor((y + 1) * rowsPerPixel), rows.length);

      let hasLabel = false;
      let hasBookmark = false;
      let hasSearchMatch = false;
      let hasInsn = false;
      let maxLoopDepth = 0;

      for (let r = startRow; r < endRow; r++) {
        const row = rows[r];
        if (row.kind === "label") {
          hasLabel = true;
        } else if (row.kind === "insn") {
          hasInsn = true;
          if (bookmarkSet.has(row.insn.address)) hasBookmark = true;
          if (searchMatchSet.current.has(r)) hasSearchMatch = true;
        }
        if (loopRowMap) {
          const d = loopRowMap.get(r);
          if (d !== undefined && d > maxLoopDepth) maxLoopDepth = d;
        }
      }

      // Draw loop indicator on left edge (thin 3px bar)
      if (maxLoopDepth > 0) {
        if (maxLoopDepth >= 3) ctx.fillStyle = "rgba(239, 68, 68, 0.5)"; // red
        else if (maxLoopDepth === 2) ctx.fillStyle = "rgba(249, 115, 22, 0.5)"; // orange
        else ctx.fillStyle = "rgba(234, 179, 8, 0.5)"; // yellow
        ctx.fillRect(0, y, 3, 1);
      }

      // Draw main content (offset by loop indicator)
      const contentX = 3;
      const contentW = width - contentX;

      if (hasBookmark) {
        ctx.fillStyle = "rgb(250, 204, 21)"; // yellow-400
        ctx.fillRect(contentX, y, contentW, 1);
      } else if (hasSearchMatch) {
        ctx.fillStyle = "rgb(251, 146, 60)"; // orange-400
        ctx.fillRect(contentX, y, contentW, 1);
      } else if (hasLabel) {
        ctx.fillStyle = "rgb(250, 204, 21)"; // yellow-400
        ctx.fillRect(contentX, y, contentW, 1);
      } else if (hasInsn) {
        ctx.fillStyle = "rgb(55, 65, 81)"; // gray-700
        ctx.fillRect(contentX, y, contentW, 1);
      }
    }

    // Draw viewport indicator
    const vpStartY = Math.floor((viewportStartIdx / rows.length) * height);
    const vpEndY = Math.ceil((viewportEndIdx / rows.length) * height);
    const vpHeight = Math.max(4, vpEndY - vpStartY);

    ctx.fillStyle = "rgba(255, 255, 255, 0.15)";
    ctx.fillRect(0, vpStartY, width, vpHeight);
    ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
    ctx.lineWidth = 1;
    ctx.strokeRect(0.5, vpStartY + 0.5, width - 1, vpHeight - 1);
  }, [rows, bookmarkSet, viewportStartIdx, viewportEndIdx, loopRowMap]);

  useEffect(() => {
    draw();
  }, [draw]);

  // Redraw on resize
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver(() => draw());
    observer.observe(container);
    return () => observer.disconnect();
  }, [draw]);

  const handleClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas || rows.length === 0) return;
    const rect = canvas.getBoundingClientRect();
    const y = e.clientY - rect.top;
    const rowIdx = Math.floor((y / rect.height) * rows.length);
    if (rowIdx >= 0 && rowIdx < rows.length) {
      onScrollTo(rowIdx);
    }
  }, [rows, onScrollTo]);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    const canvas = canvasRef.current;
    if (!canvas || rows.length === 0) return;
    const rect = canvas.getBoundingClientRect();
    const y = e.clientY - rect.top;
    const rowIdx = Math.floor((y / rect.height) * rows.length);
    if (rowIdx >= 0 && rowIdx < rows.length) {
      const row = rows[rowIdx];
      let text: string;
      if (row.kind === "insn") {
        text = `0x${row.insn.address.toString(16).toUpperCase()}`;
      } else if (row.kind === "label") {
        text = row.fn.name;
      } else {
        text = `Row ${rowIdx}`;
      }
      setTooltip({ y: e.clientY - rect.top, text });
    }
  }, [rows]);

  return (
    <div
      ref={containerRef}
      className="w-5 shrink-0 border-l border-gray-700 bg-gray-900 relative cursor-pointer"
    >
      <canvas
        ref={canvasRef}
        className="w-full h-full"
        onClick={handleClick}
        onMouseMove={handleMouseMove}
        onMouseLeave={() => setTooltip(null)}
      />
      {tooltip && (
        <div
          className="absolute right-6 z-30 bg-gray-800 border border-gray-600 rounded px-1.5 py-0.5 text-[9px] text-gray-300 whitespace-nowrap pointer-events-none"
          style={{ top: tooltip.y - 10 }}
        >
          {tooltip.text}
        </div>
      )}
    </div>
  );
}
