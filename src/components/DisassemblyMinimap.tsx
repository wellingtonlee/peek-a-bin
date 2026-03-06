import { useRef, useEffect, useCallback, useState, useMemo } from "react";
import type { DisasmFunction } from "../disasm/types";
import type { Loop } from "../disasm/cfg";
import type { LayoutBlock, CFGEdge } from "../disasm/cfg";

type DisplayRow =
  | { kind: "label"; fn: DisasmFunction }
  | { kind: "insn"; insn: { address: number }; blockIdx: number }
  | { kind: "separator" }
  | { kind: "data"; item: { address: number } };

interface DisassemblyMinimapProps {
  rows: DisplayRow[];
  bookmarkSet: Set<number>;
  searchMatches: number[];
  viewportStartIdx: number;
  viewportEndIdx: number;
  loopRanges?: Loop[];
  onScrollTo: (rowIdx: number) => void;
  // Graph mode props
  mode?: "linear" | "graph";
  graphBlocks?: LayoutBlock[];
  graphEdges?: CFGEdge[];
  graphPan?: { x: number; y: number };
  graphZoom?: number;
  graphViewport?: { width: number; height: number };
  onGraphPanTo?: (pan: { x: number; y: number }) => void;
  currentAddress?: number;
}

export function DisassemblyMinimap({
  rows,
  bookmarkSet,
  searchMatches,
  viewportStartIdx,
  viewportEndIdx,
  loopRanges,
  onScrollTo,
  mode = "linear",
  graphBlocks,
  graphEdges,
  graphPan,
  graphZoom,
  graphViewport,
  onGraphPanTo,
  currentAddress,
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
    const addrToRowIdx = new Map<number, number>();
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (row.kind === "insn") addrToRowIdx.set(row.insn.address, i);
    }
    const m = new Map<number, number>();
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

  // Find which block contains currentAddress (for graph mode highlighting)
  const currentBlockId = useMemo(() => {
    if (!graphBlocks || currentAddress === undefined) return -1;
    for (const b of graphBlocks) {
      if (currentAddress >= b.startAddr && currentAddress < b.endAddr) return b.id;
    }
    return -1;
  }, [graphBlocks, currentAddress]);

  const drawLinear = useCallback(() => {
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

      if (maxLoopDepth > 0) {
        if (maxLoopDepth >= 3) ctx.fillStyle = "rgba(239, 68, 68, 0.5)";
        else if (maxLoopDepth === 2) ctx.fillStyle = "rgba(249, 115, 22, 0.5)";
        else ctx.fillStyle = "rgba(234, 179, 8, 0.5)";
        ctx.fillRect(0, y, 3, 1);
      }

      const contentX = 3;
      const contentW = width - contentX;

      if (hasBookmark) {
        ctx.fillStyle = "rgb(250, 204, 21)";
        ctx.fillRect(contentX, y, contentW, 1);
      } else if (hasSearchMatch) {
        ctx.fillStyle = "rgb(251, 146, 60)";
        ctx.fillRect(contentX, y, contentW, 1);
      } else if (hasLabel) {
        ctx.fillStyle = "rgb(250, 204, 21)";
        ctx.fillRect(contentX, y, contentW, 1);
      } else if (hasInsn) {
        ctx.fillStyle = "rgb(55, 65, 81)";
        ctx.fillRect(contentX, y, contentW, 1);
      }
    }

    const vpStartY = Math.floor((viewportStartIdx / rows.length) * height);
    const vpEndY = Math.ceil((viewportEndIdx / rows.length) * height);
    const vpHeight = Math.max(4, vpEndY - vpStartY);

    ctx.fillStyle = "rgba(255, 255, 255, 0.15)";
    ctx.fillRect(0, vpStartY, width, vpHeight);
    ctx.strokeStyle = "rgba(255, 255, 255, 0.3)";
    ctx.lineWidth = 1;
    ctx.strokeRect(0.5, vpStartY + 0.5, width - 1, vpHeight - 1);
  }, [rows, bookmarkSet, viewportStartIdx, viewportEndIdx, loopRowMap]);

  const drawGraph = useCallback(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || !graphBlocks || graphBlocks.length === 0) return;

    const canvasH = container.clientHeight;
    const canvasW = 20;
    canvas.width = canvasW;
    canvas.height = canvasH;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, canvasW, canvasH);

    // Compute graph bounds
    const minX = Math.min(...graphBlocks.map(b => b.x));
    const maxX = Math.max(...graphBlocks.map(b => b.x + b.w));
    const minY = Math.min(...graphBlocks.map(b => b.y));
    const maxY = Math.max(...graphBlocks.map(b => b.y + b.h));
    const graphW = maxX - minX;
    const graphH = maxY - minY;

    if (graphW === 0 || graphH === 0) return;

    const padding = 2;
    const scaleX = (canvasW - padding * 2) / graphW;
    const scaleY = (canvasH - padding * 2) / graphH;
    const scale = Math.min(scaleX, scaleY);

    const offsetX = padding + (canvasW - padding * 2 - graphW * scale) / 2;
    const offsetY = padding + (canvasH - padding * 2 - graphH * scale) / 2;

    // Draw blocks
    for (const block of graphBlocks) {
      const bx = offsetX + (block.x - minX) * scale;
      const by = offsetY + (block.y - minY) * scale;
      const bw = Math.max(1, block.w * scale);
      const bh = Math.max(1, block.h * scale);

      if (block.id === currentBlockId) {
        ctx.fillStyle = "rgba(59, 130, 246, 0.6)"; // blue
      } else {
        ctx.fillStyle = "rgba(107, 114, 128, 0.5)"; // gray
      }
      ctx.fillRect(bx, by, bw, bh);
    }

    // Draw viewport rectangle
    if (graphPan && graphZoom && graphViewport) {
      // Viewport in graph coordinates
      const vpGx = -graphPan.x / graphZoom;
      const vpGy = -graphPan.y / graphZoom;
      const vpGw = graphViewport.width / graphZoom;
      const vpGh = graphViewport.height / graphZoom;

      const vx = offsetX + (vpGx - minX) * scale;
      const vy = offsetY + (vpGy - minY) * scale;
      const vw = vpGw * scale;
      const vh = vpGh * scale;

      ctx.strokeStyle = "rgba(255, 255, 255, 0.4)";
      ctx.lineWidth = 1;
      ctx.strokeRect(Math.max(0, vx) + 0.5, Math.max(0, vy) + 0.5, Math.min(canvasW, vw), Math.min(canvasH, vh));
    }
  }, [graphBlocks, graphPan, graphZoom, graphViewport, currentBlockId]);

  const draw = mode === "graph" ? drawGraph : drawLinear;

  useEffect(() => {
    draw();
  }, [draw]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver(() => draw());
    observer.observe(container);
    return () => observer.disconnect();
  }, [draw]);

  const handleClick = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (mode === "graph") {
      if (!graphBlocks || graphBlocks.length === 0 || !onGraphPanTo || !graphZoom || !graphViewport) return;
      const canvas = canvasRef.current;
      if (!canvas) return;
      const rect = canvas.getBoundingClientRect();
      const clickY = e.clientY - rect.top;
      const clickX = e.clientX - rect.left;

      const minX = Math.min(...graphBlocks.map(b => b.x));
      const maxX = Math.max(...graphBlocks.map(b => b.x + b.w));
      const minY = Math.min(...graphBlocks.map(b => b.y));
      const maxY = Math.max(...graphBlocks.map(b => b.y + b.h));
      const graphW = maxX - minX;
      const graphH = maxY - minY;
      if (graphW === 0 || graphH === 0) return;

      const canvasW = 20;
      const canvasH = rect.height;
      const padding = 2;
      const scaleX = (canvasW - padding * 2) / graphW;
      const scaleY = (canvasH - padding * 2) / graphH;
      const scale = Math.min(scaleX, scaleY);
      const offsetX = padding + (canvasW - padding * 2 - graphW * scale) / 2;
      const offsetY = padding + (canvasH - padding * 2 - graphH * scale) / 2;

      const graphClickX = (clickX - offsetX) / scale + minX;
      const graphClickY = (clickY - offsetY) / scale + minY;

      onGraphPanTo({
        x: graphViewport.width / 2 - graphClickX * graphZoom,
        y: graphViewport.height / 2 - graphClickY * graphZoom,
      });
      return;
    }

    const canvas = canvasRef.current;
    if (!canvas || rows.length === 0) return;
    const rect = canvas.getBoundingClientRect();
    const y = e.clientY - rect.top;
    const rowIdx = Math.floor((y / rect.height) * rows.length);
    if (rowIdx >= 0 && rowIdx < rows.length) {
      onScrollTo(rowIdx);
    }
  }, [mode, rows, onScrollTo, graphBlocks, graphZoom, graphViewport, onGraphPanTo]);

  const handleMouseMove = useCallback((e: React.MouseEvent<HTMLCanvasElement>) => {
    if (mode === "graph") {
      setTooltip(null);
      return;
    }
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
  }, [mode, rows]);

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
