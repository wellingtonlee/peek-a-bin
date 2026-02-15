import { useMemo, useState, useRef, useCallback, useEffect } from "react";
import type { Instruction, DisasmFunction, Xref } from "../disasm/types";
import { buildCFG, layoutCFG, type LayoutBlock, type CFGEdge } from "../disasm/cfg";

interface CFGViewProps {
  func: DisasmFunction;
  instructions: Instruction[];
  typedXrefMap: Map<number, Xref[]>;
  currentAddress: number;
  onNavigate: (addr: number) => void;
  onClose: () => void;
}

const EDGE_COLORS: Record<CFGEdge['type'], string> = {
  fallthrough: "#4ade80", // green
  branch: "#fb923c",     // orange
  jump: "#ef4444",       // red
};

export function CFGView({
  func,
  instructions,
  typedXrefMap,
  currentAddress,
  onNavigate,
  onClose,
}: CFGViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [pan, setPan] = useState({ x: 0, y: 0 });
  const [zoom, setZoom] = useState(0.8);
  const [dragging, setDragging] = useState(false);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });

  const { blocks, edges } = useMemo(() => {
    const cfg = buildCFG(func, instructions, typedXrefMap);
    return layoutCFG(cfg);
  }, [func, instructions, typedXrefMap]);

  // Find bounds for centering
  useEffect(() => {
    if (blocks.length === 0) return;
    const container = containerRef.current;
    if (!container) return;

    const minX = Math.min(...blocks.map(b => b.x));
    const maxX = Math.max(...blocks.map(b => b.x + b.w));
    const centerX = (minX + maxX) / 2;
    const containerW = container.clientWidth;

    setPan({ x: containerW / 2 - centerX * zoom, y: 20 });
  }, [blocks, zoom]);

  const currentBlockId = useMemo(() => {
    for (const block of blocks) {
      if (currentAddress >= block.startAddr && currentAddress < block.endAddr) {
        return block.id;
      }
    }
    return -1;
  }, [blocks, currentAddress]);

  // Block ID → LayoutBlock map for edge rendering
  const blockMap = useMemo(() => {
    const m = new Map<number, LayoutBlock>();
    for (const b of blocks) m.set(b.id, b);
    return m;
  }, [blocks]);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    setDragging(true);
    dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging) return;
    setPan({
      x: dragStart.current.panX + (e.clientX - dragStart.current.x),
      y: dragStart.current.panY + (e.clientY - dragStart.current.y),
    });
  }, [dragging]);

  const handleMouseUp = useCallback(() => {
    setDragging(false);
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? -0.1 : 0.1;
    setZoom((z) => Math.max(0.2, Math.min(3, z + delta)));
  }, []);

  const handleBlockClick = useCallback((block: LayoutBlock) => {
    onNavigate(block.startAddr);
    onClose();
  }, [onNavigate, onClose]);

  // Compute SVG bounds
  const svgBounds = useMemo(() => {
    if (blocks.length === 0) return { minX: -100, minY: -100, width: 200, height: 200 };
    const minX = Math.min(...blocks.map(b => b.x)) - 50;
    const minY = Math.min(...blocks.map(b => b.y)) - 20;
    const maxX = Math.max(...blocks.map(b => b.x + b.w)) + 50;
    const maxY = Math.max(...blocks.map(b => b.y + b.h)) + 50;
    return { minX, minY, width: maxX - minX, height: maxY - minY };
  }, [blocks]);

  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center bg-black/60">
      <div className="w-[90vw] h-[85vh] bg-gray-900 border border-gray-600 rounded-lg shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center px-4 py-2 border-b border-gray-700 text-sm shrink-0">
          <span className="text-gray-300 font-semibold">CFG:</span>
          <span className="text-yellow-400 ml-2 font-mono">{func.name}</span>
          <span className="text-gray-500 ml-2 text-xs">
            ({blocks.length} blocks, {edges.length} edges)
          </span>
          <div className="flex-1" />
          <div className="flex items-center gap-2 text-xs text-gray-400 mr-4">
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-green-400 inline-block" /> fallthrough
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-orange-400 inline-block" /> branch
            </span>
            <span className="flex items-center gap-1">
              <span className="w-3 h-0.5 bg-red-400 inline-block" /> jump
            </span>
          </div>
          <span className="text-gray-500 text-xs mr-3">
            Zoom: {Math.round(zoom * 100)}%
          </span>
          <button
            onClick={onClose}
            className="text-gray-400 hover:text-white px-2 py-1 hover:bg-gray-700 rounded"
          >
            Close
          </button>
        </div>

        {/* SVG container */}
        <div
          ref={containerRef}
          className="flex-1 overflow-hidden cursor-grab active:cursor-grabbing"
          onMouseDown={handleMouseDown}
          onMouseMove={handleMouseMove}
          onMouseUp={handleMouseUp}
          onMouseLeave={handleMouseUp}
          onWheel={handleWheel}
        >
          <svg
            width="100%"
            height="100%"
            style={{
              transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
              transformOrigin: "0 0",
            }}
          >
            <defs>
              <marker id="arrow-green" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <path d="M0,0 L8,3 L0,6" fill="#4ade80" />
              </marker>
              <marker id="arrow-orange" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <path d="M0,0 L8,3 L0,6" fill="#fb923c" />
              </marker>
              <marker id="arrow-red" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                <path d="M0,0 L8,3 L0,6" fill="#ef4444" />
              </marker>
            </defs>

            {/* Edges */}
            {edges.map((edge, i) => {
              const fromBlock = blockMap.get(edge.from);
              const toBlock = blockMap.get(edge.to);
              if (!fromBlock || !toBlock) return null;

              const fromX = fromBlock.x + fromBlock.w / 2;
              const fromY = fromBlock.y + fromBlock.h;
              const toX = toBlock.x + toBlock.w / 2;
              const toY = toBlock.y;

              // Offset horizontally for multiple edges
              const edgeIdx = edges.filter(e => e.from === edge.from).indexOf(edge);
              const offset = (edgeIdx - 0.5) * 15;

              const midY = (fromY + toY) / 2;
              const color = EDGE_COLORS[edge.type];
              const markerId = edge.type === 'fallthrough' ? 'arrow-green'
                : edge.type === 'branch' ? 'arrow-orange' : 'arrow-red';

              // Handle back-edges (loops)
              if (toY <= fromY) {
                const loopX = Math.max(fromBlock.x + fromBlock.w, toBlock.x + toBlock.w) + 30 + Math.abs(offset);
                return (
                  <path
                    key={i}
                    d={`M${fromX + offset},${fromY} L${fromX + offset},${fromY + 15} L${loopX},${fromY + 15} L${loopX},${toY - 15} L${toX + offset},${toY - 15} L${toX + offset},${toY}`}
                    fill="none"
                    stroke={color}
                    strokeWidth={1.5}
                    opacity={0.7}
                    markerEnd={`url(#${markerId})`}
                  />
                );
              }

              return (
                <path
                  key={i}
                  d={`M${fromX + offset},${fromY} C${fromX + offset},${midY} ${toX + offset},${midY} ${toX + offset},${toY}`}
                  fill="none"
                  stroke={color}
                  strokeWidth={1.5}
                  opacity={0.7}
                  markerEnd={`url(#${markerId})`}
                />
              );
            })}

            {/* Blocks */}
            {blocks.map((block) => {
              const isCurrent = block.id === currentBlockId;
              return (
                <g
                  key={block.id}
                  onClick={(e) => { e.stopPropagation(); handleBlockClick(block); }}
                  className="cursor-pointer"
                >
                  <rect
                    x={block.x}
                    y={block.y}
                    width={block.w}
                    height={block.h}
                    rx={4}
                    ry={4}
                    fill={isCurrent ? "#1e3a5f" : "#1f2937"}
                    stroke={isCurrent ? "#3b82f6" : "#4b5563"}
                    strokeWidth={isCurrent ? 2 : 1}
                  />
                  {/* Header */}
                  <rect
                    x={block.x}
                    y={block.y}
                    width={block.w}
                    height={20}
                    rx={4}
                    ry={4}
                    fill={isCurrent ? "#1e40af" : "#374151"}
                  />
                  <rect
                    x={block.x}
                    y={block.y + 16}
                    width={block.w}
                    height={4}
                    fill={isCurrent ? "#1e40af" : "#374151"}
                  />
                  <text
                    x={block.x + 6}
                    y={block.y + 14}
                    fill="#9ca3af"
                    fontSize="10"
                    fontFamily="monospace"
                  >
                    {`0x${block.startAddr.toString(16).toUpperCase()}`}
                  </text>
                  <text
                    x={block.x + block.w - 6}
                    y={block.y + 14}
                    fill="#6b7280"
                    fontSize="9"
                    fontFamily="monospace"
                    textAnchor="end"
                  >
                    {block.insns.length} insn
                  </text>
                  {/* Instructions (truncated) */}
                  {block.insns.slice(0, Math.floor((block.h - 24) / 14)).map((insn, j) => (
                    <text
                      key={insn.address}
                      x={block.x + 6}
                      y={block.y + 34 + j * 14}
                      fill={
                        insn.address === currentAddress ? "#60a5fa" :
                        insn.mnemonic === 'call' ? "#4ade80" :
                        insn.mnemonic === 'ret' || insn.mnemonic === 'retn' ? "#f87171" :
                        insn.mnemonic.startsWith('j') ? "#fb923c" :
                        "#d1d5db"
                      }
                      fontSize="10"
                      fontFamily="monospace"
                    >
                      {`${insn.mnemonic} ${insn.opStr}`.substring(0, 28)}
                    </text>
                  ))}
                </g>
              );
            })}
          </svg>
        </div>
      </div>
    </div>
  );
}
