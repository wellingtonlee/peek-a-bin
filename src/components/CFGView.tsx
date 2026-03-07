import { useMemo, useRef, useCallback, useEffect } from "react";
import type { Instruction, DisasmFunction, Xref } from "../disasm/types";
import type { PEFile } from "../pe/types";
import { buildCFG, layoutCFG, getCfgLayout, type LayoutBlock, type CFGEdge } from "../disasm/cfg";
import { loadFontSize } from "../llm/settings";
import { parseOperandTargets } from "../disasm/operands";
import { ColoredOperand, mnemonicClass, type ClickableTarget } from "./shared";
import { MNEMONIC_HINTS } from "../disasm/mnemonics";

export interface CFGViewProps {
  func: DisasmFunction;
  instructions: Instruction[];
  typedXrefMap: Map<number, Xref[]>;
  jumpTables?: Map<number, number[]>;
  currentAddress: number;
  pe: PEFile;
  onNavigate: (addr: number) => void;
  onAddressClick: (addr: number) => void;
  onDoubleClickAddr: (addr: number) => void;
  onContextMenu: (e: React.MouseEvent, insn: Instruction) => void;
  onRegClick: (regName: string) => void;
  highlightRegs: Set<string> | null;
  copiedAddr: number | null;
  editingComment: { address: number; value: string } | null;
  onEditComment: (state: { address: number; value: string } | null) => void;
  comments: Record<number, string>;
  renames: Record<number, string>;
  bookmarkSet: Set<number>;
  iatMap: Map<number, { lib: string; func: string }>;
  pan: { x: number; y: number };
  zoom: number;
  onPanChange: (pan: { x: number; y: number }) => void;
  onZoomChange: (zoom: number) => void;
  collapsedBlocks: Set<number>;
  onToggleCollapse: (blockId: number) => void;
  onCommentSubmit: (address: number, text: string) => void;
  onCommentDelete: (address: number) => void;
  restorePanZoom?: { pan: { x: number; y: number }; zoom: number } | null;
  reCenterTrigger?: number;
  onNavBack?: () => void;
}

const EDGE_COLORS: Record<CFGEdge['type'], string> = {
  fallthrough: "#4ade80",
  branch: "#fb923c",
  jump: "#ef4444",
};

export function CFGView({
  func,
  instructions,
  typedXrefMap,
  jumpTables,
  currentAddress,
  pe,
  onNavigate,
  onAddressClick,
  onDoubleClickAddr,
  onContextMenu,
  onRegClick,
  highlightRegs,
  copiedAddr,
  editingComment,
  onEditComment,
  comments,
  renames,
  bookmarkSet,
  iatMap,
  pan,
  zoom,
  onPanChange,
  onZoomChange,
  collapsedBlocks,
  onToggleCollapse,
  onCommentSubmit,
  onCommentDelete,
  restorePanZoom,
  reCenterTrigger,
  onNavBack,
}: CFGViewProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const dragStart = useRef({ x: 0, y: 0, panX: 0, panY: 0 });
  const draggingRef = useRef(false);
  const graphInteractionRef = useRef(false);

  const fontSize = loadFontSize();
  const cfgLayout = useMemo(() => getCfgLayout(fontSize), [fontSize]);

  const { blocks, edges } = useMemo(() => {
    const cfg = buildCFG(func, instructions, typedXrefMap, jumpTables);
    return layoutCFG(cfg, fontSize);
  }, [func, instructions, typedXrefMap, jumpTables, fontSize]);

  const blockMap = useMemo(() => {
    const m = new Map<number, LayoutBlock>();
    for (const b of blocks) m.set(b.id, b);
    return m;
  }, [blocks]);

  // addr → blockId lookup
  const addrToBlockId = useMemo(() => {
    const m = new Map<number, number>();
    for (const b of blocks) {
      for (const insn of b.insns) m.set(insn.address, b.id);
    }
    return m;
  }, [blocks]);

  const currentBlockId = useMemo(() => {
    return addrToBlockId.get(currentAddress) ?? -1;
  }, [addrToBlockId, currentAddress]);

  // Track whether we just consumed a restorePanZoom to avoid re-centering when it's cleared
  const consumedRestoreRef = useRef(false);

  // Auto-center on mount or function change — pan to block containing currentAddress
  useEffect(() => {
    if (blocks.length === 0) return;
    const container = containerRef.current;
    if (!container) return;
    graphInteractionRef.current = false;
    // If restoring pan/zoom from navigation, use those values instead of auto-centering
    if (restorePanZoom) {
      onPanChange(restorePanZoom.pan);
      onZoomChange(restorePanZoom.zoom);
      consumedRestoreRef.current = true;
      return;
    }
    // Skip auto-center on the re-fire caused by clearing restorePanZoom
    if (consumedRestoreRef.current) {
      consumedRestoreRef.current = false;
      return;
    }
    const containerW = container.clientWidth;
    // Try to center on the block containing currentAddress
    const targetBlockId = addrToBlockId.get(currentAddress);
    const targetBlock = targetBlockId !== undefined ? blockMap.get(targetBlockId) : undefined;
    if (targetBlock) {
      onPanChange({
        x: containerW / 2 - (targetBlock.x + targetBlock.w / 2) * zoom,
        y: 40 - targetBlock.y * zoom,
      });
    } else {
      const minX = Math.min(...blocks.map(b => b.x));
      const maxX = Math.max(...blocks.map(b => b.x + b.w));
      const minY = Math.min(...blocks.map(b => b.y));
      const centerX = (minX + maxX) / 2;
      onPanChange({ x: containerW / 2 - centerX * zoom, y: 20 - minY * zoom });
    }
  }, [func.address, blocks.length, restorePanZoom]);

  // Re-center when decompile panel opens (container width changes)
  useEffect(() => {
    if (!reCenterTrigger || blocks.length === 0) return;
    const container = containerRef.current;
    if (!container) return;
    const containerW = container.clientWidth;
    const targetBlockId = addrToBlockId.get(currentAddress);
    const targetBlock = targetBlockId !== undefined ? blockMap.get(targetBlockId) : undefined;
    if (targetBlock) {
      onPanChange({
        x: containerW / 2 - (targetBlock.x + targetBlock.w / 2) * zoom,
        y: 40 - targetBlock.y * zoom,
      });
    }
  }, [reCenterTrigger]);

  // Zoom-to-fit callback
  const zoomToFit = useCallback(() => {
    if (blocks.length === 0) return;
    const container = containerRef.current;
    if (!container) return;
    const minX = Math.min(...blocks.map(b => b.x));
    const maxX = Math.max(...blocks.map(b => b.x + b.w));
    const minY = Math.min(...blocks.map(b => b.y));
    const maxY = Math.max(...blocks.map(b => b.y + b.h));
    const graphW = maxX - minX;
    const graphH = maxY - minY;
    const cW = container.clientWidth;
    const cH = container.clientHeight;
    const padding = 40;
    const newZoom = Math.min(
      Math.max(0.2, Math.min(3, (cW - padding * 2) / graphW, (cH - padding * 2) / graphH)),
      3,
    );
    onZoomChange(newZoom);
    onPanChange({
      x: (cW - graphW * newZoom) / 2 - minX * newZoom,
      y: (cH - graphH * newZoom) / 2 - minY * newZoom,
    });
  }, [blocks, onZoomChange, onPanChange]);

  // Zoom toward viewport center (for zoom bar controls)
  const zoomToCenter = useCallback((newZoom: number) => {
    const container = containerRef.current;
    if (!container) { onZoomChange(newZoom); return; }
    const cx = container.clientWidth / 2;
    const cy = container.clientHeight / 2;
    const scale = newZoom / zoom;
    onZoomChange(newZoom);
    onPanChange({
      x: cx - (cx - pan.x) * scale,
      y: cy - (cy - pan.y) * scale,
    });
  }, [zoom, pan, onZoomChange, onPanChange]);

  // Expose zoomToFit on the container element for parent access
  useEffect(() => {
    const el = containerRef.current;
    if (el) (el as any).__zoomToFit = zoomToFit;
  }, [zoomToFit]);

  // Auto-pan to current block when address changes externally
  useEffect(() => {
    if (restorePanZoom) return;
    if (currentBlockId < 0 || graphInteractionRef.current) {
      graphInteractionRef.current = false;
      return;
    }
    const block = blockMap.get(currentBlockId);
    const container = containerRef.current;
    if (!block || !container) return;
    const cW = container.clientWidth;
    const cH = container.clientHeight;
    // Check if block top is visible in viewport
    const bcx = block.x * zoom + pan.x + (block.w * zoom) / 2;
    const bty = block.y * zoom + pan.y;
    const margin = 50;
    if (bcx >= margin && bcx <= cW - margin && bty >= margin && bty <= cH - margin) return;
    // Top-align the block in the viewport with 40px margin
    onPanChange({
      x: cW / 2 - (block.x + block.w / 2) * zoom,
      y: 40 - block.y * zoom,
    });
  }, [currentBlockId, currentAddress]);

  // Viewport culling
  const visibleBlockIds = useMemo(() => {
    const container = containerRef.current;
    if (!container) return new Set(blocks.map(b => b.id));
    const cW = container.clientWidth;
    const cH = container.clientHeight;
    const margin = 100;
    const ids = new Set<number>();
    for (const b of blocks) {
      const bx = b.x * zoom + pan.x;
      const by = b.y * zoom + pan.y;
      const bw = b.w * zoom;
      const bh = (collapsedBlocks.has(b.id) ? cfgLayout.BLOCK_HEADER : b.h) * zoom;
      if (bx + bw >= -margin && bx <= cW + margin && by + bh >= -margin && by <= cH + margin) {
        ids.add(b.id);
      }
    }
    return ids;
  }, [blocks, pan, zoom, collapsedBlocks]);

  // Wrap onNavigate to flag graph-internal navigation
  const handleGraphNavigate = useCallback((addr: number) => {
    graphInteractionRef.current = true;
    onNavigate(addr);
  }, [onNavigate]);

  // Pan handlers
  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    if (e.button !== 0) return;
    // Don't start drag if clicking on a block element
    if ((e.target as HTMLElement).closest('.cfg-block')) return;
    draggingRef.current = true;
    dragStart.current = { x: e.clientX, y: e.clientY, panX: pan.x, panY: pan.y };
    e.preventDefault();
  }, [pan]);

  const handleMouseMove = useCallback((e: React.MouseEvent) => {
    if (!draggingRef.current) return;
    onPanChange({
      x: dragStart.current.panX + (e.clientX - dragStart.current.x),
      y: dragStart.current.panY + (e.clientY - dragStart.current.y),
    });
  }, [onPanChange]);

  const handleMouseUp = useCallback(() => {
    draggingRef.current = false;
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const container = containerRef.current;
    if (!container) return;

    if (e.ctrlKey || e.metaKey) {
      // Ctrl+scroll: zoom toward cursor
      const rect = container.getBoundingClientRect();
      const mouseX = e.clientX - rect.left;
      const mouseY = e.clientY - rect.top;
      const oldZoom = zoom;
      const delta = e.deltaY > 0 ? -0.1 : 0.1;
      const newZoom = Math.max(0.2, Math.min(3, oldZoom + delta));
      const scale = newZoom / oldZoom;
      onZoomChange(newZoom);
      onPanChange({
        x: mouseX - (mouseX - pan.x) * scale,
        y: mouseY - (mouseY - pan.y) * scale,
      });
    } else {
      // Regular scroll: pan
      onPanChange({
        x: pan.x - e.deltaX,
        y: pan.y - e.deltaY,
      });
    }
  }, [zoom, pan, onZoomChange, onPanChange]);

  // Mouse back/forward
  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const handler = (e: MouseEvent) => {
      if (e.button === 3 || e.button === 4) e.preventDefault();
    };
    el.addEventListener("mouseup", handler);
    return () => el.removeEventListener("mouseup", handler);
  }, []);

  // Edges filtered by visibility
  const visibleEdges = useMemo(() => {
    return edges.filter(e => visibleBlockIds.has(e.from) || visibleBlockIds.has(e.to));
  }, [edges, visibleBlockIds]);

  // Graph bounds for SVG sizing
  const graphBounds = useMemo(() => {
    if (blocks.length === 0) return { minX: 0, minY: 0, maxX: 100, maxY: 100 };
    const minX = Math.min(...blocks.map(b => b.x)) - 100;
    const minY = Math.min(...blocks.map(b => b.y)) - 50;
    const maxX = Math.max(...blocks.map(b => b.x + b.w)) + 100;
    const maxY = Math.max(...blocks.map(b => b.y + b.h)) + 100;
    return { minX, minY, maxX, maxY };
  }, [blocks]);

  return (
    <div
      ref={containerRef}
      className="cfg-container flex-1 overflow-hidden cursor-grab active:cursor-grabbing relative"
      style={{ overscrollBehavior: "none", touchAction: "none" }}
      onMouseDown={handleMouseDown}
      onMouseMove={handleMouseMove}
      onMouseUp={handleMouseUp}
      onMouseLeave={handleMouseUp}
      onWheel={handleWheel}
    >
      {/* Zoom control bar */}
      <div className="absolute top-2 right-2 z-10 flex items-center gap-1 bg-gray-900/80 px-1.5 py-0.5 rounded text-[10px] text-gray-400">
        <button
          className="hover:text-white px-0.5"
          onClick={(e) => { e.stopPropagation(); zoomToCenter(Math.max(0.2, zoom - 0.1)); }}
          title="Zoom out"
        >−</button>
        <input
          type="range"
          min="0.2"
          max="3"
          step="0.05"
          value={zoom}
          onChange={(e) => { zoomToCenter(parseFloat(e.target.value)); }}
          onClick={(e) => e.stopPropagation()}
          onMouseDown={(e) => e.stopPropagation()}
          className="w-16 h-1 accent-gray-500 cursor-pointer"
        />
        <button
          className="hover:text-white px-0.5"
          onClick={(e) => { e.stopPropagation(); zoomToCenter(Math.min(3, zoom + 0.1)); }}
          title="Zoom in"
        >+</button>
        <span className="w-7 text-center text-gray-500">{Math.round(zoom * 100)}%</span>
        <button
          className="hover:text-white px-0.5"
          onClick={(e) => { e.stopPropagation(); zoomToFit(); }}
          title="Fit to view"
        >⊡</button>
      </div>

      <div
        style={{
          transform: `translate(${pan.x}px, ${pan.y}px) scale(${zoom})`,
          transformOrigin: "0 0",
          position: "absolute",
          top: 0,
          left: 0,
        }}
      >
        {/* SVG edge layer */}
        <svg
          style={{
            position: "absolute",
            top: graphBounds.minY,
            left: graphBounds.minX,
            width: graphBounds.maxX - graphBounds.minX,
            height: graphBounds.maxY - graphBounds.minY,
            pointerEvents: "none",
            overflow: "visible",
          }}
        >
          <defs>
            <marker id="cfg-arrow-green" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <path d="M0,0 L8,3 L0,6" fill="#4ade80" />
            </marker>
            <marker id="cfg-arrow-orange" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <path d="M0,0 L8,3 L0,6" fill="#fb923c" />
            </marker>
            <marker id="cfg-arrow-red" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
              <path d="M0,0 L8,3 L0,6" fill="#ef4444" />
            </marker>
          </defs>

          {visibleEdges.map((edge, i) => {
            const fromBlock = blockMap.get(edge.from);
            const toBlock = blockMap.get(edge.to);
            if (!fromBlock || !toBlock) return null;

            const fromCollapsed = collapsedBlocks.has(fromBlock.id);
            const toCollapsed = collapsedBlocks.has(toBlock.id);

            // Offset within SVG coordinate space
            const ox = -graphBounds.minX;
            const oy = -graphBounds.minY;

            const fromH = fromCollapsed ? cfgLayout.BLOCK_HEADER : fromBlock.h;
            const fromX = ox + fromBlock.x + fromBlock.w / 2;
            const fromY = oy + fromBlock.y + fromH;
            const toX = ox + toBlock.x + toBlock.w / 2;
            const toY = oy + toBlock.y;

            // Small offset for multiple edges from same block to avoid overlap
            const siblings = edges.filter(e => e.from === edge.from);
            const edgeIdx = siblings.indexOf(edge);
            const offset = siblings.length > 1 ? (edgeIdx - (siblings.length - 1) / 2) * 12 : 0;

            const color = EDGE_COLORS[edge.type];
            const markerId = edge.type === 'fallthrough' ? 'cfg-arrow-green'
              : edge.type === 'branch' ? 'cfg-arrow-orange' : 'cfg-arrow-red';

            // Back-edge (loop)
            if (toBlock.y <= fromBlock.y) {
              const loopX = ox + Math.max(fromBlock.x + fromBlock.w, toBlock.x + toBlock.w) + 30 + Math.abs(offset);
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

            const midY = (fromY + toY) / 2;
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
        </svg>

        {/* HTML block layer */}
        {blocks.filter(b => visibleBlockIds.has(b.id)).map(block => (
          <CFGBlock
            key={block.id}
            block={block}
            cfgLayout={cfgLayout}
            isCurrent={block.id === currentBlockId}
            currentAddress={currentAddress}
            collapsed={collapsedBlocks.has(block.id)}
            onToggleCollapse={() => onToggleCollapse(block.id)}
            pe={pe}
            iatMap={iatMap}
            onNavigate={handleGraphNavigate}
            onAddressClick={onAddressClick}
            onDoubleClickAddr={onDoubleClickAddr}
            onContextMenu={onContextMenu}
            onRegClick={onRegClick}
            highlightRegs={highlightRegs}
            copiedAddr={copiedAddr}
            editingComment={editingComment}
            onEditComment={onEditComment}
            comments={comments}
            bookmarkSet={bookmarkSet}
            onCommentSubmit={onCommentSubmit}
            onCommentDelete={onCommentDelete}
          />
        ))}
      </div>
    </div>
  );
}

// --- CFGBlock sub-component ---

function CFGBlock({
  block,
  cfgLayout,
  isCurrent,
  currentAddress,
  collapsed,
  onToggleCollapse,
  pe,
  iatMap,
  onNavigate,
  onAddressClick,
  onDoubleClickAddr,
  onContextMenu,
  onRegClick,
  highlightRegs,
  copiedAddr,
  editingComment,
  onEditComment,
  comments,
  bookmarkSet,
  onCommentSubmit,
  onCommentDelete,
}: {
  block: LayoutBlock;
  cfgLayout: ReturnType<typeof getCfgLayout>;
  isCurrent: boolean;
  currentAddress: number;
  collapsed: boolean;
  onToggleCollapse: () => void;
  pe: PEFile;
  iatMap: Map<number, { lib: string; func: string }>;
  onNavigate: (addr: number) => void;
  onAddressClick: (addr: number) => void;
  onDoubleClickAddr: (addr: number) => void;
  onContextMenu: (e: React.MouseEvent, insn: Instruction) => void;
  onRegClick: (regName: string) => void;
  highlightRegs: Set<string> | null;
  copiedAddr: number | null;
  editingComment: { address: number; value: string } | null;
  onEditComment: (state: { address: number; value: string } | null) => void;
  comments: Record<number, string>;
  bookmarkSet: Set<number>;
  onCommentSubmit: (address: number, text: string) => void;
  onCommentDelete: (address: number) => void;
}) {
  const height = collapsed ? cfgLayout.BLOCK_HEADER : block.h;

  return (
    <div
      className="cfg-block absolute select-none"
      style={{
        left: block.x,
        top: block.y,
        width: block.w,
        height,
        border: `${isCurrent ? 2 : 1}px solid ${isCurrent ? "#2563eb" : "#4b5563"}`,
        borderRadius: 4,
        background: isCurrent ? "#1e3a5f" : "#1f2937",
        overflow: "hidden",
        fontSize: "var(--mono-font-size, 10px)",
        fontFamily: "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, monospace",
      }}
    >
      {/* Header bar */}
      <div
        className="flex items-center justify-between px-1.5 cursor-pointer hover:brightness-125"
        style={{
          height: cfgLayout.BLOCK_HEADER,
          background: isCurrent ? "#1e40af" : "#374151",
          borderRadius: collapsed ? "3px" : "3px 3px 0 0",
        }}
        onClick={(e) => { e.stopPropagation(); onToggleCollapse(); }}
      >
        <span className="text-gray-400 text-[0.85em]">
          {collapsed ? "▶" : "▼"} 0x{block.startAddr.toString(16).toUpperCase()}
        </span>
        <span className="text-gray-500 text-[0.75em]">
          {block.insns.length} insn
        </span>
      </div>

      {/* Instruction rows */}
      {!collapsed && block.insns.map(insn => {
        const isCurrentAddr = insn.address === currentAddress;
        const isBookmarked = bookmarkSet.has(insn.address);
        const isEditing = editingComment?.address === insn.address;
        const userComment = comments[insn.address];

        const operandTargets = parseOperandTargets(
          insn,
          pe.optionalHeader.imageBase,
          pe.optionalHeader.imageBase + pe.optionalHeader.sizeOfImage,
          iatMap,
        );

        return (
          <div
            key={insn.address}
            className={`flex items-center px-1 group ${isCurrentAddr ? "bg-yellow-500/20 border-l-2 border-yellow-400" : "hover:bg-gray-700/30"}`}
            style={{ height: cfgLayout.INSN_HEIGHT, lineHeight: `${cfgLayout.INSN_HEIGHT}px` }}
            onClick={(e) => {
              e.stopPropagation();
              onNavigate(insn.address);
            }}
            onContextMenu={(e) => {
              e.stopPropagation();
              onContextMenu(e, insn);
            }}
          >
            {/* Bookmark indicator */}
            <span className="w-3 shrink-0 text-center text-[0.67em]">
              {isBookmarked && <span className="text-yellow-300">★</span>}
            </span>

            {/* Address */}
            <span
              className={`w-[5.5em] shrink-0 text-[0.85em] cursor-pointer hover:text-blue-400 ${
                copiedAddr === insn.address ? "text-green-400" : "text-gray-500"
              }`}
              onClick={(e) => { e.stopPropagation(); onAddressClick(insn.address); }}
              onDoubleClick={(e) => { e.stopPropagation(); onDoubleClickAddr(insn.address); }}
            >
              {insn.address.toString(16).toUpperCase().slice(-8)}
            </span>

            {/* Mnemonic */}
            <span
              className={`w-10 shrink-0 ${mnemonicClass(insn.mnemonic)}`}
              title={MNEMONIC_HINTS[insn.mnemonic]}
            >
              {insn.mnemonic}
            </span>

            {/* Operands */}
            <span className="flex-1 truncate">
              <ColoredOperand
                opStr={insn.opStr}
                targets={operandTargets}
                onNavigate={onAddressClick}
                highlightRegs={highlightRegs}
                onRegClick={onRegClick}
              />
            </span>

            {/* Comment */}
            {isEditing ? (
              <span className="ml-1 shrink-0">
                <input
                  autoFocus
                  className="bg-gray-900/80 border border-blue-500 rounded px-1 text-[#6ee7b7] text-[0.75em] font-mono outline-none w-32"
                  value={editingComment.value}
                  onChange={(e) => onEditComment({ ...editingComment, value: e.target.value })}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") {
                      e.preventDefault();
                      const val = editingComment.value.trim();
                      if (val) onCommentSubmit(editingComment.address, val);
                      else onCommentDelete(editingComment.address);
                      onEditComment(null);
                    }
                    if (e.key === "Escape") onEditComment(null);
                    e.stopPropagation();
                  }}
                  onBlur={() => onEditComment(null)}
                  onClick={(e) => e.stopPropagation()}
                />
              </span>
            ) : (insn.comment || userComment) ? (
              <span className="disasm-comment ml-1 truncate max-w-[8em] text-[0.75em]" title={userComment || insn.comment || ""}>
                ; {userComment || insn.comment}
              </span>
            ) : null}
          </div>
        );
      })}
    </div>
  );
}
