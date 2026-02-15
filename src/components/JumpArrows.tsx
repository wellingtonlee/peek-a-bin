import { useMemo } from "react";
import type { VirtualItem } from "@tanstack/react-virtual";
import type { DisasmFunction } from "../disasm/types";

type DisplayRow =
  | { kind: "label"; fn: DisasmFunction }
  | { kind: "insn"; insn: { address: number; mnemonic: string; opStr: string; size: number }; blockIdx: number }
  | { kind: "separator" };

interface JumpArrowsProps {
  visibleItems: VirtualItem[];
  rows: DisplayRow[];
  funcMap: Map<number, DisasmFunction>;
  currentFuncAddr: number | null;
  currentAddress: number;
  rowHeight: number;
}

interface Arrow {
  fromY: number;
  toY: number;
  lane: number;
  isBackward: boolean;
  isCurrent: boolean;
  clipped: "none" | "top" | "bottom";
}

function parseBranchTarget(mnemonic: string, opStr: string): number | null {
  if (mnemonic === "jmp" || (mnemonic.startsWith("j") && mnemonic !== "jmp")) {
    const m = opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (m) return parseInt(m[1], 16);
  }
  // Also handle jmp
  if (mnemonic === "jmp") {
    const m = opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (m) return parseInt(m[1], 16);
  }
  return null;
}

export function JumpArrows({
  visibleItems,
  rows,
  funcMap,
  currentFuncAddr,
  currentAddress,
  rowHeight,
}: JumpArrowsProps) {
  const arrows = useMemo(() => {
    if (!currentFuncAddr || visibleItems.length === 0) return [];

    // Find current function boundaries
    const curFunc = funcMap.get(currentFuncAddr);
    if (!curFunc) return [];
    const funcStart = curFunc.address;
    const funcEnd = curFunc.address + curFunc.size;

    // Build address→vItem Y map for visible items
    const addrToY = new Map<number, number>();
    const visibleAddrs = new Set<number>();

    let minY = Infinity;
    let maxY = -Infinity;

    for (const vItem of visibleItems) {
      const row = rows[vItem.index];
      if (row?.kind === "insn") {
        const addr = row.insn.address;
        addrToY.set(addr, vItem.start + rowHeight / 2);
        visibleAddrs.add(addr);
        minY = Math.min(minY, vItem.start);
        maxY = Math.max(maxY, vItem.start + rowHeight);
      }
    }

    // Collect branch arrows from visible instructions
    const rawArrows: { fromAddr: number; toAddr: number; fromY: number; span: number }[] = [];

    for (const vItem of visibleItems) {
      const row = rows[vItem.index];
      if (row?.kind !== "insn") continue;
      const insn = row.insn;
      if (insn.address < funcStart || insn.address >= funcEnd) continue;

      const target = parseBranchTarget(insn.mnemonic, insn.opStr);
      if (target === null) continue;
      // Intra-function only
      if (target < funcStart || target >= funcEnd) continue;

      const fromY = vItem.start + rowHeight / 2;
      const span = Math.abs(target - insn.address);

      rawArrows.push({ fromAddr: insn.address, toAddr: target, fromY, span });
    }

    if (rawArrows.length === 0) return [];

    // Cap at 30 arrows
    const limited = rawArrows.slice(0, 30);

    // Assign lanes: sort by span (innermost = lane 0)
    limited.sort((a, b) => a.span - b.span);

    const result: Arrow[] = [];
    for (let i = 0; i < limited.length; i++) {
      const { fromAddr, toAddr, fromY } = limited[i];
      const isBackward = toAddr < fromAddr;
      const isCurrent = fromAddr === currentAddress || toAddr === currentAddress;

      let toY: number;
      let clipped: "none" | "top" | "bottom" = "none";

      if (addrToY.has(toAddr)) {
        toY = addrToY.get(toAddr)!;
      } else if (toAddr < fromAddr) {
        toY = minY - 5;
        clipped = "top";
      } else {
        toY = maxY + 5;
        clipped = "bottom";
      }

      result.push({
        fromY,
        toY,
        lane: i,
        isBackward,
        isCurrent,
        clipped,
      });
    }

    return result;
  }, [visibleItems, rows, funcMap, currentFuncAddr, currentAddress, rowHeight]);

  if (arrows.length === 0) return null;

  // Calculate SVG dimensions
  const allYs = arrows.flatMap((a) => [a.fromY, a.toY]);
  const svgMinY = Math.min(...allYs) - 10;
  const svgMaxY = Math.max(...allYs) + 10;
  const maxLane = Math.max(...arrows.map((a) => a.lane));
  const svgWidth = Math.min((maxLane + 1) * 8 + 8, 40);

  return (
    <svg
      className="absolute left-0 top-0 pointer-events-none"
      style={{
        width: `${svgWidth}px`,
        height: "100%",
        overflow: "visible",
      }}
    >
      {arrows.map((arrow, i) => {
        const x = svgWidth - (arrow.lane + 1) * 8;
        const { fromY, toY } = arrow;
        const color = arrow.isBackward ? "rgb(251 146 60)" : "rgb(52 211 153)"; // orange-400 / emerald-400
        const opacity = arrow.isCurrent ? 0.9 : 0.35;

        // Stepped path: from source → left → vertical → right → to target
        const path = `M ${svgWidth - 2} ${fromY} H ${x} V ${toY} H ${svgWidth - 2}`;

        return (
          <g key={i}>
            <path
              d={path}
              stroke={color}
              strokeWidth={arrow.isCurrent ? 1.5 : 1}
              fill="none"
              opacity={opacity}
            />
            {/* Arrowhead at target */}
            {arrow.clipped === "none" && (
              <polygon
                points={`${svgWidth - 2},${toY} ${svgWidth - 6},${toY - 3} ${svgWidth - 6},${toY + 3}`}
                fill={color}
                opacity={opacity}
              />
            )}
            {/* Direction indicator for clipped arrows */}
            {arrow.clipped === "top" && (
              <polygon
                points={`${x},${toY} ${x - 3},${toY + 4} ${x + 3},${toY + 4}`}
                fill={color}
                opacity={opacity}
              />
            )}
            {arrow.clipped === "bottom" && (
              <polygon
                points={`${x},${toY} ${x - 3},${toY - 4} ${x + 3},${toY - 4}`}
                fill={color}
                opacity={opacity}
              />
            )}
          </g>
        );
      })}
    </svg>
  );
}
