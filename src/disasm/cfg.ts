import type { Instruction, DisasmFunction, Xref } from './types';

export interface BasicBlock {
  id: number;
  startAddr: number;
  endAddr: number;
  insns: Instruction[];
  succs: number[];
  preds: number[];
}

export interface LayoutBlock extends BasicBlock {
  x: number;
  y: number;
  w: number;
  h: number;
}

export interface CFGEdge {
  from: number;
  to: number;
  type: 'fallthrough' | 'jump' | 'branch';
}

export function buildCFG(
  func: DisasmFunction,
  instructions: Instruction[],
  xrefMap: Map<number, Xref[]>,
  jumpTables?: Map<number, number[]>,
): BasicBlock[] {
  const endAddr = func.address + func.size;

  // Collect function instructions
  const funcInsns: Instruction[] = [];
  for (const insn of instructions) {
    if (insn.address >= func.address && insn.address < endAddr) {
      funcInsns.push(insn);
    }
    if (insn.address >= endAddr) break;
  }

  if (funcInsns.length === 0) return [];

  // Determine block leaders (addresses where new blocks start)
  const leaders = new Set<number>();
  leaders.add(func.address); // entry point

  // Xref targets within this function are leaders
  for (const insn of funcInsns) {
    const mn = insn.mnemonic;
    if (mn === 'call') continue; // calls don't split blocks

    if (mn === 'jmp' || mn.startsWith('j')) {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= func.address && target < endAddr) {
          leaders.add(target);
        }
      }
      // Instruction after an unconditional branch/conditional branch is a leader
      const idx = funcInsns.indexOf(insn);
      if (idx >= 0 && idx + 1 < funcInsns.length) {
        leaders.add(funcInsns[idx + 1].address);
      }
    }

    if (mn === 'ret' || mn === 'retn') {
      const idx = funcInsns.indexOf(insn);
      if (idx >= 0 && idx + 1 < funcInsns.length) {
        leaders.add(funcInsns[idx + 1].address);
      }
    }
  }

  // Add jump table targets as leaders
  if (jumpTables) {
    for (const insn of funcInsns) {
      const targets = jumpTables.get(insn.address);
      if (targets) {
        for (const target of targets) {
          if (target >= func.address && target < endAddr) {
            leaders.add(target);
          }
        }
        // Instruction after indirect jmp is a leader
        const idx = funcInsns.indexOf(insn);
        if (idx >= 0 && idx + 1 < funcInsns.length) {
          leaders.add(funcInsns[idx + 1].address);
        }
      }
    }
  }

  // Also add xref targets as leaders
  for (const insn of funcInsns) {
    const xrefs = xrefMap.get(insn.address);
    if (xrefs && xrefs.some(x => x.type === 'branch' || x.type === 'jmp')) {
      leaders.add(insn.address);
    }
  }

  // Sort leaders
  const sortedLeaders = Array.from(leaders).sort((a, b) => a - b);

  // Build blocks
  const blocks: BasicBlock[] = [];
  const addrToBlock = new Map<number, number>(); // leader addr → block id

  let blockId = 0;
  for (let li = 0; li < sortedLeaders.length; li++) {
    const leaderAddr = sortedLeaders[li];
    const nextLeaderAddr = li + 1 < sortedLeaders.length ? sortedLeaders[li + 1] : endAddr;

    const blockInsns: Instruction[] = [];
    for (const insn of funcInsns) {
      if (insn.address >= leaderAddr && insn.address < nextLeaderAddr) {
        blockInsns.push(insn);
      }
    }

    if (blockInsns.length === 0) continue;

    const block: BasicBlock = {
      id: blockId,
      startAddr: blockInsns[0].address,
      endAddr: blockInsns[blockInsns.length - 1].address + blockInsns[blockInsns.length - 1].size,
      insns: blockInsns,
      succs: [],
      preds: [],
    };
    addrToBlock.set(leaderAddr, blockId);
    blocks.push(block);
    blockId++;
  }

  // Compute edges
  for (const block of blocks) {
    const lastInsn = block.insns[block.insns.length - 1];
    const mn = lastInsn.mnemonic;

    if (mn === 'ret' || mn === 'retn') {
      // No successors
      continue;
    }

    if (mn === 'jmp') {
      const m = lastInsn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        const targetBlockId = addrToBlock.get(target);
        if (targetBlockId !== undefined) {
          block.succs.push(targetBlockId);
          blocks[targetBlockId].preds.push(block.id);
        }
      } else if (jumpTables) {
        // Indirect jmp — check for jump table targets
        const targets = jumpTables.get(lastInsn.address);
        if (targets) {
          const addedSuccs = new Set<number>();
          for (const target of targets) {
            const targetBlockId = addrToBlock.get(target);
            if (targetBlockId !== undefined && !addedSuccs.has(targetBlockId)) {
              addedSuccs.add(targetBlockId);
              block.succs.push(targetBlockId);
              blocks[targetBlockId].preds.push(block.id);
            }
          }
        }
      }
      continue;
    }

    if (mn.startsWith('j')) {
      // Conditional jump: two successors
      const m = lastInsn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        const targetBlockId = addrToBlock.get(target);
        if (targetBlockId !== undefined) {
          block.succs.push(targetBlockId);
          blocks[targetBlockId].preds.push(block.id);
        }
      }
      // Fallthrough
      const fallthroughBlockId = addrToBlock.get(block.endAddr);
      if (fallthroughBlockId !== undefined) {
        block.succs.push(fallthroughBlockId);
        blocks[fallthroughBlockId].preds.push(block.id);
      }
      continue;
    }

    // Default: fallthrough
    const fallthroughBlockId = addrToBlock.get(block.endAddr);
    if (fallthroughBlockId !== undefined) {
      block.succs.push(fallthroughBlockId);
      blocks[fallthroughBlockId].preds.push(block.id);
    }
  }

  return blocks;
}

export interface Loop {
  headerAddr: number;
  backEdgeFromAddr: number;
  depth: number;
  bodyAddrs: Set<number>;
}

export function detectLoops(blocks: BasicBlock[]): Loop[] {
  if (blocks.length === 0) return [];

  // BFS layer assignment from entry block (id 0)
  const layers = new Map<number, number>();
  const queue: number[] = [0];
  layers.set(0, 0);
  const visited = new Set<number>();

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const layer = layers.get(id)!;

    for (const succ of blocks[id].succs) {
      if (!layers.has(succ)) {
        layers.set(succ, layer + 1);
      }
      if (!visited.has(succ)) {
        queue.push(succ);
      }
    }
  }

  // Build block ID lookup
  const blockById = new Map<number, typeof blocks[0]>();
  for (const b of blocks) blockById.set(b.id, b);

  // Detect back-edges: successor's layer <= current block's layer
  const loops: Loop[] = [];
  const headerAddrs = new Set<number>();

  for (const block of blocks) {
    const blockLayer = layers.get(block.id) ?? 0;
    for (const succId of block.succs) {
      const succLayer = layers.get(succId) ?? 0;
      if (succLayer <= blockLayer) {
        // Back-edge found: successor is the loop header
        const header = blocks[succId];
        if (header && !headerAddrs.has(header.startAddr)) {
          headerAddrs.add(header.startAddr);

          // Collect loop body: all blocks reachable from header that can reach the back-edge source
          // Simple approach: walk successors from header, stop at back-edge source, collect instruction addresses
          const bodyAddrs = new Set<number>();
          const bodyVisited = new Set<number>();
          const bodyQueue = [header.id];
          while (bodyQueue.length > 0) {
            const bid = bodyQueue.shift()!;
            if (bodyVisited.has(bid)) continue;
            bodyVisited.add(bid);
            const b = blockById.get(bid);
            if (!b) continue;
            // Add all instruction addresses in this block
            for (const insn of b.insns) bodyAddrs.add(insn.address);
            // Don't follow successors past the back-edge source block
            if (bid === block.id) continue;
            for (const sid of b.succs) {
              if (!bodyVisited.has(sid)) {
                const sLayer = layers.get(sid) ?? 0;
                // Only follow blocks within the loop range (between header and back-edge)
                if (sLayer >= succLayer && sLayer <= blockLayer + 1) {
                  bodyQueue.push(sid);
                }
              }
            }
          }

          loops.push({
            headerAddr: header.startAddr,
            backEdgeFromAddr: block.endAddr,
            depth: 0,
            bodyAddrs,
          });
        }
      }
    }
  }

  // Sort by address
  loops.sort((a, b) => a.headerAddr - b.headerAddr);

  // Compute nesting depth: a loop header inside another loop's range gets depth++
  // Approximate loop range as [headerAddr, backEdgeFromAddr]
  for (let i = 0; i < loops.length; i++) {
    let depth = 0;
    for (let j = 0; j < loops.length; j++) {
      if (i === j) continue;
      if (loops[i].headerAddr >= loops[j].headerAddr &&
          loops[i].headerAddr < loops[j].backEdgeFromAddr) {
        depth++;
      }
    }
    loops[i].depth = depth;
  }

  return loops;
}

export const CFG_LAYOUT = {
  BLOCK_WIDTH: 320,
  BLOCK_MIN_HEIGHT: 50,
  INSN_HEIGHT: 16,
  V_SPACING: 80,
  H_SPACING: 50,
  BLOCK_HEADER: 22,
} as const;

export function layoutCFG(blocks: BasicBlock[]): { blocks: LayoutBlock[]; edges: CFGEdge[] } {
  if (blocks.length === 0) return { blocks: [], edges: [] };

  // Topological layer assignment via BFS from entry
  const layers = new Map<number, number>();
  const queue: number[] = [0];
  layers.set(0, 0);
  const visited = new Set<number>();

  while (queue.length > 0) {
    const id = queue.shift()!;
    if (visited.has(id)) continue;
    visited.add(id);
    const layer = layers.get(id)!;

    for (const succ of blocks[id].succs) {
      const existingLayer = layers.get(succ);
      if (existingLayer === undefined || existingLayer < layer + 1) {
        layers.set(succ, layer + 1);
      }
      if (!visited.has(succ)) {
        queue.push(succ);
      }
    }
  }

  // Assign unvisited blocks
  for (const block of blocks) {
    if (!layers.has(block.id)) {
      layers.set(block.id, 0);
    }
  }

  // Group blocks by layer
  const layerGroups = new Map<number, number[]>();
  for (const block of blocks) {
    const layer = layers.get(block.id)!;
    if (!layerGroups.has(layer)) layerGroups.set(layer, []);
    layerGroups.get(layer)!.push(block.id);
  }

  const { BLOCK_WIDTH, BLOCK_MIN_HEIGHT, INSN_HEIGHT, V_SPACING, H_SPACING, BLOCK_HEADER } = CFG_LAYOUT;

  const layoutBlocks: LayoutBlock[] = [];

  const sortedLayers = Array.from(layerGroups.keys()).sort((a, b) => a - b);
  let y = 20;

  for (const layer of sortedLayers) {
    const group = layerGroups.get(layer)!;
    const totalWidth = group.length * BLOCK_WIDTH + (group.length - 1) * H_SPACING;
    let x = -totalWidth / 2;

    let maxHeight = 0;
    for (const blockId of group) {
      const block = blocks[blockId];
      const h = Math.max(BLOCK_MIN_HEIGHT, block.insns.length * INSN_HEIGHT + BLOCK_HEADER + 4);
      maxHeight = Math.max(maxHeight, h);

      layoutBlocks.push({
        ...block,
        x,
        y,
        w: BLOCK_WIDTH,
        h,
      });
      x += BLOCK_WIDTH + H_SPACING;
    }

    y += maxHeight + V_SPACING;
  }

  // Build edges
  const edges: CFGEdge[] = [];
  for (const block of blocks) {
    const lastInsn = block.insns[block.insns.length - 1];
    const mn = lastInsn.mnemonic;

    for (const succId of block.succs) {
      let type: CFGEdge['type'];
      if (mn === 'jmp') {
        type = 'jump';
      } else if (mn.startsWith('j') && mn !== 'jmp') {
        // Check if this is the branch target or fallthrough
        const m = lastInsn.opStr.match(/^0x([0-9a-fA-F]+)$/);
        if (m && parseInt(m[1], 16) === blocks[succId].startAddr) {
          type = 'branch';
        } else {
          type = 'fallthrough';
        }
      } else {
        type = 'fallthrough';
      }
      edges.push({ from: block.id, to: succId, type });
    }
  }

  return { blocks: layoutBlocks, edges };
}
