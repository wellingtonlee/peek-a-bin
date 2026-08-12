import dagre from "@dagrejs/dagre";
import { classifyArm64Branch } from "./arm64Operands";
import { computeDominators, computeDomTree, computeRPO, detectNaturalLoops } from "./decompile/ssa";
import { getFuncInsns } from "./funcInsns";
import type { DisasmFunction, Instruction, Xref } from "./types";

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
  type: "fallthrough" | "jump" | "branch";
}

export function buildCFG(
  func: DisasmFunction,
  instructions: Instruction[],
  xrefMap: Map<number, Xref[]>,
  jumpTables?: Map<number, number[]>,
  funcInsnMap?: Map<number, Instruction[]>,
): BasicBlock[] {
  const endAddr = func.address + func.size;

  // Collect function instructions
  const funcInsns = getFuncInsns(func, instructions, funcInsnMap);

  if (funcInsns.length === 0) return [];

  // Determine block leaders (addresses where new blocks start)
  const leaders = new Set<number>();
  leaders.add(func.address); // entry point

  // Xref targets within this function are leaders.
  // Indexed loop: the "instruction after this one" lookups below used
  // `funcInsns.indexOf(insn)` on the array being iterated, which is O(n) per
  // branch instruction.
  for (let i = 0; i < funcInsns.length; i++) {
    const insn = funcInsns[i];
    const mn = insn.mnemonic;
    if (mn === "call") continue; // calls don't split blocks

    if (mn === "jmp" || mn.startsWith("j")) {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= func.address && target < endAddr) {
          leaders.add(target);
        }
      }
      // Instruction after an unconditional branch/conditional branch is a leader
      if (i + 1 < funcInsns.length) {
        leaders.add(funcInsns[i + 1].address);
      }
    } else {
      // A64. Reached only for mnemonics the x86 arm above did not claim: the
      // two grammars share no branch spelling (see `arm64Operands.ts`), so this
      // cannot change any x86 answer. `bl`/`blr` classify as "call" and are
      // skipped for the same reason x86 `call` is — control returns.
      const a64 = classifyArm64Branch(mn, insn.opStr);
      if (a64 && a64.kind !== "call") {
        if (a64.target !== null && a64.target >= func.address && a64.target < endAddr) {
          leaders.add(a64.target);
        }
        // Everything after a jump, a conditional branch or a return starts a
        // new block — including after an indirect `br`, whose target this
        // module deliberately does not guess.
        if (a64.kind !== "return" && i + 1 < funcInsns.length) {
          leaders.add(funcInsns[i + 1].address);
        }
      }
    }

    if (mn === "ret" || mn === "retn") {
      if (i + 1 < funcInsns.length) {
        leaders.add(funcInsns[i + 1].address);
      }
    }
  }

  // Add jump table targets as leaders
  if (jumpTables) {
    for (let i = 0; i < funcInsns.length; i++) {
      const insn = funcInsns[i];
      const targets = jumpTables.get(insn.address);
      if (targets) {
        for (const target of targets) {
          if (target >= func.address && target < endAddr) {
            leaders.add(target);
          }
        }
        // Instruction after indirect jmp is a leader
        if (i + 1 < funcInsns.length) {
          leaders.add(funcInsns[i + 1].address);
        }
      }
    }
  }

  // Also add xref targets as leaders
  for (const insn of funcInsns) {
    const xrefs = xrefMap.get(insn.address);
    if (xrefs?.some((x) => x.type === "branch" || x.type === "jmp")) {
      leaders.add(insn.address);
    }
  }

  // Sort leaders
  const sortedLeaders = Array.from(leaders).sort((a, b) => a - b);

  // Build blocks
  const blocks: BasicBlock[] = [];
  const addrToBlock = new Map<number, number>(); // leader addr → block id

  // Bucket each instruction into its leader's range with a binary search over
  // the leaders, instead of rescanning every instruction once per leader.
  // Leaders tile [func.address, endAddr) and every instruction in `funcInsns`
  // lies in that window, so each lands in exactly one bucket — the same one the
  // per-leader rescan picked, and in the same order.
  const buckets: Instruction[][] = sortedLeaders.map(() => []);
  for (const insn of funcInsns) {
    let lo = 0;
    let hi = sortedLeaders.length - 1;
    let owner = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (sortedLeaders[mid] <= insn.address) {
        owner = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    if (owner >= 0) buckets[owner].push(insn);
  }

  let blockId = 0;
  for (let li = 0; li < sortedLeaders.length; li++) {
    const leaderAddr = sortedLeaders[li];
    const blockInsns = buckets[li];

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

    if (mn === "ret" || mn === "retn") {
      // No successors
      continue;
    }

    if (mn === "jmp") {
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

    if (mn.startsWith("j")) {
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

    // A64 terminators. Unreachable for x86 — no x86 mnemonic classifies.
    const a64 = classifyArm64Branch(mn, lastInsn.opStr);
    if (a64 && a64.kind !== "call") {
      // `ret`/`retaa`/`retab`: no successors, same as the x86 arm above.
      if (a64.kind === "return") continue;

      // An indirect `br x8` is a switch dispatch or a tail call through a
      // register. Where the dispatch table was recovered (`arm64.ts`'s
      // `findArm64JumpTables`, peek-a-bin-8ij) its case bodies are the block's
      // successors; where it was not, this code will not invent one. The block
      // then simply has no successor, which the graph view draws as a dead end
      // — an edge to the wrong block would be indistinguishable from a real one.
      if (a64.target !== null) {
        const targetBlockId = addrToBlock.get(a64.target);
        if (targetBlockId !== undefined) {
          block.succs.push(targetBlockId);
          blocks[targetBlockId].preds.push(block.id);
        }
      } else if (jumpTables) {
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

      // A conditional branch also falls through; an unconditional `b` does not.
      if (a64.kind === "cond") {
        const fallthroughBlockId = addrToBlock.get(block.endAddr);
        if (fallthroughBlockId !== undefined) {
          block.succs.push(fallthroughBlockId);
          blocks[fallthroughBlockId].preds.push(block.id);
        }
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
  /** `startAddr` of the loop header block — the block every iteration re-enters. */
  headerAddr: number;
  /**
   * `endAddr` of the latch: the back-edge source block furthest into the
   * function. A loop with several back edges (`continue`s) reports only this
   * one, which is the bottom test of a do-while when there is one.
   */
  backEdgeFromAddr: number;
  /** How many *other* loops of this function contain this header. */
  depth: number;
  /** Addresses of every instruction in every block of the loop body. */
  bodyAddrs: Set<number>;
}

/**
 * Find the natural loops of a CFG.
 *
 * A back edge is an edge `u → v` where **v dominates u**. This used to be
 * approximated by BFS layers from the entry ("succLayer <= blockLayer"), which
 * is wrong for the most common shape in compiled code: in a triangle
 * (`cond → then → merge`, an `if` with no `else`) BFS puts both `then` and
 * `merge` on layer 1, so `then → merge` looked like a back edge and the merge
 * block became a loop header. A diamond is unaffected (its merge lands on
 * layer 2), which is why hand-written fixtures never caught it. Measured
 * against a dominator solver on three real MSVC binaries, ~86% of the loops
 * reported that way did not exist (peek-a-bin-lrs).
 *
 * The dominance-based detector already lived in `decompile/ssa.ts`, where the
 * SSA optimiser was using it; this reuses it rather than keeping a second,
 * disagreeing notion of "loop" in the tree. `ssa.ts` only *type*-imports
 * `BasicBlock` from here, so there is no runtime import cycle.
 */
export function detectLoops(blocks: BasicBlock[]): Loop[] {
  if (blocks.length === 0) return [];

  const blockById = new Map<number, BasicBlock>();
  for (const b of blocks) blockById.set(b.id, b);

  const idom = computeDominators(blocks, computeRPO(blocks));
  const natural = detectNaturalLoops(blocks, idom, computeDomTree(idom));

  const loops: Loop[] = [];

  for (const [headerId, bodyIds] of natural) {
    const header = blockById.get(headerId);
    if (!header) continue;

    const bodyAddrs = new Set<number>();
    // Every block that closes the loop is a back-edge source; the latch is the
    // last of them, which is where a bottom-tested loop keeps its condition.
    let latchEnd = header.endAddr;
    for (const id of bodyIds) {
      const b = blockById.get(id);
      if (!b) continue;
      for (const insn of b.insns) bodyAddrs.add(insn.address);
      if (b.succs.includes(headerId) && b.endAddr > latchEnd) latchEnd = b.endAddr;
    }

    loops.push({
      headerAddr: header.startAddr,
      backEdgeFromAddr: latchEnd,
      depth: 0,
      bodyAddrs,
    });
  }

  loops.sort((a, b) => a.headerAddr - b.headerAddr);

  // Nesting depth by containment in the natural-loop bodies, rather than by
  // overlap of [header, latch] address ranges: a loop body need not be
  // contiguous in memory, and two sibling loops' ranges can overlap without
  // either containing the other. `bodyAddrs` holds instruction addresses and a
  // header block always starts at one of its own instructions, so testing the
  // header address against another loop's body is exact.
  for (const loop of loops) {
    let depth = 0;
    for (const other of loops) {
      if (other !== loop && other.bodyAddrs.has(loop.headerAddr)) depth++;
    }
    loop.depth = depth;
  }

  return loops;
}

export function getCfgLayout(fontSize = 12) {
  const scale = fontSize / 12;
  return {
    BLOCK_WIDTH: Math.round(320 * scale),
    BLOCK_MIN_HEIGHT: Math.round(50 * scale),
    INSN_HEIGHT: Math.round(14 * scale),
    V_SPACING: 40,
    H_SPACING: 30,
    BLOCK_HEADER: Math.round(22 * scale),
  };
}

export const CFG_LAYOUT = getCfgLayout(12);

export function layoutCFG(
  blocks: BasicBlock[],
  fontSize = 12,
): { blocks: LayoutBlock[]; edges: CFGEdge[] } {
  if (blocks.length === 0) return { blocks: [], edges: [] };

  const { BLOCK_WIDTH, BLOCK_MIN_HEIGHT, INSN_HEIGHT, V_SPACING, H_SPACING, BLOCK_HEADER } =
    getCfgLayout(fontSize);

  const g = new dagre.graphlib.Graph();
  g.setGraph({ rankdir: "TB", nodesep: H_SPACING, ranksep: V_SPACING, edgesep: 10 });
  g.setDefaultEdgeLabel(() => ({}));

  // Add nodes
  for (const block of blocks) {
    const h = Math.max(BLOCK_MIN_HEIGHT, block.insns.length * INSN_HEIGHT + BLOCK_HEADER + 4);
    g.setNode(String(block.id), { width: BLOCK_WIDTH, height: h });
  }

  // Build edges — classify and add to dagre with weights
  const edges: CFGEdge[] = [];
  for (const block of blocks) {
    const lastInsn = block.insns[block.insns.length - 1];
    const mn = lastInsn.mnemonic;

    for (const succId of block.succs) {
      let type: CFGEdge["type"];
      if (mn === "jmp") {
        type = "jump";
      } else if (mn.startsWith("j") && mn !== "jmp") {
        const m = lastInsn.opStr.match(/^0x([0-9a-fA-F]+)$/);
        if (m && parseInt(m[1], 16) === blocks[succId].startAddr) {
          type = "branch";
        } else {
          type = "fallthrough";
        }
      } else {
        // A64, by the same rule: an edge is "branch" when it goes where the
        // conditional branch points, and "fallthrough" when it is the other
        // one. `bl`/`blr` classify as calls and keep the fallthrough default.
        const a64 = classifyArm64Branch(mn, lastInsn.opStr);
        if (a64?.kind === "jump") {
          type = "jump";
        } else if (a64?.kind === "cond" && a64.target === blocks[succId].startAddr) {
          type = "branch";
        } else {
          type = "fallthrough";
        }
      }

      // Fallthrough edges get higher weight to stay straight
      const weight = type === "fallthrough" ? 10 : 1;
      g.setEdge(String(block.id), String(succId), { weight });
      edges.push({ from: block.id, to: succId, type });
    }
  }

  dagre.layout(g);

  // Read back positions (dagre gives center coords, convert to top-left)
  const layoutBlocks: LayoutBlock[] = blocks.map((block) => {
    const node = g.node(String(block.id));
    const h = Math.max(BLOCK_MIN_HEIGHT, block.insns.length * INSN_HEIGHT + BLOCK_HEADER + 4);
    return { ...block, x: node.x - BLOCK_WIDTH / 2, y: node.y - h / 2, w: BLOCK_WIDTH, h };
  });

  return { blocks: layoutBlocks, edges };
}
