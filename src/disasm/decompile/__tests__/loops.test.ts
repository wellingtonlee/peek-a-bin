import { describe, it, expect } from 'vitest';
import { detectNaturalLoops, computeRPO, computeDominators, computeDomTree } from '../ssa';
import type { BasicBlock } from '../../cfg';

function makeBlock(id: number, succs: number[], preds: number[]): BasicBlock {
  return {
    id,
    startAddr: id * 0x10,
    endAddr: id * 0x10 + 0x0F,
    insns: [],
    succs,
    preds,
  };
}

describe('Natural Loop Detection', () => {
  it('should detect a simple while loop', () => {
    // Block 0 → Block 1 (header) → Block 2 (body) → Block 1 (back edge)
    //                             → Block 3 (exit)
    const blocks: BasicBlock[] = [
      makeBlock(0, [1], []),        // entry
      makeBlock(1, [2, 3], [0, 2]), // loop header
      makeBlock(2, [1], [1]),       // loop body (back edge to 1)
      makeBlock(3, [], [1]),        // exit
    ];

    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    const domTree = computeDomTree(idom);
    const loops = detectNaturalLoops(blocks, idom, domTree);

    expect(loops.size).toBe(1);
    expect(loops.has(1)).toBe(true);
    const body = loops.get(1)!;
    expect(body.has(1)).toBe(true); // header in body
    expect(body.has(2)).toBe(true); // body block in body
    expect(body.has(0)).toBe(false); // entry not in loop
    expect(body.has(3)).toBe(false); // exit not in loop
  });

  it('should detect nested loops', () => {
    // 0 → 1 (outer header) → 2 (inner header) → 3 (inner body) → 2
    //                                          → 4 → 1 (outer back edge)
    //     1 → 5 (exit)
    const blocks: BasicBlock[] = [
      makeBlock(0, [1], []),
      makeBlock(1, [2, 5], [0, 4]),
      makeBlock(2, [3, 4], [1, 3]),
      makeBlock(3, [2], [2]),
      makeBlock(4, [1], [2]),
      makeBlock(5, [], [1]),
    ];

    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    const domTree = computeDomTree(idom);
    const loops = detectNaturalLoops(blocks, idom, domTree);

    expect(loops.size).toBe(2);
    expect(loops.has(1)).toBe(true); // outer
    expect(loops.has(2)).toBe(true); // inner
  });

  it('should return empty for acyclic CFG', () => {
    const blocks: BasicBlock[] = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];

    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    const domTree = computeDomTree(idom);
    const loops = detectNaturalLoops(blocks, idom, domTree);

    expect(loops.size).toBe(0);
  });
});
