import { describe, it, expect } from 'vitest';
import type { BasicBlock } from '../../cfg';
import type { IRStmt, IRReg } from '../ir';
import { irReg, irConst, irBinary, canonReg } from '../ir';
import { computeRPO, computeDominators, computeDomFrontier, computeDomTree, buildSSA } from '../ssa';
import { ssaOptimize } from '../ssaopt';
import { destroySSA } from '../ssadestroy';

// ── Helpers ──

function makeBlock(id: number, succs: number[], preds: number[]): BasicBlock {
  return {
    id,
    startAddr: id * 0x100,
    endAddr: id * 0x100 + 0x10,
    insns: [],
    succs,
    preds,
  };
}

function findAssign(stmts: IRStmt[], regName: string): IRStmt | undefined {
  return stmts.find(s =>
    s.kind === 'assign' && s.dest.kind === 'reg' && canonReg(s.dest.name) === canonReg(regName),
  );
}

// ── Tests ──

describe('computeRPO', () => {
  it('computes RPO for linear CFG', () => {
    const blocks = [
      makeBlock(0, [1], []),
      makeBlock(1, [2], [0]),
      makeBlock(2, [], [1]),
    ];
    const rpo = computeRPO(blocks);
    expect(rpo).toEqual([0, 1, 2]);
  });

  it('computes RPO for diamond CFG', () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const rpo = computeRPO(blocks);
    expect(rpo[0]).toBe(0);
    expect(rpo[rpo.length - 1]).toBe(3);
  });
});

describe('computeDominators', () => {
  it('computes idom for diamond CFG', () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    expect(idom.get(0)).toBe(0); // entry dominates itself
    expect(idom.get(1)).toBe(0);
    expect(idom.get(2)).toBe(0);
    expect(idom.get(3)).toBe(0); // merge dominated by entry
  });

  it('computes idom for sequential CFG', () => {
    const blocks = [
      makeBlock(0, [1], []),
      makeBlock(1, [2], [0]),
      makeBlock(2, [], [1]),
    ];
    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    expect(idom.get(1)).toBe(0);
    expect(idom.get(2)).toBe(1);
  });
});

describe('computeDomFrontier', () => {
  it('computes DF for diamond CFG', () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    const df = computeDomFrontier(blocks, idom);
    // Blocks 1 and 2 have block 3 in their DF
    expect(df.get(1)!.has(3)).toBe(true);
    expect(df.get(2)!.has(3)).toBe(true);
    expect(df.get(0)!.size).toBe(0); // entry has no DF
  });
});

describe('buildSSA', () => {
  it('inserts phi at merge point for diamond CFG', () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    // Block 0: empty
    liftedBlocks.set(0, []);
    // Block 1: eax = 1
    liftedBlocks.set(1, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(1) },
    ]);
    // Block 2: eax = 2
    liftedBlocks.set(2, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(2) },
    ]);
    // Block 3: uses eax (return eax)
    liftedBlocks.set(3, [
      { kind: 'return', value: irReg('eax') },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);

    // Block 3 should have a phi for rax
    const phisAt3 = ctx.phis.get(3) ?? [];
    expect(phisAt3.length).toBe(1);
    expect(canonReg(phisAt3[0].dest.name)).toBe('rax');
    expect(phisAt3[0].operands.length).toBe(2);
  });

  it('does not insert phi when only one definition reaches', () => {
    const blocks = [
      makeBlock(0, [1], []),
      makeBlock(1, [], [0]),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(42) },
    ]);
    liftedBlocks.set(1, [
      { kind: 'return', value: irReg('eax') },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);

    // No phis needed
    const phisAt1 = ctx.phis.get(1) ?? [];
    expect(phisAt1.length).toBe(0);

    // The return in block 1 should reference eax with version 0
    const retStmt = liftedBlocks.get(1)![0];
    expect(retStmt.kind).toBe('return');
    if (retStmt.kind === 'return' && retStmt.value?.kind === 'reg') {
      expect(retStmt.value.version).toBe(0);
    }
  });

  it('handles loop CFG with phi at header', () => {
    const blocks = [
      makeBlock(0, [1], []),     // entry → header
      makeBlock(1, [2, 3], [0, 2]), // header (loop header, preds: entry + back-edge)
      makeBlock(2, [1], [1]),    // body → back to header
      makeBlock(3, [], [1]),     // exit
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: 'assign', dest: irReg('ecx'), src: irConst(0) },
    ]);
    liftedBlocks.set(1, [
      { kind: 'return', value: irReg('ecx') },
    ]);
    liftedBlocks.set(2, [
      { kind: 'assign', dest: irReg('ecx'), src: irBinary('+', irReg('ecx'), irConst(1)) },
    ]);
    liftedBlocks.set(3, []);

    const ctx = buildSSA(blocks, liftedBlocks);

    // Block 1 (header) should have a phi for rcx
    const phisAt1 = ctx.phis.get(1) ?? [];
    expect(phisAt1.length).toBeGreaterThanOrEqual(1);
    const rcxPhi = phisAt1.find(p => canonReg(p.dest.name) === 'rcx');
    expect(rcxPhi).toBeDefined();
  });
});

describe('ssaOptimize', () => {
  it('eliminates dead definitions', () => {
    const blocks = [
      makeBlock(0, [], []),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(1) },
      { kind: 'assign', dest: irReg('ebx'), src: irConst(2) },
      { kind: 'return', value: irReg('eax') },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    // ebx assignment should be eliminated (unused)
    const stmts = ctx.liftedBlocks.get(0)!;
    const ebxAssign = stmts.find(s =>
      s.kind === 'assign' && s.dest.kind === 'reg' && canonReg(s.dest.name) === 'rbx',
    );
    expect(ebxAssign).toBeUndefined();
  });

  it('propagates constants through SSA', () => {
    const blocks = [
      makeBlock(0, [1], []),
      makeBlock(1, [], [0]),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(42) },
    ]);
    liftedBlocks.set(1, [
      { kind: 'return', value: irReg('eax') },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    // The return value should be constant 42 (propagated from block 0)
    const retStmt = ctx.liftedBlocks.get(1)!.find(s => s.kind === 'return');
    expect(retStmt).toBeDefined();
    if (retStmt?.kind === 'return' && retStmt.value) {
      expect(retStmt.value.kind).toBe('const');
      if (retStmt.value.kind === 'const') {
        expect(retStmt.value.value).toBe(42);
      }
    }
  });
});

describe('destroySSA', () => {
  it('strips version numbers', () => {
    const blocks = [
      makeBlock(0, [1], []),
      makeBlock(1, [], [0]),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(5) },
    ]);
    liftedBlocks.set(1, [
      { kind: 'return', value: irReg('eax') },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);
    destroySSA(ctx);

    // All registers should have no version
    for (const [, stmts] of ctx.liftedBlocks) {
      for (const s of stmts) {
        if (s.kind === 'assign' && s.dest.kind === 'reg') {
          expect(s.dest.version).toBeUndefined();
        }
        if (s.kind === 'return' && s.value?.kind === 'reg') {
          expect(s.value.version).toBeUndefined();
        }
      }
    }
  });

  it('round-trips diamond CFG correctly', () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, []);
    liftedBlocks.set(1, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(1) },
    ]);
    liftedBlocks.set(2, [
      { kind: 'assign', dest: irReg('eax'), src: irConst(2) },
    ]);
    liftedBlocks.set(3, [
      { kind: 'return', value: irReg('eax') },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);
    destroySSA(ctx);

    // All phis should be cleared
    for (const [, phis] of ctx.phis) {
      expect(phis.length).toBe(0);
    }

    // Block 3 should still have a return
    const retStmt = ctx.liftedBlocks.get(3)!.find(s => s.kind === 'return');
    expect(retStmt).toBeDefined();
  });
});
