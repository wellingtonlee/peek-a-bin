import { describe, it, expect } from 'vitest';
import { buildCFG, detectLoops, type BasicBlock } from '../cfg';
import type { Instruction, DisasmFunction, Xref } from '../types';

const START = 0x401000;

type Spec = [mnemonic: string, opStr: string, size: number];

/** Lay out instructions back-to-back starting at `start`. */
function layout(start: number, specs: Spec[]): Instruction[] {
  let addr = start;
  return specs.map(([mnemonic, opStr, size]) => {
    const insn: Instruction = { address: addr, mnemonic, opStr, size, bytes: new Uint8Array(size) };
    addr += size;
    return insn;
  });
}

function totalSize(insns: Instruction[]): number {
  return insns.reduce((n, i) => n + i.size, 0);
}

function cfg(
  specs: Spec[],
  opts: { xrefs?: Map<number, Xref[]>; jumpTables?: Map<number, number[]>; funcSize?: number } = {},
): { blocks: BasicBlock[]; insns: Instruction[] } {
  const insns = layout(START, specs);
  const func: DisasmFunction = {
    name: 'f',
    address: START,
    size: opts.funcSize ?? totalSize(insns),
  };
  const blocks = buildCFG(func, insns, opts.xrefs ?? new Map(), opts.jumpTables);
  return { blocks, insns };
}

/** succs/preds must agree in both directions for every edge. */
function expectEdgesConsistent(blocks: BasicBlock[]) {
  for (const b of blocks) {
    for (const s of b.succs) {
      expect(blocks[s], `succ ${s} of block ${b.id} exists`).toBeDefined();
      expect(blocks[s].preds, `block ${s}.preds contains ${b.id}`).toContain(b.id);
    }
    for (const p of b.preds) {
      expect(blocks[p].succs, `block ${p}.succs contains ${b.id}`).toContain(b.id);
    }
  }
  // Block ids must equal their array index — the edge code indexes blocks[] by id.
  blocks.forEach((b, i) => expect(b.id).toBe(i));
}

describe('buildCFG', () => {
  it('returns no blocks when the function range holds no instructions', () => {
    const insns = layout(START, [['ret', '', 1]]);
    expect(buildCFG({ name: 'f', address: 0x500000, size: 0x10 }, insns, new Map())).toEqual([]);
  });

  it('makes a single block from straight-line code', () => {
    const { blocks } = cfg([
      ['push', 'rbp', 1],
      ['mov', 'rbp, rsp', 3],
      ['xor', 'eax, eax', 2],
      ['pop', 'rbp', 1],
      ['ret', '', 1],
    ]);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].startAddr).toBe(START);
    expect(blocks[0].endAddr).toBe(START + 8);
    expect(blocks[0].insns).toHaveLength(5);
    expect(blocks[0].succs).toEqual([]);
    expect(blocks[0].preds).toEqual([]);
  });

  it('does not split a block at a call', () => {
    const { blocks } = cfg([
      ['xor', 'ecx, ecx', 2],
      ['call', '0x401500', 5],
      ['ret', '', 1],
    ]);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].insns).toHaveLength(3);
  });

  it('splits a conditional branch into branch-target and fallthrough successors', () => {
    //   0x401000 cmp eax, 0
    //   0x401003 je  0x40100a      → taken: block 2, fallthrough: block 1
    //   0x401005 mov eax, 1
    //   0x40100a ret
    const { blocks } = cfg([
      ['cmp', 'eax, 0', 3],
      ['je', '0x40100a', 2],
      ['mov', 'eax, 1', 5],
      ['ret', '', 1],
    ]);
    expect(blocks.map(b => b.startAddr)).toEqual([0x401000, 0x401005, 0x40100a]);
    // Taken edge is recorded before the fallthrough edge.
    expect(blocks[0].succs).toEqual([2, 1]);
    expect(blocks[1].succs).toEqual([2]);
    expect(blocks[2].succs).toEqual([]);
    expect(blocks[2].preds).toEqual([0, 1]);
    expectEdgesConsistent(blocks);
  });

  it('gives a conditional branch only a fallthrough edge when the target is outside the function', () => {
    const { blocks } = cfg([
      ['cmp', 'eax, 0', 3],
      ['je', '0x402000', 2], // outside [0x401000, 0x401006)
      ['ret', '', 1],
    ]);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].succs).toEqual([1]);
    expectEdgesConsistent(blocks);
  });

  it('follows an unconditional jmp and leaves the skipped block unreachable', () => {
    const { blocks } = cfg([
      ['jmp', '0x401006', 2], // 0x401000
      ['mov', 'eax, 1', 4], // 0x401002 — never entered
      ['ret', '', 1], // 0x401006
    ]);
    expect(blocks.map(b => b.startAddr)).toEqual([0x401000, 0x401002, 0x401006]);
    expect(blocks[0].succs).toEqual([2]);
    expect(blocks[1].preds).toEqual([]); // no fallthrough into a block after a jmp
    expect(blocks[1].succs).toEqual([2]);
    expectEdgesConsistent(blocks);
  });

  it('leaves a tail-call jmp outside the function with no successors', () => {
    const { blocks } = cfg([
      ['mov', 'rcx, rbx', 3],
      ['jmp', '0x408000', 5],
    ]);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].succs).toEqual([]);
  });

  it('leaves an unresolved indirect jmp with no successors', () => {
    const { blocks } = cfg([
      ['mov', 'rax, rbx', 3],
      ['jmp', 'rax', 2],
    ]);
    expect(blocks[0].succs).toEqual([]);
  });

  it('records a back edge for a loop', () => {
    //   0x401000 xor eax, eax
    //   0x401002 inc eax          ← loop header
    //   0x401004 cmp eax, 5
    //   0x401007 jl  0x401002
    //   0x401009 ret
    const { blocks } = cfg([
      ['xor', 'eax, eax', 2],
      ['inc', 'eax', 2],
      ['cmp', 'eax, 5', 3],
      ['jl', '0x401002', 2],
      ['ret', '', 1],
    ]);
    expect(blocks.map(b => b.startAddr)).toEqual([0x401000, 0x401002, 0x401009]);
    expect(blocks[0].succs).toEqual([1]);
    expect(blocks[1].succs).toEqual([1, 2]); // back edge to itself, then exit
    expect(blocks[1].preds).toEqual([0, 1]);
    expectEdgesConsistent(blocks);

    const loops = detectLoops(blocks);
    expect(loops).toHaveLength(1);
    expect(loops[0].headerAddr).toBe(0x401002);
  });

  it('records a back edge that spans several blocks', () => {
    //   0x401000 mov ecx, 0
    //   0x401004 cmp ecx, 8       ← header
    //   0x401007 jge 0x401011
    //   0x401009 inc ecx          ← body
    //   0x40100b jmp 0x401004
    //   0x401011 ret
    const { blocks } = cfg([
      ['mov', 'ecx, 0', 4],
      ['cmp', 'ecx, 8', 3],
      ['jge', '0x401011', 2],
      ['inc', 'ecx', 2],
      ['jmp', '0x401004', 6],
      ['ret', '', 1],
    ]);
    expect(blocks.map(b => b.startAddr)).toEqual([0x401000, 0x401004, 0x401009, 0x401011]);
    expect(blocks[1].succs).toEqual([3, 2]);
    expect(blocks[2].succs).toEqual([1]); // back edge
    expect(blocks[1].preds).toEqual([0, 2]);
    expectEdgesConsistent(blocks);

    const loops = detectLoops(blocks);
    expect(loops.map(l => l.headerAddr)).toEqual([0x401004]);
  });

  it('starts a new block after a ret in the middle of a function', () => {
    const { blocks } = cfg([
      ['ret', '', 1], // 0x401000
      ['xor', 'eax, eax', 2], // 0x401001 — separate exit path
      ['ret', '', 1],
    ]);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].succs).toEqual([]);
    expect(blocks[1].preds).toEqual([]);
  });

  it('starts a block at an address branched to from elsewhere (xref)', () => {
    // Nothing inside this function jumps to 0x401003, but an xref says something does.
    const xrefs = new Map<number, Xref[]>([[0x401003, [{ from: 0x409000, type: 'branch' }]]]);
    const { blocks } = cfg(
      [
        ['mov', 'eax, 1', 3],
        ['mov', 'ebx, 2', 3],
        ['ret', '', 1],
      ],
      { xrefs },
    );
    expect(blocks.map(b => b.startAddr)).toEqual([0x401000, 0x401003]);
    expect(blocks[0].succs).toEqual([1]); // fallthrough
    expectEdgesConsistent(blocks);
  });

  it('ignores a data xref when choosing block leaders', () => {
    const xrefs = new Map<number, Xref[]>([[0x401003, [{ from: 0x409000, type: 'data' }]]]);
    const { blocks } = cfg(
      [
        ['mov', 'eax, 1', 3],
        ['mov', 'ebx, 2', 3],
        ['ret', '', 1],
      ],
      { xrefs },
    );
    expect(blocks).toHaveLength(1);
  });

  it('excludes instructions that lie outside the function range', () => {
    const insns = layout(START, [
      ['mov', 'eax, 1', 4], // 0x401000 — previous function
      ['xor', 'ecx, ecx', 4], // 0x401004 — ours
      ['ret', '', 4], // 0x401008 — ours
      ['nop', '', 4], // 0x40100c — next function
    ]);
    const blocks = buildCFG({ name: 'f', address: 0x401004, size: 8 }, insns, new Map());
    expect(blocks).toHaveLength(1);
    expect(blocks[0].insns.map(i => i.address)).toEqual([0x401004, 0x401008]);
  });

  describe('jump tables', () => {
    const specs: Spec[] = [
      ['cmp', 'eax, 3', 3], // 0x401000
      ['ja', '0x401014', 2], // 0x401003 — default
      ['jmp', 'qword ptr [rax*8 + 0x402000]', 7], // 0x401005 — indirect
      ['mov', 'eax, 1', 5], // 0x40100c — case 0
      ['mov', 'eax, 2', 3], // 0x401011 — case 1
      ['ret', '', 1], // 0x401014
    ];

    it('adds an edge to every jump table target', () => {
      const { blocks } = cfg(specs, {
        jumpTables: new Map([[0x401005, [0x40100c, 0x401011]]]),
      });
      const byAddr = new Map(blocks.map(b => [b.startAddr, b]));
      expect([...byAddr.keys()]).toEqual([0x401000, 0x401005, 0x40100c, 0x401011, 0x401014]);
      const indirect = byAddr.get(0x401005)!;
      expect(indirect.succs.map(id => blocks[id].startAddr)).toEqual([0x40100c, 0x401011]);
      expectEdgesConsistent(blocks);
    });

    it('deduplicates repeated jump table targets', () => {
      const { blocks } = cfg(specs, {
        jumpTables: new Map([[0x401005, [0x40100c, 0x401011, 0x40100c, 0x40100c]]]),
      });
      const indirect = blocks.find(b => b.startAddr === 0x401005)!;
      expect(indirect.succs).toHaveLength(2);
      expectEdgesConsistent(blocks);
    });

    it('skips jump table targets outside the function', () => {
      const { blocks } = cfg(specs, {
        jumpTables: new Map([[0x401005, [0x40100c, 0x409000]]]),
      });
      const indirect = blocks.find(b => b.startAddr === 0x401005)!;
      expect(indirect.succs.map(id => blocks[id].startAddr)).toEqual([0x40100c]);
    });
  });
});
