import { describe, expect, it } from "vitest";
import type { BasicBlock } from "../../cfg";
import type { IRFieldAccess, IRStmt } from "../ir";
import { irArrayAccess, irConst, irFieldAccess, irReg } from "../ir";
import {
  buildSSA,
  computeDomFrontier,
  computeDominators,
  computeDomTree,
  computeRPO,
  detectNaturalLoops,
} from "../ssa";
import { destroySSA } from "../ssadestroy";

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

/**
 * 0 → 1, 0 → 2, 1 ⇄ 2: a loop with two entries, so no single header dominates
 * it. Blocks come from disassembling untrusted bytes, so shapes like this
 * reach the dominator code.
 */
function irreducibleCFG(): BasicBlock[] {
  return [
    makeBlock(0, [1, 2], []),
    makeBlock(1, [2], [2, 0]), // back-edge predecessor listed first
    makeBlock(2, [1], [1, 0]),
  ];
}

// ── Tests ──

describe("computeDominators — malformed and irreducible input", () => {
  it("terminates on an irreducible CFG and stays entry-rooted", () => {
    const blocks = irreducibleCFG();
    const idom = computeDominators(blocks, computeRPO(blocks));

    expect(idom.get(0)).toBe(0);
    // Neither node of the two-entry loop dominates the other, so both must
    // resolve to the entry.
    expect(idom.get(1)).toBe(0);
    expect(idom.get(2)).toBe(0);

    // No node may point at itself except the entry — a self-referencing idom
    // is what makes the chain walks in intersect()/domFrontier spin.
    for (const [node, parent] of idom) {
      if (node !== 0) expect(parent).not.toBe(node);
    }
  });

  it("terminates when the caller passes a stale reverse-postorder", () => {
    // rpo that does not match the CFG: node 2 is missing entirely, so its
    // rank falls back to 0 and collides with the entry's.
    const blocks = irreducibleCFG();
    const idom = computeDominators(blocks, [0, 1]);
    expect(idom.get(0)).toBe(0);
    expect(idom.has(2)).toBe(false);
  });

  it("terminates when a predecessor is not a block in the list", () => {
    const blocks = [
      makeBlock(0, [1], []),
      makeBlock(1, [], [0, 99]), // 99 does not exist
    ];
    const idom = computeDominators(blocks, computeRPO(blocks));
    expect(idom.get(1)).toBe(0);
  });

  it("buildSSA completes on an irreducible CFG", () => {
    const blocks = irreducibleCFG();
    const lifted = new Map<number, IRStmt[]>([
      [0, [{ kind: "assign", dest: irReg("rax", 8), src: irConst(1, 8) }]],
      [1, [{ kind: "assign", dest: irReg("rax", 8), src: irConst(2, 8) }]],
      [2, [{ kind: "return", value: irReg("rax", 8) }]],
    ]);
    const ctx = buildSSA(blocks, lifted);
    expect(ctx.idom.get(0)).toBe(0);
    expect(ctx.liftedBlocks.size).toBe(3);
  });
});

describe("dominator-tree walks tolerate a broken idom map", () => {
  // idom entries that cannot come from a well-formed CFG: 1 and 2 point at each
  // other. Every consumer walks these chains, and each walk used to be
  // unbounded — one bad map wedged the worker thread at 100% CPU forever.
  const blocks = [
    makeBlock(0, [1], []),
    makeBlock(1, [2, 3], [0, 2]),
    makeBlock(2, [1], [1]),
    makeBlock(3, [], [1]),
  ];
  const cyclicIdom = new Map<number, number>([
    [0, 0],
    [1, 2],
    [2, 1],
    [3, 1],
  ]);

  it("computeDomFrontier returns instead of looping forever", () => {
    const df = computeDomFrontier(blocks, cyclicIdom);
    expect(df.size).toBe(blocks.length);
  });

  it("detectNaturalLoops returns instead of looping forever", () => {
    const domTree = computeDomTree(cyclicIdom);
    const loops = detectNaturalLoops(blocks, cyclicIdom, domTree);
    expect(loops).toBeInstanceOf(Map);
  });

  it("computeDomFrontier still computes the frontier for a normal diamond", () => {
    const diamond = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const idom = computeDominators(diamond, computeRPO(diamond));
    const df = computeDomFrontier(diamond, idom);
    expect([...(df.get(1) ?? [])]).toEqual([3]);
    expect([...(df.get(2) ?? [])]).toEqual([3]);
    expect([...(df.get(3) ?? [])]).toEqual([]);
  });
});

describe("SSA renaming covers every IRExpr kind", () => {
  it("versions and then strips registers nested in field/array accesses", () => {
    // renameExpr and stripVersionsExpr both fell through to `default: return
    // expr` for field_access/array_access, so registers inside them were left
    // un-renamed (and later, un-stripped).
    const blocks = [makeBlock(0, [], [])];
    const stmts: IRStmt[] = [
      { kind: "assign", dest: irReg("rax", 8), src: irConst(0x1000, 8) },
      {
        kind: "assign",
        dest: irReg("rcx", 8),
        src: irFieldAccess(irReg("rax", 8), "struct_1", 0x10, "field_0x10", 8),
      },
      {
        kind: "assign",
        dest: irReg("rdx", 8),
        src: irArrayAccess(irReg("rax", 8), irReg("rcx", 8), 4, 4),
      },
    ];
    const lifted = new Map<number, IRStmt[]>([[0, stmts]]);
    const ctx = buildSSA(blocks, lifted);

    const renamed = ctx.liftedBlocks.get(0)!;
    // Version 1, not 0: 0 is the value the register held on entry, and each of
    // these registers is written by an earlier statement here (peek-a-bin-swi).
    const field = (renamed[1] as Extract<IRStmt, { kind: "assign" }>).src as IRFieldAccess;
    expect(field.kind).toBe("field_access");
    expect(field.base.kind).toBe("reg");
    expect((field.base as { version?: number }).version).toBe(1);

    const array = (renamed[2] as Extract<IRStmt, { kind: "assign" }>).src;
    expect(array.kind).toBe("array_access");
    if (array.kind === "array_access") {
      expect((array.base as { version?: number }).version).toBe(1);
      expect((array.index as { version?: number }).version).toBe(1);
    }

    // ...and destroySSA must strip those versions again.
    destroySSA(ctx);
    const stripped = ctx.liftedBlocks.get(0)!;
    const strippedField = (stripped[1] as Extract<IRStmt, { kind: "assign" }>).src as IRFieldAccess;
    expect((strippedField.base as { version?: number }).version).toBeUndefined();
  });
});
