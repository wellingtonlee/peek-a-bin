import { describe, it, expect } from "vitest";
import {
  detectShortCircuit,
  detectForLoop,
  detectMultiExitLoop,
  detectIfElseIfChain,
} from "../cfgpatterns";
import { irBinary, irConst, irReg, irVar } from "../ir";
import type { IRExpr, IRStmt } from "../ir";
import type { BasicBlock } from "../../cfg";
import type { Instruction } from "../../types";

const BASE = 0x401000;
const addrOf = (id: number) => BASE + id * 0x10;

function insn(mnemonic: string, opStr: string, address: number): Instruction {
  return { address, mnemonic, opStr, size: 2, bytes: new Uint8Array(2) };
}

interface BlockSpec {
  succs?: number[];
  preds?: number[];
  /** Mnemonic + operand of the block's terminator, e.g. ['je', 9] jumps to block 9. */
  end?: [string, number | null];
}

function block(id: number, spec: BlockSpec = {}): BasicBlock {
  const insns: Instruction[] = [];
  if (spec.end) {
    const [mn, target] = spec.end;
    const op = target === null ? "" : `0x${addrOf(target).toString(16)}`;
    insns.push(insn(mn, op, addrOf(id) + 8));
  }
  return {
    id,
    startAddr: addrOf(id),
    endAddr: addrOf(id) + 0xf,
    insns,
    succs: spec.succs ?? [],
    preds: spec.preds ?? [],
  };
}

function mapOf(blocks: BasicBlock[]): Map<number, BasicBlock> {
  return new Map(blocks.map((b) => [b.id, b]));
}

/**
 * Mirror of structure.ts's own identifyBranches: the branch successor is the one
 * whose start address matches the terminator's operand, the other is fallthrough.
 */
function makeIdentifyBranches(blockById: Map<number, BasicBlock>) {
  return (b: BasicBlock): [number | null, number | null] => {
    const last = b.insns[b.insns.length - 1];
    if (!last) return [null, null];
    const mn = last.mnemonic.toLowerCase();
    if (!mn.startsWith("j") || mn === "jmp") return [null, null];
    const m = last.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (!m) return [null, null];
    const target = parseInt(m[1], 16);
    let branch: number | null = null;
    let fall: number | null = null;
    for (const s of b.succs) {
      const sb = blockById.get(s);
      if (!sb) continue;
      if (sb.startAddr === target) branch = s;
      else fall = s;
    }
    return [branch, fall];
  };
}

/** Distinct, recognisable condition per block: `cond<id> == 0`. */
const condOf = (b: BasicBlock): IRExpr => irBinary("==", irReg(`cond${b.id}`, 4), irConst(0));
const negCondOf = (id: number): IRExpr => irBinary("!=", irReg(`cond${id}`, 4), irConst(0));

function shortCircuit(blocks: BasicBlock[], startId = 0) {
  const byId = mapOf(blocks);
  return detectShortCircuit(startId, byId, condOf, makeIdentifyBranches(byId));
}

/**
 * Two conditional blocks that both branch to `target`, falling through
 * 0 → 1 → exit. This is the canonical short-circuit shape.
 */
function twoBlockChain(): BasicBlock[] {
  return [
    block(0, { succs: [9, 1], end: ["je", 9] }),
    block(1, { succs: [9, 2], preds: [0], end: ["je", 9] }),
    block(2, { preds: [1] }),
    block(9, { preds: [0, 1] }),
  ];
}

describe("detectShortCircuit", () => {
  describe("rejects non-patterns", () => {
    it("returns null for an unknown block id", () => {
      expect(shortCircuit(twoBlockChain(), 42)).toBeNull();
    });

    it("returns null when the block has a single successor", () => {
      const blocks = [block(0, { succs: [1], end: ["jmp", 1] }), block(1, { preds: [0] })];
      expect(shortCircuit(blocks)).toBeNull();
    });

    it("returns null when the block has three successors (jump table)", () => {
      const blocks = [
        block(0, { succs: [1, 2, 3], end: ["jmp", null] }),
        block(1, { preds: [0] }),
        block(2, { preds: [0] }),
        block(3, { preds: [0] }),
      ];
      expect(shortCircuit(blocks)).toBeNull();
    });

    it("returns null when the terminator is not a conditional jump", () => {
      const blocks = twoBlockChain();
      blocks[0].insns = [insn("jmp", `0x${addrOf(9).toString(16)}`, addrOf(0))];
      expect(shortCircuit(blocks)).toBeNull();
    });

    it("returns null when the branch target is unresolved", () => {
      const blocks = twoBlockChain();
      blocks[0].insns = [insn("je", "rax", addrOf(0))];
      expect(shortCircuit(blocks)).toBeNull();
    });

    it("returns null when the fallthrough block is missing from the map", () => {
      const blocks = twoBlockChain().filter((b) => b.id !== 1);
      expect(shortCircuit(blocks)).toBeNull();
    });

    it("returns null when the fallthrough block is not conditional", () => {
      const blocks = twoBlockChain();
      blocks[1].succs = [2];
      blocks[1].insns = [insn("jmp", `0x${addrOf(2).toString(16)}`, addrOf(1))];
      expect(shortCircuit(blocks)).toBeNull();
    });

    it("returns null when the fallthrough block has more than one predecessor", () => {
      // A join point is reachable other than by falling through, so folding it
      // into the condition would duplicate or lose a path.
      const blocks = twoBlockChain();
      blocks[1].preds = [0, 7];
      expect(shortCircuit(blocks)).toBeNull();
    });

    it("returns null when the two conditionals branch to different targets", () => {
      const blocks = twoBlockChain();
      blocks[1].succs = [8, 2];
      blocks[1].insns = [insn("je", `0x${addrOf(8).toString(16)}`, addrOf(1))];
      blocks.push(block(8, { preds: [1] }));
      expect(shortCircuit(blocks)).toBeNull();
    });
  });

  describe("&& pattern", () => {
    it("folds two conditionals sharing a branch target", () => {
      const sc = shortCircuit(twoBlockChain());
      expect(sc).not.toBeNull();
      expect(sc?.kind).toBe("&&");
      expect(sc?.trueTarget).toBe(2);
      expect(sc?.falseTarget).toBe(9);
      expect(sc?.consumedBlocks).toEqual([1]);
    });

    it("negates both conditions (the jump is the failure path)", () => {
      // `je FAIL` is taken when cond is true, so reaching the fallthrough
      // means !condA, and reaching the join means !condA && !condB.
      const sc = shortCircuit(twoBlockChain());
      expect(sc?.condition).toEqual(irBinary("&&", negCondOf(0), negCondOf(1)));
    });

    it("chains a third conditional with the same branch target", () => {
      const blocks = [
        block(0, { succs: [9, 1], end: ["je", 9] }),
        block(1, { succs: [9, 2], preds: [0], end: ["je", 9] }),
        block(2, { succs: [9, 3], preds: [1], end: ["je", 9] }),
        block(3, { preds: [2] }),
        block(9, { preds: [0, 1, 2] }),
      ];
      const sc = shortCircuit(blocks);
      expect(sc?.consumedBlocks).toEqual([1, 2]);
      expect(sc?.trueTarget).toBe(3);
      expect(sc?.falseTarget).toBe(9);
      expect(sc?.condition).toEqual(
        irBinary("&&", irBinary("&&", negCondOf(0), negCondOf(1)), negCondOf(2)),
      );
    });

    it("stops chaining at a block that branches somewhere else", () => {
      const blocks = [
        block(0, { succs: [9, 1], end: ["je", 9] }),
        block(1, { succs: [9, 2], preds: [0], end: ["je", 9] }),
        block(2, { succs: [8, 3], preds: [1], end: ["je", 8] }),
        block(3, { preds: [2] }),
        block(8, { preds: [2] }),
        block(9, { preds: [0, 1] }),
      ];
      const sc = shortCircuit(blocks);
      expect(sc?.consumedBlocks).toEqual([1]);
      expect(sc?.trueTarget).toBe(2);
    });

    it("stops chaining at a block reachable from elsewhere", () => {
      const blocks = [
        block(0, { succs: [9, 1], end: ["je", 9] }),
        block(1, { succs: [9, 2], preds: [0], end: ["je", 9] }),
        block(2, { succs: [9, 3], preds: [1, 7], end: ["je", 9] }),
        block(3, { preds: [2] }),
        block(9, { preds: [0, 1, 2] }),
      ];
      expect(shortCircuit(blocks)?.consumedBlocks).toEqual([1]);
    });

    it("caps the chain at eight conditions", () => {
      // The loop runs at most 6 extra times on top of the first two blocks.
      const blocks: BasicBlock[] = [];
      const CHAIN = 12;
      for (let i = 0; i < CHAIN; i++) {
        blocks.push(
          block(i, { succs: [99, i + 1], preds: i === 0 ? [] : [i - 1], end: ["je", 99] }),
        );
      }
      blocks.push(block(CHAIN, { preds: [CHAIN - 1] }));
      blocks.push(block(99, { preds: blocks.map((b) => b.id) }));
      const sc = shortCircuit(blocks);
      expect(sc?.consumedBlocks).toEqual([1, 2, 3, 4, 5, 6, 7]);
      expect(sc?.trueTarget).toBe(8);
    });
  });

  describe("|| pattern", () => {
    it("expresses `a || b` in De Morgan form rather than as a `||` node", () => {
      // Two blocks that both jump to the SUCCESS block on a true condition are
      // structurally identical to the && case; the result is correct (the join
      // is reached only when neither condition held) but `kind` is always '&&'.
      // The `||` branch in the module body is unreachable dead code.
      const sc = shortCircuit(twoBlockChain());
      expect(sc).not.toBeNull();
      expect(sc?.kind).toBe("&&");
      expect(sc?.condition).toMatchObject({ kind: "binary", op: "&&" });
    });
  });
});

describe("detectForLoop", () => {
  const header = (): BasicBlock => block(1, { succs: [2, 3], preds: [0, 2], end: ["jge", 3] });

  function forLoop(lifted: Record<number, IRStmt[]>, bodyBlocks = [2], hdr: BasicBlock = header()) {
    const liftedMap = new Map<number, IRStmt[]>(
      Object.entries(lifted).map(([k, v]) => [Number(k), v]),
    );
    return detectForLoop(hdr, bodyBlocks, liftedMap, new Map());
  }

  const assign = (dest: IRExpr, src: IRExpr): IRStmt => ({ kind: "assign", dest, src });
  const incReg = (name: string) =>
    assign(irReg(name, 4), irBinary("+", irReg(name, 4), irConst(1)));
  const initReg = (name: string, v: number) => assign(irReg(name, 4), irConst(v));

  it("returns null when the loop has no body blocks", () => {
    expect(forLoop({ 0: [initReg("ecx", 0)] }, [])).toBeNull();
  });

  it("returns null when no body block ends in an increment", () => {
    const lifted = { 0: [initReg("ecx", 0)], 2: [assign(irReg("eax", 4), irConst(3))] };
    expect(forLoop(lifted)).toBeNull();
  });

  it("detects `x = x + 1` over a register", () => {
    const init = initReg("ecx", 0);
    const res = forLoop({ 0: [init], 2: [incReg("ecx")] });
    expect(res?.init).toBe(init);
    expect(res?.update).toEqual(incReg("ecx"));
  });

  it("detects a decrement as the update", () => {
    const dec = assign(irReg("ecx", 4), irBinary("-", irReg("ecx", 4), irConst(1)));
    const res = forLoop({ 0: [initReg("ecx", 0)], 2: [dec] });
    expect(res?.update).toEqual(dec);
  });

  it("detects an update over a named variable", () => {
    const inc = assign(irVar("i", 4), irBinary("+", irVar("i", 4), irConst(1)));
    const init = assign(irVar("i", 4), irConst(0));
    const res = forLoop({ 0: [init], 2: [inc] });
    expect(res?.update).toEqual(inc);
    expect(res?.init).toBe(init);
  });

  it("matches register names case-insensitively", () => {
    const inc = assign(irReg("ECX", 4), irBinary("+", irReg("ecx", 4), irConst(1)));
    const res = forLoop({ 0: [initReg("ecx", 0)], 2: [inc] });
    expect(res?.update).toEqual(inc);
  });

  it("rejects an update whose destination differs from its source", () => {
    const notInc = assign(irReg("ecx", 4), irBinary("+", irReg("edx", 4), irConst(1)));
    expect(forLoop({ 0: [initReg("ecx", 0)], 2: [notInc] })).toBeNull();
  });

  it("rejects an update by a non-constant amount", () => {
    const byReg = assign(irReg("ecx", 4), irBinary("+", irReg("ecx", 4), irReg("edx", 4)));
    expect(forLoop({ 0: [initReg("ecx", 0)], 2: [byReg] })).toBeNull();
  });

  it("rejects a multiplicative update", () => {
    const mul = assign(irReg("ecx", 4), irBinary("*", irReg("ecx", 4), irConst(2)));
    expect(forLoop({ 0: [initReg("ecx", 0)], 2: [mul] })).toBeNull();
  });

  it("only looks at the last statement of a body block", () => {
    // An increment followed by anything else is not recognised — the update
    // has to sit at the very end of the block.
    const lifted = {
      0: [initReg("ecx", 0)],
      2: [incReg("ecx"), assign(irReg("eax", 4), irConst(0))],
    };
    expect(forLoop(lifted)).toBeNull();
  });

  it("returns null when no initialiser is found", () => {
    expect(forLoop({ 2: [incReg("ecx")] })).toBeNull();
  });

  it("takes the last assignment to the induction variable in the predecessor", () => {
    const first = initReg("ecx", 5);
    const second = initReg("ecx", 0);
    const res = forLoop({
      0: [first, assign(irReg("eax", 4), irConst(9)), second],
      2: [incReg("ecx")],
    });
    expect(res?.init).toBe(second);
  });

  it("ignores predecessors whose id is above the header (assumed back-edges)", () => {
    // The back-edge filter is `pred.id < header.id`, so an initialiser in a
    // later-numbered block is never found. Real initialisers precede the
    // header in address order, so this only costs a for/while downgrade.
    const hdr = block(1, { succs: [2, 3], preds: [5, 2], end: ["jge", 3] });
    expect(forLoop({ 5: [initReg("ecx", 0)], 2: [incReg("ecx")] }, [2], hdr)).toBeNull();
  });

  it("reports a placeholder condition for the caller to replace", () => {
    // The header condition is not available here; structureCFG supplies it.
    const res = forLoop({ 0: [initReg("ecx", 0)], 2: [incReg("ecx")] });
    expect(res?.condition).toEqual(irConst(1));
  });

  it("strips the update from the body statements", () => {
    const work = assign(irReg("eax", 4), irConst(7));
    const res = forLoop({ 0: [initReg("ecx", 0)], 2: [work, incReg("ecx")] });
    expect(res?.bodyStmts).toEqual([work]);
  });

  it("concatenates every body block, stripping only the update block tail", () => {
    const a = assign(irReg("eax", 4), irConst(1));
    const b = assign(irReg("ebx", 4), irConst(2));
    const res = forLoop({ 0: [initReg("ecx", 0)], 2: [a, incReg("ecx")], 4: [b] }, [2, 4]);
    expect(res?.bodyStmts).toEqual([a, b]);
  });

  it("tolerates body blocks with no lifted statements", () => {
    const res = forLoop({ 0: [initReg("ecx", 0)], 2: [incReg("ecx")] }, [2, 7]);
    expect(res?.bodyStmts).toEqual([]);
  });
});

describe("detectMultiExitLoop", () => {
  const header = block(1, { succs: [2, 5], preds: [0, 3] });

  function exits(blocks: BasicBlock[], bodyIds: number[]) {
    const bodyAddrs = new Set(bodyIds.map(addrOf));
    return detectMultiExitLoop(header, bodyAddrs, blocks, mapOf(blocks));
  }

  it("returns nothing when every successor stays inside the loop", () => {
    const blocks = [
      header,
      block(2, { succs: [3], preds: [1] }),
      block(3, { succs: [1], preds: [2] }),
    ];
    expect(exits(blocks, [1, 2, 3])).toEqual([]);
  });

  it("reports a body block that branches out of the loop", () => {
    const blocks = [
      header,
      block(2, { succs: [3, 9], preds: [1] }),
      block(3, { succs: [1], preds: [2] }),
      block(9, { preds: [2] }),
    ];
    expect(exits(blocks, [1, 2, 3])).toEqual([{ blockId: 2, exitTarget: 9 }]);
  });

  it("does not report the back edge to the header as an exit", () => {
    // The header address is inside bodyAddrs, and the explicit header check
    // covers the case where it is not.
    const blocks = [header, block(2, { succs: [1], preds: [1] })];
    expect(exits(blocks, [2])).toEqual([]);
  });

  it("skips the header block itself", () => {
    const blocks = [header, block(5, { preds: [1] }), block(2, { succs: [1], preds: [1] })];
    expect(exits(blocks, [1, 2])).toEqual([]);
  });

  it("ignores blocks that are not part of the loop body", () => {
    const blocks = [header, block(7, { succs: [9], preds: [] }), block(9, { preds: [7] })];
    expect(exits(blocks, [1])).toEqual([]);
  });

  it("reports every exit of a block with two outside successors", () => {
    const blocks = [
      header,
      block(2, { succs: [8, 9], preds: [1] }),
      block(8, { preds: [2] }),
      block(9, { preds: [2] }),
    ];
    expect(exits(blocks, [1, 2])).toEqual([
      { blockId: 2, exitTarget: 8 },
      { blockId: 2, exitTarget: 9 },
    ]);
  });

  it("reports one entry per exiting block", () => {
    const blocks = [
      header,
      block(2, { succs: [3, 9], preds: [1] }),
      block(3, { succs: [1, 9], preds: [2] }),
      block(9, { preds: [2, 3] }),
    ];
    expect(exits(blocks, [1, 2, 3])).toEqual([
      { blockId: 2, exitTarget: 9 },
      { blockId: 3, exitTarget: 9 },
    ]);
  });

  it("ignores successors that are absent from the block map", () => {
    const blocks = [header, block(2, { succs: [404], preds: [1] })];
    expect(exits(blocks, [1, 2])).toEqual([]);
  });

  it("recognises body membership by the first instruction address", () => {
    // Blocks whose startAddr differs from their first instruction (e.g. after
    // a re-split) are still matched through insns[0].
    const b = block(2, { succs: [9], preds: [1] });
    b.insns = [insn("nop", "", 0xdead00)];
    const blocks = [header, b, block(9, { preds: [2] })];
    const bodyAddrs = new Set([addrOf(1), 0xdead00]);
    expect(detectMultiExitLoop(header, bodyAddrs, blocks, mapOf(blocks))).toEqual([
      { blockId: 2, exitTarget: 9 },
    ]);
  });
});

// detectIfElseIfChain is exported but never imported anywhere in the codebase.
// These tests pin its current behaviour so a future caller knows what it does.
describe("detectIfElseIfChain (currently unused)", () => {
  function chain(blocks: BasicBlock[], start = 0) {
    return detectIfElseIfChain(start, mapOf(blocks));
  }

  it("returns false for an unknown block", () => {
    expect(chain(twoBlockChain(), 42)).toBe(false);
  });

  it("returns false for a single conditional", () => {
    const blocks = [
      block(0, { succs: [9, 1], end: ["je", 9] }),
      block(1, { preds: [0] }),
      block(9, { preds: [0] }),
    ];
    expect(chain(blocks)).toBe(false);
  });

  it("returns true for two chained conditionals", () => {
    expect(chain(twoBlockChain())).toBe(true);
  });

  it("returns false when the fallthrough is not itself conditional", () => {
    const blocks = twoBlockChain();
    blocks[1].succs = [2];
    blocks[1].insns = [insn("jmp", `0x${addrOf(2).toString(16)}`, addrOf(1))];
    expect(chain(blocks)).toBe(false);
  });

  it("counts a block before checking that it can be walked past", () => {
    // The counter is bumped as soon as a block has two successors, so an
    // unresolved (or missing) terminator still contributes to the count and
    // the function reports a chain it never actually walked.
    const unresolved = twoBlockChain();
    unresolved[1].insns = [insn("je", "rax", addrOf(1))];
    expect(chain(unresolved)).toBe(true);

    const empty = twoBlockChain();
    empty[1].insns = [];
    expect(chain(empty)).toBe(true);
  });
});
