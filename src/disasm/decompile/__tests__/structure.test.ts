import { describe, expect, it } from "vitest";
import type { BasicBlock, Loop } from "../../cfg";
import type { Instruction } from "../../types";
import type { IRExpr, IRStmt } from "../ir";
import { irBinary, irConst, irReg } from "../ir";
import { structureCFG } from "../structure";

const BASE = 0x401000;
const addrOf = (id: number) => BASE + id * 0x100;

function insn(mnemonic: string, opStr: string, address: number): Instruction {
  return { address, mnemonic, opStr, size: 4, bytes: new Uint8Array(4) };
}

interface BlockSpec {
  succs?: number[];
  preds?: number[];
  /** Instructions as [mnemonic, operand]; a numeric operand is a block id. */
  code?: [string, string | number][];
}

function bb(id: number, spec: BlockSpec = {}): BasicBlock {
  const code = spec.code ?? [];
  const insns = code.map(([mn, op], i) =>
    insn(mn, typeof op === "number" ? `0x${addrOf(op).toString(16)}` : op, addrOf(id) + i * 4),
  );
  return {
    id,
    startAddr: addrOf(id),
    endAddr: addrOf(id) + Math.max(code.length, 1) * 4,
    insns,
    succs: spec.succs ?? [],
    preds: spec.preds ?? [],
  };
}

/** `ecx == 0` — what extractCondition builds from `cmp ecx, 0` + `je`. */
const eq0 = (reg = "ecx"): IRExpr => irBinary("==", irReg(reg, 4), irConst(0, 4));
const ne0 = (reg = "ecx"): IRExpr => irBinary("!=", irReg(reg, 4), irConst(0, 4));

/** A recognisable statement per block. */
const mark = (n: number): IRStmt => ({ kind: "assign", dest: irReg("eax", 4), src: irConst(n) });

/** The label `structureCFG` introduces a leftover block with. */
const loc = (n: number): IRStmt => ({
  kind: "label",
  name: `loc_${addrOf(n).toString(16).toUpperCase()}`,
});

function structure(
  blocks: BasicBlock[],
  lifted: Record<number, IRStmt[]> = {},
  loops: Loop[] = [],
  jumpTables: Map<number, number[]> = new Map(),
): IRStmt[] {
  const liftedMap = new Map<number, IRStmt[]>(
    Object.entries(lifted).map(([k, v]) => [Number(k), v]),
  );
  return structureCFG(blocks, loops, liftedMap, jumpTables);
}

/** Depth-first search for the first statement of a kind, at any nesting level. */
function findStmt(stmts: IRStmt[], kind: IRStmt["kind"]): IRStmt | undefined {
  for (const s of stmts) {
    if (s.kind === kind) return s;
    const nested: IRStmt[][] = [];
    if (s.kind === "if") nested.push(s.thenBody, s.elseBody ?? []);
    if (s.kind === "while" || s.kind === "do_while" || s.kind === "for") nested.push(s.body);
    if (s.kind === "switch") {
      for (const c of s.cases) nested.push(c.body);
      nested.push(s.defaultBody ?? []);
    }
    for (const group of nested) {
      const hit = findStmt(group, kind);
      if (hit) return hit;
    }
  }
  return undefined;
}

function loopOf(headerId: number, bodyIds: number[], backEdgeFromId: number): Loop {
  return {
    headerAddr: addrOf(headerId),
    backEdgeFromAddr: addrOf(backEdgeFromId),
    depth: 1,
    bodyAddrs: new Set([headerId, ...bodyIds].map(addrOf)),
  };
}

describe("structureCFG — straight-line code", () => {
  it("returns nothing for an empty CFG", () => {
    expect(structure([])).toEqual([]);
  });

  it("emits a single block with no successors", () => {
    expect(structure([bb(0, { code: [["ret", ""]] })], { 0: [mark(0)] })).toEqual([mark(0)]);
  });

  it("emits nothing when the entry block has no lifted statements", () => {
    expect(structure([bb(0, { code: [["ret", ""]] })])).toEqual([]);
  });

  it("follows a chain of single-successor blocks", () => {
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [2], preds: [0], code: [["jmp", 2]] }),
      bb(2, { preds: [1], code: [["ret", ""]] }),
    ];
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)], 2: [mark(2)] })).toEqual([
      mark(0),
      mark(1),
      mark(2),
    ]);
  });

  it("stops at a ret even when the block has a successor", () => {
    const blocks = [
      bb(0, { succs: [1], code: [["ret", ""]] }),
      bb(1, { preds: [0], code: [["ret", ""]] }),
    ];
    // The walk stops: block 1's statement is not inlined after block 0's, which
    // is what falling through a `ret` would look like. It is appended under its
    // own `loc_` label instead, by the leftover pass — a `ret` ends the path
    // through a block but does not make the code after it stop existing, and
    // block 1 is where an exception funclet lands (peek-a-bin-d3z).
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)] })).toEqual([mark(0), loc(1), mark(1)]);
  });

  it("emits a goto for a jump back to an already-visited block, under its label", () => {
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [0], preds: [0], code: [["jmp", 0]] }),
    ];
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)] })).toEqual([
      loc(0),
      mark(0),
      mark(1),
      { kind: "goto", label: `loc_${addrOf(0).toString(16).toUpperCase()}` },
    ]);
  });

  it("labels only the blocks something jumps to", () => {
    // Every block is emitted under a label while the walk runs, because a back
    // edge found later can name a block emitted long before. The ones nothing
    // reaches are swept away again: three `loc_` lines for straight-line code
    // is noise a reader pays for.
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [2], preds: [0], code: [["jmp", 2]] }),
      bb(2, { preds: [1], code: [["ret", ""]] }),
    ];
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)], 2: [mark(2)] })).toEqual([
      mark(0),
      mark(1),
      mark(2),
    ]);
  });

  it("labels a jumped-to block that lifted to no statements at all", () => {
    // Block 1 lifts to nothing, so no emitted statement carries its address and
    // an emitter matching on addresses has nothing to anchor to. The label is a
    // statement in its own right, so it survives the block being empty.
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [2], preds: [0, 2], code: [["jmp", 2]] }),
      bb(2, { succs: [1], preds: [1], code: [["jmp", 1]] }),
    ];
    expect(structure(blocks, { 0: [mark(0)], 2: [mark(2)] })).toEqual([
      mark(0),
      loc(1),
      mark(2),
      { kind: "goto", label: `loc_${addrOf(1).toString(16).toUpperCase()}` },
    ]);
  });

  it("ignores a successor id that is not in the block list", () => {
    const blocks = [bb(0, { succs: [9], code: [["jmp", 9]] })];
    expect(structure(blocks, { 0: [mark(0)] })).toEqual([mark(0)]);
  });
});

describe("structureCFG — conditionals", () => {
  /** if/else diamond: 0 branches to 2, falls through to 1, both join at 3. */
  function diamond(): BasicBlock[] {
    return [
      bb(0, {
        succs: [2, 1],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 2],
        ],
      }),
      bb(1, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(2, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(3, { preds: [1, 2], code: [["ret", ""]] }),
    ];
  }

  it("builds an if/else from a diamond and continues after the join", () => {
    const out = structure(diamond(), { 1: [mark(1)], 2: [mark(2)], 3: [mark(3)] });
    expect(out).toEqual([
      { kind: "if", condition: eq0(), thenBody: [mark(2)], elseBody: [mark(1)] },
      mark(3),
    ]);
  });

  it("guards the branch target with the taken condition", () => {
    // `je target` is taken when ecx == 0, and block 2 is the target, so block 2
    // is the then-branch and the condition must be the un-negated `ecx == 0`.
    // Emitting `ecx != 0` here would invert the meaning of every if in the
    // decompiled output.
    const out = structure(diamond(), { 1: [mark(1)], 2: [mark(2)] });
    expect((out[0] as { condition: IRExpr }).condition).toEqual(eq0());
  });

  it("emits a single-branch if when the else side is empty", () => {
    const out = structure(diamond(), { 2: [mark(2)] });
    expect(out).toEqual([{ kind: "if", condition: eq0(), thenBody: [mark(2)] }]);
  });

  it("inverts the condition when only the fallthrough has statements", () => {
    // Block 1 runs when the `je` is *not* taken, and it is hoisted into the
    // then-slot, so the condition flips.
    const out = structure(diamond(), { 1: [mark(1)] });
    expect(out).toEqual([{ kind: "if", condition: ne0(), thenBody: [mark(1)] }]);
  });

  it("drops the if entirely when neither side has statements", () => {
    expect(structure(diamond(), { 3: [mark(3)] })).toEqual([mark(3)]);
  });

  it("builds an early-return if when the branch target returns", () => {
    const blocks = [
      bb(0, {
        succs: [2, 1],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 2],
        ],
      }),
      bb(1, { preds: [0], code: [["ret", ""]] }),
      bb(2, { preds: [0], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 1: [mark(1)], 2: [mark(2)] });
    expect(out).toEqual([{ kind: "if", condition: eq0(), thenBody: [mark(2)] }, mark(1)]);
  });

  it("negates the condition when the fallthrough returns", () => {
    const blocks = [
      bb(0, {
        succs: [2, 1],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 2],
        ],
      }),
      bb(1, { preds: [0], code: [["ret", ""]] }),
      bb(2, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(3, { preds: [2], code: [["ret", ""]] }),
    ];
    // Block 1 is the fallthrough, reached when `je` is not taken → `ecx != 0`.
    const out = structure(blocks, { 1: [mark(1)], 2: [mark(2)], 3: [mark(3)] });
    expect(out[0]).toEqual({ kind: "if", condition: ne0(), thenBody: [mark(1)] });
    expect(out.slice(1)).toEqual([mark(2), mark(3)]);
  });

  it("reads the comparison operands into the condition", () => {
    const blocks = [
      bb(0, {
        succs: [2, 1],
        code: [
          ["cmp", "eax, 0x5"],
          ["jg", 2],
        ],
      }),
      bb(1, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(2, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(3, { preds: [1, 2], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 1: [mark(1)], 2: [mark(2)] });
    // jg → '>', and block 2 (the jump target) is the then-branch, so the
    // comparison survives unflipped.
    expect((out[0] as { condition: IRExpr }).condition).toEqual(
      irBinary(">", irReg("eax", 4), irConst(5, 4)),
    );
  });

  it("reads a memory operand in the comparison", () => {
    const blocks = [
      bb(0, {
        succs: [2, 1],
        code: [
          ["cmp", "dword ptr [rbp - 0x4], 0x0"],
          ["je", 2],
        ],
      }),
      bb(1, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(2, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(3, { preds: [1, 2], code: [["ret", ""]] }),
    ];
    const cond = (structure(blocks, { 1: [mark(1)] })[0] as { condition: IRExpr }).condition;
    expect(cond).toMatchObject({ kind: "binary", left: { kind: "deref" } });
  });

  it("produces an unknown condition when no compare precedes the jump", () => {
    const blocks = [
      bb(0, { succs: [2, 1], code: [["je", 2]] }),
      bb(1, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(2, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(3, { preds: [1, 2], code: [["ret", ""]] }),
    ];
    const cond = (structure(blocks, { 2: [mark(2)] })[0] as { condition: IRExpr }).condition;
    expect(cond).toEqual({ kind: "unknown", text: "je" });
    // Negating an unrecognised condition falls back to a `!` wrapper.
    const inverted = (structure(blocks, { 1: [mark(1)] })[0] as { condition: IRExpr }).condition;
    expect(inverted).toEqual({ kind: "unary", op: "!", operand: { kind: "unknown", text: "je" } });
  });

  it("stops when the branch target cannot be resolved, but still emits both arms", () => {
    const blocks = [
      bb(0, {
        succs: [1, 2],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", "rax"],
        ],
      }),
      bb(1, { preds: [0], code: [["ret", ""]] }),
      bb(2, { preds: [0], code: [["ret", ""]] }),
    ];
    // The *walk* still stops — `je rax` gives no target to structure an `if`
    // around, so no conditional is emitted. What changed (peek-a-bin-cb2) is
    // what happens to the two arms afterwards: this used to assert
    // `[mark(0)]`, i.e. both blocks deleted outright. They are real code that
    // the branch reaches, so they are appended under their labels instead.
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)], 2: [mark(2)] })).toEqual([
      mark(0),
      loc(1),
      mark(1),
      loc(2),
      mark(2),
    ]);
  });

  it("emits both branches inline when they never converge", () => {
    const blocks = [
      bb(0, {
        succs: [2, 1],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 2],
        ],
      }),
      bb(1, { succs: [3], preds: [0], code: [["jmp", 3]] }),
      bb(2, { succs: [4], preds: [0], code: [["jmp", 4]] }),
      bb(3, { preds: [1], code: [["ret", ""]] }),
      bb(4, { preds: [2], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 1: [mark(1)], 2: [mark(2)], 3: [mark(3)], 4: [mark(4)] });
    expect(out).toEqual([
      {
        kind: "if",
        condition: eq0(),
        thenBody: [mark(2), mark(4)],
        elseBody: [mark(1), mark(3)],
      },
    ]);
  });
});

describe("structureCFG — short-circuit conditions", () => {
  /** `if (a && b)` — two conditionals sharing the same failure target. */
  function shortCircuit(): BasicBlock[] {
    return [
      bb(0, {
        succs: [3, 1],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 3],
        ],
      }),
      bb(1, {
        succs: [3, 2],
        preds: [0],
        code: [
          ["cmp", "edx, 0x0"],
          ["je", 3],
        ],
      }),
      bb(2, { succs: [4], preds: [1], code: [["jmp", 4]] }),
      bb(3, { succs: [4], preds: [0, 1], code: [["jmp", 4]] }),
      bb(4, { preds: [2, 3], code: [["ret", ""]] }),
    ];
  }

  it("folds two conditionals into a single && condition", () => {
    const out = structure(shortCircuit(), { 2: [mark(2)], 3: [mark(3)], 4: [mark(4)] });
    expect(out[0]).toEqual({
      kind: "if",
      condition: irBinary("&&", ne0("ecx"), ne0("edx")),
      thenBody: [mark(2)],
      elseBody: [mark(3)],
    });
    expect(out[1]).toEqual(mark(4));
  });

  // This asserted `expect(flat).not.toContain("GetLastError")` — the old
  // comment called it a KNOWN BUG (reported, not fixed) and pinned the loss in
  // place. It is fixed (peek-a-bin-cb2): a block that does work as well as
  // testing is no longer eligible for the fold.
  //
  // x86 semantics: the machine runs `call GetLastError` unconditionally once
  // control falls out of the first test, and only then evaluates the second.
  // `condA && condB` in C has no place to put that call — the C `&&` evaluates
  // its right operand conditionally and evaluates no statements at all — so
  // the only faithful shape is the nested `if` the general path builds.
  it("keeps the statements of a block that would otherwise fold into the condition", () => {
    const call: IRStmt = {
      kind: "call_stmt",
      call: { kind: "call", target: "GetLastError", args: [] },
    };
    const out = structure(shortCircuit(), { 1: [call], 2: [mark(2)], 3: [mark(3)] });
    const flat = JSON.stringify(out);
    expect(flat).toContain("GetLastError");
    // Not folded: the outer condition is the first test on its own.
    expect(out[0]).toMatchObject({ kind: "if", condition: eq0("ecx") });
    // ...and the call sits on the path where the first test passed, ahead of
    // the second test, exactly where the machine runs it.
    const outer = out[0] as { elseBody: IRStmt[] };
    expect(outer.elseBody[0]).toEqual(call);
    // The second test names where it goes. Block 3 is the shared FAIL target
    // of both tests and the first arm already emitted it, so the second test
    // reaches it by `goto`; asserting the negated form (`if (edx != 0)` with
    // an implicit fallthrough) would say the machine skips block 3's
    // statements on this path, which it does not.
    expect(outer.elseBody[1]).toMatchObject({
      kind: "if",
      condition: eq0("edx"),
      thenBody: [{ kind: "goto", label: (loc(3) as { name: string }).name }],
      elseBody: [mark(2)],
    });
  });
});

describe("structureCFG — loops", () => {
  /**
   * while loop: 0 → 1 (header, `cmp`/`je exit`) → 2 (body) → back to 1, exit 3.
   */
  function whileLoop(): BasicBlock[] {
    return [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, {
        succs: [3, 2],
        preds: [0, 2],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 3],
        ],
      }),
      bb(2, { succs: [1], preds: [1], code: [["jmp", 1]] }),
      bb(3, { preds: [1], code: [["ret", ""]] }),
    ];
  }

  it("builds a while loop from a pre-tested header", () => {
    // The header's `je 3` leaves the loop when ecx == 0, so the loop runs while
    // ecx != 0 — the exit test has to be negated to become the while condition.
    const out = structure(whileLoop(), { 0: [mark(0)], 2: [mark(2)], 3: [mark(3)] }, [
      loopOf(1, [2], 2),
    ]);
    expect(out[0]).toEqual(mark(0));
    expect(out[1]).toMatchObject({ kind: "while", condition: ne0(), body: [mark(2)] });
    expect(out[2]).toEqual(mark(3));
  });

  // Was: `while (ecx != 0) { mark(1); mark(2); }`, which states that the test
  // runs before the header's own statements. The machine runs block 1 in full
  // — statements first, `cmp`/`je` last — so the test sees what those
  // statements just produced, and on the iteration that leaves the loop they
  // have already run. `while (1)` with the test spelled out where the machine
  // performs it is the only shape that says both.
  it("puts the header statements ahead of the test, not inside a pre-tested while", () => {
    const out = structure(whileLoop(), { 1: [mark(1)], 2: [mark(2)] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toMatchObject({
      kind: "while",
      condition: { kind: "const", value: 1 },
      body: [
        mark(1),
        { kind: "if", condition: eq0(), thenBody: [{ kind: "goto", label: "loc_401300" }] },
        mark(2),
      ],
    });
  });

  it("keeps a plain pre-tested while when the header only tests", () => {
    // No statements in block 1, so nothing runs before the test and
    // `while (cond)` says exactly what the machine does.
    const out = structure(whileLoop(), { 2: [mark(2)] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toMatchObject({ kind: "while", condition: ne0(), body: [mark(2)] });
  });

  it("keeps the condition when the branch target is the loop body", () => {
    // Mirror image of the test above: here `je 2` jumps *into* the body, so the
    // taken condition is already the continue-looping condition.
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, {
        succs: [2, 3],
        preds: [0, 2],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 2],
        ],
      }),
      bb(2, { succs: [1], preds: [1], code: [["jmp", 1]] }),
      bb(3, { preds: [1], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 2: [mark(2)] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toMatchObject({ kind: "while", condition: eq0() });
  });

  // KNOWN BUG (reported, not fixed): insertContinueStmts rewrites `goto
  // <header>` into `continue`, but the header is always in the body's stopAt
  // set, and structureFrom only emits a goto for targets *outside* stopAt. No
  // goto to the header is ever produced, so the rewrite is unreachable and
  // `continue` never appears in decompiled output.
  it("drops the back edge instead of emitting a continue", () => {
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, {
        succs: [4, 2],
        preds: [0, 3],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 4],
        ],
      }),
      bb(2, { succs: [3], preds: [1], code: [["jmp", 3]] }),
      bb(3, { succs: [1], preds: [2], code: [["jmp", 1]] }),
      bb(4, { preds: [1], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 2: [mark(2)], 3: [mark(3)] }, [loopOf(1, [2, 3], 3)]);
    expect(out[0]).toMatchObject({ kind: "while", body: [mark(2), mark(3)] });
    expect(findStmt(out, "continue")).toBeUndefined();
  });

  it("does not emit a continue for a conditional back edge either", () => {
    // `if (edx == 0) continue;` shape: block 2 jumps back to the header.
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, {
        succs: [4, 2],
        preds: [0, 2, 3],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 4],
        ],
      }),
      bb(2, {
        succs: [1, 3],
        preds: [1],
        code: [
          ["cmp", "edx, 0x0"],
          ["je", 1],
        ],
      }),
      bb(3, { succs: [1], preds: [2], code: [["jmp", 1]] }),
      bb(4, { preds: [1], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 2: [mark(2)], 3: [mark(3)] }, [loopOf(1, [2, 3], 3)]);
    expect(findStmt(out, "continue")).toBeUndefined();
  });

  it("builds a do-while when the header is not a conditional", () => {
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [2], preds: [0, 2], code: [["jmp", 2]] }),
      bb(2, {
        succs: [1, 3],
        preds: [1],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 1],
        ],
      }),
      bb(3, { preds: [2], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 1: [mark(1)], 2: [mark(2)] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toMatchObject({ kind: "do_while", condition: eq0(), body: [mark(1), mark(2)] });
  });

  it("structures the body of a do-while rather than concatenating its blocks", () => {
    // Header 1 ends in `jmp`, so this takes the bottom-tested fallback. Inside
    // the body, block 2 branches to 3 or 4 and they join at 5, which tests the
    // back edge. The fallback used to concatenate 2..5's statements in block-id
    // order, which emits both arms unconditionally (peek-a-bin-b37).
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [2], preds: [0, 5], code: [["jmp", 2]] }),
      bb(2, {
        succs: [4, 3],
        preds: [1],
        code: [
          ["cmp", "edx, 0x0"],
          ["je", 4],
        ],
      }),
      bb(3, { succs: [5], preds: [2], code: [["jmp", 5]] }),
      bb(4, { succs: [5], preds: [2], code: [["jmp", 5]] }),
      bb(5, {
        succs: [1, 6],
        preds: [3, 4],
        code: [
          ["cmp", "ecx, 0x0"],
          ["jne", 1],
        ],
      }),
      bb(6, { preds: [5], code: [["ret", ""]] }),
    ];
    const out = structure(
      blocks,
      { 1: [mark(1)], 2: [mark(2)], 3: [mark(3)], 4: [mark(4)], 5: [mark(5)], 6: [mark(6)] },
      [loopOf(1, [2, 3, 4, 5], 5)],
    );

    const doWhile = out[0] as { kind: string; body: IRStmt[] };
    expect(doWhile.kind).toBe("do_while");
    // `je 4` is taken when edx == 0, so block 4 is the `then` body.
    expect(findStmt(doWhile.body, "if")).toMatchObject({
      condition: eq0("edx"),
      thenBody: [mark(4)],
      elseBody: [mark(3)],
    });
    // The join runs once either way, after the guard and inside the loop.
    expect(JSON.stringify(doWhile.body).match(/"value":5/g)).toHaveLength(1);
    // Nothing from the body escaped to the outside of the loop.
    expect(JSON.stringify(out.slice(1))).not.toContain('"value":3');
  });

  it("falls back to an infinite do-while when no back-edge condition is found", () => {
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [2], preds: [0, 2], code: [["jmp", 2]] }),
      bb(2, { succs: [1], preds: [1], code: [["jmp", 1]] }),
    ];
    const out = structure(blocks, { 1: [mark(1)], 2: [mark(2)] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toMatchObject({ kind: "do_while", condition: irConst(1, 4) });
  });

  it("stops the loop body at an exit branch out of the loop", () => {
    // Block 2 breaks out to 4; the break target must not be inlined in the body.
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, {
        succs: [4, 2],
        preds: [0, 2],
        code: [
          ["cmp", "ecx, 0x0"],
          ["je", 4],
        ],
      }),
      bb(2, {
        succs: [4, 3],
        preds: [1],
        code: [
          ["cmp", "edx, 0x0"],
          ["je", 4],
        ],
      }),
      bb(3, { succs: [1], preds: [2], code: [["jmp", 1]] }),
      bb(4, { preds: [1, 2], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 2: [mark(2)], 3: [mark(3)], 4: [mark(4)] }, [
      loopOf(1, [2, 3], 3),
    ]);
    const body = JSON.stringify((out[0] as { body: IRStmt[] }).body);
    expect(body).not.toContain('"value":4'); // block 4 is outside the loop
  });
});

describe("structureCFG — for loops", () => {
  /** Counted loop: 0 initialises ecx, 1 tests, 2 is the body + increment. */
  function counted(): BasicBlock[] {
    return [
      bb(0, {
        succs: [1],
        code: [
          ["mov", "ecx, 0x0"],
          ["jmp", 1],
        ],
      }),
      bb(1, {
        succs: [3, 2],
        preds: [0, 2],
        code: [
          ["cmp", "ecx, 0xa"],
          ["jge", 3],
        ],
      }),
      bb(2, { succs: [1], preds: [1], code: [["jmp", 1]] }),
      bb(3, { preds: [1], code: [["ret", ""]] }),
    ];
  }

  const init: IRStmt = { kind: "assign", dest: irReg("ecx", 4), src: irConst(0) };
  const inc: IRStmt = {
    kind: "assign",
    dest: irReg("ecx", 4),
    src: irBinary("+", irReg("ecx", 4), irConst(1)),
  };

  it("builds a for loop from an init, a test and an increment", () => {
    const out = structure(counted(), { 0: [init], 2: [mark(2), inc] }, [loopOf(1, [2], 2)]);
    const forStmt = findStmt(out, "for");
    expect(forStmt).toBeDefined();
    expect(forStmt).toMatchObject({ init, update: inc, body: [mark(2)] });
  });

  it("wires the header condition into the for, not detectForLoop placeholder", () => {
    // detectForLoop returns `condition: const 1` as a placeholder it documents
    // the caller must replace. `jge 3` exits when ecx >= 10, so the loop runs
    // while ecx < 10 — the same negation the equivalent while loop gets.
    const out = structure(counted(), { 0: [init], 2: [mark(2), inc] }, [loopOf(1, [2], 2)]);
    const forStmt = findStmt(out, "for") as { condition: IRExpr };
    expect(forStmt.condition).toEqual(irBinary("<", irReg("ecx", 4), irConst(10, 4)));
  });

  // Was a KNOWN BUG: the initialiser was emitted twice — once as part of the
  // predecessor block the walk had already emitted, and again in the `for`
  // header. `x = f()` run twice is a different program, so the statement moves
  // into the header instead of being copied there.
  it("moves the initialiser into the for header rather than repeating it", () => {
    const out = structure(counted(), { 0: [init], 2: [mark(2), inc] }, [loopOf(1, [2], 2)]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ kind: "for", init });
  });

  it("keeps the loop a while when the initialiser is not the statement before it", () => {
    // `mark(9)` sits between the initialiser and the loop, so hoisting `init`
    // into the header would move it past that statement. The loop stays a
    // `while` with the update at the end of the body, where the machine put it,
    // and nothing is duplicated or lost.
    const out = structure(counted(), { 0: [init, mark(9)], 2: [mark(2), inc] }, [
      loopOf(1, [2], 2),
    ]);
    expect(out).toEqual([
      init,
      mark(9),
      {
        kind: "while",
        condition: irBinary("<", irReg("ecx", 4), irConst(10, 4)),
        body: [mark(2), inc],
      },
    ]);
  });

  // Was a KNOWN BUG: detectForLoop returns a flat concatenation of the body
  // blocks' lifted statements and structureCFG used it verbatim, discarding
  // every `if`, nested loop, `break` and `continue` the structurer had already
  // recovered — and the header's own statements with them (peek-a-bin-42l).
  it("keeps control flow inside the loop body", () => {
    // Body: 2 tests edx and branches to 4, both paths reach 5, which increments
    // and jumps back to the header. The `if` must survive — it does not.
    const blocks = [
      bb(0, {
        succs: [1],
        code: [
          ["mov", "ecx, 0x0"],
          ["jmp", 1],
        ],
      }),
      bb(1, {
        succs: [6, 2],
        preds: [0, 5],
        code: [
          ["cmp", "ecx, 0xa"],
          ["jge", 6],
        ],
      }),
      bb(2, {
        succs: [4, 3],
        preds: [1],
        code: [
          ["cmp", "edx, 0x0"],
          ["je", 4],
        ],
      }),
      bb(3, { succs: [5], preds: [2], code: [["jmp", 5]] }),
      bb(4, { succs: [5], preds: [2], code: [["jmp", 5]] }),
      bb(5, { succs: [1], preds: [3, 4], code: [["jmp", 1]] }),
      bb(6, { preds: [1], code: [["ret", ""]] }),
    ];
    const out = structure(blocks, { 0: [init], 3: [mark(3)], 4: [mark(4)], 5: [inc] }, [
      loopOf(1, [2, 3, 4, 5], 5),
    ]);
    const forStmt = findStmt(out, "for") as { body: IRStmt[] } | undefined;
    expect(forStmt).toBeDefined();
    expect(forStmt?.body).toEqual([
      { kind: "if", condition: eq0("edx"), thenBody: [mark(4)], elseBody: [mark(3)] },
    ]);
  });

  it("keeps the header's own statements, which the flat body left out", () => {
    // The header is the test block; anything it computes before the test runs
    // on every iteration and belongs in the loop. The flat body was built from
    // the body blocks only, so a header statement vanished from the output.
    //
    // It is no longer a `for`: `for (ecx = 0; ecx < 10; ecx++) { mark1; mark2; }`
    // runs `mark1` only after the test passes, and the machine runs it before
    // every test — including the one that ends the loop. A `for` header has no
    // room for a statement that runs on the way in, so the loop is spelled with
    // the test where the machine performs it.
    const out = structure(counted(), { 0: [init], 1: [mark(1)], 2: [mark(2), inc] }, [
      loopOf(1, [2], 2),
    ]);
    expect(findStmt(out, "for")).toBeUndefined();
    expect(out[0]).toEqual(init);
    expect(out[1]).toMatchObject({
      kind: "while",
      condition: { kind: "const", value: 1 },
      body: [
        mark(1),
        {
          kind: "if",
          condition: irBinary(">=", irReg("ecx", 4), irConst(0xa, 4)),
          thenBody: [{ kind: "goto", label: "loc_401300" }],
        },
        mark(2),
        inc,
      ],
    });
  });

  it("keeps a while loop when no initialiser precedes it", () => {
    const out = structure(counted(), { 2: [mark(2), inc] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toMatchObject({ kind: "while" });
  });
});

describe("structureCFG — switches", () => {
  /**
   * Bounds check in block 0 (`ja default`), jump table in block 1,
   * cases 2 and 3, default 4, join 5.
   */
  function switchCFG(): BasicBlock[] {
    return [
      bb(0, {
        succs: [4, 1],
        code: [
          ["cmp", "eax, 0x2"],
          ["ja", 4],
        ],
      }),
      bb(1, { succs: [2, 3, 4], preds: [0], code: [["jmp", "qword ptr [rax*8 + 0x402000]"]] }),
      bb(2, { succs: [5], preds: [1], code: [["jmp", 5]] }),
      bb(3, { succs: [5], preds: [1], code: [["jmp", 5]] }),
      bb(4, { succs: [5], preds: [0, 1], code: [["jmp", 5]] }),
      bb(5, { preds: [2, 3, 4], code: [["ret", ""]] }),
    ];
  }

  function jumpTable(blocks: BasicBlock[], targets: number[]): Map<number, number[]> {
    const jmp = blocks[1].insns[blocks[1].insns.length - 1];
    return new Map([[jmp.address, targets.map(addrOf)]]);
  }

  it("builds a switch with one case per jump-table entry", () => {
    const blocks = switchCFG();
    const out = structure(
      blocks,
      { 2: [mark(2)], 3: [mark(3)], 4: [mark(4)], 5: [mark(5)] },
      [],
      jumpTable(blocks, [2, 3]),
    );
    const sw = findStmt(out, "switch") as { cases: { values: number[]; body: IRStmt[] }[] };
    expect(sw.cases).toEqual([
      { values: [0], body: [mark(2), { kind: "break" }] },
      { values: [1], body: [mark(3), { kind: "break" }] },
    ]);
  });

  it("groups jump-table entries that share a target into one case", () => {
    const blocks = switchCFG();
    const out = structure(blocks, { 2: [mark(2)] }, [], jumpTable(blocks, [2, 2, 2]));
    const sw = findStmt(out, "switch") as { cases: { values: number[] }[] };
    expect(sw.cases).toHaveLength(1);
    expect(sw.cases[0].values).toEqual([0, 1, 2]);
  });

  it("takes the switch expression from the bounds check", () => {
    const blocks = switchCFG();
    const out = structure(
      blocks,
      { 2: [mark(2)], 3: [mark(3)], 4: [mark(4)] },
      [],
      jumpTable(blocks, [2, 3]),
    );
    const sw = findStmt(out, "switch") as { expr: IRExpr; defaultBody?: IRStmt[] };
    expect(sw.expr).toEqual(irReg("eax", 4));
  });

  it("sends the default arm to the block the bounds check already emitted", () => {
    // The `ja default` edge is structured as an ordinary if first, so the
    // default block is already visited by the time the switch is built and its
    // statements end up outside the switch, under the bounds-check condition.
    // The arm must not get a second copy of them — but `break`, which is what
    // it used to get, says the default does nothing, when what it does is the
    // block it was emitted under (peek-a-bin-dp6).
    const blocks = switchCFG();
    const out = structure(
      blocks,
      { 2: [mark(2)], 3: [mark(3)], 4: [mark(4)] },
      [],
      jumpTable(blocks, [2, 3]),
    );
    const sw = findStmt(out, "switch") as { defaultBody?: IRStmt[] };
    expect(sw.defaultBody).toEqual([{ kind: "goto", label: "loc_401400" }]);
    expect(findStmt(out, "if")).toMatchObject({ thenBody: expect.arrayContaining([mark(4)]) });
    // Emitted once: the statements are under the `if`, not in the switch too.
    expect(sw).not.toMatchObject({ defaultBody: expect.arrayContaining([mark(4)]) });
  });

  it("excludes the default block from the case list", () => {
    const blocks = switchCFG();
    const out = structure(blocks, { 4: [mark(4)] }, [], jumpTable(blocks, [2, 4]));
    const sw = findStmt(out, "switch") as { cases: { values: number[] }[] };
    expect(sw.cases.map((c) => c.values)).toEqual([[0]]);
  });

  it("emits a bare break for a case whose target block is unknown", () => {
    const blocks = switchCFG();
    const jmp = blocks[1].insns[blocks[1].insns.length - 1];
    const out = structure(blocks, {}, [], new Map([[jmp.address, [0xdeadbeef]]]));
    const sw = findStmt(out, "switch") as { cases: { body: IRStmt[] }[] };
    expect(sw.cases[0].body).toEqual([{ kind: "break" }]);
  });

  it("continues with the join block after the switch", () => {
    const blocks = switchCFG();
    const out = structure(
      blocks,
      { 2: [mark(2)], 3: [mark(3)], 5: [mark(5)] },
      [],
      jumpTable(blocks, [2, 3]),
    );
    expect(out[out.length - 1]).toEqual(mark(5));
  });

  it("leaves an indirect jump with no jump table unstructured", () => {
    const blocks = switchCFG();
    const out = structure(blocks, { 2: [mark(2)] }, [], new Map());
    expect(findStmt(out, "switch")).toBeUndefined();
  });
});
