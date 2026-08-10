import { describe, it, expect } from "vitest";
import { structureCFG } from "../structure";
import { irBinary, irConst, irReg } from "../ir";
import type { IRExpr, IRStmt } from "../ir";
import type { BasicBlock, Loop } from "../../cfg";
import type { Instruction } from "../../types";

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
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)] })).toEqual([mark(0)]);
  });

  it("emits a goto for a jump back to an already-visited block", () => {
    const blocks = [
      bb(0, { succs: [1], code: [["jmp", 1]] }),
      bb(1, { succs: [0], preds: [0], code: [["jmp", 0]] }),
    ];
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)] })).toEqual([
      mark(0),
      mark(1),
      { kind: "goto", label: `loc_${addrOf(0).toString(16).toUpperCase()}` },
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

  it("stops when the branch target cannot be resolved", () => {
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
    expect(structure(blocks, { 0: [mark(0)], 1: [mark(1)], 2: [mark(2)] })).toEqual([mark(0)]);
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

  // KNOWN BUG (reported, not fixed): the blocks folded into the condition are
  // marked visited and their lifted statements are never emitted. Anything the
  // second test block did besides the compare — a call, an assignment — is
  // silently dropped from the output.
  it("discards the statements of a block folded into the condition", () => {
    const call: IRStmt = {
      kind: "call_stmt",
      call: { kind: "call", target: "GetLastError", args: [] },
    };
    const out = structure(shortCircuit(), { 1: [call], 2: [mark(2)], 3: [mark(3)] });
    const flat = JSON.stringify(out);
    expect(flat).not.toContain("GetLastError"); // the call is lost
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

  it("includes the header statements at the top of the loop body", () => {
    const out = structure(whileLoop(), { 1: [mark(1)], 2: [mark(2)] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toMatchObject({ kind: "while", body: [mark(1), mark(2)] });
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

  // KNOWN BUG (reported, not fixed): the initialiser is emitted twice — once as
  // part of the predecessor block that structureFrom already walked, and again
  // inside the `for` header.
  it("emits the initialiser both before and inside the loop", () => {
    const out = structure(counted(), { 0: [init], 2: [mark(2), inc] }, [loopOf(1, [2], 2)]);
    expect(out[0]).toEqual(init); // already emitted here
    expect(out[1]).toMatchObject({ kind: "for", init }); // and again here
  });

  // KNOWN BUG (reported, not fixed): detectForLoop returns a flat concatenation
  // of the body blocks' lifted statements, and structureCFG uses it verbatim.
  // Every `if`, nested loop, `break` and `continue` that the structurer had
  // already recovered inside the loop body is discarded.
  it("flattens control flow inside the loop body", () => {
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
    // The `if` is gone: both arms are emitted unconditionally, one after the other.
    expect(forStmt?.body).toEqual([mark(3), mark(4)]);
    expect(forStmt?.body.some((s) => s.kind === "if")).toBe(false);
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

  it("leaves the default body empty once the bounds check has emitted it", () => {
    // The `ja default` edge is structured as an ordinary if first, so the
    // default block is already visited by the time the switch is built and its
    // statements end up outside the switch, under the bounds-check condition.
    const blocks = switchCFG();
    const out = structure(
      blocks,
      { 2: [mark(2)], 3: [mark(3)], 4: [mark(4)] },
      [],
      jumpTable(blocks, [2, 3]),
    );
    const sw = findStmt(out, "switch") as { defaultBody?: IRStmt[] };
    expect(sw.defaultBody).toEqual([{ kind: "break" }]);
    expect(findStmt(out, "if")).toMatchObject({ thenBody: expect.arrayContaining([mark(4)]) });
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
