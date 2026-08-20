import { describe, expect, it } from "vitest";
import type { BasicBlock } from "../../cfg";
import type { IRBranch, IRStmt } from "../ir";
import { irBinary, irConst, irReg } from "../ir";
import { buildSSA, detectNaturalLoops } from "../ssa";
import { destroySSA } from "../ssadestroy";
import { loopInvariantCodeMotion, ssaOptimize } from "../ssaopt";

/**
 * The dataflow passes must SEE a branch statement's condition and must never
 * MOVE the statement itself. Both halves are silent when wrong: a pass that
 * cannot see the condition leaves the guard naming a register whose definition
 * it has just deleted (peek-a-bin-f50k), and a pass that relocates the branch
 * puts a block's terminator somewhere that is not the end of the block.
 *
 * Nothing here renders or emits — these assert on the IR the passes leave
 * behind, because that is where the defect lives. The end-to-end consequences
 * are pinned in `pipeline.test.ts`.
 */

function makeBlock(id: number, succs: number[], preds: number[]): BasicBlock {
  return {
    id,
    startAddr: 0x401000 + id * 0x100,
    endAddr: 0x401000 + id * 0x100 + 0x10,
    insns: [],
    succs,
    preds,
  };
}

const branch = (condition: IRBranch["condition"], jcc = "jne"): IRBranch => ({
  kind: "branch",
  condition,
  target: 0x401200,
  jcc,
  addr: 0x401080,
});

/** Every statement of every block, in block-id order. */
function allStmts(blocks: BasicBlock[], lifted: Map<number, IRStmt[]>): IRStmt[] {
  return blocks.flatMap((b) => lifted.get(b.id) ?? []);
}

describe("loopInvariantCodeMotion — a branch is never hoisted out of a loop", () => {
  /**
   * The plan for peek-a-bin-c33 named this the highest-risk site, on the
   * grounds that a walker whose fallback is "hoistable" fails catastrophically
   * and silently. It is safe by construction rather than by luck — the hoist
   * guard leads with `s.kind === "assign"`, so a branch fails it before
   * `isInvariant` is ever called — but "safe by construction" is exactly the
   * kind of claim that stops being true during an unrelated refactor.
   *
   * The condition here is deliberately loop-INVARIANT (`edi != 0`, with EDI
   * defined outside the loop and never written inside it), so a hoist that
   * keyed off the condition rather than the statement kind would fire.
   */
  it("leaves an invariant condition's branch in the block it terminates", () => {
    // 0 → 1 → 2 → 1 (back edge), 1 → 3
    const blocks = [
      makeBlock(0, [1], []),
      makeBlock(1, [2, 3], [0, 2]),
      makeBlock(2, [1], [1]),
      makeBlock(3, [], [1]),
    ];
    const lifted = new Map<number, IRStmt[]>([
      [0, [{ kind: "assign", dest: irReg("edi", 4), src: irConst(7, 4) }]],
      [1, [branch(irBinary("!=", irReg("edi", 4), irConst(0, 4)))]],
      [
        2,
        [
          { kind: "assign", dest: irReg("esi", 4), src: irConst(3, 4) },
          {
            kind: "assign",
            dest: irReg("eax", 4),
            src: irBinary("+", irReg("eax", 4), irConst(1, 4)),
          },
        ],
      ],
      [3, [{ kind: "return", value: irReg("eax", 4) }]],
    ]);

    const ctx = buildSSA(blocks, lifted);
    const loops = detectNaturalLoops(blocks, ctx.idom, ctx.domTree);
    expect(loops.size).toBeGreaterThan(0);
    loopInvariantCodeMotion(ctx, loops);

    const header = ctx.liftedBlocks.get(1) ?? [];
    expect(header.filter((s) => s.kind === "branch")).toHaveLength(1);
    expect(header[header.length - 1].kind).toBe("branch");
    // And it did not appear anywhere else, which is the failure a bare count
    // in one block would miss.
    expect(allStmts(blocks, ctx.liftedBlocks).filter((s) => s.kind === "branch")).toHaveLength(1);
  });

  it("hoists into the preheader AHEAD of the branch that block ends with", () => {
    // 0 (preheader, ends in a branch) → 1 → 1 (self loop) and 1 → 2.
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [1, 2], [0, 1]), makeBlock(2, [], [1])];
    const invariant: IRStmt = {
      kind: "assign",
      dest: irReg("esi", 4),
      src: irBinary("+", irReg("edi", 4), irConst(4, 4)),
    };
    const lifted = new Map<number, IRStmt[]>([
      [
        0,
        [
          { kind: "assign", dest: irReg("edi", 4), src: irConst(9, 4) },
          branch(irBinary("!=", irReg("edi", 4), irConst(0, 4))),
        ],
      ],
      [1, [invariant, branch(irBinary("!=", irReg("esi", 4), irConst(0, 4)))]],
      [2, [{ kind: "return", value: irReg("eax", 4) }]],
    ]);

    const ctx = buildSSA(blocks, lifted);
    const loops = detectNaturalLoops(blocks, ctx.idom, ctx.domTree);
    loopInvariantCodeMotion(ctx, loops);

    const preheader = ctx.liftedBlocks.get(0) ?? [];
    // Whether the hoist fired at all is not the point — where it landed is.
    expect(preheader[preheader.length - 1].kind).toBe("branch");
  });
});

describe("a guard's registers are reads the SSA passes act on", () => {
  it("renames the condition to the definition that reaches the jcc", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const lifted = new Map<number, IRStmt[]>([
      [
        0,
        [
          { kind: "assign", dest: irReg("eax", 4), src: irConst(5, 4) },
          branch(irBinary("==", irReg("eax", 4), irConst(0, 4)), "je"),
        ],
      ],
      [1, [{ kind: "return", value: irReg("eax", 4) }]],
    ]);

    const ctx = buildSSA(blocks, lifted);
    const b = (ctx.liftedBlocks.get(0) ?? []).find((s) => s.kind === "branch") as IRBranch;
    expect(b.condition.kind).toBe("binary");
    const left = b.condition.kind === "binary" ? b.condition.left : null;
    // Version 1, i.e. the constant assignment above it — not version 0, the
    // register's entry value.
    expect(left?.kind === "reg" ? left.version : undefined).toBe(1);
  });

  it("propagates a constant into the condition and drops the dead definition", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const lifted = new Map<number, IRStmt[]>([
      [
        0,
        [
          { kind: "assign", dest: irReg("eax", 4), src: irConst(0x200, 4) },
          branch(irBinary("==", irReg("ecx", 4), irReg("eax", 4)), "je"),
        ],
      ],
      [1, [{ kind: "return", value: irReg("ecx", 4) }]],
    ]);

    const ctx = buildSSA(blocks, lifted);
    ssaOptimize(ctx);
    destroySSA(ctx);

    const b = (ctx.liftedBlocks.get(0) ?? []).find((s) => s.kind === "branch") as IRBranch;
    const right = b.condition.kind === "binary" ? b.condition.right : null;
    expect(right).toEqual(expect.objectContaining({ kind: "const", value: 0x200 }));
  });

  it("repairs a stale read inside a condition, which needs mapReads' branch arm", () => {
    // `edx` is read by the guard under version 1 and overwritten by version 2
    // one statement earlier in the emitted order, so binding the guard to the
    // bare name would read the new value. `splitStaleReads` takes a copy.
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const lifted = new Map<number, IRStmt[]>([
      [
        0,
        [
          {
            kind: "assign",
            dest: irReg("edx", 4),
            src: irBinary("+", irReg("esi", 4), irConst(1, 4)),
          },
          { kind: "store", address: irReg("ebx", 4), value: irReg("edx", 4), size: 4 },
          {
            kind: "assign",
            dest: irReg("edx", 4),
            src: irBinary("+", irReg("edi", 4), irConst(2, 4)),
          },
        ],
      ],
      [1, [{ kind: "return", value: irReg("edx", 4) }]],
    ]);
    // The guard reads the FIRST definition, from a position after the second.
    const stmts = lifted.get(0) as IRStmt[];
    const ctx = buildSSA(blocks, lifted);
    const renamed = ctx.liftedBlocks.get(0) as IRStmt[];
    const firstDef = renamed[0];
    const v =
      firstDef.kind === "assign" && firstDef.dest.kind === "reg"
        ? firstDef.dest.version
        : undefined;
    expect(v).toBeDefined();
    renamed.push(branch(irBinary("!=", irReg("edx", 4, v), irConst(0, 4))));
    void stmts;

    destroySSA(ctx);

    const b = (ctx.liftedBlocks.get(0) ?? []).find((s) => s.kind === "branch") as IRBranch;
    const left = b.condition.kind === "binary" ? b.condition.left : null;
    // A `var`, not the register: the repair copy holds the value the guard
    // means, and the register by then holds the second definition.
    expect(left?.kind).toBe("var");
  });
});
