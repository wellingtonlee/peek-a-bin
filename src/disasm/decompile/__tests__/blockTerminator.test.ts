import { describe, expect, it } from "vitest";
import type { IRStmt } from "../ir";
import { irBinary, irConst, irReg, irVar, isBlockTerminator, pushBeforeTerminator } from "../ir";

/**
 * `destroySSA` and `loopInvariantCodeMotion` both add a statement to the END of
 * another block's lifted list — a phi lowered to a copy in the predecessor, and
 * an invariant assignment hoisted into the preheader. Both were correct only
 * because no terminator existed in the IR, so "end of the statement list" and
 * "end of the block's straight-line code" were the same place.
 *
 * `IRBranch` makes them different places. A plain `push` would land the
 * definition AFTER the branch that reads it, which is a read preceding its own
 * definition — and in the preheader's case that is `ctx.idom.get(header)`, the
 * block deciding whether the loop is entered, so it is the likeliest block in
 * the whole function to end in such a branch (peek-a-bin-c33).
 *
 * Nothing constructs a branch yet, so on today's tree both call sites take the
 * plain-`push` path and the emitted C is unchanged — which is exactly why this
 * behaviour needs a test of its own rather than waiting for the corpus to show
 * it. The corpus cannot: there is nothing there to see.
 */
describe("pushBeforeTerminator", () => {
  const branch: IRStmt = {
    kind: "branch",
    condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
    target: 0x401234,
    jcc: "je",
    addr: 0x401010,
  };
  const copy = (): IRStmt => ({ kind: "assign", dest: irVar("x", 4), src: irConst(7, 4) });

  it("inserts ahead of a trailing branch rather than after it", () => {
    const stmts: IRStmt[] = [{ kind: "assign", dest: irVar("y", 4), src: irConst(1, 4) }, branch];
    pushBeforeTerminator(stmts, copy());

    expect(stmts).toHaveLength(3);
    expect(stmts[1].kind).toBe("assign");
    // The terminator stays last — that is the whole property.
    expect(stmts[2]).toBe(branch);
  });

  it("appends normally when the block has no terminator", () => {
    const stmts: IRStmt[] = [{ kind: "assign", dest: irVar("y", 4), src: irConst(1, 4) }];
    const added = copy();
    pushBeforeTerminator(stmts, added);

    expect(stmts).toHaveLength(2);
    expect(stmts[1]).toBe(added);
  });

  it("appends to an empty block", () => {
    const stmts: IRStmt[] = [];
    const added = copy();
    pushBeforeTerminator(stmts, added);

    expect(stmts).toEqual([added]);
  });

  it("keeps the terminator last across repeated insertions", () => {
    const stmts: IRStmt[] = [branch];
    pushBeforeTerminator(stmts, copy());
    pushBeforeTerminator(stmts, copy());

    expect(stmts).toHaveLength(3);
    expect(stmts[2]).toBe(branch);
  });

  /**
   * `return` is deliberately not a block terminator here: nothing appends to a
   * block on the strength of it, and widening the predicate would silently move
   * where the two existing passes insert.
   */
  it("treats only a branch as a terminator", () => {
    expect(isBlockTerminator(branch)).toBe(true);
    expect(isBlockTerminator({ kind: "return", value: irConst(0, 4) })).toBe(false);
    expect(isBlockTerminator(copy())).toBe(false);
    expect(isBlockTerminator({ kind: "goto", label: "loc_401000" })).toBe(false);
  });
});
