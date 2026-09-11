import { describe, expect, it } from "vitest";
import { cleanupStructured, emptyCleanupStats } from "../cleanup";
import type { IRStmt } from "../ir";
import { irBinary, irConst, irReg, irUnary, irUnknown } from "../ir";

/**
 * `if (c) { continue; } break;` at the bottom of a loop body → `if (!c) { break; }`.
 *
 * `structure.ts`'s `armFrom` gives a body-bottom conditional both of its arms, and
 * the pair says one thing in two statements. The rewrite is cosmetic — `continue`
 * and falling off the end of a loop body both reach the back edge — and every one
 * of its restrictions is about a position where that sentence stops being true
 * (peek-a-bin-252).
 */
describe("cleanupStructured — loop tail continue", () => {
  const cond = () => irBinary("<", irReg("ecx", 4), irConst(0x2d));
  const guard = (thenBody: IRStmt[], elseBody?: IRStmt[]): IRStmt => ({
    kind: "if",
    condition: cond(),
    thenBody,
    elseBody,
  });
  const loop = (body: IRStmt[]): IRStmt => ({
    kind: "while",
    condition: irConst(1),
    body,
  });
  const tailOf = (out: IRStmt[]): IRStmt[] => {
    const w = out[0];
    if (w.kind !== "while") throw new Error("expected a while");
    return w.body;
  };

  it("swaps the arms and flips the comparison", () => {
    const out = cleanupStructured([loop([guard([{ kind: "continue" }]), { kind: "break" }])]);
    const body = tailOf(out);
    expect(body).toHaveLength(1);
    const only = body[0];
    if (only.kind !== "if") throw new Error("expected an if");
    expect(only.condition).toEqual(irBinary(">=", irReg("ecx", 4), irConst(0x2d)));
    expect(only.thenBody).toEqual([{ kind: "break" }]);
    expect(only.elseBody).toBeUndefined();
  });

  it("keeps a goto exit spelled as a goto", () => {
    // The label is NOT the loop's own continuation — `breakForwardGotos` would
    // have respelled it `break` if it were, which is a different rule.
    const out = cleanupStructured([
      loop([guard([{ kind: "continue" }]), { kind: "goto", label: "loc_401000" }]),
      { kind: "assign", dest: irReg("esi", 4), src: irConst(2) },
      { kind: "label", name: "loc_401000" },
      { kind: "return" },
    ]);
    const body = tailOf(out);
    expect(body).toHaveLength(1);
    const only = body[0];
    if (only.kind !== "if") throw new Error("expected an if");
    expect(only.thenBody).toEqual([{ kind: "goto", label: "loc_401000" }]);
  });

  it("recurses into a nested loop", () => {
    const inner = loop([guard([{ kind: "continue" }]), { kind: "break" }]);
    const out = cleanupStructured([loop([inner, { kind: "return" }])]);
    const outer = tailOf(out);
    const nested = outer[0];
    if (nested.kind !== "while") throw new Error("expected the inner while");
    expect(nested.body).toHaveLength(1);
    expect(nested.body[0].kind).toBe("if");
  });

  /**
   * The refusals. Each is a position where `break` and the fallthrough do not
   * mean the same thing, or where the negation would read worse than the pair.
   */

  it("refuses a switch arm, where the fallthrough is the next case", () => {
    // `break` here leaves the switch; falling off the end of the arm falls into
    // the case below it. Swapping the arms would be a different program.
    const arm: IRStmt[] = [guard([{ kind: "continue" }]), { kind: "break" }];
    const out = cleanupStructured([
      loop([
        {
          kind: "switch",
          expr: irReg("eax", 4),
          cases: [{ values: [0], body: arm }],
        },
      ]),
    ]);
    const body = tailOf(out);
    const sw = body[0];
    if (sw.kind !== "switch") throw new Error("expected a switch");
    expect(sw.cases[0].body).toHaveLength(2);
    expect(sw.cases[0].body[1]).toEqual({ kind: "break" });
  });

  it("refuses a nested if, where the fallthrough is the rest of the loop body", () => {
    const nested = guard([guard([{ kind: "continue" }]), { kind: "break" }]);
    const out = cleanupStructured([loop([nested, { kind: "return" }])]);
    const body = tailOf(out);
    const outerIf = body[0];
    if (outerIf.kind !== "if") throw new Error("expected the outer if");
    expect(outerIf.thenBody).toHaveLength(2);
  });

  it("refuses a pair that is not the last two statements of the body", () => {
    const out = cleanupStructured([
      loop([guard([{ kind: "continue" }]), { kind: "break" }, { kind: "return" }]),
    ]);
    expect(tailOf(out)).toHaveLength(3);
  });

  it("refuses a guard with an else arm", () => {
    const out = cleanupStructured([
      loop([guard([{ kind: "continue" }], [{ kind: "return" }]), { kind: "break" }]),
    ]);
    // Guard-clause flattening moves the else out; the pair is then not adjacent.
    expect(tailOf(out).length).toBeGreaterThan(1);
  });

  it("refuses a guard whose body is more than the continue", () => {
    const out = cleanupStructured([
      loop([
        guard([{ kind: "assign", dest: irReg("esi", 4), src: irConst(1) }, { kind: "continue" }]),
        { kind: "break" },
      ]),
    ]);
    expect(tailOf(out)).toHaveLength(2);
  });

  it("refuses a condition the negation cannot flip", () => {
    // `!!__unrecovered_1` would become `!!!__unrecovered_1`, which states the
    // test less directly than the two-armed form it replaces.
    const unrec = irUnary("!", irUnary("!", irUnknown("__unrecovered_1")));
    const out = cleanupStructured([
      loop([{ kind: "if", condition: unrec, thenBody: [{ kind: "continue" }] }, { kind: "break" }]),
    ]);
    expect(tailOf(out)).toHaveLength(2);
  });

  it("refuses a short-circuit condition, where De Morgan reads worse", () => {
    const both = irBinary("&&", cond(), irBinary("!=", irReg("edx", 4), irConst(0)));
    const out = cleanupStructured([
      loop([{ kind: "if", condition: both, thenBody: [{ kind: "continue" }] }, { kind: "break" }]),
    ]);
    expect(tailOf(out)).toHaveLength(2);
  });
});

/**
 * `if (c) { …; goto L; } L:` → `if (c) { …; } L:`.
 *
 * `structure.ts`'s `armFrom` closes an arm the walk would not follow with a
 * `goto` to where control really goes; where that is the very statement after
 * the `if`, falling off the arm says the same thing. The rule is sibling-only
 * and name-exact, and the two refusals below are the whole of it: a `goto` to
 * any other label is a transfer the arm's fallthrough does not make, and a case
 * body's trailing `goto` has no sibling because falling off a case body falls
 * into the next case (peek-a-bin-5b6q.6).
 */
describe("cleanupStructured — arm goto elimination", () => {
  const c = () => irBinary("==", irReg("ecx", 4), irConst(0));
  const set = (n: number): IRStmt => ({ kind: "assign", dest: irReg("eax", 4), src: irConst(n) });
  const label = (name: string): IRStmt => ({ kind: "label", name });
  const go = (name: string): IRStmt => ({ kind: "goto", label: name });
  const iff = (thenBody: IRStmt[], elseBody?: IRStmt[]): IRStmt => ({
    kind: "if",
    condition: c(),
    thenBody,
    elseBody,
  });

  it("drops a then-arm goto to the label that follows the if", () => {
    const stats = emptyCleanupStats();
    const out = cleanupStructured([iff([set(1), go("loc_A")]), label("loc_A"), set(2)], stats);
    expect(out).toEqual([iff([set(1)]), label("loc_A"), set(2)]);
    expect(stats.armGotosDropped).toBe(1);
  });

  it("drops the goto from both arms, and keeps the if/else rather than flattening it", () => {
    // With the goto gone the then arm no longer terminates, so guard-clause
    // flattening does not fire and the two arms stay where the machine put them.
    const stats = emptyCleanupStats();
    const out = cleanupStructured(
      [iff([set(1), go("loc_A")], [set(2), go("loc_A")]), label("loc_A"), set(3)],
      stats,
    );
    expect(out).toEqual([iff([set(1)], [set(2)]), label("loc_A"), set(3)]);
    expect(stats.armGotosDropped).toBe(2);
  });

  it("removes the if entirely when the goto was the whole arm", () => {
    // The existing treatment of a test whose outcome the tree does not
    // distinguish: `if (c) {}` is removed.
    const out = cleanupStructured([iff([go("loc_A")]), label("loc_A"), set(2)]);
    expect(out).toEqual([label("loc_A"), set(2)]);
  });

  it("keeps a goto to a different label", () => {
    // The negative control for the rule: `goto loc_B` is a transfer the arm's
    // fallthrough does not make. Dropping it would rejoin the arm to `loc_A`.
    const stats = emptyCleanupStats();
    const out = cleanupStructured(
      [iff([set(1), go("loc_B")]), label("loc_A"), set(2), label("loc_B"), set(3)],
      stats,
    );
    expect(out[0]).toEqual(iff([set(1), go("loc_B")]));
    expect(stats.armGotosDropped).toBe(0);
  });

  it("keeps the goto when the next sibling is not a label", () => {
    const out = cleanupStructured([iff([set(1), go("loc_A")]), set(2), label("loc_A"), set(3)]);
    expect(out[0]).toEqual(iff([set(1), go("loc_A")]));
  });

  it("keeps a goto that is not the arm's last statement", () => {
    const out = cleanupStructured([iff([go("loc_A"), set(1)]), label("loc_A"), set(2)]);
    expect(out[0]).toEqual(iff([go("loc_A"), set(1)]));
  });

  it("does not reach into a switch arm, whose fallthrough is the next case", () => {
    const sw: IRStmt = {
      kind: "switch",
      expr: irReg("ecx", 4),
      cases: [{ values: [1], body: [set(1), go("loc_A")] }],
    };
    const out = cleanupStructured([sw, label("loc_A"), set(2)]);
    expect(out[0]).toEqual(sw);
  });

  it("fires on a nested if whose sibling label is inside the same arm", () => {
    const stats = emptyCleanupStats();
    const out = cleanupStructured(
      [iff([iff([set(1), go("loc_A")]), label("loc_A"), set(2)]), set(3)],
      stats,
    );
    expect(out).toEqual([iff([iff([set(1)]), label("loc_A"), set(2)]), set(3)]);
    expect(stats.armGotosDropped).toBe(1);
  });
});
