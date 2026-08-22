/**
 * Negative controls for `corpus/undefinedCallees.ts`.
 *
 * The corpus run demonstrates that the audit sees the class it was built for:
 * reverting `peek-a-bin-d827`'s fourth admission takes the INTERNAL count from
 * 25 to 13 on t32 and 23 to 11 on w32 while `functions` rises 268 -> 280 and
 * 266 -> 278, i.e. the instrument moves by exactly the twelve funclet starts
 * that admission withdraws. What a corpus run cannot demonstrate is that the
 * two classifications are each doing work, because the corpus happens to
 * populate both halves with one shape apiece — every internal row is a folded
 * `__finally` funclet and every external one a tail call or an IAT-less
 * indirect. So the rules are pinned here, over the classifier directly:
 *
 *   - INTERNAL vs EXTERNAL is the address relation and nothing else. It is not
 *     a funclet test, and the audit's docstring says so; a test that asserted
 *     "funclet" would be asserting a property of this corpus.
 *   - `labelled` is the row that decided the outcome of `peek-a-bin-pf5g`: a
 *     comment naming the body is only available where the target is a block
 *     leader `structureCFG` labelled, which in the corpus is 8 of 25 sites on
 *     t32 and 6 of 23 on w32. If that flag stopped distinguishing the two, the
 *     refusal to emit such a comment would lose its evidence.
 *   - A resolved callee must NOT be reported, and `calls` must count it anyway —
 *     the denominator is the liveness half, and a text-scraping audit fails by
 *     silently matching nothing.
 *
 * It lives in `build/` for `corpusPreflight.test.ts`'s reason: the module
 * imports one type and nothing else, so it runs in the ordinary suite while the
 * audits it belongs to cannot.
 */
import { describe, expect, it } from "vitest";
import type { FuncRec } from "../corpus/sweep";
import { auditUndefinedCallees } from "../corpus/undefinedCallees";

function fn(addr: number, size: number, code: string): FuncRec {
  return {
    addr,
    size,
    name: `sub_${addr.toString(16).toUpperCase()}`,
    insns: 0,
    threw: null,
    code,
  };
}

const run = (funcs: FuncRec[]) => auditUndefinedCallees([{ funcs }]);

describe("undefined callee audit", () => {
  it("reports nothing for a call the output defines a function for", () => {
    const r = run([
      fn(0x401000, 0x20, "int sub_401000(void) {\n    sub_402000();\n}"),
      fn(0x402000, 0x10, "int sub_402000(void) {\n    return 0;\n}"),
    ]);
    expect(r.internal + r.external).toBe(0);
    // The denominator still counts it: a resolved call is a call.
    expect(r.calls).toBe(1);
    expect(r.funcs).toBe(2);
  });

  it("calls a target inside the caller's own extent internal", () => {
    const r = run([fn(0x401000, 0x20, "int sub_401000(void) {\n    sub_401018();\n}")]);
    expect(r.internal).toBe(1);
    expect(r.external).toBe(0);
    expect(r.rows[0].target).toBe(0x401018);
    expect(r.internalDistinct).toBe(1);
    expect(r.internalFuncs).toBe(1);
  });

  /**
   * The boundary is half-open, exactly as a detected extent is: the first byte
   * past the function is the NEXT function's, so a call there is external even
   * though it is one byte from the end.
   */
  it("calls the byte one past the extent external", () => {
    const r = run([fn(0x401000, 0x20, "int sub_401000(void) {\n    sub_401020();\n}")]);
    expect(r.internal).toBe(0);
    expect(r.external).toBe(1);
    expect(r.externalDistinct).toBe(1);
  });

  it("sets labelled only where the function emits a label at the target", () => {
    // The shape at t32 0x401DB3: the target is a block leader, so a comment at
    // the call site could name `loc_401E67`.
    const labelled = run([
      fn(
        0x401db3,
        0xbe,
        "int sub_401DB3(void) {\n    sub_401E67();\n    return 0;\nloc_401E67:\n    return 1;\n}",
      ),
    ]);
    expect(labelled.internal).toBe(1);
    expect(labelled.internalLabelled).toBe(1);

    // The shape at t32 0x40388B, which is 17 of the 25 sites: the block leader
    // is the UNWINDER's entry three bytes earlier, so nothing names the body and
    // the label that exists would claim a reload the call does not execute.
    const unlabelled = run([
      fn(
        0x40388b,
        0x74,
        "int sub_40388B(void) {\n    sub_4038F7();\n    return 0;\nloc_4038F4:\n    return 1;\n}",
      ),
    ]);
    expect(unlabelled.internal).toBe(1);
    expect(unlabelled.internalLabelled).toBe(0);
  });

  it("never sets labelled for an external target", () => {
    const r = run([
      fn(0x401000, 0x10, "int sub_401000(void) {\n    sub_402000();\nloc_402000:\n    return 1;\n}"),
    ]);
    expect(r.external).toBe(1);
    expect(r.rows[0].labelled).toBe(false);
  });

  it("counts one call twice and one target once", () => {
    const r = run([
      fn(
        0x401000,
        0x40,
        "int sub_401000(void) {\n    sub_401030();\n    sub_401030();\n    sub_401038();\n}",
      ),
    ]);
    expect(r.internal).toBe(3);
    expect(r.internalDistinct).toBe(2);
    expect(r.internalFuncs).toBe(1);
    expect(r.calls).toBe(3);
  });

  it("ignores a commented-out call", () => {
    const r = run([
      fn(0x401000, 0x20, "int sub_401000(void) {\n    // sub_401018();\n    return 0;\n}"),
    ]);
    expect(r.internal + r.external).toBe(0);
    expect(r.calls).toBe(0);
  });

  /**
   * A mention that is not a call is not a call. `resolveCallTarget` only ever
   * mints `sub_<hex>` in a call position today, so this is a bound on the rule
   * rather than a saving — the corpus has 0 such mentions, measured at
   * `d8d2d02` — and it is what keeps the count from following a future change
   * that takes a function's address.
   */
  it("ignores a sub_ mention that is not applied as a function", () => {
    const r = run([
      fn(0x401000, 0x20, "int sub_401000(void) {\n    eax = sub_401018;\n    return 0;\n}"),
    ]);
    expect(r.calls).toBe(0);
    expect(r.internal + r.external).toBe(0);
  });
});
