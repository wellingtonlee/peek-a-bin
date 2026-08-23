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
 *     leader `structureCFG` labelled, which in the corpus is 15 of 33 sites on
 *     t32 and 13 of 31 on w32 at `84eed6e`. If that flag stopped distinguishing
 *     the two, the refusal to emit such a comment would lose its evidence.
 *   - `threaded` is what decided it the SECOND time, and it is the half the
 *     corpus provably cannot pin: there, `threaded` and `labelled` agree on all
 *     64 rows, so a run cannot show that the two rules are different questions
 *     at all. They are — one scrapes `loc_<hex>:` lines and the other the bare
 *     hex anywhere — and the refusal rests on their agreement being a
 *     measurement rather than a tautology. Both directions of the difference are
 *     pinned below over shapes the corpus does not contain: a thread that is not
 *     a label, and an unlabelled site with nothing at all. An implementation
 *     that answered `threaded` by asking `labelled` would pass every corpus run
 *     and fail here.
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

    // The shape at t32 0x40388B, which is 18 of the 33 sites at `84eed6e`: the
    // block leader is the UNWINDER's entry three bytes earlier, so nothing names
    // the body and the label that exists would claim a reload the call does not
    // execute.
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
  /**
   * The hex thread, in the direction the corpus DOES contain: a labelled site.
   * Trivial here by construction — the label carries the hex — and asserted so
   * that the guaranteed half of `threaded >= labelled` is stated.
   */
  it("counts a loc_ label as the target's hex thread", () => {
    const r = run([
      fn(
        0x401db3,
        0xbe,
        "int sub_401DB3(void) {\n    sub_401E67();\n    return 0;\nloc_401E67:\n    return 1;\n}",
      ),
    ]);
    expect(r.internalLabelled).toBe(1);
    expect(r.internalThreaded).toBe(1);
    expect(r.internalUnlabelled).toBe(0);
  });

  /**
   * The direction the corpus has 0 of, and the one that makes `threaded` a
   * different question from `labelled`: the hex is on the page as something
   * other than a label. An implementation that answered `threaded` by consulting
   * the label set reports 0 here.
   */
  it("counts a hex thread that is not a label", () => {
    const r = run([
      fn(
        0x401db3,
        0xbe,
        "int sub_401DB3(void) {\n    sub_401E67();\n    eax = 0x401E67;\n    return 0;\n}",
      ),
    ]);
    expect(r.internalLabelled).toBe(0);
    expect(r.internalUnlabelled).toBe(1);
    expect(r.internalThreaded).toBe(1);
  });

  /**
   * The unlabelled shape, which is what the harm figure counts: the block leader
   * is the unwinder's entry a few bytes earlier, so neither a label nor anything
   * else on the page carries the target's hex. A reader searching the
   * identifier's own hex finds only the call.
   */
  it("finds no thread where only the call names the target", () => {
    const r = run([
      fn(
        0x40388b,
        0x74,
        "int sub_40388B(void) {\n    sub_4038F7();\n    return 0;\nloc_4038F4:\n    return 1;\n}",
      ),
    ]);
    expect(r.internalLabelled).toBe(0);
    expect(r.internalUnlabelled).toBe(1);
    expect(r.internalThreaded).toBe(0);
  });

  /**
   * A SECOND call to the same funclet is not its own thread. Without the `sub_`
   * exclusion every internal row would read as threaded and the harm figure
   * would be structurally 0 — a row leaving a scan by no longer being looked at.
   */
  it("does not count another call to the same target as a thread", () => {
    const r = run([
      fn(0x401000, 0x40, "int sub_401000(void) {\n    sub_401030();\n    sub_401030();\n}"),
    ]);
    expect(r.internal).toBe(2);
    expect(r.internalThreaded).toBe(0);
    expect(r.internalUnlabelled).toBe(2);
  });

  /**
   * Hex-digit boundaries. A longer constant that merely contains the target's
   * digits is not a thread, and a shorter one is not either — otherwise the harm
   * figure would fall for coincidences.
   */
  it("does not count a hex run the target's digits are only part of", () => {
    const r = run([
      fn(
        0x401000,
        0x40,
        "int sub_401000(void) {\n    sub_401030();\n    eax = 0x4010301;\n    ebx = 0x40103;\n}",
      ),
    ]);
    expect(r.internalThreaded).toBe(0);
  });

  /**
   * `threaded` is asked of internal rows only, exactly as `labelled` is: an
   * external target's body is not in this function whatever the page says about
   * its address.
   */
  it("never sets threaded for an external target", () => {
    const r = run([
      fn(0x401000, 0x10, "int sub_401000(void) {\n    sub_402000();\nloc_402000:\n    return 1;\n}"),
    ]);
    expect(r.external).toBe(1);
    expect(r.rows[0].threaded).toBe(false);
    expect(r.internalThreaded).toBe(0);
  });
});
