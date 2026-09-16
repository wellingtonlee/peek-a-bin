/**
 * Negative controls for `corpus/calleeArity.ts`.
 *
 * The corpus run demonstrates that the audit reads real emitted C and resolves
 * real callees. What a corpus run CANNOT demonstrate is that the six
 * classifications are each doing work, because the corpus does not populate them
 * all — the whole point of the audit is that `stdcall over` is EMPTY, and a row
 * class with no instance is a rule nothing has ever exercised. So the rules are
 * pinned here, over the classifier directly:
 *
 *   - THE ASYMMETRY IS THE AUDIT. `stdcall` is the `ret N` arm of
 *     `inferSignature` and is exact in both directions, so both `over` and
 *     `under` are rows. Every other arm is a LOWER bound, so the OVER direction
 *     there is `above-frame` / `above-scan` and is explicitly not a defect. An
 *     implementation that judged all conventions alike passes every corpus run
 *     and fails here.
 *   - An over-count against a lower bound must NOT land in `exact`. Folding it
 *     in would be a false green, and `exact` is printed in the report.
 *   - A callee with NO recovered signature is not compared, and `callSites`
 *     must count it anyway — the denominator is the liveness half, and a
 *     text-scraping audit fails by silently matching nothing.
 *   - The callee is resolved by NAME, so a name two functions share is resolved
 *     to NEITHER: a wrong callee is a wrong oracle. The corpus has 0 of these.
 *
 * It lives in `build/` for `corpusPreflight.test.ts`'s reason: the module
 * imports one type and one sibling audit and nothing else, so it runs in the
 * ordinary suite while the audits it belongs to cannot.
 */
import { describe, expect, it } from "vitest";
import { auditCalleeArity } from "../corpus/calleeArity";
import type { FuncRec } from "../corpus/sweep";

function fn(
  addr: number,
  code: string,
  sig: { params: number; convention: string } | null = null,
  name?: string,
): FuncRec {
  return {
    addr,
    size: 0x40,
    name: name ?? `sub_${addr.toString(16).toUpperCase()}`,
    insns: 1,
    threw: null,
    code,
    sigParams: sig === null ? null : sig.params,
    sigConvention: sig === null ? null : sig.convention,
  };
}

const CALLER = (body: string) => `int sub_401000(void) {\n${body}\n}`;

describe("callee arity audit", () => {
  it("counts a call whose arity matches the callee's `ret N` as exact", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    sub_402000(1);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 1,
          convention: "stdcall",
        }),
      ],
      false,
    );
    expect(r.compared).toBe(1);
    expect(r.exact).toBe(1);
    expect(r.rows).toHaveLength(0);
    expect(r.withSignature).toBe(1);
    // The gated row's own population, counted in EVERY direction including
    // `exact` — a liveness half that only counted defects would be zero exactly
    // when the gate is green.
    expect(r.stdcallSites).toBe(1);
  });

  /**
   * THE GATE'S OWN CLASS. `ret N` is exact, so a call passing more is an
   * argument the emitter invented — `corpus/arity.ts`'s OVER verdict on the
   * population that oracle is blind to.
   */
  it("reports an argument invented at a `ret N` callee", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    sub_402000(1, 2, 3);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 1,
          convention: "stdcall",
        }),
      ],
      false,
    );
    expect(r.stdcallOver).toBe(1);
    expect(r.exact).toBe(0);
    expect(r.rows[0].klass).toBe("stdcall-over");
    expect(r.rows[0].emitted).toBe(3);
    expect(r.rows[0].declared).toBe(1);
    expect(r.rows[0].args).toEqual(["1", "2", "3"]);
    expect(r.rows[0].calleeAddr).toBe(0x402000);
  });

  it("reports the other direction at a `ret N` callee as stdcall under", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    sub_402000(1);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 3,
          convention: "stdcall",
        }),
      ],
      false,
    );
    expect(r.stdcallUnder).toBe(1);
    expect(r.stdcallOver).toBe(0);
  });

  /**
   * THE ASYMMETRY, in the direction that decides what may gate: the SAME
   * over-count against a `cdecl` callee is the frame count being a lower bound,
   * not an invented argument. It must not be `stdcall-over` and it must not be
   * `exact` either.
   */
  it("does not call an over-count at a cdecl callee a defect, and does not call it exact", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    sub_402000(1, 2, 3);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 1,
          convention: "cdecl",
        }),
      ],
      false,
    );
    expect(r.stdcallOver).toBe(0);
    expect(r.exact).toBe(0);
    expect(r.cdeclAboveFrame).toBe(1);
    expect(r.rows[0].klass).toBe("cdecl-above-frame");
    // …and it is NOT in the gated row's population, so a corpus made entirely
    // of cdecl callees cannot make the gate look live.
    expect(r.stdcallSites).toBe(0);
  });

  it("reports an under-count at a cdecl callee, which the frame count does bound", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    sub_402000(1);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 3,
          convention: "cdecl",
        }),
      ],
      false,
    );
    expect(r.cdeclUnder).toBe(1);
  });

  /**
   * x64 has ONE convention, so the split cannot be made on the name: it is made
   * on the width. `inferSignature64`'s count is registers read before written,
   * capped at 4, so more arguments than that is the normal case and never a row
   * to gate.
   */
  it("splits x64 on the width, not the convention name", () => {
    const funcs = [
      fn(0x140001000, CALLER("    sub_140002000(rcx, rdx, r8, r9, 5);")),
      fn(0x140002000, "int sub_140002000(void) {\n    return 0;\n}", {
        params: 1,
        convention: "fastcall",
      }),
    ];
    const r = auditCalleeArity(funcs, true);
    expect(r.x64AboveScan).toBe(1);
    expect(r.stdcallOver).toBe(0);
    expect(r.exact).toBe(0);
    // x64 has one convention and it is named `fastcall`, but a 64-bit image
    // contributes NOTHING to the gated row's population: the count came from
    // the register scan, not from `ret N`.
    expect(r.stdcallSites).toBe(0);

    const under = auditCalleeArity(
      [
        fn(0x140001000, CALLER("    sub_140002000(rcx);")),
        fn(0x140002000, "int sub_140002000(void) {\n    return 0;\n}", {
          params: 4,
          convention: "fastcall",
        }),
      ],
      true,
    );
    expect(under.x64Under).toBe(1);
  });

  /**
   * A callee with no recovered signature is not compared — `inferSignature32`
   * answers `null` wherever the body offers no evidence — but the call is still
   * a call site. LIVENESS: a denominator that shrank with the numerator would
   * report perfection for a scan that stopped resolving anything.
   */
  it("counts a call to a signature-less callee as a site and compares nothing", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    sub_402000(1, 2, 3);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}"),
      ],
      false,
    );
    expect(r.callSites).toBe(1);
    expect(r.compared).toBe(0);
    expect(r.rows).toHaveLength(0);
  });

  it("compares nothing for a callee this binary defines no function for", () => {
    const r = auditCalleeArity([fn(0x401000, CALLER("    GetLastError();"))], false);
    expect(r.callSites).toBe(0);
    expect(r.compared).toBe(0);
    expect(r.funcs).toBe(1);
  });

  /**
   * A name two functions share is resolved to NEITHER. Detection renames import
   * thunks after their import, so a collision is possible in principle; a wrong
   * callee is a wrong oracle, and the count is reported so the refusal cannot
   * quietly shrink the population.
   */
  it("resolves an ambiguous name to neither function", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    helper(1, 2, 3);")),
        fn(0x402000, "int helper(void) {\n    return 0;\n}", { params: 1, convention: "stdcall" }, "helper"),
        fn(0x403000, "int helper(void) {\n    return 1;\n}", { params: 3, convention: "stdcall" }, "helper"),
      ],
      false,
    );
    expect(r.ambiguousNames).toBe(1);
    expect(r.compared).toBe(0);
    expect(r.stdcallOver).toBe(0);
  });

  /** A commented-out call is not a call — the masking is what makes that true. */
  it("ignores a commented-out call", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    // sub_402000(1, 2, 3);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 1,
          convention: "stdcall",
        }),
      ],
      false,
    );
    expect(r.callSites).toBe(0);
  });

  /**
   * The function's own definition HEADER is not a call to itself, but a genuine
   * self-recursive call is a row. The two are told apart by the line's shape,
   * not by the name, which is `undefinedCallees.ts`'s rule.
   */
  it("skips the definition header and keeps a self-recursive call", () => {
    const r = auditCalleeArity(
      [
        fn(
          0x401000,
          "int sub_401000(void) {\n    sub_401000(1, 2);\n    return 0;\n}",
          { params: 1, convention: "stdcall" },
        ),
      ],
      false,
    );
    expect(r.callSites).toBe(1);
    expect(r.stdcallOver).toBe(1);
  });

  /** A longer identifier that merely ends in the callee's name is not that callee. */
  it("does not match a name inside a longer identifier", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    xsub_402000(1, 2, 3);\n    p->sub_402000(1, 2, 3);")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 1,
          convention: "stdcall",
        }),
      ],
      false,
    );
    expect(r.callSites).toBe(0);
  });

  /** A nested call is found on its own match rather than skipped with the outer one. */
  it("reads a call nested in another call's argument list", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER("    sub_402000(sub_403000(1, 2));")),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 1,
          convention: "stdcall",
        }),
        fn(0x403000, "int sub_403000(void) {\n    return 0;\n}", {
          params: 2,
          convention: "stdcall",
        }),
      ],
      false,
    );
    expect(r.compared).toBe(2);
    expect(r.exact).toBe(2);
  });

  /**
   * A string argument containing a comma must not be split. `arity.ts` masks a
   * literal to same-length `0`s for exactly this, and this audit reuses that
   * masker rather than rolling a second one.
   */
  it("does not split a string argument at its comma", () => {
    const r = auditCalleeArity(
      [
        fn(0x401000, CALLER('    sub_402000("a, b");')),
        fn(0x402000, "int sub_402000(void) {\n    return 0;\n}", {
          params: 1,
          convention: "stdcall",
        }),
      ],
      false,
    );
    expect(r.exact).toBe(1);
    expect(r.stdcallOver).toBe(0);
  });
});
