import { describe, expect, it } from "vitest";
import { emptyCaseBodies } from "../corpus/emitAudits";

/**
 * `emptyCaseBodies` is corpus-only — it reads emitted C, and the corpus binaries
 * are not in the repo — so these tests pin its RULE on synthetic input, in the
 * manner of `paramClobberAudit.test.ts` beside them.
 *
 * They exist because a text-scraping audit fails by silently matching nothing,
 * and because the two stop rules in `caseBody` are the whole instrument. `emit.ts`
 * puts a case label at the SAME indent as its `switch (`, and the switch's own
 * closing brace with it, so a stop at a *strictly* shallower brace runs the last
 * arm's body on into whatever follows the switch — a genuinely bare final arm
 * then reads as one that does work, which is the audit reporting 0 for the one
 * reason that is not a clean tree. And a `loc_` label is emitted at column 0
 * whatever its nesting, so an indent-only rule ends the body at the first one.
 *
 * Measured against the real corpus at `d8d2d02`: **0 bare bodies of 72 case
 * labels on t32 and 0 of 54 on w32** (13 and 11 switches; 29 and 29 a lone
 * `goto`, 43 and 25 with a body of their own), 0 of 0 on both x64 binaries,
 * which recover no jump table. The bead this answers, `peek-a-bin-37az`, filed
 * **10 of 72 on t32** on 2026-08-12 — 8 of the 27 labels `peek-a-bin-mk42` had
 * just added, plus 2 pre-existing in `sub_40887C`. Reverting `armBody`'s
 * reclaimed-label `goto` (`peek-a-bin-dp6`) to a `break` takes the count to
 * **29 on t32 and 29 on w32**, which is the negative control the corpus can run.
 */
const fn = (name: string, code: string) => ({
  addr: 0,
  name,
  size: 0,
  insns: 0,
  threw: null,
  code,
});

/** The emitter's shape: label and `switch (` at one indent, body four deeper. */
const sw = (arms: string) => `void f() {\n    switch (eax) {\n${arms}    }\n    return;\n}`;

describe("emptyCaseBodies", () => {
  it("names a case whose whole body is a break", () => {
    const r = emptyCaseBodies([{ funcs: [fn("sub_1", sw("    case 0:\n        break;\n"))] }]);
    expect(r.bare).toBe(1);
    expect(r.gotoOnly).toBe(0);
    expect(r.ownBlock).toBe(0);
    expect(r.bad).toEqual(["sub_1 case 0:"]);
  });

  /**
   * THE LAST-ARM STOP RULE. The switch's closing brace sits at the case label's
   * own indent, so a stop at a strictly shallower brace would absorb
   * `after = 1;` into this arm and report `ownBlock` — the audit reading 0 for
   * the one reason indistinguishable from a clean tree.
   */
  it("stops the last arm at the switch's own closing brace", () => {
    const r = emptyCaseBodies([
      {
        funcs: [
          fn(
            "sub_1",
            "void f() {\n    switch (eax) {\n    case 0:\n        break;\n    }\n    after = 1;\n}",
          ),
        ],
      },
    ]);
    expect(r.bare).toBe(1);
    expect(r.ownBlock).toBe(0);
  });

  /**
   * A `loc_` label is not a statement and is emitted at column 0 whatever its
   * nesting, so it neither counts as a body nor ends one. Both halves matter:
   * counting it hides a bare arm, and ending on it truncates a real one.
   */
  it("neither counts nor stops on a loc_ label at column 0", () => {
    const bare = emptyCaseBodies([
      { funcs: [fn("sub_1", sw("    case 0:\nloc_401000:\n        break;\n"))] },
    ]);
    expect(bare.bare).toBe(1);

    const real = emptyCaseBodies([
      { funcs: [fn("sub_1", sw("    case 0:\nloc_401000:\n        eax = 1;\n        break;\n"))] },
    ]);
    expect(real.bare).toBe(0);
    expect(real.ownBlock).toBe(1);
  });

  it("counts a lone goto apart from a bare break", () => {
    const r = emptyCaseBodies([
      { funcs: [fn("sub_1", sw("    case 0:\n        goto loc_401000;\n"))] },
    ]);
    expect(r.bare).toBe(0);
    expect(r.gotoOnly).toBe(1);
  });

  /**
   * `armExit`'s two-edge spelling — the arm's own block reduced to its test.
   * It is a body, not an empty arm: the condition and both transfers are the
   * whole of what that block does (peek-a-bin-pqs5).
   */
  it("treats a conditional exit pair as a body", () => {
    const r = emptyCaseBodies([
      {
        funcs: [
          fn(
            "sub_1",
            sw(
              "    case 0:\n        if (dl != 0x2A) {\n            goto loc_401000;\n        }\n        goto loc_401010;\n",
            ),
          ),
        ],
      },
    ]);
    expect(r.bare).toBe(0);
    expect(r.gotoOnly).toBe(0);
    expect(r.ownBlock).toBe(1);
  });

  it("reads a nested brace as part of the body, not as the arm's end", () => {
    const r = emptyCaseBodies([
      {
        funcs: [
          fn(
            "sub_1",
            sw("    case 0:\n        if (eax) {\n            ecx = 1;\n        }\n        break;\n"),
          ),
        ],
      },
    ]);
    expect(r.bare).toBe(0);
    expect(r.ownBlock).toBe(1);
  });

  it("counts each label of a grouped case separately", () => {
    const r = emptyCaseBodies([
      {
        funcs: [
          fn("sub_1", sw("    case VAL_0x0:\n    case VAL_0x1:\n        goto loc_401000;\n")),
        ],
      },
    ]);
    expect(r.labels).toBe(2);
    // The first label's body is the second label, so it is empty of statements
    // and is neither a bare break nor a lone goto — a grouped label is not the
    // class, and must not be counted as one.
    expect(r.bare).toBe(0);
    expect(r.gotoOnly).toBe(1);
    expect(r.ownBlock).toBe(1);
  });

  it("counts the default arm and the switches, and the three buckets sum", () => {
    const r = emptyCaseBodies([
      {
        funcs: [
          fn(
            "sub_1",
            sw("    case 0:\n        eax = 1;\n        break;\n    default:\n        break;\n"),
          ),
        ],
      },
    ]);
    expect(r.switches).toBe(1);
    expect(r.labels).toBe(2);
    expect(r.bare).toBe(1);
    expect(r.bare + r.gotoOnly + r.ownBlock).toBe(r.labels);
    expect(r.funcsAffected).toBe(1);
  });

  it("reads every function handed to it, affected or not", () => {
    const r = emptyCaseBodies([
      { funcs: [fn("sub_1", "void f() {\n    return;\n}"), fn("sub_2", sw("    case 0:\n        eax = 1;\n        break;\n"))] },
    ]);
    expect(r.funcs).toBe(2);
    expect(r.funcsAffected).toBe(0);
    expect(r.bare).toBe(0);
  });
});
