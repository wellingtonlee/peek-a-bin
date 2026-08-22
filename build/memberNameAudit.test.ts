import { describe, expect, it } from "vitest";
import { memberNameAgreement } from "../corpus/emitAudits";

/**
 * `memberNameAgreement` is corpus-only — it reads emitted C, and the corpus
 * binaries are not in the repo — so these tests pin its RULE on synthetic
 * input, in the manner of `caseBodyAudit.test.ts` beside them.
 *
 * They matter more than usual here because the corpus reads **0** on all four
 * binaries as of `peek-a-bin-tm29`, so a run cannot demonstrate the instrument
 * still discriminates: the negative control is reverting `mergeFields`' rename,
 * which takes it to 10/1/1/10 over 4/1/1/4 functions (measured at `51264fe`).
 * Without something asserting the rule directly, an audit that stopped matching
 * would be indistinguishable from a clean tree — and `members`/`defs` are in
 * every assertion below for exactly that reason.
 *
 * Both directions are pinned. Only `field_` with `[...]` has ever been produced
 * (`mergeFields` promotes `isArray` and has no path to a demotion), but a rule
 * that renamed every member `array_` instead of promoting would reach 0 on the
 * one direction while being the same defect pointing the other way.
 */
const withDef = (body: string) =>
  `#pragma pack(1)\nstruct struct_1 {\n${body}\n};\n#pragma pack()\n\nvoid f(void) {\n    return;\n}`;

const one = (code: string) =>
  memberNameAgreement([{ tag: "t64", funcs: [{ addr: 0x1000, name: "f", size: 0, insns: 0, threw: null, code }] }]);

describe("memberNameAgreement", () => {
  it("names a field_ member declared with brackets", () => {
    const r = one(withDef("    uint64_t field_0x0;\n    uint64_t field_0x8[];"));
    expect(r.disagreeing).toBe(1);
    expect(r.fieldNamedArrays).toBe(1);
    expect(r.arrayNamedScalars).toBe(0);
    expect(r.rows[0]).toContain("field_0x8 declared with []");
    expect(r.members).toBe(2);
    expect(r.defs).toBe(1);
    expect(r.funcsAffected).toBe(1);
  });

  // A bounded extent is the same disagreement: `[1]` is still an array
  // declaration, and `declareArrayField` reaches it whenever a following field
  // bounds the one it promoted.
  it("names a field_ member declared with a bounded extent", () => {
    const r = one(withDef("    uint32_t field_0x0[1];\n    uint32_t array_0x4[];"));
    expect(r.disagreeing).toBe(1);
    expect(r.fieldNamedArrays).toBe(1);
    expect(r.members).toBe(2);
  });

  it("names an array_ member declared without brackets", () => {
    const r = one(withDef("    uint32_t field_0x0;\n    uint32_t array_0x4;"));
    expect(r.disagreeing).toBe(1);
    expect(r.arrayNamedScalars).toBe(1);
    expect(r.fieldNamedArrays).toBe(0);
    expect(r.rows[0]).toContain("array_0x4 declared without []");
  });

  // The two agreeing spellings, and the ones that are not this audit's business:
  // padding carries no recovered name, and a note about an unplaceable field is
  // a comment rather than a declaration.
  it("is silent on a declaration whose halves agree", () => {
    const r = one(
      withDef(
        [
          "    uint8_t field_0x0;",
          "    uint8_t _pad_0x1[0x3];",
          "    uint32_t array_0x4[1];",
          "    struct_2* field_0x8;",
          "    uint32_t field_0xC; /* PVOID */",
          "    /* field_0x2: 2 bytes at 0x2 — its bytes overlap field_0x0. */",
          "    uint64_t array_0x10[];",
        ].join("\n"),
      ),
    );
    expect(r.disagreeing).toBe(0);
    expect(r.members).toBe(5);
    expect(r.defs).toBe(1);
    expect(r.funcsAffected).toBe(0);
  });

  // Liveness: a function with no struct in it is read and contributes nothing,
  // so `funcs` rises while `defs` and `members` do not. A scan reporting 0 over 0
  // members is the failure this separates from a clean tree.
  it("counts a function with no struct definition as read but empty", () => {
    const r = one("void f(void) {\n    return;\n}");
    expect(r.funcs).toBe(1);
    expect(r.defs).toBe(0);
    expect(r.members).toBe(0);
  });
});
