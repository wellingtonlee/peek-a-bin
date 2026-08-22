import { describe, expect, it } from "vitest";
import { paramClobberedAtEntry } from "../corpus/emitAudits";

/**
 * `paramClobberedAtEntry` is corpus-only — it reads emitted C, and the corpus
 * binaries are not in the repo — so these tests pin its RULE on synthetic input.
 * They exist because the audit's discriminating power is the whole reason it was
 * written: `offsetNamedArgs` reaches 0 both when a home slot is correctly
 * withdrawn and when every slot is wrongly named, and this is the gate that
 * tells those apart (`peek-a-bin-15q7`).
 *
 * Measured against the real corpus at `99203fb`: 0 rows over 430/578/414/565
 * declared parameters, and under the variant `peek-a-bin-sx57` refused (naming
 * every x64 home slot) it reports 11 rows over 4 functions on each x64 binary
 * while `offsetNamedArgs` sits at its BEST value of 0 on all four.
 */
const fn = (name: string, code: string) => ({
  addr: 0,
  name,
  size: 0,
  insns: 0,
  threw: null,
  code,
});

describe("paramClobberedAtEntry", () => {
  it("names a parameter overwritten from a callee-saved register before any read", () => {
    const r = paramClobberedAtEntry([
      { funcs: [fn("sub_1", "void sub_1(int64_t arg_0) {\n    arg_0 = rbx;\n    return;\n}")] },
    ]);
    expect(r.rows).toEqual(["sub_1:arg_0 = rbx"]);
    expect(r.clobbered).toBe(1);
    expect(r.params).toBe(1);
  });

  /**
   * The register set is what makes this a defect rather than a shape. A volatile
   * register is not obliged to be restored, so an argument slot reused to hold
   * one is ordinary. The real corpus contains exactly this row (`arg_3 = rax`)
   * beside the eleven it does report, which is the direct evidence the
   * restriction discriminates instead of matching any register.
   */
  it("ignores an assignment from a volatile register", () => {
    const r = paramClobberedAtEntry([
      { funcs: [fn("sub_2", "void sub_2(int64_t arg_3) {\n    arg_3 = rax;\n}")] },
    ]);
    expect(r.clobbered).toBe(0);
    expect(r.params).toBe(1);
  });

  /** A sub-width callee-saved spelling is the same register. The corpus's
   * eleventh row is `arg_3 = r13b`, a byte local in an unfilled home slot. */
  it("counts a callee-saved register at a narrower width", () => {
    const r = paramClobberedAtEntry([
      { funcs: [fn("sub_3", "void sub_3(int32_t arg_3) {\n    arg_3 = r13b;\n}")] },
    ]);
    expect(r.clobbered).toBe(1);
  });

  /**
   * FIRST appearance, not any appearance — and this is the whole precision of the
   * audit. Once the callee has consumed an argument it may reuse the slot as
   * scratch, and MSVC does; only a write that precedes every read says the
   * declaration was wrong.
   */
  it("allows a parameter reused as scratch after it has been read", () => {
    const r = paramClobberedAtEntry([
      {
        funcs: [
          fn("sub_4", "void sub_4(int64_t arg_0) {\n    rcx = arg_0;\n    arg_0 = rbx;\n}"),
        ],
      },
    ]);
    expect(r.clobbered).toBe(0);
    expect(r.params).toBe(1);
  });

  /**
   * Liveness. A text-scraping audit fails by silently matching nothing, so the
   * gate asserts `params > 0` beside the count; these pin that the grammar
   * really does read a signature and really does decline a non-signature.
   */
  it("reads parameters out of the signature and reports none for a body it cannot parse", () => {
    expect(
      paramClobberedAtEntry([
        { funcs: [fn("sub_5", "int64_t sub_5(int64_t arg_0, uint8_t var_4, void *p) {\n}")] },
      ]).params,
    ).toBe(3);
    expect(paramClobberedAtEntry([{ funcs: [fn("sub_6", "/* nothing */")] }]).params).toBe(0);
    expect(paramClobberedAtEntry([{ funcs: [fn("sub_7", "void sub_7(void) {\n}")] }]).params).toBe(
      0,
    );
  });
});
