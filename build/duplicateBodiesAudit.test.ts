/**
 * Negative controls for `corpus/duplicateBodies.ts`.
 *
 * The corpus run reports 35 groups and 3 self-recursive thunks per x64 binary
 * at `6299113`, and a report-only row has no red state to show it discriminates.
 * So the two rules are pinned here over the shapes that matter:
 *
 *   - The normalisation collapses EXACTLY the spellings the emitter derives from
 *     an address or a counter — `sub_`, `loc_`, `struct_N`, hex constants,
 *     whitespace, and the function's own name — and nothing else. Two bodies
 *     differing in a register name or an SSA version are two groups.
 *   - A self-recursive thunk is the header name in `return <name>(` position in
 *     its own body; a call to a neighbour is not one, and neither is a mention
 *     that is not a call.
 *   - `bodies` excludes an empty body, and `headersLocated` falls when the
 *     signature grammar does not match, so both liveness halves can go to 0.
 */
import { describe, expect, it } from "vitest";
import { auditDuplicateBodies, headerName, normaliseBody } from "../corpus/duplicateBodies";
import type { FuncRec } from "../corpus/sweep";

function fn(name: string, code: string, addr: number): FuncRec {
  return { addr, size: 0x20, name, insns: 0, threw: null, code, sigParams: null };
}
const run = (...codes: [string, string][]) =>
  auditDuplicateBodies([
    { tag: "t", funcs: codes.map(([n, c], i) => fn(n, c, 0x401000 + i * 0x100)) },
  ]);

describe("duplicate body audit", () => {
  it("groups bodies that differ only in address-derived spellings and whitespace", () => {
    const r = run(
      ["sub_401000", "int sub_401000(void) {\n    sub_402000(0x10);\n    goto loc_401010;\nloc_401010:\n    return 0;\n}"],
      ["sub_401100", "int sub_401100(void) {\n  sub_403000(0x20);\n  goto loc_401110;\nloc_401110:\n  return 0;\n}"],
      ["sub_401200", "int sub_401200(void) {\n    sub_402000(0x10);\n    goto loc_401210;\nloc_401210:\n    return 1;\n}"],
    );
    expect(r.groups).toBe(1);
    expect(r.functions).toBe(2);
    expect(r.largestGroup).toBe(2);
    expect(r.bodies).toBe(3);
    expect(r.headersLocated).toBe(3);
    expect(r.rows[0].names).toEqual(["sub_401000", "sub_401100"]);
  });

  it("keeps a register name and an SSA version as distinguishing", () => {
    const r = run(
      ["a", "int a(void) {\n    return eax;\n}"],
      ["b", "int b(void) {\n    return ecx;\n}"],
      ["c", "int c(void) {\n    return eax_1;\n}"],
    );
    expect(r.groups).toBe(0);
  });

  it("normalises the function's own name so three thunks are one group", () => {
    const r = run(
      ["RtlVirtualUnwind", "int RtlVirtualUnwind() {\n    return RtlVirtualUnwind();\n}"],
      ["RtlLookupFunctionEntry", "int RtlLookupFunctionEntry() {\n    return RtlLookupFunctionEntry();\n}"],
      ["RtlCaptureContext", "int RtlCaptureContext() {\n    return RtlCaptureContext();\n}"],
    );
    expect(r.groups).toBe(1);
    expect(r.functions).toBe(3);
    expect(r.selfRecursiveThunks).toBe(3);
    expect(r.thunkNames).toEqual([
      "t:RtlVirtualUnwind",
      "t:RtlLookupFunctionEntry",
      "t:RtlCaptureContext",
    ]);
  });

  it("does not call a tail call to a NEIGHBOUR, or a bare mention, self-recursive", () => {
    const r = run(
      ["a", "int a(void) {\n    return b();\n}"],
      ["b", "int b(void) {\n    x = b;\n    return 0;\n}"],
    );
    expect(r.selfRecursiveThunks).toBe(0);
  });

  it("excludes an empty body from the population and an unlocated header from both", () => {
    const r = run(
      ["a", "int a(void) {\n}"],
      ["b", "int b(void) {\n}"],
      ["c", "// c: no instructions found"],
    );
    expect(r.funcs).toBe(3);
    expect(r.headersLocated).toBe(2);
    expect(r.bodies).toBe(0);
    expect(r.groups).toBe(0);
  });

  it("reads the header name off the signature line", () => {
    expect(headerName("int sub_401000(void) {")).toBe("sub_401000");
    expect(headerName("struct struct_3 *f(int64_t arg0) {")).toBe("f");
    expect(headerName("no parens here")).toBeNull();
  });

  it("normalises exactly the address-derived spellings", () => {
    expect(normaliseBody("  sub_40A(0x1F, loc_3, struct_12);\n\n  f();\n", "f")).toBe(
      "sub_#(0x#, loc_#, struct_#);\nSELF();",
    );
    // `0x` inside an identifier is not a constant, and a decimal is left alone.
    expect(normaliseBody("var_0x30 = 12;", null)).toBe("var_0x30 = 12;");
  });
});
