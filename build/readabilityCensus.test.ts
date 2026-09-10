/**
 * Negative controls for the emitted-text censuses `peek-a-bin-n9cl.1` added to
 * `corpus/emitAudits.ts` — the readability instruments that are REPORT-ONLY in
 * the corpus run and so have no red row there to prove they see anything.
 *
 * A text-scraping census fails by silently matching nothing, and every one of
 * these has a "good" direction that is downward, so an instrument that went
 * blind would print the best number in the report. The corpus asserts the
 * liveness halves; this file pins the CLASSIFICATIONS, over shapes the corpus
 * does not necessarily contain:
 *
 *   - `REGISTER_NAME` is written out rather than imported from `ir.ts`, so the
 *     `register` class does not agree with the decompiler by construction. The
 *     two declarations meet HERE: every GPR alias `regAtSize` can spell must be
 *     admitted, and everything the regex admits must be a register `ir.ts`
 *     knows — the differential is asserted in both directions.
 *   - `unliftedBaseMnemonic` strips `lock` and keeps `rep` as the bucket, and
 *     that asymmetry is the whole of the rule.
 *   - `voidReturnsValue` reads the RETURN TYPE, never `void` anywhere on the
 *     line — `int f(void)` is not a void function. A valued return nested in a
 *     `for`/`switch`/`__try` counts; a bare `return;` does not.
 *   - `stackPointerScaffolding` tells a write from a read by what follows the
 *     token, with `==` not a write, and a versioned `rsp_1` is still the stack
 *     pointer.
 *   - `copyPairs` needs ADJACENCY and two different names; the exact
 *     `swapDefWithCopy` shape is a register assigned from its own version.
 *   - `gotoCheck`'s `lines` counts every function with code, goto or not, and
 *     `labelsUntargeted` counts labels no goto names.
 *
 * It lives in `build/` for `corpusPreflight.test.ts`'s reason: the module runs
 * in the ordinary suite while the audits it belongs to cannot.
 */
import { describe, expect, it } from "vitest";
import {
  classifyIdentifier,
  copyPairs,
  gotoCheck,
  gotosPer100Lines,
  headerReturnType,
  REGISTER_NAME,
  stackPointerScaffolding,
  unliftedBaseMnemonic,
  unliftedCensus,
  voidReturnsValue,
} from "../corpus/emitAudits";
import type { FuncRec } from "../corpus/sweep";
import { isKnownRegister, regAtSize } from "../src/disasm/decompile/ir";

function fn(code: string, addr = 0x401000): FuncRec {
  return {
    addr,
    size: 0x40,
    name: `sub_${addr.toString(16).toUpperCase()}`,
    insns: 0,
    threw: null,
    code,
    sigParams: null,
  };
}
const sets = (...codes: string[]) => [{ funcs: codes.map((c, i) => fn(c, 0x401000 + i * 0x100)) }];

const CANON = [
  "rax",
  "rbx",
  "rcx",
  "rdx",
  "rsi",
  "rdi",
  "rbp",
  "rsp",
  "r8",
  "r9",
  "r10",
  "r11",
  "r12",
  "r13",
  "r14",
  "r15",
];

describe("REGISTER_NAME against ir.ts (the differential)", () => {
  it("admits every alias regAtSize can spell, at every width, versioned or not", () => {
    for (const canon of CANON) {
      for (const width of [8, 4, 2, 1]) {
        const name = regAtSize(canon, width);
        expect(`${name} admitted`).toBe(`${name} ${REGISTER_NAME.test(name) ? "admitted" : "REFUSED"}`);
        expect(REGISTER_NAME.test(`${name}_7`)).toBe(true);
      }
    }
    for (const high of ["ah", "bh", "ch", "dh"]) expect(REGISTER_NAME.test(high)).toBe(true);
  });

  it("admits nothing ir.ts does not know as a register", () => {
    // Every candidate the grammar could produce, enumerated rather than sampled.
    const stems = [
      "ax",
      "bx",
      "cx",
      "dx",
      "si",
      "di",
      "bp",
      "sp",
      "ip",
      "al",
      "ah",
      "bl",
      "bh",
      "cl",
      "ch",
      "dl",
      "dh",
      "sil",
      "dil",
      "bpl",
      "spl",
    ];
    const candidates = [
      ...stems,
      ...stems.map((s) => `e${s}`),
      ...stems.map((s) => `r${s}`),
      ...[8, 9, 10, 11, 12, 13, 14, 15].flatMap((n) => [`r${n}`, `r${n}b`, `r${n}w`, `r${n}d`]),
      ...Array.from({ length: 16 }, (_, i) => `xmm${i}`),
    ];
    const admitted = candidates.filter((c) => REGISTER_NAME.test(c));
    const unknown = admitted.filter((c) => !isKnownRegister(c));
    expect(unknown).toEqual([]);
    expect(admitted.length).toBeGreaterThan(60);
  });

  it("refuses the names that merely look like registers", () => {
    for (const not of ["rax_", "_rax", "raxx", "var_10", "arg_0", "eaxb", "r16", "xmm16", "rip_"])
      expect(`${not}: ${REGISTER_NAME.test(not)}`).toBe(`${not}: false`);
  });

  it("classifies register, minted, api and other in that order of precedence", () => {
    const api = new Set(["ExitProcess", "rax"]);
    expect(classifyIdentifier("rax", api)).toBe("register");
    expect(classifyIdentifier("ecx_12", api)).toBe("register");
    expect(classifyIdentifier("clobbered_rcx_4", api)).toBe("minted");
    expect(classifyIdentifier("flg_401000_0", api)).toBe("minted");
    expect(classifyIdentifier("stk_3", api)).toBe("minted");
    expect(classifyIdentifier("__unrecovered_9", api)).toBe("minted");
    expect(classifyIdentifier("ExitProcess", api)).toBe("api");
    expect(classifyIdentifier("something", api)).toBe("other");
  });
});

describe("unlifted census", () => {
  it("strips a lock prefix and keeps a rep-family prefix as the bucket", () => {
    expect(unliftedBaseMnemonic("lock or dword ptr [eax], 0")).toEqual({ base: "or", repForm: null });
    expect(unliftedBaseMnemonic("rep movsd")).toEqual({ base: "rep", repForm: "rep movsd" });
    expect(unliftedBaseMnemonic("repne scasw")).toEqual({ base: "repne", repForm: "repne scasw" });
    expect(unliftedBaseMnemonic("LEAVE")).toEqual({ base: "leave", repForm: null });
    expect(unliftedBaseMnemonic("sbb eax, eax")).toEqual({ base: "sbb", repForm: null });
  });

  it("counts every site, per mnemonic, indifferent to indentation and the trailing semicolon", () => {
    const r = unliftedCensus(
      sets(
        "int f(void) {\n    /* unlifted: leave */;\n  /*unlifted: lock or eax, 1*/\n\t/* unlifted: rep stosd */;\n}",
        "int g(void) {\n    return 0;\n}",
      ),
    );
    expect(r.sites).toBe(3);
    expect(r.byMnemonic).toEqual({ leave: 1, or: 1, rep: 1 });
    expect(r.repForms).toEqual({ "rep stosd": 1 });
    expect(r.funcsAffected).toBe(1);
    expect(r.funcs).toBe(2);
    expect(r.rows.map((x) => x.line)).toEqual([2, 3, 4]);
  });

  it("reads no function with empty code, so the liveness half can fall to 0", () => {
    const r = unliftedCensus([{ funcs: [fn("")] }]);
    expect(r.funcs).toBe(0);
  });
});

describe("void returning a value", () => {
  it("reads the return type, not the word void anywhere on the line", () => {
    expect(headerReturnType("int sub_401000(void) {")).toBe("int");
    expect(headerReturnType("void sub_401000(int64_t arg0) {")).toBe("void");
    expect(headerReturnType("struct struct_3 *sub_401000(void) {")).toBe("struct struct_3 *");
    const r = voidReturnsValue(sets("int sub_401000(void) {\n    return rax;\n}"));
    expect(r.voidHeaders).toBe(0);
    expect(r.voidValued).toBe(0);
    expect(r.nonVoidValued).toBe(1);
    expect(r.headers).toBe(1);
  });

  it("counts a void header over a valued return, however deep it sits", () => {
    const r = voidReturnsValue(
      sets(
        "void a(void) {\n    __try {\n        return rax;\n    }\n}",
        "void b(void) {\n    for (i = 0; i < 3; i++) {\n        switch (x) {\n        case 1:\n            return sub_401000(rcx);\n        }\n    }\n}",
        "void c(void) {\n    if (x) return;\n}",
        "void d(void) {\n    eax = 1;\n}",
      ),
    );
    expect(r.voidHeaders).toBe(4);
    expect(r.voidValued).toBe(2);
    expect(r.voidBare).toBe(1);
    expect(r.rows).toEqual(["sub_401000", "sub_401100"]);
  });

  it("does not read the parameter list as a return", () => {
    const r = voidReturnsValue(sets("void f(int64_t return_value) {\n    x = 1;\n}"));
    expect(r.voidValued).toBe(0);
  });
});

describe("stack-pointer scaffolding", () => {
  it("tells a write from a read by what follows the token", () => {
    const r = stackPointerScaffolding(
      sets(
        "int f(void) {\n    rsp -= 0x28;\n    rbp = rsp;\n    rax ^= rsp;\n    rcx = rsp + 0x30;\n    if (rsp == 0) {\n    }\n    rsp += 0x28;\n}",
      ),
    );
    expect(r.writes).toBe(2);
    expect(r.reads).toBe(4);
    expect(r.copies).toBe(1);
    expect(r.subs).toBe(1);
    expect(r.adds).toBe(1);
    expect(r.offsets).toBe(1);
    expect(r.xors).toBe(1);
    expect(r.mentioning).toBe(1);
    expect(r.writeNoRead).toBe(0);
  });

  it("counts a function that adjusts the pointer and never reads it, versioned or not", () => {
    const r = stackPointerScaffolding(
      sets("int f(void) {\n    esp_1 -= 4;\n    esp = 0;\n}", "int g(void) {\n    eax = 1;\n}"),
    );
    expect(r.mentioning).toBe(1);
    expect(r.writeNoRead).toBe(1);
    expect(r.writes).toBe(2);
    expect(r.rows).toEqual(["sub_401000"]);
    expect(r.funcs).toBe(2);
  });

  it("counts unlifted leave without reading it as a pointer mention", () => {
    const r = stackPointerScaffolding(sets("int f(void) {\n    /* unlifted: leave */;\n}"));
    expect(r.unliftedLeave).toBe(1);
    expect(r.mentioning).toBe(0);
  });
});

describe("adjacent copy pairs", () => {
  it("counts v = X; r = v; only when adjacent and the names differ", () => {
    const r = copyPairs(
      sets(
        "int f(void) {\n    ecx_1 = eax + 1;\n    ecx = ecx_1;\n    var_8 = rdx;\n    x = 0;\n    rcx = var_8;\n    eax = eax;\n    eax = eax;\n}",
      ),
    );
    expect(r.pairs).toBe(1);
    expect(r.versionToRegister).toBe(1);
    expect(r.funcsAffected).toBe(1);
    expect(r.lines).toBe(9);
  });

  it("does not count a copy into a register from someone else's version", () => {
    const r = copyPairs(sets("int f(void) {\n    edx_3 = 1;\n    ecx = edx_3;\n}"));
    expect(r.pairs).toBe(1);
    expect(r.versionToRegister).toBe(0);
  });

  it("is indifferent to `==`", () => {
    const r = copyPairs(sets("int f(void) {\n    a = 1;\n    if (b == a) {\n    }\n}"));
    expect(r.pairs).toBe(0);
  });
});

describe("goto density", () => {
  it("counts lines over every function with code and labels no goto names", () => {
    const g = gotoCheck(
      sets(
        "int f(void) {\n    goto loc_401010;\nloc_401010:\n    return 0;\nloc_401020:\n    return 1;\n}",
        "int g(void) {\n    return 2;\n}",
        "",
      ),
    );
    expect(g.gotos).toBe(1);
    expect(g.labels).toBe(2);
    expect(g.labelsUntargeted).toBe(1);
    expect(g.funcs).toBe(2);
    expect(g.lines).toBe(7 + 3);
    expect(gotosPer100Lines(g)).toBe(10);
    expect(gotosPer100Lines({ ...g, lines: 0 })).toBe(0);
  });
});
