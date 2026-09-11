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
  RESIDUE_NAME,
  stackPointerScaffolding,
  stripDeclarationBlock,
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

  it("classifies register, residue, minted, api and other in that order of precedence", () => {
    const api = new Set(["ExitProcess", "rax"]);
    expect(classifyIdentifier("rax", api)).toBe("register");
    expect(classifyIdentifier("ecx_12", api)).toBe("register");
    expect(classifyIdentifier("clobbered_rcx_4", api)).toBe("minted");
    expect(classifyIdentifier("flg_401000_0", api)).toBe("minted");
    expect(classifyIdentifier("__unrecovered_9", api)).toBe("minted");
    expect(classifyIdentifier("ExitProcess", api)).toBe("api");
    expect(classifyIdentifier("something", api)).toBe("other");
  });

  /**
   * THE RESIDUE, the class the emitter refuses to declare and the gate excludes
   * (peek-a-bin-n9cl.4). `stk_` was `minted` before and is checked BEFORE
   * `MINTED_NAME` now; the XMM names were `register` and are not, since a
   * 16-byte register has no C integer to be declared as. Both orders are pinned
   * here because a wrong one puts a refused name inside the gate, and the gate
   * would then be red for a reason no emitter change can fix.
   */
  it("files the names the emitter refuses to declare as residue, outside the gate", () => {
    const api = new Set<string>();
    for (const name of ["stk_401000", "stk_3", "tmp_xchg", "st0", "st7", "xmm0", "xmm15", "ymm3"])
      expect(`${name}: ${classifyIdentifier(name, api)}`).toBe(`${name}: residue`);
    for (const name of ["xmm0", "ymm15", "st0", "stk_3"])
      expect(`${name}: ${REGISTER_NAME.test(name)}`).toBe(`${name}: false`);
    // Not residue: a real GPR, a minted name, and the look-alikes.
    expect(RESIDUE_NAME.test("rax")).toBe(false);
    expect(RESIDUE_NAME.test("clobbered_rcx_4")).toBe(false);
    expect(RESIDUE_NAME.test("st8")).toBe(false);
    expect(RESIDUE_NAME.test("xmm16")).toBe(false);
    expect(RESIDUE_NAME.test("stk_")).toBe(false);
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

/**
 * THE DECLARATION BLOCK IS NOT STATEMENTS (peek-a-bin-n9cl.4). Since the
 * emitter declares every register and minted variable, three text scans were
 * counting `int64_t rsp;` as a stack-pointer read, `int64_t clobbered_rcx_4;`
 * as a clobbered read, and a declaration line as a statement between two
 * others. `stripDeclarationBlock` is what they read through; both halves of its
 * recognition are pinned here — every line declaration-shaped AND a blank line
 * closing the block — so a body can never be stripped by mistake.
 */
describe("the declaration block is stripped before a text scan counts mentions", () => {
  const withBlock =
    "int f(int64_t arg0) {\n    int64_t var_8;\n    int64_t rsp;\n    int32_t ecx_3;\n" +
    "    intptr_t __unrecovered_1; /* not recovered */\n\n    rsp -= 8;\n    ecx_3 = rsp;\n}";

  it("removes exactly the block and keeps the header and the body", () => {
    expect(stripDeclarationBlock(withBlock)).toBe(
      "int f(int64_t arg0) {\n    rsp -= 8;\n    ecx_3 = rsp;\n}",
    );
  });

  it("leaves a function with no block, and one whose first line is a statement, untouched", () => {
    const none = "int f(void) {\n    return eax;\n}";
    expect(stripDeclarationBlock(none)).toBe(none);
    // A keyword line is not declaration-shaped, so a blank line after it does
    // not make a block of what precedes it.
    const keyword = "int f(void) {\n    return eax;\n\n    x = 1;\n}";
    expect(stripDeclarationBlock(keyword)).toBe(keyword);
    // No header at all: nothing to anchor on.
    expect(stripDeclarationBlock("garbage")).toBe("garbage");
  });

  it("does not read a stack-pointer DECLARATION as a stack-pointer read", () => {
    const r = stackPointerScaffolding(sets(withBlock));
    expect(r.writes).toBe(1);
    // `ecx_3 = rsp;` is the one read; `int64_t rsp;` is not.
    expect(r.reads).toBe(1);
    const noRead = stackPointerScaffolding(sets("int f(void) {\n    int64_t rsp;\n\n    rsp -= 8;\n}"));
    expect(noRead.writeNoRead).toBe(1);
    expect(noRead.reads).toBe(0);
  });

  it("does not pair a definition with a copy across the block", () => {
    // Without the strip, `int32_t ecx;` sits between the two and they are not
    // adjacent; with it they are, which is what the page shows.
    const r = copyPairs(
      sets("int f(void) {\n    int32_t ecx;\n    int32_t edx_3;\n\n    edx_3 = 1;\n    ecx = edx_3;\n}"),
    );
    expect(r.pairs).toBe(1);
    expect(r.lines).toBe(4);
  });

  it("counts a copy through a narrowing cast — the zero-extending write into a wider variable", () => {
    const r = copyPairs(sets("int f(void) {\n    eax_3 = 0;\n    rax = (uint32_t)eax_3;\n}"));
    expect(r.pairs).toBe(1);
    // `rax` is a bare register but `eax_3` is not ITS versioned name, so the
    // swapDefWithCopy sub-count stays at 0 — the same rule as without the cast.
    expect(r.versionToRegister).toBe(0);
    const same = copyPairs(sets("int f(void) {\n    rax_3 = 0;\n    rax = (uint32_t)rax_3;\n}"));
    expect(same.versionToRegister).toBe(1);
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
