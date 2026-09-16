import { describe, expect, it } from "vitest";
import { TYPE_BASED_NAMES } from "../../disasm/decompile/userNames";
import {
  declaredNamesOf,
  identKeyFor,
  renameableIdentClass,
  validateVarName,
} from "../decompileIdent";

/**
 * The pure half of "Rename var_20…" (peek-a-bin-5b6q.7): which on-screen
 * identifiers may be keys, how a displayed name maps back to its key, and
 * what a user may type. `DecompileView.dom.test.tsx` pins the render over
 * these; `promote.test.ts` pins the pipeline's use of the same rule.
 */

describe("renameableIdentClass — the stable-key table", () => {
  it.each([
    ["var_20", "var"],
    ["var_4", "var"],
    ["var_1C", "var"],
    ["var_8_rsp", "var"],
    ["arg_0", "param"],
    ["arg_12", "param"],
    ["arg_0x10", "param"],
    ["arg_ecx", "param"],
    ["arg_edx", "param"],
    ...Object.values(TYPE_BASED_NAMES).map((n): [string, string] => [n, "typed"]),
    ["hFile2", "typed"],
    ["status3", "typed"],
  ])("%s → %s", (name, cls) => {
    expect(renameableIdentClass(name)).toBe(cls);
  });

  // Each row names a different instability; see the function's docstring.
  it.each([
    "field_0x18",
    "array_0xC",
    "struct_3",
    "__unrecovered_1",
    "flg_401004_0",
    "clobbered_rcx_2",
    "rax",
    "eax",
    "al",
    "r8d",
    "rcx_3",
    "g_140003000",
    "__imp_CreateFileW",
    "__security_cookie",
    "sub_401000",
    "loc_401020",
    "VAL_0x2",
    "CreateFileW",
    "count",
    "var_",
    "var_2g",
    "var_20x",
    "arg_",
    "arg_abc",
    "hFilex",
    "",
  ])("%s → null", (name) => {
    expect(renameableIdentClass(name)).toBeNull();
  });

  it("is case-exact: the emitter spells the offset in upper-case hex", () => {
    expect(renameableIdentClass("var_1c")).toBeNull();
    expect(renameableIdentClass("VAR_1C")).toBeNull();
  });
});

describe("identKeyFor — the on-screen token is the NEW name, the key is the original", () => {
  const renames = { var_20: "count", arg_0: "ctx" };

  it("maps a displayed rename back to its key", () => {
    expect(identKeyFor("count", renames)).toBe("var_20");
    expect(identKeyFor("ctx", renames)).toBe("arg_0");
  });

  it("returns the token itself when nothing maps to it", () => {
    expect(identKeyFor("var_24", renames)).toBe("var_24");
    expect(identKeyFor("rax", renames)).toBe("rax");
  });

  it("returns the token itself with no record at all", () => {
    expect(identKeyFor("var_20", undefined)).toBe("var_20");
    expect(identKeyFor("var_20", {})).toBe("var_20");
  });

  it("composes with the class table: a renamed local is still a `var`, a register still nothing", () => {
    expect(renameableIdentClass(identKeyFor("count", renames))).toBe("var");
    expect(renameableIdentClass(identKeyFor("ctx", renames))).toBe("param");
    expect(renameableIdentClass(identKeyFor("rax", renames))).toBeNull();
  });
});

describe("validateVarName — what a user may type", () => {
  const declared = new Set(["arg_0", "var_20", "var_24", "rax", "flg_401004_0", "g_140003000"]);

  it("accepts an ordinary identifier", () => {
    for (const ok of ["count", "ctx", "pDevice", "_tmp", "x1", "CamelCase", "count_2"]) {
      expect(validateVarName(ok, declared), ok).toBeNull();
    }
  });

  it("refuses a non-identifier", () => {
    for (const bad of ["", "1abc", "a-b", "a b", "count;", "var 20", "é", "x.y"]) {
      expect(validateVarName(bad, declared), JSON.stringify(bad)).toBe("not a C identifier");
    }
  });

  it("refuses every generated pattern, whether or not this function declares it", () => {
    for (const gen of [
      "var_8",
      "var_ZZ",
      "arg_5",
      "arg_x",
      "flg_1_0",
      "clobbered_rax_1",
      "__unrecovered_9",
      "sub_401000",
      "loc_401000",
      "struct_1",
      "field_0x8",
      "array_0x8",
      "_pad_0x4",
      "g_140001000",
      "__imp_Foo",
      "__security_cookie",
      "VAL_0x1",
    ]) {
      expect(validateVarName(gen, new Set()), gen).toMatch(/^reserved/);
    }
  });

  it("refuses register names at every width, and a split-repair spelling of one", () => {
    for (const reg of [
      "rax",
      "eax",
      "ax",
      "al",
      "ah",
      "r8",
      "r8d",
      "r8w",
      "r8b",
      "rsp",
      "ebp",
      "xmm0",
      "ecx_3",
      "rdx_12",
    ]) {
      expect(validateVarName(reg, new Set()), reg).toMatch(/^reserved/);
    }
    // …but an ordinary `name_2` is not a split repair.
    expect(validateVarName("count_2", new Set())).toBeNull();
  });

  it("refuses C keywords and the emitter's type spellings", () => {
    for (const word of [
      "int",
      "void",
      "return",
      "if",
      "struct",
      "uint32_t",
      "int64_t",
      "HANDLE",
      "NTSTATUS",
      "BOOL",
      "intptr_t",
    ]) {
      expect(validateVarName(word, new Set()), word).toMatch(/^reserved/);
    }
  });

  it("refuses a name the function already declares, and says so", () => {
    expect(validateVarName("count", new Set(["count"]))).toBe("already declared in this function");
    expect(validateVarName("count", ["count"])).toBe("already declared in this function");
  });

  it("does not refuse the generated names of THIS function by the collision rule — the reserved rule already did", () => {
    // Both answers are refusals; the reserved one is the more useful reason.
    expect(validateVarName("var_20", declared)).toMatch(/^reserved/);
  });
});

describe("declaredNamesOf — the names the emitted C already binds", () => {
  const CODE = [
    "typedef struct struct_0 struct_0;",
    "",
    "#pragma pack(push, 1) /* offsets below are the recovered ones */",
    "struct struct_0 {",
    "    uint32_t field_0x0;",
    "    uint8_t _pad_0x4[0x4];",
    "};",
    "#pragma pack(pop)",
    "",
    "extern int64_t __security_cookie;",
    "extern void *__imp_CreateFileW; /* IAT slot: KERNEL32.dll!CreateFileW */",
    "extern uint8_t g_140003000[]; /* .data; accessed at 4 and 8 bytes */",
    "",
    "int sub_401000(int64_t arg_0, uint32_t arg_1) {",
    "    uint32_t var_20;",
    "    HANDLE hFile;",
    "    int64_t rax;",
    "    uint32_t ecx_3;",
    "    uint32_t flg_401004_0;",
    "    intptr_t __unrecovered_1; /* not recovered */",
    "",
    "    var_20 = arg_1 + 1;",
    "    hFile = CreateFileW(arg_0);",
    "    if (flg_401004_0 == 0) {",
    "        return VAL_0x2;",
    "    }",
    "    return rax;",
    "}",
  ].join("\n");

  it("reads the header's parameters and name", () => {
    const names = declaredNamesOf(CODE);
    expect(names.has("sub_401000")).toBe(true);
    expect(names.has("arg_0")).toBe(true);
    expect(names.has("arg_1")).toBe(true);
  });

  it("reads every kind of line in the declaration block", () => {
    const names = declaredNamesOf(CODE);
    for (const n of ["var_20", "hFile", "rax", "ecx_3", "flg_401004_0", "__unrecovered_1"]) {
      expect(names.has(n), n).toBe(true);
    }
  });

  it("reads the extern block and the typedef names", () => {
    const names = declaredNamesOf(CODE);
    for (const n of ["__security_cookie", "__imp_CreateFileW", "g_140003000", "struct_0"]) {
      expect(names.has(n), n).toBe(true);
    }
  });

  it("does NOT read struct members, body identifiers or callee names", () => {
    const names = declaredNamesOf(CODE);
    for (const n of ["field_0x0", "_pad_0x4", "CreateFileW", "VAL_0x2", "uint32_t", "int"]) {
      expect(names.has(n), n).toBe(false);
    }
  });

  it("stops at the blank line that ends the declaration block", () => {
    // A body line shaped like a declaration must not be read as one.
    const code = "void f(void) {\n    int a;\n\n    b;\n    int c;\n}";
    const names = declaredNamesOf(code);
    expect(names.has("a")).toBe(true);
    expect(names.has("c")).toBe(false);
  });

  it("is empty for an empty or comment-only text", () => {
    expect(declaredNamesOf("")).toEqual(new Set());
    expect(declaredNamesOf("// sub_401000: no instructions found")).toEqual(new Set());
  });

  it("reads a renamed parameter and local under their new names", () => {
    const code = "void f(int64_t ctx) {\n    uint32_t count;\n\n    count = 1;\n}";
    const names = declaredNamesOf(code);
    expect(names.has("ctx")).toBe(true);
    expect(names.has("count")).toBe(true);
    expect(names.has("f")).toBe(true);
  });
});
