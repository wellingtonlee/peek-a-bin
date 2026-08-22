import { describe, expect, it } from "vitest";
import type { RuntimeFunction } from "../../../pe/types";
import { analyzeStackFrame } from "../../stack";
import type { DisasmFunction, Instruction, Xref } from "../../types";
import { isKnownRegister } from "../ir";
import { decompileFunction, type StructuringTap } from "../pipeline";
import { StructRegistry } from "../structs";

/**
 * End-to-end pipeline tests: instructions in, C-like pseudocode out.
 *
 * Everything else in this directory tests one stage in isolation, which left a
 * real gap — a whole class of defect only shows up in the emitted text. The
 * inverted-condition bug (peek-a-bin-h9v) lived in `structureCFG` for the
 * project's entire history and every stage-level test agreed with it, because
 * they asserted on the IR the buggy code produced.
 *
 * `decompileFunction` takes `Instruction[]`, not bytes, so none of this needs
 * Capstone or a worker — the instruction stream is written out by hand, which
 * also makes the intended semantics explicit rather than trusting a
 * disassembler to agree.
 */

let nextAddr = 0;

/** One instruction. `size` is nominal — only the addresses have to line up. */
function ins(address: number, mnemonic: string, opStr = "", size = 4): Instruction {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

/** Instructions at 4-byte spacing from `start`, so hand-written jump targets stay readable. */
function seq(start: number, rows: [string, string?][]): Instruction[] {
  nextAddr = start;
  return rows.map(([mnemonic, opStr]) => {
    const i = ins(nextAddr, mnemonic, opStr ?? "");
    nextAddr += 4;
    return i;
  });
}

function run(instructions: Instruction[], is64 = false): string {
  const start = instructions[0].address;
  const end =
    instructions[instructions.length - 1].address + instructions[instructions.length - 1].size;
  const func: DisasmFunction = { name: "sub_401000", address: start, size: end - start };
  const xrefMap = new Map<number, Xref[]>();
  const result = decompileFunction(
    func,
    instructions,
    xrefMap,
    null,
    null,
    is64,
    new Map(),
    new Map(),
    new Map(),
    new Map(),
  );
  return result.code;
}

/**
 * As `run`, but with a struct registry (struct synthesis is skipped without
 * one) and an optional import table, so a call can resolve to a real API name.
 */
function runWithStructs(
  instructions: Instruction[],
  iatMap: Map<number, { lib: string; func: string }> = new Map(),
): string {
  const start = instructions[0].address;
  const last = instructions[instructions.length - 1];
  const func: DisasmFunction = {
    name: "sub_401000",
    address: start,
    size: last.address + last.size - start,
  };
  return decompileFunction(
    func,
    instructions,
    new Map<number, Xref[]>(),
    null,
    null,
    false,
    new Map(),
    iatMap,
    new Map(),
    new Map(),
    new StructRegistry(),
  ).code;
}

/**
 * The emitted code with the struct-pointer cast taken off every field access.
 *
 * A field access is emitted as `((struct_0 *)ebx)->field_0x8`, because the base
 * is usually a register and nothing declares a register (see `structPointer` in
 * emit.ts). Assertions about *what* is accessed read better without it; the cast
 * itself is pinned separately, below.
 */
function withoutStructCasts(code: string): string {
  return code.replace(/\(\(struct_\w+ \*\)([^()]*)\)->/g, "$1->");
}

/** The declared type of a field in the emitted `typedef struct` block. */
function declaredType(code: string, fieldName: string): string | undefined {
  const line = code.split("\n").find((l) => l.trim().endsWith(`${fieldName};`));
  return line?.trim().split(/\s+/)[0];
}

/** An import table with one entry, at the address the tests below call through. */
const imports = (func: string) => new Map([[0x402000, { lib: "kernel32.dll", func }]]);

describe("decompileFunction — conditionals reach the output with the right sense", () => {
  // The regression test for peek-a-bin-h9v, written at the level the bug was
  // actually visible at. `je` jumps when ecx == 0, and the jump target is the
  // block that assigns 2. So the guard around "eax = 2" must be `== 0`.
  // Before the fix this emitted `!= 0` with the bodies in the same places,
  // i.e. valid C stating the opposite of the machine code.
  it("guards the jump target with the condition under which the jump is taken", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, 0"],
        ["je", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"], // 0x401010 — reached when ecx == 0
        ["ret"],
      ]),
    );

    const guard = code.split("\n").find((l) => l.includes("if"));
    expect(guard).toBeDefined();
    expect(guard).toContain("== 0");
    expect(guard).not.toContain("!= 0");
  });

  it("emits the opposite sense for the opposite jump", () => {
    // Same shape, `jne` instead of `je`: the target is now reached when
    // ecx != 0, so the guard must flip with it. A pipeline that hard-coded
    // either polarity would fail exactly one of these two tests.
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, 0"],
        ["jne", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    const guard = code.split("\n").find((l) => l.includes("if"));
    expect(guard).toBeDefined();
    expect(guard).toContain("!= 0");
    expect(guard).not.toContain("== 0");
  });

  it("keeps a signed comparison the right way round", () => {
    // `jg` is taken when eax > 5, and 0x401010 is the target.
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["jg", "0x401010"],
        ["mov", "ecx, 1"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
      ]),
    );

    const guard = code.split("\n").find((l) => l.includes("if"));
    expect(guard).toBeDefined();
    expect(guard).toContain(">");
    expect(guard).not.toContain("<=");
  });
});

/**
 * A condition is built from the `cmp`/`test` operands by `extractCondition`,
 * not by the lifter, so for the project's history it went through a private
 * parser that hardcoded a width of 4 and did not know about RIP (peek-a-bin-w6f).
 * Both symptoms are only visible in the emitted text: the IR the buggy parser
 * produced was internally consistent, so every stage-level test agreed with it.
 */
describe("decompileFunction — a condition reads the width the compare wrote", () => {
  it("compares a byte at byte width, not as a 32-bit load", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "byte ptr [rcx], dl"],
        ["jne", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    const guard = code.split("\n").find((l) => l.includes("if"));
    expect(guard).toBeDefined();
    // `cmp byte ptr [rcx], dl` reads one byte. Reading four says the program
    // examines three bytes it never looks at.
    expect(guard).toContain("*(uint8_t*)(rcx)");
    expect(guard).not.toContain("int32_t");
  });

  it("compares a word at word width", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "word ptr [rcx], 0x5a4d"],
        ["jne", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    const guard = code.split("\n").find((l) => l.includes("if"));
    expect(guard).toBeDefined();
    expect(guard).toContain("*(uint16_t*)(rcx)");
    expect(guard).not.toContain("int32_t");
  });

  it("resolves a RIP-relative compare to the address it names", () => {
    // RIP holds the address of the NEXT instruction, so `[rip + 0x100]` at
    // 0x401000 (4 bytes long) is 0x401104. Leaving the text `rip + 0x100` in
    // the output is not an address at all — and `mov eax, dword ptr [rip + …]`
    // in the same function has always resolved, because that goes through the
    // lifter.
    const code = run(
      seq(0x401000, [
        ["cmp", "dword ptr [rip + 0x100], 2"],
        ["jne", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    const guard = code.split("\n").find((l) => l.includes("if"));
    expect(guard).toBeDefined();
    expect(guard).toContain("0x401104");
    expect(guard).not.toContain("rip");
  });

  it("resolves a RIP-relative byte compare at byte width", () => {
    // Both halves of peek-a-bin-w6f at once, which is how the bead met it:
    // `cmp byte ptr [rip + 0x13358], 0`.
    const code = run(
      seq(0x401000, [
        ["cmp", "byte ptr [rip + 0x100], 0"],
        ["jne", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    const guard = code.split("\n").find((l) => l.includes("if"));
    expect(guard).toBeDefined();
    expect(guard).toContain("*(uint8_t*)(0x401104)");
    expect(guard).not.toContain("rip");
  });
});

describe("decompileFunction — output shape", () => {
  it("produces a function signature and a balanced body", () => {
    const code = run(seq(0x401000, [["mov", "eax, 1"], ["ret"]]));

    expect(code).toContain("sub_401000");
    // Whatever the body is, the braces have to balance or the pane shows
    // syntactically broken C.
    const opens = (code.match(/\{/g) ?? []).length;
    const closes = (code.match(/\}/g) ?? []).length;
    expect(opens).toBe(closes);
  });

  it("reports rather than throws when there are no instructions", () => {
    const func: DisasmFunction = { name: "empty", address: 0x401000, size: 0 };
    const result = decompileFunction(
      func,
      [],
      new Map(),
      null,
      null,
      false,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
    );
    expect(result.code).toContain("no instructions");
    expect(result.lineMap).toEqual([]);
  });

  it("returns a line map that points into the emitted text", () => {
    const instructions = seq(0x401000, [
      ["cmp", "ecx, 0"],
      ["je", "0x401010"],
      ["mov", "eax, 1"],
      ["ret"],
      ["mov", "eax, 2"],
      ["ret"],
    ]);
    const func: DisasmFunction = { name: "sub_401000", address: 0x401000, size: 0x18 };
    const result = decompileFunction(
      func,
      instructions,
      new Map(),
      null,
      null,
      false,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
    );

    const lineCount = result.code.split("\n").length;
    for (const [line, addr] of result.lineMap) {
      expect(line).toBeGreaterThanOrEqual(0);
      expect(line).toBeLessThan(lineCount);
      expect(addr).toBeGreaterThanOrEqual(0x401000);
    }
  });
});

/**
 * Struct field types as they reach the reader, in the emitted `typedef struct`
 * block. Every case here declared `PVOID field_0x8;` before peek-a-bin-2kz:
 * struct synthesis turned any pointer-sized field passed to any function, and
 * any field a loaded value was stored into, into a pointer to nothing, whatever
 * else was known about it.
 *
 * `[ebx + 0x10]` is written in each fixture only to give the base its second
 * distinct offset, which is what makes it a struct candidate at all.
 */
describe("decompileFunction — struct field types", () => {
  it("takes the callee parameter type over the pointer guess", () => {
    // Sleep's parameter is a DWORD, so the field it is loaded from is one too.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["push", "dword ptr [ebx + 8]"],
        ["call", "dword ptr [0x402000]"],
        ["ret"],
      ]),
      imports("Sleep"),
    );

    expect(withoutStructCasts(code)).toContain("Sleep(ebx->field_0x8)");
    expect(declaredType(code, "field_0x8")).toBe("uint32_t");
  });

  it("takes a specific parameter type from the callee signature", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["push", "dword ptr [ebx + 8]"],
        ["call", "dword ptr [0x402000]"],
        ["ret"],
      ]),
      imports("CloseHandle"),
    );

    expect(withoutStructCasts(code)).toContain("CloseHandle(ebx->field_0x8)");
    expect(declaredType(code, "field_0x8")).toBe("HANDLE");
  });

  it("still guesses a pointer when the callee is unknown", () => {
    // The retained heuristic: nothing is known about sub_408000's parameters,
    // so a machine word passed to it is still read as an address.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["push", "dword ptr [ebx + 8]"],
        ["call", "0x408000"],
        ["ret"],
      ]),
    );

    expect(withoutStructCasts(code)).toContain("sub_408000(ebx->field_0x8)");
    expect(declaredType(code, "field_0x8")).toBe("PVOID");
  });

  it("does not turn a field-to-field copy of a scalar into a pointer", () => {
    // `ebx->field_0x8 = esi->field_0x4` copies an integer. The value having come
    // from memory says nothing about whether it is an address.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "eax, dword ptr [esi + 4]"],
        ["mov", "dword ptr [ebx + 8], eax"],
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "dword ptr [esi + 0xC], 2"],
        ["ret"],
      ]),
    );

    // Two statements, not one: the `ret` reads EAX too, so the load is a
    // two-use definition and cannot be inlined into the store. The subject
    // here is the *type*, and that is unchanged — see the field-to-field copy
    // in the two lines below.
    const body = withoutStructCasts(code);
    expect(body).toContain("eax = esi->field_0x4;");
    expect(body).toContain("ebx->field_0x8 = eax;");
    expect(declaredType(code, "field_0x8")).toBe("uint32_t");
  });
});

/**
 * How a recovered field access names the object it reads.
 *
 * Struct recovery works out that a register holds a `struct_N *` and the
 * emitter wrote `ebx->field_0x8` — of a register, which nothing declares. That
 * was 1656 `invalid type argument of '->'` errors across three binaries, far
 * the largest category of broken output: the recovery was right and only the
 * spelling was missing.
 *
 * The repair is a cast at the point of use rather than a declaration, and the
 * second test below is why. A register is not a variable — the same register
 * holds a struct pointer on one line and an integer the next — so declaring
 * `struct_1 *rax;` would make C scale the byte offsets written off that
 * register elsewhere by `sizeof(struct_1)`. That version compiles and describes
 * different addresses, which is the failure this project has been bitten by
 * before.
 */
describe("decompileFunction — a field access names its struct", () => {
  const load = (): Instruction[] =>
    seq(0x401000, [
      ["mov", "dword ptr [ebx + 0x10], 1"],
      ["mov", "eax, dword ptr [ebx + 8]"],
      ["ret"],
    ]);

  it("casts the base to the struct, so the access has a type to act on", () => {
    const code = runWithStructs(load());

    expect(code).toContain("((struct_0 *)ebx)->field_0x8");
    // The bare form was not valid C for any base the emitter actually produces.
    expect(code).not.toMatch(/(^|[^)])\bebx->/);
  });

  it("leaves the register itself untyped, so byte offsets off it still mean bytes", () => {
    // `[ebx + ecx]` has no constant offset, so it is not a field and stays a
    // byte-addressed dereference — in the same function, off the same register
    // that carries the struct. Declaring `struct_0 *ebx;` would make C scale
    // that `ecx` by `sizeof(struct_0)`: still valid C, now a different address.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "eax, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], eax"],
        ["mov", "eax, dword ptr [ebx + ecx]"],
        ["ret"],
      ]),
    );

    expect(code).toContain("((struct_0 *)ebx)->field_0x8");
    expect(code).not.toMatch(/^\s*struct_\w+\s*\*\s*ebx;/m);
    expect(code).toContain("*(int32_t*)(ebx + ecx)");
  });

  it("declares every struct it casts to", () => {
    const code = runWithStructs(load());
    const declared = new Set(
      [...code.matchAll(/^typedef struct (struct_\w+) \1;$/gm)].map((m) => m[1]),
    );

    for (const [, id] of code.matchAll(/\(\((struct_\w+) \*\)/g)) expect(declared).toContain(id);
  });

  it("does not cast a base that is already declared as that pointer", () => {
    // The nested case: `esi` is promoted to a variable declared `struct_1*`, so
    // repeating the type at the access site would say nothing new.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["ret"],
      ]),
    );

    // Whether esi ends up declared is up to promotion; if it is, no cast.
    if (/^\s*struct_\w+\s*\*\s*esi;/m.test(code)) {
      expect(code).toContain("esi->field_0x0 = 7");
      expect(code).not.toContain("(struct_1 *)esi");
    } else {
      expect(code).toContain("((struct_1 *)esi)->field_0x0 = 7");
    }
  });
});

/**
 * Nested struct fields, as they reach the reader.
 *
 * The interesting part is what survives folding. A loaded value with one use is
 * substituted into that use and leaves no statement behind — but it also leaves
 * the inner object with one offset, which is not a struct anyway. The cases
 * below are the ones where the load survives *because* the value is used more
 * than once, which is the same condition that makes the inner object a
 * candidate. Nothing else was ever reachable.
 */
describe("decompileFunction — nested struct fields", () => {
  it("declares a field whose value is used as a struct base as a pointer to that struct", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["ret"],
      ]),
    );

    // The two objects, and the load that links them.
    expect(withoutStructCasts(code)).toContain("esi = ebx->field_0x8");
    expect(withoutStructCasts(code)).toContain("esi->field_0x0 = 7");
    // Before this pass, `uint32_t field_0x8;` — the outer declaration said
    // nothing about the object the rest of the function goes on to use.
    expect(declaredType(code, "field_0x8")).toBe("struct_1*");
    // …and struct_1 has to be declared, or the block names a type it never
    // defines.
    expect(code).toContain("struct struct_1 {");
  });

  it("resolves a chain of nestings in one pass", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi + 0x20], 2"],
        ["mov", "edi, dword ptr [esi + 0x24]"],
        ["mov", "dword ptr [edi], 7"],
        ["mov", "dword ptr [edi + 0xC], 9"],
        ["ret"],
      ]),
    );

    expect(declaredType(code, "field_0x8")).toBe("struct_1*");
    expect(declaredType(code, "field_0x24")).toBe("struct_2*");
    expect(code).toContain("struct struct_2 {");
  });

  it("leaves the field alone when the register holds two different objects", () => {
    // ESI is loaded from field 8 and then from field 0x10. The struct grouping
    // is already flow-insensitive enough to pool both objects' accesses; naming
    // either one as field 8's pointee on top of that would be a guess.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["mov", "esi, dword ptr [ebx + 0x10]"],
        ["mov", "dword ptr [esi], 5"],
        ["mov", "dword ptr [esi + 4], 6"],
        ["ret"],
      ]),
    );

    expect(declaredType(code, "field_0x8")).toBe("uint32_t");
    expect(declaredType(code, "field_0x10")).toBe("uint32_t");
  });

  it("keeps the type the callee signature established over the nesting", () => {
    // The field is passed to CloseHandle *and* dereferenced at two offsets. The
    // parameter type is evidence about this field; the dereferences are an
    // inference about the value it happens to hold.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["push", "dword ptr [ebx + 8]"],
        ["call", "dword ptr [0x402000]"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["ret"],
      ]),
      imports("CloseHandle"),
    );

    expect(declaredType(code, "field_0x8")).toBe("HANDLE");
  });

  it("follows a copy of the loaded value to the base actually dereferenced", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "eax, dword ptr [ebx + 8]"],
        ["mov", "esi, eax"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["ret"],
      ]),
    );

    expect(declaredType(code, "field_0x8")).toBe("struct_1*");
  });

  it("emits a self-reference when the inner object shares the outer struct", () => {
    // Both bases are read at offsets 0 and 8, so findOrCreate had already given
    // them one struct on the exact-fingerprint path. Reading a base of that type
    // out of field 8 is the linked-list node, and it is also what that
    // conflation looks like when it is wrong — the nesting makes an existing
    // claim legible rather than adding a new one.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 8], 9"],
        ["ret"],
      ]),
    );

    expect(declaredType(code, "field_0x8")).toBe("struct_0*");
    // One struct, so exactly one definition — the closure must not loop.
    expect(code.match(/^struct struct_\d+ \{$/gm)).toHaveLength(1);
    // …and one forward declaration, which is what makes the self-reference
    // legal C rather than a use of an undeclared type.
    expect(code.match(/^typedef struct struct_\d+ struct_\d+;$/gm)).toHaveLength(1);
  });
});

/**
 * Declaration order in the emitted typedef block.
 *
 * A struct field can point at a struct that is declared later (or, since
 * `IRFunction.typedefs` only snapshots what this function touched, at one that
 * is never declared here at all). The block used to be emitted in registry
 * order with anonymous `typedef struct { ... } struct_N;`, so a forward
 * reference was simply a use of an undeclared type and the output did not
 * compile — t64's sub_14000228C declared a `struct_6*` field inside struct_5,
 * above struct_6. Forward declarations fix that without needing an order,
 * which matters because the self-reference case above has a cycle and no
 * ordering exists for it.
 */
describe("decompileFunction — typedef declaration order", () => {
  it("forward-declares a struct above the field that points at it", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "eax, dword ptr [ebx + 8]"],
        ["mov", "esi, eax"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["ret"],
      ]),
    );

    const forward = code.indexOf("typedef struct struct_1 struct_1;");
    const use = code.indexOf("struct_1* field_0x8;");
    const definition = code.indexOf("struct struct_1 {");

    expect(forward).toBeGreaterThanOrEqual(0);
    expect(use).toBeGreaterThan(forward);
    // The definition genuinely comes after the use — this is the arrangement
    // that did not compile, and the forward declaration is what fixes it.
    expect(definition).toBeGreaterThan(use);
  });

  it("declares every struct name the block mentions", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi + 0x20], 2"],
        ["mov", "edi, dword ptr [esi + 0x24]"],
        ["mov", "dword ptr [edi], 7"],
        ["mov", "dword ptr [edi + 0xC], 9"],
        ["ret"],
      ]),
    );

    const declared = new Set(
      [...code.matchAll(/^typedef struct (struct_\d+) \1;$/gm)].map((m) => m[1]),
    );
    const mentioned = new Set(
      code
        .split("\n")
        .filter((l) => !l.startsWith("typedef struct "))
        .flatMap((l) => l.match(/\bstruct_\d+\b/g) ?? []),
    );
    expect(mentioned.size).toBeGreaterThan(0);
    for (const name of mentioned) expect(declared).toContain(name);
  });
});

/**
 * IOCTL annotation.
 *
 * `isPlausibleIOCTL` is a shape test — device type in `0x01..0x45` or
 * `>= 0x8000`, any function code, any method — which a large share of ordinary
 * 32-bit constants satisfy. Running it over every constant the emitter touched
 * put 782 `IOCTL:` comments into one of pip's console-launcher stubs (40% of
 * its functions), naming devices and function codes that do not exist. The
 * annotation now needs the call site as well as the shape.
 */
describe("decompileFunction — IOCTL annotation", () => {
  it("does not decode a constant that never reaches an IOCTL parameter", () => {
    // 0x4110B0 is a data address in a user-mode image; it decodes as device
    // type 0x41 (BLUETOOTH) purely because of where its bits fall.
    const code = run(
      seq(0x401000, [["push", "0xC"], ["push", "0x4110B0"], ["call", "0x408000"], ["ret"]]),
    );

    expect(code).toContain("sub_408000(0x4110B0, 0xC)");
    expect(code).not.toContain("IOCTL:");
  });

  it("does not decode a constant outside a call at all", () => {
    const code = run(seq(0x401000, [["mov", "eax, 0x412284"], ["ret"]]));

    expect(code).toContain("0x412284");
    expect(code).not.toContain("IOCTL:");
  });

  it("still decodes the control code of a real DeviceIoControl call", () => {
    // The positive case the gate has to keep: 0x222000 is
    // CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS),
    // in the second argument, where DeviceIoControl takes its control code.
    const code = runWithStructs(
      seq(0x401000, [
        // The handle argument has to be *loaded* into ESI, not assumed to be
        // there: `collectArgs32` reads a push of a callee-saved register that
        // this function has not written as a prologue save, because on cdecl
        // and stdcall its entry value belongs to a caller further up and
        // forwarding it would be meaningless (peek-a-bin-6lmh).
        ["mov", "esi, dword ptr [0x403000]"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0x222000"],
        ["push", "esi"],
        ["call", "dword ptr [0x402000]"],
        ["ret"],
      ]),
      imports("DeviceIoControl"),
    );

    expect(code).toContain("0x222000 /* IOCTL: UNKNOWN | Fn=0x800 | BUFFERED */");
  });

  it("leaves the other arguments of that call alone", () => {
    // Same call, with a plausible-looking constant in the input-buffer
    // argument. Only argument 1 is a control code.
    const code = runWithStructs(
      seq(0x401000, [
        // See above: ESI is loaded so the push of it is an argument rather
        // than a register save.
        ["mov", "esi, dword ptr [0x403000]"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0"],
        ["push", "0x4110B0"],
        ["push", "0x222000"],
        ["push", "esi"],
        ["call", "dword ptr [0x402000]"],
        ["ret"],
      ]),
      imports("DeviceIoControl"),
    );

    expect(code).toContain("0x222000 /* IOCTL: UNKNOWN | Fn=0x800 | BUFFERED */");
    // The input buffer keeps its bare value: only argument 1 is a control code.
    expect(code).toContain("0x4110B0,");
    expect(code).not.toContain("0x4110B0 /*");
  });
});

/**
 * What the emitter says when the recovery gave up.
 *
 * Two shapes reached the output claiming more than they had. A condition the
 * lifter could not reconstruct emitted as `if (!)` with a comment where the
 * test belongs — a statement that reads as a recovered branch and states
 * nothing. An instruction with no C form emitted as MSVC's `__asm { ... };`,
 * which is not C outside MSVC. Between them they were the bulk of ~1744 syntax
 * errors across three binaries.
 *
 * Both now say what they are. The unrecovered value becomes a named free
 * variable carrying the original text, declared uninitialised, because that is
 * what it is; the unlifted instruction becomes a comment, because inventing an
 * `__asm__("...")` gcc will syntax-check and then fail to assemble is precisely
 * the "compiles while lying" failure this project has been bitten by.
 */
describe("decompileFunction — what the emitter says when recovery failed", () => {
  /**
   * `rol` writes CF and OF only, so a `jb` after it reads a flag this
   * whole-flags model cannot attribute and the guard has no condition.
   *
   * This was `bt eax, 3 / jb` until peek-a-bin-frt8, which recovers exactly that
   * shape — CF after a `bt` is the selected bit of an unmodified operand, so it
   * is spellable. These three tests are about the *emitter's* placeholder
   * machinery and only ever needed some unrecoverable guard; `rol` is one whose
   * CF really is a function of nothing the IR names. (`bt` with a memory bit
   * base is another, and is asserted as such in `flagModel.test.ts`.)
   */
  const unrecoveredCondition = (): Instruction[] =>
    seq(0x401000, [
      ["rol", "eax, 3"],
      ["jb", "0x401014"],
      ["mov", "ecx, 1"],
      ["ret"],
      ["mov", "ecx, 2"], // 0x401010
      ["ret"],
    ]);

  it("names the unrecovered condition instead of emitting an empty test", () => {
    const code = run(unrecoveredCondition());
    const guard = code.split("\n").find((l) => l.includes("if ("));

    expect(guard).toBeDefined();
    // The old output: `if (!/* jb */)`, which is not an expression at all.
    expect(guard).not.toMatch(/if \(!?\s*\/\*[^*]*\*\/\s*\)/);
    expect(guard).toMatch(/__unrecovered_\d+/);
    // The mnemonic that produced it stays where the reader is looking.
    expect(guard).toContain("jb");
  });

  it("declares the placeholder, so the reader is told and the C stays valid", () => {
    const code = run(unrecoveredCondition());

    expect(code).toMatch(/^ +intptr_t __unrecovered_1; \/\* not recovered: jb \*\/$/m);
  });

  it("gives two unrecovered values two names, since they are two facts", () => {
    const code = run(
      seq(0x401000, [
        ["rol", "eax, 3"],
        ["jb", "0x401014"],
        ["mov", "ecx, 1"],
        ["jmp", "0x401018"],
        ["mov", "ecx, 2"], // 0x401010
        ["rol", "edx, 1"], // 0x401014
        ["jb", "0x401028"],
        ["mov", "esi, 3"],
        ["ret"],
        ["mov", "esi, 4"], // 0x401028
        ["ret"],
      ]),
    );

    expect(code).toContain("__unrecovered_1");
    expect(code).toContain("__unrecovered_2");
    // Two declarations, not one shared name asserting the two tests are equal.
    expect(code.match(/^ +intptr_t __unrecovered_\d+;/gm)).toHaveLength(2);
  });

  it("reports an unlifted instruction as a comment rather than as MSVC asm", () => {
    // `leave` has no C form and no operands to lift.
    const code = run(seq(0x401000, [["push", "ebp"], ["mov", "ebp, esp"], ["leave"], ["ret"]]));

    expect(code).not.toContain("__asm");
    expect(code).toMatch(/\/\* unlifted: leave *\*\/;/);
  });

  it("keeps the operands of an unlifted instruction verbatim", () => {
    const code = run(
      seq(0x401000, [["rep movsd", "dword ptr es:[edi], dword ptr [esi]"], ["ret"]]),
    );

    expect(code).toContain("/* unlifted: rep movsd dword ptr es:[edi], dword ptr [esi] */;");
  });

  it("still gives a trailing label the empty statement it needs", () => {
    // cleanup.ts asks for that with an empty `raw`, which is not an unlifted
    // instruction and must not be reported as one.
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 1"],
        ["jne", "0x401018"],
        ["cmp", "ebx, 2"],
        ["je", "0x401020"],
        ["call", "0x402010"],
        ["ret"],
        ["call", "0x402000"], // 401018
        ["jmp", "0x401028"],
        ["call", "0x402014"], // 401020
        ["jmp", "0x401030"],
        ["nop"], // 401028
        ["jmp", "0x401010"],
        ["call", "0x402008"], // 401030
        ["jmp", "0x401028"],
      ]),
    );
    const lines = code.split("\n");
    const at = lines.findIndex((l) => l.trim() === "loc_401028:");

    expect(at).toBeGreaterThan(-1);
    expect(lines[at + 1].trim()).toBe(";");
  });
});

/**
 * Branches whose flags come from arithmetic rather than from `cmp`/`test`.
 *
 * `dec ecx / jnz`, `sub eax, ebx / je` and `and eax, 3 / je` are ordinary
 * compiler output that `extractCondition` could not read at all: 606 blocks
 * across the three reference binaries, every one emitting `__unrecovered_N`
 * (peek-a-bin-b531).
 *
 * x86 sets the flags from the **result**, so the condition names the
 * destination *after* the instruction ran — `dec ecx / jnz` repeats while the
 * decremented `ecx` is non-zero. Naming the operands instead would state the
 * same test one iteration early, which is the peek-a-bin-h9v class of defect:
 * valid C that disagrees with the machine. Each case below is asserted on the
 * emitted text for that reason.
 *
 * Only ZF and SF are functions of the result, so only the Jcc forms that read
 * one of them and nothing else are recovered. The cases that stay
 * `__unrecovered_N` are here too — that mechanism exists so that ignorance is
 * visible rather than guessed at.
 */
describe("decompileFunction — conditions from flag-setting arithmetic", () => {
  it("reads a `dec` counter loop as the decremented value", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, 10"],
        ["mov", "eax, 0"],
        ["add", "eax, ecx"], // 0x401008 — loop top
        ["dec", "ecx"],
        ["jne", "0x401008"],
        ["ret"],
      ]),
    );

    // `jne` is taken while ZF is clear, i.e. while the *decremented* ecx is
    // non-zero, and the decrement is inside the body above the test.
    expect(code).toContain("ecx--;");
    expect(code).toMatch(/\}\s*while \(ecx != 0\);/);
    expect(code).not.toContain("__unrecovered");
  });

  it("reads `sub` + `je` as the difference being zero", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, ecx"],
        ["sub", "eax, edx"],
        ["je", "0x401014"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401014 — the jump target
        ["ret"],
      ]),
    );

    // The guard is the jump target's, so it is the un-negated taken sense.
    expect(code).toContain("if (eax == 0) {");
    expect(code).not.toContain("__unrecovered");
  });

  it("reads `and` + `je` as the masked value being zero", () => {
    const code = run(
      seq(0x401000, [
        ["and", "eax, 3"],
        ["je", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    // `eax` has been masked by the time the test runs, so `eax == 0` *is*
    // `(eax_before & 3) == 0` — and the mask is right there above the guard.
    expect(code).toContain("eax &= 3;");
    expect(code).toContain("if (eax == 0) {");
    expect(code).not.toContain("__unrecovered");
  });

  it("reads the `or reg, reg` zero-test idiom", () => {
    const code = run(
      seq(0x401000, [
        ["or", "eax, eax"],
        ["jne", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).toContain("if (eax != 0) {");
    expect(code).not.toContain("__unrecovered");
  });

  it("reads `inc` + `je` as the incremented value being zero", () => {
    const code = run(
      seq(0x401000, [
        ["inc", "eax"],
        ["je", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).toContain("eax++;");
    expect(code).toContain("if (eax == 0) {");
  });

  it("reads `xor` + `jne` as the exclusive-or being non-zero", () => {
    const code = run(
      seq(0x401000, [
        ["xor", "eax, edx"],
        ["jne", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).toContain("if (eax != 0) {");
  });

  it("reads `neg` + `je` as the negated value being zero", () => {
    const code = run(
      seq(0x401000, [
        ["neg", "eax"],
        ["je", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).toContain("if (eax == 0) {");
  });

  it("reads `js` after arithmetic as the result's sign", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "eax"],
        ["js", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    // SF is the top bit of the result, so `js` is exactly "the decremented
    // value is negative".
    expect(code).toContain("if (eax < 0) {");
  });

  it("reads a shift by an immediate, which sets ZF from its result", () => {
    const code = run(
      seq(0x401000, [
        ["shr", "eax, 2"],
        ["jne", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).toContain("if (eax != 0) {");
  });

  it("leaves a shift by CL unrecovered, since a count of 0 sets no flags", () => {
    const code = run(
      seq(0x401000, [
        ["shr", "eax, cl"],
        ["jne", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    // `shr eax, cl` with cl == 0 leaves the flags to whatever set them last,
    // which is not in this block. Guessing would be a guard that is right most
    // of the time, which is the worst kind.
    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jne \*\/\)/);
  });

  it("leaves `sub` + `jl` unrecovered, since a signed compare reads OF too", () => {
    const code = run(
      seq(0x401000, [
        ["sub", "eax, edx"],
        ["jl", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    // `jl` is SF != OF, which is `eax_before < edx` signed — and that is not
    // `result < 0`: the two disagree exactly when the subtraction overflowed.
    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jl \*\/\)/);
  });

  it("leaves the condition unrecovered when a call sits between it and the Jcc", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "ecx"],
        ["call", "0x402000"],
        ["jne", "0x401014"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401014
        ["ret"],
      ]),
    );

    // The callee's flags are what the `jne` reads, and nothing here knows them.
    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jne \*\/\)/);
  });

  it("leaves the condition unrecovered when the result register is overwritten", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "ecx"],
        ["mov", "ecx, edx"],
        ["jne", "0x401014"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401014
        ["ret"],
      ]),
    );

    // `ecx` no longer holds the decremented value where the guard would read
    // it, so naming it would state a different test entirely.
    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jne \*\/\)/);
  });

  it("refuses a shift whose count masks to zero", () => {
    // `shl eax, 0x20` shifts a 32-bit destination by `0x20 & 0x1f == 0`: it is
    // a no-op that writes no flag, so the `jne` is reading whatever set them
    // earlier. The backward walk asked only whether the count was a non-zero
    // immediate and emitted `if (eax != 0)` — a test on a value the machine
    // never derived flags from. `flagModel.ts` applies the mask, so the guard
    // is refused instead (peek-a-bin-c33 stage 4).
    const code = run(
      seq(0x401000, [
        ["shl", "eax, 0x20"],
        ["jne", "0x401010"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jne \*\/\)/);
    expect(code).not.toMatch(/eax != 0/);
  });

  it("answers a 64-bit shift by the same count, which really does shift", () => {
    const code = run(
      seq(0x401000, [
        ["shl", "rax, 0x20"],
        ["jne", "0x401010"],
        ["mov", "rbx, 1"],
        ["ret"],
        ["mov", "rbx, 2"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toContain("if (rax != 0)");
  });

  it("keeps a result nothing else reads, so the condition survives DCE", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "ecx"],
        ["jne", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    // The only reader of `ecx` here is the flags. When the flags were not in
    // the IR, dead-code elimination deleted the decrement and the guard it
    // would have been read from went with it — 190 of the remaining
    // unrecovered branches across the three reference binaries had that one
    // cause (peek-a-bin-pu06). It was fixed twice: first by `ssaopt.ts` holding
    // the definition live by hand off `flagResultSetter`, and then properly, by
    // `liftBlock` building an `IRBranch` whose condition reads `ecx` — so the
    // decrement has an ordinary counted use and the hand-holding is gone
    // (peek-a-bin-c33 stage 4).
    expect(code).toContain("ecx--");
    expect(code).toMatch(/if \(ecx != 0\)/);
    expect(code).not.toContain("__unrecovered_");
  });

  it("still reads the `cmp` when a block has both arithmetic and a compare", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "ecx"],
        ["cmp", "ecx, 5"],
        ["jne", "0x401014"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401014
        ["ret"],
      ]),
    );

    // The `cmp` is what the `jne` reads; the `dec` before it is not.
    expect(code).toContain("if (ecx != 5) {");
  });

  // The protection DCE applies is keyed off the same predicate the structurer
  // uses, so these pin the edges of that predicate end to end rather than the
  // protection in isolation — a def held live that the structurer then declines
  // to name is a statement nobody reads, appearing in the emitted C for no
  // reason (peek-a-bin-pu06).
  it("recovers each flag-setting form whose result nothing else reads", () => {
    for (const [mn, ops, guard] of [
      ["dec", "ecx", "ecx != 0"],
      ["sub", "ecx, edx", "ecx != 0"],
      ["and", "ecx, 3", "ecx != 0"],
      ["or", "ecx, ecx", "ecx != 0"],
      ["xor", "ecx, edx", "ecx != 0"],
      ["shr", "ecx, 2", "ecx != 0"],
    ] as const) {
      const code = run(
        seq(0x401000, [
          [mn, ops],
          ["jne", "0x401010"],
          ["mov", "esi, 1"],
          ["ret"],
          ["mov", "esi, 2"], // 0x401010
          ["ret"],
        ]),
      );
      expect(code, `${mn} ${ops}`).toMatch(new RegExp(`if \\(${guard.replace(/[!]/g, "\\!")}\\)`));
      expect(code, `${mn} ${ops}`).not.toContain("__unrecovered_");
    }
  });

  it("does not hold a definition live for a Jcc the result cannot answer", () => {
    // `jb` reads CF, which is not a function of the result, so the structurer
    // declines it. Protecting the `sub` anyway would resurrect a statement
    // nothing reads into the output.
    const code = run(
      seq(0x401000, [
        ["sub", "ecx, edx"],
        ["jb", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jb \*\/\)/);
    expect(code).not.toMatch(/^\s*ecx\b.*=/m);
  });

  it("does not hold a definition live when a shift count could be zero", () => {
    // `shl eax, cl` with cl == 0 leaves the flags to an earlier instruction.
    const code = run(
      seq(0x401000, [
        ["shl", "ecx, cl"],
        ["jne", "0x401010"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jne \*\/\)/);
  });

  it("declines when the result is overwritten by a dead instruction", () => {
    // The overwriting `mov` is itself dead, so dead-code elimination drops it
    // on its first iteration and the `dec` becomes the block's last write to
    // ECX on the second. Deciding protection from the *instructions* rather
    // than the in-flight IR is what keeps this answer independent of which
    // iteration asked — the machine still puts EDX in ECX before the branch.
    const code = run(
      seq(0x401000, [
        ["dec", "ecx"],
        ["mov", "ecx, edx"],
        ["jne", "0x401014"],
        ["mov", "esi, 1"],
        ["ret"],
        ["mov", "esi, 2"], // 0x401014
        ["ret"],
      ]),
    );

    expect(code).toMatch(/if \(__unrecovered_\d+ \/\* jne \*\/\)/);
    expect(code).not.toContain("ecx--");
  });
});

/**
 * Indirect calls, which are calls through a value rather than to a name.
 *
 * The lifter names the target `*esi`, and emitting that verbatim asked C to
 * dereference an integer — 314 errors across three binaries once the field
 * accesses stopped hiding them, in 70 functions that had nothing else wrong.
 */
describe("decompileFunction — indirect calls", () => {
  it("says what is being called through, instead of dereferencing an integer", () => {
    const code = run(seq(0x401000, [["mov", "esi, 0x402000"], ["call", "esi"], ["ret"]]));

    expect(code).not.toMatch(/\(\*\w+\)\(/);
    expect(code).toContain("((intptr_t (*)())esi)(");
  });

  it("leaves a direct call to a name alone", () => {
    const code = run(seq(0x401000, [["call", "0x408000"], ["ret"]]));

    expect(code).toContain("sub_408000()");
    expect(code).not.toContain("intptr_t (*)()");
  });

  it("reports a target it could not parse rather than pasting the operand in", () => {
    const code = run(seq(0x401000, [["call", "dword ptr [ebp + 8]"], ["ret"]]));

    expect(code).not.toContain("dword ptr [ebp + 8])(");
    expect(code).toMatch(
      /\(\(intptr_t \(\*\)\(\)\)__unrecovered_\d+ \/\* dword ptr \[ebp \+ 8\] \*\/\)/,
    );
  });
});

/**
 * A test the machine makes that the output does not state at all.
 *
 * This is the class the polarity audit is blind to (peek-a-bin-lbz): a guard
 * that states one of two tests and drops the other passes every polarity check,
 * because the operator it does state matches its own jcc. The way it happens in
 * practice is a `jcc` whose target lies past the end of the detected function —
 * `buildCFG` draws no edge for it, so the block has one successor and reads as
 * unconditional. `t32!sub_4031A4` loses four that way, two of them inside a
 * loop, and emitted `do { …; LeaveCriticalSection(…); } while (1)`: an
 * unconditional call inside a loop the reader is told never ends.
 *
 * The transfer cannot be spelled — there is no label in this function to `goto`
 * and no function to call — so the arm is a comment. The test itself is what
 * matters: without it the decision is not in the output in any form.
 */
describe("decompileFunction — a branch out of the function is still a decision", () => {
  it("states the test of a conditional jump whose target is outside the function", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "esi, 0x40"], // 0x401000
        ["jge", "0x409000"], // 0x401004 — far past the end of this function
        ["mov", "eax, 1"], // 0x401008
        ["ret"], // 0x40100c
      ]),
    );

    const guard = code.split("\n").find((l) => l.includes("if ("));
    expect(guard).toBeDefined();
    // `jge` is taken when esi >= 0x40, and the taken side is what leaves.
    expect(guard).toContain(">= 0x40");
    expect(code).toContain("0x409000");
  });

  it("says nothing extra when the CFG does have the edge", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "esi, 0x40"],
        ["jge", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"], // 0x401010 — a real block, so a real edge
        ["ret"],
      ]),
    );

    expect(code).not.toContain("outside this function");
  });
});

/**
 * Code no CFG edge reaches is still code.
 *
 * An MSVC exception funclet — an `__except`/`__finally` continuation on x64, a
 * 32-bit SEH scope handler — is entered by the unwinder, so it has no
 * predecessor and sits past a `ret`. `structureCFG`'s leftover pass used to
 * require reachability from the entry, on the grounds that anything else is
 * alignment padding; what it actually excluded was 1160 blocks of real code
 * across the corpus, taking 59 `call` sites with it (peek-a-bin-d3z).
 * `t64!sub_140004104` is 95 instructions with 20 calls, and exactly the two in
 * its funclet went missing.
 *
 * Padding is still excluded, by the test that was already there: a block that
 * lifts to no statements is not resurrected.
 */
describe("decompileFunction — an unreachable block still reaches the output", () => {
  it("names a call only an exception funclet makes", () => {
    const code = run(
      seq(0x401000, [
        ["call", "0x401100"], // 0x401000
        ["ret"], // 0x401004
        ["call", "0x401200"], // 0x401008 — no edge reaches this
        ["ret"], // 0x40100c
      ]),
    );

    expect(code).toContain("sub_401100()");
    // A reader of the old output concluded the program never calls this.
    expect(code).toContain("sub_401200()");
  });

  it("introduces it by its own label, rather than falling into it past the ret", () => {
    const code = run(seq(0x401000, [["call", "0x401100"], ["ret"], ["call", "0x401200"], ["ret"]]));

    const lines = code.split("\n").map((l) => l.trim());
    const label = lines.indexOf("loc_401008:");
    expect(label).toBeGreaterThan(-1);
    // The label comes after the first block's `ret`, so nothing suggests
    // control falls through into it.
    expect(lines.slice(0, label).some((l) => l.startsWith("return"))).toBe(true);
    expect(lines.slice(label).some((l) => l.includes("sub_401200()"))).toBe(true);
  });

  it("leaves a block that lifts to nothing alone", () => {
    const code = run(
      seq(0x401000, [
        ["call", "0x401100"], // 0x401000
        ["ret"], // 0x401004
        ["nop"], // 0x401008 — padding, unreachable and empty
        ["nop"], // 0x40100c
      ]),
    );

    expect(code).not.toContain("loc_401008");
  });
});

/**
 * Tail calls — a `jmp` that leaves the function.
 *
 * `buildCFG` gives such a jmp no successor, and the lifter used to skip every
 * `j*` mnemonic, so the call the program makes did not appear anywhere in the
 * output. The argument set-up above it was then deleted as unread, which is
 * why `t64!sub_140002680` — `mov rcx, [rip+0x14a82] / add rsp,0x28 / jmp
 * 0x140002208` — emitted a body that appears to do nothing at the end
 * (peek-a-bin-22t). A reader of that output concludes the code does not call
 * it, which is worse than ugly output.
 *
 * A tail call is `call` plus `ret` with the return address reused, so it lifts
 * to exactly what this file already asserts for that pair.
 */
describe("decompileFunction — a tail call is a call", () => {
  /** As `run`, 64-bit, with an import table so a `jmp [rip+..]` can name an API. */
  function run64WithIat(
    instructions: Instruction[],
    iatMap: Map<number, { lib: string; func: string }>,
  ): string {
    const start = instructions[0].address;
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: start,
      size: last.address + last.size - start,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      true,
      new Map(),
      iatMap,
      new Map(),
      new Map(),
    ).code;
  }

  it("names the function a direct tail jmp transfers to", () => {
    const code = run(
      seq(0x401000, [
        ["sub", "rsp, 0x28"],
        ["add", "rsp, 0x28"],
        ["jmp", "0x401100"],
      ]),
      true,
    );

    expect(code).toContain("sub_401100(");
  });

  it("keeps the argument the tail call was given, which died as unread before", () => {
    // The shape of t64!sub_140002680: the argument register is loaded, the
    // frame is torn down, and control leaves by `jmp`.
    const code = run(
      seq(0x401000, [
        ["sub", "rsp, 0x28"],
        ["mov", "rcx, 5"],
        ["add", "rsp, 0x28"],
        ["jmp", "0x401100"],
      ]),
      true,
    );

    expect(code).toContain("sub_401100(5)");
  });

  it("names the import a tail jmp through the IAT reaches", () => {
    // `jmp qword ptr [rip + 0x100]` at 0x401004, size 4 → 0x401004 + 4 + 0x100.
    const iat = new Map([[0x401108, { lib: "KERNEL32.dll", func: "EnterCriticalSection" }]]);
    const code = run64WithIat(
      [ins(0x401000, "lea", "rcx, [rdx + 0x30]"), ins(0x401004, "jmp", "qword ptr [rip + 0x100]")],
      iat,
    );

    expect(code).toContain("EnterCriticalSection(");
    expect(code).not.toContain("rip + 0x100");
  });

  it("emits the tail call on the taken side of a branch, whose body looked dropped", () => {
    // t64!sub_14000270C: the `jge` arm is `lea rcx,[rdx+0x30]; jmp
    // EnterCriticalSection`, an unlifted tail call, so that arm emitted nothing.
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, 0x14"], // 0x401000
        ["jge", "0x401010"], // 0x401004
        ["call", "0x407908"], // 0x401008
        ["ret"], // 0x40100c
        ["lea", "rcx, [rdx + 0x30]"], // 0x401010
        ["jmp", "0x401200"], // 0x401014
      ]),
      true,
    );

    expect(code).toContain("sub_401200(");
    expect(code).toContain("sub_407908(");
  });

  it("calls the function a 32-bit tail jmp transfers to", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, 1"],
        ["jmp", "0x401100"],
      ]),
    );

    expect(code).toContain("sub_401100(");
  });

  it("does not call a jmp that stays inside the function", () => {
    // This jmp has a successor, so it is ordinary control flow, not a call.
    const code = run(
      seq(0x401000, [["mov", "eax, 1"], ["jmp", "0x40100c"], ["mov", "eax, 2"], ["ret"]]),
    );

    expect(code).not.toContain("sub_40100C");
    expect(code).not.toContain("0x40100c(");
  });

  it("does not invent a callee for an indirect tail jmp", () => {
    // `jmp eax` also ends a successorless block, but the disassembly names no
    // target — an unrecovered jump-table dispatch looks exactly like this.
    const code = run(
      seq(0x401000, [
        ["mov", "eax, 1"],
        ["jmp", "eax"],
      ]),
    );

    expect(code).not.toContain("(*eax)");
    expect(code).not.toMatch(/\beax\(/);
  });

  /**
   * …but it does say the transfer is there.
   *
   * Refusing to name the callee is right; emitting nothing at all is a
   * different claim, and a false one. t32!sub_402C5A is the measured case: it
   * decodes a pointer and the emitted C then does nothing whatever with it,
   * because the `jmp eax` through the decoded pointer was absent. Four sites
   * corpus-wide at cee6f91, all 32-bit (peek-a-bin-xerm).
   */
  it("says a transfer happens at an indirect tail jmp, naming the register", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, 1"],
        ["jmp", "eax"],
      ]),
    );

    expect(code).toContain("indirect jmp through eax");
    // Still no invented callee.
    expect(code).not.toMatch(/\beax\(/);
  });

  it("reports the indirect transfer in the shape of t32!sub_402C5A", () => {
    // `DecodePointer` is called, and the non-zero path jumps through the
    // result. That path used to emit nothing at all.
    const code = run(
      seq(0x401000, [
        ["call", "dword ptr [0x40f090]"], // 0x401000
        ["test", "eax, eax"], // 0x401004
        ["je", "0x401010"], // 0x401008
        ["jmp", "eax"], // 0x40100c
        ["call", "0x402c35"], // 0x401010
        ["ret"], // 0x401014
      ]),
    );

    expect(code).toContain("indirect jmp through eax");
    expect(code).toContain("sub_402C35(");
  });

  it("stays silent at an unrecovered jump-table dispatch", () => {
    // `jmp dword ptr [ecx*4 + 0x40b900]` — 14 of the 18 silent sites, and the
    // property that separates them from the 4 above is the operand shape: a
    // bare register versus a memory reference. A table whose entries WERE
    // recovered never reaches this code, because its case targets are block
    // leaders and the dispatch block then has successors.
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, 1"],
        ["jmp", "dword ptr [ecx*4 + 0x40b900]"],
      ]),
    );

    expect(code).not.toContain("indirect jmp through");
    expect(code).not.toContain("unlifted");
  });

  it("leaves a nameable tail jmp as the call it already was", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, 1"],
        ["jmp", "0x401100"],
      ]),
    );

    expect(code).toContain("sub_401100(");
    expect(code).not.toContain("indirect jmp through");
  });
});

/**
 * String literals, judged as C literals rather than as display text.
 *
 * The emitter escaped `"` and nothing else, which is the half of the job that
 * well-behaved sample data shows you. Recovered strings are bytes out of a
 * hostile file: `<launcher_dir>\` is a real string in every distlib launcher,
 * and its trailing backslash escaped the closing quote, so the literal ran on
 * into the rest of the line (8 "missing terminating quote" errors and 2 stray
 * backslashes across three binaries).
 */
describe("decompileFunction — string literals", () => {
  /** As `run`, but with a string table, so a constant can resolve to a literal. */
  function runWithStrings(instructions: Instruction[], strings: Map<number, string>): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      new Map(),
      new Map(),
      strings,
      new Map(),
    ).code;
  }

  /** The one emitted line that carries the literal. */
  function literalLine(code: string): string {
    return code.split("\n").find((l) => l.includes('"')) ?? "";
  }

  const load = (s: string) =>
    literalLine(
      runWithStrings(seq(0x401000, [["mov", "eax, 0x403000"], ["ret"]]), new Map([[0x403000, s]])),
    );

  it("escapes a trailing backslash instead of escaping the closing quote", () => {
    const line = load("<launcher_dir>\\");

    expect(line).toContain('"<launcher_dir>\\\\"');
    // The quote count is what gcc's tokeniser is really doing: an odd number
    // means the literal never closed.
    expect(line.split('"').length - 1).toBe(2);
  });

  it("escapes an embedded quote and backslash separately", () => {
    expect(load('say "hi"\\now')).toContain('"say \\"hi\\"\\\\now"');
  });

  it("escapes a newline rather than emitting a line break inside the literal", () => {
    const line = load("a\r\nb\tc");

    expect(line).toContain('"a\\r\\nb\\tc"');
    expect(line).not.toContain("\n");
  });

  it("spells a control byte in octal, which cannot absorb the digit after it", () => {
    // `\x1` followed by a literal `1` would be read back as `\x11`: C's hex
    // escapes are greedy, three-digit octal is not.
    expect(load("a\x0111b")).toContain('"a\\001' + '11b"');
  });

  it("keeps a high byte as one byte", () => {
    expect(load("café")).toContain('"caf\\351"');
  });

  it("breaks up a trigraph", () => {
    expect(load("what??!")).toContain('"what?\\?!"');
  });
});

/**
 * Control-flow structuring, judged on the emitted C.
 *
 * `detectLoops` used to declare a back edge from BFS layers ("the successor is
 * on my layer or above"), which is true of the merge block of every `if`
 * without an `else`: the branch reaches the merge in one edge and so does the
 * fallthrough body, so both sit on layer 1 and the body → merge edge looked
 * like a loop. A diamond is immune — its merge lands on layer 2 — which is why
 * hand-written fixtures never caught it, while ~86% of the loops reported on
 * three real MSVC binaries turned out not to exist (peek-a-bin-lrs).
 *
 * These shapes are written as instruction streams because the defect is only
 * visible in the emitted text: the guard around a conditional store was
 * *dropped* and the store became unconditional, which no stage-level assertion
 * on the IR would have noticed.
 */
describe("decompileFunction — control-flow structuring", () => {
  /** All `if`/`while`/`for`/`do` lines, trimmed, in order. */
  function controlLines(code: string): string[] {
    return code
      .split("\n")
      .map((l) => l.trim())
      .filter((l) => /^(\}\s*)?(else\b|if \(|while \(|for \(|do \{)/.test(l));
  }

  it("keeps the guard on an if without an else, and invents no loop", () => {
    // test ecx, ecx / je merge  → the store runs only when ecx != 0.
    const code = run(
      seq(0x401000, [
        ["test", "ecx, ecx"],
        ["je", "0x401014"],
        ["mov", "edx, 5"],
        ["mov", "dword ptr [ecx], edx"],
        ["xor", "eax, eax"],
        ["ret"], // 0x401014 — the merge, reached both ways
      ]),
    );

    // `je` is taken when ecx == 0 and the taken path skips the store, so the
    // store's guard is the negation: ecx != 0.
    expect(code).toContain("if (ecx != 0)");
    const guarded = code.slice(code.indexOf("if (ecx != 0)"));
    expect(guarded).toContain("= 5;");
    expect(code).not.toMatch(/\bwhile\b|\bdo\b/);
  });

  it("keeps both arms of an if/else", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, 0"],
        ["je", "0x401014"],
        ["mov", "eax, 1"],
        ["jmp", "0x401018"],
        ["mov", "eax, 2"],
        ["mov", "eax, 3"], // 0x401014 — the `je` target
        ["ret"], // 0x401018 — the merge
      ]),
    );

    expect(controlLines(code)).toEqual(["if (ecx == 0) {", "} else {"]);
    expect(code).not.toMatch(/\bwhile\b|\bdo\b/);
  });

  it("still finds a genuine pre-tested loop", () => {
    //   0x401004 cmp ecx, 8      ← header, dominates the latch below
    //   0x401008 jge exit
    //   0x40100c inc ecx
    //   0x401010 jmp 0x401004    ← back edge
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, 0"],
        ["cmp", "ecx, 8"],
        ["jge", "0x401014"],
        ["inc", "ecx"],
        ["jmp", "0x401004"],
        ["ret"],
      ]),
    );

    // `jge` leaves the loop, so iteration continues while ecx < 8. Either
    // spelling of the loop carries that: the induction variable is recognised
    // here, so it comes out as a `for` whenever the initialisation ends up
    // adjacent to the loop — which it does once the phi's `ecx = ecx` self-copy
    // is no longer emitted between the two.
    expect(code).toMatch(/(while \(ecx < 8\)|for \(ecx = 0; ecx < 8; ecx\+\+\))/);
    expect(code).not.toContain("ecx >= 8");
  });

  it("still finds a genuine bottom-tested loop", () => {
    //   0x401004 inc eax         ← header; the jl below jumps back to it
    //   0x401008 cmp eax, 5
    //   0x40100c jl  0x401004    ← back edge
    const code = run(
      seq(0x401000, [
        ["xor", "eax, eax"],
        ["inc", "eax"],
        ["cmp", "eax, 5"],
        ["jl", "0x401004"],
        ["ret"],
      ]),
    );

    // `do`/`while`, not `while`: the increment is in the header, so it runs
    // before the test on every iteration including the first. `while (eax < 5)
    // { eax++; }` would test the value the increment has not produced yet, and
    // would run the increment one time fewer than the machine does.
    // `controlLines` counts `do {` and `} while (…);` separately.
    const loop = controlLines(code);
    expect(loop).toEqual(["do {", "} while (eax < 5);"]);
    // The increment has to survive, in either spelling emit.ts uses for it.
    expect(code).toMatch(/(eax\+\+|eax \+= 1|= eax \+ 1)/);
  });

  it("keeps the back-edge test of a loop that also leaves from its header", () => {
    // The `WriteFile` retry shape of t64 `sub_14000D8C4` / w64 `sub_14000BD44`
    // (peek-a-bin-jlo), reduced. The loop has two exits and continues only when
    // *both* tests say so:
    //
    //   0x401004 mov  [ebp-4], 3     ← header: the work (the `WriteFile` call)
    //   0x401008 test eax, eax
    //   0x40100c je   0x40101c       ← leaves when eax == 0
    //   0x401010 add  esi, 4
    //   0x401014 cmp  edi, esi
    //   0x401018 jg   0x401004       ← back edge: repeats while edi > esi
    //   0x40101c ret                   both exits land here
    //
    // The emitted loop said `while (eax != 0)` and stopped there: the body
    // ended, the loop repeated, and `edi > esi` appeared nowhere inside it. C
    // that claims the loop runs again on `eax != 0` alone.
    const code = run(
      seq(0x401000, [
        ["xor", "esi, esi"],
        ["mov", "dword ptr [ebp - 4], 3"], // 0x401004 — header
        ["test", "eax, eax"],
        ["je", "0x40101c"],
        ["add", "esi, 4"], // 0x401010
        ["cmp", "edi, esi"],
        ["jg", "0x401004"],
        ["mov", "edx, 1"], // 0x40101c
        ["ret"],
      ]),
    );

    // Both tests are inside the loop, and the loop repeats only when both hold.
    expect(code).toMatch(/if \(edi <= esi\) \{\n\s+break;/);
    expect(code).toMatch(/if \(eax == 0\) \{\n\s+break;/);
    // …and the one thing it must never say is that `eax` alone decides.
    expect(code).not.toMatch(/while \(eax != 0\) \{/);
  });

  it("does not take a header test whose arms both stay in the loop as the loop test", () => {
    // t32 `sub_40A702` / `sub_40C2E3` / `sub_4052AE` (peek-a-bin-bhh): the
    // block the back edge lands on ends in a branch that picks between two
    // places *inside* the body. It decides nothing about whether there is
    // another iteration, and reading it as the loop's test produced
    // `while (edi >= ecx)` for a loop the machine runs while `edx < esi`.
    //
    //   0x401004 cmp  edi, ecx      ← header, both arms below stay in the loop
    //   0x401008 jb   0x401014
    //   0x40100c mov  [edi], 7
    //   0x401010 jmp  0x401014
    //   0x401014 inc  edx
    //   0x401018 cmp  edx, esi
    //   0x40101c jb   0x401004      ← back edge: the real test
    const code = run(
      seq(0x401000, [
        ["xor", "edx, edx"],
        ["cmp", "edi, ecx"], // 0x401004 — header
        ["jb", "0x401014"],
        ["mov", "dword ptr [edi], 7"], // 0x40100c
        ["jmp", "0x401014"],
        ["inc", "edx"], // 0x401014
        ["cmp", "edx, esi"],
        ["jb", "0x401004"],
        ["ret"], // 0x401020
      ]),
    );

    // The loop test is the back edge's, and it is not negated.
    expect(code).toMatch(/\} while \(edx < esi\);/);
    // The header's comparison is a guard inside the body — never the loop's
    // own condition, in either polarity.
    expect(code).not.toMatch(/(while|for) \([^)]*edi[^)]*\)/);
    // `jb` skips the store, so the store runs when edi >= ecx, and it still
    // runs conditionally.
    expect(code).toMatch(/if \(edi >= ecx\) \{\n\s+\*\(int32_t\*\)\(edi\) = 7;/);
  });

  it("does not test a header's own statements before running them", () => {
    // The `while ((c = *p) != 0)` shape: the header loads the byte the test
    // looks at, so `while (al != 0) { al = *rbx; … }` guards the first
    // iteration on whatever `al` held *before* the loop, and stops running the
    // load one iteration early. w64 `sub_140009740` (peek-a-bin-bhh).
    //
    //   0x401004 mov  al, [esi]     ← header does work…
    //   0x401008 test al, al
    //   0x40100c je   0x401018      ← …and only then tests it
    //   0x401010 inc  esi
    //   0x401014 jmp  0x401004
    const code = run(
      seq(0x401000, [
        ["xor", "esi, esi"],
        ["mov", "al, byte ptr [esi]"], // 0x401004 — header
        ["test", "al, al"],
        ["je", "0x401018"],
        ["inc", "esi"], // 0x401010
        ["jmp", "0x401004"],
        ["mov", "edx, 1"], // 0x401018
        ["ret"],
      ]),
    );

    // No pre-test on a register the loop body is what assigns.
    expect(code).not.toMatch(/while \(al != 0\) \{/);
    // The load comes first, then the test, in that order.
    const load = code.search(/al = /);
    const test = code.search(/al == 0/);
    expect(load).toBeGreaterThanOrEqual(0);
    expect(test).toBeGreaterThan(load);
    expect(code).toMatch(/break;|goto /);
  });

  it("emits two `if`s in a row as siblings, not as one nested in the other", () => {
    //   if (ecx) *ecx = 1;
    //   if (edx) *edx = 2;
    // Both merges are `if`-without-`else` triangles, and the second one is the
    // first one's merge block.
    const code = run(
      seq(0x401000, [
        ["test", "ecx, ecx"],
        ["je", "0x40100c"],
        ["mov", "dword ptr [ecx], 1"],
        ["test", "edx, edx"], // 0x40100c
        ["je", "0x401018"],
        ["mov", "dword ptr [edx], 2"],
        ["xor", "eax, eax"], // 0x401018
        ["ret"],
      ]),
    );

    expect(controlLines(code)).toEqual(["if (ecx != 0) {", "if (edx != 0) {"]);
    // Siblings: both guards at the same indentation, and no jump out of one
    // into the middle of the other.
    const indents = code
      .split("\n")
      .filter((l) => l.trim().startsWith("if ("))
      .map((l) => l.match(/^ */)![0].length);
    expect(indents[0]).toBe(indents[1]);
    expect(code).not.toContain("goto");
  });

  it("keeps a guard that sits inside a loop body", () => {
    //   0x401004 cmp ecx, 8       ← header
    //   0x401008 jge exit
    //   0x40100c test edx, edx    ← guard inside the body
    //   0x401010 je  0x401018
    //   0x401014 mov [edx], ecx
    //   0x401018 inc ecx
    //   0x40101c jmp 0x401004     ← back edge
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, 0"],
        ["cmp", "ecx, 8"],
        ["jge", "0x401020"],
        ["test", "edx, edx"],
        ["je", "0x401018"],
        ["mov", "dword ptr [edx], ecx"],
        ["inc", "ecx"],
        ["jmp", "0x401004"],
        ["ret"],
      ]),
    );

    const lines = controlLines(code);
    // `while` or `for` — see "still finds a genuine pre-tested loop"; what
    // matters here is that the guard stays inside whichever one it is.
    expect(lines[0]).toMatch(/(while \(ecx < 8\)|for \(ecx = 0; ecx < 8; ecx\+\+\))/);
    expect(lines).toContain("if (edx != 0) {");
    expect(code).toContain("= ecx;");
  });

  it("does not turn a tail call into an infinite loop", () => {
    // add rsp, 0x28 / jmp <another function> — `jmp` out of the function is not
    // a back edge, and the block it leaves has no successor at all.
    const code = run(
      seq(0x401000, [
        ["sub", "rsp, 0x28"],
        ["test", "ecx, ecx"],
        ["je", "0x401014"],
        ["mov", "edx, 1"],
        ["add", "rsp, 0x28"], // 0x401010
        ["jmp", "0x408000"], // 0x401014 — outside [0x401000, 0x401018)
      ]),
      true,
    );

    expect(code).not.toContain("while (1)");
    expect(code).not.toContain("do {");
  });

  /**
   * peek-a-bin-cb2. A loop with two different exit targets: the header's `jge`
   * leaves to one, an `if` inside the body leaves to the other. Structuring a
   * loop ends by picking *one* block to carry on from, so everything hanging off
   * the other exit used to vanish from the output with no trace at all — the
   * worst kind of defect this pipeline can have, because the reader concludes
   * the code does not exist.
   */
  it("keeps both exit paths of a loop that breaks to two different places", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, 0"],
        ["cmp", "ecx, 8"], // 0x401004 — loop header
        ["jge", "0x40101c"], // exit A
        ["test", "edx, edx"], // 0x40100c
        ["je", "0x401024"], // exit B — a *different* way out of the same loop
        ["inc", "ecx"], // 0x401014
        ["jmp", "0x401004"], // back edge
        ["mov", "eax, 0x11"], // 0x40101c — exit A
        ["ret"],
        ["mov", "eax, 0x22"], // 0x401024 — exit B
        ["ret"],
      ]),
    );

    expect(code).toContain("0x11");
    expect(code).toContain("0x22");
  });

  /**
   * peek-a-bin-cb2, the loop-free half. Two conditional blocks branching to the
   * same failure target are folded into `condA && condB`, and every block the
   * fold consumes is marked visited — so any *work* those blocks did between
   * the two tests is discarded with them. On t32 that deleted two whole calls
   * from one function (`sub_405B72`).
   *
   * `a && f()` in C only evaluates `f()` when `a` holds, so the collapse is
   * only sound for a block that does nothing but test. When it does more, the
   * shape is a nested `if`, and the statements have to survive either way.
   */
  it("does not fold a side effect away into a short-circuit condition", () => {
    const code = run(
      seq(0x401000, [
        ["test", "ecx, ecx"],
        ["je", "0x401018"], // A fails → skip everything
        ["call", "0x402000"], // 0x401008 — runs only when ecx != 0
        ["test", "edx, edx"], // 0x40100c
        ["je", "0x401018"], // B fails → same target, so this looks like `&&`
        ["mov", "dword ptr [ecx], 1"], // 0x401014
        ["ret"], // 0x401018
      ]),
    );

    expect(code).toContain("sub_402000");
  });
});

/**
 * `.pdata` exception regions. `DisasmFunction.address` is a VA and
 * `RuntimeFunction.beginAddress` is an RVA; comparing them directly matched
 * nothing on any real image, so `__try` was emitted zero times across 1475
 * functions of three real binaries despite the handlers being present
 * (peek-a-bin-yrh).
 */
describe("decompileFunction — .pdata exception regions", () => {
  const body = seq(0x401000, [["mov", "eax, 1"], ["ret"]]);
  const func: DisasmFunction = { name: "sub_401000", address: 0x401000, size: 8 };

  function decompile(runtimeFunctions: RuntimeFunction[]): string {
    return decompileFunction(
      func,
      body,
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      undefined,
      runtimeFunctions,
    ).code;
  }

  /** An entry whose RVAs correspond to `func` under a 0x400000 image base. */
  const entry = (begin: number, size: number, handler?: number): RuntimeFunction => ({
    beginAddress: begin,
    endAddress: begin + size,
    unwindInfoAddress: 0x3000,
    handlerAddress: handler,
    handlerFlags: handler === undefined ? 0 : 1,
  });

  it("wraps the body when the entry is the same function, expressed as an RVA", () => {
    const code = decompile([entry(0x1000, 8, 0x2000)]);
    expect(code).toContain("__try {");
    expect(code).toContain("__except(");
    // The handler is an RVA too; it is reported in the same unit as every
    // other address in the pane, i.e. rebased to a VA.
    expect(code).toContain("0x402000");
    expect(code).not.toContain("0x2000\n");
  });

  it("still matches an array the caller already normalised to VAs", () => {
    const code = decompile([entry(0x401000, 8, 0x402000)]);
    expect(code).toContain("__try {");
    expect(code).toContain("0x402000");
  });

  it("ignores an entry with no exception handler", () => {
    expect(decompile([entry(0x1000, 8)])).not.toContain("__try");
  });

  it("refuses to guess between two entries an image base apart", () => {
    // 0x1000 and 0x11000 are both 64K-congruent with the function's VA and
    // both claim its extent: there is no evidence for either, so neither is
    // used. A wrongly attributed __try is worse than a missing one.
    const code = decompile([entry(0x1000, 8, 0x2000), entry(0x11000, 8, 0x12000)]);
    expect(code).not.toContain("__try");
  });
});

/**
 * `goto` and the label it needs.
 *
 * `structure.ts` emits a `goto loc_<addr>` when a block's only successor has
 * already been emitted, and nothing ever emitted the matching label — every one
 * of the 762 gotos in the three real binaries dangled (peek-a-bin-alc). The
 * label is placed by address, on the first emitted line carrying the target
 * address, so it lands wherever that block's code actually ended up — including
 * inside a branch body, which is legal C and is where these jumps go.
 *
 * The instruction streams below are shaped to defeat convergence detection: the
 * else arm reaches the shared block two blocks later than it reaches the join,
 * so the join wins as the convergence and the shared block is left to be jumped
 * to rather than emitted after the `if`.
 */
describe("decompileFunction — goto labels", () => {
  /**
   * 0x401028 is emitted inside the then-arm and jumped to from the else-arm.
   * `[10]` is that block's only body instruction, so a caller can blank it.
   */
  const sharedBlockJump = (bodyOfTarget: [string, string?]): Instruction[] =>
    seq(0x401000, [
      ["cmp", "eax, 1"], // 401000
      ["jne", "0x401018"], // 401004 → then-arm
      ["cmp", "ebx, 2"], // 401008   else-arm
      ["je", "0x401020"], // 40100c
      ["call", "0x402010"], // 401010 the join
      ["ret"], // 401014
      ["call", "0x402000"], // 401018 then-arm
      ["jmp", "0x401028"], // 40101c → the shared block
      ["call", "0x402014"], // 401020
      ["jmp", "0x401030"], // 401024
      bodyOfTarget, // 401028 the shared block
      ["jmp", "0x401010"], // 40102c → the join
      ["call", "0x402008"], // 401030
      ["jmp", "0x401028"], // 401034 → the shared block, already emitted
    ]);

  it("emits the label for a goto whose target reached the output", () => {
    const code = run(sharedBlockJump(["call", "0x402004"]));

    expect(code).toContain("goto loc_401028;");
    // The label, on the line the target block's own code was emitted at.
    expect(code).toMatch(/^\s*loc_401028:$/m);
    const lines = code.split("\n");
    expect(lines[lines.findIndex((l) => l.trim() === "loc_401028:") + 1].trim()).toBe(
      "sub_402004();",
    );
    // Nothing was invented: exactly one label, for the one jump that needs it.
    expect(code.match(/^\s*loc_[0-9A-F]+:$/gm)).toHaveLength(1);
  });

  it("does not label an address nothing jumps to", () => {
    // Same stream, minus the second reference to the shared block, so no goto
    // is emitted at all. Labelling every block start would litter the output.
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 1"],
        ["je", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"], // 0x401010
        ["ret"],
      ]),
    );

    expect(code).not.toContain("goto ");
    expect(code).not.toMatch(/^\s*loc_[0-9A-F]+:$/m);
  });

  it("labels a target block that lifted to no statements at all", () => {
    // The shared block is a `nop`: it lifts to nothing, so no emitted line
    // carries 0x401028 and an emitter matching on addresses has nothing to
    // anchor to — that was two thirds of every goto (peek-a-bin-uzi).
    // `structure.ts` knows where the block goes whether or not it produced a
    // statement, so it emits the label there, and the empty statement after it
    // is what C requires of a label at the end of a block.
    const code = run(sharedBlockJump(["nop"]));

    expect(code).toContain("goto loc_401028;");
    expect(code).not.toContain("// no label:");
    const lines = code.split("\n");
    const at = lines.findIndex((l) => l.trim() === "loc_401028:");
    expect(at).toBeGreaterThan(-1);
    expect(lines[at + 1].trim()).toBe(";");
  });

  it("keeps the line map pointing at the right instructions after inserting labels", () => {
    // The labels are spliced into the emitted lines, so every address mapped
    // below the insertion point shifts by one. A stale map sends the
    // disassembly pane to the wrong instruction on click.
    const func: DisasmFunction = { name: "sub_401000", address: 0x401000, size: 0x38 };
    const result = decompileFunction(
      func,
      sharedBlockJump(["call", "0x402004"]),
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
    );
    const lines = result.code.split("\n");
    for (const [line, addr] of result.lineMap) {
      expect(lines[line]).not.toMatch(/^\s*loc_[0-9A-F]+:$/);
      if (addr === 0x401028) expect(lines[line].trim()).toBe("sub_402004();");
    }
  });
});

/**
 * What a counted loop's body is allowed to lose on the way to `for` (peek-a-bin-42l).
 *
 * `detectForLoop` recognises the induction variable and hands back a body that
 * is every body block's statements concatenated in block-id order. Used as the
 * loop body verbatim that is a rewrite, not a recovery: the control flow
 * between those blocks is gone, and blocks belonging to the loop that the walk
 * had already emitted somewhere else come back a second time. On the three
 * distlib binaries it lost 111 statements per x64 image and duplicated enough
 * on t32 to make two functions four times longer than the code they describe.
 */
describe("decompileFunction — a for loop keeps its body", () => {
  /**
   * `for (ecx = 0; ecx < 10; ecx++)` around a branch: the arms call different
   * functions and join at the increment, which is the back edge's block.
   */
  const countedLoopWithBranch = (): Instruction[] =>
    seq(0x401000, [
      ["mov", "rcx, 0"], // 401000 init
      ["jmp", "0x401008"], // 401004
      ["cmp", "rcx, 0xa"], // 401008 the test
      ["jge", "0x40102c"], // 40100c exit
      ["cmp", "edx, 0"], // 401010 body: branch
      ["je", "0x401020"], // 401014
      ["call", "0x402000"], // 401018 not-taken arm
      ["jmp", "0x401024"], // 40101c
      ["call", "0x402004"], // 401020 taken arm
      ["add", "rcx, 1"], // 401024 the update
      ["jmp", "0x401008"], // 401028 back edge
      ["ret"], // 40102c
    ]);

  /** The same loop with a load in the header, which runs on every iteration. */
  const countedLoopWithHeaderWork = (): Instruction[] =>
    seq(0x401000, [
      ["mov", "rcx, 0"], // 401000
      ["jmp", "0x401008"], // 401004
      ["mov", "rax, qword ptr [rsi]"], // 401008 header work
      ["cmp", "rcx, 0xa"], // 40100c
      ["jge", "0x401030"], // 401010
      ["cmp", "edx, 0"], // 401014
      ["je", "0x401024"], // 401018
      ["call", "0x402000"], // 40101c
      ["jmp", "0x401028"], // 401020
      ["call", "0x402004"], // 401024
      ["add", "rcx, 1"], // 401028
      ["jmp", "0x401008"], // 40102c
      ["ret"], // 401030
    ]);

  it("keeps the branch inside the body instead of running both arms", () => {
    const code = run(countedLoopWithBranch(), true);

    expect(code).toMatch(/^\s*for \(/m);
    // Both calls are conditional, and each appears exactly once.
    expect(code).toContain("} else {");
    expect(code.match(/sub_402000\(\);/g)).toHaveLength(1);
    expect(code.match(/sub_402004\(\);/g)).toHaveLength(1);
  });

  it("keeps the statements of the loop header itself", () => {
    // The load runs on every iteration, before the test. The flat body was
    // built from the body blocks only, so the header's own work vanished.
    const code = run(countedLoopWithHeaderWork(), true);

    expect(code).toContain("rax = *(int64_t*)(rsi);");
  });

  it("does not repeat the initialiser it lifted into the header", () => {
    const code = run(countedLoopWithBranch(), true);
    // Once, in the `for` header — never also as a statement before the loop.
    expect(code.match(/rcx = 0\b/g)).toHaveLength(1);
    expect(code).not.toMatch(/^\s*rcx = 0;$/m);
  });

  /**
   * MSVC's newline count, which is the shape `detectForLoop` used to give up on
   * (peek-a-bin-9q2, census at `bd73798`).
   *
   *   for (rax = start; rax < end; rax++) if (*rax == '\n') counter++;
   *
   * The *conditionally* incremented counter is a self-increment too, and its
   * block is numbered below the latch — so the first candidate in block-id
   * order is `r8d`, whose initialiser is not in the function at all. Committing
   * to it made the whole loop unrecognisable: 26 loops corpus-wide, of which
   * this one shape (t64!sub_140003200 and w64!sub_14000356C) reached the page.
   */
  const countedLoopWithConditionalCounter = (): Instruction[] =>
    seq(0x401000, [
      ["mov", "rax, qword ptr [rsi]"], // 401000 the real init
      ["jmp", "0x401018"], // 401004 straight to the test
      ["cmp", "byte ptr [rax], 0xa"], // 401008 body head
      ["jne", "0x401014"], // 40100c
      ["add", "r8d, 1"], // 401010 the counter — no init anywhere
      ["add", "rax, 1"], // 401014 the latch update
      ["cmp", "rax, rdi"], // 401018 the header test
      ["jb", "0x401008"], // 40101c
      ["mov", "eax, r8d"], // 401020 so the counter is read
      ["ret"], // 401024
    ]);

  it("recognises the induction variable when another counter is incremented first", () => {
    const code = run(countedLoopWithConditionalCounter(), true);

    // The `for` names RAX, not the counter, and its init came out of the block
    // above rather than being repeated there.
    expect(code).toMatch(/for \(rax = [^;]+; [^;]+; rax\+\+\)/);
    expect(code).not.toMatch(/^\s*while \(/m);
    // The conditional counter stays conditional, inside the body.
    expect(code).toMatch(/if \(\*\(uint8_t\*\)\(rax\) == 0xA\) \{\n\s*r8d\+\+;\n\s*\}/);
  });
});

/**
 * Array fields in the emitted typedef block (peek-a-bin-b2x).
 *
 * `isArray` records only that the field was reached through an index; struct
 * synthesis never learns an element count. Declaring all of them `[]` produced
 * "flexible array member not at end of struct" for 26 structs across the three
 * real binaries — and a field with another field after it plainly cannot run
 * past that field's offset, so the layout does bound it.
 */
describe("decompileFunction — array fields are sized from the layout", () => {
  it("sizes an array field from the offset of the field that follows it", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + ecx*4], 1"],
        ["mov", "dword ptr [ebx + 8], 2"],
        ["ret"],
      ]),
    );

    // Two 4-byte elements fit between offset 0 and offset 8.
    expect(code).toContain("uint32_t array_0x0[2];");
    expect(code).not.toContain("array_0x0[]");
  });

  it("counts elements by element size, not by field size", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "word ptr [ebx + ecx*2], 1"],
        ["mov", "dword ptr [ebx + 8], 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain("uint16_t array_0x0[4];");
  });

  it("leaves a trailing array field open, which is what a flexible array member means", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx], 1"],
        ["mov", "dword ptr [ebx + ecx*4 + 8], 2"],
        ["ret"],
      ]),
    );

    // Nothing after it bounds it, and it is last, so `[]` is both legal and
    // the honest reading.
    expect(code).toContain("uint32_t array_0x8[];");
    const structBlock = code.slice(code.indexOf("struct struct_0 {"), code.indexOf("};"));
    expect(structBlock.trimEnd().split("\n").pop()?.trim()).toBe("uint32_t array_0x8[];");
  });
});

describe("decompileFunction — an expression is only moved where it still means the same thing", () => {
  // peek-a-bin-juu, the half of it that lives in fold.ts. `foldBlock`'s
  // single-use inlining scanned forward for the one statement that reads the
  // destination register, and stopped only at a write to *that* register or at
  // a call. It never checked the expression's own inputs, so a redefinition of
  // one of them in between was invisible — and after destroySSA the versions
  // are gone, so two different SSA values of a register share one name and
  // nothing downstream can tell them apart either.
  //
  // `cmove rbx, r9` reads r9 before `inc r9` runs. Emitting the increment first
  // states that the conditional move saw the incremented value.
  it("keeps a conditional move ahead of the increment it reads", () => {
    const code = run(
      seq(0x401000, [
        ["xor", "ebx, ebx"],
        ["mov", "eax, dword ptr [r9]"], // 0x401004 — loop head
        ["cmp", "eax, r10d"],
        ["cmove", "rbx, r9"],
        ["inc", "r9"],
        ["cmp", "r9, 10"],
        ["jl", "0x401004"],
        ["mov", "rax, rbx"],
        ["ret"],
      ]),
      true,
    );

    const body = code.split("\n").map((l) => l.trim());
    const move = body.findIndex((l) => l.includes("? r9 :"));
    const inc = body.findIndex((l) => l.startsWith("r9++"));
    expect(move).toBeGreaterThanOrEqual(0);
    expect(inc).toBeGreaterThanOrEqual(0);
    // Before the fix these came out the other way round.
    expect(move).toBeLessThan(inc);
  });
});

describe("decompileFunction — a value is only reused where it has actually been computed", () => {
  // Global value numbering kept one flat table of available expressions while
  // walking the dominator tree, so a definition stayed visible after its
  // subtree was left. Both arms of this branch compute `edx + 5` into ebx; the
  // else arm's definition was rewritten to the then arm's, the phi went
  // trivial, and the assignment disappeared from the else arm entirely — the
  // emitted C then returned the *incoming* ebx on a path where the machine
  // code assigns it. SSA versions do not catch this: each register really is
  // defined once, just on paths that exclude each other.
  it("assigns on every path the machine code assigns on", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, 0"],
        ["je", "0x401014"],
        ["lea", "ebx, [edx + 5]"],
        ["mov", "ebp, 1"],
        ["jmp", "0x40101c"],
        ["lea", "esi, [edx + 5]"], // 0x401014 — reached when ecx == 0
        ["mov", "ebx, esi"],
        ["mov", "eax, ebx"], // 0x40101c — join
        ["ret"],
      ]),
    );

    // Two assignments of the same value, one per arm. Before the fix the
    // `else` arm was empty and only one assignment survived.
    const assigns = code.split("\n").filter((l) => /= edx \+ 5;$/.test(l.trim()));
    expect(assigns).toHaveLength(2);
    expect(code).toContain("else");
  });
});

/**
 * A function's own stack frame is not an object, and must not be synthesised
 * into one (peek-a-bin-a6n).
 *
 * The whole difficulty is that the two readings of `[rbp + N]` are spelled
 * identically. In a function that established a frame pointer it is a stack
 * slot — an incoming argument or a local — and the struct this pass used to
 * build out of them had a local and an argument as its two "fields". Under
 * frame-pointer omission, which is most of x64, RBP is an ordinary callee-saved
 * register usually holding an object pointer, and `[rbp + N]` really is a field
 * access.
 *
 * So the pairs below differ by exactly the two prologue instructions and expect
 * opposite things. Excluding RBP outright would satisfy the first of each pair
 * and break the second, which is the failure mode being guarded: it would
 * delete most of the struct recovery on x64.
 *
 * The accesses are written with an index register on purpose. A plain
 * `[rbp + 0x30]` in a framed function is promoted to a named slot long before
 * struct synthesis sees it; an indexed one is not, and is how a frame reached
 * the emitted output as `esp->field_0x8` in the first place.
 */
describe("decompileFunction — the stack frame is not a struct", () => {
  /**
   * Identical in both cases. `[rbp + 0x10]` is the argument slot whose *name*
   * carries the verdict — `arg_0` when stack.ts verified the prologue,
   * `arg_0x10` when it did not. The pair at 4 and 8 sits below the argument
   * area, so no promotion pass claims either one and both reach struct
   * synthesis as raw derefs, which is what makes the two cases comparable at
   * all. They are 4 bytes wide because the subject here is which base is an
   * object, not what a layout does with fields that overlap — an 8-byte read at
   * 4 runs through 8, and no struct declaration can place both (peek-a-bin-ey0).
   */
  const ACCESSES: [string, string?][] = [
    ["mov", "rax, qword ptr [rbp + 0x10]"],
    ["mov", "edx, dword ptr [rbp + 4]"],
    ["mov", "dword ptr [rbp + 8], edx"],
    ["ret"],
  ];

  const PROLOGUE: [string, string?][] = [
    ["push", "rbp"],
    ["mov", "rbp, rsp"],
    ["sub", "rsp, 0x20"],
  ];

  /** 64-bit, with the StackFrame the real caller computes — as dispatch.ts does. */
  function run64(instructions: Instruction[]): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      analyzeStackFrame(func, instructions, true),
      null,
      true,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      new StructRegistry(),
    ).code;
  }

  it("does not synthesise a struct out of a verified frame pointer", () => {
    const code = run64(seq(0x401000, [...PROLOGUE, ...ACCESSES]));

    // Before the fix: `struct struct_0 { field_0x4; field_0x8; }` and
    // `rbp->field_0x8 = rbp->field_0x4` — two stack slots declared as an
    // object, and not compilable C either, since rbp is not a struct pointer.
    expect(code).not.toContain("typedef struct");
    expect(code).not.toMatch(/\b(?:rbp|rsp|ebp|esp)->/);
    // The accesses are still emitted, as the stack references they are.
    expect(code).toMatch(/rbp \+ /);
    // …and the argument slot is still an argument.
    expect(code).toContain("arg_0");
  });

  it("still synthesises a struct from a frame-pointer-omitted object pointer", () => {
    // Identical accesses, no prologue: nothing here ever wrote a stack address
    // into RBP, so it holds an object it was handed — and stack.ts says as much
    // by naming the slot `arg_0x10` rather than `arg_0`.
    const code = run64(seq(0x401000, ACCESSES));

    expect(code).toContain("typedef struct");
    expect(code).toContain("field_0x4");
    expect(code).toContain("field_0x8");
    expect(withoutStructCasts(code)).toMatch(/rbp->field_0x8 = rbp->field_0x4/);
  });

  it("does not synthesise a struct out of the stack pointer itself", () => {
    // No frame pointer anywhere — two indexed accesses off RSP, an outgoing
    // argument slot and a spill slot. The stack pointer is never an object.
    const code = run64(
      seq(0x401000, [
        ["sub", "rsp, 0x40"],
        ["mov", "rax, qword ptr [rsp + rcx*8 + 0x18]"],
        ["mov", "qword ptr [rsp + rcx*8 + 0x20], rax"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("typedef struct");
    expect(code).not.toMatch(/\brsp->/);
  });

  it("does not synthesise a struct out of a frame pointer established with lea", () => {
    // `lea rbp, [rsp + 0x20]` shifts every argument offset, so stack.ts refuses
    // to number the slots and the name channel stays silent. The assignment
    // survives in the body, which is the other half of the evidence.
    const code = run64(
      seq(0x401000, [
        ["push", "rbp"],
        ["lea", "rbp, [rsp + 0x20]"],
        ["mov", "rax, qword ptr [rbp + rcx*8 + 0x30]"],
        ["mov", "qword ptr [rbp + rcx*8 + 0x38], rax"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("typedef struct");
    expect(code).not.toMatch(/\brbp->/);
  });
});

/**
 * The parameter reached only through `push dword ptr [ebp + 8]`.
 *
 * Capstone prints a displacement as `0x`-prefixed hex only from 0xA up and as a
 * bare digit below it, so `analyzeStackFrame`'s `0x`-only operand patterns saw
 * nothing in the first ten bytes of the frame — which on x86 is argument 0 at
 * `[ebp + 8]` and the first locals at `[ebp - 4]` / `[ebp - 8]`. The frame came
 * back holding whatever happened to live at 0xA or beyond and nothing else, so
 * the function was emitted as taking no arguments and the unrecognised slots
 * stayed raw derefs all the way to the output.
 */
describe("decompileFunction — stack slots below 0xA", () => {
  /** A 32-bit run with the StackFrame the real caller computes. */
  function runWithStackFrame(instructions: Instruction[]): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      analyzeStackFrame(func, instructions, false),
      null,
      false,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      new StructRegistry(),
    ).code;
  }

  it("recovers the argument at [ebp + 8] alongside the one at [ebp + 0xC]", () => {
    const code = runWithStackFrame(
      seq(0x401000, [
        ["push", "ebp"],
        ["mov", "ebp, esp"],
        ["mov", "eax, dword ptr [ebp + 0xC]"],
        ["push", "dword ptr [ebp + 8]"],
        ["call", "0x408000"],
        ["ret"],
      ]),
    );

    const signature = code.split("\n").find((l) => /^\w[^;]*\(/.test(l))!;
    // Before the fix the signature named only arg_1 — the argument at 0xC —
    // and argument 0 was emitted as a bare `*(int32_t*)(ebp + 8)`.
    expect(signature).toContain("arg_0");
    expect(signature).toContain("arg_1");
    expect(code).toContain("sub_408000(arg_0)");
  });

  it("names the local at [ebp - 4] like any other", () => {
    const code = runWithStackFrame(
      seq(0x401000, [
        ["push", "ebp"],
        ["mov", "ebp, esp"],
        ["sub", "esp, 0x10"],
        ["mov", "dword ptr [ebp - 4], eax"],
        ["mov", "dword ptr [ebp - 0x10], eax"],
        ["ret"],
      ]),
    );

    expect(code).toContain("var_4");
    expect(code).toContain("var_10");
  });
});

/**
 * A register's incoming value and its first definition are two different
 * values, and SSA has to keep them apart.
 *
 * `renameVariables` numbered the first definition 0, and a read with an empty
 * version stack — the function-entry value — also renamed to 0. Every pass in
 * `ssaopt.ts` keys on (canonical register, version), so the two were one value:
 * constant and copy propagation rewrote *incoming* values with a definition
 * that may never have run, and the phi that should have joined them went
 * trivial, taking the branch it came from with it (peek-a-bin-swi).
 */
describe("decompileFunction — an incoming register value is not the first definition", () => {
  it("stores the incoming register, not the value written to it afterwards", () => {
    // `mov [rsp+0x48], rsi` saves the *caller's* rsi; `xor esi, esi` after it
    // is a different value. Before the fix this emitted `= 0`.
    const code = run(
      seq(0x401000, [["mov", "qword ptr [rsp + 0x48], rsi"], ["xor", "esi, esi"], ["ret"]]),
      true,
    );

    const store = code.split("\n").find((l) => l.includes("rsp + 0x48"));
    expect(store).toBeDefined();
    expect(store).toContain("= rsi");
    expect(store).not.toContain("= 0");
  });

  it("keeps the branch whose other path leaves the register alone", () => {
    // ebx is written only when ecx != 0, then stored either way. Before the fix
    // the phi at the join saw one value, the `if` disappeared, and the store
    // read `1` on the path where the machine stores the incoming ebx.
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, 0"],
        ["je", "0x401010"],
        ["mov", "ebx, 1"],
        ["jmp", "0x401010"],
        ["mov", "dword ptr [edx], ebx"], // 0x401010 — the join
        ["ret"],
      ]),
    );

    expect(code).toContain("if (ecx != 0)");
    const store = code.split("\n").find((l) => l.includes("(edx)"));
    expect(store).toContain("= ebx");
    expect(store).not.toContain("= 1");
  });

  it("returns the incoming accumulator on the path that does not assign it", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, 0"],
        ["je", "0x401010"],
        ["mov", "eax, edx"],
        ["jmp", "0x401010"],
        ["ret"], // 0x401010
      ]),
    );

    // Before the fix: `return edx;` — on the bypass path the machine returns
    // whatever eax already held.
    expect(code).not.toMatch(/return edx;/);
    expect(code).toContain("if (ecx != 0)");
  });
});

/**
 * Two values of one register cannot share the register's name.
 *
 * `destroySSA` drops version numbers, which is only sound while one version of
 * a register is live at a time. `ssaopt.ts` breaks that on purpose — GVN
 * forwards a value to a later use, copy propagation forwards a source across a
 * later write to it — so the read has to keep a name of its own
 * (peek-a-bin-lh6's neighbourhood: same mechanism, different pass).
 */
describe("decompileFunction — a value survives a later write to the register holding it", () => {
  it("stores the value the register held when it was copied", () => {
    // rcx holds the incoming rax; rax is then overwritten with 5. The store
    // must be of the *old* rax. Before the fix it emitted `= 5`.
    const code = run(
      seq(0x401000, [
        ["mov", "rcx, rax"],
        ["cmp", "rdx, 0"],
        ["je", "0x401018"],
        ["mov", "rax, 5"],
        ["mov", "qword ptr [rbx], rcx"],
        ["ret"], // 0x401018
      ]),
      true,
    );

    const store = code.split("\n").find((l) => l.includes("(rbx)"));
    expect(store).toBeDefined();
    expect(store).not.toContain("= 5");
  });

  it("does not emit a register assigned to itself", () => {
    // Phi destruction inserts a copy per operand; between two versions of one
    // register that copy is `ebx = ebx` once the versions come off. It carries
    // no behaviour and was a quarter of all emitted lines on t64.exe. The loop
    // below carries ebx round the back edge without writing it on every path,
    // which is exactly the shape that produced one.
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, 0"],
        ["mov", "ebx, 0"],
        ["cmp", "ecx, 8"], // 0x401008 — header
        ["jge", "0x401020"],
        ["add", "ebx, ecx"],
        ["inc", "ecx"],
        ["jmp", "0x401008"],
        ["mov", "dword ptr [edx], ebx"], // 0x401020
        ["ret"],
      ]),
    );

    expect(code).not.toMatch(/^\s*(\w+) = \1;\s*$/m);
    // …and the statements that do carry behaviour are still there.
    expect(code).toMatch(/ebx \+= ecx|ebx = ebx \+ ecx/);
    expect(code).toMatch(/ecx\+\+|ecx = ecx \+ 1/);
  });
});

/**
 * What a `do`-`while` body is allowed to lose (peek-a-bin-b37).
 *
 * The sibling of the `for`-loop defect above, in the other arm of
 * `structureLoop`. When the loop header does not end in a conditional jump —
 * a bottom-tested loop whose header ends in `jmp`, which is what MSVC emits
 * for `do { } while` — the fallback concatenated every body block's lifted
 * statements in block-id order and called that the body. The control flow
 * between them was simply gone: both arms of an `if` inside the loop came out
 * as consecutive unconditional code. Nothing is dropped, so no
 * statement-identity instrument sees it; the result is valid C stating
 * something the machine does not do, which is this project's worst defect
 * class (see the condition-polarity gotcha).
 */
describe("decompileFunction — a do-while keeps its body's control flow", () => {
  /**
   * `do { ecx = 0; if (edx == 0) f2(); else f1(); } while (eax < 5);`
   *
   * The header at 0x401004 ends in `jmp`, so `structureLoop` takes the
   * do-while fallback. `je` is taken when edx == 0 and lands on the call to
   * 0x402004, so that call is the one guarded by `edx == 0`.
   */
  const doWhileWithBranch = (): Instruction[] =>
    seq(0x401000, [
      ["mov", "eax, 0"], // 401000
      ["mov", "ecx, 0"], // 401004 loop header (jumped back to)
      ["jmp", "0x40100c"], // 401008 — unconditional, so no pre-test
      ["cmp", "edx, 0"], // 40100c
      ["je", "0x40101c"], // 401010
      ["call", "0x402000"], // 401014 not-taken arm
      ["jmp", "0x401020"], // 401018
      ["call", "0x402004"], // 40101c taken arm (edx == 0)
      ["cmp", "eax, 5"], // 401020
      ["jl", "0x401004"], // 401024 back edge
      ["ret"], // 401028
    ]);

  it("guards each arm instead of running both", () => {
    const code = run(doWhileWithBranch());
    const lines = code.split("\n");

    expect(code).toContain("do {");
    expect(code.match(/sub_402000\(\);/g)).toHaveLength(1);
    expect(code.match(/sub_402004\(\);/g)).toHaveLength(1);

    // Both calls must sit in opposite arms of a guard on edx, with the arm
    // matching the sense of the `je` that selects it.
    const ifIdx = lines.findIndex((l) => /\bif \(/.test(l));
    expect(ifIdx).toBeGreaterThanOrEqual(0);
    const cond = lines[ifIdx].match(/if \(([^)]*)\)/)?.[1];
    expect(cond).toMatch(/^edx (==|!=) 0$/);

    const elseIdx = lines.findIndex((l, i) => i > ifIdx && /\}\s*else\s*\{/.test(l));
    expect(elseIdx).toBeGreaterThan(ifIdx);
    const thenArm = lines.slice(ifIdx + 1, elseIdx).join("\n");
    const elseArm = lines.slice(elseIdx + 1).join("\n");

    const guarded = cond === "edx == 0" ? "sub_402004();" : "sub_402000();";
    const other = cond === "edx == 0" ? "sub_402000();" : "sub_402004();";
    expect(thenArm).toContain(guarded);
    expect(thenArm).not.toContain(other);
    expect(elseArm).toContain(other);
  });

  it("keeps the loop itself bottom-tested on the back edge's condition", () => {
    const code = run(doWhileWithBranch());
    expect(code).toMatch(/\}\s*while \(eax < 5\);/);
  });
});

/**
 * The subject of a recovered `switch` (peek-a-bin-rev).
 *
 * Jump-table case targets only stopped truncating their own function this
 * morning (peek-a-bin-jy4), which made these the first switches the
 * decompiler has ever emitted from a real binary. `structureSwitch` recovered
 * the subject from a `ja`/`jae` bounds check alone, so the inverted-sense form
 * — `cmp ecx, 8 / jb table`, where the in-range path is the branch taken —
 * emitted `switch (/* switch_expr *\/)`, a switch with no subject.
 *
 * The bounds check is also not the subject in general. In t32's `sub_40B780`
 * the guard is `cmp ecx, 8` while the table is `jmp [edx*4 + 0x40b8f0]`, and
 * `edx` is `ecx & 3` — a different value with a different range. The index
 * register of the indirect jump is what selects the case, so it is the one
 * thing that is the subject by construction.
 */
describe("decompileFunction — a switch states what it switches on", () => {
  function runTables(instructions: Instruction[], tables: Map<number, number[]>): string {
    const start = instructions[0].address;
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: start,
      size: last.address + last.size - start,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      tables,
      new Map(),
      new Map(),
      new Map(),
    ).code;
  }

  /** `cmp ecx, 8 / jb table`, with the table indexed by a different register. */
  const invertedGuard = (): Instruction[] =>
    seq(0x401000, [
      ["cmp", "ecx, 8"], // 401000
      ["jb", "0x401010"], // 401004 — in range on the *taken* path
      ["call", "0x402000"], // 401008 out-of-range path
      ["ret"], // 40100c
      ["jmp", "dword ptr [edx*4 + 0x403000]"], // 401010 the table
      ["call", "0x402004"], // 401014 case 0
      ["ret"], // 401018
      ["call", "0x402008"], // 40101c case 1
      ["ret"], // 401020
      ["call", "0x40200c"], // 401024 case 2
      ["ret"], // 401028
    ]);

  const threeEntries = new Map([[0x401010, [0x401014, 0x40101c, 0x401024]]]);

  it("names the register the jump table is indexed by", () => {
    const code = runTables(invertedGuard(), threeEntries);

    expect(code).toContain("switch (edx)");
    expect(code).not.toContain("switch_expr");
    // `ecx` is the bounds-checked value, not the one selecting the case.
    expect(code).not.toContain("switch (ecx)");
  });

  it("still recovers a case per table entry behind the inverted guard", () => {
    const code = runTables(invertedGuard(), threeEntries);

    // Case values are spelled as the members of the enum type inference
    // synthesises for a switch with three or more cases.
    expect(code).toMatch(/case (0|VAL_0x0):/);
    expect(code).toMatch(/case (1|VAL_0x1):/);
    expect(code).toMatch(/case (2|VAL_0x2):/);
    expect(code).toContain("sub_402004();");
    expect(code).toContain("sub_402008();");
    expect(code).toContain("sub_40200C();");
  });

  it("recognises a table whose entries share targets", () => {
    // Three entries, two distinct blocks. The gate counted successor blocks,
    // so this shape fell below `> 2` and was never recognised as a switch at
    // all — one target was emitted inline and the other left to the leftover
    // pass, with no `switch` and no case values anywhere.
    const code = runTables(invertedGuard(), new Map([[0x401010, [0x401014, 0x401014, 0x40101c]]]));

    expect(code).toContain("switch (edx)");
    expect(code).toMatch(/case (0|VAL_0x0):\s*\n\s*case (1|VAL_0x1):/);
    expect(code).toMatch(/case (2|VAL_0x2):/);
  });

  it("keeps taking the subject and the default from a ja bounds check", () => {
    // The form that already worked, so that corroborating the two sources
    // does not cost the one the `ja` path recovers.
    const code = runTables(
      seq(0x401000, [
        ["cmp", "eax, 2"], // 401000
        ["ja", "0x401024"], // 401004 out of range → default
        ["jmp", "dword ptr [eax*4 + 0x403000]"], // 401008 the table
        ["call", "0x402004"], // 40100c case 0
        ["ret"], // 401010
        ["call", "0x402008"], // 401014 case 1
        ["ret"], // 401018
        ["call", "0x40200c"], // 40101c case 2
        ["ret"], // 401020
        ["call", "0x402010"], // 401024 default
        ["ret"], // 401028
      ]),
      new Map([[0x401008, [0x40100c, 0x401014, 0x40101c]]]),
    );

    expect(code).toContain("switch (eax)");
    expect(code).toMatch(/case (0|VAL_0x0):/);
    expect(code).toMatch(/case (2|VAL_0x2):/);
    expect(code).toContain("default:");
  });

  /**
   * Two tables that dispatch into the same blocks (peek-a-bin-dp6).
   *
   * MSVC emits one table per copy-direction/alignment path of `memcpy` and
   * lands them all on the same four tail blocks: t32's `sub_40B780` has nine
   * tables over two distinct target sets. A block is emitted once, so the
   * switch that reaches it first takes the body and every later switch used to
   * emit `case VAL_0x1: break;` — true about the case value and silent about
   * what the case does, which is exactly the shape a reader cannot tell from a
   * case that really is empty.
   */
  const sharedTargets = (): Instruction[] =>
    seq(0x401000, [
      ["cmp", "eax, 1"], // 401000
      ["je", "0x40100c"], // 401004 → the second table
      ["jmp", "dword ptr [ecx*4 + 0x403000]"], // 401008 first table
      ["jmp", "dword ptr [edx*4 + 0x403100]"], // 40100c second table
      ["call", "0x402004"], // 401010 case 0 of both
      ["ret"], // 401014
      ["call", "0x402008"], // 401018 case 1 of both
      ["ret"], // 40101c
      ["call", "0x40200c"], // 401020 case 2 of both
      ["ret"], // 401024
    ]);

  const bothTables = new Map([
    [0x401008, [0x401010, 0x401018, 0x401020]],
    [0x40100c, [0x401010, 0x401018, 0x401020]],
  ]);

  it("gives the second switch over shared blocks a body per case", () => {
    const code = runTables(sharedTargets(), bothTables);

    // Both tables are switches, on their own index registers.
    expect(code).toContain("switch (ecx)");
    expect(code).toContain("switch (edx)");
    // The blocks themselves are still emitted exactly once...
    expect(code.match(/sub_402004\(\)/g)).toHaveLength(1);
    expect(code.match(/sub_402008\(\)/g)).toHaveLength(1);
    expect(code.match(/sub_40200C\(\)/g)).toHaveLength(1);
    // ...and the switch that did not get them says where each case goes.
    expect(code).toContain("goto loc_401010;");
    expect(code).toContain("goto loc_401018;");
    expect(code).toContain("goto loc_401020;");
  });

  it("leaves no case claiming to be empty when its block was taken", () => {
    const code = runTables(sharedTargets(), bothTables);

    // `case …:` immediately followed by `break;` is the shape that says "this
    // case does nothing"; none of these six cases does nothing.
    expect(code).not.toMatch(/case [^\n]*:\s*\n\s*break;/);
  });

  /**
   * An arm whose own block ends in a test (peek-a-bin-pqs5).
   *
   * `armBody` claims one block and closed it with `break` however the block
   * ends — and `break` is a claim about control flow. For an arm block ending
   * in a conditional jump it is false, and the condition disappears with it:
   * step 4b has already hoisted the `IRBranch` out of `liftedBlocks`, and
   * nothing else ever asks the block what it tested. On t32's `sub_4045B1`,
   * `case 7:` was `eax = (uint16_t)ecx; break;` for a block whose next two
   * instructions are `cmp eax, 0x64 / jg 0x404B46`, with `eax > 0x64` nowhere
   * in the function and no `goto` naming either successor.
   */
  const armThatTests = (): Instruction[] =>
    seq(0x401000, [
      ["cmp", "eax, 2"], // 401000
      ["ja", "0x401030"], // 401004 out of range → default
      ["jmp", "dword ptr [eax*4 + 0x403000]"], // 401008 the table
      ["call", "0x402004"], // 40100c case 0 — and it goes on to test
      ["cmp", "ecx, 5"], // 401010
      ["jne", "0x401038"], // 401014 taken → 401038, else falls into case 1
      ["call", "0x402008"], // 401018 case 1
      ["ret"], // 40101c
      ["nop"], // 401020
      ["call", "0x40200c"], // 401024 case 2
      ["ret"], // 401028
      ["nop"], // 40102c
      ["call", "0x402010"], // 401030 default
      ["ret"], // 401034
      ["call", "0x402014"], // 401038 where the arm's test goes
      ["ret"], // 40103c
    ]);

  const armTable = new Map([[0x401008, [0x40100c, 0x401018, 0x401024]]]);

  it("states the test an arm block ends in, and where each side goes", () => {
    const code = runTables(armThatTests(), armTable);

    expect(code).toContain("switch (eax)");
    // The arm's own statements, then its test — not a `break` in between.
    expect(code).toMatch(
      /case (0|VAL_0x0):\s*\n\s*(eax = )?sub_402004\(\);\s*\n\s*if \(ecx != 5\)\s*\{\s*\n\s*goto loc_401038;/,
    );
    // Both sides of the test are named: the taken edge and the fallthrough.
    expect(code).toContain("goto loc_401018;");
    // And the region the test jumps to is emitted under the label named.
    expect(code).toContain("loc_401038:");
    expect(code).toContain("sub_402014();");
  });

  /**
   * THE HOOK THE CORPUS GATE READS, END TO END (peek-a-bin-64gp).
   *
   * `corpus/armExits.ts` gates "an arm closed with `break` while its own block
   * has a successor" at 0, and the observations it judges come from
   * `structureSwitch` through `structureCFG`'s last parameter and
   * `pipeline.ts`'s `StructuringTap`. Every link in that chain is invisible to
   * an output assertion — drop the argument and the emitted C is unchanged, the
   * tap reports no arms at all, and the gate passes by observing nothing. Here
   * the plumbing is exercised rather than scraped, on the same fixture whose
   * emitted text is asserted above.
   */
  it("reports every arm's closure through the tap, and none is a false break", () => {
    const instructions = armThatTests();
    const last = instructions[instructions.length - 1];
    const taps: StructuringTap[] = [];
    decompileFunction(
      {
        name: "sub_401000",
        address: instructions[0].address,
        size: last.address + last.size - instructions[0].address,
      },
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      armTable,
      new Map(),
      new Map(),
      new Map(),
      undefined,
      undefined,
      (ev) => taps.push(ev),
    );

    expect(taps).toHaveLength(1);
    const arms = taps[0].armExits;
    // Three cases and the default: an arm is reported whatever it was closed
    // with, so this count is the gate's denominator and not its subject.
    expect(arms.length).toBeGreaterThanOrEqual(3);
    // The arm that ends in `jne` is reported as the two named transfers it
    // became, and as a conditional jump — which is the half of the class that
    // loses a recovered test as well as the transfer.
    expect(arms).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ armAddr: 0x40100c, closedWith: "if-goto", condJmp: true }),
      ]),
    );
    // The gate itself, on this fixture: no arm asserts the switch is over while
    // the CFG says its block goes on.
    expect(
      arms.filter((a) => a.closedWith === "break" && a.claimedHere && a.succs.length > 0),
    ).toEqual([]);
  });

  it("sends an arm that jumps into another arm there rather than out of the switch", () => {
    // `case 0` ends in `jmp` to the default body. `break` skips it; the
    // machine runs it. 10 arm blocks on t32 and 5 on w32 are this shape.
    const code = runTables(
      seq(0x401000, [
        ["cmp", "eax, 2"], // 401000
        ["ja", "0x401030"], // 401004 → default
        ["jmp", "dword ptr [eax*4 + 0x403000]"], // 401008 the table
        ["call", "0x402004"], // 40100c case 0
        ["jmp", "0x401030"], // 401010 → the default body
        ["nop"], // 401014
        ["call", "0x402008"], // 401018 case 1
        ["ret"], // 40101c
        ["nop"], // 401020
        ["call", "0x40200c"], // 401024 case 2
        ["ret"], // 401028
        ["nop"], // 40102c
        ["call", "0x402010"], // 401030 default
        ["ret"], // 401034
      ]),
      armTable,
    );

    expect(code).toMatch(
      /case (0|VAL_0x0):\s*\n\s*(eax = )?sub_402004\(\);\s*\n\s*goto loc_401030;/,
    );
    expect(code).toContain("sub_402010();");
  });
});

describe("decompileFunction — an instruction is lifted once, and reads what it reads", () => {
  /**
   * `liftBlock` used to resolve a register operand through `RegState`, i.e. to
   * the symbolic expression that register was last given — while still
   * emitting the assignment that produced it. Everything below is a
   * consequence of that (peek-a-bin-urs, peek-a-bin-zsb, peek-a-bin-juu), and
   * none of it was visible to a stage-level test: the IR the lifter handed on
   * was self-consistent, just not a description of the machine code.
   */

  it("calls a function once when the machine code calls it once", () => {
    // `test eax, eax` after a call reads the accumulator. Substituting the
    // recorded value put the whole call expression on both sides of the `&`,
    // so one CALL instruction became three calls in the emitted C — a real
    // change of behaviour for anything with a side effect, which is every
    // call the decompiler cannot see inside.
    const code = run(
      seq(0x401000, [
        ["call", "0x402000"],
        ["test", "eax, eax"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
      ]),
    );

    expect(code.match(/sub_402000\(/g)).toHaveLength(1);
  });

  it("does not leak the eflags pseudo-register into the output", () => {
    // The flag definition has no consumer, so dead-code elimination should
    // drop it. It survived only because the duplicated call inside it made
    // `hasSideEffects` true.
    const code = run(
      seq(0x401000, [
        ["call", "0x402000"],
        ["test", "eax, eax"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("eflags");
  });

  /**
   * The `eflags` pseudo-register did not merely fail to be dropped — a real
   * value could be rewritten *into* it and then deleted with it.
   *
   * `cmp ecx, edx` used to lift to `eflags = ecx - edx`, which is an ordinary
   * IR expression, so global value numbering happily gave it and the `sub eax,
   * edx` two lines above the same value number, copy propagation rewrote every
   * reader of EAX to name `eflags`, and `ssaOptimize`'s end-of-fixpoint strip
   * then deleted the only statement that assigned it. The result was C that
   * returns a register nothing assigns and in which the subtraction the machine
   * performs does not appear at all: **20 such reads across 14 functions of the
   * four corpus binaries** at `f685b6d`.
   *
   * `liftBlock` emits no `eflags` statement now, so there is nothing for GVN to
   * unify with (peek-a-bin-c33 stage 2b). This is the minimal reproduction;
   * `assign` rather than `not.toContain` because the point is that the value is
   * *present and named*, not merely that a token is absent.
   */
  it("does not rewrite a real value into the flag proxy and then delete it", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "ecx, edx"],
        ["mov", "eax, ecx"],
        ["sub", "eax, edx"],
        ["jne", "0x401018"],
        ["mov", "ebx, eax"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("eflags");
    expect(code).toContain("eax = ecx - edx");
  });

  it("does not re-expand a subexpression the register no longer holds", () => {
    // The t64 wcslen epilogue: (rax - rcx) / 2 - 1. Each instruction reads the
    // accumulator the previous one wrote, so substituting the recorded
    // expression nested it into itself and RCX came out subtracted three
    // times — arithmetically wrong, not merely verbose.
    const code = run(
      seq(0x401000, [
        ["sub", "rax, rcx"],
        ["sar", "rax, 1"],
        ["dec", "rax"],
        ["mov", "qword ptr [rdx], rax"],
        ["ret"],
      ]),
      true,
    );

    expect(code.match(/rcx/g)).toHaveLength(1);
    expect(code).toContain("rax - rcx >> 1");
  });

  it("swaps both registers on an xchg", () => {
    // `a = b; b = a` is not a swap: SSA renames the second read of `a` to the
    // definition the first statement just made, so both registers ended up
    // holding B. The lifter goes through a temporary, which copy propagation
    // then removes.
    const code = run(
      seq(0x401000, [
        ["xchg", "eax, ebx"],
        ["mov", "dword ptr [ecx], eax"],
        ["mov", "dword ptr [edx], ebx"],
        ["ret"],
      ]),
    );

    expect(code).toContain("*(int32_t*)(ecx) = ebx;");
    expect(code).toContain("*(int32_t*)(edx) = eax;");
  });

  it("takes a div's quotient and remainder from the same dividend", () => {
    // One instruction writes EAX and EDX from the same input. Emitting EAX
    // first made the remainder read the quotient.
    const code = run(
      seq(0x401000, [
        ["div", "ecx"],
        ["mov", "dword ptr [esi], eax"],
        ["mov", "dword ptr [edi], edx"],
        ["ret"],
      ]),
    );

    expect(code).toContain("edx = eax % ecx;");
    expect(code).toContain("eax /= ecx;");
  });

  it("takes a mul's high and low halves from the same product", () => {
    const code = run(
      seq(0x401000, [
        ["mul", "ecx"],
        ["mov", "dword ptr [esi], eax"],
        ["mov", "dword ptr [edi], edx"],
        ["ret"],
      ]),
    );

    expect(code).toContain("edx = eax * ecx >> 0x20;");
    expect(code).toContain("eax *= ecx;");
  });
});

describe("decompileFunction — a return names the accumulator", () => {
  /**
   * `ret` used to emit whatever expression `RegState` had recorded for RAX,
   * which is bound to the registers it names *as they were when it was
   * recorded* — and nothing invalidates it when one of them is written again
   * (peek-a-bin-lh6). Every case below is an epilogue: the point where a
   * callee-saved register is restored is exactly where the two disagree.
   */

  it("returns the value the accumulator was given, not the register it came from", () => {
    // t64 sub_140001514. RAX takes RBX, then RBX is restored from its spill
    // slot. RegState still mapped RAX to reg(RBX), so this returned the
    // restored RBX — emitted as `var_30`, the saved-register slot itself.
    const code = run(
      seq(0x401000, [["mov", "rax, rbx"], ["mov", "rbx, qword ptr [rsp + 0x30]"], ["ret"]]),
      true,
    );

    expect(code).toContain("return rbx;");
    expect(code).not.toContain("var_30");
  });

  it("does not return a value written after the accumulator was set", () => {
    // The knock-on the bead records: with the true RAX definition unread, DCE
    // deleted `rax = rbx`, that made RBX dead, and the whole `or rbx, -1`
    // block went with it. Here that block is the one being returned from, so
    // the wrong answer is visible directly — it returned -1.
    const code = run(seq(0x401000, [["mov", "rax, rbx"], ["or", "rbx, -1"], ["ret"]]), true);

    expect(code).toContain("return rbx;");
    expect(code).not.toContain("return -1;");
  });

  it("keeps a load above the store it was written before", () => {
    // The `ret` re-expanded the load, which put a second copy of it below a
    // store to an address nothing can prove does not alias.
    const code = run(
      seq(0x401000, [
        ["mov", "eax, dword ptr [ecx]"],
        ["mov", "dword ptr [edx], 7"],
        ["mov", "esi, eax"],
        ["mov", "dword ptr [ebx], esi"],
        ["ret"],
      ]),
    );

    const lines = code.split("\n");
    const load = lines.findIndex((l) => l.includes("(ecx)"));
    const store = lines.findIndex((l) => l.includes("(edx) = 7"));
    expect(load).toBeGreaterThanOrEqual(0);
    expect(load).toBeLessThan(store);
    expect(code.match(/\(ecx\)/g)).toHaveLength(1);
  });

  it("names the base register the instruction named, not the stack pointer", () => {
    // `mov ebp, esp` then a `push` — which the lifter does not model, so RSP
    // changes with nothing in the IR saying it did. Inlining the copy moved
    // the read of ESP past that push, printing a base register the
    // instruction never named and one push off the value it did name
    // (peek-a-bin-rt4). `foldBlock` now refuses it, as `ssaopt.ts` already did.
    const code = run(
      seq(0x401000, [
        ["mov", "ebp, esp"],
        ["push", "dword ptr [ebp + 8]"],
        ["call", "0x408000"],
        ["ret"],
      ]),
    );

    expect(code).toContain("sub_408000(*(int32_t*)(ebp + 8))");
    expect(code).not.toContain("esp + 8");
  });
});

describe("decompileFunction — the instructions a branch condition reads survive", () => {
  /**
   * The branch condition is not an IR value: `structure.ts` takes it from
   * `RegState.getCondition`, which recorded the `cmp`/`test` operands from the
   * *instruction*. So the registers a condition names have no IR consumer, and
   * dead-code elimination was right — given what it could see — to delete the
   * `eflags` definition and then everything that fed it (peek-a-bin-ua8).
   *
   * `ssaOptimize` now holds the flag definition of any block ending in a Jcc
   * live through the fixpoint, and drops it afterwards so nothing leaks into
   * the emitted text.
   */

  it("keeps the load a loop condition depends on, so the loop can end", () => {
    // t64 sub_14000A4AC, wcslen. Without the load that updates DX this emitted
    // `while (dx != 0) { rax += 2; }` — an infinite loop (peek-a-bin-juu).
    // The condition names the register the body assigns rather than the
    // sub-register spelling `test dx, dx` used (peek-a-bin-uxm).
    const code = run(
      seq(0x401000, [
        ["movzx", "edx, word ptr [rax]"],
        ["add", "rax, 2"],
        ["test", "dx, dx"],
        ["jne", "0x401000"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toContain("while ((uint16_t)edx != 0)");
    expect(code).toContain("(rax)");
    expect(code).toContain("rax += 2;");
  });

  it("keeps the load an if condition depends on", () => {
    const code = run(
      seq(0x402000, [
        ["mov", "ecx, dword ptr [eax]"],
        ["cmp", "ecx, 5"],
        ["jg", "0x402014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain("ecx = *(int32_t*)(eax);");
    expect(code).toContain("if (ecx > 5)");
  });

  it("does not leave the held flag definition in the output", () => {
    const code = run(
      seq(0x402000, [
        ["mov", "ecx, dword ptr [eax]"],
        ["cmp", "ecx, 5"],
        ["jg", "0x402014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("eflags");
  });
});

describe("decompileFunction — a definition read twice is not deleted after one of them", () => {
  it("keeps a definition that is read again after a call", () => {
    // `foldBlock`'s single-use scan used to stop at the first `call_stmt`,
    // which ended the *use count* as well as the hazard scan. A definition
    // read once before a call and once after therefore looked single-use: it
    // was substituted into the first read and dropped, and the second read
    // named a register nothing assigns (peek-a-bin-9ml). The call is a
    // boundary for whether the value may *move*, not for how many times it is
    // read.
    //
    // The register is RBX, which is callee-saved: the original fixture used RCX
    // and asserted that its value reached the read after the call, which is the
    // one thing the Windows x64 ABI says does not happen (peek-a-bin-0t4). The
    // defect 9ml is about — a definition read on both sides of a call counted
    // as single-use — needs a register whose value genuinely survives, or the
    // second read is not a read of that definition at all.
    const code = run(
      seq(0x401000, [
        ["lea", "rbx, [rdi + 0x30]"],
        ["mov", "qword ptr [rsp + 0x20], rbx"],
        ["call", "0x403b24"],
        ["mov", "rdx, rbx"],
        ["mov", "qword ptr [rsi], rdx"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toContain("rbx = rdi + 0x30;");
    expect(code).toContain("*(int64_t*)(rsp + 0x20) = rbx;");
    expect(code).toContain("*(int64_t*)(rsi) = rbx;");
  });

  it("keeps a definition whose other reads are in a later block", () => {
    // The same defect one block over, and the reason `foldBlock` alone cannot
    // see it: it is handed ONE block, so `totalReads === 1` means "once in this
    // block" and says nothing about the successors. `t32!sub_40D99A`'s
    // `mov ecx, [ebp+8]` has exactly one in-block reader — the store on the
    // next line — and eleven reads in the three blocks after it, so the
    // definition was inlined into the store and deleted, and every one of those
    // eleven named a register the emitted function never assigns. gcc compiles
    // that because `preludeFor` declares `ecx` as its own `long`
    // (peek-a-bin-7eyn). `blockLiveOut` is what makes the escape visible.
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, dword ptr [ebp + 8]"],
        ["mov", "dword ptr [ecx + 8], eax"],
        ["test", "eax, eax"],
        ["je", "0x401014"],
        ["mov", "dword ptr [ecx + 0xc], 1"],
        ["mov", "dword ptr [ecx + 0x18], 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain("ecx = *(int32_t*)(ebp + 8);");
    // The inlined form, which is what the definition's deletion looked like.
    expect(code).not.toContain("*(int32_t*)(*(int32_t*)(ebp + 8) + 8)");
  });

  it("still inlines a definition the block itself overwrites", () => {
    // The refusal is about a value that ESCAPES, not about the register being
    // written again later: `mov ecx, [ebp+8]` here dies at the `mov ecx, 5`
    // below it, so the live-out set describes the constant and not the load,
    // and inlining the load into its one reader remains sound. Without the
    // `killedInBlock` half of the test this would stop folding, which is churn
    // in the emitted C for no recovered value.
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, dword ptr [ebp + 8]"],
        ["mov", "dword ptr [ecx + 8], eax"],
        ["mov", "ecx, 5"],
        ["test", "eax, eax"],
        ["je", "0x401018"],
        ["mov", "dword ptr [edx + 0xc], ecx"],
        ["mov", "dword ptr [edx + 0x18], ecx"],
        ["ret"],
      ]),
    );

    expect(code).toContain("*(int32_t*)(*(int32_t*)(ebp + 8) + 8) = eax;");
    // The constant reaches both later blocks under its own value rather than
    // under the load's, which is what says the live range really did end here.
    expect(code).toContain("*(int32_t*)(edx + 0xC) = 5;");
    expect(code).toContain("*(int32_t*)(edx + 0x18) = 5;");
  });
});

/**
 * A logical shift right, which C has no operator for (peek-a-bin-kce).
 *
 * `shr` lifts to `>>>`, JavaScript's unsigned shift, and it used to reach the
 * output verbatim — 66 syntax errors over three real binaries, the largest
 * remaining category. The repair has to carry a width: `>>` alone is an
 * arithmetic shift and shifts the sign bit in where the machine shifts zeros,
 * and a fixed `(uintptr_t)` cast picks a width instead of finding one. The
 * width is on the operand node, which is why none of this needed new IR.
 */
describe("decompileFunction — a logical shift right says which bits it shifts", () => {
  it("takes the width from a 32-bit register operand", () => {
    const code = run(seq(0x401000, [["shr", "eax, 1"], ["ret"]]));

    expect(code).toContain("(uint32_t)eax >> 1");
    expect(code).not.toContain(">>>");
  });

  it("takes the width from a 64-bit register operand", () => {
    const code = run(
      seq(0x401000, [["shr", "rdx, 0x10"], ["mov", "qword ptr [rcx], rdx"], ["ret"]]),
      true,
    );

    expect(code).toContain("(uint64_t)rdx >> 0x10");
    expect(code).not.toContain(">>>");
  });

  it("takes the width of a memory operand from the access size", () => {
    const code = run(seq(0x401000, [["shr", "byte ptr [ebp + 8], 3"], ["ret"]]));

    expect(code).toContain("(uint8_t)");
    expect(code).not.toContain(">>>");
  });

  it("has no compound form, so the shift is spelled out", () => {
    // `x >>>= 1` was emitted too, and `x >>= 1` would be the arithmetic shift.
    const code = run(seq(0x401000, [["shr", "ecx, 1"], ["mov", "dword ptr [edx], ecx"], ["ret"]]));

    expect(code).not.toContain(">>>=");
    expect(code).toContain("(uint32_t)ecx >> 1");
  });

  it("parenthesises a compound operand, so the cast applies to all of it", () => {
    // `(uint32_t)eax + 4 >> 1` would compile and mean something else: the cast
    // binds tighter than the addition. This is the silent-wrong-value case.
    const code = run(seq(0x401000, [["add", "eax, 4"], ["shr", "eax, 1"], ["ret"]]));

    expect(code).toMatch(/\(uint32_t\)\(eax \+ 4\) >> 1/);
  });

  it("reports the value rather than emit a shift the width contradicts", () => {
    // 32 bits off an 8-bit operand: one of the two is wrong, and every C
    // spelling of it would state a width. `>> 32` on a `uint8_t` is also
    // undefined behaviour, so it would not even be reliably wrong.
    const code = run(seq(0x401000, [["shr", "al, 0x20"], ["ret"]]));

    expect(code).toContain("__unrecovered_1");
    expect(code).toContain("logical shift right");
    expect(code).toMatch(/intptr_t __unrecovered_1;\s*\/\* not recovered/);
    expect(code).not.toContain(">>>");
  });
});

/**
 * A truncated string states the prefix it recovered, not a value ending in
 * three dots (peek-a-bin-7l0).
 */
describe("decompileFunction — a shortened string literal stays true", () => {
  function runStrings(instructions: Instruction[], strings: Map<number, string>): string {
    const start = instructions[0].address;
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: start,
      size: last.address + last.size - start,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      new Map(),
      new Map(),
      strings,
      new Map(),
    ).code;
  }

  const push = (): Instruction[] => seq(0x401000, [["mov", "eax, 0x403000"], ["ret"]]);

  it("keeps the ellipsis outside the quotes, where it cannot be read as data", () => {
    const long = "C:\\Users\\Public\\Documents\\Very\\Long\\Path\\file.txt";
    const code = runStrings(push(), new Map([[0x403000, long]]));

    const prefix = long.slice(0, 37).replace(/\\/g, "\\\\");
    expect(code).toContain(`"${prefix}" /* + ${long.length - 37} more characters */`);
    expect(code).not.toContain('..."');
  });

  it("leaves a string that fits exactly as it is", () => {
    const code = runStrings(push(), new Map([[0x403000, "short one"]]));

    expect(code).toContain('"short one"');
    expect(code).not.toContain("more characters");
  });
});

/**
 * The enum synthesised for a switch reaches the output as a declaration
 * (peek-a-bin-a0p), and its member names stay where they mean something.
 */
describe("decompileFunction — a synthesised enum is declared before it is used", () => {
  function runTables(instructions: Instruction[], tables: Map<number, number[]>): string {
    const start = instructions[0].address;
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: start,
      size: last.address + last.size - start,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      tables,
      new Map(),
      new Map(),
      new Map(),
    ).code;
  }

  const threeCases = (): Instruction[] =>
    seq(0x401000, [
      ["cmp", "eax, 2"], // 401000
      ["ja", "0x401024"], // 401004 out of range → default
      ["jmp", "dword ptr [eax*4 + 0x403000]"], // 401008 the table
      ["mov", "dword ptr [edi], 2"], // 40100c case 0 — an unrelated 2
      ["ret"], // 401010
      ["call", "0x402008"], // 401014 case 1
      ["ret"], // 401018
      ["call", "0x40200c"], // 40101c case 2
      ["ret"], // 401020
      ["call", "0x402010"], // 401024 default
      ["ret"], // 401028
    ]);

  const table = new Map([[0x401008, [0x40100c, 0x401014, 0x40101c]]]);

  it("declares every member it names, with the value the name stands for", () => {
    const code = runTables(threeCases(), table);

    // The case labels were emitted as undeclared identifiers: not integer
    // constant expressions, so the switch did not compile.
    expect(code).toMatch(/typedef enum \{[^}]*VAL_0x0 = 0[^}]*\} enum_0;/);
    expect(code).toContain("case VAL_0x0:");
    expect(code.indexOf("typedef enum")).toBeLessThan(code.indexOf("case VAL_0x0:"));
  });

  it("leaves an unrelated constant of the same value alone", () => {
    // Every literal matching any member of any enum in the function used to be
    // renamed — a coincidence of value read as membership of the enumeration.
    const code = runTables(threeCases(), table);

    expect(code).toContain("*(int32_t*)(edi) = 2;");
    expect(code).not.toContain("VAL_0x2;");
  });
});

/**
 * A field the layout calls an array, accessed as a scalar (peek-a-bin-hyv).
 *
 * `structs.ts` marks an offset `isArray` when an index reaches it, and direct
 * accesses to the same offset stay — a direct access *is* consistent with an
 * array, being element zero, so the two readings only contradict each other
 * when the stride is not the width read there (the last case below, which
 * structs.ts now settles by dropping the array claim). The spelling still has to
 * be true either way: `p->array_0x0` is an address, not the value at that
 * offset, so reading one silently yielded a pointer where the machine loaded
 * data, and writing one did not compile at all.
 */
describe("decompileFunction — a scalar access to an array field means that access", () => {
  /** As `runWithStructs`, in 64-bit mode. */
  function run64WithStructs(instructions: Instruction[]): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      true,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      new StructRegistry(),
    ).code;
  }

  const indexedAndDirect = (store: string): Instruction[] =>
    seq(0x401000, [
      ["mov", "dword ptr [ecx + eax*4], edx"], // the indexed access that sets isArray
      ["mov", "dword ptr [ecx + 0x10], esi"], // a second offset, so a struct is synthesised
      [store.split("|")[0], store.split("|")[1]],
      ["ret"],
    ]);

  it("writes the first element, when the access is exactly one element wide", () => {
    const code = runWithStructs(indexedAndDirect("mov|dword ptr [ecx], 0x16"));

    expect(code).toContain("array_0x0[0] = 0x16;");
    expect(code).not.toMatch(/->array_0x0 = /);
  });

  it("reads the first element rather than the array's address", () => {
    // `edx = p->array_0x0;` compiles and means the address — a wrong value that
    // no compiler complains about, which is the worse half of this defect.
    const code = runWithStructs([
      ...indexedAndDirect("mov|edi, dword ptr [ecx]").slice(0, 3),
      ins(0x40100c, "mov", "dword ptr [ebx], edi"),
      ins(0x401010, "ret"),
    ]);

    expect(code).toContain("array_0x0[0]");
    expect(code).not.toMatch(/= \(\(struct_0 \*\)ecx\)->array_0x0;/);
  });

  it("does not call an offset an array when the stride is not the width read there", () => {
    // The other half of peek-a-bin-hyv, and the one that had to be settled in
    // structs.ts: the index walks in steps of 4 while the widest access at the
    // offset is 8. `uint64_t array_0x0[n]` describes an object neither reading
    // found — the elements are not 8 bytes, and an array of 4-byte elements is
    // not what was written. The width is a direct measurement of one access, so
    // it is kept; the array claim is the one dropped, and the name says so.
    const code = run64WithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [rcx + rax*4], edx"],
        ["mov", "dword ptr [rcx + 0x10], esi"],
        ["mov", "qword ptr [rcx], rdx"],
        ["ret"],
      ]),
    );

    expect(code).toContain("((struct_0 *)rcx)->field_0x0 = rdx;");
    expect(code).toContain("uint64_t field_0x0;");
    expect(code).not.toContain("array_0x0");
  });
});

/**
 * The layout an emitted struct definition actually has (peek-a-bin-ey0).
 *
 * A field *name* carries the offset the recovery found, so the declaration is
 * only true if C puts the field there. 131 of the 149 struct definitions emitted
 * over the three distlib binaries did not: the fields were declared back to back
 * and the compiler placed them by its own alignment rules, so
 * `struct_0 { uint32_t field_0x0; uint16_t field_0x18; }` read byte 4 every time
 * the body said `field_0x18`. Valid C, stating something the machine does not do.
 *
 * These assert on the layout rather than on the spelling: the emitted block is
 * read back the way a compiler under `#pragma pack(1)` reads it, and every field
 * has to land where its own name says. The gcc side of the same measurement —
 * `offsetof` over every emitted struct of the three binaries — is in the bead.
 */
describe("decompileFunction — a struct lays out at the offsets its field names record", () => {
  /** The width of a member spelling, as a compiler under `#pragma pack(1)` sees it. */
  function widthOf(type: string): number {
    const fixed = /^u?int(8|16|32|64)_t$/.exec(type);
    if (fixed) return Number(fixed[1]) / 8;
    if (type.endsWith("*")) return 8; // a pointer, on any compiler this targets
    if (type === "float") return 4;
    if (type === "double") return 8;
    return 4; // `int`, `unsigned int`
  }

  /**
   * Every member of `struct <id>` in the emitted code and the offset it lands
   * at, computed from the declarations alone — nothing here asks the emitter
   * where it thinks it put them.
   */
  function emittedLayout(code: string, id: string): Map<string, number> {
    const start = code.indexOf(`struct ${id} {`);
    expect(start, `no definition of ${id}`).toBeGreaterThanOrEqual(0);
    const body = code.slice(start, code.indexOf("};", start));
    const offsets = new Map<string, number>();
    let cursor = 0;
    for (const raw of body.split("\n").slice(1)) {
      const line = raw.trim();
      if (!line || line.startsWith("/*")) continue;
      const m = /^([A-Za-z_]\w*\s*\*?)\s+(\w+)(?:\[(\w*)\])?;/.exec(line);
      expect(m, `unparsed member: ${line}`).not.toBeNull();
      if (!m) continue;
      const [, type, name, count] = m;
      offsets.set(name, cursor);
      const element = widthOf(type.replace(/\s+/g, ""));
      cursor += count === undefined ? element : count === "" ? 0 : element * Number(count);
    }
    return offsets;
  }

  /** Every field of every emitted struct sits at the offset its name records. */
  function expectNamesToMatchLayout(code: string): void {
    const ids = [...code.matchAll(/^struct (struct_\w+) \{$/gm)].map((m) => m[1]);
    expect(ids.length).toBeGreaterThan(0);
    for (const id of ids) {
      for (const [name, offset] of emittedLayout(code, id)) {
        const recorded = /^(?:field|array)_0x([0-9A-F]+)$/.exec(name);
        if (!recorded) continue; // padding
        expect(offset, `${id}.${name}`).toBe(Number.parseInt(recorded[1], 16));
      }
    }
  }

  it("pads the gap between two fields, so the second is where its name says", () => {
    const code = runWithStructs(
      seq(0x401000, [["mov", "dword ptr [ebx], 1"], ["mov", "word ptr [ebx + 0x18], dx"], ["ret"]]),
    );

    // The defect exactly: C put field_0x18 at 4.
    expect(code).toContain("uint8_t _pad_0x4[0x14];");
    expect(emittedLayout(code, "struct_0").get("field_0x18")).toBe(0x18);
    expectNamesToMatchLayout(code);
  });

  it("packs, because padding alone cannot express an unaligned offset", () => {
    // field_0x3 is 4 bytes wide at an offset of 3. Padding puts it there and
    // default alignment moves it straight back to 4; only the pragma holds it.
    const code = runWithStructs(
      seq(0x401000, [["mov", "byte ptr [ebx], 1"], ["mov", "dword ptr [ebx + 3], eax"], ["ret"]]),
    );

    expect(code).toContain("#pragma pack(push, 1)");
    expect(code).toContain("#pragma pack(pop)");
    expect(code.indexOf("#pragma pack(push, 1)")).toBeLessThan(code.indexOf("struct struct_0 {"));
    expect(emittedLayout(code, "struct_0").get("field_0x3")).toBe(3);
  });

  it("declares a field at the width its access had when the inferred type would move the next one", () => {
    // field_0x8 holds a pointer, and 32-bit pointers are 4 bytes — but the
    // emitted C is read with 8-byte ones, which would put field_0xC at 0x10.
    // The inferred type is what the reader wants and the offset is what the
    // recovery established, so the type moves to a comment.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0xC], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["ret"],
      ]),
    );

    expect(code).toContain("uint32_t field_0x8; /* struct_1* */");
    expect(emittedLayout(code, "struct_0").get("field_0xC")).toBe(0xc);
    expectNamesToMatchLayout(code);
  });

  it("keeps the inferred type where it displaces nothing", () => {
    // The same shape with the next field 8 bytes on: the pointer fits, so the
    // declaration that says what the object is stays.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x10], 1"],
        ["mov", "esi, dword ptr [ebx + 8]"],
        ["mov", "dword ptr [esi], 7"],
        ["mov", "dword ptr [esi + 4], 9"],
        ["ret"],
      ]),
    );

    expect(declaredType(code, "field_0x8")).toBe("struct_1*");
    expect(emittedLayout(code, "struct_0").get("field_0x10")).toBe(0x10);
    expectNamesToMatchLayout(code);
  });

  it("keeps an array field's element size and its extent in agreement", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + ecx*4], 1"],
        ["mov", "word ptr [ebx + 0x12], dx"],
        ["ret"],
      ]),
    );

    // Four whole 4-byte elements fit below 0x12; the odd two bytes are padding,
    // not a fifth element the accesses never reached.
    expect(code).toContain("uint32_t array_0x0[4];");
    expect(code).toContain("uint8_t _pad_0x10[2];");
    expect(emittedLayout(code, "struct_0").get("field_0x12")).toBe(0x12);
    expectNamesToMatchLayout(code);
  });
});

/**
 * The other half of the layout work: a grouping that produces a field no struct
 * can lay out is a grouping that was wrong (peek-a-bin-u3v).
 *
 * Once the emitter stopped putting fields wherever C's alignment rules said
 * (peek-a-bin-ey0) it started reporting the ones it could not place at all —
 * over the three distlib binaries, 68 fields at a negative offset, 9 whose bytes
 * overlapped a field already placed and 13 past the largest layout the emitted
 * dialect states. Each is a question about the *grouping*, and the answers here
 * are, in order:
 *
 * - An access before the base belongs to some other object. The base of t64's
 *   `__handler_1400043dc` is `rdi + (rsi + 1) * 16`, an array element pointer,
 *   and its `[rbx - 0xC]` reaches the previous element — so the object the base
 *   names is what lies at and after it, and that is what is declared.
 * - An access whose bytes are inside a field already recovered is a second
 *   reading of that field, not a second field.
 * - A displacement of 0x412620 is an address, not an offset.
 *
 * In every case the access itself is still emitted — as the byte-addressed
 * dereference it is — so nothing is dropped, only the claim that it was a
 * member. The three "must still fire" tests are the other direction: a base
 * with real fields keeps them, and refusing to group is not the same as
 * refusing to recover.
 */
describe("decompileFunction — struct synthesis does not group what no struct can lay out", () => {
  /** As `runWithStructs`, in 64-bit mode, where an 8-byte field is reachable. */
  function run64(instructions: Instruction[]): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      true,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      new StructRegistry(),
    ).code;
  }

  it("does not make a field of an access that reaches behind the base", () => {
    // Two eligible offsets are needed for a candidate at all, so `[ebx - 2]`
    // not being one of them is also what leaves this base with a single field
    // and no struct.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "word ptr [ebx - 2], dx"],
        ["mov", "dword ptr [ebx + 4], eax"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("struct");
    expect(code).not.toContain("field_neg_0x2");
    // Both accesses are still there, as the byte offsets they are.
    expect(code).toContain("*(uint16_t*)(ebx - 2) = dx;");
    expect(code).toContain("*(int32_t*)(ebx + 4) = eax;");
  });

  it("keeps the object at and after a base an access reaches behind", () => {
    // The array-element-pointer shape: the accesses at and after the base are
    // an object, the one before it is the previous element's business.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "word ptr [ebx - 2], dx"],
        ["mov", "dword ptr [ebx + 4], eax"],
        ["mov", "dword ptr [ebx + 0xC], eax"],
        ["ret"],
      ]),
    );

    expect(code).toContain("struct struct_0 {");
    expect(code).toContain("uint32_t field_0x4;");
    expect(code).toContain("uint32_t field_0xC;");
    expect(code).not.toContain("neg_0x2");
    expect(code).toContain("*(uint16_t*)(ebx - 2) = dx;");
  });

  it("does not make a second field of an access inside a field already recovered", () => {
    // An 8-byte access at 0 and a 2-byte access at 2 cannot both be members:
    // one of the two readings is wrong, and no amount of padding places both.
    // A union would say they are both members of one object, which is a claim
    // about the object rather than about the accesses that were seen.
    const code = run64(
      seq(0x401000, [
        ["mov", "qword ptr [rbx], rax"],
        ["mov", "word ptr [rbx + 2], dx"],
        ["mov", "qword ptr [rbx + 8], rcx"],
        ["ret"],
      ]),
    );

    expect(code).toContain("uint64_t field_0x0;");
    expect(code).toContain("uint64_t field_0x8;");
    expect(code).not.toContain("field_0x2");
    // The reading is still in the output, as the store to those two bytes.
    expect(code).toContain("*(uint16_t*)(rbx + 2) = dx;");
  });

  it("does not synthesise a struct when the overlapping reading was the only other one", () => {
    // {0:8, 2:2} is two distinct offsets and used to be a candidate on that
    // count alone. One field is left after the contradiction is settled, and
    // one field is not evidence of a struct.
    const code = run64(
      seq(0x401000, [["mov", "qword ptr [rbx], rax"], ["mov", "word ptr [rbx + 2], dx"], ["ret"]]),
    );

    expect(code).not.toContain("struct");
    expect(code).toContain("*(int64_t*)(rbx) = rax;");
    expect(code).toContain("*(uint16_t*)(rbx + 2) = dx;");
  });

  it("does not treat an absolute address that reached a base as a displacement as a field", () => {
    // Both offsets are addresses, not positions in an object — the shape of
    // t32's `[eax + 0x412620]`, a global table indexed by a register. Declaring
    // the first means 36KB of padding nobody observed, and the struct this used
    // to produce had nothing in it but the two reports.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x9000], eax"],
        ["mov", "dword ptr [ebx + 0x9100], eax"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("struct");
    expect(code).toContain("*(int32_t*)(ebx + 0x9000) = eax;");
    expect(code).toContain("*(int32_t*)(ebx + 0x9100) = eax;");
  });

  it("keeps the fields a base really has when an address also reaches it", () => {
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx + 0x9000], eax"],
        ["mov", "dword ptr [ebx + 4], eax"],
        ["mov", "dword ptr [ebx + 0xC], eax"],
        ["ret"],
      ]),
    );

    expect(code).toContain("struct struct_0 {");
    expect(code).toContain("uint32_t field_0x4;");
    expect(code).toContain("uint32_t field_0xC;");
    expect(code).not.toContain("field_0x9000");
    expect(code).toContain("*(int32_t*)(ebx + 0x9000) = eax;");
  });

  it("still recovers an ordinary struct, which is what all of this is for", () => {
    // The over-correction guard: two ordinary offsets on one base are still a
    // struct, are still declared, and their accesses are still field accesses.
    const code = runWithStructs(
      seq(0x401000, [
        ["mov", "dword ptr [ebx], 1"],
        ["mov", "dword ptr [ebx + 0x18], eax"],
        ["ret"],
      ]),
    );

    expect(code).toContain("struct struct_0 {");
    expect(code).toContain("((struct_0 *)ebx)->field_0x0 = 1;");
    expect(code).toContain("((struct_0 *)ebx)->field_0x18 = eax;");
  });
});

/**
 * A field the code does bitwise arithmetic on is not a pointer (peek-a-bin-h89).
 *
 * `struct_4::field_0x18` in t64 was declared `struct_4 *` and then masked:
 * `((struct_4 *)rdx)->field_0x18 |= 0x20`, which does not compile and, more to
 * the point, is not what the field is — all six of its uses in that binary are
 * flag arithmetic on a CRT `FILE::_flag`. The pointer came from *another*
 * function, which loaded the value and used it as a base, and reached this one
 * because StructFields are shared live registry state.
 *
 * The two functions below are that pair, sharing a registry as the worker's
 * does. Both orders are checked: which function a session decompiles first is
 * not evidence about the field.
 */
describe("decompileFunction — arithmetic on a field is evidence against a pointer", () => {
  function run(instructions: Instruction[], registry: StructRegistry): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: `sub_${instructions[0].address.toString(16).toUpperCase()}`,
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      false,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      registry,
    ).code;
  }

  /** Loads field 0x18 and dereferences the value at two offsets: the nesting. */
  const promoter = (): Instruction[] =>
    seq(0x401000, [
      ["mov", "dword ptr [ebx + 0x30], 1"],
      ["mov", "esi, dword ptr [ebx + 0x18]"],
      ["mov", "dword ptr [esi], 7"],
      ["mov", "dword ptr [esi + 4], 9"],
      ["ret"],
    ]);

  /** Sets a bit in the same field of the same shape. */
  const masker = (): Instruction[] =>
    seq(0x402000, [
      ["mov", "dword ptr [ebx + 0x30], 1"],
      ["or", "dword ptr [ebx + 0x18], 0x20"],
      ["ret"],
    ]);

  it("takes back a pointer type when a later function masks the field", () => {
    const registry = new StructRegistry();
    expect(run(promoter(), registry)).toContain("struct_1* field_0x18;");

    const code = run(masker(), registry);

    expect(declaredType(code, "field_0x18")).toBe("uint32_t");
    expect(code).toContain("->field_0x18 |= 0x20;");
    expect(code).not.toContain("struct_1*");
  });

  it("refuses the pointer when the mask was seen first", () => {
    const registry = new StructRegistry();
    run(masker(), registry);

    const code = run(promoter(), registry);

    // The nesting is still visible where it belongs — esi is used as a base —
    // but the field it came out of is not declared as one.
    expect(declaredType(code, "field_0x18")).toBe("uint32_t");
    expect(code).toContain("((struct_1 *)esi)->field_0x0 = 7;");
  });
});

/**
 * A machine `add`/`sub` is byte arithmetic. C's `+`/`-` is not, once an operand
 * has a pointer type — it scales by the pointee, and struct recovery hands the
 * emitter pointer-typed fields all the time. Two consequences, one loud and one
 * silent, and the silent one is the worse of the two: `p->field + 8` on a
 * `struct_1*` field compiles and means 8 *objects* on, which is a statement the
 * machine code contradicts (peek-a-bin-d8t, peek-a-bin-q30).
 */
describe("decompileFunction — arithmetic on a recovered address is byte arithmetic", () => {
  function run64(instructions: Instruction[]): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      true,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      new StructRegistry(),
    ).code;
  }

  /**
   * Loads the field at 0x10 and uses it as a base twice, which is what makes it
   * a `struct_1*`. The CRT `FILE` shape this is taken from does the same to
   * `_base`, and then subtracts it from `_ptr`.
   */
  const nestedAt0x10 = (): [string, string?][] => [
    ["mov", "rdx, qword ptr [rbx + 0x10]"],
    ["mov", "qword ptr [rdx], 7"],
    ["mov", "qword ptr [rdx + 8], 9"],
  ];

  it("states the byte difference of two recovered addresses", () => {
    const code = run64(
      seq(0x401000, [
        ...nestedAt0x10(),
        ["mov", "rcx, qword ptr [rbx + 0x10]"],
        ["mov", "rax, qword ptr [rbx]"],
        ["sub", "rax, rcx"],
        ["ret"],
      ]),
    );

    // The two fields are recovered as one integer word and one struct pointer,
    // and C rejects the subtraction outright — the last five gcc errors over
    // the three distlib binaries were all this line.
    expect(code).toContain("field_0x0 - (uintptr_t)");
    expect(code).toContain("(uintptr_t)((struct_0 *)rbx)->field_0x10");
    // The recovery itself is untouched: both fields keep the types the
    // evidence gave them, so nothing about which one is right is hidden.
    expect(declaredType(code, "field_0x10")).toBe("struct_1*");
  });

  it("adds the bytes the instruction added, not that many objects", () => {
    const code = run64(
      seq(0x401000, [
        ...nestedAt0x10(),
        ["mov", "rcx, qword ptr [rbx + 0x10]"],
        ["add", "rcx, 8"],
        ["mov", "qword ptr [rbx + 0x20], rcx"],
        ["ret"],
      ]),
    );

    // `p->field_0x10 + 8` compiles, and on a `struct_1*` means 0x80 bytes on.
    expect(code).toContain("(uintptr_t)((struct_0 *)rbx)->field_0x10 + 8");
  });

  it("leaves a bitwise use of a pointer-typed field to say what it says", () => {
    // The counterpart case (peek-a-bin-h89): a mask of a value inferred as a
    // pointer is a contradiction between two claims, and emit has no evidence
    // about which of them is wrong. `&` therefore gets no cast — unlike `-`,
    // it is not an operation C defines on addresses at all, so making it
    // compile would mean retracting one claim silently.
    const code = run64(
      seq(0x401000, [
        ...nestedAt0x10(),
        ["mov", "rcx, qword ptr [rbx + 0x10]"],
        ["and", "rcx, 0xFFFFFFF0"],
        ["mov", "qword ptr [rbx + 0x20], rcx"],
        ["ret"],
      ]),
    );

    expect(code).toContain("& 0xFFFFFFF0");
    expect(code).not.toContain("(uintptr_t)((struct_0 *)rbx)->field_0x10 &");
  });
});

/**
 * A sub-register read is a read of the same storage the body writes under a
 * wider name, and the emitted C used to say otherwise: `while (dx != 0)` around
 * a body whose only assignment is to `edx` names a variable nothing in the
 * function assigns, so as C the loop cannot terminate (peek-a-bin-uxm).
 */
describe("decompileFunction — a sub-register read names storage the body writes", () => {
  function run64(instructions: Instruction[]): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      true,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
    ).code;
  }

  it("narrows the register the loop body assigns, so the loop can end", () => {
    // t64's wcslen: movzx into edx, test dx.
    const code = run64(
      seq(0x401000, [
        ["mov", "rax, rcx"],
        ["movzx", "edx, word ptr [rax]"],
        ["add", "rax, 2"],
        ["test", "dx, dx"],
        ["jne", "0x401004"],
        ["ret"],
      ]),
    );

    expect(code).toContain("while ((uint16_t)edx != 0)");
    expect(code).not.toMatch(/\bdx != 0/);
  });

  it("leaves a sub-register the body does assign exactly as it is", () => {
    // t32's wcslen writes `dx` itself, so the C already says what it means and
    // a cast would be noise.
    const code = run64(
      seq(0x401000, [
        ["mov", "rax, rcx"],
        ["mov", "dx, word ptr [rax]"],
        ["add", "rax, 2"],
        ["test", "dx, dx"],
        ["jne", "0x401004"],
        ["ret"],
      ]),
    );

    expect(code).toContain("while (dx != 0)");
    expect(code).not.toContain("(uint16_t)");
  });

  it("keeps a signed test of the low byte signed", () => {
    // `js` after a load into edx tests bit 7 of DL. An unsigned narrowing would
    // make `>= 0` constantly true — compilable, and a different program. The
    // width comes from the register name, the signedness from the operator.
    const code = run64(
      seq(0x401000, [
        ["mov", "edx, dword ptr [rcx]"],
        ["test", "dl, dl"],
        ["js", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain("if ((int8_t)edx >= 0)");
    expect(code).not.toContain("(uint8_t)edx");
  });
});

/**
 * A call destroys the registers it was passed, and the emitted C has to say so.
 *
 * The IR used to record only the result register, so SSA bound a read after a
 * call to the definition before it — and every pass downstream was then
 * entitled to propagate that value across the call. The output did not lose
 * anything, it *stated* something false: `*(int64_t*)(rsi) = rcx;` with RCX
 * still bound to the `lea` above the call (peek-a-bin-0t4).
 *
 * Stripping the version alone would not fix it. C's `rcx` holds whatever the
 * last `rcx = …` line assigned, so a bare `rcx` after the call reads exactly
 * the pre-call value; the read has to name something else.
 *
 * The model is deliberately narrower than the ABI's volatile set, which also
 * covers R10 and R11 — see `clobberedByCall` in `ssa.ts` for the measurements
 * that decided it, and the R10 case below for what the wider set cost.
 */
describe("decompileFunction — a register a call was passed does not survive it", () => {
  it("does not bind a post-call read of RCX to the definition before the call", () => {
    // Windows x64: RCX is volatile. `mov rdx, rcx` after the call reads
    // whatever the callee left there, not `rbx + 0x30`.
    const code = run(
      seq(0x401000, [
        ["lea", "rcx, [rbx + 0x30]"],
        ["call", "0x403b24"],
        ["mov", "rdx, rcx"],
        ["mov", "qword ptr [rsi], rdx"],
        ["ret"],
      ]),
      true,
    );

    const store = code.split("\n").find((l) => l.includes("(rsi)"));
    expect(store).toBeDefined();
    // Before the fix: `*(int64_t*)(rsi) = rcx;` with `rcx = rbx + 0x30;` above.
    expect(store).not.toMatch(/=\s*rcx\s*;/);
    expect(store).not.toContain("rbx + 0x30");
    expect(code).toContain("clobbered_rcx");
    // The argument the call really was given is still there.
    expect(code).toContain("sub_403B24(rbx + 0x30)");
  });

  it("lets a callee-saved register survive the same call", () => {
    // RBX is non-volatile under every Windows calling convention: clobbering it
    // too would throw away a real definition chain rather than a false one.
    const code = run(
      seq(0x401000, [
        ["lea", "rbx, [rdi + 0x30]"],
        ["call", "0x403b24"],
        ["mov", "qword ptr [rsi], rbx"],
        ["ret"],
      ]),
      true,
    );

    const store = code.split("\n").find((l) => l.includes("(rsi)"));
    expect(store).toContain("rbx");
    expect(code).not.toContain("clobbered_rbx");
  });

  it("lets R10 survive a call it was not passed, because compiled code relies on that", () => {
    // R10 is volatile under the ABI, and MSVC still parks live values there
    // across calls to helpers it has analysed: t64!sub_1400063E8 holds `[rcx]`
    // in R10 across two of them, and `__chkstk` preserves everything but
    // RAX/R10/R11 by contract. Clobbering the whole volatile set deleted a
    // guard outright in t64!sub_140004A9C. The claim this file pins is the
    // narrow one — the call consumed RCX, and nothing was said about R10.
    const code = run(
      seq(0x401000, [
        ["lea", "r10, [rbx + 0x30]"],
        ["mov", "rcx, rdi"],
        ["call", "0x403b24"],
        ["mov", "qword ptr [rsi], r10"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toContain("r10 = rbx + 0x30;");
    expect(code).toContain("*(int64_t*)(rsi) = r10;");
    expect(code).not.toContain("clobbered_r10");
  });

  it("keeps the value on the path that does not call, and only that path", () => {
    // rcx is 1 at the join only when the branch skipped the call; the calling
    // arm passes 2 and gets back something indeterminate. Before the fix the
    // arm emitted `rcx = 2;` and the join read it, so the store claimed the
    // argument was still in RCX afterwards.
    const code = run(
      seq(0x401000, [
        ["mov", "rcx, 1"], // 0x401000
        ["cmp", "rdx, 0"], // 0x401004
        ["je", "0x401014"], // 0x401008
        ["mov", "rcx, 2"], // 0x40100c
        ["call", "0x403b24"], // 0x401010
        ["mov", "qword ptr [rsi], rcx"], // 0x401014 — the join
        ["ret"], // 0x401018
      ]),
      true,
    );

    expect(code).toContain("if (rdx != 0)");
    expect(code).toContain("sub_403B24(2)");
    // The calling arm has to say the register no longer holds the argument.
    expect(code).toMatch(/rcx = clobbered_rcx_\d+;/);
    expect(code).toContain("*(int64_t*)(rsi) = rcx;");
  });

  it("does not carry a value round a loop through a call in its body", () => {
    // The call at the top of the body is passed RCX and destroys it, so the
    // increment below is not of the previous trip's value. Before the fix the
    // increment disappeared altogether — `do { sub_403B24(rdi); } while (rcx <
    // 0x10);`, a loop that as C cannot terminate.
    const code = run(
      seq(0x401000, [
        ["mov", "rbx, rdi"], // 0x401000
        ["mov", "rcx, rbx"], // 0x401004 — loop header
        ["call", "0x403b24"], // 0x401008
        ["add", "rcx, 1"], // 0x40100c
        ["cmp", "rcx, 0x10"], // 0x401010
        ["jb", "0x401004"], // 0x401014
        ["ret"], // 0x401018
      ]),
      true,
    );

    expect(code).toMatch(/rcx = clobbered_rcx_\d+ \+ 1;/);
    expect(code).toContain("while (rcx < 0x10)");
  });
});

/**
 * A function is never told about a register its image cannot have.
 *
 * `canonReg` maps every alias to the 64-bit parent because that is the register's
 * *identity*, and SSA keys on identity: `insertPhis` builds every phi from the
 * canonical name and `renameVariables` forces the destination back to it. So a
 * phi in a 32-bit function is a phi over `rdi` at size 8 — `phi.dest.size` is
 * `regSize("rdi")`, not the width of anything the code did — and lowering it to a
 * copy emitted `rdi = rax` inside a function whose every other line says `edi`.
 * 77 of t32.exe's 293 functions named a register the image has no encoding for
 * (peek-a-bin-1k4), and the same canonical name reached `clobberedName`, so a
 * 32-bit call produced `clobbered_rcx_2` (peek-a-bin-4hg).
 *
 * The width is not recoverable from the phi, so it is taken from the code:
 * `destroySSA` spells a canonical register with the widest spelling the
 * function's own statements use. That can never invent RDI in a 32-bit image,
 * and in a 64-bit one it prefers the 64-bit name wherever the code uses it.
 */
describe("decompileFunction — register names belong to the image's width", () => {
  /**
   * `mov edi, eax` in one arm of a diamond inside a loop: copy propagation
   * rewrites the phi operand for EDI to EAX, so the phi's two sides have
   * different canonical registers and the copy is emitted rather than skipped
   * as a self-copy. This is t32!sub_4010D4's shape.
   */
  const phiCopy = (regs: [string, string, string, string]): Instruction[] => {
    const [di, ax, cx, dx] = regs;
    return seq(0x401000, [
      ["mov", `${di}, 0`], // 401000
      ["mov", `${ax}, ${cx}`], // 401004 — loop top
      ["test", `${ax}, ${ax}`], // 401008
      ["je", "0x401024"], // 40100c — exit
      ["cmp", `${dx}, ${ax}`], // 401010
      ["jne", "0x40101c"], // 401014 — skip the assignment
      ["mov", `${di}, ${ax}`], // 401018
      ["add", `${cx}, 1`], // 40101c — the join
      ["jmp", "0x401004"], // 401020 — back edge
      ["mov", `${ax}, ${di}`], // 401024
      ["ret"], // 401028
    ]);
  };

  /** Registers x86-32 has no encoding for, as whole identifiers. */
  const REG64_ONLY =
    /\b(?:clobbered_)?(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|r(?:8|9|1[0-5])[bwd]?)(?:_\d+)?\b/;

  it("lowers a phi to a copy at the width the 32-bit code wrote", () => {
    const code = run(phiCopy(["edi", "eax", "ecx", "edx"]));

    // Before: `rdi = rcx;`.
    expect(code).toContain("edi = ecx;");
    expect(code).not.toMatch(REG64_ONLY);
  });

  it("still uses the 64-bit name for the same shape in 64-bit code", () => {
    // The narrowing must be driven by what the code says, not applied blindly:
    // here every statement names the 64-bit register, so the copy must too.
    const code = run(phiCopy(["rdi", "rax", "rcx", "rdx"]), true);

    expect(code).toContain("rdi = rcx;");
  });

  it("names a clobbered 32-bit argument register after the register that exists", () => {
    // `push ecx` makes ECX argument 1 by `collectArgs32`, which is what
    // `clobberedByCall` reads as "the call was given this register", so the read
    // after the call is of an indeterminate value and needs a name of its own.
    // Before: `clobbered_rcx_2`.
    const code = run(
      seq(0x401000, [
        ["mov", "ecx, 1"],
        ["push", "ecx"],
        ["call", "0x403b24"],
        ["mov", "dword ptr [esi], ecx"],
        ["ret"],
      ]),
    );

    expect(code).toMatch(/clobbered_ecx_\d+/);
    expect(code).not.toMatch(REG64_ONLY);
  });

  it("uses the 32-bit alias in 64-bit code when that is all the function wrote", () => {
    // t64!sub_140001564: R14's only definition is `xor r14d, r14d`, and a
    // 32-bit write zero-extends, so R14 *is* R14D here. Saying `r13 = r14d`
    // rather than `r13 = r14` is the narrower and more faithful claim.
    const code = run(
      seq(0x401000, [
        ["xor", "r14d, r14d"], // 401000
        ["test", "rax, rax"], // 401004
        ["je", "0x401014"], // 401008
        ["mov", "r13, r14"], // 40100c
        ["jmp", "0x401018"], // 401010
        ["mov", "r13, rbx"], // 401014
        ["mov", "rax, r13"], // 401018
        ["ret"], // 40101c
      ]),
      true,
    );

    expect(code).toContain("r14d = 0;");
    // Before: `r13 = r14;`, naming storage the function never writes.
    expect(code).toContain("r13 = r14d;");
    expect(code).not.toContain("r13 = r14;");
  });
});

/**
 * Constant folding at the width the operands say they are.
 *
 * The folder evaluated every constant binary op with plain JavaScript
 * operators, and `&`, `|`, `^`, `<<`, `>>`, `>>>`, `|0` and `>>> 0` all coerce
 * to *int32* first. So every bit above 31 was dropped and a wrong constant was
 * emitted with nothing to signal it — `0x100000000 >>> 4` folded to 0 and
 * `1 << 0x20` folded to 1 (peek-a-bin-8fv).
 *
 * Each case below is chosen so the 64-bit answer and the int32 answer differ:
 * a case they agree on is not evidence.
 */
describe("decompileFunction — a 64-bit constant folds at 64 bits", () => {
  it("keeps the bits a logical shift right moves down from above bit 31", () => {
    // Folded to 0 before: `0x100000000 >>> 4` is 0 in int32.
    const code = run(
      seq(0x401000, [["mov", "rax, 0x100000000"], ["shr", "rax, 4"], ["ret"]]),
      true,
    );

    expect(code).toContain("return 0x10000000;");
  });

  it("does not wrap a shift count past 31 back round", () => {
    // Folded to 1 before: JavaScript masks a shift count to 5 bits, so
    // `1 << 0x20` is `1 << 0`.
    const code = run(seq(0x401000, [["mov", "rax, 1"], ["shl", "rax, 0x20"], ["ret"]]), true);

    expect(code).toContain("return 0x100000000;");
  });

  it("keeps the high half of a mask", () => {
    // Folded to 0 before: both operands truncate to 0 in int32.
    const code = run(
      seq(0x401000, [["mov", "rax, 0x100000000"], ["and", "rax, 0x1ffffffff"], ["ret"]]),
      true,
    );

    expect(code).toContain("return 0x100000000;");
  });

  it("keeps the high half of a bitwise or", () => {
    // Folded to 0xFF before.
    const code = run(
      seq(0x401000, [["mov", "rax, 0x100000000"], ["or", "rax, 0xff"], ["ret"]]),
      true,
    );

    expect(code).toContain("return 0x1000000FF;");
  });

  it("keeps the bits an arithmetic shift right moves down", () => {
    // Folded to 0 before.
    const code = run(
      seq(0x401000, [["mov", "rax, 0x800000000"], ["sar", "rax, 4"], ["ret"]]),
      true,
    );

    expect(code).toContain("return 0x80000000;");
  });

  it("leaves the expression alone rather than fold to a value it cannot hold", () => {
    // `1 << 0x3f` is 2^63, past the exactly-representable range of the
    // `number` an IRConst holds. Before, int32 truncation gave -0x80000000;
    // an unfolded shift is still true.
    const code = run(seq(0x401000, [["mov", "rax, 1"], ["shl", "rax, 0x3f"], ["ret"]]), true);

    expect(code).not.toContain("-0x80000000");
    expect(code).toContain("1 << 0x3F");
  });

  it("still folds a 32-bit shift at 32 bits", () => {
    // `shr eax, 4` on 0x80000000 is 0x08000000 at either width; this pins that
    // the 32-bit path was not disturbed.
    const code = run(seq(0x401000, [["mov", "eax, 0x80000000"], ["shr", "eax, 4"], ["ret"]]));

    expect(code).toContain("return 0x8000000;");
  });

  it("still lets a 32-bit shift drop the bits that leave the register", () => {
    // `shl eax, 2` on 0x40000000 is 0 in a 32-bit register, and stays 0.
    const code = run(seq(0x401000, [["mov", "eax, 0x40000000"], ["shl", "eax, 2"], ["ret"]]));

    expect(code).toContain("return 0;");
  });
});

/**
 * A 64-bit immediate is read at 64 bits.
 *
 * Capstone prints an immediate unsigned, so `or rdi, -1` arrives as
 * `0xffffffffffffffff`, and `parseInt` rounds that to 2^64 — a value no later
 * stage can do anything true with. The folder then evaluated `0 | 2^64` and
 * emitted `rdi = 0`, which is the opposite of what the instruction does.
 */
describe("decompileFunction — a 64-bit immediate keeps its value", () => {
  it("reads an all-ones immediate as the negative one it is", () => {
    // Emitted `return 0;` before.
    const code = run(
      seq(0x401000, [["xor", "eax, eax"], ["or", "rax, 0xffffffffffffffff"], ["ret"]]),
      true,
    );

    expect(code).toContain("return -1;");
  });

  it("does not paste an unrepresentable literal into the output", () => {
    const code = run(seq(0x401000, [["mov", "rax, 0xfffffffffffffffe"], ["ret"]]), true);

    expect(code).not.toContain("0x10000000000000000");
    expect(code).toContain("return -2;");
  });

  it("leaves a 32-bit all-ones immediate reading as -1", () => {
    // `or eax, 0xffffffff` is a 32-bit operation; -1 is its value and the
    // spelling this file already had. Pins that the 64-bit path does not
    // capture it and print 0xFFFFFFFF instead.
    const code = run(
      seq(0x401000, [["xor", "eax, eax"], ["or", "eax, 0xffffffff"], ["ret"]]),
      true,
    );

    expect(code).toContain("return -1;");
  });
});

/**
 * Dropping SSA version numbers is only sound while one version of a register is
 * live at a time, and `ssaopt` deliberately breaks that — copy propagation
 * forwards a source across a later write to it, GVN forwards a value to a later
 * use. Both are fine in SSA and both become wrong when the versions come off.
 *
 * `splitStaleReads` used to see only inside one block, so a value redefined in
 * another block was left to bind to whatever the register held by then
 * (peek-a-bin-bld). It now asks which version actually reaches the read, and
 * takes the copy at that version's own definition — the one point where the
 * register is known to hold it — and only where that definition dominates the
 * read.
 */
describe("decompileFunction — a value read after another block redefined its register", () => {
  it("stores the first call's result, not the second's", () => {
    // `mov rbx, rax` makes RBX a copy of the first result; copy propagation
    // forwards it to the store, which is in a later block — by which point the
    // second call has rewritten RAX. Before the fix the store read `rax` and so
    // claimed the *second* result was the address written through.
    const code = run(
      seq(0x401000, [
        ["call", "0x403000"], // 0x401000
        ["mov", "rbx, rax"], // 0x401004
        ["call", "0x403010"], // 0x401008
        ["test", "rax, rax"], // 0x40100c
        ["je", "0x40101c"], // 0x401010
        ["mov", "qword ptr [rbx], 0"], // 0x401014
        ["jmp", "0x40101c"], // 0x401018
        ["ret"], // 0x40101c
      ]),
      true,
    );

    expect(code).toContain("sub_403000()");
    expect(code).toContain("sub_403010()");
    const store = code.split("\n").find((l) => l.includes("= 0;") && l.includes("*("));
    expect(store).toBeDefined();
    // Before the fix: `*(int64_t*)(rax) = 0;`
    expect(store).not.toMatch(/\(rax\)/);
    expect(store).toMatch(/rax_\d+/);
    // The copy is taken before the call that destroys the value, not after.
    const lines = code.split("\n");
    const copyAt = lines.findIndex((l) => /rax_\d+ = rax;/.test(l));
    const secondCallAt = lines.findIndex((l) => l.includes("sub_403010"));
    expect(copyAt).toBeGreaterThanOrEqual(0);
    expect(copyAt).toBeLessThan(secondCallAt);
  });

  it("names the split value the way the function spells the register", () => {
    // The same shape in 32-bit code. The split name follows the reads, so a
    // function whose disassembly only ever says `eax` does not get an `rax_1`
    // naming a register it never mentions.
    const code = run(
      seq(0x401000, [
        ["call", "0x403000"],
        ["mov", "esi, eax"],
        ["call", "0x403010"],
        ["test", "eax, eax"],
        ["je", "0x40101c"],
        ["mov", "dword ptr [esi], 0"],
        ["jmp", "0x40101c"],
        ["ret"],
      ]),
    );

    expect(code).toMatch(/eax_\d+ = eax;/);
    expect(code).not.toMatch(/\brax_\d+\b/);
  });

  it("keeps the register's own definition, which a branch condition still reads", () => {
    // The copy is written as `esi_1 = arg; esi = esi_1;`, not `esi = arg;
    // esi_1 = esi;`. Branch conditions are built by `structure.ts` from
    // `RegState`, so they are not in the statement list `foldBlock` counts uses
    // over: with the reads renamed, appending the copy made the definition look
    // single-use, it folded into the copy, and the guard was left reading a
    // variable nothing assigns.
    const code = run(
      seq(0x401000, [
        ["mov", "esi, dword ptr [ebp + 8]"], // 0x401000
        ["test", "esi, esi"], // 0x401004
        ["je", "0x401018"], // 0x401008
        ["call", "0x403010"], // 0x40100c
        ["mov", "esi, eax"], // 0x401010 — redefines esi
        ["jmp", "0x401018"], // 0x401014
        ["mov", "dword ptr [edi], esi"], // 0x401018 — the join
        ["ret"], // 0x40101c
      ]),
    );

    // Whatever the guard reads, the body has to assign it.
    const guard = code.split("\n").find((l) => l.includes("if ("));
    expect(guard).toBeDefined();
    const named = /\b(e?[a-z]{2}\d*)\b/.exec(guard!.replace(/if \(|\)/g, ""));
    expect(named).not.toBeNull();
    expect(code).toMatch(new RegExp(`^\\s*${named![1]} =`, "m"));
  });
});

/**
 * SSA version 0 is the register's *entry* value, and it is the one version no
 * statement in the function defines — `newVersion` in `ssa.ts` starts at 1. So
 * the repair `splitStaleReads` makes for every other version, a copy taken at
 * the defining statement, has no site to be taken at.
 *
 * The old rule was a copy at the top of the *reading* block, and only when an
 * earlier statement in that same block was the overwriter. Both halves of that
 * are wrong when a block that STRICTLY DOMINATES the read has already written
 * the register: the read gets no repair at all and binds to a name holding
 * something else, or — worse — it gets one, taken past the damage, so the copy
 * preserves the wrong value under a name that looks recovered (peek-a-bin-dqpk;
 * 78 of the first kind and 19 spoiled copies of the second on t64 alone).
 *
 * The site that is always right for version 0 is the function's entry, before
 * anything has run. The objection on record — a loop reading RAX_0 while the
 * body adds to RAX would be frozen at the entry value — needs a block the
 * unwinder enters, with no predecessor and so no `idom` entry, and `dominates`
 * from the entry block declines those.
 */
describe("decompileFunction — a register's entry value outlives a write to the register", () => {
  // ECX is the entry value (`this`, in MSVC's thiscall), parked in EDX and read
  // back in a block the definition of ECX dominates. Both `return`s said `ecx`
  // before the fix, and one of them meant the global.
  const parked = () =>
    seq(0x401000, [
      ["mov", "edx, ecx"], // 0x401000 — park the entry ECX
      ["mov", "ecx, dword ptr [0x412920]"], // 0x401004 — and overwrite it
      ["test", "edx, edx"], // 0x401008
      ["je", "0x401018"], // 0x40100c
      ["mov", "eax, edx"], // 0x401010 — the entry value…
      ["ret"], // 0x401014
      ["mov", "eax, ecx"], // 0x401018 — …against the global
      ["ret"], // 0x40101c
    ]);

  it("does not name the register for a value a dominating block overwrote", () => {
    const code = run(parked());
    const returns = code.split("\n").filter((l) => l.trim().startsWith("return"));
    expect(returns).toHaveLength(2);
    // One arm returns the global the machine loaded into ECX; the other returns
    // the value ECX held on entry. Two `return ecx;` lines cannot be both.
    expect(new Set(returns.map((l) => l.trim())).size).toBe(2);
    expect(code).toMatch(/\becx_0\b/);
    expect(code).toContain("ecx = *(int32_t*)(0x412920);");
  });

  it("takes the entry value's copy at the function's entry", () => {
    const lines = run(parked())
      .split("\n")
      .map((l) => l.trim());
    const copyAt = lines.indexOf("ecx_0 = ecx;");
    const clobberAt = lines.indexOf("ecx = *(int32_t*)(0x412920);");
    expect(copyAt).toBeGreaterThanOrEqual(0);
    expect(clobberAt).toBeGreaterThanOrEqual(0);
    expect(copyAt).toBeLessThan(clobberAt);
    // One copy, not one per reading block: the entry dominates every read.
    expect(lines.filter((l) => l === "ecx_0 = ecx;")).toHaveLength(1);
  });

  it("does not take the copy after a dominating block has already spoiled it", () => {
    // The nastier form. The reading block redefines ECX itself, which is what
    // used to buy it a copy at that block's top — but the entry block had
    // already overwritten ECX, so the copy captured the global and `ecx_0`
    // named it. Nothing on the page looks wrong.
    const lines = run(
      seq(0x401000, [
        ["mov", "edx, ecx"], // 0x401000
        ["mov", "ecx, dword ptr [0x412920]"], // 0x401004 — dominating write
        ["test", "edx, edx"], // 0x401008
        ["je", "0x401020"], // 0x40100c
        ["mov", "ecx, dword ptr [0x412930]"], // 0x401010 — in-block redefinition
        ["mov", "eax, edx"], // 0x401014 — reads the entry ECX
        ["add", "eax, ecx"], // 0x401018
        ["ret"], // 0x40101c
        ["mov", "eax, ecx"], // 0x401020
        ["ret"], // 0x401024
      ]),
    )
      .split("\n")
      .map((l) => l.trim());

    const copyAt = lines.indexOf("ecx_0 = ecx;");
    const clobberAt = lines.indexOf("ecx = *(int32_t*)(0x412920);");
    expect(copyAt).toBeGreaterThanOrEqual(0);
    expect(clobberAt).toBeGreaterThanOrEqual(0);
    expect(copyAt).toBeLessThan(clobberAt);
  });
});

/**
 * A call's result.
 *
 * `liftBlock` gives every `call_stmt` a `resultDest` of RAX/EAX, and SSA binds
 * a later read of the accumulator to it — but the emitter printed the call and
 * dropped the assignment, so the value the call produced was invisible in the
 * output. Across t32/t64/w64 that left ~1500 register reads naming something
 * the emitted function never assigns, `return rax` after a call being the
 * common shape (peek-a-bin-oro).
 *
 * Which calls get one is a liveness question, and these pin both answers: the
 * assignment appears when the result is read, and does not when the next thing
 * to touch the register is another definition of it.
 */
describe("decompileFunction — a call's result", () => {
  it("assigns the register the call returned in, when the body reads it", () => {
    const code = run(seq(0x401000, [["mov", "ecx, 1"], ["call", "0x408000"], ["ret"]]));

    // Before: `sub_408000(); return eax;` — C in which nothing assigns eax.
    expect(code).toMatch(/eax = sub_408000\(\);/);
    expect(code).toContain("return eax;");
  });

  it("leaves a call whose result the next call overwrites as a bare statement", () => {
    const code = run(seq(0x401000, [["call", "0x408000"], ["call", "0x408004"], ["ret"]]));

    // Only the second call's result reaches the `ret`; the first one's is dead,
    // and an assignment nobody reads is noise in output written for people.
    expect(code).toMatch(/^\s*sub_408000\(\);$/m);
    expect(code).not.toMatch(/= sub_408000\(/);
    expect(code).toMatch(/eax = sub_408004\(\);/);
  });

  it("says where the value a guard tests came from, and spells both the same way", () => {
    const code = run(
      seq(0x401000, [
        ["call", "0x401100"], // 0x401000
        ["test", "al, al"], // 0x401004
        ["je", "0x401014"], // 0x401008
        ["mov", "eax, 1"], // 0x40100c
        ["ret"], // 0x401010
        ["ret"], // 0x401014
      ]),
      true,
    );

    // `registerText` respells the read of AL as a narrowing of RAX because the
    // function assigns RAX. That was already true of the call's `resultDest`
    // before the assignment was ever printed, so the emitted guard tested
    // `(uint8_t)rax` in a function whose body assigned no `rax` at all.
    //
    // The `je` targets the final `ret` on purpose. It used to target one past
    // it, over a `mov eax, 2` nothing reached; that block is now emitted like
    // any other unreachable one (peek-a-bin-d3z), and its `eax = 2` is a second
    // spelling of the same storage, which is the one thing this test cannot
    // have in the function.
    expect(code).toContain("(uint8_t)rax");
    expect(code).toMatch(/rax = sub_401100\(\);/);
  });

  /**
   * The same rule at 32 bits, which is where nearly all of it lives
   * (`peek-a-bin-k8i`).
   *
   * `registerText` used to respell only 8- and 16-bit reads, on the reasoning
   * that `eax` is the whole register in 32-bit code and a sub-register of RAX in
   * 64-bit code and emit is not told which. But the alias search answers that
   * without being told: a read is respelled only if the function assigns a
   * *strictly wider* alias, and on a PE32 image nothing ever assigns a bare
   * 64-bit name — 0 functions across both 32-bit corpus binaries. So the
   * exclusion did no work the search was not already doing, and it cost the
   * largest population of this defect: 214 reads over 88 distinct (function,
   * name) pairs on t64 and 211 over 85 on w64 at `177ada8`, almost all of them
   * exactly the shape below — a 32-bit read of an accumulator a *call* assigned
   * as RAX, so the emitted guard tested a name the function never assigns.
   */
  it("respells a 32-bit read of an accumulator only the call assigned", () => {
    const code = run(
      seq(0x401000, [
        ["call", "0x401100"],
        ["test", "eax, eax"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toMatch(/rax = sub_401100\(\);/);
    // The guard reads the call's result, narrowed — not a bare `eax` that
    // nothing in the emitted function ever assigns.
    expect(code).toContain("(uint32_t)rax");
    expect(code).not.toMatch(/\beax\b\s*[!=]=/);
  });

  it("leaves a 32-bit image's own accumulator alone, having nothing wider", () => {
    // The other half of the rule, and the reason widening to 32 bits is safe
    // rather than merely measured: on a PE32 image the call's `resultDest` is
    // EAX, so the widest assigned alias of the read IS the read, the alias
    // search finds nothing wider, and the name stands. A cast here would be
    // inventing a register the image has no encoding for — `peek-a-bin-1k4`'s
    // defect arriving from the other direction.
    const code = run(
      seq(0x401000, [
        ["call", "0x401100"],
        ["test", "eax, eax"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["ret"],
      ]),
    );

    expect(code).toMatch(/eax = sub_401100\(\);/);
    expect(code).not.toContain("rax");
    expect(code).not.toContain("(uint32_t)");
  });

  /**
   * The call clobber (`clobberedByCall` in `ssa.ts`) and this are two halves of
   * one account of what a call does, and they cover disjoint registers: the
   * result is assigned because the call produced it, and an argument register
   * the call consumed becomes a variable nothing assigns because its value is
   * gone. Both have to be visible in the same function for either to be read
   * correctly.
   */
  it("assigns the result while an argument register the call destroyed stays unassigned", () => {
    const code = run(
      seq(0x401000, [["mov", "rcx, 1"], ["call", "0x401100"], ["add", "rax, rcx"], ["ret"]]),
      true,
    );

    expect(code).toMatch(/rax = sub_401100\(1\);/);
    const clobbered = /\bclobbered_rcx_\d+\b/.exec(code);
    expect(clobbered).not.toBeNull();
    // The clobbered name is read and never assigned — that is what it is for.
    expect(code).not.toMatch(new RegExp(`${clobbered![0]}\\s*=[^=]`));
  });

  /**
   * A pin on the rule rather than a regression test: the emitted text for this
   * one is the same before and after, because a bare call is what both a dead
   * result and no analysis at all produce. It is here because the obvious
   * cheaper rule — "the register is read somewhere in the function" — passes
   * every other test in this block and fails this one.
   */
  it("does not assign a result the very next statement overwrites", () => {
    const code = run(seq(0x401000, [["call", "0x408000"], ["mov", "eax, 5"], ["ret"]]));

    expect(code).toMatch(/^\s*sub_408000\(\);$/m);
    expect(code).not.toMatch(/= sub_408000\(/);
  });

  /**
   * A zeroing idiom must not come out as a copy of a register that has since
   * been written (peek-a-bin-21ey).
   *
   * GVN forwards the `xor edi, edi` to the earlier `xor ebx, ebx` — same value,
   * and its definition dominates, so it is a sound rewrite *in SSA*. What makes
   * it wrong is that `destroySSA` ends SSA by stripping versions rather than by
   * splitting live ranges, and EBX has been reloaded in between: `ebx_1` and
   * `ebx_2` collapse to one name, so the lowered phi operand read the reload.
   * `splitStaleReads` exists to repair exactly that and did not look at phi
   * operands, which is the one place GVN had put it.
   *
   * The shape is load-bearing in three ways and the bug hides if any is
   * dropped: EBX must be *visibly* reassigned in the output, so its reload
   * takes two uses and cannot be inlined away; the zeroing must sit in a
   * conditional arm, so the value reaches its use through a phi rather than a
   * statement; and the arm must be reached by a `jcc` whose fallthrough is the
   * zeroing, so the join really has two incoming versions. The pre-fix output
   * was `edi = ebx` under `ebx = var_18`, which is valid C reading the wrong
   * value.
   */
  it("keeps a zeroed register zero when the value-numbering source is overwritten", () => {
    const code = run(
      seq(0x401000, [
        ["xor", "ebx, ebx"],
        ["mov", "dword ptr [ebp - 0x10], ebx"],
        ["mov", "ebx, dword ptr [ebp - 0x18]"],
        ["mov", "dword ptr [ebp - 0x1c], ebx"],
        ["mov", "dword ptr [ebp - 0x24], ebx"],
        ["test", "dword ptr [ebp - 0x14], 0x9000"],
        ["mov", "edi, edx"],
        ["jne", "0x401024"],
        ["xor", "edi, edi"],
        ["mov", "dword ptr [ebp - 0x20], edi"],
        ["ret"],
      ]),
    );

    // EBX really is reassigned in the emitted body — without this the test
    // passes for the wrong reason, because `edi = ebx` would then read zero.
    expect(code).toMatch(/^\s*ebx = var_18;$/m);
    // The guarded arm must not read that reassigned register.
    expect(code).not.toMatch(/^\s*edi = ebx;$/m);
    // Whatever it does read has to be the zero: either the constant itself or
    // the split live range holding it.
    const arm = /\(var_14 & 0x9000\) == 0\) \{\s*\n\s*edi = ([^;]+);/.exec(code);
    expect(arm).not.toBeNull();
    const src = arm![1];
    expect(src === "0" || new RegExp(`^\\s*${src} = 0;$`, "m").test(code)).toBe(true);
  });
});

/**
 * Windows x64 argument setup is routinely sub-width, and it was invisible
 * (peek-a-bin-qb2x).
 *
 * `collectArgs64` reads arity out of `RegState` — how many *leading* fastcall
 * registers this block wrote — and `RegState` keys its defs by the literal
 * operand text, so `mov ecx, 1` lands under `"ecx"`. Probing the 64-bit name
 * missed it and broke out of the loop at that position, and since the argument
 * never reached the IR, nothing read the `ecx = 1` and DCE deleted it: both the
 * argument and the statement that set it were gone from the output.
 *
 * `mov ecx, 1 / call ExitProcess` is the shape at its smallest, and it occurred
 * five times in each of the two real x64 binaries.
 *
 * What must *not* change is which expression is passed. `collectArgs64` pushes
 * the plain `irReg(reg, 8)` on purpose — substituting `RegState`'s recorded
 * expression re-expanded whatever computed it at the call site and rebound its
 * leaves once SSA renaming ran (peek-a-bin-urs). Widening the probe changes
 * only *whether* an argument is emitted.
 */
describe("decompileFunction — a sub-width write is still argument setup", () => {
  /** As `run`, but 64-bit and with an import table, so the callee has a name. */
  function run64(
    instructions: Instruction[],
    iat: Map<number, { lib: string; func: string }> = new Map(),
  ): string {
    const start = instructions[0].address;
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_140001000",
      address: start,
      size: last.address + last.size - start,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      null,
      null,
      true,
      new Map(),
      iat,
      new Map(),
      new Map(),
    ).code;
  }

  it("passes an exit code set with a 32-bit mov", () => {
    const code = run64(
      seq(0x140001000, [["mov", "ecx, 1"], ["call", "qword ptr [0x140002000]"], ["ret"]]),
      new Map([[0x140002000, { lib: "kernel32.dll", func: "ExitProcess" }]]),
    );

    // Before the fix this was `ExitProcess()` — no argument, and no `ecx = 1`
    // anywhere either, because the write had no reader left to keep it alive.
    expect(code).toMatch(/ExitProcess\(1\)/);
    expect(code).not.toMatch(/ExitProcess\(\)/);
  });

  it("counts a sub-width write at every fastcall position", () => {
    // RCX full width, RDX 32-bit, R8 32-bit (the xor idiom), R9 8-bit. The
    // pre-fix output stopped at RCX and emitted `sub_140003E90(rbx)`.
    const code = run64(
      seq(0x140001000, [
        ["mov", "rcx, rbx"],
        ["mov", "edx, 0x400"],
        ["xor", "r8d, r8d"],
        ["mov", "r9b, 1"],
        ["call", "0x140003e90"],
        ["ret"],
      ]),
    );

    expect(code).toMatch(/sub_140003E90\(rbx, 0x400, 0, 1\)/);
  });

  it("still stops at a fastcall register the block never wrote", () => {
    // Arity is *leading* registers. Nothing sets RCX, so there is no evidence
    // of a first argument and a second cannot be claimed over the gap — the
    // wider probe must not turn this into a one- or two-argument call.
    const code = run64(seq(0x140001000, [["mov", "edx, 7"], ["call", "0x140003e90"], ["ret"]]));

    expect(code).toMatch(/sub_140003E90\(\)/);
  });

  it("passes the register, not the expression that computed it", () => {
    // The peek-a-bin-urs guard, at the arity boundary this change moves. ECX is
    // set from a call, so substituting `RegState`'s record would emit
    // `sub_140003E90(GetLastError())` — the same machine call twice. What is
    // lifted is the register; only SSA-aware propagation may rewrite it, and
    // here it cannot, because the value came from a call rather than a constant.
    const code = run64(
      seq(0x140001000, [
        ["call", "qword ptr [0x140002000]"],
        ["mov", "ecx, eax"],
        ["call", "0x140003e90"],
        ["ret"],
      ]),
      new Map([[0x140002000, { lib: "kernel32.dll", func: "GetLastError" }]]),
    );

    // A narrowing cast is allowed here and is the expected spelling: the value
    // read is ECX, the widest alias the function assigns is RAX (the call's
    // result), so `registerText` ties the read to it as `(uint32_t)rax` rather
    // than printing an `ecx` nothing assigns (peek-a-bin-k8i). What this case
    // guards is unaffected by that — the argument is still the *register*, not
    // the call expression. Before k8i widened it to 32-bit names the assertion
    // read `/sub_140003E90\(\w+\)/`, which pinned the spelling rather than the
    // property and failed on the cast.
    expect(code).toMatch(/sub_140003E90\((\((?:u?int\d+_t)\))?\w+\)/);
    expect(code).not.toMatch(/sub_140003E90\(GetLastError/);
    // And exactly one call to it, not one per read of the register.
    expect(code.match(/GetLastError\(/g)?.length).toBe(1);
  });

  it("is a 64-bit rule only — a 32-bit image still reads its pushes", () => {
    // `collectArgs32` walks the instruction stream, not `RegState`, so a
    // register write near a 32-bit call is not argument evidence at all.
    const code = run(seq(0x401000, [["mov", "ecx, 1"], ["call", "0x408000"], ["ret"]]));

    expect(code).toMatch(/sub_408000\(\)/);
  });
});

/**
 * A `push` of a callee-saved register the function has not yet written is a
 * REGISTER SAVE, not an argument.
 *
 * `collectArgs32` walks backwards from a call over consecutive pushes, and used
 * to walk straight into the function's own prologue — emitting
 * `GetModuleHandleW("KERNEL32.DLL", edi)` for an API declaring one parameter
 * and `GetCommandLineW(edi, esi, ebx)` for one declaring none. Every shape
 * below is a site in the real corpus; `gcc -fsyntax-only` cannot see any of it,
 * because an implicit declaration is accepted at any arity (peek-a-bin-6lmh).
 */
describe("decompileFunction — a prologue register save is not an argument", () => {
  /** The arguments of the one call in the emitted body, as written text. */
  function argsOf(code: string, callee: string): string[] {
    const open = code.indexOf(`${callee}(`);
    if (open < 0) throw new Error(`no call to ${callee} in:\n${code}`);
    let depth = 0;
    let buf = "";
    const args: string[] = [];
    for (let i = open + callee.length; i < code.length; i++) {
      const ch = code[i];
      if (ch === "(") {
        depth++;
        if (depth === 1) continue;
      }
      if (ch === ")") {
        depth--;
        if (depth === 0) break;
      }
      if (ch === "," && depth === 1) {
        args.push(buf.trim());
        buf = "";
        continue;
      }
      buf += ch;
    }
    if (buf.trim() !== "") args.push(buf.trim());
    return args;
  }

  it("drops a save pushed before the register is ever written", () => {
    // t32.exe 0x405F2F: mov edi, edi (hot-patch pad, i.e. the entry) /
    // push edi (save) / push "KERNEL32.DLL" (the only argument) / call.
    const code = run(
      seq(0x401000, [
        ["mov", "edi, edi"],
        ["push", "edi"],
        ["push", "0x40F54C"],
        ["call", "0x402000"],
        ["ret"],
      ]),
    );

    expect(argsOf(code, "sub_402000")).toHaveLength(1);
  });

  it("keeps a push of the same register after the function has written it", () => {
    // t32.exe 0x402C35, the site that refutes "a push of ESI is a save": the
    // same register in the same block is a save at 0x402C37 and an argument at
    // 0x402C3F, and only the intervening `mov esi, 0xC0000417` separates them.
    const code = run(
      seq(0x401000, [
        ["mov", "edi, edi"],
        ["push", "esi"],
        ["push", "1"],
        ["mov", "esi, 0xc0000417"],
        ["push", "esi"],
        ["push", "2"],
        ["call", "0x402000"],
        ["ret"],
      ]),
    );

    // Two, and the second of them is the ESI the `mov` wrote — folded to its
    // constant, which is the proof it was kept rather than read as a save.
    //
    // Not three: the walk collects *consecutive* pushes and the `mov` ends the
    // run, so `push 1` is out of reach. That is pre-existing behaviour and an
    // admitted under-count — the machine's own `add esp, 0xC` at 0x402C47 says
    // three — and it is unrelated to the save rule, which is what this pins.
    const args = argsOf(code, "sub_402000");
    expect(args).toHaveLength(2);
    expect(args).toContain("0xC0000417");
  });

  it("keeps an argument whose register was written in an EARLIER block", () => {
    // w32.exe 0x40104D: `push esi / call FreeLibrary` at a block leader, with
    // ESI written at 0x40100F in an earlier block. A block-local scope turns
    // this genuine argument into an admitted under-count.
    const code = run(
      seq(0x401000, [
        ["mov", "esi, dword ptr [0x404000]"],
        ["test", "esi, esi"],
        ["je", "0x401014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["push", "esi"],
        ["call", "0x402000"],
        ["ret"],
      ]),
    );

    expect(argsOf(code, "sub_402000")).toHaveLength(1);
  });

  it("stops the walk at the save rather than skipping over it", () => {
    // t32.exe 0x4086CC: a SUNK save — `push edi` leads a mid-function block
    // reached by `jne`, ahead of the four genuine pushes. Reaching it ends the
    // argument list; the four below it are still collected.
    const code = run(
      seq(0x401000, [
        ["mov", "edi, edi"],
        ["push", "edi"],
        ["push", "dword ptr [0x404000]"],
        ["push", "0"],
        ["push", "dword ptr [0x404004]"],
        ["push", "eax"],
        ["call", "0x402000"],
        ["mov", "edi, eax"],
        ["ret"],
      ]),
    );

    expect(argsOf(code, "sub_402000")).toHaveLength(4);
  });

  it("is restricted to the callee-saved registers", () => {
    // EAX and ECX carry results and __fastcall arguments, so "this is still the
    // entry value" says nothing about whether a push of one is an argument.
    const code = run(seq(0x401000, [["push", "ecx"], ["call", "0x402000"], ["ret"]]));

    expect(argsOf(code, "sub_402000")).toHaveLength(1);
  });
});

/**
 * The `if (…)` / `while (…)` conditions in emitted code, as the text between
 * each guard's outermost parentheses.
 */
function guardConditions(code: string): string[] {
  const out: string[] = [];
  for (const line of code.split("\n")) {
    const t = line.trim();
    if (!/^(\}\s*)?(else\s+)?(if|while)\s*\(/.test(t)) continue;
    const open = t.indexOf("(");
    const close = t.lastIndexOf(")");
    if (open >= 0 && close > open) out.push(t.slice(open + 1, close));
  }
  return out;
}

/** Registers the emitted body assigns — `eax = …`, `eax += …`, `eax++`. */
function assignedRegisters(code: string): Set<string> {
  const out = new Set<string>();
  for (const line of code.split("\n")) {
    const m = line.trim().match(/^(\w+)\s*(?:[-+*/|&^%]|<<|>>)?=(?!=)|^(\w+)\+\+/);
    const name = m?.[1] ?? m?.[2];
    if (name && isKnownRegister(name)) out.add(name.toLowerCase());
  }
  return out;
}

/**
 * Registers a guard reads that nothing in the emitted body ever assigns.
 *
 * `entryValues` names the registers holding an incoming value, which correctly
 * appear with no assignment. Anything else in this list is a guard reading a
 * value the emitted C never put there — the peek-a-bin-f50k defect. The check
 * is deliberately spelling-agnostic: re-materialising the dropped assignment
 * and re-spelling the guard to name the surviving register are both correct
 * repairs, and both empty this list.
 */
function staleGuardReads(code: string, entryValues: string[]): string[] {
  const assigned = assignedRegisters(code);
  const entry = new Set(entryValues.map((r) => r.toLowerCase()));
  const bad = new Set<string>();
  for (const cond of guardConditions(code)) {
    for (const word of cond.match(/[a-z][a-z0-9]*/gi) ?? []) {
      const r = word.toLowerCase();
      if (!isKnownRegister(r) || assigned.has(r) || entry.has(r)) continue;
      bad.add(r);
    }
  }
  return [...bad].sort();
}

/**
 * peek-a-bin-f50k — a branch condition names a register the emitted body never
 * assigns.
 *
 * `structure.ts`'s `extractCondition` re-parses the `cmp`/`test` operands off
 * the raw `Instruction` through a fresh `RegState` that is fed *only* `cmp` and
 * `test`. The condition is therefore not in `liftedBlocks` at all: it carries
 * no SSA version, no reaching definition, and no use that any dataflow pass can
 * count. So the register that computed the compared value is free to be
 * propagated away, folded into a use, or deleted — while the guard goes on
 * naming it. That is peek-a-bin-c33, and these three are its symptoms.
 *
 * Three *distinct* stages produce it, which is why there are three fixtures and
 * not one. Confirmed by stepping the passes on each fixture (HEAD 069b016):
 *
 *   1. `copyPropagation` (ssaopt.ts) deletes **every** copy statement
 *      unconditionally — `stmts.filter((s) => !isCopyStmt(s))` — after
 *      rewriting its IR readers. The guard is not an IR reader.
 *   2. `constantPropagation` + `deadCodeElimination` (ssaopt.ts). Nothing is
 *      wrongly dropped here: every IR reader correctly receives the constant
 *      and the now-dead def is correctly removed. The guard simply was never
 *      part of the conversation, so it keeps the register and loses the value.
 *   3. `foldBlock` (fold.ts) inlines a single-use def into its one remaining IR
 *      use. The guard's read does not count towards that use total, and by then
 *      `ssaOptimize`'s end-of-fixpoint `eflags` strip has removed the only IR
 *      statement that mentioned the register.
 *
 * `deadCodeElimination` does hold a block's `eflags` definition live for
 * exactly this reason (peek-a-bin-ua8), which is why a def that is neither a
 * copy nor a constant nor single-use survives — see the two controls below.
 * That protection preserves the *statement* but not the register names inside
 * it, and propagation is free to rewrite those.
 *
 * Reproduced on t32.exe!sub_4045B1 at HEAD 069b016 (719 instructions, 702
 * emitted lines). Case 1 is 0x404EC1 `mov eax, esi`, whose guard emits
 * `} else if (*(uint8_t*)(eax) != 0x30) {` with `eax = esi` nowhere in the
 * function. Case 2 is 0x404E34 `mov eax, 0x200`, whose guard emits
 * `if (var_40C > eax)` where the machine compares against 0x200 — the constant
 * reaches the neighbouring store and is lost from the compare.
 *
 * All three PASS as of peek-a-bin-c33's Stage 3, which made the guard's
 * registers real IR readers: the condition now goes through SSA renaming, copy
 * and constant propagation and `foldBlock`'s use counting like every other
 * expression, so mechanisms 1 and 2 rewrite it in step with the rest of the
 * block and mechanism 3 no longer sees a single-use definition. They were
 * pinned with `it.fails` while the defect stood; the `.fails` came off when it
 * did. Do not put it back — a failure here now means the guard has stopped
 * being an IR reader again.
 */
describe("decompileFunction — a guard names a value the body actually computed", () => {
  // peek-a-bin-f50k case 1. `mov eax, ecx` is a copy, so `copyPropagation`
  // deletes it. Correct output: the guard dereferences the value ECX holds,
  // either by naming `ecx` or by keeping `eax = ecx` above it.
  it("keeps the copy that computed the compared value", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, ecx"],
        ["cmp", "byte ptr [eax], 0x30"],
        ["je", "0x401014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(staleGuardReads(code, ["ecx"])).toEqual([]);
    expect(code).toMatch(/eax = ecx|\(uint8_t\*\)\(ecx\)/);
  });

  // peek-a-bin-f50k case 2. Nothing is wrongly deleted: `constantPropagation`
  // correctly puts 0x200 into the store and `deadCodeElimination` correctly
  // removes the dead def. Correct output: the guard compares against 0x200,
  // exactly as the store does.
  it("compares against the constant, not the register that carried it", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, 0x200"],
        ["cmp", "ecx, eax"],
        ["jle", "0x401014"],
        ["mov", "dword ptr [ebx], eax"],
        ["ret"],
        ["mov", "edx, 7"],
        ["ret"],
      ]),
    );

    expect(guardConditions(code).join(" | ")).toContain("0x200");
    expect(staleGuardReads(code, ["ecx", "ebx"])).toEqual([]);
  });

  // peek-a-bin-f50k, third mechanism. The load is neither a copy nor a
  // constant, so it survives `ssaOptimize` — but the store is its only
  // remaining IR use once the `eflags` def is stripped, so `foldBlock` inlines
  // it. Correct output: the guard and the store name the same machine value.
  it("does not fold away the only definition its guard reads", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, dword ptr [ecx]"],
        ["mov", "dword ptr [ebx], eax"],
        ["cmp", "byte ptr [eax], 0x30"],
        ["jne", "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(staleGuardReads(code, ["ecx", "ebx"])).toEqual([]);
  });

  // Control, and it must keep passing — but the mechanism changed underneath
  // it and the change is the point. It used to survive because
  // `deadCodeElimination` holds a Jcc block's `eflags` definition live
  // (peek-a-bin-ua8), which preserved the statement without the guard ever
  // being a reader. Now the guard IS a reader, so the def has a real use — and
  // `foldBlock` deliberately refuses to inline into a branch, or this would
  // become `if (*(uint8_t*)(*(int32_t*)(ecx)) == 0x30)` with the assignment
  // gone. That refusal is what keeps EAX assigned for any successor block that
  // reads it, and what keeps `structureCFG` able to recognise a loop by the
  // statement its body ends with (peek-a-bin-c33).
  it("keeps a load whose only reader is the guard", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, dword ptr [ecx]"],
        ["cmp", "byte ptr [eax], 0x30"],
        ["je", "0x401014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain("eax = *(int32_t*)(ecx)");
    expect(staleGuardReads(code, ["ecx"])).toEqual([]);
  });

  // The same control one step further out, and the sharper one: `add eax, ecx`
  // WRITES EAX, so inlining it into the guard would delete a machine effect
  // rather than merely relocate an expression.
  it("keeps an arithmetic definition whose only reader is the guard", () => {
    const code = run(
      seq(0x401000, [
        ["add", "eax, ecx"],
        ["cmp", "byte ptr [eax], 0x30"],
        ["je", "0x401014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain("eax += ecx");
    expect(staleGuardReads(code, ["eax", "ecx"])).toEqual([]);
  });
});

/**
 * A GUARD THAT NAMES THE RIGHT OPERATOR OVER THE WRONG OPERANDS.
 *
 * The defect class no standing gate can see, which is why it survived. The
 * emitted comparison matches its jcc's taken sense, so the corpus polarity
 * audit passes it; it is not `__unrecovered_N`, so the recovery baseline does
 * not count it; gcc compiles it. Only the operands are wrong, and only the
 * machine text says so.
 *
 * Two mechanisms, filed and fixed separately because either could outlive the
 * other. Both are pinned here end to end — instructions in, emitted C out —
 * because a stage-level test asserts on the IR the buggy code produced.
 *
 * The correct output in every defect case is `__unrecovered_N`, not a repaired
 * name: refusing to state a test the machine does not make is the whole fix.
 * "Clean is not recovered", and an admission is the honest direction.
 */
describe("decompileFunction — a guard reads the flags the jcc actually reads", () => {
  /** The emitted guards, or ["<unrecovered>"] where the condition was admitted. */
  function guardTexts(code: string): string[] {
    return guardConditions(code).map((c) => (/__unrecovered_\d+/.test(c) ? "<unrecovered>" : c));
  }

  // peek-a-bin-jitf. `sub ecx, edx` writes the flags `jne` reads; the `cmp` two
  // instructions earlier no longer describes them. Base emitted `eax != 5`,
  // where the machine branches on `ecx - edx != 0`.
  it("does not answer a jcc from a cmp a later flag writer superseded", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["sub", "ecx, edx"],
        ["jne", "0x401014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
    expect(code).not.toContain("eax != 5");
  });

  // The shape of the two real corpus occurrences, reduced. MSVC's branchless
  // unsigned size check is `mov eax, 0x7fffffff / cmp eax, [ebp+0x10] / sbb
  // eax, eax / inc eax / jne` (t32.exe 0x4078de, w32.exe 0x4070e3): the `cmp`
  // sets CF, `sbb` turns it into -CF, and **`inc` sets the ZF the `jne`
  // reads**. Base emitted `eax != arg_0x10`, naming a compare three
  // instructions dead over a register that by then holds a one-bit flag.
  //
  // The full sequence does not survive reduction — with no predecessor block
  // the constant folds to 0x80000000 and the branch disappears altogether — so
  // what is pinned here is the load-bearing part, a one-operand flag writer
  // superseding the compare. The idiom itself is pinned by
  // `corpus/staleGuards.ts`, which reports it at both real addresses.
  it("does not answer a jcc from a cmp a one-operand flag writer superseded", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, dword ptr [ebp + 0x10]"],
        ["inc", "eax"],
        ["jne", "0x401014"],
        ["mov", "ecx, 1"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  // peek-a-bin-xe01, then peek-a-bin-xskz. The flags ARE the cmp's, but the
  // block's statements are emitted above the `if`, so `eax = edx;` runs first
  // and a guard naming EAX would read the new value. That was refused outright
  // until the lifter learned to MATERIALISE the compared value at the compare's
  // own program point; the guard now reads the capture, and the assertion is
  // that it names neither the old register (whose value has moved) nor EDX (the
  // value the spoiler put there, which is what the same jcc emits when the
  // refusal is bypassed WITHOUT a capture — measured, and the reason
  // `corpus/staleGuards.ts` cannot judge this by looking for a clobbered
  // register name).
  it("materialises a compared register a later instruction overwrote", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["mov", "eax, edx"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["flg_401000_0 == 5"]);
    expect(code).toContain("flg_401000_0 = eax;");
    expect(code).not.toMatch(/\beax [=!]= 5/);
    expect(code).not.toMatch(/\bedx [=!]= 5/);
  });

  // The capture is taken BEFORE the clobber, which is the whole claim, and the
  // shape above cannot demonstrate it: DCE deletes `mov eax, edx` there, so a
  // guard naming a bare `eax` would be correct by accident. Here the clobbered
  // value is read in two successors, so it escapes the block and stays on the
  // page — and the capture's source must still be the value from BEFORE it.
  it("captures the value from before a clobber that survives to the page", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "eax, esi"],
        ["cmp", "eax, 5"],
        ["mov", "eax, edx"],
        ["je", "0x40101c"],
        ["mov", "dword ptr [ebx], eax"],
        ["ret"],
        ["mov", "dword ptr [ecx], eax"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["flg_401004_0 == 5"]);
    expect(code).toContain("flg_401004_0 = esi;");
    expect(code).not.toMatch(/\bedx [=!]= 5/);
  });

  // The overwrite question is width-blind, because a byte write really does
  // change what the name denotes at any width. `mov al, 1` spoils `eax`, so the
  // capture fires — and bypassing the refusal with no capture emits `if (1)`
  // here, a control-flow claim rather than a test, which is why this shape is
  // worth pinning rather than merely counting.
  it("counts a sub-register write as overwriting the register", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["mov", "al, 1"],
        ["jne", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["flg_401000_0 != 5"]);
    expect(code).toContain("flg_401000_0 = eax;");
  });

  // A compare against memory is spoiled by an intervening STORE, not only by a
  // register write — the guard's deref would be evaluated at the `if`, below it.
  // This is the majority shape in the corpus (77 of 104 at `97249dc`), and the
  // capture is a real load rather than a copy: the value is in memory and no
  // name in the emitted C holds it.
  it("materialises a compared memory operand a later store overwrote", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "dword ptr [ecx], 5"],
        ["mov", "dword ptr [ecx], edx"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["flg_401000_0 == 5"]);
    // The load is above the store, which is the entire point.
    expect(code.indexOf("flg_401000_0 = *(int32_t*)(ecx)")).toBeGreaterThan(-1);
    expect(code.indexOf("flg_401000_0 = *(int32_t*)(ecx)")).toBeLessThan(
      code.indexOf("*(int32_t*)(ecx) = edx"),
    );
  });

  // …and by a write to the register the deref is spelled with. Bypassing the
  // refusal here emits `*(int32_t*)(edx) == 5` — a load through the register the
  // spoiler wrote INTO ecx, which is neither the compare's base nor a member of
  // the clobber set, so no text scan over register names can see it.
  it("materialises a deref whose base register was overwritten", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "dword ptr [ecx], 5"],
        ["mov", "ecx, edx"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["flg_401000_0 == 5"]);
    expect(code).toContain("flg_401000_0 = *(int32_t*)(ecx);");
    expect(code).not.toContain("*(int32_t*)(edx) == 5");
  });

  // A CONSTANT OPERAND IS NOT CAPTURED, and a repeated one is captured once.
  // `test eax, eax` names the same register twice, so one statement holds it and
  // the condition reads it on both sides — two statements saying the same thing
  // would be noise, and an `IRConst` has nothing to preserve.
  it("captures each distinct non-constant operand exactly once", () => {
    const code = run(
      seq(0x401000, [
        ["test", "eax, eax"],
        ["mov", "eax, edx"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    // A trailing space, so `flg_… == 0` in the guard is not counted as an
    // assignment: the point is one capture STATEMENT, read twice.
    expect(code.match(/flg_401000_\d+ = /g)).toEqual(["flg_401000_0 = "]);
    expect(guardTexts(code)).toEqual(["flg_401000_0 == 0"]);
  });

  // EVERY CAPTURE IS DECLARED, AT THE OPERAND'S OWN WIDTH. A capture is a local
  // the emitter invents and writes, so leaving it undeclared made the emitted C
  // reference an identifier nothing in it declares — 114 of them over the four
  // corpus binaries at `f169c00`, and `corpus/emitAudits.ts`' `preludeFor` hid
  // every one by manufacturing `long flg_…;` in answer to gcc's complaint. The
  // width is the point of the assertion as much as the presence: not one of
  // those 114 captures is 8 bytes wide, so `long` was wrong for all of them and
  // the program gcc compiled was not the one the emitter wrote.
  it.each([
    ["a 32-bit register", "eax, 5", "eax, edx", "int32_t"],
    ["a byte register", "al, 5", "al, dl", "uint8_t"],
    ["a 16-bit register", "ax, 5", "ax, dx", "uint16_t"],
  ])("declares the capture of %s", (_label, cmp, spoil, type) => {
    const code = run(
      seq(0x401000, [
        ["cmp", cmp],
        ["mov", spoil],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain(`    ${type} flg_401000_0;`);
  });

  // THE DECLARATION IS WHAT MAKES THE COMPARISON UNSIGNED, so the type is taken
  // from type inference where it has one. `cOp` spells `u<` as a bare `<`, so
  // nothing in the expression says which comparison the machine makes — under
  // the prelude's `long` both of these compiled as a signed 64-bit compare.
  // Inference is consulted only when its spelling names the SAME width as the
  // operand, because `typeInfer.ts` types a comparison operand with the width
  // hard-coded at 4.
  it.each([
    ["jl", "int32_t"],
    ["jb", "uint32_t"],
  ])("declares a captured operand of a %s with inference's signedness", (jcc, type) => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, ecx"],
        ["mov", "eax, edx"],
        [jcc, "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain(`    ${type} flg_401000_0;`);
    expect(code).toContain(`    ${type} flg_401000_1;`);
    expect(guardTexts(code)).toEqual(["flg_401000_0 < flg_401000_1"]);
  });

  // ── Controls. Every one of these must keep recovering, or the refusal is
  // too wide and the cost is guards that were correct becoming admissions.

  it("still recovers across a flag-transparent instruction", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["mov", "esi, edi"],
        ["jne", "0x401014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["eax != 5"]);
  });

  it("still recovers when the later write touches an unrelated register", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["mov", "edx, ecx"],
        ["je", "0x401014"],
        ["mov", "ebx, 1"],
        ["ret"],
        ["mov", "ebx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["eax == 5"]);
  });

  // Last cmp wins, which the forward walk always got right — the defect was
  // that nothing OTHER than a cmp could take the flags away.
  it("still answers from the last of two compares", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["cmp", "ecx, 7"],
        ["jne", "0x401014"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["ecx != 7"]);
  });

  // The arithmetic path is untouched: no cmp in the block, so
  // `conditionFromFlagResult` answers it by naming the result, as before.
  it("still recovers a condition from flag-setting arithmetic", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "ecx"],
        ["jne", "0x401010"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["ecx != 0"]);
  });
});

/**
 * A Jcc alone in its basic block reads flags set in the block before it, and
 * until peek-a-bin-suql no condition path crossed that edge: `blockFlagOwner`
 * read `block.insns` only, so for a one-instruction block the forward walk ran
 * zero iterations and reported `{kind: "none", reason: "no-owner"}`, and
 * `extractCondition`'s fallback looped over the same single block. **88 such
 * blocks across the four corpus binaries**, every one of them emitting
 * `__unrecovered_N` however good the predecessor's test was — while the sibling
 * Jcc reading the *same* flags one block earlier was recovered two lines up.
 *
 * The dominant machine shape is MSVC's three-way dispatch, and t32.exe 0x40490B
 * is it verbatim: `cmp eax, 0x64 / jg` then a lone `je`, then `cmp eax, 0x53 /
 * jg` then a lone `je`. That is what the first test below is.
 *
 * Three things make the recovery sound rather than a guess, and each has a test
 * here because each is a way to get it wrong that no stage-level test would
 * catch:
 *
 * - **The predecessor's terminator must be skipped explicitly.** `jmp` and every
 *   Jcc are absent from `NO_FLAG_WRITE`, so `flagEffect` classes them as a
 *   clobber and a walk that reads them clears the very owner it came for. That
 *   is not a lost optimisation: it recovers **0** guards on all four binaries,
 *   which is a false negative the first measurement pass actually produced.
 * - **The taken edge is as safe as the fallthrough.** A Jcc writes no flags, so
 *   entry flags are the owner's flags on either edge; the predecessor's own
 *   condition being true rather than false on that path is a fact about values.
 *   Restricting to fallthrough leaves 17 of the 69 recoverable guards unclaimed
 *   and over half the x64 win.
 * - **More than one predecessor is a phi of conditions, and one block-local
 *   condition cannot state it.** All 12 corpus cases have exactly two
 *   predecessors, each with a perfectly spellable owner, and they are *different
 *   instructions* — t64 0x140002AFD is `test rbx, rbx` against `test rbp, rbp`.
 *   Answering from either would be a guard the machine does not always make.
 */
describe("decompileFunction — a Jcc alone in its block reads its predecessor's flags", () => {
  /** The emitted guards, or ["<unrecovered>"] where the condition was admitted. */
  function guardTexts(code: string): string[] {
    return guardConditions(code).map((c) => (/__unrecovered_\d+/.test(c) ? "<unrecovered>" : c));
  }

  // MSVC's three-way dispatch, the shape 56 of the 88 corpus blocks have:
  // `cmp` + `jcc` in the predecessor, a second `jcc` alone in the fallthrough.
  // Both guards must be real. This is also the terminator-skip test — the
  // predecessor's last instruction is the `jg`, and reading it as a flag writer
  // takes the second guard back to `<unrecovered>`.
  it("recovers a lone jcc from the compare in its fallthrough predecessor", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 0x53"],
        ["jg", "0x401018"],
        ["je", "0x401020"],
        ["mov", "ecx, 1"],
        ["mov", "eax, ecx"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
        ["mov", "ecx, 3"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["eax > 0x53", "eax == 0x53"]);
    expect(code).not.toContain("__unrecovered");
  });

  // `test reg, reg` is the other half of the corpus population (34 of the 76
  // single-predecessor blocks), and on x64 it is the majority.
  it("recovers a lone jcc from a test in its predecessor", () => {
    const code = run(
      seq(0x401000, [
        ["test", "eax, eax"],
        ["js", "0x401018"],
        ["jle", "0x401020"],
        ["mov", "ecx, 1"],
        ["mov", "eax, ecx"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
        ["mov", "ecx, 3"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["eax < 0", "eax <= 0"]);
  });

  // The taken edge. The lone `je` at 0x401010 is reached only by the `jg`
  // JUMPING there, and it is still the `cmp`'s flags that it reads — a Jcc
  // writes none. Worth 17 of the 69 corpus recoveries, and 6 of t64's 13.
  it("recovers a lone jcc reached by its predecessor's taken edge", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 0x53"],
        ["jg", "0x401010"],
        ["mov", "ecx, 1"],
        ["ret"],
        ["je", "0x40101c"],
        ["mov", "ecx, 2"],
        ["ret"],
        ["mov", "ecx, 3"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["eax <= 0x53", "eax == 0x53"]);
    expect(code).not.toContain("__unrecovered");
  });

  // Two predecessors, each with its own spellable owner, and they are different
  // instructions: `cmp eax, 0x53` on one edge, `test ecx, ecx` on the other. The
  // `je` reads whichever ran, which no single condition states, so it must stay
  // admitted. Refusing this is what keeps the recovery from being a guess, and
  // it is 12 of the 14 multi-predecessor blocks in the corpus at `f169c00`
  // (peek-a-bin-xdxt). The other 2 are the test below.
  it("refuses a lone jcc whose two predecessors set the flags differently", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 0x53"],
        ["jg", "0x401010"],
        ["test", "ecx, ecx"],
        ["jmp", "0x401010"],
        ["je", "0x40101c"],
        ["mov", "edx, 1"],
        ["ret"],
        ["mov", "edx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toContain("<unrecovered>");
    expect(code).not.toContain("eax == 0x53");
    expect(code).not.toContain("ecx == 0");
  });

  // ...and the generalisation: when every predecessor sets the flags from the
  // SAME test, the block is entered with those flags however it was reached, so
  // one block-local condition states the machine and there is nothing to merge.
  // This is MSVC's `_stricmp` tail, the only shape in the corpus that agrees —
  // t32 0x40E696 and w32 0x40CDB6, one guard per 32-bit binary. `jb` after
  // `cmp ah, al` is unsigned-below, and the arm that runs is the fallthrough, so
  // the emitted guard is its negation (peek-a-bin-xdxt).
  it("recovers a lone jcc whose two predecessors set the flags from the same test", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "ah, al"],
        ["jne", "0x401014"],
        ["xor", "ecx, ecx"],
        ["cmp", "ah, al"],
        ["je", "0x401020"],
        ["mov", "ecx, 0xffffffff"],
        ["jb", "0x401020"],
        ["neg", "ecx"],
        ["mov", "eax, ecx"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["ah != al", "ah >= al", "ah != al"]);
    expect(code).not.toContain("__unrecovered");
  });

  // The predecessor's compare is spoiled by a store in its own tail, which is
  // the `staleGuards` class exactly: `cmp dword ptr [ebp - 0x18], 0` followed by
  // `mov dword ptr [ebp - 0x18], edx` compares the OLD slot, and the store is
  // emitted above the guard.
  //
  // BOTH jccs are answered, and the second one is the point. The `jg` is in the
  // compare's OWN block, so peek-a-bin-xskz materialises the slot for it. The
  // `je` is a block away and this used to be refused, on the reading that a
  // cross-block owner would need a capture PLACED in the predecessor — which
  // `liftBlock` cannot do. It does not need one: the predecessor's own trailing
  // jcc reads the same compare, so the capture is already there, and the `je` is
  // downstream of it. `reusablePredecessorCapture` looks it up rather than
  // placing anything (peek-a-bin-zylv). All 2/0/0/1 cross-block spoiled owners
  // in the corpus at `16f1633` are this shape.
  //
  // THIS FIXTURE IS THE DISCRIMINATOR, and the corpus is not. On all three real
  // sites the spoiling stores write OTHER slots — `spoils` refuses on any store,
  // with no alias analysis — so simply bypassing the refusal and reading the raw
  // operands recovers the same 3 guards with the same text, and every gate stays
  // flat. Here the store overwrites the compared slot itself, so that variant
  // emits `if (var_18 == 0)` below `var_18 = edx;` and the last two assertions
  // fail.
  it("reads a predecessor's spoiled compare through the capture the predecessor took", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "dword ptr [ebp - 0x18], 0"],
        ["mov", "dword ptr [ebp - 0x18], edx"],
        ["jg", "0x401020"],
        ["je", "0x401028"],
        ["mov", "ecx, 1"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
        ["mov", "ecx, 3"],
        ["ret"],
      ]),
    );

    // Both guards read the materialised value, and the cross-block one is spelled
    // from the SAME capture — one statement, at the compare, read twice.
    expect(guardTexts(code)).toEqual(["flg_401000_0 > 0", "flg_401000_0 == 0"]);
    // The load of the slot is emitted ABOVE the store that replaces it, which is
    // the whole claim; neither guard names the slot itself.
    expect(code.indexOf("flg_401000_0 = var_18;")).toBeGreaterThan(-1);
    expect(code.indexOf("flg_401000_0 = var_18;")).toBeLessThan(code.indexOf("var_18 = edx;"));
    expect(code).not.toContain("if (var_18");
    // Exactly one capture statement: the reading block reuses the predecessor's
    // rather than emitting a second one, which would sit BELOW the store.
    expect(code.split("flg_401000_0 = var_18;").length - 1).toBe(1);
    expect(code).not.toContain("__unrecovered");
  });

  // …and the reuse is refused when the predecessor took no capture, which is the
  // half of this that keeps it a lookup rather than an assumption. The
  // predecessor's tail spoils its compare exactly as above, but the predecessor
  // ends in `jmp` — it reads no flags, so its own lift had no guard to answer and
  // materialised nothing. There is no statement to read and the guard stays
  // admitted. `reusablePredecessorCapture` finds that out by re-asking
  // `spoiledCompareCapture` of the predecessor rather than by assuming the
  // spoiling implies a capture (peek-a-bin-zylv).
  it("refuses a predecessor's spoiled compare when the predecessor took no capture", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "dword ptr [ebp - 0x18], 0"],
        ["mov", "dword ptr [ebp - 0x18], edx"],
        ["jmp", "0x401014"],
        ["mov", "ecx, 9"],
        ["ret"],
        ["je", "0x40101c"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
    // Nothing was materialised, so there is nothing for the guard to have read.
    expect(code).not.toContain("flg_401000_0");
    expect(code).not.toContain("if (var_18");
  });

  // …and spoiled from the OTHER side of the edge. The block need not hold only
  // the Jcc — a block whose instructions are all flag-transparent reads its
  // predecessor's flags just as surely — but one of them can overwrite what the
  // condition is spelled with, and the guard is emitted below it. The walk
  // continues through both sides of the edge for exactly this, so `spoiled` is
  // already set by the time the caller asks.
  it("refuses a predecessor's compare that the reading block overwrote", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 0x53"],
        ["jg", "0x401018"],
        ["mov", "eax, edx"],
        ["je", "0x401020"],
        ["mov", "ecx, 1"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
        ["mov", "ecx, 3"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["eax > 0x53", "<unrecovered>"]);
  });

  // The predecessor has no owner at all: `sbb` is `{clobber, carry-in}`, so
  // clearing is correct and the `jg` is a signed 64-bit comparison over a
  // register pair this model has no expression for. 4 of the 19 refusals, all
  // this one shape — MSVC's 64-bit subtract.
  it("refuses a lone jcc whose predecessor's flags were clobbered", () => {
    const code = run(
      seq(0x401000, [
        ["sub", "esi, eax"],
        ["sbb", "edi, edx"],
        ["js", "0x401010"],
        ["jg", "0x401018"],
        ["mov", "ecx, 1"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code).filter((g) => g !== "<unrecovered>")).toEqual([]);
  });

  // Control. A flag-transparent write to a register the condition does not name
  // must not refuse the crossing — the refusals above are asked of the operands,
  // not of the edge.
  it("still crosses the edge when the predecessor's tail writes an unrelated register", () => {
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 0x53"],
        ["mov", "edx, ecx"],
        ["jg", "0x40101c"],
        ["je", "0x401024"],
        ["mov", "ecx, 1"],
        ["mov", "eax, ecx"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
        ["mov", "ecx, 3"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["eax > 0x53", "eax == 0x53"]);
  });
});

/**
 * MSVC spells a small constant `push <imm>` / `pop <reg>` — two bytes against
 * the five of `mov reg, imm` — and until peek-a-bin-3axd `liftBlock` skipped
 * both halves outright (`if (mn === "push" || mn === "pop") continue;`). The
 * `pop` was therefore not a DEFINITION in SSA, so every later read of the
 * register bound to the value it held BEFORE the pop, and nothing downstream
 * was at fault: `ssaOptimize` is sound given that input.
 *
 * The damage is wrong values in C that compiles clean, and **no gate here can
 * see any of it** — gcc compiles `edi = edi`, the operator is right so polarity
 * and `corpus/staleGuards.ts` pass, it is not `__unrecovered_N`, and the
 * statement-drop audit snapshots after `foldBlock` so a value folded away
 * earlier is outside its comparison. Measured on the corpus at 896fa6f: 46
 * idiom pops on t32 whose value is READ in the post-fold IR, 97 reads across 28
 * functions, of which only 2 happened to land on a visible self-assignment.
 *
 * The three tests below are the three shapes that were hand-verified against
 * `objdump -d -M intel t32.exe`, and the refusals are the fourth: the rule is
 * `../../stackIdiom`'s `pushedImmediate`, shared with `functionDetect.ts`
 * rather than re-derived, and anything it will not pair is left exactly as it
 * was.
 */
describe("decompileFunction — push <imm> / pop <reg> is a move", () => {
  // t32 0x40D23F, the site the bead was filed about: `push 0x8 / … / pop esi`
  // sets ESI to 8 and `add edi, esi` is `edi += 8` — a varargs walker stepping
  // over a 64-bit argument, corroborated by the `[edi-8]` and `[edi-4]` loads
  // that follow. With the pop invisible, ESI folded to a zeroing definition
  // that reaches a DIFFERENT block and the addend vanished: `edi = edi`.
  //
  // The `shr` between the push and the pop is in the machine text too, and it
  // is why the pairing may not require adjacency. So are the two loads off
  // `[edi-8]` and `[edi-4]`, and they earn their place in the fixture twice
  // over: they are the semantic corroboration that the step is 8 rather than 4
  // (this is a varargs walker reading the halves of a 64-bit argument), and
  // they give EDI more than one surviving reader, without which `foldBlock`
  // inlines the whole thing into the return and the compound-assignment shape
  // never appears. The `var_21C = edi` spill is in the machine text at 0x40D247
  // for the same reason it is here.
  it("lifts a pop of a pushed immediate as an assignment", () => {
    const code = run(
      seq(0x401000, [
        ["push", "0x8"],
        ["shr", "eax, 0x4"],
        ["pop", "esi"],
        ["add", "edi, esi"],
        ["mov", "eax, dword ptr [edi - 8]"],
        ["mov", "edx, dword ptr [edi - 4]"],
        ["mov", "dword ptr [ebx], edi"],
        ["ret"],
      ]),
    );

    expect(code).toContain("edi += 8");
    expect(code).not.toMatch(/edi = edi/);
  });

  // t32 0x40CD31: the same `push 0x8 / pop esi` feeds `cmp eax, esi / je`, and
  // the guard read `eax == 0` because the folded-in ESI was a zero from
  // elsewhere. The 8-case switch two instructions later is bounded by a second
  // instance of the idiom, `push 0x7 / pop ecx / cmp eax, ecx / ja`, which
  // `functionDetect.ts` ALREADY read correctly through the very same rule —
  // that inconsistency, one file's answer invisible to another three files
  // away, is why the rule is now a shared leaf module.
  it("recovers a guard that compares against a pushed immediate", () => {
    const code = run(
      seq(0x401000, [
        ["push", "0x8"],
        ["pop", "esi"],
        ["cmp", "eax, esi"],
        ["je", "0x401020"],
        ["mov", "ecx, 1"],
        ["mov", "eax, ecx"],
        ["ret"],
        ["mov", "ecx, 2"],
        ["ret"],
      ]),
    );

    expect(guardConditions(code)).toEqual(["eax == 8"]);
    expect(code).not.toContain("eax == 0");
  });

  // t32!sub_401E71, the worst hand-verified site and the one with no
  // self-assignment anywhere in it to give it away. `test esi, esi / jne` means
  // the fallthrough path has PROVED ESI == 0; then `_errno()` is called and
  // `push 0x16 / pop esi / mov [eax], esi` sets errno to 22 (EINVAL) and
  // returns 22. With the pop skipped, ESI was still bound to the argument the
  // guard had just proved zero, so the emitted C set errno to 0 and returned 0
  // — an inverted success/failure path.
  //
  // The assertion that matters is the one on the STORE: a test that only
  // checked for `0x16` appearing somewhere would pass on output that also still
  // stored the stale zero.
  it("does not store a value a guard proved zero where the machine stores an immediate", () => {
    const code = run(
      seq(0x401000, [
        ["mov", "esi, dword ptr [ebp + 8]"],
        ["test", "esi, esi"],
        ["jne", "0x401028"],
        ["call", "0x404127"],
        ["push", "0x16"],
        ["pop", "esi"],
        ["mov", "dword ptr [eax], esi"],
        ["mov", "eax, esi"],
        ["ret"],
        ["xor", "eax, eax"],
        ["ret"],
      ]),
    );

    const store = code.split("\n").find((l) => l.includes("*(int32_t*)(eax) ="));
    expect(store).toBeDefined();
    expect(store).toContain("0x16");
    expect(store).not.toMatch(/=\s*(0|esi)\s*;/);
  });

  // Every refusal below leaves the pop unlifted, which is exactly the
  // pre-existing behaviour — `pop` as a general stack operation is
  // peek-a-bin-4ynk and deliberately out of scope, because modelling it needs a
  // stack pseudo-slot and the alternative (refusing outright) would trade
  // correct save/restore readings for admitted gaps.
  //
  // A pop with no `push <imm>` above it in its own block must therefore produce
  // no assignment at all. `pushedImmediate` is given `block.insns`, so running
  // off the front is a refusal — and since peek-a-bin-6ilz a SECOND rule gets
  // asked afterwards, so this fixture pins the case by having the pop in the
  // ENTRY block: no predecessor pushes anything, because there is no
  // predecessor.
  it("lifts nothing for a pop with no push above it", () => {
    const code = run(
      seq(0x401000, [["pop", "esi"], ["mov", "edi, esi"], ["mov", "eax, edi"], ["ret"]]),
    );

    expect(code).not.toMatch(/\besi\s*=/);
  });

  // `add esp, 4` between the two moves the stack pointer, so the pop takes
  // something else entirely and the pairing would be one slot out. Neither a
  // stack mnemonic nor a memory operand, which is why the operand text is
  // scanned as well as the mnemonic set.
  it("lifts nothing when the stack pointer moved between the push and the pop", () => {
    const code = run(
      seq(0x401000, [
        ["push", "0x8"],
        ["add", "esp, 4"],
        ["pop", "esi"],
        ["mov", "eax, esi"],
        ["ret"],
      ]),
    );

    expect(code).not.toMatch(/\besi\s*=/);
    expect(code).not.toContain("= 8");
  });

  // A push of a REGISTER is a copy this rule cannot state, not a constant. It
  // must not be read as an immediate, and it must not be read as a move either
  // — that is the save/restore class, and `push esi / pop esi` around a body is
  // the single most common `pop` in this corpus.
  it("lifts nothing for a pop of a pushed register", () => {
    const code = run(
      seq(0x401000, [["push", "ebx"], ["pop", "esi"], ["mov", "eax, esi"], ["ret"]]),
    );

    expect(code).not.toMatch(/\besi\s*=/);
  });

  // Capstone prints a sign-extended `push imm8` as `push -2`, where objdump
  // prints `push 0xfffffffe`. The signed spelling is a real push of a real
  // constant and must lift: at t32 0x4022FA, refusing it left the two later
  // `esi` reads naming `0x14`, the value ESI held before the pop, which is the
  // same defect one refusal further along.
  it("lifts a pop of a negative pushed immediate", () => {
    const code = run(
      seq(0x401000, [["push", "-2"], ["pop", "esi"], ["mov", "dword ptr [eax], esi"], ["ret"]]),
    );

    expect(code).toContain("*(int32_t*)(eax) = -2");
  });
});

/**
 * …and the same idiom split across a branch, which is a PHI of immediates.
 *
 * MSVC routinely puts the `push` in each arm of an `if`/`else if` chain and the
 * `pop` at the join, so the register's value is one of several constants. The
 * `pop` is not a definition in SSA and every later read binds to the value the
 * register held before it — `peek-a-bin-3axd`'s defect one block further out,
 * and `pushedImmediate` cannot see it because it is handed one block.
 *
 * These are end-to-end for the reason the whole file is: the fix puts a
 * definition in each PREDECESSOR and relies on `buildSSA` to build the phi, so
 * nothing at the stage level can tell you the read at the join binds to it.
 * Both shapes below were read against `objdump -d -M intel t32.exe`
 * (peek-a-bin-6ilz).
 */
describe("decompileFunction — a cross-block push <imm> / pop <reg>", () => {
  // t32 0x4077f3, the site the bead named: `cmp WORD PTR [ebp-8], 0xa / je` then
  // `push 0xd` on the fallthrough and `push 0xa` from an earlier block that
  // jumps in, joining at `pop eax / mov WORD PTR [ebx], ax`. MSVC writing CR or
  // LF. With the pop invisible the store named whatever EAX last held — a
  // `ReadFile` result at the real site.
  it("gives the join a phi of the immediates its predecessors push", () => {
    const code = run(
      seq(0x401000, [
        ["test", "eax, 0x100"],
        ["je", "0x401010"],
        ["push", "0xd"],
        ["jmp", "0x401014"],
        ["push", "0xa"],
        ["pop", "ecx"],
        ["mov", "dword ptr [ebx], ecx"],
        ["ret"],
      ]),
    );

    expect(code).toMatch(/\becx = 0xD\b/);
    expect(code).toMatch(/\becx = 0xA\b/);
    expect(code).toContain("*(int32_t*)(ebx) = ecx");
  });

  // ALL predecessors or none, and this is the test that says why: defining the
  // register on one incoming edge and not the other leaves the phi's other
  // operand naming the stale value, which reads as recovered while being wrong
  // on that path. Refusing leaves both paths at today's behaviour, which is
  // visible rather than plausible.
  it("refuses when one predecessor pushes nothing", () => {
    const code = run(
      seq(0x401000, [
        ["test", "eax, 0x100"],
        ["je", "0x401010"],
        ["push", "0xd"],
        ["jmp", "0x401014"],
        ["mov", "edx, 1"],
        ["pop", "ecx"],
        ["mov", "dword ptr [ebx], ecx"],
        ["ret"],
      ]),
    );

    expect(code).not.toMatch(/\becx = 0xD\b/);
  });

  // The definition is appended to the predecessor, so it reaches every successor
  // of it — including the one where the `pop` never runs. `push 0xd / jne <pop>`
  // must therefore refuse, and this is the shape where the emitted C would state
  // a value the machine does not have on the fallthrough path.
  it("refuses a predecessor whose push is guarded by its own conditional jump", () => {
    const code = run(
      seq(0x401000, [
        ["push", "0xd"],
        ["jne", "0x401010"],
        ["mov", "edx, 1"],
        ["ret"],
        ["pop", "ecx"],
        ["mov", "dword ptr [ebx], ecx"],
        ["ret"],
      ]),
    );

    expect(code).not.toMatch(/\becx = 0xD\b/);
  });
});

/**
 * A read-modify-write on memory sets the flags from what it wrote, and the
 * guard reading them is spelled from that memory operand.
 *
 * `dec dword ptr [ebp + 0x10] / je` is the shape, and until peek-a-bin-ie0j it
 * emitted `__unrecovered_N` for a reason that was purely about spelling:
 * `flagModel.ts` published only `destReg`, which is null for a memory
 * destination, and `lifter.ts` built the condition with `irReg(destText, …)`,
 * which cannot express `dword ptr [ebp + 0x10]`. The parent bead had recorded
 * the cause as dataflow — "the result is in memory; naming it would need a load
 * that is not in the IR" — and that was wrong: the lifter emits the store,
 * `promoteVars` names its slot, and t32.exe 0x4020EE emitted `arg_2--;` on the
 * line directly above an `if` whose condition was `!!__unrecovered_1` with the
 * originating `je` in a trailing comment. The value was already on the page,
 * spelled, one line up.
 *
 * **The ordering is the whole soundness argument, so it is asserted directly.**
 * These are read-modify-write guards, so the `if` must read the location AFTER
 * the store. That holds because `structureCFG` emits a block's statements above
 * the `if` it closes with — the same property the compare arm's
 * `conditionSpoiled` depends on, read the other way round — and it is a
 * property no unit test of `flagModel` or `branchFor` can see.
 *
 * **Refusal is on any store, with no attempt to prove the addresses alias.**
 * That is `spoils`' whole alias analysis, and the negative controls below are
 * what say so: an unrelated `mov [eax], ecx` between the `dec` and the `je`
 * gives the guard up rather than assume EAX misses the slot, and a `push` does
 * too, since it writes memory its operand text does not name.
 */
describe("decompileFunction — a guard reads a memory destination the block just wrote", () => {
  /** A 32-bit run with the StackFrame the real caller computes. */
  function runFramed(instructions: Instruction[]): string {
    const last = instructions[instructions.length - 1];
    const func: DisasmFunction = {
      name: "sub_401000",
      address: instructions[0].address,
      size: last.address + last.size - instructions[0].address,
    };
    return decompileFunction(
      func,
      instructions,
      new Map<number, Xref[]>(),
      analyzeStackFrame(func, instructions, false),
      null,
      false,
      new Map(),
      new Map(),
      new Map(),
      new Map(),
      new StructRegistry(),
    ).code;
  }

  /** The emitted guards, or ["<unrecovered>"] where the condition was admitted. */
  function guardTexts(code: string): string[] {
    return guardConditions(code).map((c) => (/__unrecovered_\d+/.test(c) ? "<unrecovered>" : c));
  }

  /**
   * t32.exe 0x4020EE, with the verified prologue that makes `[ebp + 0x10]` the
   * third argument slot. This is the bead's own example: in, `dec dword ptr
   * [ebp + 0x10]` / `je`; out, `arg_2 == 0`.
   */
  const framedDec: [string, string?][] = [
    ["push", "ebp"],
    ["mov", "ebp, esp"],
    ["dec", "dword ptr [ebp + 0x10]"],
    ["je", "0x401020"],
    ["mov", "eax, 1"],
    ["pop", "ebp"],
    ["ret"],
    ["mov", "eax, 2"],
    ["pop", "ebp"],
    ["ret"],
  ];

  it("spells the guard from the argument slot the dec wrote", () => {
    expect(guardTexts(runFramed(seq(0x401000, framedDec)))).toEqual(["arg_2 == 0"]);
  });

  it("emits the decrement ABOVE the if that reads it", () => {
    // The read-modify-write risk, stated as an assertion rather than assumed.
    // `arg_2--` after the guard, or missing, would make `arg_2 == 0` a test of
    // the value on the way IN, which is one iteration early — the same error
    // `setFlagsFromResult`'s docstring warns about for a register.
    const code = runFramed(seq(0x401000, framedDec));
    const lines = code.split("\n").map((l) => l.trim());
    const store = lines.findIndex((l) => /^arg_2--;$/.test(l));
    const guard = lines.findIndex((l) => l.includes("arg_2 == 0"));
    expect(store).toBeGreaterThanOrEqual(0);
    expect(guard).toBeGreaterThan(store);
  });

  it("recovers a dec through a plain pointer, with no frame to promote it", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "dword ptr [ecx + 4]"],
        ["js", "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["*(int32_t*)(ecx + 4) < 0"]);
  });

  it("recovers an add of a negative immediate to memory", () => {
    // t32.exe 0x40AAF5: `add DWORD PTR [esi+0x4], 0xfffffffe / js`. The flags
    // are the add's and the operand is the value it produced, so the sign test
    // is exact — the same rule the `dec` cases use, with a different mnemonic.
    const code = run(
      seq(0x401000, [
        ["add", "dword ptr [esi + 4], -2"],
        ["js", "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["*(int32_t*)(esi + 4) < 0"]);
  });

  it("keeps recovering across a write to an unrelated register", () => {
    // The real corpus shape at t32.exe 0x402125: `dec DWORD PTR [ebp+0x10] /
    // movzx eax, ax / je`. A register write cannot reach the slot.
    const code = runFramed(
      seq(0x401000, [
        ["push", "ebp"],
        ["mov", "ebp, esp"],
        ["dec", "dword ptr [ebp + 0x10]"],
        ["movzx", "eax, ax"],
        ["je", "0x401024"],
        ["mov", "eax, 1"],
        ["pop", "ebp"],
        ["ret"],
        ["mov", "eax, 2"],
        ["pop", "ebp"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["arg_2 == 0"]);
  });

  // ── Negative controls ──

  it("refuses when an unrelated store could have reached the location", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "dword ptr [ecx + 4]"],
        ["mov", "dword ptr [eax], edx"],
        ["js", "0x40101c"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("refuses across a push, which writes memory its operand text does not name", () => {
    const code = run(
      seq(0x401000, [
        ["dec", "dword ptr [ecx + 4]"],
        ["push", "eax"],
        ["js", "0x40101c"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("refuses a jcc the result cannot answer at all", () => {
    // `inc`/`dec` do not write CF, and no result determines OF the way a `cmp`
    // does, so `jae` stays unrecovered however well the destination is spelled.
    // Admitting memory must not be read as admitting more Jcc forms.
    const code = run(
      seq(0x401000, [
        ["dec", "dword ptr [ecx + 4]"],
        ["jae", "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("refuses a memory result in a block that also holds a cmp", () => {
    // Refusal 3 in `branchFor` — the compare and result recovery paths are kept
    // disjoint, because `corpus/staleGuards.ts` reads ANY condition emitted at
    // such a jcc as the superseded one. Admitting memory does not change that.
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["dec", "dword ptr [ecx + 4]"],
        ["js", "0x40101c"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });
});

/**
 * A `lock`-prefixed read-modify-write lifts as its unlocked form, and the guard
 * reading its flags is spelled from the memory it wrote.
 *
 * `flagModel.ts` used to return `{clobber, "locked"}` for **any** `lock` prefix
 * before looking at the base mnemonic, and `liftBlock` dispatched on the
 * prefixed text — so `lock dec dword ptr [rbx] / jne`, the textbook COM
 * `Release`, emitted an `unlifted` comment above `if (!!__unrecovered_1)`. Both
 * halves were wrong about the machine in the same way: the prefix changes
 * atomicity and the bus and **nothing** about the values or the flags, so the
 * instruction sets ZF from what it wrote exactly as the unlocked form does, and
 * peek-a-bin-ie0j had already made a memory destination spellable
 * (peek-a-bin-3qrl).
 *
 * **What the lift loses is the word `lock`**, and that is the deliberate trade:
 * nothing in this IR can express atomicity — `xchg` with a memory operand is
 * implicitly locked on x86 and has been lifted as a plain swap since long
 * before this — and a comment naming the instruction beside an unrecovered
 * guard states strictly less than the decrement plus the test.
 *
 * The negative controls are the other half of the rule: `lock cmpxchg` and
 * `lock xadd` are **not** `lock dec`, the lifter has no handler for either
 * base, and inventing a reading for them would be worse than leaving them. Both
 * stay verbatim on the `raw` fallback, `lock` included.
 */
describe("decompileFunction — a lock-prefixed read-modify-write lifts as its base form", () => {
  /** The emitted guards, or ["<unrecovered>"] where the condition was admitted. */
  function guardTexts(code: string): string[] {
    return guardConditions(code).map((c) => (/__unrecovered_\d+/.test(c) ? "<unrecovered>" : c));
  }

  /** t64.exe 0x140005BC8 and three siblings: an atomic refcount release. */
  const lockDec: [string, string?][] = [
    ["lock dec", "dword ptr [rbx]"],
    ["jne", "0x401020"],
    ["mov", "rcx, rbx"],
    ["call", "0x401100"],
    ["ret"],
    ["mov", "eax, 2"],
    ["ret"],
  ];

  it("spells the guard from the memory the locked decrement wrote", () => {
    expect(guardTexts(run(seq(0x401000, lockDec), true))).toEqual(["*(int32_t*)(rbx) != 0"]);
  });

  it("emits the decrement ABOVE the if that reads it", () => {
    // Same read-modify-write ordering argument as peek-a-bin-ie0j's, asserted
    // rather than assumed: a guard emitted above the store would test the
    // refcount on the way in, which is one release too early.
    const lines = run(seq(0x401000, lockDec), true)
      .split("\n")
      .map((l) => l.trim());
    const store = lines.findIndex((l) => /\*\(int32_t\*\)\(rbx\).*(--|-= 1|= .*- 1)/.test(l));
    const guard = lines.findIndex((l) => l.includes("*(int32_t*)(rbx) != 0"));
    expect(store).toBeGreaterThanOrEqual(0);
    expect(guard).toBeGreaterThan(store);
  });

  it("leaves no unlifted comment for a locked form it now lifts", () => {
    expect(run(seq(0x401000, lockDec), true)).not.toContain("unlifted");
  });

  it("lifts a locked increment and a locked add with no guard involved", () => {
    // t64.exe 0x140006143 and 0x1400061E5. There is a `test`/`cmp` between each
    // of these and its Jcc in the real binary, so the compare owns the flags and
    // this is purely about the value reaching the page at all.
    const code = run(
      seq(0x401000, [
        ["lock inc", "dword ptr [rax]"],
        ["lock add", "dword ptr [rcx], r9d"],
        ["ret"],
      ]),
      true,
    );

    expect(code).not.toContain("unlifted");
    expect(code).toContain("*(int32_t*)(rax)");
    expect(code).toContain("r9d");
  });

  // ── Negative controls ──

  it("leaves lock cmpxchg unlifted, prefix included, and its guard unrecovered", () => {
    const code = run(
      seq(0x401000, [
        ["lock cmpxchg", "dword ptr [rbx], edx"],
        ["jne", "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toContain("unlifted: lock cmpxchg dword ptr [rbx], edx");
    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("leaves lock xadd unlifted, prefix included, and its guard unrecovered", () => {
    const code = run(
      seq(0x401000, [
        ["lock xadd", "dword ptr [rbx], edx"],
        ["jne", "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toContain("unlifted: lock xadd dword ptr [rbx], edx");
    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("refuses the locked guard when a later store could have reached the location", () => {
    // `spoils`' whole alias analysis, inherited unchanged from peek-a-bin-ie0j.
    const code = run(
      seq(0x401000, [
        ["lock dec", "dword ptr [rbx]"],
        ["mov", "dword ptr [rax], ecx"],
        ["jne", "0x40101c"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });
});

/**
 * A locked read-modify-write with **no value effect** is a memory barrier, and
 * says so instead of claiming a store.
 *
 * `lock or byte ptr [rsp], 0` is the classic full fence; MSVC emits it right
 * after a non-temporal `movnti` store loop, which is where all six corpus
 * occurrences sit (t64 0x140007F80 / 0x14000C5CA / 0x14000C76A and the same
 * three in w64). peek-a-bin-3qrl made `liftBlock` dispatch on the *base*
 * mnemonic — correctly, and it recovered four guards per x64 binary — and the
 * fence was its unintended residue: it reached the `or` handler, lifted to
 * `*(rsp) = *(rsp) | 0`, `foldExpr` folded `x | 0` to `x`, and `promoteVars`
 * named `[rsp+0]` a frame slot. The reader got `var_0 = var_0;` plus an invented
 * `uint8_t var_0;` declaration, and the fence was gone from the page
 * (peek-a-bin-qbk3).
 *
 * The negative controls are the rule, not decoration. **The prefix is required
 * as well as the nil value effect, never instead of it** — an unlocked
 * `or [mem], 0` is a dead store rather than a fence — and `and <mem>, <all
 * ones>` is refused because `and`'s identity element is width-dependent and a
 * text-level reading of it misfires on real instructions in this corpus.
 */
describe("decompileFunction — a value-effect-free locked RMW is a barrier, not a store", () => {
  /** t64.exe 0x140007F80: the fence closing a `movnti` store loop. */
  const fence: [string, string?][] = [["lock or", "byte ptr [rsp], 0"], ["ret"]];

  it("leaves the fence as a comment naming the instruction", () => {
    expect(run(seq(0x401000, fence), true)).toContain("unlifted: lock or byte ptr [rsp], 0");
  });

  it("invents neither a self-assignment nor a declaration for it", () => {
    const code = run(seq(0x401000, fence), true);
    // Both halves of the symptom. `var_0` must not appear at all: not as the
    // statement, and not as the `uint8_t var_0;` above it that nothing reads.
    expect(code).not.toMatch(/\bvar_0\b/);
    expect(code).not.toMatch(/(\w+)\s*=\s*\1\s*;/);
  });

  it("treats the other zero-neutral locked forms the same way", () => {
    // `add`/`sub`/`xor` with a 0 source are the same nil value effect and are on
    // the same `lock`-legal opcode list. None occurs in this corpus, so these
    // are asserted from the rule rather than from a site.
    for (const mn of ["lock add", "lock sub", "lock xor"]) {
      const code = run(seq(0x401000, [[mn, "byte ptr [rsp], 0"], ["ret"]]), true);
      expect(code).toContain(`unlifted: ${mn} byte ptr [rsp], 0`);
      expect(code).not.toMatch(/\bvar_0\b/);
    }
  });

  // ── Negative controls ──

  it("still lifts a locked read-modify-write that DOES change the value", () => {
    // The 3qrl population — 24 of the 27 locked instructions in each x64 binary
    // — must be untouched. A source of 1 is not the identity element.
    const code = run(
      seq(0x401000, [
        ["lock or", "dword ptr [rbx], 1"],
        ["lock add", "dword ptr [rcx], r9d"],
        ["ret"],
      ]),
      true,
    );

    expect(code).not.toContain("unlifted");
    expect(code).toContain("*(int32_t*)(rbx)");
    expect(code).toContain("r9d");
  });

  it("does NOT claim an UNLOCKED or [mem], 0 as a barrier", () => {
    // The prefix is required as well. An unlocked `or [mem], 0` is a genuinely
    // dead store, and deleting one is a different judgement from this; 0 occur
    // over memory in the corpus, so the restriction costs nothing measurable.
    const code = run(seq(0x401000, [["or", "byte ptr [rsp], 0"], ["ret"]]), true);
    expect(code).not.toContain("unlifted");
  });

  it("does NOT claim a locked and <mem>, <all ones> as a barrier", () => {
    // Refused on measured evidence: `and`'s identity element is width-dependent,
    // and a text-level "all ones" reading misfires on real instructions here —
    // `and <reg>, 0xff` / `0xffff` (PE32) and `and <reg>, 0xfff` (x64) are
    // truncations. A misfire in the admitting direction deletes a real store.
    for (const src of ["0xff", "-1", "0xffffffff"]) {
      const code = run(seq(0x401000, [["lock and", `byte ptr [rsp], ${src}`], ["ret"]]), true);
      expect(code).not.toContain("unlifted");
    }
  });

  it("does NOT claim a locked RMW whose destination is a REGISTER", () => {
    // `lock` requires a memory operand, so this encoding does not exist; the
    // dest test is what keeps the rule about instructions that can.
    const code = run(seq(0x401000, [["lock or", "eax, 0"], ["ret"]]), true);
    expect(code).not.toContain("unlifted");
  });
});

/**
 * `bt <reg>, <imm> / jb` tests one bit, and the guard says which.
 *
 * `bt` is in `PARTIAL_FLAG_WRITERS`, so `flagEffect` clobbered on it and the Jcc
 * reading its CF was left unrecovered — 34 sites across the four corpus
 * binaries, every one of them in an MSVC `_bittest`-style flag check where the
 * neighbouring bits were tested with `test r11b, 1` and read perfectly well.
 * The blocker was literal: `bt` fell to the `raw` fallback, so the emitted C
 * carried `/* unlifted: bt r11d, 0xa *\/;` and nothing named the value
 * (peek-a-bin-frt8).
 *
 * **`bt` is a compare over one bit, not a read-modify-write**, and modelling it
 * as either of the existing kinds would be wrong. It writes NO value: the bit
 * base is unmodified, so there is no "read the destination after it ran" step —
 * `FlagOwnerResult`'s whole premise — and the condition is an expression over
 * the operand as written. Hence a third owner kind, `bittest`, and a `RegState`
 * flag op of the same name whose `getCondition` arm answers **only** the
 * CF-reading Jccs.
 *
 * ZF is where that restriction earns its keep. Intel: "The CF flag contains the
 * value of the selected bit. The ZF flag is **unaffected**." So a `je` after a
 * `bt` genuinely branches on an older instruction's ZF, and answering it from
 * the bit would be a wrong test rather than a missing one — the exact opposite
 * of `test`, which pins OF and CF to 0 and therefore answers strictly MORE Jcc
 * forms than a result owner (peek-a-bin-92yy). The two look parallel and are not.
 */
describe("decompileFunction — a bt names the bit its jcc tests", () => {
  /** The emitted guards, or ["<unrecovered>"] where the condition was admitted. */
  function guardTexts(code: string): string[] {
    return guardConditions(code).map((c) => (/__unrecovered_\d+/.test(c) ? "<unrecovered>" : c));
  }

  /** t64.exe 0x140003BB5, the bead's own witness: `bt r11d, 0xa / jb`. */
  function btThen(jcc: string, ops = "r11d, 0xa"): string {
    return run(
      seq(0x401000, [
        ["bt", ops],
        [jcc, "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );
  }

  it("spells jb as the selected bit being set", () => {
    expect(guardTexts(btThen("jb"))).toEqual(["(r11d >> 0xA & 1) != 0"]);
  });

  it("spells jae as the selected bit being clear", () => {
    expect(guardTexts(btThen("jae"))).toEqual(["(r11d >> 0xA & 1) == 0"]);
  });

  it("emits no unlifted comment for the bt it now models", () => {
    // `bt` writes no value, so like `cmp` and `test` it contributes no
    // statement at all — the flags reach the page as the branch's condition.
    expect(btThen("jb")).not.toContain("unlifted");
  });

  it("reduces the bit offset modulo the operand size, as the machine does", () => {
    expect(guardTexts(btThen("jb", "eax, 0x21"))).toEqual(["(eax >> 1 & 1) != 0"]);
  });

  // ── Negative controls: the Jcc forms and operand forms that stay refused ──

  it("refuses a ZF-reading jcc after a bt, because bt leaves ZF alone", () => {
    // The single most important assertion here. `je` after a `bt` reads an older
    // instruction's ZF, which this whole-flags model cannot name — so an
    // admitted gap is the honest answer and a bit test would be a wrong one.
    expect(guardTexts(btThen("je"))).toEqual(["<unrecovered>"]);
    expect(guardTexts(btThen("jne"))).toEqual(["<unrecovered>"]);
    expect(guardTexts(btThen("jg"))).toEqual(["<unrecovered>"]);
  });

  it("refuses a memory bit base, whose offset can address outside the operand", () => {
    // t32.exe 0x40B678 and w32.exe 0x40A3A8 are exactly this — MSVC's
    // `_bittest` on a stack temporary — and it is why bucket 1 recovers nothing
    // on the PE32 pair. With a memory bit base the offset indexes a bit string,
    // so `(*(uint32_t*)esp >> eax) & 1` is right only while `eax < 32`, which
    // nothing proves. The instruction keeps its verbatim comment.
    const code = run(
      seq(0x401000, [
        ["bt", "dword ptr [esp], eax"],
        ["jae", "0x401018"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
    );

    expect(code).toContain("unlifted: bt dword ptr [esp], eax");
    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("refuses a register bit offset", () => {
    const code = btThen("jb", "eax, ecx");
    expect(code).toContain("unlifted: bt eax, ecx");
    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("keeps bts/btr/btc refused — their CF is the bit BEFORE the write", () => {
    // `bts` sets the bit and leaves CF holding its previous value, so nothing
    // readable after the instruction names what the Jcc tested. 54 `bts` and 10
    // `btr` sites on t64 stay unlifted, deliberately.
    for (const mn of ["bts", "btr", "btc"]) {
      const code = run(
        seq(0x401000, [
          [mn, "r13d, 0xf"],
          ["jb", "0x401018"],
          ["mov", "eax, 1"],
          ["ret"],
          ["mov", "eax, 2"],
          ["ret"],
        ]),
        true,
      );
      expect(code, mn).toContain(`unlifted: ${mn} r13d, 0xf`);
      expect(guardTexts(code), mn).toEqual(["<unrecovered>"]);
    }
  });

  it("refuses a bt whose bit base a later instruction overwrote", () => {
    // `spoils`, over the one register there is to watch. The block's statements
    // are emitted above the `if`, so a guard naming `r11d` here would read the
    // value the `mov` put there rather than the bits that were tested.
    const code = run(
      seq(0x401000, [
        ["bt", "r11d, 0xa"],
        ["mov", "r11d, edx"],
        ["jb", "0x40101c"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("refuses a bt in a block that also holds a cmp", () => {
    // Refusal 3 in `branchFor`, applied to the new arm for the same reason it
    // applies to a result: `corpus/staleGuards.ts` reads ANY condition emitted
    // at such a jcc as the superseded one, and that gate is at 0.
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["bt", "r11d, 0xa"],
        ["jb", "0x40101c"],
        ["mov", "eax, 1"],
        ["ret"],
        ["mov", "eax, 2"],
        ["ret"],
      ]),
      true,
    );

    expect(guardTexts(code)).toEqual(["<unrecovered>"]);
  });

  it("does not leave an earlier compare standing across a refused bt", () => {
    // The clear `liftBlock`'s `bt` case has to make by hand. `bt` is in
    // `FLAG_MODELLED`, which suppresses the deferred clear at the top of the
    // loop, so a form `parseBitTest` refuses must clear the flags itself — and
    // the reader that would otherwise see the stale `cmp` is `setcc`, not the
    // Jcc: `branchFor` asks `blockFlagOwner`, whose own forward walk clobbers on
    // the refused `bt` in any case, while `setne` reads `regState` directly.
    // Without the clear this emits `dl = (eax != 5)`, a value the machine does
    // not compute — peek-a-bin-jitf one mnemonic further on.
    const code = run(
      seq(0x401000, [
        ["cmp", "eax, 5"],
        ["bt", "dword ptr [esp], edx"],
        ["setne", "dl"],
        // A reader for DL, or DCE deletes the `setne` and the whole question
        // with it — which is itself worth knowing about this shape.
        ["movzx", "eax, dl"],
        ["ret"],
      ]),
    );

    expect(code).not.toContain("eax != 5");
    expect(code).toMatch(/__unrecovered_\d+ \/\* jne \*\//);
  });
});

/**
 * `mov <r32>, <same r32>` on x64 is a ZERO-EXTENSION, not a no-op
 * (peek-a-bin-tez6).
 *
 * Both directions are pinned because one rule has to be true of both: the x64
 * sites must state the truncation, and the 173 + 170 PE32 hot-patch pads must
 * stay exactly as they were.
 */
describe("a 32-bit self-move", () => {
  it("states the zero-extension it performs on x64", () => {
    // t64.exe 0x140002BD6, the site whose value reaches arithmetic: a call
    // returns in EAX, `mov eax, eax` clears RAX's high half, and `sub rbp, rax`
    // two bytes later reads all 64 bits. Lifted as a plain `assign rax = rax`
    // this is structurally a copy, so `copyPropagation` deletes it and RBP is
    // decremented by the UNTRUNCATED value — a wrong value in C that compiles.
    const code = run(
      seq(0x140001000, [
        ["call", "0x140008804"],
        ["mov", "eax, eax"],
        ["sub", "rbp, rax"],
        ["mov", "rax, rbp"],
        ["ret"],
      ]),
      true,
    );

    // The mask has to SURVIVE `foldExpr` as well as `copyPropagation`:
    // `x & 0xFFFFFFFF` is stripped only when the left operand is no wider than
    // the mask (peek-a-bin-6hw), so the 64-bit destination is what keeps it on
    // the page. Where the truncated value has a single reader `foldBlock`
    // inlines it into that reader, so the mask is asserted at the subtraction
    // rather than as a statement of its own.
    expect(code).toMatch(/rbp - \(rax & 0xFFFFFFFF\)/);
  });

  it("brings back a guarded arm whose only content is the self-move", () => {
    // t64.exe 0x14000523F: `bt r12d, 0xc / jb <skip> / mov r8d, r8d`, where the
    // self-move is the ENTIRE arm. With nothing lifted for it the arm is empty,
    // `cleanup.ts` drops the `if`, and the test the machine makes leaves the
    // output. R8 is read at 64 bits below, which is what makes it matter.
    const code = run(
      seq(0x140001000, [
        ["bt", "r12d, 0xc"],
        ["jb", "0x140001010"],
        ["mov", "r8d, r8d"],
        ["mov", "rax, r8"],
        ["ret"],
      ]),
      true,
    );

    expect(code).toMatch(/rax = r8 & 0xFFFFFFFF/);
    expect(code).toMatch(/r12d >> 0xC & 1/);
  });

  it("is left alone on PE32, where it is a true no-op", () => {
    // MSVC's hot-patch pad — 173 in t32.exe, 170 in w32.exe. A 32-bit image has
    // no register above the one being written, so nothing is cleared and there
    // is nothing to state. The two x86 binaries are this change's control.
    const code = run(seq(0x401000, [["mov", "edi, edi"], ["mov", "eax, edi"], ["ret"]]));

    expect(code).not.toContain("0xFFFFFFFF");
  });

  it("is left alone at byte, word and 64-bit width on x64", () => {
    // Only the 32-bit width zero-extends: a byte or word write leaves its
    // parent's upper bits untouched, and `mov rax, rax` writes what it read.
    // 0 occurrences of any of these three in the corpus, so this is the rule's
    // bound rather than a measured population.
    for (const operands of ["al, al", "ax, ax", "rax, rax"]) {
      const code = run(seq(0x140001000, [["mov", operands], ["ret"]]), true);
      expect(code).not.toContain("0xFFFFFFFF");
    }
  });
});

describe("a matched push/pop restores the value the machine saved", () => {
  /**
   * peek-a-bin-6f3v, reduced from `t32!sub_40D99A` — MSVC's SSE memset.
   *
   * `push edx` saves the remaining byte count, the loop reuses EDX as a scratch
   * and decrements it to zero, `pop edx` restores the count and the code below
   * reads it. Without the pairing the `pop` is no definition in SSA, so the read
   * binds to the loop's decremented scratch — which is 0 at loop exit.
   */
  it("reads the saved value after the restore, not the scratch the loop left", () => {
    const code = run(
      seq(0x401000, [
        ["push", "edx"],
        ["mov", "edx, ebx"],
        ["dec", "edx"],
        ["jne", "0x401008"],
        ["pop", "edx"],
        ["mov", "eax, edx"],
        ["ret"],
      ]),
    );
    // The whole body, because what matters is that the value read after the
    // loop is the one pushed BEFORE it. `stk_401000 = edx` / `edx = stk_401000`
    // is what `liftBlock` emits; here the region is reachable, so SSA sees it,
    // `copyPropagation` folds both copies away and `splitStaleReads` parks the
    // entry value in `edx_0` at the function's entry — which is the same value
    // and one statement fewer.
    expect(code).toBe(
      [
        "int sub_401000() {",
        "    edx_0 = edx;",
        "    edx = ebx;",
        "    do {",
        "        edx--;",
        "    } while (edx != 0);",
        "    return edx_0;",
        "}",
      ].join("\n"),
    );
    // The scratch the loop left is 0, and nothing reads it after the restore.
    expect(code).not.toMatch(/return edx;/);
  });

  /**
   * The `ret` half, from the same function at 0x40D9E7 / 0x40DA6F: memset
   * returns its destination pointer, saved on entry and popped into EAX. `pop`
   * pairs by DEPTH, so the restore into a different register still resolves.
   */
  it("returns the pointer a differently-named pop took off the stack", () => {
    const code = run(
      seq(0x401000, [
        ["push", "ecx"],
        ["mov", "ecx, 0"],
        ["mov", "eax, 1"],
        ["pop", "eax"],
        ["ret"],
      ]),
    );
    expect(code).toBe(["int sub_401000() {", "    return ecx;", "}"].join("\n"));
  });

  /**
   * The shape the corpus actually has, and the one where the slot survives to
   * the page. Both t32 sites sit in a region that follows a `ret` and that
   * nothing in the function branches to — MSVC's memset merged into its
   * neighbour by function detection — so `renameVariables` never reaches it,
   * there are no SSA versions there and no pass folds the two copies away. The
   * slot is then the only thing that can name the saved value at all.
   */
  it("names the slot outright in a region SSA never renames", () => {
    const code = run(
      seq(0x401000, [["ret"], ["push", "ecx"], ["mov", "ecx, 0"], ["pop", "eax"], ["ret"]]),
    );
    expect(code).toMatch(/stk_401004 = ecx;/);
    expect(code).toMatch(/return stk_401004;/);
  });

  /**
   * The other direction, and the reason this costs nothing where it recovers
   * nothing: a save/restore the emitted C already read correctly must not grow
   * two statements. `stk = ebx` is a copy, so `copyPropagation` deletes it and
   * rewrites the pop's readers to the pushed version; `ebx = ebx_0` is a copy
   * too and DCE takes the pair.
   */
  it("adds nothing to a save/restore whose register was never overwritten", () => {
    const code = run(
      seq(0x401000, [
        ["push", "ebx"],
        ["mov", "eax, 1"],
        ["pop", "ebx"],
        ["mov", "eax, ebx"],
        ["ret"],
      ]),
    );
    expect(code).not.toMatch(/stk_/);
    expect(code).toMatch(/return ebx/);
  });

  it("says nothing at a pop whose pairing the depth model refused", () => {
    // A `call` between the two: the callee may have popped the arguments, so
    // which push this `pop` takes is not a fact about the instruction stream.
    const code = run(
      seq(0x401000, [
        ["push", "ebx"],
        ["call", "0x408000"],
        ["mov", "ebx, 2"],
        ["pop", "ebx"],
        ["mov", "eax, ebx"],
        ["ret"],
      ]),
    );
    expect(code).not.toMatch(/stk_/);
  });
});
