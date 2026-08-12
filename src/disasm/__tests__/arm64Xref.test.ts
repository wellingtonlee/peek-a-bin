/**
 * peek-a-bin-erb — ARM64 cross-references.
 *
 * The instruction sequences below are Capstone's output on t64-arm.exe, with
 * the addresses kept: `adrp x8, #0x140024000` / `add x1, x8, #0x480` really
 * does reference the string "Fatal error in launcher: %s", and
 * `adrp x8, #0x14001d000` / `ldr x8, [x8, #0x98]` really is the IAT slot for
 * KERNEL32!ExitProcess.
 */

import { describe, expect, it } from "vitest";
import { buildArm64Xrefs } from "../arm64Xref";
import type { Instruction } from "../types";

const insn = (address: number, mnemonic: string, opStr: string): Instruction => ({
  address,
  mnemonic,
  opStr,
  size: 4,
  bytes: new Uint8Array(4),
});

describe("buildArm64Xrefs — string and import references", () => {
  it("finds a string reference the x86 grammar cannot see", () => {
    // Neither operand contains 0x140024480. It exists only as the sum.
    const insns = [
      insn(0x140002038, "adrp", "x8, #0x140024000"),
      insn(0x14000203c, "add", "x1, x8, #0x480"),
    ];

    expect(buildArm64Xrefs(insns, [0x140024480], []).stringXrefs).toEqual([
      [0x140024480, [0x14000203c]],
    ]);
  });

  it("finds an import reference through the adrp/ldr form", () => {
    const insns = [
      insn(0x140002048, "adrp", "x8, #0x14001d000"),
      insn(0x14000204c, "ldr", "x8, [x8, #0x98]"),
    ];

    expect(buildArm64Xrefs(insns, [], [0x14001d098]).importXrefs).toEqual([
      [0x14001d098, [0x14000204c]],
    ]);
  });

  it("attributes the reference to the completing instruction, not the adrp", () => {
    // The adrp alone names a 4 KiB page; putting the cursor there would point a
    // reader at an address no instruction actually uses.
    const [[, froms]] = buildArm64Xrefs(
      [insn(0x140002038, "adrp", "x8, #0x140024000"), insn(0x14000203c, "add", "x1, x8, #0x480")],
      [0x140024480],
      [],
    ).stringXrefs;

    expect(froms).toEqual([0x14000203c]);
  });

  it("collects several referrers of the same string", () => {
    const insns = [
      insn(0x140002038, "adrp", "x8, #0x140024000"),
      insn(0x14000203c, "add", "x1, x8, #0x480"),
      insn(0x1400020a0, "adrp", "x9, #0x140024000"),
      insn(0x1400020a4, "add", "x2, x9, #0x480"),
    ];

    expect(buildArm64Xrefs(insns, [0x140024480], []).stringXrefs).toEqual([
      [0x140024480, [0x14000203c, 0x1400020a4]],
    ]);
  });
});

describe("buildArm64Xrefs — data references", () => {
  it("records an address landing in a declared data section", () => {
    const insns = [
      insn(0x140003000, "adrp", "x8, #0x140024000"),
      insn(0x140003004, "add", "x0, x8, #0x100"),
    ];

    expect(
      buildArm64Xrefs(insns, [], [], undefined, [{ va: 0x140024000, size: 0x1000 }]).dataXrefs,
    ).toEqual([[0x140024100, [0x140003004]]]);
  });

  it("does not double-count a string or an import as a data reference", () => {
    const insns = [
      insn(0x140003000, "adrp", "x8, #0x140024000"),
      insn(0x140003004, "add", "x0, x8, #0x100"),
    ];

    expect(
      buildArm64Xrefs(insns, [0x140024100], [], undefined, [{ va: 0x140024000, size: 0x1000 }])
        .dataXrefs,
    ).toEqual([]);
  });

  it("records nothing when no data sections are declared", () => {
    const insns = [
      insn(0x140003000, "adrp", "x8, #0x140024000"),
      insn(0x140003004, "add", "x0, x8, #0x100"),
    ];

    expect(buildArm64Xrefs(insns, [], []).dataXrefs).toEqual([]);
  });
});

describe("buildArm64Xrefs — call graph", () => {
  const funcs: [number, number][] = [
    [0x140001000, 0x40],
    [0x140003160, 0x20],
  ];

  it("builds an edge from a direct bl between two known functions", () => {
    const insns = [insn(0x140001010, "bl", "#0x140003160")];

    expect(buildArm64Xrefs(insns, [], [], funcs).callGraph).toEqual([[0x140001000, [0x140003160]]]);
  });

  it("does not record a bl to an address that is not a known function", () => {
    const insns = [insn(0x140001010, "bl", "#0x140009999")];
    expect(buildArm64Xrefs(insns, [], [], funcs).callGraph).toEqual([]);
  });

  it("records no edge for an indirect blr, rather than guessing one", () => {
    // 262 of t64-arm.exe's calls are `blr xN`. Naming a callee for any of them
    // would be an invented edge in the call graph.
    const insns = [insn(0x140001010, "blr", "x2")];
    expect(buildArm64Xrefs(insns, [], [], funcs).callGraph).toEqual([]);
  });

  it("deduplicates repeated calls to the same callee", () => {
    const insns = [
      insn(0x140001010, "bl", "#0x140003160"),
      insn(0x140001014, "bl", "#0x140003160"),
    ];
    expect(buildArm64Xrefs(insns, [], [], funcs).callGraph).toEqual([[0x140001000, [0x140003160]]]);
  });

  it("records nothing without function bounds — a caller cannot be attributed", () => {
    expect(buildArm64Xrefs([insn(0x140001010, "bl", "#0x140003160")], [], []).callGraph).toEqual(
      [],
    );
  });
});

describe("buildArm64Xrefs — finds nothing in x86 instructions", () => {
  it("reports no reference for a rip-relative string load", () => {
    // The x86 builder resolves this one; running BOTH over the same image is
    // not the design — the caller picks by architecture. What matters is that
    // this one invents nothing when handed the wrong grammar.
    const insns = [insn(0x401000, "lea", "rax, [rip + 0x100]"), insn(0x401007, "call", "0x401100")];

    expect(buildArm64Xrefs(insns, [0x401107], [], [[0x401000, 0x20]])).toEqual({
      stringXrefs: [],
      importXrefs: [],
      callGraph: [],
      dataXrefs: [],
    });
  });
});
