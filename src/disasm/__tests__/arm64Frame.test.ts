/**
 * The ARM64 stack-frame grammar.
 *
 * Two halves with two very different footings, and the tests are labelled
 * accordingly. `analyzeArm64StackFrame`'s frame comes from `.pdata` and is
 * cross-checked against an independently written reading of the prologue in
 * `corpus/arm64.ts` — 716 of 716 frame pointers on the real binaries. The var
 * list comes from the instruction stream and **has no oracle at all**, so these
 * tests are its only verification; where a rule has no corpus population it says
 * so and is a BOUND rather than a measured saving.
 */
import { describe, expect, it } from "vitest";
import { analyzeArm64StackFrame, collectArm64StackVars } from "../arm64Frame";
import type { DisasmFunction, Instruction, RuntimeFunctionLike } from "./arm64FrameFixtures";
import { body, func, record } from "./arm64FrameFixtures";

/** Slot keys, in frame order. */
function keys(insns: Instruction[]): string[] {
  return collectArm64StackVars(insns).map((v) => v.key ?? "");
}

describe("A64 frame-relative operands", () => {
  it("records a constant displacement off x29 and off sp, keyed apart", () => {
    expect(keys(body(["ldr", "x0, [x29, #0x10]"], ["ldr", "x1, [sp, #0x10]"]))).toEqual([
      "bp:16",
      "sp:16",
    ]);
  });

  it("records a bare [sp] and a bare [x29] at offset 0", () => {
    expect(keys(body(["str", "x0, [sp]"], ["str", "x1, [x29]"]))).toEqual(["bp:0", "sp:0"]);
  });

  it("does NOT record a pre-index writeback — that is the prologue allocating", () => {
    // `stp x19, x20, [sp, #-0x50]!` moves the stack pointer; the displacement is
    // an allocation size, not a slot. Treating it as one reports 683 and 617
    // spurious negative-offset "variables" per corpus binary.
    expect(keys(body(["stp", "x19, x20, [sp, #-0x50]!"]))).toEqual([]);
    expect(keys(body(["str", "x19, [sp, #-0x10]!"]))).toEqual([]);
  });

  it("does NOT record a register offset — there is no constant slot to name", () => {
    expect(keys(body(["ldr", "x0, [sp, x8]"], ["ldr", "x1, [x29, w9, sxtw #3]"]))).toEqual([]);
  });

  it("does NOT record an operand based on any other register", () => {
    // A copy of the frame pointer is followed on x86 and deliberately is not
    // here; refusing leaves a plain deref, which is the benign direction.
    expect(keys(body(["ldr", "x0, [x19, #0x10]"], ["ldr", "x1, [x8]"]))).toEqual([]);
  });

  it("records BOTH slots an ldp/stp pair touches", () => {
    // `stp x19, x20, [sp, #0x10]` writes +0x10 and +0x18. Reporting one 8-byte
    // slot leaves the second unnamed, so a later single access to it looks like
    // a different variable.
    expect(keys(body(["stp", "x19, x20, [sp, #0x10]"]))).toEqual(["sp:16", "sp:24"]);
    expect(keys(body(["ldp", "w0, w1, [sp, #8]"]))).toEqual(["sp:8", "sp:12"]);
  });

  it("takes the width from the mnemonic suffix where there is one, not the register", () => {
    // `ldrb w8, [sp, #4]` reads ONE byte through a four-byte register; taking
    // the register's width would claim the slot is four bytes wide.
    const vars = collectArm64StackVars(
      body(["ldrb", "w8, [sp, #4]"], ["ldrh", "w9, [sp, #8]"], ["ldrsw", "x10, [sp, #0x10]"]),
    );
    expect(vars.map((v) => v.size)).toEqual([1, 2, 4]);
  });

  it("takes the width from the register where the mnemonic says nothing", () => {
    const vars = collectArm64StackVars(
      body(["ldr", "w0, [sp, #0]"], ["ldr", "x1, [sp, #8]"], ["ldr", "q2, [sp, #0x10]"]),
    );
    expect(vars.map((v) => v.size)).toEqual([4, 8, 16]);
  });

  it("counts repeated accesses and keeps the WIDEST width seen", () => {
    const vars = collectArm64StackVars(
      body(["ldrb", "w0, [sp, #8]"], ["ldr", "x1, [sp, #8]"], ["str", "x2, [sp, #8]"]),
    );
    expect(vars).toHaveLength(1);
    expect(vars[0].accessCount).toBe(3);
    expect(vars[0].size).toBe(8);
  });

  it("records a negative x29 offset — a BOUND, it occurs 0 times in either binary", () => {
    // MSVC lays the A64 frame out upward from an x29 at its bottom, so every one
    // of the 1906 and 1669 recovered slots is non-negative. The branch exists so
    // that a toolchain which does otherwise is described rather than dropped.
    const vars = collectArm64StackVars(body(["ldr", "x0, [x29, #-8]"]));
    expect(vars[0].key).toBe("bp:-8");
    expect(vars[0].offset).toBe(8);
    expect(vars[0].signedOffset).toBe(-8);
  });

  it("ignores an instruction that is not a load or a store", () => {
    expect(keys(body(["add", "x0, sp, #0x10"], ["mov", "x29, sp"]))).toEqual([]);
  });

  it("names every slot var_, never arg_", () => {
    // There are 0 accesses at or above frameDelta across all 800 corpus
    // functions, so AAPCS64 stack arguments have no population here and a
    // positional rule would gate on nothing. Naming a slot `arg_` would be a
    // claim about a calling convention nothing has checked.
    const vars = collectArm64StackVars(body(["ldr", "x0, [x29, #0x400]"]));
    expect(vars.map((v) => v.name)).toEqual(["var_400"]);
  });

  it("suffixes the base when two slots share an operand offset", () => {
    const vars = collectArm64StackVars(
      body(["ldr", "x0, [x29, #0x10]"], ["ldr", "x1, [sp, #0x10]"]),
    );
    expect(vars.map((v) => v.name)).toEqual(["var_10", "var_10_sp"]);
  });
});

describe("the frame comes from .pdata and only from .pdata", () => {
  const insns = body(["ldr", "x0, [sp, #8]"]);
  const fn: DisasmFunction = func(0x10);

  it("reports the record's delta and size", () => {
    const frame = analyzeArm64StackFrame(
      fn,
      insns,
      [record({ begin: 0x1000, delta: 0x20, size: 0x60 })],
      0,
    );
    expect(frame?.frameDelta).toBe(0x20);
    expect(frame?.frameSize).toBe(0x60);
    expect(frame?.vars.map((v) => v.key)).toEqual(["sp:8"]);
  });

  it("leaves frameEstablishedAt null, because its one consumer refuses A64", () => {
    // `promote.ts`'s `frameRegisterAliases` is the only reader of that field and
    // it is decompiler machinery. Reading the `mov x29, sp` out of the prologue
    // to fill it would be an unverifiable claim bought for nothing.
    const frame = analyzeArm64StackFrame(fn, insns, [record({ begin: 0x1000 })], 0);
    expect(frame?.frameEstablishedAt).toBeNull();
  });

  it("refuses a function the table does not name — 22% of those detected", () => {
    // 419 of 539 and 381 of 494 detected functions have a record. The rest are
    // `bl` targets and jump-table cases the linker emitted no unwind data for,
    // and recovering a frame for one would mean reading the prologue, which is
    // the heuristic this module exists to avoid.
    expect(analyzeArm64StackFrame(fn, insns, [record({ begin: 0x2000 })], 0)).toBeNull();
    expect(analyzeArm64StackFrame(fn, insns, [], 0)).toBeNull();
    expect(analyzeArm64StackFrame(fn, insns, undefined, 0)).toBeNull();
  });

  it("matches a record by EXACT begin, never by containment", () => {
    // An address inside another function's extent belongs to that function's
    // frame; handing it out here would describe the wrong frame confidently.
    const enclosing = record({ begin: 0x0f00, end: 0x2000, delta: 0x40 });
    expect(analyzeArm64StackFrame(fn, insns, [enclosing], 0)).toBeNull();
  });

  it("refuses a record whose unwind data did not decode", () => {
    const undecoded: RuntimeFunctionLike = {
      beginAddress: 0x1000,
      endAddress: 0x1010,
      unwindInfoAddress: 0,
    };
    expect(analyzeArm64StackFrame(fn, insns, [undecoded], 0)).toBeNull();
  });

  it("resolves the record's RVA against the image base", () => {
    const frame = analyzeArm64StackFrame(
      { name: "sub_140001000", address: 0x140001000, size: 0x10 },
      body(["ldr", "x0, [sp, #8]"], undefined, 0x140001000),
      [record({ begin: 0x1000, delta: 0x30 })],
      0x140000000,
    );
    expect(frame?.frameDelta).toBe(0x30);
  });

  it("reports a frame with no pointer as a size and a null delta", () => {
    const frame = analyzeArm64StackFrame(
      fn,
      insns,
      [record({ begin: 0x1000, delta: null, size: 0x10 })],
      0,
    );
    expect(frame?.frameDelta).toBeNull();
    expect(frame?.frameSize).toBe(0x10);
  });
});
