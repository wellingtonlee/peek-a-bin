/**
 * The architecture dispatch for stack-frame recovery.
 *
 * There are two grammars and this is the one place that chooses between them.
 * What these tests pin is the CHOICE, not either grammar: that an unsupported
 * machine type is eliminated before a known one is tested for, that the ARM64
 * arm refuses without its unwind context rather than falling through, and that
 * the x86 arm is reached unchanged and ignores that context entirely.
 */
import { describe, expect, it } from "vitest";
import type { PEFile } from "../../pe/types";
import { arm64UnwindContext, stackFrameFor } from "../stackFrame";
import { body, func, record } from "./arm64FrameFixtures";

const A64_INSNS = body(["ldr", "x0, [sp, #8]"]);
const A64_CTX = {
  runtimeFunctions: [record({ begin: 0x1000, delta: 0x20, size: 0x60 })],
  imageBase: 0,
};
const FN = func(0x10);

describe("stackFrameFor", () => {
  it("recovers an ARM64 frame from the unwind context", () => {
    const frame = stackFrameFor(FN, A64_INSNS, "arm64", true, A64_CTX);
    expect(frame?.frameDelta).toBe(0x20);
    expect(frame?.frameSize).toBe(0x60);
  });

  it("refuses ARM64 with no unwind context, rather than falling through to x86", () => {
    // Falling through would run an x86 operand grammar over A64 text: `rbp` and
    // `rsp` do not occur there, so it would answer null for the frame and an
    // empty list for the vars — the shape `peek-a-bin-56q` removed.
    expect(stackFrameFor(FN, A64_INSNS, "arm64", true, undefined)).toBeNull();
  });

  it("refuses an unsupported machine type EVEN WITH an ARM64 context in hand", () => {
    // The `"unsupported"` arm is checked FIRST. `ImageArch` is a widening of
    // `TargetArch`, so ARM32, IA-64 and RISC-V all arrive here as
    // `"unsupported"`, and an arm order that tested for `"arm64"` first would
    // still be correct only because x86's own refusal catches the remainder —
    // making the guarantee a property of the callee rather than of this dispatch.
    expect(stackFrameFor(FN, A64_INSNS, "unsupported", true, A64_CTX)).toBeNull();
  });

  it("reaches the x86 grammar and ignores the ARM64 context", () => {
    // The x86 answer must be exactly what `analyzeStackFrame` gives on its own,
    // context or no context: the two grammars share nothing.
    const x86 = body(["push", "rbp"], ["mov", "rbp, rsp"], ["mov", "eax, [rbp - 8]"]);
    const withCtx = stackFrameFor(func(0xc), x86, "x86", true, A64_CTX);
    const without = stackFrameFor(func(0xc), x86, "x86", true, undefined);
    expect(withCtx?.vars.map((v) => v.key)).toEqual(["bp:-8"]);
    expect(withCtx).toEqual(without);
    // …and it is the x86 frame, not the record's: the ARM64 context claims a
    // 0x60 frame at delta 0x20 and neither number appears.
    expect(withCtx?.frameSize).not.toBe(0x60);
    expect(withCtx?.frameDelta).not.toBe(0x20);
  });
});

describe("arm64UnwindContext", () => {
  it("takes the unwind table and the base that turns its RVAs into addresses", () => {
    const pe = {
      runtimeFunctions: [record({ begin: 0x1000 })],
      optionalHeader: { imageBase: 0x140000000 },
    } as unknown as PEFile;
    const ctx = arm64UnwindContext(pe);
    expect(ctx.imageBase).toBe(0x140000000);
    expect(ctx.runtimeFunctions).toHaveLength(1);
  });

  it("carries an absent table through as undefined rather than an empty list", () => {
    // "The image has no `.pdata`" and "the table is empty" reach the same
    // refusal, but only the first is a statement about the file.
    const pe = { optionalHeader: { imageBase: 0 } } as unknown as PEFile;
    expect(arm64UnwindContext(pe).runtimeFunctions).toBeUndefined();
  });
});
