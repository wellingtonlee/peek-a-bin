/**
 * Which stack-frame grammar an image gets — the one place that chooses.
 *
 * There are two, they share nothing, and that is the point. `stack.ts`'s
 * `analyzeStackFrame` is an x86 operand grammar that refuses every other
 * architecture outright (`peek-a-bin-56q`), and `arm64Frame.ts`'s
 * `analyzeArm64StackFrame` recovers an A64 frame from the linker's own `.pdata`
 * unwind record (`peek-a-bin-hof0`). Neither was widened to admit the other:
 * `analyzeStackFrame` still opens with `if (arch !== "x86") return null`, so a
 * future third machine type reaches an x86 grammar through neither this
 * function nor that one.
 *
 * THE `"unsupported"` ARM IS CHECKED FIRST AND THAT ORDER IS LOAD-BEARING. It is
 * the rule `workers/dispatch.ts` and `mcp/disasm.ts` already carry: an
 * architecture chain whose tail is a real grammar must eliminate the unknown
 * machine types before it tests for a known one, or a fourth `ImageArch` value
 * added later falls through to whichever grammar happens to be last. Here the
 * tail is x86's own refusal, so a fall-through would be caught — but writing the
 * order the other way would make that a property of the callee rather than of
 * this dispatch, and the next person to add an arm would not know which.
 *
 * This lives in its own module rather than in `stack.ts` for one mechanical
 * reason: `arm64Frame.ts` imports `stackVarKey` from `stack.ts`, so a dispatcher
 * there would close an import cycle. One declaration of slot identity is worth
 * more than one fewer file.
 *
 * THREE CALL SITES DELIBERATELY DO NOT COME THROUGH HERE, and they are all the
 * same site: `mcp/tools.ts`, `hooks/useDecompileTabs.ts` and
 * `llm/decompileForLLM.ts` each build a `StackFrame` only to hand it to
 * `decompileFunction`, and the decompiler refuses ARM64 above them — in
 * `mcp/tools.ts` before the address is even resolved, and in
 * `workers/dispatch.ts` for the browser. Routing them here would be inert at
 * best; at worst, if that refusal ever moved, it would hand an x86 IR lifter a
 * frame recovered under another architecture's rules. They call
 * `analyzeStackFrame` directly and are x86-only by construction. The one caller
 * here is `DisassemblyView`'s detail panel, which is the only surface an A64
 * frame can currently reach.
 */

import type { PEFile, RuntimeFunction } from "../pe/types";
import type { ImageArch } from "./arch";
import { analyzeArm64StackFrame } from "./arm64Frame";
import { analyzeStackFrame } from "./stack";
import type { DisasmFunction, Instruction, StackFrame } from "./types";

/**
 * What the ARM64 grammar needs out of the PE: the unwind table and the base
 * that turns its RVAs into the addresses a `DisasmFunction` carries.
 *
 * A context object rather than the `PEFile` itself so a test can build one in a
 * line, and `arm64UnwindContext` below so the extraction is written once rather
 * than at each of the five call sites — the shape `sections.ts`, `ripRelative.ts`
 * and `funcInsns.ts` each exist to prevent.
 */
export interface Arm64UnwindContext {
  runtimeFunctions: readonly RuntimeFunction[] | undefined;
  imageBase: number;
}

/** The unwind context of a parsed image. */
export function arm64UnwindContext(pe: PEFile): Arm64UnwindContext {
  return {
    runtimeFunctions: pe.runtimeFunctions,
    imageBase: pe.optionalHeader.imageBase,
  };
}

/**
 * The stack frame of one function, under whichever grammar its architecture has.
 *
 * `unwind` is REQUIRED AND POSITIONAL, ahead of the optional instruction map,
 * for the reason `arch` itself is (`peek-a-bin-56q`): a call site that has not
 * been threaded must fail to compile rather than silently answer null for every
 * ARM64 function, which is indistinguishable from the pre-recovery behaviour and
 * so would never be noticed. Pass `undefined` deliberately where there is no
 * image to ask — that is a statement, not an omission.
 */
export function stackFrameFor(
  func: DisasmFunction,
  instructions: Instruction[],
  arch: ImageArch,
  is64: boolean,
  unwind: Arm64UnwindContext | undefined,
  funcInsnMap?: Map<number, Instruction[]>,
): StackFrame | null {
  if (arch === "unsupported") return null;
  if (arch === "arm64") {
    if (!unwind) return null;
    return analyzeArm64StackFrame(
      func,
      instructions,
      unwind.runtimeFunctions,
      unwind.imageBase,
      funcInsnMap,
    );
  }
  return analyzeStackFrame(func, instructions, arch, is64, funcInsnMap);
}
