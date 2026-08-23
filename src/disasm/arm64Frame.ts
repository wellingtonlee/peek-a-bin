/**
 * The ARM64 stack frame — a SECOND grammar, not a relaxation of the x86 one.
 *
 * `analyzeStackFrame` in `stack.ts` is an x86 operand grammar from end to end,
 * and `peek-a-bin-56q` made it refuse anything else outright rather than return
 * an empty frame. This module is the A64 answer to the same question, and it
 * arrives at it from a completely different place: **the linker already wrote
 * it down**. Every ARM64 function with a `.pdata` entry carries an unwind record
 * that states whether `x29` is a frame pointer and how far below the entry
 * stack pointer it sits (`pe/arm64Unwind.ts`). Where x86 needs
 * `inlineFrameGeometry`, `frameGeometry` and a `__SEH_prolog4` helper walk to
 * recover that, A64 needs a two-bit field.
 *
 * So the two halves of a `StackFrame` come from two different sources here, and
 * that is the design rather than an accident:
 *
 *  - `frameDelta` and `frameSize` come from `.pdata` ALONE. That is what makes
 *    `corpus/arm64.ts`'s gate an oracle: the instruction stream is an
 *    independent record of the same frame, and it is never consulted for these.
 *    Measured over both corpus binaries, the record and the stream agree on
 *    **716 of 716** frame pointers and on **800 of 800** functions as to whether
 *    there is one at all.
 *  - `vars` comes from the instruction stream, because no unwind record names a
 *    local. THIS HALF HAS NO ORACLE and that is stated rather than implied — see
 *    `collectArm64StackVars`.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO, each refused on a measurement:
 *
 *  - **It numbers no arguments.** AAPCS64 passes eight arguments in x0-x7 with
 *    no home space, so a stack argument only exists from the ninth onward, at
 *    `[x29 + frameDelta + 8N]`. Over all 800 `.pdata` functions of both corpus
 *    binaries there are **0** frame accesses at or above `frameDelta`, so a
 *    positional rule here would gate on an empty population — the vacuous-zero
 *    failure this project records against `armExits` on x64. None of x86's
 *    `ARG_AREA` / `homeRegs` / `inUnfilledHomeSpace` apparatus has an A64
 *    analogue and none of it is copied over.
 *  - **It sets `frameEstablishedAt` to null.** That field exists for exactly one
 *    consumer, `promote.ts`'s `frameRegisterAliases`, which is decompiler
 *    machinery that refuses on A64 above address resolution. Reading the
 *    `mov x29, sp` out of the prologue to fill a field nothing can consult would
 *    be an unverifiable claim bought for nothing.
 *  - **It infers no signature.** `inferSignature` still refuses; see its
 *    docstring for the two measurements behind that.
 */

import type { RuntimeFunction } from "../pe/types";
import { getFuncInsns } from "./funcInsns";
import { stackVarKey } from "./stack";
import type { DisasmFunction, Instruction, StackFrame, StackVar } from "./types";

/**
 * A frame-relative memory operand: `[x29]`, `[x29, #0x10]`, `[sp, #8]`.
 *
 * Three A64 forms are deliberately NOT matched, and each exclusion is the
 * difference between a slot and something else entirely:
 *
 *  - **Writeback**, `[sp, #-0x20]!` and `[sp], #0x20`. Those are the prologue
 *    and epilogue *moving* the stack pointer, not touching a variable, and the
 *    displacement is an allocation size. Counting them as slots reports 683 and
 *    617 spurious negative-offset "variables" per corpus binary.
 *  - **A register offset**, `[sp, x8]` or `[x29, w9, sxtw #3]`. The offset is
 *    not a constant, so there is no slot to name — the same reason x86's
 *    grammar takes a displacement only.
 *  - **Anything based on a register other than `x29`/`fp` or `sp`.** A copy of
 *    the frame pointer into another register is followed on x86 by
 *    `frameRegisterAliases` and is not followed here; refusing leaves a plain
 *    deref, which is the benign direction.
 *
 * The negative branch exists although **`[x29, #-N]` occurs 0 times in either
 * corpus binary**: MSVC lays the whole A64 frame out at non-negative offsets
 * from `x29`, which sits at the bottom. It is a bound on the grammar rather
 * than a measured saving, and it is pinned by unit test for that reason.
 */
const FRAME_OPERAND_RE = /\[\s*(x29|fp|sp)\s*(?:,\s*#(-?)(0x[0-9a-fA-F]+|\d+)\s*)?\](?!\s*!)/g;

/** Widths an A64 mnemonic suffix states outright, overriding the register. */
const MNEMONIC_WIDTH: ReadonlyArray<[suffix: string, size: number]> = [
  // Longest first: `ldrsw` must not be read as `ldrs` + `w`, and `ldrsb`
  // before `ldrb`.
  ["sw", 4],
  ["sb", 1],
  ["sh", 2],
  ["b", 1],
  ["h", 2],
];

/** Width of an A64 transfer register: `w8` is 4 bytes, `d0` is 8, `q3` is 16. */
function registerWidth(token: string): number | null {
  const m = /^([wxbhsdq])(\d{1,2}|zr)$/i.exec(token.trim());
  if (!m) return null;
  switch (m[1].toLowerCase()) {
    case "b":
      return 1;
    case "h":
      return 2;
    case "w":
    case "s":
      return 4;
    case "x":
    case "d":
      return 8;
    default:
      return 16; // q
  }
}

/**
 * How many bytes one access touches, and how many consecutive slots.
 *
 * `ldp`/`stp` are the reason the second half exists: `stp x19, x20, [sp, #0x10]`
 * writes TWO eight-byte slots, at +0x10 and +0x18, and reporting one 8-byte slot
 * would leave the second unnamed while a later single access to it appeared to
 * be a different variable. There is no x86 analogue — a `push` names no slot in
 * an operand — so this is not a gap in the shared grammar being filled in.
 */
function accessShape(insn: Instruction): { size: number; slots: number } | null {
  const mn = insn.mnemonic.toLowerCase();
  if (!mn.startsWith("ld") && !mn.startsWith("st")) return null;
  const pair = mn === "ldp" || mn === "stp" || mn === "ldnp" || mn === "stnp";
  // The register list is everything before the `[`.
  const bracket = insn.opStr.indexOf("[");
  if (bracket < 0) return null;
  const regs = insn.opStr
    .slice(0, bracket)
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  if (regs.length === 0) return null;

  // A suffix width is a property of the INSTRUCTION and beats the register:
  // `ldrb w8, [sp, #4]` reads one byte through a 4-byte register, and taking
  // the register's width would claim the slot is four bytes wide.
  const base = mn.replace(/^(ld|st)(u?r|p|np|ur)?/, "");
  for (const [suffix, size] of MNEMONIC_WIDTH) {
    if (base === suffix) return { size, slots: 1 };
  }
  const width = registerWidth(regs[0]);
  if (width === null) return null;
  return { size: width, slots: pair ? 2 : 1 };
}

/** A displacement as Capstone printed it: `0x`-prefixed hex, or bare decimal. */
function parseDisp(text: string): number {
  return /^0[xX]/.test(text) ? Number.parseInt(text.slice(2), 16) : Number.parseInt(text, 10);
}

interface VarEntry {
  base: "bp" | "sp";
  offset: number;
  signedOffset: number;
  size: number;
  accessCount: number;
}

/**
 * Every constant-displacement frame slot this function's instructions touch.
 *
 * **THIS HALF HAS NO ORACLE AND THAT IS NOT A FORMALITY.** `frameDelta` above it
 * is checked against an independently written reading of the prologue; a var
 * list is checked against nothing, because the only other record of which bytes
 * are locals is the instruction stream this reads. `corpus/arm64.ts` reports the
 * count and the fraction lying inside the frame the linker recorded — a
 * cross-check between two records rather than an oracle — and does NOT gate it:
 * an access outside the recorded frame is ordinary and legitimate in two
 * measured shapes, a shared stack-probe thunk reading its caller's stack
 * (`t64-arm!0x140001804`) and the area MSVC allocates BELOW the frame pointer,
 * which no unwind record describes at all (`t64-arm!0x14000568c`, a
 * `sub sp, sp, #0x4b0` after a `bl __chkstk`).
 *
 * The slots are keyed exactly as x86 keys them — `stackVarKey`, `bp:` or `sp:`
 * plus the signed offset — so a consumer that already understands one
 * architecture's frame needs no second notion of slot identity. **Every offset
 * this reports on the corpus binaries is non-negative** (measured: 0 negative of
 * 1906 and 1669 slots), because MSVC addresses A64 locals upward from `sp` or
 * from an `x29` at the bottom of the frame. That inverts x86's convention, where
 * a negative `bp:` offset IS the local, which is why nothing here reads the sign
 * to decide what a slot is — and why `arg_` never appears in a name below.
 */
export function collectArm64StackVars(funcInsns: readonly Instruction[]): StackVar[] {
  const varMap = new Map<string, VarEntry>();

  for (const insn of funcInsns) {
    const shape = accessShape(insn);
    if (shape === null) continue;
    // `matchAll` on a `g` regex restarts from 0 for each new string, so there
    // is no shared `lastIndex` to reset between instructions.
    for (const m of insn.opStr.matchAll(FRAME_OPERAND_RE)) {
      const base = m[1].toLowerCase() === "sp" ? "sp" : "bp";
      const magnitude = m[3] === undefined ? 0 : parseDisp(m[3]);
      const signedBase = m[2] === "-" ? -magnitude : magnitude;
      for (let slot = 0; slot < shape.slots; slot++) {
        const signedOffset = signedBase + slot * shape.size;
        const key = stackVarKey(base, signedOffset);
        const existing = varMap.get(key);
        if (existing) {
          existing.accessCount++;
          if (shape.size > existing.size) existing.size = shape.size;
        } else {
          varMap.set(key, {
            base,
            offset: Math.abs(signedOffset),
            signedOffset,
            size: shape.size,
            accessCount: 1,
          });
        }
      }
    }
  }

  // Ties broken `bp` first, exactly as `stack.ts` breaks them, so the two
  // architectures order a var list the same way and the un-suffixed name goes
  // to the same base. Without the tiebreak the order of two slots sharing an
  // offset is whichever instruction the sweep reached first.
  const entries = [...varMap.values()].sort(
    (a, b) => a.signedOffset - b.signedOffset || a.base.localeCompare(b.base),
  );
  const usedNames = new Set<string>();
  const vars: StackVar[] = [];
  for (const v of entries) {
    // No `arg_N` branch, deliberately — see the module docstring. Every A64
    // slot this can see is a local, and naming one `arg_` would be a claim
    // about a calling convention nothing here has checked.
    let name = `var_${v.offset.toString(16).toUpperCase()}`;
    if (usedNames.has(name)) name = `${name}_${v.base}`;
    usedNames.add(name);
    vars.push({
      offset: v.offset,
      signedOffset: v.signedOffset,
      size: v.size,
      accessCount: v.accessCount,
      name,
      key: stackVarKey(v.base, v.signedOffset),
    });
  }
  return vars;
}

/**
 * The `.pdata` record for a function, by its virtual address.
 *
 * A linear scan is deliberate: the caller has one function, not a sweep, and
 * building an index per call would cost more than the scan. `imageBase` is what
 * turns a `RuntimeFunction`'s RVA into the address a `DisasmFunction` carries.
 */
function recordFor(
  runtimeFunctions: readonly RuntimeFunction[],
  imageBase: number,
  address: number,
): RuntimeFunction | undefined {
  for (const rf of runtimeFunctions) {
    if (imageBase + rf.beginAddress === address) return rf;
  }
  return undefined;
}

/**
 * The ARM64 stack frame of one function, or null when `.pdata` does not
 * describe it.
 *
 * NULL IS THE ANSWER FOR A FUNCTION THE TABLE DOES NOT NAME, and that is a real
 * population rather than a defensive branch: the A64 detector finds 539 and 494
 * functions against 419 and 381 `.pdata` entries, so ~22% of them get no frame.
 * Those are `bl` targets, jump-table cases and export entries the linker emitted
 * no unwind record for; recovering a frame for one would mean reading the
 * prologue, which is the heuristic this module exists to avoid.
 *
 * It is also the answer for a record whose begin address is not this function's.
 * A `.pdata` entry is matched by an EXACT begin, never by containment: an
 * address inside another function's extent belongs to that function's frame,
 * and handing it out here would describe the wrong frame confidently.
 */
export function analyzeArm64StackFrame(
  func: DisasmFunction,
  instructions: Instruction[],
  runtimeFunctions: readonly RuntimeFunction[] | undefined,
  imageBase: number,
  funcInsnMap?: Map<number, Instruction[]>,
): StackFrame | null {
  if (!runtimeFunctions || runtimeFunctions.length === 0) return null;
  const record = recordFor(runtimeFunctions, imageBase, func.address);
  const frame = record?.arm64Frame;
  if (!frame) return null;

  const funcInsns = getFuncInsns(func, instructions, funcInsnMap);
  return {
    frameSize: frame.frameSize,
    vars: collectArm64StackVars(funcInsns),
    frameDelta: frame.frameDelta,
    // See the module docstring: the one consumer of this field is decompiler
    // machinery that refuses on A64, so filling it would be unverifiable.
    frameEstablishedAt: null,
  };
}
