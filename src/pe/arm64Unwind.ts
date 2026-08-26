/**
 * The ARM64 unwind record, decoded into the frame it describes.
 *
 * `.pdata` on ARM64 is the linker's own statement of every function's stack
 * frame, and until `peek-a-bin-hof0` nothing here read it: `pdata.ts` took the
 * function's extent and its handler out of each entry and threw the rest away.
 * What it threw away answers, with no heuristic at all, the question
 * `disasm/stack.ts` spends `inlineFrameGeometry`, `frameGeometry` and a
 * `__SEH_prolog4` helper walk recovering on x86 — **is the frame register a
 * frame pointer, and how far below the entry stack pointer does it sit**.
 *
 * There are two encodings and this module is the one place that knows either.
 *
 * **PACKED** (`UnwindData & 3` is 1 or 2) puts the whole frame in the `.pdata`
 * word itself, with no `.xdata` record to read:
 *
 * | bits  | field                                                       |
 * |-------|-------------------------------------------------------------|
 * | 2-12  | function length, in 4-byte words                            |
 * | 13-15 | `RegF` — 0, or `RegF + 1` FP registers d8.. saved           |
 * | 16-19 | `RegI` — integer registers x19.. saved                      |
 * | 20    | `H` — the eight argument registers x0-x7 are homed          |
 * | 21-22 | `CR` — 0/1 unchained, 3 chained (an `x29`/`lr` pair)        |
 * | 23-31 | `FrameSize`, in 16-byte units                               |
 *
 * **`.xdata`** (flag 0) spells the prologue out as a byte string of *unwind
 * codes*, in reverse prologue order — the first code is the LAST prologue
 * instruction. `decodeUnwindCodes` below is the interpreter.
 *
 * WHAT `FrameSize` MEANS WAS MEASURED, NOT READ OFF THE SPEC, AND THE ANSWER IS
 * NOT "the total stack the function allocates". Over the 500 packed entries of
 * `t64-arm.exe` and `w64-arm.exe`, `FrameSize` equals the distance from the
 * stack pointer on entry to `x29` — the frame delta — on **all 496 chained
 * entries**, and equals the whole allocation on the 4 unchained ones. Where
 * MSVC allocates a further area *below* the frame pointer (`sub sp, sp, #N`
 * after `mov x29, sp`, or a `bl __chkstk` and then a large `sub`), that area is
 * **outside the record entirely** — 9 of 263 and 10 of 237 packed entries, and
 * the `.xdata` codes do not describe it either. That is not an omission: a
 * chained unwinder restores `sp` from `x29`, so it never needs to know. This
 * module therefore reports what the record states and nothing more, and
 * `frameSize`'s docstring below says so where a caller will read it.
 *
 * The cross-check that makes all of this a fact rather than a reading of
 * Microsoft's documentation is in `corpus/arm64.ts`: the instruction stream is
 * an independent record of the same frame, and the two agree on 716 of 716
 * frame pointers and 800 of 800 "is there one at all".
 */

/** Which of the two encodings a frame was recovered from. */
export type Arm64UnwindSource = "packed" | "xdata";

/**
 * The frame one ARM64 unwind record describes.
 *
 * Deliberately flat and small: a `RuntimeFunction` crosses the worker boundary
 * by structured clone and a large image has ~100k of them, so this is six
 * scalars rather than the raw fields plus a decoder.
 */
export interface Arm64UnwindFrame {
  /**
   * `E - x29`, where `E` is the stack pointer on entry — the same quantity
   * `StackFrame.frameDelta` carries on x86, and `null` when the function
   * establishes no frame pointer at all.
   */
  frameDelta: number | null;
  /**
   * The stack the record says the prologue allocates, in bytes.
   *
   * NOT the same quantity as `frameDelta`, and conflating them was a real
   * defect caught by reading one recovered frame: MSVC's `add_fp` shape puts
   * `x29` near the TOP of the frame rather than at its bottom, so
   * `t64-arm!sub_140001070` has a delta of 0x10 and allocates 0x60, and
   * reporting the delta as the size understated it by 80 bytes while the
   * function's own slots ran out to +0x28.
   *
   * A LOWER BOUND, and knowingly so: an area allocated BELOW the frame pointer
   * after it is established is outside every unwind record, in both encodings —
   * 9 of 263 and 10 of 237 packed entries of the corpus binaries, plus the
   * `bl __chkstk` shape (`t64-arm!0x14000568c`, `sub sp, sp, #0x4b0`). A chained
   * unwinder restores `sp` from `x29` and never needs it, so the linker does not
   * record it and nothing here invents it.
   */
  frameSize: number;
  /** Integer callee-saved registers (x19 upward) the prologue saves. */
  savedIntRegs: number;
  /** FP callee-saved registers (d8 upward) the prologue saves. */
  savedFpRegs: number;
  /**
   * The prologue stores all eight argument registers x0-x7 to the stack, which
   * is what a variadic function's prologue does. **`H` is 0 on every packed
   * entry of both corpus binaries**, so nothing here is exercised by a real
   * image and this field is carried because the encoding has it, not because
   * anything was measured with it.
   */
  homesParams: boolean;
  source: Arm64UnwindSource;
}

/**
 * Decode a packed `.pdata` word.
 *
 * `CR` is the whole of the frame-pointer question: 3 is a chained function,
 * which saves the `x29`/`lr` pair and establishes `x29`, and anything else does
 * not establish one. Measured against the instruction stream over all 500
 * packed entries of the two corpus binaries, that is exact in both directions —
 * 496 chained entries and 496 prologues with an `x29` setup, 4 unchained and 4
 * without.
 */
export function decodePackedArm64Unwind(unwindData: number): Arm64UnwindFrame {
  const regF = (unwindData >>> 13) & 0x7;
  const regI = (unwindData >>> 16) & 0xf;
  const h = (unwindData >>> 20) & 0x1;
  const cr = (unwindData >>> 21) & 0x3;
  const frameSize = ((unwindData >>> 23) & 0x1ff) * 16;
  return {
    // CR == 3 is "chained": the x29/lr pair is saved and x29 is established.
    // For every other value the function has no frame pointer, so there is no
    // delta to state — `null`, exactly as x86 spells frame-pointer omission.
    frameDelta: cr === 3 ? frameSize : null,
    frameSize,
    savedIntRegs: regI,
    // "RegF == 0 means none, otherwise RegF + 1 are saved" is the encoding's
    // own rule, not an off-by-one: the field counts the *highest* register
    // saved, and d8 alone is spelled 0 the same way as "no FP registers", which
    // the encoding resolves by making a lone d8 impossible (they are saved in
    // pairs from d8 up).
    savedFpRegs: regF > 0 ? regF + 1 : 0,
    homesParams: h === 1,
    source: "packed",
  };
}

/**
 * How many bytes an unwind code allocates, and how wide the code is.
 *
 * The table is the ARM64 exception-handling encoding and every row of it is
 * fixed by the ISA documentation rather than by anything observed here. Only
 * the *allocating* rows matter for a frame — a `save_regp` writes a register
 * into space some other code already allocated — but every row must still be
 * present, because the codes are a byte stream and a code whose WIDTH is wrong
 * desynchronises everything after it. That is why an unrecognised byte stops
 * the walk and is reported rather than skipped.
 *
 * Two rows were wrong in a first draft and both were caught by the corpus
 * cross-check rather than by reading: `save_r19r20_x` allocates `z * 8` and not
 * `(z + 1) * 16`, and `add_fp` moves the frame pointer *up* from `sp`, so its
 * displacement is subtracted from the delta and not added. With either wrong
 * the agreement with the instruction stream is 85 of 156 rather than 156 of
 * 156.
 */
interface UnwindCode {
  /** Bytes this code occupies, including the opcode byte. */
  width: number;
  /** Bytes of stack it allocates. */
  alloc: number;
  /** `set_fp` / `add_fp`: establishes x29 at `sp + displacement`. */
  setsFp?: { displacement: number };
  /** `end` / `end_c`: the prologue's codes stop here. */
  ends?: boolean;
}

/** Read one code at `i`, or null when the byte is not one this table knows. */
function readUnwindCode(bytes: ArrayLike<number>, i: number): UnwindCode | null {
  const b = bytes[i];
  const next = (k: number): number => bytes[i + k] ?? 0;
  // Truncated: a multi-byte code whose operand bytes are not present cannot be
  // read, and guessing zero for them would invent an allocation.
  const need = (n: number): boolean => i + n <= bytes.length;

  if (b <= 0x1f) return { width: 1, alloc: (b & 0x1f) * 16 }; // alloc_s
  if (b <= 0x3f) return { width: 1, alloc: (b & 0x1f) * 8 }; // save_r19r20_x
  if (b <= 0x7f) return { width: 1, alloc: 0 }; // save_fplr
  if (b <= 0xbf) return { width: 1, alloc: ((b & 0x3f) + 1) * 8 }; // save_fplr_x
  if (b <= 0xc7) return need(2) ? { width: 2, alloc: (((b & 0x7) << 8) | next(1)) * 16 } : null; // alloc_m
  if (b <= 0xcb) return need(2) ? { width: 2, alloc: 0 } : null; // save_regp
  if (b <= 0xcf) return need(2) ? { width: 2, alloc: ((next(1) & 0x3f) + 1) * 8 } : null; // save_regp_x
  if (b <= 0xd3) return need(2) ? { width: 2, alloc: 0 } : null; // save_reg
  if (b <= 0xd5) return need(2) ? { width: 2, alloc: ((next(1) & 0x3f) + 1) * 8 } : null; // save_reg_x
  if (b <= 0xd7) return need(2) ? { width: 2, alloc: 0 } : null; // save_lrpair
  if (b <= 0xd9) return need(2) ? { width: 2, alloc: 0 } : null; // save_fregp
  if (b <= 0xdb) return need(2) ? { width: 2, alloc: ((next(1) & 0x3f) + 1) * 8 } : null; // save_fregp_x
  if (b <= 0xdd) return need(2) ? { width: 2, alloc: 0 } : null; // save_freg
  if (b === 0xde) return need(2) ? { width: 2, alloc: ((next(1) & 0x3f) + 1) * 8 } : null; // save_freg_x
  if (b === 0xe0)
    return need(4) ? { width: 4, alloc: ((next(1) << 16) | (next(2) << 8) | next(3)) * 16 } : null; // alloc_l
  if (b === 0xe1) return { width: 1, alloc: 0, setsFp: { displacement: 0 } }; // set_fp
  if (b === 0xe2)
    return need(2) ? { width: 2, alloc: 0, setsFp: { displacement: next(1) * 8 } } : null; // add_fp
  if (b === 0xe3) return { width: 1, alloc: 0 }; // nop
  if (b === 0xe4) return { width: 1, alloc: 0, ends: true }; // end
  if (b === 0xe5) return { width: 1, alloc: 0, ends: true }; // end_c
  if (b === 0xe6) return { width: 1, alloc: 0 }; // save_next
  if (b === 0xfc) return { width: 1, alloc: 0 }; // pac_sign_lr
  return null;
}

/** What a walk of one record's prologue codes established. */
export interface Arm64UnwindCodeWalk {
  /** Total stack the codes allocate. */
  totalAlloc: number;
  /** `E - x29`, or null when no code establishes a frame pointer. */
  frameDelta: number | null;
  /** The first byte the table above does not know, or null. */
  unknownByte: number | null;
}

/**
 * Walk a record's unwind codes and report the frame they establish.
 *
 * **The codes run backwards through the prologue** — the first byte describes
 * the LAST prologue instruction — which is the whole of the frame-delta
 * arithmetic and is easy to get inverted. Everything allocated by codes read
 * *before* `set_fp`/`add_fp` was allocated by prologue instructions that run
 * *after* the frame pointer was established, i.e. below it; so the delta is the
 * total minus that, minus `add_fp`'s own displacement.
 */
export function decodeUnwindCodes(bytes: ArrayLike<number>): Arm64UnwindCodeWalk {
  let i = 0;
  let totalAlloc = 0;
  let allocBelowFp: number | null = null;
  let fpDisplacement = 0;
  while (i < bytes.length) {
    const code = readUnwindCode(bytes, i);
    if (code === null) return { totalAlloc, frameDelta: null, unknownByte: bytes[i] };
    if (code.setsFp && allocBelowFp === null) {
      // The FIRST fp-establishing code in the stream is the LAST one in the
      // prologue, which is the one that stands: a prologue that moved x29 twice
      // ends where its last move put it.
      allocBelowFp = totalAlloc;
      fpDisplacement = code.setsFp.displacement;
    }
    totalAlloc += code.alloc;
    i += code.width;
    if (code.ends) break;
  }
  return {
    totalAlloc,
    frameDelta: allocBelowFp === null ? null : totalAlloc - allocBelowFp - fpDisplacement,
    unknownByte: null,
  };
}

/**
 * The frame an `.xdata` record's prologue codes describe.
 *
 * A NEGATIVE DELTA IS REFUSED, and it is not a hypothetical: `t64-arm` and
 * `w64-arm` each contain one function whose record allocates nothing and then
 * says `add x29, sp, #0x10`, putting the frame register SIXTEEN BYTES ABOVE its
 * own entry stack pointer — `0x140001830`, a fragment of the shared stack-probe
 * thunk that runs on and writes into its caller's frame. `[x29 + N]` there is
 * not this function's storage at all, so reporting a delta would describe the
 * wrong frame confidently.
 *
 * That is the same judgement `stack.ts`'s `addressesOwnFrame` makes on x86 for
 * the same reason (`peek-a-bin-s7hl`, where the function is `__SEH_prolog4`),
 * arrived at here independently from the A64 record rather than copied over: a
 * frame register above entry `sp` means the function is establishing somebody
 * else's frame. Zero is allowed — an empty frame whose pointer is the entry
 * stack pointer is degenerate but is still this function's.
 *
 * The packed encoding cannot express it: `FrameSize` is an unsigned field and
 * the delta is that field verbatim, so the guard there is structural rather
 * than a measured saving.
 */
export function frameFromUnwindCodes(bytes: ArrayLike<number>): Arm64UnwindFrame | null {
  const walk = decodeUnwindCodes(bytes);
  if (walk.unknownByte !== null) return null;
  return {
    frameDelta: walk.frameDelta !== null && walk.frameDelta >= 0 ? walk.frameDelta : null,
    // The TOTAL the codes allocate, never the delta — see `frameSize`.
    frameSize: walk.totalAlloc,
    // The codes name each saved register individually rather than counting
    // them, and nothing here consumes a count, so these are deliberately not
    // re-derived from the byte stream: a number nobody reads is a number
    // nobody checks.
    savedIntRegs: 0,
    savedFpRegs: 0,
    homesParams: false,
    source: "xdata",
  };
}
