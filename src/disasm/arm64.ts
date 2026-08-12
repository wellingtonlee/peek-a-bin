/**
 * ARM64 disassembly and function detection.
 *
 * Deliberately separate from `functionDetect.ts` rather than another branch
 * inside it. Almost nothing there transfers: the prologue table is x86 opcode
 * bytes, the recursive descent keys off `jmp`/`call`/`j<cc>` mnemonics and
 * `0x…` operands, the jump-table reader models an MSVC x86 `jmp [tbl+i*n]`,
 * and the thunk and tail-call passes read `[rip ± 0x..]`. On a fixed-width ISA
 * none of that machinery is even needed for the disassembly itself — a linear
 * sweep at 4-byte alignment is not a heuristic, it is the decoding.
 *
 * What is in scope here is what can be got right: instructions, and function
 * boundaries from evidence (`.pdata`, exports, the entry point, unwind
 * handlers, direct `bl` targets). Everything the x86 grammar would have to
 * interpret — operand parsing, xrefs, stack frames, the decompiler's IR lifter
 * — is refused by the callers rather than run on ARM64 bytes; see
 * `unsupportedOnArch` in ./arch.ts.
 */

import type { DisasmFunction, Instruction } from "./types";
import { type DetectPass, type DetectResult, mapInsn } from "./functionDetect";
import { createScan, requireCapstone } from "./capstoneWindow";

/** Every A64 instruction is exactly four bytes, always 4-byte aligned. */
export const ARM64_INSN_SIZE = 4;

/**
 * Bytes handed to Capstone in one `disasm` call.
 *
 * Small on purpose, and now smaller than the shared ceiling in
 * `./capstoneWindow.ts` rather than the only bound in the codebase. The
 * original observation stands: sweeping t64-arm.exe (110 KiB of .text) with a
 * 64 KiB window yielded 11548 instructions and covered 202 of 419 function
 * starts, and by the end of it even `new Capstone(...)` threw `memory access
 * out of bounds`; the same sweep with this window yields 27428 instructions and
 * 419/419 starts. What that was actually hitting is now measured: a 64 KiB
 * window is the whole of capstone-wasm's ~65.6 KiB WASM stack, because the
 * input is passed by `stackAlloc`, not by the heap.
 *
 * The other half of that bound is {@link disassembleArm64}'s probe: after a
 * word fails to decode the next attempt is one instruction wide, not a full
 * window, so a section of undecodable data costs 4 bytes per word instead of
 * 4 KiB.
 */
export const ARM64_DECODE_WINDOW = 0x1000;

/**
 * How much of a section must decode as A64 before this sweep will call its
 * output a disassembly.
 *
 * Measured with the shipped `capstone.wasm`, sweeping each image's code section
 * at 4-byte alignment with a `CS_ARCH_ARM64` handle:
 *
 * | image                | machine | words | decoded as A64 |
 * |----------------------|---------|-------|----------------|
 * | t64-arm.exe          | 0xAA64  | 28160 | 27428 (97.4%)  |
 * | w64-arm.exe          | 0xAA64  | 24960 | 24393 (97.7%)  |
 * | t64.exe              | 0x8664  | 15360 |  4209 (27.4%)  |
 * | w64.exe              | 0x8664  | 13824 |  3858 (27.9%)  |
 * | gcc-amd64-mingw-exec | 0x8664  |  6784 |  1804 (26.6%)  |
 * | t32.exe              | 0x014C  | 13824 |  3016 (21.8%)  |
 *
 * A64's encoding space is dense enough that a quarter of arbitrary x86 bytes
 * decode to *something*, which is exactly why the failure this guards against is
 * silent. The two bands are 3.5x apart and this sits between them: 1.8x above
 * everything that is not ARM64 and 1.95x below everything that is.
 */
export const ARM64_MIN_DECODE_FRACTION = 0.5;

/**
 * Words below which the decode rate is not evidence about anything.
 *
 * A section of a few dozen thunks can miss the fraction by chance, and every
 * synthetic fixture in the tests is smaller than this.
 */
export const ARM64_MIN_MEASURED_WORDS = 256;

/**
 * The bytes are not A64, whatever the COFF header says.
 *
 * Thrown by {@link disassembleArm64} rather than returning the ~27% of words
 * that happened to decode, because that list is the failure mode this whole
 * module exists to avoid: plausible-looking instructions that are not what the
 * file contains (peek-a-bin-2t1).
 *
 * The likely cause is **ARM64EC or ARM64X**. Both carry machine 0xAA64, the same
 * value pure ARM64 does, and both hold x86-64 code — all of it for EC, some of
 * it for X. Telling the three apart properly needs the CHPE metadata pointer out
 * of the load-config data directory, which `src/pe/parser.ts` does not read; this
 * is the evidence available without it, and it is evidence about the bytes
 * rather than a guess about the header. An ARM64X image is the case this may
 * *not* catch: half its section is genuine A64, which can land above the floor.
 */
export class Arm64DecodeRateError extends Error {
  constructor(
    readonly decoded: number,
    readonly words: number,
  ) {
    super(
      `Only ${((100 * decoded) / words).toFixed(1)}% of this section decoded as ` +
        `ARM64 instructions (${decoded} of ${words} words); a real ARM64 image ` +
        `decodes over 97%. The COFF machine type says ARM64, but ARM64EC and ` +
        `ARM64X images carry that same 0xAA64 and hold x86-64 code, which is what ` +
        `a rate this low looks like. Disassembling it as ARM64 anyway would ` +
        `produce a screenful of instructions the file does not contain, so this ` +
        `stops instead. Distinguishing the three needs the CHPE metadata pointer ` +
        `from the load-config directory, which is not parsed.`,
    );
    this.name = "Arm64DecodeRateError";
  }
}

/** What ARM64 disassembly needs from the session — one Capstone handle, opened
 *  `CS_ARCH_ARM64`, plus the annotation maps `mapInsn` reads. */
export interface Arm64Context {
  cs: any;
  stringMap: Map<number, string>;
  iatMap: Map<number, { lib: string; func: string }>;
  driverMode: boolean;
}

/** A `.pdata`-derived function extent, in virtual addresses. */
export interface CodeRange {
  beginAddress: number;
  endAddress: number;
}

/** `addr => is addr inside one of these ranges`, for marking speculative code. */
function rangeTest(ranges: CodeRange[] | undefined): (addr: number) => boolean {
  if (!ranges || ranges.length === 0) return () => false;
  const sorted = [...ranges].sort((a, b) => a.beginAddress - b.beginAddress);
  const starts = new Float64Array(sorted.length);
  const maxEnds = new Float64Array(sorted.length);
  let running = Number.NEGATIVE_INFINITY;
  for (let i = 0; i < sorted.length; i++) {
    starts[i] = sorted[i].beginAddress;
    running = Math.max(running, sorted[i].endAddress);
    maxEnds[i] = running;
  }
  return (addr: number): boolean => {
    let lo = 0;
    let hi = starts.length - 1;
    let last = -1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (starts[mid] <= addr) {
        last = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return last >= 0 && maxEnds[last] > addr;
  };
}

/**
 * Disassemble an ARM64 code section by linear sweep.
 *
 * This is both the plain and the "hybrid" disassembly for ARM64: recursive
 * descent exists on x86 to find the instruction boundaries that a
 * variable-length encoding makes ambiguous, and A64 has no such ambiguity. Any
 * 4-byte-aligned word is either a valid instruction or it is not, and reading
 * it in isolation gives the same answer as reading it in context.
 *
 * `pdataRanges`, when supplied, only classifies the result: a word inside a
 * linker-recorded function extent is code the image itself vouches for
 * (`source: "recursive"`), a word outside every extent is the sweep's own guess
 * (`source: "gap-fill"`, which the disassembly view dims). Nothing is decoded
 * differently because of it.
 */
export function disassembleArm64(
  bytes: Uint8Array,
  baseAddress: number,
  ctx: Arm64Context,
  pdataRanges?: CodeRange[],
): Instruction[] {
  // Throw rather than return `[]`: this sweep *is* the ARM64 disassembly, so an
  // empty list is a complete-looking answer for a `.text` full of code
  // (peek-a-bin-cen). `detectArm64Functions` below keeps its own `if (ctx.cs)`
  // guard, because its other evidence does not come from the decoder.
  const cs = requireCapstone(ctx.cs, "ARM64 sweep");
  const out: Instruction[] = [];

  const scan = createScan(cs, "ARM64 sweep", ARM64_DECODE_WINDOW);
  const isKnownCode = rangeTest(pdataRanges);
  const marks = pdataRanges !== undefined && pdataRanges.length > 0;
  // A trailing partial word cannot be an instruction.
  const len = bytes.length - (bytes.length % ARM64_INSN_SIZE);
  let offset = 0;
  /** The previous attempt decoded nothing, so the next one probes a single word. */
  let probing = false;

  while (offset + ARM64_INSN_SIZE <= len) {
    // When probing, the *limit* is one word past the offset, which is how the
    // scan is told to hand Capstone four bytes instead of a full window.
    const limit = probing ? offset + ARM64_INSN_SIZE : len;
    const insns = scan.decode(bytes, offset, limit, baseAddress + offset);

    if (insns.length === 0) {
      probing = true;
      offset += ARM64_INSN_SIZE;
      continue;
    }
    probing = false;

    for (const insn of insns) {
      const mapped = mapInsn(insn, ctx.stringMap, ctx.iatMap, ctx.driverMode);
      if (marks) mapped.source = isKnownCode(insn.address) ? "recursive" : "gap-fill";
      out.push(mapped);
    }

    const last = insns[insns.length - 1];
    const next = last.address + last.size - baseAddress;
    // Defensive: a decoder that reported an instruction at or before where the
    // window started would otherwise spin here forever.
    offset = next > offset ? next : offset + ARM64_INSN_SIZE;
  }

  // Everything above assumes the section holds A64. Nothing before this point
  // checks that assumption, and it is checkable: see {@link Arm64DecodeRateError}.
  const words = len / ARM64_INSN_SIZE;
  if (words >= ARM64_MIN_MEASURED_WORDS && out.length < words * ARM64_MIN_DECODE_FRACTION) {
    throw new Arm64DecodeRateError(out.length, words);
  }

  return out;
}

/** `bl #0x140001018` — the only call form whose target is known statically. */
const BL_TARGET = /^#?(0x[0-9a-fA-F]+)$/;

// ── A64 switch dispatch tables ──────────────────────────────────────────────
//
// An A64 switch cannot name its table in the dispatching instruction the way
// 32-bit x86 does, and it does not use the x86-64 RVA form either. Both
// compilers spell it as a dependency chain ending in `br`, in one of two shapes
// that differ only in whether the table base and the case base are the same
// `adr`:
//
// ```text
//   one adr, byte entries                  two adrs, word entries
//   cmp   w11, #7                          cmp   w10, #0x37
//   b.hi  <default>                        b.hi  <default>
//   adr   x9, #TABLE                       adr   x9, #TABLE
//   ldrsb x8, [x9, w11, uxtw]              ldrsw x8, [x9, w10, uxtw #2]
//   add   x8, x9, x8, lsl #2               adr   x9, #CASEBASE
//   br    x8                               add   x8, x9, x8, lsl #2
//                                          br    x8
// ```
//
// Entries are **offsets in instruction-sized units**, not addresses — signed or
// unsigned by which load was used — and the `lsl #k` on the `add` is the scale.
// The second shape reassigns the *same register* between the load and the add,
// so the walk has to be positional: the base is the nearest `adr` before the
// `add`, and the table is the nearest `adr` before the *load*. Reading either
// one as the other silently relocates every case body.
//
// Not every `br` is a switch. The other two shapes in a real image are
// `adrp`/`add`/`ldar xN, [x8]` — a function pointer loaded from `.data` at run
// time, which has no static target at all — and sweep artefacts in padding.
// Both contribute nothing, which is the point, and {@link classifyArm64Br} is
// where the difference between "nothing to find" and "found nothing" is stated.
//
// The index is not always bounded by a `cmp`, either: a block loop's remainder
// is bounded by the `subs`/`add` pair around it, which is the only statement of
// length `memcmp`'s tail dispatch has. See {@link loopResidueBound}.

/** Entries read from one A64 table. Same ceiling, and same reason, as the x86 reader. */
const MAX_ARM64_JUMP_TABLE_CASES = 512;

/** How far back the dispatch walk looks: the chain is 4-6 instructions. */
const ARM64_MAX_RECENT = 16;

/**
 * `x9`, `w9`, `X9` → `"9"`; `xzr`/`wzr` → `"zr"`; anything else → null.
 *
 * A64 mixes widths within one idiom on purpose — the table load writes `w8` and
 * the `add` that consumes it reads `x8` — so registers are only ever compared
 * by number.
 */
function a64Reg(text: string | undefined): string | null {
  if (text === undefined) return null;
  const m = text.trim().toLowerCase().match(/^[wx](\d{1,2}|zr)$/);
  if (!m) return null;
  if (m[1] === "zr") return "zr";
  const n = Number(m[1]);
  return n <= 30 ? String(n) : null;
}

/** Mnemonics whose first operand is a source, so it must not read as a write. */
const A64_NO_WRITE = new Set(["cmp", "cmn", "tst", "str", "strb", "strh", "stur", "stp", "st1"]);

/**
 * The register an instruction writes, or null.
 *
 * Deliberately crude and deliberately over-eager: anything not on the deny list
 * is taken to write its first operand. Over-reporting a write only ends a walk
 * early, which yields no table — the safe direction. Under-reporting would let
 * the walk step over the instruction that actually produced the value.
 */
function a64Dest(mnemonic: string, opStr: string): string | null {
  if (A64_NO_WRITE.has(mnemonic.toLowerCase())) return null;
  return a64Reg(opStr.split(",")[0]);
}

/** `adr x9, #0x140007a8c` → `{ reg: "9", target: 0x140007a8c }`. */
function parseAdr(mnemonic: string, opStr: string): { reg: string; target: number } | null {
  if (mnemonic.toLowerCase() !== "adr") return null;
  const parts = opStr.split(",");
  const reg = a64Reg(parts[0]);
  const m = parts[1]?.trim().match(/^#?(0x[0-9a-fA-F]+|\d+)$/);
  if (!reg || !m) return null;
  return { reg, target: Number(m[1]) };
}

/** `add x8, x9, x8, lsl #2` / `sub x3, x3, x8, lsl #2`, with the shift required. */
function parseTableAdd(
  mnemonic: string,
  opStr: string,
): { dest: string; base: string; offset: string; shift: number; sign: 1 | -1 } | null {
  const mn = mnemonic.toLowerCase();
  if (mn !== "add" && mn !== "sub") return null;
  const parts = opStr.split(",");
  if (parts.length !== 4) return null;
  const dest = a64Reg(parts[0]);
  const base = a64Reg(parts[1]);
  const offset = a64Reg(parts[2]);
  const sh = parts[3].trim().toLowerCase().match(/^lsl\s+#(\d+)$/);
  // The shift is required, not defaulted to zero: it is the statement of what
  // unit the table's entries are in, and a table whose entry scale cannot be
  // established yields no targets rather than a plausible set.
  if (!dest || !base || !offset || !sh) return null;
  const shift = Number(sh[1]);
  if (shift > 4) return null;
  return { dest, base, offset, shift, sign: mn === "sub" ? -1 : 1 };
}

/** Byte width and signedness of the five scaled-index loads a dispatch uses. */
const A64_TABLE_LOADS = new Map<string, { width: number; signed: boolean }>([
  ["ldrb", { width: 1, signed: false }],
  ["ldrsb", { width: 1, signed: true }],
  ["ldrh", { width: 2, signed: false }],
  ["ldrsh", { width: 2, signed: true }],
  ["ldrsw", { width: 4, signed: true }],
]);

/**
 * `ldrsw x8, [x9, w10, uxtw #2]` → table register, index register, entry width.
 *
 * The extend's shift must equal the entry width, because it is the same
 * statement made twice — `[table + index * width]`. A mismatch means this is not
 * a table read and the walk gives up. A plain `ldr` is refused outright: its
 * width comes from the destination register rather than the mnemonic, and
 * nothing observed emits one here.
 */
function parseTableLoad(
  mnemonic: string,
  opStr: string,
): { dest: string; table: string; index: string; width: number; signed: boolean } | null {
  const kind = A64_TABLE_LOADS.get(mnemonic.toLowerCase());
  if (!kind) return null;
  const m = opStr.match(/^\s*([wx]\w+)\s*,\s*\[\s*([wx]\w+)\s*,\s*([wx]\w+)\s*(?:,\s*(?:uxtw|sxtw|lsl)(?:\s+#(\d+))?\s*)?\]\s*$/i);
  if (!m) return null;
  const dest = a64Reg(m[1]);
  const table = a64Reg(m[2]);
  const index = a64Reg(m[3]);
  if (!dest || !table || !index) return null;
  const shift = m[4] === undefined ? 0 : Number(m[4]);
  if (1 << shift !== kind.width) return null;
  return { dest, table, index, width: kind.width, signed: kind.signed };
}

/** `cmp w10, #0x37` → 0x37, the largest case index the dispatch can be reached with. */
function parseCmpImmediate(mnemonic: string, opStr: string, reg: string): number | null {
  if (mnemonic.toLowerCase() !== "cmp") return null;
  const parts = opStr.split(",");
  if (a64Reg(parts[0]) !== reg) return null;
  const m = parts[1]?.trim().match(/^#?(0x[0-9a-fA-F]+|\d+)$/);
  return m ? Number(m[1]) : null;
}

/** `add x2, x2, #8` / `subs x2, x2, #8` on one register, or null. */
function parseSelfImm(
  mnemonic: string,
  opStr: string,
  want: "add" | "subs",
): { reg: string; imm: number } | null {
  if (mnemonic.toLowerCase() !== want) return null;
  const parts = opStr.split(",");
  if (parts.length !== 3) return null;
  const dest = a64Reg(parts[0]);
  const src = a64Reg(parts[1]);
  if (dest === null || dest !== src) return null;
  const m = parts[2].trim().match(/^#?(0x[0-9a-fA-F]+|\d+)$/);
  return m ? { reg: dest, imm: Number(m[1]) } : null;
}

/**
 * The bound a *decrement loop* puts on an index, where there is no `cmp`.
 *
 * A block-at-a-time loop leaves its remainder in the counter and then dispatches
 * on it. `memcmp` in the ARM64 CRT is the observed case, at `0x140001db0` in
 * both t64-arm.exe and w64-arm.exe (peek-a-bin-mxw):
 *
 * ```text
 *   subs x2, x2, #8          ; consume one 8-byte block
 *   b.gt <loop>              ; still more than a block left
 *   b.eq <exact>             ; landed exactly on the end
 *   add  x2, x2, #8          ; x2 is now the 1..7 byte remainder
 *   adr  x3, #TABLE
 *   ldrb w8, [x3, x2]
 * ```
 *
 * `findArm64JumpTables` requires a compare because a compare is normally the
 * only statement of a table's length, and this shape has none — the walk hit the
 * `add` writing the index and gave up. But the pair *is* a statement of the
 * range, and a tight one: control only reaches a `subs` with the counter above
 * zero (that is what the loop's own back-edge tests), so the residue is in
 * `[1-K, 0]` and the `add` puts the index in `[1, K]`. `K` entries are read.
 *
 * That is deliberately the *low* reading of two. Where the exact-zero residue is
 * branched away — the `b.eq` above, present in both real images — the reachable
 * indices are `1..K-1` and `K` entries cover every one of them. Where it is not,
 * index `K` exists and its case is missed: one edge short, never one invented,
 * which is the direction this file errs in everywhere else. Index 0 is listed
 * although the residue cannot reach it; it is a real entry of a real table, and
 * on the observed images it is the same case body the *other* dispatch through
 * that same table reaches with index 0.
 *
 * `at` is where the walk found the `add`. The `subs` must be the next write of
 * the same register going back, must carry the same immediate, and must be
 * followed by a conditional branch — the loop test that makes the residue
 * bounded in the first place.
 */
function loopResidueBound(reg: string, recent: Instruction[], at: number): number {
  const add = parseSelfImm(recent[at].mnemonic, recent[at].opStr, "add");
  if (!add || add.reg !== reg || add.imm <= 0) return 0;
  for (let i = at - 1; i >= 0; i--) {
    if (a64Dest(recent[i].mnemonic, recent[i].opStr) !== reg) continue;
    const subs = parseSelfImm(recent[i].mnemonic, recent[i].opStr, "subs");
    if (!subs || subs.imm !== add.imm) return 0;
    if (!recent[i + 1]?.mnemonic.toLowerCase().startsWith("b.")) return 0;
    return add.imm;
  }
  return 0;
}

/** The chain a `br` was reached through, or null when any link is missing. */
export interface Arm64Dispatch {
  /** Address of the table's first entry. */
  table: number;
  /** Address case offsets are measured from. */
  caseBase: number;
  width: number;
  signed: boolean;
  /** `caseBase + sign * (entry << shift)`. */
  shift: number;
  sign: 1 | -1;
  /** Upper bound on entries, from the bounds check in front of the dispatch. */
  count: number;
}

/**
 * Walk back from a `br <reg>` to the table it dispatches through.
 *
 * `recent` is the instruction window ending at the `br`. Every step takes the
 * nearest match and gives up the moment something else writes the register it
 * is chasing: a later write means the value the branch used came from somewhere
 * this walk has not modelled, and guessing there is how a table gets misread.
 */
function recoverArm64Dispatch(brOpStr: string, recent: Instruction[]): Arm64Dispatch | null {
  const brReg = a64Reg(brOpStr);
  if (brReg === null || brReg === "zr") return null;

  /** Nearest index below `from` whose instruction writes `reg`, or -1. */
  const lastWrite = (reg: string, from: number): number => {
    for (let i = from; i >= 0; i--) {
      if (a64Dest(recent[i].mnemonic, recent[i].opStr) === reg) return i;
    }
    return -1;
  };

  const iAdd = lastWrite(brReg, recent.length - 1);
  if (iAdd < 0) return null;
  const add = parseTableAdd(recent[iAdd].mnemonic, recent[iAdd].opStr);
  if (!add || add.dest !== brReg) return null;

  // The case base and the table load are both looked for from the `add`
  // backwards, independently. They are frequently the *same register* rewritten
  // in between (`adr x9, #TABLE` … `adr x9, #CASEBASE`), so position is the only
  // thing that separates them.
  const iBase = lastWrite(add.base, iAdd - 1);
  if (iBase < 0) return null;
  const baseAdr = parseAdr(recent[iBase].mnemonic, recent[iBase].opStr);
  if (!baseAdr) return null;

  const iLoad = lastWrite(add.offset, iAdd - 1);
  if (iLoad < 0) return null;
  const load = parseTableLoad(recent[iLoad].mnemonic, recent[iLoad].opStr);
  if (!load) return null;

  const iTable = lastWrite(load.table, iLoad - 1);
  if (iTable < 0) return null;
  const tableAdr = parseAdr(recent[iTable].mnemonic, recent[iTable].opStr);
  if (!tableAdr) return null;

  // Something has to state how long the table is, so without a statement there
  // is no table. It has to be about the index the load used, and it has to come
  // before the load — anything writing that index in between means the compare
  // was about a different value.
  //
  // Two things can state it. A `cmp` is the usual one. The other is the write
  // itself: a `subs`/`add` pair around a decrement loop bounds the index just as
  // tightly, and is the only bound the `memcmp` dispatch has — see
  // {@link loopResidueBound}. Any *other* write to the index still ends the walk.
  let count = 0;
  for (let i = iLoad - 1; i >= 0; i--) {
    const imm = parseCmpImmediate(recent[i].mnemonic, recent[i].opStr, load.index);
    if (imm !== null) {
      count = imm + 1;
      break;
    }
    if (a64Dest(recent[i].mnemonic, recent[i].opStr) === load.index) {
      count = loopResidueBound(load.index, recent, i);
      break;
    }
  }
  if (count <= 0 || count > MAX_ARM64_JUMP_TABLE_CASES) return null;

  return {
    table: tableAdr.target,
    caseBase: baseAdr.target,
    width: load.width,
    signed: load.signed,
    shift: add.shift,
    sign: add.sign,
    count,
  };
}

/** `ldar x9, [x8]` / `ldr x8, [x8, #0x2c0]` → the register held and the byte offset. */
function parsePointerLoad(
  mnemonic: string,
  opStr: string,
): { dest: string; addr: string; offset: number } | null {
  const mn = mnemonic.toLowerCase();
  // The acquire loads are what a guarded-import or delay-load thunk uses; the
  // plain ones are here because the same shape appears without the barrier.
  if (mn !== "ldar" && mn !== "ldapr" && mn !== "ldr" && mn !== "ldur") return null;
  const m = opStr.match(/^\s*([wx]\w+)\s*,\s*\[\s*([wx]\w+)\s*(?:,\s*#?(-?(?:0x[0-9a-fA-F]+|\d+))\s*)?\]\s*$/i);
  if (!m) return null;
  const dest = a64Reg(m[1]);
  const addr = a64Reg(m[2]);
  if (!dest || !addr) return null;
  return { dest, addr, offset: m[3] === undefined ? 0 : Number(m[3]) };
}

/** `adrp x8, #0x14001d000` → `{ reg: "8", target: 0x14001d000 }`. Same shape as `adr`. */
function parseAdrp(mnemonic: string, opStr: string): { reg: string; target: number } | null {
  if (mnemonic.toLowerCase() !== "adrp") return null;
  const parts = opStr.split(",");
  const reg = a64Reg(parts[0]);
  const m = parts[1]?.trim().match(/^#?(0x[0-9a-fA-F]+|\d+)$/);
  if (!reg || !m) return null;
  return { reg, target: Number(m[1]) };
}

/** `add x9, x11, #0x148` — the page-offset half of an `adrp`/`add` address. */
function parseAddImm(
  mnemonic: string,
  opStr: string,
): { dest: string; base: string; imm: number } | null {
  if (mnemonic.toLowerCase() !== "add") return null;
  const parts = opStr.split(",");
  if (parts.length !== 3) return null;
  const dest = a64Reg(parts[0]);
  const base = a64Reg(parts[1]);
  const m = parts[2].trim().match(/^#?(0x[0-9a-fA-F]+|\d+)$/);
  if (!dest || !base || !m) return null;
  return { dest, base, imm: Number(m[1]) };
}

/**
 * What a `br` dispatches through.
 *
 * `br` is not one construct, and the three shapes that reach one in a real image
 * mean three different things by "no table". Collapsing them into a null made
 * the commonest of them — a run-time function pointer, which has no static
 * target *at all* — indistinguishable from a chain this reader simply cannot
 * follow. peek-a-bin-mxw: 11 of t64-arm.exe's 13 remaining dead-end `br` blocks
 * and 11 of w64-arm.exe's are that shape, and for every one of them **no edge is
 * the correct answer**, not a missing one.
 */
export type Arm64BrKind =
  /** A switch: `adr` / scaled load / `add` / `br`, with a bounded table. */
  | { kind: "table"; dispatch: Arm64Dispatch }
  /**
   * The branch register was loaded from memory — `adrp`/`add` to a `.data`
   * slot, then `ldar`, then `br`. A guarded-import or delay-load thunk: nothing
   * in the file says where it goes, because the loader writes that slot at run
   * time. Recovering it would mean modelling the delay-load descriptor or the
   * guarded-CF table, not reading further back through registers.
   *
   * `slot` is the address read, when the `adrp`/`add` pair resolves.
   */
  | { kind: "runtime-pointer"; slot: number | null }
  /**
   * Neither. Includes `br` on a register produced by something unmodelled, and
   * the linear sweep's own artefacts — a `br` decoded out of alignment padding
   * (e.g. `br x1` at 0x1400040e0 in t64-arm.exe, right after a `nop` and two
   * words that do not decode) has no chain because the words in front of it are
   * not instructions.
   */
  | { kind: "unrecognised" };

/**
 * Classify the `br` at the end of `recent`.
 *
 * Exported for the tests, alongside {@link findArm64JumpTables} and for the same
 * reason: the distinction between "no static target exists" and "this reader
 * could not follow the chain" is the whole point of the type, and asserting it
 * through a whole synthetic image would restate the walk rather than test it.
 */
export function classifyArm64Br(brOpStr: string, recent: Instruction[]): Arm64BrKind {
  const brReg = a64Reg(brOpStr);
  if (brReg === null || brReg === "zr") return { kind: "unrecognised" };

  const dispatch = recoverArm64Dispatch(brOpStr, recent);
  if (dispatch) return { kind: "table", dispatch };

  /** Nearest index below `from` whose instruction writes `reg`, or -1. */
  const lastWrite = (reg: string, from: number): number => {
    for (let i = from; i >= 0; i--) {
      if (a64Dest(recent[i].mnemonic, recent[i].opStr) === reg) return i;
    }
    return -1;
  };

  const iLoad = lastWrite(brReg, recent.length - 1);
  if (iLoad < 0) return { kind: "unrecognised" };
  const load = parsePointerLoad(recent[iLoad].mnemonic, recent[iLoad].opStr);
  if (!load) return { kind: "unrecognised" };

  // The value is from memory, which already settles it: there is no static
  // target. Resolving the slot is a courtesy, and failing to resolve it does not
  // change the answer.
  const iAdd = lastWrite(load.addr, iLoad - 1);
  const add = iAdd < 0 ? null : parseAddImm(recent[iAdd].mnemonic, recent[iAdd].opStr);
  if (!add) return { kind: "runtime-pointer", slot: null };
  const iPage = lastWrite(add.base, iAdd - 1);
  const page = iPage < 0 ? null : parseAdrp(recent[iPage].mnemonic, recent[iPage].opStr);
  if (!page) return { kind: "runtime-pointer", slot: null };
  return { kind: "runtime-pointer", slot: page.target + add.imm + load.offset };
}

/**
 * Case targets of one A64 dispatch table.
 *
 * Every entry has to resolve inside the code section and land on a 4-byte
 * boundary — an A64 instruction address is always aligned, so an unaligned
 * target is proof the reading is wrong rather than a case body in an odd place.
 * The read stops at the first entry that fails either test, so a table shorter
 * than its bounds check claims yields its real cases and nothing after them.
 */
function readArm64Table(
  d: Arm64Dispatch,
  bytes: Uint8Array,
  baseAddress: number,
): number[] {
  const endAddress = baseAddress + bytes.length;
  const targets: number[] = [];
  for (let c = 0; c < d.count; c++) {
    const at = d.table + c * d.width - baseAddress;
    if (at < 0 || at + d.width > bytes.length) break;
    let raw = 0;
    for (let b = 0; b < d.width; b++) raw |= bytes[at + b] << (8 * b);
    raw >>>= 0;
    const bits = d.width * 8;
    const entry = d.signed && raw >= 2 ** (bits - 1) ? raw - 2 ** bits : raw;
    const target = d.caseBase + d.sign * (entry * 2 ** d.shift);
    if (target < baseAddress || target >= endAddress) break;
    if (target % ARM64_INSN_SIZE !== 0) break;
    targets.push(target);
  }
  return targets;
}

/**
 * Every A64 dispatch table in `insns`, keyed by the address of its `br`.
 *
 * Exported for the tests: the walk has enough steps that testing it only
 * through `detectArm64Functions` would mean building a whole image for each
 * refusal case.
 */
export function findArm64JumpTables(
  insns: Instruction[],
  bytes: Uint8Array,
  baseAddress: number,
): Map<number, number[]> {
  const tables = new Map<number, number[]>();
  const recent: Instruction[] = [];
  for (const insn of insns) {
    // Only the plain `br`. The pointer-authenticated forms (`braa`, `brab`, …)
    // reach a signed pointer, never a table computed like this.
    if (insn.mnemonic.toLowerCase() === "br") {
      const br = classifyArm64Br(insn.opStr, recent);
      if (br.kind === "table") {
        const targets = readArm64Table(br.dispatch, bytes, baseAddress);
        // One target is a jump, not a switch: it says nothing the CFG could not
        // already see, and two is the least a table can distinguish.
        if (targets.length >= 2) tables.set(insn.address, targets);
      }
      // The other two kinds contribute nothing, and that is the answer rather
      // than a shortfall: a `runtime-pointer` has no static target for any
      // reader to find, and an `unrecognised` one is usually the sweep having
      // decoded padding. See {@link Arm64BrKind}.
    }
    recent.push(insn);
    if (recent.length > ARM64_MAX_RECENT) recent.shift();
  }
  return tables;
}

/**
 * Function boundaries for an ARM64 image.
 *
 * Every start here is *recorded* somewhere, not guessed from a byte pattern:
 *
 *  * `.pdata` — the linker's own table of function extents. On ARM64 it is
 *    mandatory for anything with a frame, and it carries the end address too,
 *    so these functions get exact sizes.
 *  * exports, the entry point, and `.xdata` exception handlers.
 *  * the target of a direct `bl`. These are the leaf functions that ARM64
 *    unwind data is allowed to omit: on t64-arm.exe, 120 of 460 distinct `bl`
 *    targets are outside every `.pdata` extent, and — a good sign that the
 *    sweep above is aligned correctly — not one lands strictly *inside* one.
 *
 * No prologue scan. `stp x29, x30, [sp, #-N]!` is the common frame setup, but
 * matching it is a byte-pattern guess of exactly the kind `.pdata` makes
 * unnecessary here, and it would find nothing that is not already listed.
 *
 * `jumpTables` holds the A64 switch dispatches recovered by
 * {@link findArm64JumpTables} — the `adr`/`ldr`/`add`/`br` chains, and only
 * those whose table base, entry width and length all resolve. The case bodies
 * are decoded by the linear sweep either way; what the tables add is the CFG
 * edges out of the dispatch block, which without them is a dead end
 * (peek-a-bin-8ij).
 *
 * Case targets are deliberately *not* added to the function list. They are case
 * labels: the `br` that reaches them sits inside a function and the bodies
 * belong to it — the same rule `functionDetect.ts` applies to the x86 tables.
 */
export function detectArm64Functions(
  bytes: Uint8Array,
  baseAddress: number,
  ctx: Arm64Context,
  options?: {
    exports?: { name: string; address: number }[];
    entryPoint?: number;
    pdataFunctions?: CodeRange[];
    handlerAddresses?: number[];
  },
): DetectResult {
  const endAddress = baseAddress + bytes.length;
  const inSection = (addr: number) => addr >= baseAddress && addr < endAddress;
  const addrSet = new Set<number>();
  const nameMap = new Map<number, string>();
  const pdataEndMap = new Map<number, number>();

  for (const rf of options?.pdataFunctions ?? []) {
    if (!inSection(rf.beginAddress)) continue;
    addrSet.add(rf.beginAddress);
    pdataEndMap.set(rf.beginAddress, rf.endAddress);
  }

  for (const ha of options?.handlerAddresses ?? []) {
    if (!inSection(ha)) continue;
    addrSet.add(ha);
    nameMap.set(ha, `__handler_${ha.toString(16)}`);
  }

  if (options?.entryPoint !== undefined && inSection(options.entryPoint)) {
    addrSet.add(options.entryPoint);
    nameMap.set(options.entryPoint, "entry_point");
  }

  for (const exp of options?.exports ?? []) {
    if (!inSection(exp.address)) continue;
    addrSet.add(exp.address);
    nameMap.set(exp.address, exp.name);
  }

  // Direct call targets. Anything landing strictly inside a `.pdata` extent is
  // an interior label, not a function — the same rule the x86 detector applies
  // to its byte-pattern candidates, and for the same reason: the linker's
  // record of where a function begins outranks an inference.
  //
  // The same sweep feeds the switch-dispatch reader, so the section is decoded
  // once for both.
  let jumpTables = new Map<number, number[]>();
  // Kept, unlike `disassembleArm64` above, because the evidence already in
  // `addrSet` is the file's own and does not come from the decoder. What it
  // costs is stated rather than left for the caller to guess (peek-a-bin-4s9):
  // no `bl` targets, so every leaf function `.pdata` is allowed to omit is
  // missing, and no dispatch tables. Thunk naming and tail-call detection are
  // not listed — the ARM64 detector has no such pass to lose.
  const omitted: DetectPass[] = ctx.cs ? [] : ["call-targets", "jump-tables"];
  if (ctx.cs) {
    try {
      const insidePdata = rangeTest(options?.pdataFunctions);
      const insns = disassembleArm64(bytes, baseAddress, ctx);
      for (const insn of insns) {
        if (insn.mnemonic !== "bl") continue;
        const m = insn.opStr.match(BL_TARGET);
        if (!m) continue;
        const target = Number(m[1]);
        if (!inSection(target) || insidePdata(target)) continue;
        addrSet.add(target);
      }
      jumpTables = findArm64JumpTables(insns, bytes, baseAddress);
    } catch (err) {
      // The section is not A64 (peek-a-bin-2t1). The *disassembly* declines
      // loudly, because instructions are all it has; detection does not have to
      // go with it. `.pdata`, the exports, the entry point and the unwind
      // handlers are the linker's own record and are still true of an ARM64EC
      // image — its ARM64 half is real. So the same degradation 4s9 defined for
      // a missing decoder applies here: answer with what the file states, and
      // say which passes did not run.
      if (!(err instanceof Arm64DecodeRateError)) throw err;
      omitted.push("call-targets", "jump-tables");
    }
  }

  const sortedAddrs = Array.from(addrSet).sort((a, b) => a - b);
  const functions: DisasmFunction[] = sortedAddrs.map((addr) => ({
    name: nameMap.get(addr) || `sub_${addr.toString(16).toUpperCase()}`,
    address: addr,
    size: 0,
  }));

  for (let i = 0; i < functions.length; i++) {
    const pdataEnd = pdataEndMap.get(functions[i].address);
    if (pdataEnd) {
      functions[i].size = pdataEnd - functions[i].address;
    } else if (i < functions.length - 1) {
      functions[i].size = functions[i + 1].address - functions[i].address;
    } else {
      functions[i].size = endAddress - functions[i].address;
    }
  }

  return { functions, jumpTables: Array.from(jumpTables.entries()), omitted };
}
