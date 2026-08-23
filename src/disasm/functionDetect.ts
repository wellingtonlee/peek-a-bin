/**
 * Shared function detection, disassembly, and xref building logic.
 * Extracted from disasm.worker.ts so both the Web Worker and the MCP server
 * can reuse the same algorithms.
 */

import { formatIOCTL, isPlausibleIOCTL } from "../analysis/driver";
import { classifyArm64Branch } from "./arm64Operands";
import { type CapstoneScan, createScan, requireCapstone } from "./capstoneWindow";
import { gridScan, type SweptInsn, sweepX86, type X86SweepCache } from "./linearSweep";
import { resolveRipTarget } from "./ripRelative";
import { MAX_SEH32_HEAD_INSNS, type Seh32Reader, seh32FuncletsOfPrologue } from "./seh32";
import { pushedImmediate, type StackInsn } from "./stackIdiom";
import type { DisasmFunction, Instruction, Xref } from "./types";

/** Context maps passed in instead of module-level state */
export interface DisasmContext {
  cs32: any;
  cs64: any;
  stringMap: Map<number, string>;
  iatMap: Map<number, { lib: string; func: string }>;
  driverMode: boolean;
}

// The module-level `CHUNK_SIZE = 0x10000` that used to size the scan loops here
// is gone: every `cs.disasm` in this module now goes through `createScan`,
// which owns the window. 0x10000 sat within 1 KiB of the WASM stack cliff and
// two-thirds of the way to the WASM heap ceiling, and going over either killed
// the decoder silently — see `./capstoneWindow.ts` for the measurements.

/**
 * The comment text for a resolved string reference.
 *
 * Exported because the ARM64 decoration path in `./arm64.ts` annotates from its
 * own reference resolver (`findArm64AddressRefs`) rather than from `mapInsn`'s
 * x86 operand grammar, and two elision rules for the same annotation would
 * drift — the same reason `ripRelative.ts` and `sections.ts` exist.
 */
export function stringComment(str: string): string {
  return str.length > 60 ? str.substring(0, 57) + "..." : str;
}

/**
 * Copy one decoded instruction, annotating it with what it references.
 *
 * **The reference resolution here is an x86 operand grammar, and only the x86
 * callers may use it.** It asks `resolveRipTarget` for a `[rip ± 0x..]` target,
 * and failing that scans the operand string for any `0x…` literal that is a
 * known string or IAT address. Both are sound on x86, where an operand really
 * can carry an absolute address (`mov eax, [0x404000]`, `push 0x40a010`).
 *
 * Neither is sound on A64, where no operand ever names a data address: a
 * literal in an A64 operand is a branch target or an `adrp` *page base*, and a
 * page base matching a data address is a coincidence rather than a reference
 * (peek-a-bin-vg3). So `arm64.ts` passes empty maps here and applies its own
 * annotation — see `decorateArm64Sweep`.
 */
export function mapInsn(
  insn: any,
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
): Instruction {
  const instruction: Instruction = {
    address: insn.address,
    bytes: insn.bytes,
    mnemonic: insn.mnemonic,
    opStr: insn.opStr,
    size: insn.size,
  };

  if (stringMap.size > 0) {
    const ripTarget = resolveRipTarget(insn);
    if (ripTarget !== null && stringMap.has(ripTarget)) {
      instruction.comment = stringComment(stringMap.get(ripTarget)!);
    }
    if (!instruction.comment) {
      const addressMatch = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
      if (addressMatch) {
        for (const addrStr of addressMatch) {
          const addr = parseInt(addrStr, 16);
          if (stringMap.has(addr)) {
            instruction.comment = stringComment(stringMap.get(addr)!);
            break;
          }
        }
      }
    }
  }

  if (iatMap.size > 0 && !instruction.comment) {
    const ripTarget = resolveRipTarget(insn);
    if (ripTarget !== null) {
      const iat = iatMap.get(ripTarget);
      if (iat) instruction.comment = `${iat.lib}!${iat.func}`;
    }
    if (!instruction.comment) {
      const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
      if (addrMatches) {
        for (const addrStr of addrMatches) {
          const addr = parseInt(addrStr, 16);
          const iat = iatMap.get(addr);
          if (iat) {
            instruction.comment = `${iat.lib}!${iat.func}`;
            break;
          }
        }
      }
    }
  }

  // IOCTL annotation (driver mode only)
  if (driverMode && !instruction.comment) {
    const hexMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
    if (hexMatches) {
      for (const hexStr of hexMatches) {
        const val = parseInt(hexStr, 16);
        if (isPlausibleIOCTL(val)) {
          const decoded = formatIOCTL(val);
          if (decoded) {
            instruction.comment = decoded;
            break;
          }
        }
      }
    }
  }

  return instruction;
}

export function disassemble(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  ctx: DisasmContext,
  scanOverride?: CapstoneScan,
): Instruction[] {
  // `requireCapstone`, not `if (!cs) return []`: this function's entire output
  // is what the decoder produced, so an empty list is a complete-looking answer
  // for a section full of code (peek-a-bin-cen). `ctx.cs32`/`ctx.cs64` are
  // undefined until the worker's WASM bootstrap resolves and stay undefined if
  // it fails, and only the `init` RPC awaits it — so this is reachable, not
  // theoretical.
  const cs = requireCapstone(is64 ? ctx.cs64 : ctx.cs32, "linear disassembly");
  const instructions: Instruction[] = [];
  // `hybridDisassemble` passes its own scan here so the gap fill is served from
  // the same held sweep the rest of it is — see {@link gridScan}. It is the
  // caller's scan and not a caller's *decoder*, so this function still cannot
  // reach `cs.disasm` by any route (`capstoneWindow.test.ts` scrapes for that).
  const scan = scanOverride ?? createScan(cs, "linear disassembly");
  let offset = 0;

  while (offset < bytes.length) {
    const insns = scan.decode(bytes, offset, bytes.length, baseAddress + offset);
    for (const insn of insns) {
      instructions.push(mapInsn(insn, ctx.stringMap, ctx.iatMap, ctx.driverMode));
    }
    if (insns.length === 0) {
      offset += 1;
    } else {
      const lastInsn = insns[insns.length - 1];
      const decoded = lastInsn.address - (baseAddress + offset) + lastInsn.size;
      offset += decoded;
    }
  }

  return instructions;
}

/**
 * A detection pass whose evidence comes from decoded instructions.
 *
 * Named individually rather than as one "degraded" bit because they are lost
 * independently and they cost different things: without `call-targets` the
 * function list is short by every leaf function nothing else records, without
 * `jump-tables` a switch dispatch is a dead-end block, without `thunk-names`
 * an import thunk is `sub_401000` instead of `CreateFileW`, and without
 * `tail-calls` a jump-terminated function looks like it simply ends.
 */
export type DetectPass = "call-targets" | "jump-tables" | "thunk-names" | "tail-calls";

export interface DetectResult {
  functions: DisasmFunction[];
  jumpTables: [number, number[]][];
  /**
   * `[start, end)` of the bytes the tables themselves occupy, deduped.
   *
   * **Not the same population as `jumpTables`, in one direction.** Every table
   * whose cases were recovered contributes a span, and so does an *unbounded*
   * dispatch, whose extent {@link unboundedTableExtent} establishes without
   * being able to state a case count — the bytes are data either way, and that
   * is all a span claims (peek-a-bin-7lb9). So a span with no entry in
   * `jumpTables` is normal; the reverse is not.
   *
   * A jump table is data in the middle of a code section, and nothing in the
   * image says so: recursive descent never walks into one, so `hybridDisassemble`
   * phase 2 reaches it as an uncovered gap and decodes the case addresses as
   * instructions. On t32.exe that turned the 32 bytes at 0x4086a4 into six
   * conditional jumps aiming past the end of the function they were filed under
   * (peek-a-bin-y1di). Pass these to `hybridDisassemble` and those bytes are
   * left alone.
   *
   * Empty is not "no tables": a table this could neither size nor locate is a
   * table that was not read at all, and one read from outside the code window
   * (an x64 `.rdata` RVA table) is reported here too but falls outside the bytes
   * the sweep sees.
   */
  jumpTableSpans: [number, number][];
  /**
   * Passes that did not run, so their contribution is missing from `functions`
   * and `jumpTables`. **Empty means this is the whole answer.**
   *
   * `detectFunctions` and `detectArm64Functions` deliberately keep answering
   * without a decoder — unlike `disassemble`/`hybridDisassemble`/`buildAllXrefs`,
   * which throw {@link CapstoneUnavailableError}, because *their* entire output
   * is instructions (peek-a-bin-cen). Detection's evidence is mostly not: the
   * `.pdata` extents, exports, the entry point, the unwind handlers and the
   * x86 byte-pattern scans are all things the file itself states, and returning
   * those is a smaller claim than returning nothing.
   *
   * But it is a *smaller* claim, and until this field existed nothing said so —
   * a caller could not tell a decoder-less detection from a complete one
   * (peek-a-bin-4s9). That is the same defect class as a short read that
   * reports success.
   *
   * Only passes this architecture *has* are ever listed. The ARM64 detector has
   * no thunk or tail-call pass at all, so their absence is not an omission and
   * naming them here would misreport a design decision as a degradation.
   */
  omitted: DetectPass[];
}

/**
 * A readable span of the image, keyed by virtual address.
 *
 * Detection is handed the code section and nothing else, which is enough for
 * the x86 layout (MSVC drops the table into `.text`, right after the function
 * that dispatches through it) but not for the x64 one: the RVA tables x64
 * compilers emit live in `.rdata`, outside the disassembly window. Callers that
 * can supply those bytes pass them here; callers that cannot still get every
 * table that happens to sit inside the code section.
 */
export interface DataWindow {
  /** Virtual address `bytes[0]` is loaded at. */
  base: number;
  bytes: Uint8Array;
}

/** Little-endian reads at a virtual address, or null when nothing maps it. */
interface ImageReader {
  u8(addr: number): number | null;
  i32(addr: number): number | null;
  u32(addr: number): number | null;
  u64(addr: number): number | null;
}

function makeImageReader(windows: DataWindow[]): ImageReader {
  const at = (addr: number, width: number): { b: Uint8Array; o: number } | null => {
    for (const w of windows) {
      const o = addr - w.base;
      if (o >= 0 && o + width <= w.bytes.length) return { b: w.bytes, o };
    }
    return null;
  };
  const raw32 = (addr: number): number | null => {
    const m = at(addr, 4);
    if (!m) return null;
    return m.b[m.o] | (m.b[m.o + 1] << 8) | (m.b[m.o + 2] << 16) | (m.b[m.o + 3] << 24);
  };
  return {
    u8: (addr) => {
      const m = at(addr, 1);
      return m === null ? null : m.b[m.o];
    },
    i32: (addr) => {
      const v = raw32(addr);
      return v === null ? null : v | 0;
    },
    u32: (addr) => {
      const v = raw32(addr);
      return v === null ? null : v >>> 0;
    },
    u64: (addr) => {
      const lo = raw32(addr);
      const hi = raw32(addr + 4);
      if (lo === null || hi === null) return null;
      return (hi >>> 0) * 0x100000000 + (lo >>> 0);
    },
  };
}

/**
 * Hard ceiling on entries read from one table.
 *
 * Nothing in a PE records a jump table's length — the bounds check in front of
 * the dispatch is the only statement of it, and that comes from the same bytes
 * a hostile file controls. Reading past the end does not fail loudly; it
 * invents case targets out of whatever follows. So the compared immediate is
 * capped here as well as being required, and every entry still has to resolve
 * into the code window before it is accepted.
 */
const MAX_JUMP_TABLE_CASES = 512;

/** How far back the x64 chain walk looks. `lea`/load/`add`/`jmp` plus the check. */
const MAX_RECENT = 16;

/**
 * Every x86-64 general-register spelling Capstone prints, mapped to its 64-bit
 * name. The idiom mixes widths on purpose — the table load writes `ecx` and the
 * `add` that consumes it reads `rcx` — so registers are only ever compared by
 * family.
 */
const REG_FAMILY = new Map<string, string>();
{
  const families: string[][] = [
    ["rax", "eax", "ax", "al", "ah"],
    ["rbx", "ebx", "bx", "bl", "bh"],
    ["rcx", "ecx", "cx", "cl", "ch"],
    ["rdx", "edx", "dx", "dl", "dh"],
    ["rsi", "esi", "si", "sil"],
    ["rdi", "edi", "di", "dil"],
    ["rbp", "ebp", "bp", "bpl"],
    ["rsp", "esp", "sp", "spl"],
  ];
  for (let i = 8; i <= 15; i++) families.push([`r${i}`, `r${i}d`, `r${i}w`, `r${i}b`]);
  for (const fam of families) for (const name of fam) REG_FAMILY.set(name, fam[0]);
}

/** 64-bit name of the register `name` belongs to, or null if it is not one. */
function regFamily(name: string): string | null {
  return REG_FAMILY.get(name.trim().toLowerCase()) ?? null;
}

/** `mov rax, rcx` → `["rax", "rcx"]`, for operand strings of exactly two registers. */
function regPair(opStr: string): [string, string] | null {
  const parts = opStr.split(",");
  if (parts.length !== 2) return null;
  const a = regFamily(parts[0]);
  const b = regFamily(parts[1]);
  return a && b ? [a, b] : null;
}

/** Destination register family of `dst, src`-shaped operands, or null. */
function destReg(opStr: string): string | null {
  const first = opStr.split(",")[0];
  return first === undefined ? null : regFamily(first);
}

/** Immediate compared by a `cmp reg, N`, hex or decimal, or null. */
function cmpImmediate(opStr: string): number | null {
  const hexMatch = opStr.match(/,\s*0x([0-9a-fA-F]+)$/);
  if (hexMatch) return parseInt(hexMatch[1], 16);
  const decMatch = opStr.match(/,\s*(\d+)$/);
  if (decMatch) return parseInt(decMatch[1], 10);
  return null;
}

/**
 * The constant a register holds at `before`, or null when it is not a constant.
 *
 * MSVC spells a small bound as `push 7` / `pop ecx` — two bytes against the five
 * of `mov ecx, 7` — and then compares against the register, so the check in
 * front of a 32-bit dispatch reads `cmp eax, ecx` with the length one step
 * further back. {@link readAbsoluteTable} used to see only the register and
 * refuse the table (peek-a-bin-mk42).
 *
 * Both recognised forms state a literal. Anything else that writes the register
 * ends the search rather than being followed: a bound this cannot read is a
 * table that is not read at all, which is the same answer the compared-immediate
 * path gives, and it is the safe direction — every entry still has to resolve
 * into the code window, but the *count* is the only statement of the table's
 * length there is.
 */
function constantRegisterValue(reg: string, recent: StackInsn[], before: number): number | null {
  for (let ri = before - 1; ri >= 0; ri--) {
    const p = recent[ri];
    const mn = p.mnemonic.toLowerCase();
    // A call clobbers every register this could be about, as in the chain walk.
    if (mn === "call") return null;
    if (mn === "pop") {
      if (regFamily(p.opStr) !== reg) continue;
      return pushedImmediate(recent, ri);
    }
    if (destReg(p.opStr) !== reg) continue;
    return mn === "mov" ? cmpImmediate(p.opStr) : null;
  }
  return null;
}

const SCALE4_BASE_FIRST =
  /\[\s*([a-z][a-z0-9]*)\s*\+\s*([a-z][a-z0-9]*)\s*\*\s*4\s*(?:([+-])\s*0x([0-9a-fA-F]+)\s*)?\]/i;
const SCALE4_INDEX_FIRST =
  /\[\s*([a-z][a-z0-9]*)\s*\*\s*4\s*\+\s*([a-z][a-z0-9]*)\s*(?:([+-])\s*0x([0-9a-fA-F]+)\s*)?\]/i;

/**
 * `byte ptr [rcx + r9 + 0x2f30]` → the two registers and the displacement.
 *
 * The *unscaled* two-register form, which is how the byte index table of a
 * dense switch is addressed. Capstone prints a SIB scale of 1 by leaving it
 * out — verified against the shipped `capstone.wasm`, which renders
 * `42 0f b6 84 09 00 10 00 00` as `byte ptr [rcx + r9 + 0x1000]` — so the `*1`
 * here is optional rather than expected.
 *
 * The two registers are returned unordered on purpose. Which of them Capstone
 * prints first follows the SIB base/index fields, and the operand text does not
 * say which is the image base; the caller knows that from the `lea` and matches
 * on it. Requiring a scale of exactly 1 is what keeps this from also matching
 * the `*4` entry load — `[r9 + rax*4 + 0x2000]` has a `*` where this pattern
 * needs a `+`, a `-` or a `]`.
 */
const SCALE1_MEM =
  /\[\s*([a-z][a-z0-9]*)\s*(?:\*\s*1\s*)?\+\s*([a-z][a-z0-9]*)\s*(?:\*\s*1\s*)?(?:([+-])\s*0x([0-9a-fA-F]+)\s*)?\]/i;

function parseScale1Load(opStr: string): { a: string; b: string; disp: number } | null {
  const m = opStr.match(SCALE1_MEM);
  if (!m) return null;
  const a = regFamily(m[1]);
  const b = regFamily(m[2]);
  if (!a || !b) return null;
  const disp = m[3] ? (m[3] === "-" ? -1 : 1) * parseInt(m[4], 16) : 0;
  return { a, b, disp };
}

/** `dword ptr [r9 + rax*4 + 0x1c]` → base `r9`, index `rax`, displacement `0x1c`. */
function parseScale4Load(opStr: string): { base: string; index: string; disp: number } | null {
  let m = opStr.match(SCALE4_BASE_FIRST);
  let baseName: string | undefined;
  let indexName: string | undefined;
  if (m) {
    baseName = m[1];
    indexName = m[2];
  } else {
    m = opStr.match(SCALE4_INDEX_FIRST);
    if (!m) return null;
    indexName = m[1];
    baseName = m[2];
  }
  const base = regFamily(baseName);
  const index = regFamily(indexName);
  if (!base || !index) return null;
  const disp = m[3] ? (m[3] === "-" ? -1 : 1) * parseInt(m[4], 16) : 0;
  return { base, index, disp };
}

/**
 * The x86-64 RVA jump table, recovered backwards from a `jmp <reg>`.
 *
 * x64 code is position-independent, so a switch cannot name its table in the
 * dispatching instruction the way 32-bit code does. Both compilers on Windows
 * spell it as a dependency chain instead, and the two spellings differ only in
 * where the `lea` points:
 *
 * ```text
 *   MSVC                                    GCC / clang
 *   lea     r9,  [rip + N]   ; __ImageBase  lea rdx, [rip + N]   ; the table
 *   mov     ecx, [r9 + rax*4 + tableRva]    movsxd rax, [rdx + rcx*4]
 *   add     rcx, r9                         add rax, rdx
 *   jmp     rcx                             jmp rax
 * ```
 *
 * Reading `lea` target + load displacement as the table address and `lea`
 * target + entry as the case target covers both: MSVC's displacement carries
 * the table's RVA and its entries are image-relative, GCC's displacement is
 * zero and its entries are table-relative. Entries are **signed 32-bit** and
 * relative to that base — never absolute addresses, which is what the 32-bit
 * path reads and why pointing this one at the same decoder would produce
 * plausible-looking nonsense.
 *
 * Returns the table location, the register the bounds check must be about, and
 * where in `recent` the load sits — the check has to come before the load, not
 * merely before the jump, because the load's destination is routinely the index
 * register itself (`movsxd rax, [rdx + rax*4]`). The caller does the reading,
 * so the ceiling on how much is read stays in one place.
 */
function recoverX64RvaChain(
  jmpInsn: StackInsn,
  recent: StackInsn[],
): {
  table: number;
  base: number;
  /** The register the `lea` wrote — `base`'s name, which the dense form matches on. */
  baseName: string;
  indexReg: string;
  loadIndex: number;
} | null {
  const jmpReg = regFamily(jmpInsn.opStr);
  if (!jmpReg) return null;

  // Backwards from the jump: `add off, base`, then the scaled load into `off`,
  // then the `lea` that materialised `base`. Each step takes the nearest match
  // and gives up the moment something else writes the register it is chasing —
  // a later write means the value the jump used came from somewhere this walk
  // has not modelled, and guessing there is how a table gets misread.
  let sought = jmpReg;
  let stage: "add" | "load" | "lea" = "add";
  let baseReg: string | null = null;
  let indexReg: string | null = null;
  let loadIndex = 0;
  let disp = 0;

  for (let ri = recent.length - 1; ri >= 0; ri--) {
    const p = recent[ri];
    const mn = p.mnemonic.toLowerCase();
    // A call clobbers every volatile register, which is all of the ones this
    // idiom uses.
    if (mn === "call") return null;

    if (stage === "add") {
      if (mn === "add") {
        const pair = regPair(p.opStr);
        if (pair && pair[0] === sought) {
          baseReg = pair[1];
          stage = "load";
          continue;
        }
      }
      if (destReg(p.opStr) === sought) return null;
      continue;
    }

    if (stage === "load") {
      if ((mn === "movsxd" || mn === "movsx" || mn === "mov") && destReg(p.opStr) === sought) {
        const mem = parseScale4Load(p.opStr);
        if (!mem || mem.base !== baseReg) return null;
        indexReg = mem.index;
        disp = mem.disp;
        loadIndex = ri;
        sought = baseReg;
        stage = "lea";
        continue;
      }
      // Either register being rewritten here ends the walk: `sought` because
      // the jump then added something this walk has not modelled, `baseReg`
      // because the value added was not the one the `lea` produced. Following
      // the chain past either reports a table read from an address the program
      // never used.
      if (destReg(p.opStr) === sought || destReg(p.opStr) === baseReg) return null;
      continue;
    }

    // stage === "lea"
    if (mn === "lea" && destReg(p.opStr) === sought) {
      const target = resolveRipTarget(p);
      if (target === null) return null;
      return {
        table: target + disp,
        base: target,
        baseName: sought,
        indexReg: indexReg!,
        loadIndex,
      };
    }
    if (destReg(p.opStr) === sought) return null;
  }

  return null;
}

/**
 * The register a scaled memory operand subscripts with — the *index*.
 *
 * `dword ptr [edx*4 + 0x40b8f0]` and `byte ptr [ecx + edx*4 + 8]` both answer
 * `rdx`. An x86 operand carries at most one scale, so a single match is the
 * whole answer, and the family rather than the spelling is returned for the
 * reason {@link REG_FAMILY} exists: the bound is routinely compared at a
 * different width from the subscript.
 */
function scaledIndexRegister(opStr: string): string | null {
  const m = opStr.match(/\b([a-z][a-z0-9]*)\s*\*\s*[1248]\b/i);
  return m ? regFamily(m[1]) : null;
}

/**
 * Base mnemonics of the x86 string primitives, which write RSI/RDI implicitly —
 * and RCX as well under a `rep` prefix — without naming them in an operand.
 *
 * They matter to {@link boundedCaseCount} only as *refusals*: a bound found
 * across one of these is a bound on a value the register no longer holds. The
 * SSE `movsd`/`cmpsd` share two of the spellings and write no general register
 * at all, so this over-refuses for them; over-refusing costs a table that is
 * not read, which is the direction every refusal here errs in.
 */
const STRING_PRIMITIVES = new Set([
  "movs",
  "movsb",
  "movsw",
  "movsd",
  "movsq",
  "stos",
  "stosb",
  "stosw",
  "stosd",
  "stosq",
  "lods",
  "lodsb",
  "lodsw",
  "lodsd",
  "lodsq",
  "scas",
  "scasb",
  "scasw",
  "scasd",
  "scasq",
  "cmps",
  "cmpsb",
  "cmpsw",
  "cmpsd",
  "cmpsq",
]);

/** `"rep movsd"` → `"movsd"`. Capstone spells a string prefix into the mnemonic. */
function withoutRepPrefix(mnemonic: string): string {
  const parts = mnemonic.toLowerCase().split(/\s+/);
  return parts.length > 1 && parts[0].startsWith("rep") ? parts[parts.length - 1] : parts[0];
}

/**
 * Upper bound on case count from the bounds check in front of a dispatch.
 *
 * THE ONE DECLARATION OF WHAT BOUNDS A JUMP TABLE. It used to be two:
 * {@link readAbsoluteTable} walked back to the *first* `cmp` it met, read its
 * immediate and stopped — never asking which register was compared — while this
 * function tracked the index register but could not read a bound carried in a
 * register. So the two paths disagreed about the same question in *both*
 * directions, and each was wrong where the other was right (peek-a-bin-padl).
 *
 * Three things count as a bound, all of them about the index register:
 *
 *  - `cmp <index>, <imm>` — `imm + 1`, an upper bound whichever way the `jcc`
 *    below it reads (`ja` admits `0..imm`, `jb` only `0..imm-1`).
 *  - `cmp <index>, <reg>` where the register provably holds a constant. MSVC
 *    spells a small bound `push 7` / `pop ecx` and compares against that, two
 *    bytes cheaper than `cmp eax, 7`; see {@link constantRegisterValue}
 *    (peek-a-bin-mk42).
 *  - `and <index>, <imm>` — `imm + 1`. A mask states the index's range
 *    *exactly*, where a `cmp` states it only together with the sense of the
 *    branch, so this is the stronger of the two forms rather than a weaker
 *    substitute for one. CLAUDE.md records `overlappedTableExtent` refusing a
 *    mask, and that refusal stands: there the question was which BYTES are
 *    opcode, which a mask says nothing about, and admitting it would have
 *    widened the vocabulary at every dispatch. Here the question is the index's
 *    range, which is the question this function already asks, and the mask
 *    counts only for the register the dispatch actually subscripts with.
 *
 * A `mov`/`movsxd`/`movzx`/`movsx` that copied the index from somewhere else is
 * followed one step at a time back to whatever the check named. **Any other
 * write of the sought register ends the search**, because a bound on a value the
 * register no longer holds is not a bound — the rule `conditionSpoiled` applies
 * to a guard. An index *loaded from memory* therefore ends it with no count:
 * that is MSVC's dense two-table form (`movzx idx, byte ptr [...]` selecting
 * into the wide table), and no count is the right answer *for this function* —
 * the index it was asked about is an entry number, and entry numbers are not
 * bounded by anything. The bound that form does have is on the *case* value one
 * step further back, and {@link recoverDenseByteTable} is what goes and gets it.
 *
 * `cmp`, `test` and `push` are the read-only forms: none writes a register, so
 * naming the sought register as their first operand is not a clobber.
 *
 * Without a bound there is no length, and a table with no length yields no
 * cases — see {@link readAbsoluteTable}, whose answer is then the bytes alone.
 *
 * `before` is the position of the table load, not of the jump: the load's
 * destination is routinely the index register itself (`movsxd rax, [rdx +
 * rax*4]`), so a search from the jump meets it and reads it as a clobber.
 */
function boundedCaseCount(indexReg: string, recent: StackInsn[], before: number): number {
  let sought = indexReg;
  for (let ri = before - 1; ri >= 0; ri--) {
    const p = recent[ri];
    const mn = p.mnemonic.toLowerCase();
    // A call clobbers every register a bound could be about, as in
    // `constantRegisterValue` and the chain walk.
    if (mn === "call") return 0;
    if (mn === "cmp") {
      if (destReg(p.opStr) !== sought) continue;
      const imm = cmpImmediate(p.opStr);
      if (imm !== null) return imm + 1;
      const pair = regPair(p.opStr);
      const bound = pair ? constantRegisterValue(pair[1], recent, ri) : null;
      return bound === null ? 0 : bound + 1;
    }
    if (mn === "and") {
      if (destReg(p.opStr) !== sought) continue;
      const imm = cmpImmediate(p.opStr);
      return imm === null ? 0 : imm + 1;
    }
    if (mn === "mov" || mn === "movsxd" || mn === "movzx" || mn === "movsx") {
      const pair = regPair(p.opStr);
      if (pair && pair[0] === sought) {
        sought = pair[1];
        continue;
      }
      if (destReg(p.opStr) === sought) return 0;
      continue;
    }
    if (mn === "test" || mn === "push") continue;
    if (STRING_PRIMITIVES.has(withoutRepPrefix(p.mnemonic))) {
      if (sought === "rsi" || sought === "rdi" || sought === "rcx") return 0;
      continue;
    }
    if (destReg(p.opStr) === sought) return 0;
  }
  return 0;
}

/**
 * Build `addr => is addr inside some [begin, end) .pdata range`.
 *
 * The ranges are sorted by start and carry a running maximum end, so one binary
 * search answers the question even when the table is unsorted or its entries
 * overlap — a linker's `.pdata` is neither, but nothing between the file and
 * here checks that, and a hostile one is cheap to write. Addresses are held as
 * doubles because these are 64-bit VAs: `0x140001000` does not survive the
 * int32 coercion an `Int32Array` (or a bitwise operator) would apply.
 *
 * An address exactly on a `beginAddress` counts as covered. It is seeded as a
 * function from that same table either way, so the answer cannot differ.
 */
function pdataRangeTest(
  ranges?: { beginAddress: number; endAddress: number }[],
): (addr: number) => boolean {
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
    let last = -1; // largest index whose start is at or below addr
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
 * One dispatch's recovered table: where it points, and which bytes it occupies.
 *
 * `spans` are `[start, end)` in virtual addresses, and only ever cover entries
 * actually read — the read stops at the first entry that does not resolve, so a
 * table shorter than its bounds check claims is reported at its real length.
 * They matter because those bytes are *data* sitting in the middle of a code
 * section: `hybridDisassemble`'s gap fill decodes everything recursive descent
 * did not reach, and a table is uncovered by construction (peek-a-bin-y1di).
 *
 * A span may lie outside the code window — an x64 RVA table lives in `.rdata` —
 * so a consumer clamps rather than assuming.
 *
 * `dataOnly` marks the one reading that reports bytes and **no cases**: an
 * unbounded dispatch, where {@link unboundedTableExtent} can say where the table
 * is without being able to say how long the switch is. Empty `targets` with a
 * non-empty `spans` cannot arise any other way, but the flag is explicit so the
 * caller states which question it is answering rather than inferring it from an
 * array length.
 *
 * `deferredBase` is the one refusal that is not final. It names a base the read
 * could not use *because the base is not an address at all* — MSVC overlaps an
 * unbounded table's entry 0 with the tail of the instruction in front of it to
 * save four bytes, so the base slot's bytes are opcode. Whether that is what
 * happened is a question about an instruction at a **higher** address than the
 * dispatch, which the linear `recent` window structurally cannot hold, so the
 * refusal is handed back to the sweep to finish once it gets there — see
 * {@link overlappedTableExtent} (peek-a-bin-xqxy).
 */
interface TableRead {
  targets: number[];
  spans: [number, number][];
  dataOnly?: true;
  deferredBase?: number;
  /**
   * The table base this reading was about, whenever one was identified — which
   * is what lets the sweep remember a table it has already read, for the
   * dispatches further on that name the same base with no bound of their own in
   * reach. See {@link readAbsoluteTable}'s `knownTables` (peek-a-bin-padl).
   */
  base?: number;
}

/** The "nothing was recovered" answer, built fresh so no refusal aliases another. */
const noTable = (): TableRead => ({ targets: [], spans: [] });

/**
 * Least evidence that will make an unbounded dispatch's bytes data.
 *
 * The bounded path is content with two entries because the `cmp` in front of it
 * independently states a length; here the run of entries **is** the whole
 * evidence, so it has to be stronger. Four pointer-width words each holding an
 * address inside the code section is the bar. Measured over the whole code
 * section of the four corpus binaries at `d514274` — every maximal run of four
 * or more such words, whether or not a dispatch names it — there are 6/5/0/0
 * (t32/w32/t64/w64), and the only ones that intersect anything the
 * disassembler files as code are exactly the two real jump tables per 32-bit
 * binary. At a threshold of two it is 8/7/0/0 with 4/4 intersecting, which is
 * the reason this is not 2 (peek-a-bin-7lb9).
 */
const MIN_UNBOUNDED_TABLE_ENTRIES = 4;

/**
 * Where an *unbounded* dispatch's table is, when there is no saying how long it
 * is.
 *
 * A bounds check is the only statement of a switch's *length*, so without one
 * there are no case targets to report — reading `maxCases` entries out of thin
 * air is how a table gets misread, and reporting entries in an order that is
 * not case order is what peek-a-bin-div refused. But the bytes are still data
 * sitting in the middle of a code section, and `hybridDisassemble`'s gap fill
 * decodes anything nothing has claimed: at `d514274` the two unbounded tables in
 * each 32-bit corpus binary came out as 25 and 33 phantom instructions, and the
 * misaligned walk ran off the end of each and ate the first bytes of the case
 * body that follows (3 bytes on t32, 10 on w32) — real instructions replaced by
 * fiction. So the extent is recovered on its own, and reported as
 * {@link TableRead.dataOnly}: these bytes are not code, and that is the whole
 * claim.
 *
 * The extent is the maximal run of pointer-width words on the named base's own
 * grid, **each** holding an address inside the code section, scanned in *both*
 * directions from the base. Both halves are the machine's, not a guess:
 *
 *  - Stopping at the first word that is not a code address is the same test the
 *    bounded path already applies to every entry it reads.
 *  - The base is not necessarily the table's first entry, because the index is
 *    not necessarily non-negative. MSVC's reverse `memmove` does `neg ecx` and
 *    then `jmp dword ptr [ecx*4 + <base>]`, so the base names the *last* slot
 *    and the seven before it are the table (t32.exe 0x40b968, w32.exe
 *    0x409602). A forward-only scan reads one entry there and refuses.
 *
 * **It errs short, and that is the safe direction.** Over-reporting marks real
 * code as data, which deletes instructions from the output with nothing said;
 * under-reporting leaves them decoded as they are today. Three things keep it
 * short: the run must contain the named base, so a table whose base slot MSVC
 * overlapped with the preceding instruction to save four bytes is not answered
 * here at all — it is deferred to {@link overlappedTableExtent} via
 * {@link TableRead.deferredBase}, because the evidence needed is an instruction
 * this function cannot see; it stops dead at one non-resolving word rather than
 * tolerating a gap; and {@link MIN_UNBOUNDED_TABLE_ENTRIES} discards a short
 * run.
 *
 * Confined to the code section on purpose. A table in `.rdata` is not reached
 * by the gap fill, so there is nothing there for this to fix, and a run scanned
 * through data it cannot bound is exactly what it must not report.
 *
 * The corroboration is worth recording, because it comes from outside this
 * rule: on all four sites it fires on in the corpus the run length is 8, which
 * is exactly the bound the machine imposes (`cmp ecx, 8` / `jb`) — a bound
 * `readAbsoluteTable` cannot see because the compare is in a control-flow
 * predecessor that sits *later* in address order, so the linear `recent` window
 * never holds it.
 */
function unboundedTableExtent(
  tableBase: number,
  reader: ImageReader,
  ptrSize: number,
  codeStart: number,
  codeEnd: number,
): TableRead {
  const resolves = (addr: number): boolean => {
    if (addr < codeStart || addr + ptrSize > codeEnd) return false;
    const v = ptrSize === 8 ? reader.u64(addr) : reader.u32(addr);
    return v !== null && v >= codeStart && v < codeEnd;
  };
  if (!resolves(tableBase)) return { targets: [], spans: [], deferredBase: tableBase };
  let lo = tableBase;
  let hi = tableBase + ptrSize;
  const entries = () => (hi - lo) / ptrSize;
  while (entries() < MAX_JUMP_TABLE_CASES && resolves(lo - ptrSize)) lo -= ptrSize;
  while (entries() < MAX_JUMP_TABLE_CASES && resolves(hi)) hi += ptrSize;
  if (entries() < MIN_UNBOUNDED_TABLE_ENTRIES) return noTable();
  return { targets: [], spans: [[lo, hi]], dataOnly: true };
}

/**
 * Most pending {@link TableRead.deferredBase} entries carried at once.
 *
 * The prune rule below bounds the list to bases the sweep has not yet reached,
 * which for real output is a handful — 7 indexed dispatches are refused per
 * 32-bit corpus binary in total, and each one is pruned within a few
 * instructions. The cap is for a file that names thousands of bases far ahead of
 * every dispatch, which costs nothing to write and which nothing between the
 * bytes and here checks (same reasoning as {@link pdataRangeTest}'s sorted
 * ranges). Refusing to add one past the cap is the safe direction: a base never
 * settled is a span never reported, which is exactly the behaviour before this
 * existed.
 */
const MAX_PENDING_OVERLAP_BASES = 64;

/**
 * Where an unbounded dispatch's table is when MSVC **overlapped its entry 0
 * with the instruction in front of it**.
 *
 * {@link unboundedTableExtent} requires the run of code-pointer words to contain
 * the base the dispatch names, and at four sites in the corpus it does not,
 * because the base's four bytes are not an address — they are the tail of a
 * real instruction plus a `nop`. t32.exe:
 *
 * ```text
 *   40b7ec  and eax, 3                          ; index is 1..3, never 0
 *   40b7ef  add ecx, eax
 *   40b7f1  jmp dword ptr [eax*4 + 0x40b804]    ; base 0x40b804
 *   40b7f8  jmp dword ptr [ecx*4 + 0x40b900]
 *   40b7ff  nop
 *   40b800  jmp dword ptr [ecx*4 + 0x40b884]    ; 7 bytes: 40b800..40b806
 *   40b807  nop                                 ; so [0x40b804] = b8 40 00 90
 *   40b808  dd 0x40b814, 0x40b840, 0x40b864     ; entries 1..3, real
 *   40b814  and edx, ecx                        ; case body 1
 * ```
 *
 * Entry 0 is unreachable: the block is entered only when `test edi, 3` was
 * non-zero, so `and eax, 3` cannot produce 0, and the assembler spent its slot
 * on an instruction rather than four bytes of padding. The other three sites are
 * the same shape — t32.exe 0x40b985 (base 0x40b990) and w32.exe 0x409491 and
 * 0x409625.
 *
 * **The evidence is real rather than statistical: a byte that belongs to a
 * decoded instruction cannot be a table entry.** So the table's *bytes* begin at
 * the first grid slot past that instruction, and the slot the instruction ate is
 * excluded from the reported span — it is code, and marking it data would delete
 * the `jmp` in front of the dispatch.
 *
 * Three restrictions keep it as short as {@link unboundedTableExtent}, and each
 * refuses something this corpus contains:
 *
 *  - **The instruction must end *inside* the base slot** (`base < end <= base +
 *    ptrSize`). That is the idiom — one instruction's tail shared with entry 0 —
 *    and it is the whole claim. An instruction reaching further has swallowed a
 *    slot whole, and a "base" that deep inside code is not a table base. This is
 *    what refuses w32.exe 0x409498, whose base 0x4095a0 the sweep covers with a
 *    6-byte `add` running to 0x4095a5.
 *  - **The run is counted from the base, not from the span**, so
 *    {@link MIN_UNBOUNDED_TABLE_ENTRIES} is applied to the table's own length.
 *    The overlapped slot is a table slot — the dispatch names it — and it is one
 *    slot by the rule above, so four table entries means three readable words.
 *    Lowering the threshold instead would weaken every *unanchored* run, which
 *    is the population that number was calibrated against. This is what refuses
 *    t32.exe 0x40b7f8, whose base 0x40b900 is followed by nothing that resolves.
 *  - **A base some recovered table already dispatches to is refused by the
 *    caller.** An address a `jmp [table]` reaches is code, so it is not any
 *    table's slot. Both `0x40b900` and `0x4095a0` are case targets of the table
 *    recovered one dispatch earlier, which makes the negative-index shape —
 *    `sub ecx, 4` leaves ecx at 0xFFFFFFFC..0xFFFFFFFF, so the words read are
 *    *below* the base and are a table already recovered and already spanned —
 *    refused as a property rather than by the two counts above happening to
 *    disagree with it.
 *
 * The corroboration is from outside the rule, as it was for
 * {@link unboundedTableExtent}: all four sites carry `and <index>, 3`
 * immediately before the dispatch, on the very register the dispatch indexes
 * with. That bounds the index to `[0, 3]` — four slots, exactly the length this
 * finds, and exactly the one the overlap plus the run predicts. It is
 * deliberately not *used*: a mask is not a `cmp`, using it would widen the
 * bounded path's vocabulary at every dispatch in the corpus, and it says nothing
 * about which bytes are opcode, so on its own it would report a span covering
 * four bytes of a real `jmp`.
 */
function overlappedTableExtent(
  tableBase: number,
  insnEnd: number,
  reader: ImageReader,
  ptrSize: number,
  codeStart: number,
  codeEnd: number,
): TableRead {
  if (insnEnd <= tableBase || insnEnd > tableBase + ptrSize) return noTable();
  const resolves = (addr: number): boolean => {
    if (addr < codeStart || addr + ptrSize > codeEnd) return false;
    const v = ptrSize === 8 ? reader.u64(addr) : reader.u32(addr);
    return v !== null && v >= codeStart && v < codeEnd;
  };
  const start = tableBase + ptrSize;
  let hi = start;
  // Counted from the base, because the overlapped slot is entry 0 of the table
  // whose length this is testing — see the second restriction above.
  const entries = () => (hi - tableBase) / ptrSize;
  while (entries() < MAX_JUMP_TABLE_CASES && resolves(hi)) hi += ptrSize;
  if (entries() < MIN_UNBOUNDED_TABLE_ENTRIES) return noTable();
  return { targets: [], spans: [[start, hi]], dataOnly: true };
}

/**
 * Case targets of a table the dispatching instruction names itself.
 *
 * The 32-bit shape — `jmp dword ptr [eax*4 + 0x40941c]`, or a RIP-relative
 * operand on x64 — where the entries are absolute addresses of pointer width.
 *
 * The bounds check is the table's only length, and it is compared against a
 * register as readily as against an immediate (see
 * {@link constantRegisterValue}). Following the register is not a weaker claim
 * than reading the immediate: both are the same instruction saying the same
 * thing, and everything downstream of the count — the {@link
 * MAX_JUMP_TABLE_CASES} ceiling, and every entry having to resolve into the
 * code window — applies unchanged.
 *
 * The bound is {@link boundedCaseCount}'s answer and is about the register the
 * dispatch subscripts with. It used not to be: this function walked back to the
 * first `cmp` it met and read its immediate whatever register it named, which at
 * 9 dispatches per 32-bit corpus binary took the bound from an unrelated
 * register (peek-a-bin-padl).
 *
 * With no bound at all there are no cases *of this dispatch's own evidence*, and
 * `knownTables` is asked before giving up: a base another dispatch has already
 * read as a table of N entries holds those same N entries however it is reached,
 * so nothing new is claimed and no length is guessed at. Only the bytes at the
 * base are being reused — never a longer list than the first reading took, which
 * would be a length claim this dispatch has no evidence for. That is what keeps
 * the four MSVC memcpy/memset tails per 32-bit binary whose mask is out of
 * linear reach, and it is the only route by which the two dispatches that follow
 * the *unrolled* copy (t32 `0x40b8e7`, `0x40ba83`) are read at all.
 *
 * Failing that the answer is {@link unboundedTableExtent}'s: where the bytes
 * are, and nothing about what they mean. That fallback is deliberately
 * restricted to the *indexed* form — the operand naming a scale, i.e. an actual
 * array subscript. A plain `jmp dword ptr [0x40f0a8]` is an import thunk, not a
 * one-entry switch, and scanning a run of words out of the IAT is not a question
 * worth asking.
 */
function readAbsoluteTable(
  insn: StackInsn,
  recent: StackInsn[],
  reader: ImageReader,
  is64: boolean,
  codeStart: number,
  codeEnd: number,
  knownTables?: ReadonlyMap<number, number[]>,
): TableRead {
  let tableBase = 0;
  const scaleMatch = insn.opStr.match(/\[.*\*\d\s*\+\s*0x([0-9a-fA-F]+)\]/);
  if (scaleMatch) tableBase = parseInt(scaleMatch[1], 16);
  const indexed = tableBase !== 0;
  if (!tableBase && is64) {
    const ripTarget = resolveRipTarget(insn);
    if (ripTarget !== null) tableBase = ripTarget;
  }
  if (!tableBase) return noTable();

  const ptrSize = is64 ? 8 : 4;
  const indexReg = scaledIndexRegister(insn.opStr);
  const maxCases = indexReg ? boundedCaseCount(indexReg, recent, recent.length) : 0;
  // A count above the ceiling is a claim not to be trusted, and not an
  // invitation to go looking for a second reading — same rule as readRvaTable.
  if (maxCases > MAX_JUMP_TABLE_CASES) return noTable();

  const targets: number[] = [];
  for (let c = 0; c < maxCases; c++) {
    const entry = tableBase + c * ptrSize;
    const target = ptrSize === 8 ? reader.u64(entry) : reader.u32(entry);
    if (target === null || target < codeStart || target >= codeEnd) break;
    targets.push(target);
  }
  if (targets.length >= 2) {
    return {
      targets,
      spans: [[tableBase, tableBase + targets.length * ptrSize]],
      base: tableBase,
    };
  }
  // The same bytes, read once. A base already recovered as a table is a table,
  // and this dispatch reads it — no bound of its own is needed to say so.
  const known = indexed ? knownTables?.get(tableBase) : undefined;
  if (known && known.length >= 2) {
    return {
      targets: [...known],
      spans: [[tableBase, tableBase + known.length * ptrSize]],
      base: tableBase,
    };
  }
  // No switch was recovered — either nothing bounded the index, or the bound
  // read fewer than two cases forward from the named base, which is not a
  // switch and which the caller has always discarded. The fallback is the same
  // decision in both: the cases are unknown, the bytes may not be. It is the
  // *cases* that a bound is needed for, and the descending shape is exactly why
  // the two must be asked separately — MSVC's reverse `memmove` does have a
  // `cmp ecx, 8` in front of it, and reading eight entries *forward* from a
  // base that is the table's last slot finds one (peek-a-bin-7lb9).
  return indexed ? unboundedTableExtent(tableBase, reader, ptrSize, codeStart, codeEnd) : noTable();
}

/**
 * The byte index table of MSVC's *dense* switch, walked back from the entry
 * load of {@link recoverX64RvaChain}.
 *
 * A switch whose cases are dense but whose bodies are not all distinct gets two
 * tables instead of one — a byte per case saying which body it uses, and a dword
 * per distinct body:
 *
 * ```text
 *   cmp   ecx, 0x21
 *   ja    <default>
 *   lea   r9,  [rip + N]                      ; __ImageBase
 *   movzx eax, byte ptr [rcx + r9 + byteRva]  ; entry = byteTable[case]
 *   mov   ecx, dword ptr [r9 + rax*4 + dwordRva]
 *   add   rcx, r9
 *   jmp   rcx
 * ```
 *
 * The chain walk already recovers everything from the `mov` onwards, and then
 * {@link boundedCaseCount} finds no bound, because `rax` is an entry number and
 * nothing bounds an entry number. This is the missing step: the `movzx` names
 * the byte table in its displacement and the *case* register in its other
 * operand, and the `cmp` in front of the whole thing bounds that.
 *
 * Both registers of the `movzx` are compared against the `lea`'s: exactly one
 * must be it, because the operand text does not say which is the image base
 * (see {@link parseScale1Load}) and getting it backwards would read the byte
 * table from the case index. `movzx` specifically, not `mov` or `movsx`: a
 * table entry that selects a row is an unsigned index, and widening it any other
 * way is not this idiom.
 */
function recoverDenseByteTable(
  chain: NonNullable<ReturnType<typeof recoverX64RvaChain>>,
  recent: StackInsn[],
): { byteTable: number; caseReg: string; loadIndex: number } | null {
  for (let ri = chain.loadIndex - 1; ri >= 0; ri--) {
    const p = recent[ri];
    const mn = p.mnemonic.toLowerCase();
    // Same reason as in the chain walk: a call clobbers every register here.
    if (mn === "call") return null;
    if (destReg(p.opStr) !== chain.indexReg) continue;
    if (mn !== "movzx") return null;
    if (!/\bbyte ptr\b/i.test(p.opStr)) return null;
    const mem = parseScale1Load(p.opStr);
    if (!mem) return null;
    const aIsBase = mem.a === chain.baseName;
    const bIsBase = mem.b === chain.baseName;
    if (aIsBase === bIsBase) return null;
    return {
      byteTable: chain.base + mem.disp,
      caseReg: aIsBase ? mem.b : mem.a,
      loadIndex: ri,
    };
  }
  return null;
}

/**
 * Case targets of an x86-64 RVA table reached through `jmp <reg>`.
 *
 * Three things bound the read, and all three are required: the chain has to
 * resolve (so the table address is the compiler's, not a guess), the index has
 * to have been bounds-checked (the only statement of the table's length), and
 * every entry has to land in the code window (so a table that is shorter than
 * its check claims stops at the first thing that is not a case body).
 *
 * The dense two-table form satisfies all three, just one step further back —
 * see {@link recoverDenseByteTable}. It used to be refused outright
 * (peek-a-bin-div), which was right at the time: entry *i* is not case *i*, so
 * reporting the dword table's targets in order files real code under wrong case
 * labels, and that is worse than reporting no switch. Reading it through the
 * byte table restores case order, so `targets[c]` means case `c` in both forms.
 *
 * **Unverified against a real image.** No binary in the local corpus contains
 * this shape — t64.exe and w64.exe hold no table-dispatched switch at all — so
 * the encodings, the operand spellings and the two tables' relationship are
 * checked against Capstone's real output and the documented idiom, and nothing
 * else. It cannot silently damage the single-table form: that path is taken
 * whenever `boundedCaseCount` succeeds, and this one only runs where the old
 * code returned an empty list.
 */
function readRvaTable(
  insn: StackInsn,
  recent: StackInsn[],
  reader: ImageReader,
  codeStart: number,
  codeEnd: number,
): TableRead {
  const chain = recoverX64RvaChain(insn, recent);
  if (!chain) return noTable();
  const maxCases = boundedCaseCount(chain.indexReg, recent, chain.loadIndex);
  if (maxCases <= 0 || maxCases > MAX_JUMP_TABLE_CASES) {
    // A count above the ceiling is a claim not to be trusted, not an invitation
    // to look for a second reading, so only the "no count" case falls through.
    return maxCases > 0 ? noTable() : readDenseRvaTable(chain, recent, reader, codeStart, codeEnd);
  }

  const targets: number[] = [];
  for (let c = 0; c < maxCases; c++) {
    const entry = reader.i32(chain.table + c * 4);
    if (entry === null) break;
    const target = chain.base + entry;
    if (target < codeStart || target >= codeEnd) break;
    targets.push(target);
  }
  if (targets.length === 0) return noTable();
  return { targets, spans: [[chain.table, chain.table + targets.length * 4]] };
}

/**
 * `targets[case] = base + int32(dwordTable[byteTable[case]])`.
 *
 * The byte table's length is the `cmp` in front of the dispatch, exactly as in
 * the single-table form. The dword table needs no separate bound: every entry
 * this reads is one the byte table pointed at, and each resulting target still
 * has to land in the code window.
 */
function readDenseRvaTable(
  chain: NonNullable<ReturnType<typeof recoverX64RvaChain>>,
  recent: StackInsn[],
  reader: ImageReader,
  codeStart: number,
  codeEnd: number,
): TableRead {
  const dense = recoverDenseByteTable(chain, recent);
  if (!dense) return noTable();
  const maxCases = boundedCaseCount(dense.caseReg, recent, dense.loadIndex);
  if (maxCases <= 0 || maxCases > MAX_JUMP_TABLE_CASES) return noTable();

  const targets: number[] = [];
  let maxRow = -1;
  for (let c = 0; c < maxCases; c++) {
    const row = reader.u8(dense.byteTable + c);
    if (row === null) break;
    const entry = reader.i32(chain.table + row * 4);
    if (entry === null) break;
    const target = chain.base + entry;
    if (target < codeStart || target >= codeEnd) break;
    maxRow = Math.max(maxRow, row);
    targets.push(target);
  }
  if (targets.length === 0) return noTable();
  // Both tables are data. The dword table is indexed by row rather than by case,
  // so its extent is the highest row reached and not the number of cases.
  return {
    targets,
    spans: [
      [dense.byteTable, dense.byteTable + targets.length],
      [chain.table, chain.table + (maxRow + 1) * 4],
    ],
  };
}

/**
 * Pattern candidates that sit strictly inside another candidate's matched bytes.
 *
 * The prologue table has entries that are prefixes of one another, and both fire
 * at once on the same function. The MSVC hot-patch prologue is the expensive
 * case: `8b ff 55 8b ec` (`mov edi, edi; push ebp; mov ebp, esp`) matches at the
 * function's real entry, and the plain `55 8b ec` matches two bytes in — so
 * every hot-patched function in a PE32 image was reported twice, and the first
 * of the pair got a size of 2. On t32.exe that is 154 of 447 functions,
 * every one of them a 2-byte `mov edi, edi` that decompiles to an empty body,
 * with the real body filed under the second entry. The x64 table has the same
 * shape (`40 53 48 83 ec` ⊃ `53 48 83 ec` ⊃ `48 83 ec`), where `.pdata` has been
 * covering for it.
 *
 * An address strictly inside a matched prologue is that same prologue seen from
 * the middle, so the outer match names the entry point and the inner one does
 * not. Only *pattern* candidates are removed: an address a call, an export, the
 * entry point or `.pdata` also vouches for is in `addrSet` already and is never
 * reached by this. So the worst case is losing a start whose only evidence was a
 * byte pattern beginning inside another byte pattern — which is the benign
 * direction, and the same principle the `.pdata` and jump-table suppressions
 * below already apply.
 *
 * Coverage is computed from every match, suppressed or not, so the result does
 * not depend on which candidate is considered first.
 */
function interiorPatternStarts(matches: Map<number, number>): Set<number> {
  const starts = Array.from(matches.keys()).sort((a, b) => a - b);
  const interior = new Set<number>();
  for (let i = 0; i < starts.length; i++) {
    const end = starts[i] + matches.get(starts[i])!;
    // Matches are at most 6 bytes long, so this inner walk is bounded by the
    // longest entry in the prologue table rather than by the candidate count.
    for (let j = i + 1; j < starts.length && starts[j] < end; j++) interior.add(starts[j]);
  }
  return interior;
}

/** Instructions after which control does not simply continue to the next one. */
const NO_FALLTHROUGH = new Set(["ret", "retn", "int3", "ud2"]);

/** What kinds of reachable direct jump aim into `[boundary, windowEnd)`. */
interface Crossings {
  /**
   * A conditional jump, whose fallthrough therefore stays on this side of the
   * boundary — so both sides belong to one function.
   */
  cond: boolean;
  /**
   * An unconditional `jmp`, which on its own implies nothing: a tail call and a
   * shared epilogue are spelled exactly this way. It is evidence only beside
   * "nothing in the image transfers to the boundary" — see
   * {@link interiorBranchedOverStarts}.
   */
  uncond: boolean;
}

/**
 * Which reachable direct jumps *from `from`* aim at or past `boundary`.
 *
 * The reachability is the whole point, and it is why this decodes rather than
 * reading the linear scan's answer. A `.text` section carries data — jump
 * tables above all, which MSVC drops in immediately after the function that
 * dispatches through them — and a linear decode turns those bytes into
 * plausible instructions. t32.exe holds eight absolute case addresses at
 * 0x4086a4, right after `sub_407ABC`'s final `ret`, and they decode as
 * `jle 0x4086e7 / jl 0x4086ef / jl 0x4086f3 / jge 0x4086f7 / jge 0x4086fb /
 * jle 0x408703` — six conditional jumps straddling the next function's start,
 * none of which the program can execute. w32.exe has the same table with the
 * same effect. Walking forward from `from` never reaches them, because the
 * `ret` in front of the table stops the walk.
 *
 * The walk follows fallthrough and direct branches only. A `call` is followed
 * by its fallthrough and nothing else — the callee's body is not this
 * function's — and an indirect jump ends its path rather than guessing. It runs
 * to completion rather than stopping at the first crossing, because both kinds
 * are wanted and the caller weighs them differently; the window is one
 * function, so that costs nothing the previous early return was saving.
 */
function reachableCrossings(
  from: number,
  boundary: number,
  windowEnd: number,
  bytes: Uint8Array,
  baseAddress: number,
  scan: CapstoneScan,
): Crossings {
  const out: Crossings = { cond: false, uncond: false };
  const lo = from - baseAddress;
  const hi = windowEnd - baseAddress;
  if (lo < 0 || hi > bytes.length || hi <= lo) return out;

  const decoded = new Map<number, { mn: string; size: number; target: number | null }>();
  let offset = lo;
  while (offset < hi) {
    const insns = scan.decode(bytes, offset, hi, baseAddress + offset);
    if (insns.length === 0) {
      offset += 1;
      continue;
    }
    for (const insn of insns) {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      decoded.set(insn.address, {
        mn: insn.mnemonic,
        size: insn.size,
        target: m ? parseInt(m[1], 16) : null,
      });
    }
    const last = insns[insns.length - 1];
    offset += last.address - (baseAddress + offset) + last.size;
  }

  const seen = new Set<number>();
  const queue: number[] = [from];
  while (queue.length > 0) {
    const addr = queue.pop()!;
    if (addr < from || addr >= windowEnd || seen.has(addr)) continue;
    seen.add(addr);
    const insn = decoded.get(addr);
    if (!insn) continue; // not on the linear grid — this path is not followed
    if (NO_FALLTHROUGH.has(insn.mn)) continue;
    if (insn.mn === "jmp") {
      if (insn.target !== null) {
        if (insn.target >= boundary && insn.target < windowEnd) out.uncond = true;
        queue.push(insn.target);
      }
      continue;
    }
    if (insn.mn.startsWith("j")) {
      if (insn.target !== null) {
        if (insn.target >= boundary && insn.target < windowEnd) out.cond = true;
        queue.push(insn.target);
      }
      queue.push(addr + insn.size);
      continue;
    }
    queue.push(addr + insn.size);
  }
  return out;
}

/**
 * A memory operand based on the frame register, in either width.
 *
 * Deliberately `[ebp` / `[rbp` and not "mentions ebp": `mov ebp, esp` and
 * `push ebp` mention it and *establish* a frame rather than read one, and they
 * are what a real entry point does with it.
 */
const FRAME_MEMORY_OPERAND = /\[[er]bp\b/;

/**
 * The operand text of the single instruction at `addr`, or null where nothing
 * decodes there or the decode does not start on `addr` itself.
 *
 * Decoded from `addr` rather than read off the linear sweep on purpose. The
 * sweep's grid is whatever the bytes before it produced, so its instruction at
 * a given address can be a misalignment — and this question is asked about an
 * address a `call` names, i.e. one that provably *is* an instruction boundary.
 * Sixteen bytes is more than the longest x86 instruction.
 */
function firstInstructionOperands(
  addr: number,
  windowEnd: number,
  bytes: Uint8Array,
  baseAddress: number,
  scan: CapstoneScan,
): string | null {
  const lo = addr - baseAddress;
  const hi = Math.min(windowEnd - baseAddress, lo + 16);
  if (lo < 0 || hi > bytes.length || hi <= lo) return null;
  const insns = scan.decodeOne(bytes, lo, hi, addr);
  return insns.length > 0 && insns[0].address === addr ? insns[0].opStr : null;
}

/**
 * The operand text of the instruction that ends exactly at `boundary`, decoded
 * on the previous function's own grid — or null where nothing lands there.
 *
 * This is the counterpart of {@link firstInstructionOperands} and the two
 * anchor differently on purpose. That one is asked about an address a `call`
 * names, so it decodes *from* the address, which provably is an instruction
 * boundary. Nothing names the address this one is asked about, so there is no
 * such anchor: the only grid available is the linear one from `prev`, which is
 * itself a detected start, walked forward until an instruction ends on
 * `boundary`. Landing exactly on `boundary` — an address a `call` does name —
 * is the self-consistency check that makes the walk worth trusting: a
 * misaligned grid would have to survive the whole previous function and then
 * come down precisely on a known boundary.
 *
 * A window that fails to decode advances a byte, as everywhere else here; the
 * search simply finds nothing, which is the null answer.
 */
function precedingOperands(
  prev: number,
  boundary: number,
  bytes: Uint8Array,
  baseAddress: number,
  scan: CapstoneScan,
): string | null {
  const lo = prev - baseAddress;
  const hi = boundary - baseAddress;
  if (lo < 0 || hi > bytes.length || hi <= lo) return null;
  let offset = lo;
  let found: string | null = null;
  while (offset < hi) {
    const insns = scan.decode(bytes, offset, hi, baseAddress + offset);
    if (insns.length === 0) {
      offset += 1;
      continue;
    }
    for (const insn of insns) {
      if (insn.address + insn.size === boundary) found = insn.opStr;
    }
    const last = insns[insns.length - 1];
    offset += last.address - (baseAddress + offset) + last.size;
  }
  return found;
}

/**
 * The first few instructions at `addr`, decoded from `addr` itself.
 *
 * Same anchoring argument as {@link firstInstructionOperands}: the sweep's grid
 * is whatever the bytes in front of it produced, and this is asked about a
 * detected function start, so it decodes from the address rather than reading
 * the sweep's answer. Bounded by {@link MAX_SEH32_HEAD_INSNS} instructions and
 * by that many longest-x86-instructions of bytes.
 */
function headInstructions(
  addr: number,
  windowEnd: number,
  bytes: Uint8Array,
  baseAddress: number,
  scan: CapstoneScan,
): { mnemonic: string; opStr: string }[] {
  const lo = addr - baseAddress;
  const hi = Math.min(windowEnd - baseAddress, lo + MAX_SEH32_HEAD_INSNS * 16);
  if (lo < 0 || hi > bytes.length || hi <= lo) return [];
  const out: { mnemonic: string; opStr: string }[] = [];
  let at = lo;
  let want = addr;
  while (out.length < MAX_SEH32_HEAD_INSNS && at < hi) {
    const insns = scan.decodeOne(bytes, at, hi, baseAddress + at);
    if (insns.length === 0 || insns[0].address !== want) break;
    out.push({ mnemonic: insns[0].mnemonic, opStr: insns[0].opStr });
    at += insns[0].size;
    want += insns[0].size;
  }
  return out;
}

/**
 * Which candidate start each function's own SEH scope table calls a funclet of
 * it — `funclet address -> the starts whose prologue names it`.
 *
 * This is the *relation* `seh32.ts`'s header describes, and it is built here
 * rather than inside {@link interiorBranchedOverStarts} because it is a
 * different kind of evidence: a linker-written table read once per candidate
 * start, where that function's four existing admissions are all inferences
 * about a boundary from the code around it.
 *
 * Keyed by funclet rather than by parent because that is how it is consulted —
 * "is *this* boundary a funclet of the function I am currently accumulating" —
 * and because a body shared between two parents' scopes would legitimately have
 * two entries. 32-bit only, and asked of the caller: on x64 the same
 * information is in `.pdata`/`.xdata`, which `pe/pdata.ts` already reads and
 * which reaches this file as `pdataFunctions` and `handlerAddresses`.
 */
function seh32FuncletRelation(
  sortedAddrs: number[],
  endAddress: number,
  bytes: Uint8Array,
  baseAddress: number,
  reader: Seh32Reader,
  scan: CapstoneScan,
): Map<number, Set<number>> {
  const relation = new Map<number, Set<number>>();
  const isCodeAddress = (addr: number) => addr >= baseAddress && addr < endAddress;
  for (const start of sortedAddrs) {
    const head = headInstructions(start, endAddress, bytes, baseAddress, scan);
    if (head.length === 0) continue;
    for (const funclet of seh32FuncletsOfPrologue(head, reader, isCodeAddress)) {
      const parents = relation.get(funclet);
      if (parents === undefined) relation.set(funclet, new Set([start]));
      else parents.add(start);
    }
  }
  return relation;
}

/**
 * Detected starts that the function in front of them conditionally jumps over.
 *
 * Sizes here are "distance to the next detected start", so one false start in
 * the middle of a function truncates it — and a truncated function loses every
 * `jcc` aiming past its new end, because `buildCFG` draws no edge to a target
 * outside the instruction range it was given. The block then reads as
 * unconditional and the test disappears from the output entirely
 * (peek-a-bin-g7yp). PE32 images have no `.pdata` to arbitrate with, which is
 * why all 37 measured cases were 32-bit.
 *
 * What actually produces the false start is MSVC's x86 `__finally`: the funclet
 * is emitted **inside its parent**, is reached by a `call` from the parent, ends
 * in a `ret`, and the parent's own body resumes on the next byte. It is a call
 * target, so it is a function start by every rule this detector has, and it cuts
 * its parent in half. `t32!sub_4031A4` is the worked example — 0x403276 is
 * `push 0xa; call _unlock; pop ecx; ret`, called from 0x403249, with the parent
 * continuing at 0x40327F and four of its `jcc`s aiming there or later.
 *
 * Two things have to hold before a start is withdrawn, and they are chosen to
 * refuse the case this could get catastrophically wrong — merging two genuinely
 * separate functions:
 *
 *  * **Nothing outside the previous function calls it.** A helper laid out right
 *    after its only caller is ordinary and must survive; a funclet has exactly
 *    one caller and it is its parent. `t32!sub_40A925` is the shape this saves:
 *    a second entry point sharing a tail with the code in front of it, called
 *    from 0x4043CE and 0x404471 as well as from its neighbour.
 *  * **A jump the previous function can actually execute crosses it** — see
 *    {@link reachableCrossings}. A *conditional* one is sufficient on its own: a
 *    `jcc` leaves its fallthrough behind, so both sides belong to one function.
 *    An unconditional `jmp` past the boundary is how a tail call and a shared
 *    epilogue are spelled, so it implies nothing by itself — but it is
 *    conclusive beside the second admission below.
 *
 * **The second admission: an unconditional `jmp` over a start NOTHING REACHES.**
 * The ambiguity in a crossing `jmp` is entirely about what sits on the far side
 * of it: a tail call's target and a shared epilogue are *reached*, by the very
 * `jmp` or `call` that spells them. So where the image contains no direct
 * transfer to the boundary at all — no `call`, no `jmp`, no `jcc`, no
 * jump-table case — the alternative readings are gone, and an address nothing
 * transfers to, admitted on a byte pattern, with the function in front of it
 * jumping past it, is that function's own code.
 *
 * `reached` is that test, and it must stay a union of every direct transfer the
 * sweep saw rather than the call sites alone. It fires on exactly one candidate
 * in the corpus and the case is worth stating, because the harm was not a lost
 * `jcc` but an INVENTED CALL: `w32!sub_401981` really runs to 0x401b4b, and the
 * `6a 0c 68` at 0x4019e0 — `push 0xc; push 0x40ece4` inside its body — cut it to
 * 95 bytes. Its `jmp 0x401aaa` at 0x4019d8 then aimed outside its own range, so
 * the lifter read it as a tail call and emitted `eax = sub_401AAA(); return
 * eax;` for an instruction that stays inside the function; the 363 bytes past
 * the cut became `sub_4019E0`, reading `[ebp + 0xC]` and `ebx` off a frame it
 * never establishes. The literal 0x4019e0 occurs nowhere in the image, so
 * nothing takes its address either.
 *
 * Two candidates this deliberately does NOT touch, and both are the reason the
 * `reached` half is phrased over every transfer kind: `t32!sub_403A88` and
 * `w32!sub_403CDC` are `mainCRTStartup`'s body, reached by the entry point's
 * `jmp` and by nothing else, and `t32!sub_40A925` / `w32!sub_4093C5` are the
 * shared-tail second entry points the previous bullet protects.
 *
 * **The third admission: a start whose first instruction reads the frame it did
 * not establish.** The two above are properties of the code *around* the
 * candidate; this one is a property of the candidate itself, and it is the
 * stronger evidence of the three. `[ebp + 8]` in the first instruction at an
 * address is a read of a frame some *other* function set up, because nothing
 * has run there yet to set one up — no x86 calling convention passes EBP, so an
 * entry point cannot mean anything by it. Paired with the funclet condition
 * above ("the previous function is the only thing that calls it") the candidate
 * is that function's `__finally`/`__except` body: MSVC emits it inside the
 * parent, `call`s it from the parent, and it runs on the parent's frame with no
 * prologue of its own — which is exactly what CLAUDE.md's `peek-a-bin-sysf`
 * note says such a funclet is, "part of that function, not another one".
 *
 * At least one caller is REQUIRED here, unlike in the second admission. A
 * candidate nothing calls is not a funclet, and the reading is then made of a
 * first instruction with no independent evidence that the address is an
 * instruction boundary at all.
 *
 * Measured over the corpus: 8 starts on t32 and 6 on w32, every one of them a
 * ten-byte `push dword ptr [ebp + N]; call; pop ecx; ret` or the 46-byte
 * `cmp dword ptr [ebp - 0x1c], edi; …` pair at t32 0x40a631 / w32 0x40921c. In
 * each case the base emitted a standalone function reading `*(int32_t*)(ebp +
 * 8)` with **nothing in it assigning `ebp`**, and after the withdrawal the same
 * read is `arg_0` — the parent's own argument slot, which `promoteVars` can name
 * because the frame is now the frame of the function it sits in. `t32!sub_401DB3`
 * overwrites `[ebp+8]` at 0x401e05, so the funclet reads the *updated* argument
 * and the base gave the reader no way to know which frame it was.
 *
 * `t32!sub_4041B5` / `w32!sub_404415` are the reason the caller condition is not
 * negotiable: `__SEH_epilog4` opens `mov ecx, dword ptr [ebp - 0x10]` — it reads
 * its caller's frame by design — and it is called from 31 and 29 sites. Dropping
 * the "no caller outside the previous function" test withdraws it, and no gate
 * in `npm run corpus` reports that (see the CHANGELOG entry for the measurement).
 *
 * **The fourth admission: the instruction that RUNS INTO the start reads a frame
 * it did not establish.** The third admission asks that of the boundary itself
 * and so only ever sees a funclet MSVC laid out with no unwinder entry in front
 * of it. But **every one of these funclets has two entries**, and that is the
 * shape the first three admissions kept missing. MSVC emits the register reloads
 * only the unwinder needs, and then the body; the *parent's* own `call` names the
 * body, past the reloads, because the parent already has the register loaded. So
 * the body is what gets detected, and the reload falls to the previous function,
 * where it is a dead assignment whose only consumer is now in another function —
 * `t32!sub_40388B` ended `loc_4038F4: esi = arg_0;` and nothing else, with
 * `sub_4023CD(esi)` a separate function that passed no argument at all.
 *
 * The evidence is the second and third admissions composed, asked one
 * instruction earlier: the instruction ending at the boundary reads memory
 * through the frame register, so nothing there established a frame, and it falls
 * into the boundary. Code running on a frame it did not establish, falling into
 * a body every caller of which is inside the same function, is that function's
 * `__finally`/`__except` funclet — the same conclusion as the third admission,
 * reached from the head of the funclet rather than from its body.
 *
 * Four things about it:
 *
 *  * **The frame test is the whole restriction and it is negative-controlled by
 *    OUTPUT, not by a count.** Relax it to "the predecessor is not a terminator"
 *    and the rule additionally takes `t32!0x4037b2` / `w32!0x403a06`, whose
 *    predecessor is `call _invalid_parameter_noinfo` — a call that does not
 *    return — and the merge appends `eax = sub_406CC0(7); return eax;` to the arm
 *    containing it, stating that control flows out of a `noreturn` call. Relaxing
 *    it also takes five more per binary for which there is no evidence at all.
 *    Every gate in `npm run corpus` reports the relaxed version as clean.
 *  * **Reachability is deliberately NOT tested, and that is measured rather than
 *    assumed.** All 12 predecessors per binary are unreached — only the unwinder
 *    enters them — so the conjunct would contribute nothing, and it is not kept
 *    as a bound because the case it would exclude is *stronger*, not weaker: a
 *    reachable instruction falling into the boundary means the previous
 *    function's own execution crosses it.
 *  * **The grid is the previous function's**, since nothing names the
 *    predecessor's address — see {@link precedingOperands} for why landing
 *    exactly on `boundary` is what makes that walk trustworthy. This is the one
 *    place here that reads an instruction it cannot decode *from*.
 *  * Measured at `cc45263`: 12 starts per 32-bit binary and **all 24 are funclet
 *    bodies — no false positive over 558 detected starts**. `functions` 280 → 268
 *    and 278 → 266, instructions unmoved, t64/w64 byte-identical.
 *
 * **The fifth admission: the previous function's own SEH scope table names the
 * boundary.** The four above are inferences about a boundary from the code
 * around it. This one is the linker's record: an MSVC x86 function using `__try`
 * opens `push <framesize>; push <scopetable>; call __SEH_prolog4`, and the table
 * in `.rdata` names the filter and the handler of every scope — addresses MSVC
 * emitted INSIDE that function, running on its frame with no prologue of their
 * own. `seh32.ts` reads it; `seh32FuncletRelation` turns it into
 * `funclet -> the starts whose prologue names it`; the admission is
 * `parents.has(prev)`.
 *
 * It reaches exactly the residue the other four refuse. Measured at `f3b89ec`,
 * **8 starts per 32-bit binary**: t32 0x403334, 0x4037b2, 0x405c2a, 0x405d64,
 * 0x406a83, 0x406c0d, 0x406d90, 0x40beba and w32 0x403588, 0x403a06, 0x404883,
 * 0x404c91, 0x4050f4, 0x405f8b, 0x406440, 0x4065ca. Every one is the handler of
 * the function immediately above it, has exactly one direct caller and that
 * caller is inside that function, and every one was read against
 * `objdump -d -M intel`. `functions` 268 -> 260 and 266 -> 258, instructions
 * unmoved, t64/w64 byte-identical, every gate flat.
 *
 * Four things about it:
 *
 *  * **`parents.has(prev)` is what makes it a relation, and protecting the same
 *    addresses instead is measurably wrong.** See the `strongStarts` docstring:
 *    putting them in `strong` re-introduces 9 withdrawn starts on t32 and 7 on
 *    w32, `sub_4058A6` and `sub_4063B8` among them.
 *  * **The pre-existing "no caller outside the previous function" refusal still
 *    runs first, and the table does not relax it.** MSVC shares one funclet body
 *    between two parents' funclets, so the body is laid out nowhere near its
 *    caller — t32 0x40618d, 0x406196, 0x406c16 (called from 0x40be90, 0x40beba
 *    and 0x40233a) and w32 0x402020, 0x402029, 0x4065d3, which stay detected. No
 *    scope table in either binary names any of those six: the table names the
 *    funclet that *calls* the shared body, so the two rules agree here and the
 *    refusal costs nothing measured.
 *  * **It settles a question this docstring previously got wrong.** t32
 *    0x40beba / w32 0x4050f4 was recorded here and in CLAUDE.md as "the six-byte
 *    thunk", a real function whose withdrawal would delete real code. It is the
 *    `__finally` handler of `sub_40BE84` / `sub_4050BE`, named as such by scope
 *    table 0x4113f0 / 0x40f2f8, called once from 0x40beac / 0x4050e6 inside that
 *    parent, and its body is `call <the shared funclet body>; ret`. The two
 *    counterexamples that are NOT touched are the ones no table names — t32
 *    `sub_40E1D8` / w32 0x40c7f8 (a hot-patch prologue with two callers) and
 *    t32 `sub_40660A` / w32 `sub_4054A1` (a four-caller shared helper).
 *  * **All three bounds inside `seh32.ts` fire 0 times on this corpus** — the
 *    `call` after the pushes, the `EnclosingLevel` chain, and the table address
 *    not being code. Dropping any of them leaves the named set at 37 and 35 and
 *    the withdrawn set at 8. They are bounds that make the claim sound by
 *    construction rather than measured savings, and each is pinned by a unit
 *    test in `__tests__/seh32.test.ts` instead.
 *
 * What is still refused, and `__tests__/functionDetect.test.ts` pins each
 * refusal beside its reason: a `push <imm>; call; pop ecx; ret` funclet whose
 * predecessor is a `ret` and which **no scope table names** (an immediate says
 * nothing about whose frame is in scope, and neither does a `ret`), and the six
 * per binary that `push` a callee-saved register (`peek-a-bin-6lmh` already
 * reads that instruction the opposite way, as a register save). Of the 10
 * detected members of that family per 32-bit binary at `f3b89ec`, the table
 * reaches 7 and the three shared bodies stay (peek-a-bin-qe8z,
 * peek-a-bin-d827).
 *
 * Two exemptions bound all five, and both are the linker's record outranking
 * this inference: a start in `strong` is never withdrawn, and a previous function
 * whose extent `.pdata` states is never extended. The second is why this is a
 * PE32 rule in practice — a `.pdata` image states where the parent ends, and it
 * is also why the scope table is read for 32-bit images only: on x64 the same
 * information is in `.pdata`/`.xdata`, which `pe/pdata.ts` already reads.
 *
 * **`strong` is "named by a table the parser reads", which is narrower than
 * "named by the file", and the gap was exactly this shape.** Two of the five
 * starts the third admission withdraws on t32 are entries in a scope table:
 * `sub_405745` pushes 0x411218, whose record at 0x411228 is
 * `{EnclosingLevel -2, Filter NULL, Handler 0x4058A6}`, and `sub_40628D` pushes
 * 0x4112A8, whose record at 0x4112B8 names 0x4063B8. (CLAUDE.md quoted 0x411230
 * and 0x4112C0, which are those records' *handler fields* — the record starts
 * 8 bytes earlier, verified against the bytes.) A NULL filter beside a handler
 * is `__finally`, and such a funclet runs on its parent's frame with no prologue
 * of its own: 0x4063B8 opens `cmp dword ptr [ebp + 0x10], 0`, the *parent's*
 * third argument. It is part of that function, not another one.
 *
 * **Do not put the handler addresses into `strong`.** That re-breaks
 * `sub_4031A4`: the table at 0x411110 names handler 0x403270, and 0x403276 sits
 * six bytes inside it, past the register reloads only the unwinder needs —
 * promoting either one cuts the parent in half again, which is the defect this
 * function exists to prevent. What the scope table states is "this address is a
 * funclet **of** that parent", strictly more than "this address is named", so it
 * belongs in a relation attributing the funclet to its parent rather than in a
 * set that protects it from one (peek-a-bin-sysf).
 */
function interiorBranchedOverStarts(
  sortedAddrs: number[],
  strong: Set<number>,
  seh32Funclets: Map<number, Set<number>>,
  callSites: Map<number, number[]>,
  forwardCondJumps: number[],
  forwardJumps: number[],
  reached: Set<number>,
  pdataEndMap: Map<number, number>,
  bytes: Uint8Array,
  baseAddress: number,
  endAddress: number,
  scan: CapstoneScan,
): Set<number> {
  const interior = new Set<number>();
  if (sortedAddrs.length < 2) return interior;

  // Both jump lists are filled in scan order, so each is already sorted by
  // source address: a binary search gives the jumps that start inside a
  // candidate's predecessor without touching the rest.
  const firstJumpFrom = (jumps: number[], addr: number): number => {
    let lo = 0;
    let hi = jumps.length / 2 - 1;
    let at = jumps.length / 2;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (jumps[mid * 2] >= addr) {
        at = mid;
        hi = mid - 1;
      } else {
        lo = mid + 1;
      }
    }
    return at;
  };

  let prev = sortedAddrs[0];
  for (let i = 1; i < sortedAddrs.length; i++) {
    const boundary = sortedAddrs[i];
    const windowEnd = i + 1 < sortedAddrs.length ? sortedAddrs[i + 1] : endAddress;
    if (strong.has(boundary) || pdataEndMap.has(prev)) {
      prev = boundary;
      continue;
    }

    const callers = callSites.get(boundary);
    if (callers?.some((c) => c < prev || c >= boundary)) {
      prev = boundary;
      continue;
    }

    // **The fifth admission: the previous function's own SEH scope table names
    // this boundary as one of its funclets.** This is the only one of the five
    // that is not an inference — it is the linker's record, read out of
    // `.rdata` by `seh32.ts`, and it says the thing the other four have to
    // deduce: the address is the filter or handler of a `__try` scope belonging
    // to that function, so it is code MSVC emitted *inside* it. Consulted first
    // for that reason.
    //
    // `parents.has(prev)` is what makes this a relation rather than a set. A
    // handler in a set would be *protected* from withdrawal, and `t32!0x403270`
    // is why that is the wrong shape: 0x403276 sits six bytes inside that
    // funclet, so promoting either address re-cuts `sub_4031A4` in half
    // (peek-a-bin-g7yp, peek-a-bin-sysf).
    if (seh32Funclets.get(boundary)?.has(prev) === true) {
      interior.add(boundary);
      // `prev` stays put, as in every other admission here: the next boundary
      // is measured from the function this one was just folded back into.
      continue;
    }

    // The third and fourth admissions. Reaching here means every direct caller —
    // if there is one at all — is inside the previous function.
    if (callers !== undefined && callers.length > 0) {
      const ops = firstInstructionOperands(boundary, windowEnd, bytes, baseAddress, scan);
      const before = precedingOperands(prev, boundary, bytes, baseAddress, scan);
      if (
        (ops !== null && FRAME_MEMORY_OPERAND.test(ops)) ||
        (before !== null && FRAME_MEMORY_OPERAND.test(before))
      ) {
        interior.add(boundary);
        // As below: `prev` stays put, so the next boundary is measured from the
        // function this one was just folded back into.
        continue;
      }
    }

    // The cheap pre-filter, over the linear scan's own answer: only a boundary
    // some jump in the previous function's address range straddles is worth
    // decoding for. An unconditional straddle only counts where the boundary is
    // unreached, which is the same condition the decode is judged against.
    const unreached = !reached.has(boundary);
    let straddles = false;
    for (const jumps of unreached ? [forwardCondJumps, forwardJumps] : [forwardCondJumps]) {
      for (let j = firstJumpFrom(jumps, prev); j * 2 < jumps.length; j++) {
        const src = jumps[j * 2];
        if (src >= boundary) break;
        const dst = jumps[j * 2 + 1];
        if (dst >= boundary && dst < windowEnd) {
          straddles = true;
          break;
        }
      }
      if (straddles) break;
    }
    if (!straddles) {
      prev = boundary;
      continue;
    }

    const crossing = reachableCrossings(prev, boundary, windowEnd, bytes, baseAddress, scan);
    if (crossing.cond || (crossing.uncond && unreached)) {
      interior.add(boundary);
      // `prev` deliberately stays where it is: the next boundary is measured
      // from the function this one was just folded back into.
      continue;
    }
    prev = boundary;
  }

  return interior;
}

export function detectFunctions(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  ctx: DisasmContext,
  options?: {
    exports?: { name: string; address: number }[];
    entryPoint?: number;
    pdataFunctions?: { beginAddress: number; endAddress: number }[];
    handlerAddresses?: number[];
    /**
     * Extra readable spans of the image — `.rdata` above all — for jump tables
     * that do not live in the code section. `bytes` is always readable and is
     * searched first; anything here is additional.
     */
    dataWindows?: DataWindow[];
  },
  /**
   * The session's memo of this section's linear sweep. Detection is the first
   * of a load's RPCs to sweep `.text`, so passing one here is what fills it for
   * the `buildAllXrefs` that follows — and for the second `buildAllXrefs` a
   * late-arriving string set provokes. Omitting it sweeps unconditionally, as
   * this always did (peek-a-bin-x40u).
   */
  sweepCache?: X86SweepCache,
): DetectResult {
  const addrSet = new Set<number>();
  const nameMap = new Map<number, string>();
  const pdataEndMap = new Map<number, number>();
  const len = bytes.length;
  const endAddress = baseAddress + len;
  /**
   * Byte-pattern guesses, held back until the `.pdata` ranges and the
   * jump-table targets are known. Everything else that reaches `addrSet` is
   * evidence about an entry point — a linker-recorded function start, an
   * export, the entry point, an unwind handler, a call target. These two scans
   * are pattern matches over instruction bytes and nothing more.
   *
   * The value is **how many bytes the pattern matched**, which is what lets one
   * candidate rule out another; see {@link interiorPatternStarts}. The padding
   * heuristic records 1, because it matches no prologue bytes at all — it is an
   * inference about a boundary, so it can be ruled out but rules nothing out.
   */
  const patternAddrs = new Map<number, number>();
  /** Record a pattern hit, keeping the longest match at a given address. */
  const addPattern = (addr: number, matched: number) => {
    const prev = patternAddrs.get(addr);
    if (prev === undefined || matched > prev) patternAddrs.set(addr, matched);
  };
  /**
   * Starts named by a linker-written table *this parser reads*: a `.pdata`
   * begin, an unwind handler, the entry point, an export.
   * {@link interiorBranchedOverStarts} will not withdraw one of these no matter
   * what the surrounding code looks like — the evidence for them is a table the
   * linker wrote, not an inference from bytes.
   *
   * Read the membership rule literally rather than as "everything the file
   * names". MSVC's 32-bit SEH scope table names `__finally` funclet addresses
   * and is deliberately **not** a source here — it is read by `seh32.ts` and
   * consumed by {@link interiorBranchedOverStarts} as a *relation*, which says
   * the opposite thing about the same addresses: they are interior to the
   * parent, not protected from it.
   *
   * That is measured, not argued. Protecting the addresses those tables name
   * instead re-introduces **9 withdrawn starts on t32 and 7 on w32** at
   * `f3b89ec` — among them 0x4058A6 and 0x4063B8, the two the fourth admission
   * withdraws and whose handler entries CLAUDE.md quotes — each of which cuts
   * its parent in half again. That is peek-a-bin-g7yp (peek-a-bin-d827).
   */
  const strongStarts = new Set<number>();

  // Integrate .pdata seeds
  if (options?.pdataFunctions) {
    for (const rf of options.pdataFunctions) {
      if (rf.beginAddress >= baseAddress && rf.beginAddress < endAddress) {
        addrSet.add(rf.beginAddress);
        strongStarts.add(rf.beginAddress);
        pdataEndMap.set(rf.beginAddress, rf.endAddress);
      }
    }
  }

  // Exception handler seeds from UNWIND_INFO
  if (options?.handlerAddresses) {
    for (const ha of options.handlerAddresses) {
      if (ha >= baseAddress && ha < endAddress) {
        addrSet.add(ha);
        strongStarts.add(ha);
        nameMap.set(ha, `__handler_${ha.toString(16)}`);
      }
    }
  }

  if (options?.entryPoint !== undefined) {
    const ep = options.entryPoint;
    if (ep >= baseAddress && ep < endAddress) {
      addrSet.add(ep);
      strongStarts.add(ep);
      nameMap.set(ep, "entry_point");
    }
  }

  if (options?.exports) {
    for (const exp of options.exports) {
      if (exp.address >= baseAddress && exp.address < endAddress) {
        addrSet.add(exp.address);
        strongStarts.add(exp.address);
        nameMap.set(exp.address, exp.name);
      }
    }
  }

  // Prologue scanning
  for (let i = 0; i < len; i++) {
    let matched = 0;
    if (is64) {
      if (
        i + 3 < len &&
        bytes[i] === 0x55 &&
        bytes[i + 1] === 0x48 &&
        bytes[i + 2] === 0x89 &&
        bytes[i + 3] === 0xe5
      ) {
        matched = 4;
      } else if (
        i + 3 < len &&
        bytes[i] === 0x48 &&
        bytes[i + 1] === 0x83 &&
        bytes[i + 2] === 0xec
      ) {
        matched = 3;
      } else if (
        i + 6 < len &&
        bytes[i] === 0x48 &&
        bytes[i + 1] === 0x81 &&
        bytes[i + 2] === 0xec
      ) {
        matched = 3;
      } else if (
        i + 3 < len &&
        bytes[i] === 0x53 &&
        bytes[i + 1] === 0x48 &&
        bytes[i + 2] === 0x83 &&
        bytes[i + 3] === 0xec
      ) {
        matched = 4;
      } else if (
        i + 4 < len &&
        bytes[i] === 0x48 &&
        bytes[i + 1] === 0x89 &&
        bytes[i + 2] === 0x4c &&
        bytes[i + 3] === 0x24 &&
        bytes[i + 4] === 0x08
      ) {
        matched = 5;
      } else if (
        i + 4 < len &&
        bytes[i] === 0x57 &&
        bytes[i + 1] === 0x56 &&
        bytes[i + 2] === 0x48 &&
        bytes[i + 3] === 0x83 &&
        bytes[i + 4] === 0xec
      ) {
        matched = 5;
      }
      // NOTE: a `48 83 EC` (sub rsp, imm8) preceded by CC/90 padding is already
      // matched by the unqualified `48 83 EC` branch above — no separate case needed.
      else if (
        i + 4 < len &&
        bytes[i] === 0x40 &&
        bytes[i + 1] === 0x53 &&
        bytes[i + 2] === 0x48 &&
        bytes[i + 3] === 0x83 &&
        bytes[i + 4] === 0xec
      ) {
        matched = 5;
      } else if (
        i + 5 < len &&
        bytes[i] === 0x40 &&
        bytes[i + 1] === 0x55 &&
        bytes[i + 2] === 0x48 &&
        bytes[i + 3] === 0x8d &&
        bytes[i + 4] === 0x6c &&
        bytes[i + 5] === 0x24
      ) {
        matched = 6;
      } else if (
        i + 4 < len &&
        bytes[i] === 0x40 &&
        bytes[i + 1] === 0x57 &&
        bytes[i + 2] === 0x48 &&
        bytes[i + 3] === 0x83 &&
        bytes[i + 4] === 0xec
      ) {
        matched = 5;
      } else if (
        i + 3 < len &&
        ((bytes[i] === 0x48 &&
          bytes[i + 1] === 0x89 &&
          bytes[i + 2] === 0x5c &&
          bytes[i + 3] === 0x24) ||
          (bytes[i] === 0x4c &&
            bytes[i + 1] === 0x89 &&
            bytes[i + 2] === 0x44 &&
            bytes[i + 3] === 0x24))
      ) {
        const atBoundary =
          i === 0 ||
          bytes[i - 1] === 0xcc ||
          bytes[i - 1] === 0xc3 ||
          bytes[i - 1] === 0x90 ||
          (baseAddress + i) % 16 === 0;
        if (atBoundary) matched = 4;
      } else if (
        i + 2 < len &&
        bytes[i] === 0x48 &&
        bytes[i + 1] === 0x8b &&
        bytes[i + 2] === 0xc4
      ) {
        const atBoundary =
          i === 0 ||
          bytes[i - 1] === 0xcc ||
          bytes[i - 1] === 0xc3 ||
          bytes[i - 1] === 0x90 ||
          (baseAddress + i) % 16 === 0;
        if (atBoundary) matched = 3;
      }
    } else {
      if (i + 2 < len && bytes[i] === 0x55 && bytes[i + 1] === 0x8b && bytes[i + 2] === 0xec) {
        matched = 3;
      } else if (
        i + 2 < len &&
        bytes[i] === 0x55 &&
        bytes[i + 1] === 0x89 &&
        bytes[i + 2] === 0xe5
      ) {
        matched = 3;
      } else if (
        i + 4 < len &&
        bytes[i] === 0x8b &&
        bytes[i + 1] === 0xff &&
        bytes[i + 2] === 0x55 &&
        bytes[i + 3] === 0x8b &&
        bytes[i + 4] === 0xec
      ) {
        matched = 5;
      } else if (i + 2 < len && bytes[i] === 0x6a && bytes[i + 2] === 0x68) {
        const atBoundary =
          i === 0 ||
          bytes[i - 1] === 0xcc ||
          bytes[i - 1] === 0xc3 ||
          bytes[i - 1] === 0x90 ||
          (baseAddress + i) % 16 === 0;
        if (atBoundary) matched = 3;
      }
    }
    if (matched > 0) addPattern(baseAddress + i, matched);
  }

  // Alignment padding heuristic
  for (let i = 0; i < len; i++) {
    if (bytes[i] === 0xcc || bytes[i] === 0x90) {
      let padEnd = i + 1;
      let hasCC = bytes[i] === 0xcc;
      while (padEnd < len && (bytes[padEnd] === 0xcc || bytes[padEnd] === 0x90)) {
        if (bytes[padEnd] === 0xcc) hasCC = true;
        padEnd++;
      }
      const padLen = padEnd - i;
      const minLen = hasCC ? 2 : 3;
      if (
        padLen >= minLen &&
        padEnd < len &&
        bytes[padEnd] !== 0xcc &&
        bytes[padEnd] !== 0x90 &&
        bytes[padEnd] !== 0x00 &&
        (baseAddress + padEnd) % 4 === 0
      ) {
        addPattern(baseAddress + padEnd, 1);
      }
      i = padEnd - 1;
    }
  }

  // Call target collection
  const callTargets = new Set<number>();
  /**
   * Where each direct `call` came from, keyed by its target.
   *
   * `callTargets` says an address is called; this says by whom, which is what
   * {@link interiorBranchedOverStarts} needs to tell a helper function that
   * happens to sit after its only caller from a funclet the caller contains.
   */
  const callSites = new Map<number, number[]>();
  /**
   * Every forward conditional jump, as `from, to` pairs in scan order.
   *
   * The pre-filter for the interior-start check below, so that the expensive
   * part (a reachability walk that decodes) only runs where a jump actually
   * straddles a candidate boundary. Forward only: the check asks whether a
   * function branches *over* the start that follows it, and a backward jump
   * cannot. Two numbers per conditional jump — 2291 of them in t32.exe's
   * `.text`, the same order as the call targets already held here.
   */
  const forwardCondJumps: number[] = [];
  /**
   * Every forward unconditional `jmp`, as `from, to` pairs in scan order — the
   * same shape and the same purpose as `forwardCondJumps`, for the second
   * admission in {@link interiorBranchedOverStarts}. Kept as its own list
   * rather than a kind flag on one, because a conditional straddle is
   * sufficient evidence on its own and an unconditional one is not: merging
   * them would need every consumer to re-separate them.
   */
  const forwardJumps: number[] = [];
  /**
   * Every address a direct `jmp` or `jcc` in the sweep aims at.
   *
   * Together with `callTargets` and the jump-table targets this is "the image
   * transfers control here", which is what makes an unconditional jump over a
   * candidate conclusive rather than ambiguous — a tail call's target and a
   * shared epilogue are both *reached*. Both directions, because the question
   * is whether anything reaches the address, not where from.
   */
  const branchTargets = new Set<number>();
  const jumpTables = new Map<number, number[]>();
  /**
   * Every address any jump table dispatches to.
   *
   * These are **case labels, not function starts**: the `jmp [table + i*n]`
   * that reaches them sits inside some function, and a switch's case bodies are
   * part of that function. They are deliberately kept out of `addrSet` — see
   * the suppression pass below for what that fixes (peek-a-bin-jy4).
   */
  const jumpTableTargets = new Set<number>();
  /** `[start, end)` of the bytes each recovered table occupies — see {@link TableRead}. */
  const jumpTableSpans: [number, number][] = [];
  const spanKeys = new Set<string>();
  /**
   * Deduped, because one table serves several dispatches — t32.exe's `0x40ba8c`
   * is read by three — and a span is about the bytes, not about the `jmp` that
   * reached them.
   */
  const recordSpans = (table: TableRead): void => {
    for (const [start, end] of table.spans) {
      const key = `${start}:${end}`;
      if (!spanKeys.has(key)) {
        spanKeys.add(key);
        jumpTableSpans.push([start, end]);
      }
    }
  };
  /**
   * Bases {@link readAbsoluteTable} refused because they hold no address, still
   * waiting for the sweep to reach the instruction that might overlap them —
   * see {@link overlappedTableExtent} (peek-a-bin-xqxy).
   */
  const pendingOverlaps: number[] = [];
  /**
   * Case lists of the tables already read, keyed by base — so a later dispatch
   * naming a base this sweep has already resolved reads the same entries rather
   * than needing a bound of its own in linear reach. MSVC's memcpy tails are
   * reached by `jmp`, so the eight addresses in front of one are not the eight
   * instructions that ran, and the `and <index>, 3` that bounds them is out of
   * reach at all but the first (peek-a-bin-padl).
   *
   * First reading wins: it is the one whose own evidence bounded the table, and
   * overwriting it with a later, longer read would be taking a length claim from
   * a dispatch that has none.
   */
  const tablesByBase = new Map<number, number[]>();
  const reader = makeImageReader([{ base: baseAddress, bytes }, ...(options?.dataWindows ?? [])]);
  // Unlike `disassemble`/`hybridDisassemble`/`buildAllXrefs`, this stage keeps
  // its no-decoder branch rather than throwing (peek-a-bin-cen). Its answer is
  // not made of instructions: `.pdata` extents, exports, the entry point,
  // unwind handlers and the byte-pattern scans are all already in `addrSet`,
  // and every one of them is evidence the file itself supplies. What is lost
  // without a decoder is the call-target, jump-table and thunk passes — a
  // narrower function list, not a silently empty one. `omitted` in the returned
  // {@link DetectResult} is what says which (peek-a-bin-4s9); before it, the
  // narrow answer and the complete one were the same shape.
  const cs = is64 ? ctx.cs64 : ctx.cs32;
  const omitted: DetectPass[] = cs
    ? []
    : ["call-targets", "jump-tables", "thunk-names", "tail-calls"];
  if (cs) {
    let prevWasUnconditional = false;
    const recentInsns: StackInsn[] = [];
    /**
     * End address of the previous decoded instruction, so a gap is visible.
     *
     * The sweep drops every byte the decoder refused, so two adjacent elements
     * of its array are not necessarily adjacent in the image, and the loop this
     * replaced answered that by watching for an empty decode — it reset
     * `prevWasUnconditional` there. Preserved here so the refactor is
     * behaviour-preserving *by construction* rather than only on the images it
     * was differentially checked against. `-1` before the first instruction,
     * which no address can equal, so the first one correctly has no predecessor.
     *
     * **It is unfalsifiable from outside, because the one reader of
     * `prevWasUnconditional` is provably inert.** That reader adds
     * `insn.address` to `addrSet` when it is a known call target — and the call
     * branch above puts every in-section call target into `addrSet` on the line
     * before it puts it into `callTargets`, so `callTargets` is a subset of
     * `addrSet` and the add can never be new. Measured as well as argued: over
     * t32/t64/w32/w64 and a 669 KiB-`.text` `go` image the guard fires 156, 34,
     * 146, 35 and 1 times and adds a new address **0** times, and dropping this
     * reset leaves every `DetectResult` in that set byte-identical. So no test
     * can pin it (see `linearSweep.test.ts`, which pins the sweep's side of the
     * contract instead — that a gap is visible at all) and the subsumed
     * heuristic is peek-a-bin-7lue, not something to delete in passing.
     */
    let prevEnd = -1;
    // One sweep, shared with `buildAllXrefs`; see ./linearSweep.ts for why the
    // two loops that used to do this separately were provably the same loop,
    // and for what the memo holds.
    const swept = sweepCache
      ? sweepCache.sweep(bytes, baseAddress, cs, "function detection")
      : sweepX86(bytes, baseAddress, cs, "function detection");
    for (const insn of swept) {
      if (insn.address !== prevEnd) prevWasUnconditional = false;
      prevEnd = insn.address + insn.size;
      if (insn.mnemonic === "call") {
        const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
        if (m) {
          const target = parseInt(m[1], 16);
          if (target >= baseAddress && target < endAddress) {
            addrSet.add(target);
            callTargets.add(target);
            const sites = callSites.get(target);
            if (sites) sites.push(insn.address);
            else callSites.set(target, [insn.address]);
          }
        }
      } else if (insn.mnemonic.startsWith("j")) {
        const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
        if (m) {
          const target = parseInt(m[1], 16);
          if (target >= baseAddress && target < endAddress) branchTargets.add(target);
          if (target > insn.address && target < endAddress) {
            if (insn.mnemonic === "jmp") forwardJumps.push(insn.address, target);
            else forwardCondJumps.push(insn.address, target);
          }
        }
      }
      if (prevWasUnconditional && callTargets.has(insn.address)) {
        addrSet.add(insn.address);
      }

      // A deferred base is settled by the sweep walking onto it. The list is
      // address-monotone with the sweep, so an instruction starting at or
      // after a pending base is proof no instruction can still contain it:
      // that base is dropped rather than carried, which is what keeps this
      // list to a handful of entries and its cost to nothing. Answered here
      // rather than at the top of the loop so the current instruction is not
      // yet in the list and cannot settle itself.
      for (let p = pendingOverlaps.length - 1; p >= 0; p--) {
        const base = pendingOverlaps[p];
        if (insn.address >= base) {
          pendingOverlaps.splice(p, 1);
          continue;
        }
        if (insn.address + insn.size <= base) continue;
        pendingOverlaps.splice(p, 1);
        const overlapped = overlappedTableExtent(
          base,
          insn.address + insn.size,
          reader,
          is64 ? 8 : 4,
          baseAddress,
          endAddress,
        );
        if (overlapped.dataOnly) recordSpans(overlapped);
      }

      // Jump table detection
      if (insn.mnemonic === "jmp" && !insn.opStr.match(/^0x[0-9a-fA-F]+$/)) {
        const table =
          is64 && regFamily(insn.opStr)
            ? readRvaTable(insn, recentInsns, reader, baseAddress, endAddress)
            : readAbsoluteTable(
                insn,
                recentInsns,
                reader,
                is64,
                baseAddress,
                endAddress,
                tablesByBase,
              );
        const hasCases = table.targets.length >= 2;
        if (hasCases) {
          jumpTables.set(insn.address, table.targets);
          for (const t of table.targets) jumpTableTargets.add(t);
          if (table.base !== undefined && !tablesByBase.has(table.base)) {
            tablesByBase.set(table.base, table.targets);
          }
        }
        // The two questions are separate, and an unbounded dispatch answers
        // only the second: `dataOnly` carries an extent with no case list,
        // because a table with no bounds check has no *length* and reporting
        // targets would be inventing one (peek-a-bin-7lb9).
        if (hasCases || table.dataOnly) recordSpans(table);
        // A base that is not an address at all may still be a table base whose
        // entry 0 shares bytes with the instruction in front of it, and that
        // instruction is at a HIGHER address than the dispatch — so the
        // question cannot be answered here, only remembered. A base a
        // recovered table already dispatches to is code and is never one of
        // these (peek-a-bin-xqxy).
        else if (
          table.deferredBase !== undefined &&
          !jumpTableTargets.has(table.deferredBase) &&
          pendingOverlaps.length < MAX_PENDING_OVERLAP_BASES
        ) {
          pendingOverlaps.push(table.deferredBase);
        }
      }

      const mn = insn.mnemonic;
      prevWasUnconditional = mn === "ret" || mn === "retn" || mn === "jmp";
      // Copied rather than pushed by reference: the sweep's elements may be a
      // memo entry shared with `buildAllXrefs`, and this window is handed to
      // the table readers. A copy costs one small object and makes it
      // impossible for anything downstream to write through into the cache.
      recentInsns.push({
        address: insn.address,
        mnemonic: insn.mnemonic,
        opStr: insn.opStr,
        size: insn.size,
      });
      if (recentInsns.length > MAX_RECENT) recentInsns.shift();
    }
  }

  // Byte-pattern candidates are admitted last, because both things that can
  // outrank them — the `.pdata` ranges and the jump-table targets — are only
  // known now. Every other contributor to `addrSet` names an entry point; these
  // two scans match instruction bytes and nothing more, so where a stronger
  // source says an address is *interior* to a function, it wins.
  //
  //  * `.pdata` is the linker's own record of where each function begins and
  //    ends, so a pattern hit strictly inside one of its ranges is a false
  //    start. On t64.exe that was 232 of 511 detected functions — whole
  //    functions redetected 20-30 bytes in, plus 1-byte `push rbx` bodies
  //    (peek-a-bin-p3i).
  //  * A jump-table target is a case label. The dispatching `jmp` is inside a
  //    function and the case bodies belong to it, so a prologue-ish byte
  //    sequence at a case body is a false start too. Case bodies frequently
  //    follow alignment padding, which is exactly what the padding heuristic
  //    fires on (peek-a-bin-jy4).
  //  * A pattern hit strictly inside *another pattern's matched bytes* is the
  //    same prologue seen from the middle — the prologue table's entries are
  //    prefixes of one another, so several fire on one function
  //    (peek-a-bin-abv). See {@link interiorPatternStarts}. This is the one
  //    arbitration a PE32 image has, since it has no `.pdata` at all.
  //
  // Images without `.pdata` (any PE32, and PE32+ files that ship none) keep
  // every pattern match not otherwise ruled out — it is all they have. And
  // none of these suppressions can drop an address some *other* source vouched
  // for: an export, the entry point, an unwind handler, a `.pdata` begin or a
  // call target that also happens to be a case label is already in `addrSet`
  // and is never removed.
  const insidePdata = pdataRangeTest(options?.pdataFunctions);
  const interior = interiorPatternStarts(patternAddrs);
  for (const addr of patternAddrs.keys()) {
    if (insidePdata(addr)) continue;
    if (jumpTableTargets.has(addr)) continue;
    if (interior.has(addr)) continue;
    addrSet.add(addr);
  }

  // A start the previous function branches over is that function's own code —
  // an MSVC `__finally` funclet, or a prologue pattern that matched mid-body —
  // and leaving it in truncates its parent. See
  // {@link interiorBranchedOverStarts}; it needs a decoder, so without one this
  // arbitration is simply not made, as with the other decoder-fed passes.
  const allStarts = Array.from(addrSet).sort((a, b) => a - b);
  const reached = new Set<number>([...callTargets, ...branchTargets, ...jumpTableTargets]);
  const interiorStarts = cs
    ? interiorBranchedOverStarts(
        allStarts,
        strongStarts,
        is64
          ? new Map<number, Set<number>>()
          : seh32FuncletRelation(
              allStarts,
              endAddress,
              bytes,
              baseAddress,
              reader,
              createScan(cs, "SEH scope table relation"),
            ),
        callSites,
        forwardCondJumps,
        forwardJumps,
        reached,
        pdataEndMap,
        bytes,
        baseAddress,
        endAddress,
        createScan(cs, "interior-start arbitration"),
      )
    : new Set<number>();
  const sortedAddrs =
    interiorStarts.size > 0 ? allStarts.filter((a) => !interiorStarts.has(a)) : allStarts;
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

  // --- Thunk detection ---
  // These windows are 16 bytes and could not exhaust anything, but they still
  // go through a scan: a decode that returns nothing is how a dead engine
  // presents itself here too, and the invariant that no `cs.disasm` call in
  // this codebase is unwindowed is worth more than the exemption.
  if (cs && ctx.iatMap.size > 0) {
    const thunkScan = createScan(cs, "thunk detection");
    for (const fn of functions) {
      if (fn.name !== `sub_${fn.address.toString(16).toUpperCase()}`) continue;
      if (fn.size > 16) continue;
      const fnOffset = fn.address - baseAddress;
      if (fnOffset < 0 || fnOffset + fn.size > len) continue;
      {
        const insns = thunkScan.decode(bytes, fnOffset, fnOffset + fn.size, fn.address);
        let jmpInsn: { address: number; mnemonic: string; opStr: string; size: number } | null =
          null;
        let meaningfulCount = 0;
        for (const insn of insns) {
          if (insn.mnemonic === "nop" || insn.mnemonic === "int3") continue;
          meaningfulCount++;
          if (insn.mnemonic === "jmp" && meaningfulCount === 1) jmpInsn = insn;
        }
        if (jmpInsn && meaningfulCount === 1) {
          let resolvedAddr: number | null = null;
          if (is64) {
            resolvedAddr = resolveRipTarget(jmpInsn);
          } else {
            const addrMatch = jmpInsn.opStr.match(/\[0x([0-9a-fA-F]+)\]/);
            if (addrMatch) resolvedAddr = parseInt(addrMatch[1], 16);
          }
          if (resolvedAddr !== null) {
            const iat = ctx.iatMap.get(resolvedAddr);
            if (iat) {
              fn.name = iat.func;
              fn.isThunk = true;
            }
          }
        }
      }
    }
  }

  // --- Tail call detection ---
  if (cs) {
    const tailScan = createScan(cs, "tail-call detection");
    const funcAddrSet = new Set(sortedAddrs);
    const jumpTableTargets = new Set<number>();
    for (const [, targets] of jumpTables) {
      for (const t of targets) jumpTableTargets.add(t);
    }
    for (const fn of functions) {
      const tailLen = Math.min(15, fn.size);
      const tailOffset = fn.address + fn.size - tailLen - baseAddress;
      if (tailOffset < 0 || tailOffset + tailLen > len) continue;
      {
        const insns = tailScan.decode(
          bytes,
          tailOffset,
          tailOffset + tailLen,
          fn.address + fn.size - tailLen,
        );
        let lastReal: { mnemonic: string; opStr: string } | null = null;
        for (let i = insns.length - 1; i >= 0; i--) {
          if (insns[i].mnemonic !== "nop" && insns[i].mnemonic !== "int3") {
            lastReal = insns[i];
            break;
          }
        }
        if (lastReal && lastReal.mnemonic === "jmp") {
          const m = lastReal.opStr.match(/^0x([0-9a-fA-F]+)$/);
          if (m) {
            const target = parseInt(m[1], 16);
            if (
              funcAddrSet.has(target) &&
              target !== fn.address &&
              (target < fn.address || target >= fn.address + fn.size) &&
              !jumpTableTargets.has(target)
            ) {
              fn.tailCallTarget = target;
            }
          }
        }
      }
    }
  }

  return {
    functions,
    jumpTables: Array.from(jumpTables.entries()),
    jumpTableSpans,
    omitted,
  };
}

/**
 * Recursive descent from `seeds`, then a linear fill of what it did not reach.
 *
 * `jumpTableSpans` are byte ranges the caller knows to be data —
 * `DetectResult.jumpTableSpans`, the tables detection actually read. Phase 2
 * fills every uncovered gap, and a jump table is uncovered by construction: no
 * control-flow path leads *into* it, so without this the case addresses of an
 * x86 switch are decoded as instructions (peek-a-bin-y1di). Omitting the
 * argument keeps the old behaviour, which is the right default for a caller
 * that has not detected any: "nobody said where the tables are" is not the same
 * claim as "there are none".
 */
export function hybridDisassemble(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  seeds: number[],
  ctx: DisasmContext,
  pdataRanges?: { beginAddress: number; endAddress: number }[],
  jumpTableSpans?: [number, number][],
  grid?: SweptInsn[],
): Instruction[] {
  // See `disassemble` — same reasoning, same silent-empty shape.
  const cs = requireCapstone(is64 ? ctx.cs64 : ctx.cs32, "hybrid disassembly");
  const visited = new Set<number>();
  const instructionMap = new Map<number, Instruction>();
  const endAddress = baseAddress + bytes.length;
  // The linear sweep of this same section, if the session already has one. All
  // three phases below decode through this one scan, so a grid hit costs a
  // binary search instead of a `cs_disasm` and a miss costs the search plus the
  // decode it would have paid anyway. Omitting it is the pre-existing
  // behaviour, instruction for instruction — see {@link gridScan}.
  const real = createScan(cs, "hybrid disassembly");
  const scan = grid ? gridScan(grid, real) : real;

  const terminators = new Set(["ret", "retn", "int3", "ud2"]);
  const conditionalJumps = new Set([
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jnp",
    "jcxz",
    "jecxz",
    "jrcxz",
  ]);

  // Performance optimization: bulk-decode .pdata ranges with known boundaries.
  //
  // A range is windowed like any other scan rather than handed over whole: the
  // only bound on its length is the section size, and `.pdata` is attacker-
  // supplied data — a single RUNTIME_FUNCTION claiming a multi-megabyte extent
  // is a one-call way over both of the decoder's ceilings. Where the old single
  // call gave up on the first undecodable byte and left the rest of the range
  // to the BFS, the loop stops at the same place for the same reason.
  if (pdataRanges) {
    for (const range of pdataRanges) {
      if (range.beginAddress < baseAddress || range.endAddress > endAddress) continue;
      const rangeOffset = range.beginAddress - baseAddress;
      const rangeLen = range.endAddress - range.beginAddress;
      if (rangeLen <= 0 || rangeOffset + rangeLen > bytes.length) continue;

      const rangeEnd = rangeOffset + rangeLen;
      let offset = rangeOffset;
      while (offset < rangeEnd) {
        const insns = scan.decode(bytes, offset, rangeEnd, baseAddress + offset);
        if (insns.length === 0) break; // fall through to BFS for the rest
        for (const insn of insns) {
          const mapped = mapInsn(insn, ctx.stringMap, ctx.iatMap, ctx.driverMode);
          mapped.source = "recursive";
          instructionMap.set(insn.address, mapped);
          visited.add(insn.address);
        }
        const lastInsn = insns[insns.length - 1];
        const decoded = lastInsn.address - (baseAddress + offset) + lastInsn.size;
        if (decoded <= 0) break;
        offset += decoded;
      }
    }
  }

  // Phase 1: Recursive descent (BFS)
  const workQueue = [...seeds];
  while (workQueue.length > 0) {
    const addr = workQueue.pop()!;
    if (visited.has(addr)) continue;
    if (addr < baseAddress || addr >= endAddress) continue;

    visited.add(addr);
    const offset = addr - baseAddress;
    const sliceEnd = Math.min(offset + 15, bytes.length);
    if (offset >= bytes.length) continue;

    // `count: 1` (via decodeOne): only `insns[0]` is ever read, and a 15-byte
    // window otherwise decodes three or four instructions to throw them away.
    const insns = scan.decodeOne(bytes, offset, sliceEnd, addr);
    if (insns.length === 0) continue;

    const insn = insns[0];
    const mapped = mapInsn(insn, ctx.stringMap, ctx.iatMap, ctx.driverMode);
    mapped.source = "recursive";
    instructionMap.set(addr, mapped);

    const mn = insn.mnemonic;

    if (terminators.has(mn)) continue;

    if (mn === "jmp") {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= baseAddress && target < endAddress) {
          workQueue.push(target);
        }
      }
      continue;
    }

    if (conditionalJumps.has(mn) || (mn.startsWith("j") && mn !== "jmp")) {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= baseAddress && target < endAddress) {
          workQueue.push(target);
        }
      }
      workQueue.push(addr + insn.size);
      continue;
    }

    if (mn === "call") {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= baseAddress && target < endAddress) {
          workQueue.push(target);
        }
      }
      workQueue.push(addr + insn.size);
      continue;
    }

    workQueue.push(addr + insn.size);
  }

  // Phase 2: Gap fill
  const covered = new Uint8Array(bytes.length);
  for (const [addr, insn] of instructionMap) {
    const start = addr - baseAddress;
    const end = Math.min(start + insn.size, bytes.length);
    for (let j = start; j < end; j++) covered[j] = 1;
  }
  // A recovered jump table's bytes are data, and marking them covered is how
  // that is said here: the gap ends at the table and a fresh one starts after
  // it, so the fill neither decodes the case addresses nor walks off the end of
  // them misaligned into the first case body. Clamped rather than trusted — a
  // span may name an x64 table in `.rdata`, which is not in `bytes` at all.
  for (const [start, end] of jumpTableSpans ?? []) {
    const lo = Math.max(0, start - baseAddress);
    const hi = Math.min(bytes.length, end - baseAddress);
    for (let j = lo; j < hi; j++) covered[j] = 1;
  }
  let gapStart = -1;

  for (let i = 0; i <= bytes.length; i++) {
    const isCovered = i < bytes.length && covered[i] === 1;

    if (!isCovered && gapStart === -1 && i < bytes.length) {
      gapStart = i;
    } else if ((isCovered || i === bytes.length) && gapStart !== -1) {
      const gapEnd = i;
      const gapLen = gapEnd - gapStart;

      if (gapLen >= 2) {
        let allPadding = true;
        for (let j = gapStart; j < gapEnd; j++) {
          if (bytes[j] !== 0xcc && bytes[j] !== 0x90) {
            allPadding = false;
            break;
          }
        }

        if (!allPadding) {
          const gapBytes = bytes.subarray(gapStart, gapEnd);
          const gapBaseAddr = baseAddress + gapStart;
          const gapInsns = disassemble(gapBytes, gapBaseAddr, is64, ctx, scan);
          for (const gi of gapInsns) {
            if (!instructionMap.has(gi.address)) {
              gi.source = "gap-fill";
              instructionMap.set(gi.address, gi);
            }
          }
        }
      }

      gapStart = -1;
    }
  }

  const result = Array.from(instructionMap.values());
  result.sort((a, b) => a.address - b.address);
  return result;
}

/**
 * Where the loader maps the image, straight out of the optional header.
 *
 * `sizeOfImage` rather than the section table: it is the header's own statement
 * of the mapped extent, it needs nothing else passed alongside it, and the gaps
 * between sections are page-alignment slack that a pointer to the end of a
 * section legitimately lands in.
 */
export interface ImageBounds {
  /** `optionalHeader.imageBase`. */
  base: number;
  /** `optionalHeader.sizeOfImage`. */
  size: number;
}

/**
 * Below this, a hex token in an operand is a constant rather than an address —
 * the floor the loose scan has always applied, kept because it is also what
 * stops small immediates in an image based at 0 from being read as references.
 */
const MIN_DATA_XREF_ADDRESS = 0x10000;

/**
 * `instructions` → `target address ⇒ who references it`.
 *
 * `imageBounds` bounds the **fallback scan only** — the arm that treats any
 * large `0x…` token in an operand as a possible data reference. That arm has no
 * grammar behind it: it fires on bitmasks and sentinels as readily as on
 * addresses, and without a bound it emitted references to addresses that cannot
 * exist. Measured before the bound (peek-a-bin-jfp): 305 of t64.exe's 856 data
 * xrefs pointed outside the image, 318 of t32.exe's 881, 239 of t64-arm.exe's
 * 1007 — `or rbx, 0xffffffffffffffff` reported as a reference to
 * 0x10000000000000000, `mov ebx, 0x4100000` as one in an image based at
 * 0x140000000.
 *
 * The other arms are deliberately left unbounded. A direct `call 0x…`, an A64
 * branch and a `[rip ± 0x..]` displacement are all *stated* destinations
 * computed from a real instruction address, so one landing outside the image is
 * a fact about the file worth reporting rather than a misread constant.
 *
 * Omitting `imageBounds` keeps the unbounded behaviour: "nobody said where the
 * image is" is not the same claim as "everything is in range".
 */
export function buildTypedXrefMap(
  instructions: Instruction[],
  imageBounds?: ImageBounds,
): [number, Xref[]][] {
  const lo = imageBounds ? imageBounds.base : 0;
  const hi = imageBounds ? imageBounds.base + imageBounds.size : Number.POSITIVE_INFINITY;
  const xrefs = new Map<number, Xref[]>();
  const conditionalJumps = new Set([
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jnp",
    "jcxz",
    "jecxz",
    "jrcxz",
  ]);

  for (const insn of instructions) {
    const mn = insn.mnemonic;

    // ── A64 control transfers ──
    // An A64 branch writes its destination as `#0x…`, so it matches neither the
    // `^0x…$` direct form below nor `resolveRipTarget`; but it DOES satisfy the
    // loose hex scan's `mn !== "call" && mn !== "jmp" && !mn.startsWith("j")`
    // guard, which is how every branch in an ARM64 image came to be reported as
    // a data reference. Classify it here and `continue`, so no A64 branch ever
    // reaches that scan: `b.ne #0x140001514` and `tbz w2, #2, #0x14000114c`
    // carry a literal address the scan would otherwise emit as `data`.
    //
    // No `arch` parameter is needed or wanted: the mnemonic sets are disjoint
    // (see `arm64Operands.ts` — x86 has no `b`/`bl`/`br`/`cbz`/`tbz` and no
    // dotted mnemonic, A64 none starting with `j`). The single shared spelling
    // is `ret`, and it is deliberately left on the x86 path below, where it
    // already yields nothing on either architecture — that keeps this block
    // provably unable to alter an x86 classification.
    const arm64Branch = classifyArm64Branch(mn, insn.opStr);
    if (arm64Branch !== null && arm64Branch.kind !== "return") {
      // `target === null` is an indirect branch (`br x8`, `blr x2`): there is
      // no statically known destination, so it contributes no xref rather than
      // a guessed one.
      if (arm64Branch.target !== null) {
        const type: Xref["type"] =
          arm64Branch.kind === "call" ? "call" : arm64Branch.kind === "jump" ? "jmp" : "branch";
        let arr = xrefs.get(arm64Branch.target);
        if (!arr) {
          arr = [];
          xrefs.set(arm64Branch.target, arr);
        }
        arr.push({ from: insn.address, type });
      }
      continue;
    }

    const directMatch = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (directMatch) {
      const target = parseInt(directMatch[1], 16);
      let type: Xref["type"];
      if (mn === "call") type = "call";
      else if (mn === "jmp") type = "jmp";
      else if (conditionalJumps.has(mn) || mn.startsWith("j")) type = "branch";
      else continue;

      let arr = xrefs.get(target);
      if (!arr) {
        arr = [];
        xrefs.set(target, arr);
      }
      arr.push({ from: insn.address, type });
      continue;
    }

    const target = resolveRipTarget(insn);
    if (target !== null) {
      let type: Xref["type"];
      if (mn === "call") type = "call";
      else if (mn === "jmp") type = "jmp";
      else type = "data";

      let arr = xrefs.get(target);
      if (!arr) {
        arr = [];
        xrefs.set(target, arr);
      }
      arr.push({ from: insn.address, type });
      continue;
    }

    if (mn !== "call" && mn !== "jmp" && !mn.startsWith("j")) {
      const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
      if (addrMatches) {
        for (const addrStr of addrMatches) {
          const addr = parseInt(addrStr, 16);
          if (addr > MIN_DATA_XREF_ADDRESS && addr >= lo && addr < hi) {
            let arr = xrefs.get(addr);
            if (!arr) {
              arr = [];
              xrefs.set(addr, arr);
            }
            arr.push({ from: insn.address, type: "data" });
          }
        }
      }
    }
  }

  return Array.from(xrefs.entries());
}

export function buildAllXrefs(
  bytes: Uint8Array,
  baseAddress: number,
  _is64: boolean,
  stringAddrs: number[],
  iatAddrs: number[],
  cs: any,
  funcEntries?: [number, number][],
  dataSections?: { va: number; size: number }[],
  /**
   * The session's memo of this section's linear sweep — see
   * {@link X86SweepCache}. The decode is 637 of this function's 681 ms on a
   * 669 KiB `.text`, so on a hit what is left is the resolve below: 44 ms,
   * with no Capstone at all. That is also what makes a second call with a
   * larger string set nearly free, which is the one App.tsx posts when string
   * extraction lands after detection (peek-a-bin-x40u).
   */
  sweepCache?: X86SweepCache,
): {
  stringXrefs: [number, number[]][];
  importXrefs: [number, number[]][];
  callGraph: [number, number[]][];
  dataXrefs: [number, number[]][];
} {
  // Four empty maps is a well-formed answer meaning "this image references no
  // strings, no imports and nothing in its data sections", which is false of
  // every real image. See `disassemble` (peek-a-bin-cen).
  requireCapstone(cs, "xref building");
  const stringSet = new Set(stringAddrs);
  const iatSet = new Set(iatAddrs);
  const strXrefs = new Map<number, number[]>();
  const impXrefs = new Map<number, number[]>();
  const dataXrefs = new Map<number, number[]>();

  const funcAddrSet = new Set<number>();
  const funcBounds: [number, number][] = [];
  const callGraphMap = new Map<number, Set<number>>();

  if (funcEntries && funcEntries.length > 0) {
    for (const [addr] of funcEntries) funcAddrSet.add(addr);
    const sorted = [...funcEntries].sort((a, b) => a[0] - b[0]);
    for (const [addr, size] of sorted) funcBounds.push([addr, addr + size]);
  }

  const hasDataSections = dataSections && dataSections.length > 0;
  const isInDataSection = (addr: number): boolean => {
    if (!hasDataSections) return false;
    for (const ds of dataSections!) {
      if (addr >= ds.va && addr < ds.va + ds.size) return true;
    }
    return false;
  };

  const findContainingFunc = (addr: number): number => {
    if (funcBounds.length === 0) return -1;
    let lo = 0,
      hi = funcBounds.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (addr < funcBounds[mid][0]) hi = mid - 1;
      else if (addr >= funcBounds[mid][1]) lo = mid + 1;
      else return funcBounds[mid][0];
    }
    return -1;
  };

  // The decode, and then the resolve — separately, which is the whole point.
  // This is the same sweep `detectFunctions` runs, one declaration of it in
  // ./linearSweep.ts, so with a memo in hand the loop below reads instructions
  // somebody else already paid for. Everything under it is a pure function of
  // the sweep and of the four address sets, so re-answering for a bigger string
  // set costs the resolve and nothing more.
  const swept: SweptInsn[] = sweepCache
    ? sweepCache.sweep(bytes, baseAddress, cs, "xref building")
    : sweepX86(bytes, baseAddress, cs, "xref building");

  for (const insn of swept) {
    const resolvedTargets: number[] = [];

    const target = resolveRipTarget(insn);
    if (target !== null) {
      resolvedTargets.push(target);
      if (stringSet.has(target)) {
        let arr = strXrefs.get(target);
        if (!arr) {
          arr = [];
          strXrefs.set(target, arr);
        }
        arr.push(insn.address);
      }
      if (iatSet.has(target)) {
        let arr = impXrefs.get(target);
        if (!arr) {
          arr = [];
          impXrefs.set(target, arr);
        }
        arr.push(insn.address);
      }
    }
    const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
    if (addrMatches) {
      for (const addrStr of addrMatches) {
        const addr = parseInt(addrStr, 16);
        resolvedTargets.push(addr);
        if (stringSet.has(addr)) {
          let arr = strXrefs.get(addr);
          if (!arr) {
            arr = [];
            strXrefs.set(addr, arr);
          }
          arr.push(insn.address);
        }
        if (iatSet.has(addr)) {
          let arr = impXrefs.get(addr);
          if (!arr) {
            arr = [];
            impXrefs.set(addr, arr);
          }
          arr.push(insn.address);
        }
      }
    }

    if (insn.mnemonic === "call" && funcBounds.length > 0) {
      const directMatch = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (directMatch) {
        const callTarget = parseInt(directMatch[1], 16);
        if (funcAddrSet.has(callTarget)) {
          const callerFunc = findContainingFunc(insn.address);
          if (callerFunc >= 0) {
            let callees = callGraphMap.get(callerFunc);
            if (!callees) {
              callees = new Set();
              callGraphMap.set(callerFunc, callees);
            }
            callees.add(callTarget);
          }
        }
      }
    }

    if (hasDataSections) {
      for (const target of resolvedTargets) {
        if (!stringSet.has(target) && !iatSet.has(target) && isInDataSection(target)) {
          let arr = dataXrefs.get(target);
          if (!arr) {
            arr = [];
            dataXrefs.set(target, arr);
          }
          arr.push(insn.address);
        }
      }
    }
  }

  const callGraph: [number, number[]][] = [];
  for (const [funcAddr, callees] of callGraphMap) {
    callGraph.push([funcAddr, Array.from(callees)]);
  }

  return {
    stringXrefs: Array.from(strXrefs.entries()),
    importXrefs: Array.from(impXrefs.entries()),
    callGraph,
    dataXrefs: Array.from(dataXrefs.entries()),
  };
}
