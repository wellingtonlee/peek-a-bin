/**
 * Shared function detection, disassembly, and xref building logic.
 * Extracted from disasm.worker.ts so both the Web Worker and the MCP server
 * can reuse the same algorithms.
 */

import type { Instruction, DisasmFunction, Xref } from "./types";
import { isPlausibleIOCTL, formatIOCTL } from "../analysis/driver";
import { resolveRipTarget } from "./ripRelative";
import { classifyArm64Branch } from "./arm64Operands";
import { createScan, requireCapstone } from "./capstoneWindow";

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
      const str = stringMap.get(ripTarget)!;
      instruction.comment = str.length > 60 ? str.substring(0, 57) + "..." : str;
    }
    if (!instruction.comment) {
      const addressMatch = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
      if (addressMatch) {
        for (const addrStr of addressMatch) {
          const addr = parseInt(addrStr, 16);
          if (stringMap.has(addr)) {
            const str = stringMap.get(addr)!;
            instruction.comment = str.length > 60 ? str.substring(0, 57) + "..." : str;
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
): Instruction[] {
  // `requireCapstone`, not `if (!cs) return []`: this function's entire output
  // is what the decoder produced, so an empty list is a complete-looking answer
  // for a section full of code (peek-a-bin-cen). `ctx.cs32`/`ctx.cs64` are
  // undefined until the worker's WASM bootstrap resolves and stay undefined if
  // it fails, and only the `init` RPC awaits it — so this is reachable, not
  // theoretical.
  const cs = requireCapstone(is64 ? ctx.cs64 : ctx.cs32, "linear disassembly");
  const instructions: Instruction[] = [];
  const scan = createScan(cs, "linear disassembly");
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

/** How far back the legacy (operand-named table) path looks for its bounds check. */
const CMP_LOOKBACK = 8;

/** How far back the x64 chain walk looks. `lea`/load/`add`/`jmp` plus the check. */
const MAX_RECENT = 16;

interface RecentInsn {
  address: number;
  mnemonic: string;
  opStr: string;
  size: number;
}

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
  jmpInsn: RecentInsn,
  recent: RecentInsn[],
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
      return { table: target + disp, base: target, baseName: sought, indexReg: indexReg!, loadIndex };
    }
    if (destReg(p.opStr) === sought) return null;
  }

  return null;
}

/**
 * Upper bound on case count from the bounds check in front of a dispatch.
 *
 * The check has to be about the index register, so a `mov`/`movsxd` that copied
 * the index from somewhere else is followed one step at a time back to whatever
 * the compare actually named. Without a check there is no length, and a table
 * with no length is not read at all.
 *
 * An index *loaded from memory* therefore ends the search with no count. That
 * is MSVC's dense two-table form (`movzx idx, byte ptr [...]` selecting into
 * the wide table), and no count is the right answer *for this function*: the
 * index it was asked about is an entry number, and entry numbers are not
 * bounded by anything. The bound that form does have is on the *case* value one
 * step further back, and {@link recoverDenseByteTable} is what goes and gets it.
 *
 * `before` is the position of the table load, not of the jump: the load's
 * destination is routinely the index register itself (`movsxd rax, [rdx +
 * rax*4]`), so a search from the jump meets it and reads it as a clobber.
 */
function boundedCaseCount(indexReg: string, recent: RecentInsn[], before: number): number {
  let sought = indexReg;
  for (let ri = before - 1; ri >= 0; ri--) {
    const p = recent[ri];
    const mn = p.mnemonic.toLowerCase();
    if (mn === "cmp") {
      if (destReg(p.opStr) === sought) {
        const imm = cmpImmediate(p.opStr);
        return imm === null ? 0 : imm + 1;
      }
      continue;
    }
    if (mn === "mov" || mn === "movsxd" || mn === "movzx" || mn === "movsx") {
      const pair = regPair(p.opStr);
      if (pair && pair[0] === sought) {
        sought = pair[1];
        continue;
      }
      if (destReg(p.opStr) === sought) return 0;
    }
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
 * Case targets of a table the dispatching instruction names itself.
 *
 * The 32-bit shape — `jmp dword ptr [eax*4 + 0x40941c]`, or a RIP-relative
 * operand on x64 — where the entries are absolute addresses of pointer width.
 */
function readAbsoluteTable(
  insn: RecentInsn,
  recent: RecentInsn[],
  reader: ImageReader,
  is64: boolean,
  codeStart: number,
  codeEnd: number,
): number[] {
  let maxCases = 0;
  for (let ri = recent.length - 1; ri >= Math.max(0, recent.length - CMP_LOOKBACK); ri--) {
    const prev = recent[ri];
    if (prev.mnemonic === "cmp") {
      const imm = cmpImmediate(prev.opStr);
      if (imm !== null) maxCases = imm + 1;
      break;
    }
  }
  if (maxCases <= 0 || maxCases > MAX_JUMP_TABLE_CASES) return [];

  let tableBase = 0;
  const scaleMatch = insn.opStr.match(/\[.*\*\d\s*\+\s*0x([0-9a-fA-F]+)\]/);
  if (scaleMatch) tableBase = parseInt(scaleMatch[1], 16);
  if (!tableBase && is64) {
    const ripTarget = resolveRipTarget(insn);
    if (ripTarget !== null) tableBase = ripTarget;
  }
  if (!tableBase) return [];

  const ptrSize = is64 ? 8 : 4;
  const targets: number[] = [];
  for (let c = 0; c < maxCases; c++) {
    const entry = tableBase + c * ptrSize;
    const target = ptrSize === 8 ? reader.u64(entry) : reader.u32(entry);
    if (target === null || target < codeStart || target >= codeEnd) break;
    targets.push(target);
  }
  return targets;
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
  recent: RecentInsn[],
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
  insn: RecentInsn,
  recent: RecentInsn[],
  reader: ImageReader,
  codeStart: number,
  codeEnd: number,
): number[] {
  const chain = recoverX64RvaChain(insn, recent);
  if (!chain) return [];
  const maxCases = boundedCaseCount(chain.indexReg, recent, chain.loadIndex);
  if (maxCases <= 0 || maxCases > MAX_JUMP_TABLE_CASES) {
    // A count above the ceiling is a claim not to be trusted, not an invitation
    // to look for a second reading, so only the "no count" case falls through.
    return maxCases > 0 ? [] : readDenseRvaTable(chain, recent, reader, codeStart, codeEnd);
  }

  const targets: number[] = [];
  for (let c = 0; c < maxCases; c++) {
    const entry = reader.i32(chain.table + c * 4);
    if (entry === null) break;
    const target = chain.base + entry;
    if (target < codeStart || target >= codeEnd) break;
    targets.push(target);
  }
  return targets;
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
  recent: RecentInsn[],
  reader: ImageReader,
  codeStart: number,
  codeEnd: number,
): number[] {
  const dense = recoverDenseByteTable(chain, recent);
  if (!dense) return [];
  const maxCases = boundedCaseCount(dense.caseReg, recent, dense.loadIndex);
  if (maxCases <= 0 || maxCases > MAX_JUMP_TABLE_CASES) return [];

  const targets: number[] = [];
  for (let c = 0; c < maxCases; c++) {
    const row = reader.u8(dense.byteTable + c);
    if (row === null) break;
    const entry = reader.i32(chain.table + row * 4);
    if (entry === null) break;
    const target = chain.base + entry;
    if (target < codeStart || target >= codeEnd) break;
    targets.push(target);
  }
  return targets;
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

  // Integrate .pdata seeds
  if (options?.pdataFunctions) {
    for (const rf of options.pdataFunctions) {
      if (rf.beginAddress >= baseAddress && rf.beginAddress < endAddress) {
        addrSet.add(rf.beginAddress);
        pdataEndMap.set(rf.beginAddress, rf.endAddress);
      }
    }
  }

  // Exception handler seeds from UNWIND_INFO
  if (options?.handlerAddresses) {
    for (const ha of options.handlerAddresses) {
      if (ha >= baseAddress && ha < endAddress) {
        addrSet.add(ha);
        nameMap.set(ha, `__handler_${ha.toString(16)}`);
      }
    }
  }

  if (options?.entryPoint !== undefined) {
    const ep = options.entryPoint;
    if (ep >= baseAddress && ep < endAddress) {
      addrSet.add(ep);
      nameMap.set(ep, "entry_point");
    }
  }

  if (options?.exports) {
    for (const exp of options.exports) {
      if (exp.address >= baseAddress && exp.address < endAddress) {
        addrSet.add(exp.address);
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
    const scan = createScan(cs, "function detection");
    let offset = 0;
    let prevWasUnconditional = false;
    const recentInsns: RecentInsn[] = [];
    while (offset < len) {
      const insns = scan.decode(bytes, offset, len, baseAddress + offset);
      for (const insn of insns) {
        if (insn.mnemonic === "call") {
          const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
          if (m) {
            const target = parseInt(m[1], 16);
            if (target >= baseAddress && target < endAddress) {
              addrSet.add(target);
              callTargets.add(target);
            }
          }
        }
        if (prevWasUnconditional && callTargets.has(insn.address)) {
          addrSet.add(insn.address);
        }

        // Jump table detection
        if (insn.mnemonic === "jmp" && !insn.opStr.match(/^0x[0-9a-fA-F]+$/)) {
          const targets =
            is64 && regFamily(insn.opStr)
              ? readRvaTable(insn, recentInsns, reader, baseAddress, endAddress)
              : readAbsoluteTable(insn, recentInsns, reader, is64, baseAddress, endAddress);
          if (targets.length >= 2) {
            jumpTables.set(insn.address, targets);
            for (const t of targets) jumpTableTargets.add(t);
          }
        }

        const mn = insn.mnemonic;
        prevWasUnconditional = mn === "ret" || mn === "retn" || mn === "jmp";
        recentInsns.push({
          address: insn.address,
          mnemonic: insn.mnemonic,
          opStr: insn.opStr,
          size: insn.size,
        });
        if (recentInsns.length > MAX_RECENT) recentInsns.shift();
      }
      if (insns.length === 0) {
        offset += 1;
        prevWasUnconditional = false;
      } else {
        const lastInsn = insns[insns.length - 1];
        const decoded = lastInsn.address - (baseAddress + offset) + lastInsn.size;
        offset += decoded;
      }
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
    omitted,
  };
}

export function hybridDisassemble(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  seeds: number[],
  ctx: DisasmContext,
  pdataRanges?: { beginAddress: number; endAddress: number }[],
): Instruction[] {
  // See `disassemble` — same reasoning, same silent-empty shape.
  const cs = requireCapstone(is64 ? ctx.cs64 : ctx.cs32, "hybrid disassembly");
  const visited = new Set<number>();
  const instructionMap = new Map<number, Instruction>();
  const endAddress = baseAddress + bytes.length;
  const scan = createScan(cs, "hybrid disassembly");

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
          const gapInsns = disassemble(gapBytes, gapBaseAddr, is64, ctx);
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
  const scan = createScan(cs, "xref building");
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

  let offset = 0;

  while (offset < bytes.length) {
    const insns = scan.decode(bytes, offset, bytes.length, baseAddress + offset);
    for (const insn of insns) {
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
    if (insns.length === 0) {
      offset += 1;
    } else {
      const lastInsn = insns[insns.length - 1];
      const decoded = lastInsn.address - (baseAddress + offset) + lastInsn.size;
      offset += decoded;
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
