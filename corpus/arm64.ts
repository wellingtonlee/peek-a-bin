/**
 * The ARM64 half of this project, made measurable.
 *
 * `npm run corpus` drives four x86 binaries and nothing else. Across the whole
 * history of the ARM64 work the only audit that has ever run against a real A64
 * image is `corpus/comments.ts`, which asks one question (is an inline comment a
 * reference or a collision) and is separately invoked for the same reason this
 * is. Everything else CLAUDE.md claims — gcc, `offsetof`, polarity, arity, the
 * stale-read and stale-guard gates — is a claim about x86.
 *
 * THIS IS A SEPARATELY INVOKED HARNESS AND THAT IS A DECISION, NOT AN
 * OVERSIGHT. Folding the ARM64 pair into `requestedBins()` would change the
 * population of every gate in `corpus.audit.ts` and the denominator of every
 * summed figure in CLAUDE.md's Verification section — `gcc 1072/1072`,
 * `offsetof 946/946 fields across 162 definitions`, `polarity 1588/1588` are all
 * sums over the binaries the gated run happens to find. CLAUDE.md carries a
 * standing instruction never to put an extra binary in the corpus directory for
 * exactly that reason. And it would buy nothing: the decompiler, the emitter and
 * the x86 operand grammars all refuse for a non-x86 image before they run
 * (`mcp/tools.ts` returns `unsupportedOnArch("Decompilation", …)` before the
 * address is even resolved), so an ARM64 key would contribute a dozen VACUOUS
 * ZEROS — the failure mode CLAUDE.md names for `armExits` on the two x64
 * binaries and `unencodableNames` on x64, where a green row says nothing at all.
 *
 * WHAT IS AUDITED HERE, and every row has an oracle outside the code under
 * test:
 *
 *  1. **The sweep**, against the A64 encoding itself. Every instruction is four
 *     bytes at a four-byte boundary — that is the ISA, not a heuristic — so a
 *     row is provably not an instruction the file contains. GATE.
 *  2. **The decode-rate floor**, against `coffHeader.machine`. The ARM64EC /
 *     ARM64X refusal is calibrated by sweeping all six corpus binaries with an
 *     A64 handle: a 0x014C or 0x8664 image is not A64 whatever it decodes to,
 *     and a 0xAA64 image that this tool accepts must be above the floor. GATE in
 *     BOTH directions, so moving the floor either way fails.
 *  3. **`.pdata`**, which is the linker's own record of where functions begin
 *     and end. A begin with no instruction at it, or an unaligned extent, is a
 *     contradiction between the sweep and the file. GATE.
 *  4. **Direct branches inside a `.pdata` extent**, the ARM64 analogue of
 *     `corpus/wildBranches.ts`. The linker resolved every branch it emitted
 *     inside a function it recorded, so a target outside the image is provably
 *     fiction. The extent restriction is what makes it an oracle — outside every
 *     extent nothing vouches that the bytes are code at all, so the same count
 *     there is reported and not gated.
 *  5. **Unreachable decoded words**, the data-as-code instrument. REPORT-ONLY.
 *  6. **The `adrp`/`adr` reference grammar**, against the ISA's own reach and
 *     page alignment. GATE.
 *  7. **A64 switch dispatch** — `findArm64JumpTables`, which had never been
 *     measured at all. GATE on a case target that is not an instruction.
 *  8. **`Arm64SweepCache`**, differentially: three RPCs through the real
 *     `dispatch` must answer identically whether the sweep is shared or
 *     re-taken, and the shared run must actually save Capstone calls. GATE.
 *
 * WHAT IS DELIBERATELY NOT AUDITED, because a green row would be vacuous:
 *
 *  * gcc syntax, `offsetof` layouts, condition polarity, call arity, `staleReads`,
 *    `staleGuards`, `popReads`, `lostDefs`, `armExits`, `selfAssigns`,
 *    `unencodableNames`, `crossEdgeGuards`, `guardShape`, `structOverlaps`,
 *    `undefinedCallees`. Every one reads emitted C or the IR behind it, and
 *    there is no emitted C for an ARM64 image — measured, not assumed: the
 *    refusal is at `mcp/tools.ts` and it precedes address resolution.
 *  * Stack frames and function signatures. `analyzeStackFrame` and
 *    `inferSignature` have no ARM64 path at all (`peek-a-bin-56q` item 1), so
 *    there is nothing to audit; auditing an absence is not an audit.
 *  * A data-marking pass. There is none (`peek-a-bin-56q` item 2). What this can
 *    do instead is census the population such a pass would have to cover, which
 *    is rows 3, 5 and 7's report halves — and those are the instrument a fix
 *    would be judged with.
 *  * Inline comments. `corpus/comments.ts` already gates that at 0 coincidences
 *    and is not duplicated here.
 *
 * Run it with `npm run corpus:arm64`. Missing binaries skip cleanly and say
 * which. Exit 1 on any red gate.
 */

import { readFileSync } from "node:fs";
import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { archForMachine } from "../src/disasm/arch";
import {
  ARM64_INSN_SIZE,
  ARM64_MIN_DECODE_FRACTION,
  ARM64_MIN_MEASURED_WORDS,
  Arm64DecodeRateError,
  classifyArm64Br,
  sweepArm64,
} from "../src/disasm/arm64";
import { classifyArm64Branch, findArm64AddressRefs } from "../src/disasm/arm64Operands";
import type { CapstoneHandle } from "../src/disasm/capstoneWindow";
import type { Instruction } from "../src/disasm/types";
import { FileSession } from "../src/mcp/session";
import { parsePE } from "../src/pe/parser";
import { dataSectionRanges, findCodeSection } from "../src/pe/sections";
import type { PEFile } from "../src/pe/types";
import { createWorkerState, dispatch } from "../src/workers/dispatch";
import { ALL_BINS, type ArmBinKey, resolveArmCorpus, resolveCorpus } from "./preflight";

// ── the report's own bookkeeping ────────────────────────────────────────────
//
// A row is a GATE when every entry it can print is provably a false statement
// about the machine, which is the criterion the whole `corpus/` directory uses.
// Anything else is REPORT — and a report row that reaches 0 for a good reason
// carries a standing note saying so, rather than being quietly promoted.

/** How many offending entries a row prints. */
const SAMPLE = 6;

export interface Row {
  gate: boolean;
  name: string;
  /** The count that must be zero (gate) or is merely observed (report). */
  value: number;
  /** The population it was drawn from. A row that matched nothing is not green. */
  live: string;
  /** Up to a handful of the offending entries. */
  rows: string[];
}

/**
 * Every judging function below RETURNS its rows rather than reporting them, and
 * takes plain data rather than a loaded image.
 *
 * That is what lets `build/arm64Audit.test.ts` negative-control the rows this
 * corpus cannot make red — `corpus/selfAssigns.ts` and
 * `build/selfAssignAudit.test.ts` are the precedent, and the reason is the same:
 * a gate whose population is empty on the two real binaries is not exercised by
 * running it, and an unexercised gate is not evidence. Where a gate CAN be made
 * red by perturbing this repo's own code, it is controlled that way instead and
 * the report says which.
 */
function gate(name: string, value: number, live: string, rows: string[] = []): Row {
  return { gate: true, name, value, live, rows: rows.slice(0, SAMPLE) };
}
function report(name: string, value: number, live: string, rows: string[] = []): Row {
  return { gate: false, name, value, live, rows: rows.slice(0, SAMPLE) };
}

// ── loading ────────────────────────────────────────────────────────────────

/**
 * The code section, sliced exactly the way `FileSession` slices it.
 *
 * `min(sizeOfRawData, buffer.byteLength - start)` rather than anything involving
 * `virtualSize`, because what is being audited is the sweep production actually
 * runs, and a different word count would make the decode rate a different
 * number from the one the floor is compared against.
 */
function codeSection(
  pe: PEFile,
  ab: ArrayBuffer,
): {
  bytes: Uint8Array;
  base: number;
  end: number;
  words: number;
} | null {
  const sec = findCodeSection(pe.sections);
  if (!sec) return null;
  const start = sec.pointerToRawData;
  const size = Math.min(sec.sizeOfRawData, ab.byteLength - start);
  const base = Number(pe.optionalHeader.imageBase) + sec.virtualAddress;
  return {
    bytes: new Uint8Array(ab, start, size),
    base,
    end: base + size,
    words: Math.floor(size / ARM64_INSN_SIZE),
  };
}

function readImage(file: string): ArrayBuffer {
  const buf = readFileSync(file);
  return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength) as ArrayBuffer;
}

/** One `.pdata` extent, in virtual addresses, sorted and searchable. */
export interface Extents {
  list: { begin: number; end: number }[];
  begins: Set<number>;
  contains(addr: number): boolean;
}

export function makeExtents(raw: readonly { begin: number; end: number }[]): Extents {
  const list = [...raw].sort((a, b) => a.begin - b.begin);
  return {
    list,
    begins: new Set(list.map((r) => r.begin)),
    contains(addr: number): boolean {
      let lo = 0;
      let hi = list.length - 1;
      while (lo <= hi) {
        const mid = (lo + hi) >>> 1;
        if (addr < list[mid].begin) hi = mid - 1;
        else if (addr >= list[mid].end) lo = mid + 1;
        else return true;
      }
      return false;
    },
  };
}

/** `.pdata`, in virtual addresses, restricted to entries beginning in the code section. */
function extentsOf(pe: PEFile, base: number, end: number): Extents {
  const imageBase = Number(pe.optionalHeader.imageBase);
  return makeExtents(
    (pe.runtimeFunctions ?? [])
      .map((r) => ({ begin: imageBase + r.beginAddress, end: imageBase + r.endAddress }))
      .filter((r) => r.begin >= base && r.begin < end),
  );
}

/** Which extent an address is in, by begin address, or -1. */
function extentOf(ex: Extents, addr: number): number {
  for (const r of ex.list) {
    if (addr >= r.begin && addr < r.end) return r.begin;
    if (addr < r.begin) break;
  }
  return -1;
}

const fmt = (a: number) => `0x${a.toString(16)}`;
const at = (i: Instruction) => `${fmt(i.address)} ${i.mnemonic} ${i.opStr}`.trim();

// ── 1. the sweep, against the A64 encoding ──────────────────────────────────

/**
 * Four bytes, at a four-byte boundary, strictly increasing, inside the section.
 *
 * All four are properties of A64 itself rather than of this decoder, so every
 * row is provably not an instruction the file contains — `polarity inverted`'s
 * character, and gated at 0 accordingly. The liveness half is the instruction
 * count: a scan over an empty array reports four zeroes.
 */
export function auditSweep(
  insns: readonly Instruction[],
  base: number,
  end: number,
  words: number,
): Row[] {
  const unaligned: string[] = [];
  const badWidth: string[] = [];
  const nonMono: string[] = [];
  const outside: string[] = [];
  let prev = Number.NEGATIVE_INFINITY;
  for (const i of insns) {
    if (i.address % ARM64_INSN_SIZE !== 0) unaligned.push(at(i));
    if (i.size !== ARM64_INSN_SIZE) badWidth.push(`${at(i)} size=${i.size}`);
    if (i.address <= prev) nonMono.push(`${at(i)} after ${fmt(prev)}`);
    prev = i.address;
    if (i.address < base || i.address >= end) outside.push(at(i));
  }
  const live = `${insns.length} insns of ${words} words`;
  return [
    gate("sweep: unaligned address", unaligned.length, live, unaligned),
    gate("sweep: width not 4", badWidth.length, live, badWidth),
    gate("sweep: address not increasing", nonMono.length, live, nonMono),
    gate("sweep: outside code section", outside.length, live, outside),
    report(
      "sweep: decode rate",
      Math.round((1000 * insns.length) / words) / 10,
      `${live} (floor ${100 * ARM64_MIN_DECODE_FRACTION}%)`,
    ),
  ];
}

// ── 3. `.pdata`, the linker's own record ───────────────────────────────────

/**
 * Does the sweep agree with the table the linker wrote?
 *
 * A `.pdata` begin is a function entry, so it is an instruction boundary by the
 * file's own statement; a begin with no instruction at it means the sweep lost a
 * word the image vouches for. An extent whose begin or end is not four-byte
 * aligned, or that is empty, contradicts the ISA. All gated.
 *
 * `undecoded` — words inside an extent that produced no instruction — is
 * REPORTED. Those are literal pools (`peek-a-bin-56q` item 2), and the sweep is
 * right to produce nothing for them; the number is the population an ARM64
 * data-marking pass would have to cover, and it is the figure that bead recorded
 * and never re-derived.
 */
export function auditPdata(
  ex: Extents,
  byAddr: ReadonlyMap<number, unknown>,
): { rows: Row[]; extentWords: number } {
  const noInsn: string[] = [];
  const unalignedBegin: string[] = [];
  const unalignedEnd: string[] = [];
  const empty: string[] = [];
  for (const r of ex.list) {
    if (r.begin % ARM64_INSN_SIZE !== 0) unalignedBegin.push(fmt(r.begin));
    if (r.end % ARM64_INSN_SIZE !== 0) unalignedEnd.push(`${fmt(r.begin)}..${fmt(r.end)}`);
    if (r.end <= r.begin) empty.push(`${fmt(r.begin)}..${fmt(r.end)}`);
    if (!byAddr.has(r.begin)) noInsn.push(fmt(r.begin));
  }
  let extentWords = 0;
  let undecoded = 0;
  for (const r of ex.list) {
    for (let a = r.begin; a < r.end; a += ARM64_INSN_SIZE) {
      extentWords++;
      if (!byAddr.has(a)) undecoded++;
    }
  }
  const live = `${ex.list.length} extents, ${extentWords} words`;
  return {
    extentWords,
    rows: [
      gate("pdata: begin with no instruction", noInsn.length, live, noInsn),
      gate("pdata: unaligned begin", unalignedBegin.length, live, unalignedBegin),
      gate("pdata: unaligned end", unalignedEnd.length, live, unalignedEnd),
      gate("pdata: empty extent", empty.length, live, empty),
      report("pdata: words in extents that do not decode", undecoded, live),
    ],
  };
}

// ── 4. wild branches, and 5. unreachable decoded words ─────────────────────

/**
 * A direct branch whose target the image does not contain.
 *
 * `corpus/wildBranches.ts`'s question, asked on A64, and with the same
 * reasoning: a branch displacement is resolved by the linker inside the image it
 * is producing, so a filed branch aiming outside `[imageBase, +sizeOfImage)` is
 * not an instruction the file contains.
 *
 * The population is restricted to branches INSIDE a `.pdata` extent, and that
 * restriction is what makes it an oracle rather than a census. A64 has no gap
 * fill — the fixed-width sweep decodes every word of the section whatever it
 * holds — so outside every extent the sweep is reading literal pools and padding
 * as code by design, and a wild target there is the expected consequence, not a
 * defect. Inside an extent the linker vouched that the bytes are code.
 */
export function auditWildBranches(
  insns: readonly Instruction[],
  ex: Extents,
  imgLo: number,
  imgHi: number,
): Row[] {
  let inExtent = 0;
  let outExtent = 0;
  const wildIn: string[] = [];
  let wildOut = 0;
  for (const i of insns) {
    const br = classifyArm64Branch(i.mnemonic, i.opStr);
    if (!br || br.target === null) continue;
    const inside = ex.contains(i.address);
    if (inside) inExtent++;
    else outExtent++;
    if (br.target >= imgLo && br.target < imgHi) continue;
    if (inside) wildIn.push(`${at(i)} -> ${fmt(br.target)}`);
    else wildOut++;
  }
  return [
    gate(
      "wild branch inside a .pdata extent",
      wildIn.length,
      `${inExtent} direct branches in extents`,
      wildIn,
    ),
    report("wild branch outside every extent", wildOut, `${outExtent} direct branches outside`),
  ];
}

/**
 * A decoded word inside a `.pdata` extent that nothing can reach.
 *
 * The word before it produced no instruction, so nothing falls through into it,
 * and no direct branch, recovered jump-table case, `.pdata` begin or detected
 * function names it — so no execution path arrives. Inside an extent the linker
 * vouched the bytes belong to a function, so an unreachable decoded word is data
 * being rendered as an instruction: `peek-a-bin-56q` item 2, and the shape of its
 * `stxrb w9, w11, [x16]` witness.
 *
 * REPORT-ONLY, because it is 2 per binary rather than 0 and there is no fix in
 * this commit. Every row it can print is nonetheless provably data, so this is
 * gateable at 0 the moment an ARM64 data-marking pass lands — the same standing
 * upgrade `arity over` carried before it became a gate.
 *
 * It is deliberately the strict reading. A pool word that happens to decode AND
 * sits directly after another decoded word is not reported, because fallthrough
 * cannot be ruled out; so this is a LOWER bound on data rendered as code, and
 * `flanked` beside it says how many words were even eligible to be judged.
 */
export function auditOrphans(
  insns: readonly Instruction[],
  ex: Extents,
  byAddr: ReadonlyMap<number, Instruction>,
  jumpTables: ReadonlyMap<number, number[]>,
  funcAddrs: readonly number[],
  extentWords: number,
): Row[] {
  const reachable = new Set<number>(funcAddrs);
  for (const r of ex.list) reachable.add(r.begin);
  for (const targets of jumpTables.values()) for (const t of targets) reachable.add(t);
  for (const i of insns) {
    const br = classifyArm64Branch(i.mnemonic, i.opStr);
    if (br && br.target !== null) reachable.add(br.target);
  }
  let flanked = 0;
  const orphans: string[] = [];
  for (const r of ex.list) {
    for (let a = r.begin + ARM64_INSN_SIZE; a < r.end; a += ARM64_INSN_SIZE) {
      const insn = byAddr.get(a);
      if (insn === undefined) continue;
      if (byAddr.has(a - ARM64_INSN_SIZE)) continue;
      flanked++;
      if (reachable.has(a)) continue;
      orphans.push(at(insn));
    }
  }
  return [
    report(
      "unreachable decoded word in a .pdata extent",
      orphans.length,
      `${flanked} words after an undecodable one, of ${extentWords} in extents`,
      orphans,
    ),
  ];
}

// ── 6. the reference grammar ───────────────────────────────────────────────

/** `adrp` reaches a 4 KiB page; `adr` reaches ±1 MiB. Both are the ISA. */
const ADRP_PAGE = 0x1000;
const ADR_REACH = 0x100000;

/**
 * `findArm64AddressRefs` against the encodings it claims to read.
 *
 * Three ISA facts, so three gates. `adrp` zeroes the low twelve bits of the
 * address it forms, so the page it names is 4096-aligned and the pair's target
 * lies inside that one page — `add xN, xN, #imm12` cannot leave it, which is why
 * the parser refuses the `lsl #12` form. `adr` encodes a signed 21-bit byte
 * displacement, so its target is within ±1 MiB of its own address. A reference
 * attributed to an address the sweep produced no instruction for is a fourth: it
 * would mean the reader and the sweep disagree about where instructions are.
 *
 * These are the gates that would catch a Capstone printing change or a mis-read
 * operand, and nothing else here can: `corpus/comments.ts` asks whether a
 * comment is justified BY this reader, so it would agree with a wrong reading.
 */
export function auditRefs(
  insns: readonly Instruction[],
  byAddr: ReadonlyMap<number, Instruction>,
): Row[] {
  const refs = findArm64AddressRefs(insns);
  const outOfPage: string[] = [];
  const pageUnaligned: string[] = [];
  const outOfReach: string[] = [];
  const noInsn: string[] = [];
  let adr = 0;
  let adrp = 0;
  let loads = 0;
  for (const ref of refs) {
    if (ref.load) loads++;
    if (byAddr.get(ref.from) === undefined) noInsn.push(`from ${fmt(ref.from)}`);
    if (ref.pairFrom === undefined) {
      adr++;
      if (Math.abs(ref.target - ref.from) > ADR_REACH) {
        outOfReach.push(`${fmt(ref.from)} -> ${fmt(ref.target)}`);
      }
      continue;
    }
    adrp++;
    const pair = byAddr.get(ref.pairFrom);
    if (pair === undefined) {
      noInsn.push(`pairFrom ${fmt(ref.pairFrom)}`);
      continue;
    }
    const m = pair.opStr
      .split(",")[1]
      ?.trim()
      .match(/^#?(0x[0-9a-fA-F]+|\d+)$/);
    if (!m) continue;
    const page = Number(m[1]);
    if (page % ADRP_PAGE !== 0) pageUnaligned.push(`${at(pair)} page ${fmt(page)}`);
    if (ref.target < page || ref.target >= page + ADRP_PAGE) {
      outOfPage.push(`${at(pair)} page ${fmt(page)} -> ${fmt(ref.target)}`);
    }
  }
  const live = `${refs.length} refs (${adr} adr, ${adrp} adrp, ${loads} load)`;
  return [
    gate("ref: target outside the adrp page", outOfPage.length, live, outOfPage),
    gate("ref: adrp page not 4 KiB aligned", pageUnaligned.length, live, pageUnaligned),
    gate("ref: adr target beyond +/-1 MiB", outOfReach.length, live, outOfReach),
    gate("ref: attributed to a non-instruction", noInsn.length, live, noInsn),
  ];
}

// ── 7. A64 switch dispatch ─────────────────────────────────────────────────

/**
 * `findArm64JumpTables`, measured for the first time.
 *
 * The reader already refuses a case target that is unaligned or outside the code
 * section, so auditing either would be restating its own input. What it does NOT
 * check is that the target is an address the sweep produced an instruction for —
 * and on a fixed-width ISA where the sweep decodes every word, a case target
 * that is not an instruction start is a CFG edge into something that is not code.
 * GATE.
 *
 * `caseOutsideDispatchFunction` is REPORTED rather than gated: a case body
 * normally belongs to the function holding its `br`, but a tail-merged or
 * ICF-shared body legitimately does not, so a row is a question and not a
 * verdict.
 *
 * `tableWordsDecodedAsCode` is the one that matters and is also REPORT-ONLY: the
 * words of a table this tool itself recovered, which the sweep nonetheless
 * presents as instructions because `detectArm64Functions` returns
 * `jumpTableSpans: []`. Every row is provably data rendered as code, so it is
 * gateable at 0 once those spans are published (`peek-a-bin-56q` item 3's
 * residue) — it is a report today only because there is no fix in this commit.
 *
 * The `br` census beside it is the liveness half, and it is also the one place
 * the three `Arm64BrKind`s are counted: "no static target exists" and "this
 * reader could not follow the chain" are different answers, which is the whole
 * reason that type is not a nullable dispatch.
 */
export function auditJumpTables(
  insns: readonly Instruction[],
  jumpTables: ReadonlyMap<number, number[]>,
  byAddr: ReadonlyMap<number, Instruction>,
  ex: Extents,
): Row[] {
  const notInsn: string[] = [];
  const otherFn: string[] = [];
  let cases = 0;
  for (const [brAddr, targets] of jumpTables) {
    for (const t of targets) {
      cases++;
      if (!byAddr.has(t)) notInsn.push(`br ${fmt(brAddr)} case ${fmt(t)}`);
      const owner = extentOf(ex, brAddr);
      const home = extentOf(ex, t);
      if (owner >= 0 && home !== owner) otherFn.push(`br ${fmt(brAddr)} case ${fmt(t)}`);
    }
  }

  // The `br` census, and the table byte extents, in one backward walk — the
  // same window `findArm64JumpTables` itself keeps, so what is counted here is
  // what that function saw.
  const recent: Instruction[] = [];
  const kinds = new Map<string, number>();
  // Deduped by ADDRESS, because two dispatches legitimately share one table —
  // t64-arm.exe's `br 0x140001a34` and `br 0x140001db0` both read
  // 0x140001df0, the second over a shorter prefix. A word is a word: counting
  // it once per reader would overstate both halves of the ratio.
  const tableWords = new Set<number>();
  const asCode = new Set<number>();
  for (const insn of insns) {
    if (insn.mnemonic.toLowerCase() === "br") {
      const k = classifyArm64Br(insn.opStr, recent);
      kinds.set(k.kind, (kinds.get(k.kind) ?? 0) + 1);
      if (k.kind === "table" && jumpTables.has(insn.address)) {
        const d = k.dispatch;
        const hi = d.table + d.count * d.width;
        for (let a = d.table - (d.table % ARM64_INSN_SIZE); a < hi; a += ARM64_INSN_SIZE) {
          tableWords.add(a);
          if (byAddr.has(a)) asCode.add(a);
        }
      }
    }
    recent.push(insn);
    if (recent.length > 16) recent.shift();
  }
  const codeRows = [...asCode]
    .sort((a, b) => a - b)
    .slice(0, SAMPLE)
    .map((a) => at(byAddr.get(a) as Instruction));

  const brs = [...kinds].map(([k, n]) => `${k} ${n}`).join(", ") || "no br";
  const live = `${jumpTables.size} tables, ${cases} cases; br: ${brs}`;
  return [
    gate("jump table: case target is not an instruction", notInsn.length, live, notInsn),
    report("jump table: case outside the dispatch's function", otherFn.length, live, otherFn),
    report(
      "jump table: table words presented as instructions",
      asCode.size,
      `${tableWords.size} words in recovered table extents`,
      codeRows,
    ),
  ];
}

// ── 2. the decode-rate floor ───────────────────────────────────────────────

/**
 * Re-calibrate the ARM64EC / ARM64X refusal against every binary here.
 *
 * `coffHeader.machine` is the oracle and it is outside the code under test: a
 * 0x014C or 0x8664 image is not A64, so its rate must be BELOW the floor, and an
 * accepted 0xAA64 image must be above it. Gating both directions is what makes
 * this a calibration rather than a restatement — moving the floor in either
 * direction turns a row red.
 *
 * `ARM64_MIN_MEASURED_WORDS` is the liveness half: below it the rate is not
 * evidence about anything, and every section here is far above it.
 */
async function auditDecodeFloor(files: [string, string][]): Promise<Row[]> {
  // `capstone-wasm`'s own `RawInsn.bytes` is a `number[]` where
  // `CapstoneHandle` says `Uint8Array`; production reaches the same decoder
  // through `Arm64Context.cs`, which is `any`. Casting here rather than
  // widening the interface keeps that discrepancy where it already is.
  const cs = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM) as unknown as CapstoneHandle;
  const armBelow: string[] = [];
  const x86Above: string[] = [];
  const tooSmall: string[] = [];
  const table: string[] = [];
  for (const [key, file] of files) {
    const ab = readImage(file);
    const pe = parsePE(ab);
    const sec = codeSection(pe, ab);
    if (!sec) continue;
    let decoded: number;
    let refused = false;
    try {
      decoded = sweepArm64(sec.bytes, sec.base, cs).length;
    } catch (e) {
      if (!(e instanceof Arm64DecodeRateError)) throw e;
      decoded = e.decoded;
      refused = true;
    }
    const rate = decoded / sec.words;
    const arch = archForMachine(pe.coffHeader.machine);
    const isArm = arch === "arm64";
    if (sec.words < ARM64_MIN_MEASURED_WORDS) tooSmall.push(`${key} ${sec.words} words`);
    if (isArm && rate < ARM64_MIN_DECODE_FRACTION) {
      armBelow.push(`${key} ${(100 * rate).toFixed(1)}%`);
    }
    if (!isArm && rate >= ARM64_MIN_DECODE_FRACTION) {
      x86Above.push(`${key} ${(100 * rate).toFixed(1)}%`);
    }
    table.push(
      `  ${key.padEnd(9)} machine=0x${pe.coffHeader.machine.toString(16).padStart(4, "0")} ` +
        `arch=${arch.padEnd(11)} words=${String(sec.words).padStart(6)} ` +
        `decoded=${String(decoded).padStart(6)} ${(100 * rate).toFixed(1).padStart(5)}%  ` +
        `${refused ? "REFUSED " : "accepted"}  ${(rate / ARM64_MIN_DECODE_FRACTION).toFixed(2)}x floor`,
    );
  }
  console.log(`\n── 2. decode-rate floor (${100 * ARM64_MIN_DECODE_FRACTION}%) ` + "─".repeat(28));
  for (const line of table) console.log(line);
  const live = `${files.length} binaries, floor ${100 * ARM64_MIN_DECODE_FRACTION}%`;
  return [
    gate("floor: ARM64 image below the floor", armBelow.length, live, armBelow),
    gate("floor: non-ARM64 image at or above the floor", x86Above.length, live, x86Above),
    gate("floor: section too small to be evidence", tooSmall.length, live, tooSmall),
  ];
}

// ── 8. the sweep cache ─────────────────────────────────────────────────────

/**
 * `Arm64SweepCache`, differentially, through the real worker dispatch.
 *
 * The three RPCs of one ARM64 file load — `detectFunctions`,
 * `hybridDisassemble`, `buildAllXrefs` — are driven twice over the same state:
 * once sharing the cache as production does, and once clearing it before each
 * call. The three answers must be identical, which is the claim
 * `Arm64SweepCache`'s docstring makes and which nothing has ever checked end to
 * end; and the shared run must make strictly fewer Capstone calls, or the audit
 * is measuring a cache that never hits.
 *
 * The Capstone handle is wrapped rather than counted inside `capstoneWindow.ts`:
 * an instrument belongs outside the code it judges, and `dispatch` takes the
 * handle as state, so no production file needs a counter in it.
 */
async function auditSweepCache(file: string): Promise<Row[]> {
  const ab = readImage(file);
  const pe = parsePE(ab);
  const sec = codeSection(pe, ab);
  if (!sec) return [];
  const imageBase = Number(pe.optionalHeader.imageBase);
  const pdataRanges = (pe.runtimeFunctions ?? []).map((r) => ({
    beginAddress: imageBase + r.beginAddress,
    endAddress: imageBase + r.endAddress,
  }));

  const run = async (share: boolean): Promise<{ answers: string; calls: number }> => {
    let calls = 0;
    const real = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM);
    // Only `arch` and `disasm` are read by anything the sweep touches; wrapping
    // rather than subclassing keeps the count honest about what was asked of
    // Capstone rather than about how many times a wrapper was constructed.
    const counting = {
      arch: (real as unknown as { arch: number }).arch,
      disasm(...args: unknown[]): unknown {
        calls++;
        return (real as unknown as { disasm: (...a: unknown[]) => unknown }).disasm(...args);
      },
    };
    const state = createWorkerState(Promise.resolve());
    state.csArm64 = counting;
    state.arch = "arm64";
    const answers: unknown[] = [];
    for (const method of ["detectFunctions", "hybridDisassemble", "buildAllXrefs"] as const) {
      if (!share) state.arm64Sweep.clear();
      answers.push(
        await dispatch(
          method,
          {
            bytes: sec.bytes,
            baseAddress: sec.base,
            pdataRanges,
            options: { pdataFunctions: pdataRanges },
            stringAddrs: [],
            iatAddrs: [],
            funcEntries: [],
            dataSections: dataSectionRanges(pe.sections, imageBase),
          },
          state,
        ),
      );
    }
    return { answers: JSON.stringify(answers), calls };
  };

  const shared = await run(true);
  const cleared = await run(false);
  const agrees = shared.answers === cleared.answers;
  const saves = shared.calls < cleared.calls;
  const live = `${cleared.calls} Capstone calls uncached, ${shared.calls} shared`;
  return [
    gate(
      "sweep cache: shared answer differs from re-taken",
      agrees ? 0 : 1,
      live,
      agrees ? [] : ["the three RPCs answered differently"],
    ),
    gate(
      "sweep cache: no Capstone calls saved",
      saves ? 0 : 1,
      live,
      saves ? [] : [`${shared.calls} >= ${cleared.calls}`],
    ),
    report(
      "sweep cache: calls saved",
      cleared.calls - shared.calls,
      `${cleared.calls} -> ${shared.calls}`,
    ),
  ];
}

// ── the run ────────────────────────────────────────────────────────────────

async function auditImage(key: ArmBinKey, file: string): Promise<Row[]> {
  const ab = readImage(file);
  const session = new FileSession();
  const af = await session.loadFile(file, file, ab);
  const pe = af.pe;
  const sec = codeSection(pe, ab);
  if (!sec) {
    console.log(`${key}: no code section — nothing to audit`);
    return [];
  }
  if (af.arch !== "arm64") {
    // Not a skip and not a pass: the file this harness was pointed at is not
    // what it is for, and saying so beats auditing an x86 sweep by accident.
    console.log(`${key}: analysed as ${af.arch}, not arm64 — SKIPPED`);
    return [];
  }
  const imageBase = Number(pe.optionalHeader.imageBase);
  const insns = af.instructions;
  const byAddr = new Map(insns.map((i) => [i.address, i]));
  const ex = extentsOf(pe, sec.base, sec.end);

  console.log(
    `\n${key}: ${insns.length} insns of ${sec.words} words, ${af.functions.length} functions, ` +
      `${ex.list.length} .pdata extents, ${af.jumpTables.size} jump tables`,
  );

  const pdata = auditPdata(ex, byAddr);
  return [
    ...auditSweep(insns, sec.base, sec.end, sec.words),
    ...pdata.rows,
    ...auditWildBranches(insns, ex, imageBase, imageBase + pe.optionalHeader.sizeOfImage),
    ...auditOrphans(
      insns,
      ex,
      byAddr,
      af.jumpTables,
      af.functions.map((f) => f.address),
      pdata.extentWords,
    ),
    ...auditRefs(insns, byAddr),
    ...auditJumpTables(insns, af.jumpTables, byAddr, ex),
  ];
}

async function main(): Promise<void> {
  await loadCapstone();
  const arm = resolveArmCorpus();
  console.log(`corpus: ${arm.dir}  [${arm.source}]`);
  console.log(`ARM64 binaries: ${arm.present.map(([k]) => k).join(", ") || "none"}`);
  if (arm.missing.length > 0) {
    console.log(`SKIPPED for ${arm.missing.join(", ")} — not in ${arm.dir}`);
    if (arm.detail) console.log(arm.detail);
  }
  if (arm.present.length === 0) {
    console.log("nothing to audit");
    return;
  }

  const findings: { bin: string; row: Row }[] = [];
  const add = (bin: string, rows: readonly Row[]) => {
    for (const row of rows) findings.push({ bin, row });
  };

  console.log(`\n── 1,3-7. per-image audits ${"─".repeat(41)}`);
  for (const [key, file] of arm.present) {
    try {
      add(key, await auditImage(key, file));
    } catch (e) {
      // An image whose sweep is REFUSED (`Arm64DecodeRateError`) cannot be
      // loaded at all — `hybridDisassembleBytes` throws rather than return a
      // short list — so the per-image rows do not exist for it. That is a
      // finding, not a crash: it is exactly what the decode-rate floor is for,
      // and the floor audit below still asks its own question about the same
      // file. Reported as a red gate so the run cannot pass while silently
      // auditing one binary instead of two.
      console.log(
        `${key}: LOAD FAILED — ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`,
      );
      add(key, [
        gate("load: image could not be analysed", 1, "1 image", [String(e).slice(0, 200)]),
      ]);
    }
  }

  // The floor needs the x86 binaries too — they are the calibration's other
  // band, and their absence makes the second gate unaskable rather than green.
  const x86 = resolveCorpus(ALL_BINS);
  const x86Files: [string, string][] = x86.found
    ? ALL_BINS.map((k) => [k, `${x86.dir}/${k}.exe`] as [string, string])
    : [];
  if (x86Files.length === 0) {
    console.log("\n── 2. decode-rate floor ── SKIPPED: the x86 binaries are the other band");
  } else {
    add("all", await auditDecodeFloor([...arm.present, ...x86Files]));
  }

  console.log(`\n── 8. sweep cache ${"─".repeat(49)}`);
  for (const [key, file] of arm.present) {
    try {
      add(key, await auditSweepCache(file));
    } catch (e) {
      // Same reasoning as the per-image catch: a refused section cannot be
      // swept at all, so there is nothing to compare, and that is a red row
      // rather than a stack trace that hides every other row's verdict.
      console.log(
        `${key}: SWEEP CACHE FAILED — ${e instanceof Error ? e.message.split("\n")[0] : String(e)}`,
      );
      add(key, [
        gate("sweep cache: could not be exercised", 1, "1 image", [String(e).slice(0, 200)]),
      ]);
    }
  }

  // ── the summary ──────────────────────────────────────────────────────────
  console.log(`\n── results ${"─".repeat(56)}`);
  let red = 0;
  for (const { bin, row } of findings) {
    const tag = row.gate ? (row.value === 0 ? "GATE  ok " : "GATE  RED") : "report   ";
    if (row.gate && row.value !== 0) red++;
    console.log(`${tag} ${bin.padEnd(8)} ${row.name}: ${row.value}   [${row.live}]`);
    for (const r of row.rows) console.log(`             ${r}`);
  }
  const gates = findings.filter((f) => f.row.gate).length;
  console.log(
    `\n${gates - red} of ${gates} gates green, ` +
      `${findings.length - gates} rows reported. ` +
      (red === 0 ? "OK" : `${red} RED`),
  );
  if (red > 0) process.exit(1);
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
