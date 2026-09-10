/**
 * A GUARD THAT NAMES THE RIGHT OPERATOR OVER THE WRONG OPERANDS.
 *
 * The class every standing audit is blind to, and the reason it survived. The
 * emitted `if (…)` states a comparison whose *sense* matches the jcc it came
 * from, so the polarity gate passes it; it is not `__unrecovered_N`, so the
 * recovery baseline does not count it; gcc compiles it; nothing in it is a
 * version-0 read, so the stale-read gate is silent. The reader is told the
 * program makes a test it does not make, and every instrument says green.
 *
 * TWO MECHANISMS, ONE DEFECT. Both are about which instruction's flags the jcc
 * actually reads, and both are visible in the instruction stream alone:
 *
 *   SUPERSEDED (peek-a-bin-jitf) — a `cmp`/`test` in the block, and then
 *       something else writes the flags before the jcc:
 *
 *           cmp eax, 5  /  sub ecx, edx  /  jne L
 *
 *       The machine branches on `ecx - edx != 0`. `extractCondition` used to
 *       feed every `cmp`/`test` it passed to a `RegState` and never clear it,
 *       so the guard said `eax != 5`.
 *
 *   CLOBBERED (peek-a-bin-xe01) — the flags really are the `cmp`'s, but
 *       something overwrites an operand before the jcc:
 *
 *           cmp eax, 5  /  mov eax, edx  /  je L
 *
 *       The block's statements are emitted above the `if`, so `eax = edx;` runs
 *       first and `if (eax != 5)` reads the new EAX. The *arithmetic* path had
 *       refused exactly this since peek-a-bin-b531; the `cmp` path never asked.
 *
 * TWO COUNTS, and only the second is the defect:
 *
 *   `shapes` — blocks whose compare reading is spoiled by one of the two
 *              mechanisms. A property of the MACHINE CODE, so the fix does not
 *              move it. It is the instrument-liveness number: this audit
 *              measures an absence, and an absence measured by an instrument
 *              that has quietly stopped looking reports the healthiest number
 *              in the report. `shapes > 0` says the shape is still found.
 *
 *   `named`  — of those, the ones whose emitted condition does not read the
 *              value the machine compared. THAT is the wrong-operand guard.
 *              Zero means every spoiled reading was either refused and admitted
 *              as `__unrecovered_N`, or recovered through a capture taken at the
 *              compare itself.
 *
 * `named` used to be "a guard is emitted at this jcc at all", and that was the
 * right question only while refusing was the only sound answer. Since
 * peek-a-bin-xskz the lifter *materialises* a spoiled compare's operands into
 * `flg_<compare address>_<operand index>` variables at the compare's own program
 * point, so a guard at a spoiled `clobbered` jcc is now routinely correct and
 * counting those would take the gate red on ~104 of them. The sharper question
 * is whether the emitted condition READS THAT CAPTURE, which is a property of
 * the text and of the machine address the shape scan already found — see
 * `wrongOperand`, including why the rule this looks like it should be ("names a
 * register the spoiler wrote") is refuted by its own negative control.
 *
 * `emittedAtShape` keeps the old count beside the new one, report-only, so the
 * refinement is legible rather than silent — and so a collapse in the recovery
 * shows up as a row rather than as silence.
 *
 * WHAT IT DOES NOT CATCH, stated so the zero is read for what it is:
 *
 *   - `named` counts only guards the polarity pass could ANCHOR to their jcc.
 *     A spoiled guard in an arm the auditor could not anchor is invisible here,
 *     so `named` is a LOWER bound. `shapes` has no such dependency.
 *   - It says NOTHING about whether the captured value is the right one. What it
 *     checks is that the guard reads a value materialised at the compare; that
 *     the materialised value is what the compare compared is a property of
 *     WHERE the statement sits, and only reading `spoiledCompareCapture` (or
 *     hand-reading a site against `objdump`) establishes it.
 *   - A `clobbered` row whose capture the lifter DECLINED for a reason of its
 *     own — a cross-block owner, an unresolvable jump target — is a row where no
 *     guard is emitted either, so it leaves through `emitted === null` rather
 *     than being judged. The count is therefore about guards that ARE on the
 *     page, which is what it has always been about.
 *   - It shares `isFlagTransparent` with the code under test. That table is a
 *     fact about x86 and is deliberately single-sourced — a second copy is the
 *     failure mode `flagModel.ts` exists to prevent — but it does mean this
 *     audit cannot catch an error IN that table. The judgement built on top of
 *     it (which registers a compare names, what writes over them) is written
 *     here independently and reads only raw operand text.
 *   - A guard spoiled by a *call* is structurally reachable and this counts it,
 *     but `buildCFG` does not split at a call and MSVC does not emit a compare
 *     a call then destroys, so the sub-class is expected to be empty.
 *   - It says nothing about a guard whose operands are right and whose value is
 *     wrong for some other reason.
 */
import type { BasicBlock } from "../src/disasm/cfg";
import { isFlagTransparent } from "../src/disasm/decompile/flagModel";
import { canonReg, isKnownRegister } from "../src/disasm/decompile/ir";
import type { Instruction } from "../src/disasm/types";

/** One block whose trailing jcc reads flags the recovered compare does not describe. */
export interface StaleGuardRec {
  bin: string;
  func: string;
  funcAddr: number;
  /**
   * Which kind of flag reader this row is about. `"jcc"` is the block's trailing
   * conditional jump — the only reader until peek-a-bin-n9cl.6 — and the rows
   * the `named` gate counts; `"setcc"`/`"cmovcc"` are the in-block readers the
   * `reader*` counts cover.
   */
  reader: "jcc" | "setcc" | "cmovcc";
  /** The reader's address: the trailing conditional jump, or the setcc/cmovcc. */
  jcc: number;
  jccMnem: string;
  /** Which mechanism spoiled the reading. */
  kind: "superseded" | "clobbered";
  /** The `cmp`/`test` whose operands the pre-fix reading would have named. */
  cmpAddr: number;
  cmpText: string;
  /** The instruction that took the flags away, or that wrote over an operand. */
  bySpoilerAddr: number;
  bySpoilerText: string;
  /**
   * The emitted condition found at this jcc, when the polarity pass anchored a
   * guard there. Absent means the reading was refused and admitted as
   * `__unrecovered_N`. Present is NOT on its own a defect — see `wrongOperand`.
   */
  emitted: string | null;
  /**
   * Why that condition is a wrong-operand guard, or null when it is not one.
   * `"reg:<name>"` names the identifier whose register the spoiler wrote;
   * `"mem:<token>"` the memory mention in a guard whose compare read memory
   * across a store.
   */
  why: string | null;
  /** Registers written between the compare and the jcc, canonicalised. Sorted. */
  clobbers: string[];
  /**
   * Whether anything in that stretch wrote memory, or wrote somewhere `writesOf`
   * cannot attribute. Recorded rather than judged: it is what makes a compare
   * over memory a spoiled shape, and 77 of the 104 `clobbered` rows at
   * `97249dc` are exactly that.
   */
  clobbersMemory: boolean;
}

export interface StaleGuardResult {
  /** Blocks ending in a conditional jump that were examined at all. */
  blocks: number;
  /** Of those, the ones whose compare reading is spoiled. Expected non-zero. */
  shapes: number;
  /**
   * Of those, the ones whose emitted condition mentions something the spoiler
   * could have written. THE DEFECT. Expect 0.
   */
  named: number;
  /**
   * Of those, the ones an emitted guard names AT ALL — `named`'s definition
   * before peek-a-bin-xskz. Report-only, and expected to be LARGE: it is the
   * recovery, not the defect. Kept beside `named` so the sharpening is visible
   * and so a collapse in the recovery shows up as a row rather than as silence.
   */
  emittedAtShape: number;
  bySuperseded: number;
  byClobbered: number;
  /**
   * The SAME question asked of every OTHER in-block flag reader — `setcc` and
   * `cmovcc` — since peek-a-bin-n9cl.6 generalised the lifter's capture from
   * the trailing Jcc to all of them. `readers` is the population examined,
   * `readerShapes` the spoiled ones (machine shape, the liveness half),
   * `readerNamed` the emitted lines at a spoiled reader that do not read the
   * capture — THE DEFECT, and 0 by construction once every reader is built
   * over the same map. `readerEmitted` is the recovery count, report-only.
   *
   * The emitted text judged is the line the line map places at the reader's
   * own address, and a reader whose value the emitter admitted as
   * `__unrecovered_N` or left `unlifted` is not judged: those are refusals,
   * which is the other sound answer.
   */
  readers: number;
  readerShapes: number;
  readerNamed: number;
  readerEmitted: number;
  rows: StaleGuardRec[];
}

export function emptyStaleGuards(): StaleGuardResult {
  return {
    blocks: 0,
    shapes: 0,
    named: 0,
    emittedAtShape: 0,
    bySuperseded: 0,
    byClobbered: 0,
    readers: 0,
    readerShapes: 0,
    readerNamed: 0,
    readerEmitted: 0,
    rows: [],
  };
}

/** Registers an operand text names, base and index included, canonicalised. */
function regsNamed(text: string): Set<string> {
  const out = new Set<string>();
  for (const word of text.toLowerCase().match(/[a-z][a-z0-9]*/g) ?? []) {
    if (isKnownRegister(word)) out.add(canonReg(word));
  }
  return out;
}

/**
 * What one instruction writes, read off its operand text and nothing else.
 *
 * Deliberately NOT `flagModel.ts`'s `clobberedAfter`: that is the predicate the
 * fix is built on, and an audit that calls it agrees with the code under test by
 * construction. This is the same question asked again from the raw text.
 */
function writesOf(insn: Instruction): { regs: Set<string>; mem: boolean; opaque: boolean } {
  const mn = insn.mnemonic.toLowerCase();
  const regs = new Set<string>();
  if (mn === "nop") return { regs, mem: false, opaque: false };
  // Destination implicit in the mnemonic — AX/EAX/RAX/EDX/RDX depending on form.
  if (["cbw", "cwd", "cwde", "cdq", "cdqe", "cqo"].includes(mn)) {
    return { regs, mem: false, opaque: true };
  }
  if (mn === "push") {
    regs.add("rsp");
    return { regs, mem: false, opaque: false };
  }
  if (mn === "pop") regs.add("rsp");
  // No x86 memory operand contains a comma.
  const dst = insn.opStr.split(",")[0]?.trim().toLowerCase() ?? "";
  if (isKnownRegister(dst)) {
    regs.add(canonReg(dst));
    return { regs, mem: false, opaque: false };
  }
  if (dst.includes("[")) return { regs, mem: true, opaque: false };
  return { regs, mem: false, opaque: dst.length > 0 };
}

/**
 * Does the emitted condition at a spoiled jcc fail to state the machine's test?
 * The reason if so, null if not.
 *
 * THE RULE IS "IT DOES NOT READ THE CAPTURE", and that is the whole of it for a
 * `clobbered` row. Since peek-a-bin-xskz the lifter materialises a spoiled
 * compare's operands into `flg_<compare address>_<operand index>` variables at
 * the compare's own program point, so a correct guard reads those and nothing
 * else that can have moved. The name is derived here from the row's own
 * `cmpAddr` — the same address `flagOwnerBefore` reports and the same one the
 * lifter names the variable after — so this is a property of the emitted text,
 * checked against the machine, and not a call into any predicate the fix is
 * built on.
 *
 * A `superseded` row has no capture and cannot have one: its flags belong to an
 * instruction the compare's operands say nothing about, so ANY guard there
 * states a test the machine does not make and the old rule is still the right
 * one (peek-a-bin-jitf).
 *
 * WHY NOT "NAMES A CLOBBERED REGISTER", which is the rule this looks like it
 * should be. Because copy propagation has rebound the overwritten register out
 * of the expression before it reaches the page — peek-a-bin-xe01's central
 * finding — so the defect does not name the clobbered register at all. Measured
 * against the negative control (bypass the refusal, capture nothing):
 * `cmp eax, 5 / mov eax, edx / je` emits `edx == 5`, naming the register the
 * spoiler READ; `cmp dword ptr [ecx], 5 / mov ecx, edx / je` emits
 * `*(int32_t*)(edx) == 5`, over a register in neither the compare nor the
 * clobber set. A clobbered-register scan reports 0 on both. The clobber set is
 * still recorded on the row, because it is what identifies the shape to a
 * reader, and a register mention is still reported as a SECOND trigger — it
 * costs nothing and it is the direct form of the defect where it does occur.
 *
 * WHY WHOLE IDENTIFIERS. Tokens are maximal `[A-Za-z_][A-Za-z0-9_]*` runs, so
 * `flg_401000_0` is one token rather than the register `flg` plus noise, and
 * `eax_3` — the variable `splitStaleReads` parks a pre-clobber value in — is not
 * mistaken for `eax`. A word-boundary match on register names would report every
 * such repair as a defect, which is the "reads emitted text, encodes formatting
 * by accident" trap CLAUDE.md warns about.
 */
function wrongOperand(emitted: string, cmpAddr: number, clobbers: Set<string>): string | null {
  const tokens = emitted.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? [];
  // `capturedOperandName`'s spelling, derived independently from the address the
  // shape scan found. Any operand index, because which operands were captured is
  // the lifter's business and only "the guard reads one of them" is asked here.
  const capture = `flg_${cmpAddr.toString(16)}_`;
  if (!tokens.some((t) => t.startsWith(capture))) return `no-capture:${capture}`;
  for (const token of tokens) {
    if (isKnownRegister(token) && clobbers.has(canonReg(token))) return `reg:${token}`;
  }
  return null;
}

/** One spoiled reading, before it is judged against what the emitter printed. */
interface SpoiledReading {
  kind: StaleGuardRec["kind"];
  cmp: Instruction;
  spoiler: Instruction;
  clobbers: Set<string>;
  clobbersMemory: boolean;
}

/**
 * Is the flag reader at `insns[readerIndex]` reading a compare the machine has
 * superseded or clobbered? The reading if so, null if the reader's flags are
 * the last `cmp`/`test`'s exactly as it set them — or if no `cmp`/`test`
 * precedes it in the block at all, which is not this audit's population.
 *
 * Asked of the instructions strictly before the reader and of nothing after
 * it, so a `setcc` in the middle of a block is judged against what it could
 * read, not against a compare that came later.
 */
function spoiledReading(insns: Instruction[], readerIndex: number): SpoiledReading | null {
  // The last instruction to write the flags, and the last `cmp`/`test`. When
  // they differ, the reader reads flags the compare did not set.
  let winner: Instruction | null = null;
  let lastCmpTest: Instruction | null = null;
  for (let i = 0; i < readerIndex; i++) {
    const mn = insns[i].mnemonic.toLowerCase();
    if (mn === "cmp" || mn === "test") {
      winner = insns[i];
      lastCmpTest = insns[i];
    } else if (!isFlagTransparent(mn)) {
      winner = insns[i];
    }
  }
  if (!lastCmpTest) return null;

  // Everything written between the compare and the reader, not just the first
  // offender. The row names the first, because that is what identifies the
  // shape to a reader; judging the emitted condition needs the whole set — a
  // guard is a wrong-operand guard if it mentions ANY of them.
  const clobbers = new Set<string>();
  let clobbersMemory = false;
  const readsMemory = lastCmpTest.opStr.includes("[");

  if (winner !== lastCmpTest) {
    // peek-a-bin-jitf. `winner` cannot be null here: it is at least the
    // `cmp` itself, and anything that displaced it is a flag writer.
    return {
      kind: "superseded",
      cmp: lastCmpTest,
      spoiler: winner as Instruction,
      clobbers,
      clobbersMemory,
    };
  }
  // peek-a-bin-xe01. The flags are the compare's; are its operands still the
  // values it compared by the time the reader is evaluated?
  const named = regsNamed(lastCmpTest.opStr);
  let spoiler: Instruction | null = null;
  for (let i = 0; i < readerIndex; i++) {
    if (insns[i].address <= lastCmpTest.address) continue;
    const w = writesOf(insns[i]);
    for (const r of w.regs) clobbers.add(r);
    if (w.mem || w.opaque) clobbersMemory = true;
    const hitsReg = [...w.regs].some((r) => named.has(r));
    if (!spoiler && (w.opaque || hitsReg || (w.mem && readsMemory))) spoiler = insns[i];
  }
  if (!spoiler) return null;
  return { kind: "clobbered", cmp: lastCmpTest, spoiler, clobbers, clobbersMemory };
}

/** Which in-block flag reader an instruction is, or null. The Jcc is the caller's. */
function readerKind(mnemonic: string): "setcc" | "cmovcc" | null {
  const mn = mnemonic.toLowerCase();
  if (/^set[a-z]+$/.test(mn)) return "setcc";
  if (/^cmov[a-z]+$/.test(mn)) return "cmovcc";
  return null;
}

/**
 * Whether an emitted line at a reader is one this audit may judge at all. A
 * value the emitter admitted — `__unrecovered_N`, or the instruction left
 * `unlifted` — is a refusal, which is the other sound answer to a spoiled
 * reading and must not be counted as a wrong-operand one.
 */
function judgeable(line: string): boolean {
  return !line.includes("__unrecovered_") && !line.includes("/* unlifted:");
}

/**
 * Classify every block of `func` that ends in a conditional jump — exactly
 * `extractCondition`'s own gate — and record the ones whose compare reading the
 * machine has superseded or clobbered. Then ask the same of every `setcc` and
 * `cmovcc` in every block (peek-a-bin-n9cl.6).
 *
 * `emittedAt` maps a jcc address to the condition the emitted C states there,
 * for the jccs the polarity pass could anchor. A spoiled block that has an entry
 * is a wrong-operand guard on the page. `emittedLineAt` maps an instruction
 * address to the emitted line the line map places there, for the other
 * readers; omitting it leaves them counted but unjudged.
 */
export function auditStaleGuards(
  out: StaleGuardResult,
  bin: string,
  funcName: string,
  funcAddr: number,
  blocks: BasicBlock[],
  emittedAt: Map<number, string>,
  emittedLineAt?: Map<number, string>,
): void {
  for (const block of blocks) {
    const insns = block.insns;
    const last = insns[insns.length - 1];
    if (!last) continue;

    // The in-block readers first, so a block's rows are in address order.
    for (let i = 0; i < insns.length; i++) {
      const reader = readerKind(insns[i].mnemonic);
      if (!reader) continue;
      out.readers++;
      const reading = spoiledReading(insns, i);
      if (!reading) continue;
      out.readerShapes++;
      const line = emittedLineAt?.get(insns[i].address) ?? null;
      const emitted = line !== null && judgeable(line) ? line : null;
      if (emitted !== null) out.readerEmitted++;
      const why =
        emitted === null
          ? null
          : reading.kind === "superseded"
            ? "superseded"
            : wrongOperand(emitted, reading.cmp.address, reading.clobbers);
      if (why !== null) out.readerNamed++;
      out.rows.push(row(bin, funcName, funcAddr, reader, insns[i], reading, emitted, why));
    }

    const jccMnem = last.mnemonic.toLowerCase();
    if (!jccMnem.startsWith("j") || jccMnem === "jmp") continue;
    out.blocks++;
    const reading = spoiledReading(insns, insns.length - 1);
    if (!reading) continue;

    out.shapes++;
    if (reading.kind === "superseded") out.bySuperseded++;
    else out.byClobbered++;
    const emitted = emittedAt.get(last.address) ?? null;
    if (emitted !== null) out.emittedAtShape++;
    // A `superseded` row's flags belong to an instruction the compare's
    // operands say nothing about, so any guard here reads the wrong test
    // whatever it names — there is no set of "safe" operands to check against.
    // `clobbers` is not even collected for one (the walk above is the
    // clobbered arm's), so the whole-set test would answer vacuously.
    const why =
      emitted === null
        ? null
        : reading.kind === "superseded"
          ? "superseded"
          : wrongOperand(emitted, reading.cmp.address, reading.clobbers);
    if (why !== null) out.named++;
    out.rows.push(row(bin, funcName, funcAddr, "jcc", last, reading, emitted, why));
  }
}

function row(
  bin: string,
  func: string,
  funcAddr: number,
  reader: StaleGuardRec["reader"],
  at: Instruction,
  reading: SpoiledReading,
  emitted: string | null,
  why: string | null,
): StaleGuardRec {
  return {
    bin,
    func,
    funcAddr,
    reader,
    jcc: at.address,
    jccMnem: at.mnemonic.toLowerCase(),
    kind: reading.kind,
    cmpAddr: reading.cmp.address,
    cmpText: `${reading.cmp.mnemonic} ${reading.cmp.opStr}`.trim(),
    bySpoilerAddr: reading.spoiler.address,
    bySpoilerText: `${reading.spoiler.mnemonic} ${reading.spoiler.opStr}`.trim(),
    emitted,
    why,
    clobbers: [...reading.clobbers].sort(),
    clobbersMemory: reading.clobbersMemory,
  };
}
