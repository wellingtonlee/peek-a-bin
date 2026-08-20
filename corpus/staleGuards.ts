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
 *       first and `if (eax != 5)` reads the new EAX. `flagResultSetter`'s
 *       condition 6 had refused exactly this on the *arithmetic* path since
 *       peek-a-bin-b531; the `cmp` path never asked.
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
 *   `named`  — of those, the ones where the emitted C nonetheless carries a
 *              recovered guard at that jcc. THAT is the wrong-operand guard.
 *              Zero means every spoiled reading was refused and admitted as
 *              `__unrecovered_N` instead — "clean is not recovered", which is
 *              the honest direction.
 *
 * WHAT IT DOES NOT CATCH, stated so the zero is read for what it is:
 *
 *   - `named` counts only guards the polarity pass could ANCHOR to their jcc.
 *     A spoiled guard in an arm the auditor could not anchor is invisible here,
 *     so `named` is a LOWER bound. `shapes` has no such dependency.
 *   - It shares `isFlagTransparent` with the code under test. That table is a
 *     fact about x86 and is deliberately single-sourced — a second copy is the
 *     failure mode `flagResult.ts` exists to prevent — but it does mean this
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
import { isFlagTransparent } from "../src/disasm/decompile/flagResult";
import { canonReg, isKnownRegister } from "../src/disasm/decompile/ir";
import type { Instruction } from "../src/disasm/types";

/** One block whose trailing jcc reads flags the recovered compare does not describe. */
export interface StaleGuardRec {
  bin: string;
  func: string;
  funcAddr: number;
  /** The block's trailing conditional jump. */
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
   * guard there. Present means the emitted C states a test the machine does not
   * make; absent means the reading was refused.
   */
  emitted: string | null;
}

export interface StaleGuardResult {
  /** Blocks ending in a conditional jump that were examined at all. */
  blocks: number;
  /** Of those, the ones whose compare reading is spoiled. Expected non-zero. */
  shapes: number;
  /** Of those, the ones an emitted guard nonetheless names. THE DEFECT. Expect 0. */
  named: number;
  bySuperseded: number;
  byClobbered: number;
  rows: StaleGuardRec[];
}

export function emptyStaleGuards(): StaleGuardResult {
  return { blocks: 0, shapes: 0, named: 0, bySuperseded: 0, byClobbered: 0, rows: [] };
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
 * Deliberately NOT `flagResult.ts`'s `clobberedAfter`: that is the predicate the
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
 * Classify every block of `func` that ends in a conditional jump — exactly
 * `extractCondition`'s own gate — and record the ones whose compare reading the
 * machine has superseded or clobbered.
 *
 * `emittedAt` maps a jcc address to the condition the emitted C states there,
 * for the jccs the polarity pass could anchor. A spoiled block that has an entry
 * is a wrong-operand guard on the page.
 */
export function auditStaleGuards(
  out: StaleGuardResult,
  bin: string,
  funcName: string,
  funcAddr: number,
  blocks: BasicBlock[],
  emittedAt: Map<number, string>,
): void {
  for (const block of blocks) {
    const insns = block.insns;
    const last = insns[insns.length - 1];
    if (!last) continue;
    const jccMnem = last.mnemonic.toLowerCase();
    if (!jccMnem.startsWith("j") || jccMnem === "jmp") continue;
    out.blocks++;

    // The last instruction to write the flags, and the last `cmp`/`test`. When
    // they differ, the jcc reads flags the compare did not set.
    let winner: Instruction | null = null;
    let lastCmpTest: Instruction | null = null;
    for (let i = 0; i < insns.length - 1; i++) {
      const mn = insns[i].mnemonic.toLowerCase();
      if (mn === "cmp" || mn === "test") {
        winner = insns[i];
        lastCmpTest = insns[i];
      } else if (!isFlagTransparent(mn)) {
        winner = insns[i];
      }
    }
    if (!lastCmpTest) continue;

    let kind: StaleGuardRec["kind"] | null = null;
    let spoiler: Instruction | null = null;

    if (winner !== lastCmpTest) {
      // peek-a-bin-jitf. `winner` cannot be null here: it is at least the
      // `cmp` itself, and anything that displaced it is a flag writer.
      kind = "superseded";
      spoiler = winner;
    } else {
      // peek-a-bin-xe01. The flags are the compare's; are its operands still
      // the values it compared by the time the guard is evaluated?
      const named = regsNamed(lastCmpTest.opStr);
      const readsMemory = lastCmpTest.opStr.includes("[");
      for (let i = 0; i < insns.length - 1; i++) {
        if (insns[i].address <= lastCmpTest.address) continue;
        const w = writesOf(insns[i]);
        const hitsReg = [...w.regs].some((r) => named.has(r));
        if (w.opaque || hitsReg || (w.mem && readsMemory)) {
          kind = "clobbered";
          spoiler = insns[i];
          break;
        }
      }
    }
    if (!kind || !spoiler) continue;

    out.shapes++;
    if (kind === "superseded") out.bySuperseded++;
    else out.byClobbered++;
    const emitted = emittedAt.get(last.address) ?? null;
    if (emitted !== null) out.named++;
    out.rows.push({
      bin,
      func: funcName,
      funcAddr,
      jcc: last.address,
      jccMnem,
      kind,
      cmpAddr: lastCmpTest.address,
      cmpText: `${lastCmpTest.mnemonic} ${lastCmpTest.opStr}`.trim(),
      bySpoilerAddr: spoiler.address,
      bySpoilerText: `${spoiler.mnemonic} ${spoiler.opStr}`.trim(),
      emitted,
    });
  }
}
