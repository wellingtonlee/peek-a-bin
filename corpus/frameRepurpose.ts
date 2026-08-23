/**
 * A FRAME-RELATIVE OPERAND AFTER THE FRAME REGISTER HAS BEEN REPURPOSED.
 *
 * `src/disasm/stack.ts` establishes the frame displacement `D` from the
 * PROLOGUE and stops at the first later write of the frame register, so a
 * mid-body *reload* of that register is never seen. Two passes downstream rest
 * on it not happening: `decompile/promote.ts`'s `frameRegisterAliases` follows a
 * split copy of the frame register on the grounds that "a frame pointer is
 * invariant for the whole body", and `decompile/structs.ts`'s
 * `stackDerivedBases` excludes the frame register from struct bases on the same
 * reading. Neither has a program point: `matchStackAccess` resolves `[<fp> ± N]`
 * to `arg_N` / `var_N` wherever it appears, at any address, unconditionally.
 *
 * So a mid-body repurposing is a soundness hole, and `peek-a-bin-633s` found the
 * counterexample: `t32!sub_40A810` 0x40a851 and `w32!sub_4092B0` 0x4092f1 are
 * `mov ebp, dword ptr [eax + 0x10]` — MSVC `longjmp` reloading the caller's EBP
 * out of a `jmp_buf` — inside two functions this tree reports as canonically
 * framed. Both are LATENT: no `[ebp ± N]` operand follows either reload, so no
 * wrong name reaches the page. **Nothing automatic modelled that.** The fact was
 * hand-audited at `99203fb`, at `fe244dc` and at `84eed6e` and held every time,
 * only because somebody remembered to look. This row is that hand audit.
 *
 * ── WHAT IS GATED ──────────────────────────────────────────────────────────
 *
 * `after` — a frame-relative operand at an address past a repurposing — GATES AT
 * 0, from the day it lands. Every row is a slot `promote.ts` will name against a
 * frame the machine has thrown away, with no evidence anywhere in the tree that
 * the frame is still in scope there; that is `polarity inverted`'s character
 * rather than a baseline's, and it is 0 on all four binaries today.
 *
 * THE ROW IS "NAMED WITHOUT EVIDENCE", NOT "PROVABLY WRONG", and the difference
 * is one word worth keeping. The scan is ADDRESS-ORDERED, because that is the
 * only order available here and it is the order `633s` hand-measured in; address
 * order is not execution order, so an operand laid out after a repurposing may
 * still execute before it. What a row therefore states is that the tool resolves
 * a frame slot at a point where nothing has shown a frame to be in scope. That
 * is enough to gate: the tool never makes the reachability claim either.
 *
 * ── THE TRAP: AN EPILOGUE RESTORE IS ALSO A WRITE ──────────────────────────
 *
 * `pop <fp>` and `leave` write the frame register, and MSVC lays a MID-FUNCTION
 * epilogue before code that executes later. So "any write after the prologue"
 * is not the rule — measured at `84eed6e`, that reading refuses essentially
 * every framed function (`declared params scanned` 430 -> 0 on t32), and
 * measured here as a control it puts **264/81/79/264 operands over 168/18/16/167
 * functions** into a gate that is supposed to read 0. The write is therefore
 * CLASSIFIED:
 *
 *   `restore`   — the instruction takes the frame register's value off the
 *                 stack, so it is putting back what a `push <fp>` saved:
 *                 `pop <fp>`, `leave`, `popa`/`popad`. 73/0/0/72 `leave` and
 *                 132/18/16/132 `pop` in this corpus, every one of them an
 *                 epilogue. These do NOT open a window.
 *   `repurpose` — any other write of the frame register. 1/0/0/1, the two
 *                 `longjmp` reloads above.
 *
 * THE POSITIVE CONTROL IS THE ONE TO TRUST, because a gate that reads 0 could
 * be reading 0 by not looking. Reversing the address comparison — count the
 * operands BEFORE a repurposing rather than after — makes `npm run corpus`
 * exit 1 and name exactly `t32!sub_40A810` 0x40a820 `push dword ptr [ebp + 8]`
 * after 0x40a851 and its w32 twin 0x4092c0 after 0x4092f1: the "1 each before
 * it" `peek-a-bin-633s` hand-counted, figure for figure. So the operand scan,
 * the classifier and the attribution all reach the witness function; the 0 is a
 * real 0.
 *
 * A `pop <fp>` is a repurposing after all when `stackIdiom.ts`'s
 * `pushedImmediate` pairs it with a `push <imm>` — that idiom is `mov <fp>, imm`
 * and has nothing to do with restoring a frame. It has **0 occurrences here**,
 * so it is a bound on the rule rather than a measured saving, and it is pinned
 * in `build/frameRepurposeAudit.test.ts` rather than by the corpus.
 *
 * ── WHY THE ORACLE IS OUTSIDE THE CODE UNDER TEST ──────────────────────────
 *
 * The judgement is made from the INSTRUCTION STREAM (which instruction writes
 * the frame register, and what form it takes) and the OPERAND TEXT (`[<fp>]`,
 * `[<fp> + N]`, `[<fp> - N]`, the three shapes `matchStackAccess` resolves). It
 * asks `stack.ts` two things and neither is the question being judged: whether a
 * frame was established at all (`frameDelta !== null`, which is what makes the
 * function a member of the population whose slots get named) and where
 * (`frameEstablishedAt`, so the prologue's own `mov <fp>, <sp>` is not counted
 * as a repurposing of itself). It does NOT ask `stack.ts` whether the frame
 * SURVIVES — `stack.ts` has no such answer, and its absence is the defect.
 *
 * The operand grammar is re-spelled here rather than imported from `stack.ts`
 * for `staleGuards.ts`'s reason: an audit that imported the reader would be
 * measuring its own input. It is the machine text, so it is also blind to what
 * copy propagation does downstream — a `[ebp + 8]` that never reaches
 * `promote.ts` still counts. That is the right direction for a screen.
 *
 * ── LIVENESS, AND A STRUCTURAL ZERO ────────────────────────────────────────
 *
 * A population-based audit fails by silently matching nothing, so four counts
 * are reported beside the gate and `corpus.audit.ts` asserts them: `framed`
 * (204/20/18/201), `writes`/`restores` (the classifier discriminating at all),
 * `repurposings` (1/0/0/1) and `operands` (frame-relative operands in framed
 * functions). **The x64 pair contributes a STRUCTURAL zero**: it has no
 * repurposing at all, so its green row says nothing whatever — the same vacuous
 * green `armExits` shows on the two binaries that recover no jump table.
 *
 * ── WHAT IT DOES NOT COVER ─────────────────────────────────────────────────
 *
 *  - A function `stack.ts` reports as UNFRAMED. `analyzeStackFrame` records
 *    `[<fp> - N]` as a local with no `frameDelta` gate, so `var_N` names appear
 *    there too — but there is no established frame for a repurposing to
 *    invalidate, and the wrongness is that the register was never a frame
 *    pointer. That is `633s`'s "frameDelta is the wrong lever" paragraph and a
 *    different class. Measured: 1 such function per binary, whose RBP is a
 *    scratch byte register (`t64!sub_140003B44`'s `setne bpl` / `lea eax,
 *    [rbp - 1]`).
 *  - A HELPER-FRAMED function is covered, and had to be asked for explicitly:
 *    `__SEH_prolog4` establishes the frame inside the helper, so
 *    `frameEstablishedAt` is null for all 31 t32 and 29 w32 of them. The whole
 *    body is then scanned, which is sound because the caller's own prologue is
 *    `push <imm>; push <imm>; call` and writes the frame register nowhere.
 *    Measured 0 writes of any kind in that population, so it is coverage rather
 *    than a saving.
 *  - Anything about the frame register's value across a CALL. A callee that
 *    corrupts a callee-saved register is the callee's defect, not this one.
 */
import { writtenRegsOfInsn } from "../src/disasm/callSummary";
import { canonReg } from "../src/disasm/decompile/ir";
import { pushedImmediate } from "../src/disasm/stackIdiom";
import type { Instruction } from "../src/disasm/types";

/** One frame-relative operand standing after a repurposing. The gated row. */
export interface FrameRepurposeRow {
  bin: string;
  func: string;
  /** The instruction carrying the frame-relative operand. */
  addr: number;
  mnemonic: string;
  opStr: string;
  /** The nearest preceding repurposing, and what it was. */
  repurposedAt: number;
  repurposeInsn: string;
}

export interface FrameRepurposeResult {
  /** Functions with a recovered frame displacement — THE POPULATION. */
  framed: number;
  /** Of those, the ones whose frame a prologue HELPER established. */
  helperFramed: number;
  /** Writes of the frame register past the establishing instruction. */
  writes: number;
  /** …classified as putting a saved value back. Liveness for the classifier. */
  restores: number;
  /** …classified as anything else. The gate's precondition population. */
  repurposings: number;
  /** Functions holding at least one repurposing. */
  funcsRepurposed: number;
  /** `[<fp>]`, `[<fp> + N]` and `[<fp> - N]` operands in framed functions. */
  operands: number;
  /** THE GATE: those of them at an address past a repurposing. */
  after: number;
  rows: FrameRepurposeRow[];
}

export const emptyFrameRepurpose = (): FrameRepurposeResult => ({
  framed: 0,
  helperFramed: 0,
  writes: 0,
  restores: 0,
  repurposings: 0,
  funcsRepurposed: 0,
  operands: 0,
  after: 0,
  rows: [],
});

/**
 * Mnemonics that write the frame register without naming it, which
 * `writtenRegsOfInsn` deliberately does not model.
 *
 * `callSummary.ts` is answering "which VOLATILE registers does this destroy",
 * and RBP is callee-saved, so `leave` and `enter` sit in its `WRITES_NOTHING`
 * table with a docstring saying in terms that the stack pointer is out of scope
 * there. That table is right for its own question and wrong for this one:
 * `leave` is `mov <sp>, <fp>; pop <fp>`, and it occurs 73 times on t32 and 72 on
 * w32 past the prologue. Naming them here rather than reaching into that table
 * keeps the two questions apart.
 *
 * `popa`/`popad` restore all eight GPRs including the frame register and have 0
 * occurrences in this corpus; `enter` establishes a SECOND frame, which is not
 * the frame `stack.ts` measured, and likewise has 0.
 *
 * THE `leave` ARM IS OBSERVABLE BUT DOES NOT MOVE THE GATE TODAY, and both
 * halves of that are worth knowing. Dropping it as a control leaves `after` at 0
 * — a `leave` classified as a restore and a `leave` not seen as a write at all
 * give the same answer — while taking `writes`/`restores` 206/205 -> 133/132 on
 * t32 and 205/204 -> 133/132 on w32, i.e. it is live in the liveness half. What
 * it guards against is `callSummary.ts` ever teaching `writtenRegsOfInsn` about
 * `leave`: this set is consulted FIRST, so the classification stays `restore`.
 * Without it that day would open 73 windows on t32 and 72 on w32, which is
 * control A's 264 red rows.
 */
const IMPLICIT_FP_WRITES = new Set(["leave", "popa", "popad", "popal", "enter"]);

/** …of which these put a value back off the stack. `enter` is not one. */
const IMPLICIT_FP_RESTORES = new Set(["leave", "popa", "popad", "popal"]);

/** Capstone prints a displacement `0x`-prefixed from 0xA up and bare below. */
const DISP = "(0[xX][0-9a-fA-F]+|\\d+)";

/**
 * The three operand shapes `promote.ts`'s `matchStackAccess` resolves to a slot
 * name: a bare frame-register deref, and a constant displacement either way.
 * An indexed operand (`[ebp + eax*4 - 0x10]`) is deliberately not one — that
 * reader requires a `const` on the right and refuses it too.
 */
function frameOperandRe(fp: string): RegExp {
  return new RegExp(`\\[${fp}\\s*(?:\\]|[-+]\\s*${DISP}\\s*\\])`, "i");
}

/** The base mnemonic, with Capstone's `lock`/`rep` prefix stripped. */
function baseMnemonic(mnemonic: string): string {
  const parts = mnemonic.trim().toLowerCase().split(/\s+/);
  return parts[parts.length - 1] ?? "";
}

export type FrameWriteKind = "none" | "restore" | "repurpose";

/**
 * Does this instruction write the frame register, and if so is it putting back
 * a value it took off the stack?
 *
 * Exported for `build/frameRepurposeAudit.test.ts`: three of the four arms have
 * no occurrence in this corpus, so a corpus run cannot show that the classifier
 * discriminates and the controls have to be written against it directly.
 *
 * `index` is this instruction's position in `insns`, which `pushedImmediate`
 * needs to walk back to the `push` a `pop` is paired with.
 */
export function classifyFrameWrite(
  insns: Instruction[],
  index: number,
  fpCanon: string,
): FrameWriteKind {
  const insn = insns[index];
  const mn = baseMnemonic(insn.mnemonic);

  if (IMPLICIT_FP_WRITES.has(mn)) {
    return IMPLICIT_FP_RESTORES.has(mn) ? "restore" : "repurpose";
  }
  if (!writtenRegsOfInsn(insn).includes(fpCanon)) return "none";

  // A `pop` reads the stack, so on its own it is a restore — and it must be, or
  // every mid-function epilogue opens a window (see the module docstring). The
  // one exception is MSVC's `push <imm>` / `pop <reg>` size idiom, which is
  // `mov <reg>, <imm>` wearing a stack instruction's clothes; `pushedImmediate`
  // is the pairing rule `lifter.ts` and `functionDetect.ts` already share, so
  // this cannot disagree with them about what the idiom is.
  if (mn === "pop") return pushedImmediate(insns, index) === null ? "restore" : "repurpose";

  return "repurpose";
}

/**
 * One framed function's contribution. `establishedAt` null with a non-null
 * `frameDelta` is the prologue-helper case: the whole body is scanned, because
 * the frame was established before the first instruction this function owns.
 */
export function auditFrameRepurpose(
  res: FrameRepurposeResult,
  bin: string,
  funcName: string,
  insns: Instruction[],
  frameDelta: number | null,
  establishedAt: number | null,
  is64: boolean,
): void {
  if (frameDelta === null || insns.length === 0) return;
  res.framed++;
  if (establishedAt === null) res.helperFramed++;

  const fp = is64 ? "rbp" : "ebp";
  const fpCanon = canonReg(fp);
  const operandRe = frameOperandRe(fp);

  /** Repurposing addresses, ascending — `insns` is address-ordered. */
  const repurposedAt: { addr: number; text: string }[] = [];
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    if (establishedAt !== null && insn.address <= establishedAt) continue;
    const kind = classifyFrameWrite(insns, i, fpCanon);
    if (kind === "none") continue;
    res.writes++;
    if (kind === "restore") {
      res.restores++;
      continue;
    }
    res.repurposings++;
    repurposedAt.push({ addr: insn.address, text: `${insn.mnemonic} ${insn.opStr}`.trim() });
  }
  if (repurposedAt.length > 0) res.funcsRepurposed++;

  for (const insn of insns) {
    if (!operandRe.test(insn.opStr)) continue;
    res.operands++;
    // The NEAREST preceding repurposing, so a row names the write it stands
    // after rather than the function's first one.
    let nearest: { addr: number; text: string } | null = null;
    for (const r of repurposedAt) {
      if (r.addr < insn.address) nearest = r;
      else break;
    }
    if (nearest === null) continue;
    res.after++;
    res.rows.push({
      bin,
      func: funcName,
      addr: insn.address,
      mnemonic: insn.mnemonic,
      opStr: insn.opStr,
      repurposedAt: nearest.addr,
      repurposeInsn: nearest.text,
    });
  }
}
