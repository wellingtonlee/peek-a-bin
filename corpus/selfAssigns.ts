/**
 * A SELF-ASSIGNMENT IN THE EMITTED C, RESOLVED BACK TO THE INSTRUCTION IT CAME FROM.
 *
 * `eax = eax;` is one line of noise if the machine instruction behind it really
 * is an identity — MSVC's multi-byte NOPs (`lea ecx,[ecx+0x0]`), its hot-patch
 * pad (`mov edi,edi`), its `or al,al` test-that-writes, an `add eax,0x0`. It is
 * something else entirely if the instruction behind it is `add edi, esi`: then
 * an operand went missing between the disassembly and the page, the emitted C
 * states that a register keeps a value the machine changes, and the
 * self-assignment is the ONLY visible trace the defect leaves.
 *
 * That is not hypothetical. `peek-a-bin-3axd` — every `push <imm>` / `pop <reg>`
 * in the image lifting to no definition, 97 wrong reads over 28 functions on
 * t32 alone, including an inverted success/failure return — was found because
 * two of those wrong reads landed on a self-assignment. Only two of ninety-seven;
 * the trace is faint, which is exactly why suppressing it would be so expensive.
 *
 * WHY THIS EXISTS AS AN AUDIT RATHER THAN A SUPPRESSION. Every other gate in
 * `npm run corpus` is structurally blind to a lost operand:
 *
 *   - `gcc -fsyntax-only` compiles `eax = eax;` without a murmur, and
 *     `preludeFor` invents a declaration for the name if it needs one;
 *   - polarity judges the operator of a guard that exists, and this changes
 *     neither the operator nor whether the guard is there;
 *   - `staleGuards` and `staleReads` compare a name against the writes that
 *     reach it — and a self-assignment IS a write of that name, so every read
 *     below it is reached by a definition and passes;
 *   - `lostDefs` counts a read whose reaching definition disappeared, and this
 *     one has not disappeared;
 *   - `arity`, `offsetof`, `armExits` and `wildBranches` are other questions;
 *   - the statement-drop audit takes its snapshot AFTER `foldBlock`, so an
 *     operand removed at or before `foldBlock` is outside its comparison. The
 *     statement is still there. It is one operand short.
 *
 * ── WHAT IS GATED, AND WHAT IS NOT ─────────────────────────────────────────
 *
 * The bead that asked for this (`peek-a-bin-o7pj`) recommended gating at 0
 * "the subset whose instruction is not an identity idiom". **That subset is not
 * empty and gating it at 0 would be a false red.** t32 0x403034 and w32
 * 0x40320B are `sub ecx, ebx` where EBX's only write anywhere in the function
 * is the `xor ebx,ebx` above it, so the fold is right to constant-propagate the
 * zero and `ecx = ecx;` is correct output. A legitimate zero-propagation and a
 * lost operand are the SAME SHAPE from here, and telling them apart is the
 * general dataflow question this audit does not answer. So:
 *
 *   `identity`  — the instruction is an identity for EVERY value it reads,
 *                 decided from the encoding alone. THE LIVENESS DENOMINATOR.
 *   `openOperand` — the instruction reads a value the emitted line does not
 *                 mention, so the identity holds only if that value is the
 *                 neutral one. REPORTED, judged in `compare.mjs`, NOT GATED —
 *                 this is where a lost operand lands, and a RISE is the signal.
 *                 Split by whether the open operand is zero-corroborated (see
 *                 below) so a rise is cheap to triage.
 *   `wrong`     — GATED at 0. The emitted name is not an alias of the
 *                 instruction's destination, so the line and the address it
 *                 carries are about different registers and the attribution is
 *                 broken whatever the dataflow says.
 *   `unresolved` — GATED at 0. No address on the line, or no instruction at
 *                 that address in the function it was emitted for. An
 *                 unjudgeable row, and it must not be dropped: a row silently
 *                 leaving the population is how a gate reads 0 by not looking.
 *
 * Read the two gates for what they are: they gate the INSTRUMENT'S INTEGRITY,
 * not the defect class. The detector for the defect class is the `openOperand`
 * baseline, and it has the status `unrecovered values` has — a number that is
 * not zero, that no threshold is established for, and whose movement between
 * two pinned runs is what is judged.
 *
 * ZERO-CORROBORATION is a HINT, never a verdict. For an open operand that is a
 * register, the function's own instructions are asked whether every write of
 * that register zeroes it (`xor r,r`, `sub r,r`, `and r,0`, `mov r,0`), using
 * `writtenRegsOfInsn` so the write model is the one `callSummary.ts` already
 * uses rather than a second copy, and a chain of register-to-register copies is
 * followed so that `xor eax,eax / mov ebx,eax` — ordinary MSVC output and a real
 * zero — corroborates. Corroborated is what both base rows are;
 * `peek-a-bin-3axd`'s defect was the opposite — ESI had five definitions with
 * one zeroing, and none of the six is a register copy.
 *
 * It is deliberately NOT GATED, and following the copy chain does not change
 * that. `peek-a-bin-o7pj` recorded a standing upgrade to gate the
 * uncorroborated half at 0 once the chain was followed, on the pattern
 * `arity over` was gated by; the chain landed and **the gate was refused**,
 * because the two are not the same kind of row. An `arity over` row is provably
 * an argument the machine never passed — no entry in `apitypes.ts` is variadic,
 * so the oracle is outside the code under test. An uncorroborated row is this
 * scan reporting that IT could not confirm the operand is zero, which is a
 * statement about the scan. Zero reaches a register by routes no peephole
 * enumerates — a frame slot the fold proved, a `movzx` of a byte that is zero, a
 * call returning zero, a phi of two zeroing paths laid out below the site — and
 * the scan is address-ordered rather than dominance-ordered on top of that. Each
 * of those is a red gate on correct C. What it is instead is the triage split on
 * a REPORTED count, so that a rise in `openOperand` comes with the cheap
 * question already answered.
 *
 * THE DENOMINATOR IS NOT DECORATION. `peek-a-bin-qbk3` emptied the entire x64
 * population three commits before this was written (six `lock or byte ptr
 * [rsp], 0` fences that folded to `var_0 = var_0`), so every count here is 0 on
 * t64/w64 *because there is nothing to see* — the same vacuous green `armExits`
 * shows on the two binaries that recover no jump table. `identity` is asserted
 * non-zero over the corpus as a whole rather than per binary, since a binary
 * whose emitted C contains no identity idiom is a legitimate state, and `lines`
 * is the liveness half of the text scan itself.
 *
 * WHAT IT CANNOT SEE. A lost operand that leaves no self-assignment behind —
 * which is the overwhelming majority of them, 95 of `3axd`'s 97. This is a
 * faint-trace detector: a green reading is weak evidence, a red one is proof.
 *
 * The text scan is anchored on the first ` = ` and a trailing `;`, ignores
 * indentation, and compares the two sides after trimming, so a reformat cannot
 * break it. `for` headers are scanned too — their init and update are
 * statements that do not end in `;` — so the population cannot hide there.
 *
 * THE OPERAND GRAMMAR IS x86, and that is sound only because `npm run corpus`
 * drives four x86 binaries and nothing else — `preflight.ts`'s `BinKey` does not
 * model the two ARM64 ones, which is `corpus/comments.ts`'s territory. On A64
 * every rule here is wrong in the quiet direction: no A64 instruction matches
 * one, so every row would be classed `openOperand` and the denominator would go
 * to 0, which is the vacuous-green shape this file warns about above. If an
 * ARM64 binary ever reaches this audit, the identity rules have to be written for
 * A64 (`mov x0, x0`, `orr x0, x0, x0`, `add x0, x0, #0`) and the exact-mnemonic
 * matching CLAUDE.md insists on for A64 applies — `brk` is not a `br`.
 */

import { writtenRegsOfInsn } from "../src/disasm/callSummary";
import { withoutLockPrefix } from "../src/disasm/decompile/flagModel";
import { canonReg, isKnownRegister } from "../src/disasm/decompile/ir";
import type { Instruction } from "../src/disasm/types";
import { forHeaderCond, guardShape, splitForHeader, statementOnLine } from "./guardShape";

/** One `X = X` in the emitted C, with the instruction it was resolved to. */
export interface SelfAssignRec {
  bin: string;
  func: number;
  fname: string;
  /** 0-based index of the emitted line, so the row can be found in the C. */
  line: number;
  /** The emitted line, trimmed. */
  text: string;
  /** The identifier on both sides of the `=`. */
  name: string;
  /** The address the line map gave, i.e. the `IRAssign.addr`. Null when none. */
  addr: number | null;
  mnemonic: string | null;
  opStr: string | null;
  verdict: "identity" | "openOperand" | "wrong" | "unresolved";
  /**
   * For an `openOperand` row: whether every write of the open operand register
   * anywhere in this function zeroes it. A HINT, not a verdict — see the header.
   * Null when the open operand is not a register, or the row is not one.
   */
  zeroCorroborated: boolean | null;
  /** Which rule decided it, or why none could. */
  why: string;
}

export interface SelfAssignResult {
  rows: SelfAssignRec[];
  /** Instruction is an identity for every value it reads. THE DENOMINATOR. */
  identity: number;
  /** Identity only if a value the line does not mention is neutral. NOT gated. */
  openOperand: number;
  /** Of those, how many have every write of the open register zeroing it. */
  openZeroCorroborated: number;
  /** GATED at 0: the emitted name is not an alias of the instruction's dest. */
  wrong: number;
  /** GATED at 0: no address, or no instruction there. An unjudgeable row. */
  unresolved: number;
  /** Functions whose emitted C contains at least one self-assignment. */
  funcsAffected: number;
  /** Lines of emitted C read. Instrument liveness for the scan itself. */
  lines: number;
  /** Self-assignments found inside a `for` header rather than on their own line. */
  inForHeader: number;
  /**
   * `for` headers read. Instrument liveness for the clause scan, which has its
   * own way of matching nothing: this scan's `wrong` and `unresolved` columns
   * gate at 0, and a header shape it stopped recognising would take rows out of
   * a gate silently (`peek-a-bin-hfsq`).
   */
  forHeaders: number;
  /**
   * `for` headers recognised as such and then refused by `splitForHeader`.
   * `emit.ts` always writes three clauses, so a non-zero here is a header whose
   * init and update were not read at all. Expect 0.
   */
  forHeadersUnsplit: number;
}

export const emptySelfAssigns = (): SelfAssignResult => ({
  rows: [],
  identity: 0,
  openOperand: 0,
  openZeroCorroborated: 0,
  wrong: 0,
  unresolved: 0,
  funcsAffected: 0,
  lines: 0,
  inForHeader: 0,
  forHeaders: 0,
  forHeadersUnsplit: 0,
});

/**
 * An emitted assignment statement. The first ` = ` cannot fall inside `==`,
 * `!=`, `<=`, `>=` or a compound `|=`/`+=`, since each of those puts a non-space
 * immediately on one side of the `=`.
 *
 * It is asked of the STATEMENT a line carries, not of the line, so `guardShape`
 * decides where the statement starts. That costs nothing today — the emitter
 * one-lines only terminators, and none of those contains a ` = ` — and it is
 * what stops the guard being read as the destination if that ever changes
 * (`peek-a-bin-0qib`, `peek-a-bin-hfsq`).
 */
const ASSIGN_LINE = /^\s*(.+?) = (.+);\s*$/;

/** A `for` clause: `X = Y` with no trailing semicolon, so it needs its own test. */
const FOR_CLAUSE = /^\s*(.+?) = (.+?)\s*$/;

/** The spellings a zero immediate can take, and nothing else. */
function isZeroImmediate(op: string): boolean {
  return /^-?(?:0x0+|0)$/.test(op.trim());
}

/** Split an x86 operand list, respecting `[...]`, which contains no comma. */
function splitOperands(opStr: string): string[] {
  const out: string[] = [];
  let depth = 0;
  let cur = "";
  for (const c of opStr) {
    if (c === "[") depth++;
    else if (c === "]") depth--;
    if (c === "," && depth === 0) {
      out.push(cur.trim());
      cur = "";
      continue;
    }
    cur += c;
  }
  if (cur.trim() !== "") out.push(cur.trim());
  return out;
}

/**
 * Whether `lea dst, <mem>` computes exactly `dst`.
 *
 * The multi-byte NOP: `lea ecx, [ecx]`, `lea esp, [esp + 0]`, and the forms an
 * assembler pads with the pseudo zero index register. Requires the base to be
 * `dst` itself at scale 1, every displacement term to be zero, and any index
 * term to be `eiz`/`riz`, which names no real register and contributes nothing
 * whatever the scale.
 */
function leaIsIdentity(dst: string, mem: string): boolean {
  const m = /\[([^\]]*)\]$/.exec(mem.trim());
  if (!m) return false;
  let sawBase = false;
  for (const plus of m[1].split("+")) {
    const pieces = plus.split("-");
    for (let k = 0; k < pieces.length; k++) {
      const term = pieces[k].trim();
      if (term === "") continue;
      const scaled = /^([A-Za-z]\w*)\s*\*\s*(\d+)$/.exec(term);
      const regName = scaled ? scaled[1] : term;
      const scale = scaled ? Number.parseInt(scaled[2], 10) : 1;
      if (regName === "eiz" || regName === "riz") continue;
      if (isKnownRegister(regName)) {
        // A negated register, a scaled one, a second base, or one that is not
        // the destination all mean the address is not `dst` itself.
        if (k > 0 || regName !== dst || scale !== 1 || sawBase) return false;
        sawBase = true;
        continue;
      }
      if (!/^(?:0x[0-9a-fA-F]+|\d+)$/.test(term)) return false;
      if (!isZeroImmediate(term)) return false;
    }
  }
  return sawBase;
}

/**
 * Same-register forms that write the value they read, at every width.
 *
 * `mov` writes what it read; `or` and `and` are idempotent; `xchg r,r` swaps a
 * value with itself. `add r,r` doubles and `sub r,r` / `xor r,r` zero, which is
 * why the set is a whitelist and not "the second operand is the first".
 */
const SAME_REG_IDENTITY = new Set(["mov", "or", "and", "xchg"]);

/** `<dst> op 0` forms that leave `<dst>` unchanged whatever it held. */
const ZERO_RHS_IDENTITY = new Set(["add", "sub", "or", "xor", "shl", "shr", "sar", "rol", "ror"]);

/**
 * Forms whose identity depends on a value the emitted line does not mention.
 *
 * `add`/`sub` with a register or memory source is an identity iff that source
 * is 0; `or`/`xor` likewise; a shift iff the count is 0; `and` iff the mask is
 * all-ones; `imul` iff the multiplier is 1; a `mov` or a `pop` iff the value
 * moved in equals the one already there — which the `push r`/`pop r` pairing
 * makes an ordinary correct case. All of them read something `X = X` is silent
 * about, and that is the property, not the arithmetic.
 */
const OPEN_OPERAND_FORMS = new Set([
  "add",
  "sub",
  "or",
  "xor",
  "and",
  "shl",
  "shr",
  "sar",
  "rol",
  "ror",
  "imul",
  "mov",
  "movzx",
  "movsx",
  "movsxd",
  "pop",
  "lea",
  "neg",
  "adc",
  "sbb",
]);

interface Rule {
  verdict: "identity" | "openOperand";
  why: string;
  /** The operand the emitted line is silent about, when there is one. */
  open: string | null;
}

/**
 * Classify the instruction a self-assignment carries the address of.
 *
 * Decided from the instruction's own OPERANDS, never from its mnemonic alone —
 * which is what keeps this useful: a lost operand is still spelled in
 * `insn.opStr`, so `add edi, esi` cannot match `add <dst>,0` and cannot match a
 * same-register form, however the emitted line reads.
 */
function classify(insn: Instruction, is64: boolean, size: number): Rule {
  const mn = withoutLockPrefix(insn.mnemonic);
  const ops = splitOperands(insn.opStr);

  if (mn === "nop") return { verdict: "identity", why: "nop", open: null };

  if (mn === "lea" && ops.length === 2 && isKnownRegister(ops[0]) && leaIsIdentity(ops[0], ops[1]))
    return { verdict: "identity", why: "lea <r>,[<r>] — multi-byte NOP", open: null };

  if (
    ops.length === 2 &&
    ops[0] === ops[1] &&
    isKnownRegister(ops[0]) &&
    SAME_REG_IDENTITY.has(mn)
  ) {
    // `mov <r32>, <r32>` ON X64 IS A ZERO-EXTENSION, NOT A NO-OP: a 32-bit
    // write clears bits 63:32 of the parent, which is exactly what MSVC asks
    // for with `mov r8d, r8d`. `peek-a-bin-tez6` lifts it as `x & 0xFFFFFFFF`
    // for that reason, so it can no longer produce a self-assignment — and if
    // one appears again, that fix has regressed. It is `openOperand` rather
    // than `wrong` because the upper half it clears is a value this line is
    // silent about, and where that half is already zero the line is right.
    // Every other width is an unconditional identity: `mov al,al` and
    // `mov ax,ax` leave the parent's upper bits alone, `mov rax,rax` writes
    // what it read, and a PE32 image has no upper half to clear.
    if (mn === "mov" && is64 && size === 4)
      return {
        verdict: "openOperand",
        why: "mov <r32>,<r32> on x64 ZERO-EXTENDS — identity only if bits 63:32 were already 0 (peek-a-bin-tez6 regressed?)",
        open: `${ops[0]}[63:32]`,
      };
    return { verdict: "identity", why: `${mn} <r>,<r>`, open: null };
  }

  if (ops.length === 2 && ZERO_RHS_IDENTITY.has(mn) && isZeroImmediate(ops[1]))
    return { verdict: "identity", why: `${mn} <dst>,0`, open: null };

  if (OPEN_OPERAND_FORMS.has(mn)) {
    const open = ops.length >= 2 ? ops[ops.length - 1] : (ops[0] ?? "");
    return {
      verdict: "openOperand",
      why: `${mn}: identity only if '${open}' is the neutral value — the emitted line is silent about it`,
      open,
    };
  }

  // Not a form this audit models at all. Still an open operand rather than a
  // verdict of wrongness: the honest statement is that the emitted line does
  // not account for what the instruction reads, and which value would make it
  // an identity is not a question asked here.
  return {
    verdict: "openOperand",
    why: `${mn} is not a modelled identity — the emitted line accounts for none of what it reads`,
    open: ops.length >= 2 ? ops[ops.length - 1] : null,
  };
}

/** Mnemonic/operand shapes that write their destination a zero. */
function zeroesItsDest(insn: Instruction): boolean {
  const mn = withoutLockPrefix(insn.mnemonic);
  const ops = splitOperands(insn.opStr);
  if (ops.length !== 2) return false;
  if ((mn === "xor" || mn === "sub") && ops[0] === ops[1]) return true;
  if ((mn === "mov" || mn === "and") && isZeroImmediate(ops[1])) return true;
  return false;
}

/**
 * A register-to-register `mov`, i.e. a copy whose source is a register.
 *
 * `[dst, src]`, or null for anything else. No width test is needed and adding
 * one would state something the ISA already guarantees: x86 `mov` requires its
 * two operands to be the same size, so there is no `mov al, ebx` to exclude.
 */
function regCopy(insn: Instruction): [string, string] | null {
  if (withoutLockPrefix(insn.mnemonic) !== "mov") return null;
  const ops = splitOperands(insn.opStr);
  if (ops.length !== 2) return null;
  if (!isKnownRegister(ops[0]) || !isKnownRegister(ops[1])) return null;
  return [ops[0], ops[1]];
}

/** How far a copy chain is followed. Hygiene: see the termination note below. */
const MAX_COPY_CHAIN_DEPTH = 16;

/**
 * Does every write of `reg` that precedes `at` in ADDRESS ORDER zero it,
 * following a chain of register-to-register copies?
 *
 * A HINT for triage and never a verdict, for the reasons in the header and
 * below. Address order is not dominance — the same one-directional
 * approximation `firstCalleeSavedWrites` makes, and a write laid out below the
 * site that only a back edge reaches is not seen. It stops at the site precisely
 * because the epilogue does not count: `sub_402FEF` restores EBX with a
 * `pop ebx` at 0x403072, and asking the whole function would report that
 * save/restore as a non-zeroing write and lose the corroboration for a genuine
 * zero.
 *
 * `writtenRegsOfInsn` is `callSummary.ts`'s write model, borrowed rather than
 * re-derived, so the two cannot disagree about what writes a register.
 *
 * ── THE COPY CHAIN ─────────────────────────────────────────────────────────
 *
 * `xor eax,eax / mov ebx,eax` is ordinary MSVC output and a real zero, and a
 * scan that reads only the writes of EBX itself calls it UNcorroborated — which
 * is a spurious triage row, because the fold this audit is watching proves zero
 * *through* copies. So a write that is a register copy is admitted when every
 * write of its SOURCE, before the copy's own address, zeroes it. Three details
 * are the whole rule and each is pinned by a test:
 *
 *   - **A source with NO write before the copy is refused**, because the
 *     recursive call keeps the `writes > 0` requirement. That register holds the
 *     function's ENTRY value, which is arbitrary; a vacuous true there would
 *     corroborate `mov edi, esi` on an untouched ESI and turn the hint into a
 *     rubber stamp. This is the one way the strengthening could have driven the
 *     count to 0 by no longer looking.
 *   - **Only `mov <r>,<r>` chains.** A memory load, a `lea`, an arithmetic
 *     result or a `pop` is refused: whether the value it produces is zero is the
 *     general dataflow question, and `mov esi, [ebp+8]` is exactly the write
 *     that (correctly) keeps `peek-a-bin-3axd`'s three sites uncorroborated.
 *   - **Termination is by construction, not by the depth cap.** Each recursive
 *     call is asked at `insn.address`, which is strictly below the `at` it was
 *     asked at, so the chain is well-founded on a finite instruction stream.
 *     `MAX_COPY_CHAIN_DEPTH` is hostile-input hygiene, and refusing at the cap
 *     is the safe direction — it is the pre-strengthening answer.
 *
 * The chain does NOT make this gateable, and the reason is not the chain's
 * reach: an uncorroborated row means "this scan could not confirm the operand
 * is zero", which is not a statement about the machine at all, where an
 * `arity over` row is provably an argument the machine never passed. Zero
 * reaches a register by routes no peephole enumerates — a frame slot the fold
 * proved, a `movzx` of a byte that is zero, a call that returns zero, a phi of
 * two zeroing paths laid out below the site — and every one of those would be a
 * red gate on correct output. Exported so the reach census and
 * `build/selfAssignAudit.test.ts` can ask it directly.
 */
export function everyWriteZeroes(
  reg: string,
  insns: Instruction[],
  at: number,
  depth = 0,
): boolean {
  const canon = canonReg(reg);
  let writes = 0;
  for (const insn of insns) {
    if (insn.address >= at) continue;
    if (!writtenRegsOfInsn(insn).includes(canon)) continue;
    writes++;
    if (zeroesItsDest(insn)) continue;
    const copy = regCopy(insn);
    if (
      copy !== null &&
      canonReg(copy[0]) === canon &&
      depth < MAX_COPY_CHAIN_DEPTH &&
      everyWriteZeroes(copy[1], insns, insn.address, depth + 1)
    )
      continue;
    return false;
  }
  return writes > 0;
}

/** What one emitted line states, as far as this audit is concerned. */
interface LineReading {
  /** Every `X = X` the line states, whether as a statement or as a `for` clause. */
  names: string[];
  /** How many of those came from a `for` header's clauses. */
  inForHeader: number;
  /** Whether the line IS a `for` header, whatever it contains. Liveness. */
  forHeader: boolean;
  /** Whether it is a `for` header whose clauses could not be split. Expect false. */
  forUnsplit: boolean;
}

/**
 * Every `X = X` this line states.
 *
 * TWO KINDS OF SITE, and neither may be read with its own hand-rolled pattern.
 * A statement of its own is `ASSIGN_LINE` over `statementOnLine`, so a one-lined
 * guard's body is read as the statement it is rather than with the guard glued
 * to the front of the destination. A `for` header holds its init and its update
 * as statements too, and that is `guardShape` plus `splitForHeader` — where it
 * used to be `/^\s*for \((.*)\) \{\s*$/`, a second hand-rolled guard-header
 * pattern in a file whose `wrong` and `unresolved` columns GATE at 0, encoding
 * single-space formatting and a trailing brace that a formatting change would
 * have taken rows out of the gate on, silently (`peek-a-bin-hfsq`).
 *
 * The two are asked independently rather than one-or-the-other: a `for` header
 * ends in `{` so `ASSIGN_LINE` cannot match it, and an inline `for` — a shape
 * the emitter does not write — would carry both its clauses and a body
 * statement, each of which is a real site.
 */
function selfAssignsOnLine(line: string): LineReading {
  const out: LineReading = { names: [], inForHeader: 0, forHeader: false, forUnsplit: false };
  const cond = forHeaderCond(guardShape(line));
  if (cond !== null) {
    out.forHeader = true;
    const clauses = splitForHeader(cond);
    if (clauses === null) out.forUnsplit = true;
    else
      for (const cl of clauses) {
        const m = FOR_CLAUSE.exec(cl);
        if (m && m[1].trim() === m[2].trim()) {
          out.names.push(m[1].trim());
          out.inForHeader++;
        }
      }
  }
  const stmt = ASSIGN_LINE.exec(statementOnLine(line));
  if (stmt && stmt[1].trim() === stmt[2].trim()) out.names.push(stmt[1].trim());
  return out;
}

/**
 * Scan one decompiled function's emitted C.
 *
 * `insns` is that function's own instruction stream, which is where the address
 * a self-assignment carries has to resolve — an assignment attributed to an
 * address outside the function it was emitted in is itself a finding, and shows
 * up here as `unresolved`.
 */
export function auditSelfAssigns(
  out: SelfAssignResult,
  bin: string,
  fname: string,
  faddr: number,
  code: string,
  lineMap: [number, number][],
  insns: Instruction[],
  is64: boolean,
): void {
  if (code === "") return;
  const lines = code.split("\n");
  out.lines += lines.length;
  const addrOfLine = new Map<number, number>(lineMap);
  let byAddr: Map<number, Instruction> | null = null;
  let hits = 0;

  for (let i = 0; i < lines.length; i++) {
    const read = selfAssignsOnLine(lines[i]);
    // Counted before the early return: the liveness halves are about the lines
    // the scan RECOGNISED, not about the ones that turned out to hold a row.
    if (read.forHeader) out.forHeaders++;
    if (read.forUnsplit) out.forHeadersUnsplit++;
    if (read.names.length === 0) continue;
    out.inForHeader += read.inForHeader;
    for (const name of read.names) {
      hits++;
      const addr = addrOfLine.get(i);
      if (byAddr === null) {
        byAddr = new Map<number, Instruction>();
        for (const insn of insns) byAddr.set(insn.address, insn);
      }
      const insn = addr === undefined ? undefined : byAddr.get(addr);
      const base = {
        bin,
        func: faddr,
        fname,
        line: i,
        text: lines[i].trim(),
        name,
        addr: addr ?? null,
        mnemonic: insn?.mnemonic ?? null,
        opStr: insn?.opStr ?? null,
      };
      if (insn === undefined) {
        out.unresolved++;
        out.rows.push({
          ...base,
          verdict: "unresolved",
          zeroCorroborated: null,
          why:
            addr === undefined
              ? "the emitted line carries no address"
              : "no instruction at that address in the function it was emitted for",
        });
        continue;
      }
      // The name the emitted C uses must be an alias of the register the
      // instruction writes, or the line and the address it carries are about
      // different registers and no dataflow answer can rescue it. Asked only
      // where both are registers: a memory destination (`var_0` from a promoted
      // frame slot) has no register name to compare with.
      const dstOp = splitOperands(insn.opStr)[0] ?? "";
      if (isKnownRegister(dstOp) && isKnownRegister(name) && canonReg(dstOp) !== canonReg(name)) {
        out.wrong++;
        out.rows.push({
          ...base,
          verdict: "wrong",
          zeroCorroborated: null,
          why: `emitted name '${name}' is not an alias of the destination '${dstOp}' of the instruction it carries the address of`,
        });
        continue;
      }
      const rule = classify(insn, is64, isKnownRegister(name) ? sizeOfName(name) : 0);
      if (rule.verdict === "identity") {
        out.identity++;
        out.rows.push({ ...base, verdict: "identity", zeroCorroborated: null, why: rule.why });
        continue;
      }
      const corroborated =
        rule.open !== null && isKnownRegister(rule.open)
          ? everyWriteZeroes(rule.open, insns, insn.address)
          : null;
      if (corroborated === true) out.openZeroCorroborated++;
      out.openOperand++;
      out.rows.push({
        ...base,
        verdict: "openOperand",
        zeroCorroborated: corroborated,
        why:
          corroborated === true
            ? `${rule.why} — every write of '${rule.open}' before this address zeroes it (corroborated, a HINT not a verdict)`
            : rule.why,
      });
    }
  }
  if (hits > 0) out.funcsAffected++;
}

/**
 * The width of the register the emitted line names, which is the only place the
 * live range's width is recorded — `mov r8d, r8d` and `mov r8, r8` are the same
 * instruction shape and different facts (see `classify`).
 */
function sizeOfName(name: string): number {
  return REG_SIZES[name] ?? 0;
}

/** Widths written out rather than imported, so the audit does not agree with
 * `regSize`'s fallback-to-4 for an unrecognised name by construction. */
const REG_SIZES: Record<string, number> = (() => {
  const m: Record<string, number> = {};
  const q = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"];
  const d = ["eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"];
  const w = ["ax", "bx", "cx", "dx", "si", "di", "bp", "sp"];
  const b = ["al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl", "ah", "bh", "ch", "dh"];
  for (const r of q) m[r] = 8;
  for (const r of d) m[r] = 4;
  for (const r of w) m[r] = 2;
  for (const r of b) m[r] = 1;
  for (let i = 8; i <= 15; i++) {
    m[`r${i}`] = 8;
    m[`r${i}d`] = 4;
    m[`r${i}w`] = 2;
    m[`r${i}b`] = 1;
  }
  return m;
})();
