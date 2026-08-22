/**
 * A GUARD THAT IS WRONG ON ONE INCOMING EDGE.
 *
 * A Jcc alone in its basic block sets no flags of its own, so the test it makes
 * was made in the block *before* it — and where there is more than one such
 * block, there is more than one test. One block-local `if` can state only one
 * of them. If the predecessors disagree about what the test is, then whichever
 * one the emitted condition spells, the emitted C claims the machine makes that
 * test on **every** path into the block, and on at least one path it does not.
 *
 *     ; t64!sub_140002A2C
 *     140002afa  test rbx, rbx
 *     140002afd  je   0x140002c5b     ← a block holding nothing but this jcc
 *     …
 *     140002c16  test rbp, rbp
 *     140002c19  jmp  0x140002afd     ← the other way in
 *
 * `if (rbx == 0)` is the machine's test on the fallthrough edge and is a
 * statement about RBX in a program that, on the other edge, branched on RBP.
 *
 * WHY EVERY OTHER AUDIT HERE IS BLIND TO IT, which is the reason this file
 * exists. Demonstrated by execution rather than by reading: drop the agreement
 * test in `flagModel.ts`'s `unanimousCompare` and answer such a block from its
 * FIRST predecessor, and `npm run corpus` exits 0 with verdict "no regression"
 * on the *previous* instrument set (measured at 16f1633 — polarity 0 inverted
 * and 0 mismatch over 519/577/499/442 audited all correct, gcc 1127/1127,
 * offsetof ratio 1.00, staleGuards named 0, every other gate flat).
 *
 *   - `polarity` judges the emitted comparison's OPERATOR against the jcc's
 *     taken sense. The operator is right — it is the OPERANDS that belong to
 *     one edge — so the guard is scored `OK` and the ratio stays 1.00.
 *   - `corpus/staleGuards.ts` is BLOCK-LOCAL by construction: its scan needs a
 *     `cmp`/`test` in the same block as the jcc, and a block holding nothing
 *     but the jcc has none, so these blocks are not in its denominator at all.
 *   - `gcc` compiles it. It is not `__unrecovered_N`, so the recovery baseline
 *     scores the wrong reading as an IMPROVEMENT — unrecovered values FALL by
 *     one per site. The statement-drop audit counts statements dropped, not
 *     readings that are wrong.
 *
 * So the refusal in `unanimousCompare` was protected by three unit tests and by
 * nothing in `npm run corpus`, and a future relaxation of it — including a
 * well-intentioned one — got a green run (peek-a-bin-0xe2).
 *
 * FOUR COUNTS, and the last two are the defect said two ways:
 *
 *   `multi`    — cross-edge blocks entered from several predecessors. The
 *                population the rule governs. A property of the machine code.
 *   `differ`   — of those, the ones whose edges make provably different tests.
 *                Also a property of the machine code, so a decompiler fix does
 *                not move it: it is the instrument-liveness number, and this
 *                audit measures an ABSENCE, which an instrument that has
 *                quietly stopped looking reports as the healthiest number in
 *                the report.
 *   `admitted` — of those, the ones the code answered from a predecessor at
 *                all. A GATE at 0, and the COMPLETE one: both routes to a
 *                condition here take their instruction stream from
 *                `flagScanStream(block, flagPredecessor(…))`, so an admitted
 *                predecessor is necessary for either to spell anything, and it
 *                is address-exact with no anchoring in the way.
 *   `named`    — of `differ`, the ones an emitted guard is anchored on the page
 *                for. The same defect stated at the OUTPUT, and also a GATE at
 *                0 — but a LOWER bound, because the polarity pass anchors only
 *                some guards.
 *
 * BOTH gates are needed and neither subsumes the other in the way that matters.
 * `named` is the stronger *claim* — a test the machine does not make, in C that
 * compiles — and the weaker *coverage*: under the negative control below it
 * sees 8 of the 12 sites and, crucially, NOT the one this audit was built for.
 * `admitted` is the weaker claim — it reads the decision the code made rather
 * than the text it produced, which makes this half a differential test between
 * two independently written answers to the same question (the pattern the PE
 * parser is checked with) rather than an oracle outside the question — and it
 * is complete: 12 of 12, the witness among them.
 *
 * A middle tier was considered and refused: replicating `pipeline.ts` stage 1
 * to read the `IRBranch` condition the lifter produced, the way `popReads.ts`
 * and `lostDefs.ts` replicate the lift. `admitted` is a strict superset of it —
 * no branch condition exists at such a block without an admitted predecessor —
 * so gating `admitted` is stricter, and it keeps this file a leaf that imports
 * no pipeline stage.
 *
 * `agree`, `soleAdmitted` and `soleNamed` are the liveness half. `agree` is the
 * population `unanimousCompare` legitimately answers (2 corpus-wide, MSVC's
 * `_stricmp` tail, one per 32-bit binary). `soleAdmitted` is every
 * single-predecessor cross-edge block, which the code answers freely, so it is
 * the whole of `sole` on a healthy tree and a fall in it says the rule is no
 * longer reached through `flagPredecessor` and that `admitted` has gone blind
 * rather than clean. `soleNamed` says the same about the anchoring behind
 * `named`, and is much thinner — 15 of 76 at 16f1633.
 *
 * WHAT IT DOES NOT CATCH, stated so the zero is read for what it is:
 *
 *   - `named` counts only guards the polarity pass could ANCHOR to their jcc,
 *     so it is a LOWER bound, exactly as `staleGuards`' is. `differ` and
 *     `admitted` have no such dependency. This is not a small gap: the
 *     `sub_140002A2C` witness above is one of the four sites the anchoring
 *     cannot reach, so `named` alone would have gone red on the control while
 *     missing the very row the control was built to expose.
 *   - `admitted` reads `flagPredecessor`. If the rule is ever reimplemented
 *     somewhere else, this count reads 0 by no longer looking — which is what
 *     `soleAdmitted` is asserted for. It also says nothing about a wrong guard
 *     that arrives at such a block by a route that never consults it; there is
 *     no such route today, and `named` is the half that does not care.
 *   - `differ` is the population where a *single* condition cannot be right.
 *     It is deliberately NOT the question "is the emitted condition the one
 *     this edge makes" — for a `differ` block no condition is, so the presence
 *     of a guard is the whole of it. That is `staleGuards`' pre-peek-a-bin-xskz
 *     rule, and it is the right rule for exactly as long as refusing is the
 *     only sound answer. **If a mechanism ever materialises the test in each
 *     predecessor** — a boolean or a captured value phi'd at the join, which is
 *     what these 12 sites would need — then a guard here becomes routinely
 *     correct and this count must be sharpened to ask whether the condition
 *     reads that materialised value, the way `wrongOperand` was sharpened when
 *     `flg_<addr>_<n>` captures landed. Until then, sharpening it would be
 *     checking for a mechanism that does not exist.
 *   - Two edges are held to DISAGREE on text inequality, after folding the two
 *     equivalences `test` has (`test x, x` states exactly what `cmp x, 0`
 *     states — same ZF, SF, OF, CF, PF — and `test a, b` is `and`, which is
 *     commutative). Every other coincidental equivalence between two different
 *     compares is therefore a possible false positive and would have to be
 *     hand-adjudicated before acting on a row; over this corpus there is none —
 *     the 12 differing pairs are two different registers, two different
 *     immediates, or two different widths of the same register.
 *   - It UNDER-reports a rip-relative compare: `parseOperand` resolves one
 *     against the instruction's own address, so the same operand text at two
 *     addresses is two different memory locations and reads here as agreement.
 *     Wrong in the safe direction, and it is why `unanimousCompare` refuses
 *     `rip` outright rather than relying on text.
 *   - The gate is restricted to edges whose owners are all `cmp`/`test`, since
 *     for a compare the mnemonic and the operand text determine the test
 *     exactly. A disagreement involving an arithmetic or bit-test owner is
 *     reported as `differOther` and not gated — 0 occurrences.
 *   - An edge `buildCFG` drew that can never execute would make a row a false
 *     positive. That is the assumption every stage here makes about a detected
 *     function's boundaries, and it is the same blind spot the loop-exit audit
 *     had before function sizing was fixed.
 *   - It shares `isFlagTransparent` with the code under test — a fact about
 *     x86, deliberately single-sourced — so it cannot catch an error in that
 *     table. Everything built on top of it here (which instruction owns the
 *     flags on each edge, whether two owners state the same test) is written
 *     from raw operand text and calls nothing the rule under test is built on:
 *     not `flagPredecessor`, not `unanimousCompare`, not `flagScanStream`.
 */
import type { BasicBlock } from "../src/disasm/cfg";
import { flagPredecessor, isFlagTransparent } from "../src/disasm/decompile/flagModel";
import type { Instruction } from "../src/disasm/types";

/** What one incoming edge leaves the flags saying. */
export interface CrossEdge {
  /** First address of the predecessor block. */
  pred: number;
  /** The instruction that owns the flags on this edge, or null if none is readable. */
  ownerAddr: number | null;
  ownerText: string;
  /** The normalised test, or null when no owner was readable. Compared for equality. */
  key: string | null;
}

/** One cross-edge block whose incoming edges do not make the same test. */
export interface CrossEdgeGuardRec {
  bin: string;
  func: string;
  funcAddr: number;
  /** The block's trailing conditional jump — the block holds no flag writer. */
  jcc: number;
  jccMnem: string;
  /** Whether every disagreeing owner is a `cmp`/`test`, i.e. whether the row is gated. */
  gated: boolean;
  /**
   * The predecessor the code under test chose to answer this block from, or null
   * when it refused. Non-null at a disagreeing block IS the defect, and this is
   * the complete, address-exact half of the audit — see `admitted`.
   */
  admittedFrom: number | null;
  edges: CrossEdge[];
  /**
   * The emitted condition found at this jcc, when the polarity pass anchored a
   * guard there. Absent means the reading was refused and admitted as
   * `__unrecovered_N`, which is the correct answer at a `differ` block. Present
   * IS the defect — see the note above on why, and on when that stops being so.
   */
  emitted: string | null;
}

export interface CrossEdgeGuardResult {
  /** Blocks ending in a flag-reading conditional jump that were examined at all. */
  blocks: number;
  /** Of those, the ones none of whose own instructions writes a flag. */
  crossEdge: number;
  /** Of those, entered from exactly one predecessor. The liveness denominator. */
  sole: number;
  /** Of `sole`, the ones carrying an anchored emitted guard. Report-only; expect > 0. */
  soleNamed: number;
  /**
   * Of `sole`, the ones the code answered from their predecessor. The liveness
   * half of `admitted`: it is the whole of `sole` on a healthy tree, and a 0
   * means the rule is no longer being consulted through `flagPredecessor` and
   * that `admitted` has gone blind rather than clean.
   */
  soleAdmitted: number;
  /** Of `crossEdge`, entered from several readable, non-self predecessors. */
  multi: number;
  /** Cross-edge blocks put aside for a self-edge or an unresolvable predecessor. */
  refused: number;
  /** Of `multi`, every edge leaves the flags set by the same test. Report-only. */
  agree: number;
  /** Of `agree`, the ones the code answered from a predecessor. Report-only. */
  agreeAdmitted: number;
  /** Of `multi`, some edge has no readable flag owner at all. Report-only, not gated. */
  unknownEdge: number;
  /**
   * Of `multi`, the edges make provably different tests and every owner is a
   * compare. A machine-code property, so a fix does not move it — the
   * instrument-liveness number. Expected non-zero.
   */
  differ: number;
  /** As `differ`, but with a non-compare owner among the edges. Report-only. */
  differOther: number;
  /**
   * Of `differ`, the ones the code ADMITTED a flag predecessor for. THE DEFECT,
   * and the gate that is complete: admitting one is necessary for either route
   * to spell a condition here, so this is a superset of both `named` and of any
   * reading the lifter produced, and it needs no anchoring. Expect 0.
   */
  admitted: number;
  /** Of `differOther`, ditto. Report-only. */
  admittedOther: number;
  /**
   * Of `differ`, an emitted guard is anchored on the page. The OUTPUT-level
   * statement of the same defect, and a gate — but a LOWER bound, since the
   * polarity pass anchors only some guards. Expect 0.
   */
  named: number;
  /** Of `differOther`, ditto. Report-only. */
  namedOther: number;
  rows: CrossEdgeGuardRec[];
}

export function emptyCrossEdgeGuards(): CrossEdgeGuardResult {
  return {
    blocks: 0,
    crossEdge: 0,
    sole: 0,
    soleNamed: 0,
    soleAdmitted: 0,
    multi: 0,
    refused: 0,
    agree: 0,
    agreeAdmitted: 0,
    unknownEdge: 0,
    differ: 0,
    differOther: 0,
    admitted: 0,
    admittedOther: 0,
    named: 0,
    namedOther: 0,
    rows: [],
  };
}

/** Does this jump read the flags? `jecxz` and friends test a register. */
function isFlagReadingJcc(mnemonic: string): boolean {
  const mn = mnemonic.toLowerCase();
  return mn.startsWith("j") && mn !== "jmp" && !/^j[er]?cxz$/.test(mn);
}

/**
 * How much of a block the flag walk reads when the block's EXIT flags are the
 * question: everything but a trailing branch.
 *
 * The terminator has to be excluded explicitly. `jmp`, `ret` and every Jcc are
 * absent from `flagModel.ts`'s `NO_FLAG_WRITE` — correctly, that set is narrow
 * on purpose — so `isFlagTransparent` says false for them and a walk that reads
 * one reports the branch itself as the flag owner. Every edge would then own
 * its own terminator, every key would differ, and this audit would report all
 * 14 blocks as disagreeing.
 */
function walkEnd(insns: Instruction[]): number {
  const last = insns[insns.length - 1];
  if (!last) return 0;
  const mn = last.mnemonic.toLowerCase();
  return isFlagReadingJcc(mn) || mn === "jmp" ? insns.length - 1 : insns.length;
}

/** The last instruction in this stream that writes a flag, or null. */
function flagOwner(stream: Instruction[]): Instruction | null {
  let owner: Instruction | null = null;
  for (const insn of stream) {
    if (!isFlagTransparent(insn.mnemonic.toLowerCase())) owner = insn;
  }
  return owner;
}

/**
 * The test an owner instruction makes, as a string two owners can be compared
 * on. Two owners with the same key make the same test; two with different keys
 * are held to make different ones.
 *
 * Only `test`'s two equivalences are folded, and both are exact rather than
 * approximate. `test x, x` is `and x, x`, which leaves ZF, SF and PF as
 * functions of x and clears OF and CF — precisely what `cmp x, 0`, i.e.
 * `sub x, 0`, leaves — so the two are one test under every Jcc. And `and` is
 * commutative, so `test a, b` and `test b, a` are the same test. Nothing else
 * is folded: see the note at the top of this file on why any other coincidental
 * equivalence is a false positive to be hand-adjudicated rather than guessed
 * at here.
 */
function testKey(owner: Instruction): string {
  const mn = owner.mnemonic.toLowerCase();
  const text = owner.opStr.toLowerCase().replace(/\s+/g, " ").trim();
  if (mn !== "test") return `${mn} ${text}`;
  const ops = text.split(",").map((o) => o.trim());
  if (ops.length !== 2) return `${mn} ${text}`;
  if (ops[0] === ops[1]) return `cmp ${ops[0]}, 0`;
  const [a, b] = ops[0] <= ops[1] ? ops : [ops[1], ops[0]];
  return `test ${a}, ${b}`;
}

function isCompare(owner: Instruction): boolean {
  const mn = owner.mnemonic.toLowerCase();
  return mn === "cmp" || mn === "test";
}

/**
 * Classify every block of `func` that ends in a flag-reading conditional jump
 * and writes no flag of its own, and record the ones whose incoming edges do
 * not agree about the test the jump makes.
 *
 * `emittedAt` maps a jcc address to the condition the emitted C states there,
 * for the jccs the polarity pass could anchor — the same map `staleGuards`
 * reads, and the only channel here between the emitted C and a machine block.
 */
export function auditCrossEdgeGuards(
  out: CrossEdgeGuardResult,
  bin: string,
  funcName: string,
  funcAddr: number,
  blocks: BasicBlock[],
  emittedAt: Map<number, string>,
): void {
  const byId = new Map(blocks.map((b) => [b.id, b]));
  for (const block of blocks) {
    const last = block.insns[block.insns.length - 1];
    if (!last || !isFlagReadingJcc(last.mnemonic)) continue;
    out.blocks++;

    // The block's own instructions, terminator excluded. A flag writer among
    // them owns the jump's flags outright and the edges are then irrelevant —
    // which is every ordinary `cmp … / jcc` block, hence the ~2200-to-35 fall.
    const own = block.insns.slice(0, Math.max(0, block.insns.length - 1));
    if (flagOwner(own) !== null) continue;
    out.crossEdge++;

    // A self-edge makes the block its own flag source, which is the question
    // rather than an answer to it; an unresolvable predecessor is a way in that
    // cannot be read, hence one that may disagree. Both put the block aside.
    const preds: BasicBlock[] = [];
    let refused = false;
    for (const id of block.preds) {
      const pred = id === block.id ? undefined : byId.get(id);
      if (!pred) {
        refused = true;
        break;
      }
      preds.push(pred);
    }
    if (refused || preds.length === 0) {
      out.refused++;
      continue;
    }
    // WHICH predecessor the code chose, if any. The one thing here the audit
    // does not work out for itself, and the reason the gate is complete: both
    // routes to a condition at such a jcc — `lifter.ts`'s `branchFor` building
    // the `IRBranch`, and `structure.ts`'s `extractCondition` re-reading the
    // machine text when there is no usable one — take their instruction stream
    // from `flagScanStream(block, flagPredecessor(...))`, so an admitted
    // predecessor is NECESSARY for either to spell anything at all. Reading the
    // decision rather than the product is what makes this address-exact and
    // free of the polarity pass's anchoring, and it makes this half a
    // differential test between two independently written answers to the same
    // question rather than an oracle outside it — see the note above.
    const admittedFrom = flagPredecessor(block, byId)?.startAddr ?? null;

    if (preds.length === 1) {
      out.sole++;
      if (emittedAt.has(last.address)) out.soleNamed++;
      if (admittedFrom !== null) out.soleAdmitted++;
      continue;
    }
    out.multi++;

    const edges: CrossEdge[] = [];
    const keys = new Set<string>();
    let unknown = false;
    let allCompares = true;
    for (const pred of preds) {
      // The owner is read over the whole path — the predecessor's instructions
      // up to its terminator, then the block's own — because an instruction in
      // the block itself would displace the predecessor's, and because that is
      // the stream the machine executes on this edge.
      const owner = flagOwner([...pred.insns.slice(0, walkEnd(pred.insns)), ...own]);
      if (!owner) {
        unknown = true;
        edges.push({ pred: pred.startAddr, ownerAddr: null, ownerText: "", key: null });
        continue;
      }
      if (!isCompare(owner)) allCompares = false;
      const key = testKey(owner);
      keys.add(key);
      edges.push({
        pred: pred.startAddr,
        ownerAddr: owner.address,
        ownerText: `${owner.mnemonic} ${owner.opStr}`.trim(),
        key,
      });
    }

    if (unknown) out.unknownEdge++;
    if (keys.size < 2) {
      if (!unknown) {
        out.agree++;
        if (admittedFrom !== null) out.agreeAdmitted++;
      }
      continue;
    }
    const gated = allCompares && !unknown;
    if (gated) out.differ++;
    else out.differOther++;
    if (admittedFrom !== null) {
      if (gated) out.admitted++;
      else out.admittedOther++;
    }
    const emitted = emittedAt.get(last.address) ?? null;
    if (emitted !== null) {
      if (gated) out.named++;
      else out.namedOther++;
    }
    out.rows.push({
      bin,
      func: funcName,
      funcAddr,
      jcc: last.address,
      jccMnem: last.mnemonic.toLowerCase(),
      gated,
      admittedFrom,
      edges,
      emitted,
    });
  }
}
