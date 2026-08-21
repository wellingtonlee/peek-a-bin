/**
 * A SWITCH ARM CLOSED WITH `break` WHILE ITS OWN BLOCK HAS A SUCCESSOR.
 *
 * `structureSwitch`'s `armBody` claims exactly one block for an arm — it does
 * not walk successors, deliberately, because the convergence scan after the
 * switch is what decides where the region following it begins — and it used to
 * close that arm with `break` however the block ends. `break` is not a
 * terminator that can always be appended: it is a claim about control flow, and
 * it says the switch is over.
 *
 * For an arm block ending in a conditional jump the claim is false twice over
 * and THE CONDITION GOES WITH IT: `pipeline.ts` step 4b has already hoisted the
 * `IRBranch` out of `liftedBlocks`, so the statements pushed above are all there
 * is and nothing else in the function ever asks what the block tested.
 * `t32!sub_4045B1` case 7 emitted `eax = (uint16_t)ecx; break;` for the block at
 * 0x40490B, which is `movzx eax, cx / cmp eax, 0x64 / jg 0x404B46` — `eax > 0x64`
 * appeared nowhere in its 698 lines and no `goto` named either successor
 * (peek-a-bin-pqs5). For an arm block ending in an unconditional `jmp` to
 * another arm or to the `default` body, `break` skips code the machine runs.
 *
 * WHAT IS COUNTED. Every arm of every emitted `switch`, at the moment
 * `structureSwitch` decides how to close it, reported by the observer
 * `structureCFG` calls and forwarded through `pipeline.ts`'s `StructuringTap`.
 * The gate is `falseBreaks`: an arm whose own block this switch claimed and
 * emitted, closed with `break`, while `buildCFG` gives that block at least one
 * successor. It is split by whether the block ends in a conditional jump,
 * because the two halves are different mechanisms — the conditional half loses a
 * recovered test as well as the transfer, the unconditional half loses only the
 * transfer.
 *
 * WHY IT IS A GATE. Every row is a provably false statement about control flow,
 * asserted by the output rather than omitted from it, which is `polarity
 * inverted`'s character rather than a baseline's. It was **35 arm blocks on t32
 * and 17 on w32** (25 and 12 conditional, 10 and 5 unconditional) before
 * `armExit` landed, and 0 on all four binaries since — so the instrument is
 * negative-controllable: replace `armExit`'s body with `[{ kind: "break" }]` and
 * the same rows come back.
 *
 * WHY THE DENOMINATOR IS REPORTED. `arms` and `truthfulExits` are the
 * populations the gate is told apart from, and both are zero on t64 and w64:
 * neither x64 binary recovers a single jump table, so `structureSwitch` never
 * runs there and a green gate on those two says nothing at all. A gate reading 0
 * for want of observing anything is the failure mode, so `corpus.audit.ts` ties
 * the denominator to the recovered-table count rather than asserting it blind.
 *
 * WHAT IT DOES NOT SEE. Three things, all of them by construction:
 *
 *   * It is scoped to a switch ARM. `break` and `goto` are emitted in many other
 *     places, and whether each of those is true of the machine is not asked
 *     here. `corpus/sweep.ts`'s `gotoCheck` answers a different question again —
 *     that a `goto` names a label the function defines, not that the transfer is
 *     the one the machine makes.
 *   * It judges the closure against `buildCFG`'s successor list, not against the
 *     instruction stream. A block whose real successor the CFG never drew is a
 *     block this audit believes has none, and `break` there reads as truthful.
 *     That is the same blind spot function sizing gave the loop-exit audit
 *     (peek-a-bin-g7yp), and it is why a `break` with no successors is counted as
 *     truthful rather than proven so.
 *   * It says nothing about whether the arm's *statements* are right, or complete.
 *     An arm that under-emits its body while spelling its exit correctly passes,
 *     which is the residue `peek-a-bin-pqs5` left behind.
 *
 * INDEPENDENCE. Weaker than an oracle and stated as such: the observation comes
 * from inside `structureSwitch`, so this cannot catch an error in `armExit`'s
 * reading of the CFG — only the closure it chose, checked against the successor
 * list the same `BasicBlock` carries. It is a regression gate on one decision,
 * not a second opinion about control flow.
 */

import type { SwitchArmExit } from "../src/disasm/decompile/structure";
import type { DisasmFunction } from "../src/disasm/types";

/** One arm closed with `break` while its own block has somewhere to go. */
export interface ArmExitRec {
  bin: string;
  func: string;
  funcAddr: number;
  /** The dispatch block — which `switch` this arm belongs to. */
  switchAddr: number;
  /** The arm's own block. */
  armAddr: number;
  /** Does that block end in a conditional jump? The two halves differ. */
  condJmp: boolean;
  /** Where the CFG says control goes, which `break` contradicts. */
  succs: number[];
  /** Which refusal inside `armExit` produced the `break`. */
  why: string;
}

export interface ArmExitResult {
  /** Functions in which at least one `switch` was structured. */
  funcsWithSwitch: number;
  /** Arms observed, `default` included. Instrument liveness. */
  arms: number;
  /** Arms whose own block this switch claimed and emitted. */
  armBlocks: number;
  /**
   * Arms closed with a statement that cannot be false: a `goto` or `if`/`goto`
   * naming where control really goes, or a `break` for a block the CFG gives no
   * successor. The population the gate is told apart from — reported, never
   * judged, and it moves with function detection like any machine-shape count.
   */
  truthfulExits: number;
  /** GATE at 0. An arm asserting the switch is over while its block goes on. */
  falseBreaks: number;
  /** Of those, the ones whose block ends in a conditional jump. */
  falseBreaksCond: number;
  /** Of those, the ones whose block ends in a `jmp` or falls through. */
  falseBreaksUncond: number;
  /**
   * Arms whose target block another region had already claimed WITHOUT emitting
   * a label — the short-circuit fold consumes blocks silently — so there is no
   * name for a `goto` to use and `break` is all that is left. A false claim with
   * no available true one, hence reported rather than gated. See `armBody`.
   */
  unnameable: number;
  funcsAffected: number;
  rows: ArmExitRec[];
}

export function emptyArmExits(): ArmExitResult {
  return {
    funcsWithSwitch: 0,
    arms: 0,
    armBlocks: 0,
    truthfulExits: 0,
    falseBreaks: 0,
    falseBreaksCond: 0,
    falseBreaksUncond: 0,
    unnameable: 0,
    funcsAffected: 0,
    rows: [],
  };
}

/**
 * Classify one function's arm closures.
 *
 * `observations` is what `structureCFG` reported for this function, in the order
 * the arms were built. Nothing is recomputed here: the point of the hook is that
 * neither side of the question survives into `decompileFunction`'s return value —
 * the emitted C shows a `break` and says nothing about the block it closed.
 */
export function auditArmExits(
  res: ArmExitResult,
  bin: string,
  func: DisasmFunction,
  observations: SwitchArmExit[],
): void {
  if (observations.length === 0) return;
  res.funcsWithSwitch++;
  const before = res.falseBreaks;

  for (const o of observations) {
    res.arms++;
    if (o.armAddr !== null && o.claimedHere) res.armBlocks++;

    if (o.closedWith !== "break") {
      res.truthfulExits++;
      continue;
    }
    // A `break` for a block with nowhere to go is the truthful spelling: an arm
    // ending in `ret` or a tail call. So is one for an arm with no block at all,
    // where the jump-table entry pointed outside anything `buildCFG` built.
    if (o.armAddr === null || o.succs.length === 0) {
      res.truthfulExits++;
      continue;
    }
    if (!o.claimedHere) {
      res.unnameable++;
      continue;
    }
    res.falseBreaks++;
    if (o.condJmp) res.falseBreaksCond++;
    else res.falseBreaksUncond++;
    res.rows.push({
      bin,
      func: func.name,
      funcAddr: func.address,
      switchAddr: o.switchAddr,
      armAddr: o.armAddr,
      condJmp: o.condJmp,
      succs: o.succs,
      why: o.why,
    });
  }

  if (res.falseBreaks > before) res.funcsAffected++;
}
