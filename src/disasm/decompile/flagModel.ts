/**
 * **The** model of what x86 does to the flags, and of which instruction owns
 * the flags a block's Jcc reads.
 *
 * It walks a block *forwards*, maintaining "who owns the flags right now" as it
 * goes. `lifter.ts` asks it, at the trailing Jcc, which instruction the jump
 * reads, and builds the `IRBranch` whose condition becomes the guard.
 *
 * There used to be a second, *backward* answer to the same question, in
 * `flagResult.ts`: an allowlist walk from the Jcc back to the setter, with
 * `ssaopt.ts`'s DCE holding that setter's definition live by hand because the
 * guard was not an IR reader and the use was invisible to it. Both are gone
 * (peek-a-bin-c33 stage 4), and so is that module. What survived from it is the
 * part that was never about ownership — `isFlagTransparent` and
 * `clobberedAfter`, at the bottom of this file.
 *
 * **A forward model is not the backward one run the other way round, and the
 * difference is the whole safety property.** Backwards, the allowlist is a
 * *permission to keep looking*: anything unrecognised ends the search with no
 * answer, so a mnemonic wrongly left off the list costs a recovery and one
 * wrongly on it produces a wrong condition. Forwards there is no search to
 * end — there is a standing owner, and the question is whether an instruction
 * displaces it. **The default must therefore be to clear**: an unrecognised
 * mnemonic, or one that writes only some of the flags, invalidates the current
 * owner rather than leaving it standing. Get that backwards and the model
 * confidently attributes the flags to an instruction that no longer owns them,
 * which yields a guard that is valid, plausible C stating something the machine
 * does not do — the defect class CLAUDE.md records as invisible to every
 * stage-level test in this repo.
 *
 * The model answers three things a consumer needs and keeps them apart:
 *
 * 1. **Which instruction the flags belong to** (`FlagOwner`). Semantics only.
 * 2. **Which flags that instruction actually determines** (`defines`). A
 *    `cmp`/`test` determines all of them; `add`/`dec`/`and` determine ZF and SF
 *    from their result, and `inc`/`dec` do not write CF at all — so a consumer
 *    answering a CF- or OF-reading Jcc from a `"zf-sf"` owner would be wrong.
 *    That judgement is the caller's — `lifter.ts` makes it by asking
 *    `RegState.getCondition`, whose `result` arm answers exactly the ZF/SF
 *    forms and `unknown` for every other Jcc — and is deliberately not made
 *    here. `flagResult.ts` stated it a second time, as `RESULT_ANSWERABLE_JCC`
 *    (peek-a-bin-wf7t).
 * 3. **Whether the condition can still be spelled** (`spoiled`, `destReg`).
 *    Owning the flags and being nameable are different facts: `dec ecx / mov
 *    ecx, edx / jne` leaves ECX holding EDX where the guard would read it, and
 *    `dec dword ptr [rcx]` leaves its result where only a load could reach it.
 *    `canSpellCondition` is the single predicate for that.
 *
 * The mnemonic tables below used to be duplicated in `flagResult.ts`, which is
 * exactly the hand-synced-copy hazard CLAUDE.md warns about (`ripRelative.ts`
 * and `parseOperand` were each re-rolled most of a dozen times). There is now
 * one copy of each and this is it. Do not start a second.
 */
import type { BasicBlock } from "../cfg";
import type { Instruction } from "../types";
import { canonReg, isKnownRegister, regSize } from "./ir";

/**
 * Instructions that leave every flag exactly as they found them.
 *
 * `isFlagTransparent` at the bottom of this file is the predicate form, for
 * callers that want the grammar without the owner model.
 *
 * Deliberately **not** widened. `xchg`, `leave`, `setcc` and `cmovcc` all write
 * no flags either and could be added, but widening this set is the dangerous
 * direction in both models — a wrong member makes a Jcc read a condition off an
 * instruction that no longer owns the flags — and nothing here has measured
 * what widening it would recover.
 */
export const NO_FLAG_WRITE: ReadonlySet<string> = new Set([
  "mov",
  "movabs",
  "movzx",
  "movsx",
  "movsxd",
  "lea",
  "push",
  "pop",
  "nop",
  "not",
  "bswap",
  "cbw",
  "cwd",
  "cwde",
  "cdq",
  "cdqe",
  "cqo",
]);

/**
 * Instructions whose ZF and SF are the zero-ness and sign of the value they
 * wrote — every arithmetic and logical operation with a single destination.
 *
 * Everything absent is absent for a stated reason, and each reason appears
 * below as a named clobber class rather than as silence, so the model reports
 * *why* it gave up: `imul`/`mul`/`div`/`idiv` leave ZF and SF *undefined*;
 * `rol`/`ror`/`rcl`/`rcr` and `bt`/`bts`/`btr`/`btc` write CF and OF only, so a
 * Jcc after one reads an older test; `not` writes no flag at all and is in
 * `NO_FLAG_WRITE`; `adc`/`sbb`/`xadd` have a perfectly good result that
 * `lifter.ts` does not lift to an assignment, so it could not be named.
 */
export const RESULT_OWNERS: ReadonlySet<string> = new Set([
  "add",
  "sub",
  "and",
  "or",
  "xor",
  "inc",
  "dec",
  "neg",
  "shl",
  "sal",
  "shr",
  "sar",
]);

export const SHIFTS: ReadonlySet<string> = new Set(["shl", "sal", "shr", "sar"]);

/**
 * `NO_FLAG_WRITE` members that write a register the operand text does not name
 * (`cdq` writes EDX, `cqo` RDX, `cwde`/`cdqe` EAX/RAX, `cbw` AX).
 *
 * They keep the standing owner — they write no flag — but this model carries no
 * table of implicit destinations, so one appearing after a claim conservatively
 * spoils it. Costing a recovery is the safe direction; reporting that a
 * register still holds a result something else overwrote is not.
 */
export const IMPLICIT_REG_WRITERS: ReadonlySet<string> = new Set([
  "cbw",
  "cwd",
  "cwde",
  "cdq",
  "cdqe",
  "cqo",
]);

/** Intel documents ZF and SF as *undefined* after these. Not a conservatism. */
export const UNDEFINED_RESULT_FLAGS: ReadonlySet<string> = new Set(["imul", "mul", "div", "idiv"]);

/**
 * Writers of CF and/or OF only. ZF and SF survive one of these from whatever
 * set them last, so the machine's own answer for a ZF-reading Jcc after a `rol`
 * is the *older* owner — but ownership in this model is whole-flags, and
 * keeping the older owner would then answer a CF-reading `jc` with an
 * instruction that did not set CF. Clearing is the sound whole-flags answer;
 * per-flag ownership is what it would take to do better, and nothing has
 * measured what that would recover.
 */
export const PARTIAL_FLAG_WRITERS: ReadonlySet<string> = new Set([
  "rol",
  "ror",
  "rcl",
  "rcr",
  "bt",
  "bts",
  "btr",
  "btc",
]);

/**
 * `adc`/`sbb`/`xadd`. Their flags *are* a function of their result, so unlike
 * every other class here the reason they clear is not Intel semantics — it is
 * that `lifter.ts` does not lift them to an assignment, so the result has no
 * name for a condition to be spelled from. If the lifter ever grows one, these
 * move to `RESULT_OWNERS` and this set shrinks.
 */
export const CARRY_IN_WRITERS: ReadonlySet<string> = new Set(["adc", "sbb", "xadd"]);

/**
 * String primitives, with or without a `rep`/`repe`/`repne` prefix. `scas` and
 * `cmps` set the flags meaningfully — a `repne scasb` leaves ZF holding the
 * loop's answer — but there is no single destination to name, and the prefixed
 * forms write them once per iteration. They clear.
 */
const STRING_OPS: ReadonlySet<string> = new Set([
  "movs",
  "stos",
  "lods",
  "scas",
  "cmps",
  "ins",
  "outs",
]);

/** Why an instruction displaced the standing owner without becoming one. */
export type FlagClobberReason =
  | "undefined-result"
  | "partial-write"
  | "carry-in"
  | "variable-count"
  | "locked"
  | "string-op"
  | "call"
  | "unrecognised";

/** What one instruction does to the flags. */
export type FlagEffect =
  | { kind: "none" }
  | { kind: "compare"; mnemonic: "cmp" | "test" }
  | { kind: "result"; destText: string }
  | { kind: "clobber"; why: FlagClobberReason };

interface FlagOwnerCommon {
  /** Index into the instruction list the owner was found in. */
  index: number;
  /** The owning instruction's address — the `addr` an `IRStmt` from it carries. */
  address: number;
  insn: Instruction;
  /**
   * Whether something written since has overwritten what the condition would be
   * spelled from: the destination register for a result, an operand register or
   * the memory it read for a compare. The flags are still this instruction's;
   * the name is no longer its value.
   */
  spoiled: boolean;
}

export interface FlagOwnerCompare extends FlagOwnerCommon {
  kind: "compare";
  mnemonic: "cmp" | "test";
  /** A compare determines every flag from its two operands. */
  defines: "all";
}

export interface FlagOwnerResult extends FlagOwnerCommon {
  kind: "result";
  /** Lowercased. */
  mnemonic: string;
  /** The destination operand exactly as written, e.g. `ecx` or `dword ptr [rcx]`. */
  destText: string;
  /** Canonicalised to the 64-bit parent, or null when the destination is memory. */
  destReg: string | null;
  /**
   * ZF and SF only. `inc`/`dec` do not write CF at all, and no result determines
   * OF for a signed comparison the way a `cmp` does — so a CF- or OF-reading Jcc
   * cannot be answered from one of these.
   */
  defines: "zf-sf";
}

export interface FlagOwnerNone {
  kind: "none";
  /**
   * `"no-owner"` — nothing in range wrote a flag at all. `"cleared"` — something
   * did, in a way this model cannot attribute, and `clearedBy` names it.
   */
  reason: "no-owner" | "cleared";
  clearedBy?: Instruction;
}

export type FlagOwner = FlagOwnerCompare | FlagOwnerResult | FlagOwnerNone;

/** An owner a condition can actually be spelled from. */
export type SpellableFlagOwner =
  | FlagOwnerCompare
  | (FlagOwnerResult & { destReg: string; spoiled: false });

export interface BlockFlagOwner {
  /** The block's trailing conditional jump, lowercased. */
  jcc: string;
  owner: FlagOwner;
  /**
   * Whether the owner was found in the block's sole *predecessor* rather than
   * in the block itself — see `flagScanStream`. It matters to a consumer for
   * two reasons: a `RegState` built by walking this block never saw the
   * compare, and being a block away is a fresh way for the reading to have gone
   * stale, so a compare owner has to be filtered on `canSpellCondition` here
   * where a block-local one deliberately is not.
   */
  fromPredecessor: boolean;
}

/** Everything before the first space — Capstone spells prefixes into the mnemonic. */
function baseMnemonic(mnemonic: string): { prefix: string; base: string } {
  const lower = mnemonic.toLowerCase().trim();
  const space = lower.indexOf(" ");
  return space < 0
    ? { prefix: "", base: lower }
    : { prefix: lower.slice(0, space), base: lower.slice(space + 1).trim() };
}

/** `opStr`'s first operand, lowercased. No x86 memory operand contains a comma. */
function firstOperand(insn: Instruction): string {
  return insn.opStr.split(",")[0]?.trim().toLowerCase() ?? "";
}

/** A shift's count when it is a plain immediate, else 0. */
function immediateCount(text: string): number {
  const t = text.trim().toLowerCase();
  const n = /^0x[0-9a-f]+$/.test(t)
    ? Number.parseInt(t.slice(2), 16)
    : /^\d+$/.test(t)
      ? Number.parseInt(t, 10)
      : 0;
  return Number.isFinite(n) ? n : 0;
}

/**
 * Did this shift provably write the flags?
 *
 * `shl eax, cl` with `cl == 0` is a no-op that leaves the flags to an earlier
 * instruction, so a register count is never good enough — that much is
 * the backward walk's rule and this keeps it. It adds the masking x86 applies to
 * the count: 5 bits, or 6 under REX.W, so `shl eax, 0x20` shifts by zero and
 * writes nothing while `shl rax, 0x20` really shifts. A non-zero immediate is
 * therefore not by itself evidence that anything happened.
 */
function shiftWritesFlags(destText: string, countText: string): boolean {
  const n = immediateCount(countText);
  if (n === 0) return false;
  const mask = isKnownRegister(destText) && regSize(destText) === 8 ? 0x3f : 0x1f;
  return (n & mask) !== 0;
}

/**
 * What `insn` does to the flags — the transfer function the forward walk
 * applies. **Anything not positively recognised clobbers**; see the module
 * docstring for why that asymmetry is the safety property rather than a
 * conservatism to be tuned away later.
 */
export function flagEffect(insn: Instruction): FlagEffect {
  const { prefix, base } = baseMnemonic(insn.mnemonic);

  // A `lock`-prefixed form is a read-modify-write on memory whose result this
  // model could not name in any case; `rep`-prefixed forms are string ops.
  if (prefix === "lock") return { kind: "clobber", why: "locked" };
  if (prefix === "rep" || prefix === "repe" || prefix === "repz") {
    return { kind: "clobber", why: "string-op" };
  }
  if (prefix === "repne" || prefix === "repnz") return { kind: "clobber", why: "string-op" };

  if (base === "cmp" || base === "test") return { kind: "compare", mnemonic: base };
  if (NO_FLAG_WRITE.has(base)) return { kind: "none" };

  if (RESULT_OWNERS.has(base)) {
    const dest = firstOperand(insn);
    if (SHIFTS.has(base)) {
      const count = insn.opStr.split(",")[1] ?? "";
      if (!shiftWritesFlags(dest, count)) return { kind: "clobber", why: "variable-count" };
    }
    return { kind: "result", destText: dest };
  }

  if (UNDEFINED_RESULT_FLAGS.has(base)) return { kind: "clobber", why: "undefined-result" };
  if (PARTIAL_FLAG_WRITERS.has(base)) return { kind: "clobber", why: "partial-write" };
  if (CARRY_IN_WRITERS.has(base)) return { kind: "clobber", why: "carry-in" };
  if (base === "call") return { kind: "clobber", why: "call" };
  // `movsb`, `stosd`, `scasq`: the primitive plus an operand-size suffix.
  if (STRING_OPS.has(base.replace(/[bwdq]$/, ""))) return { kind: "clobber", why: "string-op" };

  return { kind: "clobber", why: "unrecognised" };
}

/** Every register named anywhere in an operand string, canonicalised. */
function registersIn(opStr: string): Set<string> {
  const out = new Set<string>();
  for (const token of opStr.toLowerCase().split(/[^a-z0-9]+/)) {
    if (token && isKnownRegister(token)) out.add(canonReg(token));
  }
  return out;
}

/** Does this flag-transparent instruction write `reg`? */
function writesRegister(insn: Instruction, reg: string): boolean {
  const { base } = baseMnemonic(insn.mnemonic);
  // The destination is in the mnemonic, so assume the worst.
  if (IMPLICIT_REG_WRITERS.has(base)) return true;
  // `push` names a register it only reads; `nop`'s operand is decoration.
  if (base === "push" || base === "nop") return false;
  const dest = firstOperand(insn);
  return isKnownRegister(dest) && canonReg(dest) === reg;
}

/** Does this flag-transparent instruction store to memory? */
function writesMemory(insn: Instruction): boolean {
  const { base } = baseMnemonic(insn.mnemonic);
  if (base === "push" || base === "nop") return false;
  return firstOperand(insn).includes("[");
}

/**
 * Would `insn`, executed after the owner, invalidate the *name* a condition
 * would be spelled from? The flags remain the owner's either way.
 *
 * For a result that is its destination register: `dec ecx / mov ecx, edx / jne`
 * leaves ECX holding EDX where the guard would read it. For a compare it is the
 * same argument applied to the operands — the block's statements are emitted
 * *before* the `if`, so `eax = edx; if (eax != 5)` reads the wrong value just as
 * surely. `clobberedAfter` below asks the same question from the other end, for
 * `structure.ts`.
 */
function spoils(insn: Instruction, owner: FlagOwnerCompare | FlagOwnerResult): boolean {
  if (owner.kind === "result") {
    if (owner.destReg === null) return writesMemory(insn);
    return writesRegister(insn, owner.destReg);
  }
  for (const reg of registersIn(owner.insn.opStr)) {
    if (writesRegister(insn, reg)) return true;
  }
  return owner.insn.opStr.includes("[") && writesMemory(insn);
}

function claimResult(insn: Instruction, index: number, destText: string): FlagOwnerResult {
  return {
    kind: "result",
    mnemonic: baseMnemonic(insn.mnemonic).base,
    insn,
    index,
    address: insn.address,
    destText,
    destReg: isKnownRegister(destText) ? canonReg(destText) : null,
    defines: "zf-sf",
    spoiled: false,
  };
}

/**
 * Which instruction owns the flags immediately before `insns[index]` executes,
 * or nothing-known.
 *
 * The walk is forward and stateful: each instruction either leaves the standing
 * owner alone, becomes the owner, or clears it. Reading past the end of the
 * list is not an error — an `index` beyond it means "after everything".
 */
export function flagOwnerBefore(insns: Instruction[], index: number): FlagOwner {
  let owner: FlagOwnerCompare | FlagOwnerResult | null = null;
  let cleared: FlagOwnerNone = { kind: "none", reason: "no-owner" };

  const limit = Math.min(index, insns.length);
  for (let i = 0; i < limit; i++) {
    const insn = insns[i];
    const effect = flagEffect(insn);
    switch (effect.kind) {
      case "none":
        // The owner survives, but what names its value may not. Mutating is
        // safe: every owner object here was constructed by this walk.
        if (owner && !owner.spoiled && spoils(insn, owner)) owner.spoiled = true;
        break;
      case "compare":
        owner = {
          kind: "compare",
          mnemonic: effect.mnemonic,
          insn,
          index: i,
          address: insn.address,
          defines: "all",
          spoiled: false,
        };
        break;
      case "result":
        owner = claimResult(insn, i, effect.destText);
        break;
      case "clobber":
        owner = null;
        cleared = { kind: "none", reason: "cleared", clearedBy: insn };
        break;
    }
  }

  return owner ?? cleared;
}

/**
 * Does this jump read the flags?
 *
 * `jecxz`/`jrcxz` test a register rather than a flag, so a block ending in one
 * has no flag owner to report even though it starts with `j` and is not `jmp` —
 * which is the predicate `structure.ts`'s `extractCondition` uses today.
 */
export function isFlagReadingJump(mnemonic: string): boolean {
  const mn = mnemonic.toLowerCase();
  return mn.startsWith("j") && mn !== "jmp" && !/^j[er]?cxz$/.test(mn);
}

/**
 * The block's only predecessor, or undefined when it has none, more than one,
 * or only itself.
 *
 * This lives beside `flagScanStream` because it is that rule's other half: the
 * flags a block is *entered* with are knowable exactly when one block can have
 * set them, and "one predecessor" is what makes that true. Self-loops are
 * excluded because the block would then be its own flag source, which is the
 * question rather than an answer to it.
 *
 * **Either edge counts, and that is a deliberate widening.** A Jcc writes no
 * flags — the `{clobber, unrecognised}` classification `flagEffect` gives it is
 * an artifact of `NO_FLAG_WRITE`'s deliberate narrowness, not hardware — so a
 * predecessor's exit flags reach its successor on the taken edge exactly as
 * they do on the fallthrough. The predecessor's own condition being true rather
 * than false on that path is a fact about *values*, not about flags. Restricting
 * to fallthrough was measured to leave 17 of 69 recoverable guards unclaimed,
 * and on the x64 pair the taken edge is the majority of them — 6 of 13 on t64
 * and 4 of 9 on w64 (peek-a-bin-suql).
 */
export function solePredecessor(
  block: BasicBlock,
  blockById: Map<number, BasicBlock>,
): BasicBlock | undefined {
  if (block.preds.length !== 1) return undefined;
  const pred = blockById.get(block.preds[0]);
  return pred && pred.id !== block.id ? pred : undefined;
}

/** An instruction stream for the forward flag walk, and where it came from. */
export interface FlagScan {
  /** Everything the walk reads, in execution order, ending before the Jcc. */
  insns: Instruction[];
  /** Whether `solePredecessor`'s instructions were prepended. */
  fromPredecessor: boolean;
}

/**
 * How much of a block the forward flag walk reads when the block's *exit* flags
 * are the question.
 *
 * The terminator has to be skipped explicitly, and this is the whole reason the
 * cross-block reading works at all. `jmp`, `ret` and every Jcc are absent from
 * `NO_FLAG_WRITE` — correctly, since that set is narrow on purpose — so
 * `flagEffect` classes them `{kind: "clobber", why: "unrecognised"}` and a walk
 * that reads them clears the very owner it came for. Measured: without this
 * skip the change below recovers **0** guards on all four corpus binaries,
 * which is exactly the false negative the first measurement pass produced
 * (peek-a-bin-suql). It is not an optimisation.
 */
function flagWalkEnd(insns: Instruction[]): number {
  const last = insns[insns.length - 1];
  if (!last) return 0;
  const mn = last.mnemonic.toLowerCase();
  return isFlagReadingJump(mn) || mn === "jmp" ? insns.length - 1 : insns.length;
}

/**
 * The instruction stream whose forward walk determines the flags a block's
 * trailing jump reads. `block`'s last instruction is assumed to be that jump.
 *
 * Normally it is the block's own instructions up to but excluding the jump.
 * When *none* of those writes a flag — `flagOwnerBefore` reporting
 * `{kind: "none", reason: "no-owner"}`, which for a block holding nothing but
 * the Jcc is a walk of zero iterations — the flags were set before the block
 * was entered, and a block with exactly one predecessor was entered with that
 * predecessor's exit flags by construction. So the predecessor's instructions,
 * minus its own terminator, are prepended and the walk continues into the
 * block's.
 *
 * Continuing the walk rather than stopping at the block boundary is what makes
 * the general case safe: the block's instructions cannot displace the owner
 * (they are all flag-transparent, which is the precondition), but they can
 * overwrite what names its value, and `spoils` sets `spoiled` on exactly that.
 * A caller filtering on `canSpellCondition` therefore refuses a predecessor's
 * compare that anything on either side of the edge has spoiled, with no second
 * grammar (peek-a-bin-suql).
 *
 * Both consumers read this: `lifter.ts`'s `branchFor`, which builds the
 * `IRBranch`, and `structure.ts`'s `extractCondition`, which re-reads the
 * `cmp`/`test` operands off the machine text for its refusals. One declaration
 * of the rule, because two would drift about which edge and which terminator.
 */
export function flagScanStream(block: BasicBlock, solePred?: BasicBlock): FlagScan {
  const own = block.insns.slice(0, Math.max(0, block.insns.length - 1));
  if (!solePred || solePred.id === block.id) return { insns: own, fromPredecessor: false };
  const scanned = flagOwnerBefore(own, own.length);
  if (scanned.kind !== "none" || scanned.reason !== "no-owner") {
    return { insns: own, fromPredecessor: false };
  }
  const tail = solePred.insns.slice(0, flagWalkEnd(solePred.insns));
  if (tail.length === 0) return { insns: own, fromPredecessor: false };
  return { insns: [...tail, ...own], fromPredecessor: true };
}

/**
 * Which instruction's flags the block's trailing conditional jump reads, or
 * null when the block does not end in one.
 *
 * Null is "you asked the wrong question" — the block's last instruction reads
 * no flags. Nothing-known is `owner.kind === "none"`.
 *
 * `solePred` is optional and opts the block into the cross-block reading
 * `flagScanStream` describes: a Jcc alone in its basic block has its flags set
 * in the block before, and without a predecessor to look at, its guard cannot
 * be recovered at all. Omitting it is exactly the pre-existing behaviour, which
 * is deliberately not the same claim as "the flags started here".
 */
export function blockFlagOwner(block: BasicBlock, solePred?: BasicBlock): BlockFlagOwner | null {
  const insns = block.insns;
  const last = insns[insns.length - 1];
  if (!last) return null;
  const jcc = last.mnemonic.toLowerCase();
  if (!isFlagReadingJump(jcc)) return null;
  const scan = flagScanStream(block, solePred);
  return {
    jcc,
    owner: flagOwnerBefore(scan.insns, scan.insns.length),
    fromPredecessor: scan.fromPredecessor,
  };
}

/**
 * Can a condition be spelled from this owner at the point it was asked about?
 *
 * Separate from ownership on purpose: `dec dword ptr [rcx] / jne` and `dec ecx /
 * mov ecx, edx / jne` both have a perfectly well-defined owner whose result
 * nothing in the emitted code names. It does **not** answer whether the *Jcc*
 * can be answered from that owner's flags — see `FlagOwnerResult.defines`.
 */
export function canSpellCondition(owner: FlagOwner): owner is SpellableFlagOwner {
  if (owner.kind === "none" || owner.spoiled) return false;
  return owner.kind === "compare" || owner.destReg !== null;
}

// ── The instruction-stream scan, asked after the fact ──

/**
 * Does this mnemonic leave every flag exactly as it found them?
 *
 * The predicate form of `NO_FLAG_WRITE`, for a caller that wants the grammar
 * without the owner model: `structure.ts`'s `extractCondition` needs it to know
 * when the `cmp` it just passed has stopped being the instruction its Jcc reads
 * (peek-a-bin-jitf), `lifter.ts` to know when to clear `RegState`'s flags, and
 * `corpus/staleGuards.ts` to find the same shape from the outside. Same
 * asymmetry as the set's own docstring — a mnemonic wrongly answered `true`
 * makes a condition come off the wrong instruction, one wrongly answered
 * `false` only costs a recovery.
 */
export function isFlagTransparent(mnemonic: string): boolean {
  return NO_FLAG_WRITE.has(mnemonic.toLowerCase());
}

/** What a block's instructions after some point overwrite. See `clobberedAfter`. */
export interface ClobberScan {
  /**
   * Registers written, canonicalised to the 64-bit parent — so a write of `al`
   * reports `rax`. Width-blind on purpose: a byte write really does change what
   * a name spelled at any width denotes.
   */
  regs: Set<string>;
  /**
   * Something was written that this scan cannot attribute to a name — an
   * instruction whose destination is implicit in the mnemonic, or a destination
   * shape it does not recognise. A caller that must not be wrong treats this as
   * "assume the worst"; encoding a second table of implicit destinations is
   * exactly what `IMPLICIT_REG_WRITERS` exists to avoid.
   */
  opaque: boolean;
  /** A store landed in memory, so any `deref` in a recovered expression may have moved under it. */
  writesMemory: boolean;
}

/**
 * What the instructions of `block` strictly after `afterAddress` — and before
 * its final instruction — overwrite.
 *
 * A value recovered from an instruction is only still nameable at the block's
 * Jcc if nothing in between has written over the names it is spelled with.
 * `structure.ts`'s `extractCondition` asks this of a `cmp`/`test`'s *operands*:
 * `cmp eax, 5 / mov eax, edx / je` emits the block's statements before the
 * `if`, so `eax != 5` reads the new EAX where the machine compared the old one
 * (peek-a-bin-xe01).
 *
 * It had a second caller — `flagResultSetter`, which asked the identical
 * question of an arithmetic instruction's *result* register, and keeping them
 * in one predicate is why they could not disagree. That caller is gone: a
 * result-derived guard is an `IRBranch` now, so SSA answers "does this register
 * still hold that value" by construction, and `spoils` above answers it
 * forwards for the lifter (peek-a-bin-c33).
 *
 * The scan is over the *instruction stream*, which is the only version of the
 * program that does not move: copy propagation will have rebound an overwritten
 * register out of the IR condition entirely, which is why `extractCondition`
 * asks this of the machine's own operand names and never of the expression it
 * is about to emit.
 *
 * `push` is reported as a write of RSP rather than of memory. It stores below
 * the stack pointer, where no operand of an instruction that already executed
 * can live, so calling it a memory write would refuse ordinary code for
 * nothing — but it does move RSP, and an `[esp + 0x10]` operand is spelled
 * relative to that.
 */
export function clobberedAfter(block: BasicBlock, afterAddress: number): ClobberScan {
  const regs = new Set<string>();
  const scan: ClobberScan = { regs, opaque: false, writesMemory: false };
  const insns = block.insns;
  for (let i = 0; i < insns.length - 1; i++) {
    if (insns[i].address <= afterAddress) continue;
    const mn = insns[i].mnemonic.toLowerCase();
    if (mn === "nop") continue;
    if (IMPLICIT_REG_WRITERS.has(mn)) {
      scan.opaque = true;
      continue;
    }
    if (mn === "push") {
      // Names a register it only reads; the write is RSP and the stack below it.
      regs.add("rsp");
      continue;
    }
    if (mn === "pop") regs.add("rsp");
    // No x86 memory operand contains a comma, so a plain split is a correct
    // operand split for the forms this reads.
    const dst = insns[i].opStr.split(",")[0]?.trim().toLowerCase() ?? "";
    if (isKnownRegister(dst)) regs.add(canonReg(dst));
    else if (dst.includes("[")) scan.writesMemory = true;
    else scan.opaque = true;
  }
  return scan;
}
