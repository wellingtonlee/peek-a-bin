/**
 * Which instruction set the flags a block's Jcc reads, when that instruction is
 * arithmetic rather than a `cmp`/`test`.
 *
 * **This is the only copy of that grammar.** Two passes need the same answer at
 * two different points in the pipeline, and they must not drift:
 *
 * - `structure.ts`'s `conditionFromFlagResult` turns the answer into the guard,
 *   naming the destination register (peek-a-bin-b531).
 * - `ssaopt.ts`'s dead-code elimination holds that destination's definition live
 *   so it still exists when the structurer asks (peek-a-bin-pu06). Without it
 *   the only reader of the value is the flags, the flags are not in the IR, and
 *   DCE deletes the arithmetic before anything can name its result.
 *
 * Keeping the two in one place is the point: if DCE protected a def the
 * structurer would not name, the emitted C grows a statement nothing reads; if
 * it protected too few, the branch stays `__unrecovered_N`. The repo has been
 * bitten by hand-synced copies of exactly this kind before — `ripRelative.ts`
 * and `parseOperand` were each re-rolled most of a dozen times — so a second
 * copy of this predicate is the thing to avoid, not the import.
 *
 * The whole module is scaffolding around one design flaw: branch conditions are
 * recovered from the *instructions* through `RegState` rather than from the IR,
 * so the IR cannot express that a Jcc reads a value. peek-a-bin-c33 removes
 * that; when it lands, this file and both call sites go with it.
 */
import type { BasicBlock } from "../cfg";
import { canonReg, isKnownRegister } from "./ir";

/**
 * Instructions that leave every flag exactly as they found them.
 *
 * This list is a *permission to keep looking backwards* for the instruction
 * that set the flags a Jcc reads, so anything not on it — including anything
 * unrecognised — ends the search with no answer. That asymmetry is the whole
 * safety property: a mnemonic wrongly on this list makes the decompiler read a
 * condition off the wrong instruction, while one wrongly left off it only
 * costs a recovery. `not` and `pop` really do write a register without
 * touching the flags, and that is fine: the result is confirmed against the IR
 * by `lastWriteIsSetter` below, so one of these overwriting it is caught there
 * rather than here. `bt` writes CF but leaves ZF and SF alone, which is exactly
 * why it is *not* here — a Jcc after it that reads ZF is reading an older test.
 */
const FLAG_TRANSPARENT = new Set([
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
 * wrote — every arithmetic and logical operation that has a single destination.
 *
 * Deliberately absent, and why:
 *
 * - `imul`/`mul`/`div`/`idiv` — Intel documents ZF and SF as *undefined*.
 * - `rol`/`ror`/`rcl`/`rcr` — write CF and OF only; ZF and SF survive from
 *   whatever set them last, so a Jcc after one is reading an older test.
 * - `bt`/`bts`/`btr` — write CF only, same problem.
 * - `not` — writes no flags at all (it is in `FLAG_TRANSPARENT`).
 * - `adc`/`sbb`/`xadd` — the result is fine, but `lifter.ts` does not lift
 *   them to an assignment, so the result could not be named.
 * - `lock`-prefixed forms — Capstone spells these `lock dec`, which matches
 *   nothing here and so ends the search, which is right: they are read-modify-
 *   write on memory, and this only names registers.
 */
const RESULT_FLAG_SETTERS = new Set([
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

const SHIFTS = new Set(["shl", "sal", "shr", "sar"]);

/**
 * `FLAG_TRANSPARENT` members that write a register the operand text does not
 * name. Their destination is implicit in the mnemonic (`cdq` writes EDX, `cqo`
 * RDX, `cwde`/`cdqe` EAX/RAX, `cbw` AX), so rather than encode a second table
 * of implicit destinations, one appearing after the flag-setter simply ends the
 * search. Costing a recovery is the safe direction; naming a register something
 * else overwrote is not.
 */
const IMPLICIT_REG_WRITERS = new Set(["cbw", "cwd", "cwde", "cdq", "cdqe", "cqo"]);

/**
 * The Jcc forms answerable from a result alone — exactly those reading ZF or SF
 * and nothing else, matching `RegState.getCondition`'s `flagOp === "result"`
 * arm. Every other Jcc also reads CF or OF, neither of which is a function of
 * the result, so the flag-result path declines them (peek-a-bin-4jdx covers
 * what it would take to answer those).
 *
 * This is checked *here* so that DCE protects a definition only when the
 * structurer will actually name it. Widening it without widening
 * `getCondition` would resurrect dead arithmetic into the emitted C for no gain.
 */
const RESULT_ANSWERABLE_JCC = new Set(["je", "jz", "jne", "jnz", "js", "jns"]);

export interface FlagResultSetter {
  /** The flag-setting instruction's mnemonic, lowercased. */
  mnemonic: string;
  /** Its address — the `addr` an `IRStmt` lifted from it carries. */
  address: number;
  /** Its destination register, canonicalised to the 64-bit parent. */
  destReg: string;
  /** The destination operand exactly as written, e.g. `ecx`. */
  destText: string;
  /** The block's trailing conditional jump, lowercased. */
  jcc: string;
}

/** A shift's count when it is a non-zero immediate, else 0 (never a count). */
function immediateCount(text: string): number {
  const n = /^0x[0-9a-f]+$/.test(text)
    ? Number.parseInt(text.slice(2), 16)
    : /^\d+$/.test(text)
      ? Number.parseInt(text, 10)
      : 0;
  return Number.isFinite(n) ? n : 0;
}

/**
 * The instruction whose result the block's trailing Jcc tests, or null when
 * that cannot be answered exactly.
 *
 * Every condition below is a reason the answer would otherwise be a guess:
 *
 * 1. **The block ends in a Jcc a result can answer.** `jmp` and the CF/OF forms
 *    are out (`RESULT_ANSWERABLE_JCC`).
 * 2. **There is no `cmp`/`test` in the block.** One present means the flags may
 *    be its, and the older reading — `RegState` fed from the `cmp` — is the one
 *    that keeps applying. This mirrors `extractCondition`'s `sawCmpTest` gate;
 *    a block with both is deliberately left to the path that predates this one.
 * 3. **The flag-setting instruction really is the last one to write flags.** The
 *    walk back from the Jcc crosses `FLAG_TRANSPARENT` instructions only, so a
 *    `call` or anything unrecognised ends it with no answer rather than
 *    attributing the flags to something older.
 * 4. **The result is somewhere nameable.** A memory destination is not: `dec
 *    dword ptr [rcx]` leaves its result where only a load could read it, and
 *    the load is not there.
 * 5. **A shift actually set the flags.** `shl eax, cl` with `cl == 0` is a
 *    no-op that leaves the flags to an earlier instruction, so a register count
 *    is never good enough.
 */
export function flagResultSetter(block: BasicBlock): FlagResultSetter | null {
  const insns = block.insns;
  const last = insns[insns.length - 1];
  if (!last) return null;
  const jcc = last.mnemonic.toLowerCase();
  if (!RESULT_ANSWERABLE_JCC.has(jcc)) return null;

  for (let i = 0; i < insns.length - 1; i++) {
    const mn = insns[i].mnemonic.toLowerCase();
    if (mn === "cmp" || mn === "test") return null;
  }

  let setter: { mnemonic: string; opStr: string; address: number } | null = null;
  for (let i = insns.length - 2; i >= 0; i--) {
    const mn = insns[i].mnemonic.toLowerCase();
    if (FLAG_TRANSPARENT.has(mn)) continue;
    if (RESULT_FLAG_SETTERS.has(mn)) setter = insns[i];
    break;
  }
  if (!setter) return null;

  const mn = setter.mnemonic.toLowerCase();
  // No x86 memory operand contains a comma, so a plain split is a correct
  // operand split for the one- and two-operand forms this reads.
  const parts = setter.opStr.split(",").map((s) => s.trim().toLowerCase());
  const destText = parts[0] ?? "";
  if (!isKnownRegister(destText)) return null;
  if (SHIFTS.has(mn) && immediateCount(parts[1] ?? "") === 0) return null;
  const destReg = canonReg(destText);

  // 6. **Nothing after it overwrites the result.** `dec ecx / mov ecx, edx /
  //    jne` leaves ECX holding EDX where the guard would read it, so naming it
  //    would state a different test entirely.
  //
  //    The structurer re-asks this of the final IR, which is the authoritative
  //    check — but it *must* also be asked here, of the instructions. The IR
  //    answer changes as passes run: the overwriting `mov` is itself dead in
  //    that example, so dead-code elimination drops it on its first iteration
  //    and the `dec` becomes the last write on the second. Protection that
  //    depended on which iteration asked would be protection decided by pass
  //    ordering. The instruction stream does not move.
  for (let i = 0; i < insns.length - 1; i++) {
    if (insns[i].address <= setter.address) continue;
    const mid = insns[i].mnemonic.toLowerCase();
    if (IMPLICIT_REG_WRITERS.has(mid)) return null;
    // `push` names a register it only reads; everything else reaching here
    // writes its first operand, and a memory destination names no register.
    if (mid === "push" || mid === "nop") continue;
    const dst = insns[i].opStr.split(",")[0]?.trim().toLowerCase() ?? "";
    if (isKnownRegister(dst) && canonReg(dst) === destReg) return null;
  }

  return { mnemonic: mn, address: setter.address, destReg, destText, jcc };
}
