import type { CalleeClobbers } from "../callSummary";
import { resolveBranchTargetAddr } from "../callSummary";
import type { BasicBlock } from "../cfg";
import { resolveRipMemExpr, resolveRipTarget } from "../ripRelative";
import { pushedImmediate } from "../stackIdiom";
import type { Instruction } from "../types";
import {
  blockFlagOwner,
  canSpellCondition,
  isFlagTransparent,
  withoutLockPrefix,
} from "./flagModel";
import type { BinaryOp, IRBranch, IRCall, IRExpr, IRStmt } from "./ir";
import {
  canonReg,
  irBinary,
  irConst,
  irDeref,
  irReg,
  irUnary,
  irUnknown,
  isKnownRegister,
  regSize,
} from "./ir";
import { RegState } from "./regstate";

// ── Operand Parsing ──

const MEM_PATTERN = /^(byte|word|dword|qword)\s+ptr\s+/i;
const BRACKET_PATTERN = /\[([^\]]+)\]/;
const HEX_PATTERN = /^-?0x([0-9a-fA-F]+)$/;
const DEC_PATTERN = /^-?\d+$/;

/** Size in bytes from memory operand prefix. */
function memPrefixSize(s: string): number {
  const m = s.match(MEM_PATTERN);
  if (!m) return 0;
  switch (m[1].toLowerCase()) {
    case "byte":
      return 1;
    case "word":
      return 2;
    case "dword":
      return 4;
    case "qword":
      return 8;
  }
  return 0;
}

function isRegister(s: string): boolean {
  // NB: not `regSize(s) > 0` — regSize() falls back to 4 for unknown names, so
  // that test matched every operand and immediates were lifted as registers.
  return isKnownRegister(s) || /^(rip|eip)$/i.test(s.trim());
}

function parseImm(s: string): number | null {
  const trimmed = s.trim();
  const hexM = trimmed.match(HEX_PATTERN);
  if (hexM) {
    const v = parseInt(hexM[1], 16);
    // An x86 immediate is at most 64 bits, and Capstone prints it unsigned:
    // `or rdi, 0xffffffffffffffff` is `or rdi, -1`. `parseInt` rounds that to
    // 2^64, a value no later stage can do anything true with — the constant
    // folder saw 2^64 and produced 0. Reading the top bit as the sign, which
    // is what the instruction does, gives a number that is both exact and
    // right.
    if (!Number.isSafeInteger(v)) {
      const signed = BigInt.asIntN(64, BigInt(`0x${hexM[1]}`));
      const n = Number(signed);
      if (Number.isSafeInteger(n)) return trimmed.startsWith("-") ? -n : n;
    }
    return trimmed.startsWith("-") ? -v : v;
  }
  if (DEC_PATTERN.test(trimmed)) return parseInt(trimmed, 10);
  return null;
}

/**
 * Parse a memory expression inside brackets: e.g. `rbp - 0x10`, `rax + rcx*4 + 0x10`.
 * Returns an IRExpr representing the address.
 */
function parseMemExpr(inside: string, insn: Instruction, is64: boolean): IRExpr {
  // Handle RIP-relative addressing
  const ripTarget = resolveRipMemExpr(inside, insn);
  if (ripTarget !== null) return irConst(ripTarget, is64 ? 8 : 4);

  // Tokenize: split on + and - while preserving sign
  const tokens: { sign: number; text: string }[] = [];
  let buf = "";
  let sign = 1;
  for (let i = 0; i <= inside.length; i++) {
    const ch = inside[i];
    if (i === inside.length || ch === "+" || ch === "-") {
      const t = buf.trim();
      if (t) tokens.push({ sign, text: t });
      sign = ch === "-" ? -1 : 1;
      buf = "";
    } else {
      buf += ch;
    }
  }

  let result: IRExpr | null = null;
  const addExpr = (expr: IRExpr, s: number) => {
    if (!result) {
      result = s === -1 ? irUnary("-", expr) : expr;
    } else {
      result = s === -1 ? irBinary("-", result, expr) : irBinary("+", result, expr);
    }
  };

  for (const tok of tokens) {
    // reg*scale
    const scaleMatch = tok.text.match(/^(\w+)\s*\*\s*(\d+)$/i);
    if (scaleMatch && isRegister(scaleMatch[1])) {
      const reg = scaleMatch[1];
      const scale = parseInt(scaleMatch[2], 10);
      addExpr(irBinary("*", irReg(reg), irConst(scale)), tok.sign);
      continue;
    }
    // register
    if (isRegister(tok.text)) {
      addExpr(irReg(tok.text), tok.sign);
      continue;
    }
    // immediate
    const imm = parseImm(tok.text);
    if (imm !== null) {
      addExpr(irConst(Math.abs(imm), is64 ? 8 : 4), imm < 0 ? -tok.sign : tok.sign);
      continue;
    }
    // fallback
    addExpr(irUnknown(tok.text), tok.sign);
  }

  return result ?? irConst(0);
}

/**
 * Parse a single Capstone operand string into an IR expression.
 *
 * A register operand lifts to a plain register read — deliberately *not* to
 * whatever expression `RegState` last recorded for it. Substituting here
 * produced IR that no later stage could read correctly: the assignment that
 * computed the value was still emitted, so a side-effecting source (a call) was
 * duplicated at every read, and the leaves of the substituted expression meant
 * "value on entry to the block" while `ssa.ts` renames every leaf to the most
 * recent definition. Propagation is buildSSA + ssaopt + foldBlock's job; they
 * do it with the version information that makes it sound. The parameter is
 * gone rather than ignored so this cannot quietly come back.
 */
export function parseOperand(op: string, insn: Instruction, is64: boolean): IRExpr {
  const trimmed = op.trim();
  if (!trimmed) return irUnknown("");

  // Memory operand: e.g. `dword ptr [rbp - 0x10]` or `[rax]`
  const prefixSize = memPrefixSize(trimmed);
  const bracketM = trimmed.match(BRACKET_PATTERN);
  if (bracketM) {
    const size = prefixSize || (is64 ? 8 : 4);
    const addr = parseMemExpr(bracketM[1], insn, is64);
    return irDeref(addr, size);
  }

  // Register
  if (isRegister(trimmed)) {
    return irReg(trimmed, regSize(trimmed));
  }

  // Immediate
  const imm = parseImm(trimmed);
  if (imm !== null) {
    return irConst(imm, is64 ? 8 : 4);
  }

  return irUnknown(trimmed);
}

/**
 * Parse operand but return the raw register (not regState expression).
 * Used for destination operands where we want the register itself.
 */
function parseDestOperand(op: string, insn: Instruction, is64: boolean): IRExpr {
  const trimmed = op.trim();
  if (!trimmed) return irUnknown("");

  const prefixSize = memPrefixSize(trimmed);
  const bracketM = trimmed.match(BRACKET_PATTERN);
  if (bracketM) {
    const size = prefixSize || (is64 ? 8 : 4);
    const addr = parseMemExpr(bracketM[1], insn, is64);
    return irDeref(addr, size);
  }

  if (isRegister(trimmed)) {
    return irReg(trimmed);
  }

  const imm = parseImm(trimmed);
  if (imm !== null) return irConst(imm, is64 ? 8 : 4);
  return irUnknown(trimmed);
}

function splitOperands(opStr: string): string[] {
  // Split on comma, respecting brackets
  const parts: string[] = [];
  let depth = 0;
  let buf = "";
  for (const ch of opStr) {
    if (ch === "[") depth++;
    if (ch === "]") depth--;
    if (ch === "," && depth === 0) {
      parts.push(buf.trim());
      buf = "";
    } else {
      buf += ch;
    }
  }
  if (buf.trim()) parts.push(buf.trim());
  return parts;
}

// ── Core Lifter ──

const ARITH_OPS: Record<string, BinaryOp> = {
  add: "+",
  sub: "-",
  and: "&",
  or: "|",
  xor: "^",
  shl: "<<",
  sal: "<<",
  shr: ">>>",
  sar: ">>",
};

const COND_SET: Record<string, string> = {
  sete: "je",
  setne: "jne",
  setz: "jz",
  setnz: "jnz",
  setg: "jg",
  setge: "jge",
  setl: "jl",
  setle: "jle",
  seta: "ja",
  setae: "jae",
  setb: "jb",
  setbe: "jbe",
  sets: "js",
  setns: "jns",
};

const CMOV_PATTERN = /^cmov(\w+)$/;

const FASTCALL_REGS_64 = ["rcx", "rdx", "r8", "r9"];

const FPU_ARITH = new Map<string, BinaryOp>([
  ["fadd", "+"],
  ["faddp", "+"],
  ["fiadd", "+"],
  ["fsub", "-"],
  ["fsubp", "-"],
  ["fisub", "-"],
  ["fmul", "*"],
  ["fmulp", "*"],
  ["fimul", "*"],
  ["fdiv", "/"],
  ["fdivp", "/"],
  ["fidiv", "/"],
]);

const SSE_SCALAR = new Map<string, BinaryOp | null>([
  ["movss", null],
  ["movsd", null],
  ["addss", "+"],
  ["addsd", "+"],
  ["subss", "-"],
  ["subsd", "-"],
  ["mulss", "*"],
  ["mulsd", "*"],
  ["divss", "/"],
  ["divsd", "/"],
  ["comiss", null],
  ["comisd", null],
  ["ucomiss", null],
  ["ucomisd", null],
]);

/**
 * Mnemonics whose flag effect this file records into `RegState`, so the state
 * they leave behind is a description of what the machine did rather than a
 * leftover.
 *
 * Everything else either leaves the flags untouched (`isFlagTransparent`) or
 * writes them in a way nothing here models, and the second case must displace
 * whatever an earlier compare recorded. Membership is deliberately narrow: a
 * mnemonic wrongly *in* this set makes a Jcc answer from a test the machine no
 * longer holds, while one wrongly left out only costs a recovery.
 */
const FLAG_MODELLED = new Set(["cmp", "test", "comiss", "comisd", "ucomiss", "ucomisd"]);

/** Does this block contain a `cmp` or `test` before its final instruction? */
function blockHasCompare(block: BasicBlock): boolean {
  const insns = block.insns;
  for (let i = 0; i < insns.length - 1; i++) {
    const mn = insns[i].mnemonic.toLowerCase();
    if (mn === "cmp" || mn === "test") return true;
  }
  return false;
}

/**
 * Record a `cmp`/`test`'s comparison into `state`'s flags, or report that its
 * operand text does not split into two.
 *
 * The one declaration of "turn this compare into flag state", asked at the two
 * points where the question arises: `branchFor` below, for a compare owner
 * `flagScanStream` found in the block's predecessor and which this block's own
 * `RegState` therefore never saw, and `structure.ts`'s `extractCondition`, for
 * its forward re-read of the machine text. It went through a private
 * `parseSimpleOperand` in `structure.ts` once, and that copy hardcoded a width
 * of 4 and never resolved a `[rip + …]` operand — CLAUDE.md's tenth hand-rolled
 * operand parse (peek-a-bin-w6f). Keeping the split here means the two callers
 * cannot disagree about it either.
 */
export function setFlagsFromCompare(
  state: RegState,
  insn: Instruction,
  mn: "cmp" | "test",
  is64: boolean,
): boolean {
  // No x86 memory operand contains a comma, so a plain split is a correct
  // operand split for the two-operand forms this reads.
  const parts = insn.opStr.split(",").map((part) => part.trim());
  if (parts.length < 2) return false;
  state.setFlags(mn, parseOperand(parts[0], insn, is64), parseOperand(parts[1], insn, is64));
  return true;
}

/**
 * The `IRBranch` a block's trailing jump becomes, or null when no condition can
 * be spelled for it.
 *
 * **Which instruction the jump's flags belong to is `flagModel.ts`'s question**,
 * and this is where its forward owner model is wired in. The lifter used to
 * answer it with a single boolean — "did I pass a `cmp`/`test` that nothing has
 * displaced" — which is the compare half of the same walk. The model answers
 * the arithmetic half as well, and that is the point: `dec ecx / jnz` sets ZF
 * from the decrement, so the guard is `ecx != 0`, and until now the only route
 * to that was `flagResult.ts`'s backward walk re-deriving it from the
 * instruction stream at structuring time, with `ssaopt.ts` holding the `dec`
 * alive by hand so it would still be there (peek-a-bin-pu06). As a branch
 * statement it is an ordinary IR
 * reader: SSA binds it to the definition that reaches the jump and DCE counts
 * it, so neither the re-derivation nor the hand-holding has anything left to do.
 *
 * Four refusals, each one a case where an answer would be a guess:
 *
 * 1. **A jump that reads no flags.** `blockFlagOwner` returns null for `jmp`
 *    and for `jecxz`/`jrcxz`/`jcxz`, which test a *register*.
 * 2. **An indirect or unresolved target.** There is no address to name, and
 *    inventing one is the failure mode `parseBranchTarget`'s guard prevents.
 * 3. **A result owner in a block that also contains a `cmp`/`test`.** The two
 *    recovery paths are kept disjoint, exactly as the deleted backward walk's
 *    condition 2 kept them: `cmp eax, 5 / sub ecx, edx / jne` really does
 *    branch on
 *    `ecx != 0`, but it is also the shape `corpus/staleGuards.ts` counts as a
 *    superseded reading, and that gate reads *any* condition emitted at such a
 *    jcc as the stale one. Recovering it is a deliberate decision to be taken
 *    with the audit, not a side effect of this wiring.
 * 4. **A result whose destination no longer holds it.** `canSpellCondition` —
 *    the forward model's equivalent of `clobberedAfter`, over the result
 *    register, or over *any* store when the result is in memory.
 *    A *compare* owner is deliberately not filtered on that: the guard's reads
 *    are what keep the compared values alive through DCE, and the same veto is
 *    applied against the machine text in `structure.ts`, which is where it has
 *    to be asked (see the `conditionSpoiled` docstring — copy propagation has
 *    rewritten the IR expression by then).
 *
 *    It is a *destination* and not a register because a memory one is spellable
 *    too: `dec dword ptr [ebp + 0x10] / je` becomes `arg_2--; if (arg_2 == 0)`,
 *    which is correct precisely because the block's statements are emitted
 *    above the `if` — the same ordering the compare arm's `conditionSpoiled`
 *    relies on, read the other way round. Ordering is what makes this sound and
 *    `pipeline.test.ts` pins it (peek-a-bin-ie0j).
 *
 * **A Jcc alone in its block owns none of this and is answered from its
 * predecessor**, which `flagScanStream` decides and `solePred` opts into. Three
 * things change on that path and each is a judgement:
 *
 * - The condition cannot come from `regState`. That state is what walking *this*
 *   block left behind, and this block never executed the compare, so the flags
 *   are re-read from the owning instruction through `setFlagsFromCompare` — the
 *   same call `structure.ts` makes, so the two readings cannot disagree.
 * - Refusal 4 applies to a **compare** owner too. Block-locally it deliberately
 *   does not, because `structure.ts` re-asks it of the machine text; across the
 *   edge the spoiling can happen in the predecessor's tail, and
 *   `flagScanStream` continues the walk through both sides so `spoiled` already
 *   states it. Three predecessors in the corpus are spoiled this way — a `cmp
 *   dword ptr [ebp-0x218], 0` followed by a store — and emitting them is
 *   precisely what `corpus/staleGuards.ts` gates at 0.
 * - Refusal 3 is asked of the **owner's** block. Keeping the compare and result
 *   paths disjoint is a property of the block the flags were set in, not of the
 *   one that reads them.
 */
function branchFor(
  block: BasicBlock,
  insn: Instruction,
  jcc: string,
  regState: RegState,
  is64: boolean,
  solePred?: BasicBlock,
): IRBranch | null {
  const owned = blockFlagOwner(block, solePred);
  if (!owned || owned.jcc !== jcc) return null;
  const target = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
  if (!target) return null;
  const ownerBlock = owned.fromPredecessor && solePred ? solePred : block;

  let condition: IRExpr;
  if (owned.owner.kind === "compare") {
    if (owned.fromPredecessor) {
      if (!canSpellCondition(owned.owner)) return null;
      const state = new RegState();
      if (!setFlagsFromCompare(state, owned.owner.insn, owned.owner.mnemonic, is64)) return null;
      condition = state.getCondition(jcc);
    } else {
      // Nothing between the compare and the jump wrote a flag — that is what
      // makes it the owner — so `regState` still holds exactly this compare.
      condition = regState.getCondition(jcc);
    }
  } else {
    if (!canSpellCondition(owned.owner) || owned.owner.kind !== "result") return null;
    if (blockHasCompare(ownerBlock)) return null;
    // x86 sets the flags from the *result*, so the value tested is the
    // destination read after the instruction ran. `setFlagsFromResult` states
    // that, and `getCondition` answers only the Jcc forms ZF and SF
    // determine — which is the judgement `RESULT_ANSWERABLE_JCC` was a second
    // copy of (peek-a-bin-wf7t).
    //
    // The destination is spelled by `parseOperand`, and that is what admits a
    // memory one. It was `irReg(destText, regSize(destText))`, which cannot
    // express `dword ptr [ebp + 0x10]` — so a `dec` on a stack slot, whose
    // store the lifter does emit and `promoteVars` even names `arg_2`, still
    // reached the page as `__unrecovered_N` with the value it needed on the
    // line directly above. `regSize` would have made a wrong answer rather than
    // no answer, since it falls back to 4 for any unrecognised name, which is
    // the reason the refusal in `canSpellCondition` had to go first
    // (peek-a-bin-ie0j). The instruction passed is the **owner's**, not the
    // Jcc's: a `[rip + …]` destination resolves against the one that names it.
    const state = new RegState();
    const resultOwner = owned.owner;
    state.setFlagsFromResult(parseOperand(resultOwner.destText, resultOwner.insn, is64));
    condition = state.getCondition(jcc);
  }
  if (condition.kind === "unknown") return null;

  return {
    kind: "branch",
    condition,
    target: Number.parseInt(target[1], 16),
    jcc,
    addr: insn.address,
  };
}

/**
 * Lift a single basic block's instructions to IR statements.
 *
 * `calleeSavedFirstWrite` is the one piece of *function*-wide context this
 * otherwise block-local pass takes: the lowest address at which each x86
 * callee-saved register is written (`firstCalleeSavedWrites`). `collectArgs32`
 * needs it to tell a prologue register save from a pushed argument, and that
 * question cannot be answered inside a block — w32.exe 0x40104D is a genuine
 * `push esi` argument at a block *leader*, with ESI written in an earlier
 * block. It is optional and means nothing on the x64 path, where arguments
 * come from registers rather than pushes; omitting it keeps the pre-existing
 * behaviour, which is deliberately not the same claim as "there are no writes".
 *
 * `solePred` is the second, and is the block's only predecessor when it has
 * exactly one (`solePredecessor`). A Jcc whose block writes no flag at all reads
 * flags set before the block was entered, so without it `branchFor` has nothing
 * to answer from and the guard emits as `__unrecovered_N` — 88 blocks across the
 * four corpus binaries, of which 69 are recoverable (peek-a-bin-suql). Omitting
 * it is the pre-existing behaviour for the same reason as above: "nobody told me
 * which block ran first" is not "the flags started here".
 */
export function liftBlock(
  block: BasicBlock,
  regState: RegState,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  _stringMap: Map<number, string>,
  funcMap: Map<number, { name: string; address: number }>,
  calleeSavedFirstWrite?: Map<string, number>,
  calleeClobbers?: CalleeClobbers,
  solePred?: BasicBlock,
): IRStmt[] {
  const stmts: IRStmt[] = [];

  /**
   * Did the *previous* instruction leave the flags somewhere this class cannot
   * describe? See `FLAG_MODELLED` — the clear is deferred by one iteration so a
   * flag *reader* still sees the state its own instruction reads.
   */
  let flagsStale = false;

  // Indexed rather than `for…of` so the `push <imm>` / `pop <reg>` rule below
  // can look backwards from the instruction being lifted. Every `continue` in
  // this loop is unconditional about the index, so it is bound at the top.
  for (let insnIndex = 0; insnIndex < block.insns.length; insnIndex++) {
    const insn = block.insns[insnIndex];
    /**
     * The verbatim mnemonic, for the `raw` fallbacks below.
     *
     * `mn` is the *dispatch* key and has any `lock` prefix stripped, so it must
     * not be the text of an instruction this file gives up on: `__asm { cmpxchg
     * … }` for a `lock cmpxchg` would drop the one word that says the exchange
     * was atomic, from the only place the reader is told about it at all.
     */
    const rawMn = insn.mnemonic.toLowerCase();
    /**
     * The dispatch key: `rawMn` with a `lock` prefix removed.
     *
     * A locked instruction is lifted exactly as its unlocked form, because the
     * prefix changes atomicity and the bus and nothing about the values — the
     * plain `dec dword ptr [rbx]` already lifts to a store here, and `lock dec
     * dword ptr [rbx]` writes the same value to the same place. Dispatching on
     * the prefixed text instead left every locked form on the `raw` fallback,
     * so the guard reading its ZF had no value to name and emitted
     * `__unrecovered_N` beside an `/* unlifted: lock dec … *\/` comment holding
     * the answer (peek-a-bin-3qrl).
     *
     * **Atomicity is not modelled, and this loses the word `lock` from the
     * page.** Nothing in this IR can express it — `xchg` with a memory operand
     * is implicitly locked on x86 and has been lifted as a plain swap since
     * before any of this — and a comment naming the instruction beside an
     * unrecovered guard states strictly less than the decrement plus the test.
     * Every form the lifter has no handler for still reaches `raw` verbatim,
     * `lock cmpxchg` and `lock xadd` among them, so nothing is silently given a
     * reading it has not earned.
     */
    const mn = withoutLockPrefix(insn.mnemonic);
    const parts = splitOperands(insn.opStr);

    // ── Forward flag invalidation ──
    //
    // `RegState`'s flag fields survive until something overwrites them, and
    // until now nothing in this loop ever did: `cmp eax, 5 / sub ecx, edx /
    // jne` recorded the `cmp` and then answered the `jne` from it, which is
    // the wrong test over the wrong operands (peek-a-bin-jitf). The same walk
    // `structure.ts`'s `extractCondition` performs is performed here, off the
    // same `isFlagTransparent` table, so the two cannot drift.
    //
    // The clear is applied at the top of the *next* iteration rather than at
    // the end of this one because a `setcc`/`cmovcc`/`jcc` reads the flags its
    // own instruction reads — the state as of *before* it. Clearing eagerly
    // would answer every one of them `unknown`.
    if (flagsStale) {
      regState.clearFlags();
      flagsStale = false;
    }
    flagsStale = !isFlagTransparent(mn) && !FLAG_MODELLED.has(mn);

    // A register this instruction uses as an address *index* has had its value
    // spent on addressing — noted before the dispatch below, so that an
    // instruction which indexes with a register and then rewrites it clears its
    // own mark when it calls `regState.set`. `collectArgs64` is the only
    // reader; see `noteIndexReads`.
    noteIndexReads(regState, mn, parts);

    // ── nop / int3 / ud2 ──
    if (mn === "nop" || mn === "int3" || mn === "ud2") continue;

    // ── push / pop ──
    //
    // Neither is lifted in general, and that is deliberate: RSP moves with
    // nothing in the IR recording it, so there is no faithful definition chain
    // over the stack slot to reason about, and `collectArgs32` reads the pushes
    // straight off the instruction stream instead.
    //
    // The one exception is MSVC's two-byte `mov reg, imm`, spelled
    // `push <imm>` / `pop <reg>`. Skipping *that* pop left it out of SSA
    // altogether, so it was not a definition and every later read of the
    // register bound to the value it held BEFORE the pop: `add edi, esi`
    // emitted as `edi = edi` where ESI is 8, `cmp eax, esi / je` emitted as
    // `if (eax == 0)` where the machine tests 8, and — the worst of them —
    // t32!sub_401E71's `push 0x16 / pop esi / mov [eax], esi` emitted as
    // `*_errno() = 0` on the one path a guard directly above had just proved
    // the old ESI was zero. An inverted success/failure return, in C that
    // compiles clean, that no gate here can see (peek-a-bin-3axd).
    //
    // The pairing is `../stackIdiom`'s, shared with `functionDetect.ts` rather
    // than re-derived — the same `push 7 / pop ecx` that sizes a jump table
    // there is this idiom, and the two must not be able to disagree. Anything
    // it refuses, including every save/restore pair and every `pop` whose
    // `push` is in another block, is left exactly as it was (peek-a-bin-4ynk).
    if (mn === "push" || mn === "pop") {
      if (mn === "pop" && parts.length === 1) {
        const name = parts[0].trim().toLowerCase();
        // The stack pointer is excluded even though `push 8 / pop esp` really
        // does set it: RSP/ESP is the one register no stage here models, so a
        // definition of it in the IR would be read by the frame analysis as a
        // value it can move, and no `pop esp` in this corpus is this idiom.
        if (isKnownRegister(name) && canonReg(name) !== "rsp") {
          const imm = pushedImmediate(block.insns, insnIndex);
          if (imm !== null) {
            const src = irConst(imm, regSize(name));
            stmts.push({ kind: "assign", dest: irReg(name), src, addr: insn.address });
            regState.set(name, src);
          }
        }
      }
      continue;
    }

    // ── mov ──
    if (mn === "mov") {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${rawMn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const src = parseOperand(parts[1], insn, is64);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: src,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, src);
      }
      continue;
    }

    // ── movzx / movsx / movsxd → emit IRCast with type annotation ──
    if (mn === "movzx" || mn === "movsx" || mn === "movsxd") {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${rawMn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const srcRaw = parseOperand(parts[1], insn, is64);
      // Determine source width from prefix or register size
      const srcSize =
        memPrefixSize(parts[1]) ||
        (srcRaw.kind === "reg" ? regSize(srcRaw.name) : srcRaw.kind === "deref" ? srcRaw.size : 4);
      const signed = mn === "movsx" || mn === "movsxd";
      const castType = signed
        ? srcSize === 1
          ? "int8_t"
          : srcSize === 2
            ? "int16_t"
            : "int32_t"
        : srcSize === 1
          ? "uint8_t"
          : "uint16_t";
      const src: IRExpr = { kind: "cast", type: castType, operand: srcRaw };
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: src,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, src);
      }
      continue;
    }

    // ── lea ──
    if (mn === "lea") {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${rawMn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      // For lea, the bracket content is the address expression (no deref)
      const bracketM = parts[1].match(BRACKET_PATTERN);
      let src: IRExpr;
      if (bracketM) {
        src = parseMemExpr(bracketM[1], insn, is64);
      } else {
        src = parseOperand(parts[1], insn, is64);
      }
      stmts.push({ kind: "assign", dest, src, addr: insn.address });
      if (dest.kind === "reg") regState.set(dest.name, src);
      continue;
    }

    // ── xor reg, reg → zero idiom ──
    if (mn === "xor" && parts.length >= 2) {
      const d = parts[0].trim().toLowerCase();
      const s = parts[1].trim().toLowerCase();
      if (d === s && isRegister(d)) {
        const dest = irReg(d);
        const zero = irConst(0, regSize(d));
        stmts.push({ kind: "assign", dest, src: zero, addr: insn.address });
        regState.set(d, zero);
        continue;
      }
    }

    // ── Arithmetic: add/sub/and/or/xor/shl/shr/sar ──
    if (mn in ARITH_OPS) {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${rawMn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64);
      const src = parseOperand(parts[1], insn, is64);
      const op = ARITH_OPS[mn];
      const result = irBinary(op, destVal, src);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: result,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── imul ──
    if (mn === "imul") {
      if (parts.length === 2) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const destVal = parseOperand(parts[0], insn, is64);
        const src = parseOperand(parts[1], insn, is64);
        const result = irBinary("*", destVal, src);
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      } else if (parts.length >= 3) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const a = parseOperand(parts[1], insn, is64);
        const b = parseOperand(parts[2], insn, is64);
        const result = irBinary("*", a, b);
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      } else {
        stmts.push({ kind: "raw", text: `${rawMn} ${insn.opStr}`, addr: insn.address });
      }
      continue;
    }

    // ── inc / dec ──
    if (mn === "inc" || mn === "dec") {
      if (parts.length < 1) {
        stmts.push({ kind: "raw", text: `${rawMn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64);
      const op: BinaryOp = mn === "inc" ? "+" : "-";
      const result = irBinary(op, destVal, irConst(1));
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: result,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── not / neg ──
    if (mn === "not" || mn === "neg") {
      if (parts.length < 1) {
        stmts.push({ kind: "raw", text: `${rawMn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64);
      const result = irUnary(mn === "not" ? "~" : "-", destVal);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: result,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── cmp / test → flag state, and no statement ──
    //
    // A compare writes only the flags, and the flags are now in the IR as the
    // *condition* of the block's branch statement rather than as an `eflags =
    // …` proxy. The proxy existed because a guard was not an IR reader: nothing
    // else named the compared registers, so DCE deleted the instructions that
    // produced them, and `ssaopt.ts` had to hold the proxy live by hand and
    // then strip it again before emission so it did not reach the page
    // (peek-a-bin-ua8, peek-a-bin-zsb). Since Stage 3 the branch counts those
    // reads directly, so the proxy is a statement with no reader that every
    // pass had to be taught to leave alone (peek-a-bin-c33).
    if (mn === "cmp" || mn === "test") {
      if (parts.length >= 2) {
        regState.setFlags(
          mn as "cmp" | "test",
          parseOperand(parts[0], insn, is64),
          parseOperand(parts[1], insn, is64),
        );
      }
      continue;
    }

    // ── setXX ──
    if (mn in COND_SET) {
      if (parts.length >= 1) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const cond = regState.getCondition(COND_SET[mn]);
        stmts.push({ kind: "assign", dest, src: cond, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, cond);
      }
      continue;
    }

    // ── cmovXX ──
    const cmovM = mn.match(CMOV_PATTERN);
    if (cmovM) {
      if (parts.length >= 2) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const destVal = parseOperand(parts[0], insn, is64);
        const src = parseOperand(parts[1], insn, is64);
        const jcc = "j" + cmovM[1];
        const cond = regState.getCondition(jcc);
        const result: IRExpr = { kind: "ternary", condition: cond, then: src, else: destVal };
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── call ──
    if (mn === "call") {
      const target = resolveCallTarget(insn, is64, iatMap, funcMap);
      const args = is64
        ? collectArgs64(regState)
        : collectArgs32(block, insn, is64, calleeSavedFirstWrite);
      const call: IRCall = {
        kind: "call",
        target: target.name,
        args,
        display: target.display,
        clobbers: calleeClobbersFor(insn, is64, iatMap, calleeClobbers),
      };
      const retReg = is64 ? "rax" : "eax";
      stmts.push({ kind: "call_stmt", call, resultDest: irReg(retReg), addr: insn.address });
      regState.invalidateCallerSaved();
      regState.set(retReg, call);
      continue;
    }

    // ── ret / retn ──
    if (mn === "ret" || mn === "retn") {
      // The return value is the accumulator, named — not the expression
      // `RegState` last recorded for it. That expression is bound to the
      // registers it names *as they were when it was recorded*, and nothing
      // invalidates it when one of them is written again: `mov rax, rbx` /
      // `mov rbx, [rsp+0x30]` / `ret` returned the restored RBX, i.e. the
      // saved-register slot, and the real return value went unread and was
      // then deleted as dead (peek-a-bin-lh6). Naming the register makes SSA
      // bind the read to the definition that actually reaches the `ret`,
      // which is what the instruction does.
      const retReg = is64 ? "rax" : "eax";
      stmts.push({ kind: "return", value: irReg(retReg, is64 ? 8 : 4), addr: insn.address });
      continue;
    }

    // ── Tail call: a `jmp` that leaves the function ──
    //
    // `buildCFG` gives such a jmp no successor, because its target is not a
    // block of this function. The instruction pushes no return address, so the
    // callee returns to *this* function's caller: it is a call followed by a
    // return of the accumulator, and that is what it lifts to. Dropping it
    // made a call the program performs invisible — and the argument set-up
    // above it then died as unread, so the reader saw a function that appears
    // to do nothing at the end (peek-a-bin-22t).
    //
    // Only a jmp whose target resolves to a *name* is lifted. An indirect
    // `jmp rax` and a jump-table dispatch whose targets were not recovered
    // also end a successorless block, and calling either one a tail call would
    // invent a callee that the disassembly does not name.
    if (mn === "jmp" && block.succs.length === 0 && insn === block.insns[block.insns.length - 1]) {
      const tail = resolveNamedTarget(insn, iatMap, funcMap);
      if (tail) {
        const args = is64
          ? collectArgs64(regState)
          : collectArgs32(block, insn, is64, calleeSavedFirstWrite);
        const call: IRCall = {
          kind: "call",
          target: tail.name,
          args,
          display: tail.display,
          clobbers: calleeClobbersFor(insn, is64, iatMap, calleeClobbers),
        };
        const retReg = is64 ? "rax" : "eax";
        stmts.push({ kind: "call_stmt", call, resultDest: irReg(retReg), addr: insn.address });
        regState.invalidateCallerSaved();
        regState.set(retReg, call);
        stmts.push({ kind: "return", value: irReg(retReg, is64 ? 8 : 4), addr: insn.address });
        continue;
      }

      // The target has no name. Saying nothing and saying "a transfer happens
      // here that I could not name" are different things, and the second is
      // what this repo does everywhere else it fails to recover something
      // (`__unrecovered_N`, `/* unlifted: … */`). t32!sub_402C5A is the case
      // that shows the cost of the first: it decodes a pointer and then, in
      // the emitted C, does nothing whatever with it — the call through the
      // decoded pointer was simply absent (peek-a-bin-xerm).
      //
      // TWO SHAPES end a successorless block with an unnameable target, and
      // only one of them is this one:
      //
      //   `jmp eax`                          — a genuine indirect transfer;
      //   `jmp dword ptr [ecx*4 + 0x40b900]` — a jump table whose entries were
      //                                        not recovered.
      //
      // A *recovered* table does not reach here at all: its case targets are
      // block leaders, so the dispatch block has successors and `structureCFG`
      // emits a `switch`. An unrecovered one is a gap in table recovery, not an
      // indirect call, and calling it one would state something false about the
      // program. So only a bare register operand is reported — measured at
      // cee6f91 that is 4 sites (t32 0x402c70/0x404480, w32 0x402ec4/0x4046e0)
      // against 14 table dispatches, and 0 sites on either x64 binary. A memory
      // operand of any shape stays silent, deliberately: `jmp [eax]` cannot be
      // told from an unrecovered table by looking at it.
      //
      // No call expression is synthesized. `resolveNamedTarget` exists because
      // there is no name here, and an invented callee is worse than an admitted
      // gap — the negative test in `pipeline.test.ts` pins that.
      const operand = insn.opStr.trim().toLowerCase();
      if (isKnownRegister(operand)) {
        stmts.push({ kind: "raw", text: `indirect jmp through ${operand}`, addr: insn.address });
        continue;
      }
    }

    // ── Conditional / unconditional jumps ──
    //
    // A conditional jump becomes an `IRBranch` so its condition is a real IR
    // reader: it gets an SSA version, a reaching definition, and a place in
    // every use count. `pipeline.ts` extracts it again before `structureCFG`,
    // so no structured tree ever contains one (peek-a-bin-c33).
    //
    // The precedent is a few lines up: `setcc` already assigns
    // `regState.getCondition()` to a register and that survives SSA renaming
    // untouched. This does for `jcc` what the lifter already does for `setcc`.
    //
    // Which instruction's flags the jump reads is `flagModel.ts`'s answer —
    // see `branchFor`.
    if (mn === "jmp" || mn.startsWith("j")) {
      if (insn === block.insns[block.insns.length - 1]) {
        const branch = branchFor(block, insn, mn, regState, is64, solePred);
        if (branch) stmts.push(branch);
      }
      continue;
    }

    // ── Sign-extend idioms ──
    if (mn === "cdq") {
      // edx = eax >> 31 (sign-extend eax into edx:eax)
      const eaxVal = irReg("eax", 4);
      const result = irBinary(">>", eaxVal, irConst(31));
      stmts.push({ kind: "assign", dest: irReg("edx"), src: result, addr: insn.address });
      regState.set("edx", result);
      continue;
    }
    if (mn === "cqo") {
      // rdx = rax >> 63
      const raxVal = irReg("rax", 8);
      const result = irBinary(">>", raxVal, irConst(63));
      stmts.push({ kind: "assign", dest: irReg("rdx"), src: result, addr: insn.address });
      regState.set("rdx", result);
      continue;
    }
    if (mn === "cdqe") {
      // rax = (int32_t)eax
      const eaxVal = irReg("eax", 4);
      const result: IRExpr = { kind: "cast", type: "int32_t", operand: eaxVal };
      stmts.push({ kind: "assign", dest: irReg("rax"), src: result, addr: insn.address });
      regState.set("rax", result);
      continue;
    }
    if (mn === "cwde") {
      // eax = (int16_t)ax
      const axVal = irReg("ax", 2);
      const result: IRExpr = { kind: "cast", type: "int16_t", operand: axVal };
      stmts.push({ kind: "assign", dest: irReg("eax"), src: result, addr: insn.address });
      regState.set("eax", result);
      continue;
    }
    if (mn === "cbw") {
      // ax = (int8_t)al
      const alVal = irReg("al", 1);
      const result: IRExpr = { kind: "cast", type: "int8_t", operand: alVal };
      stmts.push({ kind: "assign", dest: irReg("ax"), src: result, addr: insn.address });
      regState.set("ax", result);
      continue;
    }
    if (mn === "cwd") {
      // dx = ax >> 15
      const axVal = irReg("ax", 2);
      const result = irBinary(">>", axVal, irConst(15));
      stmts.push({ kind: "assign", dest: irReg("dx"), src: result, addr: insn.address });
      regState.set("dx", result);
      continue;
    }

    // ── div / idiv ──
    if (mn === "div" || mn === "idiv") {
      if (parts.length >= 1) {
        const divisor = parseOperand(parts[0], insn, is64);
        const srcSize =
          divisor.kind === "reg"
            ? regSize(divisor.name)
            : divisor.kind === "deref"
              ? divisor.size
              : 4;
        const dividendHi = srcSize === 8 ? "rdx" : srcSize === 2 ? "dx" : "edx";
        const dividendLo = srcSize === 8 ? "rax" : srcSize === 2 ? "ax" : "eax";
        const loVal = irReg(dividendLo, regSize(dividendLo));
        const quotient = irBinary("/", loVal, divisor);
        const remainder = irBinary("%", loVal, divisor);
        // Remainder first. Both expressions read the dividend, and one
        // instruction writes both halves *from the same input* — so the
        // statement that overwrites the dividend has to come second or SSA
        // binds the other one's read to it, giving `edx = (eax / ecx) % ecx`.
        // Emitting EDX first also keeps a divisor like `[eax]` readable.
        stmts.push({ kind: "assign", dest: irReg(dividendHi), src: remainder, addr: insn.address });
        stmts.push({ kind: "assign", dest: irReg(dividendLo), src: quotient, addr: insn.address });
        regState.set(dividendLo, quotient);
        regState.set(dividendHi, remainder);
      } else {
        stmts.push({ kind: "raw", text: `__asm { ${rawMn} ${insn.opStr} }`, addr: insn.address });
      }
      continue;
    }

    // ── mul (single-operand) ──
    if (mn === "mul") {
      if (parts.length >= 1) {
        const src = parseOperand(parts[0], insn, is64);
        const srcSize =
          src.kind === "reg" ? regSize(src.name) : src.kind === "deref" ? src.size : 4;
        const accLo = srcSize === 8 ? "rax" : srcSize === 2 ? "ax" : "eax";
        const accHi = srcSize === 8 ? "rdx" : srcSize === 2 ? "dx" : "edx";
        const loVal = irReg(accLo, regSize(accLo));
        const result = irBinary("*", loVal, src);
        // High part first — SSA DCE will eliminate it if unused. Both halves
        // are computed from the accumulator *before* the multiply, so writing
        // the low half first would make the high half read the product and
        // square it.
        stmts.push({
          kind: "assign",
          dest: irReg(accHi),
          src: irBinary(">>", result, irConst(srcSize * 8)),
          addr: insn.address,
        });
        stmts.push({ kind: "assign", dest: irReg(accLo), src: result, addr: insn.address });
        regState.set(accLo, result);
        regState.set(accHi, irBinary(">>", result, irConst(srcSize * 8)));
      } else {
        stmts.push({ kind: "raw", text: `__asm { ${rawMn} ${insn.opStr} }`, addr: insn.address });
      }
      continue;
    }

    // ── xchg ──
    if (mn === "xchg" && parts.length >= 2) {
      const a = parseDestOperand(parts[0], insn, is64);
      const b = parseDestOperand(parts[1], insn, is64);
      const aVal = parseOperand(parts[0], insn, is64);
      const bVal = parseOperand(parts[1], insn, is64);
      if (a.kind === "reg" && b.kind === "reg") {
        // A swap needs the temporary. `a = b; b = a` is not one: SSA renames
        // the second statement's read of `a` to the definition the first
        // statement just made, so both registers end up holding b's value.
        // The temporary is a plain register, so copy propagation collapses it
        // back to `a = b_0; b = a_0` — the temporary exists to pin the *read*
        // to the right program point, not to survive into the output.
        const tmp = irReg("tmp_xchg", regSize(a.name));
        stmts.push({ kind: "assign", dest: tmp, src: aVal, addr: insn.address });
        stmts.push({ kind: "assign", dest: a, src: bVal, addr: insn.address });
        stmts.push({ kind: "assign", dest: b, src: tmp, addr: insn.address });
        regState.set(a.name, bVal);
        regState.set(b.name, aVal);
      } else {
        stmts.push({ kind: "raw", text: `__asm { ${rawMn} ${insn.opStr} }`, addr: insn.address });
      }
      continue;
    }

    // ── String ops: rep movsb → memcpy, rep stosb → memset ──
    if (mn === "rep" || insn.opStr.toLowerCase().startsWith("rep ")) {
      const innerMn =
        mn === "rep" ? insn.opStr.toLowerCase().replace(/^rep\s+/, "") : insn.opStr.toLowerCase();

      if (innerMn.startsWith("movs")) {
        const rdi = irReg(is64 ? "rdi" : "edi", is64 ? 8 : 4);
        const rsi = irReg(is64 ? "rsi" : "esi", is64 ? 8 : 4);
        const rcx = irReg(is64 ? "rcx" : "ecx", is64 ? 8 : 4);
        const call: IRCall = { kind: "call", target: "memcpy", args: [rdi, rsi, rcx] };
        stmts.push({ kind: "call_stmt", call, addr: insn.address });
        continue;
      }
      if (innerMn.startsWith("stos")) {
        const rdi = irReg(is64 ? "rdi" : "edi", is64 ? 8 : 4);
        const al = irReg("al", 1);
        const rcx = irReg(is64 ? "rcx" : "ecx", is64 ? 8 : 4);
        const call: IRCall = { kind: "call", target: "memset", args: [rdi, al, rcx] };
        stmts.push({ kind: "call_stmt", call, addr: insn.address });
        continue;
      }
    }

    // ── Basic FPU: fld/fst/fstp/fadd/fsub/fmul/fdiv ──
    if (mn === "fld" && parts.length >= 1) {
      const src = parseOperand(parts[0], insn, is64);
      stmts.push({ kind: "assign", dest: irReg("st0"), src, addr: insn.address });
      regState.set("st0", src);
      continue;
    }
    if ((mn === "fst" || mn === "fstp") && parts.length >= 1) {
      const dest = parseDestOperand(parts[0], insn, is64);
      const st0 = irReg("st0", 10);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: st0,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: st0, addr: insn.address });
      }
      continue;
    }
    if (FPU_ARITH.has(mn) && parts.length >= 1) {
      const src = parseOperand(parts[0], insn, is64);
      const st0 = irReg("st0", 10);
      const op = FPU_ARITH.get(mn)!;
      const result = irBinary(op, st0, src);
      stmts.push({ kind: "assign", dest: irReg("st0"), src: result, addr: insn.address });
      regState.set("st0", result);
      continue;
    }

    // ── SSE scalar: movss/addss/subss/mulss/divss/comiss ──
    if (SSE_SCALAR.has(mn) && parts.length >= 2) {
      const dest = parseDestOperand(parts[0], insn, is64);
      const src = parseOperand(parts[1], insn, is64);
      if (mn === "movss" || mn === "movsd") {
        if (dest.kind === "deref") {
          stmts.push({
            kind: "store",
            address: dest.address,
            value: src,
            size: dest.size,
            addr: insn.address,
          });
        } else {
          stmts.push({ kind: "assign", dest, src, addr: insn.address });
          if (dest.kind === "reg") regState.set(dest.name, src);
        }
      } else if (mn === "comiss" || mn === "comisd" || mn === "ucomiss" || mn === "ucomisd") {
        // Sets the flags and writes nothing else, exactly as `cmp` does, and
        // for the same reason emits no statement. `setcc`/`cmovcc` read the
        // state it leaves; a *branch* is deliberately not built from it — see
        // `branchFor`.
        regState.setFlags("cmp", parseOperand(parts[0], insn, is64), src);
      } else {
        // Arithmetic: addss/subss/mulss/divss
        const op = SSE_SCALAR.get(mn)!;
        const destVal = parseOperand(parts[0], insn, is64);
        const result = irBinary(op, destVal, src);
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── Everything else: AVX, etc. → raw asm ──
    stmts.push({ kind: "raw", text: `__asm { ${rawMn} ${insn.opStr} }`, addr: insn.address });
  }

  return stmts;
}

// ── Call Target Resolution ──

/**
 * The name a direct, RIP-relative or absolute branch target stands for, or
 * null when the operand names no address at all (an indirect branch through a
 * register or a computed expression).
 *
 * Split out from `resolveCallTarget` because a tail `jmp` may only be lifted
 * when the target *is* nameable: `resolveCallTarget`'s `(*rax)` fallback is
 * right for `call rax`, where the disassembly already says a call happens, and
 * wrong for `jmp rax`, where it would invent one.
 */
function resolveNamedTarget(
  insn: Instruction,
  iatMap: Map<number, { lib: string; func: string }>,
  funcMap: Map<number, { name: string; address: number }>,
): { name: string; display?: string } | null {
  const opStr = insn.opStr.trim();

  // Direct: `call 0xNNNN`
  const directM = opStr.match(/^0x([0-9a-fA-F]+)$/);
  if (directM) {
    const addr = parseInt(directM[1], 16);
    const fn = funcMap.get(addr);
    if (fn) return { name: fn.name };
    return { name: `sub_${addr.toString(16).toUpperCase()}` };
  }

  // RIP-relative: `call qword ptr [rip + 0xNNNN]`
  const target = resolveRipTarget(insn);
  if (target !== null) {
    const iat = iatMap.get(target);
    if (iat) return { name: iat.func, display: `${iat.lib}!${iat.func}` };
    const fn = funcMap.get(target);
    if (fn) return { name: fn.name };
    return { name: `sub_${target.toString(16).toUpperCase()}` };
  }

  // Direct address in brackets: `call dword ptr [0xNNNN]`
  const addrM = opStr.match(/\[\s*0x([0-9a-fA-F]+)\s*\]/);
  if (addrM) {
    const abs = parseInt(addrM[1], 16);
    const iat = iatMap.get(abs);
    if (iat) return { name: iat.func, display: `${iat.lib}!${iat.func}` };
    return { name: `sub_${abs.toString(16).toUpperCase()}` };
  }

  return null;
}

/**
 * The registers this call site's callee is known to modify, or `undefined` when
 * no summary was supplied.
 *
 * THREE RULES, and the third is the one that keeps this honest:
 *
 * - **x64 only.** On x86 `clobberedByCall` reports nothing at all — cdecl and
 *   stdcall pass nothing in a register, so there is no call-site evidence to
 *   union with — and every register this could add would be new. The 32-bit CRT
 *   helpers are also the shape the summary is least sure about; see
 *   `callSummary.ts`. The two PE32 binaries are the control for this change and
 *   their emitted C must not move.
 * - **RAX is dropped.** `liftBlock` gives every `call_stmt` a `resultDest` of
 *   RAX/EAX, so it is already defined at this point and listing it again buys
 *   nothing.
 * - **A target with no summary gets `unresolved`, not silence.** An import, an
 *   indirect call and a jump into unrecovered code are the same fact — a callee
 *   whose body this analysis never read — and what they are worth is the
 *   caller's policy, not this function's. `CalleeClobbers.unresolved` carries it.
 */
function calleeClobbersFor(
  insn: Instruction,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  summaries: CalleeClobbers | undefined,
): string[] | undefined {
  if (!is64 || !summaries) return undefined;
  const target = resolveBranchTargetAddr(insn);
  let regs: readonly string[] = summaries.unresolved;
  if (target && !(target.kind === "indirectMem" && iatMap.has(target.addr))) {
    const known = summaries.byAddress.get(target.addr);
    if (known) regs = known;
  }
  const out = regs.filter((r) => r !== "rax");
  return out.length > 0 ? out : undefined;
}

function resolveCallTarget(
  insn: Instruction,
  _is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  funcMap: Map<number, { name: string; address: number }>,
): { name: string; display?: string } {
  const named = resolveNamedTarget(insn, iatMap, funcMap);
  if (named) return named;

  const opStr = insn.opStr.trim();

  // Indirect call through register
  if (isRegister(opStr)) {
    return { name: `(*${opStr})` };
  }

  // Comment-based IAT
  if (insn.comment) {
    const iatMatch = insn.comment.match(/^(\S+)!(\S+)$/);
    if (iatMatch) return { name: iatMatch[2], display: insn.comment };
  }

  return { name: `(*${opStr})` };
}

// ── Argument Collection ──

/**
 * Arguments for a Windows x64 fastcall, in register order.
 *
 * `RegState` is consulted for *arity only*: a call is given as many arguments
 * as there are leading fastcall registers this block has written, which is the
 * only arity evidence available at lift time. The argument itself is the plain
 * register — substituting the recorded expression re-expanded whatever computed
 * it (including another call) at the call site, and bound its leaves to the
 * wrong definitions once SSA renaming ran.
 *
 * The probe is `wroteAnyAlias`, not `get`, because argument setup is routinely
 * sub-width: MSVC emits `mov ecx, 1` for an `int` argument, and `RegState`
 * keys that def by the operand text, so asking for `rcx` missed it and stopped
 * arity right there. `ExitProcess()` was emitted with no argument at all while
 * the machine passed one, and with no reader in the IR the `ecx = 1` was then
 * deleted as dead — the exit code vanished from the output entirely. Only
 * *whether* an argument is emitted changes; what is emitted is still the plain
 * 64-bit register, and SSA already keys on the same canonical identity, so the
 * `rcx` read binds to the `ecx` def.
 *
 * A written register is not enough on its own, and that was the last x64
 * over-count: a block that computes an index into RCX, addresses with it, and
 * then calls `GetLastError` has written RCX for its own purposes, not for the
 * call. So the scan also stops at the first register whose value the block has
 * already *spent* as an address index — see `noteIndexReads` for why an index
 * and not a base, and for the three widenings this corpus refutes.
 */
function collectArgs64(regState: RegState): IRExpr[] {
  const args: IRExpr[] = [];
  for (const reg of FASTCALL_REGS_64) {
    if (!regState.wroteAnyAlias(reg)) break; // stop at first register this block never set
    if (regState.readSinceWrite(reg)) break; // …or the first whose value is already spent
    args.push(irReg(reg, 8));
  }
  return args;
}

/**
 * Registers this instruction spends as the *index* of a memory operand, fed to
 * `RegState.noteRead`. `collectArgs64` stops at the first fastcall register
 * whose value has been spent that way.
 *
 * BASE AND INDEX ARE NOT THE SAME EVIDENCE, and the rule turns on the
 * distinction. The base of an effective address is routinely an object pointer
 * the very next call also receives — `lea rdx, [rcx+0x10]` / `f(rcx, rdx)` — so
 * a base read says nothing about whether the register is an argument. An index
 * is a subscript: a value produced to address *with*, and once the access using
 * it is emitted the value has been spent. Both x64 over-count shapes are that:
 *
 *   imul rcx, rcx, 0x58                     ; rcx becomes a table offset
 *   and  BYTE PTR [rax+rcx*1+0x8], 0xfe     ; …spent addressing with it
 *   call QWORD PTR [GetLastError]           ; which declares no parameters
 *
 *   imul rdx, rdx, 0x58
 *   lea  rcx, [rax+rdx*1+0x10]              ; rdx spent, rcx is the argument
 *   jmp  QWORD PTR [LeaveCriticalSection]   ; which declares one
 *
 * ONE EXEMPTION, and it is the prefix property rather than a patch. An index
 * read does not spend the register when the instruction's destination is a
 * fastcall register *later in the argument order* than it: `mov rdx,
 * QWORD PTR [rdx+rcx*8]` is argument two being derived from argument one.
 * `collectArgs64` counts a prefix, so if RDX is an argument then RCX is one
 * too, and the index read cannot be evidence against it. The reverse direction
 * carries no such implication — `lea rcx, [rax+rdx*1+0x10]` makes RCX argument
 * one whether or not RDX is argument two — which is why the two `lea`s above
 * are judged differently. Without this, t64!sub_14000FCE7 emits
 * `sub_14000278C()` for a callee that reads both ECX and RDX, and the two
 * statements computing them are then deleted as dead: the whole body becomes
 * one bare call. That is `peek-a-bin-qb2x`'s failure mode.
 *
 * THREE SHAPES REFUTED by this same corpus, none of which may be re-tried as a
 * widening — each drops a genuine argument:
 *
 * - *Any* read spends the register. t64 0x14000FAF0 `mov DWORD PTR [rsp+0x20],
 *   r8d` spills R8 to the outgoing stack-argument area *because* it is also the
 *   register argument; `CreateFileW(…)` loses two of its four.
 * - Any read from inside a memory operand spends it. t64 0x14000BD6E
 *   `lea edx, [r9+0x8]` is MSVC computing the constant 9 from the 1 it just put
 *   in R9 — arithmetic wearing an address's clothes — and R9 is argument four
 *   of the `MultiByteToWideChar` two instructions later. R9 is the *base* there,
 *   which is why base and index are separated.
 * - Distance, and dominance, from the write to the call. Both were the filed
 *   hypothesis and both are refuted by every one of the six rows: `RegState` is
 *   per-block so the write always dominates, and it is two instructions from
 *   the call at t64 0x14000B35F and 0x14000369C.
 *
 * `call` and the `j`-prefixed mnemonics are exempt because they *are* the call
 * site: `call QWORD PTR [rax+rcx*8]` finding its callee through a table is not
 * the block spending RCX before the call. (x86/x64 only — no non-branch
 * mnemonic starts with `j`. Do not copy that to A64, where `bfi` is not a
 * branch.)
 */
function noteIndexReads(regState: RegState, mn: string, parts: string[]): void {
  if (mn === "call" || mn.startsWith("j")) return;
  // Intel syntax: the destination is the first operand, and only when there is
  // a second one. `cmp`/`test`/`push` therefore report -1 and spend normally.
  const destSlot = parts.length >= 2 ? fastcallSlot(parts[0]) : -1;
  for (const part of parts) {
    for (const mem of part.toLowerCase().matchAll(MEM_OPERAND)) {
      let haveBase = false;
      for (const tok of mem[1].matchAll(INDEXABLE_TOKEN)) {
        const name = tok[1];
        if (!isKnownRegister(name)) continue;
        // The first register carrying no `*scale` is the base; anything after
        // it, or anything scaled, is the index. Capstone omits `*1`, so the
        // positional test is what fires on `[rax + rcx + 8]`.
        if (!haveBase && !tok[2]) {
          haveBase = true;
          continue;
        }
        const slot = fastcallSlot(name);
        if (destSlot >= 0 && slot >= 0 && slot < destSlot) continue;
        regState.noteRead(name);
      }
    }
  }
}

/** Position of `reg` in the Windows x64 fastcall order, or -1. */
function fastcallSlot(reg: string): number {
  const name = reg.trim().toLowerCase();
  if (!isKnownRegister(name)) return -1;
  return FASTCALL_REGS_64.indexOf(canonReg(name));
}

/** The `[…]` body of a memory operand. Capstone never nests them. */
const MEM_OPERAND = /\[([^\]]*)\]/g;

/**
 * A bare identifier inside a memory operand, plus the `*` that would make it a
 * scaled index. Anchored on a letter so a hex literal's `0x…` cannot match, and
 * `\b`-delimited so `ptr`, `rip` and the rest are whole tokens
 * `isKnownRegister` simply rejects.
 */
const INDEXABLE_TOKEN = /\b([a-z][a-z0-9]*)\b(\s*\*)?/g;

/**
 * The x86 callee-saved registers, canonicalised (`canonReg` maps every alias to
 * its 64-bit parent, which is the register's *identity*).
 *
 * The restriction to these four is what makes `collectArgs32`'s save rule below
 * sound rather than merely empirical. On x86 cdecl and stdcall every incoming
 * argument arrives on the stack, so a callee-saved register's *entry* value is
 * semantically opaque to the callee: it belongs to some caller further up and
 * this function has no reading of it. Forwarding it as an argument is
 * meaningless, so a `push` of one before anything has written it is a register
 * save. The same statement about EAX or ECX would be false — those carry
 * results and `__fastcall` arguments.
 */
const CALLEE_SAVED_CANON_32 = new Set(["rbx", "rsi", "rdi", "rbp"]);

/**
 * Mnemonics whose first operand is read, not written.
 *
 * Deliberately a DENY-list rather than an allow-list of writers, and the
 * asymmetry is the reason. A mnemonic missing from here is treated as a write,
 * which lowers the register's first-write address, which classifies *more*
 * pushes as arguments — i.e. it degrades towards the behaviour that existed
 * before this rule, and can invent nothing new. A wrongly *added* entry raises
 * the first-write address and drops a genuine argument. So the failure mode of
 * an incomplete list is the status quo, and the failure mode of an over-eager
 * one is a new under-count; the list is kept to mnemonics that provably do not
 * write their destination operand.
 *
 * Every conditional and unconditional jump is handled by the `j` prefix at the
 * call site — this is the x86 path only, where no non-branch mnemonic starts
 * with `j`. (Do not copy that shortcut to A64, where `bfi` is not a branch.)
 */
const NON_DEFINING_MNEMONICS = new Set([
  "push",
  "cmp",
  "test",
  "call",
  "ret",
  "retn",
  "nop",
  "int3",
  "ud2",
  "bt",
  "hlt",
  "leave", // handled separately: it writes EBP, but not its (absent) operand
]);

/** String-instruction mnemonics, which write ESI/EDI with no operand naming them. */
const STRING_OP_MNEMONICS = new Set([
  "movsb",
  "movsw",
  "movsd",
  "movsq",
  "stosb",
  "stosw",
  "stosd",
  "stosq",
  "lodsb",
  "lodsw",
  "lodsd",
  "lodsq",
  "scasb",
  "scasw",
  "scasd",
  "scasq",
  "cmpsb",
  "cmpsw",
  "cmpsd",
  "cmpsq",
]);

const REP_PREFIXES = new Set(["rep", "repe", "repz", "repne", "repnz"]);

/**
 * The lowest address in a function at which each callee-saved register is
 * written — the evidence `collectArgs32` needs to tell a register save from an
 * argument.
 *
 * A `push ebx` before the function has written EBX pushes the value EBX held on
 * entry; a `push ebx` after it pushes something this function computed. That is
 * the ONLY thing that separates the two, and it separates them at a site where
 * the same register in the same basic block is both. Verified on t32.exe at
 * 0x402C35:
 *
 *     402c37: 56              push esi            ; SAVE — ESI not yet written
 *     402c3a: be 17 04 00 c0  mov  esi, 0xc0000417 ; ESI defined here
 *     402c3f: 56              push esi            ; ARGUMENT
 *
 * Three properties of this scan are load-bearing and were each established
 * against a specific site in the corpus:
 *
 * - **Function-wide, not block-local.** w32.exe 0x40104D is `push esi` /
 *   `call FreeLibrary` at a *block leader*, with ESI written at 0x40100F in an
 *   earlier block. Scoped to the block, that genuine argument is dropped.
 * - **`mov X, X` is not a definition.** MSVC's hot-patch pad is `mov edi, edi`
 *   and it is the *entry instruction* of two of the four over-counting t32
 *   sites (0x405D6D, 0x405F2F). Counting it as a write to EDI re-admits both.
 * - **Address order, not CFG order.** This is an approximation, and its error
 *   is one-directional by construction: a write laid out *after* a push that
 *   dynamically precedes it makes the push look like a save, which drops an
 *   argument. It can never invent one. The reverse — a write laid out before a
 *   push it does not dominate — leaves the push classified as an argument, i.e.
 *   exactly today's behaviour.
 *
 * The scan reads the instruction stream only. It must never consult
 * `apitypes.ts`: `corpus/arity.ts` audits the emitted arity *against* that
 * table, so a lifter that reads it measures its own input and blinds the only
 * oracle in this repo that can see call arity at all.
 */
export function firstCalleeSavedWrites(blocks: BasicBlock[]): Map<string, number> {
  const first = new Map<string, number>();

  const note = (operand: string, addr: number): void => {
    const name = operand.trim().toLowerCase();
    if (!isKnownRegister(name)) return;
    const canon = canonReg(name);
    if (!CALLEE_SAVED_CANON_32.has(canon)) return;
    const prev = first.get(canon);
    if (prev === undefined || addr < prev) first.set(canon, addr);
  };

  for (const block of blocks) {
    for (const insn of block.insns) {
      const addr = insn.address;
      const tokens = insn.mnemonic.toLowerCase().split(/\s+/).filter(Boolean);
      const mn = tokens[tokens.length - 1] ?? "";
      const repPrefixed = tokens.some((t) => REP_PREFIXES.has(t));
      const parts = splitOperands(insn.opStr);

      // `leave` is `mov esp, ebp` + `pop ebp`, and `enter` builds a frame:
      // both write EBP while naming no operand that says so.
      if (mn === "leave" || mn === "enter") {
        note("ebp", addr);
        continue;
      }

      // A string instruction advances ESI and/or EDI. Capstone spells the
      // operands as `es:[edi]` / `[esi]` memory references, so the generic
      // destination-operand path below cannot see the write. The guard keeps
      // SSE `movsd xmm0, qword ptr [rax]` — the same mnemonic, a different
      // instruction — out: that one names real operands and no `rep` prefix.
      if (
        STRING_OP_MNEMONICS.has(mn) &&
        (repPrefixed || parts.length === 0 || /\bes:/i.test(insn.opStr))
      ) {
        note("esi", addr);
        note("edi", addr);
        continue;
      }

      if (NON_DEFINING_MNEMONICS.has(mn) || mn.startsWith("j")) continue;

      // One-operand `mul` / `div` / `imul` / `idiv` READ their operand and
      // write EDX:EAX. The two- and three-operand `imul` forms do write it.
      if ((mn === "mul" || mn === "div" || mn === "imul" || mn === "idiv") && parts.length < 2) {
        continue;
      }

      if (parts.length === 0) continue;

      // `mov edi, edi` is MSVC's hot-patch pad, not a definition. Stated in the
      // general form — `mov X, X` changes nothing whatever X is — but ONLY for
      // `mov`: `xor esi, esi` has the same operand shape and is a zeroing, i.e.
      // the most common definition there is. Generalising the test past `mov`
      // withdrew the write at t32.exe 0x4068C6 and turned four real `Sleep(esi)`
      // calls per x86 binary into `Sleep()`.
      if (mn === "mov" && parts.length === 2 && parts[0].toLowerCase() === parts[1].toLowerCase()) {
        continue;
      }

      note(parts[0], addr);
      // `xchg` writes both of its operands.
      if (mn === "xchg" && parts.length === 2) note(parts[1], addr);
    }
  }

  return first;
}

/**
 * Is this call nested in a *later* call's argument list?
 *
 * The shape is `call inner` / `push eax` / … / `call outer`: the inner call's
 * result is pushed, so the inner call is an argument expression of the outer
 * one and the outer one's argument list is still being built around it. The
 * pushes *before* the inner call therefore belong to the outer call, not to it.
 *
 * THE MARKER IS AFTER THE INNER CALL, NOT BEFORE IT, and that is the whole
 * reason a simpler rule does not work. The tempting reading — "stop the
 * backwards push-walk at an intervening call" — never fires, because in this
 * shape there is no call between the pushes and the inner call. Verified on
 * t32.exe at 0x40e08b:
 *
 *     53                 push ebx                ; 0x1000 → HeapAlloc's arg
 *     6a 08              push 0x8                ;        → HeapAlloc's arg
 *     ff 15 60 f0 40 00  call GetProcessHeap     ; declares 0, claimed both
 *     50                 push eax
 *     ff 15 70 f0 40 00  call HeapAlloc
 *
 * and at 0x402c4a with GetCurrentProcess/TerminateProcess.
 *
 * Only a push of the accumulator counts, and only as the very next instruction:
 * that is the evidence that this call's *result* is what feeds the outer one.
 * Everything from there to the outer call must be a push, i.e. the argument
 * list is still under construction — anything else and the accumulator's route
 * to the outer call is no longer something this scan can read.
 */
function nestedInLaterCallArgs(insns: Instruction[], callIdx: number, is64: boolean): boolean {
  const acc = is64 ? "rax" : "eax";
  const next = insns[callIdx + 1];
  if (next === undefined || next.mnemonic !== "push") return false;
  if (next.opStr.trim().toLowerCase() !== acc) return false;
  for (let i = callIdx + 2; i < insns.length; i++) {
    if (insns[i].mnemonic === "call") return true;
    if (insns[i].mnemonic !== "push") return false;
  }
  return false;
}

function collectArgs32(
  block: BasicBlock,
  callInsn: Instruction,
  is64: boolean,
  calleeSavedFirstWrite: Map<string, number> | undefined,
): IRExpr[] {
  // Scan backwards from call for consecutive push instructions
  const args: IRExpr[] = [];
  const insns = block.insns;
  let callIdx = -1;
  for (let i = insns.length - 1; i >= 0; i--) {
    if (insns[i].address === callInsn.address) {
      callIdx = i;
      break;
    }
  }
  if (callIdx < 0) return args;

  // A call whose result is pushed into a following call's argument list gets no
  // pushed arguments at all. The pushes above it are the OUTER call's, and
  // attributing them here invents arguments the machine never passed —
  // `GetProcessHeap(8, 0x1000)` for an API that declares none, which compiles
  // clean and which `corpus/arity.ts` is the only oracle here able to see.
  //
  // This is deliberately an ADMITTED UNDER-COUNT rather than a re-attribution:
  // handing the pushes to the outer call instead would be a guess in the
  // over-count direction, and an invented argument is the one error this
  // codebase will not trade for a recovered one. Where the inner call really
  // does take pushed arguments they are dropped, and it becomes an `under` row
  // — visible, and the benign direction. In this corpus every inner callee the
  // rule fires on declares zero parameters, so all four sites land on `exact`.
  if (nestedInLaterCallArgs(insns, callIdx, is64)) return args;

  // Walking backwards from the call already yields argument order: cdecl
  // pushes the last argument first, so the push nearest the call is argument 1.
  for (let i = callIdx - 1; i >= 0 && args.length < 8; i--) {
    if (insns[i].mnemonic !== "push") break;
    const op = insns[i].opStr.trim();
    if (isCalleeSavedSave(insns[i], op, calleeSavedFirstWrite)) break;
    args.push(parseOperand(op, insns[i], is64));
  }
  return args;
}

/**
 * Is this `push` a callee-saved register SAVE rather than an argument?
 *
 * The whole discriminator is whether the pushed register still holds its
 * function-entry value — see `firstCalleeSavedWrites` for the evidence and for
 * why address order is a sound approximation here. Reaching one of these ends
 * the backwards walk: a save sitting under an argument list means the walk has
 * left the argument list.
 *
 * Without this the walk swallowed the function's own prologue saves and emitted
 * them as arguments — `GetModuleHandleW("KERNEL32.DLL", edi)` for an API that
 * declares one parameter, `GetCommandLineW(edi, esi, ebx)` for one that
 * declares none. There is no reading of the machine on which those are right,
 * and they compile clean, so only `corpus/arity.ts` could see them
 * (peek-a-bin-6lmh).
 *
 * `calleeSavedFirstWrite === undefined` means nobody told us where the writes
 * are, which is not the same as "there are none": the rule declines and the
 * pre-existing behaviour stands.
 */
function isCalleeSavedSave(
  pushInsn: Instruction,
  operand: string,
  calleeSavedFirstWrite: Map<string, number> | undefined,
): boolean {
  if (calleeSavedFirstWrite === undefined) return false;
  const name = operand.toLowerCase();
  if (!isKnownRegister(name)) return false;
  const canon = canonReg(name);
  if (!CALLEE_SAVED_CANON_32.has(canon)) return false;
  const firstWrite = calleeSavedFirstWrite.get(canon);
  // Never written in this function at all — every push of it is a save.
  return firstWrite === undefined || pushInsn.address < firstWrite;
}
