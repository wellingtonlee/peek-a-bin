/**
 * TWO POPULATIONS THAT SIZE EPIC 3 OF `peek-a-bin-n9cl`, read from the machine
 * text and the emitted C side by side.
 *
 * 1. **A callee that is not a name.** `resolveCallTarget` spells `call rax` as
 *    `(*rax)(…)` and a target it cannot resolve at all reaches the page as an
 *    `__unrecovered_N` — so the work of giving `IRCall` a real `targetExpr` is
 *    sized by how many call sites have no named callee today. Both spellings are
 *    counted from the text, the machine-level indirect calls beside them as the
 *    population they are drawn from, and an `indirect jmp through <reg>` raw
 *    (the lifter's honest spelling for a register tail call) as the third shape.
 *
 * 2. **Stack arguments five and up on x64.** The Microsoft x64 convention puts
 *    argument N (N ≥ 5) at `[rsp + 0x20 + 8*(N-5)]` in the caller's frame, so a
 *    `mov qword ptr [rsp + 0x28], r` whose next control transfer is a `call` is
 *    the caller passing a fifth or later argument — and `collectArgs64` reads
 *    none of them, so the emitted call is arity-short by exactly that many
 *    (`corpus/arity.ts` reports it as UNDER at the ABI ceiling). The census
 *    counts the stores from the MACHINE, since the emitted C may spell the slot
 *    through an alias (`r11 = rsp; *(int64_t*)(r11 + 0x20) = …`) or not at all,
 *    and separately counts the text's own `(rsp + 0x20..) =` spellings so a
 *    change that starts consuming them is visible from both sides.
 *
 * **REPORT-ONLY.** Every row is a size, not a verdict: a register call is
 * correctly spelled `(*rax)()` today, and a fifth argument the emitter does not
 * pass is the admitted under-count `peek-a-bin-f51x` prefers to an invented one.
 * `calls` and `insns` are the liveness halves, and the x86 pair's stack-argument
 * figures are STRUCTURALLY 0 — the 32-bit conventions pass on the stack by
 * `push`, which `collectArgs32` already reads — so a green x86 row there says
 * nothing.
 *
 * WHAT IT DOES NOT SEE. A store to the home area through a register other than
 * RSP (the `r11` alias above) is not counted at the machine level either — the
 * question is what a direct `[rsp + N]` scan would find, which is the shape the
 * arity work would consume first. "Next control transfer is a `call`" is a
 * straight-line reading and says nothing about a store the call reaches through
 * a branch.
 */

import type { Instruction } from "../src/disasm/types";

export interface CallShapeResult {
  /** Functions read. Liveness. */
  funcs: number;
  /** Instructions read. Liveness. */
  insns: number;
  /** Machine `call` instructions. */
  calls: number;
  /** Of those, not a bare immediate target. */
  indirectCalls: number;
  /** Of those, a bare register operand — the `(*rax)()` population. */
  indirectRegCalls: number;
  /** Every emitted indirect callee — `((intptr_t (*)())<target>)(`. The four rows below partition it. */
  indirectCallees: number;
  /** Of those, the target is a register name. */
  registerCallees: number;
  /** Of those, the target is `__unrecovered_N` — the value the emitter could not name. */
  unrecoveredCallees: number;
  /** Of those, the target is some OTHER identifier: `arg_0`, `var_20`, `__imp_X`. */
  namedCallees: number;
  /** Of those, the target is not an identifier at all — a deref, a field access. */
  exprCallees: number;
  /** Emitted `indirect jmp through <reg>` raws. */
  indirectJmpRaws: number;
  /** x64 only: machine stores to `[rsp + disp]`, disp ≥ 0x20. */
  slotStores: number;
  /** Of those, the next control transfer after the store is a `call`. */
  slotStoresBeforeCall: number;
  /** x64 only: machine reads of such a slot (operand other than a store's destination). */
  slotReads: number;
  /** Functions with at least one store before a call. */
  funcsPassingStackArgs: number;
  /** Emitted `(rsp + 0x<disp>) =` lines, disp ≥ 0x20 — the text's own spelling. */
  textSlotStores: number;
  /** Emitted reads of `(rsp + 0x<disp>)`, disp ≥ 0x20, that are not such a store. */
  textSlotReads: number;
}

export const emptyCallShapes = (): CallShapeResult => ({
  funcs: 0,
  insns: 0,
  calls: 0,
  indirectCalls: 0,
  indirectRegCalls: 0,
  indirectCallees: 0,
  registerCallees: 0,
  unrecoveredCallees: 0,
  namedCallees: 0,
  exprCallees: 0,
  indirectJmpRaws: 0,
  slotStores: 0,
  slotStoresBeforeCall: 0,
  slotReads: 0,
  funcsPassingStackArgs: 0,
  textSlotStores: 0,
  textSlotReads: 0,
});

/** The first argument slot the x64 convention puts in the caller's frame. */
export const X64_FIRST_STACK_ARG = 0x20;

const REGISTER =
  /^(?:r(?:ax|bx|cx|dx|si|di|bp|sp)|e(?:ax|bx|cx|dx|si|di|bp|sp)|r(?:8|9|1[0-5])d?)$/i;
const RSP_SLOT = /\[rsp \+ 0x([0-9a-f]+)\]/i;
const IDENTIFIER = /^[A-Za-z_]\w*$/;

/** How `emit.ts`'s `calleeText` opens an indirect callee. THE spelling — it has only one. */
const CALLEE_PREFIX = "((intptr_t (*)())";

/**
 * The target text of every indirect callee on one emitted line.
 *
 * DEPTH-COUNTED, not anchored on the first `)`. The old patterns here
 * (`(*<ident>)(` and `__unrecovered_N(`) matched spellings `calleeText` has
 * NEVER produced — it wraps every indirect target in `CALLEE_PREFIX` — so both
 * rows read a structural 0 on all four binaries and the census that was
 * supposed to SIZE `IRCall.targetExpr` said the population was empty while
 * eight call sites sat in it (`peek-a-bin-s1f6.1`). A non-discriminating
 * control is not a control. The targets that need counting today include
 * `*(int32_t*)(eax + 4)` and `((struct_0 *)eax)->field_0x4`, both of which
 * carry their own parentheses, so the scan balances them.
 */
function indirectCalleeTargets(line: string): string[] {
  const out: string[] = [];
  for (let i = line.indexOf(CALLEE_PREFIX); i >= 0; i = line.indexOf(CALLEE_PREFIX, i + 1)) {
    let depth = 0;
    let end = -1;
    for (let j = i; j < line.length; j++) {
      if (line[j] === "(") depth++;
      else if (line[j] === ")" && --depth === 0) {
        end = j;
        break;
      }
    }
    if (end < 0) continue;
    out.push(line.slice(i + CALLEE_PREFIX.length, end).trim());
  }
  return out;
}

/** Capstone's operands, split at the commas that separate them — none is inside a memory operand. */
const operandsOf = (opStr: string): string[] =>
  opStr
    .split(",")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);

const isTransfer = (mn: string) => mn === "call" || mn === "ret" || mn.startsWith("j");

export function auditCallShapes(
  res: CallShapeResult,
  insns: Instruction[],
  code: string,
  is64: boolean,
): void {
  res.funcs++;
  res.insns += insns.length;
  let passing = false;
  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];
    const mn = insn.mnemonic.toLowerCase();
    if (mn === "call") {
      res.calls++;
      const op = insn.opStr.trim();
      if (!/^0x[0-9a-f]+$/i.test(op)) {
        res.indirectCalls++;
        if (REGISTER.test(op)) res.indirectRegCalls++;
      }
      continue;
    }
    if (!is64) continue;
    const ops = operandsOf(insn.opStr);
    ops.forEach((op, idx) => {
      const m = RSP_SLOT.exec(op);
      if (m === null || Number.parseInt(m[1], 16) < X64_FIRST_STACK_ARG) return;
      const isStore = idx === 0 && mn.startsWith("mov") && ops.length > 1;
      if (!isStore) {
        res.slotReads++;
        return;
      }
      res.slotStores++;
      for (let j = i + 1; j < insns.length; j++) {
        const next = insns[j].mnemonic.toLowerCase();
        if (!isTransfer(next)) continue;
        if (next === "call") {
          res.slotStoresBeforeCall++;
          passing = true;
        }
        break;
      }
    });
  }
  if (passing) res.funcsPassingStackArgs++;

  for (const raw of code.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("//")) continue;
    for (const target of indirectCalleeTargets(line)) {
      res.indirectCallees++;
      if (target.startsWith("__unrecovered_")) res.unrecoveredCallees++;
      else if (!IDENTIFIER.test(target)) res.exprCallees++;
      else if (REGISTER.test(target)) res.registerCallees++;
      else res.namedCallees++;
    }
    if (/indirect jmp through/.test(line)) res.indirectJmpRaws++;
    for (const m of line.matchAll(/\(rsp \+ 0x([0-9A-Fa-f]+)\)(\s*=(?!=))?/g)) {
      if (Number.parseInt(m[1], 16) < X64_FIRST_STACK_ARG) continue;
      if (m[2] !== undefined) res.textSlotStores++;
      else res.textSlotReads++;
    }
  }
}
