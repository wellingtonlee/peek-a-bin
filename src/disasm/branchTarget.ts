/**
 * The branch-target grammar, by address.
 *
 * Where a `call`/`jmp` operand points, or null when it points nowhere nameable.
 *
 * `direct` is a code address — `call 0x140001000`. `indirectMem` is the address
 * of a *pointer*: `call qword ptr [rip + 0x…]` and `call dword ptr [0x…]` are
 * how both an import thunk and an ordinary indirect call through a global are
 * spelled, and telling them apart is the caller's job (look the address up in
 * the IAT first, as `lifter.ts` does).
 *
 * Deliberately the same grammar `resolveNamedTarget` reads, and RIP
 * displacements go through `ripRelative.ts` rather than a tenth private copy —
 * see the `parseOperand` gotcha in CLAUDE.md.
 *
 * A LEAF, on purpose: `callSummary.ts` re-exports it and `crtIdioms.ts` reads it
 * for a `cmp`'s memory operand (the same three spellings, minus `direct`), and
 * `callSummary.ts` in turn imports `crtIdioms.ts` for its batch pass — so the
 * grammar has to sit below both to keep the import graph acyclic.
 */

import type { RipInsn } from "./ripRelative";
import { resolveRipTarget } from "./ripRelative";

export type BranchTargetAddr =
  | { kind: "direct"; addr: number }
  | { kind: "indirectMem"; addr: number };

/** The least an instruction has to carry for its operand to be resolved. */
export type BranchTargetInsn = RipInsn;

export function resolveBranchTargetAddr(insn: BranchTargetInsn): BranchTargetAddr | null {
  const opStr = insn.opStr.trim();

  const directM = opStr.match(/^0x([0-9a-fA-F]+)$/);
  if (directM) return { kind: "direct", addr: parseInt(directM[1], 16) };

  const rip = resolveRipTarget(insn);
  if (rip !== null) return { kind: "indirectMem", addr: rip };

  const addrM = opStr.match(/\[\s*0x([0-9a-fA-F]+)\s*\]/);
  if (addrM) return { kind: "indirectMem", addr: parseInt(addrM[1], 16) };

  return null;
}
