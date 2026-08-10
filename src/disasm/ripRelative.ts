/**
 * RIP-relative displacement parsing.
 *
 * `[rip + 0xNNNN]` / `[rip - 0xNNNN]` was hand-rolled at nine call sites across
 * functionDetect.ts, operands.ts and decompile/lifter.ts. They agreed on the
 * arithmetic but not on the pattern (two of the nine matched `rip`
 * case-insensitively, seven did not), so this module is the single home for
 * both the regex and the address computation.
 *
 * x86-64 semantics: RIP holds the address of the NEXT instruction, so the base
 * is `insn.address + insn.size`, never `insn.address`.
 */

/** Bracketed form, matched anywhere in an operand string: `qword ptr [rip + 0x10]`. */
const RIP_BRACKETED = /\[\s*rip\s*([+-])\s*0x([0-9a-fA-F]+)\s*\]/i;

/** Bare form, matched against the whole contents of a bracket: `rip + 0x10`. */
const RIP_BARE = /^\s*rip\s*([+-])\s*0x([0-9a-fA-F]+)\s*$/i;

/** The minimum an instruction has to expose to resolve a RIP displacement. */
export interface RipInsn {
  address: number;
  size: number;
  opStr: string;
}

export interface RipDisplacement {
  /** Signed displacement — negative for `[rip - 0x..]`. */
  disp: number;
  /** Start offset of the match within the searched string. */
  index: number;
  /** Length of the matched text. */
  length: number;
}

function matchDisplacement(re: RegExp, text: string): RipDisplacement | null {
  const m = text.match(re);
  if (!m) return null;
  const sign = m[1] === "+" ? 1 : -1;
  return {
    disp: sign * parseInt(m[2], 16),
    index: m.index ?? 0,
    length: m[0].length,
  };
}

/**
 * Find a bracketed `[rip +/- 0x..]` anywhere in an operand string.
 * Callers that only want the resolved address should use `resolveRipTarget`;
 * this form exists for callers that also need the matched span (to stop a
 * later absolute-hex scan from reporting the displacement a second time).
 */
export function matchRipOperand(opStr: string): RipDisplacement | null {
  return matchDisplacement(RIP_BRACKETED, opStr);
}

/** Match a bare `rip +/- 0x..` that makes up the entire contents of a bracket. */
export function matchRipMemExpr(inside: string): RipDisplacement | null {
  return matchDisplacement(RIP_BARE, inside);
}

/**
 * Absolute address referenced by a bracketed RIP-relative operand, or null if
 * the instruction has no such operand.
 */
export function resolveRipTarget(insn: RipInsn): number | null {
  const m = matchRipOperand(insn.opStr);
  if (!m) return null;
  return insn.address + insn.size + m.disp;
}

/**
 * Absolute address for an already-unwrapped bracket body, or null if the body
 * is not a bare RIP displacement.
 */
export function resolveRipMemExpr(inside: string, insn: RipInsn): number | null {
  const m = matchRipMemExpr(inside);
  if (!m) return null;
  return insn.address + insn.size + m.disp;
}
