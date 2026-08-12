import type { ImportEntry } from "../pe/types";
import { matchRipOperand } from "./ripRelative";
import type { Instruction } from "./types";

export interface OperandTarget {
  address: number;
  display?: string; // import name like "kernel32.dll!CreateFileW"
}

/**
 * Parse all hex address targets from an instruction's operands.
 * Returns targets that fall within the image range.
 */
export function parseOperandTargets(
  insn: Instruction,
  imageBase: number,
  imageEnd: number,
  iatMap?: Map<number, { lib: string; func: string }>,
): OperandTarget[] {
  const targets: OperandTarget[] = [];
  const seen = new Set<number>();

  const addTarget = (addr: number) => {
    if (seen.has(addr)) return;
    seen.add(addr);
    const iat = iatMap?.get(addr);
    targets.push({
      address: addr,
      display: iat ? `${iat.lib}!${iat.func}` : undefined,
    });
  };

  const mn = insn.mnemonic;
  const op = insn.opStr;

  // Case 1: direct branch call/jmp 0xNNNN
  if (mn === "call" || mn === "jmp" || mn.startsWith("j")) {
    const m = op.match(/^0x([0-9a-fA-F]+)$/);
    if (m) {
      const target = parseInt(m[1], 16);
      if (target >= imageBase && target < imageEnd) addTarget(target);
      return targets; // direct branch, no other targets
    }
  }

  // Case 2: RIP-relative [rip +/- 0xNNNN]
  // The matched span is remembered so case 3 cannot report the displacement a
  // second time. A RIP displacement is an offset from the next instruction, so
  // it is never an address in its own right; with a low image base it can still
  // fall in range and produce a bogus xref alongside the real one.
  let ripSpan: [number, number] | null = null;
  const ripMatch = matchRipOperand(op);
  if (ripMatch) {
    const target = insn.address + insn.size + ripMatch.disp;
    if (target >= imageBase && target < imageEnd) addTarget(target);
    ripSpan = [ripMatch.index, ripMatch.index + ripMatch.length];
  }

  // Case 3: all hex addresses in operand (absolute [0xNNNN] or bare 0xNNNN).
  // Only the RIP span is skipped, not the whole operand string — a store like
  // `mov dword ptr [rip + 0x10], 0x407120` still carries a real second target.
  const hexMatches = op.matchAll(/0x([0-9a-fA-F]+)/g);
  for (const m of hexMatches) {
    const idx = m.index ?? 0;
    if (ripSpan && idx >= ripSpan[0] && idx < ripSpan[1]) continue;
    const addr = parseInt(m[1], 16);
    if (addr >= imageBase && addr < imageEnd) addTarget(addr);
  }

  return targets;
}

/**
 * Build a lookup map from IAT addresses to import names.
 */
export function buildIATLookup(imports: ImportEntry[]): Map<number, { lib: string; func: string }> {
  const map = new Map<number, { lib: string; func: string }>();
  for (const imp of imports) {
    for (let i = 0; i < imp.functions.length; i++) {
      if (i < imp.iatAddresses.length) {
        map.set(imp.iatAddresses[i], {
          lib: imp.libraryName,
          func: imp.functions[i],
        });
      }
    }
  }
  return map;
}
