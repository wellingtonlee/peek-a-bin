import type { Instruction, DisasmFunction, StackFrame, StackVar } from './types';

export function analyzeStackFrame(
  func: DisasmFunction,
  instructions: Instruction[],
  is64: boolean,
): StackFrame | null {
  // Find instructions within this function
  const funcInsns: Instruction[] = [];
  const endAddr = func.address + func.size;
  for (const insn of instructions) {
    if (insn.address >= func.address && insn.address < endAddr) {
      funcInsns.push(insn);
    }
    if (insn.address >= endAddr) break;
  }

  if (funcInsns.length === 0) return null;

  // Detect frame size from prologue: sub rsp, N / sub esp, N
  let frameSize = 0;
  for (const insn of funcInsns.slice(0, 10)) {
    if (insn.mnemonic === 'sub') {
      const m = is64
        ? insn.opStr.match(/^rsp,\s*0x([0-9a-fA-F]+)$/i)
        : insn.opStr.match(/^esp,\s*0x([0-9a-fA-F]+)$/i);
      if (m) {
        frameSize = parseInt(m[1], 16);
        break;
      }
      // Decimal immediate
      const md = is64
        ? insn.opStr.match(/^rsp,\s*(\d+)$/i)
        : insn.opStr.match(/^esp,\s*(\d+)$/i);
      if (md) {
        frameSize = parseInt(md[1], 10);
        break;
      }
    }
  }

  // Scan for stack variable accesses.
  // Keyed by "<base>:<signedOffset>" — `[rbp-0x10]` and `[rsp+0x10]` are
  // different memory locations, so keying on the bare numeric offset merged
  // them into one entry with a combined size, a combined access count, and
  // whichever isParam flag happened to be written first.
  interface VarEntry {
    base: 'bp' | 'sp';
    offset: number;        // as written in the operand (always positive)
    signedOffset: number;  // negative for [rbp - N]
    size: number;
    accessCount: number;
    isParam: boolean;
  }
  const varMap = new Map<string, VarEntry>();

  function record(base: 'bp' | 'sp', offset: number, signedOffset: number, size: number, isParam: boolean) {
    const key = stackVarKey(base, signedOffset);
    const existing = varMap.get(key);
    if (existing) {
      existing.accessCount++;
      if (size > existing.size) existing.size = size;
    } else {
      varMap.set(key, { base, offset, signedOffset, size, accessCount: 1, isParam });
    }
  }

  const bpReg = is64 ? 'rbp' : 'ebp';
  const spReg = is64 ? 'rsp' : 'esp';

  // Size heuristic from operand prefix
  function inferSize(opStr: string): number {
    if (opStr.includes('byte')) return 1;
    if (opStr.includes('word') && !opStr.includes('dword') && !opStr.includes('qword')) return 2;
    if (opStr.includes('dword')) return 4;
    if (opStr.includes('qword')) return 8;
    // Default based on architecture
    return is64 ? 8 : 4;
  }

  for (const insn of funcInsns) {
    const op = insn.opStr;

    // [rbp - 0xN] → local variable
    const bpLocalMatch = op.match(new RegExp(`\\[${bpReg}\\s*-\\s*0x([0-9a-fA-F]+)\\]`, 'i'));
    if (bpLocalMatch) {
      const offset = parseInt(bpLocalMatch[1], 16);
      record('bp', offset, -offset, inferSize(op), false);
    }

    // [rsp + 0xN] → could be local or param depending on offset vs frameSize
    const spMatch = op.match(new RegExp(`\\[${spReg}\\s*\\+\\s*0x([0-9a-fA-F]+)\\]`, 'i'));
    if (spMatch) {
      const offset = parseInt(spMatch[1], 16);
      record('sp', offset, offset, inferSize(op), false);
    }

    // [rbp + 0xN] → parameter (above saved rbp + return addr)
    const bpParamMatch = op.match(new RegExp(`\\[${bpReg}\\s*\\+\\s*0x([0-9a-fA-F]+)\\]`, 'i'));
    if (bpParamMatch) {
      const offset = parseInt(bpParamMatch[1], 16);
      // In 64-bit: [rbp+0x10] = first stack param, [rbp+0x18] = second, etc.
      // In 32-bit: [ebp+0x8] = first param, [ebp+0xC] = second, etc.
      const minParamOffset = is64 ? 0x10 : 0x8;
      if (offset >= minParamOffset) {
        record('bp', offset, offset, inferSize(op), true);
      }
    }
  }

  if (varMap.size === 0 && frameSize === 0) return null;

  // Build sorted variable list. Sorted by the operand offset as before; entries
  // that now stay distinct (same offset, different base) are ordered bp first.
  const vars: StackVar[] = [];
  const entries = Array.from(varMap.values())
    .sort((a, b) => a.offset - b.offset || a.base.localeCompare(b.base));

  let paramIdx = 0;
  const usedNames = new Set<string>();
  for (const v of entries) {
    let name: string;
    if (v.isParam) {
      name = `arg_${paramIdx}`;
      paramIdx++;
    } else {
      // Two locals can now share an operand offset (e.g. [rbp-0x10] and
      // [rsp+0x10]); suffix the base so their names stay distinct. Names are
      // unchanged whenever there is no collision.
      name = `var_${v.offset.toString(16).toUpperCase()}`;
      if (usedNames.has(name)) name = `${name}_${v.base}`;
    }
    usedNames.add(name);
    vars.push({
      offset: v.offset,
      size: v.size,
      accessCount: v.accessCount,
      name,
      key: stackVarKey(v.base, v.signedOffset),
    });
  }

  return { frameSize, vars };
}

/** Stable identity for a stack slot: base register + signed operand offset. */
export function stackVarKey(base: 'bp' | 'sp', signedOffset: number): string {
  return `${base}:${signedOffset}`;
}
