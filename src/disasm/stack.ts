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

  // Scan for stack variable accesses
  const varMap = new Map<number, { size: number; accessCount: number; isParam: boolean }>();

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
      const existing = varMap.get(offset);
      const size = inferSize(op);
      if (existing) {
        existing.accessCount++;
        if (size > existing.size) existing.size = size;
      } else {
        varMap.set(offset, { size, accessCount: 1, isParam: false });
      }
    }

    // [rsp + 0xN] → could be local or param depending on offset vs frameSize
    const spMatch = op.match(new RegExp(`\\[${spReg}\\s*\\+\\s*0x([0-9a-fA-F]+)\\]`, 'i'));
    if (spMatch) {
      const offset = parseInt(spMatch[1], 16);
      const existing = varMap.get(offset);
      const size = inferSize(op);
      if (existing) {
        existing.accessCount++;
        if (size > existing.size) existing.size = size;
      } else {
        varMap.set(offset, { size, accessCount: 1, isParam: false });
      }
    }

    // [rbp + 0xN] → parameter (above saved rbp + return addr)
    const bpParamMatch = op.match(new RegExp(`\\[${bpReg}\\s*\\+\\s*0x([0-9a-fA-F]+)\\]`, 'i'));
    if (bpParamMatch) {
      const offset = parseInt(bpParamMatch[1], 16);
      // In 64-bit: [rbp+0x10] = first stack param, [rbp+0x18] = second, etc.
      // In 32-bit: [ebp+0x8] = first param, [ebp+0xC] = second, etc.
      const minParamOffset = is64 ? 0x10 : 0x8;
      if (offset >= minParamOffset) {
        const existing = varMap.get(offset);
        const size = inferSize(op);
        if (existing) {
          existing.accessCount++;
        } else {
          varMap.set(offset, { size, accessCount: 1, isParam: true });
        }
      }
    }
  }

  if (varMap.size === 0 && frameSize === 0) return null;

  // Build sorted variable list
  const vars: StackVar[] = [];
  const sortedOffsets = Array.from(varMap.keys()).sort((a, b) => a - b);

  let paramIdx = 0;
  for (const offset of sortedOffsets) {
    const v = varMap.get(offset)!;
    let name: string;
    if (v.isParam) {
      name = `arg_${paramIdx}`;
      paramIdx++;
    } else {
      name = `var_${offset.toString(16).toUpperCase()}`;
    }
    vars.push({
      offset,
      size: v.size,
      accessCount: v.accessCount,
      name,
    });
  }

  return { frameSize, vars };
}
