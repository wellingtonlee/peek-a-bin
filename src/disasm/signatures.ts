import type { Instruction, DisasmFunction } from './types';

export interface FunctionSignature {
  convention: string;
  paramCount: number;
}

const FASTCALL_REGS_64 = ['rcx', 'rdx', 'r8', 'r9'];
const CDECL_PARAM_REGS_32 = ['ecx']; // for thiscall detection

function isSourceOperand(mnemonic: string, opStr: string, reg: string): boolean {
  const lower = opStr.toLowerCase();
  const regLower = reg.toLowerCase();

  // For mov/lea: first operand is destination, second is source
  if (mnemonic === 'mov' || mnemonic === 'lea' || mnemonic === 'movzx' || mnemonic === 'movsx') {
    const parts = lower.split(',');
    if (parts.length >= 2) {
      // If reg appears only in second part (source), it's a read
      const inDest = parts[0].includes(regLower);
      const inSrc = parts.slice(1).join(',').includes(regLower);
      if (inSrc && !inDest) return true;
      if (inDest && !inSrc) return false;
    }
    return false;
  }

  // For cmp/test: both operands are sources (read-only)
  if (mnemonic === 'cmp' || mnemonic === 'test') {
    return lower.includes(regLower);
  }

  // For push: source operand
  if (mnemonic === 'push') {
    return lower.includes(regLower);
  }

  // For call: rcx/rdx/r8/r9 are implicitly read
  if (mnemonic === 'call') {
    return false; // don't count call as reading params
  }

  // For arithmetic (add, sub, and, or, xor): first operand is both src+dest
  // If reg is in the operand at all, it's being read
  return lower.includes(regLower);
}

function inferSignature64(funcInsns: Instruction[]): FunctionSignature {
  // Windows x64 fastcall: RCX, RDX, R8, R9
  const scanLimit = Math.min(funcInsns.length, 20);
  const written = new Set<string>();
  let maxParam = 0;

  for (let i = 0; i < scanLimit; i++) {
    const insn = funcInsns[i];
    const mn = insn.mnemonic;

    for (let pi = 0; pi < FASTCALL_REGS_64.length; pi++) {
      const reg = FASTCALL_REGS_64[pi];
      if (written.has(reg)) continue;

      if (isSourceOperand(mn, insn.opStr, reg)) {
        maxParam = Math.max(maxParam, pi + 1);
      }

      // Check if this instruction writes to the register (destination)
      const parts = insn.opStr.toLowerCase().split(',');
      if (parts.length >= 1 && parts[0].trim() === reg) {
        // mov reg, ... writes to reg
        if (mn === 'mov' || mn === 'lea' || mn === 'xor' || mn === 'sub') {
          written.add(reg);
        }
      }
    }
  }

  // Check for stack params beyond 4 (shadow space at [rsp+0x28] and beyond)
  const stackParamPattern = /\[rsp\s*\+\s*0x([0-9a-fA-F]+)\]/i;
  let extraStackParams = 0;
  for (let i = 0; i < scanLimit; i++) {
    const m = funcInsns[i].opStr.match(stackParamPattern);
    if (m) {
      const offset = parseInt(m[1], 16);
      if (offset >= 0x28) {
        const paramIdx = Math.floor((offset - 0x28) / 8) + 5;
        extraStackParams = Math.max(extraStackParams, paramIdx);
      }
    }
  }

  const paramCount = Math.max(maxParam, extraStackParams);
  return { convention: 'fastcall', paramCount };
}

function inferSignature32(funcInsns: Instruction[]): FunctionSignature {
  const last = funcInsns[funcInsns.length - 1];
  let convention = 'cdecl';
  let paramCount = 0;

  // Check for ret N -> stdcall
  if (last && (last.mnemonic === 'ret' || last.mnemonic === 'retn')) {
    const m = last.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (!m) {
      // Also check simple decimal
      const d = parseInt(last.opStr, 10);
      if (!isNaN(d) && d > 0) {
        convention = 'stdcall';
        paramCount = Math.floor(d / 4);
      }
    } else {
      const retBytes = parseInt(m[1], 16);
      if (retBytes > 0) {
        convention = 'stdcall';
        paramCount = Math.floor(retBytes / 4);
      }
    }
  }

  // Check ecx usage in first 10 insns -> thiscall
  const scanLimit = Math.min(funcInsns.length, 10);
  let ecxRead = false;
  let ecxWritten = false;
  for (let i = 0; i < scanLimit; i++) {
    const insn = funcInsns[i];
    if (!ecxWritten && isSourceOperand(insn.mnemonic, insn.opStr, 'ecx')) {
      ecxRead = true;
      break;
    }
    const parts = insn.opStr.toLowerCase().split(',');
    if (parts[0]?.trim() === 'ecx' && (insn.mnemonic === 'mov' || insn.mnemonic === 'xor')) {
      ecxWritten = true;
    }
  }
  if (ecxRead && convention !== 'stdcall') {
    convention = 'thiscall';
  }

  // Count [ebp+0x8+] stack param accesses if not already determined by ret N
  if (paramCount === 0) {
    const ebpParamPattern = /\[ebp\s*\+\s*0x([0-9a-fA-F]+)\]/i;
    let maxOffset = 0;
    for (const insn of funcInsns) {
      const m = insn.opStr.match(ebpParamPattern);
      if (m) {
        const offset = parseInt(m[1], 16);
        if (offset >= 0x8) {
          maxOffset = Math.max(maxOffset, offset);
        }
      }
    }
    if (maxOffset >= 0x8) {
      paramCount = Math.floor((maxOffset - 0x8) / 4) + 1;
    }
  }

  return { convention, paramCount };
}

export function inferSignature(
  func: DisasmFunction,
  instructions: Instruction[],
  is64: boolean
): FunctionSignature {
  const endAddr = func.address + func.size;
  const funcInsns: Instruction[] = [];
  for (const insn of instructions) {
    if (insn.address >= func.address && insn.address < endAddr) {
      funcInsns.push(insn);
    }
    if (insn.address >= endAddr) break;
  }

  if (funcInsns.length === 0) {
    return { convention: is64 ? 'fastcall' : 'cdecl', paramCount: 0 };
  }

  return is64 ? inferSignature64(funcInsns) : inferSignature32(funcInsns);
}
