import type { Instruction, DisasmFunction } from './types';
import { getFuncInsns } from './funcInsns';

export interface FunctionSignature {
  convention: string;
  paramCount: number;
}

const FASTCALL_REGS_64 = ['rcx', 'rdx', 'r8', 'r9'];

/**
 * Canonical 64-bit parent + width of a general-purpose register token.
 * Deliberately a local table rather than an import of `canonReg()` from
 * `decompile/ir.ts`: nothing else in the disassembly layer depends on the
 * decompiler, and that helper returns the token unchanged for non-registers,
 * which is not enough to tell `ptr` from `rdx` when scanning operand text.
 */
const LEGACY_REGS: Record<string, [canon: string, width: number]> = {
  rax: ['rax', 8], eax: ['rax', 4], ax: ['rax', 2], al: ['rax', 1], ah: ['rax', 1],
  rbx: ['rbx', 8], ebx: ['rbx', 4], bx: ['rbx', 2], bl: ['rbx', 1], bh: ['rbx', 1],
  rcx: ['rcx', 8], ecx: ['rcx', 4], cx: ['rcx', 2], cl: ['rcx', 1], ch: ['rcx', 1],
  rdx: ['rdx', 8], edx: ['rdx', 4], dx: ['rdx', 2], dl: ['rdx', 1], dh: ['rdx', 1],
  rsi: ['rsi', 8], esi: ['rsi', 4], si: ['rsi', 2], sil: ['rsi', 1],
  rdi: ['rdi', 8], edi: ['rdi', 4], di: ['rdi', 2], dil: ['rdi', 1],
  rbp: ['rbp', 8], ebp: ['rbp', 4], bp: ['rbp', 2], bpl: ['rbp', 1],
  rsp: ['rsp', 8], esp: ['rsp', 4], sp: ['rsp', 2], spl: ['rsp', 1],
};

const EXT_REG_RE = /^(r(?:[89]|1[0-5]))([bwd])?$/;
const EXT_WIDTHS: Record<string, number> = { b: 1, w: 2, d: 4 };

/** Canonical name + width of a register token, or null if it is not a register. */
function regInfo(token: string): { canon: string; width: number } | null {
  const t = token.toLowerCase();
  const ext = t.match(EXT_REG_RE);
  if (ext) return { canon: ext[1], width: ext[2] ? EXT_WIDTHS[ext[2]] : 8 };
  const legacy = LEGACY_REGS[t];
  return legacy ? { canon: legacy[0], width: legacy[1] } : null;
}

/** Whole-word tokens, so `r8d` matches r8 but `rdx` never matches `dx`. */
const TOKEN_RE = /\b[a-z][a-z0-9]*\b/g;

/** Every canonical register mentioned anywhere in a chunk of operand text. */
function canonRegsIn(text: string): string[] {
  const out: string[] = [];
  for (const m of text.toLowerCase().matchAll(TOKEN_RE)) {
    const info = regInfo(m[0]);
    if (info) out.push(info.canon);
  }
  return out;
}

// Destination is operand 0, remaining operands are pure sources.
const MOV_LIKE = new Set(['mov', 'movabs', 'movzx', 'movsx', 'movsxd', 'lea']);
// Every operand is a source; nothing is written.
const READ_ONLY = new Set(['cmp', 'test', 'push']);
// Operand 0 is read *and* written (except the 3-operand `imul` form).
const READ_MODIFY_WRITE = new Set([
  'add', 'sub', 'and', 'or', 'xor', 'adc', 'sbb',
  'shl', 'shr', 'sar', 'rol', 'ror', 'imul',
  'inc', 'dec', 'neg', 'not',
]);

interface RegEffects {
  /** Canonical registers read by the instruction. */
  reads: Set<string>;
  /** Canonical registers fully overwritten (32/64-bit destinations only). */
  writes: Set<string>;
}

/**
 * Split an instruction into the registers it reads and the ones it clobbers.
 * A destination register is only reported as written when the write kills the
 * whole register — an 8/16-bit write leaves the caller's upper bits intact, so
 * a later read of the parent is still partly a read of the incoming argument.
 */
function analyzeInsn(mnemonic: string, opStr: string): RegEffects {
  const reads = new Set<string>();
  const writes = new Set<string>();
  const mn = mnemonic.toLowerCase();

  const parts = opStr.split(',').map(p => p.trim()).filter(p => p.length > 0);
  if (parts.length === 0) return { reads, writes };

  const addReads = (text: string) => {
    for (const r of canonRegsIn(text)) reads.add(r);
  };

  const dest = parts[0];
  const destInfo = dest.includes('[') ? null : regInfo(dest);
  const addDestWrite = () => {
    if (destInfo && destInfo.width >= 4) writes.add(destInfo.canon);
  };
  const srcText = parts.slice(1).join(',');

  // Arguments are counted where they are set up, not at the call itself.
  if (mn === 'call') return { reads, writes };

  if (MOV_LIKE.has(mn)) {
    addReads(srcText);
    if (destInfo) addDestWrite();
    else addReads(dest); // memory destination: the address registers are read
    return { reads, writes };
  }

  if (READ_ONLY.has(mn)) {
    addReads(opStr);
    return { reads, writes };
  }

  if (mn === 'pop') {
    if (destInfo) addDestWrite();
    else addReads(dest);
    return { reads, writes };
  }

  if (READ_MODIFY_WRITE.has(mn)) {
    // `xor reg, reg` / `sub reg, reg` are zeroing idioms: they clobber the
    // register without reading anything meaningful out of it.
    const zeroingIdiom =
      (mn === 'xor' || mn === 'sub') &&
      parts.length === 2 &&
      destInfo !== null &&
      regInfo(parts[1])?.canon === destInfo.canon;

    if (!zeroingIdiom) addReads(srcText);
    if (destInfo) {
      // The 3-operand `imul dst, src, imm` form does not read its destination.
      if (!zeroingIdiom && parts.length < 3) reads.add(destInfo.canon);
      addDestWrite();
    } else {
      addReads(dest);
    }
    return { reads, writes };
  }

  // Unknown mnemonic: assume every operand is read, clobber nothing.
  addReads(opStr);
  return { reads, writes };
}

function inferSignature64(funcInsns: Instruction[]): FunctionSignature {
  // Windows x64 fastcall: RCX, RDX, R8, R9
  const scanLimit = Math.min(funcInsns.length, 20);
  const written = new Set<string>();
  let maxParam = 0;

  for (let i = 0; i < scanLimit; i++) {
    const insn = funcInsns[i];
    const { reads, writes } = analyzeInsn(insn.mnemonic, insn.opStr);

    // Reads are resolved against the state *before* the instruction, so a
    // register that is both read and written here still counts as a parameter.
    for (let pi = 0; pi < FASTCALL_REGS_64.length; pi++) {
      const reg = FASTCALL_REGS_64[pi];
      if (written.has(reg)) continue;
      if (reads.has(reg)) maxParam = Math.max(maxParam, pi + 1);
    }
    for (const w of writes) written.add(w);
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
      if (!Number.isNaN(d) && d > 0) {
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
  for (let i = 0; i < scanLimit; i++) {
    const insn = funcInsns[i];
    const { reads, writes } = analyzeInsn(insn.mnemonic, insn.opStr);
    if (reads.has('rcx')) {
      ecxRead = true;
      break;
    }
    // ECX defined locally before any read: it is not an incoming `this`.
    if (writes.has('rcx')) break;
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
  is64: boolean,
  funcInsnMap?: Map<number, Instruction[]>,
): FunctionSignature {
  const funcInsns = getFuncInsns(func, instructions, funcInsnMap);

  if (funcInsns.length === 0) {
    return { convention: is64 ? 'fastcall' : 'cdecl', paramCount: 0 };
  }

  return is64 ? inferSignature64(funcInsns) : inferSignature32(funcInsns);
}
