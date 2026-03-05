import type { Instruction } from '../types';
import type { BasicBlock } from '../cfg';
import type {
  IRExpr, IRStmt, IRCall, BinaryOp,
} from './ir';
import {
  irConst, irReg, irBinary, irUnary, irDeref, irUnknown, regSize, canonReg,
} from './ir';
import { RegState } from './regstate';

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
    case 'byte': return 1;
    case 'word': return 2;
    case 'dword': return 4;
    case 'qword': return 8;
  }
  return 0;
}

function isRegister(s: string): boolean {
  return regSize(s) > 0 || /^(rip|eip)$/i.test(s);
}

function parseImm(s: string): number | null {
  const trimmed = s.trim();
  const hexM = trimmed.match(HEX_PATTERN);
  if (hexM) {
    const v = parseInt(hexM[1], 16);
    return trimmed.startsWith('-') ? -v : v;
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
  const ripMatch = inside.match(/^rip\s*([+-])\s*0x([0-9a-fA-F]+)$/i);
  if (ripMatch) {
    const sign = ripMatch[1] === '+' ? 1 : -1;
    const disp = parseInt(ripMatch[2], 16);
    return irConst(insn.address + insn.size + sign * disp, is64 ? 8 : 4);
  }

  // Tokenize: split on + and - while preserving sign
  const tokens: { sign: number; text: string }[] = [];
  let buf = '';
  let sign = 1;
  for (let i = 0; i <= inside.length; i++) {
    const ch = inside[i];
    if (i === inside.length || ch === '+' || ch === '-') {
      const t = buf.trim();
      if (t) tokens.push({ sign, text: t });
      sign = ch === '-' ? -1 : 1;
      buf = '';
    } else {
      buf += ch;
    }
  }

  let result: IRExpr | null = null;
  const addExpr = (expr: IRExpr, s: number) => {
    if (!result) {
      result = s === -1 ? irUnary('-', expr) : expr;
    } else {
      result = s === -1 ? irBinary('-', result, expr) : irBinary('+', result, expr);
    }
  };

  for (const tok of tokens) {
    // reg*scale
    const scaleMatch = tok.text.match(/^(\w+)\s*\*\s*(\d+)$/i);
    if (scaleMatch && isRegister(scaleMatch[1])) {
      const reg = scaleMatch[1];
      const scale = parseInt(scaleMatch[2], 10);
      addExpr(irBinary('*', irReg(reg), irConst(scale)), tok.sign);
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
 */
export function parseOperand(op: string, insn: Instruction, is64: boolean, regState: RegState): IRExpr {
  const trimmed = op.trim();
  if (!trimmed) return irUnknown('');

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
    return regState.getOrReg(trimmed, regSize(trimmed));
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
  if (!trimmed) return irUnknown('');

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
  let buf = '';
  for (const ch of opStr) {
    if (ch === '[') depth++;
    if (ch === ']') depth--;
    if (ch === ',' && depth === 0) {
      parts.push(buf.trim());
      buf = '';
    } else {
      buf += ch;
    }
  }
  if (buf.trim()) parts.push(buf.trim());
  return parts;
}

// ── Core Lifter ──

const ARITH_OPS: Record<string, BinaryOp> = {
  add: '+', sub: '-', and: '&', or: '|', xor: '^',
  shl: '<<', sal: '<<', shr: '>>>', sar: '>>',
};

const COND_SET: Record<string, string> = {
  sete: 'je', setne: 'jne', setz: 'jz', setnz: 'jnz',
  setg: 'jg', setge: 'jge', setl: 'jl', setle: 'jle',
  seta: 'ja', setae: 'jae', setb: 'jb', setbe: 'jbe',
  sets: 'js', setns: 'jns',
};

const CMOV_PATTERN = /^cmov(\w+)$/;

const FASTCALL_REGS_64 = ['rcx', 'rdx', 'r8', 'r9'];

/**
 * Lift a single basic block's instructions to IR statements.
 */
export function liftBlock(
  block: BasicBlock,
  regState: RegState,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  stringMap: Map<number, string>,
  funcMap: Map<number, { name: string; address: number }>,
): IRStmt[] {
  const stmts: IRStmt[] = [];

  for (const insn of block.insns) {
    const mn = insn.mnemonic.toLowerCase();
    const parts = splitOperands(insn.opStr);

    // ── nop / int3 / ud2 ──
    if (mn === 'nop' || mn === 'int3' || mn === 'ud2') continue;

    // ── push / pop: handled implicitly, but we still track for x86 call args ──
    if (mn === 'push' || mn === 'pop') continue;

    // ── mov ──
    if (mn === 'mov') {
      if (parts.length < 2) { stmts.push({ kind: 'raw', text: `${mn} ${insn.opStr}`, addr: insn.address }); continue; }
      const dest = parseDestOperand(parts[0], insn, is64);
      const src = parseOperand(parts[1], insn, is64, regState);
      if (dest.kind === 'deref') {
        stmts.push({ kind: 'store', address: dest.address, value: src, size: dest.size, addr: insn.address });
      } else {
        stmts.push({ kind: 'assign', dest, src, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, src);
      }
      continue;
    }

    // ── movzx / movsx / movsxd → emit IRCast with type annotation ──
    if (mn === 'movzx' || mn === 'movsx' || mn === 'movsxd') {
      if (parts.length < 2) { stmts.push({ kind: 'raw', text: `${mn} ${insn.opStr}`, addr: insn.address }); continue; }
      const dest = parseDestOperand(parts[0], insn, is64);
      const srcRaw = parseOperand(parts[1], insn, is64, regState);
      // Determine source width from prefix or register size
      const srcSize = memPrefixSize(parts[1]) || (srcRaw.kind === 'reg' ? regSize(srcRaw.name) : (srcRaw.kind === 'deref' ? srcRaw.size : 4));
      const signed = mn === 'movsx' || mn === 'movsxd';
      const castType = signed
        ? (srcSize === 1 ? 'int8_t' : srcSize === 2 ? 'int16_t' : 'int32_t')
        : (srcSize === 1 ? 'uint8_t' : 'uint16_t');
      const src: IRExpr = { kind: 'cast', type: castType, operand: srcRaw };
      if (dest.kind === 'deref') {
        stmts.push({ kind: 'store', address: dest.address, value: src, size: dest.size, addr: insn.address });
      } else {
        stmts.push({ kind: 'assign', dest, src, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, src);
      }
      continue;
    }

    // ── lea ──
    if (mn === 'lea') {
      if (parts.length < 2) { stmts.push({ kind: 'raw', text: `${mn} ${insn.opStr}`, addr: insn.address }); continue; }
      const dest = parseDestOperand(parts[0], insn, is64);
      // For lea, the bracket content is the address expression (no deref)
      const bracketM = parts[1].match(BRACKET_PATTERN);
      let src: IRExpr;
      if (bracketM) {
        src = parseMemExpr(bracketM[1], insn, is64);
      } else {
        src = parseOperand(parts[1], insn, is64, regState);
      }
      stmts.push({ kind: 'assign', dest, src, addr: insn.address });
      if (dest.kind === 'reg') regState.set(dest.name, src);
      continue;
    }

    // ── xor reg, reg → zero idiom ──
    if (mn === 'xor' && parts.length >= 2) {
      const d = parts[0].trim().toLowerCase();
      const s = parts[1].trim().toLowerCase();
      if (d === s && isRegister(d)) {
        const dest = irReg(d);
        const zero = irConst(0, regSize(d));
        stmts.push({ kind: 'assign', dest, src: zero, addr: insn.address });
        regState.set(d, zero);
        continue;
      }
    }

    // ── Arithmetic: add/sub/and/or/xor/shl/shr/sar ──
    if (mn in ARITH_OPS) {
      if (parts.length < 2) { stmts.push({ kind: 'raw', text: `${mn} ${insn.opStr}`, addr: insn.address }); continue; }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64, regState);
      const src = parseOperand(parts[1], insn, is64, regState);
      const op = ARITH_OPS[mn];
      const result = irBinary(op, destVal, src);
      if (dest.kind === 'deref') {
        stmts.push({ kind: 'store', address: dest.address, value: result, size: dest.size, addr: insn.address });
      } else {
        stmts.push({ kind: 'assign', dest, src: result, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, result);
      }
      continue;
    }

    // ── imul ──
    if (mn === 'imul') {
      if (parts.length === 2) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const destVal = parseOperand(parts[0], insn, is64, regState);
        const src = parseOperand(parts[1], insn, is64, regState);
        const result = irBinary('*', destVal, src);
        stmts.push({ kind: 'assign', dest, src: result, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, result);
      } else if (parts.length >= 3) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const a = parseOperand(parts[1], insn, is64, regState);
        const b = parseOperand(parts[2], insn, is64, regState);
        const result = irBinary('*', a, b);
        stmts.push({ kind: 'assign', dest, src: result, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, result);
      } else {
        stmts.push({ kind: 'raw', text: `${mn} ${insn.opStr}`, addr: insn.address });
      }
      continue;
    }

    // ── inc / dec ──
    if (mn === 'inc' || mn === 'dec') {
      if (parts.length < 1) { stmts.push({ kind: 'raw', text: `${mn} ${insn.opStr}`, addr: insn.address }); continue; }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64, regState);
      const op: BinaryOp = mn === 'inc' ? '+' : '-';
      const result = irBinary(op, destVal, irConst(1));
      if (dest.kind === 'deref') {
        stmts.push({ kind: 'store', address: dest.address, value: result, size: dest.size, addr: insn.address });
      } else {
        stmts.push({ kind: 'assign', dest, src: result, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, result);
      }
      continue;
    }

    // ── not / neg ──
    if (mn === 'not' || mn === 'neg') {
      if (parts.length < 1) { stmts.push({ kind: 'raw', text: `${mn} ${insn.opStr}`, addr: insn.address }); continue; }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64, regState);
      const result = irUnary(mn === 'not' ? '~' : '-', destVal);
      if (dest.kind === 'deref') {
        stmts.push({ kind: 'store', address: dest.address, value: result, size: dest.size, addr: insn.address });
      } else {
        stmts.push({ kind: 'assign', dest, src: result, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, result);
      }
      continue;
    }

    // ── cmp / test → flag state only ──
    if (mn === 'cmp' || mn === 'test') {
      if (parts.length >= 2) {
        const left = parseOperand(parts[0], insn, is64, regState);
        const right = parseOperand(parts[1], insn, is64, regState);
        regState.setFlags(mn as 'cmp' | 'test', left, right);
      }
      continue;
    }

    // ── setXX ──
    if (mn in COND_SET) {
      if (parts.length >= 1) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const cond = regState.getCondition(COND_SET[mn]);
        stmts.push({ kind: 'assign', dest, src: cond, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, cond);
      }
      continue;
    }

    // ── cmovXX ──
    const cmovM = mn.match(CMOV_PATTERN);
    if (cmovM) {
      if (parts.length >= 2) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const destVal = parseOperand(parts[0], insn, is64, regState);
        const src = parseOperand(parts[1], insn, is64, regState);
        const jcc = 'j' + cmovM[1];
        const cond = regState.getCondition(jcc);
        const result: IRExpr = { kind: 'ternary', condition: cond, then: src, else: destVal };
        stmts.push({ kind: 'assign', dest, src: result, addr: insn.address });
        if (dest.kind === 'reg') regState.set(dest.name, result);
      }
      continue;
    }

    // ── call ──
    if (mn === 'call') {
      const target = resolveCallTarget(insn, is64, iatMap, funcMap);
      const args = is64
        ? collectArgs64(regState)
        : collectArgs32(block, insn, is64, regState);
      const call: IRCall = {
        kind: 'call',
        target: target.name,
        args,
        display: target.display,
      };
      const retReg = is64 ? 'rax' : 'eax';
      stmts.push({ kind: 'call_stmt', call, resultDest: irReg(retReg), addr: insn.address });
      regState.invalidateCallerSaved();
      regState.set(retReg, call);
      continue;
    }

    // ── ret / retn ──
    if (mn === 'ret' || mn === 'retn') {
      const retReg = is64 ? 'rax' : 'eax';
      const val = regState.get(retReg);
      stmts.push({ kind: 'return', value: val ?? irReg(retReg), addr: insn.address });
      continue;
    }

    // ── Conditional / unconditional jumps: handled at structure level ──
    if (mn === 'jmp' || mn.startsWith('j')) {
      continue;
    }

    // ── cdq / cdqe / cqo / cwde — sign-extend idioms ──
    if (mn === 'cdq' || mn === 'cdqe' || mn === 'cqo' || mn === 'cwde' || mn === 'cbw' || mn === 'cwd') {
      continue;
    }

    // ── xchg ──
    if (mn === 'xchg' && parts.length >= 2) {
      stmts.push({ kind: 'raw', text: `__asm { ${mn} ${insn.opStr} }`, addr: insn.address });
      continue;
    }

    // ── Everything else: FPU, SSE, AVX, etc. → raw asm ──
    stmts.push({ kind: 'raw', text: `__asm { ${mn} ${insn.opStr} }`, addr: insn.address });
  }

  return stmts;
}

// ── Call Target Resolution ──

function resolveCallTarget(
  insn: Instruction,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  funcMap: Map<number, { name: string; address: number }>,
): { name: string; display?: string } {
  const opStr = insn.opStr.trim();

  // Direct call: `call 0xNNNN`
  const directM = opStr.match(/^0x([0-9a-fA-F]+)$/);
  if (directM) {
    const addr = parseInt(directM[1], 16);
    const fn = funcMap.get(addr);
    if (fn) return { name: fn.name };
    return { name: `sub_${addr.toString(16).toUpperCase()}` };
  }

  // RIP-relative: `call qword ptr [rip + 0xNNNN]`
  const ripM = opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/i);
  if (ripM) {
    const sign = ripM[1] === '+' ? 1 : -1;
    const disp = parseInt(ripM[2], 16);
    const target = insn.address + insn.size + sign * disp;
    const iat = iatMap.get(target);
    if (iat) return { name: iat.func, display: `${iat.lib}!${iat.func}` };
    const fn = funcMap.get(target);
    if (fn) return { name: fn.name };
    return { name: `sub_${target.toString(16).toUpperCase()}` };
  }

  // Direct address in brackets: `call dword ptr [0xNNNN]`
  const addrM = opStr.match(/\[\s*0x([0-9a-fA-F]+)\s*\]/);
  if (addrM) {
    const target = parseInt(addrM[1], 16);
    const iat = iatMap.get(target);
    if (iat) return { name: iat.func, display: `${iat.lib}!${iat.func}` };
    return { name: `sub_${target.toString(16).toUpperCase()}` };
  }

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

function collectArgs64(regState: RegState): IRExpr[] {
  const args: IRExpr[] = [];
  for (const reg of FASTCALL_REGS_64) {
    const val = regState.get(reg);
    if (val) args.push(val);
    else break; // stop at first missing param
  }
  return args;
}

function collectArgs32(
  block: BasicBlock,
  callInsn: Instruction,
  is64: boolean,
  regState: RegState,
): IRExpr[] {
  // Scan backwards from call for consecutive push instructions
  const args: IRExpr[] = [];
  const insns = block.insns;
  let callIdx = -1;
  for (let i = insns.length - 1; i >= 0; i--) {
    if (insns[i].address === callInsn.address) { callIdx = i; break; }
  }
  if (callIdx < 0) return args;

  for (let i = callIdx - 1; i >= 0 && args.length < 8; i--) {
    if (insns[i].mnemonic !== 'push') break;
    const op = insns[i].opStr.trim();
    args.push(parseOperand(op, insns[i], is64, regState));
  }
  // push order is reverse of arg order
  args.reverse();
  return args;
}
