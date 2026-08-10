import { describe, it, expect } from 'vitest';
import { inferSignature } from '../signatures';
import type { Instruction, DisasmFunction } from '../types';

const START = 0x401000;
const INSN_SIZE = 4;

function makeInsns(start: number, list: [string, string][]): Instruction[] {
  return list.map(([mnemonic, opStr], i) => ({
    address: start + i * INSN_SIZE,
    mnemonic,
    opStr,
    size: INSN_SIZE,
    bytes: new Uint8Array(INSN_SIZE),
  }));
}

function func(address: number, insnCount: number): DisasmFunction {
  return { name: 'f', address, size: insnCount * INSN_SIZE };
}

function sig(list: [string, string][], is64: boolean) {
  return inferSignature(func(START, list.length), makeInsns(START, list), is64);
}

const sig64 = (list: [string, string][]) => sig(list, true);
const sig32 = (list: [string, string][]) => sig(list, false);

const nop: [string, string] = ['nop', ''];

describe('inferSignature — x64 (Windows fastcall)', () => {
  it('always reports the fastcall convention', () => {
    expect(sig64([['ret', '']]).convention).toBe('fastcall');
  });

  it('counts a read of rcx as one parameter', () => {
    expect(sig64([['mov', 'rax, rcx'], ['ret', '']]).paramCount).toBe(1);
  });

  it('counts a read of rdx as two parameters', () => {
    // RCX is param 1, RDX is param 2 — reading RDX implies RCX is used too.
    expect(sig64([['mov', 'rax, rdx'], ['ret', '']]).paramCount).toBe(2);
  });

  it('infers four parameters from a read of r9', () => {
    expect(sig64([['mov', 'rax, r9'], ['ret', '']]).paramCount).toBe(4);
  });

  it('takes the highest register index read, not the count of reads', () => {
    const s = sig64([
      ['mov', 'rax, r8'],
      ['add', 'rax, rcx'],
      ['ret', ''],
    ]);
    expect(s.paramCount).toBe(3);
  });

  it('ignores a read that happens after the register was overwritten', () => {
    // `mov rcx, 0x10` defines RCX locally, so the later read is not a parameter.
    const s = sig64([
      ['mov', 'rcx, 0x10'],
      ['mov', 'rax, rcx'],
      ['ret', ''],
    ]);
    expect(s.paramCount).toBe(0);
  });

  it('does not count the destination of a mov as a read', () => {
    expect(sig64([['mov', 'rcx, rax'], ['ret', '']]).paramCount).toBe(0);
  });

  it('counts both operands of a cmp as reads', () => {
    expect(sig64([['cmp', 'rdx, 0x0'], ['ret', '']]).paramCount).toBe(2);
  });

  it('counts a pushed argument register as a read', () => {
    expect(sig64([['push', 'rcx'], ['ret', '']]).paramCount).toBe(1);
  });

  it('counts a memory dereference through an argument register', () => {
    expect(sig64([['mov', 'eax, dword ptr [rcx + 0x8]'], ['ret', '']]).paramCount).toBe(1);
  });

  describe('stack parameters', () => {
    it('reads [rsp+0x28] as the fifth parameter', () => {
      // 0x00–0x20 is the x64 shadow space + return address; 0x28 is arg 5.
      expect(sig64([['mov', 'rax, qword ptr [rsp + 0x28]'], ['ret', '']]).paramCount).toBe(5);
    });

    it('reads [rsp+0x30] as the sixth parameter', () => {
      expect(sig64([['mov', 'rax, qword ptr [rsp + 0x30]'], ['ret', '']]).paramCount).toBe(6);
    });

    it('ignores accesses inside the shadow space', () => {
      expect(sig64([['mov', 'qword ptr [rsp + 0x20], rax'], ['ret', '']]).paramCount).toBe(0);
    });

    it('takes the deepest stack access', () => {
      const s = sig64([
        ['mov', 'rax, qword ptr [rsp + 0x38]'],
        ['mov', 'rbx, qword ptr [rsp + 0x28]'],
        ['ret', ''],
      ]);
      expect(s.paramCount).toBe(7);
    });

    it('combines register and stack parameters by taking the max', () => {
      const s = sig64([
        ['mov', 'rax, rcx'],
        ['mov', 'rbx, qword ptr [rsp + 0x28]'],
        ['ret', ''],
      ]);
      expect(s.paramCount).toBe(5);
    });
  });

  describe('scan window', () => {
    it('sees a read at instruction 19', () => {
      const s = sig64([...Array(19).fill(nop), ['mov', 'rax, rcx'], ['ret', '']]);
      expect(s.paramCount).toBe(1);
    });

    it('stops after 20 instructions', () => {
      const s = sig64([...Array(20).fill(nop), ['mov', 'rax, rcx'], ['ret', '']]);
      expect(s.paramCount).toBe(0);
    });
  });

  it('returns a zero-parameter fastcall for a function with no instructions', () => {
    expect(inferSignature(func(START, 4), [], true)).toEqual({ convention: 'fastcall', paramCount: 0 });
  });

  it('only considers instructions inside the function range', () => {
    // A neighbouring function reads RCX; ours does not.
    const insns = makeInsns(START, [
      ['mov', 'rax, rcx'], // belongs to the previous function
      ['ret', ''],
      ['xor', 'eax, eax'], // our function starts here
      ['ret', ''],
      ['mov', 'rax, r9'], // belongs to the next function
    ]);
    const ours: DisasmFunction = { name: 'f', address: START + 2 * INSN_SIZE, size: 2 * INSN_SIZE };
    expect(inferSignature(ours, insns, true).paramCount).toBe(0);
  });

  // KNOWN BUG (reported, not fixed here): `xor rcx, rcx` is a zeroing idiom, not a
  // parameter read, but isSourceOperand() falls through to a substring match for
  // non-mov mnemonics and reports a read before the write is recorded.
  it('miscounts the `xor rcx, rcx` zeroing idiom as a parameter', () => {
    expect(sig64([['xor', 'rcx, rcx'], ['ret', '']]).paramCount).toBe(1);
  });

  // KNOWN BUG (reported): only the 64-bit register names are matched, so 32-bit
  // sub-registers of RCX/RDX are invisible while r8d/r9d match by substring.
  it('does not see edx as a parameter but does see r8d', () => {
    expect(sig64([['mov', 'eax, edx'], ['ret', '']]).paramCount).toBe(0);
    expect(sig64([['mov', 'eax, r8d'], ['ret', '']]).paramCount).toBe(3);
  });
});

describe('inferSignature — x86', () => {
  it('defaults to cdecl with no parameters', () => {
    expect(sig32([['xor', 'eax, eax'], ['ret', '']])).toEqual({ convention: 'cdecl', paramCount: 0 });
  });

  describe('stdcall detection', () => {
    it('reads `ret 0xc` as stdcall with three parameters', () => {
      expect(sig32([['xor', 'eax, eax'], ['ret', '0xc']])).toEqual({
        convention: 'stdcall',
        paramCount: 3,
      });
    });

    it('accepts the retn spelling', () => {
      expect(sig32([['retn', '0x8']])).toEqual({ convention: 'stdcall', paramCount: 2 });
    });

    it('accepts a decimal operand', () => {
      expect(sig32([['ret', '16']])).toEqual({ convention: 'stdcall', paramCount: 4 });
    });

    it('leaves `ret 0x0` as cdecl', () => {
      expect(sig32([['ret', '0x0']]).convention).toBe('cdecl');
    });

    it('leaves a bare ret as cdecl', () => {
      expect(sig32([['ret', '']]).convention).toBe('cdecl');
    });

    it('ignores a `ret N` that is not the last instruction of the function', () => {
      // Early-out returns are common; only the final instruction is inspected.
      expect(sig32([['ret', '0x8'], ['xor', 'eax, eax'], ['ret', '']]).convention).toBe('cdecl');
    });
  });

  describe('ebp-relative parameter counting', () => {
    it('counts [ebp+0x8] as one parameter', () => {
      expect(sig32([['mov', 'eax, dword ptr [ebp + 0x8]'], ['ret', '']]).paramCount).toBe(1);
    });

    it('counts [ebp+0x10] as three parameters', () => {
      expect(sig32([['mov', 'eax, dword ptr [ebp + 0x10]'], ['ret', '']]).paramCount).toBe(3);
    });

    it('takes the deepest offset, not the number of accesses', () => {
      const s = sig32([
        ['mov', 'eax, dword ptr [ebp + 0xc]'],
        ['mov', 'ebx, dword ptr [ebp + 0x8]'],
        ['ret', ''],
      ]);
      expect(s.paramCount).toBe(2);
    });

    it('ignores negative offsets (locals)', () => {
      expect(sig32([['mov', 'dword ptr [ebp - 0x8], eax'], ['ret', '']]).paramCount).toBe(0);
    });

    it('scans the whole function, not just the prologue', () => {
      const s = sig32([...Array(30).fill(nop), ['mov', 'eax, dword ptr [ebp + 0x8]'], ['ret', '']]);
      expect(s.paramCount).toBe(1);
    });

    it('lets `ret N` win over the ebp scan', () => {
      const s = sig32([['mov', 'eax, dword ptr [ebp + 0x10]'], ['ret', '0x8']]);
      expect(s).toEqual({ convention: 'stdcall', paramCount: 2 });
    });
  });

  describe('thiscall detection', () => {
    it('reports thiscall when ecx is read before being written', () => {
      const s = sig32([['mov', 'eax, dword ptr [ecx + 0x4]'], ['ret', '']]);
      expect(s.convention).toBe('thiscall');
    });

    it('does not report thiscall when ecx is written first', () => {
      const s = sig32([
        ['mov', 'ecx, 0x5'],
        ['mov', 'eax, dword ptr [ecx]'],
        ['ret', ''],
      ]);
      expect(s.convention).toBe('cdecl');
    });

    it('keeps stdcall when a `ret N` is also present', () => {
      const s = sig32([['mov', 'eax, dword ptr [ecx + 0x4]'], ['ret', '0x8']]);
      expect(s).toEqual({ convention: 'stdcall', paramCount: 2 });
    });

    it('only scans the first ten instructions for the ecx read', () => {
      const early = sig32([...Array(9).fill(nop), ['mov', 'eax, dword ptr [ecx]'], ['ret', '']]);
      expect(early.convention).toBe('thiscall');
      const late = sig32([...Array(10).fill(nop), ['mov', 'eax, dword ptr [ecx]'], ['ret', '']]);
      expect(late.convention).toBe('cdecl');
    });

    it('combines thiscall with ebp-relative parameters', () => {
      const s = sig32([
        ['mov', 'eax, dword ptr [ecx + 0x4]'],
        ['mov', 'ebx, dword ptr [ebp + 0x8]'],
        ['ret', ''],
      ]);
      expect(s).toEqual({ convention: 'thiscall', paramCount: 1 });
    });
  });

  it('returns a zero-parameter cdecl for a function with no instructions', () => {
    expect(inferSignature(func(START, 4), [], false)).toEqual({ convention: 'cdecl', paramCount: 0 });
  });
});
