import { describe, it, expect } from 'vitest';
import { analyzeStackFrame, stackVarKey } from '../stack';
import type { DisasmFunction, Instruction } from '../types';

// ── Helpers ──

function insn(address: number, mnemonic: string, opStr: string): Instruction {
  return { address, bytes: new Uint8Array(), mnemonic, opStr, size: 4 };
}

function func(size: number): DisasmFunction {
  return { name: 'sub_1000', address: 0x1000, size };
}

/** Build instructions at consecutive addresses starting at the function entry. */
function body(...ops: [string, string][]): Instruction[] {
  return ops.map(([mn, op], i) => insn(0x1000 + i * 4, mn, op));
}

// ── Tests ──

describe('analyzeStackFrame — slot identity', () => {
  it('keeps [rbp - 0x10] and [rsp + 0x10] as separate variables', () => {
    // Same numeric offset, different base register → two distinct stack slots.
    // Keying the internal map on the bare offset merged them into one entry
    // with a combined size and access count.
    const insns = body(
      ['mov', 'dword ptr [rbp - 0x10], eax'],
      ['mov', 'dword ptr [rbp - 0x10], ecx'],
      ['mov', 'qword ptr [rsp + 0x10], rdx'],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame).not.toBeNull();

    const at10 = frame!.vars.filter(v => v.offset === 0x10);
    expect(at10).toHaveLength(2);

    const bp = at10.find(v => v.key === stackVarKey('bp', -0x10));
    const sp = at10.find(v => v.key === stackVarKey('sp', 0x10));
    expect(bp).toBeDefined();
    expect(sp).toBeDefined();

    // Sizes stay independent: the 8-byte rsp access must not widen the
    // 4-byte rbp local.
    expect(bp!.size).toBe(4);
    expect(sp!.size).toBe(8);

    // Access counts stay independent too.
    expect(bp!.accessCount).toBe(2);
    expect(sp!.accessCount).toBe(1);

    // ...and the two slots get distinct names.
    expect(bp!.name).not.toBe(sp!.name);
  });

  it('does not let a [rbp + 0x10] param absorb a [rsp + 0x10] local', () => {
    // The param branch ran first for [rbp + N] and set isParam, so a later
    // [rsp + N] access with the same offset inherited "param" and vanished
    // into arg_0.
    const insns = body(
      ['mov', 'eax, dword ptr [rbp + 0x10]'],
      ['mov', 'dword ptr [rsp + 0x10], ecx'],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame).not.toBeNull();

    const names = frame!.vars.map(v => v.name);
    expect(names).toContain('arg_0');
    // The rsp slot is a local, not part of the parameter list.
    const spVar = frame!.vars.find(v => v.key === stackVarKey('sp', 0x10));
    expect(spVar).toBeDefined();
    expect(spVar!.name).not.toMatch(/^arg_/);
    expect(frame!.vars.filter(v => v.name.startsWith('arg_'))).toHaveLength(1);
  });

  it('still merges repeated accesses to the same slot', () => {
    const insns = body(
      ['mov', 'byte ptr [rbp - 0x8], al'],
      ['mov', 'dword ptr [rbp - 0x8], eax'],
      ['mov', 'dword ptr [rbp - 0x8], ecx'],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    const v = frame!.vars.find(x => x.key === stackVarKey('bp', -0x8));
    expect(v).toBeDefined();
    expect(v!.accessCount).toBe(3);
    expect(v!.size).toBe(4); // widest access wins
    expect(frame!.vars).toHaveLength(1);
  });

  it('names and orders unambiguous frames exactly as before', () => {
    const insns = body(
      ['sub', 'rsp, 0x28'],
      ['mov', 'dword ptr [rbp - 0x4], eax'],
      ['mov', 'dword ptr [rbp - 0x8], ecx'],
      ['mov', 'eax, dword ptr [rbp + 0x10]'],
      ['mov', 'ecx, dword ptr [rbp + 0x18]'],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame!.frameSize).toBe(0x28);
    expect(frame!.vars.map(v => v.name)).toEqual(['var_4', 'var_8', 'arg_0', 'arg_1']);
  });

  it('handles 32-bit ebp/esp bases', () => {
    const insns = body(
      ['mov', 'dword ptr [ebp - 0xC], eax'],
      ['mov', 'dword ptr [esp + 0xC], ecx'],
      ['mov', 'eax, dword ptr [ebp + 0x8]'],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, false);
    const keys = frame!.vars.map(v => v.key);
    expect(keys).toContain(stackVarKey('bp', -0xC));
    expect(keys).toContain(stackVarKey('sp', 0xC));
    expect(keys).toContain(stackVarKey('bp', 0x8));
    expect(frame!.vars).toHaveLength(3);
  });
});
