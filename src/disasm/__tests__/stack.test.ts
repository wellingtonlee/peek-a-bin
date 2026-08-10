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

/** The canonical frame-pointer prologue, which is what makes `[fp + N]` an argument slot. */
const PROLOGUE_64: [string, string][] = [['push', 'rbp'], ['mov', 'rbp, rsp']];
const PROLOGUE_32: [string, string][] = [['push', 'ebp'], ['mov', 'ebp, esp']];

/** Names of the parameter slots, in frame order. */
function argNames(frame: { vars: { name: string }[] } | null): string[] {
  return frame!.vars.map(v => v.name).filter(n => n.startsWith('arg_'));
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
      ...PROLOGUE_64,
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
      ...PROLOGUE_64,
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

// The N in `arg_N` used to be a running counter over the slots the function was
// observed to touch, so it encoded the order the arguments happened to be
// referenced in rather than their position. It is now derived from the offset.
describe('analyzeStackFrame — argument numbering', () => {
  it('numbers a 32-bit argument by its offset, not by the order it was touched', () => {
    // The function never reads its first argument. The counter called this one
    // arg_0; it is [ebp+0xC], the second argument.
    const insns = body(
      ...PROLOGUE_32,
      ['mov', 'eax, dword ptr [ebp + 0xC]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(['arg_1']);
  });

  it('leaves a gap for an argument the function never touches', () => {
    // Arguments 0 and 2 are read, 1 is not. The counter renumbered argument 2
    // as arg_1, quietly moving it into the untouched argument's position.
    const insns = body(
      ...PROLOGUE_32,
      ['mov', 'eax, dword ptr [ebp + 0x8]'],
      ['mov', 'ecx, dword ptr [ebp + 0x10]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(['arg_0', 'arg_2']);
  });

  it('maps an x64 home slot to the index of the register that owns it', () => {
    // A Win64 caller allocates 32 bytes of shadow space, so [rbp+0x10] through
    // [rbp+0x28] are the home slots of arguments 0-3 — the ones that arrive in
    // RCX/RDX/R8/R9. A spilled argument therefore gets the same index whether
    // it is reached through its register or through its slot. Two slots, not
    // four, so the numbering cannot coincide with a running counter.
    const insns = body(
      ...PROLOGUE_64,
      ['mov', 'rax, qword ptr [rbp + 0x18]'],
      ['mov', 'rcx, qword ptr [rbp + 0x28]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual(['arg_1', 'arg_3']);
  });

  it('numbers the fifth x64 argument past the shadow space', () => {
    // The first argument with no register sits above the four home slots, at
    // [rbp+0x30], and is argument 4. This is where an off-by-shadow-space error
    // would surface: read as the *first* stack argument it would be numbered 0
    // and collide with RCX, linking the fifth argument to the first.
    const insns = body(
      ...PROLOGUE_64,
      ['mov', 'rax, qword ptr [rbp + 0x10]'],
      ['mov', 'rcx, qword ptr [rbp + 0x30]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual(['arg_0', 'arg_4']);
  });

  it('numbers each slot of a multi-slot argument separately', () => {
    // A 32-bit int64 argument occupies [ebp+0x8] and [ebp+0xC], so its high
    // half is numbered arg_1 and a following argument would be arg_2. Pinned
    // because it is a known imprecision, not an accident: the caller side
    // counts the same slots (an int64 is two pushes), so the two indices still
    // agree with each other even though both differ from the source-level
    // argument position.
    const insns = body(
      ...PROLOGUE_32,
      ['mov', 'eax, dword ptr [ebp + 0x8]'],
      ['mov', 'edx, dword ptr [ebp + 0xC]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(['arg_0', 'arg_1']);
  });

  it('names a sub-slot access by offset rather than rounding it into a neighbour', () => {
    // [ebp+0xA] is the third byte of argument 0. It divides into no argument
    // index, so it does not get one.
    const insns = body(
      ...PROLOGUE_32,
      ['mov', 'al, byte ptr [ebp + 0xA]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(['arg_0xA']);
  });
});

// An index can only be read out of the offset if the frame pointer is really a
// frame pointer. In x64 code RBP is more often a callee-saved object pointer,
// and `[rbp + 0x10]` is then a field of that object, not an argument.
describe('analyzeStackFrame — frame-pointer verification', () => {
  it('does not number slots of a function with no frame-pointer prologue', () => {
    const insns = body(
      ['sub', 'rsp, 0x28'],
      ['mov', 'rax, qword ptr [rbp + 0x10]'],
      ['mov', 'rcx, qword ptr [rbp + 0x18]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true)))
      .toEqual(['arg_0x10', 'arg_0x18']);
  });

  it('does not number slots of a frame established with lea', () => {
    // `lea rbp, [rsp + 0x20]` shifts every argument offset by 0x20, so the
    // offsets mean something — just not what the standard prologue makes them
    // mean.
    const insns = body(
      ['push', 'rbp'],
      ['lea', 'rbp, [rsp + 0x20]'],
      ['mov', 'rax, qword ptr [rbp + 0x10]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual(['arg_0x10']);
  });

  it('does not number slots when a register is pushed before the frame pointer', () => {
    // `push ebx` before `push ebp` puts the saved EBX where the return address
    // would otherwise be, shifting the whole argument area by one slot.
    const insns = body(
      ['push', 'ebx'],
      ...PROLOGUE_32,
      ['mov', 'eax, dword ptr [ebp + 0x8]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(['arg_0x8']);
  });

  it('sees through hot-patch padding before the prologue', () => {
    // `mov edi, edi` is MSVC's hot-patch pad and is not part of the frame.
    const insns = body(
      ['mov', 'edi, edi'],
      ...PROLOGUE_32,
      ['mov', 'eax, dword ptr [ebp + 0x8]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(['arg_0']);
  });

  it('does not mistake a push of another register for the frame-pointer push', () => {
    const insns = body(
      ['push', 'esi'],
      ['mov', 'ebp, esp'],
      ['mov', 'eax, dword ptr [ebp + 0x8]'],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(['arg_0x8']);
  });
});
