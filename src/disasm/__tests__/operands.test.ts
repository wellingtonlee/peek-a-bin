import { describe, it, expect } from 'vitest';
import { parseOperandTargets, buildIATLookup } from '../operands';
import type { Instruction } from '../types';
import type { ImportEntry } from '../../pe/types';

/** Typical x64 PE layout used by most cases below. */
const BASE = 0x140000000;
const END = 0x140010000;

function insn(address: number, mnemonic: string, opStr: string, size = 5): Instruction {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

function iat(entries: [number, string, string][]) {
  return new Map(entries.map(([addr, lib, func]) => [addr, { lib, func }]));
}

describe('parseOperandTargets', () => {
  describe('direct branches', () => {
    it('resolves a direct call inside the image', () => {
      const targets = parseOperandTargets(insn(0x140001000, 'call', '0x140002000'), BASE, END);
      expect(targets).toEqual([{ address: 0x140002000, display: undefined }]);
    });

    it('drops a direct call outside the image', () => {
      // A call into a runtime-resolved address (e.g. a stub in ntdll) is not ours.
      const targets = parseOperandTargets(insn(0x140001000, 'call', '0x7ffe0300'), BASE, END);
      expect(targets).toEqual([]);
    });

    it('resolves a direct unconditional jmp', () => {
      const targets = parseOperandTargets(insn(0x140001000, 'jmp', '0x140001080'), BASE, END);
      expect(targets.map(t => t.address)).toEqual([0x140001080]);
    });

    it('resolves conditional jumps (any j* mnemonic)', () => {
      for (const mn of ['je', 'jne', 'jbe', 'jnle', 'jrcxz']) {
        const targets = parseOperandTargets(insn(0x140001000, mn, '0x140001040'), BASE, END);
        expect(targets.map(t => t.address), mn).toEqual([0x140001040]);
      }
    });

    it('treats imageBase as inclusive and imageEnd as exclusive', () => {
      expect(parseOperandTargets(insn(0x140001000, 'call', '0x140000000'), BASE, END)).toHaveLength(1);
      expect(parseOperandTargets(insn(0x140001000, 'call', '0x140010000'), BASE, END)).toHaveLength(0);
      expect(parseOperandTargets(insn(0x140001000, 'call', '0x13fffffff'), BASE, END)).toHaveLength(0);
    });
  });

  describe('RIP-relative operands', () => {
    it('resolves [rip + disp] relative to the END of the instruction', () => {
      // 48 8b 05 <disp32>: mov rax, [rip + 0x2000] at 0x140001000, 7 bytes
      // → 0x140001007 + 0x2000 = 0x140003007
      const targets = parseOperandTargets(
        insn(0x140001000, 'mov', 'rax, qword ptr [rip + 0x2000]', 7),
        BASE,
        END,
      );
      expect(targets.map(t => t.address)).toEqual([0x140003007]);
    });

    it('resolves [rip - disp] backwards', () => {
      const targets = parseOperandTargets(
        insn(0x140005000, 'lea', 'rcx, [rip - 0x1000]', 7),
        BASE,
        END,
      );
      expect(targets.map(t => t.address)).toEqual([0x140004007]);
    });

    it('drops a RIP-relative target that lands outside the image', () => {
      const targets = parseOperandTargets(
        insn(0x14000f000, 'mov', 'rax, qword ptr [rip + 0x20000]', 7),
        BASE,
        END,
      );
      expect(targets).toEqual([]);
    });

    it('annotates an indirect IAT call with the import name', () => {
      // The canonical x64 import call: call qword ptr [rip + disp] → IAT slot.
      // 6 bytes at 0x140001000, disp 0x8ff2 → 0x140001006 + 0x8ff2 = 0x140009ff8
      const targets = parseOperandTargets(
        insn(0x140001000, 'call', 'qword ptr [rip + 0x8ff2]', 6),
        BASE,
        END,
        iat([[0x140009ff8, 'kernel32.dll', 'CreateFileW']]),
      );
      expect(targets).toEqual([{ address: 0x140009ff8, display: 'kernel32.dll!CreateFileW' }]);
    });

    // Regression: the displacement was being re-scanned by the absolute-hex
    // pass and reported as an address of its own. Realistic x64 bases hide it
    // (the displacement sorts below imageBase), a low base does not.
    it('reports one target for [rip + disp] even when disp falls inside a low image', () => {
      const LOW = 0x1000;
      const LOW_END = 0x40000;
      // 0x2000 + 7 + 0x2000 = 0x4007; the raw disp 0x2000 is also in range.
      const targets = parseOperandTargets(
        insn(0x2000, 'mov', 'rax, qword ptr [rip + 0x2000]', 7),
        LOW,
        LOW_END,
      );
      expect(targets.map(t => t.address)).toEqual([0x4007]);
    });

    it('does not report a negative displacement that falls inside a low image', () => {
      const targets = parseOperandTargets(
        insn(0x8000, 'lea', 'rcx, [rip - 0x2000]', 7),
        0x1000,
        0x40000,
      );
      expect(targets.map(t => t.address)).toEqual([0x6007]);
    });

    it('still reports an immediate stored through a RIP-relative address', () => {
      // mov dword ptr [rip + 0x100], 0x3000 — the immediate sits outside the
      // RIP span, so it remains a genuine second target.
      const targets = parseOperandTargets(
        insn(0x2000, 'mov', 'dword ptr [rip + 0x100], 0x3000', 10),
        0x1000,
        0x40000,
      );
      expect(targets.map(t => t.address)).toEqual([0x210a, 0x3000]);
    });

    it('leaves display undefined when the target is not an IAT slot', () => {
      const targets = parseOperandTargets(
        insn(0x140001000, 'call', 'qword ptr [rip + 0x8ff2]', 6),
        BASE,
        END,
        iat([[0x140001234, 'kernel32.dll', 'CreateFileW']]),
      );
      expect(targets).toEqual([{ address: 0x140009ff8, display: undefined }]);
    });
  });

  describe('absolute operands', () => {
    const B32 = 0x400000;
    const E32 = 0x410000;

    it('resolves an absolute memory reference', () => {
      const targets = parseOperandTargets(insn(0x401000, 'mov', 'eax, dword ptr [0x404000]'), B32, E32);
      expect(targets.map(t => t.address)).toEqual([0x404000]);
    });

    it('resolves an immediate that happens to be an image address', () => {
      // push offset g_string — very common in x86 code.
      const targets = parseOperandTargets(insn(0x401000, 'push', '0x407120'), B32, E32);
      expect(targets.map(t => t.address)).toEqual([0x407120]);
    });

    it('returns every in-range hex operand, in operand order', () => {
      const targets = parseOperandTargets(
        insn(0x401000, 'mov', 'dword ptr [0x405000], 0x406000'),
        B32,
        E32,
      );
      expect(targets.map(t => t.address)).toEqual([0x405000, 0x406000]);
    });

    it('deduplicates a repeated address', () => {
      const targets = parseOperandTargets(
        insn(0x401000, 'mov', 'dword ptr [0x405000], 0x405000'),
        B32,
        E32,
      );
      expect(targets.map(t => t.address)).toEqual([0x405000]);
    });

    it('ignores small immediates and displacements below the image base', () => {
      expect(parseOperandTargets(insn(0x401000, 'add', 'esp, 0x10'), B32, E32)).toEqual([]);
      expect(parseOperandTargets(insn(0x401000, 'mov', 'eax, dword ptr [ebp - 0x8]'), B32, E32)).toEqual([]);
    });

    it('returns nothing for register-only operands', () => {
      expect(parseOperandTargets(insn(0x401000, 'mov', 'eax, ebx'), B32, E32)).toEqual([]);
      expect(parseOperandTargets(insn(0x401000, 'ret', ''), B32, E32)).toEqual([]);
    });

    it('annotates an x86 indirect IAT call', () => {
      const targets = parseOperandTargets(
        insn(0x401000, 'call', 'dword ptr [0x403010]'),
        B32,
        E32,
        iat([[0x403010, 'user32.dll', 'MessageBoxA']]),
      );
      expect(targets).toEqual([{ address: 0x403010, display: 'user32.dll!MessageBoxA' }]);
    });

    it('parses uppercase hex digits', () => {
      const targets = parseOperandTargets(insn(0x401000, 'mov', 'eax, dword ptr [0x40ABCD]'), B32, E32);
      expect(targets.map(t => t.address)).toEqual([0x40abcd]);
    });
  });
});

describe('buildIATLookup', () => {
  const entry = (libraryName: string, functions: string[], iatAddresses: number[]): ImportEntry => ({
    libraryName,
    functions,
    iatAddresses,
  });

  it('pairs each function with the IAT slot at the same index', () => {
    const map = buildIATLookup([
      entry('kernel32.dll', ['CreateFileW', 'CloseHandle'], [0x403000, 0x403008]),
    ]);
    expect(map.get(0x403000)).toEqual({ lib: 'kernel32.dll', func: 'CreateFileW' });
    expect(map.get(0x403008)).toEqual({ lib: 'kernel32.dll', func: 'CloseHandle' });
    expect(map.size).toBe(2);
  });

  it('merges multiple libraries', () => {
    const map = buildIATLookup([
      entry('kernel32.dll', ['Sleep'], [0x403000]),
      entry('user32.dll', ['MessageBoxA'], [0x404000]),
    ]);
    expect(map.size).toBe(2);
    expect(map.get(0x404000)?.lib).toBe('user32.dll');
  });

  it('skips functions with no matching IAT address', () => {
    // Ordinal-only or truncated imports can leave the arrays unbalanced.
    const map = buildIATLookup([entry('kernel32.dll', ['A', 'B', 'C'], [0x403000])]);
    expect(map.size).toBe(1);
    expect(map.get(0x403000)?.func).toBe('A');
  });

  it('ignores IAT addresses beyond the function list', () => {
    const map = buildIATLookup([entry('kernel32.dll', ['A'], [0x403000, 0x403008])]);
    expect(map.size).toBe(1);
    expect(map.has(0x403008)).toBe(false);
  });

  it('returns an empty map for no imports', () => {
    expect(buildIATLookup([]).size).toBe(0);
    expect(buildIATLookup([entry('kernel32.dll', [], [])]).size).toBe(0);
  });

  it('lets a later entry win when two libraries claim the same slot', () => {
    const map = buildIATLookup([
      entry('a.dll', ['first'], [0x403000]),
      entry('b.dll', ['second'], [0x403000]),
    ]);
    expect(map.get(0x403000)).toEqual({ lib: 'b.dll', func: 'second' });
  });
});
