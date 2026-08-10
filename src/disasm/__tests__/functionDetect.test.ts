import { describe, it, expect } from 'vitest';
import {
  mapInsn, disassemble, detectFunctions, hybridDisassemble, buildTypedXrefMap, buildAllXrefs,
  type DisasmContext,
} from '../functionDetect';
import type { Instruction } from '../types';

const BASE = 0x401000;

function ctxOf(over: Partial<DisasmContext> = {}): DisasmContext {
  return {
    cs32: null,
    cs64: null,
    stringMap: new Map(),
    iatMap: new Map(),
    driverMode: false,
    ...over,
  };
}

/** Raw capstone-shaped instruction, as `mapInsn` receives it. */
function raw(mnemonic: string, opStr: string, address = BASE, size = 5) {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

// ── A minimal stand-in for the Capstone WASM decoder ──
// Encodings: E8=call rel32, E9=jmp rel32, EB=jmp rel8, 74=je rel8, C3=ret,
// 90=nop, CC=int3, 83 F8 ii=cmp eax imm8, FF 24 C5 dd=jmp [rax*8+disp32],
// FF 25 dd=jmp [rip+disp32], 00=undecodable (stops the chunk).
function readI32(b: Uint8Array, i: number): number {
  return (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) | 0;
}
const hex = (n: number) => `0x${(n >>> 0).toString(16)}`;

interface FakeInsn { address: number; mnemonic: string; opStr: string; size: number; bytes: Uint8Array }

function fakeCs() {
  return {
    disasm(bytes: Uint8Array, opts: { address: number }): FakeInsn[] {
      const out: FakeInsn[] = [];
      let i = 0;
      const emit = (mnemonic: string, opStr: string, size: number) => {
        out.push({ address: opts.address + i, mnemonic, opStr, size, bytes: bytes.slice(i, i + size) });
        i += size;
      };
      while (i < bytes.length) {
        const b = bytes[i];
        const here = opts.address + i;
        if (b === 0x00) break; // undecodable
        if (b === 0xe8 && i + 4 < bytes.length) { emit('call', hex(here + 5 + readI32(bytes, i + 1)), 5); continue; }
        if (b === 0xe9 && i + 4 < bytes.length) { emit('jmp', hex(here + 5 + readI32(bytes, i + 1)), 5); continue; }
        if (b === 0xeb && i + 1 < bytes.length) { emit('jmp', hex(here + 2 + ((bytes[i + 1] << 24) >> 24)), 2); continue; }
        if (b === 0x74 && i + 1 < bytes.length) { emit('je', hex(here + 2 + ((bytes[i + 1] << 24) >> 24)), 2); continue; }
        if (b === 0xc3) { emit('ret', '', 1); continue; }
        if (b === 0x90) { emit('nop', '', 1); continue; }
        if (b === 0xcc) { emit('int3', '', 1); continue; }
        if (b === 0x83 && bytes[i + 1] === 0xf8 && i + 2 < bytes.length) { emit('cmp', `eax, ${hex(bytes[i + 2])}`, 3); continue; }
        if (b === 0xff && bytes[i + 1] === 0x24 && bytes[i + 2] === 0xc5 && i + 6 < bytes.length) {
          emit('jmp', `qword ptr [rax*8 + ${hex(readI32(bytes, i + 3))}]`, 7); continue;
        }
        if (b === 0xff && bytes[i + 1] === 0x25 && i + 5 < bytes.length) {
          emit('jmp', `qword ptr [rip + ${hex(readI32(bytes, i + 2))}]`, 6); continue;
        }
        emit('nop', '', 1);
      }
      return out;
    },
  };
}

/** Assemble a byte buffer from fragments placed at explicit offsets. */
function image(len: number, parts: Record<number, number[]>): Uint8Array {
  const out = new Uint8Array(len);
  for (const [off, bytes] of Object.entries(parts)) out.set(bytes, Number(off));
  return out;
}

/** `call` to an absolute address from `at`. */
const callTo = (at: number, target: number) => {
  const rel = target - (BASE + at + 5);
  return [0xe8, rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >> 24) & 0xff];
};
const jmpTo = (at: number, target: number) => {
  const rel = target - (BASE + at + 5);
  return [0xe9, rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >> 24) & 0xff];
};
const le32 = (v: number) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];

describe('mapInsn', () => {
  it('copies the capstone fields verbatim', () => {
    expect(mapInsn(raw('mov', 'eax, ecx', 0x401000, 2), new Map(), new Map(), false)).toEqual({
      address: 0x401000, mnemonic: 'mov', opStr: 'eax, ecx', size: 2, bytes: new Uint8Array(2),
    });
  });

  it('adds no comment when no maps are supplied', () => {
    expect(mapInsn(raw('lea', 'rax, [rip + 0x10]'), new Map(), new Map(), false).comment).toBeUndefined();
  });

  it('annotates a rip-relative string reference', () => {
    const target = 0x401000 + 5 + 0x100;
    const strings = new Map([[target, 'hello world']]);
    expect(mapInsn(raw('lea', 'rax, [rip + 0x100]'), strings, new Map(), false).comment).toBe('hello world');
  });

  it('resolves a negative rip displacement', () => {
    const target = 0x401000 + 5 - 0x100;
    const strings = new Map([[target, 'backwards']]);
    expect(mapInsn(raw('lea', 'rax, [rip - 0x100]'), strings, new Map(), false).comment).toBe('backwards');
  });

  it('annotates an absolute string address in the operand', () => {
    const strings = new Map([[0x404000, 'literal']]);
    expect(mapInsn(raw('push', '0x404000'), strings, new Map(), false).comment).toBe('literal');
  });

  it('truncates a long string comment to 60 characters', () => {
    const long = 'x'.repeat(100);
    const comment = mapInsn(raw('push', '0x404000'), new Map([[0x404000, long]]), new Map(), false).comment!;
    expect(comment).toHaveLength(60);
    expect(comment.endsWith('...')).toBe(true);
  });

  it('keeps a string of exactly 60 characters intact', () => {
    const exact = 'y'.repeat(60);
    expect(mapInsn(raw('push', '0x404000'), new Map([[0x404000, exact]]), new Map(), false).comment).toBe(exact);
  });

  it('takes the first matching address when several appear', () => {
    const strings = new Map([[0x404000, 'first'], [0x405000, 'second']]);
    expect(mapInsn(raw('mov', 'qword ptr [0x404000], 0x405000'), strings, new Map(), false).comment).toBe('first');
  });

  it('annotates an import through a rip-relative reference', () => {
    const target = 0x401000 + 5 + 0x200;
    const iat = new Map([[target, { lib: 'kernel32.dll', func: 'ExitProcess' }]]);
    expect(mapInsn(raw('call', 'qword ptr [rip + 0x200]'), new Map(), iat, false).comment)
      .toBe('kernel32.dll!ExitProcess');
  });

  it('annotates an import at an absolute address', () => {
    const iat = new Map([[0x403000, { lib: 'user32.dll', func: 'MessageBoxW' }]]);
    expect(mapInsn(raw('call', 'dword ptr [0x403000]'), new Map(), iat, false).comment)
      .toBe('user32.dll!MessageBoxW');
  });

  it('prefers a string comment over an import comment', () => {
    const strings = new Map([[0x403000, 'str']]);
    const iat = new Map([[0x403000, { lib: 'a.dll', func: 'f' }]]);
    expect(mapInsn(raw('push', '0x403000'), strings, iat, false).comment).toBe('str');
  });

  it('annotates a plausible IOCTL only in driver mode', () => {
    const ioctl = 0x22e004; // FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
    expect(mapInsn(raw('cmp', `eax, 0x${ioctl.toString(16)}`), new Map(), new Map(), false).comment)
      .toBeUndefined();
    const withDriver = mapInsn(raw('cmp', `eax, 0x${ioctl.toString(16)}`), new Map(), new Map(), true);
    expect(withDriver.comment).toBeTruthy();
  });

  it('does not annotate an implausible IOCTL value', () => {
    expect(mapInsn(raw('cmp', 'eax, 0x1'), new Map(), new Map(), true).comment).toBeUndefined();
  });
});

describe('detectFunctions — seeds', () => {
  const empty = new Uint8Array(0x100);

  it('returns no functions for an empty image', () => {
    expect(detectFunctions(new Uint8Array(0), BASE, true, ctxOf()).functions).toEqual([]);
  });

  it('names the entry point', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), { entryPoint: BASE + 0x20 });
    expect(functions).toEqual([{ name: 'entry_point', address: BASE + 0x20, size: 0x100 - 0x20 }]);
  });

  it('names exported functions', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      exports: [{ name: 'DriverEntry', address: BASE + 0x10 }],
    });
    expect(functions[0].name).toBe('DriverEntry');
  });

  it('lets an export name override the entry point name at the same address', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      entryPoint: BASE,
      exports: [{ name: 'Start', address: BASE }],
    });
    expect(functions[0].name).toBe('Start');
  });

  it('ignores seeds outside the image', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      entryPoint: BASE - 1,
      exports: [{ name: 'Far', address: BASE + 0x1000 }],
      handlerAddresses: [0],
    });
    expect(functions).toEqual([]);
  });

  it('seeds and sizes functions from .pdata', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      pdataFunctions: [{ beginAddress: BASE + 0x10, endAddress: BASE + 0x40 }],
    });
    expect(functions).toEqual([{ name: `sub_${(BASE + 0x10).toString(16).toUpperCase()}`, address: BASE + 0x10, size: 0x30 }]);
  });

  it('names exception handlers', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), { handlerAddresses: [BASE + 0x30] });
    expect(functions[0].name).toBe(`__handler_${(BASE + 0x30).toString(16)}`);
  });

  it('sizes each function up to the next one', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      exports: [{ name: 'a', address: BASE }, { name: 'b', address: BASE + 0x40 }],
    });
    expect(functions.map(f => [f.name, f.size])).toEqual([['a', 0x40], ['b', 0xc0]]);
  });

  it('sorts functions by address', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      exports: [{ name: 'b', address: BASE + 0x40 }, { name: 'a', address: BASE }],
    });
    expect(functions.map(f => f.name)).toEqual(['a', 'b']);
  });

  it('lets a .pdata end address win over the next-function heuristic', () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 0x10 }],
      exports: [{ name: 'b', address: BASE + 0x80 }],
    });
    expect(functions[0].size).toBe(0x10);
  });
});

describe('detectFunctions — prologue scanning', () => {
  const at = (offset: number, bytes: number[], len = 0x40) =>
    detectFunctions(image(len, { [offset]: bytes }), BASE, true, ctxOf()).functions.map(f => f.address);
  const at32 = (offset: number, bytes: number[], len = 0x40) =>
    detectFunctions(image(len, { [offset]: bytes }), BASE, false, ctxOf()).functions.map(f => f.address);

  it('recognises the x64 frame-pointer prologue', () => {
    expect(at(0x10, [0x55, 0x48, 0x89, 0xe5])).toContain(BASE + 0x10);
  });

  it('recognises `sub rsp, imm8` and `sub rsp, imm32`', () => {
    expect(at(0x10, [0x48, 0x83, 0xec, 0x28])).toContain(BASE + 0x10);
    expect(at(0x10, [0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00])).toContain(BASE + 0x10);
  });

  it('recognises push rbx / push rdi+rsi / rex-prefixed prologues', () => {
    expect(at(0x10, [0x53, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x57, 0x56, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x40, 0x53, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x40, 0x57, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x40, 0x55, 0x48, 0x8d, 0x6c, 0x24])).toContain(BASE + 0x10);
  });

  it('recognises the home-space register spill', () => {
    expect(at(0x10, [0x48, 0x89, 0x4c, 0x24, 0x08])).toContain(BASE + 0x10);
  });

  it('requires a boundary before an ambiguous `mov [rsp+x], rbx` spill', () => {
    // 0x11 is neither 16-aligned nor preceded by padding.
    const unaligned = image(0x40, { 0x11: [0x48, 0x89, 0x5c, 0x24, 0x08] });
    unaligned[0x10] = 0x41; // not padding
    expect(detectFunctions(unaligned, BASE, true, ctxOf()).functions).toEqual([]);
    // Preceded by int3 padding it is accepted.
    expect(at(0x11, [0xcc, 0x48, 0x89, 0x5c, 0x24, 0x08])).toContain(BASE + 0x12);
  });

  it('accepts an ambiguous prologue at a 16-byte boundary', () => {
    const img = image(0x40, { 0x20: [0x48, 0x8b, 0xc4] });
    img[0x1f] = 0x41;
    expect(detectFunctions(img, BASE, true, ctxOf()).functions.map(f => f.address)).toContain(BASE + 0x20);
  });

  it('recognises the x86 frame-pointer prologues', () => {
    expect(at32(0x10, [0x55, 0x8b, 0xec])).toContain(BASE + 0x10);
    expect(at32(0x10, [0x55, 0x89, 0xe5])).toContain(BASE + 0x10);
    expect(at32(0x10, [0x8b, 0xff, 0x55, 0x8b, 0xec])).toContain(BASE + 0x10);
  });

  it('does not use x64 prologues in 32-bit mode', () => {
    expect(at32(0x10, [0x48, 0x83, 0xec, 0x28])).not.toContain(BASE + 0x10);
  });

  it('does not use x86 prologues in 64-bit mode', () => {
    expect(at(0x10, [0x55, 0x8b, 0xec])).not.toContain(BASE + 0x10);
  });

  it('starts a function after alignment padding', () => {
    const img = image(0x40, { 0x00: [0x90, 0xcc, 0xcc, 0xcc], 0x04: [0x41, 0x41] });
    expect(detectFunctions(img, BASE, true, ctxOf()).functions.map(f => f.address)).toContain(BASE + 4);
  });

  it('ignores padding followed by zero bytes', () => {
    const img = image(0x40, { 0x00: [0xcc, 0xcc] });
    expect(detectFunctions(img, BASE, true, ctxOf()).functions).toEqual([]);
  });

  it('ignores padding that does not reach the minimum run length', () => {
    // A single 0xCC needs a run of 2; a lone 0x90 needs 3.
    const oneInt3 = image(0x40, { 0x00: [0xcc, 0x41] });
    expect(detectFunctions(oneInt3, BASE, true, ctxOf()).functions).toEqual([]);
    const twoNops = image(0x40, { 0x00: [0x90, 0x90, 0x41] });
    expect(detectFunctions(twoNops, BASE, true, ctxOf()).functions).toEqual([]);
  });

  it('requires the post-padding address to be 4-byte aligned', () => {
    const img = image(0x40, { 0x00: [0x41, 0xcc, 0xcc, 0x41] });
    expect(detectFunctions(img, BASE, true, ctxOf()).functions).toEqual([]);
  });

  it('deduplicates a prologue that is also a seed', () => {
    const img = image(0x40, { 0x00: [0x55, 0x48, 0x89, 0xe5] });
    const { functions } = detectFunctions(img, BASE, true, ctxOf(), { entryPoint: BASE });
    expect(functions).toHaveLength(1);
    expect(functions[0].name).toBe('entry_point');
  });
});

describe('detectFunctions — with a decoder', () => {
  const ctx = () => ctxOf({ cs64: fakeCs() });

  it('adds direct call targets as functions', () => {
    const img = image(0x40, { 0x00: callTo(0x00, BASE + 0x20), 0x05: [0xc3] });
    const { functions } = detectFunctions(img, BASE, true, ctx());
    expect(functions.map(f => f.address)).toContain(BASE + 0x20);
  });

  it('ignores call targets outside the image', () => {
    const img = image(0x40, { 0x00: callTo(0x00, BASE + 0x8000), 0x05: [0xc3] });
    expect(detectFunctions(img, BASE, true, ctx()).functions).toEqual([]);
  });

  it('reads a jump table behind a bounds check', () => {
    const tableRva = 0x20;
    const img = image(0x60, {
      0x00: [0x83, 0xf8, 0x02], // cmp eax, 2
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + tableRva)],
      [tableRva]: [...le32(BASE + 0x40), ...le32(BASE + 0x44), ...le32(BASE + 0x48)],
    });
    const { functions, jumpTables } = detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() }));
    expect(jumpTables).toHaveLength(1);
    const [, targets] = jumpTables[0];
    expect(targets).toEqual([BASE + 0x40, BASE + 0x44, BASE + 0x48]);
    for (const t of targets) expect(functions.map(f => f.address)).toContain(t);
  });

  it('ignores an indirect jump with no preceding bounds check', () => {
    const img = image(0x60, {
      0x00: [0xff, 0x24, 0xc5, ...le32(BASE + 0x20)],
      0x20: [...le32(BASE + 0x40), ...le32(BASE + 0x44)],
    });
    expect(detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() })).jumpTables).toEqual([]);
  });

  it('stops reading a jump table at the first out-of-range entry', () => {
    const img = image(0x60, {
      0x00: [0x83, 0xf8, 0x04],
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + 0x20)],
      0x20: [...le32(BASE + 0x40), ...le32(BASE + 0x44), ...le32(0xdeadbeef)],
    });
    const { jumpTables } = detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() }));
    expect(jumpTables[0][1]).toEqual([BASE + 0x40, BASE + 0x44]);
  });

  it('needs at least two valid entries to accept a jump table', () => {
    const img = image(0x60, {
      0x00: [0x83, 0xf8, 0x04],
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + 0x20)],
      0x20: [...le32(BASE + 0x40), ...le32(0xdeadbeef)],
    });
    expect(detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() })).jumpTables).toEqual([]);
  });

  const IAT_ADDR = BASE + 0x30;
  const thunkImage = () =>
    image(0x40, { 0x00: [0xff, 0x25, ...le32(IAT_ADDR - (BASE + 6))] });
  const thunkCtx = () => ctxOf({
    cs64: fakeCs(),
    iatMap: new Map([[IAT_ADDR, { lib: 'kernel32.dll', func: 'Sleep' }]]),
  });

  it('renames a single-jump function that targets an import', () => {
    const { functions } = detectFunctions(thunkImage(), BASE, true, thunkCtx(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 6 }],
    });
    const thunk = functions.find(f => f.address === BASE);
    expect(thunk?.name).toBe('Sleep');
    expect(thunk?.isThunk).toBe(true);
  });

  it('does not treat a longer function as a thunk', () => {
    // The jump is preceded by real work, so meaningfulCount > 1.
    const img = thunkImage();
    img.copyWithin(2, 0, 8);
    img[0] = 0x83; img[1] = 0xf8; // cmp eax, imm8 before the jump
    const { functions } = detectFunctions(img, BASE, true, thunkCtx(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 9 }],
    });
    expect(functions[0].isThunk).toBeUndefined();
  });

  it('does not consider a function larger than 16 bytes a thunk', () => {
    const { functions } = detectFunctions(thunkImage(), BASE, true, thunkCtx(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 0x20 }],
    });
    expect(functions[0].isThunk).toBeUndefined();
  });

  it('leaves a named function alone even if it looks like a thunk', () => {
    const { functions } = detectFunctions(thunkImage(), BASE, true, thunkCtx(), {
      exports: [{ name: 'MyExport', address: BASE }],
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 6 }],
    });
    expect(functions[0].name).toBe('MyExport');
    expect(functions[0].isThunk).toBeUndefined();
  });

  it('records a tail call to another function', () => {
    // Function A at 0x00 ends with `jmp B`; B is a seeded function at 0x20.
    const img = image(0x40, { 0x00: jmpTo(0x00, BASE + 0x20), 0x20: [0xc3] });
    const { functions } = detectFunctions(img, BASE, true, ctxOf({ cs64: fakeCs() }), {
      pdataFunctions: [
        { beginAddress: BASE, endAddress: BASE + 5 },
        { beginAddress: BASE + 0x20, endAddress: BASE + 0x21 },
      ],
    });
    expect(functions.find(f => f.address === BASE)?.tailCallTarget).toBe(BASE + 0x20);
  });

  it('does not record a self-jump as a tail call', () => {
    const img = image(0x40, { 0x00: jmpTo(0x00, BASE) });
    const { functions } = detectFunctions(img, BASE, true, ctxOf({ cs64: fakeCs() }), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 5 }],
    });
    expect(functions[0].tailCallTarget).toBeUndefined();
  });
});

describe('disassemble', () => {
  it('decodes a whole buffer', () => {
    const img = image(4, { 0: [0xc3, 0x90, 0xcc, 0xc3] });
    expect(disassemble(img, BASE, true, ctxOf({ cs64: fakeCs() })).map(i => i.mnemonic))
      .toEqual(['ret', 'nop', 'int3', 'ret']);
  });

  it('skips a byte the decoder cannot handle and resumes', () => {
    const img = image(3, { 0: [0x00, 0xc3, 0x90] });
    expect(disassemble(img, BASE, true, ctxOf({ cs64: fakeCs() })).map(i => i.mnemonic))
      .toEqual(['ret', 'nop']);
  });

  it('returns nothing for an empty buffer', () => {
    expect(disassemble(new Uint8Array(0), BASE, true, ctxOf({ cs64: fakeCs() }))).toEqual([]);
  });

  it('applies instruction comments while decoding', () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x10)] });
    const iatMap = new Map([[BASE + 6 + 0x10, { lib: 'a.dll', func: 'F' }]]);
    expect(disassemble(img, BASE, true, ctxOf({ cs64: fakeCs(), iatMap }))[0].comment).toBe('a.dll!F');
  });
});

describe('hybridDisassemble', () => {
  const ctx = () => ctxOf({ cs64: fakeCs() });

  it('follows a call and its fallthrough from a seed', () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3], 0x10: [0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    const byAddr = new Map(insns.map(i => [i.address, i]));
    expect(byAddr.get(BASE)?.mnemonic).toBe('call');
    expect(byAddr.get(BASE + 5)?.mnemonic).toBe('ret');
    expect(byAddr.get(BASE + 0x10)?.source).toBe('recursive');
  });

  it('follows both edges of a conditional jump', () => {
    const img = image(0x10, { 0x00: [0x74, 0x04], 0x02: [0xc3], 0x06: [0xc3] });
    const addrs = hybridDisassemble(img, BASE, true, [BASE], ctx()).map(i => i.address);
    expect(addrs).toContain(BASE + 2);
    expect(addrs).toContain(BASE + 6);
  });

  it('stops recursive descent at a terminator', () => {
    const img = image(0x10, { 0x00: [0xc3], 0x01: [0x41] });
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    expect(insns.find(i => i.address === BASE + 1)?.source).not.toBe('recursive');
  });

  it('returns instructions sorted by address', () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3], 0x10: [0xc3] });
    const addrs = hybridDisassemble(img, BASE, true, [BASE], ctx()).map(i => i.address);
    expect(addrs).toEqual([...addrs].sort((a, b) => a - b));
  });

  it('ignores seeds outside the image', () => {
    // Out-of-range seeds contribute nothing; the bytes are only reached by the
    // gap-fill pass, which marks them as such.
    const img = image(0x10, { 0x00: [0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE - 0x100, BASE + 0x1000], ctx());
    expect(insns.every(i => i.source === 'gap-fill')).toBe(true);
  });

  it('gap-fills bytes the recursive pass never reached', () => {
    const img = image(0x10, { 0x00: [0xc3], 0x01: [0x90, 0x90, 0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    expect(insns.find(i => i.address === BASE + 3)?.source).toBe('gap-fill');
  });

  it('does not gap-fill a run of padding', () => {
    const img = new Uint8Array(0x10).fill(0xcc);
    img[0] = 0xc3;
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    expect(insns.map(i => i.address)).toEqual([BASE]);
  });

  it('bulk-decodes .pdata ranges before the recursive pass', () => {
    const img = image(0x20, { 0x10: [0xc3, 0x90] });
    const insns = hybridDisassemble(img, BASE, true, [], ctx(), [
      { beginAddress: BASE + 0x10, endAddress: BASE + 0x12 },
    ]);
    expect(insns.map(i => [i.address, i.source])).toEqual([
      [BASE + 0x10, 'recursive'], [BASE + 0x11, 'recursive'],
    ]);
  });

  it('ignores a .pdata range that runs past the image', () => {
    const img = image(0x10, {});
    expect(hybridDisassemble(img, BASE, true, [], ctx(), [
      { beginAddress: BASE, endAddress: BASE + 0x100 },
    ])).toEqual([]);
  });

  it('never decodes the same address twice', () => {
    const img = image(0x10, { 0x00: [0x74, 0x00], 0x02: [0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE, BASE, BASE + 2], ctx());
    const addrs = insns.map(i => i.address);
    expect(new Set(addrs).size).toBe(addrs.length);
  });
});

describe('buildTypedXrefMap', () => {
  const insn = (mnemonic: string, opStr: string, address: number, size = 5): Instruction =>
    ({ address, mnemonic, opStr, size, bytes: new Uint8Array(size) });

  it('returns nothing for an empty instruction list', () => {
    expect(buildTypedXrefMap([])).toEqual([]);
  });

  it('classifies a direct call as a call xref', () => {
    expect(buildTypedXrefMap([insn('call', '0x401100', BASE)]))
      .toEqual([[0x401100, [{ from: BASE, type: 'call' }]]]);
  });

  it('classifies jmp and conditional branches', () => {
    expect(buildTypedXrefMap([insn('jmp', '0x401100', BASE)])[0][1][0].type).toBe('jmp');
    expect(buildTypedXrefMap([insn('je', '0x401100', BASE)])[0][1][0].type).toBe('branch');
    expect(buildTypedXrefMap([insn('jrcxz', '0x401100', BASE)])[0][1][0].type).toBe('branch');
  });

  it('ignores a direct address operand on a non-branch instruction', () => {
    expect(buildTypedXrefMap([insn('push', '0x401100', BASE)])).toEqual([]);
  });

  it('groups several references to the same target', () => {
    const xrefs = buildTypedXrefMap([
      insn('call', '0x401100', BASE),
      insn('je', '0x401100', BASE + 5),
    ]);
    expect(xrefs).toEqual([[0x401100, [
      { from: BASE, type: 'call' },
      { from: BASE + 5, type: 'branch' },
    ]]]);
  });

  it('resolves a rip-relative call to an import as a call xref', () => {
    const [[target, refs]] = buildTypedXrefMap([insn('call', 'qword ptr [rip + 0x100]', BASE, 6)]);
    expect(target).toBe(BASE + 6 + 0x100);
    expect(refs[0].type).toBe('call');
  });

  it('classifies a rip-relative load as a data xref', () => {
    expect(buildTypedXrefMap([insn('lea', 'rax, [rip + 0x100]', BASE, 7)])[0][1][0].type).toBe('data');
  });

  it('records data xrefs for absolute addresses above 0x10000', () => {
    expect(buildTypedXrefMap([insn('mov', 'eax, dword ptr [0x404000]', BASE)]))
      .toEqual([[0x404000, [{ from: BASE, type: 'data' }]]]);
  });

  it('ignores small immediates as data xrefs', () => {
    expect(buildTypedXrefMap([insn('mov', 'eax, 0x10', BASE)])).toEqual([]);
  });

  it('records every address in a multi-operand instruction', () => {
    const xrefs = buildTypedXrefMap([insn('mov', 'dword ptr [0x404000], 0x405000', BASE)]);
    expect(xrefs.map(([addr]) => addr)).toEqual([0x404000, 0x405000]);
  });
});

describe('buildAllXrefs', () => {
  const cs = fakeCs();

  it('returns empty maps for an empty image', () => {
    expect(buildAllXrefs(new Uint8Array(0), BASE, true, [], [], cs)).toEqual({
      stringXrefs: [], importXrefs: [], callGraph: [], dataXrefs: [],
    });
  });

  it('records a string reference behind a rip-relative operand', () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x10)] });
    const strAddr = BASE + 6 + 0x10;
    const { stringXrefs } = buildAllXrefs(img, BASE, true, [strAddr], [], cs);
    expect(stringXrefs).toEqual([[strAddr, [BASE]]]);
  });

  it('records an import reference behind a rip-relative operand', () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x20)] });
    const iatAddr = BASE + 6 + 0x20;
    const { importXrefs } = buildAllXrefs(img, BASE, true, [], [iatAddr], cs);
    expect(importXrefs).toEqual([[iatAddr, [BASE]]]);
  });

  it('builds a call graph edge between two known functions', () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3], 0x10: [0xc3] });
    const { callGraph } = buildAllXrefs(img, BASE, true, [], [], cs, [[BASE, 0x10], [BASE + 0x10, 0x10]]);
    expect(callGraph).toEqual([[BASE, [BASE + 0x10]]]);
  });

  it('does not record a call to an address that is not a known function', () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3] });
    const { callGraph } = buildAllXrefs(img, BASE, true, [], [], cs, [[BASE, 0x10]]);
    expect(callGraph).toEqual([]);
  });

  it('records data xrefs into declared data sections', () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x1000)] });
    const dataAddr = BASE + 6 + 0x1000;
    const { dataXrefs } = buildAllXrefs(img, BASE, true, [], [], cs, undefined, [
      { va: dataAddr - 0x10, size: 0x100 },
    ]);
    expect(dataXrefs.map(([addr]) => addr)).toContain(dataAddr);
  });

  it('does not double-count a string address as a data xref', () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x1000)] });
    const target = BASE + 6 + 0x1000;
    const { dataXrefs } = buildAllXrefs(img, BASE, true, [target], [], cs, undefined, [
      { va: target, size: 0x10 },
    ]);
    expect(dataXrefs).toEqual([]);
  });

  it('ignores data sections when none are supplied', () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x1000)] });
    expect(buildAllXrefs(img, BASE, true, [], [], cs).dataXrefs).toEqual([]);
  });
});
