import { describe, it, expect } from 'vitest';
import { decompileFunction } from '../pipeline';
import type { Instruction, DisasmFunction, Xref } from '../../types';

/**
 * End-to-end pipeline tests: instructions in, C-like pseudocode out.
 *
 * Everything else in this directory tests one stage in isolation, which left a
 * real gap — a whole class of defect only shows up in the emitted text. The
 * inverted-condition bug (peek-a-bin-h9v) lived in `structureCFG` for the
 * project's entire history and every stage-level test agreed with it, because
 * they asserted on the IR the buggy code produced.
 *
 * `decompileFunction` takes `Instruction[]`, not bytes, so none of this needs
 * Capstone or a worker — the instruction stream is written out by hand, which
 * also makes the intended semantics explicit rather than trusting a
 * disassembler to agree.
 */

let nextAddr = 0;

/** One instruction. `size` is nominal — only the addresses have to line up. */
function ins(address: number, mnemonic: string, opStr = '', size = 4): Instruction {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

/** Instructions at 4-byte spacing from `start`, so hand-written jump targets stay readable. */
function seq(start: number, rows: [string, string?][]): Instruction[] {
  nextAddr = start;
  return rows.map(([mnemonic, opStr]) => {
    const i = ins(nextAddr, mnemonic, opStr ?? '');
    nextAddr += 4;
    return i;
  });
}

function run(instructions: Instruction[], is64 = false): string {
  const start = instructions[0].address;
  const end = instructions[instructions.length - 1].address + instructions[instructions.length - 1].size;
  const func: DisasmFunction = { name: 'sub_401000', address: start, size: end - start };
  const xrefMap = new Map<number, Xref[]>();
  const result = decompileFunction(
    func,
    instructions,
    xrefMap,
    null,
    null,
    is64,
    new Map(),
    new Map(),
    new Map(),
    new Map(),
  );
  return result.code;
}

describe('decompileFunction — conditionals reach the output with the right sense', () => {
  // The regression test for peek-a-bin-h9v, written at the level the bug was
  // actually visible at. `je` jumps when ecx == 0, and the jump target is the
  // block that assigns 2. So the guard around "eax = 2" must be `== 0`.
  // Before the fix this emitted `!= 0` with the bodies in the same places,
  // i.e. valid C stating the opposite of the machine code.
  it('guards the jump target with the condition under which the jump is taken', () => {
    const code = run(seq(0x401000, [
      ['cmp', 'ecx, 0'],
      ['je', '0x401010'],
      ['mov', 'eax, 1'],
      ['ret'],
      ['mov', 'eax, 2'], // 0x401010 — reached when ecx == 0
      ['ret'],
    ]));

    const guard = code.split('\n').find(l => l.includes('if'));
    expect(guard).toBeDefined();
    expect(guard).toContain('== 0');
    expect(guard).not.toContain('!= 0');
  });

  it('emits the opposite sense for the opposite jump', () => {
    // Same shape, `jne` instead of `je`: the target is now reached when
    // ecx != 0, so the guard must flip with it. A pipeline that hard-coded
    // either polarity would fail exactly one of these two tests.
    const code = run(seq(0x401000, [
      ['cmp', 'ecx, 0'],
      ['jne', '0x401010'],
      ['mov', 'eax, 1'],
      ['ret'],
      ['mov', 'eax, 2'],
      ['ret'],
    ]));

    const guard = code.split('\n').find(l => l.includes('if'));
    expect(guard).toBeDefined();
    expect(guard).toContain('!= 0');
    expect(guard).not.toContain('== 0');
  });

  it('keeps a signed comparison the right way round', () => {
    // `jg` is taken when eax > 5, and 0x401010 is the target.
    const code = run(seq(0x401000, [
      ['cmp', 'eax, 5'],
      ['jg', '0x401010'],
      ['mov', 'ecx, 1'],
      ['ret'],
      ['mov', 'ecx, 2'],
      ['ret'],
    ]));

    const guard = code.split('\n').find(l => l.includes('if'));
    expect(guard).toBeDefined();
    expect(guard).toContain('>');
    expect(guard).not.toContain('<=');
  });
});

describe('decompileFunction — output shape', () => {
  it('produces a function signature and a balanced body', () => {
    const code = run(seq(0x401000, [
      ['mov', 'eax, 1'],
      ['ret'],
    ]));

    expect(code).toContain('sub_401000');
    // Whatever the body is, the braces have to balance or the pane shows
    // syntactically broken C.
    const opens = (code.match(/\{/g) ?? []).length;
    const closes = (code.match(/\}/g) ?? []).length;
    expect(opens).toBe(closes);
  });

  it('reports rather than throws when there are no instructions', () => {
    const func: DisasmFunction = { name: 'empty', address: 0x401000, size: 0 };
    const result = decompileFunction(
      func, [], new Map(), null, null, false,
      new Map(), new Map(), new Map(), new Map(),
    );
    expect(result.code).toContain('no instructions');
    expect(result.lineMap).toEqual([]);
  });

  it('returns a line map that points into the emitted text', () => {
    const instructions = seq(0x401000, [
      ['cmp', 'ecx, 0'],
      ['je', '0x401010'],
      ['mov', 'eax, 1'],
      ['ret'],
      ['mov', 'eax, 2'],
      ['ret'],
    ]);
    const func: DisasmFunction = { name: 'sub_401000', address: 0x401000, size: 0x18 };
    const result = decompileFunction(
      func, instructions, new Map(), null, null, false,
      new Map(), new Map(), new Map(), new Map(),
    );

    const lineCount = result.code.split('\n').length;
    for (const [line, addr] of result.lineMap) {
      expect(line).toBeGreaterThanOrEqual(0);
      expect(line).toBeLessThan(lineCount);
      expect(addr).toBeGreaterThanOrEqual(0x401000);
    }
  });
});
