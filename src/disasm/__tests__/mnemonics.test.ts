import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { MNEMONIC_HINTS } from '../mnemonics';

const keys = Object.keys(MNEMONIC_HINTS);

// MNEMONIC_HINTS is a pure lookup table with no logic, so these are format
// guards for the one thing that can silently break: the key must match the
// mnemonic text Capstone produces, since the UI looks it up with
// `MNEMONIC_HINTS[insn.mnemonic]` and shows nothing on a miss.
describe('MNEMONIC_HINTS', () => {
  it('keys every entry by a lowercase, unpadded mnemonic', () => {
    for (const k of keys) {
      expect(k, k).toBe(k.toLowerCase().trim());
      expect(k, k).toMatch(/^[a-z][a-z0-9]*$/);
    }
  });

  it('gives every entry a non-empty description', () => {
    for (const k of keys) {
      expect(MNEMONIC_HINTS[k].trim().length, k).toBeGreaterThan(0);
    }
  });

  it('has no duplicate keys in the source literal', () => {
    const src = readFileSync(fileURLToPath(new URL('../mnemonics.ts', import.meta.url)), 'utf8');
    const declared = [...src.matchAll(/^ {2}(\w+):/gm)].map(m => m[1]);
    expect(declared.filter((n, i) => declared.indexOf(n) !== i)).toEqual([]);
    expect(declared.length).toBe(keys.length);
  });

  // Every conditional branch needs a hint: buildCFG treats any `j*` as a
  // branch and RegState.getCondition understands the negated aliases, so a
  // missing entry means a blank tooltip on a real, reachable instruction.
  const CONDITIONAL_JUMPS = [
    'je', 'jz', 'jne', 'jnz',
    'jg', 'jnle', 'jge', 'jnl', 'jl', 'jnge', 'jle', 'jng',
    'ja', 'jnbe', 'jae', 'jnb', 'jnc', 'jb', 'jnae', 'jc', 'jbe', 'jna',
    'js', 'jns', 'jo', 'jno',
    'jp', 'jpe', 'jnp', 'jpo',
    'jcxz', 'jecxz', 'jrcxz',
  ];

  it('describes every x86 conditional jump, including the negated aliases', () => {
    expect(CONDITIONAL_JUMPS.filter(m => !(m in MNEMONIC_HINTS))).toEqual([]);
  });

  // Catches a jcc added to RegState.getCondition's condMap without a hint.
  it('describes every jcc RegState.getCondition knows about', () => {
    const src = readFileSync(
      fileURLToPath(new URL('../decompile/regstate.ts', import.meta.url)),
      'utf8',
    );
    const jccs = [...new Set([...src.matchAll(/'(jn?[a-z]{1,4})'/g)].map(m => m[1]))];
    expect(jccs.length).toBeGreaterThan(0);
    expect(jccs.filter(m => !(m in MNEMONIC_HINTS))).toEqual([]);
  });

  it('covers the mnemonics that dominate real disassembly', () => {
    const common = [
      'mov', 'lea', 'push', 'pop', 'call', 'ret', 'jmp', 'je', 'jne', 'jz', 'jnz',
      'cmp', 'test', 'add', 'sub', 'xor', 'and', 'or', 'nop', 'int3',
    ];
    expect(common.filter(m => !(m in MNEMONIC_HINTS))).toEqual([]);
  });
});
