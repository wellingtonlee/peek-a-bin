import { describe, it, expect } from 'vitest';
import { RegState } from '../regstate';
import { irBinary, irConst, irReg, irUnary } from '../ir';
import type { BinaryOp, IRExpr } from '../ir';

describe('RegState definitions', () => {
  it('stores and retrieves a definition case-insensitively', () => {
    const st = new RegState();
    st.set('RAX', irConst(7));
    expect(st.get('rax')).toEqual(irConst(7));
    expect(st.get('RaX')).toEqual(irConst(7));
  });

  it('lets the last writer win', () => {
    const st = new RegState();
    st.set('rax', irConst(1));
    st.set('rax', irConst(2));
    expect(st.get('rax')).toEqual(irConst(2));
  });

  it('returns undefined for an undefined register', () => {
    expect(new RegState().get('rbx')).toBeUndefined();
  });

  it('falls back to a bare register expression in getOrReg', () => {
    const st = new RegState();
    expect(st.getOrReg('rbx', 8)).toEqual(irReg('rbx', 8));
    st.set('rbx', irConst(5));
    expect(st.getOrReg('rbx', 8)).toEqual(irConst(5));
  });

  it('keeps sub-registers as distinct slots', () => {
    // The lifter keys defs by the literal operand text, so eax and rax differ.
    const st = new RegState();
    st.set('eax', irConst(1));
    expect(st.get('rax')).toBeUndefined();
  });
});

describe('RegState.getCondition — after cmp', () => {
  function afterCmp(jcc: string, left: IRExpr = irReg('eax', 4), right: IRExpr = irConst(5)) {
    const st = new RegState();
    st.setFlags('cmp', left, right);
    return st.getCondition(jcc);
  }

  it('maps signed comparisons to signed operators', () => {
    expect(afterCmp('jl')).toEqual(irBinary('<', irReg('eax', 4), irConst(5)));
    expect(afterCmp('jle')).toEqual(irBinary('<=', irReg('eax', 4), irConst(5)));
    expect(afterCmp('jg')).toEqual(irBinary('>', irReg('eax', 4), irConst(5)));
    expect(afterCmp('jge')).toEqual(irBinary('>=', irReg('eax', 4), irConst(5)));
  });

  it('maps unsigned comparisons to unsigned operators', () => {
    // ja/jb are the unsigned forms — emitting signed < here would be a real defect.
    expect(afterCmp('ja').kind).toBe('binary');
    expect((afterCmp('ja') as { op: string }).op).toBe('u>');
    expect((afterCmp('jae') as { op: string }).op).toBe('u>=');
    expect((afterCmp('jb') as { op: string }).op).toBe('u<');
    expect((afterCmp('jbe') as { op: string }).op).toBe('u<=');
  });

  it('maps equality forms', () => {
    expect((afterCmp('je') as { op: string }).op).toBe('==');
    expect((afterCmp('jz') as { op: string }).op).toBe('==');
    expect((afterCmp('jne') as { op: string }).op).toBe('!=');
    expect((afterCmp('jnz') as { op: string }).op).toBe('!=');
  });

  it('maps the negated aliases to the same operators as their primaries', () => {
    const pairs: [string, string][] = [
      ['jnle', 'jg'], ['jnl', 'jge'], ['jnge', 'jl'], ['jng', 'jle'],
      ['jnbe', 'ja'], ['jnb', 'jae'], ['jnc', 'jae'], ['jnae', 'jb'],
      ['jc', 'jb'], ['jna', 'jbe'],
    ];
    for (const [alias, primary] of pairs) {
      expect(afterCmp(alias), alias).toEqual(afterCmp(primary));
    }
  });

  it('expresses js/jns as a sign test on the difference', () => {
    expect(afterCmp('js')).toEqual(
      irBinary('<', irBinary('-', irReg('eax', 4), irConst(5)), irConst(0)),
    );
    expect(afterCmp('jns')).toEqual(
      irBinary('>=', irBinary('-', irReg('eax', 4), irConst(5)), irConst(0)),
    );
  });

  it('falls back to an unknown expression for an unmapped jcc', () => {
    const cond = afterCmp('jp');
    expect(cond.kind).toBe('unknown');
  });

  it('returns unknown when no flags have been set', () => {
    const cond = new RegState().getCondition('je');
    expect(cond).toEqual({ kind: 'unknown', text: 'je' });
  });

  it('preserves the compared expressions verbatim', () => {
    const left = irBinary('+', irReg('rbx', 8), irConst(4));
    const cond = afterCmp('je', left, irConst(0));
    expect(cond).toEqual(irBinary('==', left, irConst(0)));
  });
});

describe('RegState.getCondition — after test', () => {
  function afterTest(jcc: string, left: IRExpr, right: IRExpr) {
    const st = new RegState();
    st.setFlags('test', left, right);
    return st.getCondition(jcc);
  }

  it('reduces `test X, X` + je to a zero comparison on X', () => {
    const eax = irReg('eax', 4);
    expect(afterTest('je', eax, irReg('eax', 4))).toEqual(irBinary('==', eax, irConst(0, 4)));
    expect(afterTest('jnz', eax, irReg('eax', 4))).toEqual(irBinary('!=', eax, irConst(0, 4)));
  });

  it('recognises the self-test idiom regardless of register case', () => {
    const cond = afterTest('je', irReg('EAX', 4), irReg('eax', 4));
    expect(cond).toEqual(irBinary('==', irReg('EAX', 4), irConst(0, 4)));
  });

  it('builds a masked comparison for `test X, imm`', () => {
    const cond = afterTest('jne', irReg('eax', 4), irConst(0x10));
    expect(cond).toEqual(
      irBinary('!=', irBinary('&', irReg('eax', 4), irConst(0x10)), irConst(0, 4)),
    );
  });

  it('treats two distinct registers as a mask, not a self-test', () => {
    const cond = afterTest('je', irReg('eax', 4), irReg('ebx', 4));
    expect(cond).toEqual(
      irBinary('==', irBinary('&', irReg('eax', 4), irReg('ebx', 4)), irConst(0, 4)),
    );
  });

  it('treats equal constants as a self-test', () => {
    const cond = afterTest('je', irConst(3), irConst(3));
    expect(cond).toEqual(irBinary('==', irConst(3), irConst(0, 4)));
  });

  it('maps js/jns to a sign test on the masked value', () => {
    const cond = afterTest('js', irReg('eax', 4), irConst(0x80));
    expect(cond).toEqual(
      irBinary('<', irBinary('&', irReg('eax', 4), irConst(0x80)), irConst(0, 4)),
    );
  });

  it('returns unknown for a jcc with no meaning after test', () => {
    // jle depends on SF/OF, which `test` clears — there is no sound translation.
    const cond = afterTest('jle', irReg('eax', 4), irReg('eax', 4));
    expect(cond).toEqual({ kind: 'unknown', text: 'jle after test' });
  });
});

describe('RegState.negate', () => {
  const a = irReg('eax', 4);
  const b = irConst(1);

  it('flips each comparison operator to its complement', () => {
    const flips: [BinaryOp, BinaryOp][] = [
      ['==', '!='], ['!=', '=='],
      ['<', '>='], ['>=', '<'],
      ['>', '<='], ['<=', '>'],
      ['u<', 'u>='], ['u>=', 'u<'],
      ['u>', 'u<='], ['u<=', 'u>'],
    ];
    for (const [op, expected] of flips) {
      const neg = RegState.negate(irBinary(op, a, b));
      expect((neg as { op: string }).op, op).toBe(expected);
    }
  });

  it('applies De Morgan to &&', () => {
    const cond = irBinary('&&', irBinary('==', a, b), irBinary('<', a, b));
    expect(RegState.negate(cond)).toEqual(
      irBinary('||', irBinary('!=', a, b), irBinary('>=', a, b)),
    );
  });

  it('applies De Morgan to ||', () => {
    const cond = irBinary('||', irBinary('==', a, b), irBinary('<', a, b));
    expect(RegState.negate(cond)).toEqual(
      irBinary('&&', irBinary('!=', a, b), irBinary('>=', a, b)),
    );
  });

  it('is an involution on comparisons', () => {
    const cond = irBinary('u<=', a, b);
    expect(RegState.negate(RegState.negate(cond))).toEqual(cond);
  });

  it('wraps a non-comparison in a logical not', () => {
    expect(RegState.negate(a)).toEqual(irUnary('!', a));
    expect(RegState.negate({ kind: 'unknown', text: 'jp' })).toEqual(
      irUnary('!', { kind: 'unknown', text: 'jp' }),
    );
  });

  it('wraps an arithmetic binary rather than flipping it', () => {
    const sum = irBinary('+', a, b);
    expect(RegState.negate(sum)).toEqual(irUnary('!', sum));
  });
});

describe('RegState.invalidateCallerSaved', () => {
  it('drops the volatile x64 registers', () => {
    const st = new RegState();
    for (const r of ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']) st.set(r, irConst(1));
    st.invalidateCallerSaved();
    for (const r of ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']) {
      expect(st.get(r), r).toBeUndefined();
    }
  });

  it('keeps the non-volatile registers', () => {
    const st = new RegState();
    for (const r of ['rbx', 'rbp', 'rsi', 'rdi', 'rsp', 'r12', 'r13', 'r14', 'r15']) {
      st.set(r, irConst(1));
    }
    st.invalidateCallerSaved();
    for (const r of ['rbx', 'rbp', 'rsi', 'rdi', 'rsp', 'r12', 'r13', 'r14', 'r15']) {
      expect(st.get(r), r).toEqual(irConst(1));
    }
  });

  it('clears the flag state so a following jcc is unknown', () => {
    const st = new RegState();
    st.setFlags('cmp', irReg('eax', 4), irConst(0));
    st.invalidateCallerSaved();
    expect(st.getCondition('je')).toEqual({ kind: 'unknown', text: 'je' });
  });

  // KNOWN BUG (reported, not fixed here): the lifter stores defs under the literal
  // operand name ('eax', 'ecx', 'r8d'), but invalidateCallerSaved only deletes the
  // 64-bit names. A stale sub-register value therefore survives a call and can be
  // folded into code after it. This is total in 32-bit mode, where every def is
  // stored as eax/ecx/edx/…
  it('fails to drop 32-bit sub-registers of the volatile registers', () => {
    const st = new RegState();
    st.set('ecx', irConst(0x1234));
    st.set('eax', irConst(1));
    st.set('r8d', irConst(2));
    st.invalidateCallerSaved();
    expect(st.get('ecx')).toEqual(irConst(0x1234)); // should be undefined
    expect(st.get('eax')).toEqual(irConst(1)); // should be undefined
    expect(st.get('r8d')).toEqual(irConst(2)); // should be undefined
  });
});

describe('RegState.clone', () => {
  it('copies definitions and flag state', () => {
    const st = new RegState();
    st.set('rax', irConst(9));
    st.setFlags('cmp', irReg('rax', 8), irConst(0));
    const copy = st.clone();
    expect(copy.get('rax')).toEqual(irConst(9));
    expect(copy.getCondition('je')).toEqual(irBinary('==', irReg('rax', 8), irConst(0)));
  });

  it('does not share the definition map with the original', () => {
    const st = new RegState();
    st.set('rax', irConst(1));
    const copy = st.clone();
    copy.set('rax', irConst(2));
    copy.set('rbx', irConst(3));
    expect(st.get('rax')).toEqual(irConst(1));
    expect(st.get('rbx')).toBeUndefined();
  });

  it('does not share flag state with the original', () => {
    const st = new RegState();
    st.setFlags('cmp', irReg('rax', 8), irConst(0));
    const copy = st.clone();
    copy.invalidateCallerSaved();
    expect(st.getCondition('je').kind).toBe('binary');
  });
});
