import { describe, it, expect } from 'vitest';
import { foldBlock } from '../fold';
import { irConst, irReg, irBinary, irUnary } from '../ir';
import type { IRStmt, IRExpr } from '../ir';

function assign(dest: IRExpr, src: IRExpr): IRStmt {
  return { kind: 'assign', dest, src };
}

function foldExprVia(src: IRExpr): IRExpr {
  const stmts = foldBlock([assign(irReg('rax'), src)]);
  return stmts.length > 0 && stmts[0].kind === 'assign' ? stmts[0].src : src;
}

describe('fold rules', () => {
  describe('div/mod folding', () => {
    it('folds const / const', () => {
      const result = foldExprVia(irBinary('/', irConst(10), irConst(3)));
      expect(result).toEqual(irConst(3, 4));
    });

    it('folds const % const', () => {
      const result = foldExprVia(irBinary('%', irConst(10), irConst(3)));
      expect(result).toEqual(irConst(1, 4));
    });

    it('skips division by zero', () => {
      const result = foldExprVia(irBinary('/', irConst(10), irConst(0)));
      expect(result.kind).toBe('binary');
    });
  });

  describe('comparison folding', () => {
    it('folds const == const (true)', () => {
      const result = foldExprVia(irBinary('==', irConst(5), irConst(5)));
      expect(result).toEqual(irConst(1, 4));
    });

    it('folds const == const (false)', () => {
      const result = foldExprVia(irBinary('==', irConst(5), irConst(3)));
      expect(result).toEqual(irConst(0, 4));
    });

    it('folds const < const', () => {
      const result = foldExprVia(irBinary('<', irConst(3), irConst(5)));
      expect(result).toEqual(irConst(1, 4));
    });

    it('folds const >= const', () => {
      const result = foldExprVia(irBinary('>=', irConst(3), irConst(5)));
      expect(result).toEqual(irConst(0, 4));
    });
  });

  describe('ternary simplification', () => {
    it('cond ? X : X → X', () => {
      const expr: IRExpr = { kind: 'ternary', condition: irReg('eax'), then: irConst(42), else: irConst(42) };
      const result = foldExprVia(expr);
      expect(result).toEqual(irConst(42, 4));
    });

    it('1 ? A : B → A', () => {
      const expr: IRExpr = { kind: 'ternary', condition: irConst(1), then: irConst(10), else: irConst(20) };
      const result = foldExprVia(expr);
      expect(result).toEqual(irConst(10, 4));
    });

    it('0 ? A : B → B', () => {
      const expr: IRExpr = { kind: 'ternary', condition: irConst(0), then: irConst(10), else: irConst(20) };
      const result = foldExprVia(expr);
      expect(result).toEqual(irConst(20, 4));
    });
  });

  describe('sign-extend patterns', () => {
    it('(x << 24) >> 24 → (int8_t)x', () => {
      const expr = irBinary('>>', irBinary('<<', irReg('eax'), irConst(24)), irConst(24));
      const result = foldExprVia(expr);
      expect(result.kind).toBe('cast');
      if (result.kind === 'cast') {
        expect(result.type).toBe('int8_t');
      }
    });

    it('(x << 16) >> 16 → (int16_t)x', () => {
      const expr = irBinary('>>', irBinary('<<', irReg('eax'), irConst(16)), irConst(16));
      const result = foldExprVia(expr);
      expect(result.kind).toBe('cast');
      if (result.kind === 'cast') {
        expect(result.type).toBe('int16_t');
      }
    });
  });

  describe('strength reduction', () => {
    it('x * 2 → x << 1', () => {
      const result = foldExprVia(irBinary('*', irReg('eax'), irConst(2)));
      expect(result.kind).toBe('binary');
      if (result.kind === 'binary') {
        expect(result.op).toBe('<<');
        expect(result.right).toEqual(irConst(1, 4));
      }
    });

    it('x * 8 → x << 3', () => {
      const result = foldExprVia(irBinary('*', irReg('eax'), irConst(8)));
      expect(result.kind).toBe('binary');
      if (result.kind === 'binary') {
        expect(result.op).toBe('<<');
        expect(result.right).toEqual(irConst(3, 4));
      }
    });

    it('x / 4 → x >>> 2', () => {
      const result = foldExprVia(irBinary('/', irReg('eax'), irConst(4)));
      expect(result.kind).toBe('binary');
      if (result.kind === 'binary') {
        expect(result.op).toBe('>>>');
        expect(result.right).toEqual(irConst(2, 4));
      }
    });

    it('x % 4 → x & 3', () => {
      const result = foldExprVia(irBinary('%', irReg('eax'), irConst(4)));
      expect(result.kind).toBe('binary');
      if (result.kind === 'binary') {
        expect(result.op).toBe('&');
        expect(result.right).toEqual(irConst(3, 4));
      }
    });
  });

  describe('double-cast removal', () => {
    it('(int8_t)(int32_t)x → (int8_t)x', () => {
      const expr: IRExpr = { kind: 'cast', type: 'int8_t', operand: { kind: 'cast', type: 'int32_t', operand: irReg('eax') } };
      const result = foldExprVia(expr);
      expect(result.kind).toBe('cast');
      if (result.kind === 'cast') {
        expect(result.type).toBe('int8_t');
        expect(result.operand.kind).toBe('reg');
      }
    });
  });

  describe('negation absorption', () => {
    it('!(x == y) → x != y', () => {
      const result = foldExprVia(irUnary('!', irBinary('==', irReg('eax'), irReg('ebx'))));
      expect(result.kind).toBe('binary');
      if (result.kind === 'binary') {
        expect(result.op).toBe('!=');
      }
    });

    it('!(x < y) → x >= y', () => {
      const result = foldExprVia(irUnary('!', irBinary('<', irReg('eax'), irReg('ebx'))));
      expect(result.kind).toBe('binary');
      if (result.kind === 'binary') {
        expect(result.op).toBe('>=');
      }
    });

    it('!(x u> y) → x u<= y', () => {
      const result = foldExprVia(irUnary('!', irBinary('u>', irReg('eax'), irReg('ebx'))));
      expect(result.kind).toBe('binary');
      if (result.kind === 'binary') {
        expect(result.op).toBe('u<=');
      }
    });
  });
});
