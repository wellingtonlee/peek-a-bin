import { describe, it, expect } from 'vitest';
import type { IRTry, IRStmt } from '../ir';
import { walkStmts, irConst, irReg } from '../ir';
import { emitFunction } from '../emit';
import type { IRFunction } from '../ir';

describe('Exception Handling IR', () => {
  it('walkStmts should traverse try body and handler', () => {
    const tryStmt: IRTry = {
      kind: 'try',
      body: [
        { kind: 'assign', dest: irReg('eax'), src: irConst(1), addr: 0x1000 },
      ],
      handler: [
        { kind: 'assign', dest: irReg('eax'), src: irConst(0), addr: 0x2000 },
      ],
      filterExpr: irConst(1),
    };

    const visited: string[] = [];
    walkStmts([tryStmt], (expr) => {
      if (expr.kind === 'const') visited.push(`const:${expr.value}`);
      if (expr.kind === 'reg') visited.push(`reg:${expr.name}`);
    });

    // Should visit: dest+src in body (eax, 1), dest+src in handler (eax, 0), filterExpr (1)
    expect(visited).toContain('reg:eax');
    expect(visited).toContain('const:1');
    expect(visited).toContain('const:0');
  });

  it('emitFunction should emit __try/__except blocks', () => {
    const tryStmt: IRTry = {
      kind: 'try',
      body: [
        { kind: 'assign', dest: irReg('eax'), src: irConst(42), addr: 0x1000 },
      ],
      handler: [
        { kind: 'assign', dest: irReg('eax'), src: irConst(0), addr: 0x2000 },
      ],
    };

    const func: IRFunction = {
      name: 'test_func',
      address: 0x1000,
      returnType: 'void',
      params: [],
      locals: [],
      body: [tryStmt],
    };

    const result = emitFunction(func);
    expect(result.code).toContain('__try');
    expect(result.code).toContain('__except');
    expect(result.code).toContain('EXCEPTION_EXECUTE_HANDLER');
    expect(result.code).toContain('eax = 0x2A');
  });

  it('emitFunction should emit filter expression when provided', () => {
    const tryStmt: IRTry = {
      kind: 'try',
      body: [
        { kind: 'raw', text: 'risky_call()', addr: 0x1000 },
      ],
      handler: [
        { kind: 'raw', text: 'handle_error()', addr: 0x2000 },
      ],
      filterExpr: irConst(1),
    };

    const func: IRFunction = {
      name: 'test_func',
      address: 0x1000,
      returnType: 'void',
      params: [],
      locals: [],
      body: [tryStmt],
    };

    const result = emitFunction(func);
    expect(result.code).toContain('__except(1)');
  });
});
