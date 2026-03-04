import type { StackFrame } from '../types';
import type { FunctionSignature } from '../signatures';
import type { IRExpr, IRStmt, IRFunction, IRLocal, IRParam } from './ir';
import { irVar, canonReg } from './ir';

// ── Size → C type mapping ──

function sizeToType(size: number): string {
  switch (size) {
    case 1: return 'uint8_t';
    case 2: return 'uint16_t';
    case 4: return 'int32_t';
    case 8: return 'int64_t';
    default: return 'int32_t';
  }
}

// ── Stack access pattern matching ──

/** Check if expr is [rbp - const] or [rsp + const] and return the offset. */
function matchStackAccess(expr: IRExpr, is64: boolean): { offset: number; isParam: boolean } | null {
  if (expr.kind !== 'deref') return null;
  const addr = expr.address;

  const bp = is64 ? 'rbp' : 'ebp';
  const sp = is64 ? 'rsp' : 'esp';

  // [rbp - offset] → local
  if (addr.kind === 'binary' && addr.op === '-' &&
      addr.left.kind === 'reg' && addr.left.name.toLowerCase() === bp &&
      addr.right.kind === 'const') {
    return { offset: addr.right.value, isParam: false };
  }

  // [rbp + offset] → param (if offset >= threshold)
  if (addr.kind === 'binary' && addr.op === '+' &&
      addr.left.kind === 'reg' && addr.left.name.toLowerCase() === bp &&
      addr.right.kind === 'const') {
    const minParam = is64 ? 0x10 : 0x8;
    if (addr.right.value >= minParam) return { offset: addr.right.value, isParam: true };
  }

  // [rsp + offset] → local
  if (addr.kind === 'binary' && addr.op === '+' &&
      addr.left.kind === 'reg' && addr.left.name.toLowerCase() === sp &&
      addr.right.kind === 'const') {
    return { offset: addr.right.value, isParam: false };
  }

  // Direct register (rbp/rsp alone) with const
  if (addr.kind === 'reg') {
    const name = addr.name.toLowerCase();
    if (name === bp || name === sp) return { offset: 0, isParam: false };
  }

  return null;
}

// ── Expression / Statement rewriting ──

function promoteExpr(
  expr: IRExpr,
  is64: boolean,
  varLookup: Map<number, string>,
  paramLookup: Map<number, string>,
): IRExpr {
  // Check if this is a stack variable deref
  const stackAccess = matchStackAccess(expr, is64);
  if (stackAccess) {
    const lookup = stackAccess.isParam ? paramLookup : varLookup;
    const name = lookup.get(stackAccess.offset);
    if (name) {
      return irVar(name, expr.kind === 'deref' ? expr.size : 4);
    }
  }

  switch (expr.kind) {
    case 'binary':
      return { ...expr, left: promoteExpr(expr.left, is64, varLookup, paramLookup), right: promoteExpr(expr.right, is64, varLookup, paramLookup) };
    case 'unary':
      return { ...expr, operand: promoteExpr(expr.operand, is64, varLookup, paramLookup) };
    case 'deref':
      return { ...expr, address: promoteExpr(expr.address, is64, varLookup, paramLookup) };
    case 'call':
      return { ...expr, args: expr.args.map(a => promoteExpr(a, is64, varLookup, paramLookup)) };
    case 'ternary':
      return {
        ...expr,
        condition: promoteExpr(expr.condition, is64, varLookup, paramLookup),
        then: promoteExpr(expr.then, is64, varLookup, paramLookup),
        else: promoteExpr(expr.else, is64, varLookup, paramLookup),
      };
    case 'cast':
      return { ...expr, operand: promoteExpr(expr.operand, is64, varLookup, paramLookup) };
    default:
      return expr;
  }
}

function promoteStmt(
  stmt: IRStmt,
  is64: boolean,
  varLookup: Map<number, string>,
  paramLookup: Map<number, string>,
): IRStmt {
  switch (stmt.kind) {
    case 'assign': {
      const dest = promoteExpr(stmt.dest, is64, varLookup, paramLookup);
      const src = promoteExpr(stmt.src, is64, varLookup, paramLookup);
      return { ...stmt, dest, src };
    }
    case 'store': {
      // Check if store target is a stack variable
      const stackAccess = matchStackAccess({ kind: 'deref', address: stmt.address, size: stmt.size }, is64);
      if (stackAccess) {
        const lookup = stackAccess.isParam ? paramLookup : varLookup;
        const name = lookup.get(stackAccess.offset);
        if (name) {
          // Convert store to assign to variable
          return {
            kind: 'assign',
            dest: irVar(name, stmt.size),
            src: promoteExpr(stmt.value, is64, varLookup, paramLookup),
            addr: stmt.addr,
          };
        }
      }
      return { ...stmt, address: promoteExpr(stmt.address, is64, varLookup, paramLookup), value: promoteExpr(stmt.value, is64, varLookup, paramLookup) };
    }
    case 'call_stmt':
      return { ...stmt, call: promoteExpr(stmt.call, is64, varLookup, paramLookup) as IRExpr & { kind: 'call' } };
    case 'return':
      return stmt.value ? { ...stmt, value: promoteExpr(stmt.value, is64, varLookup, paramLookup) } : stmt;
    case 'if':
      return {
        ...stmt,
        condition: promoteExpr(stmt.condition, is64, varLookup, paramLookup),
        thenBody: stmt.thenBody.map(s => promoteStmt(s, is64, varLookup, paramLookup)),
        elseBody: stmt.elseBody?.map(s => promoteStmt(s, is64, varLookup, paramLookup)),
      };
    case 'while':
      return {
        ...stmt,
        condition: promoteExpr(stmt.condition, is64, varLookup, paramLookup),
        body: stmt.body.map(s => promoteStmt(s, is64, varLookup, paramLookup)),
      };
    case 'do_while':
      return {
        ...stmt,
        condition: promoteExpr(stmt.condition, is64, varLookup, paramLookup),
        body: stmt.body.map(s => promoteStmt(s, is64, varLookup, paramLookup)),
      };
    case 'switch':
      return {
        ...stmt,
        expr: promoteExpr(stmt.expr, is64, varLookup, paramLookup),
        cases: stmt.cases.map(c => ({ ...c, body: c.body.map(s => promoteStmt(s, is64, varLookup, paramLookup)) })),
        defaultBody: stmt.defaultBody?.map(s => promoteStmt(s, is64, varLookup, paramLookup)),
      };
    default:
      return stmt;
  }
}

// ── Detect whether function writes to return register before ret ──

function hasReturnValue(body: IRStmt[]): boolean {
  for (const stmt of body) {
    if (stmt.kind === 'return' && stmt.value) {
      // Check if value is a call result or non-trivial expression
      if (stmt.value.kind !== 'reg') return true;
      // Even a bare register return counts
      return true;
    }
    if (stmt.kind === 'if') {
      if (hasReturnValue(stmt.thenBody)) return true;
      if (stmt.elseBody && hasReturnValue(stmt.elseBody)) return true;
    }
    if (stmt.kind === 'while' || stmt.kind === 'do_while') {
      if (hasReturnValue(stmt.body)) return true;
    }
  }
  return false;
}

const FASTCALL_REGS = ['rcx', 'rdx', 'r8', 'r9'];

/**
 * Promote stack variable references to named variables and
 * build function signature from stack frame + signature analysis.
 */
export function promoteVars(
  name: string,
  address: number,
  body: IRStmt[],
  stackFrame: StackFrame | null,
  signature: FunctionSignature | null,
  is64: boolean,
): IRFunction {
  // Build lookup maps from stack frame vars
  const varLookup = new Map<number, string>();  // offset → var name (locals)
  const paramLookup = new Map<number, string>(); // offset → param name
  const locals: IRLocal[] = [];
  const params: IRParam[] = [];

  if (stackFrame) {
    for (const v of stackFrame.vars) {
      const type = sizeToType(v.size);
      if (v.name.startsWith('arg_')) {
        paramLookup.set(v.offset, v.name);
        params.push({ name: v.name, type });
      } else {
        varLookup.set(v.offset, v.name);
        locals.push({ name: v.name, type });
      }
    }
  }

  // For x64 fastcall: add register params
  if (is64 && signature && signature.paramCount > 0) {
    for (let i = 0; i < Math.min(signature.paramCount, 4); i++) {
      const paramName = `arg${i}`;
      // Only add if not already present from stack frame
      if (!params.some(p => p.name === paramName)) {
        params.push({ name: paramName, type: 'int64_t' });
      }
    }
  }

  // Promote body
  const promoted = body.map(s => promoteStmt(s, is64, varLookup, paramLookup));

  // Filter out register assignments that are just param saves (mov [rsp+shadow], rcx/rdx/r8/r9)
  // These are captured in params already

  // Determine return type
  const returnType = hasReturnValue(promoted) ? 'int' : 'void';

  return {
    name,
    address,
    returnType,
    params,
    locals,
    body: promoted,
  };
}
