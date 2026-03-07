import type { IRStmt, IRExpr, BinaryOp } from './ir';
import { walkStmts, canonReg } from './ir';
import { API_TYPES } from './apitypes';

// ── Type Lattice ──

export type DecompType =
  | { kind: 'unknown' }
  | { kind: 'int'; size: number; signed: boolean }
  | { kind: 'float'; size: number }
  | { kind: 'ptr'; pointee: DecompType }
  | { kind: 'bool' }
  | { kind: 'void' }
  | { kind: 'struct'; id: string }
  | { kind: 'array'; element: DecompType; count: number }
  | { kind: 'handle' }
  | { kind: 'ntstatus' }
  | { kind: 'hresult' };

export interface TypeContext {
  /** Map of variable/register name → inferred type */
  types: Map<string, DecompType>;
}

/** Format a DecompType to a C-style string. */
export function typeToString(t: DecompType): string {
  switch (t.kind) {
    case 'unknown': return 'int';
    case 'void': return 'void';
    case 'bool': return 'BOOL';
    case 'float': return t.size === 4 ? 'float' : 'double';
    case 'ptr':
      if (t.pointee.kind === 'unknown') return 'PVOID';
      if (t.pointee.kind === 'int' && t.pointee.size === 1 && t.pointee.signed) return 'char*';
      if (t.pointee.kind === 'int' && t.pointee.size === 2 && !t.pointee.signed) return 'wchar_t*';
      return `${typeToString(t.pointee)}*`;
    case 'int':
      if (t.size === 1) return t.signed ? 'int8_t' : 'uint8_t';
      if (t.size === 2) return t.signed ? 'int16_t' : 'uint16_t';
      if (t.size === 4) return t.signed ? 'int32_t' : 'uint32_t';
      if (t.size === 8) return t.signed ? 'int64_t' : 'uint64_t';
      return t.signed ? 'int' : 'unsigned int';
    case 'struct':
      return `${t.id}*`;
    case 'array':
      return `${typeToString(t.element)}[${t.count || ''}]`;
    case 'handle':
      return 'HANDLE';
    case 'ntstatus':
      return 'NTSTATUS';
    case 'hresult':
      return 'HRESULT';
  }
}

/** Lattice meet: merge two types (more specific wins). */
export function meetTypes(a: DecompType, b: DecompType): DecompType {
  if (a.kind === 'unknown') return b;
  if (b.kind === 'unknown') return a;
  if (a.kind === b.kind) {
    if (a.kind === 'int' && b.kind === 'int') {
      return {
        kind: 'int',
        size: Math.max(a.size, b.size),
        signed: a.signed || b.signed, // signed wins
      };
    }
    if (a.kind === 'float' && b.kind === 'float') {
      return { kind: 'float', size: Math.max(a.size, b.size) };
    }
    if (a.kind === 'struct' && b.kind === 'struct') {
      return a.id === b.id ? a : { kind: 'unknown' };
    }
    if (a.kind === 'array' && b.kind === 'array') {
      return { kind: 'array', element: meetTypes(a.element, b.element), count: Math.max(a.count, b.count) };
    }
    return a;
  }
  // handle vs ptr → handle wins
  if (a.kind === 'handle' && b.kind === 'ptr') return a;
  if (b.kind === 'handle' && a.kind === 'ptr') return b;
  // ntstatus/hresult vs int → ntstatus/hresult wins
  if (a.kind === 'ntstatus' && b.kind === 'int') return a;
  if (b.kind === 'ntstatus' && a.kind === 'int') return b;
  if (a.kind === 'hresult' && b.kind === 'int') return a;
  if (b.kind === 'hresult' && a.kind === 'int') return b;
  // handle vs int → handle wins
  if (a.kind === 'handle' && b.kind === 'int') return a;
  if (b.kind === 'handle' && a.kind === 'int') return b;
  // ptr vs int → ptr wins
  if (a.kind === 'ptr') return a;
  if (b.kind === 'ptr') return b;
  // bool vs int → int wins
  if (a.kind === 'bool' && b.kind === 'int') return b;
  if (a.kind === 'int' && b.kind === 'bool') return a;
  return a;
}

// ── Signed/unsigned Jcc sets ──
const SIGNED_OPS = new Set<BinaryOp>(['<', '<=', '>', '>=']);
const UNSIGNED_OPS = new Set<BinaryOp>(['u<', 'u<=', 'u>', 'u>=']);

// ── XMM / FPU register prefixes ──
function isFloatReg(name: string): boolean {
  const lower = name.toLowerCase();
  return lower.startsWith('xmm') || lower.startsWith('st');
}

/**
 * Infer types for variables and registers from the structured IR body.
 * Forward + backward propagation to fixpoint.
 */
export function inferTypes(
  body: IRStmt[],
  iatMap: Map<number, { lib: string; func: string }>,
): TypeContext {
  const types = new Map<string, DecompType>();

  function setType(name: string, t: DecompType) {
    const canon = canonReg(name);
    const existing = types.get(canon);
    if (!existing) {
      types.set(canon, t);
    } else {
      types.set(canon, meetTypes(existing, t));
    }
  }

  function getType(name: string): DecompType {
    return types.get(canonReg(name)) ?? { kind: 'unknown' };
  }

  // Forward pass: walk all statements and infer types from operations
  walkStmts(body, (expr) => {
    // Cast → source type hint
    if (expr.kind === 'cast') {
      const castType = parseCastType(expr.type);
      if (castType && expr.operand.kind === 'reg') {
        setType(expr.operand.name, castType);
      }
      if (castType && expr.operand.kind === 'var') {
        setType(expr.operand.name, castType);
      }
    }

    // movzx result → unsigned
    // movsx result → signed
    // (Already handled by cast)

    // LEA result → pointer
    // Deref address → must be pointer
    if (expr.kind === 'deref') {
      if (expr.address.kind === 'reg') {
        setType(expr.address.name, { kind: 'ptr', pointee: { kind: 'unknown' } });
      }
      if (expr.address.kind === 'var') {
        setType(expr.address.name, { kind: 'ptr', pointee: { kind: 'unknown' } });
      }
    }

    // Field access base → ptr<struct>
    if (expr.kind === 'field_access') {
      const base = expr.base;
      if (base.kind === 'reg') {
        setType(base.name, { kind: 'ptr', pointee: { kind: 'struct', id: expr.structId } });
      }
      if (base.kind === 'var') {
        setType(base.name, { kind: 'ptr', pointee: { kind: 'struct', id: expr.structId } });
      }
    }

    // Array access base → pointer
    if (expr.kind === 'array_access') {
      const base = expr.base;
      if (base.kind === 'reg') {
        setType(base.name, { kind: 'ptr', pointee: { kind: 'unknown' } });
      }
      if (base.kind === 'var') {
        setType(base.name, { kind: 'ptr', pointee: { kind: 'unknown' } });
      }
    }

    // Float registers → float type
    if (expr.kind === 'reg' && isFloatReg(expr.name)) {
      setType(expr.name, { kind: 'float', size: expr.name.startsWith('xmm') ? 4 : 8 });
    }

    // Comparison result → bool (for setcc assignments)
    if (expr.kind === 'binary') {
      const op = expr.op;
      if (op === '==' || op === '!=' || SIGNED_OPS.has(op) || UNSIGNED_OPS.has(op)) {
        // The result of this comparison is a bool (for the enclosing assign)
        // Backward: signed comparisons imply signed operands
        if (SIGNED_OPS.has(op)) {
          if (expr.left.kind === 'reg') setType(expr.left.name, { kind: 'int', size: 4, signed: true });
          if (expr.right.kind === 'reg') setType(expr.right.name, { kind: 'int', size: 4, signed: true });
          if (expr.left.kind === 'var') setType(expr.left.name, { kind: 'int', size: 4, signed: true });
          if (expr.right.kind === 'var') setType(expr.right.name, { kind: 'int', size: 4, signed: true });
        }
        if (UNSIGNED_OPS.has(op)) {
          if (expr.left.kind === 'reg') setType(expr.left.name, { kind: 'int', size: 4, signed: false });
          if (expr.right.kind === 'reg') setType(expr.right.name, { kind: 'int', size: 4, signed: false });
          if (expr.left.kind === 'var') setType(expr.left.name, { kind: 'int', size: 4, signed: false });
          if (expr.right.kind === 'var') setType(expr.right.name, { kind: 'int', size: 4, signed: false });
        }
      }
    }
  });

  // API call pass: infer types from known API signatures
  inferFromAPICalls(body, types);

  return { types };
}

function inferFromAPICalls(
  body: IRStmt[],
  types: Map<string, DecompType>,
): void {
  function processStmts(stmts: IRStmt[]) {
    for (const s of stmts) {
      if (s.kind === 'call_stmt') {
        const funcName = s.call.display?.split('!')?.pop() ?? s.call.target;
        const apiType = API_TYPES[funcName];
        if (apiType) {
          // Infer return type
          if (s.resultDest?.kind === 'reg') {
            const canon = canonReg(s.resultDest.name);
            const existing = types.get(canon);
            if (!existing || existing.kind === 'unknown') {
              types.set(canon, apiType.returnType);
            }
          }
          // Infer param types
          for (let i = 0; i < Math.min(s.call.args.length, apiType.params.length); i++) {
            const arg = s.call.args[i];
            if (arg.kind === 'reg') {
              const canon = canonReg(arg.name);
              const existing = types.get(canon);
              if (!existing || existing.kind === 'unknown') {
                types.set(canon, apiType.params[i]);
              }
            }
            if (arg.kind === 'var') {
              const existing = types.get(arg.name);
              if (!existing || existing.kind === 'unknown') {
                types.set(arg.name, apiType.params[i]);
              }
            }
          }
        }
      }
      // Recurse into nested statements
      if (s.kind === 'if') {
        processStmts(s.thenBody);
        if (s.elseBody) processStmts(s.elseBody);
      }
      if (s.kind === 'while' || s.kind === 'do_while') processStmts(s.body);
      if (s.kind === 'for') processStmts(s.body);
      if (s.kind === 'switch') {
        s.cases.forEach(c => processStmts(c.body));
        if (s.defaultBody) processStmts(s.defaultBody);
      }
    }
  }
  processStmts(body);
}

function parseCastType(typeStr: string): DecompType | null {
  switch (typeStr) {
    case 'int8_t': return { kind: 'int', size: 1, signed: true };
    case 'uint8_t': return { kind: 'int', size: 1, signed: false };
    case 'int16_t': return { kind: 'int', size: 2, signed: true };
    case 'uint16_t': return { kind: 'int', size: 2, signed: false };
    case 'int32_t': return { kind: 'int', size: 4, signed: true };
    case 'uint32_t': return { kind: 'int', size: 4, signed: false };
    case 'int64_t': return { kind: 'int', size: 8, signed: true };
    case 'uint64_t': return { kind: 'int', size: 8, signed: false };
    default: return null;
  }
}
