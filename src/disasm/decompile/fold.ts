import type { IRExpr, IRStmt, BinaryOp } from './ir';
import { irConst, canonReg } from './ir';

/** Shallow structural equality for simple expressions (reg, const, var). */
function exprEq(a: IRExpr, b: IRExpr): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'const' && b.kind === 'const') return a.value === b.value;
  if (a.kind === 'reg' && b.kind === 'reg') return canonReg(a.name) === canonReg(b.name);
  if (a.kind === 'var' && b.kind === 'var') return a.name === b.name;
  if (a.kind === 'binary' && b.kind === 'binary')
    return a.op === b.op && exprEq(a.left, b.left) && exprEq(a.right, b.right);
  if (a.kind === 'unary' && b.kind === 'unary')
    return a.op === b.op && exprEq(a.operand, b.operand);
  return false;
}

// ── Constant Folding ──

function foldExpr(expr: IRExpr): IRExpr {
  if (expr.kind === 'binary') {
    const left = foldExpr(expr.left);
    const right = foldExpr(expr.right);

    // Constant folding: both sides constant
    if (left.kind === 'const' && right.kind === 'const') {
      const l = left.value;
      const r = right.value;
      let result: number | null = null;
      switch (expr.op) {
        case '+': result = l + r; break;
        case '-': result = l - r; break;
        case '*': result = l * r; break;
        case '/': if (r !== 0) result = (l / r) | 0; break;
        case '%': if (r !== 0) result = l % r; break;
        case '&': result = l & r; break;
        case '|': result = l | r; break;
        case '^': result = l ^ r; break;
        case '<<': result = l << r; break;
        case '>>': result = l >> r; break;
        case '>>>': result = l >>> r; break;
        case '==': result = l === r ? 1 : 0; break;
        case '!=': result = l !== r ? 1 : 0; break;
        case '<': result = l < r ? 1 : 0; break;
        case '<=': result = l <= r ? 1 : 0; break;
        case '>': result = l > r ? 1 : 0; break;
        case '>=': result = l >= r ? 1 : 0; break;
        case 'u<': result = (l >>> 0) < (r >>> 0) ? 1 : 0; break;
        case 'u<=': result = (l >>> 0) <= (r >>> 0) ? 1 : 0; break;
        case 'u>': result = (l >>> 0) > (r >>> 0) ? 1 : 0; break;
        case 'u>=': result = (l >>> 0) >= (r >>> 0) ? 1 : 0; break;
      }
      if (result !== null) return irConst(result, left.size);
    }

    // Identity elimination
    if (right.kind === 'const') {
      // x + 0 → x
      if (expr.op === '+' && right.value === 0) return left;
      // x - 0 → x
      if (expr.op === '-' && right.value === 0) return left;
      // x * 1 → x
      if (expr.op === '*' && right.value === 1) return left;
      // x * 0 → 0
      if (expr.op === '*' && right.value === 0) return irConst(0, right.size);
      // x & 0xFFFFFFFF → x (32-bit mask on 32-bit value)
      if (expr.op === '&' && (right.value === 0xFFFFFFFF || right.value === -1)) return left;
      // x | 0 → x
      if (expr.op === '|' && right.value === 0) return left;
      // x ^ 0 → x
      if (expr.op === '^' && right.value === 0) return left;
      // x << 0 → x
      if ((expr.op === '<<' || expr.op === '>>' || expr.op === '>>>') && right.value === 0) return left;
    }

    if (left.kind === 'const') {
      // 0 + x → x
      if (expr.op === '+' && left.value === 0) return right;
      // 0 * x → 0
      if (expr.op === '*' && left.value === 0) return irConst(0, left.size);
      // 1 * x → x
      if (expr.op === '*' && left.value === 1) return right;
    }

    // Canonicalize: const OP var/reg → var/reg reversed_OP const
    if (left.kind === 'const' && right.kind !== 'const') {
      const flipMap: Partial<Record<BinaryOp, BinaryOp>> = {
        '==': '==', '!=': '!=',
        '<': '>', '>': '<', '<=': '>=', '>=': '<=',
        'u<': 'u>', 'u>': 'u<', 'u<=': 'u>=', 'u>=': 'u<=',
      };
      const flipped = flipMap[expr.op];
      if (flipped !== undefined) {
        return foldExpr({ kind: 'binary', op: flipped, left: right, right: left });
      }
    }

    // Same-operand patterns (after folding both sides)
    if (exprEq(left, right)) {
      // x - x → 0, x ^ x → 0
      if (expr.op === '-' || expr.op === '^') return irConst(0, 4);
      // x & x → x, x | x → x
      if (expr.op === '&' || expr.op === '|') return left;
    }

    // Additional constant-right patterns
    if (right.kind === 'const') {
      // x & 0 → 0
      if (expr.op === '&' && right.value === 0) return irConst(0, right.size);
      // x | 0xFFFFFFFF → 0xFFFFFFFF
      if (expr.op === '|' && (right.value === 0xFFFFFFFF || right.value === -1))
        return irConst(right.value, right.size);
      // Strength reduction: x * 2 → x << 1
      if (expr.op === '*' && right.value === 2)
        return { kind: 'binary', op: '<<', left, right: irConst(1, right.size) };
      // x * 4 → x << 2, x * 8 → x << 3
      if (expr.op === '*' && right.value > 0 && (right.value & (right.value - 1)) === 0) {
        const shift = Math.log2(right.value);
        if (Number.isInteger(shift) && shift <= 31)
          return { kind: 'binary', op: '<<', left, right: irConst(shift, right.size) };
      }
      // unsigned x / 2 → x >> 1 (only for power of 2)
      if (expr.op === '/' && right.value > 0 && (right.value & (right.value - 1)) === 0) {
        const shift = Math.log2(right.value);
        if (Number.isInteger(shift) && shift <= 31)
          return { kind: 'binary', op: '>>>', left, right: irConst(shift, right.size) };
      }
      // unsigned x % 2 → x & 1 (only for power of 2)
      if (expr.op === '%' && right.value > 0 && (right.value & (right.value - 1)) === 0)
        return { kind: 'binary', op: '&', left, right: irConst(right.value - 1, right.size) };
    }

    // Sign-extend patterns: (x << 24) >> 24 → (int8_t)x
    if (expr.op === '>>' && right.kind === 'const' &&
        left.kind === 'binary' && left.op === '<<' &&
        left.right.kind === 'const' && left.right.value === right.value) {
      const shift = right.value;
      if (shift === 24) return { kind: 'cast', type: 'int8_t', operand: left.left };
      if (shift === 16) return { kind: 'cast', type: 'int16_t', operand: left.left };
    }

    return { ...expr, left, right };
  }

  if (expr.kind === 'unary') {
    const operand = foldExpr(expr.operand);
    // Constant fold unary
    if (operand.kind === 'const') {
      switch (expr.op) {
        case '~': return irConst(~operand.value, operand.size);
        case '-': return irConst(-operand.value, operand.size);
        case '!': return irConst(operand.value ? 0 : 1, operand.size);
      }
    }
    // Double negation: !!x → x, ~~x → x, --x → x
    if (operand.kind === 'unary' && operand.op === expr.op && (expr.op === '!' || expr.op === '~' || expr.op === '-')) {
      return operand.operand;
    }
    // Negation absorption: !(x == y) → x != y, !(x < y) → x >= y, etc.
    if (expr.op === '!' && operand.kind === 'binary') {
      const negMap: Partial<Record<BinaryOp, BinaryOp>> = {
        '==': '!=', '!=': '==',
        '<': '>=', '>=': '<',
        '>': '<=', '<=': '>',
        'u<': 'u>=', 'u>=': 'u<',
        'u>': 'u<=', 'u<=': 'u>',
      };
      const neg = negMap[operand.op];
      if (neg) return { ...operand, op: neg };
      // De-Morgan: !(a && b) → !a || !b
      if (operand.op === '&&') {
        return foldExpr({
          kind: 'binary', op: '||',
          left: { kind: 'unary', op: '!', operand: operand.left },
          right: { kind: 'unary', op: '!', operand: operand.right },
        });
      }
      // De-Morgan: !(a || b) → !a && !b
      if (operand.op === '||') {
        return foldExpr({
          kind: 'binary', op: '&&',
          left: { kind: 'unary', op: '!', operand: operand.left },
          right: { kind: 'unary', op: '!', operand: operand.right },
        });
      }
    }
    return { ...expr, operand };
  }

  if (expr.kind === 'ternary') {
    const cond = foldExpr(expr.condition);
    const then = foldExpr(expr.then);
    const els = foldExpr(expr.else);
    // cond ? X : X → X
    if (exprEq(then, els)) return then;
    // 1 ? A : B → A
    if (cond.kind === 'const' && cond.value !== 0) return then;
    // 0 ? A : B → B
    if (cond.kind === 'const' && cond.value === 0) return els;
    return { ...expr, condition: cond, then, else: els };
  }

  // Cast simplification
  if (expr.kind === 'cast') {
    const operand = foldExpr(expr.operand);
    // Double-cast removal: (T2)(T1)x → (T2)x
    if (operand.kind === 'cast') {
      return { kind: 'cast', type: expr.type, operand: operand.operand };
    }
    // Cast on constant → fold away
    if (operand.kind === 'const') {
      return operand;
    }
    // Same-size cast on reg/var → strip
    const castSize = castTypeSize(expr.type);
    if ((operand.kind === 'reg' || operand.kind === 'var') && operand.size === castSize) {
      return operand;
    }
    return { ...expr, operand };
  }

  if (expr.kind === 'deref') {
    return { ...expr, address: foldExpr(expr.address) };
  }

  if (expr.kind === 'call') {
    return { ...expr, args: expr.args.map(foldExpr) };
  }

  if (expr.kind === 'field_access') {
    return { ...expr, base: foldExpr(expr.base) };
  }

  if (expr.kind === 'array_access') {
    return { ...expr, base: foldExpr(expr.base), index: foldExpr(expr.index) };
  }

  return expr;
}

function castTypeSize(typeStr: string): number {
  const m = typeStr.match(/(\d+)/);
  if (m) return parseInt(m[1], 10) / 8;
  return 4; // default
}

function foldStmt(stmt: IRStmt): IRStmt {
  switch (stmt.kind) {
    case 'assign':
      return { ...stmt, src: foldExpr(stmt.src) };
    case 'store':
      return { ...stmt, address: foldExpr(stmt.address), value: foldExpr(stmt.value) };
    case 'call_stmt':
      return { ...stmt, call: foldExpr(stmt.call) as IRExpr & { kind: 'call' } };
    case 'return':
      return stmt.value ? { ...stmt, value: foldExpr(stmt.value) } : stmt;
    case 'if':
      return { ...stmt, condition: foldExpr(stmt.condition), thenBody: stmt.thenBody.map(foldStmt), elseBody: stmt.elseBody?.map(foldStmt) };
    case 'while':
      return { ...stmt, condition: foldExpr(stmt.condition), body: stmt.body.map(foldStmt) };
    case 'do_while':
      return { ...stmt, condition: foldExpr(stmt.condition), body: stmt.body.map(foldStmt) };
    case 'switch':
      return { ...stmt, expr: foldExpr(stmt.expr), cases: stmt.cases.map(c => ({ ...c, body: c.body.map(foldStmt) })), defaultBody: stmt.defaultBody?.map(foldStmt) };
    case 'for':
      return { ...stmt, init: foldStmt(stmt.init), condition: foldExpr(stmt.condition), update: foldStmt(stmt.update), body: stmt.body.map(foldStmt) };
    case 'try':
      return { ...stmt, body: stmt.body.map(foldStmt), handler: stmt.handler.map(foldStmt), filterExpr: stmt.filterExpr ? foldExpr(stmt.filterExpr) : undefined };
    default:
      return stmt;
  }
}

// ── Register Substitution (Single-Use Inlining) ──

/** Count reads of a register in an expression. */
function countReads(expr: IRExpr, canon: string): number {
  switch (expr.kind) {
    case 'reg': return canonReg(expr.name) === canon ? 1 : 0;
    case 'binary': return countReads(expr.left, canon) + countReads(expr.right, canon);
    case 'unary': return countReads(expr.operand, canon);
    case 'deref': return countReads(expr.address, canon);
    case 'call': return expr.args.reduce((n, a) => n + countReads(a, canon), 0);
    case 'ternary': return countReads(expr.condition, canon) + countReads(expr.then, canon) + countReads(expr.else, canon);
    case 'cast': return countReads(expr.operand, canon);
    case 'field_access': return countReads(expr.base, canon);
    case 'array_access': return countReads(expr.base, canon) + countReads(expr.index, canon);
    default: return 0;
  }
}

function countReadsInStmt(stmt: IRStmt, canon: string): number {
  switch (stmt.kind) {
    case 'assign': return countReads(stmt.src, canon) + (stmt.dest.kind === 'deref' ? countReads(stmt.dest.address, canon) : 0);
    case 'store': return countReads(stmt.address, canon) + countReads(stmt.value, canon);
    case 'call_stmt': return stmt.call.args.reduce((n, a) => n + countReads(a, canon), 0);
    case 'return': return stmt.value ? countReads(stmt.value, canon) : 0;
    default: return 0;
  }
}

function substituteReg(expr: IRExpr, canon: string, replacement: IRExpr): IRExpr {
  switch (expr.kind) {
    case 'reg':
      return canonReg(expr.name) === canon ? replacement : expr;
    case 'binary':
      return { ...expr, left: substituteReg(expr.left, canon, replacement), right: substituteReg(expr.right, canon, replacement) };
    case 'unary':
      return { ...expr, operand: substituteReg(expr.operand, canon, replacement) };
    case 'deref':
      return { ...expr, address: substituteReg(expr.address, canon, replacement) };
    case 'call':
      return { ...expr, args: expr.args.map(a => substituteReg(a, canon, replacement)) };
    case 'ternary':
      return { ...expr, condition: substituteReg(expr.condition, canon, replacement), then: substituteReg(expr.then, canon, replacement), else: substituteReg(expr.else, canon, replacement) };
    case 'cast':
      return { ...expr, operand: substituteReg(expr.operand, canon, replacement) };
    case 'field_access':
      return { ...expr, base: substituteReg(expr.base, canon, replacement) };
    case 'array_access':
      return { ...expr, base: substituteReg(expr.base, canon, replacement), index: substituteReg(expr.index, canon, replacement) };
    default:
      return expr;
  }
}

function substituteRegInStmt(stmt: IRStmt, canon: string, replacement: IRExpr): IRStmt {
  switch (stmt.kind) {
    case 'assign': {
      const dest = stmt.dest.kind === 'deref'
        ? { ...stmt.dest, address: substituteReg(stmt.dest.address, canon, replacement) } as IRExpr
        : stmt.dest;
      return { ...stmt, dest, src: substituteReg(stmt.src, canon, replacement) };
    }
    case 'store':
      return { ...stmt, address: substituteReg(stmt.address, canon, replacement), value: substituteReg(stmt.value, canon, replacement) };
    case 'call_stmt':
      return { ...stmt, call: { ...stmt.call, args: stmt.call.args.map(a => substituteReg(a, canon, replacement)) } };
    case 'return':
      return stmt.value ? { ...stmt, value: substituteReg(stmt.value, canon, replacement) } : stmt;
    default:
      return stmt;
  }
}

/** Returns true if the expression might have side effects (calls). */
function hasSideEffects(expr: IRExpr): boolean {
  if (expr.kind === 'call') return true;
  if (expr.kind === 'binary') return hasSideEffects(expr.left) || hasSideEffects(expr.right);
  if (expr.kind === 'unary') return hasSideEffects(expr.operand);
  if (expr.kind === 'deref') return hasSideEffects(expr.address);
  if (expr.kind === 'ternary') return hasSideEffects(expr.condition) || hasSideEffects(expr.then) || hasSideEffects(expr.else);
  if (expr.kind === 'field_access') return hasSideEffects(expr.base);
  if (expr.kind === 'array_access') return hasSideEffects(expr.base) || hasSideEffects(expr.index);
  return false;
}

/**
 * Fold a flat list of IR statements within a single block:
 * - Constant fold
 * - Inline single-use register assignments
 * - Eliminate dead register stores
 */
export function foldBlock(stmts: IRStmt[]): IRStmt[] {
  // Pass 1: Constant fold
  let result = stmts.map(foldStmt);

  // Pass 2: Single-use register inlining
  // If reg = expr and reg is read exactly once in the next statement and not read again, inline.
  let changed = true;
  let passes = 0;
  while (changed && passes < 5) {
    changed = false;
    passes++;
    const next: IRStmt[] = [];
    for (let i = 0; i < result.length; i++) {
      const stmt = result[i];
      // Only inline register assignments (not memory stores, not calls)
      if (stmt.kind === 'assign' && stmt.dest.kind === 'reg' && !hasSideEffects(stmt.src)) {
        const canon = canonReg(stmt.dest.name);
        // Count total reads in remaining statements until next write to same register
        let totalReads = 0;
        let firstReadIdx = -1;
        let hitWrite = false;
        for (let j = i + 1; j < result.length; j++) {
          const s = result[j];
          const reads = countReadsInStmt(s, canon);
          if (reads > 0 && firstReadIdx < 0) firstReadIdx = j;
          totalReads += reads;
          // Check if this statement writes to the same register
          if (s.kind === 'assign' && s.dest.kind === 'reg' && canonReg(s.dest.name) === canon) {
            hitWrite = true;
            break;
          }
          if (s.kind === 'call_stmt') break; // calls clobber regs
        }
        if (totalReads === 1 && firstReadIdx >= 0) {
          // Inline: substitute into the statement that reads it
          result[firstReadIdx] = substituteRegInStmt(result[firstReadIdx], canon, stmt.src);
          changed = true;
          continue; // skip adding this assignment
        }
      }
      next.push(stmt);
    }
    result = next;
  }

  // Pass 3: Constant fold again after inlining
  result = result.map(foldStmt);

  return result;
}

// eliminateDeadStores removed — now handled by SSA dead code elimination
