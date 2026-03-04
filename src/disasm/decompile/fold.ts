import type { IRExpr, IRStmt } from './ir';
import { irConst, canonReg } from './ir';

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
        case '&': result = l & r; break;
        case '|': result = l | r; break;
        case '^': result = l ^ r; break;
        case '<<': result = l << r; break;
        case '>>': result = l >> r; break;
        case '>>>': result = l >>> r; break;
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
    return { ...expr, operand };
  }

  if (expr.kind === 'ternary') {
    return { ...expr, condition: foldExpr(expr.condition), then: foldExpr(expr.then), else: foldExpr(expr.else) };
  }

  if (expr.kind === 'deref') {
    return { ...expr, address: foldExpr(expr.address) };
  }

  if (expr.kind === 'call') {
    return { ...expr, args: expr.args.map(foldExpr) };
  }

  if (expr.kind === 'cast') {
    return { ...expr, operand: foldExpr(expr.operand) };
  }

  return expr;
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

/**
 * Remove dead register stores: assignments to registers that are never read
 * before the next write. Only removes register assignments, never memory stores or calls.
 */
export function eliminateDeadStores(stmts: IRStmt[]): IRStmt[] {
  const result: IRStmt[] = [];
  for (let i = 0; i < stmts.length; i++) {
    const stmt = stmts[i];
    if (stmt.kind === 'assign' && stmt.dest.kind === 'reg' && !hasSideEffects(stmt.src)) {
      const canon = canonReg(stmt.dest.name);
      let isRead = false;
      for (let j = i + 1; j < stmts.length; j++) {
        const s = stmts[j];
        if (countReadsInStmt(s, canon) > 0) { isRead = true; break; }
        if (s.kind === 'assign' && s.dest.kind === 'reg' && canonReg(s.dest.name) === canon) break;
        if (s.kind === 'call_stmt') { isRead = true; break; } // conservative: call might read
        if (s.kind === 'return') { isRead = true; break; } // return might read
      }
      // If we reached end of block without a read, it might be read in a successor
      // Be conservative and keep it if we hit end of block
      if (!isRead && i + 1 < stmts.length) continue;
    }
    result.push(stmt);
  }
  return result;
}
