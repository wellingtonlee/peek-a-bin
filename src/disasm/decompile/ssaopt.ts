import type { SSAContext } from './ssa';
import type { IRStmt, IRExpr, IRReg, IRPhi } from './ir';
import { canonReg } from './ir';

function sameReg(a: IRReg, b: IRReg): boolean {
  return canonReg(a.name) === canonReg(b.name) && a.version === b.version;
}

function regKey(r: IRReg): string {
  return `${canonReg(r.name)}_${r.version ?? 0}`;
}

// ── Replace helpers ──

function replaceRegInExpr(expr: IRExpr, oldReg: IRReg, newVal: IRExpr): IRExpr {
  switch (expr.kind) {
    case 'reg':
      return sameReg(expr, oldReg) ? newVal : expr;
    case 'binary':
      return { ...expr, left: replaceRegInExpr(expr.left, oldReg, newVal), right: replaceRegInExpr(expr.right, oldReg, newVal) };
    case 'unary':
      return { ...expr, operand: replaceRegInExpr(expr.operand, oldReg, newVal) };
    case 'deref':
      return { ...expr, address: replaceRegInExpr(expr.address, oldReg, newVal) };
    case 'call':
      return { ...expr, args: expr.args.map(a => replaceRegInExpr(a, oldReg, newVal)) };
    case 'ternary':
      return { ...expr, condition: replaceRegInExpr(expr.condition, oldReg, newVal), then: replaceRegInExpr(expr.then, oldReg, newVal), else: replaceRegInExpr(expr.else, oldReg, newVal) };
    case 'cast':
      return { ...expr, operand: replaceRegInExpr(expr.operand, oldReg, newVal) };
    default:
      return expr;
  }
}

function replaceRegInStmt(stmt: IRStmt, oldReg: IRReg, newVal: IRExpr): IRStmt {
  switch (stmt.kind) {
    case 'assign': {
      const src = replaceRegInExpr(stmt.src, oldReg, newVal);
      const dest = stmt.dest.kind === 'deref'
        ? { ...stmt.dest, address: replaceRegInExpr(stmt.dest.address, oldReg, newVal) } as IRExpr
        : stmt.dest;
      return { ...stmt, dest, src };
    }
    case 'store':
      return { ...stmt, address: replaceRegInExpr(stmt.address, oldReg, newVal), value: replaceRegInExpr(stmt.value, oldReg, newVal) };
    case 'call_stmt':
      return { ...stmt, call: { ...stmt.call, args: stmt.call.args.map(a => replaceRegInExpr(a, oldReg, newVal)) } };
    case 'return':
      return stmt.value ? { ...stmt, value: replaceRegInExpr(stmt.value, oldReg, newVal) } : stmt;
    default:
      return stmt;
  }
}

function replaceRegInCtx(ctx: SSAContext, oldReg: IRReg, newVal: IRExpr): void {
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    ctx.liftedBlocks.set(blockId, stmts.map(s => replaceRegInStmt(s, oldReg, newVal)));
  }
  for (const [, blockPhis] of ctx.phis) {
    for (const phi of blockPhis) {
      for (const op of phi.operands) {
        if (op.value.kind === 'reg' && sameReg(op.value, oldReg) && newVal.kind === 'reg') {
          op.value = { ...newVal as IRReg };
        }
      }
    }
  }
}

// ── SSA Optimization Passes ──

/** Remove trivial phis (all operands identical, or single unique non-self operand). */
export function simplifyPhis(ctx: SSAContext): boolean {
  let changed = false;
  for (const [blockId, blockPhis] of ctx.phis) {
    const newPhis: IRPhi[] = [];
    for (const phi of blockPhis) {
      const nonSelf = phi.operands.filter(op => !sameReg(op.value, phi.dest));
      if (nonSelf.length === 0) {
        changed = true;
        continue;
      }
      const first = nonSelf[0].value;
      const allSame = nonSelf.every(op => sameReg(op.value, first));
      if (allSame) {
        replaceRegInCtx(ctx, phi.dest, first);
        changed = true;
        continue;
      }
      newPhis.push(phi);
    }
    ctx.phis.set(blockId, newPhis);
  }
  return changed;
}

/** Copy propagation: r_3 = r_2 → replace all uses of r_3 with r_2. */
export function copyPropagation(ctx: SSAContext): boolean {
  let changed = false;
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    const newStmts: IRStmt[] = [];
    for (const s of stmts) {
      if (s.kind === 'assign' && s.dest.kind === 'reg' && s.src.kind === 'reg' &&
          s.dest.version !== undefined) {
        replaceRegInCtx(ctx, s.dest as IRReg, s.src);
        changed = true;
        continue;
      }
      newStmts.push(s);
    }
    ctx.liftedBlocks.set(blockId, newStmts);
  }
  return changed;
}

/** Constant propagation: r_3 = 42 → replace uses with constant. */
export function constantPropagation(ctx: SSAContext): boolean {
  let changed = false;
  // Collect all simple constant defs first, then replace
  const constDefs: { reg: IRReg; val: IRExpr }[] = [];
  for (const [, stmts] of ctx.liftedBlocks) {
    for (const s of stmts) {
      if (s.kind === 'assign' && s.dest.kind === 'reg' && s.src.kind === 'const' &&
          s.dest.version !== undefined) {
        constDefs.push({ reg: s.dest as IRReg, val: s.src });
      }
    }
  }
  for (const { reg, val } of constDefs) {
    replaceRegInCtx(ctx, reg, val);
    changed = true;
  }
  return changed;
}

/** Dead code elimination: remove defs with zero uses (keep stores/calls/returns). */
export function deadCodeElimination(ctx: SSAContext): boolean {
  let changed = false;

  // Count uses of each versioned register
  const useCounts = new Map<string, number>();

  function countExprUses(expr: IRExpr) {
    if (expr.kind === 'reg' && expr.version !== undefined) {
      const key = regKey(expr);
      useCounts.set(key, (useCounts.get(key) ?? 0) + 1);
    }
    if (expr.kind === 'binary') { countExprUses(expr.left); countExprUses(expr.right); }
    if (expr.kind === 'unary') countExprUses(expr.operand);
    if (expr.kind === 'deref') countExprUses(expr.address);
    if (expr.kind === 'call') expr.args.forEach(countExprUses);
    if (expr.kind === 'ternary') { countExprUses(expr.condition); countExprUses(expr.then); countExprUses(expr.else); }
    if (expr.kind === 'cast') countExprUses(expr.operand);
  }

  function countStmtUses(s: IRStmt) {
    switch (s.kind) {
      case 'assign':
        countExprUses(s.src);
        if (s.dest.kind === 'deref') countExprUses(s.dest.address);
        break;
      case 'store':
        countExprUses(s.address); countExprUses(s.value);
        break;
      case 'call_stmt':
        s.call.args.forEach(countExprUses);
        break;
      case 'return':
        if (s.value) countExprUses(s.value);
        break;
    }
  }

  for (const [, stmts] of ctx.liftedBlocks) {
    for (const s of stmts) countStmtUses(s);
  }
  for (const [, blockPhis] of ctx.phis) {
    for (const phi of blockPhis) {
      for (const op of phi.operands) {
        if (op.value.version !== undefined) {
          const key = regKey(op.value);
          useCounts.set(key, (useCounts.get(key) ?? 0) + 1);
        }
      }
    }
  }

  // Remove unused defs
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    const newStmts: IRStmt[] = [];
    for (const s of stmts) {
      if (s.kind === 'assign' && s.dest.kind === 'reg' && s.dest.version !== undefined) {
        const key = regKey(s.dest);
        if ((useCounts.get(key) ?? 0) === 0 && !hasSideEffects(s.src)) {
          changed = true;
          continue;
        }
      }
      newStmts.push(s);
    }
    ctx.liftedBlocks.set(blockId, newStmts);
  }

  // Remove dead phis
  for (const [blockId, blockPhis] of ctx.phis) {
    const newPhis = blockPhis.filter(phi => {
      const key = regKey(phi.dest);
      if ((useCounts.get(key) ?? 0) === 0) {
        changed = true;
        return false;
      }
      return true;
    });
    ctx.phis.set(blockId, newPhis);
  }

  return changed;
}

function hasSideEffects(expr: IRExpr): boolean {
  if (expr.kind === 'call') return true;
  if (expr.kind === 'binary') return hasSideEffects(expr.left) || hasSideEffects(expr.right);
  if (expr.kind === 'unary') return hasSideEffects(expr.operand);
  if (expr.kind === 'deref') return hasSideEffects(expr.address);
  if (expr.kind === 'ternary') return hasSideEffects(expr.condition) || hasSideEffects(expr.then) || hasSideEffects(expr.else);
  return false;
}

/** Run all SSA optimization passes until stable (max 3 iterations). */
export function ssaOptimize(ctx: SSAContext): void {
  for (let iter = 0; iter < 3; iter++) {
    let changed = false;
    changed = simplifyPhis(ctx) || changed;
    changed = copyPropagation(ctx) || changed;
    changed = constantPropagation(ctx) || changed;
    changed = deadCodeElimination(ctx) || changed;
    if (!changed) break;
  }
}
