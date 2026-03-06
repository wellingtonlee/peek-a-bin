import type { SSAContext } from './ssa';
import type { IRStmt, IRExpr } from './ir';
import { canonReg } from './ir';

/**
 * Destroy SSA form: convert phi nodes to copy assignments at predecessors,
 * strip all version numbers from registers.
 */
export function destroySSA(ctx: SSAContext): void {
  // Insert copies for phi operands at end of predecessor blocks
  for (const [, blockPhis] of ctx.phis) {
    for (const phi of blockPhis) {
      const destCanon = canonReg(phi.dest.name);
      for (const op of phi.operands) {
        const srcCanon = canonReg(op.value.name);
        // Skip self-copies
        if (destCanon === srcCanon && phi.dest.version === op.value.version) continue;

        const predStmts = ctx.liftedBlocks.get(op.blockId);
        if (!predStmts) continue;

        const copy: IRStmt = {
          kind: 'assign',
          dest: { kind: 'reg', name: destCanon, size: phi.dest.size },
          src: { kind: 'reg', name: srcCanon, size: op.value.size },
        };
        predStmts.push(copy);
      }
    }
  }

  ctx.phis.clear();

  // Strip version numbers from all registers
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    ctx.liftedBlocks.set(blockId, stmts.map(stripVersionsStmt));
  }
}

function stripVersionsExpr(expr: IRExpr): IRExpr {
  switch (expr.kind) {
    case 'reg':
      return expr.version !== undefined ? { ...expr, version: undefined } : expr;
    case 'binary':
      return { ...expr, left: stripVersionsExpr(expr.left), right: stripVersionsExpr(expr.right) };
    case 'unary':
      return { ...expr, operand: stripVersionsExpr(expr.operand) };
    case 'deref':
      return { ...expr, address: stripVersionsExpr(expr.address) };
    case 'call':
      return { ...expr, args: expr.args.map(stripVersionsExpr) };
    case 'ternary':
      return { ...expr, condition: stripVersionsExpr(expr.condition), then: stripVersionsExpr(expr.then), else: stripVersionsExpr(expr.else) };
    case 'cast':
      return { ...expr, operand: stripVersionsExpr(expr.operand) };
    default:
      return expr;
  }
}

function stripVersionsStmt(stmt: IRStmt): IRStmt {
  switch (stmt.kind) {
    case 'assign':
      return { ...stmt, dest: stripVersionsExpr(stmt.dest), src: stripVersionsExpr(stmt.src) };
    case 'store':
      return { ...stmt, address: stripVersionsExpr(stmt.address), value: stripVersionsExpr(stmt.value) };
    case 'call_stmt': {
      const call = { ...stmt.call, args: stmt.call.args.map(stripVersionsExpr) };
      const resultDest = stmt.resultDest ? stripVersionsExpr(stmt.resultDest) : undefined;
      return { ...stmt, call: call as typeof stmt.call, resultDest };
    }
    case 'return':
      return stmt.value ? { ...stmt, value: stripVersionsExpr(stmt.value) } : stmt;
    default:
      return stmt;
  }
}
