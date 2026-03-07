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
    case 'field_access':
      return { ...expr, base: replaceRegInExpr(expr.base, oldReg, newVal) };
    case 'array_access':
      return { ...expr, base: replaceRegInExpr(expr.base, oldReg, newVal), index: replaceRegInExpr(expr.index, oldReg, newVal) };
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
    if (expr.kind === 'field_access') countExprUses(expr.base);
    if (expr.kind === 'array_access') { countExprUses(expr.base); countExprUses(expr.index); }
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
  if (expr.kind === 'field_access') return hasSideEffects(expr.base);
  if (expr.kind === 'array_access') return hasSideEffects(expr.base) || hasSideEffects(expr.index);
  return false;
}

// ── Global Value Numbering ──

const COMMUTATIVE_OPS = new Set(['+', '*', '&', '|', '^', '==', '!=']);

function canonicalizeExpr(expr: IRExpr, regToVN: Map<string, number>, uid: { n: number }): string {
  switch (expr.kind) {
    case 'const':
      return `c:${expr.value}:${expr.size}`;
    case 'reg': {
      const vn = regToVN.get(regKey(expr));
      return vn !== undefined ? `v:${vn}` : `r:${regKey(expr)}`;
    }
    case 'var':
      return `var:${expr.name}`;
    case 'binary': {
      let l = canonicalizeExpr(expr.left, regToVN, uid);
      let r = canonicalizeExpr(expr.right, regToVN, uid);
      if (COMMUTATIVE_OPS.has(expr.op) && l > r) { const t = l; l = r; r = t; }
      return `bin:${expr.op}:${l}:${r}`;
    }
    case 'unary':
      return `un:${expr.op}:${canonicalizeExpr(expr.operand, regToVN, uid)}`;
    case 'cast':
      return `cast:${expr.type}:${canonicalizeExpr(expr.operand, regToVN, uid)}`;
    case 'ternary':
      return `tern:${canonicalizeExpr(expr.condition, regToVN, uid)}:${canonicalizeExpr(expr.then, regToVN, uid)}:${canonicalizeExpr(expr.else, regToVN, uid)}`;
    case 'field_access':
      return `fa:${canonicalizeExpr(expr.base, regToVN, uid)}:${expr.structId}:${expr.fieldOffset}`;
    case 'array_access':
      return `aa:${canonicalizeExpr(expr.base, regToVN, uid)}:${canonicalizeExpr(expr.index, regToVN, uid)}:${expr.elementSize}`;
    case 'deref':
      return `deref:${uid.n++}`;
    case 'call':
      return `call:${uid.n++}`;
    case 'unknown':
      return `unk:${uid.n++}`;
  }
}

/** Global Value Numbering: eliminate redundant expressions across SSA. */
export function globalValueNumbering(ctx: SSAContext): boolean {
  let changed = false;
  const regToVN = new Map<string, number>();
  const exprToReg = new Map<string, IRReg>();
  let nextVN = 0;
  const uid = { n: 0 };

  // Assign unique VNs to all phi dests
  for (const [, blockPhis] of ctx.phis) {
    for (const phi of blockPhis) {
      regToVN.set(regKey(phi.dest), nextVN++);
    }
  }

  // Walk blocks in dominator-tree preorder
  const entry = ctx.blocks.length > 0 ? ctx.blocks[0].id : undefined;
  if (entry === undefined) return false;

  const stack: number[] = [entry];
  while (stack.length > 0) {
    const blockId = stack.pop()!;
    const children = ctx.domTree.get(blockId) ?? [];
    // Push children in reverse so leftmost is processed first
    for (let i = children.length - 1; i >= 0; i--) stack.push(children[i]);

    const stmts = ctx.liftedBlocks.get(blockId);
    if (!stmts) continue;

    for (const s of stmts) {
      if (s.kind !== 'assign' || s.dest.kind !== 'reg' || s.dest.version === undefined) continue;

      const dest = s.dest as IRReg;
      const key = canonicalizeExpr(s.src, regToVN, uid);
      const existing = exprToReg.get(key);

      if (existing) {
        // Replace all uses of dest with the existing register
        replaceRegInCtx(ctx, dest, existing);
        regToVN.set(regKey(dest), regToVN.get(regKey(existing))!);
        changed = true;
      } else {
        const vn = nextVN++;
        regToVN.set(regKey(dest), vn);
        exprToReg.set(key, dest);
      }
    }
  }

  return changed;
}

// ── Loop-Aware Optimizations ──

/** Loop-Invariant Code Motion: move assignments whose operands are all defined
 *  outside the loop (or are constants) to the loop's preheader. */
export function loopInvariantCodeMotion(
  ctx: SSAContext,
  loops: Map<number, Set<number>>,
): boolean {
  let changed = false;

  for (const [header, bodySet] of loops) {
    // Find preheader: the immediate dominator of the header
    const preheader = ctx.idom.get(header);
    if (preheader === undefined || preheader === header) continue;
    // Only move to preheader if it's NOT in the loop
    if (bodySet.has(preheader)) continue;

    const preheaderStmts = ctx.liftedBlocks.get(preheader);
    if (!preheaderStmts) continue;

    // Collect all defs inside the loop
    const loopDefs = new Set<string>();
    for (const blockId of bodySet) {
      const stmts = ctx.liftedBlocks.get(blockId) ?? [];
      for (const s of stmts) {
        if (s.kind === 'assign' && s.dest.kind === 'reg' && s.dest.version !== undefined) {
          loopDefs.add(regKey(s.dest as IRReg));
        }
        if (s.kind === 'call_stmt' && s.resultDest?.kind === 'reg' && (s.resultDest as IRReg).version !== undefined) {
          loopDefs.add(regKey(s.resultDest as IRReg));
        }
      }
      // Phi defs
      const blockPhis = ctx.phis.get(blockId) ?? [];
      for (const phi of blockPhis) {
        loopDefs.add(regKey(phi.dest));
      }
    }

    // Check if an expression only uses values defined outside the loop
    function isInvariant(expr: IRExpr): boolean {
      switch (expr.kind) {
        case 'const': return true;
        case 'var': return true;
        case 'reg':
          if (expr.version === undefined) return false;
          return !loopDefs.has(regKey(expr));
        case 'binary': return isInvariant(expr.left) && isInvariant(expr.right);
        case 'unary': return isInvariant(expr.operand);
        case 'cast': return isInvariant(expr.operand);
        // Don't move calls, derefs, or unknowns (side effects / memory)
        case 'call': return false;
        case 'deref': return false;
        case 'unknown': return false;
        case 'ternary': return isInvariant(expr.condition) && isInvariant(expr.then) && isInvariant(expr.else);
        case 'field_access': return false; // memory access
        case 'array_access': return false; // memory access
      }
    }

    // Move invariant assignments to preheader
    for (const blockId of bodySet) {
      const stmts = ctx.liftedBlocks.get(blockId);
      if (!stmts) continue;
      const newStmts: IRStmt[] = [];
      for (const s of stmts) {
        if (s.kind === 'assign' && s.dest.kind === 'reg' && isInvariant(s.src)) {
          // Move to preheader
          preheaderStmts.push(s);
          changed = true;
        } else {
          newStmts.push(s);
        }
      }
      if (newStmts.length !== stmts.length) {
        ctx.liftedBlocks.set(blockId, newStmts);
      }
    }
  }

  return changed;
}

/** Recognize induction variables: phi nodes at loop header with pattern
 *  phi(init, update) where update = phi_result + step (or - step).
 *  Tags them by setting an `addr` metadata field to the step value. */
export function canonicalizeInductionVars(
  ctx: SSAContext,
  loops: Map<number, Set<number>>,
): boolean {
  let changed = false;

  for (const [header, bodySet] of loops) {
    const headerPhis = ctx.phis.get(header) ?? [];

    for (const phi of headerPhis) {
      if (phi.operands.length !== 2) continue;

      // One operand should be from outside the loop (init), one from inside (update)
      let initOp: typeof phi.operands[0] | null = null;
      let updateOp: typeof phi.operands[0] | null = null;

      for (const op of phi.operands) {
        if (bodySet.has(op.blockId)) {
          updateOp = op;
        } else {
          initOp = op;
        }
      }

      if (!initOp || !updateOp) continue;

      // Check if update is: phi_dest + step or phi_dest - step
      // Look in the update's block for: updateOp.value = phi.dest OP const
      const updateBlock = ctx.liftedBlocks.get(updateOp.blockId);
      if (!updateBlock) continue;

      for (const s of updateBlock) {
        if (s.kind !== 'assign' || s.dest.kind !== 'reg') continue;
        if (s.dest.version !== updateOp.value.version) continue;
        if (canonReg(s.dest.name) !== canonReg(updateOp.value.name)) continue;

        if (s.src.kind === 'binary' && (s.src.op === '+' || s.src.op === '-')) {
          const left = s.src.left;
          const right = s.src.right;

          // Check if left is the phi dest
          if (left.kind === 'reg' && canonReg(left.name) === canonReg(phi.dest.name) &&
              left.version === phi.dest.version && right.kind === 'const') {
            // This is an induction variable!
            // Tag the phi with induction info (addr metadata)
            phi.addr = right.value; // Reuse addr field as step marker
            changed = true;
          }
        }
      }
    }
  }

  return changed;
}

/** Run all SSA optimization passes until stable (max 3 iterations). */
export function ssaOptimize(ctx: SSAContext, loops?: Map<number, Set<number>>): void {
  for (let iter = 0; iter < 3; iter++) {
    let changed = false;
    changed = simplifyPhis(ctx) || changed;
    changed = copyPropagation(ctx) || changed;
    changed = constantPropagation(ctx) || changed;
    changed = globalValueNumbering(ctx) || changed;
    if (loops) {
      changed = loopInvariantCodeMotion(ctx, loops) || changed;
      changed = canonicalizeInductionVars(ctx, loops) || changed;
    }
    changed = deadCodeElimination(ctx) || changed;
    if (!changed) break;
  }
}
