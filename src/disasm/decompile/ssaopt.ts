// One definition, shared with foldBlock. Keeping a second copy here is how the
// two drifted: this one classified `(int64_t)f()` as pure, so an unused
// cast-of-call def was deleted along with the call.
import { hasSideEffects } from "./fold";
import type { IRExpr, IRPhi, IRReg, IRStmt } from "./ir";
import { canonReg } from "./ir";
import type { SSAContext } from "./ssa";

function sameReg(a: IRReg, b: IRReg): boolean {
  return canonReg(a.name) === canonReg(b.name) && a.version === b.version;
}

function regKey(r: IRReg): string {
  return `${canonReg(r.name)}_${r.version ?? 0}`;
}

// ── Replace helpers ──

function replaceRegInExpr(expr: IRExpr, oldReg: IRReg, newVal: IRExpr): IRExpr {
  switch (expr.kind) {
    case "reg":
      return sameReg(expr, oldReg) ? newVal : expr;
    case "binary":
      return {
        ...expr,
        left: replaceRegInExpr(expr.left, oldReg, newVal),
        right: replaceRegInExpr(expr.right, oldReg, newVal),
      };
    case "unary":
      return { ...expr, operand: replaceRegInExpr(expr.operand, oldReg, newVal) };
    case "deref":
      return { ...expr, address: replaceRegInExpr(expr.address, oldReg, newVal) };
    case "call":
      return { ...expr, args: expr.args.map((a) => replaceRegInExpr(a, oldReg, newVal)) };
    case "ternary":
      return {
        ...expr,
        condition: replaceRegInExpr(expr.condition, oldReg, newVal),
        then: replaceRegInExpr(expr.then, oldReg, newVal),
        else: replaceRegInExpr(expr.else, oldReg, newVal),
      };
    case "cast":
      return { ...expr, operand: replaceRegInExpr(expr.operand, oldReg, newVal) };
    case "field_access":
      return { ...expr, base: replaceRegInExpr(expr.base, oldReg, newVal) };
    case "array_access":
      return {
        ...expr,
        base: replaceRegInExpr(expr.base, oldReg, newVal),
        index: replaceRegInExpr(expr.index, oldReg, newVal),
      };
    default:
      return expr;
  }
}

function replaceRegInStmt(stmt: IRStmt, oldReg: IRReg, newVal: IRExpr): IRStmt {
  switch (stmt.kind) {
    case "assign": {
      const src = replaceRegInExpr(stmt.src, oldReg, newVal);
      const dest =
        stmt.dest.kind === "deref"
          ? ({
              ...stmt.dest,
              address: replaceRegInExpr(stmt.dest.address, oldReg, newVal),
            } as IRExpr)
          : stmt.dest;
      return { ...stmt, dest, src };
    }
    case "store":
      return {
        ...stmt,
        address: replaceRegInExpr(stmt.address, oldReg, newVal),
        value: replaceRegInExpr(stmt.value, oldReg, newVal),
      };
    case "call_stmt":
      return {
        ...stmt,
        call: {
          ...stmt.call,
          args: stmt.call.args.map((a) => replaceRegInExpr(a, oldReg, newVal)),
        },
      };
    case "return":
      return stmt.value ? { ...stmt, value: replaceRegInExpr(stmt.value, oldReg, newVal) } : stmt;
    default:
      return stmt;
  }
}

function replaceRegInCtx(ctx: SSAContext, oldReg: IRReg, newVal: IRExpr): void {
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    ctx.liftedBlocks.set(
      blockId,
      stmts.map((s) => replaceRegInStmt(s, oldReg, newVal)),
    );
  }
  for (const [, blockPhis] of ctx.phis) {
    for (const phi of blockPhis) {
      for (const op of phi.operands) {
        if (op.value.kind === "reg" && sameReg(op.value, oldReg) && newVal.kind === "reg") {
          op.value = { ...(newVal as IRReg) };
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
      const nonSelf = phi.operands.filter((op) => !sameReg(op.value, phi.dest));
      if (nonSelf.length === 0) {
        changed = true;
        continue;
      }
      const first = nonSelf[0].value;
      const allSame = nonSelf.every((op) => sameReg(op.value, first));
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

/**
 * The stack pointer has no faithful definition chain in this IR, so no read of
 * it may be moved to another program point.
 *
 * `liftBlock` skips `push` and `pop` outright, and `call` pushes a return
 * address it never models either — so between two IR statements RSP can change
 * with nothing in the IR saying it did. `rsp_0` is therefore not one value: it
 * means "whatever RSP is *here*", and two reads carrying that version can be
 * different machine values. SSA's guarantee does not hold for it.
 *
 * Substituting across that is how `mov rbp, rsp` turned every later `[rbp + 8]`
 * into `[esp + 8]`, printing a base register the instruction never named and
 * one `sub esp, 0xc` off the value it did name (peek-a-bin-rt4). Leaving the
 * copy in place costs nothing: `rbp = rsp` is a real statement and the frame
 * pointer keeps its own name, which is also what lets stack-slot promotion
 * recognise an argument slot.
 */
function isStackPointer(e: IRExpr): boolean {
  return e.kind === "reg" && canonReg(e.name) === "rsp";
}

function isCopyStmt(s: IRStmt): boolean {
  return (
    s.kind === "assign" &&
    s.dest.kind === "reg" &&
    s.src.kind === "reg" &&
    s.dest.version !== undefined &&
    !isStackPointer(s.dest) &&
    !isStackPointer(s.src)
  );
}

/**
 * Copy propagation: r_3 = r_2 → replace all uses of r_3 with r_2.
 *
 * **Collect first, rewrite afterwards** — the shape `constantPropagation`
 * already uses. `replaceRegInCtx` writes straight into `ctx.liftedBlocks`, so
 * rewriting while walking a block and *then* storing the list built from that
 * walk put the pre-rewrite statements back: the copy was deleted and its uses
 * in the same block kept naming a destination that no longer had a definition.
 * Dead-code elimination then removed whatever fed the copy, and whole branch
 * bodies went with it (peek-a-bin-fxm).
 *
 * A copy's source may itself be another copy's destination, and the two are
 * discovered in program order — definition before use — so replacing them in
 * that order would rewrite `b_2` away before the pending `a_1 = b_2` was
 * applied, re-creating the dangling read this function exists to avoid. Each
 * substitution is therefore applied to the *pending* copies as well, which
 * makes the result independent of the order they were collected in.
 */
export function copyPropagation(ctx: SSAContext): boolean {
  const copies: { dest: IRReg; src: IRExpr }[] = [];
  for (const [, stmts] of ctx.liftedBlocks) {
    for (const s of stmts) {
      if (s.kind === "assign" && isCopyStmt(s)) copies.push({ dest: s.dest as IRReg, src: s.src });
    }
  }
  if (copies.length === 0) return false;

  for (const [blockId, stmts] of ctx.liftedBlocks) {
    ctx.liftedBlocks.set(
      blockId,
      stmts.filter((s) => !isCopyStmt(s)),
    );
  }
  for (let i = 0; i < copies.length; i++) {
    const c = copies[i];
    replaceRegInCtx(ctx, c.dest, c.src);
    for (let j = i + 1; j < copies.length; j++) {
      copies[j].src = replaceRegInExpr(copies[j].src, c.dest, c.src);
    }
  }
  return true;
}

/** Constant propagation: r_3 = 42 → replace uses with constant. */
export function constantPropagation(ctx: SSAContext): boolean {
  let changed = false;
  // Collect all simple constant defs first, then replace
  const constDefs: { reg: IRReg; val: IRExpr }[] = [];
  for (const [, stmts] of ctx.liftedBlocks) {
    for (const s of stmts) {
      if (
        s.kind === "assign" &&
        s.dest.kind === "reg" &&
        s.src.kind === "const" &&
        s.dest.version !== undefined
      ) {
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
    if (expr.kind === "reg" && expr.version !== undefined) {
      const key = regKey(expr);
      useCounts.set(key, (useCounts.get(key) ?? 0) + 1);
    }
    if (expr.kind === "binary") {
      countExprUses(expr.left);
      countExprUses(expr.right);
    }
    if (expr.kind === "unary") countExprUses(expr.operand);
    if (expr.kind === "deref") countExprUses(expr.address);
    if (expr.kind === "call") expr.args.forEach(countExprUses);
    if (expr.kind === "ternary") {
      countExprUses(expr.condition);
      countExprUses(expr.then);
      countExprUses(expr.else);
    }
    if (expr.kind === "cast") countExprUses(expr.operand);
    if (expr.kind === "field_access") countExprUses(expr.base);
    if (expr.kind === "array_access") {
      countExprUses(expr.base);
      countExprUses(expr.index);
    }
  }

  function countStmtUses(s: IRStmt) {
    switch (s.kind) {
      case "assign":
        countExprUses(s.src);
        if (s.dest.kind === "deref") countExprUses(s.dest.address);
        break;
      case "store":
        countExprUses(s.address);
        countExprUses(s.value);
        break;
      case "call_stmt":
        s.call.args.forEach(countExprUses);
        break;
      case "return":
        if (s.value) countExprUses(s.value);
        break;
    }
  }

  for (const [, stmts] of ctx.liftedBlocks) {
    for (const s of stmts) countStmtUses(s);
  }

  // A block ending in a Jcc has a use this pass cannot see. `structure.ts`
  // builds the branch condition from the `cmp`/`test` *instruction* through
  // RegState, not from the IR, so once the unread `eflags` definition is
  // dropped the registers that condition names have no IR consumer either —
  // and the load that computes them goes too. That is how the t64 wcslen body
  // lost `movzx edx, [rax]` and became `while (dx != 0) { rax += 2; }`, an
  // infinite loop (peek-a-bin-ua8).
  //
  // The flag definition is held live as well as counted: dropping it on this
  // pass would make its operands dead on the next one.
  const protectedFlagDefs = new Set<IRStmt>();
  for (const block of ctx.blocks) {
    const last = block.insns[block.insns.length - 1];
    if (!last) continue;
    const mn = last.mnemonic.toLowerCase();
    if (!mn.startsWith("j") || mn === "jmp") continue;
    const stmts = ctx.liftedBlocks.get(block.id) ?? [];
    for (let i = stmts.length - 1; i >= 0; i--) {
      const s = stmts[i];
      if (s.kind === "assign" && s.dest.kind === "reg" && canonReg(s.dest.name) === "eflags") {
        countExprUses(s.src);
        protectedFlagDefs.add(s);
        break;
      }
    }
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
      if (s.kind === "assign" && s.dest.kind === "reg" && s.dest.version !== undefined) {
        if (protectedFlagDefs.has(s)) {
          newStmts.push(s);
          continue;
        }
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
    const newPhis = blockPhis.filter((phi) => {
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

// ── Global Value Numbering ──

const COMMUTATIVE_OPS = new Set(["+", "*", "&", "|", "^", "==", "!="]);

function canonicalizeExpr(expr: IRExpr, regToVN: Map<string, number>, uid: { n: number }): string {
  switch (expr.kind) {
    case "const":
      return `c:${expr.value}:${expr.size}`;
    case "reg": {
      const vn = regToVN.get(regKey(expr));
      return vn !== undefined ? `v:${vn}` : `r:${regKey(expr)}`;
    }
    case "var":
      return `var:${expr.name}`;
    case "binary": {
      let l = canonicalizeExpr(expr.left, regToVN, uid);
      let r = canonicalizeExpr(expr.right, regToVN, uid);
      if (COMMUTATIVE_OPS.has(expr.op) && l > r) {
        const t = l;
        l = r;
        r = t;
      }
      return `bin:${expr.op}:${l}:${r}`;
    }
    case "unary":
      return `un:${expr.op}:${canonicalizeExpr(expr.operand, regToVN, uid)}`;
    case "cast":
      return `cast:${expr.type}:${canonicalizeExpr(expr.operand, regToVN, uid)}`;
    case "ternary":
      return `tern:${canonicalizeExpr(expr.condition, regToVN, uid)}:${canonicalizeExpr(expr.then, regToVN, uid)}:${canonicalizeExpr(expr.else, regToVN, uid)}`;
    case "field_access":
      return `fa:${canonicalizeExpr(expr.base, regToVN, uid)}:${expr.structId}:${expr.fieldOffset}`;
    case "array_access":
      return `aa:${canonicalizeExpr(expr.base, regToVN, uid)}:${canonicalizeExpr(expr.index, regToVN, uid)}:${expr.elementSize}`;
    case "deref":
      return `deref:${uid.n++}`;
    case "call":
      return `call:${uid.n++}`;
    case "unknown":
      return `unk:${uid.n++}`;
  }
}

/**
 * Global Value Numbering: eliminate redundant expressions across SSA.
 *
 * **A definition may only be reused inside the subtree it dominates.** The
 * available-expression table is pushed and popped around each dominator-tree
 * node, so leaving a subtree forgets what was defined in it. A flat table that
 * merely *visited* blocks in preorder also matches definitions in already-
 * visited sibling subtrees, which do not dominate the current block — for a
 * plain if/else where both arms compute `edx + 5`, the else arm's register was
 * rewritten to the then arm's, and the value read after the join came from a
 * block that had not run. SSA versions do not catch this: both registers are
 * legitimately defined exactly once, just on paths that exclude each other.
 */
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

  // Explicit DFS rather than recursion — a deep dominator tree is ordinary in a
  // large function. An `exit` frame is the scope marker: popping it means the
  // block's subtree is done, so drop the expressions that block introduced.
  const stack: { blockId: number; exit: boolean }[] = [{ blockId: entry, exit: false }];
  const introduced = new Map<number, string[]>();

  while (stack.length > 0) {
    const frame = stack.pop()!;
    const blockId = frame.blockId;

    if (frame.exit) {
      for (const key of introduced.get(blockId) ?? []) exprToReg.delete(key);
      introduced.delete(blockId);
      continue;
    }

    stack.push({ blockId, exit: true });
    const children = ctx.domTree.get(blockId) ?? [];
    // Push children in reverse so leftmost is processed first
    for (let i = children.length - 1; i >= 0; i--)
      stack.push({ blockId: children[i], exit: false });

    const stmts = ctx.liftedBlocks.get(blockId);
    if (!stmts) continue;

    const added: string[] = [];
    introduced.set(blockId, added);

    for (const s of stmts) {
      if (s.kind !== "assign" || s.dest.kind !== "reg" || s.dest.version === undefined) continue;

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
        added.push(key);
      }
    }
  }

  return changed;
}

// ── Loop-Aware Optimizations ──

/** Loop-Invariant Code Motion: move assignments whose operands are all defined
 *  outside the loop (or are constants) to the loop's preheader. */
export function loopInvariantCodeMotion(ctx: SSAContext, loops: Map<number, Set<number>>): boolean {
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
        if (s.kind === "assign" && s.dest.kind === "reg" && s.dest.version !== undefined) {
          loopDefs.add(regKey(s.dest as IRReg));
        }
        if (
          s.kind === "call_stmt" &&
          s.resultDest?.kind === "reg" &&
          (s.resultDest as IRReg).version !== undefined
        ) {
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
        case "const":
          return true;
        case "var":
          return true;
        case "reg":
          if (expr.version === undefined) return false;
          // A version a *call* handed out (SSAContext.clobbered) has no defining
          // statement, so `loopDefs` cannot see it and it would otherwise read
          // as loop-invariant. It is the opposite: the call that produced it is
          // usually inside the loop and produces a different value each trip.
          if (ctx.clobbered.has(regKey(expr))) return false;
          return !loopDefs.has(regKey(expr));
        case "binary":
          return isInvariant(expr.left) && isInvariant(expr.right);
        case "unary":
          return isInvariant(expr.operand);
        case "cast":
          return isInvariant(expr.operand);
        // Don't move calls, derefs, or unknowns (side effects / memory)
        case "call":
          return false;
        case "deref":
          return false;
        case "unknown":
          return false;
        case "ternary":
          return isInvariant(expr.condition) && isInvariant(expr.then) && isInvariant(expr.else);
        case "field_access":
          return false; // memory access
        case "array_access":
          return false; // memory access
      }
    }

    // Move invariant assignments to preheader
    for (const blockId of bodySet) {
      const stmts = ctx.liftedBlocks.get(blockId);
      if (!stmts) continue;
      const newStmts: IRStmt[] = [];
      for (const s of stmts) {
        if (s.kind === "assign" && s.dest.kind === "reg" && isInvariant(s.src)) {
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
      let initOp: (typeof phi.operands)[0] | null = null;
      let updateOp: (typeof phi.operands)[0] | null = null;

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
        if (s.kind !== "assign" || s.dest.kind !== "reg") continue;
        if (s.dest.version !== updateOp.value.version) continue;
        if (canonReg(s.dest.name) !== canonReg(updateOp.value.name)) continue;

        if (s.src.kind === "binary" && (s.src.op === "+" || s.src.op === "-")) {
          const left = s.src.left;
          const right = s.src.right;

          // Check if left is the phi dest
          if (
            left.kind === "reg" &&
            canonReg(left.name) === canonReg(phi.dest.name) &&
            left.version === phi.dest.version &&
            right.kind === "const"
          ) {
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

  // The flag definitions held live above have served their purpose: everything
  // they keep alive has survived the fixpoint. They have no IR consumer, so
  // they go now rather than leaking `eflags = ...` into the emitted text
  // (peek-a-bin-zsb). A flag definition that *does* have a side effect stays —
  // deleting it would delete the call inside it.
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    ctx.liftedBlocks.set(
      blockId,
      stmts.filter(
        (s) =>
          !(
            s.kind === "assign" &&
            s.dest.kind === "reg" &&
            canonReg(s.dest.name) === "eflags" &&
            !hasSideEffects(s.src)
          ),
      ),
    );
  }
}
