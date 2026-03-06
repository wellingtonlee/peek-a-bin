import type { BasicBlock } from '../cfg';
import type { IRStmt, IRReg, IRPhi, IRExpr } from './ir';
import { irReg, canonReg } from './ir';

export interface SSAContext {
  blocks: BasicBlock[];
  liftedBlocks: Map<number, IRStmt[]>;
  phis: Map<number, IRPhi[]>;
  idom: Map<number, number>;
  domTree: Map<number, number[]>;
}

// ── Reverse Postorder ──

export function computeRPO(blocks: BasicBlock[]): number[] {
  const blockById = new Map<number, BasicBlock>();
  for (const b of blocks) blockById.set(b.id, b);
  const visited = new Set<number>();
  const postorder: number[] = [];

  function dfs(id: number) {
    if (visited.has(id)) return;
    visited.add(id);
    const block = blockById.get(id);
    if (!block) return;
    for (const succ of block.succs) dfs(succ);
    postorder.push(id);
  }

  if (blocks.length > 0) dfs(blocks[0].id);
  return postorder.reverse();
}

// ── Cooper-Harvey-Kennedy Iterative Dominator Algorithm ──

export function computeDominators(blocks: BasicBlock[], rpo: number[]): Map<number, number> {
  const rpoIndex = new Map<number, number>();
  for (let i = 0; i < rpo.length; i++) rpoIndex.set(rpo[i], i);

  const blockById = new Map<number, BasicBlock>();
  for (const b of blocks) blockById.set(b.id, b);

  const idom = new Map<number, number>();
  const entry = rpo[0];
  idom.set(entry, entry);

  function intersect(b1: number, b2: number): number {
    let f1 = b1, f2 = b2;
    while (f1 !== f2) {
      while ((rpoIndex.get(f1) ?? 0) > (rpoIndex.get(f2) ?? 0)) f1 = idom.get(f1)!;
      while ((rpoIndex.get(f2) ?? 0) > (rpoIndex.get(f1) ?? 0)) f2 = idom.get(f2)!;
    }
    return f1;
  }

  let changed = true;
  while (changed) {
    changed = false;
    for (let i = 1; i < rpo.length; i++) {
      const b = rpo[i];
      const block = blockById.get(b);
      if (!block) continue;

      let newIdom = -1;
      for (const p of block.preds) {
        if (idom.has(p)) { newIdom = p; break; }
      }
      if (newIdom === -1) continue;

      for (const p of block.preds) {
        if (p === newIdom) continue;
        if (idom.has(p)) newIdom = intersect(p, newIdom);
      }

      if (idom.get(b) !== newIdom) {
        idom.set(b, newIdom);
        changed = true;
      }
    }
  }

  return idom;
}

// ── Dominance Frontier ──

export function computeDomFrontier(
  blocks: BasicBlock[],
  idom: Map<number, number>,
): Map<number, Set<number>> {
  const df = new Map<number, Set<number>>();
  for (const b of blocks) df.set(b.id, new Set());

  for (const b of blocks) {
    if (b.preds.length < 2) continue;
    for (const p of b.preds) {
      let runner = p;
      while (runner !== idom.get(b.id) && runner !== undefined) {
        df.get(runner)!.add(b.id);
        runner = idom.get(runner)!;
      }
    }
  }

  return df;
}

// ── Dominator Tree (children list) ──

export function computeDomTree(idom: Map<number, number>): Map<number, number[]> {
  const tree = new Map<number, number[]>();
  for (const [node] of idom) tree.set(node, []);

  for (const [node, parent] of idom) {
    if (node === parent) continue;
    tree.get(parent)?.push(node);
  }

  return tree;
}

// ── Liveness & Phi Insertion ──

function collectDefs(stmts: IRStmt[]): Set<string> {
  const defs = new Set<string>();
  for (const s of stmts) {
    if (s.kind === 'assign' && s.dest.kind === 'reg') {
      defs.add(canonReg(s.dest.name));
    }
    if (s.kind === 'call_stmt' && s.resultDest?.kind === 'reg') {
      defs.add(canonReg(s.resultDest.name));
    }
  }
  return defs;
}

function stmtUses(s: IRStmt): Set<string> {
  const uses = new Set<string>();
  function walk(e: IRExpr) {
    if (e.kind === 'reg') { uses.add(canonReg(e.name)); return; }
    if (e.kind === 'binary') { walk(e.left); walk(e.right); return; }
    if (e.kind === 'unary') { walk(e.operand); return; }
    if (e.kind === 'deref') { walk(e.address); return; }
    if (e.kind === 'call') { e.args.forEach(walk); return; }
    if (e.kind === 'ternary') { walk(e.condition); walk(e.then); walk(e.else); return; }
    if (e.kind === 'cast') { walk(e.operand); return; }
  }
  switch (s.kind) {
    case 'assign':
      walk(s.src);
      if (s.dest.kind === 'deref') walk(s.dest.address);
      break;
    case 'store':
      walk(s.address); walk(s.value);
      break;
    case 'call_stmt':
      s.call.args.forEach(walk);
      break;
    case 'return':
      if (s.value) walk(s.value);
      break;
  }
  return uses;
}

export function insertPhis(
  blocks: BasicBlock[],
  liftedBlocks: Map<number, IRStmt[]>,
  domFrontier: Map<number, Set<number>>,
): Map<number, IRPhi[]> {
  const phis = new Map<number, IRPhi[]>();
  const blockById = new Map<number, BasicBlock>();
  for (const b of blocks) {
    phis.set(b.id, []);
    blockById.set(b.id, b);
  }

  // Definitions per block
  const blockDefs = new Map<number, Set<string>>();
  for (const b of blocks) {
    blockDefs.set(b.id, collectDefs(liftedBlocks.get(b.id) ?? []));
  }

  // Liveness: upward-exposed uses + backward propagation
  const liveIn = new Map<number, Set<string>>();
  for (const b of blocks) liveIn.set(b.id, new Set());

  // Initialize with upward-exposed uses
  for (const b of blocks) {
    const stmts = liftedBlocks.get(b.id) ?? [];
    const defined = new Set<string>();
    for (const s of stmts) {
      for (const u of stmtUses(s)) {
        if (!defined.has(u)) liveIn.get(b.id)!.add(u);
      }
      if (s.kind === 'assign' && s.dest.kind === 'reg') defined.add(canonReg(s.dest.name));
      if (s.kind === 'call_stmt' && s.resultDest?.kind === 'reg') defined.add(canonReg(s.resultDest.name));
    }
  }

  // Propagate liveness backwards
  let liveChanged = true;
  while (liveChanged) {
    liveChanged = false;
    for (let i = blocks.length - 1; i >= 0; i--) {
      const b = blocks[i];
      const defs = blockDefs.get(b.id)!;
      for (const succId of b.succs) {
        for (const reg of liveIn.get(succId) ?? []) {
          if (!defs.has(reg) && !liveIn.get(b.id)!.has(reg)) {
            liveIn.get(b.id)!.add(reg);
            liveChanged = true;
          }
        }
      }
    }
  }

  // Place phis (pruned: only where live-in)
  const allRegs = new Set<string>();
  for (const [, defs] of blockDefs) for (const d of defs) allRegs.add(d);

  for (const reg of allRegs) {
    const defBlocks = new Set<number>();
    for (const b of blocks) {
      if (blockDefs.get(b.id)!.has(reg)) defBlocks.add(b.id);
    }

    const hasPhiAt = new Set<number>();
    const worklist = [...defBlocks];

    while (worklist.length > 0) {
      const b = worklist.pop()!;
      for (const d of domFrontier.get(b) ?? []) {
        if (hasPhiAt.has(d)) continue;
        if (!liveIn.get(d)!.has(reg)) continue;
        hasPhiAt.add(d);
        const block = blockById.get(d);
        if (!block) continue;
        const phi: IRPhi = {
          kind: 'phi',
          dest: irReg(reg),
          operands: block.preds.map(p => ({ blockId: p, value: irReg(reg) })),
        };
        phis.get(d)!.push(phi);
        if (!defBlocks.has(d)) {
          defBlocks.add(d);
          worklist.push(d);
        }
      }
    }
  }

  return phis;
}

// ── Variable Renaming ──

export function renameVariables(
  blocks: BasicBlock[],
  liftedBlocks: Map<number, IRStmt[]>,
  phis: Map<number, IRPhi[]>,
  domTree: Map<number, number[]>,
  entry: number,
): void {
  const counter = new Map<string, number>();
  const stacks = new Map<string, number[]>();
  const blockById = new Map<number, BasicBlock>();
  for (const b of blocks) blockById.set(b.id, b);

  function newVersion(reg: string): number {
    const canon = canonReg(reg);
    const ver = counter.get(canon) ?? 0;
    counter.set(canon, ver + 1);
    if (!stacks.has(canon)) stacks.set(canon, []);
    stacks.get(canon)!.push(ver);
    return ver;
  }

  function currentVersion(reg: string): number {
    const canon = canonReg(reg);
    const stack = stacks.get(canon);
    if (!stack || stack.length === 0) return -1;
    return stack[stack.length - 1];
  }

  function renameExpr(expr: IRExpr): IRExpr {
    switch (expr.kind) {
      case 'reg': {
        const ver = currentVersion(expr.name);
        return { ...expr, version: ver >= 0 ? ver : 0 };
      }
      case 'binary':
        return { ...expr, left: renameExpr(expr.left), right: renameExpr(expr.right) };
      case 'unary':
        return { ...expr, operand: renameExpr(expr.operand) };
      case 'deref':
        return { ...expr, address: renameExpr(expr.address) };
      case 'call':
        return { ...expr, args: expr.args.map(renameExpr) };
      case 'ternary':
        return { ...expr, condition: renameExpr(expr.condition), then: renameExpr(expr.then), else: renameExpr(expr.else) };
      case 'cast':
        return { ...expr, operand: renameExpr(expr.operand) };
      default:
        return expr;
    }
  }

  function renameBlock(blockId: number) {
    const block = blockById.get(blockId);
    if (!block) return;

    const pushCounts = new Map<string, number>();
    function trackPush(reg: string) {
      const canon = canonReg(reg);
      pushCounts.set(canon, (pushCounts.get(canon) ?? 0) + 1);
    }

    // Rename phi destinations
    const blockPhis = phis.get(blockId) ?? [];
    for (const phi of blockPhis) {
      const canon = canonReg(phi.dest.name);
      const ver = newVersion(canon);
      trackPush(canon);
      phi.dest = { ...phi.dest, name: canon, version: ver };
    }

    // Rename statements
    const stmts = liftedBlocks.get(blockId) ?? [];
    const renamed: IRStmt[] = [];
    for (const s of stmts) {
      renamed.push(renameStmt(s));
    }
    liftedBlocks.set(blockId, renamed);

    function renameStmt(stmt: IRStmt): IRStmt {
      switch (stmt.kind) {
        case 'assign': {
          const src = renameExpr(stmt.src);
          if (stmt.dest.kind === 'reg') {
            const canon = canonReg(stmt.dest.name);
            const ver = newVersion(canon);
            trackPush(canon);
            return { ...stmt, dest: { ...stmt.dest, version: ver }, src };
          }
          if (stmt.dest.kind === 'deref') {
            return { ...stmt, dest: { ...stmt.dest, address: renameExpr(stmt.dest.address) } as IRExpr, src };
          }
          return { ...stmt, src };
        }
        case 'store':
          return { ...stmt, address: renameExpr(stmt.address), value: renameExpr(stmt.value) };
        case 'call_stmt': {
          const call = { ...stmt.call, args: stmt.call.args.map(renameExpr) };
          let resultDest = stmt.resultDest;
          if (resultDest?.kind === 'reg') {
            const canon = canonReg(resultDest.name);
            const ver = newVersion(canon);
            trackPush(canon);
            resultDest = { ...resultDest, version: ver };
          }
          return { ...stmt, call, resultDest };
        }
        case 'return':
          return stmt.value ? { ...stmt, value: renameExpr(stmt.value) } : stmt;
        default:
          return stmt;
      }
    }

    // Fill phi operands in successors
    for (const succId of block.succs) {
      const succPhis = phis.get(succId) ?? [];
      for (const phi of succPhis) {
        const canon = canonReg(phi.dest.name);
        for (const op of phi.operands) {
          if (op.blockId === blockId) {
            const ver = currentVersion(canon);
            op.value = { kind: 'reg', name: canon, size: phi.dest.size, version: ver >= 0 ? ver : 0 };
          }
        }
      }
    }

    // Recurse into dominator tree children
    for (const child of domTree.get(blockId) ?? []) {
      renameBlock(child);
    }

    // Pop versions
    for (const [canon, count] of pushCounts) {
      const stack = stacks.get(canon)!;
      for (let i = 0; i < count; i++) stack.pop();
    }
  }

  renameBlock(entry);
}

// ── Orchestrator ──

export function buildSSA(
  blocks: BasicBlock[],
  liftedBlocks: Map<number, IRStmt[]>,
): SSAContext {
  if (blocks.length === 0) {
    return { blocks, liftedBlocks, phis: new Map(), idom: new Map(), domTree: new Map() };
  }

  const rpo = computeRPO(blocks);
  const idom = computeDominators(blocks, rpo);
  const domFrontier = computeDomFrontier(blocks, idom);
  const domTree = computeDomTree(idom);
  const phis = insertPhis(blocks, liftedBlocks, domFrontier);

  renameVariables(blocks, liftedBlocks, phis, domTree, rpo[0]);

  return { blocks, liftedBlocks, phis, idom, domTree };
}
