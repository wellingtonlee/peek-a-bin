import type { BasicBlock } from "../cfg";
import type { IRExpr, IRPhi, IRStmt } from "./ir";
import { canonReg, irReg } from "./ir";

export interface SSAContext {
  blocks: BasicBlock[];
  liftedBlocks: Map<number, IRStmt[]>;
  phis: Map<number, IRPhi[]>;
  idom: Map<number, number>;
  domTree: Map<number, number[]>;
  /**
   * `canonicalName_version` keys handed out by a *call* rather than by a
   * statement — see `clobberedByCall`. Nothing in the IR defines them, so a read
   * carrying one is a read of an indeterminate machine value.
   */
  clobbered: Set<string>;
}

/**
 * The Windows x64 fastcall argument registers, in order. `lifter.ts` fills a
 * call's argument list from exactly this sequence and stops at the first one the
 * block never wrote, so an argument in position *i* that is a bare read of
 * `FASTCALL_ARG_REGS[i]` is the lifter saying "this register was passed to this
 * call" — see `clobberedByCall`.
 */
const FASTCALL_ARG_REGS = ["rcx", "rdx", "r8", "r9"];

/**
 * The registers a call destroys: the ones the decompiler has already said the
 * call was *given*.
 *
 * The ABI's volatile set is wider — RAX, RCX, RDX and R8-R11 on Windows x64 —
 * and clobbering all of it is what the machine permits but not what compiled
 * code does. Measured on t64/t32/w64: MSVC parks live values in R10 across calls
 * to helpers it has analysed (t64!sub_1400063E8 holds `[rcx]` in R10 across two
 * of them), and `__chkstk` preserves everything but RAX/R10/R11 by documented
 * contract, so the arguments of every function with a large frame are read after
 * a call to it. Treating the whole volatile set as destroyed renamed 17 reads of
 * t64!sub_14000D8C4's own parameters and deleted a guard outright in
 * t64!sub_140004A9C. A read of R10 after a call is *evidence the compiler proved
 * it survives*; a read of an argument register the same call consumed is not.
 *
 * RAX needs nothing here: `liftBlock` already gives every `call_stmt` a
 * `resultDest` of RAX/EAX, which is a definition in its own right.
 *
 * So this is narrower than the ABI on purpose. It is the part that is supported
 * by the decompiler's own reading of the call rather than only by what a
 * conforming callee is allowed to do (peek-a-bin-0t4).
 */
export function clobberedByCall(stmt: IRStmt): string[] {
  if (stmt.kind !== "call_stmt") return [];
  const out: string[] = [];
  for (let i = 0; i < stmt.call.args.length && i < FASTCALL_ARG_REGS.length; i++) {
    const arg = stmt.call.args[i];
    // 32-bit arguments come from `push`, so they are stack expressions and never
    // match — x86 gets no clobber, which is the conservative reading: cdecl and
    // stdcall pass nothing in ECX/EDX, so nothing here says the callee used them.
    if (arg.kind === "reg" && canonReg(arg.name) === FASTCALL_ARG_REGS[i])
      out.push(FASTCALL_ARG_REGS[i]);
  }
  return out;
}

/** The `regKey` spelling `ssaopt.ts` and `SSAContext.clobbered` share. */
export function versionKey(canon: string, version: number): string {
  return `${canon}_${version}`;
}

/**
 * The name a read of a clobbered version emits under.
 *
 * It is a *variable*, and one that nothing ever assigns: the value the call left
 * in the register is not recoverable, and naming it after the register would put
 * the emitted C back where it started — C's `rcx` still holds whatever the last
 * `rcx = …` line put there, so a bare `rcx` after a call reads exactly the
 * pre-call value the machine destroyed. One name per (register, version) rather
 * than per occurrence, because two reads of the same clobbered version really
 * are the same indeterminate value.
 */
export function clobberedName(canon: string, version: number): string {
  return `clobbered_${canon}_${version}`;
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

  // Walking up the idom chain assumes every node reached has both an idom entry
  // and an RPO index. That holds for a well-formed CFG, but these blocks come
  // from disassembling untrusted bytes and callers may pass a stale `rpo`, so a
  // broken chain (missing entry, self-loop, or cycle) must degrade to a
  // conservative answer instead of spinning this worker thread forever.
  // Every walk is bounded and every lookup that comes back empty bails out.
  const maxSteps = rpo.length * 2 + 8;

  function intersect(b1: number, b2: number): number {
    let f1 = b1,
      f2 = b2;
    let steps = 0;
    while (f1 !== f2) {
      let moved = false;
      while ((rpoIndex.get(f1) ?? 0) > (rpoIndex.get(f2) ?? 0)) {
        const next = idom.get(f1);
        if (next === undefined || next === f1) return f2; // chain ends early
        f1 = next;
        moved = true;
        if (++steps > maxSteps) return entry; // cyclic idom — entry dominates all
      }
      while ((rpoIndex.get(f2) ?? 0) > (rpoIndex.get(f1) ?? 0)) {
        const next = idom.get(f2);
        if (next === undefined || next === f2) return f1;
        f2 = next;
        moved = true;
        if (++steps > maxSteps) return entry;
      }
      // Distinct nodes with equal RPO rank (only reachable when a node is
      // missing from the RPO): neither pointer can advance, so stop.
      if (!moved) return entry;
    }
    return f1;
  }

  let changed = true;
  // The fixpoint converges in a handful of passes for real CFGs; the cap only
  // matters if an imprecise intersect() result above makes an entry oscillate.
  let passes = 0;
  while (changed) {
    changed = false;
    if (++passes > rpo.length + 2) break;
    for (let i = 1; i < rpo.length; i++) {
      const b = rpo[i];
      const block = blockById.get(b);
      if (!block) continue;

      let newIdom = -1;
      for (const p of block.preds) {
        if (idom.has(p)) {
          newIdom = p;
          break;
        }
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
    const stop = idom.get(b.id);
    for (const p of b.preds) {
      let runner: number | undefined = p;
      // Bounded: a malformed idom map can be cyclic, which would otherwise walk
      // forever here. A chain longer than the block count must contain a cycle.
      let steps = 0;
      while (runner !== undefined && runner !== stop) {
        const frontier = df.get(runner);
        if (!frontier) break; // runner isn't a block in this CFG
        frontier.add(b.id);
        runner = idom.get(runner);
        if (++steps > blocks.length) break;
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

// ── Natural Loop Detection ──

/** Detect natural loops: for each back-edge (succ → header where header dominates succ),
 *  collect loop body via reverse walk from succ, stopping at header.
 *  Returns: header blockId → set of body blockIds (including header). */
export function detectNaturalLoops(
  blocks: BasicBlock[],
  idom: Map<number, number>,
  _domTree: Map<number, number[]>,
): Map<number, Set<number>> {
  const loops = new Map<number, Set<number>>();
  const blockById = new Map<number, BasicBlock>();
  for (const b of blocks) blockById.set(b.id, b);

  // Check if a dominates b
  function dominates(a: number, b: number): boolean {
    let cur = b;
    // Bounded for the same reason as computeDomFrontier: a cyclic idom map
    // would otherwise loop forever.
    let steps = 0;
    while (cur !== a) {
      const parent = idom.get(cur);
      if (parent === undefined || parent === cur) return false;
      cur = parent;
      if (++steps > blocks.length) return false;
    }
    return true;
  }

  // Find back edges: edge (src → target) where target dominates src
  for (const block of blocks) {
    for (const succ of block.succs) {
      if (dominates(succ, block.id)) {
        // Back edge: block → succ (succ is the loop header)
        const header = succ;
        if (!loops.has(header)) loops.set(header, new Set([header]));
        const body = loops.get(header)!;

        // Reverse DFS from block, collecting until header
        const worklist = [block.id];
        while (worklist.length > 0) {
          const n = worklist.pop()!;
          if (body.has(n)) continue;
          body.add(n);
          const b = blockById.get(n);
          if (b) {
            for (const pred of b.preds) {
              if (!body.has(pred)) worklist.push(pred);
            }
          }
        }
      }
    }
  }

  return loops;
}

// ── Liveness & Phi Insertion ──

function collectDefs(stmts: IRStmt[]): Set<string> {
  const defs = new Set<string>();
  for (const s of stmts) {
    if (s.kind === "assign" && s.dest.kind === "reg") {
      defs.add(canonReg(s.dest.name));
    }
    if (s.kind === "call_stmt") {
      // A call defines the registers it was passed, not just its result
      // register. Phi placement keys off this: without it, a join whose one arm
      // calls and whose other does not gets no phi for RCX, so a read at the
      // join binds straight through to the definition the call consumed.
      if (s.resultDest?.kind === "reg") defs.add(canonReg(s.resultDest.name));
      for (const r of clobberedByCall(s)) defs.add(r);
    }
  }
  return defs;
}

function stmtUses(s: IRStmt): Set<string> {
  const uses = new Set<string>();
  function walk(e: IRExpr) {
    if (e.kind === "reg") {
      uses.add(canonReg(e.name));
      return;
    }
    if (e.kind === "binary") {
      walk(e.left);
      walk(e.right);
      return;
    }
    if (e.kind === "unary") {
      walk(e.operand);
      return;
    }
    if (e.kind === "deref") {
      walk(e.address);
      return;
    }
    if (e.kind === "call") {
      e.args.forEach(walk);
      return;
    }
    if (e.kind === "ternary") {
      walk(e.condition);
      walk(e.then);
      walk(e.else);
      return;
    }
    if (e.kind === "cast") {
      walk(e.operand);
      return;
    }
    if (e.kind === "field_access") {
      walk(e.base);
      return;
    }
    if (e.kind === "array_access") {
      walk(e.base);
      walk(e.index);
      return;
    }
  }
  switch (s.kind) {
    case "assign":
      walk(s.src);
      if (s.dest.kind === "deref") walk(s.dest.address);
      break;
    case "store":
      walk(s.address);
      walk(s.value);
      break;
    case "call_stmt":
      s.call.args.forEach(walk);
      break;
    case "return":
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
      if (s.kind === "assign" && s.dest.kind === "reg") defined.add(canonReg(s.dest.name));
      if (s.kind === "call_stmt") {
        if (s.resultDest?.kind === "reg") defined.add(canonReg(s.resultDest.name));
        // Same reason as `collectDefs`: an argument register read *after* the
        // call that consumed it is not an upward-exposed use, so it must not
        // make the register live-in and pull a phi (and a definition) from above.
        for (const r of clobberedByCall(s)) defined.add(r);
      }
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
          kind: "phi",
          dest: irReg(reg),
          operands: block.preds.map((p) => ({ blockId: p, value: irReg(reg) })),
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
  /** Filled with the `versionKey`s a call handed out. See `SSAContext.clobbered`. */
  clobbered: Set<string> = new Set(),
): void {
  const counter = new Map<string, number>();
  const stacks = new Map<string, number[]>();
  const blockById = new Map<number, BasicBlock>();
  for (const b of blocks) blockById.set(b.id, b);

  function newVersion(reg: string): number {
    const canon = canonReg(reg);
    // Version 0 is reserved for the register's function-entry value: a read with
    // an empty version stack is an incoming/parameter value, and both readers
    // below map that to version 0. So the first *definition* must be 1. With the
    // counter starting at 0 the incoming value and the first definition were the
    // same (canonical name, version) pair, and every pass in ssaopt.ts that keys
    // on that pair — copy/constant propagation, GVN, DCE — treated them as one
    // value, rewriting entry values with a definition that may not have run.
    const ver = counter.get(canon) ?? 1;
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
      case "reg": {
        const ver = currentVersion(expr.name);
        return { ...expr, version: ver >= 0 ? ver : 0 };
      }
      case "binary":
        return { ...expr, left: renameExpr(expr.left), right: renameExpr(expr.right) };
      case "unary":
        return { ...expr, operand: renameExpr(expr.operand) };
      case "deref":
        return { ...expr, address: renameExpr(expr.address) };
      case "call":
        return { ...expr, args: expr.args.map(renameExpr) };
      case "ternary":
        return {
          ...expr,
          condition: renameExpr(expr.condition),
          then: renameExpr(expr.then),
          else: renameExpr(expr.else),
        };
      case "cast":
        return { ...expr, operand: renameExpr(expr.operand) };
      case "field_access":
        return { ...expr, base: renameExpr(expr.base) };
      case "array_access":
        return { ...expr, base: renameExpr(expr.base), index: renameExpr(expr.index) };
      case "const":
      case "var":
      case "unknown":
        return expr; // leaf kinds — nothing to rename
      default: {
        // Compile error if a new IRExpr kind is added without handling it here.
        const _exhaustive: never = expr;
        return _exhaustive;
      }
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
        case "assign": {
          const src = renameExpr(stmt.src);
          if (stmt.dest.kind === "reg") {
            const canon = canonReg(stmt.dest.name);
            const ver = newVersion(canon);
            trackPush(canon);
            return { ...stmt, dest: { ...stmt.dest, version: ver }, src };
          }
          if (stmt.dest.kind === "deref") {
            return {
              ...stmt,
              dest: { ...stmt.dest, address: renameExpr(stmt.dest.address) } as IRExpr,
              src,
            };
          }
          return { ...stmt, src };
        }
        case "store":
          return { ...stmt, address: renameExpr(stmt.address), value: renameExpr(stmt.value) };
        case "call_stmt": {
          // Arguments are renamed first, so they still read the versions that
          // reached the call site; the clobber applies to everything after it.
          const call = { ...stmt.call, args: stmt.call.args.map(renameExpr) };
          let resultDest = stmt.resultDest;
          let resultCanon: string | null = null;
          if (resultDest?.kind === "reg") {
            resultCanon = canonReg(resultDest.name);
            const ver = newVersion(resultCanon);
            trackPush(resultCanon);
            resultDest = { ...resultDest, version: ver };
          }
          // Each argument register the call consumed gets a fresh version too,
          // with no statement behind it. That is the whole point: a later read
          // now binds to a version the call created rather than to the
          // definition the call consumed, and no pass can propagate a value it
          // cannot find a definition for.
          for (const canon of clobberedByCall({ ...stmt, call })) {
            if (canon === resultCanon) continue;
            const ver = newVersion(canon);
            trackPush(canon);
            clobbered.add(versionKey(canon, ver));
          }
          return { ...stmt, call, resultDest };
        }
        case "return":
          return stmt.value ? { ...stmt, value: renameExpr(stmt.value) } : stmt;
        // A branch reads its condition and defines nothing. Renaming it here is
        // the entire point of the kind: it is what gives a guard's registers an
        // SSA version, so a reaching definition can be found for them and no
        // pass can silently bind the guard to a value the machine never tested.
        case "branch":
          return { ...stmt, condition: renameExpr(stmt.condition) };
        // Renaming runs before structuring, so these kinds carry no registers to
        // rename here (phi destinations/operands are handled separately above).
        case "if":
        case "while":
        case "do_while":
        case "for":
        case "switch":
        case "goto":
        case "label":
        case "comment":
        case "raw":
        case "break":
        case "continue":
        case "phi":
        case "try":
          return stmt;
        default: {
          const _exhaustive: never = stmt;
          return _exhaustive;
        }
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
            op.value = {
              kind: "reg",
              name: canon,
              size: phi.dest.size,
              version: ver >= 0 ? ver : 0,
            };
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

export function buildSSA(blocks: BasicBlock[], liftedBlocks: Map<number, IRStmt[]>): SSAContext {
  if (blocks.length === 0) {
    return {
      blocks,
      liftedBlocks,
      phis: new Map(),
      idom: new Map(),
      domTree: new Map(),
      clobbered: new Set(),
    };
  }

  const rpo = computeRPO(blocks);
  const idom = computeDominators(blocks, rpo);
  const domFrontier = computeDomFrontier(blocks, idom);
  const domTree = computeDomTree(idom);
  const phis = insertPhis(blocks, liftedBlocks, domFrontier);

  const clobbered = new Set<string>();
  renameVariables(blocks, liftedBlocks, phis, domTree, rpo[0], clobbered);

  return { blocks, liftedBlocks, phis, idom, domTree, clobbered };
}
