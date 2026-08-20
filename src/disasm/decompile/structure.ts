import type { BasicBlock, Loop } from "../cfg";
import { detectForLoop, detectMultiExitLoop, detectShortCircuit } from "./cfgpatterns";
import type { ClobberScan } from "./flagModel";
import { clobberedAfter, flagScanStream, isFlagTransparent, solePredecessor } from "./flagModel";
import type { IRBranch, IRExpr, IRStmt } from "./ir";
import { bodiesOf, canonReg, irReg, isKnownRegister, rewriteBodies, walkExpr } from "./ir";
import { parseOperand, setFlagsFromCompare } from "./lifter";
import { RegState } from "./regstate";
import { computeDominators, computeRPO } from "./ssa";

/**
 * The label a `goto` to a block spells. One function so the `goto` and the
 * label that receives it cannot drift on formatting — `emit.ts`'s
 * `labelForAddr` derives the same name from the same address for the labels it
 * places itself, and has its own note about why.
 */
function labelNameFor(addr: number): string {
  return `loc_${addr.toString(16).toUpperCase()}`;
}

/** The union of two `clobberedAfter` scans: written by either, opaque to either. */
function mergeClobberScans(a: ClobberScan, b: ClobberScan): ClobberScan {
  return {
    regs: new Set([...a.regs, ...b.regs]),
    opaque: a.opaque || b.opaque,
    writesMemory: a.writesMemory || b.writesMemory,
  };
}

/**
 * Has anything between the flag-setting instruction and the block's Jcc written
 * over a name the recovered condition is spelled with?
 *
 * The guard is emitted *after* the block's statements, and that ordering is
 * what makes this a question at all. So `cmp eax, 5 / mov eax, edx / je` emits
 * `eax = edx;` and then `if (eax != 5)`, which reads the new EAX where the
 * machine compared the old one: right operator, wrong operands
 * (peek-a-bin-xe01).
 *
 * The scan is `flagModel.ts`'s `clobberedAfter`. Its forward twin is `spoils`
 * in the same module, which `lifter.ts` asks of a *result* owner before
 * building a branch from it — one grammar, asked at the two points where the
 * question arises. It used to be asked here and by `flagResultSetter`, and
 * those two paths had disagreed about whether a later write mattered at all.
 *
 * Refusing is the whole repair: the caller returns `unknown`, the emitter
 * prints `__unrecovered_N /* jcc *\/`, and the reader is told the condition was
 * not recovered instead of being told a test the machine does not make. Naming
 * the *old* value instead would mean materialising a temporary before the
 * clobber, which is a lifter change and not this one.
 *
 * `predBlock` widens the scan across one edge, and is passed exactly when the
 * setter was found in the block's sole predecessor (see `flagScanStream`). Two
 * scans are then unioned and each covers a different stretch. The predecessor's
 * is `clobberedAfter(predBlock, flagSetterAddr)`, which already means "after the
 * setter and before the block's final instruction" — the predecessor's tail
 * minus its own terminator, which is exactly the right stretch with no new
 * grammar. The block's own is taken from `-1` rather than from the setter's
 * address, because the setter is in *another* block and `clobberedAfter` filters
 * by address: a predecessor reached by a backward jump sits at a *higher*
 * address than the block it feeds, so passing the setter's address there would
 * silently skip the block's instructions and under-scan. From `-1` it reads all
 * of them, which is the whole stretch between the setter and the guard on this
 * side of the edge (peek-a-bin-suql).
 */
function conditionSpoiled(
  block: BasicBlock,
  flagSetterAddr: number,
  cond: IRExpr,
  predBlock?: BasicBlock,
): boolean {
  const clobbered = predBlock
    ? mergeClobberScans(clobberedAfter(predBlock, flagSetterAddr), clobberedAfter(block, -1))
    : clobberedAfter(block, flagSetterAddr);
  if (clobbered.opaque) return true;
  if (clobbered.regs.size === 0 && !clobbered.writesMemory) return false;
  let spoiled = false;
  walkExpr(cond, (e) => {
    if (e.kind === "reg") {
      if (isKnownRegister(e.name) && clobbered.regs.has(canonReg(e.name))) spoiled = true;
    } else if (e.kind === "deref" && clobbered.writesMemory) spoiled = true;
  });
  return spoiled;
}

/** Index of the first statement that is not a label, or -1 if there is none. */
function firstNonLabel(stmts: IRStmt[]): number {
  for (let i = 0; i < stmts.length; i++) if (stmts[i].kind !== "label") return i;
  return -1;
}

/**
 * Push `if (condition) thenBody else elseBody`, with the arms reduced to what
 * they actually contribute.
 *
 * An arm holding nothing but labels contributes no behaviour — it is an empty
 * branch — but the labels are anchors for `goto`s and cannot simply be dropped.
 * They move out to just after the `if`, which is where that arm goes anyway:
 * an empty arm falls straight through to the join, and the join is what follows
 * the `if`. Without this an arm whose blocks all lifted to nothing would read
 * as a real `else`, and the negate-and-hoist that turns `if (c) {} else {x}`
 * into `if (!c) {x}` would stop firing.
 */
function pushConditional(
  out: IRStmt[],
  condition: IRExpr,
  thenBody: IRStmt[],
  elseBody: IRStmt[],
): void {
  const isLabel = (s: IRStmt) => s.kind === "label";
  const thenRuns = thenBody.some((s) => !isLabel(s));
  const elseRuns = elseBody.some((s) => !isLabel(s));

  if (thenRuns && elseRuns) {
    out.push({ kind: "if", condition, thenBody, elseBody });
  } else if (thenRuns) {
    out.push({ kind: "if", condition, thenBody });
    out.push(...elseBody.filter(isLabel));
  } else if (elseRuns) {
    out.push({ kind: "if", condition: RegState.negate(condition), thenBody: elseBody });
    out.push(...thenBody.filter(isLabel));
  } else {
    out.push(...thenBody.filter(isLabel), ...elseBody.filter(isLabel));
  }
}

/**
 * Is there a `continue` bound to *this* loop anywhere in `body`?
 *
 * Nested loops are not searched: a `continue` inside one belongs to it. The
 * question matters only for `for`, where `continue` runs the update expression;
 * the back edge it stands for jumps straight to the test and runs nothing.
 */
function hasFreeContinue(stmts: IRStmt[]): boolean {
  for (const s of stmts) {
    if (s.kind === "continue") return true;
    if (s.kind === "while" || s.kind === "do_while" || s.kind === "for") continue;
    for (const nested of bodiesOf(s)) if (hasFreeContinue(nested)) return true;
  }
  return false;
}

/**
 * Drop every label nothing jumps to, and any repeat of a name already defined.
 *
 * `structureFrom` puts a label in front of every block it emits, because which
 * blocks turn out to be `goto` targets is only known once the whole walk is
 * done — a back edge discovered late refers to a block emitted long before.
 * Keeping them all would bury the reader in `loc_` lines for straight-line
 * code, so the sweep afterwards keeps only the ones a `goto` actually needs.
 *
 * `pinned` names survive regardless: the leftover pass introduces a region the
 * walk never reached, and its label is what tells the reader the code above it
 * does not fall into it.
 *
 * A duplicate definition of the same label does not compile, so the first one
 * wins; the walk visits a block once, but nothing downstream guarantees that.
 */
function pruneLabels(stmts: IRStmt[], pinned: Set<string>): IRStmt[] {
  const targets = new Set<string>();
  const collect = (list: IRStmt[]): void => {
    for (const s of list) {
      if (s.kind === "goto") targets.add(s.label);
      for (const nested of bodiesOf(s)) collect(nested);
    }
  };
  collect(stmts);

  const defined = new Set<string>();
  const rewrite = (list: IRStmt[]): IRStmt[] => {
    const out: IRStmt[] = [];
    for (const s of list) {
      if (s.kind === "label") {
        if (!targets.has(s.name) && !pinned.has(s.name)) continue;
        if (defined.has(s.name)) continue;
        defined.add(s.name);
        out.push(s);
        continue;
      }
      out.push(rewriteBodies(s, rewrite));
    }
    return out;
  };
  return rewrite(stmts);
}

/**
 * Immediate post-dominators: the dominators of the reversed CFG, rooted at a
 * virtual exit that every returning block feeds.
 *
 * `ipdom(b)` is the block where the arms of a branch in `b` are guaranteed to
 * be back together — exactly the join an `if` closes at. Blocks that cannot
 * reach any exit (an infinite loop, or a tail call that leaves the function)
 * simply get no entry, and the caller falls back to its search.
 */
function computePostDominators(blocks: BasicBlock[]): Map<number, number> {
  const exitId = Math.max(...blocks.map((b) => b.id)) + 1;
  const returning = blocks.filter((b) => b.succs.length === 0).map((b) => b.id);
  if (returning.length === 0) return new Map();

  const virtualExit: BasicBlock = {
    id: exitId,
    startAddr: -1,
    endAddr: -1,
    insns: [],
    succs: returning,
    preds: [],
  };
  const returningSet = new Set(returning);
  const reversed: BasicBlock[] = [
    virtualExit,
    ...blocks.map((b) => ({
      ...b,
      succs: b.preds,
      preds: returningSet.has(b.id) ? [...b.succs, exitId] : b.succs,
    })),
  ];

  const ipdom = computeDominators(reversed, computeRPO(reversed));
  ipdom.delete(exitId);
  // A block whose post-dominator is the virtual exit has no real join point.
  for (const [id, pd] of ipdom) if (pd === exitId) ipdom.delete(id);
  return ipdom;
}

/**
 * Structure a CFG into high-level control flow (if/while/do-while/switch).
 *
 * Approach: recursive structural analysis over basic blocks, using the loop
 * detection results and the post-dominator tree.
 *
 * `is64` reaches only `extractCondition`, which parses the `cmp`/`test`
 * operands of a branch with the lifter's parser. It is optional because the
 * default reproduces exactly what the hand-rolled parser it replaced did: that
 * parser hardcoded a width of 4, and `is64: false` is what makes
 * `parseOperand` fall back to 4 for an immediate and for a memory operand with
 * no size prefix. Passing the real value is strictly better and costs nothing,
 * but omitting it cannot make a condition worse than it already was.
 */
export function structureCFG(
  blocks: BasicBlock[],
  loops: Loop[],
  liftedBlocks: Map<number, IRStmt[]>,
  jumpTables: Map<number, number[]>,
  is64 = false,
  branches: Map<number, IRBranch> = new Map(),
): IRStmt[] {
  if (blocks.length === 0) return [];

  // Build helper maps
  const blockById = new Map<number, BasicBlock>();
  const blockByAddr = new Map<number, BasicBlock>();
  for (const b of blocks) {
    blockById.set(b.id, b);
    blockByAddr.set(b.startAddr, b);
  }

  // Loop header addresses
  const loopHeaderSet = new Set<number>();
  const loopByHeader = new Map<number, Loop>();
  for (const loop of loops) {
    loopHeaderSet.add(loop.headerAddr);
    loopByHeader.set(loop.headerAddr, loop);
  }

  const visited = new Set<number>();
  const ipdom = computePostDominators(blocks);

  /**
   * Blocks whose `loc_` label has actually been pushed somewhere in the output.
   *
   * `visited` is not the same question. A block is marked visited by whoever
   * claims it, and every claimant emits its label *except* the short-circuit
   * fold, which consumes the blocks between two tests without emitting
   * anything for them. A `goto` naming one of those would be a label reference
   * to nothing, which does not compile — so the one place that has to name an
   * already-claimed block by label asks this rather than `visited`.
   */
  const labelled = new Set<number>();

  /** Push the `loc_` label for `block`, recording that the name now exists. */
  function pushLabel(out: IRStmt[], block: BasicBlock): void {
    labelled.add(block.id);
    out.push({ kind: "label", name: labelNameFor(block.startAddr) });
  }

  /**
   * Blocks whose closing conditional jump *is* a `do`/`while`'s condition.
   *
   * The back-edge test of a bottom-tested loop is spelled by the loop
   * statement itself, so the walk must not also spell it inside the body —
   * `do { …; if (c) goto top; } while (c)` says the same thing twice. Every
   * other dropped arm is restored as a `goto` (see `armFrom`); this is the one
   * place where dropping it is what makes the output true.
   */
  const backEdgeConditionBlocks = new Set<number>();

  /**
   * Label names that survive `pruneLabels` even with no `goto` naming them.
   *
   * A region the walk reached only by starting a fresh walk at it is not
   * fallen into from the code above it, and its label is what says so. Both
   * places that introduce one — the leftover pass at the end of this function
   * and the same sweep inside `structureLoop` — record the name here.
   */
  const pinned = new Set<string>();

  /**
   * Get the condition from the last instruction(s) of a block.
   *
   * The `cmp`/`test` operands are parsed by `lifter.ts`'s `parseOperand`, the
   * same function the lifter itself uses. It used to be a private
   * `parseSimpleOperand` here, and the two disagreed in the two ways such a
   * copy always eventually does: it hardcoded a width of 4, so `cmp byte ptr
   * [rcx], dl` read as a 32-bit load, and it never went through
   * `ripRelative.ts`, so `cmp byte ptr [rip + 0x13358], 0` kept the literal
   * `rip + 0x…` — while `mov eax, dword ptr [rip + 0x142b3]` in the same
   * function resolved to an absolute address, because *that* went through the
   * lifter. CLAUDE.md records that `ripRelative.ts` exists because this parse
   * was hand-rolled nine times; this was the tenth.
   */
  function extractCondition(block: BasicBlock): IRExpr {
    const insns = block.insns;
    if (insns.length === 0) return { kind: "unknown", text: "empty block" };

    const last = insns[insns.length - 1];
    const mn = last.mnemonic.toLowerCase();

    // Conditional jump → build condition from cmp/test before it
    if (mn.startsWith("j") && mn !== "jmp") {
      // Find the cmp/test before this jump.
      //
      // The walk is forward and LAST WRITER WINS, which is why it has to know
      // what writes the flags. It used to call `setFlags` on each `cmp`/`test`
      // it passed and nothing ever cleared them — not a call, not arithmetic,
      // not a shift — so `cmp eax, 5 / … / sub ecx, edx / jne` emitted
      // `eax != 5` where the machine branches on `ecx - edx != 0`: the right
      // operator over operands belonging to a test that no longer holds
      // (peek-a-bin-jitf). `isFlagTransparent` is `flagModel.ts`'s own table,
      // exported rather than copied, and anything not on it — including
      // anything unrecognised — ends the reading, which is the safe direction.
      //
      // What the walk reads is `flagModel.ts`'s `flagScanStream`, not the block
      // alone. A Jcc whose block writes no flag reads the flags of the block
      // before it, and where there is exactly one such block the stream starts
      // in it — the same rule, from the same declaration, that `lifter.ts` uses
      // to build the `IRBranch`, so the reading this refuses over and the
      // reading the IR offers below cannot come off different instructions
      // (peek-a-bin-suql).
      const solePred = solePredecessor(block, blockById);
      const scan = flagScanStream(block, solePred);
      const regState = new RegState();
      let flagSetterAddr: number | null = null;
      for (const insn of scan.insns) {
        const insnMn = insn.mnemonic.toLowerCase();
        if (insnMn === "cmp" || insnMn === "test") {
          // A `cmp` this cannot parse still WRITES the flags, so the previous
          // one has stopped applying either way — clear first, then record only
          // what was actually read.
          regState.clearFlags();
          flagSetterAddr = setFlagsFromCompare(regState, insn, insnMn, is64) ? insn.address : null;
        } else if (!isFlagTransparent(insnMn)) {
          regState.clearFlags();
          flagSetterAddr = null;
        }
      }
      // ── The refusals, asked of the reading taken from the instructions ──
      //
      // Both are questions about the machine, not about the IR, and they must
      // be asked of the machine's own operand names. Asking them of the IR
      // condition instead defeats them: `cmp eax, 5 / mov eax, edx / je` has
      // its guard rebound to EDX by copy propagation, so by the time the
      // expression reaches here the register that was overwritten is not in it
      // and `conditionSpoiled` finds nothing to object to — while the emitted
      // test is still the one the machine does not make (peek-a-bin-xe01).
      const cond = regState.getCondition(mn);
      if (
        flagSetterAddr !== null &&
        cond.kind !== "unknown" &&
        conditionSpoiled(block, flagSetterAddr, cond, scan.fromPredecessor ? solePred : undefined)
      )
        return { kind: "unknown", text: mn };

      // ── The IR's answer, where there is one ──
      //
      // `liftBlock` built this from the same `RegState` and the same forward
      // walk, at the same program point, so it starts out the expression the
      // lines below would have produced. What makes it a better answer is
      // everything that has happened to it since: SSA renamed its registers to
      // the definitions that reach the Jcc, copy and constant propagation
      // rewrote them, `splitStaleReads` repaired the ones a later write had
      // spoiled, and `foldBlock` inlined any definition whose only remaining
      // reader is this guard. Re-parsing `insn.opStr` here threw all of that
      // away and named registers whose assignments those same passes had
      // deleted (peek-a-bin-c33, peek-a-bin-f50k).
      //
      // A block with no branch statement still reaches the `cmp`/`test`
      // reading above, and so does one whose condition the lifter could not
      // spell: an indirect or unresolved jump target records no branch at all,
      // and `jecxz` and friends read a register rather than the flags.
      //
      // **A Jcc whose flags come from arithmetic is answered here too, and only
      // here.** `dec ecx / jnz` used to take a second route — `flagResult.ts`'s
      // backward walk, re-deriving the setter from the instruction stream with
      // `ssaopt.ts` holding the `dec` alive by hand so it would still be there
      // to name — and that route's last check, "is this still the register's
      // last write", is what SSA answers by construction. `liftBlock` builds
      // the branch from the same flag model, so the whole apparatus was
      // measured dead on all four corpus binaries before it was removed
      // (peek-a-bin-c33 stage 4, peek-a-bin-wf7t).
      const fromIR = branches.get(block.id)?.condition;
      if (fromIR && fromIR.kind !== "unknown") return fromIR;

      return cond;
    }

    return { kind: "unknown", text: `end: ${mn}` };
  }

  /** BFS distances from `start`, in edges, never leaving `loopBody` if given. */
  function bfsDistances(start: number, loopBody?: Set<number>): Map<number, number> {
    const dist = new Map<number, number>([[start, 0]]);
    const queue = [start];
    let head = 0;
    while (head < queue.length) {
      const id = queue[head++];
      const d = dist.get(id)!;
      const block = blockById.get(id);
      if (!block) continue;
      for (const succ of block.succs) {
        if (dist.has(succ)) continue;
        // Don't leave loop body
        if (loopBody) {
          const succBlock = blockById.get(succ);
          if (
            succBlock &&
            !loopBody.has(succBlock.startAddr) &&
            !loopBody.has(succBlock.insns[0]?.address)
          )
            continue;
        }
        dist.set(succ, d + 1);
        queue.push(succ);
      }
    }
    return dist;
  }

  /**
   * Where the two arms of the branch in `blockId` come back together.
   *
   * The post-dominator is the answer whenever there is one: it is the block
   * every path out of the branch has to pass through, which is precisely what
   * an `if` closes at. `branchA`/`branchB` drive the fallback search for the
   * cases post-dominance cannot answer — a branch whose arms return
   * separately (no join at all), and a branch inside a loop body whose join
   * lies outside the body, where the caller has to stay within the loop.
   */
  function convergenceOf(
    blockId: number,
    branchA: number,
    branchB: number,
    loopBody?: Set<number>,
  ): number {
    const pd = ipdom.get(blockId);
    if (pd !== undefined && pd !== blockId) {
      const pdBlock = blockById.get(pd);
      if (
        pdBlock &&
        (!loopBody ||
          loopBody.has(pdBlock.startAddr) ||
          loopBody.has(pdBlock.insns[0]?.address ?? -1))
      ) {
        return pd;
      }
    }
    return findConvergence(branchA, branchB, loopBody);
  }

  /**
   * Find the convergence point of two branches: the block both reach with the
   * smallest total number of edges. Returns -1 if they never meet.
   *
   * A branch target may itself be the convergence — that is precisely the
   * `if` without an `else`, where one arm falls into the other's target. The
   * previous version excluded both branch heads and returned the first block
   * B's search happened to reach inside A's reachable set, so for two `if`s in
   * a row it picked the *second* merge, nested the second `if` inside the
   * first and left a `goto` into the middle of it. Scoring by combined
   * distance picks the nearest join instead, which for a diamond is still the
   * merge block (1 + 1) and for a triangle is the branch target itself
   * (0 + 1).
   */
  function findConvergence(branchA: number, branchB: number, loopBody?: Set<number>): number {
    const distA = bfsDistances(branchA, loopBody);
    const distB = bfsDistances(branchB, loopBody);

    let best = -1;
    let bestScore = Number.POSITIVE_INFINITY;
    // `distA` is in BFS order from A, so equal scores keep the block closer to
    // A — the deterministic choice the old fallback scan also made.
    for (const [id, da] of distA) {
      const db = distB.get(id);
      if (db === undefined) continue;
      if (da + db < bestScore) {
        bestScore = da + db;
        best = id;
      }
    }

    return best;
  }

  /** Check if a block ends with unconditional jmp. */
  function endsWithJmp(block: BasicBlock): boolean {
    const insns = block.insns;
    if (insns.length === 0) return false;
    return insns[insns.length - 1].mnemonic.toLowerCase() === "jmp";
  }

  /** Check if a block ends with a conditional jump. */
  function endsWithCondJmp(block: BasicBlock): boolean {
    const insns = block.insns;
    if (insns.length === 0) return false;
    const mn = insns[insns.length - 1].mnemonic.toLowerCase();
    return mn.startsWith("j") && mn !== "jmp";
  }

  /**
   * Where a conditional jump ending `block` goes when the CFG has no edge for
   * it, or `null` when it has one (or the block does not end in one).
   *
   * `buildCFG` only draws an edge to a target inside the instruction range it
   * was given, so a `jcc` past the end of the detected function leaves its
   * block with a single successor. Everything after that reads the block as
   * unconditional: the test disappears, and so does the fact that the machine
   * can leave there. In `t32!sub_4031A4` four such jumps vanish, two of them
   * inside a loop, and what came out was `do { … } while (1)` — an
   * unconditional `LeaveCriticalSection` inside a loop the reader is told never
   * ends (peek-a-bin-lbz).
   *
   * The transfer itself cannot be spelled: the destination is not in this
   * function, so there is no label to `goto` and no name to call. Stating the
   * test with a comment for its arm is the most that is true — a reader can see
   * the decision and where it goes. 37 conditional jumps across the corpus are
   * in this position (20 on t32, 17 on w32, none on either 64-bit binary); all
   * of them are a function whose detected end falls short of code that is
   * really part of it, so the standing fix belongs to `functionDetect.ts`.
   */
  function lostBranchTarget(block: BasicBlock): number | null {
    if (!endsWithCondJmp(block)) return null;
    const last = block.insns[block.insns.length - 1];
    const m = last.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (!m) return null;
    const target = parseInt(m[1], 16);
    const targetBlock = blockByAddr.get(target);
    if (targetBlock && block.succs.includes(targetBlock.id)) return null;
    return target;
  }

  /** Check if a block ends with ret. */
  function endsWithRet(block: BasicBlock): boolean {
    const insns = block.insns;
    if (insns.length === 0) return false;
    const mn = insns[insns.length - 1].mnemonic.toLowerCase();
    return mn === "ret" || mn === "retn";
  }

  /** Collect block IDs in a region between start and end (exclusive). */
  /**
   * Structure a sequence of blocks starting from blockId.
   * stopAt: set of block IDs to stop before (e.g., convergence point, loop exit).
   *
   * `enterStart` walks the starting block even though it is already visited or
   * in `stopAt`. Only the bottom-tested loop path uses it, to structure the
   * loop header as the first block of the body: the header is marked visited
   * before `structureLoop` is called and is in `stopAt` so the back edge stops
   * there, yet its own statements and branch belong to the body.
   */
  function structureFrom(
    blockId: number,
    stopAt: Set<number>,
    loopBody?: Set<number>,
    enterStart = false,
  ): IRStmt[] {
    const result: IRStmt[] = [];
    let current: number | null = blockId;
    let first = true;

    while (current !== null) {
      const forced = first && enterStart;
      first = false;
      if (!forced && (stopAt.has(current) || visited.has(current))) break;

      const block = blockById.get(current);
      if (!block) break;

      // Check for loop header
      const loop = loopByHeader.get(block.startAddr);
      if (loop && !visited.has(current) && !forced) {
        visited.add(current);
        const loopResult = structureLoop(block, loop);

        // A `for` header repeats the init assignment, which the walk has
        // already emitted as part of an earlier block. Emitting both runs it
        // twice, and `x = f()` run twice is a different program. When it is
        // the statement immediately before the loop it can simply move into
        // the header; otherwise the loop is demoted back to the `while` the
        // `for` was built from, with the update at the end of the body where
        // the machine put it.
        const asFor =
          loopResult.length === 1 && loopResult[0].kind === "for" ? loopResult[0] : null;
        if (asFor && result[result.length - 1] === asFor.init) {
          result.pop();
        } else if (asFor) {
          loopResult[0] = {
            kind: "while",
            condition: asFor.condition,
            body: [...asFor.body, asFor.update],
          };
        }

        // The header's label goes *before* the loop, not inside its body: a
        // jump to the header re-runs the test, which is what re-entering the
        // loop statement does and what jumping into the body would skip.
        pushLabel(result, block);
        result.push(...loopResult);

        // Continue after the loop from one of its exits: a successor of a body
        // block that lies outside the body.
        //
        // A loop can leave to several different places — the header test falls
        // out to one, a guard inside the body breaks to another — and only one
        // of them can be the block this walk carries on into. This used to keep
        // whichever candidate the scan happened to see last, which dropped the
        // rest of the function hanging off every other exit (peek-a-bin-cb2).
        // The lowest address is picked instead so the choice does not depend on
        // block ordering, and the leftover pass at the end of `structureCFG`
        // picks up the exits this walk does not reach.
        const exits: number[] = [];
        for (const bid of blocks) {
          if (!loop.bodyAddrs.has(bid.startAddr) && !loop.bodyAddrs.has(bid.insns[0]?.address))
            continue;
          for (const succ of bid.succs) {
            const succBlock = blockById.get(succ);
            if (
              succBlock &&
              !loop.bodyAddrs.has(succBlock.startAddr) &&
              !loop.bodyAddrs.has(succBlock.insns[0]?.address)
            ) {
              if (!visited.has(succ) && !exits.includes(succ)) exits.push(succ);
            }
          }
        }
        exits.sort(
          (a, b) => (blockById.get(a)?.startAddr ?? 0) - (blockById.get(b)?.startAddr ?? 0),
        );
        current = exits.length > 0 ? exits[0] : null;
        continue;
      }

      visited.add(current);

      // Emit block's lifted statements, under the label a `goto` to this block
      // would use.
      //
      // Every block gets one, whether or not anything jumps here and whether or
      // not it lifted to any statement: the walk only learns which blocks are
      // `goto` targets once it is over — a back edge names a block emitted long
      // before — and a block that lifted to nothing is still a place code jumps
      // to. `pruneLabels` removes the ones that turn out to be unused, so the
      // reader never sees a label for an address nothing reaches. Before this,
      // `emit.ts` had to anchor labels by matching the target address against
      // the addresses of emitted *lines*, which finds nothing when the block's
      // first instruction folded away — two thirds of all gotos (peek-a-bin-uzi).
      const blockStmts = liftedBlocks.get(block.id) ?? [];
      pushLabel(result, block);
      result.push(...blockStmts);

      // A conditional jump the CFG has no edge for is still a test the machine
      // makes. See `lostBranchTarget`.
      const lostTarget = lostBranchTarget(block);
      if (lostTarget !== null) {
        result.push({
          kind: "if",
          condition: extractCondition(block),
          thenBody: [
            {
              kind: "comment",
              text: `control leaves for 0x${lostTarget.toString(16).toUpperCase()}, which is outside this function`,
            },
          ],
        });
      }

      // Determine what comes next based on block's exit
      if (endsWithRet(block) || block.succs.length === 0) {
        current = null;
        continue;
      }

      // Check for switch (indirect jump with jump table).
      //
      // The gate used to also require `block.succs.length > 2`. Successors are
      // distinct blocks, so a table with three entries two of which share a
      // target has two of them, fell below the threshold, and was not
      // recognised as a switch at all: one target was emitted inline as if it
      // were a fallthrough, the rest left to the leftover pass, and no case
      // value appeared anywhere (peek-a-bin-rev). How many distinct blocks a
      // table lands on is not part of what makes it a switch — the table is.
      if (endsWithJmp(block)) {
        const lastInsn = block.insns[block.insns.length - 1];
        const jtTargets = jumpTables.get(lastInsn.address);
        if (jtTargets && jtTargets.length > 0) {
          const switchResult = structureSwitch(block, jtTargets);
          result.push(switchResult);

          // Find convergence after switch — include successors of all case
          // blocks and the default block when searching for the exit point
          const caseBlockIds = new Set<number>(block.succs);
          // Also include the default block if present
          if (switchResult.kind === "switch" && switchResult.defaultBody) {
            for (const predId of block.preds) {
              const pred = blockById.get(predId);
              if (!pred) continue;
              const lastInsn = pred.insns[pred.insns.length - 1];
              if (lastInsn) {
                const m = lastInsn.opStr.match(/^0x([0-9a-fA-F]+)$/);
                if (m) {
                  const defBlock = blockByAddr.get(parseInt(m[1], 16));
                  if (defBlock) caseBlockIds.add(defBlock.id);
                }
              }
            }
          }
          const exitCandidates = new Set<number>();
          for (const succId of caseBlockIds) {
            const succBlock = blockById.get(succId);
            if (succBlock) {
              for (const ss of succBlock.succs) {
                if (!caseBlockIds.has(ss)) exitCandidates.add(ss);
              }
            }
          }
          current = null;
          for (const cand of exitCandidates) {
            if (!visited.has(cand)) {
              current = cand;
              break;
            }
          }
          continue;
        }
      }

      // Unconditional jump to single successor
      if (block.succs.length === 1) {
        const nextId = block.succs[0];
        if (visited.has(nextId) || stopAt.has(nextId)) {
          // Back-edge or exit: emit goto if needed
          if (!stopAt.has(nextId)) {
            const targetBlock = blockById.get(nextId);
            if (targetBlock) {
              result.push({ kind: "goto", label: labelNameFor(targetBlock.startAddr) });
            }
          }
          current = null;
        } else {
          current = nextId;
        }
        continue;
      }

      // Conditional branch (2 successors)
      if (block.succs.length === 2 && endsWithCondJmp(block)) {
        const condition = extractCondition(block);
        const [branchTarget, fallthrough] = identifyBranches(block);

        if (branchTarget === null || fallthrough === null) {
          current = null;
          continue;
        }

        // Find convergence
        const convergence = convergenceOf(current, branchTarget, fallthrough, loopBody);

        const convergenceSet = new Set(stopAt);
        if (convergence >= 0) convergenceSet.add(convergence);

        // Check for short-circuit && / || pattern.
        //
        // Folding `condA` and `condB` into one expression consumes the blocks
        // between them, and their statements go with them. That is only sound
        // when those blocks do nothing but test: `a && f()` in C evaluates
        // `f()` conditionally, so a block that both computes and tests cannot
        // be spelled as one operand of `&&` without either losing the work or
        // lying about when it happens. The real shape is a nested `if`, which
        // the general path below produces. On t32 this fold deleted two calls
        // outright from `sub_405B72` (peek-a-bin-cb2).
        const sc = detectShortCircuit(current, blockById, extractCondition, identifyBranches);
        if (sc?.consumedBlocks.every((cid) => (liftedBlocks.get(cid)?.length ?? 0) === 0)) {
          const scConvergenceSet = new Set(stopAt);
          const scConvergence = convergenceOf(current, sc.trueTarget, sc.falseTarget, loopBody);
          if (scConvergence >= 0) scConvergenceSet.add(scConvergence);

          // Mark consumed blocks as visited
          for (const cid of sc.consumedBlocks) visited.add(cid);

          const thenBody = armFrom(
            current,
            sc.trueTarget,
            scConvergenceSet,
            scConvergence,
            loopBody,
          );
          const elseBody = armFrom(
            current,
            sc.falseTarget,
            scConvergenceSet,
            scConvergence,
            loopBody,
          );
          pushConditional(result, sc.condition, thenBody, elseBody);

          current = scConvergence >= 0 ? scConvergence : null;
          continue;
        }

        // Check for simple patterns first:
        // 1. One branch returns → if-return pattern
        const branchBlock = blockById.get(branchTarget);
        const fallthroughBlock = blockById.get(fallthrough);

        // A branch that is *also* the convergence point is the shared tail of
        // both paths, not an early return belonging to one of them: taking the
        // shortcut there structures the tail as the `then` body, and since the
        // tail is the block both paths reach, that body comes back empty and
        // the guard is dropped altogether — the other path's statements are
        // then emitted unconditionally. (The triangle in peek-a-bin-lrs turned
        // a conditional store into an unconditional one this way.) The general
        // if/else path below handles that shape correctly, negating the
        // condition so the non-tail side becomes the `then` body.
        if (
          branchBlock &&
          branchTarget !== convergence &&
          endsWithRet(branchBlock) &&
          branchBlock.succs.length === 0
        ) {
          // if (cond) { ... return; } — the branch target runs when the jcc is taken
          //
          // Through `armFrom`/`pushConditional`, so that an arm the walk
          // refused to follow becomes the `goto` that says where control
          // really goes, and an arm that is genuinely the join leaves no
          // guard with nothing in it.
          const thenBody = armFrom(current, branchTarget, convergenceSet, convergence, loopBody);
          pushConditional(result, condition, thenBody, []);
          // Continue with fallthrough
          current = fallthrough;
          continue;
        }

        if (
          fallthroughBlock &&
          fallthrough !== convergence &&
          endsWithRet(fallthroughBlock) &&
          fallthroughBlock.succs.length === 0
        ) {
          // if (!cond) { ... return; } — the fallthrough runs when the jcc is
          // *not* taken. Same empty-body reasoning as the branch-target case.
          const thenBody = armFrom(current, fallthrough, convergenceSet, convergence, loopBody);
          pushConditional(result, RegState.negate(condition), thenBody, []);
          // Continue with branch target
          current = branchTarget;
          continue;
        }

        // General if-else.
        // `condition` is the condition under which the jcc is *taken*, so the
        // branch target is the "then" body and the fallthrough is the "else":
        //   if (condition) { branchBody } else { fallthroughBody }
        // When only the fallthrough has statements the condition is negated so
        // that body can be hoisted into the "then" slot.

        if (convergence >= 0) {
          const thenBody = armFrom(current, branchTarget, convergenceSet, convergence, loopBody);
          const elseBody = armFrom(current, fallthrough, convergenceSet, convergence, loopBody);
          pushConditional(result, condition, thenBody, elseBody);
          current = convergence;
        } else {
          // No convergence found — emit both branches inline. Nothing follows
          // the `if`, so neither arm has a join to fall into: an arm the walk
          // refuses becomes a `goto`.
          const thenBody = armFrom(current, branchTarget, stopAt, -1, loopBody);
          const elseBody = armFrom(current, fallthrough, stopAt, -1, loopBody);
          pushConditional(result, condition, thenBody, elseBody);
          current = null;
        }
        continue;
      }

      // Fallthrough to next block
      if (block.succs.length >= 1) {
        current = block.succs[0];
      } else {
        current = null;
      }
    }

    return result;
  }

  /**
   * One arm of the branch in `fromId`: the statements the walk produced for
   * `targetId`, or the `goto` that says where control really goes when the
   * walk would not follow it there.
   *
   * `structureFrom` returns an empty list for exactly one reason — the target
   * is in `stopAt` or already visited, so it bails before emitting anything.
   * (Any block it does enter contributes at least its own label.) Handing that
   * empty list to `pushConditional` deletes the guard, and the arm then reads
   * as "falls through to whatever follows the `if`". That is true only when the
   * target *is* what follows the `if` — the convergence. Everywhere else it is
   * a statement about the machine that is not true, and it is how a loop's own
   * exit test disappeared: the test at the bottom of a body whose two arms are
   * the header and the way out has both of them in `stopAt`, so the whole
   * `if` evaporated and the loop was left claiming it repeats on the header
   * test alone (peek-a-bin-jlo). The bound of `sub_406437`'s table search
   * vanished the same way, leaving `for (eax = 0; ecx != tbl[eax]; eax++)`
   * with no `eax < 0x16` anywhere.
   *
   * A `goto` to the target's label is faithful whatever the target is. The
   * loop header's label sits immediately before the loop statement, so jumping
   * to it re-enters the loop from the top, which is what the machine's back
   * edge does; `insertContinueStmts` then upgrades that to `continue` where
   * the two are the same thing.
   */
  function armFrom(
    fromId: number,
    targetId: number,
    stopSet: Set<number>,
    convergence: number,
    loopBody?: Set<number>,
  ): IRStmt[] {
    const body = structureFrom(targetId, stopSet, loopBody);
    if (body.length > 0) return body;
    if (targetId === convergence) return [];
    if (backEdgeConditionBlocks.has(fromId)) return [];
    const target = blockById.get(targetId);
    if (!target) return [];
    return [{ kind: "goto", label: labelNameFor(target.startAddr) }];
  }

  /** Identify which successor is the branch target vs fallthrough. */
  function identifyBranches(block: BasicBlock): [number | null, number | null] {
    const insns = block.insns;
    if (insns.length === 0) return [null, null];
    const last = insns[insns.length - 1];
    const mn = last.mnemonic.toLowerCase();

    if (!mn.startsWith("j") || mn === "jmp") return [null, null];

    // Branch target from operand
    const m = last.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (!m) return [null, null];
    const targetAddr = parseInt(m[1], 16);

    // Find which successor matches
    let branchSucc: number | null = null;
    let fallSucc: number | null = null;

    for (const succId of block.succs) {
      const succBlock = blockById.get(succId);
      if (!succBlock) continue;
      if (succBlock.startAddr === targetAddr) {
        branchSucc = succId;
      } else {
        fallSucc = succId;
      }
    }

    // If we couldn't distinguish, use order
    if (branchSucc === null && fallSucc === null && block.succs.length === 2) {
      branchSucc = block.succs[0];
      fallSucc = block.succs[1];
    }

    return [branchSucc, fallSucc];
  }

  /** Structure a loop. */
  function structureLoop(header: BasicBlock, loop: Loop): IRStmt[] {
    const condition = extractCondition(header);
    const headerStmts = liftedBlocks.get(header.id) ?? [];

    // Determine loop type based on header structure
    // If header has conditional branch: pre-tested (while) loop
    // The branch target outside the loop = exit, body continues inside

    if (endsWithCondJmp(header) && header.succs.length === 2) {
      // Pre-tested while loop
      const [branchTarget, fallthrough] = identifyBranches(header);

      // Determine which successor is inside the loop and which is exit
      let bodyStart: number | null = null;
      let exitId: number | null = null;

      for (const succId of [branchTarget, fallthrough]) {
        if (succId === null) continue;
        const succBlock = blockById.get(succId);
        if (!succBlock) continue;
        const inLoop =
          loop.bodyAddrs.has(succBlock.startAddr) ||
          loop.bodyAddrs.has(succBlock.insns[0]?.address);
        if (inLoop) {
          bodyStart = succId;
        } else {
          exitId = succId;
        }
      }

      // Both `bodyStart` and `exitId`, or this is not a pre-tested loop.
      //
      // A header conditional whose two arms are *both* inside the body decides
      // something within an iteration; it does not decide whether there is
      // another one. Reading it as the loop's test states a condition the
      // machine never uses to continue or stop, and since which arm is which
      // is then arbitrary the result was as often inverted as merely wrong:
      // t32 `sub_40A702` walks the section table with `cmp edx, esi / jb` at
      // the bottom and emitted `while (edi >= ecx)` from a bounds check in the
      // middle of the body (peek-a-bin-bhh). Such a loop is bottom-tested — the
      // back edge carries the real test — so it falls through to the path
      // below, which structures the header as the first block of the body and
      // keeps its branch as the `if` it is.
      if (bodyStart !== null && exitId !== null) {
        const loopStopAt = new Set<number>([header.id, exitId]);

        // Detect multi-exit: conditional branches inside body targeting outside → break
        const multiExits = detectMultiExitLoop(header, loop.bodyAddrs, blocks, blockById);
        for (const exit of multiExits) {
          loopStopAt.add(exit.exitTarget);
        }

        const body = structureFrom(bodyStart, loopStopAt, loop.bodyAddrs);

        // Continue detection: scan body for conditional branches targeting header (back-edge)
        const bodyWithContinue = insertContinueStmts(body, header, loop);

        // Include header statements if any (before the condition check)
        const fullBody =
          headerStmts.length > 0 ? [...headerStmts, ...bodyWithContinue] : bodyWithContinue;

        // The condition for while: we continue looping when condition takes us to body
        // If branch goes to body (exit is fallthrough): while(condition)
        // If fallthrough goes to body (branch goes to exit): while(!condition)
        let whileCondition: IRExpr;
        if (bodyStart === branchTarget) {
          whileCondition = condition;
        } else {
          whileCondition = RegState.negate(condition);
        }

        // A header that does work as well as testing cannot be a `while`.
        //
        // `while (c) { H; B }` runs the test first and `H` only after it
        // passes; the machine runs `H` first and tests what `H` just computed.
        // Where the two disagree is not a corner: `sub_14000D8C4`'s header is
        // the `WriteFile` call itself, so the emitted loop tested the *previous*
        // call's result before making the first one, and `sub_140009740`'s
        // header loads the byte its test looks at, so the first iteration was
        // guarded on a stale register (peek-a-bin-jlo, peek-a-bin-bhh). The
        // shapes that are exact:
        //
        //   H empty          →  while (c) { B }
        //   B empty          →  do { H } while (c)
        //   neither          →  while (1) { H; if (!c) goto exit; B }
        //
        // The third is the ugly one, and it is chosen deliberately: a `while`
        // whose condition cannot be stated without also stating when `H` runs
        // is a loop the reader cannot check against the disassembly. `do/while`
        // is only reached for when the loop leaves by this test alone —
        // otherwise falling out of the `do` would land on the wrong exit.
        if (headerStmts.length > 0) {
          const exitBlock = blockById.get(exitId);
          const exitLabel = exitBlock ? labelNameFor(exitBlock.startAddr) : null;
          if (firstNonLabel(bodyWithContinue) < 0 && multiExits.length === 0) {
            return [{ kind: "do_while", condition: whileCondition, body: fullBody }];
          }
          if (exitLabel !== null) {
            return [
              {
                kind: "while",
                condition: { kind: "const", value: 1, size: 4 },
                body: [
                  ...headerStmts,
                  {
                    kind: "if",
                    condition: RegState.negate(whileCondition),
                    thenBody: [{ kind: "goto", label: exitLabel }],
                  },
                  ...bodyWithContinue,
                ],
              },
            ];
          }
        }

        // Better loop classification: if body starts with if (cond) break; → while(!cond)
        // The scan skips over labels: a label carries no behaviour, and the
        // block it introduces is what supplies the leading guard.
        const leadIdx = firstNonLabel(fullBody);
        if (whileCondition.kind === "const" && whileCondition.value === 1 && leadIdx >= 0) {
          const first = fullBody[leadIdx];
          if (
            first.kind === "if" &&
            first.thenBody.length === 1 &&
            first.thenBody[0].kind === "break" &&
            !first.elseBody
          ) {
            return [
              {
                kind: "while",
                condition: RegState.negate(first.condition),
                body: [...fullBody.slice(0, leadIdx), ...fullBody.slice(leadIdx + 1)],
              },
            ];
          }
        }

        // Try for-loop detection.
        //
        // `detectForLoop` recognises the induction variable, but the body it
        // returns is every body block's statements concatenated in block-id
        // order, with the control flow between them discarded — the arms of an
        // `if` inside the loop come out as unconditional, consecutive code, and
        // the header's own statements are missing entirely (peek-a-bin-42l:
        // 111 statements per x64 binary, every one of them inside a loop). The
        // structured `fullBody` is used instead, with the update hoisted out of
        // it, so only the recognition comes from `detectForLoop`.
        const bodyBlockIds = collectLoopBodyBlockIds(header, loop);
        const forLoop = detectForLoop(header, bodyBlockIds, liftedBlocks, blockById);
        // Hoisting is only sound when the update really is what runs last on
        // every iteration: as the final statement of the body, and with no
        // `continue` that would reach the `for`'s update but not the machine's.
        if (
          forLoop &&
          fullBody.length > 0 &&
          fullBody[fullBody.length - 1] === forLoop.update &&
          !hasFreeContinue(fullBody)
        ) {
          // detectForLoop returns `condition: irConst(1)` as a placeholder and
          // documents that the caller fills it in — the header condition is
          // only available here. Always override it.
          return [
            {
              kind: "for",
              init: forLoop.init,
              condition: whileCondition,
              update: forLoop.update,
              body: fullBody.slice(0, -1),
            },
          ];
        }

        return [{ kind: "while", condition: whileCondition, body: fullBody }];
      }
    }

    // Fallback: bottom-tested loop. The header does not end in a two-way
    // conditional — for a `do`/`while` it ends in a `jmp`, or in nothing at all
    // — so there is no pre-test to lift out, and the body is simply everything
    // the header leads to.
    //
    // That body is structured like any other region. Concatenating the body
    // blocks' lifted statements in block-id order instead, which is what this
    // did, keeps every statement but throws away the control flow between
    // them: both arms of an `if` inside the loop came out as consecutive
    // unconditional code (peek-a-bin-b37). Nothing is dropped, so no
    // statement-identity check sees it — the result is valid C stating
    // something the machine does not do, the same class as the inverted
    // conditions of peek-a-bin-h9v. It is the sibling of the `for` defect
    // fixed just above, in the other arm of this function.
    const inLoop = (b: BasicBlock): boolean =>
      loop.bodyAddrs.has(b.startAddr) || loop.bodyAddrs.has(b.insns[0]?.address);

    // The walk must not wander out of the loop. It stops at the header — that
    // edge is the back edge, which the `do`/`while` itself expresses — and at
    // every block outside the body that a body block can reach. Those exits
    // belong to the caller: `structureFrom` continues from one of them after
    // the loop and the leftover pass at the end picks up the others.
    const loopStopAt = new Set<number>([header.id]);
    for (const b of blocks) {
      if (!inLoop(b)) continue;
      for (const succ of b.succs) {
        const succBlock = blockById.get(succ);
        if (succBlock && !inLoop(succBlock)) loopStopAt.add(succ);
      }
    }

    // The back edge's own test is the loop statement's condition, so it is
    // found before the body is walked: `armFrom` has to know not to spell it a
    // second time inside the body.
    const backEdgeBlock = blocks.find(
      (b) =>
        b.endAddr === loop.backEdgeFromAddr ||
        b.insns.some((i) => i.address === loop.backEdgeFromAddr),
    );
    let loopCondition: IRExpr = { kind: "const", value: 1, size: 4 }; // true = infinite loop
    if (backEdgeBlock && endsWithCondJmp(backEdgeBlock)) {
      loopCondition = extractCondition(backEdgeBlock);
      backEdgeConditionBlocks.add(backEdgeBlock.id);
    }

    // The body starts at the header, walked as an ordinary region.
    //
    // Pushing the header's statements and then each in-loop successor's region
    // in turn, which is what this did, is only right when the header has one
    // successor inside the loop. With two — the shape that arrives here now
    // that a header conditional with both arms in the body no longer counts as
    // a pre-test — it emits both arms of that `if` as consecutive
    // unconditional code, the peek-a-bin-b37 defect one level up. `enterStart`
    // walks the header itself despite its being visited and in `stopAt`, so
    // its branch is structured like any other.
    const body: IRStmt[] = structureFrom(header.id, loopStopAt, loop.bodyAddrs, true);

    // Whatever that walk did not reach — a region entered only by a jump it
    // cut — is appended under its own label, exactly as the leftover pass at
    // the end of `structureCFG` does for the function as a whole, so that no
    // part of the body goes missing. Terminates because `structureFrom` marks
    // its starting block visited on every path through it.
    for (;;) {
      let next: BasicBlock | undefined;
      for (const b of blocks) {
        if (b.id === header.id || !inLoop(b) || visited.has(b.id)) continue;
        if ((liftedBlocks.get(b.id)?.length ?? 0) === 0) continue;
        if (!next || b.startAddr < next.startAddr) next = b;
      }
      if (!next) break;
      const tail = structureFrom(next.id, loopStopAt, loop.bodyAddrs);
      if (tail.length === 0) continue;
      pinned.add(labelNameFor(next.startAddr));
      body.push(...tail);
    }

    // do-while with leading break → while (labels skipped: see the same scan
    // in the pre-tested path above)
    const leadIdx = firstNonLabel(body);
    const lead = leadIdx >= 0 ? body[leadIdx] : undefined;
    if (
      lead?.kind === "if" &&
      lead.thenBody.length === 1 &&
      lead.thenBody[0].kind === "break" &&
      !lead.elseBody
    ) {
      return [
        {
          kind: "while",
          condition: RegState.negate(lead.condition),
          body: [...body.slice(0, leadIdx), ...body.slice(leadIdx + 1)],
        },
      ];
    }

    return [{ kind: "do_while", condition: loopCondition, body }];
  }

  /** Collect block IDs that are part of a loop body. */
  function collectLoopBodyBlockIds(header: BasicBlock, loop: Loop): number[] {
    const ids: number[] = [];
    for (const b of blocks) {
      if (b.id === header.id) continue;
      if (loop.bodyAddrs.has(b.startAddr) || loop.bodyAddrs.has(b.insns[0]?.address)) {
        ids.push(b.id);
      }
    }
    return ids;
  }

  /** Insert continue statements for conditional branches back to loop header. */
  function insertContinueStmts(body: IRStmt[], header: BasicBlock, _loop: Loop): IRStmt[] {
    const headerLabel = labelNameFor(header.startAddr);
    return body.map((stmt) => {
      // Replace goto to header with continue
      if (stmt.kind === "goto" && stmt.label === headerLabel) {
        return { kind: "continue" as const };
      }
      // Check if-goto-header patterns: if (cond) { goto header; } → if (cond) { continue; }
      if (stmt.kind === "if") {
        const newThen = stmt.thenBody.map((s) =>
          s.kind === "goto" && s.label === headerLabel
            ? ({ kind: "continue" as const } as IRStmt)
            : s,
        );
        const newElse = stmt.elseBody?.map((s) =>
          s.kind === "goto" && s.label === headerLabel
            ? ({ kind: "continue" as const } as IRStmt)
            : s,
        );
        return { ...stmt, thenBody: newThen, elseBody: newElse };
      }
      return stmt;
    });
  }

  /**
   * The register a jump table is indexed by, or null.
   *
   * `jmp [reg*4 + table]` picks its target by `reg` alone, so `reg` *is* the
   * subject of the switch by construction: entry *i* runs exactly when it
   * holds *i*, which is what the case values say. Nothing else in the function
   * has to agree for that to hold.
   */
  function jumpTableIndexReg(block: BasicBlock): string | null {
    const last = block.insns[block.insns.length - 1];
    const mem = last?.opStr.match(/\[([^\]]*)\]/);
    if (!mem) return null;
    const scaled = mem[1].match(/\b([a-z][a-z0-9]*)\s*\*\s*[1248]\b/i);
    if (!scaled || !isKnownRegister(scaled[1])) return null;
    return scaled[1].toLowerCase();
  }

  /**
   * The compared operand of a bounds check on a predecessor of `block`, and
   * the default target if that check has one.
   *
   * Two shapes, and they are not symmetric:
   *
   * - `cmp x, N / ja default` — out of range on the *taken* path. The in-range
   *   path falls through into the table, and the jump target is the default
   *   arm of the switch.
   * - `cmp x, N / jb table` — in range on the *taken* path, which is the form
   *   MSVC emits for `memcpy`'s dispatch (t32's `sub_40B780`). There is no
   *   default: the fallthrough is the out-of-range code, which is not reached
   *   from the switch block at all and so is not an arm of it. Reading the
   *   jump target as a default here would attribute unrelated code to the
   *   switch.
   */
  function boundsCheckOf(block: BasicBlock): { expr: IRExpr | null; defaultAddr: number | null } {
    for (const predId of block.preds) {
      const pred = blockById.get(predId);
      if (!pred || pred.insns.length === 0) continue;
      const lastInsn = pred.insns[pred.insns.length - 1];
      const lastMn = lastInsn.mnemonic.toLowerCase();
      const outOfRangeTaken = lastMn === "ja" || lastMn === "jae" || lastMn === "jnb";
      const inRangeTaken =
        lastMn === "jb" || lastMn === "jbe" || lastMn === "jnae" || lastMn === "jna";
      if (!outOfRangeTaken && !inRangeTaken) continue;

      const m = lastInsn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      const targetAddr = m ? parseInt(m[1], 16) : null;
      // The in-range form is only this switch's guard if what it jumps to is
      // this switch.
      if (inRangeTaken && targetAddr !== block.startAddr) continue;

      let expr: IRExpr | null = null;
      for (const insn of pred.insns) {
        if (insn.mnemonic.toLowerCase() === "cmp") {
          const parts = insn.opStr.split(",").map((s) => s.trim());
          if (parts.length >= 1) expr = parseOperand(parts[0], insn, is64);
          break;
        }
      }
      return { expr, defaultAddr: outOfRangeTaken ? targetAddr : null };
    }
    return { expr: null, defaultAddr: null };
  }

  /** Structure a switch statement. */
  function structureSwitch(block: BasicBlock, targets: number[]): IRStmt {
    let switchExpr: IRExpr = { kind: "unknown", text: "switch_expr" };

    // Two independent readings of what is being switched on: the register the
    // table is indexed by, and the value a predecessor bounds-checks.
    //
    // They usually name the same register, and then the bounds check's
    // spelling wins — it is the width the comparison was written at, and it
    // comes with the default target. When they disagree the index register is
    // the honest answer: in t32's `sub_40B780` the guard is `cmp ecx, 8` and
    // the table is `jmp [edx*4 + 0x40b8f0]`, where `edx` is `ecx & 3` — a
    // different value with a different range, so `switch (ecx)` against case
    // values 0..3 would be a statement about the machine that is not true.
    // Only a `ja`/`jae` guard was consulted before, so the inverted-sense form
    // left the subject unrecovered entirely (peek-a-bin-rev).
    const indexReg = jumpTableIndexReg(block);
    const { expr: boundsExpr, defaultAddr } = boundsCheckOf(block);
    const agrees =
      indexReg !== null &&
      boundsExpr?.kind === "reg" &&
      canonReg(boundsExpr.name) === canonReg(indexReg);

    if (boundsExpr && (agrees || indexReg === null)) switchExpr = boundsExpr;
    else if (indexReg !== null) switchExpr = irReg(indexReg);

    // Fallback: scan current block for cmp (original behavior)
    if (switchExpr.kind === "unknown") {
      for (const insn of block.insns) {
        if (insn.mnemonic.toLowerCase() === "cmp") {
          const parts = insn.opStr.split(",").map((s) => s.trim());
          if (parts.length >= 1) {
            switchExpr = parseOperand(parts[0], insn, is64);
            break;
          }
        }
      }
    }

    const cases: { values: number[]; body: IRStmt[] }[] = [];
    const targetToCase = new Map<number, number[]>();

    // Group targets by address (multiple cases can go to same block)
    for (let i = 0; i < targets.length; i++) {
      const arr = targetToCase.get(targets[i]) ?? [];
      arr.push(i);
      targetToCase.set(targets[i], arr);
    }

    const switchStopAt = new Set<number>();
    for (const succId of block.succs) switchStopAt.add(succId);

    /**
     * The body for one arm of the switch.
     *
     * A block is emitted once, so an arm whose target another region already
     * claimed cannot have the statements again. MSVC emits one jump table per
     * copy-direction/alignment path of `memcpy` and lands them all on the same
     * few tail blocks — t32's `sub_40B780` has nine tables over two distinct
     * target sets — so this is the normal case there, not a corner. Emitting
     * `break` for those arms says the case does nothing, which is indistinguishable
     * from a case that really is empty and was wrong for four arms of that one
     * function (peek-a-bin-dp6). A `goto` to the label the block was emitted
     * under says where the case goes instead, and needs no second copy of the
     * statements. Where even the label does not exist — the short-circuit fold
     * consumes blocks without emitting anything — there is nothing to name, and
     * `break` is all that is left.
     */
    function armBody(targetBlock: BasicBlock | undefined): IRStmt[] {
      if (targetBlock && !visited.has(targetBlock.id)) {
        visited.add(targetBlock.id);
        const body: IRStmt[] = [];
        pushLabel(body, targetBlock);
        body.push(...(liftedBlocks.get(targetBlock.id) ?? []), { kind: "break" });
        return body;
      }
      if (targetBlock && labelled.has(targetBlock.id)) {
        return [{ kind: "goto", label: labelNameFor(targetBlock.startAddr) }];
      }
      return [{ kind: "break" }];
    }

    for (const [targetAddr, values] of targetToCase) {
      // Skip if this is the default target — handle it separately
      if (defaultAddr !== null && targetAddr === defaultAddr) continue;
      cases.push({ values, body: armBody(blockByAddr.get(targetAddr)) });
    }

    // Structure the default case body
    let defaultBody: IRStmt[] | undefined;
    if (defaultAddr !== null) {
      defaultBody = armBody(blockByAddr.get(defaultAddr));
    }

    return { kind: "switch", expr: switchExpr, cases, defaultBody };
  }

  // Start structuring from the entry block (id 0)
  const result = structureFrom(0, new Set(), undefined);

  /**
   * Append whatever the walk never reached.
   *
   * `structureFrom` follows one chain of blocks and stops wherever it runs into
   * a `stopAt`, a visited block, or an exit it did not choose. Every block only
   * reachable through a path it cut is then simply absent from the output, and
   * nothing downstream can tell: the statements never enter the tree, so there
   * is no dangling reference, no comment, nothing. A reader concludes the code
   * does not exist. On three real MSVC binaries that silently deleted 6% of
   * every statement the front end produced (peek-a-bin-cb2).
   *
   * Each leftover is introduced by its `loc_` label, which is both honest — the
   * block is jumped to, not fallen into — and the anchor `emit.ts` already
   * looks for when it places the label for a `goto`. `structureFrom` emits that
   * label itself now, so all this pass has to do is pin the name against the
   * sweep that drops labels nothing jumps to.
   *
   * Reachability from the entry is deliberately *not* a condition. It used to
   * be, on the grounds that the rest is alignment padding decoded past the last
   * `ret`; that is not what it excluded (peek-a-bin-d3z). An exception funclet
   * — an MSVC `__except`/`__finally` continuation, or a 32-bit SEH scope
   * handler — is entered by the unwinder, not by a CFG edge, so it is
   * unreachable by construction while being ordinary code sitting inside the
   * function's own bounds. Across t32/t64/w64/w32 there are 1160 such blocks
   * carrying 2685 statements and 200 `call` sites, and skipping them was the
   * whole of the corpus's remaining lost-call count: 59 callees that the
   * disassembly names and the emitted C never mentioned, now 0.
   *
   * Padding is excluded by the test that was already doing the work — a block
   * that lifts to no statements is not resurrected — and padding lifts to
   * nothing. On t32, 34 of the 807 unreachable blocks lift empty and are
   * dropped here; the emitted text grows 20% on t32 and 0.1% on t64, which is
   * the shape of "recovered real code", not "resurrected noise".
   *
   * Terminates because `structureFrom` marks its starting block visited on
   * every path through it, so each round removes at least one candidate.
   */
  for (;;) {
    let next: BasicBlock | undefined;
    for (const b of blocks) {
      if (visited.has(b.id)) continue;
      if ((liftedBlocks.get(b.id)?.length ?? 0) === 0) continue;
      if (!next || b.startAddr < next.startAddr) next = b;
    }
    if (!next) break;

    const tail = structureFrom(next.id, new Set(), undefined);
    if (tail.length === 0) continue;
    pinned.add(labelNameFor(next.startAddr));
    result.push(...tail);
  }

  /**
   * Emit any block a `goto` names but the walk never reached.
   *
   * The pass above only resurrects blocks that lifted to at least one
   * statement, on the grounds that a block contributing nothing is not worth a
   * region of its own. A block a `goto` jumps to is worth one regardless: the
   * label is what the `goto` needs to compile, and `structureFrom` emits the
   * label as part of walking the block. `armFrom` can name such a block —
   * an exit whose own statements all folded away, say — so without this the
   * honest `goto` would be a label reference to nothing.
   *
   * Terminates for the same reason as the pass above: each round marks at
   * least one more block visited, and a visited block is never a candidate
   * again.
   */
  for (;;) {
    const wanted = new Set<string>();
    const have = new Set<string>(pinned);
    const scan = (list: IRStmt[]): void => {
      for (const s of list) {
        if (s.kind === "goto") wanted.add(s.label);
        else if (s.kind === "label") have.add(s.name);
        for (const nested of bodiesOf(s)) scan(nested);
      }
    };
    scan(result);

    let next: BasicBlock | undefined;
    for (const b of blocks) {
      if (visited.has(b.id) || !wanted.has(labelNameFor(b.startAddr))) continue;
      if (have.has(labelNameFor(b.startAddr))) continue;
      if (!next || b.startAddr < next.startAddr) next = b;
    }
    if (!next) break;

    const tail = structureFrom(next.id, new Set(), undefined);
    if (tail.length === 0) break;
    pinned.add(labelNameFor(next.startAddr));
    result.push(...tail);
  }

  return pruneLabels(result, pinned);
}
