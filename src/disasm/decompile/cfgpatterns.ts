import type { BasicBlock } from "../cfg";
import type { IRAssign, IRExpr, IRStmt } from "./ir";
import { irBinary, irConst } from "./ir";
import { RegState } from "./regstate";

/**
 * Detect short-circuit && / || pattern:
 * Two consecutive conditional blocks sharing a common true or false target.
 *
 * Pattern A (&&):
 *   Block1: if (!condA) goto FAIL; fallthrough to Block2
 *   Block2: if (!condB) goto FAIL; fallthrough to SUCCESS
 *   → if (condA && condB)
 *
 * Pattern B (||):
 *   Block1: if (condA) goto SUCCESS; fallthrough to Block2
 *   Block2: if (condB) goto SUCCESS; fallthrough to FAIL
 *   → if (condA || condB)
 */
export function detectShortCircuit(
  blockId: number,
  blockById: Map<number, BasicBlock>,
  extractCondition: (block: BasicBlock) => IRExpr,
  identifyBranches: (block: BasicBlock) => [number | null, number | null],
): {
  kind: "&&" | "||";
  condition: IRExpr;
  trueTarget: number;
  falseTarget: number;
  consumedBlocks: number[];
} | null {
  const block = blockById.get(blockId);
  if (block?.succs.length !== 2) return null;

  const [branchA, fallA] = identifyBranches(block);
  if (branchA === null || fallA === null) return null;

  // Check if fallthrough leads to another conditional block
  const blockB = blockById.get(fallA);
  if (blockB?.succs.length !== 2) return null;
  if (blockB.preds.length !== 1) return null;

  const [branchB, fallB] = identifyBranches(blockB);
  if (branchB === null || fallB === null) return null;

  const condA = extractCondition(block);
  const condB = extractCondition(blockB);

  // Pattern A (&&): both branch to same FAIL target
  if (branchA === branchB) {
    let combined = irBinary("&&", RegState.negate(condA), RegState.negate(condB));
    const consumed = [fallA];

    // Chained &&: keep extending if next block also branches to same FAIL
    let currentFall = fallB;
    for (let depth = 0; depth < 6; depth++) {
      // cap total at 8 blocks
      const nextBlock = blockById.get(currentFall);
      if (nextBlock?.succs.length !== 2 || nextBlock.preds.length !== 1) break;
      const [nextBranch, nextFall] = identifyBranches(nextBlock);
      if (nextBranch === null || nextFall === null) break;
      if (nextBranch !== branchA) break; // not same fail target
      const nextCond = extractCondition(nextBlock);
      combined = irBinary("&&", combined, RegState.negate(nextCond));
      consumed.push(currentFall);
      currentFall = nextFall;
    }

    return {
      kind: "&&",
      condition: combined,
      trueTarget: currentFall,
      falseTarget: branchA,
      consumedBlocks: consumed,
    };
  }

  // Pattern B (||): Block1 and Block2 both branch to same SUCCESS
  // Block1 branch != Block2 branch handled — check if fallA == blockB.id
  // and both branch to same target
  if (fallA === blockB.id) {
    // This means Block1's fallthrough IS Block2
    // For ||: we need branchA to be a SUCCESS target that other blocks also branch to
    // Check: Block2's branch goes to same place? No, branchA !== branchB already.
    // But maybe Block2's fallthrough goes to FAIL and we want branchA || branchB with different targets
    // Actually, the || pattern is: Block1 branches to SUCCESS, Block2 also branches to SUCCESS
    // Since branchA !== branchB here, this isn't the simple case.
    // Skip — not a clean || pattern
  }

  return null;
}

/**
 * Is this statement an increment of its own destination — `x = x + c`, `x = x - c`?
 *
 * The candidate update of a `for`. Register names are compared case-insensitively
 * because the lifter's spelling of one is whatever Capstone printed.
 */
function isSelfIncrement(stmt: IRStmt): stmt is IRAssign {
  if (stmt.kind !== "assign") return false;
  if (stmt.src.kind !== "binary") return false;
  if (stmt.src.op !== "+" && stmt.src.op !== "-") return false;
  if (stmt.src.right.kind !== "const") return false;
  const d = stmt.dest;
  const l = stmt.src.left;
  return (
    (d.kind === "reg" && l.kind === "reg" && d.name.toLowerCase() === l.name.toLowerCase()) ||
    (d.kind === "var" && l.kind === "var" && d.name === l.name)
  );
}

/** Do these two destinations name the same register or the same variable? */
function sameDest(a: IRExpr, b: IRExpr): boolean {
  if (a.kind === "reg" && b.kind === "reg") return a.name.toLowerCase() === b.name.toLowerCase();
  if (a.kind === "var" && b.kind === "var") return a.name === b.name;
  return false;
}

/**
 * The last assignment to `dest` in any of `preds`, or null.
 *
 * `preds` is searched in order and the first block with a match wins, which is
 * the caller's problem rather than this function's: the caller passes only
 * blocks outside the loop, so every candidate is a genuine pre-loop write.
 */
function lastAssignTo(
  dest: IRExpr,
  preds: number[],
  liftedBlocks: Map<number, IRStmt[]>,
): IRStmt | null {
  for (const predId of preds) {
    const stmts = liftedBlocks.get(predId);
    if (!stmts) continue;
    for (let i = stmts.length - 1; i >= 0; i--) {
      const s = stmts[i];
      if (s.kind === "assign" && sameDest(s.dest, dest)) return s;
    }
  }
  return null;
}

/**
 * Detect for-loop pattern:
 *   init block → header (cmp) → body → increment → back to header
 *
 * Requires:
 * - Header block ends with conditional jump (loop test)
 * - A body block ends with an assignment that looks like an increment (x = x + 1)
 * - An init assignment to the same place exists before the loop
 *
 * TWO THINGS THE SEARCH DELIBERATELY DOES, both of which it used not to
 * (`peek-a-bin-9q2`, census at `bd73798`):
 *
 * **Every increment-shaped statement is a candidate, and the first one with an
 * init wins.** A loop body can increment more than one thing — MSVC's
 * newline-counting loop is `for (p = start; p < end; p++) if (*p == '\n') n++;`,
 * whose *conditionally* incremented counter sits in a lower-numbered block than
 * the latch. Committing to the first candidate in block-id order picked `n`,
 * failed to find an init for it (there is none: `n` comes in from an enclosing
 * scope) and returned null, so the loop was emitted as a `while` — 26 loops
 * corpus-wide, 8/8/5/5 on t32/t64/w64/w32. The candidate that runs last on
 * every iteration is the one the caller's guard demands anyway, so trying the
 * rest costs nothing and claims nothing: a candidate is only ever *offered*,
 * and `structureCFG` still refuses it unless it is the final statement of the
 * structured body.
 *
 * **A predecessor inside the loop body is not a source of inits.** The back-edge
 * test used to be `p < header.id`, block-id order standing in for "before the
 * loop" — and the latch is routinely numbered below its header, so in 19/18/15/16
 * of the loops reaching here one of the "pre-loop" predecessors was a body
 * block. Reading an init out of one means reading it out of the loop, and the
 * statement found is often the update itself. It has been harmless so far only
 * because `structureFrom` cannot find such a statement in the code it has
 * already emitted and demotes the `for` back to a `while`; the loop body is the
 * fact, so it is what gets asked.
 */
export function detectForLoop(
  header: BasicBlock,
  bodyBlocks: number[],
  liftedBlocks: Map<number, IRStmt[]>,
  _blockById: Map<number, BasicBlock>,
): {
  init: IRStmt;
  condition: IRExpr;
  update: IRStmt;
  bodyStmts: IRStmt[];
} | null {
  if (bodyBlocks.length === 0) return null;

  // Every body block whose last statement increments its own destination, in
  // block-id order. More than one is ordinary rather than exceptional — see the
  // docstring — so the list is kept instead of the first entry.
  const candidates: Array<{ update: IRAssign; blockId: number }> = [];
  for (const bid of bodyBlocks) {
    const stmts = liftedBlocks.get(bid);
    if (!stmts || stmts.length === 0) continue;
    const last = stmts[stmts.length - 1];
    if (isSelfIncrement(last)) candidates.push({ update: last, blockId: bid });
  }
  if (candidates.length === 0) return null;

  // Where an init can come from: a predecessor of the header that is not part
  // of the loop. The header itself is named explicitly because
  // `collectLoopBodyBlockIds` omits it, so a self-loop would otherwise offer
  // its own statements as pre-loop ones.
  const initPreds = header.preds.filter((p) => p !== header.id && !bodyBlocks.includes(p));

  for (const cand of candidates) {
    const initStmt = lastAssignTo(cand.update.dest, initPreds, liftedBlocks);
    if (!initStmt) continue;

    // Collect body stmts (excluding the increment at the end)
    const bodyStmts: IRStmt[] = [];
    for (const bid of bodyBlocks) {
      const stmts = liftedBlocks.get(bid) ?? [];
      if (bid === cand.blockId) {
        bodyStmts.push(...stmts.slice(0, -1)); // exclude increment
      } else {
        bodyStmts.push(...stmts);
      }
    }

    // The condition is the header's, which only the caller can extract; it
    // documents that it always overrides this placeholder.
    return {
      init: initStmt,
      condition: irConst(1), // placeholder
      update: cand.update,
      bodyStmts,
    };
  }
  return null;
}

/**
 * Detect multi-exit loop: conditional branches inside loop body
 * targeting blocks outside the loop → if (cond) break;
 */
export function detectMultiExitLoop(
  header: BasicBlock,
  bodyAddrs: Set<number>,
  blocks: BasicBlock[],
  blockById: Map<number, BasicBlock>,
): { blockId: number; exitTarget: number }[] {
  const exits: { blockId: number; exitTarget: number }[] = [];

  for (const b of blocks) {
    if (b.id === header.id) continue;
    if (!bodyAddrs.has(b.startAddr) && !bodyAddrs.has(b.insns[0]?.address)) continue;

    // Check if block has a successor outside the loop
    for (const succId of b.succs) {
      const succ = blockById.get(succId);
      if (!succ) continue;
      if (!bodyAddrs.has(succ.startAddr) && !bodyAddrs.has(succ.insns[0]?.address)) {
        // This successor is outside the loop
        if (succId !== header.id) {
          exits.push({ blockId: b.id, exitTarget: succId });
        }
      }
    }
  }

  return exits;
}

/**
 * Detect if-else-if chain: sequential diamonds where else leads to another conditional.
 *
 * Block ending with conditional → then body, else is another conditional block
 * → emit: if {} else if {} else if {} else {}
 */
export function detectIfElseIfChain(blockId: number, blockById: Map<number, BasicBlock>): boolean {
  const block = blockById.get(blockId);
  if (block?.succs.length !== 2) return false;

  // Check if the fallthrough successor is also a conditional
  // This is detected naturally by the recursive structuring
  // Just return true to indicate the pattern exists
  let count = 0;
  let current = blockId;
  while (count < 5) {
    const b = blockById.get(current);
    if (b?.succs.length !== 2) break;
    count++;
    // Follow the fallthrough
    const insns = b.insns;
    if (insns.length === 0) break;
    const last = insns[insns.length - 1];
    const m = last.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (!m) break;
    const branchAddr = parseInt(m[1], 16);
    const fallId = b.succs.find((s) => {
      const sb = blockById.get(s);
      return sb && sb.startAddr !== branchAddr;
    });
    if (fallId === undefined) break;
    current = fallId;
  }
  return count >= 2;
}
