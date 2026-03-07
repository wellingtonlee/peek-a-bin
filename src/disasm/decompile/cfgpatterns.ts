import type { BasicBlock } from '../cfg';
import type { IRExpr, IRStmt } from './ir';
import { irBinary, irConst } from './ir';
import { RegState } from './regstate';

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
  kind: '&&' | '||';
  condition: IRExpr;
  trueTarget: number;
  falseTarget: number;
  consumedBlocks: number[];
} | null {
  const block = blockById.get(blockId);
  if (!block || block.succs.length !== 2) return null;

  const [branchA, fallA] = identifyBranches(block);
  if (branchA === null || fallA === null) return null;

  // Check if fallthrough leads to another conditional block
  const blockB = blockById.get(fallA);
  if (!blockB || blockB.succs.length !== 2) return null;
  if (blockB.preds.length !== 1) return null;

  const [branchB, fallB] = identifyBranches(blockB);
  if (branchB === null || fallB === null) return null;

  const condA = extractCondition(block);
  const condB = extractCondition(blockB);

  // Pattern A (&&): both branch to same FAIL target
  if (branchA === branchB) {
    let combined = irBinary('&&', RegState.negate(condA), RegState.negate(condB));
    const consumed = [fallA];

    // Chained &&: keep extending if next block also branches to same FAIL
    let currentFall = fallB;
    for (let depth = 0; depth < 6; depth++) { // cap total at 8 blocks
      const nextBlock = blockById.get(currentFall);
      if (!nextBlock || nextBlock.succs.length !== 2 || nextBlock.preds.length !== 1) break;
      const [nextBranch, nextFall] = identifyBranches(nextBlock);
      if (nextBranch === null || nextFall === null) break;
      if (nextBranch !== branchA) break; // not same fail target
      const nextCond = extractCondition(nextBlock);
      combined = irBinary('&&', combined, RegState.negate(nextCond));
      consumed.push(currentFall);
      currentFall = nextFall;
    }

    return {
      kind: '&&',
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
 * Detect for-loop pattern:
 *   init block → header (cmp) → body → increment → back to header
 *
 * Requires:
 * - Header block ends with conditional jump (loop test)
 * - Body ends with an assignment that looks like an increment (x = x + 1, x += 1)
 * - An init assignment exists before the loop
 */
export function detectForLoop(
  header: BasicBlock,
  bodyBlocks: number[],
  liftedBlocks: Map<number, IRStmt[]>,
  blockById: Map<number, BasicBlock>,
): {
  init: IRStmt;
  condition: IRExpr;
  update: IRStmt;
  bodyStmts: IRStmt[];
} | null {
  if (bodyBlocks.length === 0) return null;

  // Search all body blocks for increment pattern: x = x + const or x = x - const
  let updateStmt: IRStmt | null = null;
  let updateBlockId: number | null = null;
  for (const bid of bodyBlocks) {
    const stmts = liftedBlocks.get(bid);
    if (!stmts || stmts.length === 0) continue;
    const last = stmts[stmts.length - 1];
    if (last.kind !== 'assign') continue;
    if (last.src.kind !== 'binary') continue;
    if (last.src.op !== '+' && last.src.op !== '-') continue;
    if (last.src.right.kind !== 'const') continue;
    const d = last.dest;
    const sl = last.src.left;
    const isInc =
      (d.kind === 'reg' && sl.kind === 'reg' && d.name.toLowerCase() === sl.name.toLowerCase()) ||
      (d.kind === 'var' && sl.kind === 'var' && d.name === sl.name);
    if (isInc) {
      updateStmt = last;
      updateBlockId = bid;
      break;
    }
  }
  if (!updateStmt || updateBlockId === null || updateStmt.kind !== 'assign') return null;
  const lastStmt = updateStmt;
  const dest = lastStmt.dest;

  // Look for init: assignment to the same variable before the loop
  // Check the header's predecessors (not back-edges) for an init
  const initPreds = header.preds.filter(p => {
    // Not a back-edge: predecessor should come before header in block order
    return p < header.id;
  });

  let initStmt: IRStmt | null = null;
  for (const predId of initPreds) {
    const predStmts = liftedBlocks.get(predId);
    if (!predStmts) continue;
    // Find last assignment to our loop variable
    for (let i = predStmts.length - 1; i >= 0; i--) {
      const s = predStmts[i];
      if (s.kind === 'assign') {
        const sDest = s.dest;
        const matches =
          (sDest.kind === 'reg' && dest.kind === 'reg' && sDest.name.toLowerCase() === dest.name.toLowerCase()) ||
          (sDest.kind === 'var' && dest.kind === 'var' && sDest.name === dest.name);
        if (matches) {
          initStmt = s;
          break;
        }
      }
    }
    if (initStmt) break;
  }

  if (!initStmt) return null;

  // Collect body stmts (excluding the increment at the end)
  const bodyStmts: IRStmt[] = [];
  for (const bid of bodyBlocks) {
    const stmts = liftedBlocks.get(bid) ?? [];
    if (bid === updateBlockId) {
      bodyStmts.push(...stmts.slice(0, -1)); // exclude increment
    } else {
      bodyStmts.push(...stmts);
    }
  }

  // We need the condition from the header
  // The caller should extract this and pass it in
  // For now, return null for the condition (caller will fill it in)
  return {
    init: initStmt,
    condition: irConst(1), // placeholder
    update: lastStmt,
    bodyStmts,
  };
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
export function detectIfElseIfChain(
  blockId: number,
  blockById: Map<number, BasicBlock>,
): boolean {
  const block = blockById.get(blockId);
  if (!block || block.succs.length !== 2) return false;

  // Check if the fallthrough successor is also a conditional
  // This is detected naturally by the recursive structuring
  // Just return true to indicate the pattern exists
  let count = 0;
  let current = blockId;
  while (count < 5) {
    const b = blockById.get(current);
    if (!b || b.succs.length !== 2) break;
    count++;
    // Follow the fallthrough
    const insns = b.insns;
    if (insns.length === 0) break;
    const last = insns[insns.length - 1];
    const m = last.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (!m) break;
    const branchAddr = parseInt(m[1], 16);
    const fallId = b.succs.find(s => {
      const sb = blockById.get(s);
      return sb && sb.startAddr !== branchAddr;
    });
    if (fallId === undefined) break;
    current = fallId;
  }
  return count >= 2;
}
