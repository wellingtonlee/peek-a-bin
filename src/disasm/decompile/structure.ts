import type { BasicBlock, Loop } from '../cfg';
import type { IRStmt, IRExpr } from './ir';
import { irBinary } from './ir';
import { RegState } from './regstate';
import { detectShortCircuit, detectMultiExitLoop, detectForLoop } from './cfgpatterns';

/**
 * Structure a CFG into high-level control flow (if/while/do-while/switch).
 *
 * Approach: recursive structural analysis over basic blocks, using existing
 * loop detection results. No full dominator tree — uses BFS convergence.
 */
export function structureCFG(
  blocks: BasicBlock[],
  loops: Loop[],
  liftedBlocks: Map<number, IRStmt[]>,
  jumpTables: Map<number, number[]>,
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

  /** Get the condition from the last instruction(s) of a block. */
  function extractCondition(block: BasicBlock): IRExpr {
    const insns = block.insns;
    if (insns.length === 0) return { kind: 'unknown', text: 'empty block' };

    const last = insns[insns.length - 1];
    const mn = last.mnemonic.toLowerCase();

    // Conditional jump → build condition from cmp/test before it
    if (mn.startsWith('j') && mn !== 'jmp') {
      // Find the cmp/test before this jump
      const regState = new RegState();
      for (let i = 0; i < insns.length - 1; i++) {
        const insnMn = insns[i].mnemonic.toLowerCase();
        if (insnMn === 'cmp' || insnMn === 'test') {
          const parts = insns[i].opStr.split(',').map(s => s.trim());
          if (parts.length >= 2) {
            // Simple operand parsing for condition extraction
            const left = parseSimpleOperand(parts[0]);
            const right = parseSimpleOperand(parts[1]);
            regState.setFlags(insnMn as 'cmp' | 'test', left, right);
          }
        }
      }
      return regState.getCondition(mn);
    }

    return { kind: 'unknown', text: `end: ${mn}` };
  }

  /** Simple operand parse for condition extraction (register or constant). */
  function parseSimpleOperand(op: string): IRExpr {
    const trimmed = op.trim().replace(/^(byte|word|dword|qword)\s+ptr\s+/i, '');
    // Hex immediate
    const hexM = trimmed.match(/^0x([0-9a-fA-F]+)$/);
    if (hexM) return { kind: 'const', value: parseInt(hexM[1], 16), size: 4 };
    // Decimal
    if (/^\d+$/.test(trimmed)) return { kind: 'const', value: parseInt(trimmed, 10), size: 4 };
    // Memory
    const bracketM = trimmed.match(/\[([^\]]+)\]/);
    if (bracketM) {
      return { kind: 'deref', address: parseSimpleOperand(bracketM[1]), size: 4 };
    }
    // Register
    return { kind: 'reg', name: trimmed, size: 4 };
  }

  /**
   * Find convergence point of two branches via BFS.
   * Returns the block ID where both branches meet, or -1 if none found.
   */
  function findConvergence(branchA: number, branchB: number, loopBody?: Set<number>): number {
    const reachableA = new Set<number>();
    const reachableB = new Set<number>();
    const queueA = [branchA];
    const queueB = [branchB];

    // BFS from branch A
    while (queueA.length > 0) {
      const id = queueA.shift()!;
      if (reachableA.has(id)) continue;
      reachableA.add(id);
      const block = blockById.get(id);
      if (!block) continue;
      for (const succ of block.succs) {
        if (!reachableA.has(succ)) {
          // Don't leave loop body
          if (loopBody) {
            const succBlock = blockById.get(succ);
            if (succBlock && !loopBody.has(succBlock.startAddr) && !loopBody.has(succBlock.insns[0]?.address)) continue;
          }
          queueA.push(succ);
        }
      }
    }

    // BFS from branch B, looking for intersection
    while (queueB.length > 0) {
      const id = queueB.shift()!;
      if (reachableB.has(id)) continue;
      reachableB.add(id);
      if (reachableA.has(id) && id !== branchA && id !== branchB) return id;
      const block = blockById.get(id);
      if (!block) continue;
      for (const succ of block.succs) {
        if (!reachableB.has(succ)) {
          if (loopBody) {
            const succBlock = blockById.get(succ);
            if (succBlock && !loopBody.has(succBlock.startAddr) && !loopBody.has(succBlock.insns[0]?.address)) continue;
          }
          queueB.push(succ);
        }
      }
    }

    // Fallback: find first block reachable from both
    for (const id of reachableA) {
      if (reachableB.has(id)) return id;
    }

    return -1;
  }

  /** Check if a block ends with unconditional jmp. */
  function endsWithJmp(block: BasicBlock): boolean {
    const insns = block.insns;
    if (insns.length === 0) return false;
    return insns[insns.length - 1].mnemonic.toLowerCase() === 'jmp';
  }

  /** Check if a block ends with a conditional jump. */
  function endsWithCondJmp(block: BasicBlock): boolean {
    const insns = block.insns;
    if (insns.length === 0) return false;
    const mn = insns[insns.length - 1].mnemonic.toLowerCase();
    return mn.startsWith('j') && mn !== 'jmp';
  }

  /** Check if a block ends with ret. */
  function endsWithRet(block: BasicBlock): boolean {
    const insns = block.insns;
    if (insns.length === 0) return false;
    const mn = insns[insns.length - 1].mnemonic.toLowerCase();
    return mn === 'ret' || mn === 'retn';
  }

  /** Collect block IDs in a region between start and end (exclusive). */
  function collectRegionBlocks(startId: number, endId: number, loopBody?: Set<number>): number[] {
    const region: number[] = [];
    const regionVisited = new Set<number>();
    const queue = [startId];
    while (queue.length > 0) {
      const id = queue.shift()!;
      if (regionVisited.has(id) || id === endId) continue;
      regionVisited.add(id);
      region.push(id);
      const block = blockById.get(id);
      if (!block) continue;
      for (const succ of block.succs) {
        if (!regionVisited.has(succ) && succ !== endId) {
          if (loopBody) {
            const succBlock = blockById.get(succ);
            if (succBlock && !loopBody.has(succBlock.startAddr) && !loopBody.has(succBlock.insns[0]?.address)) continue;
          }
          queue.push(succ);
        }
      }
    }
    return region;
  }

  /**
   * Structure a sequence of blocks starting from blockId.
   * stopAt: set of block IDs to stop before (e.g., convergence point, loop exit).
   */
  function structureFrom(blockId: number, stopAt: Set<number>, loopBody?: Set<number>): IRStmt[] {
    const result: IRStmt[] = [];
    let current: number | null = blockId;

    while (current !== null) {
      if (stopAt.has(current) || visited.has(current)) break;

      const block = blockById.get(current);
      if (!block) break;

      // Check for loop header
      const loop = loopByHeader.get(block.startAddr);
      if (loop && !visited.has(current)) {
        visited.add(current);
        const loopResult = structureLoop(block, loop);
        result.push(...loopResult);

        // Continue after loop: find exit block
        // The exit is a successor of a loop body block that's outside the loop
        let exitId: number | null = null;
        for (const bid of blocks) {
          if (!loop.bodyAddrs.has(bid.startAddr) && !loop.bodyAddrs.has(bid.insns[0]?.address)) continue;
          for (const succ of bid.succs) {
            const succBlock = blockById.get(succ);
            if (succBlock && !loop.bodyAddrs.has(succBlock.startAddr) && !loop.bodyAddrs.has(succBlock.insns[0]?.address)) {
              if (!visited.has(succ)) exitId = succ;
            }
          }
        }
        current = exitId;
        continue;
      }

      visited.add(current);

      // Emit block's lifted statements
      const blockStmts = liftedBlocks.get(block.id) ?? [];
      result.push(...blockStmts);

      // Determine what comes next based on block's exit
      if (endsWithRet(block) || block.succs.length === 0) {
        current = null;
        continue;
      }

      // Check for switch (indirect jump with jump table)
      if (endsWithJmp(block) && block.succs.length > 2) {
        const lastInsn = block.insns[block.insns.length - 1];
        const jtTargets = jumpTables.get(lastInsn.address);
        if (jtTargets) {
          const switchResult = structureSwitch(block, jtTargets);
          result.push(switchResult);

          // Find convergence after switch — include successors of all case
          // blocks and the default block when searching for the exit point
          const caseBlockIds = new Set<number>(block.succs);
          // Also include the default block if present
          if (switchResult.kind === 'switch' && switchResult.defaultBody) {
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
            if (!visited.has(cand)) { current = cand; break; }
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
              result.push({ kind: 'goto', label: `loc_${targetBlock.startAddr.toString(16).toUpperCase()}` });
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
        const convergence = findConvergence(branchTarget, fallthrough, loopBody);

        const convergenceSet = new Set(stopAt);
        if (convergence >= 0) convergenceSet.add(convergence);

        // Check for short-circuit && / || pattern
        const sc = detectShortCircuit(current, blockById, extractCondition, identifyBranches);
        if (sc) {
          const scConvergenceSet = new Set(stopAt);
          const scConvergence = findConvergence(sc.trueTarget, sc.falseTarget, loopBody);
          if (scConvergence >= 0) scConvergenceSet.add(scConvergence);

          // Mark consumed blocks as visited
          for (const cid of sc.consumedBlocks) visited.add(cid);

          const thenBody = structureFrom(sc.trueTarget, scConvergenceSet, loopBody);
          const elseBody = structureFrom(sc.falseTarget, scConvergenceSet, loopBody);
          const scCond = sc.condition;

          if (thenBody.length > 0 && elseBody.length > 0) {
            result.push({ kind: 'if', condition: scCond, thenBody, elseBody });
          } else if (thenBody.length > 0) {
            result.push({ kind: 'if', condition: scCond, thenBody });
          } else if (elseBody.length > 0) {
            result.push({ kind: 'if', condition: RegState.negate(scCond), thenBody: elseBody });
          }

          current = scConvergence >= 0 ? scConvergence : null;
          continue;
        }

        // Check for simple patterns first:
        // 1. One branch returns → if-return pattern
        const branchBlock = blockById.get(branchTarget);
        const fallthroughBlock = blockById.get(fallthrough);

        if (branchBlock && endsWithRet(branchBlock) && branchBlock.succs.length === 0) {
          // if (cond) { ... return; }
          const thenBody = structureFrom(branchTarget, convergenceSet, loopBody);
          result.push({ kind: 'if', condition: RegState.negate(condition), thenBody });
          // Continue with fallthrough
          current = fallthrough;
          continue;
        }

        if (fallthroughBlock && endsWithRet(fallthroughBlock) && fallthroughBlock.succs.length === 0) {
          // if (!cond) { ... return; }
          const thenBody = structureFrom(fallthrough, convergenceSet, loopBody);
          result.push({ kind: 'if', condition, thenBody });
          // Continue with branch target
          current = branchTarget;
          continue;
        }

        // General if-else
        // Branch target (jcc taken) = "then" with negated condition
        // because: jne target → if (condition) goto target → if (!condition) { fallthrough }
        // Actually: jne = jump if not equal. So the "then" for "jne target" is when cond IS true → go to target
        // We want: if (cond) { branchTarget } else { fallthrough }
        // But our condition already represents "when the jump is taken"
        // So: if (condition) { branchBody } else { fallthroughBody }

        if (convergence >= 0) {
          const thenBody = structureFrom(branchTarget, convergenceSet, loopBody);
          const elseBody = structureFrom(fallthrough, convergenceSet, loopBody);

          if (thenBody.length > 0 && elseBody.length > 0) {
            result.push({ kind: 'if', condition: RegState.negate(condition), thenBody, elseBody });
          } else if (thenBody.length > 0) {
            result.push({ kind: 'if', condition: RegState.negate(condition), thenBody });
          } else if (elseBody.length > 0) {
            result.push({ kind: 'if', condition, thenBody: elseBody });
          }

          current = convergence;
        } else {
          // No convergence found — emit both branches inline
          const thenBody = structureFrom(branchTarget, stopAt, loopBody);
          const elseBody = structureFrom(fallthrough, stopAt, loopBody);
          if (thenBody.length > 0 || elseBody.length > 0) {
            result.push({ kind: 'if', condition: RegState.negate(condition), thenBody, elseBody: elseBody.length > 0 ? elseBody : undefined });
          }
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

  /** Identify which successor is the branch target vs fallthrough. */
  function identifyBranches(block: BasicBlock): [number | null, number | null] {
    const insns = block.insns;
    if (insns.length === 0) return [null, null];
    const last = insns[insns.length - 1];
    const mn = last.mnemonic.toLowerCase();

    if (!mn.startsWith('j') || mn === 'jmp') return [null, null];

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
        const inLoop = loop.bodyAddrs.has(succBlock.startAddr) || loop.bodyAddrs.has(succBlock.insns[0]?.address);
        if (inLoop) {
          bodyStart = succId;
        } else {
          exitId = succId;
        }
      }

      if (bodyStart !== null) {
        const loopStopAt = new Set<number>([header.id]);
        if (exitId !== null) loopStopAt.add(exitId);

        // Detect multi-exit: conditional branches inside body targeting outside → break
        const multiExits = detectMultiExitLoop(header, loop.bodyAddrs, blocks, blockById);
        for (const exit of multiExits) {
          loopStopAt.add(exit.exitTarget);
        }

        const body = structureFrom(bodyStart, loopStopAt, loop.bodyAddrs);

        // Continue detection: scan body for conditional branches targeting header (back-edge)
        const bodyWithContinue = insertContinueStmts(body, header, loop);

        // Include header statements if any (before the condition check)
        const fullBody = headerStmts.length > 0 ? [...headerStmts, ...bodyWithContinue] : bodyWithContinue;

        // The condition for while: we continue looping when condition takes us to body
        // If branch goes to body (exit is fallthrough): while(condition)
        // If fallthrough goes to body (branch goes to exit): while(!condition)
        let whileCondition: IRExpr;
        if (bodyStart === branchTarget) {
          whileCondition = RegState.negate(condition);
        } else {
          whileCondition = condition;
        }

        // Better loop classification: if body starts with if (cond) break; → while(!cond)
        if (whileCondition.kind === 'const' && whileCondition.value === 1 && fullBody.length > 0) {
          const first = fullBody[0];
          if (first.kind === 'if' && first.thenBody.length === 1 && first.thenBody[0].kind === 'break' && !first.elseBody) {
            return [{ kind: 'while', condition: RegState.negate(first.condition), body: fullBody.slice(1) }];
          }
        }

        // Try for-loop detection
        const bodyBlockIds = collectLoopBodyBlockIds(header, loop);
        const forLoop = detectForLoop(header, bodyBlockIds, liftedBlocks, blockById);
        if (forLoop) {
          // Wire actual header condition
          const forCond = whileCondition.kind === 'const' && whileCondition.value === 1
            ? whileCondition
            : whileCondition;
          return [{ kind: 'for', init: forLoop.init, condition: forCond, update: forLoop.update, body: forLoop.bodyStmts }];
        }

        return [{ kind: 'while', condition: whileCondition, body: fullBody }];
      }
    }

    // Fallback: do-while pattern or just emit body with goto
    const bodyBlockIds: number[] = [];
    for (const b of blocks) {
      if (b.id === header.id) continue;
      if (loop.bodyAddrs.has(b.startAddr) || loop.bodyAddrs.has(b.insns[0]?.address)) {
        bodyBlockIds.push(b.id);
      }
    }

    const loopStopAt = new Set<number>([header.id]);
    const body: IRStmt[] = [...headerStmts];
    for (const bid of bodyBlockIds) {
      if (!visited.has(bid)) {
        visited.add(bid);
        const blockStmts = liftedBlocks.get(bid) ?? [];
        body.push(...blockStmts);
      }
    }

    // Find back-edge block for condition
    const backEdgeBlock = blocks.find(b => b.endAddr === loop.backEdgeFromAddr || b.insns.some(i => i.address === loop.backEdgeFromAddr));
    let loopCondition: IRExpr = { kind: 'const', value: 1, size: 4 }; // true = infinite loop
    if (backEdgeBlock && endsWithCondJmp(backEdgeBlock)) {
      loopCondition = extractCondition(backEdgeBlock);
    }

    // do-while with leading break → while
    if (body.length > 0 && body[0].kind === 'if' &&
        body[0].thenBody.length === 1 && body[0].thenBody[0].kind === 'break' && !body[0].elseBody) {
      return [{ kind: 'while', condition: RegState.negate(body[0].condition), body: body.slice(1) }];
    }

    return [{ kind: 'do_while', condition: loopCondition, body }];
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
  function insertContinueStmts(body: IRStmt[], header: BasicBlock, loop: Loop): IRStmt[] {
    const headerLabel = `loc_${header.startAddr.toString(16).toUpperCase()}`;
    return body.map(stmt => {
      // Replace goto to header with continue
      if (stmt.kind === 'goto' && stmt.label === headerLabel) {
        return { kind: 'continue' as const };
      }
      // Check if-goto-header patterns: if (cond) { goto header; } → if (cond) { continue; }
      if (stmt.kind === 'if') {
        const newThen = stmt.thenBody.map(s =>
          s.kind === 'goto' && s.label === headerLabel ? { kind: 'continue' as const } as IRStmt : s
        );
        const newElse = stmt.elseBody?.map(s =>
          s.kind === 'goto' && s.label === headerLabel ? { kind: 'continue' as const } as IRStmt : s
        );
        return { ...stmt, thenBody: newThen, elseBody: newElse };
      }
      return stmt;
    });
  }

  /** Structure a switch statement. */
  function structureSwitch(block: BasicBlock, targets: number[]): IRStmt {
    // Try to find the switch expression and default target from the predecessor
    // block that performs the bounds check (cmp reg, N / ja default).
    let switchExpr: IRExpr = { kind: 'unknown', text: 'switch_expr' };
    let defaultAddr: number | null = null;

    // Walk predecessors looking for the bounds-check block (ends with ja/jae)
    for (const predId of block.preds) {
      const pred = blockById.get(predId);
      if (!pred || pred.insns.length === 0) continue;
      const lastInsn = pred.insns[pred.insns.length - 1];
      const lastMn = lastInsn.mnemonic.toLowerCase();
      if (lastMn === 'ja' || lastMn === 'jae') {
        // Extract switch expression from cmp in this predecessor
        for (const insn of pred.insns) {
          if (insn.mnemonic.toLowerCase() === 'cmp') {
            const parts = insn.opStr.split(',').map(s => s.trim());
            if (parts.length >= 1) {
              switchExpr = parseSimpleOperand(parts[0]);
            }
            break;
          }
        }
        // The ja/jae target is the default case block
        const m = lastInsn.opStr.match(/^0x([0-9a-fA-F]+)$/);
        if (m) defaultAddr = parseInt(m[1], 16);
        break;
      }
    }

    // Fallback: scan current block for cmp (original behavior)
    if (switchExpr.kind === 'unknown') {
      for (const insn of block.insns) {
        if (insn.mnemonic.toLowerCase() === 'cmp') {
          const parts = insn.opStr.split(',').map(s => s.trim());
          if (parts.length >= 1) {
            switchExpr = parseSimpleOperand(parts[0]);
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

    for (const [targetAddr, values] of targetToCase) {
      // Skip if this is the default target — handle it separately
      if (defaultAddr !== null && targetAddr === defaultAddr) continue;
      const targetBlock = blockByAddr.get(targetAddr);
      if (targetBlock && !visited.has(targetBlock.id)) {
        visited.add(targetBlock.id);
        const body = liftedBlocks.get(targetBlock.id) ?? [];
        cases.push({ values, body: [...body, { kind: 'break' as const }] });
      } else {
        cases.push({ values, body: [{ kind: 'break' as const }] });
      }
    }

    // Structure the default case body
    let defaultBody: IRStmt[] | undefined;
    if (defaultAddr !== null) {
      const defaultBlock = blockByAddr.get(defaultAddr);
      if (defaultBlock && !visited.has(defaultBlock.id)) {
        visited.add(defaultBlock.id);
        const body = liftedBlocks.get(defaultBlock.id) ?? [];
        defaultBody = [...body, { kind: 'break' as const }];
      } else {
        defaultBody = [{ kind: 'break' as const }];
      }
    }

    return { kind: 'switch', expr: switchExpr, cases, defaultBody };
  }

  // Start structuring from the entry block (id 0)
  return structureFrom(0, new Set(), undefined);
}
