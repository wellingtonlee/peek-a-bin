import type { Instruction, DisasmFunction, Xref, StackFrame } from '../types';
import type { FunctionSignature } from '../signatures';
import { buildCFG, detectLoops } from '../cfg';
import { liftBlock } from './lifter';
import { foldBlock } from './fold';
import { buildSSA } from './ssa';
import { ssaOptimize } from './ssaopt';
import { destroySSA } from './ssadestroy';
import { structureCFG } from './structure';
import { promoteVars } from './promote';
import { emitFunction } from './emit';
import { inferTypes } from './typeInfer';
import { RegState } from './regstate';

export interface DecompileResult {
  code: string;
  lineMap: [number, number][];  // serializable for worker transfer
}

/**
 * Full decompilation pipeline: instructions → pseudocode string + line map.
 *
 * buildCFG → liftBlock → [buildSSA → ssaOptimize → destroySSA] → foldBlock
 * → structureCFG → promoteVars → emitFunction
 */
export function decompileFunction(
  func: DisasmFunction,
  instructions: Instruction[],
  xrefMap: Map<number, Xref[]>,
  stackFrame: StackFrame | null,
  signature: FunctionSignature | null,
  is64: boolean,
  jumpTables: Map<number, number[]>,
  iatMap: Map<number, { lib: string; func: string }>,
  stringMap: Map<number, string>,
  funcMap: Map<number, { name: string; address: number }>,
): DecompileResult {
  try {
    // 1. Build CFG + detect loops
    const blocks = buildCFG(func, instructions, xrefMap, jumpTables);
    if (blocks.length === 0) {
      return { code: `// ${func.name}: no instructions found`, lineMap: [] };
    }
    const loops = detectLoops(blocks);

    // 2. Lift each block (fresh RegState per block — SSA handles cross-block)
    const liftedBlocks = new Map<number, import('./ir').IRStmt[]>();

    for (const block of blocks) {
      const regState = new RegState();
      const stmts = liftBlock(block, regState, is64, iatMap, stringMap, funcMap);
      liftedBlocks.set(block.id, stmts);
    }

    // 3. SSA: build → optimize → destroy
    const ssaCtx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ssaCtx);
    destroySSA(ssaCtx);

    // 4. Fold per block (constant folding + single-use inlining, post-SSA)
    for (const [blockId, stmts] of liftedBlocks) {
      liftedBlocks.set(blockId, foldBlock(stmts));
    }

    // 5. Structure CFG → structured IR statements
    const structured = structureCFG(blocks, loops, liftedBlocks, jumpTables);

    // 6. Type inference
    const typeCtx = inferTypes(structured, iatMap);

    // 7. Wrap in IRFunction with variable promotion
    const irFunc = promoteVars(func.name, func.address, structured, stackFrame, signature, is64, typeCtx);

    // 8. Emit C text + lineMap
    const result = emitFunction(irFunc);
    return {
      code: result.code,
      lineMap: Array.from(result.lineMap.entries()),
    };
  } catch (err: any) {
    return {
      code: `// Decompilation error for ${func.name}: ${err?.message ?? String(err)}`,
      lineMap: [],
    };
  }
}
