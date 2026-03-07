import type { Instruction, DisasmFunction, Xref, StackFrame } from '../types';
import type { RuntimeFunction } from '../../pe/types';
import type { FunctionSignature } from '../signatures';
import { buildCFG, detectLoops } from '../cfg';
import { liftBlock } from './lifter';
import { foldBlock } from './fold';
import { buildSSA, detectNaturalLoops } from './ssa';
import { ssaOptimize } from './ssaopt';
import { destroySSA } from './ssadestroy';
import { structureCFG } from './structure';
import { promoteVars } from './promote';
import { emitFunction } from './emit';
import { inferTypes } from './typeInfer';
import { RegState } from './regstate';
import { synthesizeStructs, StructRegistry } from './structs';
import { cleanupStructured } from './cleanup';
import type { IRStmt, IRTry, IRExpr } from './ir';

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
  registry?: StructRegistry,
  runtimeFunctions?: RuntimeFunction[],
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
    const naturalLoops = detectNaturalLoops(blocks, ssaCtx.idom, ssaCtx.domTree);
    ssaOptimize(ssaCtx, naturalLoops.size > 0 ? naturalLoops : undefined);
    destroySSA(ssaCtx);

    // 4. Fold per block (constant folding + single-use inlining, post-SSA)
    for (const [blockId, stmts] of liftedBlocks) {
      liftedBlocks.set(blockId, foldBlock(stmts));
    }

    // 5. Structure CFG → structured IR statements
    const structured = structureCFG(blocks, loops, liftedBlocks, jumpTables);

    // 5b. Post-structuring cleanup (guard clauses, goto/empty-block elimination)
    let cleaned = cleanupStructured(structured);

    // 5c. Exception handling: wrap try/except regions from .pdata
    if (runtimeFunctions && runtimeFunctions.length > 0) {
      cleaned = wrapExceptionRegions(cleaned, func, runtimeFunctions);
    }

    // 6. Type inference
    const typeCtx = inferTypes(cleaned, iatMap);

    // 7. Wrap in IRFunction with variable promotion
    let irFunc = promoteVars(func.name, func.address, cleaned, stackFrame, signature, is64, typeCtx);

    // 8. Struct synthesis (if registry provided)
    if (registry) {
      irFunc = synthesizeStructs(irFunc, registry);
    }

    // 9. Emit C text + lineMap
    const result = emitFunction(irFunc, typeCtx, stringMap);
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

/**
 * Wrap structured statements in __try/__except blocks based on .pdata exception info.
 * Looks for RuntimeFunctions that overlap the current function and have exception handlers.
 */
function wrapExceptionRegions(
  body: IRStmt[],
  func: DisasmFunction,
  runtimeFunctions: RuntimeFunction[],
): IRStmt[] {
  // Find RuntimeFunctions with handlers that overlap this function's address range
  const funcRVA = func.address;
  const matching = runtimeFunctions.filter(
    rf => rf.handlerAddress !== undefined &&
          rf.beginAddress === funcRVA &&
          (rf.handlerFlags ?? 0) & 0x3, // EHANDLER or UHANDLER
  );

  if (matching.length === 0) return body;

  // For now, wrap the entire function body in a try block for the first matching handler.
  // The handler body is represented as a comment referencing the handler address.
  const rf = matching[0];
  const handlerAddr = rf.handlerAddress!;
  const tryStmt: IRTry = {
    kind: 'try',
    body,
    handler: [
      { kind: 'comment', text: `Exception handler at 0x${handlerAddr.toString(16).toUpperCase()}` },
    ],
  };

  return [tryStmt];
}
