import type { Instruction, DisasmFunction, Xref, StackFrame } from '../types';
import type { FunctionSignature } from '../signatures';
import { buildCFG, detectLoops } from '../cfg';
import { liftBlock } from './lifter';
import { foldBlock, eliminateDeadStores } from './fold';
import { structureCFG } from './structure';
import { promoteVars } from './promote';
import { emitFunction } from './emit';
import { RegState } from './regstate';

/**
 * Full decompilation pipeline: instructions → pseudocode string.
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
): string {
  try {
    // 1. Build CFG + detect loops
    const blocks = buildCFG(func, instructions, xrefMap, jumpTables);
    if (blocks.length === 0) {
      return `// ${func.name}: no instructions found`;
    }
    const loops = detectLoops(blocks);

    // 2. Lift each block
    const liftedBlocks = new Map<number, import('./ir').IRStmt[]>();
    const regState = new RegState();

    for (const block of blocks) {
      const stmts = liftBlock(block, regState, is64, iatMap, stringMap, funcMap);
      liftedBlocks.set(block.id, stmts);
    }

    // 3. Fold + dead store elimination per block
    for (const [blockId, stmts] of liftedBlocks) {
      let folded = foldBlock(stmts);
      folded = eliminateDeadStores(folded);
      liftedBlocks.set(blockId, folded);
    }

    // 4. Structure CFG → structured IR statements
    const structured = structureCFG(blocks, loops, liftedBlocks, jumpTables);

    // 5. Wrap in IRFunction with variable promotion
    const irFunc = promoteVars(func.name, func.address, structured, stackFrame, signature, is64);

    // 6. Emit C text
    return emitFunction(irFunc);
  } catch (err: any) {
    return `// Decompilation error for ${func.name}: ${err?.message ?? String(err)}`;
  }
}
