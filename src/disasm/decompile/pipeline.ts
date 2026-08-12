import type { RuntimeFunction } from "../../pe/types";
import { buildCFG, detectLoops } from "../cfg";
import type { FunctionSignature } from "../signatures";
import type { DisasmFunction, Instruction, StackFrame, Xref } from "../types";
import { cleanupStructured } from "./cleanup";
import { emitFunction } from "./emit";
import { foldBlock } from "./fold";
import type { IRStmt, IRTry } from "./ir";
import { liftBlock } from "./lifter";
import { promoteVars } from "./promote";
import { RegState } from "./regstate";
import { buildSSA, detectNaturalLoops } from "./ssa";
import { destroySSA } from "./ssadestroy";
import { ssaOptimize } from "./ssaopt";
import { type StructRegistry, synthesizeStructs } from "./structs";
import { structureCFG } from "./structure";
import { inferTypes } from "./typeInfer";

export interface DecompileResult {
  code: string;
  lineMap: [number, number][]; // serializable for worker transfer
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
    const liftedBlocks = new Map<number, import("./ir").IRStmt[]>();

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
    const structured = structureCFG(blocks, loops, liftedBlocks, jumpTables, is64);

    // 5b. Post-structuring cleanup (guard clauses, goto/empty-block elimination)
    let cleaned = cleanupStructured(structured);

    // 5c. Exception handling: wrap try/except regions from .pdata
    if (runtimeFunctions && runtimeFunctions.length > 0) {
      cleaned = wrapExceptionRegions(cleaned, func, runtimeFunctions);
    }

    // 6. Type inference
    const typeCtx = inferTypes(cleaned, iatMap);

    // 7. Wrap in IRFunction with variable promotion
    let irFunc = promoteVars(
      func.name,
      func.address,
      cleaned,
      stackFrame,
      signature,
      is64,
      typeCtx,
    );

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
 * Looks for the RuntimeFunction describing the current function, if it has a handler.
 *
 * **Units.** `DisasmFunction.address` is a virtual address — the image base is
 * already in it. `RuntimeFunction.beginAddress` is an RVA, exactly as parsed
 * out of `.pdata`; nothing normalises the array on the way here (the worker and
 * the MCP server both forward `pe.runtimeFunctions` untouched). Comparing the
 * two directly matched nothing at all: on t64.exe all 240 entries match
 * `beginAddress + imageBase` and none match the raw RVA, so `__try` was emitted
 * zero times across 1475 real functions despite 50 handlers being present
 * (peek-a-bin-yrh).
 *
 * The image base is not plumbed this far, so it is recovered here from the pair
 * instead: a VA and its RVA differ by the image base, which the PE spec
 * requires to be a multiple of 64K. That is not by itself a unique test — two
 * functions exactly 64K apart are congruent — so an ambiguous match is
 * *discarded* rather than guessed at. A missing `__try` is a gap; a `__try`
 * attributed to the wrong function is a lie about what the code does.
 */
function wrapExceptionRegions(
  body: IRStmt[],
  func: DisasmFunction,
  runtimeFunctions: RuntimeFunction[],
): IRStmt[] {
  const withHandler = runtimeFunctions.filter(
    (rf) => rf.handlerAddress !== undefined && (rf.handlerFlags ?? 0) & 0x3, // EHANDLER or UHANDLER
  );

  // Same unit on both sides: either the caller normalised the array to VAs, or
  // the image is based at 0.
  let matching = withHandler.filter((rf) => rf.beginAddress === func.address);

  if (matching.length === 0) {
    const IMAGE_BASE_ALIGNMENT = 0x10000;
    const congruent = withHandler.filter((rf) => {
      const imageBase = func.address - rf.beginAddress;
      return imageBase > 0 && imageBase % IMAGE_BASE_ALIGNMENT === 0;
    });
    // Prefer an entry whose extent is the function's own; only an unambiguous
    // survivor is used.
    const exact = congruent.filter((rf) => rf.endAddress - rf.beginAddress === func.size);
    const candidates = exact.length > 0 ? exact : congruent;
    matching = candidates.length === 1 ? candidates : [];
  }

  if (matching.length === 0) return body;

  // For now, wrap the entire function body in a try block for the first matching handler.
  // The handler body is represented as a comment referencing the handler address.
  const rf = matching[0];
  // `handlerAddress` is an RVA like `beginAddress`; report it in the same unit
  // as every other address in the pane, i.e. as a VA.
  const handlerAddr = rf.handlerAddress! + (func.address - rf.beginAddress);
  const tryStmt: IRTry = {
    kind: "try",
    body,
    handler: [
      { kind: "comment", text: `Exception handler at 0x${handlerAddr.toString(16).toUpperCase()}` },
    ],
  };

  return [tryStmt];
}
