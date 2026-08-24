import type { RuntimeFunction } from "../../pe/types";
import type { CalleeClobbers } from "../callSummary";
import { buildCFG, detectLoops } from "../cfg";
import { funcExceptionRecord } from "../funcInsns";
import type { FunctionSignature } from "../signatures";
import type { DisasmFunction, Instruction, StackFrame, Xref } from "../types";
import { cleanupStructured } from "./cleanup";
import { emitFunction } from "./emit";
import { flagPredecessor } from "./flagModel";
import { blockLiveOut, foldBlock } from "./fold";
import type { IRBranch, IRStmt, IRTry } from "./ir";
import { firstCalleeSavedWrites, liftBlock, liftCrossBlockPops, matchedStackSlots } from "./lifter";
import { promoteVars } from "./promote";
import { RegState } from "./regstate";
import { buildSSA, detectNaturalLoops } from "./ssa";
import { destroySSA } from "./ssadestroy";
import { ssaOptimize } from "./ssaopt";
import { type StructGroupReport, type StructRegistry, synthesizeStructs } from "./structs";
import { type SwitchArmExit, structureCFG } from "./structure";
import { inferTypes } from "./typeInfer";

export interface DecompileResult {
  code: string;
  lineMap: [number, number][]; // serializable for worker transfer
}

/**
 * The two sides of the structuring step, handed to an instrument that asks to
 * watch it.
 *
 * This exists for ONE reason: the statements `liftBlock` produced and the
 * statements `structureCFG` returned are the same objects, so a statement the
 * structurer drops can be identified **by object identity** and by nothing
 * else. Both sides are internal to `decompileFunction` and neither is
 * recoverable from its return value — the emitted C says nothing about a
 * statement that never entered the tree, which is precisely what makes that
 * class of defect invisible (see `structureCFG`'s leftover pass, and
 * `peek-a-bin-cb2`, where 6% of every statement the front end produced was
 * silently deleted).
 *
 * `corpus/sweep.ts` is the only caller. Passing no tap costs one `undefined`
 * check and changes no value the pipeline computes, which is the point: an
 * instrument that alters what it measures is worse than no instrument.
 */
export interface StructuringTap {
  func: DisasmFunction;
  /**
   * The per-block lifted statements as `structureCFG` was handed them — after
   * SSA and `foldBlock`, so a statement inlined into a later use is already
   * gone from here and is not a drop. The arrays are copies; the statement
   * objects in them are the originals, because identity is the whole point.
   */
  lifted: Map<number, IRStmt[]>;
  /** `structureCFG`'s output, before `cleanupStructured` touches it. */
  structured: IRStmt[];
  /**
   * How `structureSwitch` closed each arm of each switch it built, in the order
   * they were built.
   *
   * Here for the same reason the two above are: the answer does not survive into
   * anything a caller can see. An arm closed with `break` is indistinguishable
   * in the emitted C from an arm that really ends, so whether the terminator is
   * true of the machine is a question only `structureSwitch` can be asked
   * (peek-a-bin-pqs5, gated by `corpus/armExits.ts`). Empty on every function
   * with no recovered jump table, which is all of them on x64.
   */
  armExits: SwitchArmExit[];
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
  /**
   * `.pdata` records. Either the image's whole table (the MCP server,
   * `corpus/sweep.ts`) or the single row a caller has already picked with
   * `funcExceptionRecord` (`disasmClient`, which cannot afford to clone a table
   * linear in the image on every request) — the same answer either way, because
   * that rule is what `wrapExceptionRegions` applies here and it is idempotent.
   */
  runtimeFunctions?: RuntimeFunction[],
  tap?: (ev: StructuringTap) => void,
  /**
   * What each callee is known to write, from `disasm/callSummary.ts`. Absent on
   * every path that does not build one, and absent means exactly the behaviour
   * this pipeline had before the summary existed — see `IRCall.clobbers`.
   *
   * Last, after `tap`, because it is the same kind of parameter: an optional
   * extra piece of evidence that a caller either has or does not, and putting it
   * anywhere else would renumber twelve existing call sites for nothing.
   */
  calleeClobbers?: CalleeClobbers,
  /**
   * An instrument watching how struct synthesis settled each base's overlapping
   * readings. Last, after `calleeClobbers`, for the reason that parameter is
   * last: appending is what keeps fourteen existing call sites unrenumbered.
   * `corpus/structOverlaps.ts` is the only caller. See `StructGroupReport`.
   */
  structTap?: (g: StructGroupReport) => void,
): DecompileResult {
  try {
    // 1. Build CFG + detect loops
    const blocks = buildCFG(func, instructions, xrefMap, jumpTables);
    if (blocks.length === 0) {
      return { code: `// ${func.name}: no instructions found`, lineMap: [] };
    }
    const loops = detectLoops(blocks);

    // 2. Lift each block (fresh RegState per block — SSA handles cross-block)
    //
    // The one exception to "block-local" is the callee-saved write map, which
    // is a property of the whole function: `collectArgs32` uses it to tell a
    // register save from a pushed argument, and the two are the same
    // instruction inside any single block. x64 collects its arguments from
    // registers, so the map is not built there.
    const calleeSavedFirstWrite = is64 ? undefined : firstCalleeSavedWrites(blocks);
    // The third, and the only one that is a property of the whole CFG rather
    // than of the instruction stream: which `push <reg>` a `pop <reg>` takes its
    // value from. A save and its restore are routinely in different blocks with
    // a loop nest between them, so the pairing cannot be answered inside
    // `liftBlock` at all (peek-a-bin-6f3v).
    const stackSlots = matchedStackSlots(blocks, is64);
    const liftedBlocks = new Map<number, import("./ir").IRStmt[]>();
    // The second piece of non-block-local context, and it is a *flag* fact: a
    // block that writes no flag at all reads the ones its predecessor left, so a
    // Jcc alone in its block can only be answered from the block before it. See
    // `flagScanStream` (peek-a-bin-suql).
    const blockById = new Map(blocks.map((b) => [b.id, b]));

    for (const block of blocks) {
      const regState = new RegState();
      const stmts = liftBlock(
        block,
        regState,
        is64,
        iatMap,
        stringMap,
        funcMap,
        calleeSavedFirstWrite,
        calleeClobbers,
        flagPredecessor(block, blockById),
        stackSlots,
      );
      liftedBlocks.set(block.id, stmts);
    }

    // 2b. A `pop <reg>` whose `push <imm>` is in a PREDECESSOR.
    //
    // MSVC's two-byte `mov reg, imm` is routinely split across a branch — three
    // arms each pushing a different character, one `pop` at the join — and
    // `stackIdiom.ts`'s pairing is handed one block, so it answers nothing there
    // and the `pop` is no definition in SSA. It cannot be done inside
    // `liftBlock` for a structural reason rather than a convenient one: the
    // definition has to land in EACH predecessor so `buildSSA` builds the phi,
    // and `liftBlock` returns one block's statements. See
    // `crossBlockPopImmediates` for the four refusals that make defining the
    // register early sound (peek-a-bin-6ilz).
    liftCrossBlockPops(blocks, liftedBlocks);

    // 3. SSA: build → optimize → destroy
    const ssaCtx = buildSSA(blocks, liftedBlocks);
    const naturalLoops = detectNaturalLoops(blocks, ssaCtx.idom, ssaCtx.domTree);
    ssaOptimize(ssaCtx, naturalLoops.size > 0 ? naturalLoops : undefined);
    destroySSA(ssaCtx);

    // 4. Fold per block (constant folding + single-use inlining, post-SSA)
    //
    // The liveness is computed once, over the whole unfolded program: a
    // definition read once in its own block and again in a successor is not
    // single-use, and inlining it deletes the assignment the successor's read
    // needs (peek-a-bin-7eyn). `blockLiveOut` is what makes that visible from
    // inside a per-block pass.
    const liveOut = blockLiveOut(blocks, liftedBlocks);
    for (const [blockId, stmts] of liftedBlocks) {
      liftedBlocks.set(blockId, foldBlock(stmts, liveOut.get(blockId)));
    }

    // 4b. Extract the branch statements again.
    //
    // They existed for the dataflow stages above — SSA renaming, propagation,
    // DCE's use counts and `foldBlock`'s inlining all saw each guard's registers
    // as real reads. From here they would only do harm: `detectForLoop` skips
    // any body block whose last statement is not an `assign`, so a branch left
    // in place takes for-loop recognition to zero corpus-wide, silently
    // (peek-a-bin-c33).
    //
    // This runs BEFORE the tap snapshot below, and that ordering is load-bearing
    // rather than incidental: the statement-drop audit compares the lifted
    // statements against the structured ones by object identity, so a branch
    // still present in `lifted` would be reported as a dropped statement in
    // every block that ends in a conditional jump.
    //
    // The conditions are kept, keyed by block, and handed to `structureCFG`:
    // `extractCondition` prefers this — the expression the dataflow stages
    // renamed, propagated into, repaired and folded — over re-reading the
    // `cmp`/`test` off the instruction. That is the whole point of the
    // statement kind; the extraction is only about where it may *appear*.
    const branches = new Map<number, IRBranch>();
    for (const [blockId, stmts] of liftedBlocks) {
      const kept: IRStmt[] = [];
      let branch: IRBranch | null = null;
      for (const s of stmts) {
        if (s.kind === "branch") branch = s;
        else kept.push(s);
      }
      if (!branch) continue;
      branches.set(blockId, branch);
      liftedBlocks.set(blockId, kept);
    }

    // 5. Structure CFG → structured IR statements
    //
    // The lifted lists are copied BEFORE the call so a tap sees what
    // `structureCFG` was handed rather than whatever it left behind. Nothing
    // here runs, and no copy is made, unless somebody is watching.
    const liftedBefore = tap
      ? new Map([...liftedBlocks].map(([id, stmts]) => [id, [...stmts]]))
      : null;
    // The switch-arm observer is wired on exactly the same condition, and for
    // the same reason: it is an instrument, so no production run may pay for it
    // or be able to notice it. `structureCFG` computes nothing from it.
    const armExits: SwitchArmExit[] = [];
    const structured = structureCFG(
      blocks,
      loops,
      liftedBlocks,
      jumpTables,
      is64,
      branches,
      tap ? (ev) => armExits.push(ev) : undefined,
    );
    if (tap && liftedBefore) tap({ func, lifted: liftedBefore, structured, armExits });

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
      irFunc = synthesizeStructs(irFunc, registry, structTap);
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
 *
 * WHICH record applies to this function is {@link funcExceptionRecord}'s rule —
 * the units, the recovered image base and the ambiguous-match discard are all
 * documented there — and it lives in a leaf so the *client* can apply it too and
 * send the one surviving row instead of a table linear in the image
 * (peek-a-bin-qmlz). What stays here is what to do with the record once chosen,
 * which is the only part the emitted C depends on.
 */
function wrapExceptionRegions(
  body: IRStmt[],
  func: DisasmFunction,
  runtimeFunctions: RuntimeFunction[],
): IRStmt[] {
  const rf = funcExceptionRecord(func, runtimeFunctions);
  if (!rf) return body;

  // For now, wrap the entire function body in a try block for the matching
  // handler. The handler body is represented as a comment referencing the
  // handler address.
  //
  // `handlerAddress` is an RVA like `beginAddress`; report it in the same unit
  // as every other address in the pane, i.e. as a VA. The difference of the two
  // is the image base `funcExceptionRecord` recovered to match them at all.
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
