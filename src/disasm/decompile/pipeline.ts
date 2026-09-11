import type { RuntimeFunction, ScopeTableEntry } from "../../pe/types";
import type { CalleeClobbers } from "../callSummary";
import { type BasicBlock, buildCFG, detectLoops } from "../cfg";
import { namedGlobalsFor } from "../crtIdioms";
import { funcExceptionRecord } from "../funcInsns";
import type { FunctionSignature } from "../signatures";
import type { DisasmFunction, Instruction, StackFrame, Xref } from "../types";
import { type CleanupStats, cleanupStructured, emptyCleanupStats } from "./cleanup";
import { type DecompileAdmissions, emitFunction, emptyAdmissions } from "./emit";
import { carryPredecessor, flagPredecessor } from "./flagModel";
import { blockLiveOut, foldBlock } from "./fold";
import { bodiesOf, type IRBranch, type IRStmt, type IRTry, rewriteBodies } from "./ir";
import { firstCalleeSavedWrites, liftBlock, liftCrossBlockPops, matchedStackSlots } from "./lifter";
import type { NamingContext } from "./naming";
import { promoteVars } from "./promote";
import { RegState } from "./regstate";
import { buildSSA, detectNaturalLoops } from "./ssa";
import { destroySSA } from "./ssadestroy";
import { ssaOptimize } from "./ssaopt";
import { type StructGroupReport, type StructRegistry, synthesizeStructs } from "./structs";
import { type LabelPruneReport, labelAddrFor, type SwitchArmExit, structureCFG } from "./structure";
import { inferTypes } from "./typeInfer";

export interface DecompileResult {
  code: string;
  lineMap: [number, number][]; // serializable for worker transfer
  /**
   * Where `code` admits a gap, as line indices — see `DecompileAdmissions` in
   * emit.ts. Plain arrays, so it crosses `postMessage` as-is. Empty arrays for a
   * whole recovery, for the no-instructions comment and on `error`.
   */
  admissions: DecompileAdmissions;
  /**
   * THE FAULT STATE. Set when the pipeline threw; `code` is then empty and
   * `lineMap`/`admissions` empty too. This used to be returned AS CODE — a
   * `// Decompilation error for <name>: <msg>` comment — so a failure reached
   * MCP as a successful response holding a comment, the browser cached and
   * rendered it as a decompilation, and `corpus/sweep.ts`'s `throws` (the
   * standing expectation of 0) could never see the class at all: nothing in
   * `src/` or `corpus/` matched that string. A field cannot be mistaken for an
   * answer: `disasmClient` throws it, MCP returns `err(...)`, the sweep counts
   * it. Absent means the pipeline ran to completion.
   */
  error?: string;
}

export type { DecompileAdmissions } from "./emit";

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
  /**
   * Why each `loc_` label survived `pruneLabels` — kept because a `goto` names
   * it, kept only because the leftover pass pinned it, or dropped. Here for the
   * reason the three above are: the emitted C shows a label and not the ground
   * it was kept on, and a pinned label is the one `structs.ts`'s
   * `baseGenerations` resets every key at. `null` only if `structureCFG` never
   * reached its final sweep, which on a non-empty CFG it always does.
   */
  labels: LabelPruneReport | null;
  /**
   * What `cleanupStructured` did to the tree above — today the count of
   * `goto`s dropped from the end of an `if` arm whose next sibling is the
   * label they name. Here for the reason the four above are: a `goto` the
   * cleanup removed and a `goto` the structurer never wrote are the same
   * absence in the emitted C. This is why the tap fires AFTER cleanup rather
   * than before it — `structured` is still the structurer's own output, since
   * no cleanup pass mutates the tree it is handed (each builds new lists and
   * `rewriteBodies` copies the statement), and the statement-drop audit that
   * reads it by identity is unaffected. `corpus/sweep.ts` is the only reader.
   */
  cleanup: CleanupStats;
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
  /**
   * The section table, the IAT and the format's cookie address, from which the
   * emitter NAMES a dereferenced constant — `g_<HEX>` in a data section,
   * `__imp_<func>` for an IAT slot. See `naming.ts` for the grounding rule.
   * Absent means exactly the spelling this pipeline had before: `*(T*)(0x…)`
   * everywhere but the cookie. Last, after `structTap`, for the reason every
   * parameter since `tap` is last: appending keeps the call sites unrenumbered.
   */
  naming?: NamingContext,
): DecompileResult {
  try {
    // 1. Build CFG + detect loops
    const blocks = buildCFG(func, instructions, xrefMap, jumpTables);
    if (blocks.length === 0) {
      // A DETECTION admission, not a pipeline fault: the detector named a range
      // no instruction was decoded in. Left as code deliberately.
      return {
        code: `// ${func.name}: no instructions found`,
        lineMap: [],
        admissions: emptyAdmissions(),
      };
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
        func,
        carryPredecessor(block, blockById),
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
    let labels: LabelPruneReport | null = null;
    const structured = structureCFG(
      blocks,
      loops,
      liftedBlocks,
      jumpTables,
      is64,
      branches,
      tap ? (ev) => armExits.push(ev) : undefined,
      tap
        ? (report) => {
            labels = report;
          }
        : undefined,
    );
    // 5b. Post-structuring cleanup (guard clauses, goto/empty-block elimination)
    //
    // The stats object exists only when somebody is watching, on the same
    // terms as `liftedBefore`: an instrument no production run pays for.
    const cleanupStats = tap ? emptyCleanupStats() : undefined;
    let cleaned = cleanupStructured(structured, cleanupStats);
    if (tap && liftedBefore && cleanupStats) {
      tap({ func, lifted: liftedBefore, structured, armExits, labels, cleanup: cleanupStats });
    }

    // 5c. Exception handling: wrap try/except regions from .pdata
    if (runtimeFunctions && runtimeFunctions.length > 0) {
      cleaned = wrapExceptionRegions(cleaned, func, runtimeFunctions);
    }

    // 5d. Say what a label no `goto` names is doing there. Spelling only —
    // the labels themselves are untouched, see `annotateLabels`.
    cleaned = annotateLabels(
      cleaned,
      blocks,
      func.address,
      runtimeFunctions ? unwinderEntryVAs(func, runtimeFunctions) : new Set(),
    );

    // 6. Type inference
    const typeCtx = inferTypes(cleaned, iatMap);

    // 7. Wrap in IRFunction with variable promotion
    //
    // THE HEADER'S NAME COMES FROM `funcMap`, THE SAME MAP EVERY CALLEE NAME
    // ALREADY COMES FROM (`resolveCallTarget`/`resolveNamedTarget` in
    // lifter.ts). Both consumers build that map from the user's renames — the
    // browser with `getDisplayName`, the MCP server from `af.renames` — while
    // `func.name` is the detector's raw `sub_<addr>`, so passing it here meant a
    // rename reached every CALLER's body and never the function's own header,
    // and a recursive call spelled a name the header did not (peek-a-bin-n9cl.7).
    // Reading the map makes header and call sites agree by construction, for
    // both consumers and for `corpus/sweep.ts`, whose map carries raw names and
    // is therefore byte-identical before and after. The fallback is the raw
    // name, for a caller whose map does not list this function at all.
    let irFunc = promoteVars(
      funcMap.get(func.address)?.name ?? func.name,
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
    //
    // The globals the recognised CRT routines identify — today the `/GS`
    // cookie — so a load of `*(int64_t*)(0x1400143C8)` is spelled
    // `__security_cookie` and declared `extern` above the header. Derived from
    // the same per-callee facts the lifter read; absent when no summary was
    // supplied, and then the emitter spells every address raw, as before.
    const globals = namedGlobalsFor(calleeClobbers?.idioms, is64);
    const result = emitFunction(irFunc, typeCtx, stringMap, globals, naming);
    return {
      code: result.code,
      lineMap: Array.from(result.lineMap.entries()),
      admissions: result.admissions,
    };
  } catch (err: any) {
    // A fault, not a decompilation — see `DecompileResult.error`. The name is
    // the display name where the map has one, as the header would have been.
    const name = funcMap.get(func.address)?.name ?? func.name;
    return {
      code: "",
      lineMap: [],
      admissions: emptyAdmissions(),
      error: `Decompilation error for ${name}: ${err?.message ?? String(err)}`,
    };
  }
}

/**
 * Wrap structured statements in a `__try`/`__except` from `.pdata` — but only
 * where the image says so, which is far less often than this used to assume.
 *
 * WHICH record applies to this function is {@link funcExceptionRecord}'s rule —
 * the units, the recovered image base and the ambiguous-match discard are all
 * documented there — and it lives in a leaf so the *client* can apply it too and
 * send the one surviving row instead of a table linear in the image
 * (peek-a-bin-qmlz). What stays here is what to do with the record once chosen,
 * which is the only part the emitted C depends on.
 *
 * **DO NOT MOVE ANY OF THE JUDGEMENT BELOW INTO `funcExceptionRecord`, AND DO
 * NOT "TIDY" ITS `& 0x3` FILTER TO MATCH.** That filter is a SELECTOR: its
 * whole soundness argument is that the client and the worker apply the SAME
 * rule and that the rule is idempotent, so narrowing it re-opens peek-a-bin-qmlz
 * for no gain. Selecting the record and deciding what may be claimed about it
 * are two questions, and only the second one belongs here.
 *
 * THREE CLAIMS THIS FUNCTION USED TO MAKE AND NEVER READ (peek-a-bin-j4uk.5):
 *
 *  1. *"A try region exists."* It fired on any selected record, i.e. on
 *     `EHANDLER | UHANDLER`. UHANDLER is `__finally`, and `__GSHandlerCheck` —
 *     a stack-cookie check with NO `__try` IN THE SOURCE AT ALL — sets
 *     EHANDLER. Measured at 4167aa3: of t64's 50 handler-bearing records, 18
 *     are that /GS shape and 2 more carry language-specific data no scope table
 *     could be read out of. All 20 emitted `__try`.
 *  2. *"The region covers the whole function."* The code's own comment said
 *     "For now, wrap the entire function body". Measured against the scope
 *     tables now that they are read: **NOT ONE of t64's 34 entries or w64's 32
 *     covers its record's extent** — every single one is strictly narrower. The
 *     whole-body wrap is not merely unproven, it is wrong in 100% of cases, so
 *     where a wrap survives at all the extent is ADMITTED in the body rather
 *     than implied by the braces.
 *  3. *"The filter is EXCEPTION_EXECUTE_HANDLER."* See `emit.ts`'s
 *     `emitTryFilter` — that was an unconditional fallback, and it is now
 *     printed only where the table's `handler` field holds the format's literal
 *     1 (exactly ONE entry per binary).
 *
 * A FOURTH the emitter cannot fix here: there is no `__finally` spelling in the
 * IR at all, so a termination-handler record used to print
 * `__except(EXCEPTION_EXECUTE_HANDLER)` — a different construct with different
 * control flow. Adding one is a new `IRStmt` kind and therefore the whole
 * "Adding new IRExpr / IRStmt kinds" checklist (peek-a-bin-fcgu). Until then a
 * `__finally` region is RECORDED AND NOT SPELLED: a leading comment states what
 * the linker wrote down and claims no construct. That is peek-a-bin-wo8g's move
 * — say what was read without claiming what was not — and it matters because
 * `__finally` is the dominant kind by an order of magnitude (31 of t64's 34
 * entries, 29 of w64's 32).
 *
 * **A RECORD WITH NO VALIDATED SCOPE TABLE PRODUCES NOTHING, NOT EVEN AN
 * ADMISSION**, and that asymmetry is deliberate rather than an omission. A
 * withheld table is the ORDINARY answer for a `__GSHandlerCheck` or
 * `__CxxFrameHandler3` record (`readScopeTable`'s docstring says so), and those
 * functions have no guarded region to admit — so a comment saying "a guarded
 * region here could not be read" would be the fabrication all over again, in
 * the voice of an admission.
 */
function wrapExceptionRegions(
  body: IRStmt[],
  func: DisasmFunction,
  runtimeFunctions: RuntimeFunction[],
): IRStmt[] {
  const rf = funcExceptionRecord(func, runtimeFunctions);
  if (!rf) return body;

  // Claim 1. `scopeTable` is `undefined` for a record whose language-specific
  // data did not pass `readScopeTable`'s structural check, and that means "the
  // record did not say" rather than "there are no regions" — so the honest
  // response is to say nothing at all.
  const table = rf.scopeTable;
  if (!table || table.length === 0) return body;

  // Every address in a scope table is an RVA, exactly like `beginAddress`;
  // report them in the same unit as the rest of the pane, i.e. as VAs. The
  // difference of the two is the image base `funcExceptionRecord` recovered in
  // order to match the record to the function at all (peek-a-bin-yrh).
  const imageBase = func.address - rf.beginAddress;
  const va = (rva: number) => `0x${(rva + imageBase).toString(16).toUpperCase()}`;

  // `jumpTarget === 0` marks the entry a `__finally`, and then `handler` is the
  // termination funclet's RVA rather than a filter's. See `ScopeTableEntry`.
  const isFinally = (e: ScopeTableEntry) => e.jumpTarget === 0;
  const region = (e: ScopeTableEntry): IRStmt => ({
    kind: "comment",
    text: isFinally(e)
      ? `.pdata: __finally region ${va(e.begin)} - ${va(e.end)}` +
        // `handler` is 0 or 1 for no entry in this corpus, but the format
        // permits both and neither is a funclet address; naming one would be
        // the same kind of invention this whole function exists to stop.
        (e.handler > 1 ? `; termination handler at ${va(e.handler)}` : "")
      : `.pdata: __except region ${va(e.begin)} - ${va(e.end)}; __except body at ${va(e.jumpTarget)}`,
  });

  const excepts = table.filter((e) => !isFinally(e));
  const regions = table.map(region);

  // A record with no `__except` entry is a `__finally`-only record, which is
  // most of them. There is nothing here the emitter can spell, so the regions
  // are recorded ahead of the body and the body is returned unwrapped.
  if (excepts.length === 0) return [...regions, ...body];

  // Claim 2. The wrap is still the whole body, because placing an extent onto
  // statements is a different piece of work (the region need not be a
  // contiguous run of top-level statements, and every entry here is strictly
  // narrower than the function). What changes is that the braces no longer
  // IMPLY the extent: the regions above name it and the line below says the
  // braces are not it.
  const admission: IRStmt = {
    kind: "comment",
    text: "extent not placed onto statements: these braces are the whole function, not the region(s) above",
  };

  // Claim 3. The first `__except` entry supplies the filter; the table is in
  // address order (`readScopeTable` check 3) and no record in this corpus has
  // more than one. Where a record did have two, one `__try` cannot represent
  // both — which is why every entry is named in `regions` above rather than
  // only the one driving the wrap.
  const chosen = excepts[0];
  const tryStmt: IRTry = {
    kind: "try",
    body: [...regions, admission, ...body],
    handler: [
      {
        kind: "comment",
        text: `__except body at ${va(chosen.jumpTarget)}; not placed onto statements`,
      },
    ],
    filterSource:
      chosen.handler === 1
        ? { spelling: "execute-handler" }
        : {
            spelling: "unrecovered",
            filterAddress: chosen.handler > 1 ? chosen.handler + imageBase : undefined,
          },
  };

  return [tryStmt];
}

/** The note a label gets when `buildCFG` found no edge into its block. */
export const LABEL_NOTE_NO_PREDECESSOR = "no predecessor in the recovered CFG";
/** The note a label gets when the image's scope table names its address. */
export const LABEL_NOTE_UNWINDER = "entered by the unwinder (.pdata scope table)";

/**
 * Every VA the selected `.pdata` record's scope table says the unwinder can
 * transfer control to inside this function: an `__except` body (`jumpTarget`)
 * and any funclet a `handler` field names. x64 only, because `.pdata` is; the
 * 32-bit SEH scope table (`seh32.ts`) is not read here yet — that plumbing is
 * epic 3's — so on x86 this set is empty and no label claims the unwinder.
 *
 * Reads the record `funcExceptionRecord` selects and nothing else: the same
 * idempotent selection `wrapExceptionRegions` applies, deliberately not moved
 * into it (see that function's docstring for why the selector stays a leaf).
 * A record with no validated scope table contributes nothing — an unreadable
 * table is not a table with no entries.
 */
function unwinderEntryVAs(func: DisasmFunction, runtimeFunctions: RuntimeFunction[]): Set<number> {
  const out = new Set<number>();
  const rf = funcExceptionRecord(func, runtimeFunctions);
  if (!rf?.scopeTable) return out;
  const imageBase = func.address - rf.beginAddress;
  for (const e of rf.scopeTable) {
    if (e.jumpTarget !== 0) out.add(e.jumpTarget + imageBase);
    // 0 and 1 are the format's own flag values, never addresses.
    if (e.handler > 1) out.add(e.handler + imageBase);
  }
  return out;
}

/**
 * Give every label no `goto` in the tree names a note saying why it is there —
 * where the CFG can vouch for one.
 *
 * WHY THIS IS SPELLING AND NOT A REWRITE. A label no `goto` names is exactly the
 * one `structs.ts`'s `baseGenerations` resets every key at, and that asymmetry
 * is its whole soundness argument (docs/decompiler-ir.md); deleting such a
 * label from the IR is a fabrication hazard. So the label statement stays, its
 * name stays, and the note rides on `IRLabel.note`, which nothing but the
 * emitter reads. The emitter prints it on the line after the label, so the
 * `^\s*(loc_[0-9A-F]+):$` scrapes in `corpus/` see exactly what they saw.
 *
 * WHICH LABELS. "No `goto` names it" is the population `pruneLabels` kept on
 * another ground — but it is NOT the population the note is true of. About a
 * third of these labels are the targets of a `goto` a later pass rewrote:
 * `breakForwardGotos` turned it into `break`, `cleanupPass` folded `goto L; L:`
 * or an arm's trailing `goto L` — and every one of those has a predecessor,
 * the fall-through or the loop. Saying "no predecessor" there would be false.
 * So the note is decided from `buildCFG`'s own edges: a block with no `preds`
 * really is entered by nothing the CFG recovered (an unwinder continuation, or
 * a region only a jump the disassembly missed reaches), and a label whose block
 * has predecessors gets no note at all. The entry block is excluded: it has no
 * predecessor and is entered by `call`.
 *
 * WHICH TEXT. "Entered by the unwinder" is a CLAIM about the machine and is
 * made only where the image says so — the label's address is a scope-table
 * `jumpTarget` or funclet in the record `funcExceptionRecord` selected
 * (x64; see `unwinderEntryVAs`). Everything else gets the fact about the CFG,
 * which is all that is known (peek-a-bin-5b6q.6).
 */
function annotateLabels(
  body: IRStmt[],
  blocks: BasicBlock[],
  entryAddr: number,
  unwinderVAs: Set<number>,
): IRStmt[] {
  const targets = new Set<string>();
  const collect = (list: IRStmt[]): void => {
    for (const s of list) {
      if (s.kind === "goto") targets.add(s.label);
      for (const nested of bodiesOf(s)) collect(nested);
    }
  };
  collect(body);

  const blockByAddr = new Map(blocks.map((b) => [b.startAddr, b]));
  const noteFor = (name: string): string | undefined => {
    if (targets.has(name)) return undefined;
    const addr = labelAddrFor(name);
    if (addr === null || addr === entryAddr) return undefined;
    if (unwinderVAs.has(addr)) return LABEL_NOTE_UNWINDER;
    const block = blockByAddr.get(addr);
    if (block && block.preds.length === 0) return LABEL_NOTE_NO_PREDECESSOR;
    return undefined;
  };

  const rewrite = (list: IRStmt[]): IRStmt[] =>
    list.map((s) => {
      if (s.kind === "label") {
        const note = noteFor(s.name);
        return note ? { ...s, note } : s;
      }
      return rewriteBodies(s, rewrite);
    });
  return rewrite(body);
}
