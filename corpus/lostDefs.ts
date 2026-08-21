/**
 * A READ WHOSE DEFINITION `foldBlock` DELETED ON ITS WAY OUT OF THE BLOCK.
 *
 * `foldBlock` inlines a register definition that is read exactly **once** into
 * that one reader and drops the assignment. It is handed one block's statement
 * list, so "once" is a statement about that block and nothing else: a
 * definition read once locally and again in a successor was inlined into the
 * local reader and deleted, and every read after the block was left naming a
 * register the emitted function never assigns. `t32!sub_40D99A` is the witness
 * on file — `mov ecx, [ebp+8]` with one in-block reader and eleven reads over
 * the three blocks below it, emitted as C whose only `ecx` on the left of an
 * `=` was an `ecx = ecx;` from an unrelated `lea ecx,[ecx]` NOP
 * (peek-a-bin-7eyn).
 *
 * WHAT IS COUNTED, and why it is not the crude scan. A register read that no
 * definition reaches is *usually correct output*: it is the function's entry
 * value, which is exactly what a parameter in a register looks like, and
 * CLAUDE.md's read-but-never-assigned scan is an upper bound for that reason.
 * The discriminator here is a **before and after**: this brackets the fold and
 * reports only reads that HAD a reaching definition in the unfolded program and
 * have none in the folded one. An entry value has none on either side and never
 * enters the count; a definition the fold removed while a successor still needed
 * it registers, and there is no other way for a read to change class across this
 * one pass.
 *
 * WHY IT IS A GATE. Every row is a provably wrong name — a store through a
 * pointer nothing computed, a call given an argument nothing produced — which is
 * `polarity inverted`'s character rather than a baseline's, and it is zero on all
 * four binaries. It was **544 reads over 172 functions** before the refusal
 * landed (168/110/110/156 on t32/t64/w64/w32 at `91085f3`), so the instrument is
 * negative-controllable: revert `pipeline.ts`'s `blockLiveOut` argument and the
 * same rows come back.
 *
 * WHAT IT DOES NOT SEE. It brackets `foldBlock` and only `foldBlock`. A
 * definition some *other* pass deletes, or a read that never had a reaching
 * definition and never should have named a register at all, is outside it — the
 * general question "does every name in the emitted C denote something the
 * function produces" is not answered here, and neither `gcc -fsyntax-only`
 * (`preludeFor` declares each undeclared identifier as its own `long`) nor any
 * other audit in this directory answers it either.
 *
 * INDEPENDENCE, stated honestly. `fold.ts` decides what to keep from *liveness*;
 * this decides what went missing from *reaching definitions*. They are dual
 * analyses rather than one shared routine, and both counts are read off the
 * statement lists the pipeline actually produces — but this is a regression gate
 * on one pass, not an oracle standing outside the question.
 */

import type { CalleeClobbers } from "../src/disasm/callSummary";
import { buildCFG } from "../src/disasm/cfg";
import { solePredecessor } from "../src/disasm/decompile/flagModel";
import { blockLiveOut, foldBlock } from "../src/disasm/decompile/fold";
import type { IRExpr, IRReg, IRStmt } from "../src/disasm/decompile/ir";
import { canonReg } from "../src/disasm/decompile/ir";
import {
  firstCalleeSavedWrites,
  liftBlock,
  liftCrossBlockPops,
  matchedStackSlots,
} from "../src/disasm/decompile/lifter";
import { RegState } from "../src/disasm/decompile/regstate";
import { buildSSA, detectNaturalLoops } from "../src/disasm/decompile/ssa";
import { destroySSA } from "../src/disasm/decompile/ssadestroy";
import { ssaOptimize } from "../src/disasm/decompile/ssaopt";
import type { DisasmFunction, Instruction, Xref } from "../src/disasm/types";

/** One (block, register) whose reaching definition the fold removed. */
export interface LostDefRec {
  bin: string;
  func: string;
  funcAddr: number;
  block: number;
  /** Canonical register name — the identity SSA and `foldBlock` both key on. */
  canon: string;
  /** How many reads of it in that block are left unbacked. */
  reads: number;
  /** The first such read's instruction address, where the statement carries one. */
  addr: number | undefined;
}

export interface LostDefResult {
  /** Functions the replica got through. Instrument liveness. */
  functionsScanned: number;
  /** Register reads examined in the folded program. Instrument liveness. */
  regReads: number;
  /**
   * Reads with no reaching definition on BOTH sides of the fold. These are the
   * entry values — correct output, and the population CLAUDE.md's crude scan
   * cannot separate from a defect. Reported for scale, never gated.
   */
  entryReads: number;
  /** Reads whose reaching definition the fold deleted. GATE at 0. */
  lostReads: number;
  /** (block, register) pairs behind those reads. */
  lostSites: number;
  funcsAffected: number;
  rows: LostDefRec[];
}

export function emptyLostDefs(): LostDefResult {
  return {
    functionsScanned: 0,
    regReads: 0,
    entryReads: 0,
    lostReads: 0,
    lostSites: 0,
    funcsAffected: 0,
    rows: [],
  };
}

// ── Reading the IR, written out here rather than imported ──────────────────
//
// Same reasoning as `staleReads.ts` and `popReads.ts`: borrowing `fold.ts`'s own
// notion of a read would make the audit and the code under test share a blind
// spot, and this audit's whole subject is a decision `fold.ts` takes. The
// `default:` arms can only make it see fewer reads, never invent one.

function regsIn(e: IRExpr, out: IRReg[]): void {
  switch (e.kind) {
    case "reg":
      out.push(e);
      return;
    case "binary":
      regsIn(e.left, out);
      regsIn(e.right, out);
      return;
    case "unary":
    case "cast":
      regsIn(e.operand, out);
      return;
    case "deref":
      regsIn(e.address, out);
      return;
    case "call":
      for (const a of e.args) regsIn(a, out);
      return;
    case "ternary":
      regsIn(e.condition, out);
      regsIn(e.then, out);
      regsIn(e.else, out);
      return;
    case "field_access":
      regsIn(e.base, out);
      return;
    case "array_access":
      regsIn(e.base, out);
      regsIn(e.index, out);
      return;
    default:
      return;
  }
}

function readsOf(stmt: IRStmt): IRReg[] {
  const out: IRReg[] = [];
  switch (stmt.kind) {
    case "assign":
      // A `deref` destination is an address computation, so its registers are
      // read even though the statement is a write.
      if (stmt.dest.kind === "deref") regsIn(stmt.dest, out);
      regsIn(stmt.src, out);
      break;
    case "store":
      regsIn(stmt.address, out);
      regsIn(stmt.value, out);
      break;
    case "call_stmt":
      for (const a of stmt.call.args) regsIn(a, out);
      break;
    case "return":
      if (stmt.value) regsIn(stmt.value, out);
      break;
    // A guard's registers are reads like any other. `pipeline.ts` extracts the
    // branches after this stage, and their conditions reach the page.
    case "branch":
      regsIn(stmt.condition, out);
      break;
  }
  return out;
}

/** The canonical register this statement defines, if any. */
function defOf(stmt: IRStmt): string | null {
  const dest =
    stmt.kind === "assign" ? stmt.dest : stmt.kind === "call_stmt" ? stmt.resultDest : undefined;
  if (dest?.kind !== "reg") return null;
  return canonReg(dest.name);
}

/** How the audit describes one read: which block, and whether anything defines it. */
interface Unbacked {
  /** `blockId:canon` → number of unbacked reads. */
  reads: Map<string, number>;
  /** `blockId:canon` → the first unbacked read's address. */
  where: Map<string, number | undefined>;
  /** Every register read seen, backed or not. */
  total: number;
}

/**
 * Reads no definition reaches, keyed by (block, canonical register).
 *
 * Forward *may*-reach: a definition anywhere on any path from the entry counts,
 * which is the weaker of the two readings and therefore the one that reports
 * fewer rows. A read this calls unbacked has no definition on ANY path, so the
 * name it prints is one nothing in the function ever assigns.
 */
function unbackedReads(
  blocks: readonly { id: number; preds: readonly number[] }[],
  stmts: ReadonlyMap<number, IRStmt[]>,
): Unbacked {
  const known = new Set(blocks.map((b) => b.id));
  const defs = new Map<number, Set<string>>();
  for (const b of blocks) {
    const d = new Set<string>();
    for (const s of stmts.get(b.id) ?? []) {
      const x = defOf(s);
      if (x) d.add(x);
    }
    defs.set(b.id, d);
  }
  // `reachOut` is what leaves the block; `reachIn` what arrives.
  const reachIn = new Map<number, Set<string>>();
  const reachOut = new Map<number, Set<string>>();
  for (const b of blocks) {
    reachIn.set(b.id, new Set());
    reachOut.set(b.id, new Set(defs.get(b.id) as Set<string>));
  }
  for (let pass = 0; pass <= blocks.length + 1; pass++) {
    let changed = false;
    for (const b of blocks) {
      const inSet = reachIn.get(b.id) as Set<string>;
      for (const p of b.preds) {
        if (!known.has(p)) continue;
        for (const r of reachOut.get(p) as Set<string>) {
          if (!inSet.has(r)) {
            inSet.add(r);
            changed = true;
          }
        }
      }
      const out = reachOut.get(b.id) as Set<string>;
      for (const r of inSet) {
        if (!out.has(r)) {
          out.add(r);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }

  const reads = new Map<string, number>();
  const where = new Map<string, number | undefined>();
  let total = 0;
  for (const b of blocks) {
    const live = new Set(reachIn.get(b.id) as Set<string>);
    for (const s of stmts.get(b.id) ?? []) {
      for (const r of readsOf(s)) {
        total++;
        const canon = canonReg(r.name);
        if (live.has(canon)) continue;
        const key = `${b.id}:${canon}`;
        reads.set(key, (reads.get(key) ?? 0) + 1);
        if (!where.has(key)) where.set(key, (s as { addr?: number }).addr);
      }
      const d = defOf(s);
      if (d) live.add(d);
    }
  }
  return { reads, where, total };
}

/**
 * One function's worth of the audit, over a replica of `pipeline.ts` stages 1-3
 * plus the fold.
 *
 * The replica exists because neither side is recoverable from
 * `decompileFunction`'s return value: the question is about the statement lists
 * on the two sides of ONE pass, and the emitted C is downstream of both. Every
 * stage it calls is the repo's own export in the order `pipeline.ts` calls them,
 * including the `blockLiveOut` argument — passing the fold a different argument
 * from production's would measure a different program.
 */
export function auditLostDefs(
  res: LostDefResult,
  bin: string,
  func: DisasmFunction,
  insns: Instruction[],
  xrefMap: Map<number, Xref[]>,
  jumpTables: Map<number, number[]>,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  stringMap: Map<number, string>,
  funcMap: Map<number, { name: string; address: number }>,
  calleeClobbers: CalleeClobbers | undefined,
): void {
  let blocks: ReturnType<typeof buildCFG>;
  let before: Unbacked;
  let after: Unbacked;
  try {
    blocks = buildCFG(func, insns, xrefMap, jumpTables);
    if (blocks.length === 0) return;
    const lifted = new Map<number, IRStmt[]>();
    const calleeSavedFirstWrite = is64 ? undefined : firstCalleeSavedWrites(blocks);
    // `pipeline.ts`'s third function-wide fact: which `push <reg>` a `pop <reg>`
    // takes its value from (peek-a-bin-6f3v). A replica missing it measures a
    // program the emitter never sees, and fails in the QUIET direction.
    const stackSlots = matchedStackSlots(blocks, is64);
    const blockById = new Map(blocks.map((b) => [b.id, b]));
    for (const b of blocks)
      lifted.set(
        b.id,
        liftBlock(
          b,
          new RegState(),
          is64,
          iatMap,
          stringMap,
          funcMap,
          calleeSavedFirstWrite,
          calleeClobbers,
          solePredecessor(b, blockById),
          stackSlots,
        ),
      );
    // `pipeline.ts` step 2b (peek-a-bin-6ilz).
    liftCrossBlockPops(blocks, lifted);
    const ctx = buildSSA(blocks, lifted);
    const natural = detectNaturalLoops(blocks, ctx.idom, ctx.domTree);
    ssaOptimize(ctx, natural.size > 0 ? natural : undefined);
    destroySSA(ctx);
    before = unbackedReads(ctx.blocks, ctx.liftedBlocks);
    const liveOut = blockLiveOut(ctx.blocks, ctx.liftedBlocks);
    const folded = new Map<number, IRStmt[]>();
    for (const b of ctx.blocks)
      folded.set(b.id, foldBlock(ctx.liftedBlocks.get(b.id) ?? [], liveOut.get(b.id)));
    after = unbackedReads(ctx.blocks, folded);
  } catch {
    // Same reading as `sweep.ts`: a function the pipeline cannot get through is
    // counted by the throw gate, not here.
    return;
  }
  res.functionsScanned++;
  res.regReads += after.total;

  let affected = false;
  for (const [key, n] of after.reads) {
    // Per (block, register) counts rather than a set membership test: a pair
    // already unbacked before the fold contributes its own reads to
    // `entryReads`, and only a RISE is attributable to the fold.
    const had = before.reads.get(key) ?? 0;
    res.entryReads += Math.min(n, had);
    if (n <= had) continue;
    affected = true;
    res.lostSites++;
    res.lostReads += n - had;
    const [blockId, canon] = key.split(":");
    res.rows.push({
      bin,
      func: func.name,
      funcAddr: func.address,
      block: Number(blockId),
      canon,
      reads: n - had,
      addr: after.where.get(key),
    });
  }
  if (affected) res.funcsAffected++;
}
