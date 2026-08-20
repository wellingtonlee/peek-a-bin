/**
 * A REGISTER NAMED IN THE EMITTED C THAT NO LONGER HOLDS THE VALUE THE SSA SAID.
 *
 * SSA version 0 is a register's *entry* value — `newVersion` in `ssa.ts` starts
 * handing out definitions at 1, so version 0 is the one thing in the function no
 * statement defines. A surviving read of it is the decompiler saying "the value
 * this register was given on the way in". If a block that **strictly dominates**
 * the read has since written that register, the bare register name in the output
 * denotes something else, and the C is ordinary-looking and wrong: a store
 * through the wrong pointer, a call passed the wrong argument, a `return` of the
 * wrong value. It compiles clean, which is exactly why nothing caught it
 * (`peek-a-bin-dqpk`).
 *
 * TWO COUNTS, and the second is the nastier one:
 *
 *   `wrong`             — the read emitted as a bare register that a dominating
 *                         write has already changed. Visibly a register name, so
 *                         a reader at least has the disassembly to check against.
 *   `copiesCorrupted`   — the *repair* spoiled. `destroySSA` preserves version 0
 *                         by taking a copy `rcx_0 = rcx`; taken at the top of the
 *                         reading block, past a dominating write, the copy
 *                         captures the wrong value and every use of `rcx_0`
 *                         reads as recovered output. There is nothing on the
 *                         page to be suspicious of.
 *
 * WHY THIS IS A GATE when the statement-drop and unrecovered-value audits are
 * not: those two report a count that is not zero and for which no threshold has
 * been justified. This one is zero by construction after the fix, and every
 * non-zero row is a *provably* wrong name — the same character as the polarity
 * audit's `inverted`, which is a gate for the same reason. Instrument-liveness
 * assertions sit beside it, because a measurement of absence that quietly stops
 * observing reports the healthiest number in the report.
 *
 * INDEPENDENCE. Nothing here imports `ssadestroy.ts`'s internals or replicates
 * its decision procedure — replicating it would make the audit agree with the
 * code under test by construction. The site set is computed from the SSA the
 * optimiser leaves behind, and both counts are read off the *output*: what the
 * lowered statement list actually says, and which block actually writes the
 * register.
 */
import { buildCFG } from "../src/disasm/cfg";
import { foldBlock } from "../src/disasm/decompile/fold";
import type { IRExpr, IRReg, IRStmt } from "../src/disasm/decompile/ir";
import { canonReg, isKnownRegister, regSize } from "../src/disasm/decompile/ir";
import { firstCalleeSavedWrites, liftBlock } from "../src/disasm/decompile/lifter";
import { RegState } from "../src/disasm/decompile/regstate";
import type { SSAContext } from "../src/disasm/decompile/ssa";
import { buildSSA, clobberedByCall, detectNaturalLoops } from "../src/disasm/decompile/ssa";
import { destroySSA } from "../src/disasm/decompile/ssadestroy";
import { ssaOptimize } from "../src/disasm/decompile/ssaopt";
import type { DisasmFunction, Instruction, Xref } from "../src/disasm/types";

/** One version-0 read whose register a dominating definition has overwritten. */
export interface StaleV0Rec {
  bin: string;
  func: string;
  funcAddr: number;
  /** The instruction the read came from, when the statement carries one. */
  addr: number | undefined;
  reg: string;
  canon: string;
  block: number;
  /** The version the bare register really holds here: -1 = no single one. */
  reaching: number | null;
  /** `wrong`, `wrong-indeterminate`, `reaching-is-v0`, `benign-identity-copy`. */
  verdict: string;
  /** The blocks whose write to this register reaches the read. */
  domDefBlocks: number[];
}

/** One `reg_0 = reg` copy that a dominating write had already spoiled. */
export interface CorruptCopyRec {
  bin: string;
  func: string;
  funcAddr: number;
  block: number;
  name: string;
  canon: string;
  /** Uses of the spoiled name in the same function. */
  reads: number;
}

export interface StaleV0Result {
  /** Functions the replica got through. Instrument liveness. */
  functionsScanned: number;
  /** Every read of a version-0 register it saw. Instrument liveness. */
  v0Reads: number;
  /** Version-0 reads with a definition of the same register dominating them. */
  sites: number;
  /** Of those, the ones that survive lowering as a bare register name. */
  confirmed: number;
  /** Of those, the ones where the register provably holds another value. GATE. */
  wrong: number;
  funcsWrong: number;
  /** `reg_0 = reg` copies `destroySSA` materialised. Instrument liveness. */
  copies: number;
  /** Of those, taken where a dominating write had already changed it. GATE. */
  copiesCorrupted: number;
  readsOfCorrupted: number;
  funcsCorrupted: number;
  rows: StaleV0Rec[];
  corrupt: CorruptCopyRec[];
}

export function emptyStaleV0(): StaleV0Result {
  return {
    functionsScanned: 0,
    v0Reads: 0,
    sites: 0,
    confirmed: 0,
    wrong: 0,
    funcsWrong: 0,
    copies: 0,
    copiesCorrupted: 0,
    readsOfCorrupted: 0,
    funcsCorrupted: 0,
    rows: [],
    corrupt: [],
  };
}

// ── Reading the IR, written out here rather than imported ──────────────────
//
// `ssadestroy.ts` has its own notion of "a read"; borrowing it would make the
// audit and the code under test share a blind spot. These walkers are
// deliberately independent, and the `default:` arms are safe here because a new
// expression kind can only make the audit see fewer reads, never invent one.

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
    // A guard's registers are reads like any other, and this audit gates at
    // zero. Omitting the kind here would make the instrument blind to exactly
    // the statement the branch kind was introduced to expose — the gate would
    // keep printing 0 while a stale read sat inside a condition (peek-a-bin-c33).
    case "branch":
      regsIn(stmt.condition, out);
      break;
  }
  return out;
}

/** Every variable name the statement mentions, on either side. */
function varsIn(stmt: IRStmt, out: Set<string>): void {
  const walk = (e: IRExpr): void => {
    if (e.kind === "var") out.add(e.name);
    switch (e.kind) {
      case "binary":
        walk(e.left);
        walk(e.right);
        return;
      case "unary":
      case "cast":
        walk(e.operand);
        return;
      case "deref":
        walk(e.address);
        return;
      case "call":
        for (const a of e.args) walk(a);
        return;
      case "ternary":
        walk(e.condition);
        walk(e.then);
        walk(e.else);
        return;
      case "field_access":
        walk(e.base);
        return;
      case "array_access":
        walk(e.base);
        walk(e.index);
        return;
      default:
        return;
    }
  };
  switch (stmt.kind) {
    case "assign":
      walk(stmt.dest);
      walk(stmt.src);
      break;
    case "store":
      walk(stmt.address);
      walk(stmt.value);
      break;
    case "call_stmt":
      walk(stmt.call);
      break;
    case "return":
      if (stmt.value) walk(stmt.value);
      break;
    // Same reasoning as `readsOf`: a repair spoiled inside a guard is still a
    // spoiled repair, and this half of the audit is gated at zero too.
    case "branch":
      walk(stmt.condition);
      break;
  }
}

/** The instruction a lifted statement came from, where the kind carries one. */
function addrOf(stmt: IRStmt): number | undefined {
  return (stmt as { addr?: number }).addr;
}

/** The register this statement defines, versioned or not. */
function regDef(stmt: IRStmt): { name: string; canon: string; version: number | undefined } | null {
  const dest =
    stmt.kind === "assign" ? stmt.dest : stmt.kind === "call_stmt" ? stmt.resultDest : undefined;
  if (dest?.kind !== "reg") return null;
  return { name: dest.name, canon: canonReg(dest.name), version: dest.version };
}

/** `rcx_0` → `rcx`, but only when the prefix really is a register. */
function entryCopyName(stmt: IRStmt): { name: string; canon: string } | null {
  if (stmt.kind !== "assign" || stmt.dest.kind !== "var") return null;
  const m = /^([a-z][a-z0-9]*)_0$/.exec(stmt.dest.name);
  if (!m || !isKnownRegister(m[1])) return null;
  let src: IRExpr = stmt.src;
  while (src.kind === "cast") src = src.operand;
  if (src.kind !== "reg") return null;
  const canon = canonReg(m[1]);
  if (canonReg(src.name) !== canon) return null;
  return { name: stmt.dest.name, canon };
}

const NO_SINGLE_VERSION = -1;

/**
 * One function's worth of the audit, run over an instrumented replica of
 * `pipeline.ts` stages 1-3.
 *
 * The replica exists because neither side is recoverable from
 * `decompileFunction`'s return value: the site set needs the SSA *before* it is
 * lowered, and the verdict needs the statement list *after*. Every pass it calls
 * is the repo's own export, in the order `pipeline.ts` calls them, so a stage
 * inserted between `ssaOptimize` and `destroySSA` will show up here as a
 * divergence rather than being silently measured as the old program.
 */
export function auditStaleV0Reads(
  res: StaleV0Result,
  bin: string,
  func: DisasmFunction,
  insns: Instruction[],
  xrefMap: Map<number, Xref[]>,
  jumpTables: Map<number, number[]>,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  stringMap: Map<number, string>,
  funcMap: Map<number, { name: string; address: number }>,
): void {
  let ctx: SSAContext;
  try {
    const blocks = buildCFG(func, insns, xrefMap, jumpTables);
    if (blocks.length === 0) return;
    const lifted = new Map<number, IRStmt[]>();
    // Same arguments the pipeline lifts with, including the callee-saved write
    // map: this audit re-lifts in order to measure the program the pipeline
    // builds, so a divergence here would make it measure a different one.
    const calleeSavedFirstWrite = is64 ? undefined : firstCalleeSavedWrites(blocks);
    for (const b of blocks)
      lifted.set(
        b.id,
        liftBlock(b, new RegState(), is64, iatMap, stringMap, funcMap, calleeSavedFirstWrite),
      );
    ctx = buildSSA(blocks, lifted);
    const natural = detectNaturalLoops(blocks, ctx.idom, ctx.domTree);
    ssaOptimize(ctx, natural.size > 0 ? natural : undefined);
  } catch {
    // Same reading as `sweep.ts`: a function the pipeline cannot get through is
    // counted by the throw gate, not here.
    return;
  }
  res.functionsScanned++;

  const blockById = new Map(ctx.blocks.map((b) => [b.id, b]));
  const strictDom = (a: number, b: number): boolean => {
    if (a === b) return false;
    let cur = b;
    for (let steps = 0; steps <= ctx.blocks.length; steps++) {
      if (cur === a) return true;
      const parent = ctx.idom.get(cur);
      if (parent === undefined || parent === cur) return false;
      cur = parent;
    }
    return false;
  };

  // ── Which version of each register reaches each point (post-optimisation) ──
  const exitState = new Map<number, Map<string, number>>();
  for (const b of ctx.blocks) exitState.set(b.id, new Map());
  const entryState = (id: number): Map<string, number> => {
    const preds = (blockById.get(id)?.preds ?? []).filter((p) => blockById.has(p));
    const state = new Map<string, number>();
    if (preds.length === 0) return state;
    for (const [k, v] of exitState.get(preds[0]) ?? []) state.set(k, v);
    for (const p of preds.slice(1)) {
      const other = exitState.get(p) ?? new Map<string, number>();
      for (const k of [...state.keys()])
        if (other.get(k) !== state.get(k)) state.set(k, NO_SINGLE_VERSION);
      for (const k of other.keys()) if (!state.has(k)) state.set(k, NO_SINGLE_VERSION);
    }
    return state;
  };
  const applyPhis = (id: number, state: Map<string, number>): Map<string, number> => {
    for (const phi of ctx.phis.get(id) ?? [])
      if (phi.dest.version !== undefined) state.set(canonReg(phi.dest.name), phi.dest.version);
    return state;
  };
  for (let pass = 0; pass <= ctx.blocks.length + 2; pass++) {
    let changed = false;
    for (const b of ctx.blocks) {
      const state = applyPhis(b.id, entryState(b.id));
      for (const s of ctx.liftedBlocks.get(b.id) ?? []) {
        const d = regDef(s);
        if (d?.version !== undefined) state.set(d.canon, d.version);
        for (const c of clobberedByCall(s)) if (c !== d?.canon) state.set(c, NO_SINGLE_VERSION);
      }
      const prev = exitState.get(b.id) ?? new Map<string, number>();
      if (prev.size !== state.size || [...state].some(([k, v]) => prev.get(k) !== v)) {
        exitState.set(b.id, state);
        changed = true;
      }
    }
    if (!changed) break;
  }
  // The SSA statement lists as the optimiser left them. `destroySSA` and
  // `foldBlock` replace the map's arrays and build new statement objects, so
  // this stays a faithful record of the program the site set was read from.
  const pre = new Map<number, IRStmt[]>();
  for (const [id, stmts] of ctx.liftedBlocks) pre.set(id, [...stmts]);

  const reachingAt = (block: number, index: number, canon: string): number | null => {
    const state = applyPhis(block, entryState(block));
    const stmts = pre.get(block) ?? [];
    for (let i = 0; i < index; i++) {
      const d = regDef(stmts[i]);
      if (d?.version !== undefined) state.set(d.canon, d.version);
      for (const c of clobberedByCall(stmts[i]))
        if (c !== d?.canon) state.set(c, NO_SINGLE_VERSION);
    }
    return state.get(canon) ?? null;
  };

  // ── Versions that are, transitively, a copy of the register's own v0 ──
  // `rcx_2 = rcx_1 = rcx_0`: the bare name still holds the entry value, so a
  // read of version 0 emitted as the bare register is benign.
  const selfCopy = new Map<string, string>();
  for (const [, stmts] of ctx.liftedBlocks) {
    for (const s of stmts) {
      if (s.kind !== "assign") continue;
      const d = regDef(s);
      if (!d || d.version === undefined) continue;
      let src: IRExpr = s.src;
      while (src.kind === "cast") src = src.operand;
      if (src.kind === "reg" && canonReg(src.name) === d.canon && src.version !== undefined)
        selfCopy.set(`${d.canon}_${d.version}`, `${d.canon}_${src.version}`);
    }
  }
  const isEntryValue = (canon: string, version: number): boolean => {
    let cur = `${canon}_${version}`;
    for (let hop = 0; hop < 32; hop++) {
      if (cur === `${canon}_0`) return true;
      const next = selfCopy.get(cur);
      if (next === undefined) return false;
      cur = next;
    }
    return false;
  };

  // ── The sites: a version-0 read a dominating definition has overwritten ──
  const defBlocks = new Map<string, Set<number>>();
  const noteDef = (canon: string, block: number): void => {
    const seen = defBlocks.get(canon);
    if (seen) seen.add(block);
    else defBlocks.set(canon, new Set([block]));
  };
  for (const b of ctx.blocks) {
    for (const phi of ctx.phis.get(b.id) ?? []) {
      const canon = canonReg(phi.dest.name);
      // A phi is a definition in its own block *in SSA*, but the program that
      // gets judged is the lowered one, and `destroySSA` does not put the copy
      // here — it puts one at the end of each PREDECESSOR (ssadestroy.ts, "a
      // phi's copy belongs on the edge"). A predecessor routinely dominates
      // blocks the phi block does not, so attributing the definition only to
      // the phi block is sound but INCOMPLETE, and its incompleteness is
      // exactly the blocks a phi-predecessor dominates: a site whose only
      // dominating writer is a relocated phi copy was discarded before it was
      // ever judged (peek-a-bin-fppy, 12 provably wrong reads printed as 0).
      //
      // Over-approximating here is safe. This map only decides which reads are
      // *examined*; the verdict is taken against the post-lowering statement
      // list, where the `writes` check below requires a strictly dominating
      // block to actually assign the bare name.
      noteDef(canon, b.id);
      for (const op of phi.operands) noteDef(canon, op.blockId);
    }
    for (const s of ctx.liftedBlocks.get(b.id) ?? []) {
      const d = regDef(s);
      if (d) noteDef(d.canon, b.id);
    }
  }

  interface Site {
    block: number;
    index: number;
    addr: number | undefined;
    reg: string;
    canon: string;
    domDefBlocks: number[];
    /** Asked before lowering, while the versions are still there to ask about. */
    reaching: number | null;
  }
  const sites: Site[] = [];
  for (const [id, stmts] of pre) {
    for (let i = 0; i < stmts.length; i++) {
      for (const r of readsOf(stmts[i])) {
        if (r.version !== 0) continue;
        const canon = canonReg(r.name);
        // RSP has no faithful definition chain (`liftBlock` skips push/pop) and
        // the flags register is not a value anyone reads by name.
        if (canon === "rsp" || canon === "eflags") continue;
        res.v0Reads++;
        // A redefinition earlier in the same block is a shape `destroySSA` has
        // always repaired soundly, and it is not what this audit is about.
        if (stmts.slice(0, i).some((s) => regDef(s)?.canon === canon)) continue;
        const dom = [...(defBlocks.get(canon) ?? [])].filter((b) => strictDom(b, id));
        if (dom.length === 0) continue;
        sites.push({
          block: id,
          index: i,
          addr: addrOf(stmts[i]),
          reg: r.name,
          canon,
          domDefBlocks: dom,
          reaching: reachingAt(id, i, canon),
        });
      }
    }
  }

  // ── Lower it, and read the answer off the output ──
  //
  // `foldBlock` runs too, because `pipeline.ts` runs it next and it is what
  // decides whether the read and the dominating write reach the page at all:
  // a single-use register assignment folds into its use and stops being a
  // visible write. Stopping at `destroySSA` measures a program nobody emits,
  // and on this corpus it doubles the count (151 against 78 on t64).
  try {
    destroySSA(ctx);
    for (const [id, stmts] of ctx.liftedBlocks) ctx.liftedBlocks.set(id, foldBlock(stmts));
  } catch {
    return;
  }

  // Where the lowering preserved an entry value, and under what name. A read
  // spelled as one of these is the repaired read, not the stale one — a single
  // instruction can hold both (`lea r9, [rdx + rsi + 0x1d]` reads the entry RDX
  // through RSI and the current RDX through RDX), so "some bare read of this
  // register survives at this address" is not on its own evidence of anything.
  //
  // This is the one place the audit has to know how `ssadestroy.ts` spells a
  // preserved value: the `_0` suffix is the only channel between them. The
  // structure is checked too — the name must be assigned a copy of that same
  // register — and `copies` is asserted non-zero, so a spelling change shows up
  // as a dead instrument rather than as a clean report.
  const preserved = new Map<string, string>();
  for (const [, stmts] of ctx.liftedBlocks) {
    for (const st of stmts) {
      const copy = entryCopyName(st);
      if (copy) preserved.set(copy.name, copy.canon);
    }
  }

  let wrongHere = 0;
  for (const s of sites) {
    res.sites++;
    // The read: a bare, version-stripped read of the same register at the same
    // instruction address, with no preserved entry value of that register named
    // at the same address.
    let survives = false;
    let repaired = false;
    /** How the surviving reads at this address actually spell the register. */
    const readNames = new Set<string>();
    for (const [, stmts] of ctx.liftedBlocks)
      for (const st of stmts) {
        if (addrOf(st) !== s.addr) continue;
        for (const r of readsOf(st))
          if (r.version === undefined && canonReg(r.name) === s.canon) {
            survives = true;
            readNames.add(r.name.toLowerCase());
          }
        const names = new Set<string>();
        varsIn(st, names);
        for (const n of names) if (preserved.get(n) === s.canon) repaired = true;
      }
    if (repaired) continue;
    // ── The write: a strictly dominating block assigns the name the read uses ──
    //
    // THE NAME, NOT THE CANONICAL REGISTER, and the distinction is the whole of
    // `peek-a-bin-pzws`. What this audit judges is the emitted C, and C's unit
    // of identity is the identifier: `r9` and `r9d` are two unrelated variables
    // there — that is precisely why `gcc -fsyntax-only` cannot see this defect
    // class, and it cuts both ways. A register carrying a 64-bit range and a
    // 32-bit range at once is correctly emitted as two names (`ssadestroy.ts`,
    // "widest-in-the-function is the wrong scope"), and against a canonical
    // test that correct output reads as a clobber that never happens: the
    // dominating statement says `r9d = …` and the read says `r9`, so nothing
    // the reader sees has changed. Asking about the canonical register makes
    // the gate permanently red on the output it exists to certify.
    //
    // NOT A NARROWING, and it was checked rather than argued: with the naming
    // fix reverted and this test in place the same twelve rows come back, one
    // per store, because the copy is then spelled `r9` — the same identifier
    // the stores read. What the name test removes is the false positive, not
    // the finding.
    //
    // One emit rule has to be honoured here or the test *would* narrow.
    // `emit.ts`'s `registerText` re-ties a read of width <= 2 to a wider
    // assigned alias, so for those the emitted identifier is the wider name and
    // a dominating write of any wider alias is a real clobber of what the
    // reader sees.
    let writes = false;
    const clobbers = (name: string): boolean => {
      const lower = name.toLowerCase();
      if (readNames.has(lower)) return true;
      const width = regSize(lower);
      for (const r of readNames) if (regSize(r) <= 2 && width > regSize(r)) return true;
      return false;
    };
    for (const [id, stmts] of ctx.liftedBlocks) {
      if (!strictDom(id, s.block)) continue;
      for (const st of stmts) {
        const d = regDef(st);
        if (d && d.version === undefined && d.canon === s.canon && clobbers(d.name)) writes = true;
      }
    }
    if (!(survives && writes)) continue;
    res.confirmed++;
    const reaching = s.reaching;
    // The SSA read denotes version 0 however it came to say so, since every pass
    // that rewrote it is value-preserving in SSA. So the emitted name is wrong
    // unless the value reaching it still IS the entry value.
    const verdict =
      reaching === 0
        ? "reaching-is-v0"
        : reaching === NO_SINGLE_VERSION
          ? "wrong-indeterminate"
          : reaching !== null && isEntryValue(s.canon, reaching)
            ? "benign-identity-copy"
            : "wrong";
    if (!verdict.startsWith("wrong")) continue;
    res.wrong++;
    wrongHere++;
    if (res.rows.length < 400)
      res.rows.push({
        bin,
        func: func.name,
        funcAddr: func.address,
        addr: s.addr,
        reg: s.reg,
        canon: s.canon,
        block: s.block,
        reaching,
        verdict,
        domDefBlocks: s.domDefBlocks,
      });
  }
  if (wrongHere > 0) res.funcsWrong++;

  // ── The repairs, and whether one was already spoiled when it was taken ──
  let corruptHere = 0;
  /** Names already charged for their reads, so one name is not counted twice. */
  const chargedReads = new Set<string>();
  for (const [id, stmts] of ctx.liftedBlocks) {
    for (let i = 0; i < stmts.length; i++) {
      const copy = entryCopyName(stmts[i]);
      if (!copy) continue;
      res.copies++;
      // Spoiled iff a write to the register reaches this copy on every path:
      // a strictly dominating block, or an earlier statement in this same block.
      const earlier = stmts.slice(0, i).some((s) => regDef(s)?.canon === copy.canon);
      const dominated = [...(defBlocks.get(copy.canon) ?? [])].some((b) => strictDom(b, id));
      if (!earlier && !dominated) continue;
      let reads = 0;
      if (!chargedReads.has(copy.name)) {
        chargedReads.add(copy.name);
        for (const [, ss] of ctx.liftedBlocks)
          for (const st of ss) {
            if (entryCopyName(st)?.name === copy.name) continue;
            const names = new Set<string>();
            varsIn(st, names);
            if (names.has(copy.name)) reads++;
          }
      }
      res.copiesCorrupted++;
      res.readsOfCorrupted += reads;
      corruptHere++;
      if (res.corrupt.length < 400)
        res.corrupt.push({
          bin,
          func: func.name,
          funcAddr: func.address,
          block: id,
          name: copy.name,
          canon: copy.canon,
          reads,
        });
    }
  }
  if (corruptHere > 0) res.funcsCorrupted++;
}
