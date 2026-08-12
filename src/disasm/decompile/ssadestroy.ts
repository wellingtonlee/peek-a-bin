import type { IRExpr, IRReg, IRStmt } from "./ir";
import { canonReg, isKnownRegister, regAtSize, regSize, walkStmts } from "./ir";
import type { SSAContext } from "./ssa";
import { clobberedByCall, clobberedName, versionKey as ssaVersionKey } from "./ssa";

/**
 * Destroy SSA form: convert phi nodes to copy assignments at predecessors,
 * strip all version numbers from registers.
 */
export function destroySSA(ctx: SSAContext): void {
  // Before anything rewrites a read: this reads the register *names* the
  // function's own statements use, and `nameClobberedReads` replaces some of
  // them with variables.
  const spell = registerSpeller(ctx);

  nameClobberedReads(ctx, spell);

  // Before the phis go: they are definitions, and the splitter has to see them
  // as such. Converting them to copies first would leave a phi destination
  // version with no definition anywhere, because the copies are written against
  // the *unversioned* register name.
  const phiRepairs = splitStaleReads(ctx, spell);

  // Insert copies for phi operands at end of predecessor blocks
  for (const [, blockPhis] of ctx.phis) {
    for (const phi of blockPhis) {
      const destCanon = canonReg(phi.dest.name);
      for (const op of phi.operands) {
        const srcCanon = canonReg(op.value.name);
        const predStmts = ctx.liftedBlocks.get(op.blockId);
        if (!predStmts) continue;

        // The operand names a version the predecessor's register no longer
        // holds, and `splitStaleReads` has parked that version in a variable at
        // its own definition. Copy from the variable, not from the register.
        const repair =
          op.value.version === undefined
            ? undefined
            : phiRepairs.get(`${op.blockId}|${versionKey(srcCanon, op.value.version)}`);

        // An operand carrying a version a *call* handed out is the one case
        // where a same-register copy is not a no-op: the value arriving on this
        // edge is whatever the call left behind, and letting the copy be skipped
        // would leave C's `rcx` holding the pre-call value on this path.
        const clobber =
          op.value.version !== undefined &&
          ctx.clobbered.has(ssaVersionKey(srcCanon, op.value.version));

        // Skip self-copies. Versions are stripped a few lines below, so a copy
        // between two versions of the *same* canonical register emits literally
        // `rax = rax` — a no-op that only adds a line. (Reserving version 0 for
        // the entry value made these common: `rax_2 = phi(rax_0, rax_1)` at a
        // join whose other arm leaves rax alone is exactly this shape.)
        //
        // A repaired operand is never a self-copy even when the names match:
        // `rax = rax` is a no-op precisely *because* the register still holds
        // the version, which is the one thing staleness rules out. There the
        // copy has to run, reading the variable.
        if (destCanon === srcCanon && !clobber && !repair) continue;

        // Canonical is the *identity* of the register, not its spelling: a phi
        // is created and renamed under the 64-bit parent whatever the code
        // said, so emitting that name puts `rdi = rax` inside a 32-bit function
        // (peek-a-bin-1k4). `spell` gives it back the name the function uses.
        const destName = spell(destCanon);
        const srcName = spell(srcCanon);
        const copy: IRStmt = {
          kind: "assign",
          dest: { kind: "reg", name: destName, size: regSize(destName) },
          src: repair
            ? { kind: "var", name: repair, size: op.value.size }
            : clobber
              ? {
                  kind: "var",
                  name: clobberedName(srcName, op.value.version as number),
                  size: op.value.size,
                }
              : { kind: "reg", name: srcName, size: regSize(srcName) },
        };
        predStmts.push(copy);
      }
    }
  }

  ctx.phis.clear();

  // Strip version numbers from all registers
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    ctx.liftedBlocks.set(blockId, stmts.map(stripVersionsStmt));
  }
}

// ── Register spelling ──

/** `ah` names the *other* half of AX from `al`, so it is the worse of the two. */
const HIGH_BYTE = /^[abcd]h$/;

/**
 * What this function calls a canonical register.
 *
 * `canonReg` is the identity of a register — the 64-bit parent — and every pass
 * keys on it, but nothing about it is a *name*: `insertPhis` builds every phi
 * from `collectDefs`, which canonicalises, and `renameVariables` then forces the
 * destination back to the canonical name. So a phi in a 32-bit function is a phi
 * over `rdi` at size 8 even though the image has no RDI and every statement in
 * it says `edi`, and lowering that phi to a copy emitted `rdi = rax` — 77 of
 * t32.exe's 293 functions named a register their disassembly never mentions
 * (peek-a-bin-1k4). The same canonical name reached `clobberedName`, which is
 * where a 32-bit image got `rdx = clobbered_rdx_2` (peek-a-bin-4hg).
 *
 * The width cannot be recovered from the phi: `phi.dest.size` is `regSize` of
 * the canonical name, i.e. 8, for every phi in every 32-bit function measured —
 * so a `canonReg` inverse taking a width has nothing to invert. What does carry
 * the width is the code: the widest spelling of the register the function's own
 * statements contain. A 32-bit function cannot mention RDI, so it can never be
 * chosen; a 64-bit one that only ever writes EDI is a function where writing EDI
 * is what the machine does, and naming it is not a loss.
 *
 * A register no *surviving* statement mentions still has to be spelled: the phi
 * was placed against the pre-optimisation IR and `ssaOptimize` can delete the
 * definition that put it there (t32!sub_4054E0's ESI reaches the emitted code
 * only through a branch condition, which `structure.ts` builds from `RegState`
 * and not from a statement). For those the function's own width decides — a
 * function that mentions no 8-byte register is 32-bit code, because no 32-bit
 * image can name RSI and every other spelling would have been seen above.
 */
function registerSpeller(ctx: SSAContext): (canon: string) => string {
  const widest = new Map<string, string>();
  const rank = (name: string) => regSize(name) * 2 - (HIGH_BYTE.test(name) ? 1 : 0);
  const note = (raw: string) => {
    const name = raw.toLowerCase();
    // `regSize` answers 4 for anything at all, so it is not a membership test.
    if (!isKnownRegister(name)) return;
    const canon = canonReg(name);
    const cur = widest.get(canon);
    if (cur === undefined || rank(name) > rank(cur)) widest.set(canon, name);
  };
  for (const [, stmts] of ctx.liftedBlocks) {
    walkStmts(stmts, (e) => {
      if (e.kind === "reg") note(e.name);
    });
    // `walkStmts` walks a call's arguments but not the register its result
    // lands in, and in a 32-bit function that register — EAX — is often the
    // only mention of RAX above the phis.
    for (const s of stmts)
      if (s.kind === "call_stmt" && s.resultDest?.kind === "reg") note(s.resultDest.name);
  }
  // Only rax..r15 are 8 bytes wide; XMM and x87 are wider still and exist in
  // both modes, so they say nothing about which one this is.
  const is64 = [...widest.values()].some((n) => regSize(n) === 8);
  return (canon) => widest.get(canon) ?? (is64 ? canon : regAtSize(canon, 4));
}

// ── Call clobbers ──

/**
 * Give every read of a call-clobbered version a name of its own.
 *
 * `renameVariables` hands each volatile register a fresh version at every call
 * (`SSAContext.clobbered`), so a read after a call already binds to that version
 * rather than to the definition the call destroyed. Stripping the version would
 * undo it: the read becomes a bare `rcx`, and C's `rcx` still holds whatever the
 * last `rcx = …` line assigned — which is precisely the pre-call value. So the
 * read becomes a variable that nothing assigns, which is what the machine says:
 * an indeterminate value, the same one at every read of that version.
 */
function nameClobberedReads(ctx: SSAContext, spell: (canon: string) => string): void {
  if (ctx.clobbered.size === 0) return;
  for (const [blockId, stmts] of ctx.liftedBlocks) {
    ctx.liftedBlocks.set(
      blockId,
      stmts.map((s) =>
        mapReads(s, (reg) => {
          if (reg.version === undefined) return null;
          const canon = canonReg(reg.name);
          if (!ctx.clobbered.has(ssaVersionKey(canon, reg.version))) return null;
          // Named from the canonical register, not from this read's own
          // spelling: two reads of the same clobbered version at different
          // widths are the same indeterminate value and must not get two names.
          return { kind: "var", name: clobberedName(spell(canon), reg.version), size: reg.size };
        }),
      ),
    );
  }
}

// ── Live-range splitting ──

/**
 * Give a value its own name wherever dropping the version number would hand the
 * read a different value.
 *
 * Stripping versions is only sound while at most one version of a register is
 * live at a time, and the optimiser breaks that: GVN replaces `r8_1` with an
 * earlier `rcx_1` holding the same value, copy propagation forwards a source
 * across a later write to it. Both are fine in SSA — the versions say which
 * value is meant — and both become wrong the moment the versions come off,
 * because the register has since been written. A real call in t64.exe went from
 * `f(rax + 0x60, "…", rsp + 0x30)` to `f(rcx, "…", rcx)` this way: same name,
 * two different values, one of them silently wrong.
 *
 * Which version a read *should* get is a reaching-definitions question, so it is
 * asked as one: a forward fixpoint over the CFG carrying, per canonical
 * register, the version that reaches each point, with disagreeing predecessors
 * meeting to "no single version". A read of version V where V is not what
 * reaches it is stale. Absent from the map means the register still holds its
 * entry value, which is version 0 — see `newVersion` in `ssa.ts`.
 *
 * The repair is a copy taken at V's own definition, not at the read: that is the
 * one program point where the register is known to hold V. It is only sound if
 * the definition runs before every read it is repairing, so the copy is inserted
 * only when the defining block dominates the reading block (or is the same block,
 * earlier). Where it does not — GVN can forward a value to a use its definition
 * does not dominate — the read is left exactly as it was rather than given a
 * name that may not have been assigned yet.
 *
 * This used to look only inside a single block, which meant it could not see the
 * case the bead was filed for and had to guess at block entry for anything
 * defined elsewhere (peek-a-bin-bld).
 */
function splitStaleReads(ctx: SSAContext, spell: (canon: string) => string): Map<string, string> {
  /** `<predecessor block>|<version key>` → the variable holding that version. */
  const phiRepairs = new Map<string, string>();
  const blockIds = ctx.blocks.map((b) => b.id);
  if (blockIds.length === 0) return phiRepairs;
  const known = new Set(blockIds);

  // ── Where each version is defined ──
  // index -1 means "the top of the block": a phi destination, or the function's
  // entry value. Both are already in the register by the time the block runs.
  const defSite = new Map<string, { block: number; index: number }>();
  for (const b of ctx.blocks) {
    for (const phi of ctx.phis.get(b.id) ?? []) {
      if (phi.dest.version !== undefined)
        defSite.set(versionKey(canonReg(phi.dest.name), phi.dest.version), {
          block: b.id,
          index: -1,
        });
    }
    const stmts = ctx.liftedBlocks.get(b.id) ?? [];
    for (let i = 0; i < stmts.length; i++) {
      const def = defOf(stmts[i]);
      if (def) defSite.set(versionKey(def.canon, def.version), { block: b.id, index: i });
    }
  }

  // ── Which version reaches each block's exit ──
  const exitState = new Map<number, Map<string, number>>();
  for (const id of blockIds) exitState.set(id, new Map());
  const entryState = (b: { id: number; preds: number[] }): Map<string, number> => {
    const preds = b.preds.filter((p) => known.has(p));
    const state = new Map<string, number>();
    if (preds.length === 0) return state;
    for (const [k, v] of exitState.get(preds[0]) ?? []) state.set(k, v);
    for (const p of preds.slice(1)) {
      const other = exitState.get(p) ?? new Map();
      for (const k of [...state.keys()]) {
        if (other.get(k) !== state.get(k)) state.set(k, NO_SURVIVING_VERSION);
      }
      for (const k of other.keys()) if (!state.has(k)) state.set(k, NO_SURVIVING_VERSION);
    }
    return state;
  };
  const applyBlock = (b: { id: number }, state: Map<string, number>): Map<string, number> => {
    for (const phi of ctx.phis.get(b.id) ?? []) {
      if (phi.dest.version !== undefined) state.set(canonReg(phi.dest.name), phi.dest.version);
    }
    for (const stmt of ctx.liftedBlocks.get(b.id) ?? []) {
      const def = defOf(stmt);
      if (def) state.set(def.canon, def.version);
      // The call consumed the registers it was passed, so no version of them
      // reaches past it.
      for (const canon of clobberedByCall(stmt))
        if (canon !== def?.canon) state.set(canon, NO_SURVIVING_VERSION);
    }
    return state;
  };
  // Bounded: one pass per block is enough for a reducible CFG, and the extra
  // two cover a back edge that only settles after the header does. These blocks
  // come from disassembling untrusted bytes, so the loop cannot be open-ended.
  for (let pass = 0; pass <= blockIds.length + 2; pass++) {
    let changed = false;
    for (const b of ctx.blocks) {
      const next = applyBlock(b, entryState(b));
      const prev = exitState.get(b.id) ?? new Map();
      if (prev.size !== next.size || [...next].some(([k, v]) => prev.get(k) !== v)) {
        exitState.set(b.id, next);
        changed = true;
      }
    }
    if (!changed) break;
  }

  // ── Collect the stale reads ──
  interface Stale {
    block: number;
    index: number;
    canon: string;
    version: number;
    size: number;
    /** How the read spelled the register — `esi` in 32-bit code, not `rsi`. */
    spelling: string;
    /** Did an earlier statement in this same block redefine the register? */
    inBlockRedef: boolean;
  }
  const stale: Stale[] = [];

  // ── A phi operand is a read, and it happens at the predecessor's exit ──
  //
  // `destroySSA` lowers the operand to a copy appended to that predecessor, so
  // the version has to be the one reaching the *end of the predecessor*, not the
  // one reaching the block holding the phi. Nothing else in this pass looks at
  // an operand, and that was the whole of peek-a-bin-21ey: GVN forwarded
  // `rdi_14 = 0` to an earlier `rbx_1 = 0` holding the same constant, which is
  // sound in SSA and dominates the read — but EBX had been rewritten in between,
  // so once the versions came off the lowered copy read `edi = ebx` where the
  // machine says `edi = 0`. Valid C, ordinary-looking, and wrong.
  //
  // `index` is `PHI_OPERAND_INDEX`, past any statement, so the "does the
  // definition come before the read" test below reads correctly for a definition
  // in the predecessor itself: every statement in that block precedes the edge.
  for (const b of ctx.blocks) {
    for (const phi of ctx.phis.get(b.id) ?? []) {
      for (const op of phi.operands) {
        if (op.value.version === undefined || !known.has(op.blockId)) continue;
        const canon = canonReg(op.value.name);
        // RSP has no faithful definition chain here — `liftBlock` skips `push`
        // and `pop`, and a `call` pushes a return address nothing models — so
        // the version reaching a point is not evidence about the machine's
        // stack pointer, and the repair would be a copy of a value taken at a
        // program point the instruction never named (peek-a-bin-rt4, and
        // `isStackPointer` in `ssaopt.ts`). Measured: without this, t32
        // `sub_4045B1` alone gained ten `esp = rsp_N` lines that say nothing.
        if (canon === "rsp") continue;
        // A version a *call* handed out has no defining statement, so there is
        // no program point at which to take a copy of it — and it does not need
        // one: `destroySSA`'s own `clobber` branch already lowers such an
        // operand to the indeterminate `clobbered_…` name. Claiming it here
        // would park the *pre-call* value in a variable and call it the value
        // the call left.
        if (ctx.clobbered.has(ssaVersionKey(canon, op.value.version))) continue;
        const live = exitState.get(op.blockId)?.get(canon);
        if (live === undefined || live === op.value.version) continue;
        stale.push({
          block: op.blockId,
          index: PHI_OPERAND_INDEX,
          canon,
          version: op.value.version,
          size: op.value.size,
          spelling: op.value.name.toLowerCase(),
          inBlockRedef: (ctx.liftedBlocks.get(op.blockId) ?? []).some(
            (s) => defOf(s)?.canon === canon,
          ),
        });
      }
    }
  }

  for (const b of ctx.blocks) {
    const state = applyPhis(ctx, b.id, entryState(b));
    const definedHere = new Set<string>();
    const stmts = ctx.liftedBlocks.get(b.id) ?? [];
    for (let i = 0; i < stmts.length; i++) {
      forEachRead(stmts[i], (reg) => {
        if (reg.version === undefined) return;
        const canon = canonReg(reg.name);
        const live = state.get(canon);
        // Absent: nothing has redefined it, so the entry value still stands.
        if (live === undefined || live === reg.version) return;
        stale.push({
          block: b.id,
          index: i,
          canon,
          version: reg.version,
          size: reg.size,
          spelling: reg.name.toLowerCase(),
          inBlockRedef: definedHere.has(canon),
        });
      });
      const def = defOf(stmts[i]);
      if (def) {
        state.set(def.canon, def.version);
        definedHere.add(def.canon);
      }
      for (const canon of clobberedByCall(stmts[i]))
        if (canon !== def?.canon) {
          state.set(canon, NO_SURVIVING_VERSION);
          definedHere.add(canon);
        }
    }
  }
  if (stale.length === 0) return phiRepairs;

  // ── Repair the ones whose definition dominates the read ──
  const dominates = (a: number, b: number): boolean => {
    let cur = b;
    for (let steps = 0; steps <= blockIds.length; steps++) {
      if (cur === a) return true;
      const parent = ctx.idom.get(cur);
      if (parent === undefined || parent === cur) return false;
      cur = parent;
    }
    return false;
  };
  /** Copies to insert, keyed by block, then by the index they follow. */
  const inserts = new Map<number, Map<number, IRStmt[]>>();
  const renamed = new Map<string, string>(); // version key → variable name
  const copied = new Set<string>(); // version key @ block, so one copy per point
  const rewrite = new Map<number, Map<number, Set<string>>>(); // block → index → keys

  // A version read under one spelling throughout is named with it, so a 32-bit
  // function gets `esi_1` rather than a canonical `rsi_1` naming a register its
  // disassembly never mentions. Disagreement — reads of both `esi` and `si` —
  // falls back to `spell`, i.e. the widest spelling the *function* uses, because
  // either read's own spelling would claim a width the other one does not have.
  const spellings = new Map<string, string | null>();
  for (const s of stale) {
    const key = versionKey(s.canon, s.version);
    const seen = spellings.get(key);
    if (seen === undefined) spellings.set(key, s.spelling);
    else if (seen !== s.spelling) spellings.set(key, null);
  }

  for (const s of stale) {
    const key = versionKey(s.canon, s.version);
    // A version with no defining statement is the register's entry value, and
    // no statement in the function is its definition, so there is no point this
    // pass can point at and call one. The function's own entry is not a stand-in:
    // t64's `wcslen` loop reads RAX_0 in a body that adds 2 to RAX every trip,
    // and a copy taken once at function entry would load the same address
    // forever. So the entry value keeps exactly the rule this pass had before it
    // could see across blocks — a copy at the top of the *reading* block, and
    // only where an earlier statement in that same block is what overwrote the
    // register. Anything else is left to bind to the register, as it did before.
    const site = defSite.get(key) ?? (s.inBlockRedef ? { block: s.block, index: -1 } : null);
    if (!site) continue;
    const ok = site.block === s.block ? site.index < s.index : dominates(site.block, s.block);
    if (!ok) continue;

    const siteKey = `${key}@${site.block}`;
    if (!copied.has(siteKey)) {
      copied.add(siteKey);
      const spelling = spellings.get(key) ?? spell(s.canon);
      const name = renamed.get(key) ?? staleName(spelling, s.version);
      renamed.set(key, name);
      const byIndex = inserts.get(site.block) ?? new Map<number, IRStmt[]>();
      const list = byIndex.get(site.index) ?? [];
      // The copy's destination is a *variable*, not a register: foldBlock's
      // single-use inlining only moves register assignments, and moving this one
      // is exactly what must not happen — the whole point is that the register
      // no longer holds this value further down.
      list.push({
        kind: "assign",
        dest: { kind: "var", name, size: s.size },
        // Spelled as the reads spell it, so a 32-bit function does not get a
        // copy `eax_1 = rax` naming a register half of which it never mentions.
        src: { kind: "reg", name: spelling, size: s.size },
      });
      byIndex.set(site.index, list);
      inserts.set(site.block, byIndex);
    }

    if (s.index === PHI_OPERAND_INDEX) {
      // Not a statement, so there is nothing in this block to rewrite: the read
      // is the phi operand, and `destroySSA` consults this map when it lowers
      // the operand to a copy.
      phiRepairs.set(`${s.block}|${key}`, renamed.get(key) as string);
      continue;
    }

    const byIndex = rewrite.get(s.block) ?? new Map<number, Set<string>>();
    const keys = byIndex.get(s.index) ?? new Set<string>();
    keys.add(key);
    byIndex.set(s.index, keys);
    rewrite.set(s.block, byIndex);
  }
  if (renamed.size === 0) return phiRepairs;

  // ── Rebuild the affected blocks ──
  for (const id of new Set([...inserts.keys(), ...rewrite.keys()])) {
    const stmts = ctx.liftedBlocks.get(id) ?? [];
    const ins = inserts.get(id);
    const rw = rewrite.get(id);
    const rebuilt: IRStmt[] = [...(ins?.get(-1) ?? [])];
    for (let i = 0; i < stmts.length; i++) {
      const keys = rw?.get(i);
      const stmt = keys
        ? mapReads(stmts[i], (reg) => {
            if (reg.version === undefined) return null;
            const key = versionKey(canonReg(reg.name), reg.version);
            if (!keys.has(key)) return null;
            const name = renamed.get(key);
            return name ? { kind: "var", name, size: reg.size } : null;
          })
        : stmts[i];
      const copies = ins?.get(i) ?? [];
      const swapped = swapDefWithCopy(stmt, copies);
      if (swapped) {
        rebuilt.push(...swapped);
        continue;
      }
      rebuilt.push(stmt);
      for (const copy of copies) rebuilt.push(copy);
    }
    ctx.liftedBlocks.set(id, rebuilt);
  }

  return phiRepairs;
}

/**
 * `esi = arg_0; esi_1 = esi;` → `esi_1 = arg_0; esi = esi_1;`.
 *
 * Appending the copy is the obvious form and it loses the register's only
 * assignment. `foldBlock` counts uses over the statement list, and a branch
 * condition is not in it — `structure.ts` builds conditions from `RegState`, so
 * the `if (esi == 0)` that also reads ESI is invisible. With the split reads
 * renamed, the register's last apparent use is the copy, the definition folds
 * into it, and the guard is left naming a variable nothing assigns. Writing the
 * variable first and the register from it keeps both: the value has a stable
 * name and the register still has its definition. Measured over the three
 * distlib binaries, appending added 119 register reads with no assignment;
 * this form adds none.
 *
 * Only for a plain `assign` to a register. A call's result register is left
 * alone: `emitFunction` does not print `rax = f()` in the first place, so there
 * is no assignment to preserve.
 */
function swapDefWithCopy(stmt: IRStmt, copies: IRStmt[]): IRStmt[] | null {
  if (copies.length !== 1) return null;
  if (stmt.kind !== "assign" || stmt.dest.kind !== "reg") return null;
  const copy = copies[0];
  if (copy.kind !== "assign" || copy.dest.kind !== "var" || copy.src.kind !== "reg") return null;
  if (canonReg(copy.src.name) !== canonReg(stmt.dest.name)) return null;
  return [
    { ...stmt, dest: copy.dest },
    { kind: "assign", dest: stmt.dest, src: copy.dest, addr: stmt.addr },
  ];
}

/** The block's entry state with its phi destinations applied. */
function applyPhis(
  ctx: SSAContext,
  blockId: number,
  state: Map<string, number>,
): Map<string, number> {
  for (const phi of ctx.phis.get(blockId) ?? []) {
    if (phi.dest.version !== undefined) state.set(canonReg(phi.dest.name), phi.dest.version);
  }
  return state;
}

/** The name a split-out value carries: `ecx` version 1 → `ecx_1`. */
function staleName(spelling: string, version: number): string {
  return `${spelling}_${version}`;
}

/** No SSA version is negative, so no read can match this. */
const NO_SURVIVING_VERSION = -1;

/**
 * A phi operand's `index`: past every statement, because the read it stands for
 * happens on the edge, after the predecessor's last statement has run.
 */
const PHI_OPERAND_INDEX = Number.MAX_SAFE_INTEGER;

/** `rcx` version 1 → `rcx_v1`; the emitted name drops the `v` (`rcx_1`). */
function versionKey(canon: string, version: number): string {
  return `${canon}_v${version}`;
}

function defOf(stmt: IRStmt): { canon: string; version: number } | null {
  const dest =
    stmt.kind === "assign" ? stmt.dest : stmt.kind === "call_stmt" ? stmt.resultDest : undefined;
  if (dest?.kind !== "reg" || dest.version === undefined) return null;
  return { canon: canonReg(dest.name), version: dest.version };
}

function forEachRead(stmt: IRStmt, visit: (reg: IRReg) => void): void {
  mapReads(stmt, (reg) => {
    visit(reg);
    return null;
  });
}

/** Rebuild `stmt` with `f` applied to every register it *reads*. */
function mapReads(stmt: IRStmt, f: (reg: IRReg) => IRExpr | null): IRStmt {
  const expr = (e: IRExpr) => mapRegs(e, f);
  switch (stmt.kind) {
    case "assign":
      return {
        ...stmt,
        dest: stmt.dest.kind === "deref" ? expr(stmt.dest) : stmt.dest,
        src: expr(stmt.src),
      };
    case "store":
      return { ...stmt, address: expr(stmt.address), value: expr(stmt.value) };
    case "call_stmt":
      return { ...stmt, call: { ...stmt.call, args: stmt.call.args.map(expr) } };
    case "return":
      return stmt.value ? { ...stmt, value: expr(stmt.value) } : stmt;
    default:
      // Same set of kinds stripVersionsStmt leaves alone: structuring has not
      // run yet, so nothing else carries a register.
      return stmt;
  }
}

/** Rebuild `expr` with `f` applied to every register in it. */
function mapRegs(expr: IRExpr, f: (reg: IRReg) => IRExpr | null): IRExpr {
  switch (expr.kind) {
    case "reg":
      return f(expr) ?? expr;
    case "binary":
      return { ...expr, left: mapRegs(expr.left, f), right: mapRegs(expr.right, f) };
    case "unary":
      return { ...expr, operand: mapRegs(expr.operand, f) };
    case "deref":
      return { ...expr, address: mapRegs(expr.address, f) };
    case "call":
      return { ...expr, args: expr.args.map((a) => mapRegs(a, f)) };
    case "ternary":
      return {
        ...expr,
        condition: mapRegs(expr.condition, f),
        then: mapRegs(expr.then, f),
        else: mapRegs(expr.else, f),
      };
    case "cast":
      return { ...expr, operand: mapRegs(expr.operand, f) };
    case "field_access":
      return { ...expr, base: mapRegs(expr.base, f) };
    case "array_access":
      return { ...expr, base: mapRegs(expr.base, f), index: mapRegs(expr.index, f) };
    case "const":
    case "var":
    case "unknown":
      return expr; // leaf kinds — no nested registers
    default: {
      // Compile error if a new IRExpr kind is added without handling it here.
      const _exhaustive: never = expr;
      return _exhaustive;
    }
  }
}

function stripVersionsExpr(expr: IRExpr): IRExpr {
  switch (expr.kind) {
    case "reg":
      return expr.version !== undefined ? { ...expr, version: undefined } : expr;
    case "binary":
      return { ...expr, left: stripVersionsExpr(expr.left), right: stripVersionsExpr(expr.right) };
    case "unary":
      return { ...expr, operand: stripVersionsExpr(expr.operand) };
    case "deref":
      return { ...expr, address: stripVersionsExpr(expr.address) };
    case "call":
      return { ...expr, args: expr.args.map(stripVersionsExpr) };
    case "ternary":
      return {
        ...expr,
        condition: stripVersionsExpr(expr.condition),
        then: stripVersionsExpr(expr.then),
        else: stripVersionsExpr(expr.else),
      };
    case "cast":
      return { ...expr, operand: stripVersionsExpr(expr.operand) };
    case "field_access":
      return { ...expr, base: stripVersionsExpr(expr.base) };
    case "array_access":
      return { ...expr, base: stripVersionsExpr(expr.base), index: stripVersionsExpr(expr.index) };
    case "const":
    case "var":
    case "unknown":
      return expr; // leaf kinds — no nested registers
    default: {
      // Compile error if a new IRExpr kind is added without handling it here.
      const _exhaustive: never = expr;
      return _exhaustive;
    }
  }
}

function stripVersionsStmt(stmt: IRStmt): IRStmt {
  switch (stmt.kind) {
    case "assign":
      return { ...stmt, dest: stripVersionsExpr(stmt.dest), src: stripVersionsExpr(stmt.src) };
    case "store":
      return {
        ...stmt,
        address: stripVersionsExpr(stmt.address),
        value: stripVersionsExpr(stmt.value),
      };
    case "call_stmt": {
      const call = { ...stmt.call, args: stmt.call.args.map(stripVersionsExpr) };
      const resultDest = stmt.resultDest ? stripVersionsExpr(stmt.resultDest) : undefined;
      return { ...stmt, call: call as typeof stmt.call, resultDest };
    }
    case "return":
      return stmt.value ? { ...stmt, value: stripVersionsExpr(stmt.value) } : stmt;
    // destroySSA runs before structuring, so no nested-body statements exist
    // yet; phis have already been converted to copies and cleared above.
    case "if":
    case "while":
    case "do_while":
    case "for":
    case "switch":
    case "goto":
    case "label":
    case "comment":
    case "raw":
    case "break":
    case "continue":
    case "phi":
    case "try":
      return stmt;
    default: {
      const _exhaustive: never = stmt;
      return _exhaustive;
    }
  }
}
