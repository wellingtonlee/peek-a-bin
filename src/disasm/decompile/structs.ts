import type { ApiFuncType } from "./apitypes";
import { API_TYPES } from "./apitypes";
import type { IRCall, IRExpr, IRFunction, IRStmt } from "./ir";
import { canonReg, irArrayAccess, irConst, irFieldAccess, irReg, walkStmts } from "./ir";
import type { DecompType } from "./typeInfer";
import { meetTypes } from "./typeInfer";

/**
 * A parameter position — one function's argument slot, identified by the
 * function's address and the argument index.
 *
 * Two bases that occupy the same slot are the same object by construction: one
 * was passed to the other. That is *evidence*, unlike the shape agreement the
 * subset path relies on, and it is what lets a partial view merge into a fuller
 * one however small it is.
 */
interface ParamSlot {
  funcAddr: number;
  paramIdx: number;
}

// ── Struct Definition Types ──

export interface StructField {
  offset: number;
  size: number;
  name: string;
  type: DecompType;
  isArray: boolean;
  arrayElementSize?: number;
  /**
   * Whether the value loaded from this field was ever an operand of a bitwise
   * operator — see `markBitwiseUses`. Evidence against it being a pointer, and
   * it lives on the field rather than in a per-function map because that is the
   * only place it can reach the function that draws the opposite conclusion.
   */
  bitwiseUse?: boolean;
}

export interface StructDef {
  id: string;
  fields: StructField[];
  totalSize: number; // max(offset+size), 0 = unknown
}

// ── Struct Registry (cross-function state) ──

export class StructRegistry {
  private structs = new Map<string, StructDef>();
  private nextId = 0;
  private fingerprintIndex = new Map<string, string>(); // fingerprint → struct id
  // Two provenance maps, deliberately kept apart — see findOrCreateLinked.
  private paramLinks = new Map<string, string>(); // "funcAddr:paramIdx" → structId a *caller* passed there
  private paramViews = new Map<string, string>(); // "funcAddr:paramIdx" → structId the *callee* built from it

  findOrCreate(fingerprint: string, fields: StructField[]): StructDef {
    // Exact match
    const existing = this.fingerprintIndex.get(fingerprint);
    if (existing) {
      const def = this.structs.get(existing)!;
      this.mergeFields(def.id, fields);
      return def;
    }

    // Subset check: if new fingerprint is a subset of existing, merge into existing.
    // Guarded — see canMergeBySubset. Shape alone is weak evidence, and the exact
    // fingerprint path above already covers the safe case.
    const newOffsets = parseFingerprint(fingerprint);
    for (const [fp, id] of this.fingerprintIndex) {
      const existingOffsets = parseFingerprint(fp);
      if (canMergeBySubset(newOffsets, existingOffsets)) {
        const def = this.structs.get(id)!;
        this.mergeFields(def.id, fields);
        // Update fingerprint index with merged fingerprint
        const merged = buildFingerprint(def.fields);
        if (merged !== fp) {
          this.fingerprintIndex.delete(fp);
          this.fingerprintIndex.set(merged, id);
        }
        return def;
      }
    }

    // Create new
    const id = `struct_${this.nextId++}`;
    const sortedFields = [...fields].sort((a, b) => a.offset - b.offset);
    const totalSize =
      sortedFields.length > 0 ? Math.max(...sortedFields.map((f) => f.offset + f.size)) : 0;
    const def: StructDef = { id, fields: sortedFields, totalSize };
    this.structs.set(id, def);
    this.fingerprintIndex.set(fingerprint, id);
    return def;
  }

  /**
   * Merge `fields` into the first of `linkedIds` that can accept them, falling
   * back to the shape-based path when none can.
   *
   * A linked id is evidence that this base and that struct are the same object:
   * a value flowed through a parameter slot shared by the two. Evidence beats
   * shape, so this path deliberately ignores MIN_SUBSET_MERGE_FIELDS — a
   * two-field view of a parameter completes from a caller's fuller view, which
   * is the capability the subset guard had to give up.
   *
   * The one thing provenance cannot override is a boundary conflict. If the
   * layouts contradict each other (overlapping, non-identical extents) then one
   * of the two readings is wrong, and merging would bake the error into a
   * declaration rather than resolve it. Such a base falls through to the shape
   * path, which will refuse it too and give it a struct of its own.
   */
  findOrCreateLinked(linkedIds: string[], fingerprint: string, fields: StructField[]): StructDef {
    const incoming = parseFingerprint(fingerprint);
    for (const id of linkedIds) {
      const def = this.structs.get(id);
      if (!def) continue; // stale link, e.g. across a clear()
      if (hasBoundaryConflict(incoming, parseFingerprint(buildFingerprint(def.fields)))) continue;
      this.mergeFields(def.id, fields);
      this.reindex(def);
      return def;
    }
    return this.findOrCreate(fingerprint, fields);
  }

  /** Keep fingerprintIndex pointing at a struct's current shape after a merge. */
  private reindex(def: StructDef): void {
    const merged = buildFingerprint(def.fields);
    for (const [fp, id] of this.fingerprintIndex) {
      if (id !== def.id) continue;
      if (fp === merged) return;
      this.fingerprintIndex.delete(fp);
      break;
    }
    this.fingerprintIndex.set(merged, def.id);
  }

  mergeFields(id: string, newFields: StructField[]): void {
    const def = this.structs.get(id);
    if (!def) return;
    const existing = new Map(def.fields.map((f) => [f.offset, f]));
    for (const nf of newFields) {
      const ef = existing.get(nf.offset);
      if (!ef) {
        // Copy rather than adopt: the caller's array is scratch built per
        // function, and adopting it makes the registry alias objects the
        // caller may still mutate.
        existing.set(nf.offset, { ...nf });
      } else {
        // Use largest size, preserve array info
        if (nf.size > ef.size) ef.size = nf.size;
        if (nf.isArray && !ef.isArray) {
          ef.isArray = true;
          ef.arrayElementSize = nf.arrayElementSize;
          // The name is the other half of the array claim, so it moves with it.
          // Kept as it was, the merged field is declared `field_0x8[]` — an
          // identifier saying scalar member over brackets saying array, since
          // `declareArrayField` reads only the flag (peek-a-bin-tm29). Derived
          // from the offset rather than adopted from `nf` so the two spellings
          // cannot come apart: the offsets are equal by the lookup above.
          ef.name = fieldNameFor(ef.offset, true);
        }
      }
    }
    def.fields = Array.from(existing.values()).sort((a, b) => a.offset - b.offset);
    def.totalSize =
      def.fields.length > 0 ? Math.max(...def.fields.map((f) => f.offset + f.size)) : 0;
  }

  get(id: string): StructDef | undefined {
    return this.structs.get(id);
  }

  getAll(): StructDef[] {
    return Array.from(this.structs.values());
  }

  /** Record the struct a *caller* passed as argument `paramIdx` of `funcAddr`. */
  linkParam(funcAddr: number, paramIdx: number, structId: string): void {
    this.paramLinks.set(slotKey(funcAddr, paramIdx), structId);
  }

  getParamStruct(funcAddr: number, paramIdx: number): string | undefined {
    return this.paramLinks.get(slotKey(funcAddr, paramIdx));
  }

  /**
   * Record the struct `funcAddr` itself builds out of its own parameter
   * `paramIdx` — that is, the callee's own reading of the argument.
   *
   * Kept separate from linkParam so that a merge always has the callee's
   * corroboration behind it. Two callers passing objects to the same slot are
   * only merged with each other through this map, so the callee has to
   * dereference that parameter as a struct before anything unifies; a
   * passthrough helper taking a void* never links its callers together.
   */
  linkParamView(funcAddr: number, paramIdx: number, structId: string): void {
    this.paramViews.set(slotKey(funcAddr, paramIdx), structId);
  }

  getParamView(funcAddr: number, paramIdx: number): string | undefined {
    return this.paramViews.get(slotKey(funcAddr, paramIdx));
  }

  clear(): void {
    this.structs.clear();
    this.nextId = 0;
    this.fingerprintIndex.clear();
    this.paramLinks.clear();
    this.paramViews.clear();
  }
}

// ── Fingerprinting helpers ──

function slotKey(funcAddr: number, paramIdx: number): string {
  return `${funcAddr}:${paramIdx}`;
}

function parseFingerprint(fp: string): Set<string> {
  return new Set(fp.split(",").filter(Boolean));
}

function isSubset(a: Set<string>, b: Set<string>): boolean {
  for (const item of a) {
    if (!b.has(item)) return false;
  }
  return true;
}

/**
 * Smallest field count that may be merged through the subset path.
 *
 * Two distinct offsets is the *minimum* a candidate can have (synthesizeStructs
 * requires 2+ distinct offsets), so two-field candidates are simultaneously the
 * most common shape and the weakest evidence — `{0:8,8:8}` is a pointer pair and
 * describes a large fraction of all structs in any binary. Requiring three
 * shared fields keeps the subset path for layouts specific enough to mean
 * something. Failing to merge is the benign direction: two struct_N declarations
 * instead of one wrong shared one.
 *
 * This also rejects the empty fingerprint, for which isSubset is vacuously true
 * and which would otherwise fold into whichever struct happened to be indexed
 * first.
 */
const MIN_SUBSET_MERGE_FIELDS = 3;

/** [offset, offset+size) extent of an "offset:size" fingerprint entry. */
function parseExtent(entry: string): { start: number; end: number } | null {
  const [o, s] = entry.split(":");
  const offset = Number(o);
  const size = Number(s);
  if (!Number.isFinite(offset) || !Number.isFinite(size)) return null;
  return { start: offset, end: offset + size };
}

/**
 * True when merging the two field sets would produce a layout in which two
 * fields overlap without being identical (e.g. a 4-byte field at 4 sitting
 * inside an 8-byte field at 0). Such layouts contradict each other, so the
 * shape match is a coincidence rather than evidence of the same type.
 */
function hasBoundaryConflict(a: Set<string>, b: Set<string>): boolean {
  const extents: { start: number; end: number }[] = [];
  for (const entry of new Set([...a, ...b])) {
    const e = parseExtent(entry);
    if (e) extents.push(e);
  }
  extents.sort((x, y) => x.start - y.start);
  for (let i = 1; i < extents.length; i++) {
    if (extents[i].start < extents[i - 1].end) return true;
  }
  return false;
}

/**
 * Whether two fingerprints are close enough to be treated as the same struct.
 * Nesting alone is not enough — see MIN_SUBSET_MERGE_FIELDS and
 * hasBoundaryConflict. Size agreement is already implied: the fingerprint
 * entries are "offset:size" pairs, so a differing size at the same offset is a
 * different entry and breaks the subset relation.
 */
function canMergeBySubset(a: Set<string>, b: Set<string>): boolean {
  const smaller = a.size <= b.size ? a : b;
  const larger = a.size <= b.size ? b : a;
  if (smaller.size < MIN_SUBSET_MERGE_FIELDS) return false;
  if (!isSubset(smaller, larger)) return false;
  return !hasBoundaryConflict(a, b);
}

/**
 * Snapshot a StructDef so a caller holding it is unaffected by later registry
 * mutation. The registry deliberately hands out live objects to the inference
 * passes — that in-place mutation IS how one function's pass refines a field
 * type another function discovered — but anything that escapes the pass (an
 * IRFunction's typedefs) must be frozen, or its emitted declaration changes
 * retroactively when an unrelated function is decompiled later.
 *
 * Field *types* are always replaced wholesale rather than mutated in place, so
 * copying the field object is sufficient; the type object needs no deep clone.
 */
export function cloneStructDef(def: StructDef): StructDef {
  return {
    id: def.id,
    totalSize: def.totalSize,
    fields: def.fields.map((f) => ({ ...f })),
  };
}

export function buildFingerprint(fields: StructField[]): string {
  return [...fields]
    .sort((a, b) => a.offset - b.offset)
    .map((f) => `${f.offset}:${f.size}`)
    .join(",");
}

// ── Address Decomposition ──

interface DecomposedAddress {
  base: IRExpr | null;
  offset: number;
  index: IRExpr | null;
  scale: number;
}

export function decomposeAddress(addr: IRExpr): DecomposedAddress | null {
  if (addr.kind === "reg" || addr.kind === "var") {
    return { base: addr, offset: 0, index: null, scale: 0 };
  }

  if (addr.kind === "const") {
    return { base: null, offset: addr.value, index: null, scale: 0 };
  }

  if (addr.kind !== "binary") return null;
  // `+` chains, plus a top-level `- const` (subtracting a register is not an
  // offset, and treating the whole subtraction as a base only invents noise).
  if (addr.op !== "+" && !(addr.op === "-" && addr.right.kind === "const")) return null;

  // Collect all terms from the addition chain
  const terms: IRExpr[] = [];
  collectAddTerms(addr, terms);

  let base: IRExpr | null = null;
  let offset = 0;
  let index: IRExpr | null = null;
  let scale = 0;

  for (const term of terms) {
    if (term.kind === "const") {
      offset += term.value;
    } else if (isScaledIndex(term)) {
      const si = extractScaledIndex(term);
      if (si && !index) {
        index = si.index;
        scale = si.scale;
      } else if (!base) {
        base = term;
      } else {
        return null; // too complex
      }
    } else {
      if (!base) {
        base = term;
      } else {
        return null; // too complex — multiple non-constant, non-scaled terms
      }
    }
  }

  if (!base && !index) return null; // pure constant, no struct
  return { base, offset, index, scale };
}

function collectAddTerms(expr: IRExpr, terms: IRExpr[]): void {
  if (expr.kind === "binary" && expr.op === "+") {
    collectAddTerms(expr.left, terms);
    collectAddTerms(expr.right, terms);
    return;
  }
  // `base - 8` is the same access as `base + (-8)`. Only a constant subtrahend
  // folds — subtracting a register is not a field offset.
  if (expr.kind === "binary" && expr.op === "-" && expr.right.kind === "const") {
    collectAddTerms(expr.left, terms);
    terms.push(irConst(-expr.right.value, expr.right.size));
    return;
  }
  terms.push(expr);
}

function isScaledIndex(expr: IRExpr): boolean {
  if (expr.kind !== "binary") return false;
  if (expr.op === "*" && expr.right.kind === "const") return true;
  if (expr.op === "<<" && expr.right.kind === "const") return true;
  return false;
}

function extractScaledIndex(expr: IRExpr): { index: IRExpr; scale: number } | null {
  if (expr.kind !== "binary") return null;
  if (expr.op === "*" && expr.right.kind === "const") {
    return { index: expr.left, scale: expr.right.value };
  }
  if (expr.op === "<<" && expr.right.kind === "const") {
    return { index: expr.left, scale: 1 << expr.right.value };
  }
  return null;
}

// ── Expression Identity ──

function exprKey(expr: IRExpr): string {
  switch (expr.kind) {
    case "reg":
      return `reg:${canonReg(expr.name)}`;
    case "var":
      return `var:${expr.name}`;
    case "const":
      return `const:${expr.value}`;
    default:
      return `?:${JSON.stringify(expr)}`;
  }
}

// ── Stack-Frame Bases ──

/**
 * Canonical key of the stack pointer. `canonReg` folds every width spelling
 * (rsp/esp/sp) onto the 64-bit name, so this one key covers both architectures.
 */
const STACK_POINTER_KEY = `reg:${canonReg("rsp")}`;

/** Canonical key of the frame pointer, under the same folding. */
const FRAME_POINTER_KEY = `reg:${canonReg("rbp")}`;

/**
 * Bases that are the stack frame rather than an object, as canonical base keys.
 *
 * The stack pointer is never an object pointer. `[rsp + N]` is a local, an
 * outgoing argument or a spill slot; nothing is ever handed `rsp` as a struct
 * base, and a `lea rax, [rsp+0x20]` that does hand a buffer's address to a
 * callee produces a *different* base (`rax`) — `buildAliasMap` refuses to alias
 * it, since the assignment is arithmetic and not a copy. So the seed is
 * unconditional.
 *
 * The frame pointer is the delicate half, and the rule is deliberately not
 * "exclude rbp". Under frame-pointer omission — the majority of x64 functions —
 * RBP is an ordinary callee-saved register, usually holding an object pointer,
 * and `[rbp + 0x10]` genuinely is a field access. Excluding RBP outright would
 * destroy most of the struct recovery this pass exists for.
 *
 * What is excluded is a frame pointer this function *established from the stack
 * pointer*, on either of two independent pieces of evidence:
 *
 *  - **A parameter named `arg_<N>`.** stack.ts spells a slot that way only
 *    after it has measured the frame register's displacement from the stack
 *    pointer on entry; a frame register it could not derive from the stack
 *    pointer leaves every slot named after its offset (`arg_0x10`), precisely
 *    so the two cases stay distinguishable. That name is the only channel
 *    between the two files, and it is the same one `paramIndexByBase` reads
 *    provenance out of. It is also the *load-bearing* half in production,
 *    because the establishing assignment frequently does not survive to this
 *    pass at all: `mov rbp, rsp` is dropped upstream while the accesses through
 *    RBP keep their base (see peek-a-bin-a6n's follow-up), leaving no trace of
 *    it in the body.
 *  - **The assignment itself, where it does survive.** `rbp = rsp`, or the
 *    `lea rbp, [rsp + 0x20]` form of it. Propagation the other way is covered
 *    by the seed: once the accesses themselves read `[rsp + N]` the base *is*
 *    the stack pointer.
 *
 * Until peek-a-bin-sx57 the first bullet was narrower than the second — the
 * name channel was silent for any prologue but the canonical one, so a
 * `lea`-established or push-shifted frame was excluded by the assignment alone
 * or not at all. It now fires wherever a displacement was recovered, so the two
 * pieces of evidence agree about far more functions than they used to. That is
 * a widening of the exclusion and therefore of the FPO reading's protection; it
 * moved no struct in the corpus, because the assignment was already catching
 * every such function there.
 *
 * A load (`pop rbp`, `mov rbp, [rsp+8]`) is *not* stack-derived: the address is
 * on the stack, the value is whatever was stored there. That matters because an
 * epilogue's `pop rbp` is otherwise the one write that would make every framed
 * function look ambiguous.
 */
function stackDerivedBases(func: IRFunction, canonBase: (e: IRExpr) => string): Set<string> {
  // Both the raw key and whatever the alias map resolves it to: a function that
  // copies the stack pointer into another register groups its `[rsp + N]`
  // accesses under that register's key, and the frame is no less a frame for it.
  const derived = new Set<string>([STACK_POINTER_KEY, canonBase(irReg(canonReg("rsp"), 8))]);

  // A verified frame pointer, named as such by stack.ts. An `arg_0x10` — the
  // spelling for a slot whose frame was *not* verified — deliberately does not
  // match, so an FPO function's RBP keeps its struct.
  if (func.params.some((p) => STACK_PARAM_RE.test(p.name))) {
    derived.add(FRAME_POINTER_KEY);
    derived.add(canonBase(irReg(canonReg("rbp"), 8)));
  }

  // Every reg/var definition, collected first so the fixpoint below can see a
  // chain written in any order (`rbx = rsp` after `rbp = rbx`).
  const defs: { destKey: string; src: IRExpr }[] = [];
  function scan(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === "assign" && (s.dest.kind === "reg" || s.dest.kind === "var")) {
        defs.push({ destKey: canonBase(s.dest), src: s.src });
      }
      if (s.kind === "if") {
        scan(s.thenBody);
        if (s.elseBody) scan(s.elseBody);
      }
      if (s.kind === "while" || s.kind === "do_while") scan(s.body);
      if (s.kind === "for") {
        scan([s.init, s.update]);
        scan(s.body);
      }
      if (s.kind === "switch") {
        for (const c of s.cases) scan(c.body);
        if (s.defaultBody) scan(s.defaultBody);
      }
      if (s.kind === "try") {
        scan(s.body);
        scan(s.handler);
      }
    }
  }
  scan(func.body);

  /** A stack address: the pointer itself, a copy of one, or one biased by a constant. */
  function isStackRooted(e: IRExpr): boolean {
    if (e.kind === "reg" || e.kind === "var") return derived.has(canonBase(e));
    if (e.kind === "cast") return isStackRooted(e.operand);
    if (e.kind === "binary" && (e.op === "+" || e.op === "-")) {
      if (e.right.kind === "const") return isStackRooted(e.left);
      if (e.op === "+" && e.left.kind === "const") return isStackRooted(e.right);
    }
    return false;
  }

  // A second definition never *un*-derives a base. One write of a stack address
  // into a register is enough to make every access through it suspect, and
  // refusing a struct is the benign direction — the cost is a `*(int*)(p + 8)`
  // where a field access was due, against a fabricated object in the other.
  let changed = true;
  while (changed) {
    changed = false;
    for (const d of defs) {
      if (derived.has(d.destKey)) continue;
      if (!isStackRooted(d.src)) continue;
      derived.add(d.destKey);
      changed = true;
    }
  }
  return derived;
}

// ── Access Pattern Collection ──

interface AccessPattern {
  base: IRExpr;
  offset: number;
  size: number;
  index: IRExpr | null;
  scale: number;
}

function collectAccessPatterns(body: IRStmt[]): AccessPattern[] {
  const patterns: AccessPattern[] = [];

  function walkStmts(stmts: IRStmt[]): void {
    for (const s of stmts) {
      switch (s.kind) {
        case "assign":
          walkExprs(s.src);
          // walkExprs handles a deref dest and also reaches accesses nested in a
          // field_access / array_access / binary dest, which the old
          // deref-only check dropped.
          walkExprs(s.dest);
          break;
        case "store":
          walkDeref({ kind: "deref", address: s.address, size: s.size });
          walkExprs(s.value);
          break;
        case "call_stmt":
          for (const a of s.call.args) walkExprs(a);
          break;
        case "return":
          if (s.value) walkExprs(s.value);
          break;
        case "if":
          walkExprs(s.condition);
          walkStmts(s.thenBody);
          if (s.elseBody) walkStmts(s.elseBody);
          break;
        case "while":
        case "do_while":
          walkExprs(s.condition);
          walkStmts(s.body);
          break;
        case "for":
          walkStmts([s.init]);
          walkExprs(s.condition);
          walkStmts([s.update]);
          walkStmts(s.body);
          break;
        case "switch":
          walkExprs(s.expr);
          for (const c of s.cases) walkStmts(c.body);
          if (s.defaultBody) walkStmts(s.defaultBody);
          break;
        case "try":
          walkStmts(s.body);
          walkStmts(s.handler);
          if (s.filterExpr) walkExprs(s.filterExpr);
          break;
      }
    }
  }

  function walkExprs(expr: IRExpr): void {
    switch (expr.kind) {
      case "deref":
        walkDeref(expr);
        break;
      case "binary":
        walkExprs(expr.left);
        walkExprs(expr.right);
        break;
      case "unary":
        walkExprs(expr.operand);
        break;
      case "call":
        for (const a of expr.args) walkExprs(a);
        break;
      case "cast":
        walkExprs(expr.operand);
        break;
      case "ternary":
        walkExprs(expr.condition);
        walkExprs(expr.then);
        walkExprs(expr.else);
        break;
      case "field_access":
        walkExprs(expr.base);
        break;
      case "array_access":
        walkExprs(expr.base);
        walkExprs(expr.index);
        break;
    }
  }

  function walkDeref(deref: { kind: "deref"; address: IRExpr; size: number }): void {
    walkExprs(deref.address);
    const decomp = decomposeAddress(deref.address);
    if (!decomp?.base) return;
    patterns.push({
      base: decomp.base,
      offset: decomp.offset,
      size: deref.size,
      index: decomp.index,
      scale: decomp.scale,
    });
  }

  walkStmts(body);
  return patterns;
}

// ── Base Alias Resolution ──

function buildAliasMap(body: IRStmt[]): Map<string, string> {
  const aliases = new Map<string, string>();
  // Keys whose alias cannot be stated for the whole function. The map is
  // flow-insensitive — one entry per name, no program point — so a name that
  // holds different things at different points has no single correct answer.
  // Dropping it costs a missed struct grouping; keeping the last write credits
  // accesses made through the earlier value to the wrong base.
  const ambiguous = new Set<string>();

  function scan(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === "assign" && (s.dest.kind === "reg" || s.dest.kind === "var")) {
        const destKey =
          s.dest.kind === "reg" ? `reg:${canonReg(s.dest.name)}` : `var:${s.dest.name}`;
        if (s.src.kind === "reg" || s.src.kind === "var") {
          // Direct copy, no arithmetic
          const srcKey = s.src.kind === "reg" ? `reg:${canonReg(s.src.name)}` : `var:${s.src.name}`;
          const prev = aliases.get(destKey);
          if (prev !== undefined && prev !== srcKey) ambiguous.add(destKey);
          else aliases.set(destKey, srcKey);
        } else {
          // Overwritten with something that is not a copy: whatever it aliased
          // before, it does not alias it across the whole function.
          ambiguous.add(destKey);
        }
      }
      // Recurse into compound statements
      if (s.kind === "if") {
        scan(s.thenBody);
        if (s.elseBody) scan(s.elseBody);
      }
      if (s.kind === "while" || s.kind === "do_while") scan(s.body);
      if (s.kind === "for") scan(s.body);
      if (s.kind === "switch") {
        for (const c of s.cases) scan(c.body);
        if (s.defaultBody) scan(s.defaultBody);
      }
      if (s.kind === "try") {
        scan(s.body);
        scan(s.handler);
      }
    }
  }
  scan(body);
  for (const key of ambiguous) aliases.delete(key);

  // Resolve transitive aliases to canonical roots
  function resolve(key: string, visited: Set<string>): string {
    if (visited.has(key)) return key;
    visited.add(key);
    const target = aliases.get(key);
    if (!target) return key;
    return resolve(target, visited);
  }

  const resolved = new Map<string, string>();
  for (const [key] of aliases) {
    resolved.set(key, resolve(key, new Set()));
  }
  return resolved;
}

// ── Field Type Inference from Usage ──

function inferFieldType(size: number): DecompType {
  // Default: unsigned int of access size
  return { kind: "int", size, signed: false };
}

/** Index scales that denote an array element rather than an arbitrary product. */
const ARRAY_SCALES = new Set([1, 2, 4, 8]);

/**
 * Offset as a C identifier fragment. `isFieldOffset` keeps negative offsets out
 * of field synthesis, so the sign branch is a guard rather than a case that
 * fires: a field named `field_0x-8` would not be an identifier at all, and the
 * emitted declaration is this name verbatim.
 */
function offsetLabel(offset: number): string {
  return offset < 0
    ? `neg_0x${(-offset).toString(16).toUpperCase()}`
    : `0x${offset.toString(16).toUpperCase()}`;
}

/**
 * A field's identifier: the offset the recovery found, prefixed by what kind of
 * member the evidence supports.
 *
 * ONE declaration, deliberately, because the name and `isArray` are two halves
 * of one statement and the emitter reads them separately — `declareArrayField`
 * spells `[...]` off `isArray` alone, so a name and a flag decided in two places
 * produce `uint64_t field_0x8[];`, a declaration whose identifier says scalar
 * member and whose brackets say array. That is exactly what happened: this rule
 * lived inline in `candidateFields` while `mergeFields` promoted `isArray`
 * without it (peek-a-bin-tm29). Anything that changes `isArray` on a field must
 * re-derive the name through here.
 */
function fieldNameFor(offset: number, isArray: boolean): string {
  return `${isArray ? "array" : "field"}_${offsetLabel(offset)}`;
}

/**
 * Largest displacement that is treated as a position inside an object.
 *
 * `decomposeAddress` reports the displacement of `[base + 0x412620]` as an
 * offset, but a displacement that large is an *address* that happened to reach a
 * base as a constant — a global table indexed by a register, where the register
 * is the index and the constant is the table. t32's image base is 0x400000 and
 * the "fields" recovered off such a base were 0x400000, 0x412620, 0x412CE0;
 * t64's were 0x140014770 and 0x140014880, both plainly image addresses.
 * Declaring them means padding out gigabytes for an object nothing allocates.
 *
 * The bound is the one emit.ts states as the largest layout it will write
 * (C89's guaranteed object size, 32767 bytes) — the two are deliberately equal
 * but justified separately, and emit.ts keeps its own check as a backstop. A
 * struct genuinely 32KB long loses the accesses past that bound as fields; they
 * are still emitted, as byte offsets from the base.
 */
export const MAX_FIELD_OFFSET = 0x8000;

/**
 * Whether a decomposed displacement can be a member's offset in the object its
 * base names.
 *
 * Two displacements cannot, and both used to become fields that no C struct can
 * lay out — reported inside the emitted struct body rather than placed
 * (peek-a-bin-u3v):
 *
 * - **A negative one.** A member of the object a pointer names is at a
 *   non-negative offset from it; `offsetof` has no other answer. An access
 *   *before* the base is an access to something else — in t64's
 *   `__handler_1400043dc` the base is `rdi + (rsi + 1) * 16`, an array element
 *   pointer, and its `[rbx - 0xC]`, `[rbx - 8]`, `[rbx - 4]` reach the fields of
 *   the *previous* element. Re-basing the group onto its lowest access was the
 *   alternative and is a worse claim: nothing observed says the object starts
 *   there, and it would restate every access in the function against an origin
 *   that was invented. Dropping the access from the *type* keeps the recovered
 *   accesses at or after the base, which are the ones the base is evidence for.
 * - **One at or past MAX_FIELD_OFFSET**, which is an address rather than an
 *   offset.
 *
 * Ineligible accesses are not fields and do not count toward the two-distinct-
 * offsets test that makes a base a struct candidate at all, so a base whose only
 * second offset is one of these gets no struct. The accesses themselves are
 * untouched: with no field at that offset the rewrite leaves the dereference
 * alone and it is emitted as the byte arithmetic it is.
 */
function isFieldOffset(offset: number): boolean {
  return offset >= 0 && offset < MAX_FIELD_OFFSET;
}

// ── Parameter Provenance ──

/** Integer argument registers of the x64 calling convention, in argument order. */
const X64_ARG_REGS = ["rcx", "rdx", "r8", "r9"];

/**
 * A stack parameter whose name carries a known argument index. stack.ts names a
 * slot `arg_<decimal index>` only when it recovered the frame register's
 * displacement, the offset divided evenly into a slot, AND — inside the x64
 * home space — the callee was shown to spill that argument's own register into
 * it; otherwise the name is the offset (`arg_0x10`), which this deliberately
 * does not match. The home-space condition exists for this map in particular:
 * a home slot's `arg_<N>` DISPLACES the argument register's claim below, so a
 * saved register named `arg_0` would be linked to whatever the callers pass as
 * argument 0 (peek-a-bin-sx57).
 */
const STACK_PARAM_RE = /^arg_(\d+)$/;

/**
 * Canonical base key → argument index, for bases that *are* a parameter.
 *
 * Two naming schemes, and which one applies is decided by the parameter names
 * promoteVars produced:
 *
 * - `arg0`…`arg3` are only emitted for an x64 function with a detected
 *   signature, and they are never substituted into the body — the body still
 *   reads RCX. Their presence is therefore the signal that the argument
 *   registers mean what they say. Without it the register mapping must not be
 *   applied: in an x86 function ECX is a scratch register, not parameter 0.
 * - `arg_N` is a promoted stack slot, and N is its argument index, derived in
 *   stack.ts from the slot's offset above the frame pointer. A slot stack.ts
 *   could not derive an index for is named after its offset instead, so it does
 *   not match here and contributes no provenance. That is the whole gate: an
 *   `arg_N` reaching this point means the frame register was shown to be
 *   derived from the entry stack pointer, which matters most on x64, where RBP
 *   is more often a callee-saved object pointer whose `[rbp+0x10]` is a struct
 *   field rather than an argument.
 *
 * Both schemes count the same thing the call-site side counts — a slot, not a
 * source-level argument — so an argument occupying two slots shifts caller and
 * callee indices identically and they still pair correctly. On x64 the two
 * schemes agree by construction rather than merely coexisting: `[rbp+0x10]` is
 * the home slot of the argument that arrives in RCX, so a homed parameter maps
 * to the same index from either direction.
 *
 * (N ≥ 4 on x64 is a real stack argument. Nothing links to it today, since
 * `collectArgs64` stops at the four argument registers, so it is published and
 * looked up harmlessly. The 32-bit side is where this earns its keep: every
 * argument is a stack slot there, and provenance did not reach it at all.)
 *
 * The two schemes can both claim one index, in an x64 function that spills RCX
 * to its home slot: RCX and `arg_0` are then the same argument. Where they
 * really are the same value the body reloads it, `buildAliasMap` folds the two
 * keys into one, and no collision reaches here. A collision that survives that
 * therefore means RCX no longer holds the argument — it was reused for
 * something else after the spill, which is routine for a volatile register —
 * and only one of the two bases can be argument N.
 *
 * The home slot wins, and since peek-a-bin-sx57 that rests on evidence rather
 * than on the ABI. `[rbp+0x10]` reaching this point as `arg_0` now means
 * stack.ts saw this function spill RCX into that slot — the home space is
 * *callee scratch* under the Microsoft x64 ABI, so the slot is argument 0's
 * storage only when the callee made it so, and a slot holding a saved register
 * is named after its offset and never gets here. (This paragraph used to argue
 * "that is the ABI", which was the wrong way round: the ABI reserves the slot
 * and then gives it away.) RCX's
 * claim rests on two heuristics instead — that the signature detector got the
 * parameter count right, and that the register still holds the incoming value
 * at the point of use — and the surviving collision is evidence the second one
 * has already failed. Keeping both would link the reused register's object to
 * the caller's argument and then publish it over the correct view, since the
 * last write to a slot wins. One base per index, so neither can happen.
 */
function paramIndexByBase(func: IRFunction): Map<string, number> {
  const names = new Set(func.params.map((p) => p.name));
  const byBase = new Map<string, number>();
  const claimedBy = new Map<number, string>();

  for (let i = 0; i < X64_ARG_REGS.length; i++) {
    if (names.has(`arg${i}`)) {
      const key = `reg:${canonReg(X64_ARG_REGS[i])}`;
      byBase.set(key, i);
      claimedBy.set(i, key);
    }
  }
  for (const name of names) {
    const m = STACK_PARAM_RE.exec(name);
    if (!m) continue;
    const index = Number(m[1]);
    const heldByRegister = claimedBy.get(index);
    if (heldByRegister !== undefined) byBase.delete(heldByRegister);
    byBase.set(`var:${name}`, index);
    claimedBy.set(index, `var:${name}`);
  }
  return byBase;
}

/**
 * An address for a call target, or null when the target is not one.
 *
 * `sub_<hex>` is the only form resolveCallTarget emits that *is* an address —
 * the others are import names, user function names and register names. Running
 * parseInt over those parses a prefix of the name as hex, so `CloseHandle`
 * became 0xC and `ExitProcess` 0xE, both silently linked as call targets.
 */
function parseCallTargetAddr(target: string): number | null {
  const m = /^sub_([0-9a-fA-F]+)$/.exec(target);
  if (!m) return null;
  const addr = parseInt(m[1], 16);
  return Number.isFinite(addr) && addr > 0 ? addr : null;
}

/**
 * Canonical base key → the argument slots that base is passed in, at direct
 * calls to known functions.
 *
 * Runs before the IR rewrite, but a bare register or variable argument is
 * returned unchanged by rewriteExpr, so the arguments seen here are the ones a
 * post-rewrite walk would see.
 */
function collectCallArgSlots(
  body: IRStmt[],
  canonBase: (e: IRExpr) => string,
): Map<string, ParamSlot[]> {
  const slots = new Map<string, ParamSlot[]>();

  function record(key: string, slot: ParamSlot): void {
    const existing = slots.get(key);
    if (existing) existing.push(slot);
    else slots.set(key, [slot]);
  }

  function walk(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === "call_stmt") {
        const funcAddr = parseCallTargetAddr(s.call.target);
        if (funcAddr !== null) {
          for (let i = 0; i < s.call.args.length; i++) {
            const arg = s.call.args[i];
            if (arg.kind === "reg" || arg.kind === "var") {
              record(canonBase(arg), { funcAddr, paramIdx: i });
            }
          }
        }
      }
      if (s.kind === "if") {
        walk(s.thenBody);
        if (s.elseBody) walk(s.elseBody);
      }
      if (s.kind === "while" || s.kind === "do_while") walk(s.body);
      if (s.kind === "for") walk(s.body);
      if (s.kind === "switch") {
        for (const c of s.cases) walk(c.body);
        if (s.defaultBody) walk(s.defaultBody);
      }
      if (s.kind === "try") {
        walk(s.body);
        walk(s.handler);
      }
    }
  }
  walk(body);
  return slots;
}

/**
 * One base's accesses, exactly as struct synthesis grouped them, handed to an
 * instrument that asks to watch.
 *
 * This exists for ONE reason: which of two OVERLAPPING readings of a base's
 * bytes becomes a field is settled inside `candidateFields`, and neither side of
 * that decision is recoverable from the emitted C — the declaration shows the
 * winner and says nothing about the loser or about there having been a choice.
 * The same is true of the same-offset rule one step earlier, where a narrower
 * directly-observed access is discarded in favour of a wider one at the same
 * offset. `peek-a-bin-k6hh` sat unmeasured for ten days because re-deriving its
 * one count needed a probe in this file.
 *
 * The report is deliberately RAW — every access grouped onto the base, with the
 * stride of any index that reached it — rather than the fields the rule chose.
 * An audit handed the rule's own answer would be a readout of the rule; handed
 * the accesses, `corpus/structOverlaps.ts` re-derives both the same-offset rule
 * and first-by-offset for itself and is a differential test of them, the status
 * `crossEdgeGuards`' `admitted` count has.
 *
 * Reported for every group that reaches `candidateFields`, i.e. after the
 * frame-base and `isFieldOffset` filters and before the two-field candidate
 * test, so a group whose overlap resolution left it under the threshold is still
 * in the population. Passing no observer costs one `undefined` check and changes
 * no value this pass computes, which is the point: an instrument that alters
 * what it measures is worse than no instrument.
 */
export interface StructGroupReport {
  func: string;
  funcAddr: number;
  /** Canonical base key — see `exprKey`. Version-blind; that is its own story. */
  baseKey: string;
  /** Offset, width, and the stride of an index that reached it (0 for none). */
  accesses: { offset: number; size: number; scale: number }[];
  /** Fields `candidateFields` returned. Under 2 and the base is no candidate. */
  fields: number;
}

// ── Candidate Fields ──

/**
 * The fields one base's accesses support, in offset order.
 *
 * Accesses at the same offset are one field of the widest access seen there.
 * What is left can still contradict itself — an 8-byte access at 0 and a 2-byte
 * access at 2 are two readings of overlapping bytes, and at most one of them is
 * a member. C has no faithful spelling for the pair (a union would assert both
 * are members of one type, which is a claim about the object rather than about
 * the accesses seen), so the later one by offset is not made a field at all and
 * its access stays as byte arithmetic. First-by-offset is arbitrary between two
 * partial overlaps but deterministic, and for the common containment case —
 * every one of the nine in the three distlib binaries — it keeps the wider
 * reading, which is the one the narrow access is a part of.
 *
 * This used to be settled in emit.ts, which reported the loser inside the struct
 * body. Deciding it here means the loser is also out of the *fingerprint*, so
 * two bases are no longer kept apart by a field neither of their declarations
 * can contain.
 */
function candidateFields(accesses: AccessPattern[]): StructField[] {
  // Deduplicate fields by offset (use largest size), and record the stride of
  // any index that reached it. Two indexed accesses that walk the offset with
  // *different* strides contradict each other, and CONTRADICTED_STRIDE loses
  // the equality test below, which is how that disagreement is settled.
  const CONTRADICTED_STRIDE = -1;
  const fieldMap = new Map<number, { size: number; stride: number }>();
  for (const acc of accesses) {
    const stride = acc.index !== null ? acc.scale : 0;
    const existing = fieldMap.get(acc.offset);
    if (!existing) {
      fieldMap.set(acc.offset, { size: acc.size, stride });
      continue;
    }
    if (acc.size > existing.size) existing.size = acc.size;
    if (stride === 0) continue;
    existing.stride =
      existing.stride === 0 || existing.stride === stride ? stride : CONTRADICTED_STRIDE;
  }

  const fields: StructField[] = [];
  let end = 0; // one past the extent of the last field kept
  for (const [offset, info] of [...fieldMap].sort((a, b) => a[0] - b[0])) {
    if (offset < end) continue; // overlaps a field already kept
    // An index reaching an offset is evidence of an array only when the
    // stride it walks is the width that was read there. `isArray` used to be
    // set by any indexed access at all while the size and type came from the
    // widest access of any kind, so a field could be declared with 8-byte
    // elements over a recovered stride of 4 — a declaration describing an
    // object neither reading found (peek-a-bin-hyv). Where the two disagree
    // the *width* is kept, because it is a direct measurement of one access,
    // and the array claim is dropped: an array of some other element type
    // may well be there, but this is not evidence of which.
    const isArray = info.stride > 0 && info.stride === info.size;
    fields.push({
      offset,
      size: info.size,
      name: fieldNameFor(offset, isArray),
      type: inferFieldType(info.size),
      isArray,
      arrayElementSize: isArray ? info.stride : undefined,
    });
    end = offset + info.size;
  }
  return fields;
}

// ── Struct Synthesis Pass ──

export function synthesizeStructs(
  func: IRFunction,
  registry: StructRegistry,
  /** An instrument watching how each base's overlapping readings were settled. */
  observe?: (g: StructGroupReport) => void,
): IRFunction {
  // 4a. Collect access patterns
  const patterns = collectAccessPatterns(func.body);
  if (patterns.length === 0) return func;

  // 4b. Build alias map
  const aliasMap = buildAliasMap(func.body);

  // Resolve base to canonical form
  function canonBase(expr: IRExpr): string {
    const key = exprKey(expr);
    return aliasMap.get(key) ?? key;
  }

  // Group accesses by canonical base. An access whose displacement cannot be a
  // member's offset is not evidence about this base's shape at all — see
  // isFieldOffset — so it is left out of the grouping entirely rather than
  // becoming a field nothing can declare.
  const groups = new Map<string, { base: IRExpr; accesses: AccessPattern[] }>();
  for (const p of patterns) {
    if (!isFieldOffset(p.offset)) continue;
    const key = canonBase(p.base);
    let group = groups.get(key);
    if (!group) {
      group = { base: p.base, accesses: [] };
      groups.set(key, group);
    }
    group.accesses.push(p);
  }

  // Bases that are this function's own stack frame. Two offsets off the frame
  // are two stack slots, not two fields of an object, and grouping them
  // fabricated a struct whose "fields" were a local and an incoming argument.
  const frameBases = stackDerivedBases(func, canonBase);

  // Filter: only groups supporting 2+ fields → struct candidates. The count is
  // of the fields that survive `candidateFields`, not of distinct offsets: an
  // access contained in another one's bytes is a second reading of the same
  // field rather than a second field, and a base with nothing else is no more a
  // struct candidate than a base accessed at one offset is.
  const candidates = new Map<string, { base: IRExpr; fields: StructField[] }>();
  for (const [key, group] of groups) {
    if (frameBases.has(key)) continue;
    const fields = candidateFields(group.accesses);
    if (observe) {
      observe({
        func: func.name,
        funcAddr: func.address,
        baseKey: key,
        accesses: group.accesses.map((a) => ({
          offset: a.offset,
          size: a.size,
          scale: a.index !== null ? a.scale : 0,
        })),
        fields: fields.length,
      });
    }
    if (fields.length >= 2) {
      candidates.set(key, { base: group.base, fields });
    }
  }

  if (candidates.size === 0) {
    // No struct candidate, but an indexed access still rewrites to array
    // syntax. This used to return early, which made array-access rewriting
    // reachable only for functions that happened to have a struct elsewhere.
    const hasIndexedAccess = patterns.some((p) => p.index !== null && ARRAY_SCALES.has(p.scale));
    if (!hasIndexedAccess) return func;
    return { ...func, body: rewriteStmts(func.body, new Map(), canonBase) };
  }

  // 4c. Build StructDefs
  const ownParamIdx = paramIndexByBase(func);
  const callArgSlots = collectCallArgSlots(func.body, canonBase);
  const baseToStruct = new Map<string, StructDef>();
  for (const [key, group] of candidates) {
    const fields = group.fields;
    const fingerprint = buildFingerprint(fields);

    // Provenance, strongest first: a struct a caller already passed into this
    // parameter, then the callee's own reading of each slot this base is passed
    // in. Either is direct evidence of identity; shape agreement is the
    // fallback, not the first resort.
    const paramIdx = ownParamIdx.get(key);
    const outgoing = callArgSlots.get(key) ?? [];
    const linked: string[] = [];
    if (paramIdx !== undefined) {
      const fromCaller = registry.getParamStruct(func.address, paramIdx);
      if (fromCaller) linked.push(fromCaller);
    }
    for (const slot of outgoing) {
      const view = registry.getParamView(slot.funcAddr, slot.paramIdx);
      if (view) linked.push(view);
    }

    const def =
      linked.length > 0
        ? registry.findOrCreateLinked(linked, fingerprint, fields)
        : registry.findOrCreate(fingerprint, fields);
    baseToStruct.set(key, def);

    // Publish this base's identity so the functions on the other side of those
    // slots can find it, whichever order they are decompiled in.
    if (paramIdx !== undefined) registry.linkParamView(func.address, paramIdx, def.id);
    for (const slot of outgoing) registry.linkParam(slot.funcAddr, slot.paramIdx, def.id);
  }

  // 4d. Enhanced field type inference from usage context
  inferFieldTypesFromUsage(func.body, baseToStruct, canonBase, registry);

  // 4e. Fields that point at another struct. After 4d, whose PVOID guess this
  // refines; before the rewrite, which turns the loads it reads into field
  // accesses.
  linkNestedStructFields(func.body, baseToStruct, canonBase);

  // 4f. IR Rewrite (struct fields + array access)
  const rewrittenBody = rewriteStmts(func.body, baseToStruct, canonBase);

  // Collect typedefs for this function
  const usedStructIds = new Set<string>();
  for (const [, def] of baseToStruct) {
    usedStructIds.add(def.id);
  }
  // A nested field names a struct this function may never have dereferenced
  // itself — including one an *earlier* function resolved, since field types
  // live in the shared registry. Its declaration has to travel with the one
  // that references it or the emitted typedef block names a type it never
  // defines. Self-reference terminates on the visited set.
  const pending = [...usedStructIds];
  while (pending.length > 0) {
    const def = registry.get(pending.pop()!);
    if (!def) continue;
    for (const f of def.fields) {
      const nested = referencedStructId(f.type);
      if (nested && !usedStructIds.has(nested)) {
        usedStructIds.add(nested);
        pending.push(nested);
      }
    }
  }
  // Snapshot, do not hand out the registry's live objects: a later function's
  // inference pass mutates field types in place, which would otherwise rewrite
  // this function's already-returned declarations after the fact.
  const typedefs = registry
    .getAll()
    .filter((d) => usedStructIds.has(d.id))
    .map(cloneStructDef);

  return {
    ...func,
    body: rewrittenBody,
    typedefs,
  };
}

// ── Field Type Inference from Usage Context ──

/** The guess two heuristics below fall back on when nothing better is known. */
const GUESSED_POINTER: DecompType = { kind: "ptr", pointee: { kind: "unknown" } };

/**
 * Merge new evidence into a field's type instead of replacing it.
 *
 * `meetTypes` is the single place the "more specific wins" ordering is written
 * down — handle beats ptr, handle/ntstatus/hresult/enum beat int, anything beats
 * unknown — and reusing it is what keeps this pass from inventing a second,
 * contradictory notion of specificity. Assigning `field.type` directly means a
 * later, weaker observation silently replaces a better-founded one, and because
 * StructDefs are shared across functions the loser can be a type some *other*
 * function established.
 */
function refineFieldType(field: StructField, evidence: DecompType): void {
  // A field the code does bitwise arithmetic on is not a pointer, whatever
  // heuristic says otherwise — see markBitwiseUses.
  if (field.bitwiseUse && (evidence.kind === "ptr" || evidence.kind === "struct")) return;
  // One case meetTypes gets backwards for a *field*: it ranks ptr above
  // everything it does not order explicitly, so `meetTypes(struct_1*, PVOID)`
  // answers PVOID. Pointer-to-nothing is the weakest thing this pass can say
  // and a resolved nesting is among the strongest, so the guess must not win.
  // The lattice itself is right for its other callers — a ptr genuinely does
  // beat a bare int — so the correction belongs here, on the field, and not in
  // meetTypes.
  if (
    field.type.kind === "struct" &&
    evidence.kind === "ptr" &&
    evidence.pointee.kind === "unknown"
  ) {
    return;
  }
  field.type = meetTypes(field.type, evidence);
}

/**
 * Whether a field still carries only what `inferFieldType` seeded it with.
 *
 * Every field starts as an unsigned int of its access size, so "unsigned int"
 * and "nothing known" are the same state. Anything else — signed, float, handle,
 * ptr, ntstatus — came from an actual observation. The guessing paths below are
 * gated on this rather than on `meetTypes` alone because meetTypes ranks ptr
 * above float and ntstatus: for its usual callers a ptr *is* evidence, and for a
 * guess it is not.
 */
function isUnrefinedFieldType(t: DecompType): boolean {
  return t.kind === "unknown" || (t.kind === "int" && !t.signed);
}

/**
 * Parameter types of a call whose target is a known API, or null.
 *
 * Name resolution matches `inferFromAPICalls` in typeInfer.ts: the display form
 * is `lib!Func`, and the bare target is already the function name.
 */
function apiParamTypes(call: IRCall): DecompType[] | null {
  const name = call.display?.split("!").pop() ?? call.target;
  // The index type says this is always an ApiFuncType, but the object is
  // indexed with a name lifted out of a binary: `toString` and `constructor`
  // are inherited from Object and would otherwise look like hits. Checking the
  // shape rejects both without needing an es2022 lib for `Object.hasOwn`.
  const hit: ApiFuncType | undefined = API_TYPES[name];
  return Array.isArray(hit?.params) ? hit.params : null;
}

/** Operators no pointer value is ever an operand of. */
const BITWISE_OPS = new Set<string>(["&", "|", "^", "<<", ">>", ">>>"]);

/**
 * Record every field whose loaded value is masked, or-ed, xor-ed or shifted,
 * and take back a pointer type that was inferred for it.
 *
 * A field is only guessed to be a pointer, and the guesses are cheap: a
 * field-to-field copy, a machine word passed to an unknown callee, a value used
 * once as a base. Arithmetic on the *value* is evidence in the other direction
 * and there was none — nothing recorded a use of a field as anything.
 * `struct_4::field_0x18` in t64 has six uses across the binary and every one of
 * them is a flag word (`& 3`, `& 0xFFFFFFEF | 2`, `|= 0x20`, `& 0xFFFFFFFE`, a
 * CRT `FILE::_flag`) — but one *other* function loaded it and used the value as
 * a base, and because StructFields are shared live registry state that promotion
 * reached every other function's snapshot, which then read
 * `((struct_4 *)rdx)->field_0x18 |= 0x20` (peek-a-bin-h89).
 *
 * So the record has to live on the field, and it has to work in both
 * directions: a mask seen first refuses the later promotion (`refineFieldType`,
 * `linkNestedStructFields`), and a mask seen after one takes it back here.
 * Otherwise the answer would depend on which function was decompiled first,
 * which is not evidence about anything.
 *
 * Only bitwise operators count. `+` and `-` are ordinary pointer arithmetic and
 * say nothing, and this deliberately does not try to read *which* mask it is:
 * clearing a pointer's low bits is a real idiom, but a field that is both a
 * tagged pointer and something this can spell is not a field this gets right
 * either way. The demotion is to the plain integer of the access width, which is
 * what the field would have been had nothing guessed at it.
 */
function markBitwiseUses(body: IRStmt[], fieldAt: (address: IRExpr) => StructField | null): void {
  const mark = (operand: IRExpr) => {
    if (operand.kind !== "deref") return;
    const field = fieldAt(operand.address);
    if (!field) return;
    field.bitwiseUse = true;
    if (field.type.kind === "ptr" || field.type.kind === "struct") {
      field.type = inferFieldType(field.size);
    }
  };
  walkStmts(body, (expr) => {
    if (expr.kind === "binary" && BITWISE_OPS.has(expr.op)) {
      mark(expr.left);
      mark(expr.right);
    }
    if (expr.kind === "unary" && expr.op === "~") mark(expr.operand);
  });
}

function inferFieldTypesFromUsage(
  body: IRStmt[],
  baseToStruct: Map<string, StructDef>,
  canonBase: (expr: IRExpr) => string,
  _registry: StructRegistry,
): void {
  /** The struct field an address expression names, if it names one. */
  function fieldAt(address: IRExpr): StructField | null {
    const decomp = decomposeAddress(address);
    if (!decomp?.base) return null;
    const def = baseToStruct.get(canonBase(decomp.base));
    if (!def) return null;
    return def.fields.find((f) => f.offset === decomp.offset) ?? null;
  }

  // First, so that everything below sees the counter-evidence.
  markBitwiseUses(body, fieldAt);

  // Walk all expressions, looking for deref patterns that match struct fields
  // and infer types from how the loaded value is used
  function walkStmts(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === "assign") {
        // Check if src is a struct field deref, and dest is used in type-revealing context
        checkDerefUsage(s.src, stmts);
      }
      if (s.kind === "store") {
        // Store value type can refine field type.
        const field = fieldAt(s.address);
        if (field && s.value.kind === "deref") {
          const source = fieldAt(s.value.address);
          if (source) {
            // A field-to-field copy carries the source field's type across. It
            // says nothing about pointerness either way: `dst->a = src->b` on
            // two scalars is an ordinary copy, and the old rule turned every
            // one of them into a PVOID.
            refineFieldType(field, source.type);
          } else if (isUnrefinedFieldType(field.type)) {
            // The value came from memory we know nothing else about. That the
            // address it was loaded from is not itself a tracked field is the
            // whole of the evidence, so it may only fill an empty slot.
            refineFieldType(field, GUESSED_POINTER);
          }
        }
      }
      if (s.kind === "call_stmt") {
        // An argument that is a struct field load types that field: from the
        // callee's real signature where there is one, and otherwise from the
        // much weaker guess that a machine-word passed to a function is an
        // address.
        const params = apiParamTypes(s.call);
        for (let i = 0; i < s.call.args.length; i++) {
          const arg = s.call.args[i];
          if (arg.kind !== "deref") continue;
          const field = fieldAt(arg.address);
          if (!field) continue;
          const declared = params?.[i];
          if (declared) {
            // A real parameter type. `Sleep(o->f)` makes f a DWORD and
            // `CloseHandle(o->f)` makes it a HANDLE; neither is a PVOID.
            refineFieldType(field, declared);
          } else if (field.size >= 4 && isUnrefinedFieldType(field.type)) {
            refineFieldType(field, GUESSED_POINTER);
          }
        }
      }
      // Recurse
      if (s.kind === "if") {
        walkStmts(s.thenBody);
        if (s.elseBody) walkStmts(s.elseBody);
      }
      if (s.kind === "while" || s.kind === "do_while") walkStmts(s.body);
      if (s.kind === "for") walkStmts(s.body);
      if (s.kind === "switch") {
        for (const c of s.cases) walkStmts(c.body);
        if (s.defaultBody) walkStmts(s.defaultBody);
      }
      if (s.kind === "try") {
        walkStmts(s.body);
        walkStmts(s.handler);
      }
    }
  }

  function checkDerefUsage(expr: IRExpr, _context: IRStmt[]): void {
    if (expr.kind !== "deref") return;
    const field = fieldAt(expr.address);
    if (!field) return;
    // XMM-sized access → float. Assigned, not merged: the access width is a
    // direct measurement rather than a guess, and meetTypes would hand the
    // seeded int the win (int and float are unordered, so it returns the left).
    if (expr.size === 16) {
      field.type = { kind: "float", size: 4 };
    }
  }

  walkStmts(body);

  // Second pass: detect signed fields from comparison context
  function walkForSigned(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === "if" || s.kind === "while" || s.kind === "do_while" || s.kind === "for") {
        checkSignedCondition(s.condition);
      }
      if (s.kind === "if") {
        walkForSigned(s.thenBody);
        if (s.elseBody) walkForSigned(s.elseBody);
      }
      if (s.kind === "while" || s.kind === "do_while") walkForSigned(s.body);
      if (s.kind === "for") walkForSigned(s.body);
      if (s.kind === "switch") {
        for (const c of s.cases) walkForSigned(c.body);
        if (s.defaultBody) walkForSigned(s.defaultBody);
      }
      if (s.kind === "try") {
        walkForSigned(s.body);
        walkForSigned(s.handler);
      }
    }
  }

  function checkSignedCondition(cond: IRExpr): void {
    if (cond.kind !== "binary") return;
    const signedOps = new Set(["<", "<=", ">", ">="]);
    if (!signedOps.has(cond.op)) return;
    markFieldSigned(cond.left, baseToStruct, canonBase);
    markFieldSigned(cond.right, baseToStruct, canonBase);
  }

  walkForSigned(body);
}

function markFieldSigned(
  expr: IRExpr,
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): void {
  if (expr.kind !== "deref") return;
  const decomp = decomposeAddress(expr.address);
  if (!decomp?.base) return;
  const key = canonBase(decomp.base);
  const def = baseToStruct.get(key);
  if (!def) return;
  const field = def.fields.find((f) => f.offset === decomp.offset);
  if (field && field.type.kind === "int") {
    field.type = { ...field.type, signed: true };
  }
}

// ── Nested Struct Linking ──

/**
 * Narrowest field that could hold an address.
 *
 * Pointer width is not carried on IRFunction, so this is the 32-bit answer and
 * an x64 binary can in principle nest through a 4-byte field. In practice the
 * load that produced the candidate base is a full-width `mov`, so the field is
 * sized 8 there anyway; the constant only exists to reject the byte and word
 * fields, which cannot be addresses under either model.
 */
const MIN_POINTER_FIELD_SIZE = 4;

/**
 * The struct a type names, if it names one — as a field type (`struct_0*`),
 * behind a pointer, or as an array element.
 */
function referencedStructId(t: DecompType): string | null {
  if (t.kind === "struct") return t.id;
  if (t.kind === "ptr") return referencedStructId(t.pointee);
  if (t.kind === "array") return referencedStructId(t.element);
  return null;
}

/**
 * The struct field an address names, when it names one unambiguously.
 *
 * The no-index condition is the one `rewriteExpr` uses to decide a deref is a
 * field access rather than an array element: `*(p + i*4 + 8)` is not field 8.
 */
function fieldAtAddress(
  address: IRExpr,
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): { def: StructDef; field: StructField } | null {
  const decomp = decomposeAddress(address);
  if (!decomp?.base || decomp.index) return null;
  const def = baseToStruct.get(canonBase(decomp.base));
  if (!def) return null;
  const field = def.fields.find((f) => f.offset === decomp.offset);
  return field ? { def, field } : null;
}

/** Types a nesting may overwrite: the ones that assert nothing. */
function isNestableFieldType(t: DecompType): boolean {
  // PVOID — the guess inferFieldTypesFromUsage falls back on — is exactly the
  // "some address, contents unknown" this pass exists to fill in. Anything
  // else (handle, ntstatus, float, a signed int, an already-resolved nesting)
  // came from a real observation and outranks a structural inference.
  if (t.kind === "ptr" && t.pointee.kind === "unknown") return true;
  return isUnrefinedFieldType(t);
}

/**
 * Retype fields that hold a pointer to another struct.
 *
 * This is a *linking* pass, not a discovery one. By the time it runs, an inner
 * object dereferenced at two or more offsets is already a struct candidate in
 * its own right — `esi = rcx->field_0x8; esi->field_0x0 = 7; esi->field_0x4 = 9`
 * produces two independent candidates, because `buildAliasMap` deliberately
 * refuses to alias `esi` to `rcx` (the assignment is a load, not a copy). What
 * is missing is the edge between them, and the load statement *is* that edge.
 *
 * That framing decides the shape of the pass. There is nothing to iterate to a
 * fixpoint: `a->b->c->d` is three independent load statements, each naming its
 * own pair, so one linear scan resolves the whole chain. The three-round loop
 * the removed v1 stub drove would have spun twice for nothing.
 *
 * An inner object dereferenced at only *one* offset is out of reach by
 * construction, and that is the right answer rather than a gap: a single
 * offset is not evidence of a struct, and `fold` will have substituted the
 * load into its one use anyway, leaving no statement to key on.
 *
 * Must run after inferFieldTypesFromUsage, whose PVOID guess is the type this
 * one refines, and before the IR rewrite, which replaces the derefs this reads
 * with field accesses.
 */
function linkNestedStructFields(
  body: IRStmt[],
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): void {
  // Canonical base key → the field its value was loaded from, or null once two
  // writes disagree about that. Same flow-insensitivity as buildAliasMap: one
  // entry per name and no program point, so a register that holds two different
  // objects over the function has no single correct answer and must be dropped.
  // A missed nesting costs a `uint32_t` where a `struct_1*` was due; a kept one
  // declares a field to point at an object it never points at.
  const loadedFrom = new Map<string, { def: StructDef; field: StructField } | null>();

  function record(key: string, src: { def: StructDef; field: StructField } | null): void {
    const prev = loadedFrom.get(key);
    if (prev === undefined) {
      loadedFrom.set(key, src);
      return;
    }
    if (!prev || !src || prev.def !== src.def || prev.field !== src.field) {
      loadedFrom.set(key, null);
    }
  }

  function walk(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === "assign" && (s.dest.kind === "reg" || s.dest.kind === "var")) {
        const key = canonBase(s.dest);
        // A copy buildAliasMap already folded into this key restates the value
        // rather than redefining it, so it is not a second write.
        const foldedCopy =
          (s.src.kind === "reg" || s.src.kind === "var") && canonBase(s.src) === key;
        if (!foldedCopy) {
          // Anything that is not a plain load — a call result, arithmetic, a
          // cast-wrapped load — is a value this pass cannot attribute to a
          // field, and records as ambiguous rather than as nothing.
          record(
            key,
            s.src.kind === "deref" ? fieldAtAddress(s.src.address, baseToStruct, canonBase) : null,
          );
        }
      }
      if (s.kind === "if") {
        walk(s.thenBody);
        if (s.elseBody) walk(s.elseBody);
      }
      if (s.kind === "while" || s.kind === "do_while") walk(s.body);
      if (s.kind === "for") {
        // init and update are statements too, and an assignment hidden in one
        // of them is exactly the second write that makes a base ambiguous.
        walk([s.init, s.update]);
        walk(s.body);
      }
      if (s.kind === "switch") {
        for (const c of s.cases) walk(c.body);
        if (s.defaultBody) walk(s.defaultBody);
      }
      if (s.kind === "try") {
        walk(s.body);
        walk(s.handler);
      }
    }
  }
  walk(body);

  for (const [key, src] of loadedFrom) {
    if (!src) continue;
    const inner = baseToStruct.get(key);
    if (!inner) continue; // the loaded value is not used as a struct base
    const { field } = src;
    if (field.isArray) continue; // base + index is an element, not a pointer
    if (field.bitwiseUse) continue; // masked or shifted somewhere: not a pointer
    if (field.size < MIN_POINTER_FIELD_SIZE) continue;
    if (!isNestableFieldType(field.type)) continue;
    // `struct` already spells itself `struct_0*` — see typeToString. Wrapping
    // it in a ptr would emit `struct_0**`, one indirection too many.
    //
    // `inner` may be the struct being written to, when a base is loaded out of
    // an object of its own type. That is the linked-list node, and it is the
    // reading to want; it is also what a fingerprint collision between two
    // unrelated same-shaped bases produces, in which case the conflation had
    // already happened in findOrCreate and this only makes it legible.
    field.type = { kind: "struct", id: inner.id };
  }
}

// ── IR Rewrite ──

function rewriteStmts(
  stmts: IRStmt[],
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): IRStmt[] {
  return stmts.map((s) => rewriteStmt(s, baseToStruct, canonBase));
}

function rewriteStmt(
  stmt: IRStmt,
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): IRStmt {
  switch (stmt.kind) {
    case "assign": {
      const src = rewriteExpr(stmt.src, baseToStruct, canonBase);
      const dest = rewriteExpr(stmt.dest, baseToStruct, canonBase);
      return { ...stmt, dest, src };
    }
    case "store": {
      // Check if this store matches a struct field
      const decomp = decomposeAddress(stmt.address);
      if (decomp?.base && !decomp.index) {
        const key = canonBase(decomp.base);
        const def = baseToStruct.get(key);
        if (def) {
          const field = def.fields.find((f) => f.offset === decomp.offset);
          if (field) {
            const base = rewriteExpr(decomp.base, baseToStruct, canonBase);
            const value = rewriteExpr(stmt.value, baseToStruct, canonBase);
            const fa = irFieldAccess(base, def.id, field.offset, field.name, field.size);
            return { kind: "assign", dest: fa, src: value, addr: stmt.addr };
          }
        }
      }
      return {
        ...stmt,
        address: rewriteExpr(stmt.address, baseToStruct, canonBase),
        value: rewriteExpr(stmt.value, baseToStruct, canonBase),
      };
    }
    case "call_stmt": {
      const rewrittenCall = rewriteExpr(stmt.call, baseToStruct, canonBase);
      return { ...stmt, call: rewrittenCall as IRExpr & { kind: "call" } };
    }
    case "return":
      return stmt.value
        ? { ...stmt, value: rewriteExpr(stmt.value, baseToStruct, canonBase) }
        : stmt;
    case "if":
      return {
        ...stmt,
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        thenBody: rewriteStmts(stmt.thenBody, baseToStruct, canonBase),
        elseBody: stmt.elseBody ? rewriteStmts(stmt.elseBody, baseToStruct, canonBase) : undefined,
      };
    case "while":
      return {
        ...stmt,
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
      };
    case "do_while":
      return {
        ...stmt,
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
      };
    case "for":
      return {
        ...stmt,
        init: rewriteStmt(stmt.init, baseToStruct, canonBase),
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        update: rewriteStmt(stmt.update, baseToStruct, canonBase),
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
      };
    case "switch":
      return {
        ...stmt,
        expr: rewriteExpr(stmt.expr, baseToStruct, canonBase),
        cases: stmt.cases.map((c) => ({
          ...c,
          body: rewriteStmts(c.body, baseToStruct, canonBase),
        })),
        defaultBody: stmt.defaultBody
          ? rewriteStmts(stmt.defaultBody, baseToStruct, canonBase)
          : undefined,
      };
    case "try":
      return {
        ...stmt,
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
        handler: rewriteStmts(stmt.handler, baseToStruct, canonBase),
        filterExpr: stmt.filterExpr
          ? rewriteExpr(stmt.filterExpr, baseToStruct, canonBase)
          : undefined,
      };
    default:
      return stmt;
  }
}

function rewriteExpr(
  expr: IRExpr,
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): IRExpr {
  switch (expr.kind) {
    case "deref": {
      // Check if this deref matches a struct field
      const decomp = decomposeAddress(expr.address);
      if (decomp?.base && !decomp.index) {
        const key = canonBase(decomp.base);
        const def = baseToStruct.get(key);
        if (def) {
          const field = def.fields.find((f) => f.offset === decomp.offset);
          if (field) {
            const base = rewriteExpr(decomp.base, baseToStruct, canonBase);
            return irFieldAccess(base, def.id, field.offset, field.name, field.size);
          }
        }
      }
      // Array access: base + index * scale where scale ∈ {1,2,4,8}
      if (decomp?.base && decomp.index && decomp.offset === 0 && ARRAY_SCALES.has(decomp.scale)) {
        const base = rewriteExpr(decomp.base, baseToStruct, canonBase);
        const index = rewriteExpr(decomp.index, baseToStruct, canonBase);
        return irArrayAccess(base, index, decomp.scale, expr.size);
      }
      return { ...expr, address: rewriteExpr(expr.address, baseToStruct, canonBase) };
    }
    case "binary":
      return {
        ...expr,
        left: rewriteExpr(expr.left, baseToStruct, canonBase),
        right: rewriteExpr(expr.right, baseToStruct, canonBase),
      };
    case "unary":
      return { ...expr, operand: rewriteExpr(expr.operand, baseToStruct, canonBase) };
    case "call":
      return { ...expr, args: expr.args.map((a) => rewriteExpr(a, baseToStruct, canonBase)) };
    case "cast":
      return { ...expr, operand: rewriteExpr(expr.operand, baseToStruct, canonBase) };
    case "ternary":
      return {
        ...expr,
        condition: rewriteExpr(expr.condition, baseToStruct, canonBase),
        then: rewriteExpr(expr.then, baseToStruct, canonBase),
        else: rewriteExpr(expr.else, baseToStruct, canonBase),
      };
    case "field_access":
      return { ...expr, base: rewriteExpr(expr.base, baseToStruct, canonBase) };
    case "array_access":
      return {
        ...expr,
        base: rewriteExpr(expr.base, baseToStruct, canonBase),
        index: rewriteExpr(expr.index, baseToStruct, canonBase),
      };
    default:
      return expr;
  }
}
