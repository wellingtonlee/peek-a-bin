import type { IRExpr, IRStmt, IRFunction } from './ir';
import { irFieldAccess, irArrayAccess, irConst, canonReg } from './ir';
import type { DecompType } from './typeInfer';

// ── Struct Definition Types ──

export interface StructField {
  offset: number;
  size: number;
  name: string;
  type: DecompType;
  isArray: boolean;
  arrayElementSize?: number;
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
  private paramLinks = new Map<string, string>(); // "funcAddr:paramIdx" → structId

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
    const totalSize = sortedFields.length > 0
      ? Math.max(...sortedFields.map(f => f.offset + f.size))
      : 0;
    const def: StructDef = { id, fields: sortedFields, totalSize };
    this.structs.set(id, def);
    this.fingerprintIndex.set(fingerprint, id);
    return def;
  }

  mergeFields(id: string, newFields: StructField[]): void {
    const def = this.structs.get(id);
    if (!def) return;
    const existing = new Map(def.fields.map(f => [f.offset, f]));
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
        }
      }
    }
    def.fields = Array.from(existing.values()).sort((a, b) => a.offset - b.offset);
    def.totalSize = def.fields.length > 0
      ? Math.max(...def.fields.map(f => f.offset + f.size))
      : 0;
  }

  get(id: string): StructDef | undefined {
    return this.structs.get(id);
  }

  getAll(): StructDef[] {
    return Array.from(this.structs.values());
  }

  linkParam(funcAddr: number, paramIdx: number, structId: string): void {
    this.paramLinks.set(`${funcAddr}:${paramIdx}`, structId);
  }

  getParamStruct(funcAddr: number, paramIdx: number): string | undefined {
    return this.paramLinks.get(`${funcAddr}:${paramIdx}`);
  }

  clear(): void {
    this.structs.clear();
    this.nextId = 0;
    this.fingerprintIndex.clear();
    this.paramLinks.clear();
  }
}

// ── Fingerprinting helpers ──

function parseFingerprint(fp: string): Set<string> {
  return new Set(fp.split(',').filter(Boolean));
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
  const [o, s] = entry.split(':');
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
    fields: def.fields.map(f => ({ ...f })),
  };
}

export function buildFingerprint(fields: StructField[]): string {
  return [...fields]
    .sort((a, b) => a.offset - b.offset)
    .map(f => `${f.offset}:${f.size}`)
    .join(',');
}

// ── Address Decomposition ──

interface DecomposedAddress {
  base: IRExpr | null;
  offset: number;
  index: IRExpr | null;
  scale: number;
}

export function decomposeAddress(addr: IRExpr): DecomposedAddress | null {
  if (addr.kind === 'reg' || addr.kind === 'var') {
    return { base: addr, offset: 0, index: null, scale: 0 };
  }

  if (addr.kind === 'const') {
    return { base: null, offset: addr.value, index: null, scale: 0 };
  }

  if (addr.kind !== 'binary') return null;
  // `+` chains, plus a top-level `- const` (subtracting a register is not an
  // offset, and treating the whole subtraction as a base only invents noise).
  if (addr.op !== '+' && !(addr.op === '-' && addr.right.kind === 'const')) return null;

  // Collect all terms from the addition chain
  const terms: IRExpr[] = [];
  collectAddTerms(addr, terms);

  let base: IRExpr | null = null;
  let offset = 0;
  let index: IRExpr | null = null;
  let scale = 0;

  for (const term of terms) {
    if (term.kind === 'const') {
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
  if (expr.kind === 'binary' && expr.op === '+') {
    collectAddTerms(expr.left, terms);
    collectAddTerms(expr.right, terms);
    return;
  }
  // `base - 8` is the same access as `base + (-8)`. Only a constant subtrahend
  // folds — subtracting a register is not a field offset.
  if (expr.kind === 'binary' && expr.op === '-' && expr.right.kind === 'const') {
    collectAddTerms(expr.left, terms);
    terms.push(irConst(-expr.right.value, expr.right.size));
    return;
  }
  terms.push(expr);
}

function isScaledIndex(expr: IRExpr): boolean {
  if (expr.kind !== 'binary') return false;
  if (expr.op === '*' && expr.right.kind === 'const') return true;
  if (expr.op === '<<' && expr.right.kind === 'const') return true;
  return false;
}

function extractScaledIndex(expr: IRExpr): { index: IRExpr; scale: number } | null {
  if (expr.kind !== 'binary') return null;
  if (expr.op === '*' && expr.right.kind === 'const') {
    return { index: expr.left, scale: expr.right.value };
  }
  if (expr.op === '<<' && expr.right.kind === 'const') {
    return { index: expr.left, scale: 1 << expr.right.value };
  }
  return null;
}

// ── Expression Identity ──

function exprKey(expr: IRExpr): string {
  switch (expr.kind) {
    case 'reg': return `reg:${canonReg(expr.name)}`;
    case 'var': return `var:${expr.name}`;
    case 'const': return `const:${expr.value}`;
    default: return `?:${JSON.stringify(expr)}`;
  }
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
        case 'assign':
          walkExprs(s.src);
          // walkExprs handles a deref dest and also reaches accesses nested in a
          // field_access / array_access / binary dest, which the old
          // deref-only check dropped.
          walkExprs(s.dest);
          break;
        case 'store':
          walkDeref({ kind: 'deref', address: s.address, size: s.size });
          walkExprs(s.value);
          break;
        case 'call_stmt':
          for (const a of s.call.args) walkExprs(a);
          break;
        case 'return':
          if (s.value) walkExprs(s.value);
          break;
        case 'if':
          walkExprs(s.condition);
          walkStmts(s.thenBody);
          if (s.elseBody) walkStmts(s.elseBody);
          break;
        case 'while':
        case 'do_while':
          walkExprs(s.condition);
          walkStmts(s.body);
          break;
        case 'for':
          walkStmts([s.init]);
          walkExprs(s.condition);
          walkStmts([s.update]);
          walkStmts(s.body);
          break;
        case 'switch':
          walkExprs(s.expr);
          for (const c of s.cases) walkStmts(c.body);
          if (s.defaultBody) walkStmts(s.defaultBody);
          break;
        case 'try':
          walkStmts(s.body);
          walkStmts(s.handler);
          if (s.filterExpr) walkExprs(s.filterExpr);
          break;
      }
    }
  }

  function walkExprs(expr: IRExpr): void {
    switch (expr.kind) {
      case 'deref':
        walkDeref(expr);
        break;
      case 'binary':
        walkExprs(expr.left);
        walkExprs(expr.right);
        break;
      case 'unary':
        walkExprs(expr.operand);
        break;
      case 'call':
        for (const a of expr.args) walkExprs(a);
        break;
      case 'cast':
        walkExprs(expr.operand);
        break;
      case 'ternary':
        walkExprs(expr.condition);
        walkExprs(expr.then);
        walkExprs(expr.else);
        break;
      case 'field_access':
        walkExprs(expr.base);
        break;
      case 'array_access':
        walkExprs(expr.base);
        walkExprs(expr.index);
        break;
    }
  }

  function walkDeref(deref: { kind: 'deref'; address: IRExpr; size: number }): void {
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
      if (s.kind === 'assign' && (s.dest.kind === 'reg' || s.dest.kind === 'var')) {
        const destKey = s.dest.kind === 'reg' ? `reg:${canonReg(s.dest.name)}` : `var:${s.dest.name}`;
        if (s.src.kind === 'reg' || s.src.kind === 'var') {
          // Direct copy, no arithmetic
          const srcKey = s.src.kind === 'reg' ? `reg:${canonReg(s.src.name)}` : `var:${s.src.name}`;
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
      if (s.kind === 'if') {
        scan(s.thenBody);
        if (s.elseBody) scan(s.elseBody);
      }
      if (s.kind === 'while' || s.kind === 'do_while') scan(s.body);
      if (s.kind === 'for') scan(s.body);
      if (s.kind === 'switch') {
        for (const c of s.cases) scan(c.body);
        if (s.defaultBody) scan(s.defaultBody);
      }
      if (s.kind === 'try') {
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
  return { kind: 'int', size, signed: false };
}

/** Index scales that denote an array element rather than an arbitrary product. */
const ARRAY_SCALES = new Set([1, 2, 4, 8]);

/**
 * Offset as a C identifier fragment. Negative offsets are real — a frame or
 * object pointer biased into the middle of its allocation is common — and
 * `0x-8` is not a valid identifier, so the sign is spelled out.
 */
function offsetLabel(offset: number): string {
  return offset < 0
    ? `neg_0x${(-offset).toString(16).toUpperCase()}`
    : `0x${offset.toString(16).toUpperCase()}`;
}

// ── Struct Synthesis Pass ──

export function synthesizeStructs(
  func: IRFunction,
  registry: StructRegistry,
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

  // Group accesses by canonical base
  const groups = new Map<string, { base: IRExpr; accesses: AccessPattern[] }>();
  for (const p of patterns) {
    const key = canonBase(p.base);
    let group = groups.get(key);
    if (!group) {
      group = { base: p.base, accesses: [] };
      groups.set(key, group);
    }
    group.accesses.push(p);
  }

  // Filter: only groups with 2+ distinct offsets → struct candidates
  const candidates = new Map<string, { base: IRExpr; accesses: AccessPattern[] }>();
  for (const [key, group] of groups) {
    const distinctOffsets = new Set(group.accesses.map(a => a.offset));
    if (distinctOffsets.size >= 2) {
      candidates.set(key, group);
    }
  }

  if (candidates.size === 0) {
    // No struct candidate, but an indexed access still rewrites to array
    // syntax. This used to return early, which made array-access rewriting
    // reachable only for functions that happened to have a struct elsewhere.
    const hasIndexedAccess = patterns.some(p => p.index !== null && ARRAY_SCALES.has(p.scale));
    if (!hasIndexedAccess) return func;
    return { ...func, body: rewriteStmts(func.body, new Map(), canonBase) };
  }

  // 4c. Build StructDefs
  const baseToStruct = new Map<string, StructDef>();
  for (const [key, group] of candidates) {
    // Deduplicate fields by offset (use largest size)
    const fieldMap = new Map<number, { size: number; isArray: boolean; scale: number }>();
    for (const acc of group.accesses) {
      const existing = fieldMap.get(acc.offset);
      if (!existing) {
        fieldMap.set(acc.offset, {
          size: acc.size,
          isArray: acc.index !== null,
          scale: acc.scale,
        });
      } else {
        if (acc.size > existing.size) existing.size = acc.size;
        if (acc.index !== null) {
          existing.isArray = true;
          existing.scale = acc.scale;
        }
      }
    }

    const fields: StructField[] = [];
    for (const [offset, info] of fieldMap) {
      const name = `${info.isArray ? 'array' : 'field'}_${offsetLabel(offset)}`;
      fields.push({
        offset,
        size: info.size,
        name,
        type: inferFieldType(info.size),
        isArray: info.isArray,
        arrayElementSize: info.isArray ? info.scale : undefined,
      });
    }

    const fingerprint = buildFingerprint(fields);
    const def = registry.findOrCreate(fingerprint, fields);
    baseToStruct.set(key, def);
  }

  // 4d. Enhanced field type inference from usage context
  inferFieldTypesFromUsage(func.body, baseToStruct, canonBase, registry);

  // 4e. IR Rewrite (struct fields + array access)
  const rewrittenBody = rewriteStmts(func.body, baseToStruct, canonBase);

  // 4f. Call-site propagation
  propagateCallSites(rewrittenBody, baseToStruct, canonBase, registry);

  // Collect typedefs for this function
  const usedStructIds = new Set<string>();
  for (const [, def] of baseToStruct) {
    usedStructIds.add(def.id);
  }
  // Snapshot, do not hand out the registry's live objects: a later function's
  // inference pass mutates field types in place, which would otherwise rewrite
  // this function's already-returned declarations after the fact.
  const typedefs = registry
    .getAll()
    .filter(d => usedStructIds.has(d.id))
    .map(cloneStructDef);

  return {
    ...func,
    body: rewrittenBody,
    typedefs,
  };
}

// ── Field Type Inference from Usage Context ──

function inferFieldTypesFromUsage(
  body: IRStmt[],
  baseToStruct: Map<string, StructDef>,
  canonBase: (expr: IRExpr) => string,
  _registry: StructRegistry,
): void {
  // Walk all expressions, looking for deref patterns that match struct fields
  // and infer types from how the loaded value is used
  function walkStmts(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === 'assign') {
        // Check if src is a struct field deref, and dest is used in type-revealing context
        checkDerefUsage(s.src, stmts);
      }
      if (s.kind === 'store') {
        // Store value type can refine field type
        const decomp = decomposeAddress(s.address);
        if (decomp?.base) {
          const key = canonBase(decomp.base);
          const def = baseToStruct.get(key);
          if (def) {
            const field = def.fields.find(f => f.offset === decomp.offset);
            if (field) {
              // If storing a float, field is float
              // Simple heuristic: mark as pointer if the value is dereffed elsewhere
              if (s.value.kind === 'deref') {
                field.type = { kind: 'ptr', pointee: { kind: 'unknown' } };
              }
            }
          }
        }
      }
      if (s.kind === 'call_stmt') {
        // Check args: if arg is a deref of struct field → field type from API
        // Mark as pointer if arg is a struct base directly
        for (const arg of s.call.args) {
          if (arg.kind === 'deref') {
            const decomp = decomposeAddress(arg.address);
            if (decomp?.base) {
              const key = canonBase(decomp.base);
              const def = baseToStruct.get(key);
              if (def) {
                const field = def.fields.find(f => f.offset === decomp.offset);
                if (field) {
                  // Loaded value passed to function → likely pointer if size is 8/4
                  if (field.size >= 4 && field.type.kind === 'int' && !field.type.signed) {
                    field.type = { kind: 'ptr', pointee: { kind: 'unknown' } };
                  }
                }
              }
            }
          }
        }
      }
      // Recurse
      if (s.kind === 'if') {
        walkStmts(s.thenBody);
        if (s.elseBody) walkStmts(s.elseBody);
      }
      if (s.kind === 'while' || s.kind === 'do_while') walkStmts(s.body);
      if (s.kind === 'for') walkStmts(s.body);
      if (s.kind === 'switch') {
        for (const c of s.cases) walkStmts(c.body);
        if (s.defaultBody) walkStmts(s.defaultBody);
      }
      if (s.kind === 'try') {
        walkStmts(s.body);
        walkStmts(s.handler);
      }
    }
  }

  function checkDerefUsage(expr: IRExpr, _context: IRStmt[]): void {
    if (expr.kind !== 'deref') return;
    const decomp = decomposeAddress(expr.address);
    if (!decomp?.base) return;
    const key = canonBase(decomp.base);
    const def = baseToStruct.get(key);
    if (!def) return;
    const field = def.fields.find(f => f.offset === decomp.offset);
    if (!field) return;
    // XMM-sized access → float
    if (expr.size === 16) {
      field.type = { kind: 'float', size: 4 };
    }
  }

  walkStmts(body);

  // Second pass: detect signed fields from comparison context
  function walkForSigned(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === 'if' || s.kind === 'while' || s.kind === 'do_while' || s.kind === 'for') {
        checkSignedCondition(s.condition);
      }
      if (s.kind === 'if') {
        walkForSigned(s.thenBody);
        if (s.elseBody) walkForSigned(s.elseBody);
      }
      if (s.kind === 'while' || s.kind === 'do_while') walkForSigned(s.body);
      if (s.kind === 'for') walkForSigned(s.body);
      if (s.kind === 'switch') {
        for (const c of s.cases) walkForSigned(c.body);
        if (s.defaultBody) walkForSigned(s.defaultBody);
      }
      if (s.kind === 'try') {
        walkForSigned(s.body);
        walkForSigned(s.handler);
      }
    }
  }

  function checkSignedCondition(cond: IRExpr): void {
    if (cond.kind !== 'binary') return;
    const signedOps = new Set(['<', '<=', '>', '>=']);
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
  if (expr.kind !== 'deref') return;
  const decomp = decomposeAddress(expr.address);
  if (!decomp?.base) return;
  const key = canonBase(decomp.base);
  const def = baseToStruct.get(key);
  if (!def) return;
  const field = def.fields.find(f => f.offset === decomp.offset);
  if (field && field.type.kind === 'int') {
    field.type = { ...field.type, signed: true };
  }
}

// ── IR Rewrite ──

function rewriteStmts(
  stmts: IRStmt[],
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): IRStmt[] {
  return stmts.map(s => rewriteStmt(s, baseToStruct, canonBase));
}

function rewriteStmt(
  stmt: IRStmt,
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
): IRStmt {
  switch (stmt.kind) {
    case 'assign': {
      const src = rewriteExpr(stmt.src, baseToStruct, canonBase);
      const dest = rewriteExpr(stmt.dest, baseToStruct, canonBase);
      return { ...stmt, dest, src };
    }
    case 'store': {
      // Check if this store matches a struct field
      const decomp = decomposeAddress(stmt.address);
      if (decomp?.base && !decomp.index) {
        const key = canonBase(decomp.base);
        const def = baseToStruct.get(key);
        if (def) {
          const field = def.fields.find(f => f.offset === decomp.offset);
          if (field) {
            const base = rewriteExpr(decomp.base, baseToStruct, canonBase);
            const value = rewriteExpr(stmt.value, baseToStruct, canonBase);
            const fa = irFieldAccess(base, def.id, field.offset, field.name, field.size);
            return { kind: 'assign', dest: fa, src: value, addr: stmt.addr };
          }
        }
      }
      return {
        ...stmt,
        address: rewriteExpr(stmt.address, baseToStruct, canonBase),
        value: rewriteExpr(stmt.value, baseToStruct, canonBase),
      };
    }
    case 'call_stmt': {
      const rewrittenCall = rewriteExpr(stmt.call, baseToStruct, canonBase);
      return { ...stmt, call: rewrittenCall as IRExpr & { kind: 'call' } };
    }
    case 'return':
      return stmt.value
        ? { ...stmt, value: rewriteExpr(stmt.value, baseToStruct, canonBase) }
        : stmt;
    case 'if':
      return {
        ...stmt,
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        thenBody: rewriteStmts(stmt.thenBody, baseToStruct, canonBase),
        elseBody: stmt.elseBody ? rewriteStmts(stmt.elseBody, baseToStruct, canonBase) : undefined,
      };
    case 'while':
      return {
        ...stmt,
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
      };
    case 'do_while':
      return {
        ...stmt,
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
      };
    case 'for':
      return {
        ...stmt,
        init: rewriteStmt(stmt.init, baseToStruct, canonBase),
        condition: rewriteExpr(stmt.condition, baseToStruct, canonBase),
        update: rewriteStmt(stmt.update, baseToStruct, canonBase),
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
      };
    case 'switch':
      return {
        ...stmt,
        expr: rewriteExpr(stmt.expr, baseToStruct, canonBase),
        cases: stmt.cases.map(c => ({
          ...c,
          body: rewriteStmts(c.body, baseToStruct, canonBase),
        })),
        defaultBody: stmt.defaultBody ? rewriteStmts(stmt.defaultBody, baseToStruct, canonBase) : undefined,
      };
    case 'try':
      return {
        ...stmt,
        body: rewriteStmts(stmt.body, baseToStruct, canonBase),
        handler: rewriteStmts(stmt.handler, baseToStruct, canonBase),
        filterExpr: stmt.filterExpr ? rewriteExpr(stmt.filterExpr, baseToStruct, canonBase) : undefined,
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
    case 'deref': {
      // Check if this deref matches a struct field
      const decomp = decomposeAddress(expr.address);
      if (decomp?.base && !decomp.index) {
        const key = canonBase(decomp.base);
        const def = baseToStruct.get(key);
        if (def) {
          const field = def.fields.find(f => f.offset === decomp.offset);
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
    case 'binary':
      return {
        ...expr,
        left: rewriteExpr(expr.left, baseToStruct, canonBase),
        right: rewriteExpr(expr.right, baseToStruct, canonBase),
      };
    case 'unary':
      return { ...expr, operand: rewriteExpr(expr.operand, baseToStruct, canonBase) };
    case 'call':
      return { ...expr, args: expr.args.map(a => rewriteExpr(a, baseToStruct, canonBase)) };
    case 'cast':
      return { ...expr, operand: rewriteExpr(expr.operand, baseToStruct, canonBase) };
    case 'ternary':
      return {
        ...expr,
        condition: rewriteExpr(expr.condition, baseToStruct, canonBase),
        then: rewriteExpr(expr.then, baseToStruct, canonBase),
        else: rewriteExpr(expr.else, baseToStruct, canonBase),
      };
    case 'field_access':
      return { ...expr, base: rewriteExpr(expr.base, baseToStruct, canonBase) };
    case 'array_access':
      return { ...expr, base: rewriteExpr(expr.base, baseToStruct, canonBase), index: rewriteExpr(expr.index, baseToStruct, canonBase) };
    default:
      return expr;
  }
}

// ── Call-Site Propagation ──

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

function propagateCallSites(
  body: IRStmt[],
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
  registry: StructRegistry,
): void {
  function walk(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === 'call_stmt') {
        const targetAddr = parseCallTargetAddr(s.call.target);
        if (targetAddr !== null) {
          for (let i = 0; i < s.call.args.length; i++) {
            const arg = s.call.args[i];
            if (arg.kind === 'reg' || arg.kind === 'var') {
              const key = canonBase(arg);
              const def = baseToStruct.get(key);
              if (def) {
                registry.linkParam(targetAddr, i, def.id);
              }
            }
          }
        }
      }
      if (s.kind === 'if') {
        walk(s.thenBody);
        if (s.elseBody) walk(s.elseBody);
      }
      if (s.kind === 'while' || s.kind === 'do_while') walk(s.body);
      if (s.kind === 'for') walk(s.body);
      if (s.kind === 'switch') {
        for (const c of s.cases) walk(c.body);
        if (s.defaultBody) walk(s.defaultBody);
      }
    }
  }
  walk(body);
}
