import type { IRExpr, IRStmt, IRFunction } from './ir';
import { irFieldAccess, irArrayAccess, canonReg } from './ir';
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

    // Subset check: if new fingerprint is a subset of existing, merge into existing
    const newOffsets = parseFingerprint(fingerprint);
    for (const [fp, id] of this.fingerprintIndex) {
      const existingOffsets = parseFingerprint(fp);
      if (isSubset(newOffsets, existingOffsets) || isSubset(existingOffsets, newOffsets)) {
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
        existing.set(nf.offset, nf);
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

  if (addr.kind !== 'binary' || addr.op !== '+') return null;

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
  } else {
    terms.push(expr);
  }
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

function exprEq(a: IRExpr, b: IRExpr): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === 'reg' && b.kind === 'reg') return canonReg(a.name) === canonReg(b.name);
  if (a.kind === 'var' && b.kind === 'var') return a.name === b.name;
  if (a.kind === 'const' && b.kind === 'const') return a.value === b.value;
  return false;
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
          if (s.dest.kind === 'deref') walkDeref(s.dest);
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
    if (!decomp || !decomp.base) return;
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

  function scan(stmts: IRStmt[]): void {
    for (const s of stmts) {
      // reg = reg or var = var (direct copy, no arithmetic)
      if (s.kind === 'assign' &&
          (s.dest.kind === 'reg' || s.dest.kind === 'var') &&
          (s.src.kind === 'reg' || s.src.kind === 'var')) {
        const destKey = s.dest.kind === 'reg' ? `reg:${canonReg(s.dest.name)}` : `var:${s.dest.name}`;
        const srcKey = s.src.kind === 'reg' ? `reg:${canonReg(s.src.name)}` : `var:${s.src.name}`;
        aliases.set(destKey, srcKey);
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

  if (candidates.size === 0) return func;

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
      const name = info.isArray
        ? `array_0x${offset.toString(16).toUpperCase()}`
        : `field_0x${offset.toString(16).toUpperCase()}`;
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

  // 4e. Nested struct detection (max 3 rounds)
  for (let round = 0; round < 3; round++) {
    let changed = false;
    for (const [, def] of baseToStruct) {
      for (const field of def.fields) {
        if (field.type.kind === 'ptr' && field.type.pointee.kind === 'unknown') {
          // Check if loaded values from this field are used as struct bases
          const nestedId = findNestedStructUse(func.body, def.id, field.offset, baseToStruct, canonBase);
          if (nestedId) {
            field.type = { kind: 'ptr', pointee: { kind: 'struct', id: nestedId } };
            field.name = `field_0x${field.offset.toString(16).toUpperCase()}`;
            changed = true;
          }
        }
      }
    }
    if (!changed) break;
  }

  // 4f. IR Rewrite (struct fields + array access)
  const rewrittenBody = rewriteStmts(func.body, baseToStruct, canonBase);

  // 4g. Call-site propagation
  propagateCallSites(rewrittenBody, baseToStruct, canonBase, registry);

  // Collect typedefs for this function
  const usedStructIds = new Set<string>();
  for (const [, def] of baseToStruct) {
    usedStructIds.add(def.id);
  }
  const typedefs = registry.getAll().filter(d => usedStructIds.has(d.id));

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
      if (s.kind === 'if' || s.kind === 'while' || s.kind === 'do_while') {
        const cond = s.kind === 'if' ? s.condition : s.condition;
        if (cond.kind === 'binary') {
          const signedOps = new Set(['<', '<=', '>', '>=']);
          if (signedOps.has(cond.op)) {
            markFieldSigned(cond.left, baseToStruct, canonBase);
            markFieldSigned(cond.right, baseToStruct, canonBase);
          }
        }
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
    }
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

// ── Nested Struct Detection ──

function findNestedStructUse(
  body: IRStmt[],
  _parentStructId: string,
  _fieldOffset: number,
  _baseToStruct: Map<string, StructDef>,
  _canonBase: (e: IRExpr) => string,
): string | null {
  // Simplified: look for deref chains where a loaded value from this field
  // is then used as a base with 2+ offsets. Full implementation would track
  // through assignments, but for v1 we rely on the main synthesis pass
  // catching these in subsequent rounds via registry re-use.
  void body;
  return null;
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
      if (decomp?.base && decomp.index && decomp.offset === 0 &&
          (decomp.scale === 1 || decomp.scale === 2 || decomp.scale === 4 || decomp.scale === 8)) {
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

function propagateCallSites(
  body: IRStmt[],
  baseToStruct: Map<string, StructDef>,
  canonBase: (e: IRExpr) => string,
  registry: StructRegistry,
): void {
  function walk(stmts: IRStmt[]): void {
    for (const s of stmts) {
      if (s.kind === 'call_stmt') {
        // Parse call target address
        const target = s.call.target;
        const targetAddr = parseInt(target, 16) || parseInt(target.replace('sub_', ''), 16);
        if (!isNaN(targetAddr) && targetAddr > 0) {
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
