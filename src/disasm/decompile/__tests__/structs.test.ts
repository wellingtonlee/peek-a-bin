import { describe, it, expect } from 'vitest';
import {
  StructRegistry, buildFingerprint, decomposeAddress, synthesizeStructs,
  type StructField,
} from '../structs';
import { irBinary, irConst, irDeref, irReg, irVar, irUnary } from '../ir';
import type { IRExpr, IRStmt, IRFunction } from '../ir';
import type { DecompType } from '../typeInfer';

const UINT = (size: number): DecompType => ({ kind: 'int', size, signed: false });

function field(offset: number, size: number, over: Partial<StructField> = {}): StructField {
  return {
    offset,
    size,
    name: `field_0x${offset.toString(16).toUpperCase()}`,
    type: UINT(size),
    isArray: false,
    ...over,
  };
}

// ── IR builders ──
const assign = (dest: IRExpr, src: IRExpr): IRStmt => ({ kind: 'assign', dest, src });
const store = (address: IRExpr, value: IRExpr, size = 4): IRStmt =>
  ({ kind: 'store', address, value, size });
const callStmt = (target: string, args: IRExpr[] = []): IRStmt =>
  ({ kind: 'call_stmt', call: { kind: 'call', target, args } });

/** `*(base + offset)` */
const at = (base: IRExpr, offset: number, size = 4): IRExpr =>
  irDeref(offset === 0 ? base : irBinary('+', base, irConst(offset)), size);
/** `*(base + index * scale)` */
const idx = (base: IRExpr, index: IRExpr, scale: number, size = 4): IRExpr =>
  irDeref(irBinary('+', base, irBinary('*', index, irConst(scale))), size);

const RCX = irReg('rcx', 8);
const RDX = irReg('rdx', 8);

function fn(body: IRStmt[], over: Partial<IRFunction> = {}): IRFunction {
  return {
    name: 'sub_401000',
    address: 0x401000,
    returnType: 'void',
    params: [],
    locals: [],
    body,
    ...over,
  };
}

/** A function whose base RCX is accessed at two distinct offsets — the minimum
 *  shape that makes a struct candidate. */
function twoFieldBody(base: IRExpr = RCX): IRStmt[] {
  return [
    assign(irReg('eax', 4), at(base, 0)),
    assign(irReg('ebx', 4), at(base, 8)),
  ];
}

describe('buildFingerprint', () => {
  it('formats fields as offset:size pairs', () => {
    expect(buildFingerprint([field(0, 8), field(8, 4)])).toBe('0:8,8:4');
  });

  it('sorts by offset regardless of input order', () => {
    expect(buildFingerprint([field(16, 4), field(0, 8)])).toBe('0:8,16:4');
  });

  it('returns an empty string for no fields', () => {
    expect(buildFingerprint([])).toBe('');
  });

  it('does not mutate the input array', () => {
    const fields = [field(16, 4), field(0, 8)];
    buildFingerprint(fields);
    expect(fields.map(f => f.offset)).toEqual([16, 0]);
  });
});

describe('decomposeAddress', () => {
  it('treats a bare register as a base at offset zero', () => {
    expect(decomposeAddress(RCX)).toEqual({ base: RCX, offset: 0, index: null, scale: 0 });
  });

  it('treats a bare variable as a base', () => {
    const v = irVar('p', 8);
    expect(decomposeAddress(v)).toEqual({ base: v, offset: 0, index: null, scale: 0 });
  });

  it('treats a bare constant as an offset with no base', () => {
    expect(decomposeAddress(irConst(0x404000))).toEqual({
      base: null, offset: 0x404000, index: null, scale: 0,
    });
  });

  it('decomposes base + displacement', () => {
    expect(decomposeAddress(irBinary('+', RCX, irConst(0x10))))
      .toEqual({ base: RCX, offset: 0x10, index: null, scale: 0 });
  });

  it('accumulates several constant terms', () => {
    const addr = irBinary('+', irBinary('+', RCX, irConst(8)), irConst(4));
    expect(decomposeAddress(addr)?.offset).toBe(12);
  });

  it('accepts a negative displacement expressed as a negative constant', () => {
    expect(decomposeAddress(irBinary('+', RCX, irConst(-8)))?.offset).toBe(-8);
  });

  it('flattens a nested addition chain', () => {
    const addr = irBinary('+', irBinary('+', RCX, irBinary('*', RDX, irConst(4))), irConst(0x20));
    expect(decomposeAddress(addr)).toEqual({ base: RCX, offset: 0x20, index: RDX, scale: 4 });
  });

  it('extracts a multiplicative scaled index', () => {
    const addr = irBinary('+', RCX, irBinary('*', RDX, irConst(8)));
    expect(decomposeAddress(addr)).toEqual({ base: RCX, offset: 0, index: RDX, scale: 8 });
  });

  it('extracts a shift-encoded scaled index', () => {
    const addr = irBinary('+', RCX, irBinary('<<', RDX, irConst(3)));
    expect(decomposeAddress(addr)?.scale).toBe(8);
  });

  it('keeps a scale that is not a power of two', () => {
    // The array-access rewrite filters these out later; decomposition does not.
    const addr = irBinary('+', RCX, irBinary('*', RDX, irConst(3)));
    expect(decomposeAddress(addr)?.scale).toBe(3);
  });

  it('produces a wrapped scale for an oversized shift', () => {
    // `1 << 31` is negative in JS and `1 << 32` wraps to 1 — neither survives
    // the {1,2,4,8} filter, so an absurd shift cannot fake an array access.
    expect(decomposeAddress(irBinary('+', RCX, irBinary('<<', RDX, irConst(31))))?.scale)
      .toBe(1 << 31);
    expect(decomposeAddress(irBinary('+', RCX, irBinary('<<', RDX, irConst(32))))?.scale).toBe(1);
  });

  it('returns null for a subtraction', () => {
    // Only `+` chains decompose, so `base - offset` is never a struct access.
    expect(decomposeAddress(irBinary('-', RCX, irConst(8)))).toBeNull();
  });

  it('returns null for a non-additive expression', () => {
    expect(decomposeAddress(irBinary('*', RCX, irConst(4)))).toBeNull();
    expect(decomposeAddress(irUnary('~', RCX))).toBeNull();
    expect(decomposeAddress(irDeref(RCX, 8))).toBeNull();
    expect(decomposeAddress({ kind: 'unknown', text: '?' })).toBeNull();
  });

  it('returns null for an addition of constants only', () => {
    expect(decomposeAddress(irBinary('+', irConst(4), irConst(8)))).toBeNull();
  });

  it('returns null when two plain registers are added', () => {
    expect(decomposeAddress(irBinary('+', RCX, RDX))).toBeNull();
  });

  it('takes a second scaled term as the base rather than failing', () => {
    const addr = irBinary('+', irBinary('*', RCX, irConst(4)), irBinary('*', RDX, irConst(8)));
    const d = decomposeAddress(addr);
    expect(d?.index).toEqual(RCX);
    expect(d?.scale).toBe(4);
    expect(d?.base).toEqual(irBinary('*', RDX, irConst(8)));
  });

  it('returns null for three non-constant terms', () => {
    const addr = irBinary('+', irBinary('+', RCX, RDX), irReg('r8', 8));
    expect(decomposeAddress(addr)).toBeNull();
  });
});

describe('StructRegistry', () => {
  it('creates sequentially numbered structs', () => {
    const reg = new StructRegistry();
    expect(reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]).id).toBe('struct_0');
    expect(reg.findOrCreate('0:4,16:4', [field(0, 4), field(16, 4)]).id).toBe('struct_1');
  });

  it('sorts fields and computes the total size on creation', () => {
    const reg = new StructRegistry();
    const def = reg.findOrCreate('0:4,16:8', [field(16, 8), field(0, 4)]);
    expect(def.fields.map(f => f.offset)).toEqual([0, 16]);
    expect(def.totalSize).toBe(24);
  });

  it('reports a zero total size for a struct with no fields', () => {
    expect(new StructRegistry().findOrCreate('', []).totalSize).toBe(0);
  });

  it('returns the same struct for an identical fingerprint', () => {
    const reg = new StructRegistry();
    const a = reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    const b = reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    expect(b.id).toBe(a.id);
    expect(reg.getAll()).toHaveLength(1);
  });

  it('merges a fingerprint that is a subset of an existing one', () => {
    const reg = new StructRegistry();
    const big = reg.findOrCreate('0:4,8:4,16:4', [field(0, 4), field(8, 4), field(16, 4)]);
    const small = reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    expect(small.id).toBe(big.id);
    expect(reg.getAll()).toHaveLength(1);
  });

  it('merges a fingerprint that is a superset of an existing one', () => {
    const reg = new StructRegistry();
    const small = reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    const big = reg.findOrCreate('0:4,8:4,16:4', [field(0, 4), field(8, 4), field(16, 4)]);
    expect(big.id).toBe(small.id);
    expect(big.fields.map(f => f.offset)).toEqual([0, 8, 16]);
    expect(big.totalSize).toBe(20);
  });

  it('keeps structs with overlapping but non-nested field sets apart', () => {
    const reg = new StructRegistry();
    reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    reg.findOrCreate('0:4,16:4', [field(0, 4), field(16, 4)]);
    expect(reg.getAll()).toHaveLength(2);
  });

  it('treats a differing field size as a different slot', () => {
    const reg = new StructRegistry();
    reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    reg.findOrCreate('0:8,8:8', [field(0, 8), field(8, 8)]);
    expect(reg.getAll()).toHaveLength(2);
  });

  // KNOWN BUG (reported, not fixed): isSubset() is vacuously true for an empty
  // set, so a struct with no fields merges into whichever struct happens to be
  // first in the fingerprint index instead of standing alone.
  it('merges an empty fingerprint into an arbitrary existing struct', () => {
    const reg = new StructRegistry();
    const first = reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    const empty = reg.findOrCreate('', []);
    expect(empty.id).toBe(first.id);
  });

  describe('mergeFields', () => {
    it('adds a field at a new offset', () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate('0:4', [field(0, 4)]);
      reg.mergeFields(def.id, [field(8, 4)]);
      expect(def.fields.map(f => f.offset)).toEqual([0, 8]);
    });

    it('keeps the larger size for an existing offset', () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate('0:4', [field(0, 4)]);
      reg.mergeFields(def.id, [field(0, 8)]);
      expect(def.fields[0].size).toBe(8);
      reg.mergeFields(def.id, [field(0, 2)]);
      expect(def.fields[0].size).toBe(8);
    });

    it('promotes a field to an array when a later access is indexed', () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate('0:4', [field(0, 4)]);
      reg.mergeFields(def.id, [field(0, 4, { isArray: true, arrayElementSize: 4 })]);
      expect(def.fields[0]).toMatchObject({ isArray: true, arrayElementSize: 4 });
    });

    it('keeps fields sorted and the total size current', () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate('8:4', [field(8, 4)]);
      reg.mergeFields(def.id, [field(0, 4), field(32, 8)]);
      expect(def.fields.map(f => f.offset)).toEqual([0, 8, 32]);
      expect(def.totalSize).toBe(40);
    });

    it('ignores an unknown struct id', () => {
      const reg = new StructRegistry();
      expect(() => reg.mergeFields('struct_99', [field(0, 4)])).not.toThrow();
    });
  });

  it('looks structs up by id', () => {
    const reg = new StructRegistry();
    const def = reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    expect(reg.get(def.id)).toBe(def);
    expect(reg.get('struct_99')).toBeUndefined();
  });

  it('round-trips parameter links', () => {
    const reg = new StructRegistry();
    reg.linkParam(0x401000, 1, 'struct_0');
    expect(reg.getParamStruct(0x401000, 1)).toBe('struct_0');
    expect(reg.getParamStruct(0x401000, 0)).toBeUndefined();
    expect(reg.getParamStruct(0x402000, 1)).toBeUndefined();
  });

  it('clears every kind of state and restarts numbering', () => {
    const reg = new StructRegistry();
    reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    reg.linkParam(1, 0, 'struct_0');
    reg.clear();
    expect(reg.getAll()).toEqual([]);
    expect(reg.getParamStruct(1, 0)).toBeUndefined();
    expect(reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]).id).toBe('struct_0');
  });

  it('hands out the live StructDef, not a copy', () => {
    // Callers mutate field types in place; that is how inference reaches the
    // registry, and it is also how one function's pass reaches another's.
    const reg = new StructRegistry();
    const def = reg.findOrCreate('0:4,8:4', [field(0, 4), field(8, 4)]);
    def.fields[0].type = { kind: 'handle' };
    expect(reg.get(def.id)?.fields[0].type).toEqual({ kind: 'handle' });
  });
});

describe('synthesizeStructs — candidate selection', () => {
  const run = (body: IRStmt[], reg = new StructRegistry()) => synthesizeStructs(fn(body), reg);

  it('returns the function untouched when there are no memory accesses', () => {
    const func = fn([assign(irReg('eax', 4), irConst(1))]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it('returns the function untouched for a single accessed offset', () => {
    const func = fn([assign(irReg('eax', 4), at(RCX, 0))]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it('does not count two accesses at the same offset as two fields', () => {
    const func = fn([
      assign(irReg('eax', 4), at(RCX, 8)),
      assign(irReg('ebx', 4), at(RCX, 8, 8)),
    ]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it('synthesizes a struct from two distinct offsets on one base', () => {
    const out = run(twoFieldBody());
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map(f => [f.offset, f.name])).toEqual([
      [0, 'field_0x0'], [8, 'field_0x8'],
    ]);
  });

  it('rewrites matching dereferences to field accesses', () => {
    const out = run(twoFieldBody());
    expect(out.body[0]).toMatchObject({
      src: { kind: 'field_access', base: RCX, fieldOffset: 0, fieldName: 'field_0x0', size: 4 },
    });
    expect(out.body[1]).toMatchObject({ src: { kind: 'field_access', fieldOffset: 8 } });
  });

  it('keeps the largest access size for a field', () => {
    const out = run([
      assign(irReg('al', 1), at(RCX, 0, 1)),
      assign(irReg('rax', 8), at(RCX, 0, 8)),
      assign(irReg('ebx', 4), at(RCX, 8)),
    ]);
    expect(out.typedefs?.[0].fields.find(f => f.offset === 0)?.size).toBe(8);
  });

  it('reports the struct size as the end of its last field', () => {
    const out = run([
      assign(irReg('eax', 4), at(RCX, 0)),
      assign(irReg('rbx', 8), at(RCX, 0x18, 8)),
    ]);
    expect(out.typedefs?.[0].totalSize).toBe(0x20);
  });

  it('groups two different bases into two structs', () => {
    const out = run([...twoFieldBody(RCX), ...twoFieldBody(RDX)]);
    const ids = new Set(out.typedefs?.map(d => d.id));
    // Both bases have the same shape, so the registry folds them together.
    expect(ids.size).toBe(1);
  });

  it('keeps bases with different shapes apart', () => {
    const out = run([
      assign(irReg('eax', 4), at(RCX, 0)),
      assign(irReg('ebx', 4), at(RCX, 8)),
      assign(irReg('ecx', 4), at(RDX, 0)),
      assign(irReg('edx', 4), at(RDX, 0x20)),
    ]);
    expect(out.typedefs).toHaveLength(2);
  });

  it('treats a variable base like a register base', () => {
    const p = irVar('p', 8);
    const out = run(twoFieldBody(p));
    expect(out.body[0]).toMatchObject({ src: { kind: 'field_access', base: p } });
  });

  it('canonicalises sub-registers of the same base', () => {
    const out = run([
      assign(irReg('eax', 4), at(irReg('rcx', 8), 0)),
      assign(irReg('ebx', 4), at(irReg('ecx', 4), 8)),
    ]);
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields).toHaveLength(2);
  });
});

describe('synthesizeStructs — stores and nesting', () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());

  it('turns a store to a struct field into a field assignment', () => {
    const out = run([
      store(irBinary('+', RCX, irConst(8)), irConst(1)),
      assign(irReg('eax', 4), at(RCX, 0)),
    ]);
    expect(out.body[0]).toMatchObject({
      kind: 'assign',
      dest: { kind: 'field_access', fieldOffset: 8 },
      src: irConst(1),
    });
  });

  it('preserves the source address of a rewritten store', () => {
    const s: IRStmt = { kind: 'store', address: irBinary('+', RCX, irConst(8)), value: irConst(1), size: 4, addr: 0x401005 };
    const out = run([s, assign(irReg('eax', 4), at(RCX, 0))]);
    expect(out.body[0]).toMatchObject({ addr: 0x401005 });
  });

  it('leaves a store to an unrelated address alone', () => {
    const out = run([...twoFieldBody(), store(irReg('r8', 8), irConst(1))]);
    expect(out.body[2]).toMatchObject({ kind: 'store', address: irReg('r8', 8) });
  });

  it('rewrites accesses nested in every compound statement', () => {
    const read = at(RCX, 0);
    const body: IRStmt[] = [
      assign(irReg('ebx', 4), at(RCX, 8)),
      { kind: 'if', condition: read, thenBody: [assign(irReg('eax', 4), read)], elseBody: [assign(irReg('eax', 4), read)] },
      { kind: 'while', condition: read, body: [assign(irReg('eax', 4), read)] },
      { kind: 'do_while', condition: read, body: [assign(irReg('eax', 4), read)] },
      { kind: 'for', init: assign(irReg('esi', 4), read), condition: read, update: assign(irReg('esi', 4), read), body: [assign(irReg('eax', 4), read)] },
      { kind: 'switch', expr: read, cases: [{ values: [1], body: [assign(irReg('eax', 4), read)] }], defaultBody: [assign(irReg('eax', 4), read)] },
      { kind: 'try', body: [assign(irReg('eax', 4), read)], handler: [assign(irReg('eax', 4), read)], filterExpr: read },
      { kind: 'return', value: read },
      callStmt('memcpy', [read]),
    ];
    const flat = JSON.stringify(synthesizeStructs(fn(body), new StructRegistry()).body);
    expect(flat).not.toContain('"kind":"deref"');
    expect(flat).toContain('field_access');
  });

  it('leaves statements it does not understand untouched', () => {
    const raw: IRStmt = { kind: 'raw', text: '__asm { cpuid }' };
    const out = run([...twoFieldBody(), raw, { kind: 'break' }, { kind: 'goto', label: 'L' }]);
    expect(out.body.slice(2)).toEqual([raw, { kind: 'break' }, { kind: 'goto', label: 'L' }]);
  });

  it('rewrites through a cast and a ternary', () => {
    const read = at(RCX, 0);
    const out = run([
      assign(irReg('ebx', 4), at(RCX, 8)),
      assign(irReg('eax', 4), { kind: 'cast', type: 'int64_t', operand: read }),
      assign(irReg('edx', 4), { kind: 'ternary', condition: read, then: read, else: irConst(0) }),
    ]);
    expect(JSON.stringify(out.body)).not.toContain('"kind":"deref"');
  });
});

// The walkers in this module (collectAccessPatterns' two walkers, rewriteStmt,
// rewriteExpr) either end in `default:` or fall off the end, so a newly added
// IR kind is dropped silently rather than failing the build. These tests
// enumerate every kind in the union so that adding one breaks something here.
describe('synthesizeStructs — IR kind coverage', () => {
  const read = at(RCX, 0);
  const other = at(RCX, 8);

  /** One statement per IRStmt kind, all 17. */
  function everyStmtKind(): IRStmt[] {
    return [
      assign(irReg('eax', 4), read),
      store(irBinary('+', RCX, irConst(8)), irConst(1)),
      callStmt('memcpy', [read]),
      { kind: 'return', value: read },
      { kind: 'if', condition: read, thenBody: [assign(irReg('eax', 4), read)], elseBody: [assign(irReg('eax', 4), read)] },
      { kind: 'while', condition: read, body: [assign(irReg('eax', 4), read)] },
      { kind: 'do_while', condition: read, body: [assign(irReg('eax', 4), read)] },
      { kind: 'for', init: assign(irReg('esi', 4), read), condition: read, update: assign(irReg('esi', 4), read), body: [assign(irReg('eax', 4), read)] },
      { kind: 'switch', expr: read, cases: [{ values: [0], body: [assign(irReg('eax', 4), read)] }], defaultBody: [assign(irReg('eax', 4), read)] },
      { kind: 'goto', label: 'loc_1' },
      { kind: 'label', name: 'loc_1' },
      { kind: 'comment', text: 'note' },
      { kind: 'raw', text: '__asm { cpuid }' },
      { kind: 'break' },
      { kind: 'continue' },
      { kind: 'phi', dest: irReg('eax', 4), operands: [{ blockId: 0, value: irReg('ebx', 4) }] },
      { kind: 'try', body: [assign(irReg('eax', 4), read)], handler: [assign(irReg('eax', 4), read)], filterExpr: read },
    ];
  }

  it('passes every statement kind through without loss', () => {
    const body = [assign(irReg('ebx', 4), other), ...everyStmtKind()];
    const out = synthesizeStructs(fn(body), new StructRegistry());
    expect(out.body).toHaveLength(body.length);
    expect(out.body.map(s => s.kind)).toEqual([
      // The store at index 2 becomes an assign to a field.
      ...body.map((s, i) => (i === 2 ? 'assign' : s.kind)),
    ]);
  });

  it('rewrites the struct access inside every statement kind that carries one', () => {
    const out = synthesizeStructs(fn([assign(irReg('ebx', 4), other), ...everyStmtKind()]), new StructRegistry());
    const json = JSON.stringify(out.body);
    expect(json).not.toContain('"kind":"deref"');
    expect(json).toContain('"kind":"field_access"');
  });

  it('returns expression-free statements unchanged by identity', () => {
    const inert: IRStmt[] = [
      { kind: 'goto', label: 'loc_1' },
      { kind: 'label', name: 'loc_1' },
      { kind: 'comment', text: 'note' },
      { kind: 'raw', text: '__asm { cpuid }' },
      { kind: 'break' },
      { kind: 'continue' },
      { kind: 'phi', dest: irReg('eax', 4), operands: [{ blockId: 0, value: irReg('ebx', 4) }] },
    ];
    const out = synthesizeStructs(fn([...twoFieldBody(), ...inert]), new StructRegistry());
    expect(out.body.slice(2)).toEqual(inert);
  });

  /** One expression per IRExpr kind, each wrapping a struct field access. */
  const everyExprKind = (inner: IRExpr): IRExpr[] => [
    irConst(1),
    irReg('r9', 8),
    irVar('v', 8),
    irBinary('+', inner, irConst(1)),
    irUnary('~', inner),
    irDeref(irBinary('+', RCX, irConst(0x30)), 8),
    { kind: 'call', target: 'f', args: [inner] },
    { kind: 'cast', type: 'int64_t', operand: inner },
    { kind: 'ternary', condition: inner, then: inner, else: irConst(0) },
    { kind: 'field_access', base: inner, structId: 's', fieldOffset: 0, fieldName: 'f', size: 4 },
    { kind: 'array_access', base: inner, index: inner, elementSize: 4, size: 4 },
    { kind: 'unknown', text: '?' },
  ];

  it('walks into every expression kind', () => {
    const body: IRStmt[] = [
      assign(irReg('ebx', 4), other),
      ...everyExprKind(read).map((e, i) => assign(irReg(`r${i % 8}`, 8), e)),
    ];
    const out = synthesizeStructs(fn(body), new StructRegistry());
    const json = JSON.stringify(out.body);
    // Only the deliberately unrelated deref at offset 0x30 may survive, and it
    // is itself a field of the same base, so nothing should remain.
    expect(json).not.toContain('"kind":"deref"');
  });

  it('does not crash on an expression kind that carries no sub-expressions', () => {
    const out = synthesizeStructs(
      fn([...twoFieldBody(), assign(irReg('eax', 4), { kind: 'unknown', text: '?' })]),
      new StructRegistry(),
    );
    expect(out.body[2]).toEqual(assign(irReg('eax', 4), { kind: 'unknown', text: '?' }));
  });
});

describe('synthesizeStructs — base aliasing', () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());

  it('follows a register copy to a single base', () => {
    const out = run([
      assign(irReg('rbx', 8), RCX),
      assign(irReg('eax', 4), at(irReg('rbx', 8), 0)),
      assign(irReg('edx', 4), at(RCX, 8)),
    ]);
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map(f => f.offset)).toEqual([0, 8]);
  });

  it('follows a transitive chain of copies', () => {
    const out = run([
      assign(irReg('rbx', 8), RCX),
      assign(irReg('r8', 8), irReg('rbx', 8)),
      assign(irReg('eax', 4), at(irReg('r8', 8), 0)),
      assign(irReg('edx', 4), at(RCX, 8)),
    ]);
    expect(out.typedefs?.[0].fields).toHaveLength(2);
  });

  it('does not loop forever on a circular alias', () => {
    const out = run([
      assign(irReg('rbx', 8), RCX),
      assign(RCX, irReg('rbx', 8)),
      ...twoFieldBody(irReg('rbx', 8)),
    ]);
    expect(out.typedefs).toHaveLength(1);
  });

  // KNOWN BUG (reported, not fixed): the alias map is flow-insensitive and the
  // last copy in the function wins, so accesses made through a register before
  // it was reassigned are attributed to the wrong base. Here the two RBX reads
  // happen while RBX aliases RCX, but they are credited to RDX.
  it('attributes accesses to the last base a register was ever copied from', () => {
    const out = run([
      assign(irReg('rbx', 8), RCX),
      assign(irReg('eax', 4), at(irReg('rbx', 8), 0)),
      assign(irReg('esi', 4), at(irReg('rbx', 8), 8)),
      assign(irReg('rbx', 8), RDX),
      assign(irReg('edi', 4), at(irReg('rbx', 8), 0x10)),
    ]);
    // All three offsets land in one struct keyed on RDX, even though 0 and 8
    // were read through RCX.
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map(f => f.offset)).toEqual([0, 8, 0x10]);
  });

  it('only follows plain copies, not arithmetic', () => {
    const out = run([
      assign(irReg('rbx', 8), irBinary('+', RCX, irConst(0x10))),
      assign(irReg('eax', 4), at(irReg('rbx', 8), 0)),
      assign(irReg('edx', 4), at(irReg('rbx', 8), 8)),
      assign(irReg('esi', 4), at(RCX, 0)),
    ]);
    // RBX is its own base; RCX has a single offset and is not a candidate.
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map(f => f.offset)).toEqual([0, 8]);
  });
});

describe('synthesizeStructs — array accesses', () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());

  // KNOWN BUG (reported, not fixed): synthesizeStructs returns early when no
  // base has 2+ distinct offsets, so the IR rewrite never runs. An indexed
  // access is only converted to IRArrayAccess when some *other* base in the
  // same function happens to qualify as a struct.
  it('leaves an indexed access alone when the function has no struct candidate', () => {
    const body = [assign(irReg('eax', 4), idx(RCX, RDX, 4))];
    const out = synthesizeStructs(fn(body), new StructRegistry());
    expect(out.body).toBe(body); // unchanged — no array_access
  });

  it('converts an indexed access once any struct candidate exists', () => {
    const out = run([
      ...twoFieldBody(irReg('r8', 8)),
      assign(irReg('eax', 4), idx(RCX, RDX, 4)),
    ]);
    expect(out.body[2]).toMatchObject({
      src: { kind: 'array_access', base: RCX, index: RDX, elementSize: 4, size: 4 },
    });
  });

  it('accepts every architectural scale', () => {
    for (const scale of [1, 2, 4, 8]) {
      const out = run([
        ...twoFieldBody(irReg('r8', 8)),
        assign(irReg('eax', 4), idx(RCX, RDX, scale)),
      ]);
      expect((out.body[2] as { src: { kind: string } }).src.kind, `scale ${scale}`).toBe('array_access');
    }
  });

  it('rejects a scale that is not a power of two', () => {
    const out = run([
      ...twoFieldBody(irReg('r8', 8)),
      assign(irReg('eax', 4), idx(RCX, RDX, 3)),
    ]);
    expect((out.body[2] as { src: { kind: string } }).src.kind).toBe('deref');
  });

  it('does not convert an indexed access at a non-zero offset', () => {
    const addr = irBinary('+', irBinary('+', RCX, irBinary('*', RDX, irConst(4))), irConst(0x10));
    const out = run([...twoFieldBody(irReg('r8', 8)), assign(irReg('eax', 4), irDeref(addr, 4))]);
    expect((out.body[2] as { src: { kind: string } }).src.kind).toBe('deref');
  });

  it('names an indexed field as an array in the struct definition', () => {
    const out = run([
      assign(irReg('eax', 4), at(RCX, 0)),
      assign(irReg('ebx', 4), idx(irBinary('+', RCX, irConst(8)), RDX, 4)),
    ]);
    const arrayField = out.typedefs?.[0].fields.find(f => f.isArray);
    expect(arrayField).toMatchObject({ name: 'array_0x8', arrayElementSize: 4 });
  });
});

describe('synthesizeStructs — field type inference', () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());
  const typeAt = (out: IRFunction, offset: number) =>
    out.typedefs?.[0].fields.find(f => f.offset === offset)?.type;

  it('defaults a field to an unsigned integer of the access size', () => {
    expect(typeAt(run(twoFieldBody()), 0)).toEqual({ kind: 'int', size: 4, signed: false });
  });

  it('marks a field signed when it is compared with a signed operator', () => {
    const out = run([
      ...twoFieldBody(),
      { kind: 'if', condition: irBinary('<', at(RCX, 0), irConst(10)), thenBody: [] },
    ]);
    expect(typeAt(out, 0)).toEqual({ kind: 'int', size: 4, signed: true });
  });

  it('does not mark a field signed for an unsigned comparison', () => {
    const out = run([
      ...twoFieldBody(),
      { kind: 'if', condition: irBinary('u<', at(RCX, 0), irConst(10)), thenBody: [] },
    ]);
    expect(typeAt(out, 0)).toMatchObject({ signed: false });
  });

  it('marks a field signed from a loop condition too', () => {
    const out = run([
      ...twoFieldBody(),
      { kind: 'while', condition: irBinary('>=', at(RCX, 0), irConst(0)), body: [] },
    ]);
    expect(typeAt(out, 0)).toMatchObject({ signed: true });
  });

  it('types a 16-byte access as a float', () => {
    const out = run([
      assign(irReg('xmm0', 16), at(RCX, 0, 16)),
      assign(irReg('ebx', 4), at(RCX, 0x20)),
    ]);
    expect(typeAt(out, 0)).toEqual({ kind: 'float', size: 4 });
  });

  it('types a field passed to a function as a pointer', () => {
    const out = run([...twoFieldBody(), callStmt('memcpy', [at(RCX, 8)])]);
    expect(typeAt(out, 8)).toEqual({ kind: 'ptr', pointee: { kind: 'unknown' } });
  });

  it('leaves a byte-sized field alone when it is passed to a function', () => {
    const out = run([
      assign(irReg('al', 1), at(RCX, 0, 1)),
      assign(irReg('ebx', 4), at(RCX, 8)),
      callStmt('f', [at(RCX, 0, 1)]),
    ]);
    expect(typeAt(out, 0)).toMatchObject({ kind: 'int', size: 1 });
  });

  it('types a field as a pointer when a loaded value is stored into it', () => {
    const out = run([
      ...twoFieldBody(),
      store(irBinary('+', RCX, irConst(8)), irDeref(irReg('r8', 8), 8)),
    ]);
    expect(typeAt(out, 8)).toEqual({ kind: 'ptr', pointee: { kind: 'unknown' } });
  });
});

describe('synthesizeStructs — cross-function registry state', () => {
  const twoFn = (body: IRStmt[], address: number) => fn(body, { address, name: `sub_${address.toString(16)}` });

  it('reuses one struct for two functions with the same layout', () => {
    const reg = new StructRegistry();
    const a = synthesizeStructs(twoFn(twoFieldBody(RCX), 0x401000), reg);
    const b = synthesizeStructs(twoFn(twoFieldBody(RDX), 0x402000), reg);
    expect(b.typedefs?.[0].id).toBe(a.typedefs?.[0].id);
    expect(reg.getAll()).toHaveLength(1);
  });

  // This is the designed sharing, and it is why the registry is not cleared
  // between functions: a struct seen partially in one function is completed by
  // another. The merge criterion is field *shape* only, though — see below.
  it('completes a struct across two functions that see different fields', () => {
    const reg = new StructRegistry();
    synthesizeStructs(twoFn([
      assign(irReg('eax', 4), at(RCX, 0)),
      assign(irReg('ebx', 4), at(RCX, 8)),
    ], 0x401000), reg);
    const b = synthesizeStructs(twoFn([
      assign(irReg('eax', 4), at(RCX, 0)),
      assign(irReg('ebx', 4), at(RCX, 8)),
      assign(irReg('ecx', 4), at(RCX, 16)),
    ], 0x402000), reg);
    expect(reg.getAll()).toHaveLength(1);
    expect(b.typedefs?.[0].fields.map(f => f.offset)).toEqual([0, 8, 16]);
  });

  // KNOWN BUG (reported, not fixed): the only evidence used to decide that two
  // bases are the same type is the set of "offset:size" pairs, so unrelated
  // structs whose observed fields happen to nest are merged session-wide. The
  // second function is then emitted with a typedef containing a field it never
  // touched, and both functions print the same struct name.
  it('merges unrelated types whose observed fields happen to nest', () => {
    const reg = new StructRegistry();
    // Function A sees a 3-field object.
    synthesizeStructs(twoFn([
      assign(irReg('eax', 4), at(RCX, 0)),
      assign(irReg('ebx', 4), at(RCX, 8)),
      assign(irReg('ecx', 4), at(RCX, 16)),
    ], 0x401000), reg);
    // Function B touches a completely different object at offsets 0 and 8.
    const b = synthesizeStructs(twoFn([
      assign(irReg('eax', 4), at(irVar('unrelated', 8), 0)),
      assign(irReg('ebx', 4), at(irVar('unrelated', 8), 8)),
    ], 0x402000), reg);
    expect(reg.getAll()).toHaveLength(1);
    expect(b.typedefs?.[0].fields.map(f => f.offset)).toEqual([0, 8, 16]); // 16 is A's
  });

  // KNOWN BUG (reported, not fixed): StructDef objects are shared by reference.
  // A later function's type inference mutates the definition an earlier
  // function already returned, so an IRFunction's typedefs change after the
  // fact — its emitted C depends on what was decompiled afterwards.
  it('mutates an already-returned typedef when a later function is processed', () => {
    const reg = new StructRegistry();
    const a = synthesizeStructs(twoFn(twoFieldBody(RCX), 0x401000), reg);
    expect(a.typedefs?.[0].fields[0].type).toMatchObject({ kind: 'int', signed: false });

    synthesizeStructs(twoFn([
      ...twoFieldBody(RDX),
      { kind: 'if', condition: irBinary('<', at(RDX, 0), irConst(0)), thenBody: [] },
    ], 0x402000), reg);

    // A's typedef was never re-derived, yet it changed.
    expect(a.typedefs?.[0].fields[0].type).toMatchObject({ signed: true });
  });

  it('isolates functions once the registry is cleared', () => {
    const reg = new StructRegistry();
    const a = synthesizeStructs(twoFn(twoFieldBody(RCX), 0x401000), reg);
    reg.clear();
    const b = synthesizeStructs(twoFn(twoFieldBody(RDX), 0x402000), reg);
    expect(b.typedefs?.[0].id).toBe('struct_0');
    expect(a.typedefs?.[0].id).toBe('struct_0'); // same name, different object
    expect(b.typedefs?.[0]).not.toBe(a.typedefs?.[0]);
  });

  it('only reports the typedefs the function actually uses', () => {
    const reg = new StructRegistry();
    synthesizeStructs(twoFn([
      assign(irReg('eax', 4), at(RCX, 0)),
      assign(irReg('ebx', 4), at(RCX, 0x40, 8)),
    ], 0x401000), reg);
    const b = synthesizeStructs(twoFn([
      assign(irReg('eax', 4), at(RDX, 4, 2)),
      assign(irReg('ebx', 4), at(RDX, 12, 2)),
    ], 0x402000), reg);
    expect(reg.getAll().length).toBeGreaterThan(1);
    expect(b.typedefs).toHaveLength(1);
  });
});

describe('synthesizeStructs — call-site propagation', () => {
  it('links a struct base passed to a known function address', () => {
    const reg = new StructRegistry();
    const out = synthesizeStructs(fn([...twoFieldBody(), callStmt('sub_402000', [RCX])]), reg);
    expect(reg.getParamStruct(0x402000, 0)).toBe(out.typedefs?.[0].id);
  });

  it('uses the argument position as the parameter index', () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt('sub_402000', [irConst(1), RCX])]), reg);
    expect(reg.getParamStruct(0x402000, 1)).toBeDefined();
    expect(reg.getParamStruct(0x402000, 0)).toBeUndefined();
  });

  it('ignores an argument that is not a tracked base', () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt('sub_402000', [irReg('r9', 8)])]), reg);
    expect(reg.getParamStruct(0x402000, 0)).toBeUndefined();
  });

  it('ignores a call whose target is not address-like', () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt('memcpy', [RCX])]), reg);
    expect(reg.getAll()).toHaveLength(1);
    expect(reg.getParamStruct(Number.NaN, 0)).toBeUndefined();
  });

  // KNOWN BUG (reported, not fixed): the call target is turned into an address
  // with `parseInt(target, 16)`, which happily parses the leading hex-looking
  // characters of an imported function's *name*. `CloseHandle` becomes 0xC, so
  // parameter links are recorded against nonsense addresses that collide with
  // each other and with real function addresses.
  it('parses an import name that starts with hex digits as an address', () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt('CloseHandle', [RCX])]), reg);
    expect(reg.getParamStruct(0xc, 0)).toBeDefined(); // 'C' parsed as an address
  });
});
