import { describe, expect, it } from "vitest";
import type { IRExpr, IRFunction, IRStmt } from "../ir";
import { irBinary, irConst, irDeref, irReg, irUnary, irVar } from "../ir";
import {
  buildFingerprint,
  decomposeAddress,
  type StructField,
  type StructGroupReport,
  StructRegistry,
  synthesizeStructs,
} from "../structs";
import type { DecompType } from "../typeInfer";

const UINT = (size: number): DecompType => ({ kind: "int", size, signed: false });

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
const assign = (dest: IRExpr, src: IRExpr): IRStmt => ({ kind: "assign", dest, src });
const store = (address: IRExpr, value: IRExpr, size = 4): IRStmt => ({
  kind: "store",
  address,
  value,
  size,
});
const callStmt = (target: string, args: IRExpr[] = [], display?: string): IRStmt => ({
  kind: "call_stmt",
  call: { kind: "call", target, args, display },
});

/** `*(base + offset)` */
const at = (base: IRExpr, offset: number, size = 4): IRExpr =>
  irDeref(offset === 0 ? base : irBinary("+", base, irConst(offset)), size);
/** `*(base + index * scale)` */
const idx = (base: IRExpr, index: IRExpr, scale: number, size = 4): IRExpr =>
  irDeref(irBinary("+", base, irBinary("*", index, irConst(scale))), size);

const RCX = irReg("rcx", 8);
const RDX = irReg("rdx", 8);

function fn(body: IRStmt[], over: Partial<IRFunction> = {}): IRFunction {
  return {
    name: "sub_401000",
    address: 0x401000,
    returnType: "void",
    params: [],
    locals: [],
    body,
    ...over,
  };
}

/** A function whose base RCX is accessed at two distinct offsets — the minimum
 *  shape that makes a struct candidate. */
function twoFieldBody(base: IRExpr = RCX): IRStmt[] {
  return [assign(irReg("eax", 4), at(base, 0)), assign(irReg("ebx", 4), at(base, 8))];
}

describe("buildFingerprint", () => {
  it("formats fields as offset:size pairs", () => {
    expect(buildFingerprint([field(0, 8), field(8, 4)])).toBe("0:8,8:4");
  });

  it("sorts by offset regardless of input order", () => {
    expect(buildFingerprint([field(16, 4), field(0, 8)])).toBe("0:8,16:4");
  });

  it("returns an empty string for no fields", () => {
    expect(buildFingerprint([])).toBe("");
  });

  it("does not mutate the input array", () => {
    const fields = [field(16, 4), field(0, 8)];
    buildFingerprint(fields);
    expect(fields.map((f) => f.offset)).toEqual([16, 0]);
  });
});

describe("decomposeAddress", () => {
  it("treats a bare register as a base at offset zero", () => {
    expect(decomposeAddress(RCX)).toEqual({ base: RCX, offset: 0, index: null, scale: 0 });
  });

  it("treats a bare variable as a base", () => {
    const v = irVar("p", 8);
    expect(decomposeAddress(v)).toEqual({ base: v, offset: 0, index: null, scale: 0 });
  });

  it("treats a bare constant as an offset with no base", () => {
    expect(decomposeAddress(irConst(0x404000))).toEqual({
      base: null,
      offset: 0x404000,
      index: null,
      scale: 0,
    });
  });

  it("decomposes base + displacement", () => {
    expect(decomposeAddress(irBinary("+", RCX, irConst(0x10)))).toEqual({
      base: RCX,
      offset: 0x10,
      index: null,
      scale: 0,
    });
  });

  it("accumulates several constant terms", () => {
    const addr = irBinary("+", irBinary("+", RCX, irConst(8)), irConst(4));
    expect(decomposeAddress(addr)?.offset).toBe(12);
  });

  it("accepts a negative displacement expressed as a negative constant", () => {
    expect(decomposeAddress(irBinary("+", RCX, irConst(-8)))?.offset).toBe(-8);
  });

  it("flattens a nested addition chain", () => {
    const addr = irBinary("+", irBinary("+", RCX, irBinary("*", RDX, irConst(4))), irConst(0x20));
    expect(decomposeAddress(addr)).toEqual({ base: RCX, offset: 0x20, index: RDX, scale: 4 });
  });

  it("extracts a multiplicative scaled index", () => {
    const addr = irBinary("+", RCX, irBinary("*", RDX, irConst(8)));
    expect(decomposeAddress(addr)).toEqual({ base: RCX, offset: 0, index: RDX, scale: 8 });
  });

  it("extracts a shift-encoded scaled index", () => {
    const addr = irBinary("+", RCX, irBinary("<<", RDX, irConst(3)));
    expect(decomposeAddress(addr)?.scale).toBe(8);
  });

  it("keeps a scale that is not a power of two", () => {
    // The array-access rewrite filters these out later; decomposition does not.
    const addr = irBinary("+", RCX, irBinary("*", RDX, irConst(3)));
    expect(decomposeAddress(addr)?.scale).toBe(3);
  });

  it("produces a wrapped scale for an oversized shift", () => {
    // `1 << 31` is negative in JS and `1 << 32` wraps to 1 — neither survives
    // the {1,2,4,8} filter, so an absurd shift cannot fake an array access.
    expect(decomposeAddress(irBinary("+", RCX, irBinary("<<", RDX, irConst(31))))?.scale).toBe(
      1 << 31,
    );
    expect(decomposeAddress(irBinary("+", RCX, irBinary("<<", RDX, irConst(32))))?.scale).toBe(1);
  });

  it("decomposes a subtraction of a constant into a negative offset", () => {
    // `base - 8` is the same access as `base + (-8)`.
    expect(decomposeAddress(irBinary("-", RCX, irConst(8)))).toMatchObject({
      base: RCX,
      offset: -8,
      index: null,
    });
  });

  it("returns null when the subtrahend is not a constant", () => {
    // Subtracting a register is not a field offset.
    expect(decomposeAddress(irBinary("-", RCX, RDX))).toBeNull();
  });

  it("returns null for a non-additive expression", () => {
    expect(decomposeAddress(irBinary("*", RCX, irConst(4)))).toBeNull();
    expect(decomposeAddress(irUnary("~", RCX))).toBeNull();
    expect(decomposeAddress(irDeref(RCX, 8))).toBeNull();
    expect(decomposeAddress({ kind: "unknown", text: "?" })).toBeNull();
  });

  it("returns null for an addition of constants only", () => {
    expect(decomposeAddress(irBinary("+", irConst(4), irConst(8)))).toBeNull();
  });

  it("returns null when two plain registers are added", () => {
    expect(decomposeAddress(irBinary("+", RCX, RDX))).toBeNull();
  });

  it("takes a second scaled term as the base rather than failing", () => {
    const addr = irBinary("+", irBinary("*", RCX, irConst(4)), irBinary("*", RDX, irConst(8)));
    const d = decomposeAddress(addr);
    expect(d?.index).toEqual(RCX);
    expect(d?.scale).toBe(4);
    expect(d?.base).toEqual(irBinary("*", RDX, irConst(8)));
  });

  it("returns null for three non-constant terms", () => {
    const addr = irBinary("+", irBinary("+", RCX, RDX), irReg("r8", 8));
    expect(decomposeAddress(addr)).toBeNull();
  });
});

describe("StructRegistry", () => {
  it("creates sequentially numbered structs", () => {
    const reg = new StructRegistry();
    expect(reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]).id).toBe("struct_0");
    expect(reg.findOrCreate("0:4,16:4", [field(0, 4), field(16, 4)]).id).toBe("struct_1");
  });

  it("sorts fields and computes the total size on creation", () => {
    const reg = new StructRegistry();
    const def = reg.findOrCreate("0:4,16:8", [field(16, 8), field(0, 4)]);
    expect(def.fields.map((f) => f.offset)).toEqual([0, 16]);
    expect(def.totalSize).toBe(24);
  });

  it("reports a zero total size for a struct with no fields", () => {
    expect(new StructRegistry().findOrCreate("", []).totalSize).toBe(0);
  });

  it("returns the same struct for an identical fingerprint", () => {
    const reg = new StructRegistry();
    const a = reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    const b = reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    expect(b.id).toBe(a.id);
    expect(reg.getAll()).toHaveLength(1);
  });

  it("merges a fingerprint that is a subset of an existing one", () => {
    const reg = new StructRegistry();
    const big = reg.findOrCreate("0:4,8:4,16:4,24:4", [
      field(0, 4),
      field(8, 4),
      field(16, 4),
      field(24, 4),
    ]);
    const small = reg.findOrCreate("0:4,8:4,16:4", [field(0, 4), field(8, 4), field(16, 4)]);
    expect(small.id).toBe(big.id);
    expect(reg.getAll()).toHaveLength(1);
  });

  it("merges a fingerprint that is a superset of an existing one", () => {
    const reg = new StructRegistry();
    const small = reg.findOrCreate("0:4,8:4,16:4", [field(0, 4), field(8, 4), field(16, 4)]);
    const big = reg.findOrCreate("0:4,8:4,16:4,24:4", [
      field(0, 4),
      field(8, 4),
      field(16, 4),
      field(24, 4),
    ]);
    expect(big.id).toBe(small.id);
    expect(big.fields.map((f) => f.offset)).toEqual([0, 8, 16, 24]);
    expect(big.totalSize).toBe(28);
  });

  // The cost of MIN_SUBSET_MERGE_FIELDS, pinned deliberately. Two distinct
  // offsets is the minimum a candidate can have, so two-field shapes are both
  // the most common and the weakest evidence; they no longer merge through the
  // subset path. Failing to merge is the benign direction — two struct_N
  // declarations instead of one wrongly shared. An *exact* fingerprint match
  // still merges, whatever the field count.
  it("refuses a subset merge when the smaller shape has fewer than three fields", () => {
    const reg = new StructRegistry();
    reg.findOrCreate("0:4,8:4,16:4", [field(0, 4), field(8, 4), field(16, 4)]);
    reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    expect(reg.getAll()).toHaveLength(2);
  });

  it("still merges a two-field shape on an exact fingerprint match", () => {
    const reg = new StructRegistry();
    const a = reg.findOrCreate("0:8,8:8", [field(0, 8), field(8, 8)]);
    const b = reg.findOrCreate("0:8,8:8", [field(0, 8), field(8, 8)]);
    expect(b.id).toBe(a.id);
    expect(reg.getAll()).toHaveLength(1);
  });

  it("refuses a subset merge whose layouts contradict each other", () => {
    // 4:4 and 8:4 sit inside the 8-byte field at 0, so the two shapes cannot
    // describe the same type however well their offset sets nest.
    const reg = new StructRegistry();
    reg.findOrCreate("0:8,4:4,8:4", [field(0, 8), field(4, 4), field(8, 4)]);
    reg.findOrCreate("0:8,4:4,8:4,16:4", [field(0, 8), field(4, 4), field(8, 4), field(16, 4)]);
    expect(reg.getAll()).toHaveLength(2);
  });

  it("keeps structs with overlapping but non-nested field sets apart", () => {
    const reg = new StructRegistry();
    reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    reg.findOrCreate("0:4,16:4", [field(0, 4), field(16, 4)]);
    expect(reg.getAll()).toHaveLength(2);
  });

  it("treats a differing field size as a different slot", () => {
    const reg = new StructRegistry();
    reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    reg.findOrCreate("0:8,8:8", [field(0, 8), field(8, 8)]);
    expect(reg.getAll()).toHaveLength(2);
  });

  // isSubset() is vacuously true for an empty set, which used to fold a
  // fieldless struct into whichever struct happened to be indexed first. The
  // minimum-field-count guard rejects it as the degenerate case.
  it("keeps an empty fingerprint separate from existing structs", () => {
    const reg = new StructRegistry();
    const first = reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    const empty = reg.findOrCreate("", []);
    expect(empty.id).not.toBe(first.id);
    expect(reg.getAll()).toHaveLength(2);
  });

  describe("mergeFields", () => {
    it("adds a field at a new offset", () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate("0:4", [field(0, 4)]);
      reg.mergeFields(def.id, [field(8, 4)]);
      expect(def.fields.map((f) => f.offset)).toEqual([0, 8]);
    });

    it("keeps the larger size for an existing offset", () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate("0:4", [field(0, 4)]);
      reg.mergeFields(def.id, [field(0, 8)]);
      expect(def.fields[0].size).toBe(8);
      reg.mergeFields(def.id, [field(0, 2)]);
      expect(def.fields[0].size).toBe(8);
    });

    // The promotion is the cross-function refinement mechanism working: another
    // function's indexed access at the same offset IS evidence of an array. What
    // this also pins is the NAME, which used to be left as the field was created
    // — so the merged field was declared `uint64_t field_0x8[];`, an identifier
    // saying scalar member over brackets saying array, in a declaration nothing
    // else here could see was self-contradictory (peek-a-bin-tm29).
    it("promotes a field to an array when a later access is indexed, and renames it", () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate("0:4", [field(0, 4)]);
      expect(def.fields[0].name).toBe("field_0x0");
      reg.mergeFields(def.id, [field(0, 4, { isArray: true, arrayElementSize: 4 })]);
      expect(def.fields[0]).toMatchObject({
        isArray: true,
        arrayElementSize: 4,
        name: "array_0x0",
      });
    });

    // The other direction of the same claim: a merge that carries no array
    // evidence must leave the name alone. Renaming on every merge would make the
    // gate green by spelling every member `array_`, which is the same defect
    // pointing the other way.
    it("leaves a field's name alone when the merge carries no array evidence", () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate("8:4", [field(8, 4)]);
      reg.mergeFields(def.id, [field(8, 8)]);
      expect(def.fields[0]).toMatchObject({ name: "field_0x8", size: 8, isArray: false });
    });

    // A field the merge ADDS keeps the name its own evidence built, which for an
    // indexed access is already `array_`. Guards the copy path against acquiring
    // the promotion path's rename.
    it("keeps an added array field's own name", () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate("0:4", [field(0, 4)]);
      reg.mergeFields(def.id, [
        field(8, 4, { isArray: true, arrayElementSize: 4, name: "array_0x8" }),
      ]);
      expect(def.fields[1]).toMatchObject({ name: "array_0x8", isArray: true });
    });

    it("keeps fields sorted and the total size current", () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate("8:4", [field(8, 4)]);
      reg.mergeFields(def.id, [field(0, 4), field(32, 8)]);
      expect(def.fields.map((f) => f.offset)).toEqual([0, 8, 32]);
      expect(def.totalSize).toBe(40);
    });

    it("ignores an unknown struct id", () => {
      const reg = new StructRegistry();
      expect(() => reg.mergeFields("struct_99", [field(0, 4)])).not.toThrow();
    });

    // The caller's array is scratch, rebuilt per function from that function's
    // access patterns. Adopting its objects made the registry alias memory the
    // caller still owned, so a later edit to the scratch field silently rewrote
    // the shared struct definition.
    it("copies an incoming field rather than adopting the caller object", () => {
      const reg = new StructRegistry();
      const def = reg.findOrCreate("0:4", [field(0, 4)]);
      const incoming = field(8, 4);
      reg.mergeFields(def.id, [incoming]);

      incoming.name = "mutated";
      incoming.size = 99;
      incoming.type = { kind: "handle" };
      incoming.isArray = true;

      const stored = reg.get(def.id)?.fields.find((f) => f.offset === 8);
      expect(stored).not.toBe(incoming);
      expect(stored).toMatchObject({ name: "field_0x8", size: 4, isArray: false, type: UINT(4) });
      expect(reg.get(def.id)?.totalSize).toBe(12);
    });
  });

  it("looks structs up by id", () => {
    const reg = new StructRegistry();
    const def = reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    expect(reg.get(def.id)).toBe(def);
    expect(reg.get("struct_99")).toBeUndefined();
  });

  it("round-trips parameter links", () => {
    const reg = new StructRegistry();
    reg.linkParam(0x401000, 1, "struct_0");
    expect(reg.getParamStruct(0x401000, 1)).toBe("struct_0");
    expect(reg.getParamStruct(0x401000, 0)).toBeUndefined();
    expect(reg.getParamStruct(0x402000, 1)).toBeUndefined();
  });

  it("clears every kind of state and restarts numbering", () => {
    const reg = new StructRegistry();
    reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    reg.linkParam(1, 0, "struct_0");
    reg.clear();
    expect(reg.getAll()).toEqual([]);
    expect(reg.getParamStruct(1, 0)).toBeUndefined();
    expect(reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]).id).toBe("struct_0");
  });

  it("hands out the live StructDef, not a copy", () => {
    // Callers mutate field types in place; that is how inference reaches the
    // registry, and it is also how one function's pass reaches another's.
    const reg = new StructRegistry();
    const def = reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    def.fields[0].type = { kind: "handle" };
    expect(reg.get(def.id)?.fields[0].type).toEqual({ kind: "handle" });
  });
});

describe("synthesizeStructs — candidate selection", () => {
  const run = (body: IRStmt[], reg = new StructRegistry()) => synthesizeStructs(fn(body), reg);

  it("returns the function untouched when there are no memory accesses", () => {
    const func = fn([assign(irReg("eax", 4), irConst(1))]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it("returns the function untouched for a single accessed offset", () => {
    const func = fn([assign(irReg("eax", 4), at(RCX, 0))]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it("does not count two accesses at the same offset as two fields", () => {
    const func = fn([assign(irReg("eax", 4), at(RCX, 8)), assign(irReg("ebx", 4), at(RCX, 8, 8))]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it("synthesizes a struct from two distinct offsets on one base", () => {
    const out = run(twoFieldBody());
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map((f) => [f.offset, f.name])).toEqual([
      [0, "field_0x0"],
      [8, "field_0x8"],
    ]);
  });

  it("rewrites matching dereferences to field accesses", () => {
    const out = run(twoFieldBody());
    expect(out.body[0]).toMatchObject({
      src: { kind: "field_access", base: RCX, fieldOffset: 0, fieldName: "field_0x0", size: 4 },
    });
    expect(out.body[1]).toMatchObject({ src: { kind: "field_access", fieldOffset: 8 } });
  });

  it("keeps the largest access size for a field", () => {
    const out = run([
      assign(irReg("al", 1), at(RCX, 0, 1)),
      assign(irReg("rax", 8), at(RCX, 0, 8)),
      assign(irReg("ebx", 4), at(RCX, 8)),
    ]);
    expect(out.typedefs?.[0].fields.find((f) => f.offset === 0)?.size).toBe(8);
  });

  it("reports the struct size as the end of its last field", () => {
    const out = run([
      assign(irReg("eax", 4), at(RCX, 0)),
      assign(irReg("rbx", 8), at(RCX, 0x18, 8)),
    ]);
    expect(out.typedefs?.[0].totalSize).toBe(0x20);
  });

  it("groups two different bases into two structs", () => {
    const out = run([...twoFieldBody(RCX), ...twoFieldBody(RDX)]);
    const ids = new Set(out.typedefs?.map((d) => d.id));
    // Both bases have the same shape, so the registry folds them together.
    expect(ids.size).toBe(1);
  });

  it("keeps bases with different shapes apart", () => {
    const out = run([
      assign(irReg("eax", 4), at(RCX, 0)),
      assign(irReg("ebx", 4), at(RCX, 8)),
      assign(irReg("ecx", 4), at(RDX, 0)),
      assign(irReg("edx", 4), at(RDX, 0x20)),
    ]);
    expect(out.typedefs).toHaveLength(2);
  });

  // `decomposeAddress` still folds `base - 8` into a negative offset — that is
  // what tells these two accesses apart at all — but a member of the object a
  // base names is at a non-negative offset from it, so the access before the
  // base is not one of its fields and does not count toward the two it takes to
  // be a candidate (peek-a-bin-u3v). It is still emitted, as byte arithmetic.
  it("does not count an access before the base as one of the base's fields", () => {
    const func = fn([
      assign(irReg("eax", 4), irDeref(irBinary("-", RCX, irConst(8)), 4)),
      assign(irReg("ebx", 4), at(RCX, 0)),
    ]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it("keeps the fields at and after a base an access reaches behind", () => {
    const out = run([
      assign(irReg("eax", 4), irDeref(irBinary("-", RCX, irConst(8)), 4)),
      assign(irReg("ebx", 4), at(RCX, 0)),
      assign(irReg("edx", 4), at(RCX, 8)),
    ]);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
    // The negative access keeps its own spelling rather than becoming a member.
    expect(out.body[0]).toMatchObject({ src: { kind: "deref" } });
  });

  it("does not make a field of a displacement that is an address", () => {
    // `[rcx + 0x412620]` is a global table indexed by a register, not a field
    // 4MB into an object — see MAX_FIELD_OFFSET.
    const out = run([
      assign(irReg("eax", 4), at(RCX, 0x412620)),
      assign(irReg("ebx", 4), at(RCX, 0)),
      assign(irReg("edx", 4), at(RCX, 8)),
    ]);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
    expect(out.body[0]).toMatchObject({ src: { kind: "deref" } });
  });

  it("does not make a second field of an access inside one already recovered", () => {
    // 8 bytes at 0 and 2 bytes at 2 are two readings of the same bytes; at most
    // one is a member, and C can spell neither pair.
    const out = run([
      assign(irReg("rax", 8), at(RCX, 0, 8)),
      assign(irReg("dx", 2), at(RCX, 2, 2)),
      assign(irReg("rbx", 8), at(RCX, 8, 8)),
    ]);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  it("does not synthesize a struct when the overlapping reading was the only other one", () => {
    const func = fn([
      assign(irReg("rax", 8), at(RCX, 0, 8)),
      assign(irReg("dx", 2), at(RCX, 2, 2)),
    ]);
    expect(synthesizeStructs(func, new StructRegistry())).toBe(func);
  });

  it("treats a variable base like a register base", () => {
    const p = irVar("p", 8);
    const out = run(twoFieldBody(p));
    expect(out.body[0]).toMatchObject({ src: { kind: "field_access", base: p } });
  });

  it("canonicalises sub-registers of the same base", () => {
    const out = run([
      assign(irReg("eax", 4), at(irReg("rcx", 8), 0)),
      assign(irReg("ebx", 4), at(irReg("ecx", 4), 8)),
    ]);
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields).toHaveLength(2);
  });
});

describe("synthesizeStructs — stores and nesting", () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());

  it("turns a store to a struct field into a field assignment", () => {
    const out = run([
      store(irBinary("+", RCX, irConst(8)), irConst(1)),
      assign(irReg("eax", 4), at(RCX, 0)),
    ]);
    expect(out.body[0]).toMatchObject({
      kind: "assign",
      dest: { kind: "field_access", fieldOffset: 8 },
      src: irConst(1),
    });
  });

  it("preserves the source address of a rewritten store", () => {
    const s: IRStmt = {
      kind: "store",
      address: irBinary("+", RCX, irConst(8)),
      value: irConst(1),
      size: 4,
      addr: 0x401005,
    };
    const out = run([s, assign(irReg("eax", 4), at(RCX, 0))]);
    expect(out.body[0]).toMatchObject({ addr: 0x401005 });
  });

  it("leaves a store to an unrelated address alone", () => {
    const out = run([...twoFieldBody(), store(irReg("r8", 8), irConst(1))]);
    expect(out.body[2]).toMatchObject({ kind: "store", address: irReg("r8", 8) });
  });

  // The assign case used to walk `dest` only when it was itself a deref, so an
  // access buried in a compound destination — `((int *)rcx->f8)[i] = 1` — was
  // never counted, and a base whose second offset only ever appeared there
  // failed to reach the two-offset candidate threshold.
  it("collects a struct access nested inside a non-deref assignment destination", () => {
    const out = run([
      assign(irReg("eax", 4), at(RCX, 0)),
      assign(
        { kind: "array_access", base: at(RCX, 8, 8), index: RDX, elementSize: 4, size: 4 },
        irConst(1),
      ),
    ]);
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
    // and the nested access is rewritten in place, not merely counted
    expect(out.body[1]).toMatchObject({
      dest: { kind: "array_access", base: { kind: "field_access", fieldOffset: 8 } },
    });
  });

  it("rewrites accesses nested in every compound statement", () => {
    const read = at(RCX, 0);
    const body: IRStmt[] = [
      assign(irReg("ebx", 4), at(RCX, 8)),
      {
        kind: "if",
        condition: read,
        thenBody: [assign(irReg("eax", 4), read)],
        elseBody: [assign(irReg("eax", 4), read)],
      },
      { kind: "while", condition: read, body: [assign(irReg("eax", 4), read)] },
      { kind: "do_while", condition: read, body: [assign(irReg("eax", 4), read)] },
      {
        kind: "for",
        init: assign(irReg("esi", 4), read),
        condition: read,
        update: assign(irReg("esi", 4), read),
        body: [assign(irReg("eax", 4), read)],
      },
      {
        kind: "switch",
        expr: read,
        cases: [{ values: [1], body: [assign(irReg("eax", 4), read)] }],
        defaultBody: [assign(irReg("eax", 4), read)],
      },
      {
        kind: "try",
        body: [assign(irReg("eax", 4), read)],
        handler: [assign(irReg("eax", 4), read)],
        filterExpr: read,
      },
      { kind: "return", value: read },
      callStmt("memcpy", [read]),
    ];
    const flat = JSON.stringify(synthesizeStructs(fn(body), new StructRegistry()).body);
    expect(flat).not.toContain('"kind":"deref"');
    expect(flat).toContain("field_access");
  });

  it("leaves statements it does not understand untouched", () => {
    const raw: IRStmt = { kind: "raw", text: "__asm { cpuid }" };
    const out = run([...twoFieldBody(), raw, { kind: "break" }, { kind: "goto", label: "L" }]);
    expect(out.body.slice(2)).toEqual([raw, { kind: "break" }, { kind: "goto", label: "L" }]);
  });

  it("rewrites through a cast and a ternary", () => {
    const read = at(RCX, 0);
    const out = run([
      assign(irReg("ebx", 4), at(RCX, 8)),
      assign(irReg("eax", 4), { kind: "cast", type: "int64_t", operand: read }),
      assign(irReg("edx", 4), { kind: "ternary", condition: read, then: read, else: irConst(0) }),
    ]);
    expect(JSON.stringify(out.body)).not.toContain('"kind":"deref"');
  });
});

// The walkers in this module (collectAccessPatterns' two walkers, rewriteStmt,
// rewriteExpr) either end in `default:` or fall off the end, so a newly added
// IR kind is dropped silently rather than failing the build. These tests
// enumerate every kind in the union so that adding one breaks something here.
describe("synthesizeStructs — IR kind coverage", () => {
  const read = at(RCX, 0);
  const other = at(RCX, 8);

  /** One statement per IRStmt kind, all 17. */
  function everyStmtKind(): IRStmt[] {
    return [
      assign(irReg("eax", 4), read),
      store(irBinary("+", RCX, irConst(8)), irConst(1)),
      callStmt("memcpy", [read]),
      { kind: "return", value: read },
      {
        kind: "if",
        condition: read,
        thenBody: [assign(irReg("eax", 4), read)],
        elseBody: [assign(irReg("eax", 4), read)],
      },
      { kind: "while", condition: read, body: [assign(irReg("eax", 4), read)] },
      { kind: "do_while", condition: read, body: [assign(irReg("eax", 4), read)] },
      {
        kind: "for",
        init: assign(irReg("esi", 4), read),
        condition: read,
        update: assign(irReg("esi", 4), read),
        body: [assign(irReg("eax", 4), read)],
      },
      {
        kind: "switch",
        expr: read,
        cases: [{ values: [0], body: [assign(irReg("eax", 4), read)] }],
        defaultBody: [assign(irReg("eax", 4), read)],
      },
      { kind: "goto", label: "loc_1" },
      { kind: "label", name: "loc_1" },
      { kind: "comment", text: "note" },
      { kind: "raw", text: "__asm { cpuid }" },
      { kind: "break" },
      { kind: "continue" },
      { kind: "phi", dest: irReg("eax", 4), operands: [{ blockId: 0, value: irReg("ebx", 4) }] },
      {
        kind: "try",
        body: [assign(irReg("eax", 4), read)],
        handler: [assign(irReg("eax", 4), read)],
        filterExpr: read,
      },
    ];
  }

  it("passes every statement kind through without loss", () => {
    const body = [assign(irReg("ebx", 4), other), ...everyStmtKind()];
    const out = synthesizeStructs(fn(body), new StructRegistry());
    expect(out.body).toHaveLength(body.length);
    expect(out.body.map((s) => s.kind)).toEqual([
      // The store at index 2 becomes an assign to a field.
      ...body.map((s, i) => (i === 2 ? "assign" : s.kind)),
    ]);
  });

  it("rewrites the struct access inside every statement kind that carries one", () => {
    const out = synthesizeStructs(
      fn([assign(irReg("ebx", 4), other), ...everyStmtKind()]),
      new StructRegistry(),
    );
    const json = JSON.stringify(out.body);
    expect(json).not.toContain('"kind":"deref"');
    expect(json).toContain('"kind":"field_access"');
  });

  it("returns expression-free statements unchanged by identity", () => {
    const inert: IRStmt[] = [
      { kind: "goto", label: "loc_1" },
      { kind: "label", name: "loc_1" },
      { kind: "comment", text: "note" },
      { kind: "raw", text: "__asm { cpuid }" },
      { kind: "break" },
      { kind: "continue" },
      { kind: "phi", dest: irReg("eax", 4), operands: [{ blockId: 0, value: irReg("ebx", 4) }] },
    ];
    const out = synthesizeStructs(fn([...twoFieldBody(), ...inert]), new StructRegistry());
    expect(out.body.slice(2)).toEqual(inert);
  });

  /** One expression per IRExpr kind, each wrapping a struct field access. */
  const everyExprKind = (inner: IRExpr): IRExpr[] => [
    irConst(1),
    irReg("r9", 8),
    irVar("v", 8),
    irBinary("+", inner, irConst(1)),
    irUnary("~", inner),
    irDeref(irBinary("+", RCX, irConst(0x30)), 8),
    { kind: "call", target: "f", args: [inner] },
    { kind: "cast", type: "int64_t", operand: inner },
    { kind: "ternary", condition: inner, then: inner, else: irConst(0) },
    { kind: "field_access", base: inner, structId: "s", fieldOffset: 0, fieldName: "f", size: 4 },
    { kind: "array_access", base: inner, index: inner, elementSize: 4, size: 4 },
    { kind: "unknown", text: "?" },
  ];

  it("walks into every expression kind", () => {
    const body: IRStmt[] = [
      assign(irReg("ebx", 4), other),
      ...everyExprKind(read).map((e, i) => assign(irReg(`r${i % 8}`, 8), e)),
    ];
    const out = synthesizeStructs(fn(body), new StructRegistry());
    const json = JSON.stringify(out.body);
    // Only the deliberately unrelated deref at offset 0x30 may survive, and it
    // is itself a field of the same base, so nothing should remain.
    expect(json).not.toContain('"kind":"deref"');
  });

  it("does not crash on an expression kind that carries no sub-expressions", () => {
    const out = synthesizeStructs(
      fn([...twoFieldBody(), assign(irReg("eax", 4), { kind: "unknown", text: "?" })]),
      new StructRegistry(),
    );
    expect(out.body[2]).toEqual(assign(irReg("eax", 4), { kind: "unknown", text: "?" }));
  });
});

describe("synthesizeStructs — base aliasing", () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());

  it("follows a register copy to a single base", () => {
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("edx", 4), at(RCX, 8)),
    ]);
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  it("follows a transitive chain of copies", () => {
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(irReg("r8", 8), irReg("rbx", 8)),
      assign(irReg("eax", 4), at(irReg("r8", 8), 0)),
      assign(irReg("edx", 4), at(RCX, 8)),
    ]);
    expect(out.typedefs?.[0].fields).toHaveLength(2);
  });

  it("does not loop forever on a circular alias", () => {
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(RCX, irReg("rbx", 8)),
      ...twoFieldBody(irReg("rbx", 8)),
    ]);
    expect(out.typedefs).toHaveLength(1);
  });

  // The reassigned register is dropped from the alias map, so its accesses are
  // no longer credited to whichever base it happened to hold last — and since
  // peek-a-bin-z8q7 they are no longer credited to each OTHER either. RBX holds
  // RCX's object for the first two accesses and RDX's for the third, so 0x10 is
  // not a member of the object 0 and 8 belong to. This used to assert all three
  // offsets in one declaration, on the reasoning that "the grouping survives";
  // the grouping was the fiction.
  it("does not credit accesses to the last base a register was ever copied from", () => {
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("esi", 4), at(irReg("rbx", 8), 8)),
      assign(irReg("rbx", 8), RDX),
      assign(irReg("edi", 4), at(irReg("rbx", 8), 0x10)),
    ]);
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  // The map is flow-insensitive — one entry per name, no program point — so a
  // name that holds different things at different points has no single correct
  // answer and is dropped entirely. Dropping costs a missed grouping; keeping
  // the last write credits earlier accesses to the wrong base.
  it("keeps the alias when a register is copied from the same base twice", () => {
    // Two writes that agree are not ambiguity, so RBX still resolves to RCX.
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("rbx", 8), RCX),
      assign(irReg("edx", 4), at(RCX, 8)),
    ]);
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  it("drops the alias of a register copied from two different bases", () => {
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("esi", 4), at(irReg("rbx", 8), 8)),
      assign(irReg("rbx", 8), RDX),
      assign(irReg("edi", 4), at(RDX, 0x10)),
      assign(irReg("r9d", 4), at(RDX, 0x18)),
    ]);
    // RBX becomes its own base rather than being folded into RDX, so RDX's
    // struct is not polluted with offsets that were read through RCX.
    expect(out.typedefs?.map((d) => d.fields.map((f) => f.offset))).toEqual([
      [0, 8],
      [0x10, 0x18],
    ]);
  });

  it("drops the alias of a register later overwritten with a computed value", () => {
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("esi", 4), at(irReg("rbx", 8), 8)),
      assign(irReg("rbx", 8), irBinary("+", RCX, irConst(8))),
      assign(irReg("edi", 4), at(RCX, 0x10)),
      assign(irReg("r9d", 4), at(RCX, 0x18)),
    ]);
    // After the arithmetic write RBX no longer holds RCX, so the two reads
    // through it cannot be merged into RCX's struct for the whole function.
    expect(out.typedefs?.map((d) => d.fields.map((f) => f.offset))).toEqual([
      [0, 8],
      [0x10, 0x18],
    ]);
  });

  it("only follows plain copies, not arithmetic", () => {
    const out = run([
      assign(irReg("rbx", 8), irBinary("+", RCX, irConst(0x10))),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("edx", 4), at(irReg("rbx", 8), 8)),
      assign(irReg("esi", 4), at(RCX, 0)),
    ]);
    // RBX is its own base; RCX has a single offset and is not a candidate.
    expect(out.typedefs).toHaveLength(1);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });
});

describe("synthesizeStructs — array accesses", () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());

  // synthesizeStructs used to return early when no base had 2+ distinct
  // offsets, which made array rewriting reachable only for functions that
  // happened to have a struct elsewhere.
  it("converts an indexed access even when the function has no struct candidate", () => {
    const body = [assign(irReg("eax", 4), idx(RCX, RDX, 4))];
    const out = synthesizeStructs(fn(body), new StructRegistry());
    expect(out.body[0]).toMatchObject({
      src: { kind: "array_access", base: RCX, index: RDX, elementSize: 4, size: 4 },
    });
    expect(out.typedefs).toBeUndefined();
  });

  it("still returns the function untouched when nothing indexes and nothing structs", () => {
    const body = [assign(irReg("eax", 4), irDeref(RCX, 4))];
    const out = synthesizeStructs(fn(body), new StructRegistry());
    expect(out.body).toBe(body);
  });

  it("converts an indexed access once any struct candidate exists", () => {
    const out = run([...twoFieldBody(irReg("r8", 8)), assign(irReg("eax", 4), idx(RCX, RDX, 4))]);
    expect(out.body[2]).toMatchObject({
      src: { kind: "array_access", base: RCX, index: RDX, elementSize: 4, size: 4 },
    });
  });

  it("accepts every architectural scale", () => {
    for (const scale of [1, 2, 4, 8]) {
      const out = run([
        ...twoFieldBody(irReg("r8", 8)),
        assign(irReg("eax", 4), idx(RCX, RDX, scale)),
      ]);
      expect((out.body[2] as { src: { kind: string } }).src.kind, `scale ${scale}`).toBe(
        "array_access",
      );
    }
  });

  it("rejects a scale that is not a power of two", () => {
    const out = run([...twoFieldBody(irReg("r8", 8)), assign(irReg("eax", 4), idx(RCX, RDX, 3))]);
    expect((out.body[2] as { src: { kind: string } }).src.kind).toBe("deref");
  });

  it("does not convert an indexed access at a non-zero offset", () => {
    const addr = irBinary("+", irBinary("+", RCX, irBinary("*", RDX, irConst(4))), irConst(0x10));
    const out = run([...twoFieldBody(irReg("r8", 8)), assign(irReg("eax", 4), irDeref(addr, 4))]);
    expect((out.body[2] as { src: { kind: string } }).src.kind).toBe("deref");
  });

  it("names an indexed field as an array in the struct definition", () => {
    const out = run([
      assign(irReg("eax", 4), at(RCX, 0)),
      assign(irReg("ebx", 4), idx(irBinary("+", RCX, irConst(8)), RDX, 4)),
    ]);
    const arrayField = out.typedefs?.[0].fields.find((f) => f.isArray);
    expect(arrayField).toMatchObject({ name: "array_0x8", arrayElementSize: 4 });
  });
});

describe("synthesizeStructs — field type inference", () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());
  const typeAt = (out: IRFunction, offset: number) =>
    out.typedefs?.[0].fields.find((f) => f.offset === offset)?.type;

  it("defaults a field to an unsigned integer of the access size", () => {
    expect(typeAt(run(twoFieldBody()), 0)).toEqual({ kind: "int", size: 4, signed: false });
  });

  it("marks a field signed when it is compared with a signed operator", () => {
    const out = run([
      ...twoFieldBody(),
      { kind: "if", condition: irBinary("<", at(RCX, 0), irConst(10)), thenBody: [] },
    ]);
    expect(typeAt(out, 0)).toEqual({ kind: "int", size: 4, signed: true });
  });

  it("does not mark a field signed for an unsigned comparison", () => {
    const out = run([
      ...twoFieldBody(),
      { kind: "if", condition: irBinary("u<", at(RCX, 0), irConst(10)), thenBody: [] },
    ]);
    expect(typeAt(out, 0)).toMatchObject({ signed: false });
  });

  it("marks a field signed from a loop condition too", () => {
    const out = run([
      ...twoFieldBody(),
      { kind: "while", condition: irBinary(">=", at(RCX, 0), irConst(0)), body: [] },
    ]);
    expect(typeAt(out, 0)).toMatchObject({ signed: true });
  });

  // The signed-comparison walker used to skip try statements entirely, which
  // loses every comparison in a __try/__except body — and SEH wrapping covers
  // whole function bodies, not small fragments.
  it("marks a field signed from a comparison inside a try body or handler", () => {
    const out = run([
      ...twoFieldBody(),
      {
        kind: "try",
        body: [{ kind: "if", condition: irBinary("<", at(RCX, 0), irConst(10)), thenBody: [] }],
        handler: [{ kind: "if", condition: irBinary(">", at(RCX, 8), irConst(0)), thenBody: [] }],
      },
    ]);
    expect(typeAt(out, 0)).toMatchObject({ signed: true });
    expect(typeAt(out, 8)).toMatchObject({ signed: true });
  });

  // A `for` was recursed into but its own condition was never inspected, so
  // `for (i = 0; p->count > i; i++)` left the field unsigned even though the
  // equivalent `while` form was handled.
  it("marks a field signed from a for-loop condition", () => {
    const out = run([
      ...twoFieldBody(),
      {
        kind: "for",
        init: assign(irReg("esi", 4), irConst(0)),
        condition: irBinary(">", at(RCX, 0), irReg("esi", 4)),
        update: assign(irReg("esi", 4), irBinary("+", irReg("esi", 4), irConst(1))),
        body: [],
      },
    ]);
    expect(typeAt(out, 0)).toMatchObject({ signed: true });
  });

  it("types a 16-byte access as a float", () => {
    const out = run([
      assign(irReg("xmm0", 16), at(RCX, 0, 16)),
      assign(irReg("ebx", 4), at(RCX, 0x20)),
    ]);
    expect(typeAt(out, 0)).toEqual({ kind: "float", size: 4 });
  });

  it("types a field passed to a function as a pointer", () => {
    const out = run([...twoFieldBody(), callStmt("memcpy", [at(RCX, 8)])]);
    expect(typeAt(out, 8)).toEqual({ kind: "ptr", pointee: { kind: "unknown" } });
  });

  it("leaves a byte-sized field alone when it is passed to a function", () => {
    const out = run([
      assign(irReg("al", 1), at(RCX, 0, 1)),
      assign(irReg("ebx", 4), at(RCX, 8)),
      callStmt("f", [at(RCX, 0, 1)]),
    ]);
    expect(typeAt(out, 0)).toMatchObject({ kind: "int", size: 1 });
  });

  it("types a field as a pointer when a loaded value is stored into it", () => {
    const out = run([
      ...twoFieldBody(),
      store(irBinary("+", RCX, irConst(8)), irDeref(irReg("r8", 8), 8)),
    ]);
    expect(typeAt(out, 8)).toEqual({ kind: "ptr", pointee: { kind: "unknown" } });
  });

  // ── Evidence beats guesswork (peek-a-bin-2kz) ──
  //
  // Two rules above used to fire unconditionally: a field passed to *any*
  // function became a pointer to nothing, and so did a field a *loaded* value
  // was stored into. Both replaced the field's type rather than merging with it,
  // so they also undid what other passes — and other functions, since StructDefs
  // are shared through the registry — had established.

  it("takes the callee parameter type over the pointer guess", () => {
    // Sleep's only parameter is a DWORD. "It was passed somewhere" is not a
    // reason to prefer PVOID over a signature that says otherwise.
    const out = run([...twoFieldBody(), callStmt("Sleep", [at(RCX, 8)])]);
    expect(typeAt(out, 8)).toEqual({ kind: "int", size: 4, signed: false });
  });

  it("takes a specific parameter type from the callee signature", () => {
    const out = run([...twoFieldBody(), callStmt("CloseHandle", [at(RCX, 8)])]);
    expect(typeAt(out, 8)).toEqual({ kind: "handle" });
  });

  it("resolves an imported callee through its display name", () => {
    // An IAT call carries the name in `display` as lib!Func; the target is the
    // thunk. Same resolution order as inferFromAPICalls in typeInfer.ts.
    const out = run([
      ...twoFieldBody(),
      callStmt("sub_402000", [at(RCX, 8)], "kernel32.dll!CloseHandle"),
    ]);
    expect(typeAt(out, 8)).toEqual({ kind: "handle" });
  });

  it("matches the parameter to the argument position", () => {
    // CreateFileA's argument 1 is a DWORD; only argument 6 is a HANDLE.
    const out = run([...twoFieldBody(), callStmt("CreateFileA", [irConst(0), at(RCX, 8)])]);
    expect(typeAt(out, 8)).toEqual({ kind: "int", size: 4, signed: false });
  });

  // Not a behaviour change — this pins the fallback that survives, which the
  // memcpy test above no longer covers now that memcpy resolves to a signature.
  it("still guesses a pointer for an unknown callee", () => {
    const out = run([...twoFieldBody(), callStmt("sub_408000", [at(RCX, 8)])]);
    expect(typeAt(out, 8)).toEqual({ kind: "ptr", pointee: { kind: "unknown" } });
  });

  it("does not make a field a pointer when another struct field is copied into it", () => {
    // RDX gets a different shape so it stays a separate struct; typedefs[0] is
    // still RCX's, created first.
    const out = run([
      ...twoFieldBody(),
      assign(irReg("ecx", 4), at(RDX, 0)),
      assign(irReg("edi", 4), at(RDX, 0x20)),
      store(irBinary("+", RCX, irConst(8)), at(RDX, 0)),
    ]);
    expect(typeAt(out, 8)).toEqual({ kind: "int", size: 4, signed: false });
  });

  it("carries a specific source type across a field-to-field copy", () => {
    const out = run([
      ...twoFieldBody(),
      assign(irReg("ecx", 4), at(RDX, 0)),
      assign(irReg("edi", 4), at(RDX, 0x20)),
      callStmt("CloseHandle", [at(RDX, 0)]),
      store(irBinary("+", RCX, irConst(8)), at(RDX, 0)),
    ]);
    expect(typeAt(out, 8)).toEqual({ kind: "handle" });
  });

  it("does not let a stored load displace a float field", () => {
    const out = run([
      assign(irReg("xmm0", 16), at(RCX, 0, 16)),
      assign(irReg("ebx", 4), at(RCX, 0x20)),
      store(RCX, irDeref(irReg("r8", 8), 8), 8),
    ]);
    expect(typeAt(out, 0)).toEqual({ kind: "float", size: 4 });
  });
});

describe("synthesizeStructs — cross-function registry state", () => {
  const twoFn = (body: IRStmt[], address: number) =>
    fn(body, { address, name: `sub_${address.toString(16)}` });

  it("reuses one struct for two functions with the same layout", () => {
    const reg = new StructRegistry();
    const a = synthesizeStructs(twoFn(twoFieldBody(RCX), 0x401000), reg);
    const b = synthesizeStructs(twoFn(twoFieldBody(RDX), 0x402000), reg);
    expect(b.typedefs?.[0].id).toBe(a.typedefs?.[0].id);
    expect(reg.getAll()).toHaveLength(1);
  });

  // This is the designed sharing, and it is why the registry is not cleared
  // between functions: a struct seen partially in one function is completed by
  // another. Since the subset path requires 3+ shared fields, completion now
  // starts from a three-field partial view rather than a two-field one.
  it("completes a struct across two functions that see different fields", () => {
    const reg = new StructRegistry();
    synthesizeStructs(
      twoFn(
        [
          assign(irReg("eax", 4), at(RCX, 0)),
          assign(irReg("ebx", 4), at(RCX, 8)),
          assign(irReg("ecx", 4), at(RCX, 16)),
        ],
        0x401000,
      ),
      reg,
    );
    const b = synthesizeStructs(
      twoFn(
        [
          assign(irReg("eax", 4), at(RCX, 0)),
          assign(irReg("ebx", 4), at(RCX, 8)),
          assign(irReg("ecx", 4), at(RCX, 16)),
          assign(irReg("edx", 4), at(RCX, 24)),
        ],
        0x402000,
      ),
      reg,
    );
    expect(reg.getAll()).toHaveLength(1);
    expect(b.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8, 16, 24]);
  });

  // The only evidence used to decide that two bases are the same type is the
  // set of "offset:size" pairs. A two-field shape is the weakest possible
  // evidence — it is the minimum a candidate can have — so it no longer
  // absorbs an unrelated larger struct.
  it("keeps an unrelated two-field base out of a larger struct", () => {
    const reg = new StructRegistry();
    // Function A sees a 3-field object.
    synthesizeStructs(
      twoFn(
        [
          assign(irReg("eax", 4), at(RCX, 0)),
          assign(irReg("ebx", 4), at(RCX, 8)),
          assign(irReg("ecx", 4), at(RCX, 16)),
        ],
        0x401000,
      ),
      reg,
    );
    // Function B touches a completely different object at offsets 0 and 8.
    const b = synthesizeStructs(
      twoFn(
        [
          assign(irReg("eax", 4), at(irVar("unrelated", 8), 0)),
          assign(irReg("ebx", 4), at(irVar("unrelated", 8), 8)),
        ],
        0x402000,
      ),
      reg,
    );
    expect(reg.getAll()).toHaveLength(2);
    // B is emitted with only the fields it actually touched.
    expect(b.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  // StructDef objects are shared by reference *inside* the registry — that
  // in-place mutation is how one function's pass refines a field type another
  // discovered — but what escapes into an IRFunction's typedefs is a snapshot.
  // Without it, an already-returned declaration changes after the fact and a
  // function's emitted C depends on what was decompiled afterwards.
  it("does not mutate an already-returned typedef when a later function is processed", () => {
    const reg = new StructRegistry();
    const a = synthesizeStructs(twoFn(twoFieldBody(RCX), 0x401000), reg);
    expect(a.typedefs?.[0].fields[0].type).toMatchObject({ kind: "int", signed: false });

    synthesizeStructs(
      twoFn(
        [
          ...twoFieldBody(RDX),
          { kind: "if", condition: irBinary("<", at(RDX, 0), irConst(0)), thenBody: [] },
        ],
        0x402000,
      ),
      reg,
    );

    expect(a.typedefs?.[0].fields[0].type).toMatchObject({ signed: false });
  });

  // The snapshot must not disable the cross-function refinement it protects:
  // the registry still learns the signed field, so a function decompiled after
  // that discovery sees it.
  it("still refines a field type across functions inside the registry", () => {
    const reg = new StructRegistry();
    synthesizeStructs(twoFn(twoFieldBody(RCX), 0x401000), reg);
    synthesizeStructs(
      twoFn(
        [
          ...twoFieldBody(RDX),
          { kind: "if", condition: irBinary("<", at(RDX, 0), irConst(0)), thenBody: [] },
        ],
        0x402000,
      ),
      reg,
    );

    const later = synthesizeStructs(twoFn(twoFieldBody(RCX), 0x403000), reg);
    expect(later.typedefs?.[0].fields[0].type).toMatchObject({ signed: true });
  });

  // The other half of that sharing: a field type one function established is
  // there to be *undone* by the next one's guesswork. A store of a loaded value
  // used to overwrite the signedness discovered above with a pointer.
  it("does not let a later function guess over a type an earlier one established", () => {
    const reg = new StructRegistry();
    synthesizeStructs(
      twoFn(
        [
          ...twoFieldBody(RCX),
          { kind: "if", condition: irBinary("<", at(RCX, 8), irConst(10)), thenBody: [] },
        ],
        0x401000,
      ),
      reg,
    );

    const b = synthesizeStructs(
      twoFn(
        [...twoFieldBody(RDX), store(irBinary("+", RDX, irConst(8)), irDeref(irReg("r8", 8), 8))],
        0x402000,
      ),
      reg,
    );

    expect(b.typedefs?.[0].fields.find((f) => f.offset === 8)?.type).toMatchObject({
      kind: "int",
      signed: true,
    });
  });

  it("isolates functions once the registry is cleared", () => {
    const reg = new StructRegistry();
    const a = synthesizeStructs(twoFn(twoFieldBody(RCX), 0x401000), reg);
    reg.clear();
    const b = synthesizeStructs(twoFn(twoFieldBody(RDX), 0x402000), reg);
    expect(b.typedefs?.[0].id).toBe("struct_0");
    expect(a.typedefs?.[0].id).toBe("struct_0"); // same name, different object
    expect(b.typedefs?.[0]).not.toBe(a.typedefs?.[0]);
  });

  it("only reports the typedefs the function actually uses", () => {
    const reg = new StructRegistry();
    synthesizeStructs(
      twoFn(
        [assign(irReg("eax", 4), at(RCX, 0)), assign(irReg("ebx", 4), at(RCX, 0x40, 8))],
        0x401000,
      ),
      reg,
    );
    const b = synthesizeStructs(
      twoFn(
        [assign(irReg("eax", 4), at(RDX, 4, 2)), assign(irReg("ebx", 4), at(RDX, 12, 2))],
        0x402000,
      ),
      reg,
    );
    expect(reg.getAll().length).toBeGreaterThan(1);
    expect(b.typedefs).toHaveLength(1);
  });
});

describe("synthesizeStructs — call-site propagation", () => {
  it("links a struct base passed to a known function address", () => {
    const reg = new StructRegistry();
    const out = synthesizeStructs(fn([...twoFieldBody(), callStmt("sub_402000", [RCX])]), reg);
    expect(reg.getParamStruct(0x402000, 0)).toBe(out.typedefs?.[0].id);
  });

  it("uses the argument position as the parameter index", () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt("sub_402000", [irConst(1), RCX])]), reg);
    expect(reg.getParamStruct(0x402000, 1)).toBeDefined();
    expect(reg.getParamStruct(0x402000, 0)).toBeUndefined();
  });

  it("ignores an argument that is not a tracked base", () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt("sub_402000", [irReg("r9", 8)])]), reg);
    expect(reg.getParamStruct(0x402000, 0)).toBeUndefined();
  });

  it("ignores a call whose target is not address-like", () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt("memcpy", [RCX])]), reg);
    expect(reg.getAll()).toHaveLength(1);
    expect(reg.getParamStruct(Number.NaN, 0)).toBeUndefined();
  });

  // The call target used to be turned into an address with
  // `parseInt(target, 16)`, which happily parsed the leading hex-looking
  // characters of an imported function's *name*: `CloseHandle` became 0xC, so
  // parameter links were recorded against nonsense addresses that collided
  // with each other and with real function addresses. Only `sub_<hex>` is an
  // address.
  it("does not treat an import name that starts with hex digits as an address", () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt("CloseHandle", [RCX])]), reg);
    expect(reg.getParamStruct(0xc, 0)).toBeUndefined();
  });

  it("does not treat an all-hex import name as an address", () => {
    const reg = new StructRegistry();
    synthesizeStructs(fn([...twoFieldBody(), callStmt("DECADE", [RCX])]), reg);
    expect(reg.getParamStruct(0xdecade, 0)).toBeUndefined();
  });

  // The call-site walk used to skip try statements, so every argument passed
  // inside a __try body was invisible — and SEH wrapping covers whole function
  // bodies, not small fragments.
  it("links an argument passed inside a try body or handler", () => {
    const reg = new StructRegistry();
    synthesizeStructs(
      fn([
        ...twoFieldBody(),
        {
          kind: "try",
          body: [callStmt("sub_402000", [RCX])],
          handler: [callStmt("sub_403000", [RCX])],
        },
      ]),
      reg,
    );
    expect(reg.getParamStruct(0x402000, 0)).toBeDefined();
    expect(reg.getParamStruct(0x403000, 0)).toBeDefined();
  });
});

// Shape agreement is a coincidence; a value flowing through a parameter slot is
// evidence. Where the evidence exists these merges are made on it instead, and
// the shape guards — which cost a two-field partial view its ability to be
// completed — do not apply.
describe("synthesizeStructs — provenance-based merging", () => {
  /** An x64 function whose parameters were named by the register path. */
  const callee = (body: IRStmt[], address: number, paramCount = 1): IRFunction =>
    fn(body, {
      address,
      name: `sub_${address.toString(16)}`,
      params: Array.from({ length: paramCount }, (_, i) => ({ name: `arg${i}`, type: "int64_t" })),
    });

  const caller = (body: IRStmt[], address = 0x401000): IRFunction =>
    fn(body, { address, name: `sub_${address.toString(16)}` });

  /** Reads `base` at each offset — the caller's fuller view of the object. */
  const reads = (base: IRExpr, offsets: number[]): IRStmt[] =>
    offsets.map((o, i) => assign(irReg(`r${i + 8}`, 8), at(base, o)));

  it("completes a two-field parameter view from a struct the caller passed in", () => {
    const reg = new StructRegistry();
    // A sees three fields and hands the object to sub_402000 as argument 0.
    synthesizeStructs(caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [RCX])]), reg);
    // B only ever touches two of them — too weak a shape to merge on, but its
    // base *is* the object A passed.
    const b = synthesizeStructs(callee(reads(RCX, [0, 8]), 0x402000), reg);

    expect(reg.getAll()).toHaveLength(1);
    expect(b.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8, 16]);
  });

  // Provenance is published from both ends — the callee records its own reading
  // of the parameter, the caller records what it passed — so the merge does not
  // depend on which of the two is decompiled first.
  it("merges a caller and callee pair the same way in either order", () => {
    const callerFirst = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [RCX])]),
      callerFirst,
    );
    synthesizeStructs(callee(reads(RCX, [0, 8]), 0x402000), callerFirst);

    const calleeFirst = new StructRegistry();
    synthesizeStructs(callee(reads(RCX, [0, 8]), 0x402000), calleeFirst);
    synthesizeStructs(
      caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [RCX])]),
      calleeFirst,
    );

    for (const reg of [callerFirst, calleeFirst]) {
      expect(reg.getAll()).toHaveLength(1);
      expect(reg.getAll()[0].fields.map((f) => f.offset)).toEqual([0, 8, 16]);
    }
  });

  // Provenance overrides the shape *guards*, not the shape *contradiction*. If
  // the two layouts cannot both be right, something upstream is wrong and a
  // merged declaration would only bake the error in.
  it("refuses a provenance merge when the two layouts contradict", () => {
    // 4:4 sits inside the 8-byte field at 0.
    const conflicting = new StructRegistry();
    synthesizeStructs(
      caller([
        assign(irReg("rax", 8), at(RCX, 0, 8)),
        assign(irReg("ebx", 4), at(RCX, 16)),
        callStmt("sub_402000", [RCX]),
      ]),
      conflicting,
    );
    synthesizeStructs(callee(reads(RCX, [4, 16]), 0x402000), conflicting);
    expect(conflicting.getAll()).toHaveLength(2);

    // Control: the same pair with the callee reading offset 8 instead of 4 has
    // no contradiction, and merges on the same evidence.
    const compatible = new StructRegistry();
    synthesizeStructs(
      caller([
        assign(irReg("rax", 8), at(RCX, 0, 8)),
        assign(irReg("ebx", 4), at(RCX, 16)),
        callStmt("sub_402000", [RCX]),
      ]),
      compatible,
    );
    synthesizeStructs(callee(reads(RCX, [8, 16]), 0x402000), compatible);
    expect(compatible.getAll()).toHaveLength(1);
  });

  // `arg0`…`arg3` are only produced for an x64 function with a detected
  // signature, and the argument registers only mean argument 0..3 there. In an
  // x86 function RCX is a scratch register.
  it("only reads RCX as a parameter for a function that has register parameters", () => {
    const withParams = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [RCX])]),
      withParams,
    );
    synthesizeStructs(callee(reads(RCX, [0, 8]), 0x402000), withParams);
    expect(withParams.getAll()).toHaveLength(1);

    const noParams = new StructRegistry();
    synthesizeStructs(caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [RCX])]), noParams);
    synthesizeStructs(fn(reads(RCX, [0, 8]), { address: 0x402000, name: "sub_402000" }), noParams);
    expect(noParams.getAll()).toHaveLength(2);
  });

  it("matches the argument index, not merely the presence of an argument", () => {
    // The object is passed in position 1, so RDX — the second argument
    // register — is the base that carries it.
    const rightSlot = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [irConst(0), RCX])]),
      rightSlot,
    );
    synthesizeStructs(callee(reads(RDX, [0, 8]), 0x402000, 2), rightSlot);
    expect(rightSlot.getAll()).toHaveLength(1);

    const wrongSlot = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [irConst(0), RCX])]),
      wrongSlot,
    );
    synthesizeStructs(callee(reads(RCX, [0, 8]), 0x402000, 2), wrongSlot);
    expect(wrongSlot.getAll()).toHaveLength(2);
  });

  /** A function whose parameter came from a promoted stack slot. */
  const stackCallee = (base: IRExpr, offsets: number[], name: string, address = 0x402000) =>
    fn(reads(base, offsets), {
      address,
      name: `sub_${address.toString(16)}`,
      params: [{ name, type: "int64_t" }],
    });

  // The N in a stack parameter's `arg_N` is now its argument index, derived in
  // stack.ts from the slot's offset, so it pairs with the caller's index. This
  // is what extends provenance to 32-bit binaries, where every argument is a
  // stack slot and none of this path applied before.
  it("reads a stack parameter name as an argument index", () => {
    const reg = new StructRegistry();
    const p = irVar("p", 8);
    synthesizeStructs(caller([...reads(p, [0, 8, 16]), callStmt("sub_402000", [p])]), reg);

    const b = synthesizeStructs(stackCallee(irVar("arg_0", 8), [0, 8], "arg_0"), reg);

    // Merged on the evidence, so the callee's two-field view is completed by
    // the caller's third field even though the shape alone was too weak.
    expect(reg.getAll()).toHaveLength(1);
    expect(b.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8, 16]);
  });

  it("matches the argument index for a stack parameter, not merely its presence", () => {
    // Passed in position 1, so only the parameter named arg_1 is that object.
    const rightSlot = new StructRegistry();
    const p = irVar("p", 8);
    const passesSecond = caller([...reads(p, [0, 8, 16]), callStmt("sub_402000", [irConst(0), p])]);
    synthesizeStructs(passesSecond, rightSlot);
    synthesizeStructs(stackCallee(irVar("arg_1", 8), [0, 8], "arg_1"), rightSlot);
    expect(rightSlot.getAll()).toHaveLength(1);

    // The same callee reading argument 0 instead is a different object. Under
    // the old observation-order numbering this slot was also called arg_0 —
    // that is the mismatch that kept the path disabled.
    const wrongSlot = new StructRegistry();
    synthesizeStructs(passesSecond, wrongSlot);
    synthesizeStructs(stackCallee(irVar("arg_0", 8), [0, 8], "arg_0"), wrongSlot);
    expect(wrongSlot.getAll()).toHaveLength(2);
  });

  // stack.ts falls back to naming a slot after its offset whenever it could not
  // establish that the frame pointer was a frame pointer — the common x64 case
  // of RBP holding a callee-saved object pointer, where `[rbp+0x10]` is a field
  // and not an argument at all. Those names carry no index and must not be
  // guessed at.
  it("ignores an offset-named stack parameter", () => {
    const reg = new StructRegistry();
    const p = irVar("p", 8);
    synthesizeStructs(caller([...reads(p, [0, 8, 16]), callStmt("sub_402000", [p])]), reg);

    const b = synthesizeStructs(stackCallee(irVar("arg_0x10", 8), [0, 8], "arg_0x10"), reg);

    // No provenance, and two fields are below MIN_SUBSET_MERGE_FIELDS, so the
    // callee keeps its own struct rather than taking a possibly-wrong merge.
    expect(reg.getAll()).toHaveLength(2);
    expect(b.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  // An x64 function that spills RCX to its home slot has both an `arg0`
  // register parameter and an `arg_0` stack parameter for the same argument.
  // Where they really are the same value the body reloads it and buildAliasMap
  // folds the two bases into one, so a collision that gets this far means RCX
  // was reused for something else after the spill. The home slot is argument
  // 0's storage by ABI; the register's claim is a heuristic that this collision
  // is itself evidence against.
  it("gives a contested argument index to the stack slot, not the register", () => {
    const reg = new StructRegistry();
    const p = irVar("p", 8);
    // The caller passes a three-field object as argument 0.
    synthesizeStructs(caller([...reads(p, [0, 8, 16]), callStmt("sub_402000", [p])]), reg);

    // The callee reads argument 0 through its home slot, and separately uses
    // RCX — no longer the argument — as the base of an unrelated object.
    const homed = fn([...reads(irVar("arg_0", 8), [0, 8]), ...reads(RCX, [0, 24])], {
      address: 0x402000,
      name: "sub_402000",
      params: [
        { name: "arg_0", type: "int64_t" },
        { name: "arg0", type: "int64_t" },
      ],
    });
    synthesizeStructs(homed, reg);

    // arg_0 completes from the caller's view; the reused RCX keeps its own
    // struct instead of being absorbed into the caller's argument.
    const shapes = reg.getAll().map((d) => d.fields.map((f) => f.offset));
    expect(shapes).toContainEqual([0, 8, 16]);
    expect(shapes).toContainEqual([0, 24]);
    expect(reg.getAll()).toHaveLength(2);
  });

  // Publication is the other half: the callee's own view of a stack parameter
  // has to reach a caller decompiled after it, or the merge would depend on
  // decompilation order.
  it("publishes a stack parameter view for a caller processed later", () => {
    const reg = new StructRegistry();
    synthesizeStructs(stackCallee(irVar("arg_0", 8), [0, 8], "arg_0"), reg);
    const p = irVar("p", 8);
    synthesizeStructs(caller([...reads(p, [0, 8, 16]), callStmt("sub_402000", [p])]), reg);
    expect(reg.getAll()).toHaveLength(1);
  });

  // Two callers of the same function are only merged with each other through
  // the callee's own reading of that parameter. A helper that never
  // dereferences the argument as a struct — a passthrough taking a void* —
  // therefore does not conflate the objects its callers hand it.
  it("unifies two callers only once the callee corroborates the parameter", () => {
    const passthrough = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8]), callStmt("sub_403000", [RCX])], 0x401000),
      passthrough,
    );
    synthesizeStructs(
      caller([...reads(RCX, [0, 16]), callStmt("sub_403000", [RCX])], 0x402000),
      passthrough,
    );
    expect(passthrough.getAll()).toHaveLength(2);

    const corroborated = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8]), callStmt("sub_403000", [RCX])], 0x401000),
      corroborated,
    );
    synthesizeStructs(callee(reads(RCX, [0, 24]), 0x403000), corroborated);
    synthesizeStructs(
      caller([...reads(RCX, [0, 16]), callStmt("sub_403000", [RCX])], 0x402000),
      corroborated,
    );
    expect(corroborated.getAll()).toHaveLength(1);
    expect(corroborated.getAll()[0].fields.map((f) => f.offset)).toEqual([0, 8, 16, 24]);
  });

  // The residual order-dependence, pinned deliberately. A base's struct is
  // decided once, when its function is synthesized, and two structs that
  // already exist are never folded together — so a caller processed before the
  // callee published its reading keeps the struct it made on shape alone.
  // Missing a merge is the benign direction; no ordering produces a *different*
  // merge, only fewer of them.
  it("leaves a caller processed before the callee out of the unification", () => {
    const inOrder = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8]), callStmt("sub_403000", [RCX])], 0x401000),
      inOrder,
    );
    synthesizeStructs(callee(reads(RCX, [0, 24]), 0x403000), inOrder);
    synthesizeStructs(
      caller([...reads(RCX, [0, 16]), callStmt("sub_403000", [RCX])], 0x402000),
      inOrder,
    );
    expect(inOrder.getAll()).toHaveLength(1);

    const callersFirst = new StructRegistry();
    synthesizeStructs(
      caller([...reads(RCX, [0, 8]), callStmt("sub_403000", [RCX])], 0x401000),
      callersFirst,
    );
    synthesizeStructs(
      caller([...reads(RCX, [0, 16]), callStmt("sub_403000", [RCX])], 0x402000),
      callersFirst,
    );
    synthesizeStructs(callee(reads(RCX, [0, 24]), 0x403000), callersFirst);
    expect(callersFirst.getAll()).toHaveLength(2);
  });

  it("follows an alias from the parameter register to the base actually used", () => {
    const reg = new StructRegistry();
    synthesizeStructs(caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [RCX])]), reg);
    // `rbx = rcx` then everything through RBX — the normal shape once a
    // parameter is kept across a call.
    const b = synthesizeStructs(
      callee([assign(irReg("rbx", 8), RCX), ...reads(irReg("rbx", 8), [0, 8])], 0x402000),
      reg,
    );

    expect(reg.getAll()).toHaveLength(1);
    expect(b.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8, 16]);
  });

  it("propagates a struct along a chain of calls", () => {
    const reg = new StructRegistry();
    synthesizeStructs(caller([...reads(RCX, [0, 8, 16]), callStmt("sub_402000", [RCX])]), reg);
    synthesizeStructs(
      callee([...reads(RCX, [0, 8]), callStmt("sub_403000", [RCX])], 0x402000),
      reg,
    );
    const c = synthesizeStructs(callee(reads(RCX, [0, 32]), 0x403000), reg);

    expect(reg.getAll()).toHaveLength(1);
    expect(c.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8, 16, 32]);
  });
});

describe("StructRegistry.findOrCreateLinked", () => {
  it("merges into a linked struct whatever the shapes look like", () => {
    const reg = new StructRegistry();
    const big = reg.findOrCreate("0:4,8:4,16:4", [field(0, 4), field(8, 4), field(16, 4)]);
    // A two-field shape the subset path refuses on its own.
    const small = reg.findOrCreateLinked([big.id], "0:4,8:4", [field(0, 4), field(8, 4)]);
    expect(small.id).toBe(big.id);
    expect(reg.getAll()).toHaveLength(1);
  });

  it("merges a shape that does not nest at all", () => {
    const reg = new StructRegistry();
    const a = reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    const b = reg.findOrCreateLinked([a.id], "0:4,16:4", [field(0, 4), field(16, 4)]);
    expect(b.id).toBe(a.id);
    expect(b.fields.map((f) => f.offset)).toEqual([0, 8, 16]);
  });

  it("re-indexes the merged struct so its new shape is found by fingerprint", () => {
    const reg = new StructRegistry();
    const a = reg.findOrCreate("0:4,8:4", [field(0, 4), field(8, 4)]);
    reg.findOrCreateLinked([a.id], "0:4,16:4", [field(0, 4), field(16, 4)]);
    const again = reg.findOrCreate("0:4,8:4,16:4", [field(0, 4), field(8, 4), field(16, 4)]);
    expect(again.id).toBe(a.id);
    expect(reg.getAll()).toHaveLength(1);
  });

  it("falls back to the shape path for a contradictory layout", () => {
    const reg = new StructRegistry();
    const a = reg.findOrCreate("0:8,16:4", [field(0, 8), field(16, 4)]);
    const b = reg.findOrCreateLinked([a.id], "4:4,16:4", [field(4, 4), field(16, 4)]);
    expect(b.id).not.toBe(a.id);
    expect(reg.getAll()).toHaveLength(2);
  });

  it("skips a stale link and takes the next one", () => {
    const reg = new StructRegistry();
    const a = reg.findOrCreate("0:4,8:4,16:4", [field(0, 4), field(8, 4), field(16, 4)]);
    const b = reg.findOrCreateLinked(["struct_99", a.id], "0:4,8:4", [field(0, 4), field(8, 4)]);
    expect(b.id).toBe(a.id);
  });

  it("creates a struct when no link resolves", () => {
    const reg = new StructRegistry();
    const def = reg.findOrCreateLinked(["struct_99"], "0:4,8:4", [field(0, 4), field(8, 4)]);
    expect(def.id).toBe("struct_0");
    expect(reg.getAll()).toHaveLength(1);
  });

  it("round-trips a callee parameter view and clears it", () => {
    const reg = new StructRegistry();
    reg.linkParamView(0x401000, 1, "struct_0");
    expect(reg.getParamView(0x401000, 1)).toBe("struct_0");
    expect(reg.getParamView(0x401000, 0)).toBeUndefined();
    reg.clear();
    expect(reg.getParamView(0x401000, 1)).toBeUndefined();
  });
});

/**
 * Fields that hold a pointer to another struct.
 *
 * The pass is a *linking* one: an object dereferenced at two or more offsets is
 * already a candidate in its own right, whatever it was loaded from, so what is
 * missing is only the edge between the two candidates. The load statement is
 * that edge, and it survives to this point precisely when the loaded value has
 * more than one use — which is the same condition that makes the inner object a
 * candidate at all.
 */
describe("synthesizeStructs — nested struct fields", () => {
  const nestFn = (extra: IRStmt[] = []) =>
    fn([
      // RCX at two offsets: the outer candidate.
      assign(irReg("eax", 4), at(RCX, 0)),
      // The edge: the value at RCX+8 becomes the base of a second candidate.
      assign(irReg("rsi", 8), at(RCX, 8, 8)),
      store(irReg("rsi", 8), irConst(7)),
      store(irBinary("+", irReg("rsi", 8), irConst(4)), irConst(9)),
      ...extra,
    ]);

  /** The type of field `offset` in the struct the function's base RCX names. */
  const outerField = (f: IRFunction, offset: number): DecompType | undefined =>
    f.typedefs
      ?.find((d) => d.fields.some((x) => x.offset === 8 && x.size === 8))
      ?.fields.find((x) => x.offset === offset)?.type;

  it("types a field whose value is used as another struct base as a pointer to it", () => {
    const out = synthesizeStructs(nestFn(), new StructRegistry());
    const inner = out.typedefs?.find((d) => d.fields.every((x) => x.offset < 8));
    expect(outerField(out, 8)).toEqual({ kind: "struct", id: inner?.id });
  });

  it("declares the struct a nested field names even though the base is elsewhere", () => {
    // Both structs have to reach the emitted typedef block: one is only ever
    // named by the other's field type, and a declaration referring to a type it
    // never defines is worse output than no nesting at all.
    const out = synthesizeStructs(nestFn(), new StructRegistry());
    expect(out.typedefs).toHaveLength(2);
  });

  it("resolves a chain of nestings in a single pass", () => {
    // a->b->c. Each link is an independent load statement naming its own pair,
    // so there is nothing for a fixpoint loop to discover on a second round.
    const RDI = irReg("rdi", 8);
    const RSI = irReg("rsi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        assign(RSI, at(RCX, 8, 8)),
        assign(irReg("ebx", 4), at(RSI, 0x20)),
        assign(RDI, at(RSI, 0x28, 8)),
        store(RDI, irConst(7)),
        store(irBinary("+", RDI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );

    const byOffsets = (...offs: number[]) =>
      out.typedefs?.find((d) => d.fields.map((f) => f.offset).join() === offs.join());
    const outer = byOffsets(0, 8);
    const middle = byOffsets(0x20, 0x28);
    const inner = byOffsets(0, 4);
    expect(outer?.fields.find((f) => f.offset === 8)?.type).toEqual({
      kind: "struct",
      id: middle?.id,
    });
    expect(middle?.fields.find((f) => f.offset === 0x28)?.type).toEqual({
      kind: "struct",
      id: inner?.id,
    });
  });

  it("refuses the nesting when the register holds two different objects", () => {
    // The map is flow-insensitive, so a register loaded from two fields has no
    // single answer. Declaring either one would name an object the field never
    // points at for half the function.
    const RSI = irReg("rsi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        assign(RSI, at(RCX, 8, 8)),
        store(RSI, irConst(7)),
        assign(RSI, at(RCX, 0, 8)),
        store(irBinary("+", RSI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );

    for (const def of out.typedefs ?? []) {
      for (const f of def.fields) expect(f.type.kind).not.toBe("struct");
    }
  });

  it("refuses the nesting when the register is also written from a call", () => {
    const RSI = irReg("rsi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        assign(RSI, at(RCX, 8, 8)),
        store(RSI, irConst(7)),
        assign(RSI, { kind: "call", target: "sub_408000", args: [] }),
        store(irBinary("+", RSI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );

    expect(outerField(out, 8)).toMatchObject({ kind: "int" });
  });

  it("follows a copy of the loaded value to the base actually dereferenced", () => {
    // `rsi = rcx->f; rdi = rsi; rdi->…` — buildAliasMap folds RDI onto RSI, and
    // the copy between them must not read as a second definition of that base.
    const RSI = irReg("rsi", 8);
    const RDI = irReg("rdi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        assign(RSI, at(RCX, 8, 8)),
        assign(RDI, RSI),
        store(RDI, irConst(7)),
        store(irBinary("+", RDI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );

    expect(outerField(out, 8)?.kind).toBe("struct");
  });

  it("leaves a field alone when the loaded value is never used as a base", () => {
    const out = synthesizeStructs(
      fn([assign(irReg("eax", 4), at(RCX, 0)), assign(irReg("rsi", 8), at(RCX, 8, 8))]),
      new StructRegistry(),
    );
    expect(outerField(out, 8)).toMatchObject({ kind: "int" });
  });

  it("does not nest through a field too narrow to hold an address", () => {
    const RSI = irReg("rsi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0, 8)),
        assign(RSI, at(RCX, 8, 2)),
        store(RSI, irConst(7)),
        store(irBinary("+", RSI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );
    expect(outerField(out, 8)).toBeUndefined();
    const outer = out.typedefs?.find((d) => d.fields.some((x) => x.offset === 8 && x.size === 2));
    expect(outer?.fields.find((x) => x.offset === 8)?.type).toMatchObject({ kind: "int", size: 2 });
  });

  it("does not nest through an indexed load, which names an element and not a field", () => {
    // `*(rcx + r9*8 + 0x18)` is an element of the array at 0x18, not the field
    // at 0x18, so the value it produces says nothing about that field's type.
    const RSI = irReg("rsi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        assign(irReg("ebx", 4), at(RCX, 8)),
        assign(
          RSI,
          irDeref(
            irBinary(
              "+",
              irBinary("+", RCX, irBinary("*", irReg("r9", 8), irConst(8))),
              irConst(0x18),
            ),
            8,
          ),
        ),
        store(RSI, irConst(7)),
        store(irBinary("+", RSI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );

    const outer = out.typedefs?.find((d) => d.fields.some((x) => x.offset === 0x18));
    expect(outer?.fields.find((x) => x.offset === 0x18)?.type.kind).not.toBe("struct");
  });

  it("upgrades the pointer guess rather than sitting behind it", () => {
    // inferFieldTypesFromUsage has already made this field a PVOID, by way of
    // the "a machine word passed to a function is an address" heuristic. The
    // nesting is the same claim with the pointee filled in.
    const RSI = irReg("rsi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        callStmt("sub_408000", [at(RCX, 8, 8)]),
        assign(RSI, at(RCX, 8, 8)),
        store(RSI, irConst(7)),
        store(irBinary("+", RSI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );
    expect(outerField(out, 8)?.kind).toBe("struct");
  });

  it("keeps a type the callee signature established over the nesting", () => {
    // CloseHandle's parameter is real evidence about the field; that the value
    // is also dereferenced at two offsets is a structural inference. Evidence
    // wins, exactly as it does against the pointer guess.
    const RSI = irReg("rsi", 8);
    const out = synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        callStmt("CloseHandle", [at(RCX, 8, 8)]),
        assign(RSI, at(RCX, 8, 8)),
        store(RSI, irConst(7)),
        store(irBinary("+", RSI, irConst(4)), irConst(9)),
      ]),
      new StructRegistry(),
    );
    expect(outerField(out, 8)).toEqual({ kind: "handle" });
  });

  it("does not let a later function guess a resolved nesting away", () => {
    // The mirror of the signedness case above. Field types are shared by
    // reference across functions, and meetTypes ranks a bare ptr above a struct,
    // so an unguarded refine would answer PVOID and quietly undo the nesting.
    const reg = new StructRegistry();
    const first = synthesizeStructs(nestFn(), reg);
    const nested = outerField(first, 8);
    expect(nested?.kind).toBe("struct");

    synthesizeStructs(
      fn(
        [
          assign(irReg("eax", 4), at(RDX, 0)),
          assign(irReg("ebx", 8), at(RDX, 8, 8)),
          callStmt("sub_408000", [at(RDX, 8, 8)]),
        ],
        { address: 0x402000 },
      ),
      reg,
    );

    const outer = reg.getAll().find((d) => d.fields.some((f) => f.offset === 8 && f.size === 8));
    expect(outer?.fields.find((f) => f.offset === 8)?.type).toEqual(nested);
  });

  it("carries a nesting resolved by one function into another that only sees the outer struct", () => {
    const reg = new StructRegistry();
    synthesizeStructs(nestFn(), reg);
    // A second function reads the same layout through RDX and never touches the
    // inner object, but its typedef block still has to define what field 8 names.
    const b = synthesizeStructs(
      fn([assign(irReg("eax", 4), at(RDX, 0)), assign(irReg("ebx", 8), at(RDX, 8, 8))], {
        address: 0x402000,
      }),
      reg,
    );
    expect(b.typedefs).toHaveLength(2);
  });
});

/**
 * One register is not one object — `baseGenerations`.
 *
 * The tests that matter most here are the ones asserting the key does NOT
 * split. Splitting is the benign direction (two declarations instead of one
 * wrongly shared), but a key sharp enough to give every access its own group
 * recovers nothing at all, since a candidate needs two fields.
 */
describe("synthesizeStructs — base value generations", () => {
  const run = (body: IRStmt[]) => synthesizeStructs(fn(body), new StructRegistry());

  it("does not group accesses through two unrelated values of one register", () => {
    const out = run([
      assign(irReg("rax", 8), at(RCX, 0x18, 8)),
      assign(irReg("ebx", 4), at(irReg("rax", 8), 0)),
      assign(irReg("rax", 8), at(RDX, 0x20, 8)),
      assign(irReg("edi", 4), at(irReg("rax", 8), 0x40)),
    ]);
    // One field per generation, so neither is a candidate. The fabricated
    // `{0x0, 0x40}` this used to declare was `t32!sub_40667A`'s struct_26 in
    // miniature (peek-a-bin-z8q7).
    expect(out.typedefs ?? []).toHaveLength(0);
  });

  it("keeps one object when the same value is read at several offsets", () => {
    const out = run([
      assign(irReg("rax", 8), at(RCX, 0x18, 8)),
      assign(irReg("ebx", 4), at(irReg("rax", 8), 0)),
      assign(irReg("edi", 4), at(irReg("rax", 8), 0x40)),
    ]);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 0x40]);
  });

  it("keeps one object across a loop that advances the base by a stride", () => {
    // The accesses are at the loop head, so what they read is the header phi —
    // element 0 on the first iteration and element N on the last, all of one
    // type. A key that separated them by iteration would recover nothing from
    // any array-of-struct walk, which is most of what this pass is for.
    const out = run([
      assign(irReg("rax", 8), at(RCX, 0x18, 8)),
      {
        kind: "while",
        condition: irBinary("!=", irReg("rax", 8), irConst(0)),
        body: [
          assign(irReg("ebx", 4), at(irReg("rax", 8), 0)),
          assign(irReg("edi", 4), at(irReg("rax", 8), 8)),
          assign(irReg("rax", 8), irBinary("+", irReg("rax", 8), irConst(0x40))),
        ],
      },
    ]);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  it("does not group across a copy the alias map refused to fold", () => {
    // RBX is written twice with different sources, so `buildAliasMap` drops it;
    // the generations then keep the two objects' accesses apart as well.
    const out = run([
      assign(irReg("rbx", 8), at(RCX, 0x18, 8)),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("rbx", 8), at(RCX, 0x20, 8)),
      assign(irReg("esi", 4), at(irReg("rbx", 8), 0x10)),
    ]);
    // The one declaration is RCX's own two loads; RBX contributes neither a
    // `{0x0, 0x10}` object nor a field to anything else.
    expect(out.typedefs?.map((d) => d.fields.map((f) => f.offset))).toEqual([[0x18, 0x20]]);
  });

  it("groups across a copy the alias map did fold", () => {
    // A copy restates the value rather than redefining it, so it inherits the
    // source's generation — the same test `linkNestedStructFields` makes.
    const out = run([
      assign(irReg("rbx", 8), RCX),
      assign(irReg("eax", 4), at(irReg("rbx", 8), 0)),
      assign(irReg("esi", 4), at(RCX, 8)),
    ]);
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });

  it("does not group across a label", () => {
    // A jump target is reached from somewhere this walk does not model, so
    // nothing in flight survives it.
    const out = run([
      assign(irReg("rax", 8), at(RCX, 0x18, 8)),
      assign(irReg("ebx", 4), at(irReg("rax", 8), 0)),
      { kind: "label", name: "loc_401020" },
      assign(irReg("edi", 4), at(irReg("rax", 8), 0x40)),
    ]);
    expect(out.typedefs ?? []).toHaveLength(0);
  });

  it("does not group an arm's accesses with the ones below the join", () => {
    const out = run([
      {
        kind: "if",
        condition: irBinary("!=", RDX, irConst(0)),
        thenBody: [
          assign(irReg("rax", 8), at(RCX, 0x18, 8)),
          assign(irReg("ebx", 4), at(irReg("rax", 8), 0)),
        ],
      },
      assign(irReg("edi", 4), at(irReg("rax", 8), 0x40)),
    ]);
    expect(out.typedefs ?? []).toHaveLength(0);
  });

  it("still reaches an access through a register nothing in the function writes", () => {
    // Generation 0 is the entry value, and a parameter register never assigned
    // has exactly one — the common case, and the one an off-by-one in the
    // annotation would break silently.
    const out = run(twoFieldBody());
    expect(out.typedefs?.[0].fields.map((f) => f.offset)).toEqual([0, 8]);
  });
});

/**
 * The observer `corpus/structOverlaps.ts` reads. Its whole value is that the
 * report is RAW — every access, not the fields the rule chose — so an audit can
 * re-derive both the same-offset width rule and first-by-offset for itself and
 * be a differential test of them rather than a readout. Handing it the fields
 * would make it agree by construction. See `StructGroupReport`.
 */
describe("synthesizeStructs — group observer", () => {
  it("reports every access grouped onto a base, not the fields the rule chose", () => {
    const seen: StructGroupReport[] = [];
    // Three readings of overlapping bytes: a word and a byte at 0, and a byte at
    // 1. The rule keeps one field; the observer must show all three.
    synthesizeStructs(
      fn([
        assign(irReg("eax", 2), at(RCX, 0, 2)),
        assign(irReg("ebx", 1), at(RCX, 0, 1)),
        assign(irReg("edx", 1), at(RCX, 1, 1)),
      ]),
      new StructRegistry(),
      (g) => seen.push(g),
    );
    expect(seen).toHaveLength(1);
    // `#0` is the generation: RCX is never assigned here, so every access reads
    // its entry value. See `baseGenerations`.
    expect(seen[0].baseKey).toBe("reg:rcx#0");
    expect(seen[0].accesses.map((a) => [a.offset, a.size])).toEqual([
      [0, 2],
      [0, 1],
      [1, 1],
    ]);
    // One field survives, so this base is no struct candidate — and the group is
    // still reported. A census that only saw candidates would miss exactly the
    // overlaps that cost a base its second field.
    expect(seen[0].fields).toBe(1);
  });

  it("records the stride of an index that reached an offset, and 0 for none", () => {
    const seen: StructGroupReport[] = [];
    synthesizeStructs(
      fn([
        assign(irReg("eax", 4), at(RCX, 0)),
        assign(irReg("ebx", 4), idx(irBinary("+", RCX, irConst(8)), RDX, 4)),
      ]),
      new StructRegistry(),
      (g) => seen.push(g),
    );
    const byOffset = new Map(seen[0].accesses.map((a) => [a.offset, a.scale]));
    expect(byOffset.get(0)).toBe(0);
    expect(byOffset.get(8)).toBe(4);
  });

  it("changes nothing it observes", () => {
    const body = [
      assign(irReg("eax", 4), at(RCX, 0)),
      assign(irReg("ebx", 4), at(RCX, 8)),
      assign(irReg("edx", 2), at(RCX, 2, 2)),
    ];
    const plain = synthesizeStructs(fn(body), new StructRegistry());
    const watched = synthesizeStructs(fn(body), new StructRegistry(), () => {});
    expect(JSON.stringify(watched)).toBe(JSON.stringify(plain));
  });
});
