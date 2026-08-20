import { describe, expect, it } from "vitest";
import type { FunctionSignature } from "../../signatures";
import { stackVarKey } from "../../stack";
import type { StackFrame, StackVar } from "../../types";
import type { IRExpr, IRStmt } from "../ir";
import { irBinary, irConst, irDeref, irReg, irVar } from "../ir";
import { promoteVars } from "../promote";
import type { DecompType, TypeContext } from "../typeInfer";

const ADDR = 0x401000;

function promote(
  body: IRStmt[],
  opts: {
    frame?: StackFrame | null;
    signature?: FunctionSignature | null;
    is64?: boolean;
    typeCtx?: TypeContext;
  } = {},
) {
  return promoteVars(
    "sub_401000",
    ADDR,
    body,
    opts.frame ?? null,
    opts.signature ?? null,
    opts.is64 ?? true,
    opts.typeCtx,
  );
}

function stackVar(over: Partial<StackVar> & { name: string }): StackVar {
  const base: StackVar = { offset: 0x8, signedOffset: -0x8, size: 4, accessCount: 1, ...over };
  // Default the sign to a local ([rbp - offset]) unless the caller states
  // otherwise, matching what these fixtures meant before signedOffset existed.
  return over.signedOffset === undefined ? { ...base, signedOffset: -base.offset } : base;
}

function frameOf(...vars: StackVar[]): StackFrame {
  return { frameSize: 0x40, vars, framed: true };
}

/** A frame whose prologue stack.ts could NOT verify — frame-pointer omission. */
function unframedFrameOf(...vars: StackVar[]): StackFrame {
  return { frameSize: 0x40, vars, framed: false };
}

/** `[rbp - offset]` — a local slot. */
const bpLocal = (offset: number, size = 4, reg = "rbp"): IRExpr =>
  irDeref(irBinary("-", irReg(reg, 8), irConst(offset)), size);
/** `[rbp + offset]` — a parameter slot. */
const bpParam = (offset: number, size = 4, reg = "rbp"): IRExpr =>
  irDeref(irBinary("+", irReg(reg, 8), irConst(offset)), size);
/** `[rsp + offset]` — a local slot addressed off the stack pointer. */
const spLocal = (offset: number, size = 4, reg = "rsp"): IRExpr =>
  irDeref(irBinary("+", irReg(reg, 8), irConst(offset)), size);

const assign = (dest: IRExpr, src: IRExpr): IRStmt => ({ kind: "assign", dest, src });
const ret = (value?: IRExpr): IRStmt => ({ kind: "return", value });

function typeCtxOf(entries: Record<string, DecompType>): TypeContext {
  return { types: new Map(Object.entries(entries)) };
}

const HANDLE: DecompType = { kind: "handle" };

describe("promoteVars — function shell", () => {
  it("carries the name and address through", () => {
    const fn = promote([]);
    expect(fn.name).toBe("sub_401000");
    expect(fn.address).toBe(ADDR);
  });

  it("produces an empty void function for an empty body", () => {
    const fn = promote([]);
    expect(fn.params).toEqual([]);
    expect(fn.locals).toEqual([]);
    expect(fn.body).toEqual([]);
    expect(fn.returnType).toBe("void");
  });

  it("leaves statements without stack references untouched", () => {
    const stmt = assign(irReg("eax", 4), irConst(1));
    expect(promote([stmt]).body).toEqual([stmt]);
  });
});

describe("promoteVars — stack frame locals and params", () => {
  it("declares a local from a stack frame slot", () => {
    const frame = frameOf(stackVar({ name: "var_8", offset: 8, key: stackVarKey("bp", -8) }));
    const fn = promote([assign(irReg("eax", 4), bpLocal(8))], { frame });
    expect(fn.locals).toHaveLength(1);
    expect(fn.locals[0].name).toBe("var_8");
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), irVar("var_8", 4)));
  });

  it("defaults an accessed local to unsigned", () => {
    // sizeToType() calls a 4-byte slot int32_t, but inferVarTypes re-derives
    // the type from the access width and only marks it signed when it sees a
    // signed cast — so any local that is actually read comes out unsigned.
    const frame = frameOf(stackVar({ name: "var_8", offset: 8, key: stackVarKey("bp", -8) }));
    expect(promote([], { frame }).locals[0].type).toBe("int32_t");
    expect(promote([assign(irReg("eax", 4), bpLocal(8))], { frame }).locals[0].type).toBe(
      "uint32_t",
    );
  });

  it("declares a parameter from an arg_ slot", () => {
    const frame = frameOf(stackVar({ name: "arg_0", offset: 0x10, key: stackVarKey("bp", 0x10) }));
    const fn = promote([assign(irReg("eax", 4), bpParam(0x10))], { frame });
    expect(fn.params).toEqual([{ name: "arg_0", type: "int32_t" }]);
    expect(fn.locals).toEqual([]);
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), irVar("arg_0", 4)));
  });

  it("maps slot sizes to C types", () => {
    const sizes: [number, string][] = [
      [1, "uint8_t"],
      [2, "uint16_t"],
      [4, "int32_t"],
      [8, "int64_t"],
      [16, "int32_t"],
    ];
    for (const [size, type] of sizes) {
      const frame = frameOf(
        stackVar({ name: "var_8", offset: 8, size, key: stackVarKey("bp", -8) }),
      );
      expect(promote([], { frame }).locals, `size ${size}`).toEqual([{ name: "var_8", type }]);
    }
  });

  it("keeps bp- and sp-relative slots at the same offset distinct", () => {
    const frame = frameOf(
      stackVar({ name: "var_10", offset: 0x10, key: stackVarKey("bp", -0x10) }),
      stackVar({ name: "var_10_sp", offset: 0x10, key: stackVarKey("sp", 0x10) }),
    );
    const fn = promote([assign(bpLocal(0x10), spLocal(0x10))], { frame });
    expect(fn.body[0]).toEqual(assign(irVar("var_10", 4), irVar("var_10_sp", 4)));
  });

  it("falls back to a bp-relative key for legacy frames without one", () => {
    const frame = frameOf(
      stackVar({ name: "var_8", offset: 8 }),
      stackVar({ name: "arg_0", offset: 0x10 }),
    );
    const fn = promote([assign(bpLocal(8), bpParam(0x10))], { frame });
    expect(fn.body[0]).toEqual(assign(irVar("var_8", 4), irVar("arg_0", 4)));
  });

  it("leaves a slot that is not in the frame as a raw dereference", () => {
    const frame = frameOf(stackVar({ name: "var_8", offset: 8, key: stackVarKey("bp", -8) }));
    const fn = promote([assign(irReg("eax", 4), bpLocal(0x20))], { frame });
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), bpLocal(0x20)));
  });
});

describe("promoteVars — stack access matching", () => {
  const frame = frameOf(
    stackVar({ name: "var_8", offset: 8, key: stackVarKey("bp", -8) }),
    stackVar({ name: "arg_0", offset: 0x10, key: stackVarKey("bp", 0x10) }),
    stackVar({ name: "sp_0", offset: 0x18, key: stackVarKey("sp", 0x18) }),
    stackVar({ name: "at_bp", offset: 0, key: stackVarKey("bp", 0) }),
  );

  it("matches [rbp - const] as a local", () => {
    expect(promote([assign(irReg("eax", 4), bpLocal(8))], { frame }).body[0]).toEqual(
      assign(irReg("eax", 4), irVar("var_8", 4)),
    );
  });

  it("matches [rsp + const] as a local", () => {
    expect(promote([assign(irReg("eax", 4), spLocal(0x18))], { frame }).body[0]).toEqual(
      assign(irReg("eax", 4), irVar("sp_0", 4)),
    );
  });

  it("matches a bare [rbp] dereference as offset zero", () => {
    const deref = irDeref(irReg("rbp", 8), 4);
    expect(promote([assign(irReg("eax", 4), deref)], { frame }).body[0]).toEqual(
      assign(irReg("eax", 4), irVar("at_bp", 4)),
    );
  });

  it("preserves the access size on the promoted variable", () => {
    const fn = promote([assign(irReg("al", 1), bpLocal(8, 1))], { frame });
    expect(fn.body[0]).toEqual(assign(irReg("al", 1), irVar("var_8", 1)));
  });

  it("ignores [rbp + const] below the x64 parameter threshold", () => {
    // The x64 home area starts at [rbp+0x10]; anything below is not a param.
    const fn = promote([assign(irReg("eax", 4), bpParam(0x8))], { frame });
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), bpParam(0x8)));
  });

  it("uses ebp/esp in 32-bit mode and ignores the 64-bit names", () => {
    const frame32 = frameOf(stackVar({ name: "var_8", offset: 8, key: stackVarKey("bp", -8) }));
    const asRbp = promote([assign(irReg("eax", 4), bpLocal(8))], { frame: frame32, is64: false });
    expect(asRbp.body[0]).toEqual(assign(irReg("eax", 4), bpLocal(8)));

    const asEbp = promote([assign(irReg("eax", 4), bpLocal(8, 4, "ebp"))], {
      frame: frame32,
      is64: false,
    });
    expect(asEbp.body[0]).toEqual(assign(irReg("eax", 4), irVar("var_8", 4)));
  });

  it("uses the lower x86 parameter threshold in 32-bit mode", () => {
    const frame32 = frameOf(stackVar({ name: "arg_0", offset: 8, key: stackVarKey("bp", 8) }));
    const fn = promote([assign(irReg("eax", 4), bpParam(8, 4, "ebp"))], {
      frame: frame32,
      is64: false,
    });
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), irVar("arg_0", 4)));
  });

  it("matches register names case-insensitively", () => {
    const fn = promote([assign(irReg("eax", 4), bpLocal(8, 4, "RBP"))], { frame });
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), irVar("var_8", 4)));
  });

  it("does not match a computed address that is not base+const", () => {
    const scaled = irDeref(irBinary("-", irReg("rbp", 8), irReg("rax", 8)), 4);
    expect(promote([assign(irReg("eax", 4), scaled)], { frame }).body[0]).toEqual(
      assign(irReg("eax", 4), scaled),
    );
  });
});

describe("promoteVars — frame-register aliases", () => {
  // `splitStaleReads` parks a register version in a variable named after it and
  // rewrites the stale reads to that variable, so a frame slot can arrive here
  // addressed off `ebp_1` at some sites and off `ebp` at others in the same
  // function. Under a verified prologue those are the same address, and this is
  // what makes them the same *name* (peek-a-bin-5zpo).
  const frame32 = () =>
    frameOf(
      stackVar({ name: "arg_0", offset: 8, key: stackVarKey("bp", 8) }),
      stackVar({ name: "var_4", offset: 4, key: stackVarKey("bp", -4) }),
    );
  /** `[<var> + offset]` — a slot reached through a split copy, which is a var. */
  const viaVar = (name: string, op: "+" | "-", offset: number, size = 4): IRExpr =>
    irDeref(irBinary(op, irVar(name, 4), irConst(offset)), size);
  /** `mov ebp, esp` as `swapDefWithCopy` leaves it. */
  const prologue: IRStmt[] = [
    assign(irVar("ebp_1", 4), irReg("esp", 4)),
    assign(irReg("ebp", 4), irVar("ebp_1", 4)),
  ];

  it("promotes a param slot addressed through a split copy of the frame register", () => {
    const fn = promote([...prologue, assign(irReg("eax", 4), viaVar("ebp_1", "+", 8))], {
      frame: frame32(),
      is64: false,
    });
    expect(fn.body[2]).toEqual(assign(irReg("eax", 4), irVar("arg_0", 4)));
  });

  it("promotes a local slot addressed through a split copy", () => {
    const fn = promote([...prologue, assign(irReg("eax", 4), viaVar("ebp_1", "-", 4))], {
      frame: frame32(),
      is64: false,
    });
    expect(fn.body[2]).toEqual(assign(irReg("eax", 4), irVar("var_4", 4)));
  });

  it("gives the same name to the copy and the register in one function", () => {
    const fn = promote(
      [
        ...prologue,
        assign(irReg("eax", 4), viaVar("ebp_1", "+", 8)),
        assign(irReg("ecx", 4), bpParam(8, 4, "ebp")),
      ],
      { frame: frame32(), is64: false },
    );
    expect(fn.body[2]).toEqual(assign(irReg("eax", 4), irVar("arg_0", 4)));
    expect(fn.body[3]).toEqual(assign(irReg("ecx", 4), irVar("arg_0", 4)));
  });

  it("follows a chain of copies", () => {
    const fn = promote(
      [
        ...prologue,
        assign(irVar("ebp_2", 4), irVar("ebp_1", 4)),
        assign(irReg("eax", 4), viaVar("ebp_2", "+", 8)),
      ],
      { frame: frame32(), is64: false },
    );
    expect(fn.body[3]).toEqual(assign(irReg("eax", 4), irVar("arg_0", 4)));
  });

  it("accepts a copy taken directly from the frame register", () => {
    const fn = promote(
      [
        assign(irVar("saved", 4), irReg("ebp", 4)),
        assign(irReg("eax", 4), viaVar("saved", "+", 8)),
      ],
      { frame: frame32(), is64: false },
    );
    expect(fn.body[1]).toEqual(assign(irReg("eax", 4), irVar("arg_0", 4)));
  });

  // The trap: without a verified prologue RBP is an ordinary callee-saved
  // register, so two versions of it are two different objects and `[rbp+0x10]`
  // is a struct field access `structs.ts` must still get to see.
  it("does not follow a copy when the prologue was not verified", () => {
    const unframed = unframedFrameOf(
      stackVar({ name: "arg_0x10", offset: 0x10, key: stackVarKey("bp", 0x10) }),
    );
    const access = viaVar("rbp_1", "+", 0x10);
    const fn = promote(
      [assign(irVar("rbp_1", 8), irReg("rbp", 8)), assign(irReg("eax", 4), access)],
      { frame: unframed },
    );
    expect(fn.body[1]).toEqual(assign(irReg("eax", 4), access));
  });

  it("still promotes the literal frame register when the prologue was not verified", () => {
    const unframed = unframedFrameOf(
      stackVar({ name: "arg_0x10", offset: 0x10, key: stackVarKey("bp", 0x10) }),
    );
    const fn = promote([assign(irReg("eax", 4), bpParam(0x10))], { frame: unframed });
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), irVar("arg_0x10", 4)));
  });

  // The stack pointer moves, so no version of it stands in for another —
  // CLAUDE.md's rule that no read of RSP may be reinterpreted elsewhere.
  it("never follows a copy of the stack pointer", () => {
    const frame = frameOf(stackVar({ name: "var_20", offset: 0x20, key: stackVarKey("sp", 0x20) }));
    const access = viaVar("rsp_1", "+", 0x20);
    const fn = promote(
      [assign(irVar("rsp_1", 8), irReg("rsp", 8)), assign(irReg("eax", 4), access)],
      { frame },
    );
    expect(fn.body[1]).toEqual(assign(irReg("eax", 4), access));
  });

  it("finds the alias wherever the assignment sits in the tree", () => {
    const fn = promote(
      [
        {
          kind: "if",
          condition: irReg("eax", 4),
          thenBody: prologue,
        } as IRStmt,
        assign(irReg("ecx", 4), viaVar("ebp_1", "+", 8)),
      ],
      { frame: frame32(), is64: false },
    );
    expect(fn.body[1]).toEqual(assign(irReg("ecx", 4), irVar("arg_0", 4)));
  });

  it("synthesizes no alias when there is no stack frame at all", () => {
    const access = viaVar("ebp_1", "-", 4);
    const fn = promote([...prologue, assign(irReg("eax", 4), access)], { is64: false });
    expect(fn.body[2]).toEqual(assign(irReg("eax", 4), access));
    expect(fn.locals).toEqual([]);
  });
});

describe("promoteVars — recursion into every construct", () => {
  const frame = frameOf(stackVar({ name: "var_8", offset: 8, key: stackVarKey("bp", -8) }));
  const V = irVar("var_8", 4);
  const promoteOne = (s: IRStmt) => promote([s], { frame }).body[0];

  it("rewrites inside binary and unary operands", () => {
    const stmt = assign(
      irReg("eax", 4),
      irBinary("+", bpLocal(8), { kind: "unary", op: "-", operand: bpLocal(8) }),
    );
    expect(promoteOne(stmt)).toEqual(
      assign(irReg("eax", 4), irBinary("+", V, { kind: "unary", op: "-", operand: V })),
    );
  });

  it("rewrites inside a nested dereference address", () => {
    const stmt = assign(irReg("eax", 4), irDeref(bpLocal(8), 8));
    expect(promoteOne(stmt)).toEqual(assign(irReg("eax", 4), irDeref(V, 8)));
  });

  it("rewrites call arguments", () => {
    const call: IRExpr = { kind: "call", target: "f", args: [bpLocal(8), irConst(1)] };
    expect(promoteOne({ kind: "call_stmt", call: call as never })).toEqual({
      kind: "call_stmt",
      call: { kind: "call", target: "f", args: [V, irConst(1)] },
    });
  });

  it("rewrites ternary and cast operands", () => {
    const t: IRExpr = {
      kind: "ternary",
      condition: bpLocal(8),
      then: bpLocal(8),
      else: irConst(0),
    };
    const c: IRExpr = { kind: "cast", type: "int64_t", operand: bpLocal(8) };
    expect(promoteOne(assign(irReg("eax", 4), t))).toEqual(
      assign(irReg("eax", 4), { kind: "ternary", condition: V, then: V, else: irConst(0) }),
    );
    expect(promoteOne(assign(irReg("eax", 4), c))).toEqual(
      assign(irReg("eax", 4), { kind: "cast", type: "int64_t", operand: V }),
    );
  });

  it("rewrites field and array accesses", () => {
    const fa: IRExpr = {
      kind: "field_access",
      base: bpLocal(8),
      structId: "s1",
      fieldOffset: 0,
      fieldName: "f",
      size: 4,
    };
    const aa: IRExpr = {
      kind: "array_access",
      base: bpLocal(8),
      index: bpLocal(8),
      elementSize: 4,
      size: 4,
    };
    expect(promoteOne(assign(irReg("eax", 4), fa))).toEqual(
      assign(irReg("eax", 4), { ...fa, base: V }),
    );
    expect(promoteOne(assign(irReg("eax", 4), aa))).toEqual(
      assign(irReg("eax", 4), { ...aa, base: V, index: V }),
    );
  });

  it("rewrites a return value", () => {
    expect(promoteOne(ret(bpLocal(8)))).toEqual(ret(V));
  });

  it("leaves a bare return alone", () => {
    expect(promoteOne(ret())).toEqual(ret());
  });

  it("rewrites if conditions and both branches", () => {
    const stmt: IRStmt = {
      kind: "if",
      condition: bpLocal(8),
      thenBody: [assign(irReg("eax", 4), bpLocal(8))],
      elseBody: [assign(irReg("ebx", 4), bpLocal(8))],
    };
    expect(promoteOne(stmt)).toEqual({
      kind: "if",
      condition: V,
      thenBody: [assign(irReg("eax", 4), V)],
      elseBody: [assign(irReg("ebx", 4), V)],
    });
  });

  it("rewrites while and do-while bodies", () => {
    const w: IRStmt = { kind: "while", condition: bpLocal(8), body: [ret(bpLocal(8))] };
    const d: IRStmt = { kind: "do_while", condition: bpLocal(8), body: [ret(bpLocal(8))] };
    expect(promoteOne(w)).toEqual({ kind: "while", condition: V, body: [ret(V)] });
    expect(promoteOne(d)).toEqual({ kind: "do_while", condition: V, body: [ret(V)] });
  });

  it("rewrites every part of a for statement", () => {
    const f: IRStmt = {
      kind: "for",
      init: assign(irReg("ecx", 4), bpLocal(8)),
      condition: bpLocal(8),
      update: assign(irReg("ecx", 4), bpLocal(8)),
      body: [ret(bpLocal(8))],
    };
    expect(promoteOne(f)).toEqual({
      kind: "for",
      init: assign(irReg("ecx", 4), V),
      condition: V,
      update: assign(irReg("ecx", 4), V),
      body: [ret(V)],
    });
  });

  it("rewrites switch selectors, cases and the default body", () => {
    const s: IRStmt = {
      kind: "switch",
      expr: bpLocal(8),
      cases: [{ values: [1], body: [ret(bpLocal(8))] }],
      defaultBody: [ret(bpLocal(8))],
    };
    expect(promoteOne(s)).toEqual({
      kind: "switch",
      expr: V,
      cases: [{ values: [1], body: [ret(V)] }],
      defaultBody: [ret(V)],
    });
  });

  it("rewrites try bodies, handlers and filter expressions", () => {
    const t: IRStmt = {
      kind: "try",
      body: [ret(bpLocal(8))],
      handler: [ret(bpLocal(8))],
      filterExpr: bpLocal(8),
    };
    expect(promoteOne(t)).toEqual({
      kind: "try",
      body: [ret(V)],
      handler: [ret(V)],
      filterExpr: V,
    });
  });

  it("leaves statements with no expressions alone", () => {
    for (const stmt of [
      { kind: "break" as const },
      { kind: "continue" as const },
      { kind: "goto" as const, label: "L" },
    ]) {
      expect(promoteOne(stmt)).toEqual(stmt);
    }
  });
});

describe("promoteVars — stores", () => {
  const frame = frameOf(
    stackVar({ name: "var_8", offset: 8, size: 4, key: stackVarKey("bp", -8) }),
  );

  it("turns a store to a known slot into a variable assignment", () => {
    const store: IRStmt = {
      kind: "store",
      address: irBinary("-", irReg("rbp", 8), irConst(8)),
      value: irConst(7),
      size: 4,
      addr: 0x401005,
    };
    expect(promote([store], { frame }).body[0]).toEqual({
      kind: "assign",
      dest: irVar("var_8", 4),
      src: irConst(7),
      addr: 0x401005,
    });
  });

  it("promotes the stored value as well as the destination", () => {
    const store: IRStmt = {
      kind: "store",
      address: irBinary("-", irReg("rbp", 8), irConst(8)),
      value: bpLocal(8),
      size: 4,
    };
    const out = promote([store], { frame }).body[0];
    expect(out).toEqual({
      kind: "assign",
      dest: irVar("var_8", 4),
      src: irVar("var_8", 4),
      addr: undefined,
    });
  });

  it("keeps a store to an unrelated address but promotes its sub-expressions", () => {
    const store: IRStmt = {
      kind: "store",
      address: irReg("rax", 8),
      value: bpLocal(8),
      size: 4,
    };
    expect(promote([store], { frame }).body[0]).toEqual({
      kind: "store",
      address: irReg("rax", 8),
      value: irVar("var_8", 4),
      size: 4,
    });
  });
});

describe("promoteVars — synthesized stack frame", () => {
  it("creates a local for a dereferenced bp slot", () => {
    const fn = promote([assign(irReg("eax", 4), bpLocal(0x10))]);
    expect(fn.locals).toEqual([{ name: "var_10", type: "uint32_t" }]);
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), irVar("var_10", 4)));
  });

  it("names the local from the hex operand offset", () => {
    const fn = promote([assign(irReg("eax", 4), bpLocal(0x2c))]);
    expect(fn.locals[0].name).toBe("var_2C");
  });

  it("creates a local for an sp slot", () => {
    const fn = promote([assign(irReg("eax", 4), spLocal(0x20))]);
    expect(fn.locals).toEqual([{ name: "var_20", type: "uint32_t" }]);
  });

  // KNOWN BUG (reported, not fixed): synthesizeStackFrame sizes the slot from
  // the *widest* access (int64_t here), then inferVarTypes immediately retypes
  // it from the *narrowest* one and wins. An 8-byte slot that is also read a
  // byte at a time is declared uint8_t, which truncates it in the emitted C.
  it("declares a slot by its narrowest access, discarding the widest", () => {
    const fn = promote([
      assign(irReg("al", 1), bpLocal(0x10, 1)),
      assign(irReg("rax", 8), bpLocal(0x10, 8)),
    ]);
    expect(fn.locals).toEqual([{ name: "var_10", type: "uint8_t" }]); // should be int64_t
  });

  it("suffixes the base when bp and sp slots collide on a name", () => {
    const fn = promote([
      assign(irReg("eax", 4), bpLocal(0x10)),
      assign(irReg("ebx", 4), spLocal(0x10)),
    ]);
    expect(fn.locals.map((l) => l.name).sort()).toEqual(["var_10", "var_10_sp"]);
  });

  it("does not synthesize parameters, only locals", () => {
    // Only non-param slots are synthesized, so [rbp+0x10] stays a raw deref.
    const fn = promote([assign(irReg("eax", 4), bpParam(0x10))]);
    expect(fn.locals).toEqual([]);
    expect(fn.params).toEqual([]);
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), bpParam(0x10)));
  });

  it("finds slots nested deep inside expressions", () => {
    const fn = promote([ret(irBinary("+", irDeref(bpLocal(0x10, 8), 4), irConst(1)))]);
    expect(fn.locals.map((l) => l.name)).toEqual(["var_10"]);
  });

  // KNOWN BUG (reported, not fixed): synthesizeStackFrame only sees IRDeref
  // nodes, but a write to a slot is an IRStore whose `address` is the bare
  // `rbp - 0x10` expression, not a deref. A slot that is only ever written
  // therefore gets no local and is emitted as a raw pointer store.
  it("misses a stack slot that is only ever written to", () => {
    const store: IRStmt = {
      kind: "store",
      address: irBinary("-", irReg("rbp", 8), irConst(0x10)),
      value: irConst(1),
      size: 4,
    };
    const fn = promote([store]);
    expect(fn.locals).toEqual([]); // should declare var_10
    expect(fn.body[0]).toEqual(store); // should be `var_10 = 1`
  });

  // KNOWN BUG (reported, not fixed): the overlap check treats operand offsets
  // as ascending addresses, which is true for [rsp+N] but backwards for
  // [rbp-N]. A bp slot that merely sits *below* a wider one is discarded.
  it("drops a distinct bp local that sits below a wider slot", () => {
    const fn = promote([
      assign(irReg("rax", 8), bpLocal(0x10, 8)), // covers rbp-0x10 .. rbp-0x09
      assign(irReg("ebx", 4), bpLocal(0x14, 4)), // covers rbp-0x14 .. rbp-0x11
    ]);
    expect(fn.locals.map((l) => l.name)).toEqual(["var_10"]); // should also have var_14
    expect(fn.body[1]).toEqual(assign(irReg("ebx", 4), bpLocal(0x14, 4))); // left unpromoted
  });

  it("does not merge sp slots that only look adjacent to bp slots", () => {
    const fn = promote([
      assign(irReg("rax", 8), bpLocal(0x10, 8)),
      assign(irReg("ebx", 4), spLocal(0x14, 4)),
    ]);
    expect(fn.locals.map((l) => l.name).sort()).toEqual(["var_10", "var_14"]);
  });

  it("merges a genuinely overlapping sp access into the wider slot", () => {
    // [rsp+0x10] size 8 covers rsp+0x10..0x17, so [rsp+0x14] is inside it.
    const fn = promote([
      assign(irReg("rax", 8), spLocal(0x10, 8)),
      assign(irReg("ebx", 4), spLocal(0x14, 4)),
    ]);
    expect(fn.locals.map((l) => l.name)).toEqual(["var_10"]);
  });
});

describe("promoteVars — register parameters", () => {
  const sig = (paramCount: number): FunctionSignature => ({ convention: "fastcall", paramCount });

  it("adds one arg per x64 register parameter", () => {
    const fn = promote([], { signature: sig(2) });
    expect(fn.params).toEqual([
      { name: "arg0", type: "int64_t" },
      { name: "arg1", type: "int64_t" },
    ]);
  });

  it("caps register parameters at four", () => {
    expect(promote([], { signature: sig(7) }).params).toHaveLength(4);
  });

  it("adds nothing for a zero-parameter signature", () => {
    expect(promote([], { signature: sig(0) }).params).toEqual([]);
  });

  it("adds no register parameters in 32-bit mode", () => {
    expect(promote([], { signature: sig(3), is64: false }).params).toEqual([]);
  });

  // KNOWN BUG (reported, not fixed): the x64 home area at [rbp+0x10] holds the
  // *same* arguments that arrive in RCX/RDX/R8/R9. The dedupe check compares
  // 'arg0' against the stack name 'arg_0', never matches, and the parameter
  // list ends up listing each spilled register argument twice.
  it("lists a spilled register argument twice", () => {
    const frame = frameOf(stackVar({ name: "arg_0", offset: 0x10, key: stackVarKey("bp", 0x10) }));
    const fn = promote([assign(irReg("eax", 4), bpParam(0x10))], { frame, signature: sig(1) });
    expect(fn.params).toEqual([
      { name: "arg_0", type: "int32_t" },
      { name: "arg0", type: "int64_t" }, // same incoming argument as arg_0
    ]);
  });
});

describe("promoteVars — type inference", () => {
  const frameWith = (size: number) =>
    frameOf(stackVar({ name: "var_8", offset: 8, size, key: stackVarKey("bp", -8) }));

  it("narrows a local to its smallest observed access width", () => {
    const fn = promote([assign(irReg("al", 1), bpLocal(8, 1))], { frame: frameWith(4) });
    expect(fn.locals).toEqual([{ name: "var_8", type: "uint8_t" }]);
  });

  it("takes signedness from a cast around the slot", () => {
    const cast: IRExpr = { kind: "cast", type: "int8_t", operand: bpLocal(8, 1) };
    const fn = promote([assign(irReg("eax", 4), cast)], { frame: frameWith(4) });
    expect(fn.locals).toEqual([{ name: "var_8", type: "int8_t" }]);
  });

  it("lets a signed cast win over an unsigned one", () => {
    const body = [
      assign(irReg("eax", 4), { kind: "cast", type: "uint16_t", operand: bpLocal(8, 2) }),
      assign(irReg("ebx", 4), { kind: "cast", type: "int16_t", operand: bpLocal(8, 2) }),
    ];
    expect(promote(body, { frame: frameWith(4) }).locals).toEqual([
      { name: "var_8", type: "int16_t" },
    ]);
  });

  it("does not retype parameters from access width", () => {
    const frame = frameOf(
      stackVar({ name: "arg_0", offset: 0x10, size: 8, key: stackVarKey("bp", 0x10) }),
    );
    const fn = promote([assign(irReg("al", 1), bpParam(0x10, 1))], { frame });
    expect(fn.params).toEqual([{ name: "arg_0", type: "int64_t" }]);
  });

  it("lets the SSA type context override the width-derived type", () => {
    const fn = promote([assign(irReg("eax", 4), bpLocal(8))], {
      frame: frameWith(4),
      typeCtx: typeCtxOf({ var_8: HANDLE }),
    });
    expect(fn.locals[0].type).toBe("HANDLE");
  });

  it("ignores an unknown inferred type", () => {
    const fn = promote([], {
      frame: frameWith(4),
      typeCtx: typeCtxOf({ var_8: { kind: "unknown" } }),
    });
    expect(fn.locals).toEqual([{ name: "var_8", type: "int32_t" }]);
  });

  it("applies the type context to parameters too", () => {
    const frame = frameOf(stackVar({ name: "arg_0", offset: 0x10, key: stackVarKey("bp", 0x10) }));
    const fn = promote([], { frame, typeCtx: typeCtxOf({ arg_0: { kind: "ntstatus" } }) });
    expect(fn.params).toEqual([{ name: "arg_0", type: "NTSTATUS" }]);
  });
});

describe("promoteVars — type-based renaming", () => {
  const frameWith = (...names: string[]) =>
    frameOf(
      ...names.map((name, i) =>
        stackVar({ name, offset: 8 + i * 8, key: stackVarKey("bp", -(8 + i * 8)) }),
      ),
    );

  it("renames a HANDLE local and every reference to it", () => {
    const fn = promote([assign(irReg("eax", 4), bpLocal(8))], {
      frame: frameWith("var_8"),
      typeCtx: typeCtxOf({ var_8: HANDLE }),
    });
    expect(fn.locals).toEqual([{ name: "hFile", type: "HANDLE" }]);
    expect(fn.body[0]).toEqual(assign(irReg("eax", 4), irVar("hFile", 4)));
  });

  it("renames by type for each known mapping", () => {
    const cases: [DecompType, string][] = [
      [{ kind: "handle" }, "hFile"],
      [{ kind: "ntstatus" }, "status"],
      [{ kind: "hresult" }, "hr"],
      [{ kind: "ptr", pointee: { kind: "unknown" } }, "pBuffer"],
      [{ kind: "bool" }, "bResult"],
    ];
    for (const [type, expected] of cases) {
      const fn = promote([], { frame: frameWith("var_8"), typeCtx: typeCtxOf({ var_8: type }) });
      expect(fn.locals[0].name, expected).toBe(expected);
    }
  });

  it("numbers a second local of the same type", () => {
    const fn = promote([assign(bpLocal(8), bpLocal(0x10))], {
      frame: frameWith("var_8", "var_10"),
      typeCtx: typeCtxOf({ var_8: HANDLE, var_10: HANDLE }),
    });
    expect(fn.locals.map((l) => l.name)).toEqual(["hFile", "hFile2"]);
    expect(fn.body[0]).toEqual(assign(irVar("hFile", 4), irVar("hFile2", 4)));
  });

  it("leaves a non var_ local alone", () => {
    const frame = frameOf(stackVar({ name: "myLocal", offset: 8, key: stackVarKey("bp", -8) }));
    const fn = promote([], { frame, typeCtx: typeCtxOf({ myLocal: HANDLE }) });
    expect(fn.locals).toEqual([{ name: "myLocal", type: "HANDLE" }]);
  });

  it("leaves a local with an unmapped type alone", () => {
    const fn = promote([], {
      frame: frameWith("var_8"),
      typeCtx: typeCtxOf({ var_8: { kind: "int", size: 4, signed: true } }),
    });
    expect(fn.locals).toEqual([{ name: "var_8", type: "int32_t" }]);
  });

  it("renames references inside nested control flow", () => {
    const fn = promote([{ kind: "if", condition: bpLocal(8), thenBody: [ret(bpLocal(8))] }], {
      frame: frameWith("var_8"),
      typeCtx: typeCtxOf({ var_8: HANDLE }),
    });
    expect(fn.body[0]).toEqual({
      kind: "if",
      condition: irVar("hFile", 4),
      thenBody: [ret(irVar("hFile", 4))],
    });
  });
});

describe("promoteVars — return type", () => {
  it("reports int when a return carries a value", () => {
    expect(promote([ret(irReg("eax", 4))]).returnType).toBe("int");
  });

  it("reports void for a bare return", () => {
    expect(promote([ret()]).returnType).toBe("void");
  });

  it("reports void when there is no return at all", () => {
    expect(promote([assign(irReg("eax", 4), irConst(0))]).returnType).toBe("void");
  });

  it("finds a value return inside an if or else branch", () => {
    expect(
      promote([{ kind: "if", condition: irConst(1), thenBody: [ret(irConst(0))] }]).returnType,
    ).toBe("int");
    expect(
      promote([
        {
          kind: "if",
          condition: irConst(1),
          thenBody: [],
          elseBody: [ret(irConst(0))],
        },
      ]).returnType,
    ).toBe("int");
  });

  it("finds a value return inside a while or do-while body", () => {
    expect(
      promote([{ kind: "while", condition: irConst(1), body: [ret(irConst(0))] }]).returnType,
    ).toBe("int");
    expect(
      promote([{ kind: "do_while", condition: irConst(1), body: [ret(irConst(0))] }]).returnType,
    ).toBe("int");
  });

  // KNOWN BUG (reported, not fixed): hasReturnValue only recurses into if /
  // while / do_while. A function whose only value-returning statement sits in
  // a for loop, a switch case or a try block is declared `void` and then emits
  // `return <value>;`, which does not compile.
  it("misses a value return inside a for loop, switch or try", () => {
    const forStmt: IRStmt = {
      kind: "for",
      init: assign(irReg("ecx", 4), irConst(0)),
      condition: irConst(1),
      update: assign(irReg("ecx", 4), irConst(1)),
      body: [ret(irConst(0))],
    };
    const switchStmt: IRStmt = {
      kind: "switch",
      expr: irReg("eax", 4),
      cases: [{ values: [1], body: [ret(irConst(0))] }],
    };
    const tryStmt: IRStmt = { kind: "try", body: [ret(irConst(0))], handler: [] };

    expect(promote([forStmt]).returnType).toBe("void"); // should be int
    expect(promote([switchStmt]).returnType).toBe("void"); // should be int
    expect(promote([tryStmt]).returnType).toBe("void"); // should be int
  });
});
