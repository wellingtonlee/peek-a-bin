import { describe, expect, it } from "vitest";
import { emitFunction } from "../emit";
import type { IRExpr, IRFunction, IRPhi, IRStmt } from "../ir";
import { irBinary, irConst, irReg, irVar } from "../ir";
import { MAX_FIELD_OFFSET } from "../structs";
import type { TypeContext } from "../typeInfer";

// ── Helpers ──

function fn(body: IRStmt[], extra: Partial<IRFunction> = {}): IRFunction {
  return {
    name: "sub_1000",
    address: 0x1000,
    returnType: "int",
    params: [],
    locals: [],
    body,
    ...extra,
  };
}

/**
 * An 'assign' whose `src` throws the first time it is read — stands in for any
 * failure inside the mutually recursive emitStmt/emitExpr walk (a RangeError
 * from deeply nested IR is the real-world case).
 */
function explodingStmt(): IRStmt {
  const stmt = { kind: "assign", dest: irVar("x", 4) } as unknown as IRStmt;
  Object.defineProperty(stmt, "src", {
    get() {
      throw new Error("emit blew up");
    },
  });
  return stmt;
}

function typeCtxWith(name: string, kind: "handle"): TypeContext {
  return { types: new Map([[name, { kind }]]) } as unknown as TypeContext;
}

// ── Tests ──

/**
 * These guard the module-level `_typeCtx` / `_stringMap` in emit.ts against
 * leaking across calls when emission throws. They pass on the pre-try/finally
 * code too, because emitFunction reassigns both globals on entry — so today the
 * leak is not observable through the public API. They exist to keep it that way
 * if that entry assignment ever becomes conditional (e.g. `typeCtx ?? _typeCtx`).
 */
describe("emitFunction — module state is not leaked when emission throws", () => {
  it("does not carry a stale string map into the next function", () => {
    const strings = new Map<number, string>([[0x404000, "SECRET STRING"]]);

    expect(() => emitFunction(fn([explodingStmt()]), undefined, strings)).toThrow("emit blew up");

    // Second function is emitted with no string map: 0x404000 is just a number.
    const after = emitFunction(
      fn([{ kind: "assign", dest: irVar("y", 4), src: irConst(0x404000, 4) }]),
    );
    expect(after.code).toContain("0x404000");
    expect(after.code).not.toContain("SECRET STRING");
  });

  it("does not carry a stale type context into the next function", () => {
    const typeCtx = typeCtxWith("rax", "handle");

    expect(() => emitFunction(fn([explodingStmt()]), typeCtx)).toThrow("emit blew up");

    // Without a type context, `rax == -1` must stay a plain comparison rather
    // than picking up the previous function's HANDLE idiom.
    const after = emitFunction(
      fn([
        {
          kind: "assign",
          dest: irVar("y", 4),
          src: irBinary("==", irReg("rax", 8), irConst(-1, 8)),
        },
      ]),
    );
    expect(after.code).not.toContain("INVALID_HANDLE_VALUE");
  });

  it("still applies the type context for the function it was passed with", () => {
    const typeCtx = typeCtxWith("rax", "handle");
    const result = emitFunction(
      fn([
        {
          kind: "assign",
          dest: irVar("y", 4),
          src: irBinary("==", irReg("rax", 8), irConst(-1, 8)),
        },
      ]),
      typeCtx,
    );
    expect(result.code).toContain("INVALID_HANDLE_VALUE");
  });
});

describe("emitFunction — surviving phi statements", () => {
  it("emits a line for a phi that outlived SSA destruction", () => {
    const phi: IRPhi = {
      kind: "phi",
      dest: irReg("rax", 8, 3),
      operands: [
        { blockId: 1, value: irReg("rax", 8, 1) },
        { blockId: 2, value: irReg("rax", 8, 2) },
      ],
      addr: 0x1010,
    };
    const result = emitFunction(fn([phi]));

    // Previously emitStmt had no 'phi' case, so the statement produced no
    // output line at all and disappeared silently.
    const bodyLines = result.code.split("\n").slice(1, -1);
    expect(bodyLines.filter((l) => l.trim().length > 0)).toHaveLength(1);
    expect(result.code).toContain("phi");
    expect(result.code).toContain("rax");
    expect(result.code).toContain("B1");
    expect(result.code).toContain("B2");

    // The line still maps back to its instruction address.
    expect([...result.lineMap.values()]).toContain(0x1010);
  });
});

/**
 * IOCTL decoding at a driver's dispatch switch (peek-a-bin-i7v).
 *
 * `structureCFG` numbers a switch's cases by their jump-table index, so a
 * control code can never reach `IRSwitch.values` through the pipeline — the
 * switch has to be written out here. None of the three binaries this branch is
 * measured against is a driver, so nothing below is corroborated against a real
 * one; what it pins is the gate, not the decoding.
 */
describe("emitFunction — a driver's dispatch switch names its control codes", () => {
  /** METHOD_BUFFERED codes on device type 0x22 (UNKNOWN), the usual private range. */
  const IOCTL_A = 0x222000;
  const IOCTL_B = 0x222004;

  function switchOn(values: number[][]): IRStmt {
    return {
      kind: "switch",
      expr: irReg("eax", 4),
      cases: values.map((v) => ({ values: v, body: [{ kind: "break" }] })) as never,
    } as unknown as IRStmt;
  }

  const driver: TypeContext = { types: new Map(), isDriver: true };
  const userMode: TypeContext = { types: new Map(), isDriver: false };

  it("decodes every label of a switch whose labels are all control codes", () => {
    const code = emitFunction(fn([switchOn([[IOCTL_A], [IOCTL_B]])]), driver).code;

    expect(code).toContain("case 0x222000: /* IOCTL: UNKNOWN | Fn=0x800 | BUFFERED */");
    expect(code).toContain("case 0x222004: /* IOCTL: UNKNOWN | Fn=0x801 | BUFFERED */");
  });

  it("says nothing in an image that is not a driver", () => {
    // The shape is identical; only the evidence differs. Deciding on shape
    // alone is what put 782 false IOCTL comments in one user-mode binary.
    const code = emitFunction(fn([switchOn([[IOCTL_A], [IOCTL_B]])]), userMode).code;

    expect(code).toContain("case 0x222000:");
    expect(code).not.toContain("IOCTL:");
  });

  it("says nothing when a label is not a control code", () => {
    // One ordinary small constant among them means this is some other switch,
    // and naming a device for the ones that happen to fit would be a guess.
    const code = emitFunction(fn([switchOn([[IOCTL_A], [IOCTL_B], [3]])]), driver).code;

    expect(code).not.toContain("IOCTL:");
  });

  it("does not name a device from a single coincidental constant", () => {
    const code = emitFunction(fn([switchOn([[IOCTL_A]])]), driver).code;

    expect(code).not.toContain("IOCTL:");
  });

  it("does not survive into the next function emitted", () => {
    // `isDriver` rides on the module-level `_typeCtx`, which is saved and
    // restored around every call; a leak would annotate a user-mode binary.
    emitFunction(fn([switchOn([[IOCTL_A], [IOCTL_B]])]), driver);

    const after = emitFunction(fn([switchOn([[IOCTL_A], [IOCTL_B]])]));
    expect(after.code).not.toContain("IOCTL:");
  });
});

/**
 * The two readings of a pointer-typed struct field that emit has to keep apart
 * (peek-a-bin-d8t / -q30 against peek-a-bin-h89). Both arrive as the same thing
 * — a field whose declared type is a pointer, used in arithmetic — and only the
 * operator says which of them it is.
 */
describe("emitFunction — a pointer field's arithmetic says what the instruction did", () => {
  const structDef = {
    id: "struct_0",
    fields: [
      {
        name: "field_0x0",
        offset: 0,
        size: 8,
        type: { kind: "ptr", pointee: { kind: "unknown" } },
      },
      { name: "field_0x8", offset: 8, size: 8, type: { kind: "struct", id: "struct_1" } },
    ],
  } as unknown as NonNullable<IRFunction["typedefs"]>[number];

  const field = (name: string, offset: number): IRExpr =>
    ({
      kind: "field_access",
      base: irReg("rcx", 8),
      structId: "struct_0",
      fieldName: name,
      fieldOffset: offset,
      size: 8,
    }) as unknown as IRExpr;

  function emit(src: IRExpr): string {
    return emitFunction(
      fn([{ kind: "assign", dest: irVar("y", 8), src }], { typedefs: [structDef] }),
    ).code;
  }

  it("subtracts two recovered addresses as the byte count the machine computed", () => {
    // `PVOID` minus `struct_1 *` is not valid C, and a plain `-` between two
    // pointers of one type would be an *element* count — neither is what `sub`
    // did. Both fields keep their declared types above.
    const code = emit(irBinary("-", field("field_0x0", 0), field("field_0x8", 8)));

    expect(code).toContain("(uintptr_t)((struct_0 *)rcx)->field_0x0");
    expect(code).toContain("- (uintptr_t)((struct_0 *)rcx)->field_0x8");
    expect(code).toContain("PVOID field_0x0;");
    expect(code).toContain("struct_1* field_0x8;");
  });

  it("leaves a mask of a pointer field to be read as the contradiction it is", () => {
    // The h89 shape. `&` is not defined on addresses at all, so a cast here
    // would not be a spelling choice — it would retract the pointer inference
    // or the mask, and emit has no evidence about which one is wrong.
    const code = emit(irBinary("&", field("field_0x8", 8), irConst(0xffffffef, 4)));

    expect(code).toContain("((struct_0 *)rcx)->field_0x8 & 0xFFFFFFEF");
    expect(code).not.toContain("uintptr_t");
  });
});

/**
 * The layout backstop, now that struct synthesis refuses to produce these at all
 * (peek-a-bin-u3v): a StructDef reaching emission with a field no declaration
 * can place is still reported inside the struct body rather than put somewhere
 * convenient, which is what kept the misplacement visible in the first place
 * (peek-a-bin-ey0).
 *
 * These defs are hand-built because the pipeline no longer produces them. The
 * check earning its keep is the *coupling* one: emit states the largest layout
 * it will write, structs.ts states the largest displacement it will call an
 * offset, and the two are equal — so a change to either that makes synthesis
 * looser lands here rather than in silently misplaced fields.
 */
describe("emitFunction — a field no declaration can place is reported, not placed", () => {
  const def = (fields: unknown[]) =>
    ({ id: "struct_0", fields }) as unknown as NonNullable<IRFunction["typedefs"]>[number];

  const uint = (size: number) => ({ kind: "int", size, signed: false });

  function emitWith(fields: unknown[]): string {
    return emitFunction(
      fn([{ kind: "assign", dest: irVar("y", 8), src: irConst(1, 4) }], {
        typedefs: [def(fields)],
      }),
    ).code;
  }

  it("reports a negative offset rather than placing it", () => {
    const code = emitWith([
      { name: "field_neg_0x8", offset: -8, size: 4, type: uint(4), isArray: false },
      { name: "field_0x0", offset: 0, size: 4, type: uint(4), isArray: false },
    ]);

    expect(code).toContain("uint32_t field_0x0;");
    expect(code).toMatch(/\/\* field_neg_0x8: 4 bytes at -0x8 — a negative offset/);
  });

  it("reports a field whose bytes overlap one already placed", () => {
    const code = emitWith([
      { name: "field_0x0", offset: 0, size: 8, type: uint(8), isArray: false },
      { name: "field_0x2", offset: 2, size: 2, type: uint(2), isArray: false },
    ]);

    expect(code).toContain("uint64_t field_0x0;");
    expect(code).toMatch(/\/\* field_0x2: 2 bytes at 0x2 — its bytes overlap field_0x0/);
  });

  it("reports an offset past the largest layout it states, and leaves the struct incomplete", () => {
    const code = emitWith([
      { name: "field_0x9000", offset: 0x9000, size: 4, type: uint(4), isArray: false },
      { name: "field_0x9100", offset: 0x9100, size: 4, type: uint(4), isArray: false },
    ]);

    expect(code).toContain("typedef struct struct_0 struct_0;");
    expect(code).not.toContain("struct struct_0 {");
    expect(code).toContain("struct_0 is left incomplete");
  });

  it("states the same bound struct synthesis does", () => {
    // Equal on purpose and justified separately (see both docstrings): a
    // displacement that large is an address, and a layout that large is past
    // what the emitted dialect promises. If MAX_FIELD_OFFSET ever rises above
    // this, synthesis starts handing over fields emit will only report.
    expect(MAX_FIELD_OFFSET).toBe(0x8000);
    const inside = emitWith([
      { name: "field_0x0", offset: 0, size: 1, type: uint(1), isArray: false },
      {
        name: `field_0x${(MAX_FIELD_OFFSET - 1).toString(16).toUpperCase()}`,
        offset: MAX_FIELD_OFFSET - 1,
        size: 1,
        type: uint(1),
        isArray: false,
      },
    ]);
    expect(inside).not.toContain("largest layout this states");

    const outside = emitWith([
      { name: "field_0x0", offset: 0, size: 1, type: uint(1), isArray: false },
      {
        name: `field_0x${MAX_FIELD_OFFSET.toString(16).toUpperCase()}`,
        offset: MAX_FIELD_OFFSET,
        size: 1,
        type: uint(1),
        isArray: false,
      },
    ]);
    expect(outside).toContain("largest layout this states");
  });
});

/**
 * The leak detector behind the `IRBranch` design (peek-a-bin-c33).
 *
 * A branch statement is confined to `liftedBlocks`, and `pipeline.ts` extracts
 * every one of them before `structureCFG` runs — so one reaching the emitter
 * means that extraction failed. `emitStmt` throws rather than no-oping, because
 * `decompileFunction` catches it and the corpus sweep counts a throw, and
 * `throws` is gated in `compare.mjs`. A silent arm would turn a structural
 * failure into a guard that simply ceases to exist, with every audit green.
 *
 * These tests exist so that detector cannot go vacuous. Nothing constructs a
 * branch today and the throw is unreachable through the pipeline by
 * construction, which is exactly the condition under which an arm quietly stops
 * doing anything — the repo has been bitten before by a suite that pinned a
 * defect as the rule and failed for nobody as long as it stood.
 */
describe("emitFunction — a branch statement that escapes extraction is a hard failure", () => {
  const escaped: IRStmt = {
    kind: "branch",
    condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
    target: 0x401234,
    jcc: "je",
    addr: 0x401010,
  };

  it("throws rather than dropping the guard", () => {
    expect(() => emitFunction(fn([escaped]))).toThrow(/IRBranch reached the emitter/);
  });

  it("names the address and the jcc, so the escaped guard can be located", () => {
    expect(() => emitFunction(fn([escaped]))).toThrow(/0x401010 \(je\)/);
  });

  it("throws from inside a nested body too, not only at the top level", () => {
    const nested: IRStmt = {
      kind: "if",
      condition: irBinary("!=", irReg("ecx", 4), irConst(0, 4)),
      thenBody: [escaped],
    };
    expect(() => emitFunction(fn([nested]))).toThrow(/IRBranch reached the emitter/);
  });
});
