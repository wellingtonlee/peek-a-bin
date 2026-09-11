import { describe, expect, it } from "vitest";
import { emitFunction } from "../emit";
import type { IRCall, IRExpr, IRFunction, IRPhi, IRStmt } from "../ir";
import { irBinary, irConst, irReg, irUnknown, irVar } from "../ir";
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
    // The tests below are written in x64 names; a 32-bit function opts out.
    is64: true,
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

/**
 * A spoiled compare's captured operand (`lifter.ts`'s `flg_<addr>_<i>`) is a
 * local the emitter itself invents and writes, so the emitter declares it.
 *
 * It did not, and nothing here noticed for a reason worth keeping in view:
 * `corpus/emitAudits.ts`' `preludeFor` answers gcc's "'flg_…' undeclared" by
 * manufacturing `long flg_…;` of its own, so the gcc gate stayed 1127/1127
 * clean over C that referenced an identifier nothing in it declared — and at a
 * width (`long`) that no capture in the corpus actually has.
 *
 * These tests are direct `emitFunction` calls rather than pipeline runs because
 * the two properties below cannot be reached through the pipeline at all: no
 * corpus function emits one capture twice, and `splitStaleReads`' repair
 * variables are the population the scope has to exclude.
 */
describe("emitFunction — spoiled-compare captures are declared", () => {
  const capture = (name: string, size: number, src: IRExpr): IRStmt => ({
    kind: "assign",
    dest: irVar(name, size),
    src,
  });

  it("declares a captured operand at its own width", () => {
    const code = emitFunction(
      fn([
        capture("flg_401000_0", 1, irReg("al", 1)),
        { kind: "return", value: irVar("flg_401000_0", 1) },
      ]),
    ).code;
    expect(code).toContain("    uint8_t flg_401000_0;");
  });

  /**
   * HAZARD TWO, and the reason the width guard is not decoration. Type
   * inference runs on the structured tree and types a comparison operand
   * `{ int, size: 4 }` with the width HARD-CODED, so for a 1- or 2-byte capture
   * its spelling claims a width the machine operand does not have — and
   * `operandWidth` reads `IRVar.size` for this same variable when it decides a
   * cast, so the declaration and the casts around it would disagree. Inference
   * is preferred only when it names the same width. Untriggered in the corpus at
   * `f169c00` (of 114 captures inference has an opinion about 10 and all 10
   * agree in width), which is why it is pinned here.
   */
  it("refuses an inferred type whose width is not the operand's", () => {
    const ctx = { types: new Map([["flg_401000_0", { kind: "int", size: 4, signed: true }]]) };
    const code = emitFunction(
      fn([
        capture("flg_401000_0", 1, irReg("al", 1)),
        { kind: "return", value: irVar("flg_401000_0", 1) },
      ]),
      ctx as unknown as TypeContext,
    ).code;
    expect(code).toContain("    uint8_t flg_401000_0;");
    expect(code).not.toContain("int32_t flg_401000_0;");
  });

  /**
   * HAZARD ONE. A capture is built per BLOCK while a declaration is per
   * FUNCTION, and `structureCFG` can emit one block more than once — the
   * switch-arm and leftover passes both emit. Two declarations of one name is
   * not valid C, so the dedupe is by name. No corpus function reaches this
   * today (measured: 0 of 114 captures is assigned twice), which is exactly the
   * condition under which such a rule quietly stops working.
   */
  it("declares a capture emitted in two regions exactly once", () => {
    const twice: IRStmt = {
      kind: "if",
      condition: irBinary("!=", irReg("ecx", 4), irConst(0, 4)),
      thenBody: [capture("flg_401000_0", 4, irReg("eax", 4))],
      elseBody: [capture("flg_401000_0", 4, irReg("eax", 4))],
    };
    const code = emitFunction(fn([twice])).code;
    expect(code.match(/int32_t flg_401000_0;/g)).toEqual(["int32_t flg_401000_0;"]);
  });

  /**
   * THE SCOPE. `ssadestroy.ts`'s `splitStaleReads` parks a pre-clobber value in
   * an `IRVar` too (`ecx_3`), and those are NOT this pass's: they are declared
   * by the register/variable pass (`registerVariables` and the `_varDecls`
   * loop in `emitFunction`, peek-a-bin-n9cl.4), which runs after this one and
   * excludes what this one declared. This pass asks `isCapturedOperandName` and
   * nothing broader, so the two cannot declare one name twice.
   */
  it("leaves a register-shaped repair variable to the variable pass", () => {
    const code = emitFunction(
      fn([capture("ecx_3", 4, irReg("ecx", 4)), { kind: "return", value: irVar("ecx_3", 4) }]),
    ).code;
    expect(code.match(/^\s+int32_t ecx_3;$/gm)).toHaveLength(1);
    expect(code).toContain("ecx_3 = ecx;");
  });

  /**
   * A capture READ where its defining statement was not emitted is a lost
   * definition, and declaring it would state that the function computes a value
   * it never assigns. It stays undeclared, so it keeps showing up in the
   * prelude, which is the honest signal. Measured at `f169c00`: 0 of 114.
   */
  it("does not declare a capture the body only reads", () => {
    const code = emitFunction(fn([{ kind: "return", value: irVar("flg_401000_0", 4) }])).code;
    expect(code).not.toMatch(/u?int\d+_t flg_401000_0;/);
    expect(code).toContain("return flg_401000_0;");
  });
});

/**
 * A GUARD WHOSE WHOLE BODY IS ONE TERMINATOR GOES ON ONE LINE (peek-a-bin-0qib).
 *
 * The shape is `if (c) break;` — three emitted lines collapsed to one, at
 * 552/540/502/499 sites on t32/t64/w64/w32 as emitted at `87a8499`. It was
 * refused once, in `peek-a-bin-252`, because `corpus/sweep.ts`'s guard scan
 * matched an `if` only when the line ended in `{` and a one-lined guard stopped
 * being a guard at all; `peek-a-bin-vwr5` made `corpus/guardShape.ts` the one
 * grammar for a guard line, taught it this shape and gated the lines it cannot
 * read at 0, which is what makes the change safe to make.
 *
 * The tests below split into the rule, its four refusals, and the line map —
 * and the line map is the load-bearing half.
 */
describe("a guard whose whole body is one terminator", () => {
  const ret = (addr: number): IRStmt => ({ kind: "return", value: irReg("eax", 4), addr });

  it("puts a break, a continue, a goto and a return on the guard's own line", () => {
    const bodies: [IRStmt, string][] = [
      [{ kind: "break" }, "break;"],
      [{ kind: "continue" }, "continue;"],
      [{ kind: "goto", label: "loc_401038" }, "goto loc_401038;"],
      [ret(0x401010), "return eax;"],
    ];
    for (const [body, text] of bodies) {
      const code = emitFunction(
        fn([
          {
            kind: "if",
            condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
            thenBody: [body],
          },
        ]),
      ).code;
      expect(code).toContain(`if (eax == 0) ${text}`);
      expect(code).not.toContain("if (eax == 0) {");
    }
  });

  /**
   * The four refusals. Each is a shape whose body is not the whole of the arm,
   * so a one-lined guard would state something the machine does not do — or, for
   * the assignment, a shape `corpus/selfAssigns.ts`'s `ASSIGN_LINE` reads at
   * statement position and would hand the guard as the destination.
   */
  it("keeps the braced form for a body that is not a terminator", () => {
    const code = emitFunction(
      fn([
        {
          kind: "if",
          condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
          thenBody: [{ kind: "assign", dest: irReg("ecx", 4), src: irConst(1, 4), addr: 0x401010 }],
        },
      ]),
    ).code;
    expect(code).toContain("if (eax == 0) {");
    expect(code).toContain("ecx = 1;");
  });

  it("keeps the braced form for two statements, and for an else", () => {
    const two = emitFunction(
      fn([
        {
          kind: "if",
          condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
          thenBody: [{ kind: "goto", label: "loc_A" }, { kind: "break" }],
        },
      ]),
    ).code;
    expect(two).toContain("if (eax == 0) {");
    const withElse = emitFunction(
      fn([
        {
          kind: "if",
          condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
          thenBody: [{ kind: "break" }],
          elseBody: [{ kind: "continue" }],
        },
      ]),
    ).code;
    expect(withElse).toContain("if (eax == 0) {");
    expect(withElse).toContain("} else {");
  });

  /**
   * The last arm of an else-if chain is one-lined too, and the chain's own
   * shape is what `guardShape`'s `} else ` prefix exists for. The address the
   * combined line inherits is still the BODY's — `emitStmt`'s chain arm copies
   * `addrs[0]` from the nested `if`, and for a one-lined one that entry IS the
   * terminator's.
   */
  it("one-lines the last arm of an else-if chain", () => {
    const { code, lineMap } = emitFunction(
      fn([
        {
          kind: "if",
          condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
          thenBody: [{ kind: "assign", dest: irReg("ecx", 4), src: irConst(1, 4), addr: 0x401000 }],
          elseBody: [
            {
              kind: "if",
              condition: irBinary("==", irReg("eax", 4), irConst(1, 4)),
              thenBody: [ret(0x401010)],
            },
          ],
        },
      ]),
    );
    const lines = code.split("\n");
    const at = lines.findIndex((l) => l.includes("} else if (eax == 1) return eax;"));
    expect(at).toBeGreaterThanOrEqual(0);
    expect(lineMap.get(at)).toBe(0x401010);
  });

  /**
   * THE LINE MAP IS THE CONTRACT, and it is what `corpus/sweep.ts` anchors an
   * inline guard's arm by. The line must carry the BODY statement's address:
   * the guard's own block would be the jcc one decision earlier, which is the
   * `peek-a-bin-8r0` / `peek-a-bin-lbz` class of false INVERTED.
   *
   * `IRIf` carries no `addr` field at all, so there is no guard address to
   * attach by mistake and `oneLinedGuard` is handed the body's own `EmitResult`
   * rather than a string — but that is a structural argument, and this is the
   * measurement of it.
   */
  it("attaches the body statement's address to the one-lined line", () => {
    const { code, lineMap } = emitFunction(
      fn([
        { kind: "assign", dest: irReg("ecx", 4), src: irConst(7, 4), addr: 0x401000 },
        {
          kind: "if",
          condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
          thenBody: [ret(0x401010)],
        },
      ]),
    );
    const lines = code.split("\n");
    const at = lines.findIndex((l) => l.includes("if (eax == 0) return eax;"));
    expect(at).toBeGreaterThanOrEqual(0);
    expect(lineMap.get(at)).toBe(0x401010);
    // …and not the address of the statement above it, which is the only other
    // address in the function.
    expect(lineMap.get(at)).not.toBe(0x401000);
  });

  /**
   * A `break`, a `continue` and a `goto` carry no address in either shape, so
   * the one-lined line has no line-map entry and `inlineBodyAddr` skips the
   * guard exactly as it skips an address-less braced body. That is why only the
   * `return` bodies — 19/9/9/19 of the 2093 sites at `87a8499` — are anchorable.
   */
  it("leaves the line address-less when the terminator has no address", () => {
    const { code, lineMap } = emitFunction(
      fn([
        {
          kind: "if",
          condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
          thenBody: [{ kind: "break" }],
        },
      ]),
    );
    const at = code.split("\n").findIndex((l) => l.includes("if (eax == 0) break;"));
    expect(at).toBeGreaterThanOrEqual(0);
    expect(lineMap.has(at)).toBe(false);
  });
});

/**
 * `promoteVars` says only `int` or `void`. `headerReturnType` widens the `int`
 * from the one thing the body proves locally — every valued return is the result
 * of one `API_TYPES` callee, and they agree — and refuses back to `int` on
 * anything else. Width and pointer-ness are deliberately not inferred
 * (peek-a-bin-n9cl.2).
 */
describe("emitFunction — the header's return type", () => {
  const call = (target: string, display?: string): IRCall => ({
    kind: "call",
    target,
    args: [],
    display,
  });
  const ret = (value?: IRExpr): IRStmt => ({ kind: "return", value });
  const header = (code: string) => code.split("\n").find((l) => l.includes(" sub_1000("));

  it("spells the API's declared return type when every valued return is its result", () => {
    const { code } = emitFunction(fn([ret(call("GetProcessHeap", "KERNEL32.dll!GetProcessHeap"))]));
    expect(header(code)).toBe("HANDLE sub_1000() {");
    expect(code).toContain("return GetProcessHeap();");
  });

  it("is asked of the folded body, which is the shape the lifter produces", () => {
    // `eax = GetLastError(); return eax;` folds to `return GetLastError();` first.
    const { code } = emitFunction(
      fn([
        { kind: "call_stmt", call: call("GetLastError"), resultDest: irReg("eax", 4) },
        ret(irReg("eax", 4)),
      ]),
    );
    expect(header(code)).toBe("uint32_t sub_1000() {");
  });

  it("agrees across two returns of two APIs declaring the same type", () => {
    const { code } = emitFunction(
      fn([
        { kind: "if", condition: irConst(1), thenBody: [ret(call("CloseHandle"))] },
        ret(call("VirtualFree")),
      ]),
    );
    expect(header(code)).toBe("BOOL sub_1000() {");
  });

  it("refuses to int when two API callees disagree", () => {
    const { code } = emitFunction(
      fn([
        { kind: "if", condition: irConst(1), thenBody: [ret(call("GetLastError"))] },
        ret(call("VirtualAlloc")),
      ]),
    );
    expect(header(code)).toBe("int sub_1000() {");
  });

  it("refuses to int when any valued return is not an API result", () => {
    const withRegister = emitFunction(
      fn([
        { kind: "if", condition: irConst(1), thenBody: [ret(call("GetLastError"))] },
        ret(irReg("eax", 4)),
      ]),
    ).code;
    expect(header(withRegister)).toBe("int sub_1000() {");
    const internalCallee = emitFunction(fn([ret(call("sub_2000"))])).code;
    expect(header(internalCallee)).toBe("int sub_1000() {");
  });

  it("refuses an API whose declared return type is void", () => {
    // `void sub_1000() { return free(p); }` is the header/body disagreement this
    // exists to end, one level up.
    const { code } = emitFunction(fn([ret(call("free"))]));
    expect(header(code)).toBe("int sub_1000() {");
  });

  it("finds the returns inside a __try, a switch arm and a for body", () => {
    const forStmt: IRStmt = {
      kind: "for",
      init: { kind: "assign", dest: irReg("ecx", 4), src: irConst(0) },
      condition: irConst(1),
      update: { kind: "assign", dest: irReg("ecx", 4), src: irConst(1) },
      body: [ret(call("GetProcessHeap"))],
    };
    const { code } = emitFunction(
      fn([
        { kind: "try", body: [forStmt], handler: [] },
        {
          kind: "switch",
          expr: irReg("eax", 4),
          cases: [{ values: [1], body: [ret(call("GetProcessHeap"))] }],
        },
      ]),
    );
    expect(header(code)).toBe("HANDLE sub_1000() {");
  });

  it("leaves a void header alone and never widens it", () => {
    const { code } = emitFunction(fn([ret()], { returnType: "void" }));
    expect(header(code)).toBe("void sub_1000() {");
  });
});

/**
 * `EmitFunctionResult.admissions` (peek-a-bin-n9cl.7): the three admission
 * spellings this file emits, read back as line indices off the FINAL lines.
 * Driven from IR directly so each kind is produced on purpose rather than
 * hoped for from an instruction stream; `pipeline.test.ts` covers the same
 * field end to end.
 */
describe("emitFunction — admissions name the lines that carry them", () => {
  it("indexes an unrecovered USE, an unlifted statement and a goto, and not the declaration", () => {
    const r = emitFunction(
      fn([
        { kind: "assign", dest: irVar("x", 4), src: irUnknown("jb") },
        { kind: "raw", text: "leave", addr: 0x1004 },
        { kind: "label", name: "loc_1008" },
        { kind: "goto", label: "loc_1008" },
      ]),
    );
    const lines = r.code.split("\n");

    expect(r.admissions.unrecovered).toHaveLength(1);
    expect(lines[r.admissions.unrecovered[0]]).toContain("x = __unrecovered_1");
    // The `intptr_t __unrecovered_1;` declaration is in the text and not a site.
    expect(lines.some((l) => /^\s*intptr_t __unrecovered_1;/.test(l))).toBe(true);
    expect(lines[r.admissions.unrecovered[0]]).not.toMatch(/intptr_t/);

    expect(r.admissions.unlifted).toHaveLength(1);
    expect(lines[r.admissions.unlifted[0]].trim()).toBe("/* unlifted: leave */;");

    expect(r.admissions.gotos).toHaveLength(1);
    expect(lines[r.admissions.gotos[0]].trim()).toBe("goto loc_1008;");
  });

  it("indexes the FINAL line, after placeGotoLabels has spliced a label in above it", () => {
    // A goto to an address that has an emitted line but no label statement:
    // `placeGotoLabels` inserts `loc_1004:` above `x = 1;`, so everything below
    // shifts by one. An index taken before that pass would name `x = 1;`.
    // (`structure.ts` emits its own labels today, so the pipeline suite cannot
    // reach this splice — the control that showed that is why this row exists.)
    const r = emitFunction(
      fn([
        { kind: "assign", dest: irVar("x", 4), src: irConst(1, 4), addr: 0x1004 } as IRStmt,
        { kind: "goto", label: "loc_1004" },
      ]),
    );
    const lines = r.code.split("\n");

    expect(lines.some((l) => l.trim() === "loc_1004:")).toBe(true);
    expect(r.admissions.gotos).toHaveLength(1);
    expect(lines[r.admissions.gotos[0]].trim()).toBe("goto loc_1004;");
  });

  it("counts a goto whose target emitted nothing, note and all", () => {
    const r = emitFunction(fn([{ kind: "goto", label: "loc_2000" }]));
    const lines = r.code.split("\n");

    expect(r.admissions.gotos).toHaveLength(1);
    expect(lines[r.admissions.gotos[0]]).toMatch(/^\s*goto loc_2000; \/\/ no label:/);
  });

  it("counts a goto one-lined as a guard's body", () => {
    const r = emitFunction(
      fn([
        { kind: "label", name: "loc_1000" },
        {
          kind: "if",
          condition: irBinary("==", irReg("eax", 4), irConst(0, 4)),
          thenBody: [{ kind: "goto", label: "loc_1000" }],
          elseBody: [],
        } as unknown as IRStmt,
      ]),
    );
    const lines = r.code.split("\n");

    expect(r.admissions.gotos).toHaveLength(1);
    expect(lines[r.admissions.gotos[0]].trim()).toBe("if (eax == 0) goto loc_1000;");
  });

  it("does not read a `goto` inside a string literal as an admission", () => {
    // A constant the string map resolves is spelled as a C string literal.
    const r = emitFunction(
      fn([{ kind: "assign", dest: irVar("s", 4), src: irConst(0x404000, 4) }]),
      undefined,
      new Map([[0x404000, "goto x;"]]),
    );
    expect(r.code).toContain('"goto x;"');
    expect(r.admissions.gotos).toEqual([]);
  });

  it("is three empty arrays for a body with nothing to admit", () => {
    const r = emitFunction(fn([{ kind: "return", value: irConst(1, 4) }]));
    expect(r.admissions).toEqual({ unrecovered: [], unlifted: [], gotos: [] });
  });
});

/**
 * ONE C VARIABLE PER CANONICAL REGISTER PER FUNCTION (peek-a-bin-n9cl.4).
 *
 * Registers used to reach the page undeclared, one free variable per NAME, so
 * `dx` and `edx` were two unrelated C variables for one machine register and
 * t64's `wcslen` tested a name nothing assigned (peek-a-bin-uxm). 979 of 1072
 * corpus functions carried the class at `2328657`; `cc` read clean only because
 * `corpus/emitAudits.ts`'s `preludeFor` invented a `long` per name. The rule
 * now: `registerVariables` declares one variable per canonical register at the
 * widest alias the body mentions, capped at the image width, and every read
 * and write is spelled through it — a narrow read as a cast, a narrow write as
 * a zero-extension (32-bit on x64) or a mask-merge (8/16-bit), with the
 * truncation IN the expression.
 */
describe("emitFunction — register variables are declared at the widest width and every alias is spelled through them", () => {
  const assign = (dest: IRExpr, src: IRExpr): IRStmt => ({ kind: "assign", dest, src });
  const ret = (value: IRExpr): IRStmt => ({ kind: "return", value });
  /** The declaration block: the lines between the header and the first blank line. */
  const decls = (code: string): string[] => {
    const lines = code.split("\n");
    const start = lines.findIndex((l) => l.endsWith(") {")) + 1;
    const end = lines.indexOf("", start);
    return end < 0 ? [] : lines.slice(start, end).map((l) => l.trim());
  };

  it("declares dx and edx as ONE variable and spells the narrow read through it", () => {
    // t64's wcslen shape at the IR level: EDX assigned, DX tested.
    const code = emitFunction(
      fn([
        assign(irReg("edx", 4), irConst(7, 4)),
        {
          kind: "while",
          condition: irBinary("!=", irReg("dx", 2), irConst(0, 4)),
          body: [assign(irReg("edx", 4), irBinary("-", irReg("edx", 4), irConst(1, 4)))],
        },
      ]),
    ).code;
    expect(decls(code)).toEqual(["int32_t edx;"]);
    expect(code).toContain("while ((uint16_t)edx != 0)");
    expect(code).not.toMatch(/\bdx\b/);
  });

  it("merges an 8-bit write into the wider variable with the truncation in the expression", () => {
    const code = emitFunction(
      fn([assign(irReg("al", 1), irReg("ecx", 4)), ret(irReg("eax", 4))], { is64: false }),
    ).code;
    expect(decls(code)).toEqual(["int32_t eax;", "int32_t ecx;"]);
    expect(code).toContain("    eax = (eax & ~0xFF) | (uint8_t)ecx;");
    expect(code).toContain("return eax;");
  });

  it("merges a 16-bit write with the 16-bit mask", () => {
    const code = emitFunction(
      fn([assign(irReg("ax", 2), irConst(0x1234, 4)), ret(irReg("eax", 4))], { is64: false }),
    ).code;
    expect(code).toContain("    eax = (eax & ~0xFFFF) | 0x1234;");
  });

  it("spells a high-byte read and write through the containing variable", () => {
    const code = emitFunction(
      fn([assign(irReg("ah", 1), irReg("cl", 1)), ret(irReg("ah", 1))], { is64: false }),
    ).code;
    // Only AH and CL are mentioned of their registers, and AH alone keeps its
    // own name — there is nothing wider to spell it through.
    expect(decls(code)).toEqual(["uint8_t ah;", "uint8_t cl;"]);
    expect(code).toContain("ah = cl;");

    const wide = emitFunction(
      fn([assign(irReg("ah", 1), irReg("cl", 1)), ret(irReg("eax", 4))], { is64: false }),
    ).code;
    expect(decls(wide)).toEqual(["uint8_t cl;", "int32_t eax;"]);
    expect(wide).toContain("    eax = (eax & ~0xFF00) | ((uint8_t)cl << 8);");
    const read = emitFunction(
      fn([assign(irReg("ecx", 4), irReg("ah", 1)), ret(irReg("eax", 4))], { is64: false }),
    ).code;
    expect(read).toContain("ecx = (uint8_t)(eax >> 8);");
  });

  it("forces a register mentioned as both AH and AL up to its 16-bit alias", () => {
    // `(uint8_t)(al >> 8)` would name bits AL does not have; the smallest
    // variable that holds both bytes is AX.
    const code = emitFunction(
      fn([ret(irBinary("==", irReg("ah", 1), irReg("al", 1)))], { is64: false }),
    ).code;
    expect(decls(code)).toEqual(["uint16_t ax;"]);
    expect(code).toContain("return (uint8_t)(ax >> 8) == (uint8_t)ax;");
  });

  it("zero-extends a 32-bit write on x64", () => {
    const code = emitFunction(
      fn([assign(irReg("eax", 4), irReg("ebx", 4)), ret(irReg("rax", 8))]),
    ).code;
    // EBX is the only mention of RBX, so it is the variable and needs no cast;
    // EAX is a sub-register of the declared RAX, so the write says what
    // happens to bits 63:32 (Intel SDM vol. 1 §3.4.1.1).
    expect(decls(code)).toEqual(["int32_t ebx;", "int64_t rax;"]);
    expect(code).toContain("    rax = (uint32_t)ebx;");
    expect(code).toContain("return rax;");
  });

  it("does not cast a constant that already fits the written width", () => {
    const code = emitFunction(
      fn([assign(irReg("eax", 4), irConst(0, 4)), ret(irReg("rax", 8))]),
    ).code;
    expect(code).toContain("    rax = 0;");
    expect(code).not.toContain("(uint32_t)0");
  });

  it("does not double a cast a narrow read already carries", () => {
    const code = emitFunction(
      fn([
        assign(irReg("eax", 4), irReg("ecx", 4)),
        ret(irBinary("+", irReg("rax", 8), irReg("rcx", 8))),
      ]),
    ).code;
    // ECX is a sub-register of the declared RCX, so its read is `(uint32_t)rcx`
    // and the write to EAX takes that text as its truncation.
    expect(code).toContain("    rax = (uint32_t)rcx;");
    expect(code).not.toContain("(uint32_t)(uint32_t)");
  });

  it("uses no compound spelling for a narrow write", () => {
    const code = emitFunction(
      fn([
        assign(irReg("eax", 4), irBinary("+", irReg("eax", 4), irConst(1, 4))),
        ret(irReg("rax", 8)),
      ]),
    ).code;
    expect(code).toContain("    rax = (uint32_t)((uint32_t)rax + 1);");
    expect(code).not.toContain("++");
  });

  /**
   * THE PE32 CAP, and the reason it is not "widest mentioned" alone. A 64-bit
   * name in a 32-bit function is a canonical name leaking in (the
   * `unencodableNames` corpus gate's class) — the variable is capped at 32 bits
   * and the leaked read is left exactly as written, UNDECLARED, so both that
   * gate and the undeclared-identifier gate see it. Spelling it through `ecx`
   * would hide the leak from both.
   */
  it("never declares a 64-bit register in a 32-bit function, and leaves a leaked name visible", () => {
    const code = emitFunction(
      fn([assign(irReg("ecx", 4), irConst(1, 4)), ret(irReg("rcx", 8))], { is64: false }),
    ).code;
    expect(decls(code)).toEqual(["int32_t ecx;"]);
    expect(code).not.toContain("int64_t");
    expect(code).toContain("return rcx;");
  });

  it("caps a function that mentions only the 64-bit name at the 32-bit alias", () => {
    const code = emitFunction(fn([ret(irReg("rcx", 8))], { is64: false })).code;
    expect(decls(code)).toEqual(["int32_t ecx;"]);
    expect(code).toContain("return rcx;");
  });

  it("declares a clobbered value uninitialised, and never assigns it", () => {
    const code = emitFunction(
      fn([ret(irBinary("+", irReg("rax", 8), irVar("clobbered_rcx_2", 8)))]),
    ).code;
    // Registers first, then the minted variables, each group sorted by name.
    expect(decls(code)).toEqual(["int64_t rax;", "int64_t clobbered_rcx_2;"]);
    expect(code).not.toMatch(/clobbered_rcx_2\s*=[^=]/);
  });

  it("declares a split-repair variable at the width it carries", () => {
    const code = emitFunction(
      fn([assign(irVar("ecx_3", 4), irReg("ecx", 4)), ret(irVar("ecx_3", 4))]),
    ).code;
    expect(decls(code)).toEqual(["int32_t ecx;", "int32_t ecx_3;"]);
  });

  it("declares a register a printed call result lands in, and not one whose result is dead", () => {
    const call: IRCall = { kind: "call", target: "sub_408000", args: [] };
    const printed = emitFunction(
      fn([
        { kind: "call_stmt", call, resultDest: irReg("rax", 8), addr: 0x1000 },
        { kind: "store", address: irReg("rcx", 8), value: irReg("rax", 8), size: 8, addr: 0x1004 },
        { kind: "return" },
      ]),
    ).code;
    expect(decls(printed)).toEqual(["int64_t rax;", "int64_t rcx;"]);
    const dead = emitFunction(
      fn([
        { kind: "call_stmt", call, resultDest: irReg("rax", 8), addr: 0x1000 },
        { kind: "return" },
      ]),
    ).code;
    expect(decls(dead)).toEqual([]);
  });

  /**
   * THE ONE MENTION THAT IS NOT AN `IRReg`. An indirect call carries its
   * register as the TEXT `(*esi)` in `IRCall.target`, and every undeclared
   * register left after the first corpus run of this rule was that shape —
   * 16/4/4/16 (function, name) pairs on t32/t64/w64/w32. The target is a read
   * like any other: declared, and spelled through the variable.
   */
  it("declares and spells the register an indirect call goes through", () => {
    const viaEsi: IRCall = { kind: "call", target: "(*esi)", args: [irReg("ebx", 4)] };
    const code = emitFunction(
      fn(
        [
          { kind: "call_stmt", call: viaEsi, resultDest: irReg("eax", 4), addr: 0x1000 },
          ret(irReg("eax", 4)),
        ],
        {
          is64: false,
        },
      ),
    ).code;
    // `eax = f(); return eax;` folds to `return f();`, so EAX is not mentioned.
    expect(decls(code)).toEqual(["int32_t ebx;", "int32_t esi;"]);
    expect(code).toContain("return ((intptr_t (*)())esi)(ebx);");

    // A sub-register target in a function that names the wider alias is spelled
    // through it, exactly as an operand read would be.
    const viaEcx: IRCall = { kind: "call", target: "(*ecx)", args: [] };
    const wide = emitFunction(
      fn([{ kind: "call_stmt", call: viaEcx, addr: 0x1000 }, ret(irReg("rcx", 8))]),
    ).code;
    expect(decls(wide)).toEqual(["int64_t rcx;"]);
    expect(wide).toContain("((intptr_t (*)())(uint32_t)rcx)();");
  });

  /**
   * THE RESIDUE. Names the emitter cannot declare honestly: a register
   * `isKnownRegister` refuses (`tmp_xchg`, a `stk_<addr>` slot) or one whose
   * width has no C integer (`st0` at 10 bytes, `xmm0` at 16). They print as
   * written, and `corpus/emitAudits.ts` counts them as `residue` beside the
   * gated `register + minted`.
   */
  it("declares none of the residue class", () => {
    const code = emitFunction(
      fn(
        [
          assign(irReg("st0", 10), irReg("xmm0", 16)),
          assign(irReg("tmp_xchg", 4), irReg("stk_401000", 4)),
          ret(irConst(0, 4)),
        ],
        { is64: false },
      ),
    ).code;
    expect(decls(code)).toEqual([]);
    expect(code).toContain("st0 = xmm0;");
    expect(code).toContain("tmp_xchg = stk_401000;");
  });

  /**
   * The `inferTypes → emit` register channel had no reader while registers were
   * undeclared. It is adopted only when it names the SAME width — the
   * `capturedOperandType` rule — so a `HANDLE`, a `PVOID` or a `struct_1*`
   * never reaches a register declaration (see `structPointer`).
   */
  it("adopts an inferred type when its width is the register's, and refuses otherwise", () => {
    const agree = {
      types: new Map([["rax", { kind: "int", size: 8, signed: false }]]),
    } as unknown as TypeContext;
    expect(decls(emitFunction(fn([ret(irReg("rax", 8))]), agree).code)).toEqual(["uint64_t rax;"]);

    const disagree = {
      types: new Map([["rax", { kind: "int", size: 4, signed: false }]]),
    } as unknown as TypeContext;
    expect(decls(emitFunction(fn([ret(irReg("rax", 8))]), disagree).code)).toEqual([
      "int64_t rax;",
    ]);

    const handle = typeCtxWith("rax", "handle");
    expect(decls(emitFunction(fn([ret(irReg("rax", 8))]), handle).code)).toEqual(["int64_t rax;"]);
  });

  it("keeps the register declarations beside the locals, ahead of the captures and unrecovered values", () => {
    const code = emitFunction(
      fn(
        [
          assign(irVar("flg_401000_0", 4), irReg("eax", 4)),
          ret(irBinary("+", irVar("flg_401000_0", 4), irUnknown("lost"))),
        ],
        { locals: [{ name: "var_8", type: "int32_t" }], is64: false },
      ),
    ).code;
    expect(decls(code).map((d) => d.split(" ")[1].replace(";", ""))).toEqual([
      "var_8",
      "eax",
      "flg_401000_0",
      "__unrecovered_1",
    ]);
  });
});
