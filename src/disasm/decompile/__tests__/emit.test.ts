import { describe, it, expect } from "vitest";
import type { IRFunction, IRStmt, IRPhi } from "../ir";
import { irConst, irReg, irVar, irBinary } from "../ir";
import { emitFunction } from "../emit";
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
