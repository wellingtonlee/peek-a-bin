import { describe, expect, it } from "vitest";
import { emitFunction } from "../emit";
import type { IRFunction, IRTry } from "../ir";
import { irConst, irReg, walkStmts } from "../ir";

describe("Exception Handling IR", () => {
  it("walkStmts should traverse try body and handler", () => {
    const tryStmt: IRTry = {
      kind: "try",
      body: [{ kind: "assign", dest: irReg("eax"), src: irConst(1), addr: 0x1000 }],
      handler: [{ kind: "assign", dest: irReg("eax"), src: irConst(0), addr: 0x2000 }],
      filterExpr: irConst(1),
    };

    const visited: string[] = [];
    walkStmts([tryStmt], (expr) => {
      if (expr.kind === "const") visited.push(`const:${expr.value}`);
      if (expr.kind === "reg") visited.push(`reg:${expr.name}`);
    });

    // Should visit: dest+src in body (eax, 1), dest+src in handler (eax, 0), filterExpr (1)
    expect(visited).toContain("reg:eax");
    expect(visited).toContain("const:1");
    expect(visited).toContain("const:0");
  });

  /**
   * A `try` carrying no filter information at all ADMITS that, and must not
   * fall back to `EXCEPTION_EXECUTE_HANDLER`.
   *
   * That literal used to be the `else` arm of
   * `stmt.filterExpr ? emitExpr(...) : "EXCEPTION_EXECUTE_HANDLER"`, and
   * nothing in production ever built a `filterExpr` — so it was printed on
   * every `__except` the decompiler emitted, as a claim about a filter nothing
   * had read (peek-a-bin-j4uk.5). Absence is now the unrecovered case.
   */
  it("emitFunction should emit __try/__except blocks, admitting an unread filter", () => {
    const tryStmt: IRTry = {
      kind: "try",
      body: [{ kind: "assign", dest: irReg("eax"), src: irConst(42), addr: 0x1000 }],
      handler: [{ kind: "assign", dest: irReg("eax"), src: irConst(0), addr: 0x2000 }],
    };

    const func: IRFunction = {
      name: "test_func",
      address: 0x1000,
      returnType: "void",
      params: [],
      locals: [],
      body: [tryStmt],
    };

    const result = emitFunction(func);
    expect(result.code).toContain("__try");
    expect(result.code).toContain("__except");
    expect(result.code).not.toContain("EXCEPTION_EXECUTE_HANDLER");
    expect(result.code).toContain("__unrecovered_");
    // The admission is a declared local, so the emitted C still compiles and
    // the refusal is visible to the unrecovered-values instrument.
    expect(result.code).toContain("intptr_t __unrecovered_1;");
    expect(result.code).toContain("eax = 0x2A");
  });

  /**
   * The one circumstance in which `EXCEPTION_EXECUTE_HANDLER` is a READING:
   * the `.pdata` scope table's `handler` field held the literal 1, which is the
   * format's own spelling of it. `pipeline.ts` is what decides that;
   * `pipeline.test.ts` covers the decision end to end, and this covers the
   * spelling.
   */
  it("emitFunction should print EXCEPTION_EXECUTE_HANDLER only when the table said so", () => {
    const tryStmt: IRTry = {
      kind: "try",
      body: [{ kind: "raw", text: "risky_call()", addr: 0x1000 }],
      handler: [{ kind: "raw", text: "handle_error()", addr: 0x2000 }],
      filterSource: { spelling: "execute-handler" },
    };

    const func: IRFunction = {
      name: "test_func",
      address: 0x1000,
      returnType: "void",
      params: [],
      locals: [],
      body: [tryStmt],
    };

    const result = emitFunction(func);
    expect(result.code).toContain("__except(EXCEPTION_EXECUTE_HANDLER");
    expect(result.code).toContain("read from the .pdata scope table");
    expect(result.code).not.toContain("__unrecovered_");
  });

  it("emitFunction should name the filter routine it could not recover", () => {
    const tryStmt: IRTry = {
      kind: "try",
      body: [{ kind: "raw", text: "risky_call()", addr: 0x1000 }],
      handler: [{ kind: "raw", text: "handle_error()", addr: 0x2000 }],
      filterSource: { spelling: "unrecovered", filterAddress: 0x14000fc19 },
    };

    const func: IRFunction = {
      name: "test_func",
      address: 0x1000,
      returnType: "void",
      params: [],
      locals: [],
      body: [tryStmt],
    };

    const result = emitFunction(func);
    expect(result.code).toContain("filter routine at 0x14000FC19");
    expect(result.code).not.toContain("EXCEPTION_EXECUTE_HANDLER");
  });

  it("emitFunction should emit filter expression when provided", () => {
    const tryStmt: IRTry = {
      kind: "try",
      body: [{ kind: "raw", text: "risky_call()", addr: 0x1000 }],
      handler: [{ kind: "raw", text: "handle_error()", addr: 0x2000 }],
      filterExpr: irConst(1),
      // A recovered expression outranks the scope table's account of the
      // filter, which is only ever the fallback for not having one.
      filterSource: { spelling: "execute-handler" },
    };

    const func: IRFunction = {
      name: "test_func",
      address: 0x1000,
      returnType: "void",
      params: [],
      locals: [],
      body: [tryStmt],
    };

    const result = emitFunction(func);
    expect(result.code).toContain("__except(1)");
    expect(result.code).not.toContain("EXCEPTION_EXECUTE_HANDLER");
  });
});
