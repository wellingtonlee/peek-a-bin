import { describe, expect, it } from "vitest";
import type { BasicBlock } from "../../cfg";
import type { EntryBinding } from "../entryBindings";
import type { IRExpr, IRStmt } from "../ir";
import { canonReg, irBinary, irConst, irDeref, irReg } from "../ir";
import { buildSSA, computeDomFrontier, computeDominators, computeRPO } from "../ssa";
import { destroySSA } from "../ssadestroy";
import { ssaOptimize } from "../ssaopt";

// ── Helpers ──

function makeBlock(id: number, succs: number[], preds: number[]): BasicBlock {
  return {
    id,
    startAddr: id * 0x100,
    endAddr: id * 0x100 + 0x10,
    insns: [],
    succs,
    preds,
  };
}

// ── Tests ──

describe("computeRPO", () => {
  it("computes RPO for linear CFG", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [2], [0]), makeBlock(2, [], [1])];
    const rpo = computeRPO(blocks);
    expect(rpo).toEqual([0, 1, 2]);
  });

  it("computes RPO for diamond CFG", () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const rpo = computeRPO(blocks);
    expect(rpo[0]).toBe(0);
    expect(rpo[rpo.length - 1]).toBe(3);
  });
});

describe("computeDominators", () => {
  it("computes idom for diamond CFG", () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    expect(idom.get(0)).toBe(0); // entry dominates itself
    expect(idom.get(1)).toBe(0);
    expect(idom.get(2)).toBe(0);
    expect(idom.get(3)).toBe(0); // merge dominated by entry
  });

  it("computes idom for sequential CFG", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [2], [0]), makeBlock(2, [], [1])];
    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    expect(idom.get(1)).toBe(0);
    expect(idom.get(2)).toBe(1);
  });
});

describe("computeDomFrontier", () => {
  it("computes DF for diamond CFG", () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const rpo = computeRPO(blocks);
    const idom = computeDominators(blocks, rpo);
    const df = computeDomFrontier(blocks, idom);
    // Blocks 1 and 2 have block 3 in their DF
    expect(df.get(1)!.has(3)).toBe(true);
    expect(df.get(2)!.has(3)).toBe(true);
    expect(df.get(0)!.size).toBe(0); // entry has no DF
  });
});

describe("buildSSA", () => {
  it("inserts phi at merge point for diamond CFG", () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    // Block 0: empty
    liftedBlocks.set(0, []);
    // Block 1: eax = 1
    liftedBlocks.set(1, [{ kind: "assign", dest: irReg("eax"), src: irConst(1) }]);
    // Block 2: eax = 2
    liftedBlocks.set(2, [{ kind: "assign", dest: irReg("eax"), src: irConst(2) }]);
    // Block 3: uses eax (return eax)
    liftedBlocks.set(3, [{ kind: "return", value: irReg("eax") }]);

    const ctx = buildSSA(blocks, liftedBlocks);

    // Block 3 should have a phi for rax
    const phisAt3 = ctx.phis.get(3) ?? [];
    expect(phisAt3.length).toBe(1);
    expect(canonReg(phisAt3[0].dest.name)).toBe("rax");
    expect(phisAt3[0].operands.length).toBe(2);
  });

  it("does not insert phi when only one definition reaches", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [{ kind: "assign", dest: irReg("eax"), src: irConst(42) }]);
    liftedBlocks.set(1, [{ kind: "return", value: irReg("eax") }]);

    const ctx = buildSSA(blocks, liftedBlocks);

    // No phis needed
    const phisAt1 = ctx.phis.get(1) ?? [];
    expect(phisAt1.length).toBe(0);

    // The return in block 1 reads the definition in block 0, which is version
    // 1: version 0 is reserved for the value a register holds on entry to the
    // function, and `mov eax, 42` overwrites that (peek-a-bin-swi). Numbering
    // the first definition 0 made the two indistinguishable, and every pass in
    // ssaopt.ts that keys on (register, version) then treated an incoming value
    // as though the definition had already run.
    const retStmt = liftedBlocks.get(1)![0];
    expect(retStmt.kind).toBe("return");
    if (retStmt.kind === "return" && retStmt.value?.kind === "reg") {
      expect(retStmt.value.version).toBe(1);
    }
  });

  it("handles loop CFG with phi at header", () => {
    const blocks = [
      makeBlock(0, [1], []), // entry → header
      makeBlock(1, [2, 3], [0, 2]), // header (loop header, preds: entry + back-edge)
      makeBlock(2, [1], [1]), // body → back to header
      makeBlock(3, [], [1]), // exit
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [{ kind: "assign", dest: irReg("ecx"), src: irConst(0) }]);
    liftedBlocks.set(1, [{ kind: "return", value: irReg("ecx") }]);
    liftedBlocks.set(2, [
      { kind: "assign", dest: irReg("ecx"), src: irBinary("+", irReg("ecx"), irConst(1)) },
    ]);
    liftedBlocks.set(3, []);

    const ctx = buildSSA(blocks, liftedBlocks);

    // Block 1 (header) should have a phi for rcx
    const phisAt1 = ctx.phis.get(1) ?? [];
    expect(phisAt1.length).toBeGreaterThanOrEqual(1);
    const rcxPhi = phisAt1.find((p) => canonReg(p.dest.name) === "rcx");
    expect(rcxPhi).toBeDefined();
  });
});

describe("ssaOptimize", () => {
  it("eliminates dead definitions", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax"), src: irConst(1) },
      { kind: "assign", dest: irReg("ebx"), src: irConst(2) },
      { kind: "return", value: irReg("eax") },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    // ebx assignment should be eliminated (unused)
    const stmts = ctx.liftedBlocks.get(0)!;
    const ebxAssign = stmts.find(
      (s) => s.kind === "assign" && s.dest.kind === "reg" && canonReg(s.dest.name) === "rbx",
    );
    expect(ebxAssign).toBeUndefined();
  });

  it("propagates constants through SSA", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [{ kind: "assign", dest: irReg("eax"), src: irConst(42) }]);
    liftedBlocks.set(1, [{ kind: "return", value: irReg("eax") }]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    // The return value should be constant 42 (propagated from block 0)
    const retStmt = ctx.liftedBlocks.get(1)!.find((s) => s.kind === "return");
    expect(retStmt).toBeDefined();
    if (retStmt?.kind === "return" && retStmt.value) {
      expect(retStmt.value.kind).toBe("const");
      if (retStmt.value.kind === "const") {
        expect(retStmt.value.value).toBe(42);
      }
    }
  });
});

describe("globalValueNumbering", () => {
  it("eliminates redundant expressions (basic CSE)", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    // a_0 already defined (param), r_1 = a + 1, r_2 = a + 1, return r_2
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax"), src: irBinary("+", irReg("ebx"), irConst(1)) },
      { kind: "assign", dest: irReg("ecx"), src: irBinary("+", irReg("ebx"), irConst(1)) },
      { kind: "return", value: irReg("ecx") },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    // ecx assignment should be eliminated (CSE + DCE), return should use eax's version
    const stmts = ctx.liftedBlocks.get(0)!;
    const ecxAssign = stmts.find(
      (s) => s.kind === "assign" && s.dest.kind === "reg" && canonReg(s.dest.name) === "rcx",
    );
    expect(ecxAssign).toBeUndefined();
  });

  it("normalizes commutative ops (a+b == b+a)", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax"), src: irBinary("+", irReg("ebx"), irReg("ecx")) },
      { kind: "assign", dest: irReg("edx"), src: irBinary("+", irReg("ecx"), irReg("ebx")) },
      { kind: "return", value: irReg("edx") },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    const stmts = ctx.liftedBlocks.get(0)!;
    const edxAssign = stmts.find(
      (s) => s.kind === "assign" && s.dest.kind === "reg" && canonReg(s.dest.name) === "rdx",
    );
    expect(edxAssign).toBeUndefined();
  });

  it("preserves non-commutative ops (a-b != b-a)", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax"), src: irBinary("-", irReg("ebx"), irReg("ecx")) },
      { kind: "assign", dest: irReg("edx"), src: irBinary("-", irReg("ecx"), irReg("ebx")) },
      { kind: "return", value: irBinary("+", irReg("eax"), irReg("edx")) },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    // Both assignments should survive
    const stmts = ctx.liftedBlocks.get(0)!;
    const assigns = stmts.filter((s) => s.kind === "assign");
    expect(assigns.length).toBe(2);
  });

  it("does not CSE calls (side effects)", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    const call: IRExpr = { kind: "call", target: "foo", args: [] };
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax"), src: { ...call } },
      { kind: "assign", dest: irReg("ecx"), src: { ...call } },
      { kind: "return", value: irBinary("+", irReg("eax"), irReg("ecx")) },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    const stmts = ctx.liftedBlocks.get(0)!;
    const assigns = stmts.filter((s) => s.kind === "assign");
    expect(assigns.length).toBe(2);
  });

  it("does not CSE derefs (memory aliasing)", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax"), src: irDeref(irReg("ebx"), 4) },
      { kind: "assign", dest: irReg("ecx"), src: irDeref(irReg("ebx"), 4) },
      { kind: "return", value: irBinary("+", irReg("eax"), irReg("ecx")) },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    const stmts = ctx.liftedBlocks.get(0)!;
    const assigns = stmts.filter((s) => s.kind === "assign");
    expect(assigns.length).toBe(2);
  });

  it("eliminates nested redundant expressions", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    // r1 = (a + b) * c, r2 = (a + b) * c
    liftedBlocks.set(0, [
      {
        kind: "assign",
        dest: irReg("eax"),
        src: irBinary("*", irBinary("+", irReg("ebx"), irReg("ecx")), irReg("edx")),
      },
      {
        kind: "assign",
        dest: irReg("esi"),
        src: irBinary("*", irBinary("+", irReg("ebx"), irReg("ecx")), irReg("edx")),
      },
      { kind: "return", value: irReg("esi") },
    ]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    const stmts = ctx.liftedBlocks.get(0)!;
    const esiAssign = stmts.find(
      (s) => s.kind === "assign" && s.dest.kind === "reg" && canonReg(s.dest.name) === "rsi",
    );
    expect(esiAssign).toBeUndefined();
  });

  it("CSEs across blocks under same dominator", () => {
    // Block 0 (entry) → Block 1, Block 2
    // Block 0 defines r1 = a + b
    // Block 1 defines r2 = a + b (same expr, dominated by block 0)
    const blocks = [makeBlock(0, [1, 2], []), makeBlock(1, [], [0]), makeBlock(2, [], [0])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax"), src: irBinary("+", irReg("ebx"), irConst(5)) },
    ]);
    liftedBlocks.set(1, [
      { kind: "assign", dest: irReg("ecx"), src: irBinary("+", irReg("ebx"), irConst(5)) },
      { kind: "return", value: irReg("ecx") },
    ]);
    liftedBlocks.set(2, [{ kind: "return", value: irReg("eax") }]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);

    // ecx assignment in block 1 should be eliminated
    const stmts1 = ctx.liftedBlocks.get(1)!;
    const ecxAssign = stmts1.find(
      (s) => s.kind === "assign" && s.dest.kind === "reg" && canonReg(s.dest.name) === "rcx",
    );
    expect(ecxAssign).toBeUndefined();
  });
});

describe("destroySSA", () => {
  it("strips version numbers", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [{ kind: "assign", dest: irReg("eax"), src: irConst(5) }]);
    liftedBlocks.set(1, [{ kind: "return", value: irReg("eax") }]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);
    destroySSA(ctx);

    // All registers should have no version
    for (const [, stmts] of ctx.liftedBlocks) {
      for (const s of stmts) {
        if (s.kind === "assign" && s.dest.kind === "reg") {
          expect(s.dest.version).toBeUndefined();
        }
        if (s.kind === "return" && s.value?.kind === "reg") {
          expect(s.value.version).toBeUndefined();
        }
      }
    }
  });

  it("round-trips diamond CFG correctly", () => {
    const blocks = [
      makeBlock(0, [1, 2], []),
      makeBlock(1, [3], [0]),
      makeBlock(2, [3], [0]),
      makeBlock(3, [], [1, 2]),
    ];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, []);
    liftedBlocks.set(1, [{ kind: "assign", dest: irReg("eax"), src: irConst(1) }]);
    liftedBlocks.set(2, [{ kind: "assign", dest: irReg("eax"), src: irConst(2) }]);
    liftedBlocks.set(3, [{ kind: "return", value: irReg("eax") }]);

    const ctx = buildSSA(blocks, liftedBlocks);
    ssaOptimize(ctx);
    destroySSA(ctx);

    // All phis should be cleared
    for (const [, phis] of ctx.phis) {
      expect(phis.length).toBe(0);
    }

    // Block 3 should still have a return
    const retStmt = ctx.liftedBlocks.get(3)!.find((s) => s.kind === "return");
    expect(retStmt).toBeDefined();
  });
});

/**
 * A register whose ENTRY value is a parameter reads as the parameter.
 *
 * Version 0 is the one version no statement defines (`newVersion` starts at 1),
 * so it is the only point at which the pipeline knows a read is the incoming
 * value; `bindEntryValues` runs on that information before the versions come
 * off. The bindings here are what `entryBindings.ts` produces for an x64
 * function with a two-parameter signature (peek-a-bin-n9cl.5).
 */
describe("destroySSA — entry values bound to parameters", () => {
  const X64: ReadonlyMap<string, EntryBinding> = new Map([
    ["rcx", { name: "arg_0", size: 8, register: "rcx" }],
    ["rdx", { name: "arg_1", size: 8, register: "rdx" }],
  ]);
  const X86_THISCALL: ReadonlyMap<string, EntryBinding> = new Map([
    ["rcx", { name: "arg_ecx", size: 4, register: "rcx" }],
  ]);

  it("rewrites a read of version 0 to the parameter, and only version 0", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    // `rax = [rcx + 8]` reads the entry RCX; `rcx = [rdx]` redefines it; the
    // store then reads the NEW rcx, which is not the argument.
    liftedBlocks.set(0, [
      {
        kind: "assign",
        dest: irReg("rax", 8),
        src: irDeref(irBinary("+", irReg("rcx", 8), irConst(8)), 8),
      },
      { kind: "assign", dest: irReg("rcx", 8), src: irDeref(irReg("rdx", 8), 8) },
      { kind: "store", address: irReg("rcx", 8), value: irReg("rax", 8), size: 8 },
    ]);
    liftedBlocks.set(1, [{ kind: "return", value: irReg("rax", 8) }]);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx, X64);

    const [load, redef, store] = ctx.liftedBlocks.get(0) ?? [];
    expect(load).toEqual({
      kind: "assign",
      dest: irReg("rax", 8),
      src: irDeref(irBinary("+", { kind: "var", name: "arg_0", size: 8 }, irConst(8)), 8),
    });
    // The other argument register, read at version 0 as the load's address.
    expect(redef).toEqual({
      kind: "assign",
      dest: irReg("rcx", 8),
      src: irDeref({ kind: "var", name: "arg_1", size: 8 }, 8),
    });
    // A later version stays the register.
    expect(store).toEqual({
      kind: "store",
      address: irReg("rcx", 8),
      value: irReg("rax", 8),
      size: 8,
    });
  });

  it("takes no copy at entry for a bound register", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("rax", 8), src: irReg("rcx", 8) },
      { kind: "assign", dest: irReg("rcx", 8), src: irConst(0) },
      { kind: "store", address: irReg("rax", 8), value: irReg("rcx", 8), size: 8 },
    ]);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx, X64);
    const stmts = ctx.liftedBlocks.get(0) ?? [];
    // The parameter IS the entry value: nothing writes a `rcx_0` or a `rcx`
    // from it, and nothing mentions `rcx_0` at all.
    const names = new Set<string>();
    for (const st of stmts) {
      if (st.kind === "assign" && st.dest.kind === "var") names.add(st.dest.name);
    }
    expect([...names]).toEqual([]);
    expect(stmts[0]).toEqual({
      kind: "assign",
      dest: irReg("rax", 8),
      src: { kind: "var", name: "arg_0", size: 8 },
    });
  });

  // The parameter AT THE READ'S WIDTH, not a cast: the emitter chooses the
  // cast's signedness from the operation (`varText`), which a cast node baked
  // into the IR cannot — `(uint32_t)arg_0 < 0` for a `js` is constantly false.
  it("spells a narrower read of the entry value as the parameter at that width", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax", 4), src: irReg("ecx", 4) },
      { kind: "assign", dest: irReg("ebx", 4), src: irReg("cl", 1) },
      { kind: "assign", dest: irReg("edi", 4), src: irReg("ch", 1) },
    ]);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx, X64);
    expect(ctx.liftedBlocks.get(0)).toEqual([
      { kind: "assign", dest: irReg("eax", 4), src: { kind: "var", name: "arg_0", size: 4 } },
      { kind: "assign", dest: irReg("ebx", 4), src: { kind: "var", name: "arg_0", size: 1 } },
      // A high byte cannot be expressed as a width and keeps the explicit shape.
      {
        kind: "assign",
        dest: irReg("edi", 4),
        src: {
          kind: "cast",
          type: "uint8_t",
          operand: irBinary(">>", { kind: "var", name: "arg_0", size: 8 }, irConst(8)),
        },
      },
    ]);
  });

  it("reads a branch condition's entry value as the parameter", () => {
    const blocks = [makeBlock(0, [1, 2], []), makeBlock(1, [], [0]), makeBlock(2, [], [0])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      {
        kind: "branch",
        condition: irBinary("==", irReg("rcx", 8), irConst(0)),
        target: 2,
        jcc: "je",
      },
    ]);
    liftedBlocks.set(1, []);
    liftedBlocks.set(2, []);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx, X64);
    expect(ctx.liftedBlocks.get(0)?.[0]).toEqual({
      kind: "branch",
      condition: irBinary("==", { kind: "var", name: "arg_0", size: 8 }, irConst(0)),
      target: 2,
      jcc: "je",
    });
  });

  it("leaves an unbound argument register alone", () => {
    // `r8` at version 0 in a function whose signature has two parameters: the
    // scan never saw it read, so it stays a register — and under n9cl.4 a
    // declared, uninitialised one on the page, which is the visible refusal.
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [{ kind: "assign", dest: irReg("rax", 8), src: irReg("r8", 8) }]);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx, X64);
    expect(ctx.liftedBlocks.get(0)).toEqual([
      { kind: "assign", dest: irReg("rax", 8), src: irReg("r8", 8) },
    ]);
  });

  // The phi's operand is typed IRReg and cannot be rewritten in place, so the
  // lowering reads the parameter when it emits the copy — and it MUST emit one:
  // the same-register self-copy skip would leave C's `rcx` holding nothing on
  // the path where the machine leaves the argument in the register.
  it("lowers a phi operand that is the entry value to a copy from the parameter", () => {
    const blocks = [makeBlock(0, [1, 2], []), makeBlock(1, [2], [0]), makeBlock(2, [], [0, 1])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      {
        kind: "branch",
        condition: irBinary("==", irReg("rax", 8), irConst(0)),
        target: 2,
        jcc: "je",
      },
    ]);
    liftedBlocks.set(1, [
      { kind: "assign", dest: irReg("rcx", 8), src: irDeref(irReg("rbx", 8), 8) },
    ]);
    liftedBlocks.set(2, [
      { kind: "store", address: irReg("rbx", 8), value: irReg("rcx", 8), size: 8 },
    ]);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx, X64);

    // Block 0's bypass edge carries the entry value into the join.
    const b0 = ctx.liftedBlocks.get(0) ?? [];
    expect(b0).toContainEqual({
      kind: "assign",
      dest: irReg("rcx", 8),
      src: { kind: "var", name: "arg_0", size: 8 },
    });
    // The copy lands before the terminator, and no `rcx_0` repair was taken.
    expect(b0[b0.length - 1].kind).toBe("branch");
    for (const [, stmts] of ctx.liftedBlocks)
      for (const st of stmts)
        expect(st.kind === "assign" && st.dest.kind === "var" && st.dest.name === "rcx_0").toBe(
          false,
        );
    // The join reads the register, which the copy has just assigned.
    expect(ctx.liftedBlocks.get(2)).toEqual([
      { kind: "store", address: irReg("rbx", 8), value: irReg("rcx", 8), size: 8 },
    ]);
  });

  it("spells an x86 thiscall body's entry ECX as arg_ecx at the code's width", () => {
    const blocks = [makeBlock(0, [1, 2], []), makeBlock(1, [2], [0]), makeBlock(2, [], [0, 1])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("eax", 4), src: irDeref(irReg("ecx", 4), 4) },
      {
        kind: "branch",
        condition: irBinary("==", irReg("eax", 4), irConst(0)),
        target: 2,
        jcc: "je",
      },
    ]);
    liftedBlocks.set(1, [
      { kind: "assign", dest: irReg("ecx", 4), src: irDeref(irReg("ebx", 4), 4) },
    ]);
    liftedBlocks.set(2, [
      { kind: "store", address: irReg("ebx", 4), value: irReg("ecx", 4), size: 4 },
    ]);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx, X86_THISCALL);
    const b0 = ctx.liftedBlocks.get(0) ?? [];
    expect(b0[0]).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: irDeref({ kind: "var", name: "arg_ecx", size: 4 }, 4),
    });
    // The phi copy is spelled `ecx`, the width the code uses, never `rcx`.
    expect(b0).toContainEqual({
      kind: "assign",
      dest: irReg("ecx", 4),
      src: { kind: "var", name: "arg_ecx", size: 4 },
    });
  });

  // NEGATIVE CONTROL for the whole describe: no bindings, no change.
  it("changes nothing when no register is bound", () => {
    const blocks = [makeBlock(0, [], [])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    liftedBlocks.set(0, [{ kind: "assign", dest: irReg("rax", 8), src: irReg("rcx", 8) }]);
    const ctx = buildSSA(blocks, liftedBlocks);
    destroySSA(ctx);
    expect(ctx.liftedBlocks.get(0)).toEqual([
      { kind: "assign", dest: irReg("rax", 8), src: irReg("rcx", 8) },
    ]);
  });
});

/**
 * `simplifyPhis` substitutes a phi OPERAND into every reader of the phi's
 * destination, and a phi operand is the register's 64-bit *identity* rather than
 * a spelling: `insertPhis` mints every phi as `irReg(canonReg(...))` and the
 * operand fill copies that name and width verbatim (peek-a-bin-1k4,
 * peek-a-bin-pzws, peek-a-bin-0s6e). `destroySSA` corrects that for a lowered
 * phi copy, via `registerSpeller`; a substituted operand becomes an ordinary
 * read with no lowering step left to correct it.
 *
 * Found while landing peek-a-bin-6f3v, which made an RSI phi trivial in one
 * function per 32-bit corpus binary and took `unencodableNames` from 0 to 34
 * mentions — 9 reads of `rsi_1` and 9 of `rdi_1` in a PE32 image that has no
 * such register. Output-neutral on its own: byte-identical emitted C on all 1127
 * functions of all four binaries at `bd73798`.
 */
describe("simplifyPhis spelling", () => {
  /**
   * The phi is built by hand rather than by `insertPhis`, deliberately: which of
   * a trivial phi's operands is `nonSelf[0]` depends on predecessor order, and
   * in the corpus one operand carries the canonical name while the other has
   * been rewritten to a real spelling by copy propagation. Pinning the bad one
   * as the survivor is what makes the assertion mean something in both orders.
   */
  it("spells a substituted phi operand the way the value's own mentions spell it", () => {
    const blocks = [makeBlock(0, [1], []), makeBlock(1, [], [0])];
    const liftedBlocks = new Map<number, IRStmt[]>();
    // A deref, so neither constant nor copy propagation can fold the value away
    // and the read below really is a register read.
    liftedBlocks.set(0, [
      { kind: "assign", dest: irReg("esi", 4), src: irDeref(irReg("ebx", 4), 4) },
    ]);
    liftedBlocks.set(1, []);
    const ctx = buildSSA(blocks, liftedBlocks);

    // One phi, at block 1, whose single operand is the version block 0 defines —
    // named the way `insertPhis` and the operand fill name it, i.e. the 64-bit
    // parent at the 64-bit width.
    const def = ctx.liftedBlocks.get(0)?.[0];
    if (def?.kind !== "assign" || def.dest.kind !== "reg") throw new Error("no definition");
    const version = def.dest.version as number;
    ctx.phis.set(1, [
      {
        kind: "phi",
        dest: irReg("rsi", 8, version + 1),
        operands: [{ blockId: 0, value: irReg("rsi", 8, version) }],
      },
    ]);
    ctx.liftedBlocks.set(1, [{ kind: "return", value: irReg("rsi", 8, version + 1) }]);

    ssaOptimize(ctx);
    destroySSA(ctx);

    const ret = ctx.liftedBlocks.get(1)?.find((st) => st.kind === "return");
    if (ret?.kind !== "return" || ret.value?.kind !== "reg") throw new Error("no return");
    // `rsi` is the register's IDENTITY, which is what SSA keys on and not a name
    // this function ever mentions.
    expect(ret.value.name).toBe("esi");
  });
});
