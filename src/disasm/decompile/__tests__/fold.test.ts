import { describe, expect, it } from "vitest";
import { foldBlock, hasSideEffects } from "../fold";
import type { IRExpr, IRStmt } from "../ir";
import { irBinary, irConst, irDeref, irReg, irUnary } from "../ir";

function assign(dest: IRExpr, src: IRExpr): IRStmt {
  return { kind: "assign", dest, src };
}

function foldExprVia(src: IRExpr): IRExpr {
  const stmts = foldBlock([assign(irReg("rax"), src)]);
  return stmts.length > 0 && stmts[0].kind === "assign" ? stmts[0].src : src;
}

describe("fold rules", () => {
  describe("div/mod folding", () => {
    it("folds const / const", () => {
      const result = foldExprVia(irBinary("/", irConst(10), irConst(3)));
      expect(result).toEqual(irConst(3, 4));
    });

    it("folds const % const", () => {
      const result = foldExprVia(irBinary("%", irConst(10), irConst(3)));
      expect(result).toEqual(irConst(1, 4));
    });

    it("skips division by zero", () => {
      const result = foldExprVia(irBinary("/", irConst(10), irConst(0)));
      expect(result.kind).toBe("binary");
    });
  });

  describe("comparison folding", () => {
    it("folds const == const (true)", () => {
      const result = foldExprVia(irBinary("==", irConst(5), irConst(5)));
      expect(result).toEqual(irConst(1, 4));
    });

    it("folds const == const (false)", () => {
      const result = foldExprVia(irBinary("==", irConst(5), irConst(3)));
      expect(result).toEqual(irConst(0, 4));
    });

    it("folds const < const", () => {
      const result = foldExprVia(irBinary("<", irConst(3), irConst(5)));
      expect(result).toEqual(irConst(1, 4));
    });

    it("folds const >= const", () => {
      const result = foldExprVia(irBinary(">=", irConst(3), irConst(5)));
      expect(result).toEqual(irConst(0, 4));
    });
  });

  describe("ternary simplification", () => {
    it("cond ? X : X → X", () => {
      const expr: IRExpr = {
        kind: "ternary",
        condition: irReg("eax"),
        then: irConst(42),
        else: irConst(42),
      };
      const result = foldExprVia(expr);
      expect(result).toEqual(irConst(42, 4));
    });

    it("1 ? A : B → A", () => {
      const expr: IRExpr = {
        kind: "ternary",
        condition: irConst(1),
        then: irConst(10),
        else: irConst(20),
      };
      const result = foldExprVia(expr);
      expect(result).toEqual(irConst(10, 4));
    });

    it("0 ? A : B → B", () => {
      const expr: IRExpr = {
        kind: "ternary",
        condition: irConst(0),
        then: irConst(10),
        else: irConst(20),
      };
      const result = foldExprVia(expr);
      expect(result).toEqual(irConst(20, 4));
    });
  });

  describe("sign-extend patterns", () => {
    it("(x << 24) >> 24 → (int8_t)x", () => {
      const expr = irBinary(">>", irBinary("<<", irReg("eax"), irConst(24)), irConst(24));
      const result = foldExprVia(expr);
      expect(result.kind).toBe("cast");
      if (result.kind === "cast") {
        expect(result.type).toBe("int8_t");
      }
    });

    it("(x << 16) >> 16 → (int16_t)x", () => {
      const expr = irBinary(">>", irBinary("<<", irReg("eax"), irConst(16)), irConst(16));
      const result = foldExprVia(expr);
      expect(result.kind).toBe("cast");
      if (result.kind === "cast") {
        expect(result.type).toBe("int16_t");
      }
    });
  });

  describe("strength reduction", () => {
    it("x * 2 → x << 1", () => {
      const result = foldExprVia(irBinary("*", irReg("eax"), irConst(2)));
      expect(result.kind).toBe("binary");
      if (result.kind === "binary") {
        expect(result.op).toBe("<<");
        expect(result.right).toEqual(irConst(1, 4));
      }
    });

    it("x * 8 → x << 3", () => {
      const result = foldExprVia(irBinary("*", irReg("eax"), irConst(8)));
      expect(result.kind).toBe("binary");
      if (result.kind === "binary") {
        expect(result.op).toBe("<<");
        expect(result.right).toEqual(irConst(3, 4));
      }
    });

    it("x / 4 → x >>> 2", () => {
      const result = foldExprVia(irBinary("/", irReg("eax"), irConst(4)));
      expect(result.kind).toBe("binary");
      if (result.kind === "binary") {
        expect(result.op).toBe(">>>");
        expect(result.right).toEqual(irConst(2, 4));
      }
    });

    it("x % 4 → x & 3", () => {
      const result = foldExprVia(irBinary("%", irReg("eax"), irConst(4)));
      expect(result.kind).toBe("binary");
      if (result.kind === "binary") {
        expect(result.op).toBe("&");
        expect(result.right).toEqual(irConst(3, 4));
      }
    });
  });

  describe("double-cast removal", () => {
    it("(int8_t)(int32_t)x → (int8_t)x", () => {
      const expr: IRExpr = {
        kind: "cast",
        type: "int8_t",
        operand: { kind: "cast", type: "int32_t", operand: irReg("eax") },
      };
      const result = foldExprVia(expr);
      expect(result.kind).toBe("cast");
      if (result.kind === "cast") {
        expect(result.type).toBe("int8_t");
        expect(result.operand.kind).toBe("reg");
      }
    });
  });

  describe("negation absorption", () => {
    it("!(x == y) → x != y", () => {
      const result = foldExprVia(irUnary("!", irBinary("==", irReg("eax"), irReg("ebx"))));
      expect(result.kind).toBe("binary");
      if (result.kind === "binary") {
        expect(result.op).toBe("!=");
      }
    });

    it("!(x < y) → x >= y", () => {
      const result = foldExprVia(irUnary("!", irBinary("<", irReg("eax"), irReg("ebx"))));
      expect(result.kind).toBe("binary");
      if (result.kind === "binary") {
        expect(result.op).toBe(">=");
      }
    });

    it("!(x u> y) → x u<= y", () => {
      const result = foldExprVia(irUnary("!", irBinary("u>", irReg("eax"), irReg("ebx"))));
      expect(result.kind).toBe("binary");
      if (result.kind === "binary") {
        expect(result.op).toBe("u<=");
      }
    });
  });
});

// Every JavaScript bitwise operator coerces its operands to *int32* first, so
// the obvious spelling of this folder silently truncates any 64-bit operand.
// The evaluator answers these in BigInt and returns null — leaving the
// expression unfolded — whenever it cannot answer exactly. An unfolded
// expression still says what the machine does; a folded constant that is off by
// a bit does not (peek-a-bin-8fv).
describe("64-bit constant folding", () => {
  it("shifts a 64-bit constant at 64 bits (JS gives 0 here)", () => {
    // 0x100000000 >>> 4 === 0 in JavaScript.
    expect(foldExprVia(irBinary(">>>", irConst(0x100000000, 8), irConst(4, 8)))).toEqual(
      irConst(0x10000000, 8),
    );
  });

  it("honours a shift count of 32 or more (JS wraps it to 5 bits)", () => {
    // 1 << 32 === 1 in JavaScript: the count is taken mod 32.
    expect(foldExprVia(irBinary("<<", irConst(1, 8), irConst(32, 8)))).toEqual(
      irConst(0x100000000, 8),
    );
  });

  it("keeps the high half of a 64-bit AND", () => {
    expect(foldExprVia(irBinary("&", irConst(0x100000000, 8), irConst(0x1ffffffff, 8)))).toEqual(
      irConst(0x100000000, 8),
    );
  });

  it("keeps the high half of a 64-bit OR and XOR", () => {
    expect(foldExprVia(irBinary("|", irConst(0x100000000, 8), irConst(1, 8)))).toEqual(
      irConst(0x100000001, 8),
    );
    expect(foldExprVia(irBinary("^", irConst(0x300000000, 8), irConst(0x100000000, 8)))).toEqual(
      irConst(0x200000000, 8),
    );
  });

  it("divides at 64 bits (`|0` on the quotient loses the high half)", () => {
    // (0x400000000 / 2) | 0 === 0 in JavaScript.
    expect(foldExprVia(irBinary("/", irConst(0x400000000, 8), irConst(2, 8)))).toEqual(
      irConst(0x200000000, 8),
    );
  });

  it("compares unsigned at 64 bits (`>>> 0` truncates the comparand)", () => {
    // (0x100000000 >>> 0) < 5 is 0 < 5, i.e. true. At 64 bits it is false.
    expect(foldExprVia(irBinary("u<", irConst(0x100000000, 8), irConst(5, 8)))).toEqual(
      irConst(0, 8),
    );
  });

  it("leaves 32-bit folds exactly as they were", () => {
    // `IRConst.size` is 8 for every immediate in a 64-bit image — the lifter
    // records the mode, not the operand width — so a value that survives the
    // coercion to int32 must keep taking the 32-bit spelling. Otherwise
    // `or esi, 0xffffffff` prints 0xFFFFFFFF where -1 is the register's value.
    expect(foldExprVia(irBinary("|", irConst(0, 8), irConst(0xffffffff, 8)))).toEqual(
      irConst(-1, 8),
    );
    expect(foldExprVia(irBinary("<<", irConst(1, 4), irConst(4, 4)))).toEqual(irConst(0x10, 4));
    expect(foldExprVia(irBinary(">>>", irConst(-1, 4), irConst(28, 4)))).toEqual(irConst(0xf, 4));
  });

  it("declines to fold an operand past 2^53 rather than guessing", () => {
    // `IRConst.value` is a `number`, so a 16-hex-digit immediate arrives
    // already rounded and no evaluator can recover it.
    //
    // The magnitude is spelled `2 ** 63` because this test was first written
    // with `0x7fffffffffffffff` — INT64_MAX — and that literal *is* the bug
    // under test: no double holds it, so it silently becomes 0x8000000000000000,
    // one greater and the wrong side of the signed boundary. Biome's
    // `noPrecisionLoss` caught it. Any 64-bit constant written as a plain
    // numeric literal is suspect for exactly this reason, which is why the
    // folder refuses these rather than evaluating them.
    const huge = irConst(2 ** 63, 8);
    expect(foldExprVia(irBinary("&", huge, irConst(0xff, 8))).kind).toBe("binary");
    expect(foldExprVia(irBinary(">>>", huge, irConst(4, 8))).kind).toBe("binary");
  });

  it("declines to fold a result past 2^53 rather than emitting a rounded one", () => {
    // 2^41 * 4097 = 2^53 + 2^41, outside the range a `number` can be trusted in.
    expect(foldExprVia(irBinary("*", irConst(0x20000000000, 8), irConst(0x1001, 8))).kind).toBe(
      "binary",
    );
  });

  // `+`, `-` and `*` must NOT wrap to int32, and this is the guard for that
  // direction rather than a statement about which reading is meant.
  //
  // The bit pattern 0x80000000 is right either way: for a 64-bit `add` it is the
  // value RAX holds, and for a 32-bit one it is the wrapped result under its
  // unsigned reading. What differs is only how the stored `number` reads back.
  // So wrapping here — `(l + r) | 0`, `Math.imul`, matching what the bitwise
  // arms of the same switch do by JavaScript's own semantics — would turn a
  // correct 64-bit constant into a negative one, and it CANNOT be decided at
  // this site: both operands are `IRConst`, `knownWidth` returns null for a
  // constant deliberately, and `IRConst.size` is the CPU mode rather than the
  // operand width (see `needs64`). `peek-a-bin-ivj5` has the census.
  //
  // Without this, the only test that failed on the wrapping experiment was the
  // 2^53 one above — which catches it incidentally, for a different stated
  // reason — while `npm run corpus` stayed byte-identical on all four binaries.
  it("does not wrap an arithmetic fold to int32", () => {
    expect(foldExprVia(irBinary("+", irConst(0x7fffffff, 8), irConst(1, 8)))).toEqual(
      irConst(0x80000000, 8),
    );
    expect(foldExprVia(irBinary("-", irConst(-0x80000000, 8), irConst(1, 8)))).toEqual(
      irConst(-0x80000001, 8),
    );
    expect(foldExprVia(irBinary("*", irConst(0x10000, 8), irConst(0x10000, 8)))).toEqual(
      irConst(0x100000000, 8),
    );
  });

  it("complements a 64-bit constant at 64 bits (JS `~` gives -1 here)", () => {
    expect(foldExprVia(irUnary("~", irConst(0x100000000, 8)))).toEqual(irConst(-0x100000001, 8));
    // ~x for any x that survives ToInt32 is the same number at 32 and 64 bits,
    // so these must not move.
    expect(foldExprVia(irUnary("~", irConst(5, 8)))).toEqual(irConst(-6, 8));
    expect(foldExprVia(irUnary("~", irConst(0, 4)))).toEqual(irConst(-1, 4));
  });

  it("declines `~` of an operand past 2^53", () => {
    expect(foldExprVia(irUnary("~", irConst(2 ** 63, 8))).kind).toBe("unary");
  });
});

// `x & 0xFFFFFFFF -> x` is a real truncation of the high half when the left
// operand is 64 bits wide, and dropping it emits a value keeping bits the
// instruction cleared. `x | 0xFFFFFFFF -> 0xFFFFFFFF` is the same mistake
// (peek-a-bin-6hw). The `-1` spellings of both are all-ones at *every* width
// and stay unconditional.
describe("width-sensitive identity elimination", () => {
  it("keeps `x & 0xFFFFFFFF` when x is 64 bits wide", () => {
    expect(foldExprVia(irBinary("&", irReg("rax"), irConst(0xffffffff, 8))).kind).toBe("binary");
    expect(foldExprVia(irBinary("&", irDeref(irReg("rcx"), 8), irConst(0xffffffff, 8))).kind).toBe(
      "binary",
    );
    // A cast spells its own width, and so does a binary whose operands do.
    expect(
      foldExprVia(
        irBinary("&", irBinary("+", irReg("rcx"), irConst(0x10, 8)), irConst(0xffffffff, 8)),
      ).kind,
    ).toBe("binary");
  });

  it("still drops `x & 0xFFFFFFFF` when x is 32 bits wide", () => {
    expect(foldExprVia(irBinary("&", irReg("eax"), irConst(0xffffffff, 4)))).toEqual(irReg("eax"));
    // The immediate's own size is the image's mode and says nothing about x.
    expect(foldExprVia(irBinary("&", irReg("eax"), irConst(0xffffffff, 8)))).toEqual(irReg("eax"));
    expect(foldExprVia(irBinary("&", irDeref(irReg("rcx"), 4), irConst(0xffffffff, 8))).kind).toBe(
      "deref",
    );
  });

  it("still drops `x & -1` at every width", () => {
    expect(foldExprVia(irBinary("&", irReg("rax"), irConst(-1, 8)))).toEqual(irReg("rax"));
    expect(foldExprVia(irBinary("&", irReg("eax"), irConst(-1, 4)))).toEqual(irReg("eax"));
  });

  it("keeps `x | 0xFFFFFFFF` when x is 64 bits wide", () => {
    expect(foldExprVia(irBinary("|", irReg("rax"), irConst(0xffffffff, 8))).kind).toBe("binary");
  });

  it("still collapses `x | 0xFFFFFFFF` at 32 bits and `x | -1` at every width", () => {
    expect(foldExprVia(irBinary("|", irReg("eax"), irConst(0xffffffff, 4)))).toEqual(
      irConst(0xffffffff, 4),
    );
    expect(foldExprVia(irBinary("|", irReg("rax"), irConst(-1, 8)))).toEqual(irConst(-1, 8));
  });

  it("leaves the width-independent identities alone", () => {
    expect(foldExprVia(irBinary("*", irReg("rax"), irConst(0, 8)))).toEqual(irConst(0, 8));
    expect(foldExprVia(irBinary("|", irReg("rax"), irConst(0, 8)))).toEqual(irReg("rax"));
    expect(foldExprVia(irBinary("&", irReg("rax"), irConst(0, 8)))).toEqual(irConst(0, 8));
    expect(foldExprVia(irBinary("+", irReg("rax"), irConst(0, 8)))).toEqual(irReg("rax"));
    expect(foldExprVia(irBinary("^", irReg("rax"), irConst(0, 8)))).toEqual(irReg("rax"));
  });
});

/**
 * A REGISTER DEFINITION NOTHING READS.
 *
 * `ssaopt.ts`'s dead-code elimination already takes every versioned definition
 * with zero uses, so what reaches this rule is what `destroySSA` creates after
 * it has run — `swapDefWithCopy`'s `esi_1 = X; esi = esi_1;` split and the
 * copies phi lowering writes into predecessors — plus anything in a region SSA
 * never versioned at all. The deletion is the one sound half of copy
 * coalescing: it removes a copy nobody reads and renames nothing
 * (peek-a-bin-5b6q.2).
 */
describe("dead register definitions", () => {
  const eax = irReg("eax");
  const ecx = irReg("ecx");

  it("deletes a definition redefined with no read in between", () => {
    // No `liveOut` argument: a redefinition inside the block ends the value's
    // live range, so what any successor does is irrelevant.
    const out = foldBlock([assign(eax, ecx), assign(eax, irConst(5))]);
    expect(out).toHaveLength(1);
    expect(out[0]).toMatchObject({ kind: "assign", src: { kind: "const", value: 5 } });
  });

  it("deletes a definition no successor reads", () => {
    const out = foldBlock([assign(eax, ecx), { kind: "return" }], new Set(["rbx"]));
    expect(out).toEqual([{ kind: "return" }]);
  });

  it("keeps a definition a successor reads", () => {
    const stmts = [assign(eax, ecx), { kind: "return" } as IRStmt];
    expect(foldBlock(stmts, new Set(["rax"]))).toHaveLength(2);
  });

  it("keeps a definition read later in the block", () => {
    // Two readers, so the single-use inlining does not take it either and the
    // assignment has to be here for the deletion rule to be the thing tested.
    const stmts: IRStmt[] = [
      assign(eax, ecx),
      { kind: "store", address: irReg("edx"), value: eax, size: 4 },
      { kind: "store", address: irReg("ebx"), value: eax, size: 4 },
    ];
    expect(foldBlock(stmts, new Set())).toHaveLength(3);
  });

  it("counts a read in the redefining statement itself", () => {
    // `eax = eax + 1` reads the old value before writing the new one, so the
    // first definition is live and the two merge rather than one being dropped.
    // Deleted instead, the survivor would read an EAX nothing assigns.
    const stmts = [
      assign(eax, ecx),
      assign(eax, irBinary("+", eax, irConst(1))),
      { kind: "return", value: eax } as IRStmt,
    ];
    // Everything folds into the return here; what the rule decides is WHOSE
    // value reaches it. Deleted instead, the `+ 1` would be over an EAX nothing
    // in the block assigns.
    const out = foldBlock(stmts, new Set());
    expect(out).toEqual([{ kind: "return", value: irBinary("+", ecx, irConst(1)) }]);
  });

  it("counts a guard's read", () => {
    // The branches are extracted after this stage, so a condition is an
    // ordinary statement here — and the one read this pass would otherwise be
    // blind to.
    const stmts: IRStmt[] = [
      assign(eax, ecx),
      { kind: "branch", condition: eax, target: 0x401000, jcc: "jne" },
    ];
    expect(foldBlock(stmts, new Set())).toHaveLength(2);
  });

  it("treats a call's result register as a redefinition", () => {
    const stmts: IRStmt[] = [
      assign(eax, ecx),
      { kind: "call_stmt", call: { kind: "call", target: "f", args: [] }, resultDest: eax },
    ];
    expect(foldBlock(stmts, new Set())).toHaveLength(1);
  });

  it("keeps a definition across a raw", () => {
    // An unlifted instruction reads nothing this IR counts and writes nothing
    // it counts either, so neither half of the question can be answered across
    // one. The inlining pass tolerates a raw because it only relocates a value
    // it can see; a deletion asserts that nobody reads it.
    const stmts: IRStmt[] = [
      assign(eax, ecx),
      { kind: "raw", text: "fldz" },
      assign(eax, irConst(5)),
    ];
    expect(foldBlock(stmts, new Set(["rax"]))).toHaveLength(3);
  });

  it("keeps a definition of the stack pointer", () => {
    // `push`, `pop` and a `call`'s return address are not lifted at all, so a
    // write to RSP that looks dead here is the prologue normalisation's
    // business, not this pass's.
    const rsp = irReg("rsp");
    const stmts = [assign(rsp, irBinary("-", rsp, irConst(0x28))), assign(rsp, irReg("rbp"))];
    expect(foldBlock(stmts, new Set())).toHaveLength(2);
  });

  it("keeps a definition whose source has side effects", () => {
    const call: IRExpr = { kind: "call", target: "GetLastError", args: [] };
    const stmts = [assign(eax, call), assign(eax, irConst(0))];
    expect(foldBlock(stmts, new Set(["rax"]))).toHaveLength(2);
  });

  it("deletes nothing past the end of the block without a liveOut set", () => {
    // Absent is "no CFG was supplied", not "nothing escapes" — the same reading
    // the inlining pass's escape test takes of the same argument.
    expect(foldBlock([assign(eax, ecx)])).toHaveLength(1);
  });

  it("cascades: a copy deleted can make its own source dead", () => {
    const stmts = [assign(eax, irBinary("+", ecx, irConst(1))), assign(irReg("edx"), eax)];
    expect(foldBlock(stmts, new Set())).toEqual([]);
  });
});

describe("hasSideEffects", () => {
  const call: IRExpr = { kind: "call", target: "GetLastError", args: [] };

  // fold.ts and ssaopt.ts each had their own copy and both omitted `cast`.
  // ssaopt's dead-code elimination asks this before deleting an unused
  // definition, so `rbx = (int64_t)GetLastError()` with rbx unused answered
  // "pure" and the call went with the statement. There is one copy now; this
  // pins the classification that made the drift matter.
  it("sees through a cast to the call inside it", () => {
    expect(hasSideEffects({ kind: "cast", type: "int64_t", operand: call })).toBe(true);
  });

  it("finds a call at any depth", () => {
    expect(hasSideEffects(irBinary("&", irReg("eax"), call))).toBe(true);
    expect(hasSideEffects({ kind: "deref", address: call, size: 4 })).toBe(true);
    expect(hasSideEffects(irUnary("!", { kind: "cast", type: "int32_t", operand: call }))).toBe(
      true,
    );
  });

  it("leaves call-free expressions alone", () => {
    expect(hasSideEffects(irBinary("+", irReg("eax"), irConst(4)))).toBe(false);
    expect(hasSideEffects({ kind: "cast", type: "int64_t", operand: irReg("eax") })).toBe(false);
    expect(hasSideEffects({ kind: "deref", address: irReg("rcx"), size: 8 })).toBe(false);
  });
});
