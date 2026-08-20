import { describe, expect, it } from "vitest";
import type { BinaryOp, IRExpr } from "../ir";
import { irBinary, irConst, irReg, irUnary } from "../ir";
import { RegState } from "../regstate";

describe("RegState definitions", () => {
  it("stores and retrieves a definition case-insensitively", () => {
    const st = new RegState();
    st.set("RAX", irConst(7));
    expect(st.get("rax")).toEqual(irConst(7));
    expect(st.get("RaX")).toEqual(irConst(7));
  });

  it("lets the last writer win", () => {
    const st = new RegState();
    st.set("rax", irConst(1));
    st.set("rax", irConst(2));
    expect(st.get("rax")).toEqual(irConst(2));
  });

  it("returns undefined for an undefined register", () => {
    expect(new RegState().get("rbx")).toBeUndefined();
  });

  it("falls back to a bare register expression in getOrReg", () => {
    const st = new RegState();
    expect(st.getOrReg("rbx", 8)).toEqual(irReg("rbx", 8));
    st.set("rbx", irConst(5));
    expect(st.getOrReg("rbx", 8)).toEqual(irConst(5));
  });

  it("keeps sub-registers as distinct slots", () => {
    // The lifter keys defs by the literal operand text, so eax and rax differ.
    const st = new RegState();
    st.set("eax", irConst(1));
    expect(st.get("rax")).toBeUndefined();
  });
});

describe("RegState.wroteAnyAlias", () => {
  // The width-exact map above is right for *values*: `mov cl, 2` says nothing
  // about the upper 56 bits of RCX, so folding it into an `rcx` key would
  // record a byte as if it were a quadword. But "did this block touch RCX at
  // all" is a different, width-blind question — it is what arity is made of —
  // and it gets this method rather than a width-blind map (peek-a-bin-qb2x).
  it("sees a write through any alias of the register", () => {
    for (const alias of ["rcx", "ecx", "cx", "cl"]) {
      const st = new RegState();
      st.set(alias, irConst(1));
      expect(st.wroteAnyAlias("rcx")).toBe(true);
    }
  });

  it("sees the extended registers' aliases too", () => {
    const st = new RegState();
    st.set("r8d", irConst(0, 4));
    expect(st.wroteAnyAlias("r8")).toBe(true);
    expect(st.wroteAnyAlias("r9")).toBe(false);
  });

  it("answers about the register asked for and no other", () => {
    const st = new RegState();
    st.set("edx", irConst(1));
    expect(st.wroteAnyAlias("rdx")).toBe(true);
    expect(st.wroteAnyAlias("rcx")).toBe(false);
  });

  it("does not report the value, only that there was one", () => {
    // Deliberate: the caller wants arity. Handing back the recorded expression
    // is the re-expansion defect `parseOperand`'s docstring warns about.
    const st = new RegState();
    st.set("ecx", irConst(1));
    expect(st.wroteAnyAlias("rcx")).toBe(true);
  });

  it("is false for a name that is not a register", () => {
    // `regSize()` would say 4 for this and make the test meaningless; the guard
    // is `isKnownRegister`.
    const st = new RegState();
    st.set("not_a_register", irConst(1));
    expect(st.wroteAnyAlias("not_a_register")).toBe(false);
  });

  it("is false on an empty state", () => {
    expect(new RegState().wroteAnyAlias("rcx")).toBe(false);
  });
});

describe("RegState.noteRead / readSinceWrite", () => {
  // The width-blind pair to `wroteAnyAlias`, and for the same reason: `and
  // BYTE PTR [rax+rcx*1+8], 0xfe` reads RCX whatever width the write that
  // produced it used. `collectArgs64` is the only caller (peek-a-bin-7r1l).
  it("reports a read through any alias of the register", () => {
    for (const alias of ["rcx", "ecx", "cx", "cl"]) {
      const st = new RegState();
      st.noteRead(alias);
      expect(st.readSinceWrite("rcx")).toBe(true);
    }
  });

  it("is false until something reads the register", () => {
    const st = new RegState();
    st.set("rcx", irConst(1));
    expect(st.readSinceWrite("rcx")).toBe(false);
  });

  // A write starts a new value, and nothing has read *that* one yet. This is
  // what makes a read-modify-write (`and edx, 0x1f`) clear its own mark: the
  // lifter notes the reads before dispatching the instruction that writes.
  it("clears the mark when the register is written again", () => {
    const st = new RegState();
    st.noteRead("ecx");
    expect(st.readSinceWrite("rcx")).toBe(true);
    st.set("rcx", irConst(1));
    expect(st.readSinceWrite("rcx")).toBe(false);
  });

  // The defs are deleted, so their marks describe nothing; leaving them would
  // let a read BEFORE the call suppress an argument set up after it.
  it("forgets the caller-saved marks when a call invalidates them", () => {
    const st = new RegState();
    st.noteRead("rcx");
    st.noteRead("rbx");
    st.invalidateCallerSaved();
    expect(st.readSinceWrite("rcx")).toBe(false);
    expect(st.readSinceWrite("rbx")).toBe(true);
  });

  it("survives a clone, like every other part of the state", () => {
    const st = new RegState();
    st.noteRead("rdx");
    expect(st.clone().readSinceWrite("rdx")).toBe(true);
  });

  it("is false for a name that is not a register", () => {
    const st = new RegState();
    st.noteRead("not_a_register");
    expect(st.readSinceWrite("not_a_register")).toBe(false);
  });
});

describe("RegState.getCondition — after cmp", () => {
  function afterCmp(jcc: string, left: IRExpr = irReg("eax", 4), right: IRExpr = irConst(5)) {
    const st = new RegState();
    st.setFlags("cmp", left, right);
    return st.getCondition(jcc);
  }

  it("maps signed comparisons to signed operators", () => {
    expect(afterCmp("jl")).toEqual(irBinary("<", irReg("eax", 4), irConst(5)));
    expect(afterCmp("jle")).toEqual(irBinary("<=", irReg("eax", 4), irConst(5)));
    expect(afterCmp("jg")).toEqual(irBinary(">", irReg("eax", 4), irConst(5)));
    expect(afterCmp("jge")).toEqual(irBinary(">=", irReg("eax", 4), irConst(5)));
  });

  it("maps unsigned comparisons to unsigned operators", () => {
    // ja/jb are the unsigned forms — emitting signed < here would be a real defect.
    expect(afterCmp("ja").kind).toBe("binary");
    expect((afterCmp("ja") as { op: string }).op).toBe("u>");
    expect((afterCmp("jae") as { op: string }).op).toBe("u>=");
    expect((afterCmp("jb") as { op: string }).op).toBe("u<");
    expect((afterCmp("jbe") as { op: string }).op).toBe("u<=");
  });

  it("maps equality forms", () => {
    expect((afterCmp("je") as { op: string }).op).toBe("==");
    expect((afterCmp("jz") as { op: string }).op).toBe("==");
    expect((afterCmp("jne") as { op: string }).op).toBe("!=");
    expect((afterCmp("jnz") as { op: string }).op).toBe("!=");
  });

  it("maps the negated aliases to the same operators as their primaries", () => {
    const pairs: [string, string][] = [
      ["jnle", "jg"],
      ["jnl", "jge"],
      ["jnge", "jl"],
      ["jng", "jle"],
      ["jnbe", "ja"],
      ["jnb", "jae"],
      ["jnc", "jae"],
      ["jnae", "jb"],
      ["jc", "jb"],
      ["jna", "jbe"],
    ];
    for (const [alias, primary] of pairs) {
      expect(afterCmp(alias), alias).toEqual(afterCmp(primary));
    }
  });

  it("expresses js/jns as a sign test on the difference", () => {
    expect(afterCmp("js")).toEqual(
      irBinary("<", irBinary("-", irReg("eax", 4), irConst(5)), irConst(0)),
    );
    expect(afterCmp("jns")).toEqual(
      irBinary(">=", irBinary("-", irReg("eax", 4), irConst(5)), irConst(0)),
    );
  });

  it("falls back to an unknown expression for an unmapped jcc", () => {
    const cond = afterCmp("jp");
    expect(cond.kind).toBe("unknown");
  });

  it("returns unknown when no flags have been set", () => {
    const cond = new RegState().getCondition("je");
    expect(cond).toEqual({ kind: "unknown", text: "je" });
  });

  it("preserves the compared expressions verbatim", () => {
    const left = irBinary("+", irReg("rbx", 8), irConst(4));
    const cond = afterCmp("je", left, irConst(0));
    expect(cond).toEqual(irBinary("==", left, irConst(0)));
  });
});

describe("RegState.getCondition — after test", () => {
  function afterTest(jcc: string, left: IRExpr, right: IRExpr) {
    const st = new RegState();
    st.setFlags("test", left, right);
    return st.getCondition(jcc);
  }

  it("reduces `test X, X` + je to a zero comparison on X", () => {
    const eax = irReg("eax", 4);
    expect(afterTest("je", eax, irReg("eax", 4))).toEqual(irBinary("==", eax, irConst(0, 4)));
    expect(afterTest("jnz", eax, irReg("eax", 4))).toEqual(irBinary("!=", eax, irConst(0, 4)));
  });

  it("recognises the self-test idiom regardless of register case", () => {
    const cond = afterTest("je", irReg("EAX", 4), irReg("eax", 4));
    expect(cond).toEqual(irBinary("==", irReg("EAX", 4), irConst(0, 4)));
  });

  it("builds a masked comparison for `test X, imm`", () => {
    const cond = afterTest("jne", irReg("eax", 4), irConst(0x10));
    expect(cond).toEqual(
      irBinary("!=", irBinary("&", irReg("eax", 4), irConst(0x10)), irConst(0, 4)),
    );
  });

  it("treats two distinct registers as a mask, not a self-test", () => {
    const cond = afterTest("je", irReg("eax", 4), irReg("ebx", 4));
    expect(cond).toEqual(
      irBinary("==", irBinary("&", irReg("eax", 4), irReg("ebx", 4)), irConst(0, 4)),
    );
  });

  it("treats equal constants as a self-test", () => {
    const cond = afterTest("je", irConst(3), irConst(3));
    expect(cond).toEqual(irBinary("==", irConst(3), irConst(0, 4)));
  });

  it("maps js/jns to a sign test on the masked value", () => {
    const cond = afterTest("js", irReg("eax", 4), irConst(0x80));
    expect(cond).toEqual(
      irBinary("<", irBinary("&", irReg("eax", 4), irConst(0x80)), irConst(0, 4)),
    );
  });

  /**
   * The signed forms, which this suite used to assert were unanswerable.
   *
   * The test that stood here read:
   *
   *     // jle depends on SF/OF, which `test` clears — there is no sound translation.
   *     expect(afterTest("jle", eax, eax)).toEqual({kind:"unknown", text:"jle after test"});
   *
   * and it is wrong about the machine. `test` does **not** clear SF: per the
   * Intel SDM, "the OF and CF flags are set to 0. The SF, ZF, and PF flags are
   * set according to the result." Clearing OF is precisely what makes the signed
   * forms exact, because `jle` is `ZF=1 or SF≠OF`, and with OF pinned to 0 that
   * collapses to `ZF=1 or SF=1` — which is `(a & b) <= 0`.
   *
   * The neighbouring "maps js/jns to a sign test" case refutes the old comment
   * on its own: `js` reads SF and nothing else, so if `test` really cleared SF
   * then `js` would be unanswerable too. The suite had pinned a defect as the
   * rule, which is why nothing failed while 70 guards across the four corpus
   * binaries went unrecovered for want of these six lines (peek-a-bin-92yy) —
   * the same shape as the `collectArgs64` KNOWN BUG assertion in
   * peek-a-bin-qb2x.
   */
  it.each([
    ["jle", "<="],
    ["jng", "<="],
    ["jg", ">"],
    ["jnle", ">"],
    ["jl", "<"],
    ["jnge", "<"],
    ["jge", ">="],
    ["jnl", ">="],
  ] as const)("answers %s after test, because test clears OF", (jcc, op) => {
    const eax = irReg("eax", 4);
    expect(afterTest(jcc, eax, irReg("eax", 4))).toEqual(irBinary(op, eax, irConst(0, 4)));
  });

  it.each([
    ["jbe", "=="],
    ["jna", "=="],
    ["ja", "!="],
    ["jnbe", "!="],
  ] as const)("answers %s after test, because test clears CF too", (jcc, op) => {
    // CF=0 makes `jbe` (CF or ZF) exactly ZF, i.e. the same test `je` makes,
    // and `ja` (not CF and not ZF) exactly `jne`. Compilers do emit these:
    // an unsigned comparison against zero reached by a mask is natural.
    const eax = irReg("eax", 4);
    expect(afterTest(jcc, eax, irReg("eax", 4))).toEqual(irBinary(op, eax, irConst(0, 4)));
  });

  it.each(["jb", "jnae", "jae", "jnb", "jo", "jno", "jp", "jnp"])(
    "still returns unknown for %s, which reads no flag test leaves meaningful",
    (jcc) => {
      // `jb`/`jae` read only CF and `jo`/`jno` only OF, both pinned to 0 by
      // `test` — so each is a constant, and the shape is real rather than
      // theoretical: 12 sites in the corpus, all `jae`, in MSVC's 64-bit negate
      // idiom (t32 0x404df1 `test eax, eax` / `jae`, reached after a `jg`/`jl`
      // pair, so the `jae` is always taken). The flag owner there is correctly
      // identified, so this is NOT a misattribution signal.
      //
      // We decline anyway because the exact answer is `if (1)`, and that is a
      // control-flow claim rather than a value claim: `structureCFG` would be
      // entitled to treat the arm as unconditional, no gate here models a
      // constant guard, and polarity has no operator to check against the jcc.
      // `jp`/`jnp` read PF, a real function of the result with no cheap
      // spelling. Unknown keeps all of it an admitted gap (peek-a-bin-x72e).
      const cond = afterTest(jcc, irReg("eax", 4), irReg("eax", 4));
      expect(cond).toEqual({ kind: "unknown", text: `${jcc} after test` });
    },
  );
});

describe("RegState.negate", () => {
  const a = irReg("eax", 4);
  const b = irConst(1);

  it("flips each comparison operator to its complement", () => {
    const flips: [BinaryOp, BinaryOp][] = [
      ["==", "!="],
      ["!=", "=="],
      ["<", ">="],
      [">=", "<"],
      [">", "<="],
      ["<=", ">"],
      ["u<", "u>="],
      ["u>=", "u<"],
      ["u>", "u<="],
      ["u<=", "u>"],
    ];
    for (const [op, expected] of flips) {
      const neg = RegState.negate(irBinary(op, a, b));
      expect((neg as { op: string }).op, op).toBe(expected);
    }
  });

  it("applies De Morgan to &&", () => {
    const cond = irBinary("&&", irBinary("==", a, b), irBinary("<", a, b));
    expect(RegState.negate(cond)).toEqual(
      irBinary("||", irBinary("!=", a, b), irBinary(">=", a, b)),
    );
  });

  it("applies De Morgan to ||", () => {
    const cond = irBinary("||", irBinary("==", a, b), irBinary("<", a, b));
    expect(RegState.negate(cond)).toEqual(
      irBinary("&&", irBinary("!=", a, b), irBinary(">=", a, b)),
    );
  });

  it("is an involution on comparisons", () => {
    const cond = irBinary("u<=", a, b);
    expect(RegState.negate(RegState.negate(cond))).toEqual(cond);
  });

  it("wraps a non-comparison in a logical not", () => {
    expect(RegState.negate(a)).toEqual(irUnary("!", a));
    expect(RegState.negate({ kind: "unknown", text: "jp" })).toEqual(
      irUnary("!", { kind: "unknown", text: "jp" }),
    );
  });

  it("wraps an arithmetic binary rather than flipping it", () => {
    const sum = irBinary("+", a, b);
    expect(RegState.negate(sum)).toEqual(irUnary("!", sum));
  });
});

describe("RegState.invalidateCallerSaved", () => {
  it("drops the volatile x64 registers", () => {
    const st = new RegState();
    for (const r of ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]) st.set(r, irConst(1));
    st.invalidateCallerSaved();
    for (const r of ["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]) {
      expect(st.get(r), r).toBeUndefined();
    }
  });

  it("keeps the non-volatile registers", () => {
    const st = new RegState();
    for (const r of ["rbx", "rbp", "rsi", "rdi", "rsp", "r12", "r13", "r14", "r15"]) {
      st.set(r, irConst(1));
    }
    st.invalidateCallerSaved();
    for (const r of ["rbx", "rbp", "rsi", "rdi", "rsp", "r12", "r13", "r14", "r15"]) {
      expect(st.get(r), r).toEqual(irConst(1));
    }
  });

  it("clears the flag state so a following jcc is unknown", () => {
    const st = new RegState();
    st.setFlags("cmp", irReg("eax", 4), irConst(0));
    st.invalidateCallerSaved();
    expect(st.getCondition("je")).toEqual({ kind: "unknown", text: "je" });
  });

  // The lifter stores defs under the literal operand name ('eax', 'ecx', 'r8d'),
  // so the clobber check has to run through the canonical parent register.
  it("drops 32-bit sub-registers of the volatile registers", () => {
    const st = new RegState();
    st.set("ecx", irConst(0x1234));
    st.set("eax", irConst(1));
    st.set("r8d", irConst(2));
    st.invalidateCallerSaved();
    expect(st.get("ecx")).toBeUndefined();
    expect(st.get("eax")).toBeUndefined();
    expect(st.get("r8d")).toBeUndefined();
  });

  it("drops 16-bit and 8-bit sub-registers of the volatile registers", () => {
    const st = new RegState();
    for (const r of ["ax", "al", "ah", "cx", "cl", "dx", "dl", "r9w", "r11b"]) {
      st.set(r, irConst(1));
    }
    st.invalidateCallerSaved();
    for (const r of ["ax", "al", "ah", "cx", "cl", "dx", "dl", "r9w", "r11b"]) {
      expect(st.get(r), r).toBeUndefined();
    }
  });

  it("keeps sub-registers of the non-volatile registers", () => {
    const st = new RegState();
    for (const r of ["ebx", "esi", "edi", "bp", "r12d", "r15w"]) st.set(r, irConst(1));
    st.invalidateCallerSaved();
    for (const r of ["ebx", "esi", "edi", "bp", "r12d", "r15w"]) {
      expect(st.get(r), r).toEqual(irConst(1));
    }
  });

  it("invalidates a 32-bit-mode constant so it cannot fold past the call", () => {
    // mov ecx, 0x1234 / call f / mov edx, ecx — ECX must not still be 0x1234.
    const st = new RegState();
    st.set("ecx", irConst(0x1234));
    st.invalidateCallerSaved();
    expect(st.getOrReg("ecx", 4)).toEqual(irReg("ecx", 4));
  });

  it("leaves the return-value def written after the call in place", () => {
    // The lifter invalidates first, then stores the call result in eax/rax.
    const st = new RegState();
    st.set("eax", irConst(0));
    st.invalidateCallerSaved();
    st.set("eax", irConst(42));
    expect(st.get("eax")).toEqual(irConst(42));
  });
});

describe("RegState.clone", () => {
  it("copies definitions and flag state", () => {
    const st = new RegState();
    st.set("rax", irConst(9));
    st.setFlags("cmp", irReg("rax", 8), irConst(0));
    const copy = st.clone();
    expect(copy.get("rax")).toEqual(irConst(9));
    expect(copy.getCondition("je")).toEqual(irBinary("==", irReg("rax", 8), irConst(0)));
  });

  it("does not share the definition map with the original", () => {
    const st = new RegState();
    st.set("rax", irConst(1));
    const copy = st.clone();
    copy.set("rax", irConst(2));
    copy.set("rbx", irConst(3));
    expect(st.get("rax")).toEqual(irConst(1));
    expect(st.get("rbx")).toBeUndefined();
  });

  it("does not share flag state with the original", () => {
    const st = new RegState();
    st.setFlags("cmp", irReg("rax", 8), irConst(0));
    const copy = st.clone();
    copy.invalidateCallerSaved();
    expect(st.getCondition("je").kind).toBe("binary");
  });
});
