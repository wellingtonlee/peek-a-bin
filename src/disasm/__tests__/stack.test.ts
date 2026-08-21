import { describe, expect, it } from "vitest";
import { analyzeStackFrame, stackVarKey } from "../stack";
import type { DisasmFunction, Instruction } from "../types";

// ── Helpers ──

function insn(address: number, mnemonic: string, opStr: string): Instruction {
  return { address, bytes: new Uint8Array(), mnemonic, opStr, size: 4 };
}

function func(size: number): DisasmFunction {
  return { name: "sub_1000", address: 0x1000, size };
}

/** Build instructions at consecutive addresses starting at the function entry. */
function body(...ops: [string, string][]): Instruction[] {
  return ops.map(([mn, op], i) => insn(0x1000 + i * 4, mn, op));
}

/** The canonical frame-pointer prologue, which is what makes `[fp + N]` an argument slot. */
const PROLOGUE_64: [string, string][] = [
  ["push", "rbp"],
  ["mov", "rbp, rsp"],
];
const PROLOGUE_32: [string, string][] = [
  ["push", "ebp"],
  ["mov", "ebp, esp"],
];

/**
 * Names of the parameter slots, in frame order.
 *
 * A null frame is `[]` rather than a crash, because refusing to record a
 * `[<fp> + N]` as a parameter is now an outcome in its own right: where that was
 * the only slot the function touched, there is no frame left to return.
 */
function argNames(frame: { vars: { name: string }[] } | null): string[] {
  return (frame?.vars ?? []).map((v) => v.name).filter((n) => n.startsWith("arg_"));
}

// ── Tests ──

describe("analyzeStackFrame — slot identity", () => {
  it("keeps [rbp - 0x10] and [rsp + 0x10] as separate variables", () => {
    // Same numeric offset, different base register → two distinct stack slots.
    // Keying the internal map on the bare offset merged them into one entry
    // with a combined size and access count.
    const insns = body(
      ["mov", "dword ptr [rbp - 0x10], eax"],
      ["mov", "dword ptr [rbp - 0x10], ecx"],
      ["mov", "qword ptr [rsp + 0x10], rdx"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame).not.toBeNull();

    const at10 = frame!.vars.filter((v) => v.offset === 0x10);
    expect(at10).toHaveLength(2);

    const bp = at10.find((v) => v.key === stackVarKey("bp", -0x10));
    const sp = at10.find((v) => v.key === stackVarKey("sp", 0x10));
    expect(bp).toBeDefined();
    expect(sp).toBeDefined();

    // Sizes stay independent: the 8-byte rsp access must not widen the
    // 4-byte rbp local.
    expect(bp!.size).toBe(4);
    expect(sp!.size).toBe(8);

    // Access counts stay independent too.
    expect(bp!.accessCount).toBe(2);
    expect(sp!.accessCount).toBe(1);

    // ...and the two slots get distinct names.
    expect(bp!.name).not.toBe(sp!.name);
  });

  it("does not let a [rbp + 0x10] param absorb a [rsp + 0x10] local", () => {
    // The param branch ran first for [rbp + N] and set isParam, so a later
    // [rsp + N] access with the same offset inherited "param" and vanished
    // into arg_0.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "eax, dword ptr [rbp + 0x10]"],
      ["mov", "dword ptr [rsp + 0x10], ecx"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame).not.toBeNull();

    const names = frame!.vars.map((v) => v.name);
    expect(names).toContain("arg_0");
    // The rsp slot is a local, not part of the parameter list.
    const spVar = frame!.vars.find((v) => v.key === stackVarKey("sp", 0x10));
    expect(spVar).toBeDefined();
    expect(spVar!.name).not.toMatch(/^arg_/);
    expect(frame!.vars.filter((v) => v.name.startsWith("arg_"))).toHaveLength(1);
  });

  it("still merges repeated accesses to the same slot", () => {
    const insns = body(
      ["mov", "byte ptr [rbp - 0x8], al"],
      ["mov", "dword ptr [rbp - 0x8], eax"],
      ["mov", "dword ptr [rbp - 0x8], ecx"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    const v = frame!.vars.find((x) => x.key === stackVarKey("bp", -0x8));
    expect(v).toBeDefined();
    expect(v!.accessCount).toBe(3);
    expect(v!.size).toBe(4); // widest access wins
    expect(frame!.vars).toHaveLength(1);
  });

  it("names and orders unambiguous frames exactly as before", () => {
    const insns = body(
      ...PROLOGUE_64,
      ["sub", "rsp, 0x28"],
      ["mov", "dword ptr [rbp - 0x4], eax"],
      ["mov", "dword ptr [rbp - 0x8], ecx"],
      ["mov", "eax, dword ptr [rbp + 0x10]"],
      ["mov", "ecx, dword ptr [rbp + 0x18]"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame!.frameSize).toBe(0x28);
    expect(frame!.vars.map((v) => v.name)).toEqual(["var_4", "var_8", "arg_0", "arg_1"]);
  });

  it("handles 32-bit ebp/esp bases", () => {
    // The prologue is here because this is about bp-vs-sp slot identity: without
    // it `[ebp + 8]` is not a parameter at all (see the frame-pointer
    // verification block), and the third key would simply not exist.
    const insns = body(
      ...PROLOGUE_32,
      ["mov", "dword ptr [ebp - 0xC], eax"],
      ["mov", "dword ptr [esp + 0xC], ecx"],
      ["mov", "eax, dword ptr [ebp + 0x8]"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, false);
    const keys = frame!.vars.map((v) => v.key);
    expect(keys).toContain(stackVarKey("bp", -0xc));
    expect(keys).toContain(stackVarKey("sp", 0xc));
    expect(keys).toContain(stackVarKey("bp", 0x8));
    expect(frame!.vars).toHaveLength(3);
  });
});

// The N in `arg_N` used to be a running counter over the slots the function was
// observed to touch, so it encoded the order the arguments happened to be
// referenced in rather than their position. It is now derived from the offset.
describe("analyzeStackFrame — argument numbering", () => {
  it("numbers a 32-bit argument by its offset, not by the order it was touched", () => {
    // The function never reads its first argument. The counter called this one
    // arg_0; it is [ebp+0xC], the second argument.
    const insns = body(...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0xC]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_1"]);
  });

  it("leaves a gap for an argument the function never touches", () => {
    // Arguments 0 and 2 are read, 1 is not. The counter renumbered argument 2
    // as arg_1, quietly moving it into the untouched argument's position.
    const insns = body(
      ...PROLOGUE_32,
      ["mov", "eax, dword ptr [ebp + 0x8]"],
      ["mov", "ecx, dword ptr [ebp + 0x10]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual([
      "arg_0",
      "arg_2",
    ]);
  });

  it("maps an x64 home slot to the index of the register that owns it", () => {
    // A Win64 caller allocates 32 bytes of shadow space, so [rbp+0x10] through
    // [rbp+0x28] are the home slots of arguments 0-3 — the ones that arrive in
    // RCX/RDX/R8/R9. A spilled argument therefore gets the same index whether
    // it is reached through its register or through its slot. Two slots, not
    // four, so the numbering cannot coincide with a running counter.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "rax, qword ptr [rbp + 0x18]"],
      ["mov", "rcx, qword ptr [rbp + 0x28]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([
      "arg_1",
      "arg_3",
    ]);
  });

  it("numbers the fifth x64 argument past the shadow space", () => {
    // The first argument with no register sits above the four home slots, at
    // [rbp+0x30], and is argument 4. This is where an off-by-shadow-space error
    // would surface: read as the *first* stack argument it would be numbered 0
    // and collide with RCX, linking the fifth argument to the first.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "rax, qword ptr [rbp + 0x10]"],
      ["mov", "rcx, qword ptr [rbp + 0x30]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([
      "arg_0",
      "arg_4",
    ]);
  });

  it("numbers each slot of a multi-slot argument separately", () => {
    // A 32-bit int64 argument occupies [ebp+0x8] and [ebp+0xC], so its high
    // half is numbered arg_1 and a following argument would be arg_2. Pinned
    // because it is a known imprecision, not an accident: the caller side
    // counts the same slots (an int64 is two pushes), so the two indices still
    // agree with each other even though both differ from the source-level
    // argument position.
    const insns = body(
      ...PROLOGUE_32,
      ["mov", "eax, dword ptr [ebp + 0x8]"],
      ["mov", "edx, dword ptr [ebp + 0xC]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual([
      "arg_0",
      "arg_1",
    ]);
  });

  it("names a sub-slot access by offset rather than rounding it into a neighbour", () => {
    // [ebp+0xA] is the third byte of argument 0. It divides into no argument
    // index, so it does not get one.
    const insns = body(...PROLOGUE_32, ["mov", "al, byte ptr [ebp + 0xA]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_0xA"]);
  });
});

// An index can only be read out of the offset if the frame pointer is really a
// frame pointer. In x64 code RBP is more often a callee-saved object pointer,
// and `[rbp + 0x10]` is then a field of that object, not an argument.
/**
 * Capstone prints a displacement as `0x`-prefixed hex only from 0xA up and as a
 * bare digit below it, so operand patterns that insisted on the `0x` saw nothing
 * in the first ten bytes of the frame. On x86 that is argument 0 and the first
 * locals — the most-used slots in the frame, missing from every frame analysed.
 */
describe("analyzeStackFrame — displacements Capstone printed in decimal", () => {
  it("records the argument at [ebp + 8], written without a 0x", () => {
    const insns = body(...PROLOGUE_32, ["push", "dword ptr [ebp + 8]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_0"]);
  });

  it("numbers a decimal and a hex slot on the same scale", () => {
    // [ebp+8] and [ebp+0xC] are arguments 0 and 1 and differ only in spelling.
    const insns = body(
      ...PROLOGUE_32,
      ["mov", "eax, dword ptr [ebp + 8]"],
      ["mov", "edx, dword ptr [ebp + 0xC]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual([
      "arg_0",
      "arg_1",
    ]);
  });

  it("records the locals at [ebp - 4] and [ebp - 8]", () => {
    const insns = body(
      ...PROLOGUE_32,
      ["mov", "dword ptr [ebp - 4], eax"],
      ["mov", "dword ptr [ebp - 8], ecx"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, false)!;
    expect(frame.vars.map((v) => v.name)).toEqual(["var_4", "var_8"]);
    expect(frame.vars.map((v) => v.signedOffset)).toEqual([-4, -8]);
  });

  it("reads a bare digit as decimal, not as hex", () => {
    // The two spellings must not collide: `[rsp + 8]` is byte 8 and
    // `[rsp + 0x8]` is the same slot, but a decimal `[rsp + 10]` — which
    // Capstone never prints — would be byte 10, not byte 16.
    const insns = body(["mov", "rax, qword ptr [rsp + 8]"], ["mov", "rcx, qword ptr [rsp + 0x8]"]);
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true)!;
    expect(frame.vars).toHaveLength(1);
    expect(frame.vars[0].offset).toBe(8);
    expect(frame.vars[0].accessCount).toBe(2);
  });
});

describe("analyzeStackFrame — frame-pointer verification", () => {
  // This asserted ["arg_0x10", "arg_0x18"] until peek-a-bin-ikd: the slots were
  // still recorded as PARAMETERS and only the positional name was withheld. RBP
  // is never written here, so it holds whatever the caller left in it and
  // `[rbp + N]` is not an argument of this function under any reading — the two
  // names were phantom parameters in the emitted signature, and they blocked
  // struct synthesis from seeing the accesses at all.
  it("records no parameter for a function with no frame pointer", () => {
    const insns = body(
      ["sub", "rsp, 0x28"],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
      ["mov", "rcx, qword ptr [rbp + 0x18]"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(argNames(frame)).toEqual([]);
    // Not renamed to a local either: nothing knows what the slot is, so the
    // deref is left exactly as it stands.
    expect(frame!.vars).toEqual([]);
  });

  it("records no parameter when the frame register holds an object pointer", () => {
    // MSVC's `mov rbp, rcx`: RBP is argument 0's object, so `[rbp + 0x18]` is a
    // field of it. This is peek-a-bin-ikd's own example, t64!sub_1400058F4.
    const insns = body(
      ["push", "rbp"],
      ["sub", "rsp, 0x20"],
      ["mov", "rbp, rcx"],
      ["mov", "rax, qword ptr [rbp + 0x18]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([]);
  });

  it("records no parameter for a slot below the argument area of a shifted frame", () => {
    // `lea rbp, [rsp - 0x1A30]` after seven pushes puts the frame register
    // 0x1A68 below the stack pointer on entry, so `[rbp + 0x1A20]` is 0x48
    // bytes BELOW the return address — a local, and in the corpus the GS
    // cookie. t64!sub_14000D8C4.
    const insns = body(
      ["push", "rbp"],
      ["lea", "rbp, [rsp - 0x1A30]"],
      ["mov", "qword ptr [rbp + 0x1A20], rax"],
      ["mov", "rcx, qword ptr [rbp + 0x1A40]"],
    );
    // 0x1A38 is the return address, so the first argument is at 0x1A40.
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([
      "arg_0x1A40",
    ]);
  });

  it("keeps an argument reached over intervening pushes", () => {
    // The displacement, not the push pattern, is what says where the arguments
    // are: three pushes then `mov rbp, rsp` puts the return address at
    // [rbp + 0x18] and argument 0 at [rbp + 0x20]. Both offsets are arguments
    // and must stay parameters — 94 of t64's 147 offset-named slots are this
    // shape, and refusing them wholesale on `framed` would have lost every one.
    const insns = body(
      ["push", "rbp"],
      ["push", "r12"],
      ["push", "r13"],
      ["mov", "rbp, rsp"],
      ["mov", "rax, qword ptr [rbp + 0x40]"],
      ["mov", "rcx, qword ptr [rbp + 0x10]"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    // 0x10 is below the return address at 0x18, so it is not an argument.
    expect(argNames(frame)).toEqual(["arg_0x40"]);
    expect(frame!.framed).toBe(false);
  });

  it("does not number slots of a frame established with lea", () => {
    // `lea rbp, [rsp + 0x20]` shifts every argument offset by 0x20, so the
    // offsets mean something — just not what the standard prologue makes them
    // mean.
    const insns = body(
      ["push", "rbp"],
      ["lea", "rbp, [rsp + 0x20]"],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual(["arg_0x10"]);
  });

  // This asserted ["arg_0x8"] until peek-a-bin-ikd. `push ebx` before
  // `push ebp` leaves EBP at entry-ESP minus two slots, so `[ebp + 8]` is the
  // RETURN ADDRESS and the first argument is at `[ebp + 0xC]`. Naming the return
  // address after an offset was still calling it a parameter.
  it("records no parameter for the return address of a shifted frame", () => {
    const insns = body(
      ["push", "ebx"],
      ...PROLOGUE_32,
      ["mov", "eax, dword ptr [ebp + 0x8]"],
      ["mov", "ecx, dword ptr [ebp + 0xC]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_0xC"]);
  });

  it("sees through hot-patch padding before the prologue", () => {
    // `mov edi, edi` is MSVC's hot-patch pad and is not part of the frame.
    const insns = body(["mov", "edi, edi"], ...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0x8]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_0"]);
  });

  // This asserted ["arg_0x8"] until peek-a-bin-ikd, on the reasoning that the
  // pushed register was not EBP. It is not the register that matters: what makes
  // `[ebp + 8]` argument 0 is that EBP ends up exactly one slot below the stack
  // pointer on entry, which `push esi / mov ebp, esp` achieves as surely as
  // `push ebp / mov ebp, esp` does. `[ebp]` is the saved ESI, `[ebp + 4]` the
  // return address, `[ebp + 8]` argument 0.
  it("numbers an argument whatever register the frame push saved", () => {
    const insns = body(["push", "esi"], ["mov", "ebp, esp"], ["mov", "eax, dword ptr [ebp + 0x8]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_0"]);
  });
});

describe("signed offsets", () => {
  // The Stack Frame panel renders the sign from signedOffset. `offset` is the
  // operand value as written and is always positive, so a frame holding locals
  // below the frame pointer AND parameters above it cannot be rendered from it:
  // a hard-coded minus labelled every parameter negative.
  it("gives locals a negative signed offset and parameters a positive one", () => {
    const frame = analyzeStackFrame(
      func(0x40),
      body(
        ...PROLOGUE_32,
        ["mov", "eax, dword ptr [ebp - 0x10]"],
        ["mov", "ecx, dword ptr [ebp + 0x8]"],
        ["ret", ""],
      ),
      false,
    );

    expect(frame!.vars.find((v) => v.offset === 0x10)?.signedOffset).toBe(-0x10);
    expect(frame!.vars.find((v) => v.offset === 0x8)?.signedOffset).toBe(0x8);
  });

  it("keeps an rsp-relative slot positive", () => {
    const frame = analyzeStackFrame(
      func(0x40),
      body(...PROLOGUE_32, ["mov", "eax, dword ptr [esp + 0x10]"], ["ret", ""]),
      false,
    );
    expect(frame!.vars.find((v) => v.offset === 0x10)?.signedOffset).toBe(0x10);
  });
});

describe("analyzeStackFrame — a frame established by a prologue helper", () => {
  /**
   * MSVC's `__SEH_prolog4`, verbatim from t32.exe 0x404170, and the caller shape
   * from t32.exe 0x401DB3. The helper establishes exactly the geometry the
   * inline prologue does: the caller pushes the frame size and the scope table,
   * the `call` pushes the return address, the helper pushes the handler and the
   * old `fs:[0]`, and `lea ebp, [esp + 0x10]` then lands on the slot holding the
   * caller's saved EBP — `16 + (-5 * 4) === -4`. So `[ebp + 8]` is argument 0.
   */
  const HELPER_ADDR = 0x2000;
  const SEH_PROLOG4: [string, string][] = [
    ["push", "0x4041d0"],
    ["push", "dword ptr fs:[0]"],
    ["mov", "eax, dword ptr [esp + 0x10]"],
    ["mov", "dword ptr [esp + 0x10], ebp"],
    ["lea", "ebp, [esp + 0x10]"],
    ["sub", "esp, eax"],
    ["mov", "dword ptr [ebp - 0x18], esp"],
    ["ret", ""],
  ];

  /** Caller at 0x1000 plus a helper at `HELPER_ADDR`, in one ascending array. */
  function withHelper(
    caller: [string, string][],
    helper: [string, string][] = SEH_PROLOG4,
  ): { func: DisasmFunction; instructions: Instruction[] } {
    const callerInsns = caller.map(([mn, op], i) => insn(0x1000 + i * 4, mn, op));
    const helperInsns = helper.map(([mn, op], i) => insn(HELPER_ADDR + i * 4, mn, op));
    return {
      func: { name: "sub_1000", address: 0x1000, size: caller.length * 4 },
      instructions: [...callerInsns, ...helperInsns],
    };
  }

  /** The real caller shape: `push <framesize> / push <scopetable> / call <helper>`. */
  const HELPER_CALL: [string, string][] = [
    ["push", "0xc"],
    ["push", "0x411050"],
    ["call", `0x${HELPER_ADDR.toString(16)}`],
  ];

  function argsOf(caller: [string, string][], helper?: [string, string][]): string[] {
    const { func: f, instructions } = withHelper(caller, helper);
    return argNames(analyzeStackFrame(f, instructions, false));
  }

  it("numbers the arguments of a function whose frame __SEH_prolog4 established", () => {
    expect(
      argsOf([
        ...HELPER_CALL,
        ["mov", "ebx, dword ptr [ebp + 0x8]"],
        ["mov", "eax, dword ptr [ebp + 0xc]"],
      ]),
    ).toEqual(["arg_0", "arg_1"]);
  });

  it("refuses a helper whose lea lands one slot off the saved frame pointer", () => {
    // The arithmetic IS the rule: `0xc + (-5 * 4) === -8`, not `-4`, so this
    // helper points EBP one slot below the caller's saved EBP and every offset
    // would be numbered one argument too high.
    const offByOne = SEH_PROLOG4.map(
      ([mn, op]) => (mn === "lea" ? [mn, "ebp, [esp + 0xc]"] : [mn, op]) as [string, string],
    );
    expect(argsOf([...HELPER_CALL, ["mov", "ebx, dword ptr [ebp + 0x8]"]], offByOne)).toEqual([]);
  });

  it("refuses a helper that saves the frame pointer with a push", () => {
    // `push ebp / lea ebp, [esp + 4]` after no caller pushes SATISFIES the
    // arithmetic (`4 + (-2 * 4) === -4`), so the arithmetic alone does not
    // refuse it — but the push is a callee-saved save with a `pop ebp` to come,
    // so whatever it computes is undone before the caller sees it.
    expect(
      argsOf(
        [
          ["call", `0x${HELPER_ADDR.toString(16)}`],
          ["mov", "ebx, dword ptr [ebp + 0x8]"],
        ],
        [
          ["push", "ebp"],
          ["lea", "ebp, [esp + 0x4]"],
          ["ret", ""],
        ],
      ),
    ).toEqual([]);
  });

  it("refuses an ordinary call: the caller may only push immediates", () => {
    // `push <reg> / push <reg> / call` is what a two-argument call looks like,
    // and it is not distinctive on its own. Only immediates — the frame size and
    // the scope table — open the search at all.
    expect(
      argsOf([
        ["push", "ebx"],
        ["push", "esi"],
        ["call", `0x${HELPER_ADDR.toString(16)}`],
        ["mov", "ebx, dword ptr [ebp + 0x8]"],
      ]),
    ).toEqual([]);
  });

  it("refuses a helper that writes the frame pointer again before returning", () => {
    const clobbers = SEH_PROLOG4.map(
      ([mn, op]) =>
        (mn === "sub" && op === "esp, eax" ? ["add", "ebp, 0x10"] : [mn, op]) as [string, string],
    );
    expect(argsOf([...HELPER_CALL, ["mov", "ebx, dword ptr [ebp + 0x8]"]], clobbers)).toEqual([]);
  });

  it("refuses a helper whose return is never reached", () => {
    // A helper whose `ret` was not seen has not been shown to preserve the
    // value it computed, so the frame is not claimed.
    const noRet = SEH_PROLOG4.filter(([mn]) => mn !== "ret");
    expect(argsOf([...HELPER_CALL, ["mov", "ebx, dword ptr [ebp + 0x8]"]], noRet)).toEqual([]);
  });

  it("refuses a call whose target is not in the instruction array", () => {
    const { func: f, instructions } = withHelper([
      ["push", "0xc"],
      ["push", "0x411050"],
      ["call", "0x9000"],
      ["mov", "ebx, dword ptr [ebp + 0x8]"],
    ]);
    expect(argNames(analyzeStackFrame(f, instructions, false))).toEqual([]);
  });

  it("applies the same arithmetic on x64, where the slot is 8 bytes", () => {
    // No x64 binary in the corpus uses a prologue helper — Windows x64 SEH is
    // table-driven — so the rule's architecture-independence is pinned here
    // rather than measured. One caller push, the return address and one helper
    // push put RSP 3 slots below the caller's entry, so the frame is the
    // caller's precisely at `0x10 + (-3 * 8) === -8`.
    const callerInsns: [string, string][] = [
      ["push", "0x20"],
      ["call", `0x${HELPER_ADDR.toString(16)}`],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
    ];
    const helper: [string, string][] = [
      ["push", "0x4041d0"],
      ["lea", "rbp, [rsp + 0x10]"],
      ["ret", ""],
    ];
    const { func: f, instructions } = withHelper(callerInsns, helper);
    expect(argNames(analyzeStackFrame(f, instructions, true))).toEqual(["arg_0"]);
  });
});
