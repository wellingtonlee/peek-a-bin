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

  it("does not let a [rbp + 0x30] param absorb a [rsp + 0x30] local", () => {
    // The param branch ran first for [rbp + N] and set isParam, so a later
    // [rsp + N] access with the same offset inherited "param" and vanished
    // into arg_4.
    //
    // The offset is index 4 — above the home space — because a home slot this
    // function never spills into is not a parameter at all (peek-a-bin-g186),
    // and the subject here is that two slots at one operand offset stay apart.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "eax, dword ptr [rbp + 0x30]"],
      ["mov", "dword ptr [rsp + 0x30], ecx"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame).not.toBeNull();

    const names = frame!.vars.map((v) => v.name);
    expect(names).toContain("arg_4");
    // The rsp slot is a local, not part of the parameter list.
    const spVar = frame!.vars.find((v) => v.key === stackVarKey("sp", 0x30));
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
    // The two spills are what make the home slots argument 0 and argument 1 —
    // an x64 caller never writes the home space, so without them the slots are
    // named after their offsets and this would be testing something else
    // (peek-a-bin-sx57). MSVC emits them for exactly this reason: a function
    // that reads a register argument out of memory has to put it there.
    const insns = body(
      ...PROLOGUE_64,
      ["sub", "rsp, 0x28"],
      ["mov", "qword ptr [rbp + 0x10], rcx"],
      ["mov", "qword ptr [rbp + 0x18], rdx"],
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
    //
    // The spills are the fixture's own premise and used to be missing from it:
    // the comment said "a spilled argument" while the instructions spilled
    // nothing, so the test passed on a rule that named any home slot after its
    // index whether or not the callee had filled it (peek-a-bin-sx57).
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "qword ptr [rbp + 0x18], rdx"],
      ["mov", "qword ptr [rbp + 0x28], r9"],
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
    //
    // [rbp+0x30] needs no spill — it is in the caller's own argument area, the
    // caller put it there, and that is the whole difference from the home space
    // below it. The RCX spill is what earns argument 0 its name.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "qword ptr [rbp + 0x10], rcx"],
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

describe("analyzeStackFrame — the x64 home space", () => {
  // The Microsoft x64 ABI has the CALLER reserve four slots for the arguments
  // that arrive in RCX/RDX/R8/R9 and hands them to the callee as scratch. So
  // the displacement says a home slot's argument index exactly, and says
  // nothing about whether the slot holds that argument: only the callee
  // spilling the register there does. Naming one `arg_0` regardless states
  // something false about the function's interface and, worse, hands
  // `paramIndexByBase` a provenance claim that DISPLACES the argument
  // register's own — so a saved register gets linked to the callers' argument.
  //
  // Measured over the corpus at f169c00: of the 22 home slots the x64 binaries
  // access through a recovered frame pointer, 16 are a saved register, a byte
  // local or an out-param buffer and 6 are a real spill (peek-a-bin-sx57,
  // peek-a-bin-g186).
  //
  // So an unfilled home slot is **not recorded as a parameter at all** — the
  // offset name it used to get still put it in the emitted signature, and
  // `arg_0x30 = rbx` is a declared parameter overwritten by a callee-saved
  // register (peek-a-bin-g186). It is not recorded as a local either: the
  // caller owns the storage, and `promote.ts` reads every `[<fp> + N]` as a
  // parameter from the offset alone, so a local name would have no site to be
  // promoted at. It stays a plain deref, which is what an offset below the
  // argument area has always been.

  it("records no parameter for a home slot the function never filled", () => {
    const insns = body(...PROLOGUE_64, ["mov", "rax, qword ptr [rbp + 0x10]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([]);
  });

  it("indexes a home slot the function spills its own argument into", () => {
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "qword ptr [rbp + 0x10], rcx"],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual(["arg_0"]);
  });

  it("reads a spill through the stack pointer before the frame exists", () => {
    // MSVC's own order: the spills come first, addressed off RSP, and the
    // pushes and the frame follow. t64!sub_1400080E0 opens exactly like this.
    const insns = body(
      ["mov", "qword ptr [rsp + 0x10], rdx"],
      ["mov", "dword ptr [rsp + 8], ecx"],
      ["push", "rbp"],
      ["push", "rbx"],
      ["mov", "rbp, rsp"],
      ["mov", "rax, qword ptr [rbp + 0x18]"],
      ["mov", "rcx, qword ptr [rbp + 0x20]"],
    );
    // Two pushes then `mov rbp, rsp` is D = 0x10, so the return address is at
    // [rbp+0x10], argument 0's home slot is [rbp+0x18] and argument 1's is
    // [rbp+0x20] — the pushes shift both by two slots from the canonical
    // 0x10/0x18, which is the whole of what `D` is for.
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([
      "arg_0",
      "arg_1",
    ]);
  });

  it("records no parameter for a home slot filled with a callee-saved register", () => {
    // NEGATIVE CONTROL for the one that matters: `mov [rbp+0x10], rbx` is the
    // same instruction shape as a spill and the opposite fact — RBX is not
    // argument 0's register, so the slot is a register save parked in the
    // scratch the ABI gave the callee. t64!sub_1400027C8 does this four times
    // over, into arguments 0-3's home slots.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "qword ptr [rbp + 0x10], rbx"],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([]);
  });

  it("indexes a home slot spilled at a narrower width", () => {
    // t64!sub_14000EE7C spills R9's low half with `mov word ptr [rsp+0x20], r9w`
    // and reads it back with `movzx`. The slot holds argument 3; the width comes
    // from the reads, not from the spill.
    const insns = body(
      ["mov", "word ptr [rsp + 0x20], r9w"],
      ["push", "rbp"],
      ["mov", "rbp, rsp"],
      ["movzx", "eax, word ptr [rbp + 0x28]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual(["arg_3"]);
  });

  it("records no parameter for a slot written at an address inside a home slot", () => {
    // A byte at [rsp+9] is not argument 0; it is one byte of it, and the slot
    // as a whole has not been shown to hold the argument.
    const insns = body(
      ["mov", "byte ptr [rsp + 9], cl"],
      ["push", "rbp"],
      ["mov", "rbp, rsp"],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([]);
  });

  it("records no parameter for a sub-slot byte of an unfilled home slot", () => {
    // `inUnfilledHomeSpace` asks containment, not slot alignment: [rbp+0x12] is
    // the third byte of argument 0's home slot, and if the callee never filled
    // that slot the byte is not part of an argument either. No such offset
    // occurs in the corpus, so this is the rule pinned rather than measured —
    // the reading it replaces named it `arg_0x12` and declared it a parameter.
    const insns = body(...PROLOGUE_64, ["mov", "al, byte ptr [rbp + 0x12]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([]);
  });

  it("keeps a sub-slot byte of a FILLED home slot, named by its offset", () => {
    // The other side of the same containment test, and the reason it is not a
    // blanket refusal: the slot is shown to hold argument 0, so the byte is
    // part of an argument. No index divides out of it, so the name is still the
    // offset — which is `argSlotName`'s sub-slot fallback, unchanged.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "qword ptr [rbp + 0x10], rcx"],
      ["mov", "al, byte ptr [rbp + 0x12]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([
      "arg_0",
      "arg_0x12",
    ]);
  });

  it("refuses a spill once any register has been written", () => {
    // `argsPristine`. After `mov rcx, rax` the register no longer provably
    // holds the incoming argument, so the store into its home slot is not
    // evidence about argument 0. Refusing costs the whole parameter, not just
    // its index; admitting it would name the slot after a value the caller
    // never passed.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "rcx, rax"],
      ["mov", "qword ptr [rbp + 0x10], rcx"],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([]);
  });

  it("indexes the caller's own argument area with no spill anywhere", () => {
    // Index 4 and up is above the home space, in storage the caller wrote
    // because there is no other way to pass a fifth argument. No spill is
    // possible and none is wanted.
    const insns = body(
      ...PROLOGUE_64,
      ["mov", "rax, qword ptr [rbp + 0x30]"],
      ["mov", "rcx, qword ptr [rbp + 0x38]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual([
      "arg_4",
      "arg_5",
    ]);
  });

  it("has no home space on x86, so a slot needs no spill", () => {
    // Every x86 argument is pushed by the caller, so `homeRegs` is empty and
    // `D` alone names every slot. This is why both PE32 binaries are the
    // byte-identical control for the whole home-space rule.
    const insns = body(...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0x8]"]);
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_0"]);
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
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(argNames(frame)).toEqual([]);
    // And the refusal is PUBLISHED, because it is also what stops `promote.ts`
    // from following a copy of RBP to a slot of a frame that does not exist —
    // the FPO reading `structs.ts` must be left to make (peek-a-bin-cvri).
    expect(frame!.frameDelta).toBeNull();
  });

  it("records no parameter for a slot below the argument area of a shifted frame", () => {
    // `lea rbp, [rsp - 0x1A30]` after one push puts the frame register 0x1A38
    // below the stack pointer on entry, so `[rbp + 0x1A20]` is 0x18 bytes
    // BELOW the return address — a local, and in the corpus the GS cookie.
    // t64!sub_14000D8C4.
    const insns = body(
      ["push", "rbp"],
      ["lea", "rbp, [rsp - 0x1A30]"],
      ["mov", "qword ptr [rbp + 0x1A20], rax"],
      ["mov", "rcx, qword ptr [rbp + 0x1A40]"],
      ["mov", "rdx, qword ptr [rbp + 0x1A60]"],
    );
    // 0x1A38 is the return address. 0x1A40 is the slot after it — and on x64
    // that is argument 0's HOME slot, which this function never spills into, so
    // it is no parameter either (peek-a-bin-g186). 0x1A60 is index 4, above the
    // home space, where the caller had no register to pass in and the slot is
    // an argument by construction. Both refusals in one fixture.
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, true))).toEqual(["arg_4"]);
  });

  it("keeps an argument reached over intervening pushes", () => {
    // The displacement, not the push pattern, is what says where the arguments
    // are — and it says *which* argument as well: three pushes then
    // `mov rbp, rsp` puts the return address at [rbp + 0x18], argument 0 at
    // [rbp + 0x20], and [rbp + 0x40] at index 4. This asserted `arg_0x40` until
    // peek-a-bin-sx57, which is the defect: `framed` is false here, so the
    // index was withheld even though the displacement determines it exactly.
    // Index 4 is above the home space, so it needs no spill.
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
    expect(argNames(frame)).toEqual(["arg_4"]);
    // The displacement is PUBLISHED, and this asserted a `framed` of false until
    // peek-a-bin-cvri — which is the second half of the same defect: `framed`
    // was also `promote.ts`'s gate on following a copy of the frame register, so
    // a shifted frame had its aliased slots left unresolved. The register is a
    // frame pointer here whatever `D` is.
    expect(frame!.frameDelta).toBe(0x18);
  });

  it("numbers slots of a frame established with lea", () => {
    // t64!sub_1400027C8's own prologue: three pushes, `sub rsp, 0x40`, then
    // `lea rbp, [rsp + 0x30]`, which leaves the frame register 0x28 below the
    // entry stack pointer. Every argument offset is shifted by that, and the
    // shift is exactly what `D` measures — so [rbp + 0x50] is index 4.
    //
    // This asserted `arg_0x10` on a fabricated single-push shape until
    // peek-a-bin-sx57, under the title "does not number slots of a frame
    // established with lea". The `lea` form is not a reason to withhold an
    // index; it is a reason to measure the displacement instead of assuming it.
    const insns = body(
      ["push", "rbp"],
      ["push", "r13"],
      ["push", "r14"],
      ["sub", "rsp, 0x40"],
      ["lea", "rbp, [rsp + 0x30]"],
      ["mov", "rax, qword ptr [rbp + 0x50]"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(argNames(frame)).toEqual(["arg_4"]);
    // Not the canonical geometry, which is a different question — and one that
    // is no longer a boolean: `promote.ts`'s `frameRegisterAliases` needs only
    // "is this a frame pointer", which is `frameDelta !== null`, so the
    // displacement is published rather than compared to `slotSize` here
    // (peek-a-bin-cvri).
    expect(frame!.frameDelta).toBe(0x28);
  });

  // This asserted ["arg_0x8"] until peek-a-bin-ikd and ["arg_0xC"] until
  // peek-a-bin-sx57. `push ebx` before `push ebp` leaves EBP at entry-ESP minus
  // two slots, so `[ebp + 8]` is the RETURN ADDRESS and the first argument is at
  // `[ebp + 0xC]`. ikd stopped calling the return address a parameter; sx57
  // gives the argument the index the comment had been asserting in prose all
  // along. There is no home space on x86 — every argument is pushed by the
  // caller — so `D` alone names it.
  it("records no parameter for the return address of a shifted frame", () => {
    const insns = body(
      ["push", "ebx"],
      ...PROLOGUE_32,
      ["mov", "eax, dword ptr [ebp + 0x8]"],
      ["mov", "ecx, dword ptr [ebp + 0xC]"],
    );
    expect(argNames(analyzeStackFrame(func(insns.length * 4), insns, false))).toEqual(["arg_0"]);
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

describe("analyzeStackFrame — the establishing instruction's address", () => {
  // Published for ONE consumer: `promote.ts` recognising the frame register's
  // own definition after `destroySSA`'s `swapDefWithCopy` swapped its
  // destination for a variable and DCE deleted the tie-back, which is the whole
  // of peek-a-bin-xb2f. It is a fact about WHICH INSTRUCTION, so it must be the
  // address of the write that set `D` and of nothing else.
  it("reports the address of the mov that establishes the frame", () => {
    const insns = body(...PROLOGUE_64, ["mov", "dword ptr [rbp - 0x10], eax"]);
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    // `body` lays the instructions out four bytes apart, so the establishing
    // `mov rbp, rsp` is the second of them.
    expect(frame!.frameDelta).toBe(8);
    expect(frame!.frameEstablishedAt).toBe(0x1004);
  });

  it("reports a frame established with no push ahead of it as +0, not -0", () => {
    // `mov ebp, esp` as the first instruction: V == E, so D == 0. Plain
    // negation yields -0 here, and `Object.is(-0, 0)` is false, so `toBe(0)`
    // IS the negative control -- it fails on the unnormalised value while
    // every relational consumer behaves identically either way. The slot at
    // [ebp+4] is argument 0 for this geometry, which is what pins that D
    // itself is right and not merely well-signed (peek-a-bin-f28y).
    const insns = body(["mov", "ebp, esp"], ["mov", "eax, dword ptr [ebp + 4]"]);
    const frame = analyzeStackFrame(func(insns.length * 4), insns, false);
    expect(frame!.frameDelta).toBe(0);
    expect(Object.is(frame!.frameDelta, -0)).toBe(false);
    expect(argNames(frame)).toEqual(["arg_0"]);
  });

  it("reports the address of a lea that establishes a shifted frame", () => {
    // t64!sub_1400027C8's geometry, and the shape whose IR copy carries a
    // *binary* source — which is why `frameRegisterAliases` reads the address
    // and never the source expression.
    const insns = body(
      ["push", "rbp"],
      ["push", "r13"],
      ["sub", "rsp, 0x40"],
      ["lea", "rbp, [rsp + 0x30]"],
      ["mov", "rax, qword ptr [rbp + 0x50]"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame!.frameDelta).toBe(0x20);
    expect(frame!.frameEstablishedAt).toBe(0x100c);
  });

  it("reports no address when the frame register is not a frame pointer", () => {
    // `mov rbp, rcx` — frame-pointer omission, so there is no establishing
    // instruction to name and the two fields refuse together.
    const insns = body(
      ["push", "rbp"],
      ["mov", "rbp, rcx"],
      ["mov", "dword ptr [rsp + 0x18], eax"],
    );
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame!.frameDelta).toBeNull();
    expect(frame!.frameEstablishedAt).toBeNull();
  });

  it("is unmoved by a second write of the frame register", () => {
    // The spill scan ends at a second write; `D` was fixed at the first and so
    // is this. Naming the later instruction would point `promote.ts` at a
    // statement that does not define the frame.
    const insns = body(...PROLOGUE_64, ["mov", "dword ptr [rbp - 0x10], eax"], ["mov", "rbp, rcx"]);
    const frame = analyzeStackFrame(func(insns.length * 4), insns, true);
    expect(frame!.frameDelta).toBe(8);
    expect(frame!.frameEstablishedAt).toBe(0x1004);
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

  it("names no establishing instruction, because it is in the helper", () => {
    // `frameEstablishedAt` is an address in THIS function's instruction stream —
    // the statement `promote.ts` will look for. The helper's `lea` is in another
    // function, so there is no such statement and the honest answer is null; a
    // caller-side address here would be an address that matches something else
    // (peek-a-bin-xb2f).
    const { func: f, instructions } = withHelper([
      ...HELPER_CALL,
      ["mov", "ebx, dword ptr [ebp + 0x8]"],
    ]);
    const frame = analyzeStackFrame(f, instructions, false);
    expect(frame!.frameDelta).toBe(4);
    expect(frame!.frameEstablishedAt).toBeNull();
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
    //
    // [rbp + 0x30] is index 4 and is what pins the arithmetic: it is only 4 if
    // the helper really was read as leaving the frame at `E - 8`. [rbp + 0x10]
    // is argument 0's HOME slot and yields NO parameter, because the helper
    // path reports no spilled home slots at all — a deliberate refusal rather
    // than a gap, since `__SEH_prolog4` is a 32-bit form with no home space and
    // the helper search fires 0 times on both x64 binaries (peek-a-bin-sx57).
    // Under peek-a-bin-g186 that empty `homed` now withholds the slot entirely
    // rather than merely offset-naming it, which is the same conservatism one
    // storey up and still costs nothing measured.
    const callerInsns: [string, string][] = [
      ["push", "0x20"],
      ["call", `0x${HELPER_ADDR.toString(16)}`],
      ["mov", "rax, qword ptr [rbp + 0x10]"],
      ["mov", "rcx, qword ptr [rbp + 0x30]"],
    ];
    const helper: [string, string][] = [
      ["push", "0x4041d0"],
      ["lea", "rbp, [rsp + 0x10]"],
      ["ret", ""],
    ];
    const { func: f, instructions } = withHelper(callerInsns, helper);
    expect(argNames(analyzeStackFrame(f, instructions, true))).toEqual(["arg_4"]);
  });

  // The helper is itself detected as a function — t32!sub_404170 and
  // w32!sub_4043D0 are exactly this — and analysed on its own it has `D = -8`:
  // two pushes leave the stack pointer at `E - 8`, so `lea ebp, [esp + 0x10]`
  // puts the frame register at `E + 8`, ABOVE its own entry stack pointer. The
  // frame it addresses is the CALLER's, so no `[ebp + off]` in it is an argument
  // of it — and at `D = -8, slot = 4` the plain threshold `off >= D + slot`
  // admits every offset there is, spelling the caller's saved EBP `arg_1` and
  // its return address `arg_2` (peek-a-bin-s7hl).
  it("records no parameter for the helper itself, whose frame is its caller's", () => {
    const asOwnFunction: [string, string][] = [
      ...SEH_PROLOG4.slice(0, 5),
      ["mov", "eax, dword ptr [ebp + 0x4]"],
      ["mov", "ecx, dword ptr [ebp + 0x10]"],
      ["ret", ""],
    ];
    const insns = asOwnFunction.map(([mn, op], i) => insn(0x1000 + i * 4, mn, op));
    const frame = analyzeStackFrame(func(insns.length * 4), insns, false);
    expect(frame!.frameDelta).toBe(-8);
    expect(argNames(frame)).toEqual([]);
  });
});
