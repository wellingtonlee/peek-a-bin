/**
 * peek-a-bin-8bj / peek-a-bin-erb — the A64 operand grammar.
 *
 * Every operand string asserted here was taken verbatim from Capstone's output
 * on t64-arm.exe, not invented: the ARM64 spellings (`#0x…` targets, the
 * three-field `tbz`, the decimal-or-hex `add` immediate) are exactly the places
 * a hand-written parser goes wrong.
 *
 * The negative cases carry as much weight as the positive ones. This branch's
 * standard is that an unresolvable branch produces NO edge rather than a
 * guessed one, and a wrong edge is undetectable downstream — so "declines" is a
 * result to pin, not an omission.
 */

import { describe, expect, it } from "vitest";
import {
  classifyArm64Branch,
  findArm64AddressRefs,
  findArm64LiteralPools,
  isArm64ConditionalBranch,
  isArm64JumpMnemonic,
} from "../arm64Operands";

describe("classifyArm64Branch — direct transfers", () => {
  it("resolves an unconditional b", () => {
    expect(classifyArm64Branch("b", "#0x140001210")).toEqual({
      kind: "jump",
      target: 0x140001210,
      indirect: false,
    });
  });

  it("resolves bl as a call, not a jump — it must not end a basic block", () => {
    expect(classifyArm64Branch("bl", "#0x140003160")).toEqual({
      kind: "call",
      target: 0x140003160,
      indirect: false,
    });
  });

  it.each([
    ["b.eq", 0x1400011d4],
    ["b.ne", 0x140001018],
    ["b.hs", 0x140001180],
    ["b.lo", 0x140001280],
    ["b.hi", 0x140001610],
    ["b.ls", 0x140003998],
    ["b.ge", 0x1400019b0],
    ["b.lt", 0x14000189c],
    ["b.gt", 0x140001538],
    ["b.le", 0x140001a28],
  ])("resolves %s as a two-successor conditional branch", (mn, target) => {
    expect(classifyArm64Branch(mn, `#0x${target.toString(16)}`)).toEqual({
      kind: "cond",
      target,
      indirect: false,
    });
  });

  it("resolves cbz/cbnz past the register operand", () => {
    expect(classifyArm64Branch("cbz", "x3, #0x140001164")?.target).toBe(0x140001164);
    expect(classifyArm64Branch("cbnz", "w2, #0x140001500")?.target).toBe(0x140001500);
  });

  it("resolves tbz/tbnz past the register AND the bit number", () => {
    // Three fields. A parser that took "the last thing that looks like an
    // address" would agree here and disagree on a malformed decode.
    expect(classifyArm64Branch("tbz", "w2, #2, #0x14000114c")?.target).toBe(0x14000114c);
    expect(classifyArm64Branch("tbnz", "w0, #0x1f, #0x1400025b8")?.target).toBe(0x1400025b8);
  });

  it("treats ret as a return with no successor", () => {
    expect(classifyArm64Branch("ret", "")).toEqual({
      kind: "return",
      target: null,
      indirect: false,
    });
    for (const mn of ["retaa", "retab"]) {
      expect(classifyArm64Branch(mn, "")?.kind).toBe("return");
    }
  });
});

describe("classifyArm64Branch — declines rather than guesses", () => {
  it("gives an indirect br no target at all", () => {
    expect(classifyArm64Branch("br", "x8")).toEqual({
      kind: "jump",
      target: null,
      indirect: true,
    });
  });

  it("gives an indirect blr no target at all", () => {
    expect(classifyArm64Branch("blr", "x2")).toEqual({
      kind: "call",
      target: null,
      indirect: true,
    });
  });

  it.each(["braa", "braaz", "brab", "brabz"])("treats %s as an indirect jump", (mn) => {
    expect(classifyArm64Branch(mn, "x8, x9")).toMatchObject({ kind: "jump", indirect: true });
  });

  it.each(["blraa", "blraaz", "blrab", "blrabz"])("treats %s as an indirect call", (mn) => {
    expect(classifyArm64Branch(mn, "x8, x9")).toMatchObject({ kind: "call", indirect: true });
  });

  it("declines a target it cannot read, without falling back to a number", () => {
    // Still classified — the block still ends — but with no destination.
    expect(classifyArm64Branch("b", "x8")).toEqual({ kind: "jump", target: null, indirect: false });
    expect(classifyArm64Branch("b", "0x140001210")).toMatchObject({ target: null });
    expect(classifyArm64Branch("cbz", "#0x140001164")).toMatchObject({ target: null });
    expect(classifyArm64Branch("tbz", "w2, #0x14000114c")).toMatchObject({ target: null });
  });

  it("matches mnemonics exactly, so brk is not a br", () => {
    // t64-arm.exe holds 18 `brk`. A prefix test on "br" would end a basic block
    // at every one of them and drop the fallthrough edge.
    expect(classifyArm64Branch("brk", "#1")).toBeNull();
    for (const mn of ["bfi", "bfxil", "bic", "bfm", "blah"]) {
      expect(classifyArm64Branch(mn, "x0, x1, #1")).toBeNull();
    }
  });

  it("rejects a condition code A64 does not define", () => {
    expect(isArm64ConditionalBranch("b.eq")).toBe(true);
    expect(isArm64ConditionalBranch("b.zz")).toBe(false);
    expect(classifyArm64Branch("b.zz", "#0x140001018")).toBeNull();
  });
});

describe("classifyArm64Branch — leaves the x86 grammar alone", () => {
  it.each([
    ["jmp", "0x401000"],
    ["je", "0x401000"],
    ["jne", "0x401000"],
    ["jrcxz", "0x401000"],
    ["call", "0x401000"],
    ["mov", "eax, 0x10"],
    ["lea", "rax, [rip + 0x100]"],
    ["push", "rbp"],
    ["bt", "eax, 1"],
    ["bts", "eax, 1"],
    ["bswap", "eax"],
    ["bsf", "eax, ebx"],
    ["bound", "eax, [ebx]"],
  ])("says nothing about x86 %s", (mn, ops) => {
    expect(classifyArm64Branch(mn, ops)).toBeNull();
  });

  it("agrees with x86 about ret, which is the one shared spelling", () => {
    // Both architectures want the same answer: end the block, no successors.
    expect(classifyArm64Branch("ret", "")?.kind).toBe("return");
    expect(classifyArm64Branch("retn", "")).toBeNull();
  });
});

describe("isArm64JumpMnemonic — the jump-arrow guard", () => {
  it.each(["b", "b.eq", "cbz", "cbnz", "tbz", "tbnz", "br"])("draws for %s", (mn) => {
    expect(isArm64JumpMnemonic(mn)).toBe(true);
  });

  it.each(["bl", "blr", "ret", "brk", "mov", "jmp", "je", "call"])("does not draw for %s", (mn) => {
    // `bl` is the A64 `call`. JumpArrows excludes x86 calls because a
    // recursive or intra-function one lands inside the drawn window and
    // sprouts an arrow the view never had; `bl` is that same instruction.
    expect(isArm64JumpMnemonic(mn)).toBe(false);
  });
});

describe("findArm64AddressRefs — adrp/add pairs (peek-a-bin-erb)", () => {
  const insn = (address: number, mnemonic: string, opStr: string) => ({
    address,
    mnemonic,
    opStr,
  });

  it("reads the IAT thunk verbatim from t64-arm.exe", () => {
    // adrp x16, #0x140027000 / add x16, x16, #0 / ldr x16, [x16] / br x16
    const refs = findArm64AddressRefs([
      insn(0x140001000, "adrp", "x16, #0x140027000"),
      insn(0x140001004, "add", "x16, x16, #0"),
      insn(0x140001008, "ldr", "x16, [x16]"),
      insn(0x14000100c, "br", "x16"),
    ]);

    expect(refs).toEqual([
      { from: 0x140001004, target: 0x140027000, pairFrom: 0x140001000, load: false },
    ]);
  });

  it("reads a non-zero page offset, hex or decimal", () => {
    expect(
      findArm64AddressRefs([
        insn(0x140001010, "adrp", "x17, #0x140027000"),
        insn(0x140001014, "add", "x17, x17, #8"),
      ])[0],
    ).toMatchObject({ target: 0x140027008 });

    expect(
      findArm64AddressRefs([
        insn(0x140001010, "adrp", "x17, #0x140027000"),
        insn(0x140001014, "add", "x17, x17, #0x20"),
      ])[0],
    ).toMatchObject({ target: 0x140027020 });
  });

  it("distinguishes a load through the pair from the address itself", () => {
    // `ldr x1, [x3, #0x50]` after `adrp x3, #page` references page+0x50 and
    // leaves its CONTENTS in x1. Conflating the two turns an IAT slot into a
    // string pointer.
    const [ref] = findArm64AddressRefs([
      insn(0x140002000, "adrp", "x3, #0x140027000"),
      insn(0x140002004, "ldr", "x1, [x3, #0x50]"),
    ]);
    expect(ref).toEqual({
      from: 0x140002004,
      target: 0x140027050,
      pairFrom: 0x140002000,
      load: true,
    });
  });

  it("reads the one-instruction adr form", () => {
    expect(findArm64AddressRefs([insn(0x140001100, "adr", "x8, #0x1400018b0")])).toEqual([
      { from: 0x140001100, target: 0x1400018b0, load: false },
    ]);
  });

  it("does not confuse x1 with x16", () => {
    // `add x16, x16, #4` mentions x16, never x1. A substring test would let the
    // x1 binding be completed by the x16 add and report a fabricated address.
    const refs = findArm64AddressRefs([
      insn(0x140003000, "adrp", "x1, #0x140030000"),
      insn(0x140003004, "add", "x16, x16, #4"),
      insn(0x140003008, "add", "x1, x1, #0x10"),
    ]);
    expect(refs).toEqual([
      { from: 0x140003008, target: 0x140030010, pairFrom: 0x140003000, load: false },
    ]);
  });
});

describe("findArm64AddressRefs — gives up rather than report a stale address", () => {
  const insn = (address: number, mnemonic: string, opStr: string) => ({
    address,
    mnemonic,
    opStr,
  });

  it("drops the binding when an unmodelled instruction touches the register", () => {
    // `mov x16, x0` leaves something this reader cannot name in x16. The later
    // `add` would otherwise be credited with the long-dead adrp page.
    expect(
      findArm64AddressRefs([
        insn(0x140004000, "adrp", "x16, #0x140027000"),
        insn(0x140004004, "mov", "x16, x0"),
        insn(0x140004008, "add", "x16, x16, #0x10"),
      ]),
    ).toEqual([]);
  });

  it("does not carry a binding across a branch", () => {
    // Control can enter at the branch target, so x16 need not hold the page by
    // the time the `add` executes.
    expect(
      findArm64AddressRefs([
        insn(0x140004100, "adrp", "x16, #0x140027000"),
        insn(0x140004104, "cbz", "w0, #0x140004200"),
        insn(0x140004108, "add", "x16, x16, #0x10"),
      ]),
    ).toEqual([]);
  });

  it("reports nothing for a lone adrp — a page base is not a reference", () => {
    expect(
      findArm64AddressRefs([
        insn(0x140004200, "adrp", "x16, #0x140027000"),
        insn(0x140004204, "nop", ""),
        insn(0x140004208, "nop", ""),
      ]),
    ).toEqual([]);
  });

  it("keeps two live pages apart and pairs each with its own completion", () => {
    const refs = findArm64AddressRefs([
      insn(0x140004300, "adrp", "x0, #0x140020000"),
      insn(0x140004304, "adrp", "x1, #0x140030000"),
      insn(0x140004308, "add", "x0, x0, #4"),
      insn(0x14000430c, "add", "x1, x1, #8"),
    ]);
    expect(refs.map((r) => r.target)).toEqual([0x140020004, 0x140030008]);
  });

  it("declines when the same register is re-based before completion", () => {
    const refs = findArm64AddressRefs([
      insn(0x140004400, "adrp", "x0, #0x140020000"),
      insn(0x140004404, "adrp", "x0, #0x140030000"),
      insn(0x140004408, "add", "x0, x0, #4"),
    ]);
    expect(refs).toEqual([
      { from: 0x140004408, target: 0x140030004, pairFrom: 0x140004404, load: false },
    ]);
  });

  it("says nothing about x86 rip-relative operands", () => {
    expect(
      findArm64AddressRefs([
        insn(0x401000, "lea", "rax, [rip + 0x100]"),
        insn(0x401007, "mov", "eax, dword ptr [0x404000]"),
      ]),
    ).toEqual([]);
  });
});

describe("findArm64AddressRefs — one adrp can serve several uses", () => {
  const insn = (address: number, mnemonic: string, opStr: string) => ({
    address,
    mnemonic,
    opStr,
  });

  it("keeps the page alive across an add into a different register", () => {
    // Verbatim shape from t64-arm.exe: `adrp x8, #0x140024000` feeds
    // `add x1, x8, #0x480` and, further on, another offset off the same x8.
    const refs = findArm64AddressRefs([
      insn(0x140002038, "adrp", "x8, #0x140024000"),
      insn(0x14000203c, "add", "x1, x8, #0x480"),
      insn(0x140002040, "add", "x2, x8, #0x4c0"),
    ]);
    expect(refs.map((r) => r.target)).toEqual([0x140024480, 0x1400244c0]);
  });

  it("ends the binding at the self-rebasing add", () => {
    // `add x8, x8, #0x10` replaces the page with page+0x10; a later
    // `add x1, x8, #0x20` would then mean page+0x30, not page+0x20. Rather
    // than model that, the reader stops.
    const refs = findArm64AddressRefs([
      insn(0x140002100, "adrp", "x8, #0x140024000"),
      insn(0x140002104, "add", "x8, x8, #0x10"),
      insn(0x140002108, "add", "x1, x8, #0x20"),
    ]);
    expect(refs.map((r) => r.target)).toEqual([0x140024010]);
  });

  it("ends the binding at a load into the base register", () => {
    const refs = findArm64AddressRefs([
      insn(0x140002200, "adrp", "x8, #0x14001d000"),
      insn(0x140002204, "ldr", "x8, [x8, #0x98]"),
      insn(0x140002208, "ldr", "x9, [x8, #0x10]"),
    ]);
    expect(refs).toEqual([
      { from: 0x140002204, target: 0x14001d098, pairFrom: 0x140002200, load: true },
    ]);
  });

  it("survives a store through the base, which writes memory and not the base", () => {
    const refs = findArm64AddressRefs([
      insn(0x140002300, "adrp", "x8, #0x140024000"),
      insn(0x140002304, "str", "x0, [x8, #0x10]"),
      insn(0x140002308, "ldr", "x1, [x8, #0x18]"),
    ]);
    expect(refs.map((r) => r.target)).toEqual([0x140024010, 0x140024018]);
  });

  it("ends the binding at a writeback form, which increments the base", () => {
    const refs = findArm64AddressRefs([
      insn(0x140002400, "adrp", "x8, #0x140024000"),
      insn(0x140002404, "ldr", "x0, [x8, #0x10]!"),
      insn(0x140002408, "ldr", "x1, [x8, #0x18]"),
    ]);
    expect(refs.map((r) => r.target)).toEqual([0x140024010]);
  });
});

/**
 * peek-a-bin-qiws — `LDR (literal)`, the ISA's own data marking.
 *
 * Every operand string here is Capstone's spelling from t64-arm.exe or
 * w64-arm.exe. The four real pools this reads on that corpus were adjudicated
 * against the bytes: 0x1400016f8 is `strlen`'s 16-byte lane vector
 * `0f 0e 0d … 01 00`, 0x140003858/0x140003860 are the 64-bit constants
 * 0x2b992ddfa232 and …33, and 0x14001ae00 is the double 0x3ea8a93728719535.
 *
 * The refusals carry as much weight as the matches. Marking a byte as data
 * removes an instruction from the view with nothing said, so every rule here
 * errs SHORT and each refusal is pinned in both directions.
 */
describe("findArm64LiteralPools", () => {
  const insn = (address: number, mnemonic: string, opStr: string) => ({
    address,
    mnemonic,
    opStr,
  });

  it("reads the 16-byte pool a `ldr q` names", () => {
    // t64-arm.exe 0x1400016ac, verbatim.
    expect(findArm64LiteralPools([insn(0x1400016ac, "ldr", "q1, #0x1400016f8")])).toEqual([
      { from: 0x1400016ac, target: 0x1400016f8, size: 16 },
    ]);
  });

  it("takes the datum width from the destination register", () => {
    const widths = findArm64LiteralPools([
      insn(0x140001000, "ldr", "w0, #0x140002000"),
      insn(0x140001004, "ldr", "s0, #0x140002000"),
      insn(0x140001008, "ldr", "x19, #0x140002000"),
      insn(0x14000100c, "ldr", "d29, #0x140002000"),
      insn(0x140001010, "ldr", "q1, #0x140002000"),
    ]).map((p) => p.size);
    // `w`/`s` read four bytes, `x`/`d` eight, `q` sixteen. That is the
    // encoding, and it is the only thing that states the pool's extent.
    expect(widths).toEqual([4, 4, 8, 8, 16]);
  });

  it("reads `ldrsw` as the FOUR bytes it loads, not the eight it produces", () => {
    // The sign extension happens in the register; the datum is a word.
    expect(findArm64LiteralPools([insn(0x140001000, "ldrsw", "x8, #0x140002000")])).toEqual([
      { from: 0x140001000, target: 0x140002000, size: 4 },
    ]);
  });

  it("reads the zero-register spelling, which the encoding permits", () => {
    expect(findArm64LiteralPools([insn(0x140001000, "ldr", "xzr, #0x140002000")])).toEqual([
      { from: 0x140001000, target: 0x140002000, size: 8 },
    ]);
  });

  it("names no pool for a bracketed operand, which is a register-based load", () => {
    // `findArm64AddressRefs` owns that form. Conflating the two would let any
    // `ldr x0, [x1, #8]` claim eight bytes of whatever address it computed.
    expect(
      findArm64LiteralPools([
        insn(0x140001000, "ldr", "x0, [x1, #8]"),
        insn(0x140001004, "ldr", "q1, [x9], #16"),
        insn(0x140001008, "ldr", "x16, [x16]"),
      ]),
    ).toEqual([]);
  });

  it("refuses a misaligned target, which means the operand was misread", () => {
    // The immediate counts WORDS, so a real target is 4-byte aligned. This is
    // a self-consistency check on the reader, not a claim about compilers.
    expect(findArm64LiteralPools([insn(0x140001000, "ldr", "x0, #0x140002002")])).toEqual([]);
  });

  it("refuses `prfm`, which names a cache line and states no width", () => {
    // It shares the LDR-literal encoding class, so it is refused explicitly
    // rather than by omission. Any width chosen for it would be invented.
    expect(findArm64LiteralPools([insn(0x140001000, "prfm", "pldl1keep, #0x140002000")])).toEqual(
      [],
    );
  });

  it("refuses a destination register spelling it does not know", () => {
    expect(
      findArm64LiteralPools([
        insn(0x140001000, "ldr", "v0, #0x140002000"),
        insn(0x140001004, "ldr", "b3, #0x140002000"),
      ]),
    ).toEqual([]);
  });

  it("refuses an operand that is not a resolved address", () => {
    expect(
      findArm64LiteralPools([
        insn(0x140001000, "ldr", "x0, #8"),
        insn(0x140001004, "ldr", "x0"),
        insn(0x140001008, "ldr", "x0, x1, #0x140002000"),
      ]),
    ).toEqual([]);
  });
});
