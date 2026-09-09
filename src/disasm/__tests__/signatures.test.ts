import { describe, expect, it } from "vitest";
import { inferSignature } from "../signatures";
import { analyzeStackFrame } from "../stack";
import type { DisasmFunction, Instruction } from "../types";

const START = 0x401000;
const INSN_SIZE = 4;

function makeInsns(start: number, list: [string, string][]): Instruction[] {
  return list.map(([mnemonic, opStr], i) => ({
    address: start + i * INSN_SIZE,
    mnemonic,
    opStr,
    size: INSN_SIZE,
    bytes: new Uint8Array(INSN_SIZE),
  }));
}

function func(address: number, insnCount: number): DisasmFunction {
  return { name: "f", address, size: insnCount * INSN_SIZE };
}

/**
 * Every test below this line is about the **x86** grammar, so the architecture
 * is fixed here and the non-null assertion is a statement about that: on x86
 * `inferSignature` always answers. The refusal for every other architecture is
 * asserted directly against the export, at the bottom of this file.
 */
function sig(list: [string, string][], is64: boolean) {
  const s = inferSignature(func(START, list.length), makeInsns(START, list), "x86", is64);
  if (s === null) throw new Error("inferSignature refused an x86 image");
  return s;
}

const sig64 = (list: [string, string][]) => sig(list, true);
const sig32 = (list: [string, string][]) => sig(list, false);

/**
 * The same call WITHOUT the non-null assertion, for the x86 tests that are
 * about the refusal itself.
 *
 * Since `peek-a-bin-j4uk.6` an x86 body that offers no evidence — no `ret N`,
 * no argument register read before it is written, and no recovered frame with
 * an `arg_<N>` slot in it — answers `null` rather than inventing
 * `{ convention: "cdecl", paramCount: 0 }`. `sig32` above still throws on
 * null, deliberately: a test that meant to exercise the grammar and instead
 * silently measured the refusal is the failure mode worth keeping loud.
 */
const maybeSig32 = (list: [string, string][]) =>
  inferSignature(func(START, list.length), makeInsns(START, list), "x86", false);

/**
 * A real 32-bit frame-pointer prologue, which the x86 parameter count now
 * REQUIRES: it is read off `stack.ts`'s recovered frame, so without one there
 * is no frame, `[ebp + N]` is not this function's argument area under any
 * reading, and the answer is `null` (peek-a-bin-ikd's rule, inherited).
 */
const PROLOGUE_32: [string, string][] = [
  ["push", "ebp"],
  ["mov", "ebp, esp"],
];

const nop: [string, string] = ["nop", ""];

describe("inferSignature — x64 (Windows fastcall)", () => {
  it("always reports the fastcall convention", () => {
    expect(sig64([["ret", ""]]).convention).toBe("fastcall");
  });

  it("counts a read of rcx as one parameter", () => {
    expect(
      sig64([
        ["mov", "rax, rcx"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(1);
  });

  it("counts a read of rdx as two parameters", () => {
    // RCX is param 1, RDX is param 2 — reading RDX implies RCX is used too.
    expect(
      sig64([
        ["mov", "rax, rdx"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(2);
  });

  it("infers four parameters from a read of r9", () => {
    expect(
      sig64([
        ["mov", "rax, r9"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(4);
  });

  it("takes the highest register index read, not the count of reads", () => {
    const s = sig64([
      ["mov", "rax, r8"],
      ["add", "rax, rcx"],
      ["ret", ""],
    ]);
    expect(s.paramCount).toBe(3);
  });

  it("ignores a read that happens after the register was overwritten", () => {
    // `mov rcx, 0x10` defines RCX locally, so the later read is not a parameter.
    const s = sig64([
      ["mov", "rcx, 0x10"],
      ["mov", "rax, rcx"],
      ["ret", ""],
    ]);
    expect(s.paramCount).toBe(0);
  });

  it("does not count the destination of a mov as a read", () => {
    expect(
      sig64([
        ["mov", "rcx, rax"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(0);
  });

  it("counts both operands of a cmp as reads", () => {
    expect(
      sig64([
        ["cmp", "rdx, 0x0"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(2);
  });

  it("counts a pushed argument register as a read", () => {
    expect(
      sig64([
        ["push", "rcx"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(1);
  });

  it("counts a memory dereference through an argument register", () => {
    expect(
      sig64([
        ["mov", "eax, dword ptr [rcx + 0x8]"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(1);
  });

  /**
   * THE x64 STACK-ARGUMENT CLAIM IS GONE, AND FIVE TESTS WENT WITH IT
   * (peek-a-bin-j4uk.6). What they pinned, so nobody restores it by reading the
   * gap as an oversight:
   *
   *  - "reads [rsp+0x28] as the fifth parameter" and "…[rsp+0x30] as the
   *    sixth", asserting 5 and 6 from a lone `mov`.
   *  - "takes the deepest stack access", asserting **7** parameters from
   *    `[rsp + 0x38]` — in a fixture containing no `sub rsp` and no `push`
   *    whatever, which is precisely why the rule was wrong: incoming argument 5
   *    sits at `[rsp + allocation + pushes + 0x28]`, so with the allocation
   *    unread the pattern matched the function's OWN OUTGOING argument area.
   *  - "combines register and stack parameters by taking the max", asserting 5.
   *  - "ignores accesses inside the shadow space", asserting 0 — the only one
   *    of the five that is still true, and now true for want of the rule rather
   *    than because of its threshold, so it pins nothing.
   *
   * They are DELETED rather than repaired with a `sub rsp` in the fixture: the
   * rule is gone, so a fixture that makes it answer correctly would pin
   * arithmetic no code performs. Measured at `97ef927`, the rule reported 262
   * parameters for `t64!sub_140001000` (`sub rsp, 0x848`) where the decompiler
   * emitted 4 — 54 over-claiming functions per x64 binary, worst +258 —
   * and `corpus/emitAudits.ts`'s `signatureAgreement` is the instrument that
   * now says so. The `client.test.ts` precedent at `peek-a-bin-1xc5`: a test
   * whose subject was removed is deleted with a note, never re-pointed at
   * something else.
   */
  it("counts no parameter from a stack access, at any offset", () => {
    // The whole population the deleted block covered, asserted as one refusal.
    for (const off of ["0x20", "0x28", "0x30", "0x38"]) {
      expect(
        sig64([
          ["mov", `rax, qword ptr [rsp + ${off}]`],
          ["ret", ""],
        ]).paramCount,
        `[rsp + ${off}] must contribute no parameter`,
      ).toBe(0);
    }
    // …and it does not suppress the register evidence beside it either.
    expect(
      sig64([
        ["mov", "rax, rcx"],
        ["mov", "rbx, qword ptr [rsp + 0x28]"],
        ["ret", ""],
      ]).paramCount,
    ).toBe(1);
  });

  describe("scan window", () => {
    it("sees a read at instruction 19", () => {
      const s = sig64([...Array(19).fill(nop), ["mov", "rax, rcx"], ["ret", ""]]);
      expect(s.paramCount).toBe(1);
    });

    it("stops after 20 instructions", () => {
      const s = sig64([...Array(20).fill(nop), ["mov", "rax, rcx"], ["ret", ""]]);
      expect(s.paramCount).toBe(0);
    });
  });

  /**
   * INVERTED at `peek-a-bin-j4uk.6`. This asserted
   * `{ convention: "fastcall", paramCount: 0 }` — a complete-shaped answer
   * invented from the optional header's magic over a function not one byte of
   * which was read, which is the exact falsehood the architecture-refusal essay
   * in the same file exists to prevent.
   */
  it("refuses a function with no instructions rather than inventing a convention", () => {
    expect(inferSignature(func(START, 4), [], "x86", true)).toBeNull();
  });

  it("only considers instructions inside the function range", () => {
    // A neighbouring function reads RCX; ours does not.
    const insns = makeInsns(START, [
      ["mov", "rax, rcx"], // belongs to the previous function
      ["ret", ""],
      ["xor", "eax, eax"], // our function starts here
      ["ret", ""],
      ["mov", "rax, r9"], // belongs to the next function
    ]);
    const ours: DisasmFunction = { name: "f", address: START + 2 * INSN_SIZE, size: 2 * INSN_SIZE };
    expect(inferSignature(ours, insns, "x86", true)?.paramCount).toBe(0);
  });

  describe("zeroing idioms", () => {
    it("does not count `xor rcx, rcx` as a parameter read", () => {
      expect(
        sig64([
          ["xor", "rcx, rcx"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("does not count `xor ecx, ecx` as a parameter read", () => {
      expect(
        sig64([
          ["xor", "ecx, ecx"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("does not count `sub r8, r8` as a parameter read", () => {
      expect(
        sig64([
          ["sub", "r8, r8"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("lets a zeroing idiom suppress a later read of the same register", () => {
      const s = sig64([
        ["xor", "ecx, ecx"],
        ["mov", "rax, rcx"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(0);
    });

    it("still counts a genuine xor against a parameter register", () => {
      // `xor rcx, rdx` reads both operands — this is arithmetic, not zeroing.
      expect(
        sig64([
          ["xor", "rcx, rdx"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(2);
    });
  });

  describe("sub-register operands", () => {
    it("counts a read of edx as two parameters", () => {
      expect(
        sig64([
          ["mov", "eax, edx"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(2);
    });

    it("counts a read of r8d as three parameters", () => {
      expect(
        sig64([
          ["mov", "eax, r8d"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(3);
    });

    it("counts 16-bit and 8-bit reads of the argument registers", () => {
      expect(
        sig64([
          ["movzx", "eax, cx"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(1);
      expect(
        sig64([
          ["movzx", "eax, dl"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(2);
      expect(
        sig64([
          ["movzx", "eax, r9b"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(4);
    });

    it("treats a 32-bit write as killing the whole register", () => {
      const s = sig64([
        ["mov", "ecx, 0x10"],
        ["mov", "rax, rcx"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(0);
    });

    it("does not read `rdx` out of the `dx` inside another mnemonic operand", () => {
      // Substring matching used to see `rdx` in text like `dx`/`edx` and vice versa.
      expect(
        sig64([
          ["mov", "rax, qword ptr [rbx]"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("does not count a write to a 32-bit argument register as a read", () => {
      expect(
        sig64([
          ["mov", "ecx, eax"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("keeps counting the parent after a partial 8-bit write", () => {
      // `mov cl, al` leaves the upper bits of RCX intact, so the later read is
      // still (partly) a read of the incoming argument.
      const s = sig64([
        ["mov", "cl, al"],
        ["mov", "rax, rcx"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(1);
    });
  });

  describe("read/write ordering within one instruction", () => {
    it("counts a register that is read and written by the same instruction", () => {
      // `add rdx, 1` reads the incoming RDX before overwriting it.
      expect(
        sig64([
          ["add", "rdx, 0x1"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(2);
    });

    it("suppresses reads only after the defining instruction", () => {
      const s = sig64([
        ["add", "rcx, 0x1"],
        ["mov", "rax, rcx"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(1);
    });

    it("counts registers read through a memory destination", () => {
      expect(
        sig64([
          ["mov", "qword ptr [rdx], rax"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(2);
    });

    it("does not treat the destination of a 3-operand imul as a read", () => {
      expect(
        sig64([
          ["imul", "rcx, rax, 0x4"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("counts the destination of a 2-operand imul as a read", () => {
      expect(
        sig64([
          ["imul", "rcx, rax"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(1);
    });

    it("treats pop as a write, not a read", () => {
      const s = sig64([
        ["pop", "rcx"],
        ["mov", "rax, rcx"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(0);
    });
  });
});

describe("inferSignature — x86", () => {
  /**
   * INVERTED at `peek-a-bin-j4uk.6`, and it is the headline of the change: this
   * asserted `{ convention: "cdecl", paramCount: 0 }` as the DEFAULT — the
   * answer for any 32-bit function the grammar could not read. x86 has four
   * conventions the tool can name and they are not interchangeable, so naming
   * one is a claim about the interface; `fastcall` on x64 is a property of the
   * architecture and states nothing, which is why the two paths differ here.
   *
   * `xor eax, eax / ret` offers none of the three kinds of evidence — no
   * `ret N`, no argument register read before it is written, no recovered frame
   * with an argument slot in it — so the honest answer is silence.
   */
  it("refuses a function that offers no evidence of a convention", () => {
    expect(
      maybeSig32([
        ["xor", "eax, eax"],
        ["ret", ""],
      ]),
    ).toBeNull();
  });

  /**
   * The liveness half of the refusal above, and the discriminator: the SAME
   * body with a real prologue and one argument access does answer. Without
   * this, gutting `inferSignature32` to `return null` would pass.
   */
  it("answers cdecl for the same body once a frame and an argument exist", () => {
    expect(
      sig32([
        ...PROLOGUE_32,
        ["mov", "eax, dword ptr [ebp + 0x8]"],
        ["xor", "eax, eax"],
        ["ret", ""],
      ]),
    ).toEqual({ convention: "cdecl", paramCount: 1 });
  });

  describe("stdcall detection", () => {
    it("reads `ret 0xc` as stdcall with three parameters", () => {
      expect(
        sig32([
          ["xor", "eax, eax"],
          ["ret", "0xc"],
        ]),
      ).toEqual({
        convention: "stdcall",
        paramCount: 3,
      });
    });

    it("accepts the retn spelling", () => {
      expect(sig32([["retn", "0x8"]])).toEqual({ convention: "stdcall", paramCount: 2 });
    });

    it("accepts a decimal operand", () => {
      expect(sig32([["ret", "16"]])).toEqual({ convention: "stdcall", paramCount: 4 });
    });

    /**
     * These three asserted `"cdecl"`; each now asserts that the cleanup
     * evidence is ABSENT, which is what they were really about, and the
     * conventions they get instead come from the evidence beside them
     * (peek-a-bin-j4uk.6). `ret 0x0` and a bare `ret` pop nothing, so nothing
     * distinguishes cdecl from stdcall and neither may be named without a
     * frame; with a frame the caller-cleans reading IS cdecl and is asserted.
     */
    it("reads `ret 0x0` as no cleanup at all", () => {
      expect(maybeSig32([["ret", "0x0"]])).toBeNull();
      expect(
        sig32([...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0x8]"], ["ret", "0x0"]]),
      ).toEqual({ convention: "cdecl", paramCount: 1 });
    });

    it("reads a bare ret as no cleanup at all", () => {
      expect(maybeSig32([["ret", ""]])).toBeNull();
      expect(sig32([...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0x8]"], ["ret", ""]])).toEqual({
        convention: "cdecl",
        paramCount: 1,
      });
    });

    it("ignores a `ret N` that is not the last instruction of the function", () => {
      // Early-out returns are common; only the final instruction is inspected.
      // The frame is what supplies the answer instead, and it says 1 rather
      // than the 2 the early `ret 0x8` would have claimed.
      expect(
        sig32([
          ...PROLOGUE_32,
          ["mov", "eax, dword ptr [ebp + 0x8]"],
          ["ret", "0x8"],
          ["xor", "eax, eax"],
          ["ret", ""],
        ]),
      ).toEqual({ convention: "cdecl", paramCount: 1 });
    });
  });

  /**
   * WAS "ebp-relative parameter counting", AND THE SCAN IT NAMED IS GONE
   * (peek-a-bin-j4uk.6). Every fixture below used to run without a prologue,
   * because the old rule counted any `[ebp + N]` operand with `N >= 8` **with
   * no frame-pointer check at all** — `peek-a-bin-ikd`'s defect verbatim, one
   * module over, and the population `decompile/structs.ts` keys `^arg_(\d+)$`
   * to exclude. Under frame-pointer omission `mov ebp, ecx` makes EBP an object
   * pointer and `[ebp + 0x10]` is a struct field access.
   *
   * The count is now read off `stack.ts`'s recovered frame, so each fixture
   * gains a real prologue and there is a matching refusal beside it. The
   * offsets and expected counts are unchanged where the frame is genuine, which
   * is the point: the answer was right for framed functions all along and wrong
   * about which functions those were.
   */
  describe("parameter counting off the recovered frame", () => {
    it("counts [ebp+0x8] as one parameter", () => {
      expect(
        sig32([...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0x8]"], ["ret", ""]]).paramCount,
      ).toBe(1);
    });

    it("counts [ebp+0x10] as three parameters", () => {
      expect(
        sig32([...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0x10]"], ["ret", ""]]).paramCount,
      ).toBe(3);
    });

    /**
     * THE FRAME-POINTER REQUIREMENT ITSELF, as a differential: the same operand
     * at the same offset, with and without a prologue. Remove the requirement
     * from `framedParamCount` — or go back to scanning operand text — and this
     * row reddens while its neighbour above stays green.
     *
     * MEASURED INERT IN THE CORPUS, and left that way deliberately: the FPO
     * refusal is documented as unfalsifiable on this corpus (peek-a-bin-5zpo,
     * peek-a-bin-cvri — removing `stack.ts`'s own leaves the emitted C
     * byte-identical), and an x86 parameter count never reaches `promote.ts`,
     * whose register-parameter arm is `is64`-gated. So this unit fixture is the
     * whole instrument for the class.
     */
    it("refuses [ebp+0x10] where no frame pointer was established", () => {
      // `mov ebp, edx` is how an MSVC funclet receives its PARENT's frame, and
      // `xor ebp, ebp` makes the register a constant; in neither is
      // `[ebp + 0x10]` an argument of this function. Both are named in
      // `StackFrame.frameDelta`'s own docstring as the population `null` covers.
      expect(
        maybeSig32([
          ["mov", "ebp, edx"],
          ["mov", "eax, dword ptr [ebp + 0x10]"],
          ["ret", ""],
        ]),
      ).toBeNull();
      expect(
        maybeSig32([
          ["xor", "ebp, ebp"],
          ["mov", "eax, dword ptr [ebp + 0x10]"],
          ["ret", ""],
        ]),
      ).toBeNull();
      // `mov ebp, ecx` — the third shape the docstring names — is deliberately
      // NOT asserted null: reading ECX before writing it is genuine evidence of
      // a register convention, so the answer is `thiscall` with paramCount 0.
      // The parameter claim is still withdrawn, which is the property here.
      expect(
        maybeSig32([
          ["mov", "ebp, ecx"],
          ["mov", "eax, dword ptr [ebp + 0x10]"],
          ["ret", ""],
        ]),
      ).toEqual({ convention: "thiscall", paramCount: 0 });
    });

    it("takes the deepest offset, not the number of accesses", () => {
      const s = sig32([
        ...PROLOGUE_32,
        ["mov", "eax, dword ptr [ebp + 0xc]"],
        ["mov", "ebx, dword ptr [ebp + 0x8]"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(2);
    });

    it("ignores negative offsets (locals)", () => {
      // A frame with locals and no arguments accounts for no argument slot, so
      // there is no parameter evidence and no convention to name either.
      expect(
        maybeSig32([...PROLOGUE_32, ["mov", "dword ptr [ebp - 0x8], eax"], ["ret", ""]]),
      ).toBeNull();
    });

    it("scans the whole function, not just the prologue", () => {
      const s = sig32([
        ...PROLOGUE_32,
        ...Array(30).fill(nop),
        ["mov", "eax, dword ptr [ebp + 0x8]"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(1);
    });

    it("lets `ret N` win over the frame", () => {
      const s = sig32([...PROLOGUE_32, ["mov", "eax, dword ptr [ebp + 0x10]"], ["ret", "0x8"]]);
      expect(s).toEqual({ convention: "stdcall", paramCount: 2 });
    });
  });

  /**
   * THISCALL AND FASTCALL, WHICH USED TO BE ONE ANSWER (peek-a-bin-j4uk.6).
   *
   * The rule was "ECX is read before it is written" and it never consulted EDX,
   * so every 32-bit `__fastcall` helper — and MSVC's CRT is full of them — was
   * labelled `thiscall` on the panel. The two conventions differ in exactly one
   * fact: `__thiscall` puts `this` in ECX and everything else on the stack,
   * `__fastcall` puts the first two integer arguments in ECX and EDX.
   *
   * The rows that previously asserted `"cdecl"` as the *absence* of thiscall
   * now assert the absence itself, since with no other evidence there is no
   * convention to fall back to.
   */
  describe("register-convention detection", () => {
    it("reports thiscall when ecx is read before being written", () => {
      const s = sig32([
        ["mov", "eax, dword ptr [ecx + 0x4]"],
        ["ret", ""],
      ]);
      expect(s.convention).toBe("thiscall");
    });

    it("reports thiscall for a read of a sub-register of ecx", () => {
      expect(
        sig32([
          ["movzx", "eax, cl"],
          ["ret", ""],
        ]).convention,
      ).toBe("thiscall");
    });

    /** The half that was missing: EDX read before written too. */
    it("reports fastcall when edx is also read before being written", () => {
      expect(
        sig32([
          ["mov", "eax, dword ptr [ecx + 0x4]"],
          ["add", "eax, edx"],
          ["ret", ""],
        ]).convention,
      ).toBe("fastcall");
    });

    it("reports fastcall for a read of a sub-register of edx", () => {
      expect(
        sig32([
          ["mov", "eax, ecx"],
          ["movzx", "ebx, dl"],
          ["ret", ""],
        ]).convention,
      ).toBe("fastcall");
    });

    /**
     * The discriminator for the EDX half in the other direction. A write of EDX
     * before any read of it is a local use of a scratch register, not an
     * incoming argument — so the answer must stay `thiscall`. Report EDX on any
     * mention and this row reddens while every row above stays green.
     */
    it("stays thiscall when edx is written before it is read", () => {
      expect(
        sig32([
          ["mov", "eax, dword ptr [ecx + 0x4]"],
          ["xor", "edx, edx"],
          ["mov", "ebx, edx"],
          ["ret", ""],
        ]).convention,
      ).toBe("thiscall");
    });

    /**
     * `__fastcall` fills ECX first, so EDX alone is not evidence of a register
     * convention — it is a garbage read, and naming a convention from it would
     * be the invention this change removed.
     */
    it("names no register convention from edx alone", () => {
      expect(
        maybeSig32([
          ["mov", "eax, edx"],
          ["ret", ""],
        ]),
      ).toBeNull();
    });

    it("does not report a register convention for the `xor ecx, ecx` zeroing idiom", () => {
      expect(
        maybeSig32([
          ["xor", "ecx, ecx"],
          ["mov", "eax, dword ptr [ecx]"],
          ["ret", ""],
        ]),
      ).toBeNull();
    });

    it("does not report a register convention when ecx is written first", () => {
      expect(
        maybeSig32([
          ["mov", "ecx, 0x5"],
          ["mov", "eax, dword ptr [ecx]"],
          ["ret", ""],
        ]),
      ).toBeNull();
    });

    it("keeps stdcall when a `ret N` is also present", () => {
      const s = sig32([
        ["mov", "eax, dword ptr [ecx + 0x4]"],
        ["ret", "0x8"],
      ]);
      expect(s).toEqual({ convention: "stdcall", paramCount: 2 });
    });

    it("only scans the first ten instructions for the ecx read", () => {
      const early = sig32([...Array(9).fill(nop), ["mov", "eax, dword ptr [ecx]"], ["ret", ""]]);
      expect(early.convention).toBe("thiscall");
      const late = maybeSig32([
        ...Array(10).fill(nop),
        ["mov", "eax, dword ptr [ecx]"],
        ["ret", ""],
      ]);
      expect(late).toBeNull();
    });

    /**
     * The fixture gained a prologue: the stack half of the count is the
     * recovered frame's now, so without one `[ebp + 0x8]` is not an argument
     * slot and the answer would be `thiscall, 0`.
     *
     * `paramCount` counts the STACK slots only — the `this` in ECX is NOT added
     * to it, deliberately and as a stated under-count. Adding it would be a new
     * arity claim with no oracle anywhere in this repo able to check it, and
     * the direction this codebase refuses to err in is the other one
     * (peek-a-bin-f51x).
     */
    it("combines thiscall with the frame's argument slots, counting only those", () => {
      const s = sig32([
        ...PROLOGUE_32,
        ["mov", "eax, dword ptr [ecx + 0x4]"],
        ["mov", "ebx, dword ptr [ebp + 0x8]"],
        ["ret", ""],
      ]);
      expect(s).toEqual({ convention: "thiscall", paramCount: 1 });
    });

    /** A register convention with no stack slots still answers, at 0. */
    it("answers a register convention even where the frame accounts for nothing", () => {
      expect(
        sig32([
          ["mov", "eax, dword ptr [ecx + 0x4]"],
          ["ret", ""],
        ]),
      ).toEqual({ convention: "thiscall", paramCount: 0 });
    });
  });

  /**
   * INVERTED at `peek-a-bin-j4uk.6`, for the x64 twin's reason: this asserted
   * `{ convention: "cdecl", paramCount: 0 }` over a function not one byte of
   * which was read.
   */
  it("refuses a function with no instructions rather than inventing a convention", () => {
    expect(inferSignature(func(START, 4), [], "x86", false)).toBeNull();
  });

  /**
   * THE STACK FRAME MAY BE HANDED IN, AND `null` IS NOT `undefined`.
   * `undefined` means the caller did not compute one, so `inferSignature`
   * does; `null` means the caller computed one and there is no frame, which
   * must not be re-analysed into the same answer at the caller's expense.
   * Asserted as a differential over one body: supplying `undefined` recovers
   * the argument, supplying `null` refuses it.
   */
  describe("the stack frame parameter", () => {
    const BODY: [string, string][] = [
      ...PROLOGUE_32,
      ["mov", "eax, dword ptr [ebp + 0x8]"],
      ["ret", ""],
    ];
    const f = () => func(START, BODY.length);
    const insns = () => makeInsns(START, BODY);

    it("computes its own frame when none is supplied", () => {
      expect(inferSignature(f(), insns(), "x86", false)).toEqual({
        convention: "cdecl",
        paramCount: 1,
      });
    });

    it("uses a frame the caller supplies", () => {
      const supplied = analyzeStackFrame(f(), insns(), "x86", false);
      expect(supplied).not.toBeNull();
      expect(inferSignature(f(), insns(), "x86", false, undefined, supplied)).toEqual({
        convention: "cdecl",
        paramCount: 1,
      });
    });

    it("takes an explicit null as the caller's answer and does not recompute", () => {
      expect(inferSignature(f(), insns(), "x86", false, undefined, null)).toBeNull();
    });
  });
});

/**
 * THE ARCHITECTURE REFUSAL (`peek-a-bin-56q` item 1).
 *
 * These are the only tests in this file that vary the architecture, and each
 * one is written as a *differential*: the same instructions, the same `is64`,
 * only `arch` differs. That is what makes them discriminating — a test that
 * merely fed A64 text and asserted null would pass against a function that had
 * simply failed to match anything, which is exactly the accidental silence this
 * change replaces with a structural one.
 *
 * Measured before the refusal existed: over t64-arm.exe and w64-arm.exe at
 * `cc70fe6` this function answered `{ convention: "fastcall", paramCount: 0 }`
 * for all **1033** detected A64 functions, and `InstructionDetail` renders that
 * string unconditionally. Both halves are false — A64 is AAPCS64, and a
 * function taking arguments in x0..x7 was reported as taking none.
 */
describe("inferSignature — architecture refusal", () => {
  const X86_BODY: [string, string][] = [
    ["mov", "rax, rcx"],
    ["mov", "rbx, rdx"],
    ["ret", ""],
  ];

  it("answers for x86, which is the liveness half of every test below", () => {
    const f = func(START, X86_BODY.length);
    expect(inferSignature(f, makeInsns(START, X86_BODY), "x86", true)).toEqual({
      convention: "fastcall",
      paramCount: 2,
    });
  });

  it("refuses ARM64 on the same instructions the x86 answer was taken from", () => {
    const f = func(START, X86_BODY.length);
    expect(inferSignature(f, makeInsns(START, X86_BODY), "arm64", true)).toBeNull();
  });

  it("refuses a machine type the engine has no grammar for", () => {
    const f = func(START, X86_BODY.length);
    expect(inferSignature(f, makeInsns(START, X86_BODY), "unsupported", true)).toBeNull();
  });

  it("refuses 32-bit callers too, so the refusal is not a property of is64", () => {
    const f = func(START, X86_BODY.length);
    expect(inferSignature(f, makeInsns(START, X86_BODY), "arm64", false)).toBeNull();
  });

  /**
   * The refusal precedes the empty-instruction early return, which used to be
   * the one path that answered without looking at a single instruction —
   * inventing `fastcall`/`cdecl` out of `is64` alone, on an A64 image included.
   *
   * **THAT ORDERING IS NO LONGER OBSERVABLE AND THE FIRST TWO ROWS BELOW ARE
   * THEREFORE INERT AS A TEST OF IT.** `peek-a-bin-j4uk.6` made the
   * empty-instruction arm answer `null` for x86 too, so both orderings now
   * produce `null` at an empty list, exactly as `stack.test.ts` records for
   * `analyzeStackFrame`. They are kept because they are still TRUE statements
   * the export must keep making, and the note is here rather than the rows
   * being deleted so the loss is on the record; the differential that still
   * discriminates the architecture refusal is the non-empty `X86_BODY` one at
   * the top of this block.
   */
  it("refuses before the no-instructions fallback invents a convention", () => {
    expect(inferSignature(func(START, 4), [], "arm64", true)).toBeNull();
    expect(inferSignature(func(START, 4), [], "unsupported", false)).toBeNull();
    // …and still answers for x86, which is what makes the two rows above about
    // the architecture. THE INSTRUCTION LIST HAD TO BECOME NON-EMPTY at
    // `peek-a-bin-j4uk.6`: the empty-instruction arm no longer invents a
    // convention for x86 either, so at an empty list every architecture now
    // answers null and the ordering is unobservable there.
    expect(
      inferSignature(func(START, X86_BODY.length), makeInsns(START, X86_BODY), "x86", true),
    ).not.toBeNull();
  });

  /**
   * The measured falsehood, stated as itself: whatever else changes, an A64
   * image must never be told it uses the Microsoft x64 calling convention.
   */
  it("never names an x86 calling convention for an ARM64 image", () => {
    const f = func(START, X86_BODY.length);
    const s = inferSignature(f, makeInsns(START, X86_BODY), "arm64", true);
    expect(s?.convention).not.toBe("fastcall");
    expect(s?.convention).not.toBe("cdecl");
    expect(s?.convention).not.toBe("thiscall");
    expect(s?.convention).not.toBe("stdcall");
  });
});
