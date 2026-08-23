import { describe, expect, it } from "vitest";
import { inferSignature } from "../signatures";
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

  describe("stack parameters", () => {
    it("reads [rsp+0x28] as the fifth parameter", () => {
      // 0x00–0x20 is the x64 shadow space + return address; 0x28 is arg 5.
      expect(
        sig64([
          ["mov", "rax, qword ptr [rsp + 0x28]"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(5);
    });

    it("reads [rsp+0x30] as the sixth parameter", () => {
      expect(
        sig64([
          ["mov", "rax, qword ptr [rsp + 0x30]"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(6);
    });

    it("ignores accesses inside the shadow space", () => {
      expect(
        sig64([
          ["mov", "qword ptr [rsp + 0x20], rax"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("takes the deepest stack access", () => {
      const s = sig64([
        ["mov", "rax, qword ptr [rsp + 0x38]"],
        ["mov", "rbx, qword ptr [rsp + 0x28]"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(7);
    });

    it("combines register and stack parameters by taking the max", () => {
      const s = sig64([
        ["mov", "rax, rcx"],
        ["mov", "rbx, qword ptr [rsp + 0x28]"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(5);
    });
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

  it("returns a zero-parameter fastcall for a function with no instructions", () => {
    expect(inferSignature(func(START, 4), [], "x86", true)).toEqual({
      convention: "fastcall",
      paramCount: 0,
    });
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
  it("defaults to cdecl with no parameters", () => {
    expect(
      sig32([
        ["xor", "eax, eax"],
        ["ret", ""],
      ]),
    ).toEqual({ convention: "cdecl", paramCount: 0 });
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

    it("leaves `ret 0x0` as cdecl", () => {
      expect(sig32([["ret", "0x0"]]).convention).toBe("cdecl");
    });

    it("leaves a bare ret as cdecl", () => {
      expect(sig32([["ret", ""]]).convention).toBe("cdecl");
    });

    it("ignores a `ret N` that is not the last instruction of the function", () => {
      // Early-out returns are common; only the final instruction is inspected.
      expect(
        sig32([
          ["ret", "0x8"],
          ["xor", "eax, eax"],
          ["ret", ""],
        ]).convention,
      ).toBe("cdecl");
    });
  });

  describe("ebp-relative parameter counting", () => {
    it("counts [ebp+0x8] as one parameter", () => {
      expect(
        sig32([
          ["mov", "eax, dword ptr [ebp + 0x8]"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(1);
    });

    it("counts [ebp+0x10] as three parameters", () => {
      expect(
        sig32([
          ["mov", "eax, dword ptr [ebp + 0x10]"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(3);
    });

    it("takes the deepest offset, not the number of accesses", () => {
      const s = sig32([
        ["mov", "eax, dword ptr [ebp + 0xc]"],
        ["mov", "ebx, dword ptr [ebp + 0x8]"],
        ["ret", ""],
      ]);
      expect(s.paramCount).toBe(2);
    });

    it("ignores negative offsets (locals)", () => {
      expect(
        sig32([
          ["mov", "dword ptr [ebp - 0x8], eax"],
          ["ret", ""],
        ]).paramCount,
      ).toBe(0);
    });

    it("scans the whole function, not just the prologue", () => {
      const s = sig32([...Array(30).fill(nop), ["mov", "eax, dword ptr [ebp + 0x8]"], ["ret", ""]]);
      expect(s.paramCount).toBe(1);
    });

    it("lets `ret N` win over the ebp scan", () => {
      const s = sig32([
        ["mov", "eax, dword ptr [ebp + 0x10]"],
        ["ret", "0x8"],
      ]);
      expect(s).toEqual({ convention: "stdcall", paramCount: 2 });
    });
  });

  describe("thiscall detection", () => {
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

    it("does not report thiscall for the `xor ecx, ecx` zeroing idiom", () => {
      const s = sig32([
        ["xor", "ecx, ecx"],
        ["mov", "eax, dword ptr [ecx]"],
        ["ret", ""],
      ]);
      expect(s.convention).toBe("cdecl");
    });

    it("does not report thiscall when ecx is written first", () => {
      const s = sig32([
        ["mov", "ecx, 0x5"],
        ["mov", "eax, dword ptr [ecx]"],
        ["ret", ""],
      ]);
      expect(s.convention).toBe("cdecl");
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
      const late = sig32([...Array(10).fill(nop), ["mov", "eax, dword ptr [ecx]"], ["ret", ""]]);
      expect(late.convention).toBe("cdecl");
    });

    it("combines thiscall with ebp-relative parameters", () => {
      const s = sig32([
        ["mov", "eax, dword ptr [ecx + 0x4]"],
        ["mov", "ebx, dword ptr [ebp + 0x8]"],
        ["ret", ""],
      ]);
      expect(s).toEqual({ convention: "thiscall", paramCount: 1 });
    });
  });

  it("returns a zero-parameter cdecl for a function with no instructions", () => {
    expect(inferSignature(func(START, 4), [], "x86", false)).toEqual({
      convention: "cdecl",
      paramCount: 0,
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
   * The refusal has to precede the empty-instruction early return, or a
   * function whose instructions are not in the array still gets a convention
   * invented for it from `is64` alone. That early return is the one path that
   * answers without looking at a single instruction, so it is the one that
   * would keep claiming `fastcall` on an A64 image.
   */
  it("refuses before the no-instructions fallback invents a convention", () => {
    expect(inferSignature(func(START, 4), [], "arm64", true)).toBeNull();
    expect(inferSignature(func(START, 4), [], "unsupported", false)).toBeNull();
    // …and still answers there for x86, so the assertion above is about the
    // architecture and not about the empty array.
    expect(inferSignature(func(START, 4), [], "x86", true)).not.toBeNull();
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
