import { describe, expect, it } from "vitest";
import {
  CRT_RECOGNISERS,
  type IdiomInsn,
  namedGlobalsFor,
  recogniseCrtIdiom,
  recogniseCrtIdioms,
  SECURITY_COOKIE_NAME,
} from "../crtIdioms";

/**
 * The recogniser is EXACT: every instruction of the routine is named, and a
 * body that differs in any way is refused. The two shapes below are the real
 * ones, read off `objdump -d -M intel` over the corpus at 6299113 —
 * t64!0x140002000 and w64!0x140002170 (hardened), t32!0x401DA4 and
 * w32!0x401EA2 (classic) — with Capstone's operand spelling as `FileSession`
 * printed it (`cmp ecx, dword ptr [0x412284]`, `rep ret` as `ret`).
 */

function ins(address: number, mnemonic: string, opStr = "", size = 4): IdiomInsn {
  return { address, mnemonic, opStr, size };
}

/** t64's `__security_check_cookie`, byte-exact addresses and sizes. */
const hardened = (): IdiomInsn[] => [
  ins(0x140002000, "cmp", "rcx, qword ptr [rip + 0x123c1]", 7), // → 0x1400143c8
  ins(0x140002007, "jne", "0x14000201a", 2),
  ins(0x140002009, "rol", "rcx, 0x10", 4),
  ins(0x14000200d, "test", "cx, 0xffff", 5),
  ins(0x140002012, "jne", "0x140002016", 2),
  ins(0x140002014, "ret", "", 2),
  ins(0x140002016, "ror", "rcx, 0x10", 4),
  ins(0x14000201a, "jmp", "0x140004290", 5),
];

/** t32's, with the trampoline into `__report_gsfailure` inside the extent. */
const classic = (): IdiomInsn[] => [
  ins(0x401da4, "cmp", "ecx, dword ptr [0x412284]", 6),
  ins(0x401daa, "jne", "0x401dae", 2),
  ins(0x401dac, "ret", "", 2),
  ins(0x401dae, "jmp", "0x403bf3", 5),
];

describe("recogniseCrtIdiom — __security_check_cookie, hardened x64 shape", () => {
  it("accepts the real t64 body and recovers the cookie's address through the RIP grammar", () => {
    const idiom = recogniseCrtIdiom(hardened(), true);
    expect(idiom).toEqual({
      kind: "security-check-cookie",
      name: "__security_check_cookie",
      preservesResult: true,
      cookieAddress: 0x1400143c8,
      args: ["rcx"],
    });
  });

  it("accepts a `rep ret` spelled with its prefix", () => {
    const body = hardened();
    body[5] = { ...body[5], mnemonic: "rep ret" };
    expect(recogniseCrtIdiom(body, true)?.cookieAddress).toBe(0x1400143c8);
  });

  it("ignores trailing int3/nop alignment padding, which is not the routine", () => {
    const body = [...hardened(), ins(0x14000201f, "int3", "", 1), ins(0x140002020, "nop", "", 1)];
    expect(recogniseCrtIdiom(body, true)).not.toBeNull();
  });

  it("refuses the body when the width is wrong for the image", () => {
    // `cmp rcx, …` in a 32-bit image is not this routine.
    expect(recogniseCrtIdiom(hardened(), false)).toBeNull();
  });

  it("refuses a jne that does not land on the failure trampoline", () => {
    const body = hardened();
    body[1] = { ...body[1], opStr: "0x140002016" };
    expect(recogniseCrtIdiom(body, true)).toBeNull();
  });

  it("refuses a second jne that does not land on the ror", () => {
    const body = hardened();
    body[4] = { ...body[4], opStr: "0x14000201a" };
    expect(recogniseCrtIdiom(body, true)).toBeNull();
  });

  it("refuses a rotate by any other amount, or the rotates swapped", () => {
    const byEight = hardened();
    byEight[2] = { ...byEight[2], opStr: "rcx, 8" };
    expect(recogniseCrtIdiom(byEight, true)).toBeNull();
    const swapped = hardened();
    swapped[2] = { ...swapped[2], mnemonic: "ror" };
    expect(recogniseCrtIdiom(swapped, true)).toBeNull();
  });
});

describe("recogniseCrtIdiom — __security_check_cookie, classic x86 shape", () => {
  it("accepts the real t32 body with an absolute cookie operand", () => {
    expect(recogniseCrtIdiom(classic(), false)).toEqual({
      kind: "security-check-cookie",
      name: "__security_check_cookie",
      preservesResult: true,
      cookieAddress: 0x412284,
      args: ["ecx"],
    });
  });

  it("accepts the three-instruction form when detection ended the routine at its ret", () => {
    // The jne then leaves the body entirely — that is what makes it the
    // failure path rather than a branch within the routine.
    expect(recogniseCrtIdiom(classic().slice(0, 3), false)?.cookieAddress).toBe(0x412284);
  });

  it("refuses the three-instruction form when the jne lands inside the body", () => {
    const body = classic().slice(0, 3);
    body[1] = { ...body[1], opStr: "0x401dac" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("accepts the same shape at 64-bit width with a RIP-relative operand", () => {
    // Older x64 CRTs emit the classic shape; the operand grammar is the same.
    const body: IdiomInsn[] = [
      ins(0x140002000, "cmp", "rcx, qword ptr [rip + 0x123c1]", 7),
      ins(0x140002007, "jne", "0x14000200b", 2),
      ins(0x140002009, "ret", "", 2),
      ins(0x14000200b, "jmp", "0x140004290", 5),
    ];
    expect(recogniseCrtIdiom(body, true)?.cookieAddress).toBe(0x1400143c8);
  });
});

describe("recogniseCrtIdiom — the refusals the bead names", () => {
  it("refuses an extra instruction anywhere in the body", () => {
    const front = [ins(0x401da0, "mov", "eax, ecx"), ...classic()];
    expect(recogniseCrtIdiom(front, false)).toBeNull();
    const middle = classic();
    middle.splice(2, 0, ins(0x401dab, "nop", "", 1));
    expect(recogniseCrtIdiom(middle, false)).toBeNull();
  });

  it("refuses a compare against a register", () => {
    const body = classic();
    body[0] = { ...body[0], opStr: "ecx, edx" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("refuses a compare against an immediate, which the grammar reads as `direct`", () => {
    const body = classic();
    body[0] = { ...body[0], opStr: "ecx, 0x412284" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("refuses a compare against a based memory operand", () => {
    const body = classic();
    body[0] = { ...body[0], opStr: "ecx, dword ptr [ebp + 8]" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("refuses a compare of the wrong register", () => {
    const body = classic();
    body[0] = { ...body[0], opStr: "eax, dword ptr [0x412284]" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("refuses a `je`", () => {
    const body = classic();
    body[1] = { ...body[1], mnemonic: "je" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("refuses a body that writes the accumulator", () => {
    // The whole point of `preservesResult`: a routine that does this defines
    // EAX and its call must keep its resultDest.
    const body = classic();
    body.splice(2, 0, ins(0x401dac, "xor", "eax, eax", 2));
    expect(recogniseCrtIdiom(body, false)).toBeNull();
    const asRet = classic().slice(0, 3);
    asRet[2] = ins(0x401dac, "mov", "eax, 1", 5);
    expect(recogniseCrtIdiom(asRet, false)).toBeNull();
  });

  it("refuses an empty body and an ordinary small function", () => {
    expect(recogniseCrtIdiom([], false)).toBeNull();
    expect(recogniseCrtIdiom([ins(0x401000, "xor", "eax, eax"), ins(0x401004, "ret")], false)).toBe(
      null,
    );
  });

  it("refuses a jmp with no direct target as the trampoline", () => {
    const body = classic();
    body[3] = { ...body[3], opStr: "eax" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });
});

describe("recogniseCrtIdioms — the whole-image pass", () => {
  it("keys each recognised routine on its entry and skips everything else", () => {
    const funcInsnMap = new Map<number, IdiomInsn[]>([
      [0x401000, [ins(0x401000, "push", "ebp"), ins(0x401004, "ret")]],
      [0x401da4, classic()],
      [0x402000, Array.from({ length: 80 }, (_, i) => ins(0x402000 + i * 4, "nop"))],
    ]);
    const idioms = recogniseCrtIdioms(funcInsnMap, false);
    expect([...idioms.keys()]).toEqual([0x401da4]);
    expect(idioms.get(0x401da4)?.name).toBe("__security_check_cookie");
  });

  it("is empty over an image with no such routine", () => {
    expect(recogniseCrtIdioms(new Map([[0x401000, [ins(0x401000, "ret")]]]), true).size).toBe(0);
  });
});

describe("namedGlobalsFor — the cookie as a named global", () => {
  it("names the cookie at the recovered address, pointer-wide", () => {
    const idioms = recogniseCrtIdioms(new Map([[0x140002000, hardened()]]), true);
    const globals = namedGlobalsFor(idioms, true);
    expect(globals.get(0x1400143c8)).toEqual({
      name: SECURITY_COOKIE_NAME,
      type: "uintptr_t",
      size: 8,
    });
  });

  it("is four bytes wide on x86", () => {
    const idioms = recogniseCrtIdioms(new Map([[0x401da4, classic()]]), false);
    expect(namedGlobalsFor(idioms, false).get(0x412284)?.size).toBe(4);
  });

  it("is empty with no idioms, so the emitter spells every address raw", () => {
    expect(namedGlobalsFor(undefined, true).size).toBe(0);
    expect(namedGlobalsFor(new Map(), true).size).toBe(0);
  });
});

describe("CRT_RECOGNISERS — the table a second routine is added to", () => {
  it("holds one entry today, and every entry refuses an empty body", () => {
    expect(CRT_RECOGNISERS).toHaveLength(1);
    for (const recognise of CRT_RECOGNISERS) {
      expect(recognise([], true)).toBeNull();
      expect(recognise([], false)).toBeNull();
    }
  });
});
