import { describe, expect, it } from "vitest";
import {
  CRT_RECOGNISERS,
  type CrtIdiom,
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

/** The cookie address a match publishes — only the cookie check has one. */
const cookieOf = (idiom: CrtIdiom | null | undefined): number | undefined =>
  idiom?.kind === "security-check-cookie" ? idiom.cookieAddress : undefined;

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
    expect(cookieOf(recogniseCrtIdiom(body, true))).toBe(0x1400143c8);
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
    expect(cookieOf(recogniseCrtIdiom(classic().slice(0, 3), false))).toBe(0x412284);
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
    expect(cookieOf(recogniseCrtIdiom(body, true))).toBe(0x1400143c8);
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

describe("CRT_RECOGNISERS — the table a new routine is added to", () => {
  it("holds three entries today, and every entry refuses an empty body", () => {
    expect(CRT_RECOGNISERS).toHaveLength(3);
    for (const recognise of CRT_RECOGNISERS) {
      expect(recognise([], true)).toBeNull();
      expect(recognise([], false)).toBeNull();
    }
  });
});

/**
 * `__SEH_epilog4`, transcribed from `t32!0x4041B5` at 21fbfa3 through Capstone
 * (`w32!0x404415` is byte-identical). Real addresses and sizes: 20 bytes.
 */
const EPILOG4 = 0x4041b5;
const epilog4 = (): IdiomInsn[] => [
  ins(EPILOG4, "mov", "ecx, dword ptr [ebp - 0x10]", 3),
  ins(EPILOG4 + 3, "mov", "dword ptr fs:[0], ecx", 7),
  ins(EPILOG4 + 10, "pop", "ecx", 1),
  ins(EPILOG4 + 11, "pop", "edi", 1),
  ins(EPILOG4 + 12, "pop", "edi", 1),
  ins(EPILOG4 + 13, "pop", "esi", 1),
  ins(EPILOG4 + 14, "pop", "ebx", 1),
  ins(EPILOG4 + 15, "mov", "esp, ebp", 2),
  ins(EPILOG4 + 17, "pop", "ebp", 1),
  ins(EPILOG4 + 18, "push", "ecx", 1),
  ins(EPILOG4 + 19, "ret", "", 1),
];

/** `__SEH_prolog4`, `t32!0x404170` at 21fbfa3: 21 instructions, 69 bytes. */
const PROLOG4 = 0x404170;
const prolog4 = (): IdiomInsn[] => {
  const rows: [string, string, number][] = [
    ["push", "0x4041d0", 5],
    ["push", "dword ptr fs:[0]", 7],
    ["mov", "eax, dword ptr [esp + 0x10]", 4],
    ["mov", "dword ptr [esp + 0x10], ebp", 4],
    ["lea", "ebp, [esp + 0x10]", 4],
    ["sub", "esp, eax", 2],
    ["push", "ebx", 1],
    ["push", "esi", 1],
    ["push", "edi", 1],
    ["mov", "eax, dword ptr [0x412284]", 5],
    ["xor", "dword ptr [ebp - 4], eax", 3],
    ["xor", "eax, ebp", 2],
    ["push", "eax", 1],
    ["mov", "dword ptr [ebp - 0x18], esp", 3],
    ["push", "dword ptr [ebp - 8]", 3],
    ["mov", "eax, dword ptr [ebp - 4]", 3],
    ["mov", "dword ptr [ebp - 4], 0xfffffffe", 7],
    ["mov", "dword ptr [ebp - 8], eax", 3],
    ["lea", "eax, [ebp - 0x10]", 3],
    ["mov", "dword ptr fs:[0], eax", 6],
    ["ret", "", 1],
  ];
  let at = PROLOG4;
  return rows.map(([mn, ops, size]) => {
    const i = ins(at, mn, ops, size);
    at += size;
    return i;
  });
};

describe("recogniseCrtIdiom — __SEH_epilog4, exact body", () => {
  it("accepts the real t32/w32 body and publishes a result-preserving, argument-less routine", () => {
    expect(recogniseCrtIdiom(epilog4(), false)).toEqual({
      kind: "seh-epilog4",
      name: "__SEH_epilog4",
      preservesResult: true,
      args: [],
    });
  });

  it("ignores w32's seven bytes of int3 padding after the ret", () => {
    const body = epilog4();
    for (let k = 0; k < 7; k++) body.push(ins(EPILOG4 + 20 + k, "int3", "", 1));
    expect(recogniseCrtIdiom(body, false)?.name).toBe("__SEH_epilog4");
  });

  it("is case- and whitespace-insensitive over the operand text, and nothing else", () => {
    const body = epilog4();
    body[0] = { ...body[0], opStr: "ECX,  dword ptr [EBP - 0x10]" };
    expect(recogniseCrtIdiom(body, false)?.name).toBe("__SEH_epilog4");
    body[0] = { ...body[0], opStr: "ecx, dword ptr [ebp - 0xc]" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("refuses the body on a 64-bit image", () => {
    expect(recogniseCrtIdiom(epilog4(), true)).toBeNull();
  });

  it("refuses an extra instruction anywhere inside the body, including a harmless one", () => {
    // Inside the body only: one AFTER the `ret` is alignment padding and is
    // stripped, as the row above pins.
    for (let at = 0; at < 11; at++) {
      const body = epilog4();
      body.splice(at, 0, ins(0x500000, "nop", "", 1));
      expect(recogniseCrtIdiom(body, false), `extra at ${at}`).toBeNull();
    }
  });

  it("refuses a missing instruction", () => {
    for (let at = 0; at < 11; at++) {
      const body = epilog4();
      body.splice(at, 1);
      expect(recogniseCrtIdiom(body, false), `missing ${at}`).toBeNull();
    }
  });

  it("refuses a body that writes the accumulator — the bead's control", () => {
    const body = epilog4();
    body.splice(7, 0, ins(0x500000, "mov", "eax, 0", 5));
    expect(recogniseCrtIdiom(body, false)).toBeNull();
    // And with the count preserved: swapping a pop for a write of EAX.
    const swapped = epilog4();
    swapped[4] = { ...swapped[4], mnemonic: "mov", opStr: "eax, edi" };
    expect(recogniseCrtIdiom(swapped, false)).toBeNull();
  });

  it("refuses a body with a call inside it", () => {
    const body = epilog4();
    body[7] = { ...body[7], mnemonic: "call", opStr: "0x401000" };
    expect(recogniseCrtIdiom(body, false)).toBeNull();
  });

  it("refuses a different frame slot, the wrong register popped, and a `retn 4`", () => {
    const slot = epilog4();
    slot[0] = { ...slot[0], opStr: "ecx, dword ptr [ebp - 0x14]" };
    expect(recogniseCrtIdiom(slot, false)).toBeNull();
    const reg = epilog4();
    reg[6] = { ...reg[6], opStr: "ebp" };
    expect(recogniseCrtIdiom(reg, false)).toBeNull();
    const ret = epilog4();
    ret[10] = { ...ret[10], opStr: "4" };
    expect(recogniseCrtIdiom(ret, false)).toBeNull();
  });
});

describe("recogniseCrtIdiom — __SEH_prolog4, name only", () => {
  it("accepts the real t32 body and publishes NO signature and preservesResult false", () => {
    const idiom = recogniseCrtIdiom(prolog4(), false);
    expect(idiom).toEqual({ kind: "seh-prolog4", name: "__SEH_prolog4", preservesResult: false });
    expect(idiom?.args).toBeUndefined();
  });

  it("accepts w32's body, which differs only in the handler and cookie addresses", () => {
    const body = prolog4();
    body[0] = { ...body[0], opStr: "0x404430" };
    body[9] = { ...body[9], opStr: "eax, dword ptr [0x410284]" };
    expect(recogniseCrtIdiom(body, false)?.name).toBe("__SEH_prolog4");
  });

  it("refuses a pushed register or a based cookie load in the two variable rows", () => {
    const push = prolog4();
    push[0] = { ...push[0], opStr: "eax" };
    expect(recogniseCrtIdiom(push, false)).toBeNull();
    const load = prolog4();
    load[9] = { ...load[9], opStr: "eax, dword ptr [ebx + 4]" };
    expect(recogniseCrtIdiom(load, false)).toBeNull();
  });

  it("refuses an extra or a missing instruction, and the body on x64", () => {
    const extra = prolog4();
    extra.splice(12, 0, ins(0x500000, "nop", "", 1));
    expect(recogniseCrtIdiom(extra, false)).toBeNull();
    const missing = prolog4();
    missing.splice(12, 1);
    expect(recogniseCrtIdiom(missing, false)).toBeNull();
    expect(recogniseCrtIdiom(prolog4(), true)).toBeNull();
  });

  it("publishes no named global — the cookie load inside it is not what this template is for", () => {
    const idioms = new Map([[PROLOG4, recogniseCrtIdiom(prolog4(), false) as CrtIdiom]]);
    expect(namedGlobalsFor(idioms, false).size).toBe(0);
  });
});

describe("recogniseCrtIdioms — both EH4 helpers in one image", () => {
  it("names each at its entry and leaves the cookie check's answer alone", () => {
    const out = recogniseCrtIdioms(
      new Map<number, IdiomInsn[]>([
        [PROLOG4, prolog4()],
        [EPILOG4, epilog4()],
        [0x401da4, classic()],
        [0x401000, [ins(0x401000, "push", "ebp", 1), ins(0x401001, "ret", "", 1)]],
      ]),
      false,
    );
    expect([...out.keys()].sort()).toEqual([0x401da4, PROLOG4, EPILOG4].sort());
    expect(out.get(EPILOG4)?.preservesResult).toBe(true);
    expect(out.get(PROLOG4)?.preservesResult).toBe(false);
    expect(cookieOf(out.get(0x401da4))).toBe(0x412284);
  });
});
