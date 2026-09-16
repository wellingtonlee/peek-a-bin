import { describe, expect, it } from "vitest";
import { type PfnInsn, type PfnRefusalReason, recognisePfnGlobals } from "../pfnGlobals";

/**
 * The recogniser is straight-line and refuses by default: every shape below
 * is read off `objdump -d -M intel` over the corpus at b613025 — the x64 one
 * from `t64!sub_14000D3C8` (0x14000d41f–0x14000d452, `MessageBoxW` through
 * `EncodePointer` into 0x1400163d0, with the NEXT lookup's `lea rdx` and `mov
 * rcx, rsi` interleaved before the store), the x86 one from `w32!sub_401000`
 * (0x40101e–0x40102a, `MessageBoxTimeoutA` into 0x4125f8, unencoded) — with
 * Capstone's operand spelling. Each refusal has its own fixture, and the two
 * the brief names as negative controls (drop the second-store refusal, drop the
 * string check) are the `other-store` and `string-unknown` cases.
 */

function ins(address: number, mnemonic: string, opStr = "", size = 4): PfnInsn {
  return { address, mnemonic, opStr, size };
}

/** Sequential instructions from `start`, each `size` bytes unless given. */
function seq(start: number, rows: [string, string?, number?][]): PfnInsn[] {
  let addr = start;
  return rows.map(([mnemonic, opStr, size]) => {
    const i = ins(addr, mnemonic, opStr ?? "", size ?? 4);
    addr += i.size;
    return i;
  });
}

// ── x64 ─────────────────────────────────────────────────────────────────────

const GPA64 = 0x1400101d0;
const ENC64 = 0x140010130;
const STR_MB = 0x140011ca0;
const STR_GAW = 0x140011c90;
const G64 = 0x1400163d0;
const iat64 = new Map([
  [GPA64, { lib: "KERNEL32.dll", func: "GetProcAddress" }],
  [ENC64, { lib: "KERNEL32.dll", func: "EncodePointer" }],
  [0x140010260, { lib: "KERNEL32.dll", func: "LoadLibraryW" }],
]);
const strings64 = new Map([
  [STR_MB, "MessageBoxW"],
  [STR_GAW, "GetActiveWindow"],
]);

/**
 * `t64!0x14000d41f..0x14000d452`, byte-exact. RIP displacements are relative
 * to the next instruction, so each row's size matters.
 */
const witness64 = (): PfnInsn[] => [
  ins(0x14000d41f, "lea", "rdx, [rip + 0x487a]", 7), // → STR_MB
  ins(0x14000d426, "mov", "rcx, rax", 3),
  ins(0x14000d429, "call", "qword ptr [rip + 0x2da1]", 6), // → GPA64
  ins(0x14000d42f, "test", "rax, rax", 3),
  ins(0x14000d432, "je", "0x14000d5b2", 6),
  ins(0x14000d438, "mov", "rcx, rax", 3),
  ins(0x14000d43b, "call", "qword ptr [rip + 0x2cef]", 6), // → ENC64
  ins(0x14000d441, "lea", "rdx, [rip + 0x4848]", 7), // → STR_GAW, the NEXT lookup's
  ins(0x14000d448, "mov", "rcx, rsi", 3),
  ins(0x14000d44b, "mov", "qword ptr [rip + 0x8f7e], rax", 7), // → G64
  ins(0x14000d452, "ret", "", 1),
];

function run64(insns: PfnInsn[], extra?: Partial<Parameters<typeof recognisePfnGlobals>[0]>) {
  return recognisePfnGlobals({
    instructions: insns,
    funcExtents: [{ address: insns[0].address, size: 0x200 }],
    iatMap: iat64,
    stringMap: strings64,
    is64: true,
    ...extra,
  });
}

function reasons(r: ReturnType<typeof recognisePfnGlobals>): PfnRefusalReason[] {
  return r.refusals.map((x) => x.reason);
}

describe("recognisePfnGlobals — x64 lea/call/EncodePointer/store", () => {
  it("names the slot after the string, marks it encoded, and attributes the string to ITS lookup", () => {
    const r = run64(witness64());
    expect(r.lookups).toBe(1);
    expect(r.refusals).toEqual([]);
    expect([...r.globals]).toEqual([
      [G64, { name: "pfn_MessageBoxW", proc: "MessageBoxW", encoded: true }],
    ]);
  });

  it("names an unencoded store, and reads a `lea` interleaved before the store as the next lookup's", () => {
    // w64!sub_140001000's shape: lea rdx / mov rcx, rbx / call / mov [G], rax.
    const insns = seq(0x140001074, [
      ["lea", "rdx, [rip + 0xfd3d]", 7], // → 0x140010db8
      ["mov", "rcx, rbx", 3],
      ["call", "qword ptr [rip + 0xe014]", 6], // → 0x14000f098
      ["mov", "qword ptr [rip + 0x14e2d], rax", 7], // → 0x140015eb8
      ["ret", "", 1],
    ]);
    const r = recognisePfnGlobals({
      instructions: insns,
      funcExtents: [{ address: 0x140001074, size: 0x40 }],
      iatMap: new Map([[0x14000f098, { lib: "KERNEL32.dll", func: "GetProcAddress" }]]),
      stringMap: new Map([[0x140010db8, "MessageBoxTimeoutW"]]),
      is64: true,
    });
    expect([...r.globals]).toEqual([
      [0x140015eb8, { name: "pfn_MessageBoxTimeoutW", proc: "MessageBoxTimeoutW", encoded: false }],
    ]);
  });

  it("reaches GetProcAddress through a `jmp [slot]` thunk, the /INCREMENTAL shape", () => {
    const body = witness64();
    // `call 0x14000e000` → a thunk `jmp qword ptr [rip + d]` landing on GPA64.
    body[2] = ins(0x14000d429, "call", "0x14000e000", 6);
    const thunk = ins(
      0x14000e000,
      "jmp",
      `qword ptr [rip + 0x${(GPA64 - 0x14000e006).toString(16)}]`,
      6,
    );
    const r = run64([...body, thunk], {
      funcExtents: [
        { address: 0x14000d41f, size: 0x40 },
        { address: 0x14000e000, size: 6 },
      ],
    });
    expect(r.globals.get(G64)?.name).toBe("pfn_MessageBoxW");
  });

  it("REFUSES a slot any other instruction in the image writes (other-store)", () => {
    // NEGATIVE CONTROL for the second-store refusal: with it dropped, this
    // fixture names a global two writers disagree on.
    const other = ins(0x14000e000, "mov", "qword ptr [rip + 0x83c9], rcx", 7); // → G64
    const r = run64([...witness64(), other]);
    expect(r.globals.size).toBe(0);
    expect(r.refusals).toEqual([
      { reason: "other-store", at: 0x14000d429, global: G64, proc: "MessageBoxW" },
    ]);
  });

  it("counts a read-modify-write and a locked RMW of the slot as writers, but not a compare", () => {
    const and = ins(0x14000e000, "and", "qword ptr [rip + 0x83c9], 0", 7);
    expect(reasons(run64([...witness64(), and]))).toEqual(["other-store"]);
    const locked = ins(0x14000e000, "lock inc", "qword ptr [rip + 0x83c9]", 7);
    expect(reasons(run64([...witness64(), locked]))).toEqual(["other-store"]);
    // t64!0x14000d3f6: `cmp qword ptr [rip + …], rbx` against the same slot.
    const cmp = ins(0x14000e000, "cmp", "qword ptr [rip + 0x83c9], rbx", 7);
    expect(run64([...witness64(), cmp]).globals.get(G64)?.name).toBe("pfn_MessageBoxW");
  });

  it("REFUSES a slot two lookups store under different strings (disagree)", () => {
    const second = witness64().map((i) => ({ ...i, address: i.address + 0x1000 }));
    // Same displacements at +0x1000 would point 0x1000 past the originals, so
    // aim the second shape's lea at GetActiveWindow and its store back at G64.
    second[0] = ins(
      second[0].address,
      "lea",
      `rdx, [rip + 0x${(STR_GAW - (second[0].address + 7)).toString(16)}]`,
      7,
    );
    second[2] = ins(
      second[2].address,
      "call",
      `qword ptr [rip + 0x${(GPA64 - (second[2].address + 6)).toString(16)}]`,
      6,
    );
    second[6] = ins(
      second[6].address,
      "call",
      `qword ptr [rip + 0x${(ENC64 - (second[6].address + 6)).toString(16)}]`,
      6,
    );
    second[9] = ins(
      second[9].address,
      "mov",
      `qword ptr [rip + 0x${(G64 - (second[9].address + 7)).toString(16)}], rax`,
      7,
    );
    const r = run64([...witness64(), ...second], {
      funcExtents: [
        { address: 0x14000d41f, size: 0x40 },
        { address: 0x14000e41f, size: 0x40 },
      ],
    });
    expect(r.globals.size).toBe(0);
    expect(reasons(r)).toEqual(["disagree", "disagree"]);
  });

  it("agrees when two lookups store the same string the same way", () => {
    const second = witness64().map((i) => ({ ...i, address: i.address + 0x1000 }));
    second[0] = ins(
      second[0].address,
      "lea",
      `rdx, [rip + 0x${(STR_MB - (second[0].address + 7)).toString(16)}]`,
      7,
    );
    second[2] = ins(
      second[2].address,
      "call",
      `qword ptr [rip + 0x${(GPA64 - (second[2].address + 6)).toString(16)}]`,
      6,
    );
    second[6] = ins(
      second[6].address,
      "call",
      `qword ptr [rip + 0x${(ENC64 - (second[6].address + 6)).toString(16)}]`,
      6,
    );
    second[9] = ins(
      second[9].address,
      "mov",
      `qword ptr [rip + 0x${(G64 - (second[9].address + 7)).toString(16)}], rax`,
      7,
    );
    const r = run64([...witness64(), ...second], {
      funcExtents: [
        { address: 0x14000d41f, size: 0x40 },
        { address: 0x14000e41f, size: 0x40 },
      ],
    });
    expect(r.globals.get(G64)?.name).toBe("pfn_MessageBoxW");
    expect(r.refusals).toEqual([]);
  });

  it("REFUSES a string address the string map does not hold (string-unknown)", () => {
    // NEGATIVE CONTROL for the string check: with it dropped, this unnamed
    // shape gets a name read from nowhere.
    const r = run64(witness64(), { stringMap: new Map([[STR_GAW, "GetActiveWindow"]]) });
    expect(r.globals.size).toBe(0);
    expect(r.refusals).toEqual([{ reason: "string-unknown", at: 0x14000d429 }]);
  });

  it("REFUSES a name argument that is not a string address (no-string-operand)", () => {
    // An ordinal: `mov edx, 0x10` in place of the lea.
    const body = witness64();
    body[0] = ins(0x14000d41f, "mov", "edx, 0x10", 7);
    expect(run64(body).refusals).toEqual([{ reason: "no-string-operand", at: 0x14000d429 }]);
    // RDX overwritten between the lea and the call.
    const clobbered = witness64();
    clobbered[1] = ins(0x14000d426, "mov", "rdx, rcx", 3);
    expect(reasons(run64(clobbered))).toEqual(["no-string-operand"]);
  });

  it("REFUSES a string that cannot follow `pfn_` in an identifier (unencodable-name)", () => {
    const r = run64(witness64(), { stringMap: new Map([[STR_MB, "Message Box W"]]) });
    expect(r.refusals).toEqual([
      { reason: "unencodable-name", at: 0x14000d429, proc: "Message Box W" },
    ]);
  });

  it("REFUSES when every register holding the result is overwritten before the store (result-redefined)", () => {
    const body = witness64();
    body[5] = ins(0x14000d438, "mov", "rax, rcx", 3); // the only holder, redefined
    const r = run64(body);
    expect(r.globals.size).toBe(0);
    expect(reasons(r)).toEqual(["result-redefined"]);
  });

  it("follows the result through a copy: the store may be of the copy", () => {
    const body = witness64();
    body[5] = ins(0x14000d438, "mov", "rcx, rax", 3);
    body[6] = ins(0x14000d43b, "mov", "rax, rbx", 6); // RAX gone, RCX still holds it
    body[8] = ins(0x14000d448, "mov", "r8, rsi", 3); // (not RCX — that would redefine the copy)
    body[9] = ins(0x14000d44b, "mov", "qword ptr [rip + 0x8f7e], rcx", 7);
    expect(run64(body).globals.get(G64)?.name).toBe("pfn_MessageBoxW");
  });

  it("REFUSES a call other than EncodePointer between the lookup and the store (intervening-call)", () => {
    const body = witness64();
    body[6] = ins(0x14000d43b, "call", "qword ptr [rip + 0x2e1f]", 6); // → LoadLibraryW
    expect(reasons(run64(body))).toEqual(["intervening-call"]);
    const local = witness64();
    local[6] = ins(0x14000d43b, "call", "0x140002000", 6);
    expect(reasons(run64(local))).toEqual(["intervening-call"]);
  });

  it("REFUSES EncodePointer called with something other than the result (encode-arg)", () => {
    const body = witness64();
    body[5] = ins(0x14000d438, "mov", "rcx, rsi", 3);
    expect(reasons(run64(body))).toEqual(["encode-arg"]);
  });

  it("REFUSES a window another path enters — a branch target inside it (joined)", () => {
    // A `jmp` elsewhere in the image lands on the store.
    const jmp = ins(0x14000e000, "jmp", "0x14000d44b", 5);
    expect(reasons(run64([...witness64(), jmp]))).toEqual(["joined"]);
    // A function start inside the window is the same fact.
    const r = run64(witness64(), {
      funcExtents: [
        { address: 0x14000d41f, size: 0x19 },
        { address: 0x14000d438, size: 0x1b },
      ],
    });
    expect(reasons(r)).toEqual(["joined"]);
  });

  it("REFUSES a lookup whose result is never stored — t64!sub_1400068DC's CorExitProcess (no-store)", () => {
    const insns = seq(0x1400068f6, [
      ["lea", "rdx, [rip + 0x9ed3]", 7], // → 0x1400107d0
      ["mov", "rcx, rax", 3],
      ["call", "qword ptr [rip + 0x98ca]", 6], // → GPA64
      ["test", "rax, rax", 3],
      ["je", "0x14000690f", 2],
      ["mov", "ecx, ebx", 2],
      ["call", "rax", 2],
      ["add", "rsp, 0x20", 4],
      ["pop", "rbx", 1],
      ["ret", "", 1],
    ]);
    const r = run64(insns, { stringMap: new Map([[0x1400107d0, "CorExitProcess"]]) });
    expect(r.lookups).toBe(1);
    expect(r.globals.size).toBe(0);
    expect(reasons(r)).toEqual(["intervening-call"]);
  });

  it("ends the window at a `jmp` or a `ret` (no-store)", () => {
    const body = witness64();
    body[9] = ins(0x14000d44b, "jmp", "0x14000d5b2", 7);
    expect(reasons(run64(body))).toEqual(["no-store"]);
  });

  it("a store of some OTHER register in the window is not the shape's store, and does not end it", () => {
    const body = witness64();
    body.splice(8, 0, ins(0x14000d448, "mov", "qword ptr [rip + 0x9000], rbx", 7));
    body[9] = ins(0x14000d44f, "mov", "rcx, rsi", 3);
    body[10] = ins(0x14000d452, "mov", "qword ptr [rip + 0x8f77], rax", 7); // → G64
    body[11] = ins(0x14000d459, "ret", "", 1);
    expect(run64(body).globals.get(G64)?.name).toBe("pfn_MessageBoxW");
  });

  it("does not count a store elsewhere in the image to a NEIGHBOURING address", () => {
    // w64!0x140008278: `and dword ptr [rip + …], 0` on 0x140015ec0, beside 0x140015eb8.
    const neighbour = ins(0x14000e000, "and", "dword ptr [rip + 0x83d1], 0", 7); // → G64 + 8
    expect(run64([...witness64(), neighbour]).globals.get(G64)?.name).toBe("pfn_MessageBoxW");
  });
});

// ── x86 ─────────────────────────────────────────────────────────────────────

const GPA32 = 0x40d04c;
const ENC32 = 0x40d050;
const STR_MBTA = 0x40ea68;
const G32 = 0x4125f8;
const iat32 = new Map([
  [GPA32, { lib: "KERNEL32.dll", func: "GetProcAddress" }],
  [ENC32, { lib: "KERNEL32.dll", func: "EncodePointer" }],
  [0x40d054, { lib: "KERNEL32.dll", func: "LoadLibraryA" }],
]);
const strings32 = new Map([[STR_MBTA, "MessageBoxTimeoutA"]]);

/** `w32!0x40101e..0x40102f`, as Capstone spells the `a3` store. */
const witness32 = (): PfnInsn[] =>
  seq(0x40101e, [
    ["push", "0x40ea68", 5],
    ["push", "esi", 1],
    ["call", "dword ptr [0x40d04c]", 6],
    ["mov", "dword ptr [0x4125f8], eax", 5],
    ["test", "eax, eax", 2],
    ["ret", "", 1],
  ]);

function run32(insns: PfnInsn[], extra?: Partial<Parameters<typeof recognisePfnGlobals>[0]>) {
  return recognisePfnGlobals({
    instructions: insns,
    funcExtents: [{ address: insns[0].address, size: 0x100 }],
    iatMap: iat32,
    stringMap: strings32,
    is64: false,
    ...extra,
  });
}

describe("recognisePfnGlobals — x86 push form", () => {
  it("reads the string from the SECOND-last push and names the slot, unencoded", () => {
    const r = run32(witness32());
    expect(r.refusals).toEqual([]);
    expect([...r.globals]).toEqual([
      [G32, { name: "pfn_MessageBoxTimeoutA", proc: "MessageBoxTimeoutA", encoded: false }],
    ]);
  });

  it("admits `push eax; call [EncodePointer]` and marks the slot encoded", () => {
    const insns = seq(0x40101e, [
      ["push", "0x40ea68", 5],
      ["push", "esi", 1],
      ["call", "dword ptr [0x40d04c]", 6],
      ["push", "eax", 1],
      ["call", "dword ptr [0x40d050]", 6],
      ["mov", "dword ptr [0x4125f8], eax", 5],
      ["ret", "", 1],
    ]);
    expect(run32(insns).globals.get(G32)?.encoded).toBe(true);
  });

  it("REFUSES EncodePointer whose last push was not the result (encode-arg)", () => {
    const insns = seq(0x40101e, [
      ["push", "0x40ea68", 5],
      ["push", "esi", 1],
      ["call", "dword ptr [0x40d04c]", 6],
      ["push", "esi", 1],
      ["call", "dword ptr [0x40d050]", 6],
      ["mov", "dword ptr [0x4125f8], eax", 5],
      ["ret", "", 1],
    ]);
    expect(reasons(run32(insns))).toEqual(["encode-arg"]);
  });

  it("REFUSES a lookup with fewer than two pushes since the last call (no-string-operand)", () => {
    const insns = seq(0x40101e, [
      ["push", "0x40ea5c", 5],
      ["call", "dword ptr [0x40d054]", 6], // LoadLibraryA consumes the push
      ["push", "eax", 1],
      ["call", "dword ptr [0x40d04c]", 6],
      ["mov", "dword ptr [0x4125f8], eax", 5],
      ["ret", "", 1],
    ]);
    expect(reasons(run32(insns))).toEqual(["no-string-operand"]);
  });

  it("REFUSES a string pushed from a register (no-string-operand) and an unknown address (string-unknown)", () => {
    const reg = witness32();
    reg[0] = ins(0x40101e, "push", "edi", 5);
    expect(reasons(run32(reg))).toEqual(["no-string-operand"]);
    expect(reasons(run32(witness32(), { stringMap: new Map() }))).toEqual(["string-unknown"]);
  });

  it("REFUSES the slot when another function writes it (other-store), by the same rule as x64", () => {
    const other = ins(0x401200, "mov", "dword ptr [0x4125f8], 0", 10);
    const r = run32([...witness32(), other]);
    expect(r.globals.size).toBe(0);
    expect(reasons(r)).toEqual(["other-store"]);
  });

  it("does not read a mov to a register between the pushes and the call as breaking the shape", () => {
    const insns = seq(0x40101e, [
      ["push", "0x40ea68", 5],
      ["mov", "ecx, esi", 2],
      ["push", "ecx", 1],
      ["call", "dword ptr [0x40d04c]", 6],
      ["mov", "dword ptr [0x4125f8], eax", 5],
      ["ret", "", 1],
    ]);
    expect(run32(insns).globals.get(G32)?.name).toBe("pfn_MessageBoxTimeoutA");
  });

  it("t32!sub_40614A: GetProcAddress whose result is only called is a refusal, not a name", () => {
    const insns = seq(0x40615e, [
      ["push", "0x40f618", 5],
      ["push", "eax", 1],
      ["call", "dword ptr [0x40f0e4]", 6],
      ["test", "eax, eax", 2],
      ["je", "0x406173", 2],
      ["push", "dword ptr [ebp + 8]", 3],
      ["call", "eax", 2],
      ["pop", "ebp", 1],
      ["ret", "", 1],
    ]);
    const r = run32(insns, {
      iatMap: new Map([[0x40f0e4, { lib: "KERNEL32.dll", func: "GetProcAddress" }]]),
      stringMap: new Map([[0x40f618, "CorExitProcess"]]),
    });
    expect(r.lookups).toBe(1);
    expect(r.globals.size).toBe(0);
    expect(reasons(r)).toEqual(["intervening-call"]);
  });
});

describe("recognisePfnGlobals — nothing to find", () => {
  it("returns an empty answer over an image with no GetProcAddress import", () => {
    const r = run64(witness64(), { iatMap: new Map() });
    expect(r).toEqual({ globals: new Map(), refusals: [], lookups: 0 });
  });
});
