/**
 * The `cs_insn` ABI oracle (peek-a-bin-fdi8).
 *
 * `src/disasm/capstoneReader.ts` marshals each instruction out of WASM memory
 * by hand, at byte offsets read off capstone-wasm's `INSN_FIELDS` and hard-coded
 * here in the product. **A version bump can change that layout silently**: a
 * wrong offset does not throw, it yields a plausible mnemonic and a plausible
 * operand string for every instruction in the tool, and every other gate in this
 * repo would go on passing — the emitted C would compile, the guards would be
 * anchored, and the disassembly would simply be a different program's.
 *
 * So the reader is checked against the one authority available: capstone-wasm's
 * own `Capstone.prototype.disasm`, decoding the same bytes at the same address.
 * Two properties make this worth having rather than reassuring:
 *
 *  * **It cannot read vacuously.** Every comparison asserts a non-zero
 *    instruction count first. A scan that matched nothing would fail rather
 *    than pass, which is the failure mode a differential test has.
 *  * **It is negative-controlled, permanently.** {@link fastCapstoneHandle}
 *    takes its {@link CsInsnAbi} as an argument for no other reason: each field
 *    is perturbed in turn and the comparison must then FAIL. A test that only
 *    ever ran against the right offsets could not show that a wrong one is
 *    visible to it.
 *
 * The inputs are deliberately pseudo-random bytes as well as hand-written
 * instructions. Random bytes decode to a far wider spread of encodings than any
 * fixture a person writes — long operand strings, unusual prefixes, undecodable
 * runs — and the generator is a fixed LCG, so the corpus is both broad and
 * reproducible.
 */

import { Capstone, Const } from "capstone-wasm";
import { beforeAll, describe, expect, it } from "vitest";
import {
  CS_INSN_ABI,
  type CsInsnAbi,
  capstoneModule,
  fastCapstoneHandle,
  loadCapstoneModule,
} from "../capstoneReader";
import type { CapstoneHandle, RawInsn } from "../capstoneWindow";

/** A fixed LCG (Numerical Recipes), so the byte corpus is the same every run. */
function pseudoRandomBytes(n: number, seed: number): Uint8Array {
  const out = new Uint8Array(n);
  let x = seed >>> 0;
  for (let i = 0; i < n; i++) {
    x = (Math.imul(x, 1664525) + 1013904223) >>> 0;
    out[i] = (x >>> 24) & 0xff;
  }
  return out;
}

/** Hand-written x86-64: a prologue, a rip-relative `lea`, a 12-byte `mov`, a `ret`. */
const X64_SEQUENCE = new Uint8Array([
  0x55, 0x48, 0x89, 0xe5, 0x48, 0x8d, 0x05, 0x10, 0x20, 0x30, 0x00, 0xe8, 0x00, 0x00, 0x00, 0x00,
  0x48, 0xc7, 0x84, 0x24, 0x80, 0x00, 0x00, 0x00, 0x78, 0x56, 0x34, 0x12, 0x90, 0xc3,
]);

/** Hand-written x86-32: MSVC's hot-patch pad and frame setup, then a call and `ret`. */
const X86_SEQUENCE = new Uint8Array([
  0x8b, 0xff, 0x55, 0x8b, 0xec, 0x83, 0xec, 0x20, 0x53, 0x56, 0x57, 0xe8, 0x00, 0x00, 0x00, 0x00,
  0x5f, 0x5e, 0x5b, 0xc9, 0xc2, 0x08, 0x00,
]);

/** Hand-written A64: `stp`/`mov`/`adrp`/`add`/`bl`/`ldp`/`ret`. */
const ARM64_SEQUENCE = new Uint8Array([
  0xfd, 0x7b, 0xbf, 0xa9, 0xfd, 0x03, 0x00, 0x91, 0x00, 0x00, 0x00, 0xb0, 0x00, 0x40, 0x0a, 0x91,
  0x05, 0x00, 0x00, 0x94, 0xfd, 0x7b, 0xc1, 0xa8, 0xc0, 0x03, 0x5f, 0xd6,
]);

/**
 * `unit` repeated to fill `n` bytes.
 *
 * The random cases below mostly decode one instruction per call — `cs_disasm`
 * stops at the first byte it cannot decode — so `stride` and `address`, which
 * only matter from the *second* instruction of a batch onward, are barely
 * exercised by them (2 and 3 differing rows under perturbation). A long run of
 * valid encodings decodes as one batch of ~2700 and puts both under real load.
 */
function tile(unit: Uint8Array, n: number): Uint8Array {
  const out = new Uint8Array(n - (n % unit.length));
  for (let i = 0; i < out.length; i += unit.length) out.set(unit, i);
  return out;
}

interface Case {
  name: string;
  arch: number;
  mode: number;
  bytes: Uint8Array;
  address: number;
}

const CASES: Case[] = [
  { name: "x86-64 sequence", arch: 0, mode: 0, bytes: X64_SEQUENCE, address: 0x140001000 },
  { name: "x86-32 sequence", arch: 0, mode: 0, bytes: X86_SEQUENCE, address: 0x401000 },
  { name: "A64 sequence", arch: 0, mode: 0, bytes: ARM64_SEQUENCE, address: 0x140001000 },
  {
    name: "x86-64 random",
    arch: 0,
    mode: 0,
    bytes: pseudoRandomBytes(8192, 1),
    address: 0x140001000,
  },
  { name: "x86-32 random", arch: 0, mode: 0, bytes: pseudoRandomBytes(8192, 2), address: 0x401000 },
  { name: "A64 random", arch: 0, mode: 0, bytes: pseudoRandomBytes(8192, 3), address: 0x140001000 },
  {
    name: "x86-64 long run",
    arch: 0,
    mode: 0,
    bytes: tile(X64_SEQUENCE, 8192),
    address: 0x140001000,
  },
  {
    name: "A64 long run",
    arch: 0,
    mode: 0,
    bytes: tile(ARM64_SEQUENCE, 8192),
    address: 0x140001000,
  },
  // Above 2^32, so the address's high word is non-zero and actually read.
  { name: "x86-64 high address", arch: 0, mode: 0, bytes: X64_SEQUENCE, address: 0x7ffe00001000 },
];

let cs32: Capstone;
let cs64: Capstone;
let csArm64: Capstone;

beforeAll(async () => {
  await loadCapstoneModule();
  cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
  cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
  csArm64 = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM);
  for (const c of CASES) {
    const arm = c.name.startsWith("A64");
    const thirtyTwo = c.name.startsWith("x86-32");
    c.arch = arm ? Const.CS_ARCH_ARM64 : Const.CS_ARCH_X86;
    c.mode = arm ? Const.CS_MODE_ARM : thirtyTwo ? Const.CS_MODE_32 : Const.CS_MODE_64;
  }
});

function handleFor(c: Case): Capstone {
  if (c.arch === Const.CS_ARCH_ARM64) return csArm64;
  return c.mode === Const.CS_MODE_32 ? cs32 : cs64;
}

/**
 * Decode a whole buffer the way a scan loop does: forward from each offset, and
 * on a window that yields nothing, advance one byte and try again.
 *
 * `cs_disasm` stops at the first byte it cannot decode, so a single call over
 * pseudo-random bytes returns two or three instructions and proves nothing. The
 * sweep is what production does (`sweepX86`, `disassembleArm64`) and it turns
 * the same 8 KiB into thousands of instructions across a very wide spread of
 * encodings — which is the whole point of using random bytes at all. Both
 * readers are driven through the identical loop, so any difference is theirs.
 */
function sweep(
  disasm: (b: Uint8Array, o: { address?: number; count?: number }) => RawInsn[],
  bytes: Uint8Array,
  address: number,
  step: number,
): RawInsn[] {
  const out: RawInsn[] = [];
  let offset = 0;
  while (offset < bytes.length) {
    let insns: RawInsn[] = [];
    try {
      insns = disasm(bytes.subarray(offset), { address: address + offset, count: 0 });
    } catch {
      insns = [];
    }
    if (insns.length === 0) {
      offset += step;
      continue;
    }
    for (const insn of insns) out.push(insn);
    const last = insns[insns.length - 1];
    const consumed = Number(last.address) - (address + offset) + last.size;
    offset += consumed > 0 ? consumed : step;
  }
  return out;
}

/** capstone-wasm's own reader, swept. */
function reference(cs: Capstone, c: Case): RawInsn[] {
  return sweep(
    (b, o) => cs.disasm(b, o) as unknown as RawInsn[],
    c.bytes,
    c.address,
    c.arch === Const.CS_ARCH_ARM64 ? 4 : 1,
  );
}

/** The hand reader, swept identically. */
function fastSwept(cs: Capstone, c: Case, abi?: CsInsnAbi): RawInsn[] {
  const handle = abi
    ? fastCapstoneHandle(capstoneModule()!, cs, abi)
    : fastCapstoneHandle(capstoneModule()!, cs);
  return sweep(
    (b, o) => handle.disasm(b, o),
    c.bytes,
    c.address,
    c.arch === Const.CS_ARCH_ARM64 ? 4 : 1,
  );
}

/** Every field of every instruction that differs, as readable rows. */
function differences(ref: RawInsn[], got: RawInsn[]): string[] {
  const out: string[] = [];
  if (ref.length !== got.length) out.push(`count ${ref.length} vs ${got.length}`);
  const n = Math.min(ref.length, got.length);
  for (let i = 0; i < n; i++) {
    const a = ref[i];
    const b = got[i];
    if (a.address !== b.address) out.push(`[${i}] address ${a.address} vs ${b.address}`);
    if (a.size !== b.size) out.push(`[${i}] size ${a.size} vs ${b.size}`);
    if (a.mnemonic !== b.mnemonic) out.push(`[${i}] mnemonic ${a.mnemonic} vs ${b.mnemonic}`);
    if (a.opStr !== b.opStr) out.push(`[${i}] opStr "${a.opStr}" vs "${b.opStr}"`);
    // Content and length, never `bytes.buffer.byteLength`: capstone-wasm slices
    // a fixed 24 bytes and subarrays it, the fast reader slices exactly `size`,
    // and CLAUDE.md's `gridScan` gotcha records that asserting that length in
    // either direction calls correct output a defect.
    if (a.bytes.length !== b.bytes.length) {
      out.push(`[${i}] bytes length ${a.bytes.length} vs ${b.bytes.length}`);
    } else {
      for (let j = 0; j < a.bytes.length; j++) {
        if (a.bytes[j] !== b.bytes[j])
          out.push(`[${i}] bytes[${j}] ${a.bytes[j]} vs ${b.bytes[j]}`);
      }
    }
  }
  return out.slice(0, 8);
}

describe("the hand reader agrees with capstone-wasm's own, field for field", () => {
  it("retains the emscripten Module, so the fast reader is the one under test", () => {
    // Without this the whole file would silently audit capstone-wasm against
    // itself: `capstoneHandle` falls back to the dependency's reader when the
    // Module was not retained, and every comparison below would pass vacuously.
    expect(capstoneModule()).not.toBeNull();
  });

  for (const c of CASES) {
    it(`agrees on ${c.name}`, () => {
      const cs = handleFor(c);
      const ref = reference(cs, c);
      const fast = fastSwept(cs, c);
      // Non-vacuous: a comparison of two empty lists proves nothing.
      expect(ref.length).toBeGreaterThan(4);
      expect(differences(ref, fast)).toEqual([]);
      expect(fast.length).toBe(ref.length);
    });
  }

  it("honours the instruction count cap exactly as capstone-wasm does", () => {
    // `CS_MAX_INSNS_PER_CALL` is one of the two measured WASM ceilings, so a
    // reader that ignored `count` would decode a whole window where production
    // asked for a slice of one.
    const ref = cs64.disasm(X64_SEQUENCE, {
      address: 0x140001000,
      count: 7,
    }) as unknown as RawInsn[];
    const fast = fastCapstoneHandle(capstoneModule()!, cs64).disasm(X64_SEQUENCE, {
      address: 0x140001000,
      count: 7,
    });
    expect(ref.length).toBe(7);
    expect(differences(ref, fast)).toEqual([]);
    expect(
      fastCapstoneHandle(capstoneModule()!, cs64).disasm(X64_SEQUENCE, {
        address: 0x140001000,
        count: 1,
      }).length,
    ).toBe(1);
  });

  it("carries `arch` through, because the liveness probe selects a nop with it", () => {
    const fast = fastCapstoneHandle(capstoneModule()!, csArm64);
    expect(fast.arch).toBe(Const.CS_ARCH_ARM64);
    expect(fastCapstoneHandle(capstoneModule()!, cs64).arch).toBe(Const.CS_ARCH_X86);
  });

  it("returns [] where capstone-wasm throws, which createScan reads the same way", () => {
    // 0x06 is `push es`, invalid in 64-bit mode. The dependency throws on a
    // window that decodes nothing; the fast reader returns an empty list, and
    // `createScan`'s `run` collapses both into the same branch — so the
    // engine-death probe still counts this as one consecutive failure.
    const nothing = new Uint8Array([0x06, 0x06, 0x06, 0x06]);
    expect(() => cs64.disasm(nothing, { address: 0x1000, count: 0 })).toThrow();
    const fast = fastCapstoneHandle(capstoneModule()!, cs64);
    expect(fast.disasm(nothing, { address: 0x1000, count: 0 })).toEqual([]);
  });

  it("slices `bytes` to the instruction's own length", () => {
    // Not an assertion about `buffer.byteLength` in either direction — see
    // `differences` above. This pins only that the view is `size` long and
    // holds the instruction's own bytes.
    const fast = fastCapstoneHandle(capstoneModule()!, cs64);
    const insns = fast.disasm(X64_SEQUENCE, { address: 0x140001000, count: 0 });
    expect(insns.length).toBeGreaterThan(4);
    let at = 0;
    for (const insn of insns) {
      expect(insn.bytes.length).toBe(insn.size);
      expect(Array.from(insn.bytes)).toEqual(Array.from(X64_SEQUENCE.subarray(at, at + insn.size)));
      at += insn.size;
    }
  });
});

describe("a wrong ABI offset is visible to that comparison", () => {
  /**
   * Each perturbation is one field moved or shrunk. The comparison above must
   * then report a difference — otherwise the offsets in `CS_INSN_ABI` are not
   * actually being exercised and the oracle above proves nothing about them.
   */
  const PERTURBATIONS: Array<[string, Partial<CsInsnAbi>]> = [
    ["stride", { stride: 248 }],
    ["address", { address: 12 }],
    ["size", { size: 18 }],
    ["bytes", { bytes: 20 }],
    ["bytesMax", { bytesMax: 2 }],
    ["mnemonic", { mnemonic: 43 }],
    ["mnemonicMax", { mnemonicMax: 2 }],
    ["opStr", { opStr: 75 }],
    ["opStrMax", { opStrMax: 3 }],
  ];

  for (const [field, patch] of PERTURBATIONS) {
    it(`fails when \`${field}\` is wrong`, () => {
      const c = CASES.find((x) => x.name === "x86-64 long run")!;
      const cs = handleFor(c);
      const ref = reference(cs, c);
      expect(ref.length).toBeGreaterThan(1000);
      let fast: RawInsn[];
      try {
        fast = fastSwept(cs, c, { ...CS_INSN_ABI, ...patch });
      } catch {
        return; // a throw is detection too
      }
      expect(differences(ref, fast).length).toBeGreaterThan(0);
    });
  }

  it("passes with the real ABI, so the controls above are not detecting noise", () => {
    const c = CASES.find((x) => x.name === "x86-64 long run")!;
    const cs = handleFor(c);
    const ref = reference(cs, c);
    expect(ref.length).toBeGreaterThan(1000);
    expect(differences(ref, fastSwept(cs, c, { ...CS_INSN_ABI }))).toEqual([]);
  });
});

describe("the fast handle satisfies CapstoneHandle structurally", () => {
  it("is assignable, so `createScan` needs no change to take it", () => {
    const handle: CapstoneHandle = fastCapstoneHandle(capstoneModule()!, cs64);
    expect(typeof handle.disasm).toBe("function");
  });
});
