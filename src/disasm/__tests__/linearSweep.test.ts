/**
 * peek-a-bin-x40u — one declaration of the x86 linear sweep, and one memo of it.
 *
 * `detectFunctions` and `buildAllXrefs` each swept `.text` end to end in loops
 * that were copy-paste identical, and a load ran the sweep three times over the
 * same bytes. These pin the two properties that make sharing it safe: what the
 * sweep says about a byte the decoder refused, and what the memo's key does and
 * does not consider.
 *
 * The gap question is the one that could go wrong silently. `detectFunctions`'
 * padding heuristic reads "was the previous instruction unconditional", and the
 * loop this replaced answered it by watching for an empty decode; a flat array
 * has to answer it from `address` and `size` instead. So the sweep must leave a
 * gap where one exists, rather than presenting a contiguous stream.
 */

import { describe, expect, it } from "vitest";
import {
  type CapstoneHandle,
  type CapstoneScan,
  createScan,
  type RawInsn,
} from "../capstoneWindow";
import { gridScan, type SweptInsn, sweepX86, X86SweepCache } from "../linearSweep";
import { SectionMemo, sameBytes } from "../sectionMemo";

/**
 * A decoder that reads every byte as a one-byte instruction, except `0xff`,
 * which it refuses — so a test can place a hole exactly where it wants one.
 *
 * Counts its own entries, which is how the memo's effect is observed: an
 * instruction count cannot distinguish a hit from a miss, only a decode count
 * can.
 */
function byteDecoder(tag = "x86") {
  const stub = {
    tag,
    calls: 0,
    arch: 3,
    disasm(bytes: Uint8Array, options?: { address?: number; count?: number }): RawInsn[] {
      stub.calls++;
      const address = options?.address ?? 0;
      const out: RawInsn[] = [];
      const limit = options?.count ?? bytes.length;
      for (let i = 0; i < bytes.length && out.length < limit; i++) {
        // A refused first byte is how capstone-wasm reports "not an encoding":
        // it throws rather than returning an empty list.
        if (bytes[i] === 0xff) {
          if (i === 0) throw new Error("Failed to disassemble");
          break;
        }
        out.push({
          address: address + i,
          bytes: bytes.subarray(i, i + 1),
          mnemonic: `op${bytes[i]}`,
          opStr: "",
          size: 1,
        });
      }
      if (out.length === 0) throw new Error("Failed to disassemble");
      return out;
    },
  };
  return stub as typeof stub & CapstoneHandle;
}

const BASE = 0x401000;

describe("sweepX86", () => {
  it("decodes a section from end to end", () => {
    const insns = sweepX86(new Uint8Array([1, 2, 3, 4]), BASE, byteDecoder(), "t");

    expect(insns.map((i) => i.address)).toEqual([BASE, BASE + 1, BASE + 2, BASE + 3]);
    expect(insns.map((i) => i.mnemonic)).toEqual(["op1", "op2", "op3", "op4"]);
  });

  it("skips a byte the decoder refuses, and leaves the gap visible", () => {
    // The property `detectFunctions` reads off the array: two elements are
    // adjacent in the image only when `address === prev.address + prev.size`.
    const insns = sweepX86(new Uint8Array([1, 0xff, 3]), BASE, byteDecoder(), "t");

    expect(insns.map((i) => i.address)).toEqual([BASE, BASE + 2]);
    expect(insns[1].address).not.toBe(insns[0].address + insns[0].size);
  });

  it("records only the four fields either consumer reads", () => {
    // Not an `Instruction`: no `bytes` view per element, which is most of the
    // difference between 135 and 372 bytes per instruction of retention.
    const [insn] = sweepX86(new Uint8Array([1]), BASE, byteDecoder(), "t");

    expect(Object.keys(insn).sort()).toEqual(["address", "mnemonic", "opStr", "size"]);
  });
});

describe("sameBytes", () => {
  it("separates two sections of equal length", () => {
    expect(sameBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false);
    expect(sameBytes(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true);
  });

  it("separates two sections of different length", () => {
    expect(sameBytes(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false);
  });
});

describe("SectionMemo", () => {
  it("computes once for the same bytes at the same address with the same decoder", () => {
    const memo = new SectionMemo<number>();
    let computed = 0;
    const cs = {};
    const get = () => memo.get(new Uint8Array([1, 2, 3]), BASE, cs, () => ++computed);

    expect(get()).toBe(1);
    expect(get()).toBe(1);
    expect(computed).toBe(1);
  });

  it("recomputes for different bytes of the same length at the same address", () => {
    // Both real ARM64 corpus binaries base `.text` at 0x140001000, so a
    // length-and-address key is unsound on the only files there are to test with.
    const memo = new SectionMemo<number>();
    let computed = 0;
    const cs = {};

    memo.get(new Uint8Array([1, 2, 3]), BASE, cs, () => ++computed);
    memo.get(new Uint8Array([1, 2, 4]), BASE, cs, () => ++computed);

    expect(computed).toBe(2);
  });

  it("recomputes for the same bytes at a different load address", () => {
    // Capstone prints resolved branch targets and rip displacements, so the
    // base is part of what the answer is.
    const memo = new SectionMemo<number>();
    let computed = 0;
    const cs = {};
    const bytes = new Uint8Array([1, 2, 3]);

    memo.get(bytes, BASE, cs, () => ++computed);
    memo.get(bytes, BASE + 0x1000, cs, () => ++computed);

    expect(computed).toBe(2);
  });

  it("recomputes for a different decoder over the same bytes at the same address", () => {
    // The part of the key `Arm64SweepCache` does not need: x86-32 and x86-64
    // disagree about what a byte string means, and the two handles are the only
    // thing that says which reading was asked for.
    const memo = new SectionMemo<number>();
    let computed = 0;
    const bytes = new Uint8Array([1, 2, 3]);

    memo.get(bytes, BASE, { mode: 32 }, () => ++computed);
    memo.get(bytes, BASE, { mode: 64 }, () => ++computed);

    expect(computed).toBe(2);
  });

  it("stores nothing when the computation throws", () => {
    // A refused section — `Arm64DecodeRateError`, `CapstoneUnavailableError` —
    // must not decay into a cached answer.
    const memo = new SectionMemo<number>();
    const bytes = new Uint8Array([1, 2, 3]);
    const cs = {};

    expect(() =>
      memo.get(bytes, BASE, cs, () => {
        throw new Error("refused");
      }),
    ).toThrow(/refused/);
    let computed = 0;
    expect(memo.get(bytes, BASE, cs, () => ++computed)).toBe(1);
  });

  it("forgets the held section on clear", () => {
    const memo = new SectionMemo<number>();
    let computed = 0;
    const bytes = new Uint8Array([1, 2, 3]);
    const cs = {};

    memo.get(bytes, BASE, cs, () => ++computed);
    memo.clear();
    memo.get(bytes, BASE, cs, () => ++computed);

    expect(computed).toBe(2);
  });
});

describe("X86SweepCache", () => {
  it("sweeps once for two calls over the same section", () => {
    const cs = byteDecoder();
    const cache = new X86SweepCache();
    const bytes = () => new Uint8Array([1, 2, 3, 4]);

    const first = cache.sweep(bytes(), BASE, cs, "a");
    const afterFirst = cs.calls;
    const second = cache.sweep(bytes(), BASE, cs, "b");

    expect(cs.calls).toBe(afterFirst);
    expect(second).toEqual(first);
    // The same array, not a copy: sharing it is the point, and it is why
    // `detectFunctions` copies into its rolling window rather than aliasing.
    expect(second).toBe(first);
  });

  it("re-sweeps a different section at the same address", () => {
    const cs = byteDecoder();
    const cache = new X86SweepCache();

    cache.sweep(new Uint8Array([1, 2, 3, 4]), BASE, cs, "a");
    const afterFirst = cs.calls;
    const second = cache.sweep(new Uint8Array([5, 6, 7, 8]), BASE, cs, "b");

    expect(cs.calls).toBeGreaterThan(afterFirst);
    expect(second.map((i) => i.mnemonic)).toEqual(["op5", "op6", "op7", "op8"]);
  });

  it("does not serve a 32-bit reading to a 64-bit request", () => {
    const cs32 = byteDecoder("32");
    const cs64 = byteDecoder("64");
    const cache = new X86SweepCache();
    const bytes = () => new Uint8Array([1, 2]);

    cache.sweep(bytes(), BASE, cs32, "a");
    cache.sweep(bytes(), BASE, cs64, "b");

    expect(cs64.calls).toBeGreaterThan(0);
  });
});

/**
 * peek-a-bin-iqzu — `hybridDisassemble` decodes through the held sweep.
 *
 * It is the last RPC of an x86 load that still ran Capstone over `.text` for
 * itself, and it is the largest: 765 ms of a 1666 ms load on a 669 KiB `.text`.
 * It is not a transcription of the sweep — recursive descent over a BFS queue
 * plus a gap fill produces a different, annotated, smaller stream — so what is
 * shared is the decoder underneath, {@link gridScan}, which answers from the
 * grid where the grid has an instruction at that address and delegates where it
 * does not.
 *
 * The measured coincidence rate is what justifies the mechanism (99.9-100.0%
 * of 222137 instructions over five real images, 100.0% agreeing in mnemonic,
 * operands and size). These pin the three ways it can be wrong, which no
 * measurement over agreeing images could ever exercise: a miss, a discontinuity
 * and a window bound. The fourth — a served `bytes` that is a *view* onto the
 * section — is the one whose harm is invisible here and catastrophic in the
 * reply's structured clone.
 */
describe("gridScan", () => {
  /** Absolute addresses; the grid is what a sweep of `[1,2,3,4]` at BASE says. */
  const contiguous: SweptInsn[] = [
    { address: BASE, mnemonic: "op1", opStr: "", size: 1 },
    { address: BASE + 1, mnemonic: "op2", opStr: "", size: 1 },
    { address: BASE + 2, mnemonic: "op3", opStr: "", size: 1 },
    { address: BASE + 3, mnemonic: "op4", opStr: "", size: 1 },
  ];

  /** The real scan, so a delegation is observable as a decoder entry. */
  function backed(grid: SweptInsn[]): { scan: CapstoneScan; cs: ReturnType<typeof byteDecoder> } {
    const cs = byteDecoder();
    return { scan: gridScan(grid, createScan(cs, "t")), cs };
  }

  it("answers a hit without entering the decoder at all", () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const { scan, cs } = backed(contiguous);

    const out = scan.decode(bytes, 0, bytes.length, BASE);

    expect(cs.calls).toBe(0);
    expect(out.map((i) => i.address)).toEqual([BASE, BASE + 1, BASE + 2, BASE + 3]);
    expect(out.map((i) => i.mnemonic)).toEqual(["op1", "op2", "op3", "op4"]);
  });

  it("delegates an address the grid has no instruction at", () => {
    // Recursive descent knows boundaries a linear sweep can miss — 26 such
    // addresses on t32 — and the two reasons the grid can lack one (the sweep
    // stepped over it; the decoder refused it) are indistinguishable from here.
    // Decoding is the right answer to both.
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const { scan, cs } = backed([{ address: BASE, mnemonic: "op1", opStr: "", size: 1 }]);

    const out = scan.decodeOne(bytes, 1, 2, BASE + 1);

    expect(cs.calls).toBe(1);
    expect(out.map((i) => i.mnemonic)).toEqual(["op2"]);
  });

  it("stops a run where the grid stops being contiguous", () => {
    // `cs_disasm` returns instructions until it meets a byte it cannot decode.
    // A hole in the grid IS that byte, recorded; serving across it would invent
    // instructions over bytes the sweep refused.
    const holed: SweptInsn[] = [
      { address: BASE, mnemonic: "op1", opStr: "", size: 1 },
      { address: BASE + 2, mnemonic: "op3", opStr: "", size: 1 },
    ];
    const { scan, cs } = backed(holed);

    const out = scan.decode(new Uint8Array([1, 0xff, 3]), 0, 3, BASE);

    expect(out.map((i) => i.address)).toEqual([BASE]);
    expect(cs.calls).toBe(0);
  });

  it("does not serve an instruction that would extend past the caller's limit", () => {
    // `createScan` clamps every call to the caller's `limit`, and Capstone never
    // returns an instruction crossing that end — so neither may this, or the
    // caller's `offset` advance differs from what it advanced by before.
    const wide: SweptInsn[] = [{ address: BASE, mnemonic: "wide", opStr: "", size: 4 }];
    const { scan } = backed(wide);

    const out = scan.decode(new Uint8Array([1, 2, 3, 4]), 0, 2, BASE);

    // Nothing servable, so it delegates, and the four-byte entry is nowhere in
    // the answer — the stub reads the two in-limit bytes one at a time.
    expect(out.map((i) => i.size)).toEqual([1, 1]);
    expect(out.some((i) => i.mnemonic === "wide")).toBe(false);
  });

  it("returns one instruction for decodeOne even where the grid could give more", () => {
    const bytes = new Uint8Array([1, 2, 3, 4]);
    const { scan } = backed(contiguous);

    expect(scan.decodeOne(bytes, 0, bytes.length, BASE)).toHaveLength(1);
    expect(scan.decode(bytes, 0, bytes.length, BASE)).toHaveLength(4);
  });

  it("gives each served instruction its OWN bytes buffer", () => {
    // The hazard with no visible symptom: `RawInsn.bytes` becomes
    // `Instruction.bytes` and crosses `postMessage` in the reply. A `subarray`
    // here would read identically and would make the reply's structured clone
    // serialise the whole `.text` once per instruction. capstone-wasm builds
    // its own small buffer with `HEAPU8.slice`; so does this.
    const section = new Uint8Array(4096);
    section.set([1, 2, 3, 4]);
    const { scan } = backed(contiguous);

    const out = scan.decode(section, 0, section.length, BASE);

    for (const insn of out) {
      expect(insn.bytes.buffer).not.toBe(section.buffer);
      expect(insn.bytes.buffer.byteLength).toBe(insn.size);
    }
    expect(Array.from(out.map((i) => i.bytes[0]))).toEqual([1, 2, 3, 4]);
  });

  it("serves out of a subarray at the right offset", () => {
    // The gap fill hands `disassemble` a *subarray* of the section with its own
    // base address, so the grid's absolute addresses have to be resolved against
    // the caller's `(offset, address)` pair rather than against the section.
    const section = new Uint8Array([9, 9, 1, 2, 3, 4]);
    const gap = section.subarray(2);
    const { scan } = backed(contiguous);

    const out = scan.decode(gap, 0, gap.length, BASE);

    expect(out.map((i) => i.bytes[0])).toEqual([1, 2, 3, 4]);
  });
});

describe("SectionMemo.peek", () => {
  it("answers a held entry without computing", () => {
    const memo = new SectionMemo<number>();
    const bytes = () => new Uint8Array([1, 2]);
    memo.get(bytes(), BASE, "cs", () => 7);

    expect(memo.peek(bytes(), BASE, "cs")).toBe(7);
  });

  it("declines rather than computing when nothing is held", () => {
    // The whole reason `hybridDisassemble` peeks: the memo has ONE slot, so a
    // `get` here would both pay for a sweep this method does not need and evict
    // the section the other RPCs share.
    const memo = new SectionMemo<number>();
    let computed = 0;

    const out = memo.peek(new Uint8Array([1, 2]), BASE, "cs");

    expect(out).toBeUndefined();
    expect(computed).toBe(0);
    // ...and it did not store, so a later `get` still computes.
    expect(memo.get(new Uint8Array([1, 2]), BASE, "cs", () => ++computed)).toBe(1);
  });

  it("declines a different section at the same address", () => {
    const memo = new SectionMemo<number>();
    memo.get(new Uint8Array([1, 2]), BASE, "cs", () => 7);

    expect(memo.peek(new Uint8Array([3, 4]), BASE, "cs")).toBeUndefined();
  });

  it("leaves the held entry alone", () => {
    const memo = new SectionMemo<number>();
    const cs = "cs";
    memo.get(new Uint8Array([1, 2]), BASE, cs, () => 7);
    let recomputed = 0;

    // A peek that misses must not displace what is held — this is a hex patch:
    // a different byte array over the same region, which the content key
    // declines and which must not cost the next caller its hit.
    memo.peek(new Uint8Array([3, 4]), BASE, cs);

    expect(memo.get(new Uint8Array([1, 2]), BASE, cs, () => ++recomputed)).toBe(7);
    expect(recomputed).toBe(0);
  });
});

describe("X86SweepCache.peek", () => {
  it("hands over the sweep another RPC already paid for", () => {
    const cs = byteDecoder();
    const cache = new X86SweepCache();
    const bytes = () => new Uint8Array([1, 2, 3, 4]);
    const swept = cache.sweep(bytes(), BASE, cs, "detect");
    const afterSweep = cs.calls;

    expect(cache.peek(bytes(), BASE, cs)).toBe(swept);
    expect(cs.calls).toBe(afterSweep);
  });

  it("declines when there is no decoder at all", () => {
    const cache = new X86SweepCache();
    cache.sweep(new Uint8Array([1, 2]), BASE, byteDecoder(), "detect");

    expect(cache.peek(new Uint8Array([1, 2]), BASE, undefined)).toBeUndefined();
  });
});
