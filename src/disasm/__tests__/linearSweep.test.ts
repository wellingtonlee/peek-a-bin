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
import type { CapstoneHandle, RawInsn } from "../capstoneWindow";
import { sweepX86, X86SweepCache } from "../linearSweep";
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
