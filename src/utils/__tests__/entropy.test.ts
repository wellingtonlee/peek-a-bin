/**
 * Shannon entropy over byte buffers.
 *
 * Every expected value here is hand-computed from the definition
 * (H = -Σ p·log2 p) rather than snapshotted from the implementation, so a
 * regression in the frequency counting or the block windowing shows up as a
 * wrong number instead of a quietly updated baseline.
 */

import { describe, it, expect } from "vitest";
import { computeEntropyBlocks, computeSectionEntropy, classifyEntropy } from "../entropy";

/** `count` bytes, all `value`. */
function repeated(value: number, count: number): Uint8Array {
  return new Uint8Array(count).fill(value);
}

/** Every byte value 0..255 exactly `times` each, in order. */
function allByteValues(times = 1): Uint8Array {
  const out = new Uint8Array(256 * times);
  for (let i = 0; i < out.length; i++) out[i] = i % 256;
  return out;
}

describe("computeSectionEntropy", () => {
  it("is 0 for an empty buffer", () => {
    expect(computeSectionEntropy(new Uint8Array(0))).toBe(0);
  });

  it("is 0 for an all-zero buffer", () => {
    // One symbol with p=1: -1·log2(1) = 0.
    expect(computeSectionEntropy(repeated(0, 1024))).toBe(0);
  });

  it("is 0 for any single repeated byte, not just zero", () => {
    expect(computeSectionEntropy(repeated(0xff, 64))).toBe(0);
    expect(computeSectionEntropy(repeated(0x90, 3))).toBe(0);
  });

  it("is 0 for a single byte", () => {
    expect(computeSectionEntropy(new Uint8Array([0x42]))).toBe(0);
  });

  it("is exactly 1 for two equally frequent bytes", () => {
    // 2 symbols at p=0.5: -2·(0.5·log2 0.5) = 1.
    expect(computeSectionEntropy(new Uint8Array([0, 1, 0, 1, 1, 0, 1, 0]))).toBeCloseTo(1, 12);
  });

  it("is exactly 2 for four equally frequent bytes", () => {
    expect(computeSectionEntropy(new Uint8Array([0, 1, 2, 3]))).toBeCloseTo(2, 12);
  });

  it("is exactly 8 when all 256 byte values appear equally often", () => {
    // The maximum for a byte alphabet — the "packed/encrypted" signal.
    expect(computeSectionEntropy(allByteValues(1))).toBeCloseTo(8, 12);
    expect(computeSectionEntropy(allByteValues(4))).toBeCloseTo(8, 12);
  });

  it("matches the hand-computed value for a skewed distribution", () => {
    // 'a'×3, 'b'×1: -(0.75·log2 0.75 + 0.25·log2 0.25) = 0.811278124459…
    const bytes = new Uint8Array([97, 97, 97, 98]);
    expect(computeSectionEntropy(bytes)).toBeCloseTo(0.8112781244591328, 12);
  });

  it("depends on frequencies, not on byte order", () => {
    const ordered = new Uint8Array([1, 1, 1, 2, 3, 4]);
    const shuffled = new Uint8Array([3, 1, 4, 1, 2, 1]);
    expect(computeSectionEntropy(shuffled)).toBeCloseTo(computeSectionEntropy(ordered), 12);
  });

  it("never exceeds 8 bits for byte data", () => {
    const random = new Uint8Array(4096);
    for (let i = 0; i < random.length; i++) random[i] = (i * 7919) % 256;
    const h = computeSectionEntropy(random);
    expect(h).toBeGreaterThan(7.9);
    expect(h).toBeLessThanOrEqual(8);
  });
});

describe("computeEntropyBlocks", () => {
  it("returns no blocks for an empty buffer", () => {
    expect(computeEntropyBlocks(new Uint8Array(0))).toEqual([]);
  });

  it("returns one block per full blockSize window", () => {
    expect(computeEntropyBlocks(repeated(0, 1024), 256)).toHaveLength(4);
  });

  it("emits a final short block rather than dropping the tail", () => {
    // 300 bytes at blockSize 256 → a 256-byte block and a 44-byte block.
    const bytes = new Uint8Array(300);
    for (let i = 256; i < 300; i++) bytes[i] = i % 2; // tail: two values, equally often
    const blocks = computeEntropyBlocks(bytes, 256);

    expect(blocks).toHaveLength(2);
    expect(blocks[0]).toBe(0); // all zeroes
    // 22×0 and 22×1 over a length of 44 — normalized by 44, not by 256.
    expect(blocks[1]).toBeCloseTo(1, 12);
  });

  it("normalizes a lone trailing byte by 1, giving entropy 0", () => {
    const bytes = new Uint8Array(5);
    bytes[4] = 0xff;
    const blocks = computeEntropyBlocks(bytes, 4);
    expect(blocks).toHaveLength(2);
    expect(blocks[1]).toBe(0);
  });

  it("scores each block independently", () => {
    // Block 0: uniform (entropy 0). Block 1: all 256 values once (entropy 8).
    const bytes = new Uint8Array(512);
    for (let i = 256; i < 512; i++) bytes[i] = i - 256;
    const blocks = computeEntropyBlocks(bytes, 256);

    expect(blocks[0]).toBe(0);
    expect(blocks[1]).toBeCloseTo(8, 12);
  });

  it("defaults to a 256-byte block", () => {
    expect(computeEntropyBlocks(repeated(1, 512))).toHaveLength(2);
    expect(computeEntropyBlocks(repeated(1, 512), 256)).toHaveLength(2);
  });

  it("treats a buffer shorter than one block as a single block", () => {
    const blocks = computeEntropyBlocks(new Uint8Array([0, 1]), 256);
    expect(blocks).toHaveLength(1);
    expect(blocks[0]).toBeCloseTo(1, 12);
  });

  it("agrees with computeSectionEntropy when the block spans the whole buffer", () => {
    const bytes = allByteValues(2);
    expect(computeEntropyBlocks(bytes, bytes.length)[0]).toBeCloseTo(
      computeSectionEntropy(bytes),
      12,
    );
  });

  it("respects a subarray view rather than reading the whole backing buffer", () => {
    const backing = new Uint8Array(64);
    backing.fill(0xaa, 0, 32);
    backing.fill(0, 32);
    // Uint8Array indexing is view-relative; a bug reading .buffer directly would
    // see the zero half too and report a non-zero entropy.
    expect(computeEntropyBlocks(backing.subarray(0, 32), 32)).toEqual([0]);
  });
});

describe("classifyEntropy", () => {
  it.each([
    [0, "empty"],
    [0.999, "empty"],
    [1, "low - data/code"],
    [3.999, "low - data/code"],
    [4, "normal - code"],
    [6.499, "normal - code"],
    [6.5, "high - compressed?"],
    [7.499, "high - compressed?"],
    [7.5, "very high - packed/encrypted?"],
    [8, "very high - packed/encrypted?"],
  ])('classifies %d as "%s"', (value, label) => {
    expect(classifyEntropy(value).label).toBe(label);
  });

  it("assigns every band a distinct colour class", () => {
    const colors = [0, 2, 5, 7, 8].map((v) => classifyEntropy(v).color);
    expect(new Set(colors).size).toBe(5);
  });

  it("classifies a negative value as empty", () => {
    expect(classifyEntropy(-1).label).toBe("empty");
  });

  it("falls through to the top band for NaN", () => {
    // Characterization: every `<` comparison against NaN is false, so a NaN
    // average is reported as packed/encrypted. Callers should not feed it NaN.
    expect(classifyEntropy(Number.NaN).label).toBe("very high - packed/encrypted?");
  });
});
