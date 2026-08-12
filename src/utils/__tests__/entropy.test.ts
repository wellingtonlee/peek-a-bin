/**
 * Shannon entropy over byte buffers.
 *
 * Every expected value here is hand-computed from the definition
 * (H = -Σ p·log2 p) rather than snapshotted from the implementation, so a
 * regression in the frequency counting or the block windowing shows up as a
 * wrong number instead of a quietly updated baseline.
 */

import { describe, expect, it } from "vitest";
import {
  classifyEntropy,
  computeEntropyBlocks,
  computeSectionEntropies,
  computeSectionEntropy,
  ENTROPY_STRIP_BLOCK_PX,
  ENTROPY_STRIP_HEIGHT_PX,
  ENTROPY_WIDTH_QUANTUM,
  entropyBlockAtX,
  entropyBlockSizeFor,
  entropyBlocksForWidth,
  entropyStripGeometry,
  MAX_ENTROPY_BLOCKS,
  MIN_ENTROPY_BLOCKS,
} from "../entropy";

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

describe("entropyBlockSizeFor", () => {
  it("leaves the minimum block size alone while the count fits", () => {
    expect(entropyBlockSizeFor(0)).toBe(256);
    expect(entropyBlockSizeFor(256)).toBe(256);
    expect(entropyBlockSizeFor(256 * MAX_ENTROPY_BLOCKS)).toBe(256);
  });

  it("grows the block size past the cap so the count stays bounded", () => {
    // One byte past the point where 256-byte blocks would exceed the cap.
    const over = 256 * MAX_ENTROPY_BLOCKS + 1;
    expect(entropyBlockSizeFor(over)).toBe(512);
    expect(Math.ceil(over / entropyBlockSizeFor(over))).toBeLessThanOrEqual(MAX_ENTROPY_BLOCKS);
  });

  it("keeps the block count under the cap at every scale up to 4 GiB", () => {
    // The cap is what stops the strip computing — and the canvas drawing —
    // hundreds of blocks per pixel; a size that slipped past it would be
    // invisible except as a freeze.
    for (let len = 1; len <= 4 * 1024 ** 3; len *= 3) {
      const size = entropyBlockSizeFor(len);
      expect(Math.ceil(len / size)).toBeLessThanOrEqual(MAX_ENTROPY_BLOCKS);
    }
  });

  it("always returns a multiple of the minimum, so block boundaries stay aligned", () => {
    for (let len = 1; len <= 4 * 1024 ** 3; len *= 7) {
      expect(entropyBlockSizeFor(len) % 256).toBe(0);
    }
  });

  it("honours a caller-supplied minimum and cap", () => {
    expect(entropyBlockSizeFor(4096, 512, 4)).toBe(1024);
    expect(entropyBlockSizeFor(2048, 512, 4)).toBe(512);
  });
});

describe("computeSectionEntropies", () => {
  const buffer = (() => {
    const b = new ArrayBuffer(1024);
    const v = new Uint8Array(b);
    for (let i = 0; i < 256; i++) v[i] = i; // uniform: H = 8
    // rest stays zero: H = 0
    return b;
  })();

  it("returns one entropy per range, in order", () => {
    const out = computeSectionEntropies(buffer, [
      { offset: 0, length: 256 },
      { offset: 256, length: 256 },
    ]);
    expect(out).toHaveLength(2);
    expect(out[0]).toBeCloseTo(8, 12);
    expect(out[1]).toBe(0);
  });

  it("agrees with computeSectionEntropy on the same window", () => {
    expect(computeSectionEntropies(buffer, [{ offset: 4, length: 100 }])[0]).toBe(
      computeSectionEntropy(new Uint8Array(buffer, 4, 100)),
    );
  });

  it("scores a range that overruns the end over the bytes that are there", () => {
    // Not 0. `detectAnomalies` warns about a high-entropy code section, and a
    // packer truncating `sizeOfRawData` past EOF is exactly the case it is
    // looking at; scoring the section "empty" drops the warning. This is the
    // behaviour `analysis/anomalies.ts`'s own copy of the walk had before the
    // two were merged (peek-a-bin-vrl) — they had drifted.
    //
    // A buffer whose tail is varied, so "the bytes that are there" and "0" are
    // distinguishable: the shared `buffer` above is zero-filled past 256 and
    // scores 0 either way.
    const varied = new ArrayBuffer(300);
    const bytes = new Uint8Array(varied);
    for (let i = 0; i < bytes.length; i++) bytes[i] = i & 0xff;

    const overrun = computeSectionEntropies(varied, [{ offset: 256, length: 4096 }])[0];
    expect(overrun).toBe(computeSectionEntropy(new Uint8Array(varied, 256, 44)));
    expect(overrun).toBeGreaterThan(5);
  });

  it.each([
    ["an empty range", { offset: 0, length: 0 }],
    ["a negative length", { offset: 0, length: -1 }],
    ["a negative offset", { offset: -8, length: 16 }],
    ["an offset exactly at the end", { offset: 1024, length: 16 }],
    ["an offset past the end", { offset: 99999, length: 16 }],
  ])("scores %s as 0 rather than throwing", (_label, range) => {
    // Section tables are attacker-controlled; pointerToRawData + sizeOfRawData
    // past EOF is routine in packed samples.
    expect(computeSectionEntropies(buffer, [range])).toEqual([0]);
  });

  it("returns an empty array for no ranges", () => {
    expect(computeSectionEntropies(buffer, [])).toEqual([]);
  });
});

describe("entropyBlocksForWidth", () => {
  it("never asks for more blocks than the strip has room to draw", () => {
    // The bug this replaces: a fixed cap of 4096 blocks on a canvas ~1000 px
    // wide. Every block past the 500th was computed, then drawn off the right
    // edge of the canvas and never seen (peek-a-bin-5cr).
    for (const width of [320, 640, 800, 1024, 1280, 1920, 2560, 3840]) {
      const blocks = entropyBlocksForWidth(width);
      // The quantum is what lets this exceed width/2 slightly; bound it by the
      // step rather than pretending it is exact.
      expect(blocks).toBeLessThanOrEqual(width / ENTROPY_STRIP_BLOCK_PX + ENTROPY_WIDTH_QUANTUM);
      expect(blocks).toBeGreaterThanOrEqual(
        Math.min(width / ENTROPY_STRIP_BLOCK_PX, MAX_ENTROPY_BLOCKS),
      );
    }
  });

  it("is unchanged by a resize smaller than the quantum, so nothing needs debouncing", () => {
    const base = entropyBlocksForWidth(1024);
    for (let dx = -ENTROPY_STRIP_BLOCK_PX; dx <= 0; dx++) {
      expect(entropyBlocksForWidth(1024 + dx)).toBe(base);
    }
    // And it does move once the width crosses a whole step.
    expect(entropyBlocksForWidth(1024 + ENTROPY_WIDTH_QUANTUM * ENTROPY_STRIP_BLOCK_PX)).toBe(
      base + ENTROPY_WIDTH_QUANTUM,
    );
  });

  it("returns a whole number of quantum steps", () => {
    for (let w = 1; w < 4000; w += 7) {
      expect(entropyBlocksForWidth(w) % ENTROPY_WIDTH_QUANTUM).toBe(0);
    }
  });

  it("stays inside the fixed cap and the floor", () => {
    expect(entropyBlocksForWidth(100000)).toBe(MAX_ENTROPY_BLOCKS);
    expect(entropyBlocksForWidth(1)).toBe(MIN_ENTROPY_BLOCKS);
  });

  it.each([0, -1, Number.NaN, Number.POSITIVE_INFINITY])(
    "falls back to the floor for an unmeasured width (%s)",
    (width) => {
      // `HexView` starts at 0 before the ResizeObserver reports; a NaN or an
      // Infinity here would reach `entropyBlockSizeFor` and produce a NaN block
      // size, i.e. an empty strip with no error anywhere.
      expect(entropyBlocksForWidth(width)).toBe(MIN_ENTROPY_BLOCKS);
    },
  );

  it("feeds a block size that keeps the count within the budget", () => {
    // The two functions have to agree, or the point of the budget is lost.
    for (const width of [640, 1024, 1920]) {
      const budget = entropyBlocksForWidth(width);
      for (const len of [1024, 64 * 1024, 1024 * 1024, 200 * 1024 * 1024]) {
        const size = entropyBlockSizeFor(len, 256, budget);
        expect(Math.ceil(len / size)).toBeLessThanOrEqual(budget);
      }
    }
  });
});

describe("entropyStripGeometry", () => {
  it("sizes the backing store in device pixels, not CSS pixels", () => {
    // The bug (peek-a-bin-fwm): canvas.width was set to canvas.clientWidth, so
    // a 2x display got one texel per CSS pixel and upscaled the result.
    const geom = entropyStripGeometry(1000, ENTROPY_STRIP_HEIGHT_PX, 500, 2);
    expect(geom.deviceWidth).toBe(2000);
    expect(geom.deviceHeight).toBe(ENTROPY_STRIP_HEIGHT_PX * 2);
    expect(geom.scale).toBe(2);
  });

  it("leaves a 1x display exactly as it was", () => {
    const geom = entropyStripGeometry(1000, ENTROPY_STRIP_HEIGHT_PX, 500, 1);
    expect(geom.deviceWidth).toBe(1000);
    expect(geom.deviceHeight).toBe(ENTROPY_STRIP_HEIGHT_PX);
    expect(geom.scale).toBe(1);
  });

  it("rounds a fractional ratio to whole device pixels", () => {
    // 1.5 is what a 150%-scaled Windows display reports, and a fractional
    // canvas.width is truncated by the DOM rather than rounded.
    const geom = entropyStripGeometry(1001, ENTROPY_STRIP_HEIGHT_PX, 500, 1.5);
    expect(Number.isInteger(geom.deviceWidth)).toBe(true);
    expect(Number.isInteger(geom.deviceHeight)).toBe(true);
    expect(geom.deviceWidth).toBe(Math.round(1001 * 1.5));
  });

  it.each([0, -2, Number.NaN, Number.POSITIVE_INFINITY, undefined as unknown as number])(
    "falls back to 1x for a ratio of %s",
    (dpr) => {
      // window.devicePixelRatio is 0 or undefined in some embedded webviews and
      // in any non-browser environment; a NaN would reach canvas.width, which
      // throws, and take the whole hex view down with it.
      const geom = entropyStripGeometry(800, ENTROPY_STRIP_HEIGHT_PX, 400, dpr);
      expect(geom.scale).toBe(1);
      expect(geom.deviceWidth).toBe(800);
    },
  );

  it("never produces a zero-sized backing store", () => {
    // canvas.width = 0 is legal but getContext draws nothing, which would read
    // as "entropy is broken" rather than "the strip has not been measured yet".
    for (const width of [0, -5, Number.NaN]) {
      const geom = entropyStripGeometry(width, ENTROPY_STRIP_HEIGHT_PX, 64, 2);
      expect(geom.deviceWidth).toBeGreaterThanOrEqual(1);
      expect(geom.deviceHeight).toBeGreaterThanOrEqual(1);
    }
  });

  it("gives a block width independent of the device ratio", () => {
    // The draw runs under ctx.setTransform(scale, …), so its coordinates stay
    // in CSS pixels — the same unit the pointer handlers get from
    // getBoundingClientRect(). If blockWidth tracked dpr the bars would be
    // drawn at double width on a HiDPI display.
    for (const dpr of [1, 1.5, 2, 3]) {
      expect(entropyStripGeometry(1000, ENTROPY_STRIP_HEIGHT_PX, 500, dpr).blockWidth).toBe(2);
    }
  });

  it("reports a zero block width rather than Infinity for an empty strip", () => {
    expect(entropyStripGeometry(1000, ENTROPY_STRIP_HEIGHT_PX, 0, 2).blockWidth).toBe(0);
  });
});

describe("entropyBlockAtX", () => {
  it("inverts the draw for every block, at every ratio", () => {
    // The regression this pins: the draw clamped each bar to a 2 px minimum
    // while the hit test divided by the unclamped quotient, so the bar under
    // the cursor was not the bar reported. Hit-testing the centre of every
    // drawn bar must return that bar.
    for (const [width, blocks] of [
      [1000, 500],
      [1000, 4096],
      [317, 64],
      [1920, 960],
    ] as const) {
      const { blockWidth } = entropyStripGeometry(width, ENTROPY_STRIP_HEIGHT_PX, blocks, 2);
      for (let i = 0; i < blocks; i++) {
        expect(entropyBlockAtX(i * blockWidth + blockWidth / 2, width, blocks)).toBe(i);
      }
    }
  });

  it("covers the whole strip with no gaps", () => {
    const width = 640;
    const blocks = entropyBlocksForWidth(width);
    for (let x = 0; x < width; x += 0.5) {
      expect(entropyBlockAtX(x, width, blocks)).toBeGreaterThanOrEqual(0);
    }
  });

  it("rejects a position outside the strip", () => {
    expect(entropyBlockAtX(-1, 1000, 500)).toBe(-1);
    expect(entropyBlockAtX(1000, 1000, 500)).toBe(-1);
    expect(entropyBlockAtX(2000, 1000, 500)).toBe(-1);
    expect(entropyBlockAtX(Number.NaN, 1000, 500)).toBe(-1);
  });

  it("rejects everything when there are no blocks", () => {
    // entropyBlocks is empty until the worker answers; x / 0 is Infinity, and
    // Math.floor(Infinity) would index past the array.
    expect(entropyBlockAtX(10, 1000, 0)).toBe(-1);
  });
});
