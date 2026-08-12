/**
 * Shannon entropy over byte ranges.
 *
 * Every function here is a linear walk over bytes and nothing else, so it is
 * safe to import from a Web Worker as well as from the UI — `metricsDispatch`
 * calls exactly these, and the main thread calls them directly for inputs small
 * enough that a round trip is not worth it (see `hooks/asyncMetricState.ts`).
 *
 * Measured cost on this machine (Node 18, synthetic 253 MiB PE, median of 5):
 * `computeSectionEntropy` runs at ~2.8 ms/MiB, `computeEntropyBlocks` at the
 * 256-byte default at ~17 ms/MiB — the per-block 256-entry log2 sweep, not the
 * histogram, is what makes the block form six times dearer.
 */

/** A window into a file buffer. Offsets are file offsets, not RVAs. */
export interface ByteRange {
  offset: number;
  length: number;
}

/**
 * Blocks the entropy strip is allowed to have.
 *
 * The strip is a canvas a thousand-odd pixels wide, so block counts past this
 * are invisible by construction: at 256 bytes per block a 200 MiB `.text` used
 * to produce 819200 blocks, which cost 3.4 s to compute and were then drawn as
 * 819200 `fillRect`s onto ~1000 px of canvas — roughly 800 rectangles per
 * pixel. Capping bounds both the computation and the draw, and nothing under
 * `MAX_ENTROPY_BLOCKS * 256` = 1 MiB is affected at all, which is every
 * section of every ordinary binary.
 */
export const MAX_ENTROPY_BLOCKS = 4096;

/** Never fewer than this many blocks, however narrow the strip is. */
export const MIN_ENTROPY_BLOCKS = 64;

/** CSS pixels each block gets on the strip. The draw uses the same number. */
export const ENTROPY_STRIP_BLOCK_PX = 2;

/** Height of the strip in CSS pixels. The canvas element is styled to match. */
export const ENTROPY_STRIP_HEIGHT_PX = 12;

/** Width step at which the block budget changes. See {@link entropyBlocksForWidth}. */
export const ENTROPY_WIDTH_QUANTUM = 64;

/**
 * Block-count budget for a strip `cssWidth` CSS pixels wide.
 *
 * {@link MAX_ENTROPY_BLOCKS} bounds the pathological case, but it is not the
 * *right* number: a canvas about a thousand pixels wide can show a thousand-odd
 * bars, so 4096 blocks is still four to eight times more than the strip can
 * draw, and every one of them costs a histogram pass. The right granularity is
 * the canvas's own width, which is known only at draw time — hence this
 * function and the `ResizeObserver` in `HexView`.
 *
 * The result is **quantized to {@link ENTROPY_WIDTH_QUANTUM}** rather than
 * debounced. A debounce needs a timer, a stale-value window and a decision
 * about what to show meanwhile; rounding up to a coarse step means a drag that
 * changes the width by a few pixels does not change the answer at all, so there
 * is nothing to debounce. Dragging a pane across a whole step does recompute,
 * which is the intended behaviour: the strip really does have more pixels now.
 */
export function entropyBlocksForWidth(
  cssWidth: number,
  blockPx = ENTROPY_STRIP_BLOCK_PX,
  maxBlocks = MAX_ENTROPY_BLOCKS,
): number {
  if (!Number.isFinite(cssWidth) || cssWidth <= 0) return MIN_ENTROPY_BLOCKS;
  const wanted = Math.ceil(cssWidth / blockPx);
  const quantized = Math.ceil(wanted / ENTROPY_WIDTH_QUANTUM) * ENTROPY_WIDTH_QUANTUM;
  return Math.min(maxBlocks, Math.max(MIN_ENTROPY_BLOCKS, quantized));
}

/** Backing-store size and draw scale for the entropy strip's canvas. */
export interface EntropyStripGeometry {
  /** `canvas.width` — the backing store, in device pixels. */
  deviceWidth: number;
  /** `canvas.height` — the backing store, in device pixels. */
  deviceHeight: number;
  /**
   * Factor for `ctx.setTransform(scale, 0, 0, scale, 0, 0)`, after which every
   * drawing coordinate is a CSS pixel again — the same unit the pointer
   * handlers work in, which is the point.
   */
  scale: number;
  /** Width of one block in CSS pixels. The exact quotient, never clamped. */
  blockWidth: number;
}

/**
 * Geometry for the entropy strip.
 *
 * The canvas is laid out by CSS (`w-full`, a fixed height), so its `width` and
 * `height` *attributes* only size the backing store. Setting them to the CSS
 * size — which is what this did before — gives one texel per CSS pixel, and on
 * a HiDPI display the browser then upscales that to the physical grid: the bars
 * come out soft and the 12 px strip loses its edges. Multiplying by
 * `devicePixelRatio` and scaling the context by the same factor gives a texel
 * per *device* pixel while leaving the drawing code in CSS pixels.
 *
 * `dpr` is not capped. `cssWidth * dpr` is by construction about the number of
 * physical pixels the strip occupies, and browser zoom that raises `dpr`
 * shrinks the CSS width in step, so the product stays bounded by the display.
 *
 * {@link blockWidth} is returned here rather than recomputed by each caller
 * because the draw and the hit test must use the *same* mapping. They did not
 * once: the draw clamped each bar to a 2 px minimum while the click handler
 * divided by the unclamped quotient, so past the point where the bars ran off
 * the right-hand edge the bar under the cursor was not the bar being reported.
 * See {@link entropyBlockAtX} for the inverse.
 */
export function entropyStripGeometry(
  cssWidth: number,
  cssHeight: number,
  blockCount: number,
  dpr: number,
): EntropyStripGeometry {
  const scale = Number.isFinite(dpr) && dpr > 0 ? dpr : 1;
  const safeWidth = Number.isFinite(cssWidth) && cssWidth > 0 ? cssWidth : 0;
  const safeHeight = Number.isFinite(cssHeight) && cssHeight > 0 ? cssHeight : 0;
  return {
    deviceWidth: Math.max(1, Math.round(safeWidth * scale)),
    deviceHeight: Math.max(1, Math.round(safeHeight * scale)),
    scale,
    blockWidth: blockCount > 0 ? safeWidth / blockCount : 0,
  };
}

/**
 * Index of the block at `x` CSS pixels from the strip's left edge, or -1 if `x`
 * falls outside it.
 *
 * The inverse of the draw performed with {@link entropyStripGeometry}'s
 * `blockWidth`, and the only mapping the pointer handlers are allowed to use.
 * Note it takes the strip's *CSS* width: the canvas backing store is bigger on
 * a HiDPI display, but `getBoundingClientRect()` and `MouseEvent.clientX` are
 * both in CSS pixels, so device pixels never enter the hit test.
 */
export function entropyBlockAtX(x: number, cssWidth: number, blockCount: number): number {
  const { blockWidth } = entropyStripGeometry(cssWidth, 0, blockCount, 1);
  if (blockWidth <= 0 || !Number.isFinite(x)) return -1;
  const idx = Math.floor(x / blockWidth);
  return idx >= 0 && idx < blockCount ? idx : -1;
}

/**
 * The block size to use for a range of `byteLength` bytes: `minBlockSize`
 * whenever that yields at most {@link MAX_ENTROPY_BLOCKS} blocks, and otherwise
 * the smallest multiple of `minBlockSize` that does.
 *
 * Kept a multiple of the minimum so block boundaries stay aligned to the same
 * grid at every size, and so callers can map a block index back to a file
 * offset by multiplication.
 */
export function entropyBlockSizeFor(
  byteLength: number,
  minBlockSize = 256,
  maxBlocks = MAX_ENTROPY_BLOCKS,
): number {
  if (byteLength <= minBlockSize * maxBlocks) return minBlockSize;
  return Math.ceil(byteLength / maxBlocks / minBlockSize) * minBlockSize;
}

export function computeEntropyBlocks(bytes: Uint8Array, blockSize = 256): number[] {
  const blocks: number[] = [];
  for (let i = 0; i < bytes.length; i += blockSize) {
    const end = Math.min(i + blockSize, bytes.length);
    const freq = new Uint32Array(256);
    for (let j = i; j < end; j++) freq[bytes[j]]++;
    const len = end - i;
    let entropy = 0;
    for (let k = 0; k < 256; k++) {
      if (freq[k] === 0) continue;
      const p = freq[k] / len;
      entropy -= p * Math.log2(p);
    }
    blocks.push(entropy);
  }
  return blocks;
}

export function computeSectionEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let entropy = 0;
  for (let k = 0; k < 256; k++) {
    if (freq[k] === 0) continue;
    const p = freq[k] / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/**
 * Entropy of each of `ranges`, in order, over `buffer`.
 *
 * One implementation for the synchronous small-file path, the worker and the
 * anomaly detector, so the three cannot disagree about a malformed range. A
 * section table is attacker-controlled and `pointerToRawData + sizeOfRawData`
 * past EOF is one of the commonest things a packer does, so nothing here
 * throws:
 *
 * - a range that **starts inside the buffer and overruns the end** is scored
 *   over the bytes that are actually there. Scoring it 0 instead would read as
 *   "empty" and, in `detectAnomalies`, would silently drop the high-entropy
 *   warning for exactly the truncated packed section the check exists to catch.
 * - a range that is empty, negative, or starts at or past the end has no bytes
 *   at all and scores 0.
 */
export function computeSectionEntropies(
  buffer: ArrayBuffer,
  ranges: readonly ByteRange[],
): number[] {
  return ranges.map((r) => {
    if (r.length <= 0 || r.offset < 0 || r.offset >= buffer.byteLength) return 0;
    const available = Math.min(r.length, buffer.byteLength - r.offset);
    return computeSectionEntropy(new Uint8Array(buffer, r.offset, available));
  });
}

export interface EntropyClassification {
  label: string;
  color: string;
}

export function classifyEntropy(avgEntropy: number): EntropyClassification {
  if (avgEntropy < 1.0) return { label: "empty", color: "text-gray-500" };
  if (avgEntropy < 4.0) return { label: "low - data/code", color: "text-green-400" };
  if (avgEntropy < 6.5) return { label: "normal - code", color: "text-blue-400" };
  if (avgEntropy < 7.5) return { label: "high - compressed?", color: "text-yellow-400" };
  return { label: "very high - packed/encrypted?", color: "text-red-400" };
}
