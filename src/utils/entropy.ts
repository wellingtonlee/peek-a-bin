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

/**
 * **Device** pixels each block gets on the strip.
 *
 * It was CSS pixels until `peek-a-bin-424o`, which is half the detail the strip
 * can physically show: at `devicePixelRatio` 2 every bar occupied four device
 * pixels of a backing store {@link entropyStripGeometry} already sizes in device
 * pixels, so the strip drew a thousand-odd bars onto two thousand-odd pixels.
 * The reason the earlier work chose CSS pixels was cost — a device-pixel budget
 * doubles the block count on every HiDPI machine — and that reason was measured
 * before this changed rather than assumed away:
 *
 * - **On every real binary in the corpus it costs nothing at all.** The budget
 *   only bites through {@link entropyBlockSizeFor}, which cannot go below its
 *   256-byte floor, so a section under `256 * budget` bytes yields the same
 *   blocks at any budget. The largest section on any of the six corpus binaries
 *   is 110 KiB (`t64-arm`'s `.text`), and the four budgets 512/1024/2048/4096
 *   produce byte-identical block counts, and times within noise, on all 34 of
 *   them.
 * - **It cannot push new work onto the main thread.** `MAX_SYNC_ENTROPY_BLOCK_BYTES`
 *   is a threshold on *bytes*, and it was calibrated at exactly that 256-byte
 *   floor — so the worst case on the synchronous path is unchanged by any
 *   budget. Measured cost of a 256 KiB section (the threshold itself) went
 *   1.82 ms → 3.67 ms for 512 → 1024 blocks and no further, since 1024 blocks
 *   *is* the floor at that size. 4096 blocks needs a section of 1 MiB, four
 *   times past the threshold, so the bead's worst case is unreachable
 *   synchronously by construction.
 * - **In the worker the marginal cost converges to nothing**, because the byte
 *   walk is O(n) and only the per-block 256-entry log2 sweep scales with the
 *   budget: 512 → 4096 blocks costs +176% at 1 MiB, +116% at 4 MiB, +46% at
 *   16 MiB, +13% at 64 MiB and +4.7% at 253 MiB (471 → 493 ms).
 *
 * Node 22 on this machine at `e22ba6e`, median of 3–9 runs, real section bytes
 * and — above 128 KiB — real bytes tiled to size. Rates are machine- and
 * engine-dependent exactly as `asyncMetricState.ts` says; the shape of the
 * curve is the claim, not the milliseconds.
 *
 * The draw uses the same number, via {@link entropyStripGeometry}'s
 * `blockWidth`. At 2 device pixels a bar is `2 / dpr` CSS pixels wide, so it
 * still covers about two device pixels after `Math.ceil` rounds the rect up to
 * whole CSS pixels — which is why the budget is in *pairs* of device pixels
 * rather than single ones.
 */
export const ENTROPY_STRIP_BLOCK_DEVICE_PX = 2;

/** Height of the strip in CSS pixels. The canvas element is styled to match. */
export const ENTROPY_STRIP_HEIGHT_PX = 12;

/** Width step at which the block budget changes. See {@link entropyBlocksForWidth}. */
export const ENTROPY_WIDTH_QUANTUM = 64;

/**
 * Block-count budget for a strip `deviceWidth` **device** pixels wide — the
 * product of its CSS width and `devicePixelRatio`; see {@link stripDeviceWidth}.
 *
 * {@link MAX_ENTROPY_BLOCKS} bounds the pathological case, but it is not the
 * *right* number: a canvas about a thousand pixels wide can show a thousand-odd
 * bars, so 4096 blocks is still four to eight times more than the strip can
 * draw, and every one of them costs a histogram pass. The right granularity is
 * the canvas's own width, which is known only at draw time — hence this
 * function and the `ResizeObserver` in `HexView`.
 *
 * The unit is device pixels because that is the unit the backing store is sized
 * in ({@link entropyStripGeometry}); passing a CSS width here asks for half the
 * blocks the strip can show on a 2x display. See
 * {@link ENTROPY_STRIP_BLOCK_DEVICE_PX} for what that costs, measured.
 *
 * The result is **quantized to {@link ENTROPY_WIDTH_QUANTUM}** rather than
 * debounced. A debounce needs a timer, a stale-value window and a decision
 * about what to show meanwhile; rounding up to a coarse step means a drag that
 * changes the width by a few pixels does not change the answer at all, so there
 * is nothing to debounce. Dragging a pane across a whole step does recompute,
 * which is the intended behaviour: the strip really does have more pixels now.
 * Note the quantum is in device pixels too, so on a 2x display the step is half
 * as many CSS pixels — which is the point, and why `nextStripWidth` has to
 * compare *device* widths or it swallows a resize that does change the budget.
 */
export function entropyBlocksForWidth(
  deviceWidth: number,
  blockPx = ENTROPY_STRIP_BLOCK_DEVICE_PX,
  maxBlocks = MAX_ENTROPY_BLOCKS,
): number {
  if (!Number.isFinite(deviceWidth) || deviceWidth <= 0) return MIN_ENTROPY_BLOCKS;
  const wanted = Math.ceil(deviceWidth / blockPx);
  const quantized = Math.ceil(wanted / ENTROPY_WIDTH_QUANTUM) * ENTROPY_WIDTH_QUANTUM;
  return Math.min(maxBlocks, Math.max(MIN_ENTROPY_BLOCKS, quantized));
}

/**
 * The width to store after the strip measures `measured` **device** pixels,
 * given the `prev` stored width. Returning `prev` unchanged is how a resize is
 * made not to re-render.
 *
 * Device pixels, not CSS pixels, because that is the unit
 * {@link entropyBlocksForWidth} works in — comparing CSS widths would compare at
 * a coarser step than the budget actually moves at on a HiDPI display, and a
 * resize that does change the block count would be swallowed.
 *
 * The stored width feeds {@link entropyBlocksForWidth}, and that answer is
 * quantized — so a drag that moves the strip by a few pixels does not change the
 * block count and there is no reason to put React through a render for it.
 * Keeping the *old* width when the budget is unchanged is what makes the
 * `ResizeObserver`'s `setState` a no-op by identity rather than by value.
 *
 * Two cases the equality alone gets wrong:
 *
 * - `prev === 0` is the *unmeasured* state, not a width. A strip narrow enough
 *   to land on the minimum budget — which an unmeasured one also does — would
 *   otherwise stay at 0 forever, and 0 is what keeps the strip switched off.
 * - a non-finite or negative measurement is not a width either. It reaches
 *   `entropyBlockSizeFor` as a NaN block size, i.e. an empty strip with no error
 *   reported anywhere, so it is discarded rather than stored.
 *
 * Note this is only about *recomputing blocks*. Redrawing the canvas at the new
 * size is a separate question with a separate answer — the draw effect observes
 * the element directly, because a sub-quantum resize still has to repaint or the
 * browser stretches the old backing store (peek-a-bin-oqp).
 */
export function nextStripWidth(prev: number, measured: number): number {
  if (!Number.isFinite(measured) || measured < 0) return prev;
  if (prev === 0) return measured;
  return entropyBlocksForWidth(prev) === entropyBlocksForWidth(measured) ? prev : measured;
}

/**
 * A media query that matches exactly the given device pixel ratio.
 *
 * `devicePixelRatio` has no change event and is not observable any other way: a
 * `ResizeObserver` reports CSS pixels, so moving a window to a display of a
 * different density — same CSS layout, twice the physical pixels — fires
 * nothing at all. The one signal available is a media query that *names the
 * current ratio*, which stops matching the moment the ratio changes. That makes
 * it single-use by construction, so the listener has to be re-armed from the new
 * ratio each time it fires.
 *
 * `dpr` is sanitised the same way {@link entropyStripGeometry} sanitises it, and
 * for the same reason: some embedded webviews report 0 or `undefined`, and
 * `(resolution: NaNdppx)` is not a valid query — `matchMedia` does not throw on
 * one, it returns a list that never matches and never fires, i.e. the listener
 * would be silently dead rather than obviously broken.
 */
export function dprMediaQuery(dpr: number): string {
  return `(resolution: ${safeDpr(dpr)}dppx)`;
}

/**
 * The ratio to actually use, given whatever `window.devicePixelRatio` reported.
 *
 * One definition for all three readers — the media query, the backing-store
 * size and the block budget — because a ratio sanitised differently in two
 * places means arming a listener for one ratio and drawing at another.
 */
function safeDpr(dpr: number): number {
  return Number.isFinite(dpr) && dpr > 0 ? dpr : 1;
}

/**
 * The strip's width in device pixels: what {@link entropyBlocksForWidth} and
 * {@link nextStripWidth} both take.
 *
 * A `ResizeObserver` reports CSS pixels and `devicePixelRatio` is read
 * separately, so this is the one place the two are combined. Not rounded — the
 * budget is quantized to {@link ENTROPY_WIDTH_QUANTUM} blocks anyway, and
 * `nextStripWidth` stores the value it was given so a fractional ratio must
 * survive the round trip unchanged or a repeated measurement re-renders.
 *
 * Only the *ratio* is sanitised. A nonsense CSS width is deliberately allowed
 * through as a nonsense device width, so that `nextStripWidth` still gets to
 * discard it: collapsing a NaN measurement to 0 here would make it a *valid*
 * width that switches the strip off, which is the one thing 0 already means.
 */
export function stripDeviceWidth(cssWidth: number, dpr: number): number {
  return cssWidth * safeDpr(dpr);
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
 * The same product is now the block budget's input, and it needs no cap of its
 * own either: {@link MAX_ENTROPY_BLOCKS} already bounds it, and a 3x display
 * reaches that ceiling at about 2690 CSS pixels of strip.
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
  const scale = safeDpr(dpr);
  const safeWidth = Number.isFinite(cssWidth) && cssWidth > 0 ? cssWidth : 0;
  const safeHeight = Number.isFinite(cssHeight) && cssHeight > 0 ? cssHeight : 0;
  return {
    deviceWidth: Math.max(1, Math.round(stripDeviceWidth(safeWidth, dpr))),
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
