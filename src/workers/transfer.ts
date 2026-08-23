/**
 * Binary argument handling for worker RPC.
 *
 * ## The problem this exists to solve
 *
 * Structured clone of an `ArrayBufferView` serialises its entire
 * `[[ViewedArrayBuffer]]`, not the view's window onto it. Every large byte
 * argument in this app is a view onto the *whole loaded file* —
 * `new Uint8Array(buffer, section.pointerToRawData, section.sizeOfRawData)` and
 * subarrays of that — so an untransferred `postMessage` copied the entire file
 * on every call, including for a 4 KiB single-function disassembly.
 *
 * Measured with node's `structuredClone` (the same algorithm `postMessage`
 * runs), 253 MiB file / 200 MiB `.text`:
 *
 * | call                            | cloned view | slice + transfer |
 * |---------------------------------|-------------|------------------|
 * | `detectFunctions(.text)`        | 182 ms      | 76 ms            |
 * | `disassemble(4 KiB function)`   | 178 ms      | ~0 ms            |
 * | whole-buffer argument           | 186 ms      | 96 ms            |
 *
 * The last row is the surprising one: slicing and transferring wins even when
 * the copy is byte-for-byte the same size, because a clone costs roughly two
 * passes over the bytes where a slice costs one memcpy (91 ms) plus O(1)
 * ownership transfer. So there is no size at which cloning is the better deal,
 * and no threshold below which this is skipped.
 *
 * ## Why it copies first instead of transferring the caller's buffer
 *
 * Transferring detaches on the sender side. The main thread keeps using the
 * file buffer — `bufferRef`, `pe.buffer`, HexView, entropy, string extraction —
 * so transferring what a caller handed us would detach the loaded file and turn
 * every later read into a hard failure. {@link prepareBinaryArgs} therefore
 * **only ever transfers buffers it allocated itself**, one `slice()` per call.
 * The caller's view and its backing buffer are never in the transfer list and
 * cannot be detached by this code. That invariant is what makes the whole
 * scheme safe, and it is what `__tests__/transfer.test.ts` pins.
 *
 * The copy is not overhead the old path avoided: a clone copied these bytes
 * too, just more of them and more slowly.
 *
 * ## Why it does not walk nested values
 *
 * Only *top-level* properties of the args object are considered. The
 * `instructions` argument is an `Instruction[]` whose every element carries a
 * `bytes` view onto its own 24-byte buffer (capstone-wasm builds them with
 * `HEAPU8.slice(...)`), so a deep walk would build a transfer list with one
 * entry per instruction. Measured on a 500k-instruction reply, transferring
 * per-instruction buffers took **80.6 s** against 1.6 s to just clone them —
 * transfer has meaningful per-entry cost and is a loss for small buffers. Those
 * tiny buffers are also individually cheap to clone precisely because they are
 * not views onto anything big, so there is nothing to win there anyway.
 *
 * ## Why the same region is copied again on every call, and stays that way
 *
 * One load ships `.text` to the worker **four** times — `detectFunctions`,
 * `buildAllXrefs`, `hybridDisassemble`, and `buildAllXrefs` again once string
 * extraction finishes — and each pays its own slice. `peek-a-bin-9a8` proposed
 * uploading each region once under a handle and naming it thereafter. It was
 * measured and REFUSED; do not rebuild it without new evidence, and read this
 * before deciding you have some.
 *
 * **The saving is between 0.008% and 0.09% of the work done on the very same
 * bytes, and that fraction does not improve with size.** Measured through the
 * real `dispatch` at `decbea4` (`npm run corpus:uploadcost -- <path>`), over the
 * four corpus binaries, both ARM64 binaries and a 669 KiB-`.text` Windows/amd64
 * PE from `go`:
 *
 * | image       | `.text` | 3 RPCs | ms/MiB | one copy  | 3 copies saved |
 * |-------------|---------|--------|--------|-----------|----------------|
 * | t32         |   54 K  |  353   |  6699  | 0.009 ms  | 0.0075%        |
 * | w64         |   54 K  |  191   |  3615  | 0.020 ms  | 0.0319%        |
 * | t64-arm     |  110 K  |  184   |  1713  | 0.046 ms  | 0.0746%        |
 * | w64-arm     |   98 K  |  142   |  1491  | 0.041 ms  | 0.0868%        |
 * | go x64      |  669 K  | 2236   |  3425  | 0.274 ms  | 0.0367%        |
 *
 * The last column is **size-invariant**, which is the whole argument: a slice
 * costs ~0.4 ms per MiB of section and the decoding it feeds costs ~1500-6700 ms
 * per MiB of the same section, and both are linear, so the ratio is a property
 * of the tool rather than of the file. Extrapolating it rather than the
 * milliseconds: at the 200 MiB `.text` the bead was written about, the saving is
 * ~0.23 s out of ~11 minutes of decoding — and `hybridDisassemble` alone is then
 * at or past `REQUEST_TIMEOUT_MS`, so that image cannot be analysed at all.
 *
 * The two ARM64 rows are the hostile case and were measured on purpose: there
 * `Arm64SweepCache` (peek-a-bin-kis) has already removed the Capstone work from
 * two of the three RPCs, so the denominator collapses and this is as good as the
 * trade ever gets. It is still under a tenth of one percent — and they are also
 * a preview of the x86 world *after* `peek-a-bin-x40u`, since that is the same
 * cache on the other architecture. So a future agent arriving with "the work is
 * much smaller now, is it worth it yet" already has the answer measured: no.
 *
 * **The bead's headline figure describes the cost this module already removed.**
 * "116-192 ms of memcpy per send" is the *cloned view* column of the table
 * above, i.e. the pre-`peek-a-bin-7mf` behaviour. What a send costs now is the
 * slice: 64-76 ms at 200 MiB on this machine, matching the `slice + transfer`
 * column. The available saving was always about half of what the bead claims.
 *
 * ### The part that cannot be made safe cheaply
 *
 * A handle scheme has to answer "are these the bytes I already hold", and there
 * are only two kinds of key:
 *
 *   * **Content** — `Arm64SweepCache`'s answer, byte-for-byte. Sound against
 *     anything, including an in-place patch. It costs a full linear pass over
 *     the section, which is *the very thing being saved*: a compare is not
 *     cheaper than a memcpy. So a content-keyed version of this saves nothing
 *     by construction.
 *   * **Identity** — the bead's sketch, `(ArrayBuffer, byteOffset, byteLength)`.
 *     O(1), and it is what makes the scheme worth anything. It is sound only
 *     while the file buffer is never written in place.
 *
 * That invariant holds today — audited: the only two writers of file-derived
 * bytes in the app are `useDisassemblyRows`, which applies hex patches to a
 * fresh `new Uint8Array(sectionBytes)`, and `HexView`'s download, which patches
 * a `pe.buffer.slice(0)` — and **nothing enforces it**. No type, no test, no
 * lint rule. The change that breaks it is an obvious one: making hex editing
 * cheap by writing a byte into the buffer instead of copying the whole section
 * per keystroke. After that, every later disassembly silently answers from the
 * pre-patch bytes — a complete, plausible, compiling disassembly of bytes the
 * file no longer contains, which is exactly the failure `Arm64SweepCache`'s
 * docstring refuses to risk and which no corpus gate can see (none of them
 * drives the worker at all).
 *
 * So the honest statement is not "a stale hit is unlikely". It is: **a stale hit
 * can be made impossible only by a key that costs more than the saving**, and
 * the cheap key is sound only by a whole-app convention that no mechanism keeps
 * true. The two in-tree caches both pass the test this one fails, and the test
 * is worth stating because it is what decides such a question generally — *the
 * key comparison must be cheaper than the work it saves*. `Arm64SweepCache`
 * spends ~0.4 ms/MiB of byte compare to skip ~1500 ms/MiB of Capstone, a margin
 * of four orders of magnitude; `CallSummaryCache` spends an O(1) token compare
 * to skip an ~18 ms build, and its key is exact because an `Instruction[]` is
 * minted fresh by a decode. Here the work saved *is* a linear pass over the
 * bytes, so there is no room underneath it for any key at all.
 *
 * ### Where the leverage actually is
 *
 * The same measurement says what to do instead. On x86 the section is not
 * merely re-*sent* four times, it is re-*decoded*: `detectFunctions`,
 * `hybridDisassemble` and both `buildAllXrefs` calls each open their own
 * `createScan` over the identical bytes. On the `go` image that is 792 + 757 +
 * 687 ms; on the ARM64 pair, where `peek-a-bin-kis` shares one sweep, the
 * second and third RPCs cost 13 and 21 ms against a 150 ms first. An x86
 * counterpart of that cache is worth ~1000 ms per MiB of `.text` — roughly a
 * thousand times this proposal — and it can afford a **content** key, because
 * there the compare is four orders of magnitude below what it skips. That is
 * `peek-a-bin-x40u`.
 */

/** An args object rewritten for posting, with the buffers it now owns. */
export interface PreparedArgs {
  /** The args to post. Identical to the input when nothing binary was found. */
  args: unknown;
  /** Buffers allocated by {@link prepareBinaryArgs}, safe to transfer. */
  transfer: ArrayBuffer[];
}

/**
 * Copy one value into a freshly allocated buffer, if it is binary.
 *
 * Returns `null` for anything else — including a `SharedArrayBuffer`, which is
 * not transferable and is already cheap to post.
 */
function copyBinary(value: unknown): { value: unknown; buffer: ArrayBuffer } | null {
  if (ArrayBuffer.isView(value)) {
    // DataView has no `slice`; copy the window out of the backing buffer.
    if (value instanceof DataView) {
      const buffer = value.buffer.slice(value.byteOffset, value.byteOffset + value.byteLength);
      return { value: new DataView(buffer), buffer };
    }
    // Typed arrays: `slice` copies just the view's window into a new buffer of
    // exactly that length, and preserves the element type.
    const copy = (value as Uint8Array).slice();
    return { value: copy, buffer: copy.buffer as ArrayBuffer };
  }
  if (value instanceof ArrayBuffer) {
    const copy = value.slice(0);
    return { value: copy, buffer: copy };
  }
  return null;
}

/**
 * Rewrite an RPC args object so its binary members can be transferred.
 *
 * Each top-level `ArrayBuffer` / `ArrayBufferView` value is replaced by a
 * private copy holding exactly that view's bytes, and that copy's buffer is
 * returned in `transfer`. The input object is not mutated and the caller's
 * buffers are never transferred — see the module docstring.
 *
 * Throws `TypeError` if a value is already detached, which is what `slice`
 * does; the caller posts inside a `try` so this surfaces as a rejected request
 * rather than a synchronous throw (an untransferred post would have thrown
 * `DataCloneError` on the same input).
 */
export function prepareBinaryArgs(args: unknown): PreparedArgs {
  if (args === null || typeof args !== "object" || Array.isArray(args)) {
    return { args, transfer: [] };
  }

  const source = args as Record<string, unknown>;
  let rewritten: Record<string, unknown> | undefined;
  const transfer: ArrayBuffer[] = [];

  for (const key of Object.keys(source)) {
    const copied = copyBinary(source[key]);
    if (!copied) continue;
    // Copy-on-first-hit: an args object with nothing binary in it is posted
    // as-is, so the common small calls allocate nothing extra.
    rewritten ??= { ...source };
    rewritten[key] = copied.value;
    transfer.push(copied.buffer);
  }

  return { args: rewritten ?? args, transfer };
}
