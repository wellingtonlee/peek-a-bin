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
