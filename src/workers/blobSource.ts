/**
 * Handing a worker the `File` instead of a copy of its bytes.
 *
 * A large byte argument reaches a worker one of two ways, and the difference is
 * the whole of this module:
 *
 * - An `ArrayBuffer` has to be **copied** before it is posted
 *   (`./transfer.ts`'s `prepareBinaryArgs`, measured at 0.38-0.43 ms per MiB and
 *   flat from 8 MiB to 200 MiB, so ~96-101 ms for a 253 MiB image), and that
 *   copy runs on the main thread — which is the thread whose responsiveness is
 *   the only reason any of this work is off-thread in the first place.
 * - A `Blob` — and therefore the `File` a drop or a file picker produces — is
 *   structured-cloneable **by reference**, so posting one is O(1) at any size
 *   and the *worker* reads the bytes itself with `Blob.arrayBuffer()`.
 *
 * So this does not make the work smaller; it moves it off the thread that must
 * stay responsive. Say it that way round: the bytes are still read once, just
 * not here.
 *
 * ## Why the ArrayBuffer arm is the common case and not a fallback
 *
 * Only the drop/browse path has a `File` at all. `loadRecentFile()` hands back
 * an `ArrayBuffer` out of IndexedDB and the bundled demo binary arrives via
 * `fetch().arrayBuffer()`, so two of the three load paths have nothing to
 * register and keep copying exactly as they always did. A change that made the
 * Blob path unconditional would break both of them, which is why registration
 * is optional and `sourceFor` answers with the buffer when there is nothing
 * registered.
 *
 * ## Why one declaration
 *
 * `metricsClient.ts` (peek-a-bin-ex2) and `disasmClient.ts` (peek-a-bin-736)
 * both ask the same two questions — "do I have a handle for these bytes" and
 * "may I trust it" — and `metricsDispatch.ts` and `dispatch.ts` both ask the
 * third, "resolve this to bytes". Two copies of a rule that must not disagree
 * is the shape `sections.ts`, `ripRelative.ts`, `funcInsns.ts` and
 * `stackIdiom.ts` each exist to end, so the rule lives here and each client owns
 * only its own registry. Separate registries are deliberate: whether a client
 * has been told about a handle is a fact about that client's wiring, and a
 * shared instance would make the second `registerSourceBlob` call in `App.tsx`
 * decoration rather than a load-bearing line.
 *
 * This module imports nothing, so it adds no edge anywhere — including into the
 * metrics worker's import graph, which is deliberately free of anything that
 * reaches `capstone-wasm`.
 */

/**
 * A binary RPC argument that may arrive as either the bytes or a handle to
 * them.
 *
 * Always a **top-level** property of an args object: `prepareBinaryArgs` copies
 * and transfers only top-level binary values, so nesting one would silently
 * fall back to a structured clone of the whole file. A `Blob` is neither an
 * `ArrayBuffer` nor a view, so it passes through that function untouched — which
 * is pinned in `__tests__/transfer.test.ts`, because a future deep walk there
 * could not *copy* a Blob but could very plausibly drop it.
 */
export type BinarySource = ArrayBuffer | Blob;

/**
 * One client's record of "these bytes came from this `Blob`".
 *
 * Keyed on the buffer, **weakly**, so a registration needs no teardown: the
 * `Blob` stays reachable exactly as long as the buffer it describes and becomes
 * garbage with it. That is also why `App.tsx` need not hold the `File` in a ref
 * or in `AppState` — the association *is* the storage.
 */
export class BlobSourceRegistry {
  private blobs = new WeakMap<ArrayBuffer, Blob>();

  /** `label` prefixes the mismatch warning, e.g. `"metrics worker"`. */
  constructor(private readonly label: string) {}

  /**
   * Record that `buffer` holds exactly the bytes of `blob`.
   *
   * Deliberately fire-and-forget: with no registration the caller posts the
   * buffer exactly as it always did (see the module docstring on why that is
   * the common case rather than a fallback).
   */
  register(buffer: ArrayBuffer, blob: Blob): void {
    this.blobs.set(buffer, blob);
  }

  /**
   * What to post for `buffer`: the registered `Blob` if there is one and it
   * looks like the right one, else the buffer itself.
   *
   * The size test is a **wiring** check, and it is worth being precise about
   * what it can and cannot catch. It catches the class of defect where the
   * wrong `File` is paired with a buffer — a stale closure, a mis-ordered
   * argument, the previous load's handle — because that mismatch is
   * overwhelmingly a length mismatch, and taking the Blob path there would
   * answer one file's question from another file's bytes. It does **not** catch
   * a same-length change to the file on disk after loading: `Blob.size` is the
   * snapshot state captured when the `File` was created, not a fresh `stat`.
   * The File API's answer to that case is that the *read* must fail with a
   * `NotReadableError` rather than silently return the new bytes, and a failed
   * read surfaces as a rejected request, which every caller here already
   * handles. So the residual risk is a user agent that ignores its snapshot
   * state, not something this check could have found.
   *
   * It is also O(1) — one integer comparison, no read — which is what puts this
   * scheme on the right side of `./transfer.ts`'s rule that *the key comparison
   * must be cheaper than the work it saves*. There is no cached answer here at
   * all: the handle is re-read on every call, so the stale-hit class that
   * refused `peek-a-bin-9a8`'s content-vs-identity key cannot arise.
   */
  sourceFor(buffer: ArrayBuffer): BinarySource {
    const blob = this.blobs.get(buffer);
    if (!blob) return buffer;
    if (blob.size !== buffer.byteLength) {
      console.warn(
        `[${this.label}] registered blob size does not match the loaded buffer; copying instead`,
      );
      return buffer;
    }
    return blob;
  }
}

/**
 * Resolve a posted source to bytes, on the worker thread.
 *
 * The `Blob` read is the whole point of accepting one: it happens here, so the
 * main thread paid nothing but an O(1) `postMessage`. It is also the reason both
 * worker dispatches are `async`.
 *
 * The test is for Blob-ness rather than for `ArrayBuffer`-ness on purpose. A
 * structured clone rebuilds the value in *this* realm, so `instanceof` is sound
 * either way here — but if it ever were not, an unrecognised value falling
 * through to the `ArrayBuffer` arm is the pre-existing behaviour, while falling
 * through to the Blob arm would call `.arrayBuffer()` on something that has no
 * such method.
 */
export async function bytesOf(source: BinarySource): Promise<ArrayBuffer> {
  return source instanceof Blob ? await source.arrayBuffer() : source;
}
