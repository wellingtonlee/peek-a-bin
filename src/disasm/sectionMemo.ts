/**
 * One derived value per code section, keyed on the section itself.
 *
 * Both worker-side decode memos in this tree — `Arm64SweepCache` (arm64.ts) and
 * `X86SweepCache` (linearSweep.ts) — are the same object: a single slot holding
 * what one `.text` decoded to, so that the several RPCs of one file load share
 * a decode instead of each paying for it. What they share is the *key rule*,
 * and it is the part that decides whether such a memo is sound at all, so there
 * is one declaration of it here rather than one per cache.
 *
 * ## The key is the bytes, and that is not a stylistic choice
 *
 * `src/workers/transfer.ts` states the rule these caches are judged by: **the
 * key comparison must be cheaper than the work it saves.** A content key costs
 * one linear pass over the section — measured at 1.4 ms per MiB, a JS byte loop
 * rather than a memcpy — and what it skips is a Capstone sweep of the same
 * bytes, ~1100 ms per MiB on x86 and ~1500 ms/MiB on A64. Just under three
 * orders of magnitude of margin (820x on the largest image here), so the compare
 * is free in the only sense that matters.
 *
 * The cheap alternative — `(ArrayBuffer, byteOffset, byteLength)` identity — is
 * refused, and `transfer.ts` records why at length: it is sound only while the
 * file buffer is never written in place, that invariant is a whole-app
 * convention no mechanism enforces, and the change that breaks it (making hex
 * editing cheap by patching the buffer rather than copying the section) is an
 * obvious one. A stale hit there is not a crash but a complete, plausible
 * disassembly of bytes the file no longer contains. A content key cannot
 * produce one, whatever anybody later does to the buffer.
 *
 * ## Three parts, because three things decide the answer
 *
 *  * **The bytes**, byte for byte. Two files may present the same section
 *    length at the same address — both real ARM64 binaries in the corpus base
 *    `.text` at 0x140001000 — so length and address cannot stand in for
 *    content.
 *  * **The load address**, because Capstone prints resolved branch targets and
 *    `[rip ± 0x..]` displacements, so the same bytes at a different base decode
 *    to different operand text.
 *  * **The decoder**, compared by identity. This is really the *mode*: x86-32
 *    and x86-64 disagree about what a byte string means, and the two handles are
 *    created once per worker and never replaced, so object identity separates
 *    them exactly and in O(1). ARM64 has a single handle, where this degenerates
 *    to a constant — kept anyway, because a memo that is sound only while its
 *    owner happens to have one decoder is sound by accident.
 *
 * ## What it is not
 *
 * Not an LRU and not a map. One slot: a session loads one image at a time, and
 * a second entry would double the retention this deliberately bounds. See
 * `X86SweepCache` for what a held sweep costs and what that was weighed
 * against.
 */

/** Byte-for-byte equality; short-circuits on the first difference. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a === b) return true;
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/**
 * A one-slot memo of something derived from a code section's bytes.
 *
 * `compute` runs on a miss and its result is stored. It is a callback rather
 * than a constructor argument so this module knows nothing about decoding —
 * and so a throwing decode stores nothing, which is what keeps a refused
 * section (`Arm64DecodeRateError`, `CapstoneUnavailableError`) from decaying
 * into a cached empty answer.
 */
export class SectionMemo<T> {
  private entry?: {
    bytes: Uint8Array;
    baseAddress: number;
    decoder: unknown;
    value: T;
  };

  /** The value for exactly these bytes at exactly this address, computed once. */
  get(bytes: Uint8Array, baseAddress: number, decoder: unknown, compute: () => T): T {
    const hit = this.entry;
    if (
      hit &&
      hit.baseAddress === baseAddress &&
      hit.decoder === decoder &&
      sameBytes(hit.bytes, bytes)
    ) {
      return hit.value;
    }
    const value = compute();
    this.entry = { bytes, baseAddress, decoder, value };
    return value;
  }

  /**
   * Forget the held section.
   *
   * Memory hygiene, not correctness: the content key above already makes a
   * stale hit impossible, so this only stops one file's decode from outliving
   * it in a session that goes on to load another.
   */
  clear(): void {
    this.entry = undefined;
  }
}
