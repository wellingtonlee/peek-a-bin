/**
 * RPC dispatch for the whole-file metrics worker.
 *
 * Separated from `metrics.worker.ts` for the same reason `dispatch.ts` is
 * separated from `disasm.worker.ts`: the worker module touches `self` and
 * cannot be imported under vitest, which would leave the routing and the
 * unknown-method branch with no runtime coverage. Everything here is pure and
 * side-effect free at module scope.
 *
 * ## Why a second worker rather than two more cases in `dispatch.ts`
 *
 * The disasm worker services messages serially, and the analysis pipeline
 * hands it whole-image `detectFunctions` / `hybridDisassemble` calls that run
 * for seconds to minutes on a large PE — `disasmClient.ts`'s own
 * `REQUEST_TIMEOUT_MS` docstring says as much ("a cheap call can sit queued
 * behind a whole-image `hybridDisassemble` for minutes"). Opening the Headers
 * tab during analysis is exactly that case, so a checksum posted into that
 * queue would trade a 100 ms freeze for a minutes-long spinner. This worker
 * holds no state, loads no WASM, and answers immediately.
 *
 * It also keeps `dispatch.ts`'s stated invariant intact — nothing in this
 * module's import graph reaches `capstone-wasm`, and nothing in that one needs
 * to grow a dependency on PE metadata.
 */

import { type ChecksumResult, checksumFile } from "../pe/metadata";
import type { PEFile } from "../pe/types";
import { type ByteRange, computeEntropyBlocks, computeSectionEntropies } from "../utils/entropy";

export type MetricsMethod = "fileMetrics" | "entropyBlocks";

export interface MetricsRequest {
  id: number;
  method: MetricsMethod;
  args: unknown;
}

/**
 * Arguments for `fileMetrics`.
 *
 * `source` is deliberately a top-level property: `prepareBinaryArgs` copies and
 * transfers only top-level binary values, so nesting it would silently fall
 * back to a structured clone of the whole file.
 *
 * ## Why the type is a union and not just an `ArrayBuffer`
 *
 * A `Blob` — and therefore the `File` the drop/open handler receives — is
 * structured-cloneable **by reference**, so posting one is O(1) regardless of
 * size and the worker reads the bytes itself via `Blob.arrayBuffer()`, entirely
 * off the main thread. An `ArrayBuffer` has to be copied before it is posted
 * (`prepareBinaryArgs`, ~0.4 ms/MiB, measured ~100 ms for a 253 MiB file), which
 * is the last main-thread cost in this path.
 *
 * The `ArrayBuffer` arm is **not** legacy: two of the three load paths have no
 * `File` at all — `loadRecentFile()` hands back an `ArrayBuffer` out of
 * IndexedDB and the demo binary arrives via `fetch().arrayBuffer()` — so it is
 * the common case, not a fallback that only fires on old browsers. Whichever
 * arm is used, the answer must be identical; `__tests__/metricsDispatch.test.ts`
 * asserts that byte for byte over the same fixture.
 *
 * A `Blob` is neither an `ArrayBuffer` nor a view, so `prepareBinaryArgs`
 * passes it through untouched and transfers nothing — pinned in
 * `__tests__/transfer.test.ts`, because a future deep-walk there could not
 * copy a Blob but could very plausibly drop it.
 */
export interface FileMetricsArgs {
  source: ArrayBuffer | Blob;
  /** `dosHeader.e_lfanew`. */
  peHeaderOffset: number;
  /** `optionalHeader.checksum`. */
  expectedChecksum: number;
  /** Raw-data window of each section, in section-table order. */
  ranges: ByteRange[];
}

export interface FileMetricsResult {
  checksum: ChecksumResult;
  /** One entry per entry of `ranges`, same order. */
  sectionEntropies: number[];
}

/**
 * The `ranges` every `fileMetrics` caller sends: each section's raw-data window,
 * in section-table order.
 *
 * One function rather than one per caller, because `metricsClient` caches the
 * result **per buffer and not per argument list** — the Headers tab, the
 * Sections tab and the anomaly pass all share whichever request went first, so
 * two callers disagreeing about the ranges would silently serve one of them the
 * other's answer. Section-table order is also the contract `detectAnomalies`
 * indexes `sectionEntropies` by.
 */
export function sectionRanges(pe: PEFile): ByteRange[] {
  return pe.sections.map((s) => ({ offset: s.pointerToRawData, length: s.sizeOfRawData }));
}

export interface EntropyBlocksArgs {
  bytes: Uint8Array;
  blockSize: number;
}

/**
 * Resolve a `fileMetrics` source to bytes.
 *
 * The `Blob` read is the whole point of accepting one: it happens here, on the
 * worker thread, so the main thread paid nothing but an O(1) postMessage. It is
 * also the only asynchronous step in this module, and the reason
 * {@link metricsDispatch} is `async`.
 *
 * The test is for Blob-ness rather than for `ArrayBuffer`-ness on purpose. A
 * structured clone rebuilds the value in *this* realm, so `instanceof` is sound
 * either way here — but if it ever were not, an unrecognised value falling
 * through to the `ArrayBuffer` arm is the pre-existing behaviour, while falling
 * through to the Blob arm would call `.arrayBuffer()` on something that has no
 * such method.
 */
async function bytesOf(source: ArrayBuffer | Blob): Promise<ArrayBuffer> {
  return source instanceof Blob ? await source.arrayBuffer() : source;
}

/**
 * Checksum and per-section entropy are answered by one method because both
 * walk essentially the whole file, and the argument copy — not the arithmetic
 * — is the only main-thread cost left. Splitting them would pay that copy
 * twice for a user who opens both the Headers and the Sections tab.
 *
 * Asynchronous only because a `Blob` source has to be read (see
 * {@link bytesOf}); every computation here is still a synchronous walk. The
 * unknown-method branch therefore *rejects* rather than throwing synchronously,
 * which is the same thing from `metrics.worker.ts`'s point of view — it awaits
 * inside the `try` — but is a visible difference to a direct caller.
 */
export async function metricsDispatch(method: MetricsMethod, args: unknown): Promise<unknown> {
  switch (method) {
    case "fileMetrics": {
      const a = args as FileMetricsArgs;
      const buffer = await bytesOf(a.source);
      return {
        checksum: checksumFile(buffer, a.peHeaderOffset, a.expectedChecksum),
        sectionEntropies: computeSectionEntropies(buffer, a.ranges ?? []),
      } satisfies FileMetricsResult;
    }

    case "entropyBlocks": {
      const a = args as EntropyBlocksArgs;
      return computeEntropyBlocks(a.bytes, a.blockSize);
    }

    default: {
      // Without this an unrecognized method posts `{ id, result: undefined }`
      // and the caller's promise resolves with undefined instead of failing.
      // The `never` binding makes a newly added method a compile error here.
      const _exhaustive: never = method;
      throw new Error(`Unknown metrics method: ${String(_exhaustive)}`);
    }
  }
}
