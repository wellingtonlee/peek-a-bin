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
 * `buffer` is deliberately a top-level property: `prepareBinaryArgs` copies and
 * transfers only top-level binary values, so nesting it would silently fall
 * back to a structured clone of the whole file.
 */
export interface FileMetricsArgs {
  buffer: ArrayBuffer;
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
 * Checksum and per-section entropy are answered by one method because both
 * walk essentially the whole file, and the argument copy — not the arithmetic
 * — is the only main-thread cost left. Splitting them would pay that copy
 * twice for a user who opens both the Headers and the Sections tab.
 */
export function metricsDispatch(method: MetricsMethod, args: unknown): unknown {
  switch (method) {
    case "fileMetrics": {
      const a = args as FileMetricsArgs;
      return {
        checksum: checksumFile(a.buffer, a.peHeaderOffset, a.expectedChecksum),
        sectionEntropies: computeSectionEntropies(a.buffer, a.ranges ?? []),
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
