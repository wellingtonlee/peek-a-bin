/**
 * Whole-file metrics — checksum, per-section entropy, the hex entropy strip —
 * computed inline for small inputs and in `metrics.worker.ts` for large ones.
 *
 * These were four `useMemo`s in HeaderView / SectionTable / HexView. A
 * `useMemo` cannot yield, so on a 253 MiB image opening a tab froze the main
 * thread outright, with no spinner to show for it. The API change is the point:
 * a value becomes an {@link AsyncMetric}, and every consumer has to say what it
 * renders while loading and what it renders on failure.
 *
 * All the decisions live in `asyncMetricState.ts` — the threshold, the
 * stale-reply guard and the render-time resolution — because nothing in this
 * repo can mount a hook. What is left here is wiring.
 */

import { useEffect, useMemo, useReducer, useRef } from "react";
import { validateChecksum } from "../pe/metadata";
import type { PEFile } from "../pe/types";
import {
  computeEntropyBlocks,
  computeSectionEntropies,
  entropyBlockSizeFor,
  MAX_ENTROPY_BLOCKS,
} from "../utils/entropy";
import { metricsWorker } from "../workers/metricsClient";
// `sectionRanges` is shared with the anomaly pass in `App.tsx`: the client
// caches `fileMetrics` per buffer and not per argument list, so two callers
// with different ranges would serve each other's answers. See its docstring.
import { type FileMetricsResult, sectionRanges } from "../workers/metricsDispatch";
import {
  type AsyncMetric,
  type AsyncMetricAction,
  asyncMetricReducer,
  initialAsyncMetric,
  MAX_SYNC_ENTROPY_BLOCK_BYTES,
  MAX_SYNC_FILE_METRIC_BYTES,
  resolveMetric,
} from "./asyncMetricState";

export type { FileMetricsResult } from "../workers/metricsDispatch";
export type { AsyncMetric } from "./asyncMetricState";

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * One metric, computed either inline or off-thread.
 *
 * Exactly one of `syncCompute` / `asyncCompute` is expected to be non-null; both
 * null means there is nothing to compute for this input. Both close over
 * exactly the inputs `key` identifies, so the effect keys off `key` alone and
 * reaches the callbacks through refs assigned *during render* — callers build
 * them inline, so listing them would re-post the request every render, and an
 * effect-assigned ref would be a render too late for the memo below.
 */
function useAsyncMetric<T>(
  key: unknown,
  syncCompute: (() => T) | null,
  asyncCompute: (() => Promise<T>) | null,
): AsyncMetric<T> {
  const [state, dispatch] = useReducer(
    asyncMetricReducer as (s: AsyncMetric<T>, a: AsyncMetricAction<T>) => AsyncMetric<T>,
    null,
    initialAsyncMetric<T>,
  );

  const syncRef = useRef(syncCompute);
  syncRef.current = syncCompute;
  const asyncRef = useRef(asyncCompute);
  asyncRef.current = asyncCompute;

  // biome-ignore lint/correctness/useExhaustiveDependencies: key is the identity of the inputs the callback closes over; the ref exists so a freshly built callback cannot re-run this.
  const syncValue = useMemo(() => syncRef.current?.() ?? null, [key]);

  // `key` changing is the only thing that may post a new request; the callback
  // is reached through a ref for the same reason as above.
  useEffect(() => {
    const run = asyncRef.current;
    if (!run) return;
    dispatch({ type: "PENDING", key });
    run().then(
      (value) => dispatch({ type: "OK", key, value }),
      (err) => dispatch({ type: "ERROR", key, error: errorMessage(err) }),
    );
    // No abort: a reply for a superseded key is dropped by the reducer, and the
    // worker has no cancellation channel. The wasted work is off-thread.
  }, [key]);

  const expectAsync = asyncCompute !== null;
  return useMemo(
    () => resolveMetric(key, syncValue, expectAsync, state),
    [key, syncValue, expectAsync, state],
  );
}

/**
 * Checksum validation and per-section entropy for the loaded file.
 *
 * Both come from one call because both walk the whole file and the argument
 * copy is the only main-thread cost left; the client caches the result per
 * buffer, so the Headers tab and the Sections tab share one computation.
 */
export function useFileMetrics(pe: PEFile | null): AsyncMetric<FileMetricsResult> {
  const ranges = useMemo(() => (pe ? sectionRanges(pe) : []), [pe]);
  const offThread = pe !== null && pe.buffer.byteLength > MAX_SYNC_FILE_METRIC_BYTES;

  return useAsyncMetric<FileMetricsResult>(
    pe,
    pe && !offThread
      ? () => ({
          checksum: validateChecksum(pe.buffer, pe),
          sectionEntropies: computeSectionEntropies(pe.buffer, ranges),
        })
      : null,
    pe && offThread
      ? () =>
          metricsWorker.fileMetrics(
            pe.buffer,
            pe.dosHeader.e_lfanew,
            pe.optionalHeader.checksum,
            ranges,
          )
      : null,
  );
}

export interface EntropyStrip {
  blocks: number[];
  /** Bytes per block — not always 256; see `entropyBlockSizeFor`. */
  blockSize: number;
}

/**
 * The hex view's entropy strip for one section.
 *
 * `enabled` is load-bearing: the strip is behind a toggle that defaults to off,
 * and this used to be computed on every Hex tab open whether or not it was ever
 * shown.
 *
 * `maxBlocks` is the caller's pixel budget — see `entropyBlocksForWidth`. It is
 * part of the key, so widening the window recomputes at the finer granularity
 * the strip can now show, and narrowing it stops computing blocks nobody can
 * see.
 */
export function useEntropyStrip(
  bytes: Uint8Array | null,
  enabled: boolean,
  maxBlocks = MAX_ENTROPY_BLOCKS,
): AsyncMetric<EntropyStrip> {
  const blockSize = entropyBlockSizeFor(bytes?.length ?? 0, 256, maxBlocks);
  // A composite key: identity changes when either the section or the block size
  // does, which is exactly when the answer changes. `useAsyncMetric` compares
  // keys with `===`, so it has to be memoized.
  const key = useMemo(
    () => (enabled && bytes ? { bytes, blockSize } : null),
    [enabled, bytes, blockSize],
  );
  const offThread = key !== null && key.bytes.length > MAX_SYNC_ENTROPY_BLOCK_BYTES;

  return useAsyncMetric<EntropyStrip>(
    key,
    key && !offThread
      ? () => ({ blocks: computeEntropyBlocks(key.bytes, blockSize), blockSize })
      : null,
    key && offThread
      ? () =>
          metricsWorker
            .entropyBlocks(key.bytes, blockSize)
            .then((blocks) => ({ blocks, blockSize }))
      : null,
  );
}
