/**
 * The decisions behind {@link ../hooks/useFileMetrics}, as pure functions.
 *
 * Leaf module: this file must not import anything that pulls in a worker
 * client, so tests can exercise the threshold, the reducer and the render-time
 * resolution directly. There is no React renderer in this repo, so this is the
 * only place any of it can be verified — the hook that drives it is a thin
 * shell by design.
 */

/** What a component sees for one asynchronously computed metric. */
export interface AsyncMetric<T> {
  /** The computed value, or `null` while loading, on error, or with no input. */
  value: T | null;
  loading: boolean;
  /** A message to show in place of the value; `null` when there is none. */
  error: string | null;
  /**
   * Identity of the input this state describes — the object the caller passed
   * as the metric's key. Replies whose key no longer matches are dropped; see
   * {@link asyncMetricReducer}.
   */
  key: unknown;
}

export type AsyncMetricAction<T> =
  /** A new input; nothing computed for it yet. */
  | { type: "PENDING"; key: unknown }
  /** A worker reply. Applied only if `key` is still the current input. */
  | { type: "OK"; key: unknown; value: T }
  /** A rejected worker request. Applied only if `key` is still current. */
  | { type: "ERROR"; key: unknown; error: string };

export function initialAsyncMetric<T>(): AsyncMetric<T> {
  // `key` starts as a value no caller can pass: `undefined` is what a caller
  // uses for "no input", so a distinct sentinel keeps the very first render of
  // an empty view from being mistaken for a settled one.
  return { value: null, loading: false, error: null, key: NO_KEY };
}

/** Sentinel for "this state does not describe any input yet". */
export const NO_KEY = Symbol("async-metric/no-key");

/**
 * The stale-result guard.
 *
 * `OK` and `ERROR` carry the key of the request that produced them and are
 * discarded unless that is still the key the reducer is holding. Without it, a
 * user who opens a large section, switches to a small one and then loads a new
 * file gets whichever reply happens to land last — the earlier, slower
 * computation overwriting the newer one, silently and only on big files.
 *
 * Follows the reducer conventions in `usePEFile.ts`: a no-op returns the *same
 * object reference* rather than an equal one, so an ignored reply cannot cause
 * a re-render, and no branch mutates its input.
 */
export function asyncMetricReducer<T>(
  state: AsyncMetric<T>,
  action: AsyncMetricAction<T>,
): AsyncMetric<T> {
  switch (action.type) {
    case "PENDING":
      if (state.key === action.key && state.loading) return state;
      return { value: null, loading: true, error: null, key: action.key };

    case "OK":
      if (state.key !== action.key) return state;
      if (!state.loading && state.value === action.value) return state;
      return { value: action.value, loading: false, error: null, key: action.key };

    case "ERROR":
      if (state.key !== action.key) return state;
      if (!state.loading && state.error === action.error) return state;
      return { value: null, loading: false, error: action.error, key: action.key };

    default: {
      // A reducer is the wrong place to throw, so an unrecognised action is
      // ignored at runtime; the `never` binding is what makes a newly added
      // action kind a compile error here instead of a silently dropped one.
      const _exhaustive: never = action;
      void _exhaustive;
      return state;
    }
  }
}

/**
 * What to render this frame, given the reducer state and the current input.
 *
 * Split out from the reducer because it answers a question the reducer cannot:
 * between the render that changes the input and the effect that posts the
 * request, the reducer still holds the *previous* input's settled value.
 * Showing it would be showing one file's checksum under another file's headers,
 * so a key mismatch reads as loading.
 *
 * @param syncValue a value computed inline this render (small inputs), or null
 * @param expectAsync whether a worker computation is expected for `key`
 */
export function resolveMetric<T>(
  key: unknown,
  syncValue: T | null,
  expectAsync: boolean,
  state: AsyncMetric<T>,
): AsyncMetric<T> {
  // Computed inline: no loading state ever becomes visible, exactly as the
  // `useMemo` this replaced behaved.
  if (syncValue !== null) return { value: syncValue, loading: false, error: null, key };
  // Nothing to compute at all (no file, or a hidden panel).
  if (!expectAsync) return { value: null, loading: false, error: null, key };
  // The request for this key has not been posted or has not replied.
  if (state.key !== key) return { value: null, loading: true, error: null, key };
  return state;
}

const MiB = 1024 * 1024;

/**
 * Inputs at or below this stay on the main thread.
 *
 * The budget is 4 ms — a quarter of a 60 Hz frame, leaving the rest of the
 * frame for React's own render and commit — converted to bytes at each metric's
 * measured rate. Below it there is nothing to win: the worker hand-off has to
 * copy the argument first, and that copy alone runs at ~0.4 ms/MiB, so at these
 * sizes an async round trip buys a spinner and a second render in exchange for
 * microseconds.
 *
 * Measured on this machine (Node 18, x86-64, median of 9, bytes taken from the
 * synthetic 253 MiB PE so the byte distribution is not degenerate):
 *
 * | bytes   | `computeEntropyBlocks` @256 | section entropy | checksum | copy    |
 * |---------|-----------------------------|-----------------|----------|---------|
 * | 64 KiB  | 0.99 ms                     | 0.17 ms         | 0.03 ms  | 0.01 ms |
 * | 256 KiB | 4.15 ms                     | 0.70 ms         | 0.12 ms  | 0.02 ms |
 * | 1 MiB   | 17.12 ms                    | 2.82 ms         | 0.51 ms  | 0.10 ms |
 * | 4 MiB   | 74.84 ms                    | 11.14 ms        | 1.92 ms  | 1.56 ms |
 *
 * so ~17 ms/MiB for the block form and ~3.3 ms/MiB for checksum plus every
 * section's entropy together. 4 ms buys 240 KiB of the first and 1.2 MiB of the
 * second; both are rounded down to the power of two below.
 *
 * These are *not* precise cutoffs and should not be treated as one — the rates
 * came from one machine and one JS engine, and a browser on a phone is several
 * times slower. What the numbers establish is the order of magnitude: hundreds
 * of KiB, not tens and not tens of MiB. The largest real PE on the machine this
 * was measured on is 273 KB, so ordinary binaries stay entirely synchronous.
 */
export const MAX_SYNC_ENTROPY_BLOCK_BYTES = 256 * 1024;
/** @see MAX_SYNC_ENTROPY_BLOCK_BYTES */
export const MAX_SYNC_FILE_METRIC_BYTES = 1 * MiB;
