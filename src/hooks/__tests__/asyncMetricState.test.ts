/**
 * The decisions behind `useFileMetrics` — the stale-reply guard, what renders
 * between input change and reply, and where the sync/async threshold sits.
 *
 * There is no React renderer in this repo, so the hook itself cannot be
 * mounted. It was written as a shell over these functions precisely so the
 * parts that can be wrong are the parts that can be tested; what is left
 * unverified is the wiring (which callback the hook passes for which input)
 * and everything the components render.
 */

import { describe, expect, it } from "vitest";
import {
  type AsyncMetric,
  asyncMetricReducer,
  initialAsyncMetric,
  MAX_SYNC_ENTROPY_BLOCK_BYTES,
  MAX_SYNC_FILE_METRIC_BYTES,
  NO_KEY,
  resolveMetric,
} from "../asyncMetricState";

const A = { file: "a" };
const B = { file: "b" };

const pending = <T>(key: unknown): AsyncMetric<T> =>
  asyncMetricReducer<T>(initialAsyncMetric<T>(), { type: "PENDING", key });

describe("asyncMetricReducer — the stale-reply guard", () => {
  it("drops a reply for a superseded input", () => {
    // The bug this exists to prevent: the user opens a 200 MiB section, then
    // switches to a small one. The slow reply lands last and overwrites the
    // newer, correct value — silently, and only on files big enough to race.
    let state = pending<number>(A);
    state = asyncMetricReducer(state, { type: "PENDING", key: B });
    const after = asyncMetricReducer(state, { type: "OK", key: A, value: 1 });

    expect(after).toBe(state);
    expect(after.value).toBeNull();
    expect(after.loading).toBe(true);
  });

  it("drops an error for a superseded input", () => {
    let state = pending<number>(A);
    state = asyncMetricReducer(state, { type: "PENDING", key: B });
    const after = asyncMetricReducer(state, { type: "ERROR", key: A, error: "boom" });

    expect(after).toBe(state);
    expect(after.error).toBeNull();
  });

  it("still accepts a reply for the current input", () => {
    const after = asyncMetricReducer(pending<number>(A), { type: "OK", key: A, value: 7 });
    expect(after).toMatchObject({ value: 7, loading: false, error: null, key: A });
  });

  it("accepts a late reply for a key that came back around", () => {
    // A → B → A: the state's key is A again, so A's reply is current by the
    // only definition that matters — same input, same answer.
    let state = pending<number>(A);
    state = asyncMetricReducer(state, { type: "PENDING", key: B });
    state = asyncMetricReducer(state, { type: "PENDING", key: A });
    expect(asyncMetricReducer(state, { type: "OK", key: A, value: 3 }).value).toBe(3);
  });

  it("does not confuse two structurally equal keys", () => {
    // Keys are compared by identity, not shape — two files with the same name
    // and size are different inputs.
    const state = pending<number>({ file: "a" });
    expect(asyncMetricReducer(state, { type: "OK", key: { file: "a" }, value: 1 })).toBe(state);
  });
});

describe("asyncMetricReducer — no-op branches keep the same object", () => {
  // Same invariant `appReducer` is held to: returning a new equal object
  // causes a pointless re-render, and these run on every worker reply.
  it("PENDING for the input already loading", () => {
    const state = pending<number>(A);
    expect(asyncMetricReducer(state, { type: "PENDING", key: A })).toBe(state);
  });

  it("a repeated OK with the same value", () => {
    const state = asyncMetricReducer(pending<number>(A), { type: "OK", key: A, value: 5 });
    expect(asyncMetricReducer(state, { type: "OK", key: A, value: 5 })).toBe(state);
  });

  it("a repeated ERROR with the same message", () => {
    const state = asyncMetricReducer(pending<number>(A), { type: "ERROR", key: A, error: "x" });
    expect(asyncMetricReducer(state, { type: "ERROR", key: A, error: "x" })).toBe(state);
  });

  it("but a different value for the same key does replace", () => {
    const state = asyncMetricReducer(pending<number>(A), { type: "OK", key: A, value: 5 });
    expect(asyncMetricReducer(state, { type: "OK", key: A, value: 6 }).value).toBe(6);
  });

  it("PENDING after a settled result clears the stale value", () => {
    // Re-requesting the same key (a retry) must not leave the old value on
    // screen labelled as fresh.
    const settled = asyncMetricReducer(pending<number>(A), { type: "OK", key: A, value: 5 });
    const again = asyncMetricReducer(settled, { type: "PENDING", key: A });
    expect(again.value).toBeNull();
    expect(again.loading).toBe(true);
  });
});

describe("asyncMetricReducer — no branch mutates", () => {
  it("leaves the previous state object untouched", () => {
    const state = pending<number>(A);
    const snapshot = { ...state };
    asyncMetricReducer(state, { type: "OK", key: A, value: 1 });
    asyncMetricReducer(state, { type: "ERROR", key: A, error: "e" });
    asyncMetricReducer(state, { type: "PENDING", key: B });
    expect(state).toEqual(snapshot);
  });
});

describe("initialAsyncMetric", () => {
  it("starts idle under a key no caller can supply", () => {
    // `undefined` is a legitimate caller key (no file loaded), so the initial
    // state needs a sentinel of its own or the first render of an empty view
    // would read as a settled result for "no file".
    const state = initialAsyncMetric<number>();
    expect(state).toMatchObject({ value: null, loading: false, error: null, key: NO_KEY });
    expect(state.key).not.toBe(undefined);
  });
});

describe("resolveMetric", () => {
  it("shows a synchronously computed value with no loading state", () => {
    const out = resolveMetric(A, 42, false, initialAsyncMetric<number>());
    expect(out).toEqual({ value: 42, loading: false, error: null, key: A });
  });

  it("prefers the synchronous value over anything the reducer holds", () => {
    const stale = asyncMetricReducer(pending<number>(B), { type: "OK", key: B, value: 9 });
    expect(resolveMetric(A, 42, false, stale).value).toBe(42);
  });

  it("is idle when there is nothing to compute", () => {
    const out = resolveMetric(null, null, false, initialAsyncMetric<number>());
    expect(out).toEqual({ value: null, loading: false, error: null, key: null });
  });

  it("does not keep showing a previous input's value while a new one loads", () => {
    // Between the render that changes the input and the effect that posts the
    // request, the reducer still holds the *old* input's settled value.
    // Showing it would put one file's checksum under another file's headers.
    const settledForB = asyncMetricReducer(pending<number>(B), { type: "OK", key: B, value: 9 });
    const out = resolveMetric(A, null, true, settledForB);
    expect(out).toEqual({ value: null, loading: true, error: null, key: A });
  });

  it("passes the reducer state through once it describes the current input", () => {
    const settled = asyncMetricReducer(pending<number>(A), { type: "OK", key: A, value: 9 });
    expect(resolveMetric(A, null, true, settled)).toBe(settled);
  });

  it("surfaces an error rather than looping on a spinner", () => {
    // AnalysisPhase has a "failed" value because a missing failure state once
    // left the UI spinning forever; the same applies here.
    const failed = asyncMetricReducer(pending<number>(A), { type: "ERROR", key: A, error: "boom" });
    const out = resolveMetric(A, null, true, failed);
    expect(out.loading).toBe(false);
    expect(out.error).toBe("boom");
    expect(out.value).toBeNull();
  });

  it("drops an error once the input changes", () => {
    const failed = asyncMetricReducer(pending<number>(B), { type: "ERROR", key: B, error: "boom" });
    expect(resolveMetric(A, null, true, failed).error).toBeNull();
  });

  it("goes idle rather than loading when the new input needs no work", () => {
    const settled = asyncMetricReducer(pending<number>(B), { type: "OK", key: B, value: 9 });
    expect(resolveMetric(null, null, false, settled)).toEqual({
      value: null,
      loading: false,
      error: null,
      key: null,
    });
  });
});

describe("sync/async thresholds", () => {
  it("keeps every ordinary binary on the synchronous path", () => {
    // The largest real PE on the machine these were measured on is 273 KB.
    const realWorld = 273 * 1024;
    expect(realWorld).toBeLessThan(MAX_SYNC_FILE_METRIC_BYTES);
  });

  it("puts the block form's threshold below the whole-file one", () => {
    // computeEntropyBlocks at 256 bytes costs ~17 ms/MiB against ~3.3 ms/MiB
    // for checksum plus every section's entropy, so it must cross first.
    expect(MAX_SYNC_ENTROPY_BLOCK_BYTES).toBeLessThan(MAX_SYNC_FILE_METRIC_BYTES);
  });

  it("keeps both within the order of magnitude the measurements support", () => {
    // A threshold of a few MiB would leave a visible freeze on the main
    // thread; one of a few KiB would pay for a worker round trip to save
    // microseconds. See the measured table in asyncMetricState.ts.
    for (const limit of [MAX_SYNC_ENTROPY_BLOCK_BYTES, MAX_SYNC_FILE_METRIC_BYTES]) {
      expect(limit).toBeGreaterThanOrEqual(64 * 1024);
      expect(limit).toBeLessThanOrEqual(4 * 1024 * 1024);
    }
  });
});
