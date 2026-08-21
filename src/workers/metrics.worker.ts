/**
 * Whole-file metrics worker: checksum, section entropy, entropy strip.
 *
 * Deliberately tiny and stateless. All the logic — and the unknown-method
 * branch — lives in `metricsDispatch.ts` so it can be tested without a worker;
 * see that module for why this is not folded into the disasm worker.
 */

import { type MetricsRequest, metricsDispatch } from "./metricsDispatch";

// `async` because a `fileMetrics` request may carry a `Blob` (the original
// `File`, posted by reference so the main thread never copies it) that has to be
// read here. The `await` is inside the `try`, so a rejected dispatch — including
// the unknown-method branch, which now rejects rather than throwing — still
// posts an `error` reply instead of surfacing as an unhandled rejection that
// would leave the caller on its watchdog.
self.onmessage = async (e: MessageEvent<MetricsRequest>) => {
  const { id, method, args } = e.data;
  try {
    self.postMessage({ id, result: await metricsDispatch(method, args) });
  } catch (err) {
    self.postMessage({ id, error: err instanceof Error ? err.message : String(err) });
  }
};
