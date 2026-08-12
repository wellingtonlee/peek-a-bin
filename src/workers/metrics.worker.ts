/**
 * Whole-file metrics worker: checksum, section entropy, entropy strip.
 *
 * Deliberately tiny and stateless. All the logic — and the unknown-method
 * branch — lives in `metricsDispatch.ts` so it can be tested without a worker;
 * see that module for why this is not folded into the disasm worker.
 */

import { type MetricsRequest, metricsDispatch } from "./metricsDispatch";

self.onmessage = (e: MessageEvent<MetricsRequest>) => {
  const { id, method, args } = e.data;
  try {
    self.postMessage({ id, result: metricsDispatch(method, args) });
  } catch (err) {
    self.postMessage({ id, error: err instanceof Error ? err.message : String(err) });
  }
};
