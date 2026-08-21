/**
 * Caller-side client for `metrics.worker.ts`.
 *
 * Same RPC shape as `disasmClient.ts` — numbered requests, a pending map, a
 * watchdog — with two deliberate differences:
 *
 * - **The worker is constructed lazily.** Every metric has a synchronous path
 *   for small inputs (see `hooks/asyncMetricState.ts`), and the largest real PE
 *   most users open never reaches the threshold, so a session that never opens
 *   a large image never spawns this thread at all.
 * - **Results are cached per `ArrayBuffer`.** A `WeakMap` keyed on the loaded
 *   file's buffer needs no invalidation: a new file is a new buffer, so the old
 *   entry becomes unreachable along with the file itself. Caching the *promise*
 *   also collapses the Headers tab and the Sections tab racing for the same
 *   `fileMetrics` call into one request. A rejected promise is evicted, so a
 *   transient worker failure does not poison the metric forever.
 *
 * `registerSourceBlob` adds one more per-buffer `WeakMap`, for the same reason
 * and with the same lifetime: it lets `App.tsx` say "these bytes came from this
 * `File`", so `fileMetrics` can post the `File` by reference instead of copying
 * the buffer. Every caller still passes the `ArrayBuffer` and the cache is still
 * keyed on it, so the caching semantics do not change — the registry only
 * changes what goes over the wire.
 */

import type { ByteRange } from "../utils/entropy";
import type { FileMetricsArgs, FileMetricsResult, MetricsMethod } from "./metricsDispatch";
import { prepareBinaryArgs } from "./transfer";

interface PendingRequest {
  resolve: (value: unknown) => void;
  reject: (reason: unknown) => void;
  method: string;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Watchdog for a metrics request.
 *
 * Every method here is a linear walk over bytes at a measured ~3 ms/MiB, and a
 * PE's file size is bounded by a `uint32`, so even a hostile 4 GiB image is
 * ~15 s of work plus its copy. 60 s is well clear of that but still bounded, so
 * a wedged worker surfaces as an error rather than a spinner that never stops.
 */
const REQUEST_TIMEOUT_MS = 60_000;

class MetricsWorkerClient {
  private worker: Worker | null = null;
  private pending = new Map<number, PendingRequest>();
  private nextId = 1;
  private fileCache = new WeakMap<ArrayBuffer, Promise<FileMetricsResult>>();
  private sourceBlobs = new WeakMap<ArrayBuffer, Blob>();
  private blockCache = new WeakMap<ArrayBuffer, Map<string, Promise<number[]>>>();

  /** Build the worker on first use; see the module docstring. */
  private ensureWorker(): Worker {
    if (this.worker) return this.worker;
    const worker = new Worker(new URL("./metrics.worker.ts", import.meta.url), { type: "module" });
    worker.onmessage = (e) => {
      const { id, result, error } = e.data;
      const p = this.take(id);
      if (!p) return;
      if (error) p.reject(new Error(error));
      else p.resolve(result);
    };
    worker.onerror = (e) => {
      console.error("[metrics worker] load error:", e.message ?? e);
      this.rejectAll(`Worker error: ${e.message ?? "unknown"}`);
    };
    worker.onmessageerror = () => {
      // The event carries nothing identifying the request it belonged to, so
      // fail everything outstanding rather than let them hang to the watchdog.
      console.error("[metrics worker] message deserialization failed");
      this.rejectAll("Worker reply could not be deserialized (structured clone failed)");
    };
    this.worker = worker;
    return worker;
  }

  private take(id: number): PendingRequest | undefined {
    const p = this.pending.get(id);
    if (!p) return undefined;
    this.pending.delete(id);
    clearTimeout(p.timer);
    return p;
  }

  private rejectAll(message: string): void {
    for (const id of [...this.pending.keys()]) {
      const p = this.take(id);
      p?.reject(new Error(`${message} (request '${p.method}')`));
    }
  }

  private send<T>(method: MetricsMethod, args: unknown): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      const id = this.nextId++;
      const timer = setTimeout(() => {
        this.take(id)?.reject(
          new Error(`Metrics request '${method}' timed out after ${REQUEST_TIMEOUT_MS / 1000}s`),
        );
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve: resolve as (v: unknown) => void, reject, method, timer });
      try {
        // `prepareBinaryArgs` replaces each top-level binary argument with a
        // private copy and transfers that; the caller's file buffer is never
        // transferred and never detaches. See ./transfer.ts. A `Blob` is
        // neither an ArrayBuffer nor a view, so it passes through untouched and
        // is cloned by reference — which is the whole point of sending one.
        const { args: payload, transfer } = prepareBinaryArgs(args);
        this.ensureWorker().postMessage({ id, method, args: payload }, transfer);
      } catch (err) {
        // Worker construction can throw, and so can copying an already-detached
        // view. Fail now rather than leave the entry sitting on its watchdog.
        this.take(id)?.reject(err);
      }
    });
  }

  /**
   * Record that `buffer` holds exactly the bytes of `blob`.
   *
   * Optional, and deliberately fire-and-forget: with no registration
   * `fileMetrics` posts the buffer exactly as it always did. That is what keeps
   * the copy path structural rather than incidental — two of the three load
   * paths (a recent file out of IndexedDB, the bundled demo binary via `fetch`)
   * have no `File` to register and never call this at all.
   *
   * Keyed on the buffer, weakly, so the registration needs no teardown: the
   * `File` stays reachable exactly as long as the buffer it describes. That is
   * also why `App.tsx` does not need to hold the `File` in a ref or in
   * `AppState` — the association *is* the storage.
   */
  registerSourceBlob(buffer: ArrayBuffer, blob: Blob): void {
    this.sourceBlobs.set(buffer, blob);
  }

  /**
   * What to post for `buffer`: the registered `Blob` if there is one, else the
   * buffer itself.
   *
   * The size test is a wiring check, and it is worth being precise about what
   * it can and cannot catch. It catches the class of defect where the wrong
   * `File` is paired with a buffer — a stale closure, a mis-ordered argument,
   * the previous load's handle — because that mismatch is overwhelmingly a
   * length mismatch, and taking the Blob path there would compute one file's
   * checksum for another's headers. It does **not** catch a same-length change
   * to the file on disk after loading: `Blob.size` is the snapshot state
   * captured when the `File` was created, not a fresh `stat`. The File API's
   * answer to that case is that the *read* must fail with a `NotReadableError`
   * rather than silently return the new bytes, and a failed read surfaces here
   * as a rejected request — which every caller already handles (the anomaly
   * pass degrades and logs; `useAsyncMetric` renders the error). So the
   * residual risk is a user agent that ignores its snapshot state, not
   * something this check could have found.
   */
  private sourceFor(buffer: ArrayBuffer): ArrayBuffer | Blob {
    const blob = this.sourceBlobs.get(buffer);
    if (!blob) return buffer;
    if (blob.size !== buffer.byteLength) {
      console.warn(
        "[metrics worker] registered blob size does not match the loaded buffer; copying instead",
      );
      return buffer;
    }
    return blob;
  }

  /**
   * Checksum plus per-section entropy, in one pass over the file.
   *
   * Repeat calls for the same buffer share the first call's promise. If a
   * source `Blob` is registered for the buffer it is posted by reference, which
   * costs nothing and moves even the argument copy off the main thread;
   * otherwise the buffer is copied and transferred as before. Both produce the
   * same answer — see `metricsDispatch.ts`.
   */
  fileMetrics(
    buffer: ArrayBuffer,
    peHeaderOffset: number,
    expectedChecksum: number,
    ranges: ByteRange[],
  ): Promise<FileMetricsResult> {
    const cached = this.fileCache.get(buffer);
    if (cached) return cached;
    const args: FileMetricsArgs = {
      source: this.sourceFor(buffer),
      peHeaderOffset,
      expectedChecksum,
      ranges,
    };
    const promise = this.send<FileMetricsResult>("fileMetrics", args).catch((err) => {
      this.fileCache.delete(buffer);
      throw err;
    });
    this.fileCache.set(buffer, promise);
    return promise;
  }

  /**
   * Entropy of each `blockSize`-byte block of `bytes`.
   *
   * Keyed on the window rather than the view object so navigating away from a
   * section and back reuses the result even though the `Uint8Array` wrapping it
   * was rebuilt.
   */
  entropyBlocks(bytes: Uint8Array, blockSize: number): Promise<number[]> {
    const buffer = bytes.buffer as ArrayBuffer;
    const key = `${bytes.byteOffset}:${bytes.byteLength}:${blockSize}`;
    let perBuffer = this.blockCache.get(buffer);
    if (!perBuffer) {
      perBuffer = new Map();
      this.blockCache.set(buffer, perBuffer);
    }
    const cached = perBuffer.get(key);
    if (cached) return cached;
    const promise = this.send<number[]>("entropyBlocks", { bytes, blockSize }).catch((err) => {
      perBuffer?.delete(key);
      throw err;
    });
    perBuffer.set(key, promise);
    return promise;
  }
}

export const metricsWorker = new MetricsWorkerClient();
