/**
 * The metrics client's own logic: lazy worker construction, the per-buffer
 * result cache, eviction of a failed request, and the invariant that the
 * caller's file buffer is never the thing that gets transferred.
 *
 * Modelled on `disasmClient.test.ts` — the fake worker runs the real
 * `structuredClone(msg, { transfer })`, which is the algorithm `postMessage`
 * runs, so it detaches exactly what a real post would detach. A test claiming
 * the file survives is worth nothing if nothing in the fake ever detaches.
 */

import { afterEach, describe, expect, it, vi } from "vitest";

/**
 * One RPC request as it goes over the wire. `args` is deliberately loose —
 * these tests reach into whichever member the method under test sends, and a
 * precise union here would just be a second copy of the argument shapes.
 */
// biome-ignore lint/suspicious/noExplicitAny: see above.
type PostedMessage = { id: number; method: string; args: any };

class FakeWorker {
  static instances: FakeWorker[] = [];
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: ((e: { message?: string }) => void) | null = null;
  onmessageerror: ((e: unknown) => void) | null = null;
  posted: PostedMessage[] = [];
  transfers: ArrayBuffer[][] = [];
  received: PostedMessage[] = [];

  constructor() {
    FakeWorker.instances.push(this);
  }

  postMessage(msg: PostedMessage, transfer: ArrayBuffer[] = []) {
    this.posted.push(msg);
    this.transfers.push(transfer);
    this.received.push(
      transfer.length > 0 ? structuredClone(msg, { transfer }) : structuredClone(msg),
    );
  }

  reply(id: number, result: unknown) {
    this.onmessage?.({ data: { id, result } });
  }

  fail(id: number, error: string) {
    this.onmessage?.({ data: { id, error } });
  }
}

async function loadClient() {
  FakeWorker.instances = [];
  vi.stubGlobal("Worker", FakeWorker);
  vi.resetModules();
  const mod = await import("../metricsClient");
  return mod.metricsWorker;
}

/** The single worker the client builds, once it has built one. */
const only = () => {
  expect(FakeWorker.instances).toHaveLength(1);
  return FakeWorker.instances[0];
};

function file(size: number): ArrayBuffer {
  const buf = new ArrayBuffer(size);
  new Uint8Array(buf).fill(0x41);
  return buf;
}

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe("MetricsWorkerClient — lazy construction", () => {
  it("builds no worker just from being imported", async () => {
    // Every metric has a synchronous path for small inputs, and most sessions
    // never exceed the threshold; spawning a thread at import would make every
    // one of them pay for a feature they never reach.
    await loadClient();
    expect(FakeWorker.instances).toHaveLength(0);
  });

  it("builds exactly one worker across many requests", async () => {
    const client = await loadClient();
    client.fileMetrics(file(64), 0x40, 0, []);
    client.entropyBlocks(new Uint8Array(64), 256);
    client.fileMetrics(file(64), 0x40, 0, []);
    expect(FakeWorker.instances).toHaveLength(1);
  });
});

describe("MetricsWorkerClient — fileMetrics", () => {
  it("posts the header scalars alongside the buffer, not the PEFile", async () => {
    // A PEFile holds `buffer`, so posting one would structured-clone the whole
    // file *nested* — which is exactly what transfer.ts only avoids at the top
    // level. The scalars exist so that cannot happen.
    const client = await loadClient();
    const buf = file(1024);
    client.fileMetrics(buf, 0x80, 0xdeadbeef, [{ offset: 0, length: 512 }]);

    const sent = only().posted[0];
    expect(sent.method).toBe("fileMetrics");
    expect(sent.args.peHeaderOffset).toBe(0x80);
    expect(sent.args.expectedChecksum).toBe(0xdeadbeef);
    expect(sent.args.ranges).toEqual([{ offset: 0, length: 512 }]);
  });

  it("transfers a private copy and leaves the caller's file intact", async () => {
    // The main thread keeps reading this buffer — HexView, the parser, the
    // disasm client. Detaching it would turn every later read into a throw.
    const client = await loadClient();
    const buf = file(1024);
    client.fileMetrics(buf, 0x80, 0, []);

    const worker = only();
    expect(worker.transfers[0]).toHaveLength(1);
    expect(worker.transfers[0][0]).not.toBe(buf);
    expect(buf.byteLength).toBe(1024);
    expect(new Uint8Array(buf)[0]).toBe(0x41);
    // And the worker still received the bytes.
    expect(worker.received[0].args.buffer.byteLength).toBe(1024);
  });

  it("serves a second call for the same buffer from the first request", async () => {
    // The Headers tab and the Sections tab both want this; without the cache
    // they would each pay the copy.
    const client = await loadClient();
    const buf = file(1024);
    const first = client.fileMetrics(buf, 0x80, 0, []);
    const second = client.fileMetrics(buf, 0x80, 0, []);

    expect(second).toBe(first);
    expect(only().posted).toHaveLength(1);

    only().reply(1, { checksum: { expected: 0, actual: 5, valid: true }, sectionEntropies: [] });
    await expect(first).resolves.toMatchObject({ checksum: { actual: 5 } });
    await expect(second).resolves.toMatchObject({ checksum: { actual: 5 } });
  });

  it("treats a different buffer as a different file", async () => {
    const client = await loadClient();
    client.fileMetrics(file(1024), 0x80, 0, []);
    client.fileMetrics(file(1024), 0x80, 0, []);
    expect(only().posted).toHaveLength(2);
  });

  it("evicts a failed request so a later attempt can retry", async () => {
    // Caching the promise is what collapses concurrent callers; caching a
    // *rejected* promise would make one transient worker failure permanent for
    // as long as the file stays loaded.
    const client = await loadClient();
    const buf = file(1024);
    const first = client.fileMetrics(buf, 0x80, 0, []);
    only().fail(1, "worker exploded");
    await expect(first).rejects.toThrow("worker exploded");

    const retry = client.fileMetrics(buf, 0x80, 0, []);
    expect(retry).not.toBe(first);
    expect(only().posted).toHaveLength(2);
    only().reply(2, { checksum: { expected: 0, actual: 1, valid: true }, sectionEntropies: [] });
    await expect(retry).resolves.toBeTruthy();
  });
});

describe("MetricsWorkerClient — entropyBlocks", () => {
  it("transfers just the section window, not the whole file", async () => {
    const client = await loadClient();
    const buf = file(4096);
    const section = new Uint8Array(buf, 1024, 512);
    client.entropyBlocks(section, 256);

    const worker = only();
    // One buffer transferred, and it is not the file's — the file survives.
    expect(worker.transfers[0]).toHaveLength(1);
    expect(worker.transfers[0][0]).not.toBe(buf);
    expect(worker.received[0].args.bytes.byteLength).toBe(512);
    expect(buf.byteLength).toBe(4096);
    expect(new Uint8Array(buf, 1024, 1)[0]).toBe(0x41);
  });

  it("caches on the window rather than the view object", async () => {
    // HexView rebuilds the Uint8Array whenever its memo deps change; keying on
    // object identity would recompute for a section the user merely revisited.
    const client = await loadClient();
    const buf = file(4096);
    const first = client.entropyBlocks(new Uint8Array(buf, 1024, 512), 256);
    const second = client.entropyBlocks(new Uint8Array(buf, 1024, 512), 256);

    expect(second).toBe(first);
    expect(only().posted).toHaveLength(1);
  });

  it("treats a different window or block size as a different request", async () => {
    const client = await loadClient();
    const buf = file(4096);
    client.entropyBlocks(new Uint8Array(buf, 1024, 512), 256);
    client.entropyBlocks(new Uint8Array(buf, 2048, 512), 256);
    client.entropyBlocks(new Uint8Array(buf, 1024, 512), 512);
    expect(only().posted).toHaveLength(3);
  });

  it("evicts a failed request", async () => {
    const client = await loadClient();
    const buf = file(4096);
    const first = client.entropyBlocks(new Uint8Array(buf, 0, 512), 256);
    only().fail(1, "nope");
    await expect(first).rejects.toThrow("nope");
    expect(client.entropyBlocks(new Uint8Array(buf, 0, 512), 256)).not.toBe(first);
  });
});

describe("MetricsWorkerClient — failure paths", () => {
  it("rejects a request that never gets a reply", async () => {
    const client = await loadClient();
    // Fake only the watchdog's timers — faking microtask scheduling would
    // stall the awaits in this test.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const p = client.fileMetrics(file(64), 0x40, 0, []);
    // Assert before advancing so an eager rejection would still be caught.
    const assertion = expect(p).rejects.toThrow(/timed out after 60s/);
    await vi.advanceTimersByTimeAsync(60_000);
    await assertion;
  });

  it("does not time out a request that gets a reply", async () => {
    const client = await loadClient();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const p = client.entropyBlocks(new Uint8Array(64), 256);
    only().reply(only().posted[0].id, [1, 2]);
    await expect(p).resolves.toEqual([1, 2]);
    // The watchdog must have been cancelled: advancing past the deadline may
    // not produce a late rejection.
    await vi.advanceTimersByTimeAsync(10 * 60_000);
  });

  it("rejects everything outstanding when the worker fails to load", async () => {
    const client = await loadClient();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const a = client.fileMetrics(file(64), 0x40, 0, []);
    const b = client.entropyBlocks(new Uint8Array(64), 256);
    only().onerror?.({ message: "module not found" });
    await expect(a).rejects.toThrow(/module not found.*fileMetrics/s);
    await expect(b).rejects.toThrow(/module not found.*entropyBlocks/s);
  });

  it("rejects rather than hanging when a reply cannot be deserialized", async () => {
    const client = await loadClient();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const p = client.entropyBlocks(new Uint8Array(64), 256);
    only().onmessageerror?.({});
    await expect(p).rejects.toThrow(/structured clone failed/);
  });

  it("fails the request when the worker cannot even be constructed", async () => {
    // `new Worker` throws under a CSP that forbids worker-src, which is a real
    // deployment failure; it must surface as a rejected metric, not an
    // exception thrown out of a React effect.
    vi.resetModules();
    vi.stubGlobal(
      "Worker",
      class {
        constructor() {
          throw new Error("blocked by CSP");
        }
      },
    );
    const { metricsWorker } = await import("../metricsClient");
    await expect(metricsWorker.fileMetrics(file(64), 0x40, 0, [])).rejects.toThrow(
      "blocked by CSP",
    );
  });
});
