import { describe, it, expect, afterEach, vi } from "vitest";

/**
 * disasmClient.ts instantiates its worker singleton at module scope, so a fake
 * Worker has to be in place before the module is imported.
 */
class FakeWorker {
  static last: FakeWorker | undefined;
  onmessage: ((e: { data: any }) => void) | null = null;
  onerror: ((e: any) => void) | null = null;
  onmessageerror: ((e: any) => void) | null = null;
  posted: any[] = [];

  constructor() {
    FakeWorker.last = this;
  }

  /** Swallow the request — models a worker wedged in an infinite loop. */
  postMessage(msg: any) {
    this.posted.push(msg);
  }

  reply(id: number, result: unknown) {
    this.onmessage?.({ data: { id, result } });
  }
}

async function loadClient() {
  vi.stubGlobal("Worker", FakeWorker);
  vi.resetModules();
  const mod = await import("../disasmClient");
  return { client: mod.disasmWorker, worker: FakeWorker.last! };
}

describe("DisasmWorkerClient — a wedged worker cannot hang callers forever", () => {
  // Fake timers are switched on only after the dynamic import resolves.
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("rejects a request that never gets a reply", async () => {
    const { client } = await loadClient();
    // Fake only the watchdog's timers — faking microtask scheduling would
    // stall the awaits in this test.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const pending = client.init();
    // Assert before advancing so an eager rejection would still be caught.
    const assertion = expect(pending).rejects.toThrow(/timed out/);
    await vi.advanceTimersByTimeAsync(5 * 60_000);
    await assertion;
  });

  it("does not time out a request that gets a reply", async () => {
    const { client, worker } = await loadClient();
    // Fake only the watchdog's timers — faking microtask scheduling would
    // stall the awaits in this test.
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const pending = client.init();
    const { id } = worker.posted[0];
    worker.reply(id, true);
    await expect(pending).resolves.toBeUndefined();

    // The watchdog must have been cancelled: advancing past the deadline may
    // not produce a late rejection.
    await vi.advanceTimersByTimeAsync(10 * 60_000);
  });

  it("rejects everything outstanding when a reply fails structured clone", async () => {
    const { client, worker } = await loadClient();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const first = client.init();
    const second = client.resetStructRegistry();

    worker.onmessageerror?.({});

    await expect(first).rejects.toThrow(/deserialized/);
    await expect(second).rejects.toThrow(/deserialized/);
  });

  it("rejects everything outstanding on a worker error", async () => {
    const { client, worker } = await loadClient();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const pending = client.init();
    worker.onerror?.({ message: "load failed" });
    await expect(pending).rejects.toThrow(/load failed/);
  });
});
