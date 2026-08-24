import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { unsupportedArchMessage } from "../../disasm/arch";
import { type SweptInsn, sweepX86 } from "../../disasm/linearSweep";
import type { Instruction, Xref } from "../../disasm/types";
import type { RuntimeFunction } from "../../pe/types";
// The far end of the wire. Importing it here is what lets a test post a request
// through the client and then answer it with the real dispatch, in the order a
// serially-servicing worker would see the messages — which is the only way to
// state an ordering property about the two together.
import { createWorkerState, dispatch, type WorkerState } from "../dispatch";

/** One RPC request as it goes over the wire. `args` is deliberately loose —
 * these tests reach into whichever member the method under test sends. */
type PostedMessage = { id: number; method: string; args: any };

/**
 * disasmClient.ts instantiates its worker singleton at module scope, so a fake
 * Worker has to be in place before the module is imported.
 */
class FakeWorker {
  static last: FakeWorker | undefined;
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: ((e: { message?: string }) => void) | null = null;
  onmessageerror: ((e: unknown) => void) | null = null;
  posted: PostedMessage[] = [];
  transfers: ArrayBuffer[][] = [];
  /** What the worker would actually see — the post-serialization message. */
  received: PostedMessage[] = [];

  constructor() {
    FakeWorker.last = this;
  }

  /** Swallow the request — models a worker wedged in an infinite loop. */
  postMessage(msg: PostedMessage, transfer: ArrayBuffer[] = []) {
    this.posted.push(msg);
    this.transfers.push(transfer);
    // Run the real thing: `structuredClone` with a transfer list is the
    // algorithm `postMessage` runs, so this both produces what the worker
    // would receive and detaches what a real post would detach. A test
    // asserting the caller's file buffer survives is worth nothing if nothing
    // in the fake ever detaches anything.
    this.received.push(
      transfer.length > 0 ? structuredClone(msg, { transfer }) : structuredClone(msg),
    );
  }

  reply(id: number, result: unknown) {
    this.onmessage?.({ data: { id, result } });
  }

  /**
   * What `disasm.worker.ts` posts when `dispatch` rejects: a plain string, not
   * the Error. Structured clone would carry an Error, but the worker
   * deliberately flattens to `err?.message ?? String(err)` — so the reply the
   * client parses is this shape and no other.
   */
  replyError(id: number, error: string) {
    this.onmessage?.({ data: { id, error } });
  }
}

async function loadClient() {
  vi.stubGlobal("Worker", FakeWorker);
  vi.resetModules();
  const mod = await import("../disasmClient");
  // The watchdog's own module, out of the *same* graph. `resetModules` gives
  // the client a fresh copy of every dependency, so a `WorkerTimeoutError`
  // imported statically at the top of this file is a different class object
  // from the one the client throws and `toBeInstanceOf` is false against it —
  // an artefact of module reloading, not of the production path, where there is
  // one graph.
  const timeouts = await import("../requestTimeout");
  return { client: mod.disasmWorker, worker: FakeWorker.last!, mod, timeouts };
}

/** The client singleton's type, which the module does not export by name. */
type DisasmClient = Awaited<ReturnType<typeof loadClient>>["client"];

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

  /**
   * peek-a-bin-meai. The timeout has to be *distinguishable* from a failure.
   *
   * One budget covers every method — correctly, since the worker is serial — so
   * a legitimate run on a very large image can trip it, and App's analysis chain
   * reported that as `analysisPhase: "failed"`, the same terminal state a
   * truncated file produces. `analysisRejection` decides between the two on the
   * error's *type*, so the watchdog has to mint one. Note the existing
   * `rejects.toThrow(/timed out/)` above passes either way: that instrument
   * cannot see this, which is why the class is asserted directly.
   */
  it("rejects with its own error type, not a bare Error", async () => {
    const { client, timeouts } = await loadClient();
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const pending = client.init();
    const assertion = expect(pending).rejects.toBeInstanceOf(timeouts.WorkerTimeoutError);
    await vi.advanceTimersByTimeAsync(timeouts.REQUEST_TIMEOUT_MS);
    await assertion;
  });

  it("names the stalled RPC and the budget it waited out", async () => {
    const { client, timeouts } = await loadClient();
    const { REQUEST_TIMEOUT_MS } = timeouts;
    vi.useFakeTimers({ toFake: ["setTimeout", "clearTimeout"] });
    const pending = client.init().catch((e) => e);
    await vi.advanceTimersByTimeAsync(REQUEST_TIMEOUT_MS);
    const err = (await pending) as InstanceType<typeof timeouts.WorkerTimeoutError>;
    expect(err.method).toBe("init");
    expect(err.timeoutMs).toBe(REQUEST_TIMEOUT_MS);
    // The message is unchanged from the bare Error it replaces, so nothing that
    // reads the text — the log line, the engine-unavailable notice for an
    // `init` that never answers — moves with this.
    expect(err.message).toBe(`Worker request 'init' timed out after ${REQUEST_TIMEOUT_MS / 1000}s`);
  });

  /**
   * The discrimination, in the direction that matters. Every other rejection
   * path must stay an ordinary Error, or `analysisRejection` routes a genuine
   * failure to the timeout notice and the defect comes back pointing the other
   * way. A change that minted the class in `rejectAll` would satisfy the two
   * assertions above.
   */
  it.each([
    ["a worker error", (w: FakeWorker) => w.onerror?.({ message: "load failed" })],
    ["a reply that cannot be deserialized", (w: FakeWorker) => w.onmessageerror?.({})],
  ])("does not claim %s timed out", async (_label, provoke) => {
    const { client, worker, timeouts } = await loadClient();
    vi.spyOn(console, "error").mockImplementation(() => {});
    const pending = client.init();
    provoke(worker);
    const err = await pending.catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(timeouts.WorkerTimeoutError);
  });

  it("does not claim a rejecting worker method timed out", async () => {
    const { client, worker, timeouts } = await loadClient();
    const pending = client.init();
    worker.replyError(worker.posted[0].id, "Capstone is unavailable");
    const err = await pending.catch((e) => e);
    expect(err).toBeInstanceOf(Error);
    expect(err).not.toBeInstanceOf(timeouts.WorkerTimeoutError);
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

  /**
   * peek-a-bin-8ru3. A rejecting stage's message is the whole content of the
   * `"analysis-failed"` notice — `App`'s catch interpolates `err.message` into
   * `SET_ERROR`, and `analysisNotice` puts that string in front of the user
   * verbatim. Every test above drives `dispatch` directly and asserts
   * `rejects.toThrow`, so the one link none of them crosses is this one: the
   * worker flattening the Error to a string, and the client rebuilding one.
   *
   * Scoped honestly: this does *not* hold up the architecture refusal. That
   * notice re-derives its text on the main thread from `coffHeader.machine`, so
   * it survives total loss of the worker's message. What it holds up is every
   * other failure the user is shown.
   */
  it("carries a rejecting stage's message across the wire intact", async () => {
    const { client, worker } = await loadClient();
    // The real sentence, from the real module, rather than a placeholder — a
    // reply path that mangled punctuation or truncated would still pass a
    // "some error" assertion.
    const message = unsupportedArchMessage("Cross-reference analysis");
    const pending = client.init();

    worker.replyError(worker.posted[0].id, message);

    await expect(pending).rejects.toThrow(message);
    // And it is an Error, which is what App's `err instanceof Error` arm needs
    // to reach `err.message` rather than printing "[object Object]".
    await expect(pending).rejects.toBeInstanceOf(Error);
  });

  it("does not read a reply carrying an error as a successful result", async () => {
    // `{ id, error }` has no `result`, so a client that only checked for one
    // would resolve the caller with `undefined` — the same silent-success shape
    // the unknown-method guard in dispatch.ts exists to prevent, arriving one
    // hop later.
    const { client, worker } = await loadClient();
    const pending = client.init();

    worker.replyError(worker.posted[0].id, "boom");

    await expect(pending).rejects.toThrow("boom");
  });
});

/**
 * The byte arguments every heavy method takes are views onto the whole loaded
 * file. Posted untransferred, structured clone copies that entire buffer — the
 * unit tests in `transfer.test.ts` pin the decision; these pin the wiring, that
 * `send()` actually applies it, on the real client with real method signatures.
 */
describe("DisasmWorkerClient — byte arguments are sliced and transferred", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  /** A 4 KiB "file" with a 256-byte ".text" at offset 1024. */
  function loadedFile() {
    const buffer = new ArrayBuffer(4096);
    new Uint8Array(buffer).fill(0xaa);
    new Uint8Array(buffer, 1024, 256).fill(0xcc);
    return buffer;
  }

  it("posts only the section window for detectFunctions", async () => {
    const { client, worker } = await loadClient();
    const buffer = loadedFile();

    void client.detectFunctions(new Uint8Array(buffer, 1024, 256), 0x1000, true);

    const { args } = worker.received[0];
    expect(args.bytes.byteLength).toBe(256);
    // Before the fix this was 4096 — the whole file.
    expect(args.bytes.buffer.byteLength).toBe(256);
    expect(worker.transfers[0]).toEqual([worker.posted[0].args.bytes.buffer]);
  });

  it("leaves the file buffer live after the call — the detach hazard", async () => {
    const { client, worker } = await loadClient();
    const buffer = loadedFile();
    const section = new Uint8Array(buffer, 1024, 256);

    // Every heavy method, against one file buffer, in the order a load runs
    // them. The fake worker detaches whatever is handed to it, so if any of
    // these transferred a caller-owned buffer the later ones would throw.
    void client.detectFunctions(section, 0x1000, true);
    void client.buildAllXrefs(section, 0x1000, true, [], []);
    void client.hybridDisassemble(section, 0x1000, true, []);
    void client.disassemble(section.subarray(16, 48), 0x1010, true);
    void client.extractStrings(buffer, [], 0x140000000, true);

    expect(worker.posted).toHaveLength(5);
    expect(buffer.byteLength).toBe(4096);
    expect(section.byteLength).toBe(256);
    // Readable, and still the right bytes.
    expect(section[0]).toBe(0xcc);
    expect(new Uint8Array(buffer, 0, 1)[0]).toBe(0xaa);
  });

  it("sends a function-sized subarray as function-sized bytes", async () => {
    // The worst case before the fix: decompiling one function for the LLM
    // panel posted a copy of the whole file per call.
    const { client, worker } = await loadClient();
    const buffer = loadedFile();
    const section = new Uint8Array(buffer, 1024, 256);

    void client.disassemble(section.subarray(0, 32), 0x1000, true);

    const { args } = worker.received[0];
    expect(args.bytes.buffer.byteLength).toBe(32);
    expect(Array.from(args.bytes.slice(0, 4))).toEqual([0xcc, 0xcc, 0xcc, 0xcc]);
  });

  it("hands extractStrings a private copy, never the caller's file buffer", async () => {
    // extractStrings takes the whole ArrayBuffer, and the main thread keeps
    // reading it (bufferRef, pe.buffer, HexView, entropy). Transferring the
    // caller's buffer here would detach the loaded file.
    const { client, worker } = await loadClient();
    const buffer = loadedFile();

    void client.extractStrings(buffer, [], 0x140000000, true);

    expect(worker.posted[0].args.buffer).not.toBe(buffer);
    expect(worker.transfers[0]).not.toContain(buffer);
    expect(worker.received[0].args.buffer.byteLength).toBe(4096);
    expect(buffer.byteLength).toBe(4096);
    expect(new Uint8Array(buffer, 1024, 1)[0]).toBe(0xcc);
  });

  it("posts no transfer list for a call with no binary arguments", async () => {
    const { client, worker } = await loadClient();

    void client.configure(new Map([[1, "hi"]]), new Map());

    expect(worker.transfers[0]).toEqual([]);
  });

  it("does not transfer the tiny per-instruction buffers in an Instruction[]", async () => {
    // A transfer list with one entry per instruction is far slower than
    // cloning them; the args walk is deliberately top-level only.
    const { client, worker } = await loadClient();
    const instructions = Array.from({ length: 4 }, (_, i) => ({
      address: 0x1000 + i,
      bytes: new Uint8Array(4),
      mnemonic: "nop",
      opStr: "",
      size: 1,
    }));

    void client.buildTypedXrefMap(instructions);

    expect(worker.transfers[0]).toEqual([]);
    expect(worker.received[0].args.instructions[0].bytes.byteLength).toBe(4);
  });

  it("rejects rather than throwing when a byte argument is already detached", async () => {
    const { client } = await loadClient();
    const orphan = new Uint8Array(16);
    structuredClone({}, { transfer: [orphan.buffer] });

    await expect(client.detectFunctions(orphan, 0x1000, true)).rejects.toThrow(TypeError);
  });
});

/**
 * peek-a-bin-yo9: the case bodies of a switch are reachable only if the
 * recursive descent is told where the jump table points. The client already
 * holds the tables — `detectFunctions` returns them and they are kept for
 * `configureDecompileMaps` — so it adds them to the seed list rather than
 * making every caller thread them through.
 */
describe("DisasmWorkerClient — jump-table targets are seeded", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** Reply to the pending `detectFunctions` request with these tables. */
  async function withTables(tables: [number, number[]][]) {
    const { client, worker } = await loadClient();
    const p = client.detectFunctions(new Uint8Array(64), 0x1000, false);
    worker.reply(worker.posted[0].id, { functions: [], jumpTables: tables });
    await p;
    return { client, worker };
  }

  it("appends the targets of every detected table to the caller's seeds", async () => {
    const { client, worker } = await withTables([
      [0x40b8f0, [0x40b900, 0x40b910]],
      [0x40ba8c, [0x40ba9c]],
    ]);

    void client.hybridDisassemble(new Uint8Array(64), 0x400000, false, [0x401000]);

    // Before the fix this was [0x401000] alone, and the case-0 bodies at
    // 0x40b900 / 0x40ba9c were left to phase 2's linear gap fill — which
    // starts on the table itself and walks off it misaligned.
    expect(worker.received[1].args.seeds).toEqual([0x401000, 0x40b900, 0x40b910, 0x40ba9c]);
  });

  it("keeps the caller's seeds first and unmodified", async () => {
    const { client, worker } = await withTables([[0x40b8f0, [0x40b900]]]);
    const seeds = [0x401000, 0x402000];

    void client.hybridDisassemble(new Uint8Array(64), 0x400000, false, seeds);

    expect(worker.received[1].args.seeds.slice(0, 2)).toEqual([0x401000, 0x402000]);
    expect(seeds).toEqual([0x401000, 0x402000]);
  });

  it("emits a target shared by two tables once", async () => {
    const { client, worker } = await withTables([
      [0x40b8f0, [0x40b900, 0x40b900]],
      [0x40ba8c, [0x40b900]],
    ]);

    void client.hybridDisassemble(new Uint8Array(64), 0x400000, false, []);

    expect(worker.received[1].args.seeds).toEqual([0x40b900]);
  });

  it("sends the caller's seeds unchanged when no tables were detected", async () => {
    // t64/w64 have no jump tables at all; their disassembly must not move.
    const { client, worker } = await withTables([]);

    void client.hybridDisassemble(new Uint8Array(64), 0x400000, true, [0x401000]);

    expect(worker.received[1].args.seeds).toEqual([0x401000]);
  });
});

/**
 * peek-a-bin-g17: the x64 jump tables `detectFunctions` reads live in
 * `.rdata`, so the detector needs those bytes as well as `.text`. They are the
 * one argument that cannot travel the obvious way: `prepareBinaryArgs` walks
 * top-level properties only (a deep walk over `Instruction[]` measured 80.6 s
 * against 1.6 s to clone), so a `{ base, bytes }[]` nested inside `options`
 * would be structured-cloned — and each `bytes` is a view onto the whole loaded
 * file, whose clone copies the entire backing buffer, once per window. The
 * client flattens them into one top-level buffer instead.
 */
describe("DisasmWorkerClient — data windows travel flat, not nested in options", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  /** A 4 KiB "file": ".text" at 1024, ".rdata" at 2048, ".data" at 3072. */
  function loadedFile() {
    const buffer = new ArrayBuffer(4096);
    new Uint8Array(buffer).fill(0xaa);
    new Uint8Array(buffer, 1024, 256).fill(0xcc);
    new Uint8Array(buffer, 2048, 64).fill(0x11);
    new Uint8Array(buffer, 3072, 32).fill(0x22);
    return buffer;
  }

  function windowsOf(buffer: ArrayBuffer) {
    return [
      { base: 0x2000, bytes: new Uint8Array(buffer, 2048, 64) },
      { base: 0x3000, bytes: new Uint8Array(buffer, 3072, 32) },
    ];
  }

  async function detectWithWindows() {
    const { client, worker } = await loadClient();
    const buffer = loadedFile();
    const section = new Uint8Array(buffer, 1024, 256);
    const dataWindows = windowsOf(buffer);

    void client.detectFunctions(section, 0x1000, true, { entryPoint: 0x1000, dataWindows });

    return { worker, buffer, section };
  }

  it("posts the windows as one buffer of exactly their own bytes", async () => {
    const { worker } = await detectWithWindows();
    const { args } = worker.received[0];

    // 96 = 64 + 32. Nested in `options` this would have been 4096 twice over —
    // the whole file, once per window.
    expect(args.dataBytes.byteLength).toBe(96);
    expect(args.dataBytes.buffer.byteLength).toBe(96);
    expect(args.options.dataWindows).toBeUndefined();
  });

  it("keeps each window's virtual address and its place in the buffer", async () => {
    const { worker } = await detectWithWindows();
    const { args } = worker.received[0];

    expect(args.dataSpans).toEqual([
      { base: 0x2000, offset: 0, length: 64 },
      { base: 0x3000, offset: 64, length: 32 },
    ]);
    expect(args.dataBytes[0]).toBe(0x11);
    expect(args.dataBytes[64]).toBe(0x22);
  });

  it("transfers that buffer rather than cloning it", async () => {
    const { worker } = await detectWithWindows();

    expect(worker.transfers[0]).toContain(worker.posted[0].args.dataBytes.buffer);
  });

  it("leaves the caller's file buffer live — the detach hazard again", async () => {
    const { buffer, section } = await detectWithWindows();

    // The fake worker really transfers what it is handed, so a window taken
    // straight from the file would have detached the file here.
    expect(buffer.byteLength).toBe(4096);
    expect(section[0]).toBe(0xcc);
    expect(new Uint8Array(buffer, 2048, 1)[0]).toBe(0x11);
  });

  it("keeps the rest of the options untouched", async () => {
    const { worker } = await detectWithWindows();

    expect(worker.received[0].args.options).toEqual({ entryPoint: 0x1000 });
  });

  it("sends no window fields at all when the caller passes none", async () => {
    // t32-style callers, and every call before this existed: the payload must
    // not grow an empty key.
    const { client, worker } = await loadClient();
    const buffer = loadedFile();

    void client.detectFunctions(new Uint8Array(buffer, 1024, 256), 0x1000, true, {
      entryPoint: 0x1000,
    });

    const { args } = worker.received[0];
    expect("dataBytes" in args).toBe(false);
    expect("dataSpans" in args).toBe(false);
    expect(worker.transfers[0]).toEqual([worker.posted[0].args.bytes.buffer]);
  });

  it("sends no window fields for an empty window list", async () => {
    const { client, worker } = await loadClient();
    const buffer = loadedFile();

    void client.detectFunctions(new Uint8Array(buffer, 1024, 256), 0x1000, true, {
      dataWindows: [],
    });

    expect("dataBytes" in worker.received[0].args).toBe(false);
  });
});

/**
 * peek-a-bin-2ap: `buildTypedXrefMap`'s image bound was implemented and tested
 * in `functionDetect.ts` and reachable from nowhere — the client did not accept
 * it and did not send it, so the browser kept the unbounded fallback scan and
 * its references to addresses outside the image.
 */
describe("DisasmWorkerClient — the image bounds reach the worker", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const instructions = [
    {
      address: 0x140001000,
      bytes: new Uint8Array(3),
      mnemonic: "or",
      opStr: "edx, 0xffffffff",
      size: 3,
    },
  ];
  const bounds = { base: 0x140000000, size: 0x1e000 };

  it("puts the bounds in the request the worker receives", async () => {
    const { client, worker } = await loadClient();

    void client.buildTypedXrefMap(instructions, bounds);

    // `received` is post-structured-clone: two plain numbers survive it whole.
    expect(worker.received[0].args.imageBounds).toEqual(bounds);
  });

  it("adds nothing to the transfer list — the bounds are not binary", async () => {
    // `prepareBinaryArgs` only ever transfers buffers it allocated. A pair of
    // numbers must not look like a binary payload to it.
    const { client, worker } = await loadClient();

    void client.buildTypedXrefMap(instructions, bounds);

    expect(worker.transfers[0]).toEqual([]);
  });

  it("sends undefined bounds when the caller has none, keeping the old behaviour", async () => {
    const { client, worker } = await loadClient();

    void client.buildTypedXrefMap(instructions);

    expect(worker.received[0].args.imageBounds).toBeUndefined();
  });

  it("does not serve a cached unbounded map to a bounded caller", async () => {
    // The cache is keyed on the instruction array's identity, and the same
    // array bounded and unbounded are different answers — so whoever asked
    // first would otherwise decide what everyone else gets.
    const { client, worker } = await loadClient();

    const first = client.buildTypedXrefMap(instructions);
    worker.reply(worker.posted[0].id, [[0xffffffff, [{ from: 0x140001000, type: "data" }]]]);
    await first;

    const second = client.buildTypedXrefMap(instructions, bounds);
    expect(worker.posted).toHaveLength(2);
    worker.reply(worker.posted[1].id, []);
    expect((await second).size).toBe(0);
  });

  it("still answers a repeat of the same request from cache", async () => {
    const { client, worker } = await loadClient();

    const first = client.buildTypedXrefMap(instructions, bounds);
    worker.reply(worker.posted[0].id, [[0x140002000, [{ from: 0x140001000, type: "data" }]]]);
    const map = await first;

    expect(await client.buildTypedXrefMap(instructions, bounds)).toBe(map);
    expect(worker.posted).toHaveLength(1);
  });
});

/**
 * peek-a-bin-x4o2: which architecture a section is decoded as used to depend on
 * which message reached the worker first.
 *
 * `App`'s detection effect posted `configure({ machine })`; `useDisassemblyRows`
 * posted `disassemble` / `hybridDisassemble` from a different effect, in a
 * lazily-loaded child, with no ordering relationship to it. A child's effect
 * runs before its parent's, so on the second file loaded into a session the
 * decode was posted *first* — and the worker, which services messages serially
 * off one mutable `state.arch`, answered it with the previous image's decoder.
 * For an ARM64 image that is an x86 sweep over A64 bytes: a full screen of
 * plausible instructions, none of them real, with no coverage signal to notice
 * it by. `DisassemblyView`'s new refusal panel masks the unsupported case; it
 * does not mask this one.
 *
 * The fix makes each decode request state its own architecture, so no ordering
 * of messages can change the answer. These drive the real `dispatch` over the
 * real posted messages, in the order the worker would see them.
 */
describe("DisasmWorkerClient — the architecture travels with the decode request", () => {
  const ARM64_MACHINE = 0xaa64;
  const AMD64_MACHINE = 0x8664;
  const ARMNT_MACHINE = 0x01c4; // ARM Thumb-2: a real image, no decoder here

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /** A Capstone stand-in that records which handle was asked to decode. */
  function stubCs(tag: string) {
    const seen: number[] = [];
    return {
      tag,
      seen,
      disasm(bytes: Uint8Array, options: { address: number }) {
        seen.push(options.address);
        if (bytes.length < 4) throw new Error("Failed to disassemble");
        return [
          {
            address: options.address,
            bytes: bytes.subarray(0, 4),
            mnemonic: tag,
            opStr: "",
            size: 4,
          },
        ];
      },
    };
  }

  /** A just-started worker: Capstone up, and `arch` still on its default. */
  function freshWorkerState(): WorkerState {
    return Object.assign(createWorkerState(Promise.resolve()), {
      cs32: stubCs("x86-32"),
      cs64: stubCs("x86-64"),
      csArm64: stubCs("arm64"),
    });
  }

  it("decodes as ARM64 when the disassemble is serviced BEFORE the configure", async () => {
    const { client, worker } = await loadClient();
    // The load handshake: `App.handleFile` declares the machine the instant the
    // file parses, before the reducer — and so before any effect — sees it.
    client.setImage(ARM64_MACHINE);

    // The interleaving the bug is made of, constructed explicitly rather than
    // assumed away: the decode is posted first, the configure second.
    void client.hybridDisassemble(new Uint8Array(8), 0x140001000, true, []);
    void client.configure(new Map(), new Map(), { machine: ARM64_MACHINE });
    expect(worker.received.map((m) => m.method)).toEqual(["hybridDisassemble", "configure"]);

    // Now the far end, in that order, on a worker whose session state still
    // says x86 because its `configure` has not run yet.
    const s = freshWorkerState();
    expect(s.arch).toBe("x86");
    const insns = (await dispatch("hybridDisassemble", worker.received[0].args, s)) as {
      mnemonic: string;
    }[];

    // Before the fix: two "x86-64" instructions, cached, and shown as fact.
    expect(insns.map((i) => i.mnemonic)).toEqual(["arm64", "arm64"]);
    expect(s.cs64.seen).toEqual([]);
    expect(s.csArm64.seen).toEqual([0x140001000, 0x140001004]);
  });

  it("refuses an image with no decoder even when the configure is still queued", async () => {
    // The same race for an ARM32 image. `disassemble` is the linear-sweep path,
    // which is what a section with no detected functions takes.
    const { client, worker } = await loadClient();
    client.setImage(ARMNT_MACHINE);

    void client.disassemble(new Uint8Array(64), 0x401000, false);
    void client.configure(new Map(), new Map(), { machine: ARMNT_MACHINE });

    const s = freshWorkerState();
    await expect(dispatch("disassemble", worker.received[0].args, s)).rejects.toThrow(
      /Disassembly is not supported for this image's machine type/,
    );
    expect(s.cs32.seen).toEqual([]);
    expect(s.cs64.seen).toEqual([]);
  });

  it("does not let a stale session architecture decide an x86 image's decode", async () => {
    // The mirror image, and the one a second file load produces: the worker is
    // mid-ARM64 session and an x86 file is dropped on it. The decode for the
    // new file is posted before its configure, so session state says ARM64.
    const { client, worker } = await loadClient();
    client.setImage(AMD64_MACHINE);

    void client.hybridDisassemble(new Uint8Array(8), 0x140001000, true, []);

    const s = Object.assign(freshWorkerState(), { arch: "arm64" as const });
    const insns = (await dispatch("hybridDisassemble", worker.received[0].args, s)) as {
      mnemonic: string;
    }[];

    expect(insns.every((i) => i.mnemonic === "x86-64")).toBe(true);
    expect(s.csArm64.seen).toEqual([]);
  });

  it.each([
    ["disassemble", (c: DisasmClient) => c.disassemble(new Uint8Array(8), 0x140001000, true)],
    [
      "hybridDisassemble",
      (c: DisasmClient) => c.hybridDisassemble(new Uint8Array(8), 0x140001000, true, []),
    ],
    [
      "detectFunctions",
      (c: DisasmClient) => c.detectFunctions(new Uint8Array(8), 0x140001000, true),
    ],
    [
      "buildAllXrefs",
      (c: DisasmClient) => c.buildAllXrefs(new Uint8Array(8), 0x140001000, true, [], []),
    ],
    ["detectIRPDispatches", (c: DisasmClient) => c.detectIRPDispatches([], true)],
    [
      "decompileFunction",
      (c: DisasmClient) =>
        c.decompileFunction(
          { name: "sub_140001000", address: 0x140001000, size: 16 },
          [],
          new Map(),
          null,
          null,
          true,
          new Map(),
        ),
    ],
  ] as [string, (c: DisasmClient) => Promise<unknown>][])(
    "stamps %s with the declared machine type",
    async (_label, call) => {
      // Every method whose answer depends on which decoder ran. A method left
      // unstamped keeps the old race, silently.
      const { client, worker } = await loadClient();
      client.setImage(ARM64_MACHINE);

      void call(client);

      expect(worker.received[0].args.machine).toBe(ARM64_MACHINE);
    },
  );

  it("sends no machine at all when no image has been declared", async () => {
    // The pre-existing contract: an un-threaded caller gets exactly the
    // behaviour it had before any of this existed, which is the worker's own
    // `state.arch`. `undefined` here is what makes that fallback reachable.
    const { client, worker } = await loadClient();

    void client.disassemble(new Uint8Array(8), 0x401000, false);

    expect(worker.received[0].args.machine).toBeUndefined();
    const s = freshWorkerState();
    await dispatch("disassemble", worker.received[0].args, s);
    expect(s.cs32.seen[0]).toBe(0x401000);
    expect(s.csArm64.seen).toEqual([]);
  });

  it("takes the machine from configure as well, for a caller that skips the handshake", async () => {
    const { client, worker } = await loadClient();

    void client.configure(new Map(), new Map(), { machine: ARM64_MACHINE });
    void client.disassemble(new Uint8Array(8), 0x140001000, true);

    expect(worker.received[1].args.machine).toBe(ARM64_MACHINE);
  });

  it("leaves the machine alone on the second configure, which carries none", async () => {
    // `configure` runs twice per file; the second time from the effect that
    // re-sends the strings after extraction, which knows nothing about the
    // machine type. It must not un-declare the image.
    const { client, worker } = await loadClient();
    client.setImage(ARM64_MACHINE);

    void client.configure(new Map([[1, "hi"]]), new Map());
    void client.disassemble(new Uint8Array(8), 0x140001000, true);

    expect(worker.received[1].args.machine).toBe(ARM64_MACHINE);
  });

  /**
   * peek-a-bin-3ucw. `CHPEMetadataPointer` is read on the far side by exactly one
   * thing — the ARM64 decode-rate refusal's message — so if the client drops it
   * the narrowing is silently unreachable and every other test still passes.
   * Unlike `machine` it rides on `configure` alone and is not on each request,
   * because it decides nothing.
   */
  it("carries the CHPE metadata pointer on configure", async () => {
    const { client, worker } = await loadClient();

    void client.configure(new Map(), new Map(), {
      machine: ARM64_MACHINE,
      chpeMetadataPointer: 0x140020000,
    });

    expect(worker.received[0].method).toBe("configure");
    expect(worker.received[0].args.chpeMetadataPointer).toBe(0x140020000);
  });

  it("sends no CHPE pointer for an image whose load config does not declare one", async () => {
    const { client, worker } = await loadClient();

    void client.configure(new Map(), new Map(), { machine: ARM64_MACHINE });

    expect(worker.received[0].args.chpeMetadataPointer).toBeUndefined();
  });
});

/**
 * The second half of peek-a-bin-x4o2: once a wrong-architecture answer had been
 * computed it was cached under `${baseAddress}:${is64}`, which does not mention
 * the architecture — so every later caller for that input got it too.
 */
describe("DisasmWorkerClient — the disassembly cache key names the architecture", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("gives two architectures two keys for the same address and pointer width", async () => {
    const { mod } = await loadClient();

    expect(mod.disasmCacheKey("arm64", "", 0x140001000, true)).not.toBe(
      mod.disasmCacheKey("x86", "", 0x140001000, true),
    );
  });

  it("still separates the linear sweep from the hybrid one, and the two x86 modes", async () => {
    const { mod } = await loadClient();
    const keys = new Set([
      mod.disasmCacheKey("x86", "", 0x401000, false),
      mod.disasmCacheKey("x86", "", 0x401000, true),
      mod.disasmCacheKey("x86", "hybrid:", 0x401000, false),
      mod.disasmCacheKey("arm64", "hybrid:", 0x401000, false),
    ]);

    expect(keys.size).toBe(4);
  });

  it("does not hand an ARM64 image the instructions cached for an x86 one", async () => {
    // End to end through the client, where declaring an image also drops the
    // caches: two defences, and this is the one a caller can observe.
    const { client, worker } = await loadClient();
    client.setImage(0x8664);
    const first = client.disassemble(new Uint8Array(8), 0x140001000, true);
    worker.reply(worker.posted[0].id, [{ address: 0x140001000, mnemonic: "x86-64", opStr: "" }]);
    await first;

    client.setImage(0xaa64);
    void client.disassemble(new Uint8Array(8), 0x140001000, true);

    // A second request, rather than the x86 answer served from cache.
    expect(worker.posted).toHaveLength(2);
    expect(worker.received[1].args.machine).toBe(0xaa64);
  });

  it("drops the jump tables and the decompile cache when a new image is declared", async () => {
    // Both are keyed on bare addresses, which mean nothing across files: the
    // previous image's table targets would be seeded into this one's recursive
    // descent, and a decompiled function would be served for whatever sits at
    // the same address here.
    const { client, worker } = await loadClient();
    const detected = client.detectFunctions(new Uint8Array(64), 0x401000, false);
    worker.reply(worker.posted[0].id, { functions: [], jumpTables: [[0x40b8f0, [0x40b900]]] });
    await detected;
    expect(client.jumpTables.size).toBe(1);

    client.setImage(0x8664);
    void client.hybridDisassemble(new Uint8Array(8), 0x401000, false, [0x401000]);

    expect(client.jumpTables.size).toBe(0);
    expect(worker.received[1].args.seeds).toEqual([0x401000]);
  });
});

/**
 * peek-a-bin-ybv2: `DetectResult.omitted` names the passes detection could not
 * run, and exists so that a narrower answer stops being shaped exactly like a
 * complete one (peek-a-bin-4s9). The client typed the reply as
 * `{ functions, jumpTables }` and returned `result.functions`, so the field
 * reached the worker boundary and stopped there.
 */
describe("DisasmWorkerClient — detectFunctions reports what it could not run", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("returns the omitted passes alongside the functions", async () => {
    const { client, worker } = await loadClient();

    const pending = client.detectFunctions(new Uint8Array(64), 0x401000, false);
    worker.reply(worker.posted[0].id, {
      functions: [{ name: "sub_401000", address: 0x401000, size: 16 }],
      jumpTables: [],
      // What a null Capstone handle produces: detection still answers from
      // .pdata, exports, the entry point and unwind info, and says so.
      omitted: ["call-targets", "jump-tables"],
    });

    await expect(pending).resolves.toEqual({
      functions: [{ name: "sub_401000", address: 0x401000, size: 16 }],
      omitted: ["call-targets", "jump-tables"],
    });
  });

  it("reports nothing omitted for a complete answer", async () => {
    const { client, worker } = await loadClient();

    const pending = client.detectFunctions(new Uint8Array(64), 0x401000, false);
    worker.reply(worker.posted[0].id, { functions: [], jumpTables: [], omitted: [] });

    expect((await pending).omitted).toEqual([]);
  });

  it("treats a reply with no omitted field as complete", async () => {
    const { client, worker } = await loadClient();

    const pending = client.detectFunctions(new Uint8Array(64), 0x401000, false);
    worker.reply(worker.posted[0].id, { functions: [], jumpTables: [] });

    expect((await pending).omitted).toEqual([]);
  });

  it("still keeps the jump tables it was handed", async () => {
    const { client, worker } = await loadClient();

    const pending = client.detectFunctions(new Uint8Array(64), 0x401000, false);
    worker.reply(worker.posted[0].id, {
      functions: [],
      jumpTables: [[0x40b8f0, [0x40b900]]],
      omitted: ["thunk-names"],
    });
    await pending;

    expect(client.jumpTables.get(0x40b8f0)).toEqual([0x40b900]);
  });
});

/**
 * The one link of the handshake no test can execute.
 *
 * Nothing in this repo renders a component, so `App.handleFile` cannot be run
 * and the claim "the image is declared before the reducer sees the file" is
 * unverifiable by behaviour. It is a straight-line pair of statements, though,
 * and their order is the whole guarantee: a `setImage` that moved below the
 * dispatch — or into an effect — would put the decode back in a race with it,
 * with every test in this file still passing. So the source is read instead.
 *
 * Comments are stripped first, and the check is on relative position rather
 * than on adjacency or indentation, so reformatting cannot break it (the same
 * treatment as the drift guard in ./dispatch.test.ts).
 */
describe("App declares the loaded image before the reducer sees it", () => {
  const source = readFileSync(
    resolve(dirname(fileURLToPath(import.meta.url)), "../../App.tsx"),
    "utf-8",
  )
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");

  it("calls setImage with the COFF machine type", () => {
    expect(source).toMatch(/disasmWorker\.setImage\(\s*pe\.coffHeader\.machine\s*\)/);
  });

  it("calls it above the SET_PE_FILE dispatch", () => {
    const declared = source.indexOf("disasmWorker.setImage(");
    const dispatched = source.indexOf('type: "SET_PE_FILE"');

    expect(declared).toBeGreaterThan(-1);
    expect(dispatched).toBeGreaterThan(-1);
    // Below it, the disassembly effect of an already-mounted DisassemblyView
    // can post a decode for the new file before its architecture is known.
    expect(declared).toBeLessThan(dispatched);
  });
});

/**
 * peek-a-bin-y1di — the spans travel exactly as the targets above do, and for
 * the same reason: `detectFunctions` is the only thing that knows where the
 * tables are, and threading them through `useDisassemblyRows` would put a
 * detail of the sweep into the UI layer. Without them the gap fill decodes each
 * table's case addresses as instructions.
 */
describe("DisasmWorkerClient — jump-table spans are carried to the sweep", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  async function afterDetect(reply: Record<string, unknown>) {
    const { client, worker } = await loadClient();
    const p = client.detectFunctions(new Uint8Array(64), 0x1000, false);
    worker.reply(worker.posted[0].id, { functions: [], jumpTables: [], ...reply });
    await p;
    return { client, worker };
  }

  it("sends the spans detection reported", async () => {
    const spans: [number, number][] = [
      [0x4086a4, 0x4086c4],
      [0x40ba8c, 0x40ba9c],
    ];
    const { client, worker } = await afterDetect({ jumpTableSpans: spans });

    void client.hybridDisassemble(new Uint8Array(64), 0x400000, false, [0x401000]);

    expect(worker.received[1].args.jumpTableSpans).toEqual(spans);
  });

  it("sends none when a reply carries no spans at all", async () => {
    // A worker from before the field existed says nothing about tables, which
    // is the behaviour the sweep had all along.
    const { client, worker } = await afterDetect({});

    void client.hybridDisassemble(new Uint8Array(64), 0x400000, false, []);

    expect(worker.received[1].args.jumpTableSpans).toEqual([]);
  });

  it("forgets them when a new image is declared", async () => {
    const { client, worker } = await afterDetect({ jumpTableSpans: [[0x4086a4, 0x4086c4]] });
    client.setImage(0x8664);

    void client.hybridDisassemble(new Uint8Array(64), 0x400000, true, []);

    expect(worker.received[1].args.jumpTableSpans).toEqual([]);
  });
});

/**
 * peek-a-bin-s2ws — the client hands the worker what the callee-clobber summary
 * needs, and the round trip actually produces one.
 *
 * `dispatch.test.ts` pins the worker's half. What it cannot see is the wire: the
 * summary needs function *extents*, and the payload that already crosses carries
 * `funcEntries` — display names, rebuilt on every rename — which have no sizes in
 * them. This block asserts the two halves meet, by posting through the real
 * client and answering with the real dispatch, so the message under test is the
 * post-`structuredClone` one a worker would actually receive.
 *
 * That combination is why this needed no browser in the end. The bead assumed a
 * summary had to arrive out of band and would race the first decompile; in fact
 * the decompile request already carries the whole section's instructions, so the
 * summary is derived from the same message that consumes it.
 */
describe("DisasmWorkerClient — the decompile request carries the callee-clobber inputs", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const CALLER = 0x401000;
  const CALLEE = 0x401100;
  const caller = { name: "sub_401000", address: CALLER, size: 0x10 };
  const callee = { name: "sub_401100", address: CALLEE, size: 0x8 };

  const insn = (address: number, mnemonic: string, opStr: string, size: number): Instruction => ({
    address,
    mnemonic,
    opStr,
    size,
    bytes: new Uint8Array(size),
  });

  /** `mov r10, rcx` / `call sub_401100` / `mov [rsi], r10` / `ret`, then the
   *  callee's `xor r10d, r10d` / `ret`. Address-ascending. */
  const instructions = () => [
    insn(CALLER, "mov", "r10, rcx", 3),
    insn(CALLER + 3, "call", `0x${CALLEE.toString(16)}`, 5),
    insn(CALLER + 8, "mov", "qword ptr [rsi], r10", 4),
    insn(CALLER + 12, "ret", "", 1),
    insn(CALLEE, "xor", "r10d, r10d", 3),
    insn(CALLEE + 3, "ret", "", 1),
  ];

  function post(client: DisasmClient, insns: Instruction[], withFuncs: boolean, is64 = true) {
    return client.decompileFunction(
      caller,
      insns,
      new Map(),
      null,
      null,
      is64,
      new Map([
        [caller.address, { name: caller.name, address: caller.address }],
        [callee.address, { name: callee.name, address: callee.address }],
      ]),
      undefined,
      withFuncs ? [caller, callee] : undefined,
    );
  }

  /** A worker state with Capstone absent — nothing here decodes bytes. */
  const freshState = () => createWorkerState(Promise.resolve());

  /**
   * Pump every message the client posts through the real `dispatch`, in order,
   * replying to each — which is what a serially-servicing worker does, and the
   * only way a request that provokes a *second* request can be exercised at all.
   *
   * The loop re-reads `worker.posted.length` on each pass, so a retry the client
   * posts in reaction to a reply is picked up rather than assumed away.
   */
  async function drive<T>(
    worker: {
      posted: PostedMessage[];
      received: PostedMessage[];
      reply(id: number, r: unknown): void;
    },
    state: WorkerState,
    call: () => Promise<T>,
  ): Promise<T> {
    // From the messages THIS call posts, never from index 0: re-servicing an
    // earlier request would re-run its side effects on `state` — a second pass
    // over a decompile retry rebuilds the clobber summary, which silently turns
    // a later cache-miss test into a cache hit.
    const from = worker.posted.length;
    const pending = call();
    for (let i = from; i < worker.posted.length; i++) {
      const msg = worker.received[i];
      const result = await dispatch(msg.method as never, msg.args, state);
      worker.reply(worker.posted[i].id, result);
      // Let the client's continuation run: it may post the retry.
      await Promise.resolve();
      await Promise.resolve();
    }
    return pending;
  }

  it("sends every function's extents, which funcEntries cannot supply", async () => {
    const { client, worker } = await loadClient();

    post(client, instructions(), true);

    const args = worker.received[0].args;
    expect(args.funcExtents).toEqual([
      [CALLER, 0x10],
      [CALLEE, 0x8],
    ]);
    // The names still travel separately: they carry renames, so they cannot be
    // cached against the instruction array the way the extents are.
    expect(args.funcEntries).toHaveLength(2);
    expect(typeof args.insnsToken).toBe("number");
  });

  it("produces a clobber when the real dispatch answers the real message", async () => {
    // End to end across the hop: post through the client, then hand the
    // *received* args — everything having survived structured clone — to the
    // dispatch. Nothing here is a mock of the thing under test.
    //
    // Driven through the pump rather than one message, because the section's
    // instructions no longer cross on every request: the first request of a file
    // is answered with `needInstructions` and the client resends
    // (peek-a-bin-9gc9). What this asserts is unchanged — a clobber reaches the
    // emitted C — and the number of messages it takes is asserted next door.
    const { client, worker } = await loadClient();

    const code = (await drive(worker, freshState(), () => post(client, instructions(), true))).code;

    const store = code.split("\n").find((l) => l.includes("(rsi)"));
    expect(store).toMatch(/clobbered_r10_\d+/);
    // Without the extents this same store reads `= rcx`: a value the callee has
    // provably zeroed, stated with no marker at all.
    expect(store).not.toMatch(/=\s*rcx\s*;/);
  });

  it("omits both fields when the caller has no extents, keeping the old behaviour", async () => {
    // Absent must mean byte-identical to the pre-summary path, which is what let
    // the worker side land before the client side did.
    const { client, worker } = await loadClient();

    post(client, instructions(), false);

    expect(worker.received[0].args.funcExtents).toBeUndefined();
    expect(worker.received[0].args.insnsToken).toBeUndefined();
  });

  it("gives one instruction array one token, and a different array a different one", async () => {
    // The token stands in for array identity, which structured clone destroys.
    // Reusing it across two different disassemblies would serve one image's
    // summary for another; minting a fresh one per request would defeat the
    // cache entirely and pay a whole-image walk per click.
    const { client, worker } = await loadClient();
    const insns = instructions();

    post(client, insns, true);
    post(client, insns, true);
    post(client, instructions(), true);

    const tokens = worker.received.map((m) => m.args.insnsToken);
    expect(tokens[0]).toBe(tokens[1]);
    expect(tokens[2]).not.toBe(tokens[0]);
  });
});

/**
 * peek-a-bin-x40u — one x86 load sweeps `.text` once, not three times.
 *
 * `detectFunctions` and `buildAllXrefs` swept the section end to end in loops
 * that were provably the same loop (verified element for element over five real
 * images), and App.tsx posts a *second* `buildAllXrefs` when string extraction
 * lands after detection — so a load paid for three identical sweeps. They now
 * share one, held in `WorkerState.x86Sweep` and keyed on the section's bytes.
 * Measured through this same path with real Capstone at `6f2ce28`: `buildAllXrefs`
 * 729 ms to 76 on a 669 KiB `.text`, and the whole load 3130 ms to 1666.
 *
 * These drive the real client and answer with the real dispatch, because the
 * bead's own verification gap was that **no harness drives the worker RPC path
 * at all** — the corpus suite goes through `FileSession`, which has no worker and
 * no session state. Two negative controls, in opposite directions: a memo that
 * never stores (so the saving is provably the memo's) and a memo that serves a
 * stale entry (so the content key is provably load-bearing).
 */
describe("DisasmWorkerClient — one x86 load sweeps .text once", () => {
  const TEXT_BASE = 0x401000;
  const AMD64 = 0x8664;
  const ARM64_MACHINE = 0xaa64;
  /** Where the emitted `mov` points, and what the second xref build calls a string. */
  const STRING_ADDR = TEXT_BASE + 0x30;

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /**
   * A stub x86 decoder whose *answer depends on the section's bytes*, which is
   * what lets a stale hit be told from a correct one.
   *
   * Four bytes per instruction: the first is a `call` whose target is derived
   * from `bytes[0]`, the second a `mov` naming {@link STRING_ADDR}, the rest
   * `nop`. It counts its own entries, since an instruction count cannot
   * distinguish a memo hit from a miss and a decode count can.
   *
   * **Both mnemonics are chosen by ABSOLUTE address, not by offset within the
   * window** — the property every real decoder has and the one this whole
   * scheme rests on, that what an address decodes to does not depend on where
   * the window handed to Capstone happened to start. It was written as
   * `i === 4` and that made the stub answer differently for a whole-section
   * sweep than for `hybridDisassemble`'s 15-byte per-address windows, so
   * peek-a-bin-iqzu's serve and the decode it replaces provably disagreed —
   * about the stub, not about any file. Do not put an `i`-relative rule back.
   */
  function countingX86() {
    const stub = {
      calls: 0,
      disasm(bytes: Uint8Array, options: { address: number }) {
        stub.calls++;
        const out: {
          address: number;
          mnemonic: string;
          opStr: string;
          size: number;
          bytes: Uint8Array;
        }[] = [];
        // The call target is a function of the content, so two sections of the
        // same length at the same address decode to different call graphs.
        const callee = TEXT_BASE + (bytes[0] & 0x30);
        for (let i = 0; i + 4 <= bytes.length; i += 4) {
          const first = options.address + i === TEXT_BASE;
          out.push({
            address: options.address + i,
            mnemonic: first ? "call" : options.address + i === TEXT_BASE + 4 ? "mov" : "nop",
            opStr: first
              ? `0x${callee.toString(16)}`
              : options.address + i === TEXT_BASE + 4
                ? `eax, 0x${STRING_ADDR.toString(16)}`
                : "",
            size: 4,
            bytes: bytes.subarray(i, i + 4),
          });
        }
        return out;
      },
    };
    return stub;
  }

  function workerState(cs: ReturnType<typeof countingX86>): WorkerState {
    return Object.assign(createWorkerState(Promise.resolve()), {
      cs32: cs,
      cs64: cs,
      csArm64: cs,
      arch: "x86" as const,
    });
  }

  /** A fresh view of the section, as `prepareBinaryArgs` hands each RPC. */
  const section = (fill = 0x5a) => new Uint8Array(0x40).fill(fill);

  /**
   * The extents the xref build needs to draw a call edge at all: it records one
   * only when the target is a known function start and the call site is inside
   * one. Both call targets the stub can produce are listed, so a wrong sweep
   * shows up as the wrong edge rather than as no edge.
   */
  const EXTENTS: [number, number][] = [
    [TEXT_BASE, 0x10],
    [TEXT_BASE + 0x10, 0x10],
    [TEXT_BASE + 0x20, 0x20],
  ];

  /**
   * One load's worth of x86 RPCs, posted through the real client and answered
   * by the real dispatch in the order a serially-servicing worker sees them.
   *
   * Four calls, App.tsx's own sequence: detect, the view, the xref build the
   * detection chain posts, and the rebuild the strings effect posts when
   * detection got there first.
   */
  async function load(
    cs: ReturnType<typeof countingX86>,
    s: WorkerState,
    fill = 0x5a,
  ): Promise<{
    det: unknown;
    insns: unknown;
    xr1: { callGraph: [number, number[]][]; stringXrefs: [number, number[]][] };
    xr2: { callGraph: [number, number[]][]; stringXrefs: [number, number[]][] };
    decodes: number;
    hybridDecodes: number;
    sweeps: number;
  }> {
    const { client, worker } = await loadClient();
    client.setImage(AMD64);
    void client.detectFunctions(section(fill), TEXT_BASE, true, { entryPoint: TEXT_BASE });
    void client.hybridDisassemble(section(fill), TEXT_BASE, true, [TEXT_BASE]);
    void client.buildAllXrefs(section(fill), TEXT_BASE, true, [], [], EXTENTS);
    // The second build differs from the first only in its string set — the whole
    // reason it exists, and the reason it must still re-run the resolve.
    void client.buildAllXrefs(section(fill), TEXT_BASE, true, [STRING_ADDR], [], EXTENTS);
    expect(worker.received.map((m) => m.method)).toEqual([
      "detectFunctions",
      "hybridDisassemble",
      "buildAllXrefs",
      "buildAllXrefs",
    ]);

    const det = await dispatch("detectFunctions", worker.received[0].args, s);
    const afterDetect = cs.calls;
    const insns = await dispatch("hybridDisassemble", worker.received[1].args, s);
    const afterHybrid = cs.calls;
    const xr1 = (await dispatch("buildAllXrefs", worker.received[2].args, s)) as {
      callGraph: [number, number[]][];
      stringXrefs: [number, number[]][];
    };
    const xr2 = (await dispatch("buildAllXrefs", worker.received[3].args, s)) as {
      callGraph: [number, number[]][];
      stringXrefs: [number, number[]][];
    };
    // Split, because peek-a-bin-iqzu made the third and fourth RPCs of this
    // load stop decoding too: `sweeps` is this bead's saving alone.
    return {
      det,
      insns,
      xr1,
      xr2,
      decodes: cs.calls,
      hybridDecodes: afterHybrid - afterDetect,
      sweeps: cs.calls - afterHybrid,
    };
  }

  /**
   * The negative control for the saving: a memo that computes every time and
   * remembers nothing, i.e. exactly the tree before this change.
   */
  function neverStores(s: WorkerState): WorkerState {
    s.x86Sweep.clear();
    const real = s.x86Sweep.sweep.bind(s.x86Sweep);
    s.x86Sweep.sweep = (...args: Parameters<typeof real>) => {
      const out = real(...args);
      s.x86Sweep.clear();
      return out;
    };
    return s;
  }

  it("sweeps the section once for detect and both xref builds", async () => {
    const shared = countingX86();
    const withMemo = await load(shared, workerState(shared));

    const alone = countingX86();
    const without = await load(alone, neverStores(workerState(alone)));

    expect(withMemo.decodes).toBeLessThan(without.decodes);
    // Two of the three sweeps are gone. The section is 0x40 bytes, one window,
    // so a sweep is exactly one decode here. Counted after `hybridDisassemble`,
    // because peek-a-bin-iqzu stopped that method decoding as well and the two
    // savings must stay separately attributable.
    expect(without.sweeps - withMemo.sweeps).toBe(2);
    expect(withMemo.sweeps).toBe(0);
  });

  it("answers exactly what it answered when each RPC swept for itself", async () => {
    const shared = countingX86();
    const withMemo = await load(shared, workerState(shared));

    const alone = countingX86();
    const without = await load(alone, neverStores(workerState(alone)));

    expect(withMemo.det).toEqual(without.det);
    expect(withMemo.insns).toEqual(without.insns);
    expect(withMemo.xr1).toEqual(without.xr1);
    expect(withMemo.xr2).toEqual(without.xr2);
  });

  it("re-runs the resolve on a hit, so a larger string set still finds more", async () => {
    // The saving must be the decode and nothing else: the second build's whole
    // purpose is that its string set grew, and a memo that short-circuited the
    // resolve would silently answer the first build's question twice.
    const cs = countingX86();
    const { xr1, xr2 } = await load(cs, workerState(cs));

    expect(xr1.stringXrefs).toEqual([]);
    expect(xr2.stringXrefs).toEqual([[STRING_ADDR, [TEXT_BASE + 4]]]);
    expect(xr2.callGraph).toEqual(xr1.callGraph);
  });

  it("does not serve one file's sweep to another with the same address and length", async () => {
    // The content key, doing the work it exists for. Both sections are 0x40
    // bytes at 0x401000 and decode differently, which is the collision a cheap
    // `(buffer, offset, length)` key cannot see — see src/workers/transfer.ts
    // for why that key was refused outright.
    const cs = countingX86();
    const s = workerState(cs);

    const first = await load(cs, s, 0x5a);
    const second = await load(cs, s, 0xa5);

    expect(first.xr1.callGraph).toEqual([[TEXT_BASE, [TEXT_BASE + 0x10]]]);
    expect(second.xr1.callGraph).toEqual([[TEXT_BASE, [TEXT_BASE + 0x20]]]);
  });

  it("would serve a stale answer under a length-and-address key", async () => {
    // The other negative control, and the one that makes the assertion above
    // mean something: with the key weakened to what a cheap scheme could
    // afford, the second file's xrefs are the FIRST file's — a complete,
    // plausible answer about bytes the image does not contain.
    const cs = countingX86();
    const s = workerState(cs);
    const held = new Map<string, unknown>();
    s.x86Sweep.sweep = ((bytes: Uint8Array, base: number, handle: unknown, where: string) => {
      const key = `${base}:${bytes.length}`;
      const hit = held.get(key);
      if (hit) return hit;
      const value = sweepX86(bytes, base, handle as never, where);
      held.set(key, value);
      return value;
    }) as typeof s.x86Sweep.sweep;

    await load(cs, s, 0x5a);
    const second = await load(cs, s, 0xa5);

    expect(second.xr1.callGraph).toEqual([[TEXT_BASE, [TEXT_BASE + 0x10]]]);
  });

  it("drops the held sweep when configure declares a machine type", async () => {
    const cs = countingX86();
    const s = workerState(cs);
    const args = { bytes: section(), baseAddress: TEXT_BASE, is64: true, machine: AMD64 };

    await dispatch("buildAllXrefs", { ...args, stringAddrs: [], iatAddrs: [] }, s);
    const afterFirst = cs.calls;
    await dispatch("configure", { stringEntries: [], iatEntries: [], machine: AMD64 }, s);
    await dispatch(
      "buildAllXrefs",
      { ...args, bytes: section(), stringAddrs: [], iatAddrs: [] },
      s,
    );

    expect(cs.calls).toBeGreaterThan(afterFirst);
  });

  it("keeps the held sweep across a configure that declares no machine type", async () => {
    // The second `configure` of a load re-sends the strings and knows nothing
    // about the machine. It is not a new file and must not cost a re-sweep —
    // which is precisely the moment the second `buildAllXrefs` is posted.
    const cs = countingX86();
    const s = workerState(cs);
    const args = { bytes: section(), baseAddress: TEXT_BASE, is64: true, machine: AMD64 };

    await dispatch("buildAllXrefs", { ...args, stringAddrs: [], iatAddrs: [] }, s);
    const afterFirst = cs.calls;
    await dispatch("configure", { stringEntries: [], iatEntries: [] }, s);
    await dispatch(
      "buildAllXrefs",
      { ...args, bytes: section(), stringAddrs: [], iatAddrs: [] },
      s,
    );

    expect(cs.calls).toBe(afterFirst);
  });

  it("never consults the x86 memo on the ARM64 path", async () => {
    const cs = countingX86();
    const s = Object.assign(workerState(cs), { arch: "arm64" as const });
    let consulted = 0;
    const real = s.x86Sweep.sweep.bind(s.x86Sweep);
    s.x86Sweep.sweep = (...a: Parameters<typeof real>) => {
      consulted++;
      return real(...a);
    };
    const common = {
      bytes: section(),
      baseAddress: TEXT_BASE,
      is64: true,
      machine: ARM64_MACHINE,
      seeds: [],
    };

    await dispatch("detectFunctions", { ...common, options: {} }, s);
    await dispatch("hybridDisassemble", common, s);
    await dispatch("buildAllXrefs", { ...common, stringAddrs: [], iatAddrs: [] }, s);

    expect(consulted).toBe(0);
  });

  it("does not let a single-function decode evict the section", async () => {
    // `disassemble` may be handed a sub-range and is deliberately not routed
    // through the memo, exactly as on the ARM64 side: the memo holds one
    // section, so a 16-byte decode taking its slot would cost the next xref
    // build a whole sweep.
    const cs = countingX86();
    const s = workerState(cs);
    const common = { baseAddress: TEXT_BASE, is64: true, machine: AMD64 };

    await dispatch(
      "buildAllXrefs",
      { ...common, bytes: section(), stringAddrs: [], iatAddrs: [] },
      s,
    );
    const afterSection = cs.calls;
    await dispatch("disassemble", { ...common, bytes: new Uint8Array(0x10).fill(0x5a) }, s);
    await dispatch(
      "buildAllXrefs",
      { ...common, bytes: section(), stringAddrs: [], iatAddrs: [] },
      s,
    );

    expect(cs.calls).toBe(afterSection + 1);
  });
});

/**
 * peek-a-bin-iqzu — `hybridDisassemble` decodes through the sweep the load has
 * already paid for, instead of running Capstone over `.text` for itself.
 *
 * peek-a-bin-x40u shared the sweep between `detectFunctions` and both
 * `buildAllXrefs` calls and deliberately left this one out, because it is not a
 * transcription of the sweep: recursive descent over a BFS work queue plus a
 * gap fill produces a different, annotated, smaller stream, one instruction at a
 * time at addresses a *caller* named. It left the number that decides it
 * untaken. Taken: over the four corpus binaries and a 669 KiB-`.text` `go`
 * image, **99.9-100.0% of the 222137 instructions this method decodes are at an
 * address the grid also holds an instruction at, and 100.0% of those agree in
 * mnemonic, operands and size**. So the decoder underneath is shared
 * (`gridScan`) while all three phases keep their own stepping. Measured through
 * this path with real Capstone, both sides pinned in one process: hybrid
 * 798 ms to 192 on the `go` image, 135 to 26 on t32, 73 to 12 on w64, with the
 * returned `Instruction[]` identical element for element and field for field
 * — `bytes` and `source` and `comment` included — on all five.
 *
 * These drive the real client answered by the real dispatch, for the reason x40u
 * records: no corpus harness drives the worker RPC path at all. Two negative
 * controls in opposite directions, plus the one that is specific to peeking —
 * that a miss must leave the slot exactly as it found it.
 */
describe("DisasmWorkerClient — hybridDisassemble decodes through the held sweep", () => {
  const TEXT_BASE = 0x401000;
  const AMD64 = 0x8664;

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  /**
   * A decoder whose answer depends on the section's bytes, so a stale grid is
   * distinguishable from a correct one, and which counts its own entries, since
   * an instruction count cannot tell a serve from a decode and a decode count
   * can.
   */
  function countingX86() {
    const stub = {
      calls: 0,
      disasm(bytes: Uint8Array, options: { address: number; count?: number }) {
        stub.calls++;
        const out: {
          address: number;
          mnemonic: string;
          opStr: string;
          size: number;
          bytes: Uint8Array;
        }[] = [];
        const limit = options.count ?? Number.POSITIVE_INFINITY;
        for (let i = 0; i + 4 <= bytes.length && out.length < limit; i += 4) {
          out.push({
            address: options.address + i,
            // A function of the CONTENT, so two sections of the same length at
            // the same address decode to different operand text.
            mnemonic: bytes[i] === 0x5a ? "nop" : "hlt",
            opStr: `0x${bytes[i].toString(16)}`,
            size: 4,
            bytes: bytes.subarray(i, i + 4),
          });
        }
        if (out.length === 0) throw new Error("Failed to disassemble");
        return out;
      },
    };
    return stub;
  }

  function workerState(cs: ReturnType<typeof countingX86>): WorkerState {
    return Object.assign(createWorkerState(Promise.resolve()), {
      cs32: cs,
      cs64: cs,
      csArm64: cs,
      arch: "x86" as const,
    });
  }

  /** A fresh view of the section, as `prepareBinaryArgs` hands each RPC. */
  const section = (fill = 0x5a) => new Uint8Array(0x40).fill(fill);

  /**
   * Detect then disassemble, in App.tsx's own order and through the real client.
   *
   * That order is structural rather than lucky: `useDisassemblyRows.ts` posts
   * `hybridDisassemble` only when `state.functions` is non-empty, i.e. only
   * after `detectFunctions` has answered — which is what fills the slot.
   */
  async function load(
    s: WorkerState,
    fill = 0x5a,
  ): Promise<{ insns: Instruction[]; sweepDecodes: number; hybridDecodes: number }> {
    const { client, worker } = await loadClient();
    client.setImage(AMD64);
    void client.detectFunctions(section(fill), TEXT_BASE, true, { entryPoint: TEXT_BASE });
    void client.hybridDisassemble(section(fill), TEXT_BASE, true, [TEXT_BASE]);
    expect(worker.received.map((m) => m.method)).toEqual(["detectFunctions", "hybridDisassemble"]);

    const cs = s.cs64 as unknown as ReturnType<typeof countingX86>;
    await dispatch("detectFunctions", worker.received[0].args, s);
    const sweepDecodes = cs.calls;
    const insns = (await dispatch(
      "hybridDisassemble",
      worker.received[1].args,
      s,
    )) as Instruction[];
    return { insns, sweepDecodes, hybridDecodes: cs.calls - sweepDecodes };
  }

  /**
   * The negative control for the saving: a memo that holds nothing, i.e. the
   * tree before this change, where detection swept and this method could not see
   * the result.
   */
  function neverHolds(s: WorkerState): WorkerState {
    s.x86Sweep.peek = () => undefined;
    return s;
  }

  it("runs the decoder not at all, where before it ran it for every instruction", async () => {
    const cs = countingX86();
    const shared = await load(workerState(cs));

    const alone = countingX86();
    const without = await load(neverHolds(workerState(alone)));

    expect(shared.hybridDecodes).toBe(0);
    expect(without.hybridDecodes).toBeGreaterThan(0);
  });

  it("answers exactly what it answered when it decoded for itself", async () => {
    // The claim the whole change rests on, and the one a coincidence rate cannot
    // make on its own: the served stream must be the decoded stream. Compared
    // field for field, `bytes` included, because a served instruction builds its
    // own record rather than passing Capstone's through.
    const shared = await load(workerState(countingX86()));
    const without = await load(neverHolds(workerState(countingX86())));

    expect(shared.insns).toEqual(without.insns);
    expect(shared.insns.length).toBeGreaterThan(0);
  });

  it("gives every served instruction its own bytes buffer", async () => {
    // A `subarray` of the section would read identically here and would make
    // the reply's structured clone serialise the whole `.text` once per
    // instruction. There is no other check for it: the values are right either
    // way.
    const { insns } = await load(workerState(countingX86()));

    for (const insn of insns) {
      expect(insn.bytes.buffer.byteLength).toBe(insn.size);
    }
  });

  it("would answer about the wrong bytes under a length-and-address key", async () => {
    // The other negative control. The grid this method now reads is the same
    // entry `buildAllXrefs` reads, so the content key is load-bearing here too:
    // weakened to what a cheap `(buffer, offset, length)` scheme could afford,
    // the second file's disassembly is the FIRST file's — complete, plausible,
    // and about bytes the image does not contain.
    const cs = countingX86();
    const s = workerState(cs);
    const held = new Map<string, SweptInsn[]>();
    s.x86Sweep.sweep = ((bytes: Uint8Array, base: number, handle: never, where: string) => {
      const key = `${base}:${bytes.length}`;
      const hit = held.get(key);
      if (hit) return hit;
      const value = sweepX86(bytes, base, handle, where);
      held.set(key, value);
      return value;
    }) as typeof s.x86Sweep.sweep;
    s.x86Sweep.peek = ((bytes: Uint8Array, base: number) =>
      held.get(`${base}:${bytes.length}`)) as typeof s.x86Sweep.peek;

    const first = await load(s, 0x5a);
    const second = await load(s, 0xa5);

    expect(first.insns[0].mnemonic).toBe("nop");
    // Correct would be "hlt": these are different bytes.
    expect(second.insns[0].mnemonic).toBe("nop");
  });

  it("does not serve one file's grid to another with the same address and length", async () => {
    // The same pair, with the real key. This is the assertion the control above
    // exists to give meaning to.
    const s = workerState(countingX86());

    const first = await load(s, 0x5a);
    const second = await load(s, 0xa5);

    expect(first.insns[0].mnemonic).toBe("nop");
    expect(second.insns[0].mnemonic).toBe("hlt");
  });

  it("does not evict the section when it is handed different bytes", async () => {
    // PEEK, not `sweep`, and this is the case that makes the difference visible:
    // a hex patch hands this method a modified copy of the section while the
    // slot holds the original. It must decode for itself AND leave the slot
    // alone, or the next `buildAllXrefs` of the same load pays for a sweep the
    // memo had already bought.
    const cs = countingX86();
    const s = workerState(cs);
    const common = { baseAddress: TEXT_BASE, is64: true, machine: AMD64 };

    await dispatch(
      "detectFunctions",
      { ...common, bytes: section(), options: { entryPoint: TEXT_BASE } },
      s,
    );
    const afterDetect = cs.calls;

    const patched = section();
    patched[0] = 0xa5;
    const patchedInsns = (await dispatch(
      "hybridDisassemble",
      { ...common, bytes: patched, seeds: [TEXT_BASE] },
      s,
    )) as Instruction[];
    const afterHybrid = cs.calls;

    // It read the patch rather than the held grid...
    expect(patchedInsns[0].mnemonic).toBe("hlt");
    // ...it decoded to do so...
    expect(afterHybrid).toBeGreaterThan(afterDetect);

    // ...and the section is STILL what the slot holds, so the xref build that
    // follows is a hit and adds no decode. Under `sweep` instead of `peek` the
    // patch would have taken the slot and this would sweep again.
    await dispatch(
      "buildAllXrefs",
      { ...common, bytes: section(), stringAddrs: [], iatAddrs: [] },
      s,
    );

    expect(cs.calls).toBe(afterHybrid);
  });

  it("never consults the x86 grid on the ARM64 path", async () => {
    const cs = countingX86();
    const s = Object.assign(workerState(cs), { arch: "arm64" as const });
    let consulted = 0;
    const real = s.x86Sweep.peek.bind(s.x86Sweep);
    s.x86Sweep.peek = (...a: Parameters<typeof real>) => {
      consulted++;
      return real(...a);
    };

    await dispatch(
      "hybridDisassemble",
      {
        bytes: section(),
        baseAddress: 0x140001000,
        is64: true,
        machine: 0xaa64,
        seeds: [],
      },
      s,
    );

    expect(consulted).toBe(0);
  });
});

/**
 * peek-a-bin-9gc9 — the decompile request carries ONE function's instructions.
 *
 * The whole section's `Instruction[]` was 72-97% of a decompile request and the
 * whole section's xref map another 7-14%, so the payload was 92-99% of what a
 * click cost: 652 ms and 65 ms of clone against 5.9 ms of decompiling on a 669
 * KiB-`.text` `go` image, measured at 11408ac by `corpus/decompileRpcCost.ts`.
 * Neither array was read in full. `decompileFunction` passes the instructions to
 * `buildCFG`, which narrows them with `getFuncInsns`, and passes the map to the
 * same place, which reads it only at those instructions' addresses.
 *
 * The one consumer of the whole section is the callee-clobber summary, which is
 * closed over the call graph and cached against the client's token — so it is
 * read on the first request bearing one and never again. That is what the
 * `needInstructions` reply is for, and the two things this block has to pin are
 * that the ask happens when it must and that it does not happen when it need
 * not: a request answered *without* a summary it should have had is well-formed
 * C that the client's address-keyed decompile cache then serves for the rest of
 * the session.
 *
 * Everything here goes through the real client and the real `dispatch`. Nothing
 * is mocked but the `Worker` itself, and the args each test reads are the
 * post-`structuredClone` ones a worker would receive.
 */
describe("DisasmWorkerClient — a decompile request carries one function's instructions", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const A = 0x140001000; // the function under test
  const B = 0x140001100; // its callee, which zeroes r10
  const C = 0x140001200; // a third function, so the section is bigger than either
  // Size = the sum of its instructions' sizes, as a detected function's is. A
  // padded size would make the slim window's boundary untestable: an off-by-one
  // would still contain every instruction.
  const fnA = { name: "sub_140001000", address: A, size: 13 };
  const fnB = { name: "sub_140001100", address: B, size: 0x8 };
  const fnC = { name: "sub_140001200", address: C, size: 0x8 };

  const insn = (address: number, mnemonic: string, opStr: string, size: number): Instruction => ({
    address,
    mnemonic,
    opStr,
    size,
    bytes: new Uint8Array(size),
  });

  /** Address-ascending, as `hybridDisassemble` returns it. */
  const section = (): Instruction[] => [
    insn(A, "mov", "r10, rcx", 3),
    insn(A + 3, "call", `0x${B.toString(16)}`, 5),
    insn(A + 8, "mov", "qword ptr [rsi], r10", 4),
    insn(A + 12, "ret", "", 1),
    insn(B, "xor", "r10d, r10d", 3),
    insn(B + 3, "ret", "", 1),
    insn(C, "xor", "eax, eax", 2),
    insn(C + 2, "ret", "", 1),
  ];

  /** One branch xref in each function, so a whole-section map has three rows. */
  const xrefs = (): Map<number, Xref[]> =>
    new Map<number, Xref[]>([
      [A + 8, [{ from: A, to: A + 8, type: "branch" } as unknown as Xref]],
      [B + 3, [{ from: B, to: B + 3, type: "branch" } as unknown as Xref]],
      [C + 2, [{ from: C, to: C + 2, type: "branch" } as unknown as Xref]],
    ]);

  const names = new Map([
    [A, { name: fnA.name, address: A }],
    [B, { name: fnB.name, address: B }],
    [C, { name: fnC.name, address: C }],
  ]);

  const freshState = () => createWorkerState(Promise.resolve());

  /** The section array for the current test; see {@link ask}. */
  let shared: Instruction[] = [];
  beforeEach(() => {
    shared = section();
  });

  /**
   * ONE array per test, deliberately. `insnsToken` is minted per array
   * *identity*, and in the app every decompile request for a file names the
   * array `hybridDisassemble` returned — so a helper that rebuilt it per call
   * would mint a fresh token each time and never exercise a cache hit at all.
   */
  function ask(
    client: DisasmClient,
    func: { name: string; address: number; size: number },
    opts: {
      extents?: boolean;
      is64?: boolean;
      insns?: Instruction[];
      pdata?: RuntimeFunction[];
    } = {},
  ) {
    return client.decompileFunction(
      func,
      opts.insns ?? shared,
      xrefs(),
      null,
      null,
      opts.is64 ?? true,
      names,
      opts.pdata,
      opts.extents === false ? undefined : [fnA, fnB, fnC],
    );
  }

  /** As above: service each posted message with the real dispatch, in order. */
  async function drive<T>(
    worker: {
      posted: PostedMessage[];
      received: PostedMessage[];
      reply(id: number, r: unknown): void;
    },
    state: WorkerState,
    call: () => Promise<T>,
  ): Promise<T> {
    // From the messages THIS call posts, never from index 0: re-servicing an
    // earlier request would re-run its side effects on `state` — a second pass
    // over a decompile retry rebuilds the clobber summary, which silently turns
    // a later cache-miss test into a cache hit.
    const from = worker.posted.length;
    const pending = call();
    for (let i = from; i < worker.posted.length; i++) {
      const result = await dispatch(
        worker.received[i].method as never,
        worker.received[i].args,
        state,
      );
      worker.reply(worker.posted[i].id, result);
      await Promise.resolve();
      await Promise.resolve();
    }
    return pending;
  }

  it("sends this function's instructions and not the section's", async () => {
    const { client, worker } = await loadClient();

    void ask(client, fnA);

    const args = worker.received[0].args;
    expect(args.funcInsns.map((i: Instruction) => i.address)).toEqual([A, A + 3, A + 8, A + 12]);
    // The four the section holds for B and C are not in the message at all.
    expect(args.instructions).toBeUndefined();
  });

  it("sends this function's xref rows and not the section's", async () => {
    const { client, worker } = await loadClient();

    void ask(client, fnA);

    expect(worker.received[0].args.xrefEntries.map(([a]: [number]) => a)).toEqual([A + 8]);
  });

  it("gives the same emitted C as the whole-section payload did", async () => {
    // The claim the whole change rests on, asked of the real dispatch: hand it
    // the slim message and then the pre-change message, and compare. The corpus
    // answers this at scale (0 of 3059 functions differ over five real images);
    // this is the same question where a test can see it.
    const { client, worker } = await loadClient();

    const slim = await drive(worker, freshState(), () => ask(client, fnA));

    const legacy = worker.received[0].args;
    const whole = (await dispatch(
      "decompileFunction",
      { ...legacy, funcInsns: undefined, instructions: section() },
      freshState(),
    )) as { code: string };

    expect(slim.code).toBe(whole.code);
    // Non-vacuous: there is a body to compare.
    expect(slim.code).toContain("(rsi)");
  });

  it("asks for the section exactly once, and the retry carries it", async () => {
    const { client, worker } = await loadClient();

    const result = await drive(worker, freshState(), () => ask(client, fnA));

    expect(worker.received).toHaveLength(2);
    expect(worker.received[0].args.instructions).toBeUndefined();
    expect(worker.received[1].args.instructions).toHaveLength(8);
    // The retry is not a bare resend of the array: it is the same request again,
    // so the worker needs no memory of the first attempt.
    expect(worker.received[1].args.func.address).toBe(A);
    expect(worker.received[1].args.funcInsns).toHaveLength(4);
    const store = result.code.split("\n").find((l) => l.includes("(rsi)"));
    expect(store).toMatch(/clobbered_r10_\d+/);
  });

  it("does not ask again once the worker holds the summary", async () => {
    // The point of the token: the second function of a file is a single message.
    const { client, worker } = await loadClient();
    const state = freshState();

    await drive(worker, state, () => ask(client, fnA));
    const afterFirst = worker.received.length;
    await drive(worker, state, () => ask(client, fnC));

    expect(afterFirst).toBe(2);
    expect(worker.received.length - afterFirst).toBe(1);
  });

  it("never asks when the caller sent no extents", async () => {
    // `llm/decompileForLLM.ts` is that caller. No extents means no summary, so
    // the whole section is never wanted and the section never crosses at all.
    const { client, worker } = await loadClient();

    const result = await drive(worker, freshState(), () => ask(client, fnA, { extents: false }));

    expect(worker.received).toHaveLength(1);
    expect(worker.received[0].args.instructions).toBeUndefined();
    expect(result.code).toContain("(rsi)");
  });

  it("never asks for a PE32 image", async () => {
    // `calleeClobbersFor` returns nothing unless `is64`, so a summary a 32-bit
    // lift cannot consult is pure cost — and the `is64` gate stays in
    // `dispatch.ts` alone rather than being spelled here as well.
    const { client, worker } = await loadClient();

    await drive(worker, freshState(), () => ask(client, fnA, { is64: false }));

    expect(worker.received).toHaveLength(1);
    expect(worker.received[0].args.instructions).toBeUndefined();
  });

  it("asks again after a configure dropped the worker's summary", async () => {
    // THE CASE A CLIENT-SIDE BELIEF GETS WRONG. `CallSummaryCache` holds one
    // entry and `configure` clears it, so "has the worker got this token" is not
    // a question this side can answer — which is why the worker asks rather than
    // the client predicting. Without the ask, this request is answered without a
    // summary and the difference is silent.
    const { client, worker } = await loadClient();
    const state = freshState();

    await drive(worker, state, () => ask(client, fnA));
    await dispatch("configure", { stringEntries: [], iatEntries: [], machine: 0x8664 }, state);
    const before = worker.received.length;
    const again = await drive(worker, state, () => ask(client, fnC));

    expect(worker.received.length - before).toBe(2);
    expect(worker.received[before].args.instructions).toBeUndefined();
    expect(worker.received[before + 1].args.instructions).toHaveLength(8);
    expect(again.code).toBeTruthy();
  });

  it("asks for a token it does not hold rather than serving the one it does", async () => {
    // The cache is keyed on the token, and this is that key doing work: a second
    // instruction array is a second disassembly, and answering it from the first
    // one's summary would report clobbers of another image's call graph.
    const { client, worker } = await loadClient();
    const state = freshState();

    await drive(worker, state, () => ask(client, fnA));
    // A genuinely different array object, so a different token — the client
    // mints per identity, and `section()` builds a fresh one each call.
    const before = worker.received.length;
    await drive(worker, state, () => ask(client, fnC, { insns: section() }));

    expect(worker.received[before].args.insnsToken).not.toBe(worker.received[0].args.insnsToken);
    expect(worker.received.length - before).toBe(2);
  });

  it("is order-insensitive when two first requests are in flight at once", async () => {
    // Two clicks before either reply lands. Both slim messages miss, so both are
    // asked to resend; the first retry builds the summary and the second finds
    // it. Nothing here depends on which order the worker services them, which is
    // what makes the ask safe without a lock — the retry is the same request
    // again, so a resend that arrives after the summary already exists is
    // answered from it.
    const { client, worker } = await loadClient();
    const state = freshState();

    const a = ask(client, fnA);
    const b = ask(client, fnC);
    for (let i = 0; i < worker.posted.length; i++) {
      const r = await dispatch(worker.received[i].method as never, worker.received[i].args, state);
      worker.reply(worker.posted[i].id, r);
      await Promise.resolve();
      await Promise.resolve();
    }

    // Two slim messages, then two retries: four in total, and both answered.
    expect(worker.received).toHaveLength(4);
    expect((await a).code).toContain("(rsi)");
    expect((await b).code).toBeTruthy();
    const store = (await a).code.split("\n").find((l) => l.includes("(rsi)"));
    expect(store).toMatch(/clobbered_r10_\d+/);
  });

  it("would answer without a clobber if the ask were skipped", async () => {
    // The negative control that makes the ask load-bearing rather than tidy.
    // This is what a worker that shrugged and answered anyway would emit — the
    // store reads the value the callee has provably zeroed, in C that compiles
    // and that no gate in this repo can tell from the right answer.
    const { client, worker } = await loadClient();

    void ask(client, fnA);
    const shrugged = (await dispatch(
      "decompileFunction",
      { ...worker.received[0].args, funcExtents: undefined, insnsToken: undefined },
      freshState(),
    )) as { code: string };

    const store = shrugged.code.split("\n").find((l) => l.includes("(rsi)"));
    expect(store).toMatch(/=\s*rcx\s*;/);
    expect(store).not.toMatch(/clobbered_r10_\d+/);
  });
});

/**
 * peek-a-bin-qmlz — the decompile request carries ONE `.pdata` row.
 *
 * With the two big arrays gone (peek-a-bin-9gc9), `runtimeFunctions` was the
 * second-largest member of the request and the largest one that *can* be cut:
 * 1.6 ms on a 669 KiB-`.text` `go` image at 755ea94, 19% of a request and 39%
 * of what was left of the payload, over a table linear in the image (1641 rows
 * there, 240 and 235 on t64/w64). `funcEntries` above it carries renames and
 * cannot be.
 *
 * Reading the consumer is what makes a slice available: `decompileFunction`
 * passes the array to `wrapExceptionRegions` and to nothing else, and that picks
 * **at most one** record — matching a begin address rather than an extent — so
 * `funcExceptionRecord` is applied by the client and again by the worker, and it
 * is idempotent. The rule has one declaration, in `disasm/funcInsns.ts` beside
 * the other two members of that family, because `disasmClient` cannot import the
 * pipeline.
 *
 * PE32 has no `.pdata` at all, so this is an x64 saving; the two 32-bit corpus
 * binaries are the untouched control. What has to be pinned here is that the one
 * row sent is the one the whole table would have chosen, in both directions —
 * a `__try` kept where the table had one, and none invented where the table
 * refused.
 */
describe("DisasmWorkerClient — a decompile request carries one .pdata row", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const A = 0x140001000;
  const B = 0x140001100;
  const C = 0x140001200;
  const fnA = { name: "sub_140001000", address: A, size: 13 };
  const fnB = { name: "sub_140001100", address: B, size: 0x8 };
  const fnC = { name: "sub_140001200", address: C, size: 0x8 };

  const insn = (address: number, mnemonic: string, opStr: string, size: number): Instruction => ({
    address,
    mnemonic,
    opStr,
    size,
    bytes: new Uint8Array(size),
  });
  const section = (): Instruction[] => [
    insn(A, "mov", "r10, rcx", 3),
    insn(A + 3, "call", `0x${B.toString(16)}`, 5),
    insn(A + 8, "mov", "qword ptr [rsi], r10", 4),
    insn(A + 12, "ret", "", 1),
    insn(B, "xor", "r10d, r10d", 3),
    insn(B + 3, "ret", "", 1),
    insn(C, "xor", "eax, eax", 2),
    insn(C + 2, "ret", "", 1),
  ];
  const names = new Map([
    [A, { name: fnA.name, address: A }],
    [B, { name: fnB.name, address: B }],
    [C, { name: fnC.name, address: C }],
  ]);

  /**
   * `.pdata` as the parser hands it over: RVAs, against functions at VAs. That
   * unit mismatch is the whole reason the match is a congruence and not an
   * equality (peek-a-bin-yrh), and a fixture in VAs would test a path no real
   * x64 image takes.
   */
  const rf = (o: Partial<RuntimeFunction> & { beginAddress: number }): RuntimeFunction => ({
    endAddress: o.beginAddress + 0x20,
    unwindInfoAddress: 0,
    handlerAddress: 0x900,
    handlerFlags: 0x1,
    ...o,
  });
  const A_RVA = A - 0x140000000;

  /**
   * A table with something to refuse as well as something to find: the row for
   * A, a row 64K above it (congruent with A, so the extent is what separates
   * them), a handler-bearing row for C, and a row with no handler at all.
   */
  const table = (): RuntimeFunction[] => [
    // A's row is deliberately NOT first: a client that sent `table()[0]` would
    // then send the right row by luck and the assertions below would not see it.
    rf({ beginAddress: A_RVA + 0x10000, endAddress: A_RVA + 0x10000 + 0x40 }),
    rf({ beginAddress: C - 0x140000000, endAddress: C - 0x140000000 + 8 }),
    rf({ beginAddress: A_RVA, endAddress: A_RVA + 13 }),
    rf({ beginAddress: 0x3000, handlerAddress: undefined, handlerFlags: 0 }),
  ];

  const freshState = () => createWorkerState(Promise.resolve());
  let shared: Instruction[] = [];
  beforeEach(() => {
    shared = section();
  });

  function ask(
    client: DisasmClient,
    func: { name: string; address: number; size: number },
    pdata?: RuntimeFunction[],
  ) {
    return client.decompileFunction(func, shared, new Map(), null, null, true, names, pdata, [
      fnA,
      fnB,
      fnC,
    ]);
  }

  it("sends the one row that applies, not the table", async () => {
    const { client, worker } = await loadClient();

    void ask(client, fnA, table());

    const sent = worker.received[0].args.runtimeFunctions as RuntimeFunction[];
    expect(sent).toHaveLength(1);
    expect(sent[0].beginAddress).toBe(A_RVA);
  });

  it("sends no rows at all when the table has nothing for this function", async () => {
    // B has no handler-bearing record, so the member is absent rather than an
    // empty array — the cheapest thing to clone, and the same answer.
    const { client, worker } = await loadClient();

    void ask(client, fnB, table());

    expect(worker.received[0].args.runtimeFunctions).toBeUndefined();
  });

  it("gives the same emitted C as the whole table did, and there is a __try to keep", async () => {
    // The claim, asked of the real dispatch in the direction where the table
    // finds something. Non-vacuous by assertion: a run in which neither side
    // emits a `__try` would prove nothing, which is exactly what a window slice
    // over an RVA table would produce.
    const { client, worker } = await loadClient();

    const slim = await drive(worker, freshState(), () => ask(client, fnA, table()));

    const whole = (await dispatch(
      "decompileFunction",
      // The retry shape: the same request with the section, so the worker can
      // build the clobber summary and answer rather than asking again.
      { ...worker.received[0].args, runtimeFunctions: table(), instructions: section() },
      freshState(),
    )) as { code: string };

    expect(slim.code).toContain("__try");
    expect(slim.code).toBe(whole.code);
  });

  it("invents no __try where the whole table refused an ambiguous match", async () => {
    // Two records congruent with A and the same extent: the table declines to
    // guess, so the slice must decline too. The other direction of the same
    // claim, and the one a client that guessed would get wrong.
    const { client, worker } = await loadClient();
    const ambiguous = [
      rf({ beginAddress: A_RVA, endAddress: A_RVA + 13 }),
      rf({ beginAddress: A_RVA + 0x10000, endAddress: A_RVA + 0x10000 + 13 }),
    ];

    const slim = await drive(worker, freshState(), () => ask(client, fnA, ambiguous));

    expect(worker.received[0].args.runtimeFunctions).toBeUndefined();
    const whole = (await dispatch(
      "decompileFunction",
      { ...worker.received[0].args, runtimeFunctions: ambiguous, instructions: section() },
      freshState(),
    )) as { code: string };
    expect(slim.code).not.toContain("__try");
    expect(slim.code).toBe(whole.code);
  });

  it("would lose the __try if the client sliced by window instead", async () => {
    // THE NEGATIVE CONTROL, and the trap this predicate is not. The other two
    // members of the `funcInsns.ts` family slice on
    // `[func.address, func.address + func.size)`; applied to a `.pdata` row that
    // window matches nothing, because the row is an RVA and the function is a
    // VA. It is `peek-a-bin-yrh` reintroduced one file earlier, and it is silent
    // — the C still compiles, it just no longer says the function has a handler.
    const { client, worker } = await loadClient();

    void ask(client, fnA, table());
    const windowed = table().filter(
      (r) => r.beginAddress >= fnA.address && r.beginAddress < fnA.address + fnA.size,
    );
    expect(windowed).toHaveLength(0);

    const lost = (await dispatch(
      "decompileFunction",
      { ...worker.received[0].args, runtimeFunctions: windowed, instructions: section() },
      freshState(),
    )) as { code: string };

    expect(lost.code).not.toContain("__try");
  });

  /** As in the block above: service each posted message with the real dispatch. */
  async function drive<T>(
    worker: {
      posted: PostedMessage[];
      received: PostedMessage[];
      reply(id: number, r: unknown): void;
    },
    state: WorkerState,
    call: () => Promise<T>,
  ): Promise<T> {
    const from = worker.posted.length;
    const pending = call();
    for (let i = from; i < worker.posted.length; i++) {
      const result = await dispatch(
        worker.received[i].method as never,
        worker.received[i].args,
        state,
      );
      worker.reply(worker.posted[i].id, result);
      await Promise.resolve();
      await Promise.resolve();
    }
    return pending;
  }
});
