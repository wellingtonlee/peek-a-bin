import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { unsupportedArchMessage } from "../../disasm/arch";
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
  return { client: mod.disasmWorker, worker: FakeWorker.last!, mod };
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
