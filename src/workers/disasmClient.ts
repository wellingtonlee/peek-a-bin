import type { IRPDispatchEntry } from "../analysis/driver";
// A value import, but `arch.ts` is pure predicates over a number and imports
// nothing itself, so it adds no edge to Capstone either.
import { archForMachine, type ImageArch } from "../disasm/arch";
import { type DataWindow, packDataWindows } from "../disasm/dataWindows";
// A value import, but `funcInsns.ts` is address arithmetic over plain data and
// imports nothing but types, so it adds no edge to Capstone either.
import {
  collectFuncInsns,
  type FuncExtent,
  funcExceptionRecord,
  funcXrefEntries,
} from "../disasm/funcInsns";
// Type-only: erased at compile time, so this adds no runtime edge to
// functionDetect (and none to Capstone through it).
import type { DetectPass, ImageBounds } from "../disasm/functionDetect";
import { jumpTableTargets } from "../disasm/seeds";
import type { FunctionSignature } from "../disasm/signatures";
import type { DisasmFunction, Instruction, StackFrame, Xref } from "../disasm/types";
import type { SectionHeader } from "../pe/types";
import { REQUEST_TIMEOUT_MS, WorkerTimeoutError } from "./requestTimeout";
import { prepareBinaryArgs } from "./transfer";

/**
 * The cache key for one disassembly answer.
 *
 * `arch` leads, and that is the point: two architectures decode the same bytes
 * at the same address into entirely different instructions, so a key of address
 * and pointer width alone let a wrong answer — computed while the worker still
 * held another image's architecture — be handed to every later caller for the
 * session (peek-a-bin-x4o2). `is64` stays because it picks between the two x86
 * modes, which `arch` does not distinguish.
 *
 * Exported as a function of its inputs so the property can be tested for what
 * it is. The client also drops the whole cache when an image is declared, so
 * the two defences are independent and this one is not observable through the
 * public API alone.
 */
export function disasmCacheKey(
  arch: ImageArch,
  prefix: "" | "hybrid:",
  baseAddress: number,
  is64: boolean,
): string {
  return `${prefix}${arch}:${baseAddress}:${is64}`;
}

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
  method: string;
  timer: ReturnType<typeof setTimeout>;
}

class DisasmWorkerClient {
  private worker: Worker;
  private pending = new Map<number, PendingRequest>();
  private nextId = 1;
  private disasmCache = new Map<string, Instruction[]>();
  /**
   * Typed xref maps, keyed by the instruction array they were built from.
   *
   * The entry carries the `imageBounds` it was built under as well: the same
   * instructions bounded and unbounded are different answers, so a cache keyed
   * on identity alone would hand a bounded caller the unbounded map, or the
   * reverse, depending only on who asked first.
   */
  private xrefCache = new WeakMap<Instruction[], { boundsKey: string; map: Map<number, Xref[]> }>();
  private decompileCache = new Map<number, { code: string; lineMap: Map<number, number> }>();
  /**
   * Serial numbers standing for whole instruction arrays, so the worker can
   * cache what it derives from one across the many requests that name it.
   *
   * The array itself cannot be the key on the far side: structured clone hands
   * the worker a fresh copy per message, so identity does not survive the hop,
   * and content-hashing an instruction array costs about what the derivation
   * does. Identity *here* is exact, which is the property that matters — a
   * different array means a different disassembly, and the same array means the
   * same instructions.
   *
   * The counter deliberately never resets, not even on `setImage`. A token is
   * then unique for the client's whole lifetime, so a worker-side hit for a
   * different image cannot arise even if a reply crosses a file load.
   */
  private insnsTokens = new WeakMap<Instruction[], number>();
  private nextInsnsToken = 1;
  jumpTables = new Map<number, number[]>(); // jmp addr → target VAs
  /**
   * `[start, end)` of the bytes those tables occupy, from the same detection
   * pass. Held here for the same reason the targets are: `hybridDisassemble`
   * needs them, and threading them through every caller would put a detail of
   * the sweep into the UI layer. Data, not code — see
   * `DetectResult.jumpTableSpans`.
   */
  jumpTableSpans: [number, number][] = [];
  /**
   * The COFF machine type of the image every later decode belongs to, or
   * `undefined` when nothing has declared one.
   *
   * This exists because the architecture is a property of the *loaded file*,
   * and the worker used to hold it as session state set by `configure` alone.
   * `configure` is posted from `App`'s detection effect while
   * `useDisassemblyRows` posts `disassemble` / `hybridDisassemble` from a
   * different effect in a lazily-loaded child — and a child's effect runs
   * before its parent's, so on the second file loaded into a session the decode
   * was posted *first*. The worker services messages serially, so it decoded an
   * ARM64 section with the x86 handle and the result was cached under a key
   * that did not mention the architecture (peek-a-bin-x4o2).
   *
   * Set by {@link setImage} at parse time — before the new `PEFile` is visible
   * to React, so before any effect can run — which is what makes every decode
   * request for that image self-describing regardless of when `configure`
   * lands. `undefined` means "nobody declared an image", and requests then send
   * no machine at all, leaving the worker on its own `state.arch`: exactly the
   * behaviour every caller had before this existed.
   */
  private imageMachine: number | undefined;

  constructor() {
    this.worker = new Worker(new URL("./disasm.worker.ts", import.meta.url), { type: "module" });
    this.worker.onmessage = (e) => {
      const { id, result, error } = e.data;
      const p = this.take(id);
      if (!p) return;
      if (error) p.reject(new Error(error));
      else p.resolve(result);
    };
    this.worker.onerror = (e) => {
      console.error("[disasm worker] load error:", e.message ?? e);
      // Reject all pending requests so callers don't hang
      this.rejectAll(`Worker error: ${e.message ?? "unknown"}`);
    };
    this.worker.onmessageerror = () => {
      // A reply that failed structured clone (the large Instruction[] payloads
      // are the risk) never reaches onmessage, and the event carries no usable
      // data identifying which request it belonged to — so fail everything
      // outstanding instead of letting them hang until the watchdog fires.
      console.error("[disasm worker] message deserialization failed");
      this.rejectAll("Worker reply could not be deserialized (structured clone failed)");
    };
  }

  /** Remove a pending request and cancel its watchdog. */
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

  private send(method: string, args: any = {}): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      const timer = setTimeout(() => {
        // Its own type, not a bare Error: a caller has to be able to tell "this
        // took too long" from "this failed", because the analysis chain reports
        // every rejection as one terminal phase and the two mean opposite
        // things to a user. The message is unchanged — see ./requestTimeout.ts.
        this.take(id)?.reject(new WorkerTimeoutError(method, REQUEST_TIMEOUT_MS));
      }, REQUEST_TIMEOUT_MS);
      this.pending.set(id, { resolve, reject, method, timer });
      try {
        // Byte arguments are views onto the whole loaded file, and structured
        // clone of a view copies its entire backing buffer — so posting these
        // untransferred copied the file on every call. `prepareBinaryArgs`
        // substitutes a private copy of just the view's window and hands that
        // over; the caller's buffer is never transferred and never detaches.
        // See ./transfer.ts for the measurements behind this.
        const { args: payload, transfer } = prepareBinaryArgs(args);
        this.worker.postMessage({ id, method, args: payload }, transfer);
      } catch (err) {
        // e.g. DataCloneError on a non-transferable argument, or a TypeError
        // from copying an already-detached view — fail now instead of leaving
        // the entry and its watchdog around for the full timeout.
        this.take(id)?.reject(err);
      }
    });
  }

  async init(): Promise<void> {
    await this.send("init");
  }

  /**
   * Declare which image is loaded, from `coffHeader.machine`.
   *
   * The load handshake. Call it the moment the file parses and before the new
   * `PEFile` reaches the reducer: from then on every decode request carries
   * this machine type, so *no* ordering between this client's messages can
   * decide what architecture a section is decoded as. That is the fix for
   * peek-a-bin-x4o2, and it is deliberately not a promise the decode methods
   * await — a barrier would order the messages but still leave the answer
   * depending on worker state that some other message can change.
   *
   * Also drops every cached answer, because all four caches are per-image: the
   * disassembly and xref caches key on addresses that mean nothing across
   * files, the decompile cache keys on a bare function address, and the jump
   * tables would otherwise be seeded into the *next* file's recursive descent.
   */
  setImage(machine: number | undefined): void {
    this.imageMachine = machine;
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
    this.decompileCache.clear();
    this.jumpTables = new Map();
    this.jumpTableSpans = [];
  }

  /** How the declared image decodes; `"x86"` when nothing was declared. */
  private get arch(): ImageArch {
    return archForMachine(this.imageMachine);
  }

  /**
   * Stamp a decode request with the loaded image's machine type.
   *
   * Every RPC whose answer depends on which decoder ran goes through here, so
   * the request states the architecture rather than inheriting whatever the
   * worker was last told. `undefined` is sent as `undefined` and the worker
   * falls back to its own `state.arch` — see {@link imageMachine}.
   */
  private decoded<T extends object>(args: T): T & { machine: number | undefined } {
    return { ...args, machine: this.imageMachine };
  }

  /**
   * Hand the worker the per-file context every later call reads.
   *
   * `machine` is the COFF machine type, and it is what selects the decoder —
   * `is64`, which the individual methods take, is the PE32+ magic and says only
   * how wide a pointer is. Omitting it leaves whatever the worker already had,
   * because this is called twice per file: once here with everything known, and
   * again from the effect that re-sends the strings after extraction, which has
   * no reason to know the machine type.
   *
   * It is no longer what *decides* the architecture of a decode — {@link
   * setImage} is, and each request carries the answer. Recorded here as well so
   * a call site that only ever calls `configure` still stamps its later
   * requests instead of silently depending on message order.
   */
  async configure(
    strings: Map<number, string>,
    iat: Map<number, { lib: string; func: string }>,
    options?: { driverMode?: boolean; machine?: number; chpeMetadataPointer?: number },
  ): Promise<void> {
    if (options?.machine !== undefined) this.imageMachine = options.machine;
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
    await this.send("configure", {
      stringEntries: Array.from(strings.entries()),
      iatEntries: Array.from(iat.entries()),
      driverMode: options?.driverMode,
      machine: options?.machine,
      // `PEFile.loadConfig.chpeMetadataPointer`, and it is read by exactly one
      // thing on the far side: the ARM64 decode-rate refusal's message, which
      // can then say the image declares CHPE metadata rather than inferring
      // hybrid-ness from the rate. Prose only — it selects no decoder and is not
      // in any cache key — so unlike `machine` it does not have to be on each
      // request, and a caller that omits it gets the previous message verbatim.
      chpeMetadataPointer: options?.chpeMetadataPointer,
    });
  }

  invalidateCache(): void {
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
    this.decompileCache.clear();
  }

  async disassemble(bytes: Uint8Array, baseAddress: number, is64: boolean): Promise<Instruction[]> {
    const key = disasmCacheKey(this.arch, "", baseAddress, is64);
    const cached = this.disasmCache.get(key);
    if (cached) return cached;
    const result: Instruction[] = await this.send(
      "disassemble",
      this.decoded({ bytes, baseAddress, is64 }),
    );
    this.disasmCache.set(key, result);
    return result;
  }

  async hybridDisassemble(
    bytes: Uint8Array,
    baseAddress: number,
    is64: boolean,
    seeds: number[],
    pdataRanges?: { beginAddress: number; endAddress: number }[],
  ): Promise<Instruction[]> {
    const key = disasmCacheKey(this.arch, "hybrid:", baseAddress, is64);
    const cached = this.disasmCache.get(key);
    if (cached) return cached;
    // Jump-table case bodies are seeded here rather than by the caller: the
    // targets are a by-product of `detectFunctions`, which this client already
    // keeps in `this.jumpTables` for `configureDecompileMaps`, so every caller
    // gets them without having to thread them through. See ../disasm/seeds.ts
    // for why the BFS cannot find these on its own. Out-of-section seeds are
    // discarded by `hybridDisassemble` itself, so seeding another section's
    // targets is harmless.
    const result: Instruction[] = await this.send(
      "hybridDisassemble",
      this.decoded({
        bytes,
        baseAddress,
        is64,
        seeds: [...seeds, ...jumpTableTargets(this.jumpTables)],
        pdataRanges,
        // Same provenance and the same reason: the spans are a by-product of
        // `detectFunctions`, and without them phase 2's gap fill decodes each
        // recovered table's case addresses as instructions (peek-a-bin-y1di).
        jumpTableSpans: this.jumpTableSpans,
      }),
    );
    this.disasmCache.set(key, result);
    return result;
  }

  /**
   * Detect functions in a code section.
   *
   * `options.dataWindows` — `.rdata` above all — is what makes an x64 jump
   * table readable: the table lives outside the code section, so without it the
   * detector sees the dispatch chain and can read none of its entries. It does
   * **not** travel inside `options`: every window is a view onto the whole
   * loaded file, and `prepareBinaryArgs` only transfers top-level binary
   * arguments, so a nested view would be structured-cloned — copying the entire
   * file once per window. It is packed into one flat top-level buffer instead
   * (see ../disasm/dataWindows.ts) and rebuilt by the dispatch.
   *
   * Returns `omitted` alongside the functions rather than only the list. That
   * field is the whole reason detection is allowed to answer where the decoding
   * stages refuse — it names the passes that did not run, so a narrower answer
   * stops being shaped exactly like a complete one (peek-a-bin-4s9). Dropping
   * it here put the browser back where it started: a short function list with
   * nothing anywhere saying why (peek-a-bin-ybv2). `?? []` because a reply from
   * before the field existed means "nothing was skipped", which is what an
   * empty list says.
   */
  async detectFunctions(
    bytes: Uint8Array,
    baseAddress: number,
    is64: boolean,
    options?: {
      exports?: { name: string; address: number }[];
      entryPoint?: number;
      pdataFunctions?: { beginAddress: number; endAddress: number }[];
      handlerAddresses?: number[];
      dataWindows?: DataWindow[];
    },
  ): Promise<{ functions: DisasmFunction[]; omitted: DetectPass[] }> {
    const { dataWindows, ...rest } = options ?? {};
    const packed = packDataWindows(dataWindows);
    const result: {
      functions: DisasmFunction[];
      jumpTables: [number, number[]][];
      jumpTableSpans?: [number, number][];
      omitted?: DetectPass[];
    } = await this.send(
      "detectFunctions",
      this.decoded({
        bytes,
        baseAddress,
        is64,
        options: options ? rest : undefined,
        ...packed,
      }),
    );
    this.jumpTables = new Map(result.jumpTables);
    // `?? []` for the same reason as `omitted` below: a reply from before the
    // field existed says nothing about tables, and no spans is what the sweep
    // behaved as all along.
    this.jumpTableSpans = result.jumpTableSpans ?? [];
    return { functions: result.functions, omitted: result.omitted ?? [] };
  }

  async buildAllXrefs(
    bytes: Uint8Array,
    baseAddress: number,
    is64: boolean,
    stringAddrs: number[],
    iatAddrs: number[],
    funcEntries?: [number, number][],
    dataSections?: { va: number; size: number }[],
  ): Promise<{
    stringXrefs: Map<number, number[]>;
    importXrefs: Map<number, number[]>;
    callGraph: Map<number, number[]>;
    dataXrefs: Map<number, number[]>;
  }> {
    const result: {
      stringXrefs: [number, number[]][];
      importXrefs: [number, number[]][];
      callGraph: [number, number[]][];
      dataXrefs: [number, number[]][];
    } = await this.send(
      "buildAllXrefs",
      this.decoded({
        bytes,
        baseAddress,
        is64,
        stringAddrs,
        iatAddrs,
        funcEntries,
        dataSections,
      }),
    );
    return {
      stringXrefs: new Map(result.stringXrefs),
      importXrefs: new Map(result.importXrefs),
      callGraph: new Map(result.callGraph),
      dataXrefs: new Map(result.dataXrefs),
    };
  }

  async extractStrings(
    buffer: ArrayBuffer,
    sections: SectionHeader[],
    imageBase: number,
    is64?: boolean,
  ): Promise<{ strings: Map<number, string>; stringTypes: Map<number, "ascii" | "utf16le"> }> {
    const result: { strings: [number, string][]; stringTypes: [number, "ascii" | "utf16le"][] } =
      await this.send("extractStrings", { buffer, sections, imageBase, is64 });
    return {
      strings: new Map(result.strings),
      stringTypes: new Map(result.stringTypes),
    };
  }

  async detectIRPDispatches(
    instructions: Instruction[],
    is64: boolean,
  ): Promise<IRPDispatchEntry[]> {
    return this.send("detectIRPDispatches", this.decoded({ instructions, is64 }));
  }

  /**
   * `imageBounds` is where the loader maps the image
   * (`{ base: optionalHeader.imageBase, size: optionalHeader.sizeOfImage }`).
   * It bounds `buildTypedXrefMap`'s fallback operand scan, the arm that reads
   * any large `0x…` token as a data reference; unbounded, that arm reported
   * bitmasks and status constants as references to addresses outside the image
   * (peek-a-bin-jfp). Two plain numbers, so nothing here is binary and
   * `prepareBinaryArgs` leaves the object alone.
   */
  async buildTypedXrefMap(
    instructions: Instruction[],
    imageBounds?: ImageBounds,
  ): Promise<Map<number, Xref[]>> {
    const boundsKey = imageBounds ? `${imageBounds.base}:${imageBounds.size}` : "";
    const cached = this.xrefCache.get(instructions);
    if (cached && cached.boundsKey === boundsKey) return cached.map;
    const entries: [number, Xref[]][] = await this.send("buildTypedXrefMap", {
      instructions,
      imageBounds,
    });
    const result = new Map(entries);
    this.xrefCache.set(instructions, { boundsKey, map: result });
    return result;
  }

  async configureDecompileMaps(
    funcMap: Map<number, { name: string; address: number }>,
  ): Promise<void> {
    await this.send("configureDecompileMaps", {
      funcEntries: Array.from(funcMap.entries()),
      jumpTableEntries: Array.from(this.jumpTables.entries()),
    });
  }

  async decompileFunction(
    func: DisasmFunction,
    instructions: Instruction[],
    xrefMap: Map<number, Xref[]>,
    stackFrame: StackFrame | null,
    signature: FunctionSignature | null,
    is64: boolean,
    funcMap: Map<number, { name: string; address: number }>,
    runtimeFunctions?: import("../pe/types").RuntimeFunction[],
    functions?: readonly FuncExtent[],
  ): Promise<{ code: string; lineMap: Map<number, number> }> {
    const cached = this.decompileCache.get(func.address);
    if (cached) return cached;
    // THE PAYLOAD IS PER-FUNCTION, and that is 94-99% of what a decompile
    // request used to cost (peek-a-bin-9gc9). The pipeline reads the instruction
    // array only through `getFuncInsns` and the xref map only at the addresses
    // of those instructions, so both are cut to this function's own window here
    // — see `funcXrefEntries` for why that is exact rather than a heuristic.
    // Measured on a 669 KiB-`.text` `go` image at 11408ac: 652 ms of instruction
    // clone and 65 ms of xref clone per request, against 5.9 ms of decompiling.
    //
    // Extents, not the whole records: the worker needs only where each function
    // starts and ends to group the whole section by owning function, which is
    // what the per-callee clobber summary is built from. `funcEntries` carries
    // the names and is rebuilt per call because it reflects renames; extents do
    // not change under a rename, which is why the summary can be cached against
    // the instruction token while `funcEntries` cannot.
    //
    // Sent only when the caller has them, so an older caller gets exactly the
    // pre-summary behaviour rather than a half-built one (peek-a-bin-s2ws).
    const pdataRecord = funcExceptionRecord(func, runtimeFunctions);
    const args = this.decoded({
      func,
      funcInsns: collectFuncInsns(func, instructions),
      xrefEntries: funcXrefEntries(func, xrefMap),
      stackFrame,
      signature,
      is64,
      funcEntries: Array.from(funcMap.entries()),
      // The one `.pdata` row this function's decompilation can consult, not the
      // image's table. `wrapExceptionRegions` picks at most one record and
      // `funcExceptionRecord` is that pick, applied here and again over there —
      // it is idempotent, so the worker's answer is unchanged and a caller
      // sending the whole table (the MCP server, `corpus/sweep.ts`) still gets
      // exactly what it always did. The table is linear in the image: 1641 rows
      // on a 669 KiB-`.text` `go` build, where cloning it was 1.37 ms — 19% of a
      // request and 39% of what was left of the payload after peek-a-bin-9gc9 —
      // against 0.001 ms for the one row, measured at 755ea94. PE32 has no
      // `.pdata` at all, so this is an x64 saving and the two 32-bit corpus
      // binaries are the untouched control.
      runtimeFunctions: pdataRecord ? [pdataRecord] : undefined,
      funcExtents: functions?.map((f) => [f.address, f.size] as [number, number]),
      insnsToken: functions ? this.insnsToken(instructions) : undefined,
    });
    type Reply = { code: string; lineMap: [number, number][]; needInstructions?: boolean };
    let result: Reply = await this.send("decompileFunction", args);
    if (result?.needInstructions) {
      // The worker has to build a clobber summary for this token and holds
      // neither the summary nor the instructions to build it from, so it asked
      // rather than answering without one. It is THE WORKER that decides this,
      // not a model of it kept here: `CallSummaryCache` holds one entry and
      // `configure` clears it, so any belief on this side would be a second copy
      // of an eviction rule that lives over there. The cost is one extra round
      // trip on the first request of a file — and none at all for a caller with
      // no extents, or a PE32 image, where no summary is built.
      //
      // Bounded at one retry by construction: a request carrying `instructions`
      // can always build, so the worker cannot ask twice. It needs no lock
      // either — the retry is the same request again, so two clicks in flight at
      // once are both answered whichever order the worker services them in, at
      // worst sending the section twice.
      result = await this.send("decompileFunction", { ...args, instructions });
    }
    const parsed = { code: result.code, lineMap: new Map(result.lineMap) };
    this.decompileCache.set(func.address, parsed);
    return parsed;
  }

  /** The stable token for this instruction array, minting one on first sight. */
  private insnsToken(instructions: Instruction[]): number {
    const seen = this.insnsTokens.get(instructions);
    if (seen !== undefined) return seen;
    const token = this.nextInsnsToken++;
    this.insnsTokens.set(instructions, token);
    return token;
  }

  invalidateDecompileCache(): void {
    this.decompileCache.clear();
  }

  async resetStructRegistry(): Promise<void> {
    this.decompileCache.clear();
    await this.send("resetStructRegistry");
  }
}

export const disasmWorker = new DisasmWorkerClient();
