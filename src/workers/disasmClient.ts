import type { Instruction, DisasmFunction, Xref, StackFrame } from "../disasm/types";
// Type-only: erased at compile time, so this adds no runtime edge to
// functionDetect (and none to Capstone through it).
import type { ImageBounds } from "../disasm/functionDetect";
import type { FunctionSignature } from "../disasm/signatures";
import type { SectionHeader } from "../pe/types";
import type { IRPDispatchEntry } from "../analysis/driver";
import { prepareBinaryArgs } from "./transfer";
import { jumpTableTargets } from "../disasm/seeds";
import { type DataWindow, packDataWindows } from "../disasm/dataWindows";

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
  method: string;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * Watchdog for every worker request.
 *
 * One timeout for all methods rather than per-method budgets: the worker
 * services messages serially on a single thread, so a cheap call (`configure`,
 * `resetStructRegistry`) can sit queued behind a whole-image
 * `hybridDisassemble` for minutes. A short per-method timeout would reject
 * those queued requests even though nothing is wrong.
 *
 * 5 minutes is far above any legitimate run — whole-image disassembly and
 * decompilation of a large PE are seconds to low minutes of CPU — but bounded,
 * so a wedged worker (infinite loop, unresolved WASM load) surfaces as a real
 * error instead of leaving this and every later request pending forever.
 */
const REQUEST_TIMEOUT_MS = 5 * 60_000;

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
  jumpTables = new Map<number, number[]>(); // jmp addr → target VAs

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
        this.take(id)?.reject(
          new Error(`Worker request '${method}' timed out after ${REQUEST_TIMEOUT_MS / 1000}s`),
        );
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
   * Hand the worker the per-file context every later call reads.
   *
   * `machine` is the COFF machine type, and it is what selects the decoder —
   * `is64`, which the individual methods take, is the PE32+ magic and says only
   * how wide a pointer is. Omitting it leaves whatever the worker already had,
   * because this is called twice per file: once here with everything known, and
   * again from the effect that re-sends the strings after extraction, which has
   * no reason to know the machine type.
   */
  async configure(
    strings: Map<number, string>,
    iat: Map<number, { lib: string; func: string }>,
    options?: { driverMode?: boolean; machine?: number },
  ): Promise<void> {
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
    await this.send("configure", {
      stringEntries: Array.from(strings.entries()),
      iatEntries: Array.from(iat.entries()),
      driverMode: options?.driverMode,
      machine: options?.machine,
    });
  }

  invalidateCache(): void {
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
    this.decompileCache.clear();
  }

  async disassemble(bytes: Uint8Array, baseAddress: number, is64: boolean): Promise<Instruction[]> {
    const key = `${baseAddress}:${is64}`;
    const cached = this.disasmCache.get(key);
    if (cached) return cached;
    const result: Instruction[] = await this.send("disassemble", { bytes, baseAddress, is64 });
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
    const key = `hybrid:${baseAddress}:${is64}`;
    const cached = this.disasmCache.get(key);
    if (cached) return cached;
    // Jump-table case bodies are seeded here rather than by the caller: the
    // targets are a by-product of `detectFunctions`, which this client already
    // keeps in `this.jumpTables` for `configureDecompileMaps`, so every caller
    // gets them without having to thread them through. See ../disasm/seeds.ts
    // for why the BFS cannot find these on its own. Out-of-section seeds are
    // discarded by `hybridDisassemble` itself, so seeding another section's
    // targets is harmless.
    const result: Instruction[] = await this.send("hybridDisassemble", {
      bytes,
      baseAddress,
      is64,
      seeds: [...seeds, ...jumpTableTargets(this.jumpTables)],
      pdataRanges,
    });
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
  ): Promise<DisasmFunction[]> {
    const { dataWindows, ...rest } = options ?? {};
    const packed = packDataWindows(dataWindows);
    const result: { functions: DisasmFunction[]; jumpTables: [number, number[]][] } =
      await this.send("detectFunctions", {
        bytes,
        baseAddress,
        is64,
        options: options ? rest : undefined,
        ...packed,
      });
    this.jumpTables = new Map(result.jumpTables);
    return result.functions;
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
    } = await this.send("buildAllXrefs", {
      bytes,
      baseAddress,
      is64,
      stringAddrs,
      iatAddrs,
      funcEntries,
      dataSections,
    });
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
    return this.send("detectIRPDispatches", { instructions, is64 });
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
  ): Promise<{ code: string; lineMap: Map<number, number> }> {
    const cached = this.decompileCache.get(func.address);
    if (cached) return cached;
    const result: { code: string; lineMap: [number, number][] } = await this.send(
      "decompileFunction",
      {
        func,
        instructions,
        xrefEntries: Array.from(xrefMap.entries()),
        stackFrame,
        signature,
        is64,
        funcEntries: Array.from(funcMap.entries()),
        runtimeFunctions,
      },
    );
    const parsed = { code: result.code, lineMap: new Map(result.lineMap) };
    this.decompileCache.set(func.address, parsed);
    return parsed;
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
