import type { Instruction, DisasmFunction, Xref, StackFrame } from '../disasm/types';
import type { FunctionSignature } from '../disasm/signatures';
import type { SectionHeader } from '../pe/types';
import type { IRPDispatchEntry } from '../analysis/driver';

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
}

class DisasmWorkerClient {
  private worker: Worker;
  private pending = new Map<number, PendingRequest>();
  private nextId = 1;
  private disasmCache = new Map<string, Instruction[]>();
  private xrefCache = new WeakMap<Instruction[], Map<number, Xref[]>>();
  private decompileCache = new Map<number, { code: string; lineMap: Map<number, number> }>();
  jumpTables = new Map<number, number[]>(); // jmp addr → target VAs

  constructor() {
    this.worker = new Worker(new URL('./disasm.worker.ts', import.meta.url), { type: 'module' });
    this.worker.onmessage = (e) => {
      const { id, result, error } = e.data;
      const p = this.pending.get(id);
      if (!p) return;
      this.pending.delete(id);
      if (error) p.reject(new Error(error));
      else p.resolve(result);
    };
    this.worker.onerror = (e) => {
      console.error('[disasm worker] load error:', e.message ?? e);
      // Reject all pending requests so callers don't hang
      for (const [id, p] of this.pending) {
        p.reject(new Error(`Worker error: ${e.message ?? 'unknown'}`));
        this.pending.delete(id);
      }
    };
  }

  private send(method: string, args: any = {}): Promise<any> {
    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, { resolve, reject });
      this.worker.postMessage({ id, method, args });
    });
  }

  async init(): Promise<void> {
    await this.send('init');
  }

  async configure(
    strings: Map<number, string>,
    iat: Map<number, { lib: string; func: string }>,
    options?: { driverMode?: boolean },
  ): Promise<void> {
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
    await this.send('configure', {
      stringEntries: Array.from(strings.entries()),
      iatEntries: Array.from(iat.entries()),
      driverMode: options?.driverMode,
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
    const result: Instruction[] = await this.send('disassemble', { bytes, baseAddress, is64 });
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
    const result: Instruction[] = await this.send('hybridDisassemble', { bytes, baseAddress, is64, seeds, pdataRanges });
    this.disasmCache.set(key, result);
    return result;
  }

  async detectFunctions(
    bytes: Uint8Array,
    baseAddress: number,
    is64: boolean,
    options?: {
      exports?: { name: string; address: number }[];
      entryPoint?: number;
      pdataFunctions?: { beginAddress: number; endAddress: number }[];
    }
  ): Promise<DisasmFunction[]> {
    const result: { functions: DisasmFunction[]; jumpTables: [number, number[]][] } =
      await this.send('detectFunctions', { bytes, baseAddress, is64, options });
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
    } = await this.send('buildAllXrefs', { bytes, baseAddress, is64, stringAddrs, iatAddrs, funcEntries, dataSections });
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
      await this.send('extractStrings', { buffer, sections, imageBase, is64 });
    return {
      strings: new Map(result.strings),
      stringTypes: new Map(result.stringTypes),
    };
  }

  async detectIRPDispatches(instructions: Instruction[], is64: boolean): Promise<IRPDispatchEntry[]> {
    return this.send('detectIRPDispatches', { instructions, is64 });
  }

  async buildTypedXrefMap(instructions: Instruction[]): Promise<Map<number, Xref[]>> {
    const cached = this.xrefCache.get(instructions);
    if (cached) return cached;
    const entries: [number, Xref[]][] = await this.send('buildTypedXrefMap', { instructions });
    const result = new Map(entries);
    this.xrefCache.set(instructions, result);
    return result;
  }

  async decompileFunction(
    func: DisasmFunction,
    instructions: Instruction[],
    xrefMap: Map<number, Xref[]>,
    stackFrame: StackFrame | null,
    signature: FunctionSignature | null,
    is64: boolean,
    iatMap: Map<number, { lib: string; func: string }>,
    stringMap: Map<number, string>,
    funcMap: Map<number, { name: string; address: number }>,
  ): Promise<{ code: string; lineMap: Map<number, number> }> {
    const cached = this.decompileCache.get(func.address);
    if (cached) return cached;
    const result: { code: string; lineMap: [number, number][] } = await this.send('decompileFunction', {
      func,
      instructions,
      xrefEntries: Array.from(xrefMap.entries()),
      stackFrame,
      signature,
      is64,
      jumpTableEntries: Array.from(this.jumpTables.entries()),
      iatEntries: Array.from(iatMap.entries()),
      stringEntries: Array.from(stringMap.entries()),
      funcEntries: Array.from(funcMap.entries()),
    });
    const parsed = { code: result.code, lineMap: new Map(result.lineMap) };
    this.decompileCache.set(func.address, parsed);
    return parsed;
  }

  invalidateDecompileCache(): void {
    this.decompileCache.clear();
  }

  async resetStructRegistry(): Promise<void> {
    this.decompileCache.clear();
    await this.send('resetStructRegistry');
  }
}

export const disasmWorker = new DisasmWorkerClient();
