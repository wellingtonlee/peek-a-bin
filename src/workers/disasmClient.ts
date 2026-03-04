import type { Instruction, DisasmFunction, Xref } from '../disasm/types';
import type { SectionHeader } from '../pe/types';

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
    iat: Map<number, { lib: string; func: string }>
  ): Promise<void> {
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
    await this.send('configure', {
      stringEntries: Array.from(strings.entries()),
      iatEntries: Array.from(iat.entries()),
    });
  }

  invalidateCache(): void {
    this.disasmCache.clear();
    this.xrefCache = new WeakMap();
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
  ): Promise<{ stringXrefs: Map<number, number[]>; importXrefs: Map<number, number[]> }> {
    const result: { stringXrefs: [number, number[]][]; importXrefs: [number, number[]][] } =
      await this.send('buildAllXrefs', { bytes, baseAddress, is64, stringAddrs, iatAddrs });
    return {
      stringXrefs: new Map(result.stringXrefs),
      importXrefs: new Map(result.importXrefs),
    };
  }

  async extractStrings(
    buffer: ArrayBuffer,
    sections: SectionHeader[],
    imageBase: number,
  ): Promise<{ strings: Map<number, string>; stringTypes: Map<number, "ascii" | "utf16le"> }> {
    const result: { strings: [number, string][]; stringTypes: [number, "ascii" | "utf16le"][] } =
      await this.send('extractStrings', { buffer, sections, imageBase });
    return {
      strings: new Map(result.strings),
      stringTypes: new Map(result.stringTypes),
    };
  }

  async buildTypedXrefMap(instructions: Instruction[]): Promise<Map<number, Xref[]>> {
    const cached = this.xrefCache.get(instructions);
    if (cached) return cached;
    const entries: [number, Xref[]][] = await this.send('buildTypedXrefMap', { instructions });
    const result = new Map(entries);
    this.xrefCache.set(instructions, result);
    return result;
  }
}

export const disasmWorker = new DisasmWorkerClient();
