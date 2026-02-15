import type { Instruction, DisasmFunction, Xref } from '../disasm/types';

interface PendingRequest {
  resolve: (value: any) => void;
  reject: (reason: any) => void;
}

class DisasmWorkerClient {
  private worker: Worker | null = null;
  private pending = new Map<number, PendingRequest>();
  private nextId = 1;

  private send(method: string, args: any = {}): Promise<any> {
    if (!this.worker) {
      this.worker = new Worker(new URL('./disasm.worker.ts', import.meta.url), { type: 'module' });
      this.worker.onmessage = (e) => {
        const { id, result, error } = e.data;
        const p = this.pending.get(id);
        if (!p) return;
        this.pending.delete(id);
        if (error) p.reject(new Error(error));
        else p.resolve(result);
      };
    }

    return new Promise((resolve, reject) => {
      const id = this.nextId++;
      this.pending.set(id, { resolve, reject });
      this.worker!.postMessage({ id, method, args });
    });
  }

  async init(): Promise<void> {
    await this.send('init');
  }

  async configure(
    strings: Map<number, string>,
    iat: Map<number, { lib: string; func: string }>
  ): Promise<void> {
    await this.send('configure', {
      stringEntries: Array.from(strings.entries()),
      iatEntries: Array.from(iat.entries()),
    });
  }

  async disassemble(bytes: Uint8Array, baseAddress: number, is64: boolean): Promise<Instruction[]> {
    return this.send('disassemble', { bytes, baseAddress, is64 });
  }

  async detectFunctions(
    bytes: Uint8Array,
    baseAddress: number,
    is64: boolean,
    options?: { exports?: { name: string; address: number }[]; entryPoint?: number }
  ): Promise<DisasmFunction[]> {
    return this.send('detectFunctions', { bytes, baseAddress, is64, options });
  }

  async buildTypedXrefMap(instructions: Instruction[]): Promise<Map<number, Xref[]>> {
    const entries: [number, Xref[]][] = await this.send('buildTypedXrefMap', { instructions });
    return new Map(entries);
  }
}

export const disasmWorker = new DisasmWorkerClient();
