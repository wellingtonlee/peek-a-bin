declare module "capstone-wasm" {
  export function loadCapstone(): Promise<void>;

  export class Capstone {
    constructor(arch: number, mode: number);
    disasm(
      code: Uint8Array | number[],
      options?: { address?: number },
    ): Array<{
      address: number;
      bytes: number[];
      mnemonic: string;
      opStr: string;
      size: number;
    }>;
    close(): void;
  }

  export namespace Const {
    const CS_ARCH_X86: number;
    const CS_MODE_32: number;
    const CS_MODE_64: number;
  }
}
