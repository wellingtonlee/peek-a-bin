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

  // Hand-written because the published `exports` map has no "types" condition,
  // so TypeScript never reaches capstone-wasm's own `index.d.ts` under bundler
  // resolution. Only the constants this project opens handles with are listed —
  // capstone-wasm declares all of them, and any that is needed can be added
  // here. `CS_ARCH_ARM64` / `CS_MODE_ARM` come from the same single WASM
  // binary as the x86 modes; naming them here does not pull in anything new.
  export namespace Const {
    const CS_ARCH_X86: number;
    const CS_ARCH_ARM64: number;
    const CS_MODE_32: number;
    const CS_MODE_64: number;
    const CS_MODE_ARM: number;
  }
}
