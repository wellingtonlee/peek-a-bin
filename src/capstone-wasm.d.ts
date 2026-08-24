declare module "capstone-wasm" {
  /**
   * Bootstrap the WASM module.
   *
   * The runtime signature takes the emscripten Module object — capstone-wasm's
   * factory opens `var Module = moduleArg`, so whatever is passed here **is**
   * the Module and is populated in place. It is how the worker supplies its
   * `instantiateWasm` hook and how `src/disasm/capstoneReader.ts` gets hold of
   * the heap views it marshals instructions through. It is a singleton: the
   * second call returns immediately and populates nothing, so exactly one place
   * in `src/` may call it (drift-guarded in
   * `src/disasm/__tests__/capstoneWindow.test.ts`).
   */
  export function loadCapstone(args?: Record<string, unknown>): Promise<void>;

  export class Capstone {
    constructor(arch: number, mode: number);
    /** The arch passed to the constructor; selects the liveness probe's `nop`. */
    readonly arch: number;
    /** The `cs_open` handle, read out of WASM memory on each access. */
    readonly handle: number;
    disasm(
      code: Uint8Array | number[],
      options?: { address?: number; count?: number },
    ): Array<{
      address: number;
      // Runtime is a `Uint8Array` — `HEAPU8.slice(...).subarray(0, size)`. The
      // package's own declaration says `number[]` and is wrong; this one is
      // hand-written, so it says what the code returns.
      bytes: Uint8Array;
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
