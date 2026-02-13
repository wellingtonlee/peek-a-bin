import { Const, Capstone, loadCapstone } from 'capstone-wasm';
import type { Instruction, DisasmFunction } from './types';

export class DisassemblyEngine {
  private cs32: any;
  private cs64: any;
  private initialized: boolean = false;
  private cache: Map<string, Instruction[]> = new Map();

  async init(): Promise<void> {
    if (this.initialized) return;

    await loadCapstone();
    this.cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
    this.cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
    this.initialized = true;
  }

  private static CHUNK_SIZE = 0x10000; // 64KB chunks to avoid WASM OOM

  private mapInsn(insn: any, stringMap?: Map<number, string>): Instruction {
    const instruction: Instruction = {
      address: insn.address,
      bytes: new Uint8Array(insn.bytes),
      mnemonic: insn.mnemonic,
      opStr: insn.opStr,
      size: insn.size,
    };

    if (stringMap && stringMap.size > 0) {
      const addressMatch = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
      if (addressMatch) {
        for (const addrStr of addressMatch) {
          const addr = parseInt(addrStr, 16);
          if (stringMap.has(addr)) {
            const str = stringMap.get(addr)!;
            instruction.comment = str.length > 60 ? str.substring(0, 57) + '...' : str;
            break;
          }
        }
      }
    }

    return instruction;
  }

  disassemble(
    bytes: Uint8Array,
    baseAddress: number,
    is64: boolean,
    stringMap?: Map<number, string>
  ): Instruction[] {
    const cacheKey = `${baseAddress}:${bytes.length}:${is64}`;
    if (this.cache.has(cacheKey)) {
      return this.cache.get(cacheKey)!;
    }

    if (!this.initialized) {
      throw new Error('DisassemblyEngine not initialized. Call init() first.');
    }

    const cs = is64 ? this.cs64 : this.cs32;
    const instructions: Instruction[] = [];
    let offset = 0;

    while (offset < bytes.length) {
      const chunkEnd = Math.min(offset + DisassemblyEngine.CHUNK_SIZE, bytes.length);
      const chunk = bytes.subarray(offset, chunkEnd);

      try {
        const insns = cs.disasm(chunk, { address: baseAddress + offset });
        for (const insn of insns) {
          instructions.push(this.mapInsn(insn, stringMap));
        }

        if (insns.length === 0) {
          // Capstone couldn't decode anything in this chunk — skip one byte
          offset += 1;
        } else {
          // Advance past the last decoded instruction
          const lastInsn = insns[insns.length - 1];
          const decoded = (lastInsn.address - (baseAddress + offset)) + lastInsn.size;
          offset += decoded;
        }
      } catch {
        // If a chunk fails, skip it and try the next one
        offset += DisassemblyEngine.CHUNK_SIZE;
      }
    }

    this.cache.set(cacheKey, instructions);
    return instructions;
  }

  disassembleRange(
    bytes: Uint8Array,
    baseAddress: number,
    is64: boolean,
    startOffset: number,
    count: number,
    stringMap?: Map<number, string>
  ): Instruction[] {
    if (!this.initialized) {
      throw new Error('DisassemblyEngine not initialized. Call init() first.');
    }

    const cs = is64 ? this.cs64 : this.cs32;
    const instructions: Instruction[] = [];
    let offset = startOffset;

    while (offset < bytes.length && instructions.length < count) {
      const chunkSize = Math.min(DisassemblyEngine.CHUNK_SIZE, bytes.length - offset);
      const chunk = bytes.subarray(offset, offset + chunkSize);

      try {
        const insns = cs.disasm(chunk, { address: baseAddress + offset });

        for (const insn of insns) {
          instructions.push(this.mapInsn(insn, stringMap));
          if (instructions.length >= count) break;
        }

        if (insns.length === 0) {
          offset += 1;
        } else {
          const lastInsn = insns[insns.length - 1];
          const decoded = (lastInsn.address - (baseAddress + offset)) + lastInsn.size;
          offset += decoded;
        }
      } catch {
        offset += chunkSize;
      }
    }

    return instructions;
  }

  detectFunctions(bytes: Uint8Array, baseAddress: number, is64: boolean): DisasmFunction[] {
    const functions: DisasmFunction[] = [];
    const len = bytes.length;

    for (let i = 0; i < len; i++) {
      let isFunctionStart = false;

      if (is64) {
        // x64 patterns:
        // 1. push rbp; mov rbp, rsp (0x55 0x48 0x89 0xE5)
        if (i + 3 < len &&
            bytes[i] === 0x55 &&
            bytes[i + 1] === 0x48 &&
            bytes[i + 2] === 0x89 &&
            bytes[i + 3] === 0xE5) {
          isFunctionStart = true;
        }
        // 2. sub rsp, imm8 (0x48 0x83 0xEC XX)
        else if (i + 3 < len &&
                 bytes[i] === 0x48 &&
                 bytes[i + 1] === 0x83 &&
                 bytes[i + 2] === 0xEC) {
          isFunctionStart = true;
        }
        // 3. sub rsp, imm32 (0x48 0x81 0xEC XX XX XX XX)
        else if (i + 6 < len &&
                 bytes[i] === 0x48 &&
                 bytes[i + 1] === 0x81 &&
                 bytes[i + 2] === 0xEC) {
          isFunctionStart = true;
        }
      } else {
        // x86 32-bit patterns:
        // push ebp; mov ebp, esp
        // Pattern 1: 0x55 0x8B 0xEC
        if (i + 2 < len &&
            bytes[i] === 0x55 &&
            bytes[i + 1] === 0x8B &&
            bytes[i + 2] === 0xEC) {
          isFunctionStart = true;
        }
        // Pattern 2: 0x55 0x89 0xE5
        else if (i + 2 < len &&
                 bytes[i] === 0x55 &&
                 bytes[i + 1] === 0x89 &&
                 bytes[i + 2] === 0xE5) {
          isFunctionStart = true;
        }
      }

      if (isFunctionStart) {
        const address = baseAddress + i;
        functions.push({
          name: `sub_${address.toString(16).toUpperCase()}`,
          address: address,
          size: 0, // Will be calculated below
        });
      }
    }

    // Calculate function sizes (distance to next function or end of bytes)
    for (let i = 0; i < functions.length; i++) {
      if (i < functions.length - 1) {
        functions[i].size = functions[i + 1].address - functions[i].address;
      } else {
        functions[i].size = (baseAddress + len) - functions[i].address;
      }
    }

    return functions;
  }

  clearCache(): void {
    this.cache.clear();
  }
}

// Export singleton
export const disasmEngine = new DisassemblyEngine();
