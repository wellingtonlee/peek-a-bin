/**
 * Capstone wrapper for Node.js (no Web Worker, no IndexedDB caching).
 * Used by the MCP server for direct disassembly.
 */

import { Const, Capstone, loadCapstone } from 'capstone-wasm';
import type { Instruction, DisasmFunction, Xref } from '../disasm/types';
import {
  type DisasmContext,
  disassemble,
  detectFunctions,
  hybridDisassemble,
  buildTypedXrefMap,
  buildAllXrefs,
} from '../disasm/functionDetect';

let cs32: any;
let cs64: any;
let initialized = false;

export async function initCapstone(): Promise<void> {
  if (initialized) return;
  await loadCapstone();
  cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
  cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
  initialized = true;
}

function makeCtx(
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
): DisasmContext {
  return { cs32, cs64, stringMap, iatMap, driverMode };
}

export function disassembleBytes(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
): Instruction[] {
  return disassemble(bytes, baseAddress, is64, makeCtx(stringMap, iatMap, driverMode));
}

export function detectFunctionsFromBytes(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
  options?: {
    exports?: { name: string; address: number }[];
    entryPoint?: number;
    pdataFunctions?: { beginAddress: number; endAddress: number }[];
    handlerAddresses?: number[];
  },
) {
  return detectFunctions(bytes, baseAddress, is64, makeCtx(stringMap, iatMap, driverMode), options);
}

export function hybridDisassembleBytes(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  seeds: number[],
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
  pdataRanges?: { beginAddress: number; endAddress: number }[],
): Instruction[] {
  return hybridDisassemble(bytes, baseAddress, is64, seeds, makeCtx(stringMap, iatMap, driverMode), pdataRanges);
}

export function buildXrefMap(instructions: Instruction[]): [number, Xref[]][] {
  return buildTypedXrefMap(instructions);
}

export function buildXrefs(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  stringAddrs: number[],
  iatAddrs: number[],
  funcEntries?: [number, number][],
  dataSections?: { va: number; size: number }[],
) {
  const cs = is64 ? cs64 : cs32;
  return buildAllXrefs(bytes, baseAddress, is64, stringAddrs, iatAddrs, cs, funcEntries, dataSections);
}

export { cs32, cs64 };
