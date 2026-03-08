/**
 * Shared function detection, disassembly, and xref building logic.
 * Extracted from disasm.worker.ts so both the Web Worker and the MCP server
 * can reuse the same algorithms.
 */

import type { Instruction, DisasmFunction, Xref } from './types';
import { isPlausibleIOCTL, formatIOCTL } from '../analysis/driver';

/** Context maps passed in instead of module-level state */
export interface DisasmContext {
  cs32: any;
  cs64: any;
  stringMap: Map<number, string>;
  iatMap: Map<number, { lib: string; func: string }>;
  driverMode: boolean;
}

const CHUNK_SIZE = 0x10000;

export function mapInsn(
  insn: any,
  stringMap: Map<number, string>,
  iatMap: Map<number, { lib: string; func: string }>,
  driverMode: boolean,
): Instruction {
  const instruction: Instruction = {
    address: insn.address,
    bytes: insn.bytes,
    mnemonic: insn.mnemonic,
    opStr: insn.opStr,
    size: insn.size,
  };

  if (stringMap.size > 0) {
    const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
    if (ripMatch) {
      const sign = ripMatch[1] === '+' ? 1 : -1;
      const disp = parseInt(ripMatch[2], 16);
      const target = insn.address + insn.size + sign * disp;
      if (stringMap.has(target)) {
        const str = stringMap.get(target)!;
        instruction.comment = str.length > 60 ? str.substring(0, 57) + '...' : str;
      }
    }
    if (!instruction.comment) {
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
  }

  if (iatMap.size > 0 && !instruction.comment) {
    const ripMatch2 = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
    if (ripMatch2) {
      const sign = ripMatch2[1] === '+' ? 1 : -1;
      const disp = parseInt(ripMatch2[2], 16);
      const target = insn.address + insn.size + sign * disp;
      const iat = iatMap.get(target);
      if (iat) instruction.comment = `${iat.lib}!${iat.func}`;
    }
    if (!instruction.comment) {
      const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
      if (addrMatches) {
        for (const addrStr of addrMatches) {
          const addr = parseInt(addrStr, 16);
          const iat = iatMap.get(addr);
          if (iat) { instruction.comment = `${iat.lib}!${iat.func}`; break; }
        }
      }
    }
  }

  // IOCTL annotation (driver mode only)
  if (driverMode && !instruction.comment) {
    const hexMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
    if (hexMatches) {
      for (const hexStr of hexMatches) {
        const val = parseInt(hexStr, 16);
        if (isPlausibleIOCTL(val)) {
          const decoded = formatIOCTL(val);
          if (decoded) { instruction.comment = decoded; break; }
        }
      }
    }
  }

  return instruction;
}

export function disassemble(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  ctx: DisasmContext,
): Instruction[] {
  const cs = is64 ? ctx.cs64 : ctx.cs32;
  const instructions: Instruction[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    const chunkEnd = Math.min(offset + CHUNK_SIZE, bytes.length);
    const chunk = bytes.subarray(offset, chunkEnd);
    try {
      const insns = cs.disasm(chunk, { address: baseAddress + offset });
      for (const insn of insns) {
        instructions.push(mapInsn(insn, ctx.stringMap, ctx.iatMap, ctx.driverMode));
      }
      if (insns.length === 0) {
        offset += 1;
      } else {
        const lastInsn = insns[insns.length - 1];
        const decoded = (lastInsn.address - (baseAddress + offset)) + lastInsn.size;
        offset += decoded;
      }
    } catch {
      offset += 1;
    }
  }

  return instructions;
}

export interface DetectResult {
  functions: DisasmFunction[];
  jumpTables: [number, number[]][];
}

export function detectFunctions(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  ctx: DisasmContext,
  options?: {
    exports?: { name: string; address: number }[];
    entryPoint?: number;
    pdataFunctions?: { beginAddress: number; endAddress: number }[];
    handlerAddresses?: number[];
  },
): DetectResult {
  const addrSet = new Set<number>();
  const nameMap = new Map<number, string>();
  const pdataEndMap = new Map<number, number>();
  const len = bytes.length;
  const endAddress = baseAddress + len;

  // Integrate .pdata seeds
  if (options?.pdataFunctions) {
    for (const rf of options.pdataFunctions) {
      if (rf.beginAddress >= baseAddress && rf.beginAddress < endAddress) {
        addrSet.add(rf.beginAddress);
        pdataEndMap.set(rf.beginAddress, rf.endAddress);
      }
    }
  }

  // Exception handler seeds from UNWIND_INFO
  if (options?.handlerAddresses) {
    for (const ha of options.handlerAddresses) {
      if (ha >= baseAddress && ha < endAddress) {
        addrSet.add(ha);
        nameMap.set(ha, `__handler_${ha.toString(16)}`);
      }
    }
  }

  if (options?.entryPoint !== undefined) {
    const ep = options.entryPoint;
    if (ep >= baseAddress && ep < endAddress) {
      addrSet.add(ep);
      nameMap.set(ep, 'entry_point');
    }
  }

  if (options?.exports) {
    for (const exp of options.exports) {
      if (exp.address >= baseAddress && exp.address < endAddress) {
        addrSet.add(exp.address);
        nameMap.set(exp.address, exp.name);
      }
    }
  }

  // Prologue scanning
  for (let i = 0; i < len; i++) {
    let isFunctionStart = false;
    if (is64) {
      if (i + 3 < len && bytes[i] === 0x55 && bytes[i + 1] === 0x48 && bytes[i + 2] === 0x89 && bytes[i + 3] === 0xE5) {
        isFunctionStart = true;
      } else if (i + 3 < len && bytes[i] === 0x48 && bytes[i + 1] === 0x83 && bytes[i + 2] === 0xEC) {
        isFunctionStart = true;
      } else if (i + 6 < len && bytes[i] === 0x48 && bytes[i + 1] === 0x81 && bytes[i + 2] === 0xEC) {
        isFunctionStart = true;
      }
      else if (i + 3 < len && bytes[i] === 0x53 && bytes[i + 1] === 0x48 && bytes[i + 2] === 0x83 && bytes[i + 3] === 0xEC) {
        isFunctionStart = true;
      }
      else if (i + 4 < len && bytes[i] === 0x48 && bytes[i + 1] === 0x89 && bytes[i + 2] === 0x4C && bytes[i + 3] === 0x24 && bytes[i + 4] === 0x08) {
        isFunctionStart = true;
      }
      else if (i + 4 < len && bytes[i] === 0x57 && bytes[i + 1] === 0x56 && bytes[i + 2] === 0x48 && bytes[i + 3] === 0x83 && bytes[i + 4] === 0xEC) {
        isFunctionStart = true;
      }
      else if (i > 0 && i + 3 < len && bytes[i] === 0x48 && bytes[i + 1] === 0x83 && bytes[i + 2] === 0xEC && (bytes[i - 1] === 0xCC || bytes[i - 1] === 0x90)) {
        isFunctionStart = true;
      }
      else if (i + 4 < len && bytes[i] === 0x40 && bytes[i + 1] === 0x53 && bytes[i + 2] === 0x48 && bytes[i + 3] === 0x83 && bytes[i + 4] === 0xEC) {
        isFunctionStart = true;
      }
      else if (i + 5 < len && bytes[i] === 0x40 && bytes[i + 1] === 0x55 && bytes[i + 2] === 0x48 && bytes[i + 3] === 0x8D && bytes[i + 4] === 0x6C && bytes[i + 5] === 0x24) {
        isFunctionStart = true;
      }
      else if (i + 4 < len && bytes[i] === 0x40 && bytes[i + 1] === 0x57 && bytes[i + 2] === 0x48 && bytes[i + 3] === 0x83 && bytes[i + 4] === 0xEC) {
        isFunctionStart = true;
      }
      else if (i + 3 < len && (
        (bytes[i] === 0x48 && bytes[i + 1] === 0x89 && bytes[i + 2] === 0x5C && bytes[i + 3] === 0x24) ||
        (bytes[i] === 0x4C && bytes[i + 1] === 0x89 && bytes[i + 2] === 0x44 && bytes[i + 3] === 0x24)
      )) {
        const atBoundary = i === 0
          || bytes[i - 1] === 0xCC || bytes[i - 1] === 0xC3 || bytes[i - 1] === 0x90
          || ((baseAddress + i) % 16 === 0);
        if (atBoundary) isFunctionStart = true;
      }
      else if (i + 2 < len && bytes[i] === 0x48 && bytes[i + 1] === 0x8B && bytes[i + 2] === 0xC4) {
        const atBoundary = i === 0
          || bytes[i - 1] === 0xCC || bytes[i - 1] === 0xC3 || bytes[i - 1] === 0x90
          || ((baseAddress + i) % 16 === 0);
        if (atBoundary) isFunctionStart = true;
      }
    } else {
      if (i + 2 < len && bytes[i] === 0x55 && bytes[i + 1] === 0x8B && bytes[i + 2] === 0xEC) {
        isFunctionStart = true;
      } else if (i + 2 < len && bytes[i] === 0x55 && bytes[i + 1] === 0x89 && bytes[i + 2] === 0xE5) {
        isFunctionStart = true;
      }
      else if (i + 4 < len && bytes[i] === 0x8B && bytes[i + 1] === 0xFF && bytes[i + 2] === 0x55 && bytes[i + 3] === 0x8B && bytes[i + 4] === 0xEC) {
        isFunctionStart = true;
      }
      else if (i + 2 < len && bytes[i] === 0x6A && bytes[i + 2] === 0x68) {
        const atBoundary = i === 0
          || bytes[i - 1] === 0xCC || bytes[i - 1] === 0xC3 || bytes[i - 1] === 0x90
          || ((baseAddress + i) % 16 === 0);
        if (atBoundary) isFunctionStart = true;
      }
    }
    if (isFunctionStart) addrSet.add(baseAddress + i);
  }

  // Alignment padding heuristic
  for (let i = 0; i < len; i++) {
    if (bytes[i] === 0xCC || bytes[i] === 0x90) {
      let padEnd = i + 1;
      let hasCC = bytes[i] === 0xCC;
      while (padEnd < len && (bytes[padEnd] === 0xCC || bytes[padEnd] === 0x90)) {
        if (bytes[padEnd] === 0xCC) hasCC = true;
        padEnd++;
      }
      const padLen = padEnd - i;
      const minLen = hasCC ? 2 : 3;
      if (padLen >= minLen && padEnd < len
          && bytes[padEnd] !== 0xCC && bytes[padEnd] !== 0x90
          && bytes[padEnd] !== 0x00
          && ((baseAddress + padEnd) % 4 === 0)) {
        addrSet.add(baseAddress + padEnd);
      }
      i = padEnd - 1;
    }
  }

  // Call target collection
  const callTargets = new Set<number>();
  const jumpTables = new Map<number, number[]>();
  const cs = is64 ? ctx.cs64 : ctx.cs32;
  if (cs) {
    let offset = 0;
    let prevWasUnconditional = false;
    const recentInsns: { address: number; mnemonic: string; opStr: string; size: number }[] = [];
    const MAX_RECENT = 8;
    while (offset < len) {
      const chunkEnd = Math.min(offset + CHUNK_SIZE, len);
      const chunk = bytes.subarray(offset, chunkEnd);
      try {
        const insns = cs.disasm(chunk, { address: baseAddress + offset });
        for (const insn of insns) {
          if (insn.mnemonic === 'call') {
            const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
            if (m) {
              const target = parseInt(m[1], 16);
              if (target >= baseAddress && target < endAddress) {
                addrSet.add(target);
                callTargets.add(target);
              }
            }
          }
          if (prevWasUnconditional && callTargets.has(insn.address)) {
            addrSet.add(insn.address);
          }

          // Jump table detection
          if (insn.mnemonic === 'jmp' && !insn.opStr.match(/^0x[0-9a-fA-F]+$/)) {
            let maxCases = 0;
            for (let ri = recentInsns.length - 1; ri >= 0; ri--) {
              const prev = recentInsns[ri];
              if (prev.mnemonic === 'cmp') {
                const immMatch = prev.opStr.match(/,\s*0x([0-9a-fA-F]+)$/);
                if (immMatch) {
                  maxCases = parseInt(immMatch[1], 16) + 1;
                } else {
                  const decMatch = prev.opStr.match(/,\s*(\d+)$/);
                  if (decMatch) maxCases = parseInt(decMatch[1], 10) + 1;
                }
                break;
              }
            }

            if (maxCases > 0 && maxCases <= 512) {
              let tableBase = 0;
              const ptrSize = is64 ? 8 : 4;

              const scaleMatch = insn.opStr.match(/\[.*\*\d\s*\+\s*0x([0-9a-fA-F]+)\]/);
              if (scaleMatch) {
                tableBase = parseInt(scaleMatch[1], 16);
              }

              if (!tableBase && is64) {
                const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
                if (ripMatch) {
                  const sign = ripMatch[1] === '+' ? 1 : -1;
                  const disp = parseInt(ripMatch[2], 16);
                  tableBase = insn.address + insn.size + sign * disp;
                }
              }

              if (tableBase) {
                const tableRVA = tableBase - baseAddress;
                if (tableRVA >= 0 && tableRVA < len) {
                  const targets: number[] = [];
                  for (let c = 0; c < maxCases; c++) {
                    const entryOffset = tableRVA + c * ptrSize;
                    if (entryOffset + ptrSize > len) break;
                    let target: number;
                    if (ptrSize === 8) {
                      const lo = bytes[entryOffset] | (bytes[entryOffset + 1] << 8) |
                                 (bytes[entryOffset + 2] << 16) | ((bytes[entryOffset + 3]) << 24);
                      const hi = bytes[entryOffset + 4] | (bytes[entryOffset + 5] << 8) |
                                 (bytes[entryOffset + 6] << 16) | ((bytes[entryOffset + 7]) << 24);
                      target = (hi * 0x100000000) + (lo >>> 0);
                    } else {
                      target = bytes[entryOffset] | (bytes[entryOffset + 1] << 8) |
                               (bytes[entryOffset + 2] << 16) | ((bytes[entryOffset + 3]) << 24);
                      target = target >>> 0;
                    }
                    if (target >= baseAddress && target < endAddress) {
                      targets.push(target);
                    } else {
                      break;
                    }
                  }
                  if (targets.length >= 2) {
                    jumpTables.set(insn.address, targets);
                    for (const t of targets) addrSet.add(t);
                  }
                }
              }
            }
          }

          const mn = insn.mnemonic;
          prevWasUnconditional = mn === 'ret' || mn === 'retn' || mn === 'jmp';
          recentInsns.push({ address: insn.address, mnemonic: insn.mnemonic, opStr: insn.opStr, size: insn.size });
          if (recentInsns.length > MAX_RECENT) recentInsns.shift();
        }
        if (insns.length === 0) {
          offset += 1;
          prevWasUnconditional = false;
        } else {
          const lastInsn = insns[insns.length - 1];
          const decoded = (lastInsn.address - (baseAddress + offset)) + lastInsn.size;
          offset += decoded;
        }
      } catch {
        offset += 1;
        prevWasUnconditional = false;
      }
    }
  }

  const sortedAddrs = Array.from(addrSet).sort((a, b) => a - b);
  const functions: DisasmFunction[] = sortedAddrs.map((addr) => ({
    name: nameMap.get(addr) || `sub_${addr.toString(16).toUpperCase()}`,
    address: addr,
    size: 0,
  }));

  for (let i = 0; i < functions.length; i++) {
    const pdataEnd = pdataEndMap.get(functions[i].address);
    if (pdataEnd) {
      functions[i].size = pdataEnd - functions[i].address;
    } else if (i < functions.length - 1) {
      functions[i].size = functions[i + 1].address - functions[i].address;
    } else {
      functions[i].size = endAddress - functions[i].address;
    }
  }

  // --- Thunk detection ---
  if (cs && ctx.iatMap.size > 0) {
    for (const fn of functions) {
      if (fn.name !== `sub_${fn.address.toString(16).toUpperCase()}`) continue;
      if (fn.size > 16) continue;
      const fnOffset = fn.address - baseAddress;
      if (fnOffset < 0 || fnOffset + fn.size > len) continue;
      const fnBytes = bytes.subarray(fnOffset, fnOffset + fn.size);
      try {
        const insns = cs.disasm(fnBytes, { address: fn.address });
        let jmpInsn: { address: number; mnemonic: string; opStr: string; size: number } | null = null;
        let meaningfulCount = 0;
        for (const insn of insns) {
          if (insn.mnemonic === 'nop' || insn.mnemonic === 'int3') continue;
          meaningfulCount++;
          if (insn.mnemonic === 'jmp' && meaningfulCount === 1) jmpInsn = insn;
        }
        if (jmpInsn && meaningfulCount === 1) {
          let resolvedAddr: number | null = null;
          if (is64) {
            const ripMatch = jmpInsn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
            if (ripMatch) {
              const sign = ripMatch[1] === '+' ? 1 : -1;
              const disp = parseInt(ripMatch[2], 16);
              resolvedAddr = jmpInsn.address + jmpInsn.size + sign * disp;
            }
          } else {
            const addrMatch = jmpInsn.opStr.match(/\[0x([0-9a-fA-F]+)\]/);
            if (addrMatch) resolvedAddr = parseInt(addrMatch[1], 16);
          }
          if (resolvedAddr !== null) {
            const iat = ctx.iatMap.get(resolvedAddr);
            if (iat) {
              fn.name = iat.func;
              fn.isThunk = true;
            }
          }
        }
      } catch { /* skip */ }
    }
  }

  // --- Tail call detection ---
  if (cs) {
    const funcAddrSet = new Set(sortedAddrs);
    const jumpTableTargets = new Set<number>();
    for (const [, targets] of jumpTables) {
      for (const t of targets) jumpTableTargets.add(t);
    }
    for (const fn of functions) {
      const tailLen = Math.min(15, fn.size);
      const tailOffset = fn.address + fn.size - tailLen - baseAddress;
      if (tailOffset < 0 || tailOffset + tailLen > len) continue;
      const tailBytes = bytes.subarray(tailOffset, tailOffset + tailLen);
      try {
        const insns = cs.disasm(tailBytes, { address: fn.address + fn.size - tailLen });
        let lastReal: { mnemonic: string; opStr: string } | null = null;
        for (let i = insns.length - 1; i >= 0; i--) {
          if (insns[i].mnemonic !== 'nop' && insns[i].mnemonic !== 'int3') {
            lastReal = insns[i];
            break;
          }
        }
        if (lastReal && lastReal.mnemonic === 'jmp') {
          const m = lastReal.opStr.match(/^0x([0-9a-fA-F]+)$/);
          if (m) {
            const target = parseInt(m[1], 16);
            if (
              funcAddrSet.has(target) &&
              target !== fn.address &&
              (target < fn.address || target >= fn.address + fn.size) &&
              !jumpTableTargets.has(target)
            ) {
              fn.tailCallTarget = target;
            }
          }
        }
      } catch { /* skip */ }
    }
  }

  return {
    functions,
    jumpTables: Array.from(jumpTables.entries()),
  };
}

export function hybridDisassemble(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  seeds: number[],
  ctx: DisasmContext,
  pdataRanges?: { beginAddress: number; endAddress: number }[],
): Instruction[] {
  const cs = is64 ? ctx.cs64 : ctx.cs32;
  const visited = new Set<number>();
  const instructionMap = new Map<number, Instruction>();
  const endAddress = baseAddress + bytes.length;

  const terminators = new Set(['ret', 'retn', 'int3', 'ud2']);
  const conditionalJumps = new Set([
    'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
    'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
    'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz',
  ]);

  // Performance optimization: bulk-decode .pdata ranges with known boundaries
  if (pdataRanges) {
    for (const range of pdataRanges) {
      if (range.beginAddress < baseAddress || range.endAddress > endAddress) continue;
      const rangeOffset = range.beginAddress - baseAddress;
      const rangeLen = range.endAddress - range.beginAddress;
      if (rangeLen <= 0 || rangeOffset + rangeLen > bytes.length) continue;

      const rangeBytes = bytes.subarray(rangeOffset, rangeOffset + rangeLen);
      try {
        const insns = cs.disasm(rangeBytes, { address: range.beginAddress });
        for (const insn of insns) {
          const mapped = mapInsn(insn, ctx.stringMap, ctx.iatMap, ctx.driverMode);
          mapped.source = 'recursive';
          instructionMap.set(insn.address, mapped);
          visited.add(insn.address);
        }
      } catch {
        // Fall through to BFS for this range
      }
    }
  }

  // Phase 1: Recursive descent (BFS)
  const workQueue = [...seeds];
  while (workQueue.length > 0) {
    const addr = workQueue.pop()!;
    if (visited.has(addr)) continue;
    if (addr < baseAddress || addr >= endAddress) continue;

    visited.add(addr);
    const offset = addr - baseAddress;
    const sliceEnd = Math.min(offset + 15, bytes.length);
    if (offset >= bytes.length) continue;

    let insns: any[];
    try {
      insns = cs.disasm(bytes.subarray(offset, sliceEnd), { address: addr });
    } catch {
      continue;
    }
    if (!insns || insns.length === 0) continue;

    const insn = insns[0];
    const mapped = mapInsn(insn, ctx.stringMap, ctx.iatMap, ctx.driverMode);
    mapped.source = 'recursive';
    instructionMap.set(addr, mapped);

    const mn = insn.mnemonic;

    if (terminators.has(mn)) continue;

    if (mn === 'jmp') {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= baseAddress && target < endAddress) {
          workQueue.push(target);
        }
      }
      continue;
    }

    if (conditionalJumps.has(mn) || (mn.startsWith('j') && mn !== 'jmp')) {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= baseAddress && target < endAddress) {
          workQueue.push(target);
        }
      }
      workQueue.push(addr + insn.size);
      continue;
    }

    if (mn === 'call') {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        if (target >= baseAddress && target < endAddress) {
          workQueue.push(target);
        }
      }
      workQueue.push(addr + insn.size);
      continue;
    }

    workQueue.push(addr + insn.size);
  }

  // Phase 2: Gap fill
  const covered = new Uint8Array(bytes.length);
  for (const [addr, insn] of instructionMap) {
    const start = addr - baseAddress;
    const end = Math.min(start + insn.size, bytes.length);
    for (let j = start; j < end; j++) covered[j] = 1;
  }
  let gapStart = -1;

  for (let i = 0; i <= bytes.length; i++) {
    const isCovered = i < bytes.length && covered[i] === 1;

    if (!isCovered && gapStart === -1 && i < bytes.length) {
      gapStart = i;
    } else if ((isCovered || i === bytes.length) && gapStart !== -1) {
      const gapEnd = i;
      const gapLen = gapEnd - gapStart;

      if (gapLen >= 2) {
        let allPadding = true;
        for (let j = gapStart; j < gapEnd; j++) {
          if (bytes[j] !== 0xCC && bytes[j] !== 0x90) {
            allPadding = false;
            break;
          }
        }

        if (!allPadding) {
          const gapBytes = bytes.subarray(gapStart, gapEnd);
          const gapBaseAddr = baseAddress + gapStart;
          const gapInsns = disassemble(gapBytes, gapBaseAddr, is64, ctx);
          for (const gi of gapInsns) {
            if (!instructionMap.has(gi.address)) {
              gi.source = 'gap-fill';
              instructionMap.set(gi.address, gi);
            }
          }
        }
      }

      gapStart = -1;
    }
  }

  const result = Array.from(instructionMap.values());
  result.sort((a, b) => a.address - b.address);
  return result;
}

export function buildTypedXrefMap(instructions: Instruction[]): [number, Xref[]][] {
  const xrefs = new Map<number, Xref[]>();
  const conditionalJumps = new Set([
    'je', 'jne', 'jz', 'jnz', 'jg', 'jge', 'jl', 'jle',
    'ja', 'jae', 'jb', 'jbe', 'jo', 'jno', 'js', 'jns',
    'jp', 'jnp', 'jcxz', 'jecxz', 'jrcxz',
  ]);

  for (const insn of instructions) {
    const mn = insn.mnemonic;

    const directMatch = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (directMatch) {
      const target = parseInt(directMatch[1], 16);
      let type: Xref['type'];
      if (mn === 'call') type = 'call';
      else if (mn === 'jmp') type = 'jmp';
      else if (conditionalJumps.has(mn) || mn.startsWith('j')) type = 'branch';
      else continue;

      let arr = xrefs.get(target);
      if (!arr) { arr = []; xrefs.set(target, arr); }
      arr.push({ from: insn.address, type });
      continue;
    }

    const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
    if (ripMatch) {
      const sign = ripMatch[1] === '+' ? 1 : -1;
      const disp = parseInt(ripMatch[2], 16);
      const target = insn.address + insn.size + sign * disp;
      let type: Xref['type'];
      if (mn === 'call') type = 'call';
      else if (mn === 'jmp') type = 'jmp';
      else type = 'data';

      let arr = xrefs.get(target);
      if (!arr) { arr = []; xrefs.set(target, arr); }
      arr.push({ from: insn.address, type });
      continue;
    }

    if (mn !== 'call' && mn !== 'jmp' && !mn.startsWith('j')) {
      const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
      if (addrMatches) {
        for (const addrStr of addrMatches) {
          const addr = parseInt(addrStr, 16);
          if (addr > 0x10000) {
            let arr = xrefs.get(addr);
            if (!arr) { arr = []; xrefs.set(addr, arr); }
            arr.push({ from: insn.address, type: 'data' });
          }
        }
      }
    }
  }

  return Array.from(xrefs.entries());
}

export function buildAllXrefs(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  stringAddrs: number[],
  iatAddrs: number[],
  cs: any,
  funcEntries?: [number, number][],
  dataSections?: { va: number; size: number }[],
): {
  stringXrefs: [number, number[]][];
  importXrefs: [number, number[]][];
  callGraph: [number, number[]][];
  dataXrefs: [number, number[]][];
} {
  const stringSet = new Set(stringAddrs);
  const iatSet = new Set(iatAddrs);
  const strXrefs = new Map<number, number[]>();
  const impXrefs = new Map<number, number[]>();
  const dataXrefs = new Map<number, number[]>();

  const funcAddrSet = new Set<number>();
  const funcBounds: [number, number][] = [];
  const callGraphMap = new Map<number, Set<number>>();

  if (funcEntries && funcEntries.length > 0) {
    for (const [addr] of funcEntries) funcAddrSet.add(addr);
    const sorted = [...funcEntries].sort((a, b) => a[0] - b[0]);
    for (const [addr, size] of sorted) funcBounds.push([addr, addr + size]);
  }

  const hasDataSections = dataSections && dataSections.length > 0;
  const isInDataSection = (addr: number): boolean => {
    if (!hasDataSections) return false;
    for (const ds of dataSections!) {
      if (addr >= ds.va && addr < ds.va + ds.size) return true;
    }
    return false;
  };

  const findContainingFunc = (addr: number): number => {
    if (funcBounds.length === 0) return -1;
    let lo = 0, hi = funcBounds.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      if (addr < funcBounds[mid][0]) hi = mid - 1;
      else if (addr >= funcBounds[mid][1]) lo = mid + 1;
      else return funcBounds[mid][0];
    }
    return -1;
  };

  let offset = 0;

  while (offset < bytes.length) {
    const chunkEnd = Math.min(offset + CHUNK_SIZE, bytes.length);
    const chunk = bytes.subarray(offset, chunkEnd);
    try {
      const insns = cs.disasm(chunk, { address: baseAddress + offset });
      for (const insn of insns) {
        const resolvedTargets: number[] = [];

        const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
        if (ripMatch) {
          const sign = ripMatch[1] === '+' ? 1 : -1;
          const disp = parseInt(ripMatch[2], 16);
          const target = insn.address + insn.size + sign * disp;
          resolvedTargets.push(target);
          if (stringSet.has(target)) {
            let arr = strXrefs.get(target);
            if (!arr) { arr = []; strXrefs.set(target, arr); }
            arr.push(insn.address);
          }
          if (iatSet.has(target)) {
            let arr = impXrefs.get(target);
            if (!arr) { arr = []; impXrefs.set(target, arr); }
            arr.push(insn.address);
          }
        }
        const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
        if (addrMatches) {
          for (const addrStr of addrMatches) {
            const addr = parseInt(addrStr, 16);
            resolvedTargets.push(addr);
            if (stringSet.has(addr)) {
              let arr = strXrefs.get(addr);
              if (!arr) { arr = []; strXrefs.set(addr, arr); }
              arr.push(insn.address);
            }
            if (iatSet.has(addr)) {
              let arr = impXrefs.get(addr);
              if (!arr) { arr = []; impXrefs.set(addr, arr); }
              arr.push(insn.address);
            }
          }
        }

        if (insn.mnemonic === 'call' && funcBounds.length > 0) {
          const directMatch = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
          if (directMatch) {
            const callTarget = parseInt(directMatch[1], 16);
            if (funcAddrSet.has(callTarget)) {
              const callerFunc = findContainingFunc(insn.address);
              if (callerFunc >= 0) {
                let callees = callGraphMap.get(callerFunc);
                if (!callees) { callees = new Set(); callGraphMap.set(callerFunc, callees); }
                callees.add(callTarget);
              }
            }
          }
        }

        if (hasDataSections) {
          for (const target of resolvedTargets) {
            if (!stringSet.has(target) && !iatSet.has(target) && isInDataSection(target)) {
              let arr = dataXrefs.get(target);
              if (!arr) { arr = []; dataXrefs.set(target, arr); }
              arr.push(insn.address);
            }
          }
        }
      }
      if (insns.length === 0) {
        offset += 1;
      } else {
        const lastInsn = insns[insns.length - 1];
        const decoded = (lastInsn.address - (baseAddress + offset)) + lastInsn.size;
        offset += decoded;
      }
    } catch {
      offset += 1;
    }
  }

  const callGraph: [number, number[]][] = [];
  for (const [funcAddr, callees] of callGraphMap) {
    callGraph.push([funcAddr, Array.from(callees)]);
  }

  return {
    stringXrefs: Array.from(strXrefs.entries()),
    importXrefs: Array.from(impXrefs.entries()),
    callGraph,
    dataXrefs: Array.from(dataXrefs.entries()),
  };
}
