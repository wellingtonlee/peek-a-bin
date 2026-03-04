import { Const, Capstone, loadCapstone as _loadCapstone } from 'capstone-wasm';

// Runtime accepts an options object with instantiateWasm hook, but the
// published types omit the parameter under bundler module resolution.
const loadCapstone = _loadCapstone as (args?: Record<string, any>) => Promise<void>;
import type { Instruction, DisasmFunction, Xref, StackFrame } from '../disasm/types';
import type { FunctionSignature } from '../disasm/signatures';
import { extractStrings } from '../pe/parser';
import type { SectionHeader } from '../pe/types';
import { decompileFunction } from '../disasm/decompile/pipeline';

let cs32: any;
let cs64: any;
let initialized = false;
let stringMap: Map<number, string> = new Map();
let iatMap: Map<number, { lib: string; func: string }> = new Map();

// --- IndexedDB WASM module cache ---
const IDB_NAME = 'peek-a-bin-wasm';
const IDB_STORE = 'modules';
const IDB_KEY = 'capstone-v1';

function openIDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(IDB_NAME, 1);
    req.onupgradeneeded = () => req.result.createObjectStore(IDB_STORE);
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function getCachedModule(): Promise<WebAssembly.Module | null> {
  try {
    const db = await openIDB();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readonly');
      const req = tx.objectStore(IDB_STORE).get(IDB_KEY);
      req.onsuccess = () => resolve(req.result instanceof WebAssembly.Module ? req.result : null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}

async function cacheModule(mod: WebAssembly.Module): Promise<void> {
  try {
    const db = await openIDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).put(mod, IDB_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // IDB write failed — non-fatal
  }
}

async function deleteCachedModule(): Promise<void> {
  try {
    const db = await openIDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(IDB_STORE, 'readwrite');
      tx.objectStore(IDB_STORE).delete(IDB_KEY);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // non-fatal
  }
}

async function loadCapstoneWithCache(): Promise<void> {
  const cached = await getCachedModule();
  if (cached) {
    // Fast path: instantiate from cached module.
    // Promise.race ensures we reject if instantiation fails (stale/corrupt module)
    // instead of hanging forever waiting for receiveInstance.
    let onError: (err: unknown) => void;
    const errorSignal = new Promise<never>((_, reject) => { onError = reject; });
    try {
      await Promise.race([
        loadCapstone({
          instantiateWasm(imports: WebAssembly.Imports, receiveInstance: (instance: WebAssembly.Instance) => void) {
            WebAssembly.instantiate(cached, imports).then(
              instance => receiveInstance(instance),
              err => onError!(err),
            );
            return {};
          },
        }),
        errorSignal,
      ]);
      return; // cached module worked
    } catch {
      await deleteCachedModule(); // stale — fall through to cold path
    }
  }

  // Cold path: let Emscripten handle fetch + compile via its default
  // instantiateAsync pipeline (has streaming → ArrayBuffer fallback).
  // Don't provide locateFile — in module workers, Emscripten's scriptDirectory
  // is empty (it checks importScripts which doesn't exist in module workers),
  // so our locateFile callback would receive an empty scriptDir and produce a
  // wrong relative URL. Without hooks, Emscripten resolves the WASM URL
  // correctly via new URL("capstone.wasm", import.meta.url).
  await loadCapstone();

  // Background: fetch + compile the WASM and cache for next visit.
  // Retrieve the URL Emscripten already fetched from the Performance API.
  try {
    const entry = performance.getEntriesByType('resource')
      .find(e => e.name.endsWith('.wasm'));
    if (entry) {
      fetch(entry.name)
        .then(r => r.arrayBuffer())
        .then(buf => WebAssembly.compile(buf))
        .then(mod => cacheModule(mod))
        .catch(() => {}); // non-fatal
    }
  } catch {
    // Performance API unavailable — skip caching
  }
}

// Start WASM loading eagerly at module evaluation time
const initPromise = (async () => {
  try {
    await loadCapstoneWithCache();
  } catch {
    // IDB or instantiateWasm hook failed — fall back to default loading
    await loadCapstone();
  }
  cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
  cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
  initialized = true;
})();

const CHUNK_SIZE = 0x10000;

function mapInsn(insn: any): Instruction {
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

  return instruction;
}

function disassemble(bytes: Uint8Array, baseAddress: number, is64: boolean): Instruction[] {
  const cs = is64 ? cs64 : cs32;
  const instructions: Instruction[] = [];
  let offset = 0;

  while (offset < bytes.length) {
    const chunkEnd = Math.min(offset + CHUNK_SIZE, bytes.length);
    const chunk = bytes.subarray(offset, chunkEnd);
    try {
      const insns = cs.disasm(chunk, { address: baseAddress + offset });
      for (const insn of insns) {
        instructions.push(mapInsn(insn));
      }
      if (insns.length === 0) {
        offset += 1;
      } else {
        const lastInsn = insns[insns.length - 1];
        const decoded = (lastInsn.address - (baseAddress + offset)) + lastInsn.size;
        offset += decoded;
      }
    } catch {
      offset += CHUNK_SIZE;
    }
  }

  return instructions;
}

interface DetectResult {
  functions: DisasmFunction[];
  jumpTables: [number, number[]][];  // jmp addr → target VAs
}

function detectFunctions(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  options?: {
    exports?: { name: string; address: number }[];
    entryPoint?: number;
    pdataFunctions?: { beginAddress: number; endAddress: number }[];
  }
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
      // push rbx; sub rsp, N (MSVC leaf/fastcall)
      else if (i + 3 < len && bytes[i] === 0x53 && bytes[i + 1] === 0x48 && bytes[i + 2] === 0x83 && bytes[i + 3] === 0xEC) {
        isFunctionStart = true;
      }
      // mov [rsp+8], rcx (SEH frame setup)
      else if (i + 4 < len && bytes[i] === 0x48 && bytes[i + 1] === 0x89 && bytes[i + 2] === 0x4C && bytes[i + 3] === 0x24 && bytes[i + 4] === 0x08) {
        isFunctionStart = true;
      }
      // push rdi; push rsi; sub rsp, N (callee-save heavy)
      else if (i + 4 < len && bytes[i] === 0x57 && bytes[i + 1] === 0x56 && bytes[i + 2] === 0x48 && bytes[i + 3] === 0x83 && bytes[i + 4] === 0xEC) {
        isFunctionStart = true;
      }
      // sub rsp, N preceded by CC/90 padding (alignment)
      else if (i > 0 && i + 3 < len && bytes[i] === 0x48 && bytes[i + 1] === 0x83 && bytes[i + 2] === 0xEC && (bytes[i - 1] === 0xCC || bytes[i - 1] === 0x90)) {
        isFunctionStart = true;
      }
    } else {
      if (i + 2 < len && bytes[i] === 0x55 && bytes[i + 1] === 0x8B && bytes[i + 2] === 0xEC) {
        isFunctionStart = true;
      } else if (i + 2 < len && bytes[i] === 0x55 && bytes[i + 1] === 0x89 && bytes[i + 2] === 0xE5) {
        isFunctionStart = true;
      }
    }
    if (isFunctionStart) addrSet.add(baseAddress + i);
  }

  // Alignment padding heuristic
  for (let i = 0; i < len; i++) {
    if (bytes[i] === 0xCC || bytes[i] === 0x90) {
      let padEnd = i + 1;
      while (padEnd < len && (bytes[padEnd] === 0xCC || bytes[padEnd] === 0x90)) padEnd++;
      if (padEnd - i >= 2 && padEnd < len && bytes[padEnd] !== 0xCC && bytes[padEnd] !== 0x90) {
        addrSet.add(baseAddress + padEnd);
      }
      i = padEnd - 1;
    }
  }

  // Call target collection
  const callTargets = new Set<number>();
  const jumpTables = new Map<number, number[]>(); // jmp addr → target VAs
  if (initialized) {
    const cs = is64 ? cs64 : cs32;
    let offset = 0;
    let prevWasUnconditional = false;
    // Track recent instructions for jump table pattern detection
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

          // Jump table detection: indirect jmp with [reg*4 + base] or [rip + disp]
          if (insn.mnemonic === 'jmp' && !insn.opStr.match(/^0x[0-9a-fA-F]+$/)) {
            // Look for cmp reg, imm in recent instructions to get max case count
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
              // Try to extract table base address
              let tableBase = 0;
              const ptrSize = is64 ? 8 : 4;

              // Pattern: jmp qword ptr [reg*8 + base] or jmp dword ptr [reg*4 + base]
              const scaleMatch = insn.opStr.match(/\[.*\*\d\s*\+\s*0x([0-9a-fA-F]+)\]/);
              if (scaleMatch) {
                tableBase = parseInt(scaleMatch[1], 16);
              }

              // Pattern: jmp qword ptr [rip + disp] (PIC jump tables, less common for switch)
              if (!tableBase && is64) {
                const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
                if (ripMatch) {
                  const sign = ripMatch[1] === '+' ? 1 : -1;
                  const disp = parseInt(ripMatch[2], 16);
                  tableBase = insn.address + insn.size + sign * disp;
                }
              }

              if (tableBase) {
                // Convert table base VA to file offset and read entries
                const tableRVA = tableBase - baseAddress;
                if (tableRVA >= 0 && tableRVA < len) {
                  // For 32-bit tables or absolute entries
                  const targets: number[] = [];
                  for (let c = 0; c < maxCases; c++) {
                    const entryOffset = tableRVA + c * ptrSize;
                    if (entryOffset + ptrSize > len) break;
                    let target: number;
                    if (ptrSize === 8) {
                      // Read as two 32-bit values to avoid BigInt
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
                    // Validate target falls within text section
                    if (target >= baseAddress && target < endAddress) {
                      targets.push(target);
                    } else {
                      break; // Invalid entry, stop reading
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
        offset += CHUNK_SIZE;
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
    // Use .pdata for precise function sizes when available
    const pdataEnd = pdataEndMap.get(functions[i].address);
    if (pdataEnd) {
      functions[i].size = pdataEnd - functions[i].address;
    } else if (i < functions.length - 1) {
      functions[i].size = functions[i + 1].address - functions[i].address;
    } else {
      functions[i].size = endAddress - functions[i].address;
    }
  }

  return {
    functions,
    jumpTables: Array.from(jumpTables.entries()),
  };
}

function hybridDisassemble(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  seeds: number[],
  pdataRanges?: { beginAddress: number; endAddress: number }[],
): Instruction[] {
  const cs = is64 ? cs64 : cs32;
  const visited = new Set<number>();
  const instructionMap = new Map<number, Instruction>();
  const endAddress = baseAddress + bytes.length;

  // Control-flow terminators
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
          const mapped = mapInsn(insn);
          mapped.source = 'recursive';
          instructionMap.set(insn.address, mapped);
          visited.add(insn.address);
        }
      } catch {
        // Fall through to BFS for this range
      }
    }
  }

  // Phase 1: Recursive descent (BFS) for non-.pdata seeds
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
    const mapped = mapInsn(insn);
    mapped.source = 'recursive';
    instructionMap.set(addr, mapped);

    const mn = insn.mnemonic;

    if (terminators.has(mn)) {
      // Stop this path
      continue;
    }

    if (mn === 'jmp') {
      // Unconditional jump — follow target, stop current path
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
      // Conditional branch — queue target + fall-through
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
      // Call — queue call target as seed + fall-through
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

    // Default: fall through to next instruction
    workQueue.push(addr + insn.size);
  }

  // Phase 2: Gap fill — scan uncovered byte ranges
  const coveredAddrs = new Set(instructionMap.keys());
  let gapStart = -1;

  for (let i = 0; i <= bytes.length; i++) {
    const addr = baseAddress + i;
    const isCovered = i < bytes.length && coveredAddrs.has(addr);

    if (!isCovered && gapStart === -1 && i < bytes.length) {
      gapStart = i;
    } else if ((isCovered || i === bytes.length) && gapStart !== -1) {
      const gapEnd = i;
      const gapLen = gapEnd - gapStart;

      // Skip tiny gaps or pure padding
      if (gapLen >= 2) {
        let allPadding = true;
        for (let j = gapStart; j < gapEnd; j++) {
          if (bytes[j] !== 0xCC && bytes[j] !== 0x90) {
            allPadding = false;
            break;
          }
        }

        if (!allPadding) {
          // Linear sweep this gap
          const gapBytes = bytes.subarray(gapStart, gapEnd);
          const gapBaseAddr = baseAddress + gapStart;
          const gapInsns = disassemble(gapBytes, gapBaseAddr, is64);
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

  // Sort by address and return
  const result = Array.from(instructionMap.values());
  result.sort((a, b) => a.address - b.address);
  return result;
}

function buildTypedXrefMap(instructions: Instruction[]): [number, Xref[]][] {
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

function buildAllXrefs(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  stringAddrs: number[],
  iatAddrs: number[],
): { stringXrefs: [number, number[]][]; importXrefs: [number, number[]][] } {
  const stringSet = new Set(stringAddrs);
  const iatSet = new Set(iatAddrs);
  const strXrefs = new Map<number, number[]>();
  const impXrefs = new Map<number, number[]>();

  const cs = is64 ? cs64 : cs32;
  let offset = 0;

  while (offset < bytes.length) {
    const chunkEnd = Math.min(offset + CHUNK_SIZE, bytes.length);
    const chunk = bytes.subarray(offset, chunkEnd);
    try {
      const insns = cs.disasm(chunk, { address: baseAddress + offset });
      for (const insn of insns) {
        // RIP-relative addressing
        const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
        if (ripMatch) {
          const sign = ripMatch[1] === '+' ? 1 : -1;
          const disp = parseInt(ripMatch[2], 16);
          const target = insn.address + insn.size + sign * disp;
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
        // Direct address references
        const addrMatches = insn.opStr.match(/0x([0-9a-fA-F]+)/g);
        if (addrMatches) {
          for (const addrStr of addrMatches) {
            const addr = parseInt(addrStr, 16);
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
      }
      if (insns.length === 0) {
        offset += 1;
      } else {
        const lastInsn = insns[insns.length - 1];
        const decoded = (lastInsn.address - (baseAddress + offset)) + lastInsn.size;
        offset += decoded;
      }
    } catch {
      offset += CHUNK_SIZE;
    }
  }

  return {
    stringXrefs: Array.from(strXrefs.entries()),
    importXrefs: Array.from(impXrefs.entries()),
  };
}

// Message protocol
interface WorkerRequest {
  id: number;
  method: 'init' | 'configure' | 'disassemble' | 'hybridDisassemble' | 'detectFunctions' | 'buildTypedXrefMap' | 'buildAllXrefs' | 'extractStrings' | 'decompileFunction';
  args: any;
}

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const { id, method, args } = e.data;
  try {
    let result: any;

    switch (method) {
      case 'init':
        await initPromise;
        result = true;
        break;

      case 'configure':
        // Receive maps as entries arrays (Maps don't survive structured clone)
        stringMap = new Map(args.stringEntries);
        iatMap = new Map(args.iatEntries);
        result = true;
        break;

      case 'disassemble':
        result = disassemble(args.bytes, args.baseAddress, args.is64);
        break;

      case 'hybridDisassemble':
        result = hybridDisassemble(args.bytes, args.baseAddress, args.is64, args.seeds, args.pdataRanges);
        break;

      case 'detectFunctions':
        result = detectFunctions(args.bytes, args.baseAddress, args.is64, args.options);
        break;

      case 'buildTypedXrefMap':
        result = buildTypedXrefMap(args.instructions);
        break;

      case 'buildAllXrefs':
        result = buildAllXrefs(args.bytes, args.baseAddress, args.is64, args.stringAddrs, args.iatAddrs);
        break;

      case 'extractStrings': {
        const { strings, stringTypes } = extractStrings(args.buffer, args.sections as SectionHeader[], args.imageBase);
        result = {
          strings: Array.from(strings.entries()),
          stringTypes: Array.from(stringTypes.entries()),
        };
        break;
      }

      case 'decompileFunction': {
        const xrefEntries: [number, Xref[]][] = args.xrefEntries ?? [];
        const xMap = new Map<number, Xref[]>(xrefEntries);
        const jtEntries: [number, number[]][] = args.jumpTableEntries ?? [];
        const jtMap = new Map<number, number[]>(jtEntries);
        const iatEntries: [number, { lib: string; func: string }][] = args.iatEntries ?? [];
        const iMap = new Map(iatEntries);
        const strEntries: [number, string][] = args.stringEntries ?? [];
        const sMap = new Map(strEntries);
        const funcEntries: [number, { name: string; address: number }][] = args.funcEntries ?? [];
        const fMap = new Map(funcEntries);
        result = decompileFunction(
          args.func as DisasmFunction,
          args.instructions as Instruction[],
          xMap,
          args.stackFrame as StackFrame | null,
          args.signature as FunctionSignature | null,
          args.is64 as boolean,
          jtMap,
          iMap,
          sMap,
          fMap,
        );
        break;
      }
    }

    self.postMessage({ id, result });
  } catch (err: any) {
    self.postMessage({ id, error: err?.message ?? String(err) });
  }
};
