import { Const, Capstone, loadCapstone } from 'capstone-wasm';
import type { Instruction, DisasmFunction, Xref } from '../disasm/types';

let cs32: any;
let cs64: any;
let initialized = false;
let stringMap: Map<number, string> = new Map();
let iatMap: Map<number, { lib: string; func: string }> = new Map();

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

function detectFunctions(
  bytes: Uint8Array,
  baseAddress: number,
  is64: boolean,
  options?: { exports?: { name: string; address: number }[]; entryPoint?: number }
): DisasmFunction[] {
  const addrSet = new Set<number>();
  const nameMap = new Map<number, string>();
  const len = bytes.length;
  const endAddress = baseAddress + len;

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

  // Call target collection for sections < 2MB
  const callTargets = new Set<number>();
  if (len < 2 * 1024 * 1024 && initialized) {
    const cs = is64 ? cs64 : cs32;
    let offset = 0;
    let prevWasUnconditional = false;
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
          const mn = insn.mnemonic;
          prevWasUnconditional = mn === 'ret' || mn === 'retn' || mn === 'jmp';
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
    if (i < functions.length - 1) {
      functions[i].size = functions[i + 1].address - functions[i].address;
    } else {
      functions[i].size = endAddress - functions[i].address;
    }
  }

  return functions;
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

// Message protocol
interface WorkerRequest {
  id: number;
  method: 'init' | 'configure' | 'disassemble' | 'detectFunctions' | 'buildTypedXrefMap';
  args: any;
}

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const { id, method, args } = e.data;
  try {
    let result: any;

    switch (method) {
      case 'init':
        if (!initialized) {
          await loadCapstone();
          cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
          cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
          initialized = true;
        }
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

      case 'detectFunctions':
        result = detectFunctions(args.bytes, args.baseAddress, args.is64, args.options);
        break;

      case 'buildTypedXrefMap':
        result = buildTypedXrefMap(args.instructions);
        break;
    }

    self.postMessage({ id, result });
  } catch (err: any) {
    self.postMessage({ id, error: err?.message ?? String(err) });
  }
};
