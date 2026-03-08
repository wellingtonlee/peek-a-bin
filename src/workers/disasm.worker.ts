import { Const, Capstone, loadCapstone as _loadCapstone } from 'capstone-wasm';

// Runtime accepts an options object with instantiateWasm hook, but the
// published types omit the parameter under bundler module resolution.
const loadCapstone = _loadCapstone as (args?: Record<string, any>) => Promise<void>;
import type { Instruction, DisasmFunction, Xref, StackFrame } from '../disasm/types';
import type { FunctionSignature } from '../disasm/signatures';
import { extractStrings } from '../pe/parser';
import type { SectionHeader } from '../pe/types';
import { decompileFunction, type DecompileResult } from '../disasm/decompile/pipeline';
import { StructRegistry } from '../disasm/decompile/structs';
import { detectIRPDispatches, type IRPDispatchEntry } from '../analysis/driver';
import {
  type DisasmContext,
  mapInsn as _mapInsn,
  disassemble as _disassemble,
  detectFunctions as _detectFunctions,
  hybridDisassemble as _hybridDisassemble,
  buildTypedXrefMap,
  buildAllXrefs as _buildAllXrefs,
} from '../disasm/functionDetect';

let cs32: any;
let cs64: any;
let initialized = false;
let stringMap: Map<number, string> = new Map();
let iatMap: Map<number, { lib: string; func: string }> = new Map();
let driverMode = false;
let funcMap: Map<number, { name: string; address: number }> = new Map();
let jumpTableMap: Map<number, number[]> = new Map();
let structRegistry = new StructRegistry();

/** Build a DisasmContext from current module-level state */
function ctx(): DisasmContext {
  return { cs32, cs64, stringMap, iatMap, driverMode };
}

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

// Message protocol
interface WorkerRequest {
  id: number;
  method: 'init' | 'configure' | 'configureDecompileMaps' | 'disassemble' | 'hybridDisassemble' | 'detectFunctions' | 'buildTypedXrefMap' | 'buildAllXrefs' | 'extractStrings' | 'decompileFunction' | 'detectIRPDispatches' | 'resetStructRegistry';
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
        if (args.driverMode !== undefined) driverMode = args.driverMode;
        structRegistry = new StructRegistry();
        result = true;
        break;

      case 'configureDecompileMaps': {
        const fEntries: [number, { name: string; address: number }][] = args.funcEntries ?? [];
        funcMap = new Map(fEntries);
        const jtEntries: [number, number[]][] = args.jumpTableEntries ?? [];
        jumpTableMap = new Map(jtEntries);
        result = true;
        break;
      }

      case 'disassemble':
        result = _disassemble(args.bytes, args.baseAddress, args.is64, ctx());
        break;

      case 'hybridDisassemble':
        result = _hybridDisassemble(args.bytes, args.baseAddress, args.is64, args.seeds, ctx(), args.pdataRanges);
        break;

      case 'detectFunctions':
        result = _detectFunctions(args.bytes, args.baseAddress, args.is64, ctx(), args.options);
        break;

      case 'buildTypedXrefMap':
        result = buildTypedXrefMap(args.instructions);
        break;

      case 'buildAllXrefs': {
        const cs = args.is64 ? cs64 : cs32;
        result = _buildAllXrefs(args.bytes, args.baseAddress, args.is64, args.stringAddrs, args.iatAddrs, cs, args.funcEntries, args.dataSections);
        break;
      }

      case 'extractStrings': {
        const { strings, stringTypes } = extractStrings(args.buffer, args.sections as SectionHeader[], args.imageBase, args.is64 as boolean | undefined);
        result = {
          strings: Array.from(strings.entries()),
          stringTypes: Array.from(stringTypes.entries()),
        };
        break;
      }

      case 'detectIRPDispatches':
        result = detectIRPDispatches(args.instructions as Instruction[], args.is64 as boolean);
        break;

      case 'resetStructRegistry':
        structRegistry = new StructRegistry();
        result = true;
        break;

      case 'decompileFunction': {
        const xrefEntries: [number, Xref[]][] = args.xrefEntries ?? [];
        const xMap = new Map<number, Xref[]>(xrefEntries);
        // Use per-call funcMap if provided (includes renames), else fall back to stored
        const fEntries: [number, { name: string; address: number }][] | undefined = args.funcEntries;
        const fMap = fEntries ? new Map(fEntries) : funcMap;
        result = decompileFunction(
          args.func as DisasmFunction,
          args.instructions as Instruction[],
          xMap,
          args.stackFrame as StackFrame | null,
          args.signature as FunctionSignature | null,
          args.is64 as boolean,
          jumpTableMap,
          iatMap,
          stringMap,
          fMap,
          structRegistry,
          args.runtimeFunctions,
        );
        break;
      }
    }

    self.postMessage({ id, result });
  } catch (err: any) {
    self.postMessage({ id, error: err?.message ?? String(err) });
  }
};
