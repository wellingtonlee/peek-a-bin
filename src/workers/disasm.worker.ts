import { Const, Capstone, loadCapstone as _loadCapstone } from "capstone-wasm";

// Runtime accepts an options object with instantiateWasm hook, but the
// published types omit the parameter under bundler module resolution.
const loadCapstone = _loadCapstone as (args?: Record<string, any>) => Promise<void>;
import { createWorkerState, dispatch, type WorkerRequest } from "./dispatch";

// --- IndexedDB WASM module cache ---
const IDB_NAME = "peek-a-bin-wasm";
const IDB_STORE = "modules";
const IDB_KEY = "capstone-v1";

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
      const tx = db.transaction(IDB_STORE, "readonly");
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
      const tx = db.transaction(IDB_STORE, "readwrite");
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
      const tx = db.transaction(IDB_STORE, "readwrite");
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
    const errorSignal = new Promise<never>((_, reject) => {
      onError = reject;
    });
    try {
      await Promise.race([
        loadCapstone({
          instantiateWasm(
            imports: WebAssembly.Imports,
            receiveInstance: (instance: WebAssembly.Instance) => void,
          ) {
            WebAssembly.instantiate(cached, imports).then(
              (instance) => receiveInstance(instance),
              (err) => onError!(err),
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
    const entry = performance.getEntriesByType("resource").find((e) => e.name.endsWith(".wasm"));
    if (entry) {
      fetch(entry.name)
        .then((r) => r.arrayBuffer())
        .then((buf) => WebAssembly.compile(buf))
        .then((mod) => cacheModule(mod))
        .catch(() => {}); // non-fatal
    }
  } catch {
    // Performance API unavailable — skip caching
  }
}

/** Session state the dispatch reads and writes. */
const state = createWorkerState(Promise.resolve());

// Start WASM loading eagerly at module evaluation time
const initPromise = (async () => {
  try {
    await loadCapstoneWithCache();
  } catch {
    // IDB or instantiateWasm hook failed — fall back to default loading
    await loadCapstone();
  }
  state.cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
  state.cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
  // ARM64 comes out of the same WASM module that is already loaded — a
  // `Capstone` is a `cs_open` handle, not an engine — so this adds no download,
  // no second `.wasm` asset to precache, and no measurable startup time. Opened
  // eagerly alongside the others so `configure` has nothing to wait for.
  state.csArm64 = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM);
})();

// `init` waits on this rather than on a placeholder.
state.ready = initPromise;

self.onmessage = async (e: MessageEvent<WorkerRequest>) => {
  const { id, method, args } = e.data;
  try {
    const result = await dispatch(method, args, state);
    self.postMessage({ id, result });
  } catch (err: any) {
    self.postMessage({ id, error: err?.message ?? String(err) });
  }
};
