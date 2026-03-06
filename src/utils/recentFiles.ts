const DB_NAME = "peek-a-bin-files";
const STORE_NAME = "files";
const MAX_ENTRIES = 5;
const MAX_SIZE = 50 * 1024 * 1024; // 50MB

export interface RecentFileEntry {
  name: string;
  size: number;
  lastOpened: number;
}

function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: "name" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function saveRecentFile(name: string, buffer: ArrayBuffer): Promise<void> {
  if (buffer.byteLength > MAX_SIZE) return;
  try {
    const db = await openDB();
    // Get all entries to enforce limit
    const all = await new Promise<{ name: string; lastOpened: number }[]>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).getAll();
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });

    // Sort oldest first
    all.sort((a, b) => a.lastOpened - b.lastOpened);

    const tx = db.transaction(STORE_NAME, "readwrite");
    const store = tx.objectStore(STORE_NAME);

    // Evict oldest if at limit (account for current entry possibly being an update)
    const isUpdate = all.some((e) => e.name === name);
    const excess = all.length - MAX_ENTRIES + (isUpdate ? 0 : 1);
    if (excess > 0) {
      for (let i = 0; i < excess; i++) {
        if (all[i].name !== name) store.delete(all[i].name);
      }
    }

    store.put({ name, buffer, size: buffer.byteLength, lastOpened: Date.now() });
    await new Promise<void>((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // IndexedDB unavailable — non-fatal
  }
}

export async function getRecentFiles(): Promise<RecentFileEntry[]> {
  try {
    const db = await openDB();
    const all = await new Promise<{ name: string; size: number; lastOpened: number }[]>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).getAll();
      req.onsuccess = () =>
        resolve(
          req.result.map((e: any) => ({
            name: e.name,
            size: e.size,
            lastOpened: e.lastOpened,
          })),
        );
      req.onerror = () => reject(req.error);
    });
    all.sort((a, b) => b.lastOpened - a.lastOpened);
    return all.slice(0, MAX_ENTRIES);
  } catch {
    return [];
  }
}

export async function loadRecentFile(name: string): Promise<ArrayBuffer | null> {
  try {
    const db = await openDB();
    const entry = await new Promise<any>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(name);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return entry?.buffer ?? null;
  } catch {
    return null;
  }
}

export async function deleteRecentFile(name: string): Promise<void> {
  try {
    const db = await openDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).delete(name);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // non-fatal
  }
}
