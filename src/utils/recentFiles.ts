import type { PEFile } from "../pe/types";
import { buildIdentityOf, buildKey } from "./annotationKey";

const DB_NAME = "peek-a-bin-files";
const STORE_NAME = "files";
const MAX_ENTRIES = 5;
const MAX_SIZE = 50 * 1024 * 1024; // 50MB

/**
 * The store's version. **Bumped 1 → 2 when the key stopped being the file
 * name** — see {@link openDB} for the upgrade and why it cannot be skipped.
 */
const DB_VERSION = 2;

/**
 * The property a record is keyed on, since v2.
 *
 * v1 used `keyPath: "name"`, so opening `v2/setup.exe` **silently evicted**
 * `v1/setup.exe`'s cached bytes — a `put` under an occupied key is an
 * overwrite — and `FileLoader`'s recents list joined its two halves on the name
 * too. It is {@link buildKey}'s composite build identity now, the same string
 * `utils/annotationKey.ts` keys annotations on, so the join between a cached
 * file and its bookmarks is exact rather than a guess (`peek-a-bin-mtry`).
 *
 * **The record still carries `name`**, for exactly the reason the annotation
 * record does: once the name is not the key it has to come back out of the
 * value, because the recents list is a list of names.
 */
const KEY_PATH = "key";

/**
 * The key a record migrated from the v1 store is carried forward under.
 *
 * **Why a synthetic key at all: a v1 record has a name and no build identity,
 * and there is no way to derive one without re-parsing the bytes.** Doing that
 * inside the `versionchange` transaction was considered and refused — see
 * {@link openDB}. So a v1 record keeps the only identity it has, its name,
 * under a prefix that can never collide with a real build key (which begins
 * with a digit, `size` being a number).
 *
 * These records are perfectly usable: they display, they load, and they are
 * evicted oldest-first like any other. They simply age out of `MAX_ENTRIES` as
 * the user opens files, and each is replaced by a properly build-keyed record
 * the moment its own file is opened again.
 */
const LEGACY_KEY_PREFIX = "name:";

/** PURE. The v1-record key for a file name. */
export function legacyRecentKey(name: string): string {
  return `${LEGACY_KEY_PREFIX}${name}`;
}

/** PURE. Whether a key is one this module synthesised for a v1 record. */
export function isLegacyRecentKey(key: string): boolean {
  return key.startsWith(LEGACY_KEY_PREFIX);
}

/**
 * PURE. What a v1 record becomes in the v2 store.
 *
 * Extracted so the migration's *decision* can be tested without an IndexedDB —
 * the wiring around it is exercised against the double in
 * `__tests__/fakeIndexedDB.ts`, but the rule is asked here.
 *
 * Every field is carried through untouched and a `key` is added. A record with
 * no usable `name` cannot be carried (it has no identity at all and would key
 * every such record to one slot), and returns null.
 */
export function migrateV1Record(record: unknown): Record<string, unknown> | null {
  if (!record || typeof record !== "object") return null;
  const row = record as Record<string, unknown>;
  if (typeof row.name !== "string" || row.name === "") return null;
  return { ...row, [KEY_PATH]: legacyRecentKey(row.name) };
}

export interface RecentFileEntry {
  /**
   * The store key — this build's identity, or a `name:`-prefixed key for a
   * record migrated from v1. **What {@link loadRecentFile} and
   * {@link deleteRecentFile} take**, because the name no longer identifies a
   * row: two builds of one binary are two rows with one name.
   */
  key: string;
  name: string;
  size: number;
  lastOpened: number;
}

/**
 * The recents key for a parsed image. The one call sites want.
 *
 * A thin composition rather than a rule of its own, so the composite format has
 * exactly one declaration (`utils/annotationKey.ts`). `buildIdentityOf` walks
 * the debug directory, which is bounded in every direction and is the same
 * bounded walk `App`'s annotation-key memo makes — the two are computed
 * independently and cheaply rather than threaded, so neither has to know the
 * other ran.
 */
export function recentFileKey(pe: PEFile): string {
  return buildKey(buildIdentityOf(pe));
}

/**
 * Open the store, upgrading a v1 database in place.
 *
 * **THE `keyPath` OF AN EXISTING OBJECT STORE CANNOT BE CHANGED**, so the v2
 * upgrade reads every v1 record out, deletes the store, recreates it under the
 * new key path and writes every record back with a synthesised key. Both
 * `deleteObjectStore` and `createObjectStore` are legal only inside a
 * `versionchange` transaction, which is why this lives here and not in a
 * migration the app calls later.
 *
 * **THE TRANSACTION MUST NOT BE LEFT IDLE.** A `versionchange` transaction
 * commits the moment control returns to the event loop with no request
 * outstanding, so the rewrite is issued from `getAll`'s own `onsuccess` — one
 * unbroken chain of requests, no `await`, no timer.
 *
 * **RE-DERIVING A REAL BUILD KEY HERE WAS REFUSED.** The bytes are right there
 * and `parsePE` is synchronous, so it *could* be done — and it would mean
 * running the PE parser up to five times, over up to 50 MB each, synchronously
 * inside a database upgrade, on the main thread, on a record that may no longer
 * parse at all. A throw there aborts the `versionchange` transaction, which
 * fails the open, which leaves the user with *no recents and no way back* until
 * the next attempt also fails. The prize would be that a cached file keeps a
 * build-keyed annotation join across the upgrade — and cached bytes are
 * recoverable by re-dropping the file, which is the whole reason this bead was
 * split from the annotation one and ranked below it. Carrying the name forward
 * costs a stale key that ages out on its own.
 *
 * A failed upgrade aborts and rolls back, so the failure mode is "no recents
 * this session", never a half-migrated store.
 */
function openDB(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (event) => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME, { keyPath: KEY_PATH });
        return;
      }
      // A store exists, so this is v1 → v2: rekey every record it holds.
      if (event.oldVersion >= DB_VERSION) return;
      const tx = req.transaction;
      if (!tx) return;
      const getAll = tx.objectStore(STORE_NAME).getAll();
      getAll.onsuccess = () => {
        const rows: unknown[] = getAll.result ?? [];
        db.deleteObjectStore(STORE_NAME);
        const store = db.createObjectStore(STORE_NAME, { keyPath: KEY_PATH });
        for (const row of rows) {
          const migrated = migrateV1Record(row);
          if (migrated) store.put(migrated);
        }
      };
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

/**
 * Cache one file's bytes under its build key.
 *
 * `name` is stored beside the key rather than as it, so the recents list can
 * still print it — and so two builds of one binary are two rows rather than one
 * overwriting the other.
 */
export async function saveRecentFile(
  key: string,
  name: string,
  buffer: ArrayBuffer,
): Promise<void> {
  if (buffer.byteLength > MAX_SIZE) return;
  try {
    const db = await openDB();
    // Get all entries to enforce limit
    const all = await new Promise<{ key: string; lastOpened: number }[]>((resolve, reject) => {
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
    const isUpdate = all.some((e) => e.key === key);
    const excess = all.length - MAX_ENTRIES + (isUpdate ? 0 : 1);
    if (excess > 0) {
      for (let i = 0; i < excess; i++) {
        if (all[i].key !== key) store.delete(all[i].key);
      }
    }

    store.put({ key, name, buffer, size: buffer.byteLength, lastOpened: Date.now() });
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
    const all = await new Promise<RecentFileEntry[]>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).getAll();
      req.onsuccess = () =>
        resolve(
          req.result.map((e: any) => ({
            key: e.key,
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

export async function loadRecentFile(key: string): Promise<ArrayBuffer | null> {
  try {
    const db = await openDB();
    const entry = await new Promise<any>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readonly");
      const req = tx.objectStore(STORE_NAME).get(key);
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error);
    });
    return entry?.buffer ?? null;
  } catch {
    return null;
  }
}

export async function deleteRecentFile(key: string): Promise<void> {
  try {
    const db = await openDB();
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).delete(key);
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    });
  } catch {
    // non-fatal
  }
}
