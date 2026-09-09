/**
 * A minimal in-memory IndexedDB double.
 *
 * `fake-indexeddb` is not a dependency of this project and pulling one in for a
 * 113-line module was not worth it, so this implements exactly the surface
 * `src/utils/recentFiles.ts` touches: open/upgradeneeded, a keyPath object
 * store, and getAll/get/put/delete inside a transaction.
 *
 * Two properties matter for the tests to mean anything:
 *
 * - **Async like the real thing.** Request callbacks fire in a later microtask,
 *   never synchronously, so code that attaches `onsuccess` after issuing the
 *   request still sees it — the ordering real IndexedDB guarantees.
 * - **`oncomplete` after the last request.** A transaction settles only once
 *   every request it issued has run, and reports `onerror` instead if any of
 *   them failed. That is what lets the quota/abort tests exercise the real
 *   rejection path rather than a shortcut.
 */

type Listener = (() => void) | null;

/** Failure injection — each flag models one way IndexedDB says no. */
export interface FakeIDBOptions {
  /** `indexedDB.open()` errors: DB blocked, or storage disabled. */
  failOpen?: boolean;
  /** A `getAll()` request errors. */
  failGetAll?: boolean;
  /** A `get()` request errors. */
  failGet?: boolean;
  /** A `put()` request errors — how QuotaExceededError arrives. */
  failPut?: boolean;
  /** A `delete()` request errors. */
  failDelete?: boolean;
  /** `db.transaction()` itself throws, as it does on a closing connection. */
  throwOnTransaction?: boolean;
  /**
   * The version the persisted database is ALREADY at, 0 for a fresh profile.
   *
   * Set it to 1 to model a browser that last saw the pre-`peek-a-bin-mtry`
   * store, which is what makes the `onupgradeneeded` migration reachable at
   * all — the whole point of the control on it.
   */
  existingVersion?: number;
  /** The keyPath the seeded records are stored under. Defaults to `"key"`. */
  seedKeyPath?: string;
}

class FakeRequest {
  onsuccess: Listener = null;
  onerror: Listener = null;
  /**
   * Only ever set on an open request, and it takes the event — `oldVersion` is
   * how a handler tells "create the store" from "migrate the store".
   */
  onupgradeneeded: ((event: { oldVersion: number; newVersion: number }) => void) | null = null;
  /** The `versionchange` transaction, readable only during an upgrade. */
  transaction: FakeTransaction | null = null;
  result: unknown = undefined;
  error: Error | null = null;
}

class FakeTransaction {
  oncomplete: Listener = null;
  onerror: Listener = null;
  error: Error | null = null;
  outstanding = 0;
  private failed = false;

  constructor(private readonly db: FakeDatabase) {}

  objectStore(_name: string): FakeObjectStore {
    return new FakeObjectStore(this, this.db);
  }

  /** Run `work` in a later microtask, then settle the transaction. */
  run(work: (req: FakeRequest) => void): FakeRequest {
    const req = new FakeRequest();
    this.outstanding++;
    queueMicrotask(() => {
      try {
        work(req);
        req.onsuccess?.();
      } catch (err) {
        req.error = err as Error;
        this.error = err as Error;
        this.failed = true;
        req.onerror?.();
      }
      this.outstanding--;
      if (this.outstanding === 0) {
        // One more turn so the caller's `tx.oncomplete = …` is in place.
        queueMicrotask(() => {
          if (this.failed) this.onerror?.();
          else this.oncomplete?.();
        });
      }
    });
    return req;
  }
}

class FakeObjectStore {
  constructor(
    private readonly tx: FakeTransaction,
    private readonly db: FakeDatabase,
  ) {}

  getAll(): FakeRequest {
    return this.tx.run((req) => {
      if (this.db.options.failGetAll) throw new Error("getAll failed");
      req.result = [...this.db.records.values()];
    });
  }

  get(key: string): FakeRequest {
    return this.tx.run((req) => {
      if (this.db.options.failGet) throw new Error("get failed");
      req.result = this.db.records.get(key);
    });
  }

  put(value: Record<string, unknown>): FakeRequest {
    return this.tx.run(() => {
      if (this.db.options.failPut) throw new Error("QuotaExceededError");
      // Real IndexedDB throws DataError when the keyPath does not evaluate to a
      // key, so a record the migration failed to give a key must not land here.
      if (value[this.db.keyPath] === undefined) throw new Error("DataError");
      this.db.records.set(String(value[this.db.keyPath]), value);
      this.db.puts.push(value);
    });
  }

  delete(key: string): FakeRequest {
    return this.tx.run(() => {
      if (this.db.options.failDelete) throw new Error("delete failed");
      this.db.records.delete(key);
      this.db.deletes.push(key);
    });
  }
}

class FakeDatabase {
  keyPath = "";
  readonly objectStoreNames = {
    contains: (name: string) => this.storeNames.has(name),
  };
  private storeNames = new Set<string>();

  constructor(
    readonly records: Map<string, Record<string, unknown>>,
    readonly options: FakeIDBOptions,
    readonly puts: Record<string, unknown>[],
    readonly deletes: string[],
  ) {}

  version = 0;

  createObjectStore(name: string, opts: { keyPath: string }) {
    this.storeNames.add(name);
    this.keyPath = opts.keyPath;
    return new FakeObjectStore(this.upgradeTx as FakeTransaction, this);
  }

  /**
   * Drops the store AND everything in it, as the real call does — which is what
   * makes "the upgrade forgot to write the records back" a data loss the
   * migration control can actually observe.
   */
  deleteObjectStore(name: string) {
    this.storeNames.delete(name);
    this.records.clear();
  }

  /** The in-flight `versionchange` transaction, so a store created inside it
   * issues its requests against it. */
  upgradeTx: FakeTransaction | null = null;

  transaction(_store: string, _mode?: string): FakeTransaction {
    if (this.options.throwOnTransaction) throw new Error("InvalidStateError");
    return new FakeTransaction(this);
  }
}

export interface FakeIDB {
  /** The `indexedDB` global stand-in. */
  indexedDB: { open(name: string, version: number): FakeRequest };
  /** Stored records, keyed by the store's current keyPath. */
  records: Map<string, Record<string, unknown>>;
  /** Names passed to `store.delete()`, in order — the eviction trail. */
  deletes: string[];
  /** Values passed to `store.put()`, in order. */
  puts: Record<string, unknown>[];
  /** How many times `indexedDB.open()` was called. */
  openCount: () => number;
  /** The version the persisted database is at. */
  version: () => number;
}

/**
 * Build a fake `indexedDB` pre-populated with `seed` records.
 *
 * The store is created on first open (mirroring `onupgradeneeded`), so
 * `createObjectStore` runs exactly as it does against a fresh browser profile.
 */
export function createFakeIDB(
  seed: Record<string, unknown>[] = [],
  options: FakeIDBOptions = {},
): FakeIDB {
  const records = new Map<string, Record<string, unknown>>();
  const deletes: string[] = [];
  const puts: Record<string, unknown>[] = [];
  let opens = 0;

  const db = new FakeDatabase(records, options, puts, deletes);
  let version = options.existingVersion ?? 0;
  if (version > 0) {
    // A database this browser has already seen: the store exists, under the
    // keyPath that version of the code created it with.
    db.createObjectStore("files", { keyPath: options.seedKeyPath ?? "key" });
    db.version = version;
  } else {
    db.keyPath = options.seedKeyPath ?? "key";
  }
  for (const record of seed) records.set(String(record[db.keyPath]), record);

  const indexedDB = {
    open(_name: string, requested: number): FakeRequest {
      opens++;
      const req = new FakeRequest();
      // `req.result` is readable from onupgradeneeded, as real IDB allows.
      req.result = db;
      queueMicrotask(() => {
        if (options.failOpen) {
          req.error = new Error("open failed");
          req.onerror?.();
          return;
        }
        if (version >= requested) {
          req.onsuccess?.();
          return;
        }
        const oldVersion = version;
        version = requested;
        db.version = requested;
        const tx = new FakeTransaction(db);
        db.upgradeTx = tx;
        req.transaction = tx;
        try {
          req.onupgradeneeded?.({ oldVersion, newVersion: requested });
        } catch (err) {
          req.error = err as Error;
          req.transaction = null;
          db.upgradeTx = null;
          req.onerror?.();
          return;
        }
        // `onsuccess` fires only once the versionchange transaction settles. A
        // handler that issued no requests has already settled.
        if (tx.outstanding === 0) {
          req.transaction = null;
          db.upgradeTx = null;
          req.onsuccess?.();
          return;
        }
        tx.oncomplete = () => {
          req.transaction = null;
          db.upgradeTx = null;
          req.onsuccess?.();
        };
        tx.onerror = () => {
          req.error = tx.error;
          req.transaction = null;
          db.upgradeTx = null;
          req.onerror?.();
        };
      });
      return req;
    },
  };

  return { indexedDB, records, deletes, puts, openCount: () => opens, version: () => version };
}
