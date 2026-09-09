/**
 * The IndexedDB-backed recent-files store.
 *
 * Every exported function wraps its body in `try {} catch {}` and degrades to a
 * neutral value, because storage can be missing (private browsing), refused
 * (disabled), or full (quota). That makes silent breakage the failure mode this
 * suite has to guard: each error path asserts BOTH that the call resolves and
 * that it resolved to the documented fallback, not merely that it didn't throw.
 *
 * The IndexedDB double lives in `./fakeIndexedDB`.
 */

import { afterEach, describe, expect, it, vi } from "vitest";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { ANNOTATION_KEY_PREFIX, annotationKey } from "../annotationKey";
import {
  deleteRecentFile,
  getRecentFiles,
  isLegacyRecentKey,
  legacyRecentKey,
  loadRecentFile,
  migrateV1Record,
  recentFileKey,
  saveRecentFile,
} from "../recentFiles";
import { createFakeIDB, type FakeIDB, type FakeIDBOptions } from "./fakeIndexedDB";

const MAX_ENTRIES = 5;
const MAX_SIZE = 50 * 1024 * 1024;

/** Install a fake `indexedDB` seeded with `records`. */
function withIDB(records: Record<string, unknown>[] = [], options: FakeIDBOptions = {}): FakeIDB {
  const fake = createFakeIDB(records, options);
  vi.stubGlobal("indexedDB", fake.indexedDB);
  return fake;
}

/**
 * A stored record as `saveRecentFile` writes them.
 *
 * **THE KEY IS THE NAME IN THIS HELPER, DELIBERATELY.** These suites are about
 * the size cap, eviction order and the error paths, none of which read the key
 * for anything but equality — the module treats it as opaque. Using the name
 * keeps every assertion below legible and unchanged across `peek-a-bin-mtry`.
 * The suites that are *about* the key being a build identity build their own
 * records; see "two builds of one binary" and "v1 → v2 migration" at the end.
 */
function record(name: string, lastOpened: number, size = 16) {
  return { key: name, name, size, lastOpened, buffer: new ArrayBuffer(size) };
}

/** `count` records, oldest first, named f0…fN. */
function records(count: number) {
  return Array.from({ length: count }, (_, i) => record(`f${i}`, 1000 + i));
}

afterEach(() => vi.unstubAllGlobals());

describe("saveRecentFile — size cap", () => {
  it("refuses a buffer over 50MB without opening the database at all", async () => {
    const fake = withIDB();
    await saveRecentFile("huge.exe", "huge.exe", new ArrayBuffer(MAX_SIZE + 1));

    expect(fake.openCount()).toBe(0);
    expect(fake.records.size).toBe(0);
  });

  it("accepts a buffer of exactly 50MB", async () => {
    const fake = withIDB();
    await saveRecentFile("edge.exe", "edge.exe", new ArrayBuffer(MAX_SIZE));

    expect(fake.records.has("edge.exe")).toBe(true);
  });

  it("accepts an empty buffer", async () => {
    const fake = withIDB();
    await saveRecentFile("empty.exe", "empty.exe", new ArrayBuffer(0));

    expect(fake.records.get("empty.exe")).toMatchObject({ name: "empty.exe", size: 0 });
  });
});

describe("saveRecentFile — what gets stored", () => {
  it("stores the name, buffer, byte length and a timestamp", async () => {
    vi.setSystemTime(new Date("2026-08-10T12:00:00Z"));
    const fake = withIDB();
    const buffer = new ArrayBuffer(1234);

    await saveRecentFile("sample.exe", "sample.exe", buffer);

    const stored = fake.records.get("sample.exe")!;
    expect(stored.name).toBe("sample.exe");
    expect(stored.buffer).toBe(buffer);
    expect(stored.size).toBe(1234);
    expect(stored.lastOpened).toBe(Date.parse("2026-08-10T12:00:00Z"));
    vi.useRealTimers();
  });

  it("overwrites the previous record for the same name", async () => {
    const fake = withIDB([record("sample.exe", 1)]);
    await saveRecentFile("sample.exe", "sample.exe", new ArrayBuffer(99));

    expect(fake.records.size).toBe(1);
    expect(fake.records.get("sample.exe")!.size).toBe(99);
  });
});

describe("saveRecentFile — eviction", () => {
  it("keeps the store at the cap by evicting the single oldest entry", async () => {
    const fake = withIDB(records(MAX_ENTRIES));
    await saveRecentFile("new.exe", "new.exe", new ArrayBuffer(8));

    expect(fake.deletes).toEqual(["f0"]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
    expect([...fake.records.keys()]).not.toContain("f0");
    expect(fake.records.has("new.exe")).toBe(true);
  });

  it("evicts nothing while there is room", async () => {
    const fake = withIDB(records(MAX_ENTRIES - 1));
    await saveRecentFile("new.exe", "new.exe", new ArrayBuffer(8));

    expect(fake.deletes).toEqual([]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
  });

  it("evicts nothing when re-saving a file already in a full store", async () => {
    // An update replaces a record rather than adding one, so the cap still holds.
    const fake = withIDB(records(MAX_ENTRIES));
    await saveRecentFile("f2", "f2", new ArrayBuffer(8));

    expect(fake.deletes).toEqual([]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
    expect(fake.records.has("f2")).toBe(true);
  });

  it("evicts by lastOpened, not by insertion order", async () => {
    const fake = withIDB([
      record("newest", 9000),
      record("oldest", 10),
      record("middle", 500),
      record("d", 6000),
      record("e", 7000),
    ]);
    await saveRecentFile("new.exe", "new.exe", new ArrayBuffer(8));

    expect(fake.deletes).toEqual(["oldest"]);
  });

  it("evicts several when the store starts over the cap", async () => {
    const fake = withIDB(records(MAX_ENTRIES + 3));
    await saveRecentFile("new.exe", "new.exe", new ArrayBuffer(8));

    // 8 stored + 1 new − 5 allowed = 4 evictions, oldest first.
    expect(fake.deletes).toEqual(["f0", "f1", "f2", "f3"]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
  });

  it("never deletes the entry it is about to write", async () => {
    // f0 is the oldest AND the file being saved: it must survive as an update.
    const fake = withIDB(records(MAX_ENTRIES));
    await saveRecentFile("f0", "f0", new ArrayBuffer(42));

    expect(fake.deletes).not.toContain("f0");
    expect(fake.records.get("f0")!.size).toBe(42);
  });

  it("leaves the store over the cap when updating the oldest of an oversized store", async () => {
    // Characterization of a real edge: `excess` counts the entry being updated,
    // but the loop skips it, so one eviction is silently forfeited. Self-heals
    // on the next save of a different file; only reachable if the store was
    // already over MAX_ENTRIES.
    const fake = withIDB(records(MAX_ENTRIES + 1));
    await saveRecentFile("f0", "f0", new ArrayBuffer(8));

    expect(fake.deletes).toEqual([]);
    expect(fake.records.size).toBe(MAX_ENTRIES + 1);
  });
});

describe("saveRecentFile — storage failures are non-fatal", () => {
  it("resolves when IndexedDB is missing entirely (private browsing)", async () => {
    vi.stubGlobal("indexedDB", undefined);
    await expect(saveRecentFile("a.exe", "a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
  });

  it("resolves when opening the database fails", async () => {
    const fake = withIDB([], { failOpen: true });
    await expect(saveRecentFile("a.exe", "a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
    expect(fake.records.size).toBe(0);
  });

  it("resolves when the existing-entries read fails, writing nothing", async () => {
    const fake = withIDB(records(2), { failGetAll: true });
    await expect(saveRecentFile("a.exe", "a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();

    // The eviction pass never ran, so the write was skipped rather than
    // performed against an unknown store state.
    expect(fake.puts).toEqual([]);
  });

  it("resolves when the write is refused by quota", async () => {
    const fake = withIDB(records(2), { failPut: true });
    await expect(saveRecentFile("a.exe", "a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
    expect(fake.records.has("a.exe")).toBe(false);
  });

  it("resolves when starting a transaction throws", async () => {
    withIDB([], { throwOnTransaction: true });
    await expect(saveRecentFile("a.exe", "a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
  });
});

describe("getRecentFiles", () => {
  it("returns entries newest first", async () => {
    withIDB([record("old", 100), record("newest", 900), record("mid", 500)]);

    expect((await getRecentFiles()).map((e) => e.name)).toEqual(["newest", "mid", "old"]);
  });

  it("returns at most 5 entries", async () => {
    withIDB(records(12));
    expect(await getRecentFiles()).toHaveLength(MAX_ENTRIES);
  });

  it("returns the 5 most recent, not the first 5 found", async () => {
    withIDB(records(12));
    expect((await getRecentFiles()).map((e) => e.name)).toEqual(["f11", "f10", "f9", "f8", "f7"]);
  });

  it("projects away the stored buffer", async () => {
    // The list view only needs metadata; carrying every buffer would mean
    // holding every recent file in memory at once.
    withIDB([record("a.exe", 1, 4096)]);
    const [entry] = await getRecentFiles();

    expect(entry).toEqual({ key: "a.exe", name: "a.exe", size: 4096, lastOpened: 1 });
    expect("buffer" in entry).toBe(false);
  });

  it("returns an empty list for an empty store", async () => {
    withIDB();
    expect(await getRecentFiles()).toEqual([]);
  });

  it("returns an empty list when IndexedDB is missing", async () => {
    vi.stubGlobal("indexedDB", undefined);
    expect(await getRecentFiles()).toEqual([]);
  });

  it("returns an empty list when opening fails", async () => {
    withIDB(records(3), { failOpen: true });
    expect(await getRecentFiles()).toEqual([]);
  });

  it("returns an empty list when the read fails", async () => {
    withIDB(records(3), { failGetAll: true });
    expect(await getRecentFiles()).toEqual([]);
  });

  it("returns an empty list when starting a transaction throws", async () => {
    withIDB(records(3), { throwOnTransaction: true });
    expect(await getRecentFiles()).toEqual([]);
  });

  it("passes through a record missing its metadata rather than dropping it", async () => {
    // Characterization: a record written by an older build (or hand-edited in
    // devtools) yields undefined fields instead of being filtered out. The UI
    // is what has to tolerate it.
    withIDB([{ key: "corrupt.exe", name: "corrupt.exe" }, record("good.exe", 500)]);
    const entries = await getRecentFiles();

    expect(entries.map((e) => e.name)).toContain("corrupt.exe");
    expect(entries.find((e) => e.name === "corrupt.exe")).toEqual({
      key: "corrupt.exe",
      name: "corrupt.exe",
      size: undefined,
      lastOpened: undefined,
    });
  });
});

describe("loadRecentFile", () => {
  it("returns the stored buffer", async () => {
    const buffer = new ArrayBuffer(64);
    withIDB([{ key: "a.exe", name: "a.exe", size: 64, lastOpened: 1, buffer }]);

    expect(await loadRecentFile("a.exe")).toBe(buffer);
  });

  it("returns null for a name that is not stored", async () => {
    withIDB([record("a.exe", 1)]);
    expect(await loadRecentFile("missing.exe")).toBeNull();
  });

  it("returns null for a record with no buffer", async () => {
    withIDB([{ key: "a.exe", name: "a.exe", size: 4, lastOpened: 1 }]);
    expect(await loadRecentFile("a.exe")).toBeNull();
  });

  it("is case- and whitespace-sensitive on the key", async () => {
    withIDB([record("Sample.exe", 1)]);
    expect(await loadRecentFile("sample.exe")).toBeNull();
    expect(await loadRecentFile("Sample.exe ")).toBeNull();
  });

  it("returns null when IndexedDB is missing", async () => {
    vi.stubGlobal("indexedDB", undefined);
    expect(await loadRecentFile("a.exe")).toBeNull();
  });

  it("returns null when opening fails", async () => {
    withIDB([record("a.exe", 1)], { failOpen: true });
    expect(await loadRecentFile("a.exe")).toBeNull();
  });

  it("returns null when the read fails", async () => {
    withIDB([record("a.exe", 1)], { failGet: true });
    expect(await loadRecentFile("a.exe")).toBeNull();
  });
});

describe("deleteRecentFile", () => {
  it("removes the named record and leaves the others", async () => {
    const fake = withIDB([record("a.exe", 1), record("b.exe", 2)]);
    await deleteRecentFile("a.exe");

    expect(fake.deletes).toEqual(["a.exe"]);
    expect([...fake.records.keys()]).toEqual(["b.exe"]);
  });

  it("resolves for a name that is not stored", async () => {
    const fake = withIDB([record("b.exe", 2)]);
    await expect(deleteRecentFile("missing.exe")).resolves.toBeUndefined();
    expect(fake.records.size).toBe(1);
  });

  it("resolves when IndexedDB is missing", async () => {
    vi.stubGlobal("indexedDB", undefined);
    await expect(deleteRecentFile("a.exe")).resolves.toBeUndefined();
  });

  it("resolves when opening fails, leaving the record in place", async () => {
    const fake = withIDB([record("a.exe", 1)], { failOpen: true });
    await expect(deleteRecentFile("a.exe")).resolves.toBeUndefined();
    expect(fake.records.has("a.exe")).toBe(true);
  });

  it("resolves when the delete itself fails", async () => {
    const fake = withIDB([record("a.exe", 1)], { failDelete: true });
    await expect(deleteRecentFile("a.exe")).resolves.toBeUndefined();
    expect(fake.records.has("a.exe")).toBe(true);
  });
});

describe("round trip", () => {
  it("saves, lists, loads and deletes through one store", async () => {
    withIDB();
    const buffer = new ArrayBuffer(32);

    await saveRecentFile("round.exe", "round.exe", buffer);
    expect((await getRecentFiles()).map((e) => e.name)).toEqual(["round.exe"]);
    expect(await loadRecentFile("round.exe")).toBe(buffer);

    await deleteRecentFile("round.exe");
    expect(await getRecentFiles()).toEqual([]);
    expect(await loadRecentFile("round.exe")).toBeNull();
  });

  it("keeps the newest 5 across a run of saves", async () => {
    withIDB();
    for (let i = 0; i < 8; i++) {
      vi.setSystemTime(new Date(2026, 0, 1, 0, 0, i));
      await saveRecentFile(`f${i}.exe`, `f${i}.exe`, new ArrayBuffer(8));
    }
    vi.useRealTimers();

    expect((await getRecentFiles()).map((e) => e.name)).toEqual([
      "f7.exe",
      "f6.exe",
      "f5.exe",
      "f4.exe",
      "f3.exe",
    ]);
  });
});

describe("the key is the BUILD, not the file name", () => {
  it("agrees with the annotation store's key, character for character", () => {
    // THE ONE-DECLARATION PROPERTY, asserted directly. If these two ever drift,
    // `FileLoader`'s join between a cached file and its bookmarks silently
    // misses and every row reads "no annotations" (peek-a-bin-mtry).
    const pe = parsePE(buildMinimalPE64({ timeDateStamp: 0x6512_3456 }));
    expect(`${ANNOTATION_KEY_PREFIX}${recentFileKey(pe)}`).toBe(annotationKey(pe));
  });

  it("gives two builds of one binary two different keys", () => {
    const v1 = parsePE(buildMinimalPE64({ timeDateStamp: 1 }));
    const v2 = parsePE(buildMinimalPE64({ timeDateStamp: 2 }));
    expect(recentFileKey(v1)).not.toBe(recentFileKey(v2));
  });

  it("keeps two same-named files of different sizes side by side", async () => {
    // THE DEFECT. Under `keyPath: "name"` the second `put` overwrote the first,
    // so opening v2/setup.exe silently threw away v1/setup.exe's cached bytes.
    const fake = withIDB();
    const oldBytes = new ArrayBuffer(2048);
    const newBytes = new ArrayBuffer(4096);

    await saveRecentFile("2048-00000001", "setup.exe", oldBytes);
    await saveRecentFile("4096-00000002", "setup.exe", newBytes);

    expect(fake.records.size).toBe(2);
    const listed = await getRecentFiles();
    expect(listed.map((e) => e.name)).toEqual(["setup.exe", "setup.exe"]);
    expect(listed.map((e) => e.size).sort((a, b) => a - b)).toEqual([2048, 4096]);
    // …and each row still loads ITS OWN bytes.
    expect(await loadRecentFile("2048-00000001")).toBe(oldBytes);
    expect(await loadRecentFile("4096-00000002")).toBe(newBytes);
  });

  it("still overwrites when the same build is opened twice", async () => {
    const fake = withIDB();
    await saveRecentFile("2048-00000001", "setup.exe", new ArrayBuffer(2048));
    await saveRecentFile("2048-00000001", "setup-renamed.exe", new ArrayBuffer(2048));

    expect(fake.records.size).toBe(1);
    // The NAME follows the file: the same build under a new name is one record.
    expect(fake.records.get("2048-00000001")!.name).toBe("setup-renamed.exe");
  });

  it("stores the name in the value now that it is not the key", async () => {
    const fake = withIDB();
    await saveRecentFile("100-0000000a", "shown.exe", new ArrayBuffer(100));
    expect(fake.records.get("100-0000000a")).toMatchObject({
      key: "100-0000000a",
      name: "shown.exe",
    });
  });
});

describe("legacyRecentKey / migrateV1Record — the v1 → v2 decision, pure", () => {
  it("prefixes the name and reports itself as legacy", () => {
    expect(legacyRecentKey("setup.exe")).toBe("name:setup.exe");
    expect(isLegacyRecentKey(legacyRecentKey("setup.exe"))).toBe(true);
  });

  it("can never collide with a real build key", () => {
    // A build key begins with `size`, which is a number, so it begins with a
    // digit; the legacy prefix begins with a letter.
    const pe = parsePE(buildMinimalPE64({ timeDateStamp: 7 }));
    expect(isLegacyRecentKey(recentFileKey(pe))).toBe(false);
    expect(recentFileKey(pe)).toMatch(/^\d/);
  });

  it("carries every field of a v1 record through untouched", () => {
    const buffer = new ArrayBuffer(8);
    expect(migrateV1Record({ name: "a.exe", size: 8, lastOpened: 99, buffer })).toEqual({
      key: "name:a.exe",
      name: "a.exe",
      size: 8,
      lastOpened: 99,
      buffer,
    });
  });

  it("refuses a record with no usable name rather than keying them all alike", () => {
    expect(migrateV1Record({ size: 8 })).toBeNull();
    expect(migrateV1Record({ name: "" })).toBeNull();
    expect(migrateV1Record({ name: 7 })).toBeNull();
    expect(migrateV1Record(null)).toBeNull();
    expect(migrateV1Record("a.exe")).toBeNull();
  });
});

describe("the v1 → v2 upgrade", () => {
  /** A v1 store: version 1, records keyed on `name`, no `key` property. */
  function withV1IDB(names: { name: string; size: number; lastOpened: number }[]) {
    const fake = createFakeIDB(
      names.map((n) => ({ ...n, buffer: new ArrayBuffer(n.size) })),
      { existingVersion: 1, seedKeyPath: "name" },
    );
    vi.stubGlobal("indexedDB", fake.indexedDB);
    return fake;
  }

  it("PRESERVES EVERY EXISTING RECORD across the version bump", async () => {
    // THE MIGRATION ROW. Skip the rewrite inside `onupgradeneeded` and this is
    // the one that reddens — `deleteObjectStore` drops the store's contents, so
    // all five cached files are gone and nothing else in the suite notices,
    // because every other row writes its own record first.
    const fake = withV1IDB([
      { name: "a.exe", size: 16, lastOpened: 100 },
      { name: "b.exe", size: 32, lastOpened: 200 },
      { name: "c.exe", size: 48, lastOpened: 300 },
      { name: "d.exe", size: 64, lastOpened: 400 },
      { name: "e.exe", size: 80, lastOpened: 500 },
    ]);

    const listed = await getRecentFiles();

    expect(listed).toHaveLength(5);
    expect(listed.map((e) => e.name)).toEqual(["e.exe", "d.exe", "c.exe", "b.exe", "a.exe"]);
    expect(listed.map((e) => e.size)).toEqual([80, 64, 48, 32, 16]);
    expect(listed.map((e) => e.key)).toEqual([
      "name:e.exe",
      "name:d.exe",
      "name:c.exe",
      "name:b.exe",
      "name:a.exe",
    ]);
    expect(fake.version()).toBe(2);
  });

  it("keeps the cached BYTES loadable, not just the metadata", async () => {
    withV1IDB([{ name: "a.exe", size: 16, lastOpened: 1 }]);
    const bytes = await loadRecentFile(legacyRecentKey("a.exe"));
    expect(bytes).toBeInstanceOf(ArrayBuffer);
    expect(bytes!.byteLength).toBe(16);
  });

  it("rekeys in place: the old name is no longer a key", async () => {
    const fake = withV1IDB([{ name: "a.exe", size: 16, lastOpened: 1 }]);
    await getRecentFiles();
    expect([...fake.records.keys()]).toEqual(["name:a.exe"]);
    expect(await loadRecentFile("a.exe")).toBeNull();
  });

  it("runs the upgrade once, not on every open", async () => {
    const fake = withV1IDB([{ name: "a.exe", size: 16, lastOpened: 1 }]);
    await getRecentFiles();
    await getRecentFiles();
    await loadRecentFile(legacyRecentKey("a.exe"));

    expect(fake.openCount()).toBe(3);
    expect(fake.records.size).toBe(1);
    expect(fake.version()).toBe(2);
  });

  it("lets a migrated record age out oldest-first like any other", async () => {
    // The whole justification for carrying v1 records under a name key rather
    // than re-parsing their bytes in the upgrade transaction: they are ordinary
    // records with an old timestamp, so they leave on their own.
    const fake = withV1IDB([
      { name: "a.exe", size: 16, lastOpened: 1 },
      { name: "b.exe", size: 16, lastOpened: 2 },
      { name: "c.exe", size: 16, lastOpened: 3 },
      { name: "d.exe", size: 16, lastOpened: 4 },
      { name: "e.exe", size: 16, lastOpened: 5 },
    ]);
    await saveRecentFile("999-00000001", "fresh.exe", new ArrayBuffer(8));

    expect(fake.deletes).toEqual([legacyRecentKey("a.exe")]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
    expect(fake.records.has("999-00000001")).toBe(true);
  });

  it("re-opening a migrated file adds a build-keyed record beside it", async () => {
    // Both rows are the same file; the stale one has the older timestamp and is
    // evicted first. Deleting the legacy row on a name match was refused — that
    // is precisely the name-keyed eviction this bead removed.
    const fake = withV1IDB([{ name: "setup.exe", size: 16, lastOpened: 1 }]);
    await saveRecentFile("16-00000001", "setup.exe", new ArrayBuffer(16));

    expect(fake.deletes).toEqual([]);
    expect([...fake.records.keys()].sort()).toEqual(["16-00000001", "name:setup.exe"]);
  });

  it("drops a v1 record with no name rather than aborting the whole upgrade", async () => {
    const fake = createFakeIDB([], { existingVersion: 1, seedKeyPath: "name" });
    fake.records.set("undefined", { size: 8, lastOpened: 1 });
    fake.records.set("good.exe", { name: "good.exe", size: 8, lastOpened: 2 });
    vi.stubGlobal("indexedDB", fake.indexedDB);

    expect((await getRecentFiles()).map((e) => e.key)).toEqual(["name:good.exe"]);
  });

  it("creates the store fresh at v2 on a profile that has never seen it", async () => {
    const fake = withIDB();
    await saveRecentFile("8-00000001", "a.exe", new ArrayBuffer(8));

    expect(fake.version()).toBe(2);
    expect([...fake.records.keys()]).toEqual(["8-00000001"]);
  });

  it("degrades to an empty list, never a half-migrated store, when the rewrite fails", async () => {
    // A throw inside `versionchange` aborts and rolls back. The user sees no
    // recents this session; nothing is silently half-rekeyed.
    const fake = createFakeIDB([{ name: "a.exe", size: 8, lastOpened: 1 }], {
      existingVersion: 1,
      seedKeyPath: "name",
      failPut: true,
    });
    vi.stubGlobal("indexedDB", fake.indexedDB);

    expect(await getRecentFiles()).toEqual([]);
  });
});
