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
import { deleteRecentFile, getRecentFiles, loadRecentFile, saveRecentFile } from "../recentFiles";
import { createFakeIDB, type FakeIDB, type FakeIDBOptions } from "./fakeIndexedDB";

const MAX_ENTRIES = 5;
const MAX_SIZE = 50 * 1024 * 1024;

/** Install a fake `indexedDB` seeded with `records`. */
function withIDB(records: Record<string, unknown>[] = [], options: FakeIDBOptions = {}): FakeIDB {
  const fake = createFakeIDB(records, options);
  vi.stubGlobal("indexedDB", fake.indexedDB);
  return fake;
}

/** A stored record as `saveRecentFile` writes them. */
function record(name: string, lastOpened: number, size = 16) {
  return { name, size, lastOpened, buffer: new ArrayBuffer(size) };
}

/** `count` records, oldest first, named f0…fN. */
function records(count: number) {
  return Array.from({ length: count }, (_, i) => record(`f${i}`, 1000 + i));
}

afterEach(() => vi.unstubAllGlobals());

describe("saveRecentFile — size cap", () => {
  it("refuses a buffer over 50MB without opening the database at all", async () => {
    const fake = withIDB();
    await saveRecentFile("huge.exe", new ArrayBuffer(MAX_SIZE + 1));

    expect(fake.openCount()).toBe(0);
    expect(fake.records.size).toBe(0);
  });

  it("accepts a buffer of exactly 50MB", async () => {
    const fake = withIDB();
    await saveRecentFile("edge.exe", new ArrayBuffer(MAX_SIZE));

    expect(fake.records.has("edge.exe")).toBe(true);
  });

  it("accepts an empty buffer", async () => {
    const fake = withIDB();
    await saveRecentFile("empty.exe", new ArrayBuffer(0));

    expect(fake.records.get("empty.exe")).toMatchObject({ name: "empty.exe", size: 0 });
  });
});

describe("saveRecentFile — what gets stored", () => {
  it("stores the name, buffer, byte length and a timestamp", async () => {
    vi.setSystemTime(new Date("2026-08-10T12:00:00Z"));
    const fake = withIDB();
    const buffer = new ArrayBuffer(1234);

    await saveRecentFile("sample.exe", buffer);

    const stored = fake.records.get("sample.exe")!;
    expect(stored.name).toBe("sample.exe");
    expect(stored.buffer).toBe(buffer);
    expect(stored.size).toBe(1234);
    expect(stored.lastOpened).toBe(Date.parse("2026-08-10T12:00:00Z"));
    vi.useRealTimers();
  });

  it("overwrites the previous record for the same name", async () => {
    const fake = withIDB([record("sample.exe", 1)]);
    await saveRecentFile("sample.exe", new ArrayBuffer(99));

    expect(fake.records.size).toBe(1);
    expect(fake.records.get("sample.exe")!.size).toBe(99);
  });
});

describe("saveRecentFile — eviction", () => {
  it("keeps the store at the cap by evicting the single oldest entry", async () => {
    const fake = withIDB(records(MAX_ENTRIES));
    await saveRecentFile("new.exe", new ArrayBuffer(8));

    expect(fake.deletes).toEqual(["f0"]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
    expect([...fake.records.keys()]).not.toContain("f0");
    expect(fake.records.has("new.exe")).toBe(true);
  });

  it("evicts nothing while there is room", async () => {
    const fake = withIDB(records(MAX_ENTRIES - 1));
    await saveRecentFile("new.exe", new ArrayBuffer(8));

    expect(fake.deletes).toEqual([]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
  });

  it("evicts nothing when re-saving a file already in a full store", async () => {
    // An update replaces a record rather than adding one, so the cap still holds.
    const fake = withIDB(records(MAX_ENTRIES));
    await saveRecentFile("f2", new ArrayBuffer(8));

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
    await saveRecentFile("new.exe", new ArrayBuffer(8));

    expect(fake.deletes).toEqual(["oldest"]);
  });

  it("evicts several when the store starts over the cap", async () => {
    const fake = withIDB(records(MAX_ENTRIES + 3));
    await saveRecentFile("new.exe", new ArrayBuffer(8));

    // 8 stored + 1 new − 5 allowed = 4 evictions, oldest first.
    expect(fake.deletes).toEqual(["f0", "f1", "f2", "f3"]);
    expect(fake.records.size).toBe(MAX_ENTRIES);
  });

  it("never deletes the entry it is about to write", async () => {
    // f0 is the oldest AND the file being saved: it must survive as an update.
    const fake = withIDB(records(MAX_ENTRIES));
    await saveRecentFile("f0", new ArrayBuffer(42));

    expect(fake.deletes).not.toContain("f0");
    expect(fake.records.get("f0")!.size).toBe(42);
  });

  it("leaves the store over the cap when updating the oldest of an oversized store", async () => {
    // Characterization of a real edge: `excess` counts the entry being updated,
    // but the loop skips it, so one eviction is silently forfeited. Self-heals
    // on the next save of a different file; only reachable if the store was
    // already over MAX_ENTRIES.
    const fake = withIDB(records(MAX_ENTRIES + 1));
    await saveRecentFile("f0", new ArrayBuffer(8));

    expect(fake.deletes).toEqual([]);
    expect(fake.records.size).toBe(MAX_ENTRIES + 1);
  });
});

describe("saveRecentFile — storage failures are non-fatal", () => {
  it("resolves when IndexedDB is missing entirely (private browsing)", async () => {
    vi.stubGlobal("indexedDB", undefined);
    await expect(saveRecentFile("a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
  });

  it("resolves when opening the database fails", async () => {
    const fake = withIDB([], { failOpen: true });
    await expect(saveRecentFile("a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
    expect(fake.records.size).toBe(0);
  });

  it("resolves when the existing-entries read fails, writing nothing", async () => {
    const fake = withIDB(records(2), { failGetAll: true });
    await expect(saveRecentFile("a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();

    // The eviction pass never ran, so the write was skipped rather than
    // performed against an unknown store state.
    expect(fake.puts).toEqual([]);
  });

  it("resolves when the write is refused by quota", async () => {
    const fake = withIDB(records(2), { failPut: true });
    await expect(saveRecentFile("a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
    expect(fake.records.has("a.exe")).toBe(false);
  });

  it("resolves when starting a transaction throws", async () => {
    withIDB([], { throwOnTransaction: true });
    await expect(saveRecentFile("a.exe", new ArrayBuffer(8))).resolves.toBeUndefined();
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

    expect(entry).toEqual({ name: "a.exe", size: 4096, lastOpened: 1 });
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
    withIDB([{ name: "corrupt.exe" }, record("good.exe", 500)]);
    const entries = await getRecentFiles();

    expect(entries.map((e) => e.name)).toContain("corrupt.exe");
    expect(entries.find((e) => e.name === "corrupt.exe")).toEqual({
      name: "corrupt.exe",
      size: undefined,
      lastOpened: undefined,
    });
  });
});

describe("loadRecentFile", () => {
  it("returns the stored buffer", async () => {
    const buffer = new ArrayBuffer(64);
    withIDB([{ name: "a.exe", size: 64, lastOpened: 1, buffer }]);

    expect(await loadRecentFile("a.exe")).toBe(buffer);
  });

  it("returns null for a name that is not stored", async () => {
    withIDB([record("a.exe", 1)]);
    expect(await loadRecentFile("missing.exe")).toBeNull();
  });

  it("returns null for a record with no buffer", async () => {
    withIDB([{ name: "a.exe", size: 4, lastOpened: 1 }]);
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

    await saveRecentFile("round.exe", buffer);
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
      await saveRecentFile(`f${i}.exe`, new ArrayBuffer(8));
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
