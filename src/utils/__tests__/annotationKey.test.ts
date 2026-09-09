import { describe, expect, it, vi } from "vitest";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import {
  ANNOTATION_KEY_PREFIX,
  type AnnotationStoreIndex,
  annotationKey,
  annotationKeyFor,
  buildIdentityOf,
  legacyAnnotationKey,
  listAnnotationRecords,
  loadAnnotations,
  readStoredAnnotations,
  removeAnnotationsFor,
  saveAnnotations,
} from "../annotationKey";

/**
 * A `localStorage` stand-in.
 *
 * A Map rather than jsdom's real one, so this whole suite runs in the node
 * environment: the key rule and the migration decision are pure, and a jsdom
 * file costs ~2s of environment setup for nothing. `AnnotationStore` exists as
 * an interface precisely so this is possible.
 */
function fakeStore(initial: Record<string, string> = {}): AnnotationStoreIndex & {
  map: Map<string, string>;
} {
  const map = new Map(Object.entries(initial));
  return {
    map,
    get length() {
      return map.size;
    },
    key: (i: number) => [...map.keys()][i] ?? null,
    getItem: (k: string) => map.get(k) ?? null,
    setItem: (k: string, v: string) => {
      map.set(k, v);
    },
    removeItem: (k: string) => {
      map.delete(k);
    },
  };
}

const BOOKMARK = { bookmarks: [{ address: 0x140001000, label: "entry" }] };

describe("the annotation key names the BUILD, not the file", () => {
  it("derives from the size and the COFF timestamp of a real parsed image", () => {
    const buffer = buildMinimalPE64({ timeDateStamp: 0x5f3a2b1c });
    const pe = parsePE(buffer);
    const id = buildIdentityOf(pe);

    expect(id.size).toBe(buffer.byteLength);
    expect(id.timeDateStamp).toBe(0x5f3a2b1c);
    expect(id.pdbGuid).toBeUndefined();
    // The stamp is spelled as 8 lowercase hex, so every key has the same shape
    // whatever the value — and the size is decimal, matching `byteLength`.
    expect(annotationKey(pe)).toBe(`${ANNOTATION_KEY_PREFIX}${buffer.byteLength}-5f3a2b1c`);
  });

  it("gives two builds differing ONLY in the timestamp DIFFERENT keys", () => {
    // THE DEFECT THIS BEAD IS FOR, stated as an assertion: v1 and v2 of one
    // binary, same name, same size, and the old key was the name alone — so
    // v1's renames landed on v2's addresses and v2's first save destroyed v1's
    // record.
    const v1 = parsePE(buildMinimalPE64({ timeDateStamp: 1 }));
    const v2 = parsePE(buildMinimalPE64({ timeDateStamp: 2 }));

    expect(v1.buffer.byteLength).toBe(v2.buffer.byteLength);
    expect(annotationKey(v1)).not.toBe(annotationKey(v2));
  });

  it("gives ONE build under two names the SAME key — that is the design", () => {
    // The mirror half of the same defect, and the quieter one: renaming a file
    // on disk used to lose every annotation.
    const buffer = buildMinimalPE64({ timeDateStamp: 7 });
    // A key derived from the image cannot see a name at all, which is the
    // property. Both readings of the same bytes must agree.
    expect(annotationKey(parsePE(buffer))).toBe(annotationKey(parsePE(buffer.slice(0))));
  });

  it("prefers the CodeView PDB GUID where the image names one", () => {
    const guid = new Uint8Array([
      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
      0x10,
    ]);
    const withPdb = parsePE(
      buildMinimalPE64({
        timeDateStamp: 3,
        directories: { debug: [{ type: 2, codeView: { guid, age: 4, pdbPath: "setup.pdb" } }] },
      }),
    );

    const id = buildIdentityOf(withPdb);
    // The GUID's own spelling is `parseDebugDirectory`'s (uppercase, dashed,
    // first three groups byte-swapped as the format requires — peek-a-bin-p0qw).
    // This suite does not restate that rule; it asserts the key carries it.
    expect(id.pdbGuid).toBe("04030201-0605-0807-090A-0B0C0D0E0F10");
    expect(annotationKey(withPdb)).toBe(
      `${ANNOTATION_KEY_PREFIX}${withPdb.buffer.byteLength}-00000003-04030201-0605-0807-090A-0B0C0D0E0F10`,
    );
  });

  it("appends the GUID rather than substituting it, so a key can only ever split", () => {
    // Appending can never merge two identities; substituting could, and a merge
    // is the direction that loses work. Same size, same stamp, one with a debug
    // directory and one without: two keys, and the stripped one is a PREFIX of
    // the other rather than an unrelated string.
    const bare = annotationKeyFor({ size: 100, timeDateStamp: 9 });
    const withGuid = annotationKeyFor({ size: 100, timeDateStamp: 9, pdbGuid: "ABC" });
    expect(withGuid).not.toBe(bare);
    expect(withGuid.startsWith(bare)).toBe(true);
  });

  it("cannot collide with a settings key, even for a file NAMED like one", () => {
    // The flat-namespace half of the defect: annotations were stored at
    // `peek-a-bin:${fileName}`, in the same namespace as ~18 settings keys, so a
    // file named `font-size` wrote its bookmarks over a setting.
    const pe = parsePE(buildMinimalPE32({ timeDateStamp: 0x11 }));
    for (const setting of [
      "font-size",
      "view-mode",
      "sidebar-width",
      "theme-id",
      "llm-profiles",
      "chat-width",
    ]) {
      expect(annotationKey(pe)).not.toBe(`peek-a-bin:${setting}`);
      // And the legacy spelling DID collide, which is what makes the row above
      // a statement about a fix rather than about an arbitrary string.
      expect(legacyAnnotationKey(setting)).toBe(`peek-a-bin:${setting}`);
    }
  });

  it("spells a timestamp with the high bit set as unsigned", () => {
    // `>>> 0` rather than the signed reading `getInt32`-shaped code produces —
    // the `parseRichHeader` class. A stamp of 0xFFFFFFFF must not key as `-1`.
    expect(annotationKeyFor({ size: 4, timeDateStamp: 0xffffffff })).toBe(
      `${ANNOTATION_KEY_PREFIX}4-ffffffff`,
    );
  });
});

describe("readStoredAnnotations — the migration decision, pure", () => {
  it("adopts a legacy bare-name blob when the current key is absent", () => {
    const read = readStoredAnnotations(null, JSON.stringify(BOOKMARK));
    expect(read?.source).toBe("legacy");
    expect(read?.payload.bookmarks).toEqual([{ address: 0x140001000, label: "entry" }]);
  });

  it("does NOT adopt the legacy blob when the current key already validates", () => {
    const read = readStoredAnnotations(
      JSON.stringify({ bookmarks: [{ address: 1, label: "current" }] }),
      JSON.stringify(BOOKMARK),
    );
    expect(read?.source).toBe("current");
    expect(read?.payload.bookmarks).toEqual([{ address: 1, label: "current" }]);
  });

  it("does NOT re-adopt the legacy blob when the current record is valid but EMPTY", () => {
    // The case that decides whether the trigger is "absent" or "absent or
    // malformed": the persist effect writes an empty record the instant a file
    // opens, so every second load of a migrated file sees exactly this. Adopting
    // legacy here would resurrect annotations the user had deleted.
    const read = readStoredAnnotations(
      JSON.stringify({ bookmarks: [], renames: {}, comments: {} }),
      JSON.stringify(BOOKMARK),
    );
    expect(read?.source).toBe("current");
    expect(read?.payload.bookmarks).toEqual([]);
  });

  it("falls back to legacy when the current record is present but malformed", () => {
    expect(readStoredAnnotations("{not json", JSON.stringify(BOOKMARK))?.source).toBe("legacy");
    expect(
      readStoredAnnotations(JSON.stringify({ bookmarks: 3 }), JSON.stringify(BOOKMARK))?.source,
    ).toBe("legacy");
  });

  it("returns null when neither key holds anything applicable", () => {
    expect(readStoredAnnotations(null, null)).toBeNull();
    expect(readStoredAnnotations("{not json", "also not json")).toBeNull();
    // Malformed is collapsed to "nothing", because both mean the same thing to
    // the reducer: apply none of it rather than part of it.
    expect(readStoredAnnotations(JSON.stringify({ renames: [1, 2] }), null)).toBeNull();
  });
});

describe("loadAnnotations — the migration, and what it must not touch", () => {
  const key = annotationKeyFor({ size: 512, timeDateStamp: 0x2a });

  it("writes a legacy blob forward under the build key", () => {
    const store = fakeStore({ "peek-a-bin:setup.exe": JSON.stringify(BOOKMARK) });
    const read = loadAnnotations(store, key, "setup.exe");

    expect(read?.source).toBe("legacy");
    const written = JSON.parse(store.getItem(key) as string);
    expect(written.bookmarks).toEqual([{ address: 0x140001000, label: "entry" }]);
    // The name goes into the VALUE, because the recents list has to read it back
    // out once the key is not the name.
    expect(written.fileName).toBe("setup.exe");
  });

  it("LEAVES THE LEGACY KEY IN PLACE — non-destructive, deliberately", () => {
    const legacy = JSON.stringify(BOOKMARK);
    const store = fakeStore({ "peek-a-bin:setup.exe": legacy });
    loadAnnotations(store, key, "setup.exe");
    // A user who reverts to an older build of the tool must still find their
    // work, and a prefix-scanning deleter on the LOAD path is the foot-gun this
    // repo already refuses for `peek-a-bin:report:`.
    expect(store.getItem("peek-a-bin:setup.exe")).toBe(legacy);
  });

  it("does not fire when the build key already holds a record", () => {
    const store = fakeStore({
      [key]: JSON.stringify({ fileName: "setup.exe", bookmarks: [{ address: 1, label: "kept" }] }),
      "peek-a-bin:setup.exe": JSON.stringify(BOOKMARK),
    });
    const read = loadAnnotations(store, key, "setup.exe");

    expect(read?.source).toBe("current");
    // And the current record is untouched: a migration that overwrote it would
    // be the original defect with a new key.
    expect(JSON.parse(store.getItem(key) as string).bookmarks).toEqual([
      { address: 1, label: "kept" },
    ]);
  });

  it("stores nothing at all when there is nothing to adopt", () => {
    const store = fakeStore();
    expect(loadAnnotations(store, key, "setup.exe")).toBeNull();
    expect(store.map.size).toBe(0);
  });

  it("two same-named builds keep separate records through one store", () => {
    // The whole bead, end to end over the store: v1 saves, v2 opens and saves,
    // v1's record is still there and still says what it said.
    const store = fakeStore();
    const k1 = annotationKeyFor({ size: 4096, timeDateStamp: 1 });
    const k2 = annotationKeyFor({ size: 4096, timeDateStamp: 2 });

    saveAnnotations(store, k1, {
      fileName: "setup.exe",
      bookmarks: [{ address: 0x1000, label: "v1 only" }],
      renames: {},
      comments: {},
    });
    saveAnnotations(store, k2, {
      fileName: "setup.exe",
      bookmarks: [],
      renames: {},
      comments: {},
    });

    expect(loadAnnotations(store, k1, "setup.exe")?.payload.bookmarks).toEqual([
      { address: 0x1000, label: "v1 only" },
    ]);
    expect(loadAnnotations(store, k2, "setup.exe")?.payload.bookmarks).toEqual([]);
  });
});

describe("listAnnotationRecords — the prefix scan that replaced a deny-list", () => {
  it("reads records by prefix and takes the name out of the value", () => {
    const store = fakeStore({
      [annotationKeyFor({ size: 1, timeDateStamp: 1 })]: JSON.stringify({
        fileName: "a.exe",
        bookmarks: [{ address: 1, label: "x" }],
        renames: { 2: "f" },
        comments: {},
      }),
    });
    expect(listAnnotationRecords(store)).toEqual([
      {
        key: annotationKeyFor({ size: 1, timeDateStamp: 1 }),
        fileName: "a.exe",
        bookmarks: 1,
        renames: 1,
        comments: 0,
      },
    ]);
  });

  it("skips every settings key in the namespace, including the four the old deny-list named", () => {
    // The deny-list was `sidebar-width`, `sections-open`, `graph-overview-open`,
    // `callers-open` — four names against a namespace of about eighteen. The
    // prefix answers for all of them, and for a file NAMED like one.
    const store = fakeStore({
      "peek-a-bin:sidebar-width": "240",
      "peek-a-bin:sections-open": "true",
      "peek-a-bin:graph-overview-open": "false",
      "peek-a-bin:callers-open": "true",
      "peek-a-bin:font-size": "13",
      "peek-a-bin:theme-id": "dark",
      "peek-a-bin:llm-profiles": JSON.stringify({ profiles: [] }),
      "peek-a-bin:chat:setup.exe": JSON.stringify([{ role: "user" }]),
      // A LEGACY annotation blob is also skipped: the scan is the new namespace
      // only, which is what leaves the legacy keys orphaned rather than listed.
      "peek-a-bin:setup.exe": JSON.stringify(BOOKMARK),
    });
    expect(listAnnotationRecords(store)).toEqual([]);
  });

  it("drops a record whose blob does not validate", () => {
    const store = fakeStore({
      [`${ANNOTATION_KEY_PREFIX}1-00000001`]: "{not json",
      [`${ANNOTATION_KEY_PREFIX}2-00000002`]: JSON.stringify({ bookmarks: "nope" }),
    });
    expect(listAnnotationRecords(store)).toEqual([]);
  });

  it("reports a nameless record with a null name rather than dropping it", () => {
    // A record written by a build of the tool between the key change and this
    // one, or hand-edited. It is a real record; it just has no name to show.
    const store = fakeStore({
      [`${ANNOTATION_KEY_PREFIX}3-00000003`]: JSON.stringify(BOOKMARK),
    });
    expect(listAnnotationRecords(store)[0].fileName).toBeNull();
  });
});

describe("removeAnnotationsFor — the one place deleting is right", () => {
  it("removes every record saved under one name, plus that name's legacy key", () => {
    const k1 = annotationKeyFor({ size: 10, timeDateStamp: 1 });
    const k2 = annotationKeyFor({ size: 10, timeDateStamp: 2 });
    const other = annotationKeyFor({ size: 20, timeDateStamp: 1 });
    const store = fakeStore({
      [k1]: JSON.stringify({ fileName: "setup.exe", ...BOOKMARK }),
      [k2]: JSON.stringify({ fileName: "setup.exe", ...BOOKMARK }),
      [other]: JSON.stringify({ fileName: "keep.exe", ...BOOKMARK }),
      "peek-a-bin:setup.exe": JSON.stringify(BOOKMARK),
      "peek-a-bin:font-size": "13",
    });

    removeAnnotationsFor(store, "setup.exe");

    expect(store.getItem(k1)).toBeNull();
    expect(store.getItem(k2)).toBeNull();
    expect(store.getItem("peek-a-bin:setup.exe")).toBeNull();
    // Another build's record and an unrelated setting are untouched — the
    // removal is targeted, never a prefix sweep.
    expect(store.getItem(other)).not.toBeNull();
    expect(store.getItem("peek-a-bin:font-size")).toBe("13");
  });
});

describe("a stored blob that is not applicable is REPORTED, not silently dropped", () => {
  const key = annotationKeyFor({ size: 8, timeDateStamp: 5 });

  it("warns when something was stored and none of it could be used", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(loadAnnotations(fakeStore({ [key]: "{not json" }), key, "setup.exe")).toBeNull();
    expect(warn).toHaveBeenCalledWith("[peek-a-bin] ignoring malformed persisted annotations");
    warn.mockRestore();
  });

  it("says nothing when nothing was stored — the liveness half", () => {
    // "Nothing stored" and "stored and unusable" are different facts and the
    // caller sees one null for both, which is why the report lives here.
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    expect(loadAnnotations(fakeStore(), key, "setup.exe")).toBeNull();
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });

  it("says nothing when a malformed current record was rescued by the legacy one", () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const store = fakeStore({
      [key]: "{not json",
      "peek-a-bin:setup.exe": JSON.stringify(BOOKMARK),
    });
    expect(loadAnnotations(store, key, "setup.exe")?.source).toBe("legacy");
    expect(warn).not.toHaveBeenCalled();
    warn.mockRestore();
  });
});
