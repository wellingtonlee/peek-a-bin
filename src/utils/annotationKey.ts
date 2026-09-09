import { parseDebugDirectory } from "../pe/metadata";
import type { PEFile } from "../pe/types";
import { type AnnotationPayload, validateAnnotations } from "./exportSchema";

/**
 * The namespace every annotation record lives under.
 *
 * **A PREFIX, and that is half of what this module buys.** Annotations used to
 * be stored at `peek-a-bin:${fileName}` — the bare file name — inside the same
 * flat `peek-a-bin:` namespace as ~18 real settings keys (`sidebar-width`,
 * `font-size`, `view-mode`, `theme-id`, `llm-profiles`, …). So a file *named*
 * `font-size` wrote its bookmarks over a setting, and `FileLoader`'s
 * recents scan had to carry a hand-written deny-list of settings keys to tell
 * the two apart — a list of four against a population of eighteen. With a
 * prefix of its own, "is this key an annotation record" is a prefix test and
 * the deny-list is gone.
 */
export const ANNOTATION_KEY_PREFIX = "peek-a-bin:annotations:";

/**
 * The legacy key an annotation record was written under before this module.
 *
 * Kept as an exported function rather than inlined because it is read in
 * exactly two places — the migration below, and `FileLoader`'s per-name
 * removal — and a second spelling of it would be a second declaration of what
 * "the old key" means.
 */
export function legacyAnnotationKey(fileName: string): string {
  return `peek-a-bin:${fileName}`;
}

/**
 * What the annotation store is keyed on: the BUILD, never the file name.
 *
 * **THE DEFECT THIS EXISTS FOR.** Dropping `v1/setup.exe`, renaming forty
 * functions, then dropping `v2/setup.exe` used to hand v1's renames to v2's
 * *addresses* — and the first save under v2 then overwrote v1's record
 * permanently. Comparing two builds of one binary is the most ordinary
 * reverse-engineering workflow there is, and it was the one case in this app
 * where a user silently lost work. The mirror case is as bad and quieter: the
 * same build renamed on disk (`setup.exe` → `setup_v1.exe`) lost every
 * annotation, because the key had moved.
 *
 * Both fields are on the parsed object *synchronously*, which is the whole
 * reason this shape was chosen — see {@link annotationKeyFor}.
 */
export interface BuildIdentity {
  /** `buffer.byteLength` — the image's size on disk. */
  size: number;
  /** `coffHeader.timeDateStamp`, as stored (a `uint32`). */
  timeDateStamp: number;
  /**
   * The CodeView PDB GUID, when the image carries a debug directory naming one.
   *
   * Absent from a stripped build, which is why it can only ever be an
   * *additional* discriminator — see {@link annotationKeyFor}.
   */
  pdbGuid?: string;
}

/**
 * The stored record. `AnnotationPayload` plus the file name it was last seen
 * under.
 *
 * **`fileName` IS NOT PART OF THE IDENTITY AND IS STORED ANYWAY**, because once
 * the key is not the name, the name has to come back *out* of the value: the
 * recents list on the loader screen is a list of file names, and it now finds
 * annotation records by scanning the prefix rather than by guessing a key from
 * a name. It is display data — a record whose `fileName` disagrees with the
 * file currently open is not a mismatch, it is the same build under a new name,
 * which is precisely the case this module exists to keep working.
 */
export interface AnnotationRecord extends AnnotationPayload {
  fileName?: string;
}

/**
 * The key for one build's annotations.
 *
 * FORMAT: `peek-a-bin:annotations:<size>-<timeDateStamp, 8 lowercase hex>` and,
 * where the image names a CodeView GUID, `-<GUID>` appended. The key is only
 * ever *compared*, never parsed back, so the GUID's own dashes are harmless.
 *
 * **WHY THESE FIELDS: THEY ARE AVAILABLE SYNCHRONOUSLY.** A content hash is the
 * obviously stronger identity and was **REFUSED, on the cost rather than on the
 * strength** — see this module's entry in `docs/gotchas.md`. Hashing a
 * couple-of-hundred-MiB image belongs on the metrics worker, which makes the
 * annotation *load* async: the load effect would await a digest while the user
 * can already bookmark and rename, so a rename made inside that window is
 * written under the wrong key or lost outright, and the persist effect would
 * need its own await plus a cancellation token. The harm being fixed (two
 * same-named builds) is smaller than the harm that would introduce (a race on
 * every load). `size` and `timeDateStamp` cost nothing: both are read off
 * `parsePE`'s own answer.
 *
 * **THE GUID IS APPENDED, NOT SUBSTITUTED, AND THAT DIRECTION IS DELIBERATE.**
 * Appending can only ever split two identities apart; substituting could merge
 * them, and a merge is the direction that loses work. It costs one thing and it
 * is worth stating: a stripped copy of a build that still has its debug
 * directory is a *different* key from the unstripped one, so annotations do not
 * follow a binary across a strip. Refusing to share is the benign direction
 * here exactly as it is for a struct candidate in `structs.ts`.
 *
 * **THE HONEST RESIDUAL.** Two builds with the same size AND the same
 * `timeDateStamp` AND no debug directory still collide. That needs a stripped,
 * reproducible-but-not-content-hashed pair of the same size, which is
 * uncommon — and worth noting in the opposite direction too: MSVC's `/Brepro`
 * writes a **hash of the content** into `timeDateStamp`, so on a reproducible
 * build this key is already content-derived, which is better than the field's
 * name suggests.
 */
export function annotationKeyFor(id: BuildIdentity): string {
  return `${ANNOTATION_KEY_PREFIX}${buildKey(id)}`;
}

/**
 * THE COMPOSITE IDENTITY ITSELF, WITHOUT ANY STORE'S PREFIX.
 *
 * `<size>-<timeDateStamp, 8 lowercase hex>` and, where the image names a
 * CodeView GUID, `-<GUID>` appended. Every rule and every refusal recorded on
 * {@link annotationKeyFor} is a statement about *this* function; that one only
 * adds a namespace.
 *
 * **IT IS SPLIT OUT BECAUSE A SECOND STORE NEEDED IT AND MUST NOT RE-DERIVE
 * IT.** `utils/recentFiles.ts`'s IndexedDB cache was keyed on the bare file
 * name, so opening `v2/setup.exe` silently evicted `v1/setup.exe`'s bytes; it
 * is keyed on this string now (`peek-a-bin-mtry`). Two identity rules that can
 * disagree would be strictly worse than the collision either one fixes — the
 * recents list joins to annotation records, so a build the cache calls one
 * thing and the annotation store calls another is a join that silently misses.
 * There is exactly one composite-key rule in this repo and this is it.
 *
 * The `peek-a-bin:annotations:` prefix is deliberately NOT carried into the
 * IndexedDB key: that namespace exists to separate annotation records from ~18
 * settings keys sharing one flat `localStorage`, and a record in a database of
 * its own has nothing to be separated from.
 */
export function buildKey(id: BuildIdentity): string {
  const stamp = (id.timeDateStamp >>> 0).toString(16).padStart(8, "0");
  const head = `${id.size}-${stamp}`;
  return id.pdbGuid ? `${head}-${id.pdbGuid}` : head;
}

/**
 * The identity of a parsed image.
 *
 * `parseDebugDirectory` is called here rather than being read off `PEFile`
 * because it is **not part of `parsePE`** — it is a lazy memo in
 * `HeaderView.tsx`. It is header-local and bounded in every direction
 * (`MAX_DEBUG_DIRECTORY_ENTRIES` x `MAX_PDB_PATH_BYTES`), so a second call
 * costs what that panel's own call costs. A **truncated** directory is used
 * anyway when it produced a GUID: a GUID that was read is a real GUID, and the
 * flag is about entries the walk never reached.
 */
export function buildIdentityOf(pe: PEFile): BuildIdentity {
  let pdbGuid: string | undefined;
  try {
    const guid = parseDebugDirectory(pe.buffer, pe).entries.find((e) => e.guid)?.guid;
    if (guid) pdbGuid = guid;
  } catch {
    // A debug directory that cannot be read is not an identity crisis: the
    // header pair below is a complete key on its own. Swallowed rather than
    // propagated, because throwing here would take an ordinary load down.
  }
  return { size: pe.buffer.byteLength, timeDateStamp: pe.coffHeader.timeDateStamp, pdbGuid };
}

/** The key this image's annotations live under. The one call sites want. */
export function annotationKey(pe: PEFile): string {
  return annotationKeyFor(buildIdentityOf(pe));
}

/**
 * The subset of `Storage` this module needs.
 *
 * An interface rather than the DOM `Storage` type so the pure decision below
 * and the thin IO wrapper around it can both be exercised from a node test —
 * which is cheaper than a jsdom one and is this repo's stated preference.
 */
export interface AnnotationStore {
  getItem(key: string): string | null;
  setItem(key: string, value: string): void;
}

/**
 * What a load should adopt, and where it came from.
 *
 * `"legacy"` is the caller's instruction to **write the payload forward** under
 * the current key. It is a separate variant rather than a boolean because the
 * caller has to do something different in that case, and a boolean beside a
 * payload is a shape a caller can read half of.
 */
export type AnnotationSource = "current" | "legacy";

export interface AnnotationRead {
  source: AnnotationSource;
  payload: AnnotationPayload;
}

/**
 * PURE. Decide what a load should adopt, given both raw blobs.
 *
 * Returns null when neither key holds anything a reader should apply — which
 * covers "nothing stored" and "stored and malformed" alike, because both mean
 * the same thing to the reducer. `validateAnnotations` is what draws that line;
 * localStorage is editable by the user and by any script on this origin, so
 * every blob reaching here is untrusted.
 *
 * **THE CURRENT KEY WINS WHENEVER IT VALIDATES, INCLUDING WHEN IT IS EMPTY.**
 * The persist effect writes an empty record the moment a file opens, so the
 * second load of any migrated file finds a valid-and-empty current record — and
 * re-adopting the legacy blob there would resurrect annotations the user had
 * deleted. "Absent or malformed" is therefore the migration's trigger, not
 * "absent".
 */
export function readStoredAnnotations(
  currentRaw: string | null,
  legacyRaw: string | null,
): AnnotationRead | null {
  const current = parseAnnotationBlob(currentRaw);
  if (current) return { source: "current", payload: current };
  const legacy = parseAnnotationBlob(legacyRaw);
  if (legacy) return { source: "legacy", payload: legacy };
  return null;
}

/** PURE. `JSON.parse` + validate, with every failure collapsed to null. */
export function parseAnnotationBlob(raw: string | null): AnnotationPayload | null {
  if (!raw) return null;
  try {
    return validateAnnotations(JSON.parse(raw));
  } catch {
    return null;
  }
}

/**
 * Read this build's annotations, adopting a legacy bare-name record if that is
 * all there is.
 *
 * **THE LEGACY KEY IS LEFT EXACTLY WHERE IT IS, AND THAT IS A RULE RATHER THAN
 * AN OMISSION.** Two reasons, and the first is the stronger. (1) A user who
 * goes back to an older build of the tool, or who reverts, must still find
 * their work; deleting on adoption makes the migration one-way and silent. (2)
 * A deleter on the *load path* has to decide which keys are annotation records,
 * and nothing enforces that `peek-a-bin:<name>` stays a prefix of nothing else
 * — which is the exact foot-gun `CLAUDE.md` already refuses for the orphaned
 * `peek-a-bin:report:` keys. So legacy records are **intentionally orphaned**,
 * on that precedent: a few KB the user can clear from devtools.
 *
 * Returns null when there is nothing to apply, so the caller's "warn about a
 * malformed blob" decision stays the caller's.
 */
export function loadAnnotations(
  store: AnnotationStore,
  key: string,
  fileName: string,
): AnnotationRead | null {
  const currentRaw = store.getItem(key);
  const legacyRaw = store.getItem(legacyAnnotationKey(fileName));
  const read = readStoredAnnotations(currentRaw, legacyRaw);
  if (!read && (currentRaw || legacyRaw)) {
    // SOMETHING WAS STORED AND NONE OF IT WAS APPLICABLE, which is a different
    // fact from "nothing was stored" and the caller cannot tell them apart from
    // a null. Warned here rather than at the call site so the two raw reads stay
    // in one place; the app has no toast mechanism and one must not be invented
    // for this, so the console is the whole of the report — as it was before.
    console.warn("[peek-a-bin] ignoring malformed persisted annotations");
  }
  if (read?.source === "legacy") {
    // Written forward here rather than left to the persist effect, so the
    // adoption survives a reload that happens before the user touches
    // anything. `setItem` can throw on a full quota; a migration that could
    // not be recorded still applies, and the next persist retries it.
    try {
      store.setItem(key, JSON.stringify({ fileName, ...read.payload } satisfies AnnotationRecord));
    } catch {
      /* quota exceeded */
    }
  }
  return read;
}

/** Store one build's annotations, with the name it was last seen under. */
export function saveAnnotations(
  store: AnnotationStore,
  key: string,
  record: AnnotationRecord,
): void {
  try {
    store.setItem(key, JSON.stringify(record));
  } catch {
    /* quota exceeded */
  }
}

/**
 * A store that can also be enumerated and deleted from.
 *
 * Split from {@link AnnotationStore} because the two callers want different
 * halves: the load/persist path needs `getItem`/`setItem` and nothing else,
 * while the recents scan needs to walk the whole namespace.
 */
export interface AnnotationStoreIndex extends AnnotationStore {
  readonly length: number;
  key(index: number): string | null;
  removeItem(key: string): void;
}

/** One stored record, summarised for the recents list. */
export interface StoredAnnotationSummary {
  key: string;
  /** The name the record was last saved under; null on a pre-prefix record. */
  fileName: string | null;
  bookmarks: number;
  renames: number;
  comments: number;
}

/**
 * Every annotation record in the store, summarised.
 *
 * **THE ONE DECLARATION OF THE PREFIX SCAN**, and it replaces a deny-list.
 * `FileLoader` used to walk `peek-a-bin:` and skip four hand-written settings
 * names — against a namespace holding about eighteen — which reads as a rule
 * that holds and does not. That deny-list was **INERT** in practice: the
 * annotation-count test after it (`bookmarks + renames + comments > 0`) is what
 * actually kept `sidebar-width` out of the recents list, since a settings value
 * has none of those fields. Its deletion is a simplification, not a bug fix.
 *
 * Records whose blob does not validate are dropped rather than reported: the
 * recents list is a convenience, and a corrupt record has no name to show.
 */
export function listAnnotationRecords(store: AnnotationStoreIndex): StoredAnnotationSummary[] {
  const out: StoredAnnotationSummary[] = [];
  for (let i = 0; i < store.length; i++) {
    const key = store.key(i);
    if (!key?.startsWith(ANNOTATION_KEY_PREFIX)) continue;
    const raw = store.getItem(key);
    const payload = parseAnnotationBlob(raw);
    if (!payload) continue;
    let fileName: string | null = null;
    try {
      const name = (JSON.parse(raw as string) as AnnotationRecord).fileName;
      if (typeof name === "string") fileName = name;
    } catch {
      /* unreachable: parseAnnotationBlob already parsed it */
    }
    out.push({
      key,
      fileName,
      bookmarks: payload.bookmarks.length,
      renames: Object.keys(payload.renames).length,
      comments: Object.keys(payload.comments).length,
    });
  }
  return out;
}

/**
 * Delete every annotation record saved under one file name, plus that name's
 * legacy key.
 *
 * **This is a user-initiated delete, which is why it may delete at all** — the
 * rule {@link loadAnnotations} keeps is about the *load* path. The user clicked
 * "remove this recent", so the legacy blob for that name goes too; leaving it
 * would be keeping data they asked to be rid of.
 *
 * It is keyed on the NAME, and after `peek-a-bin-mtry` that is the FALLBACK
 * rather than the rule: `recentFiles.ts` is keyed on {@link buildKey} now, so a
 * recents row that came out of IndexedDB can name its own annotation record
 * exactly and calls {@link removeAnnotationRecord} instead. This is what the
 * rows that have no build identity use — a record migrated from the v1 store,
 * and an annotation-only row with no cached bytes at all. Where two builds
 * share a name it still removes both records, which is what a row that can only
 * name a name claims to be.
 */
export function removeAnnotationsFor(store: AnnotationStoreIndex, fileName: string): void {
  const doomed = listAnnotationRecords(store)
    .filter((r) => r.fileName === fileName)
    .map((r) => r.key);
  doomed.push(legacyAnnotationKey(fileName));
  for (const key of doomed) {
    try {
      store.removeItem(key);
    } catch {
      /* nothing to do */
    }
  }
}

/**
 * Delete ONE annotation record, named exactly.
 *
 * The precise counterpart to {@link removeAnnotationsFor}, and the one a
 * recents row backed by cached bytes uses: that row knows the build it
 * describes, so removing it must not take a *different* build that happens to
 * share the file name — which is the whole collision `peek-a-bin-mtry` closed
 * on the cache side.
 *
 * **The legacy bare-name blob is deliberately left behind here**, where
 * {@link removeAnnotationsFor} takes it. That blob is not attributable to a
 * build: deleting it while removing one of two same-named builds would take
 * data the other one can still adopt. It is orphaned instead, on
 * {@link loadAnnotations}' precedent.
 */
export function removeAnnotationRecord(store: AnnotationStoreIndex, key: string): void {
  try {
    store.removeItem(key);
  } catch {
    /* nothing to do */
  }
}
