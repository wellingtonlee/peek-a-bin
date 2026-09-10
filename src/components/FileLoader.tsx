import { useCallback, useEffect, useRef, useState } from "react";
import {
  ANNOTATION_KEY_PREFIX,
  listAnnotationRecords,
  removeAnnotationRecord,
  removeAnnotationsFor,
} from "../utils/annotationKey";
import {
  deleteRecentFile,
  getRecentFiles as getRecentFilesFromIDB,
  isLegacyRecentKey,
  loadRecentFile,
  type RecentFileEntry,
} from "../utils/recentFiles";

interface FileLoaderProps {
  /**
   * @param buffer the file's bytes, already read.
   * @param fileName the name to show and to key annotations by.
   * @param file the `File` the bytes were read from, when there is one.
   *
   * The third argument exists because a `File` is structured-cloneable by
   * reference, so the metrics worker can be handed the handle instead of a copy
   * of the buffer (`workers/metricsClient.ts`'s `registerSourceBlob`). It is
   * optional and **not** merely for old browsers: only the drop/browse path has
   * a `File` at all. `loadExample` fetches an `ArrayBuffer` and
   * `handleRecentClick` reads one out of IndexedDB, so those two omit it and
   * keep paying the copy, which is by construction rather than by accident.
   */
  onFile: (buffer: ArrayBuffer, fileName: string, file?: File) => void;
  error: string | null;
}

interface RecentFile {
  /**
   * WHAT IDENTIFIES THE ROW, and it is not the name.
   *
   * For a row with cached bytes this is `recentFiles.ts`'s store key — the
   * build identity, or a `name:` key on a record carried over from the v1
   * store. For an annotation-only row it is the annotation record's own key.
   * Both are unique, which is what lets two builds of one binary be two rows;
   * the name is display text and two rows may legitimately share it
   * (peek-a-bin-mtry).
   */
  key: string;
  name: string;
  size: number;
  lastOpened: number;
  hasBuffer: boolean;
  bookmarks: number;
  renames: number;
  comments: number;
}

interface AnnotationCounts {
  bookmarks: number;
  renames: number;
  comments: number;
}

const NO_ANNOTATIONS: AnnotationCounts = { bookmarks: 0, renames: 0, comments: 0 };

interface AnnotationIndex {
  /** Counts by the annotation record's OWN key. An exact join. */
  byKey: Map<string, AnnotationCounts>;
  /** Counts by file name, richest record wins. The fallback join. */
  byName: Map<string, AnnotationCounts>;
  /** Every record, for the annotation-only rows below. */
  records: ReturnType<typeof listAnnotationRecords>;
}

/**
 * The two joins a recents row can make against the annotation store.
 *
 * **`byKey` IS THE REAL ONE AND IT IS EXACT.** Both stores are keyed on
 * `buildKey`'s composite identity now, so a cached file finds its own build's
 * bookmarks and nothing else — the point of `peek-a-bin-mtry`. `byName` is the
 * fallback for the two rows that have no build identity to join on: a record
 * carried over from the v1 IndexedDB store, and an annotation-only row. It is a
 * *display* fold rather than an identity, so where two builds share a name the
 * richer record's counts are the ones shown; nothing here decides which record
 * a load reads.
 */
function annotationIndex(): AnnotationIndex {
  const byKey = new Map<string, AnnotationCounts>();
  const byName = new Map<string, AnnotationCounts>();
  const records = listAnnotationRecords(localStorage);
  for (const rec of records) {
    const counts = {
      bookmarks: rec.bookmarks,
      renames: rec.renames,
      comments: rec.comments,
    };
    byKey.set(rec.key, counts);
    if (rec.fileName === null) continue;
    const total = rec.bookmarks + rec.renames + rec.comments;
    const seen = byName.get(rec.fileName);
    if (seen && seen.bookmarks + seen.renames + seen.comments >= total) continue;
    byName.set(rec.fileName, counts);
  }
  return { byKey, byName, records };
}

/**
 * PURE. The counts one cached file should show.
 *
 * **EXACT-OR-NOTHING WHERE THE ROW NAMES A BUILD, and that is not a detail.**
 * Falling back to the name join for a build-keyed row with no record of its own
 * hands it a *sibling build's* bookmark count — measured, when this was first
 * written with a `??` chain: two builds of `setup.exe`, one annotated, and both
 * rows advertised the same five bookmarks. The name join is reached only by a
 * row that has no build identity to join on: a record carried over from the v1
 * IndexedDB store. A build with nothing saved has nothing to show.
 */
export function countsForRecent(index: AnnotationIndex, entry: RecentFileEntry): AnnotationCounts {
  if (isLegacyRecentKey(entry.key)) return index.byName.get(entry.name) ?? NO_ANNOTATIONS;
  return index.byKey.get(`${ANNOTATION_KEY_PREFIX}${entry.key}`) ?? NO_ANNOTATIONS;
}

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatRelativeTime(timestamp: number): string {
  const diff = Date.now() - timestamp;
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return "just now";
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.floor(days / 7)}w ago`;
}

/**
 * The pre-file screen: drop zone, error, "try example" and the recents list.
 *
 * THERE IS DELIBERATELY NO PROGRESS PANEL HERE, AND RE-ADDING ONE WOULD BE DEAD
 * CODE — the reason is in `App.tsx` and not visible from this file. `App`
 * renders this component only when `!state.peFile`, and its `handleFile`
 * dispatches RESET, SET_ANALYSIS_PHASE "parsing" and SET_PE_FILE from ONE
 * synchronous callback. React cannot commit a render in the middle of that, so
 * by the first paint after a drop either `peFile` is set — and this component
 * is unmounted — or the parse threw, and the catch dispatches "idle", NOT a
 * terminal phase. So no in-flight phase is ever observable while this component
 * is mounted.
 *
 * There used to be a second half to this argument, about `AppState.loading`
 * being cleared by SET_PE_FILE and SET_ERROR inside the same batch. That field
 * is GONE (peek-a-bin-576b): deleting the panel left it with no reader at all,
 * so it was write-only state and `SET_LOADING` went with it.
 *
 * It used to carry a four-step panel keyed off a second phase-to-label table
 * (`ANALYSIS_STEPS`) plus a fourth hand-written `phase !== "idle" && !== "ready"`
 * chain — the shape `ANALYSIS_IN_PROGRESS` exists to replace, one term shorter
 * than the three sites peek-a-bin-bo3b converted. None of it could render. The
 * steps a user really waits on (detect functions, build xrefs) all run *after*
 * this screen is gone, and what they actually see is the sidebar skeleton and
 * the status-bar spinner — both of which read `ANALYSIS_IN_PROGRESS`, the one
 * declaration. Relocating the panel would have meant keeping two tables for one
 * fact (peek-a-bin-v3uh.13).
 */
export function FileLoader({ onFile, error }: FileLoaderProps) {
  const [dragging, setDragging] = useState(false);
  const [loadingExample, setLoadingExample] = useState(false);
  const [loadingRecent, setLoadingRecent] = useState<string | null>(null);
  const [recentFiles, setRecentFiles] = useState<RecentFile[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  // Load recent files from IndexedDB + localStorage annotations
  useEffect(() => {
    let cancelled = false;
    (async () => {
      const idbFiles = await getRecentFilesFromIDB();

      // ONE PREFIX SCAN, WHERE THIS USED TO BE A DENY-LIST. Annotation records
      // live under `peek-a-bin:annotations:` now, so telling them apart from the
      // ~18 settings keys sharing the `peek-a-bin:` namespace is a prefix test
      // rather than four hand-written names (peek-a-bin-v3uh.5).
      const annotations = annotationIndex();

      // Also find annotation-only entries (files with annotations but no buffer).
      // A record is CLAIMED when a cached file joined to it — by key where both
      // sides have a build identity, and by name for a row carried over from the
      // v1 store, which has none.
      const claimedKeys = new Set(
        idbFiles
          .filter((f) => !isLegacyRecentKey(f.key))
          .map((f) => `${ANNOTATION_KEY_PREFIX}${f.key}`),
      );
      const legacyNames = new Set(
        idbFiles.filter((f) => isLegacyRecentKey(f.key)).map((f) => f.name),
      );
      const lsOnlyFiles: RecentFileEntry[] = [];
      for (const rec of annotations.records) {
        if (rec.fileName === null) continue;
        if (claimedKeys.has(rec.key) || legacyNames.has(rec.fileName)) continue;
        if (rec.bookmarks + rec.renames + rec.comments > 0) {
          lsOnlyFiles.push({ key: rec.key, name: rec.fileName, size: 0, lastOpened: 0 });
        }
      }

      if (cancelled) return;

      const combined: RecentFile[] = idbFiles.map((f) => ({
        ...f,
        hasBuffer: true,
        ...countsForRecent(annotations, f),
      }));
      for (const f of lsOnlyFiles) {
        combined.push({
          ...f,
          hasBuffer: false,
          ...(annotations.byKey.get(f.key) ?? NO_ANNOTATIONS),
        });
      }
      // Sort by lastOpened (most recent first), then by annotation count for ls-only
      combined.sort(
        (a, b) =>
          b.lastOpened - a.lastOpened ||
          b.bookmarks + b.renames + b.comments - (a.bookmarks + a.renames + a.comments),
      );
      setRecentFiles(combined.slice(0, 5));
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  const loadExample = useCallback(async () => {
    setLoadingExample(true);
    try {
      const res = await fetch(`${import.meta.env.BASE_URL}crackme01.exe`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const buffer = await res.arrayBuffer();
      onFile(buffer, "crackme01.exe");
    } catch (e) {
      console.error("Failed to load example:", e);
    } finally {
      setLoadingExample(false);
    }
  }, [onFile]);

  // Keyed on the ROW, not the name: two builds of one binary are two rows with
  // one name, so a name here would load and spin the wrong one (peek-a-bin-mtry).
  const handleRecentClick = useCallback(
    async (key: string, name: string) => {
      setLoadingRecent(key);
      try {
        const buffer = await loadRecentFile(key);
        if (buffer) {
          onFile(buffer, name);
        }
      } finally {
        setLoadingRecent(null);
      }
    },
    [onFile],
  );

  const handleRemoveRecent = useCallback(async (e: React.MouseEvent, row: RecentFile) => {
    e.stopPropagation();
    if (row.hasBuffer) await deleteRecentFile(row.key);
    // A user-initiated delete, which is the one place deleting is right — the
    // LOAD path deliberately never deletes (`loadAnnotations`). Where the row
    // names a build, exactly that record goes: taking every record sharing the
    // name would delete the OTHER build's work, which is the collision this
    // list stopped having. A row with no build identity has only the name.
    if (row.hasBuffer && isLegacyRecentKey(row.key)) {
      removeAnnotationsFor(localStorage, row.name);
    } else if (row.hasBuffer) {
      removeAnnotationRecord(localStorage, `${ANNOTATION_KEY_PREFIX}${row.key}`);
    } else {
      removeAnnotationRecord(localStorage, row.key);
    }
    setRecentFiles((prev) => prev.filter((f) => f.key !== row.key));
  }, []);

  const handleFile = useCallback(
    (file: File) => {
      const reader = new FileReader();
      reader.onload = () => {
        if (reader.result instanceof ArrayBuffer) {
          // The `File` rides along: same bytes, and posting it to the metrics
          // worker costs nothing where copying the buffer costs a walk over it.
          onFile(reader.result, file.name, file);
        }
      };
      reader.onerror = () => {
        console.error("FileReader error:", reader.error);
      };
      reader.readAsArrayBuffer(file);
    },
    [onFile],
  );

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragging(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  const onDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(true);
  }, []);

  const onDragLeave = useCallback(() => setDragging(false), []);

  const onChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0];
      if (file) handleFile(file);
    },
    [handleFile],
  );

  return (
    <div className="flex flex-col items-center justify-center h-screen app-bg">
      {/* Branding */}
      <div className="mb-6 text-center">
        <h1 className="text-2xl font-bold text-gray-100">Peek-a-Bin</h1>
        <p className="text-sm text-gray-500">Browser-based PE disassembler</p>
      </div>

      {/* Drop zone */}
      {/* A real <button> so the "click to browse" affordance is keyboard-operable;
          the drag handlers ride along unchanged. */}
      <button
        type="button"
        aria-label="Drop a PE file here, or activate to browse"
        className={`flex flex-col items-center justify-center w-[600px] h-[350px] border-2 border-dashed rounded-xl transition-colors cursor-pointer ${
          dragging ? "border-blue-400 bg-blue-400/10" : "border-gray-600 hover:border-gray-400"
        }`}
        onDrop={onDrop}
        onDragOver={onDragOver}
        onDragLeave={onDragLeave}
        onClick={() => inputRef.current?.click()}
      >
        <svg
          aria-hidden="true"
          className="w-16 h-16 mb-4 text-gray-500"
          fill="none"
          stroke="currentColor"
          viewBox="0 0 24 24"
        >
          <path
            strokeLinecap="round"
            strokeLinejoin="round"
            strokeWidth={1.5}
            d="M9 8h6m-5 0a3 3 0 110 6H9l3 3m-3-3h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V17a2 2 0 01-2 2z"
          />
        </svg>
        <p className="text-xl text-gray-300 mb-2">Drop a PE file here</p>
        <p className="text-sm text-gray-500">or click to browse (.exe, .dll)</p>
        {error && <p className="mt-4 text-sm text-red-400 max-w-md text-center">{error}</p>}

        {/* Divider + Try example */}
        <div className="flex items-center gap-3 mt-5 w-48">
          <hr className="flex-1 border-gray-700" />
          <span className="text-xs text-gray-600">or</span>
          <hr className="flex-1 border-gray-700" />
        </div>
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            loadExample();
          }}
          disabled={loadingExample}
          className="mt-3 text-sm text-gray-500 hover:text-gray-300 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {loadingExample ? "Loading..." : "Try example: crackme01.exe"}
        </button>
      </button>

      {/* Sibling of the drop zone, not a child: a form control nested inside a
          <button> is invalid, and the programmatic .click() would bubble back into
          the button's own onClick. */}
      <input
        ref={inputRef}
        type="file"
        accept=".exe,.dll,.sys,.ocx"
        onChange={onChange}
        className="hidden"
      />

      {/* Recent files */}
      {recentFiles.length > 0 && (
        <div className="mt-6 w-[500px]">
          <p className="text-xs text-gray-600 uppercase tracking-wider mb-2">Recent analyses</p>
          <div className="flex flex-col gap-1">
            {recentFiles.map((f) => {
              const parts: string[] = [];
              if (f.bookmarks > 0)
                parts.push(`${f.bookmarks} bookmark${f.bookmarks !== 1 ? "s" : ""}`);
              if (f.renames > 0) parts.push(`${f.renames} rename${f.renames !== 1 ? "s" : ""}`);
              if (f.comments > 0) parts.push(`${f.comments} comment${f.comments !== 1 ? "s" : ""}`);
              const isLoading = loadingRecent === f.key;
              return (
                // The row is a button and the "remove" × is its sibling — buttons
                // cannot nest. The button still spans everything but the ×, so the
                // whole row stays clickable.
                <div
                  key={f.key}
                  className={`flex items-center gap-2 text-sm px-2 py-1.5 rounded group ${
                    f.hasBuffer ? "cursor-pointer hover:bg-gray-800/60 transition-colors" : ""
                  }`}
                >
                  <button
                    type="button"
                    disabled={!f.hasBuffer || isLoading}
                    className="flex items-center justify-between gap-2 flex-1 min-w-0 text-left"
                    onClick={() => handleRecentClick(f.key, f.name)}
                  >
                    <div className="flex items-center gap-2 min-w-0 flex-1">
                      <span
                        className={`font-mono text-xs truncate ${f.hasBuffer ? "text-blue-400" : "text-gray-400"}`}
                      >
                        {f.name}
                      </span>
                      {isLoading && (
                        <span className="text-yellow-400 text-[10px] animate-pulse">
                          loading...
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      {f.size > 0 && (
                        <span className="text-gray-600 text-[10px]">{formatFileSize(f.size)}</span>
                      )}
                      {f.lastOpened > 0 && (
                        <span className="text-gray-600 text-[10px]">
                          {formatRelativeTime(f.lastOpened)}
                        </span>
                      )}
                      {parts.length > 0 && (
                        <span className="text-gray-600 text-[10px]">{parts.join(", ")}</span>
                      )}
                    </div>
                  </button>
                  <button
                    type="button"
                    onClick={(e) => handleRemoveRecent(e, f)}
                    className="shrink-0 text-gray-700 hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity text-xs px-1"
                    title="Remove from recent"
                  >
                    ×
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
