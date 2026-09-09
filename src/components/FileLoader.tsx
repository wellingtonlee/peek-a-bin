import { useCallback, useEffect, useRef, useState } from "react";
import { listAnnotationRecords, removeAnnotationsFor } from "../utils/annotationKey";
import {
  deleteRecentFile,
  getRecentFiles as getRecentFilesFromIDB,
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

/**
 * Annotation counts per FILE NAME, folded out of the build-keyed records.
 *
 * Annotations are keyed on the build (`utils/annotationKey.ts`), so this map is
 * a *display* fold and not an identity: it reads the name back out of each
 * record's value. Where two builds share one name — the case that keying on the
 * build exists to keep working — the richer record's counts are the ones shown,
 * because this list is still name-keyed on the other side too
 * (`recentFiles.ts` uses `keyPath: "name"`, and changing that is its own bead).
 * Showing the richer of the two is a choice about a summary line; nothing here
 * decides which record a load reads.
 */
function annotationCountsByName(): Map<string, AnnotationCounts> {
  const byName = new Map<string, AnnotationCounts>();
  for (const rec of listAnnotationRecords(localStorage)) {
    if (rec.fileName === null) continue;
    const total = rec.bookmarks + rec.renames + rec.comments;
    const seen = byName.get(rec.fileName);
    if (seen && seen.bookmarks + seen.renames + seen.comments >= total) continue;
    byName.set(rec.fileName, {
      bookmarks: rec.bookmarks,
      renames: rec.renames,
      comments: rec.comments,
    });
  }
  return byName;
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
 * dispatches RESET, SET_LOADING, SET_ANALYSIS_PHASE "parsing" and SET_PE_FILE
 * from ONE synchronous callback. React cannot commit a render in the middle of
 * that, so by the first paint after a drop either `peFile` is set — and this
 * component is unmounted — or the parse threw, and the catch dispatches "idle",
 * NOT a terminal phase. `loading` cannot rescue it either: SET_PE_FILE and
 * SET_ERROR both clear it inside the same batch. So no in-flight phase and no
 * truthy `loading` is ever observable while this component is mounted.
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
      const annotations = annotationCountsByName();

      // Also find annotation-only entries (files with annotations but no buffer)
      const idbNames = new Set(idbFiles.map((f) => f.name));
      const lsOnlyFiles: RecentFileEntry[] = [];
      for (const [name, ann] of annotations) {
        if (idbNames.has(name)) continue;
        if (ann.bookmarks + ann.renames + ann.comments > 0) {
          lsOnlyFiles.push({ name, size: 0, lastOpened: 0 });
        }
      }

      if (cancelled) return;

      const combined: RecentFile[] = idbFiles.map((f) => ({
        ...f,
        hasBuffer: true,
        ...(annotations.get(f.name) ?? NO_ANNOTATIONS),
      }));
      for (const f of lsOnlyFiles) {
        combined.push({
          ...f,
          hasBuffer: false,
          ...(annotations.get(f.name) ?? NO_ANNOTATIONS),
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

  const handleRecentClick = useCallback(
    async (name: string) => {
      setLoadingRecent(name);
      try {
        const buffer = await loadRecentFile(name);
        if (buffer) {
          onFile(buffer, name);
        }
      } finally {
        setLoadingRecent(null);
      }
    },
    [onFile],
  );

  const handleRemoveRecent = useCallback(async (e: React.MouseEvent, name: string) => {
    e.stopPropagation();
    await deleteRecentFile(name);
    // Every build-keyed record saved under this name, plus the legacy bare-name
    // key. A user-initiated delete, which is the one place deleting is right —
    // the LOAD path deliberately never deletes (`loadAnnotations`).
    removeAnnotationsFor(localStorage, name);
    setRecentFiles((prev) => prev.filter((f) => f.name !== name));
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
              const isLoading = loadingRecent === f.name;
              return (
                // The row is a button and the "remove" × is its sibling — buttons
                // cannot nest. The button still spans everything but the ×, so the
                // whole row stays clickable.
                <div
                  key={f.name}
                  className={`flex items-center gap-2 text-sm px-2 py-1.5 rounded group ${
                    f.hasBuffer ? "cursor-pointer hover:bg-gray-800/60 transition-colors" : ""
                  }`}
                >
                  <button
                    type="button"
                    disabled={!f.hasBuffer || isLoading}
                    className="flex items-center justify-between gap-2 flex-1 min-w-0 text-left"
                    onClick={() => handleRecentClick(f.name)}
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
                    onClick={(e) => handleRemoveRecent(e, f.name)}
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
