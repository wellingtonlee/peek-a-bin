// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FileLoader } from "../FileLoader";

// Only the three IO functions are replaced. `isLegacyRecentKey` and
// `legacyRecentKey` are the module's PURE key rules and the component reads them
// to decide which join a row makes — stubbing those would be writing a second
// copy of the very rule `peek-a-bin-mtry` exists to keep single.
vi.mock("../../utils/recentFiles", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../utils/recentFiles")>()),
  getRecentFiles: vi.fn(async () => []),
  loadRecentFile: vi.fn(async () => null),
  deleteRecentFile: vi.fn(async () => {}),
}));

import { ANNOTATION_KEY_PREFIX, annotationKeyFor } from "../../utils/annotationKey";
import {
  deleteRecentFile,
  getRecentFiles,
  legacyRecentKey,
  loadRecentFile,
} from "../../utils/recentFiles";

/**
 * The pre-file screen, and the one place `state.error` has a render site.
 *
 * That last point is the whole of peek-a-bin-b3jn's premise. `App.tsx` says it
 * twice — "`state.error` renders only in FileLoader, which unmounts the moment a
 * PE parses" — and the bead turns on it: a bare `SET_ERROR` from a dead engine
 * reached no screen at all, which is why `SET_DISASM_FAILED` and the notice
 * exist. The premise has never been checked. It is checkable in two halves, and
 * this file does the first: that the error really does render here, and that
 * the screen stays usable so the next file can be tried. The second half — that
 * nothing else renders it — is `App.tsx`'s conditional and is out of reach of a
 * component test.
 *
 * THE PROGRESS-PANEL TESTS WENT WITH THEIR SUBJECT (peek-a-bin-v3uh.13). The
 * four-step panel, its `ANALYSIS_STEPS` table and the `analysisPhase`/`loading`
 * props could not render — `App` batches the whole load into one synchronous
 * handler, so this component unmounts before any in-flight phase is committed —
 * and the tripwire that used to stand here has been removed along with the
 * hazard it guarded, exactly as its own instructions said to do.
 *
 * MOCKING. `utils/recentFiles` is replaced wholesale rather than left to fail.
 * Its every export swallows its own exception and returns a default, so under
 * jsdom (no `indexedDB`) the real module yields an empty list and the component
 * mounts perfectly well — but then the recents list can only ever be tested
 * empty, and "the list is absent" would be indistinguishable from "the list was
 * suppressed", which is exactly one of the assertions below.
 *
 * SCOPE. jsdom has no layout and no drag-and-drop implementation. The drop
 * handlers are invoked by constructing the events, so what is verified is the
 * component's own reaction to a drop event — not that a browser would deliver
 * one, and not that the target is where a user would aim. Nothing here is
 * evidence about the drop zone's size, position or visibility.
 */

function renderLoader(over: Partial<Parameters<typeof FileLoader>[0]> = {}) {
  const onFile = vi.fn();
  render(<FileLoader onFile={onFile} error={null} {...over} />);
  return { onFile, user: userEvent.setup() };
}

const dropZone = () =>
  screen.getByRole("button", { name: "Drop a PE file here, or activate to browse" });

describe("FileLoader error rendering", () => {
  it("renders the error, which is the render site peek-a-bin-b3jn turns on", () => {
    renderLoader({ error: "Not a PE file: bad DOS signature" });
    expect(screen.getByText("Not a PE file: bad DOS signature")).toBeTruthy();
  });

  it("still invites another file after a rejection", async () => {
    // The whole point of showing the error here rather than on a dead-end
    // screen: the drop zone has to stay usable so the next file can be tried.
    const { onFile, user } = renderLoader({ error: "Not a PE file" });
    expect((dropZone() as HTMLButtonElement).disabled).toBe(false);
    const file = new File([new Uint8Array([0x4d, 0x5a])], "second.exe");
    await user.upload(fileInput(), file);
    await waitFor(() => expect(onFile).toHaveBeenCalled());
  });

  it("says nothing when there is no error", () => {
    renderLoader();
    expect(screen.queryByText(/Not a PE/)).toBeNull();
    expect(screen.getByText("Drop a PE file here")).toBeTruthy();
  });
});

function fileInput(): HTMLInputElement {
  const el = document.querySelector('input[type="file"]');
  if (!el) throw new Error("no file input");
  return el as HTMLInputElement;
}

describe("FileLoader file hand-off", () => {
  it("passes the File itself alongside the bytes on the browse path", async () => {
    const { onFile, user } = renderLoader();
    const bytes = new Uint8Array([0x4d, 0x5a, 0x90, 0x00]);
    const file = new File([bytes], "browsed.exe");
    await user.upload(fileInput(), file);
    await waitFor(() => expect(onFile).toHaveBeenCalledTimes(1));
    const [buffer, name, handed] = onFile.mock.calls[0];
    expect(name).toBe("browsed.exe");
    expect(new Uint8Array(buffer as ArrayBuffer)).toEqual(bytes);
    // The third argument is the whole of peek-a-bin-ex2 and peek-a-bin-736: a
    // Blob is structured-cloneable by reference, so the two workers can be
    // handed the handle instead of a copy. Only the drop/browse path has one,
    // and the prop's docstring says the other two paths "omit it and keep
    // paying the copy, which is by construction rather than by accident".
    // Nothing checked that this path supplies it.
    expect(handed).toBe(file);
  });

  it("passes the File on the drop path too", async () => {
    const { onFile } = renderLoader();
    const file = new File([new Uint8Array([0x4d, 0x5a])], "dropped.exe");
    const zone = dropZone();
    // jsdom implements no drag-and-drop, so the transfer is constructed. This
    // proves the component's handler reads `dataTransfer.files[0]` and forwards
    // the handle; it proves nothing about whether a browser would fire it here.
    const event = new Event("drop", { bubbles: true, cancelable: true });
    Object.defineProperty(event, "dataTransfer", { value: { files: [file] } });
    zone.dispatchEvent(event);
    await waitFor(() => expect(onFile).toHaveBeenCalledTimes(1));
    expect(onFile.mock.calls[0][2]).toBe(file);
  });

  it("omits the File on the recents path, which is the copy it keeps paying", async () => {
    vi.mocked(getRecentFiles).mockResolvedValueOnce([
      { key: "1024-00000001", name: "saved.exe", size: 1024, lastOpened: Date.now() },
    ]);
    vi.mocked(loadRecentFile).mockResolvedValueOnce(new Uint8Array([0x4d, 0x5a]).buffer);
    const { onFile, user } = renderLoader();
    const row = await screen.findByText("saved.exe");
    await user.click(row);
    await waitFor(() => expect(onFile).toHaveBeenCalledTimes(1));
    // Two arguments, not three: there is no File behind an IndexedDB buffer.
    expect(onFile.mock.calls[0]).toHaveLength(2);
  });
});

describe("FileLoader recent analyses", () => {
  it("lists a saved file with its size", async () => {
    vi.mocked(getRecentFiles).mockResolvedValueOnce([
      { key: "2048-00000001", name: "t64.exe", size: 2048, lastOpened: Date.now() },
    ]);
    renderLoader();
    expect(await screen.findByText("t64.exe")).toBeTruthy();
    expect(screen.getByText("2.0 KB")).toBeTruthy();
  });

  it("offers an annotations-only entry but will not load it", async () => {
    // A BUILD-KEYED record, and the name comes out of the VALUE. Annotations are
    // keyed on the image rather than on the file name (`utils/annotationKey.ts`),
    // so this scan finds records by prefix and reads `fileName` back out of each
    // one — which is why the record carries it at all (peek-a-bin-v3uh.5).
    localStorage.setItem(
      annotationKeyFor({ size: 4096, timeDateStamp: 0x41414141 }),
      JSON.stringify({
        fileName: "ghost.exe",
        bookmarks: [
          { address: 0x1000, label: "a" },
          { address: 0x2000, label: "b" },
        ],
        renames: { 3: "x" },
        comments: {},
      }),
    );
    renderLoader();
    const name = await screen.findByText("ghost.exe");
    // No buffer in IndexedDB, so the row is inert — but the annotations are
    // advertised, which is the reason the row exists at all.
    expect(screen.getByText("2 bookmarks, 1 rename")).toBeTruthy();
    expect((name.closest("button") as HTMLButtonElement).disabled).toBe(true);
  });

  it("no longer lists a LEGACY bare-name record, which is the documented cost", async () => {
    // The other half of deleting `KNOWN_LS_KEYS`: the scan is the
    // `peek-a-bin:annotations:` namespace only, so it cannot mistake a settings
    // key for a file — and cannot see a pre-migration record either. The DATA is
    // not lost (opening that file adopts it, non-destructively), but the row is
    // gone until then. Deciding which bare `peek-a-bin:<x>` keys are files is
    // exactly the deny-list this change exists to remove.
    localStorage.setItem(
      "peek-a-bin:ghost.exe",
      JSON.stringify({ bookmarks: [{ address: 1, label: "a" }], renames: {}, comments: {} }),
    );
    renderLoader();
    await waitFor(() => expect(vi.mocked(getRecentFiles)).toHaveBeenCalled());
    expect(screen.queryByText("ghost.exe")).toBeNull();
  });

  it("ignores a settings key whose value could not be a record", async () => {
    // The liveness half of the row above: with the prefix test in place these
    // are skipped for a structural reason rather than by a four-name list, and
    // the list that used to name the first four of them is gone.
    for (const [k, v] of [
      ["peek-a-bin:sidebar-width", "240"],
      ["peek-a-bin:sections-open", "true"],
      ["peek-a-bin:graph-overview-open", "false"],
      ["peek-a-bin:callers-open", "true"],
      ["peek-a-bin:font-size", "13"],
    ]) {
      localStorage.setItem(k, v);
    }
    renderLoader();
    await waitFor(() => expect(vi.mocked(getRecentFiles)).toHaveBeenCalled());
    // The heading is absent because the list is empty — the section is
    // conditional on `recentFiles.length > 0`.
    expect(screen.queryByText("Recent analyses")).toBeNull();
  });
});

describe("FileLoader recents — two builds of one binary (peek-a-bin-mtry)", () => {
  /** An annotation record for one build, with `n` bookmarks. */
  function annotate(key: string, fileName: string, n: number) {
    localStorage.setItem(
      key,
      JSON.stringify({
        fileName,
        bookmarks: Array.from({ length: n }, (_, i) => ({ address: i + 1, label: `b${i}` })),
        renames: {},
        comments: {},
      }),
    );
  }

  const V1 = "2048-00000001";
  const V2 = "4096-00000002";

  function twoBuilds() {
    vi.mocked(getRecentFiles).mockResolvedValue([
      { key: V2, name: "setup.exe", size: 4096, lastOpened: 2000 },
      { key: V1, name: "setup.exe", size: 2048, lastOpened: 1000 },
    ]);
  }

  it("shows BOTH same-named rows, told apart by size", async () => {
    // The React list key is `f.key`, not `f.name`: two rows sharing a name would
    // otherwise share a key and be reconciled as one. A duplicate key is a
    // console warning rather than a render failure, so the spy is the only
    // instrument — and it is file-wide (below) because React caches that warning
    // per owner component, so a spy installed here would see a clean console.
    twoBuilds();
    renderLoader();
    await waitFor(() => expect(screen.getAllByText("setup.exe")).toHaveLength(2));
    expect(screen.getByText("4.0 KB")).toBeTruthy();
    expect(screen.getByText("2.0 KB")).toBeTruthy();
  });

  it("joins each row to ITS OWN build's annotations, not to the name's", async () => {
    // THE POINT. Both records say `fileName: "setup.exe"`; only the key tells
    // them apart, and both stores are keyed on the same composite string.
    twoBuilds();
    annotate(`${ANNOTATION_KEY_PREFIX}${V1}`, "setup.exe", 1);
    annotate(`${ANNOTATION_KEY_PREFIX}${V2}`, "setup.exe", 7);
    renderLoader();

    await waitFor(() => expect(screen.getAllByText("setup.exe")).toHaveLength(2));
    expect(screen.getByText("7 bookmarks")).toBeTruthy();
    expect(screen.getByText("1 bookmark")).toBeTruthy();
  });

  it("loads the row that was clicked, by key", async () => {
    twoBuilds();
    const { user } = renderLoader();
    const rows = await screen.findAllByText("setup.exe");
    // The older row is second; clicking it must load V1's bytes, not V2's.
    await user.click(rows[1]);
    await waitFor(() => expect(vi.mocked(loadRecentFile)).toHaveBeenCalled());
    expect(vi.mocked(loadRecentFile).mock.calls[0][0]).toBe(V1);
  });

  it("removes only the clicked build, leaving the other row and its annotations", async () => {
    twoBuilds();
    annotate(`${ANNOTATION_KEY_PREFIX}${V1}`, "setup.exe", 1);
    annotate(`${ANNOTATION_KEY_PREFIX}${V2}`, "setup.exe", 7);
    const { user } = renderLoader();
    await waitFor(() => expect(screen.getAllByText("setup.exe")).toHaveLength(2));

    // The × buttons sit in row order beside each name.
    await user.click(screen.getAllByTitle("Remove from recent")[1]);

    await waitFor(() => expect(screen.getAllByText("setup.exe")).toHaveLength(1));
    expect(vi.mocked(deleteRecentFile).mock.calls[0][0]).toBe(V1);
    expect(localStorage.getItem(`${ANNOTATION_KEY_PREFIX}${V1}`)).toBeNull();
    // The OTHER build's work survives — under a name key it would have gone too.
    expect(localStorage.getItem(`${ANNOTATION_KEY_PREFIX}${V2}`)).not.toBeNull();
  });

  it("a record migrated from the v1 store joins by name, having no build identity", async () => {
    // The documented fallback. A `name:` key cannot name an annotation record,
    // so this row falls back to the name join — which is all a v1 record has.
    vi.mocked(getRecentFiles).mockResolvedValue([
      { key: legacyRecentKey("old.exe"), name: "old.exe", size: 512, lastOpened: 10 },
    ]);
    annotate(annotationKeyFor({ size: 512, timeDateStamp: 0x99 }), "old.exe", 3);
    renderLoader();

    expect(await screen.findByText("old.exe")).toBeTruthy();
    expect(screen.getByText("3 bookmarks")).toBeTruthy();
  });

  it("does not also list an annotation-only row for a build a cached file claims", async () => {
    // The claim is by KEY now. Without it the same build would appear twice —
    // once with its bytes and once as a ghost.
    vi.mocked(getRecentFiles).mockResolvedValue([
      { key: V1, name: "setup.exe", size: 2048, lastOpened: 1000 },
    ]);
    annotate(`${ANNOTATION_KEY_PREFIX}${V1}`, "setup.exe", 2);
    renderLoader();

    await waitFor(() => expect(screen.getAllByText("setup.exe")).toHaveLength(1));
    expect(screen.getByText("2 bookmarks")).toBeTruthy();
  });

  it("still lists a build with annotations and no cached bytes beside a cached sibling", async () => {
    // Two builds, one cached: the uncached one is an inert annotations-only row
    // rather than being swallowed by its sibling's name.
    vi.mocked(getRecentFiles).mockResolvedValue([
      { key: V2, name: "setup.exe", size: 4096, lastOpened: 2000 },
    ]);
    annotate(`${ANNOTATION_KEY_PREFIX}${V1}`, "setup.exe", 5);
    renderLoader();

    await waitFor(() => expect(screen.getAllByText("setup.exe")).toHaveLength(2));
    expect(screen.getByText("5 bookmarks")).toBeTruthy();
  });
});

/**
 * React's duplicate-key warning is a `console.error`, and it is cached PER OWNER
 * COMPONENT — so a spy installed inside one test sees a clean console once any
 * earlier render has already warned. It has to be file-wide, failing on the
 * FIRST render that warns.
 */
let consoleErrorSpy: ReturnType<typeof vi.spyOn>;

beforeEach(() => {
  consoleErrorSpy = vi.spyOn(console, "error").mockImplementation(() => {});
  vi.mocked(getRecentFiles).mockResolvedValue([]);
  vi.mocked(loadRecentFile).mockResolvedValue(null);
  localStorage.clear();
});

afterEach(() => {
  const keyWarnings = (consoleErrorSpy.mock.calls as unknown[][]).filter((c) =>
    String(c[0] ?? "").includes("same key"),
  );
  consoleErrorSpy.mockRestore();
  expect(keyWarnings).toEqual([]);
  localStorage.clear();
  vi.clearAllMocks();
});
