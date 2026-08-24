// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ANALYSIS_IN_PROGRESS, type AnalysisPhase } from "../../hooks/usePEFile";
import { FileLoader } from "../FileLoader";

vi.mock("../../utils/recentFiles", () => ({
  getRecentFiles: vi.fn(async () => []),
  loadRecentFile: vi.fn(async () => null),
  deleteRecentFile: vi.fn(async () => {}),
}));

import { getRecentFiles, loadRecentFile } from "../../utils/recentFiles";

/**
 * The pre-file screen, and the one place `state.error` has a render site.
 *
 * That last point is the whole of peek-a-bin-b3jn's premise. `App.tsx` says it
 * twice — "`state.error` renders only in FileLoader, which unmounts the moment a
 * PE parses" — and the bead turns on it: a bare `SET_ERROR` from a dead engine
 * reached no screen at all, which is why `SET_DISASM_FAILED` and the notice
 * exist. The premise has never been checked. It is checkable in two halves, and
 * this file does the first: that the error really does render here, and under
 * which phases it does not. The second half — that nothing else renders it — is
 * `App.tsx`'s conditional and is out of reach of a component test.
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

const PHASES: AnalysisPhase[] = Object.keys(ANALYSIS_IN_PROGRESS) as AnalysisPhase[];

function renderLoader(over: Partial<Parameters<typeof FileLoader>[0]> = {}) {
  const onFile = vi.fn();
  render(
    <FileLoader
      onFile={onFile}
      loading={false}
      error={null}
      analysisPhase="idle"
      fileName={null}
      {...over}
    />,
  );
  return { onFile, user: userEvent.setup() };
}

const dropZone = () =>
  screen.getByRole("button", { name: "Drop a PE file here, or activate to browse" });

/** True when the drop zone is showing the four-step progress panel. */
const showingProgress = () => screen.queryByText("Parsing PE") !== null;

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

describe("FileLoader analysis progress", () => {
  it("shows the drop zone, not the progress panel, when idle", () => {
    renderLoader({ analysisPhase: "idle" });
    expect(showingProgress()).toBe(false);
    expect(screen.getByText("Drop a PE file here")).toBeTruthy();
  });

  it("marks the step matching the phase active and the earlier ones done", () => {
    renderLoader({ analysisPhase: "building-xrefs", fileName: "t32.exe" });
    expect(showingProgress()).toBe(true);
    // ● marks the active step, ✓ the completed ones. The three before
    // "Building xrefs" are done, so exactly one ● and three ✓.
    expect(screen.getAllByText("●")).toHaveLength(1);
    expect(screen.getAllByText("✓")).toHaveLength(3);
    expect(screen.getByText("t32.exe")).toBeTruthy();
  });

  it("treats the three recursive-descent phases as the one detection step", () => {
    for (const phase of ["detecting-functions", "recursive-descent", "gap-filling"] as const) {
      const { unmount } = render(
        <FileLoader
          onFile={vi.fn()}
          loading={false}
          error={null}
          analysisPhase={phase}
          fileName={null}
        />,
      );
      // One step active in all three, and it is always the same one — the
      // ANALYSIS_STEPS grouping, which is otherwise only visible by reading it.
      // Two done before it (Parsing, Extracting strings) and one pending after.
      expect(screen.getAllByText("●")).toHaveLength(1);
      expect(screen.getAllByText("✓")).toHaveLength(2);
      expect(screen.getByText("Detecting functions").previousElementSibling?.textContent).toBe("●");
      unmount();
    }
  });

  it("marks every step done once the phase reaches ready", () => {
    // `ready` is the one arm of `getStepStatus` that is load-bearing, and this
    // is the only combination that renders it: `isAnalyzing` is false for
    // `ready`, so the panel is on screen only because `loading` is still true —
    // the frame between the analysis finishing and the parent unmounting this.
    //
    // ITS NEIGHBOUR IS NOT LOAD-BEARING, and that is recorded here because a
    // negative control found it rather than because it was read: removing
    // `getStepStatus`'s `if (analysisPhase === "failed") return "pending"` arm
    // changes NO output, in this suite or in principle. No ANALYSIS_STEPS entry
    // lists "failed", so `activeStepIndex` is -1 and the very next line returns
    // "pending" anyway. The arm is redundant, no test can discriminate it, and
    // the comment above it ("stop every remaining step showing as
    // pending-forever") describes a job the line below it was already doing.
    renderLoader({ loading: true, analysisPhase: "ready" });
    expect(showingProgress()).toBe(true);
    expect(screen.getAllByText("\u2713")).toHaveLength(4);
    expect(screen.queryAllByText("\u25cf")).toHaveLength(0);
    expect(screen.queryAllByText("\u25cb")).toHaveLength(0);
  });

  it("disables the drop zone while an analysis is running", () => {
    renderLoader({ analysisPhase: "detecting-functions" });
    expect((dropZone() as HTMLButtonElement).disabled).toBe(true);
  });

  it("shows the progress panel for a `loading` with no phase yet", () => {
    // `loading` is a separate prop and gates the same panel, so a file being
    // read off disk before the phase moves does not flash the drop zone.
    renderLoader({ loading: true, analysisPhase: "idle" });
    expect(showingProgress()).toBe(true);
  });
});

/**
 * A LATENT HAZARD, PINNED AS A TRIPWIRE — READ BEFORE "FIXING" EITHER SIDE.
 *
 * `FileLoader` computes `isAnalyzing` itself, as
 * `analysisPhase !== "idle" && analysisPhase !== "ready"`. That is the
 * hand-written chain `ANALYSIS_IN_PROGRESS` exists to replace, one term shorter:
 * CLAUDE.md records the original as `!== "idle" && !== "ready" && !== "failed"`
 * at three sites, and says a shape that "defaults any phase added later to
 * 'still analysing'" is "a spinner that can never resolve", so a new phase must
 * fail the build instead (peek-a-bin-bo3b). `StatusBar` and `Sidebar` were
 * converted; this fourth site was not, and it is missing even the `failed` term
 * the others had.
 *
 * IT IS NOT A LIVE DEFECT, and the reason lives in another file. All three
 * phases the two predicates disagree about are unreachable while this component
 * is mounted, because `App.tsx` renders it only when `!state.peFile`:
 *   - `"failed"` is dispatched below `if (!state.peFile) return` in the
 *     detection effect, so it needs a parsed file;
 *   - `"no-code"` and `"timed-out"` likewise arise only after a successful parse;
 *   - and `handleFile`'s own catch dispatches `"idle"`, NOT `"failed"`, which is
 *     the single line keeping the common case correct.
 *
 * So the coupling is invisible: making that catch dispatch `"failed"` reads like
 * a straightforward improvement — the parse did fail — and would immediately
 * give a user with a corrupt file four grey pending circles, no error message
 * (it renders in the `else` arm), and a disabled drop zone, with a page reload
 * the only way out.
 *
 * THESE TWO TESTS RECORD THE DIVERGENCE; THEY DO NOT ENDORSE IT. Converting
 * this component to `ANALYSIS_IN_PROGRESS[analysisPhase]` is the better code and
 * would make both of them fail — that is the intended notification and NOT a
 * regression. If you make that change, delete this whole block: the conversion
 * removes the hazard, so there is nothing left to trip over. What must not
 * happen is the other order — App learning to dispatch a terminal phase here
 * while this predicate stays as it is — and that is the case these guard.
 */
describe("FileLoader phase predicate vs ANALYSIS_IN_PROGRESS", () => {
  const DIVERGENT: AnalysisPhase[] = ["failed", "no-code", "timed-out"];

  it("diverges from ANALYSIS_IN_PROGRESS on exactly the three terminal phases", () => {
    for (const phase of PHASES) {
      const { unmount } = render(
        <FileLoader
          onFile={vi.fn()}
          loading={false}
          error="parse failed"
          analysisPhase={phase}
          fileName={null}
        />,
      );
      const treatedAsRunning = showingProgress();
      const expected = DIVERGENT.includes(phase) ? true : ANALYSIS_IN_PROGRESS[phase];
      expect(treatedAsRunning, `phase ${phase}`).toBe(expected);
      unmount();
    }
    // The divergent set is exactly the phases where the shared record says
    // "not running" and this component says "running".
    for (const phase of DIVERGENT) expect(ANALYSIS_IN_PROGRESS[phase]).toBe(false);
  });

  it("would swallow the error and lock the drop zone on a terminal phase (unreachable today)", () => {
    // Characterisation, NOT a specification: this is the harm, written down.
    // Reachable only if App starts dispatching a terminal phase with no peFile.
    // A fix to either side should make this test fail — see the block comment.
    renderLoader({ analysisPhase: "failed", error: "Not a PE file" });
    expect(screen.queryByText("Not a PE file")).toBeNull();
    expect((dropZone() as HTMLButtonElement).disabled).toBe(true);
    // All four steps grey: getStepStatus has an explicit `failed` arm, so the
    // symptom was treated one layer deeper than the cause.
    expect(screen.queryAllByText("●")).toHaveLength(0);
    expect(screen.queryAllByText("✓")).toHaveLength(0);
    expect(screen.getAllByText("○")).toHaveLength(4);
  });
});

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
      { name: "saved.exe", size: 1024, lastOpened: Date.now() },
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
      { name: "t64.exe", size: 2048, lastOpened: Date.now() },
    ]);
    renderLoader();
    expect(await screen.findByText("t64.exe")).toBeTruthy();
    expect(screen.getByText("2.0 KB")).toBeTruthy();
  });

  it("hides the list while an analysis is running", async () => {
    vi.mocked(getRecentFiles).mockResolvedValueOnce([
      { name: "t64.exe", size: 2048, lastOpened: Date.now() },
    ]);
    renderLoader({ analysisPhase: "detecting-functions" });
    // Wait for the effect to have resolved, so this is "suppressed" rather than
    // "not loaded yet" — the distinction the module mock exists to make.
    await waitFor(() => expect(vi.mocked(getRecentFiles)).toHaveBeenCalled());
    expect(screen.queryByText("t64.exe")).toBeNull();
  });

  it("offers an annotations-only entry but will not load it", async () => {
    localStorage.setItem(
      "peek-a-bin:ghost.exe",
      JSON.stringify({ bookmarks: [1, 2], renames: { 3: "x" }, comments: {} }),
    );
    renderLoader();
    const name = await screen.findByText("ghost.exe");
    // No buffer in IndexedDB, so the row is inert — but the annotations are
    // advertised, which is the reason the row exists at all.
    expect(screen.getByText("2 bookmarks, 1 rename")).toBeTruthy();
    expect((name.closest("button") as HTMLButtonElement).disabled).toBe(true);
  });
});

beforeEach(() => {
  vi.mocked(getRecentFiles).mockResolvedValue([]);
  vi.mocked(loadRecentFile).mockResolvedValue(null);
  localStorage.clear();
});

afterEach(() => {
  localStorage.clear();
  vi.clearAllMocks();
});
