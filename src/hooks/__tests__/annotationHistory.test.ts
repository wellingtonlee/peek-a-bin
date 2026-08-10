import { describe, it, expect } from "vitest";
import { appReducer, initialState, type AppAction, type AppState } from "../usePEFile";

/**
 * The annotation undo/redo snapshot stack.
 *
 * Snapshot stacks classically break in four ways, all covered below: redo
 * surviving a new action, walking past either end, unbounded growth, and
 * snapshot aliasing where a stored snapshot shares a mutable reference with live
 * state and changes underneath you.
 */

const MAX_UNDO = 50;

function run(actions: AppAction[], from: AppState = initialState): AppState {
  return actions.reduce(appReducer, from);
}

describe("undo/redo — basic round trips", () => {
  it("undo restores the annotations from before the last change", () => {
    const renamed = appReducer(initialState, { type: "RENAME_FUNCTION", address: 0x1000, name: "main" });
    expect(renamed.renames).toEqual({ 0x1000: "main" });

    const undone = appReducer(renamed, { type: "UNDO_ANNOTATION" });
    expect(undone.renames).toEqual({});
  });

  it("redo re-applies what undo took away", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "main" },
      { type: "UNDO_ANNOTATION" },
      { type: "REDO_ANNOTATION" },
    ]);
    expect(state.renames).toEqual({ 0x1000: "main" });
  });

  it("restores bookmarks, renames and comments as one unit", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "main" },
      { type: "TOGGLE_BOOKMARK", address: 0x1000 },
      { type: "SET_COMMENT", address: 0x1000, text: "entry" },
    ]);
    expect(state.bookmarks).toHaveLength(1);

    // One undo reverses only the comment, the most recent change.
    const once = appReducer(state, { type: "UNDO_ANNOTATION" });
    expect(once.comments).toEqual({});
    expect(once.bookmarks).toHaveLength(1);
    expect(once.renames).toEqual({ 0x1000: "main" });

    const twice = appReducer(once, { type: "UNDO_ANNOTATION" });
    expect(twice.bookmarks).toEqual([]);
    expect(twice.renames).toEqual({ 0x1000: "main" });

    const thrice = appReducer(twice, { type: "UNDO_ANNOTATION" });
    expect(thrice.renames).toEqual({});
  });

  it("walks a multi-step sequence back and forward again", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "a" },
      { type: "RENAME_FUNCTION", address: 0x2000, name: "b" },
      { type: "RENAME_FUNCTION", address: 0x3000, name: "c" },
    ]);
    const back3 = run([
      { type: "UNDO_ANNOTATION" }, { type: "UNDO_ANNOTATION" }, { type: "UNDO_ANNOTATION" },
    ], state);
    expect(back3.renames).toEqual({});

    const fwd3 = run([
      { type: "REDO_ANNOTATION" }, { type: "REDO_ANNOTATION" }, { type: "REDO_ANNOTATION" },
    ], back3);
    expect(fwd3.renames).toEqual({ 0x1000: "a", 0x2000: "b", 0x3000: "c" });
  });

  it("every annotating action is undoable", () => {
    const cases: { label: string; action: AppAction }[] = [
      { label: "TOGGLE_BOOKMARK", action: { type: "TOGGLE_BOOKMARK", address: 0x1000 } },
      { label: "SET_BOOKMARK_LABEL", action: { type: "SET_BOOKMARK_LABEL", address: 0x1000, label: "x" } },
      { label: "RENAME_FUNCTION", action: { type: "RENAME_FUNCTION", address: 0x1000, name: "n" } },
      { label: "CLEAR_RENAME", action: { type: "CLEAR_RENAME", address: 0x1000 } },
      { label: "SET_COMMENT", action: { type: "SET_COMMENT", address: 0x1000, text: "c" } },
      { label: "DELETE_COMMENT", action: { type: "DELETE_COMMENT", address: 0x1000 } },
    ];
    for (const { label, action } of cases) {
      const next = appReducer(initialState, action);
      expect(next.annotationUndoStack, label).toHaveLength(1);
      expect(next.annotationRedoStack, label).toEqual([]);
    }
  });
});

describe("undo/redo — a new action invalidates the redo branch", () => {
  it("clears the redo stack, so redo cannot resurrect an abandoned branch", () => {
    const undone = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "original" },
      { type: "UNDO_ANNOTATION" },
    ]);
    expect(undone.annotationRedoStack).toHaveLength(1);

    const branched = appReducer(undone, { type: "RENAME_FUNCTION", address: 0x2000, name: "different" });
    expect(branched.annotationRedoStack).toEqual([]);

    // Redo is now a no-op; "original" is gone for good.
    const afterRedo = appReducer(branched, { type: "REDO_ANNOTATION" });
    expect(afterRedo.renames).toEqual({ 0x2000: "different" });
  });

  it("undo remains available on the new branch", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "original" },
      { type: "UNDO_ANNOTATION" },
      { type: "RENAME_FUNCTION", address: 0x2000, name: "different" },
      { type: "UNDO_ANNOTATION" },
    ]);
    expect(state.renames).toEqual({});
  });
});

describe("undo/redo — bounds", () => {
  it("undo past the beginning is a no-op returning the same object", () => {
    expect(appReducer(initialState, { type: "UNDO_ANNOTATION" })).toBe(initialState);

    const exhausted = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "a" },
      { type: "UNDO_ANNOTATION" },
    ]);
    expect(exhausted.annotationUndoStack).toEqual([]);
    expect(appReducer(exhausted, { type: "UNDO_ANNOTATION" })).toBe(exhausted);
  });

  it("redo past the end is a no-op returning the same object", () => {
    expect(appReducer(initialState, { type: "REDO_ANNOTATION" })).toBe(initialState);

    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "a" },
      { type: "UNDO_ANNOTATION" },
      { type: "REDO_ANNOTATION" },
    ]);
    expect(state.annotationRedoStack).toEqual([]);
    expect(appReducer(state, { type: "REDO_ANNOTATION" })).toBe(state);
  });

  it("repeated undo at the floor does not corrupt the redo stack", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "a" },
      { type: "UNDO_ANNOTATION" },
      { type: "UNDO_ANNOTATION" },
      { type: "UNDO_ANNOTATION" },
    ]);
    expect(state.annotationRedoStack).toHaveLength(1);
    expect(appReducer(state, { type: "REDO_ANNOTATION" }).renames).toEqual({ 0x1000: "a" });
  });
});

describe("undo/redo — growth is bounded", () => {
  it(`caps the undo stack at ${MAX_UNDO}, dropping the oldest snapshot`, () => {
    let state: AppState = initialState;
    for (let i = 1; i <= 60; i++) {
      state = appReducer(state, { type: "RENAME_FUNCTION", address: i, name: `f${i}` });
    }
    expect(state.annotationUndoStack).toHaveLength(MAX_UNDO);

    // The dropped snapshots are the oldest, so undoing all the way back cannot
    // reach the empty state — it stops at whatever the oldest retained snapshot holds.
    let unwound = state;
    for (let i = 0; i < MAX_UNDO; i++) {
      unwound = appReducer(unwound, { type: "UNDO_ANNOTATION" });
    }
    expect(unwound.annotationUndoStack).toEqual([]);
    expect(Object.keys(unwound.renames)).toHaveLength(60 - MAX_UNDO);
  });

  it(`caps the redo stack at ${MAX_UNDO}`, () => {
    let state: AppState = initialState;
    for (let i = 1; i <= 60; i++) {
      state = appReducer(state, { type: "RENAME_FUNCTION", address: i, name: `f${i}` });
    }
    for (let i = 0; i < MAX_UNDO; i++) {
      state = appReducer(state, { type: "UNDO_ANNOTATION" });
    }
    expect(state.annotationRedoStack).toHaveLength(MAX_UNDO);
  });
});

describe("undo/redo — snapshots do not alias live state", () => {
  it("a stored snapshot is unaffected by later edits", () => {
    const first = appReducer(initialState, { type: "RENAME_FUNCTION", address: 0x1000, name: "a" });
    const snapshot = first.annotationUndoStack[0];
    const snapshotJson = JSON.stringify(snapshot);

    // Pile on several more edits of every annotation kind.
    run([
      { type: "RENAME_FUNCTION", address: 0x2000, name: "b" },
      { type: "TOGGLE_BOOKMARK", address: 0x3000 },
      { type: "SET_COMMENT", address: 0x4000, text: "c" },
      { type: "CLEAR_RENAME", address: 0x1000 },
    ], first);

    expect(JSON.stringify(snapshot)).toBe(snapshotJson);
  });

  it("undoing twice to the same snapshot yields the same values both times", () => {
    const base = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "a" },
      { type: "TOGGLE_BOOKMARK", address: 0x1000 },
    ]);
    const firstUndo = appReducer(base, { type: "UNDO_ANNOTATION" });
    const redone = appReducer(firstUndo, { type: "REDO_ANNOTATION" });
    const secondUndo = appReducer(redone, { type: "UNDO_ANNOTATION" });

    expect(secondUndo.bookmarks).toEqual(firstUndo.bookmarks);
    expect(secondUndo.renames).toEqual(firstUndo.renames);
    expect(secondUndo.comments).toEqual(firstUndo.comments);
  });

  it("restored annotation objects are not the same references the caller kept", () => {
    const base = appReducer(initialState, { type: "RENAME_FUNCTION", address: 0x1000, name: "a" });
    const liveRenames = base.renames;
    const undone = appReducer(base, { type: "UNDO_ANNOTATION" });
    // Undo swaps in the older object rather than editing the current one.
    expect(undone.renames).not.toBe(liveRenames);
  });
});

describe("undo/redo — actions that bypass the stack", () => {
  it("LOAD_PERSISTED does not create an undo entry", () => {
    const loaded = appReducer(initialState, {
      type: "LOAD_PERSISTED",
      bookmarks: [{ address: 1, label: "" }],
      renames: { 1: "x" },
      comments: {},
    });
    // Restoring saved state on file open is not a user edit, so it is not undoable.
    expect(loaded.annotationUndoStack).toEqual([]);
  });

  it("IMPORT_FULL_ANALYSIS is undoable", () => {
    const imported = appReducer(initialState, {
      type: "IMPORT_FULL_ANALYSIS",
      bookmarks: [{ address: 1, label: "" }],
      renames: { 1: "x" },
      comments: {},
      hexPatches: new Map(),
    });
    expect(imported.annotationUndoStack).toHaveLength(1);
    expect(appReducer(imported, { type: "UNDO_ANNOTATION" }).renames).toEqual({});
  });

  // KNOWN BUG (usePEFile.ts:330-342, IMPORT_ANNOTATIONS).
  //
  // IMPORT_ANNOTATIONS neither pushes an undo snapshot nor clears the redo stack,
  // unlike IMPORT_FULL_ANALYSIS directly below it which does both. Two consequences:
  //
  //   1. An import cannot be undone.
  //   2. Worse — a redo entry left over from before the import survives it, and
  //      redoing silently reverts the imported annotations.
  //
  // This is reachable in normal use: useMcpSync dispatches IMPORT_ANNOTATIONS for
  // every annotation message from the MCP bridge, so a remote sync arriving while
  // the user has an open redo branch can be wiped by a single Ctrl-Shift-Z.
  //
  // These assertions pin the CURRENT behaviour so the fix is visible when made.
  // Whether an import should be undoable is a product call — see the report.
  it("KNOWN BUG: IMPORT_ANNOTATIONS is not undoable", () => {
    const imported = appReducer(initialState, {
      type: "IMPORT_ANNOTATIONS",
      bookmarks: [{ address: 1, label: "" }],
      renames: { 1: "imported" },
      comments: {},
    });
    expect(imported.annotationUndoStack).toEqual([]);
    // Undo cannot reach back past it.
    expect(appReducer(imported, { type: "UNDO_ANNOTATION" })).toBe(imported);
  });

  it("KNOWN BUG: a stale redo entry survives IMPORT_ANNOTATIONS and reverts it", () => {
    const undone = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "local" },
      { type: "UNDO_ANNOTATION" },
    ]);
    expect(undone.annotationRedoStack).toHaveLength(1);

    const imported = appReducer(undone, {
      type: "IMPORT_ANNOTATIONS",
      bookmarks: [],
      renames: { 0x2000: "from-mcp" },
      comments: {},
    });
    expect(imported.renames).toEqual({ 0x2000: "from-mcp" });
    // The redo branch was never invalidated by the import.
    expect(imported.annotationRedoStack).toHaveLength(1);

    const redone = appReducer(imported, { type: "REDO_ANNOTATION" });
    // The imported rename is gone, replaced by the pre-import snapshot.
    expect(redone.renames).toEqual({ 0x1000: "local" });
    expect(redone.renames[0x2000]).toBeUndefined();
  });
});
