import { describe, expect, it } from "vitest";
import type { DisasmFunction } from "../../disasm/types";
import type { PEFile } from "../../pe/types";
import { type AppAction, type AppState, appReducer, initialState } from "../usePEFile";

/**
 * Reducer-level coverage for `appReducer`.
 *
 * A wrong branch here corrupts application state silently rather than throwing,
 * so these assert the shape of the result, not just that it changed. Two themes
 * recur because they are the failure modes that do not announce themselves:
 *
 *   - returning the *same object reference* when something did change, which
 *     makes React skip the re-render, and
 *   - writing one field while forgetting a sibling that must move with it.
 */

function fn(address: number, size = 0x10, name = `sub_${address.toString(16)}`): DisasmFunction {
  return { address, size, name } as DisasmFunction;
}

/** Enough of a PEFile for SET_PE_FILE; the reducer only reads the two header fields. */
function peFile(imageBase = 0x400000, entryRva = 0x1000): PEFile {
  return {
    optionalHeader: { imageBase, addressOfEntryPoint: entryRva },
    sections: [],
    imports: [],
    exports: [],
  } as unknown as PEFile;
}

function run(actions: AppAction[], from: AppState = initialState): AppState {
  return actions.reduce(appReducer, from);
}

describe("appReducer — loading and file lifecycle", () => {
  it("SET_LOADING sets loading and clears a previous error", () => {
    const errored = appReducer(initialState, { type: "SET_ERROR", error: "bad magic" });
    const next = appReducer(errored, { type: "SET_LOADING" });
    expect(next.loading).toBe(true);
    expect(next.error).toBeNull();
  });

  it("SET_ERROR clears loading so the UI cannot spin forever", () => {
    const loading = appReducer(initialState, { type: "SET_LOADING" });
    const next = appReducer(loading, { type: "SET_ERROR", error: "truncated" });
    expect(next.error).toBe("truncated");
    expect(next.loading).toBe(false);
  });

  it("SET_PE_FILE seeds address, history and index together from the entry point", () => {
    const next = appReducer(initialState, {
      type: "SET_PE_FILE",
      peFile: peFile(0x400000, 0x1000),
      fileName: "a.exe",
    });
    expect(next.currentAddress).toBe(0x401000);
    expect(next.addressHistory).toEqual([0x401000]);
    expect(next.historyIndex).toBe(0);
    expect(next.fileName).toBe("a.exe");
    expect(next.loading).toBe(false);
    expect(next.error).toBeNull();
  });

  it("SET_PE_FILE without a name nulls fileName rather than leaving the previous one", () => {
    const withName = appReducer(initialState, {
      type: "SET_PE_FILE",
      peFile: peFile(),
      fileName: "first.exe",
    });
    const without = appReducer(withName, { type: "SET_PE_FILE", peFile: peFile() });
    expect(without.fileName).toBeNull();
  });

  it("RESET returns to the initial state but keeps disasmReady", () => {
    const dirty = run([
      { type: "SET_DISASM_READY" },
      { type: "SET_PE_FILE", peFile: peFile(), fileName: "a.exe" },
      { type: "RENAME_FUNCTION", address: 0x401000, name: "main" },
      { type: "TOGGLE_BOOKMARK", address: 0x402000 },
      { type: "PATCH_BYTE", offset: 4, value: 0x90 },
    ]);
    const next = appReducer(dirty, { type: "RESET" });

    expect(next.disasmReady).toBe(true); // the Capstone worker survives a file swap
    expect(next.peFile).toBeNull();
    expect(next.fileName).toBeNull();
    expect(next.renames).toEqual({});
    expect(next.bookmarks).toEqual([]);
    expect(next.hexPatches.size).toBe(0);
    expect(next.annotationUndoStack).toEqual([]);
    expect(next.annotationRedoStack).toEqual([]);
  });

  it("an unknown action returns the identical state object", () => {
    const weird = { type: "NOT_A_REAL_ACTION" } as unknown as AppAction;
    expect(appReducer(initialState, weird)).toBe(initialState);
  });
});

describe("appReducer — address history", () => {
  it("SET_ADDRESS appends and advances the index", () => {
    const next = run([
      { type: "SET_ADDRESS", address: 0x1000 },
      { type: "SET_ADDRESS", address: 0x2000 },
    ]);
    expect(next.addressHistory).toEqual([0x1000, 0x2000]);
    expect(next.historyIndex).toBe(1);
    expect(next.currentAddress).toBe(0x2000);
  });

  it("navigating to the address already under the cursor does not duplicate it", () => {
    const next = run([
      { type: "SET_ADDRESS", address: 0x1000 },
      { type: "SET_ADDRESS", address: 0x1000 },
    ]);
    expect(next.addressHistory).toEqual([0x1000]);
    expect(next.historyIndex).toBe(0);
  });

  it("NAV_BACK then NAV_FORWARD walks without mutating the history", () => {
    const three = run([
      { type: "SET_ADDRESS", address: 0x1000 },
      { type: "SET_ADDRESS", address: 0x2000 },
      { type: "SET_ADDRESS", address: 0x3000 },
    ]);
    const back = appReducer(three, { type: "NAV_BACK" });
    expect(back.currentAddress).toBe(0x2000);
    expect(back.historyIndex).toBe(1);
    expect(back.addressHistory).toEqual([0x1000, 0x2000, 0x3000]);

    const fwd = appReducer(back, { type: "NAV_FORWARD" });
    expect(fwd.currentAddress).toBe(0x3000);
    expect(fwd.historyIndex).toBe(2);
  });

  it("NAV_BACK at the beginning is a no-op returning the same object", () => {
    const one = appReducer(initialState, { type: "SET_ADDRESS", address: 0x1000 });
    expect(appReducer(one, { type: "NAV_BACK" })).toBe(one);
    // And from a fresh state, where historyIndex is -1.
    expect(appReducer(initialState, { type: "NAV_BACK" })).toBe(initialState);
  });

  it("NAV_FORWARD at the end is a no-op returning the same object", () => {
    const one = appReducer(initialState, { type: "SET_ADDRESS", address: 0x1000 });
    expect(appReducer(one, { type: "NAV_FORWARD" })).toBe(one);
    expect(appReducer(initialState, { type: "NAV_FORWARD" })).toBe(initialState);
  });

  it("navigating after going back truncates the forward history", () => {
    const three = run([
      { type: "SET_ADDRESS", address: 0x1000 },
      { type: "SET_ADDRESS", address: 0x2000 },
      { type: "SET_ADDRESS", address: 0x3000 },
    ]);
    const back = appReducer(three, { type: "NAV_BACK" }); // at 0x2000, index 1
    const branched = appReducer(back, { type: "SET_ADDRESS", address: 0x9000 });

    expect(branched.addressHistory).toEqual([0x1000, 0x2000, 0x9000]);
    expect(branched.historyIndex).toBe(2);
    // 0x3000 is unreachable now.
    expect(appReducer(branched, { type: "NAV_FORWARD" })).toBe(branched);
  });

  it("caps the history at 50 entries, dropping the oldest", () => {
    let state = initialState;
    for (let i = 1; i <= 60; i++) {
      state = appReducer(state, { type: "SET_ADDRESS", address: i * 0x100 });
    }
    expect(state.addressHistory).toHaveLength(50);
    expect(state.historyIndex).toBe(49);
    expect(state.addressHistory[0]).toBe(11 * 0x100);
    expect(state.addressHistory[49]).toBe(60 * 0x100);
    expect(state.currentAddress).toBe(60 * 0x100);
  });
});

describe("appReducer — bookmarks", () => {
  it("TOGGLE_BOOKMARK adds then removes at the same address", () => {
    const added = appReducer(initialState, { type: "TOGGLE_BOOKMARK", address: 0x401000 });
    expect(added.bookmarks).toEqual([{ address: 0x401000, label: "" }]);

    const removed = appReducer(added, { type: "TOGGLE_BOOKMARK", address: 0x401000 });
    expect(removed.bookmarks).toEqual([]);
  });

  it("TOGGLE_BOOKMARK with no address uses the current address", () => {
    const at = appReducer(initialState, { type: "SET_ADDRESS", address: 0x4055aa });
    const marked = appReducer(at, { type: "TOGGLE_BOOKMARK" });
    expect(marked.bookmarks).toEqual([{ address: 0x4055aa, label: "" }]);
  });

  it("removes only the toggled bookmark, leaving siblings in order", () => {
    const state = run([
      { type: "TOGGLE_BOOKMARK", address: 0x1000 },
      { type: "TOGGLE_BOOKMARK", address: 0x2000 },
      { type: "TOGGLE_BOOKMARK", address: 0x3000 },
      { type: "TOGGLE_BOOKMARK", address: 0x2000 },
    ]);
    expect(state.bookmarks.map((b) => b.address)).toEqual([0x1000, 0x3000]);
  });

  it("SET_BOOKMARK_LABEL updates only the matching bookmark", () => {
    const state = run([
      { type: "TOGGLE_BOOKMARK", address: 0x1000 },
      { type: "TOGGLE_BOOKMARK", address: 0x2000 },
      { type: "SET_BOOKMARK_LABEL", address: 0x2000, label: "decrypt loop" },
    ]);
    expect(state.bookmarks).toEqual([
      { address: 0x1000, label: "" },
      { address: 0x2000, label: "decrypt loop" },
    ]);
  });

  it("SET_BOOKMARK_LABEL for an unknown address changes no labels", () => {
    const state = run([
      { type: "TOGGLE_BOOKMARK", address: 0x1000 },
      { type: "SET_BOOKMARK_LABEL", address: 0xdead, label: "ghost" },
    ]);
    expect(state.bookmarks).toEqual([{ address: 0x1000, label: "" }]);
  });
});

describe("appReducer — renames and comments", () => {
  it("RENAME_FUNCTION and CLEAR_RENAME round-trip", () => {
    const named = appReducer(initialState, {
      type: "RENAME_FUNCTION",
      address: 0x1000,
      name: "main",
    });
    expect(named.renames).toEqual({ 0x1000: "main" });

    const cleared = appReducer(named, { type: "CLEAR_RENAME", address: 0x1000 });
    expect(cleared.renames).toEqual({});
  });

  it("CLEAR_RENAME leaves other renames intact", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "a" },
      { type: "RENAME_FUNCTION", address: 0x2000, name: "b" },
      { type: "CLEAR_RENAME", address: 0x1000 },
    ]);
    expect(state.renames).toEqual({ 0x2000: "b" });
  });

  it("CLEAR_RENAME on an absent address is harmless", () => {
    const state = appReducer(initialState, { type: "CLEAR_RENAME", address: 0xdead });
    expect(state.renames).toEqual({});
  });

  it("renaming the same address twice overwrites rather than duplicating", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "first" },
      { type: "RENAME_FUNCTION", address: 0x1000, name: "second" },
    ]);
    expect(state.renames).toEqual({ 0x1000: "second" });
  });

  it("SET_COMMENT and DELETE_COMMENT round-trip", () => {
    const commented = appReducer(initialState, {
      type: "SET_COMMENT",
      address: 0x1000,
      text: "loop head",
    });
    expect(commented.comments).toEqual({ 0x1000: "loop head" });

    const deleted = appReducer(commented, { type: "DELETE_COMMENT", address: 0x1000 });
    expect(deleted.comments).toEqual({});
  });

  it("an empty comment is stored, not treated as a delete", () => {
    const state = appReducer(initialState, { type: "SET_COMMENT", address: 0x1000, text: "" });
    expect(state.comments).toEqual({ 0x1000: "" });
  });

  it("renames and comments are independent maps", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "main" },
      { type: "SET_COMMENT", address: 0x1000, text: "entry" },
      { type: "CLEAR_RENAME", address: 0x1000 },
    ]);
    expect(state.renames).toEqual({});
    expect(state.comments).toEqual({ 0x1000: "entry" });
  });
});

describe("appReducer — annotation import and persistence", () => {
  it("LOAD_PERSISTED replaces annotations wholesale", () => {
    const dirty = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "old" },
      { type: "TOGGLE_BOOKMARK", address: 0x1000 },
    ]);
    const loaded = appReducer(dirty, {
      type: "LOAD_PERSISTED",
      bookmarks: [{ address: 0x9000, label: "persisted" }],
      renames: { 0x9000: "restored" },
      comments: { 0x9000: "note" },
    });
    expect(loaded.bookmarks).toEqual([{ address: 0x9000, label: "persisted" }]);
    expect(loaded.renames).toEqual({ 0x9000: "restored" });
    expect(loaded.comments).toEqual({ 0x9000: "note" });
  });

  it("IMPORT_ANNOTATIONS merges, with imported values winning on renames", () => {
    const existing = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "local" },
      { type: "TOGGLE_BOOKMARK", address: 0x1000 },
    ]);
    const merged = appReducer(existing, {
      type: "IMPORT_ANNOTATIONS",
      bookmarks: [
        { address: 0x1000, label: "dupe" },
        { address: 0x2000, label: "new" },
      ],
      renames: { 0x1000: "imported", 0x2000: "other" },
      comments: { 0x2000: "hi" },
    });

    // Bookmark at an address we already have is skipped, so the local label survives.
    expect(merged.bookmarks).toEqual([
      { address: 0x1000, label: "" },
      { address: 0x2000, label: "new" },
    ]);
    // Renames are a plain spread, so the import wins.
    expect(merged.renames).toEqual({ 0x1000: "imported", 0x2000: "other" });
    expect(merged.comments).toEqual({ 0x2000: "hi" });
  });

  it("IMPORT_FULL_ANALYSIS also merges hex patches", () => {
    const existing = run([{ type: "PATCH_BYTE", offset: 0x10, value: 0x90 }]);
    const merged = appReducer(existing, {
      type: "IMPORT_FULL_ANALYSIS",
      bookmarks: [],
      renames: {},
      comments: {},
      hexPatches: new Map([[0x20, 0xcc]]),
    });
    expect([...merged.hexPatches.entries()].sort()).toEqual([
      [0x10, 0x90],
      [0x20, 0xcc],
    ]);
  });

  it("IMPORT_FULL_ANALYSIS lets the imported patch win on a colliding offset", () => {
    const existing = run([{ type: "PATCH_BYTE", offset: 0x10, value: 0x90 }]);
    const merged = appReducer(existing, {
      type: "IMPORT_FULL_ANALYSIS",
      bookmarks: [],
      renames: {},
      comments: {},
      hexPatches: new Map([[0x10, 0xcc]]),
    });
    expect(merged.hexPatches.get(0x10)).toBe(0xcc);
  });
});

describe("appReducer — hex patches", () => {
  it("PATCH_BYTE writes into a fresh Map, never mutating the old one", () => {
    const before = appReducer(initialState, { type: "PATCH_BYTE", offset: 0, value: 0x41 });
    const after = appReducer(before, { type: "PATCH_BYTE", offset: 1, value: 0x42 });
    expect(after.hexPatches).not.toBe(before.hexPatches);
    expect(before.hexPatches.size).toBe(1);
    expect(after.hexPatches.size).toBe(2);
  });

  it("patching the same offset twice overwrites", () => {
    const state = run([
      { type: "PATCH_BYTE", offset: 4, value: 0x90 },
      { type: "PATCH_BYTE", offset: 4, value: 0xcc },
    ]);
    expect(state.hexPatches.get(4)).toBe(0xcc);
    expect(state.hexPatches.size).toBe(1);
  });

  it("UNDO_PATCH removes one offset and CLEAR_PATCHES removes all", () => {
    const two = run([
      { type: "PATCH_BYTE", offset: 4, value: 0x90 },
      { type: "PATCH_BYTE", offset: 8, value: 0xcc },
    ]);
    const undone = appReducer(two, { type: "UNDO_PATCH", offset: 4 });
    expect([...undone.hexPatches.keys()]).toEqual([8]);

    expect(appReducer(undone, { type: "CLEAR_PATCHES" }).hexPatches.size).toBe(0);
  });

  it("UNDO_PATCH on an unpatched offset is harmless", () => {
    const state = appReducer(initialState, { type: "UNDO_PATCH", offset: 0xdead });
    expect(state.hexPatches.size).toBe(0);
  });

  it("a patch of 0 is stored, not treated as absent", () => {
    const state = appReducer(initialState, { type: "PATCH_BYTE", offset: 0, value: 0 });
    expect(state.hexPatches.has(0)).toBe(true);
    expect(state.hexPatches.get(0)).toBe(0);
  });
});

describe("appReducer — call stack", () => {
  it("PUSH_CALL_STACK appends, carrying the optional view snapshot", () => {
    const snap = { viewMode: "graph" as const, graphPan: { x: 1, y: 2 }, graphZoom: 1.5 };
    const state = run([
      { type: "PUSH_CALL_STACK", address: 0x1000, name: "a" },
      { type: "PUSH_CALL_STACK", address: 0x2000, name: "b", viewSnapshot: snap },
    ]);
    expect(state.callStack).toHaveLength(2);
    expect(state.callStack[0].viewSnapshot).toBeUndefined();
    expect(state.callStack[1].viewSnapshot).toEqual(snap);
  });

  it("caps the call stack at 8 frames, dropping the oldest", () => {
    let state = initialState;
    for (let i = 1; i <= 12; i++) {
      state = appReducer(state, { type: "PUSH_CALL_STACK", address: i * 0x100, name: `f${i}` });
    }
    expect(state.callStack).toHaveLength(8);
    expect(state.callStack[0].name).toBe("f5");
    expect(state.callStack[7].name).toBe("f12");
  });

  it("POP_CALL_STACK truncates to the given index, dropping that frame too", () => {
    const three = run([
      { type: "PUSH_CALL_STACK", address: 0x1000, name: "a" },
      { type: "PUSH_CALL_STACK", address: 0x2000, name: "b" },
      { type: "PUSH_CALL_STACK", address: 0x3000, name: "c" },
    ]);
    expect(
      appReducer(three, { type: "POP_CALL_STACK", index: 1 }).callStack.map((f) => f.name),
    ).toEqual(["a"]);
    expect(appReducer(three, { type: "POP_CALL_STACK", index: 0 }).callStack).toEqual([]);
  });

  it("CLEAR_CALL_STACK empties it", () => {
    const one = appReducer(initialState, { type: "PUSH_CALL_STACK", address: 0x1000, name: "a" });
    expect(appReducer(one, { type: "CLEAR_CALL_STACK" }).callStack).toEqual([]);
  });
});

describe("appReducer — analysis results", () => {
  it("SET_FUNCTIONS, SET_ANOMALIES and SET_IRP_HANDLERS replace wholesale", () => {
    const withFuncs = appReducer(initialState, {
      type: "SET_FUNCTIONS",
      functions: [fn(0x1000), fn(0x2000)],
    });
    expect(withFuncs.functions).toHaveLength(2);
    expect(appReducer(withFuncs, { type: "SET_FUNCTIONS", functions: [] }).functions).toEqual([]);
  });

  it("SET_STRINGS is ignored when no file is loaded", () => {
    const next = appReducer(initialState, {
      type: "SET_STRINGS",
      strings: new Map([[1, "a"]]),
      stringTypes: new Map(),
    });
    expect(next).toBe(initialState);
  });

  it("SET_STRINGS writes through onto the loaded PE file", () => {
    const loaded = appReducer(initialState, { type: "SET_PE_FILE", peFile: peFile() });
    const next = appReducer(loaded, {
      type: "SET_STRINGS",
      strings: new Map([[0x1000, "hello"]]),
      stringTypes: new Map([[0x1000, "ascii"]]),
    });
    expect(next.peFile?.strings.get(0x1000)).toBe("hello");
    // A fresh peFile object, so memoised consumers actually re-run.
    expect(next.peFile).not.toBe(loaded.peFile);
  });

  it("SET_XREFS keeps the existing dataXrefs when the action omits them", () => {
    const first = appReducer(initialState, {
      type: "SET_XREFS",
      stringXrefs: new Map([[1, [2]]]),
      importXrefs: new Map(),
      dataXrefs: new Map([[3, [4]]]),
    });
    const second = appReducer(first, {
      type: "SET_XREFS",
      stringXrefs: new Map(),
      importXrefs: new Map(),
    });
    expect(second.dataXrefs).toBe(first.dataXrefs);
    expect(second.stringXrefs?.size).toBe(0);
  });

  it("SET_ANALYSIS_PHASE reaches the failed state, so a bad parse cannot spin forever", () => {
    const next = appReducer(initialState, { type: "SET_ANALYSIS_PHASE", phase: "failed" });
    expect(next.analysisPhase).toBe("failed");
  });

  // peek-a-bin-8ru3 / peek-a-bin-x7b. The engine refuses to disassemble an
  // image whose machine type it has no decoder for, and the entire point of
  // refusing per *stage* rather than at load is that the headers, sections,
  // imports, exports, resources and strings still reach the user. That holds
  // only if the failure path leaves `peFile` alone: App renders the tabs off
  // `state.peFile`, so a branch that cleared it would blank every one of them
  // and turn a precise refusal back into "something went wrong". An unguarded
  // throw discarded exactly this in `mcp/session.ts`'s loadFile.
  describe("a failed analysis keeps everything the parser recovered", () => {
    const loaded = run([
      { type: "SET_PE_FILE", peFile: peFile(), fileName: "arm32.exe" },
      { type: "SET_ANALYSIS_PHASE", phase: "detecting-functions" },
    ]);

    it("SET_ERROR after a successful parse does not drop the PE", () => {
      const next = appReducer(loaded, { type: "SET_ERROR", error: "Analysis failed: no decoder" });
      expect(next.peFile).toBe(loaded.peFile);
      expect(next.fileName).toBe("arm32.exe");
      expect(next.error).toBe("Analysis failed: no decoder");
    });

    it("neither does the failed phase", () => {
      const next = appReducer(loaded, { type: "SET_ANALYSIS_PHASE", phase: "failed" });
      expect(next.peFile).toBe(loaded.peFile);
      expect(next.analysisPhase).toBe("failed");
    });

    it("holds the phase and the reason at the same time", () => {
      // App dispatches the two separately, so neither may clear the other —
      // the phase without the message is the "something went wrong" screen.
      const next = run(
        [
          { type: "SET_ANALYSIS_PHASE", phase: "failed" },
          { type: "SET_ERROR", error: "Cross-reference analysis is not supported" },
        ],
        loaded,
      );
      expect(next.analysisPhase).toBe("failed");
      expect(next.error).toBe("Cross-reference analysis is not supported");
      expect(next.peFile).toBe(loaded.peFile);
    });

    it("an empty function list is not itself a reset — the file is still loaded", () => {
      // Detection answers `[]` rather than throwing for an unsupported image.
      const next = appReducer(loaded, { type: "SET_FUNCTIONS", functions: [] });
      expect(next.functions).toEqual([]);
      expect(next.peFile).toBe(loaded.peFile);
    });
  });

  it("SET_CURRENT_INSTRUCTION and SET_CURRENT_BLOCK accept null to clear", () => {
    const set = run([
      { type: "SET_CURRENT_INSTRUCTION", instruction: { bytes: [0x90], size: 1 } },
      { type: "SET_CURRENT_BLOCK", block: { startAddr: 0x1000, endAddr: 0x1010 } },
    ]);
    expect(set.currentInstruction).not.toBeNull();
    const cleared = run(
      [
        { type: "SET_CURRENT_INSTRUCTION", instruction: null },
        { type: "SET_CURRENT_BLOCK", block: null },
      ],
      set,
    );
    expect(cleared.currentInstruction).toBeNull();
    expect(cleared.currentBlock).toBeNull();
  });

  it("SET_DISASM_READY is sticky", () => {
    const ready = appReducer(initialState, { type: "SET_DISASM_READY" });
    expect(appReducer(ready, { type: "SET_DISASM_READY" }).disasmReady).toBe(true);
  });
});

describe("appReducer — batch rename", () => {
  it("BATCH_RENAME_START opens the run in the decompiling phase", () => {
    const next = appReducer(initialState, { type: "BATCH_RENAME_START", total: 12 });
    expect(next.batchRename).toEqual({
      status: "decompiling",
      progress: { done: 0, total: 12 },
      results: [],
      error: null,
    });
  });

  it("every batch-rename action is ignored when no run is open", () => {
    for (const action of [
      { type: "BATCH_RENAME_PROGRESS", done: 1 },
      { type: "BATCH_RENAME_DONE", results: [] },
      { type: "BATCH_RENAME_ERROR", error: "x" },
    ] as AppAction[]) {
      expect(appReducer(initialState, action), action.type).toBe(initialState);
    }
  });

  // Regression: the status ternary used to read
  // `status === "decompiling" ? "decompiling" : "running"`, which can only ever
  // re-select the value it just tested for — so the run was pinned to
  // "decompiling" and the modal's "Generating names…" branch was dead code.
  it("progress alone does not change the phase", () => {
    const started = appReducer(initialState, { type: "BATCH_RENAME_START", total: 3 });
    const progressed = appReducer(started, { type: "BATCH_RENAME_PROGRESS", done: 2 });
    expect(progressed.batchRename?.status).toBe("decompiling");
    expect(progressed.batchRename?.progress).toEqual({ done: 2, total: 3 });
  });

  it("an explicit phase moves the run from decompiling to running", () => {
    const state = run([
      { type: "BATCH_RENAME_START", total: 3 },
      { type: "BATCH_RENAME_PROGRESS", done: 3 },
      { type: "BATCH_RENAME_PROGRESS", done: 0, phase: "running" },
    ]);
    expect(state.batchRename?.status).toBe("running");
    expect(state.batchRename?.progress).toEqual({ done: 0, total: 3 });
  });

  it("progress after the phase change keeps the running status", () => {
    const state = run([
      { type: "BATCH_RENAME_START", total: 3 },
      { type: "BATCH_RENAME_PROGRESS", done: 0, phase: "running" },
      { type: "BATCH_RENAME_PROGRESS", done: 2 },
    ]);
    expect(state.batchRename?.status).toBe("running");
  });

  it("BATCH_RENAME_DONE moves to review and clears any earlier error", () => {
    const state = run([
      { type: "BATCH_RENAME_START", total: 1 },
      { type: "BATCH_RENAME_ERROR", error: "transient" },
      {
        type: "BATCH_RENAME_DONE",
        results: [
          {
            address: 0x1000,
            currentName: "sub_1000",
            suggestedName: "main",
            confidence: 0.9,
            reasoning: "",
            accepted: null,
          },
        ],
      },
    ]);
    expect(state.batchRename?.status).toBe("review");
    expect(state.batchRename?.error).toBeNull();
    expect(state.batchRename?.results).toHaveLength(1);
  });

  it("BATCH_RENAME_ACCEPT applies only accepted suggestions and closes the modal", () => {
    const started = appReducer(initialState, { type: "BATCH_RENAME_START", total: 3 });
    const next = appReducer(started, {
      type: "BATCH_RENAME_ACCEPT",
      results: [
        {
          address: 0x1000,
          currentName: "sub_1000",
          suggestedName: "yes",
          confidence: 1,
          reasoning: "",
          accepted: true,
        },
        {
          address: 0x2000,
          currentName: "sub_2000",
          suggestedName: "no",
          confidence: 1,
          reasoning: "",
          accepted: false,
        },
        {
          address: 0x3000,
          currentName: "sub_3000",
          suggestedName: "undecided",
          confidence: 1,
          reasoning: "",
          accepted: null,
        },
      ],
    });
    expect(next.renames).toEqual({ 0x1000: "yes" });
    expect(next.batchRename).toBeNull();
  });

  it("BATCH_RENAME_ACCEPT is undoable", () => {
    const started = appReducer(initialState, { type: "BATCH_RENAME_START", total: 1 });
    const accepted = appReducer(started, {
      type: "BATCH_RENAME_ACCEPT",
      results: [
        {
          address: 0x1000,
          currentName: "sub_1000",
          suggestedName: "main",
          confidence: 1,
          reasoning: "",
          accepted: true,
        },
      ],
    });
    expect(accepted.annotationUndoStack).toHaveLength(1);
    expect(appReducer(accepted, { type: "UNDO_ANNOTATION" }).renames).toEqual({});
  });

  it("BATCH_RENAME_DISMISS drops the run without touching renames", () => {
    const state = run([
      { type: "RENAME_FUNCTION", address: 0x1000, name: "kept" },
      { type: "BATCH_RENAME_START", total: 1 },
      { type: "BATCH_RENAME_DISMISS" },
    ]);
    expect(state.batchRename).toBeNull();
    expect(state.renames).toEqual({ 0x1000: "kept" });
  });
});

describe("appReducer — AI report", () => {
  it("AI_REPORT_START opens a streaming report with empty content", () => {
    const next = appReducer(initialState, { type: "AI_REPORT_START" });
    expect(next.aiReport).toEqual({ status: "streaming", content: "", error: null });
  });

  it("tokens replace content wholesale, matching the accumulate-then-send client", () => {
    const state = run([
      { type: "AI_REPORT_START" },
      { type: "AI_REPORT_TOKEN", content: "# Rep" },
      { type: "AI_REPORT_TOKEN", content: "# Report" },
    ]);
    expect(state.aiReport?.content).toBe("# Report");
  });

  it("AI_REPORT_DONE and AI_REPORT_ERROR set terminal statuses", () => {
    const streaming = appReducer(initialState, { type: "AI_REPORT_START" });
    expect(appReducer(streaming, { type: "AI_REPORT_DONE" }).aiReport?.status).toBe("done");

    const errored = appReducer(streaming, { type: "AI_REPORT_ERROR", error: "rate limited" });
    expect(errored.aiReport?.status).toBe("error");
    expect(errored.aiReport?.error).toBe("rate limited");
  });

  it("report actions are ignored when no report is open", () => {
    for (const action of [
      { type: "AI_REPORT_TOKEN", content: "x" },
      { type: "AI_REPORT_DONE" },
      { type: "AI_REPORT_ERROR", error: "x" },
    ] as AppAction[]) {
      expect(appReducer(initialState, action), action.type).toBe(initialState);
    }
  });

  it("AI_REPORT_DISMISS clears the report", () => {
    const streaming = appReducer(initialState, { type: "AI_REPORT_START" });
    expect(appReducer(streaming, { type: "AI_REPORT_DISMISS" }).aiReport).toBeNull();
  });
});

describe("appReducer — no branch mutates its input", () => {
  // A branch that mutates instead of replacing returns the same reference, and
  // React then skips the re-render. Rather than trusting each branch, snapshot
  // the whole state and assert nothing moved underneath it.
  const base = run([
    { type: "SET_PE_FILE", peFile: peFile(), fileName: "a.exe" },
    { type: "SET_FUNCTIONS", functions: [fn(0x401000)] },
    { type: "SET_ADDRESS", address: 0x401000 },
    { type: "RENAME_FUNCTION", address: 0x401000, name: "main" },
    { type: "TOGGLE_BOOKMARK", address: 0x401000 },
    { type: "SET_COMMENT", address: 0x401000, text: "entry" },
    { type: "PATCH_BYTE", offset: 0, value: 0x90 },
    { type: "PUSH_CALL_STACK", address: 0x402000, name: "callee" },
    { type: "BATCH_RENAME_START", total: 1 },
    { type: "AI_REPORT_START" },
    { type: "AI_SCAN_START", total: 1 },
  ]);

  const actions: AppAction[] = [
    { type: "SET_LOADING" },
    { type: "SET_ERROR", error: "e" },
    { type: "SET_TAB", tab: "hex" },
    { type: "SET_ADDRESS", address: 0x403000 },
    { type: "SET_FUNCTIONS", functions: [] },
    { type: "SET_DISASM_READY" },
    { type: "NAV_BACK" },
    { type: "NAV_FORWARD" },
    { type: "TOGGLE_BOOKMARK", address: 0x401000 },
    { type: "SET_BOOKMARK_LABEL", address: 0x401000, label: "L" },
    { type: "RENAME_FUNCTION", address: 0x404000, name: "x" },
    { type: "CLEAR_RENAME", address: 0x401000 },
    { type: "SET_COMMENT", address: 0x404000, text: "c" },
    { type: "DELETE_COMMENT", address: 0x401000 },
    { type: "LOAD_PERSISTED", bookmarks: [], renames: {}, comments: {} },
    {
      type: "IMPORT_ANNOTATIONS",
      bookmarks: [{ address: 9, label: "" }],
      renames: { 9: "n" },
      comments: {},
    },
    {
      type: "IMPORT_FULL_ANALYSIS",
      bookmarks: [],
      renames: {},
      comments: {},
      hexPatches: new Map([[1, 2]]),
    },
    { type: "PATCH_BYTE", offset: 1, value: 1 },
    { type: "UNDO_PATCH", offset: 0 },
    { type: "CLEAR_PATCHES" },
    { type: "UNDO_ANNOTATION" },
    { type: "PUSH_CALL_STACK", address: 0x405000, name: "z" },
    { type: "POP_CALL_STACK", index: 0 },
    { type: "CLEAR_CALL_STACK" },
    { type: "SET_STRINGS", strings: new Map(), stringTypes: new Map() },
    { type: "SET_XREFS", stringXrefs: new Map(), importXrefs: new Map() },
    { type: "SET_CALL_GRAPH", callGraph: new Map() },
    { type: "SET_ANOMALIES", anomalies: [] },
    { type: "SET_ANALYSIS_PHASE", phase: "ready" },
    { type: "SET_CURRENT_INSTRUCTION", instruction: null },
    { type: "SET_CURRENT_BLOCK", block: null },
    { type: "SET_IAT_MAP", iatMap: new Map() },
    { type: "SET_IRP_HANDLERS", handlers: [] },
    { type: "BATCH_RENAME_PROGRESS", done: 1 },
    { type: "BATCH_RENAME_DONE", results: [] },
    { type: "BATCH_RENAME_ERROR", error: "e" },
    { type: "BATCH_RENAME_ACCEPT", results: [] },
    { type: "BATCH_RENAME_DISMISS" },
    { type: "AI_REPORT_TOKEN", content: "t" },
    { type: "AI_REPORT_DONE" },
    { type: "AI_REPORT_ERROR", error: "e" },
    { type: "AI_REPORT_DISMISS" },
    { type: "AI_SCAN_ADD", findings: [] },
    { type: "AI_SCAN_FAILED", error: "e" },
    { type: "AI_SCAN_COMPLETE" },
    { type: "AI_SCAN_CLEAR" },
    { type: "RESET" },
  ];

  for (const action of actions) {
    it(`${action.type} leaves the previous state untouched`, () => {
      const before = JSON.stringify(base, (_k, v) => (v instanceof Map ? [...v.entries()] : v));
      appReducer(base, action);
      const after = JSON.stringify(base, (_k, v) => (v instanceof Map ? [...v.entries()] : v));
      expect(after).toBe(before);
    });
  }
});
