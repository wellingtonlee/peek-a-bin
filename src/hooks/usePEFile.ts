import { createContext, type Dispatch, useContext, useReducer } from "react";
import type { Anomaly } from "../analysis/anomalies";
import type { DriverInfo, IRPDispatchEntry } from "../analysis/driver";
import type { DetectPass } from "../disasm/functionDetect";
import type { DisasmFunction } from "../disasm/types";
import type { AIScanFinding, BatchRenameResult } from "../llm/types";
import type { PEFile, StringScanCoverage } from "../pe/types";

export type ViewTab =
  | "disassembly"
  | "headers"
  | "sections"
  | "imports"
  | "exports"
  | "hex"
  | "strings"
  | "resources"
  | "anomalies";

/**
 * Every view tab, in the order the tab bar shows them.
 *
 * Exported because that order is also the 1–9 keyboard shortcuts: `AddressBar`
 * builds both its buttons and its `TAB_KEYS` map from this array, so the tab a
 * digit selects cannot disagree with the tab at that position. Display names
 * are not here — they live in `components/analysisNotice.ts`, which is where
 * prose that has to name a tab already reads them from.
 */
export const VIEW_TABS: readonly ViewTab[] = [
  "disassembly",
  "headers",
  "sections",
  "imports",
  "exports",
  "hex",
  "strings",
  "resources",
  "anomalies",
];

/** Narrow an untrusted string (e.g. the `#tab=` URL param) to a ViewTab. */
export function parseViewTab(value: string | null | undefined): ViewTab | null {
  return value != null && (VIEW_TABS as readonly string[]).includes(value)
    ? (value as ViewTab)
    : null;
}

export interface Bookmark {
  address: number;
  label: string;
}

export interface AnnotationSnapshot {
  bookmarks: Bookmark[];
  renames: Record<number, string>;
  comments: Record<number, string>;
}

export type AnalysisPhase =
  | "idle"
  | "parsing"
  | "detecting-functions"
  | "recursive-descent"
  | "gap-filling"
  | "building-xrefs"
  | "extracting-strings"
  | "ready"
  | "failed"
  /**
   * Terminal, and not a failure: the image has no executable section, so there
   * was never anything to disassemble.
   *
   * `findCodeSection` returns undefined for a resource-only DLL — a satellite
   * or MUI file is the ordinary case, not malformed input — and App's analysis
   * effect returns at that point, *before* the first phase it dispatches. So
   * the phase stayed on whatever preceded it ("extracting-strings") forever and
   * the status bar spun with no explanation (peek-a-bin-bo3b). "failed" is the
   * wrong word for it: the parse succeeded, nothing went wrong, and every
   * parser-derived tab is populated — see `analysisNotice`'s
   * `"no-code-section"` kind for what the user is told.
   */
  | "no-code"
  /**
   * Terminal, and not the same thing as `"failed"`: the analysis chain was cut
   * off by the worker request watchdog.
   *
   * `REQUEST_TIMEOUT_MS` is one budget for every RPC — correctly, since the
   * worker services messages serially — so a legitimate run on a very large
   * image can trip it. Reported as `"failed"`, that is the same terminal state
   * a truncated or corrupt file produces, and the two call for opposite
   * responses: a parse failure means the file is bad and there is nothing to
   * do, a timeout means the file is fine and the tool gave up. Its own value
   * rather than a boolean beside `"failed"`, because a phase is single-valued
   * and every load dispatches `"parsing"` over it — a parallel flag would need
   * clearing at load *and* at re-analysis, and a stale one reports the next
   * file's genuine parse failure as a timeout. See `analysisNotice`'s
   * `"analysis-timed-out"` kind for what the user is told (peek-a-bin-meai).
   */
  | "timed-out";

/**
 * Whether a phase means analysis is still in flight.
 *
 * Typed `Record<AnalysisPhase, boolean>` on purpose. Three surfaces — the
 * status bar and the sidebar's two — spelled this out as a hand-written
 * `phase !== "idle" && phase !== "ready" && phase !== "failed"` chain, which
 * defaults *any* new phase to "still analysing" and so pins a spinner that can
 * never resolve. That is exactly the defect peek-a-bin-bo3b was, one phase
 * earlier in the chain; adding a phase now fails the build here instead.
 */
export const ANALYSIS_IN_PROGRESS: Record<AnalysisPhase, boolean> = {
  idle: false,
  parsing: true,
  "detecting-functions": true,
  "recursive-descent": true,
  "gap-filling": true,
  "building-xrefs": true,
  "extracting-strings": true,
  ready: false,
  failed: false,
  "no-code": false,
  "timed-out": false,
};

export interface AppState {
  peFile: PEFile | null;
  fileName: string | null;
  loading: boolean;
  error: string | null;
  activeTab: ViewTab;
  currentAddress: number;
  functions: DisasmFunction[];
  disasmReady: boolean;
  /**
   * Why the decode engine is unavailable, or null while it is still loading or
   * once it is ready. A *session*-level fact, not a per-file one: Capstone is
   * initialised once, so a rejection here withholds the disassembly for every
   * file this tab will ever open — which is why `RESET` carries it across a
   * load exactly as it carries `disasmReady` (peek-a-bin-b3jn).
   */
  disasmFailed: string | null;
  addressHistory: number[];
  historyIndex: number;
  bookmarks: Bookmark[];
  renames: Record<number, string>;
  comments: Record<number, string>;
  hexPatches: Map<number, number>;
  annotationUndoStack: AnnotationSnapshot[];
  annotationRedoStack: AnnotationSnapshot[];
  callStack: {
    address: number;
    name: string;
    viewSnapshot?: {
      viewMode: "linear" | "graph";
      graphPan: { x: number; y: number };
      graphZoom: number;
    };
  }[];
  stringXrefs: Map<number, number[]> | null;
  importXrefs: Map<number, number[]> | null;
  dataXrefs: Map<number, number[]> | null;
  callGraph: Map<number, number[]> | null;
  anomalies: Anomaly[];
  analysisPhase: AnalysisPhase;
  /**
   * Function-detection passes that did not run, from `DetectResult.omitted`.
   *
   * Empty means the function list is whole. Non-empty means it is narrower than
   * a complete one — either the image has no decoder, or Capstone is dead — and
   * detection answered from `.pdata`, the exports, the entry point and the
   * unwind handlers alone. Kept in state rather than logged because a short
   * function list looks exactly like a complete one on screen; see
   * `components/analysisNotice.ts` for what the user is told.
   */
  omittedPasses: DetectPass[];
  currentInstruction: { bytes: number[]; size: number } | null;
  currentBlock: { startAddr: number; endAddr: number } | null;
  iatMap: Map<number, { lib: string; func: string }>;
  driverInfo: DriverInfo | null;
  irpHandlers: IRPDispatchEntry[];
  // AI features
  batchRename: {
    status: "idle" | "decompiling" | "running" | "review" | "applying";
    progress: { done: number; total: number };
    results: BatchRenameResult[];
    error: string | null;
  } | null;
  aiReport: {
    status: "idle" | "streaming" | "done" | "error";
    content: string;
    error: string | null;
  } | null;
  aiScanResults: AIScanFinding[];
  aiScan: AIScanState;
}

/**
 * Outcome of the AI vulnerability scan, kept separate from `aiScanResults` so the
 * three outcomes stay distinguishable:
 *
 *   - `phase: "idle"`                        → never run for this binary
 *   - `phase: "complete"`, no findings       → ran, genuinely found nothing
 *   - `phase: "failed"`                      → ran, produced nothing usable
 *
 * An empty `aiScanResults` therefore means "clean" only when `phase` says the scan
 * actually completed. Collapsing the two is what made an unparseable response
 * render identically to a clean binary — the worst failure mode for a scanner,
 * because it reads as "your binary is fine".
 *
 * A run can also be partially successful: `phase: "complete"` with `failed > 0`
 * means some functions were scanned and others could not be, so the finding list
 * is real but incomplete.
 */
export interface AIScanState {
  phase: "idle" | "scanning" | "complete" | "failed";
  /** Functions whose response came back and validated. */
  scanned: number;
  /** Functions whose request failed or whose response could not be parsed. */
  failed: number;
  /** Functions this run set out to scan. */
  total: number;
  /** First failure message from this run, retained for display. */
  error: string | null;
}

const IDLE_SCAN: AIScanState = {
  phase: "idle",
  scanned: 0,
  failed: 0,
  total: 0,
  error: null,
};

export type AppAction =
  | { type: "SET_LOADING" }
  | { type: "SET_PE_FILE"; peFile: PEFile; fileName?: string }
  | { type: "SET_ERROR"; error: string }
  | { type: "SET_TAB"; tab: ViewTab }
  | { type: "SET_ADDRESS"; address: number }
  | { type: "SET_FUNCTIONS"; functions: DisasmFunction[] }
  | { type: "SET_OMITTED_PASSES"; omitted: DetectPass[] }
  | { type: "SET_DISASM_READY" }
  | { type: "SET_DISASM_FAILED"; error: string }
  | { type: "NAV_BACK" }
  | { type: "NAV_FORWARD" }
  | { type: "TOGGLE_BOOKMARK"; address?: number }
  | { type: "SET_BOOKMARK_LABEL"; address: number; label: string }
  | { type: "RENAME_FUNCTION"; address: number; name: string }
  | { type: "CLEAR_RENAME"; address: number }
  | { type: "SET_COMMENT"; address: number; text: string }
  | { type: "DELETE_COMMENT"; address: number }
  | {
      type: "LOAD_PERSISTED";
      bookmarks: Bookmark[];
      renames: Record<number, string>;
      comments: Record<number, string>;
    }
  // `source` splits the two very different callers of this action. Omitting it
  // means "user": that direction can only over-record history, never lose it.
  | {
      type: "IMPORT_ANNOTATIONS";
      bookmarks: Bookmark[];
      renames: Record<number, string>;
      comments: Record<number, string>;
      source?: "user" | "mcp";
    }
  | {
      type: "IMPORT_FULL_ANALYSIS";
      bookmarks: Bookmark[];
      renames: Record<number, string>;
      comments: Record<number, string>;
      hexPatches: Map<number, number>;
    }
  | { type: "PATCH_BYTE"; offset: number; value: number }
  | { type: "UNDO_PATCH"; offset: number }
  | { type: "CLEAR_PATCHES" }
  | { type: "UNDO_ANNOTATION" }
  | { type: "REDO_ANNOTATION" }
  | {
      type: "PUSH_CALL_STACK";
      address: number;
      name: string;
      viewSnapshot?: {
        viewMode: "linear" | "graph";
        graphPan: { x: number; y: number };
        graphZoom: number;
      };
    }
  | { type: "POP_CALL_STACK"; index: number }
  | { type: "CLEAR_CALL_STACK" }
  | {
      type: "SET_STRINGS";
      strings: Map<number, string>;
      stringTypes: Map<number, "ascii" | "utf16le">;
      /**
       * What the scan did not look at, when a bound cut it short. Optional
       * because it is absent for every ordinary file, and it must be carried
       * here rather than derived later: the scan happens in the worker and this
       * action is the only thing that crosses back with it (`peek-a-bin-2py5`).
       */
      stringScan?: StringScanCoverage;
    }
  | {
      type: "SET_XREFS";
      stringXrefs: Map<number, number[]>;
      importXrefs: Map<number, number[]>;
      dataXrefs?: Map<number, number[]>;
    }
  | { type: "SET_CALL_GRAPH"; callGraph: Map<number, number[]> }
  | { type: "SET_ANOMALIES"; anomalies: Anomaly[] }
  | { type: "SET_ANALYSIS_PHASE"; phase: AnalysisPhase }
  | { type: "SET_CURRENT_INSTRUCTION"; instruction: { bytes: number[]; size: number } | null }
  | { type: "SET_CURRENT_BLOCK"; block: { startAddr: number; endAddr: number } | null }
  | { type: "SET_IAT_MAP"; iatMap: Map<number, { lib: string; func: string }> }
  | { type: "SET_DRIVER_INFO"; driverInfo: DriverInfo }
  | { type: "SET_IRP_HANDLERS"; handlers: IRPDispatchEntry[] }
  // Batch rename
  | { type: "BATCH_RENAME_START"; total: number }
  // `phase` moves the run from decompiling to the LLM stage. Without it the
  // status could never leave "decompiling", so the modal's "Generating names…"
  // branch was unreachable.
  | { type: "BATCH_RENAME_PROGRESS"; done: number; phase?: "decompiling" | "running" }
  | { type: "BATCH_RENAME_DONE"; results: BatchRenameResult[] }
  | { type: "BATCH_RENAME_ERROR"; error: string }
  | { type: "BATCH_RENAME_ACCEPT"; results: BatchRenameResult[] }
  | { type: "BATCH_RENAME_DISMISS" }
  // AI report
  | { type: "AI_REPORT_START" }
  | { type: "AI_REPORT_TOKEN"; content: string }
  | { type: "AI_REPORT_DONE" }
  | { type: "AI_REPORT_ERROR"; error: string }
  | { type: "AI_REPORT_DISMISS" }
  // AI scan
  | { type: "AI_SCAN_START"; total: number }
  // Dispatched once per successfully scanned function, including when that
  // function produced no findings — that is what makes "scanned and clean"
  // countable rather than indistinguishable from "not scanned".
  | { type: "AI_SCAN_ADD"; findings: AIScanFinding[] }
  | { type: "AI_SCAN_FAILED"; error: string }
  | { type: "AI_SCAN_COMPLETE" }
  | { type: "AI_SCAN_CLEAR" }
  | { type: "RESET" };

export const initialState: AppState = {
  peFile: null,
  fileName: null,
  loading: false,
  error: null,
  activeTab: "disassembly",
  currentAddress: 0,
  functions: [],
  disasmReady: false,
  disasmFailed: null,
  addressHistory: [],
  historyIndex: -1,
  bookmarks: [],
  renames: {},
  comments: {},
  hexPatches: new Map(),
  annotationUndoStack: [],
  annotationRedoStack: [],
  callStack: [],
  stringXrefs: null,
  importXrefs: null,
  dataXrefs: null,
  callGraph: null,
  anomalies: [],
  analysisPhase: "idle",
  omittedPasses: [],
  currentInstruction: null,
  currentBlock: null,
  iatMap: new Map(),
  driverInfo: null,
  irpHandlers: [],
  batchRename: null,
  aiReport: null,
  aiScanResults: [],
  aiScan: { ...IDLE_SCAN },
};

const MAX_HISTORY = 50;
const MAX_UNDO = 50;

function snapshotAnnotations(state: AppState): AnnotationSnapshot {
  return { bookmarks: state.bookmarks, renames: state.renames, comments: state.comments };
}

function pushUndo(state: AppState): Pick<AppState, "annotationUndoStack" | "annotationRedoStack"> {
  const stack = [...state.annotationUndoStack, snapshotAnnotations(state)];
  if (stack.length > MAX_UNDO) stack.shift();
  return { annotationUndoStack: stack, annotationRedoStack: [] };
}

function pushHistory(
  state: AppState,
  address: number,
): Pick<AppState, "addressHistory" | "historyIndex"> {
  // Don't push if same as current
  if (state.addressHistory.length > 0 && state.addressHistory[state.historyIndex] === address) {
    return { addressHistory: state.addressHistory, historyIndex: state.historyIndex };
  }
  // Truncate forward history
  const history = state.addressHistory.slice(0, state.historyIndex + 1);
  history.push(address);
  // Cap at MAX_HISTORY
  if (history.length > MAX_HISTORY) {
    history.shift();
    return { addressHistory: history, historyIndex: history.length - 1 };
  }
  return { addressHistory: history, historyIndex: history.length - 1 };
}

export function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "SET_LOADING":
      return { ...state, loading: true, error: null };
    case "SET_PE_FILE": {
      const addr =
        action.peFile.optionalHeader.addressOfEntryPoint + action.peFile.optionalHeader.imageBase;
      return {
        ...state,
        peFile: action.peFile,
        fileName: action.fileName ?? null,
        loading: false,
        error: null,
        currentAddress: addr,
        addressHistory: [addr],
        historyIndex: 0,
      };
    }
    case "SET_ERROR":
      return { ...state, error: action.error, loading: false };
    case "SET_TAB":
      return { ...state, activeTab: action.tab };
    case "SET_ADDRESS": {
      const hist = pushHistory(state, action.address);
      return { ...state, currentAddress: action.address, ...hist };
    }
    case "SET_FUNCTIONS":
      return { ...state, functions: action.functions };
    case "SET_OMITTED_PASSES": {
      // The common case by far is "nothing was omitted" arriving over an
      // already-empty list, once per loaded file. Returning a new array for it
      // would give the notice memo in App and StatusBar a fresh input identity
      // and re-render both for no change, so compare and return `state` itself.
      const prev = state.omittedPasses;
      if (
        prev.length === action.omitted.length &&
        prev.every((pass, i) => pass === action.omitted[i])
      ) {
        return state;
      }
      return { ...state, omittedPasses: action.omitted };
    }
    case "SET_DISASM_READY":
      return { ...state, disasmReady: true };
    // Sets `error` too, in the same action rather than as a second dispatch
    // beside it: the two are one fact, and `error` is what FileLoader renders
    // when the engine dies before any file was opened.
    case "SET_DISASM_FAILED":
      return { ...state, disasmFailed: action.error, error: action.error };
    case "NAV_BACK": {
      if (state.historyIndex <= 0) return state;
      const idx = state.historyIndex - 1;
      return { ...state, currentAddress: state.addressHistory[idx], historyIndex: idx };
    }
    case "NAV_FORWARD": {
      if (state.historyIndex >= state.addressHistory.length - 1) return state;
      const idx = state.historyIndex + 1;
      return { ...state, currentAddress: state.addressHistory[idx], historyIndex: idx };
    }
    case "TOGGLE_BOOKMARK": {
      const undo = pushUndo(state);
      const addr = action.address ?? state.currentAddress;
      const exists = state.bookmarks.findIndex((b) => b.address === addr);
      if (exists >= 0) {
        return { ...state, ...undo, bookmarks: state.bookmarks.filter((_, i) => i !== exists) };
      }
      return { ...state, ...undo, bookmarks: [...state.bookmarks, { address: addr, label: "" }] };
    }
    case "SET_BOOKMARK_LABEL": {
      const undo = pushUndo(state);
      return {
        ...state,
        ...undo,
        bookmarks: state.bookmarks.map((b) =>
          b.address === action.address ? { ...b, label: action.label } : b,
        ),
      };
    }
    case "RENAME_FUNCTION": {
      const undo = pushUndo(state);
      return { ...state, ...undo, renames: { ...state.renames, [action.address]: action.name } };
    }
    case "CLEAR_RENAME": {
      const undo = pushUndo(state);
      const { [action.address]: _, ...rest } = state.renames;
      return { ...state, ...undo, renames: rest };
    }
    case "SET_COMMENT": {
      const undo = pushUndo(state);
      return { ...state, ...undo, comments: { ...state.comments, [action.address]: action.text } };
    }
    case "DELETE_COMMENT": {
      const undo = pushUndo(state);
      const { [action.address]: _, ...rest } = state.comments;
      return { ...state, ...undo, comments: rest };
    }
    case "LOAD_PERSISTED": {
      return {
        ...state,
        bookmarks: action.bookmarks,
        renames: action.renames,
        comments: action.comments,
      };
    }
    case "IMPORT_ANNOTATIONS": {
      // A user-initiated import is a user edit, so it is undoable — symmetric
      // with IMPORT_FULL_ANALYSIS below.
      //
      // MCP sync frames are not: useMcpSync dispatches one per frame from the
      // bridge, and pushing each into a stack capped at MAX_UNDO would evict the
      // user's own edits. They still clear redo, though — a redo entry from
      // before the sync would otherwise restore a pre-sync snapshot and silently
      // revert the annotations the sync just brought in.
      const history: Pick<AppState, "annotationUndoStack" | "annotationRedoStack"> =
        action.source === "mcp"
          ? { annotationUndoStack: state.annotationUndoStack, annotationRedoStack: [] }
          : pushUndo(state);
      const mergedBookmarks = [...state.bookmarks];
      const existingAddrs = new Set(mergedBookmarks.map((b) => b.address));
      for (const b of action.bookmarks) {
        if (!existingAddrs.has(b.address)) mergedBookmarks.push(b);
      }
      return {
        ...state,
        ...history,
        bookmarks: mergedBookmarks,
        renames: { ...state.renames, ...action.renames },
        comments: { ...state.comments, ...action.comments },
      };
    }
    case "IMPORT_FULL_ANALYSIS": {
      const undo = pushUndo(state);
      const mergedBookmarks = [...state.bookmarks];
      const existingAddrs = new Set(mergedBookmarks.map((b) => b.address));
      for (const b of action.bookmarks) {
        if (!existingAddrs.has(b.address)) mergedBookmarks.push(b);
      }
      return {
        ...state,
        ...undo,
        bookmarks: mergedBookmarks,
        renames: { ...state.renames, ...action.renames },
        comments: { ...state.comments, ...action.comments },
        hexPatches: new Map([...state.hexPatches, ...action.hexPatches]),
      };
    }
    case "PATCH_BYTE": {
      const next = new Map(state.hexPatches);
      next.set(action.offset, action.value);
      return { ...state, hexPatches: next };
    }
    case "UNDO_PATCH": {
      const next = new Map(state.hexPatches);
      next.delete(action.offset);
      return { ...state, hexPatches: next };
    }
    case "CLEAR_PATCHES":
      return { ...state, hexPatches: new Map() };
    case "UNDO_ANNOTATION": {
      if (state.annotationUndoStack.length === 0) return state;
      const stack = [...state.annotationUndoStack];
      const snapshot = stack.pop()!;
      const redoStack = [...state.annotationRedoStack, snapshotAnnotations(state)];
      if (redoStack.length > MAX_UNDO) redoStack.shift();
      return {
        ...state,
        bookmarks: snapshot.bookmarks,
        renames: snapshot.renames,
        comments: snapshot.comments,
        annotationUndoStack: stack,
        annotationRedoStack: redoStack,
      };
    }
    case "REDO_ANNOTATION": {
      if (state.annotationRedoStack.length === 0) return state;
      const stack = [...state.annotationRedoStack];
      const snapshot = stack.pop()!;
      const undoStack = [...state.annotationUndoStack, snapshotAnnotations(state)];
      if (undoStack.length > MAX_UNDO) undoStack.shift();
      return {
        ...state,
        bookmarks: snapshot.bookmarks,
        renames: snapshot.renames,
        comments: snapshot.comments,
        annotationUndoStack: undoStack,
        annotationRedoStack: stack,
      };
    }
    case "PUSH_CALL_STACK": {
      const entry: AppState["callStack"][0] = { address: action.address, name: action.name };
      if (action.viewSnapshot) entry.viewSnapshot = action.viewSnapshot;
      const stack = [...state.callStack, entry];
      if (stack.length > 8) stack.shift();
      return { ...state, callStack: stack };
    }
    case "POP_CALL_STACK":
      return { ...state, callStack: state.callStack.slice(0, action.index) };
    case "CLEAR_CALL_STACK":
      return { ...state, callStack: [] };
    case "SET_STRINGS": {
      if (!state.peFile) return state;
      return {
        ...state,
        peFile: {
          ...state.peFile,
          strings: action.strings,
          stringTypes: action.stringTypes,
          // Spread rather than assigned, so a complete scan leaves the field
          // ABSENT rather than writing `undefined` over it — the presence of the
          // object is the admission, `PEFile.importsTruncated`'s rule.
          ...(action.stringScan ? { stringScan: action.stringScan } : {}),
        },
      };
    }
    case "SET_XREFS":
      return {
        ...state,
        stringXrefs: action.stringXrefs,
        importXrefs: action.importXrefs,
        dataXrefs: action.dataXrefs ?? state.dataXrefs,
      };
    case "SET_CALL_GRAPH":
      return { ...state, callGraph: action.callGraph };
    case "SET_ANOMALIES":
      return { ...state, anomalies: action.anomalies };
    case "SET_ANALYSIS_PHASE":
      return { ...state, analysisPhase: action.phase };
    case "SET_CURRENT_INSTRUCTION":
      return { ...state, currentInstruction: action.instruction };
    case "SET_CURRENT_BLOCK":
      return { ...state, currentBlock: action.block };
    case "SET_IAT_MAP":
      return { ...state, iatMap: action.iatMap };
    case "SET_DRIVER_INFO":
      return { ...state, driverInfo: action.driverInfo };
    case "SET_IRP_HANDLERS":
      return { ...state, irpHandlers: action.handlers };
    // ── Batch Rename ──
    case "BATCH_RENAME_START":
      return {
        ...state,
        batchRename: {
          status: "decompiling",
          progress: { done: 0, total: action.total },
          results: [],
          error: null,
        },
      };
    case "BATCH_RENAME_PROGRESS":
      // Previously `status === "decompiling" ? "decompiling" : "running"`, which
      // pinned the run to "decompiling" forever — the ternary could only ever
      // re-select the status it was testing for. The caller now says explicitly
      // when the phase changes, and progress alone leaves the status untouched.
      return state.batchRename
        ? {
            ...state,
            batchRename: {
              ...state.batchRename,
              status: action.phase ?? state.batchRename.status,
              progress: { ...state.batchRename.progress, done: action.done },
            },
          }
        : state;
    case "BATCH_RENAME_DONE":
      return state.batchRename
        ? {
            ...state,
            batchRename: {
              ...state.batchRename,
              status: "review",
              results: action.results,
              error: null,
            },
          }
        : state;
    case "BATCH_RENAME_ERROR":
      return state.batchRename
        ? { ...state, batchRename: { ...state.batchRename, status: "idle", error: action.error } }
        : state;
    case "BATCH_RENAME_ACCEPT": {
      const undo = pushUndo(state);
      const accepted = action.results.filter((r) => r.accepted);
      const newRenames = { ...state.renames };
      for (const r of accepted) newRenames[r.address] = r.suggestedName;
      return { ...state, ...undo, renames: newRenames, batchRename: null };
    }
    case "BATCH_RENAME_DISMISS":
      return { ...state, batchRename: null };
    // ── AI Report ──
    case "AI_REPORT_START":
      return { ...state, aiReport: { status: "streaming", content: "", error: null } };
    case "AI_REPORT_TOKEN":
      return state.aiReport
        ? { ...state, aiReport: { ...state.aiReport, content: action.content } }
        : state;
    case "AI_REPORT_DONE":
      return state.aiReport ? { ...state, aiReport: { ...state.aiReport, status: "done" } } : state;
    case "AI_REPORT_ERROR":
      return state.aiReport
        ? { ...state, aiReport: { ...state.aiReport, status: "error", error: action.error } }
        : state;
    case "AI_REPORT_DISMISS":
      return { ...state, aiReport: null };
    // ── AI Scan ──
    case "AI_SCAN_START":
      // Clears findings and any error from the previous run, so a stale failure
      // can never bleed into the next scan.
      return {
        ...state,
        aiScanResults: [],
        aiScan: { phase: "scanning", scanned: 0, failed: 0, total: action.total, error: null },
      };
    case "AI_SCAN_ADD":
      return {
        ...state,
        aiScanResults: [...state.aiScanResults, ...action.findings],
        aiScan: { ...state.aiScan, scanned: state.aiScan.scanned + 1 },
      };
    case "AI_SCAN_FAILED":
      return {
        ...state,
        aiScan: {
          ...state.aiScan,
          failed: state.aiScan.failed + 1,
          // Keep the first failure; later ones are usually the same cause.
          error: state.aiScan.error ?? action.error,
        },
      };
    case "AI_SCAN_COMPLETE":
      return {
        ...state,
        aiScan: {
          ...state.aiScan,
          // Nothing usable came back at all → failed. Anything scanned, even with
          // zero findings, is a real result the user can trust.
          phase: state.aiScan.scanned === 0 && state.aiScan.failed > 0 ? "failed" : "complete",
        },
      };
    case "AI_SCAN_CLEAR":
      return { ...state, aiScanResults: [], aiScan: { ...IDLE_SCAN } };
    case "RESET":
      return {
        ...initialState,
        disasmReady: state.disasmReady,
        // Both halves of the engine's status survive a load. A dead engine is
        // still dead for the next file, and dropping this here put the spinner
        // back for the rest of the session.
        disasmFailed: state.disasmFailed,
        callGraph: null,
        dataXrefs: null,
        anomalies: [],
      };
    default:
      return state;
  }
}

export const AppStateContext = createContext<AppState>(initialState);
export const AppDispatchContext = createContext<Dispatch<AppAction>>(() => {});

export function useAppState() {
  return useContext(AppStateContext);
}

export function useAppDispatch() {
  return useContext(AppDispatchContext);
}

export function getDisplayName(fn: DisasmFunction, renames: Record<number, string>): string {
  return renames[fn.address] ?? fn.name;
}

export { useReducer };
