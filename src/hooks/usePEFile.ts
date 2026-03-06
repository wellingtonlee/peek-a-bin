import { createContext, useContext, useReducer, type Dispatch } from "react";
import type { PEFile } from "../pe/types";
import type { DisasmFunction } from "../disasm/types";
import type { DriverInfo, IRPDispatchEntry } from "../analysis/driver";
import type { Anomaly } from "../analysis/anomalies";

export type ViewTab =
  | "disassembly"
  | "headers"
  | "sections"
  | "imports"
  | "exports"
  | "hex"
  | "strings"
  | "resources";

export interface Bookmark {
  address: number;
  label: string;
}

export interface AnnotationSnapshot {
  bookmarks: Bookmark[];
  renames: Record<number, string>;
  comments: Record<number, string>;
}

export type AnalysisPhase = "idle" | "parsing" | "detecting-functions" | "recursive-descent" | "gap-filling" | "building-xrefs" | "extracting-strings" | "ready";

export interface AppState {
  peFile: PEFile | null;
  fileName: string | null;
  loading: boolean;
  error: string | null;
  activeTab: ViewTab;
  currentAddress: number;
  functions: DisasmFunction[];
  disasmReady: boolean;
  addressHistory: number[];
  historyIndex: number;
  bookmarks: Bookmark[];
  renames: Record<number, string>;
  comments: Record<number, string>;
  hexPatches: Map<number, number>;
  annotationUndoStack: AnnotationSnapshot[];
  annotationRedoStack: AnnotationSnapshot[];
  callStack: { address: number; name: string; viewSnapshot?: { viewMode: "linear" | "graph"; graphPan: { x: number; y: number }; graphZoom: number } }[];
  stringXrefs: Map<number, number[]> | null;
  importXrefs: Map<number, number[]> | null;
  dataXrefs: Map<number, number[]> | null;
  callGraph: Map<number, number[]> | null;
  anomalies: Anomaly[];
  analysisPhase: AnalysisPhase;
  currentInstruction: { bytes: number[]; size: number } | null;
  currentBlock: { startAddr: number; endAddr: number } | null;
  driverInfo: DriverInfo | null;
  irpHandlers: IRPDispatchEntry[];
}

export type AppAction =
  | { type: "SET_LOADING" }
  | { type: "SET_PE_FILE"; peFile: PEFile; fileName?: string }
  | { type: "SET_ERROR"; error: string }
  | { type: "SET_TAB"; tab: ViewTab }
  | { type: "SET_ADDRESS"; address: number }
  | { type: "SET_FUNCTIONS"; functions: DisasmFunction[] }
  | { type: "SET_DISASM_READY" }
  | { type: "NAV_BACK" }
  | { type: "NAV_FORWARD" }
  | { type: "TOGGLE_BOOKMARK"; address?: number }
  | { type: "SET_BOOKMARK_LABEL"; address: number; label: string }
  | { type: "RENAME_FUNCTION"; address: number; name: string }
  | { type: "CLEAR_RENAME"; address: number }
  | { type: "SET_COMMENT"; address: number; text: string }
  | { type: "DELETE_COMMENT"; address: number }
  | { type: "LOAD_PERSISTED"; bookmarks: Bookmark[]; renames: Record<number, string>; comments: Record<number, string> }
  | { type: "IMPORT_ANNOTATIONS"; bookmarks: Bookmark[]; renames: Record<number, string>; comments: Record<number, string> }
  | { type: "IMPORT_FULL_ANALYSIS"; bookmarks: Bookmark[]; renames: Record<number, string>; comments: Record<number, string>; hexPatches: Map<number, number> }
  | { type: "PATCH_BYTE"; offset: number; value: number }
  | { type: "UNDO_PATCH"; offset: number }
  | { type: "CLEAR_PATCHES" }
  | { type: "UNDO_ANNOTATION" }
  | { type: "REDO_ANNOTATION" }
  | { type: "PUSH_CALL_STACK"; address: number; name: string; viewSnapshot?: { viewMode: "linear" | "graph"; graphPan: { x: number; y: number }; graphZoom: number } }
  | { type: "POP_CALL_STACK"; index: number }
  | { type: "CLEAR_CALL_STACK" }
  | { type: "SET_STRINGS"; strings: Map<number, string>; stringTypes: Map<number, "ascii" | "utf16le"> }
  | { type: "SET_XREFS"; stringXrefs: Map<number, number[]>; importXrefs: Map<number, number[]>; dataXrefs?: Map<number, number[]> }
  | { type: "SET_CALL_GRAPH"; callGraph: Map<number, number[]> }
  | { type: "SET_ANOMALIES"; anomalies: Anomaly[] }
  | { type: "SET_ANALYSIS_PHASE"; phase: AnalysisPhase }
  | { type: "SET_CURRENT_INSTRUCTION"; instruction: { bytes: number[]; size: number } | null }
  | { type: "SET_CURRENT_BLOCK"; block: { startAddr: number; endAddr: number } | null }
  | { type: "SET_DRIVER_INFO"; driverInfo: DriverInfo }
  | { type: "SET_IRP_HANDLERS"; handlers: IRPDispatchEntry[] }
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
  currentInstruction: null,
  currentBlock: null,
  driverInfo: null,
  irpHandlers: [],
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

function pushHistory(state: AppState, address: number): Pick<AppState, "addressHistory" | "historyIndex"> {
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
      const addr = action.peFile.optionalHeader.addressOfEntryPoint + action.peFile.optionalHeader.imageBase;
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
    case "SET_DISASM_READY":
      return { ...state, disasmReady: true };
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
      return { ...state, bookmarks: action.bookmarks, renames: action.renames, comments: action.comments };
    }
    case "IMPORT_ANNOTATIONS": {
      const mergedBookmarks = [...state.bookmarks];
      const existingAddrs = new Set(mergedBookmarks.map(b => b.address));
      for (const b of action.bookmarks) {
        if (!existingAddrs.has(b.address)) mergedBookmarks.push(b);
      }
      return {
        ...state,
        bookmarks: mergedBookmarks,
        renames: { ...state.renames, ...action.renames },
        comments: { ...state.comments, ...action.comments },
      };
    }
    case "IMPORT_FULL_ANALYSIS": {
      const undo = pushUndo(state);
      const mergedBookmarks = [...state.bookmarks];
      const existingAddrs = new Set(mergedBookmarks.map(b => b.address));
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
        peFile: { ...state.peFile, strings: action.strings, stringTypes: action.stringTypes },
      };
    }
    case "SET_XREFS":
      return { ...state, stringXrefs: action.stringXrefs, importXrefs: action.importXrefs, dataXrefs: action.dataXrefs ?? state.dataXrefs };
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
    case "SET_DRIVER_INFO":
      return { ...state, driverInfo: action.driverInfo };
    case "SET_IRP_HANDLERS":
      return { ...state, irpHandlers: action.handlers };
    case "RESET":
      return { ...initialState, disasmReady: state.disasmReady, callGraph: null, dataXrefs: null, anomalies: [] };
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
