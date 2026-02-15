import { createContext, useContext, useReducer, type Dispatch } from "react";
import type { PEFile } from "../pe/types";
import type { DisasmFunction } from "../disasm/types";

export type ViewTab =
  | "disassembly"
  | "headers"
  | "sections"
  | "imports"
  | "exports"
  | "hex"
  | "strings";

export interface Bookmark {
  address: number;
  label: string;
}

export interface AnnotationSnapshot {
  bookmarks: Bookmark[];
  renames: Record<number, string>;
  comments: Record<number, string>;
}

export interface AppState {
  peFile: PEFile | null;
  fileName: string | null;
  loading: boolean;
  error: string | null;
  activeTab: ViewTab;
  currentAddress: number;
  functions: DisasmFunction[];
  disasmReady: boolean;
  selectedSection: number;
  addressHistory: number[];
  historyIndex: number;
  bookmarks: Bookmark[];
  renames: Record<number, string>;
  comments: Record<number, string>;
  hexPatches: Map<number, number>;
  annotationUndoStack: AnnotationSnapshot[];
  annotationRedoStack: AnnotationSnapshot[];
  callStack: { address: number; name: string }[];
}

export type AppAction =
  | { type: "SET_LOADING" }
  | { type: "SET_PE_FILE"; peFile: PEFile; fileName?: string }
  | { type: "SET_ERROR"; error: string }
  | { type: "SET_TAB"; tab: ViewTab }
  | { type: "SET_ADDRESS"; address: number }
  | { type: "SET_FUNCTIONS"; functions: DisasmFunction[] }
  | { type: "SET_DISASM_READY" }
  | { type: "SET_SELECTED_SECTION"; index: number }
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
  | { type: "PATCH_BYTE"; offset: number; value: number }
  | { type: "UNDO_PATCH"; offset: number }
  | { type: "CLEAR_PATCHES" }
  | { type: "UNDO_ANNOTATION" }
  | { type: "REDO_ANNOTATION" }
  | { type: "PUSH_CALL_STACK"; address: number; name: string }
  | { type: "POP_CALL_STACK"; index: number }
  | { type: "CLEAR_CALL_STACK" }
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
  selectedSection: 0,
  addressHistory: [],
  historyIndex: -1,
  bookmarks: [],
  renames: {},
  comments: {},
  hexPatches: new Map(),
  annotationUndoStack: [],
  annotationRedoStack: [],
  callStack: [],
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
    case "SET_SELECTED_SECTION":
      return { ...state, selectedSection: action.index };
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
      const stack = [...state.callStack, { address: action.address, name: action.name }];
      if (stack.length > 8) stack.shift();
      return { ...state, callStack: stack };
    }
    case "POP_CALL_STACK":
      return { ...state, callStack: state.callStack.slice(0, action.index) };
    case "CLEAR_CALL_STACK":
      return { ...state, callStack: [] };
    case "RESET":
      return initialState;
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
