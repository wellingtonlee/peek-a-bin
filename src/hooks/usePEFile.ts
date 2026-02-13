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
  | { type: "LOAD_PERSISTED"; bookmarks: Bookmark[]; renames: Record<number, string> }
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
};

const MAX_HISTORY = 50;

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
      const addr = action.address ?? state.currentAddress;
      const exists = state.bookmarks.findIndex((b) => b.address === addr);
      if (exists >= 0) {
        return { ...state, bookmarks: state.bookmarks.filter((_, i) => i !== exists) };
      }
      return { ...state, bookmarks: [...state.bookmarks, { address: addr, label: "" }] };
    }
    case "SET_BOOKMARK_LABEL": {
      return {
        ...state,
        bookmarks: state.bookmarks.map((b) =>
          b.address === action.address ? { ...b, label: action.label } : b,
        ),
      };
    }
    case "RENAME_FUNCTION": {
      return { ...state, renames: { ...state.renames, [action.address]: action.name } };
    }
    case "CLEAR_RENAME": {
      const { [action.address]: _, ...rest } = state.renames;
      return { ...state, renames: rest };
    }
    case "LOAD_PERSISTED": {
      return { ...state, bookmarks: action.bookmarks, renames: action.renames };
    }
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
