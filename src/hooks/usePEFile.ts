import { createContext, useContext, useReducer, type Dispatch } from "react";
import type { PEFile } from "../pe/types";
import type { DisasmFunction, Instruction } from "../disasm/types";

export type ViewTab =
  | "disassembly"
  | "headers"
  | "sections"
  | "imports"
  | "exports"
  | "hex";

export interface AppState {
  peFile: PEFile | null;
  loading: boolean;
  error: string | null;
  activeTab: ViewTab;
  currentAddress: number;
  functions: DisasmFunction[];
  disasmReady: boolean;
  instructions: Instruction[];
  selectedSection: number;
}

export type AppAction =
  | { type: "SET_LOADING" }
  | { type: "SET_PE_FILE"; peFile: PEFile }
  | { type: "SET_ERROR"; error: string }
  | { type: "SET_TAB"; tab: ViewTab }
  | { type: "SET_ADDRESS"; address: number }
  | { type: "SET_FUNCTIONS"; functions: DisasmFunction[] }
  | { type: "SET_DISASM_READY" }
  | { type: "SET_INSTRUCTIONS"; instructions: Instruction[] }
  | { type: "SET_SELECTED_SECTION"; index: number }
  | { type: "RESET" };

export const initialState: AppState = {
  peFile: null,
  loading: false,
  error: null,
  activeTab: "disassembly",
  currentAddress: 0,
  functions: [],
  disasmReady: false,
  instructions: [],
  selectedSection: 0,
};

export function appReducer(state: AppState, action: AppAction): AppState {
  switch (action.type) {
    case "SET_LOADING":
      return { ...state, loading: true, error: null };
    case "SET_PE_FILE":
      return {
        ...state,
        peFile: action.peFile,
        loading: false,
        error: null,
        currentAddress: action.peFile.optionalHeader.addressOfEntryPoint + action.peFile.optionalHeader.imageBase,
      };
    case "SET_ERROR":
      return { ...state, error: action.error, loading: false };
    case "SET_TAB":
      return { ...state, activeTab: action.tab };
    case "SET_ADDRESS":
      return { ...state, currentAddress: action.address };
    case "SET_FUNCTIONS":
      return { ...state, functions: action.functions };
    case "SET_DISASM_READY":
      return { ...state, disasmReady: true };
    case "SET_INSTRUCTIONS":
      return { ...state, instructions: action.instructions };
    case "SET_SELECTED_SECTION":
      return { ...state, selectedSection: action.index };
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

export { useReducer };
