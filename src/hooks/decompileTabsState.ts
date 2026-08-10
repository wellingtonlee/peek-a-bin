export type DecompileTab = "low" | "high" | "ai";
export type HighLevelEngine = "ghidra" | "retdec" | "none";

export interface TabState {
  code: string;
  lineMap: Map<number, number>;
  loading: boolean;
  error: string;
  ready: boolean;
  engine?: HighLevelEngine;
}

export interface DecompileTabsState {
  activeTab: DecompileTab;
  low: TabState;
  high: TabState;
  ai: TabState;
  aiMode: "enhance" | "explain" | null;
}

export type TabAction =
  | { type: "SET_TAB"; tab: DecompileTab }
  | { type: "BEGIN_LOAD"; tab: DecompileTab }
  | { type: "LOAD_OK"; tab: DecompileTab; code: string; lineMap: Map<number, number>; engine?: HighLevelEngine }
  | { type: "LOAD_ERR"; tab: DecompileTab; error: string }
  | { type: "AI_TOKEN"; accumulated: string }
  | { type: "AI_DONE" }
  | { type: "AI_MODE"; mode: "enhance" | "explain" }
  | { type: "RESET_FUNC" };

export function emptyTabState(): TabState {
  return { code: "", lineMap: new Map(), loading: false, error: "", ready: false };
}

export function initialTabsState(): DecompileTabsState {
  return {
    activeTab: "low",
    low: emptyTabState(),
    high: emptyTabState(),
    ai: emptyTabState(),
    aiMode: null,
  };
}

export function tabsReducer(state: DecompileTabsState, action: TabAction): DecompileTabsState {
  switch (action.type) {
    case "SET_TAB":
      return { ...state, activeTab: action.tab };
    case "BEGIN_LOAD":
      return { ...state, [action.tab]: { ...state[action.tab], loading: true, error: "" } };
    case "LOAD_OK":
      return {
        ...state,
        [action.tab]: {
          code: action.code,
          lineMap: action.lineMap,
          loading: false,
          error: "",
          ready: true,
          engine: action.engine,
        },
      };
    case "LOAD_ERR":
      return {
        ...state,
        [action.tab]: { ...state[action.tab], loading: false, error: action.error, ready: false },
      };
    case "AI_TOKEN":
      return {
        ...state,
        ai: { ...state.ai, code: action.accumulated, loading: true, ready: false },
      };
    case "AI_DONE":
      return {
        ...state,
        ai: { ...state.ai, loading: false, ready: true },
      };
    case "AI_MODE":
      return { ...state, aiMode: action.mode };
    case "RESET_FUNC":
      return {
        ...state,
        low: emptyTabState(),
        high: emptyTabState(),
        ai: { ...emptyTabState(), lineMap: state.ai.lineMap },
        aiMode: null,
      };
    default:
      return state;
  }
}
