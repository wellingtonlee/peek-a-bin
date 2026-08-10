// Leaf module: this file must not import anything that pulls in disasmClient or
// Capstone WASM, so tests can exercise the decisions below directly.

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

// ── High Level result cache ──

/**
 * The parts of `DecompileServerSettings` that decide *which* backend produced a
 * high-level result. Declared structurally rather than imported so this module
 * stays a leaf.
 */
export interface DecompileServerConfig {
  enabled: boolean;
  ghidraUrl: string;
  apiKey: string;
}

export interface HighCacheEntry {
  code: string;
  lineMap: Map<number, number>;
  engine: HighLevelEngine;
  /** Backend identity that produced this entry — see `decompileServerKey()`. */
  serverKey: string;
}

/**
 * Identity of the configured high-level backend. Derived from settings at read
 * time, so a cached result is only reused while the backend that produced it is
 * still the one selected — no invalidation call at the Settings save path, and
 * nothing to remember to wire up when another settings path is added.
 */
export function decompileServerKey(cfg: DecompileServerConfig): string {
  if (!cfg.enabled) return "none";
  // Trailing slashes are stripped by GhidraClient, so they are not a distinct server.
  return `ghidra\x00${cfg.ghidraUrl.replace(/\/+$/, "")}\x00${cfg.apiKey}`;
}

/** Cache hit only if the entry came from the currently configured backend. */
export function readHighCache(
  cache: Map<number, HighCacheEntry>,
  addr: number,
  serverKey: string,
): HighCacheEntry | null {
  const hit = cache.get(addr);
  if (!hit || hit.serverKey !== serverKey) return null;
  return hit;
}

/**
 * Store a high-level result, unless there was no engine to produce one.
 * `engine: "none"` is the "configure a server" placeholder — the absence of a
 * result, not a result — and caching it is what used to leave the tab showing
 * the placeholder forever after the user enabled Ghidra.
 */
export function writeHighCache(
  cache: Map<number, HighCacheEntry>,
  addr: number,
  entry: HighCacheEntry,
): void {
  if (entry.engine === "none") return;
  cache.set(addr, entry);
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
