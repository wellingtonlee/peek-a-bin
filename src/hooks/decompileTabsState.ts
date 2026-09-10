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
  | {
      type: "LOAD_OK";
      tab: DecompileTab;
      code: string;
      lineMap: Map<number, number>;
      engine?: HighLevelEngine;
    }
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

// ── Low Level result cache ──

/**
 * One cached Low Level decompilation, keyed on the function's address by the
 * map that holds it and on {@link LowCacheEntry.inputsKey} for whether it is
 * still the answer.
 */
export interface LowCacheEntry {
  code: string;
  lineMap: Map<number, number>;
  /** The user inputs this entry was decompiled under — see `decompileInputsKey()`. */
  inputsKey: string;
}

/**
 * Identity of every user-supplied input a Low Level decompilation reads, so a
 * cached result is reused exactly while those inputs are what they were.
 *
 * The same rule as {@link decompileServerKey} for the High Level tab, and for
 * the same reason: derived at read time, so there is no invalidation call to
 * remember. `disasmClient` used to keep a second decompile cache keyed on the
 * bare address with an `invalidateDecompileCache()` that nothing called, and a
 * rename therefore reached the disassembly listing and never the C — that cache
 * is deleted (peek-a-bin-n9cl.7), and this key is what replaces its rule.
 *
 * DELIBERATELY OVER ALL RENAMES, NOT THIS FUNCTION'S. A rename of function B
 * changes the emitted C of every function that calls B — the callee name comes
 * from the same `funcMap` the header does — and the set of callers is not
 * known here: `state.callGraph` would give it, but it is null before
 * `buildAllXrefs` finishes and stays null forever after a timeout, so an
 * invalidation derived from it would silently be a no-op exactly then. The
 * price of the coarse key is one re-decompile (~6 ms, peek-a-bin-9gc9's figure)
 * per revisited function per rename, against a stale header or call site for
 * the session. It is O(R log R) in the number of user renames — tens — never in
 * the number of functions.
 *
 * Sorted by numeric address so the key does not depend on insertion order, and
 * JSON-encoded so no name — whatever characters it holds — can read as a
 * separator (a `join` on a delimiter was tried first and its own test found the
 * collision).
 */
export function decompileInputsKey(renames: Readonly<Record<number, string>>): string {
  const pairs: [number, string][] = Object.entries(renames).map(([addr, name]) => [
    Number(addr),
    name,
  ]);
  pairs.sort((a, b) => a[0] - b[0]);
  return JSON.stringify(pairs);
}

/** Cache hit only if the entry was produced under the current inputs. */
export function readLowCache(
  cache: Map<number, LowCacheEntry>,
  addr: number,
  inputsKey: string,
): LowCacheEntry | null {
  const hit = cache.get(addr);
  if (!hit || hit.inputsKey !== inputsKey) return null;
  return hit;
}

/** Store a Low Level result under the inputs that produced it. */
export function writeLowCache(
  cache: Map<number, LowCacheEntry>,
  addr: number,
  entry: LowCacheEntry,
): void {
  cache.set(addr, entry);
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
