import { describe, it, expect } from "vitest";
import {
  tabsReducer,
  initialTabsState,
  decompileServerKey,
  readHighCache,
  writeHighCache,
  type DecompileServerConfig,
  type HighCacheEntry,
} from "../decompileTabsState";

const DISABLED: DecompileServerConfig = { enabled: false, ghidraUrl: "http://localhost:8765", apiKey: "" };
const ENABLED: DecompileServerConfig = { enabled: true, ghidraUrl: "http://localhost:8765", apiKey: "" };

function entry(code: string, serverKey: string, engine: HighCacheEntry["engine"] = "ghidra"): HighCacheEntry {
  return { code, lineMap: new Map(), engine, serverKey };
}

const PLACEHOLDER = "// Client-side decompiler not yet available.";

describe("decompileServerKey", () => {
  it("collapses every disabled configuration to one key", () => {
    expect(decompileServerKey(DISABLED)).toBe("none");
    expect(decompileServerKey({ ...DISABLED, ghidraUrl: "http://other:1234", apiKey: "k" })).toBe("none");
  });

  it("distinguishes enabled from disabled", () => {
    expect(decompileServerKey(ENABLED)).not.toBe(decompileServerKey(DISABLED));
  });

  it("distinguishes servers by url and by api key", () => {
    expect(decompileServerKey({ ...ENABLED, ghidraUrl: "http://other:1234" })).not.toBe(decompileServerKey(ENABLED));
    expect(decompileServerKey({ ...ENABLED, apiKey: "secret" })).not.toBe(decompileServerKey(ENABLED));
  });

  it("treats a trailing slash as the same server (GhidraClient strips it)", () => {
    expect(decompileServerKey({ ...ENABLED, ghidraUrl: "http://localhost:8765/" })).toBe(decompileServerKey(ENABLED));
    expect(decompileServerKey({ ...ENABLED, ghidraUrl: "http://localhost:8765///" })).toBe(decompileServerKey(ENABLED));
  });
});

describe("high-level cache: a failure is never stored as a success", () => {
  it("does not cache the 'no engine configured' placeholder", () => {
    const cache = new Map<number, HighCacheEntry>();
    writeHighCache(cache, 0x401000, entry(PLACEHOLDER, "none", "none"));
    expect(cache.size).toBe(0);
  });

  it("caches a real engine result", () => {
    const cache = new Map<number, HighCacheEntry>();
    const key = decompileServerKey(ENABLED);
    writeHighCache(cache, 0x401000, entry("int main() {}", key));
    expect(readHighCache(cache, 0x401000, key)?.code).toBe("int main() {}");
  });

  it("regression (peek-a-bin-no6): enabling Ghidra after seeing the placeholder re-decompiles", () => {
    const cache = new Map<number, HighCacheEntry>();

    // User opens High Level with no server configured.
    const offKey = decompileServerKey(DISABLED);
    expect(readHighCache(cache, 0x401000, offKey)).toBeNull();
    writeHighCache(cache, 0x401000, entry(PLACEHOLDER, offKey, "none"));

    // User enables Ghidra in Settings and returns to the tab: must be a miss,
    // so the hook actually calls the server instead of serving the placeholder.
    expect(readHighCache(cache, 0x401000, decompileServerKey(ENABLED))).toBeNull();
  });
});

describe("high-level cache: results are scoped to the backend that produced them", () => {
  it("misses after the server url changes", () => {
    const cache = new Map<number, HighCacheEntry>();
    writeHighCache(cache, 0x401000, entry("from A", decompileServerKey(ENABLED)));
    const other = decompileServerKey({ ...ENABLED, ghidraUrl: "http://other:1234" });
    expect(readHighCache(cache, 0x401000, other)).toBeNull();
  });

  it("misses after the api key changes", () => {
    const cache = new Map<number, HighCacheEntry>();
    writeHighCache(cache, 0x401000, entry("from A", decompileServerKey(ENABLED)));
    const rekeyed = decompileServerKey({ ...ENABLED, apiKey: "secret" });
    expect(readHighCache(cache, 0x401000, rekeyed)).toBeNull();
  });

  it("misses after Ghidra is disabled — stale server output is not shown as if local", () => {
    const cache = new Map<number, HighCacheEntry>();
    writeHighCache(cache, 0x401000, entry("from A", decompileServerKey(ENABLED)));
    expect(readHighCache(cache, 0x401000, decompileServerKey(DISABLED))).toBeNull();
  });

  it("hits again when the original server is restored", () => {
    const cache = new Map<number, HighCacheEntry>();
    const keyA = decompileServerKey(ENABLED);
    writeHighCache(cache, 0x401000, entry("from A", keyA));
    expect(readHighCache(cache, 0x401000, decompileServerKey(DISABLED))).toBeNull();
    expect(readHighCache(cache, 0x401000, keyA)?.code).toBe("from A");
  });

  it("is still keyed per function address", () => {
    const cache = new Map<number, HighCacheEntry>();
    const key = decompileServerKey(ENABLED);
    writeHighCache(cache, 0x401000, entry("a", key));
    expect(readHighCache(cache, 0x402000, key)).toBeNull();
  });
});

describe("tabsReducer engine tracking", () => {
  it("carries the engine onto the high tab so the '(not available)' hint is accurate", () => {
    const withPlaceholder = tabsReducer(initialTabsState(), {
      type: "LOAD_OK", tab: "high", code: PLACEHOLDER, lineMap: new Map(), engine: "none",
    });
    expect(withPlaceholder.high.engine).toBe("none");

    const withGhidra = tabsReducer(withPlaceholder, {
      type: "LOAD_OK", tab: "high", code: "int main() {}", lineMap: new Map(), engine: "ghidra",
    });
    expect(withGhidra.high.engine).toBe("ghidra");
    expect(withGhidra.high.code).toBe("int main() {}");
  });

  it("RESET_FUNC drops the stale engine label with the code", () => {
    const loaded = tabsReducer(initialTabsState(), {
      type: "LOAD_OK", tab: "high", code: "x", lineMap: new Map(), engine: "ghidra",
    });
    const reset = tabsReducer(loaded, { type: "RESET_FUNC" });
    expect(reset.high.engine).toBeUndefined();
    expect(reset.high.code).toBe("");
    expect(reset.high.ready).toBe(false);
  });
});
