import { describe, expect, it } from "vitest";
import { type DecompileAdmissions, emptyAdmissions } from "../../disasm/decompile/emit";
import {
  ADMISSION_SEPARATOR,
  admissionSummary,
  type DecompileServerConfig,
  decompileInputsKey,
  decompileServerKey,
  type HighCacheEntry,
  initialTabsState,
  type LowCacheEntry,
  readHighCache,
  readLowCache,
  tabsReducer,
  writeHighCache,
  writeLowCache,
} from "../decompileTabsState";

const DISABLED: DecompileServerConfig = {
  enabled: false,
  ghidraUrl: "http://localhost:8765",
  apiKey: "",
};
const ENABLED: DecompileServerConfig = {
  enabled: true,
  ghidraUrl: "http://localhost:8765",
  apiKey: "",
};

function entry(
  code: string,
  serverKey: string,
  engine: HighCacheEntry["engine"] = "ghidra",
): HighCacheEntry {
  return { code, lineMap: new Map(), engine, serverKey };
}

const PLACEHOLDER = "// Client-side decompiler not yet available.";

/**
 * The Low Level cache's key (peek-a-bin-n9cl.7). `disasmClient` used to hold a
 * second decompile cache keyed on the bare address, with an invalidation method
 * nothing called, so a rename reached the listing and never the C. That cache
 * is gone; this key is the one rule that replaces it, and — as with
 * `decompileServerKey` — it is derived at read time so there is nothing to
 * remember to invalidate.
 */
describe("decompileInputsKey", () => {
  it("differs when a rename is added", () => {
    expect(decompileInputsKey({ 0x401000: "main" })).not.toBe(decompileInputsKey({}));
  });

  it("differs when a rename is changed", () => {
    expect(decompileInputsKey({ 0x401000: "main" })).not.toBe(
      decompileInputsKey({ 0x401000: "entry" }),
    );
  });

  it("returns to the original key when a rename is cleared", () => {
    const before = decompileInputsKey({});
    const during = decompileInputsKey({ 0x401000: "main" });
    expect(during).not.toBe(before);
    expect(decompileInputsKey({})).toBe(before);
  });

  it("does not depend on insertion order", () => {
    const a: Record<number, string> = {};
    a[0x402000] = "second";
    a[0x401000] = "first";
    const b: Record<number, string> = {};
    b[0x401000] = "first";
    b[0x402000] = "second";
    expect(decompileInputsKey(a)).toBe(decompileInputsKey(b));
  });

  it("covers a rename of ANOTHER function, deliberately", () => {
    // A rename of `sub_402000` changes the C of every function that calls it,
    // and the callers are not known here (`callGraph` is null before xrefs
    // finish and after a timeout). So the key is over all renames, not the
    // function's own: coarse, and never silently stale.
    expect(decompileInputsKey({ 0x402000: "helper" })).not.toBe(decompileInputsKey({}));
  });

  it("keeps two renames apart from one whose name happens to contain the other", () => {
    expect(decompileInputsKey({ 0x1: "a", 0x2: "b" })).not.toBe(
      decompileInputsKey({ 0x1: "a\x002=b" }),
    );
  });
});

describe("low-level cache: results are scoped to the renames they were emitted under", () => {
  const low = (code: string, inputsKey: string): LowCacheEntry => ({
    code,
    lineMap: new Map(),
    admissions: emptyAdmissions(),
    inputsKey,
  });

  it("hits under the key it was written with", () => {
    const cache = new Map<number, LowCacheEntry>();
    const key = decompileInputsKey({});
    writeLowCache(cache, 0x401000, low("int sub_401000() {}", key));
    expect(readLowCache(cache, 0x401000, key)?.code).toBe("int sub_401000() {}");
  });

  it("misses on a stale key — a rename after the entry was written", () => {
    const cache = new Map<number, LowCacheEntry>();
    writeLowCache(cache, 0x401000, low("int sub_401000() {}", decompileInputsKey({})));
    expect(readLowCache(cache, 0x401000, decompileInputsKey({ 0x401000: "main" }))).toBeNull();
  });

  it("hits again when the rename is reverted", () => {
    const cache = new Map<number, LowCacheEntry>();
    const plain = decompileInputsKey({});
    writeLowCache(cache, 0x401000, low("int sub_401000() {}", plain));
    expect(readLowCache(cache, 0x401000, decompileInputsKey({ 0x401000: "main" }))).toBeNull();
    expect(readLowCache(cache, 0x401000, plain)?.code).toBe("int sub_401000() {}");
  });

  it("misses for an address never written", () => {
    const cache = new Map<number, LowCacheEntry>();
    expect(readLowCache(cache, 0x401000, decompileInputsKey({}))).toBeNull();
  });

  it("replaces the entry rather than keeping both", () => {
    const cache = new Map<number, LowCacheEntry>();
    writeLowCache(cache, 0x401000, low("old", decompileInputsKey({})));
    writeLowCache(cache, 0x401000, low("new", decompileInputsKey({ 0x401000: "main" })));
    expect(cache.size).toBe(1);
    expect(readLowCache(cache, 0x401000, decompileInputsKey({}))).toBeNull();
  });
});

describe("decompileServerKey", () => {
  it("collapses every disabled configuration to one key", () => {
    expect(decompileServerKey(DISABLED)).toBe("none");
    expect(decompileServerKey({ ...DISABLED, ghidraUrl: "http://other:1234", apiKey: "k" })).toBe(
      "none",
    );
  });

  it("distinguishes enabled from disabled", () => {
    expect(decompileServerKey(ENABLED)).not.toBe(decompileServerKey(DISABLED));
  });

  it("distinguishes servers by url and by api key", () => {
    expect(decompileServerKey({ ...ENABLED, ghidraUrl: "http://other:1234" })).not.toBe(
      decompileServerKey(ENABLED),
    );
    expect(decompileServerKey({ ...ENABLED, apiKey: "secret" })).not.toBe(
      decompileServerKey(ENABLED),
    );
  });

  it("treats a trailing slash as the same server (GhidraClient strips it)", () => {
    expect(decompileServerKey({ ...ENABLED, ghidraUrl: "http://localhost:8765/" })).toBe(
      decompileServerKey(ENABLED),
    );
    expect(decompileServerKey({ ...ENABLED, ghidraUrl: "http://localhost:8765///" })).toBe(
      decompileServerKey(ENABLED),
    );
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
      type: "LOAD_OK",
      tab: "high",
      code: PLACEHOLDER,
      lineMap: new Map(),
      engine: "none",
    });
    expect(withPlaceholder.high.engine).toBe("none");

    const withGhidra = tabsReducer(withPlaceholder, {
      type: "LOAD_OK",
      tab: "high",
      code: "int main() {}",
      lineMap: new Map(),
      engine: "ghidra",
    });
    expect(withGhidra.high.engine).toBe("ghidra");
    expect(withGhidra.high.code).toBe("int main() {}");
  });

  it("RESET_FUNC drops the stale engine label with the code", () => {
    const loaded = tabsReducer(initialTabsState(), {
      type: "LOAD_OK",
      tab: "high",
      code: "x",
      lineMap: new Map(),
      engine: "ghidra",
    });
    const reset = tabsReducer(loaded, { type: "RESET_FUNC" });
    expect(reset.high.engine).toBeUndefined();
    expect(reset.high.code).toBe("");
    expect(reset.high.ready).toBe(false);
  });
});

/**
 * The admissions line's sentence (peek-a-bin-n9cl.7). One pure function owns
 * the count and the wording, so the panel cannot print a number beside the
 * wrong word; tested here without a DOM, the way `matchSummary` is.
 */
describe("admissionSummary", () => {
  const adm = (over: Partial<DecompileAdmissions>): DecompileAdmissions => ({
    ...emptyAdmissions(),
    ...over,
  });

  it("prints nothing for a function recovered whole", () => {
    expect(admissionSummary(emptyAdmissions())).toEqual([]);
  });

  it("prints one clause per non-empty kind, in a fixed order, with the count as the length", () => {
    const parts = admissionSummary(
      adm({ unrecovered: [12, 40, 41], unlifted: [7, 8, 9, 10, 11], gotos: [30, 60] }),
    );
    expect(parts.map((p) => p.text)).toEqual(["3 unrecovered", "5 unlifted", "2 goto"]);
    expect(parts.map((p) => p.text).join(ADMISSION_SEPARATOR)).toBe(
      "3 unrecovered · 5 unlifted · 2 goto",
    );
  });

  it("omits a kind with no sites rather than printing a zero", () => {
    const parts = admissionSummary(adm({ gotos: [4] }));
    expect(parts.map((p) => p.text)).toEqual(["1 goto"]);
  });

  it("names the FIRST site as the scroll target", () => {
    const parts = admissionSummary(adm({ unlifted: [9, 3, 20] }));
    // The emitter pushes indices in line order, so [0] is the first line; the
    // summary takes [0] rather than re-sorting — it is a reading, not a repair.
    expect(parts[0].firstLine).toBe(9);
  });

  it("keeps the order fixed whatever the counts", () => {
    const parts = admissionSummary(
      adm({ unrecovered: [1], unlifted: [2, 3, 4, 5], gotos: [6, 7] }),
    );
    expect(parts.map((p) => p.kind)).toEqual(["unrecovered", "unlifted", "gotos"]);
  });
});

describe("tabs reducer carries the admissions with the code", () => {
  it("LOAD_OK on the low tab stores them, and the other tabs have none", () => {
    const admissions = { ...emptyAdmissions(), unlifted: [3] };
    const s = tabsReducer(initialTabsState(), {
      type: "LOAD_OK",
      tab: "low",
      code: "int f() {}",
      lineMap: new Map(),
      admissions,
    });
    expect(s.low.admissions).toBe(admissions);
    expect(s.high.admissions).toBeUndefined();
    expect(s.ai.admissions).toBeUndefined();
  });

  it("a LOAD_OK without admissions (High Level, AI) leaves the field undefined", () => {
    const s = tabsReducer(initialTabsState(), {
      type: "LOAD_OK",
      tab: "high",
      code: "int f() {}",
      lineMap: new Map(),
      engine: "ghidra",
    });
    expect(s.high.admissions).toBeUndefined();
  });

  it("RESET_FUNC clears them with the code", () => {
    const loaded = tabsReducer(initialTabsState(), {
      type: "LOAD_OK",
      tab: "low",
      code: "int f() {}",
      lineMap: new Map(),
      admissions: { ...emptyAdmissions(), gotos: [1] },
    });
    const reset = tabsReducer(loaded, { type: "RESET_FUNC" });
    expect(reset.low.admissions).toBeUndefined();
    expect(reset.low.code).toBe("");
  });
});
