/**
 * Every event the command palette can fire is one something already listens for.
 *
 * `PaletteEventName` is a closed union, which stops a *typo* at the call site
 * and nothing else: adding a member for an event no component listens for
 * type-checks perfectly, and `window.dispatchEvent` is happy to fire it. The
 * result is a palette row that silently does nothing — the class the
 * `ResultTarget` union was introduced to close, arriving through the one door
 * the type leaves open.
 *
 * So the union is derived from `PALETTE_EVENTS` and this reads the array back
 * against the source text. A source scrape, deliberately: whether a listener
 * exists is a fact about another module's `useEffect`, and nothing at runtime
 * here can see it — the palette dispatches on `window` whether or not anyone is
 * listening, and `dispatchEvent` returns `true` either way.
 *
 * NOT a `*.dom.test.tsx`: it renders nothing, and `import.meta.url` is not a
 * `file:` URL under jsdom, so `fileURLToPath` would throw (see
 * `build/domTestNaming.test.ts`, which was bitten by exactly that).
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { PALETTE_EVENTS } from "../CommandPalette";

const SRC_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");

/** Every `.ts`/`.tsx` under `src/`, tests excluded — a test listener is not a listener. */
function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const entry of readdirSync(dir)) {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      if (entry !== "__tests__" && entry !== "test") sourceFiles(full, out);
    } else if (/\.tsx?$/.test(entry) && !/\.test\.tsx?$/.test(entry)) {
      out.push(full);
    }
  }
  return out;
}

const SOURCES = sourceFiles(SRC_DIR).map((f) => readFileSync(f, "utf-8"));

describe("palette events", () => {
  it("has a non-empty table and a non-empty corpus to check it against", () => {
    // The liveness half: a scrape that matches nothing passes by no longer
    // looking, and so does an empty event table.
    expect(PALETTE_EVENTS.length).toBeGreaterThan(0);
    expect(SOURCES.length).toBeGreaterThan(20);
    expect(SOURCES.some((s) => s.includes('addEventListener("peek-a-bin:'))).toBe(true);
  });

  it("names only events something in src/ listens for", () => {
    for (const event of PALETTE_EVENTS) {
      // Written with the quote inside the needle so a listener registered on a
      // variable, which this cannot verify, does not accidentally match.
      const needle = `addEventListener("${event}"`;
      expect(
        SOURCES.some((s) => s.includes(needle)),
        `no component listens for ${event}`,
      ).toBe(true);
    }
  });
});
