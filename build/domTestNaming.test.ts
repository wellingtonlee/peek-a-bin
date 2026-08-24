/**
 * Drift guard: the component tests' two-part opt-in must stay intact, in both
 * directions.
 *
 * There is one vitest config and its default environment is node — right for
 * the ~110 suites that are pure TypeScript over plain data, and wrong for the
 * handful that render React. Those opt in per file, with two things:
 *
 *   1. the marker `@vitest-environment`, then `jsdom`, in a `//` comment on the
 *      first line (written apart here on purpose — see below), and
 *   2. `import "…/test/domSetup";`, which installs the `offsetParent` stand-in
 *      jsdom does not provide and registers the unmount-between-tests hook.
 *
 * Both were measured alternatives to a global setting: `test.projects` breaks
 * `--dir` and a global `setupFiles` cost 3.0s across the node suites (see
 * `vitest.config.ts` and `src/test/domSetup.ts`). The price of that is two
 * things to remember instead of zero, which is what this guards.
 *
 * FORGETTING EITHER ONE FAILS QUIETLY IN A DIFFERENT WAY, which is why both are
 * checked rather than just the docblock:
 *
 *  - no docblock: `document is not defined`, loud, but only if the file happens
 *    to touch the DOM at import time;
 *  - no `domSetup` import: `offsetParent` stays jsdom's constant `null`, so
 *    `focusableWithin` returns `[]` for every dialog and a focus-trap test goes
 *    VACUOUSLY GREEN — and `cleanup()` never runs, so trees and focus leak from
 *    one test into the next.
 *
 * The reverse direction matters too: a DOM-rendering test that is NOT named
 * `*.dom.test.tsx` is invisible to a reader scanning a directory listing and to
 * anyone grepping for which suites need an environment.
 *
 * BEWARE WRITING THE DOCBLOCK OUT IN FULL ANYWHERE. Vitest's `detectCodeBlock`
 * runs `content.match(/@(?:vitest|jest)-environment\s+([\w-]+)\b/)` over the
 * WHOLE FILE, not over the leading comment — so a mention of it in a string, or
 * in prose like this one, silently moves that file into jsdom. This guard hit it
 * immediately: with the marker spelled literally as a constant, this node-only
 * file ran under jsdom and died on `fileURLToPath` at import. Hence the split
 * below. (This paragraph is safe: the two halves are never adjacent.)
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const srcDir = fileURLToPath(new URL("../src", import.meta.url));

// Split so this file does not match vitest's own scan — see the note above.
const ENVIRONMENT_DOCBLOCK = `// @vitest-${"environment"} jsdom`;
const SETUP_IMPORT = /^import ["'][^"']*\/domSetup["'];$/m;
/** Any module that only makes sense with a document behind it. */
const NEEDS_A_DOCUMENT = /from "@testing-library\/(react|user-event|dom)"/;

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(p));
    else if (/\.tsx?$/.test(entry.name)) out.push(p);
  }
  return out.sort();
}

const files = walk(srcDir);
const domTests = files.filter((f) => f.endsWith(".dom.test.tsx"));
const rel = (f: string) => f.slice(srcDir.length + 1);

describe("component tests declare their environment", () => {
  it("finds some, so the checks below are not vacuous", () => {
    // A scrape that matches nothing reports a clean tree.
    expect(domTests.length).toBeGreaterThan(0);
  });

  it.each(domTests.map(rel))("%s opens with the jsdom docblock", (name) => {
    const src = readFileSync(join(srcDir, name), "utf8");
    expect(src.split("\n")[0]).toBe(ENVIRONMENT_DOCBLOCK);
  });

  it.each(domTests.map(rel))("%s imports the shared DOM setup", (name) => {
    const src = readFileSync(join(srcDir, name), "utf8");
    expect(src).toMatch(SETUP_IMPORT);
  });

  it("has no DOM-rendering test hiding under another name", () => {
    const stragglers = files
      .filter((f) => !f.endsWith(".dom.test.tsx"))
      .filter((f) => /\.(test|spec)\.tsx?$/.test(f))
      .filter((f) => NEEDS_A_DOCUMENT.test(readFileSync(f, "utf8")))
      .map(rel);
    expect(stragglers).toEqual([]);
  });

  it("keeps the setup module out of the node suites", () => {
    // If it were ever added to `setupFiles`, every node suite would load
    // @testing-library/react again — the 3.0s this arrangement exists to avoid.
    // Adding it back TODAY fails louder than this (the setup file touches
    // `HTMLElement`, which node has not got), but re-guarding it with a
    // `typeof document` check would make the same mistake silent, and that is
    // the arrangement this catches.
    const config = readFileSync(fileURLToPath(new URL("../vitest.config.ts", import.meta.url)), "utf8");
    // The KEY, not the word: the config's own comment explains why it is absent.
    expect(config).not.toMatch(/^\s*setupFiles\s*:/m);
  });
});
