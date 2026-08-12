/**
 * `biome.json` — the two properties of it that fail silently.
 *
 * 1. IT MUST BE STRICT JSON. Biome does not accept JSONC here: a single `//`
 *    comment does not warn, it voids the entire configuration and Biome falls
 *    back to its defaults. What that looks like from the outside is every rule
 *    setting in this file randomly ceasing to apply — `noNonNullAssertion` and
 *    `noParameterAssign` come back on, `useHookAtTopLevel` drops to a warning —
 *    with no message saying so.
 *
 * 2. `correctness/useExhaustiveDependencies` MUST BE AT `error`
 *    (peek-a-bin-7ki). `npm run lint` is `biome lint src`, which exits 0 on
 *    warnings, so at `warn` a missing React dependency cannot fail CI: it is
 *    visible only to someone who reads a 71-line warning list. There is no React
 *    renderer in this repo — nothing mounts a hook, nothing renders a component
 *    — so this rule is the only automated check of the whole stale-closure
 *    class, of which peek-a-bin-ehv (`D` opened the decompile panel but could
 *    not close it, because a memoized `handleKeyDown` closed over a `const`
 *    declared 340 lines later) is the worked example.
 *
 *    Measured before ratcheting: 0 findings across 230 files, so this cost
 *    nothing on the day. Verified in both directions — with a deliberate missing
 *    dependency present, `biome lint src` exits 1 at `error` and 0 at `warn`.
 *
 * The deliberate "dependency the body never reads, as a change key" pattern is
 * still allowed; at `error` it just has to say so with a `biome-ignore`, which
 * is the point. Note that a multi-line `biome-ignore` needs `//` on every line
 * — Biome honours the directive only on the line immediately preceding the
 * offence.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const path = fileURLToPath(new URL("../biome.json", import.meta.url));
const raw = readFileSync(path, "utf8");

describe("biome.json", () => {
  it("parses as strict JSON", () => {
    expect(() => JSON.parse(raw)).not.toThrow();
  });

  it("contains no comment of any kind", () => {
    // Asserted on the text as well as through the parser: a `/* … */` block in
    // a position JSON.parse happens to tolerate is not a thing, but the failure
    // mode is severe enough that this checks the shape a human would add.
    // String literals are blanked first, so the `//` inside the `$schema` URL
    // is not mistaken for a line comment.
    const offending = raw
      .split("\n")
      .map((line, i) => [i + 1, line.replace(/"(?:[^"\\]|\\.)*"/g, '""')] as const)
      .filter(([, line]) => line.includes("//") || line.includes("/*"));

    expect(
      offending,
      "biome.json must be strict JSON. A comment does not warn — it voids the whole " +
        "configuration and Biome silently falls back to its defaults.",
    ).toEqual([]);
  });

  it("keeps useExhaustiveDependencies at error, so a stale closure fails the gate", () => {
    const config = JSON.parse(raw);

    expect(
      config.linter?.rules?.correctness?.useExhaustiveDependencies,
      "`npm run lint` is `biome lint src`, which exits 0 on warnings. At 'warn' this rule " +
        "cannot fail CI, and it is the only automated check of the stale-closure class in a " +
        "repo with no React renderer (peek-a-bin-7ki).",
    ).toBe("error");
  });

  it("keeps useHookAtTopLevel at error alongside it", () => {
    // The other half of the same guarantee, and a canary for property 1: if the
    // config were voided, this would silently become Biome's default.
    expect(JSON.parse(raw).linter?.rules?.correctness?.useHookAtTopLevel).toBe("error");
  });
});
