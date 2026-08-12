import { defineConfig } from "vitest/config";

/**
 * The corpus audits (`npm run corpus`) run under THIS config, not the default
 * one. Two things keep them out of `npm test`, deliberately belt and braces:
 *
 *  1. they are named `*.audit.ts`, which vitest's default `include` — which
 *     matches only `*.test.*` and `*.spec.*` — cannot match; and
 *  2. this config's `include` names only them.
 *
 * Either alone would do. Both together mean that neither renaming a file nor
 * editing a config can quietly put a run that needs machine-local binaries and
 * a C compiler into CI. `build/corpusIsolation.test.ts` fails the ordinary
 * suite if the first of those stops holding.
 */
export default defineConfig({
  test: {
    include: ["corpus/**/*.audit.ts"],
    // One binary at a time: each sweep holds a whole decompiled image in
    // memory, and the audits are I/O and compiler bound rather than CPU bound.
    fileParallelism: false,
    testTimeout: 600_000,
    hookTimeout: 3_600_000,
  },
});
