import { defineConfig } from "vitest/config";

/**
 * ONE config, one environment default, and the DOM opt-in is per file.
 *
 * This config deliberately does NOT `mergeConfig` with `vite.config.ts`. Almost
 * every suite here is pure TypeScript over plain data — no DOM, no JSX — and
 * pushing 110+ such files through the React, Tailwind and PWA plugins buys
 * nothing and costs transform time on every one of them.
 *
 * A handful of suites *do* render components. Each opts in with a docblock on
 * its first line:
 *
 *     // @vitest-environment jsdom
 *
 * and is named `*.dom.test.tsx` so the opt-in is visible from a directory
 * listing. `build/domTestNaming.test.ts` fails the ordinary suite if those two
 * ever come apart.
 *
 * WHY NOT `test.projects`, which is the documented Vitest 4 replacement for the
 * removed `environmentMatchGlobs`: it was implemented, and it BREAKS `--dir`.
 * The CLI's `--dir` is not propagated into project configs, so under a
 * two-project config `npx vitest run --dir build` runs all 114 files instead of
 * 12 — measured. CLAUDE.md documents `--dir` as the way to keep a root run out
 * of sibling agent worktrees, and it is how the gates are invoked, so silently
 * disarming it is a worse regression than anything projects would have bought.
 *
 * WHY NO `@vitejs/plugin-react`: it is not needed. Vite transforms `.tsx` with
 * esbuild, which reads `jsx: "react-jsx"` from `tsconfig.json` and emits the
 * automatic runtime — verified, the component tests render without it. The
 * plugin's own value is Fast Refresh and a Babel pipeline, neither of which a
 * test run uses. So the DOM opt-in costs the node suites nothing at all: not a
 * plugin, not a transform, and not a setup module — `src/test/domSetup.ts` is
 * IMPORTED by each component test rather than listed as `setupFiles` here,
 * because vitest loads a setup module once per test file and doing so cost 3.0s
 * across the ~110 files that want nothing from it (see that file).
 *
 * Tailwind and the PWA plugin stay out for their own reasons. Nothing asserts on
 * a computed style — jsdom does no layout, so a class either is or is not on the
 * element, which is decidable from `className` and is what `modalScaffold.ts`'s
 * pure class-composition tests already cover. And there is no service worker in
 * jsdom and no build output to precache.
 */
export default defineConfig({
  test: {
    coverage: {
      // NB: `@vitest/coverage-v8` is not installed, so `npm run test:coverage`
      // fails. That predates this config and is deliberately not fixed here.
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/__tests__/**", "src/**/*.d.ts"],
    },
  },
});
