import { defineConfig } from 'vitest/config';

// NOTE: this config fully shadows vite.config.ts for test runs (no mergeConfig),
// so tests execute without the React/Tailwind/PWA plugins. That is fine for the
// current pure-TS suite; adding a component test will require merging them.
export default defineConfig({
  test: {
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov'],
      include: ['src/**/*.ts'],
      exclude: ['src/**/__tests__/**', 'src/**/*.d.ts'],
    },
  },
});
