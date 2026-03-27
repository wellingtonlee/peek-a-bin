# Contributing to Peek-a-Bin

## Getting Started

Requirements: **Node.js 20+** and **npm**.

```bash
git clone https://github.com/wellingtonlee/peek-a-bin.git
cd peek-a-bin
npm install
npm run dev
# http://localhost:5173/peek-a-bin/
```

## Development Workflow

1. Create a feature branch from `main`
2. Make your changes
3. Verify: `npx tsc --noEmit && npx vite build && npm test`
4. Commit with a descriptive message
5. Open a PR against `main`

## Verification

Always run before submitting:

```bash
npx tsc --noEmit && npx vite build
npm test
```

CI runs type-check and tests on every PR.

## Code Style

- **File naming:** Components = `PascalCase.tsx`, hooks = `useCamelCase.ts`, modules = `camelCase.ts`
- **TypeScript:** Strict mode enabled. No `any` leaks.
- **Styling:** Tailwind utility classes with theme-aware CSS variables (`--t-*`)
- See `CLAUDE.md` for full conventions (don't duplicate here)

## Testing

- Framework: [Vitest](https://vitest.dev/)
- PE parsing tests: `src/pe/__tests__/`
- Decompiler tests: `src/disasm/decompile/__tests__/`
- Fixture builders: `buildMinimalPE32()` / `buildMinimalPE64()` — no binary fixture files
- Run tests: `npm test` or `npm run test:watch` for watch mode

## Adding Features

| Area | Where to Start |
|------|---------------|
| New app state | Add action to `AppAction` union in `src/hooks/usePEFile.ts` |
| New IR expression | Follow checklist in [docs/decompiler.md](docs/decompiler.md#adding-new-irexpr-kinds) |
| New IR statement | Follow checklist in [docs/decompiler.md](docs/decompiler.md#adding-new-irstmt-kinds) |
| New MCP client | Add entry to registry in `src/mcp/clients.ts` — see [docs/mcp-server.md](docs/mcp-server.md#adding-new-clients) |
| New theme | See [docs/theming.md](docs/theming.md#custom-themes) |
| New keyboard shortcut | Update `ShortcutsPanel` component + [docs/keyboard.md](docs/keyboard.md) |

## Pull Request Process

- CI must pass (type-check + tests)
- One feature per PR — keep changes focused
- Update `CHANGELOG.md` under `[Unreleased]` with a timestamp: `(YYYY-MM-DD HH:MM)`
- Update relevant docs if your change affects user-facing behavior

## CHANGELOG Convention

Entries go under `## [Unreleased]` in the appropriate section:

- `### Added` — new features
- `### Changed` — changes to existing features
- `### Fixed` — bug fixes
- `### Removed` — removed features

Format: `- **Feature name** — concise description (YYYY-MM-DD HH:MM)`

## AI Agent Context

If your change introduces new conventions, gotchas, pipeline stages, or source directories, update `CLAUDE.md` so future AI agents have accurate context.

## Documentation

Update relevant `docs/` files when changes affect:
- Keyboard shortcuts → `docs/keyboard.md`
- Theme system → `docs/theming.md`
- AI features → `docs/ai-features.md`
- MCP server → `docs/mcp-server.md`
- Ghidra server → `docs/ghidra-server.md`
- Architecture → `docs/architecture.md`
- Decompiler internals → `docs/decompiler.md`
- Build/deploy → `docs/deployment.md`
