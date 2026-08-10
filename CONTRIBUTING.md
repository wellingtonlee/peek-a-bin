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
3. Verify: `npm run lint && npm run typecheck && npm test && npm run build`
4. Commit with a descriptive message
5. Open a PR against `main`

## Verification

Always run before submitting:

```bash
npm run lint
npm run typecheck
npm test
npm run build
```

CI runs `lint`, `typecheck`, `test` and `build` on every push and PR to `main`, plus a separate
`npm audit --audit-level=high` job.

## Code Style

- **File naming:** Components = `PascalCase.tsx`, hooks = `useCamelCase.ts`, modules = `camelCase.ts`
- **TypeScript:** Strict mode enabled. No `any` leaks.
- **Styling:** Tailwind utility classes with theme-aware CSS variables (`--t-*`)
- See `CLAUDE.md` for full conventions (don't duplicate here)

## Testing

- Framework: [Vitest](https://vitest.dev/)
- PE parsing tests: `src/pe/__tests__/`
- Disassembly tests: `src/disasm/__tests__/`
- Decompiler tests: `src/disasm/decompile/__tests__/`
- MCP server tests: `src/mcp/__tests__/`
- Utility tests: `src/utils/__tests__/`
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
| New keyboard shortcut | Add to `SHORTCUT_GROUPS` in `src/components/KeyboardShortcuts.tsx` + [docs/keyboard.md](docs/keyboard.md) |

## Pull Request Process

- CI must pass (lint, type-check, tests, build, audit)
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

If your change affects user-facing behavior, update the matching `docs/` file. The mapping from
"what you changed" to "what to update" lives in one place:
**[docs/README.md → Which doc do I update?](docs/README.md#which-doc-do-i-update)**
