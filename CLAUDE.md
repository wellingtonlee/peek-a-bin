# Peek-a-Bin

Browser-based PE disassembler/analyzer. Fully client-side (no server). PWA with offline support.

**Tech**: React 19, TypeScript 5.7 (strict), Vite 6, Tailwind CSS 4, capstone-wasm (WASM disassembly engine), @tanstack/react-virtual, @dagrejs/dagre

## Commands

```sh
npm run dev          # dev server
npm run build        # tsc -b && vite build (use for verification)
npm test             # vitest run (27 tests, PE parsing)
npx tsc --noEmit     # type check only (faster than full build)
```

## Source Layout (`src/`)

- `pe/` — PE format parser (headers, imports, exports, resources, authenticode)
- `disasm/` — disassembly engine, types, CFG, operand parsing, stack analysis, signatures
- `disasm/decompile/` — IR lifting → folding → structuring → emission pipeline
- `components/` — React components (DisassemblyView, CFGView, HexView, Sidebar, etc.)
- `hooks/` — state management (usePEFile), derived state, disassembly rows, search
- `workers/` — Web Worker for Capstone WASM + off-thread analysis (disasm.worker.ts + disasmClient.ts)
- `analysis/` — driver detection, anomalies, IOCTL decoding
- `llm/` — LLM integration (settings, streaming client, prompts)
- `utils/` — recent files (IndexedDB), export schema, entropy, fuzzy match

## Architecture

**State**: `useReducer` + React Context in `src/hooks/usePEFile.ts`. `AppState` (30+ fields), `AppAction` discriminated union (36 action types). Access via `useAppState()` / `useAppDispatch()`.

**Worker**: RPC-style communication in `src/workers/disasmClient.ts`. Heavy work (disassembly, function detection, xref building, decompilation) runs off-thread. Client caches results (disasm, xref, decompile caches).

**Pipeline**: File drop → `parsePE()` → detect functions (worker) → hybrid disassemble (recursive + gap-fill) → build xrefs → extract strings. All async, phased via `analysisPhase` state.

**Rendering**: Virtual scrolling via `@tanstack/react-virtual`. `DisplayRow` union type: `label | insn | separator | data`. `DisassemblyView` + `HexView` are lazy-loaded.

**CFG**: `buildCFG()` + `layoutCFG()` (dagre) in `src/disasm/cfg.ts`. Inline graph view toggled with Space key.

**Styling**: Tailwind utility classes. Runtime font size via `--mono-font-size` CSS variable set on app root.

## Conventions

**File naming**: Components = PascalCase.tsx, hooks = useCamelCase.ts, modules = camelCase.ts

**localStorage**: `peek-a-bin:<feature>` namespace (e.g. `peek-a-bin:llm-settings`, `peek-a-bin:font-size`, `peek-a-bin:view-mode`)

**Custom events**: `window.dispatchEvent(new CustomEvent("peek-a-bin:<action>"))` for cross-component communication

**New state**: Add action to `AppAction` union in usePEFile.ts, handle in `appReducer` switch.

**New component types**: If a component defines its own `DisplayRow` (JumpArrows, DisassemblyMinimap), keep it in sync with the canonical one in useDisassemblyRows.ts.

**Annotations**: Bookmarks, renames, comments auto-persist to localStorage per file. Undo/redo via snapshot stack.

**Tests**: `src/pe/__tests__/`. Use `buildMinimalPE32()` / `buildMinimalPE64()` fixture builders (no binary files).

## Gotchas

- **DisassemblyView.tsx** is ~2000 lines. Read in chunks.
- **JumpArrows.tsx** and **DisassemblyMinimap.tsx** have their own local `DisplayRow` types — must update when extending the canonical union.
- `sectionInfo.characteristics & 0x20000000` = `IMAGE_SCN_MEM_EXECUTE`. Used to distinguish code vs data sections.
- Worker uses Transferable for large arrays. Don't hold references to transferred buffers.
- Capstone WASM is cached in IndexedDB (`peek-a-bin-wasm`). First load fetches, subsequent loads read from cache.

## Verification

Always run after changes:

```sh
npx tsc --noEmit && npx vite build
npm test
```

## CHANGELOG Convention

Maintain `CHANGELOG.md` under `## [Unreleased]` with `### Added`, `### Changed`, `### Fixed`, `### Removed`. Each entry: `- **Feature name** — concise description`

When editing CHANGELOG.md, append a timestamp to each new or modified entry in the format `(YYYY-MM-DD HH:MM)` using the current date and time. Example: `- **Feature name** — concise description (2026-03-06 15:30)`
