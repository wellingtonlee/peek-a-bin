# Peek-a-Bin

Browser-based PE disassembler/analyzer. Fully client-side (no server). PWA with offline support.

**Tech**: React 19, TypeScript 5.7 (strict), Vite 6, Tailwind CSS 4, capstone-wasm (WASM disassembly engine), @tanstack/react-virtual, @dagrejs/dagre

## Commands

```sh
npm run dev          # dev server
npm run build        # tsc -b && vite build (use for verification)
npm test             # vitest run (78 tests: PE parsing + decompiler)
npx tsc --noEmit     # type check only (faster than full build)
```

## Source Layout (`src/`)

- `pe/` — PE format parser (headers, imports, exports, resources, authenticode)
- `disasm/` — disassembly engine, types, CFG, operand parsing, stack analysis, signatures
- `disasm/decompile/` — IR lifting → SSA → folding → structuring → cleanup → type inference → promotion → struct synthesis → emission pipeline
- `components/` — React components (DisassemblyView, CFGView, HexView, Sidebar, etc.)
- `hooks/` — state management (usePEFile), derived state, disassembly rows, search
- `workers/` — Web Worker for Capstone WASM + off-thread analysis (disasm.worker.ts + disasmClient.ts)
- `analysis/` — driver detection, anomalies, IOCTL decoding
- `llm/` — LLM integration (multi-profile settings, streaming client, prompts, types)
- `utils/` — recent files (IndexedDB), export schema, entropy, fuzzy match

## Architecture

**State**: `useReducer` + React Context in `src/hooks/usePEFile.ts`. `AppState` (33+ fields), `AppAction` discriminated union (48 action types). Access via `useAppState()` / `useAppDispatch()`.

**Worker**: RPC-style communication in `src/workers/disasmClient.ts`. Heavy work (disassembly, function detection, xref building, decompilation) runs off-thread. Client caches results (disasm, xref, decompile caches).

**Pipeline**: File drop → `parsePE()` → detect functions (worker) → hybrid disassemble (recursive + gap-fill) → build xrefs → extract strings. All async, phased via `analysisPhase` state.

**Rendering**: Virtual scrolling via `@tanstack/react-virtual`. `DisplayRow` union type: `label | insn | separator | data`. `DisassemblyView` + `HexView` are lazy-loaded.

**CFG**: `buildCFG()` + `layoutCFG()` (dagre) in `src/disasm/cfg.ts`. Inline graph view toggled with Space key.

**Styling**: Tailwind utility classes. Runtime font size via `--mono-font-size` CSS variable set on app root.

**AI Features**: 4 AI-powered tools: Chat (multi-turn, `useAIChat`), Batch Rename (`useBatchRename`), Report (`useAIReport`), Vulnerability Scanner (`useVulnScanner`). All use `streamChat()` from `src/llm/client.ts`. Chat panel is local state in DisassemblyView. Batch rename/report/scan state in `AppState` (batchRename, aiReport, aiScanResults). Triggered via custom events (`peek-a-bin:open-chat`, `peek-a-bin:batch-rename`, `peek-a-bin:generate-report`, `peek-a-bin:ai-scan`). Markdown rendering via `marked` library in `MarkdownRenderer.tsx`.

## Conventions

**File naming**: Components = PascalCase.tsx, hooks = useCamelCase.ts, modules = camelCase.ts

**localStorage**: `peek-a-bin:<feature>` namespace (e.g. `peek-a-bin:llm-profiles`, `peek-a-bin:font-size`, `peek-a-bin:view-mode`, `peek-a-bin:chat:${fileName}`, `peek-a-bin:report:${fileName}`, `peek-a-bin:chat-width`). Legacy `peek-a-bin:llm-settings` auto-migrates to `peek-a-bin:llm-profiles` on first load.

**Custom events**: `window.dispatchEvent(new CustomEvent("peek-a-bin:<action>"))` for cross-component communication

**New state**: Add action to `AppAction` union in usePEFile.ts, handle in `appReducer` switch.

**New component types**: If a component defines its own `DisplayRow` (JumpArrows, DisassemblyMinimap), keep it in sync with the canonical one in useDisassemblyRows.ts.

**Annotations**: Bookmarks, renames, comments auto-persist to localStorage per file. Undo/redo via snapshot stack.

**Tests**: `src/pe/__tests__/` for PE parsing. `src/disasm/decompile/__tests__/` for decompiler (fold rules, SSA). Use `buildMinimalPE32()` / `buildMinimalPE64()` fixture builders (no binary files).

## Decompiler Architecture (`src/disasm/decompile/`)

**Pipeline** (`pipeline.ts`): `buildCFG → liftBlock → buildSSA → ssaOptimize → destroySSA → foldBlock → structureCFG → cleanupStructured → inferTypes → promoteVars → synthesizeStructs → emitFunction`

**IR** (`ir.ts`): `IRExpr` union (13 kinds: const, reg, var, binary, unary, deref, call, cast, ternary, field_access, array_access, unknown) + `IRStmt` union (17 kinds including if/while/do_while/for/switch/break/continue/phi). All expression walkers (`walkExpr`, `walkStmts`) must handle every `IRExpr` kind.

**Adding new IRExpr kinds**: Update walkers in `ir.ts` (`walkExpr`), `fold.ts` (`foldExpr`, `countReads`, `substituteReg`, `hasSideEffects`), `ssaopt.ts` (`replaceRegInExpr`, `countExprUses`, `hasSideEffects`), `promote.ts` (`promoteExpr`), `structs.ts` (`walkExprs`, `rewriteExpr`), `emit.ts` (`emitExpr`). Missing any walker causes silent data loss.

**Adding new IRStmt kinds**: Update `foldStmt` in `fold.ts`, `emitStmt` in `emit.ts`, `walkStmts` in `ir.ts`, and control flow handlers in `structure.ts`/`cleanup.ts`.

**Type system** (`typeInfer.ts`): `DecompType` lattice with 11 kinds (unknown, int, float, ptr, bool, void, struct, array, handle, ntstatus, hresult). `meetTypes()` merges types — specific wins over unknown, handle/ntstatus/hresult win over int/ptr.

**API signatures** (`apitypes.ts`): ~130 Win32/NT API type signatures. Use type shorthands (PVOID, HANDLE_T, NTSTATUS_T, etc.) for consistency. Return `HANDLE_T` for handle-returning APIs, `NTSTATUS_T` for Nt/Zw, `HRESULT_T` for COM.

**Struct synthesis** (`structs.ts`): `StructRegistry` is cross-function state shared in the worker. `decomposeAddress()` breaks `base + idx*scale + offset` patterns. 2+ distinct offsets on same base → struct candidate. Scale ∈ {1,2,4,8} without struct match → `IRArrayAccess`.

**emit.ts module-level `_typeCtx`**: Set before emission, cleared after. Enables cast suppression and type-aware idioms (INVALID_HANDLE_VALUE, NT_SUCCESS, SUCCEEDED/FAILED).

## Gotchas

- **DisassemblyView.tsx** is ~2000 lines. Read in chunks.
- **JumpArrows.tsx** and **DisassemblyMinimap.tsx** have their own local `DisplayRow` types — must update when extending the canonical union.
- `sectionInfo.characteristics & 0x20000000` = `IMAGE_SCN_MEM_EXECUTE`. Used to distinguish code vs data sections.
- Worker uses Transferable for large arrays. Don't hold references to transferred buffers.
- Capstone WASM is cached in IndexedDB (`peek-a-bin-wasm`). First load fetches, subsequent loads read from cache.
- **`fold.ts` has a `castTypeSize` helper** for double-cast removal. Uses regex to extract bit width from type strings like `int32_t`.
- **`cleanup.ts`** runs after `structureCFG`, before `inferTypes`. Guard clause flattening is single-level only (not recursive inversion).
- **`StructRegistry`** persists across decompilation calls in the worker — don't clear it between functions in the same session.

## Verification

Always run after changes:

```sh
npx tsc --noEmit && npx vite build
npm test
```

## Documentation

When making architectural changes, adding major features, or changing conventions, update this file (`CLAUDE.md`) so future AI agents have accurate context. This includes new source directories, new pipeline stages, new conventions, new gotchas, and changes to the build/test commands.

Update `README.md` when changes affect the public-facing project description: new features, new commands, setup instructions, configuration formats, or project structure changes.

## CHANGELOG Convention

Maintain `CHANGELOG.md` under `## [Unreleased]` with `### Added`, `### Changed`, `### Fixed`, `### Removed`. Each entry: `- **Feature name** — concise description`

When editing CHANGELOG.md, append a timestamp to each new or modified entry in the format `(YYYY-MM-DD HH:MM)` using the current date and time. Example: `- **Feature name** — concise description (2026-03-06 15:30)`
