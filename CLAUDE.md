# Peek-a-Bin

Browser-based PE disassembler/analyzer. Fully client-side (no server). PWA with offline support.

**Tech**: React 19, TypeScript 5.7 (strict), Vite 6, Tailwind CSS 4, capstone-wasm (WASM disassembly engine), @tanstack/react-virtual, @dagrejs/dagre

**Requires Node 20+** (`engines.node` in package.json). On Node 18 the build reaches the end of
bundling and then dies with `ReferenceError: crypto is not defined` — `serialize-javascript`
(pulled in via `@rollup/plugin-terser`, i.e. the PWA/Workbox path) calls the global `crypto`,
which Node only exposes unflagged from 20 onward. Workaround if you are stuck on 18:
`node --experimental-global-webcrypto ./node_modules/vite/bin/vite.js build`.

## Commands

```sh
npm run dev            # dev server
npm run build          # tsc -b && vite build (use for verification)
npm test               # vitest run (PE parsing + disasm + decompiler + MCP + utils)
npm run typecheck      # tsc --noEmit (faster than full build)
npm run lint           # biome lint src
npm run format         # biome format --write
npm run check          # biome check
npm run test:coverage  # vitest run --coverage (v8 provider)
```

**Biome** (`biome.json`) is the linter/formatter. The whole `a11y` group is set to `warn`, not
error — there is a real accessibility backlog and the warnings keep it visible without blocking
CI. `correctness/useHookAtTopLevel` is `error`. CI runs `lint`, `typecheck`, `test` and `build`
on every PR, plus a separate `npm audit --audit-level=high` job.

## Source Layout (`src/`)

- `pe/` — PE format parser (headers, imports, exports, resources, authenticode)
- `disasm/` — disassembly engine, types, CFG, operand parsing, stack analysis, signatures
- `disasm/decompile/` — IR lifting → SSA → folding → structuring → cleanup → type inference → promotion → struct synthesis → emission pipeline
- `components/` — React components (DisassemblyView, CFGView, HexView, Sidebar, etc.)
- `hooks/` — state management (usePEFile), derived state, disassembly rows, search
- `workers/` — Web Worker for Capstone WASM + off-thread analysis (disasm.worker.ts + disasmClient.ts)
- `analysis/` — driver detection, anomalies, IOCTL decoding
- `llm/` — LLM integration (multi-profile settings, streaming client, prompts, types)
- `mcp/` — MCP server (tools, resources, session, Capstone wrapper) + `cli.ts` (setup command) + `clients.ts` (client config registry)
- `utils/` — recent files (IndexedDB), export schema, entropy, fuzzy match

## Architecture

**State**: `useReducer` + React Context in `src/hooks/usePEFile.ts`. `AppState` (31 fields), `AppAction` discriminated union (50 action types). Access via `useAppState()` / `useAppDispatch()`.

`AnalysisPhase` includes a `"failed"` value — the analysis chain rejects into it, and the status
bar surfaces it. Without it a failed parse left the UI spinning forever. `usePEFile.ts` also
exports `parseViewTab()`, which narrows the `#tab=` URL parameter; do not cast that string to
`ViewTab` directly.

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

**Tests**: `src/pe/__tests__/` for PE parsing (including `malformed.test.ts` for adversarial input), `src/disasm/__tests__/` for CFG/operands/signatures/mnemonics, `src/disasm/decompile/__tests__/` for the decompiler (fold rules, SSA, dominators, emit, enum, loops, exceptions), `src/mcp/__tests__/` for the MCP server, `src/utils/__tests__/` for the export schema and annotation validation. Use `buildMinimalPE32()` / `buildMinimalPE64()` fixture builders from `src/pe/__tests__/fixtures.ts` (no binary files).

Don't hard-code a test count in docs — it goes stale within a session. Run `npm test` for the current number.

**MCP setup CLI**: `npx tsx src/mcp/index.ts setup <client>` configures AI clients (claude-code, opencode, continue). Registry in `src/mcp/clients.ts` — add new clients by inserting a map entry. `.mcp.json` at project root enables Claude Code auto-discovery.

## Decompiler Architecture (`src/disasm/decompile/`)

**Pipeline** (`pipeline.ts`): `buildCFG → liftBlock → buildSSA → ssaOptimize → destroySSA → foldBlock → structureCFG → cleanupStructured → wrapExceptionRegions → inferTypes → promoteVars → synthesizeStructs → emitFunction`

(`wrapExceptionRegions` is local to `pipeline.ts` and only runs when `.pdata` exception info is
present. The docstring at the top of `pipeline.ts` lists a shorter, outdated order — trust the
code, not that comment.)

**IR** (`ir.ts`): `IRExpr` union (12 kinds: const, reg, var, binary, unary, deref, call, cast, ternary, field_access, array_access, unknown) + `IRStmt` union (17 kinds including if/while/do_while/for/switch/break/continue/phi/try).

### Adding new IRExpr / IRStmt kinds

Adding a kind means updating every switch that dispatches on `expr.kind` / `stmt.kind` — there
are ~30 of them, and a missed one silently drops data rather than failing. They split into two
groups:

**The compiler catches these.** Seven switches end in a `const _exhaustive: never = …` binding,
so adding a union member breaks the build until they are handled. Just run `npm run typecheck`:

| File | Functions |
|------|-----------|
| `ssa.ts` | `renameExpr` / `renameStmt` (inside `renameVariables`) |
| `ssadestroy.ts` | `stripVersionsExpr` / `stripVersionsStmt` |
| `emit.ts` | `emitExpr` / `emitStmt` |
| `workers/disasm.worker.ts` | the RPC method dispatch (guards `WorkerMethod`, not IR) |

**You must find these by hand.** The typechecker stays silent on all of them.

*Switches ending in `default:`* — the new kind takes the fallback branch:

| File | Functions |
|------|-----------|
| `fold.ts` | `foldStmt`, `countReads`, `countReadsInStmt`, `substituteReg`, `substituteRegInStmt` |
| `ssaopt.ts` | `replaceRegInExpr`, `replaceRegInStmt` |
| `structs.ts` | `exprKey`, `rewriteExpr`, `rewriteStmt` |
| `promote.ts` | `renameVarsInExpr`, `renameVarsInStmt`, `promoteExpr`, `promoteStmt` |
| `cleanup.ts` | `cleanupStmt` |

*Switches with neither `default:` nor a `never` assert* — control simply falls off the end, so
the new kind is dropped with no trace at all. These are the dangerous ones:

| File | Functions |
|------|-----------|
| `ir.ts` | `walkExpr`, `walkStmts` |
| `ssaopt.ts` | `canonicalizeExpr`, the stmt walker in `deadCodeElimination`, the LICM expr walker |
| `structs.ts` | `walkExprs` and the stmt walker in `collectAccessPatterns` (both nested functions) |

*Not switches at all* — `foldExpr` (`fold.ts`), `hasSideEffects` (defined separately in both
`fold.ts` and `ssaopt.ts`) and `countExprUses` (nested in `ssaopt.ts`'s
`deadCodeElimination`) are if-chains on `expr.kind`. Grep the function name, not `case`.

`typeInfer.ts`'s `parseCastType` keys off type *strings*, not kinds — only relevant if the new
kind gets a cast spelling.

**Type system** (`typeInfer.ts`): `DecompType` lattice with 12 kinds (unknown, int, float, ptr, bool, void, struct, array, handle, ntstatus, hresult, enum). `meetTypes()` merges types — specific wins over unknown, handle/ntstatus/hresult win over int/ptr. `enum` carries a name and a `Map<number, string>` of members, synthesized from switches with 3+ cases.

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
npm run typecheck && npm run build
npm test
npm run lint
```

## Documentation

Documentation lives in `docs/`. **`docs/README.md` is the canonical index and holds the
"which doc do I update when I change X" mapping table** — consult it there rather than keeping
a second copy here or in `CONTRIBUTING.md`.

When making architectural changes, adding major features, or changing conventions, update this file (`CLAUDE.md`) so future AI agents have accurate context. This includes new source directories, new pipeline stages, new conventions, new gotchas, and changes to the build/test commands.

Update `README.md` only when changes affect the top-level project description (new major features, setup changes).

## CHANGELOG Convention

Maintain `CHANGELOG.md` under `## [Unreleased]` with `### Added`, `### Changed`, `### Fixed`, `### Removed`. Each entry: `- **Feature name** — concise description`

When editing CHANGELOG.md, append a timestamp to each new or modified entry in the format `(YYYY-MM-DD HH:MM)` using the current date and time. Example: `- **Feature name** — concise description (2026-03-06 15:30)`


<!-- BEGIN BEADS INTEGRATION v:1 profile:minimal hash:6cd5cc61 -->
## Beads Issue Tracker

This project uses **bd (beads)** for issue tracking. Run `bd prime` to see full workflow context and commands.

### Quick Reference

```bash
bd ready              # Find available work
bd show <id>          # View issue details
bd update <id> --claim  # Claim work
bd close <id>         # Complete work
```

### Rules

- Use `bd` for ALL task tracking — do NOT use TodoWrite, TaskCreate, or markdown TODO lists
- Run `bd prime` for detailed command reference and session close protocol
- Use `bd remember` for persistent knowledge — do NOT use MEMORY.md files

**Architecture in one line:** issues live in a local Dolt DB; sync uses `refs/dolt/data` on your git remote; `.beads/issues.jsonl` is a passive export. See https://github.com/gastownhall/beads/blob/main/docs/SYNC_CONCEPTS.md for details and anti-patterns.

## Agent Context Profiles

The managed Beads block is task-tracking guidance, not permission to override repository, user, or orchestrator instructions.

- **Conservative (default)**: Use `bd` for task tracking. Do not run git commits, git pushes, or Dolt remote sync unless explicitly asked. At handoff, report changed files, validation, and suggested next commands.
- **Minimal**: Keep tool instruction files as pointers to `bd prime`; use the same conservative git policy unless active instructions say otherwise.
- **Team-maintainer**: Only when the repository explicitly opts in, agents may close beads, run quality gates, commit, and push as part of session close. A current "do not commit" or "do not push" instruction still wins.

## Session Completion

This protocol applies when ending a Beads implementation workflow. It is subordinate to explicit user, repository, and orchestrator instructions.

1. **File issues for remaining work** - Create beads for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **Handle git/sync by active profile**:
   ```bash
   # Conservative/minimal/default: report status and proposed commands; wait for approval.
   git status

   # Team-maintainer opt-in only, unless current instructions forbid it:
   git pull --rebase
   git push
   git status
   ```
5. **Hand off** - Summarize changes, validation, issue status, and any blocked sync/commit/push step

**Critical rules:**
- Explicit user or orchestrator instructions override this Beads block.
- Do not commit or push without clear authority from the active profile or the current user request.
- If a required sync or push is blocked, stop and report the exact command and error.
<!-- END BEADS INTEGRATION -->
