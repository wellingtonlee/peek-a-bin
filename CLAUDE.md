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

- `pe/` — PE format parser (headers, imports, exports, resources, authenticode). `ordinalTables.ts` is generated data transcribed from pefile's `ordlookup` — do not hand-edit; imphash must agree with pefile or it matches nothing in any corpus. `sections.ts` holds `findCodeSection` / `isCodeSection` / `dataSectionRanges` — use them rather than rewriting the `.text`-or-executable predicate, which was hand-written at seven sites. `buildSectionIndex()` + `rvaToFileOffsetIndexed()` in `parser.ts` are the batch form of `rvaToFileOffset` for anything resolving many RVAs
- `disasm/` — disassembly engine, types, CFG, operand parsing, stack analysis, signatures. `funcInsns.ts` collects a function's instructions (cached binary search; do not re-roll the scan — it was duplicated in three files); `ripRelative.ts` owns all `[rip ± 0x..]` parsing (it was hand-rolled nine times)
- `disasm/decompile/` — IR lifting → SSA → folding → structuring → cleanup → type inference → promotion → struct synthesis → emission pipeline
- `components/` — React components (DisassemblyView, CFGView, HexView, Sidebar, etc.). The disassembly view is split across `DisassemblyView.tsx` (orchestration), `DisassemblyRows.tsx` (the virtualized `SeparatorRow`/`DataRow`/`LabelRow`/`InsnRow`), `DisassemblyToolbar.tsx` and `InsnContextMenu.tsx`, with the context-menu actions in `hooks/useInsnContextMenu.ts`
- `hooks/` — state management (usePEFile), derived state, disassembly rows, search. Also `decompileTabsState.ts`, the pure reducer behind `useDecompileTabs` (kept as its own leaf module so tests can import it without dragging in `disasmClient` → Capstone WASM)
- `ghidra/` — `client.ts`, the REST client for the optional Ghidra decompile server in `ghidra-server/`. Powers the decompile panel's **High Level** tab; used by `useDecompileTabs` and by SettingsModal's "Test Connection". Not a decompiler — see `disasm/decompile/` for that
- `workers/` — Web Worker for Capstone WASM + off-thread analysis. `disasm.worker.ts` owns the `self`/`indexedDB`/WASM setup; `dispatch.ts` holds the RPC method switch (extracted so it is importable under vitest — the worker module is not); `disasmClient.ts` is the caller-side RPC client
- `analysis/` — driver detection, anomalies, IOCTL decoding
- `llm/` — LLM integration (multi-profile settings, streaming client, prompts, types). `models.ts` is the single source of model IDs, provider defaults and per-task token budgets — never write a model ID anywhere else. `retry.ts` holds the backoff/limiter policy; `responseSchema.ts` the zod validation. `apiLists.ts` owns `DANGEROUS_APIS` / `NOTABLE_APIS` (notable is a superset by construction — the two drifted apart when maintained separately) and `matchesApi` for A/W suffix handling; `decompileForLLM.ts` is the one decompile-a-function-for-context routine, previously copied into three hooks
- `mcp/` — MCP server (tools, resources, session, Capstone wrapper) + `cli.ts` (setup command) + `clients.ts` (client config registry) + `paths.ts` (`parseAddr`, `resolveExportPath`)
- `utils/` — recent files (IndexedDB), export schema, entropy, fuzzy match

## Architecture

**State**: `useReducer` + React Context in `src/hooks/usePEFile.ts`. `AppState` (32 fields), `AppAction` discriminated union (53 action types). Access via `useAppState()` / `useAppDispatch()`.

`appReducer` is covered branch-by-branch in `src/hooks/__tests__/appReducer.test.ts`. Two invariants that suite pins and you should preserve: no-op branches return the **same object reference** (returning a new equal object causes pointless re-renders), and every mutating action **replaces** rather than mutates — the annotation undo/redo snapshots hold direct references to annotation objects, so a branch that mutates in place would corrupt history retroactively.

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

**New component types**: `DisplayRow` has exactly one declaration — the exported union in `useDisassemblyRows.ts`. JumpArrows and DisassemblyMinimap used to keep private narrowed copies that had to be hand-synced; they now `import type` the canonical one. Do not reintroduce a local copy: a narrowed structural clone still accepts the canonical rows at the call site, so it drifts silently instead of failing the build.

**Annotations**: Bookmarks, renames, comments auto-persist to localStorage per file. Undo/redo via snapshot stack.

**Tests**: `src/pe/__tests__/` for PE parsing (including `malformed.test.ts` for adversarial input, and `metadata.test.ts`, which pins the hand-rolled MD5 against the RFC 1321 vectors *and* differentially against Node's `crypto` — a wrong digest is invisible at runtime because nothing cross-checks a hash), `src/disasm/__tests__/` and `src/disasm/decompile/__tests__/` for the engine and decompiler, `src/hooks/__tests__/` for `appReducer` and the annotation undo/redo stack, `src/mcp/__tests__/` for the MCP server, `src/utils/__tests__/` and `src/workers/__tests__/` for utilities and RPC dispatch, `src/components/__tests__/` for the keyboard drift guard. Use `buildMinimalPE32()` / `buildMinimalPE64()` fixture builders from `src/pe/__tests__/fixtures.ts` (no binary files).

`src/disasm/decompile/__tests__/pipeline.test.ts` is the **end-to-end** one: instructions in, emitted C out. `decompileFunction` takes `Instruction[]` rather than bytes, so it needs neither Capstone nor a worker, and hand-writing the instruction stream makes the intended semantics explicit instead of trusting a disassembler to agree. Reach for it whenever a change could alter emitted output — a whole class of defect (see the condition-polarity gotcha) is invisible to stage-level tests because they assert on the IR the buggy code produced.

There is **no React renderer configured** — no jsdom, no `@testing-library/react`. Hooks cannot be mounted, so hook logic is tested by extracting the decision into an exported pure function (see `parseAnnotationMessage` in `useMcpSync.ts`). **Nothing renders a component**, so no test catches a UI regression: `DisassemblyView` and everything it was split into, the modals, and the a11y work are all verified only by typecheck, lint, build and reading. Adding a renderer means adding deps to `package.json` and merging the React plugins into `vitest.config.ts`. `@vitest/coverage-v8` is also not installed, so `npm run test:coverage` currently fails.

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
| `workers/dispatch.ts` | the RPC method dispatch (guards `WorkerMethod`, not IR) |

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

**Struct synthesis** (`structs.ts`): `StructRegistry` is cross-function state shared in the worker. `decomposeAddress()` breaks `base + idx*scale + offset` patterns, including a top-level `base - const` (folded to a negative offset; subtracting a *register* is not an offset and still returns null). 2+ distinct offsets on same base → struct candidate.

Scale ∈ {1,2,4,8} → `IRArrayAccess`, whether or not the function has a struct candidate. A function with no candidate but an indexed access takes a rewrite-only path; one with neither is returned by identity.

**Escaping struct defs are snapshots; registry-internal ones are live.** `synthesizeStructs` clones into `IRFunction.typedefs` (`cloneStructDef`), so an already-returned declaration cannot change when an unrelated function is decompiled later. Inside the registry the objects stay shared and the inference passes still mutate `field.type` in place — that **is** the cross-function type-refinement mechanism. So do **not** clone in `findOrCreate` or `get`: it disables refinement silently, with no test failing. Field *types* are always replaced wholesale rather than mutated, so a shallow field copy is sufficient.

**Merging is shape-based but guarded.** An exact `offset:size` fingerprint match merges unconditionally. The subset path additionally requires the smaller shape to have **3+ fields** (`MIN_SUBSET_MERGE_FIELDS`) and the merged layout to be free of overlapping extents (`hasBoundaryConflict`). Two distinct offsets is the *minimum* a candidate can have, so two-field shapes are simultaneously the most common and the weakest evidence — `{0:8, 8:8}` describes a large fraction of all structs. The cost is real and deliberate: a two-field partial view of a struct no longer completes from another function's larger view. Failing to merge is the benign direction — two `struct_N` declarations instead of one wrongly shared.

**Provenance beats shape, and recovers that cost.** Two bases occupying the same parameter slot are the same object by construction, so `findOrCreateLinked` merges on that evidence and deliberately ignores `MIN_SUBSET_MERGE_FIELDS` — a two-field view of a parameter *does* complete from a caller's fuller view. It still cannot override `hasBoundaryConflict`: contradictory layouts mean one reading is wrong. Two maps are kept apart on purpose — `paramLinks` (what a *caller* passed in) and `paramViews` (the *callee's* own reading) — so a merge always has the callee's corroboration and a passthrough `void*` helper never links its unrelated callers. Identity is published in both directions, so caller-then-callee and callee-then-caller agree.

Both merge directions scan `fingerprintIndex` in insertion order and take the first match, so *which* struct absorbs which is still order-dependent.

**emit.ts module-level `_typeCtx`**: Set before emission, cleared after. Enables cast suppression and type-aware idioms (INVALID_HANDLE_VALUE, NT_SUCCESS, SUCCEEDED/FAILED).

## Gotchas

- **`extractCondition` returns the condition under which the jump is TAKEN.** Every entry in `regstate.ts`'s `condMap` is taken-polarity (`jg`→`>`, `jbe`→`u<=`, `js`→`< 0`), and `identifyBranches` returns the block the jcc jumps to. So the branch target is the `then` body under the *un-negated* condition, and `RegState.negate` is for the fallthrough — its own docstring says "for structuring: if-not-taken path". Getting this backwards inverted **every `if` and `while` the decompiler ever emitted** while leaving the bodies in place: valid C stating the opposite of the machine code, invisible to every stage-level test. `__tests__/pipeline.test.ts` guards it end to end now.
- **`arg_N` in a stack frame means argument *position*, and only when the frame was verified.** `stack.ts` numbers a slot `arg_<index>` from its offset, but only after confirming a real `push rbp` / `mov rbp, rsp` prologue; otherwise the name is offset-based (`arg_0x10`). That distinction is load-bearing — under frame-pointer omission RBP is usually a callee-saved object pointer, so `[rbp+0x10]` is often a struct field access, and `structs.ts` keys struct provenance off `^arg_(\d+)$` precisely to exclude those. The name is the only channel between the two files (`IRParam` carries name and type and nothing else), so do not loosen it. On x64 the first slot is RCX's ABI home slot, which puts the fifth argument at `[rbp+0x30]`, past the shadow space.
- **`regSize()` is not a membership test.** It falls back to `4` for any unrecognised name, so `regSize(x) > 0` is true for every string. Use `isKnownRegister()` (`decompile/ir.ts`). This exact mistake made `lifter.ts`'s `isRegister()` a no-op that lifted immediates as registers.
- **The CSP is generated, not hand-written.** Edit `build/csp.ts`, never `nginx.conf`'s header or `index.html` directly — `build/csp.test.ts` fails on drift. A meta CSP cannot be committed into `index.html` because it is also the dev entry point and Vite injects an inline React Refresh preamble there. Note the shipped `connect-src` omits non-localhost plain `http:`, so a LAN Ghidra server is blocked on the HTTP nginx deployment.
- **Do not re-add a plugin that copies `capstone.wasm`.** Rollup already rewrites `new URL("capstone.wasm", import.meta.url)` to its hashed asset; a manual copy is pure duplication and was 1.7 MiB of the PWA precache. `capstone-wasm-guard` in `vite.config.ts` fails the build if more than one WASM asset is emitted.
- **`tools.ts` and `resources.ts` must only *type*-import `./session`.** A value import pulls in `./disasm`, which loads Capstone WASM at module scope, and both MCP suites become slow and fragile. `src/mcp/__tests__/importGraph.test.ts` enforces this.
- **`biome.json` must be strict JSON.** A single `//` comment silently voids the whole config and Biome falls back to defaults — which looks like your rule settings randomly stopped applying. The a11y group is now mostly at `error` (301 findings were cleared); keep it there.
- **A multi-line `biome-ignore` needs `//` on every line.** Biome only honours the directive on the line immediately preceding the offence, so put prose in a normal comment block above a single-line directive. Getting this wrong leaves bare text inside JSX and breaks the parse.
- **DisassemblyView.tsx** is ~1600 lines even after the split. Read in chunks. Two seams are still unextracted and both are traps: `handleKeyDown` is ~250 lines with a 19-entry dependency array (that array *is* the behaviour — copy it verbatim if you move it), and the graph-search state machine. `CFGView` is still passed 33 props from here.
- **A callback declared later in a component cannot go in an earlier hook's dependency array** — it is a `const`, so the array hits its temporal dead zone at hook-call time. This is not hypothetical: `handleKeyDown` closed over `handleDecompileToggle` (declared ~340 lines later) without it in the deps, so **D opened the decompile panel but could not close it** — the memoized handler kept a closure where `showDecompile` was still `false`. The fix is a ref assigned *during render*; an effect is too late, because a keypress can be handled before effects flush.
- **`parseBranchTarget` lives only in `components/shared.tsx`** and resolves `call` immediates as well as jumps. JumpArrows draws jump arrows only, so it guards with `mnemonic.startsWith("j")` *before* calling — dropping that guard makes recursive/intra-function calls sprout arrows. Covered by `src/components/__tests__/parseBranchTarget.test.ts`.
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
