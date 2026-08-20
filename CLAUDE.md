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
npm run check          # biome check — GREEN as of 2026-08-12, and now a CI gate; see below
npm run test:coverage  # vitest run --coverage — RED, @vitest/coverage-v8 is not installed
```

**`npm run check` passes as of 2026-08-12, and CI now gates on it instead of `lint`.** It had
been red for the project's entire history, so treat any older note saying otherwise as stale.
`biome check` is a superset of `biome lint src`: same rules, plus the formatter and
`assist/source/organizeImports`, over the whole repo rather than just `src/`. It reported **164
errors across 9 files**; `f8bc466` sorted imports repo-wide and cleared all but one, and the
survivor was `vite.config.ts` — that commit only walked `src/`, and `check` also covers the root
config files. `.git-blame-ignore-revs` carries `f8bc466` so the sort does not pollute blame.

Current state: **0 errors, 71 warnings, 3 infos over 238 files, exit 0.** Warnings and infos do
not fail it. Two of the infos are `useNodejsImportProtocol` on `vite.config.ts`'s `"path"`/`"fs"`
imports — Biome classes those fixes as *unsafe* so `--write` skips them; they are deliberately
left. The third is a `biome.json` deprecation notice (`linter.rules.recommended` → `preset`),
fixable with `biome migrate` whenever someone wants it.

Because `check` is now the gate, an unsorted import or an unformatted file fails CI where it
previously did not. `npm run lint` is still there and is strictly implied by `check`; use it when
you want the faster, `src/`-only signal.

**Reading a Biome result is itself a trap, and it will tell you a red tree is green.** Biome's
default `--max-diagnostics` truncates the output *before* the `Found N errors.` summary line, so
`npm run check | tail` routinely ends on `Found 71 warnings.` with the error count scrolled away.
Piping makes it worse: `npm run check 2>&1 | tail; echo $?` reports **`tail`'s** status, not
npm's, so it prints 0 for a failing run. Do not check the gate that way. Either

```sh
npm run check > /tmp/check.txt 2>&1; echo "exit=$?"     # no pipe, so $? is Biome's
npx biome check --diagnostic-level=error --max-diagnostics=300   # errors only, untruncated
```

Warnings and infos never fail the run — only error-severity findings do, so the second form is
the one that answers "will CI pass".

**Biome** (`biome.json`) is the linter/formatter. All seven configured `a11y` rules,
`correctness/useHookAtTopLevel` and `correctness/useExhaustiveDependencies` are at **`error`** —
the 301-finding a11y backlog was cleared and the severities were ratcheted so it cannot come
back. `npx biome lint src` is currently **71 warnings, 0 error-severity, 0 a11y**, and the 71
are only `noArrayIndexKey` (41), `noExplicitAny` (27) and `noAssignInExpressions` (3).

`useExhaustiveDependencies` was the last ratchet and it is the one worth understanding: it sat
at `warn`, and `npm run lint` is `biome lint src`, which exits 0 on warnings — so a missing React
dependency, the entire stale-closure class, **could not fail CI**, and there is no renderer here
to catch one at runtime either. It became urgent when `useDisassemblySearch`'s return was
memoised: that turned `handleKeyDown`'s 37 dependency entries from inert decoration into
load-bearing state. Measured 0 findings before and after the ratchet and the warning total
unchanged at 71, which is the tell that `biome.json` is still being honoured at all;
`build/lintConfig.test.ts` now guards both that severity and the strict-JSON landmine below.
CI runs `lint`, `typecheck`, `test` and `build` on every PR, plus a separate
`npm audit --audit-level=high` job.

## Source Layout (`src/`)

- `pe/` — PE format parser (headers, imports, exports, resources, authenticode). `ordinalTables.ts` is generated data transcribed from pefile's `ordlookup` — do not hand-edit; imphash must agree with pefile or it matches nothing in any corpus. `sections.ts` holds `findCodeSection` / `isCodeSection` / `dataSectionRanges` — use them rather than rewriting the `.text`-or-executable predicate, which was hand-written at seven sites. `buildSectionIndex()` + `rvaToFileOffsetIndexed()` in `parser.ts` are the batch form of `rvaToFileOffset` for anything resolving many RVAs
- `disasm/` — disassembly engine, types, CFG, operand parsing, stack analysis, signatures. `capstoneWindow.ts` owns **every** call into the Capstone WASM decoder — see the gotcha; nothing else may call `cs.disasm`. `arch.ts` maps `coffHeader.machine` to an `ImageArch` and holds `unsupportedOnArch()` / `unsupportedArchMessage()` — see **Architectures, and refusing one** below; do not select a decoder with `is64`, which is the PE32+ magic and true for ARM64 too. `funcInsns.ts` collects a function's instructions (cached binary search; do not re-roll the scan — it was duplicated in three files); `ripRelative.ts` owns all `[rip ± 0x..]` parsing (it was hand-rolled nine times); `seeds.ts` turns detected jump tables into recursive-descent seeds; `dataWindows.ts` builds (and packs, for the worker hop) the `.rdata`-style spans function detection needs to read an x64 jump table
- `disasm/arm64*.ts` — ARM64 support: `arm64.ts` (fixed-width linear sweep at 4-byte alignment plus evidence-only function starts), `arm64Operands.ts` (**the single A64 branch/address grammar** — the `ripRelative.ts` precedent, do not hand-roll a second one), `arm64Xref.ts` (`buildArm64Xrefs`). Everything x86-shaped — the decompiler, x86 xref building, IRP dispatch detection, stack frames, signatures — declines on ARM64 rather than guessing
- `disasm/decompile/` — IR lifting → SSA → folding → structuring → cleanup → type inference → promotion → struct synthesis → emission pipeline
- `components/` — React components (DisassemblyView, CFGView, HexView, Sidebar, etc.). The disassembly view is split across `DisassemblyView.tsx` (orchestration), `DisassemblyRows.tsx` (the virtualized `SeparatorRow`/`DataRow`/`LabelRow`/`InsnRow`), `DisassemblyToolbar.tsx` and `InsnContextMenu.tsx`, with the context-menu actions in `hooks/useInsnContextMenu.ts`. All six dialogs go through one `Modal.tsx` (overlay, centring, dialog semantics, focus trap, body scroll lock, and dismissal as a per-dialog *option* — Settings and in-progress work are deliberately non-dismissible); its class composition, focus arithmetic and `accidentalDismissAllowed` rule live in `modalScaffold.ts` as pure functions, which is the only way any of it is tested. Outside-click dismissal is `hooks/useDismissOnOutsideClick.ts`
- `hooks/` — state management (usePEFile), derived state, disassembly rows, search. `useDisassemblyKeyboard.ts` and `useGraphSearch.ts` are the two seams extracted out of `DisassemblyView`; `useFileMetrics.ts` drives the metrics worker and `asyncMetricState.ts` is its pure reducer plus the sync/async size thresholds. Also `decompileTabsState.ts`, the pure reducer behind `useDecompileTabs` (kept as its own leaf module so tests can import it without dragging in `disasmClient` → Capstone WASM). The pure-leaf-module pattern is deliberate and is the *only* way hook logic gets tested here — nothing renders a component
- `ghidra/` — `client.ts`, the REST client for the optional Ghidra decompile server in `ghidra-server/`. Powers the decompile panel's **High Level** tab; used by `useDecompileTabs` and by SettingsModal's "Test Connection". Not a decompiler — see `disasm/decompile/` for that
- `workers/` — **two** workers. The disasm worker (`disasm.worker.ts` owns the `self`/`indexedDB`/WASM setup; `dispatch.ts` holds the RPC method switch, extracted so it is importable under vitest — the worker module is not; `disasmClient.ts` is the caller-side RPC client) and a second, stateless `metrics.worker.ts` / `metricsDispatch.ts` / `metricsClient.ts` for checksum and entropy. The split is not tidiness: the disasm worker services messages **serially**, so a checksum posted to it queues behind a whole-image disassembly that can run for minutes. `transfer.ts` holds `prepareBinaryArgs`, which every RPC's args go through
- `analysis/` — driver detection, anomalies, IOCTL decoding. `isPlausibleIOCTL` is a *shape* test that a large share of ordinary 32-bit values pass, so decoding also requires the **call site**: `ioctlCodeArgIndex` in `driver.ts` says which argument of which API carries a control code. Without that gate the emitter put 1475 confident, wrong `/* IOCTL: … */` comments into three user-mode binaries
- `llm/` — LLM integration (multi-profile settings, streaming client, prompts, types). `models.ts` is the single source of model IDs, provider defaults and per-task token budgets — never write a model ID anywhere else. `retry.ts` holds the backoff/limiter policy; `responseSchema.ts` the zod validation. `apiLists.ts` owns `DANGEROUS_APIS` / `NOTABLE_APIS` (notable is a superset by construction — the two drifted apart when maintained separately) and `matchesApi` for A/W suffix handling; `decompileForLLM.ts` is the one decompile-a-function-for-context routine, previously copied into three hooks
- `mcp/` — MCP server (tools, resources, session, Capstone wrapper) + `cli.ts` (setup command) + `clients.ts` (client config registry) + `paths.ts` (`parseAddr`, `resolveExportPath`)
- `utils/` — recent files (IndexedDB), export schema, entropy, fuzzy match

## Architecture

**State**: `useReducer` + React Context in `src/hooks/usePEFile.ts`. `AppState` (46 fields), `AppAction` discriminated union (54 action types). Access via `useAppState()` / `useAppDispatch()`.

`usePEFile.ts` also exports **`VIEW_TABS`**, the nine view tabs in display order, and it is the
single declaration of that ordering — `AddressBar`'s tab bar and its 1-9 `TAB_KEYS` shortcut map
are both derived from it, with labels from `VIEW_TAB_LABELS` in `components/analysisNotice.ts`.
Do not re-spell either the order or the names: they were previously written out three times, so a
tab could be called one thing on its button and another in the notice telling you to open it.
`VIEW_TAB_LABELS` is `Record<ViewTab, string>` and fails the build on a missing tab, where an
array would silently drop it from the bar.

`appReducer` is covered branch-by-branch in `src/hooks/__tests__/appReducer.test.ts`. Two invariants that suite pins and you should preserve: no-op branches return the **same object reference** (returning a new equal object causes pointless re-renders), and every mutating action **replaces** rather than mutates — the annotation undo/redo snapshots hold direct references to annotation objects, so a branch that mutates in place would corrupt history retroactively.

`AnalysisPhase` includes a `"failed"` value — the analysis chain rejects into it, and the status
bar surfaces it. Without it a failed parse left the UI spinning forever. `usePEFile.ts` also
exports `parseViewTab()`, which narrows the `#tab=` URL parameter; do not cast that string to
`ViewTab` directly.

**`AnalysisPhase` has a *second* terminal value, `"no-code"`, and it is not a failure.** A PE
with no executable section — a resource-only DLL, i.e. an ordinary satellite/MUI file — makes
`findCodeSection` return undefined, and App's analysis effect returns at that point, *above*
the first `SET_ANALYSIS_PHASE` it dispatches. So the phase stayed on `"extracting-strings"`
forever and the UI spun with nothing said. Do not relabel this `"failed"`: the parse succeeded,
nothing went wrong, and every parser-derived tab is populated. **Whether a phase means "still
working" is `ANALYSIS_IN_PROGRESS`**, a `Record<AnalysisPhase, boolean>` in `usePEFile.ts` that
`StatusBar` and `Sidebar` both read. It replaced a hand-written
`phase !== "idle" && !== "ready" && !== "failed"` chain written out at three sites — that shape
defaults any phase added later to "still analysing", which is a spinner that can never resolve,
so a new phase must fail the build here instead (peek-a-bin-bo3b).

**`analysisNotice()` (`components/analysisNotice.ts`) has four kinds, and they are ranked**:
`"unsupported-arch"`, then `"no-code-section"`, then `"analysis-failed"`, then
`"partial-detection"`. `"no-code-section"` is the `"no-code"` phase's notice and sits below the
architecture deliberately — an ARM32 resource-only DLL should report the machine type, which
withholds the disassembly for every such file, where "no executable section" is a property this
one file would still have on a supported architecture. Its detail lists the populated tabs from
`PARSER_DERIVED_TABS` rather than spelling them, so the prose cannot disagree with the buttons
rendered from `availableTabs`. The last is fed by
`AppState.omittedPasses` (`SET_OMITTED_PASSES`, from `DetectResult.omitted`) and exists for the
*supported*-architecture case where Capstone is dead: detection keeps answering from `.pdata`,
the exports, the entry point and the unwind handlers, so the list is short rather than empty and
the status bar's green "Ready" over it said nothing was wrong. An unsupported architecture
already implies every decoder-fed pass, so partial-detection is deliberately **not** reported on
top of it; on a failure its sentence is *appended* rather than substituted, because which stage
threw and how much of the list survived are different facts. `DETECT_PASS_LABELS` is
`Record<DetectPass, string>`, so wire values like `call-targets` cannot reach the screen and a
fifth pass fails the build.

**Worker**: RPC-style communication in `src/workers/disasmClient.ts`. Heavy work (disassembly, function detection, xref building, decompilation) runs off-thread. Client caches results (disasm, xref, decompile caches). Whole-file checksum and entropy go to the separate metrics worker via `metricsClient.ts`; inputs under the thresholds in `asyncMetricState.ts` (256 KiB for the entropy strip, 1 MiB for file metrics) stay synchronous and spawn no worker, so ordinary binaries never show a loading state.

**Pipeline**: File drop → `parsePE()` → detect functions (worker) → hybrid disassemble (recursive + gap-fill, seeded with jump-table case targets from `seeds.ts`) → build xrefs → extract strings. All async, phased via `analysisPhase` state. The decoder is chosen from `coffHeader.machine` (`disasm/arch.ts`): x86/x64 take recursive descent + gap fill, ARM64 takes the fixed-width sweep in `arm64.ts`.

**Architectures, and refusing one.** `archForMachine()` returns `ImageArch = TargetArch | "unsupported"`. `"arm64"` for 0xAA64; `"x86"` for I386/AMD64 **and for `undefined`**, which means "the caller never told us" and keeps every un-threaded call site at exactly its pre-ARM64 behaviour; `"unsupported"` for everything else — ARM32/Thumb, IA-64, RISC-V, MIPS. `ImageArch` is a *widening* of `TargetArch` rather than a replacement, so a stage that has only ever run after a supported architecture was confirmed keeps the narrow type and fails to compile rather than falling through.

The refusal is deliberately **asymmetric, and it is a judgement, not an oversight**: do not collapse it into one behaviour.

- **Throw** from the stages whose entire output is instructions — `disassemble`, `hybridDisassemble`, `buildAllXrefs`, `decompileFunction` (`workers/dispatch.ts`, `mcp/disasm.ts`). An empty instruction list is indistinguishable from a correct answer.
- **Return empty, with `DetectResult.omitted` populated**, from function detection. The point is that an ARM32 file still yields the headers, sections, imports, exports, resources and strings the PE parser gets right — those are format-level facts, and a user should get every one of them. `mcp/session.ts` guards its two throwing calls behind a `decodable` flag for exactly this reason: an unguarded throw in `loadFile` discarded all of it.

**`DetectResult.omitted: DetectPass[]`** names the decoder-fed passes that did not run — `"call-targets" | "jump-tables" | "thunk-names" | "tail-calls"` — and is **empty when the answer is whole**. It covers both the unsupported-architecture case and a null Capstone handle, where detection deliberately keeps answering from `.pdata`, exports, the entry point and unwind handlers. It exists because a narrower answer used to be the same shape as a complete one. Only passes the architecture actually has are ever listed: the ARM64 detector has no thunk or tail-call pass, so their absence is a design decision rather than a degradation.

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

**Tests**: `src/pe/__tests__/` for PE parsing (including `malformed.test.ts` for adversarial input, and `metadata.test.ts`, which pins the hand-rolled MD5 against the RFC 1321 vectors *and* differentially against Node's `crypto` — a wrong digest is invisible at runtime because nothing cross-checks a hash), `src/disasm/__tests__/` and `src/disasm/decompile/__tests__/` for the engine and decompiler, `src/hooks/__tests__/` for `appReducer` and the annotation undo/redo stack, `src/mcp/__tests__/` for the MCP server, `src/utils/__tests__/` and `src/workers/__tests__/` for utilities, RPC dispatch, `prepareBinaryArgs` and the metrics worker, `src/llm/__tests__/` for retry/schema/API lists, and `src/components/__tests__/` for the pure extracts and the drift guards. Use `buildMinimalPE32()` / `buildMinimalPE64()` fixture builders from `src/pe/__tests__/fixtures.ts` (no binary files).

Several suites are **drift guards that scrape source text** rather than call it — the `.disasm(` scan in `capstoneWindow.test.ts`, the import-graph check in `mcp/__tests__/importGraph.test.ts`, the `dispatch.ts` purity check, and `keyboardShortcuts.test.ts` against `docs/keyboard.md`. They are cheap and they catch a whole class of silent regression, but they encode formatting by accident; write the pattern so a reformat cannot break it. Two more read structure rather than text and are correspondingly sturdier: `hooks/__tests__/disasmHandlerDeps.test.ts` walks the TypeScript AST and fails if `useDisassemblySearch` stops returning a `useMemo`, or if `handleKeyDown` grows a read without a dependency entry or an entry without a read; `build/lintConfig.test.ts` parses `biome.json` and fails if it stops being strict JSON or if `useExhaustiveDependencies` drops below `error`.

`src/disasm/decompile/__tests__/pipeline.test.ts` is the **end-to-end** one: instructions in, emitted C out. `decompileFunction` takes `Instruction[]` rather than bytes, so it needs neither Capstone nor a worker, and hand-writing the instruction stream makes the intended semantics explicit instead of trusting a disassembler to agree. Reach for it whenever a change could alter emitted output — a whole class of defect (see the condition-polarity gotcha) is invisible to stage-level tests because they assert on the IR the buggy code produced.

Don't hard-code a test count in docs — it goes stale within a session. Run `npm test` for the current number.

**MCP setup CLI**: `npx tsx src/mcp/index.ts setup <client>` configures AI clients (claude-code, opencode, continue). Registry in `src/mcp/clients.ts` — add new clients by inserting a map entry. `.mcp.json` at project root enables Claude Code auto-discovery.

## Verification status — what is measured and what is not

Every suite in `src/` is synthetic. Real binaries were first driven through the tool on
2026-08-11: real MSVC output covering PE32, PE32+ and ARM64 (pip `distlib`'s `t64.exe` /
`t32.exe` / `w64.exe` plus the two ARM64 launchers), headlessly, no browser. Keep this section
honest — the distinction between *measured* and *reasoned* is the point of it.

- **A register is never named for a value it no longer holds — and the blind spot that used to qualify that sentence is closed.** Every surviving read of a register's SSA *entry* value is checked against the writes that dominate it: **0 wrong names and 0 spoiled entry-value copies on all four binaries**, over **33/182/181/34 sites** (t32/t64/w64/w32) at `82ed61e`, from 28/78/28/78 and 13/19/13/18 at `cee6f91`. A gate, not a baseline — see `corpus/README.md` on why this one gates when the statement-drop and unrecovered-value counts do not. **What is gated is every surviving *version-0* read whose register a dominating write has changed *under the name the read uses*.** Both halves of that were wrong until `peek-a-bin-fppy` and `peek-a-bin-pzws` were fixed together, and the pair is worth understanding because each hid the other:
  - **The site filter could not see a definition phi lowering had relocated.** It attributed a phi's definition to the phi's own block, while `destroySSA` materialises the copy in each *predecessor* — and a predecessor routinely dominates blocks the phi block does not. Where the only dominating writer was a relocated phi copy the site was discarded before it was ever judged, so the gate printed **0 over 12 provably wrong reads**. Noting the phi at each operand's block as well takes the site count 28/159/158/28 → 33/182/181/34 and the gate red at 12 (six in `t64!sub_1400045DC`, six in `w64!sub_14000496C`, all `r9`, 0x140004883-0x140004898).
  - **Those 12 were one defect: `registerSpeller` gave one name to two live ranges of different widths.** Fixed by per-live-range naming — see the `ssadestroy.ts` gotcha below. It is **not** the "no value-level audit can see this" class it was once filed as: this half *is* value-level and the gate does see it now.
  - **The `writes` test compares the *name*, not the canonical register**, because what the audit judges is emitted C and C's unit of identity is the identifier. A register correctly split into `r9` and `r9d` reads as a clobber that never happens against a canonical test, which would leave the gate permanently red on correct output. Checked rather than argued: with the naming fix reverted and the name test in place the same 12 rows come back, and with the naming fix in place a canonical test still reports 12 — so neither change alone is sufficient and the name test provably hides nothing.

  A *name* collision the gate still cannot see is the crude positional one: an identifier read but never assigned while a sibling alias of the same register is assigned. That scan reads 187/179 names on t64/w64 at `82ed61e`, **up** from 164/156 — and the rise is the fix, not a regression. Every one of the 29 names it newly flags on t64 is a 64-bit *entry* value that the machine spills or reads unchanged and that the emitted C therefore correctly never assigns; before the fix a 32-bit live range's phi copy was writing that name and masking it. Treat the scan as an upper bound and never as a defect count.
- **`gcc -fsyntax-only` is structurally blind to a wrong register *name*.** `corpus/emitAudits.ts`'s `preludeFor` declares every undeclared identifier as its own `long`, so `r13` and `r13d` compile cleanly as two unrelated variables. The 842/842 ratio **cannot move** on that defect class, and it stayed green across six functions that each assigned `rNN` and then read `rNNd`, a name nothing in them ever assigned. Do not read "all of them compile" as evidence about naming. It is blind to **call arity** for the same kind of reason — an implicit declaration is accepted at any arity — which is what `corpus/arity.ts` is for.

**The harnesses live in `corpus/`. Run them with `npm run corpus`** — see `corpus/README.md`,
which says what each audit proves and what a failure means. They are deliberately outside
`npm test`: they need real MSVC binaries that are not in the repo and a C compiler, and they skip
cleanly (naming what is missing) when either is absent. `npm run corpus:compare -- <base> <change>`
diffs two runs guard-by-guard and is how a commit gets judged. Nothing here is re-checked unless
someone re-runs it. (They lived only in `/tmp` scratchpads until `peek-a-bin-dfae`, and were
rebuilt from scratch twice in one day as a result — do not move them back.)

**There is no default corpus directory, deliberately.** `preflight.ts` searches
`PEEK_CORPUS_DIR` (environment), `PEEK_CORPUS_DIR` in a gitignored `.env` at the repo root, then
`$XDG_DATA_HOME/peek-a-bin-corpus`, `~/.peek-a-bin-corpus` and `<repo>/corpus/binaries` — every
candidate derived from `$XDG_DATA_HOME`, `$HOME` or the repo. An explicit setting is the *whole*
search, so a wrong override is reported about the directory you named rather than quietly
satisfied from elsewhere. On this machine the binaries are in
`~/.local/share/peek-a-bin-corpus`, which the third candidate finds with nothing set.
**Do not reintroduce an absolute default**: the old one pointed into a virtualenv that no longer
exists, and because a missing corpus *skips* rather than fails, the default path silently became
the skip path — the verification existed and was not being run (`peek-a-bin-alx1`).
`build/corpusPreflight.test.ts` fails the ordinary suite if a candidate stops being
`$HOME`/`$XDG_DATA_HOME`/repo-derived.

**Measured against real binaries.** Each of these has an oracle outside the code under test:

- **The PE parser holds**, differentially against an **independently written from-spec reader** — sections, imports, exports, imphash, resources, checksum and `.pdata` agree on every file, including 419/419 and 381/381 ARM64 `.pdata` entries on begin/end/unwind/handler. pefile is **not** installed here, so the reference is hand-written, not pefile.
- **Condition polarity is audited per guard against the originating jcc**, not spot-checked: **0 inverted at every re-run** (1276 guards when first audited, 1505 at `57f8406`), and every subsequent structuring change re-ran the audit. It now covers all four emitted shapes — `if`, `while`, `for` and `do/while` — and resolves candidates through `jmp`-only blocks, since anchoring to the wrong jcc one edge away produced a false inverted on an ordinary MSVC loop entry (`peek-a-bin-8r0`, `peek-a-bin-lbz`).
- **A loop being told about every way the machine can leave it** is a separate audit from polarity, and it found what polarity cannot. It is now **0 short of the machine on all four binaries** (448 innermost loops audited, 122/111/105/110 — measured at `cee6f91`), and the defect it was built to catch is **retired**: do not go looking for it. History, because the numbers are still quoted — it first reported 319 loops audited with exactly **one** short, a `do { … } while (1)`, an unconditional call inside a loop the reader is told never ends. Never the structurer: the missing tests jumped past the end of the *detected* function, and `buildCFG` draws no edge to a target outside the range it was given, so the block read as unconditional. Function sizing fixed it, in `functionDetect.ts` as predicted — the corpus-wide count of conditional jumps in that position went **37 → 9** when `interiorBranchedOverStarts` withdrew the MSVC `__finally` funclet starts (`peek-a-bin-g7yp`), then **9 → 0** when jump-table spans stopped the gap fill decoding case addresses as instructions (`peek-a-bin-y1di`, `peek-a-bin-mk42`). **Anyone quoting 37 is quoting a fixed defect.** The "control leaves for 0x…" comment arm in `structure.ts` remains as a backstop for an arm that has no label to `goto` and no function to call, and now fires on nothing in this corpus (`peek-a-bin-lbz`).
- **The emitted C is checked by a compiler.** `gcc -std=gnu89 -fsyntax-only` over every emitted function of the three x86 binaries: **all of them compile clean** — 842 of 842 at `57f8406`, and t32 currently detects **288** functions. *Both numbers are date-stamps; "all of them" is the claim.* The history matters only because two of its figures are still quoted at people: the denominator was once 1001, because the detector reported every hot-patched function twice (MSVC's `8b ff 55 8b ec` prologue table has entries that are prefixes of one another), and t32 was once 447, then 293. **Anyone pinning 447, 293 or 1001 is pinning a defect or a stale count.** 447 → 293 was the double-detection fix, with 154 empty decompiled bodies → 0 (`peek-a-bin-dot`, `peek-a-bin-abv`); 293 → 288 was `95229d3` folding five MSVC `__finally` funclet bodies into the parents they are interior to, with the instruction stream byte-identical either way (`peek-a-bin-gtlf`).
- **Struct layouts are verified by a compiled and *run* `offsetof` program**, not by reading the declaration: every definition and field lays out at the offsets its field names record — **975/975 fields across 169 definitions** at `57f8406`, from 18/149 and 318/852 (`peek-a-bin-ey0`).

**These denominators move, so treat the ratio as the claim and the absolute as a date-stamp.**
Every count above is "all of them", and the totals shift whenever function detection changes —
which it does often, and usually because a defect was fixed. Between the run that produced
847/847 and 1007/1007-across-197 and the one at `57f8406` they became 842/842 and
975/975-across-169, with polarity 1276 → 1505 checked, purely from detection moving underneath.
None of that is a regression. **A number here going stale is normal; a ratio falling below 1 is
not.** When you re-measure, pin *both* sides of a comparison to one commit — a base sweep taken
against a moving HEAD silently compares your change against someone else's.

**The same rule applies to counts recorded in a bead, and it is not being followed.** A bead
that says "22 for-loops per x64 binary" or "4 functions self-assign" without naming the commit
it was measured at becomes a trap the moment detection moves: an agent re-measures, gets a
different number, and spends its budget deciding whether it broke something. Audited
2026-08-20 over every open bead — the staleness rate is low (1 of 38 described a fixed defect),
but **three** carried counts HEAD contradicts by 2–4× in both directions, and one of those
(`peek-a-bin-9q2`, for-loop recognition) had fallen a further 4× with nothing recording it,
because no audit models loop *shape*. **Stamp every count in a bead with the commit it was
taken at**, exactly as this section does.
- **Function boundaries** are cross-checked against `.pdata` (t64 511 → 279 functions, 232 overlapping pairs → 0) and, on ARM64, against the sweep's own alignment invariants.
- **A call's callee reaching the emitted C is a standing guard**, not a spot check: the callees the disassembly names are compared against the identifiers the emitted C applies. Distinct callees lost is 0 on all three binaries, and stayed 0 through the register-width and call-result work.
- **Statements `structureCFG` loses are counted by object identity**, not inferred from line map coverage: **0 dropped of 6996/7475/6637/6494 lifted statements** (t32/t64/w64/w32, current tree; it was 7002/7331/6519/6500 at `cee6f91` — the denominator moves with every lifter change, the zero is the claim). Folding and relocation — two of the three things lost coverage can mean — cannot register in it, so what it counts is only the case that is a defect. Observable because `decompileFunction` takes an optional last argument, `tap`, whose only caller is `corpus/sweep.ts`; with the audit running the emitted C is byte-identical on all four binaries. **Reported, never gated** — the short-circuit fold legitimately consumes blocks, and today's zero is not evidence that zero is an invariant; a rise between two pinned runs is a regression in `compare.mjs`. Validated by negative control: disabling `structureCFG`'s leftover pass makes it report 1380/7002 on t32 (`peek-a-bin-hu7`).
- **Guards the decompiler gave up on are counted, and the count is now visible at all**: **108/85/67/85 unrecovered values** (t32/t64/w64/w32, current tree) across 39/35/33/37 functions — 216/170/134/170 occurrences of the `__unrecovered_N` token, exactly 2× the values because `emit.ts` declares each once and uses it once. 89/85/67/67 are branch conditions, of which only 32/37/31/25 can be given a jcc address: the emitted `if (…)` line carries no line-map entry, so polarity anchoring is the only route and ~64% is a structural ceiling. **Reported, never gated in the run** — the count is not zero and no threshold on it is established; a *rise* is a regression in `compare.mjs`. This existed because `sweep.ts` skipped any guard with no top-level operator, so an unrecovered guard was not a failing row, it was **not a row at all**, and polarity's `ok/checked` ratio stayed 1.00 as guards fell out of the denominator. Validated by executing the hypothetical rather than arguing it: with `conditionFromFlagResult` disabled, t32 goes 108 → 300 values, and `compare.mjs` *as of `cee6f91`* reports “no regression”, exit 0, over the same two artifact directories — 192 correctly-recovered guards lost, called clean (`peek-a-bin-rl01`).
- **Emitted call arity is checked against `apitypes.ts`'s declared signatures**, which is the only oracle in the repo that can see arity at all: `corpus/arity.ts`, **74/105, 88/127, 92/133 and 77/111 calls at the declared arity** (t32/t64/w64/w32, measured against base `78b6040` with `peek-a-bin-f51x` applied), with **under 27/36/38/28** — of which 0/26/26/0 sit at the ABI evidence's ceiling, where `collectArgs64`'s four fastcall registers cannot reach a five-parameter API — and **over 4/3/3/6**. Over-count is the direction that means an argument was *invented*, and every one of the 16 remaining rows is provably wrong (`GetLastError(rcx)`, `GetModuleHandleW("KERNEL32.DLL", edi)`), so **read it as `polarity inverted`'s character, not a baseline's** — it is nevertheless **reported, never gated**, because the count is not zero and a gate would have to pin today's absolute; a rise is judged in `compare.mjs`. `gcc -std=gnu89` accepts an implicit declaration at any arity and the emitter writes no prototypes, so the 842/842 figure **cannot move** on an arity defect. Validated by negative control: reverting `peek-a-bin-qb2x` (`collectArgs64` probing width-exactly again) takes t64 88→62 and w64 92→66 exact with over unmoved at 3, and `5 ExitProcess` reappears among the under rows (`peek-a-bin-02fa`; the instrument this replaces was lost with a deleted worktree, which is why these numbers are the first reproducible ones).

  **The over-count was 8/3/3/10 at `e22ba6e`, and the x86 half of the fall is `peek-a-bin-f51x`, which reached exactly half of it.** The 8 and 10 were **two shapes, not one**, and only one is structurally fixable — see the `collectArgs32` gotcha below. What remains on x86 is **Shape 2, 4 rows on t32 and 6 on w32**: `collectArgs32`'s backwards walk running past the real arguments into the function's own callee-saved *prologue* pushes (`GetCommandLineW(edi, esi, ebx)`, `GetModuleHandleW(…, edi)`, `SetFilePointer(…, 5 of 4)`, `GetLastError(edi, esi)`, and on w32 `LoadLibraryA("user32.dll", esi)` twice). **Do not "fix" that with the rule that a push of ebx/esi/edi is a save** — this same corpus refutes it at t32 0x402c4a, where `push esi` *is* a genuine argument to `TerminateProcess`. A save and an argument are the same instruction and nothing in the basic block distinguishes them; for stdcall imports the callee pops its own arguments, so there is no `add esp, N` to read back either. Tracked as `peek-a-bin-6lmh`; **the residual is not a threshold** and no gate should be invented at 4/6.
- **A register read that names a value it does not hold is a gate**: `corpus/staleReads.ts`, **0 wrong and 0 spoiled repairs on all four binaries**, over 33/182/181/34 sites at `82ed61e`, from 28/78/28/78 wrong reads and 13/19/13/18 spoiled copies before the fix. Unlike the two audits above this one *is* gated at zero — every row it can report is a provably wrong name (a store through the wrong pointer, a call given the wrong argument), which is `polarity inverted`'s character rather than a count awaiting a threshold. It must run `foldBlock`: stopping at `destroySSA` reports 151 on t64 instead of 78, by counting dominating writes that fold into their single use (`peek-a-bin-dqpk`). Two things it must keep doing, both of which it once did not: attribute a phi's definition to each *predecessor* as well as to the phi block, since that is where the copy lands, and compare the *name* rather than the canonical register, since a correct live-range split emits two names for one register (`peek-a-bin-fppy`, `peek-a-bin-pzws`).
- **The practical file-size ceiling is disassembly, not parsing** — performance envelope in `docs/architecture.md`.

**"Clean" is not "recovered."** 287 of those functions (of 847, when that count was taken) contain an *admitted* gap — a
`__unrecovered_N` or a `/* unlifted: … */` — and compile precisely because the emitter names
what it failed to recover instead of printing something plausible. That is the intended
behaviour, not a defect count, but do not read "all of them compile" as "all of them are right".
(287 was counted at `peek-a-bin-oro`; the funclet change landed after it and the count was not
re-taken.)

**Not verified. Say so rather than implying otherwise:**

- **Nothing has rendered a component.** No jsdom, no `@testing-library/react`, no renderer at all. Hooks cannot be mounted, so hook logic is tested only by extracting the decision into an exported pure function (`parseAnnotationMessage` in `useMcpSync.ts`, `modalScaffold.ts`, `listboxIds.ts`, `asyncMetricState.ts`, `decompileTabsState.ts`) or, for the two dependency arrays that matter most, by checking them against the function body over the AST. `DisassemblyView` and everything split out of it, all six modals, the focus trap, the body scroll lock, the command-palette listbox and the whole a11y pass are verified by typecheck, lint, pure-function tests, build and reading — nothing else. Adding a renderer means new deps plus React plugins in `vitest.config.ts`, and that decision has never been taken.
- **No human has looked at this branch in a browser.** `peek-a-bin-v2u` is the checklist; ~15 minutes with the app open closes more risk than any further static work.
- **The architecture refusal has never been seen in the UI.** The engine rejects, and per the `AnalysisPhase` contract that lands as `"failed"` in the status bar — but whether `unsupportedArchMessage`'s *text* reaches the user, or only a generic failure, is unverified, and so is whether the header/import/export/string views stay populated in that state. They should, since `parsePE` runs on the main thread before any worker call, but the MCP path needed an explicit guard in `FileSession.loadFile` for exactly this failure, so the browser path deserves a check rather than the same assumption (`peek-a-bin-8ru3`).
- **There is no ARM32, ARM64EC or ARM64X binary on this machine**, so every one of those paths is verified against synthetic fixtures and nothing else. The A64 decode-rate floor is calibrated against real ARM64 and real x64 only, and an ARM64X image — half of which is genuine A64 — may sit above it.
- **The nginx headers and the CSP have never been exercised in a browser** — both are researched from code and build output.
- **The a11y work has never met a screen reader.**
- **MCP → browser WebSocket annotation sync has never been exercised end to end**, in particular since the 127.0.0.1 bind change.
- `@vitest/coverage-v8` is not installed, so `npm run test:coverage` fails.

When a UI or deployment change lands, the honest report says which of these it did *not* move.

## Decompiler Architecture (`src/disasm/decompile/`)

**Pipeline** (`pipeline.ts`): `buildCFG → liftBlock → buildSSA → ssaOptimize → destroySSA → foldBlock → structureCFG → cleanupStructured → wrapExceptionRegions → inferTypes → promoteVars → synthesizeStructs → emitFunction`

(`wrapExceptionRegions` is local to `pipeline.ts` and only runs when `.pdata` exception info is
present. The docstring at the top of `pipeline.ts` lists a shorter, outdated order — trust the
code, not that comment.)

**IR** (`ir.ts`): `IRExpr` union (12 kinds: const, reg, var, binary, unary, deref, call, cast, ternary, field_access, array_access, unknown) + `IRStmt` union (18 kinds including if/while/do_while/for/switch/break/continue/phi/try/**branch**).

**`branch` is confined to `liftedBlocks` and never appears in a structured tree.** `liftBlock` turns a block's trailing conditional jump into an `IRBranch` so its condition is a real IR reader — an SSA version, a reaching definition, a place in every use count — and `pipeline.ts` step 4b extracts every one of them again *before* `structureCFG`. Two orderings are load-bearing and neither is obvious:

- The extraction runs **before the tap snapshot**, or the statement-drop audit reports every branch as a dropped statement in each block ending in a conditional jump.
- The branches must not survive into the tree: `detectForLoop` skips any body block whose last statement is not an `assign`, so one left in place takes **for-loop recognition to zero corpus-wide**, silently and with no failing test.

`emit.ts` therefore *throws* on a branch rather than ignoring it — `decompileFunction`'s catch turns that into a counted `throws`, which `compare.mjs` gates on, where a silent arm would make a structural failure invisible. Anything that appends to the end of another block's statement list must go through **`pushBeforeTerminator`** (`ir.ts`): `destroySSA` lowering a phi into a predecessor and `loopInvariantCodeMotion` hoisting into a preheader both did a plain `push`, which was correct only while no terminator existed in the IR.

**`ssadestroy.ts`'s `mapReads` deliberately has no `branch` arm, and that must change *with* the `extractCondition` flip, not before it.** A guard's registers are reads, so `splitStaleReads` can neither see nor repair one today (~300 stale, unrepairable reads per binary) — but while step 4b discards the conditions, adding the arm costs **+116 emitted lines across 96 functions** in dead repair copies for no recovered value. None of those reads is version 0, so the stale-read gate stays green through all of them (`peek-a-bin-c33`).

### Adding new IRExpr / IRStmt kinds

Adding a kind means updating every switch that dispatches on `expr.kind` / `stmt.kind` — there
are **64** of them (44 switches and 20 if-chains), and a missed one silently drops data rather
than failing. The tables below are accurate about every site they name but do **not** name them
all — roughly 30 are missing, so grep as well as reading. They split into two
groups:

**That 64 counts `IRExpr` and `IRStmt` sites together. For `IRStmt` alone the count is 88**,
across `src/disasm/decompile/{ir,ssa,ssaopt,ssadestroy,fold,cfgpatterns,structure,cleanup,typeInfer,promote,structs,emit}.ts`
plus `corpus/{sweep,staleReads}.ts` — nothing else under `src/` imports `IRStmt` at all. It was 91
before `bodiesOf`/`rewriteBodies` were merged into `ir.ts`, which removed five such switches and
added two (peek-a-bin-svwt). **8 are compiler-caught; the other 80 are silent.**

That 8 is *measured*, not counted by reading: add a throwaway `IRStmt` kind to the union, run
`npm run typecheck`, count the `not assignable to type 'never'` errors. Doing that names exactly
`ssa.ts:renameStmt`, `ssadestroy.ts:stripVersionsStmt`, `emit.ts`'s three (`emitStmt`,
`liveInStmt`, `collectAssignedRegs`), `corpus/sweep.ts`, and `ir.ts`'s `bodiesOf` and
`rewriteBodies`. **This paragraph previously also claimed 8 while `ir.ts`'s two did not exist**,
because it credited `ssadestroy.ts:mapRegs` and `fold.ts:hasSideEffects` — both of which are
`IRExpr` switches and catch nothing about a statement kind. Use the probe rather than the table
if the number matters.

Two beyond the tables below are worth knowing about because
no table lists them and they are not dispatches at all: `cfgpatterns.ts`'s `detectForLoop` reads
`stmts[len-1].kind !== "assign"` and `cleanup.ts`'s `endsWithTerminator` reads the last statement's
kind — both are *predicates over a block's final statement*, so a new terminator-shaped kind changes
loop shape rather than dropping data, which is the defect class no audit here models.

**The compiler catches these.** Thirteen switches end in a `const _exhaustive: never = …` binding,
so adding a union member breaks the build until they are handled. Just run `npm run typecheck`:

| File | Functions |
|------|-----------|
| `ir.ts` | `bodiesOf` / `rewriteBodies` — the **only** declaration of the structured-tree body traversal, and the reason these two are in this table rather than the `default:` one below. See the entry under **Gotchas** |
| `ssa.ts` | `renameExpr` / `renameStmt` (inside `renameVariables`) |
| `ssadestroy.ts` | `mapRegs`, `stripVersionsExpr` / `stripVersionsStmt` |
| `emit.ts` | `emitExpr` / `emitStmt`, plus `liveInStmt` and `collectAssignedRegs` — the backward liveness and the assigned-register set behind a call's result assignment. Both are full `IRStmt` switches, so a new statement kind breaks the build in **three** places in this file — `emitStmt`, `liveInStmt` and `collectAssignedRegs`; `emitExpr` is an `IRExpr` switch and is not one of them |
| `fold.ts` | `hasSideEffects` — now **one** exported definition, imported by `ssaopt.ts`. It used to be two independent if-chains that had both omitted `cast`, so `rbx = (int64_t)GetLastError()` read as pure and DCE deleted the call |
| `workers/dispatch.ts` | the RPC method dispatch (guards `WorkerMethod`, not IR) |

**You must find these by hand.** The typechecker stays silent on all of them.

*Switches ending in `default:`* — the new kind takes the fallback branch:

| File | Functions |
|------|-----------|
| `fold.ts` | `foldStmt`, `countReads`, `countReadsInStmt`, `substituteReg`, `substituteRegInStmt` |
| `ssaopt.ts` | `replaceRegInExpr`, `replaceRegInStmt` |
| `structs.ts` | `exprKey`, `rewriteExpr`, `rewriteStmt` |
| `promote.ts` | `renameVarsInExpr`, `renameVarsInStmt`, `promoteExpr`, `promoteStmt` |

(`cleanup.ts` used to be in this table, for `cleanupStmt`. It is gone — it was `rewriteBodies`
with `cleanupPass` as the callback, as was its neighbour `repairStmt`, and both are now that call.)

*Switches with neither `default:` nor a `never` assert* — control simply falls off the end, so
the new kind is dropped with no trace at all. These are the dangerous ones:

| File | Functions |
|------|-----------|
| `ir.ts` | `walkExpr`, `walkStmts` — **only these two**; `bodiesOf` and `rewriteBodies` in the same file are exhaustive and belong to the compiler-caught table |
| `ssaopt.ts` | `canonicalizeExpr`, the stmt walker in `deadCodeElimination`, the LICM expr walker |
| `structs.ts` | `walkExprs` and the stmt walker in `collectAccessPatterns` (both nested functions) |

*Not switches at all* — `foldExpr` (`fold.ts`) and `countExprUses` (nested in `ssaopt.ts`'s
`deadCodeElimination`) are if-chains on `expr.kind`. Grep the function name, not `case`.

`typeInfer.ts`'s `parseCastType` keys off type *strings*, not kinds — only relevant if the new
kind gets a cast spelling.

**Type system** (`typeInfer.ts`): `DecompType` lattice with 12 kinds (unknown, int, float, ptr, bool, void, struct, array, handle, ntstatus, hresult, enum). `meetTypes()` merges types — specific wins over unknown, handle/ntstatus/hresult win over int/ptr. `enum` carries a name and a `Map<number, string>` of members, synthesized from switches with 3+ cases.

**API signatures** (`apitypes.ts`): **209** Win32/NT API type signatures at `e22ba6e` (the long-standing "~130" here was stale), none of them variadic — which is what makes the table usable as `corpus/arity.ts`'s arity oracle. Use type shorthands (PVOID, HANDLE_T, NTSTATUS_T, etc.) for consistency. Return `HANDLE_T` for handle-returning APIs, `NTSTATUS_T` for Nt/Zw, `HRESULT_T` for COM.

**Struct synthesis** (`structs.ts`): `StructRegistry` is cross-function state shared in the worker. `decomposeAddress()` breaks `base + idx*scale + offset` patterns, including a top-level `base - const` (folded to a negative offset; subtracting a *register* is not an offset and still returns null). 2+ distinct offsets on same base → struct candidate.

Scale ∈ {1,2,4,8} → `IRArrayAccess`, whether or not the function has a struct candidate. A function with no candidate but an indexed access takes a rewrite-only path; one with neither is returned by identity.

**Escaping struct defs are snapshots; registry-internal ones are live.** `synthesizeStructs` clones into `IRFunction.typedefs` (`cloneStructDef`), so an already-returned declaration cannot change when an unrelated function is decompiled later. Inside the registry the objects stay shared and the inference passes still mutate `field.type` in place — that **is** the cross-function type-refinement mechanism. So do **not** clone in `findOrCreate` or `get`: it disables refinement silently, with no test failing. Field *types* are always replaced wholesale rather than mutated, so a shallow field copy is sufficient.

**Merging is shape-based but guarded.** An exact `offset:size` fingerprint match merges unconditionally. The subset path additionally requires the smaller shape to have **3+ fields** (`MIN_SUBSET_MERGE_FIELDS`) and the merged layout to be free of overlapping extents (`hasBoundaryConflict`). Two distinct offsets is the *minimum* a candidate can have, so two-field shapes are simultaneously the most common and the weakest evidence — `{0:8, 8:8}` describes a large fraction of all structs. The cost is real and deliberate: a two-field partial view of a struct no longer completes from another function's larger view. Failing to merge is the benign direction — two `struct_N` declarations instead of one wrongly shared.

**Provenance beats shape, and recovers that cost.** Two bases occupying the same parameter slot are the same object by construction, so `findOrCreateLinked` merges on that evidence and deliberately ignores `MIN_SUBSET_MERGE_FIELDS` — a two-field view of a parameter *does* complete from a caller's fuller view. It still cannot override `hasBoundaryConflict`: contradictory layouts mean one reading is wrong. Two maps are kept apart on purpose — `paramLinks` (what a *caller* passed in) and `paramViews` (the *callee's* own reading) — so a merge always has the callee's corroboration and a passthrough `void*` helper never links its unrelated callers. Identity is published in both directions, so caller-then-callee and callee-then-caller agree.

Both merge directions scan `fingerprintIndex` in insertion order and take the first match, so *which* struct absorbs which is still order-dependent.

**Emitted struct definitions are `#pragma pack(1)` with explicit `_pad_0xNN` members**, and the two are inseparable — padding alone cannot express an unaligned recovered offset and C would re-align on top of it. The field *names* record the offsets the recovery found (`field_0x18`), so a declaration C would not lay out that way is a declaration that states something false: before the fix, 131 of 149 emitted definitions were wrong that way, and every `p->field_0x18` in those bodies read bytes the access never touched. A field no padding can place — overlapping one already placed, negative, past 0x8000, or of a width with no spelling — is reported in the struct body and its accesses spelled as the bytes they touch, rather than declared somewhere convenient (`peek-a-bin-ey0`).

**A call takes an assignment only when its result is live out of the call.** `liftBlock` gives every `call_stmt` a `resultDest` of RAX/EAX, but emit printed the call and dropped the assignment, so `GetProcAddress(...)` followed by `if (rax == 0)` was C in which nothing ever assigns `rax` — 968 accumulator reads of an unassigned name across the corpus, now 254. Which calls get one is answered as the liveness question it is: a backward pass over the **structured** body (the tree emission walks, so the statement the reader sees after a call is the one the analysis asked about), loop headers to a fixpoint, `break`/`continue` carrying the live set of the construct they leave, a handler live throughout the body it guards, and a `goto` — the one shape the tree does not model — falling back to every register the body names. 2665 of 4160 calls take an assignment; the rest stay bare, because an assignment nobody reads is noise. `_assignedRegs` follows the same rule, so `registerText` cannot respell a read of `al` as `(uint8_t)rax` in a function whose only write of RAX went unprinted.

**emit.ts module-level `_typeCtx`**: Set before emission, cleared after. Enables cast suppression and type-aware idioms (INVALID_HANDLE_VALUE, NT_SUCCESS, SUCCEEDED/FAILED).

## Gotchas

- **Nothing may call `cs.disasm` directly. Every decode goes through `disasm/capstoneWindow.ts`.** capstone-wasm's linear memory is a fixed **16 MiB that cannot grow** (its `emscripten_resize_heap` aborts immediately), the input is copied onto a **~65.6 KiB WASM stack** by emscripten's `ccall`/`stackAlloc`, and `cs_disasm` allocates one contiguous `cs_insn[]` (~240 B/insn) for the whole window. The old `CHUNK_SIZE` of 0x10000 sat within **1 KiB** of the stack cliff: 65536-byte windows decode, 66560-byte ones throw `table index is out of bounds` and leave the module permanently dead. Going over is **silent** — `disasm` *throws* when it decodes nothing, and every scan loop read a throw as "this byte is not code, skip one", which is the right reading for an undecodable byte and exactly the wrong one for a dead engine. Measured: `hybridDisassemble` over a real `.text` grown to 0.5/1/2/4 MiB returned **12.5% / 7.2% / 4.6% / 3.2%** of its instructions, raised nothing, and afterwards could not decode a single `nop`. `createScan` clamps to `CS_WINDOW_BYTES` (0x2000) and `CS_MAX_INSNS_PER_CALL` (2048) and probes the engine after a run of failed decodes, so exhaustion surfaces as `CapstoneUnavailableError` → `analysisPhase: "failed"`. Smaller windows are also *faster*. A source-scraping drift guard in `__tests__/capstoneWindow.test.ts` fails if any file under `src/` outside `capstoneWindow.ts` contains `.disasm(`.
- **In every arch dispatch, the `"unsupported"` arm must be checked *before* the `"arm64"` arm.** `dispatch.ts` and `mcp/disasm.ts` branch on `state.arch` in a chain, and the tail of that chain is the x86 path. Put the ARM64 test first and an unsupported image falls straight through to x86 — which is the exact bug the third state exists to fix: an ARMNT file decoded as x86 produces a full screen of plausible instructions the file does not contain, and unlike ARM64 there is no coverage signal to notice it by, because an x86 linear sweep decodes essentially any byte string. `WorkerState.arch`'s docstring says this too; keep both true.
- **A block with no predecessor is not necessarily dead code.** `structureCFG`'s leftover pass used to require reachability from the entry, on the reasoning that everything else is alignment padding. What that excluded was 1160 blocks of real code: an MSVC `__except`/`__finally` continuation or a 32-bit SEH scope handler is entered *by the unwinder*, so it has no predecessor at all and sits past a `ret`, while being ordinary code inside the function's own bounds. 29 real calls never reached the output. Padding is still excluded, by the test that was already doing the work — a block that lifts to no statements is not resurrected. Cost of the fix: +20.1% emitted text on t32, +0.1% on the two x64 binaries (`peek-a-bin-d3z`).
- **Register names follow the image's width, and the phi cannot tell you what that is.** `canonReg` maps every alias to the 64-bit parent because that is the register's *identity*, and SSA keys on identity — so `phi.dest.size` is `regSize("rdi") = 8` for **every** phi even in 32-bit code (measured over every phi t32.exe produced, 741 of them at the time), and a width-based `canonReg` inverse has nothing to invert. Lowering a phi to a copy with the canonical name emitted `rdi = rax` inside a function whose every other line said `edi`: **77 of t32's functions — better than a quarter of them** — named a register the image has no encoding for. `destroySSA` takes the width from the function's own statements instead (`registerSpeller`), falling back to `regAtSize(canon, 4)` where `ssaOptimize` deleted the defining statement after the phi was placed (`peek-a-bin-1k4`).
- **…but the *function* is the wrong scope for that width, and the live range is the right one.** `registerSpeller` kept the widest alias per canonical register and gave it **one name per function**, which cannot serve a register carrying two live ranges of different widths at once — and that is ordinary MSVC output, not a corner case. `mov rbp, r9` / `mov r9d, r14d` is R9's entry value copied away as a pointer and then a 32-bit clobber of R9D; copy propagation forwards `rbp` to `r9`, so the stores are emitted against a 64-bit read of the entry value while the 32-bit range gets a phi copy — and asking the function gives *both* the name `r9`. Six stores plus a `rax = r9` then went through a pointer the emitted C had already reassigned, while two guards read an `r9d` nothing assigned: a write through the wrong pointer and a read of an unassigned name, in C that compiles clean, because `gcc` declares `r9` and `r9d` as two unrelated `long`s. The fix is **per-live-range naming**, not more evidence — both ranges survive and one name cannot serve both. A live range here is a *phi web*: the versions a phi ties together transitively, restricted to one canonical register (after `ssaOptimize` an operand may name a different register, and that is a real cross-register copy whose two sides are spelled from their own ranges). The web takes the widest mention of its **own** members, which is what its readers already say; the function-wide answer is the fallback for a web `ssaOptimize` left with no mention at all, which is what keeps `peek-a-bin-1k4` fixed. Narrowing can only help — a web is then named by a spelling some member uses, where the function-wide answer may be one *no* member uses. `nameClobberedReads` and the phi copy's `clobber` branch build the same `clobbered_…` name, so both pass the version or neither may. Measured at `82ed61e`: emitted C changed in 4/288, 43/279, 3/285 and 41/275 functions (t32/t64/w32/w64), gcc/offsetof/polarity/callees/statement-drops/**arity all unmoved**, and the stale-read gate green at 0 over a widened site set (`peek-a-bin-pzws`).
- **ARM64EC and ARM64X carry machine 0xAA64 too, and are refused by decode rate.** Telling them apart properly needs the CHPE metadata pointer out of the load-config directory, which the parser does not read, so the evidence used is the bytes: sweeping a code section with an A64 handle decodes 97.4%/97.7% of the two real ARM64 binaries against 21.8–27.9% of four x86/x64 ones. **~A quarter of arbitrary x86 bytes decode as *something* in A64** — that density is exactly why the failure was silent, and why the floor is 50% rather than anything near 100%. `disassembleArm64` throws `Arm64DecodeRateError` below it on sections of 256+ words; `detectArm64Functions` catches and degrades via `DetectResult.omitted`, because `.pdata`, the exports and the unwind handlers are the linker's own record and stay true. Stated limitation: an ARM64X image is half genuine A64 and may pass the floor (`peek-a-bin-2t1`).
- **`.pdata` is authoritative for x64 function boundaries and beats prologue scanning.** Where a `.pdata` range exists, a prologue-byte or padding-heuristic candidate strictly inside it is a re-detection of a function already known exactly, not a new function: t64 went 511 → 279 functions, 232 overlapping pairs → 0, 93 fully-contained → 0, 53 empty decompiled bodies → 16. Evidence about an *entry point* — call target, jump-table target, export, entry point, unwind handler, `.pdata` begin — still wins inside a range. PE32 has no `.pdata` to arbitrate and still over-produces (`peek-a-bin-abv`).
- **An MSVC x86 `__finally` funclet is not a function, and the SEH scope table must not be used to argue that it is.** The funclet is emitted *inside* its parent, reached by a `call` from it, ends in `ret`, and the parent resumes on the next byte — so it is a call target, hence a function start by every other rule, and since sizes are distance-to-next-start it cuts its parent in half and the parent loses every `jcc` aiming past the new end. `interiorBranchedOverStarts` (`functionDetect.ts`) withdraws such a start when nothing outside the previous function calls it *and* a conditional jump that function can actually execute crosses it; that is what took t32 from 293 to 288 functions at `95229d3`, folding five funclet bodies into the five parents, with the instruction stream byte-identical either way. The trap for later: **the file does name two of those five** — 0x4058A6 and 0x4063B8 are handler entries in their parents' scope tables in `.rdata` (`{EnclosingLevel -2, Filter NULL, Handler …}`, and a NULL filter means `__finally`) — so `strong` means "named by a table the parser reads", not "named by the file". Parsing that table and feeding its handlers into `strong` would re-break `sub_4031A4`, whose funclet the table names at 0x403270 with the withdrawn 0x403276 six bytes inside it. The table's real content is *funclet-of-parent*, which belongs in a relation, not in a set that protects a start (`peek-a-bin-sysf`, `peek-a-bin-gtlf`).
- **A jump-table case target is not a function start.** `detectFunctions` used to add every case target to the function-entry set, and function sizes are the gap to the next entry in that same set — so the function holding the `jmp [table]` ended at its first case and each case body became a bogus function. Downstream, `buildCFG`'s range guard rejected every target as a block leader, the indirect-jmp block got **zero** successors, and `structureSwitch` was dead code on real input: **no `switch` had ever been emitted for a real binary in the project's history**. Case targets now go to a separate set, outrank a byte-pattern guess at the same address (case bodies routinely follow alignment padding), and are fed to `hybridDisassemble` as seeds via `seeds.ts` — without them, phase-2 gap fill starts *on the table*, decodes its entries as instructions and eats the head of case 0.
- **A recovered jump table's bytes are data, and only `DetectResult.jumpTableSpans` says so.** Seeding the case bodies is not enough: nothing walks *into* a table, so the gap fill still reaches it as an uncovered range and decodes the case addresses as instructions — 32 bytes at t32.exe's 0x4086a4 came out as six conditional jumps aiming past the end of the function they were filed under, and w32.exe produced three more, which were the corpus's last 9 lost CFG edges (peek-a-bin-y1di, the residue of peek-a-bin-g7yp). `detectFunctions` reports the extent it actually read, `hybridDisassemble` takes it as a last optional argument and marks it covered before computing gaps, and the client and `mcp/session.ts` carry it beside the seeds. Omitting the argument keeps the old behaviour, deliberately: "nobody said where the tables are" is not "there are none". A bound the dispatch compares against a *register* — MSVC's `push 7 / pop ecx / cmp eax, ecx`, two bytes cheaper than `cmp eax, 7` — is followed back to the constant, because a table that cannot be sized is also a table whose bytes nothing knows to be data (peek-a-bin-mk42; +3 tables on t32, +1 on w32, and three more `switch`es emitted).
- **There is exactly one notion of "loop": dominance.** `cfg.ts`'s `detectLoops` delegates to `decompile/ssa.ts`'s `detectNaturalLoops` (an edge `u → v` is a back edge only when v dominates u) and repackages the result as `Loop[]`. It used to approximate back edges with BFS layers from the entry, which called the merge block of every `if`-without-`else` a loop header — ~86% of the loops reported on real binaries did not exist, and the mis-structuring **deleted guards**, turning conditional stores into unconditional ones. A diamond is immune to that mistake and a triangle is not, so hand-written fixtures never caught it; `__tests__/cfg.test.ts` and `decompile/__tests__/pipeline.test.ts` now pin both shapes. `detectLoops` is also what draws loop markers in the disassembly view (`useDisassemblyRows.ts`), so its semantics are shared with the UI.
- **`structureCFG` closes an `if` at the immediate post-dominator**, computed by `computePostDominators` (`structure.ts`) — `computeDominators` over the reversed CFG rooted at a virtual exit. The two "one arm ends in `ret`" shortcuts must not fire when that arm *is* the convergence point: in a triangle the branch target is the shared tail, so structuring it as the `then` body yields an empty body and drops the guard. A nearest-common-successor heuristic is not a substitute — for a switch it picks the default block, which is not on every path, and the code after the switch is then lost.
- **`extractCondition` returns the condition under which the jump is TAKEN.** Every entry in `regstate.ts`'s `condMap` is taken-polarity (`jg`→`>`, `jbe`→`u<=`, `js`→`< 0`), and `identifyBranches` returns the block the jcc jumps to. So the branch target is the `then` body under the *un-negated* condition, and `RegState.negate` is for the fallthrough — its own docstring says "for structuring: if-not-taken path". Getting this backwards inverted **every `if` and `while` the decompiler ever emitted** while leaving the bodies in place: valid C stating the opposite of the machine code, invisible to every stage-level test. `__tests__/pipeline.test.ts` guards it end to end now.
- **A branch condition goes through the lifter's real `parseOperand`.** `extractCondition` (`structure.ts`) used to re-parse the `cmp`/`test` operands with a private `parseSimpleOperand` that hardcoded `size: 4` and never called `ripRelative.ts` — the **tenth** hand-rolled copy of the parsing this repo has already centralised nine times, and the one that mattered most, because it decides what every guard says. `cmp byte ptr [rcx], dl` read as a 32-bit load, and `cmp byte ptr [rip + 0x13358], 0` kept the literal `rip + 0x…` while a `mov` two lines away resolved. Guard derefs went from 550/420/385 uniformly `int32_t` to their real widths and literal `rip` in guards to zero, and three separate classes fell out of the width alone: `*(int32_t*)(rbp - 0x64)` became the frame slot `var_64`, `r13 != -1` became `r13 != INVALID_HANDLE_VALUE`, and 51 more structs were synthesized. `structureCFG` takes `is64` for this; `pipeline.ts` passes it (`peek-a-bin-w6f`, `peek-a-bin-h0us`).
- **SSA version 0 means a register's *entry* value. The definition counter starts at 1.** `renameExpr` and the phi-operand fill both map a read with an empty version stack — the function-entry or parameter value — to version 0, so if `newVersion()` also handed out 0 then `rax_0` the incoming value and `rax_0` the first definition were the same `(name, version)` pair. `ssaopt`'s `sameReg`/`regKey` key on exactly that pair, so copy propagation, constant propagation, GVN and DCE all treated the two as one value: a store of an incoming register emitted the value written to it *afterwards*, and a `return` on a path that never assigns the accumulator returned the other path's value. Real binaries: 0 lost callees, 0 throws, −66 to −71 emitted lines, polarity unchanged (`peek-a-bin-swi`).
- **Version 0's repair is taken at the function's entry, and nowhere else.** Version 0 is the register's *entry* value, so no statement defines it and `splitStaleReads`' usual repair — a copy at the defining statement — has no site. It used to take the copy at the top of the *reading* block, and only when an earlier statement in that block was the overwriter. Both halves fail when a **strictly dominating** block has already written the register: the read gets no repair and binds to a name holding something else (78 reads on t64, 28 on t32), or it gets one taken past the damage, so `rcx_0` preserves the wrong value under a name that looks recovered (19 spoiled copies on t64, 13 on t32). The one point where the register provably holds version 0 is the function's entry, so the copy goes there and every stale read of that version routes to it — one copy per register per function. The objection on record, a `wcslen` loop reading RAX_0 while the body advances RAX, needs a block the *unwinder* enters: no predecessor, hence no `idom` entry, hence `dominates` from the entry block declines it structurally. Corpus gate: `corpus/staleReads.ts`, 0 on all four binaries (`peek-a-bin-dqpk`).
- **`liftBlock` emits plain register reads. It does not substitute `RegState`'s symbolic value at each read.** It used to, while still emitting the assignment that produced the value, so one machine `call` became three calls in the IR (`rax := call f(r9)`, `r9 = f(r9)`, `eflags = f(r9) & f(r9)`) and `sub rax,rcx / sar rax,1 / dec rax` emitted RCX subtracted three times. Measured fix: lines calling the same function twice 121/188/120 → 0 on t64/t32/w64, `eflags` lines 138/326/135 → 5/4/5. Propagation belongs to SSA, `ssaopt` and `foldBlock`, which have the version information that makes it sound; `RegState`'s symbolic values are still needed for `getCondition`/flag tracking (`peek-a-bin-urs`, `peek-a-bin-zsb`).
- **No read of RSP may be moved to another program point.** `push`, `pop` and the return address a `call` pushes are not lifted, so RSP changes with nothing in the IR recording it — there is no faithful definition chain to reason over. Inlining `mov ebp, esp` across an unmodelled `push` printed `*(int32_t*)(esp + 8)` where the instruction said `[ebp + 8]`: a base register the instruction never named, one push off the value it did name. **Both** `ssaopt.ts`'s copy propagation and `fold.ts`'s single-use inlining guard this, and both are needed — the second re-introduced the defect the moment an unrelated fix made the frame-pointer copy single-use (`peek-a-bin-rt4`).
- **`arg_N` in a stack frame means argument *position*, and only when the frame was verified.** `stack.ts` numbers a slot `arg_<index>` from its offset, but only after confirming a real `push rbp` / `mov rbp, rsp` prologue; otherwise the name is offset-based (`arg_0x10`). That distinction is load-bearing — under frame-pointer omission RBP is usually a callee-saved object pointer, so `[rbp+0x10]` is often a struct field access, and `structs.ts` keys struct provenance off `^arg_(\d+)$` precisely to exclude those. The name is the only channel between the two files (`IRParam` carries name and type and nothing else), so do not loosen it. On x64 the first slot is RCX's ABI home slot, which puts the fifth argument at `[rbp+0x30]`, past the shadow space.
- **Recursing into a statement's nested bodies is `ir.ts`'s `bodiesOf` / `rewriteBodies`, and there is exactly one declaration of each.** `rewriteBodies` was a *verbatim* copy — docstring included — in both `structure.ts` and `cleanup.ts`, and `cleanup.ts` held two more specialisations of it under other names (`repairStmt` = it with `giveTrailingLabelsAStatement`, `cleanupStmt` = it with `cleanupPass`): four hand-synced switches over `IRStmt` for one traversal, the shape `sections.ts`, `ripRelative.ts`, `funcInsns.ts` and `apiLists.ts` each exist to end. All four ended in `default:`, so a new statement kind carrying a body would be returned unrecursed in every one of them — silently, and the copy you had not noticed is the one that bites. Both now end in an exhaustive `never` instead, which is a deliberate second decision and not part of the de-duplication: it names all twelve body-less kinds explicitly so the *next* body-carrying kind is a build error. Verified both directions — the merge is output-neutral (all 1127 emitted functions byte-identical across t32/t64/w64/w32, `compare.mjs` CHANGED 0 of 3144 guards, at `e22ba6e`), and a probe kind added to the union does fail the build at both switches. **`for`'s `init` and `update` are single statements, not lists, so neither function reaches inside them** — true of the copies too, and a caller needing that wants `foldStmt`'s shape (peek-a-bin-svwt).
- **`regSize()` is not a membership test.** It falls back to `4` for any unrecognised name, so `regSize(x) > 0` is true for every string. Use `isKnownRegister()` (`decompile/ir.ts`). This exact mistake made `lifter.ts`'s `isRegister()` a no-op that lifted immediates as registers.
- **`RegState.defs` is keyed by the literal operand text, and that is deliberate — ask `wroteAnyAlias` instead of canonicalising the map.** The map stores the *expression* last written, and that expression has the operand's width, so a key of `rcx` would record `mov cl, 2`'s one byte as if it were eight; on x86-64 a byte write does not even clear the upper bits a 32-bit write does. But *arity* is a width-blind question — `mov ecx, 1 / call f` passes an argument in RCX exactly as `mov rcx, 1` does — and `collectArgs64` probed the literal 64-bit name, missed every sub-width setup, and broke out of the loop there. With no argument in the IR the write had no reader and DCE deleted it: `ExitProcess()` with the exit code gone, in valid well-typed C, 5 times in each x64 binary. `wroteAnyAlias` answers the width-blind question over the width-exact map (same shape as `invalidateCallerSaved`), and returns a boolean so the recorded expression can never be substituted at the call site — `peek-a-bin-urs` cannot come back through it. **The suite had pinned the defect as the rule** (`it("misses x64 arguments set up through 32-bit sub-registers")`, asserting `[]` under a KNOWN BUG comment), which is why nothing failed for as long as it stood. Measured: 156/279 t64 and 154/275 w64 functions changed emitted text, t32/w32 byte-identical (`collectArgs32` reads pushes, not `RegState`), and against `apitypes.ts`'s declared signatures — the only oracle here that can see arity, since `gcc -std=gnu89` accepts an implicit declaration at any arity — exact-arity calls went 64→90 and 70→96 with over-count unmoved at 3 (`peek-a-bin-qb2x`). **Those four figures are stamped at the qb2x measurement and detection has moved since; the audit is now `corpus/arity.ts` and HEAD's numbers are in the Verification section.** The instrument that produced 64→90 was lost with a scratch worktree and the claim was unrepeatable for a while (`peek-a-bin-02fa`) — when you build an oracle to verify a change, land the oracle.
- **`collectArgs32`'s backwards push-walk stops dead at a call whose result feeds a *following* call, and the marker is AFTER the call, not before it.** The shape is `call inner` / `push eax` / `call outer`: the inner call's result is pushed, so the inner call is an argument expression of the outer one and the pushes *above* it are the outer call's. Verified on t32.exe at 0x40e08b (`push ebx` / `push 0x8` / `call GetProcessHeap` / `push eax` / `call HeapAlloc`) and 0x402c4a (`push esi` / `call GetCurrentProcess` / `push eax` / `call TerminateProcess`) — **there is no call *between* the pushes and the inner call**, which is why the tempting rule "stop the walk at an intervening call boundary" would never fire once. 19 such marker sites on t32 and 18 on w32; ~7 and ~6 emitted calls actually lose arguments, the rest having had none to steal. It is deliberately an **admitted under-count, not a re-attribution**: handing the pushes to the outer call instead is a guess in the *over*-count direction, and an invented argument is the one error this codebase will not trade for a recovered one. In this corpus every callee the rule fires on takes zero arguments, so all of them land on `exact` — arity over went **8→4 on t32 and 10→6 on w32, exact 70→74/105 and 73→77/111**, x64 byte-identical (`collectArgs32` is the x86 path only). **The best evidence is a callee `apitypes.ts` cannot see**: t32's `sub_402283(edi, esi)` became `sub_402283()`, and that function is called with no preceding pushes at 10 of its 13 call sites, so it provably takes none — the two arguments were invented and no oracle here would ever have reported it. Costs, both benign and both measured: two struct shapes on each x86 binary stop merging (`distinctDefs` 57→59 and 56→58, per-preamble `fields` 358→348 and 413→403, **every layout still correct in both runs**), which renumbers `struct_N` across ~43 t32 and ~41 w32 functions whose text is otherwise unchanged (`peek-a-bin-f51x`).
- **The CSP is generated, not hand-written.** Edit `build/csp.ts`, never `nginx.conf`'s header or `index.html` directly — `build/csp.test.ts` fails on drift. A meta CSP cannot be committed into `index.html` because it is also the dev entry point and Vite injects an inline React Refresh preamble there. Note the shipped `connect-src` omits non-localhost plain `http:`, so a LAN Ghidra server is blocked on the HTTP nginx deployment.
- **Do not re-add a plugin that copies `capstone.wasm`.** Rollup already rewrites `new URL("capstone.wasm", import.meta.url)` to its hashed asset; a manual copy is pure duplication and was 1.7 MiB of the PWA precache. `capstone-wasm-guard` in `vite.config.ts` fails the build if more than one WASM asset is emitted.
- **`tools.ts` and `resources.ts` must only *type*-import `./session`.** A value import pulls in `./disasm`, which loads Capstone WASM at module scope, and both MCP suites become slow and fragile. `src/mcp/__tests__/importGraph.test.ts` enforces this.
- **`biome.json` must be strict JSON.** A single `//` comment silently voids the whole config and Biome falls back to defaults — which looks like your rule settings randomly stopped applying. `build/lintConfig.test.ts` fails on a comment and on `useExhaustiveDependencies` dropping below `error`; the seven a11y rules are at `error` too (301 findings were cleared), so keep all of it there.
- **A multi-line `biome-ignore` needs `//` on every line.** Biome only honours the directive on the line immediately preceding the offence, so put prose in a normal comment block above a single-line directive. Getting this wrong leaves bare text inside JSX and breaks the parse.
- **DisassemblyView.tsx** is ~1520 lines even after the split. Read in chunks. The two seams that used to live here are now `hooks/useDisassemblyKeyboard.ts` (`handleKeyDown`, ~270 lines with a **37-entry** dependency array — that array *is* the behaviour; copy it verbatim if you move it, and note the entries carrying `//` comments explaining why a stable value is listed or a value is deliberately omitted) and `hooks/useGraphSearch.ts`. That array only began doing anything recently: `useDisassemblySearch` returned a bare object literal, so `search` had a fresh identity every render and the `useCallback` memoised nothing, leaving the other 36 entries inert decoration. It was audited entry-by-entry over the AST before the memo landed and came back exactly 1:1, so nothing latent was exposed; `hooks/__tests__/disasmHandlerDeps.test.ts` now fails the build if it drifts in either direction. `CFGView` now takes 23 props, several of the former ones read from context instead. Both extractions were strictly mechanical, and neither has ever been rendered.
- **A callback declared later in a component cannot go in an earlier hook's dependency array** — it is a `const`, so the array hits its temporal dead zone at hook-call time. This is not hypothetical: `handleKeyDown` closed over `handleDecompileToggle` (declared ~340 lines later) without it in the deps, so **D opened the decompile panel but could not close it** — the memoized handler kept a closure where `showDecompile` was still `false`. The fix is a ref assigned *during render*; an effect is too late, because a keypress can be handled before effects flush.
- **`parseBranchTarget` lives only in `components/shared.tsx`** and resolves `call` immediates as well as jumps. JumpArrows draws jump arrows only, so it guards with `mnemonic.startsWith("j")` *before* calling — dropping that guard makes recursive/intra-function calls sprout arrows. Covered by `src/components/__tests__/parseBranchTarget.test.ts`.
- `sectionInfo.characteristics & 0x20000000` = `IMAGE_SCN_MEM_EXECUTE`. Used to distinguish code vs data sections.
- **A64 mnemonic matching is by *exact* mnemonic, never by prefix.** `brk` is not a `br` and `bfi` is not a branch, so `startsWith("b")` — the habit x86 encourages — mis-classifies real instructions. `arm64Operands.ts` is the one place that knows the grammar (`b`, `b.<cc>`, `bl`, `br`/`blr` including the PAuth forms, `cbz`/`cbnz`, `tbz`/`tbnz`, `ret`, and the `adrp`+`add`/`ldr` address idiom); `buildCFG`, `layoutCFG`, `parseBranchTarget`, the `JumpArrows` guard and `buildTypedXrefMap` all read it rather than re-deriving it. The x86 path is untouched by any of it and its edge and xref lists are byte-identical — keep it that way; the one shared spelling (`ret`) is deliberately left on the x86 path, where both architectures already yield nothing.
- **Don't put a cheap request on the disasm worker.** It services messages serially, so a checksum or entropy call posted behind a whole-image disassembly waits minutes. That is what `metrics.worker.ts` exists for. The same reasoning is why a `useMemo` is not an option: it cannot yield, and on a 253 MiB PE the entropy strip froze the UI for ~6.5 s on every Hex tab open whether or not the strip was ever shown.
- **Never put a caller-owned buffer in a worker transfer list.** Structured clone of an `ArrayBufferView` serialises its whole backing `ArrayBuffer`, not the view's window, and every large byte argument here is a view onto the *entire loaded file* — so a 4 KiB single-function `disassemble` used to copy all 253 MiB. `disasmClient.send()` routes args through `prepareBinaryArgs` (`workers/transfer.ts`), which replaces each top-level binary argument with a private `slice()` of exactly that window and transfers **only buffers it allocated itself**. That invariant is what makes the detach hazard structurally impossible: the main thread keeps reading the file through `bufferRef`, `pe.buffer`, HexView and entropy, and transferring a caller's buffer would detach the loaded file under them. The walk is **top-level only** — an `Instruction[]` carries a tiny `bytes` buffer per element, and transferring 500k of those measured **80.6 s against 1.6 s to clone**. Anything that must cross flattened (e.g. `packDataWindows`) does so for the same reason. Slicing wins even when the copy is the same size (186 → 96 ms), so there is no threshold below which this is skipped.
- Capstone WASM is cached in IndexedDB (`peek-a-bin-wasm`). First load fetches, subsequent loads read from cache.
- **`fold.ts` has a `castTypeSize` helper** for double-cast removal. Uses regex to extract bit width from type strings like `int32_t`.
- **`cleanup.ts`** runs after `structureCFG`, before `inferTypes`. Guard clause flattening is single-level only (not recursive inversion).
- **`StructRegistry`** persists across decompilation calls in the worker — don't clear it between functions in the same session.

## Gates

Always run after changes:

```sh
npm run typecheck && npm run build
npm test
npm run lint      # expect 71 warnings, 0 error-severity, 0 a11y
```

Passing these is *not* the same as the change being verified — see **Verification status**
above. If the change touched a component, a modal, the CSP or the nginx headers, nothing you can
run here exercised it.

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
