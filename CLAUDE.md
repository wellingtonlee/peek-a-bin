# Peek-a-Bin

Browser-based PE disassembler/analyzer. Fully client-side (no server). PWA with offline support.

**Tech**: React 19, TypeScript 5.7 (strict), Vite 6, Tailwind CSS 4, capstone-wasm, @tanstack/react-virtual, @dagrejs/dagre

**Requires Node 20+**. On Node 18 the build dies at the end of bundling with `ReferenceError: crypto
is not defined` (`serialize-javascript` via the PWA/Workbox terser path). Workaround:
`node --experimental-global-webcrypto ./node_modules/vite/bin/vite.js build`.

**This file is the index; the evidence lives in `docs/`.** Three companion documents carry the
long-form record — the measurements, the negative controls, the alternatives built and rejected:
[`docs/gotchas.md`](docs/gotchas.md), [`docs/verification.md`](docs/verification.md),
[`docs/decompiler-ir.md`](docs/decompiler-ir.md). Each keeps the same entries in the same order as
the matching section here. **Read the long-form entry before changing the code it describes** —
most of these rules are load-bearing in a way a summary can state but not justify.

Two habits the record exists to support: **a measured refusal is a result** (several entries
record an approach that was built, measured and rejected — re-attempting one costs a session), and
**a control that does not discriminate is a test that is not testing**, this repo's most frequently
recurring mistake.

## Commands

```sh
npm run dev            # dev server
npm run build          # tsc -b && vite build
npm test               # vitest run
npm run typecheck      # tsc --noEmit (faster than the full build)
npm run lint           # biome lint src — the fast, src/-only signal
npm run check          # biome check — THE CI GATE
npm run format         # biome format --write
npm run test:coverage  # RED — @vitest/coverage-v8 is not installed
```

Corpus harnesses need real MSVC binaries that are not in the repo and **skip cleanly (exit 0) when
they are missing** — see `corpus/README.md`:

```sh
npm run corpus                        # the four x86 binaries: every detection/decompiler gate
npm run corpus:arm64                  # A64 sweep, .pdata, xrefs, jump tables, sweep-cache differential
npm run corpus:comments               # ARM64 comment audit + x86 comment digest
npm run corpus:parserdiff             # PE parser vs an independent from-spec reader, all six binaries
npm run corpus:compare -- <base> <change>   # diff two runs; takes PATHS (corpus/artifacts/<label>)
npm run corpus:jumptables    -- <pe>  # indirect-dispatch census
npm run corpus:gridserve     -- <pe>  # hybridDisassemble grid coincidence + served-vs-decoded diff
npm run corpus:uploadcost    -- <pe>  # what re-sending .text costs
npm run corpus:decompilecost -- <pe>  # one decompile request, per payload member
npm run corpus:detectcost    -- <pe>  # where detectFunctions spends its time, per phase
npm run corpus:replycost     -- <pe>  # what the worker's reply costs
```

### Three traps in running the gates

- **`npm run check` is the gate, not `lint`** — same rules plus the formatter and
  `organizeImports`, over the whole repo. Current state: **0 errors**, ~70 warnings, 3 infos;
  warnings never fail it. Two infos are `useNodejsImportProtocol` on `vite.config.ts` (Biome classes
  the fix *unsafe*, so it is deliberately left); the third is a `biome.json` deprecation notice.
- **Reading a Biome result will tell you a red tree is green.** `--max-diagnostics` truncates
  *before* the `Found N errors.` summary, and piping makes `$?` report `tail`'s status. Use:
  ```sh
  npm run check > /tmp/check.txt 2>&1; echo "exit=$?"              # no pipe, so $? is Biome's
  npx biome check --diagnostic-level=error --max-diagnostics=300   # errors only, untruncated
  ```
- **A worktree inside the repo makes a root test run lie.** Tool-created subagent worktrees land at
  `<repo>/.claude/worktrees/`, *inside* the working tree, so a bare `npm test` reports someone
  else's results — and such a worktree has no `node_modules`, so it resolves another tree's
  dependency versions. Scope it: `npx vitest run --dir src`, then `npx vitest run --dir build` as a
  second command. Create worktrees yourself (see **Working in parallel**). The corpus config is
  anchored at `corpus/**` and is not at risk.

**Biome severities are ratcheted and must stay there** (`biome.json`): all seven configured `a11y`
rules, `correctness/useHookAtTopLevel` and `correctness/useExhaustiveDependencies` at **`error`**.
The last matters most — at `warn` the entire stale-closure class could not fail CI.
`build/lintConfig.test.ts` guards that severity and the strict-JSON landmine below. CI runs
`check`, `typecheck`, `test`, `build` and `npm audit --audit-level=high` on every PR.

## Source Layout (`src/`)

Many entries name a module as **the one declaration** of some rule. That phrasing is load-bearing:
each exists because the same predicate was hand-written at several sites and the copies drifted.
Reuse them rather than re-rolling the logic.

- **`pe/`** — PE parser (headers, imports, exports, resources, authenticode).
  - `truncation.ts` — `TRUNCATION_MARKER` / `isTruncatedValue`, the admission spelled *into a value*.
  - `dataDirectories.ts` — `dataDirectoryClamp`, `directoryDeclared`, `certificateUnreadable`,
    `resourcesUnreadable`; `admissions.ts` turns those facts into the SENTENCES the two
    session-outliving surfaces print (`parseAdmissions`, read by MCP resources and the report).
  - `ordinalTables.ts` — generated from pefile's `ordlookup`, **do not hand-edit**; also owns the
    `Ordinal_<n>` spelling (`ORDINAL_IMPORT_PREFIX`, `formatOrdinalImport`, `parseOrdinalImport`,
    `resolveOrdinal`), which is a **wire format** the parser writes and `computeImphash` reads back.
  - `sections.ts` — `findCodeSection`/`isCodeSection`/`dataSectionRanges`; `parser.ts`'s
    `buildSectionIndex()` + `rvaToFileOffsetIndexed()` are the batch form of `rvaToFileOffset`.
  - `arm64Unwind.ts` (both ARM64 unwind encodings); `pdata.ts`'s `readScopeTable` (the
    `__C_specific_handler` scope table — nothing consumes `RuntimeFunction.scopeTable` yet).
- **`disasm/`** — engine, types, CFG, operand parsing, stack analysis, signatures.
  - `capstoneWindow.ts` owns **every** call into the decoder; nothing else may call `cs.disasm`.
    `capstoneReader.ts` is the hand-written `cs_insn` marshaller under it (~3x faster) and the only
    place allowed to call `loadCapstone`.
  - `arch.ts` maps `coffHeader.machine` to `ImageArch`; holds `unsupportedOnArch()`. **Never select
    a decoder with `is64`** — that is the PE32+ magic and true for ARM64 too.
  - `funcInsns.ts` — one function's slice of a whole-image collection (`collectFuncInsns`,
    `funcXrefEntries`, `funcExceptionRecord`); imports only types, which is what lets
    `disasmClient.ts` and `decompile/pipeline.ts` share it.
  - `ripRelative.ts` — all `[rip ± 0x..]` parsing (was hand-rolled nine times).
  - `linearSweep.ts` — `sweepX86`, its session memo `X86SweepCache`, and `gridScan` (serves
    `hybridDisassemble` from the held sweep). `sectionMemo.ts` holds the memo key rule (bytes, load
    address, decoder identity).
  - `stackIdiom.ts` — the `push <imm>`/`pop <reg>` rule; **a leaf that imports nothing**.
  - `callSummary.ts`, `seeds.ts`, `dataWindows.ts`, `seh32.ts`. `branchTarget.ts` is the leaf both
    `callSummary.ts` (re-exporting it) and `crtIdioms.ts` read the `call`/`jmp` target grammar from.
  - `crtIdioms.ts` — CRT helpers recognised from their **body**, exactly (`__security_check_cookie`
    today, a table built for `__SEH_epilog4` next): the name, `preservesResult`, the cookie's
    address and the routine's register signature, riding in `CalleeClobbers.idioms` through the
    same whole-image pass and `needInstructions` protocol as the clobber summaries.
- **`disasm/arm64*.ts`** — `arm64.ts` (fixed-width sweep, `Arm64SweepCache`, jump-table reader,
  `arm64ThunkSlot`), `arm64Operands.ts` (**the single A64 branch/address grammar** — do not
  hand-roll a second), `arm64Frame.ts` (A64 frame from `.pdata`, a *second grammar* rather than a
  relaxation of `stack.ts`'s; `stackFrame.ts` dispatches), `arm64Xref.ts`. Everything x86-shaped —
  decompiler, x86 xrefs, IRP dispatch, signatures — **declines on ARM64 rather than guessing**.
- **`disasm/decompile/`** — IR lifting → SSA → folding → structuring → cleanup → type inference →
  promotion → struct synthesis → emission.
- **`components/`** — the disassembly view is `DisassemblyView.tsx` (orchestration),
  `DisassemblyRows.tsx`, `DisassemblyToolbar.tsx`, `InsnContextMenu.tsx`. All four dialogs go
  through one `Modal.tsx`; its class composition, focus arithmetic and `accidentalDismissAllowed`
  are pure functions in `modalScaffold.ts`.
- **`hooks/`** — state (`usePEFile`), derived state, rows, search. `useDisassemblyKeyboard.ts` and
  `useGraphSearch.ts` are seams extracted from `DisassemblyView`. Pure leaf modules
  (`asyncMetricState.ts`, `decompileTabsState.ts`, `modalScaffold.ts`, `listboxIds.ts`) exist so
  hook logic can be tested without a DOM or a worker.
- **`workers/`** — **two** workers, and the split is not tidiness: the disasm worker services
  messages **serially**, so a checksum posted to it queues behind a multi-minute disassembly.
  Disasm: `disasm.worker.ts` / `dispatch.ts` (the RPC switch, extracted so it is importable under
  vitest) / `disasmClient.ts`. Metrics: `metrics.worker.ts` / `metricsDispatch.ts` /
  `metricsClient.ts`, stateless. Shared: `transfer.ts` (`prepareBinaryArgs`), `blobSource.ts`
  (`WeakMap<ArrayBuffer, Blob>`), `requestTimeout.ts` (`REQUEST_TIMEOUT_MS`, `WorkerTimeoutError`).
  Both clients build their `Worker` in a private `ensureWorker()` called inside `send`'s own `try`,
  so with no `Worker` the *request* rejects instead of the caller throwing — which is what makes
  `DisassemblyView` mountable under jsdom.
- **`analysis/`** — driver detection, anomalies, IOCTL decoding. `isPlausibleIOCTL` is a *shape*
  test most 32-bit values pass, so decoding also requires the call site (`ioctlCodeArgIndex`);
  without that gate the emitter produced 1475 confident wrong IOCTL comments.
- **`llm/`** — `models.ts` is the single source of model IDs and token budgets — **never write a
  model ID anywhere else**; `client.ts` (`streamChat`), `prompt.ts`, `settings.ts` (profile store,
  `hasApiKey()`), `retry.ts` (backoff, `RequestLimiter`). `LLMTask` is `chat | enhance`.
- **`ghidra/`** — REST client for the optional server in `ghidra-server/`; powers the decompile
  panel's **High Level** tab. Not a decompiler.
- **`mcp/`** — MCP server (tools, resources, session, Capstone wrapper), `cli.ts`, `clients.ts`,
  `paths.ts`.
- **`utils/`** — recent files (IndexedDB), export schema, entropy, fuzzy match.

## Architecture

**State**: `useReducer` + React Context in `src/hooks/usePEFile.ts`. `AppState` and an `AppAction`
discriminated union; access via `useAppState()` / `useAppDispatch()`. New state = add an action to
the union, handle it in the `appReducer` switch. **Counts drift — re-measure rather than trusting a
number, and count the union by unique `type: "…"` string, not by `| {` lines** (six members span
several lines, which has produced a 6-short re-measurement twice).

`appReducer` is covered branch-by-branch in `src/hooks/__tests__/appReducer.test.ts`. **Two
invariants that suite pins**: a no-op branch returns the **same object reference**, and every
mutating action **replaces** rather than mutates (annotation undo/redo snapshots hold direct
references, so an in-place mutation corrupts history retroactively).

**`VIEW_TABS` (in `usePEFile.ts`) is the single declaration of the eight view tabs and their
order**, with labels from `VIEW_TAB_LABELS` (`components/analysisNotice.ts`) — a `Record<ViewTab,
string>`, so a missing tab fails the build. `AddressBar`'s tab bar and its 1-8 `TAB_KEYS` map are
derived from it. `parseViewTab()` narrows the `#tab=` URL parameter; do not cast to `ViewTab`.

### Analysis phases and the notice

**`AnalysisPhase` has THREE terminal values besides `"ready"`, and telling them apart is the
point.** The defect class behind all of them is a terminal state that is never entered, leaving a
spinner that can never resolve.

- **`"failed"`** — the analysis chain rejected.
- **`"no-code"` — not a failure.** A PE with no executable section (a resource-only DLL) makes
  `findCodeSection` return undefined; the parse succeeded and every parser-derived tab is
  populated. **Do not relabel it `"failed"`.**
- **`"timed-out"` — a fault, but not about the file.** A **phase, not a flag beside `"failed"`**,
  so `RESET` clears it and the fact cannot outlive its run. The watchdog mints `WorkerTimeoutError`
  (`workers/requestTimeout.ts`) and `analysisRejection` (`analysisNotice.ts`) is the pure function
  App's `catch` reads. Only a *client-side* rejection can be an instance — an error thrown inside
  the worker is flattened to a string by `postMessage`. Its message is recorded **verbatim**,
  without the `"Analysis failed: "` prefix.

**Whether a phase means "still working" is `ANALYSIS_IN_PROGRESS`**, a `Record<AnalysisPhase,
boolean>` read by `StatusBar` and `Sidebar`. It replaced a hand-written phase chain at three sites
— a shape that defaults any new phase to "still analysing". A new phase must fail the build here.
(A fourth such chain in `FileLoader` gated a progress panel that provably could not render; the
panel was deleted, leaving `FileLoader`'s props as `onFile` and `error` alone. Consequence:
`AppState.loading` now has **no reader** and `SET_LOADING` is write-only state, left deliberately.)

**`analysisNotice()` has six kinds, RANKED**: `"unsupported-arch"` → `"no-code-section"` →
`"engine-unavailable"` → `"analysis-timed-out"` → `"analysis-failed"` → `"partial-detection"`. Each
carries **`isFault`**, and **all five render sites read that** rather than testing the kind — each
had spelled `kind === "analysis-failed"` by hand, and the fifth was missed, putting one notice on
screen in two colours at once.

Rank reasoning, the part to preserve: the two **properties of the file** come first (each survives
the engine being fixed); `"engine-unavailable"` next, since its remedy is a reload and `init()` is
watchdogged by the same timer; then the timeout, because a run the watchdog stopped did not fail.
`"partial-detection"` (from `DetectResult.omitted`) is not reported on top of an unsupported
architecture and is *appended* to a failure rather than substituted. `"no-code-section"` lists
populated tabs from `PARSER_DERIVED_TABS` so the prose cannot disagree with the buttons.

**`"analysis-timed-out"` is the one fault kind whose `unavailableTabs` is EMPTY** — `buildAllXrefs`
is the last stage, so a timeout there leaves a complete listing with only xrefs missing. For the
same reason `DisassemblyView` deliberately does not take that kind into its replacement arm.

**`AppState.disasmFailed` is the engine's own session-level fact** (`SET_DISASM_FAILED`, which sets
`error` too). `RESET` carries it across a load exactly as it carries `disasmReady` — Capstone is
initialised once per tab, so a dead engine stays dead (contrast the phases, which must not outlive
their run). App's detection effect must dispatch a **terminal phase** for it, above
`analyzedBufferRef`, for **both** orders (file after death, death under an open file), which is why
`state.disasmFailed` is in that effect's dependency array. The two surfaces that cannot reach the
notice (the tab bar, the panel's early return) are told directly.

### Worker and pipeline

**Pipeline**: File drop → `parsePE()` → detect functions (worker) → hybrid disassemble (recursive +
gap-fill, seeded with jump-table case targets from `seeds.ts`) → build xrefs → extract strings. All
async, phased via `analysisPhase`. The decoder comes from `coffHeader.machine` (`disasm/arch.ts`):
x86/x64 take recursive descent + gap fill, ARM64 the fixed-width sweep.

**Worker**: RPC-style, `src/workers/disasmClient.ts`. The client caches results (disasm, xref —
**not decompile**) and mints the instruction-array tokens the worker's derived caches key on
(`insnsTokens`; **the counter never resets, so a token cannot be reused across files**). **The one
decompile cache is `useDecompileTabs`' `lowCache`, content-keyed by `decompileInputsKey` (all
renames) in `decompileTabsState.ts` — derived at read time like `decompileServerKey`, so there is no
invalidation call to remember.** The client's address-keyed copy, with an `invalidateDecompileCache()`
nothing called, was deleted: a rename changed the request and not the address, so it served
pre-rename C for the session. The `resetStructRegistry` RPC stays. The pipeline's own header name
comes from `funcMap` — the same map the callee names come from — so a rename reaches the header and
every call site by construction (`pipeline.ts` step 7). Whole-file
checksum and entropy go to the metrics worker; inputs under the thresholds in `asyncMetricState.ts`
(256 KiB entropy strip, 1 MiB file metrics) stay synchronous, so ordinary binaries never show a
loading state.

- **`hybridDisassemble` returns the typed xref map with the instructions, so the browser posts
  `buildTypedXrefMap` ZERO times on an ordinary load.** `withXrefs` is **opt-in**, set by
  `disasmClient` alone, so MCP and the `corpus/` harnesses keep the bare `Instruction[]` they
  measure — an absent `xrefs` means "not asked for", not "empty". The seed's bounds half goes
  through **`xrefBoundsKey`**, the one declaration, since a second spelling would silently *miss*.
  `useDisassemblyRows` must hand `hybridDisassemble` the **same two `pe.optionalHeader` numbers its
  xref effect passes**. The plain RPC stays for `disassemble`, MCP and the terminal-phase fallback.
  The test to keep is the **hit** (zero sends), not that two maps are equal.
- **Where a `File` exists it is posted instead of a copy.** A `Blob` is structured-cloneable by
  reference, so posting the original `File` is O(1) at any size. **Only the drop/browse path HAS
  one** — recents return an `ArrayBuffer` and the demo arrives via `fetch()`. `App.tsx` calls
  `registerSourceBlob(buffer, file)` on **both** clients after a successful parse; with no
  registration the buffer is posted as before. Three things not to undo: the result cache stays
  keyed on the `ArrayBuffer`; a Blob passes through `prepareBinaryArgs` untouched; the size check in
  `sourceFor` is a **wiring** check. `extractStrings` takes the same handle and must be **no more
  gated than the buffer arm** — an arch gate added there by symmetry empties the tab the notice has
  just told the user to open.
- **`buildTypedXrefMap` sends `XrefInsn`, not `Instruction`.** `prepareBinaryArgs` walks top level
  only, so every element's `bytes` is cloned as its own `ArrayBuffer` — 26% of the clone is the
  field nobody reads. **The deliverable is the TYPE, not a `.map()`**: `XrefInsn`
  (`functionDetect.ts`) is the consumer's own parameter type, `Instruction` satisfies it
  structurally, and the client's strip is **annotated `XrefInsn[]`, never inferred**, so a new read
  fails to compile instead of reading `undefined` worker-side.
- **A load must not post the whole-section `disassemble` it is about to throw away.** Gated on
  **`!ANALYSIS_IN_PROGRESS[state.analysisPhase]`** — the record, never a hand-written chain —
  computed above the effect and in its dependency array. All four legitimately-no-functions cases
  still reach the fallback (`"ready"` with an empty list, `"failed"`, `"no-code"`, `"timed-out"`);
  gating on `phase === "ready"` withholds the listing from three of them. `disassembling` stays
  **true** across the early return so the pane keeps its spinner.

### Architectures, and refusing one

`archForMachine()` returns `ImageArch = TargetArch | "unsupported"`. `"arm64"` for 0xAA64; `"x86"`
for I386/AMD64 **and for `undefined`** ("the caller never told us", keeping un-threaded call sites
at pre-ARM64 behaviour); `"unsupported"` for everything else. `ImageArch` is a *widening* of
`TargetArch`, so a stage that has only ever run after a supported architecture was confirmed keeps
the narrow type and fails to compile rather than falling through.

**The refusal is deliberately ASYMMETRIC. Do not collapse it into one behaviour:**

- **Throw** from stages whose entire output is instructions — `disassemble`, `hybridDisassemble`,
  `buildAllXrefs`, `decompileFunction`. An empty instruction list looks like a correct answer.
- **Return empty, with `DetectResult.omitted` populated**, from function detection. An ARM32 file
  still yields headers, sections, imports, exports, resources and strings. `mcp/session.ts` guards
  its two throwing calls behind a `decodable` flag for exactly this reason.

**`DetectResult.omitted: DetectPass[]`** names the decoder-fed passes that did not run
(`"call-targets" | "jump-tables" | "thunk-names" | "tail-calls"`) and is **empty when the answer is
whole**. It covers both an unsupported architecture and a null Capstone handle. `DETECT_PASS_LABELS`
is a `Record<DetectPass, string>`, so a wire value cannot reach the screen and a fifth pass fails
the build.

**In every arch dispatch the `"unsupported"` arm must be checked *before* the `"arm64"` arm** —
`dispatch.ts` and `mcp/disasm.ts` end their chain at x86, so testing ARM64 first drops an
unsupported image into x86 and produces a full screen of plausible instructions the file does not
contain.

### Rendering and the rest

**Rendering**: virtual scrolling via `@tanstack/react-virtual`; `DisplayRow` union
(`label | insn | separator | data`) has **exactly one declaration**, the export in
`useDisassemblyRows.ts` — a narrowed structural clone still accepts the canonical rows at the call
site, so a local copy drifts silently instead of failing the build. `DisassemblyView` and `HexView`
are lazy-loaded. **Styling**: Tailwind utilities; runtime font size via a `--mono-font-size` CSS
variable on the app root.

- **No virtualized row may carry a LINEAR SCAN.** `InsnRow`'s tooltip resolves through
  `funcMap.get(addr)`, not `functions.find(...)`; the `functions` prop was deleted from `InsnRow`
  so re-adding a scan is a compile error. `funcMap` is injective by construction, so it cannot
  disagree with the scan it replaced.
- **ONE `ErrorBoundary` PER TAB PANE**, taking a **`label`** (`VIEW_TAB_LABELS[key]`) and offering
  **Try again** beside Reload. A single boundary around `renderMainView()` put every tab behind one
  `hasError` with no recovery but a page reload. **Not clearing on re-render is a decision** — an
  automatic reset retries a deterministic fault every parent render.
- **FOUR CHROME REGIONS have one too**, on a criterion stated once in `ErrorBoundary`'s docstring:
  guard a region exactly when the app is still worth using without it. The `variant` prop
  (`"pane" | "chrome"`) is the mount site saying how much room it has; `"chrome"` is one line and
  offers **no Reload**. Guarded: `Sidebar`, `StatusBar`, `AIChatPanel`, `BottomPanelContainer`.
  **`AddressBar` is deliberately LEFT LOUD** — it owns the global keydown handler carrying
  `TAB_KEYS`, so a boundary removes *both* routes to another tab. `DecompileView` and `CFGView` get
  none: they *are* the pane in the mode that shows them. `main.tsx` still puts none above `<App/>`.
- **The four dialogs use `DialogBoundary.tsx`**, a different class for a mechanism reason: a
  dialog's subtree carries `Modal`'s backdrop, focus trap, scroll lock and Escape, so the ordinary
  card renders undimmed with no way out; and a never-clearing `hasError` would make Ctrl+P silently
  dead for the session. Its fallback is itself a `Modal`; the reset is keyed on the dialog's own
  **closed → open transition**, in `getDerivedStateFromProps`. The boundary is **outside** the
  dialog, not inside `Modal`, because these dialogs run hooks above their own `if (!open) return
  null`. A caught-and-then-closed boundary renders **nothing**. `dialogBoundaryRender` and
  `dialogBoundaryReset` are the pure rules in `modalScaffold.ts`.
- **The command palette is a COMMAND surface, and what a row does is a discriminated union**
  (`ResultTarget`: `navigate | event | action`) closed by a `never` assert. `PALETTE_COMMANDS` is
  the table, with **one `SET_TAB` entry per `VIEW_TABS` member, DERIVED** so no tab name is spelled
  here. **An event a command fires must be one something ALREADY listens for**: the union is derived
  from `PALETTE_EVENTS` and `components/__tests__/paletteEvents.test.ts` reads it back against the
  tree's `addEventListener` calls. Three refusals are load-bearing: `:show-xrefs` is out (it needs a
  `detail.address` and its listener is inside `DisassemblyView`); `RESET` and `CLEAR_PATCHES` are
  out (each discards the user's work and already has an entry point where a confirmation belongs);
  and **no new event was invented**. The 15-per-category cap admits itself with a dimmed
  `role="presentation"` count line — deliberately not a `role="option"`, or arrows would land on it.
- **The view switcher is a WAI-ARIA tablist, and the pattern is all-or-nothing.** `role="tablist"`
  around exactly the eight tabs, each `role="tab"` with `aria-selected`, `id`, `aria-controls` and a
  **roving tabindex that follows FOCUS, not selection**. **Activation is MANUAL**, and *nothing
  handles Enter/Space* — a real `<button>` already fires `onClick` for both. That is a cost
  decision: automatic activation would import and permanently mount both lazy chunks for one sweep.
  `App.renderMainView` renders a **wrapper for every tab** so `aria-controls` can never dangle. Ids
  come from `components/tabIds.ts`. `tabIndex={0}` on the **shown** panel only. The arrows are in
  `docs/keyboard.md` and **deliberately absent from the `?` panel** — every other entry there is a
  *global* binding.
- **A severity's ORDER is declared once, in `components/severity.ts`** — `BadgeLevel`, `BADGE_RANK`,
  `ANOMALY_BADGE`. Its one reader is `HeaderView`'s `AnomalyBanners`, which keeps its own
  `severityConfig` palette (a banner and a table row legitimately differ). A fourth severity fails
  the build as a **two-step chain**: adding to `Anomaly["severity"]` reddens `ANOMALY_BADGE` alone;
  widening `BadgeLevel` to satisfy that reddens `BADGE_RANK` *and* `severityConfig`.
- **`XrefType` (`disasm/types.ts`) and `StatusBar`'s `phaseLabels` are keyed on their unions**, and
  the xref half had to NAME the union first. `XREF_TYPES` is **derived from the chip table**,
  because an array is the one shape that cannot fail the build on a new member. `phaseLabels` is
  `Record<AnalysisPhase, string | null>` with explicit `null` for the terminal phases. Three things
  not to undo: **the three palettes are deliberately NOT merged** (the union is the thing with one
  declaration); the **`?? fallback`s at the five use sites STAY**, since these values cross a
  `postMessage`; and the change is runtime-inert by construction.
- **`floatingClamp.ts`'s `clampFloatingPosition` is the one declaration of where a floating bottom
  panel may be**, and takes **no height** deliberately, since a whole-panel-inside rule pins a panel
  taller than the window. The clamped position is **derived, never written back** — spreading it
  into `poppedOut` replaces the user's stored position with a picture of it.
- **`persistedSizeClamp.ts`'s `clampPersistedSize` is the NEIGHBOURING question** — how large may a
  persisted, user-chosen SIZE be, given the viewport — and is a different function because
  `floatingClamp` anchors on a constant slice of a drag handle where this is *about* the size. Two
  readers: `Sidebar`'s width and `BottomPanelContainer`'s docked height. Three rules: the answer is
  **derived for rendering and never written back**; **when the floor and the viewport cannot both be
  satisfied the FLOOR WINS** (`Math.max(min, …)` outermost — yielding drives the size through zero
  and leaves an element that cannot be dragged back); and **a DRAG is not clamped**, unlike
  `floatingClamp`'s write, or one drag in a narrow window discards a wide preference permanently.
  The two reserves (306px width, 166px height) are **sums of measured element extents**. The
  height's one-row listing floor is a **blocked alternative**: any reserve above 168 reddens
  `BottomPanels.dom.test.tsx`.
- **`Sidebar.tsx` is a flex column with ONE `flex-1` child, the function list, and nothing whose
  height follows the CURSOR may sit above it.** The Call Graph block is below the list, bounded at
  160px with `maxHeight: 40%`, its own scroller and a resize handle. Two things there are **not**
  copies of `BottomPanelContainer`'s: the wrapper takes **no `shrink-0`** (it competes with four
  content-sized siblings), and the list carries a **`min-h-[120px]` floor** (a `flex-1` scroll
  container's automatic minimum is 0, so all negative free space landed on it).
- **The ANNOTATIONS block sits ABOVE the list and is BOUNDED — two separate judgements.** Its height
  follows USER EDITS, not the cursor, so its placement is permitted; unbounded growth is not. It
  carries `maxHeight: min(180px, 30%)`, a **CEILING rather than a height** (unlike the Call Graph's,
  which is resizable and persisted), **no `shrink-0`**, and a body that is `overflow-auto` but
  deliberately **NOT `flex-1`** — which is what keeps `[data-panel="functions"]` the FIRST
  `.flex-1.overflow-auto` in the document as a property rather than a coincidence.
  **`sortedAnnotations` is not decoration**: `Object.entries` returns integer-like keys in numeric
  order only for array indices, and an x64 image base puts every address past 2^32 - 1. **The
  BOOKMARKS BLOCK IS STILL UNBOUNDED**, a known deliberate asymmetry left for the user to decide.
- **`ResizeHandle.tsx` guarantees `onResizeEnd` runs AFTER the resize it describes has committed**,
  and that is why its four callers may read their own state in it. The mouse path always could; the
  keyboard path called both callbacks inline, so **three of the four callers persisted a step behind
  on every arrow press**. The keyboard step is deferred by one microtask; the mouse path is
  deliberately untouched. **Do not "simplify" that back to an inline call, and do not re-add a
  per-caller ref** — the contract is asserted once, in `panelUtilities.dom.test.tsx`, with a harness
  that is deliberately the naive state-reading caller. A `vi.fn()` cannot see this class. Its
  duplicate in `Sidebar.tsx` (the width grip) is **deliberately not consolidated**: the two
  arithmetic forms differ at the clamps (absolute-offset recovers, accumulated-delta flies to max).
- **A cursor-following filter must fall back VISIBLY** — the opposite direction from the `omitted`
  rule. `XrefPanel`'s `scopeAvailable()` is the one declaration of "has the caller given this panel
  the address this scope needs", read by the filter chain *and* the scope buttons, with
  `effectiveScope` what everything on screen reads (`scopeMode` is the preference and may outlive
  its address). The fallback is **derived, not written back**.
- **`AddressBar` is the app's first responsive code, and what made it CLIP is that nothing in it can
  shrink** — ~20 single-word items, fixed SVGs and a definite-width `<input>`, so `min-width: auto`
  is min-content == preferred width. It sits **outside `<main>`**, in a column whose `body` is
  `overflow: hidden`, so overflow was clipped away rather than scrolled to. The fix is `flex-wrap`
  plus exactly ONE shrinkable item, the address field (`flex-1 min-w-24 max-w-48`). Two breakpoints,
  both Tailwind 4 defaults: **`2xl` governs tabs inline vs. their own row**, **`lg` governs dividers
  shown vs. hidden**. Keep the two concerns separate. **The tablist is the container's FIRST element
  child, a FOCUS-ORDER decision** — `order-last` moves the box while focus walks DOM order.
  **`min-w-0` on the tablist is load-bearing**: `basis-full` leaves zero free space, so
  `min-width: auto` would floor the strip at min-content and overflow. Nothing is conditionally
  unmounted — **CSS only** — because bare `G` focuses the address input by ref and the hidden Import
  `<input type="file">` is why `focusableWithin()` filters on `offsetParent`.
- **`StatusBar` is the other bar outside `<main>`, and what it crowded off its right edge was the
  ANALYSIS NOTICE** — its last child, i.e. the one place the strip says the analysis failed. `hidden
  2xl:inline` on the two largest fields (`insnBytesStr`, `blockStr`) recovers ~518px; both are the
  only fields whose fact is on screen elsewhere. **`2xl` and NOT `lg`**, which buys a clean layout at
  no width at all. Its fields **can** shrink (wrappable text), so the old bar shrink-wrapped rather
  than clipping. `h-5` is deliberately untouched. A **`VA:` field** was added ahead of `RVA:`/`File:`.
- **`flex-wrap` is the house answer to a crowded toolbar** and five rows carry it — `HexView`,
  `XrefPanel`, `AddressBar`, `DisassemblyToolbar`'s section-header bar and `BottomPanelContainer`'s
  tab strip. When ranking a new instance, ask which side of `<main>` it is on first: inside it,
  overflow becomes a page-level horizontal scroll (bad); outside it, controls are unreachable by any
  input (worse). Accepted trades: `DisassemblyToolbar`'s `flex-1` spacer stays on line 1, so a
  wrapped search box left-aligns on line 2.
- **CFG**: `buildCFG()` + `layoutCFG()` (dagre) in `src/disasm/cfg.ts`; inline graph toggled with
  Space. **THE BROWSER BUILDS ONE CFG AND LAYS IT OUT ONCE**: `useDisassemblyRows`' `cfg` memo is
  the only `buildCFG` call site and `DisassemblyView`'s `graphLayout` memo the only `layoutCFG`;
  `CFGView` takes `layout` and `funcAddress` as props. Three things not to undo. The shared memo must
  **NOT** inherit the `loops` memo's `typedXrefMap.size === 0` guard — real behaviour for the linear
  view's loop markers, but on the shared build it renders **nothing** between the disassembly
  arriving and `buildAllXrefs` finishing. `fontSize` is read during render in both components and
  neither subscribes, which is what makes the two calls in one pass agree. `graphLayout` is gated on
  `viewMode === "graph"`, so linear mode runs no dagre.
- **The decompile panel's ADMISSIONS ARE DATA, and a pipeline fault is a FAULT STATE.**
  `DecompileAdmissions` (`decompile/emit.ts`) is three arrays of **0-based line indices** into the
  emitted C — `unrecovered` (a use of `__unrecovered_N`, declarations excluded), `unlifted`
  (`/* unlifted: … */;`), `gotos` (whole-line or a one-lined guard's body) — read off the FINAL lines
  **after `placeGotoLabels`** by one declared pattern per admission beside its emit site
  (`UNRECOVERED_USE`/`UNRECOVERED_DECL`, `UNLIFTED_LINE`, `GOTO_ADMISSION_LINE`, all built from the
  spelling the emitter itself uses), so the counter and the emitter cannot disagree. Lines, not
  addresses, because `lineMap` is many-to-one and the declaration block has none. Plumbed
  `EmitFunctionResult` → `DecompileResult` → `dispatch` (as-is) → `disasmClient` → `LowCacheEntry` →
  `TabState.admissions` (set by the low tab's `LOAD_OK` only — which is what makes it a Low Level
  affordance as a property of the state) → `DecompileView`'s header line, `N unrecovered · N
  unlifted · N goto`, each a button scrolling to the first site through the same `scrollToLine` the
  `loc_` follow uses. **A `struct_N` token follows to its typedef the same way** (`structLines`,
  `/^struct (struct_\w+) \{/` over the rendered text, first occurrence wins, above the `onNavigate`
  guard like `loc_`); **struct/field RENAMES ARE REFUSED** — `struct_N` is a `nextId++` reset per
  file, so a name persisted under it lands on a different struct next session. **Copy carries the
  comments as ` // <first line>` trailers** through `codeWithComments` in `decompileTabsState.ts`,
  which owns `formatComment` too — ONE declaration for screen and clipboard; the string is built
  before `copyText` is called; Shift-click copies raw (title `Copy (Shift: without comments)`); on
  the AI tab (`syncDisabled`) it is raw with the plain title, since that line map numbers a
  different body. **An in-section hex constant is a link**, grounded by `classifyAddress`
  (`components/classifyAddress.ts`, beside `parseBranchTarget`'s home): `"code"` → `onNavigate`,
  `"data"` → `onNavigateData` (`SET_ADDRESS` + `SET_TAB "hex"`; `HexView` follows
  `currentAddress`), `null` for a value in NO SECTION — inside the image is not enough (headers,
  alignment gaps), so `0x10` in `var_8 + 0x10` stays a plain number; the link class is applied
  in the `lines` memo from the same classifier the click asks. **A `sub_` token's hover is the
  recovered signature** via `subTitle(addr)` → `funcMap` → the cached `getSigForFunc` →
  `formatSignature` (`disasm/signatures.ts`), the ONE spelling `DisassemblyRows`' label row also
  reads. **`admissionSummary` in `decompileTabsState.ts` owns count and wording
  together** (the `matchSummary` precedent). MCP `decompile_function` returns `admissions` beside
  `lineMap`. **`corpus/emitAudits.ts` keeps its own text scans** — an audit reading the field stops
  being independent. `DecompileResult.error` is the fault: the pipeline's `catch` used to return
  `// Decompilation error for …` **as code**, so a failure reached MCP as a successful response
  holding a comment; now `code` is empty and `error` set, `disasmClient` **throws** it into the
  hook's existing `LOAD_ERR` banner, MCP returns `err(...)`, and `corpus/sweep.ts` counts
  `pipelineErrors` beside `throws` (a class the sweep's "0 throws" was blind to). `// <name>: no
  instructions found` stays as code — a detection admission, not a pipeline fault. `DecompileView`
  still takes no `ErrorBoundary`; no new custom event.
- **AI features**: two tools — Chat (`useAIChat`) and Enhance/Explain in the decompile panel's **AI**
  sub-tab (`useDecompileTabs`) — both via `streamChat()`. **Neither keeps state in `AppState`.** The
  only AI custom event left is `peek-a-bin:open-chat`. Markdown via `marked` in
  `MarkdownRenderer.tsx`. Both are gated by `hasApiKey()`, which bounces to Settings with no message.

## Conventions

**File naming**: components = PascalCase.tsx, hooks = useCamelCase.ts, modules = camelCase.ts.

**localStorage**: `peek-a-bin:<feature>` namespace (`:llm-profiles`, `:font-size`, `:view-mode`,
`:chat:${fileName}`, `:chat-width`, `:callgraph-height`). Legacy `:llm-settings` auto-migrates.
`:report:${fileName}` is orphaned and **deliberately unmigrated** — a prefix-scanning deleter on the
load path is a foot-gun to reclaim a few KB.

**ANNOTATIONS ARE KEYED ON THE BUILD, NOT ON THE FILE NAME**, and `utils/annotationKey.ts` is the
one declaration of both that key and its migration:
`peek-a-bin:annotations:<size>-<timeDateStamp, 8 hex>[-<CodeView PDB GUID>]`. It fixed **the only
place in this app where a user silently lost work** — the key had been `peek-a-bin:${fileName}`, so
two builds under one name shared a record and the same build renamed on disk lost everything; it was
also a flat namespace shared with ~18 settings keys. `fileName` moved **into the stored value**.
Migration is one-time, on load, and **leaves the legacy key where it is** (idempotent, on
`:report:`'s precedent). The metrics-worker content hash was **REFUSED**: it makes annotation load
async, so a rename made while the digest is in flight is written under the wrong key or lost.

**`recentFiles.ts` (IndexedDB) is keyed on the SAME composite string.** Its store was
`keyPath: "name"`, so opening `v2/setup.exe` **silently evicted** `v1/setup.exe`. It uses
`buildKey(id)` now — the identity split out of `annotationKeyFor`, which is
`ANNOTATION_KEY_PREFIX + buildKey(id)` — so there is one composite-key rule and the join from a
cached file to its bookmarks is exact. The prefix is deliberately **not** carried into the IndexedDB
key. `RecentFileEntry` carries a `key`; `FileLoader`'s list key, loading flag and remove button all
route on it (a `key={f.name}` reconciles two builds as one row), and removing a row deletes **that
build's** annotation record via `removeAnnotationRecord`. **A build-keyed row with no record of its
own shows NOTHING** — a `??` chain to the name join hands a sibling build's bookmark count to an
unannotated row. **The v1 → v2 upgrade carries records forward under a `name:` key rather than
re-deriving a real one**, deliberately: re-deriving means running `parsePE` up to five times inside
a `versionchange` transaction, and a throw there leaves the user with no recents at all. Such rows
age out of `MAX_ENTRIES` on their own. `migrateV1Record` is the pure decision; wiring is tested
against `src/utils/__tests__/fakeIndexedDB.ts`, since jsdom has no IndexedDB.

**`hexPatches` IS NOT AUTO-PERSISTED, AND THAT REFUSAL IS THE DESIGN — it is guarded instead.** A
byte patch is a byte of the **file**, held only in memory. **It is not unpersistable**:
`utils/exportSchema.ts` serialises it and Import restores it — a *deliberate* channel.
Auto-persisting is refused four ways, the last being that a restored patch makes a file **silently
disassemble differently on reopen**. So `AddressBar.tsx` carries two guards over
`state.hexPatches.size > 0`: a `confirm` on Open naming the count and pointing at Export, and a
`beforeunload` registered **only while a patch exists**. Any new "Close file"/`RESET` command must
route **through** `handleReset`. `confirm` is spied **file-wide** in `AddressBar.dom.test.tsx` —
jsdom's unstubbed `window.confirm` returns `undefined`, so an unspied row silently stops dispatching.

**Custom events**: `window.dispatchEvent(new CustomEvent("peek-a-bin:<action>"))`. **Dispatching one
nothing listens for is silent**, so the command palette may only name events from `PALETTE_EVENTS`.
Adding a palette entry is not a reason to add an event.

**Annotations**: bookmarks, renames and comments auto-persist to localStorage per file; undo/redo
via a snapshot stack.

### Tests

Suites sit beside what they cover (`src/pe/__tests__/`, `src/disasm/__tests__/`, etc.). Use
`buildMinimalPE32()` / `buildMinimalPE64()` from `src/pe/__tests__/fixtures.ts` — **no binary
files**. **Don't hard-code a test count anywhere; it goes stale within a session.**

`src/disasm/decompile/__tests__/pipeline.test.ts` is the **end-to-end** one: instructions in,
emitted C out. `decompileFunction` takes `Instruction[]`, so it needs neither Capstone nor a worker.
**Reach for it whenever a change could alter emitted output** — a whole class of defect is invisible
to stage-level tests, which assert on the IR the buggy code produced.

**Component tests are the `*.dom.test.tsx` files and the ONLY ones that render React.** Each opts in
with the `@vitest-environment jsdom` marker in a `//` comment on the **first line** and
`import "…/test/domSetup";`. `build/domTestNaming.test.ts` fails the ordinary suite if either is
missing. Three things to know, all measured:

- **`test.projects` — the documented Vitest 4 replacement for `environmentMatchGlobs` — BREAKS
  `--dir`.** The CLI flag is not propagated into project configs. It was implemented and reverted.
- **A global `setupFiles` entry costs ~3s**, because vitest loads it once per test file. Hence the
  per-file import.
- **`@vitejs/plugin-react` is NOT used and is not needed** — Vite transforms `.tsx` with esbuild
  reading `jsx: "react-jsx"`; the plugin only buys Fast Refresh and Babel.

**Writing a component test has four traps, all measured:** (1) **`waitFor` and `userEvent` both
deadlock under `vi.useFakeTimers()`** — drive a debounced control with `fireEvent.change` and
advance the clock inside `act()`. (2) **Advance SHORT of a debounce first**, or a single advance past
the boundary cannot tell a 250 ms debounce from no debounce. (3) **React caches its key warning PER
OWNER COMPONENT**, so the guard must be a file-wide `beforeEach`/`afterEach`. (4) **`target: "window"`
cannot be discriminated behaviourally in jsdom** — assert on which global receives which listener.

### Drift guards

Several suites **scrape source text** rather than call it (the `.disasm(` scan, the MCP import
graph, the `dispatch.ts` purity check, `keyboardShortcuts.test.ts` against `docs/keyboard.md`).
Cheap, and they catch a whole class of silent regression, but **they encode formatting by accident:
write the pattern so a reformat cannot break it.** `build/guardShape.test.ts` is the same family
used against itself. Sturdier variants read *structure*: `analysisNotice.test.ts` asserts the
**order** of two regex matches; `hooks/__tests__/disasmHandlerDeps.test.ts` walks the TypeScript AST
and fails if `handleKeyDown` grows a read without a dependency entry or an entry without a read;
`build/lintConfig.test.ts` parses `biome.json`.

**An audit needs a liveness half — a rule that reaches 0 by no longer looking is this repo's
recurring failure mode.** `DOC_ONLY_KEYS` (`keyboardShortcuts.test.ts`) now has **three
directions**: doc→panel, every exemption must name a key the doc still documents, and **no entry may
name a token `SHORTCUT_GROUPS` binds**. The third was measured: binding Home/End left the guard
135/135 green with both exemptions claiming keys that by then had bindings. `"left"`/`"right"` stay
exactly as they are.

**Two AST guards pin the threshold-and-worker pattern and fail in OPPOSITE directions** —
`analysis/__tests__/anomalyOffThread.test.ts` (dropping the anomaly threshold puts multi-second
walks on the main thread) and `hooks/__tests__/fileMetricsOffThread.test.ts` (dropping the metrics
one puts a worker round trip on every *small* file). Both assert which **side** of the size
comparison each callback sits on, so an *inverted* guard fails too. Their helpers are deliberately
duplicated: `useFileMetrics.ts` has no `if` statement.

**Hook logic is otherwise tested by extracting the decision into an exported pure function**
(`parseAnnotationMessage`, `modalScaffold.ts`, `listboxIds.ts`, `asyncMetricState.ts`,
`decompileTabsState.ts`) or by checking a dependency array against the body over the AST. Prefer
that: a jsdom test costs ~2s of environment setup per file.

**MCP setup CLI**: `npx tsx src/mcp/index.ts setup <client>` (claude-code, opencode, continue).
Registry in `src/mcp/clients.ts`. `.mcp.json` enables Claude Code auto-discovery.

## Verification status

**Full record: [`docs/verification.md`](docs/verification.md)** — every per-binary figure, every
per-change delta, every negative-control enumeration. This is the working summary; go there for a
number. Every suite in `src/` is synthetic; real binaries (PE32, PE32+, ARM64 MSVC output) are
driven only by the `corpus/` harnesses.

### Standing rules for reading anything here

- **Treat the ratio as the claim and the absolute as a date-stamp.** Every denominator moves
  whenever function detection changes. A number going stale is normal; a ratio falling below 1, or a
  gate leaving 0, is not.
- **Anyone quoting a bare historical figure is probably quoting a fixed defect or a stale count.**
  Do not argue from a number without its commit.
- **Pin BOTH sides of a comparison to one commit.** `npm run corpus:compare` takes artifact *paths*.
- **Stamp every count recorded in a bead with the commit it was taken at.**
- **A missing corpus directory SKIPS and still exits 0** — confirm the report header names **four**
  binaries. That is why there is no absolute default corpus path; `preflight.ts` searches
  `PEEK_CORPUS_DIR`, a gitignored `.env`, `$XDG_DATA_HOME/peek-a-bin-corpus`,
  `~/.peek-a-bin-corpus`, `<repo>/corpus/binaries`, and `build/corpusPreflight.test.ts` guards it.
- **Every gate is negative-controlled** — perturb the code, confirm the row goes red, and confirm
  the row is also asked over well-formed input. **An INERT control must be reported, not tuned
  away.**
- **A green row over an empty population says nothing.** Most audits carry a liveness half.
- **ARM64 and the Go binary are separate runs deliberately**: the audits iterate over whatever
  binaries they find, so an extra one changes every gate's population and every summed denominator.
  **Never put a Go binary in the corpus directory** — Go's ABI and prologues are not MSVC's.

### What the harnesses establish

The gated runs are `npm run corpus` (four x86 binaries), `npm run corpus:arm64` (**55 gate
assertions, all 0**) and `npm run corpus:parserdiff` (**98 green, 0 red, 20 vacuous**); the
`corpus:*cost` censuses take a path and gate nothing. `corpus/README.md` says what each audit proves
and what a failure means; `docs/verification.md` carries what each is structurally *blind* to,
which is the half worth reading before quoting a green run.

Gates at 0: condition polarity (anchor A only — A2 and B are reported and must not gate), loop
exits, call arity **over**, stale guards, cross-edge guards, stale reads, pop reads, lost defs, arm
exits, unencodable names, **undeclared register and minted names** (`register + minted`, since
`peek-a-bin-n9cl.4`), wild branches, self-assign `wrong`/`unresolved`, frame repurposing,
`signatureAgreement` **over on x64**, member-name agreement, `offsetof` struct layouts (ratio
1.00 — it proves a declaration self-consistent and can **never** see a wrong identity), `distinct callees lost`, emitter
`throws`, and `guard lines unparsed`. Report-only and **not** targets: unrecovered values (a rise
can be a *refusal* replacing a confident wrong answer), dropped statements, `offsetNamedArgs`
(reaching 0 is the wrong target — two opposite changes both reach it), struct overlaps, undefined
callees (watch `internalUnlabelled`, not `internal`), empty case bodies, loop shape, field accesses
reaching the page (it rises with correct recovery *and* with fabrication).

**Nine readability censuses landed as report-only rows ahead of the decompiler-readability epic
(`peek-a-bin-n9cl.1`), each with a liveness half; one has since become a gate**: `undeclared
identifiers` (what `preludeFor` invents, classified register/residue/minted/api/other — **`register
+ minted` GATES at 0 since `peek-a-bin-n9cl.4`**, 1460/2443/2265/1417 → 0/0/0/0 at `2328657`, the
negative control returning 1518/2612/2419/1471; `residue` is the class the emitter refuses to
declare — `stk_`, `tmp_xchg`, `st0`, `xmm` — reported beside it, never inside it); `unlifted
instructions` by base mnemonic (the ONE row
of the group `compare.mjs` judges: a rise in any bucket is a regression); `void returning a value`
(0/3/3/0 at 6299113 — the plan's 48/44 predates the `__try` narrowing; gates in the return-type
child); `stack-pointer scaffolding` by shape; `adjacent copy pairs`; `goto density` (**MUST NEVER
GATE**, three reasons recorded at `gotosPer100Lines`); `duplicate bodies` with
`selfRecursiveThunks` 0/3/3/0 (gates in the thunk child); `label origins` from `pruneLabels`'s own
report (`pinnedOnly` is the `baseGenerations` fabrication-hazard population); and `callees that are
not names` beside the x64 `[rsp+0x20..]` store-before-call population. `corpus/README.md` carries
the baseline figures and what each cannot see.

**"Clean" is not "recovered".** A large minority of emitted functions contain an *admitted* gap —
`__unrecovered_N` or `/* unlifted: … */` — and compile precisely because the emitter names what it
failed to recover. Do not read "all of them compile" as "all of them are right"; gcc is
structurally blind to wrong register names, call arity, undeclared identifiers and undefined
callees, because `preludeFor` completes them.

### Not verified. Say so rather than implying otherwise

- **No human has looked at this branch in a browser.** `peek-a-bin-v2u` is the checklist; ~15
  minutes with the app open closes more risk than any further static work.
- **jsdom is NOT a browser.** No layout, so nothing about geometry, overflow or visibility;
  `offsetParent` is a constant `null` supplied by a stand-in the focus trap depends on; no browser
  focus algorithm, no screen reader, no service worker. **A row in the document is not a row on
  screen.** Every responsive rule above (`hidden`, `flex-wrap`, `basis-full`, `min-w-0`,
  `overflow-x-auto`) is a **class-string contract** — Tailwind is not loaded under vitest — and
  every breakpoint figure is **computed from a 0.6em monospace advance, never measured**.
- **Virtualization is a STAND-IN.** `virtual-core` reads `offsetHeight`, so a virtualized list
  renders **zero** rows in jsdom; `domSetup.ts`'s `stubLayoutRect()` makes every element report one
  600px rect with `scrollTop` pinned at 0. Which rows are windowed, whether `overscan` is right and
  whether anything is visible all stay unanswered — measured: `estimateSize` 28 → 280 and `overscan`
  20 → 0 both leave `ExportsView`'s suite green.
- **Every drag is verified as arithmetic, never as motion.** Both persisted-size clamps are verified
  as arithmetic and as wiring, and **as layout not at all**. What *is* covered end to end is
  `ResizeHandle`'s post-commit guarantee, on both paths, from the caller's side.
- **Render COUNT is measured; render COST is not.** Exactly two full-tree renders per cursor move,
  negative-controlled. Whether that is *slow* needs the Profiler on a real binary in a real browser.
- **Nothing has crossed a real `postMessage`** — `structuredClone` in one process stands in, so
  every payload figure is an upper bound; the Blob hand-off is verified for **equivalence**, not
  speed. The request watchdog has fired end to end but **never on a real file**, so the budget's
  calibration is extrapolation.
- **The a11y work has never met a screen reader**, and the clipboard's absence has never been
  produced by a browser (it is manufactured by replacing `navigator`).
- **ARM64 is measured only as far as instructions, boundaries, references and tables.** No ARM64
  semantics: no decompilation, IR, emitted C, guard, type, struct or call arity has ever been
  judged. There is no general ARM64 data-marking pass; import thunk naming is gated on a population
  of **one per image**; epilogue unwind scopes are unaudited; the `bl` call graph is counted, not
  verified; and no A64 disassembly has been seen on screen.
- **There is no ARM32, ARM64EC or ARM64X binary on this machine.** Those paths are fixture-only and
  the machine-type claims are settled from **documentation**, not from a file.
- **A real x64 PE with jump tables can be built here and the tool recovers NONE of them** — measured
  harm exactly zero (every base is in `.rdata`, so the gap fill never reaches it). The dense
  two-table reader has never run on a real image. Reopening the register-base reader needs **new
  evidence**, not a re-reading of these facts.
- **MCP → browser WebSocket annotation sync has never been exercised end to end**; the nginx headers
  and the CSP have never been exercised in a browser; `@vitest/coverage-v8` is not installed.
- **The token-budget table has no discriminating runtime test** (both budgets are 16384), and
  `modalScaffold.test.ts` passes over branches no code path can reach — three of four rows,
  measured. Both are recorded rather than repaired with invented values.

When a UI or deployment change lands, the honest report says which of these it did *not* move.

## Decompiler Architecture (`src/disasm/decompile/`)

**Full record: [`docs/decompiler-ir.md`](docs/decompiler-ir.md)** — the complete dispatch census,
the struct-grouping history, and the measurements behind every rule below.

**Pipeline** (`pipeline.ts`): `buildCFG → liftBlock → liftCrossBlockPops → buildSSA → ssaOptimize →
destroySSA → foldBlock → structureCFG → cleanupStructured → wrapExceptionRegions → inferTypes →
promoteVars → synthesizeStructs → emitFunction`. (`wrapExceptionRegions` is local to `pipeline.ts`
and only runs with `.pdata` exception info. **The docstring at the top of `pipeline.ts` lists a
shorter, outdated order — trust the code.**)

**IR** (`ir.ts`): `IRExpr` (12 kinds) + `IRStmt` (18 kinds including `branch`).

**`branch` is confined to `liftedBlocks` and never appears in a structured tree — but its
*condition* does, and `structureCFG` takes it as a sixth argument.** Two orderings are load-bearing:
the extraction runs **before the tap snapshot** (or the statement-drop audit reports every branch as
a dropped statement), and the branches must not survive into the tree (`detectForLoop` skips any
body block whose last statement is not an `assign`, so one left in place takes for-loop recognition
to **zero corpus-wide**, silently). `structureCFG`'s **seventh** parameter is an observer of how
`structureSwitch` closed each arm — an instrument, which must never change what the other six
decide. `emit.ts` therefore *throws* on a branch rather than ignoring it. **Anything appending to
another block's statement list must go through `pushBeforeTerminator`.**

### Adding new IRExpr / IRStmt kinds

Adding a kind means updating every switch dispatching on `expr.kind` / `stmt.kind` — dozens — and
**a missed one silently drops data rather than failing. Only NINE are compiler-caught.** Get the
current number by measurement: add a throwaway kind, run `npm run typecheck`, count the
`not assignable to type 'never'` errors. **The tables in `docs/decompiler-ir.md` are accurate about
every site they name but do not name them all — grep as well as read.** The dangerous tier is the
switches with neither `default:` nor a `never` assert (`ir.ts`'s `walkExpr`/`walkStmts`,
`ssaopt.ts`'s `canonicalizeExpr` and two walkers, `structs.ts`'s `walkExprs` and one walker), plus
two if-chains that are not switches at all (`foldExpr`, `countExprUses`) — grep the function name,
not `case`. Two sites are not dispatches: `detectForLoop` and `cleanup.ts`'s `endsWithTerminator`
read a block's **final statement's kind**, so a new terminator-shaped kind changes loop shape rather
than dropping data.

**Type system** (`typeInfer.ts`): a `DecompType` lattice of 12 kinds; `meetTypes()` merges, specific
over unknown and handle/ntstatus/hresult over int/ptr. `enum` carries a name and members,
synthesized from switches with 3+ cases.

**API signatures** (`apitypes.ts`): **209** Win32/NT signatures, **none variadic — which is what
makes the table usable as `corpus/arity.ts`'s arity oracle.**

**Struct synthesis** (`structs.ts`): `StructRegistry` is cross-function state shared in the worker;
**don't clear it between functions in the same session.** `decomposeAddress()` breaks
`base + idx*scale + offset`. 2+ distinct offsets on one base → struct candidate.

- **Escaping struct defs are snapshots; registry-internal ones are live.** `synthesizeStructs`
  clones into `IRFunction.typedefs`, so a returned declaration cannot change later. Inside the
  registry the objects stay shared and inference mutates `field.type` in place — that **is** the
  cross-function refinement mechanism, so do **not** clone in `findOrCreate` or `get`.
- **Merging is shape-based but guarded.** An exact `offset:size` fingerprint merges unconditionally;
  the subset path needs 3+ fields and no boundary conflict. Failing to merge is the benign
  direction. **Provenance beats shape**: `findOrCreateLinked` merges two bases occupying one
  parameter slot and ignores the field minimum, but cannot override `hasBoundaryConflict`.
  `paramLinks` and `paramViews` are kept apart on purpose.
- **A field's NAME is the other half of its array claim, and `fieldNameFor` is the only declaration
  of the rule** — `emit.ts` reads *only* the `isArray` flag when it spells `[...]`, so anything else
  setting that flag must go through `fieldNameFor` or emit a declaration contradicting itself.
- **One register is not one object: a base is keyed on the VALUE it holds, not on its name.**
  `accessKey` is `canonBase(expr) + "#" + generation`; `canonBase` stays register-level for
  `stackDerivedBases`, `paramIndexByBase` and `collectCallArgSlots` (which register is a frame
  pointer is a fact about the *name*), and every access-side pass takes `accessKey`. **DO NOT DELETE
  THE LABEL RESET** — it scores higher on field counts and **fabricates**, the exact defect the
  generation key exists to fix, and `structOverlaps` is blind to it in both runs. A stride walk must
  keep grouping, or nothing is recovered from any array-of-struct walk.
- **Emitted struct definitions are `#pragma pack(1)` with explicit `_pad_0xNN` members**, and the
  two are inseparable — padding alone cannot express an unaligned recovered offset. A field no
  padding can place is reported in the struct body rather than declared somewhere convenient.

**A call takes an assignment only when its result is live out of the call**, from a backward pass
over the **structured** body. Where the only reader is the very next `return`, the two lines print
as one — `foldReturnedCallResults` is `emitFunction`'s **FIRST** act, and that ordering is its
safety: both `collectCapturedCalls` and `collectAssignedRegs` are asked about the *folded* body. The
folded line keeps the **CALL's** address.

**emit.ts module-level `_typeCtx`**: set before emission, cleared after. Enables cast suppression and
type-aware idioms (INVALID_HANDLE_VALUE, NT_SUCCESS, SUCCEEDED/FAILED).

**REGISTERS ARE DECLARED VARIABLES: one C variable per canonical register per function, at emit**
(`registerVariables`, `emit.ts`, `peek-a-bin-n9cl.4`). Until then every register reached the page
undeclared, one free variable per *name*, so `dx` and `edx` were two C variables for one machine
register — t64's `wcslen` assigned `edx` and tested `dx`, a loop that as C could not end — and
`cc` read 1072/1072 clean only because `corpus/emitAudits.ts`'s `preludeFor` invented a `long`
per name (979/1072 functions, 7,519 pairs). The rule: the variable is named for the **widest alias
the body mentions, capped at the image width** (`regAtSize(canon, 4)` when `!IRFunction.is64` —
the cap is what keeps the PE32-only `unencodableNames` gate at 0, and a red row there is the cap
*catching* a canonical-name leak, never a reason to loosen it); typed `sizeToType(width)`, refined
from `typeCtx.types.get(canon)` only when the widths agree, so a register is never declared a
pointer and `emitsAsPointer` stays false for it. A narrow **read** is `(uint16_t)edx` (high byte
`(uint8_t)(eax >> 8)`); a narrow **write** puts the truncation IN the expression — `rax =
(uint32_t)(e)` for a 32-bit write on x64 (zero-extension, SDM) and `eax = (eax & ~0xFF) |
(uint8_t)(e)` for 8/16 bits — through `narrowRegisterWrite`, decided first in the `assign` and
`call_stmt` arms. Every non-param/local `IRVar` the body names is declared too (`rcx_0`-style
split repairs; `clobbered_<reg>_<n>` uninitialised, which is the indeterminate it denotes).
**Counted and NOT declared**: `stk_*`, `tmp_xchg`, `st0`, `xmm*` — the audit's `residue` class.
`IRFunction.is64` is set by `promoteVars` from the pipeline's own flag — **never** inferred from
the body the way `registerSpeller` infers its (`peek-a-bin-0s6e`'s leak would read as evidence).
`_assignedRegs` and `registerText`'s alias search are gone; the register stays the **prefix** of
every spelling, which `corpus/selfAssigns.ts` relies on. The declaration block is the lines
between the header and the first blank line, and `corpus/emitAudits.ts`'s `stripDeclarationBlock`
is the one declaration of that shape for every text scan that counts *mentions*.

## Gotchas

**Full record: [`docs/gotchas.md`](docs/gotchas.md)**, same entries in the same order — how each
defect was found, what it emitted, the measurements, the negative controls, and the alternatives
refused. **Read the long-form entry before changing the code it describes.**

### Decoder and workers

- **Nothing may call `cs.disasm` directly.** capstone-wasm's linear memory is a fixed 16 MiB, the
  input is copied onto a ~65.6 KiB stack, and a window much over 64 KiB throws and leaves the module
  **permanently dead** — silently, because every scan loop reads a throw as "not code, skip one".
  `createScan` clamps to `CS_WINDOW_BYTES` (0x2000) and `CS_MAX_INSNS_PER_CALL` (2048) and probes
  the engine after a run of failures. **Lifting the ceiling for speed was measured and refused**
  (0.035%). The `cs_insn` ABI in `capstoneReader.ts` is **hard-coded and a version bump can change
  it silently** — a wrong offset yields plausible output for every instruction; the both-readers
  differential test is the whole mitigation, and a *runtime* self-check was refused.
- **Don't put a cheap request on the disasm worker** — it services messages serially. That is what
  the metrics worker is for. A `useMemo` is not an option either: it cannot yield.
- **Never put a caller-owned buffer in a worker transfer list, and never walk below the top level.**
  Structured clone of an `ArrayBufferView` serialises its whole backing buffer, so a 4 KiB
  `disassemble` used to copy 253 MiB. `prepareBinaryArgs` replaces each **top-level** binary argument
  with a private `slice()` and transfers **only buffers it allocated itself** — the invariant that
  makes the detach hazard impossible. The walk stays top-level because transferring an
  `Instruction[]`'s per-element buffers is **strongly superlinear**. Slicing wins even when the copy
  is the same size, so there is no threshold below which it is skipped.
- **Uploading the section once under a handle was MEASURED AND REFUSED** — the saving is under a
  tenth of one percent, and no key is both cheap and sound (a content key costs the pass it saves;
  an identity key rests on an invariant nothing enforces). **The general rule: the key comparison
  must be cheaper than the work it saves.** `Arm64SweepCache` and `CallSummaryCache` pass it.
- **Where a payload IS worth cutting, send only what the consumer reads — never worker-side
  residency.** `decompileFunction` sends this function's slice (16-68x cheaper, retention still
  zero); on a miss the **worker asks** (`{ needInstructions: true }`) rather than the client
  predicting. `funcExceptionRecord` applies one **idempotent** rule on both sides, so no protocol is
  needed — its predicate is a **begin-address equality**, not an extent intersection, and it
  recovers the image base from the RVA/VA pair rather than slicing naively.
- **One x86 load swept `.text` three times**; `linearSweep.ts` is the one declaration. `SectionMemo`
  has **three** parts: bytes, load address, and **decoder handle by identity** — x86-32 and x86-64
  disagree about what a byte string means. `hybridDisassemble` shares it via `gridScan`: **peek,
  never `sweep`** (a `get` evicts the section the other RPCs share), a served `bytes` must be a
  private `.slice()`, a miss delegates, and a run stops where the grid stops being **contiguous**.
- **`detectFunctions` being "13x the next RPC" is arithmetic, not a diagnosis** — it is the RPC that
  fills the cache. Nothing is superlinear. **Almost nothing in detection is worth changing**; the one
  thing taken was the SEH32 prologue head, because the work was provably unread.

### PE parser

- **The attacker-controlled-bound class**: every reader must state what bounds it, whether the
  *work* is bounded or only the reads, whether two file-supplied counts **multiply**, whether
  anything allocates a file-chosen size, and whether it runs on the main thread. Sites swept and
  bounded: PDB path scan, imports (descriptors × thunks — the budget is **global**, since every
  descriptor may name one array), ARM64 unwind codes, debug directory, export tables, relocation
  blocks, `extractStrings`, `readDERChildren`, and `readScopeTable`. `sectionRawLimitForRva` is the
  **one declaration** of the section bound, and it is the bound that improves the *answer*.
- **How a narrowing is admitted depends on its shape.** A **string** carries `TRUNCATION_MARKER`
  in the value. A **list** cannot — an invented entry would be a lie inside data feeding a digest —
  so the admission is a flag plus the rendered **count**, and `computeImphash` **returns `null`**
  rather than hashing a short list (its parameter is the **`PEFile`**, so forgetting to ask is a
  compile error). A **globally-budgeted walk** puts the admission on the count line, not a row,
  because no single entry is "the incomplete one". Every flag is decided **exactly** — control must
  have read past the bound — so a value of exactly the cap is not marked.
- **`Budget.incomplete` means "an entry the file declares was not walked", whatever stopped the
  walk.** Its old name (`stopped`) read as a fact about the budget, so three other abandonment
  points never set it. `depth >= MAX_DEPTH` and a repeat visit deliberately still do not.
- **A directory the file declares and the reader gave up on is NOT a directory the file lacks.**
  `directoryDeclared` / `certificateUnreadable` / `resourcesUnreadable` are derived from what is
  already public rather than being new flags, and `parser.ts`'s resource gate is the **same call** —
  a premise that drifts from the gate claims a read failed on a directory nothing attempted.
- **An admission that stops at the browser UI is no admission at all on the two surfaces that
  outlive the session.** `pe/admissions.ts`'s `parseAdmissions(pe)` is the one declaration for MCP
  resources and the markdown report; **the value is PROSE, not a flag**, because the consumers are
  an LLM and a human reading a file months later. Empty means the parse was whole. The MCP list
  resources moved their arrays **under a key**, unconditionally, since a shape that varies with the
  file is worse to consume than one extra key.
- **A green "Signed" pill is a verified answer's shape, and the parse established only that a
  `WIN_CERTIFICATE` header read.** Nothing here computes a digest, checks a signature or builds a
  chain, so the pill reads `Signed (unverified)` in a **neutral** chip with a grey scope sentence.
  **Expiry is a fact about the CERTIFICATE, never about the signature** (signatures are routinely
  countersigned and this tool reads no timestamp), so it is an amber row that does not move the
  pill. `certificateValidityState` has **three** states — folding an unreadable date in with
  `current` is the green pill's own defect one level down. The view must not re-parse the display
  string: `parseUTCTime`/`parseGeneralizedTime` return `{ text, ms }` from one reading.
- **A Distinguished Name is not its CN, and a PKCS#7 `certificates` SET is not one certificate.**
  `subject`/`issuer` hold the rendered DN in **encoding order**; an attribute with no short name is
  spelled as a dotted OID rather than skipped. `certificateCount` is a **count, not a validated
  chain**. `BMPString`/`T61String` are decoded by hand (`TextDecoder` labels may be absent).
- **`Ordinal_<n>` is a WIRE FORMAT**: `parsePE` writes it and `computeImphash` parses it back, with
  nothing in the type system connecting them, so respelling it silently changes hashes. The view
  resolves through the **same** `resolveOrdinal` and marks the row `#115` because the name is
  inferred rather than read out of the file. `parseOrdinalImport` returns **null**, never `NaN`.
- **A CodeView PDB GUID is a `GUID` STRUCT** — the first three fields are little-endian integers, so
  hex-joining sixteen bytes byte-swaps them. Same class as `Ordinal_<n>`: a value only read *out* of
  the tool, so a wrong spelling matches nothing while looking well-formed. The oracle is real MSVC
  output (the version-4 nibble sits in the swapped group). Beside it, `parseRichHeader`'s `^` is an
  int32 operator, so a stored `0xFFFFFFFF` use count reached the table as `-1`.
- **`>>> 0` on a value that can exceed 2^32 is a TRUNCATION.** Right for `characteristics`, wrong for
  `HeaderView`'s `CopyableHex`, which is handed 64-bit quantities — it printed
  `Image Base 0x0000000040000000` under a correct `Entry Point 0x140001000`. Reinterpret only what
  is actually **negative**.
- **A number the parser CLAMPED and the raw number it clamped mislead as a pair.**
  `dataDirectoryClamp` is derived rather than published, because `dataDirectories.length <
  numberOfRvaAndSizes` **is** the clamp exactly; a parser field would be a second declaration that
  can disagree with the array it describes. It carries a `reason` — "count exceeds the maximum" and
  "the file ends mid-table" are different findings.
- **A derived LABEL must come from the value it labels, and a flag row must admit the bits its table
  does not name.** `decodeFlags` returns the leftover mask and `FlagChips` prints
  `(unknown bits: 0x…)` — deliberately **not** a chip, since a chip means "the format names this".
- **`.pdata` is authoritative for x64 function boundaries and beats prologue scanning.** Evidence
  about an *entry point* still wins inside a range. **The x64 language-specific data is not
  self-describing**, so `readScopeTable` admits a table only behind a four-part structural check;
  `handler == 1` is the format's own spelling of `EXCEPTION_EXECUTE_HANDLER` and must never be
  resolved as an address; a failure yields **nothing rather than a short table**; and `undefined`
  means "the record did not say", never "there are no regions".
- **A hybrid image has TWO exception tables and `pe/pdata.ts` reads the one the machine word
  describes** — right for every hybrid case and incomplete for all of them. **ARM64X carries 0xAA64
  and is refused by decode rate; ARM64EC does NOT — it is marked 0x8664** and is disassembled as x64
  with nothing said, knowingly. 0xA641/0xA64E never appear in a linked image; **do not re-add
  either**. Rests entirely on documentation.
- **A resource LANGUAGE level can be name-identified and must not be flattened to 0** — 0 is a real
  LANGID. `ordinalLabel` is the one declaration of the `#` marker; `keyPart` is a **different
  question** (which rows are the same row) and deliberately not the same function.

### Detection and disassembly

- **A jump-table case target is not a function start.** Adding one to the entry set ended the
  dispatching function at its first case; `buildCFG` then rejected every target as a block leader and
  `structureSwitch` was dead code on real input. Case targets go to a separate set, outrank a
  byte-pattern guess, and are fed to `hybridDisassemble` as seeds.
- **A recovered jump table's bytes are data, and only `DetectResult.jumpTableSpans` says so** —
  nothing walks *into* a table, so gap fill decodes it. The reported extent is the one actually
  **read**, never the count the bounds check claimed; **omitting the argument keeps the old
  behaviour deliberately**. `unboundedTableExtent` reports an extent with **no targets** (case order
  unknown), scans in **both directions**, and errs short. `overlappedTableExtent` starts past the
  instruction that overlaps entry 0 — a byte belonging to a decoded instruction cannot be a table
  entry — and takes its evidence by **deferral** rather than a forward probe. **Shape 2 (a negative
  index) is not a defect and must not be "fixed".** `boundedCaseCount` is the one declaration of what
  bounds a table; `and <index>, imm` is the **stronger** form; a register check alone is refuted by
  measurement, so `readAbsoluteTable` consults `tablesByBase` but **never takes a longer run than
  the first reading**.
- **An MSVC x86 `__finally` funclet is not a function, and the SEH scope table must not PROTECT
  one.** `interiorBranchedOverStarts` has **five admissions**, each naming a different kind of
  evidence, and the fifth uses `seh32FuncletRelation` as a **relation**, never a `strong` membership
  — feeding those handlers into `strong` re-introduces withdrawn starts, each cutting its parent in
  half. The frame test in admission (4) is the whole restriction and only the emitted C can see it;
  dropping the "no caller outside the previous function" test swallows `__SEH_epilog4`. **The rest
  of the family is refused on evidence, and the count-chasing rule is invisible to every gate.**
- **A folded funclet leaves its parent calling an identifier the output never defines** — measured,
  adjudicated and deliberately **NOT repaired**. `goto` is wrong, re-emitting restores the defect,
  and a comment is available at under half the sites and would state something false at the rest.
  Watch `internalUnlabelled`, not `internal`.
- **"A call target immediately after a `ret`/`jmp` is a function start" is deleted, and reviving it
  as *strong* evidence is worse than inert** — it describes the withdrawn funclet population exactly.
- **A TLS callback is a FILE-DECLARED entry point and belongs in `strongStarts`.** **THE UNIT IS THE
  WHOLE RISK AND NOTHING IN THE TYPE SYSTEM HOLDS IT** — every address in the bag is a VA, by two
  separate readings of the format rather than by construction; a caller "converting to an RVA like
  everything else" compiles and every callback is silently dropped. The mirror defect was live:
  `ExportEntry.address` really *is* an RVA and `mcp/session.ts` passed it raw, so **the harness and
  the browser had been detecting functions from different seed sets**, structurally invisible (all
  six binaries have zero exports). Hence `mcp/__tests__/detectSeedUnits.test.ts`.
- **The ARM64 sweep is shared via `WorkerState.arm64Sweep`, keyed on the section's BYTES** — both
  real ARM64 binaries base `.text` at 0x140001000, and a content key needs no assumption about
  message order. **Only the decode is cached**, with `comment`/`source` reapplied per caller; **a
  refused section is never stored**, so `sweepArm64`'s `Arm64DecodeRateError` refusal cannot decay into a cached empty
  answer. The plain `disassemble` RPC is deliberately out.
- **`mapInsn`'s comment resolution is an x86 operand grammar, so ARM64 passes it the empty maps.**
  On A64 the only literals are a branch target and an `adrp` **page base**, so an instruction was
  annotated exactly when a page base *coincided* with a data address. `decorateArm64Sweep` annotates
  from `findArm64AddressRefs` instead, attributed to the instruction that **completes** the pair.
  The empty maps are the mechanism, not a tidy-up — passing the real maps back is the defect
  returning. `corpus/comments.ts` is what catches it; nothing in `npm run corpus` can.
- **ARM64 publishes its recovered switch tables' byte extents, and the masking is on the decoration
  side** — the span is the extent actually **read**, marking is by **byte range with an intersection
  test**, spans are deduped, and the filter lives in `decorateArm64Sweep`, never in the sweep or the
  cache, or two callers with different spans would share one entry.
- **A PC-relative `LDR (literal)` is the ISA marking its own data** — the only A64 data-marking rule
  needing no inference. Pools are derived inside `decorateArm64Sweep` from `raw` itself; a load
  inside another load's pool is not honoured (one pass, not a fixpoint); and **`source` was
  deliberately not changed**, since the `.pdata` extent really is the linker's record.
- **The ARM64 stack frame comes out of `.pdata`, and the packed `FrameSize` means the frame DELTA,
  not the total allocation.** `frameSize` is the record's total and `frameDelta` the delta —
  conflating them was a live defect no gate saw. A **negative** delta is refused. The unwind codes
  run **backwards** through the prologue and carry more bytes after `end`. **The SIGNATURE was
  refused on evidence**: `.pdata` carries no arity information, so `inferSignature` returns null.
- **A64 mnemonic matching is by *exact* mnemonic, never by prefix** — `brk` is not a `br` and `bfi`
  is not a branch. `arm64Operands.ts` is the one place that knows the grammar.
- **`analyzeStackFrame` and `inferSignature` take `arch: ImageArch` ahead of `is64`.** Both **return
  empty rather than throwing** — the throw arm is for stages whose whole output is instructions.
  `archThreading.test.ts` guards what the type cannot see: a caller writing a literal `"x86"`.
- **…and the same file then invented on x86 everything its essay forbids on A64. Four sites, and the
  first is a DELETION**: the x64 stack-argument claim is **gone** (it described the function's own
  *outgoing* argument area — 262 parameters against the decompiler's 4), and **repairing the
  arithmetic was refused on evidence** — it would be a second stack grammar inside `signatures.ts`.
  `paramCount` on x64 is the register scan alone, 0..4. x86 reads `stack.ts`'s recovered frame;
  `thiscall` now consults EDX; and "no instructions in range" returns `null` rather than naming one
  of x86's four conventions. **Reopening needs an entry-SP displacement published by `stack.ts` plus
  an oracle.**
- **`arg_N` means argument *position*; the frame register's displacement from entry SP is
  `StackFrame.frameDelta`.** The name is the only channel to `structs.ts`, which keys `^arg_(\d+)$`
  to exclude frame-pointer-omitted RBP — **do not loosen it**. `frameRegisterAliases` follows a
  `splitStaleReads` copy **only when `frameDelta !== null`**; under FPO two versions are two objects.
  The stack pointer gets none of this — it moves. **`isParam` is decided by that displacement, not by
  whether the prologue was canonical**, and a refusal is **total**. `addressesOwnFrame` refuses
  `D < 0` (establishing somebody else's frame). **The prologue may be in another function**
  (`__SEH_prolog4`): the rule is stack **arithmetic**, not a byte pattern, carried by three refusals.
  **On x64 an index is not enough to name a slot** — an unfilled home slot is **withdrawn entirely**
  by `inUnfilledHomeSpace`, not re-labelled, since the caller owns the storage.
- **`regSize()` is not a membership test** — it falls back to 4 for any unrecognised name. Use
  `isKnownRegister()`.
- **`sectionInfo.characteristics & 0x20000000` = `IMAGE_SCN_MEM_EXECUTE`.**
- Capstone WASM is cached in IndexedDB (`peek-a-bin-wasm`).

### Decompiler passes

- **There is exactly one notion of "loop": dominance.** `detectLoops` delegates to
  `detectNaturalLoops`. The BFS-layer approximation it replaced called an `if`-without-`else` merge
  block a loop header and **deleted guards**; a diamond is immune to that mistake and a triangle is
  not, so hand-written fixtures never caught it.
- **`structureCFG` closes an `if` at the immediate post-dominator.** The two "one arm ends in `ret`"
  shortcuts must not fire when that arm *is* the convergence point. A nearest-common-successor
  heuristic is not a substitute — for a switch it picks the default block.
- **`extractCondition` returns the condition under which the jump is TAKEN.** Backwards, this
  inverted every `if` and `while` while leaving the bodies in place — valid C stating the opposite of
  the machine, invisible to every stage-level test.
- **A guard is answered from the flags the Jcc *actually* reads, and only while the compare still
  describes them.** Two refusals in `extractCondition`, both reading `flagModel.ts`'s own tables:
  the forward walk clears flags on anything not `isFlagTransparent`, and a compare whose operand was
  overwritten before the Jcc is refused. **Refusal *is* the repair**, so the cost appears as
  unrecovered values rather than changed guard text. **Both are asked of the condition read off the
  *instructions*, never of the IR one** — copy propagation has rebound the register out of the
  expression, so asking the IR defeats the check outright.
- **A spoiled compare is recovered by MATERIALISING its operands at the compare**
  (`spoiledCompareCapture`, `lifter.ts`), not by refusing the guard. The destination is an **`IRVar`**, not a
  deletable pseudo-register; the signal is `IRBranch.capturedAt`, an **address**; the scope is a
  block-local **compare** owner; and the emitter must **declare** the capture, or `preludeFor`
  manufactures it and gcc reads clean over C the harness completed.
- **…and the capture is placed for EVERY in-block flag reader, not for the trailing Jcc alone.**
  `setcc`/`cmovcc` built their conditions from `regState.getCondition` at their own program point,
  so `cmp eax, 5 / mov eax, edx / sete al` lifted `al = (eax == 5)` *after* `eax = edx` — the Jcc's
  defect one reader over, and it reached the page as `edx == 0x53`, the register the SPOILER read.
  `operandCaptures` (`lifter.ts`) is the one map: every reader's owner is asked, needs merge per
  setter, the compare's flag state names the captures, and `branchFor` looks its owner up in the
  same map. `corpus/staleGuards.ts` gates the reader population (`readerNamed`, 0) beside the Jcc
  one, judged from the emitted LINE at the reader's address; an admitted value is a refusal, not a
  row.
- **CF is a VALUE, spelled as an EXPRESSION substituted into the consumer — never a statement, never
  a pseudo-register.** `sbb`/`adc` were `raw`, and a `raw` is a dataflow hole, so `neg edi / sbb
  rax, rax / and rax, rbp` returned `rax & rbp` over the RAX from *before* the `sbb`. `carryFor`
  (`lifter.ts`) builds the CF from `flagModel.ts`'s CF grammar — `carryOwnerBefore` over
  `carryScanStream`, the one per-flag walk, with `inc`/`dec` and `sbb d, d` preserving where the
  whole-flags owner moves — and `sbb d, d` → `-(CF)`, `sbb d, s` → `d - s - CF`, `adc` → `d + s +
  CF`. Spellings: `cmp`/`sub` → `a u< b` (a `sub`'s destination is CAPTURED before it runs), `neg`
  and `sbb d, d` → `d != 0` read after, logical ops → 0, `bt` → the bit. **Refused, and `raw` is
  the whole refusal**: `add`/`adc`/`sbb d, s` carry-out (no wraparound model), a spoiled setter with
  no capture, a chain whose first link was refused, several predecessors. **`sbb`/`adc` are
  `RESULT_OWNERS` now, and `branchFor` refuses a result owner the lifter left `raw`**
  (`resultOwnerLifted`) — the lift-first rule made checkable. The `eflags` proxy's history is why
  none of this may become a statement (`docs/decompiler-ir.md`).
- **`bts`/`btr`/`btc` are STATEMENTS over the bit base** (`d | (1 << i)`, `d & ~(1 << i)`, `d ^ (1
  << i)`; memory destination → store), and their CF is deliberately NOT recorded — it is the bit
  BEFORE the write, so they stay clobbers in both flag models and `parseBitTest` stays `bt`-only.
  The index is the SDM's rule: a register base reduces modulo the width (`(idx & (W-1))` for a
  register index); a memory base addresses a bit STRING, so a register index over memory is refused
  and an immediate is admitted only below the width. `bitWrite` (`lifter.ts`) is the one declaration.
- **`movabs` is a `mov`, and an immediate that is not a SAFE INTEGER is refused (`raw`), never
  rounded.** `IRConst.value` is a JS number; a 64-bit magic constant beyond 2^53 would be silently
  rounded to a value the program never contains and folded with downstream. `exactImmediate`
  (`lifter.ts`) is the one declaration; `0xffffffffffffff0` is FIFTEEN digits (2^60 − 16, refused),
  not −16. 36 of 42 corpus sites are refused this way — a measured cost left standing, since the
  refusal keeps a `raw` hole (strncmp's masks stay unassigned) and the alternative is epic 2's
  unknown-assignment.
- **`rep movs*`/`stos*` are the MSVC intrinsics WITH their side effects modelled, dispatched on the
  tokens of the raw mnemonic.** Capstone spells the prefix into the mnemonic (`rep movsd`, operands
  present or empty), so the old `mn === "rep"` path was dead against real disassembly. `parseStringOp`
  (`lifter.ts`) is the one declaration; the spelling is `__movsd(rdi, rsi, rcx)` / `__stosd(rdi, eax,
  rcx)` — exact semantics, never `memcpy`/`memset` — followed by `rdi += rcx*S; rsi += rcx*S; rcx =
  0` (increments before the zeroing), with RCX then marked SPENT so `collectArgs64` cannot hand the
  zeroed counter to the next call (arity OVER is a gate at 0). An unprefixed `stos`/`movs` is one
  store plus the advance. **Refused**: anything inside a block-local `std` region (the primitive runs
  backwards; `std`/`cld` themselves stay `raw`), and every `repne`/`repnz` form. **The intrinsics are
  NOT in `apitypes.ts`** — the arity oracle must not measure its own input.
- **Which instruction a Jcc's flags belong to is `flagModel.ts`'s answer**, and `branchFor` is the
  only place that asks. It refuses four ways, each a case where an answer would be a guess. The third
  (a result/bittest owner in a block that also holds a `cmp`) is a **policy**, to be revisited *with*
  `corpus/staleGuards.ts`. A **compare** owner is deliberately not filtered on `spoiled`.
- **A compare emits no statement at all.** The old `eflags = …` proxy was actively harmful — GVN gave
  it and a real `sub` the same value number and the post-fixpoint strip deleted the only assignment.
  `isFlagTransparent`/`clobberedAfter` live at the bottom of `flagModel.ts` so there is **one** copy
  of the x86 flag grammar, with a drift guard failing on a second declaration.
- **`push`/`pop` write no flags; a guard behind an epilogue restore is refused by `spoils`, not by
  the flag model.** `baseMnemonic`'s exact match is what keeps `popf`/`pusha` clobbering — a
  `startsWith("pop")` test silently admits `popf`. Do not try to fix this by moving the `IRBranch`
  earlier: `structureCFG` emits a block's statements above the `if`.
- **`test` clears OF and CF; it does NOT clear SF**, which is why the `test` arm answers strictly
  more Jcc forms than the `result` arm. Not to be re-tried: `jb`/`jae`/`jo`/`jno` are constants after
  `test`, and emitting `if (1)` is a control-flow claim; `jp`/`jnp` read PF with no cheap spelling.
- **`bt` is a compare over one bit and needs its own owner kind** — it writes nothing and **leaves ZF
  unaffected**, so a following `je` branches on an older instruction's ZF. `parseBitTest` admits only
  a register bit base with an immediate offset; `bts`/`btr`/`btc` stay clobbers permanently. Spell it
  with `>>`, not `>>>`.
- **A Jcc alone in its block is answered from its predecessors, and only when every way in leaves the
  flags saying the same thing.** The predecessor's **terminator must be skipped explicitly** (without
  it the change recovers 0); **either edge counts**; and unanimity is a **text-equality test over
  Capstone's operands, never a merge**. **Nothing in the corpus protects the disagreeing sites** —
  answering from the first predecessor recovers 12 more guards with `npm run corpus` at exit 0.
- **A memory destination is spellable**; refusing it was a spelling limit reading as a dataflow fact.
  `destForm` is for spellability while `destReg` stays for `spoils` — conflating them refused every
  row. Soundness is the **ordering** (statements above the `if`), assertable only in
  `pipeline.test.ts`.
- **A `lock` prefix changes atomicity, not values or flags**, so it must not change any
  classification — but **a locked read-modify-write with no value effect is a fence and must stay
  unlifted**. `withoutLockPrefix` is the one declaration; `rep` must survive stripping. Lift before
  classifying. `isValueNeutralLockedRmw` requires the **prefix as well as** the nil value effect.
- **A switch arm that ends in a test must say so: `break` is a claim about control flow.** `armExit`
  (`structure.ts`) spells the block's own exit; the transfer is **spelled, not followed**, and a `goto` where `break`
  was already right is noise rather than a claim. The bead's suggested fix was measured and refused —
  naively it empties every arm and **every gate stayed green**.
- **A block with no predecessor is not necessarily dead code** — an MSVC `__except`/`__finally`
  continuation is entered by the unwinder. Padding is still excluded by "lifts to no statements",
  but step 4b hoists branches out, so the test is `… === 0 && !branches.has(b.id)`. **No gate could
  see it.**
- **`if (c) { continue; } break;` at a loop tail is emitted as `if (!c) { break; }`**
  (`collapseLoopTailContinue`), cosmetic, restricted to a **loop's own** body. The negation must be a
  **flipped comparison, never a `!`-wrapping**; `&&`/`||` are refused; it runs **after
  `breakForwardGotos`**; and the braces stay, or the corpus guard scan loses every
  single-terminator-body guard.
- **A guard whose whole body is one terminator is one-lined by `oneLinedGuard`**, handed the body's
  own `EmitResult` with the guard out of scope, or the arm anchors to the jcc one decision earlier.
  Only the four **terminators** are admitted — a one-lined assignment would hand `selfAssigns.ts` the
  guard as its destination.
- **A `for`'s init need not be the statement immediately before the loop** (`initHoistable`), and
  hoisting moves the init **later**, so four refusals carry it, including a **whitelist** of what may
  intervene rather than a blacklist. `initAt >= 0` is **not** redundant with the equality test.
  **`detectForLoop` must try every increment-shaped candidate, not the first**, and a predecessor
  inside the loop body is not a source of inits (`p < header.id` stood in for "before the loop"; the
  latch is routinely numbered below its header). The update-position guard is **exact, not strict**.
- **`mov <r32>, <same r32>` on x64 is a zero-extension**, and the pass that lost it was
  `copyPropagation`. The truncation must be **in the expression** (`x & 0xFFFFFFFF` over the 64-bit
  parent). `is64` only, 32-bit width only, not RSP. `firstCalleeSavedWrites`' own self-move test
  answers a different question and must keep reading `mov X, X` as a non-definition.
- **A branch condition goes through the lifter's real `parseOperand`** — the private
  `parseSimpleOperand` hardcoded `size: 4` and never called `ripRelative.ts`, and the width alone
  recovered frame slots, `INVALID_HANDLE_VALUE` and dozens of structs.
- **SSA version 0 means a register's *entry* value; the definition counter starts at 1.** Its repair
  is taken **at the function's entry and nowhere else** — no statement defines version 0, and a copy
  in the reading block binds to a name holding something else.
- **`liftBlock` emits plain register reads; it does not substitute `RegState`'s symbolic value.**
  Propagation belongs to SSA, which has the version information that makes it sound.
- **No read of RSP may be moved to another program point.** Both `copyPropagation` and `fold.ts`'s
  single-use inlining guard it, and **both are needed** — the second reintroduced the defect the
  moment an unrelated fix made the frame-pointer copy single-use.
- **Three stack idioms ARE lifted, because an unlifted `pop` is not an SSA definition.**
  (a) `push <imm>`/`pop <reg>`, one declaration in `disasm/stackIdiom.ts`, `pop esp` refused.
  (b) The same idiom split across a branch is a **phi of immediates**, so the definition lands in
  *each predecessor* — `pipeline.ts` step 2b, appending through `pushBeforeTerminator`, with four
  refusals making it sound. (c) A matched `push <reg>`/`pop <reg>` becomes a pseudo-**register**
  slot identified by the **pairing**, never an address; the lattice needs a **TOP** element.
  `regState` is deliberately not told about a slot pop, or arity over-counts. **Every replica of the
  lift loop must carry all three calls** — `stackIdiom.test.ts` enforces it.
- **`foldBlock` counts uses inside ONE block, so a definition that escapes the block is not
  single-use.** `blockLiveOut` is computed once on the unfolded program; the refusal is
  `killedInBlock`-guarded; a **`raw` reads nothing** while a **`branch` very much is** a read.
- **Register names follow the image's width, and the phi cannot tell you what that is — ask the live
  range, not the function.** Naming is per **phi web**, taking the widest mention of its own members.
  **One name per function is still wrong** where a register carries two live ranges of different
  widths. A trivial phi's operand is the register's **identity**, not a spelling, so `simplifyPhis`
  must spell it the way the value's own mentions do. Giving the phi a truthful width was measured and
  is **not worth a session**.
- **A call clobbers what the callee writes, and that answer is only ever ADDED to the narrow one.**
  Modelling a call as destroying the whole volatile set was tried and is **worse** — it deleted a
  guard outright. The summary **under-approximates** by construction; recursion needs no special
  case; it is x64 only. **`RegState.invalidateCallerSaved` must NOT be narrowed with it** — that
  needs an over-approximation.
- **A call to a callee that PRESERVES the accumulator defines no result, and the `/GS` cookie check is
  the one that mattered.** Every `call_stmt` took `resultDest: RAX/EAX`, `__security_check_cookie`
  included, so the function's real return value was dead and every protected function that returns
  a value printed `return sub_140002000(rcx);` — a WRONG VALUE (15/13/18/16 functions on
  t64/w64/t32/w32 at 6299113). `disasm/crtIdioms.ts` recognises the routine's body **exactly** (two
  shapes, both read off the corpus; an extra instruction, a compare against a register, a `je`, a
  body writing EAX are all refused) and publishes `preservesResult`, the cookie's address and the
  routine's one-register signature; the lifter then emits the call with **no `resultDest`** and the
  signature's argument. The call and the `x ^ rsp` xor are **NAMED, never deleted** — instrumentation
  is real control flow, and on x86 the argument is what keeps the xor alive. The name is applied
  **at detection** (`functionDetect.ts`'s thunk pass), so the function list, the emitted C and the
  harness's expected-callee set have one source and `distinct callees lost` stays 0 by construction.
  The cookie load is spelled `__security_cookie` by the **emitter**, from the address the one operand
  grammar already resolved, with an `extern` above the header; a load at another width keeps the
  raw spelling. Format-side corroboration (`LoadConfigDirectory.securityCookie`) is parsed and
  **reported, not consulted** — the worker never sees the PE. Measured cost: RAX now live at the
  `ret` materialises phi copies, which withdrew **two** struct definitions on t64 and moved one
  A2-anchored guard per x64 binary out of the polarity audit (arms swapped, hand-read correct).
- **`RegState.defs` is keyed by literal operand text deliberately** (the recorded expression carries
  the operand's width). Ask `wroteAnyAlias` for the width-blind question; it returns a **boolean**,
  so the recorded expression can never be substituted at the call site.
- **A written fastcall register is not an argument if the block already SPENT it as an address
  index** — but an address **base** proves nothing. Four rules are refuted by this corpus and must
  not be re-tried: distance, dominance, any read spending it, and any read from inside a memory
  operand. **Never answer this from `apitypes.ts`** — that blinds the only arity oracle here.
- **`collectArgs32`'s backwards push-walk stops at a call whose result feeds a following call**, and
  the marker is `push eax` **after** the call. Deliberately an **admitted under-count**.
- **A `push` of a callee-saved register the function has not yet written is a register SAVE** — and
  that, not the register and not the position, is the discriminator. Two rules refuted by this
  corpus: "a push of ebx/esi/edi is a save", and "a save has a matching `pop` before the `ret`".
  Scope is **function-wide**; `mov X, X` is not a definition but `xor X, X` is; restricted to the
  four callee-saved registers.
- **A `__try` is emitted only where the scope table holds an `__except` entry.** The old wrapper's
  three claims were all unread — 100% of regions are narrower than their function, and `/GS` sets
  EHANDLER with no `__try` in the source at all. `__finally` is **recorded as a comment and not
  spelled** (the IR has no statement kind for one); a record with **no validated table emits
  nothing, not even an admission**. **`IRTry.filterSource`'s ABSENCE is the unrecovered case, never
  the constant.** **Do not push any of this into `funcExceptionRecord`** — that is a *selector*, and
  its soundness rests on client and worker applying the same idempotent rule. **gcc has never
  checked this construct** (`#define __except(x) if (0)` discards its argument).
- **Recursing into a statement's nested bodies is `ir.ts`'s `bodiesOf`/`rewriteBodies`, one
  declaration each**, both ending in an exhaustive `never`. `for`'s `init`/`update` are single
  statements, so neither reaches inside them.
- **`+`, `-` and `*` do not model wraparound, and the const-const fold site has no width evidence.**
  `knownWidth` returns null for an `IRConst` deliberately — `IRConst.size` is the CPU *mode*.
  Wrapping them the way the bitwise arms do **introduces** a defect.
- **`fold.ts` has a `castTypeSize` helper** for double-cast removal. **`cleanup.ts`** runs after
  `structureCFG`, before `inferTypes`; guard-clause flattening is single-level, not recursive.
- **The polarity audit's population was one trailing brace wide.** `corpus/guardShape.ts` is the one
  declaration of what a guard line is, and the condition is **depth-counted, not anchored** — a
  greedy widening reads `if (a == 0) x = f(b);` as the condition `a == 0) x = f(b`. One-lining breaks
  three scrapes in three directions, including one that goes **red on correct output**.
  `selfAssigns.ts`'s `FOR_HEADER` was the second hand-rolled copy and the drift guard could not see
  it (it names one keyword, not two); **widening the guard to single-keyword patterns was measured
  and refused**.
- **A function's return type is decided over the WHOLE structured tree, through `bodiesOf`.**
  `promote.ts`'s `hasReturnValue` hand-listed `if`/`while`/`do_while`, so a valued `return` inside a
  `for`, a `switch` arm or a `__try` body left a `void` header above `return rax;` — every
  `__try`-wrapped function with a value in the x64 corpus (3/3 on t64/w64 at 6299113 → 0/0), and
  gcc only *warns*. `emit.ts`'s `headerReturnType` then widens the `int` **only** when every valued
  return is one `API_TYPES` call result and they all agree, asked of the **folded** body; a
  void-returning API, a returned register, a `sub_…()` result or a disagreement refuse to `int`.
  **Width (`int` vs `int64_t`) and pointer-ness from callers are deliberately NOT inferred.**
- **An import thunk is NAMED after its callee, so its tail `jmp` must not be spelled as a call to
  itself.** `functionDetect.ts` renames a `jmp [IAT slot]` function to the import and sets
  `isThunk`; the lifter resolved the same slot to the same name and emitted
  `RtlVirtualUnwind() { return RtlVirtualUnwind(); }` (3 per x64 binary). `importThunkTransfer`
  (`lifter.ts`) spells the transfer through the slot — `((intptr_t (*)())__imp_X)()` under a
  `// import thunk: … <dll>!<func>` comment — when `isThunk` **or** the resolved name equals the
  function's, and only when the target *is* an IAT slot. **`importSlotName` / `IMPORT_SLOT_PREFIX`
  (`lifter.ts`) are the one declaration of the `__imp_` spelling**; epic n9cl's IAT-slot loads must
  reuse it, and `corpus/sweep.ts`'s `emittedCallees` reads the prefix back so `distinct callees
  lost` stays 0.
- **One variable per register made a SPELLING device load-bearing, and the value-level repair had
  to replace it.** `peek-a-bin-pzws` spelled two live ranges of R9 as `r9` and `r9d` so that `mov
  rbp, r9 / mov r9d, r14d / … / mov [rbp+0x18], esi` — copy propagation forwards `rbp` to the entry
  `r9`, and the 32-bit range's only write is a lowered **phi copy** in the loop header's
  predecessor — printed as two C variables. With one variable that copy is `r9 = (uint32_t)r14d_1`
  above six stores through `r9`, and `corpus/staleReads.ts` went red at exactly those 6 per x64
  binary the moment its `writes` test compared canonical registers (which under one variable per
  register is the only correct test — the old name test is inverted, not dropped). The cause was in
  `splitStaleReads`: it attributed a phi's write to the phi's **own** block, while `destroySSA` emits
  the copy at the end of each **predecessor**, which dominates blocks the header does not — the same
  attribution the audit has made since `peek-a-bin-fppy`. Two halves, both negative-controlled: the
  predecessor is noted in `defBlocks`, and a predecessor whose exit still holds the entry value hands
  the phi's version to its *other* successors (`phiCopiesOut`), so a version-0 read on a pure bypass
  path is stale at all. Result: `r9_0 = r9;` at entry, the stores through `r9_0`, exactly one new
  entry copy per affected function (`t64!sub_1400045DC`, `w64!sub_14000496C`), gate back at 0.
  `registerSpeller`'s per-web spelling stays for what it was always evidence of: the **width**.

### UI, build and deployment

- **`navigator.clipboard` is a SECURE-CONTEXT API and this app has an HTTP deployment**, so every
  copy goes through `utils/clipboard.ts`'s `copyText`. Over plain `http:` off localhost the whole
  object is absent, so it is a **TypeError at the property access**, on click — 18 unguarded sites,
  zero guards. Four rules: the feature test names **`writeText`**; it is called **before the first
  suspension**, so it stays inside the user gesture; it is called **on** the clipboard object; and it
  returns a **boolean**, never throws. Four sites flash **red** on `false`; **the other fourteen fail
  silently — the app has no toast mechanism and one was not invented for a bug fix.** A
  `document.execCommand` fallback was costed and **REFUSED**.
- **A caret that opens onto nothing, a blob URL nobody revokes, and a column dressed as a link** —
  the pane's OUTPUT is honest and its CONTROLS lie about what they will do. The unknown-type fallback
  is a hex dump **through `resourceBytes`, the one declaration of the bound** (a hand-rolled bound
  reintroduces the `RangeError` across the whole population); `resourceBytes` returns a **reason**
  carried out of the guard rather than re-derived; the guard sits **above** RT_VERSION and **outside**
  RT_GROUP_ICON, whose `buffer.slice` clamps where `new Uint8Array` throws. `GroupIconPreview` mints
  in a `useEffect` and **revokes in the cleanup** — the instrument is the **pairing**, since a create
  count alone passes against the defect.
- **The hex tab's byte search reported its cap as a fact.** `findBytePatternMatches` returns
  `{ offsets, truncated }`, and **`truncated` is decided EXACTLY** — the break is taken on the match
  that would *exceed* the cap. The admission goes on the **count line**, and `matchSummary` is the
  one declaration of the sentence so the `+` and the `(search stopped at N)` cannot come apart. The
  second half is the **SCOPE**: the scan covers ONE section, so an unscoped `No matches` is the
  stronger falsehood.
- **…and debouncing that scan creates the same class in reverse — a sentence about a scan that has
  not happened — so the scanned query is carried with its result.** `searchSettled` compares **both**
  `result.query === byteSearch` (the BOX, never `activeSearch`) and `result.data === sectionBytes`;
  an unsettled query prints a neutral `Searching…`. The highlight set is deliberately **not** gated.
- **`lineMap` is MANY-TO-ONE**, so anything keying a rendered element off an address alone renders one
  per sharing line. Resolve to **one** anchor line and take the **lowest** — `placeGotoLabels`' own
  tiebreak, and the line the auto-scroll effect reaches. `syncDisabled` must be re-tested at the
  anchor rather than inherited.
- **A default parameter is a place two callers can disagree**, and `layoutCFG(blocks, fontSize = 12)`
  is where they did — the minimap passed nothing, so at any non-default font size the geometry
  published to the sidebar described a different graph from the one drawn. What is assertable is the
  numbers handed to `setGraphOverview`, never that the minimap looks like the graph.
- **A callback declared later in a component cannot go in an earlier hook's dependency array** — it
  is a `const` in its temporal dead zone. The fix is a ref assigned *during render*; an effect is too
  late, because a keypress can be handled before effects flush.
- **`DisassemblyView.tsx` is ~1620 lines even after the split — read it in chunks.** The extracted
  seams are `useDisassemblyKeyboard.ts` (a **38-entry** dependency array that *is* the behaviour —
  copy it verbatim if you move it, comments included) and `useGraphSearch.ts`. That array only began
  doing anything when `useDisassemblySearch`'s return was memoised. `CFGView` takes 23 props.
- **`parseBranchTarget` lives only in `components/shared.tsx`** and resolves `call` immediates as well
  as jumps, so JumpArrows guards with `mnemonic.startsWith("j")` *before* calling.
- **The CSP is generated, not hand-written.** Edit `build/csp.ts`, never `nginx.conf`'s header or
  `index.html`; `build/csp.test.ts` fails on drift. A meta CSP cannot go in `index.html` because it
  is also the dev entry point. The shipped `connect-src` omits non-localhost plain `http:`, so a LAN
  Ghidra server is blocked on the HTTP deployment.
- **Do not re-add a plugin that copies `capstone.wasm`** — Rollup already rewrites the `new URL(...)`
  to its hashed asset. `capstone-wasm-guard` fails the build if more than one WASM asset is emitted.
- **`tools.ts` and `resources.ts` must only *type*-import `./session`** — a value import pulls in
  `./disasm`, which loads Capstone WASM at module scope.
- **`biome.json` must be strict JSON.** A single `//` comment silently voids the whole config and
  Biome falls back to defaults.
- **Vitest's environment marker is matched against the WHOLE FILE, not the leading docblock**, so a
  node-only file that quotes the marker in a string or a comment is silently switched to jsdom. It
  bit `build/domTestNaming.test.ts`, whose whole job is to check that marker. Keep the two halves of
  the token apart.
- **A multi-line `biome-ignore` needs `//` on every line** — Biome only honours the directive on the
  line immediately preceding the offence.

## Working in parallel — use subagents, and how

**Default to farming independent work out to subagents.** Changes here are mostly self-contained —
one bead, one measurement, one audit — and each carries a large reading cost that does not need to
land in the integrator's context. Sessions have run three or four agents in parallel and cleanly.

**Reach for one when** the task is a whole bead, a measurement with a stated method, or a read-heavy
audit whose answer is a paragraph and whose *inputs* are hundreds of files. **Do it yourself when**
it is a single fact you know where to find, when the work needs the integrated tree (integration
itself is not delegable), or when briefing would cost more than doing.

### Give each agent its own worktree, and make it its own

Tool-created worktrees land *inside* the working tree and arrive with no `node_modules`. Create them
yourself:

```sh
git worktree add /tmp/pab-wt/NAME -b sNN-NAME <HEAD_SHA>
ln -sfn /home/taylor/dev/peek-a-bin/node_modules /tmp/pab-wt/NAME/node_modules
mkdir -p /tmp/pab-wt/NAME/.scratch
```

- **The symlink means every such worktree SHARES one `node_modules`.** Fine for reading; **not** fine
  for a task that changes `package.json` — an `npm install` there rewrites the tree under every
  sibling and can invalidate a timing measurement one of them is taking. Give such an agent a real
  `npm ci` in its own worktree (~90 s) and tell the others the shared tree is read-only.
- **Scratch goes in `<worktree>/.scratch/`, never a bare `/tmp/<name>`** — one agent's control backup
  was once clobbered mid-run by a sibling using the same filename.
- **Tell each agent to print `git rev-parse --short HEAD` first and stop if it is wrong.**
- Remove the worktrees at session close; keep the branches as provenance.

### What every brief needs

- **The gate commands, including the traps** — `npm run check` must not be piped, and `npm run
  corpus` skips cleanly and still exits 0, so say "confirm the header names FOUR binaries".
- **What byte-identical output would mean.** For a pure-performance change it is the whole case.
- **Negative controls, asked for explicitly**, and say to **report** an inert one rather than quietly
  tuning it away. This repo has repeatedly found inert controls — four in three agents in one session.
- **"A measured refusal is a fine outcome."** Say it.
- **Read-only means read-only.** An audit agent running beside editors must be told not to edit,
  commit or touch the tracker, and to hand back a report.

### Integrating

- **Do not take an agent's results at face value.** Re-derive the load-bearing ones.
- **Several agents will all touch `CLAUDE.md` and `CHANGELOG.md`.** Cherry-pick in order; the
  `CHANGELOG.md` conflict is two additions under one heading — **keep both, newest timestamp first**.
- **Run the full gate set on the INTEGRATED tree**, not just per branch.
- **Pin a baseline before the agents start** — one `npm run corpus` on the session's base commit,
  under its own label.

## Gates

```sh
npm run typecheck && npm run build
npm test
npm run check      # the CI gate; expect exit 0
```

Passing these is *not* the same as the change being verified — see **Verification status**. If the
change touched a component, a modal, the CSP or the nginx headers, nothing you can run here
exercised it.

## Committing

**This repository opts in to agents committing.** Commit a coherent unit of work yourself once the
gates are green — do not finish a piece of work and then ask permission to record it. This overrides
the Conservative default below. A current instruction not to commit still wins.

**Pushing is NOT included.** Ask before `git push`, before `git pull --rebase`, and before any Dolt
remote sync. **Do not assume `main` is ahead of `origin/main` — CHECK** with
`git rev-list --count origin/main..main`; either state is normal. One consequence when main *is*
ahead: **tool-created subagent worktrees are cut from `origin/main`**, so they silently lack your
unpushed work — which is one reason the recipe above uses an explicit local SHA.

### Before you commit

```sh
npm run typecheck && npm test && npm run build
npm run check        # the CI gate
npm run corpus       # ONLY if the change could move emitted C
```

Run the corpus whenever the change touches `src/disasm/`, the decompiler pipeline, function
detection or the emitter, and **confirm the report header names four binaries**. Diff against a base
run pinned to one commit; **byte-identical output is itself a result worth stating**.

### What a commit here looks like

- **One logical change**, with its documentation and `CHANGELOG.md` updates in the same commit.
- **Straight to `main`.** Use a worktree when a subagent needs isolation, not to stage a commit.
- **The message carries the measurements**, in the style already in `git log`: imperative subject,
  then what changed, *why*, the numbers before and after with the commit they were taken at, and the
  bead id. Prefer a long message to a short one — the log is the only place some of this is written.
- **Stage only your own files.** `.beads/dolt-backup.json` is tracked but is not yours;
  `.beads/interactions.jsonl` moves as a side effect of `bd` and goes in its own commit.
- **End the message with** `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.
- **Never pass unescaped backticks to a `bd` text flag — the SHELL executes them and silently drops
  the fragment.** Use a quoted heredoc (`--body-file - <<'EOF'`) or `--append-notes "$(cat file)"`,
  and **read it back with `bd show`**. Two more things `bd show` misleads about: its renderer bolds
  `__tests__` and eats `<angle-bracket>` placeholders, so use `--json` when it matters.

### Author identity

**Not configured in git, deliberately, and must be passed per command:**

```sh
GIT_AUTHOR_NAME=welly GIT_AUTHOR_EMAIL=wklee@m2.local \
GIT_COMMITTER_NAME=welly GIT_COMMITTER_EMAIL=wklee@m2.local git commit -m "…"
```

That matches every existing commit. The user's own address is `mantis2406@wellingtonlee.io`; if they
say to use it, amending is cheap while these commits are unpushed. Do not write either into
`git config` without being asked.

## Documentation

Documentation lives in `docs/`. **`docs/README.md` is the canonical index and holds the "which doc do
I update when I change X" mapping table** — consult it there rather than keeping a second copy.

Three of those files are the long-form record split out of this one, and a change to a rule
summarised here usually belongs in its detail file too: [`docs/gotchas.md`](docs/gotchas.md),
[`docs/verification.md`](docs/verification.md), [`docs/decompiler-ir.md`](docs/decompiler-ir.md).

Update this file for architectural changes, new source directories, new pipeline stages, new
conventions, new gotchas and changes to the build/test commands. **Keep it a summary** — the
evidence, the measurements and the negative controls go in the `docs/` file, not here. Update
`README.md` only when changes affect the top-level project description.

## CHANGELOG Convention

Maintain `CHANGELOG.md` under `## [Unreleased]` with `### Added`, `### Changed`, `### Fixed`,
`### Removed`. Each entry: `- **Feature name** — concise description`, with a timestamp appended in
the format `(YYYY-MM-DD HH:MM)`. Example:
`- **Feature name** — concise description (2026-03-06 15:30)`

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
