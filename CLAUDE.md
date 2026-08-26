# Peek-a-Bin

Browser-based PE disassembler/analyzer. Fully client-side (no server). PWA with offline support.

**Tech**: React 19, TypeScript 5.7 (strict), Vite 6, Tailwind CSS 4, capstone-wasm (WASM disassembly engine), @tanstack/react-virtual, @dagrejs/dagre

**Requires Node 20+** (`engines.node`). On Node 18 the build dies at the end of bundling with
`ReferenceError: crypto is not defined` — `serialize-javascript`, via `@rollup/plugin-terser` on
the PWA/Workbox path, calls the global `crypto`, which Node only exposes unflagged from 20.
Workaround: `node --experimental-global-webcrypto ./node_modules/vite/bin/vite.js build`.

**This file is the index; the evidence lives in `docs/`.** Three companion documents carry the
long-form record — the measurements, the negative controls, the alternatives tried and refused —
that used to be inline here: [`docs/gotchas.md`](docs/gotchas.md),
[`docs/verification.md`](docs/verification.md) and
[`docs/decompiler-ir.md`](docs/decompiler-ir.md). Each keeps the same entries in the same order as
the summary sections below, so an entry here lines up with its full record there. **Read the
long-form entry before changing the code it describes** — most of these rules are load-bearing in
a way the summary can state but not justify, and several record an approach that was built,
measured and rejected.

## Commands

```sh
npm run dev            # dev server
npm run build          # tsc -b && vite build
npm test               # vitest run
npm run typecheck      # tsc --noEmit (faster than the full build)
npm run lint           # biome lint src — the fast, src/-only signal
npm run check          # biome check — THE CI GATE; see the reading trap below
npm run format         # biome format --write
npm run test:coverage  # RED — @vitest/coverage-v8 is not installed
```

Corpus harnesses need real MSVC binaries that are not in the repo, and **skip cleanly (exit 0)
when they are missing** — see `corpus/README.md`, and the Verification section for what each
proves:

```sh
npm run corpus                        # the four x86 binaries: every detection/decompiler gate
npm run corpus:arm64                  # A64 sweep, .pdata, xrefs, jump tables, sweep-cache differential
npm run corpus:comments               # ARM64 comment audit + x86 comment digest
npm run corpus:parserdiff             # PE parser vs an independent from-spec reader, all six binaries
npm run corpus:compare -- <base> <change>   # diff two runs guard-by-guard; takes PATHS (corpus/artifacts/<label>)
npm run corpus:jumptables    -- <pe>  # indirect-dispatch census: was each reader even reached
npm run corpus:gridserve     -- <pe>  # hybridDisassemble grid coincidence + served-vs-decoded diff
npm run corpus:uploadcost    -- <pe>  # what re-sending .text costs
npm run corpus:decompilecost -- <pe>  # one decompile request, per payload member
npm run corpus:detectcost    -- <pe>  # where detectFunctions spends its time, per phase
npm run corpus:replycost     -- <pe>  # what the worker's reply costs
```

**`npm run check` is the gate, not `lint`.** It is a superset: same rules, plus the formatter and
`assist/source/organizeImports`, over the whole repo rather than just `src/`. So an unsorted
import or an unformatted root config file fails CI. Current state: **0 errors**, ~70 warnings, 3
infos. Warnings and infos never fail it. Two infos are `useNodejsImportProtocol` on
`vite.config.ts` — Biome classes those fixes *unsafe*, so `--write` skips them and they are
deliberately left; the third is a `biome.json` deprecation notice.

**Reading a Biome result is itself a trap, and it will tell you a red tree is green.** The default
`--max-diagnostics` truncates *before* the `Found N errors.` summary, so `npm run check | tail`
routinely ends on the warning count with the error count scrolled away — and piping makes it
worse, because `npm run check 2>&1 | tail; echo $?` reports **`tail`'s** status, printing 0 for a
failing run. Use one of:

```sh
npm run check > /tmp/check.txt 2>&1; echo "exit=$?"              # no pipe, so $? is Biome's
npx biome check --diagnostic-level=error --max-diagnostics=300   # errors only, untruncated
```

**A worktree inside the repo makes a root test run lie.** Tool-created subagent worktrees land at
`<repo>/.claude/worktrees/agent-<id>`, *inside* the working tree, so a bare `npm test` walks into
them and reports someone else's in-progress results — a green run that says nothing about your
change, or a red one that is not your fault. Scope it: `npx vitest run --dir src`, then
`npx vitest run --dir build` as a second command (`--dir` takes exactly one directory, and bare
path filters are regex-matched against full paths and still hit the worktrees). `git worktree
list` is the check when a gate count looks unfamiliar. Such a worktree also arrives with **no
`node_modules`**, so Node resolves from the nearest ancestor that has one and the gate runs
against another tree's dependency versions. Create worktrees yourself — see **Working in
parallel** for the recipe and what the shared `node_modules` forbids. The corpus config is not at
risk; its `include` is anchored at `corpus/**`.

**Biome severities are ratcheted and must stay there** (`biome.json`): all seven configured `a11y`
rules, `correctness/useHookAtTopLevel` and `correctness/useExhaustiveDependencies` are at
**`error`**. The last matters most — it sat at `warn`, and since `lint` exits 0 on warnings the
entire stale-closure class **could not fail CI**, with no renderer to catch one at runtime. The
remaining warnings are only `noArrayIndexKey`, `noExplicitAny` and `noAssignInExpressions`.
`build/lintConfig.test.ts` guards that severity and the strict-JSON landmine below. CI runs
`check`, `typecheck`, `test` and `build` on every PR, plus `npm audit --audit-level=high`.

## Source Layout (`src/`)

Many entries below name a module as **the one declaration** of some rule. That phrasing is load-
bearing: each of those exists because the same predicate had been hand-written at several sites
and the copies drifted. Reuse them rather than re-rolling the logic.

- **`pe/`** — PE parser (headers, imports, exports, resources, authenticode). `ordinalTables.ts`
  is generated from pefile's `ordlookup` — do not hand-edit; imphash must agree with pefile or it
  matches nothing. It also owns the **one declaration of the `Ordinal_<n>` spelling** —
  `ORDINAL_IMPORT_PREFIX`, `formatOrdinalImport`, `parseOrdinalImport`, `resolveOrdinal` — because
  that string is a *wire format* the parser writes and `computeImphash` reads back, not a label. `sections.ts` owns `findCodeSection`/`isCodeSection`/`dataSectionRanges` (the
  `.text`-or-executable predicate, previously written at seven sites). `buildSectionIndex()` +
  `rvaToFileOffsetIndexed()` in `parser.ts` are the batch form of `rvaToFileOffset`.
  `arm64Unwind.ts` decodes both ARM64 unwind encodings.
- **`disasm/`** — engine, types, CFG, operand parsing, stack analysis, signatures.
  - `capstoneWindow.ts` owns **every** call into the Capstone decoder; nothing else may call
    `cs.disasm`. `capstoneReader.ts` is the decoder underneath — a hand-written `cs_insn`
    marshaller (~3x faster than capstone-wasm's) and the only place allowed to call
    `loadCapstone`.
  - `arch.ts` maps `coffHeader.machine` to an `ImageArch` and holds `unsupportedOnArch()`.
    **Never select a decoder with `is64`** — that is the PE32+ magic and true for ARM64 too.
  - `funcInsns.ts` — "what does one function's decompilation need out of a whole-image
    collection": `collectFuncInsns`, `funcXrefEntries`, `funcExceptionRecord`. Imports nothing but
    types, which is what lets `disasmClient.ts` and `decompile/pipeline.ts` share it.
  - `ripRelative.ts` — all `[rip ± 0x..]` parsing (was hand-rolled nine times).
  - `linearSweep.ts` — the one x86 linear sweep (`sweepX86`), its session memo (`X86SweepCache`),
    and `gridScan`, which serves `hybridDisassemble` from that held sweep.
    `sectionMemo.ts` holds the memo key rule (bytes, load address, decoder identity).
  - `stackIdiom.ts` — the `push <imm>`/`pop <reg>` pairing rule; **a leaf that imports nothing**,
    so `decompile/lifter.ts` can share it with `functionDetect.ts` without inheriting a Capstone
    edge.
  - `callSummary.ts` (what a callee modifies), `seeds.ts` (jump tables → descent seeds),
    `dataWindows.ts` (`.rdata` spans for x64 jump tables), `seh32.ts` (MSVC 32-bit SEH scope table
    as a funclet-of-parent relation).
- **`disasm/arm64*.ts`** — `arm64.ts` (fixed-width sweep + `Arm64SweepCache` + jump-table reader),
  `arm64Operands.ts` (**the single A64 branch/address grammar** — do not hand-roll a second),
  `arm64Frame.ts` (the A64 stack frame from `.pdata` — a *second grammar*, not a relaxation of
  `stack.ts`'s; `stackFrame.ts` dispatches between the two), `arm64Xref.ts`. Everything x86-shaped
  — the decompiler, x86 xrefs, IRP dispatch, signatures — **declines on ARM64 rather than
  guessing**. Gated by `npm run corpus:arm64`.
- **`disasm/decompile/`** — IR lifting → SSA → folding → structuring → cleanup → type inference →
  promotion → struct synthesis → emission.
- **`components/`** — the disassembly view is split across `DisassemblyView.tsx` (orchestration),
  `DisassemblyRows.tsx` (virtualized rows), `DisassemblyToolbar.tsx`, `InsnContextMenu.tsx`.
  `XrefPanel.tsx`'s `scopeAvailable()` is the one declaration of "has the caller given this panel
  the address this scope needs", read by the filter chain *and* by the scope buttons, with
  `effectiveScope` the thing everything on screen reads — `scopeMode` is the user's preference and
  may outlive its address. `floatingClamp.ts`'s
  `clampFloatingPosition` is the one declaration of where a floating bottom panel may be —
  read by the header drag, `handlePopOut`'s mint and the render-time derivation in
  `BottomPanelContainer.tsx`, and deliberately taking **no height**, since a whole-panel-inside
  rule pins a panel taller than the window. The clamped position is **derived, never written
  back** — a callback spreading that derived object into `poppedOut` replaces the user's stored
  position with the picture of it, which is how the corner resize lost one. All
  six dialogs go through one `Modal.tsx`; its class composition, focus arithmetic and
  `accidentalDismissAllowed` rule are pure functions in `modalScaffold.ts`.
- **`hooks/`** — state (`usePEFile`), derived state, rows, search. `useDisassemblyKeyboard.ts` and
  `useGraphSearch.ts` are seams extracted from `DisassemblyView`. Pure leaf modules
  (`asyncMetricState.ts`, `decompileTabsState.ts`, `modalScaffold.ts`, `listboxIds.ts`) exist so
  hook logic can be tested without a DOM or a worker — still the cheapest way, though no longer
  the only one.
- **`workers/`** — **two** workers, and the split is not tidiness: the disasm worker services
  messages **serially**, so a checksum posted to it queues behind a multi-minute disassembly.
  - Disasm: `disasm.worker.ts` (setup), `dispatch.ts` (the RPC switch, extracted so it is
    importable under vitest), `disasmClient.ts` (caller side).
  - Metrics: `metrics.worker.ts` / `metricsDispatch.ts` / `metricsClient.ts`, stateless.
  - `transfer.ts` (`prepareBinaryArgs`, which every RPC's args go through), `blobSource.ts` (the
    `WeakMap<ArrayBuffer, Blob>` registry shared by both clients and dispatches),
    `requestTimeout.ts` (`REQUEST_TIMEOUT_MS` and `WorkerTimeoutError`, a leaf because both have
    readers outside the client).
  - Both clients build their `Worker` on first use via a private `ensureWorker()`; `send` builds
    inside its own `try`, so with no `Worker` at all the *request* rejects instead of the caller
    throwing — which is what makes `DisassemblyView` mountable under jsdom. The four
    client-side-state methods deliberately do not go through it.
- **`analysis/`** — driver detection, anomalies, IOCTL decoding. `isPlausibleIOCTL` is a *shape*
  test most 32-bit values pass, so decoding also requires the call site (`ioctlCodeArgIndex`);
  without that gate the emitter produced 1475 confident wrong IOCTL comments.
- **`llm/`** — `models.ts` is the single source of model IDs and token budgets — **never write a
  model ID anywhere else**. `apiLists.ts` owns `DANGEROUS_APIS`/`NOTABLE_APIS` (notable is a
  superset by construction) and `matchesApi`; `decompileForLLM.ts` is the one
  decompile-for-context routine; `retry.ts` the backoff policy; `responseSchema.ts` zod
  validation.
- **`ghidra/`** — REST client for the optional server in `ghidra-server/`; powers the decompile
  panel's **High Level** tab. Not a decompiler.
- **`mcp/`** — MCP server (tools, resources, session, Capstone wrapper), `cli.ts`, `clients.ts`,
  `paths.ts`.
- **`utils/`** — recent files (IndexedDB), export schema, entropy, fuzzy match.

## Architecture

**State**: `useReducer` + React Context in `src/hooks/usePEFile.ts`. `AppState` (34 top-level
fields) and an `AppAction` discriminated union (55 action types), both counted at `1c3de72` —
counts drift, so re-measure rather than trusting them. Access via `useAppState()` /
`useAppDispatch()`. New state = add an action to the union, handle it in the `appReducer` switch.

`appReducer` is covered branch-by-branch in `src/hooks/__tests__/appReducer.test.ts`. **Two
invariants that suite pins and you must preserve**: a no-op branch returns the **same object
reference** (a new equal object causes pointless re-renders), and every mutating action
**replaces** rather than mutates — the annotation undo/redo snapshots hold direct references to
annotation objects, so an in-place mutation would corrupt history retroactively.

**`VIEW_TABS` (in `usePEFile.ts`) is the single declaration of the nine view tabs and their
order.** `AddressBar`'s tab bar and its 1-9 `TAB_KEYS` shortcut map are both derived from it, with
labels from `VIEW_TAB_LABELS` in `components/analysisNotice.ts` — previously written out three
times, so a tab could be called one thing on its button and another in the notice telling you to
open it. `VIEW_TAB_LABELS` is a `Record<ViewTab, string>` and fails the build on a missing tab
where an array would silently drop it. `parseViewTab()` narrows the `#tab=` URL parameter; do not
cast that string to `ViewTab`.

### Analysis phases and the notice

**`AnalysisPhase` has THREE terminal values besides `"ready"`, and telling them apart is the
point.** The class of defect behind all of them is a terminal state that is never entered, leaving
a spinner that can never resolve.

- **`"failed"`** — the analysis chain rejected. Without it a failed parse left the UI spinning.
- **`"no-code"` — not a failure.** A PE with no executable section (a resource-only DLL, i.e. an
  ordinary satellite/MUI file) makes `findCodeSection` return undefined and App's effect returns
  *above* the first `SET_ANALYSIS_PHASE` it dispatches. The parse succeeded, nothing went wrong,
  and every parser-derived tab is populated — **do not relabel it `"failed"`**.
- **`"timed-out"` — a fault, but not about the file.** `REQUEST_TIMEOUT_MS` is one budget for
  every RPC (correctly, since the worker is serial), and every rejection used to reach the user as
  `"failed"` — exactly what a truncated file produces, so a user whose large image merely needed
  longer was told the same thing as a user who dropped a corrupt one. It is a **phase, not a flag
  beside `"failed"`**: a phase is single-valued and `RESET` returns it to `"idle"`, so the fact
  cannot outlive the run it describes, where a parallel boolean needs clearing at load *and*
  wherever a re-analysis starts and a stale one reports the next file's genuine parse failure as a
  timeout. Distinguishable because the watchdog **mints a class**, `WorkerTimeoutError`
  (`workers/requestTimeout.ts`); `analysisRejection` (`analysisNotice.ts`) is the pure function
  App's `catch` reads, pure because nothing here renders a component so an inline `catch` body is
  unreachable by any test. Note the asymmetry: only a *client-side* rejection can be an instance,
  since an error thrown inside the worker is flattened to a string before it crosses
  `postMessage`. The timeout's message is recorded **verbatim**, without the `"Analysis failed: "`
  prefix, or the notice interpolates those words into the sentence saying the analysis did not
  fail. (`peek-a-bin-meai`)

**Whether a phase means "still working" is `ANALYSIS_IN_PROGRESS`**, a `Record<AnalysisPhase,
boolean>` in `usePEFile.ts` that `StatusBar` and `Sidebar` both read. It replaced a hand-written
`phase !== "idle" && !== "ready" && !== "failed"` chain written at three sites — a shape that
defaults any phase added later to "still analysing", i.e. a spinner that can never resolve. A new
phase must fail the build here instead (`peek-a-bin-bo3b`).

**`analysisNotice()` (`components/analysisNotice.ts`) has six kinds, and they are RANKED**:
`"unsupported-arch"` → `"no-code-section"` → `"engine-unavailable"` → `"analysis-timed-out"` →
`"analysis-failed"` → `"partial-detection"`. Each carries **`isFault`**, and **all five render
sites — three in `App.tsx`, one in `DisassemblyView.tsx` and one in `StatusBar.tsx` — read
that** rather than testing the kind;
each had spelled `kind === "analysis-failed"` by hand to pick red over amber, which is a predicate
a new kind joins on the wrong side of silently. That is not hypothetical: the fifth site was
missed, and two `isFault: true` kinds rendered amber in the status bar while the same notice
rendered red in App's banner — one notice, two colours, on screen at once (`peek-a-bin-n7q1`).

**THE SAME HAND-WRITTEN-PREDICATE CLASS WAS FOUND TWICE MORE, IN `AnomaliesView.tsx`, AND BOTH ARE
NOW CLOSED.** Its AI-findings palette was a ternary chain over `AIScanFinding["severity"]`
(`=== "critical" || === "high" ? red : === "medium" ? amber : blue`), and both anomaly tables were
keyed `Record<string, …>` so a fourth severity compiled, sorted last behind `info` and rendered in
`info`'s blue — a new severity silently painted as the mildest one. Both are now keyed on the
union, so a sixth member fails the build the way `DETECT_PASS_LABELS` and `VIEW_TAB_LABELS` do
(`peek-a-bin-p0qw`). The **third** site was `AddressBar.tsx`, which answers a *different* question
of the same union — the maximum severity across anomalies and findings — with its own
`=== "critical" || === "high"` chain and a third palette; it was closed at `1591289` by
`components/severity.ts`, and the paragraph on that module below is the current statement of the
rule. **Read that one for the identifiers**, which are `BADGE_RANK`, `ANOMALY_BADGE` and
`FINDING_BADGE`.

Rank reasoning, which is the part to preserve: the two **properties of the file** come first
because each survives the engine being fixed (an ARM32 resource-only DLL has no disassembly on a
healthy engine either); `"engine-unavailable"` next because its remedy is a page reload rather
than a retry, and `init()` is watchdogged by the same timer so an engine that never answers *is*
itself a timeout — reporting the chain's timeout there would report the symptom; then the timeout,
because a run the watchdog stopped did not fail and `"analysis-failed"` would print the watchdog's
message as a diagnosis of the file. `"partial-detection"` (fed by `AppState.omittedPasses` from
`DetectResult.omitted`) is deliberately **not** reported on top of an unsupported architecture,
which already implies every decoder-fed pass; on a failure its sentence is *appended* rather than
substituted, since which stage threw and how much survived are different facts.
`"no-code-section"` lists the populated tabs from `PARSER_DERIVED_TABS` rather than spelling them,
so the prose cannot disagree with the buttons.

**`"analysis-timed-out"` is the one fault kind whose `unavailableTabs` is EMPTY**, and that is
deliberate: the three withholding kinds can never populate the disassembly, but a timeout
routinely can — `buildAllXrefs` is the *last* stage, so a timeout there leaves a complete function
list and disassembly with only the xrefs missing. Naming `DECODER_DERIVED_TABS` would print "Still
available: everything else" over a fully populated panel. For the same reason `DisassemblyView`
deliberately does **not** take that kind into its replacement arm — replacing the panel would
delete a real disassembly in order to explain its absence.

**`AppState.disasmFailed` is the engine's own session-level fact** (`SET_DISASM_FAILED`, which
sets `error` too). `disasmWorker.init()` rejecting used to dispatch a bare `SET_ERROR`, and
`state.error` renders only in `FileLoader`, which is unmounted whenever a PE is open — so an
engine that died under a loaded file said *nothing*, while three surfaces spun "Loading engine..."
off `!state.disasmReady`, which a rejection never clears. `RESET` carries it across a load exactly
as it carries `disasmReady`: Capstone is initialised once per tab, so a dead engine is still dead
for the next file (contrast the phases above, which must not outlive their run). App's detection
effect must dispatch a **terminal phase** for it, above `analyzedBufferRef`, and for **both**
orders — a file opened after the engine died, and an engine that dies with one open, which is why
`state.disasmFailed` is in that effect's dependency array. The two surfaces that cannot reach the
notice (the tab bar renders beside it; the panel's arm is an early return) are told directly, or
they keep claiming the engine is loading while the banner says it failed (`peek-a-bin-b3jn`).

### Worker and pipeline

**Worker**: RPC-style, `src/workers/disasmClient.ts`. Heavy work (disassembly, detection, xref
building, decompilation) runs off-thread. The client caches results (disasm, xref, decompile) and
mints the instruction-array tokens the worker's derived caches key on (`insnsTokens`; **the
counter never resets, so a token cannot be reused across files**). Whole-file checksum and entropy
go to the separate metrics worker; inputs under the thresholds in `asyncMetricState.ts` (256 KiB
for the entropy strip, 1 MiB for file metrics) stay synchronous and spawn no worker, so ordinary
binaries never show a loading state.

**Where a `File` exists it is posted instead of a copy.** A `Blob` is structured-cloneable *by
reference*, so posting the original `File` is O(1) at any size and the worker reads the bytes
itself — taking the last main-thread cost in that path (`prepareBinaryArgs`' slice, ~100 ms for a
253 MiB file) to zero. **But only the drop/browse path HAS a `File`**: `loadRecentFile()` returns
an `ArrayBuffer` from IndexedDB and the demo binary arrives via `fetch().arrayBuffer()`, so two of
three load paths still copy. `App.tsx` calls `registerSourceBlob(buffer, file)` on **both** clients
beside the `bufferRef` assignment, only after a successful parse; the registry is a
`WeakMap<ArrayBuffer, Blob>` so nothing needs tearing down, and with no registration the buffer is
posted exactly as before. Three things not to undo: the result cache stays keyed on the
`ArrayBuffer`, not on what is posted, so the Headers and Sections tabs still share one request; a
Blob must pass through `prepareBinaryArgs` untouched, being neither a buffer nor a view with no
synchronous way to copy one; and the size check in `sourceFor` is a **wiring** check catching a
mis-paired handle, not an on-disk change. `extractStrings` takes the same handle — it is the only
disasm RPC whose binary argument is the whole image, since the scan addresses every section by
absolute `pointerToRawData`. **It moves work off the main thread; it does not make the work
smaller.** The rule is declared once, in `workers/blobSource.ts`, shared by both clients and both
dispatches; the **registries stay per-client** deliberately, since whether a client has been told
is a fact about that client's wiring. `extractStrings` must be **no more gated than the buffer
arm** — it is the one parser-derived answer coming back over this RPC, and an arch gate added
there by symmetry would empty the tab the notice has just told the user to open
(`peek-a-bin-ex2`, `peek-a-bin-736`).

**Pipeline**: File drop → `parsePE()` → detect functions (worker) → hybrid disassemble (recursive
+ gap-fill, seeded with jump-table case targets from `seeds.ts`) → build xrefs → extract strings.
All async, phased via `analysisPhase`. The decoder is chosen from `coffHeader.machine`
(`disasm/arch.ts`): x86/x64 take recursive descent + gap fill, ARM64 the fixed-width sweep.

### Architectures, and refusing one

`archForMachine()` returns `ImageArch = TargetArch | "unsupported"`. `"arm64"` for 0xAA64; `"x86"`
for I386/AMD64 **and for `undefined`**, which means "the caller never told us" and keeps every
un-threaded call site at its pre-ARM64 behaviour; `"unsupported"` for everything else (ARM32/Thumb,
IA-64, RISC-V, MIPS). `ImageArch` is a *widening* of `TargetArch` rather than a replacement, so a
stage that has only ever run after a supported architecture was confirmed keeps the narrow type
and fails to compile rather than falling through.

**The refusal is deliberately ASYMMETRIC — a judgement, not an oversight. Do not collapse it into
one behaviour:**

- **Throw** from stages whose entire output is instructions — `disassemble`,
  `hybridDisassemble`, `buildAllXrefs`, `decompileFunction` (`workers/dispatch.ts`,
  `mcp/disasm.ts`). An empty instruction list is indistinguishable from a correct answer.
- **Return empty, with `DetectResult.omitted` populated**, from function detection. An ARM32 file
  still yields the headers, sections, imports, exports, resources and strings the PE parser gets
  right — those are format-level facts and a user should get every one. `mcp/session.ts` guards
  its two throwing calls behind a `decodable` flag for exactly this reason: an unguarded throw in
  `loadFile` discarded all of it.

**`DetectResult.omitted: DetectPass[]`** names the decoder-fed passes that did not run —
`"call-targets" | "jump-tables" | "thunk-names" | "tail-calls"` — and is **empty when the answer
is whole**. It covers both the unsupported architecture and a null Capstone handle, where
detection keeps answering from `.pdata`, exports, the entry point and unwind handlers. It exists
because a narrower answer used to be the same shape as a complete one. Only passes the
architecture actually has are ever listed. `DETECT_PASS_LABELS` is a `Record<DetectPass, string>`,
so a wire value like `call-targets` cannot reach the screen and a fifth pass fails the build.

### Rendering and the rest

**Rendering**: virtual scrolling via `@tanstack/react-virtual`. `DisplayRow` union:
`label | insn | separator | data`. `DisassemblyView` + `HexView` are lazy-loaded.

**There is ONE `ErrorBoundary` PER TAB PANE, and the placement is the whole of what it buys.** A
single boundary around `renderMainView()` — which is what was there — put every tab behind one
`hasError`: `App` keeps every visited tab in the tree class-hidden, so a throw in the Hex view
replaced headers, sections, disassembly, imports, exports, strings, resources and anomalies as
well, and because `hasError` is never cleared on a re-render and the boundary sat *above* the tab
switch, changing tabs could not recover it either. The only exit was a page reload, which discards
the parsed image and the worker's disassembly to recover from what may have been one bad render.
The boundary takes a **`label`** (`VIEW_TAB_LABELS[key]`, so the fallback cannot call a tab
something the tab bar does not) and offers **Try again** beside Reload — cheapest exit first.
**Not clearing on a re-render is a decision, not a leftover**: an automatic reset would retry a
deterministic fault on every parent render and flicker the fallback in and out with no way to read
it, so recovery is explicit. Blast radius is asserted in `src/__tests__/App.dom.test.tsx` by
`vi.mock`ing one tab's component to throw on a flag; nothing static can see any of this, since
`typecheck` accepts a boundary with neither `getDerivedStateFromError` nor `componentDidCatch` and
`componentDidCatch` has no signature to inspect (`peek-a-bin-p0qw`).

**…and FOUR CHROME REGIONS now have one too, on a criterion that is stated once, in
`ErrorBoundary`'s own docstring: guard a region exactly when the app is still worth using without
it.** The `variant` prop (`"pane" | "chrome"`) is the mount site saying how much room it has, the
way `label` says what it is guarding — the pane's centred card overflows a 224px sidebar column and
dwarfs a 20px status strip, so `"chrome"` is one line sized to its own text, and it deliberately
offers **no Reload**: a chrome boundary is only ever placed where the session is otherwise intact,
so discarding the parsed image and the worker's disassembly is the wrong trade to put one click
away. Guarded: **`Sidebar`** and **`StatusBar`** (in `App`), **`AIChatPanel`** and
**`BottomPanelContainer`** (in `DisassemblyView`). **Loudness is not a second criterion competing
with the first** — `componentDidCatch` logs the stack either way and the fallback additionally
*names* the region, which a blank page does not.

**`AddressBar` is deliberately LEFT LOUD, and the argument is a measurement rather than a
preference**: it owns the global `window` keydown handler carrying the 1-9 `TAB_KEYS` map, so a
boundary would remove **both** routes to another tab, not just the buttons, leaving an app pinned
to whichever tab was showing. No partial function is bought, so the boundary would only convert an
unmistakable blank page into a half-working app that gets worked around instead of reported. The
suggested middle in `peek-a-bin-t23y` grouped `StatusBar` with it; **measured, that is wrong** —
the status bar's only navigation affordance is a jump to the containing function, duplicated by the
sidebar and by the listing.

**Two measured corrections to that bead's premise, worth keeping**: `AIChatPanel` and
`BottomPanelContainer` mount inside `DisassemblyView` and were therefore never a blank page — they
sat inside the *pane's* boundary, and what a throw cost was the listing, toolbar, graph and
decompile panel, which is `p0qw`'s own argument one level down. **`DecompileView` and `CFGView` get
no boundary on purpose**: they *are* the pane in the mode that shows them, so the pane's boundary is
already the right radius.

**The six dialogs are guarded by a DIFFERENT class, `DialogBoundary.tsx`, and the split is the
mechanism rather than the criterion.** They pass the criterion trivially — they are overlays — but
could not use `ErrorBoundary`'s fallback for two reasons, and both are now measured rather than
argued. (1) A dialog's subtree carries its own backdrop, focus trap, scroll lock and Escape, all of
them `Modal`'s, so the ordinary card renders where that chrome would have been: floating in `App`'s
root, undimmed, with no way out, over a dialog still `open` in state. The fallback here is itself a
`Modal`, and Escape, the backdrop and its one **Close** button all call the caller's own `onClose`.
(2) `hasError` never clearing would mean one throw in the palette makes **Ctrl+P silently do nothing
for the rest of the session**; the reset is keyed on the dialog's own **closed → open transition**,
which is a NAMED trigger and leaves the rule below untouched — it is a different class in a
different file, and `"pane"`/`"chrome"` cannot reach it. Three things not to undo: the boundary is
**outside** the dialog, not inside `Modal` around its children, because every one of these dialogs
runs hooks and memos above its own `if (!open) return null`, so the common throw happens before
`Modal` renders at all; a caught-and-then-closed boundary renders **nothing**, never the children,
or that same pre-`open` code throws again with the boundary spent; and the reset is in
`getDerivedStateFromProps`, not `componentDidUpdate`, so re-opening produces one commit instead of
painting the fallback first. `dialogBoundaryRender` and `dialogBoundaryReset` are the rules, pure,
in `modalScaffold.ts`. **The wrong version was built first and measured**: wrapping each dialog in
the existing `ErrorBoundary` passes a naive blast-radius assertion and fails both halves that matter
(`peek-a-bin-pikv`).

**`main.tsx` still puts no boundary above `<App/>`**, deliberately: that is a whole-page fallback
whose argument is crash reporting rather than partial function, and it is a separate question
(`peek-a-bin-t23y`).

**The view switcher is a WAI-ARIA tablist, and the pattern is all-or-nothing.** `AddressBar`
renders `role="tablist"` around exactly the nine tabs (not the toolbar, which also holds
Open/Back/Forward/Undo/Redo and the address field), each `role="tab"` with `aria-selected`, `id`,
`aria-controls` and a **roving tabindex that follows FOCUS, not selection** — cleared when focus
leaves, so tabbing back in lands on the tab that is showing. **Activation is MANUAL**: arrows move
focus, Enter/Space selects, and *nothing in the component handles either key*, because a real
`<button>` already fires `onClick` for both and a second path would dispatch `SET_TAB` twice. That
is a cost decision, not a style one — `App`'s `tabComponents` marks `DisassemblyView` and `HexView`
lazy and `mountedTabs` never unmounts, so automatic activation would import *and permanently mount*
both chunks for one sweep across the bar. `App.renderMainView` renders a **wrapper for every tab**
and mounts the component inside only once visited, so `aria-controls` can never dangle while
mounting behaviour is unchanged; omitting the attribute instead would have put App's mounting rule
in AddressBar as a second declaration. Ids come from `components/tabIds.ts`, on `listboxIds.ts`'s
model, because both ends of every reference are written in different files. `tabIndex={0}` on the
**shown** panel only: most panes are static tables with no focusable content, so without a stop a
keyboard user cannot reach the region they just switched to. The arrows are documented in
`docs/keyboard.md` and **deliberately absent from the `?` panel** — every other entry there is a
*global* binding, and bare arrows belong to the disassembly view everywhere outside the bar
(`peek-a-bin-w50c`).

**A severity's ORDER is declared once, in `components/severity.ts`; the PALETTE is not.**
`ANOMALY_BADGE` and `FINDING_BADGE` fold two different unions onto one `BadgeLevel`, `BADGE_RANK`
orders it, and `maxBadgeLevel` reduces both lists at once. `AnomaliesView` and `AddressBar` each
keep their own `Record<BadgeLevel, …>` of class names, because a table row (`-900/20`, `-300`,
`-600`) and an 8px dot (`-500`) legitimately differ — sharing the mapping is the point, sharing the
colours is not. The unknown-value fallbacks stay **at the call sites and are deliberately
different**: an unknown severity sorts *last* and paints *blue* in `AnomaliesView` but reads as the
*mildest* in `maxBadgeLevel`, which is why the module exports raw lookups rather than one total
function — folding them would have quietly changed a sort an existing test pins
(`peek-a-bin-rl95`).

**CFG**: `buildCFG()` + `layoutCFG()` (dagre) in `src/disasm/cfg.ts`; inline graph toggled with
Space.

**Styling**: Tailwind utilities; runtime font size via a `--mono-font-size` CSS variable on the
app root.

**AI features**: four tools — Chat (`useAIChat`), Batch Rename (`useBatchRename`), Report
(`useAIReport`), Vulnerability Scanner (`useVulnScanner`) — all using `streamChat()` from
`src/llm/client.ts`. Chat panel is local state in `DisassemblyView`; the other three keep state in
`AppState`. Triggered via custom events (`peek-a-bin:open-chat`, `:batch-rename`,
`:generate-report`, `:ai-scan`). Markdown via `marked` in `MarkdownRenderer.tsx`.

## Conventions

**File naming**: components = PascalCase.tsx, hooks = useCamelCase.ts, modules = camelCase.ts.

**localStorage**: `peek-a-bin:<feature>` namespace (`peek-a-bin:llm-profiles`, `:font-size`,
`:view-mode`, `:chat:${fileName}`, `:report:${fileName}`, `:chat-width`). Legacy
`peek-a-bin:llm-settings` auto-migrates to `:llm-profiles` on first load.

**Custom events**: `window.dispatchEvent(new CustomEvent("peek-a-bin:<action>"))` for
cross-component communication.

**`DisplayRow` has exactly one declaration** — the exported union in `useDisassemblyRows.ts`.
JumpArrows and DisassemblyMinimap used to keep private narrowed copies that had to be hand-synced;
they now `import type` the canonical one. Do not reintroduce a local copy: a narrowed structural
clone still accepts the canonical rows at the call site, so it drifts silently instead of failing
the build.

**Annotations**: bookmarks, renames and comments auto-persist to localStorage per file; undo/redo
via a snapshot stack.

### Tests

Suites sit beside what they cover: `src/pe/__tests__/` (including `malformed.test.ts` for
adversarial input and `metadata.test.ts`, which pins the hand-rolled MD5 against the RFC 1321
vectors *and* differentially against Node's `crypto` — a wrong digest is invisible at runtime
because nothing cross-checks a hash), `src/disasm/__tests__/`,
`src/disasm/decompile/__tests__/`, `src/hooks/__tests__/`, `src/mcp/__tests__/`,
`src/utils/__tests__/`, `src/workers/__tests__/`, `src/llm/__tests__/`,
`src/components/__tests__/`. Use `buildMinimalPE32()` / `buildMinimalPE64()` from
`src/pe/__tests__/fixtures.ts` — **no binary files**. **Don't hard-code a test count anywhere; it
goes stale within a session.** Run `npm test`.

`src/disasm/decompile/__tests__/pipeline.test.ts` is the **end-to-end** one: instructions in,
emitted C out. `decompileFunction` takes `Instruction[]` rather than bytes, so it needs neither
Capstone nor a worker, and hand-writing the instruction stream makes the intended semantics
explicit instead of trusting a disassembler to agree. **Reach for it whenever a change could alter
emitted output** — a whole class of defect (see the condition-polarity gotcha) is invisible to
stage-level tests, because they assert on the IR the buggy code produced.

**Component tests are the `*.dom.test.tsx` files and the ONLY ones that render React.** Each opts
in with two things, since the default environment is node and stays that way: the
`@vitest-environment jsdom` marker in a `//` comment on the **first line**, and `import
"…/test/domSetup";`. `build/domTestNaming.test.ts` fails the ordinary suite if either is missing,
or if a DOM-rendering test hides under an ordinary name. Three things to know before adding one,
all measured (`vitest.config.ts` and `src/test/domSetup.ts` carry the numbers):

- **`test.projects` — the documented Vitest 4 replacement for the removed `environmentMatchGlobs`
  — BREAKS `--dir`.** The CLI flag is not propagated into project configs, so a two-project config
  runs every file instead of the directory you named. `--dir` is how the gates are invoked and how
  a root run is kept out of sibling worktrees, so it was implemented and reverted.
- **A global `setupFiles` entry costs ~3s**, because vitest loads a setup module once per test
  file and most want nothing from it — even with the whole body behind a `typeof document` check.
  Hence the per-file import.
- **`@vitejs/plugin-react` is NOT used and is not needed.** Vite transforms `.tsx` with esbuild,
  reading `jsx: "react-jsx"` from `tsconfig.json`; the plugin's value is Fast Refresh and a Babel
  pipeline, and a test run uses neither. So the node suites pay nothing for the DOM opt-in.

### Drift guards

Several suites **scrape source text** rather than call it — the `.disasm(` scan in
`capstoneWindow.test.ts`, the import-graph check in `mcp/__tests__/importGraph.test.ts`, the
`dispatch.ts` purity check, `keyboardShortcuts.test.ts` against `docs/keyboard.md`. They are cheap
and catch a whole class of silent regression, but **they encode formatting by accident: write the
pattern so a reformat cannot break it.** `build/guardShape.test.ts` is the same family used
against itself — it pins the one grammar `corpus/sweep.ts` reads a guard line with, and fails if
any other file under `corpus/` alternates two guard keywords in a regex. It **cannot see a
single-keyword copy**, which is how `selfAssigns.ts`'s `FOR_HEADER` survived; that reader was
brought under the grammar rather than the guard widened, and the reason widening was refused is in
the guard's own docstring.

Sturdier variants read *structure* rather than text: `analysisNotice.test.ts` asserts the **order**
of two regex matches (the notice's branch must precede the spinner and error branches in
`DisassemblyView` and `StatusBar`); `hooks/__tests__/disasmHandlerDeps.test.ts` walks the
TypeScript AST and fails if `useDisassemblySearch` stops returning a `useMemo`, or if
`handleKeyDown` grows a read without a dependency entry or an entry without a read;
`build/lintConfig.test.ts` parses `biome.json` and fails if it stops being strict JSON or if
`useExhaustiveDependencies` drops below `error`.

**`DOC_ONLY_KEYS` needs a liveness half, and the hole was found by a control coming back inert.**
`keyboardShortcuts.test.ts` compares `SHORTCUT_GROUPS` against `docs/keyboard.md` as key-token
sets, with `DOC_ONLY_KEYS` exempting keys the `?` panel deliberately omits. An exemption only ever
*skips* a doc→panel check, so **a key could leave the documentation entirely while the entry
excusing it stayed behind**, reading as if it were still documented — deleting the doc rows and
keeping the exemptions left the suite green. It now asserts the other direction too: every
`DOC_ONLY_KEYS` entry must name a key the doc still documents. Same family as
`build/guardShape.test.ts` — an instrument judging the audit, because a guard whose population has
emptied passes by no longer looking (`peek-a-bin-w50c`).

**Two AST guards pin the threshold-and-worker pattern and fail in OPPOSITE directions** —
`analysis/__tests__/anomalyOffThread.test.ts` and `hooks/__tests__/fileMetricsOffThread.test.ts`.
Dropping the anomaly threshold puts multi-second walks on the main thread for a large file;
dropping the metrics one puts a worker round trip on every *small* file, i.e. a loading state on
every ordinary binary, which is the thing the sync path exists to prevent. Both assert which
**side** of the size comparison each callback sits on, so an *inverted* guard fails and not only a
deleted one, and the metrics one is table-driven over both thresholds so a swap between the two
hooks fails. Their helpers are deliberately duplicated: `useFileMetrics.ts` has no `if` statement,
so the anomaly guard's `ts.IfStatement` reader does not transfer. Neither executes a hook
(`peek-a-bin-yvr1`).

**Hook logic is otherwise tested by extracting the decision into an exported pure function** —
`parseAnnotationMessage` (`useMcpSync.ts`), `modalScaffold.ts`, `listboxIds.ts`,
`asyncMetricState.ts`, `decompileTabsState.ts` — or by checking a dependency array against the
function body over the AST. Prefer that where it works: a pure test is cheaper and needs no DOM,
where a jsdom test costs ~2s of environment setup per file.

**MCP setup CLI**: `npx tsx src/mcp/index.ts setup <client>` configures AI clients (claude-code,
opencode, continue). Registry in `src/mcp/clients.ts` — add a client by inserting a map entry.
`.mcp.json` at the project root enables Claude Code auto-discovery.

## Verification status — what is measured and what is not

**Full record: [`docs/verification.md`](docs/verification.md)** — every per-binary figure, every
per-change delta narrative, every negative-control enumeration. This is the working summary; go
there for a number.

Every suite in `src/` is synthetic. Real binaries were first driven through the tool on
2026-08-11: real MSVC output covering PE32, PE32+ and ARM64 (pip `distlib`'s `t64.exe` /
`t32.exe` / `w64.exe` plus the two ARM64 launchers), headlessly, no browser. **Keep this section
honest — the distinction between *measured* and *reasoned* is the point of it.**

### Standing rules for reading anything here

- **Treat the ratio as the claim and the absolute as a date-stamp.** Every denominator moves
  whenever function detection changes, which is often and usually because a defect was fixed.
  A number going stale is normal; a ratio falling below 1, or a gate leaving 0, is not.
- **Anyone quoting a bare historical figure is probably quoting a fixed defect or a stale
  count.** This file has had to retire several. Do not argue from a number without its commit.
- **Pin BOTH sides of a comparison to one commit.** A base sweep taken against a moving HEAD
  silently compares your change against someone else's. `npm run corpus:compare -- <base>
  <change>` takes artifact *paths* (`corpus/artifacts/<label>`), not labels.
- **Stamp every count recorded in a bead with the commit it was taken at.** An unstamped count
  becomes a trap the moment detection moves: the next agent re-measures, gets something else,
  and spends its budget deciding whether it broke something.
- **A missing corpus directory SKIPS and still exits 0.** A green run is not always a run —
  confirm the report header names **four** binaries. That default-path-becomes-skip-path failure
  is why there is no absolute default (`peek-a-bin-alx1`).
- **Every gate is negative-controlled** — perturb the code and confirm the row goes red, and
  confirm the row is also asked over well-formed input (a test checking only the red direction
  passes against an audit that has stopped looking). **An INERT control must be reported, not
  tuned away.** Several have been; they are recorded in the tests themselves.
- **A green row over an empty population says nothing.** Where an audit's zero is vacuous it is
  marked below. A rule that reaches 0 *by no longer looking* is the recurring failure mode here,
  which is why most audits carry a liveness half (a denominator that must be non-zero).

### The harnesses

They live in `corpus/`; `corpus/README.md` says what each audit proves and what a failure means.
Deliberately outside `npm test` — they need real MSVC binaries not in the repo, and a C compiler.
Nothing here is re-checked unless someone re-runs it.

- **`npm run corpus`** — the four x86 binaries, and nothing else.
- **`npm run corpus:arm64`** (`corpus/arm64.ts`) — `t64-arm.exe` / `w64-arm.exe`, **51 gate
  assertions, all 0**.
- **`npm run corpus:comments`** — the ARM64 comment audit plus an x86 comment digest.
- **Path-taking censuses, outside the gated run**: `corpus:jumptables`, `corpus:gridserve`,
  `corpus:uploadcost`, `corpus:decompilecost`, `corpus:detectcost`, `corpus:replycost`. Each takes
  a `<path>` to any PE.

**ARM64 and the Go binary are separate runs deliberately, and the reason is the same for both:
the audits iterate over whatever binaries they find, so an extra one changes the population of
every gate and the denominator of every summed figure** (`gcc`, `offsetof`, `polarity` are sums).
Folding ARM64 in would also buy only vacuous zeros — the decompiler refuses any non-x86 image
above address resolution (`mcp/tools.ts`), so ~15 audits would draw from an empty population.
**Never put a Go binary in the corpus directory**; Go's ABI and prologues are not MSVC's.

**No default corpus directory, deliberately.** `preflight.ts` searches `PEEK_CORPUS_DIR`
(environment), then `PEEK_CORPUS_DIR` in a gitignored `.env` at the repo root, then
`$XDG_DATA_HOME/peek-a-bin-corpus`, `~/.peek-a-bin-corpus`, `<repo>/corpus/binaries` — every
candidate derived from `$XDG_DATA_HOME`, `$HOME` or the repo. An explicit setting is the *whole*
search, so a wrong override is reported about the directory you named. On this machine the
binaries are in `~/.local/share/peek-a-bin-corpus`, found with nothing set.
**Do not reintroduce an absolute default.** `build/corpusPreflight.test.ts` guards it.

### The audits — what each catches, and what is blind to it

Each of these has an oracle outside the code under test.

- **The PE parser holds, differentially against an independently written from-spec reader —
  and THE ORACLE IS NOW IN THE TREE**, as `corpus/parserDifferential.ts`
  (`npm run corpus:parserdiff`). Until 2026-08-26 that sentence was a record of a past measurement
  whose instrument had been lost with a scratch directory: five of the six `corpus/` files calling
  `parsePE` were cost censuses, and only `corpus/arm64.ts` compared the parser with anything (the
  ARM64 `.pdata` rows). Six of the seven named subjects had **no standing differential at all** —
  the `peek-a-bin-02fa` failure mode, *land the oracle*, for the third time. A run now
  re-establishes, over **all six** binaries: headers and data directories, sections, imports
  (names, order and IAT slot VAs), the checksum, imphash end to end, resources (leaves *and*
  tree shape), x64 `.pdata`, and relocations — **98 gates green, 0 red**, each with a liveness
  half beside it. pefile is not installed here, so imphash is a second reading of the ALGORITHM,
  hashed with `node:crypto`, not a comparison against pefile's output.
  - **Independence is the whole value and nothing in the language holds it.** The reference region
    uses nothing from `src/`; `build/parserIndependence.test.ts` splits the file on two banner
    comments and fails if a name imported from `src/` appears in it, with a liveness half. Without
    that guard, adding `rvaToFileOffset` to the reference turns the harness into a differential
    test between one implementation and itself and **every row stays green**.
  - **20 of the 118 gates are VACUOUS and print as such**, excluded from the green count. All six
    binaries are EXEs — **0 exports, 0 forwarders, 0 ordinal imports**, and no DLL exists on this
    machine — so the export reader and the `Ordinal_<n>` wire-format check have never run on a
    real image. They are controlled in `build/parserIndependence.test.ts` over a hand-built image
    instead. Pass a DLL as an argument and those rows stop being vacuous.
  - **Ten controls red, one INERT and recorded.** Accepting `UNWIND_INFO` version 0 — undoing
    `peek-a-bin-eu8` — moves no row, because on t64 and w64 every record resolves and every one
    carries version 1. Two report rows now print that population, so the blind spot is visible
    rather than inferred. The x64 `.pdata` half of the parser is asked **here and nowhere else**;
    ARM64 stays with `npm run corpus:arm64`, which judges it against the sweep.
  - **What a green run still does not establish**: TLS, load config, debug directory, rich header,
    Authenticode and string extraction are not compared; nothing malformed is (both readers see
    well-formed MSVC output, so every clamp and lenient continue in the parser is unreached);
    and the RVA→offset *rule* is necessarily the same in both readers, so only the parser's
    `SectionIndex` fast path is independently checked.
- **Function boundaries** are cross-checked against `.pdata` on x64 (which is authoritative), and
  on ARM64 against the sweep's alignment invariants. PE32 has no `.pdata` and still over-produces.
- **gcc / the emitted C compiles.** `gcc -std=gnu89 -fsyntax-only` over every emitted function:
  **all of them compile clean**. "All of them" is the claim. **Structurally blind to four
  classes**, all worth knowing: a wrong *register name* (`preludeFor` in `corpus/emitAudits.ts`
  declares every undeclared identifier as its own `long`, so `rcx` and `ecx` compile as two
  unrelated variables); *call arity* (an implicit declaration is accepted at any arity); an
  identifier the emitted C **does not declare at all**, at any width (`preludeFor` completes it);
  and an **undefined callee** — gcc 15.2.0 emits no diagnostic for an implicitly declared
  function at all, with or without `-w`, so there is not even a prelude declaration invented.
  Do not read "all of them compile" as evidence about naming, arity or declarations.
- **`offsetof` — struct layouts are verified by a compiled and *run* program**, not by reading
  the declaration: every definition and field lays out at the offsets its field names record,
  **ratio 1.00**. **It proves a declaration self-consistent and can NEVER see a wrong identity** —
  a fabricated struct lays out fine. The instrument for *recovery* is a different one (below),
  and adjudicating an identity means reading the emitted C against `objdump -d -M intel`.
- **`memberNameAgreement` (`corpus/emitAudits.ts`) — GATE at 0.** A struct member whose NAME and
  whose BRACKETS disagree (`uint64_t field_0x8[];` — identifier says scalar, extent says array).
  The naming half of what `offsetof` claims about layout. **Both nearest gates are blind**: gcc
  compiles a flexible array member without comment, and `offsetofCheck` reads the *same* member
  list and passes at 1.00, because the layout is right and the member's *kind* is what is
  misstated. `members`/`defs` are the liveness halves.
- **Condition polarity (`corpus/sweep.ts`) — GATE at 0 inverted**, per guard against the
  originating jcc, over all four emitted shapes (`if`, `while`, `for`, `do/while`), resolving
  candidates through `jmp`-only blocks. **Three anchoring tiers and only the strict one gates**:
  anchor **A** (the body's first line carries a block start address by itself) gates; **A2** (the
  line had to be normalised to its CFG block) and **B** (the statement after a loop) are reported
  and do not. "0 inverted" in this file has always meant anchor A. **A2 must not gate** — LICM
  hoists into a loop preheader carrying an inner block's address, so a hoisted first line with no
  rival claimant is mis-anchored silently and A2 has no oracle over the output. It judges the
  *operator*; the *operands* belong to one edge, which is `crossEdgeGuards`' business.
- **Loop exits (`auditLoopExits`) — GATE at 0 short of the machine.** Whether a loop is told about
  every way the machine can leave it; a separate audit from polarity and it found what polarity
  cannot. The defect it was built to catch is **retired** — do not go looking for it. Its
  standing blind spot: a block whose real successor `buildCFG` never drew reads as unconditional.
- **Statements `structureCFG` loses, counted by object identity — REPORT-ONLY, 0 dropped.**
  Not inferred from line-map coverage; folding and relocation cannot register in it, so it counts
  only the case that is a defect. Observed through `decompileFunction`'s optional `tap`, whose
  only caller is `corpus/sweep.ts`; emitted C is byte-identical with the audit running. Not gated
  because the short-circuit fold legitimately consumes blocks; a **rise** is a regression in
  `compare.mjs`.
- **Unrecovered values (`__unrecovered_N`) — REPORT-ONLY, and NEITHER DIRECTION IS READABLE ON
  ITS OWN.** A rise can be a *refusal* replacing a confident wrong answer (which is the repair);
  a fall can be real recovery. Only `compare.mjs` beside the polarity and stale-guard gates tells
  you which. It exists at all because `sweep.ts` used to skip any guard with no top-level
  operator, so an unrecovered guard was not a failing row — it was **not a row at all**, and
  polarity's ratio stayed 1.00 as guards fell out of the denominator. ~64% of branch conditions
  are unanchorable by construction (the emitted `if (…)` line carries no line-map entry).
- **`corpus/arity.ts` — the OVER count is a GATE at 0; exact and under are report-only.** Emitted
  call arity against `apitypes.ts`'s declared signatures — **the only oracle in the repo that can
  see arity at all**. No entry in that table is variadic, so an over-count is provably an argument
  the machine never passed. Under is not zero and no threshold on it is justified; part of it
  sits at the ABI evidence's ceiling (four fastcall registers cannot reach a five-parameter API).
  It only sees calls the table declares — a bogus argument to a `sub_` callee is invisible to it.
- **`corpus/staleGuards.ts` — GATE at 0 `named`.** A guard stating a test the machine does not
  make. **The class every other gate is structurally blind to**: the emitted comparison matches
  its jcc's taken sense so *polarity passes it*, it is not `__unrecovered_N` so the recovery
  baseline does not count it, and gcc compiles it. Two counts: `shapes` is a property of the
  *machine code* and does not move with a decompiler fix (the liveness number); `named` is the
  reading that reached the page and gates. **`named` is a LOWER bound** — it counts only guards
  the polarity pass could anchor. `emittedAtShape` beside it is report-only and is the
  *recovery*; a fall in it is what a regression looks like.
- **`corpus/crossEdgeGuards.ts` — GATE at 0 (`admitted` and `named`).** A guard wrong on ONE
  INCOMING EDGE. **Until this existed the whole corpus suite was blind to it, demonstrated by
  executing the wrong version**: answer a lone-Jcc block from its first predecessor and all 19
  pre-existing gates pass, `compare.mjs` says "no regression", and the recovery baseline scores
  it as an *improvement*. `admitted` is a differential (the disagreement rule written twice) and
  is address-exact; `named` is the oracle over the output and is the half with holes.
- **`corpus/staleReads.ts` — GATE at 0** wrong and 0 spoiled repairs. A register read naming a
  value it does not hold. Two things it must keep doing: attribute a phi's definition to each
  *predecessor* as well as the phi block (that is where `destroySSA` lands the copy), and compare
  the **name** rather than the canonical register (a correct live-range split emits two names for
  one register — which is also why a canonical name reaching the page passes here). It must run
  `foldBlock`, or it counts dominating writes that fold into their single use.
- **`corpus/popReads.ts` — GATE at 0** wrong and 0 `ret`-wrong. A register a `pop` wrote, read
  under its previous value. **A PAIRED pop leaves the population, so read `popsLifted/pops`
  beside the gate** — a rule claiming every pop would drive it to 0 by no longer looking. The
  write test must be the **machine's**, not the IR's, or it attributes other passes' defects here.
- **`corpus/lostDefs.ts` — GATE at 0.** A definition `foldBlock` deleted while a later block still
  read it. **gcc is structurally blind** (`preludeFor` again). **The discriminator is a
  before-and-after, not a scan** — a read no definition reaches is *usually correct output* (a
  function's entry value, i.e. a register parameter), so the audit brackets the fold and counts
  only reads that had a reaching definition before and none after; `entryReads` reports the
  legitimate population beside it. Its independence is weaker than the audits above: it is a
  regression gate on one pass, not an oracle outside the question.
- **`corpus/armExits.ts` — GATE at 0.** A switch arm claiming the switch is over while its block
  goes on (`break` is a *claim* about control flow, not an appendable terminator). **VACUOUS ON
  BOTH x64 BINARIES**, which recover no jump table, so `structureSwitch` never runs and a green
  row there says nothing whatever; liveness is tied to the recovered-table count. Hangs off
  `pipeline.ts`'s `StructuringTap` — the question cannot be asked of the emitted C, since a
  `break` looks identical either way. Scoped to `armExit`'s decision and `buildCFG`'s successor
  list; an arm that under-emits its *body* while spelling its exit correctly passes.
- **`emptyCaseBodies` (`corpus/emitAudits.ts`) — REPORT-ONLY, 0.** A case label whose whole body
  is `break;`. Not gated, for `armExits`' own reason: where the short-circuit fold consumed the
  target block there is no label for a `goto` and `break` is all that is left. **The nearest gate
  is measurably blind** — under the negative control this row goes 0 → 29 per PE32 binary while
  `armExits`' `falseBreaks` stays at 0 and `npm run corpus` exits 0. Read it beside `a lone goto`
  (a rule spelling every arm as a `goto` would drive `bare` to 0 by saying nothing).
- **`unencodableNames` (`corpus/emitAudits.ts`) — GATE at 0.** A register name the image has no
  encoding for (`rcx` in a PE32 function). **Asked of PE32 ONLY, and that restriction is what
  makes it an oracle** — on x64 `rcx` is a correct spelling, so the **x64 pair contributes a
  structural 0 and a green row there says nothing**; `funcs` is the liveness half. **Both nearest
  gates are blind**: gcc (preludeFor), and `staleReads` compares the *name* deliberately, so a
  canonical name reads to it as a legitimate second live range.
- **`paramClobberedAtEntry` (`corpus/emitAudits.ts`) — GATE at 0.** A declared parameter a
  callee-saved register overwrites at entry. It exists because **`offsetNamedArgs` beside it
  cannot tell a right change from a wrong one, and that is measured**: two opposite changes both
  drive that row to 0 and move nothing else in the report, one by withdrawing the parameter and
  one by *naming* all 35 home slots. So `offsetNamedArgs` is a **target** and this is the
  **gate**. First appearance, not any appearance (a callee may reuse a consumed slot as scratch);
  the volatile/callee-saved register set is what makes it a defect rather than a shape. Nothing
  else sees it — gcc compiles an unread parameter, `offsetof` only checks layouts it was given.
- **`offsetNamedArgs` — REPORT-ONLY in both directions and not gateable at 0.** How much of the
  argument area frame recovery still spells by offset. Currently 0 everywhere, i.e. a **dead**
  instrument until frame recovery regresses. **Reaching 0 is the wrong target** — see above.
- **`corpus/wildBranches.ts` — GATE at 0.** A direct branch whose target the image does not
  contain, decided against `[imageBase, imageBase + sizeOfImage)` alone. Deliberately not the
  weaker question ("leaves its function" is ordinary; "outside the code section" is arguable).
  Phrased without mentioning jump tables, so it is independent of what it caught. **A LOWER
  bound, and a loose one** — data read as code registers only where it happens to decode as a
  direct branch aiming outside the image; it saw one of two sites per binary. A green reading is
  weak evidence; a red one is proof. Every other standing instrument is blind to invented code.
- **`corpus/selfAssigns.ts` — `wrong` and `unresolved` are GATES at 0; `openOperand` is
  REPORT-ONLY.** A self-assignment in the emitted C resolved back to its instruction. What gates
  is the **instrument's integrity** (`wrong` = broken attribution; `unresolved` = a row that could
  not be judged, gated because a row silently leaving the population is how a gate reads 0). The
  interesting column cannot gate: a legitimate zero-propagation and a lost operand are the *same
  shape* from the emitted text. **This is the one visible trace a LOST OPERAND leaves, which is
  why a self-assignment must never be suppressed** — `peek-a-bin-3axd`'s 97 wrong reads were
  found through two such lines. **A faint trace**: 95 of those 97 left none, so green is weak
  evidence and red is proof. Every other gate is blind — gcc compiles `eax = eax`; a
  self-assignment *is* a reaching definition, so `staleReads`/`lostDefs` pass the reads below it.
  **The x64 population is empty, so 0 there is as vacuous as `armExits`'.** The whitelist is
  tested against the instruction's **operands**, never its mnemonic alone. Gating
  "uncorroborated" was taken up and **REFUSED** — do not re-attempt it; an uncorroborated row is
  a statement about the scan, not about the machine.
- **`corpus/undefinedCallees.ts` — REPORT-ONLY in both directions, split internal/external.** A
  call whose callee the emitted C defines nowhere. Internal = the body is in the output, in that
  same function, under a `loc_` label — call and body not connected (MSVC `__finally` funclets
  the detector folded into their parents). External = a tail `jmp` to a function detection never
  produced, or an indirect call through a data pointer with no IAT entry. Not a falsehood but an
  *incompleteness*, hence not gateable. **Watch `internalUnlabelled`, not `internal`** — the
  labelled half is reachable by a reader who searches the identifier's own hex, and `internal`
  rises whenever a funclet is correctly folded. `compare.mjs` flags both separately. **gcc is
  structurally blind** for its own reason (silent implicit function declarations, above);
  `distinct callees lost` asks only whether the name is on the page; `wildBranches` judges
  targets outside the *image* and these are inside it. The repair was measured and **refused
  twice**: a comment naming the label is available at only ~45% of sites and would state
  something false at the rest.
- **`corpus/structOverlaps.ts` — REPORT-ONLY, no column is a gate, currently 0 on all four.**
  Which of two overlapping readings of a struct base became a field. Neither answer is provably
  wrong, hence no gate. **Its zero is a LOWER BOUND on fabrication and NOT a clean bill of
  health** — a fabricated base was found that produced no overlap row at all, which is why
  adjudication goes through `objdump`. `groups`/`candidates`/`extents` are the liveness halves.
- **`corpus/comments.ts` — 0 coincidences on both ARM64 binaries (gate character, reported).** An
  ARM64 inline comment naming an address the instruction does not reference. **The only audit that
  reads `Instruction.comment` at all**; a comment reaches neither the emitted C nor the IR, so
  gcc, polarity, `offsetof`, arity and the stale-read gates are all structurally blind. Reported
  rather than gated only because it is not wired into `npm run corpus`. Its **x86 half is a
  DIGEST, not a judgement** — four md5s that must not move unless the change is meant to touch
  the shared `mapInsn` comment path; if it is, restamp them and say why.
- **`corpus/guardShape.ts` — GATE at 0 `unparsed`, and it is the only gate that judges the AUDIT
  rather than the output.** A guard-shaped line the polarity walk does not understand. It exists
  because the polarity denominator *is* whatever the line walk recognised, so a formatting change
  can take rows out of a gate silently. `braced`/`doTail`/`inline` are the liveness halves — a
  text-scraping audit fails by matching nothing. `corpus/selfAssigns.ts` reads the same grammar
  and adds a second gate at 0, **`for headers unsplittable`** (a header recognised whose clauses
  the splitter refused, i.e. a site that left a scan gating at 0).
- **`corpus/frameRepurpose.ts` — GATE at 0.** A frame-relative operand after the frame register
  has been repurposed mid-body. The oracle is the instruction stream and the operand text, never
  `stack.ts`'s answer about survival — which does not exist, and whose absence is the defect. The
  write is **classified**, not merely found: `pop <fp>`/`leave`/`popa` are epilogue restores and
  open no window. **The x64 pair's zero is structural** (no repurposing there at all), so only the
  PE32 pair demonstrates anything.
- **Other gates at 0 in the run**: `distinct callees lost`, `throws` (an `emit.ts` throw on an
  IR shape it cannot emit, counted rather than swallowed).
- **Report-only rows worth naming.** *Loop shape* (`if`, top-tested `while`, `do/while`, `for`) —
  **no gate models it**, a `for` becoming a `while` is a fidelity loss not a falsehood, and the
  point of reporting it is that a shape change between two pinned runs is a *row* rather than
  something the next agent must think to count. `clobbered_<reg>_<n>` reads — **not a target in
  either direction**; a call that really destroys a register should say so, and the narrow model
  reaches zero by saying nothing; judge it beside the `if`/`while`/`for` counts, which is where a
  harm of that shape shows up. *Field accesses reaching the page* (`->field_0x` occurrences) —
  the instrument that actually measures **struct recovery**, since `offsetof` sums fields over
  *distinct definitions* and therefore moves with merging; **it is not a gate and must not become
  one, because it rises with correct recovery AND with fabrication.** *Invented prelude
  declarations* (the `long <name>;` lines under `artifacts/<label>/cc/<bin>/`) — the only
  instrument for an identifier the emitted C never declares; not a gate, has to be read on
  purpose. *The crude read-but-never-assigned name scan* — an **upper bound, never a defect
  count**; a name with no wider assigned alias is an incoming value and its own name is honest.
- **The practical file-size ceiling is disassembly, not parsing** — envelope in
  `docs/architecture.md`.

### The ARM64 gated run (`npm run corpus:arm64`, `corpus/arm64.ts`)

**51 gate assertions, all 0.** Every row has an oracle outside the code under test plus a liveness
half, because a population-based audit fails by silently matching nothing:

- **The sweep against the A64 encoding** — four bytes, four-byte boundary, strictly increasing,
  inside the section. The ISA, not a heuristic, so every row is provably not an instruction the
  file contains.
- **The decode-rate floor, gated in BOTH directions** over all six binaries — `coffHeader.machine`
  is the oracle, so an accepted 0xAA64 image must be above the floor and every 0x014C/0x8664 image
  must be below it. Moving the floor either way turns a row red. This is the one place the ARM64
  and x86 halves meet.
- **`.pdata`, the linker's own record** — a begin with no instruction at it, an unaligned begin or
  end, an empty extent. This is the *sweep* agreeing with the same table the parser is checked
  against.
- **A direct branch inside a `.pdata` extent aiming outside the image.** The extent restriction is
  what makes it an oracle: A64 has **no gap fill**, so outside every extent the sweep reads
  literal pools and padding as code *by design* and a wild target there is expected — reported,
  not gated. Same restriction pattern as `unencodableNames`' PE32-only population.
- **The `adrp`/`adr` grammar against the ISA's own reach** — `adrp`'s 4 KiB page, `adr`'s ±1 MiB,
  and a reference attributed to an address the sweep produced no instruction for. Nothing else
  could see this class: `corpus/comments.ts` asks whether a comment is justified *by this reader*,
  so it would agree with a wrong reading.
- **A64 switch dispatch** — 0 case targets that are not an instruction; 0 words of a recovered
  table presented as instructions; 0 published tables the walk could not re-derive (that last is
  the liveness half — the walk re-derives each dispatch itself, so anything making the stream
  unreadable would drive the first gate to 0 by no longer looking). It judges the extent **READ**,
  never the extent the dispatch *claimed*, because gating on an unread tail would be red on
  correct output.
- **`.pdata` unwind CODES**, both encodings, against an independently written reading of the
  prologue: 0 disagreements in either direction. **Epilogue scopes are NOT audited.**
- **Literal pools — a WIRING gate, not an oracle.** It asks whether every datum the production
  grammar names was actually withheld from the stream the view renders. Measured rather than
  argued: silence the grammar and this row goes **vacuously green** while the unreachability row
  goes red. `words of pool` beside it is what makes a vacuous green visible.
- **An unreachable decoded word inside a `.pdata` extent — GATE at 0**, and the row to read,
  because its rule (reachability) shares nothing with either production rule and is therefore the
  independent oracle over both. Deliberately the *strict* reading, hence a **lower bound**.
- **`Arm64SweepCache`, differentially through the real `dispatch`** — the three RPCs of one load
  driven twice, sharing and clearing: answers must be identical and the shared run must save
  Capstone calls. The handle is *wrapped* by the audit rather than counted inside
  `capstoneWindow.ts` — an instrument belongs outside the code it judges.
- **The one report-only gap left in the census is `.pdata` words that do not decode**, ~30 per
  binary explained by a literal pool and the rest unattributed. **That row RISES whenever a
  marking pass lands and that is the honest counterpart, not a regression** — a word calling
  itself data stops decoding by definition.
- **Rows that cannot be made red from this repo** (instruction width, monotonicity, section
  bounds, `.pdata` alignment, `adrp` page alignment) are properties of Capstone's output, of the
  linker's table or of the section's size, and are controlled in `build/arm64Audit.test.ts`
  instead, over exported judging functions taking plain data.

### "Clean" is not "recovered"

A large minority of emitted functions contain an *admitted* gap — a `__unrecovered_N` or a
`/* unlifted: … */` — and compile precisely because the emitter names what it failed to recover
instead of printing something plausible. That is intended behaviour, not a defect count. Do not
read "all of them compile" as "all of them are right".

### Not verified. Say so rather than implying otherwise:

- **THE RENDER GAP IS CLOSED: every component under `src/components/` plus `App` itself is now
  rendered by a suite that asserts on it.** Measured, not recalled — 31 `*.dom.test.tsx` suites, and
  a per-component scan names 40 of the 41 files; the one it does not is `ModalBackdrop`, which
  `Modal`'s suite renders by way of it. Four sessions ago this list opened "Nothing has rendered a
  component". **What that does NOT mean is that the components are verified**, and the rest of this
  section is the list of what a green suite here still says nothing about. Two words are worth
  keeping straight: a component *mounting* as somebody's child is not coverage, and after `App` was
  rendered a transitive-reachability census over the import graph reads **41 of 41** while asserting
  nothing — the measured refusal of a drift guard built on it. "Rendered" here means an assertion
  about that component's own output.
- **The renderer has now found NINE real defects, and that is the argument for using it.** Two in
  earlier sessions: `peek-a-bin-n7q1` (a fifth `kind === "analysis-failed"` site in `StatusBar.tsx`
  rendering amber where App's banner rendered red — one notice, two colours, on screen at once) and
  `peek-a-bin-a5sw` (the arrow keys **permanently wedged** on a separator row, so everything below
  the first function tail was unreachable by keyboard). Five in the pass that closed the gap, all
  under `peek-a-bin-p0qw`:
  - **`HeaderView` printed a truncated `ImageBase` on essentially every 64-bit binary.**
    `CopyableHex` spelled its value `(value >>> 0)`, so `0x140000000` rendered as
    `0x0000000040000000` two rows under an `Entry Point` of `0x140001000` it had spelled correctly.
  - **`DecompileView` opened one comment editor per line sharing the edited address.** `lineMap` is
    many-to-one, so the `;` shortcut mounted N identical `<textarea>`s, each running `focusOnMount`.
  - **`AnomaliesView` picked its AI-findings colour with a hand-written chain over the severity
    string** — the `n7q1` shape again — and keyed both anomaly tables `Record<string, …>`, so a
    fourth severity would have compiled, sorted last and rendered in `info`'s blue.
  - **`ResourcesView` returned a keyless shorthand fragment as the element of a `.map`**, so every
    render of a populated tab logged React's key warning and reconciled rows by index.
  - **`App`'s tab bar gave the Anomalies tab the accessible name `"Anomalies3"`** — the count badge
    sat inside the button with no separator. Fixed at `6f99fdf` with `peek-a-bin-w50c`: the badge
    is `aria-hidden` and the count is spelled into an `aria-label` instead.
  Two more from *closing* two of the named holes above — found not by a render failing but by
  having to state, for the first time, what the block being rendered was supposed to print:
  - **`parseDebugDirectory` printed the CodeView PDB GUID in file byte order.** `CV_INFO_PDB70`'s
    `Signature` is a `GUID` struct, so `Data1`/`Data2`/`Data3` are little-endian integers and only
    `Data4` is a byte string; hex-joining all sixteen bytes byte-swaps the first three groups. The
    GUID is the symbol-server key for the PDB, i.e. a value only ever read *out* of the tool, so a
    wrong spelling is well-formed and simply matches nothing — the `Ordinal_<n>` class, not the
    `>>> 0` class. The **oracle is real MSVC output**: `CoCreateGuid` mints version-4 UUIDs and the
    version nibble sits in the third group, which reads 4 on **all six** corpus binaries under the
    corrected reading against E / 4 / 7 / B / 1 / 7 before it — one accidental match in six. `pe/__tests__/metadata.test.ts` had **pinned
    the defect as the rule**, under the comment "Bytes 01..10 in file order".
  - **`parseRichHeader` reported a use count with the top bit set as negative.** `^` is an int32
    operator, so a stored `0xFFFFFFFF` reached the Rich Header table as `-1`. Unfalsifiable on real
    output — all 36 Rich entries across the four x86 corpus binaries are under 150 (maxima 121, 118, 118, 115) — so the
    population is packed and corrupted headers, where a negative count reads as a parse failure.
  **None of the nine is visible to any static instrument here**: every one compiles, type-checks
  and lints clean, and nothing under `corpus/` renders React.
- **Writing a component test has four traps, all of them measured rather than reasoned.** They cost
  four separate agents a round trip each. (1) **`waitFor` and `userEvent` both deadlock under
  `vi.useFakeTimers()`** — `waitFor` polls on a timer of its own and `userEvent`'s inter-keystroke
  awaits never resolve even with `advanceTimers` wired up; drive a debounced control with
  `fireEvent.change` and advance the clock inside `act()`. (2) **Advance SHORT of a debounce first**:
  "nothing has happened yet" is equally true of a 0 ms timer nobody ticked, so a single advance past
  the boundary cannot tell a 250 ms debounce from no debounce — that control came back inert twice.
  (3) **React caches its key warning PER OWNER COMPONENT**, so a dedicated `console.error` spy placed
  after any other render sees a clean console with a keyless list in place; the guard has to be a
  file-wide `beforeEach`/`afterEach`, so the *first* render that warns fails. (4) **`target:
  "window"` cannot be discriminated behaviourally in jsdom** — `e.target` is then `window` and
  jsdom's `Node.contains` throws a TypeError on a non-Node before `onDismiss` runs, so the popup
  stays open for the wrong reason; assert on which global receives which listener instead.
- **Every drag in this repo is verified as arithmetic, never as motion.** `ResizeHandle` (mouse
  events, not pointer events) and `FloatingPanel`'s header drag and corner resize are asserted
  through `mousedown`/`mousemove`/`mouseup` on `document`, checking the deltas the handlers compute
  and the inline styles they write. jsdom has no layout, so **nothing has ever been observed to move
  or resize.** The off-screen clamp is the same: the four bounds, the reopen-after-shrink case and
  the resize case are pinned as numbers, and **nothing has seen a panel be reachable or not** — that
  a 48px sliver or a 24px header band is enough to grab needs `peek-a-bin-v2u`. `handlePopOut`'s own
  call to the clamp is **provably inert** (centring can violate only the viewport-independent top
  bound), reported rather than removed. What *is* covered end to end is `ResizeHandle`'s ref indirection:
  `BottomPanelContainer`'s `handleResizeEnd` closes over `height` from its own render, so a mouseup
  handler captured at mousedown would store the PRE-drag height — red under its own control from
  both sides.
- **Named holes inside the rendered set, so a green suite is not over-read**: `DisassemblyMinimap`
  and `ResourcesView`'s `RT_GROUP_ICON` preview mount and never paint (no 2D context, no
  `URL.createObjectURL`) — the preview's *reconstruction* has unit coverage, but no test and no
  human has seen an icon; and every popup's *placement* is unasserted, `getBoundingClientRect`
  being all-zero.
- **THE RESOURCE-DIRECTORY HOLE IS CLOSED, AND CLOSING IT FOUND A DEFECT.** `DirectorySpec` gained
  an **opt-in** `resources` tree (`ResourceTypeDef` → `ResourceNameDef` → `ResourceLangDef`) that
  emits a real three-level `IMAGE_RESOURCE_DIRECTORY`: high-bit subdirectory flags, named entries
  as length-prefixed **UTF-16** strings beside ID entries, named entries sorted ahead of ID ones
  as `rc.exe` writes them, two languages under one id, per-leaf code pages, and data entries whose
  `OffsetToData` is an **RVA** while every offset around it is resource-base-relative. All 20
  existing builds are byte-identical. **The sixteen bytes of 0xCC in front of the root are the
  load-bearing part**: a real `.rsrc` puts the root at offset 0, so resource base and section base
  coincide and a walk that confused them is *structurally* undetectable — measured, not argued.
  Reading the section base instead of the resource base reddens **17** rows across the two suites
  with the pad in place, and with it removed reddens **one** — the row asserting the pad exists. The defect: **`ExpandedLeaf`'s manifest arm and `downloadResource`
  threw `RangeError` on a TRUNCATED image.** `rvaToFileOffset` answers against the section table
  and never sees the buffer, so where the headers describe more than the file holds it returns an
  offset past the end; `Math.min(size, byteLength - fileOff)` goes negative and `new Uint8Array`
  throws — taking the pane into its `ErrorBoundary` on a click, while the tree itself walks fine
  (`parseResourceDirectory` bounds every read on the buffer) so every row is on screen.
  `resourceBytes` is the one declaration of the guard; the `RT_GROUP_ICON` arm deliberately keeps
  `buffer.slice`, which **clamps** rather than throwing. Nothing static could see it and nothing
  under `corpus/` renders.
- **A NAME-IDENTIFIED LANGUAGE LEVEL IS CARRIED, NOT FLATTENED TO ZERO, and `ResourceTree.lang` is
  `number | string` like the two levels above it.** All three levels of the directory are
  identified by the same high bit, but the flatten step read `typeof currentPath[2] === "number" ?
  … : 0` — so a named language became `lang: 0`, and 0 is a **real LANGID** (neutral): the narrower
  answer wearing a complete one's shape, with two named localisations of one resource rendering as
  two rows both claiming language 0 and separable only by RVA. `rc.exe` never writes one, so the
  population is a hand-rolled or non-Microsoft resource compiler's output — and a hostile sample
  reaching for exactly the shape tools mishandle. No file on this machine has one; the evidence is
  the fixture (`ResourceLangDef.lang` widened to `number | string`), which had to land first or
  there was nothing to fail against. **`ordinalLabel` in `ResourcesView` is the one declaration of
  the `#` marker** the Name column always used, now read by the Language column too, because a
  language *named* `"1033"` and LANGID 1033 are otherwise one string on the page. **`keyPart` is a
  DIFFERENT question and deliberately not the same function** — it decides which rows are the same
  row, so it tags the kind (`i3` vs `s3`); at the **type** level, where `String(entry.type)` merged
  a named type and the ordinal spelling the same digits into one heading with one collapse state,
  that is a real fix, and at the **leaf** level it is belt only, since `leafKey` still ends in the
  row index — which must stay, two identical entries in one crafted directory being two rows whose
  key would otherwise collide. **That control is measured INERT and reported.** Beside it,
  `truncated` was read off `remaining > 0`, so a directory holding **exactly** `MAX_TOTAL_ENTRIES`
  claimed to be short over a complete answer; the flag is set at the `break` now, and both sides of
  the boundary are pinned (`peek-a-bin-6qx9`).
- **`HeaderView`'s four named holes are CLOSED, and closing them found a defect.** The fixture
  builders now emit an **`IMAGE_DEBUG_DIRECTORY` with an RSDS CodeView record**, a **`Rich`
  header** (which moves `e_lfanew` past 0x80, so the whole layout is re-derived) and a
  **`WIN_CERTIFICATE`** carrying a hand-built PKCS#7 blob past the last section — all three
  **opt-in**, so no existing caller's bytes change. The **async arms of the Checksum Validation
  row** are reached by a fixture genuinely over `MAX_SYNC_FILE_METRIC_BYTES` rather than by
  mocking the threshold, with the sub-threshold case as the control that the size is what routes
  it; the failure arm is additionally reached through the **real** `MetricsWorkerClient`, since
  jsdom has no `Worker` and `send` rejects inside its own `try`. **What is still not reached**: the
  PKCS#7 blob carries no digest and no signature value, because nothing in this tool verifies
  either — the assertions are about the DER walk's output reaching the page; nothing has watched a
  real `postMessage`; the **other** consumer of that same `useFileMetrics` state, `SectionTable`'s
  entropy column, still renders neither async arm; and `useEntropyStrip`'s (a different threshold,
  `MAX_SYNC_ENTROPY_BLOCK_BYTES`, in `HexView`) are untouched by any of this. Two controls came
  back **INERT and are recorded rather than tuned away**: misaligning the certificate by one byte
  (`parseSecurityDirectory` reads the directory's offset verbatim and is indifferent to the 8-byte
  alignment a real image has) and zeroing a debug entry's `SizeOfData` (`parseDebugDirectory`
  never reads it — see the unbounded PDB-path scan noted below) (`peek-a-bin-p0qw`).
- **Virtualization is a STAND-IN and a green suite must not be read as covering it.** `virtual-core`
  reads the scroll element's `offsetHeight` (not `getBoundingClientRect`), so in jsdom a
  virtualized list renders **zero** rows, not a short list. `domSetup.ts`'s `stubLayoutRect()` is
  opt-in per file; with it every element reports the same size, `scrollTop` is permanently 0 and
  the stub `ResizeObserver` never fires, so which rows are windowed in, whether `overscan` is
  right, whether `scrollToIndex` works and whether anything is *visible* all stay unanswered.
  **A row in the document is not a row on screen.** The sidebar's function rows and the hex grid
  are out of reach; the entropy strip additionally gates on a width jsdom reports as 0.
  **How blind, measured rather than argued**: under `stubLayoutRect` two real behaviour changes to
  `ExportsView` — `estimateSize` 28 → 280 and `overscan` 20 → 0 — leave its whole suite green,
  because every element reports one 600px rect and `scrollTop` is pinned at 0, so the computed range
  covers the entire fixture whatever those numbers are. Those two controls are **left inert on
  purpose** and recorded as the statement of the gap; making them discriminate would mean fabricating
  a scroll position no browser produced. The stub itself is controlled in both directions — remove it
  and 15 of `ExportsView`'s 18 row assertions fail, and `StringsView`'s twelve strings render **zero**
  rows while its toolbar still counts all twelve — so the row assertions are not vacuous.
- **jsdom is NOT a browser.** No layout, so nothing about geometry, overflow or visibility;
  `offsetParent` is a constant `null` and is supplied by a stand-in the focus trap depends on; no
  browser focus algorithm, no service worker, no screen reader. A green focus-trap test says the
  component's own logic moves focus where it says; it does not say a browser agrees.
- **The browser's callee-clobber summary is wired and guarded end to end, but no human has seen a
  `clobbered_` name on screen.** The client→worker hop, the two-message `needInstructions` retry
  and the `.pdata` single-row slice are all asserted through the real `disasmClient` answered by
  the real `dispatch` — **and nothing has watched any of it cross a real `postMessage`**. The
  build cost is measured only on ~108 KB binaries; a large image is extrapolation. The emitted-C
  effect is measured on the **MCP path** (`FileSession`), not the browser path.
- **The request watchdog's terminal state HAS now fired, end to end — but never on a real file,
  and that distinction is the whole of what is still unverified.** The claim here used to be that
  it "cannot be made to fire here", on the evidence that provoking it needs ~200 MiB of *code* and
  `find / -xdev` finds no PE over 2 MB on this machine. **That is true of the FILE route and only
  of it**: `REQUEST_TIMEOUT_MS` is a module constant, so `src/__tests__/App.dom.test.tsx` mocks the
  budget down to 500 ms — `importActual` and a spread, never a hand-written stub, because
  `analysisRejection` decides on `err instanceof WorkerTimeoutError` and a lost class identity
  would make the test prove the opposite of what it claims — leaves `detectFunctions` unanswered,
  and drives the real `App`, the real client watchdog and the real notice. Three cases: the banner
  is **red** and spells the budget from the constant rather than hardcoding it; it withholds **no**
  tab (the `"Still available:"` sentence is absent, which is what `unavailableTabs: []` is for
  where `buildAllXrefs` is the last stage); and it does **not** say the analysis failed. Three
  controls, all discriminating — report a timeout as `"failed"` (which reproduces
  `peek-a-bin-meai`'s defect verbatim: `ANALYSIS FAILED / Analysis failed: … timed out`), give the
  kind a non-empty `unavailableTabs`, hardcode the budget words. **`App.tsx`'s own catch says
  "nothing here can be reached by a test, which is why the decision is a pure function elsewhere"
  — the pure function was the right call and the comment's premise is now false.** What remains
  unverified is the thing the old sentence was really about: **no real image has ever taken this
  path**, so the budget's calibration against a genuinely slow stage is still extrapolation, and
  the status-bar label and empty-panel case remain verified by typecheck, pure tests and reading.
- **Render COUNT is measured; render COST is not.** Exactly two full-tree renders per cursor
  *move*, for every context consumer, measured against the real `DisassemblyView` and
  negative-controlled. Whether two renders of a virtualized list and a dagre-laid-out graph is
  *slow* still needs the React DevTools Profiler on a real binary in a real browser.
- **No human has looked at this branch in a browser.** `peek-a-bin-v2u` is the checklist; ~15
  minutes with the app open closes more risk than any further static work.
- **The metrics worker's Blob hand-off is verified for EQUIVALENCE and not at all for SPEED.**
  That a `Blob` and an `ArrayBuffer` source produce identical results is measured and
  negative-controlled. That posting one is O(1) is a spec property plus an earlier measurement of
  the copy it replaces. Nothing has watched a real `File` cross a real `postMessage`, and the drop
  path is the only one that would. Same for `extractStrings`. The *browser* side of the trade is
  unmeasured: a `File` is backed by disk, so `Blob.arrayBuffer()` there is I/O, not the memcpy
  Node times.
- **The architecture refusal IS now rendered — all three surfaces, on one screen — and what is
  left unverified is narrower and different.** The old bullet said "no test has seen the banner,
  the panel or the status bar"; by the time it was checked that was **a third stale**, since
  `DisassemblyView.dom.test.tsx` had been rendering the replacement panel for an ARMNT image for
  two sessions. `App.dom.test.tsx`'s "an image no decoder here reads" suite now drives a real
  ARM32 fixture (`buildMinimalPE32({ machine: 0x01c4 })`, with genuine import and export
  directories) through the real `App`, answered by the **real `dispatch`** rather than a stub — so
  the empty `omitted`-bearing `detectFunctions` result and `buildAllXrefs`' throw are production
  code. It asserts the banner is **amber while `analysisPhase` is `"failed"` and `state.error`
  holds the refusal**, which is the property this kind alone discriminates; that the status bar
  reads the same notice in the same colour *at the same time* (`peek-a-bin-n7q1`'s shape, for the
  one kind `StatusBar.dom.test.tsx`'s agreement loop had never covered); that `"partial-detection"`
  is outranked though all four passes are in the state; that `unavailableTabs` withholds exactly
  the tab the panel withholds; and that all eight named tabs mount with content and none falls to
  its error boundary. **Still not verified**: no human has seen it in a browser
  (`peek-a-bin-v2u`), nothing has crossed a real `postMessage`, and jsdom shows no layout — so
  every virtualized pane among those eight is asserted only through its heading, and a row in the
  document is still not a row on screen. **Two controls came back INERT and neither was tuned
  away**: spelling either the banner's or the status bar's predicate as `kind ===
  "analysis-failed"` — the `n7q1` defect verbatim — leaves every row green, because for an
  `isFault: false` kind the hand-written predicate and `isFault` *agree*. The discriminating
  perturbation for this kind is a site reading the **phase**, and both go red under it.
- **There is no ARM32, ARM64EC or ARM64X binary on this machine**, so every one of those paths is
  verified against synthetic fixtures and nothing else. The decode-rate floor is calibrated
  against real ARM64 and real x64 only and is **not** a claim about ARM64X, a good share of which
  is genuine A64 and may sit above the floor. `chpeMetadataPointer` is non-zero for no file here,
  so the "declares CHPE metadata" branch is fixture-and-control only. **The machine-type claims
  are settled from DOCUMENTATION, not from a file** — ARM64EC is marked 0x8664 and ARM64X 0xAA64
  — so the ARM64EC-as-x64 misclassification has never been observed. Likewise the
  two-exception-tables finding: which format each of a hybrid image's two function tables carries,
  and the ARM64X relocation that swaps them, are read out of lld, Wine and Microsoft's ABI page
  and out of no file. No `ExtraRFETable` value has ever been read here.
- **ARM64 is measured only as far as instructions, boundaries, references and tables**, and a
  green `corpus:arm64` run is easy to over-read:
  - **Nothing about ARM64 *semantics* is checked at all.** No ARM64 decompilation, so no IR, no
    emitted C, no guard, no type, no struct and no call arity has ever been judged. The dozen
    decompiler gates would each be a vacuous zero.
  - **Stack frames now have an ARM64 path (out of `.pdata`); signatures deliberately do not.**
    `inferSignature` returns null rather than the x86 answer it used to give — it had labelled
    every A64 function `fastcall` with 0 parameters, on screen. `analyzeStackFrame`'s own refusal
    is **unfalsifiable on this corpus** (it already answered null for every A64 function), so it
    is a bound pinned by unit test, not something a green run says anything about. `.pdata`
    carries no arity information, so an A64 signature has no oracle at all.
  - **There is no GENERAL ARM64 data-marking pass.** Two populations are marked and gated
    (recovered dispatch tables, `LDR (literal)` pools) and both share the property that *an
    instruction names the data*. Everything left is data nothing names — alignment padding inside
    a `.pdata` extent, pools reached other than by an `ldr`-literal — and no instrument here can
    say which a residual word is.
  - **The ARM64 *signature refusal* has been rendered; nothing else about an ARM64 view has.**
    `DisassemblyPanel.dom.test.tsx` mounts the real panel under an ARM64 machine word and asserts
    that no calling convention reaches the screen — `peek-a-bin-56q`'s render step, landed at
    `b70fb72`. But that fixture's instruction stream is scripted **x86** bytes with only the
    machine word flipped, so no human and no test has seen an A64 disassembly on screen: `source`
    dimming, the `db`/`dd` rendering, jump arrows, the CFG and the minimap are verified by
    typecheck and reading. It bites harder here because the remaining report row is a
    *view* defect, and because the jump-table fix's last step — `buildDataItems` rendering the
    withheld words as `db`/`dd` — **has never been executed**. What is measured is that the words
    leave the stream.
  - **Epilogue unwind scopes are unaudited** — the walk stops at `end` and the per-epilog code
    lists after it are read past and never judged.
  - **The `bl` call graph is counted, not verified.** No oracle checks an edge.
  - **ARM64 performance is measured only in Capstone call counts.** The wall-clock figures in
    `Arm64SweepCache`'s docstring are not re-derived and no ARM64 timing has been taken on this
    tree.
- **`REQUEST_TIMEOUT_MS` has measurements behind it, all extrapolated.** `go` cross-compiles real
  Windows PEs here, and `detectFunctions` is the **sole** budget setter, linear in code size to
  within a small spread over a 37–38× range — the shape finding, not the digits. Re-derived four
  times; the last (the hand-written `cs_insn` reader) roughly thirds the rate. **Read the ratios,
  never the digits** — runs were taken on a shared machine under background load. Extrapolation in
  three respects: Go's code density is not MSVC's, this was Node rather than the browser's WASM,
  and one machine. **The population is still zero on this machine** — nothing here can provoke the
  watchdog, so the notice is fixture-verified and has never been rendered.
- **A real x64 PE with jump tables can be built here, the tool recovers NONE of them, and this is
  SHAPE rather than defect.** `go` emits dense `jmp [reg + reg*8]` dispatches behind a
  rip-relative `lea` table base; **the harm is measured at exactly ZERO** — every table base is in
  `.rdata` so the gap fill never reaches it, no byte is decoded as code, and every case target is
  already an instruction start inside the dispatching function's range. The residue is CFG edges.
  **The dense two-table reader has never run on a real image** — instrumented call counts are 0 on
  all five binaries — so `peek-a-bin-6rge` remains verified by synthetic fixtures only, and no
  binary obtainable on this machine can change that. The register-base reader is adjudicated out
  of scope; **reopening needs new evidence (a real MSVC or clang-cl PE using that spelling), not a
  re-reading of these facts.** `npm run corpus:jumptables -- <path>` is the landed census.
- **The nginx headers and the CSP have never been exercised in a browser** — both are researched
  from code and build output.
- **The clipboard's absence has never been produced by a browser.** `copyText`'s branches, the four
  red-flash sites and two of the fourteen silent ones are covered, but the absence is **manufactured
  by replacing `navigator`** — a stand-in exactly like `domSetup.ts`'s `offsetParent` shim. Nine
  unaffordanced sites and `CFGView`'s red/green branch have no test at all: reverting `HexView`'s
  copy to the unguarded call moves no row, which was reported as an inert control rather than
  papered over. Belongs in the `peek-a-bin-v2u` pass, over plain `http:` to a non-localhost host.
- **The a11y work has never met a screen reader.** The tablist's *mechanics* are checked in jsdom —
  roles, `aria-selected`, the roving tabindex, arrow/Home/End focus movement, and `aria-controls`
  resolved against the document in both directions — and `XrefPanel`'s two "To" buttons now carry
  `aria-label`s that tell them apart, asserted through testing-library's name computation. **None of
  that is evidence about a screen reader or a browser focus algorithm**, neither of which exists
  here: nothing says a reader announces "Sections, tab 3 of 9", reads the panel on activation, or
  honours `aria-labelledby`. Two further reasoned-not-observed points: a hidden panel is out of the
  a11y tree only because `hidden` carries `display: none` in a browser, which it does not here; and
  the extra tab stop on panes that *do* contain focusable content costs one Tab, which nobody has
  judged. `peek-a-bin-v2u` is unchanged. `XrefPanel` now carries `aria-label`s separating
  its direction toggle from its "To" sort header — the two shared one accessible name — and states
  sort direction in words rather than as a bare "▲" glyph, asserted through testing-library's name
  computation, which is jsdom and not an assistive technology.
- **MCP → browser WebSocket annotation sync has never been exercised end to end**, in particular
  since the 127.0.0.1 bind change.
- **`@vitest/coverage-v8` is not installed**, so `npm run test:coverage` fails.

When a UI or deployment change lands, the honest report says which of these it did *not* move.

## Decompiler Architecture (`src/disasm/decompile/`)

**Full record: [`docs/decompiler-ir.md`](docs/decompiler-ir.md)** — the complete dispatch census, the
struct-grouping history and the measurements behind every rule below.

**Pipeline** (`pipeline.ts`): `buildCFG → liftBlock → liftCrossBlockPops → buildSSA → ssaOptimize → destroySSA → foldBlock → structureCFG → cleanupStructured → wrapExceptionRegions → inferTypes → promoteVars → synthesizeStructs → emitFunction`

(`wrapExceptionRegions` is local to `pipeline.ts` and only runs when `.pdata` exception info is present. **The docstring at the top of `pipeline.ts` lists a shorter, outdated order — trust the code, not that comment.**)

**IR** (`ir.ts`): `IRExpr` union (12 kinds: const, reg, var, binary, unary, deref, call, cast, ternary, field_access, array_access, unknown) + `IRStmt` union (18 kinds including if/while/do_while/for/switch/break/continue/phi/try/**branch**).

**`branch` is confined to `liftedBlocks` and never appears in a structured tree — but its *condition* does, and `structureCFG` takes it as a sixth argument.** `liftBlock` turns a block's trailing conditional jump into an `IRBranch` so its condition is a real IR reader — an SSA version, a reaching definition, a place in every use count — and `pipeline.ts` step 4b lifts every one out of `liftedBlocks` into a `Map<blockId, IRBranch>` *before* `structureCFG`, which `extractCondition` prefers over re-parsing `insn.opStr`. Two orderings are load-bearing and neither is obvious:

- The extraction runs **before the tap snapshot**, or the statement-drop audit reports every branch as a dropped statement in each block ending in a conditional jump.
- The branches must not survive into the tree: `detectForLoop` skips any body block whose last statement is not an `assign`, so one left in place takes **for-loop recognition to zero corpus-wide**, silently and with no failing test.

`structureCFG` has a **seventh** parameter, a different kind of thing: an optional observer told how `structureSwitch` closed each switch arm, wired only when `pipeline.ts` has a tap of its own. It is an instrument reading the structurer, must never change what the other six decide, and `corpus/armExits.ts` gates its reports at 0.

`emit.ts` therefore *throws* on a branch rather than ignoring it — `decompileFunction`'s catch turns that into a counted `throws` that `compare.mjs` gates on, where a silent arm would make a structural failure invisible. **Anything appending to the end of another block's statement list must go through `pushBeforeTerminator`** (`ir.ts`): `destroySSA` lowering a phi into a predecessor and `loopInvariantCodeMotion` hoisting into a preheader both did a plain `push`, correct only while no terminator existed in the IR.

**Three things about the flag flip are judgements, not details, and reversing any silently breaks something no gate reports** (`peek-a-bin-c33`):

- **`foldBlock` counts a guard's reads but never inlines into a branch**, and separately never inlines a definition that escapes its block at all (see the `blockLiveOut` gotcha). Counting stops a definition two statements read from being folded into one and leaving the other naming nothing. Inlining *into* the guard deletes the assignment and rewrites the condition, and both halves do damage — the register is frequently live out (a loop counter always is), and `structureCFG` matches loop shapes on the statement a body block ends with, so `inc eax / cmp eax, 5 / jl` became `while (eax + 1 < 5)` with the increment gone.
- **`extractCondition`'s two refusals are asked of the condition read off the *instructions*, never of the IR one.** Both are questions about the machine. Asking `conditionSpoiled` of the IR condition defeats it outright: `cmp eax, 5 / mov eax, edx / je` has its guard rebound to EDX by copy propagation, so the overwritten register is no longer in the expression and the scan finds nothing to object to, while the emitted test is still one the machine does not make (`peek-a-bin-xe01`).
- **Which instruction a Jcc's flags belong to is `flagModel.ts`'s answer, and `lifter.ts`'s `branchFor` is the only place that asks.** It calls `blockFlagOwner` at the trailing jump and refuses four ways, each a case where an answer would be a guess: (1) a jump reading no flags (`jmp`, `jecxz`/`jrcxz`/`jcxz`); (2) an indirect or unresolved target; (3) a **result** or **bittest** owner in a block that also contains a `cmp`/`test`; (4) a result whose **destination** no longer holds it (`canSpellCondition`). The third is a policy rather than a fact — `cmp eax, 5 / sub ecx, edx / jne` really does branch on `ecx != 0`, but `corpus/staleGuards.ts` reads **any** condition emitted at such a jcc as the superseded one, so recovering it is a decision to take *with* the audit. A **compare** owner is deliberately *not* filtered on `spoiled` — the guard's reads hold the compared values alive through DCE, and the same veto is applied against the machine text in `structure.ts`, the only place it can be asked.

`liftBlock` also clears `RegState`'s flag state on any instruction that is neither `isFlagTransparent` nor a modelled setter, keeping `setcc`/`cmovcc` reading their own instruction's state. That is a *different* question from ownership and the two are deliberately not merged: the SSE `comis*` forms set flags `setcc` reads and `flagModel` classes them a clobber, so a `comis` leaves `setcc` working and produces no branch.

**A compare emits no statement at all.** The old `eflags = …` proxy was actively harmful: `eflags = ecx - edx` is an ordinary IR expression, so GVN gave it and a real `sub eax, edx` the same value number, copy propagation rewrote EAX's readers to name `eflags`, and the post-fixpoint strip deleted the only assignment. `ssaopt.ts` holds no flag definition live by hand and `flagResult.ts` is gone; its survivors `isFlagTransparent` and `clobberedAfter` live at the bottom of `flagModel.ts` so there is **one** copy of the x86 flag grammar, with a drift guard failing on a second declaration under `src/disasm/decompile` or `corpus`. `ssadestroy.ts`'s `mapReads` has a `branch` arm so `splitStaleReads` sees and repairs a guard's registers; it must land *with* the `extractCondition` flip, not before it.

### Adding new IRExpr / IRStmt kinds

Adding a kind means updating every switch dispatching on `expr.kind` / `stmt.kind` — dozens of them — and **a missed one silently drops data rather than failing. Only NINE are compiler-caught.** The tables below are accurate about every site they name but do **not** name them all, so **grep as well as read**.

**Get the current compiler-caught number by measurement, never from a stale count**: add a throwaway `IRStmt` kind to the union, run `npm run typecheck`, count the `not assignable to type 'never'` errors.

Two sites are not dispatches at all and no table lists them: `cfgpatterns.ts`'s `detectForLoop` reads `stmts[len-1].kind !== "assign"` and `cleanup.ts`'s `endsWithTerminator` reads the last statement's kind — *predicates over a block's final statement*, so a new terminator-shaped kind changes loop shape rather than dropping data, the defect class no audit models.

**Compiler-caught** (exhaustive `never` assert — `npm run typecheck` finds these):

| File | Functions |
|------|-----------|
| `ir.ts` | `bodiesOf`, `rewriteBodies` — the **only** declaration of the structured-tree body traversal |
| `ssa.ts` | `renameExpr`, `renameStmt` |
| `ssadestroy.ts` | `mapRegs`, `stripVersionsExpr`, `stripVersionsStmt` |
| `emit.ts` | `emitExpr`, `emitStmt`, `liveInStmt`, `collectAssignedRegs`, `collectCapturedOperands` (four are `IRStmt`; `emitExpr` is `IRExpr`) |
| `fold.ts` | `hasSideEffects` — one exported definition, imported by `ssaopt.ts` |
| `workers/dispatch.ts` | RPC method dispatch (guards `WorkerMethod`, not IR) |

**You must find the rest by hand. The typechecker stays silent on all of them.**

*Switches ending in `default:`* — the new kind takes the fallback branch:

| File | Functions |
|------|-----------|
| `fold.ts` | `foldStmt`, `countReads`, `countReadsInStmt`, `substituteReg`, `substituteRegInStmt` |
| `ssaopt.ts` | `replaceRegInExpr`, `replaceRegInStmt` |
| `structs.ts` | `exprKey`, `rewriteExpr`, `rewriteStmt` |
| `promote.ts` | `renameVarsInExpr`, `renameVarsInStmt`, `promoteExpr`, `promoteStmt` |

*Neither `default:` nor a `never` assert* — control falls off the end and the kind is dropped **with no trace at all. These are the dangerous ones:**

| File | Functions |
|------|-----------|
| `ir.ts` | `walkExpr`, `walkStmts` — only these two |
| `ssaopt.ts` | `canonicalizeExpr`, the stmt walker in `deadCodeElimination`, the LICM expr walker |
| `structs.ts` | `walkExprs`, the stmt walker in `collectAccessPatterns` (both nested) |

*Not switches at all* — `foldExpr` (`fold.ts`) and `countExprUses` (nested in `ssaopt.ts`'s `deadCodeElimination`) are if-chains on `expr.kind`. **Grep the function name, not `case`.**

`typeInfer.ts`'s `parseCastType` keys off type *strings*, not kinds — only relevant if the new kind gets a cast spelling.

**Type system** (`typeInfer.ts`): `DecompType` lattice with 12 kinds (unknown, int, float, ptr, bool, void, struct, array, handle, ntstatus, hresult, enum). `meetTypes()` merges — specific wins over unknown, handle/ntstatus/hresult win over int/ptr. `enum` carries a name and a `Map<number, string>` of members, synthesized from switches with 3+ cases.

**API signatures** (`apitypes.ts`): **209** Win32/NT signatures, **none variadic — which is what makes the table usable as `corpus/arity.ts`'s arity oracle.** Use type shorthands (PVOID, HANDLE_T, NTSTATUS_T); return `HANDLE_T` for handle-returning APIs, `NTSTATUS_T` for Nt/Zw, `HRESULT_T` for COM.

**Struct synthesis** (`structs.ts`): `StructRegistry` is cross-function state shared in the worker. `decomposeAddress()` breaks `base + idx*scale + offset`, including a top-level `base - const` (folded to a negative offset; subtracting a *register* is not an offset and returns null). 2+ distinct offsets on the same base → struct candidate. Scale ∈ {1,2,4,8} → `IRArrayAccess`, whether or not the function has a candidate; a function with no candidate but an indexed access takes a rewrite-only path, one with neither is returned by identity.

**Escaping struct defs are snapshots; registry-internal ones are live.** `synthesizeStructs` clones into `IRFunction.typedefs` (`cloneStructDef`), so an already-returned declaration cannot change when an unrelated function is decompiled later. Inside the registry the objects stay shared and the inference passes mutate `field.type` in place — that **is** the cross-function type-refinement mechanism. So do **not** clone in `findOrCreate` or `get`: it disables refinement silently, with no test failing. Field *types* are replaced wholesale, so a shallow field copy suffices.

**Merging is shape-based but guarded.** An exact `offset:size` fingerprint match merges unconditionally. The subset path additionally requires the smaller shape to have **3+ fields** (`MIN_SUBSET_MERGE_FIELDS`) and the merged layout to be free of overlapping extents (`hasBoundaryConflict`). Two distinct offsets is the *minimum* a candidate can have, so two-field shapes are the most common and the weakest evidence. Failing to merge is the benign direction — two `struct_N` declarations instead of one wrongly shared. Both merge directions scan `fingerprintIndex` in insertion order and take the first match, so *which* struct absorbs which is order-dependent.

**Provenance beats shape, and recovers that cost.** Two bases occupying the same parameter slot are the same object by construction, so `findOrCreateLinked` merges on that evidence and deliberately ignores `MIN_SUBSET_MERGE_FIELDS`. It still cannot override `hasBoundaryConflict`: contradictory layouts mean one reading is wrong. Two maps are kept apart on purpose — `paramLinks` (what a *caller* passed in) and `paramViews` (the *callee's* own reading) — so a merge always has the callee's corroboration and a passthrough `void*` helper never links its unrelated callers. Identity is published in both directions.

**A field's NAME is the other half of its array claim, and `fieldNameFor` is the only declaration of the rule.** `candidateFields` decides `isArray` and the identifier together, and `emit.ts`'s `declareField` reads *only* the flag when it spells `[...]` — so a second place that changes `isArray` without re-deriving the name emits `uint64_t field_0x8[];`, a declaration contradicting itself. **Anything else that sets `isArray` must go through `fieldNameFor`.** The reverse move is refused: renaming on every merge rather than on the promotion reaches the gate's 0 by spelling every member `array_`. A field name is consequently not stable across a merge; the snapshot rule bounds that to two functions disagreeing about a member's *name* where they previously disagreed about its *type*.

**A base's OVERLAPPING readings are settled by discarding a directly observed access, twice, and neither discard leaves a trace in the emitted C.** `candidateFields` first collapses two accesses at one offset into one field of the **wider** width (the width is a direct measurement of one instruction), then drops any surviving extent overlapping one already kept at a **lower offset**. `corpus/structOverlaps.ts` is the only instrument that can see it — `offsetof` proves a layout *self-consistent* and can never see a wrong identity.

**One register is not one object: a base is keyed on the VALUE it holds, not on its name.** `exprKey` answering `reg:${canonReg(name)}` was version-blind and program-point-blind, so every access through any value a register held anywhere in the function grouped as one object — fabricating structs out of two unrelated objects. `baseGenerations` mints a generation per `reg`/`var` node standing in for the SSA version `destroySSA` collapsed away, and `accessKey` is `canonBase(expr) + "#" + generation`. The rules:

- **It cannot invent an object**: the scoped key determines the unscoped one, so the grouping is a partition *refinement*. It can split a group below the two-field minimum; the registry re-unifies honest shapes by fingerprint.
- **`canonBase` stays register-level** for `stackDerivedBases`, `paramIndexByBase` and `collectCallArgSlots` — which register is a frame pointer or a parameter is a fact about the *name*. Every access-side pass (`rewriteStmts`, `inferFieldTypesFromUsage`, `linkNestedStructFields`, `fieldAtAddress`) takes `accessKey`.
- **Generations are tracked per NAME and handed over per OBJECT**: a folded copy (`rcx_0` onto `reg:rcx`) hands its source's generation over rather than minting one, or every read of the repair variable takes the register's newest generation.
- **A merge point mints a fresh generation for every key an arm CHANGED** (a dynamic diff, not the syntactic assigned-set), **an `if`'s arms are visited in isolation** with save/restore, **a `call_stmt`'s `resultDest` mints**, a `try`'s handler enters from the *body's merge* (the unwinder enters mid-body), and a **loop header** mints over the body's definitions plus what a `label` in the body would re-value — one pass, no nested fixpoint.
- **A `label` is resolved from the states its own `goto`s carry, plus the fall-through, at a fixpoint** — the iteration starts *optimistic*, and generations are **tokens naming the tree node** (`a<n>`/`j<n>.<k>`/`L<n>`) rather than counters, or "did both edges carry the same value" has no answer. **A label NO `goto` names still resets every key unconditionally**: `pruneLabels` means such a label is a leftover region's head with no CFG predecessor, entered by the unwinder.
- **DO NOT DELETE THE LABEL RESET.** It scores higher on field-access counts and **fabricates** — at `t32!sub_4041D0` it merges a read through `arg_1` with a read through `[arg_1+0xC]`, the exact defect class the generation key exists to fix, and `structOverlaps` is blind to it in both runs.
- **`raw` does not reset**, and that is the one stated hole: an unlifted instruction's register writes are not modelled anywhere in this IR.
- **A stride walk must keep grouping** — `eax += 0x40` through an array of structs reads the loop-header phi, one generation per element. A key sharp enough to separate iterations recovers nothing from any array-of-struct walk, which is most of what this pass is for.

**`stackDerivedBases`' copy chain sees only `assign` with a register or variable destination, so what `promoteVars` promotes decides how far stack-derivation propagates.** A stack address spilled to a frame slot and reloaded is a `store` plus a `deref`, neither a copy, so the chain stopped at the spill; promoting the slot closes it and a base that provably holds a stack address on some path is refused a struct it previously got. That is the rule working — one write of a stack address into a register is enough to make every access through it suspect — and refusing is the benign direction.

**Emitted struct definitions are `#pragma pack(1)` with explicit `_pad_0xNN` members**, and the two are inseparable — padding alone cannot express an unaligned recovered offset and C would re-align on top of it. The field *names* record the offsets the recovery found (`field_0x18`), so a declaration C would not lay out that way states something false. A field no padding can place — overlapping one already placed, negative, past 0x8000, or of a width with no spelling — is reported in the struct body and its accesses spelled as the bytes they touch, rather than declared somewhere convenient.

**A call takes an assignment only when its result is live out of the call.** `liftBlock` gives every `call_stmt` a `resultDest` of RAX/EAX; emit printing the call and dropping the assignment left `GetProcAddress(...)` followed by `if (rax == 0)` with nothing assigning `rax`. Liveness is a backward pass over the **structured** body (the tree emission walks, so the statement the reader sees after a call is the one the analysis asked about), loop headers to a fixpoint, `break`/`continue` carrying the live set of the construct they leave, a handler live throughout the body it guards, and a `goto` — the one shape the tree does not model — falling back to every register the body names. An assignment nobody reads is noise. `_assignedRegs` follows the same rule, so `registerText` cannot respell `al` as `(uint8_t)rax` in a function whose only write of RAX went unprinted.

**…and where that assignment's only reader is the very next `return` of it, the two lines print as one**: `rax = f(); return rax;` → `return f();`. **`foldReturnedCallResults` (`emit.ts`) is `emitFunction`'s FIRST act, before `collectCapturedCalls` and `collectAssignedRegs`, and that ordering is the whole of its safety rather than tidiness** — both sets are asked about the *folded* body, so a read is respelled exactly when a wider alias really is assigned in the text the reader sees, and removing an assigned name can only withdraw a respelling, never add one. It cannot change which *other* calls print a result (the accumulator is dead immediately above the pair either way). Three rules: the folded line keeps the **CALL's** address, not the `return`'s, so a guard whose body begins there anchors to the same jcc; adjacency in the statement list is required, so an `/* unlifted: … */` between the two refuses the fold; and it is restricted to a `call_stmt`.

**emit.ts module-level `_typeCtx`**: set before emission, cleared after. Enables cast suppression and type-aware idioms (INVALID_HANDLE_VALUE, NT_SUCCESS, SUCCEEDED/FAILED).

## Gotchas

**Full record: [`docs/gotchas.md`](docs/gotchas.md)**, same entries in the same order — how each
defect was found, what it emitted, the measurements, the negative controls, and the alternatives
tried and refused. Read the long-form entry before changing the code it describes. Two habits it
exists to support: **a measured refusal is a result** (several entries record an approach that was
built, measured and rejected — re-attempting one costs a session), and **a control that does not
discriminate is a test that is not testing**, which is this repo's most frequently recurring
mistake.

- **Nothing may call `cs.disasm` directly; every decode goes through `disasm/capstoneWindow.ts`.** capstone-wasm's linear memory is a fixed 16 MiB that cannot grow, the input is copied onto a ~65.6 KiB WASM stack, and `cs_disasm` allocates one contiguous `cs_insn[]` for the whole window — a window much over 64 KiB throws and leaves the module **permanently dead**, and every scan loop reads that throw as "this byte is not code, skip one", so exhaustion is silent. `createScan` clamps to `CS_WINDOW_BYTES` (0x2000) and `CS_MAX_INSNS_PER_CALL` (2048) and probes the engine after a run of failed decodes, surfacing `CapstoneUnavailableError`; smaller windows are also faster. **Lifting the ceiling for speed was measured and refused**: the fixed cost of a `cs_disasm` call is sub-microsecond, so collapsing a section into one call is worth 0.035% (`peek-a-bin-ktp`). A drift guard in `__tests__/capstoneWindow.test.ts` fails on `.disasm(`, `cs_disasm` or `loadCapstone(` anywhere under `src/` outside the two owning files, checking each exemption in both directions.
  - **The decoder *under* that bound is ours: `disasm/capstoneReader.ts` marshals each `cs_insn` by hand, for ~3x** — capstone-wasm's per-instruction cost was 83-86% JS marshalling, dominated by `readStruct`'s spread accumulator. The **`cs_insn` ABI is hard-coded and a version bump can change it silently**: a wrong offset does not throw, it yields a plausible mnemonic and operand string for every instruction in the tool, and `__tests__/capstoneReader.test.ts` — both readers over the same bytes, negative-controlled per field — is the whole mitigation. A *runtime* self-check was **refused**: a new way for startup to fail, on the decoder everything is downstream of, to catch a change that only ever arrives with a `package.json` edit. It sits below `createScan` and must not window. `loadCapstone` is a singleton, so a second bootstrap site wins the race, leaves the Module unpopulated and silently drops the tool back onto the dependency's reader — retention is optional by construction and `capstoneHandle` falls back. MCP is threaded too, or `npm run corpus` would verify a decoder the app does not use. Two deltas: `bytes` is a slice of exactly `size` (**do not test that buffer length in either direction**), and a window that decodes nothing returns `[]` where capstone-wasm throws. (`peek-a-bin-fdi8`)

- **The ARM64 sweep is shared across one load's RPCs via `WorkerState.arm64Sweep` (`Arm64SweepCache`), and the key is the section's bytes.** A64 has no recursive descent — the sweep *is* the disassembly — so `detectFunctions`, `hybridDisassemble` and `buildAllXrefs` each wanted the same decode and each did it. Handing one RPC's `Instruction[]` to the next is **not** the fix: every element carries a `bytes` view, the case `workers/transfer.ts` exists to keep out of a message. Three things, none optional: the key is the **bytes** compared byte-for-byte, not the address (both real ARM64 binaries base `.text` at 0x140001000) and not the length, and a content key needs no assumption about message order, since a decode can be serviced before the `configure` announcing its file; **only the decode is cached**, with `comment` and `source` reapplied per caller by `decorateArm64Sweep`; and **a refused section is never stored**, so the `Arm64DecodeRateError` refusal cannot decay into a cached empty answer. The plain `disassemble` RPC is deliberately out — it may be handed a sub-range, and a one-function decode would evict the `.text` the other three share. Call counts are gated by `npm run corpus:arm64` driving the three RPCs shared and cleared. (`peek-a-bin-kis`)

- **`mapInsn`'s comment resolution is an x86 operand grammar, so ARM64 passes it the empty string/IAT maps.** It scans the operand string for any `0x…` literal matching a known string or IAT address — sound on x86, where an operand really can carry an absolute address; unsound on A64, where the only literals are a branch target and an `adrp` **page base**, so an instruction was annotated exactly when a page base *coincided* with a data address, and nearly every comment on both ARM64 binaries named the same wrong import. `decorateArm64Sweep` annotates from `findArm64AddressRefs` instead, attributed to the instruction that **completes** the pair — `buildArm64Xrefs`' rule, so one grammar answers both. The empty maps are the mechanism, not a tidy-up: `mapInsn` is *declined* rather than filtered afterwards, which is what makes the x86 path structurally unmovable; passing the real maps back is the defect returning. `driverMode` is still passed, so IOCTL annotation (a shape test over immediates) is unchanged; the recomputation belongs on the **decoration** side, never inside `Arm64SweepCache`. **The suite had pinned the defect as the rule** in two places, asserting that a lone `adrp` whose page base is in the string map gets that string; `corpus/comments.ts` is what catches it now, and nothing in `npm run corpus` can, because a comment reaches neither the emitted C nor the IR. (`peek-a-bin-vg3`)

- **A call clobbers what the callee writes, and that answer is only ever ADDED to the narrow one.** `clobberedByCall` (`decompile/ssa.ts`) unions the argument registers the call site was read as passing with `IRCall.clobbers` — the volatile registers `disasm/callSummary.ts` says the *callee* modifies, closed over the call graph — and must never substitute one for the other. Modelling a call as destroying the whole Windows x64 volatile set was tried and is **worse**: `__chkstk` preserves all but RAX/R10/R11 by contract, MSVC parks live values in R10, and clobbering renamed reads of a function's own parameters and **deleted a guard outright** (`peek-a-bin-hj1`). The summary is built to **under-approximate** — unrecognised mnemonic writes nothing, a matched `push`/`pop` is a save/restore, an import or indirect call contributes nothing — because a missed write costs a clobber and an invented one is the harm. Recursion needs no special case (the worklist reaches its least fixpoint; collapsing an SCC to the ABI set would report writes no member performs). It is x64 only, gated at `calleeClobbersFor` in `lifter.ts`. **`RegState.invalidateCallerSaved` must NOT be narrowed with it**: it deletes the *expression* recorded for a register and needs an over-approximation, where this is an under-approximation by construction (`peek-a-bin-lh6`). The browser builds it inside the `decompileFunction` RPC, from the same message that consumes it, so there is no sender and no ordering race; the cache key is a token minted from array identity, never a content hash, and the counter never resets, so `CallSummaryCache.clear()` is hygiene rather than correctness. (`peek-a-bin-s2ws`)

- **ARM64 publishes its recovered switch tables' byte extents, and the masking is on the decoration side.** `findArm64JumpTables` (`arm64.ts`) recovers the `adr`/scaled-load/`add`/`br` chain; `detectArm64Functions` returned `jumpTableSpans: []` one screen below it, so table words rendered as instructions, one of them a `cbz` aiming outside the image. The cost is the **view**, not the decode — A64 has no gap fill, so nothing was invented or eaten; the spans *withhold* words, which is why the fix has two halves (publishing and consuming) and each is separately controlled. Four rules: the span is the extent `readArm64Table` actually **read** (`targets.length`), never the count the bounds check claimed, since marking an unread tail as data would delete real instructions; marking is by **byte range with an intersection test**, not containment, because an entry width of 1 leaves a word owning a single table byte; spans are deduped by byte range, since two dispatches legitimately share one table; and the filter lives in `decorateArm64Sweep`, never in `sweepArm64` or the cache, or two callers with different spans would share one entry. (`peek-a-bin-gb40`)

- **A PC-relative `LDR (literal)` is the ISA marking its own data — on A64 the only data-marking rule here needing no inference.** The instruction carries a signed 19-bit word offset and states the datum's width in its destination register (4/8/16 bytes for `w`,`s`/`x`,`d`/`q`), so the pool is read off one instruction; it matters because the fixed-width sweep decodes every word whatever it holds, and a pool word that happens to be a valid encoding renders as a plausible instruction *inside a `.pdata` extent*, i.e. presented as linker-vouched code. `findArm64LiteralPools` (`arm64Operands.ts`) is the grammar, `literalPoolTest` (`arm64.ts`) applies it. Five things: the pools are **not** a caller's fact and are derived inside `decorateArm64Sweep` from `raw` itself, because a forwarding step is exactly what `gb40` found falling out of step, and it reaches callers a `DetectResult` field would miss; `sweepArm64` and `Arm64SweepCache` stay untouched, only what is *presented* differs; a load sitting inside another load's pool is not honoured (one pass, not a fixpoint — re-admitting could only mark more, and short is the direction to err); a misaligned target and `prfm <prfop>, <label>` are both refused; and **`source` was judged separately and deliberately not changed** — the `.pdata` extent really is the linker's record, so downgrading on suspicion would dim 25k words to make one honest, and the answer where a word is *provably* data is to withhold it. (`peek-a-bin-qiws`)

- **The ARM64 stack frame comes out of `.pdata`, and the packed `FrameSize` field means the frame DELTA, not the total allocation.** `analyzeStackFrame` is an x86 operand grammar that refuses A64; `disasm/arm64Frame.ts` is the **second grammar**, reading what the linker already wrote down, and `disasm/stackFrame.ts` is the one place that dispatches between them. `pe/arm64Unwind.ts` decodes both encodings — the packed `.pdata` word and the `.xdata` unwind codes. Six things: `FrameSize` states `E - x29` exactly, so a crude total-allocation reader is measuring the wrong thing; an area allocated *below* the frame pointer is outside every unwind record in both encodings, by design, so `frameSize` is a lower bound for a chained function; **`frameSize` is the record's total and `frameDelta` the delta, and conflating them was a live defect no gate saw** (the corpus was 51/51 green with it in place) — `arm64Unwind.test.ts` is the whole instrument; a **negative** delta is refused, being x86's `addressesOwnFrame` rule reached from the A64 side (`peek-a-bin-s7hl`); the unwind codes run **backwards through the prologue** and carry more bytes after `end` that must not be counted, and two table errors there were caught by the corpus rather than by reading; and the var list has **no oracle** and is reported, not gated, with pre-index writeback, register offsets and the two-slot `ldp`/`stp` each excluded for its own reason. **The SIGNATURE was refused on evidence**: `.pdata` carries no arity information, AAPCS64 has no home space so any positional rule would gate on an empty population, and `inferSignature` returns null rather than a count nothing can check. **Only one call site was converted** — `mcp/tools.ts`, `useDecompileTabs.ts` and `decompileForLLM.ts` build a `StackFrame` only for `decompileFunction`, which refuses A64 above them, so routing them through the dispatcher would be inert at best and would hand an x86 lifter another architecture's frame at worst. (`peek-a-bin-hof0`)

- **In every arch dispatch, the `"unsupported"` arm must be checked *before* the `"arm64"` arm.** `dispatch.ts` and `mcp/disasm.ts` branch on `state.arch` in a chain whose tail is the x86 path, so testing ARM64 first drops an unsupported image straight into x86 — a full screen of plausible instructions the file does not contain, with no coverage signal to notice it by, since an x86 linear sweep decodes essentially any byte string. `WorkerState.arch`'s docstring says this too; keep both true.

- **`if (c) { continue; } break;` at the bottom of a loop body is emitted as `if (!c) { break; }`, and every restriction on it marks a position where the fallthrough means something else.** `collapseLoopTailContinue` (`cleanup.ts`) is the pass; it is cosmetic, and identical in every loop construct because `continue` and falling off the end both reach the back edge. The pair must be the last two statements of a **loop's own** body — hence an explicit walk rather than `rewriteBodies`, since in a `switch` arm `break` leaves the switch and inside a nested `if` the fallthrough is the rest of the body. The negation must be a **flipped comparison, never a `!`-wrapping**, or `if (!!x)` becomes `if (!!!x)`; `&&`/`||` are refused (De Morgan is correct and harder to read). The exit arm keeps its own spelling, and the pass runs **after `breakForwardGotos`** or a quarter of the population is still spelled `goto` and missed. The braces stay: `corpus/sweep.ts`'s guard scan then matched an `if` only when the line ended in `{`, so one-lining would have taken every single-terminator-body guard out of that scan. These guards were never in the polarity audit's population, so nothing in the corpus suite would catch a wrong negation — the oracle is `cleanup.test.ts` plus hand-reading. (`peek-a-bin-252`)

- **A block with no predecessor is not necessarily dead code, and "lifts to no statements" stopped identifying padding once step 4b hoisted branches out.** `structureCFG`'s leftover pass required reachability from the entry, on the reasoning that everything else is alignment padding; that excluded ~1160 blocks of real code, since an MSVC `__except`/`__finally` continuation or a 32-bit SEH scope handler is entered *by the unwinder*, has no predecessor at all, and sits past a `ret` while being ordinary code inside the function's bounds (`peek-a-bin-d3z`). Padding is still excluded by the test already doing the work — a block that lifts to no statements is not resurrected. But a `cmp`/`jg` block lifts to exactly one statement, the branch, and `pipeline.ts` step 4b takes it, so an emptied list read as alignment and a **test the machine makes** was dropped wherever this pass was the only route to the block. The test is now `… === 0 && !branches.has(b.id)`, because `branches.has` *is* "step 4b took a statement out of this block" — asked of the block, not its instructions, so a jcc the lifter deliberately refused to model still counts as contributing nothing. **No gate could see it**: the statement-drop audit snapshots after 4b so both sides are empty, polarity only judges guards that exist, `staleGuards` counts wrong readings not absent ones, and gcc compiles a shorter function happily; the instrument is the count of blocks left unvisited split by whether `branches` holds an entry. (`peek-a-bin-3zji`)

- **A switch arm that ends in a test must say so: `break` is a claim about control flow, not a terminator you can always append.** `armBody` claimed one block and closed it with `break` however that block ended, which for a block ending in a conditional jump is false twice — the switch does not end there, and **the condition goes with it**, since step 4b has already hoisted the `IRBranch` out and nothing else asks the block what it tested, leaving both successors as regions the emitted C can never reach. `armExit` (`structure.ts`) spells the block's own exit: `if (cond) goto <taken>;` then `goto <fallthrough>;` for a conditional jump, `goto <succ>` for an unconditional one, `break` only for a block with no successors. Two decisions: the transfer is **spelled, not followed** (`armFrom`'s doctrine — a `goto` to the target's label is faithful whatever the target is), which keeps it out of the switch's convergence scan so the guard ledger is provably flat; and a `goto` where `break` was already right is noise rather than a claim, so it is emitted uniformly rather than guessing at the join. **The bead's suggested fix — giving `armBody` `structureFrom`'s treatment — was measured and refused**: naively it empties every arm (the arm's own block is in `switchStopAt`, and *every gate stayed green*), and with `enterStart` it still appends an unconditional `break` wherever its walk stops. The instrument is `armExit`'s own answer, gateable at 0. (`peek-a-bin-pqs5`)

- **Register names follow the image's width, and the phi cannot tell you what that is — ask the live range, not the function.** `canonReg` maps every alias to the 64-bit parent because that is the register's *identity* and SSA keys on identity, so `phi.dest.size` is 8 for every phi even in 32-bit code and a width-based inverse has nothing to invert; lowering a phi to a copy with the canonical name emitted `rdi = rax` inside a function whose every other line said `edi`. `destroySSA` takes the width from the function's own statements (`registerSpeller`), falling back to `regAtSize(canon, 4)` (`peek-a-bin-1k4`).
  - **One name per *function* is still wrong** where a register carries two live ranges of different widths at once — ordinary MSVC output — giving a 64-bit entry-value pointer and a 32-bit clobber both the name `r9`: a write through the wrong pointer and a read of an unassigned name, in C that compiles because gcc declares `r9` and `r9d` as two unrelated `long`s. Naming is per **phi web** (the versions a phi ties together transitively, restricted to one canonical register), taking the widest mention of its *own* members; the function-wide answer is the fallback for a web left with no mention. `nameClobberedReads` and the phi copy's `clobber` branch build the same name, so both pass the version or neither may (`peek-a-bin-pzws`).
  - **The phi's fake *width* is inert and its canonical *name* leaked through one line of `splitStaleReads`; giving the phi a truthful width in `ssa.ts` was measured and is not worth a session.** Only 11 sites read an `IRReg`'s `.size` at all and just two are genuinely downstream (both in `fold.ts`), neither sees a phi-derived register on this corpus, and both already fail conservatively — a truthful width would make folding more aggressive rather than repair anything. What reached the page was `spellings` treating a **phi operand** as a read when it is the canonical identity; the fix is one `continue`, admitting such a row only when a later pass substituted a real value into it. (`peek-a-bin-0s6e`)

- **A register name the image has no encoding for is a gate, and the only oracle here that can see a wrong register name.** `unencodableNames` (`corpus/emitAudits.ts`) is asked of **PE32 only**, and that restriction is what makes it an oracle: a 32-bit image has no RCX, so every occurrence is provably a name no instruction wrote. On x64 `rcx` is a correct spelling and separating a canonical name from a real 64-bit read needs the live range's width, which the emitted text does not record, so the x64 pair contributes a structural 0 and `funcs` beside it is the liveness half. **gcc and `corpus/staleReads.ts` are both blind**: `preludeFor` declares every undeclared identifier as its own `long`, and `staleReads` compares the *name* a read uses (deliberately, since a correct live-range split emits two names for one register). (`peek-a-bin-0s6e`)

- **How much of the argument area frame recovery is still missing is REPORTED, never gated.** `offsetNamedArgs` (`corpus/emitAudits.ts`) counts an `arg_0x<N>` at a slot `stack.ts` would have indexed had it recognised the frame; the sub-slot half is reported apart, being correctly offset-named at any level of recovery. **Reaching 0 is the wrong target and that is measured, not argued**: a variant naming all 35 x64 slots takes the row to 0/0/0/0 and moves no other number in the report, while declaring four parameters that the callee-saved registers immediately overwrite — and `peek-a-bin-g186` reaches the same 0 by declaring *no* parameter there, so the row cannot tell the two apart. The instrument that can is the emitted parameter list read against `objdump`. Nothing else sees the class: an offset-named argument is well-typed C, states nothing false, is not an admission, and never reaches struct synthesis as a parameter. (`peek-a-bin-emlv`)

- **ARM64X carries machine 0xAA64 and is refused by decode rate; ARM64EC does NOT — it is marked x64 (0x8664).** Settled from Microsoft's documentation and lld, since no such binary exists here; **0xA641/0xA64E never appear in a linked image's machine field** (they are object/lib markers). Consequences: the refusal's real population is an ARM64X image marked 0xAA64 plus an image whose machine word does not describe its bytes, never an ARM64EC one; and **an ARM64EC image, and an ARM64X marked 0x8664, take the `"x86"` arm and are disassembled as x64 with nothing said** — a real misclassification, knowingly left alone, because routing on CHPE would be a decision taken on a field never once read non-zero on any file here. The evidence actually used is the bytes: an A64 handle decodes ~97% of the real ARM64 binaries against ~22-28% of x86/x64 ones — **a quarter of arbitrary x86 bytes decode as *something* in A64**, which is why the failure was silent and why the floor is 50%. `disassembleArm64` throws `Arm64DecodeRateError` below it on sections of 256+ words and `detectArm64Functions` degrades via `DetectResult.omitted`, since `.pdata`, exports and unwind handlers stay true. The calibration is now gated in **both** directions by `npm run corpus:arm64`, with `coffHeader.machine` as the oracle. Stated limitation, not narrowed by the gate: an ARM64X image is largely genuine A64 and may pass the floor, and there is none on this machine. (`peek-a-bin-2t1`)

- **A hybrid image has TWO exception tables, `pe/pdata.ts` reads one, and the one it reads is the one the machine word describes.** The exception directory always holds the table of the architecture the image *presents itself as* — x64 12-byte entries for ARM64EC (marked 0x8664), ARM64 8-byte entries for ARM64X (marked 0xAA64) — and CHPE's `ExtraRFETable` (at 0x40 of `IMAGE_ARM64EC_METADATA`, size at 0x44, both RVAs) always holds the other; for ARM64X the dynamic-value relocations swap both at load, so a *static* reader sees the ARM64 view. So `parsePdata` is **right for every hybrid case and incomplete for all of them**, and machine-keying is right here and could never be right for the other table. Reading the second table was deliberately not attempted — `chpeMetadataPointer` has never been observed non-zero on any file here, so a consumer would be unverifiable in both directions. **The two hybrid machine constants are gone and one was WRONG rather than merely unreachable**: `isArm64Machine` sent 0xA641 down the ARM64 path, which would have read 12-byte entries at an 8-byte stride — `peek-a-bin-kwc`'s desynchronisation from the other direction. **Do not re-add either.** Rests entirely on documentation: no such binary exists here, no `ExtraRFETable` value has ever been read. (`peek-a-bin-c71x`)
  - **Where the image declares CHPE metadata the refusal message says so, instead of inferring hybrid-ness from the rate.** `PEFile.loadConfig.chpeMetadataPointer` reaches `Arm64DecodeRateError` through `configure` → `WorkerState` → `Arm64Context`, and is **consumed for prose only** — the throw condition and every caller's behaviour are untouched, which is what makes it safe where `peek-a-bin-7p5t` refused a consumer. It is optional, not a dependency: only a **non-zero** value is evidence (`0` says *not* hybrid, `undefined` says unreadable, and collapsing the two makes the field useless). It is session state keyed on **`machine` being declared** rather than on its own presence, or one file's CHPE pointer stays attached to the next file's refusal; and it is **not in any cache key**, or one file's prose costs another file's sweep. `mcp/disasm.ts` is deliberately not threaded. The non-zero branch is fixture-only. (`peek-a-bin-3ucw`)

- **`.pdata` is authoritative for x64 function boundaries and beats prologue scanning.** Where a `.pdata` range exists, a prologue-byte or padding-heuristic candidate strictly inside it is a re-detection of a function already known exactly, not a new function. Evidence about an *entry point* — call target, jump-table target, export, entry point, unwind handler, `.pdata` begin — still wins inside a range. PE32 has no `.pdata` to arbitrate and still over-produces. (`peek-a-bin-abv`)

- **An MSVC x86 `__finally` funclet is not a function, and the SEH scope table must not be used to PROTECT one.** The funclet is emitted *inside* its parent, reached by a `call`, ends in `ret`, and the parent resumes on the next byte — so it is a call target and hence a function start by every other rule, and since sizes are distance-to-next-start it cuts its parent in half and the parent loses every `jcc` aiming past the new end. `interiorBranchedOverStarts` (`functionDetect.ts`) withdraws such a start. The trap: the file *does* name some of them in `_EH4_SCOPETABLE` records in `.rdata`, so `strong` means "named by a table the parser reads", not "named by the file" — feeding those handlers into `strong` re-introduces 9 withdrawn starts on t32 and 7 on w32, each cutting its parent in half again (measured, not reasoned). The table's real content is *funclet-of-parent*, which belongs in a relation, not in a set that protects a start. (`peek-a-bin-sysf`)

- **`interiorBranchedOverStarts` has FIVE admissions, and each names a different kind of evidence.** (1) The original: nothing outside the previous function calls the start *and* a conditional jump that function can execute crosses it. (2) An unconditional `jmp` over a start **nothing reaches at all** — no `call`, `jmp`, `jcc` or jump-table case — since the tail-call/shared-epilogue ambiguity is entirely about the far side of the jump and both alternatives are *reached*; `reached` must be a union over every transfer kind, and `reachableCrossings` decodes forward rather than reading the sweep's grid. (3) `[ebp + N]` in the **first** instruction at an address is a read of a frame some other function established, because nothing has run there to set one up and no x86 convention passes EBP; **at least one caller is required**, or there is no evidence the address is even an instruction boundary, and the first instruction is decoded from the boundary (`firstInstructionOperands` uses `decodeOne`), not read off the misalignable linear grid. (4) The funclet has **two entries** — MSVC emits unwinder-only register reloads and the parent's `call` names the body *past* them — so the same test asked one instruction earlier: the instruction ending *at* the boundary reads memory through the frame register and falls into a body all of whose callers are inside the same function. (5) The previous function's own SEH scope table names the boundary: `src/disasm/seh32.ts` reads `_EH4_SCOPETABLE` (16-byte header, 12-byte `{EnclosingLevel, FilterFunc, HandlerFunc}` records, no count field, NULL filter meaning `__finally`), `seh32FuncletRelation` turns it into `funclet → parents`, and the admission is **`parents.has(prev)`** — a relation, never a `strong` membership. Three things to keep:
  - **The frame test in (4) is the whole restriction and only the emitted C can see it.** Relaxed to "the predecessor is not a terminator" it also takes a boundary whose predecessor is a `noreturn` call, appending statements that claim control flows out of it — and `npm run corpus` reports the relaxed version **clean, exit 0**.
  - **Dropping the pre-existing "no caller outside the previous function" test swallows `__SEH_epilog4`**, which reads its caller's frame by design and has 30-odd call sites; its body ends up as a `loc_` inside `__SEH_prolog4` while every call site still names a function that no longer exists — and the function count moves *toward* the target while `distinct callees lost` stays 0.
  - **The rest of the family is refused on evidence, and the count-chasing rule is invisible to every gate.** Withdrawing the whole family on body shape (`push X; call; pop ecx; ret`) moves the count much further "toward" the target with `npm run corpus` at exit 0 and `compare.mjs` flagging the same rows as the correct change — so no instrument here distinguishes a right withdrawal from a wrong one, and the oracle is reading the parent's emitted C at the join. Specifically refused: `push <imm>` with a `ret` predecessor (byte-for-byte a legitimate one-line helper); `push <callee-saved reg>` (the tree already reads that as a register **save** — `peek-a-bin-6lmh` — and two contradictory readings of one instruction is worse than the miss); "the predecessor is unreached" with no test of what it does (it takes a real function with a full hot-patch prologue and two callers); and moving a start *backwards* onto the unwinder entry (those entries are admitted by nothing and reached by nothing). (`peek-a-bin-qe8z`, `peek-a-bin-d827`)

- **A folded funclet leaves its parent calling an identifier the output never defines — measured, adjudicated, and deliberately NOT repaired.** The parent still contains `call <funclet>` while the funclet's body sits below it under a `loc_` label in the same function; both halves are faithful in isolation and not connected. `goto` is wrong (the machine calls and the funclet returns, so control comes back) and re-emitting the funclet restores `qe8z`'s defect. A **comment naming the label is available at under half the sites** and would state something false at the rest, since the block leader there is the unwinder's own entry a few bytes earlier — and its coverage is perfectly anti-correlated with need, because a labelled site's `sub_<HEX>` and `loc_<HEX>` carry the same hex string, so the repair exists exactly where the call can already be followed. Forcing a label at the target is a **CFG change, not a spelling one** (a `call` is not an edge here, so the entry is mid-block by construction, and no emitted statement carries the target's address to hang a label on). The outcome is the instrument: `corpus/undefinedCallees.ts`, report-only, splitting internal from external with `internalLabelled`/`internalThreaded`/`internalUnlabelled` beside them — **read `internalUnlabelled`, not `internal`**, since folding more funclets raises the latter without costing the reader anything. Gating becomes worth re-arguing only if `internalUnlabelled` reaches 0. (`peek-a-bin-pf5g`)

- **"A call target immediately after a `ret`/`jmp` is a function start" is subsumed, and reviving it as *strong* evidence is worse than inert — the heuristic is deleted.** `detectFunctions`' `prevWasUnconditional` had one reader whose add can never be new (`callTargets ⊆ addrSet` by construction). **The tempting reading is exactly backwards**: an MSVC `__finally` funclet is a call target emitted at its parent's **tail**, past the parent's last `ret`, so "call target after a `ret`" *describes the withdrawn population* — the retired guard names roughly half the starts `interiorBranchedOverStarts` withdraws, including the very addresses the `strongStarts` docstring already names as its counterexample. The `jmp` half is ambiguous on a population where its one disambiguator (an *unreached* boundary) is false by construction, since every address it fires on is a call target and hence reached; on x64 it is doubly vacuous. Control does not fall through a `ret` or `jmp`, so what the guard read was *layout* adjacency, which is a tail funclet precisely. **No gate can see either choice** — the corpus is byte-identical whichever way it goes — so the census is the only instrument and it lives in the `callTargets` and `strongStarts` docstrings. (`peek-a-bin-7lue`)

- **A jump-table case target is not a function start.** `detectFunctions` added every case target to the function-entry set, and sizes are the gap to the next entry — so the function holding the `jmp [table]` ended at its first case and each case body became a bogus function; `buildCFG`'s range guard then rejected every target as a block leader, the indirect-jmp block got zero successors, and `structureSwitch` was dead code on real input (**no `switch` had ever been emitted for a real binary**). Case targets go to a separate set, outrank a byte-pattern guess at the same address (case bodies routinely follow alignment padding), and are fed to `hybridDisassemble` as seeds via `seeds.ts` — without them, gap fill starts *on the table* and eats the head of case 0.

- **A recovered jump table's bytes are data, and only `DetectResult.jumpTableSpans` says so.** Seeding the case bodies is not enough: nothing walks *into* a table, so the gap fill reaches it as an uncovered range and decodes the case addresses as instructions — the corpus's last lost CFG edges. `detectFunctions` reports the extent it actually read, `hybridDisassemble` takes it as a last optional argument and marks it covered before computing gaps, and the client and `mcp/session.ts` carry it beside the seeds; **omitting the argument keeps the old behaviour deliberately**, since "nobody said where the tables are" is not "there are none". A bound compared against a *register* (`push 7 / pop ecx / cmp eax, ecx`) is followed back to the constant, because a table that cannot be sized is one whose bytes nothing knows to be data (`peek-a-bin-mk42`). Three follow-ups, each a separate question:
  - **A table with no bounds check has bytes but no cases.** `unboundedTableExtent` (`functionDetect.ts`) answers the byte question alone and reports `TableRead.dataOnly` — an extent with **no targets**, because reporting entries whose case order is unknown is what `peek-a-bin-div` refused; so `jumpTableSpans` is no longer a subset of `jumpTables`' extents. The extent is the maximal run of pointer-width words on the base's own grid holding code-section addresses, scanned in **both directions** (MSVC's reverse `memmove` names the table's *last* slot, and a forward-only read finds one entry); the fallback keys on "no cases recovered", not "no bound found", or the descending shape stays decoded as code; and it errs **short** — the run must contain the base, it stops at one non-resolving word, `MIN_UNBOUNDED_TABLE_ENTRIES` is 4 rather than the bounded path's 2 because the run *is* the whole evidence, it is confined to the code section, and it is restricted to the *indexed* operand form since `jmp dword ptr [0x…]` is an import thunk.
  - **A base that is not an address at all can still be a table base**: MSVC overlaps an unbounded table's entry 0 with the instruction in front of it, where that entry is provably unreachable. **A byte belonging to a decoded instruction cannot be a table entry**, so `overlappedTableExtent` starts the table at the first grid slot past that instruction and reports `[base + ptrSize, hi)` — marking the overlapped slot as data would delete the `jmp` in front of the dispatch. The evidence arrives by **deferral** (`TableRead.deferredBase`), settled when the address-monotone sweep walks onto an instruction containing the base and dropped the moment `insn.address >= base`, rather than by an instruction-extents array or a forward probe that could disagree with the sweep. The instruction must end **inside** the base slot; the run is counted from the base, not the span. **Shape 2 — a dispatch through a negative index, reading words *below* the base — is not a defect and must not be "fixed"**; it is refused three ways over, the caller's refusal of any `deferredBase` a recovered table already dispatches to being what makes that a property. The `and <index>, 3` beside these sites is corroboration from outside the rule and is deliberately **not** read here: the span question is not the index question. (`peek-a-bin-xqxy`)
  - **What bounds a table is one rule about one register, and it took two disagreeing declarations to notice.** `readAbsoluteTable` walked back to the first `cmp` it met without asking which register was compared, while `boundedCaseCount` tracked the index register but could not read a bound carried in a register — each wrong where the other was right. `boundedCaseCount` is now the one declaration. `and <index>, imm` is admitted as a bound of `imm + 1` and is the **stronger** form, stating the range exactly where a `cmp` states it only with the sense of the branch below it. A **write of the index between the bound and the dispatch ends the search** (`conditionSpoiled`'s rule for a guard), with `cmp`/`test`/`push` as the read-only forms and the string primitives refused explicitly because they write RCX/RSI/RDI while naming none. **A register check alone is refuted by measurement** — it halves the recovered tables, because these tails are reached by `jmp` so the preceding linear instructions are not the ones that ran — so `readAbsoluteTable` consults the sweep's `tablesByBase`, reusing the *entries* but **never a longer run than the first reading took**; first reading wins, being the one whose own evidence bounded the table. Not verified on x64: this corpus recovers 0 tables there, so the arms `recoverX64RvaChain` and `recoverDenseByteTable` gained are synthetic-fixture only. (`peek-a-bin-padl`)

- **There is exactly one notion of "loop": dominance.** `cfg.ts`'s `detectLoops` delegates to `decompile/ssa.ts`'s `detectNaturalLoops` — an edge `u → v` is a back edge only when v dominates u. The BFS-layer approximation it replaced called the merge block of every `if`-without-`else` a loop header, and the mis-structuring **deleted guards**, turning conditional stores into unconditional ones; a diamond is immune to that mistake and a triangle is not, so hand-written fixtures never caught it and `cfg.test.ts` plus `pipeline.test.ts` now pin both shapes. `detectLoops` also draws the loop markers in `useDisassemblyRows.ts`, so its semantics are shared with the UI.

- **`structureCFG` closes an `if` at the immediate post-dominator**, from `computePostDominators` (`structure.ts`) — `computeDominators` over the reversed CFG rooted at a virtual exit. The two "one arm ends in `ret`" shortcuts must not fire when that arm *is* the convergence point: in a triangle the branch target is the shared tail, so structuring it as the `then` body yields an empty body and drops the guard. A nearest-common-successor heuristic is not a substitute — for a switch it picks the default block, which is not on every path, and the code after the switch is lost.

- **`extractCondition` returns the condition under which the jump is TAKEN.** Every entry in `regstate.ts`'s `condMap` is taken-polarity (`jg`→`>`, `jbe`→`u<=`, `js`→`< 0`) and `identifyBranches` returns the block the jcc jumps to, so the branch target is the `then` body under the *un-negated* condition and `RegState.negate` is for the fallthrough. Backwards, this inverted every `if` and `while` the decompiler emitted while leaving the bodies in place — valid C stating the opposite of the machine, invisible to every stage-level test; `pipeline.test.ts` guards it end to end.

- **A guard is answered from the flags the Jcc *actually* reads, and only while the compare still describes them.** Two refusals in `extractCondition`, one defect class — the right operator over the wrong operands, which polarity cannot see (it checks the operator), gcc compiles, and which is not an admitted `__unrecovered_N`. (a) The forward walk clears the flags on anything not `isFlagTransparent`; it used to clear on *nothing*, so `cmp eax, 5 / … / sub ecx, edx / jne` emitted `eax != 5` (`peek-a-bin-jitf`). (b) A compare whose operand was overwritten before the Jcc is refused, because the block's statements are emitted **above** the `if` — `cmp eax, 5 / mov eax, edx / je` printed `eax = edx;` then `if (eax != 5)` (`peek-a-bin-xe01`). Both read `flagModel.ts`'s own tables (`isFlagTransparent`, `clobberedAfter`), never a copy; refusal *is* the repair, so the cost shows up as unrecovered values rather than as changed guard text. Gated by `corpus/staleGuards.ts`.

- **`push` and `pop` write no flags and are already in `NO_FLAG_WRITE`; a guard behind an epilogue restore is refused by `spoils`, not by the flag model.** Membership and `spoils` are two questions about one instruction and a `pop` answers them oppositely: it writes no flag, so the compare owner stands, *and* it writes its operand register, so the name the guard would use is gone — `test edi, edi / pop edi / pop esi / pop ebx / jne` would emit `edi != 0` over a restored callee-saved value. `baseMnemonic`'s exact match is what keeps `popf`/`pushf`/`pusha`/`popa` clobbering; a `startsWith("pop")` test would silently admit `popf`. Do not try to fix this class by moving the `IRBranch` earlier in the statement list — `structureCFG` emits a block's statements above the `if`, so the restore still runs before the guard (`peek-a-bin-thsj`).

- **A spoiled compare is recovered by MATERIALISING its operands at the compare, not by refusing the guard — and the cross-block case needs no new placement.** `spoiledCompareCapture` (`lifter.ts`) emits `flg_<compare addr>_<operand index> = <parsed operand>` per non-constant operand at the compare's own program point and builds the `IRBranch` over those, so the clobber runs between capture and guard and reaches neither. Four rules: the destination is an **`IRVar`**, not a deletable pseudo-register — a register-destination copy is folded away by `copyPropagation`, which leaves the recovered and the defective spelling textually identical and the class ungateable; the signal to `structure.ts` is `IRBranch.capturedAt`, an **address**, and `extractCondition` bypasses `conditionSpoiled` only when it equals the setter its own forward walk found, since asking `conditionSpoiled` of the IR condition defeats it outright (copy propagation has rebound the register out of the expression); the scope is a block-local **compare** owner, never a `result` or `bittest` one, whose value the instruction has not yet written; and the emitter must **declare** the capture, at `IRVar.size`'s width via `sizeToType`, preferring type inference only where it names the same width — `corpus/emitAudits.ts`' `preludeFor` manufactures `long flg_…;` for an undeclared one, so gcc reads clean over C the harness completed and the instrument is the count of invented prelude declarations. For a **predecessor**-owned spoiled compare, `reusablePredecessorCapture` (`lifter.ts`) *looks up* the capture the predecessor's own lift already emitted rather than placing one; it requires exactly one predecessor and that the capture be at the compare this jump reads. The corpus cannot separate this from simply reading the raw operands — only `pipeline.test.ts`, whose fixture stores over the compared slot itself, can (`peek-a-bin-xskz`, `peek-a-bin-x54q`, `peek-a-bin-zylv`).

- **`test` clears OF and CF; it does NOT clear SF — which is why `getCondition`'s `test` arm answers strictly more Jcc forms than its `result` arm.** For a **result** owner (`dec ecx`, `sub eax, ecx`) only ZF and SF are functions of the result, so only `je`/`jne`/`js`/`jns` are answerable. For a **`test`** owner every flag a Jcc reads is a function of `a & b` or a known constant, so `jle` collapses to `(a & b) <= 0` and `jg`/`jl`/`jge`/`ja`/`jbe` follow. **The suite had asserted the defect as the rule** (`it("returns unknown for a jcc with no meaning after test")`, commented "jle depends on SF/OF, which `test` clears") while its own neighbour answered `js`. Two things not to re-try: `jb`/`jae` and `jo`/`jno` read *only* a flag `test` clears, so they are constants, and emitting `if (1)` is a control-flow claim `structureCFG` may act on and no gate models; `jp`/`jnp` read PF, a real function of the result with no cheap spelling (`peek-a-bin-92yy`, `peek-a-bin-x72e`).

- **A Jcc alone in its block is answered from its predecessors, and only when every way in leaves the flags saying the same thing.** `flagScanStream` (`flagModel.ts`) prepends the predecessor's instructions when, and only when, the block's own scan finds no flag writer at all; `flagPredecessor` supplies the edge, answering with any predecessor when all of them are **unanimous** via `unanimousCompare`, and both consumers — `lifter.ts`'s `branchFor` and `structure.ts`'s `extractCondition` — read that one stream so they cannot drift about which edge. Four rules: the predecessor's **terminator must be skipped explicitly**, since `jmp`/`ret`/every Jcc are absent from `NO_FLAG_WRITE` and a walk that reads one clears the owner it came for (without the skip the whole change recovers 0); **either edge counts**, because a Jcc writes no flags and the predecessor's condition being true on a path is a fact about values; the walk continues *through* the block so `spoils` covers both sides with one grammar; and the condition is re-read from the owning instruction via `setFlagsFromCompare`, never from the reading block's `RegState`, which never executed the compare. Unanimity is a **text-equality test over Capstone's operands and never a merge** — no `rip` (resolved against the instruction's own address, so equal text at two addresses is two expressions), no stack pointer, and no `result`/`bittest` owner, whose condition depends on the destination too. **Nothing in the corpus protects the disagreeing sites**: answering from the first predecessor instead recovers 12 more guards and `npm run corpus` exits 0 with "no regression", because polarity judges the operator (right) and not the operands (wrong on one path), and `staleGuards`' population is block-local. Materialising a per-edge value would need a new `pipeline.ts` step, and duplicating the block per predecessor changes the CFG at a merge point where loop shape is decided — both refused (`peek-a-bin-suql`, `peek-a-bin-xdxt`, `peek-a-bin-0xe2`).

- **A memory destination is spellable; refusing it was a spelling limit that read as a dataflow fact.** `dec dword ptr [ebp + 0x10] / je` owns its flags like any `RESULT_OWNERS` form and the tested value is the destination read *after* the instruction ran. `flagModel.ts` publishes `destForm: "reg" | "mem" | "none"` for spellability while `destReg` stays for `spoils` — they answer different questions, and conflating them refused every row; `branchFor`'s old `irReg(destText, regSize(destText))` was worse than a refusal, since `regSize` falls back to 4 for any unrecognised name. Soundness is the **ordering**: `structureCFG` emits a block's statements above the `if`, so the guard reads the location after the store — asserted directly in `pipeline.test.ts`, since no unit test of `flagModel` or `branchFor` can see it. Refusal is on **any** intervening store with no aliasing attempt, and across a `push` (which writes `[rsp - N]`) although `writesMemory` exempts it for the compare case (`peek-a-bin-ie0j`).

- **A `lock` prefix changes atomicity, not values or flags — so it must not change any classification; but a locked read-modify-write with no value effect is a fence and must stay unlifted.** `withoutLockPrefix` (`flagModel.ts`) is the one declaration stripping it for the dispatch key, read by both `flagEffect` and `liftBlock` so they cannot disagree about the base mnemonic; `rep` must survive stripping (Capstone puts the string primitives in either the mnemonic or `opStr`) and the `raw` fallback keeps the verbatim mnemonic so an atomic exchange still says so. Lift before classifying: with the flag model fixed but `liftBlock` still dispatching on `"lock dec"`, the guard tests a location the block never stores to — one release early, in compiling C. Forms the lifter has no handler for (`cmpxchg`, `xadd`) reach `raw` by themselves; no whitelist of "safe locked forms" is wanted. `isValueNeutralLockedRmw` (`lifter.ts`) sends `lock or byte ptr [rsp], 0` back to `raw`, or `foldExpr` folds `x | 0` and `promoteVars` names the slot, leaving `var_0 = var_0;` and the fence gone. That test requires the **`lock` prefix as well as** the nil value effect — an unlocked `or [mem], 0` is a dead store, a different judgement — and refuses `and <mem>, <all ones>`, whose identity element is width-dependent and whose text-level reading misfires on real truncations. Atomicity is lost from the page deliberately; nothing in this IR expresses it (`peek-a-bin-3qrl`, `peek-a-bin-qbk3`).

- **`bt` is a compare over one bit and is neither a compare nor a result — it needs its own owner kind.** `bt` **writes nothing**, so unlike a result owner it needs no lift first; and **`bt` leaves ZF unaffected** (SDM: CF gets the selected bit, ZF is unaffected), so a `je` after one really branches on an older instruction's ZF and answering it from the bit would be a *wrong test*. `defines: "cf"` keeps it apart from `"zf-sf"`; `getCondition`'s `bittest` arm answers `jb`/`jc`/`jnae` and `jae`/`jnb`/`jnc` and nothing else. `parseBitTest` admits only a register bit base with an immediate offset: with a **memory** base the offset indexes a bit string and can select a bit outside the operand's own dword, so the reading would be unsound rather than merely unmeasured; `bts`/`btr`/`btc` stay clobbers permanently, their CF being the bit's value *before* the write. One predicate, two callers (`flagEffect` to claim ownership, `liftBlock` to record the same reading). Spell it `(x >> n & 1) != 0` with `>>`, not `>>>`, which `emitLogicalShiftRight` turns into an `__unrecovered_N` when it cannot determine the width. `corpus/sweep.ts` gained `BIT_TAKEN` in the same commit, keyed on the *immediately preceding* instruction being a `bt`; contorting the emitted C to satisfy the old table was refused as gaming the oracle (`peek-a-bin-frt8`).

- **The polarity audit's population was one trailing brace wide, and the loss would have been silent.** `corpus/sweep.ts`'s guard scan required a header line ending in `{`, so an `if` whose body moved onto its own line stopped being a guard **at all** — not judged, not skipped, not a row. `corpus/guardShape.ts` is now the one declaration of what a guard line is, read by the polarity scan, `auditLoopExits`' header detection and (through `statementOnLine`) the two terminator scrapes; `unparsed` counts every line starting with a guard keyword and an open paren that was not understood, and **gates at 0**. The condition is **depth-counted, not anchored** — widening the old regex in place gives `/\((.*)\)\s*(.*)$/`, greedy to the last `)`, so `if (a == 0) x = f(b);` reads its condition as `a == 0) x = f(b`, and a wrong condition is worse than silence. One-lining breaks three scrapes in three directions: polarity goes silent, `auditLoopExits` goes **red on correct output**, and `emitAudits.ts`'s `gotoCheck` reports `dangling` 0 out of a population it can no longer see — a gate at 0 passing because it stopped looking (`peek-a-bin-vwr5`).

- **The second hand-rolled guard-header pattern is gone, and the drift guard could not see it.** `corpus/selfAssigns.ts`'s `FOR_HEADER` encoded single-space formatting and a trailing brace, in a file whose `wrong` and `unresolved` columns **gate at 0**, and `build/guardShape.test.ts` missed it because that guard's tell is a regex *alternating* two guard keywords and this one named `for` alone. It now asks `forHeaderCond` and `splitForHeader` (`corpus/guardShape.ts`) and reads its assignment through `statementOnLine`; the grammar answers what the *line* is and what a caller wants out of it stays the caller's. `forHeadersUnsplit` — a header recognised and then refused by the splitter — is a **gate at 0** beside `forHeaders` as the liveness half, since a text-scraping audit fails by matching nothing. **Widening the drift guard to single-keyword patterns was measured and refused**: the three `corpus/` patterns it would trip (`sweep.ts`'s `OPENER`, its descriptive `siteOf` buckets, `clobbered.whiles`/`fors`) gate nothing and none reads a guard header as a whole line (`peek-a-bin-hfsq`).

- **A guard whose whole body is one terminator is emitted on one line, and `oneLinedGuard` (`emit.ts`) exists so the line cannot carry the wrong address.** It is handed the body's own `EmitResult` with the guard out of scope, because attaching the guard's block would anchor the arm to the jcc one decision earlier — the `peek-a-bin-8r0`/`peek-a-bin-lbz` class of false INVERTED — and `bodyAddrAt`'s `inlineBodyAddr` reads exactly that entry. Only the four **terminators** (`goto`, `break`, `return`, `continue`) are admitted: a one-lined *assignment* would hand `corpus/selfAssigns.ts`'s `ASSIGN_LINE` the guard as its destination, a row leaving a scan that gates at 0. `compare.mjs` flags `braced + inline`, not `braced`, or a guard changing spelling reads as a guard lost. The precondition was `guardShape.ts`; the benefit is density and nothing else (`peek-a-bin-0qib`).

- **A `for`'s init need not be the statement immediately before the loop; `initHoistable` (`structure.ts`) answers the general case.** The header repeats the init `structureFrom` already emitted, so one copy must go and only the emitted one may; hoisting moves the init **later**, so it is not enough that nothing in between touches the induction variable — the value must be the same after the move. Four refusals: a **whitelist** of what may intervene (`assign`, `store`, `comment`), never a blacklist, since a `label` in between is a jump target a `goto` skips today and would run after the move, and a `raw`'s effects are unknown by definition; a side-effecting init (`hasSideEffects`); any mention in between of the induction variable or of anything the init reads, scanned with `walkStmts` so nested bodies count (refusing on a read costs a `for` and claims nothing false); and a memory write in between when the init reads memory, with no aliasing attempt. `initAt >= 0` is **not** redundant with the equality test — `detectForLoop` can name a statement in a region this walk never emitted, and for an empty `result` both `indexOf` and `length - 1` are `-1`, so an equality-only test copies an init into the header that was never emitted (`peek-a-bin-9q2`).

- **`detectForLoop` must try every increment-shaped candidate, not the first, and a predecessor inside the loop body is not a source of inits.** A loop body routinely increments more than one thing (`for (p…) if (*p=='\n') n++;`), and the search picked `n`, failed the init test and returned null. Candidates are tried in block-id order and the first with an init wins — additive by construction, since a first candidate with an init behaves exactly as before. `p < header.id` stood in for "before the loop" and the latch is routinely numbered *below* its header, so the search found in-loop writes; `!bodyBlocks.includes(p)` plus the header named explicitly is what gets asked. **The suite pinned the proxy as the rule** — `it("ignores predecessors whose id is above the header (assumed back-edges)")`, justified with "real initialisers precede the header in address order", which the corpus refutes. **The rest of the funnel is refused on evidence: the update-position guard is not strict but exact** — every trailing `if` in every candidate loop contains a `continue`, `goto` or `label`, and a `continue` reaches a `for`'s update while the machine's back edge does not. Do not re-attempt it (`peek-a-bin-9q2`).

- **`mov <r32>, <same r32>` on x64 is a zero-extension, and the pass that lost it was `copyPropagation`, not the lift.** A 32-bit write clears bits 63:32, so `mov r8d, r8d` asks for exactly that; `isCopyStmt` admitted the plain `assign`, rewrote every reader to the **pre**-truncation version and dropped it — correctly by its own rule, since nothing in `r8d = r8d` says the high half was cleared. The truncation must therefore be **in the expression**, spelled `x & 0xFFFFFFFF` over the 64-bit parent, which `foldExpr`'s `narrowEnoughForMask32` already refuses to strip. Three bounds: `is64` only (PE32 `mov edi, edi` is the hot-patch pad and a real no-op), **32-bit width only** (`mov al, al`/`ax, ax` leave the parent alone, `mov rax, rax` writes what it read), and `canonReg !== "rsp"`. Scoped to the lift: `firstCalleeSavedWrites`' own self-move test answers a different question and must keep reading `mov X, X` as a non-definition, or real `Sleep(esi)` calls lose their argument (`peek-a-bin-tez6`).

- **A branch condition goes through the lifter's real `parseOperand`.** `extractCondition` used to re-parse `cmp`/`test` operands with a private `parseSimpleOperand` that hardcoded `size: 4` and never called `ripRelative.ts` — the tenth hand-rolled copy of parsing this repo has centralised nine times, and the one that decides what every guard says. `cmp byte ptr [rcx], dl` read as a 32-bit load and rip-relative operands kept the literal `rip + 0x…`; the width alone then recovered frame slots, `INVALID_HANDLE_VALUE` and dozens of structs. `structureCFG` takes `is64` for it and `pipeline.ts` passes it (`peek-a-bin-w6f`).

- **SSA version 0 means a register's *entry* value; the definition counter starts at 1.** `renameExpr` and the phi-operand fill map a read with an empty version stack to version 0, so a `newVersion()` also handing out 0 makes the incoming value and the first definition one `(name, version)` pair — which `ssaopt`'s `sameReg`/`regKey` key on, so copy propagation, constant propagation, GVN and DCE all treat them as one value and a `return` on a path that never assigns the accumulator returns the other path's value (`peek-a-bin-swi`).

- **Version 0's repair is taken at the function's entry and nowhere else.** No statement defines version 0, so `splitStaleReads`' usual copy-at-the-definition has no site; taking it at the top of the *reading* block fails when a strictly dominating block has already written the register — the read binds to a name holding something else, or the copy is taken past the damage and preserves the wrong value under a name that looks recovered. The entry is the one point where the register provably holds version 0, so one copy per register per function serves every stale read of it. The `wcslen`-loop objection needs a block the *unwinder* enters, which has no `idom` entry, so `dominates` declines it structurally. Gated by `corpus/staleReads.ts` (`peek-a-bin-dqpk`).

- **`liftBlock` emits plain register reads; it does not substitute `RegState`'s symbolic value at each read.** It used to, while still emitting the assignment that produced the value, so one machine `call` became three calls in the IR and `sub/sar/dec` emitted RCX subtracted three times. Propagation belongs to SSA, `ssaopt` and `foldBlock`, which have the version information that makes it sound; `RegState`'s symbolic values are still needed for `getCondition` and flag tracking (`peek-a-bin-urs`).

- **No read of RSP may be moved to another program point.** `push`, `pop` and the return address a `call` pushes are not lifted, so RSP changes with nothing in the IR recording it and there is no definition chain to reason over; inlining `mov ebp, esp` across an unmodelled `push` printed `*(int32_t*)(esp + 8)` for `[ebp + 8]` — a base register the instruction never named, one push off the value it did. **Both** `ssaopt.ts`'s copy propagation and `fold.ts`'s single-use inlining guard it, and both are needed: the second reintroduced the defect the moment an unrelated fix made the frame-pointer copy single-use (`peek-a-bin-rt4`).

- **Three stack idioms ARE lifted, because an unlifted `pop` is not an SSA definition and every later read of that register binds to the value it held before.** (a) **`push <imm>` / `pop <reg>`** is a `mov` in stack clothing and MSVC spells it pervasively; unlifted it emitted `*_errno() = 0` for `push 0x16 / pop esi / mov [eax], esi`, an inverted success/failure return. The pairing has one declaration, `disasm/stackIdiom.ts` — a leaf importing nothing, so `decompile/lifter.ts` does not gain `functionDetect.ts`'s Capstone edge — because the same idiom sizes a jump table there and the two could otherwise disagree; `pop esp`/`pop rsp` is refused explicitly, ESP being the one register no stage models; and `loneImmediate` must accept Capstone's `push -2` spelling of a sign-extended `imm8` (`peek-a-bin-3axd`). (b) **The same idiom split across a branch is a phi of immediates**, so the definition must land in *each predecessor* — every real site selects a *different* constant per arm — which is why it cannot live in `liftBlock` at all and is `pipeline.ts` step 2b (`crossBlockPopImmediates` + `liftCrossBlockPops`), appending through **`pushBeforeTerminator`** or the definition lands after the `IRBranch` that reads it. Four refusals make it sound: every predecessor must pair or none do; a pushing predecessor's only successor must be the pop's block; its tail must not be a conditional jump; and the `pop` must be its block's **first** instruction, which makes the interval provably empty and is why no second register-liveness grammar was written. The statement carries the **pop's** address, so `corpus/popReads.ts`' `popsLifted` covers it with no second notion of "handled" (`peek-a-bin-6ilz`). (c) **A matched `push <reg>` / `pop <reg>`** becomes `stk_<pushaddr> = <reg>` and `<reg> = stk_<pushaddr>`, from `matchedStackSlots` (`lifter.ts`) — a whole-CFG depth analysis, since a save and its restore are routinely blocks apart. The slot is identified by the **pairing**, never by an address, so no RSP-relative expression is built; it is a pseudo-**register**, not an `IRVar`, so `copyPropagation` and DCE erase it wherever it recovers nothing and a correctly-read save/restore stays byte-identical. The lattice needs a **TOP** element — seeding an unreached block with the empty stack meets a concrete depth 0 against the real shape and takes the whole region to BOTTOM. It refuses across a `call` (whether the callee or the caller pops is not a fact about the instruction), across a store *through* ESP, and on `pop esp`/`leave`/`enter`/narrow pushes; an immediate or memory push keeps its **depth** and claims no value. `regState` is deliberately not told about a slot pop, or `collectArgs64` would read a stack restore as an invented argument and the arity over-count gates at 0 (`peek-a-bin-6f3v`). **Every replica of the lift loop must carry all three calls** — `popReads.ts`, `staleReads.ts` and `lostDefs.ts` replicate `pipeline.ts` stages 1–3, and a replica missing one keeps reporting rows a landed fix removed, so a green tree reads as red; `stackIdiom.test.ts` fails if any file calling `liftBlock(` does not also call `liftCrossBlockPops(` and `matchedStackSlots(`.

- **A trivial phi's operand is the register's identity, not a spelling.** `insertPhis` mints every phi as `irReg(canonReg(...))`, so an operand is `rsi` at eight bytes even in 32-bit code; `destroySSA` corrects that for a *lowered* phi copy through `registerSpeller`, but `simplifyPhis` substitutes the operand into every reader with no lowering step left to correct it, putting a name the image has no encoding for on the page. It now spells the operand the way the value's own mentions spell it (`registerSpeller`'s `perVersion` rule), with the width following the name; a version with no mention keeps the operand as it was. `corpus/emitAudits.ts`' `unencodableNames` is the only oracle that sees it — gcc declares `rsi` and `esi` as two unrelated `long`s and `staleReads` compares the name a read uses, deliberately (`peek-a-bin-pzws`).

- **`foldBlock` counts uses inside ONE block, so a definition that escapes the block is not single-use.** Inlining moves the right-hand side into its one reader and **deletes the assignment**, which is correct only while that reader is the last thing wanting the value; handed one block's statements, a definition read once locally and again two blocks later looked single-use and every successor read named a register the emitted C never assigns. `blockLiveOut` (`fold.ts`) is ordinary backward may-liveness over the CFG, computed once on the unfolded program in `pipeline.ts` step 4, and `foldBlock` refuses any candidate in its block's live-out set. Three rules: the refusal is `killedInBlock`-guarded, since a later definition of the same register ends this value's live range and the live-out set then describes the *other* definition; a **`raw` reads nothing** (an unlifted instruction reaches the page as a comment, so its register names are not reads) while a **`branch` very much is**, its condition being extracted after this stage; and liveness is taken **before** any folding, erring safe. `blockLiveOut`'s block parameter is structural, not `BasicBlock`, so `fold.ts` still imports only `ir.ts`. Gated by `corpus/lostDefs.ts` (`peek-a-bin-7eyn`).

- **`analyzeStackFrame` and `inferSignature` take `arch: ImageArch` ahead of `is64`, because `is64` is the PE32+ magic and true for ARM64.** Both are x86 instruction grammars; the parameter is required and positional so an unthreaded call site fails to compile. Both **return empty rather than throwing** — the throw arm is for stages whose whole output is instructions, and these are per-function analyses feeding a view whose caller must still render; `unsupportedOnArch` is not called, there being no channel through `StackFrame | null`. The two refusals have different standing: `analyzeStackFrame` already answered null for every A64 function, so it is unfalsifiable on this corpus and pinned by `stack.test.ts` alone, while `inferSignature` was answering `{ convention: "fastcall", paramCount: 0 }` and that reached the panel — hence `FunctionSignature | null`, since the type could not say "unknown". Answering `"aapcs64"` instead was refused: the count is the false half. The refusal must precede `inferSignature`'s empty-instruction early return, the one path that answers from `is64` without looking at an instruction. `src/disasm/__tests__/archThreading.test.ts` guards what the type cannot see — a caller writing a literal `"x86"` instead of deriving the arch from the machine word (`peek-a-bin-56q`).

- **`arg_N` in a stack frame means argument *position*; the frame register's displacement from the entry stack pointer is the published quantity, `StackFrame.frameDelta`.** `stack.ts` numbers a slot positionally only from a recovered displacement; otherwise the name is offset-based (`arg_0x10`). The name is the only channel to `structs.ts`, which keys parameter provenance off `^arg_(\d+)$` precisely to exclude frame-pointer-omitted RBP — where `[rbp+0x10]` is a struct field access, not an argument — so do not loosen it. `promote.ts`'s `frameRegisterAliases` follows a `splitStaleReads` copy of the frame register (`ebp_1`) **only when `frameDelta !== null`**: a frame pointer is invariant so every version denotes the same frame, and under FPO two versions are two objects. The stack pointer gets none of this — it moves. The old boolean `StackFrame.framed` answered two questions with one bit ("is it a frame pointer" and "is the geometry canonical") and is gone; each consumer asks its own question of `D`. **The FPO refusal is unfalsifiable on this corpus** — removing it leaves emitted C byte-identical — but the *mechanism* is worth 1147 sites, so do not remove it because nothing moved. **Refused and not to be re-attempted:** asking `inlineFrameGeometry` whether the frame register survives to the returns — `stack.ts` has no CFG and can only ask in address order, while MSVC lays a mid-function epilogue before code that executes earlier, so it refuses the frame of every function with an epilogue. The two real mid-body repurposings (`longjmp` reloading EBP out of a `jmp_buf`) are now a gated row, `corpus/frameRepurpose.ts`, whose oracle is the instruction stream and which **classifies** the write — `pop <fp>`/`leave`/`popa` are epilogue restores and open no window. (`peek-a-bin-5zpo`, `peek-a-bin-cvri`, `peek-a-bin-633s`, `peek-a-bin-nhw0`)

- **…and the copy is only recognisable while the tie-back survives: DCE deletes `ebp = ebp_1`, leaving `ebp_1 = esp` alone, which must be refused** (no read of RSP may be reinterpreted at another program point). Shape 3 is `StackFrame.frameEstablishedAt` — the address of the instruction that set `D` — with `frameRegisterAliases` seeding its fixpoint from any `assign` at that address whose destination is a variable. It keys on the **address**, never the variable's name (`ebp_1` is a spelling, not dataflow) and never the source, which is what makes the shifted `lea rbp, [rax - 0x488]` form work. Undo it and declared slots go unpromoted, spelled `*(int32_t*)(ebp_1 - N)` beside a `var_4` nothing reads. No corpus gate can see any of it — the base output was true, merely less readable. (`peek-a-bin-xb2f`)

- **…and `isParam` is decided by that displacement, not by whether the prologue was canonical.** `inlineFrameDisplacement` computes `D = E - V`; argument 0 is at `[E + slot]`, so `[<fp> + off]` below `D + slot` is below the return address, hence a local. A refusal is **total** — nothing recorded, the deref left alone — since renaming it to a local claims a stack slot as falsely as calling it an argument. Gating on the old `framed` instead was measured and **refused**: it demotes genuine `push*; mov rbp, rsp` arguments. `promote.ts` no longer re-derives the threshold either (it had a hard-coded `is64 ? 0x10 : 0x8`): a positive `bp:` key resolves in `paramLookup`, a negative or `sp:` one in `varLookup`, so the argument-area judgement lives in one file; `StackAccess.aboveFrame` asks that structural question, and it must not consult both maps or route on the name. `addressesOwnFrame` refuses `D < 0` outright — the frame register pointing above entry `sp` means the function is establishing somebody else's frame (`__SEH_prolog4`), where the threshold would record the caller's return address as `arg_2`. (`peek-a-bin-ikd`, `peek-a-bin-s7hl`)

- **…and the prologue may be in another function: MSVC delegates it to `__SEH_prolog4`.** `push <framesize> / push <scopetable> / call __SEH_prolog4` gives a perfectly ordinary EBP frame; `hasFramePointerPrologue` looked only at the function's own first two instructions, so 296 genuine argument accesses were named `arg_0x8` and were invisible to `findOrCreateLinked`. The rule is stack **arithmetic**, not a byte pattern: `lea <fp>, [<sp> + N]` establishes the *caller's* frame precisely when `N + delta === -slot`. Three refusals carry it — the caller may only `push` immediates before the `call`; the helper may not `push <fp>` (a callee-saved save satisfies the arithmetic); `<fp>` must survive to the helper's `ret`. Residue is PE32 detection over-production, whose prologue is outside the detected range. (`peek-a-bin-emlv`)

- **…and on x64 an index is not enough to name a slot: the home space is four slots the caller reserves and the callee may spend on anything.** `[E + slot]`…`[E + 4*slot]` holds argument N only if the callee spilled that register there itself; `ARG_AREA.homeRegs` is the geometry and is **empty on x86**, where the caller pushes everything. The discriminator is `inlineFrameGeometry`'s `homed` — a spill of the argument's *own* register while `argsPristine` holds (no instruction has yet written any register but `sp` and `<fp>`), so no liveness analysis is needed. An unfilled home slot is **withdrawn entirely** by `inUnfilledHomeSpace` (`stack.ts`), not re-labelled: it is not a local either, the caller owns the storage. Getting this wrong is not cosmetic — `paramIndexByBase` lets a home slot's `arg_<N>` displace the argument register's provenance claim, so a saved register named `arg_0` links to whatever callers pass. **Do not chase `offsetNamedArgs` to 0**: a variant naming all 35 slots also reaches 0 and moves nothing else in the report while printing four declared parameters that a callee-saved save overwrites at entry; `offsetof` at ratio 1.00 sees a self-consistent declaration, never a wrong parameter identity, and the only instrument that separates the variants is the declared parameter list read against `objdump`. (`peek-a-bin-sx57`, `peek-a-bin-g186`)

- **Recursing into a statement's nested bodies is `ir.ts`'s `bodiesOf` / `rewriteBodies`, one declaration each.** `rewriteBodies` was a verbatim copy in `structure.ts` and `cleanup.ts` plus two specialisations under other names — four hand-synced `IRStmt` switches all ending in `default:`, so a new body-carrying kind would be returned unrecursed in every one, silently. Both now end in an exhaustive `never`. `for`'s `init` and `update` are single statements, not lists, so neither reaches inside them; a caller needing that wants `foldStmt`'s shape. (`peek-a-bin-svwt`)

- **`+`, `-` and `*` do not model wraparound, and the const-const fold site has no width evidence to key one on.** `knownWidth` returns null for an `IRConst` deliberately — `IRConst.size` is the CPU *mode*, 8 for every immediate in a 64-bit binary, not the operand's width. Wrapping them with `| 0` / `Math.imul` the way the bitwise arms do **introduces** a defect: those go through `fold64`, these do not, so a correct 64-bit `add rax, 1` over the boundary becomes a negative constant. The class does not occur in this corpus and no gate can see either direction; `is64` is the only sound evidence and `fold.ts` deliberately imports only `ir.ts`. `fold.test.ts` carries `does not wrap an arithmetic fold to int32`. (`peek-a-bin-ivj5`)

- **`navigator.clipboard` is a SECURE-CONTEXT API and this app has an HTTP deployment, so every
  copy goes through `utils/clipboard.ts`'s `copyText`.** Over plain `http:` on anything but
  localhost the whole `clipboard` object is absent from `navigator`, so
  `navigator.clipboard.writeText(…)` is not a call that fails — it is a **TypeError at the property
  access**, on click. At `09a160e` there were **18 unguarded sites across 9 files** and zero guards,
  so on the nginx HTTP deployment every Copy affordance in the app was dead. One declaration, for
  the `pe/sections.ts` reason. Four rules: the feature test names **`writeText`**, not `clipboard`,
  since the object can be present with a partial surface; `writeText` is called **before the first
  suspension**, so it stays inside the user gesture — an `await` above it fails in a browser while
  every ordinary test still passes, and `clipboard.test.ts` asserts the ordering directly; it is
  called **on** the clipboard object, never through a detached reference, which a native method
  rejects with `Illegal invocation`; and it returns a **boolean**, never throws. The four sites with
  a "Copied" tick flash **red** on `false` (`CopyFlash` carries the outcome, which is why
  `copiedAddr` is not a bare address — the type change is what forces `DisassemblyRows` *and*
  `CFGView` to be revisited together). **The other fourteen fail silently: the app has no toast
  mechanism and one was not invented for a bug fix.** A `document.execCommand` fallback was **costed
  and REFUSED** — deprecated, ~30 lines of selection choreography, a return value that has lied on
  Safari, unreachable from the two Ctrl+C handlers, and untestable in jsdom, which has neither
  `execCommand` nor a real `Selection`. **Two controls came back inert and both are recorded in the
  tests**: removing only the feature test is subsumed by the catch, and — the transferable one —
  `expect(…).not.toThrow()` around a click is **inert at any site that changes no state after the
  copy**, because React does not rethrow out of `dispatchEvent`; the unguarded call left
  `DecompileView` 87/87 green and the instrument had to become a `window` `error` listener.
  (`peek-a-bin-p0tz`)

- **A cursor-following filter must fall back VISIBLY, and that is the OPPOSITE direction from the
  `omitted` rule.** `XrefPanel`'s scope chain tested `scopeMode === "function" && currentFuncAddr !=
  null` per arm, so a scope whose address lapsed fell through: the full list returned, the "Func"
  button vanished, and "All" was not highlighted either — an unfiltered list with no control
  claiming it. The house rule this *looks* like a case of (`DetectResult.omitted`,
  `analysisNotice`) forbids a **narrower** answer wearing a complete one's shape; here the answer
  was already complete and the **controls** had gone quiet, so widening and *saying so* is the
  repair. Holding an empty scope and explaining it was refused because these scopes follow the
  **cursor** rather than being values the user entered — a cursor crossing padding between detected
  functions would blank and refill the panel for a lapse the user never caused, and PE32 detection
  is known to under-produce so those gaps are ordinary. The fallback is **derived, not written
  back**, so the preference survives the lapse and clicking "All" during one makes the widening
  stick. `scopeAvailable()` is the one declaration of "has the caller given this panel the address
  this scope needs", read by the filter chain *and* by the buttons, so a scope can never be applied
  without a button claiming it nor offered without an address. (`peek-a-bin-jvvi`)

- **`Ordinal_<n>` is a WIRE FORMAT, not a label: `parsePE` writes it and `computeImphash` parses it
  back out.** Nothing in the type system connects the two — they are in different files and neither
  points at the other — so respelling the parser's output used to change every affected imphash
  **silently**: an ordinal import falls through imphash's ordinal branch into its by-name branch and
  hashes the literal display text. A hash has no runtime symptom, because it is only ever compared
  with another tool's answer, so the failure mode is a corpus match that quietly stops matching.
  `ORDINAL_IMPORT_PREFIX` and its two functions in `pe/ordinalTables.ts` are the one declaration
  now, and `pe/__tests__/ordinalImports.test.ts` states the property directly — move the prefix and
  the digests must not move. `parseOrdinalImport` returns **null**, never `NaN`, for a malformed
  tail, since callers read null as "this is a name". **The view resolves through the SAME
  `resolveOrdinal` imphash uses**, so the Imports tab can show `WSAStartup` for `ws2_32!115` without
  a second table to drift: it resolves in the memo *above* the filter, so the name a reader sees is
  the name they can search for, and marks the row `#115` because the name is inferred from a table
  rather than read out of the file. An ordinal the tables do not cover keeps its honest
  `Ordinal_<n>` spelling. (`peek-a-bin-p0qw`)

- **A CodeView PDB GUID is a `GUID` STRUCT, not sixteen bytes: the first three fields are
  little-endian integers and only `Data4` reads straight through.** `CV_INFO_PDB70.Signature` is
  `{ DWORD Data1; WORD Data2; WORD Data3; BYTE Data4[8] }` in native order, and the canonical text
  form prints the first three as integers — so hex-joining all sixteen bytes in file order
  byte-swaps the first three groups. `parseDebugDirectory` did exactly that. Same class as
  `Ordinal_<n>` above and **not** the `>>> 0` class: the GUID is the symbol-server key for the PDB
  (`foo.pdb/<GUID><Age>/foo.pdb`), a value nothing inside the tool ever compares with anything, so
  a wrong spelling is well-formed and simply matches nothing. **The oracle is real MSVC output, not
  a fixture**: `CoCreateGuid` mints version-4 UUIDs and the version nibble is the first digit of the
  THIRD group — precisely the group this swap moves — reading 4 on all six corpus binaries under
  the corrected reading against E / 4 / 7 / B under the old one, with the RFC 4122 variant bits
  sitting in `Data4` and reading `10` either way. `pe/__tests__/metadata.test.ts` had **pinned the
  defect as the rule**, asserting `01020304-0506-0708-…` under the comment "Bytes 01..10 in file
  order, formatted as a GUID string" — a restatement of the implementation rather than of the
  format. **Nothing static could see it and no corpus gate can**: both spellings are `string`, and
  a comment reaches neither the emitted C nor the IR. The instrument is `HeaderView.dom.test.tsx`,
  which derives the expected text from the fixture's own bytes with an independent swap and pins
  the literal beside it. A neighbouring one-character fix in the same file: `parseRichHeader`'s
  `useCount` was `getUint32(…) ^ xorKey`, and `^` is an int32 operator, so a stored `0xFFFFFFFF`
  reached the Rich Header table as `-1`; `toolId`/`buildId` are masked back to 16 bits and were
  never affected. **Two things left alone, deliberately**: `parseDebugDirectory` never reads
  `SizeOfData`, so the PDB path scan runs to the next NUL *anywhere in the file* — a control
  zeroing that field is **inert** and the bound to choose is a judgement, not an obvious fix; and
  the Data Directories table heads the Certificate Table's first column "RVA" when the format says
  it is a **file offset**, which is what `dumpbin` prints too. (`peek-a-bin-p0qw`)

- **`>>> 0` on a value that can exceed 2^32 is a TRUNCATION, not a respelling, and the Headers tab
  is where that bit.** ToUint32 is the right way to print a value read as a signed int32 unsigned —
  which is why `SectionTable` uses it on `characteristics` — but `HeaderView`'s `CopyableHex` is
  handed 64-bit quantities: a PE32+ `ImageBase` is 0x140000000 for an MSVC x64 EXE and 0x180000000
  for a DLL, and every TLS field is an image-based VA. Applied unconditionally it printed
  `Image Base 0x0000000040000000` two rows under an `Entry Point` of `0x140001000` the same panel
  spelled correctly — self-contradictory on essentially every 64-bit binary the tool opens, and
  reachable with no gate in front of it. Reinterpret only what is actually **negative**. **No static
  instrument can see this class**: `value` is `number` either way, `>>> 0` beside a `padStart(16)`
  reads as deliberate, and the corpus never renders. The instrument is `HeaderView.dom.test.tsx`,
  which asserts printed text against the fixture's own bytes rather than that a table appeared.
  (`peek-a-bin-p0qw`)

- **A number the parser CLAMPED and the raw number it clamped are two true facts that mislead as a
  pair, and the clamp is DERIVED rather than published.** `numberOfRvaAndSizes` is
  attacker-controlled, so `parseDataDirectories` reads `Math.min(count, 16, fits)` entries while
  `optionalHeader.numberOfRvaAndSizes` keeps the raw value — and `HeaderView` printed
  `Number of RVA and Sizes: 40` directly above a table of SIXTEEN rows. Same class as the
  Certificate Table's mislabelled offset, in the **adversarial-input** direction: a declared 40 is a
  crafted-PE tell the parser noticed on purpose, and the one surface a human reads was the one place
  it disappeared. **`dataDirectoryClamp` (`pe/dataDirectories.ts`) is the one declaration**, read by
  the panel's row *and* by `analysis/anomalies.ts`, which is where "this file claims something
  implausible" belongs and is the surface an analyst opens rather than one they must notice.
  **The `importsTruncated` precedent was considered and deliberately not followed**: that flag
  exists because a walk cut short at a bound is *shaped exactly like* a complete short list, so
  nothing downstream can recover it — whereas `dataDirectories.length < numberOfRvaAndSizes` **is**
  the clamp exactly, over two fields already on `PEFile`. A parser field there would be a second
  declaration that can disagree with the array it describes. The clamp carries a `reason`, because
  "the count exceeds the format maximum" and "the file ends mid-table" are different findings and
  only the second says bytes are missing. Nothing static sees any of it — both numbers are `number`
  and the corpus never renders. (`peek-a-bin-dd94`)

- **A derived LABEL must come from the value it labels, and a flag row must admit the bits its table
  does not name.** Two more of the same class in `HeaderView`, both found by reading rather than by
  a failing test. `Magic` spelled its parenthetical `pe.is64 ? "PE32+" : "PE32"`, and `is64` **is**
  `magic === 0x020B` — so every third value, e.g. 0x0107 (ROM), would have printed `(PE32)`, where
  the Machine and Subsystem rows beside it both admit an unmapped value with `(Unknown)`. It is
  **unreachable through `parsePE` today** (which throws on any other magic), so that half is a guard
  against a widening there, not a repair — stated rather than implied. `COFF_CHARACTERISTICS` was
  separately missing all three deprecated bits (0x0010, 0x0080, 0x8000), and neither flag row said
  anything about a set bit it could not name, so `0x0042` rendered exactly as `0x0002` would.
  `decodeFlags` now returns the leftover mask and `FlagChips` prints `(unknown bits: 0x…)` — the
  admission cannot be closed by completing the table instead, since 0x0040 is reserved by the format
  and has no name to give it. The admission is deliberately **not** a chip: a chip means "the format
  names this bit", which is the opposite of what it says, and the suite's `chips()` helper reads
  `span.rounded`. (`peek-a-bin-dd94`)

- **`lineMap` is MANY-TO-ONE, so anything keying a rendered element off an address alone renders one
  per sharing line.** Several emitted C lines routinely carry one instruction address —
  `DisassemblyView` builds an address → `line[]` map for exactly that reason, and `emit.ts`'s
  `placeGotoLabels` says in as many words that "if an address somehow appears twice the earlier copy
  is the one the jump was structured around". `DecompileView`'s comment editor decided `isEditing`
  from `editingComment.address` alone and mounted N identical `<textarea>`s for one comment, each
  running `focusOnMount`, so focus landed on the last. The rule: resolve the address to **one**
  anchor line and take the **lowest** — `placeGotoLabels`' own tiebreak, and the line the auto-scroll
  effect reaches with `Math.min`, so the editor opens where the panel just scrolled to.
  `syncDisabled` must be re-tested at the anchor rather than inherited, since on the AI tab the map
  numbers a different body. (`peek-a-bin-p0qw`)

- **A NUL-terminated string read out of a PE must be bounded, and `SizeOfData` alone is not the
  bound.** `parseDebugDirectory` (`pe/metadata.ts`) scanned for the CodeView PDB path's NUL from
  `pointerToRawData + 24` forward through the **whole buffer** and decoded everything it passed —
  inside `HeaderView`'s `useMemo`, i.e. during a render on the main thread, on images this tool
  opens at a couple of hundred MiB. Measured on a 1 MiB NUL-free fixture: 1,049,036 characters
  returned against 4,109 after. The scan is now `min(declared size, MAX_PDB_PATH_BYTES = 4096, end
  of buffer)`, and **all three are needed**: `SizeOfData` is as attacker-controlled as the bytes it
  describes and is the only bound that can be too *small*, so honouring it alone silently shortens
  a valid path — the `Ordinal_<n>`/imphash trap again, since the path is read *out* of the tool for
  a symbol server and a short one matches nothing while looking well-formed; a cap alone still lets
  a hostile record spend the whole cap. A declared size at or under the 24-byte fixed part is
  **not credible** and drops to the cap rather than being honoured. **When the scan is cut short
  the VALUE says so, not just the type**: `pdbPath` carries `PDB_PATH_TRUNCATION_MARKER`
  (`… <truncated>`) beside the `pdbPathTruncated` flag, because a narrower answer must not wear a
  complete one's shape and the one render site prints `pdbPath` verbatim with no knowledge of the
  flag — there is no toast mechanism and one must not be invented for a bug fix. **The control that
  exposed this was inert** (zeroing `SizeOfData` moved no row, because nothing read the field), and
  the zero row **remains** inert as a before/after control; the row that proves the field is read
  is the understating one. Cases and six discriminating controls in
  `pe/__tests__/malformed.test.ts`; corpus byte-identical over four binaries. (`peek-a-bin-nygv`)

- **…and where the truncated thing is a LIST, the admission goes on the COUNT and the digest
  REFUSES.** `parseImports` (`pe/parser.ts`) had two attacker-controlled walks: the thunk walk was
  bounded **only by the end of the file**, so an unterminated array pushed one entry per
  pointer-width slot to EOF inside `parsePE`, on the main thread; the descriptor walk was bounded
  by the directory's declared size, a uint32 the file supplies. Measured at `5baec33` on a 1 MiB
  fixture: 262,080 functions in one library (now `MAX_IMPORT_FUNCTIONS` = 65,536) and 52,416
  libraries (now `MAX_IMPORT_DESCRIPTORS` = 4,096). **The cost that matters is the PRODUCT** — every
  descriptor may name the same array — so the function budget is **global, not per-library**: with
  both, the pre-fix parser did not hang, node died with `Ineffective mark-compacts near heap limit`,
  ~4 GB out of a one-megabyte file. Bounds are `min(containing section, declared size, count cap,
  buffer)`; the **section** bound (`sectionRawLimitForRva`) is the one that improves the *answer* —
  without it a missing terminator at the end of `.rdata` reads the next section as thunks (192 →
  4,288 measured) — and section selection is now **one declaration** (`scanSectionForRva` /
  `sectionForRva` / `offsetInSection`) that `rvaToFileOffset` and `rvaToFileOffsetIndexed` both
  answer from. **A list cannot carry `nygv`'s marker**: an invented `<truncated>` entry would be a
  lie inside a list feeding `computeImphash`, the Imports tab, the IAT map and MCP. So the admission
  is `ImportEntry.truncated` / `PEFile.importsTruncated` (on `ResourceTree.truncated`'s model), the
  Imports tab's own **counts**, and **`computeImphash` returning `null`** — a digest over a short
  list is well-formed, wrong, and only ever compared with another tool's answer, so it fails by
  matching nothing. Its parameter is the **`PEFile`, not `PEFile["imports"]`**, deliberately:
  whether the list is whole is a fact about the parse, so taking the file makes forgetting to ask a
  compile error. `""` still means "imports nothing" and `HeaderView` prints a different sentence for
  each. `readCString`'s 1024-byte cap now appends `NAME_TRUNCATION_MARKER` (measured: 1024 silent
  characters before), **but the marker alone would be wrong here** — unlike a PDB path these names
  reach a digest, so a truncated name also marks the entry, which makes the hash refuse; truncation
  is decided exactly ("stopped at the bound *and* no NUL sits at it") so a name of exactly 1024
  bytes plus its terminator is not marked. Nine discriminating controls, none inert; corpus
  byte-identical over four binaries. (`peek-a-bin-tmo9`)

- **…and the resource tree's half of that admission is now built, plus the three places the flag
  was not being set. `Budget.incomplete`'s OLD NAME COST ALL THREE.** `parseResourceDirectory`
  (`pe/resources.ts`) had set `ResourceTree.truncated` since long before this and **no view rendered
  it**, so a tree cut short by `MAX_TOTAL_ENTRIES` read on screen exactly like a complete one. The
  admission goes **on the count line and not on a row** — the opposite half of the choice
  `ImportsView` makes — because the budget is *global to the walk*: one `Budget` is threaded by
  reference through every `walkDirectory` frame, so when it runs out the walk breaks out of whatever
  directory it reached and every ancestor is equally short, leaving no row that is "the incomplete
  one". `ImportEntry.truncated` is per-library precisely because each descriptor has its own thunk
  walk. **The `entries.length === 0` arm is the worse half and is separate**: it took the same exit
  as a PE with no resource directory and printed "No resources found in this PE file.", a positive
  claim about the *file* rather than a narrow answer — `HeaderView`'s `""`-versus-`null` imphash
  distinction in view form. It is reachable with no leaf at all, the allowance being spent on
  *directory* entries. **And the flag's field was called `stopped`, which reads as a fact about the
  budget, so three other abandonment points never touched it**: a directory whose declared entry
  array runs past the buffer, a declared subdirectory whose own header is past the buffer, and a
  resource directory whose RVA resolves nowhere (that last returned a bare empty tree — byte-for-byte
  the answer a PE with no resources gets, and a **pre-existing test had pinned that as the rule**).
  It is `incomplete` now and means exactly "an entry the file declares was not walked", whatever
  stopped the walk. `depth >= MAX_DEPTH` and a repeat visit deliberately still do **not** set it and
  say so at their sites — both are judgements about a malformed *shape* rather than an unread entry.
  **The two resource STRING clips now carry `nygv`'s marker too**
  (`RESOURCE_STRING_TRUNCATION_MARKER`): a resource name clipped at
  `MAX_RESOURCE_STRING`, and a version-info key or value the walk stopped collecting. Both are
  rendered verbatim (`ordinalLabel`, `ExpandedLeaf`'s table) and **neither feeds a digest**, which is
  the stated asymmetry with `readCString` — there a marker had to additionally mark the entry so it
  could never reach `computeImphash`; here the marker alone is the whole fix. Both are decided
  **exactly**, never on "we reached the bound": `readResourceString` compares what it collected
  against the count the string's own uint16 header declares (covering the cap *and* the buffer
  ending mid-string with one test) and `readWString` records the drop at the drop site, so a string
  of exactly the cap's length is not marked. **Two pre-existing tests had pinned both silences as
  the rule** (`length <= 4096`, and `toMatch(/^A+$/)` — the `tmo9` forwarder row's exact shape).
  Eleven discriminating controls, none inert; `npm run corpus:parserdiff` reports all six real
  binaries unflagged, which is the case rather than a formality. The full census of which parser
  admissions reach a screen is `peek-a-bin-ul9m`, summarised in `docs/verification.md`.
  (`peek-a-bin-dhcx`)
  byte-identical over four binaries. **`ResourceTree.truncated` is still only half built — no view
  renders it.** (`peek-a-bin-tmo9`)
- **THE ATTACKER-CONTROLLED-BOUND CLASS WAS SWEPT DELIBERATELY, AND SEVEN MORE SITES WERE OPEN —
  including one that produced a WRONG NAME on real instructions.** `nygv` and `tmo9` were both
  found incidentally, so nobody had ever asked every reader in `src/pe/` the five questions the
  class turns on: what bounds it; whether the *work* is bounded or only the reads; whether two
  file-supplied counts **multiply**; whether anything allocates a size the file chose; and whether
  it runs on the main thread. Ranked, with the figure that was measured at `d8d8a6d` against an
  identical fixture: **ARM64 `.pdata` unwind codes** (a real product — 1020 bytes per record x a
  `buffer / 8` entry count, all naming one record: 37.7 s on a 266 KB file, growing linearly, so
  hours at 253 MiB, in `parsePE`); **the debug directory's entry count** (`nygv`'s own defect with
  a new multiplier — 153,877,941 characters of PDB path from a 1 MiB file, *inside a render*);
  **the export tables** (524,093 entries / 104,696,157 characters of name); **`parseImports`'
  parallel `functions`/`iatAddresses`** (desynchronised by one unresolvable name RVA, so
  `buildIATLookup` labelled every later call site in that library with **another import's name** —
  a wrong value no flag repairs); two more `tmo9` bypasses in `parseImports` (a vanished library
  and a `KERNEL32.dll (0)`, each yielding a confident imphash); **relocation blocks** (an
  eight-byte directory producing 524,284 entries, where the pre-existing test asserted only
  `< buf.byteLength`, which that satisfies); **`extractStrings`** (sections x 1 MiB: 13.3M strings
  in 87.7 s, the largest amplification and the only one off the main thread); and
  **`readDERChildren`** (41.6 MB of heap from a 1 MiB file, an OOM no `try/catch` can catch).
  `sectionRawLimitForRva` is now exported as the **one declaration** of the section bound, because
  five walks wanted it and every one had the end of the file instead. `MAX_EXPORT_ENTRIES` is the
  *format's* `uint16` ordinal ceiling rather than an invented number, which matters because no
  binary here exports anything and `corpus:parserdiff`'s export gates are **vacuous**; the ARM64
  unwind budget is calibrated against the real tables (1220 code bytes in total on `t64-arm`, 28
  in the largest record). **Fifteen controls, one INERT and recorded rather than repaired** — the
  export section bound's fixture was too small to distinguish a section from the buffer, so removal
  left the row green. Deliberately **not** bounded: the relocation entry *total* (legitimately
  O(image), and the section extent is the file's own statement). Deliberately **refused and handed
  back**: the two `catch {}` blocks in `parsePE` that render "Unsigned" and "No resources found"
  for a file that has both — the render site is the whole of the fix and those files are owned
  elsewhere, the standing precedent being `ResourceTree.truncated`, set since before `tmo9` and
  **still rendered by no view**. `corpus:parserdiff` byte-identical (98/118, 20 vacuous), `corpus`
  byte-identical over four binaries, `corpus:arm64` 51/51.

- **`regSize()` is not a membership test.** It falls back to `4` for any unrecognised name, so `regSize(x) > 0` is true for every string. Use `isKnownRegister()` (`decompile/ir.ts`) — this mistake made `lifter.ts`'s `isRegister()` a no-op that lifted immediates as registers.

- **`RegState.defs` is keyed by literal operand text deliberately; ask `wroteAnyAlias` rather than canonicalising the map.** The map stores the last-written *expression*, which carries the operand's width, so a key of `rcx` would record `mov cl, 2`'s one byte as eight. But arity is width-blind, and `collectArgs64` probing the literal 64-bit name missed every sub-width setup and broke out of the loop — the write then had no reader and DCE deleted it, giving `ExitProcess()` with the exit code gone, in well-typed C. `wroteAnyAlias` answers the width-blind question over the width-exact map and returns a **boolean**, so the recorded expression can never be substituted at the call site (`peek-a-bin-urs` cannot return through it). The suite had pinned the defect as the rule under a KNOWN BUG comment. And: when you build an oracle to verify a change, land the oracle — the instrument for this one was lost with a scratch worktree (`peek-a-bin-02fa`). (`peek-a-bin-qb2x`)

- **A written fastcall register is not an argument if the block already SPENT it as an address index — and base and index are different evidence.** `collectArgs64` asked only *whether* the block wrote RCX/RDX/R8/R9, which is equally true of a register computed for its own addressing. The discriminator is a subscript scaled by an element size whose access has already been emitted; an address **base** proves nothing (`lea rdx, [rcx+0x10]` / `f(rcx, rdx)` is a pointer that *is* the argument). `liftBlock` calls `noteIndexReads` before dispatching so a read-modify-write clears its own mark; `RegState.consumed` holds them and `invalidateCallerSaved` drops the volatile ones. One exemption, from the prefix property: an index read does not spend the register when the destination is a fastcall register *later* in the argument order. **Four rules refuted by this corpus and not to be re-tried:** distance from the write to the call, dominance (`RegState` is per-block, so the write always dominates), any read spending it (a spill to the outgoing stack-argument area happens *because* it is the register argument), and any read from inside a memory operand (`lea edx, [r9+0x8]` is arithmetic wearing an address's clothes). **Never answer this from `apitypes.ts`** — that blinds the only arity oracle here. (`peek-a-bin-7r1l`)

- **`collectArgs32`'s backwards push-walk stops at a call whose result feeds a following call, and the marker is `push eax` AFTER the call, not before it.** `call inner / push eax / call outer` makes the inner call an argument expression of the outer, so the pushes above it are the outer's; there is no call *between* the pushes and the inner call, which is why "stop at an intervening call boundary" would never fire. Deliberately an **admitted under-count, not a re-attribution** — handing the pushes to the outer call is a guess in the over-count direction, and an invented argument is the one error this codebase will not trade for a recovered one. (`peek-a-bin-f51x`)

- **A `push` of a callee-saved register the function has not yet written is a register SAVE — and that, not the register and not the position, is the discriminator.** Without it the walk ran into the prologue and emitted `GetCommandLineW(edi, esi, ebx)` for an API declaring none. **Two rules refuted by this corpus:** "a push of ebx/esi/edi is a save" (t32 0x402c3f is a genuine argument), and "a save has a matching `pop` before the `ret`" (`push imm8 / pop reg` is a pervasive MSVC size idiom, and saves are often sunk to a mid-function block leader). `firstCalleeSavedWrites` (`lifter.ts`) precomputes the lowest address writing each of ebx/esi/edi/ebp; a push below its register's first write ends the walk. Three load-bearing constraints: the scope is **function-wide**; `mov X, X` is not a definition but `xor X, X` is (generalising the self-move test past `mov` turned four real `Sleep(esi)` calls per binary into `Sleep()`); and it is **restricted to the four callee-saved registers**, since under cdecl/stdcall every argument arrives on the stack so their entry values are opaque. The address-order approximation is one-directional: it drops an argument, never invents one. **Never answer this from `apitypes.ts`.** (`peek-a-bin-6lmh`)

- **The CSP is generated, not hand-written.** Edit `build/csp.ts`, never `nginx.conf`'s header or `index.html` directly — `build/csp.test.ts` fails on drift. A meta CSP cannot go in `index.html` because it is also the dev entry point and Vite injects an inline React Refresh preamble there. The shipped `connect-src` omits non-localhost plain `http:`, so a LAN Ghidra server is blocked on the HTTP nginx deployment.

- **Do not re-add a plugin that copies `capstone.wasm`.** Rollup already rewrites `new URL("capstone.wasm", import.meta.url)` to its hashed asset; a manual copy is pure duplication and was 1.7 MiB of the PWA precache. `capstone-wasm-guard` in `vite.config.ts` fails the build if more than one WASM asset is emitted.

- **`tools.ts` and `resources.ts` must only *type*-import `./session`.** A value import pulls in `./disasm`, which loads Capstone WASM at module scope, and both MCP suites become slow and fragile. `src/mcp/__tests__/importGraph.test.ts` enforces it.

- **`biome.json` must be strict JSON.** A single `//` comment silently voids the whole config and Biome falls back to defaults — which looks like your rule settings randomly stopped applying. `build/lintConfig.test.ts` fails on a comment and on `useExhaustiveDependencies` dropping below `error`; the seven a11y rules are at `error` too, so keep all of it there.

- **Vitest's environment marker is matched against the WHOLE FILE, not the leading docblock, so writing it out in prose moves that file into jsdom.** `detectCodeBlock` (vitest 4) runs `content.match(/@(?:vitest|jest)-environment\s+([\w-]+)\b/)` over the entire source, so a node-only file that quotes the marker — in a string constant, in a comment explaining the convention — is silently switched. It bit `build/domTestNaming.test.ts`, whose whole job is to check that marker: it ran under jsdom and died at import on `fileURLToPath`, because `import.meta.url` there is not a `file:` URL, naming a line that is obviously fine. Both the constant and the prose in that file are written with the two halves apart; keep them apart.

- **A multi-line `biome-ignore` needs `//` on every line.** Biome only honours the directive on the line immediately preceding the offence, so put prose in a normal comment block above a single-line directive; getting it wrong leaves bare text inside JSX and breaks the parse.

- **`DisassemblyView.tsx` is ~1620 lines even after the split — read it in chunks.** The two extracted seams are `hooks/useDisassemblyKeyboard.ts` (`handleKeyDown`, with a **37-entry** dependency array that *is* the behaviour — copy it verbatim if you move it, and keep the `//` comments explaining why a stable value is listed or a value omitted) and `hooks/useGraphSearch.ts`. That array only began doing anything when `useDisassemblySearch`'s return was memoised; before that `search` had a fresh identity every render and the `useCallback` memoised nothing. `hooks/__tests__/disasmHandlerDeps.test.ts` fails the build if it drifts in either direction. `CFGView` takes 23 props. Neither extraction has ever been rendered.

- **A callback declared later in a component cannot go in an earlier hook's dependency array** — it is a `const`, so the array hits its temporal dead zone at hook-call time. Not hypothetical: `handleKeyDown` closed over `handleDecompileToggle` (declared ~340 lines later) without it in the deps, so D opened the decompile panel but could not close it. The fix is a ref assigned *during render*; an effect is too late, because a keypress can be handled before effects flush.

- **`parseBranchTarget` lives only in `components/shared.tsx`** and resolves `call` immediates as well as jumps. JumpArrows draws jump arrows only, so it guards with `mnemonic.startsWith("j")` *before* calling — dropping that guard makes recursive/intra-function calls sprout arrows. Covered by `src/components/__tests__/parseBranchTarget.test.ts`.

- `sectionInfo.characteristics & 0x20000000` = `IMAGE_SCN_MEM_EXECUTE`. Used to distinguish code vs data sections.

- **A64 mnemonic matching is by *exact* mnemonic, never by prefix.** `brk` is not a `br` and `bfi` is not a branch, so `startsWith("b")` — the habit x86 encourages — mis-classifies real instructions. `arm64Operands.ts` is the one place that knows the grammar (`b`, `b.<cc>`, `bl`, `br`/`blr` with the PAuth forms, `cbz`/`cbnz`, `tbz`/`tbnz`, `ret`, and the `adrp`+`add`/`ldr` idiom); `buildCFG`, `layoutCFG`, `parseBranchTarget`, the `JumpArrows` guard and `buildTypedXrefMap` all read it rather than re-deriving it. The x86 path is untouched by any of it — keep it that way.

- **Don't put a cheap request on the disasm worker.** It services messages serially, so a checksum or entropy call posted behind a whole-image disassembly waits minutes; that is what `metrics.worker.ts` exists for. A `useMemo` is not an option either — it cannot yield, and on a 253 MiB PE the entropy strip froze the UI for ~6.5 s on every Hex tab open whether or not the strip was shown.

- **Never put a caller-owned buffer in a worker transfer list, and never walk below the top level.** Structured clone of an `ArrayBufferView` serialises its whole backing `ArrayBuffer`, not the view's window, and every large byte argument here is a view onto the entire loaded file — so a 4 KiB single-function `disassemble` used to copy all 253 MiB. `disasmClient.send()` routes args through `prepareBinaryArgs` (`workers/transfer.ts`), which replaces each **top-level** binary argument with a private `slice()` of exactly that window and transfers **only buffers it allocated itself**; that invariant is what makes the detach hazard structurally impossible, since the main thread keeps reading the file through `bufferRef`, `pe.buffer`, HexView and entropy. The walk stays top-level because an `Instruction[]` carries a tiny `bytes` buffer per element, and transferring them is **strongly superlinear** (exponent ~1.7) — so a large transfer list is a tax that grows with the image, not a fixed one. Anything that must cross flattened (`packDataWindows`) does so for the same reason, and slicing wins even when the copy is the same size, so there is no threshold below which it is skipped. **The REPLY path was measured and packing refused** — most of a reply is object and string overhead rather than bytes, and an unpacked shared buffer forces the receiver to re-slice — but the instrument is now landed as `corpus/replyCloneCost.ts` (`npm run corpus:replycost -- <path>`) rather than a lost scratchpad. One correction to `linearSweep.ts`'s comment: `StructuredSerializeInternal` carries a memory map, so a shared `ArrayBuffer` is serialised **once per message**, not once per instruction; `.slice()` is still right, because a whole-section tax on every reply is real. (`peek-a-bin-7mf`, `peek-a-bin-rjt`)

- **…and uploading the section once under a handle was MEASURED AND REFUSED — do not rebuild it without new evidence.** One load ships `.text` four times and each pays its own slice; the saving is **under a tenth of one percent** of the work done on those same bytes, and the fraction does not improve with size or after the work was cut roughly threefold twice over — both terms are linear in the section, so the ratio is a property of the tool. The refusal is that a stale hit cannot be made impossible cheaply: a **content** key costs a full linear pass, which is the very thing being saved, and an **identity** key `(ArrayBuffer, byteOffset, byteLength)` is sound only while the file buffer is never written in place — an invariant nothing enforces, and whose obvious breaker (making hex editing cheap by patching the buffer in place) would silently serve pre-patch bytes for the rest of the session with no corpus gate able to see it. **The general rule this settles: the key comparison must be cheaper than the work it saves.** `Arm64SweepCache` and `CallSummaryCache` both pass it; this fails it. `npm run corpus:uploadcost -- <path>` is the instrument. (`peek-a-bin-9a8`)

- **…and where a payload IS worth cutting, the fix is to send only what the consumer reads — never worker-side residency.** `decompileFunction` shipped the whole section's `Instruction[]` and typed xref map on every request (92-99% of it), but `buildCFG` narrows the array with `getFuncInsns` on its first line and reads the map only at those instructions' addresses. The client sends this function's slice of each — `collectFuncInsns` and `funcXrefEntries` in `funcInsns.ts` — for a request **16-68x cheaper**, with **retention unchanged at zero**. The one consumer of the whole section is the callee-clobber summary, and **the worker asks; the client does not predict**: on a miss `dispatch` returns `{ needInstructions: true }` above the work and the client resends once. Mirroring `CallSummaryCache` client-side would put an eviction rule in two files and a stale belief yields well-formed C that the address-keyed decompile cache then serves all session. Likewise `runtimeFunctions`: `wrapExceptionRegions` picks **at most one row**, so `funcExceptionRecord` (`funcInsns.ts`) applies the same rule on both sides — no protocol, no key, no cache, because the rule is **idempotent**. Two traps there: the predicate is a **begin-address equality**, not an extent intersection (a row covering the function without beginning at it describes another function's frame); and `.pdata` holds RVAs while `DisasmFunction.address` is a VA, so a naive window slice matches nothing on any real x64 image — the rule recovers the image base from the pair and **discards an ambiguous match**. The rule had to move to a leaf: `disasmClient` cannot import the decompile pipeline. `npm run corpus:decompilecost -- <path>` censuses equivalence and prints a `__try` count as the liveness half, since `0 differing` is a statement about a population that can be empty. Several negative controls here came back **inert** and the fixtures were sharpened rather than the controls kept — a control that does not discriminate is a test that is not testing. **Not verified:** nothing spawns a real `Worker`, so `structuredClone` in one process stands in for a `postMessage` across two and every figure is an upper bound. (`peek-a-bin-9gc9`, `peek-a-bin-qmlz`)

- **One x86 load swept `.text` three times and two of those loops were the same loop; `linearSweep.ts` is now the one declaration.** `sweepX86` plus a session memo (`X86SweepCache` in `WorkerState.x86Sweep`), the x86 counterpart of `Arm64SweepCache`. The key rule has one declaration, `SectionMemo` in `sectionMemo.ts`, and has **three** parts: the bytes byte-for-byte, the load address, and **the decoder handle by identity** — a part ARM64 does not need, because x86-32 and x86-64 disagree about what a byte string means. The memo caches only the **sweep**, never the xref *result*: the second `buildAllXrefs` exists to re-resolve over a new string set. `disassemble` stays out, since it may be handed a sub-range and the memo holds one section. Retention is ~135 B/instruction; interning the strings was measured and refused. No harness drove the worker RPC path at all before this — `npm run corpus` goes through `FileSession`, which has no worker — so `disasmClient.test.ts` now posts a whole load through the real client answered by the real `dispatch`. (`peek-a-bin-x40u`)

- **…and `hybridDisassemble` shares that sweep one level down, as a decoder rather than an array.** Recursive descent plus gap fill produces a different, annotated, smaller stream at addresses a *caller* named, so it takes `gridScan` (`linearSweep.ts`): a `CapstoneScan` answering from the held grid where the grid has an instruction at that address and delegating to Capstone where it does not, with all three phases keeping their loops verbatim. The coincidence rate is ~100% because a sweep walking into data comes out misaligned and *adds* entries, making the grid a superset — but **a rate is not a correctness argument**; the differential is, and the returned `Instruction[]` is identical field for field including `bytes`, `source` and `comment`. Four rules: **peek, never `sweep`** (the memo holds one slot, so a `get` would evict the section the other RPCs share; a hex patch is the live miss and the fall-back is the whole fix); **a served `bytes` must be a private `.slice()`**, never a `subarray` of the section, or the reply's clone drags the whole `.text` — note the property is *not aliasing*, not "exactly `size` long", since capstone-wasm backs its own records with a fixed 24-byte slice; a miss delegates; a run stops where the grid stops being **contiguous**, and the caller's window still bounds it. Unsorted input degrades safely — a missed binary search delegates. Lesson from the test stub: a decoder stub must key on the **absolute address**, never an offset within the window it was handed, or a serve and the decode it replaces disagree about the stub. `npm run corpus:gridserve -- <path>` is the instrument, driving the real `dispatch` with a *wrapped* handle. (`peek-a-bin-iqzu`)

- **`detectFunctions` is dominated by the one shared Capstone sweep, and the "13x the next RPC" reading of that is arithmetic rather than a diagnosis.** Detection is the load's first RPC, so it is the one that fills `X86SweepCache` and the others are cheap because it already paid; read end to end (the harness's `warm` column), its own work is *smaller* than either successor's. `npm run corpus:detectcost -- <path>` (`corpus/detectPhaseCost.ts`, fed by an optional `phaseTap`) regenerates the per-phase split. Nothing is superlinear — `interiorBranchedOverStarts`' binary-search prefilter holds up at scale — so the ms/MiB figure is a rate and `REQUEST_TIMEOUT_MS`' headroom is a rate calculation, not a shape problem. **The measured refusal: almost nothing in detection is worth changing.** `tail-calls` served from the grid would decode under the *sweep's* alignment instead of from `end - 15`, changing which instruction is judged last and therefore `fn.tailCallTarget` — not a pure-performance change; `sweep-scan`'s `recentInsns` window feeds `readAbsoluteTable`/`boundedCaseCount`/`overlappedTableExtent` for 3-4%. The one thing taken was the SEH32 prologue head, because the work was provably **unread**: `headInstructions` eagerly decoded 8 instructions where the rule consumes 1-2, and it is a pull now (`HeadReader` in `seh32.ts`), output-neutral by construction — which matters because it feeds function boundaries. One of the harness's three self-controls is **inert**: moving the `sweep`/`sweep-scan` boundary past the scan loop fools both the unattributed check and the cold-minus-warm cross-check, so that boundary rests on reading the code. (`peek-a-bin-6dv3`)

- Capstone WASM is cached in IndexedDB (`peek-a-bin-wasm`). First load fetches, subsequent loads read from cache.

- **`fold.ts` has a `castTypeSize` helper** for double-cast removal; it regexes the bit width out of type strings like `int32_t`.

- **`cleanup.ts`** runs after `structureCFG`, before `inferTypes`. Guard clause flattening is single-level only, not recursive inversion.

- **`StructRegistry`** persists across decompilation calls in the worker — don't clear it between functions in the same session.

## Working in parallel — use subagents, and how

**Default to farming independent work out to subagents.** Changes here are mostly self-contained —
one bead, one measurement, one audit — and each carries a large reading cost (this file, plus the
bead's notes, plus the module) that does not need to land in the integrator's context. Sessions
have run three or four agents in parallel and cleanly.

**Reach for one when** the task is a whole bead; a measurement with a stated method; a read-heavy
audit whose answer is a paragraph and whose *inputs* are hundreds of files; or anything you would
otherwise do by reading a module you do not already have in context. **Do it yourself when** it is
a single fact you know where to find, when the work needs the integrated tree (integration itself
is not delegable), or when briefing would cost more than doing — a good brief for this repo runs
to a page, because the traps have to be named.

### Give each agent its own worktree, and make it its own

Tool-created worktrees land *inside* the working tree and arrive with no `node_modules` — see
**Commands** for what that breaks. Create them yourself:

```sh
git worktree add /tmp/pab-wt/NAME -b sNN-NAME <HEAD_SHA>
ln -sfn /home/taylor/dev/peek-a-bin/node_modules /tmp/pab-wt/NAME/node_modules
mkdir -p /tmp/pab-wt/NAME/.scratch
```

- **The symlink means every such worktree SHARES one `node_modules` with the main tree.** Fine for
  reading; **not** fine for a task that changes `package.json` — an `npm install` there rewrites
  the shared tree under every sibling agent and can invalidate a timing measurement one of them is
  taking. For dependency-changing work give that agent a real `npm ci` in its own worktree (~90 s)
  and tell the others the shared tree is read-only.
- **Scratch goes in `<worktree>/.scratch/`, never a bare `/tmp/<name>`** — one agent's control
  backup was once clobbered mid-run by a sibling using the same filename.
- **Tell each agent to print `git rev-parse --short HEAD` first and stop if it is wrong.**
- Remove the worktrees at session close; keep the branches as provenance.

### What every brief needs

- **The gate commands, including the traps** — `npm run check` must not be piped, and `npm run
  corpus` **skips cleanly and still exits 0** with no corpus directory, so say "confirm the header
  names FOUR binaries".
- **What byte-identical output would mean.** For a pure-performance change it is the whole case,
  and saying so up front stops an agent accepting a diff it should have chased.
- **Negative controls, asked for explicitly.** This repo has repeatedly found *inert* controls —
  four in three different agents in one session. Say to **report** an inert one rather than
  quietly tuning it away.
- **"A measured refusal is a fine outcome."** Say it. Some of the best results have been an agent
  declining to land a change and explaining why.
- **Read-only means read-only.** An audit agent running beside editors must be told not to edit,
  commit or touch the tracker, and to hand back a report.

### Integrating

- **Do not take an agent's results at face value.** Re-derive the load-bearing ones; they are
  cheap next to the work of producing them.
- **Several agents will all touch `CLAUDE.md` and `CHANGELOG.md`.** Cherry-pick in order;
  `CLAUDE.md` normally auto-merges if each agent stayed in its own sections, and the
  `CHANGELOG.md` conflict is two additions under one heading — **keep both, newest timestamp
  first**.
- **Run the full gate set on the INTEGRATED tree**, not just per branch. Each agent's run was
  against its own base; only the combination is what ships.
- **Pin a baseline before the agents start.** One `npm run corpus` on the session's base commit,
  kept under its own label, is what every later comparison is made against.

## Gates

Always run after changes:

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
gates are green — do not finish a piece of work and then ask permission to record it. This is the
repository-level opt-in that the **Team-maintainer** profile below refers to, and it overrides the
Conservative default's "do not commit unless explicitly asked". A current instruction not to
commit still wins.

**Pushing is NOT included, and the distinction is deliberate.** `main` has run many commits ahead
of `origin/main` for a while; that is the normal state here, not a backlog to clear. Ask before
`git push`, before `git pull --rebase`, and before any Dolt remote sync. One consequence worth
knowing: **tool-created subagent worktrees are cut from `origin/main`, not your local `main`**, so
while main is unpushed every such worktree silently lacks your recent work.

### Before you commit

```sh
npm run typecheck && npm test && npm run build
npm run check        # the CI gate
npm run corpus       # ONLY if the change could move emitted C — see below
```

`npm run corpus` is the one that is easy to skip and expensive to have skipped. Run it whenever the
change touches `src/disasm/`, the decompiler pipeline, function detection or the emitter, and
**confirm the report header names four binaries** — a missing corpus directory *skips* and still
exits 0, so a green run is not always a run. Diff against a base run pinned to one commit
(`npm run corpus:compare -- <base> <change>`); **byte-identical output is itself a result worth
stating**, since it proves a change was confined to the path you meant.

### What a commit here looks like

- **One logical change.** The documentation and `CHANGELOG.md` updates for that change belong in
  the same commit, not a follow-up.
- **Straight to `main`.** That is this project's history and there are no other branches; do not
  invent a feature branch for a change you are about to commit anyway. Use a worktree when a
  subagent needs isolation, not to stage a commit.
- **The message carries the measurements**, in the style already in `git log`: an imperative
  subject, then what changed, *why*, the numbers before and after with the commit they were taken
  at, and the bead id. A defect fixed says what the defect was and what would have caught it.
  Prefer a long message to a short one — the log is the only place some of this is written down.
- **Stage only your own files.** `.beads/dolt-backup.json` is tracked but is not yours — leave it;
  it was once swept into a commit that did not mean to take it. `.beads/interactions.jsonl` moves
  as a side effect of using `bd`, and history records it in its own commit rather than smuggling
  it into a code change.
- **End the message with** `Co-Authored-By: Claude Opus 5 <noreply@anthropic.com>`.

### Author identity

**Not configured in git, deliberately, and must be passed per command:**

```sh
GIT_AUTHOR_NAME=welly GIT_AUTHOR_EMAIL=wklee@m2.local \
GIT_COMMITTER_NAME=welly GIT_COMMITTER_EMAIL=wklee@m2.local git commit -m "…"
```

That matches every existing commit. The user's own address is `mantis2406@wellingtonlee.io`; if
they say to use it, amending is cheap while these commits are unpushed. Do not write either one
into `git config` without being asked.

## Documentation

Documentation lives in `docs/`. **`docs/README.md` is the canonical index and holds the "which doc
do I update when I change X" mapping table** — consult it there rather than keeping a second copy
here or in `CONTRIBUTING.md`.

Three of those files are the long-form record split out of this one, and a change to a rule
summarised here usually belongs in its detail file too: [`docs/gotchas.md`](docs/gotchas.md),
[`docs/verification.md`](docs/verification.md), [`docs/decompiler-ir.md`](docs/decompiler-ir.md).

When making architectural changes, adding major features or changing conventions, update this file
(`CLAUDE.md`) so future agents have accurate context: new source directories, new pipeline stages,
new conventions, new gotchas, changes to the build/test commands. **Keep it a summary** — the
evidence, the measurements and the negative controls go in the `docs/` file, not here.

Update `README.md` only when changes affect the top-level project description.

## CHANGELOG Convention

Maintain `CHANGELOG.md` under `## [Unreleased]` with `### Added`, `### Changed`, `### Fixed`,
`### Removed`. Each entry: `- **Feature name** — concise description`, with a timestamp appended
in the format `(YYYY-MM-DD HH:MM)` using the current date and time. Example:
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
