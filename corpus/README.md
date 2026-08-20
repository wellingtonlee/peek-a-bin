# Corpus audits

The measurements behind CLAUDE.md's **"Verification status — what is measured and what is not"**
section. Everything in `src/__tests__` is synthetic; these are the audits that drive **real MSVC
binaries** through the tool and check the answer against an oracle outside the code under test.

```sh
npm run corpus                 # run every audit, print a report
npm run corpus:compare -- A B  # diff two runs (see "Did my commit break anything?")
```

If the binaries or a C compiler are missing, every audit is **skipped** — not passed — and the run
says exactly which paths it looked for. It never fails for want of a corpus.

## Why this directory exists

These harnesses previously lived only in session scratchpads under `/tmp`. They were rebuilt from
scratch **twice in one day** (2026-08-12), and the second rebuild had to validate itself by
checking that it reproduced CLAUDE.md's documented `842/842` and `975/975` — a step that was only
necessary *because* the originals were not durable. `peek-a-bin-dfae`.

Two consequences worth preserving:

- `corpus` is in `tsconfig.json`'s `include`, so `npm run typecheck` covers it. If someone changes
  `decompileFunction`'s signature, the build breaks **now** rather than the next time somebody
  needs a measurement.
- `corpus/**` is in `biome.json`'s `files.includes`, so `npm run check` — the CI gate — covers it
  too.

## Requirements

| | |
|---|---|
| **Binaries** | `t32.exe`, `t64.exe`, `w64.exe`, `w32.exe` — pip's vendored `distlib` launchers. Real MSVC output: t32/w32 are PE32, t64/w64 are PE32+. Between them they cover both widths, SEH, jump tables and hot-patched prologues. |
| **Default location** | `/home/jacob/silver-carnival-demo/.venv/lib/python3.12/site-packages/pip/_vendor/distlib` |
| **Compiler** | `gcc` on PATH (or set `CC`). Needed by two audits. |

**The binaries are deliberately not in the repo and must not be added.** They are third-party
executables; a disassembler vendoring its own test corpus is the wrong trade. That is why every
entry point has to answer "can I run?" first.

### Environment variables

| Variable | Meaning |
|---|---|
| `PEEK_CORPUS_DIR` | Directory holding the four `.exe` files. Point it at any copy. |
| `PEEK_CORPUS_BINS` | Comma-separated subset, e.g. `t32,t64`. Default: all four. |
| `PEEK_CORPUS_OUT` | Where artifacts go. Default `corpus/artifacts` (gitignored). |
| `PEEK_CORPUS_LABEL` | Subdirectory under the output dir. Default `local`. Use it to keep two runs apart. |
| `PEEK_CORPUS_TABLES` | Directory of another run's `jumpTables_<key>.json`, used instead of this commit's own. See "Did my change cause that". |
| `CC` | Compiler to invoke. Default `gcc`. |

## The audits: what each one proves, and what a failure means

### Gates — a failure is a defect in the decompiler

**Condition polarity, per guard, anchored to the originating jcc.** Every emitted `if`, `while`,
`for` and `do/while` is matched to the conditional jump it came from, and its comparison operator
checked against that jump's taken sense. *A failure means the emitted C states the opposite of what
the machine does* — valid C, plausible-looking, and invisible to every stage-level test in `src`,
because those assert on the IR the buggy code produced. This exact defect once inverted **every
`if` and `while` the decompiler ever emitted**. See the `extractCondition` gotcha in CLAUDE.md.

Two details in `sweep.ts` are load-bearing and must not be "simplified":

- The anchor is the **body**, not the condition text. `if (x != 0) A else B` and
  `if (x == 0) B else A` both pass, because each is judged against the arm it actually guards. That
  is what makes the audit survive the structurer legitimately swapping arms round.
- Candidate edges are resolved **through `jmp`-only blocks**. `jne exit / jmp top` is an ordinary
  MSVC loop entry, and matching the nearer jcc anchors to the wrong test — which produced a false
  INVERTED on a real function. A body two jccs can reach is *ambiguous and skipped*, never guessed.

Three anchors are reported and only one gates:

| Anchor | What it is | Gates? |
|---|---|---|
| **A** | The body's first line carries a block start address by itself. | **Yes** |
| A2 | That line had to be normalised to its CFG block. Sound whenever the line really is in the arm's first block. | No |
| B | The statement *after* a loop — its test's other side only when the loop has no other exit. A heuristic; it has disagreed with A on real functions. | No |

A2 currently carries **two long-standing INVERTED verdicts on each of t64 and w64** (`jae`,
`if (r14 < rax)`). They are not new, and CLAUDE.md's "0 inverted" claim has always meant anchor A.

**Loop exit coverage.** For each innermost emitted loop matched to a machine loop, every
conditional jump inside it whose target leaves it is an exit the machine has; the emitted loop must
offer at least as many (its own test, plus each `break`, `return` and outward `goto`). *A failure
means a test the program makes is not in the output.* This finds what polarity cannot: a guard that
states one of two tests and drops the other passes the polarity audit perfectly, because the
operator it does state matches its own jcc.

**Distinct callees lost.** The callees the disassembly names — direct `call` through the function
map, indirect through the IAT — against the identifiers the emitted C applies. *A failure means a
call the reader is told does not happen.*

**Dangling gotos.** Every `goto` must name a label its own function defines.

**`cc -std=gnu89 -fsyntax-only` over every emitted function.** *A failure means the decompiler
emitted something that is not C.* Registers, imported APIs and Win32 typedefs are declared for it
from gcc's own complaints, because the decompiler deliberately does not declare them.

> **It is blind to call arity, by construction.** An implicit declaration is accepted at any
> arity, and `preludeFor` declares each undeclared identifier as its own `long`, so a call passing
> two arguments to a no-argument API compiles clean. **Call arity** below is the audit for that,
> and it is the only one in the repo that can see the dimension at all.

> **"Clean" is not "recovered."** A large share of these functions compile precisely because the
> emitter *names* what it failed to recover — `__unrecovered_N`, an "unlifted" comment — instead of
> printing something plausible. Do not read "all of them compile" as "all of them are right". The
> `__unrecovered_N` half of that is now counted: see **Unrecovered values** below.

**Struct layout, by a compiled and *run* `offsetof` program.** Field names record the offsets
recovery found (`field_0x18`), so a declaration C would not lay out that way states something
false, and every `p->field_0x18` in that body then reads bytes the access never touched. Reading
the declaration is not enough; this compiles and executes it. *A failure means the emitted struct
declarations and the emitted field accesses disagree about where the data is.*

**Throws.** `decompileFunction` raising on any real function.

**Stale version-0 names.** SSA version 0 is a register's *entry* value — no statement in the
function defines it — so a surviving read of it is the decompiler saying "the value this register
was given on the way in". If a block that **strictly dominates** the read has since written that
register, the name in the output denotes something else. *A failure means the emitted C names a
register for a value it does not hold*: a store through the wrong pointer, a call passed the wrong
argument, a `return` of the wrong value. It compiles clean, which is why nothing caught it
(`peek-a-bin-dqpk` — 78 such reads on t64 and 28 on t32 before the fix).

Two counts, and the second is the worse one:

| Count | What it is |
|---|---|
| `wrong` | The read emitted as a bare register a dominating write has already changed. At least visibly a register name, so a reader has the disassembly to check against. |
| `copiesCorrupted` | The *repair* spoiled. `destroySSA` preserves version 0 with a copy `rcx_0 = rcx`; taken past a dominating write, the copy captures the wrong value and every use of `rcx_0` reads as recovered output. Nothing on the page looks wrong. |

**Why this gates when the two baselines below do not.** Those report a count that is not zero and
for which no threshold has been justified, so a gate on them would assert something nobody has
established. This one is zero, and every non-zero row is a *provably* wrong name — the same
character as `polarity inverted`, which gates for the same reason.

Two liveness assertions sit beside it and both matter. `sites > 0` says the audit still finds the
*shape* — a version-0 read a dominating definition overwrote — which is common (28/159/28/158) and
is not itself a defect once the value is preserved. `copies > 0` says it can still see the
preservation, and that check depends on `ssadestroy.ts` spelling a preserved entry value
`<reg>_0`; a spelling change would otherwise turn every repaired site back into a reported defect.
It is the one place the audit has to know anything about how the code under test writes its answer.

Per-site detail is in `stalev0_<bin>.jsonl` — the wrong reads first, then the spoiled copies.

### Baselines — reported, never gated

**Line map coverage**, per instruction and per CFG block. Read the name literally: it measures
whether an instruction's address appears in the emitted line map, **and nothing more**.

> **Lost coverage is not a missing statement.** It has three quite different causes and this
> metric cannot tell them apart:
>
> 1. **folded into a use** — the value survives inside a later expression;
> 2. **relocated** — the statement is emitted, but carrying a different address, or moved
>    relative to its neighbours;
> 3. **genuinely dropped** — nothing in the output corresponds to it.
>
> Only (3) is a defect. Separating it from (1) and (2) requires reading the emitted C beside the
> machine text, function by function. There is no shortcut and this metric is not one.

This has already cost real time. A report of the per-block form called three statements at t32
`sub_4045B1` 0x404e10 absent in a change; two of them — `edi = edx` and `ebx = eax` — were still
being emitted and had merely lost their address mapping, one having been relocated below its
neighbour. Only the third was genuinely gone. The finding survived (`peek-a-bin-qzrl` turned up
three real drops with wrong values, including a `xor r,r` zeroing emitted as a copy of a live
register) but the *stated evidence* was wrong, and it was wrong because the metric's name promised
more than it measures.

Per-instruction is the finer instrument and the one that located those defects: a block counts as
covered when *one* of its five instructions maps, while the other four do not. Per-block is kept
for continuity with earlier measurements. Coverage has **never been 100%** and is not expected to
be — alignment padding and blocks that lift to no statements land here legitimately. Anyone who
reads a brief for these audits as "expect 0 drops" is chasing a number this harness has never
produced.

**Statement drops across `structureCFG`, by object identity.** Every statement `liftBlock`
produced is either somewhere in the tree `structureCFG` returned or it is not, and the test is
`Set<IRStmt>.has` on the object itself. **Measured 0/7002, 0/7331, 0/6519 and 0/6500 lifted
statements at `cee6f91`** (t32/t64/w64/w32).

This is the metric line map coverage is not. Of the three things lost coverage can mean, two
cannot register here at all:

| Cause | Line map coverage | This |
|---|---|---|
| folded into a use | lost | not a drop — folding is `foldBlock`, which runs *before* the snapshot |
| relocated / re-addressed | lost | not a drop — same object, elsewhere in the same tree |
| genuinely dropped | lost | **this, and only this** |

*A non-zero result means a statement nothing downstream can know existed.* It never enters the
tree, so there is no dangling `goto`, no missing label, no comment — the reader simply concludes
the code does not exist. That is what `peek-a-bin-cb2` was (6% of every statement the front end
produced, from the leftover pass requiring reachability from the entry) and what `peek-a-bin-hu7`
describes (4/8/8 assignments on t32/t64/w64, "always exactly 2 per function").

**It is reported, not gated, and that is deliberate.** Zero is what it measures today, but one
commit's measurement is not evidence that zero is an invariant of the design: `structureCFG`'s
short-circuit fold legitimately consumes the blocks between two tests without emitting anything
for them, and it is only true *today* that such blocks lift to no statements. Asserting 0 in the
run would pin something nobody has established — the same mistake as briefing an agent to "expect
0 drops" against a harness that had never produced 0. A **rise** is judged where regressions are
actually judged: `compare.mjs` treats `statements dropped` going up between two pinned runs as a
regression, on its own terms, whatever the baseline is.

Per-site detail is in `drops_<bin>.jsonl` — function, block address, the statement's own machine
address, its kind, its position in its block, and an assignment's destination register. The
report prints the count, the affected function count and a breakdown by statement kind.

*The instrument was validated by negative control, not by trusting its zero.* Disabling
`structureCFG`'s leftover pass — restoring the pre-`peek-a-bin-d3z` behaviour — makes it report
**1380/7002 dropped across 41 functions on t32** (612 assign, 577 store, 113 call_stmt, 49 raw,
29 return), and the `callees lost` gate goes red beside it. A measurement of *absence* can fail by
quietly observing nothing, so `corpus.audit.ts` also asserts that the tap fired and statements
were examined. That assertion is instrument liveness; it is not a threshold on the count.

**Unrecovered values — `__unrecovered_N` in the emitted C, counted and located.** This is the
audit for the sentence two sections up: *"clean" is not "recovered."* The emitter prints
`__unrecovered_N` when it cannot name a value — most often the condition of a Jcc whose flags
nothing in the IR explains — and declares it at the top of the function, which is exactly why the
C compiles. **Measured 108, 85, 67 and 85 values at `cee6f91`** (t32/t64/w64/w32; 216/170/134/170
occurrences of the token, since each value is declared once and used once). Of those, 89/85/67/67
stand in for a *branch*, and 32/37/31/25 of the branches could be given the address of the jcc
they came from.

**Until this existed, every gate here was structurally blind to all of them, and one of them was
actively misleading.** `guards_<bin>.jsonl` contains **zero** unrecovered guards, and not because
none exist:

| Audit | Why it is silent |
|---|---|
| polarity | `topOp(cond)` must find exactly one comparison operator. `__unrecovered_7 /* jne */` has none, so an unrecovered guard is **not a failing row — it is not a row at all**. |
| gcc | The value is declared. `if (__unrecovered_7)` is valid C. |
| callees lost / loop exits / offsetof / gotos | None of them reads a condition. |

The misleading part is the ratio. Polarity is reported as `ok/checked`, and a guard that falls
**out** of the audited set reduces `checked` while leaving the fraction at 1.00. So a change that
turned 400 correctly recovered guards into `__unrecovered_N` moved no number in a bad direction
anywhere in this harness, and `compare.mjs` called it no regression. That is not hypothetical —
it is the negative control below, and the **`compare.mjs` of `cee6f91` prints "VERDICT: no
regression" and exits 0** over it (`peek-a-bin-rl01`).

Both directions cross that boundary in silence, which is why the *denominator* is now judged in
its own right: recovery getting worse moves guards out of the audited set, and conditions getting
richer (a comparison cascade folding into `&&`) moves them out too.

Per-site detail is in `unrecovered_<bin>.jsonl` — function, the name, the note the emitter wrote
beside it, whether that note names a branch, what the value is used *for*, and the originating jcc
where one could be named. The report prints the count, the branch subset, a breakdown by site and
one by jcc mnemonic.

*Validated by negative control.* Disabling `conditionFromFlagResult` in `structure.ts` — restoring
the pre-`peek-a-bin-pu06` behaviour, where a Jcc whose flags were set by `dec`/`sub`/`and`/`or`
rather than `cmp`/`test` had no recoverable condition — takes t32 from **108 to 300** unrecovered
values (89 → 281 branches) and t64/w64/w32 from 85/67/85 to 220/186/241. `polarity.checked` falls
462 → 398 on t32 in the same run, and `npm run corpus` itself stays **green**, because none of
this is gated in the run. `compare.mjs` reports 16 regressions and exits 1.

**Call arity against `apitypes.ts`'s declared signatures** — `arity.ts`. For every emitted call
whose callee `src/disasm/decompile/apitypes.ts` declares, the arguments the emitted C passes are
counted against the parameters the table declares. **Measured at `e22ba6e`:**

| | t32 | t64 | w64 | w32 |
|---|---|---|---|---|
| exact / sites | 70/105 | 88/127 | 92/133 | 73/111 |
| under (at the ABI ceiling / below it) | 27 (0/27) | 36 (26/10) | 38 (26/12) | 28 (0/28) |
| **over** | 8 | 3 | 3 | 10 |

**This is the only oracle in the repo that can see call arity, and the gcc gate is blind to the
dimension by construction.** `gcc -std=gnu89` accepts an implicit declaration at *any* arity, the
emitter deliberately writes no callee prototypes, and `emitAudits.ts`'s `preludeFor` declares
every undeclared identifier as its own `long`. So `842/842 clean` cannot move on an arity defect:
it could not have caught `peek-a-bin-qb2x` — x64 arguments set up through a 32-bit sub-register,
where `ExitProcess()` was emitted with no argument at all while the machine passed one, and the
`mov ecx, 1` that set it up was then deleted as dead — and it cannot certify the fix. No entry in
the table is variadic, so a declared count is exact rather than a minimum — 209 signatures at
`e22ba6e`, 14 of which take no parameter at all (CLAUDE.md's "~130" for that table is stale).

**Why the file exists at all**, and it is this directory's own lesson turned on its author:
`peek-a-bin-qb2x` was verified against an instrument that lived in a scratch worktree and was
deleted with it. The diff carried the fix; it did not carry the measurement, and the headline
claim became unrepeatable until this was rebuilt (`peek-a-bin-02fa`). *When an agent builds an
oracle to verify a change, landing the oracle is part of the change.*

The two directions are not symmetric and must not be read as one number:

| | |
|---|---|
| **over** | The call passes MORE arguments than the API takes. There is no reading of the machine on which that is right — the argument was invented. `GetLastError(rcx)`, `GetProcessHeap(8, 0x1000)` (the pushes belong to the *next* call), `SetFilePointer(…, 5 of 4)`. Every one of the 24 rows in the corpus is provably wrong, and every one compiles clean. |
| **under** | The call passes FEWER. Split in two, because only one half is a recoverable defect: `underAtCeiling` is the emitted count sitting exactly at the ABI evidence's ceiling — `collectArgs64`'s four fastcall registers, `collectArgs32`'s eight-push scan — where an API declaring five or more parameters is short *by construction*; `underBelowCeiling` is an argument the evidence was there for. All 26 of t64's ceiling rows are `CreateFileW`, `WriteFile`, `MultiByteToWideChar` and friends. |

**NOT GATED IN THE RUN, and this is the closest call in the directory.** Every OVER row has the
character that makes `stale version-0 names` a gate — provably wrong, not a count awaiting a
threshold. The only thing separating them is that this count is *not zero*: 3 per x64 binary and
8–10 per x86 one, none of them introduced by the change the audit was rebuilt to certify. A gate
would therefore have to pin today's absolute, and absolutes here move whenever detection does — a
newly detected function carrying the same pre-existing defect would fail CI for a change that
caused nothing. So a rise is judged where rises are judged: `compare.mjs` treats `arity
over-count`, `arity under-count` and `under below the ceiling` rising as regressions, and `arity
exact` is a ratio that must not fall. **If the OVER count is ever driven to 0, make it a gate at
0** — that is the honest upgrade, and it is exactly the history of the stale-read audit.

What the run itself asserts is instrument liveness, and it matters more than usual because the
*good* direction of both counts is downward: a scan that quietly stopped matching call sites would
report `over 0, under 0` and look like the healthiest thing in the report. So `sites`,
`distinctCallees`, `declaredNames` (the table still exports its entries) and `scannedFuncs` all
have floors, and `exact + under + over` must equal `sites`.

Per-site detail is in `arity_<bin>.jsonl` — the OVER rows first, then the UNDER rows, each with
the callee, both counts, the emitted argument texts and the emitted line. **Adjudicate an OVER row
against the real prototype**: it is either an invented argument or a wrong entry in `apitypes.ts`,
and the audit cannot tell you which.

*Validated by negative control.* Reverting the `peek-a-bin-qb2x` fix — `collectArgs64` probing the
width-exact `RegState.get(reg)` instead of `wroteAnyAlias(reg)`, so a sub-width argument setup is
missed and arity stops there — takes t64 from **88/127 exact to 62/127** and w64 from **92/133 to
66/133**, with under 36 → 62 and 38 → 64 (below-ceiling 10 → 61 and 12 → 63) and **over unchanged
at 3 on both**. `5 ExitProcess` and `4 Sleep` reappear among the under rows, which is the defect
qb2x was filed for. `npm run corpus` stays green, because none of this is gated in the run;
`compare.mjs` reports the six arity regressions and exits 1. Without the arity rows that same pair
of runs moved nothing about arguments at all — the only other signal was `polarity guards audited`
falling by 2 and 3, which is an instruction to go and read some guards, not a statement about
calls.

**Function, instruction and jump-table counts.** These move whenever detection changes, which is
often, and usually because a defect was fixed.

## What the standing set does NOT catch

**None of the eight gates above catches a wrong-value defect** — a statement that is emitted, is
well-formed, and computes the wrong thing. `peek-a-bin-qzrl` is the worked example: a `xor edi, edi`
(zeroing) emitted as `edi = ebx`, a copy of a live register. Every gate was green over it, and each
for its own reason:

| Audit | Why it is silent |
|---|---|
| gcc | The C is well-typed. `edi = ebx` compiles perfectly. |
| polarity | The *guards* are correct; it is the assignments inside them that are wrong. |
| loop exit coverage | Counts ways out of a loop, not what the body computes. |
| callees lost | Looks only at call targets. |
| offsetof | Looks only at struct declarations and field offsets. |
| dangling gotos | Looks only at labels. |
| throws | Nothing raised. |

So a green run means "no defect **of the seven kinds these audits model**", which is a real and
useful claim but a narrower one than "the output is right". Wrong values are found by reading the
emitted C against the machine text, and the instruments for that are per-instruction line map
coverage (above) and cross-substitution (below) — neither of which is a gate, because neither has
a threshold that means anything on its own.

**A green polarity ratio is not evidence of a recovery rate, and never was.** `1490/1490 correct`
says every guard the auditor *could judge* states its jcc's sense. It says nothing whatever about
how many guards there were to judge: the denominator is what survived anchoring **and** had a
single top-level comparison operator, and roughly two thirds of every emitted guard fails one of
those two tests. 1257 skips against 462 judged on t32 is the actual shape of it. An unrecovered
condition fails the second test by construction, so the number that ought to fall when recovery
gets worse — `polarity.ok` — cannot, because the guard leaves the fraction entirely. Read
`polarity guards audited` and `unrecovered values` beside the ratio, or the ratio will tell you a
shrinking audited set is a perfect score.

Two distinct failures hide in a green number, and it is worth keeping them apart:

- **A ratio at 1.00 over a shrinking denominator is not evidence.** Whatever left the denominator
  left without being judged, and the fraction cannot report it. Always read the denominator.
- **A gate that is green on the dimension it measures says nothing about the dimension it does
  not.** This is not a hypothetical either. `peek-a-bin-qb2x` was verified against an oracle that
  sees call **arity** (which now lives here, as `arity.ts` — it did not at the time, and that is
  `peek-a-bin-02fa`), shipped green on every gate here, and four of the arguments it recovered
  name a **stale register** — `SearchPathW(0, rcx, rax, 0x400)` has exactly the right arity and a
  wrong second argument, because nothing in the standing set reads argument *naming*. The same
  shape as this section's own subject, one dimension over. Before quoting a green run, say which
  dimension it was green on.

### What the statement-drop audit does not catch

Its zero is a narrow claim and worth stating precisely, because "0 statements dropped" invites a
much larger reading than it earns.

- **It watches one step.** `cleanupStructured`, `wrapExceptionRegions`, `inferTypes`,
  `promoteVars`, `synthesizeStructs` and `emitFunction` all run after `structureCFG`, and a
  statement any of them discards is counted as **kept**. `cleanupStructured` in particular exists
  to remove statements. The audit says the structurer did not lose anything; it says nothing about
  the back half of the pipeline.
- **It watches one direction.** A statement that reaches the tree *twice* — the `for`-header
  double-emission the structurer guards against, where `x = f()` would run twice — is not a drop
  and does not register.
- **Kept is not correct.** A statement present in the tree but computing the wrong thing passes,
  exactly as it passes every gate above (`peek-a-bin-qzrl`).
- **It cannot see what was never lifted.** An instruction the lifter declines to model produces no
  statement, so there is nothing for the structurer to drop and nothing here to count. That gap
  shows up as `/* unlifted: … */` in the emitted C, not as a drop.
- **A block that lifts to no statements is invisible on both sides**, which is intended — that is
  how alignment padding stays out of the number — but it means a *lifting* regression that emptied
  a block would read as clean here.

### What the unrecovered-value audit does not catch

- **It counts admissions, not errors.** A `__unrecovered_N` is the emitter being honest. A guard
  that recovers *and states the wrong thing* is not counted here at all — that is the polarity
  audit's job, and the two are complements: this one watches the set polarity cannot see, and
  polarity watches the set this one cannot judge.
- **It cannot name the jcc for most branches.** 32 of 89 on t32, and the ceiling is not a bug in
  the scan. The emitted `if (…)` line carries **no line-map address** (`emit.ts` pushes the header
  without one), so the only route to a machine address is the same body-anchoring the polarity
  audit does, and that fails on roughly two thirds of all guards for reasons that have nothing to
  do with recovery. `jccFrom` in the jsonl says which happened for each one; `not-in-an-audited-guard`
  means the value was not in a guard at all.
- **`jcc` is a locator, not the identity of the unrecovered branch.** Anchoring names the jump
  that guards the *arm*, which in a short-circuited condition —
  `if (!__unrecovered_1 /* jle */ && edi <= 0x7FFFFFF0)` — is the last test in the chain, not the
  first, which is the one that was unrecovered. `note` is the authority on which branch it was.
  Over the corpus the two name the same mnemonic **123 times in 125**, and both exceptions are
  that shape; the agreement is worth something on its own, since the note comes from `structure.ts`
  and the anchor from the auditor's own reading of the CFG.
- **`/* unlifted: … */` is a different admission and is not counted here.** An instruction the
  lifter declines to model produces no expression and therefore no `__unrecovered_N`.
- **It does not know what a value was worth.** 300 unrecovered values in one function and 300
  spread over 60 are the same number.
- **`guards w/o single compare` is a lower bound on traffic across the audited-set boundary.** A
  guard whose *body* could not be anchored never reaches the judging step, so it is skipped for an
  anchoring reason and never lands in that bucket, however unrecoverable its condition was.

### What the arity audit does not catch

- **Nothing about what an argument SAYS.** Arity is a count. `SearchPathW(0, rcx, rax, 0x400)` has
  exactly the right arity and a wrong second argument, and this audit calls it exact — that is the
  stale-read audit's dimension, and the worked example is two sections up.
- **Only the 209 callees the table declares.** Every `sub_…`, every indirect call and every
  imported API `apitypes.ts` does not know is outside the denominator entirely: 105–133 sites per
  binary against 842–978 callee pairs the callee-loss audit sees. Adding a signature to the table
  widens the audit, which is worth knowing before reading a moved denominator as a regression.
- **It is only as good as the table.** An OVER row is either an invented argument or a wrong entry
  in `apitypes.ts`. `src/disasm/decompile/__tests__/apitypes.test.ts` pins the arity of some
  entries and the A/W pairs against each other, not the whole table against the SDK.
- **An argument in the right *position* is not checked.** A call emitted with the declared count of
  arguments in the wrong order is exact here.
- **`underAtCeiling` is a classification, not a proof.** It says the emitted count equals the ABI
  evidence's ceiling, which is *usually* why the call is short — but a call that would have been
  short anyway lands in the same bucket, and the bucket is therefore a lower bound on the
  structural half rather than a partition of blame.
- **It reads the emitted text, so it cannot see a call that was never emitted.** A dropped call
  is `distinct callees lost`' dimension.

### What the stale-version-0 audit does not catch

- **Only version 0.** A read of any *other* version that a later write has spoiled is a defect of
  the same family, and `splitStaleReads` repairs those from the version's own defining statement.
  Nothing here re-checks that it did.
- **Only a definition that dominates.** A write on *some* path to the read makes the name wrong on
  that path, and this audit does not count it — the site set requires a strictly dominating block,
  because that is the case where the name is wrong on every path and therefore provable.
- **A loop header that writes the register after the read is not a site.** The block does not
  strictly dominate itself, so a read at index 0 of a block whose index 5 redefines the register is
  invisible here even though the second trip through reaches it with the new value.
- **It reads the lifted statement list, not the emitted C.** `structureCFG`, `cleanupStructured`,
  `inferTypes`, `promoteVars`, `synthesizeStructs` and `emitFunction` all run afterwards, and any
  renaming they do is outside this measurement. `foldBlock` is included, because it is what decides
  whether the read and the write reach the page at all — stopping at `destroySSA` doubles the count
  (151 against 78 on t64) by counting writes that fold into their single use.
- **One address, one verdict.** A repaired read and a stale read of the same register at the same
  instruction cannot be told apart: an instruction can name a register twice
  (`lea r9, [rdx + rsi + 0x1d]`, where RSI holds the entry RDX), and the audit treats the address
  as repaired if any preserved entry value of that register is named there.

## Reading the numbers

> **The ratio is the claim. The absolute is a date-stamp.**

Denominators move underneath you. `842/842` becoming `838/838` is **not** a regression;
`838/840` is. Between two documented runs the gcc figure went `847/847` → `842/842` and the
offsetof figure `1007/1007 across 197` → `975/975 across 169`, purely from function detection
moving. None of that was a regression. Do not pin an absolute in documentation or a test.

The report prints a **"COMPARABLE WITH CLAUDE.md"** block covering `t32 + t64 + w64` only. The
historical figures in that file were measured over those three; `w32` was added later and audited
too, so the four-binary totals are *not* comparable with anything written there.

## Did my commit break anything?

A single run gives absolutes, and absolutes move on their own. To judge a commit you need both
sides pinned — **a base sweep taken against a moving HEAD silently compares your change against
someone else's work**, which has bitten this project more than once.

```sh
COMMIT=<the commit under test>
OUT=/tmp/corpusout

git worktree add /tmp/base "$COMMIT^"
ln -s "$PWD/node_modules" /tmp/base/node_modules
( cd /tmp/base && PEEK_CORPUS_LABEL=base PEEK_CORPUS_OUT=$OUT npm run corpus )

git worktree add /tmp/chg "$COMMIT"
ln -s "$PWD/node_modules" /tmp/chg/node_modules
( cd /tmp/chg && PEEK_CORPUS_LABEL=change PEEK_CORPUS_OUT=$OUT npm run corpus )

npm run corpus:compare -- $OUT/base $OUT/change

rm /tmp/base/node_modules /tmp/chg/node_modules
git worktree remove /tmp/base && git worktree remove /tmp/chg
```

`compare.mjs` joins guards on **the address of the originating jcc** — function names move when
detection changes, instruction addresses do not. It exits non-zero if an invariant rose or a ratio
fell, and prints every guard that changed.

**A guard leaving the audited set is not automatically a regression, but it is no longer silent.**
It can mean the function was restructured — a comparison cascade becoming a `switch`, say — or
that the auditor could no longer anchor it. That is exactly what happened at `4a4ec70`, where 41
guards left t32's audited set and every one of them belonged to a function that had gained a
`switch`. It can equally mean the guard stopped being recoverable, which *is* a regression, and
the two were indistinguishable because neither moved a number. So `polarity guards audited`
falling now counts as a regression, marked `FEWER GUARDS AUDITED — adjudicate`, and it means
**"read the emitted C for these functions"** rather than "the change is wrong". `guards w/o
single compare` rising is marked the same way. Both sit beside `unrecovered values`, which is the
one of the three that says the guards left because recovery got worse.

**Three findings in the per-guard join are report-only, and one is not.** `changed`, `onlyBase`
and `onlyChange` do not affect the verdict — `shapeOf` includes the emitted condition *text*, so
it moves whenever a spelling improves (`*(int32_t*)(rbp - 0x64)` becoming `var_64` changes
hundreds of guards without changing what any of them means), and gating that would make
"regression" mean "something changed". A non-zero `CHANGED` now prints a banner saying it is not
in the verdict; read it. What **is** gated is a guard at a jcc present on both sides whose
**anchor-A verdict got worse** — the swap that the aggregate `polarity inverted` and `mismatch`
rows cannot see, because one guard fixed and another broken leaves the total flat.

## Did my change *cause* that, or merely reveal it?

The decisive experiment, and the one nobody rebuilds from scratch under time pressure: **hand one
commit's decompiler another commit's recovered jump tables** and see whether the emitted C moves.

```sh
# tables recovered by the change, decompiled by the BASE decompiler
PEEK_CORPUS_TABLES=$OUT/change PEEK_CORPUS_LABEL=base-with-change-tables \
  PEEK_CORPUS_OUT=$OUT npm run corpus            # run this inside the BASE worktree

npm run corpus:compare -- $OUT/base-with-change-tables $OUT/change
```

If the two agree, the change did not cause the difference — its detection merely fed the same
decompiler different input, and whatever you are looking at was latent. That is precisely how
`peek-a-bin-qzrl` was settled: the base decompiler at `fe032ab`, given `4a4ec70`'s tables, emitted
**byte-identical C including every defect**. Those blocks had simply never been through
SSA/fold/structure before, because they were predecessor-less and `structureCFG`'s leftover pass
dumped them out flat.

**What it substitutes is only the jump tables.** The instruction stream still comes from the
running commit's own detection and disassembly. That is the point — it isolates the tables as the
single variable — but it means a null result says "the tables are not the cause", not "nothing
about detection is". Every run that used substituted tables says so loudly in its report header and
in `summary_*.json`'s `tablesFrom`, because such a run is **not** a measurement of that commit as
it would actually behave and must never be quoted as one.

Measured on that same pair (t32), which shows exactly how far the isolation reaches:

| | instructions | tables | guards audited | `switch` in `sub_4045B1` |
|---|---|---|---|---|
| base `fe032ab` | 18140 | 10 | 493 | 0 |
| base **+ change's tables** | 18140 | 13 | **459** | **1** |
| change `4a4ec70` | 18060 | 13 | 459 | 1 |

Handing base the tables reproduces the whole of the guard change — 459 audited against the
change's 459, and `compare.mjs` reports **0 changed, 0 only-base** guards between them, against
5 changed and 41 only-base without substitution — and recovers the `switch`. It does **not**
reproduce the 80 removed instructions, because those go away through `jumpTableSpans` feeding
`hybridDisassemble`'s coverage, which is a *disassembly-stage* input rather than the `jumpTables`
map. So one commit's two effects come apart cleanly: the map explains the restructuring, the spans
explain the instruction removal. Substituting the instruction stream as well would close the
remaining gap and is not implemented.

## Layout

| File | |
|---|---|
| `corpus.audit.ts` | The entry point. Preflight, the shared sweep, the gates, the report. |
| `preflight.ts` | Where the corpus is, and whether this machine can run at all. |
| `sweep.ts` | One load + decompile pass per binary; polarity, loop exits, callee loss, line map coverage, statement drops, unrecovered values. |
| `emitAudits.ts` | The audits that read only emitted text: gcc, `offsetof`, gotos. |
| `arity.ts` | Emitted call arity against `apitypes.ts`'s declared signatures. Reads only emitted text; the one oracle here that can see arity. |
| `compare.mjs` | Base-vs-change diff over two artifact directories. Plain node. |
| `artifacts/<label>/jumpTables_<key>.json` | The recovered tables, as the cross-substitution input. |
| `artifacts/<label>/drops_<key>.jsonl` | Every dropped statement, per site. Empty file = audit ran and found none. |
| `artifacts/<label>/unrecovered_<key>.jsonl` | Every `__unrecovered_N`, per site: note, cause, use site, originating jcc where one could be named. |
| `artifacts/<label>/arity_<key>.jsonl` | Every declared-API call whose emitted arity is not the declared one, OVER rows first. Empty file = audit ran and found none. |
| `artifacts/<label>/stalev0_<key>.jsonl` | Every version-0 read left naming an overwritten register, then every spoiled entry-value copy. Empty file = audit ran and found none. |
| `artifacts/` | Generated. Gitignored. |

### The two audits that re-run the pipeline prefix, and why one of them has to

`staleReads.ts` drives its own `buildCFG → liftBlock → buildSSA → ssaOptimize → destroySSA →
foldBlock` and is the one place in this directory that does. It is exactly the second copy the tap
below exists to avoid, and it is accepted here for a reason the tap cannot serve: the question
needs the SSA **before** it is lowered and the statement list **after**, and there is no single
point in `pipeline.ts` at which one observer sees both. Every pass it calls is the repo's own
export, in `pipeline.ts`'s order, so a stage inserted between `ssaOptimize` and `destroySSA` shows
up as a divergence between the two — but nothing enforces that automatically. If you insert one,
update the replica.

### The one thing these audits need from `src/`

`decompileFunction` takes an optional last argument, `tap`, and the statement-drop audit is its
only caller. It fires once, between `structureCFG` being handed the lifted blocks and its result
being passed on, and hands both sides over.

It exists because **neither side is recoverable from the return value** — the emitted C says
nothing whatever about a statement that never entered the tree — and because the alternative was
worse. Re-running `buildCFG → liftBlock → buildSSA → ssaOptimize → destroySSA → foldBlock →
structureCFG` here instead would be a second copy of the pipeline prefix, and the day a stage is
inserted between `foldBlock` and `structureCFG` that copy measures a different program while
looking exactly like it measures this one. `typecheck` would not notice.

Passing no tap costs one `undefined` check and copies nothing. **Keep it that way**: an
instrument that alters what it measures is worse than no instrument.

**Everything reads one sweep per binary, and that is a correctness requirement rather than an
optimisation.** `StructRegistry` is cross-function state shared for the lifetime of a loaded file,
so the emitted C for a function depends on which functions were decompiled before it. An audit that
ran its own pass over a *subset* — only functions with a jcc, say — would be measuring a different
program from the one production emits.

## Things that will trip you up

- **`tsx` does not work on this machine** (Node 18, `ERR_REQUIRE_ESM`). That is why the audits are
  vitest files and `compare.mjs` is plain node. Do not "fix" this by reaching for tsx.
- **Vitest's default reporter discards `console.log` from inside a test** but passes
  `process.stdout.write` through. The report uses the latter, and is also written to `report.txt`.
- **These must never join `npm test`.** They are named `*.audit.ts` so vitest's default include
  cannot match them, and they run under `vitest.corpus.config.ts`.
  `build/corpusIsolation.test.ts` fails the ordinary suite if that stops holding. Renaming one to
  `*.test.ts` would make every CI run try to disassemble binaries it does not have.
- **A run takes a few minutes**, most of it gcc. There is no sampling mode on purpose: an audit
  over a sample answers a different question.
