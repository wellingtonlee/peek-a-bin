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

> **"Clean" is not "recovered."** A large share of these functions compile precisely because the
> emitter *names* what it failed to recover — `__unrecovered_N`, an "unlifted" comment — instead of
> printing something plausible. Do not read "all of them compile" as "all of them are right".

**Struct layout, by a compiled and *run* `offsetof` program.** Field names record the offsets
recovery found (`field_0x18`), so a declaration C would not lay out that way states something
false, and every `p->field_0x18` in that body then reads bytes the access never touched. Reading
the declaration is not enough; this compiles and executes it. *A failure means the emitted struct
declarations and the emitted field accesses disagree about where the data is.*

**Throws.** `decompileFunction` raising on any real function.

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

**A guard leaving the audited set is not automatically a regression.** It can mean the function was
restructured — a comparison cascade becoming a `switch`, say — or that the auditor could no longer
anchor it. Read the emitted C for those functions before judging. That is exactly what happened at
`4a4ec70`, where 41 guards left t32's audited set and every one of them belonged to a function that
had gained a `switch`.

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

## Layout

| File | |
|---|---|
| `corpus.audit.ts` | The entry point. Preflight, the shared sweep, the gates, the report. |
| `preflight.ts` | Where the corpus is, and whether this machine can run at all. |
| `sweep.ts` | One load + decompile pass per binary; polarity, loop exits, callee loss, drops. |
| `emitAudits.ts` | The audits that read only emitted text: gcc, `offsetof`, gotos. |
| `compare.mjs` | Base-vs-change diff over two artifact directories. Plain node. |
| `artifacts/<label>/jumpTables_<key>.json` | The recovered tables, as the cross-substitution input. |
| `artifacts/` | Generated. Gitignored. |

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
