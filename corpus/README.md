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
| **Where they go** | Any of the locations below. **There is no default absolute path** — see "Finding the binaries". |
| **Compiler** | `gcc` on PATH (or set `CC`). Needed by two audits. |

**The binaries are deliberately not in the repo and must not be added.** They are third-party
executables; a disassembler vendoring its own test corpus is the wrong trade. That is why every
entry point has to answer "can I run?" first.

### Finding the binaries

`preflight.ts` searches, in this order, and the **first directory holding all four wins**:

| | Location | |
|---|---|---|
| 1 | `PEEK_CORPUS_DIR` in the environment | this run only |
| 2 | `PEEK_CORPUS_DIR` in `.env` at the repo root | this machine, durably; gitignored, and documented in `.env.example` |
| 3 | `$XDG_DATA_HOME/peek-a-bin-corpus` | `$XDG_DATA_HOME` defaults to `~/.local/share` |
| 4 | `~/.peek-a-bin-corpus` | |
| 5 | `<repo>/corpus/binaries` | gitignored — **never commit what you put here** |

**An explicit setting (1 or 2) is the whole search.** If you say where the binaries are and they
are not there, the run reports that about *the directory you named* rather than quietly
succeeding from somewhere else. Only when nothing is set are 3–5 probed.

Setup, once per machine, is therefore either "put the four files in
`~/.local/share/peek-a-bin-corpus`" or one line in `.env`:

```sh
echo 'PEEK_CORPUS_DIR=/path/to/them' >> .env
```

`.env` rather than an `export` because an export has to be retyped by the next shell, the next
session and the next agent, and this harness's failure mode is precisely *not being run*.

**There used to be a hardcoded default** — an absolute path inside a virtualenv on the machine
this project was developed on. It stopped existing, and because a missing corpus **skips** rather
than fails, nothing ever went red: the default path simply became the skip path, so
`npm run corpus` with nothing set did nothing on the machine the project lives on, while the
binaries sat two directories away. That is `peek-a-bin-dfae` one layer out — the verification
existed and was not being run (`peek-a-bin-alx1`). `build/corpusPreflight.test.ts` now fails the
ordinary suite if any candidate directory stops being derived from `$XDG_DATA_HOME`, `$HOME` or
the repo, which is the property a personal absolute path violates.

A skip names **every** directory it probed and what was wrong with each, plus the two ways to say
where they really are:

```
CORPUS AUDITS SKIPPED — nothing was verified.
  4 of 4 corpus binaries not found (t32, t64, w64, w32); looked in … [no such directory]; …

  Looked for t32.exe, t64.exe, w64.exe, w32.exe in:
    /home/you/.local/share/peek-a-bin-corpus  — no such directory  [$XDG_DATA_HOME]
    /home/you/.peek-a-bin-corpus              — no such directory  [home directory]
    /repo/corpus/binaries                     — no such directory  [this repo (gitignored)]
  …
    export PEEK_CORPUS_DIR=/path/to/them          # this shell only
    echo 'PEEK_CORPUS_DIR=/path/to/them' >> /repo/.env   # this machine, durably
```

### Environment variables

| Variable | Meaning |
|---|---|
| `PEEK_CORPUS_DIR` | Directory holding the four `.exe` files. Point it at any copy. Also read from `.env`; see "Finding the binaries". |
| `PEEK_CORPUS_BINS` | Comma-separated subset, e.g. `t32,t64`. Default: all four. |
| `PEEK_CORPUS_OUT` | Where artifacts go. Default `corpus/artifacts` (gitignored). |
| `PEEK_CORPUS_LABEL` | Subdirectory under the output dir. Default `local`. Use it to keep two runs apart. |
| `PEEK_CORPUS_TABLES` | Directory of another run's `jumpTables_<key>.json`, used instead of this commit's own. See "Did my change cause that". |
| `CC` | Compiler to invoke. Default `gcc`. |

All of these may also be set in `.env` at the repo root, with a shell setting taking precedence.
`PEEK_CORPUS_OUT` and `PEEK_CORPUS_LABEL` are read straight from the environment in
`corpus.audit.ts` and are the two that are **not** — they are per-run, and a per-run value has no
business being recorded per-machine.

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
- `TAKEN` is a **`cmp` model**, and `BIT_TAKEN` is the one place it is widened. It maps each jcc to
  the operator of the magnitude comparison its flags describe, which is right for a `cmp` and for
  every `test`-owned form that reduces to a comparison against zero — and simply the wrong
  vocabulary for a `bt`, where CF is bit *n* of the operand and no `<`- or `>=`-shaped spelling of
  "that bit is set" exists. `BIT_TAKEN` gives `jb → !=` and `jae → ==` for a jcc whose
  **immediately preceding instruction** is a `bt`, decided from the machine text with no
  flag-transparency reasoning, so a `bt` one instruction further away keeps `TAKEN`'s expectation
  and is reported MISMATCH — the widening is exactly as narrow as the fact justifying it. **It is a
  widening, not a weakening, and that is checkable**: `NEG` maps `!=` and `==` to each other, so a
  bit-test guard emitted at the wrong polarity is still INVERTED and one emitted as a magnitude
  comparison is still MISMATCH. Negative-controlled — flipping the decompiler's `bittest` arm makes
  the run exit 1 with `inverted=8` on t64 and `inverted=5` on w64 (`peek-a-bin-frt8`).

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

**A register name the image has no encoding for** (`unencodableNames` in `emitAudits.ts`). *A
failure means the emitted C names a register no instruction in the file can have written and no
reader can mean.* `canonReg` maps every alias to the 64-bit parent because that is the register's
*identity* and SSA keys on it, so any path that lets a canonical name reach the page prints `rcx`
in a function whose every other line says `ecx`. **124 mentions, 18 distinct names, over 19 of 573
PE32 functions at `d514274`; 0 now** (`peek-a-bin-1k4`'s residue, closed by `peek-a-bin-0s6e`).

**It is asked of PE32 only, and that restriction is what makes it an oracle rather than a
heuristic.** In a 32-bit image the instruction set has no RCX, so every occurrence is provably
wrong — `polarity inverted`'s character, hence a gate at 0. On x64 `rcx` is an ordinary correct
spelling, and telling a canonical name apart from a real 64-bit read needs the *live range's* own
width, which is `registerSpeller`'s question and is not recorded in the emitted text. So the x64
pair contributes structurally 0 and a green row there says nothing; `funcs` beside it is the
liveness half, and a fall in it is a scan that stopped observing.

**Two other gates are structurally blind to this and one of them by design.** `gcc` cannot see it
because `preludeFor` declares every undeclared identifier as its own `long`, so `rcx` and `ecx`
compile cleanly as two unrelated variables. `staleReads.ts` cannot either: it compares the *name* a
read uses rather than the canonical register, deliberately, because a correct live-range split
emits two names for one register — so a canonical name reads to it as a legitimate second live
range and passes. Negative-controlled: restore the phi operand's spelling evidence in
`splitStaleReads` and `npm run corpus` exits 1 naming exactly 124.

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
was given on the way in". If a block that **strictly dominates** the read has since assigned the
**name the read uses**, the name in the output denotes something else. The name, not the canonical
register: a register split into two live ranges is correctly emitted as two identifiers, and only
one of them is clobbered — see "Two things the site set and the verdict had to be taught" below. *A failure means the emitted C names a
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

**Wrong-operand guards.** The right operator over the wrong operands — the class every other gate
here is *structurally* blind to, which is why it survived to be found by reading. Polarity checks
the emitted comparison **operator** against its jcc's taken sense, and a wrong-operand guard has
the right operator, so it passes; it is not `__unrecovered_N`, so the recovery baseline does not
count it; gcc compiles it; nothing in it is a version-0 read. *A failure means the emitted `if`
asserts a test the program does not make.*

Two mechanisms, both visible in the instruction stream alone:

| | |
|---|---|
| **superseded** | A `cmp`/`test` in the block, then something else writes the flags before the jcc. `cmp eax, 5 / sub ecx, edx / jne` — the machine branches on `ecx - edx != 0` (`peek-a-bin-jitf`). |
| **clobbered** | The flags really are the `cmp`'s, but an operand is overwritten before the jcc. `cmp eax, 5 / mov eax, edx / je` — the block's statements are emitted above the `if`, so the guard reads the new EAX (`peek-a-bin-xe01`). |

Two counts, and only the second is a defect:

| Count | What it is |
|---|---|
| `shapes` | Blocks whose compare reading one of the two mechanisms spoiled. A property of the **machine code**, so a decompiler fix does not move it. This is the liveness number: an audit that measures an absence and has quietly stopped looking reports the healthiest figure in the report. **53/9/6/38** (t32/t64/w64/w32) at `e22ba6e`. |
| `named` | Of those, the ones the emitted C nonetheless states. **The defect, and the gate.** |

**Why this gates when the baselines below do not**, on the same terms as stale version-0 rather
than by analogy: every row is a provably false statement about the program, which is
`polarity inverted`'s character, not a count awaiting a threshold. It is 0 because a fix put it
there, not because it was found there.

*Validated by negative control, and the control is unusually strong.* With both fixes disabled —
the emitted C then **byte-identical to the true base on all four binaries**, checked by md5 — it
reports **29/5/3/21, i.e. 58 named**. Those 58 are *precisely* the 58 guards `compare.mjs`
independently reports as `only in BASE` over the same pair of runs, with `CHANGED 0` and
`only-change 0`. Two instruments that share nothing agree row for row. Three were adjudicated by
hand against `objdump`, including t64 `0x1400055a6` (`cmp %cx,(%r8) / mov $0x58,%ecx / jne`,
emitted as `*(uint16_t*)(r8) != (uint16_t)ecx`).

**In `compare.mjs`** (`peek-a-bin-x5lb`): `named` is gated on a rise, and `shapes`,
`bySuperseded`, `byClobbered` and `blocks` are reported. `named` is already gated at 0 *in the run*,
so a rise fails CI before `compare.mjs` is reached — it is repeated there because `compare.mjs` is
what says **what moved** between two pinned commits, and a run that fails without naming the rows
that came back is the failure mode `peek-a-bin-rl01` documented. `shapes` is deliberately **not**
gated: it counts blocks whose trailing jcc reads flags the recovered compare does not describe,
which is a property of the machine code and moves only when function detection or block
construction moves, so a change in it is a signal about something else and is adjudicated rather
than judged. Guarded with the `if (B.x && C.x)` idiom, so an artifact directory predating the audit
reads `NOT MEASURED` rather than scoring a perfect zero — verified in both directions.

**What it does not catch**, so the zero is read for what it is:

- **`named` is a lower bound.** It counts only guards the polarity pass could **anchor** to a jcc.
  The other 48 spoiled readings in this corpus were equally wrong on the page and merely
  unanchorable. `shapes` has no such dependency, which is the other reason to read both.
- **It shares `isFlagTransparent` with the code under test.** That table is a fact about x86 and is
  deliberately single-sourced — a second copy is the failure mode `flagModel.ts` exists to
  prevent — so this audit cannot catch an error *in that table*. The judgement built on top of it,
  which registers a compare names and what writes over them, is written in `staleGuards.ts`
  independently and reads only raw operand text; it does **not** call `clobberedAfter`.
- **A guard spoiled by a `call` is structurally reachable and counted, and the sub-class is
  empty.** `buildCFG` does not split at a call, so the shape is available — MSVC simply never
  emits a compare that a call then destroys, because that would be branching on garbage.
- **Nothing about a guard whose operands are right and whose value is wrong** for some other
  reason. That is the wrong-value class no gate here models.

Per-site detail is in `staleguards_<bin>.jsonl` — the block's jcc, which mechanism, the `cmp` whose
operands the reading would have named, the instruction that took them away, and the emitted
condition where one reached the page (`null` where the reading was refused).

**A read whose definition the fold deleted** (`lostDefs.ts`). *A failure means the emitted C reads
a register that nothing in the function assigns.* `foldBlock` inlines a definition read exactly
**once** into that one reader and drops the assignment — but it is handed ONE block, so "once"
counts only that block's reads. A definition read once locally and again in a successor was
therefore deleted out from under every later read: `t32!sub_40D99A`'s `mov ecx, [ebp+8]` has one
in-block reader and eleven reads over the three blocks below it, and the emitted function's only
`ecx` on the left of an `=` was an `ecx = ecx;` from an unrelated `lea ecx,[ecx]` NOP
(`peek-a-bin-7eyn`). **544 reads over 172 functions at `91085f3`** — 168/110/110/156 on
t32/t64/w64/w32 — and **0 on all four** since `pipeline.ts` passes `blockLiveOut`'s answer to the
fold.

The discriminator is what makes this a gate rather than another upper bound. A register read that
no definition reaches is *usually correct output*: it is the function's entry value, which is
exactly what a parameter arriving in a register looks like, and CLAUDE.md's crude
read-but-never-assigned scan cannot separate the two. So the audit brackets the fold and counts
only reads that **had** a reaching definition before it and have none after — an entry value has
none on either side and never enters the count. `entryReads` reports that legitimate population
(1159/1513/1460/1498) beside the gate, and a run where it collapsed to zero would be a gate
reading 0 because the instrument stopped observing.

**What it does not catch.** It brackets `foldBlock` and only `foldBlock`. A definition some *other*
pass deletes, and the general question "does every name in the emitted C denote something the
function produces", are outside it. Its independence is also weaker than the audits above and is
stated as such in the module docstring: `fold.ts` decides what to keep from *liveness*, this
decides what went missing from *reaching definitions*, which are dual analyses rather than one
shared routine — but this is a regression gate on one pass, not an oracle standing outside the
question. Negative-controlled the usual way: force `escapes` to false in `fold.ts` and
`npm run corpus` exits 1 naming the rows, at exactly the 168/110/110/156 an independent throwaway
instrument reported at `91085f3`.

**A direct branch aimed outside the image** (`wildBranches.ts`). *A failure means the
disassembler is decoding data as code somewhere, and this branch is where it showed.* `jmp`, `call`
and every `Jcc` with a literal target encode a displacement relative to the next instruction, and a
linker resolves that displacement inside the image it is producing. So a filed `jmp 0x288402b` in a
PE whose image is `0x400000`..`0x40e000` is not an instruction the file contains: nothing the loader
maps is there, the branch could only fault, and no compiler or hand-written prologue emits one. It
is a byte string the disassembler walked into — and what it walked into is the interesting part,
because it is always either `.text` data read as code or a misaligned walk off the end of some.
**1/0/0/1 over 4241/4073/3644/3792 direct branches** at `6d5ae92`; **0 on all four** since
`overlappedTableExtent` (`peek-a-bin-xqxy`).

Deliberately *not* the weaker question. "This branch leaves its function" is ordinary — a tail
call, a `__finally` funclet, an ICF-shared epilogue — and it is what `peek-a-bin-y1di`'s instrument
asked; "outside the code *section*" would be arguable, since a thunk table lives in a data section
on some toolchains. The image is the one boundary nothing legitimate crosses, which is what makes
every row unarguable rather than merely suspicious.

**It is a lower bound, and a loose one.** Fiction registers here only when it happens to decode as
a direct branch AND the displacement happens to land outside the image: of the four jump-table
sites `peek-a-bin-xqxy` fixed, this saw one per binary. So a green reading is weak evidence that no
bytes are being read as code, while a red one is proof that some are. Every other standing
instrument was blind to that class — gcc compiles fiction, polarity judges guards that exist, the
statement-drop audit counts drops rather than inventions, and the spurious-run census below needs a
run of four code-pointer words *containing its own dispatch base*, which Shape 1's three-word run
does not. `checked` is the liveness half and is non-vacuous on all four binaries, so unlike the
switch-arm denominator it needs no per-binary condition. Negative-controlled: revert
`overlappedTableExtent` and `npm run corpus` exits 1 naming exactly `t32 0x40b824 jmp 0x288402b`
and `w32 0x40964c jmp 0x2301953`, both `source: "gap-fill"`.

**What it does not look at.** Only a literal absolute target — `insn.opStr` being exactly `0x…`.
An indirect branch names no address to check and a register's value is not a static fact. It is
also phrased in terms of the emitted stream and `sizeOfImage` and mentions neither jump tables nor
`unboundedTableExtent`, on purpose: the change it was built for works by marking table bytes as
data, and an audit in those terms would be measuring its own input.

**A switch arm claiming the switch is over** (`armExits.ts`). *A failure means the emitted C
states control flow the machine contradicts.* `structureSwitch`'s `armBody` claims exactly one
block per arm — deliberately, because the convergence scan after the switch is what decides where
the region following it begins — and it used to close that arm with `break` however the block ends.
`break` is not a terminator that can always be appended: it is a claim, and it says the switch is
over. **35 arm blocks on t32 and 17 on w32** were closed that way while having a successor (25 and
12 ending in a conditional jump, 10 and 5 in a `jmp`), of which 31 and 14 were a false claim; **0
on all four** since `armExit` spells the block's own exit (`peek-a-bin-pqs5`). For the conditional
half the recovered **test** went with the transfer: `pipeline.ts` step 4b has already hoisted the
`IRBranch` out of `liftedBlocks`, so `t32!sub_4045B1` case 7 emitted `eax = (uint16_t)ecx; break;`
for a block whose next two instructions are `cmp eax, 0x64 / jg 0x404B46`, with `eax > 0x64`
nowhere in its 698 lines and no `goto` naming either successor.

The two halves are reported separately because they are different mechanisms — the conditional one
loses a recovered test as well as a transfer — and `arms`, `truthfulExits` and `unnameable` are the
denominator. **That denominator is 0 on both x64 binaries**, which recover no jump table at all, so
a green gate there says nothing whatever; the gate therefore ties its liveness check to the
recovered-table count rather than asserting it blind (72 arms over 5 functions on t32, 54 over 3 on
w32, all of them truthful, at `5c5dab9`). Negative-controlled: replace `armExit`'s body with
`[{ kind: "break" }]` and `npm run corpus` exits 1 naming exactly 35/0/0/17, the figures an
independent throwaway probe reported at `91085f3`.

**What it does not catch.** Three things, all structural. It is scoped to a switch **arm** —
`break` and `goto` are emitted in many other places and none of those closures is judged here
(`gotoCheck` asks only that a `goto` names a label the function defines, never that the transfer is
the one the machine makes). It judges the closure against `buildCFG`'s successor list, so a block
whose real successor the CFG never drew reads as a block with nowhere to go, which is the blind
spot function sizing gave the loop-exit audit. And it says nothing about the arm's *statements*: an
arm that under-emits its body while spelling its exit correctly passes, which is the residue
`peek-a-bin-pqs5` left behind. **The observation also comes from inside `structureSwitch`**, so it
cannot catch an error in `armExit`'s own reading of the CFG — only the closure it chose, checked
against the successor list the same `BasicBlock` carries. It is a regression gate on one decision,
not a second opinion about control flow.

**Call arity OVER-count, against `apitypes.ts`'s declared signatures.** No entry in that table is
variadic, so a call the emitted C passes more arguments to than the API declares passes one the
machine never passed. *A failure means the emitted C states that the program hands a function a
value it does not.* This is the **only** audit here that can see call arity at all — gcc accepts an
implicit declaration at any arity, so `842/842 clean` cannot move on the dimension — and it gates
only in this one direction. **UNDER is not gated**; see the full section under *Baselines* below
for both counts, the ceiling split, and the three shapes this defect had. Gated at 0 since
`peek-a-bin-7r1l` (`peek-a-bin-f51x` and `peek-a-bin-6lmh` cleared the x86 half first).

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

**What a call destroys — `clobbered_<reg>_<n>` in the emitted C, counted beside the constructs
emitted.** The emitter prints `clobbered_rcx_4` for a read of a register version a *call* handed
out: nothing defines it, and naming it `rcx` would put the reader back where they started, because
C's `rcx` still holds whatever the last `rcx = …` line put there. **Measured at `f685b6d`: 0, 11,
11 and 0 reads (t32/t64/w64/w32) with the narrow model, and 0, 21, 21 and 0 once
`src/disasm/callSummary.ts`'s per-callee summaries were wired in** — 17 distinct values across 7
functions per x64 binary.

**IT IS NOT A GATE IN EITHER DIRECTION, and that is the whole design of the row.** A rise is not a
defect: a call that really does destroy a register *should* say so, and the entire point of
`peek-a-bin-hj1` was to widen this honestly. A fall is not an improvement either — the narrow model
reaches zero by saying nothing at all, which is how the ABI-set experiment could look like a
regression when it was measured and how the narrow one could look like a triumph.

**What makes a change here judgeable is the `if`/`while`/`for` counts printed beside it.** The ABI
volatile set's measured harm was a guard **deleted** — `t64!sub_140004A9C` computes R10
conditionally, calls, and stores through it, and clobbering took the `if` count 1925 → 1924 — so
the construct counts are the row that turns a clobber count into a verdict. Read them together or
read neither. On the run that took clobbered reads 11 → 21 they were **unchanged on all four
binaries**, and `t64!sub_140004A9C` was byte-identical.

Three further figures are instrument liveness for the summary pass, which would otherwise report
the healthiest possible numbers if it quietly stopped resolving callees: `callee summaries`
non-empty out of functions summarised, how many sit at the full volatile set (267/279 non-empty
and 187 full on t64; 286/288 and **0** on t32, because 32-bit code can only write EAX/ECX/EDX), and
`unclassified mnemonics` — instructions whose mnemonic `callSummary.ts`'s written-register table
does not classify. That last one is **0 on all four binaries** and each one would be a write the
scan cannot see, so `compare.mjs` treats a rise in it as a regression while every other row here is
report-only.

*Adjudicating a change.* The cost of the wiring measured here was entry-value copies: 103 → 153 on
t64 and 96 → 144 on w64, both with `spoiled 0`, +111 and +106 emitted lines, and 66 of 279 and 61
of 275 functions changed against **byte-identical PE32**. Six guards on t64 and five on w64 left the polarity audit's anchored set; every one was an
entry-value copy inserted at the top of the guarded block, which moves the anchor while the guard
text and the `if` count stay put. That is the shape to expect, and it is exactly why
`polarity guards audited` falling means "read the emitted C" rather than "the change is wrong".

**Call arity against `apitypes.ts`'s declared signatures** — `arity.ts`. For every emitted call
whose callee `src/disasm/decompile/apitypes.ts` declares, the arguments the emitted C passes are
counted against the parameters the table declares. **Measured on base `7082e66` with
`peek-a-bin-7r1l` applied:**

| | t32 | t64 | w64 | w32 |
|---|---|---|---|---|
| exact / sites | 79/105 | 93/127 | 99/133 | 85/111 |
| under (at the ABI ceiling / below it) | 26 (0/26) | 34 (26/8) | 34 (26/8) | 26 (0/26) |
| **over — GATED at 0** | 0 | 0 | 0 | 0 |

The same base with `peek-a-bin-7r1l` **not** applied reads 79/105, 90/127, 96/133 and 85/111
exact, the same under counts and ceiling splits, and **over 0/3/3/0**. So the x64 fix moved 3 rows
per x64 binary from `over` straight to `exact` with **the under counts and both ceiling splits
unchanged**, and t32/w32 byte-identical because `collectArgs64` is the x64 path only. One step
earlier, base `91cca4f` without `peek-a-bin-6lmh` read 75/105, 90/127, 96/133 and 79/111 exact
with **over 4/3/3/6**, the x86 half of the same story.

**Part of the drift from the previous table in this file is the AUDIT being fixed, not the
decompiler, and the two must not be conflated.** `maskLiteralsAndComments` blanked a string
literal to spaces so its commas and parentheses could not mis-split the argument list — which
also erased the argument, so `LoadLibraryA("user32.dll")`, a call whose *only* argument is a
literal, read as a call with none. A literal is an argument and a comment is not, so they are now
masked differently: literals to a digit filler that survives `splitArgs`' emptiness test,
comments still to whitespace. The defect could only invent `under` rows, never hide an `over`
one, which is why every historical over-count quoted here still stands; on the same base
`91cca4f` with the decompiler untouched it moved exact 74→75, 88→90, 92→96 and 77→79 and under
27→26, 36→34, 38→34 and 28→26, with over unmoved at 4/3/3/6. It surfaced only once the emitter
stopped putting an invented second argument beside the literal. **Both sides of every
before/after pair above are taken with the fixed oracle.**

At `78b6040` with `peek-a-bin-f51x` applied and the *old* oracle the table read 74/88/92/77
exact, under 27/36/38/28, over 4/3/3/6; at `e22ba6e` the exact counts were 70/88/92/73 and
**over was 8/3/3/10**.

**The over-count was THREE SHAPES and all three are now fixed.** This matters more than the
numbers, because none of them was a smaller version of another:

- **Shape 1 — a nested call in argument position.** `call inner` / `push eax` / `call outer`:
  the inner call's result is pushed, so the pushes *above* the inner call belong to the outer
  one. `GetProcessHeap(8, 0x1000)` for an API that declares none. **Fixed** — see the
  `collectArgs32` gotcha in `CLAUDE.md`. Note the marker is *after* the inner call: there is no
  call between the pushes and it, so a "stop the walk at an intervening call" rule never fires.
- **Shape 2 — over-reach into the function's own callee-saved prologue pushes.** At t32 0x405f2f:
  `mov edi, edi` (hotpatch pad, i.e. the function entry) / `push edi` (a register save) /
  `push "KERNEL32.DLL"` (the only real argument) / `call GetModuleHandleW`. That was the whole
  x86 residual: 4 rows on t32 (`GetCommandLineW`, `GetLastError`, `GetModuleHandleW`,
  `SetFilePointer`) and 6 on w32 (those four plus `LoadLibraryA` twice). **Fixed** — see the
  callee-saved-save gotcha in `CLAUDE.md`. Two rules that look right and are refuted by this same
  corpus, neither of which may be re-tried: "a push of ebx/esi/edi is a save" (at t32 0x402c3f
  `push esi` *is* a genuine argument), and "a save is identifiable by *position* plus a matching
  `pop` before the `ret`" — `push imm8 / pop reg` is a pervasive MSVC size idiom, so in t32's
  `sub_401A4E` every `pop ebx`/`pop edi` is `mov reg, imm`, and the saves are often six
  instructions in, or sunk to a mid-function block leader. What works is whether the pushed value
  is the register's **entry** value, i.e. whether the push precedes the register's first write in
  the function (`peek-a-bin-6lmh`).
- **Shape 3 — a fastcall register the block had already SPENT as an address index.** The x64 path
  does not walk pushes at all: `collectArgs64` asks `RegState` which of RCX/RDX/R8/R9 the block
  wrote, which is equally true of a register the block computed for its own addressing. t64
  0x14000B34B: `imul rcx, rcx, 0x58` / `and BYTE PTR [rax+rcx*1+8], 0xfe` / `call GetLastError`,
  an API declaring none. **Fixed** — see the `collectArgs64` index gotcha in `CLAUDE.md`. Four
  rules refuted by this same corpus, none of which may be re-tried: *distance* and *dominance*
  from the write to the call (the filed hypothesis — `RegState` is per-block so the write always
  dominates, and the write is two instructions from the call at both sites); *any* read spends the
  register (t64 0x14000FAF0 spills R8 to the outgoing stack-argument area **because** it is also
  the register argument, costing `CreateFileW` two of four); and any read from inside a memory
  operand spends it (t64 0x14000BD6E `lea edx, [r9+0x8]` is MSVC computing the constant 9 from the
  1 it just put in R9, and R9 is argument four of the call two instructions later — R9 is the
  *base* there, which is why base and index are told apart) (`peek-a-bin-7r1l`).

**So the upgrade path recorded below HAS triggered and has been taken: over-count is now a gate
at 0.** No threshold was invented at any residual — it reached zero on all four binaries and the
gate is at zero. `npm run corpus` now exits 1 on an invented argument, naming each row.

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
| **over** | The call passes MORE arguments than the API takes. There is no reading of the machine on which that is right — the argument was invented. `GetLastError(rcx)`, `GetModuleHandleW("KERNEL32.DLL", edi)` (the second push is a prologue save), `SetFilePointer(…, 5 of 4)`. Every one of the 6 rows left in the corpus is provably wrong, and every one compiles clean. It was 24 before `peek-a-bin-f51x`, which retired the `GetProcessHeap(8, 0x1000)` shape — pushes that belonged to the *next* call — and 16 before `peek-a-bin-6lmh`, which retired the prologue-save shape and took the x86 half to 0. |
| **under** | The call passes FEWER. Split in two, because only one half is a recoverable defect: `underAtCeiling` is the emitted count sitting exactly at the ABI evidence's ceiling — `collectArgs64`'s four fastcall registers, `collectArgs32`'s eight-push scan — where an API declaring five or more parameters is short *by construction*; `underBelowCeiling` is an argument the evidence was there for. All 26 of t64's ceiling rows are `CreateFileW`, `WriteFile`, `MultiByteToWideChar` and friends. |

**THE OVER COUNT IS GATED AT 0 SINCE `peek-a-bin-7r1l`; UNDER IS NOT.** Every OVER row has the
character that makes `stale version-0 names` a gate — provably wrong, not a count awaiting a
threshold — and the only thing that had ever separated them was that this count was not zero: 24
corpus-wide at `e22ba6e`, 16 after `peek-a-bin-f51x`, 6 after `peek-a-bin-6lmh` took the x86 half
to 0, and 0 once `peek-a-bin-7r1l` retired the last shape. **A gate at 0 is not a threshold on an
absolute**, which was the whole of the earlier refusal: it does not move when detection does,
because a newly detected function either carries an invented argument or it does not. That is
exactly the history of the stale-read audit, and it is now this one's.

UNDER stays ungated for the reason it always was — it is not zero and no threshold on it has been
justified — so falls in it are judged where falls are judged: `compare.mjs` treats `arity
under-count` and `under below the ceiling` rising as regressions, and `arity exact` is a ratio
that must not fall. `arity over-count` rising is still reported there too; it is now caught by the
run first.

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
`compare.mjs` reports the six arity regressions and exits 1. (That control predates the gate;
`npm run corpus` would stay green over it today too, because reverting qb2x moves UNDER, not
OVER. The gate's own control is removing the one `readSinceWrite` line from `collectArgs64`, which
makes the run exit 1 and name all six pre-`7r1l` rows.) Without the arity rows that same pair
of runs moved nothing about arguments at all — the only other signal was `polarity guards audited`
falling by 2 and 3, which is an instruction to go and read some guards, not a statement about
calls.

**A register a `pop` wrote, read under its previous value** (`popReads.ts`). Reported, never
gated — *for now*, and only because the count is not zero. Every row it prints is a provably
wrong name, which gives it the character of `polarity inverted` rather than of a baseline: **gate
it at 0 the moment a fix gets it there.** `6952d53`: **7 wrong over 5 pops on t32, 6 over 4 on
w32, 0 on both x64 binaries**, plus 2/2/0/0 implicit `ret` reads and 67/63/0/0 pops lifted by
`stackIdiom.ts`'s pairing.

`liftBlock` does not lift `pop`, so it is no definition in SSA and a later read of the register
binds to the value it held *before* the pop. The audit walks forward from each `pop <reg>` over
the CFG to the first instruction that writes that register **on the machine**, and reports every
read of it in the post-fold IR on the way.

> **The write test has to be the machine's, not the IR's**, and that single choice is the
> difference between 7 rows and 54 on t32. An IR-level "first write" attributes other classes'
> defects to the pop: t32!`sub_40D99A` does `pop ecx` (cdecl argument cleanup) and then
> `mov ecx, [ebp+8]`, whose IR definition `foldBlock` inlines into its single in-block use while
> ECX is live out — so eleven reads two blocks later name an ECX nothing ever assigns, and against
> an IR test they read as the pop's fault. They are not: the popped value is dead there. The same
> choice is why the count on both x64 binaries is **0** rather than 6: every x64 row is the
> epilogue `mov rax, rbx` / `pop rbx` / `ret`, where the emitted `return rbx` names a value
> copied *before* the pop that the C never reassigns — correct output.

Two counts beside `wrong`, and both are about the cost of the obvious fix. `benign` is reads where
the paired push pushed the *same* register with nothing written in between, so the pop restores a
value the C never reassigned and emitting nothing is **correct**; refusing every pop (lifting it as
`reg = <unknown>`) would trade each one for an `__unrecovered_N`. That count is 0 in this corpus,
because an epilogue restore is followed by `ret` and not by a read — *except* for the implicit read
`ret` itself makes of the return register, which is counted separately as `retBenign` and is **1 per
x86 binary** (t32!`sub_40A925` is `push eax` / `pop eax` / `ret 4`, and its `return eax` is right
only because the pop emits nothing). `retWrong` is **2 per x86 binary**: a `return` of a value the
machine popped, named from before the pop — both of them MSVC's `memset` returning its destination
pointer, where the emitted `return eax` returns the loop counter instead.

> **The "is this pop already lifted" test is asked of the LIFT, not of the lowered program.**
> `push 0x1a / pop eax / ret` *is* lifted, copy propagation folds the constant into the `return`
> and DCE then deletes the assignment — so nothing survives at the pop's address, and a post-fold
> test called the pop unlifted and printed **four false `ret-wrong` rows per x86 binary**, each one
> a function returning a constant the emitted C states correctly.

*Validated by negative control, in both directions.* Disabling `stackIdiom.ts`'s `push <imm>` /
`pop <reg>` pairing — the half of this class that **is** fixed (`peek-a-bin-3axd`) — takes t32 from
7 to **78** wrong over 44 pops and w32 from 6 to **61** over 38, and fails the run's liveness
assertion on `popsLifted`. Lifting every unpaired `pop` as `reg = <unknown>` takes all four
binaries to **0** — which is the measured cost of that fix, not a recommendation: it moves
`unrecovered values` 106 → 166 on t32 and 87 → 146 on w32 (+229 token occurrences corpus-wide),
changes 66 functions of emitted text, loses one struct field on each x86 binary
(`offsetof` 353/353 → 352/352 and 408/408 → 407/407, ratio unmoved), destroys the one correct
`retBenign` read per binary, and leaves both x64 binaries byte-identical. Every gate stays green
over it.

**Function, instruction and jump-table counts.** These move whenever detection changes, which is
often, and usually because a defect was fixed.

## `corpus/comments.ts` — separate, and the only ARM64 coverage here

`npm run corpus` drives **t32, t64, w64, w32** and nothing else. The ARM64 half of this project
has no coverage in it at all: not one of the audits above loads `t64-arm.exe` or `w64-arm.exe`,
and `preflight.ts`'s `BinKey` does not name them. `corpus/comments.ts` is the exception, and it is
run on its own (`npm run corpus:comments`) precisely so that this run's header keeps naming the
four binaries the standing numbers are measured against.

It also audits something no gate above can see. Every gate here reads emitted C or the IR behind
it, and an inline `Instruction.comment` reaches neither — so gcc, polarity, `offsetof`, arity, the
stale-read gates and the statement-drop audit are all *structurally* blind to a comment that names
the wrong thing, while a comment is one of the few things a reader of the disassembly view takes
purely on trust.

Two questions, one per architecture, and they are not the same question:

- **ARM64: is the comment a reference or a collision?** `mapInsn`'s resolution is an x86 operand
  grammar — `resolveRipTarget`, then any `0x…` literal in the operand string that is a known
  string or IAT address. On A64 the only literals an operand carries are branch targets and `adrp`
  *page bases*, so a hit meant a coincidence rather than a reference. The audit splits today's
  comments by whether `findArm64AddressRefs` — the real A64 reference reader, and already
  `buildArm64Xrefs`' oracle — agrees. **0 coincidences on both binaries** now, from 248/248 and
  253/253 at `91085f3`, where 243 and 252 of them said the same one wrong thing because the IAT
  begins at a page boundary. Every row it can report is provably wrong, so this has a gate's
  character; it is reported rather than gated only because it is outside the gated run.
- **x86/x64: has the comment stream moved?** The same operand scan *is* sound there — an x86
  operand really can carry an absolute address — so there is nothing to judge and the audit prints
  an md5 over every commented instruction instead. That is the byte-identity instrument for any
  change to the shared `mapInsn` path: run it at both commits and the four digests must not move.

## What the standing set does NOT catch

**None of the nine gates above catches a wrong-value defect** — a statement that is emitted, is
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

**The OVER-count gate inherits every one of these.** A gate at 0 says no *declared* API is passed
an argument the machine did not; it says nothing about the callees below. Two of the three
`peek-a-bin-7r1l` fixes landed on `sub_` callees (`sub_140007808` and `sub_140007908` on t64, the
same shape on w64) and moved no number in this audit at all — they were adjudicated against
`objdump`, which is the only instrument that can see them.

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
- **Only a phi-operand read that a statement also makes.** Reads come from the post-`ssaOptimize`
  statement lists, so a version read *only* as a phi operand is not in the read set at all — unlike
  `splitStaleReads`, which does treat one as a read (`PHI_OPERAND_INDEX`).
- **A name collision the SSA is right about.** An identifier read but never assigned, while a
  sibling alias of the same register *is* assigned, is a spelling defect with correct SSA
  underneath, and no value-level test can see it. A crude positional scan of the emitted text is
  the only instrument here, it admits false positives (a legitimately-unassigned entry value looks
  identical), and it is an upper bound rather than a count.

### Two things the site set and the verdict had to be taught, and why

Both were found together and each hid the other (`peek-a-bin-fppy`, `peek-a-bin-pzws`). Neither is
a subtlety of the audit's *subject*; both were the audit describing a program nobody emits.

**A phi's definition lands in its predecessors, not in its own block.** The site filter builds
`defBlocks` from the SSA, where a phi is a definition of the block holding it — but `destroySSA`
puts the copy at the end of each *predecessor*, and a predecessor routinely dominates blocks the
phi block does not. Where the only dominating writer was a relocated phi copy the site was
discarded before it was ever judged. Noting the phi at each operand's block as well is sound
because it only widens which reads get *examined*; the verdict is still taken against the
post-lowering statements. Measured at `82ed61e`: sites 28/159/158/28 → **33/182/181/34**, and the
gate went red at **12** over correct-looking output.

**The `writes` test asks about the identifier, not the canonical register.** What this audit judges
is emitted C, and C's unit of identity is the name: `r9` and `r9d` are unrelated variables there —
which is exactly why `cc -fsyntax-only` is blind to this family, and it cuts both ways. A register
carrying a 64-bit and a 32-bit live range at once is *correctly* emitted as two names, and against
a canonical test that correct output reads as a clobber that never happens. One emit rule has to be
honoured or the name test would narrow: `registerText` re-ties a read of width <= 2 to a wider
assigned alias, so for those a dominating write of any wider alias is a real clobber.

That test was checked rather than argued, both ways, pinned to `82ed61e`:

| | canonical `writes` | name-level `writes` |
|---|---|---|
| before per-live-range naming | 12 | **12** |
| after per-live-range naming | 12 | **0** |

Neither change alone is sufficient, and the name test provably hides nothing — with the naming fix
reverted it still reports every one of the twelve rows.

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
| `sweep.ts` | One load + decompile pass per binary; polarity, loop exits, callee loss, line map coverage, statement drops, unrecovered values, clobbered reads. |
| `emitAudits.ts` | The audits that read only emitted text: gcc, `offsetof`, gotos. |
| `arity.ts` | Emitted call arity against `apitypes.ts`'s declared signatures. Reads only emitted text; the one oracle here that can see arity. |
| `staleGuards.ts` | The wrong-operand guard audit: which instruction's flags a jcc reads, and whether the compare still describes them. |
| `popReads.ts` | A register a `pop` wrote, read in the emitted C under its previous value. Machine-level write test — see the baseline entry. |
| `lostDefs.ts` | A read whose reaching definition `foldBlock` deleted. Brackets that one pass; see the gate entry. |
| `armExits.ts` | How every switch arm was closed, and whether `break` was true of the block. Reads the tap's observations; recomputes nothing. |
| `wildBranches.ts` | A filed direct branch whose target the image does not contain. Reads the instruction stream and the PE header; nothing else. |
| `compare.mjs` | Base-vs-change diff over two artifact directories. Plain node. |
| `artifacts/<label>/jumpTables_<key>.json` | The recovered tables, as the cross-substitution input. |
| `artifacts/<label>/drops_<key>.jsonl` | Every dropped statement, per site. Empty file = audit ran and found none. |
| `artifacts/<label>/unrecovered_<key>.jsonl` | Every `__unrecovered_N`, per site: note, cause, use site, originating jcc where one could be named. |
| `artifacts/<label>/arity_<key>.jsonl` | Every declared-API call whose emitted arity is not the declared one, OVER rows first. Empty file = audit ran and found none. |
| `artifacts/<label>/stalev0_<key>.jsonl` | Every version-0 read left naming an overwritten register, then every spoiled entry-value copy. Empty file = audit ran and found none. |
| `artifacts/<label>/staleguards_<key>.jsonl` | Every block whose trailing jcc reads flags the recovered compare does not describe, with the emitted condition where one reached the page. Empty file = audit ran and found none. |
| `artifacts/<label>/lostdefs_<key>.jsonl` | Every (block, register) whose reaching definition the fold removed. Empty file = audit ran and found none. |
| `artifacts/<label>/armexits_<key>.jsonl` | Every switch arm closed with `break` while its own block has a successor, with that block's successors and which refusal produced the `break`. Empty file = audit ran and found none. |
| `artifacts/<label>/wildbranches_<key>.jsonl` | Every filed direct branch aimed outside the image, with its `source`. Empty file = audit ran and found none. |
| `artifacts/<label>/popreads_<key>.jsonl` | Every read of a register a `pop` wrote that the emitted C names under its previous value, with the paired push. Empty file = audit ran and found none. |
| `artifacts/` | Generated. Gitignored. |

### The audits that re-run the pipeline prefix, and why they have to

`staleReads.ts`, `popReads.ts` and `lostDefs.ts` each drive their own `buildCFG → liftBlock →
buildSSA → ssaOptimize → destroySSA → foldBlock`, and they are the only three places in this
directory that do.
That is exactly the second copy the tap below exists to avoid, and it is accepted here for a
reason the tap cannot serve: both questions need the SSA **before** it is lowered and the
statement list **after**, and there is no single point in `pipeline.ts` at which one observer sees
both. `popReads.ts` needs a third thing on top — the machine instruction at each read, to ask
whether the register is read *there* rather than named by a value propagated from earlier.
`lostDefs.ts` needs the statement lists on the two sides of `foldBlock` specifically, which is one
pass narrower than the tap can see. Every pass they call is the repo's own export, in
`pipeline.ts`'s order, so a stage inserted between `ssaOptimize` and `destroySSA` shows up as a
divergence — but nothing enforces that automatically. If you insert one, update **all three**
replicas.

**`foldBlock`'s `liveOut` argument is part of the same hazard and is the newest instance of it.**
All three replicas must pass `blockLiveOut`'s answer, exactly as `pipeline.ts` does: without it the
fold deletes definitions that escape their block, so the replica measures a program nobody emits —
and in `lostDefs.ts`'s case it would report its own missing argument as a decompiler defect
(`peek-a-bin-7eyn`).

**The `liftBlock` arguments are part of that, and one of them has already been missed.** The
replica must be handed everything the pipeline lifts with, including `calleeSavedFirstWrite` and
`calleeClobbers`; the second was added to `pipeline.ts` and not to the replica, which would have
left the stale-version-0 gate measuring the pre-summary lift while the sweep beside it measured the
post-summary one. `calleeClobbers` in particular decides which registers a call destroys, which is
the very subject of that audit. Nothing catches this: both sides typecheck, and the audit reports a
confident number about a program the pipeline does not build.

### The one thing these audits need from `src/`

`decompileFunction` takes an optional `tap` argument — its second-to-last, since
`calleeClobbers` was appended after it in `df50c3f`; a call site passing only `tap` therefore
reads `…, runtimeFunctions, tap)` while one passing both ends `…, tap, calleeClobbers)`, and the
worker's passes `undefined` in the `tap` slot. `corpus/sweep.ts` is `tap`'s only caller. It fires once, between `structureCFG` being handed the
lifted blocks and its result being passed on, and hands both sides over.

**It now carries a second observation, and that was a deliberate choice not to build a second
mechanism.** `StructuringTap.armExits` is how `structureSwitch` reports the closure it chose for
each switch arm, which `structureCFG` collects through an observer `pipeline.ts` wires on exactly
the same condition as the tap itself — so a production run pays one `undefined` check per arm and
can notice nothing else. Adding it to the existing hook rather than beside it is the point: two
ways to watch one function drift about *when* they fire, and this observation has to be taken at
the same moment as the statement snapshot to be about the same program.

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
