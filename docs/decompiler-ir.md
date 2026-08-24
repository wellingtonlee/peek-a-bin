# Decompiler IR and pipeline — the long-form record

**This is the detail behind `CLAUDE.md`'s Decompiler Architecture summary**: the pipeline order and
what each stage may assume, the `IRExpr`/`IRStmt` dispatch census with the file-by-file tables of
every switch that must be updated when a kind is added, the flag-model and `branch` decisions, and
the type/API/struct-synthesis rules.

The dispatch tables are the part to come back to: adding a union member means updating dozens of
switches, only nine of which the compiler catches. Run the throwaway-kind probe described below
rather than trusting a count.

**Pipeline** (`pipeline.ts`): `buildCFG → liftBlock → liftCrossBlockPops → buildSSA → ssaOptimize → destroySSA → foldBlock → structureCFG → cleanupStructured → wrapExceptionRegions → inferTypes → promoteVars → synthesizeStructs → emitFunction`

(`wrapExceptionRegions` is local to `pipeline.ts` and only runs when `.pdata` exception info is
present. The docstring at the top of `pipeline.ts` lists a shorter, outdated order — trust the
code, not that comment.)

**IR** (`ir.ts`): `IRExpr` union (12 kinds: const, reg, var, binary, unary, deref, call, cast, ternary, field_access, array_access, unknown) + `IRStmt` union (18 kinds including if/while/do_while/for/switch/break/continue/phi/try/**branch**).

**`branch` is confined to `liftedBlocks` and never appears in a structured tree — but its *condition* does, and `structureCFG` now takes it as a sixth argument.** `liftBlock` turns a block's trailing conditional jump into an `IRBranch` so its condition is a real IR reader — an SSA version, a reaching definition, a place in every use count — and `pipeline.ts` step 4b lifts every one of them out of `liftedBlocks` into a `Map<blockId, IRBranch>` *before* `structureCFG`, which `extractCondition` prefers over re-parsing `insn.opStr`. Two orderings are load-bearing and neither is obvious:

- The extraction runs **before the tap snapshot**, or the statement-drop audit reports every branch as a dropped statement in each block ending in a conditional jump.
- The branches must not survive into the tree: `detectForLoop` skips any body block whose last statement is not an `assign`, so one left in place takes **for-loop recognition to zero corpus-wide**, silently and with no failing test.

`structureCFG` has a **seventh** parameter after that, and it is a different kind of thing: an optional observer told how `structureSwitch` closed each switch arm, which `pipeline.ts` wires only when it has a tap of its own. It is an instrument reading the structurer rather than evidence the structurer reads, it must never be able to change what the other six decide, and `corpus/armExits.ts` gates its reports at 0 (see the Verification section).

`emit.ts` therefore *throws* on a branch rather than ignoring it — `decompileFunction`'s catch turns that into a counted `throws`, which `compare.mjs` gates on, where a silent arm would make a structural failure invisible. Anything that appends to the end of another block's statement list must go through **`pushBeforeTerminator`** (`ir.ts`): `destroySSA` lowering a phi into a predecessor and `loopInvariantCodeMotion` hoisting into a preheader both did a plain `push`, which was correct only while no terminator existed in the IR.

**Three things about the flip are judgements, not details, and reversing any of them silently breaks something no gate reports** (`peek-a-bin-c33`):

- **`foldBlock` counts a guard's reads but never inlines into a branch**, and — separately — never inlines a definition that escapes its block at all (see the `blockLiveOut` gotcha). Counting is what stops a definition two statements read from being folded into one and leaving the other naming nothing. Inlining *into* the guard is the opposite: it deletes the assignment and rewrites the condition, and both halves do damage — the register is frequently live out of the block (a loop counter always is), and `structureCFG` matches loop shapes on the statement a body block ends with, so `inc eax / cmp eax, 5 / jl` became `while (eax + 1 < 5)` with the increment gone. Measured before the refusal existed: 8 structuring tests changed shape. With it, corpus loop shapes are **identical** — for 3/5/5/3, while 114/107/100/101, do/while 78/77/76/77 on t32/t64/w64/w32, as those stood when the refusal was measured. (`for` is 6/6/6/6 and `while` 111/106/99/98 at HEAD; what this bullet claims is that the refusal moved none of them, not that these are current.)
- **`extractCondition`'s two refusals are asked of the condition read off the *instructions*, never of the IR one.** Both are questions about the machine. Asking `conditionSpoiled` of the IR condition defeats it outright: `cmp eax, 5 / mov eax, edx / je` has its guard rebound to EDX by copy propagation, so the overwritten register is no longer in the expression and the scan finds nothing to object to, while the emitted test is still one the machine does not make (`peek-a-bin-xe01`).
- **Which instruction a Jcc's flags belong to is `flagModel.ts`'s answer, and `lifter.ts`'s `branchFor` is the only place that asks.** It calls `blockFlagOwner` at the trailing jump and refuses four ways, each of which is a case where an answer would be a guess: a jump that reads no flags at all (`jmp`, `jecxz`/`jrcxz`/`jcxz`); an indirect or unresolved target; a **result** owner (or, since `peek-a-bin-frt8`, a **bittest** owner) in a block that also contains a `cmp`/`test`; and a result whose **destination** no longer holds it (`canSpellCondition`). The third is the one that is a policy rather than a fact — `cmp eax, 5 / sub ecx, edx / jne` really does branch on `ecx != 0`, but it is also the shape `corpus/staleGuards.ts` counts as a *superseded* reading, and that gate reads **any** condition emitted at such a jcc as the stale one. Recovering it is a decision to be taken together with the audit, not a side effect of the wiring. A **compare** owner is deliberately *not* filtered on `spoiled`: the guard's reads are what hold the compared values alive through DCE, and the same veto is applied against the machine text in `structure.ts`, which is the only place it can be asked (see the second bullet). A **bittest** owner — `bt <reg>, <imm>` — takes the third refusal for exactly the third's reason and needs no form test of its own, since `parseBitTest` admits only the forms that can be named.

`liftBlock` also clears `RegState`'s flag state on any instruction that is neither `isFlagTransparent` nor a modelled setter, which keeps `setcc`/`cmovcc` reading their own instruction's state. That is a *different* question from ownership and the two are deliberately not merged: the SSE `comis*` forms set flags `setcc` reads, and `flagModel` classes them as a clobber, so a `comis` leaves `setcc` working and produces no branch.

**A compare emits no statement at all, and the `eflags = …` proxy it used to emit was actively harmful** (`peek-a-bin-c33` stage 2b). The proxy existed because a guard was not an IR reader: nothing else named the compared registers, so DCE deleted the instructions producing them, `ssaopt.ts` had to hold the proxy live by hand, and it then had to be stripped again after the fixpoint so it did not reach the page. But `eflags = ecx - edx` is an ordinary IR expression, so **GVN gave it and a real `sub eax, edx` the same value number**, copy propagation rewrote the readers of EAX to name `eflags`, and the strip deleted the only assignment — leaving C that returns a register nothing assigns, with the subtraction the machine performs absent entirely. **20 such reads across 14 functions of the four corpus binaries at `f685b6d`, now 0**; minimal reproduction pinned in `pipeline.test.ts` ("does not rewrite a real value into the flag proxy and then delete it"), negative-controlled against that commit.

**`ssaopt.ts` no longer holds any flag definition live by hand, and `flagResult.ts` is gone** (`peek-a-bin-c33` stage 4, closing `peek-a-bin-wf7t`). Two loops of `protectedFlagDefs` — one for the `eflags` def of a Jcc block (`peek-a-bin-ua8`), one re-deriving an arithmetic setter from the instruction stream via `flagResultSetter` (`peek-a-bin-pu06`) — plus the post-fixpoint `eflags` strip, `conditionFromFlagResult`, `RESULT_ANSWERABLE_JCC` and the backward walk all deleted together. Every one of them existed to stand in for a use DCE could not see; the `branch` arm of `countStmtUses` *is* that use. **Deleting them is output-neutral: byte-identical emitted C on all 1127 functions of all four binaries, `compare.mjs` `CHANGED 0`, verdict "no regression".** That byte-identity is the proof the hand-holding was redundant, and it was taken as its own measured step for exactly that reason. Measured first: with the scaffolding still in place, `conditionFromFlagResult` was instrumented over the whole corpus and fired **0 times**. `flagResult.ts`'s two survivors — `isFlagTransparent` and `clobberedAfter` — now live at the bottom of `flagModel.ts`, so there is **one** copy of the x86 flag grammar; `flagModel.test.ts`'s drift guard was inverted to fail on a *second* declaration appearing anywhere under `src/disasm/decompile` or `corpus`.

**Two of the defects `peek-a-bin-c33`'s forward flag model was expected to fix as a side effect were fixed without it** (`peek-a-bin-jitf`, `peek-a-bin-xe01`), by two local refusals in `extractCondition` sharing the flag tables (then in `flagResult.ts`, now in `flagModel.ts`). That removes them from c33's justification and from what its Stage 3a has to demonstrate, and it means the **58 wrong-operand guards are already gone from the baseline** any future c33 measurement is taken against — so a c33 run that shows no movement there is agreeing with the current tree, not failing. It did not touch c33's own case, and c33 has since landed on the structural argument alone — see the `branch` paragraphs above and the flip's measurement below. The two refusals survive the flip unchanged and are still asked of the instruction stream; the wrong-operand gate is still 0 named. **`peek-a-bin-xskz` then made the refusals conditional** — they stand unless the lifter materialised the compared values at the compare — so the 58 are no longer an admitted gap but a recovered guard; see the `spoiledCompareCapture` gotcha.

**`ssadestroy.ts`'s `mapReads` has a `branch` arm, and it landed in the same change as the `extractCondition` flip — deliberately, not incidentally.** A guard's registers are reads, so `splitStaleReads` both sees and repairs one; before the arm existed there were ~300 stale, unrepairable reads per binary. Adding it *earlier* was measured and reverted: while step 4b discarded the conditions it cost **+116 emitted lines across 96 functions** in dead repair copies for no recovered value, and none of those reads is version 0, so the stale-read gate stayed green through every one (`peek-a-bin-c33`). Landed together, the repairs are 192 of the 770 guards whose text moved and the whole corpus grows by 238 lines (+0.4%).

### Adding new IRExpr / IRStmt kinds

Adding a kind means updating every switch that dispatches on `expr.kind` / `stmt.kind` — there
are **56** of them (53 switches and 3 if-chains) — measured over the AST at `488ddde` under the
rule stated below — and a missed one silently drops data rather than failing. **The figure this
replaces, 64 (44 switches and 20 if-chains), was a hand count under an unrecorded definition and
is not comparable**: the switch half rose 44 → 53 and the chain half fell 20 → 3, which is two
different rules rather than movement in the tree. The tables below are accurate about every site they name but do **not** name them
all — roughly 30 are missing, so grep as well as reading. They split into two
groups:

**That 56 counts `IRExpr` and `IRStmt` sites together (25 switch + 2 chain, and 28 switch + 1 chain). For
`IRStmt` the number has now been taken over the AST instead, and the rule matters more than the
figure**, because a hand count has been corrected twice and the two rules do not agree.

The rule: resolve, with the TypeScript checker, every read of a `.kind` property whose object's
type is `IRStmt` or a narrowing of it — matching on the *declared interface names*
(`IRAssign`…`IRBranch`), never on kind strings, or `DisplayRow` (whose kinds include `"label"`)
and every other tagged union in the tree join the count. Then classify: a `switch`, or an
`if`/`else if` chain with **two or more** arms testing the kind, is a **dispatch**; a lone `if`,
ternary or boolean test is a **narrowing predicate**. Over `src/` and `corpus/` excluding
`__tests__`, at `f685b6d` + `peek-a-bin-c33` stages 2b and 4:

| | dispatches | predicates | dispatch units + predicate reads |
|---|---|---|---|
| `f685b6d` | 26 (23 switch + 3 if-chain) | 117 | 143 |
| after stage 4 | **24** (23 switch + 1 if-chain) | 113 | **137** |
| `488ddde` | **29** (28 switch + 1 if-chain) | 176 | **205** |

**The third column is NOT a count of kind-reads and was mislabelled as one.** It adds dispatch
*units* to predicate *reads*, but a switch is one read and a two-arm chain is two, so the literal
read count at the stage-4 row is 138 rather than 137; raw `IRStmt` kind-reads at `488ddde` are
**206**. **And the PREDICATE half of the two older rows does not reproduce from the rule stated
above** — re-running that rule against `f685b6d` itself gives 145 where the row says 117, a gap of
28 that narrowing, optional chaining and test exclusion do not account for. Some filter was applied
and not written down, so treat the dispatch column as the reproducible one; it re-derives exactly
(26 = 23 + 3 at `f685b6d`).

The two dispatches that went are `ssaopt.ts`'s `protectedFlagDefs` arithmetic loop and
`structure.ts`'s `conditionFromFlagResult`. Test files add 15 more reads. Files are exactly
`src/disasm/decompile/{ir,ssa,ssaopt,ssadestroy,fold,cfgpatterns,structure,cleanup,typeInfer,promote,structs,emit,pipeline}.ts`
plus `corpus/{sweep,staleReads,lostDefs,popReads}.ts` — the last two each hold one `IRStmt` switch
and joined after the stamp above. Nothing else under `src/` dispatches on `IRStmt` at all.
**Do not compare 137 with the 88 this paragraph used to claim**: that was a different rule, taken
by hand, and nobody wrote down which reads it admitted. **9 are compiler-caught; the rest are
silent** — unchanged by stage 4, and still the number the probe below reports.

That 9 is *measured*, not counted by reading: add a throwaway `IRStmt` kind to the union, run
`npm run typecheck`, count the `not assignable to type 'never'` errors. Re-run at `586a9f9` it
reports exactly 9 — `ssa.ts:renameStmt`, `ssadestroy.ts:stripVersionsStmt`, `emit.ts`'s **four**
(`emitStmt`, `liveInStmt`, `collectAssignedRegs` and, since `peek-a-bin-x54q`,
`collectCapturedOperands`), `corpus/sweep.ts`, and `ir.ts`'s `bodiesOf` and `rewriteBodies`. **This paragraph previously also claimed 8 while `ir.ts`'s two did not exist**,
because it credited `ssadestroy.ts:mapRegs` and `fold.ts:hasSideEffects` — both of which are
`IRExpr` switches and catch nothing about a statement kind. Use the probe rather than the table
if the number matters.

Two beyond the tables below are worth knowing about because
no table lists them and they are not dispatches at all: `cfgpatterns.ts`'s `detectForLoop` reads
`stmts[len-1].kind !== "assign"` and `cleanup.ts`'s `endsWithTerminator` reads the last statement's
kind — both are *predicates over a block's final statement*, so a new terminator-shaped kind changes
loop shape rather than dropping data, which is the defect class no audit here models.

**The compiler catches these.** Fourteen switches in the scope of this table end in a
`const _exhaustive: never = …` binding (repo-wide there are 17; the other three are
`workers/metricsDispatch.ts`, `hooks/asyncMetricState.ts` and `corpus/sweep.ts`),
so adding a union member breaks the build until they are handled. Just run `npm run typecheck`:

| File | Functions |
|------|-----------|
| `ir.ts` | `bodiesOf` / `rewriteBodies` — the **only** declaration of the structured-tree body traversal, and the reason these two are in this table rather than the `default:` one below. See the entry under **Gotchas** |
| `ssa.ts` | `renameExpr` / `renameStmt` (inside `renameVariables`) |
| `ssadestroy.ts` | `mapRegs`, `stripVersionsExpr` / `stripVersionsStmt` |
| `emit.ts` | `emitExpr` / `emitStmt`, plus `liveInStmt` and `collectAssignedRegs` — the backward liveness and the assigned-register set behind a call's result assignment. Those are full `IRStmt` switches, and so is `collectCapturedOperands`, so a new statement kind breaks the build in **four** places in this file — `emitStmt`, `liveInStmt`, `collectAssignedRegs` and `collectCapturedOperands`; `emitExpr` is an `IRExpr` switch and is not one of them |
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

**Struct synthesis** (`structs.ts`): `StructRegistry` is cross-function state shared in the worker. `decomposeAddress()` breaks `base + idx*scale + offset` patterns, including a top-level `base - const` (folded to a negative offset; subtracting a *register* is not an offset and still returns null). 2+ distinct offsets on same base → struct candidate. A "base" is a canonical register **plus the generation of the value it holds** (`baseGenerations` / `accessKey`) — see the gotcha; the register alone is not an object. A `label` takes the join of the states its own `goto`s and its fall-through carry, at a fixpoint, and resets every key only when no `goto` names it.

Scale ∈ {1,2,4,8} → `IRArrayAccess`, whether or not the function has a struct candidate. A function with no candidate but an indexed access takes a rewrite-only path; one with neither is returned by identity.

**Escaping struct defs are snapshots; registry-internal ones are live.** `synthesizeStructs` clones into `IRFunction.typedefs` (`cloneStructDef`), so an already-returned declaration cannot change when an unrelated function is decompiled later. Inside the registry the objects stay shared and the inference passes still mutate `field.type` in place — that **is** the cross-function type-refinement mechanism. So do **not** clone in `findOrCreate` or `get`: it disables refinement silently, with no test failing. Field *types* are always replaced wholesale rather than mutated, so a shallow field copy is sufficient.

**Merging is shape-based but guarded.** An exact `offset:size` fingerprint match merges unconditionally. The subset path additionally requires the smaller shape to have **3+ fields** (`MIN_SUBSET_MERGE_FIELDS`) and the merged layout to be free of overlapping extents (`hasBoundaryConflict`). Two distinct offsets is the *minimum* a candidate can have, so two-field shapes are simultaneously the most common and the weakest evidence — `{0:8, 8:8}` describes a large fraction of all structs. The cost is real and deliberate: a two-field partial view of a struct no longer completes from another function's larger view. Failing to merge is the benign direction — two `struct_N` declarations instead of one wrongly shared.

**Provenance beats shape, and recovers that cost.** Two bases occupying the same parameter slot are the same object by construction, so `findOrCreateLinked` merges on that evidence and deliberately ignores `MIN_SUBSET_MERGE_FIELDS` — a two-field view of a parameter *does* complete from a caller's fuller view. It still cannot override `hasBoundaryConflict`: contradictory layouts mean one reading is wrong. Two maps are kept apart on purpose — `paramLinks` (what a *caller* passed in) and `paramViews` (the *callee's* own reading) — so a merge always has the callee's corroboration and a passthrough `void*` helper never links its unrelated callers. Identity is published in both directions, so caller-then-callee and callee-then-caller agree.

**A field's NAME is the other half of its array claim, and `fieldNameFor` is the only declaration of the rule.** `candidateFields` decides `isArray` and the identifier together, and `emit.ts`'s `declareField` then reads *only* the flag when it spells `[...]` — so a second place that changes `isArray` without re-deriving the name produces a declaration contradicting itself. That is what `mergeFields` did: promoting a field to an array on a later function's indexed access at the same offset is the cross-function refinement mechanism working, and is right, but it kept the name the field was created with and emitted `uint64_t field_0x8[];` (`peek-a-bin-tm29`). The name is now re-derived from the offset rather than adopted from the incoming field, so the two spellings cannot come apart — the offsets are equal by the lookup that found the field. **Anything else that sets `isArray` must go through `fieldNameFor`**, and the reverse move is refused: renaming on every merge, rather than on the promotion, reaches the gate's 0 by spelling every member `array_` and is the same defect pointing the other way (pinned in `structs.test.ts`).

**The cost is that a field name is no longer stable across a merge, and that is the reason this was filed rather than folded into `peek-a-bin-u3v`.** It is bounded by the snapshot rule above: `cloneStructDef` copies each field object, so a function already returned keeps `field_0x8` in both its declaration and its accesses, and the rewrite in step 4f runs after every merge for the function being decompiled, so that one gets `array_0x8` in both. Each emitted function is therefore internally consistent and only *two functions* can now disagree about the member's name — where before they disagreed about its type (`uint32_t field_0x8;` against `uint32_t field_0x8[1];`), which is the same divergence spelled less honestly. Nothing keys on the `field_` prefix: `structs.ts`' parameter provenance matches `^arg_(\d+)$` on a *parameter* name, `emit.ts` matches a field by `field.name === expr.fieldName` out of the one snapshot, and `corpus/emitAudits.ts`' `defsIn` — the only place a field name is parsed for meaning — already read `(?:field|array)_0x[0-9A-F]+` and took the offset from the hex suffix, so the `offsetof` denominator is untouched (measured: fields **and** distinct definitions unmoved at 346/301/303/354 and 55/54/53/59, ratio 1.00).

Both merge directions scan `fingerprintIndex` in insertion order and take the first match, so *which* struct absorbs which is still order-dependent.

**A base's own OVERLAPPING readings are settled twice over, both times by discarding a directly observed access, and neither discard leaves a trace in the emitted C.** `candidateFields` first collapses two accesses at one offset into one field of the **wider** width (deliberate — the width is a direct measurement of one instruction, `peek-a-bin-hyv`), then drops any surviving extent that overlaps one already kept at a **lower offset**. So the declaration shows the winner and never says that there was a choice, what the alternative was, or that a narrower reading of the same offset was seen. `corpus/structOverlaps.ts` is the only instrument that can see it — `offsetof` compiles and runs the layout, which proves it *self-consistent* and can never see a wrong identity; `memberNameAgreement` sees a name disagreeing with its own brackets; gcc compiles any layout. Measured at `f3b89ec`, and the population is smaller and stranger than `peek-a-bin-k6hh` recorded:

- **12 overlaps over 1231 bases (3 per binary), 6 contained and 6 PARTIAL, 8 reaching a declaration.** The bead's "all nine are a narrow access sitting inside a wider one" is **false** — half are partial overlaps, and its own example list includes `{0:4}` vs `{0x3:4}`, two equal-width readings that overlap rather than nest. Anyone quoting nine is quoting a count taken before w32 joined the corpus *and* mis-describing half of it.
- **First-by-offset is a maximum-cardinality selection at all 10 groups, so the bead's proposed policy — prefer the decomposition that yields more fields — is a measured NO-OP.** Computed by exhaustive search over the extents, it yields the identical field *set*, not merely the same count. At 7 of the 10 groups the maximum is non-unique, and at every one of those the rival selection is the *narrower or later* reading, i.e. strictly less measurement. The mirror-image shape the bead predicts would be got wrong — an 8-byte access at 0 alongside a 4-byte one at 4 — **does not occur here at all**.
- **A maximal selection can still be the wrong reading, and four of the twelve are.** t32 `sub_40667A` / w32 `sub_406037` (`field_0x1F`) and t64 `sub_140006FA8` / w64 `sub_140006AC4` (`field_0x2F`) are MSVC's `_ioinit`, read against `objdump -d -M intel` and the CRT `ioinfo` layout: the object has a one-byte `textmode`/`unicode` bitfield followed by `char pipech2[2]`, and the emitted `uint16_t field_0x1F` spans one byte of each while `field_0x21` is the array's *second element* declared as a member of its own. The correct pair is **fully present in the accesses** — `and byte ptr [eax+0x1f], 0x80` and `mov word ptr [eax+0x20], 0xa0a` — and was lost at the **same-offset width step**, one pass before the overlap rule ever ran. So the defect in this class is real and the overlap tie-break is innocent of it.
- **Every one of the 10 groups is a base the grouping should not have formed.** `exprKey` keys a register base on `canonReg(name)` — version-blind and program-point-blind — so t32 `sub_40667A`'s `reg:rax` merges the `_ioinit` element pointer (`eax` = ioinfo + 5, hence the shifted origin and the negative offsets `isFieldOffset` refuses) with a read through `StartupInfo.lpReserved2`; `struct_26` is a fiction either way, and the row where the offset-order winner IS wrong and the loser IS a real field (`{0x0:4}` kept over `{0x3:4}`, the genuine `lockinitflag`) is a symptom of that, not of the tie-break — no policy over the extents could separate two 4-byte readings that give the same cardinality. The same function's *correctly* based reading of the same object is emitted beside it as `struct_6` / `struct_4`, with three right fields.

So the order-dependence is real, live at 7 of 10 bases, and **changes the answer at exactly one row per 32-bit binary — where both answers describe an object that does not exist.** `peek-a-bin-k6hh` closes as adjudicated-not-a-defect; the two live defects it uncovered are the same-offset width rule and the version-blind base key, and neither is a tie-break question.

**One register is not one object: a base is keyed on the *value* it holds, not on its
name.** `exprKey` answered `reg:${canonReg(name)}` for a register base — version-blind and
program-point-blind — so every access through any dynamic value one register held anywhere in the
function grouped as one object. `t32!sub_40667A` (MSVC `_ioinit`) emitted a `struct_26` whose
`field_0x0` is `*(DWORD*)StartupInfo.lpReserved2` and whose `field_0x1F`/`field_0x33` are `ioinfo`
members read through a `__pioinfo` element pointer, three full redefinitions of EAX apart — and
the fabricated `field_0x0` *displaced* the real `[eax+3]` access, which the overlap rule then
dropped. `baseGenerations` (`structs.ts`) is the fix: a generation number per `reg`/`var` node
standing in for the SSA version `destroySSA` collapsed away, and `accessKey` is
`canonBase(expr) + "#" + generation`. Seven things (`peek-a-bin-z8q7`):

- **It cannot invent an object, and that is a property rather than a measurement.** The scoped key
  *determines* the unscoped one, so the grouping is a partition **refinement** of the old one: two
  accesses grouped apart before cannot be brought together. What it can do is split a group below
  the two-field minimum, which is the cost, and the *registry* re-unifies the honest shapes where
  they agree — `findOrCreate`'s fingerprint match is what turns two generations of one type back
  into one declaration.
- **`canonBase` stays register-level and three passes keep asking it.** `stackDerivedBases`,
  `paramIndexByBase` and `collectCallArgSlots` ask which *register* is a frame pointer or a
  parameter, which is a fact about the name and not about a value it held; each group therefore
  carries `regKey` beside its scoped key. Everything on the *access* side — `rewriteStmts`,
  `inferFieldTypesFromUsage`, `linkNestedStructFields`, `fieldAtAddress` — takes `accessKey`, and
  it reaches them with no signature change because every one of them already called the resolver
  on `decomp.base`, a node the walk annotates.
- **Generations are tracked per NAME and handed over per OBJECT.** `cur` is keyed on the raw
  `exprKey` while the grouping is keyed on the alias-resolved one, because `buildAliasMap` folds
  `rcx_0` (a `splitStaleReads` repair variable) onto `reg:rcx` — correctly, they denote the same
  object at the copy — but a later `rcx = *(rcx_0 + 8)` redefines only RCX. Tracking the generation
  on the *folded* key made every read of `rcx_0` take RCX's newest generation and cost
  `t64!sub_14000CB64` a four-offset object outright, along with its share of the 87-field
  `_locale_t`-ish declaration (emitted in 4 functions → 1 → 3 as this was fixed). So a folded copy
  hands its source's generation over rather than minting one, and the two names then move apart.
  Worth **+64 field accesses** corpus-wide (1807 → 1871).
- **A merge point mints a fresh generation for every key an arm assigned** — an SSA phi by another
  name — and **a `label` is resolved from its own incoming edges**, which is the one place this walk
  reaches a fixpoint. It used to mint one for every key in flight, on the grounds that a jump target
  is reached from somewhere tree order does not model; that was sound and cost **109 field accesses**
  (1871 → 1980 with it dropped), and it is now `peek-a-bin-slkh` — see the gotcha below for the rule,
  the three refusals that make it sound, and why **deleting the reset outright is the wrong answer
  even though it scores higher**.
- **A stride walk must keep grouping, and that is what the loop-header phi buys.** `eax += 0x40`
  through an array of `ioinfo` is a redefinition, but the accesses are at the loop *head*, so they
  read the header phi — one generation for every element. A key sharp enough to separate them by
  iteration recovers nothing from any array-of-struct walk, which is most of what this pass is for;
  `structs.test.ts` pins that direction and an over-sharp control (one generation per read) fails 54
  tests.
- **`raw` does not reset, and it is the one stated hole.** An unlifted instruction's register writes
  are not modelled anywhere in this IR (`fold.ts`'s `blockLiveOut` reads a `raw` as reading nothing),
  so a base redefined by one still groups across it. Resetting on every `raw` was refused because
  `t32!sub_40667A`'s own correct `ioinfo` recovery sits either side of a
  `/* unlifted: sbb eax, eax */`.

- **A construct's ARMS are visited in isolation, and the regression that blocked doing so was a
  `call_stmt` that never minted — not the join's key set.** `baseGenerations` visited an `if` as
  `visit(thenBody); visit(elseBody); join(...)` over ONE mutable `cur`, so the else arm started from
  whatever the then arm left behind: a precision loss (a label's reset inside one arm leaks into the
  other) and a **fabrication** hazard of `peek-a-bin-z8q7`'s own class, one construct in. Isolating
  the arms naively produces **1 `structOverlaps` row per binary** where the shipping tree has 0, and
  `peek-a-bin-9fp5` recorded the cause as `join` minting only for keys an arm ASSIGNS and not for
  keys a label inside an arm RESET. **That prescription was implemented and the regression survives
  it** (1964 and still 1 row per binary), so the filed diagnosis is refuted. Six things:
  - **The real cause is that a `call_stmt`'s `resultDest` never minted a generation.** In
    `t32!sub_40DD37` the else arm opens with `call_stmt@40dd72` (`eax = sub_401EB8(...)`), so
    `[eax+2]` at 0x40dd8c kept the token `assign@40dd3f` gave it and grouped with `[eax]` at
    0x40dd65 — two objects, one base. The shared `cur` was **masking** it, because the then arm's
    `eax = 0xFFFFFFFF` happened to stand between the two readings. **No join rule can reach it**: the
    bad read is *inside* an arm, not at the merge.
  - **Both halves are needed and neither suffices.** Isolation alone is 1966 with 1 row per binary;
    call minting alone is 1918 with 0 rows; together **1946 with 0 rows**. Attribution measured with
    all four runs pinned.
  - **The join key set is what an arm CHANGED, not what it assigns** — a dynamic diff, which
    subsumes the label-reset set the bead asked for. Isolation with the old syntactic `assigned()`
    key set is measurably *worse* than sharing the arms.
  - **A `try`'s handler enters from the BODY'S MERGE**, not from the pre-construct state and not from
    the body's end state: the unwinder enters mid-body (`peek-a-bin-d3z`'s 1160 blocks are the same
    fact one storey up).
  - **Loop *exit* joins use the changed set; loop *headers* used to keep the syntactic
    `assigned()`.** That was recorded as needing a per-loop fixpoint nested inside the label one
    (2^depth walks); **`peek-a-bin-mvc2` closed it in ONE pass and no second fixpoint** — see the
    bullet below. Callee clobbers need nothing: SSA already spells them `clobbered_<reg>_<n>`,
    which are distinct keys.
  - **The `try` and loop-exit rules are INERT on this corpus** — an ablation reverting both leaves
    the emitted C byte-identical on all four binaries — so they are bounds pinned by unit test, the
    status `pop esp` and the `rip`/`rsp` refusals have, and not measured savings. Five negative
    controls, each failing only its own test (`peek-a-bin-9fp5`).

- **…and a LOOP HEADER is answered in one pass after all, exactly — the nested fixpoint it was
  filed as needing is not required, and the population it closes is real but INERT here.** The
  header is the one merge that cannot diff against the pre-construct state, because its back edge
  is a body the walk has not reached, so `join` minted over `assigned()` alone. The set is now the
  body's *definitions* plus what a `label` in the body would re-value, and the reason no iteration
  is needed is a boundedness argument rather than a measurement: **a key enters `cur` only through
  an `assign`, a `call_stmt` result, a `mint`, or a `label` reset, and the last two only ever
  re-value keys `cur` already holds** — so every key the body can change is already in flight at
  the header or is one a syntactic walk names. Five things (`peek-a-bin-mvc2`, measured at
  `1198f4a`, both sides pinned):
  - **THE FILED SHAPE — a label the body resets — WAS NOT THE WHOLE POPULATION, and the half nobody
    had noticed is `peek-a-bin-9fp5`'s own fact.** `assigned()` read `assign` destinations and not
    `call_stmt.resultDest`, so a loop whose body calls anything failed to mint the **accumulator**
    at its own header — `t32!sub_40DD37`'s defect, at a loop. Census over the four binaries:
    **50/53/47/38 of 187/188/180/174 loop headers** (t32/t64/w64/w32) had a key the body changed and
    the header missed; adding call results fixes 30/33/31/22 of those headers, and the residue is
    **20/20/16/16 headers, every single one of which contains a `label`**. That 100% is what makes
    the two-part rule provably complete rather than a pair of patches.
  - **What the label contributes is `atLabel`'s own rule read FORWARDS, never "every key in
    flight".** A label no `goto` names resets all of them, so for that shape the union is exact; a
    `goto`-named one leaves a key the fixpoint settled exactly as it found it, and `labelResets`
    compares the settled value against the header's rather than assuming. It mirrors `atLabel`
    branch for branch — the `probe` pass, the `blunt` fallback, and the kept-key-not-in-flight arm —
    because two readings of one label is how they come to disagree.
  - **THE BLUNT VERSION WAS IMPLEMENTED AND MEASURED, AND IT COSTS `t32!sub_4041D0`** — the
    single-definition ESI `peek-a-bin-slkh` adjudicated against `objdump`. Minting every in-flight
    key whenever the body holds a label moves emitted C in **50/10/8/47** functions, of which
    **2/1/1/2** are substantive once `struct_N` renumbering is normalised out, and two of those are
    slkh's witness and its w32 twin losing a member access each (`->field_0x` 531→529 and
    516→514). Every gate stays green through that variant — `structOverlaps` 0, `offsetof` 1.00,
    verdict "no regression" — so **the corpus cannot tell the blunt rule from the exact one** and
    only reading the emitted C separates them. The precision half is pinned by its own test.
  - **The gap is now provably CLOSED, not narrowed, and the instrument says so.** Instrumented over
    the whole corpus, keys a loop body changes that its own header did not mint go
    **328/681/448/215 → 0/0/0/0**, while the header key sets grow **635→958, 785→1460, 685→1127,
    578→788** across **49/52/46/37** headers (+30/34/32/22 from call results, +293/641/410/188 from
    labels). So the rule is *reached* — the reason to report both numbers is that a rule adding
    nothing and a rule never consulted read the same.
  - **And not one of those extra phis moves anything.** Emitted C **byte-identical on all four
    binaries**, `report.txt` identical line for line, the `cc/` and `offsetof/` artifact trees
    identical under `diff -r`, `CHANGED 0 / only-base 0 / only-change 0`, `structOverlaps` 0,
    `offsetof` 393/282/287/309 at ratio 1.00, `->field_0x` 531/459/440/516 unmoved. It is therefore
    a **bound pinned by unit test rather than a measured saving**, the status the `try` and
    loop-exit rules above already have. Three negative controls, each failing exactly one test.

- **…and a `label` is resolved from the states its own `goto`s carry, not reset blindly — but the
  ceiling that reaching for it suggests is a FABRICATION, measured on the very witness that
  motivated the change.** `structureCFG` spells every transfer it cannot fall through as a `goto`
  naming its target, so the predecessors of a label *are* expressible in tree order: the states at
  the `goto`s that name it, plus the fall-through. The join over them is the same phi the constructs
  above already stand in for, and `baseGenerations` now takes it to a fixpoint. **`t32!sub_4041D0`
  is the adjudicated witness and it goes from 1 member access to 3**: ESI is established once, by
  `mov esi,[ebx+8]` / `xor esi,ds:0x412284` at 0x4041dd–0x4041e0, and nothing writes it again, so
  all three `[esi]` reads — 0x4041e7, 0x404278, 0x40430e — are one object and now say so.
  Six things (`peek-a-bin-slkh`):
  - **A label NO `goto` NAMES still resets every key, unconditionally, and that asymmetry is the
    whole soundness argument.** `structureCFG` ends in `pruneLabels`, which drops any label nothing
    jumps to *unless* it is `pinned` — so a label with no `goto` in the tree this pass receives is
    precisely a leftover region's head, i.e. a block with no CFG predecessor at all. Those are not
    dead code: an MSVC `__except`/`__finally` continuation or a 32-bit SEH scope handler is entered
    by the **unwinder** (`peek-a-bin-d3z`, 1160 such blocks here), an edge no statement in the tree
    expresses, so a generation carried into one would be a value the unwinder never established.
    `structs.test.ts` pins it at a shape whose edges *would* agree, so the test fails if the arm is
    removed rather than merely being satisfied by accident.
  - **The edge set is a SUPERSET of the real one everywhere else, so an error in it can only reset
    MORE.** The fall-through is counted whenever the preceding sibling is not a `return`/`goto`/
    `break`/`continue`, which over-counts for a goto-named leftover region the pass above appended
    after a region that did not end in one — and such a block is CFG-reachable by construction (the
    `goto` naming it *is* its predecessor), so the extra state is spurious rather than missing.
  - **A generation is a TOKEN NAMING THE TREE NODE, not a counter, and without that the fixpoint
    cannot be written.** A counter's ids depend on how many `fresh` calls a pass made, so the same
    id means different things on two passes and "did both edges carry the same value" has no
    answer. `a<n>`/`j<n>.<k>`/`L<n>` are functions of a pre-order statement numbering, hence stable.
  - **The iteration must start OPTIMISTIC — from "the label costs nothing" — and starting the other
    way was implemented and measured.** Conflicts are what accumulate, so a pessimistic first pass
    locks in its own artifacts: a key that agrees on every real edge disagrees on that pass purely
    because one edge came through another label that reset it. That order reaches **+13** field
    accesses against the optimistic order's **+65**, and *no unit test separates the two* — it is a
    precision choice measured by the corpus, and `structs.test.ts`'s "does not let one label's reset
    spoil the next label's edges" is the shape that pins it. Termination is monotone by construction
    (each (label, key) goes absent → kept → conflicted and never back); `LABEL_FIXPOINT_PASSES` is a
    belt-and-braces cap whose fallback is the pre-slkh blunt rule.
  - **DELETING THE RESET REACHES 1980 AND FABRICATES AT THE WITNESS ITSELF.** The bead recorded the
    ceiling as costing nothing on `structOverlaps` and being a split of one real object in 4 of 4
    samples; built as a control at `87a8499` it reproduces 1980 exactly (541/466/447/526) — and on
    `t32!sub_4041D0` its extra `struct_9 {0x8, 0xC}` over EBX groups `[ebx+0xC]` at **0x404344**,
    which sits inside `loc_40433F`, a label entered both from 0x404220 (`jne`, EBX = `arg_1`, the
    `EXCEPTION_REGISTRATION`) **and** by fall-through from 0x40433a, where EBX has been redefined at
    0x40422f (`mov ebx,[ebx+0xc]`) and again at 0x40426b. So the ceiling merges a read through
    `arg_1` with a read through `[arg_1+0xC]`: `z8q7`'s own defect class, at the site whose loss
    justified reopening the question, and invisible to `structOverlaps` in both runs. **1980 is not
    the target.** The join takes 65 of the 109 and refuses that one.
  - **What is measured, and what the sample was.** 25 functions moved a field-access count and
    **none of the 25 fell**; 6 were hand-read against `objdump -d -M intel` and all 6 are correct —
    `t32!sub_4041D0` (ESI single-def), `t32!sub_402D75` (EDI single-def at 0x402d7f, 6 accesses,
    with `field_0x4` correctly turning signed off `cmp/jge`), `t64!sub_1400043DC` (RBX between
    `lea rbx,[rdi+rax*8+0xc]` at 0x140004438 and `add rbx,0x10` at 0x1400044f3, so all four
    `[rbx+…]` reads are one value), `t32!sub_4038FF` and its x64 twin `t64!sub_140003F84` (a global
    loaded once, two flag bytes 0x44/0x84 and 0x60/0xB8), and `t32!sub_40E2C0` (ESI single-def).
    The other 19 are **counted, not read** — including the `w32`/`w64` members of families whose
    `t32`/`t64` twin was read. **Six guards left the polarity ledger with their text still on the
    page**, four of them anchor-A: each is a deref that became a member access the auditor cannot
    anchor (`*(int32_t*)(edi + 4) < 0` → `((struct_3 *)edi)->field_0x4 < 0` on the PE32 pair,
    `*(int32_t*)(rcx_0 + 8) < 0` → `->field_0x8 < 0` on the x64 pair, `*(uint8_t*)(esi) != 0` →
    `->field_0x0 != 0` on the PE32 pair), which is the same benign shape `peek-a-bin-c33` records.
  - **The residual 44 are NOT this rule's to take, and the mechanism is now identified**:
    `visit` shares one `cur` across an `if`'s two arms with no save and restore, so a reset (or an
    assignment) in the `then` arm leaks into the `else` arm. That is what still costs
    `t32!sub_4041D0` its EBX `{0x8, 0xC}` — `loc_40433F` is the first statement of the `then` arm and
    its reset reaches the `else` arm's `[ebx+0xC]`. It is also a **fabrication** hazard in its own
    right (`if (c) { rax = load(A); use(*rax) } else { use(*(rax+8)) }` gives the `else` read the
    `then` arm's generation). Isolating the arms naively reaches 1966 and `t32!sub_4041D0` = 5 — and
    **produces 1 `structOverlaps` row per binary** (`t32!sub_40DD37`, `reg:rax#a4`, `0x0:4` over
    `0x2:2`), because `join` mints for keys the arms *assign* and not for keys a label inside an arm
    reset. So it is a real defect with a known trap, filed as `peek-a-bin-9fp5`, not folded in here.
    **`peek-a-bin-9fp5` HAS SINCE LANDED, AND THE DIAGNOSIS ABOVE IS WRONG — see the gotcha below.**
    The naive isolation's `structOverlaps` row is not the join's key set at all; it is a `call_stmt`
    that never minted.
- **THREE TESTS PINNED THE DEFECT AS THE RULE.** `structs.test.ts`'s "does not credit accesses to
  the last base a register was ever copied from" asserted all three offsets of an RBX that holds
  RCX's object and then RDX's in **one** declaration, with a comment saying "the grouping survives";
  the grouping was the fiction. `pipeline.test.ts`'s "leaves the field alone when the register holds
  two different objects" asserted `uint32_t` for both fields *because* "the struct grouping is
  already flow-insensitive enough to pool both objects' accesses" — now each field names its own
  pointee, and a new test asserts the refusal at the shape that still deserves it (two arms loading
  the register from different fields, where the join leaves no single source). The third was the
  observer's `baseKey`, now `reg:rcx#0`. `corpus.audit.ts`'s `rows > 0` liveness assertion also had
  to go: its population is now empty *because* of the fix, and `groups`/`candidates`/`extents` carry
  the liveness instead — they rose exactly where the rows fell.

**`stackDerivedBases`' copy chain sees only `assign` with a register or variable
destination, so what `promoteVars` promotes decides how far stack-derivation
propagates.** A stack address spilled to a frame slot and reloaded is two
statements — a `store` and a `deref` — and neither is a copy, so the chain used
to stop dead at the spill. Promote the slot and both halves become
`var_41C = ecx` / `edi = var_41C`, the chain closes, and a base that provably
holds a stack address on some path is refused a struct it previously got. That
is the rule working, not a regression — "one write of a stack address into a
register is enough to make every access through it suspect", and refusing is the
benign direction. It is also the *only* way struct synthesis moved when
`promote.ts` started following frame-register aliases: t32 59 → 58 and w32
58 → 57 distinct definitions, one two-field `{0x0, 0x4}` shape each (the weakest
evidence a candidate can have), with `offsetof` unmoved at 353/353 and 408/408
fields and x64 byte-identical (peek-a-bin-5zpo, measured at `f685b6d`).

**Emitted struct definitions are `#pragma pack(1)` with explicit `_pad_0xNN` members**, and the two are inseparable — padding alone cannot express an unaligned recovered offset and C would re-align on top of it. The field *names* record the offsets the recovery found (`field_0x18`), so a declaration C would not lay out that way is a declaration that states something false: before the fix, 131 of 149 emitted definitions were wrong that way, and every `p->field_0x18` in those bodies read bytes the access never touched. A field no padding can place — overlapping one already placed, negative, past 0x8000, or of a width with no spelling — is reported in the struct body and its accesses spelled as the bytes they touch, rather than declared somewhere convenient (`peek-a-bin-ey0`).

**A call takes an assignment only when its result is live out of the call.** `liftBlock` gives every `call_stmt` a `resultDest` of RAX/EAX, but emit printed the call and dropped the assignment, so `GetProcAddress(...)` followed by `if (rax == 0)` was C in which nothing ever assigns `rax` — 968 accumulator reads of an unassigned name across the corpus, now 254. Which calls get one is answered as the liveness question it is: a backward pass over the **structured** body (the tree emission walks, so the statement the reader sees after a call is the one the analysis asked about), loop headers to a fixpoint, `break`/`continue` carrying the live set of the construct they leave, a handler live throughout the body it guards, and a `goto` — the one shape the tree does not model — falling back to every register the body names. 2665 of 4160 calls take an assignment; the rest stay bare, because an assignment nobody reads is noise. **That pair was unstamped and `peek-a-bin-l1f` has since moved the numerator down**: it folds `<acc> = f(); return <acc>;` into `return f();` at **396 sites corpus-wide** (117/84/83/112 on t32/t64/w64/w32), and because `foldReturnedCallResults` is `emitFunction`'s first act the liveness pass is asked about the *folded* body, so each of those calls stops printing an assignment. The 2665/4160 therefore describes the tree **before `2e66241`** and the current numerator is lower by up to that 396 — not re-measured here, so treat the pair as pre-`l1f` rather than as a figure to compare against. `_assignedRegs` follows the same rule, so `registerText` cannot respell a read of `al` as `(uint8_t)rax` in a function whose only write of RAX went unprinted.

**…and where that assignment's only reader is the very next `return` of it, the two lines are
printed as one: `rax = f(); return rax;` → `return f();`** — 396 pairs folded over the four
corpus binaries at `f3b89ec` (117/84/83/112 on t32/t64/w64/w32, of a population of 400).
`foldReturnedCallResults` (`emit.ts`) is `emitFunction`'s **first** act, before
`collectCapturedCalls` and `collectAssignedRegs`, and that ordering is the whole of its safety
rather than tidiness. Five things:

- **Asking both sets about the folded body is what keeps the output self-consistent.** The fold
  removes an assignment of the accumulator, so `_assignedRegs` may lose that name — and
  `registerText` respells a narrow read as a narrowing of the widest *assigned* alias. Computed
  over the folded body, a read is respelled exactly when a wider alias really is assigned in the
  text the reader sees. Removing an assigned name can only ever **withdraw** a respelling, never
  add one, and `peek-a-bin-k8i`'s own residue rule says what is left is honest: a name with no
  wider assigned alias is an incoming value and its own name is what to call it. Measured, the
  k8i instrument moves in the *good* direction — invented prelude declarations
  **1495/2506/2328/1451 → 1460/2456/2278/1417**, i.e. −169 corpus-wide, because a folded function
  stops naming the accumulator at all. The one function per PE32 binary where a respelling is
  withdrawn is `t32!sub_40E714` / `w32!sub_40CE34`, where 115 `(uint8_t)eax` become `al` — decoded
  `00 00` padding past a `ret`, i.e. a region the machine never executes.
- **It cannot change which OTHER calls print a result, and that is a property rather than a
  measurement.** Before the fold the accumulator is dead immediately above `<acc> = f()` (the
  assignment kills it); after it, dead immediately above `return f()` for want of a mention. The
  live set every earlier statement is judged against is therefore identical, so `_capturedCalls`
  moves by exactly this call.
- **The folded line keeps the CALL's address, not the `return`'s**, which is what the base's line
  at that position carried — so a guard whose body *begins* here (27/35/35/26 of the sites)
  anchors to the same jcc in `corpus/sweep.ts`. Measured: `polarity guards audited` exactly flat
  at 517/574/497/441 with `CHANGED 0 / only-base 0 / only-change 0` on all four. The `return`'s
  own address leaves the line map, which is the one unavoidable cost of printing two statements as
  one line: `insns covered` **6624/6144/5565/6136 → 6517/6097/5520/6033**, with `blocks covered`
  unmoved. That row is labelled "read the C, not a gate" for exactly this kind of move.
- **Adjacency in the statement list is the rule, and it refuses more than it looks like.**
  `t32!sub_401000` ends `eax = sub_401DA4(); /* unlifted: leave */; return eax;` and is left
  alone — an unlifted instruction between the two is a statement, and folding across it would
  claim the machine does nothing there.
- **Restricted to a `call_stmt`**, which is the shape the liveness rule is about. The residue is
  **2/0/0/2** pairs whose left side is an ordinary `assign` (`eax = var_4; return eax;` in
  `t32!sub_4079E0` / `w32!sub_4071F0`); folding those is equally sound and is deliberately out of
  scope.

**Two tests pinned the two-line shape and both were pinning the shape, not the property**
(`pipeline.test.ts`, "a call's result"). `peek-a-bin-oro` exists so that a call's result reaches
the reader instead of a `return eax` with nothing assigning `eax`, and `return sub_408000();`
satisfies that more directly than `eax = sub_408000(); return eax;` did; the sibling test's real
claim — the *first* of two calls stays bare because its result is dead — is untouched. Both now
assert the property (`peek-a-bin-l1f`).

**emit.ts module-level `_typeCtx`**: Set before emission, cleared after. Enables cast suppression and type-aware idioms (INVALID_HANDLE_VALUE, NT_SUCCESS, SUCCEEDED/FAILED).

