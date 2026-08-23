/**
 * Compare two corpus runs: `npm run corpus:compare -- <baseDir> <changeDir>`.
 *
 * This is the audit that actually catches regressions. A single run tells you
 * the absolute numbers, and CLAUDE.md is emphatic that those move on their own:
 * denominators shift whenever function detection changes, so "842/842" becoming
 * "838/838" is not a regression while "838/840" is. What you almost always want
 * to know is whether a specific commit changed anything, and for that you need
 * both sides pinned.
 *
 * THE METHOD THAT MAKES THIS TRUSTWORTHY — a base sweep taken against a moving
 * HEAD silently compares your change against someone else's work, and that has
 * bitten this project more than once:
 *
 *     git worktree add /tmp/base <commit>^
 *     ln -s "$PWD/node_modules" /tmp/base/node_modules
 *     PEEK_CORPUS_LABEL=base   PEEK_CORPUS_OUT=/tmp/corpusout npm run corpus   # in /tmp/base
 *     PEEK_CORPUS_LABEL=change PEEK_CORPUS_OUT=/tmp/corpusout npm run corpus   # in the worktree at <commit>
 *     npm run corpus:compare -- /tmp/corpusout/base /tmp/corpusout/change
 *     rm /tmp/base/node_modules && git worktree remove /tmp/base
 *
 * Guards are joined on the ADDRESS OF THE ORIGINATING JCC, not on the function
 * name or an index: function names move when detection changes, instruction
 * addresses do not. A guard present on both sides whose condition, expected
 * operator or verdict differs is the finding — new guards appearing is normal,
 * a pre-existing one changing is not.
 *
 * Plain node, no TypeScript, and the reason is that it reads only the artifacts
 * and never the repo's source — so it can be pointed at two runs from different
 * commits without itself being one of the things under comparison.
 *
 * The other reason once given here — "`tsx` does not work on this machine (Node
 * 18, ERR_REQUIRE_ESM)" — is stale and was checked: this machine runs Node
 * v22.22.1 and `npx tsx` works (verified 2026-08-20). Node 20+ is required
 * anyway, per `engines.node`. Do not port this to TypeScript on that news
 * though; the first reason is the load-bearing one.
 */
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const [baseDir, chgDir] = process.argv.slice(2);
if (!baseDir || !chgDir) {
  process.stderr.write(
    "usage: node corpus/compare.mjs <baseArtifactDir> <changeArtifactDir>\n" +
      "  each directory is one produced by `npm run corpus` (see PEEK_CORPUS_OUT / PEEK_CORPUS_LABEL)\n",
  );
  process.exit(2);
}
for (const d of [baseDir, chgDir]) {
  if (!existsSync(d)) {
    process.stderr.write(`no such artifact directory: ${d}\n`);
    process.exit(2);
  }
}

const binsIn = (dir) =>
  readdirSync(dir)
    .map((f) => /^summary_(\w+)\.json$/.exec(f))
    .filter(Boolean)
    .map((m) => m[1]);

const bins = binsIn(baseDir).filter((b) => binsIn(chgDir).includes(b));
if (bins.length === 0) {
  process.stderr.write("the two directories have no binary in common\n");
  process.exit(2);
}

const readSummary = (dir, b) => JSON.parse(readFileSync(join(dir, `summary_${b}.json`), "utf8"));
const readFuncs = (dir, b) =>
  readFileSync(join(dir, `funcs_${b}.jsonl`), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));
const readGuards = (dir, b) =>
  readFileSync(join(dir, `guards_${b}.jsonl`), "utf8")
    .split("\n")
    .filter(Boolean)
    .map((l) => JSON.parse(l));

/** Everything about a guard except which function it happened to be filed under. */
const shapeOf = (g) =>
  `${g.kind}|${g.cond}|${g.expect}|${g.emitted}|${g.verdict}|${g.sense}|${g.anchor}`;

let regressions = 0;
const out = [];
const note = (s) => out.push(s);

for (const b of bins) {
  const B = readSummary(baseDir, b);
  const C = readSummary(chgDir, b);
  note(`\n═══ ${b} ${"═".repeat(60)}`);

  const row = (name, get, worseIf, why = "REGRESSION") => {
    const a = get(B);
    const c = get(C);
    const worse = worseIf ? worseIf(a, c) : false;
    if (worse) regressions++;
    const mark = worse ? `   <<< ${why}` : a === c ? "" : "   (moved)";
    note(`  ${name.padEnd(30)}${String(a).padStart(10)} -> ${String(c).padStart(10)}${mark}`);
  };

  // Counts that are expected to move when detection changes. Reported, never
  // judged: the ratio is the claim, the absolute is a date-stamp.
  row("functions", (x) => x.functions);
  row("instructions", (x) => x.instructions);
  row("jumpTables", (x) => x.jumpTables);

  // Invariants. Any rise is a regression on its own terms.
  row(
    "throws",
    (x) => x.throws,
    (a, c) => c > a,
  );
  row(
    "polarity inverted",
    (x) => x.polarity.inverted,
    (a, c) => c > a,
  );
  row(
    "polarity mismatch",
    (x) => x.polarity.mismatch,
    (a, c) => c > a,
  );
  row(
    "loops short of machine",
    (x) => x.loops.short,
    (a, c) => c > a,
  );
  row(
    "distinct callees lost",
    (x) => x.callees.lost,
    (a, c) => c > a,
  );
  // Statements liftBlock produced that structureCFG put nowhere, by object
  // identity. The absolute is NOT gated in the run itself — see the README —
  // but a rise between two pinned commits is a regression on its own terms:
  // whatever the baseline is, a change that loses more statements than the
  // commit before it has lost statements. Nothing downstream can notice.
  //
  // An artifact directory produced before this audit existed has no such field,
  // and "absent" must not read as "zero" — that would score a run that never
  // measured as the best possible result.
  if (B.stmtDrops && C.stmtDrops) {
    row(
      "statements dropped",
      (x) => x.stmtDrops.dropped,
      (a, c) => c > a,
    );
    row("statements lifted (denom)", (x) => x.stmtDrops.tracked);
  } else {
    note("  statements dropped            NOT MEASURED on both sides (a run predating the audit)");
  }

  // A register named for a value it no longer holds. GATED AT 0 in the run
  // itself, so a rise here can only mean the gate was not run — but it is
  // compared anyway, because a comparison is how a run at an older commit is
  // read, and those predate the gate entirely. Absent on either side must not
  // read as zero: a run that never measured would otherwise score as the best
  // possible result.
  if (B.staleV0 && C.staleV0) {
    row(
      "stale version-0 names",
      (x) => x.staleV0.wrong,
      (a, c) => c > a,
    );
    row(
      "  spoiled entry copies",
      (x) => x.staleV0.copiesCorrupted,
      (a, c) => c > a,
    );
    row("  entry copies taken", (x) => x.staleV0.copies);
    row("  sites of the shape", (x) => x.staleV0.sites);
  } else {
    note("  stale version-0 names         NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── Branch and value recovery. ─────────────────────────────────────────
  //
  // `__unrecovered_N` is what the emitter prints when it cannot name a value,
  // most often the condition of a Jcc. Until `peek-a-bin-rl01` nothing counted
  // them, and NOTHING IN THIS FILE COULD SEE THEM: an unrecovered condition has
  // no top-level comparison operator, so the polarity audit does not record a
  // failing row for it — it records no row at all. A change turning recovered
  // guards into unrecovered ones therefore moved `polarity.checked` down while
  // leaving `ok/checked` at 1.00, and this script called that no regression.
  //
  // A rise is a regression on its own terms, whatever the baseline: the change
  // hands the reader fewer machine facts than the commit before it did. The
  // denominator moving underneath (a function appearing or disappearing) can
  // raise it innocently, exactly as it can raise `throws` or `callees lost`;
  // the function count is printed above, and a rise is adjudicated, not
  // assumed. Absent on either side must not read as zero.
  if (B.unrecovered && C.unrecovered) {
    row(
      "unrecovered values",
      (x) => x.unrecovered.values,
      (a, c) => c > a,
    );
    row(
      "  of which branch guards",
      (x) => x.unrecovered.branches,
      (a, c) => c > a,
    );
    row("  branches with a jcc", (x) => x.unrecovered.branchesWithJcc);
    row("  token occurrences", (x) => x.unrecovered.occurrences);
  } else {
    note("  unrecovered values            NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── Call arity against apitypes.ts's declared signatures. ──────────────
  //
  // The dimension NOTHING ELSE HERE CAN SEE. `gcc -std=gnu89` accepts an
  // implicit declaration at any arity and the emitter writes no prototypes, so
  // the compiler gate is insensitive to call arity by construction: it could
  // not have caught `peek-a-bin-qb2x` (x64 arguments set up through a 32-bit
  // sub-register, ExitProcess() emitted with no argument at all) and cannot
  // certify the fix. `apitypes.ts` is the only oracle in the repo that can.
  //
  // OVER is the direction with no benign reading: no entry in the table is
  // variadic, so a call passing more arguments than the API takes passes one the
  // machine never passed. It is not gated in the run only because its standing
  // value is not zero and a threshold at today's absolute goes stale as
  // detection moves; a RISE between two pinned commits is a regression on its
  // own terms. UNDER is judged the same way with the caveat that a newly
  // detected function can raise it innocently — the function count is printed
  // above, and a rise is adjudicated, not assumed. Absent on either side must
  // not read as zero: a run that never measured would otherwise score best.
  if (B.arity && C.arity) {
    row(
      "arity over-count",
      (x) => x.arity.over,
      (a, c) => c > a,
    );
    row(
      "arity under-count",
      (x) => x.arity.under,
      (a, c) => c > a,
    );
    row("  under at the ABI ceiling", (x) => x.arity.underAtCeiling);
    row(
      "  under below the ceiling",
      (x) => x.arity.underBelowCeiling,
      (a, c) => c > a,
    );
    row("  declared callees called", (x) => x.arity.distinctCallees);
  } else {
    note("  arity over-count              NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── What a call destroys (corpus/sweep.ts `auditClobbered`). ──────────────
  //
  // REPORT-ONLY, both directions, and deliberately. A rise means more reads were
  // named as the indeterminate values they are, which is what `peek-a-bin-hj1`
  // set out to achieve; a fall can equally mean the model went quiet. The row
  // that turns this into a judgement is `if`/`while`/`for` beside it: the ABI
  // volatile set's measured harm was a guard DELETED, and construct counts are
  // where that shows up. Read them together or read neither.
  if (B.clobbered && C.clobbered) {
    row("clobbered reads", (x) => x.clobbered.reads);
    row("  distinct clobbered values", (x) => x.clobbered.values);
    row("  functions affected", (x) => x.clobbered.funcsAffected);
    row("  if emitted", (x) => x.clobbered.ifs);
    row("  while emitted (raw)", (x) => x.clobbered.whiles);
    // LOOP SHAPE, and it is the property no gate here models — which is why
    // `peek-a-bin-9q2`'s 4x fall in for-loop recognition happened with nothing
    // recording it, and why every session since has counted these by hand.
    //
    // `whiles` is the raw `while (` match count and so is the SUM of a
    // top-tested `while (c) {` and a do/while's `} while (c);` back edge; the
    // row above keeps that meaning so a comparison against an artifact
    // directory predating `doWhiles` is not a fake fall of exactly that many.
    // These two rows are the split, and the top-tested figure is the one
    // CLAUDE.md's loop-shape lines quote.
    //
    // REPORT-ONLY, in both directions, for the same reason as the clobbered
    // rows above: a `for` that becomes a `while` is a fidelity loss rather than
    // a wrong statement about the machine, the absolutes move whenever function
    // detection does, and no threshold on any of them is established. What this
    // buys is that a shape change between two pinned runs is a ROW rather than
    // something the next agent has to think to count.
    if (B.clobbered.doWhiles !== undefined && C.clobbered.doWhiles !== undefined) {
      row("    of which do/while", (x) => x.clobbered.doWhiles);
      row("    top-tested while", (x) => x.clobbered.whiles - x.clobbered.doWhiles);
    } else {
      note(
        "    of which do/while           NOT MEASURED on both sides (a run predating the split)",
      );
    }
    row("  for emitted", (x) => x.clobbered.fors);
    row("  callee summaries non-empty", (x) => x.clobbered.summaryNonEmpty);
    row(
      "  unclassified mnemonics",
      (x) => x.clobbered.uncoveredMnemonics,
      (a, c) => c > a,
      "MORE MNEMONICS THE WRITTEN-REGISTER TABLE DOES NOT CLASSIFY",
    );
  } else {
    note("  clobbered reads               NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── Guards naming the wrong operands (corpus/staleGuards.ts). ──────────────
  //
  // The other dimension no other guard here can see. A wrong-operand guard has
  // the RIGHT comparison operator — it is answered from a compare the flags have
  // moved on from, or one whose operand a later instruction overwrote — so it
  // passes `polarity inverted` unchanged, and it is not an unrecovered value
  // either, so it is not a row in the branch-recovery count. Both `peek-a-bin-xe01`
  // and `peek-a-bin-jitf` survived precisely because every standing gate was blind
  // to them.
  //
  // NAMED is gated at 0 in the run itself, so a rise fails CI before this script
  // is reached. It is repeated here because compare.mjs is what says *what moved*
  // between two pinned commits, and a run that fails without saying which rows
  // came back is the failure mode `peek-a-bin-rl01` documented for unrecovered
  // values.
  //
  // SHAPES is deliberately NOT gated: it counts blocks whose trailing jcc reads
  // flags the recovered compare does not describe, which is a property of the
  // machine code and moves only when function detection or block construction
  // moves. That makes a change in it a signal about something else entirely, so
  // it is reported and adjudicated rather than judged here.
  if (B.staleGuards && C.staleGuards) {
    row(
      "wrong-operand guards named",
      (x) => x.staleGuards.named,
      (a, c) => c > a,
    );
    row("  spoiled readings (machine shape)", (x) => x.staleGuards.shapes);
    row("  of which superseded", (x) => x.staleGuards.bySuperseded);
    row("  of which clobbered", (x) => x.staleGuards.byClobbered);
    row("  jcc blocks examined", (x) => x.staleGuards.blocks);
    // The recovery, not the defect: guards emitted at a spoiled jcc at all,
    // which is what `named` counted before peek-a-bin-xskz. A FALL is what
    // matters here — it means the lifter stopped materialising a spoiled
    // compare's operands — so it is reported and adjudicated, not judged.
    if (B.staleGuards.emittedAtShape !== undefined && C.staleGuards.emittedAtShape !== undefined) {
      row("  guards emitted at a shape", (x) => x.staleGuards.emittedAtShape);
    } else {
      note("  guards emitted at a shape     NOT MEASURED on both sides (a run predating xskz)");
    }
  } else {
    note("  wrong-operand guards named    NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A guard wrong on one incoming edge (corpus/crossEdgeGuards.ts). ────────
  //
  // The dimension `staleGuards` above cannot reach: its scan needs a cmp/test in
  // the jcc's own block, and these blocks hold nothing but the jcc, so they are
  // not in its denominator. A Jcc alone in its block reads flags set before the
  // block was entered, and where its predecessors set them from different tests
  // no block-local `if` states the machine on every path in.
  //
  // NAMED is gated at 0 in the run, so a rise fails CI before this script is
  // reached; it is repeated here because compare.mjs is what says WHICH rows came
  // back. DIFFER is deliberately not gated — it is a property of the machine code
  // and moves only when function detection or block construction moves, so a
  // change in it is a signal about something else and is adjudicated, not judged.
  // ANSWERED is the complete half — the predecessor the code admitted, which is
  // necessary for either route to spell a condition at such a jcc — and NAMED is
  // the same defect stated at the output, where it depends on the polarity
  // anchor and is a lower bound. The two SOLE- rows are the liveness halves: a
  // fall in either says a 0 above may be for want of observing rather than for
  // want of a defect.
  if (B.crossEdgeGuards && C.crossEdgeGuards) {
    row(
      "cross-edge guards answered",
      (x) => x.crossEdgeGuards.admitted,
      (a, c) => c > a,
    );
    row(
      "  of those, named on the page",
      (x) => x.crossEdgeGuards.named,
      (a, c) => c > a,
    );
    row("  disagreeing edges (machine shape)", (x) => x.crossEdgeGuards.differ);
    row("  agreeing edges", (x) => x.crossEdgeGuards.agree);
    row("  multi-edge blocks", (x) => x.crossEdgeGuards.multi);
    row("  cross-edge blocks", (x) => x.crossEdgeGuards.crossEdge);
    row("  sole-predecessor blocks answered", (x) => x.crossEdgeGuards.soleAdmitted);
    row("  sole-predecessor blocks named", (x) => x.crossEdgeGuards.soleNamed);
  } else {
    note("  cross-edge guards answered    NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A register a `pop` wrote, read under its previous value (popReads.ts). ──
  //
  // Not gated in the run — the count is not zero and no fix has been taken —
  // so this is the only place a change in it is judged. A RISE is a regression:
  // every row is a name the emitted C applies to a value the machine replaced.
  // A FALL is the fix, and `benign` is what a blanket refusal of every pop
  // would cost, so it is reported beside it rather than gated in either
  // direction: it moves with function detection like any machine-shape count.
  if (B.popReads && C.popReads) {
    row(
      "pop-restored stale reads",
      (x) => x.popReads.wrong,
      (a, c) => c > a,
      "MORE READS NAMING A VALUE A POP REPLACED",
    );
    row("  pops accounted for", (x) => x.popReads.popsWrong);
    row("  benign restores (would cost)", (x) => x.popReads.benign);
    row("  implicit ret reads wrong", (x) => x.popReads.retWrong);
    row("  implicit ret reads benign", (x) => x.popReads.retBenign);
    row(
      "  pops lifted as push-imm",
      (x) => x.popReads.popsLifted,
      (a, c) => c < a,
      "THE push-imm/pop PAIRING STOPPED FIRING",
    );
    row("  pops examined", (x) => x.popReads.pops);
  } else {
    note("  pop-restored stale reads      NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A definition the fold deleted while a later block read it (lostDefs.ts). ──
  //
  // Gated at 0 in the run, so a rise here is a second alarm rather than the
  // only one. The rows beneath it are the liveness numbers, and `entry-value
  // reads` is the population the gate is told apart from: it moves with
  // function detection like any machine-shape count and is reported, never
  // judged.
  if (B.lostDefs && C.lostDefs) {
    row(
      "fold-lost definitions",
      (x) => x.lostDefs.lostReads,
      (a, c) => c > a,
      "A DEFINITION A LATER BLOCK READS WAS DELETED",
    );
    row("  sites of the shape", (x) => x.lostDefs.lostSites);
    row("  functions affected", (x) => x.lostDefs.funcsAffected);
    row("  entry-value reads (legit)", (x) => x.lostDefs.entryReads);
    row("  register reads examined", (x) => x.lostDefs.regReads);
  } else {
    note("  fold-lost definitions         NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A switch arm asserting the switch is over (armExits.ts). ───────────────
  //
  // Gated at 0 in the run, so a rise here is the second alarm rather than the
  // only one — and it is the one that says WHICH arms came back. `arms` and the
  // truthful closures below it are the denominator: they move with function
  // detection and with how many jump tables are recovered, so they are reported
  // and never judged, and a FALL in `arms` on a binary that still recovers
  // tables is the shape of an instrument that stopped observing.
  if (B.armExits && C.armExits) {
    row(
      "switch-arm false breaks",
      (x) => x.armExits.falseBreaks,
      (a, c) => c > a,
      "AN ARM CLAIMS THE SWITCH IS OVER WHERE ITS BLOCK GOES ON",
    );
    row("  of those, conditional", (x) => x.armExits.falseBreaksCond);
    row("  of those, unconditional", (x) => x.armExits.falseBreaksUncond);
    row("  functions affected", (x) => x.armExits.funcsAffected);
    row("  arms examined", (x) => x.armExits.arms);
    row("  truthful closures", (x) => x.armExits.truthfulExits);
    row("  breaks with no true spelling", (x) => x.armExits.unnameable);
  } else {
    note("  switch-arm false breaks       NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A case label whose whole body is `break;` (emitAudits.ts). ─────────────
  //
  // The question `armExits` cannot answer: it judges the closure `armExit`
  // chose, from inside `structureSwitch`, so an arm that spells its exit
  // correctly and emits no body passes it. This reads the emitted text.
  //
  // Not gated in the run — one row can be legitimate, see `emptyCaseBodies` —
  // so a rise here is the ONLY alarm. `a lone goto` is the population it is
  // told apart from and must be read beside it: spelling every arm as a `goto`
  // would drive `bare` to 0 by saying nothing about any of them. The three
  // buckets sum to `case labels`, which moves with how many tables detection
  // recovers and is reported rather than judged.
  if (B.caseBodies && C.caseBodies) {
    row(
      "empty case bodies",
      (x) => x.caseBodies.bare,
      (a, c) => c > a,
      "A CASE SAYS IT DOES NOTHING",
    );
    row("  of those, functions", (x) => x.caseBodies.funcsAffected);
    row("  case labels", (x) => x.caseBodies.labels);
    row("  of those, a lone goto", (x) => x.caseBodies.gotoOnly);
    row("  of those, with a body", (x) => x.caseBodies.ownBlock);
    row("  switches emitted", (x) => x.caseBodies.switches);
  } else {
    note("  empty case bodies             NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A direct branch aimed outside the image (wildBranches.ts). ─────────────
  //
  // Gated at 0 in the run, so a rise here names which branch. `checked` is the
  // denominator and moves with detection like any instruction count; a FALL in
  // it to zero is an instrument that stopped observing, which is the only way
  // this gate can read green for the wrong reason. The count is a LOWER bound:
  // bytes read as code register here only when they happen to decode as a
  // direct branch whose displacement lands outside the image.
  if (B.wildBranches && C.wildBranches) {
    row(
      "branches outside the image",
      (x) => x.wildBranches.rows,
      (a, c) => c > a,
      "A FILED BRANCH NAMES AN ADDRESS THE IMAGE DOES NOT CONTAIN",
    );
    row(
      "  direct branches examined",
      (x) => x.wildBranches.checked,
      (a, c) => c === 0 && a > 0,
      "THE SCAN STOPPED SEEING BRANCHES AT ALL",
    );
  } else {
    note("  branches outside the image    NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A self-assignment in the emitted C (selfAssigns.ts). ──────────────────
  //
  // `openOperand` is the one that matters and it is NOT gated in the run: a
  // self-assignment whose instruction reads a value the emitted line is silent
  // about is either a legitimate zero-propagation or a LOST OPERAND, and telling
  // those apart is the dataflow question the audit does not answer. So a RISE
  // here is the signal — measured: disabling `peek-a-bin-3axd` takes it 1 -> 4
  // on both PE32 binaries. The corroboration split is the triage hint, so a rise
  // in the UNcorroborated half is the alarming shape; it is derived rather than
  // stored, since the stored field is the corroborated count.
  //
  // THE UNCORROBORATED HALF IS NOT A GATE AND MUST NOT BECOME ONE. `everyWriteZeroes`
  // follows a copy chain, so `peek-a-bin-o7pj`'s standing upgrade to gate it at 0 has
  // been discharged — and refused: an uncorroborated row says this SCAN could not
  // confirm the operand is zero, where an `arity over` row is provably an argument the
  // machine never passed. See `corpus/README.md` for the census and the refusal.
  //
  // `wrong` and `unresolved` ARE gated at 0 in the run, so a rise here names
  // which binary. `identity` is the denominator and is 0 on both x64 binaries
  // because `peek-a-bin-qbk3` emptied that population — a FALL in it on a PE32
  // binary is an instrument that stopped observing, which is the only way these
  // gates read green for the wrong reason.
  if (B.selfAssigns && C.selfAssigns) {
    row(
      "self-assign open operand",
      (x) => x.selfAssigns.openOperand,
      (a, c) => c > a,
      "A SELF-ASSIGNMENT WHOSE INSTRUCTION READS SOMETHING THE C DOES NOT MENTION",
    );
    row(
      "  of those, uncorroborated",
      (x) => x.selfAssigns.openOperand - x.selfAssigns.openZeroCorroborated,
      (a, c) => c > a,
      "NOTHING IN THE FUNCTION CORROBORATES THE MISSING OPERAND BEING ZERO",
    );
    row(
      "  wrong (name vs dest)",
      (x) => x.selfAssigns.wrong,
      (a, c) => c > a,
      "THE EMITTED NAME IS NOT AN ALIAS OF THE INSTRUCTION'S DESTINATION",
    );
    row(
      "  unresolved (unjudgeable)",
      (x) => x.selfAssigns.unresolved,
      (a, c) => c > a,
      "A SELF-ASSIGNMENT THAT RESOLVED TO NO INSTRUCTION",
    );
    row("  machine identities", (x) => x.selfAssigns.identity);
    row("  functions affected", (x) => x.selfAssigns.funcsAffected);
    row(
      "  emitted lines scanned",
      (x) => x.selfAssigns.lines,
      (a, c) => c === 0 && a > 0,
      "THE SCAN STOPPED READING EMITTED C AT ALL",
    );
    // The `for`-header half has its own way of matching nothing, and it is the
    // half whose pattern was hand-rolled (peek-a-bin-hfsq). A fall means a
    // header shape the grammar no longer recognises; a rise in `unsplittable`
    // means one it recognises and whose clauses it did not read. Both take rows
    // out of a scan that gates at 0 on `wrong` and `unresolved`.
    if (B.selfAssigns.forHeaders !== undefined && C.selfAssigns.forHeaders !== undefined) {
      row(
        "  for headers read",
        (x) => x.selfAssigns.forHeaders,
        (a, c) => c < a,
        "THE FOR-HEADER SCAN RECOGNISES FEWER LINES",
      );
      row(
        "  for headers unsplittable",
        (x) => x.selfAssigns.forHeadersUnsplit,
        (a, c) => c > a,
        "A FOR HEADER'S CLAUSES WERE NOT READ",
      );
    } else {
      note("  for headers read              NOT MEASURED on both sides (a run predating it)");
    }
  } else {
    note("  self-assignments              NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A call whose callee the output defines nowhere (undefinedCallees.ts). ──
  //
  // REPORT-ONLY in the run, so a RISE here is the whole signal. The two halves
  // have different owners and must not be added together: INTERNAL is a body
  // that IS in the output, in the same function, merely unconnected — the
  // emitter's business, and what `peek-a-bin-pf5g` is about — while EXTERNAL is
  // a function detection never produced or an indirect call through a data
  // pointer, which no emitter change reaches. Neither is gateable at 0: the
  // machine really does make the call and the name is derived from its target,
  // so a row is an incompleteness rather than a false statement. `calls` is the
  // liveness half, and a FALL in it to zero is a text scan that stopped
  // matching — the only way this reads clean for the wrong reason.
  if (B.undefinedCallees && C.undefinedCallees) {
    row(
      "undefined callees, internal",
      (x) => x.undefinedCallees.internal,
      (a, c) => c > a,
      "MORE CALLS TO A BODY THAT IS IN THIS FUNCTION BUT NOT CONNECTED TO THE CALL",
    );
    row("  of those, target labelled", (x) => x.undefinedCallees.internalLabelled);
    row("  distinct internal targets", (x) => x.undefinedCallees.internalDistinct);
    row("  functions affected", (x) => x.undefinedCallees.internalFuncs);
    row(
      "  undefined callees, external",
      (x) => x.undefinedCallees.external,
      (a, c) => c > a,
      "MORE CALLS TO A FUNCTION DETECTION DID NOT PRODUCE",
    );
    row("  distinct external targets", (x) => x.undefinedCallees.externalDistinct);
    row(
      "  sub_ call sites scanned",
      (x) => x.undefinedCallees.calls,
      (a, c) => c === 0 && a > 0,
      "THE SCAN STOPPED SEEING CALLS AT ALL",
    );
  } else {
    note("  undefined callees             NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A register name the image has no encoding for (emitAudits.ts). ─────────
  //
  // Gated at 0 in the run, so a rise here names which binary. PE32 ONLY: on the
  // x64 pair `rcx` is an ordinary correct spelling and the counts are
  // structurally 0, so a green row there says nothing at all — `funcs` beside it
  // is the liveness half, and a FALL in it is a scan that stopped observing.
  if (B.unencodable && C.unencodable) {
    row(
      "unencodable register names",
      (x) => x.unencodable.names,
      (a, c) => c > a,
      "THE C NAMES A REGISTER THIS IMAGE HAS NO ENCODING FOR",
    );
    row("  distinct such names", (x) => x.unencodable.distinct);
    row("  functions affected", (x) => x.unencodable.funcsAffected);
    row("  PE32 functions scanned", (x) => x.unencodable.funcs);
  } else {
    note("  unencodable register names    NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A struct member whose name and brackets disagree (emitAudits.ts). ──────
  //
  // Gated at 0 in the run, so a rise here names which binary. `members` and
  // `defs` beside it are the liveness halves: a FALL in either with the gate at
  // 0 is a text scrape that stopped matching, which reads green for want of
  // observation.
  if (B.memberNames && C.memberNames) {
    row(
      "member name vs brackets",
      (x) => x.memberNames.disagreeing,
      (a, c) => c > a,
      "A STRUCT MEMBER'S NAME AND ITS BRACKETS DISAGREE",
    );
    row("  field_ declared with []", (x) => x.memberNames.fieldNamedArrays);
    row("  array_ declared without", (x) => x.memberNames.arrayNamedScalars);
    row("  functions affected", (x) => x.memberNames.funcsAffected);
    row(
      "  struct members scanned",
      (x) => x.memberNames.members,
      (a, c) => c === 0 && a > 0,
      "THE MEMBER SCAN STOPPED MATCHING",
    );
    row("  struct definitions scanned", (x) => x.memberNames.defs);
  } else {
    note("  member name vs brackets       NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── Offset-named argument slots (emitAudits.ts). ───────────────────────────
  //
  // How much of the argument area the frame recovery is still missing. NOT a
  // gate in either direction: a fall is a recovery, and a rise can be function
  // detection moving underneath rather than a naming regression — but either
  // way it is a row rather than something the next agent has to think to count.
  if (B.offsetArgs && C.offsetArgs) {
    row("offset-named argument slots", (x) => x.offsetArgs.aligned);
    row("  distinct such names", (x) => x.offsetArgs.distinct);
    row("  functions affected", (x) => x.offsetArgs.funcsAffected);
    row("  sub-slot (correctly named)", (x) => x.offsetArgs.subSlot);
    row(
      "  functions scanned",
      (x) => x.offsetArgs.funcs,
      (a, c) => c < a,
      "THE SCAN STOPPED READING FUNCTIONS",
    );
  } else {
    note("  offset-named argument slots    NOT MEASURED on both sides (a run predating the audit)");
  }

  // ── A parameter a callee-saved register overwrites at entry (emitAudits.ts). ─
  //
  // A GATE at 0 in the run, and the row that discriminates where the one above
  // cannot: `offsetArgs` reaches its best value under BOTH a correct withdrawal
  // and the wrong naming variant, so a rise here is what separates them. Any
  // rise is a regression (peek-a-bin-15q7).
  if (B.paramClobber && C.paramClobber) {
    row(
      "params clobbered at entry",
      (x) => x.paramClobber.clobbered,
      (a, c) => c > a,
      "A DECLARED PARAMETER IS OVERWRITTEN BEFORE IT IS READ",
    );
    row("  distinct (function, param)", (x) => x.paramClobber.distinct);
    row("  functions affected", (x) => x.paramClobber.funcsAffected);
    row(
      "  declared params scanned",
      (x) => x.paramClobber.params,
      (a, c) => c < a,
      "THE SCAN STOPPED READING PARAMETERS",
    );
  } else {
    note("  params clobbered at entry     NOT MEASURED on both sides (a run predating the audit)");
  }

  // GUARDS LEAVING THE AUDITED SET IS ITSELF A SIGNAL. `polarity correct` below
  // is ok/checked, and a guard that stops being anchorable — or stops having a
  // single comparison operator, which is what an unrecovered condition is —
  // leaves BOTH sides of that fraction. The ratio stays at 1.00 and says
  // nothing. So the denominator is judged in its own right.
  //
  // THIS IS THE ONE GATE HERE THAT IS NOT "the change is wrong". It means
  // guards left the audited set and a human has to read them: the README
  // records a legitimate instance (41 guards left t32 at `4a4ec70`, every one
  // in a function that had gained a `switch`). What it will no longer do is
  // happen in silence.
  row(
    "polarity guards audited",
    (x) => x.polarity.checked,
    (a, c) => c < a,
    "FEWER GUARDS AUDITED — adjudicate, see README",
  );
  // The skip bucket an unrecovered condition lands in when the auditor COULD
  // anchor it. Summed over if/while/for/do_while, since the bucket key carries
  // the construct. It is a lower bound on the traffic across that boundary:
  // a guard whose body could not be anchored never reaches `judge` and is
  // skipped for an anchoring reason instead, so it is not counted here.
  if (B.skipReasons && C.skipReasons) {
    const notSingle = (x) =>
      Object.entries(x.skipReasons)
        .filter(([k]) => k.endsWith(":cond-not-single-comparison"))
        .reduce((n, [, v]) => n + v, 0);
    row("guards w/o single compare", notSingle, (a, c) => c > a, "MORE GUARDS UNJUDGEABLE");
  } else {
    note("  guards w/o single compare     NOT MEASURED on both sides (a run predating the audit)");
  }

  // THE POPULATION THE TWO ROWS ABOVE ARE DRAWN FROM. `polarity guards audited`
  // falling says guards left the audited set; this says whether the audit still
  // recognises the lines they came from at all. A guard-shaped line the grammar
  // refuses is `unparsed` and gates at 0 in the run itself, but a guard line
  // leaving the census ALTOGETHER is the other half of the same question and is
  // only visible between two pinned runs (peek-a-bin-vwr5).
  //
  // WHAT IS FLAGGED IS THE SUM, which is what that sentence has always meant:
  // `braced` and `inline` are two spellings of one top-tested guard, so a guard
  // moving between them loses nothing. The predicate was `braced` alone, which
  // does not match the rule its own comment stated, and `peek-a-bin-0qib` is the
  // first change to make `braced` fall legitimately — 572/550/512/515 lines with
  // `inline` rising by exactly the same, flagged as four regressions that were
  // not one. It is a widening and not a weakening: the hazard vwr5 measured as
  // control 1 (one-lining with the old grammar, `braced` down 572 and `inline`
  // still 0) takes the sum down by 572 and is still flagged, and a shape the
  // grammar refuses outright is `unparsed`, which gates at 0 in the run itself.
  if (B.guardShapes && C.guardShapes) {
    row(
      "guard lines unparsed",
      (x) => x.guardShapes.unparsed,
      (a, c) => c > a,
      "THE GUARD SCAN STOPPED UNDERSTANDING A LINE",
    );
    row(
      "guard lines seen (top-tested)",
      (x) => x.guardShapes.topTested + x.guardShapes.inline,
      (a, c) => c < a,
      "FEWER GUARD LINES RECOGNISED",
    );
    row("  of which braced", (x) => x.guardShapes.topTested);
    row("  of which brace-less", (x) => x.guardShapes.inline);
    row("  do/while tails seen", (x) => x.guardShapes.doTail);
  } else {
    note("  guard lines unparsed          NOT MEASURED on both sides (a run predating the audit)");
  }

  // Ratios. A denominator moving is fine; the fraction falling is not.
  const ratio = (name, num, den) => {
    const a = den(B) === 0 ? 1 : num(B) / den(B);
    const c = den(C) === 0 ? 1 : num(C) / den(C);
    const worse = c < a - 1e-12;
    if (worse) regressions++;
    note(
      `  ${name.padEnd(30)}${`${num(B)}/${den(B)}`.padStart(10)} -> ${`${num(C)}/${den(C)}`.padStart(10)}` +
        `${worse ? "   <<< REGRESSION (ratio fell)" : ""}`,
    );
  };
  ratio(
    "gcc clean",
    (x) => x.cc.clean,
    (x) => x.cc.compiled,
  );
  ratio(
    "offsetof fields correct",
    (x) => x.offsetof.fieldsCorrect,
    (x) => x.offsetof.fields,
  );
  ratio(
    "polarity correct",
    (x) => x.polarity.ok,
    (x) => x.polarity.checked,
  );
  // The share of declared-API calls whose emitted arity is the declared one —
  // the figure `peek-a-bin-qb2x` moved, and the one a regression in argument
  // recovery shows up in. The denominator moves with detection; the fraction
  // falling is the finding.
  if (B.arity && C.arity) {
    ratio(
      "arity exact",
      (x) => x.arity.exact,
      (x) => x.arity.sites,
    );
  }

  // A baseline, not a gate — see README. Reported because a move in it is worth
  // looking at even though a nonzero value is normal. LOST COVERAGE IS NOT A
  // MISSING STATEMENT: it can mean folded into a use, relocated, or genuinely
  // dropped, and only the emitted C read beside the machine text tells you which.
  const cov = (x) => x.lineMapCoverage;
  const covRow = (name, num, den) => {
    const a = `${num(cov(B))}/${den(cov(B))}`;
    const c = `${num(cov(C))}/${den(cov(C))}`;
    const fell = num(cov(C)) / den(cov(C)) < num(cov(B)) / den(cov(B)) - 1e-12;
    note(
      `  ${name.padEnd(30)}${a.padStart(10)} -> ${c.padStart(10)}` +
        `${fell ? "   (coverage fell — read the C, not a gate)" : ""}`,
    );
  };
  covRow(
    "BASELINE insns covered",
    (x) => x.insnsCovered,
    (x) => x.insnsTotal,
  );
  covRow(
    "BASELINE blocks covered",
    (x) => x.blocksTotal - x.blocksUncovered,
    (x) => x.blocksTotal,
  );
  if (B.tablesFrom || C.tablesFrom) {
    note(
      `  *** CROSS-SUBSTITUTED RUN: base=${B.tablesFrom ?? "own"} change=${C.tablesFrom ?? "own"}`,
    );
  }

  // ── Emitted C, function by function. ──────────────────────────────────
  //
  // The companion to cross-substitution: "byte-identical C" is the finding that
  // settles whether a change caused a difference or merely revealed it. Joined
  // on function ADDRESS, since names move when detection changes.
  {
    const fb = new Map(readFuncs(baseDir, b).map((f) => [f.addr, f.code]));
    const fc = new Map(readFuncs(chgDir, b).map((f) => [f.addr, f.code]));
    const shared = [...fb.keys()].filter((a) => fc.has(a));
    const same = shared.filter((a) => fb.get(a) === fc.get(a));
    const differing = shared.filter((a) => fb.get(a) !== fc.get(a));
    note(
      `  emitted C identical            ${`${same.length}/${shared.length}`.padStart(10)}` +
        ` functions in both${differing.length === 0 ? "   (byte-identical throughout)" : ""}`,
    );
    if (differing.length > 0 && differing.length <= 12) {
      const names = new Map(readFuncs(chgDir, b).map((f) => [f.addr, f.name]));
      note(
        `    differing: ${differing.map((a) => `${names.get(a)}@0x${a.toString(16)}`).join(" ")}`,
      );
    }
  }

  // ── The per-guard join. ────────────────────────────────────────────────
  const gb = new Map();
  const gc = new Map();
  for (const g of readGuards(baseDir, b)) {
    if (!gb.has(g.jcc)) gb.set(g.jcc, []);
    gb.get(g.jcc).push(g);
  }
  for (const g of readGuards(chgDir, b)) {
    if (!gc.has(g.jcc)) gc.set(g.jcc, []);
    gc.get(g.jcc).push(g);
  }
  const common = [...gb.keys()].filter((k) => gc.has(k));
  const onlyBase = [...gb.keys()].filter((k) => !gc.has(k));
  const onlyChange = [...gc.keys()].filter((k) => !gb.has(k));
  const changed = [];
  for (const k of common) {
    const a = gb.get(k).map(shapeOf).sort().join(" ;; ");
    const c = gc.get(k).map(shapeOf).sort().join(" ;; ");
    if (a !== c) changed.push({ jcc: k, fname: gb.get(k)[0].fname, a, c });
  }

  // ── What the join gates, and what it deliberately does not. ────────────
  //
  // The join was report-only: `changed`, `onlyBase` and `onlyChange` never
  // touched `regressions`, so this script exited 0 whatever it found here.
  //
  // Making CHANGED itself a regression would be wrong, and the reason is worth
  // stating. `shapeOf` includes `cond`, which is the emitted condition TEXT, so
  // it moves whenever any spelling improves — a type inference that turns
  // `*(int32_t*)(rbp - 0x64)` into `var_64` changes hundreds of guards without
  // touching a single one's meaning. Gating that would make "regression" mean
  // "something changed" and the verdict would stop meaning anything.
  //
  // What IS gated is the one dimension with a bad direction: a guard at a jcc
  // present on both sides whose ANCHOR-A verdict got worse. The aggregate
  // `polarity inverted` / `mismatch` rows already catch the count going up;
  // this catches the swap they cannot see, one guard fixed and another broken
  // in the same run. Anchor A only, matching the gate in `corpus.audit.ts` —
  // A2 carries two long-standing INVERTED verdicts on t64 and w64.
  const badA = (gs) => gs.filter((g) => g.anchor === "A" && g.verdict !== "OK").length;
  const worsened = common.filter((k) => badA(gc.get(k)) > badA(gb.get(k)));
  if (worsened.length > 0) {
    regressions++;
    note(`  *** ${worsened.length} guard(s) at a shared jcc got a WORSE anchor-A verdict:`);
    for (const k of worsened.slice(0, 20)) {
      note(
        `      <<< REGRESSION 0x${k.toString(16)} ${gc.get(k)[0].fname}: ` +
          `${gb
            .get(k)
            .map((g) => g.verdict)
            .join(",")} -> ${gc
            .get(k)
            .map((g) => g.verdict)
            .join(",")}`,
      );
    }
  }

  note(
    `  guards: ${gb.size} -> ${gc.size} distinct jccs; in both ${common.length}, ` +
      `CHANGED ${changed.length}, only-base ${onlyBase.length}, only-change ${onlyChange.length}`,
  );
  if (changed.length > 0) {
    note(
      `  ${"!".repeat(66)}\n` +
        `  !! ${changed.length} guard(s) SHARE A JCC ADDRESS AND SAY SOMETHING DIFFERENT.\n` +
        "  !! Not counted as a regression — the condition text moves for benign reasons\n" +
        "  !! (a better spelling of the same operand). READ THEM. This is report-only\n" +
        `  !! and the verdict line below does not account for it.\n  ${"!".repeat(66)}`,
    );
  }
  for (const c of changed.slice(0, 40)) {
    note(`    CHANGED 0x${c.jcc.toString(16)} ${c.fname}`);
    note(`      base: ${c.a}`);
    note(`      chg : ${c.c}`);
  }
  if (changed.length > 40) note(`    … and ${changed.length - 40} more`);
  if (onlyBase.length > 0) {
    note(
      `    guards only in BASE: ${onlyBase
        .sort((x, y) => x - y)
        .map((k) => `0x${k.toString(16)}(${gb.get(k)[0].fname})`)
        .slice(0, 60)
        .join(" ")}`,
    );
  }
  if (onlyChange.length > 0) {
    note(
      `    guards only in CHANGE: ${onlyChange
        .sort((x, y) => x - y)
        .map((k) => `0x${k.toString(16)}(${gc.get(k)[0].fname})`)
        .slice(0, 60)
        .join(" ")}`,
    );
  }
}

out.push("");
out.push(
  regressions === 0
    ? "VERDICT: no regression. Every invariant held and no ratio fell."
    : `VERDICT: ${regressions} regression(s) above, marked <<<.`,
);
out.push("A guard leaving the audited set is NOT automatically a regression — it can mean the");
out.push("function was restructured (a cascade becoming a switch, say) or that the auditor could");
out.push("no longer anchor it. It is nevertheless FLAGGED now, by `polarity guards audited` and");
out.push("`guards w/o single compare`, because the alternative was silence: guards leaving that");
out.push("set used to move no number at all, while `polarity correct` sat at 1.00. Read the");
out.push("emitted C for those functions before judging.");
out.push("");
out.push("NOT accounted for in the verdict: CHANGED guards at a shared jcc (report-only, see the");
out.push('banner), and every defect class in README.md\'s "What the standing set does NOT catch".');
process.stdout.write(`${out.join("\n")}\n`);
process.exit(regressions === 0 ? 0 : 1);
