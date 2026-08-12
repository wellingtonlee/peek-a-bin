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
 * Plain node, no TypeScript: `tsx` does not work on this machine (Node 18,
 * ERR_REQUIRE_ESM), and this reads only the artifacts, never the repo's source.
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

  const row = (name, get, worseIf) => {
    const a = get(B);
    const c = get(C);
    const worse = worseIf ? worseIf(a, c) : false;
    if (worse) regressions++;
    const mark = worse ? "   <<< REGRESSION" : a === c ? "" : "   (moved)";
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

  note(
    `  guards: ${gb.size} -> ${gc.size} distinct jccs; in both ${common.length}, ` +
      `CHANGED ${changed.length}, only-base ${onlyBase.length}, only-change ${onlyChange.length}`,
  );
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
out.push("no longer anchor it. Read the emitted C for those functions before judging.");
process.stdout.write(`${out.join("\n")}\n`);
process.exit(regressions === 0 ? 0 : 1);
