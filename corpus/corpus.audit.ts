/**
 * THE ENTRY POINT for the corpus audits: `npm run corpus`.
 *
 * This file is NOT part of `npm test`. It is named `.audit.ts` rather than
 * `.test.ts` so vitest's default include cannot match it, and it runs through
 * its own config (`vitest.corpus.config.ts`). `build/corpusIsolation.test.ts`
 * fails the ordinary suite if either of those ever stops being true — because
 * the failure mode is CI trying to disassemble binaries it does not have.
 *
 * WHAT EACH AUDIT PROVES, and what a failure means, is in `corpus/README.md`.
 * Read it before acting on a red run: some of these numbers are baselines
 * rather than gates, and one of them has never been zero.
 *
 * If the corpus binaries or a C compiler are missing, every audit is SKIPPED —
 * not passed — and the missing paths are named on stdout and in the skip.
 *
 * Note on output: vitest's default reporter DISCARDS console.log from inside a
 * test but passes `process.stdout.write` through, which is why the report is
 * written that way. It is also saved to `report.txt` beside the artifacts.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import {
  type CcResult,
  ccSyntaxCheck,
  gotoCheck,
  type OffsetofResult,
  offsetofCheck,
} from "./emitAudits";
import { type BinKey, corpusDir, DOC_BINS, preflight } from "./preflight";
import { type BinResult, sweepBinary } from "./sweep";

const pre = preflight();

/** Where artifacts land. A label keeps two runs (e.g. two commits) apart. */
const label = process.env.PEEK_CORPUS_LABEL ?? "local";
const artifactDir = join(
  process.env.PEEK_CORPUS_OUT ?? new URL("./artifacts", import.meta.url).pathname,
  label,
);

const results = new Map<BinKey, BinResult>();
const ccResults = new Map<BinKey, CcResult>();
const ozResults = new Map<BinKey, OffsetofResult>();

const auditedKeys = (): BinKey[] => [...results.keys()];
function over<T>(keys: readonly BinKey[], m: Map<BinKey, T>): T[] {
  return keys.filter((k) => m.has(k)).map((k) => m.get(k) as T);
}
const sum = <T>(xs: T[], f: (x: T) => number) => xs.reduce((a, x) => a + f(x), 0);

if (!pre.haveBins || !pre.haveCc) {
  process.stdout.write(
    `\n${"═".repeat(78)}\nCORPUS AUDITS SKIPPED — nothing was verified.\n  ${pre.reason}\n` +
      (pre.haveBins
        ? ""
        : "  The binaries are real PE files, deliberately not in the repo; point\n" +
          "  PEEK_CORPUS_DIR at a copy if you have one.\n") +
      `  See corpus/README.md.\n${"═".repeat(78)}\n\n`,
  );
  describe("corpus audits", () => {
    // A dynamic test NAME, so the reason survives whatever the reporter prints:
    // a skip whose reason lives only in an API the reporter ignores is
    // indistinguishable from a pass, which is the one outcome forbidden here.
    it.skip(`SKIPPED — ${pre.reason}`, () => {});
  });
} else {
  describe("corpus audits", () => {
    beforeAll(async () => {
      mkdirSync(artifactDir, { recursive: true });
      for (const key of pre.present) {
        // ONE load + decompile pass per binary; every audit below reads it.
        // See sweep.ts on why a per-audit pass would measure a different
        // program (StructRegistry is shared for the lifetime of the file).
        const r = await sweepBinary(key);
        results.set(key, r);
        const sets = [{ tag: key, funcs: r.funcs }];
        ccResults.set(key, ccSyntaxCheck(pre.cc, join(artifactDir, "cc", key), sets));
        ozResults.set(key, offsetofCheck(pre.cc, join(artifactDir, "offsetof", key), sets));

        // Written per binary rather than at the end, so a run that dies on the
        // fourth binary still leaves the first three on disk.
        writeFileSync(
          join(artifactDir, `guards_${key}.jsonl`),
          r.guards.map((g) => JSON.stringify(g)).join("\n") + (r.guards.length > 0 ? "\n" : ""),
        );
        writeFileSync(
          join(artifactDir, `funcs_${key}.jsonl`),
          `${r.funcs.map((f) => JSON.stringify(f)).join("\n")}\n`,
        );
        // The recovered tables, so a run at another commit can be handed them
        // with PEEK_CORPUS_TABLES. See preflight.ts on what that isolates.
        writeFileSync(join(artifactDir, `jumpTables_${key}.json`), r.jumpTablesJson);
        writeFileSync(
          join(artifactDir, `summary_${key}.json`),
          JSON.stringify(
            {
              ...r,
              guards: r.guards.length,
              funcs: r.funcs.length,
              jumpTablesJson: undefined,
              cc: ccResults.get(key),
              offsetof: ozResults.get(key),
            },
            null,
            1,
          ),
        );
      }
      const report = renderReport();
      writeFileSync(join(artifactDir, "report.txt"), `${report}\n`);
      process.stdout.write(`\n${report}\n\n`);
    }, 3_600_000);

    // ── Gates. A failure in any of these is a defect in the decompiler. ────
    //
    // Each asserts on a STRING naming the offenders before asserting on the
    // count, so a failure reports which function and which address rather than
    // "expected 3 to be 0".

    it("raises nothing while decompiling any function", () => {
      for (const r of results.values()) {
        expect(`${r.key}: ${r.throwDetail.slice(0, 3).join(" | ")}`).toBe(`${r.key}: `);
        expect(r.throws).toBe(0);
      }
    });

    it("states every guard at the polarity of the jcc it came from", () => {
      for (const r of results.values()) {
        // Anchor A only. A2 and B are reported but never gate — see README.
        const bad = r.guards.filter((g) => g.anchor === "A" && g.verdict !== "OK");
        expect(
          `${r.key} bad guards: ${bad
            .map(
              (g) =>
                `${g.verdict} 0x${g.jcc.toString(16)} ${g.fname} (${g.cond}) want ${g.expect} got ${g.emitted}`,
            )
            .join("; ")}`,
        ).toBe(`${r.key} bad guards: `);
        expect(r.polarity.inverted).toBe(0);
        expect(r.polarity.mismatch).toBe(0);
        // An audit that stopped anchoring anything would pass vacuously.
        expect(r.polarity.checked).toBeGreaterThan(100);
      }
    });

    it("tells every loop about every way the machine can leave it", () => {
      for (const r of results.values()) {
        expect(
          `${r.key} short: ${r.loopShort
            .map(
              (l) =>
                `${l.fname}@line${l.line} emitted ${l.emittedExits} < machine ${l.machineExits}`,
            )
            .join("; ")}`,
        ).toBe(`${r.key} short: `);
        expect(r.loops.short).toBe(0);
        expect(r.loops.audited).toBeGreaterThan(10);
      }
    });

    it("names every callee the disassembly names", () => {
      for (const r of results.values()) {
        expect(`${r.key} lost: ${r.callees.detail.slice(0, 5).join("; ")}`).toBe(`${r.key} lost: `);
        expect(r.callees.lost).toBe(0);
        expect(r.callees.pairs).toBeGreaterThan(0);
      }
    });

    it("resolves every goto to a label the same function defines", () => {
      const g = gotoCheck(over(auditedKeys(), results).map((r) => ({ funcs: r.funcs })));
      expect(g.dangling).toBe(0);
      expect(g.gotos).toBeGreaterThan(0);
    });

    it("emits C that a C compiler accepts, for every function", () => {
      for (const [key, r] of ccResults) {
        expect(
          `${key}: ${r.byCategory.map((c) => `${c.n}x ${c.category} (${c.examples.join(",")})`).join("; ")}`,
        ).toBe(`${key}: `);
        expect(r.clean).toBe(r.compiled);
        expect(r.compiled).toBeGreaterThan(0);
      }
    });

    it("lays every struct field out at the offset its name records", () => {
      for (const [key, r] of ozResults) {
        expect(`${key}: ${r.bad.join("; ")}`).toBe(`${key}: `);
        expect(r.fieldsCorrect).toBe(r.fields);
        expect(r.defsCorrect).toBe(r.defs);
        expect(r.uncompilable).toBe(0);
      }
    });
  });
}

function renderReport(): string {
  const keys = auditedKeys();
  const L: string[] = [];
  const pct = (n: number, d: number) => (d === 0 ? "n/a" : `${((100 * n) / d).toFixed(1)}%`);

  L.push(`corpus audit — label=${label}`);
  L.push(`  corpus dir: ${corpusDir()}`);
  L.push(`  compiler:   ${pre.cc}`);
  L.push(`  binaries:   ${keys.join(", ")}`);
  // Loud, because a substituted run is NOT a measurement of this commit and
  // must never be quoted as one.
  const subbed = keys.filter((k) => (results.get(k) as BinResult).tablesFrom !== null);
  if (subbed.length > 0) {
    L.push("");
    L.push(`  *** CROSS-SUBSTITUTION RUN — ${subbed.join(", ")} used ANOTHER run's jump tables.`);
    L.push("  *** These numbers do not describe this commit as it would actually behave.");
  }
  L.push("");

  for (const key of keys) {
    const r = results.get(key) as BinResult;
    const c = ccResults.get(key) as CcResult;
    const o = ozResults.get(key) as OffsetofResult;
    L.push(`── ${key} ${"─".repeat(58)}`);
    L.push(
      `  functions ${r.functions}   instructions ${r.instructions}   jumpTables ${r.jumpTables}`,
    );
    L.push(`  throws                      ${r.throws}`);
    L.push(
      `  polarity (anchor A)         ${r.polarity.ok}/${r.polarity.checked} correct   ` +
        `inverted=${r.polarity.inverted} mismatch=${r.polarity.mismatch} skipped=${r.polarity.skipped}`,
    );
    L.push(
      `    anchor A2 (not a gate)    ${r.polarity.a2Ok}/${r.polarity.a2Checked}   ` +
        `anchor B (heuristic)  ${r.polarity.weakOk}/${r.polarity.weakChecked}`,
    );
    L.push(
      `  loop exit coverage          ${r.loops.audited} audited, ${r.loops.short} short of the machine`,
    );
    L.push(`  distinct callees lost       ${r.callees.lost} of ${r.callees.pairs}`);
    L.push(`  gcc -fsyntax-only           ${c.clean}/${c.compiled} clean`);
    L.push(
      `  offsetof (compiled and run) ${o.fieldsCorrect}/${o.fields} fields, ` +
        `${o.distinctCorrect}/${o.distinctDefs} distinct definitions`,
    );
    const cov = r.lineMapCoverage;
    L.push(
      `  BASELINE line map coverage  ${cov.insnsCovered}/${cov.insnsTotal} instructions ` +
        `(${pct(cov.insnsCovered, cov.insnsTotal)}), ` +
        `${cov.blocksTotal - cov.blocksUncovered}/${cov.blocksTotal} blocks ` +
        `(${pct(cov.blocksTotal - cov.blocksUncovered, cov.blocksTotal)}) — NOT a gate`,
    );
    L.push("    lost coverage means no address mapped: folded into a use, relocated, OR dropped.");
    L.push("    Telling those apart needs the emitted C read beside the machine text.");
    if (r.tablesFrom !== null) {
      L.push(`  *** CROSS-SUBSTITUTED jump tables from ${r.tablesFrom}`);
    }
  }

  const g = gotoCheck(over(keys, results).map((r) => ({ funcs: r.funcs })));
  L.push("");
  L.push(`── totals ${"─".repeat(54)}`);
  L.push(`  gotos ${g.gotos}, labels ${g.labels}, dangling ${g.dangling}`);

  // The subset CLAUDE.md's documented gcc and offsetof figures are measured
  // over. Reporting it separately is what makes a claim in that file checkable
  // against a run here: four-binary totals are NOT comparable with it.
  const doc = DOC_BINS.filter((k) => results.has(k));
  if (doc.length === DOC_BINS.length) {
    const cs = over(doc, ccResults);
    const os = over(doc, ozResults);
    const rs = over(doc, results);
    L.push("");
    L.push(`  COMPARABLE WITH CLAUDE.md (${DOC_BINS.join(" + ")} only):`);
    L.push(`    gcc         ${sum(cs, (c) => c.clean)}/${sum(cs, (c) => c.compiled)}`);
    L.push(
      `    offsetof    ${sum(os, (o) => o.fieldsCorrect)}/${sum(os, (o) => o.fields)} fields` +
        ` across ${sum(os, (o) => o.distinctDefs)} distinct definitions`,
    );
    L.push(
      `    polarity    ${sum(rs, (r) => r.polarity.ok)}/${sum(rs, (r) => r.polarity.checked)} correct,` +
        ` ${sum(rs, (r) => r.polarity.inverted)} inverted`,
    );
  }
  L.push("");
  L.push(`  artifacts: ${artifactDir}`);
  return L.join("\n");
}
