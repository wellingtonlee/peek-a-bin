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
import { type ArityResult, auditApiArity } from "./arity";
import {
  type CcResult,
  ccSyntaxCheck,
  gotoCheck,
  type OffsetofResult,
  offsetNamedArgs,
  offsetofCheck,
  paramClobberedAtEntry,
  unencodableNames,
} from "./emitAudits";
import { type BinKey, corpusDir, corpusDirSource, DOC_BINS, preflight } from "./preflight";
import { type BinResult, sweepBinary } from "./sweep";
import { auditUndefinedCallees, type UndefinedCalleeResult } from "./undefinedCallees";

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
const arResults = new Map<BinKey, ArityResult>();
const ucResults = new Map<BinKey, UndefinedCalleeResult>();

const auditedKeys = (): BinKey[] => [...results.keys()];
function over<T>(keys: readonly BinKey[], m: Map<BinKey, T>): T[] {
  return keys.filter((k) => m.has(k)).map((k) => m.get(k) as T);
}
const sum = <T>(xs: T[], f: (x: T) => number) => xs.reduce((a, x) => a + f(x), 0);

if (!pre.haveBins || !pre.haveCc) {
  // `detail` is the discovery half: every directory that was probed, what was
  // wrong with each, and the two ways to say where the binaries really are.
  // "I found nothing" on its own is what let a wrong default sit unnoticed
  // (`peek-a-bin-alx1`); the useful output is "here is how to tell me".
  process.stdout.write(
    `\n${"═".repeat(78)}\nCORPUS AUDITS SKIPPED — nothing was verified.\n  ${pre.reason}\n\n` +
      (pre.detail === "" ? "" : `${pre.detail}\n`) +
      `${"═".repeat(78)}\n\n`,
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
        // The ONE audit here with an oracle that can see call arity. gcc cannot:
        // it accepts an implicit declaration at any arity, and `preludeFor`
        // declares every undeclared identifier as its own `long`.
        arResults.set(key, auditApiArity(r.funcs, r.is64));
        // Every emitted call whose callee is defined nowhere in the output,
        // split by whether the target is inside the caller's own extent. Report
        // only, in both directions — see `undefinedCallees.ts` on why an
        // undefined callee is an incompleteness rather than a false statement.
        ucResults.set(key, auditUndefinedCallees([{ funcs: r.funcs }]));

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
        // Every statement the structurer dropped, per site. Written even when
        // empty, so its absence means the audit did not run rather than that
        // it found nothing.
        writeFileSync(
          join(artifactDir, `drops_${key}.jsonl`),
          r.drops.map((d) => JSON.stringify(d)).join("\n") + (r.drops.length > 0 ? "\n" : ""),
        );
        // Every `__unrecovered_N` in the emitted C, per site. NONE of these
        // appear in guards_<key>.jsonl — an unrecovered condition is not a
        // failing polarity row, it is not a row at all — which is exactly why
        // they get a file of their own.
        writeFileSync(
          join(artifactDir, `unrecovered_${key}.jsonl`),
          r.unrecoveredSites.map((s) => JSON.stringify(s)).join("\n") +
            (r.unrecoveredSites.length > 0 ? "\n" : ""),
        );
        // The recovered tables, so a run at another commit can be handed them
        // with PEEK_CORPUS_TABLES. See preflight.ts on what that isolates.
        // Every version-0 read the lowering left naming a register that holds
        // something else, and every entry-value copy taken after the damage.
        // Written even when empty — the standing expectation is that both are,
        // and an absent file has to mean the audit did not run.
        writeFileSync(
          join(artifactDir, `stalev0_${key}.jsonl`),
          [...r.staleV0.rows, ...r.staleV0.corrupt].map((x) => JSON.stringify(x)).join("\n") +
            (r.staleV0.rows.length + r.staleV0.corrupt.length > 0 ? "\n" : ""),
        );
        // Every emitted call to an API `apitypes.ts` declares whose arity does
        // not match the declaration — the OVER rows first, since an over-count
        // is an argument the emitter invented and there is no reading of the
        // machine on which it is right. Written even when empty, so an absent
        // file means the audit did not run rather than that it found nothing.
        const ar = arResults.get(key) as ArityResult;
        const arBad = [
          ...ar.rows.filter((x) => x.verdict === "over"),
          ...ar.rows.filter((x) => x.verdict === "under"),
        ];
        writeFileSync(
          join(artifactDir, `arity_${key}.jsonl`),
          arBad.map((x) => JSON.stringify(x)).join("\n") + (arBad.length > 0 ? "\n" : ""),
        );
        // Every block whose trailing jcc reads flags the recovered compare does
        // not describe, with the emitted condition where one reached the page.
        // Written even when empty — the standing expectation is that `named` is
        // 0 while `shapes` is not, and an absent file has to mean the audit did
        // not run rather than that it found nothing.
        writeFileSync(
          join(artifactDir, `staleguards_${key}.jsonl`),
          r.staleGuards.rows.map((x) => JSON.stringify(x)).join("\n") +
            (r.staleGuards.rows.length > 0 ? "\n" : ""),
        );
        // Every cross-edge block whose incoming edges make different tests,
        // with the emitted condition where one reached the page. Written even
        // when empty, because the standing claim is that `named` is 0 while
        // `differ` is not — an absent file has to mean the audit did not run.
        writeFileSync(
          join(artifactDir, `crossedgeguards_${key}.jsonl`),
          r.crossEdgeGuards.rows.map((x) => JSON.stringify(x)).join("\n") +
            (r.crossEdgeGuards.rows.length > 0 ? "\n" : ""),
        );
        // Every read of a register a `pop` wrote that the emitted C still names
        // under its previous value. Written even when empty, so an absent file
        // means the audit did not run rather than that it found nothing.
        writeFileSync(
          join(artifactDir, `popreads_${key}.jsonl`),
          r.popReads.rows.map((x) => JSON.stringify(x)).join("\n") +
            (r.popReads.rows.length > 0 ? "\n" : ""),
        );
        // Every (block, register) whose reaching definition the fold removed.
        // Written even when empty, because the standing claim about this one is
        // that it IS empty — an absent file has to mean the audit did not run.
        writeFileSync(
          join(artifactDir, `lostdefs_${key}.jsonl`),
          r.lostDefs.rows.map((x) => JSON.stringify(x)).join("\n") +
            (r.lostDefs.rows.length > 0 ? "\n" : ""),
        );
        // Every switch arm closed with `break` while its own block has a
        // successor. Written even when empty, because the standing claim about
        // this one is that it IS empty — an absent file has to mean the audit
        // did not run.
        writeFileSync(
          join(artifactDir, `armexits_${key}.jsonl`),
          r.armExits.rows.map((x) => JSON.stringify(x)).join("\n") +
            (r.armExits.rows.length > 0 ? "\n" : ""),
        );
        // Every filed direct branch aimed outside the image. Written even when
        // empty, for the same reason `armexits_` is: the standing claim is that
        // it IS empty, so an absent file must not read as a clean run.
        writeFileSync(
          join(artifactDir, `wildbranches_${key}.jsonl`),
          r.wildBranches.rows.map((x) => JSON.stringify(x)).join("\n") +
            (r.wildBranches.rows.length > 0 ? "\n" : ""),
        );
        // Every self-assignment in the emitted C with the instruction it
        // resolved to, idiom rows included — the idiom count is this audit's
        // liveness denominator, so a file holding only the failures would make
        // a vacuous zero indistinguishable from a clean one.
        writeFileSync(
          join(artifactDir, `selfassigns_${key}.jsonl`),
          r.selfAssigns.rows.map((x) => JSON.stringify(x)).join("\n") +
            (r.selfAssigns.rows.length > 0 ? "\n" : ""),
        );
        // Every emitted call to an identifier the output never defines, the
        // INTERNAL rows first — those are the ones an emitter change could
        // reach. Written even when empty, so an absent file means the audit did
        // not run rather than that every call resolves.
        {
          const uc = ucResults.get(key) as UndefinedCalleeResult;
          const ordered = [...uc.rows].sort((a, b) => Number(b.internal) - Number(a.internal));
          writeFileSync(
            join(artifactDir, `undefinedcallees_${key}.jsonl`),
            ordered.map((x) => JSON.stringify(x)).join("\n") + (ordered.length > 0 ? "\n" : ""),
          );
        }
        writeFileSync(join(artifactDir, `jumpTables_${key}.json`), r.jumpTablesJson);
        writeFileSync(
          join(artifactDir, `summary_${key}.json`),
          JSON.stringify(
            {
              ...r,
              staleV0: {
                ...r.staleV0,
                rows: r.staleV0.rows.length,
                corrupt: r.staleV0.corrupt.length,
              },
              staleGuards: { ...r.staleGuards, rows: r.staleGuards.rows.length },
              crossEdgeGuards: { ...r.crossEdgeGuards, rows: r.crossEdgeGuards.rows.length },
              popReads: { ...r.popReads, rows: r.popReads.rows.length },
              lostDefs: { ...r.lostDefs, rows: r.lostDefs.rows.length },
              armExits: { ...r.armExits, rows: r.armExits.rows.length },
              wildBranches: { ...r.wildBranches, rows: r.wildBranches.rows.length },
              selfAssigns: { ...r.selfAssigns, rows: r.selfAssigns.rows.length },
              guards: r.guards.length,
              funcs: r.funcs.length,
              drops: r.drops.length,
              unrecoveredSites: r.unrecoveredSites.length,
              jumpTablesJson: undefined,
              cc: ccResults.get(key),
              offsetof: ozResults.get(key),
              arity: { ...ar, rows: ar.rows.length },
              // Per binary rather than only in the totals, so `compare.mjs` can
              // judge it. Structurally 0 on the x64 pair — see
              // `unencodableNames` on why the question is PE32-only — which is
              // why `funcs` is beside it as the liveness half.
              unencodable: unencodableNames([{ funcs: r.funcs, is64: r.is64 }]),
              // How much of the argument area the frame recovery is still
              // missing. Report-only in both directions — see `offsetNamedArgs`
              // on why a residue is legitimate — and per binary so
              // `compare.mjs` can name which one moved.
              offsetArgs: offsetNamedArgs([{ funcs: r.funcs, is64: r.is64 }]),
              // The question `offsetArgs` above CANNOT answer: that row reaches 0
              // both when a slot is correctly withdrawn and when every slot is
              // wrongly named, so this asks it over the declared parameter list
              // instead, where the two differ (peek-a-bin-15q7).
              paramClobber: (() => {
                const p = paramClobberedAtEntry([{ funcs: r.funcs }]);
                return { ...p, rows: p.rows.length };
              })(),
              // A call the reader cannot follow. Per binary because the two
              // halves have different owners and only the INTERNAL one is an
              // emitter question; `compare.mjs` judges a rise in each.
              undefinedCallees: (() => {
                const uc = ucResults.get(key) as UndefinedCalleeResult;
                return { ...uc, rows: uc.rows.length };
              })(),
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
        // A2 does not gate — see README on why it has no oracle over the output
        // — but it needs the same liveness half, and for a sharper reason than
        // anchor A does. `peek-a-bin-1qqx` removed 4 A2 rows per x64 binary by
        // refusing a (jcc, sense) two guards claim, which is the right fix for
        // that shape and is also exactly the shape of the WRONG fix: a rule
        // that refused more broadly would drive A2's reported failures to 0 by
        // no longer looking, and the report would read better for it. Measured
        // at cc45263: 391/234/216/369 on t32/t64/w64/w32.
        expect(r.polarity.a2Checked).toBeGreaterThan(100);
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

    /**
     * A GATE, and the one audit in this file whose count was moved to zero by a
     * fix rather than found there. `corpus/staleReads.ts` argues why it is a
     * gate when the two BASELINE audits below are not: every row is a register
     * name the emitted C applies to a value the SSA says it does not hold, so
     * a non-zero count is a wrong answer, not a threshold judgement.
     *
     * Both liveness assertions matter. `sites` non-zero says the audit still
     * finds the *shape* — a version-0 read a dominating definition overwrote —
     * which is common and is not itself a defect once the value is preserved.
     * `copies` non-zero says it can still see the preservation; that check
     * depends on `ssadestroy.ts` spelling a preserved entry value `<reg>_0`,
     * and a spelling change would otherwise turn every repaired site back into
     * a reported defect.
     */
    it("never names a register for a value it no longer holds", () => {
      for (const r of results.values()) {
        const v = r.staleV0;
        expect(
          `${r.key} stale: ${v.rows
            .slice(0, 5)
            .map((x) => `${x.func}@0x${(x.addr ?? 0).toString(16)} ${x.reg} ${x.verdict}`)
            .join("; ")}`,
        ).toBe(`${r.key} stale: `);
        expect(v.wrong).toBe(0);
        expect(
          `${r.key} spoiled repairs: ${v.corrupt
            .slice(0, 5)
            .map((x) => `${x.func} blk${x.block} ${x.name}`)
            .join("; ")}`,
        ).toBe(`${r.key} spoiled repairs: `);
        expect(v.copiesCorrupted).toBe(0);
        expect(v.sites).toBeGreaterThan(0);
        expect(v.copies).toBeGreaterThan(0);
      }
    });

    /**
     * A GATE at 0 on `named`, and it earns that on the same terms
     * `staleV0` does rather than by analogy: every row is an emitted `if`
     * stating a test the machine does not make — the right operator over
     * operands a later instruction took away — which is a wrong answer, not a
     * count awaiting a threshold. It reached 0 by a fix (peek-a-bin-jitf,
     * peek-a-bin-xe01), not by being found there: with both fixes disabled it
     * reports 29/5/3/21 named on t32/t64/w64/w32 at `e22ba6e`, and those 58
     * are precisely the 58 guards `compare.mjs` independently reports leaving
     * the audited set over the same pair of runs.
     *
     * Two liveness assertions, and they answer different questions. `blocks`
     * says the audit examined this binary at all — it is thousands, so it is
     * the robust "did it run" check. `shapes` says the audit can still FIND
     * the shape it exists to watch, and is asserted over the corpus TOTAL
     * rather than per binary: it is 6 on w64, thin enough that a legitimate
     * detection change could take one binary to 0 without the instrument
     * having gone blind.
     *
     * `named` is a LOWER bound — it counts only guards the polarity pass could
     * anchor to a jcc. The other 48 spoiled readings in this corpus were
     * equally wrong on the page and merely unanchorable. See
     * `corpus/staleGuards.ts`.
     *
     * Since peek-a-bin-xskz `named` is no longer "a guard is emitted here at
     * all": the lifter can materialise a spoiled compare's operands, so a guard
     * at a spoiled jcc is routinely correct and the count now asks whether the
     * emitted condition MENTIONS something the spoiler could have written. The
     * old number is `emittedAtShape`, reported beside it and deliberately not
     * gated — it is the recovery.
     */
    it("never states a guard over operands the machine took away", () => {
      let shapes = 0;
      for (const r of results.values()) {
        const sg = r.staleGuards;
        shapes += sg.shapes;
        expect(
          `${r.key} wrong-operand: ${sg.rows
            .filter((x) => x.why !== null)
            .slice(0, 5)
            .map((x) => `${x.func}@0x${x.jcc.toString(16)} ${x.kind} ${x.why} '${x.emitted}'`)
            .join("; ")}`,
        ).toBe(`${r.key} wrong-operand: `);
        expect(sg.named).toBe(0);
        expect(sg.blocks).toBeGreaterThan(0);
      }
      expect(shapes).toBeGreaterThan(0);
    });

    /**
     * A GATE at 0, for the class every audit above is structurally blind to.
     *
     * A Jcc alone in its basic block reads flags set before the block was
     * entered. Where several predecessors set them from DIFFERENT tests, no
     * single block-local `if` states the machine, and a guard emitted there is
     * a test the machine does not make on at least one path in. Every row is
     * therefore provably wrong output rather than a count awaiting a threshold,
     * which is `polarity inverted`'s character and is what makes it gateable.
     *
     * It is a gate on the day it lands because it lands at 0: `unanimousCompare`
     * already refuses all 12 disagreeing sites in this corpus. What it buys is
     * that a RELAXATION of that refusal is red rather than green. Negative-
     * controlled at 16f1633 — drop the agreement test and answer such a block
     * from its first predecessor, and this names 2/5/4/1 rows, including
     * `t64!sub_140002A2C` at 0x140002afd, whose emitted `if (rbx_2 == 0)` sits
     * on a block the other edge reaches having tested RBP. Every other gate in
     * this file passes that control, and the recovery baseline scores it as an
     * IMPROVEMENT, unrecovered values falling by 12.
     *
     * TWO GATED COUNTS, and the reason for both is that the stronger claim has
     * the weaker coverage. `named` is a guard anchored on the page — a test the
     * machine does not make, in C that compiles — but the polarity pass anchors
     * only some guards, so under the control it sees 8 of the 12 sites and NOT
     * the `sub_140002A2C` witness, whose `if (rbx_2 == 0)` is on the page at
     * emitted line 67 with no anchor to hang it on. `admitted` is the complete
     * one: both routes to a condition at such a jcc take their stream from
     * `flagScanStream(block, flagPredecessor(…))`, so an admitted predecessor
     * is necessary for either to spell anything, and it is address-exact —
     * 12 of 12 under the control. It reads the decision the code made rather
     * than the text it produced, which makes that half a differential test
     * between two independently written answers to the same question rather
     * than an oracle outside it.
     *
     * FOUR liveness assertions, because this audit measures an absence and four
     * different things could make the absence vacuous. `blocks` says it
     * examined the binary at all — thousands, so it is the robust "did it run"
     * check. `differ` says it can still find the machine-code shape it watches,
     * and is asserted over the corpus TOTAL rather than per binary: it is 1 on
     * w32, thin enough that a legitimate detection change could take one binary
     * to 0 without the instrument having gone blind. `soleAdmitted === sole`
     * says `flagPredecessor` is still what decides this, so `admitted` is 0 for
     * want of a defect rather than for want of looking. `soleNamed` says the
     * same about the anchoring behind `named`.
     *
     * See `corpus/crossEdgeGuards.ts` for why the presence of a guard is the
     * whole question today, and for the one mechanism that would require
     * sharpening it (peek-a-bin-0xe2).
     */
    it("never answers a jcc from an edge that disagrees with the others", () => {
      let differ = 0;
      let soleNamed = 0;
      for (const r of results.values()) {
        const ce = r.crossEdgeGuards;
        differ += ce.differ;
        soleNamed += ce.soleNamed;
        expect(
          `${r.key} cross-edge: ${ce.rows
            .filter((x) => x.gated && x.admittedFrom !== null)
            .slice(0, 6)
            .map(
              (x) =>
                `${x.func}@0x${x.jcc.toString(16)} answered from ` +
                `0x${(x.admittedFrom ?? 0).toString(16)} ${x.emitted === null ? "(refused downstream)" : `'${x.emitted}'`} ` +
                `— edges ${x.edges.map((e) => `0x${e.pred.toString(16)}:${e.ownerText}`).join(" | ")}`,
            )
            .join("; ")}`,
        ).toBe(`${r.key} cross-edge: `);
        expect(ce.admitted).toBe(0);
        expect(ce.named).toBe(0);
        expect(ce.blocks).toBeGreaterThan(0);
        // `flagPredecessor` still being consulted, which is what stops
        // `admitted` reading 0 for want of looking. A cross-edge block with one
        // predecessor is exactly the shape the rule answers freely, so the two
        // are equal on a healthy tree rather than merely non-zero.
        expect(ce.soleAdmitted).toBe(ce.sole);
      }
      expect(differ).toBeGreaterThan(0);
      expect(soleNamed).toBeGreaterThan(0);
    });

    /**
     * A GATE at 0, and it became one the moment a fix got it there.
     *
     * A register a `pop` wrote and the emitted C still names under its previous
     * value is a provably wrong name — a store through the wrong pointer, a
     * `return` of a loop counter where the machine returns a pointer — so this
     * always had `polarity inverted`'s character rather than a baseline's, and
     * the standing instruction here, in `popReads.ts` and in CLAUDE.md was to
     * gate it at 0 as soon as the count reached 0. It was 7/6/0/0 on
     * t32/w32/t64/w64 at `6952d53` over 5/4/0/0 pops plus 2/2/0/0 implicit
     * `ret` reads; peek-a-bin-3axd, peek-a-bin-6ilz and peek-a-bin-6f3v took
     * the three shapes to **0 on all four**.
     *
     * BOTH counts are gated. `wrong` is a read of the register in a statement;
     * `retWrong` is the implicit read a `ret` makes of the return register, and
     * it is the same defect said differently — two of the four x86 rows it
     * carried were `memset`/`memcpy` returning a loop counter instead of the
     * destination pointer.
     *
     * The liveness half matters as much as the gate, because a lifted pop LEAVES
     * this audit's population: `popsLifted` counts the pops the lifter defines
     * and the scan skips them, so a rule that started claiming every pop would
     * drive `wrong` to 0 by no longer looking. Both are therefore asserted —
     * `pops` non-zero says pops were examined at all, and the ratio is reported
     * beside the gate so the denominator is visible rather than implied.
     */
    it("never reads a register a pop wrote under its previous value", () => {
      let lifted = 0;
      for (const r of results.values()) {
        expect(
          `${r.key} pop-restored: ${r.popReads.rows
            .filter((x) => x.verdict !== "ret-benign")
            .slice(0, 5)
            .map((x) => `${x.func}@0x${x.readAddr.toString(16)} ${x.reg} '${x.insn}'`)
            .join("; ")}`,
        ).toBe(`${r.key} pop-restored: `);
        expect(r.popReads.wrong).toBe(0);
        expect(r.popReads.retWrong).toBe(0);
        expect(r.popReads.pops).toBeGreaterThan(0);
        expect(r.popReads.functionsScanned).toBeGreaterThan(0);
        lifted += r.popReads.popsLifted;
      }
      expect(lifted).toBeGreaterThan(0);
    });

    /**
     * A GATE at 0, and the class it covers is one nothing else here can see.
     *
     * `foldBlock` inlines a definition read exactly once into that reader and
     * deletes the assignment, counting reads over the ONE block it is handed —
     * so a value read again in a successor used to be deleted out from under
     * every later read. 544 reads over 172 functions at `91085f3`
     * (168/110/110/156 on t32/t64/w64/w32); 0 since `blockLiveOut`. Every row
     * is a register the emitted C reads and never assigns, which gcc accepts
     * because `preludeFor` declares each undeclared identifier as its own
     * `long` — the same blindness that hid `peek-a-bin-pzws`.
     *
     * `entryReads` and `regReads` are the liveness numbers, and the first is
     * also the point of the audit: a read no definition reaches is USUALLY
     * correct output — a parameter arriving in a register — so the count that
     * matters is the one that separates the two, not the crude
     * read-but-never-assigned scan. See `corpus/lostDefs.ts`.
     */
    it("never deletes a definition a later block still reads", () => {
      for (const r of results.values()) {
        const ld = r.lostDefs;
        expect(
          `${r.key} fold-lost: ${ld.rows
            .slice(0, 5)
            .map((x) => `${x.func}@B${x.block} ${x.canon} x${x.reads}`)
            .join("; ")}`,
        ).toBe(`${r.key} fold-lost: `);
        expect(ld.lostReads).toBe(0);
        expect(ld.functionsScanned).toBeGreaterThan(0);
        // The entry values are the population the gate is distinguished from.
        // Zero here would mean the discriminator stopped observing, and the
        // gate would then read 0 for the wrong reason.
        expect(ld.entryReads).toBeGreaterThan(0);
        expect(ld.regReads).toBeGreaterThan(0);
      }
    });

    /**
     * A GATE at 0, over a class that is a false STATEMENT rather than an omission.
     *
     * `structureSwitch`'s `armBody` claims exactly one block per arm and used to
     * close it with `break` however the block ends — and `break` says the switch
     * is over. 35 arm blocks on t32 and 17 on w32 were closed that way while
     * having a successor (25/12 ending in a conditional jump, 10/5 in a `jmp`),
     * of which 31 and 14 were a false claim; 0 on all four since `armExit`
     * (peek-a-bin-pqs5). For the conditional half the recovered test went with
     * it, since `pipeline.ts` step 4b has already taken the `IRBranch` out.
     *
     * THE DENOMINATOR IS TIED TO THE JUMP TABLES rather than asserted blind: a
     * binary with no recovered table structures no switch, so `arms` is
     * legitimately 0 on both x64 binaries and a green gate there says nothing.
     * Where tables were recovered, arms and truthful closures must both be
     * non-zero or the instrument has stopped observing and the gate reads 0 for
     * the wrong reason. See `corpus/armExits.ts`.
     */
    it("never closes a switch arm with break while its block has a successor", () => {
      let arms = 0;
      for (const r of results.values()) {
        const ae = r.armExits;
        expect(
          `${r.key} false break: ${ae.rows
            .slice(0, 5)
            .map(
              (x) =>
                `${x.func}@0x${x.armAddr.toString(16)} ${x.condJmp ? "cond" : "uncond"} ${x.why}`,
            )
            .join("; ")}`,
        ).toBe(`${r.key} false break: `);
        expect(ae.falseBreaks).toBe(0);
        // A recovered jump table in a decompiled function is what makes a
        // switch, so this is the one non-vacuous form the liveness check has.
        if (r.jumpTables > 0) {
          expect(ae.arms).toBeGreaterThan(0);
          expect(ae.truthfulExits).toBeGreaterThan(0);
        }
        arms += ae.arms;
      }
      expect(arms).toBeGreaterThan(0);
    });

    /**
     * A GATE at 0, decided against the PE header and nothing else.
     *
     * A direct branch's displacement is resolved by the linker inside the image
     * it is producing, so a filed `jmp 0x288402b` in a 0x400000-0x40e000 image
     * names an address nothing maps: it is a byte string the disassembler walked
     * into, not an instruction the file contains. Every row is therefore
     * provably fiction and the gate has `polarity inverted`'s character.
     *
     * It is a LOWER bound and a loose one — fiction registers only where it
     * happens to decode as a direct branch aimed outside the image, which was 1
     * of the 2 jump-table sites per 32-bit binary that `peek-a-bin-xqxy` fixed.
     * `checked` is the liveness half, and it is non-vacuous on all four
     * binaries: every one of them is full of ordinary intra-image branches, so
     * unlike the switch-arm denominator this needs no per-binary condition.
     * See `corpus/wildBranches.ts`.
     */
    it("never files a direct branch aimed outside the image", () => {
      for (const r of results.values()) {
        const wb = r.wildBranches;
        expect(
          `${r.key} wild: ${wb.rows
            .slice(0, 5)
            .map(
              (x) =>
                `0x${x.addr.toString(16)} ${x.mnemonic} 0x${x.target.toString(16)}` +
                ` [${x.source ?? "?"}]`,
            )
            .join("; ")}`,
        ).toBe(`${r.key} wild: `);
        expect(wb.rows.length).toBe(0);
        expect(wb.checked).toBeGreaterThan(0);
      }
    });

    /**
     * TWO GATES AT 0 OVER THE INSTRUMENT'S INTEGRITY, and a REPORTED baseline
     * over the one visible trace a LOST OPERAND leaves.
     *
     * `eax = eax;` is a cosmetic line when the instruction behind it is one of
     * MSVC's identities — `lea ecx,[ecx+0x0]`, `mov edi,edi`, `or al,al`,
     * `add eax,0x0` — and it is a wrong statement about the machine when the
     * instruction behind it is `add edi, esi`. `peek-a-bin-3axd` (97 wrong reads
     * over 28 t32 functions, from `push <imm>`/`pop <reg>` lifting to no
     * definition) was found through exactly two such lines, and every other gate
     * here is blind to that class: gcc compiles it, polarity judges a guard's
     * operator, `staleReads` and `lostDefs` both see a definition reaching the
     * read (a self-assignment IS one), and the statement-drop audit snapshots
     * after `foldBlock`.
     *
     * WHAT IS NOT GATED, and why the bead's recommendation could not be taken
     * literally: "gate at 0 the subset whose instruction is not an identity
     * idiom" would be a FALSE RED. t32 0x403034 and w32 0x40320B are
     * `sub ecx, ebx` whose EBX is zeroed by the only write of it in the whole
     * function, so the fold is right and `ecx = ecx;` is correct output. A
     * legitimate zero-propagation and a lost operand are the same shape from
     * here. `openOperand` is therefore REPORTED and judged in `compare.mjs`,
     * with the status `unrecovered values` has.
     *
     * WHAT IS GATED: `wrong`, where the emitted name is not even an alias of the
     * destination of the instruction the line carries the address of — broken
     * attribution, which no dataflow answer rescues — and `unresolved`, a row
     * that could not be judged at all. The second is the one that keeps the
     * report honest: a row silently leaving the population is how a gate reads 0
     * by not looking.
     *
     * THE DENOMINATOR IS NOT OPTIONAL. `peek-a-bin-qbk3` emptied the whole x64
     * population three commits before this audit existed, so every count is 0 on
     * t64/w64 for want of anything to see — exactly the vacuous green `armExits`
     * shows on the two binaries with no jump table. `identity` is asserted over
     * the corpus rather than per binary, since a binary with no identity idiom in
     * its emitted C is a legitimate state. See `corpus/selfAssigns.ts`.
     */
    it("resolves every emitted self-assignment to an instruction that writes that register", () => {
      let identity = 0;
      for (const r of results.values()) {
        const sa = r.selfAssigns;
        expect(
          `${r.key} self-assign: ${sa.rows
            .filter((x) => x.verdict === "wrong" || x.verdict === "unresolved")
            .slice(0, 5)
            .map(
              (x) =>
                `${x.fname}:${x.line} '${x.text}' @${x.addr === null ? "?" : `0x${x.addr.toString(16)}`}` +
                ` ${x.mnemonic ?? "?"} ${x.opStr ?? ""} — ${x.why}`,
            )
            .join("; ")}`,
        ).toBe(`${r.key} self-assign: `);
        expect(sa.wrong).toBe(0);
        expect(sa.unresolved).toBe(0);
        expect(sa.lines).toBeGreaterThan(0);
        identity += sa.identity;
      }
      expect(identity).toBeGreaterThan(0);
    });

    /**
     * A GATE at 0, and the only oracle here that can see a wrong register NAME.
     *
     * `canonReg` maps every alias to the 64-bit parent because that is the
     * register's identity, so any path that lets a canonical name reach the page
     * prints `rcx` in a function whose every other line says `ecx`. In a PE32
     * image the instruction set has no RCX, so every occurrence is provably a
     * name no statement wrote and no reader can mean — a defect, not a count
     * awaiting a threshold. It was 71 mentions over 18 distinct names on t32 and
     * 53 over 13 on w32 at `d514274` (peek-a-bin-1k4's residue, closed by
     * peek-a-bin-0s6e).
     *
     * gcc cannot see it — `preludeFor` declares every undeclared identifier as
     * its own `long`, so `rcx` and `ecx` are two unrelated variables — and
     * `corpus/staleReads.ts` cannot either, since it compares the name a read
     * uses and therefore reads a canonical one as a legitimate live-range split.
     *
     * The liveness half matters as much as the gate: `funcs` must be non-zero,
     * or a scan that stopped reading anything reads green.
     */
    it("never names a register the image has no encoding for", () => {
      const u = unencodableNames(
        over(auditedKeys(), results).map((r) => ({ funcs: r.funcs, is64: r.is64 })),
      );
      expect(u.names).toBe(0);
      expect(u.funcs).toBeGreaterThan(0);
    });

    /**
     * A GATE at 0, and the one that discriminates where `offsetNamedArgs` cannot.
     *
     * A declared parameter overwritten from a callee-saved register before it is
     * ever read says the caller passed a value the callee discarded unread, which
     * no calling convention produces. See `paramClobberedAtEntry` for why the
     * `offsetNamedArgs` row beside it is a target rather than a gate: the wrong
     * variant `peek-a-bin-sx57` measured drives that row to its BEST value while
     * printing exactly these rows.
     *
     * `params` is the liveness half and matters as much as the gate — a text
     * scan whose signature grammar stopped matching would report 0 over 0.
     */
    it("never declares a parameter that a callee-saved register overwrites at entry", () => {
      const p = paramClobberedAtEntry(
        over(auditedKeys(), results).map((r) => ({ funcs: r.funcs })),
      );
      expect(p.rows.join("; ")).toBe("");
      expect(p.clobbered).toBe(0);
      expect(p.params).toBeGreaterThan(0);
      expect(p.funcs).toBeGreaterThan(0);
    });

    /**
     * Not a gate: a residue is legitimate (see `offsetNamedArgs`), so what is
     * asserted is only that the scan READ something. A count of 0 for want of
     * observation would otherwise be indistinguishable from a clean tree, and
     * this is the only instrument here that sees the class at all.
     */
    it("reads the emitted C for offset-named argument slots (instrument liveness)", () => {
      const o = offsetNamedArgs(
        over(auditedKeys(), results).map((r) => ({ funcs: r.funcs, is64: r.is64 })),
      );
      expect(o.funcs).toBeGreaterThan(0);
    });

    /**
     * NOT A GATE, and read `undefinedCallees.ts` before making it one. An
     * undefined callee is an incompleteness rather than a false statement — the
     * machine really does call that address — so the row has `offsetNamedArgs`'
     * character and not `unencodableNames`'. What is asserted is only that the
     * scan READ something: this is a text-scraping audit, and the way one fails
     * is by silently matching nothing, which would report 0 undefined callees
     * over a binary whose every call is undefined.
     */
    it("reads the emitted C for calls with no definition (instrument liveness)", () => {
      for (const [key, uc] of ucResults) {
        expect(`${key}: funcs=${uc.funcs > 0}`).toBe(`${key}: funcs=true`);
        expect(uc.calls).toBeGreaterThan(0);
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

    /**
     * NOT A GATE ON THE DROP COUNT — read this before "tightening" it.
     *
     * All it asserts is that the instrument is alive: that the tap fired and
     * statements were examined. A statement-drop audit that quietly stopped
     * observing anything would report `0 dropped` forever and look like the
     * healthiest number in the report, which is the one failure mode a
     * measurement of absence has that the others do not.
     *
     * The count itself is reported and never asserted. It measured 0/7002,
     * 0/7331, 0/6519 and 0/6500 at `cee6f91`, but one commit's measurement is
     * not evidence that zero is an invariant of the design: `structureCFG` has
     * a path that legitimately consumes a block without emitting it (the
     * short-circuit fold), and it is only true today that such blocks lift to
     * nothing. Pinning 0 here would assert something nobody has established.
     * A *rise* is judged where regressions are actually judged — `compare.mjs`,
     * between two runs pinned to two commits, where it counts as one.
     */
    it("observes the structuring step at all (instrument liveness, not a gate)", () => {
      const dead = [...results.values()].filter((r) => r.stmtDrops.tracked === 0).map((r) => r.key);
      expect(`observed no lifted statement for: ${dead.join(", ")}`).toBe(
        "observed no lifted statement for: ",
      );
      for (const r of results.values()) expect(r.stmtDrops.tracked).toBeGreaterThan(1000);
    });

    /**
     * NOT A GATE ON THE UNRECOVERED COUNT — same reasoning as the drop audit.
     *
     * Two things are asserted, and neither is a threshold on how much the
     * decompiler recovers:
     *
     * 1. The scan read emitted C at all. A count of `__unrecovered_N` is a
     *    measurement whose *good* direction is downward, so an instrument that
     *    quietly stopped looking reports the best number in the report.
     * 2. Every value it found was also DECLARED in a form this file could
     *    parse. `emit.ts` declares each one exactly once, so `declsParsed`
     *    below `values` means the declaration spelling moved and the note —
     *    the only record of what was lost, and what `byMnemonic` and `branches`
     *    are derived from — is being read from somewhere less reliable. That is
     *    a broken instrument, not a decompiler defect, and it should say so
     *    rather than silently reclassifying every site.
     *
     * The count itself is reported and never asserted: it is not zero, no
     * threshold on it has been established, and a rise is judged in
     * `compare.mjs` between two pinned runs.
     */
    it("reads the emitted C for unrecovered values (instrument liveness, not a gate)", () => {
      const blind = [...results.values()]
        .filter((r) => r.unrecovered.scannedFuncs === 0)
        .map((r) => r.key);
      expect(`scanned no emitted C for: ${blind.join(", ")}`).toBe("scanned no emitted C for: ");
      const unparsed = [...results.values()]
        .filter((r) => r.unrecovered.declsParsed !== r.unrecovered.values)
        .map((r) => `${r.key} ${r.unrecovered.declsParsed}/${r.unrecovered.values}`);
      expect(`declarations parsed of values found: ${unparsed.join(", ")}`).toBe(
        "declarations parsed of values found: ",
      );
      for (const r of results.values()) expect(r.unrecovered.scannedFuncs).toBeGreaterThan(100);
    });

    /**
     * THE OVER COUNT IS A GATE AT 0, since `peek-a-bin-7r1l`. Everything else
     * this audit measures is reported and not asserted.
     *
     * The upgrade this file recorded as a condition has been met, so it has been
     * taken. Every OVER row is *provably* wrong: no entry in `apitypes.ts` is
     * variadic, so a call passing more arguments than the API declares passes
     * one the machine never passed — a store through the wrong pointer's worth
     * of wrong, and it compiles clean, because gcc accepts an implicit
     * declaration at any arity. That is `stale version-0 names`' character
     * rather than a baseline's, and the only thing that had ever separated them
     * was that this count was not zero: 24 corpus-wide at `e22ba6e`, 16 after
     * `peek-a-bin-f51x`, 6 after `peek-a-bin-6lmh` took the x86 half to 0, and 0
     * after `peek-a-bin-7r1l` retired the last shape (`collectArgs64`
     * attributing a spent index register to the next call).
     *
     * A gate at 0 is NOT a threshold on an absolute, which is what the earlier
     * refusal was about: it does not move when function detection does, because
     * a newly detected function either carries an invented argument or it does
     * not. UNDER stays ungated for exactly the reason it always was — it is not
     * zero, no threshold on it has been justified, and a fall in it is judged in
     * `compare.mjs` between two pinned runs.
     *
     * Liveness is asserted alongside, and it matters more than usual because
     * both counts' *good* direction is downward: a scan that quietly stopped
     * matching call sites would report `over 0, under 0` and look like the
     * healthiest thing in the report. The gate would pass over the wreckage;
     * the liveness floors are what stop it.
     */
    it("passes no argument the machine did not (arity OVER-count gate at 0)", () => {
      const blind = [...arResults.entries()]
        .filter(([, a]) => a.sites === 0 || a.scannedFuncs === 0)
        .map(([k, a]) => `${k} (${a.sites} sites, ${a.scannedFuncs} functions read)`);
      expect(`found no declared-API call site in: ${blind.join(", ")}`).toBe(
        "found no declared-API call site in: ",
      );
      // THE GATE. Named per row, because an over-count is adjudicated against
      // the real prototype: it is either an argument the emitter invented or a
      // wrong entry in `apitypes.ts`, and the audit cannot tell you which.
      const invented = [...arResults.entries()].flatMap(([k, a]) =>
        a.rows
          .filter((r) => r.verdict === "over")
          .map(
            (r) => `${k} ${r.fname} ${r.callee} passes ${r.emitted} of ${r.declared}: ${r.line}`,
          ),
      );
      expect(`arguments the machine never passed:\n  ${invented.join("\n  ")}`).toBe(
        "arguments the machine never passed:\n  ",
      );
      for (const a of arResults.values()) {
        expect(a.over).toBe(0);
        expect(a.sites).toBeGreaterThan(50);
        expect(a.distinctCallees).toBeGreaterThan(10);
        // The table itself. An `apitypes.ts` that stopped exporting its entries
        // would take every row with it and report a perfect score.
        expect(a.declaredNames).toBeGreaterThan(100);
        // Every site the scan counted produced a row, so the jsonl and the
        // totals cannot disagree about what was measured.
        expect(a.rows.length).toBe(a.sites);
        expect(a.exact + a.under + a.over).toBe(a.sites);
        expect(a.underAtCeiling + a.underBelowCeiling).toBe(a.under);
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
  L.push(`  corpus dir: ${corpusDir()}  [${corpusDirSource()}]`);
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
    const ar = arResults.get(key) as ArityResult;
    L.push(
      `  API call arity vs apitypes   ${ar.exact}/${ar.sites} exact (${pct(ar.exact, ar.sites)}), ` +
        `under ${ar.under} (${ar.underAtCeiling} at the ABI ceiling, ${ar.underBelowCeiling} below), ` +
        `over ${ar.over} — OVER is GATED at 0`,
    );
    L.push(
      "    The ONLY oracle here that can see arity: gcc accepts an implicit declaration at any",
    );
    L.push("    arity. OVER is an argument the emitter invented and every row is provably wrong,");
    L.push("    so it gates at 0 (peek-a-bin-7r1l). UNDER is NOT gated: at the ceiling it is the");
    L.push("    argument evidence running out (4 fastcall registers, 8 scanned pushes), below it");
    L.push("    a recovery the evidence was there for; a rise in either is judged in compare.mjs.");
    const overBy = ar.byCallee
      .filter((c) => c.over > 0)
      .map((c) => `${c.over} ${c.callee}`)
      .join(", ");
    const underBy = ar.byCallee
      .filter((c) => c.under > 0)
      .slice(0, 8)
      .map((c) => `${c.under} ${c.callee}`)
      .join(", ");
    if (overBy) L.push(`    over:  ${overBy}`);
    if (underBy) L.push(`    under: ${underBy}`);
    const cov = r.lineMapCoverage;
    L.push(
      `  BASELINE line map coverage  ${cov.insnsCovered}/${cov.insnsTotal} instructions ` +
        `(${pct(cov.insnsCovered, cov.insnsTotal)}), ` +
        `${cov.blocksTotal - cov.blocksUncovered}/${cov.blocksTotal} blocks ` +
        `(${pct(cov.blocksTotal - cov.blocksUncovered, cov.blocksTotal)}) — NOT a gate`,
    );
    L.push("    lost coverage means no address mapped: folded into a use, relocated, OR dropped.");
    L.push("    Telling those apart needs the emitted C read beside the machine text.");
    const sd = r.stmtDrops;
    const kinds = Object.entries(sd.byKind)
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => `${n} ${k}`)
      .join(", ");
    L.push(
      `  BASELINE statements dropped ${sd.dropped}/${sd.tracked} lifted ` +
        `(${pct(sd.dropped, sd.tracked)}) across ${sd.funcsAffected} functions — NOT a gate` +
        (kinds ? `\n    kinds: ${kinds}` : ""),
    );
    L.push("    liftBlock -> structureCFG, by OBJECT IDENTITY. A drop is a statement nothing");
    L.push("    downstream can know existed. Sites in drops_<bin>.jsonl; see README.md.");
    const un = r.unrecovered;
    const sites = Object.entries(un.bySite)
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => `${n} ${k}`)
      .join(", ");
    const mnems = Object.entries(un.byMnemonic)
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => `${n} ${k}`)
      .join(", ");
    L.push(
      `  BASELINE unrecovered values ${un.values} across ${un.funcsAffected} functions ` +
        `(${un.occurrences} occurrences of the token) — NOT a gate`,
    );
    L.push(
      `    of which BRANCH conditions ${un.branches}, ${un.branchesWithJcc} with a named jcc` +
        (sites ? `\n    sites: ${sites}` : "") +
        (mnems ? `\n    jcc:   ${mnems}` : ""),
    );
    L.push("    An unrecovered value is a machine fact the emitter names instead of guessing.");
    L.push("    NONE of them is in guards_<bin>.jsonl: an unrecovered condition has no top-level");
    L.push("    operator, so it is not a failing polarity row, it is not a row at all. A rise is");
    L.push("    judged in compare.mjs, beside polarity.checked FALLING. See README.md.");
    const cb = r.clobbered;
    const byReg = Object.entries(cb.byRegister)
      .sort((a, b) => b[1] - a[1])
      .map(([k, n]) => `${n} ${k}`)
      .join(", ");
    L.push(
      `  BASELINE clobbered reads    ${cb.reads} of ${cb.values} distinct values ` +
        `across ${cb.funcsAffected} functions — NOT a gate`,
    );
    L.push(
      `    constructs emitted        ${cb.ifs} if, ${cb.whiles - cb.doWhiles} while, ` +
        `${cb.doWhiles} do/while, ${cb.fors} for` +
        (byReg ? `\n    by register:              ${byReg}` : ""),
    );
    L.push(
      `    callee summaries          ${cb.summaryNonEmpty}/${cb.summaryFuncs} non-empty, ` +
        `${cb.summaryFull} at the full volatile set, ${cb.uncoveredMnemonics} unclassified mnemonics`,
    );
    L.push("    What a call destroys. NOT gated in either direction: a call that really does");
    L.push("    destroy a register SHOULD say so, and the narrow model reaches zero by saying");
    L.push("    nothing. Judge it beside the construct counts — modelling a call as clobbering");
    L.push("    the whole ABI volatile set DELETED a guard (peek-a-bin-hj1). See README.md.");
    const sv = r.staleV0;
    L.push(
      `  stale version-0 names       ${sv.wrong} wrong of ${sv.confirmed} confirmed, ` +
        `${sv.sites} sites over ${sv.v0Reads} version-0 reads`,
    );
    L.push(
      `    entry-value copies        ${sv.copies}, of which ${sv.copiesCorrupted} spoiled ` +
        `(${sv.readsOfCorrupted} reads, ${sv.funcsCorrupted} functions)`,
    );
    L.push("    A GATE at 0 on both, unlike the two BASELINEs above: each row is a register the");
    L.push("    emitted C names for a value it does not hold. Sites in stalev0_<bin>.jsonl.");
    const sg = r.staleGuards;
    L.push(
      `  wrong-operand guards        ${sg.named} named of ${sg.shapes} spoiled readings ` +
        `(${sg.bySuperseded} superseded, ${sg.byClobbered} clobbered) over ${sg.blocks} jcc blocks`,
    );
    L.push(
      `    guards emitted at a shape ${sg.emittedAtShape} — the RECOVERY, not the defect; not gated`,
    );
    L.push("    The right operator over the WRONG OPERANDS: polarity passes it, gcc compiles it,");
    L.push("    it is not __unrecovered_N. `shapes` is machine-code shape and does not move with");
    L.push("    a decompiler fix. `named` asks whether the emitted condition MENTIONS something");
    L.push("    the spoiler could have written — since peek-a-bin-xskz the lifter materialises a");
    L.push("    spoiled compare's operands, so a guard being present is no longer the question.");
    L.push("    Sites in staleguards_<bin>.jsonl. See corpus/README.md.");
    const ce = r.crossEdgeGuards;
    L.push(
      `  cross-edge guards           ${ce.admitted} answered / ${ce.named} named of ` +
        `${ce.differ} disagreeing (${ce.differOther} non-compare, ${ce.admittedOther} answered, ` +
        `${ce.namedOther} named) of ${ce.multi} multi-edge, ${ce.agree} agreeing ` +
        `(${ce.agreeAdmitted} answered), over ${ce.crossEdge} cross-edge of ${ce.blocks} jcc blocks`,
    );
    L.push(
      `    sole-predecessor blocks   ${ce.soleAdmitted}/${ce.sole} answered, ${ce.soleNamed} named ` +
        `— the two liveness halves; ${ce.refused} refused, ${ce.unknownEdge} unreadable edge`,
    );
    L.push("    A Jcc ALONE in its block reads flags set before the block, and where its");
    L.push("    predecessors set them from different tests no block-local `if` states the");
    L.push("    machine on every path in. GATED at 0 on BOTH counts: `named` is the guard on");
    L.push("    the page, `answered` is the predecessor the code admitted — necessary for");
    L.push("    either route to spell a condition, so it is the COMPLETE half where `named`");
    L.push("    depends on the polarity anchor. `staleGuards` above cannot see this at all:");
    L.push("    its scan needs a cmp/test in the jcc's own block. Polarity judges the");
    L.push("    OPERATOR, which is right; it is the operands that belong to one edge.");
    L.push("    `differ` is machine-code shape and does not move with a decompiler fix.");
    L.push("    Sites in crossedgeguards_<bin>.jsonl. See crossEdgeGuards.ts.");
    const pr = r.popReads;
    L.push(
      `  pop-restored reads          ${pr.wrong} wrong over ${pr.popsWrong} pops ` +
        `(${pr.funcsWrong} functions), ${pr.benign} benign restores, ` +
        `${pr.popsLifted}/${pr.pops} pops paired by the lifter`,
    );
    L.push(
      `    implicit \`ret\` reads      ${pr.retWrong} wrong, ${pr.retBenign} benign ` +
        `— a benign row is one where emitting NOTHING is what makes the C right`,
    );
    L.push("    A register a `pop` wrote, read in the C under its PREVIOUS value. GATED at 0 on");
    L.push("    both counts (3axd, 6ilz, 6f3v): every row is a provably wrong name, and two of");
    L.push("    the last four were memset/memcpy returning a loop counter for their destination");
    L.push("    pointer. A PAIRED pop leaves this population, so read the ratio beside the gate —");
    L.push("    a rule claiming every pop would reach 0 by no longer looking. Sites in");
    L.push("    popreads_<bin>.jsonl. See popReads.ts.");
    const ld = r.lostDefs;
    L.push(
      `  fold-lost definitions       ${ld.lostReads} reads over ${ld.lostSites} sites ` +
        `(${ld.funcsAffected} functions), against ${ld.entryReads} entry-value reads ` +
        `of ${ld.regReads} examined`,
    );
    L.push("    A read whose reaching definition `foldBlock` deleted: single-use inlining counts");
    L.push("    uses within ONE block, so a value read again in a successor was dropped and every");
    L.push(
      "    later read named a register the C never assigns. A GATE at 0 — `entryReads` is the",
    );
    L.push("    legitimate population it is told apart from. Sites in lostdefs_<bin>.jsonl.");
    const ae = r.armExits;
    L.push(
      `  switch-arm false breaks     ${ae.falseBreaks} of ${ae.arms} arms ` +
        `(${ae.falseBreaksCond} conditional, ${ae.falseBreaksUncond} unconditional; ` +
        `${ae.truthfulExits} truthful, ${ae.unnameable} unnameable) over ` +
        `${ae.funcsWithSwitch} functions with a switch`,
    );
    L.push("    An arm closed with `break` while its own block has a successor: `break` says the");
    L.push("    switch is over, and for the conditional half the recovered test goes with it. A");
    L.push("    GATE at 0, from 35/0/0/17 before `armExit` (peek-a-bin-pqs5). `arms` is the");
    L.push("    denominator and is 0 wherever no jump table was recovered — both x64 binaries.");
    L.push("    Sites in armexits_<bin>.jsonl. See armExits.ts.");
    const wb = r.wildBranches;
    L.push(`  branches outside the image  ${wb.rows.length} of ${wb.checked} direct branches`);
    L.push("    A literal branch displacement is resolved inside the image, so a filed");
    L.push("    `jmp 0x288402b` in a 0x400000-0x40e000 image is bytes decoded as code. A GATE at");
    L.push("    0, from 1/0/0/1 at 6d5ae92 (peek-a-bin-xqxy). A LOWER bound: it sees fiction only");
    L.push("    where the fiction happens to be a direct branch aimed out of the image.");
    L.push("    Sites in wildbranches_<bin>.jsonl. See wildBranches.ts.");
    const sa = r.selfAssigns;
    L.push(
      `  self-assignments            ${sa.wrong} wrong, ${sa.unresolved} unresolved, ` +
        `${sa.openOperand} open-operand (${sa.openZeroCorroborated} zero-corroborated), ` +
        `${sa.identity} machine identities, over ${sa.funcsAffected} functions` +
        (sa.inForHeader > 0 ? ` (${sa.inForHeader} in a for header)` : ""),
    );
    L.push("    `eax = eax;` is noise where the instruction is an identity (`lea ecx,[ecx+0x0]`,");
    L.push("    `or al,al`, `add eax,0x0`) and a LOST OPERAND where it is not — `add edi, esi`");
    L.push("    emitted as `edi = edi` is what peek-a-bin-3axd was found by, and no other gate");
    L.push("    here sees that class. GATED at 0 on `wrong` (the emitted name is not even an");
    L.push("    alias of the instruction's destination) and on `unresolved` (a row that could");
    L.push("    not be judged). `openOperand` is REPORTED, NOT gated — a zero-propagated");
    L.push("    `sub ecx,ebx` and a lost operand are the same shape from here, and both base");
    L.push("    rows are the legitimate kind; a RISE is the signal, judged in compare.mjs.");
    L.push("    `identity` is the denominator and is 0 on both x64 binaries because");
    L.push("    peek-a-bin-qbk3 emptied that population, so a green x64 row says nothing. A");
    L.push(
      "    FAINT trace: only 2 of 3axd's 97 wrong reads left one. In selfassigns_<bin>.jsonl.",
    );
    const uc = ucResults.get(r.key);
    if (uc !== undefined) {
      L.push(
        `  calls with no definition    ${uc.internal} internal ` +
          `(${uc.internalDistinct} distinct targets over ${uc.internalFuncs} functions, ` +
          `${uc.internalLabelled} with a loc_ label to name), ` +
          `${uc.external} external (${uc.externalDistinct} distinct over ${uc.externalFuncs}), ` +
          `of ${uc.calls} sub_ calls scanned`,
      );
      L.push("    An emitted `sub_<hex>(` the output defines nowhere — a call the reader cannot");
      L.push("    follow. REPORT-ONLY in both directions: the machine does make that call and");
      L.push("    the name is derived from its target, so the row is an INCOMPLETENESS and not a");
      L.push("    false statement — `offsetNamedArgs`' character, not `unencodableNames`'.");
      L.push("    INTERNAL means the target is inside the caller's own extent, so the callee's");
      L.push("    body IS in the output, further down under a `loc_` label, merely unconnected;");
      L.push("    in this corpus all of them are MSVC `__finally` funclets the detector folded");
      L.push("    into their parents (peek-a-bin-qe8z, peek-a-bin-d827), 25/0/0/23 at d8d2d02.");
      L.push("    EXTERNAL is detection's or the IAT's business, not the emitter's: a tail `jmp`");
      L.push("    to a function detection never produced, or an indirect call through a data");
      L.push("    pointer with no IAT entry, where the name is the POINTER's address. `label`");
      L.push("    is what decides whether a comment could name the body: only where the target");
      L.push("    is a block leader, 8 of 25 and 6 of 23 here — elsewhere the leader is the");
      L.push("    UNWINDER's entry a few bytes earlier and naming it would claim a reload the");
      L.push("    call does not execute. gcc is structurally blind (one function per file, no");
      L.push("    prototypes, so every callee is an implicit declaration `gnu89` accepts) and so");
      L.push("    is `distinct callees lost`, which asks only whether the name is on the page.");
      L.push(
        "    Sites in undefinedcallees_<bin>.jsonl. See undefinedCallees.ts (peek-a-bin-pf5g).",
      );
    }
    if (r.tablesFrom !== null) {
      L.push(`  *** CROSS-SUBSTITUTED jump tables from ${r.tablesFrom}`);
    }
  }

  const g = gotoCheck(over(keys, results).map((r) => ({ funcs: r.funcs })));
  const un = unencodableNames(over(keys, results).map((r) => ({ funcs: r.funcs, is64: r.is64 })));
  L.push("");
  L.push(`── totals ${"─".repeat(54)}`);
  L.push(`  gotos ${g.gotos}, labels ${g.labels}, dangling ${g.dangling}`);
  L.push(
    `  unencodable register names  ${un.names} mentions, ${un.distinct} distinct, over ` +
      `${un.funcsAffected} of ${un.funcs} PE32 functions`,
  );
  for (const key of keys) {
    const r = results.get(key) as BinResult;
    const oa = offsetNamedArgs([{ funcs: r.funcs, is64: r.is64 }]);
    L.push(
      `  offset-named argument slots  ${key}: ${oa.aligned} occurrences over ` +
        `${oa.funcsAffected} of ${oa.funcs} functions, ${oa.distinct} distinct` +
        (oa.subSlot > 0 ? `, plus ${oa.subSlot} sub-slot (correctly offset-named)` : ""),
    );
  }
  L.push("    An `arg_0xN` whose offset divides evenly into an argument slot. REPORT-ONLY in");
  L.push("    both directions, and NOT a defect count: since peek-a-bin-sx57 a slot is indexed");
  L.push("    when the frame register's displacement was recovered AND — inside the x64 home");
  L.push("    space, which the ABI hands the callee as scratch — the callee was shown to spill");
  L.push("    that argument's own register into it. So the x64 residue is mostly slots that");
  L.push("    are NOT arguments: 15 of the 20 home slots in this corpus hold a saved register");
  L.push("    or a byte local, and naming those would state something false. Driving this row");
  L.push("    to 0 is therefore the WRONG target — measured, it moves no other number in this");
  L.push("    report at all. The PE32 residue is detection over-production, where the prologue");
  L.push("    is outside the range and the frame register is the enclosing function's.");
  L.push("    Nothing else here sees this class: it is a well-typed name gcc compiles.");
  L.push("  unencodable register names — detail:");
  L.push("    A 64-bit name in the C of a PE32 image: `canonReg` maps every alias to the 64-bit");
  L.push("    parent, so any leak of that identity prints `rcx` where the image has no RCX. A");
  L.push(
    "    GATE at 0, from 124 mentions / 18 distinct over 19 functions at `d514274` (0s6e). ASKED",
  );
  L.push("    OF PE32 ONLY — on x64 `rcx` is an ordinary correct spelling and this says nothing,");
  L.push("    so `funcs` is the liveness check. gcc and staleReads are both blind to it.");

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
