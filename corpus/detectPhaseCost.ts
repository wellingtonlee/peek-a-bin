/**
 * Where does `detectFunctions` spend its time, phase by phase?
 *
 * THE INSTRUMENT peek-a-bin-6dv3 ASKS FOR, and the reason it is needed is that
 * detection became the load's whole budget by standing still. When the three
 * decode-bound RPCs were first timed they were within 1.2x of one another and
 * the budget was set by whichever happened to run longest; `peek-a-bin-x40u`
 * then made `buildAllXrefs` share detection's linear sweep and
 * `peek-a-bin-iqzu` served `hybridDisassemble` from the same grid, cutting each
 * roughly threefold and leaving detection untouched. It is now many times the
 * next RPC and the sole constraint on `REQUEST_TIMEOUT_MS` — and nobody had
 * ever broken it down, so every proposal about it was an argument rather than a
 * measurement.
 *
 * WHAT IT REPORTS, and the second table is the one that matters:
 *
 *  1. The premise: the three RPCs through the real `dispatch`, so the ratio the
 *     bead was filed on is re-derived here rather than quoted.
 *  2. The per-phase split, from a {@link DetectPhase} tap wired into
 *     `detectFunctions` itself. `unattributed` beside it is the integrity
 *     column: phases that do not sum to the whole call mean a phase boundary is
 *     in the wrong place, and a split that quietly loses a third of the time
 *     would otherwise read as a clean answer.
 *  3. The same figures as rates, against three different denominators — the
 *     section's size, the instructions the sweep produced, and the functions
 *     detected. A phase whose cost is linear in one of them has a flat column
 *     under it, and one that is *super*linear has a column that climbs. That is
 *     the whole answer to "is this a rate problem or a shape problem", and it
 *     needs images of very different sizes to say anything, which is why this
 *     takes paths.
 *
 * THE SWEEP IS SEPARATED FROM EVERYTHING ELSE, AND THAT IS THE POINT. The
 * linear sweep is Capstone over the whole section, and since `x40u` it is paid
 * once and then *free-ridden on* by both of detection's successors. Charging it
 * to detection is arithmetically correct and reads as though detection were
 * expensive, when what is expensive is decoding the section at all — which any
 * of the three would have had to do. Both directions are printed: the tap's own
 * `sweep` figure, and `cold - warm`, the same quantity measured from OUTSIDE
 * the tap by running detection twice, once with an empty memo and once with the
 * memo already holding this section's sweep. The two must agree; if they do not,
 * the tap's boundaries are wrong.
 *
 * WHY IT TAKES A PATH AND IS NOT IN `npm run corpus`. The rule
 * `corpus/jumpTableReach.ts`, `corpus/rpcUploadCost.ts` and
 * `corpus/decompileRpcCost.ts` already follow: that run's header names the four
 * MSVC binaries every standing figure is measured against, and the audits
 * iterate over whatever they find in the corpus directory, so an extra binary
 * silently changes the population of every gate and the denominator of every
 * summed figure. The images most worth pointing this at are the Windows/amd64
 * PEs `go` builds — see the recipe in this directory's README — which must NOT
 * be put there. Run it with `npm run corpus:detectcost -- <path> [<path>...]`.
 *
 * WHY IT IS DERIVED AND NOT TABULATED. Everything comes out of the image and
 * out of the code under test: the section from the PE header, the phases from
 * the real `detectFunctions` with real Capstone handles, the totals from the
 * real `dispatch`. There is no address, no size and no timing constant in here
 * to go stale, so it runs against any PE on any machine — which is what
 * `peek-a-bin-ayhj`'s lost probe did not do.
 *
 * HOW ITS OWN BOUNDARIES WERE CHECKED, since a phase split is exactly the kind
 * of answer that reads as authoritative whether or not it is right. Three
 * controls, each run against this repo's own code:
 *
 *  * DELETE a `phase()` call — `phase("tail-calls")` — and that column reads
 *    0.00 while `unattributed` goes from 0.2% to 10.7% on the `go` x64 image.
 *    So the integrity column detects a missing boundary, and
 *    `functionDetect.test.ts`' ordering assertion fails at the same time. (It
 *    found a real one: `phase("pdata-seeds")` was never inserted, and its cost
 *    was being reported as `handler-seeds`.)
 *  * REPORT `sweep` BEFORE the sweep runs, so its time lands in the next
 *    column: `unattributed` stays at -0.0% and does not notice, while the
 *    cold-minus-warm cross-check goes from agreeing within 9% to disagreeing by
 *    six orders of magnitude. The two checks are complementary — one sees a
 *    boundary that is missing, the other one that is in the wrong place.
 *  * MOVE the `sweep`/`sweep-scan` boundary past the scan loop, so the sweep
 *    column absorbs its neighbour: BOTH checks are INERT. `unattributed` is
 *    unmoved because no boundary is missing, and cold-minus-warm still agrees
 *    within 0.5% because `sweep-scan` is 4% of `sweep` and this machine's
 *    run-to-run spread on that figure is ~10%. So the cross-check resolves a
 *    gross misattribution of the sweep and NOT a small neighbour leaking into
 *    it; that boundary rests on reading the code, and this note is here so the
 *    next reader knows which parts of the split are instrumented and which are
 *    argued.
 *
 * WHAT IT IS NOT. A census and a stopwatch, never a gate. Wall clock on a
 * loaded machine is not a benchmark: run it twice and a small column moves by
 * tens of percent. What does not move is which phase dominates and whether a
 * rate column is flat, and that is the only thing any conclusion should rest
 * on. The phase run is also a REPLICA of `dispatch`'s argument construction, so
 * it checks its own faithfulness — `same answer as dispatch` below — because a
 * replica that has drifted reports a confident split of a call the worker never
 * makes.
 */

import { readFileSync } from "node:fs";
import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { archForMachine } from "../src/disasm/arch";
import {
  type DetectPhase,
  type DetectResult,
  type DisasmContext,
  detectFunctions,
} from "../src/disasm/functionDetect";
import { sweepX86, X86SweepCache } from "../src/disasm/linearSweep";
import { parsePE } from "../src/pe/parser";
import { dataSectionRanges, findCodeSection } from "../src/pe/sections";
import { createWorkerState, dispatch } from "../src/workers/dispatch";

/**
 * Every phase, in run order, so a column that is always zero still appears.
 *
 * Spelled out rather than collected from the tap: a phase that never fires —
 * `sweep`/`sweep-scan` with no decoder, `seh32-relation` on x64, which reports
 * the trivial empty-map arm — is a fact worth seeing, and a table built from
 * whatever happened to fire hides it.
 */
const PHASES = [
  "pdata-seeds",
  "handler-seeds",
  "entry-point",
  "exports",
  "prologue-scan",
  "padding-scan",
  "sweep",
  "sweep-scan",
  "pattern-admit",
  "seh32-relation",
  "interior-starts",
  "sizes",
  "thunk-names",
  "tail-calls",
] as const satisfies readonly DetectPhase[];

/**
 * A phase added to {@link DetectPhase} and not to {@link PHASES} fails the
 * build here rather than silently losing a column.
 *
 * The alternative — deriving the columns from whatever the tap reported —
 * cannot distinguish a phase that did nothing from a phase nobody wired, which
 * is the one thing this harness must not confuse. `Record<DetectPhase, …>` is
 * the pattern this borrows from `VIEW_TAB_LABELS`; an array needs the check
 * written out.
 */
const _everyPhaseListed: [Exclude<DetectPhase, (typeof PHASES)[number]>] extends [never]
  ? true
  : false = true;
void _everyPhaseListed;

/** Median of `n` samples, which is what to read off a loaded machine. */
function median(xs: number[]): number {
  const t = [...xs].sort((a, b) => a - b);
  return t[Math.floor(t.length / 2)];
}

interface Row {
  name: string;
  codeBytes: number;
  is64: boolean;
  insns: number;
  funcs: number;
  /** The three RPCs through the real `dispatch`, in a load's order. */
  detect: number;
  hybrid: number;
  xrefs: number;
  /** Detection with an empty memo and with a full one — the sweep, from outside. */
  cold: number;
  warm: number;
  /** Median milliseconds per phase, and what the phases failed to account for. */
  phase: Map<DetectPhase, number>;
  phaseTotal: number;
  unattributed: number;
  faithful: boolean;
}

/**
 * How many samples to take, given the section's size.
 *
 * More on a small image, because the quantity is a difference of two medians
 * and a 50 ms figure on a machine with other work on it moves by tens of
 * percent between samples where a 3000 ms one does not. Five on the largest
 * images because each sample there is several seconds and the noise is already
 * a small fraction of it.
 */
function repsFor(codeBytes: number): number {
  return codeBytes < 256 * 1024 ? 21 : 5;
}

async function measure(path: string): Promise<Row | null> {
  const file = readFileSync(path);
  const buffer = file.buffer.slice(
    file.byteOffset,
    file.byteOffset + file.byteLength,
  ) as ArrayBuffer;
  const pe = parsePE(buffer);
  const text = findCodeSection(pe.sections);
  if (!text) {
    console.log(`${path}: no executable section — detection returns before any phase runs`);
    return null;
  }
  const arch = archForMachine(pe.coffHeader.machine);
  if (arch !== "x86") {
    // ARM64 detection is `detectArm64Functions`, a different function with its
    // own phases and its own harness (`npm run corpus:arm64`); an unsupported
    // machine type refuses above every phase here.
    console.log(`${path}: ${arch} — this instrument is the x86 detectFunctions only`);
    return null;
  }
  const bytes = new Uint8Array(buffer, text.pointerToRawData, text.sizeOfRawData);
  const base = pe.optionalHeader.imageBase + text.virtualAddress;

  const state = createWorkerState(Promise.resolve());
  state.cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
  state.cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
  state.csArm64 = new Capstone(Const.CS_ARCH_ARM64, Const.CS_MODE_ARM);
  state.arch = arch;

  const pdataRanges = pe.runtimeFunctions?.map((rf) => ({
    beginAddress: pe.optionalHeader.imageBase + rf.beginAddress,
    endAddress: pe.optionalHeader.imageBase + rf.endAddress,
  }));
  const common = { bytes, baseAddress: base, is64: pe.is64, machine: pe.coffHeader.machine };
  const detectArgs = { options: { pdataFunctions: pdataRanges }, pdataRanges };

  // 1. The premise, through the real dispatch. `state.x86Sweep` is shared
  // across these exactly as it is in the worker, so `xrefs` is the resolve
  // alone and `hybrid` is served from the grid — i.e. this is the ratio a real
  // load has, not one measured with the memo disabled.
  const timeRpc = async (
    method: Parameters<typeof dispatch>[0],
    extra: object,
  ): Promise<number> => {
    const t0 = performance.now();
    await dispatch(method, { ...common, ...extra }, state);
    return performance.now() - t0;
  };
  const fromDispatch = (await dispatch(
    "detectFunctions",
    { ...common, ...detectArgs },
    state,
  )) as DetectResult;
  // SEQUENTIALLY, and that is not a style preference. `dispatch` is an async
  // function, so `await dispatch(...)` suspends the caller to a microtask even
  // when the branch it took never awaited anything — which means a
  // `Promise.all` over N timed closures starts all N before the first one's
  // clock is read, and every sample but the last measures several runs. It
  // produces a descending staircase (3208/2197/1129 ms where each run is 950)
  // whose median is ~3x the truth, and it looks exactly like a slow RPC.
  const detectSamples: number[] = [];
  const reps = repsFor(bytes.length);
  for (let i = 0; i < reps; i++) {
    state.x86Sweep.clear();
    detectSamples.push(await timeRpc("detectFunctions", detectArgs));
  }
  const detect = median(detectSamples);
  const hybrid = await timeRpc("hybridDisassemble", {
    seeds: fromDispatch.functions.map((f) => f.address),
    pdataRanges,
    jumpTableSpans: fromDispatch.jumpTableSpans,
  });
  const xrefs = await timeRpc("buildAllXrefs", {
    stringAddrs: [],
    iatAddrs: [],
    funcEntries: fromDispatch.functions.map((f) => [f.address, f.size]),
    dataSections: dataSectionRanges(pe.sections, pe.optionalHeader.imageBase),
  });

  // 2. The phase split. `dispatch`'s own argument construction, replicated
  // here because nothing may hand a tap through the wire format — and checked
  // against `dispatch`'s answer below rather than trusted.
  const ctx: DisasmContext = {
    cs32: state.cs32,
    cs64: state.cs64,
    iatMap: state.iatMap,
    stringMap: state.stringMap,
    driverMode: state.driverMode,
  };
  const runOnce = (cache: X86SweepCache, tap?: (p: DetectPhase, ms: number) => void) => {
    const t0 = performance.now();
    const r = detectFunctions(bytes, base, pe.is64, ctx, detectArgs.options, cache, tap);
    return { ms: performance.now() - t0, result: r };
  };
  const direct = runOnce(new X86SweepCache());
  const faithful =
    JSON.stringify(direct.result.functions) === JSON.stringify(fromDispatch.functions) &&
    JSON.stringify(direct.result.jumpTables) === JSON.stringify(fromDispatch.jumpTables) &&
    JSON.stringify(direct.result.jumpTableSpans) === JSON.stringify(fromDispatch.jumpTableSpans);

  const samples = new Map<DetectPhase, number[]>();
  const totals: number[] = [];
  for (let i = 0; i < reps; i++) {
    const seen = new Map<DetectPhase, number>();
    const run = runOnce(new X86SweepCache(), (p, ms) => seen.set(p, (seen.get(p) ?? 0) + ms));
    totals.push(run.ms);
    for (const p of PHASES) {
      const list = samples.get(p) ?? [];
      list.push(seen.get(p) ?? 0);
      samples.set(p, list);
    }
  }
  const phase = new Map<DetectPhase, number>();
  for (const p of PHASES) phase.set(p, median(samples.get(p) ?? [0]));
  const phaseTotal = [...phase.values()].reduce((a, b) => a + b, 0);

  // 3. The sweep from outside the tap. A memo already holding this section's
  // sweep makes detection's own first act free, so the difference between the
  // two runs is the sweep and nothing else — an independent reading of the
  // largest column, which is the one a wrong phase boundary would corrupt.
  const warmed = new X86SweepCache();
  warmed.sweep(bytes, base, pe.is64 ? state.cs64 : state.cs32, "harness prefill");
  // ALTERNATING, so that a machine-load drift over the run lands on both
  // populations equally: the quantity wanted is their difference, and taking
  // all of one and then all of the other charges any drift entirely to the
  // second. On the largest image here that is worth tens of percent.
  const coldSamples: number[] = [];
  const warmSamples: number[] = [];
  for (let i = 0; i < reps; i++) {
    coldSamples.push(runOnce(new X86SweepCache()).ms);
    warmSamples.push(runOnce(warmed).ms);
  }
  const cold = median(coldSamples);
  const warm = median(warmSamples);

  const insns = sweepX86(bytes, base, pe.is64 ? state.cs64 : state.cs32, "harness census").length;

  console.log(
    `${path.split("/").pop()} — x86${pe.is64 ? "-64" : "-32"}, .text ${(bytes.length / 1024).toFixed(0)} KiB, ` +
      `${reps} samples, ` +
      `${insns} swept insns, ${direct.result.functions.length} functions, ` +
      `${pdataRanges?.length ?? 0} .pdata rows — same answer as dispatch: ${faithful ? "YES" : "NO"}`,
  );
  return {
    name: path.split("/").pop() ?? path,
    codeBytes: bytes.length,
    is64: pe.is64,
    insns,
    funcs: direct.result.functions.length,
    detect,
    hybrid,
    xrefs,
    cold,
    warm,
    phase,
    phaseTotal,
    unattributed: median(totals) - phaseTotal,
    faithful,
  };
}

const MiB = 1024 * 1024;
const pad = (s: string | number, n: number) => String(s).padStart(n);

function printPremise(rows: Row[]): void {
  console.log("");
  console.log("THE PREMISE — the three decode-bound RPCs through the real dispatch, ms");
  console.log(
    "image            .text   detect   hybrid    xrefs    total  detect%  d/MiB   det-sweep  ds/MiB",
  );
  for (const r of rows) {
    const total = r.detect + r.hybrid + r.xrefs;
    const mib = r.codeBytes / MiB;
    // From the phase run rather than `detect` minus the tapped sweep: those are
    // two different runs, and their difference carries both runs' noise. The
    // `warm` column of the previous table is the same quantity measured end to
    // end and is the corroboration.
    const own = r.phaseTotal - (r.phase.get("sweep") ?? 0);
    console.log(
      [
        r.name.padEnd(15),
        `${pad((r.codeBytes / 1024).toFixed(0), 5)}K`,
        pad(r.detect.toFixed(0), 8),
        pad(r.hybrid.toFixed(0), 8),
        pad(r.xrefs.toFixed(0), 8),
        pad(total.toFixed(0), 8),
        `${pad(((r.detect * 100) / total).toFixed(0), 7)}%`,
        pad((r.detect / mib).toFixed(0), 6),
        pad(own.toFixed(0), 11),
        pad((own / mib).toFixed(0), 7),
      ].join(" "),
    );
  }
  console.log("");
  console.log("`det-sweep` is detection WITHOUT the shared linear sweep — the work that is");
  console.log("genuinely detection's, as against the decode both successors free-ride on.");
}

function printPhases(rows: Row[]): void {
  console.log("");
  console.log("THE SPLIT — medians, ms, and % of the phase total");
  const head = ["phase".padEnd(16), ...rows.map((r) => pad(r.name.slice(0, 11), 17))].join(" ");
  console.log(head);
  for (const p of PHASES) {
    console.log(
      [
        p.padEnd(16),
        ...rows.map((r) => {
          const ms = r.phase.get(p) ?? 0;
          const pct = r.phaseTotal > 0 ? (ms * 100) / r.phaseTotal : 0;
          return pad(`${ms.toFixed(2)} ${pct.toFixed(1).padStart(5)}%`, 17);
        }),
      ].join(" "),
    );
  }
  console.log(
    [
      "PHASE TOTAL".padEnd(16),
      ...rows.map((r) => pad(`${r.phaseTotal.toFixed(2)}       `, 17)),
    ].join(" "),
  );
  console.log(
    [
      "unattributed".padEnd(16),
      ...rows.map((r) =>
        pad(
          `${r.unattributed.toFixed(2)} ${(r.phaseTotal > 0 ? (r.unattributed * 100) / r.phaseTotal : 0).toFixed(1).padStart(5)}%`,
          17,
        ),
      ),
    ].join(" "),
  );
  console.log("");
  console.log("The sweep, read twice: the tap's own figure, and cold-minus-warm from outside it.");
  for (const r of rows) {
    const tapped = r.phase.get("sweep") ?? 0;
    const outside = r.cold - r.warm;
    console.log(
      `  ${r.name.padEnd(15)} tap ${pad(tapped.toFixed(1), 7)}   cold-warm ${pad(outside.toFixed(1), 7)}` +
        `   (cold ${r.cold.toFixed(0)}, warm ${r.warm.toFixed(0)})   agree to ${
          tapped > 0 ? `${((100 * Math.abs(tapped - outside)) / tapped).toFixed(1)}%` : "n/a"
        }`,
    );
  }
}

/**
 * The fit, for ONE architecture's images.
 *
 * Split by architecture rather than run over everything, because two of the
 * phases are PE32-only — `seh32-relation` reads MSVC's 32-bit SEH scope tables
 * and `interior-starts` takes the empty-map arm on x64, where `.pdata` has
 * already settled every boundary it arbitrates. Mixing a PE32 image with a
 * PE32+ one therefore reports a spread of hundreds for a phase that is simply
 * absent from half the population, which reads exactly like superlinearity and
 * is nothing of the kind.
 */
function printRates(rows: Row[], label: string): void {
  const denoms: [string, (r: Row) => number, string][] = [
    ["ms per MiB of .text", (r) => r.codeBytes / MiB, "3"],
    ["us per swept insn", (r) => r.insns / 1000, "3"],
    ["us per detected function", (r) => r.funcs / 1000, "2"],
  ];
  for (const [d, denom, dp] of denoms) {
    console.log("");
    console.log(`THE FIT, ${label} — ${d}; a flat row is linear in this denominator`);
    console.log(
      ["phase".padEnd(16), ...rows.map((r) => pad(r.name.slice(0, 11), 11)), pad("spread", 8)].join(
        " ",
      ),
    );
    for (const p of PHASES) {
      const vals = rows.map((r) => (r.phase.get(p) ?? 0) / denom(r));
      const nz = vals.filter((v) => v > 0);
      const spread = nz.length > 1 ? Math.max(...nz) / Math.min(...nz) : 0;
      console.log(
        [
          p.padEnd(16),
          ...vals.map((v) => pad(v.toFixed(Number(dp)), 11)),
          pad(spread > 0 ? `${spread.toFixed(1)}x` : "-", 8),
        ].join(" "),
      );
    }
    const totals = rows.map((r) => r.phaseTotal / denom(r));
    console.log(
      [
        "PHASE TOTAL".padEnd(16),
        ...totals.map((v) => pad(v.toFixed(Number(dp)), 11)),
        pad(`${(Math.max(...totals) / Math.min(...totals)).toFixed(1)}x`, 8),
      ].join(" "),
    );
  }
  console.log("");
  console.log("`spread` is the largest rate over the smallest, across the images given, counting");
  console.log("only images where the phase ran. Near 1 means the phase is linear in that");
  console.log("denominator; a large spread in EVERY denominator is what superlinearity looks");
  console.log("like. Small absolutes are noise — read a spread only where the milliseconds are.");
}

async function main(): Promise<void> {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.log("usage: npm run corpus:detectcost -- <pe path> [<pe path>...]");
    console.log("");
    console.log("Any x86 PE. Pass SEVERAL of very different sizes or the fit tables say");
    console.log("nothing: the four corpus binaries are ~50 KiB of .text and ~260 functions,");
    console.log("and the Windows/amd64 images `go` builds reach 2 MiB and thousands. See the");
    console.log("recipe in corpus/README.md; do not put one in the corpus directory.");
    return;
  }
  await loadCapstone();
  const rows: Row[] = [];
  for (const p of paths) {
    const row = await measure(p);
    if (row) rows.push(row);
  }
  if (rows.length === 0) return;
  rows.sort((a, b) => a.codeBytes - b.codeBytes);
  printPremise(rows);
  printPhases(rows);
  for (const [label, subset] of [
    ["PE32 (x86-32)", rows.filter((r) => !r.is64)],
    ["PE32+ (x86-64)", rows.filter((r) => r.is64)],
  ] as [string, Row[]][]) {
    if (subset.length < 2) {
      console.log("");
      console.log(
        `THE FIT, ${label} — ${subset.length} image${subset.length === 1 ? "" : "s"}; a fit needs at least two of different sizes.`,
      );
      continue;
    }
    printRates(subset, label);
  }
  const unfaithful = rows.filter((r) => !r.faithful).map((r) => r.name);
  if (unfaithful.length > 0) {
    console.log("");
    console.log(`WARNING: the phase run disagreed with dispatch on ${unfaithful.join(", ")} —`);
    console.log("this harness replicates dispatch's argument construction and has drifted from");
    console.log("it. Every figure above is a split of a call the worker does not make.");
  }
}

main();
