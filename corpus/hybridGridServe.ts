/**
 * Does `hybridDisassemble` decode at addresses the linear sweep already has?
 *
 * THE NUMBER peek-a-bin-x40u DEFERRED. That change shared one linear sweep
 * between `detectFunctions` and both `buildAllXrefs` calls and deliberately left
 * `hybridDisassemble` out, because it is not a transcription of the sweep:
 * recursive descent over a BFS work queue plus a gap fill decodes ONE
 * INSTRUCTION AT A TIME at addresses a *caller* named, and a linear sweep's grid
 * need not have an instruction at any of them. Whether it does was the question
 * that decided it, and x40u closed leaving a comment in `src/workers/dispatch.ts`
 * pointing at itself "for the coincidence rate" — a number it never took.
 *
 * This takes it, and then answers the harder question beside it. Three rows:
 *
 *  * **The coincidence rate**, split by the three phases, because they have
 *    different reasons to coincide: the `.pdata` bulk pass and the gap fill walk
 *    linearly, which is what a sweep does, while the BFS jumps to call and
 *    branch targets — which are function *starts*, and a function start is
 *    exactly where a linear sweep is most likely to be aligned. So do not
 *    predict the answer from the mechanism; it is measured here.
 *  * **The differential**, which is the row that actually protects anything.
 *    A coincidence rate says the addresses line up; it does not say the
 *    instructions do. Both paths are driven through the real `dispatch` with
 *    real Capstone and the two `Instruction[]` are compared element for element
 *    and field for field — `bytes`, `source` and `comment` included. Any
 *    non-zero here is a defect, whatever the rate says.
 *  * **The timing**, both sides pinned in one process, because the only
 *    honest before-and-after is one that cannot be a comparison between two
 *    different machine loads.
 *
 * WHY IT TAKES A PATH AND IS NOT IN `npm run corpus`. `jumpTableReach.ts`' and
 * `rpcUploadCost.ts`' reason: that run's header names the four MSVC binaries
 * every standing figure is measured against, and its audits iterate over
 * whatever they find in the corpus directory. The image most worth pointing this
 * at is the ~2.4 MiB Windows/amd64 PE `go` builds (recipe in this directory's
 * README), which must NOT be stored there. `npm run corpus:gridserve -- <path>`.
 *
 * WHAT IT IS NOT. Not a gate, and the differential is the only row that could
 * ever become one. The rate is a property of the images it is pointed at; the
 * milliseconds are a wall clock on a loaded machine and move by tens of percent
 * between runs. Read the differential as a yes/no and the rest as a census.
 */

import { readFileSync } from "node:fs";
import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { archForMachine } from "../src/disasm/arch";
import { type SweptInsn, sweepX86 } from "../src/disasm/linearSweep";
import type { Instruction } from "../src/disasm/types";
import { parsePE } from "../src/pe/parser";
import { findCodeSection } from "../src/pe/sections";
import { createWorkerState, dispatch, type WorkerState } from "../src/workers/dispatch";

/** Median of a sample, which is what to read off a loaded machine. */
function median(xs: number[]): number {
  const s = [...xs].sort((a, b) => a - b);
  return s[s.length >> 1];
}

/**
 * Every `cs.disasm` this run makes, recorded by WRAPPING the handle.
 *
 * `corpus/arm64.ts`' rule for its sweep-cache differential: an instrument
 * belongs outside the code it judges, so nothing is counted inside
 * `capstoneWindow.ts` and nothing here replicates `hybridDisassemble`'s loop.
 * `count === 1` separates the BFS's per-address `decodeOne` from the two bulk
 * phases; those two are told apart by call order, since the `.pdata` pass runs
 * before the BFS and the gap fill after it.
 */
interface Call {
  count: number;
  produced: { address: number; mnemonic: string; opStr: string; size: number }[];
}

function recording(cs: unknown, sink: { calls: Call[]; on: boolean }): unknown {
  const handle = cs as {
    disasm: (b: Uint8Array, o?: { address?: number; count?: number }) => unknown[];
  };
  const real = handle.disasm.bind(handle);
  handle.disasm = (bytes, options) => {
    const out = real(bytes, options);
    if (sink.on) {
      sink.calls.push({
        count: options?.count ?? -1,
        produced: (out ?? []).map((i) => {
          const r = i as { address: number; mnemonic: string; opStr: string; size: number };
          return { address: r.address, mnemonic: r.mnemonic, opStr: r.opStr, size: r.size };
        }),
      });
    }
    return out;
  };
  return handle;
}

type Phase = "pdata" | "bfs" | "gap";

interface Tally {
  calls: number;
  insns: number;
  hit: number;
  agree: number;
}

interface Row {
  name: string;
  arch: string;
  codeKiB: number;
  gridInsns: number;
  hybridInsns: number;
  tally: Record<Phase, Tally>;
  diffs: number;
  ownBuffers: boolean;
  servedMs: number;
  decodedMs: number;
}

/** Every field of an `Instruction` a caller can observe. */
function sameInstruction(a: Instruction, b: Instruction): boolean {
  return (
    a.address === b.address &&
    a.mnemonic === b.mnemonic &&
    a.opStr === b.opStr &&
    a.size === b.size &&
    a.source === b.source &&
    a.comment === b.comment &&
    a.bytes.length === b.bytes.length &&
    a.bytes.every((v, i) => v === b.bytes[i])
  );
}

async function measure(path: string, reps: number): Promise<Row | null> {
  const file = readFileSync(path);
  const buffer = file.buffer.slice(
    file.byteOffset,
    file.byteOffset + file.byteLength,
  ) as ArrayBuffer;
  const pe = parsePE(buffer);
  const text = findCodeSection(pe.sections);
  if (!text) {
    console.log(`${path}: no executable section — nothing to disassemble`);
    return null;
  }
  const arch = archForMachine(pe.coffHeader.machine);
  if (arch !== "x86") {
    console.log(`${path}: ${arch} — this is the x86 sweep; A64 shares its whole array already`);
    return null;
  }
  const base = pe.optionalHeader.imageBase + text.virtualAddress;
  /** A fresh view each time, as `prepareBinaryArgs` hands each RPC. */
  const section = () =>
    new Uint8Array(buffer.slice(text.pointerToRawData, text.pointerToRawData + text.sizeOfRawData));
  const pdataRanges = pe.runtimeFunctions?.map((rf) => ({
    beginAddress: pe.optionalHeader.imageBase + rf.beginAddress,
    endAddress: pe.optionalHeader.imageBase + rf.endAddress,
  }));

  function fresh(sink?: { calls: Call[]; on: boolean }): WorkerState {
    const st = createWorkerState(Promise.resolve());
    const cs32 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_32);
    const cs64 = new Capstone(Const.CS_ARCH_X86, Const.CS_MODE_64);
    st.cs32 = (sink ? recording(cs32, sink) : cs32) as never;
    st.cs64 = (sink ? recording(cs64, sink) : cs64) as never;
    st.arch = arch;
    return st;
  }

  const common = { baseAddress: base, is64: pe.is64, machine: pe.coffHeader.machine };
  async function detect(st: WorkerState) {
    return (await dispatch(
      "detectFunctions",
      { ...common, bytes: section(), options: { pdataFunctions: pdataRanges }, pdataRanges },
      st,
    )) as { functions: { address: number }[]; jumpTableSpans?: [number, number][] };
  }

  /**
   * One load's `hybridDisassemble`, `reps` times.
   *
   * `served: false` clears the slot before each repetition, which is exactly the
   * tree before peek-a-bin-iqzu: detection still swept — it always did — and
   * this method simply could not see the result.
   */
  async function run(served: boolean, sink?: { calls: Call[]; on: boolean }) {
    const st = fresh(sink);
    const found = await detect(st);
    const args = {
      ...common,
      seeds: found.functions.map((f) => f.address),
      pdataRanges,
      jumpTableSpans: found.jumpTableSpans,
    };
    const times: number[] = [];
    let insns: Instruction[] = [];
    for (let i = 0; i < reps; i++) {
      if (!served) st.x86Sweep.clear();
      if (sink) sink.on = true;
      const t0 = performance.now();
      insns = (await dispatch(
        "hybridDisassemble",
        { ...args, bytes: section() },
        st,
      )) as Instruction[];
      times.push(performance.now() - t0);
      if (sink) sink.on = false;
    }
    return { insns, ms: median(times) };
  }

  // The coincidence rate is a fact about the DECODING path, so it is taken with
  // the slot cleared — that is the population the question is about.
  const sink = { calls: [] as Call[], on: false };
  const decoded = await run(false, sink);
  const served = await run(true);

  // The grid itself, from the same sweep the memo would hold.
  const censusState = fresh();
  const grid: SweptInsn[] = sweepX86(
    section(),
    base,
    (pe.is64 ? censusState.cs64 : censusState.cs32) as never,
    "census",
  );
  const gridAt = new Map<number, SweptInsn>();
  for (const g of grid) gridAt.set(g.address, g);

  const tally: Record<Phase, Tally> = {
    pdata: { calls: 0, insns: 0, hit: 0, agree: 0 },
    bfs: { calls: 0, insns: 0, hit: 0, agree: 0 },
    gap: { calls: 0, insns: 0, hit: 0, agree: 0 },
  };
  // One load's worth: the last repetition's calls. The two bulk phases are told
  // apart by where they sit relative to the first per-address call, since the
  // `.pdata` pass runs before the BFS and the gap fill after it.
  const perRep = Math.floor(sink.calls.length / reps);
  const window = sink.calls.slice(sink.calls.length - perRep);
  const firstBfs = window.findIndex((c) => c.count === 1);
  window.forEach((c, i) => {
    const phase: Phase = c.count === 1 ? "bfs" : firstBfs === -1 || i < firstBfs ? "pdata" : "gap";
    const t = tally[phase];
    t.calls++;
    // A `count: 1` call has only `insns[0]` read by its caller.
    for (const ins of c.count === 1 ? c.produced.slice(0, 1) : c.produced) {
      t.insns++;
      const g = gridAt.get(ins.address);
      if (!g) continue;
      t.hit++;
      if (g.mnemonic === ins.mnemonic && g.opStr === ins.opStr && g.size === ins.size) t.agree++;
    }
  });

  let diffs = decoded.insns.length === served.insns.length ? 0 : 1;
  const n = Math.min(decoded.insns.length, served.insns.length);
  // A served `bytes` that is a VIEW onto the section would read identically in
  // every field and would make the reply's structured clone serialise the whole
  // `.text` once per instruction. There is no other check for it.
  //
  // The property is that it does not ALIAS the section, not that its buffer is
  // exactly `size` long: capstone-wasm backs each of its own records with a
  // fixed 24-byte `HEAPU8.slice` of the `cs_insn.bytes[24]` field and views the
  // first `size` of it, so an exact test reports every decoded instruction as a
  // defect. Measured on t32: 18045 of 18045, buffer 24 at every instruction
  // size — which is what a first draft of this row did report.
  const sectionBuffer = section().buffer;
  let ownBuffers = true;
  for (let i = 0; i < n; i++) {
    if (!sameInstruction(decoded.insns[i], served.insns[i])) diffs++;
    const held = served.insns[i].bytes.buffer;
    if (held === sectionBuffer || held.byteLength > 64) ownBuffers = false;
  }

  return {
    name: path.split("/").pop() ?? path,
    arch: pe.is64 ? "x64" : "x86-32",
    codeKiB: text.sizeOfRawData / 1024,
    gridInsns: grid.length,
    hybridInsns: served.insns.length,
    tally,
    diffs,
    ownBuffers,
    servedMs: served.ms,
    decodedMs: decoded.ms,
  };
}

function pct(a: number, b: number): string {
  return b === 0 ? "n/a" : `${((a * 100) / b).toFixed(1)}%`;
}

function print(rows: Row[]): void {
  console.log("");
  console.log("COINCIDENCE — instructions hybridDisassemble decodes, at an address the grid also");
  console.log("has an instruction starting at, and agreeing in mnemonic, operands and size.");
  console.log("");
  console.log("image        .text     grid   hybrid    pdata      bfs      gap    TOTAL    agree");
  for (const r of rows) {
    const t = r.tally;
    const insns = t.pdata.insns + t.bfs.insns + t.gap.insns;
    const hit = t.pdata.hit + t.bfs.hit + t.gap.hit;
    const agree = t.pdata.agree + t.bfs.agree + t.gap.agree;
    console.log(
      [
        r.name.padEnd(12),
        `${r.codeKiB.toFixed(0).padStart(5)}K`,
        String(r.gridInsns).padStart(8),
        String(r.hybridInsns).padStart(8),
        pct(t.pdata.hit, t.pdata.insns).padStart(8),
        pct(t.bfs.hit, t.bfs.insns).padStart(8),
        pct(t.gap.hit, t.gap.insns).padStart(8),
        pct(hit, insns).padStart(8),
        pct(agree, hit).padStart(8),
      ].join(" "),
    );
  }
  console.log("");
  console.log("DIFFERENTIAL — served against decoded, element for element and field for field");
  console.log(
    "(bytes, source and comment included). Non-zero is a defect, whatever the rate says.",
  );
  console.log("");
  console.log("image          insns     differing   own bytes buffers   decoded   served   off");
  for (const r of rows) {
    console.log(
      [
        r.name.padEnd(12),
        String(r.hybridInsns).padStart(9),
        String(r.diffs).padStart(13),
        (r.ownBuffers ? "yes" : "NO").padStart(19),
        `${r.decodedMs.toFixed(0).padStart(9)}`,
        `${r.servedMs.toFixed(0).padStart(8)}`,
        `${(100 - (r.servedMs * 100) / r.decodedMs).toFixed(0).padStart(5)}%`,
      ].join(" "),
    );
  }
  console.log("");
  console.log("milliseconds, medians, both sides pinned in one process. Wall clock on a loaded");
  console.log("machine is not a benchmark — read the order of magnitude, never the digits.");
  const bad = rows.filter((r) => r.diffs > 0 || !r.ownBuffers);
  if (bad.length > 0) {
    console.log("");
    console.log(`DEFECT: ${bad.map((r) => r.name).join(", ")} — see the differential above.`);
  }
}

async function main(): Promise<void> {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.log("usage: npm run corpus:gridserve -- <pe path> [<pe path>...]");
    console.log("");
    console.log("Any x86 PE. The one worth pointing it at is the ~2.4 MiB Windows/amd64");
    console.log("image `go` builds — see the recipe in corpus/README.md — which must");
    console.log("NOT be put in the corpus directory.");
    return;
  }
  await loadCapstone();
  const rows: Row[] = [];
  for (const p of paths) {
    const row = await measure(p, 5);
    if (row) rows.push(row);
  }
  if (rows.length > 0) print(rows);
}

main();
