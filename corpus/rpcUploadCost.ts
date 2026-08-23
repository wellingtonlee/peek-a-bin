/**
 * What does re-sending one code section to the worker actually cost?
 *
 * THE INSTRUMENT peek-a-bin-9a8 HAS BEEN WAITING FOR, and the reason it was
 * waiting is recorded in its own staleness audit: "the timings NOT re-measured
 * and NOT measurable here". The bead proposes worker-side image residency —
 * upload each region once, name it by a handle thereafter — on the strength of
 * one figure, "116-192 ms of memcpy" per send, taken on a 253 MiB file that
 * does not exist on this machine and never has. A proposal whose whole case is
 * a number nobody can re-take is a proposal that can only be argued about, so
 * this takes a PATH and answers the question for whatever is at it.
 *
 * It reports, per image: what the three decode-bound RPCs cost, what
 * `prepareBinaryArgs` pays to ship the section to one of them, and the ratio.
 * The ratio is the whole point — an absolute in milliseconds says nothing on
 * its own, because both the copy and the work it feeds are linear in the size
 * of the section, so the interesting quantity is what fraction of the work the
 * copy is, and that fraction is a property of the *tool* rather than of the
 * file.
 *
 * WHY IT TAKES A PATH AND IS NOT IN `npm run corpus`. Same rule as
 * `corpus/jumpTableReach.ts`: that run's header names the four MSVC binaries
 * every standing figure is measured against, and the audits iterate over
 * whatever they find in the corpus directory, so an extra binary silently
 * changes the population of every gate. The image most worth pointing this at
 * is the ~2.4 MiB Windows/amd64 PE `go` builds (see the recipe in this
 * directory's README), which must NOT be stored there. Run it with
 * `npm run corpus:uploadcost -- <path> [<path>...]`.
 *
 * WHY IT IS DERIVED AND NOT TABULATED. Everything comes out of the image and
 * out of the code under test: the section from the PE header, the work from the
 * real `dispatch` with real Capstone handles, the copy from the real
 * `prepareBinaryArgs`. There is no address, no size and no timing constant to
 * go stale, so it runs against any PE on any machine. `SENDS_PER_LOAD` is the
 * one number that comes from reading rather than from measuring, and
 * {@link checkOneRegion} exists so that the *premise* behind it — that those
 * sends are all of one region — is re-derived here rather than trusted.
 *
 * WHAT IT IS NOT. A census and a stopwatch, never a gate. Wall clock on a
 * loaded machine is not a benchmark: run it twice and the columns move by tens
 * of percent. What does not move is the ratio's order of magnitude, and that is
 * the only thing any conclusion should rest on.
 */

import { readFileSync } from "node:fs";
import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { archForMachine } from "../src/disasm/arch";
import { parsePE } from "../src/pe/parser";
import { dataSectionRanges, findCodeSection } from "../src/pe/sections";
import { createWorkerState, dispatch } from "../src/workers/dispatch";
import { prepareBinaryArgs } from "../src/workers/transfer";

/**
 * How many times one load ships `.text` to the worker.
 *
 * Read off the call sites rather than measured, because nothing in the worker
 * path counts them: `App.tsx` sends it to `detectFunctions`, then to
 * `buildAllXrefs`, then again to `buildAllXrefs` when string extraction
 * finishes, and `useDisassemblyRows.ts` sends it to `hybridDisassemble`. An
 * upload-once scheme pays the copy on the first and none of the rest, so the
 * saving is `SENDS_PER_LOAD - 1` copies.
 */
const SENDS_PER_LOAD = 4;

/*
 * Still 4 after `peek-a-bin-x40u`, deliberately. That change shares the *decode*
 * between `detectFunctions` and both `buildAllXrefs` calls (see
 * `src/disasm/linearSweep.ts`); it does not change how many times the section
 * crosses the wire, which is what this constant counts and what an upload-once
 * scheme would collapse. What it does change is the denominator — the `xrefs`
 * column below is now the resolve alone — so the ratio this harness prints got
 * slightly *worse* for residency while the absolute load got much better, which
 * is the shape of the argument in `src/workers/transfer.ts`.
 */

/** Median of `n` samples, which is what to read off a loaded machine. */
function median(fn: () => number, n: number): number {
  fn();
  fn();
  const t = Array.from({ length: n }, fn).sort((a, b) => a - b);
  return t[Math.floor(t.length / 2)];
}

/**
 * Re-derive the premise behind {@link SENDS_PER_LOAD}: that those sends are of
 * ONE region, so a handle scheme would collapse them.
 *
 * The three call sites each build their own `new Uint8Array(fileBuffer,
 * pointerToRawData, sizeOfRawData)`, so the *view objects* differ and only the
 * triple is shared. That distinction decides the whole design — keying a cache
 * on view identity would collapse two sends of the four, keying it on the
 * triple collapses all four — so it is checked here rather than asserted.
 */
function checkOneRegion(buffer: ArrayBuffer, ptr: number, size: number): string {
  const views = [
    new Uint8Array(buffer, ptr, size),
    new Uint8Array(buffer, ptr, size),
    new Uint8Array(buffer, ptr, size),
  ];
  const distinctObjects = new Set(views).size;
  const sameTriple = views.every(
    (v) => v.buffer === buffer && v.byteOffset === ptr && v.byteLength === size,
  );
  return `${distinctObjects} distinct view objects over ${sameTriple ? "one" : "MORE THAN ONE"} (buffer, offset, length)`;
}

interface Row {
  name: string;
  codeMiB: number;
  detect: number;
  hybrid: number;
  xrefs: number;
  copy: number;
}

async function measure(path: string): Promise<Row | null> {
  const file = readFileSync(path);
  // One ArrayBuffer holding exactly the file, which is what the browser has
  // after `File.arrayBuffer()` / `fetch().arrayBuffer()` / IndexedDB.
  const buffer = file.buffer.slice(
    file.byteOffset,
    file.byteOffset + file.byteLength,
  ) as ArrayBuffer;
  const pe = parsePE(buffer);
  const text = findCodeSection(pe.sections);
  if (!text) {
    console.log(`${path}: no executable section — nothing is sent, nothing to measure`);
    return null;
  }
  const bytes = new Uint8Array(buffer, text.pointerToRawData, text.sizeOfRawData);
  const base = pe.optionalHeader.imageBase + text.virtualAddress;
  const arch = archForMachine(pe.coffHeader.machine);
  if (arch === "unsupported") {
    console.log(`${path}: unsupported architecture — every decode RPC refuses`);
    return null;
  }

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
  const time = async (method: Parameters<typeof dispatch>[0], extra: object): Promise<number> => {
    const t0 = performance.now();
    await dispatch(method, { ...common, ...extra }, state);
    return performance.now() - t0;
  };

  const detectArgs = { options: { pdataFunctions: pdataRanges }, pdataRanges };
  const detect = await time("detectFunctions", detectArgs);
  const found = (await dispatch("detectFunctions", { ...common, ...detectArgs }, state)) as {
    functions: { address: number; size: number }[];
    jumpTableSpans?: [number, number][];
  };
  const hybrid = await time("hybridDisassemble", {
    seeds: found.functions.map((f) => f.address),
    pdataRanges,
    jumpTableSpans: found.jumpTableSpans,
  });
  const xrefs = await time("buildAllXrefs", {
    stringAddrs: [],
    iatAddrs: [],
    funcEntries: found.functions.map((f) => [f.address, f.size]),
    dataSections: dataSectionRanges(pe.sections, pe.optionalHeader.imageBase),
  });

  // What ONE send costs: `prepareBinaryArgs`' private slice of the section. The
  // `postMessage` transfer of that slice is O(1) and is not modelled — see the
  // measurement table in src/workers/transfer.ts.
  const copy = median(() => {
    const t0 = performance.now();
    prepareBinaryArgs({ bytes, baseAddress: base });
    return performance.now() - t0;
  }, 25);

  console.log(`${path.split("/").pop()} — ${arch}, .text ${(bytes.length / 1024).toFixed(0)} KiB`);
  console.log(`  region: ${checkOneRegion(buffer, text.pointerToRawData, text.sizeOfRawData)}`);
  return {
    name: path.split("/").pop() ?? path,
    codeMiB: bytes.length / (1024 * 1024),
    detect,
    hybrid,
    xrefs,
    copy,
  };
}

function print(rows: Row[]): void {
  console.log("");
  console.log(
    "image           .text    detect   hybrid    xrefs     work  work/MiB   copy   copy/MiB   saving  % of work",
  );
  for (const r of rows) {
    const work = r.detect + r.hybrid + r.xrefs;
    const saving = r.copy * (SENDS_PER_LOAD - 1);
    console.log(
      [
        r.name.padEnd(14),
        `${(r.codeMiB * 1024).toFixed(0).padStart(5)}K`,
        `${r.detect.toFixed(0).padStart(8)}`,
        `${r.hybrid.toFixed(0).padStart(8)}`,
        `${r.xrefs.toFixed(0).padStart(8)}`,
        `${work.toFixed(0).padStart(8)}`,
        `${(work / r.codeMiB).toFixed(0).padStart(9)}`,
        `${r.copy.toFixed(3).padStart(7)}`,
        `${(r.copy / r.codeMiB).toFixed(3).padStart(10)}`,
        `${saving.toFixed(3).padStart(8)}`,
        `${((saving * 100) / work).toFixed(4).padStart(10)}%`,
      ].join(" "),
    );
  }
  console.log("");
  console.log("milliseconds. work = the three decode-bound RPCs over these bytes.");
  console.log(
    `saving = ${SENDS_PER_LOAD - 1} of ${SENDS_PER_LOAD} copies, i.e. what worker-side residency removes.`,
  );
  console.log("Both columns are linear in section size, so the last one is size-invariant:");
  console.log("extrapolate it, not the milliseconds. Wall clock on a loaded machine is not a");
  console.log("benchmark — read the order of magnitude, never the digits.");
}

/**
 * Demonstrate that the copy is linear out to the sizes the bead is about.
 *
 * Every real image here has a `.text` under 1 MiB, and the proposal was written
 * about a 200 MiB one that does not exist on this machine — so the ratio above
 * is only extrapolable if the copy really is linear, and asserting that would be
 * exactly the kind of unmeasured claim this file exists to replace. Synthetic
 * buffers, because the question is about `memcpy` and not about any file: a
 * window onto a larger `ArrayBuffer`, which is the shape `prepareBinaryArgs`
 * always gets.
 *
 * `structuredClone` with a transfer list runs the same algorithm `postMessage`
 * does, so the third column is the whole per-send cost and the gap between it
 * and the second is what transferring adds. It is ~0, which is the property the
 * slice-and-transfer design was chosen for.
 */
function scaleSweep(): void {
  const MiB = 1024 * 1024;
  console.log("");
  console.log("copy cost against section size (synthetic; slice, then slice + transfer)");
  console.log("  MiB     slice   ms/MiB    +transfer   ms/MiB");
  for (const mib of [0.5, 1, 8, 32, 64, 128, 200]) {
    const n = Math.round(mib * MiB);
    const file = new ArrayBuffer(n + 4096);
    const view = new Uint8Array(file, 4096, n);
    // Touch it so the pages are real; a fresh ArrayBuffer is zero-filled lazily
    // and timing a copy out of untouched pages measures the fault, not the copy.
    for (let i = 0; i < n; i += 4093) view[i] = i & 0xff;
    const reps = mib > 64 ? 5 : 15;
    const slice = median(() => {
      const t0 = performance.now();
      view.slice();
      return performance.now() - t0;
    }, reps);
    const posted = median(() => {
      const t0 = performance.now();
      const copy = view.slice();
      structuredClone(copy, { transfer: [copy.buffer] });
      return performance.now() - t0;
    }, reps);
    console.log(
      [
        String(mib).padStart(5),
        slice.toFixed(2).padStart(9),
        (slice / mib).toFixed(3).padStart(8),
        posted.toFixed(2).padStart(13),
        (posted / mib).toFixed(3).padStart(8),
      ].join(" "),
    );
  }
}

async function main(): Promise<void> {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.log("usage: npm run corpus:uploadcost -- <pe path> [<pe path>...]");
    console.log("");
    console.log("Any PE. The one worth pointing it at is the ~2.4 MiB Windows/amd64");
    console.log("image `go` builds — see the recipe in corpus/README.md — which must");
    console.log("NOT be put in the corpus directory.");
    console.log("");
    console.log("Pass --scale for the synthetic size sweep alone, which is what makes the");
    console.log("ratio extrapolable past the largest image on this machine.");
    return;
  }
  if (paths.length === 1 && paths[0] === "--scale") {
    scaleSweep();
    return;
  }
  await loadCapstone();
  const rows: Row[] = [];
  for (const p of paths) {
    const row = await measure(p);
    if (row) rows.push(row);
  }
  if (rows.length > 0) print(rows);
  scaleSweep();
}

main();
