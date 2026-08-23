/**
 * What does one decompile request cost, and how much of that is the payload?
 *
 * THE INSTRUMENT `peek-a-bin-yavq` HAS BEEN WAITING FOR, and the bead says so
 * itself: "WORTH MEASURING BEFORE FIXING, and nothing here can: the corpus
 * binaries are 90-180 KB (~280 functions), where all of this is noise." Its
 * subject is that `disasmClient.decompileFunction` re-sends `funcEntries` and
 * `funcExtents` — one entry per detected function — on every request, and its
 * option (a) is to send the extents only on the first request bearing a token,
 * which is a protocol change rather than a one-liner. Whether that is worth
 * anything is a question about a *ratio*, and the ratio needs a real image with
 * a realistic function count.
 *
 * So this takes a PATH and answers it for whatever is at it: it builds the
 * exact payload the app builds, clones each component the way `postMessage`
 * would, runs the real `decompileFunction` through the real `dispatch`, and
 * prints what fraction of a request each component is.
 *
 * WHY IT TAKES A PATH AND IS NOT IN `npm run corpus`. Same rule as
 * `corpus/rpcUploadCost.ts` and `corpus/jumpTableReach.ts`: that run's header
 * names the four MSVC binaries every standing figure is measured against, and
 * the audits iterate over whatever they find in the corpus directory, so an
 * extra binary silently changes the population of every gate. The image most
 * worth pointing this at is the ~2.4 MiB Windows/amd64 PE `go` builds (recipe
 * in this directory's README), which must NOT be stored there.
 *
 * WHY IT IS DERIVED AND NOT TABULATED. The section comes from the PE header,
 * the functions and instructions from the real `dispatch`, the xref map from
 * the real `buildTypedXrefMap`, the payload shape from `disasmClient`'s own
 * argument list, and the clone from the platform's `structuredClone` — which is
 * the algorithm `postMessage` runs. There is no address, no size and no timing
 * constant to go stale. {@link checkNothingIsTransferred} exists so the one
 * premise that is read rather than measured — that `prepareBinaryArgs` finds
 * nothing binary at the top level of these args, so the *whole* payload is
 * cloned — is re-derived here rather than trusted.
 *
 * WHAT IT IS NOT. A census and a stopwatch, never a gate. Wall clock on a
 * loaded machine is not a benchmark: run it twice and the columns move by tens
 * of percent. What does not move is the shares' order of magnitude, and that is
 * the only thing any conclusion should rest on.
 *
 * ONE THING IT DELIBERATELY OVERSTATES. `structuredClone` here does serialise
 * and deserialise in one process, where `postMessage` splits them across the
 * two threads. That is the right model for "what does a request cost", and it
 * is an over-estimate of what the *main thread* blocks for — so a component
 * this reports as negligible is negligible under either reading.
 *
 * ## What it measured, and why `peek-a-bin-yavq` was REFUSED
 *
 * Measured at `1198f4a` over the four corpus binaries and a 669 KiB-`.text`
 * Windows/amd64 PE from `go` (1973 functions, 155531 instructions), as a share
 * of one median decompile request:
 *
 * | image  | funcs | instructions | xrefEntries | funcEntries | funcExtents | work  |
 * |--------|-------|--------------|-------------|-------------|-------------|-------|
 * | t32    |   267 | 84.5%        | 8.2%        | 0.464%      | **0.135%**  | 5.45% |
 * | w32    |   265 | 84.0%        | 8.3%        | 0.559%      | **0.190%**  | 6.10% |
 * | t64    |   279 | 81.6%        | 8.7%        | 0.512%      | **0.148%**  | 4.27% |
 * | w64    |   275 | 72.1%        | 9.5%        | 0.613%      | **0.177%**  | 4.97% |
 * | go x64 |  1973 | 84.5%        | 9.4%        | 0.370%      | **0.107%**  | 1.00% |
 *
 * The table is ONE run. A second run over the same five moved every column by
 * tens of percent and the `funcExtents` share to 0.094%-0.226%, with
 * `funcExtents / funcEntries` spreading to 0.17x-0.34x — which is the noise
 * floor of a wall clock on a loaded machine, and is why nothing below quotes a
 * digit as a claim. In that run `instructions` on t64 read 99.2% of a request
 * against a `WHOLE PAYLOAD` of 95.4%, i.e. a member measured larger than the
 * whole; that is the same noise and not a contradiction, since the two are
 * medianed over different repetition counts.
 *
 * **`funcExtents` is a tenth to a quarter of one percent of a decompile request,
 * and that share does not grow with the image.** It is flat across a 7.4x
 * function count, and it is flat for a structural reason the table also carries:
 * the extents are linear in *functions* and the instruction array is linear in
 * *instructions*, so their ratio is fixed by the code's function density — 55 to
 * 79 instructions per function across these five, i.e. within 1.4x. There is no
 * size at which this becomes worth a protocol change, which is what option (a)
 * is: the bead's own sketch needs the worker to be able to answer "I do not hold
 * that token, resend", and `CallSummaryCache` holds exactly **one** entry and is
 * cleared by `configure`, so that reply is mandatory rather than an optimisation
 * — two round trips on a miss to save 0.1% on a hit.
 *
 * **The bead's own reasoning is confirmed**: `funcExtents` is **0.17x-0.34x
 * `funcEntries`** across the two runs (0.29x on four of five images in the
 * first), and `funcEntries` has to cross on every request because it carries
 * renames. So the thing proposed for removal is between a fifth and a third of
 * something that cannot be removed.
 *
 * **The strongest-looking version of the change is also refused, and it is not
 * the one the bead names.** `dispatch` reads the extents only when `args.is64`,
 * so on a **PE32** image they cross on every request and are discarded unread —
 * and the client already has `is64`, so `funcExtents: is64 ? … : undefined` is a
 * one-liner needing no protocol at all. That is measured rather than read off
 * the gate, and in both directions: decompiling *every* function of t32 and w32
 * with the extents and again without them gives **byte-identical** emitted C
 * over all 267 and 265 functions, while the same probe on t64 gives **different**
 * output (626878 against 624967 characters) — so it is a probe that can tell,
 * and not one that has stopped looking. It buys 0.135% (t32) and 0.190% (w32),
 * which is two to twenty-five times `peek-a-bin-9a8`'s refused saving and still
 * under a fifth of one percent, and it pays for that by putting the `is64` gate
 * in two places — one in `dispatch.ts` documented as "exactly the behaviour this
 * path had before the summary existed", one in the client — which is the
 * duplicate-rule shape `sections.ts`, `ripRelative.ts`, `funcInsns.ts` and
 * `stackIdiom.ts` each exist to end.
 *
 * ## Where the cost actually is, and why that is not this bead's to take
 *
 * **The payload is 94-99% of a decompile request and the instruction array
 * alone is 72-89 points of it** — 481 ms per request on the `go` image against
 * 5.7 ms of decompiling. That reproduces `src/workers/transfer.ts`'s own
 * 500k-instruction figure on a different machine and a different image: 3.09
 * µs per instruction here, 3.22 on the second run, against its 3.2 — which is
 * an independent re-derivation, and is why that module refuses
 * to build a transfer list out of per-instruction `bytes` views. `xrefEntries`
 * is the second member and was not in the bead's list at all.
 *
 * It is bounded by the client's `decompileCache`, which is keyed on the
 * function's address, so the RPC fires once per function per file — a user
 * clicking through fifty functions of the `go` image pays ~28 s of clone. The
 * fix for that is worker-side *instruction* residency, which is the bead's own
 * option (b) and a much larger change than either option (a) or the PE32
 * one-liner; it is deliberately left unattempted here rather than approximated.
 * Note it is NOT `peek-a-bin-9a8`, which is about re-sending the section's
 * BYTES and was measured and refused: the bytes are ~0.03% of the work they
 * feed, where these instructions are 84% of the work they feed, so the two
 * questions have opposite answers and must not be argued from each other.
 */

import { readFileSync } from "node:fs";
import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { archForMachine } from "../src/disasm/arch";
import { inferSignature } from "../src/disasm/signatures";
import { analyzeStackFrame } from "../src/disasm/stack";
import type { DisasmFunction, Instruction, Xref } from "../src/disasm/types";
import { parsePE } from "../src/pe/parser";
import { findCodeSection } from "../src/pe/sections";
import { createWorkerState, dispatch } from "../src/workers/dispatch";
import { prepareBinaryArgs } from "../src/workers/transfer";

/** How many functions to decompile when sampling the work side. */
const WORK_SAMPLE = 40;

/** Median of `n` samples, which is what to read off a loaded machine. */
function median(fn: () => number, n: number): number {
  fn();
  fn();
  const t = Array.from({ length: n }, fn).sort((a, b) => a - b);
  return t[Math.floor(t.length / 2)];
}

/** Wall time of one clone of `v`, taken as a median. */
function cloneMs(v: unknown, reps: number): number {
  return median(() => {
    const t0 = performance.now();
    structuredClone(v);
    return performance.now() - t0;
  }, reps);
}

/**
 * Re-derive the premise that the whole payload is CLONED and none of it is
 * transferred.
 *
 * `prepareBinaryArgs` replaces each top-level `ArrayBuffer`/`ArrayBufferView`
 * with a private copy and transfers that, and its walk is deliberately
 * top-level only — an `Instruction[]` carries a `bytes` view per element and
 * transferring 500k of those measured 80.6 s against 1.6 s to clone them (see
 * `src/workers/transfer.ts`). So for this payload it should find nothing, and
 * every byte below — including one tiny buffer per instruction — crosses by
 * clone. If that ever stops being true the numbers below stop meaning what they
 * say, so it is checked rather than asserted.
 */
function checkNothingIsTransferred(payload: object): string {
  const { args, transfer } = prepareBinaryArgs(payload);
  const untouched = args === payload;
  return `${transfer.length} buffers transferred, args object ${untouched ? "returned as-is" : "REWRITTEN"}`;
}

interface Row {
  name: string;
  funcs: number;
  insns: number;
  xrefs: number;
  /** Per-component clone cost, in payload order. */
  parts: { key: string; ms: number }[];
  whole: number;
  firstWork: number;
  medianWork: number;
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
    console.log(`${path}: no executable section — nothing is decompiled`);
    return null;
  }
  const arch = archForMachine(pe.coffHeader.machine);
  if (arch !== "x86") {
    // `mcp/tools.ts` and `dispatch.ts` both refuse decompilation above address
    // resolution for anything that is not x86, so there is no request to cost.
    console.log(`${path}: ${arch} — the decompiler refuses, so there is no request here`);
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

  const found = (await dispatch(
    "detectFunctions",
    { ...common, options: { pdataFunctions: pdataRanges }, pdataRanges },
    state,
  )) as { functions: DisasmFunction[]; jumpTableSpans?: [number, number][] };
  const functions = found.functions;
  const instructions = (await dispatch(
    "hybridDisassemble",
    {
      ...common,
      seeds: functions.map((f) => f.address),
      pdataRanges,
      jumpTableSpans: found.jumpTableSpans,
    },
    state,
  )) as Instruction[];
  // Exactly what `useDisassemblyRows` posts and hands `useDecompileTabs`. The
  // RPC answers with ENTRIES; `disasmClient` builds a `Map` from them and
  // `decompileFunction` turns that straight back into entries, so this array is
  // literally the `xrefEntries` member of the payload. Taking the Map's
  // `.entries()` instead would silently measure an extra index per row, because
  // an Array has that method too.
  const xrefEntries = (await dispatch(
    "buildTypedXrefMap",
    {
      ...common,
      instructions,
      imageBounds: {
        base: pe.optionalHeader.imageBase,
        size: pe.optionalHeader.sizeOfImage,
      },
    },
    state,
  )) as [number, Xref[]][];

  // The payload, built the way `useDecompileTabs.decompileLow` and
  // `disasmClient.decompileFunction` build it between them. `funcMap` carries
  // display names, which is why the client rebuilds it per call.
  const func = functions[Math.floor(functions.length / 2)];
  const stackFrame = analyzeStackFrame(func, instructions, arch, pe.is64);
  const signature = inferSignature(func, instructions, arch, pe.is64);
  const funcMap = new Map(functions.map((f) => [f.address, { name: f.name, address: f.address }]));
  const payload = {
    func,
    instructions,
    xrefEntries,
    stackFrame,
    signature,
    is64: pe.is64,
    funcEntries: Array.from(funcMap.entries()),
    runtimeFunctions: pe.runtimeFunctions,
    funcExtents: functions.map((f) => [f.address, f.size] as [number, number]),
    insnsToken: 1,
    machine: pe.coffHeader.machine,
  };

  // Reps scale down for the expensive members so a large image still finishes;
  // the median is over whatever they get, and three samples of a 300 ms clone
  // is a steadier reading than fifteen of a 0.3 ms one.
  const parts = (Object.keys(payload) as (keyof typeof payload)[]).map((key) => {
    const v = payload[key];
    const big = key === "instructions" || key === "xrefEntries";
    return { key, ms: cloneMs(v, big ? 5 : 25) };
  });
  const whole = cloneMs(payload, 5);

  // The work: the real RPC through the real dispatch. The FIRST request bearing
  // a token is the only one that reads `funcExtents` — `CallSummaryCache` serves
  // every later one — so it is reported apart from the median, because that
  // asymmetry is the whole of the bead's option (a).
  const decompileArgs = (f: DisasmFunction, token: number): object => ({
    ...payload,
    func: f,
    stackFrame: analyzeStackFrame(f, instructions, arch, pe.is64),
    signature: inferSignature(f, instructions, arch, pe.is64),
    insnsToken: token,
  });
  const t0 = performance.now();
  await dispatch("decompileFunction", decompileArgs(func, 1), state);
  const firstWork = performance.now() - t0;

  const stride = Math.max(1, Math.floor(functions.length / WORK_SAMPLE));
  const times: number[] = [];
  for (let i = 0; i < functions.length && times.length < WORK_SAMPLE; i += stride) {
    const t = performance.now();
    await dispatch("decompileFunction", decompileArgs(functions[i], 1), state);
    times.push(performance.now() - t);
  }
  times.sort((a, b) => a - b);

  console.log(
    `${path.split("/").pop()} — ${arch}, .text ${(bytes.length / 1024).toFixed(0)} KiB, ` +
      `${functions.length} functions, ${instructions.length} instructions`,
  );
  console.log(`  premise: ${checkNothingIsTransferred(payload)}`);
  return {
    name: path.split("/").pop() ?? path,
    funcs: functions.length,
    insns: instructions.length,
    xrefs: xrefEntries.length,
    parts,
    whole,
    firstWork,
    medianWork: times[Math.floor(times.length / 2)],
  };
}

function print(rows: Row[]): void {
  for (const r of rows) {
    const payload = r.parts.reduce((a, p) => a + p.ms, 0);
    const request = r.whole + r.medianWork;
    console.log("");
    console.log(
      `${r.name} — ${r.funcs} functions, ${r.insns} instructions, ${r.xrefs} xref entries`,
    );
    console.log("  component            clone ms   % of a median request");
    for (const p of [...r.parts].sort((a, b) => b.ms - a.ms)) {
      console.log(
        `  ${p.key.padEnd(20)} ${p.ms.toFixed(3).padStart(8)}   ${((p.ms * 100) / request).toFixed(3).padStart(8)}%`,
      );
    }
    console.log(
      `  ${"(sum of parts)".padEnd(20)} ${payload.toFixed(3).padStart(8)}   ${((payload * 100) / request).toFixed(3).padStart(8)}%`,
    );
    console.log(
      `  ${"WHOLE PAYLOAD".padEnd(20)} ${r.whole.toFixed(3).padStart(8)}   ${((r.whole * 100) / request).toFixed(3).padStart(8)}%`,
    );
    console.log(
      `  ${"decompile (median)".padEnd(20)} ${r.medianWork.toFixed(3).padStart(8)}   ${((r.medianWork * 100) / request).toFixed(3).padStart(8)}%`,
    );
    console.log(
      `  ${"decompile (first)".padEnd(20)} ${r.firstWork.toFixed(3).padStart(8)}   ` +
        "  — pays the whole-image callee-clobber build, and is the ONLY",
    );
    console.log(`  ${"".padEnd(20)} ${"".padStart(8)}     request that reads funcExtents at all.`);
    // The two derived quantities the conclusion actually rests on. The first is
    // why the share above is a property of the tool rather than of the file:
    // `funcExtents` is linear in functions and `instructions` is linear in
    // instructions, so their ratio is fixed by the code's function density,
    // which is a compiler's business and moves by well under an order of
    // magnitude between images. The second is the bead's own argument, measured:
    // the extents are strictly smaller than the names, and the names have to
    // cross on every request because they carry renames.
    const extents = r.parts.find((p) => p.key === "funcExtents");
    const entries = r.parts.find((p) => p.key === "funcEntries");
    const insns = r.parts.find((p) => p.key === "instructions");
    if (extents && entries && insns) {
      console.log(
        `  density ${(r.insns / r.funcs).toFixed(1)} instructions/function; ` +
          `funcExtents is ${((extents.ms * 100) / insns.ms).toFixed(3)}% of the instruction clone ` +
          `and ${(extents.ms / entries.ms).toFixed(2)}x funcEntries, which must cross for renames`,
      );
    }
  }
  console.log("");
  console.log("milliseconds. A request is WHOLE PAYLOAD + decompile (median): what one click");
  console.log("costs end to end. structuredClone is the algorithm postMessage runs, and here it");
  console.log("serialises AND deserialises in one process, so it over-states what the main");
  console.log("thread blocks for. Read the shares, never the digits — wall clock on a loaded");
  console.log("machine moves by tens of percent between runs, and (sum of parts) sitting a few");
  console.log("percent either side of WHOLE PAYLOAD is that noise, not a missing member: the");
  console.log("two big components are medianed over fewer repetitions than the small ones.");
  console.log("");
  console.log("The RPC fires once per function per file — disasmClient's decompileCache is");
  console.log("keyed on the function address — so multiply a request by the functions a user");
  console.log("opens, not by anything the loader does.");
}

async function main(): Promise<void> {
  const paths = process.argv.slice(2);
  if (paths.length === 0) {
    console.log("usage: npm run corpus:decompilecost -- <pe path> [<pe path>...]");
    console.log("");
    console.log("Any x86 PE. The one worth pointing it at is the ~2.4 MiB Windows/amd64");
    console.log("image `go` builds — see the recipe in corpus/README.md — which must NOT");
    console.log("be put in the corpus directory. ARM64 images are declined, because the");
    console.log("decompiler refuses them before there is a request to cost.");
    return;
  }
  await loadCapstone();
  const rows: Row[] = [];
  for (const p of paths) {
    const row = await measure(p);
    if (row) rows.push(row);
  }
  if (rows.length > 0) print(rows);
}

void main();
