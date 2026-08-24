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
 *
 * ## What `peek-a-bin-9gc9` then did, and why it was not residency
 *
 * The bead above proposed worker-side *residency* under the client's token. The
 * premise — that the array has to live somewhere — is false, and reading the
 * consumers is what shows it: `decompileFunction` hands the array to `buildCFG`
 * and to nothing else, `buildCFG` narrows it with `getFuncInsns` on its first
 * line, and the only reader of the *whole* section is the callee-clobber
 * summary, which is cached against the token and so is read once per file. The
 * same is true of the xref map, which `buildCFG` reads only at the addresses of
 * those same instructions.
 *
 * So the client sends this function's slice of each (`collectFuncInsns`,
 * `funcXrefEntries`) and the worker asks — `{ needInstructions: true }` — on the
 * one request that needs more. Nothing is retained anywhere, which is the whole
 * advantage over residency: `peek-a-bin-x40u` measured an `Instruction[]` at
 * ~135 B/instruction, 24 MB for the `go` image, and the main thread already
 * holds that array.
 *
 * Measured at `11408ac`, both sides pinned, and this harness now reports both
 * payloads side by side plus the equivalence census:
 *
 * | image  | before  | after   | cheaper | payload share    | resends | differ |
 * |--------|---------|---------|---------|------------------|---------|--------|
 * | t32    | 56.6 ms |  3.4 ms |  16.6x  | 94.7% -> 11.3%   | 0       | 0/267  |
 * | t64    | 54.8 ms |  3.0 ms |  18.1x  | 95.7% -> 23.1%   | 1       | 0/279  |
 * | w32    | 53.0 ms |  2.3 ms |  22.9x  | 96.3% -> 16.0%   | 0       | 0/265  |
 * | w64    | 49.0 ms |  2.4 ms |  20.5x  | 96.8% -> 35.2%   | 1       | 0/275  |
 * | go x64 |  629 ms | 11.2 ms |  56.3x  | 99.0% -> 41.6%   | 1       | 0/1973 |
 *
 * One resend per x64 image and none for either PE32 image, because
 * `calleeClobbersFor` returns nothing unless `is64` — so no summary is built and
 * the section is never wanted. **0 of 3059 functions across the five emit
 * different C**, which is the claim the change rests on; the property itself is
 * pinned and negative-controlled in `src/disasm/__tests__/funcInsns.test.ts` and
 * `src/workers/__tests__/disasmClient.test.ts`.
 *
 * **READ THE RESIDUE, because it moves this bead's own arithmetic.** With the
 * two big arrays gone, the `go` image's remaining payload is `funcEntries` 2.18
 * ms (19.5% of a request), `runtimeFunctions` 1.53 ms (13.7%) and `funcExtents`
 * 0.645 ms (5.8%), against `funcInsns` at 0.012 ms and the xref rows at 0.004
 * ms. `funcEntries` still cannot be cached — it carries renames. `funcExtents`
 * was refused at 0.1-0.2% of a request and is now ~6% of a much smaller one,
 * with the resend protocol it was said to need now built — but its ABSOLUTE cost
 * is unchanged, which is what that refusal rested on, so re-measure rather than
 * assume.
 *
 * ## `peek-a-bin-qmlz` then took `runtimeFunctions`, with no protocol at all
 *
 * That member is the `.pdata` table, linear in the image, and reading its
 * consumer is again what settles it: `decompileFunction` hands it to
 * `wrapExceptionRegions` and to nothing else, and that picks **at most one**
 * record — by a *begin-address* match modulo a recovered image base, never by an
 * extent. So `funcExceptionRecord` (`src/disasm/funcInsns.ts`, beside
 * `collectFuncInsns` and `funcXrefEntries`) is applied by the client and again by
 * the worker; it is idempotent, so sending its own answer back is exact. No key,
 * no cache, nothing retained — which is why `peek-a-bin-9a8`'s rule about a key
 * being cheaper than the work does not arise.
 *
 * Measured at `755ea94`, with the whole table and the one row clocked in the
 * SAME process so machine noise cancels (two runs):
 *
 * | image  | .pdata rows | whole table | one row  | member share    | payload          |
 * |--------|-------------|-------------|----------|-----------------|------------------|
 * | t32    |           0 | 0.001 ms    | 0.001 ms | 0.002% -> 0.03% | unmoved          |
 * | t64    |         240 | 0.193 ms    | 0.001 ms | 7.24% -> 0.032% | 0.670 -> 0.419ms |
 * | w32    |           0 | 0.001 ms    | 0.001 ms | 0.002% -> 0.03% | unmoved          |
 * | w64    |         235 | 0.210 ms    | 0.003 ms | 8.69% -> 0.150% | 1.137 -> 0.647ms |
 * | go x64 |        1641 | 1.369 ms    | 0.001 ms | 18.9% -> 0.012% | 4.162 -> 2.599ms |
 *
 * PE32 has no `.pdata` at all, so t32/w32 are the untouched control and their
 * rising *share* is only the denominator shrinking — the same trap `funcExtents`
 * sets. w64 is the one image whose median function has a record, so 0.003 ms is
 * the one-row cost measured and the rest is the cost of cloning `undefined`.
 *
 * **THE CENSUS NEEDED A LIVENESS HALF for this member**, which is the `.pdata`
 * line printed beside it: `runtimeFunctions` is read at one place and its whole
 * observable effect is a `__try`, so an image emitting none would score a change
 * that dropped the array entirely as clean. It is **50 on t64 and 46 on w64,
 * equal under both payloads** — also exactly the handler-bearing row counts, so
 * the emitted C and the table corroborate each other — 2 on the `go` image, and
 * **0 on the PE32 pair, which the row labels vacuous rather than reporting as a
 * pass**.
 */

import { readFileSync } from "node:fs";
import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { archForMachine } from "../src/disasm/arch";
import { collectFuncInsns, funcExceptionRecord, funcXrefEntries } from "../src/disasm/funcInsns";
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
  /** The same, for the per-function payload the client sends since 9gc9. */
  slimParts: { key: string; ms: number }[];
  slimWhole: number;
  /** Mean members of the two slimmed arrays, per request. */
  meanOwnInsns: number;
  meanOwnXrefs: number;
  /** Functions whose emitted C differs between the two payloads, of `funcs`. */
  differing: number;
  /** `.pdata` rows in the image, and how many the per-function payload sends. */
  pdataRows: number;
  pdataSent: number;
  /** Functions emitting a `__try`, whole payload and per-function payload. */
  wholeTries: number;
  slimTries: number;
  /** Requests it took to decompile every function under the real protocol. */
  messages: number;
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
  const xrefMap = new Map(xrefEntries);
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

  // THE PAYLOAD SINCE peek-a-bin-9gc9, built the way `disasmClient` builds it:
  // this function's own instructions and its own xref rows. `instructions` is
  // absent — it crosses only on the retry the worker asks for, once per file.
  // `runtimeFunctions` is the one `.pdata` row this function can consult, not
  // the image's table — the same rule the pipeline applies, so the slice is
  // exact (peek-a-bin-qmlz). PE32 has no `.pdata`, so on t32/w32 both columns
  // read the same nothing.
  const pdataRecord = funcExceptionRecord(func, pe.runtimeFunctions);
  const slimPayload = {
    ...payload,
    instructions: undefined,
    funcInsns: collectFuncInsns(func, instructions),
    xrefEntries: funcXrefEntries(func, xrefMap),
    runtimeFunctions: pdataRecord ? [pdataRecord] : undefined,
  };
  const slimParts = (Object.keys(slimPayload) as (keyof typeof slimPayload)[]).map((key) => ({
    key:
      key === "funcInsns" ? "funcInsns (own)" : key === "xrefEntries" ? "xrefEntries (own)" : key,
    ms: cloneMs(slimPayload[key], 25),
  }));
  const slimWhole = cloneMs(slimPayload, 25);

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

  // ── The claim the slim payload rests on, over EVERY function ──────────────
  //
  // Decompile the whole image twice: once from the whole-section payload, once
  // from the per-function one under the real protocol, and compare the emitted C
  // string by string. A fresh `WorkerState` each way, so the two runs see the
  // same `StructRegistry` history in the same order — struct synthesis is
  // cross-function, so sharing one would make the second run's input depend on
  // the first's.
  //
  // This is a CENSUS of a property, not a gate, and it is here because a
  // measurement of what a change saves is worth nothing beside a measurement of
  // what it costs. `src/disasm/__tests__/funcInsns.test.ts` and
  // `src/workers/__tests__/disasmClient.test.ts` are where the property is
  // pinned and negative-controlled; this is where it is asked at scale.
  const codeFor = async (slim: boolean): Promise<string[]> => {
    const st = createWorkerState(Promise.resolve());
    st.cs32 = state.cs32;
    st.cs64 = state.cs64;
    st.csArm64 = state.csArm64;
    st.arch = arch;
    const out: string[] = [];
    let msgs = 0;
    for (const f of functions) {
      const base = { ...decompileArgs(f, 1) } as Record<string, unknown>;
      if (slim) {
        base.instructions = undefined;
        base.funcInsns = collectFuncInsns(f, instructions);
        base.xrefEntries = funcXrefEntries(f, xrefMap);
        const own = funcExceptionRecord(f, pe.runtimeFunctions);
        base.runtimeFunctions = own ? [own] : undefined;
      }
      msgs++;
      let r = (await dispatch("decompileFunction", base, st)) as {
        code?: string;
        needInstructions?: boolean;
      };
      if (r.needInstructions) {
        // Exactly the client's retry: the same request again, with the section.
        msgs++;
        r = (await dispatch("decompileFunction", { ...base, instructions }, st)) as {
          code?: string;
        };
      }
      out.push(r.code ?? "");
    }
    if (slim) slimMessages = msgs;
    return out;
  };
  let slimMessages = 0;
  const wholeCode = await codeFor(false);
  const slimCode = await codeFor(true);
  let differing = 0;
  for (let i = 0; i < wholeCode.length; i++) if (wholeCode[i] !== slimCode[i]) differing++;
  // THE LIVENESS HALF of the census above, and it is what stops "0 differing"
  // from being a statement about a population of zero. `runtimeFunctions` is
  // read at exactly one place — `wrapExceptionRegions`, whose whole observable
  // effect is a `__try` — so if neither run emits one, dropping the array
  // entirely would also read as 0 differing. PE32 has no `.pdata` at all and
  // reports 0 here on purpose; on the x64 pair it is the handler-bearing row
  // count, which is the number the slice has to preserve.
  const tries = (code: string[]): number => code.filter((c) => /^\s*__try \{/m.test(c)).length;
  const wholeTries = tries(wholeCode);
  const slimTries = tries(slimCode);

  const meanOwnInsns =
    functions.reduce((a, f) => a + collectFuncInsns(f, instructions).length, 0) / functions.length;
  const meanOwnXrefs =
    functions.reduce((a, f) => a + funcXrefEntries(f, xrefMap).length, 0) / functions.length;

  console.log(
    `${path.split("/").pop()} — ${arch}, .text ${(bytes.length / 1024).toFixed(0)} KiB, ` +
      `${functions.length} functions, ${instructions.length} instructions`,
  );
  console.log(`  premise: ${checkNothingIsTransferred(payload)}`);
  // The same premise for the payload that actually crosses now: `funcInsns`
  // still carries a `bytes` view per element, so it is still nested and still
  // cloned rather than transferred. If that ever changed the columns below
  // would stop meaning what they say.
  console.log(`  premise (per-function): ${checkNothingIsTransferred(slimPayload)}`);
  return {
    name: path.split("/").pop() ?? path,
    funcs: functions.length,
    insns: instructions.length,
    xrefs: xrefEntries.length,
    parts,
    whole,
    firstWork,
    medianWork: times[Math.floor(times.length / 2)],
    slimParts,
    slimWhole,
    meanOwnInsns,
    meanOwnXrefs,
    differing,
    pdataRows: pe.runtimeFunctions?.length ?? 0,
    pdataSent: pdataRecord ? 1 : 0,
    wholeTries,
    slimTries,
    messages: slimMessages,
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
    // ── The per-function payload, which is what actually crosses now ─────────
    const slimPayloadMs = r.slimParts.reduce((a, p) => a + p.ms, 0);
    const slimRequest = r.slimWhole + r.medianWork;
    console.log("");
    console.log(
      `  the per-function payload (peek-a-bin-9gc9): ${r.meanOwnInsns.toFixed(1)} instructions ` +
        `and ${r.meanOwnXrefs.toFixed(1)} xref rows per request, mean over all ${r.funcs} functions`,
    );
    console.log("  component            clone ms   % of a median request");
    // Every member, not the top few: the payload is small enough now that the
    // interesting rows are the ones that used to be rounding error.
    for (const p of [...r.slimParts].sort((a, b) => b.ms - a.ms)) {
      console.log(
        `  ${p.key.padEnd(20)} ${p.ms.toFixed(3).padStart(8)}   ${((p.ms * 100) / slimRequest).toFixed(3).padStart(8)}%`,
      );
    }
    console.log(
      `  ${"(sum of parts)".padEnd(20)} ${slimPayloadMs.toFixed(3).padStart(8)}   ${((slimPayloadMs * 100) / slimRequest).toFixed(3).padStart(8)}%`,
    );
    console.log(
      `  ${"WHOLE PAYLOAD".padEnd(20)} ${r.slimWhole.toFixed(3).padStart(8)}   ${((r.slimWhole * 100) / slimRequest).toFixed(3).padStart(8)}%`,
    );
    console.log(
      `  ${"decompile (median)".padEnd(20)} ${r.medianWork.toFixed(3).padStart(8)}   ${((r.medianWork * 100) / slimRequest).toFixed(3).padStart(8)}%`,
    );
    console.log(
      `  a request is ${(request / slimRequest).toFixed(1)}x cheaper end to end ` +
        `(${request.toFixed(1)} ms -> ${slimRequest.toFixed(1)} ms); payload share ` +
        `${((r.whole * 100) / request).toFixed(1)}% -> ${((r.slimWhole * 100) / slimRequest).toFixed(1)}%`,
    );
    console.log(
      `  opening all ${r.funcs} functions: ${((request * r.funcs) / 1000).toFixed(2)} s -> ` +
        `${((slimRequest * r.funcs + r.whole) / 1000).toFixed(2)} s ` +
        "(the second includes the ONE resend the worker asks for)",
    );
    console.log(
      `  EQUIVALENCE: ${r.differing} of ${r.funcs} functions emit different C; ` +
        `${r.messages} messages for ${r.funcs} requests ` +
        `(${r.messages - r.funcs} resend${r.messages - r.funcs === 1 ? "" : "s"})`,
    );
    console.log(
      `  .pdata: ${r.pdataRows} rows in the image, ${r.pdataSent} sent per request; ` +
        `__try emitted in ${r.wholeTries} functions from the whole table and ` +
        `${r.slimTries} from the per-function row ` +
        `(${r.wholeTries === 0 ? "NO POPULATION — the census above is vacuous here" : r.wholeTries === r.slimTries ? "the population the slice must preserve" : "MISMATCH"})`,
    );
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
