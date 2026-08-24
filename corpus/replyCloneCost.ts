/**
 * What does the worker's REPLY cost, and would packing the instruction bytes
 * help?
 *
 * THE INSTRUMENT `peek-a-bin-rjt` LOST. That bead records a measured decision
 * not to change the reply path, on the strength of a four-row table taken at
 * 500k instructions — and it ends "Bench: scratchpad bench-reply.mjs,
 * methodology in its header". Two staleness audits have since confirmed that no
 * such file exists anywhere outside `node_modules`, so the table had become a
 * claim nobody could re-take. CLAUDE.md records the identical hazard for a
 * different measurement (`peek-a-bin-02fa`, where "the instrument that produced
 * 64→90 was lost with a scratch worktree and the claim was unrepeatable"), with
 * the standing lesson **"when you build an oracle to verify a change, land the
 * oracle"**. This is that oracle, landed.
 *
 * The reply to `disassemble` / `hybridDisassemble` is an `Instruction[]`, and
 * `disasm.worker.ts` posts it as `self.postMessage({ id, result })` — no
 * transfer list. Each element carries a `bytes` view onto its own small private
 * buffer, so there is no whole-buffer amplification on the way back, unlike the
 * send path `src/workers/transfer.ts` is about. There are just N small buffers.
 * The question is whether N small buffers are worth consolidating, and it is
 * asked as four rows over the same objects:
 *
 *  * **A — clone as-is.** What ships today.
 *  * **B — transfer every per-insn buffer.** The obvious "avoid the copy" move.
 *  * **C — pack the bytes into one buffer and transfer that.** The candidate.
 *  * **D — the same objects with no `bytes` field at all.** The floor: what the
 *    reply would cost if the bytes were free, so that A − D is the entire
 *    budget any scheme here is competing for.
 *
 * plus two rows the recorded table did not have and the refusal now rests on:
 * **C+**, which is C with the re-slice on unpack that the return trip forces,
 * and the **return-trip** row itself — see {@link printReturnTrip}.
 *
 * WHY IT TAKES A PATH AND IS NOT IN `npm run corpus`. Same rule as
 * `corpus/rpcUploadCost.ts`, `corpus/decompileRpcCost.ts` and
 * `corpus/jumpTableReach.ts`: that run's header names the four MSVC binaries
 * every standing figure is measured against, and its audits iterate over
 * whatever they find in the corpus directory, so an extra binary silently
 * changes the population of every gate. The image most worth pointing this at
 * is the ~2.4 MiB Windows/amd64 PE `go` builds (recipe in this directory's
 * README), which must NOT be stored there.
 *
 * WHY IT IS DERIVED AND NOT TABULATED. The section comes from the PE header,
 * the instructions from the real `dispatch` with real Capstone handles, and the
 * clone from the platform's `structuredClone` — the algorithm `postMessage`
 * runs. There is no address, no size and no timing constant to go stale.
 * {@link censusBacking} exists so the one premise the whole question rests on —
 * that every `bytes` is a view onto its own private buffer rather than onto the
 * section — is re-derived here rather than trusted.
 *
 * ONE THING IT DELIBERATELY OVERSTATES, as its two sibling harnesses say of
 * themselves: `structuredClone` serialises AND deserialises in one process,
 * where `postMessage` splits the two across threads. That is the right model
 * for "what does this reply cost", and an over-estimate of what the main thread
 * blocks for — so a row this reports as negligible is negligible either way.
 *
 * WHAT IT IS NOT. A census and a stopwatch, never a gate. Wall clock on a
 * loaded machine is not a benchmark: run it twice and the columns move by tens
 * of percent. What does not move is the ORDER of the rows and the shape of
 * curve B, and that is the only thing any conclusion should rest on.
 */

import { readFileSync } from "node:fs";
import { Capstone, Const, loadCapstone } from "capstone-wasm";
import { archForMachine } from "../src/disasm/arch";
import type { Instruction } from "../src/disasm/types";
import { parsePE } from "../src/pe/parser";
import { findCodeSection } from "../src/pe/sections";
import { createWorkerState, dispatch } from "../src/workers/dispatch";

/**
 * How many per-insn buffers row B is allowed to transfer on a real image.
 *
 * Row B is strongly SUPERLINEAR in the number of buffers in the transfer list —
 * about N^1.7, see {@link scaleSweep} — so it is the one row that cannot simply
 * be run: at 500k it is a minute and a half. On a real image it therefore runs at this cap and
 * the whole-image figure is reported as an extrapolation *marked as such* —
 * and, because the growth is superlinear, a linear extrapolation is a LOWER
 * BOUND rather than an estimate. Pass `--full-b` to run it uncapped.
 */
const B_CAP = 20000;

/** Median of `n` samples, which is what to read off a loaded machine. */
function median(fn: () => number, n: number): number {
  fn();
  const t = Array.from({ length: n }, fn).sort((a, b) => a - b);
  return t[Math.floor(t.length / 2)];
}

/** One timed run of `fn`, in milliseconds. */
function once(fn: () => void): number {
  const t0 = performance.now();
  fn();
  return performance.now() - t0;
}

interface Backing {
  /** Distinct `ArrayBuffer`s behind the whole reply. */
  distinct: number;
  /** Sum of those buffers' lengths: what a structured clone actually copies. */
  backingBytes: number;
  /** Sum of the VIEW lengths: the instruction bytes a reader can see. */
  viewBytes: number;
  /** Views whose buffer is exactly their own length — `gridScan`'s `.slice()`. */
  exact: number;
  /** Views onto a private 24-byte buffer — capstone-wasm's `cs_insn.bytes`. */
  padded24: number;
  /** Anything else, including a view onto a buffer larger than one instruction. */
  other: number;
  /** Views sharing a buffer with another view. The amplification hazard. */
  shared: number;
}

/**
 * Re-derive the premise: is every `bytes` a view onto its OWN small buffer?
 *
 * This is the fact that makes the reply path a different question from the send
 * path. `StructuredSerialize` of an `ArrayBufferView` serialises the whole
 * underlying `ArrayBuffer`, not the view's window — so a `subarray` of the
 * section would look identical to a reader and would put the entire `.text`
 * into the message once per instruction. `src/disasm/linearSweep.ts` forbids
 * exactly that in `gridScan` and pins it with a test; `corpus/hybridGridServe.ts`
 * reports it as its "own bytes buffers" column. It is re-derived here because
 * every row below is meaningless if it is false: row A would already be
 * catastrophic and packing would be a rescue rather than a micro-optimisation.
 *
 * The split also says where the bytes came from, which has changed since the
 * bead was filed — see {@link printImage}.
 */
function censusBacking(insns: Instruction[]): Backing {
  const seen = new Map<ArrayBuffer, number>();
  let viewBytes = 0;
  let exact = 0;
  let padded24 = 0;
  let other = 0;
  for (const i of insns) {
    const buf = i.bytes.buffer as ArrayBuffer;
    viewBytes += i.bytes.byteLength;
    seen.set(buf, (seen.get(buf) ?? 0) + 1);
    if (buf.byteLength === i.bytes.byteLength) exact++;
    else if (buf.byteLength === 24) padded24++;
    else other++;
  }
  let backingBytes = 0;
  let shared = 0;
  for (const [buf, n] of seen) {
    backingBytes += buf.byteLength;
    if (n > 1) shared += n;
  }
  return { distinct: seen.size, backingBytes, viewBytes, exact, padded24, other, shared };
}

/** The reply, minus the bytes: row D's payload, and row C's object half. */
function stripBytes(insns: Instruction[]): object[] {
  return insns.map((i) => ({
    address: i.address,
    mnemonic: i.mnemonic,
    opStr: i.opStr,
    size: i.size,
    comment: i.comment,
    source: i.source,
  }));
}

/**
 * Row C's payload: every instruction's bytes copied into one buffer, each
 * object carrying the offset and length it was written at.
 *
 * The packing itself is INSIDE the caller's timer, deliberately: it is work a
 * packing scheme would have to do, on the worker thread, before it could post
 * anything. Timing only the clone would be measuring a saving without its cost.
 */
function packed(insns: Instruction[]): { objs: object[]; buf: Uint8Array } {
  let total = 0;
  for (const i of insns) total += i.bytes.byteLength;
  const buf = new Uint8Array(total);
  const objs = new Array<object>(insns.length);
  let off = 0;
  for (let k = 0; k < insns.length; k++) {
    const i = insns[k];
    buf.set(i.bytes, off);
    objs[k] = {
      address: i.address,
      mnemonic: i.mnemonic,
      opStr: i.opStr,
      size: i.size,
      comment: i.comment,
      source: i.source,
      byteOff: off,
      byteLen: i.bytes.byteLength,
    };
    off += i.bytes.byteLength;
  }
  return { objs, buf };
}

interface Rows {
  n: number;
  a: number;
  /** Measured at {@link bN}, which is `n` only under `--full-b`. */
  b: number;
  bN: number;
  c: number;
  cPlus: number;
  d: number;
}

/**
 * The four rows, plus C+.
 *
 * C+ is C with the receiving side re-slicing each instruction's bytes out of
 * the packed buffer, and it is the row that matters rather than C. The bead's
 * own reason for refusing C is that an unpacked `bytes` is a view onto ONE
 * shared buffer, and those instructions get sent BACK to the worker a function
 * at a time — so a shared view is exactly the amplification `prepareBinaryArgs`
 * exists to remove. Re-slicing on unpack is what avoids that, and the bead
 * notes it "gives back most of the 555 ms". C and C+ are printed side by side
 * so that clause is a number rather than a caveat.
 */
function measureRows(insns: Instruction[], fullB: boolean): Rows {
  const n = insns.length;
  const bare = stripBytes(insns);
  const a = median(() => once(() => void structuredClone(insns)), 5);
  const d = median(() => once(() => void structuredClone(bare)), 5);
  const c = median(
    () =>
      once(() => {
        const p = packed(insns);
        structuredClone({ objs: p.objs, buf: p.buf }, { transfer: [p.buf.buffer] });
      }),
    5,
  );
  const cPlus = median(
    () =>
      once(() => {
        const p = packed(insns);
        const got = structuredClone({ objs: p.objs, buf: p.buf }, { transfer: [p.buf.buffer] }) as {
          objs: { byteOff: number; byteLen: number }[];
          buf: Uint8Array;
        };
        // The receiving side, giving each instruction a private buffer again so
        // that sending ~100 of them back does not drag the whole packed buffer.
        for (const o of got.objs) {
          void got.buf.slice(o.byteOff, o.byteOff + o.byteLen);
        }
      }),
    5,
  );
  // Row B needs a FRESH payload each repetition: transferring detaches every
  // buffer, so a second run over the same objects would transfer nothing.
  const bN = fullB ? n : Math.min(n, B_CAP);
  const src = insns.slice(0, bN);
  const b = median(() => {
    const cp = src.map((i) => ({ ...i, bytes: i.bytes.slice() }));
    return once(() => void structuredClone(cp, { transfer: cp.map((i) => i.bytes.buffer) }));
  }, 3);
  return { n, a, b, bN, c, cPlus, d };
}

interface Row extends Rows {
  name: string;
  codeKiB: number;
  funcs: number;
  backing: Backing;
  /** Median instructions in one detected function: the return trip's unit. */
  perFuncInsns: number;
  /** One function's slice sent back, each `bytes` private (today). */
  backPrivate: number;
  /** The same slice with every `bytes` a view onto the whole packed buffer. */
  backShared: number;
  /** The packed buffer's size: what the shared-view tax is proportional to. */
  packedKiB: number;
}

async function measure(path: string, fullB: boolean): Promise<Row | null> {
  // Skip cleanly rather than throwing, and NAME what was missing: a caller told
  // only "skipped" has been told nothing. `corpus/preflight.ts` opens with the
  // same rule for the corpus directory, and it applies at least as much here,
  // where the interesting image is one the reader has to build themselves from
  // the recipe in this directory's README and may simply not have yet.
  let file: Buffer;
  try {
    file = readFileSync(path);
  } catch (err) {
    console.log(`${path}: cannot read it — ${(err as NodeJS.ErrnoException).code ?? String(err)}`);
    console.log("  skipped. If this is the `go` image, the recipe is in corpus/README.md.");
    return null;
  }
  const buffer = file.buffer.slice(
    file.byteOffset,
    file.byteOffset + file.byteLength,
  ) as ArrayBuffer;
  let pe: ReturnType<typeof parsePE>;
  try {
    pe = parsePE(buffer);
  } catch (err) {
    console.log(`${path}: not a PE this parser accepts — ${(err as Error).message}`);
    return null;
  }
  const text = findCodeSection(pe.sections);
  if (!text) {
    console.log(`${path}: no executable section — there is no reply to cost`);
    return null;
  }
  const arch = archForMachine(pe.coffHeader.machine);
  if (arch === "unsupported") {
    console.log(`${path}: unsupported architecture — the disassembly RPC refuses`);
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
  )) as { functions: { address: number; size: number }[]; jumpTableSpans?: [number, number][] };
  const insns = (await dispatch(
    "hybridDisassemble",
    {
      ...common,
      seeds: found.functions.map((f) => f.address),
      pdataRanges,
      jumpTableSpans: found.jumpTableSpans,
    },
    state,
  )) as Instruction[];
  if (insns.length === 0) {
    console.log(`${path}: the disassembly is empty — every row below would be vacuous`);
    return null;
  }

  const rows = measureRows(insns, fullB);
  const backing = censusBacking(insns);
  const trip = returnTrip(insns, found.functions);
  return {
    name: path.split("/").pop() ?? path,
    codeKiB: bytes.length / 1024,
    funcs: found.functions.length,
    backing,
    ...rows,
    ...trip,
  };
}

/**
 * The return trip, which is the bead's stated reason for refusing C — and which
 * `peek-a-bin-9gc9` has since made the shape of EVERY request.
 *
 * `disasmClient.decompileFunction` used to ship the whole section's
 * `Instruction[]`; it now ships `collectFuncInsns(func, instructions)`, one
 * function's slice, with the full array crossing only once per file. So when
 * this bead was filed a packed buffer would have travelled beside an array that
 * was crossing in full anyway, and now the per-request payload is ~100
 * instructions. If those instructions' `bytes` are views onto one shared packed
 * buffer, each such request drags the whole packed buffer along.
 *
 * Both halves are measured over the SAME instructions, so the only difference
 * is where their bytes are backed: private buffers (today) against one shared
 * buffer (what an unpacked row C hands you). The ratio is the tax, and it is
 * paid once per function the user opens.
 */
function returnTrip(
  insns: Instruction[],
  funcs: { address: number; size: number }[],
): { perFuncInsns: number; backPrivate: number; backShared: number; packedKiB: number } {
  // The median function, so the unit is typical rather than extreme.
  const sizes = funcs.map((f) => f.size).sort((a, b) => a - b);
  const target = sizes[sizes.length >> 1] ?? 0;
  const pick = funcs.find((f) => f.size === target) ?? funcs[0];
  if (!pick) return { perFuncInsns: 0, backPrivate: 0, backShared: 0, packedKiB: 0 };
  const slice = insns.filter(
    (i) => i.address >= pick.address && i.address < pick.address + pick.size,
  );
  if (slice.length === 0) return { perFuncInsns: 0, backPrivate: 0, backShared: 0, packedKiB: 0 };

  // What ships today: each `bytes` on its own buffer.
  const backPrivate = median(() => once(() => void structuredClone(slice)), 25);
  // What an unpacked row C ships: each `bytes` a window onto the whole packed
  // buffer. Same instructions, same view lengths, one shared backing.
  const p = packed(insns);
  const shared = slice.map((i, k) => {
    const o = p.objs[insns.indexOf(i)] as { byteOff: number; byteLen: number } | undefined;
    const off = o?.byteOff ?? k;
    const len = o?.byteLen ?? i.bytes.byteLength;
    return { ...i, bytes: new Uint8Array(p.buf.buffer, off, len) };
  });
  const backShared = median(() => once(() => void structuredClone(shared)), 5);
  return {
    perFuncInsns: slice.length,
    backPrivate,
    backShared,
    packedKiB: p.buf.byteLength / 1024,
  };
}

function printImage(r: Row): void {
  const b = r.backing;
  console.log("");
  console.log(
    `${r.name} — .text ${r.codeKiB.toFixed(0)} KiB, ${r.funcs} functions, ${r.n} instructions`,
  );
  console.log(
    `  bytes: ${b.distinct} distinct backing buffers over ${r.n} instructions, ` +
      `${b.backingBytes} B backed for ${b.viewBytes} B visible ` +
      `(${b.shared === 0 ? "NO view shares a buffer — the premise holds" : `${b.shared} views SHARE a buffer — the premise is BROKEN, read no row below`})`,
  );
  // Where the bytes came from. capstone-wasm slices a fixed 24-byte `cs_insn.bytes`
  // and subarrays it to `size`; `gridScan` slices to the exact length. So the
  // split is a provenance census, and it moved when peek-a-bin-iqzu landed.
  console.log(
    `  provenance: ${b.exact} exact-size (gridScan .slice), ${b.padded24} 24-byte ` +
      `(capstone-wasm cs_insn.bytes), ${b.other} other` +
      (b.other > 0 ? "  <-- investigate: neither known provenance" : ""),
  );
  const budget = r.a - r.d;
  const bFull =
    r.bN === r.n
      ? ""
      : ` (at N=${r.bN}; >=${((r.b * r.n) / r.bN).toFixed(0)} extrapolated, see below)`;
  console.log("");
  console.log("  row                                       ms    us/insn   vs A");
  // `vs A` is only meaningful for a row measured over the same N, so row B —
  // which is capped — gets a dash rather than a ratio between two populations.
  const line = (name: string, ms: number, n: number, note = "") =>
    console.log(
      `  ${name.padEnd(36)} ${ms.toFixed(1).padStart(7)} ${((ms * 1000) / n).toFixed(3).padStart(9)} ${(n === r.n ? `${((ms * 100) / r.a).toFixed(0)}%` : "-").padStart(6)}${note}`,
    );
  line("A clone as-is (today)", r.a, r.n);
  line("B transfer every per-insn buffer", r.b, r.bN, bFull);
  line("C pack bytes + transfer", r.c, r.n);
  line("C+ ... and re-slice on unpack", r.cPlus, r.n);
  line("D no bytes field at all (floor)", r.d, r.n);
  console.log(
    `  budget A-D ${budget.toFixed(1)} ms — the whole of what any scheme here competes for; ` +
      `C saves ${(r.a - r.c).toFixed(1)} ms of it, C+ saves ${(r.a - r.cPlus).toFixed(1)} ms`,
  );
}

/**
 * The bead's refusal, as a number.
 *
 * Printed apart from the table because it is a cost paid on a DIFFERENT event:
 * the table is once per load, this is once per function the user opens.
 */
function printReturnTrip(rows: Row[]): void {
  console.log("");
  console.log("the return trip — what row C costs on the way BACK (peek-a-bin-9gc9)");
  console.log(
    "image           insns/func   packed KiB   private ms   shared ms   ratio   per 100 opens",
  );
  for (const r of rows) {
    if (r.perFuncInsns === 0) {
      console.log(`${r.name.padEnd(14)}  no function slice — this row is vacuous here`);
      continue;
    }
    console.log(
      [
        r.name.padEnd(14),
        String(r.perFuncInsns).padStart(10),
        r.packedKiB.toFixed(0).padStart(12),
        r.backPrivate.toFixed(3).padStart(12),
        r.backShared.toFixed(3).padStart(11),
        `${(r.backShared / Math.max(r.backPrivate, 1e-9)).toFixed(0)}x`.padStart(7),
        `${((r.backShared - r.backPrivate) * 100).toFixed(0)} ms`.padStart(14),
      ].join(" "),
    );
  }
  console.log("");
  console.log("`private` is what ships today: one function's instructions, each `bytes` on its");
  console.log("own buffer. `shared` is the same instructions with each `bytes` a window onto one");
  console.log("packed buffer, which is what an unpacked row C hands the caller. The last column");
  console.log("is the extra cost over 100 opened functions — against a row-C saving that is paid");
  console.log("ONCE per load. This is why C+ and not C is the row to read.");
  console.log("");
  console.log("THE TAX IS PROPORTIONAL TO `packed KiB`, NOT TO `insns/func`, because the clone");
  console.log("algorithm deduplicates a shared buffer (control 4): a request carrying 36 views");
  console.log("onto one packed buffer pays for that buffer ONCE, not 36 times. So it is small on");
  console.log("these images because their whole .text is under a megabyte, and it grows with the");
  console.log("image while the row-C saving it is set against does not grow any faster. Do not");
  console.log("read the ratio here as the size of the objection — read `packed KiB`.");
}

/**
 * Reach the bead's own N, and show why row B is the shape it is.
 *
 * No image on this machine has 500k instructions — the largest obtainable is
 * the ~2.4 MiB `go` build, at ~155k — so the recorded table can only be
 * re-derived synthetically. The objects are instruction-SHAPED and the harness
 * says so rather than implying otherwise: same six fields, a private buffer per
 * element, string field lengths in the range a real reply has. Their clone rate
 * is validated against the real images above, which is the check that makes the
 * synthetic worth anything.
 *
 * ROW B IS STRONGLY SUPERLINEAR IN THE NUMBER OF TRANSFERRED BUFFERS, and that
 * is the finding this sweep exists to show rather than assert. It is a much
 * stronger statement than any single figure: the harm from a large transfer list
 * grows with the image instead of being a fixed tax, so `prepareBinaryArgs`
 * being top-level only is not a micro-optimisation but the difference between a
 * linear reply and a superlinear one. Measured on an idle machine at `488ddde`,
 * the per-buffer cost rises 5.7 -> 164 us over N = 5000 -> 500000, i.e. total
 * time 28 ms -> 82135 ms over a 100x range in N: an exponent of about **1.7**,
 * not the 1.0 a linear cost would give. Read the `us/buf` column climbing rather
 * than any single millisecond figure, and do not round the exponent to 2 — it is
 * measured, and it is between the two.
 */
function syntheticReply(n: number): Instruction[] {
  const out = new Array<Instruction>(n);
  for (let k = 0; k < n; k++) {
    // 1..8 bytes, its own buffer, as both real provenances produce.
    const len = 1 + (k % 8);
    const b = new Uint8Array(len);
    for (let j = 0; j < len; j++) b[j] = (k + j) & 0xff;
    out[k] = {
      address: 0x140001000 + k * 4,
      bytes: b,
      mnemonic: k % 3 === 0 ? "mov" : k % 3 === 1 ? "lea" : "call",
      opStr: k % 2 === 0 ? "rax, qword ptr [rbx + 0x20]" : "rcx, rdx",
      size: len,
      source: k % 5 === 0 ? "gap-fill" : "recursive",
    };
  }
  return out;
}

function scaleSweep(fullB: boolean): void {
  console.log("");
  console.log("synthetic scale sweep — instruction-SHAPED objects, not a real disassembly");
  console.log(
    "       N        A ms   A us/insn        B ms    B us/buf        C ms       C+ ms        D ms",
  );
  const sizes = [10000, 20000, 40000, 80000, 160000, 320000, 500000];
  for (const n of sizes) {
    const insns = syntheticReply(n);
    const bare = stripBytes(insns);
    const a = median(() => once(() => void structuredClone(insns)), 3);
    const d = median(() => once(() => void structuredClone(bare)), 3);
    const c = median(
      () =>
        once(() => {
          const p = packed(insns);
          structuredClone({ objs: p.objs, buf: p.buf }, { transfer: [p.buf.buffer] });
        }),
      3,
    );
    const cPlus = median(
      () =>
        once(() => {
          const p = packed(insns);
          const got = structuredClone(
            { objs: p.objs, buf: p.buf },
            { transfer: [p.buf.buffer] },
          ) as { objs: { byteOff: number; byteLen: number }[]; buf: Uint8Array };
          for (const o of got.objs) void got.buf.slice(o.byteOff, o.byteOff + o.byteLen);
        }),
      3,
    );
    // Row B: quadratic, so it is capped unless asked for. One sample, and a
    // fresh payload, because transferring detaches.
    const bN = fullB || n <= 160000 ? n : 0;
    let b = Number.NaN;
    if (bN > 0) {
      const cp = syntheticReply(bN);
      b = once(() => void structuredClone(cp, { transfer: cp.map((i) => i.bytes.buffer) }));
    }
    console.log(
      [
        String(n).padStart(8),
        a.toFixed(0).padStart(11),
        ((a * 1000) / n).toFixed(3).padStart(11),
        Number.isNaN(b) ? "  (skipped)".padStart(11) : b.toFixed(0).padStart(11),
        Number.isNaN(b) ? "".padStart(11) : ((b * 1000) / n).toFixed(2).padStart(11),
        c.toFixed(0).padStart(11),
        cPlus.toFixed(0).padStart(11),
        d.toFixed(0).padStart(11),
      ].join(" "),
    );
  }
  console.log("");
  console.log("A, C, C+ and D are LINEAR in N to within the noise — their us/insn is flat. B is");
  console.log("not: its us/buf climbs with N, so a large transfer list is strongly superlinear");
  console.log("(about N^1.7 measured idle) and the harm grows with the image rather than being a");
  console.log("fixed tax. That is the row that makes prepareBinaryArgs' top-level-only rule");
  console.log("structural. Rows past 160k are skipped for B unless --full-b, and a LINEAR");
  console.log("extrapolation of B is a LOWER BOUND, never an estimate.");
  console.log("");
  console.log("RUN THIS ON AN IDLE MACHINE. The 500k row allocates several hundred MB and is the");
  console.log("first to show memory pressure: measured beside the test suites it read 6.99");
  console.log("us/insn for A against 3.77 idle, which is load and GC rather than nonlinearity.");
}

/**
 * Negative controls: perturb the payload so a row that should move does move.
 *
 * A harness that measures nothing reads exactly like a harness that measures a
 * zero, and this repo has repeatedly landed controls that turned out inert. Each
 * of these changes one property of the payload and names the row that must
 * respond.
 *
 * TWO OF THEM CAME BACK INERT ON THE FIRST ATTEMPT AND WERE RESCALED RATHER
 * THAN KEPT, which is the whole reason this function is written out at length.
 * Control 2 was inert because it is measuring a real nullity — see its note —
 * and control 3 was inert because it had been given a section small enough that
 * the object overhead swamped it. A control that does not discriminate is a
 * test that is not testing, so control 3 now runs at the shape the hazard
 * actually has: a SMALL payload aliasing a LARGE buffer.
 */
function controls(): void {
  const N = 80000;
  const insns = syntheticReply(N);
  const a = median(() => once(() => void structuredClone(insns)), 3);
  const d = median(() => once(() => void structuredClone(stripBytes(insns))), 3);
  console.log("");
  console.log("negative controls (synthetic)");
  console.log(
    `  baseline N=${N}: A ${a.toFixed(0)} ms, D ${d.toFixed(0)} ms, budget A-D ${(a - d).toFixed(0)} ms`,
  );

  // 1. Drop the bytes. A must collapse onto D — if it does not, row A is not
  //    measuring the bytes at all and the whole table is about object overhead.
  const gap = ((a - d) * 100) / a;
  console.log(
    `  1 bytes dropped:        A -> D is ${gap.toFixed(0)}% of A  ` +
      `[${gap > 5 ? "DISCRIMINATES" : "INERT — row A is not measuring the bytes"}]`,
  );

  // 2. Widen every backing buffer to capstone-wasm's 24 bytes while leaving the
  //    view lengths alone: the difference between this reply's two provenances.
  const padded = insns.map((i) => {
    const buf = new Uint8Array(24);
    buf.set(i.bytes);
    return { ...i, bytes: buf.subarray(0, i.bytes.byteLength) };
  });
  const a24 = median(() => once(() => void structuredClone(padded)), 3);
  const rise = ((a24 - a) * 100) / a;
  console.log(
    `  2 backing 24 B not exact: A ${a.toFixed(0)} -> ${a24.toFixed(0)} ms, ` +
      `${rise >= 0 ? "+" : ""}${rise.toFixed(0)}%  [NULL RESULT, and it is a finding — see below]`,
  );

  // 3. The defect `gridScan` is forbidden from committing: `bytes` a subarray of
  //    the section instead of a private slice. Run at the RETURN TRIP's shape —
  //    a small payload — because that is where the hazard bites.
  //
  //    JUDGED ON SHAPE, NOT ON A RATIO, and that is a correction: a first
  //    version compared the aliased clone against the private one and called
  //    anything under 10x inert, which read 17x on an idle machine and 5x while
  //    the test suites were running — i.e. the verdict depended on the load. The
  //    claim being controlled is that the tax is proportional to the SECTION and
  //    independent of N, so it is checked that way: hold N fixed, double the
  //    section, and the tax must roughly double.
  const SMALL = 100;
  const small = syntheticReply(SMALL);
  const aSmall = median(() => once(() => void structuredClone(small)), 15);
  const taxAt = (mib: number): number => {
    const section = new Uint8Array(mib * 1024 * 1024);
    for (let i = 0; i < section.length; i += 4093) section[i] = i & 0xff;
    const aliased = small.map((i, k) => ({
      ...i,
      bytes: section.subarray(k * 8, k * 8 + i.bytes.byteLength),
    }));
    return median(() => once(() => void structuredClone(aliased)), 5) - aSmall;
  };
  const taxSmall = taxAt(8);
  const taxBig = taxAt(32);
  // The verdict is that the tax DWARFS the private baseline, which is robust to
  // machine load because it is a memcpy of tens of MB against a hundred small
  // objects. The two sizes are reported beside it as the supporting evidence
  // that it tracks the section: it grows, though sublinearly at these sizes, so
  // no ratio threshold is asserted on that half.
  const over = taxBig / Math.max(aSmall, 1e-9);
  console.log(
    `  3 ${SMALL} insns aliasing a section, private baseline ${aSmall.toFixed(3)} ms:` +
      ` tax ${taxSmall.toFixed(1)} ms at 8 MiB, ${taxBig.toFixed(1)} ms at 32 MiB ` +
      `(${(taxBig / Math.max(taxSmall, 1e-9)).toFixed(1)}x for 4x section), ` +
      `${over.toFixed(0)}x the baseline  ` +
      `[${over > 10 && taxBig > taxSmall ? "DISCRIMINATES — the tax tracks the section, not N" : "INERT — the amplification hazard is invisible here"}]`,
  );

  // 4. The MECHANISM behind control 3's magnitude, checked as a property rather
  //    than a timing, because it is the part that corrects a comment in the tree.
  //    `StructuredSerializeInternal` carries a memory map, so an ArrayBuffer
  //    referenced by many views is serialised ONCE and the deserialised views
  //    all share one buffer.
  const oneBuffer = new Uint8Array(8 * 1024 * 1024);
  const manyViews = Array.from({ length: 500 }, (_, k) => oneBuffer.subarray(k, k + 4));
  const cloned = structuredClone(manyViews);
  const distinct = new Set(cloned.map((v) => v.buffer)).size;
  const wholeKept = cloned[0].buffer.byteLength === oneBuffer.byteLength;
  console.log(
    `  4 500 views of one buffer clone to ${distinct} buffer(s) of ` +
      `${(cloned[0].buffer.byteLength / 1024 / 1024).toFixed(0)} MiB  ` +
      `[${distinct === 1 && wholeKept ? "DEDUPLICATED, and the whole buffer is kept" : "NOT deduplicated"}]`,
  );

  console.log("");
  console.log("Control 2 is a NULL RESULT and it is reported rather than tuned until it moves.");
  console.log("Its SIGN is not stable between runs (-5% and +17% on two runs at 488ddde), which");
  console.log("is the tell that it is noise rather than a small real effect. The two provenances");
  console.log("of `bytes` differ by ~20 B of backing per instruction, which against this reply's");
  console.log("per-object cost is below that floor — so peek-a-bin-iqzu");
  console.log("changing almost every instruction from capstone's padded 24-byte buffer to an");
  console.log("exact-size one did NOT change what the reply costs. Control 3 is what shows the");
  console.log("harness can see backing-buffer size when there is size to see.");
  console.log("");
  console.log("Control 4 QUALIFIES A COMMENT IN THE TREE. src/disasm/linearSweep.ts says a");
  console.log("subarray of the section there 'would make the reply's structured clone serialise");
  console.log("the WHOLE .text once per instruction'. Once per MESSAGE: the clone algorithm");
  console.log("deduplicates, so N views cost one section-sized copy and not N of them. The rule");
  console.log("is unaffected and `.slice()` is still right — a whole-section tax on every reply");
  console.log("and on every ~100-instruction request back is a real cost, and control 3 measures");
  console.log("it — but the magnitude in that comment overstates it by a factor of N.");
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const fullB = argv.includes("--full-b");
  const paths = argv.filter((a) => !a.startsWith("--"));
  const scaleOnly = argv.includes("--scale");
  const wantControls = argv.includes("--control");

  if (paths.length === 0 && !scaleOnly && !wantControls) {
    console.log("usage: npm run corpus:replycost -- <pe path> [<pe path>...] [--full-b]");
    console.log("");
    console.log("Any PE the disassembly RPC accepts. The one worth pointing it at is the");
    console.log("~2.4 MiB Windows/amd64 image `go` builds — see the recipe in corpus/README.md");
    console.log("— which must NOT be put in the corpus directory.");
    console.log("");
    console.log("  --scale     the synthetic sweep alone, which is the only way to reach the");
    console.log("              500k instructions peek-a-bin-rjt's recorded table was taken at.");
    console.log("  --control   the negative controls: perturb the payload and check that the");
    console.log("              row which should move does move.");
    console.log("  --full-b    run row B uncapped. It is strongly SUPERLINEAR in the transfer");
    console.log("              list (about N^1.7), so this takes about a minute and a half at");
    console.log("              500k. Off by default.");
    return;
  }

  if (paths.length > 0) {
    await loadCapstone();
    const rows: Row[] = [];
    for (const p of paths) {
      const row = await measure(p, fullB);
      if (row) rows.push(row);
    }
    if (rows.length === 0) {
      console.log("");
      console.log("No image produced a reply — every row would be vacuous, so none is printed.");
    } else {
      for (const r of rows) printImage(r);
      printReturnTrip(rows);
      console.log("");
      console.log("milliseconds, medians. structuredClone is the algorithm postMessage runs, and");
      console.log("here it serialises AND deserialises in one process, so it over-states what the");
      console.log("main thread blocks for. Read the ORDER of the rows, never the digits — wall");
      console.log("clock on a loaded machine moves by tens of percent between runs.");
    }
  }
  if (wantControls) controls();
  if (paths.length > 0 || scaleOnly) scaleSweep(fullB);
}

void main();
