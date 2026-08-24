/**
 * The x86 linear sweep of a code section — one declaration, and one memo of it.
 *
 * `functionDetect.ts` swept `.text` from end to end in two places, in loops that
 * were copy-paste identical down to the offset arithmetic: once in
 * `detectFunctions` (for call targets, branch targets, jump-table dispatches and
 * the padding heuristic) and once in `buildAllXrefs` (for string, import, data
 * and call-graph references). Verified over t32/t64/w32/w64 and a 669 KiB-`.text`
 * Windows/amd64 PE from `go`: the two produced **the same instruction stream,
 * element for element** — 186281 instructions on the `go` image, 18280 on t32,
 * first difference nowhere. So this is the `sections.ts` / `ripRelative.ts` /
 * `funcInsns.ts` / `stackIdiom.ts` case exactly: one rule spelled twice, where a
 * fix to the offset advance in one would silently not reach the other.
 *
 * ## Why it is also a cache
 *
 * A load runs the sweep three times over the identical bytes — `detectFunctions`,
 * `buildAllXrefs`, and `buildAllXrefs` again when late-arriving strings enlarge
 * the string set — and each pays for its own. `buildAllXrefs` taken apart, base
 * `6f2ce28`, real Capstone, medians of five (milliseconds):
 *
 * | image  | `.text` | whole call | the sweep | the key compare | the resolve |
 * |--------|---------|------------|-----------|-----------------|-------------|
 * | go x64 |  669 K  |    802     |  **754**  |    **0.918**    |   **67**    |
 * | t32    |   54 K  |     87     |     71    |      0.075      |      8      |
 * | t64    |   60 K  |     85     |     75    |      0.077      |      6      |
 * | w32    |   48 K  |     63     |     67    |      0.067      |      5      |
 * | w64    |   54 K  |     72     |     63    |      0.075      |      5      |
 *
 * **The sweep is 94% of `buildAllXrefs` and 82% of `detectFunctions`**, and what
 * is left of the former on a memo hit is the resolve: the string, import, data
 * and call-graph sets, 67 ms on the `go` image with no decoder involved. The key
 * compare that buys that is 0.918 ms — 1.4 ms per MiB, a JS byte loop rather
 * than a memcpy — so it skips **820x its own cost**, which is the test
 * `src/workers/transfer.ts` sets for whether such a memo may exist at all.
 * (`peek-a-bin-9a8` failed the same test because the work it proposed to save
 * *was* a linear pass over the bytes, leaving no room under any key.)
 *
 * This is `peek-a-bin-kis`' `Arm64SweepCache` on the other architecture, and
 * unlike that one it is *not* a transcription: A64 is fixed-width, so there the
 * sweep IS the disassembly and all three RPCs want the same *array*. Here only
 * two of the three do — `hybridDisassemble` is recursive descent over a BFS work
 * queue plus a gap fill, producing a different, annotated, smaller stream. It
 * shares this sweep all the same, one level down: {@link gridScan} makes the
 * held grid the *decoder* underneath that method, so a decode at an address the
 * grid has costs a binary search instead of a `cs_disasm` and every phase keeps
 * its own stepping. See that function for the coincidence rate that justifies
 * it and for the three ways it could be wrong (peek-a-bin-iqzu).
 *
 * End to end through the real `dispatch`, four RPCs in App.tsx's order
 * (detect, hybrid, xrefs, xrefs again with the extracted string set), one memo
 * against a memo that never stores. **The `hybrid` column is this table's
 * historical figure and has since fallen by a further 74-88%** — it was
 * unchanged work when this was taken and is `gridScan`'s subject now; the
 * current totals are `go` 1018, t32 128, t64 96, w32 117, w64 82:
 *
 * | image  | mode   | detect | hybrid | xrefs | xrefs2 | total |
 * |--------|--------|--------|--------|-------|--------|-------|
 * | go x64 | each   |  857   |  800   |  729  |  744   | 3130  |
 * | go x64 | shared |  761   |  765   | **76**| **64** |**1666**|
 * | t32    | each   |  117   |  137   |   73  |   82   |  409  |
 * | t32    | shared |  100   |  125   | **10**|  **9** | **243**|
 * | t64    | each   |   90   |   72   |   73  |   71   |  307  |
 * | t64    | shared |   83   |   70   |  **7**|  **5** | **165**|
 * | w32    | each   |   96   |  116   |   62  |   62   |  336  |
 * | w32    | shared |   94   |  123   |  **6**|  **5** | **228**|
 * | w64    | each   |   66   |   63   |   65   |  61   |  255  |
 * | w64    | shared |   70   |   65   |  **7**|  **6** | **148**|
 *
 * 32-47% off the whole load. The `detect` and `hybrid` columns are unchanged
 * work and their movement is this machine's run-to-run spread, which is what a
 * wall clock on a loaded machine is worth — read the `xrefs` columns.
 *
 * ## What holding it costs, and what that was weighed against
 *
 * Retention is the price and it is not small: **~135 bytes per instruction, so
 * ~24 MB for the `go` image's 669 KiB `.text` and 2.3 MB for t32's** — about
 * 37-43x the section, held for as long as the session holds the image. The
 * measured comparison is what makes that acceptable rather than the argument:
 * the app **already** retains `hybridDisassemble`'s `Instruction[]` for the same
 * section, in `AppState`, for the same session — 55.2 MB on the `go` image and
 * 6.3 MB on t32, at 372 B/insn. So this adds 44% to a term already dominated by
 * an array 2.7x heavier per instruction, and it is lighter precisely because it
 * holds no `bytes` view per element (see below).
 *
 * Interning the strings was measured and **refused**: over the `go` image,
 * pooling mnemonics takes 24.1 MB to 19.8 and pooling `opStr` as well takes it
 * to 17.7 (165 and 40616 distinct values), with the sweep unchanged at
 * 735/716/739 ms. A 27% cut of a term that is itself 44% of the dominant one is
 * ~12%, bought with a second mechanism whose 40k-entry pool has retention of its
 * own. Not worth the explanation.
 *
 * ## Why the record is not an `Instruction`
 *
 * Neither consumer reads `bytes`, `comment` or `source`: both read exactly
 * `address`, `mnemonic`, `opStr` and `size`. Capstone hands back a `bytes`
 * subarray per instruction, each onto its own 24-byte buffer, and retaining
 * 186281 of those is the single largest avoidable cost here — it is most of the
 * gap between this array's 135 B/insn and the view array's 372. {@link SweptInsn}
 * is therefore the four fields and nothing else, and it is structurally the same
 * shape as `stackIdiom.ts`' `StackInsn`, so `functionDetect.ts` passes its
 * rolling window straight through with no cast and no conversion.
 */

import {
  type CapstoneHandle,
  type CapstoneScan,
  CS_MAX_INSNS_PER_CALL,
  CS_WINDOW_BYTES,
  createScan,
  type RawInsn,
} from "./capstoneWindow";
import { SectionMemo } from "./sectionMemo";

/**
 * What a linear sweep records per instruction.
 *
 * A structural subset of `./types`' `Instruction` and structurally identical to
 * `./stackIdiom`' `StackInsn` — deliberately, so a caller can hand one array to
 * either without converting. See the module docstring for why `bytes` is absent.
 */
export interface SweptInsn {
  address: number;
  mnemonic: string;
  opStr: string;
  size: number;
}

/**
 * Decode `bytes` from one end to the other, following the decoder's own idea of
 * where each instruction ends.
 *
 * Windowed through {@link createScan}, so no call can reach either of the WASM
 * decoder's ceilings — `capstoneWindow.ts` is the only thing that may touch
 * `cs.disasm`, and the whole reason a bare `cs_disasm` over a section is
 * forbidden.
 *
 * A byte the decoder refuses advances by one and is simply not in the result, so
 * the returned array is *not* contiguous in general: literal pools, alignment
 * padding and data inside `.text` all leave gaps. A consumer that cares whether
 * two instructions are adjacent must ask —
 * `insn.address === prev.address + prev.size` — which is exactly the question
 * the old inline loops answered by watching for an empty decode.
 *
 * Throws {@link CapstoneUnavailableError} for a dead engine, as every scan does;
 * `where` names the caller in that message.
 */
export function sweepX86(
  bytes: Uint8Array,
  baseAddress: number,
  cs: CapstoneHandle,
  where: string,
): SweptInsn[] {
  const scan = createScan(cs, where);
  const out: SweptInsn[] = [];
  const len = bytes.length;
  let offset = 0;
  while (offset < len) {
    const insns = scan.decode(bytes, offset, len, baseAddress + offset);
    for (const insn of insns) {
      out.push({
        address: insn.address,
        mnemonic: insn.mnemonic,
        opStr: insn.opStr,
        size: insn.size,
      });
    }
    if (insns.length === 0) {
      offset += 1;
    } else {
      const lastInsn = insns[insns.length - 1];
      offset += lastInsn.address - (baseAddress + offset) + lastInsn.size;
    }
  }
  return out;
}

/**
 * The session's memo of one x86 code section's linear sweep.
 *
 * Keyed on the section's bytes, its load address and the decoder handle — see
 * {@link SectionMemo} for why each part is there and why a cheap identity key
 * is refused. Lives in `WorkerState`, so it is per worker and per session;
 * `dispatch` clears it when a `configure` declares a machine type, which is
 * hygiene rather than correctness.
 *
 * One consequence of the content key worth knowing: an engine that dies
 * *between* two RPCs over the same section makes the second answer from memory
 * where it would previously have thrown `CapstoneUnavailableError`. That is a
 * correct answer instead of a refusal — the entry is the decode of exactly those
 * bytes — and it is the same property `Arm64SweepCache` has.
 */
export class X86SweepCache {
  private memo = new SectionMemo<SweptInsn[]>();

  /** The sweep of exactly these bytes, from memory when possible. */
  sweep(bytes: Uint8Array, baseAddress: number, cs: CapstoneHandle, where: string): SweptInsn[] {
    return this.memo.get(bytes, baseAddress, cs, () => sweepX86(bytes, baseAddress, cs, where));
  }

  /**
   * The held sweep of exactly these bytes, or `undefined` — never sweeping.
   *
   * `hybridDisassemble`'s call. See {@link SectionMemo.peek} for why a
   * consumer that must not evict the slot has to peek rather than `get`, and
   * {@link gridScan} for what it does with the answer.
   */
  peek(
    bytes: Uint8Array,
    baseAddress: number,
    cs: CapstoneHandle | undefined,
  ): SweptInsn[] | undefined {
    return this.memo.peek(bytes, baseAddress, cs);
  }

  /** Forget the held section. See {@link SectionMemo.clear}. */
  clear(): void {
    this.memo.clear();
  }
}

/**
 * The index of the entry at exactly `address`, or `-1`.
 *
 * {@link sweepX86} emits strictly ascending addresses — it advances past the
 * instruction it just decoded, or by one byte when the decoder refused — so a
 * binary search is available with **no second structure over the same bytes**.
 * That is the point: a `Map<number, SweptInsn>` would be a third array over the
 * section (measured at ~0.13 µs/insn to build and tens of megabytes to hold on
 * a large image), where 18 comparisons cost 0.076 µs against the 3.7 µs decode
 * they replace.
 */
function indexOfAddress(grid: SweptInsn[], address: number): number {
  let lo = 0;
  let hi = grid.length - 1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const at = grid[mid].address;
    if (at === address) return mid;
    if (at < address) lo = mid + 1;
    else hi = mid - 1;
  }
  return -1;
}

/**
 * A scan that answers from an already-computed sweep where it can, and from the
 * decoder where it cannot.
 *
 * ## Why this is the shape, rather than a map consulted by each phase
 *
 * `hybridDisassemble` decodes in three quite different ways — a bulk pass over
 * each `.pdata` extent, a BFS asking for one instruction at a time at addresses
 * a *caller* named, and a linear fill of every gap the first two left — and each
 * has its own rule for how far to advance and when to stop. Interposing at the
 * **decoder** rather than at the three call sites means all three keep their
 * loops verbatim, so the stepping cannot come apart from the stepping this
 * replaces. It is `Arm64SweepCache`'s division exactly: only the decode is
 * served, and everything the caller does with it — `mapInsn`'s annotation, the
 * `source` marking, the coverage bitmap — is redone per call.
 *
 * ## Why it is sound
 *
 * A decode at an address is a function of the bytes at that address, and the
 * grid was produced from the same section, at the same load address, by the same
 * handle — which is exactly what {@link SectionMemo}'s three-part key
 * guarantees, and why the caller must obtain the grid by peeking that memo
 * rather than by sweeping for itself. Measured over the four corpus binaries and
 * a 669 KiB-`.text` `go` image: of the 222137 instructions `hybridDisassemble`
 * decodes, **99.9-100.0% are at an address the grid also has an instruction at,
 * and 100.0% of those agree in mnemonic, operands and size** (peek-a-bin-iqzu).
 *
 * The residue is 26 instructions on t32 and 22 on w32 and zero on the three x64
 * images, and it is not a defect in either direction: a linear sweep walks into
 * data and comes out misaligned, so it has *more* instructions than this method
 * wants (186281 against 155531 on the `go` image) and occasionally lacks one at
 * an address recursive descent knows to be a boundary. Every such address simply
 * misses and is decoded.
 *
 * ## The three rules, each of which is a way to be wrong
 *
 *  * **A miss delegates.** An address the grid has no entry at is either one the
 *    sweep stepped over or one the decoder refused; the two are indistinguishable
 *    from the grid, and in both cases the real scan gives the right answer.
 *  * **A run stops where the grid stops being contiguous.** `cs_disasm` returns
 *    instructions until it meets a byte it cannot decode; a discontinuity in the
 *    grid is that byte, recorded. Serving past it would invent instructions
 *    across a hole the caller is entitled to see.
 *  * **The caller's window still bounds the run.** `createScan` clamps every call
 *    to {@link CS_WINDOW_BYTES}, to the caller's `limit` and to the buffer, and
 *    Capstone never returns an instruction extending past that end. So an entry
 *    that would straddle the window ends the run here too, or the caller's
 *    `offset` advance would differ from what it advanced by before.
 *
 * ## `bytes` is a private copy, and that is not a detail
 *
 * `RawInsn.bytes` reaches the view as `Instruction.bytes` (the hex column) and
 * therefore crosses `postMessage` in the reply. capstone-wasm builds it with
 * `HEAPU8.slice`, i.e. its own small buffer; a `subarray` of the section here
 * would look identical in every field and would make the reply's structured
 * clone serialise the **whole `.text`**. `.slice()`, always — pinned by a test.
 *
 * ONCE PER MESSAGE, not once per instruction, and this sentence used to say the
 * latter. `StructuredSerializeInternal` carries a memory map, so one
 * `ArrayBuffer` referenced by N views is serialised once and the deserialised
 * views share it — measured in `corpus/replyCloneCost.ts`, whose control 4 clones
 * 500 views of an 8 MiB buffer and gets back exactly one 8 MiB buffer. The rule
 * is unaffected: a whole-section tax on every reply, and on every
 * ~100-instruction request back (`peek-a-bin-9gc9`), is a real cost, and that
 * harness measures it at 112x the private baseline. Only the magnitude was
 * overstated, by a factor of N. Note the *send* path is untouched by the dedup —
 * `workers/transfer.ts` is about a single view onto the whole file, and one
 * 16-byte view onto 8 MiB still drags all 8 MiB.
 */
export function gridScan(grid: SweptInsn[], real: CapstoneScan): CapstoneScan {
  function serve(
    bytes: Uint8Array,
    offset: number,
    limit: number,
    address: number,
    maxInsns: number,
  ): RawInsn[] | null {
    // `createScan.run`'s own bound, restated: a served run must end where a
    // decoded one would have.
    const end = Math.min(offset + CS_WINDOW_BYTES, limit, bytes.length);
    if (end <= offset) return null;
    let i = indexOfAddress(grid, address);
    if (i < 0) return null;
    const out: RawInsn[] = [];
    let expect = address;
    while (i < grid.length && out.length < maxInsns) {
      const g = grid[i];
      if (g.address !== expect) break;
      const at = offset + (g.address - address);
      if (at + g.size > end) break;
      out.push({
        address: g.address,
        bytes: bytes.slice(at, at + g.size),
        mnemonic: g.mnemonic,
        opStr: g.opStr,
        size: g.size,
      });
      expect = g.address + g.size;
      i++;
    }
    return out.length > 0 ? out : null;
  }

  return {
    decode: (bytes, offset, limit, address) =>
      serve(bytes, offset, limit, address, CS_MAX_INSNS_PER_CALL) ??
      real.decode(bytes, offset, limit, address),
    decodeOne: (bytes, offset, limit, address) =>
      serve(bytes, offset, limit, address, 1) ?? real.decodeOne(bytes, offset, limit, address),
  };
}
