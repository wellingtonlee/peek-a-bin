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
 * sweep IS the disassembly and all three RPCs want the same array. Here only two
 * of the three do — `hybridDisassemble` is recursive descent over a BFS work
 * queue plus a gap fill, producing a different and annotated stream — so it is
 * deliberately not routed through this.
 *
 * End to end through the real `dispatch`, four RPCs in App.tsx's order
 * (detect, hybrid, xrefs, xrefs again with the extracted string set), one memo
 * against a memo that never stores:
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

import { type CapstoneHandle, createScan } from "./capstoneWindow";
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

  /** Forget the held section. See {@link SectionMemo.clear}. */
  clear(): void {
    this.memo.clear();
  }
}
