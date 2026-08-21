/**
 * The metrics worker's RPC dispatch.
 *
 * Extracted from `metrics.worker.ts` for the same reason `dispatch.ts` is
 * extracted from `disasm.worker.ts`: the worker module touches `self` and
 * cannot be imported under vitest, which would leave routing and the
 * unknown-method branch with no runtime coverage at all.
 *
 * What is checked here is the dispatch's own job — routing, argument
 * defaulting, error propagation, and that a reply computed off-thread equals
 * what the synchronous path the UI still uses for small files would have
 * produced. That last one is the real risk of this change: two code paths for
 * the same number, only one of which the user usually sees.
 *
 * Since `fileMetrics` accepts a `Blob` as well as an `ArrayBuffer` there are now
 * *three* paths to the same number, and the third is the one no other harness
 * can reach: the browser posts the `File` by reference and only the worker ever
 * reads its bytes. Node 20+ has a global `Blob`, so the equivalence is checked
 * here directly — same fixture, both arms, identical results — which is the
 * actual correctness claim of handing the handle over instead of a copy.
 */

import { describe, expect, it } from "vitest";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { checksumFile, validateChecksum } from "../../pe/metadata";
import { parsePE } from "../../pe/parser";
import {
  computeEntropyBlocks,
  computeSectionEntropies,
  computeSectionEntropy,
} from "../../utils/entropy";
import {
  type EntropyBlocksArgs,
  type FileMetricsArgs,
  type FileMetricsResult,
  type MetricsMethod,
  metricsDispatch,
} from "../metricsDispatch";

/** A buffer whose bytes are varied enough that entropy is not degenerate. */
function noisy(length: number, seed = 1): Uint8Array {
  const out = new Uint8Array(length);
  let x = seed;
  for (let i = 0; i < length; i++) {
    x = (x * 1103515245 + 12345) & 0x7fffffff;
    out[i] = (x >>> 16) & 0xff;
  }
  return out;
}

describe("metricsDispatch — unknown method", () => {
  // The dispatch is `async` now — a `Blob` source has to be read — so the
  // unknown-method branch rejects where it used to throw synchronously. That is
  // the same thing to `metrics.worker.ts`, which awaits inside its `try`, but it
  // is why these assertions are `rejects` and not `toThrow`.
  it("rejects instead of returning undefined", async () => {
    // The regression this guards: an unrecognised method posts
    // `{ id, result: undefined }` and the caller's promise resolves with
    // undefined, so a typo'd method looks like a call that returned nothing.
    await expect(metricsDispatch("bogus" as MetricsMethod, {})).rejects.toThrow(
      "Unknown metrics method: bogus",
    );
  });

  it.each([
    ["an empty string", ""],
    ["undefined", undefined],
    ["null", null],
    ["a number", 42],
    ["a near-miss of a real method", "FileMetrics"],
    ["an object", { method: "fileMetrics" }],
  ])("rejects on %s rather than falling through", async (_label, method) => {
    await expect(metricsDispatch(method as MetricsMethod, {})).rejects.toThrow(
      /Unknown metrics method/,
    );
  });
});

describe("metricsDispatch — fileMetrics", () => {
  const pe = parsePE(buildMinimalPE64());
  const ranges = pe.sections.map((s) => ({
    offset: s.pointerToRawData,
    length: s.sizeOfRawData,
  }));
  const args: FileMetricsArgs = {
    source: pe.buffer,
    peHeaderOffset: pe.dosHeader.e_lfanew,
    expectedChecksum: pe.optionalHeader.checksum,
    ranges,
  };

  it("returns the same checksum the main-thread path returns", async () => {
    // The threshold in asyncMetricState.ts means most files never take the
    // worker path, so nothing else would catch the two disagreeing.
    const result = (await metricsDispatch("fileMetrics", args)) as FileMetricsResult;
    expect(result.checksum).toEqual(validateChecksum(pe.buffer, pe));
  });

  it("returns one entropy per section, in section-table order", async () => {
    const result = (await metricsDispatch("fileMetrics", args)) as FileMetricsResult;
    expect(result.sectionEntropies).toHaveLength(pe.sections.length);
    expect(result.sectionEntropies).toEqual(computeSectionEntropies(pe.buffer, ranges));
  });

  it("computes each section's entropy over its raw-data window", async () => {
    const result = (await metricsDispatch("fileMetrics", args)) as FileMetricsResult;
    pe.sections.forEach((sec, i) => {
      const expected =
        sec.sizeOfRawData === 0
          ? 0
          : computeSectionEntropy(
              new Uint8Array(pe.buffer, sec.pointerToRawData, sec.sizeOfRawData),
            );
      expect(result.sectionEntropies[i]).toBe(expected);
    });
  });

  it("treats a missing ranges array as no sections", async () => {
    // `args.ranges ?? []` — a request built without it must not throw inside
    // the worker, where the failure only ever surfaces as a rejected promise.
    const result = (await metricsDispatch("fileMetrics", {
      ...args,
      ranges: undefined,
    } as unknown as FileMetricsArgs)) as FileMetricsResult;
    expect(result.sectionEntropies).toEqual([]);
    expect(result.checksum.actual).toBe(validateChecksum(pe.buffer, pe).actual);
  });

  it("scores an out-of-bounds section 0 rather than throwing", async () => {
    const result = (await metricsDispatch("fileMetrics", {
      ...args,
      ranges: [{ offset: 0x7fffffff, length: 0x1000 }],
    })) as FileMetricsResult;
    expect(result.sectionEntropies).toEqual([0]);
  });

  it("reports the checksum as invalid when the header value disagrees", async () => {
    const result = (await metricsDispatch("fileMetrics", {
      ...args,
      expectedChecksum: 0xdeadbeef,
    })) as FileMetricsResult;
    expect(result.checksum.expected).toBe(0xdeadbeef);
    expect(result.checksum.valid).toBe(false);
  });

  it("uses the peHeaderOffset it was given, not one it rediscovers", async () => {
    // The whole reason the checksum was split out of validateChecksum is that
    // a PEFile cannot be posted cheaply; a worker that ignored these scalars
    // and guessed would be wrong on any image with an unusual e_lfanew.
    const shifted = (await metricsDispatch("fileMetrics", {
      ...args,
      peHeaderOffset: args.peHeaderOffset + 2,
    })) as FileMetricsResult;
    expect(shifted.checksum.actual).toBe(
      checksumFile(pe.buffer, args.peHeaderOffset + 2, args.expectedChecksum).actual,
    );
  });
});

describe("metricsDispatch — entropyBlocks", () => {
  const bytes = noisy(4096);

  it("agrees with the synchronous path for the same block size", async () => {
    const args: EntropyBlocksArgs = { bytes, blockSize: 256 };
    expect(await metricsDispatch("entropyBlocks", args)).toEqual(computeEntropyBlocks(bytes, 256));
  });

  it("honours the block size it is given", async () => {
    expect(await metricsDispatch("entropyBlocks", { bytes, blockSize: 1024 })).toHaveLength(4);
    expect(await metricsDispatch("entropyBlocks", { bytes, blockSize: 512 })).toHaveLength(8);
  });

  it("returns an empty array for an empty range", async () => {
    expect(
      await metricsDispatch("entropyBlocks", { bytes: new Uint8Array(0), blockSize: 256 }),
    ).toEqual([]);
  });

  it("handles a trailing partial block", async () => {
    const odd = noisy(700);
    const blocks = (await metricsDispatch("entropyBlocks", {
      bytes: odd,
      blockSize: 256,
    })) as number[];
    expect(blocks).toHaveLength(3);
    expect(blocks[2]).toBe(computeSectionEntropy(odd.subarray(512)));
  });

  it("survives a view that is a window onto a larger buffer", async () => {
    // The client slices the view before transferring it, so the worker always
    // sees offset 0 — but the dispatch must not assume that.
    const backing = noisy(8192);
    const window = backing.subarray(1000, 1000 + 512);
    expect(await metricsDispatch("entropyBlocks", { bytes: window, blockSize: 256 })).toEqual(
      computeEntropyBlocks(window, 256),
    );
  });
});

/**
 * The equivalence that the Blob source rests on.
 *
 * `App.tsx` hands `metricsClient` the original `File` when the drop/browse path
 * produced one, and the client posts it by reference — so on that path *nothing*
 * ever reads the bytes on the main thread and the only reader is this dispatch.
 * If the two arms could disagree, the disagreement would be invisible: the file
 * would still parse, still disassemble, still render, and only the checksum
 * verdict and the section entropies (hence the anomaly list) would be wrong,
 * on large files, in a browser, with no test able to open the app.
 *
 * So the claim is asserted at full strength — `toEqual` over the whole result
 * object, not a spot check on one field — and with a negative control, because
 * a dispatch that quietly ignored the Blob and answered from something else
 * would otherwise be indistinguishable from one that read it.
 */
describe("metricsDispatch — fileMetrics from a Blob", () => {
  const pe = parsePE(buildMinimalPE64());
  const ranges = pe.sections.map((s) => ({
    offset: s.pointerToRawData,
    length: s.sizeOfRawData,
  }));
  const scalars = {
    peHeaderOffset: pe.dosHeader.e_lfanew,
    expectedChecksum: pe.optionalHeader.checksum,
    ranges,
  };
  const fromBuffer = (source: ArrayBuffer | Blob) =>
    metricsDispatch("fileMetrics", { source, ...scalars }) as Promise<FileMetricsResult>;

  it("returns exactly what the ArrayBuffer arm returns, field for field", async () => {
    const viaBuffer = await fromBuffer(pe.buffer);
    const viaBlob = await fromBuffer(new Blob([pe.buffer]));
    expect(viaBlob).toEqual(viaBuffer);
    // Spelled out as well as compared, so a failure says which half moved.
    expect(viaBlob.checksum).toEqual(validateChecksum(pe.buffer, pe));
    expect(viaBlob.sectionEntropies).toEqual(computeSectionEntropies(pe.buffer, ranges));
  });

  it("accepts a File, which is the type the browser actually posts", async () => {
    // `File extends Blob`; the dispatch tests for Blob-ness, so this is the
    // assertion that the subclass is not excluded by a narrower check.
    const file = new File([pe.buffer], "fixture.exe", { type: "application/octet-stream" });
    expect(await fromBuffer(file)).toEqual(await fromBuffer(pe.buffer));
  });

  it("reads the bytes out of the Blob rather than ignoring it", async () => {
    // Negative control. Every assertion above would still pass if the dispatch
    // resolved a Blob to the wrong bytes in some consistent way, so flip one
    // byte and require the answer to follow the Blob.
    const patched = new Uint8Array(pe.buffer.slice(0));
    patched[patched.length - 1] ^= 0xff;
    const viaBlob = await fromBuffer(new Blob([patched]));
    expect(viaBlob.checksum.actual).not.toBe(validateChecksum(pe.buffer, pe).actual);
    expect(viaBlob.checksum.actual).toBe(
      checksumFile(patched.buffer as ArrayBuffer, scalars.peHeaderOffset, scalars.expectedChecksum)
        .actual,
    );
  });

  it("agrees on a multi-part Blob, and on an odd length", async () => {
    // A Blob is a concatenation of its parts, and `Blob.arrayBuffer()` is the
    // only place that concatenation happens — an odd total length also exercises
    // `checksumFile`'s trailing-byte arm, where a half-word read differs.
    const bytes = noisy(4097, 7);
    const whole = bytes.slice();
    const parts = new Blob([bytes.subarray(0, 1000), bytes.subarray(1000)]);
    const args = {
      peHeaderOffset: 0x40,
      expectedChecksum: 0,
      ranges: [{ offset: 8, length: 512 }],
    };
    const viaBlob = (await metricsDispatch("fileMetrics", {
      source: parts,
      ...args,
    })) as FileMetricsResult;
    const viaBuffer = (await metricsDispatch("fileMetrics", {
      source: whole.buffer as ArrayBuffer,
      ...args,
    })) as FileMetricsResult;
    expect(viaBlob).toEqual(viaBuffer);
    expect(viaBlob.sectionEntropies).toEqual([
      computeSectionEntropy(new Uint8Array(whole.buffer, 8, 512)),
    ]);
  });

  it("rejects rather than answering from nothing when the Blob cannot be read", async () => {
    // A `File` whose backing file changed on disk must fail the read per the
    // File API rather than return the new bytes. The client turns a rejection
    // into a failed metric, which every caller already handles; what must never
    // happen is a plausible answer computed from an empty or partial read.
    const unreadable = {
      size: pe.buffer.byteLength,
      arrayBuffer: () => Promise.reject(new Error("NotReadableError")),
    };
    Object.setPrototypeOf(unreadable, Blob.prototype);
    await expect(fromBuffer(unreadable as unknown as Blob)).rejects.toThrow("NotReadableError");
  });
});
