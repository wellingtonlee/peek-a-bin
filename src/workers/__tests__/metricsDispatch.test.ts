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
  it("throws instead of returning undefined", () => {
    // The regression this guards: an unrecognised method posts
    // `{ id, result: undefined }` and the caller's promise resolves with
    // undefined, so a typo'd method looks like a call that returned nothing.
    expect(() => metricsDispatch("bogus" as MetricsMethod, {})).toThrow(
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
  ])("throws on %s rather than falling through", (_label, method) => {
    expect(() => metricsDispatch(method as MetricsMethod, {})).toThrow(/Unknown metrics method/);
  });
});

describe("metricsDispatch — fileMetrics", () => {
  const pe = parsePE(buildMinimalPE64());
  const ranges = pe.sections.map((s) => ({
    offset: s.pointerToRawData,
    length: s.sizeOfRawData,
  }));
  const args: FileMetricsArgs = {
    buffer: pe.buffer,
    peHeaderOffset: pe.dosHeader.e_lfanew,
    expectedChecksum: pe.optionalHeader.checksum,
    ranges,
  };

  it("returns the same checksum the main-thread path returns", () => {
    // The threshold in asyncMetricState.ts means most files never take the
    // worker path, so nothing else would catch the two disagreeing.
    const result = metricsDispatch("fileMetrics", args) as FileMetricsResult;
    expect(result.checksum).toEqual(validateChecksum(pe.buffer, pe));
  });

  it("returns one entropy per section, in section-table order", () => {
    const result = metricsDispatch("fileMetrics", args) as FileMetricsResult;
    expect(result.sectionEntropies).toHaveLength(pe.sections.length);
    expect(result.sectionEntropies).toEqual(computeSectionEntropies(pe.buffer, ranges));
  });

  it("computes each section's entropy over its raw-data window", () => {
    const result = metricsDispatch("fileMetrics", args) as FileMetricsResult;
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

  it("treats a missing ranges array as no sections", () => {
    // `args.ranges ?? []` — a request built without it must not throw inside
    // the worker, where the failure only ever surfaces as a rejected promise.
    const result = metricsDispatch("fileMetrics", {
      ...args,
      ranges: undefined,
    } as unknown as FileMetricsArgs) as FileMetricsResult;
    expect(result.sectionEntropies).toEqual([]);
    expect(result.checksum.actual).toBe(validateChecksum(pe.buffer, pe).actual);
  });

  it("scores an out-of-bounds section 0 rather than throwing", () => {
    const result = metricsDispatch("fileMetrics", {
      ...args,
      ranges: [{ offset: 0x7fffffff, length: 0x1000 }],
    }) as FileMetricsResult;
    expect(result.sectionEntropies).toEqual([0]);
  });

  it("reports the checksum as invalid when the header value disagrees", () => {
    const result = metricsDispatch("fileMetrics", {
      ...args,
      expectedChecksum: 0xdeadbeef,
    }) as FileMetricsResult;
    expect(result.checksum.expected).toBe(0xdeadbeef);
    expect(result.checksum.valid).toBe(false);
  });

  it("uses the peHeaderOffset it was given, not one it rediscovers", () => {
    // The whole reason the checksum was split out of validateChecksum is that
    // a PEFile cannot be posted cheaply; a worker that ignored these scalars
    // and guessed would be wrong on any image with an unusual e_lfanew.
    const shifted = metricsDispatch("fileMetrics", {
      ...args,
      peHeaderOffset: args.peHeaderOffset + 2,
    }) as FileMetricsResult;
    expect(shifted.checksum.actual).toBe(
      checksumFile(pe.buffer, args.peHeaderOffset + 2, args.expectedChecksum).actual,
    );
  });
});

describe("metricsDispatch — entropyBlocks", () => {
  const bytes = noisy(4096);

  it("agrees with the synchronous path for the same block size", () => {
    const args: EntropyBlocksArgs = { bytes, blockSize: 256 };
    expect(metricsDispatch("entropyBlocks", args)).toEqual(computeEntropyBlocks(bytes, 256));
  });

  it("honours the block size it is given", () => {
    expect(metricsDispatch("entropyBlocks", { bytes, blockSize: 1024 })).toHaveLength(4);
    expect(metricsDispatch("entropyBlocks", { bytes, blockSize: 512 })).toHaveLength(8);
  });

  it("returns an empty array for an empty range", () => {
    expect(metricsDispatch("entropyBlocks", { bytes: new Uint8Array(0), blockSize: 256 })).toEqual(
      [],
    );
  });

  it("handles a trailing partial block", () => {
    const odd = noisy(700);
    const blocks = metricsDispatch("entropyBlocks", { bytes: odd, blockSize: 256 }) as number[];
    expect(blocks).toHaveLength(3);
    expect(blocks[2]).toBe(computeSectionEntropy(odd.subarray(512)));
  });

  it("survives a view that is a window onto a larger buffer", () => {
    // The client slices the view before transferring it, so the worker always
    // sees offset 0 — but the dispatch must not assume that.
    const backing = noisy(8192);
    const window = backing.subarray(1000, 1000 + 512);
    expect(metricsDispatch("entropyBlocks", { bytes: window, blockSize: 256 })).toEqual(
      computeEntropyBlocks(window, 256),
    );
  });
});
