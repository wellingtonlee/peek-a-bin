/**
 * `validateChecksum` against a literal transcription of the algorithm.
 *
 * The fast path sums the file through a `Uint16Array` and folds the carries
 * once at the end instead of after every word, which is only equivalent because
 * the fold is a reduction modulo 0xFFFF that reaches zero solely from an
 * all-zero sum. Nothing at runtime cross-checks a checksum, so that equivalence
 * is pinned here differentially rather than argued in a comment.
 */

import { describe, it, expect } from "vitest";
import { validateChecksum } from "../metadata";
import type { PEFile } from "../types";

/**
 * The algorithm as written in the PE spec and as this module used to implement
 * it: walk even offsets, skip the two words of the checksum field, fold after
 * every word, add the file length.
 */
function referenceChecksum(buffer: ArrayBuffer, checksumOffset: number): number {
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);
  let sum = 0;
  const limit = bytes.length;
  for (let i = 0; i < limit; i += 2) {
    if (i === checksumOffset || i === checksumOffset + 2) continue;
    const word = i + 1 < limit ? view.getUint16(i, true) : bytes[i];
    sum += word;
    sum = (sum & 0xffff) + (sum >>> 16);
  }
  sum = (sum & 0xffff) + (sum >>> 16);
  return (sum + limit) >>> 0;
}

/**
 * `validateChecksum` reads exactly two fields off the PEFile, so a stub is
 * enough — and it is the only way to reach an odd `e_lfanew`, which `parsePE`
 * would produce only from a file no linker writes.
 */
function stubPE(e_lfanew: number, checksum = 0): PEFile {
  return {
    dosHeader: { e_magic: 0x5a4d, e_lfanew },
    optionalHeader: { checksum },
  } as unknown as PEFile;
}

function buffered(bytes: number[]): ArrayBuffer {
  return new Uint8Array(bytes).buffer;
}

describe("validateChecksum against the reference walk", () => {
  it("agrees on a hand-built buffer at the usual 4-byte-aligned e_lfanew", () => {
    const buf = new ArrayBuffer(512);
    const b = new Uint8Array(buf);
    for (let i = 0; i < b.length; i++) b[i] = (i * 31) & 0xff;

    const peOffset = 0x80;
    expect(validateChecksum(buf, stubPE(peOffset)).actual).toBe(
      referenceChecksum(buf, peOffset + 88),
    );
  });

  it("agrees on an empty buffer", () => {
    expect(validateChecksum(new ArrayBuffer(0), stubPE(0x80)).actual).toBe(
      referenceChecksum(new ArrayBuffer(0), 0x80 + 88),
    );
  });

  it("agrees on an all-zero buffer, where the fold must land on 0 and not 0xFFFF", () => {
    const buf = new ArrayBuffer(256);
    expect(validateChecksum(buf, stubPE(0x80)).actual).toBe(referenceChecksum(buf, 0x80 + 88));
    // 256 bytes of zero: the sum is 0 and the result is just the file length.
    expect(validateChecksum(buf, stubPE(0x80)).actual).toBe(256);
  });

  it("agrees on an all-0xFF buffer, where the fold must land on 0xFFFF and not 0", () => {
    const buf = new ArrayBuffer(256);
    new Uint8Array(buf).fill(0xff);
    expect(validateChecksum(buf, stubPE(0x80)).actual).toBe(referenceChecksum(buf, 0x80 + 88));
  });

  it("agrees when the checksum field is the last thing in the file", () => {
    const buf = new ArrayBuffer(200);
    new Uint8Array(buf).fill(0xab);
    // e_lfanew chosen so checksumOffset + 4 lands exactly on the end.
    const peOffset = 200 - 4 - 88;
    expect(validateChecksum(buf, stubPE(peOffset)).actual).toBe(
      referenceChecksum(buf, peOffset + 88),
    );
  });

  it("agrees when the checksum field runs off the end of the file", () => {
    const buf = new ArrayBuffer(120);
    new Uint8Array(buf).fill(0xab);
    for (const peOffset of [30, 32, 34, 200]) {
      expect(validateChecksum(buf, stubPE(peOffset)).actual).toBe(
        referenceChecksum(buf, peOffset + 88),
      );
    }
  });

  it("agrees on an odd e_lfanew, where the walk never skips the field at all", () => {
    // Every visited offset is even, so an odd checksumOffset matches nothing and
    // the file sums its own checksum field. Quietly "fixing" that would break
    // round-tripping: the value this function computes has to verify against
    // itself when written back.
    const buf = new ArrayBuffer(300);
    const b = new Uint8Array(buf);
    for (let i = 0; i < b.length; i++) b[i] = (i * 17 + 3) & 0xff;

    for (const peOffset of [0x81, 0x83, 0x8f]) {
      expect(validateChecksum(buf, stubPE(peOffset)).actual).toBe(
        referenceChecksum(buf, peOffset + 88),
      );
    }
  });

  it("agrees on odd-length buffers, where the last byte is a half word", () => {
    for (const len of [1, 3, 91, 201, 511]) {
      const buf = new ArrayBuffer(len);
      const b = new Uint8Array(buf);
      for (let i = 0; i < len; i++) b[i] = (i * 97 + 11) & 0xff;
      expect(validateChecksum(buf, stubPE(0x10)).actual).toBe(referenceChecksum(buf, 0x10 + 88));
    }
  });

  it("agrees on a buffer whose only non-zero bytes are inside the checksum field", () => {
    // The excluded words carry the entire sum, so subtracting them has to leave
    // a true zero — the one case where a sum reduced modulo 0xFFFF could come
    // back as 0xFFFF instead.
    const peOffset = 8;
    const co = peOffset + 88;
    const bytes = new Array(160).fill(0);
    bytes[co] = 0xff;
    bytes[co + 1] = 0xff;
    bytes[co + 2] = 0xff;
    bytes[co + 3] = 0xff;

    expect(validateChecksum(buffered(bytes), stubPE(peOffset)).actual).toBe(
      referenceChecksum(buffered(bytes), co),
    );
    expect(validateChecksum(buffered(bytes), stubPE(peOffset)).actual).toBe(160);
  });

  it("agrees across 3000 pseudo-random buffers", () => {
    let seed = 0x9e3779b9;
    const rand = (n: number) => {
      seed = (Math.imul(seed, 1103515245) + 12345) & 0x7fffffff;
      return seed % n;
    };

    for (let trial = 0; trial < 3000; trial++) {
      const len = rand(400);
      const buf = new ArrayBuffer(len);
      const b = new Uint8Array(buf);
      const mode = trial & 3;
      for (let i = 0; i < len; i++) {
        if (mode === 0) b[i] = 0;
        else if (mode === 1) b[i] = 0xff;
        else if (mode === 2) b[i] = rand(256);
        else b[i] = rand(2) ? 0xff : 0;
      }
      const peOffset = rand(len + 8);
      expect(validateChecksum(buf, stubPE(peOffset)).actual).toBe(
        referenceChecksum(buf, peOffset + 88),
      );
    }
  });
});
