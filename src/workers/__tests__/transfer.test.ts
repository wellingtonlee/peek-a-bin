/**
 * The transfer-list decision, tested in isolation.
 *
 * Two properties matter here and neither is visible by reading a call site:
 *
 *  1. What gets posted must hold *only the view's window*, not its whole
 *     backing buffer. That is the actual bug — a 4 KiB function argument was
 *     shipping a 262 MB file because structured clone serialises a view's
 *     entire `[[ViewedArrayBuffer]]`.
 *  2. Nothing the caller owns may end up in the transfer list. Transferring
 *     detaches, the main thread keeps reading the file buffer, and a detached
 *     file buffer is a hard crash on every subsequent read — strictly worse
 *     than the slow copy this replaces.
 */

import { describe, expect, it } from "vitest";
import { prepareBinaryArgs } from "../transfer";

/** A stand-in for the loaded file: 4 KiB, with a recognisable ".text" inside. */
function fileBuffer(): ArrayBuffer {
  const buffer = new ArrayBuffer(4096);
  new Uint8Array(buffer).fill(0xaa);
  new Uint8Array(buffer, 1024, 256).fill(0xcc);
  return buffer;
}

describe("prepareBinaryArgs — what gets posted", () => {
  it("posts only the view's window, not the whole backing buffer", () => {
    const buffer = fileBuffer();
    const section = new Uint8Array(buffer, 1024, 256);

    const { args } = prepareBinaryArgs({ bytes: section, baseAddress: 0x1000, is64: true });
    const posted = (args as { bytes: Uint8Array }).bytes;

    // The regression: this used to be the whole 4096-byte buffer.
    expect(posted.buffer.byteLength).toBe(256);
    expect(posted.byteOffset).toBe(0);
    expect(posted.byteLength).toBe(256);
  });

  it("preserves the bytes exactly", () => {
    const buffer = new ArrayBuffer(64);
    const all = new Uint8Array(buffer);
    for (let i = 0; i < 64; i++) all[i] = i;
    const window = new Uint8Array(buffer, 16, 8);

    const { args } = prepareBinaryArgs({ bytes: window });

    expect(Array.from((args as { bytes: Uint8Array }).bytes)).toEqual([
      16, 17, 18, 19, 20, 21, 22, 23,
    ]);
  });

  it("passes non-binary arguments through untouched", () => {
    const options = { entryPoint: 0x1400 };
    const { args, transfer } = prepareBinaryArgs({ baseAddress: 1, is64: false, options });

    expect(transfer).toEqual([]);
    expect((args as { options: unknown }).options).toBe(options);
  });

  it("returns the same object when there is nothing binary to rewrite", () => {
    // No allocation for the many small calls (configure, decompileFunction...).
    const input = { funcEntries: [[1, { name: "f", address: 1 }]] };
    expect(prepareBinaryArgs(input).args).toBe(input);
  });

  it("does not mutate the caller's args object", () => {
    const section = new Uint8Array(fileBuffer(), 1024, 256);
    const input = { bytes: section };

    prepareBinaryArgs(input);

    expect(input.bytes).toBe(section);
  });

  it("copies a whole ArrayBuffer argument rather than passing the original", () => {
    // `extractStrings` takes the file buffer itself. Slicing costs the same
    // bytes a clone would have copied but halves the time, and — critically —
    // keeps the original out of the transfer list.
    const buffer = fileBuffer();
    const { args, transfer } = prepareBinaryArgs({ buffer, imageBase: 0x140000000 });

    const posted = (args as { buffer: ArrayBuffer }).buffer;
    expect(posted).not.toBe(buffer);
    expect(posted.byteLength).toBe(buffer.byteLength);
    expect(transfer).toEqual([posted]);
  });

  it("handles several binary arguments in one call", () => {
    const a = new Uint8Array([1, 2, 3]);
    const b = new ArrayBuffer(8);
    const { args, transfer } = prepareBinaryArgs({ bytes: a, buffer: b, is64: true });

    expect(transfer).toHaveLength(2);
    expect((args as { is64: boolean }).is64).toBe(true);
  });
});

describe("prepareBinaryArgs — the detach hazard", () => {
  it("never puts a caller-owned buffer in the transfer list", () => {
    const buffer = fileBuffer();
    const section = new Uint8Array(buffer, 1024, 256);

    const { args, transfer } = prepareBinaryArgs({ bytes: section });

    expect(transfer).not.toContain(buffer);
    expect(transfer).toEqual([(args as { bytes: Uint8Array }).bytes.buffer]);
  });

  it("leaves the caller's buffer readable after the transferred copy is detached", () => {
    const buffer = fileBuffer();
    const section = new Uint8Array(buffer, 1024, 256);

    const { args, transfer } = prepareBinaryArgs({ bytes: section });
    // structuredClone with a transfer list is the same algorithm postMessage
    // runs, so this detaches exactly what a real post would detach.
    structuredClone(args, { transfer });

    expect(buffer.byteLength).toBe(4096);
    expect(section.byteLength).toBe(256);
    expect(section[0]).toBe(0xcc);
    // ...while the copy we handed over is gone, which is the point.
    expect((args as { bytes: Uint8Array }).bytes.byteLength).toBe(0);
  });

  it("survives the same buffer being sent on call after call", () => {
    // The load path sends `.text` at least four times (detectFunctions,
    // buildAllXrefs, hybridDisassemble, buildAllXrefs again once strings land).
    // If any one of them detached the file, the next would throw.
    const buffer = fileBuffer();

    for (let i = 0; i < 4; i++) {
      const section = new Uint8Array(buffer, 1024, 256);
      const { args, transfer } = prepareBinaryArgs({ bytes: section });
      structuredClone(args, { transfer });
      expect(section[0]).toBe(0xcc);
    }

    expect(new Uint8Array(buffer, 1024, 256)[255]).toBe(0xcc);
  });

  it("does not transfer a SharedArrayBuffer, which cannot be detached", () => {
    if (typeof SharedArrayBuffer === "undefined") return;
    const shared = new SharedArrayBuffer(16);
    const { args, transfer } = prepareBinaryArgs({ buffer: shared });

    expect(transfer).toEqual([]);
    expect((args as { buffer: unknown }).buffer).toBe(shared);
  });
});

describe("prepareBinaryArgs — edges", () => {
  it("throws on an already-detached view instead of posting garbage", () => {
    const owned = new Uint8Array(8);
    structuredClone(owned, { transfer: [owned.buffer] });

    expect(() => prepareBinaryArgs({ bytes: owned })).toThrow(TypeError);
  });

  it("handles a zero-length view", () => {
    const { args, transfer } = prepareBinaryArgs({ bytes: new Uint8Array(fileBuffer(), 8, 0) });

    expect((args as { bytes: Uint8Array }).bytes.byteLength).toBe(0);
    expect(transfer[0].byteLength).toBe(0);
  });

  it("preserves the element type of a non-byte typed array", () => {
    const { args } = prepareBinaryArgs({ bytes: new Uint32Array([1, 2, 3]) });
    const posted = (args as { bytes: Uint32Array }).bytes;

    expect(posted).toBeInstanceOf(Uint32Array);
    expect(Array.from(posted)).toEqual([1, 2, 3]);
  });

  it("copies a DataView's window", () => {
    const view = new DataView(fileBuffer(), 1024, 4);
    const { args } = prepareBinaryArgs({ bytes: view });
    const posted = (args as { bytes: DataView }).bytes;

    expect(posted).toBeInstanceOf(DataView);
    expect(posted.byteLength).toBe(4);
    expect(posted.buffer.byteLength).toBe(4);
    expect(posted.getUint8(0)).toBe(0xcc);
  });

  it.each([
    ["null", null],
    ["undefined", undefined],
    ["an array", [1, 2, 3]],
    ["a number", 42],
  ])("passes %s through with an empty transfer list", (_label, value) => {
    const { args, transfer } = prepareBinaryArgs(value);
    expect(args).toBe(value);
    expect(transfer).toEqual([]);
  });

  it("does not walk into nested values", () => {
    // An Instruction[] carries one tiny `bytes` buffer per element. Measured on
    // a 500k-instruction reply, transferring those took 80.6 s against 1.6 s to
    // clone them — per-entry transfer cost dominates for small buffers.
    const instructions = Array.from({ length: 3 }, () => ({ bytes: new Uint8Array(4) }));
    const { args, transfer } = prepareBinaryArgs({ instructions });

    expect(transfer).toEqual([]);
    expect((args as { instructions: unknown }).instructions).toBe(instructions);
  });
});
