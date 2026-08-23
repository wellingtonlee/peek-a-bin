/**
 * The ARM64 unwind record decoder, rule by rule.
 *
 * The corpus binaries exercise most of this — 800 records, and
 * `corpus/arm64.ts` gates the answer against an independently written reading of
 * the prologue. What they do NOT exercise is written here and labelled: `RegF`,
 * `H`, `CR` 1 and 2, `alloc_l` and a truncated code all have **zero occurrences**
 * in either binary, so they are BOUNDS ON THE GRAMMAR rather than measured
 * savings, and a green corpus run says nothing whatever about them.
 */
import { describe, expect, it } from "vitest";
import { decodePackedArm64Unwind, decodeUnwindCodes, frameFromUnwindCodes } from "../arm64Unwind";

/** Build a packed `.pdata` word from its fields. */
function packed(o: {
  length?: number;
  regF?: number;
  regI?: number;
  h?: number;
  cr?: number;
  frameSize?: number;
}): number {
  const words = (o.length ?? 16) / 4;
  return (
    (1 |
      (words << 2) |
      ((o.regF ?? 0) << 13) |
      ((o.regI ?? 0) << 16) |
      ((o.h ?? 0) << 20) |
      ((o.cr ?? 3) << 21) |
      (((o.frameSize ?? 16) / 16) << 23)) >>>
    0
  );
}

describe("packed .pdata unwind word", () => {
  it("reads a chained function's frame delta straight out of FrameSize", () => {
    const f = decodePackedArm64Unwind(packed({ cr: 3, frameSize: 0x60, regI: 9 }));
    expect(f.frameDelta).toBe(0x60);
    expect(f.frameSize).toBe(0x60);
    expect(f.savedIntRegs).toBe(9);
    expect(f.source).toBe("packed");
  });

  it("reports NO frame pointer for every CR but 3", () => {
    // CR 0 is the only one of these the corpus contains (2 entries per binary);
    // 1 and 2 are bounds. Answering a delta for CR 1 — which saves lr but does
    // NOT establish x29 — would describe a frame register the function never
    // sets up.
    for (const cr of [0, 1, 2]) {
      expect(decodePackedArm64Unwind(packed({ cr, frameSize: 0x10 })).frameDelta).toBeNull();
    }
    // …and the size is still stated: an unchained function allocates a frame,
    // it just has no pointer to it.
    expect(decodePackedArm64Unwind(packed({ cr: 0, frameSize: 0x10 })).frameSize).toBe(0x10);
  });

  it("reads RegF as 'none, or RegF + 1' — a BOUND, RegF is 0 on all 500 corpus entries", () => {
    expect(decodePackedArm64Unwind(packed({ regF: 0 })).savedFpRegs).toBe(0);
    expect(decodePackedArm64Unwind(packed({ regF: 1 })).savedFpRegs).toBe(2);
    expect(decodePackedArm64Unwind(packed({ regF: 7 })).savedFpRegs).toBe(8);
  });

  it("reads H — a BOUND, H is 0 on all 500 corpus entries", () => {
    expect(decodePackedArm64Unwind(packed({ h: 0 })).homesParams).toBe(false);
    expect(decodePackedArm64Unwind(packed({ h: 1 })).homesParams).toBe(true);
  });
});

describe("unwind code stream", () => {
  it("allocates from save_r19r20_x as z * 8, not (z + 1) * 16", () => {
    // The exact rule the corpus caught wrong: with the other reading, agreement
    // with the instruction stream is 85 of 156 rather than 156 of 156, and the
    // frame-delta gate reports 70 disagreements on t64-arm.
    expect(decodeUnwindCodes([0x2c, 0xe4]).totalAlloc).toBe(96);
    expect(decodeUnwindCodes([0x24, 0xe4]).totalAlloc).toBe(32);
  });

  it("reads the codes as REVERSE prologue order when placing the frame pointer", () => {
    // Prologue: stp x19,x20,[sp,#-0x30]! / stp x29,lr,[sp,#0x20] / mov x29,sp
    // Codes, last instruction first: set_fp, save_fplr, save_r19r20_x.
    // Nothing is allocated after the fp is established, so the delta is the
    // whole allocation.
    const w = decodeUnwindCodes([0xe1, 0x44, 0x26, 0xe4]);
    expect(w.totalAlloc).toBe(48);
    expect(w.frameDelta).toBe(48);
  });

  it("subtracts what the prologue allocates AFTER the frame pointer is set", () => {
    // set_fp appears in the stream after alloc_s, i.e. the `sub sp,sp,#0x10`
    // runs after `mov x29,sp` and sits BELOW the frame pointer.
    const w = decodeUnwindCodes([0x01, 0xe1, 0x86, 0xe4]);
    expect(w.totalAlloc).toBe(16 + 56);
    expect(w.frameDelta).toBe(56);
  });

  it("SUBTRACTS add_fp's displacement rather than adding it", () => {
    // `add x29, sp, #0x50` puts the frame pointer 0x50 ABOVE the current sp, so
    // it is that much closer to entry sp. Adding instead takes the corpus to 3
    // wrong deltas and 1 wrong frame-pointer verdict on t64-arm.
    const w = decodeUnwindCodes([0xe2, 0x0a, 0x4a, 0x2c, 0xe4]);
    expect(w.totalAlloc).toBe(96);
    expect(w.frameDelta).toBe(96 - 80);
  });

  it("stops at `end`, so the epilogue's codes after it are not allocation", () => {
    // Real records carry more bytes after `end` — 112 of t64-arm's 156 do.
    // Counting them doubles the frame.
    expect(decodeUnwindCodes([0x24, 0xe4, 0x24, 0x24]).totalAlloc).toBe(32);
    expect(decodeUnwindCodes([0x24, 0xe5, 0x24]).totalAlloc).toBe(32);
  });

  it("reports the first byte it does not know instead of skipping it", () => {
    // A code stream is byte-packed, so a code of unknown WIDTH desynchronises
    // everything after it — skipping one byte and carrying on would produce a
    // confident wrong frame rather than no frame.
    const w = decodeUnwindCodes([0x24, 0xef, 0xe4]);
    expect(w.unknownByte).toBe(0xef);
    expect(frameFromUnwindCodes([0x24, 0xef, 0xe4])).toBeNull();
  });

  it("refuses a multi-byte code whose operand bytes are missing — a BOUND", () => {
    // No truncated record occurs in either corpus binary. Reading the absent
    // byte as 0 would invent an allocation of 0 and carry on.
    expect(decodeUnwindCodes([0x24, 0xc0]).unknownByte).toBe(0xc0);
    expect(decodeUnwindCodes([0xe0, 0x00, 0x01]).unknownByte).toBe(0xe0);
  });

  it("reads alloc_l's three operand bytes — a BOUND, it does not occur here", () => {
    expect(decodeUnwindCodes([0xe0, 0x00, 0x01, 0x00, 0xe4]).totalAlloc).toBe(0x100 * 16);
  });

  it("reports no frame pointer when no code establishes one", () => {
    const w = decodeUnwindCodes([0x24, 0xe4]);
    expect(w.frameDelta).toBeNull();
    expect(frameFromUnwindCodes([0x24, 0xe4])?.frameSize).toBe(32);
  });
});

describe("a frame register above the entry stack pointer", () => {
  it("is REFUSED, because it is the caller's frame and not this function's", () => {
    // t64-arm!0x140001830 and w64-arm's twin: a stack-probe thunk fragment that
    // allocates nothing and then says `add x29, sp, #0x10`. Publishing -16 puts
    // the frame-pointer gate red at exactly 1 on each binary.
    const w = decodeUnwindCodes([0xe2, 0x02, 0x44, 0xe4]);
    expect(w.frameDelta).toBe(-16);
    expect(frameFromUnwindCodes([0xe2, 0x02, 0x44, 0xe4])?.frameDelta).toBeNull();
  });

  it("allows a zero delta, which is an empty frame this function does own", () => {
    expect(frameFromUnwindCodes([0xe1, 0xe4])?.frameDelta).toBe(0);
  });
});

describe("frameSize is the record's TOTAL, never the delta", () => {
  it("keeps the whole allocation when the frame pointer is near the top", () => {
    // The defect this pins was live and was found by reading one recovered
    // frame: t64-arm!sub_140001070 has a delta of 0x10 and allocates 0x60, and
    // reporting the delta as the size understated it by 80 bytes while the
    // function's own slots ran out to +0x28. NO GATE SEES THIS — the corpus run
    // is 51 of 51 green with the defect in place — so this test is the whole
    // instrument.
    const f = frameFromUnwindCodes([0xe2, 0x0a, 0x4a, 0x2c, 0xe4]);
    expect(f?.frameDelta).toBe(16);
    expect(f?.frameSize).toBe(96);
  });
});
