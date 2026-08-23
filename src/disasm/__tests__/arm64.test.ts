/**
 * The ARM64 disassembly path (peek-a-bin-amu).
 *
 * Capstone is faked. A64 is fixed-width and 4-byte aligned, so a decoder stub
 * that maps one word to one instruction reproduces every property this module
 * actually depends on — where the sweep restarts after an undecodable word, how
 * wide a buffer it hands the decoder, and which words it treats as vouched-for
 * code. Using the real engine here would test Capstone, not this file, and
 * would drag WASM into the suite; the real engine's output is verified against
 * t64-arm.exe / w64-arm.exe outside the repo.
 */

import { describe, expect, it } from "vitest";
import {
  ARCH_LABEL,
  archForMachine,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_I386,
  isKnownMachine,
  unsupportedArchMessage,
  unsupportedOnArch,
} from "../arch";
import {
  ARM64_DECODE_WINDOW,
  ARM64_INSN_SIZE,
  ARM64_MIN_DECODE_FRACTION,
  ARM64_MIN_MEASURED_WORDS,
  type Arm64Context,
  Arm64DecodeRateError,
  Arm64SweepCache,
  classifyArm64Br,
  decorateArm64Sweep,
  detectArm64Functions,
  disassembleArm64,
  findArm64JumpTables,
  sweepArm64,
} from "../arm64";
import { CapstoneUnavailableError, CS_ARCH_ARM64 } from "../capstoneWindow";
import type { Instruction } from "../types";

/** `nop` on A64 — `d503201f`, little-endian. See {@link fakeCs}. */
function isArm64Nop(bytes: Uint8Array, i: number): boolean {
  return (
    bytes[i] === 0x1f && bytes[i + 1] === 0x20 && bytes[i + 2] === 0x03 && bytes[i + 3] === 0xd5
  );
}

/** One decoded word, in the shape capstone-wasm returns. */
interface FakeInsn {
  address: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
  size: number;
}

/**
 * A stand-in for a `CS_ARCH_ARM64` handle.
 *
 * `words` maps a 4-byte-aligned address to what it decodes to; an address that
 * is absent is an undecodable word. Like capstone-wasm, a call whose *first*
 * word does not decode throws rather than returning an empty list, and a call
 * stops at the first word that does not decode.
 */
function fakeCs(words: Map<number, { mnemonic: string; opStr: string }>) {
  const calls: { address: number; length: number }[] = [];
  return {
    calls,
    // A real handle carries the arch it was opened with, and the liveness probe
    // in `capstoneWindow.ts` reads it to decide which `nop` encoding to send.
    arch: CS_ARCH_ARM64,
    disasm(bytes: Uint8Array, options: { address: number }): FakeInsn[] {
      calls.push({ address: options.address, length: bytes.length });
      const out: FakeInsn[] = [];
      for (let i = 0; i + ARM64_INSN_SIZE <= bytes.length; i += ARM64_INSN_SIZE) {
        const address = options.address + i;
        // A real decoder answers on the encoding, not the address, so the one
        // word `capstoneWindow.ts` sends as a liveness probe (`nop`, d503201f)
        // decodes here wherever it appears. Without this the stub is a decoder
        // that fails its own liveness check, and a long run of undecodable
        // words — which is what several of these cases are — reads as an
        // exhausted engine.
        const word = isArm64Nop(bytes, i) ? { mnemonic: "nop", opStr: "" } : words.get(address);
        if (!word) break;
        out.push({
          address,
          bytes: bytes.subarray(i, i + ARM64_INSN_SIZE),
          mnemonic: word.mnemonic,
          opStr: word.opStr,
          size: ARM64_INSN_SIZE,
        });
      }
      if (out.length === 0) throw new Error("Failed to disassemble, error: OK (CS_ERR_OK)");
      return out;
    },
  };
}

const BASE = 0x140001000;

/** `count` decodable words starting at `BASE + startOffset`. */
function code(
  count: number,
  startOffset = 0,
  mnemonic = "mov",
): Map<number, { mnemonic: string; opStr: string }> {
  const m = new Map<number, { mnemonic: string; opStr: string }>();
  for (let i = 0; i < count; i++) {
    m.set(BASE + startOffset + i * ARM64_INSN_SIZE, { mnemonic, opStr: "x0, x1" });
  }
  return m;
}

function ctx(cs: unknown): Arm64Context {
  return { cs, stringMap: new Map(), iatMap: new Map(), driverMode: false };
}

describe("disassembleArm64", () => {
  it("decodes a run of instructions", () => {
    const cs = fakeCs(code(8));

    const insns = disassembleArm64(new Uint8Array(32), BASE, ctx(cs));

    expect(insns).toHaveLength(8);
    expect(insns[0].address).toBe(BASE);
    expect(insns[7].address).toBe(BASE + 28);
    expect(insns.every((i) => i.size === ARM64_INSN_SIZE)).toBe(true);
  });

  it("resumes after an undecodable word instead of stopping there", () => {
    // Alignment padding and literal data sit between functions in every real
    // ARM64 .text. A sweep that gave up at the first one would return the first
    // function and nothing else.
    const words = code(4);
    for (const [k, v] of code(4, 20)) words.set(k, v);

    const insns = disassembleArm64(new Uint8Array(36), BASE, ctx(fakeCs(words)));

    expect(insns.map((i) => i.address - BASE)).toEqual([0, 4, 8, 12, 20, 24, 28, 32]);
  });

  it("keeps every address 4-byte aligned", () => {
    const words = code(2);
    for (const [k, v] of code(2, 24)) words.set(k, v);

    const insns = disassembleArm64(new Uint8Array(32), BASE, ctx(fakeCs(words)));

    expect(insns.every((i) => (i.address - BASE) % ARM64_INSN_SIZE === 0)).toBe(true);
  });

  it("probes one word at a time across a run of undecodable data", () => {
    // The heap cost of a sweep is roughly calls x window, and capstone-wasm does
    // not release the input buffer. Widening the probe to a full window would
    // make a section of data cost a thousand times more heap per word — which is
    // how a 64 KiB-window sweep of t64-arm.exe ended up exhausting the WASM heap
    // and returning 11548 of 27428 instructions.
    const cs = fakeCs(code(1, 400));

    // 0x2000 bytes with one decodable word in them is also, correctly, a
    // section that is not A64 — see Arm64DecodeRateError. That refusal comes
    // after the sweep, so it says nothing about how the sweep was conducted,
    // which is what this case is about.
    expect(() => disassembleArm64(new Uint8Array(0x2000), BASE, ctx(cs))).toThrow(
      Arm64DecodeRateError,
    );

    const probes = cs.calls.filter((c) => c.address > BASE && c.address < BASE + 400);
    expect(probes.length).toBeGreaterThan(0);
    expect(probes.every((c) => c.length === ARM64_INSN_SIZE)).toBe(true);
  });

  it("never hands the decoder more than one window at a time", () => {
    const cs = fakeCs(code(0x4000 / ARM64_INSN_SIZE));

    disassembleArm64(new Uint8Array(0x4000), BASE, ctx(cs));

    expect(cs.calls.every((c) => c.length <= ARM64_DECODE_WINDOW)).toBe(true);
    expect(cs.calls.length).toBeGreaterThan(1); // it really did chunk
  });

  it("decodes past the end of one window", () => {
    const total = (0x4000 / ARM64_INSN_SIZE) | 0;
    const insns = disassembleArm64(new Uint8Array(0x4000), BASE, ctx(fakeCs(code(total))));

    expect(insns).toHaveLength(total);
  });

  it("ignores a trailing partial word", () => {
    const insns = disassembleArm64(new Uint8Array(10), BASE, ctx(fakeCs(code(2))));

    expect(insns).toHaveLength(2);
  });

  it("marks words inside a .pdata extent as vouched-for and the rest as gap fill", () => {
    // The disassembly view dims "gap-fill" rows. For ARM64 that distinction is
    // exactly "the image says this is a function" vs "the sweep decoded it".
    const insns = disassembleArm64(new Uint8Array(32), BASE, ctx(fakeCs(code(8))), [
      { beginAddress: BASE, endAddress: BASE + 16 },
    ]);

    expect(insns.filter((i) => i.source === "recursive").map((i) => i.address - BASE)).toEqual([
      0, 4, 8, 12,
    ]);
    expect(insns.filter((i) => i.source === "gap-fill")).toHaveLength(4);
  });

  it("leaves source unset when no .pdata is available to judge against", () => {
    const insns = disassembleArm64(new Uint8Array(16), BASE, ctx(fakeCs(code(4))));

    expect(insns.every((i) => i.source === undefined)).toBe(true);
  });

  it("throws rather than returning nothing when the handle is missing", () => {
    // peek-a-bin-cen, replacing the opposite assertion. The worker's Capstone
    // bootstrap is async and a decode RPC can land before it resolves — but
    // "the sweep found no instructions" and "there was no decoder" are the same
    // value here, and this sweep IS the ARM64 disassembly. Taking the analysis
    // chain down is the smaller harm: `analysisPhase` has a "failed" state and
    // the status bar surfaces it, whereas an empty `.text` is surfaced as a
    // finished analysis of a file with no code in it.
    expect(() => disassembleArm64(new Uint8Array(16), BASE, ctx(undefined))).toThrow(
      CapstoneUnavailableError,
    );
  });

  it("terminates on a decoder that reports no forward progress", () => {
    const stuck = {
      disasm: (_b: Uint8Array, o: { address: number }): FakeInsn[] => [
        { address: o.address, bytes: new Uint8Array(4), mnemonic: "nop", opStr: "", size: 0 },
      ],
    };

    const insns = disassembleArm64(new Uint8Array(16), BASE, ctx(stuck));

    expect(insns).toHaveLength(4);
  });

  /**
   * peek-a-bin-2t1. ARM64EC and ARM64X images carry machine 0xAA64, the same
   * value pure ARM64 does, and hold x86-64 code. Nothing here can read the CHPE
   * pointer that tells them apart — it lives in the load-config directory the
   * PE parser does not parse — but the decode rate is evidence about the bytes
   * themselves, and it separates cleanly: 97.4% / 97.7% on t64-arm.exe and
   * w64-arm.exe against 21.8%-27.9% for the x86 and x64 binaries swept as A64.
   */
  describe("a section that does not decode as A64 is refused, not reported", () => {
    const WORDS = ARM64_MIN_MEASURED_WORDS * 2;
    const BYTES = WORDS * ARM64_INSN_SIZE;

    /** A section where `n` of its `WORDS` words decode. */
    const partial = (n: number) => {
      const words = new Map<number, { mnemonic: string; opStr: string }>();
      // Spread them out, so this is a low rate rather than a short section.
      for (let i = 0; i < n; i++) {
        words.set(BASE + i * 2 * ARM64_INSN_SIZE, { mnemonic: "mov", opStr: "x0, x1" });
      }
      return words;
    };

    it("throws below the floor rather than returning the words that decoded", () => {
      const decoded = Math.floor(WORDS * ARM64_MIN_DECODE_FRACTION) - 1;
      expect(() =>
        disassembleArm64(new Uint8Array(BYTES), BASE, ctx(fakeCs(partial(decoded)))),
      ).toThrow(Arm64DecodeRateError);
    });

    it("names the rate it measured, so the claim can be checked", () => {
      const decoded = 10;
      try {
        disassembleArm64(new Uint8Array(BYTES), BASE, ctx(fakeCs(partial(decoded))));
        expect.unreachable();
      } catch (err) {
        expect(err).toBeInstanceOf(Arm64DecodeRateError);
        expect((err as Arm64DecodeRateError).decoded).toBe(decoded);
        expect((err as Arm64DecodeRateError).words).toBe(WORDS);
        expect((err as Error).message).toContain("ARM64EC");
      }
    });

    it("accepts a section at the floor", () => {
      const decoded = Math.ceil(WORDS * ARM64_MIN_DECODE_FRACTION);
      const insns = disassembleArm64(new Uint8Array(BYTES), BASE, ctx(fakeCs(partial(decoded))));
      expect(insns).toHaveLength(decoded);
    });

    it("does not judge a section too small to be evidence", () => {
      // A handful of thunks can miss the fraction by chance. Every other
      // fixture in this file is under the minimum for exactly that reason.
      const small = (ARM64_MIN_MEASURED_WORDS - 4) * ARM64_INSN_SIZE;
      expect(disassembleArm64(new Uint8Array(small), BASE, ctx(fakeCs(new Map())))).toEqual([]);
    });

    it("leaves the real ARM64 rate a long way clear of the floor", () => {
      // 97.4% measured on t64-arm.exe. Raising the floor past that band would
      // start refusing the images this module was written for.
      expect(ARM64_MIN_DECODE_FRACTION).toBeLessThan(0.9);
      expect(ARM64_MIN_DECODE_FRACTION).toBeGreaterThan(0.35);
    });
  });
});

describe("detectArm64Functions", () => {
  const pdata = [
    { beginAddress: BASE, endAddress: BASE + 16 },
    { beginAddress: BASE + 32, endAddress: BASE + 48 },
  ];

  it("takes function extents from .pdata, with exact sizes", () => {
    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(new Map())), {
      pdataFunctions: pdata,
    });

    expect(functions.map((f) => [f.address - BASE, f.size])).toEqual([
      [0, 16],
      [32, 16],
    ]);
  });

  it("names exports, the entry point and unwind handlers", () => {
    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(new Map())), {
      pdataFunctions: pdata,
      entryPoint: BASE + 32,
      exports: [{ name: "DllMain", address: BASE }],
      handlerAddresses: [BASE + 48],
    });

    const byAddr = new Map(functions.map((f) => [f.address - BASE, f.name]));
    expect(byAddr.get(0)).toBe("DllMain");
    expect(byAddr.get(32)).toBe("entry_point");
    expect(byAddr.get(48)).toBe(`__handler_${(BASE + 48).toString(16)}`);
  });

  it("names anything else sub_ADDR in upper-case hex, as the x86 path does", () => {
    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(new Map())), {
      pdataFunctions: [pdata[0]],
    });

    expect(functions[0].name).toBe(`sub_${BASE.toString(16).toUpperCase()}`);
  });

  it("adds the target of a direct bl — the leaf functions .pdata may omit", () => {
    const words = code(8);
    words.set(BASE, { mnemonic: "bl", opStr: `#0x${(BASE + 32).toString(16)}` });

    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(words)), {
      pdataFunctions: [pdata[0]],
    });

    expect(functions.map((f) => f.address - BASE)).toEqual([0, 32]);
  });

  it("ignores a bl into the middle of a known function", () => {
    // A call to an interior label is not a second function. .pdata recorded
    // where this one starts, and that outranks the inference.
    const words = code(8);
    words.set(BASE, { mnemonic: "bl", opStr: `#0x${(BASE + 8).toString(16)}` });

    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(words)), {
      pdataFunctions: [pdata[0]],
    });

    expect(functions.map((f) => f.address - BASE)).toEqual([0]);
  });

  it("ignores a bl outside the section", () => {
    const words = code(8);
    words.set(BASE, { mnemonic: "bl", opStr: "#0x7ff900001000" });

    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(words)), {
      pdataFunctions: [pdata[0]],
    });

    expect(functions.map((f) => f.address - BASE)).toEqual([0]);
  });

  it("sizes a bl-discovered function up to the next function start", () => {
    const words = code(16);
    words.set(BASE + 4, { mnemonic: "bl", opStr: `#0x${(BASE + 16).toString(16)}` });

    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(words)), {
      pdataFunctions: [pdata[0], pdata[1]],
    });

    expect(functions.map((f) => [f.address - BASE, f.size])).toEqual([
      [0, 16],
      [16, 16],
      [32, 16],
    ]);
  });

  it("reports no jump tables where nothing dispatches through one", () => {
    const { jumpTables } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(code(16))), {
      pdataFunctions: pdata,
    });

    expect(jumpTables).toEqual([]);
  });

  it("reports a recovered dispatch table, and does not call its cases functions", () => {
    // Case bodies are labels inside the dispatching function, so they belong in
    // `jumpTables` and not in `functions` — the same split `functionDetect.ts`
    // makes for the x86 tables.
    const words = new Map<number, { mnemonic: string; opStr: string }>();
    const set = (off: number, mnemonic: string, opStr: string) =>
      words.set(BASE + off, { mnemonic, opStr });
    set(0x00, "cmp", "w1, #1");
    set(0x04, "b.hi", `#0x${(BASE + 0x40).toString(16)}`);
    set(0x08, "adr", `x9, #0x${(BASE + 0x20).toString(16)}`);
    set(0x0c, "ldrb", "w8, [x9, w1, uxtw]");
    set(0x10, "add", "x8, x9, x8, lsl #2");
    set(0x14, "br", "x8");

    const img = new Uint8Array(0x60);
    img[0x20] = 2; // case 0 -> BASE + 0x20 + 8  = BASE + 0x28
    img[0x21] = 4; // case 1 -> BASE + 0x20 + 16 = BASE + 0x30

    const { functions, jumpTables } = detectArm64Functions(img, BASE, ctx(fakeCs(words)), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 0x40 }],
    });

    expect(jumpTables).toEqual([[BASE + 0x14, [BASE + 0x28, BASE + 0x30]]]);
    expect(functions.map((f) => f.address)).toEqual([BASE]);
  });

  /**
   * peek-a-bin-gb40. The extents go out with the tables. Nothing else tells
   * `dataView.ts` those bytes are data, and until this was published 9 words of
   * 255 in recovered table extents on t64-arm.exe rendered as instructions —
   * one of them a `cbz` aiming outside the image.
   */
  it("publishes the byte extent of each recovered table", () => {
    const words = new Map<number, { mnemonic: string; opStr: string }>();
    const set = (off: number, mnemonic: string, opStr: string) =>
      words.set(BASE + off, { mnemonic, opStr });
    set(0x00, "cmp", "w1, #1");
    set(0x04, "b.hi", `#0x${(BASE + 0x40).toString(16)}`);
    set(0x08, "adr", `x9, #0x${(BASE + 0x20).toString(16)}`);
    set(0x0c, "ldrb", "w8, [x9, w1, uxtw]");
    set(0x10, "add", "x8, x9, x8, lsl #2");
    set(0x14, "br", "x8");

    const img = new Uint8Array(0x60);
    img[0x20] = 2;
    img[0x21] = 4;

    const { jumpTableSpans } = detectArm64Functions(img, BASE, ctx(fakeCs(words)), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 0x40 }],
    });

    // Two one-byte entries at BASE + 0x20.
    expect(jumpTableSpans).toEqual([[BASE + 0x20, BASE + 0x22]]);
  });

  it("publishes no extents where no table was recovered", () => {
    const { jumpTableSpans } = detectArm64Functions(
      new Uint8Array(64),
      BASE,
      ctx(fakeCs(code(16))),
      { pdataFunctions: pdata },
    );

    expect(jumpTableSpans).toEqual([]);
  });

  it("finds nothing at all in an image with no recorded starts and no calls", () => {
    // Notably it does NOT fall back to a prologue byte scan — that is the x86
    // heuristic this module exists to avoid running on ARM64 bytes.
    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(code(16))));

    expect(functions).toEqual([]);
  });

  // peek-a-bin-4s9. Answering without a decoder is right — `.pdata` is the
  // evidence this detector is built on and it is not made of instructions —
  // but the answer is narrower, and until `omitted` existed nothing said so.
  describe("without a decoder, the answer is narrower and says so", () => {
    const words = code(8);
    words.set(BASE + 4, { mnemonic: "bl", opStr: `#0x${(BASE + 32).toString(16)}` });

    it("still reports the starts .pdata records", () => {
      const { functions, omitted } = detectArm64Functions(new Uint8Array(64), BASE, ctx(null), {
        pdataFunctions: [pdata[0]],
      });

      expect(functions.map((f) => f.address - BASE)).toEqual([0]);
      expect(omitted).toEqual(["call-targets", "jump-tables"]);
    });

    it("reports nothing omitted with a decoder, and the bl target proves it", () => {
      const { functions, omitted } = detectArm64Functions(
        new Uint8Array(64),
        BASE,
        ctx(fakeCs(words)),
        { pdataFunctions: [pdata[0]] },
      );

      // The same image the decoder-less run above saw only one function in.
      expect(functions.map((f) => f.address - BASE)).toEqual([0, 32]);
      expect(omitted).toEqual([]);
    });

    it("degrades the same way when the section turns out not to be A64", () => {
      // peek-a-bin-2t1 meeting peek-a-bin-4s9. `disassembleArm64` refuses an
      // ARM64EC-shaped section outright, because instructions are its whole
      // output — but `.pdata` is the linker's own record and is still true of
      // such an image, so detection reports it and says what it could not do.
      const wide = ARM64_MIN_MEASURED_WORDS * 2 * ARM64_INSN_SIZE;
      const { functions, omitted } = detectArm64Functions(
        new Uint8Array(wide),
        BASE,
        ctx(fakeCs(new Map())),
        { pdataFunctions: [pdata[0]], exports: [{ name: "DllMain", address: BASE }] },
      );

      expect(functions.map((f) => f.name)).toEqual(["DllMain"]);
      expect(omitted).toEqual(["call-targets", "jump-tables"]);
    });

    it("does not claim to have lost passes it never had", () => {
      // Thunk naming and tail-call detection are x86-only by design. Listing
      // them would report a design decision as a degradation.
      const { omitted } = detectArm64Functions(new Uint8Array(64), BASE, ctx(null));

      expect(omitted).not.toContain("thunk-names");
      expect(omitted).not.toContain("tail-calls");
    });
  });
});

/**
 * peek-a-bin-8ij. The dispatch chain is read straight from decoded instructions,
 * so these cases are written as instruction streams rather than as images: the
 * thing under test is the walk and the entry arithmetic, and a fake decoder in
 * between would only restate them.
 */
describe("findArm64JumpTables", () => {
  const TABLE_OFF = 0x40;

  /** `[mnemonic, opStr]` pairs laid out one word apart from `BASE`. */
  function stream(rows: [string, string][], from = BASE): Instruction[] {
    return rows.map(([mnemonic, opStr], i) => ({
      address: from + i * ARM64_INSN_SIZE,
      bytes: new Uint8Array(4),
      mnemonic,
      opStr,
      size: ARM64_INSN_SIZE,
    }));
  }

  /** An image with `entries` written at `TABLE_OFF`, `width` bytes each. */
  function imageWith(entries: number[], width = 1, size = 0x100): Uint8Array {
    const img = new Uint8Array(size);
    entries.forEach((e, i) => {
      for (let b = 0; b < width; b++) img[TABLE_OFF + i * width + b] = (e >>> (8 * b)) & 0xff;
    });
    return img;
  }

  const TABLE = BASE + TABLE_OFF;
  /** `cmp`/`b.hi`/`adr`/`ldrb`/`add`/`br` — the one-adr, byte-entry shape. */
  const byteEntryChain: [string, string][] = [
    ["cmp", "w1, #3"],
    ["b.hi", `#0x${(BASE + 0x80).toString(16)}`],
    ["adr", `x9, #0x${TABLE.toString(16)}`],
    ["ldrb", "w8, [x9, w1, uxtw]"],
    ["add", "x8, x9, x8, lsl #2"],
    ["br", "x8"],
  ];
  const brAddr = BASE + 5 * ARM64_INSN_SIZE;

  /** The case lists alone; `spans` has its own describe block below. */
  const find = (rows: [string, string][], img: Uint8Array) =>
    findArm64JumpTables(stream(rows), img, BASE).tables;

  it("recovers the one-adr, byte-entry dispatch", () => {
    // Entries are offsets from the table base in instruction-sized units.
    const tables = find(byteEntryChain, imageWith([1, 2, 3, 4]));
    expect(tables.get(brAddr)).toEqual([TABLE + 4, TABLE + 8, TABLE + 12, TABLE + 16]);
  });

  it("recovers the two-adr, word-entry dispatch, where the same register is reused", () => {
    // `adr x9` names the table, then `adr x9` names the case base — reading
    // either as the other relocates every case body.
    const caseBase = BASE + 0x20;
    const rows: [string, string][] = [
      ["cmp", "w10, #1"],
      ["b.hi", `#0x${(BASE + 0x80).toString(16)}`],
      ["adr", `x9, #0x${TABLE.toString(16)}`],
      ["ldrsw", "x8, [x9, w10, uxtw #2]"],
      ["adr", `x9, #0x${caseBase.toString(16)}`],
      ["add", "x8, x9, x8, lsl #2"],
      ["br", "x8"],
    ];
    const tables = findArm64JumpTables(stream(rows), imageWith([2, 5], 4), BASE).tables;
    expect(tables.get(BASE + 6 * ARM64_INSN_SIZE)).toEqual([caseBase + 8, caseBase + 20]);
  });

  it("subtracts when the chain ends in `sub`", () => {
    const rows = byteEntryChain.map((r) =>
      r[0] === "add" ? (["sub", "x8, x9, x8, lsl #2"] as [string, string]) : r,
    );
    // Only entries whose target stays in the image survive; 0x30 * 4 = 0xc0 is
    // below BASE, so the read stops there.
    expect(find(rows, imageWith([1, 2, 0x30, 4])).get(brAddr)).toEqual([TABLE - 4, TABLE - 8]);
  });

  /** The same chain, bounded to two cases. */
  const twoCases = (): [string, string][] =>
    byteEntryChain.map((r) => (r[0] === "cmp" ? (["cmp", "w1, #1"] as [string, string]) : r));

  it("reads signed entries as signed", () => {
    // 0xff is -1 under `ldrsb`, so case 0 sits one instruction *before* the base.
    const rows = twoCases().map((r) =>
      r[0] === "ldrb" ? (["ldrsb", "w8, [x9, w1, uxtw]"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([0xff, 1])).get(brAddr)).toEqual([TABLE - 4, TABLE + 4]);
  });

  it("reads unsigned entries as unsigned", () => {
    // The same byte under `ldrb` is 255, i.e. 0x3fc bytes forward.
    const img = imageWith([0xff, 1], 1, 0x1000);
    expect(findArm64JumpTables(stream(twoCases()), img, BASE).tables.get(brAddr)).toEqual([
      TABLE + 0x3fc,
      TABLE + 4,
    ]);
  });

  it("refuses a dispatch with nothing bounding its index", () => {
    // Something has to state how long the table is. With the compare removed
    // and nothing else writing the index, nothing does.
    const rows = byteEntryChain.filter((r) => r[0] !== "cmp");
    expect(find(rows, imageWith([1, 2, 3, 4]))).toEqual(new Map());
  });

  // peek-a-bin-mxw. The one real table among the 13 dead-end `br` blocks left
  // on each ARM64 binary: `memcmp`'s tail dispatch at 0x140001db0, identical in
  // t64-arm.exe and w64-arm.exe, whose index is the residue of a block loop
  // rather than a compared value.
  describe("a decrement loop bounds the index just as a compare does", () => {
    /** The 0x140001db0 shape, verbatim apart from the table address. */
    const loopChain = (): [string, string][] => [
      ["subs", "x2, x2, #8"],
      ["b.gt", `#0x${(BASE - 0x20).toString(16)}`],
      ["b.eq", `#0x${(BASE + 0x90).toString(16)}`],
      ["add", "x2, x2, #8"],
      ["adr", `x3, #0x${TABLE.toString(16)}`],
      ["ldrb", "w8, [x3, x2]"],
      ["sub", "x3, x3, x8, lsl #2"],
      ["br", "x3"],
    ];
    const loopBr = BASE + 7 * ARM64_INSN_SIZE;

    it("reads K entries, where K is the loop's stride", () => {
      // Entries are subtracted, so each is an offset back from the table.
      const img = imageWith([1, 2, 3, 4, 5, 6, 7, 8]);
      expect(find(loopChain(), img).get(loopBr)).toEqual([
        TABLE - 4,
        TABLE - 8,
        TABLE - 12,
        TABLE - 16,
        TABLE - 20,
        TABLE - 24,
        TABLE - 28,
        TABLE - 32,
      ]);
    });

    it("does not read past K, even where the next entry would resolve", () => {
      // The real table at 0x140001df0 continues for 17 entries — it is shared
      // with a second dispatch — and every one of them decodes to a plausible
      // address. An unbounded read there invents edges silently.
      const img = imageWith([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
      expect(find(loopChain(), img).get(loopBr)).toHaveLength(8);
    });

    it("refuses when the `add` and the `subs` disagree on the stride", () => {
      const rows = loopChain().map((r) =>
        r[0] === "add" ? (["add", "x2, x2, #4"] as [string, string]) : r,
      );
      expect(find(rows, imageWith([1, 2, 3, 4, 5, 6, 7, 8]))).toEqual(new Map());
    });

    it("refuses when nothing branches on the `subs`, so the residue is unbounded", () => {
      // Without the loop test, the value at the `subs` is not known to be
      // positive and the residue is not known to be small.
      const rows = loopChain().map((r) =>
        r[0] === "b.gt" ? (["nop", ""] as [string, string]) : r,
      );
      expect(find(rows, imageWith([1, 2, 3, 4, 5, 6, 7, 8]))).toEqual(new Map());
    });

    it("refuses a plain `sub`, which is not a loop test", () => {
      const rows = loopChain().map((r) =>
        r[0] === "subs" ? (["sub", "x2, x2, #8"] as [string, string]) : r,
      );
      expect(find(rows, imageWith([1, 2, 3, 4, 5, 6, 7, 8]))).toEqual(new Map());
    });

    it("refuses an `add` that is not the index plus a constant", () => {
      const rows = loopChain().map((r) =>
        r[0] === "add" ? (["add", "x2, x5, #8"] as [string, string]) : r,
      );
      expect(find(rows, imageWith([1, 2, 3, 4, 5, 6, 7, 8]))).toEqual(new Map());
    });
  });

  it("refuses a bounds check about a different register", () => {
    const rows = byteEntryChain.map((r) =>
      r[0] === "cmp" ? (["cmp", "w4, #3"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([1, 2, 3, 4]))).toEqual(new Map());
  });

  it("refuses when the index is rewritten between the compare and the load", () => {
    const rows: [string, string][] = [
      ["cmp", "w1, #3"],
      ["b.hi", `#0x${(BASE + 0x80).toString(16)}`],
      ["mov", "w1, w7"],
      ["adr", `x9, #0x${TABLE.toString(16)}`],
      ["ldrb", "w8, [x9, w1, uxtw]"],
      ["add", "x8, x9, x8, lsl #2"],
      ["br", "x8"],
    ];
    expect(findArm64JumpTables(stream(rows), imageWith([1, 2, 3, 4]), BASE).tables).toEqual(
      new Map(),
    );
  });

  it("refuses an `add` with no shift, whose entry unit is unstated", () => {
    const rows = byteEntryChain.map((r) =>
      r[0] === "add" ? (["add", "x8, x9, x8"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([1, 2, 3, 4]))).toEqual(new Map());
  });

  it("refuses a load whose index scale disagrees with its entry width", () => {
    // `[x9, w1, uxtw #2]` scales the index by 4; `ldrb` reads 1 byte. One of
    // the two is being misread, so neither is trusted.
    const rows = byteEntryChain.map((r) =>
      r[0] === "ldrb" ? (["ldrb", "w8, [x9, w1, uxtw #2]"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([1, 2, 3, 4]))).toEqual(new Map());
  });

  it("refuses a plain `ldr`, whose entry width the mnemonic does not state", () => {
    const rows = byteEntryChain.map((r) =>
      r[0] === "ldrb" ? (["ldr", "w8, [x9, w1, uxtw #2]"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([1, 2, 3, 4]))).toEqual(new Map());
  });

  it("refuses the run-time function-pointer dispatch, which has no table", () => {
    // `adrp`/`add`/`ldar xN, [x8]`/`br xN` — a pointer read from .data. Eight of
    // t64-arm.exe's twenty-seven `br`s are this, and none of them is a switch.
    const rows: [string, string][] = [
      ["adrp", "x8, #0x14001d000"],
      ["add", "x8, x8, #0x148"],
      ["ldar", "x9, [x8]"],
      ["br", "x9"],
    ];
    expect(findArm64JumpTables(stream(rows), imageWith([1, 2]), BASE).tables).toEqual(new Map());
  });

  it("refuses when the table register is rewritten between its `adr` and the load", () => {
    const rows: [string, string][] = [
      ["cmp", "w1, #3"],
      ["adr", `x9, #0x${TABLE.toString(16)}`],
      ["mov", "x9, x11"],
      ["ldrb", "w8, [x9, w1, uxtw]"],
      ["add", "x8, x9, x8, lsl #2"],
      ["br", "x8"],
    ];
    expect(findArm64JumpTables(stream(rows), imageWith([1, 2, 3, 4]), BASE).tables).toEqual(
      new Map(),
    );
  });

  it("stops at the first entry pointing outside the code section", () => {
    // 0x40 * 4 = 0x100 past a 0x100-byte image.
    expect(find(byteEntryChain, imageWith([1, 2, 0x40, 4])).get(brAddr)).toEqual([
      TABLE + 4,
      TABLE + 8,
    ]);
  });

  it("stops at an entry whose target is not 4-byte aligned", () => {
    // Every A64 instruction address is aligned, so an unaligned target is proof
    // the reading is wrong, not a case body in an odd place. `lsl #0` makes the
    // entries plain byte offsets, so a 3 lands off the grid.
    const rows = byteEntryChain.map((r) =>
      r[0] === "add" ? (["add", "x8, x9, x8, lsl #0"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([4, 8, 3, 12])).get(brAddr)).toEqual([TABLE + 4, TABLE + 8]);
  });

  it("does not report a one-entry table", () => {
    const rows = byteEntryChain.map((r) =>
      r[0] === "cmp" ? (["cmp", "w1, #0"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([1]))).toEqual(new Map());
  });

  it("ignores the pointer-authenticated branch forms", () => {
    const rows = byteEntryChain.map((r) =>
      r[0] === "br" ? (["braa", "x8, x17"] as [string, string]) : r,
    );
    expect(find(rows, imageWith([1, 2, 3, 4]))).toEqual(new Map());
  });

  it("does not let one dispatch's chain be read from a window before another", () => {
    // The walk is bounded to the instructions preceding the `br`, so a second
    // `br` further on with no chain of its own recovers nothing.
    const rows: [string, string][] = [...byteEntryChain, ["nop", ""], ["br", "x3"]];
    const tables = find(rows, imageWith([1, 2, 3, 4]));
    expect(tables.has(brAddr)).toBe(true);
    expect(tables.has(BASE + 7 * ARM64_INSN_SIZE)).toBe(false);
  });

  /**
   * peek-a-bin-gb40. The bytes a table was read out of, so the view can call
   * them data instead of decoding them.
   */
  describe("the spans it reports are the bytes it actually read", () => {
    const spansOf = (rows: [string, string][], img: Uint8Array) =>
      findArm64JumpTables(stream(rows), img, BASE).spans;

    it("reports one span per accepted table, sized by its entry width", () => {
      expect(spansOf(byteEntryChain, imageWith([1, 2, 3, 4]))).toEqual([[TABLE, TABLE + 4]]);
    });

    it("sizes a word-entry table by its own width, not by the word size", () => {
      const caseBase = BASE + 0x20;
      const rows: [string, string][] = [
        ["cmp", "w10, #1"],
        ["b.hi", `#0x${(BASE + 0x80).toString(16)}`],
        ["adr", `x9, #0x${TABLE.toString(16)}`],
        ["ldrsw", "x8, [x9, w10, uxtw #2]"],
        ["adr", `x9, #0x${caseBase.toString(16)}`],
        ["add", "x8, x9, x8, lsl #2"],
        ["br", "x8"],
      ];
      expect(spansOf(rows, imageWith([2, 5], 4))).toEqual([[TABLE, TABLE + 8]]);
    });

    /**
     * THE RULE THIS ROW EXISTS FOR. `readArm64Table` stops at the first entry
     * failing its range or alignment test, so the bound can claim more entries
     * than the table has. Reporting the claimed extent would hand the caller
     * bytes nothing has shown to be data, and `disassembleArm64` would then
     * withhold real instructions from the view — the direction this project
     * refuses in. Both corpus binaries read every table to its bound, so this
     * case does not occur there and only this test holds the rule.
     */
    it("reports the SHORT extent when the read stops before the bound", () => {
      // `cmp w1, #3` claims four entries; 0x40 * 4 lands past a 0x100 image, so
      // the third entry ends the read and only two bytes were ever a table.
      const img = imageWith([1, 2, 0x40, 4]);
      expect(find(byteEntryChain, img).get(brAddr)).toHaveLength(2);
      expect(spansOf(byteEntryChain, img)).toEqual([[TABLE, TABLE + 2]]);
    });

    it("claims no bytes for a dispatch it refuses", () => {
      // A one-entry read is not a table, so its byte is not table data either.
      const rows = byteEntryChain.map((r) =>
        r[0] === "cmp" ? (["cmp", "w1, #0"] as [string, string]) : r,
      );
      expect(spansOf(rows, imageWith([1]))).toEqual([]);
    });

    it("reports one span for two dispatches reading the same table the same way", () => {
      // A span is about the bytes, not about the `br` that reached them.
      const rows: [string, string][] = [...byteEntryChain, ...byteEntryChain];
      const found = findArm64JumpTables(stream(rows), imageWith([1, 2, 3, 4]), BASE);
      expect(found.tables.size).toBe(2);
      expect(found.spans).toEqual([[TABLE, TABLE + 4]]);
    });

    it("keeps both spans where two dispatches read the same base to different lengths", () => {
      // t64-arm.exe's 0x140001df0, read over 17 entries by one `br` and 8 by
      // another. Their union is the marked region either way.
      const shorter = byteEntryChain.map((r) =>
        r[0] === "cmp" ? (["cmp", "w1, #1"] as [string, string]) : r,
      );
      const found = findArm64JumpTables(
        stream([...byteEntryChain, ...shorter]),
        imageWith([1, 2, 3, 4]),
        BASE,
      );
      expect(found.spans).toEqual([
        [TABLE, TABLE + 4],
        [TABLE, TABLE + 2],
      ]);
    });
  });

  /**
   * peek-a-bin-mxw. `findArm64JumpTables` reports the same nothing for a `br`
   * with no static target and a `br` whose chain this reader cannot follow, and
   * those are not the same claim. This is where the difference is stated.
   */
  describe("classifyArm64Br says why a `br` has no table", () => {
    /** Instructions in address order, ending with the `br`, as the walk sees them. */
    const recent = (rows: [string, string][]) => stream(rows).slice(0, -1);

    it("calls a bounded dispatch chain a table", () => {
      const br = classifyArm64Br("x8", recent(byteEntryChain));
      expect(br.kind).toBe("table");
      if (br.kind === "table") {
        expect(br.dispatch.table).toBe(TABLE);
        expect(br.dispatch.count).toBe(4);
      }
    });

    it("calls a value loaded from a .data slot a run-time pointer, and names the slot", () => {
      // 0x14000ffc8 in t64-arm.exe, verbatim. The loader writes that slot; no
      // edge is the correct answer here, not a missing one.
      const rows: [string, string][] = [
        ["adrp", "x8, #0x14001d000"],
        ["add", "x8, x8, #0x218"],
        ["ldar", "x9, [x8]"],
        ["br", "x9"],
      ];
      expect(classifyArm64Br("x9", recent(rows))).toEqual({
        kind: "runtime-pointer",
        slot: 0x14001d218,
      });
    });

    it("adds the load's own displacement to the slot", () => {
      const rows: [string, string][] = [
        ["adrp", "x8, #0x14001d000"],
        ["add", "x8, x8, #0x200"],
        ["ldr", "x9, [x8, #0x2c0]"],
        ["br", "x9"],
      ];
      expect(classifyArm64Br("x9", recent(rows))).toEqual({
        kind: "runtime-pointer",
        slot: 0x14001d4c0,
      });
    });

    it("leaves the slot unresolved when the `adrp` half is missing", () => {
      const rows: [string, string][] = [
        ["add", "x8, x8, #0x218"],
        ["ldar", "x9, [x8]"],
        ["br", "x9"],
      ];
      // Still a run-time pointer, which is the part that matters: the value
      // came from memory, so no static target exists either way.
      expect(classifyArm64Br("x9", recent(rows))).toEqual({
        kind: "runtime-pointer",
        slot: null,
      });
    });

    it("still calls it a run-time pointer when the address cannot be resolved", () => {
      const rows: [string, string][] = [
        ["ldar", "x9, [x8]"],
        ["br", "x9"],
      ];
      expect(classifyArm64Br("x9", recent(rows))).toEqual({
        kind: "runtime-pointer",
        slot: null,
      });
    });

    it("calls a `br` with nothing in front of it unrecognised", () => {
      // The sweep's own artefact: `br x1` at 0x1400040e0 in t64-arm.exe follows
      // a `nop` and two words that do not decode, so there is no chain because
      // the bytes before it are not instructions.
      expect(
        classifyArm64Br(
          "x1",
          recent([
            ["nop", ""],
            ["br", "x1"],
          ]),
        ),
      ).toEqual({
        kind: "unrecognised",
      });
    });

    it("calls a branch through the zero register unrecognised", () => {
      expect(
        classifyArm64Br(
          "xzr",
          recent([
            ["nop", ""],
            ["br", "xzr"],
          ]),
        ),
      ).toEqual({
        kind: "unrecognised",
      });
    });
  });
});

/**
 * peek-a-bin-kis. Three RPCs sweep the same `.text` on every ARM64 file load —
 * `detectFunctions`, `hybridDisassemble` and `buildAllXrefs` — because each one
 * needs instructions and none can be handed the previous one's array across the
 * worker boundary (a per-element `bytes` view is the case `workers/transfer.ts`
 * exists to keep out of a message). Measured on t64-arm.exe before this cache:
 * 3 sweeps, 4083 `cs.disasm` calls, 2.44 MiB fed to Capstone three times.
 *
 * What makes it safe is that the key is the section's *bytes*. The two real
 * ARM64 binaries in the corpus both base `.text` at 0x140001000, so an
 * address-and-length key is not hypothetically unsound here, it is unsound on
 * the only two files there are.
 */
describe("Arm64SweepCache", () => {
  /** Distinct, decoder-irrelevant filler — the stub decodes on address, not
   *  content, but the cache compares content, so each section needs its own. */
  function section(bytes: number, fill: number): Uint8Array {
    return new Uint8Array(bytes).fill(fill);
  }

  it("decodes once and answers the second ask from memory", () => {
    const cs = fakeCs(code(8));
    const cache = new Arm64SweepCache();
    const bytes = section(32, 0x11);

    const first = cache.sweep(bytes, BASE, cs);
    const callsAfterFirst = cs.calls.length;
    const second = cache.sweep(bytes, BASE, cs);

    expect(first).toHaveLength(8);
    expect(second).toBe(first);
    expect(cs.calls.length).toBe(callsAfterFirst);
    expect(callsAfterFirst).toBeGreaterThan(0);
  });

  it("answers a byte-identical copy, not just the same array object", () => {
    // The worker never sees the caller's buffer twice: `prepareBinaryArgs`
    // hands each RPC its own private slice, so identity would never hit.
    const cs = fakeCs(code(8));
    const cache = new Arm64SweepCache();

    const first = cache.sweep(section(32, 0x11), BASE, cs);
    const callsAfterFirst = cs.calls.length;
    const second = cache.sweep(section(32, 0x11), BASE, cs);

    expect(second).toBe(first);
    expect(cs.calls.length).toBe(callsAfterFirst);
  });

  it("re-decodes when one byte differs, at the same address and length", () => {
    const cs = fakeCs(code(8));
    const cache = new Arm64SweepCache();
    const a = section(32, 0x11);
    const b = section(32, 0x11);
    b[31] ^= 0xff;

    cache.sweep(a, BASE, cs);
    const callsAfterFirst = cs.calls.length;
    cache.sweep(b, BASE, cs);

    expect(cs.calls.length).toBeGreaterThan(callsAfterFirst);
  });

  it("re-decodes when the same bytes load at a different address", () => {
    const cs = fakeCs(new Map([...code(8), ...code(8, 0x1000)]));
    const cache = new Arm64SweepCache();
    const bytes = section(32, 0x11);

    const first = cache.sweep(bytes, BASE, cs);
    const second = cache.sweep(bytes, BASE + 0x1000, cs);

    expect(second).not.toBe(first);
    expect(second[0].address).toBe(BASE + 0x1000);
  });

  it("re-decodes after clear()", () => {
    const cs = fakeCs(code(8));
    const cache = new Arm64SweepCache();
    const bytes = section(32, 0x11);

    cache.sweep(bytes, BASE, cs);
    const callsAfterFirst = cs.calls.length;
    cache.clear();
    cache.sweep(bytes, BASE, cs);

    expect(cs.calls.length).toBeGreaterThan(callsAfterFirst);
  });

  it("stores nothing when the section fails the decode-rate floor", () => {
    // The ARM64EC/ARM64X refusal must not become a cached empty answer: every
    // ask has to throw, not just the first one (peek-a-bin-2t1).
    const cs = fakeCs(code(1, 400));
    const cache = new Arm64SweepCache();
    const bytes = section(0x2000, 0x22);

    expect(() => cache.sweep(bytes, BASE, cs)).toThrow(Arm64DecodeRateError);
    expect(() => cache.sweep(bytes, BASE, cs)).toThrow(Arm64DecodeRateError);
  });

  it("caches the decode, never the decoration", () => {
    // The cached array is undecorated, and each caller re-annotates. Two
    // callers with different string maps must not see each other's comments.
    const cs = fakeCs(
      new Map([
        [BASE, { mnemonic: "adrp", opStr: "x0, #0x140002000" }],
        [BASE + 4, { mnemonic: "add", opStr: "x1, x0, #0x10" }],
      ]),
    );
    const cache = new Arm64SweepCache();
    const bytes = section(8, 0x33);

    const bare = disassembleArm64(bytes, BASE, ctx(cs), undefined, cache);
    const annotated = disassembleArm64(
      bytes,
      BASE,
      { cs, stringMap: new Map([[0x140002010, "hello"]]), iatMap: new Map(), driverMode: false },
      undefined,
      cache,
    );
    const bareAgain = disassembleArm64(bytes, BASE, ctx(cs), undefined, cache);

    expect(bare[1].comment).toBeUndefined();
    expect(annotated[1].comment).toBe("hello");
    expect(bareAgain[1].comment).toBeUndefined();
  });

  it("caches the decode, never the .pdata classification", () => {
    const cs = fakeCs(code(2));
    const cache = new Arm64SweepCache();
    const bytes = section(8, 0x44);
    const ranges = [{ beginAddress: BASE, endAddress: BASE + 4 }];

    const marked = disassembleArm64(bytes, BASE, ctx(cs), ranges, cache);
    const unmarked = disassembleArm64(bytes, BASE, ctx(cs), undefined, cache);

    expect(marked.map((i) => i.source)).toEqual(["recursive", "gap-fill"]);
    expect(unmarked.map((i) => i.source)).toEqual([undefined, undefined]);
  });

  it("gives disassembleArm64 the same answer with a cache as without one", () => {
    const words = new Map([
      [BASE, { mnemonic: "adrp", opStr: "x0, #0x140002000" }],
      [BASE + 4, { mnemonic: "bl", opStr: "#0x140001100" }],
    ]);
    const c = {
      cs: fakeCs(words),
      stringMap: new Map([[0x140002000, "s"]]),
      iatMap: new Map(),
      driverMode: false,
    };
    const ranges = [{ beginAddress: BASE, endAddress: BASE + 4 }];
    const bytes = section(8, 0x55);

    const withoutCache = disassembleArm64(bytes, BASE, c, ranges);
    const withCache = disassembleArm64(bytes, BASE, c, ranges, new Arm64SweepCache());

    expect(withCache).toEqual(withoutCache);
  });

  it("gives detectArm64Functions the same answer with a cache as without one", () => {
    const words = new Map([
      [BASE, { mnemonic: "bl", opStr: "#0x140001010" }],
      [BASE + 4, { mnemonic: "ret", opStr: "" }],
      [BASE + 16, { mnemonic: "ret", opStr: "" }],
    ]);
    const bytes = section(32, 0x66);
    const opts = { entryPoint: BASE };

    const withoutCache = detectArm64Functions(bytes, BASE, ctx(fakeCs(words)), opts);
    const withCache = detectArm64Functions(
      bytes,
      BASE,
      ctx(fakeCs(words)),
      opts,
      new Arm64SweepCache(),
    );

    expect(withCache).toEqual(withoutCache);
    expect(withCache.functions.map((f) => f.address)).toContain(BASE + 0x10);
  });

  it("still degrades detection rather than throwing when the floor is missed", () => {
    const bytes = section(0x2000, 0x77);

    const r = detectArm64Functions(
      bytes,
      BASE,
      ctx(fakeCs(code(1, 400))),
      { entryPoint: BASE },
      new Arm64SweepCache(),
    );

    expect(r.omitted).toEqual(["call-targets", "jump-tables"]);
    expect(r.functions.map((f) => f.address)).toEqual([BASE]);
  });
});

describe("sweepArm64 / decorateArm64Sweep", () => {
  it("sweeps undecorated and decorates without touching the raw array", () => {
    // The reference is the PAIR: `adrp` names the page, `add` completes it.
    // Annotating the `adrp` off its own operand is the defect peek-a-bin-vg3
    // fixed — see the "an A64 comment names a reference" block below.
    const cs = fakeCs(
      new Map([
        [BASE, { mnemonic: "adrp", opStr: "x0, #0x140002000" }],
        [BASE + 4, { mnemonic: "add", opStr: "x1, x0, #0x10" }],
      ]),
    );
    const raw = sweepArm64(new Uint8Array(8), BASE, cs);

    const decorated = decorateArm64Sweep(
      raw,
      { cs, stringMap: new Map([[0x140002010, "abc"]]), iatMap: new Map(), driverMode: false },
      [{ beginAddress: BASE, endAddress: BASE + 8 }],
    );

    expect(raw[1].comment).toBeUndefined();
    expect(raw[1].source).toBeUndefined();
    expect(decorated[1].comment).toBe("abc");
    expect(decorated[1].source).toBe("recursive");
    expect(decorated[1]).not.toBe(raw[1]);
  });

  it("throws the decode-rate error from the sweep, before any decoration", () => {
    expect(() => sweepArm64(new Uint8Array(0x2000), BASE, fakeCs(code(1, 400)))).toThrow(
      Arm64DecodeRateError,
    );
  });

  /**
   * peek-a-bin-gb40. A word the tool has already called a jump-table entry is
   * not an instruction, and this is where it stops being presented as one. The
   * decode is untouched — A64 has no gap fill, so the sweep read every word
   * either way — which is why this is a decoration-side filter and not a change
   * to {@link sweepArm64} or to what {@link Arm64SweepCache} holds.
   */
  describe("jump-table bytes are withheld from the decorated answer", () => {
    const cs = () => fakeCs(code(6));
    const addrs = (insns: Instruction[]) => insns.map((i) => i.address);

    it("changes nothing when no spans are supplied", () => {
      // "Nobody said where the tables are" is not "there are none".
      const raw = sweepArm64(new Uint8Array(24), BASE, cs());
      expect(addrs(decorateArm64Sweep(raw, ctx(null)))).toEqual(addrs([...raw]));
    });

    it("drops a word that lies inside a span", () => {
      const raw = sweepArm64(new Uint8Array(24), BASE, cs());
      const out = decorateArm64Sweep(raw, ctx(null), undefined, [[BASE + 8, BASE + 12]]);
      expect(addrs(out)).toEqual([BASE, BASE + 4, BASE + 12, BASE + 16, BASE + 20]);
    });

    /**
     * The real corpus shape: t64-arm.exe's table at 0x1400018b0 is 33 entries
     * of one byte, so it ends at 0x1400018d1 and its last word owns exactly one
     * table byte. Note this case does NOT need the interval test — the word's
     * own address is inside the span — so a point test passes it too. The case
     * that separates them is the next one.
     */
    it("drops a word that owns only the first byte of an unaligned span end", () => {
      const raw = sweepArm64(new Uint8Array(24), BASE, cs());
      const out = decorateArm64Sweep(raw, ctx(null), undefined, [[BASE + 4, BASE + 9]]);
      expect(addrs(out)).toEqual([BASE, BASE + 12, BASE + 16, BASE + 20]);
    });

    it("keeps the word that ends exactly where a span begins", () => {
      const raw = sweepArm64(new Uint8Array(24), BASE, cs());
      const out = decorateArm64Sweep(raw, ctx(null), undefined, [[BASE + 4, BASE + 8]]);
      expect(addrs(out)).toEqual([BASE, BASE + 8, BASE + 12, BASE + 16, BASE + 20]);
    });

    /**
     * THE CASE THAT MAKES THIS AN INTERVAL TEST, and the only one. A span whose
     * start is past the word's own address is invisible to a point test, so
     * that word would be kept although it holds table bytes. It does not occur
     * on either corpus binary — every table base there is 4-byte aligned, so
     * `npm run corpus:arm64` is green with a point test too (measured) — which
     * makes this test the only thing holding the rule.
     */
    it("drops a word a span sits strictly inside", () => {
      // Two one-byte entries at an unaligned base is the smallest table there
      // can be, and it fits between one word's boundaries.
      const raw = sweepArm64(new Uint8Array(24), BASE, cs());
      const out = decorateArm64Sweep(raw, ctx(null), undefined, [[BASE + 5, BASE + 7]]);
      expect(addrs(out)).toEqual([BASE, BASE + 8, BASE + 12, BASE + 16, BASE + 20]);
    });

    it("handles overlapping spans, which two dispatches sharing a table produce", () => {
      const raw = sweepArm64(new Uint8Array(24), BASE, cs());
      const out = decorateArm64Sweep(raw, ctx(null), undefined, [
        [BASE + 4, BASE + 16],
        [BASE + 4, BASE + 8],
      ]);
      expect(addrs(out)).toEqual([BASE, BASE + 16, BASE + 20]);
    });

    it("masks on the caller's spans while the cache still shares one decode", () => {
      // The masking is a fact about the caller, so a cached raw sweep must serve
      // a masked and an unmasked caller without either seeing the other's.
      const handle = cs();
      const cache = new Arm64SweepCache();
      const bytes = new Uint8Array(24);
      const masked = disassembleArm64(bytes, BASE, ctx(handle), undefined, cache, [
        [BASE + 8, BASE + 12],
      ]);
      const plain = disassembleArm64(bytes, BASE, ctx(handle), undefined, cache);
      expect(addrs(masked)).not.toContain(BASE + 8);
      expect(addrs(plain)).toContain(BASE + 8);
      expect(plain).toHaveLength(6);
      // One decode served both.
      expect(handle.calls).toHaveLength(1);
    });
  });
});

/**
 * peek-a-bin-vg3. `mapInsn`'s reference resolution is an x86 operand grammar:
 * `resolveRipTarget`, then any `0x…` literal in the operand string that is a
 * known string or IAT address. On A64 the first never fires and the second is
 * unsound — the only literals an A64 operand carries are branch targets and
 * `adrp` PAGE BASES, neither of which is a data reference. Measured on the two
 * real ARM64 binaries at 91085f3: 248 of t64-arm.exe's 248 comments and 253 of
 * w64-arm.exe's 253 were such coincidences, and 243/252 of them said the same
 * one wrong thing, because the IAT begins at a page boundary so every `adrp` at
 * that page matched the FIRST import in it.
 *
 * The right answer is `findArm64AddressRefs`, attributed — as `buildArm64Xrefs`
 * already does — to the instruction that COMPLETES the pair.
 */
describe("an A64 comment names a reference, not a collision", () => {
  /** Decode `rows` as consecutive words from BASE and decorate with `ctx`. */
  function decorate(
    rows: [string, string][],
    stringMap: Map<number, string>,
    iatMap: Map<number, { lib: string; func: string }>,
    driverMode = false,
  ): Instruction[] {
    const words = new Map<number, { mnemonic: string; opStr: string }>();
    rows.forEach(([mnemonic, opStr], i) => {
      words.set(BASE + i * ARM64_INSN_SIZE, { mnemonic, opStr });
    });
    const cs = fakeCs(words);
    const raw = sweepArm64(new Uint8Array(rows.length * ARM64_INSN_SIZE), BASE, cs);
    return decorateArm64Sweep(raw, { cs, stringMap, iatMap, driverMode });
  }

  const IAT = new Map([
    [0x14001d000, { lib: "KERNEL32.dll", func: "GetStartupInfoW" }],
    [0x14001d098, { lib: "KERNEL32.dll", func: "ExitProcess" }],
  ]);

  it("does not comment an adrp whose page base collides with an IAT entry", () => {
    // t64-arm.exe 0x140002048/0x14000204c, the shape behind 243 of its 248
    // comments: the page base IS the first IAT entry, and the paired `ldr`
    // loads a different import entirely.
    const insns = decorate(
      [
        ["adrp", "x8, #0x14001d000"],
        ["ldr", "x8, [x8, #0x98]"],
      ],
      new Map(),
      IAT,
    );
    expect(insns[0].comment).toBeUndefined();
    expect(insns[1].comment).toBe("KERNEL32.dll!ExitProcess");
  });

  it("comments the add that completes an adrp, not the adrp", () => {
    // t64-arm.exe 0x140002038/0x14000203c.
    const insns = decorate(
      [
        ["adrp", "x8, #0x140024000"],
        ["add", "x1, x8, #0x480"],
      ],
      new Map([[0x140024480, "Fatal error in launcher: %s"]]),
      new Map(),
    );
    expect(insns[0].comment).toBeUndefined();
    expect(insns[1].comment).toBe("Fatal error in launcher: %s");
  });

  it("comments the one-instruction adr form on the instruction itself", () => {
    const insns = decorate(
      [["adr", "x8, #0x1400018b0"]],
      new Map([[0x1400018b0, "hi"]]),
      new Map(),
    );
    expect(insns[0].comment).toBe("hi");
  });

  it("does not comment a branch whose target collides with a string address", () => {
    // `extractStrings` scans the code section too, so a `.text` address can be
    // in the string map. A branch target is still not a data reference.
    const insns = decorate(
      [
        ["b", "#0x140001210"],
        ["bl", "#0x140001210"],
        ["cbz", "x0, #0x140001210"],
      ],
      new Map([[0x140001210, "not a reference"]]),
      new Map(),
    );
    expect(insns.map((i) => i.comment)).toEqual([undefined, undefined, undefined]);
  });

  it("takes the string over the import when a target is in both maps", () => {
    // mapInsn's own precedence, preserved.
    const insns = decorate(
      [
        ["adrp", "x8, #0x140024000"],
        ["add", "x1, x8, #0x8"],
      ],
      new Map([[0x140024008, "the string"]]),
      new Map([[0x140024008, { lib: "A.dll", func: "B" }]]),
    );
    expect(insns[1].comment).toBe("the string");
  });

  it("elides a long string exactly as the x86 path does", () => {
    const long = "x".repeat(80);
    const insns = decorate(
      [
        ["adrp", "x8, #0x140024000"],
        ["add", "x1, x8, #0x8"],
      ],
      new Map([[0x140024008, long]]),
      new Map(),
    );
    expect(insns[1].comment).toBe(`${"x".repeat(57)}...`);
  });

  it("leaves the driver-mode IOCTL annotation alone, and a reference outranks it", () => {
    // The IOCTL comment is a shape test over immediates, not a reference
    // resolution, so it is unchanged on this architecture — but a resolved
    // reference still wins, exactly as a string or IAT hit did before.
    const ioctl = decorate([["mov", "w2, #0x22e004"]], new Map(), new Map(), true);
    expect(ioctl[0].comment).toMatch(/IOCTL|FILE_DEVICE|METHOD_/);

    const both = decorate(
      [
        ["adrp", "x8, #0x140024000"],
        ["add", "x1, x8, #0x22e004"],
      ],
      new Map([[0x140024000 + 0x22e004, "wins"]]),
      new Map(),
      true,
    );
    expect(both[1].comment).toBe("wins");
  });

  it("re-decorating one raw sweep with different maps does not leak comments", () => {
    const cs = fakeCs(
      new Map([
        [BASE, { mnemonic: "adrp", opStr: "x8, #0x140024000" }],
        [BASE + 4, { mnemonic: "add", opStr: "x1, x8, #0x8" }],
      ]),
    );
    const raw = sweepArm64(new Uint8Array(8), BASE, cs);
    const withMaps = decorateArm64Sweep(raw, {
      cs,
      stringMap: new Map([[0x140024008, "abc"]]),
      iatMap: new Map(),
      driverMode: false,
    });
    const without = decorateArm64Sweep(raw, ctx(cs));
    expect(withMaps[1].comment).toBe("abc");
    expect(without[1].comment).toBeUndefined();
    expect(raw[1].comment).toBeUndefined();
  });
});

describe("archForMachine", () => {
  it("selects ARM64 from the COFF machine type", () => {
    expect(archForMachine(IMAGE_FILE_MACHINE_ARM64)).toBe("arm64");
    expect(IMAGE_FILE_MACHINE_ARM64).toBe(0xaa64);
  });

  it.each([
    ["AMD64", IMAGE_FILE_MACHINE_AMD64],
    ["I386", IMAGE_FILE_MACHINE_I386],
  ])("selects x86 for %s", (_label, machine) => {
    expect(archForMachine(machine)).toBe("x86");
  });

  it("falls back to x86 for an unthreaded call site", () => {
    // undefined means "nobody said", which must keep the pre-ARM64 behaviour
    // rather than picking a decoder at random.
    expect(archForMachine(undefined)).toBe("x86");
  });

  /**
   * peek-a-bin-x7b. These used to answer `"x86"`, which is how an ARM32/Thumb
   * image came to be decoded as x86 and rendered as a full screen of plausible
   * instructions that were pure fiction. There is no coverage signal to catch
   * that by — an x86 linear sweep decodes essentially any byte string, unlike
   * the A64 decode rate `arm64.ts` refuses on — so the machine type has to be
   * the answer.
   */
  it.each([
    ["ARM (0x01C0)", 0x01c0],
    ["ARM Thumb (0x01C2)", 0x01c2],
    ["ARMNT / Thumb-2 (0x01C4)", 0x01c4],
    ["IA-64 (0x0200)", 0x0200],
    ["RISC-V 64 (0x5064)", 0x5064],
    ["MIPS R4000 (0x0166)", 0x0166],
  ])("reports %s as unsupported rather than as x86", (_label, machine) => {
    expect(archForMachine(machine)).toBe("unsupported");
    expect(isKnownMachine(machine)).toBe(false);
  });

  it("keeps isKnownMachine's separate answer for the three it knows", () => {
    expect(isKnownMachine(IMAGE_FILE_MACHINE_ARM64)).toBe(true);
    expect(isKnownMachine(IMAGE_FILE_MACHINE_AMD64)).toBe(true);
    expect(isKnownMachine(IMAGE_FILE_MACHINE_I386)).toBe(true);
    // Asked about a machine *value*, not about a caller's state, so `undefined`
    // is false here while `archForMachine(undefined)` is deliberately "x86".
    expect(isKnownMachine(undefined)).toBe(false);
  });

  it("builds a refusal that names the stage and the architecture", () => {
    const message = unsupportedOnArch("Decompilation", "arm64");

    expect(message).toContain("Decompilation");
    expect(message).toContain(ARCH_LABEL.arm64);
    expect(message).toContain("x86");
  });

  it("builds a refusal for an unnamed architecture that says what is supported", () => {
    const message = unsupportedArchMessage("Disassembly");

    expect(message).toContain("Disassembly");
    // Cannot name the architecture — recognising it is exactly what did not
    // happen — so it names what a user can do something with instead.
    expect(message).toContain("x86");
    expect(message).toContain("ARM64");
    // And says the parse itself is unaffected, because it is.
    expect(message).toMatch(/imports/);
  });

  it("routes unsupportedOnArch's third state to that message, so an arch !== 'x86' check covers it", () => {
    // `src/mcp/tools.ts` refuses to decompile on `af.arch !== "x86"` and passes
    // `af.arch` straight through. Widening the parameter is what makes that
    // existing line cover ARM32 without an edit — and stops it claiming to have
    // recognised an architecture it did not.
    expect(unsupportedOnArch("Decompilation", "unsupported")).toBe(
      unsupportedArchMessage("Decompilation"),
    );
    expect(unsupportedOnArch("Decompilation", "unsupported")).not.toContain("ARM64 images");
  });
});
