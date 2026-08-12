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
  ARM64_DECODE_WINDOW,
  ARM64_INSN_SIZE,
  type Arm64Context,
  detectArm64Functions,
  disassembleArm64,
  findArm64JumpTables,
} from "../arm64";
import type { Instruction } from "../types";
import {
  ARCH_LABEL,
  IMAGE_FILE_MACHINE_AMD64,
  IMAGE_FILE_MACHINE_ARM64,
  IMAGE_FILE_MACHINE_I386,
  archForMachine,
  isKnownMachine,
  unsupportedOnArch,
} from "../arch";
import { CS_ARCH_ARM64, CapstoneUnavailableError } from "../capstoneWindow";

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

    disassembleArm64(new Uint8Array(0x2000), BASE, ctx(cs));

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

  it("finds nothing at all in an image with no recorded starts and no calls", () => {
    // Notably it does NOT fall back to a prologue byte scan — that is the x86
    // heuristic this module exists to avoid running on ARM64 bytes.
    const { functions } = detectArm64Functions(new Uint8Array(64), BASE, ctx(fakeCs(code(16))));

    expect(functions).toEqual([]);
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

  const find = (rows: [string, string][], img: Uint8Array) =>
    findArm64JumpTables(stream(rows), img, BASE);

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
    const tables = findArm64JumpTables(stream(rows), imageWith([2, 5], 4), BASE);
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
    expect(findArm64JumpTables(stream(twoCases()), img, BASE).get(brAddr)).toEqual([
      TABLE + 0x3fc,
      TABLE + 4,
    ]);
  });

  it("refuses a dispatch with no bounds check", () => {
    // The compare is the only statement of how long the table is. t64-arm.exe
    // has one of these, where the index is bounded by `subs`/`add` instead.
    const rows = byteEntryChain.filter((r) => r[0] !== "cmp");
    expect(find(rows, imageWith([1, 2, 3, 4]))).toEqual(new Map());
  });

  it("refuses a bounds check about a different register", () => {
    const rows = byteEntryChain.map((r) => (r[0] === "cmp" ? (["cmp", "w4, #3"] as [string, string]) : r));
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
    expect(findArm64JumpTables(stream(rows), imageWith([1, 2, 3, 4]), BASE)).toEqual(new Map());
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
    expect(findArm64JumpTables(stream(rows), imageWith([1, 2]), BASE)).toEqual(new Map());
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
    expect(findArm64JumpTables(stream(rows), imageWith([1, 2, 3, 4]), BASE)).toEqual(new Map());
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
    const rows = byteEntryChain.map((r) => (r[0] === "cmp" ? (["cmp", "w1, #0"] as [string, string]) : r));
    expect(find(rows, imageWith([1]))).toEqual(new Map());
  });

  it("ignores the pointer-authenticated branch forms", () => {
    const rows = byteEntryChain.map((r) => (r[0] === "br" ? (["braa", "x8, x17"] as [string, string]) : r));
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

  it("falls back to x86 for a machine type with no disassembler here", () => {
    expect(archForMachine(0x0200)).toBe("x86"); // IA-64
    expect(isKnownMachine(0x0200)).toBe(false);
    expect(isKnownMachine(IMAGE_FILE_MACHINE_ARM64)).toBe(true);
    expect(isKnownMachine(undefined)).toBe(false);
  });

  it("builds a refusal that names the stage and the architecture", () => {
    const message = unsupportedOnArch("Decompilation", "arm64");

    expect(message).toContain("Decompilation");
    expect(message).toContain(ARCH_LABEL.arm64);
    expect(message).toContain("x86");
  });
});
