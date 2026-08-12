/**
 * The bound on what the Capstone WASM decoder is handed (peek-a-bin-6a5).
 *
 * Capstone is faked, and the fake's whole point is that it *has limits* — a
 * maximum window and a maximum instruction count, past which it dies and stays
 * dead. That is the real engine's shape: its linear memory is a fixed 16 MiB
 * that cannot grow, the input is copied onto a ~65.6 KiB WASM stack, and
 * `cs_disasm` allocates one contiguous `cs_insn[]` for the whole window.
 * Measured limits are in `../capstoneWindow.ts`; the numbers here are those,
 * rounded to the boundary each one was measured at.
 *
 * The defect these guard against is not a crash. A decoder that has died throws
 * on every call, and a scan loop that reads a throw as "this byte is not code,
 * skip one" turns that into an empty result and no error — a `.text` that is
 * 97% missing, presented as a complete disassembly.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { describe, expect, it } from "vitest";
import {
  CapstoneUnavailableError,
  CS_ARCH_ARM64,
  CS_MAX_INSNS_PER_CALL,
  CS_WINDOW_BYTES,
  capstoneDecodes,
  createScan,
} from "../capstoneWindow";
import { type DisasmContext, disassemble, hybridDisassemble } from "../functionDetect";

const BASE = 0x140001000;

interface Call {
  length: number;
  address: number;
  count?: number;
}

/**
 * A decoder with the real engine's failure modes.
 *
 * Every byte decodes as a one-byte `nop`, which is the worst-case density and
 * the one that actually triggers the heap ceiling in the field (`00 00` is
 * `add byte ptr [rax], al` — two bytes — so a run of zeros inside a code
 * section is already within a factor of two of this).
 *
 * Exceeding either limit kills it permanently, exactly as the WASM module dies:
 * every later call throws, including the liveness probe.
 */
function limitedCs(limits: { maxWindow: number; maxInsns: number }) {
  const calls: Call[] = [];
  const state = { dead: false };
  return {
    calls,
    state,
    disasm(bytes: Uint8Array, options?: { address?: number; count?: number }) {
      calls.push({ length: bytes.length, address: options?.address ?? 0, count: options?.count });
      if (state.dead) throw new Error("Failed to disassemble, error: OK (CS_ERR_OK)");
      if (bytes.length > limits.maxWindow) {
        state.dead = true;
        throw new Error("table index is out of bounds");
      }
      const want = Math.min(bytes.length, options?.count ?? Number.POSITIVE_INFINITY);
      if (want > limits.maxInsns) {
        state.dead = true;
        throw new Error("Aborted(OOM). Build with -sASSERTIONS for more info.");
      }
      const out = [];
      for (let i = 0; i < want; i++) {
        out.push({
          address: (options?.address ?? 0) + i,
          bytes: bytes.subarray(i, i + 1),
          mnemonic: "nop",
          opStr: "",
          size: 1,
        });
      }
      return out;
    },
  };
}

/** A decoder that answers `n` calls and then nothing at all, ever. */
function diesAfter(n: number) {
  let seen = 0;
  return {
    disasm(bytes: Uint8Array, options?: { address?: number; count?: number }) {
      if (++seen > n) throw new Error("Failed to disassemble, error: OK (CS_ERR_OK)");
      const want = Math.min(bytes.length, options?.count ?? Number.POSITIVE_INFINITY);
      const out = [];
      for (let i = 0; i < want; i++) {
        out.push({
          address: (options?.address ?? 0) + i,
          bytes: bytes.subarray(i, i + 1),
          mnemonic: "nop",
          opStr: "",
          size: 1,
        });
      }
      return out;
    },
  };
}

/** A decoder that only ever decodes the one-byte `nop` the probe sends. */
const nopOnly = {
  disasm(bytes: Uint8Array, options?: { address?: number }) {
    if (bytes.length === 1 && bytes[0] === 0x90) {
      return [{ address: options?.address ?? 0, bytes, mnemonic: "nop", opStr: "", size: 1 }];
    }
    throw new Error("Failed to disassemble, error: OK (CS_ERR_OK)");
  },
};

function ctxOf(cs: unknown): DisasmContext {
  return { cs32: cs, cs64: cs, stringMap: new Map(), iatMap: new Map(), driverMode: false };
}

describe("createScan — the window is a bound, not a suggestion", () => {
  it("never hands the decoder more than CS_WINDOW_BYTES", () => {
    const cs = limitedCs({ maxWindow: 0x10000, maxInsns: 0x10000 });
    const scan = createScan(cs, "test");

    scan.decode(new Uint8Array(0x100000), 0, 0x100000, BASE);

    expect(cs.calls[0].length).toBe(CS_WINDOW_BYTES);
  });

  it("caps the instruction count as a second, density-independent bound", () => {
    const cs = limitedCs({ maxWindow: 0x10000, maxInsns: 0x10000 });

    createScan(cs, "test").decode(new Uint8Array(0x100000), 0, 0x100000, BASE);

    expect(cs.calls[0].count).toBe(CS_MAX_INSNS_PER_CALL);
  });

  it("honours a narrower window but refuses a wider one", () => {
    const cs = limitedCs({ maxWindow: 0x10000, maxInsns: 0x10000 });
    const buf = new Uint8Array(0x100000);

    createScan(cs, "test", 0x400).decode(buf, 0, buf.length, BASE);
    createScan(cs, "test", 0x40000).decode(buf, 0, buf.length, BASE);

    expect(cs.calls[0].length).toBe(0x400);
    expect(cs.calls[1].length).toBe(CS_WINDOW_BYTES);
  });

  it("stops at the caller's limit when that is nearer than the window", () => {
    const cs = limitedCs({ maxWindow: 0x10000, maxInsns: 0x10000 });

    createScan(cs, "test").decode(new Uint8Array(0x100000), 0x40, 0x44, BASE);

    expect(cs.calls[0].length).toBe(4);
  });

  it("asks for exactly one instruction on the decodeOne path", () => {
    const cs = limitedCs({ maxWindow: 0x10000, maxInsns: 0x10000 });

    const insns = createScan(cs, "test").decodeOne(new Uint8Array(64), 0, 15, BASE);

    expect(cs.calls[0].count).toBe(1);
    expect(insns).toHaveLength(1);
  });
});

describe("createScan — an undecodable byte is not a dead engine", () => {
  it("returns nothing, without complaint, for bytes that do not decode", () => {
    // A `.text` full of alignment padding and literal data produces these by
    // the thousand. Treating one as an engine failure would refuse every real
    // image.
    expect(createScan(nopOnly, "test").decode(new Uint8Array([0x00]), 0, 1, BASE)).toEqual([]);
  });

  it("survives a long run of undecodable bytes while the engine still answers", () => {
    const scan = createScan(nopOnly, "test");
    const data = new Uint8Array(4096); // no 0x90 anywhere

    for (let i = 0; i < data.length; i++) {
      expect(scan.decode(data, i, i + 1, BASE + i)).toEqual([]);
    }
  });
});

describe("capstoneDecodes", () => {
  it("says no for a missing handle", () => {
    expect(capstoneDecodes(null)).toBe(false);
    expect(capstoneDecodes(undefined)).toBe(false);
  });

  it("says yes when the handle still decodes a nop", () => {
    expect(capstoneDecodes(nopOnly)).toBe(true);
  });

  it("says no when every call throws", () => {
    expect(capstoneDecodes(diesAfter(0))).toBe(false);
  });

  it("sends a 4-byte A64 nop to an ARM64 handle, not the x86 one", () => {
    const seen: number[] = [];
    const arm = {
      arch: CS_ARCH_ARM64,
      disasm(bytes: Uint8Array) {
        seen.push(bytes.length);
        return [{ address: 0, bytes, mnemonic: "nop", opStr: "", size: 4 }];
      },
    };

    expect(capstoneDecodes(arm)).toBe(true);
    expect(seen).toEqual([4]);
  });
});

describe("a decoder that stops decoding is reported, not absorbed", () => {
  it("throws from the scan once the engine fails a liveness probe", () => {
    const scan = createScan(diesAfter(0), "test scan");
    const data = new Uint8Array(4096);

    expect(() => {
      for (let i = 0; i < data.length; i++) scan.decode(data, i, i + 1, BASE + i);
    }).toThrow(CapstoneUnavailableError);
  });

  it("names the caller, so the message says which stage stopped", () => {
    const scan = createScan(diesAfter(0), "hybrid disassembly");
    const data = new Uint8Array(4096);

    expect(() => {
      for (let i = 0; i < data.length; i++) scan.decode(data, i, i + 1, BASE + i);
    }).toThrow(/hybrid disassembly/);
  });

  it("makes `disassemble` reject rather than return a short list", () => {
    // Four windows decode, then the engine dies. The old shape returned the
    // instructions it had and said nothing at all about the rest of the image.
    expect(() => disassemble(new Uint8Array(0x10000), BASE, true, ctxOf(diesAfter(4)))).toThrow(
      CapstoneUnavailableError,
    );
  });
});

describe("a decoder with the real engine's limits decodes the whole section", () => {
  // Measured against the shipped capstone.wasm: a 65536-byte window works and a
  // 66560-byte one kills the module; 22528 instructions in one call work and
  // 23552 abort with OOM. See ../capstoneWindow.ts.
  const REAL_LIMITS = { maxWindow: 65600, maxInsns: 22528 };

  it("linear disassembly of a section far larger than one window", () => {
    const cs = limitedCs(REAL_LIMITS);
    const bytes = new Uint8Array(0x30000); // 196608 one-byte instructions

    const insns = disassemble(bytes, BASE, true, ctxOf(cs));

    expect(cs.state.dead).toBe(false);
    expect(insns).toHaveLength(bytes.length);
  });

  it("hybrid disassembly of the same section", () => {
    const cs = limitedCs(REAL_LIMITS);
    const bytes = new Uint8Array(0x30000);

    const insns = hybridDisassemble(bytes, BASE, true, [BASE], ctxOf(cs));

    expect(cs.state.dead).toBe(false);
    expect(insns).toHaveLength(bytes.length);
  });

  it("a .pdata range spanning the whole section, which used to be one call", () => {
    // `.pdata` is attacker-controlled: a single RUNTIME_FUNCTION claiming a
    // multi-megabyte extent was a one-call way over both ceilings.
    const cs = limitedCs(REAL_LIMITS);
    const bytes = new Uint8Array(0x30000);

    const insns = hybridDisassemble(bytes, BASE, true, [], ctxOf(cs), [
      { beginAddress: BASE, endAddress: BASE + bytes.length },
    ]);

    expect(cs.state.dead).toBe(false);
    expect(insns).toHaveLength(bytes.length);
    expect(cs.calls.every((c) => c.length <= CS_WINDOW_BYTES)).toBe(true);
  });
});

describe("no unwindowed decode survives anywhere in src/", () => {
  /** Every `.ts`/`.tsx` under `src/`, except this module and the tests. */
  function sources(dir: string, out: string[] = []): string[] {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (e.name !== "__tests__") sources(p, out);
      } else if (/\.tsx?$/.test(e.name) && e.name !== "capstoneWindow.ts") {
        out.push(p);
      }
    }
    return out;
  }

  it("routes every cs.disasm through createScan", () => {
    // The bound is only a bound if nothing goes around it. A new scan loop
    // written the old way — `cs.disasm(chunk)` inside `try { } catch { offset++ }`
    // — reintroduces the whole defect, decodes correctly on every binary small
    // enough to test with, and fails silently on the first large one.
    const offenders = sources(path.join(process.cwd(), "src"))
      .filter((f) => /\.disasm\s*\(/.test(fs.readFileSync(f, "utf8")))
      .map((f) => path.relative(process.cwd(), f));

    expect(offenders).toEqual([]);
  });

  it("keeps the window under both of the decoder's measured ceilings", () => {
    // ~65.6 KiB of WASM stack; ~22528 instructions of WASM heap. Anything at or
    // near either one is a decoder that dies on some real image.
    expect(CS_WINDOW_BYTES).toBeLessThanOrEqual(0x8000);
    expect(CS_MAX_INSNS_PER_CALL).toBeLessThanOrEqual(8192);
    expect(CS_WINDOW_BYTES).toBeGreaterThan(0);
  });
});
