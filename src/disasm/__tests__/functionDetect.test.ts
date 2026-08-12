import { describe, expect, it } from "vitest";
import { CapstoneUnavailableError } from "../capstoneWindow";
import { buildCFG } from "../cfg";
import {
  buildAllXrefs,
  buildTypedXrefMap,
  type DisasmContext,
  detectFunctions,
  disassemble,
  hybridDisassemble,
  mapInsn,
} from "../functionDetect";
import type { Instruction } from "../types";

const BASE = 0x401000;

function ctxOf(over: Partial<DisasmContext> = {}): DisasmContext {
  return {
    cs32: null,
    cs64: null,
    stringMap: new Map(),
    iatMap: new Map(),
    driverMode: false,
    ...over,
  };
}

/** Raw capstone-shaped instruction, as `mapInsn` receives it. */
function raw(mnemonic: string, opStr: string, address = BASE, size = 5) {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(size) };
}

// ── A minimal stand-in for the Capstone WASM decoder ──
// Encodings: E8=call rel32, E9=jmp rel32, EB=jmp rel8, 74=je rel8, 77=ja rel8,
// C3=ret, 90=nop, CC=int3, 83 /7 ii=cmp r32 imm8, FF 24 C5 dd=jmp
// [rax*8+disp32], FF 25 dd=jmp [rip+disp32], 00=undecodable (stops the chunk),
// plus the x86-64 switch idiom: 48 8D /r (rip)=lea r64, 48 63 /r=movsxd,
// 8B /r=mov r32, 0F B6 /r=movzx r32, 48 01 /r=add r64, 48 89 /r=mov r64,
// FF E0+r=jmp r64. Real encodings throughout, printed the way Capstone prints
// them — the detector parses these strings, so a fake that spelled them
// differently would test nothing.
function readI32(b: Uint8Array, i: number): number {
  return b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24) | 0;
}
const hex = (n: number) => `0x${(n >>> 0).toString(16)}`;
/**
 * An immediate the way Capstone prints one: decimal below ten, hex above.
 *
 * Verified against the shipped decoder on t32.exe — `6a 07` comes back as
 * `push 7` and `83 f9 08` as `cmp ecx, 8`, while `83 e0 0f` is `and eax, 0xf`.
 * Both spellings have to be read, so a fake that emitted only one would leave
 * half of the immediate parsing in `functionDetect.ts` untested.
 */
const imm = (n: number) => (n < 10 ? String(n) : hex(n));
const R64 = ["rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi"];
const R32 = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"];
const R8 = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"];
/** Capstone's spelling of a signed displacement inside a memory operand. */
const sdisp = (v: number) => (v < 0 ? `- 0x${(-v).toString(16)}` : `+ 0x${v.toString(16)}`);

/**
 * `[base + index*scale]` with an optional displacement, from a ModRM/SIB pair.
 * Returns null for anything that is not a mod=00/mod=10 SIB form.
 */
function memOperand(b: Uint8Array, i: number): { text: string; size: number } | null {
  const modrm = b[i];
  const mod = modrm >> 6;
  if ((modrm & 7) !== 4 || (mod !== 0 && mod !== 2)) return null;
  const sib = b[i + 1];
  const scale = 1 << (sib >> 6);
  const index = R64[(sib >> 3) & 7];
  const base = R64[sib & 7];
  const disp = mod === 2 ? readI32(b, i + 2) : 0;
  const tail = mod === 2 ? ` ${sdisp(disp)}` : "";
  // Capstone leaves a scale of 1 out — `42 0f b6 84 09 00 10 00 00` prints as
  // `byte ptr [rcx + r9 + 0x1000]`, verified against the shipped capstone.wasm.
  // A fake that wrote `*1` would be testing a spelling no decoder produces.
  const scaleText = scale === 1 ? "" : `*${scale}`;
  return { text: `[${base} + ${index}${scaleText}${tail}]`, size: mod === 2 ? 6 : 2 };
}

interface FakeInsn {
  address: number;
  mnemonic: string;
  opStr: string;
  size: number;
  bytes: Uint8Array;
}

function fakeCs() {
  return {
    disasm(bytes: Uint8Array, opts: { address: number }): FakeInsn[] {
      const out: FakeInsn[] = [];
      let i = 0;
      const emit = (mnemonic: string, opStr: string, size: number) => {
        out.push({
          address: opts.address + i,
          mnemonic,
          opStr,
          size,
          bytes: bytes.slice(i, i + size),
        });
        i += size;
      };
      while (i < bytes.length) {
        const b = bytes[i];
        const here = opts.address + i;
        if (b === 0x00) break; // undecodable
        if (b === 0xe8 && i + 4 < bytes.length) {
          emit("call", hex(here + 5 + readI32(bytes, i + 1)), 5);
          continue;
        }
        if (b === 0xe9 && i + 4 < bytes.length) {
          emit("jmp", hex(here + 5 + readI32(bytes, i + 1)), 5);
          continue;
        }
        if (b === 0xeb && i + 1 < bytes.length) {
          emit("jmp", hex(here + 2 + ((bytes[i + 1] << 24) >> 24)), 2);
          continue;
        }
        if (b === 0x74 && i + 1 < bytes.length) {
          emit("je", hex(here + 2 + ((bytes[i + 1] << 24) >> 24)), 2);
          continue;
        }
        if (b === 0xc3) {
          emit("ret", "", 1);
          continue;
        }
        if (b === 0x90) {
          emit("nop", "", 1);
          continue;
        }
        if (b === 0xcc) {
          emit("int3", "", 1);
          continue;
        }
        if (b === 0x83 && (bytes[i + 1] & 0xf8) === 0xf8 && i + 2 < bytes.length) {
          emit("cmp", `${R32[bytes[i + 1] & 7]}, ${hex(bytes[i + 2])}`, 3);
          continue;
        }
        if (b === 0x81 && (bytes[i + 1] & 0xf8) === 0xf8 && i + 5 < bytes.length) {
          emit("cmp", `${R32[bytes[i + 1] & 7]}, ${hex(readI32(bytes, i + 2))}`, 6);
          continue;
        }
        if (b === 0x77 && i + 1 < bytes.length) {
          emit("ja", hex(here + 2 + ((bytes[i + 1] << 24) >> 24)), 2);
          continue;
        }
        if (b === 0x3b && bytes[i + 1] >= 0xc0) {
          emit("cmp", `${R32[(bytes[i + 1] >> 3) & 7]}, ${R32[bytes[i + 1] & 7]}`, 2);
          continue;
        }
        if (b === 0x6a && i + 1 < bytes.length) {
          emit("push", imm(bytes[i + 1]), 2);
          continue;
        }
        if (b >= 0x58 && b <= 0x5f) {
          emit("pop", R32[b & 7], 1);
          continue;
        }
        if (b >= 0xb8 && b <= 0xbf && i + 4 < bytes.length) {
          emit("mov", `${R32[b & 7]}, ${imm(readI32(bytes, i + 1))}`, 5);
          continue;
        }
        if (b === 0x83 && (bytes[i + 1] & 0xf8) === 0xc0 && i + 2 < bytes.length) {
          emit("add", `${R32[bytes[i + 1] & 7]}, ${imm(bytes[i + 2])}`, 3);
          continue;
        }
        if (b === 0x89 && bytes[i + 1] >= 0xc0) {
          emit("mov", `${R32[bytes[i + 1] & 7]}, ${R32[(bytes[i + 1] >> 3) & 7]}`, 2);
          continue;
        }
        if (
          b === 0x48 &&
          bytes[i + 1] === 0x8d &&
          (bytes[i + 2] & 0xc7) === 0x05 &&
          i + 6 < bytes.length
        ) {
          emit("lea", `${R64[(bytes[i + 2] >> 3) & 7]}, [rip ${sdisp(readI32(bytes, i + 3))}]`, 7);
          continue;
        }
        if (b === 0x48 && bytes[i + 1] === 0x63) {
          const mem = memOperand(bytes, i + 2);
          if (mem && i + 1 + mem.size < bytes.length) {
            emit("movsxd", `${R64[(bytes[i + 2] >> 3) & 7]}, dword ptr ${mem.text}`, 2 + mem.size);
            continue;
          }
        }
        if (b === 0x8b) {
          const mem = memOperand(bytes, i + 1);
          if (mem && i + mem.size < bytes.length) {
            emit("mov", `${R32[(bytes[i + 1] >> 3) & 7]}, dword ptr ${mem.text}`, 1 + mem.size);
            continue;
          }
        }
        if (b === 0x8a) {
          const mem = memOperand(bytes, i + 1);
          if (mem && i + mem.size < bytes.length) {
            emit("mov", `${R8[(bytes[i + 1] >> 3) & 7]}, byte ptr ${mem.text}`, 1 + mem.size);
            continue;
          }
        }
        if (b === 0x0f && bytes[i + 1] === 0xb6) {
          const mem = memOperand(bytes, i + 2);
          if (mem && i + 1 + mem.size < bytes.length) {
            emit("movzx", `${R32[(bytes[i + 2] >> 3) & 7]}, byte ptr ${mem.text}`, 2 + mem.size);
            continue;
          }
        }
        if (
          b === 0x48 &&
          (bytes[i + 1] === 0x01 || bytes[i + 1] === 0x89) &&
          bytes[i + 2] >= 0xc0
        ) {
          const modrm = bytes[i + 2];
          emit(
            bytes[i + 1] === 0x01 ? "add" : "mov",
            `${R64[modrm & 7]}, ${R64[(modrm >> 3) & 7]}`,
            3,
          );
          continue;
        }
        if (b === 0xff && bytes[i + 1] >= 0xe0 && bytes[i + 1] <= 0xe7 && i + 1 < bytes.length) {
          emit("jmp", R64[bytes[i + 1] & 7], 2);
          continue;
        }
        if (b === 0xff && bytes[i + 1] === 0x24 && bytes[i + 2] === 0xc5 && i + 6 < bytes.length) {
          emit("jmp", `qword ptr [rax*8 + ${hex(readI32(bytes, i + 3))}]`, 7);
          continue;
        }
        if (b === 0xff && bytes[i + 1] === 0x25 && i + 5 < bytes.length) {
          emit("jmp", `qword ptr [rip + ${hex(readI32(bytes, i + 2))}]`, 6);
          continue;
        }
        emit("nop", "", 1);
      }
      return out;
    },
  };
}

/** Assemble a byte buffer from fragments placed at explicit offsets. */
function image(len: number, parts: Record<number, number[]>): Uint8Array {
  const out = new Uint8Array(len);
  for (const [off, bytes] of Object.entries(parts)) out.set(bytes, Number(off));
  return out;
}

/** `call` to an absolute address from `at`. */
const callTo = (at: number, target: number) => {
  const rel = target - (BASE + at + 5);
  return [0xe8, rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >> 24) & 0xff];
};
const jmpTo = (at: number, target: number) => {
  const rel = target - (BASE + at + 5);
  return [0xe9, rel & 0xff, (rel >> 8) & 0xff, (rel >> 16) & 0xff, (rel >> 24) & 0xff];
};
const le32 = (v: number) => [v & 0xff, (v >> 8) & 0xff, (v >> 16) & 0xff, (v >>> 24) & 0xff];

describe("mapInsn", () => {
  it("copies the capstone fields verbatim", () => {
    expect(mapInsn(raw("mov", "eax, ecx", 0x401000, 2), new Map(), new Map(), false)).toEqual({
      address: 0x401000,
      mnemonic: "mov",
      opStr: "eax, ecx",
      size: 2,
      bytes: new Uint8Array(2),
    });
  });

  it("adds no comment when no maps are supplied", () => {
    expect(
      mapInsn(raw("lea", "rax, [rip + 0x10]"), new Map(), new Map(), false).comment,
    ).toBeUndefined();
  });

  it("annotates a rip-relative string reference", () => {
    const target = 0x401000 + 5 + 0x100;
    const strings = new Map([[target, "hello world"]]);
    expect(mapInsn(raw("lea", "rax, [rip + 0x100]"), strings, new Map(), false).comment).toBe(
      "hello world",
    );
  });

  it("resolves a negative rip displacement", () => {
    const target = 0x401000 + 5 - 0x100;
    const strings = new Map([[target, "backwards"]]);
    expect(mapInsn(raw("lea", "rax, [rip - 0x100]"), strings, new Map(), false).comment).toBe(
      "backwards",
    );
  });

  it("annotates an absolute string address in the operand", () => {
    const strings = new Map([[0x404000, "literal"]]);
    expect(mapInsn(raw("push", "0x404000"), strings, new Map(), false).comment).toBe("literal");
  });

  it("truncates a long string comment to 60 characters", () => {
    const long = "x".repeat(100);
    const comment = mapInsn(raw("push", "0x404000"), new Map([[0x404000, long]]), new Map(), false)
      .comment!;
    expect(comment).toHaveLength(60);
    expect(comment.endsWith("...")).toBe(true);
  });

  it("keeps a string of exactly 60 characters intact", () => {
    const exact = "y".repeat(60);
    expect(
      mapInsn(raw("push", "0x404000"), new Map([[0x404000, exact]]), new Map(), false).comment,
    ).toBe(exact);
  });

  it("takes the first matching address when several appear", () => {
    const strings = new Map([
      [0x404000, "first"],
      [0x405000, "second"],
    ]);
    expect(
      mapInsn(raw("mov", "qword ptr [0x404000], 0x405000"), strings, new Map(), false).comment,
    ).toBe("first");
  });

  it("annotates an import through a rip-relative reference", () => {
    const target = 0x401000 + 5 + 0x200;
    const iat = new Map([[target, { lib: "kernel32.dll", func: "ExitProcess" }]]);
    expect(mapInsn(raw("call", "qword ptr [rip + 0x200]"), new Map(), iat, false).comment).toBe(
      "kernel32.dll!ExitProcess",
    );
  });

  it("annotates an import at an absolute address", () => {
    const iat = new Map([[0x403000, { lib: "user32.dll", func: "MessageBoxW" }]]);
    expect(mapInsn(raw("call", "dword ptr [0x403000]"), new Map(), iat, false).comment).toBe(
      "user32.dll!MessageBoxW",
    );
  });

  it("prefers a string comment over an import comment", () => {
    const strings = new Map([[0x403000, "str"]]);
    const iat = new Map([[0x403000, { lib: "a.dll", func: "f" }]]);
    expect(mapInsn(raw("push", "0x403000"), strings, iat, false).comment).toBe("str");
  });

  it("annotates a plausible IOCTL only in driver mode", () => {
    const ioctl = 0x22e004; // FILE_DEVICE_UNKNOWN, METHOD_BUFFERED
    expect(
      mapInsn(raw("cmp", `eax, 0x${ioctl.toString(16)}`), new Map(), new Map(), false).comment,
    ).toBeUndefined();
    const withDriver = mapInsn(
      raw("cmp", `eax, 0x${ioctl.toString(16)}`),
      new Map(),
      new Map(),
      true,
    );
    expect(withDriver.comment).toBeTruthy();
  });

  it("does not annotate an implausible IOCTL value", () => {
    expect(mapInsn(raw("cmp", "eax, 0x1"), new Map(), new Map(), true).comment).toBeUndefined();
  });
});

describe("detectFunctions — seeds", () => {
  const empty = new Uint8Array(0x100);

  it("returns no functions for an empty image", () => {
    expect(detectFunctions(new Uint8Array(0), BASE, true, ctxOf()).functions).toEqual([]);
  });

  it("names the entry point", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), { entryPoint: BASE + 0x20 });
    expect(functions).toEqual([{ name: "entry_point", address: BASE + 0x20, size: 0x100 - 0x20 }]);
  });

  it("names exported functions", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      exports: [{ name: "DriverEntry", address: BASE + 0x10 }],
    });
    expect(functions[0].name).toBe("DriverEntry");
  });

  it("lets an export name override the entry point name at the same address", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      entryPoint: BASE,
      exports: [{ name: "Start", address: BASE }],
    });
    expect(functions[0].name).toBe("Start");
  });

  it("ignores seeds outside the image", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      entryPoint: BASE - 1,
      exports: [{ name: "Far", address: BASE + 0x1000 }],
      handlerAddresses: [0],
    });
    expect(functions).toEqual([]);
  });

  it("seeds and sizes functions from .pdata", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      pdataFunctions: [{ beginAddress: BASE + 0x10, endAddress: BASE + 0x40 }],
    });
    expect(functions).toEqual([
      { name: `sub_${(BASE + 0x10).toString(16).toUpperCase()}`, address: BASE + 0x10, size: 0x30 },
    ]);
  });

  it("names exception handlers", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      handlerAddresses: [BASE + 0x30],
    });
    expect(functions[0].name).toBe(`__handler_${(BASE + 0x30).toString(16)}`);
  });

  it("sizes each function up to the next one", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      exports: [
        { name: "a", address: BASE },
        { name: "b", address: BASE + 0x40 },
      ],
    });
    expect(functions.map((f) => [f.name, f.size])).toEqual([
      ["a", 0x40],
      ["b", 0xc0],
    ]);
  });

  it("sorts functions by address", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      exports: [
        { name: "b", address: BASE + 0x40 },
        { name: "a", address: BASE },
      ],
    });
    expect(functions.map((f) => f.name)).toEqual(["a", "b"]);
  });

  it("lets a .pdata end address win over the next-function heuristic", () => {
    const { functions } = detectFunctions(empty, BASE, true, ctxOf(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 0x10 }],
      exports: [{ name: "b", address: BASE + 0x80 }],
    });
    expect(functions[0].size).toBe(0x10);
  });
});

describe("detectFunctions — prologue scanning", () => {
  const at = (offset: number, bytes: number[], len = 0x40) =>
    detectFunctions(image(len, { [offset]: bytes }), BASE, true, ctxOf()).functions.map(
      (f) => f.address,
    );
  const at32 = (offset: number, bytes: number[], len = 0x40) =>
    detectFunctions(image(len, { [offset]: bytes }), BASE, false, ctxOf()).functions.map(
      (f) => f.address,
    );

  it("recognises the x64 frame-pointer prologue", () => {
    expect(at(0x10, [0x55, 0x48, 0x89, 0xe5])).toContain(BASE + 0x10);
  });

  it("recognises `sub rsp, imm8` and `sub rsp, imm32`", () => {
    expect(at(0x10, [0x48, 0x83, 0xec, 0x28])).toContain(BASE + 0x10);
    expect(at(0x10, [0x48, 0x81, 0xec, 0x88, 0x00, 0x00, 0x00])).toContain(BASE + 0x10);
  });

  it("recognises push rbx / push rdi+rsi / rex-prefixed prologues", () => {
    expect(at(0x10, [0x53, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x57, 0x56, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x40, 0x53, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x40, 0x57, 0x48, 0x83, 0xec])).toContain(BASE + 0x10);
    expect(at(0x10, [0x40, 0x55, 0x48, 0x8d, 0x6c, 0x24])).toContain(BASE + 0x10);
  });

  it("recognises the home-space register spill", () => {
    expect(at(0x10, [0x48, 0x89, 0x4c, 0x24, 0x08])).toContain(BASE + 0x10);
  });

  it("requires a boundary before an ambiguous `mov [rsp+x], rbx` spill", () => {
    // 0x11 is neither 16-aligned nor preceded by padding.
    const unaligned = image(0x40, { 0x11: [0x48, 0x89, 0x5c, 0x24, 0x08] });
    unaligned[0x10] = 0x41; // not padding
    expect(detectFunctions(unaligned, BASE, true, ctxOf()).functions).toEqual([]);
    // Preceded by int3 padding it is accepted.
    expect(at(0x11, [0xcc, 0x48, 0x89, 0x5c, 0x24, 0x08])).toContain(BASE + 0x12);
  });

  it("accepts an ambiguous prologue at a 16-byte boundary", () => {
    const img = image(0x40, { 0x20: [0x48, 0x8b, 0xc4] });
    img[0x1f] = 0x41;
    expect(detectFunctions(img, BASE, true, ctxOf()).functions.map((f) => f.address)).toContain(
      BASE + 0x20,
    );
  });

  it("recognises the x86 frame-pointer prologues", () => {
    expect(at32(0x10, [0x55, 0x8b, 0xec])).toContain(BASE + 0x10);
    expect(at32(0x10, [0x55, 0x89, 0xe5])).toContain(BASE + 0x10);
    expect(at32(0x10, [0x8b, 0xff, 0x55, 0x8b, 0xec])).toContain(BASE + 0x10);
  });

  it("does not use x64 prologues in 32-bit mode", () => {
    expect(at32(0x10, [0x48, 0x83, 0xec, 0x28])).not.toContain(BASE + 0x10);
  });

  it("does not use x86 prologues in 64-bit mode", () => {
    expect(at(0x10, [0x55, 0x8b, 0xec])).not.toContain(BASE + 0x10);
  });

  it("starts a function after alignment padding", () => {
    const img = image(0x40, { 0x00: [0x90, 0xcc, 0xcc, 0xcc], 0x04: [0x41, 0x41] });
    expect(detectFunctions(img, BASE, true, ctxOf()).functions.map((f) => f.address)).toContain(
      BASE + 4,
    );
  });

  it("ignores padding followed by zero bytes", () => {
    const img = image(0x40, { 0x00: [0xcc, 0xcc] });
    expect(detectFunctions(img, BASE, true, ctxOf()).functions).toEqual([]);
  });

  it("ignores padding that does not reach the minimum run length", () => {
    // A single 0xCC needs a run of 2; a lone 0x90 needs 3.
    const oneInt3 = image(0x40, { 0x00: [0xcc, 0x41] });
    expect(detectFunctions(oneInt3, BASE, true, ctxOf()).functions).toEqual([]);
    const twoNops = image(0x40, { 0x00: [0x90, 0x90, 0x41] });
    expect(detectFunctions(twoNops, BASE, true, ctxOf()).functions).toEqual([]);
  });

  it("requires the post-padding address to be 4-byte aligned", () => {
    const img = image(0x40, { 0x00: [0x41, 0xcc, 0xcc, 0x41] });
    expect(detectFunctions(img, BASE, true, ctxOf()).functions).toEqual([]);
  });

  it("deduplicates a prologue that is also a seed", () => {
    const img = image(0x40, { 0x00: [0x55, 0x48, 0x89, 0xe5] });
    const { functions } = detectFunctions(img, BASE, true, ctxOf(), { entryPoint: BASE });
    expect(functions).toHaveLength(1);
    expect(functions[0].name).toBe("entry_point");
  });
});

/**
 * peek-a-bin-abv. The prologue table's entries are prefixes of one another, so
 * more than one fires on the same function and the extra hits land a byte or two
 * past the real entry. A PE32 image has no `.pdata` to arbitrate, which is why
 * this showed up there first: on t32.exe 154 of 447 "functions" were a 2-byte
 * `mov edi, edi` with the real body filed under a second entry 2 bytes in, and
 * all 154 decompiled to an empty body.
 */
describe("detectFunctions — a prologue inside a prologue is one function", () => {
  const addrs32 = (img: Uint8Array, options?: Parameters<typeof detectFunctions>[4]) =>
    detectFunctions(img, BASE, false, ctxOf(), options).functions;
  const addrs64 = (img: Uint8Array) =>
    detectFunctions(img, BASE, true, ctxOf()).functions.map((f) => f.address);

  it("reports the MSVC hot-patch prologue once, at the `mov edi, edi`", () => {
    // 8b ff 55 8b ec — `mov edi, edi; push ebp; mov ebp, esp`. The plain
    // `55 8b ec` rule matches two bytes in and used to add a second start.
    const img = image(0x40, { 0x10: [0x8b, 0xff, 0x55, 0x8b, 0xec, 0x5d, 0xc3] });
    const fns = addrs32(img);
    expect(fns.map((f) => f.address)).toEqual([BASE + 0x10]);
    expect(fns[0].size).toBeGreaterThan(2);
  });

  it("still reports a bare `push ebp; mov ebp, esp` with nothing in front of it", () => {
    // The other direction: suppression must be about being inside a *match*,
    // not about the bytes at -2 being anything in particular.
    const img = image(0x40, { 0x10: [0x55, 0x8b, 0xec] });
    expect(addrs32(img).map((f) => f.address)).toEqual([BASE + 0x10]);
  });

  it("reports only the outermost x64 prologue when three rules overlap", () => {
    // 40 53 48 83 ec matches at 0x10; 53 48 83 ec at 0x11; 48 83 ec at 0x12.
    const img = image(0x40, { 0x10: [0x40, 0x53, 0x48, 0x83, 0xec, 0x28] });
    expect(addrs64(img)).toEqual([BASE + 0x10]);
  });

  it("reports only the outermost of `57 56 48 83 ec`", () => {
    const img = image(0x40, { 0x10: [0x57, 0x56, 0x48, 0x83, 0xec, 0x28] });
    expect(addrs64(img)).toEqual([BASE + 0x10]);
  });

  it("keeps two adjacent prologues that do not overlap", () => {
    const img = image(0x40, { 0x10: [0x55, 0x48, 0x89, 0xe5], 0x14: [0x55, 0x48, 0x89, 0xe5] });
    expect(addrs64(img)).toEqual([BASE + 0x10, BASE + 0x14]);
  });

  it("keeps an interior address a call reaches, because that is not a guess", () => {
    // A hot-patched function whose +2 entry is genuinely called: the call is
    // evidence of an entry point, so it is in `addrSet` before any pattern is
    // admitted and no suppression can touch it.
    const img = image(0x40, {
      0x00: callTo(0x00, BASE + 0x12),
      0x10: [0x8b, 0xff, 0x55, 0x8b, 0xec],
    });
    const fns = detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() })).functions;
    expect(fns.map((f) => f.address)).toContain(BASE + 0x12);
    expect(fns.map((f) => f.address)).toContain(BASE + 0x10);
  });

  it("keeps a small leaf thunk that no prologue rule matches", () => {
    // t32.exe's one surviving <=4-byte function: `call eax; ret`, reached only
    // by a direct call. Nothing about this fix may cost it.
    const img = image(0x40, { 0x00: callTo(0x00, BASE + 0x20), 0x20: [0xff, 0xd0, 0xc3] });
    const fns = detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() })).functions;
    expect(fns.map((f) => f.address)).toContain(BASE + 0x20);
  });

  it("lets the padding heuristic be ruled out but rule nothing out", () => {
    // A padding candidate matches no prologue bytes, so a prologue starting one
    // byte after it is still a start.
    const img = image(0x40, { 0x02: [0xcc, 0xcc], 0x04: [0x41], 0x05: [0x55, 0x48, 0x89, 0xe5] });
    expect(addrs64(img)).toEqual([BASE + 4, BASE + 5]);
  });
});

describe("detectFunctions — a start the function before it jumps over (peek-a-bin-g7yp)", () => {
  // MSVC's x86 `__finally` funclet is emitted *inside* its parent: the parent
  // `call`s it, it ends in `ret`, and the parent's own body resumes on the next
  // byte. Every rule this detector has makes it a function start, and sizes are
  // "distance to the next start", so it used to cut its parent in half — and a
  // truncated parent loses every `jcc` aiming past its new end, because buildCFG
  // draws no edge to a target outside the range it was given.
  //
  // `t32!sub_4031A4` is the measured case: 0x403276 is `push 0xa; call _unlock;
  // pop ecx; ret`, called from 0x403249, with the parent continuing at 0x40327F
  // and four `jcc`s aiming there or later. All four tests vanished from the
  // emitted C and the loop around them came out as `while (1)`.
  //
  //   0x00  je   0x401014   ; crosses the funclet, lands back in the parent
  //   0x02  call 0x401010   ; the funclet
  //   0x10  ...  ret        ; the funclet, ending here
  //   0x14  ...  ret        ; the parent resumes
  //   0x16  cc cc           ; padding — 0x18 is the next real function
  const FUNCLET = 0x10;
  const RESUME = 0x14;
  const NEXT = 0x18;
  /** 0x40 decodes as a one-byte filler and is not padding, so it starts nothing. */
  const filled = (len: number, parts: Record<number, number[]>): Uint8Array => {
    const out = new Uint8Array(len).fill(0x40);
    for (const [off, bytes] of Object.entries(parts)) out.set(bytes, Number(off));
    return out;
  };
  const parent = {
    0x00: [0x74, RESUME - 0x02], // je BASE+0x14
    0x02: callTo(0x02, BASE + FUNCLET),
    [FUNCLET]: [0x40, 0xc3],
    [RESUME]: [0x40, 0xc3],
    0x16: [0xcc, 0xcc],
    [NEXT]: [0x40, 0xc3],
  };
  const detect = (img: Uint8Array) =>
    detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() }), { entryPoint: BASE }).functions;

  it("withdraws it, so the parent keeps the code past it", () => {
    const funcs = detect(filled(0x20, parent));
    expect(funcs.map((f) => f.address)).toEqual([BASE, BASE + NEXT]);
    expect(funcs[0].size).toBe(NEXT);
  });

  it("still ends the parent where the next real function starts", () => {
    // The negative half of the same assertion: withdrawing a start must not run
    // the parent on into a function that is genuinely separate.
    const funcs = detect(filled(0x20, parent));
    expect(funcs[1].address).toBe(BASE + NEXT);
    expect(funcs[0].address + funcs[0].size).toBe(funcs[1].address);
  });

  it("gives the crossing jcc both of its successors", () => {
    // The end of the chain: with the parent sized right, buildCFG has a block at
    // the branch target and the test survives into the graph.
    const img = filled(0x20, parent);
    const ctx = ctxOf({ cs32: fakeCs() });
    const { functions } = detectFunctions(img, BASE, false, ctx, { entryPoint: BASE });
    const insns = hybridDisassemble(img, BASE, false, [BASE], ctx);
    const blocks = buildCFG(functions[0], insns, new Map());
    const branch = blocks.find((b) => b.insns.some((i) => i.mnemonic === "je"));
    expect(branch).toBeDefined();
    expect(branch?.succs.map((s) => blocks[s].startAddr).sort((a, b) => a - b)).toEqual([
      BASE + 0x02,
      BASE + RESUME,
    ]);
  });

  it("keeps a start that something outside the previous function calls", () => {
    // `t32!sub_40A925`: a second entry point sharing a tail with the code in
    // front of it, called from 0x4043CE and 0x404471 as well as from its
    // neighbour. One caller from outside is enough to make it a function, and a
    // helper laid out right after its only caller must survive too.
    const img = filled(0x28, { ...parent, [NEXT]: callTo(NEXT, BASE + FUNCLET), 0x1d: [0xc3] });
    const funcs = detect(img);
    expect(funcs.map((f) => f.address)).toEqual([BASE, BASE + FUNCLET, BASE + NEXT]);
    expect(funcs[0].size).toBe(FUNCLET);
  });

  it("ignores a crossing jcc the function cannot reach", () => {
    // `.text` carries data. t32.exe holds eight absolute case addresses at
    // 0x4086a4, right after `sub_407ABC`'s final `ret`, and a linear decode
    // turns them into `jle 0x4086e7 / jl 0x4086ef / jl 0x4086f3 / jge 0x4086f7 /
    // jge 0x4086fb / jle 0x408703` — six conditional jumps straddling the next
    // function's start that the program cannot execute. Suppressing on those
    // would swallow a real 288-byte function (w32.exe has the same table with
    // the same effect, in front of `sub_408014`).
    //
    //   0x00  ret            ; the function really ends here
    //   0x02  74 10          ; data, decoding as `je 0x401014`
    //   0x04  cc cc cc cc    ; padding — 0x08 is the next function
    const img = filled(0x20, {
      0x00: [0x40, 0xc3],
      0x02: [0x74, 0x10],
      0x04: [0xcc, 0xcc, 0xcc, 0xcc],
    });
    expect(detect(img).map((f) => f.address)).toEqual([BASE, BASE + 0x08]);
  });
});

describe("detectFunctions — .pdata outranks the pattern scan", () => {
  const RANGE = [{ beginAddress: BASE, endAddress: BASE + 0x40 }];
  const addrs = (img: Uint8Array, options: Parameters<typeof detectFunctions>[4], ctx = ctxOf()) =>
    detectFunctions(img, BASE, true, ctx, options).functions.map((f) => f.address);

  it("drops a prologue match inside a .pdata function", () => {
    const img = image(0x100, { 0x20: [0x48, 0x83, 0xec, 0x28] });
    expect(addrs(img, { pdataFunctions: RANGE })).toEqual([BASE]);
  });

  it("keeps that same prologue match when the image has no .pdata", () => {
    const img = image(0x100, { 0x20: [0x48, 0x83, 0xec, 0x28] });
    expect(addrs(img, {})).toContain(BASE + 0x20);
  });

  it("keeps a prologue match outside every .pdata range", () => {
    const img = image(0x100, { 0x50: [0x48, 0x83, 0xec, 0x28] });
    expect(addrs(img, { pdataFunctions: RANGE })).toContain(BASE + 0x50);
  });

  it("keeps a prologue match at a .pdata function's first byte", () => {
    const img = image(0x100, { 0x00: [0x48, 0x83, 0xec, 0x28] });
    expect(addrs(img, { pdataFunctions: RANGE })).toEqual([BASE]);
  });

  it("keeps a prologue match at the byte a .pdata range ends on", () => {
    // endAddress is exclusive, so the first byte after a function is fair game.
    const img = image(0x100, { 0x40: [0x48, 0x83, 0xec, 0x28] });
    expect(addrs(img, { pdataFunctions: RANGE })).toContain(BASE + 0x40);
  });

  it("drops a post-padding start inside a .pdata function", () => {
    const img = image(0x100, { 0x20: [0xcc, 0xcc, 0xcc, 0xcc, 0x41, 0x41] });
    expect(addrs(img, { pdataFunctions: RANGE })).toEqual([BASE]);
  });

  it("keeps a call target inside a .pdata function", () => {
    // A direct call is evidence about an entry point in its own right; only the
    // byte-pattern guesses are what .pdata overrides.
    const img = image(0x100, { 0x00: callTo(0x00, BASE + 0x20) });
    expect(addrs(img, { pdataFunctions: RANGE }, ctxOf({ cs64: fakeCs() }))).toContain(BASE + 0x20);
  });

  it("keeps an exported symbol inside a .pdata function", () => {
    const img = image(0x100, {});
    expect(
      addrs(img, { pdataFunctions: RANGE, exports: [{ name: "mid", address: BASE + 0x20 }] }),
    ).toContain(BASE + 0x20);
  });

  it("keeps an exception handler inside a .pdata function", () => {
    const img = image(0x100, {});
    expect(addrs(img, { pdataFunctions: RANGE, handlerAddresses: [BASE + 0x20] })).toContain(
      BASE + 0x20,
    );
  });

  it("suppresses only inside the ranges it was given", () => {
    const img = image(0x100, {
      0x20: [0x48, 0x83, 0xec, 0x28],
      0x60: [0x48, 0x83, 0xec, 0x28],
      0xa0: [0x48, 0x83, 0xec, 0x28],
    });
    expect(
      addrs(img, {
        pdataFunctions: [
          { beginAddress: BASE + 0x80, endAddress: BASE + 0xc0 },
          { beginAddress: BASE, endAddress: BASE + 0x40 },
        ],
      }),
    ).toEqual([BASE, BASE + 0x60, BASE + 0x80]);
  });
});

describe("detectFunctions — jump-table targets are case labels, not functions", () => {
  // A 32-bit image whose only function starts at BASE, bounds-checks eax and
  // dispatches through a table at 0x20 to three case bodies at 0x40/0x44/0x48.
  // Each case body is `nop; ret` so the decoder has something real to land on.
  const TABLE = 0x20;
  const CASES = [0x40, 0x44, 0x48];
  const LEN = 0x60;
  const cs32 = () => ctxOf({ cs32: fakeCs() });
  const switcher = (extra: Record<number, number[]> = {}) =>
    image(LEN, {
      0x00: [0x83, 0xf8, 0x02], // cmp eax, 2
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + TABLE)], // jmp [eax*4 + table]
      [TABLE]: [...le32(BASE + CASES[0]), ...le32(BASE + CASES[1]), ...le32(BASE + CASES[2])],
      [CASES[0]]: [0x90, 0xc3],
      [CASES[1]]: [0x90, 0xc3],
      [CASES[2]]: [0x90, 0xc3],
      ...extra,
    });
  const detect = (img: Uint8Array, options: Parameters<typeof detectFunctions>[4] = {}) =>
    detectFunctions(img, BASE, false, cs32(), { entryPoint: BASE, ...options });

  it("does not start a function at a case target", () => {
    const { functions } = detect(switcher());
    expect(functions.map((f) => f.address)).toEqual([BASE]);
  });

  it("still reports the table itself", () => {
    // The suppression is about `addrSet`; jump-table *detection* is untouched.
    const { jumpTables } = detect(switcher());
    expect(jumpTables).toEqual([[BASE + 3, CASES.map((c) => BASE + c)]]);
  });

  it("leaves the dispatching function long enough to contain its case bodies", () => {
    // The bug this pins: sizing runs to the next entry of the same set the case
    // targets were being added to, so the function stopped at its first case.
    const { functions } = detect(switcher());
    expect(functions[0].size).toBe(LEN);
    expect(functions[0].address + functions[0].size).toBeGreaterThan(BASE + CASES[2]);
  });

  it("keeps a case target that a direct call also reaches", () => {
    // A call is evidence about an entry point in its own right. Something that
    // is both called and dispatched to really is a function, and stays one.
    const { functions } = detect(switcher({ 0x0a: callTo(0x0a, BASE + CASES[1]) }));
    expect(functions.map((f) => f.address)).toContain(BASE + CASES[1]);
  });

  it("keeps a case target that is also an export", () => {
    const { functions } = detect(switcher(), {
      exports: [{ name: "shared", address: BASE + CASES[1] }],
    });
    expect(functions.map((f) => f.address)).toContain(BASE + CASES[1]);
  });

  it("keeps a case target that is also an exception handler", () => {
    const { functions } = detect(switcher(), { handlerAddresses: [BASE + CASES[1]] });
    expect(functions.map((f) => f.address)).toContain(BASE + CASES[1]);
  });

  it("drops a prologue match sitting on a case target", () => {
    // Case bodies routinely start with something prologue-shaped, and the
    // byte-pattern scan cannot tell a case label from an entry point.
    const { functions } = detect(switcher({ [CASES[1]]: [0x55, 0x8b, 0xec] }));
    expect(functions.map((f) => f.address)).toEqual([BASE]);
  });

  it("keeps the same prologue match one byte off a case target", () => {
    const { functions } = detect(switcher({ [CASES[1] + 1]: [0x55, 0x8b, 0xec] }));
    expect(functions.map((f) => f.address)).toContain(BASE + CASES[1] + 1);
  });

  it("composes with the .pdata suppression", () => {
    // 64-bit, so the table entries are 8 bytes wide. Three prologue matches:
    // one inside a .pdata function, one on a case target, one on neither.
    const le64 = (v: number) => [...le32(v), 0, 0, 0, 0];
    const PROLOGUE = [0x48, 0x83, 0xec, 0x28]; // sub rsp, 0x28
    const img = image(0x120, {
      0x00: [0x83, 0xf8, 0x01], // cmp eax, 1
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + 0x100)],
      0x20: PROLOGUE, // inside .pdata → dropped
      0x60: PROLOGUE, // case target → dropped
      0xa0: PROLOGUE, // neither → kept
      0x100: [...le64(BASE + 0x60), ...le64(BASE + 0x80)],
    });
    const { functions, jumpTables } = detectFunctions(img, BASE, true, ctxOf({ cs64: fakeCs() }), {
      entryPoint: BASE,
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 0x40 }],
    });
    expect(jumpTables[0][1]).toEqual([BASE + 0x60, BASE + 0x80]);
    expect(functions.map((f) => f.address)).toEqual([BASE, BASE + 0xa0]);
  });
});

// ── A bound the dispatch compares against a register (peek-a-bin-mk42) ──
// MSVC spells a small bound `push 7` / `pop ecx` and then compares against the
// register, which is two bytes cheaper than `cmp eax, 7`. Reading only the
// immediate form refused three of t32.exe's tables and one of w32.exe's, and a
// table that is not recovered is also a table whose bytes nothing knows to be
// data — see the span tests below.
describe("detectFunctions — a bound compared against a register", () => {
  const TABLE = 0x20;
  const CASES = [0x40, 0x44, 0x48];
  const LEN = 0x60;
  /** `jmp dword ptr [eax*4 + <table>]`, the 32-bit dispatch, 7 bytes. */
  const dispatch = [0xff, 0x24, 0xc5, ...le32(BASE + TABLE)];
  const bodies = {
    [TABLE]: [...le32(BASE + CASES[0]), ...le32(BASE + CASES[1]), ...le32(BASE + CASES[2])],
    [CASES[0]]: [0x90, 0xc3],
    [CASES[1]]: [0x90, 0xc3],
    [CASES[2]]: [0x90, 0xc3],
  };
  const detect32 = (img: Uint8Array) =>
    detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() }), { entryPoint: BASE });
  /** `push N; pop ecx; cmp eax, ecx; jmp [eax*4 + table]` at the image start. */
  const pushPop = (bound: number, extra: Record<number, number[]> = {}) =>
    image(LEN, {
      0x00: [0x6a, bound], // push N
      0x02: [0x59], // pop ecx
      0x03: [0x3b, 0xc1], // cmp eax, ecx
      0x05: dispatch,
      ...bodies,
      ...extra,
    });

  it("recovers a table bounded by push/pop into a register", () => {
    expect(detect32(pushPop(2)).jumpTables).toEqual([[BASE + 5, CASES.map((c) => BASE + c)]]);
  });

  it("recovers a table bounded by `mov ecx, N`", () => {
    const img = image(LEN, {
      0x00: [0xb9, ...le32(2)], // mov ecx, 2
      0x05: [0x3b, 0xc1], // cmp eax, ecx
      0x07: dispatch,
      ...bodies,
    });
    expect(detect32(img).jumpTables).toEqual([[BASE + 7, CASES.map((c) => BASE + c)]]);
  });

  it("stops at the first entry that is not in the code window", () => {
    // The bound claims eight cases and only three entries resolve. The count is
    // an upper bound on the read, never the length of the answer.
    expect(detect32(pushPop(7)).jumpTables[0][1]).toEqual(CASES.map((c) => BASE + c));
  });

  it("refuses when the stack moved between the push and the pop", () => {
    // `add esp, 4` after the push means the popped value is not the pushed one.
    const img = image(LEN, {
      0x00: [0x6a, 0x02],
      0x02: [0x83, 0xc4, 0x04], // add esp, 4
      0x05: [0x59],
      0x06: [0x3b, 0xc1],
      0x08: dispatch,
      ...bodies,
    });
    expect(detect32(img).jumpTables).toEqual([]);
  });

  it("refuses when a call sits between the constant and the compare", () => {
    const img = image(LEN, {
      0x00: [0x6a, 0x02],
      0x02: [0x59],
      0x03: callTo(0x03, BASE + CASES[0]),
      0x08: [0x3b, 0xc1],
      0x0a: dispatch,
      ...bodies,
    });
    expect(detect32(img).jumpTables).toEqual([]);
  });

  it("refuses a register that holds a copy of another register", () => {
    // `mov ecx, edx` states nothing about a length, and following it further
    // would be guessing at a value the instruction stream does not carry.
    const img = image(LEN, {
      0x00: [0x89, 0xd1], // mov ecx, edx
      0x02: [0x3b, 0xc1],
      0x04: dispatch,
      ...bodies,
    });
    expect(detect32(img).jumpTables).toEqual([]);
  });

  it("applies the case ceiling to a register-carried bound", () => {
    const img = image(LEN, {
      0x00: [0xb9, ...le32(0x1000)], // mov ecx, 0x1000
      0x05: [0x3b, 0xc1],
      0x07: dispatch,
      ...bodies,
    });
    expect(detect32(img).jumpTables).toEqual([]);
  });
});

describe("detectFunctions — jumpTableSpans", () => {
  const TABLE = 0x20;
  const CASES = [0x40, 0x44, 0x48];
  const LEN = 0x60;
  const switcher = (extra: Record<number, number[]> = {}, entries = CASES) =>
    image(LEN, {
      0x00: [0x83, 0xf8, entries.length - 1], // cmp eax, n-1
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + TABLE)],
      [TABLE]: entries.flatMap((c) => le32(BASE + c)),
      [CASES[0]]: [0x90, 0xc3],
      [CASES[1]]: [0x90, 0xc3],
      [CASES[2]]: [0x90, 0xc3],
      ...extra,
    });
  const detect32 = (img: Uint8Array) =>
    detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() }), { entryPoint: BASE });

  it("reports the bytes the recovered table occupies", () => {
    expect(detect32(switcher()).jumpTableSpans).toEqual([[BASE + TABLE, BASE + TABLE + 12]]);
  });

  it("reports only as far as it read", () => {
    // Bound of eight, three resolvable entries: the span is the three, because
    // claiming the other five bytes are data would be claiming the bound.
    const img = image(LEN, {
      0x00: [0x83, 0xf8, 0x07], // cmp eax, 7
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + TABLE)],
      [TABLE]: CASES.flatMap((c) => le32(BASE + c)),
      [CASES[0]]: [0x90, 0xc3],
      [CASES[1]]: [0x90, 0xc3],
      [CASES[2]]: [0x90, 0xc3],
    });
    expect(detect32(img).jumpTableSpans).toEqual([[BASE + TABLE, BASE + TABLE + 12]]);
  });

  it("reports one span for a table two dispatches share", () => {
    // t32.exe reads 0x40ba8c from three different `jmp`s. A span is about the
    // bytes, not about who reached them.
    const img = switcher({ 0x0a: [0xff, 0x24, 0xc5, ...le32(BASE + TABLE)] });
    const { jumpTables, jumpTableSpans } = detect32(img);
    expect(jumpTables.length).toBe(2);
    expect(jumpTableSpans).toEqual([[BASE + TABLE, BASE + TABLE + 12]]);
  });

  it("reports nothing when no table was recovered", () => {
    expect(detect32(image(LEN, { 0x00: [0xc3] })).jumpTableSpans).toEqual([]);
  });

  it("reports nothing without a decoder", () => {
    const { jumpTableSpans, omitted } = detectFunctions(switcher(), BASE, false, ctxOf(), {
      entryPoint: BASE,
    });
    expect(jumpTableSpans).toEqual([]);
    expect(omitted).toContain("jump-tables");
  });
});

// ── x86-64 RVA jump tables (peek-a-bin-ydh) ──
// x64 code is position-independent, so the dispatch cannot name its table: the
// table address arrives through a `lea`, the entry through a scaled load, and
// the two are added. Entries are signed 32-bit *displacements from the lea's
// target*, not addresses. Register numbers are the ModRM/SIB encodings.
const RAX = 0;
const RCX = 1;
const RDX = 2;
const RBX = 3;
/** `lea <r64>, [rip + d]` — 7 bytes, resolving to `target`. */
const leaRip = (at: number, reg: number, target: number) => [
  0x48,
  0x8d,
  0x05 | (reg << 3),
  ...le32(target - (BASE + at + 7)),
];
/** `movsxd <r64>, dword ptr [<base> + <idx>*4]` — 4 bytes. */
const movsxdScaled = (dst: number, base: number, idx: number) => [
  0x48,
  0x63,
  0x04 | (dst << 3),
  0x80 | (idx << 3) | base,
];
/** `mov <r32>, dword ptr [<base> + <idx>*4 + disp32]` — 7 bytes. */
const movScaledDisp = (dst: number, base: number, idx: number, disp: number) => [
  0x8b,
  0x84 | (dst << 3),
  0x80 | (idx << 3) | base,
  ...le32(disp),
];
/** `movzx <r32>, byte ptr [<base> + <idx>*<scale> + disp32]` — 8 bytes. */
const movzxByteDisp = (dst: number, base: number, idx: number, disp: number, scale = 1) => [
  0x0f,
  0xb6,
  0x84 | (dst << 3),
  (Math.log2(scale) << 6) | (idx << 3) | base,
  ...le32(disp),
];
/** `mov <r32>, byte ptr [<base> + <idx> + disp32]` — 7 bytes. Not the dense idiom. */
const movByteDisp = (dst: number, base: number, idx: number, disp: number) => [
  0x8a,
  0x84 | (dst << 3),
  (idx << 3) | base,
  ...le32(disp),
];
const addReg = (dst: number, src: number) => [0x48, 0x01, 0xc0 | (src << 3) | dst];
const movReg = (dst: number, src: number) => [0x48, 0x89, 0xc0 | (src << 3) | dst];
const jmpReg = (r: number) => [0xff, 0xe0 | r];
const cmpImm8 = (r: number, imm: number) => [0x83, 0xf8 | r, imm];
const cmpImm32 = (r: number, imm: number) => [0x81, 0xf8 | r, ...le32(imm)];
const jaTo = (at: number, target: number) => [0x77, (target - (BASE + at + 2)) & 0xff];
const body = [0x90, 0xc3]; // nop; ret — something real for a case label to be

describe("detectFunctions — x86-64 RVA jump tables", () => {
  const ctx64 = () => ctxOf({ cs64: fakeCs() });
  const detect64 = (img: Uint8Array, options: Parameters<typeof detectFunctions>[4] = {}) =>
    detectFunctions(img, BASE, true, ctx64(), options);

  // The GCC/clang spelling: the `lea` names the table, entries are relative to
  // it. Table at 0x20, four case bodies at 0x40/0x48/0x50/0x58.
  const GCC_TABLE = 0x20;
  const GCC_CASES = [0x40, 0x48, 0x50, 0x58];
  const gccSwitch = (extra: Record<number, number[]> = {}) =>
    image(0x80, {
      0x00: cmpImm8(RCX, 3),
      0x03: jaTo(0x03, 0x60),
      0x05: leaRip(0x05, RDX, BASE + GCC_TABLE),
      0x0c: movsxdScaled(RAX, RDX, RCX),
      0x10: addReg(RAX, RDX),
      0x13: jmpReg(RAX),
      [GCC_TABLE]: GCC_CASES.flatMap((c) => le32(c - GCC_TABLE)),
      [GCC_CASES[0]]: body,
      [GCC_CASES[1]]: body,
      [GCC_CASES[2]]: body,
      [GCC_CASES[3]]: body,
      0x60: [0xc3],
      ...extra,
    });

  it("reads a table whose entries are offsets from the lea target", () => {
    // Nothing here is an address: the four entries are 0x20/0x28/0x30/0x38.
    // Read as absolute pointers — the 32-bit path's rule — they would resolve
    // into the first page of the image and be rejected, which is why the whole
    // shape has to be recognised rather than fed to the existing reader.
    const { jumpTables } = detect64(gccSwitch());
    expect(jumpTables).toEqual([[BASE + 0x13, GCC_CASES.map((c) => BASE + c)]]);
  });

  it("finds the bounds check when the load overwrites the index register", () => {
    // `movsxd rax, dword ptr [rdx + rax*4]` — the index and the loaded entry
    // share a register, which is what compilers actually emit. The check has to
    // be looked for *before the load*: searching back from the jump instead
    // meets the load first, reads it as the index being clobbered, and reports
    // no table at all. Verified on a real x64 image before this was fixed.
    const img = image(0x80, {
      0x00: cmpImm8(RAX, 3),
      0x03: jaTo(0x03, 0x60),
      0x05: leaRip(0x05, RDX, BASE + GCC_TABLE),
      0x0c: movsxdScaled(RAX, RDX, RAX),
      0x10: addReg(RAX, RDX),
      0x13: jmpReg(RAX),
      [GCC_TABLE]: GCC_CASES.flatMap((c) => le32(c - GCC_TABLE)),
      [GCC_CASES[0]]: body,
      [GCC_CASES[1]]: body,
      [GCC_CASES[2]]: body,
      [GCC_CASES[3]]: body,
      0x60: [0xc3],
    });
    expect(detect64(img).jumpTables).toEqual([[BASE + 0x13, GCC_CASES.map((c) => BASE + c)]]);
  });

  it("keys the table by the address of the indirect jump", () => {
    // buildCFG and structureCFG both look tables up by the jump's address.
    const { jumpTables } = detect64(gccSwitch());
    expect(jumpTables[0][0]).toBe(BASE + 0x13);
  });

  it("reads entries as signed, so a case body before the table resolves", () => {
    const img = image(0x80, {
      0x00: cmpImm8(RCX, 1),
      0x03: leaRip(0x03, RDX, BASE + 0x60),
      0x0a: movsxdScaled(RAX, RDX, RCX),
      0x0e: addReg(RAX, RDX),
      0x11: jmpReg(RAX),
      0x30: body,
      0x38: body,
      0x60: [...le32(0x30 - 0x60), ...le32(0x38 - 0x60)],
    });
    expect(detect64(img).jumpTables[0][1]).toEqual([BASE + 0x30, BASE + 0x38]);
  });

  // The MSVC spelling: the `lea` names __ImageBase, the table's RVA rides in
  // the load's displacement, and entries are image-relative.
  const IMAGE_BASE = BASE - 0x1000;
  const MSVC_CASES = [0x40, 0x48, 0x50];
  const msvcSwitch = (tableAddr: number, extra: Record<number, number[]> = {}) =>
    image(0x80, {
      0x00: cmpImm8(RAX, 2),
      0x03: leaRip(0x03, RDX, IMAGE_BASE),
      0x0a: movScaledDisp(RCX, RDX, RAX, tableAddr - IMAGE_BASE),
      0x11: addReg(RCX, RDX),
      0x14: jmpReg(RCX),
      ...extra,
    });
  const msvcEntries = MSVC_CASES.flatMap((c) => le32(BASE + c - IMAGE_BASE));

  it("resolves the form where the lea names the image base and the load carries the table RVA", () => {
    const img = msvcSwitch(BASE + 0x20, {
      0x20: msvcEntries,
      [MSVC_CASES[0]]: body,
      [MSVC_CASES[1]]: body,
      [MSVC_CASES[2]]: body,
    });
    expect(detect64(img).jumpTables).toEqual([[BASE + 0x14, MSVC_CASES.map((c) => BASE + c)]]);
  });

  it("cannot reach a table outside the code section without being given the bytes", () => {
    // Where x64 compilers actually put these tables. The detector is handed the
    // code section, so this is a real limit, not a preference: with no window
    // covering the table there is nothing to read and nothing is reported.
    const img = msvcSwitch(0x410000, {
      [MSVC_CASES[0]]: body,
      [MSVC_CASES[1]]: body,
      [MSVC_CASES[2]]: body,
    });
    expect(detect64(img).jumpTables).toEqual([]);
  });

  it("reads a table outside the code section from a data window", () => {
    const img = msvcSwitch(0x410000, {
      [MSVC_CASES[0]]: body,
      [MSVC_CASES[1]]: body,
      [MSVC_CASES[2]]: body,
    });
    const { jumpTables } = detect64(img, {
      dataWindows: [{ base: 0x410000, bytes: new Uint8Array(msvcEntries) }],
    });
    expect(jumpTables).toEqual([[BASE + 0x14, MSVC_CASES.map((c) => BASE + c)]]);
  });

  it("ignores a register dispatch with no bounds check", () => {
    // No `cmp` means no statement of the table's length, and a table read
    // without a length invents case targets out of whatever follows it.
    const img = gccSwitch();
    img.set([0x90, 0x90, 0x90], 0x00); // erase the cmp
    expect(detect64(img).jumpTables).toEqual([]);
  });

  it("refuses a bounds check too large to be a case count", () => {
    // The compared immediate comes from the file, and nothing else states the
    // table's length. Here it claims 4097 cases and every dword that follows
    // resolves to a plausible target, so an uncapped reader would report a
    // 24-entry table invented out of unrelated bytes. Raising
    // MAX_JUMP_TABLE_CASES above the claim makes this test fail.
    const img = image(0x80, {
      0x00: cmpImm32(RCX, 0x1000),
      0x06: leaRip(0x06, RDX, BASE + 0x20),
      0x0d: movsxdScaled(RAX, RDX, RCX),
      0x11: addReg(RAX, RDX),
      0x14: jmpReg(RAX),
      0x20: Array.from({ length: 24 }, () => le32(0x20)).flat(),
    });
    expect(detect64(img).jumpTables).toEqual([]);
  });

  it("stops at the first entry that leaves the code section", () => {
    // The check says four cases; the third entry points outside the image, so
    // the table ends there instead of continuing into whatever follows.
    const img = gccSwitch({
      [GCC_TABLE]: [...le32(0x20), ...le32(0x28), ...le32(0x7fff0000), ...le32(0x38)],
    });
    expect(detect64(img).jumpTables[0][1]).toEqual([BASE + 0x40, BASE + 0x48]);
  });

  it("follows a copy of the index register to find the bounds check", () => {
    // `cmp ecx, N / ja / mov rbx, rcx / … [rdx + rbx*4]` — the check names the
    // register the index was copied from, which is still a check on the index.
    const img = image(0x80, {
      0x00: cmpImm8(RCX, 1),
      0x03: jaTo(0x03, 0x60),
      0x05: leaRip(0x05, RDX, BASE + 0x20),
      0x0c: movReg(RBX, RCX),
      0x0f: movsxdScaled(RAX, RDX, RBX),
      0x13: addReg(RAX, RDX),
      0x16: jmpReg(RAX),
      0x20: [...le32(0x20), ...le32(0x28)],
      0x40: body,
      0x48: body,
      0x60: [0xc3],
    });
    expect(detect64(img).jumpTables[0][1]).toEqual([BASE + 0x40, BASE + 0x48]);
  });

  it("gives up when the table base is overwritten before the jump", () => {
    // `mov rdx, rbx` between the load and the `add` means the value added was
    // not the lea's — following the chain past it would report a table read
    // from an address the program never used.
    const img = image(0x80, {
      0x00: cmpImm8(RCX, 1),
      0x03: leaRip(0x03, RDX, BASE + 0x20),
      0x0a: movsxdScaled(RAX, RDX, RCX),
      0x0e: movReg(RDX, RBX),
      0x11: addReg(RAX, RDX),
      0x14: jmpReg(RAX),
      0x20: [...le32(0x20), ...le32(0x28)],
      0x40: body,
      0x48: body,
    });
    expect(detect64(img).jumpTables).toEqual([]);
  });

  it("gives up when a call sits inside the chain", () => {
    // Every register this idiom uses is volatile, so a call between the `lea`
    // and the jump means the base register no longer holds the lea's value.
    const img = image(0x80, {
      0x00: cmpImm8(RCX, 1),
      0x03: jaTo(0x03, 0x60),
      0x05: leaRip(0x05, RDX, BASE + 0x20),
      0x0c: callTo(0x0c, BASE + 0x60),
      0x11: movsxdScaled(RAX, RDX, RCX),
      0x15: addReg(RAX, RDX),
      0x18: jmpReg(RAX),
      0x20: [...le32(0x20), ...le32(0x28)],
      0x40: body,
      0x48: body,
      0x60: [0xc3],
    });
    expect(detect64(img).jumpTables).toEqual([]);
  });

  /**
   * peek-a-bin-div. MSVC's *dense* switch: a byte per case naming a row, and a
   * dword per distinct body. This was detected and deliberately refused,
   * because entry `i` is not case `i` and wrong case labels are worse than no
   * switch. Reading both tables puts it back in case order.
   *
   * **Nothing in the local corpus emits this shape**, so these cases are the
   * only verification there is. The encodings are real x86-64 and the operand
   * spellings are the ones the shipped capstone.wasm produces (checked against
   * it directly), but no real image has been through this path.
   */
  describe("the dense two-table form", () => {
    const BYTE_TABLE = 0x20;
    const DWORD_TABLE = 0x28;
    const BODIES = [0x40, 0x48, 0x50];
    /** Case → row. Deliberately not the identity: cases 3/4/5 reuse bodies. */
    const ROWS = [0, 1, 2, 1, 0, 2];

    const dense = (over: Record<number, number[]> = {}, movzx?: number[]) =>
      image(0x80, {
        0x00: cmpImm8(RCX, ROWS.length - 1),
        0x03: jaTo(0x03, 0x60),
        0x05: leaRip(0x05, RDX, IMAGE_BASE),
        0x0c: movzx ?? movzxByteDisp(RAX, RDX, RCX, BASE + BYTE_TABLE - IMAGE_BASE),
        0x14: movScaledDisp(RCX, RDX, RAX, BASE + DWORD_TABLE - IMAGE_BASE),
        0x1b: addReg(RCX, RDX),
        0x1e: jmpReg(RCX),
        [BYTE_TABLE]: ROWS,
        [DWORD_TABLE]: BODIES.flatMap((c) => le32(BASE + c - IMAGE_BASE)),
        [BODIES[0]]: body,
        [BODIES[1]]: body,
        [BODIES[2]]: body,
        0x60: [0xc3],
        ...over,
      });
    const denseJmp = BASE + 0x1e;

    it("reads both tables, so targets come out in case order", () => {
      // Row order is 0x40/0x48/0x50; case order is 0x40/0x48/0x50/0x48/0x40/0x50.
      // Reporting the dword table's three entries in order — what refusing this
      // form avoided having to do — would have filed cases 3-5 under nothing and
      // cases 0-2 under bodies that are only sometimes theirs.
      expect(detect64(dense()).jumpTables).toEqual([[denseJmp, ROWS.map((r) => BASE + BODIES[r])]]);
    });

    it("keeps its case bodies out of the function set", () => {
      const { functions } = detect64(dense(), { entryPoint: BASE });
      for (const c of BODIES) expect(functions.map((f) => f.address)).not.toContain(BASE + c);
    });

    it("refuses when nothing bounds the case value", () => {
      // The `cmp` is the only statement of the byte table's length, exactly as
      // in the single-table form.
      const img = dense();
      img.set([0x90, 0x90, 0x90], 0x00);
      expect(detect64(img).jumpTables).toEqual([]);
    });

    it("refuses when neither operand of the byte load is the lea's register", () => {
      // Then the displacement is not an RVA off the image base, and the byte
      // table address it implies is one the program never formed. The compare
      // is moved onto RBX so that everything *else* about this dispatch checks
      // out: without the base test it reads a full, plausible, wrong table.
      const img = dense(
        { 0x00: cmpImm8(RBX, ROWS.length - 1) },
        movzxByteDisp(RAX, RBX, RCX, BASE + BYTE_TABLE - IMAGE_BASE),
      );
      expect(detect64(img).jumpTables).toEqual([]);
    });

    it("refuses when both operands of the byte load are the lea's register", () => {
      // `[rdx + rdx + d]` says nothing about which one is the case index, so
      // there is no case register to bound. Again bounded, so the refusal is
      // about the ambiguity and not about a missing compare.
      const img = dense(
        { 0x00: cmpImm8(RDX, ROWS.length - 1) },
        movzxByteDisp(RAX, RDX, RDX, BASE + BYTE_TABLE - IMAGE_BASE),
      );
      expect(detect64(img).jumpTables).toEqual([]);
    });

    it("refuses a scaled byte load, which is not this idiom", () => {
      // `[rdx + rcx*4 + d]` indexes something four bytes wide; a byte table's
      // entries are one byte apart, so one of the two readings is wrong.
      const img = dense({}, movzxByteDisp(RAX, RDX, RCX, BASE + BYTE_TABLE - IMAGE_BASE, 4));
      expect(detect64(img).jumpTables).toEqual([]);
    });

    it("refuses a plain `mov` byte load, which does not widen an unsigned row", () => {
      const img = dense({}, movByteDisp(RAX, RDX, RCX, BASE + BYTE_TABLE - IMAGE_BASE));
      expect(detect64(img).jumpTables).toEqual([]);
    });

    it("stops at a case whose row points outside the dword table's reach", () => {
      // Row 9 reads past the three-entry dword table into the case bodies,
      // whose bytes do not resolve to anything in the code window.
      const img = dense({ [BYTE_TABLE]: [0, 1, 9, 1, 0, 2] });
      expect(detect64(img).jumpTables[0][1]).toEqual([BASE + BODIES[0], BASE + BODIES[1]]);
    });

    it("does not take this path when the single-table reading already worked", () => {
      // The dense reader only ever runs where `boundedCaseCount` found nothing,
      // so a normal RVA switch cannot be re-read through it.
      expect(detect64(gccSwitch()).jumpTables).toEqual([
        [BASE + 0x13, GCC_CASES.map((c) => BASE + c)],
      ]);
    });
  });

  it("keeps x64 case targets out of the function set", () => {
    // The same rule the 32-bit path follows (peek-a-bin-jy4): a case body is
    // interior to the dispatching function, and registering it as a function
    // start truncates that function at its first case.
    const img = gccSwitch({ [GCC_CASES[1]]: [0x48, 0x83, 0xec, 0x28] }); // prologue-shaped
    const { functions } = detect64(img, { entryPoint: BASE });
    for (const c of GCC_CASES) expect(functions.map((f) => f.address)).not.toContain(BASE + c);
    expect(functions[0].address).toBe(BASE);
    expect(functions[0].size).toBe(0x80);
  });

  it("gives the register dispatch one CFG successor per case", () => {
    const ctx = ctx64();
    const img = gccSwitch();
    const { functions, jumpTables } = detectFunctions(img, BASE, true, ctx, { entryPoint: BASE });
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx);
    const blocks = buildCFG(functions[0], insns, new Map(), new Map(jumpTables));
    const dispatch = blocks.find((b) => b.insns.some((i) => i.address === BASE + 0x13));
    const succAddrs = dispatch?.succs.map((s) => blocks[s].startAddr).sort((a, b) => a - b);
    expect(succAddrs).toEqual(GCC_CASES.map((c) => BASE + c));
  });
});

describe("detectFunctions → buildCFG — a dispatched-to case body is a block", () => {
  // The end of the chain the case-label fix exists to repair: with the targets
  // registered as functions, the dispatching function ended at its first case,
  // buildCFG's range guard rejected every target as a leader, and the block
  // ending in the indirect jmp came out with *zero* successors — which is why
  // the structurer's switch path never fired on a real binary.
  const TABLE = 0x20;
  const CASES = [0x40, 0x44, 0x48];
  const img = image(0x60, {
    0x00: [0x83, 0xf8, 0x02],
    0x03: [0xff, 0x24, 0xc5, ...le32(BASE + TABLE)],
    [TABLE]: [...le32(BASE + CASES[0]), ...le32(BASE + CASES[1]), ...le32(BASE + CASES[2])],
    [CASES[0]]: [0x90, 0xc3],
    [CASES[1]]: [0x90, 0xc3],
    [CASES[2]]: [0x90, 0xc3],
  });

  it("gives the indirect jump one successor per case", () => {
    const ctx = ctxOf({ cs32: fakeCs() });
    const { functions, jumpTables } = detectFunctions(img, BASE, false, ctx, { entryPoint: BASE });
    const insns = hybridDisassemble(img, BASE, false, [BASE], ctx);
    const blocks = buildCFG(functions[0], insns, new Map(), new Map(jumpTables));

    const dispatch = blocks.find((b) => b.insns.some((i) => i.address === BASE + 3));
    expect(dispatch).toBeDefined();
    const last = dispatch!.insns[dispatch!.insns.length - 1];
    expect(last.address).toBe(BASE + 3);
    const succAddrs = dispatch?.succs.map((s) => blocks[s].startAddr).sort((a, b) => a - b);
    expect(succAddrs).toEqual(CASES.map((c) => BASE + c));
  });
});

describe("detectFunctions — with a decoder", () => {
  const ctx = () => ctxOf({ cs64: fakeCs() });

  it("adds direct call targets as functions", () => {
    const img = image(0x40, { 0x00: callTo(0x00, BASE + 0x20), 0x05: [0xc3] });
    const { functions } = detectFunctions(img, BASE, true, ctx());
    expect(functions.map((f) => f.address)).toContain(BASE + 0x20);
  });

  it("ignores call targets outside the image", () => {
    const img = image(0x40, { 0x00: callTo(0x00, BASE + 0x8000), 0x05: [0xc3] });
    expect(detectFunctions(img, BASE, true, ctx()).functions).toEqual([]);
  });

  it("reads a jump table behind a bounds check", () => {
    const tableRva = 0x20;
    const img = image(0x60, {
      0x00: [0x83, 0xf8, 0x02], // cmp eax, 2
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + tableRva)],
      [tableRva]: [...le32(BASE + 0x40), ...le32(BASE + 0x44), ...le32(BASE + 0x48)],
    });
    const { functions, jumpTables } = detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() }));
    expect(jumpTables).toHaveLength(1);
    const [, targets] = jumpTables[0];
    expect(targets).toEqual([BASE + 0x40, BASE + 0x44, BASE + 0x48]);
    // The targets are case labels, not entry points — see the dedicated block
    // below. Nothing else in this image vouches for them, so no function starts
    // at any of them.
    for (const t of targets) expect(functions.map((f) => f.address)).not.toContain(t);
  });

  it("ignores an indirect jump with no preceding bounds check", () => {
    const img = image(0x60, {
      0x00: [0xff, 0x24, 0xc5, ...le32(BASE + 0x20)],
      0x20: [...le32(BASE + 0x40), ...le32(BASE + 0x44)],
    });
    expect(detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() })).jumpTables).toEqual([]);
  });

  it("stops reading a jump table at the first out-of-range entry", () => {
    const img = image(0x60, {
      0x00: [0x83, 0xf8, 0x04],
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + 0x20)],
      0x20: [...le32(BASE + 0x40), ...le32(BASE + 0x44), ...le32(0xdeadbeef)],
    });
    const { jumpTables } = detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() }));
    expect(jumpTables[0][1]).toEqual([BASE + 0x40, BASE + 0x44]);
  });

  it("needs at least two valid entries to accept a jump table", () => {
    const img = image(0x60, {
      0x00: [0x83, 0xf8, 0x04],
      0x03: [0xff, 0x24, 0xc5, ...le32(BASE + 0x20)],
      0x20: [...le32(BASE + 0x40), ...le32(0xdeadbeef)],
    });
    expect(detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() })).jumpTables).toEqual([]);
  });

  const IAT_ADDR = BASE + 0x30;
  const thunkImage = () => image(0x40, { 0x00: [0xff, 0x25, ...le32(IAT_ADDR - (BASE + 6))] });
  const thunkCtx = () =>
    ctxOf({
      cs64: fakeCs(),
      iatMap: new Map([[IAT_ADDR, { lib: "kernel32.dll", func: "Sleep" }]]),
    });

  it("renames a single-jump function that targets an import", () => {
    const { functions } = detectFunctions(thunkImage(), BASE, true, thunkCtx(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 6 }],
    });
    const thunk = functions.find((f) => f.address === BASE);
    expect(thunk?.name).toBe("Sleep");
    expect(thunk?.isThunk).toBe(true);
  });

  it("does not treat a longer function as a thunk", () => {
    // The jump is preceded by real work, so meaningfulCount > 1.
    const img = thunkImage();
    img.copyWithin(2, 0, 8);
    img[0] = 0x83;
    img[1] = 0xf8; // cmp eax, imm8 before the jump
    const { functions } = detectFunctions(img, BASE, true, thunkCtx(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 9 }],
    });
    expect(functions[0].isThunk).toBeUndefined();
  });

  it("does not consider a function larger than 16 bytes a thunk", () => {
    const { functions } = detectFunctions(thunkImage(), BASE, true, thunkCtx(), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 0x20 }],
    });
    expect(functions[0].isThunk).toBeUndefined();
  });

  it("leaves a named function alone even if it looks like a thunk", () => {
    const { functions } = detectFunctions(thunkImage(), BASE, true, thunkCtx(), {
      exports: [{ name: "MyExport", address: BASE }],
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 6 }],
    });
    expect(functions[0].name).toBe("MyExport");
    expect(functions[0].isThunk).toBeUndefined();
  });

  it("records a tail call to another function", () => {
    // Function A at 0x00 ends with `jmp B`; B is a seeded function at 0x20.
    const img = image(0x40, { 0x00: jmpTo(0x00, BASE + 0x20), 0x20: [0xc3] });
    const { functions } = detectFunctions(img, BASE, true, ctxOf({ cs64: fakeCs() }), {
      pdataFunctions: [
        { beginAddress: BASE, endAddress: BASE + 5 },
        { beginAddress: BASE + 0x20, endAddress: BASE + 0x21 },
      ],
    });
    expect(functions.find((f) => f.address === BASE)?.tailCallTarget).toBe(BASE + 0x20);
  });

  it("does not record a self-jump as a tail call", () => {
    const img = image(0x40, { 0x00: jmpTo(0x00, BASE) });
    const { functions } = detectFunctions(img, BASE, true, ctxOf({ cs64: fakeCs() }), {
      pdataFunctions: [{ beginAddress: BASE, endAddress: BASE + 5 }],
    });
    expect(functions[0].tailCallTarget).toBeUndefined();
  });
});

describe("disassemble", () => {
  it("decodes a whole buffer", () => {
    const img = image(4, { 0: [0xc3, 0x90, 0xcc, 0xc3] });
    expect(disassemble(img, BASE, true, ctxOf({ cs64: fakeCs() })).map((i) => i.mnemonic)).toEqual([
      "ret",
      "nop",
      "int3",
      "ret",
    ]);
  });

  it("skips a byte the decoder cannot handle and resumes", () => {
    const img = image(3, { 0: [0x00, 0xc3, 0x90] });
    expect(disassemble(img, BASE, true, ctxOf({ cs64: fakeCs() })).map((i) => i.mnemonic)).toEqual([
      "ret",
      "nop",
    ]);
  });

  it("returns nothing for an empty buffer", () => {
    expect(disassemble(new Uint8Array(0), BASE, true, ctxOf({ cs64: fakeCs() }))).toEqual([]);
  });

  it("applies instruction comments while decoding", () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x10)] });
    const iatMap = new Map([[BASE + 6 + 0x10, { lib: "a.dll", func: "F" }]]);
    expect(disassemble(img, BASE, true, ctxOf({ cs64: fakeCs(), iatMap }))[0].comment).toBe(
      "a.dll!F",
    );
  });
});

describe("hybridDisassemble", () => {
  const ctx = () => ctxOf({ cs64: fakeCs() });

  it("follows a call and its fallthrough from a seed", () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3], 0x10: [0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    const byAddr = new Map(insns.map((i) => [i.address, i]));
    expect(byAddr.get(BASE)?.mnemonic).toBe("call");
    expect(byAddr.get(BASE + 5)?.mnemonic).toBe("ret");
    expect(byAddr.get(BASE + 0x10)?.source).toBe("recursive");
  });

  it("follows both edges of a conditional jump", () => {
    const img = image(0x10, { 0x00: [0x74, 0x04], 0x02: [0xc3], 0x06: [0xc3] });
    const addrs = hybridDisassemble(img, BASE, true, [BASE], ctx()).map((i) => i.address);
    expect(addrs).toContain(BASE + 2);
    expect(addrs).toContain(BASE + 6);
  });

  it("stops recursive descent at a terminator", () => {
    const img = image(0x10, { 0x00: [0xc3], 0x01: [0x41] });
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    expect(insns.find((i) => i.address === BASE + 1)?.source).not.toBe("recursive");
  });

  it("returns instructions sorted by address", () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3], 0x10: [0xc3] });
    const addrs = hybridDisassemble(img, BASE, true, [BASE], ctx()).map((i) => i.address);
    expect(addrs).toEqual([...addrs].sort((a, b) => a - b));
  });

  it("ignores seeds outside the image", () => {
    // Out-of-range seeds contribute nothing; the bytes are only reached by the
    // gap-fill pass, which marks them as such.
    const img = image(0x10, { 0x00: [0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE - 0x100, BASE + 0x1000], ctx());
    expect(insns.every((i) => i.source === "gap-fill")).toBe(true);
  });

  it("gap-fills bytes the recursive pass never reached", () => {
    const img = image(0x10, { 0x00: [0xc3], 0x01: [0x90, 0x90, 0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    expect(insns.find((i) => i.address === BASE + 3)?.source).toBe("gap-fill");
  });

  it("does not gap-fill a run of padding", () => {
    const img = new Uint8Array(0x10).fill(0xcc);
    img[0] = 0xc3;
    const insns = hybridDisassemble(img, BASE, true, [BASE], ctx());
    expect(insns.map((i) => i.address)).toEqual([BASE]);
  });

  it("bulk-decodes .pdata ranges before the recursive pass", () => {
    const img = image(0x20, { 0x10: [0xc3, 0x90] });
    const insns = hybridDisassemble(img, BASE, true, [], ctx(), [
      { beginAddress: BASE + 0x10, endAddress: BASE + 0x12 },
    ]);
    expect(insns.map((i) => [i.address, i.source])).toEqual([
      [BASE + 0x10, "recursive"],
      [BASE + 0x11, "recursive"],
    ]);
  });

  it("ignores a .pdata range that runs past the image", () => {
    const img = image(0x10, {});
    expect(
      hybridDisassemble(img, BASE, true, [], ctx(), [
        { beginAddress: BASE, endAddress: BASE + 0x100 },
      ]),
    ).toEqual([]);
  });

  // ── Recovered jump tables are data (peek-a-bin-y1di) ──
  // A table sits in `.text` and no control-flow path leads into it, so it is
  // uncovered by construction and phase 2 decodes its case addresses as
  // instructions. On t32.exe the 32 bytes at 0x4086a4 came out as six
  // conditional jumps aiming past the end of the function they were filed
  // under, and nothing downstream could tell them from real code.
  describe("jump-table spans", () => {
    const TABLE = 0x08;
    const CASES = [0x18, 0x1a];
    // Entries that decode as something if they are read as code: `74 xx` is a
    // `je`, which is exactly the shape the phantom instructions took.
    const tableImage = () =>
      image(0x20, {
        0x00: [0xc3],
        [TABLE]: [...le32(BASE + CASES[0]), ...le32(BASE + CASES[1])],
        [CASES[0]]: [0x90, 0xc3],
        [CASES[1]]: [0x90, 0xc3],
      });
    const spans = (): [number, number][] => [[BASE + TABLE, BASE + TABLE + 8]];
    const inTable = (insns: Instruction[]) =>
      insns.filter((i) => i.address >= BASE + TABLE && i.address < BASE + TABLE + 8);

    it("decodes a table's bytes when nobody says they are data", () => {
      // The defect, pinned so the fix below is measuring something.
      const insns = hybridDisassemble(tableImage(), BASE, true, [BASE], ctx());
      expect(inTable(insns).length).toBeGreaterThan(0);
    });

    it("leaves the bytes of a recovered table alone", () => {
      const insns = hybridDisassemble(tableImage(), BASE, true, [BASE], ctx(), undefined, spans());
      expect(inTable(insns)).toEqual([]);
    });

    it("resumes the fill after the table", () => {
      const insns = hybridDisassemble(tableImage(), BASE, true, [BASE], ctx(), undefined, spans());
      expect(insns.map((i) => i.address)).toContain(BASE + CASES[0]);
    });

    it("keeps an instruction recursive descent actually reached inside a span", () => {
      // Seeded into the span: a control-flow path leading there is evidence
      // about the bytes that outranks the span, and dropping it would hide it.
      const insns = hybridDisassemble(
        tableImage(),
        BASE,
        true,
        [BASE, BASE + TABLE],
        ctx(),
        undefined,
        spans(),
      );
      expect(insns.find((i) => i.address === BASE + TABLE)?.source).toBe("recursive");
    });

    it("clamps a span that lies outside the disassembled bytes", () => {
      // An x64 RVA table lives in `.rdata`, so its span names addresses this
      // call has no bytes for.
      const withOutside = hybridDisassemble(tableImage(), BASE, true, [BASE], ctx(), undefined, [
        [BASE - 0x1000, BASE - 0x800],
        [BASE + 0x1000, BASE + 0x2000],
      ]);
      const none = hybridDisassemble(tableImage(), BASE, true, [BASE], ctx());
      expect(withOutside.map((i) => i.address)).toEqual(none.map((i) => i.address));
    });
  });

  it("never decodes the same address twice", () => {
    const img = image(0x10, { 0x00: [0x74, 0x00], 0x02: [0xc3] });
    const insns = hybridDisassemble(img, BASE, true, [BASE, BASE, BASE + 2], ctx());
    const addrs = insns.map((i) => i.address);
    expect(new Set(addrs).size).toBe(addrs.length);
  });
});

/**
 * peek-a-bin-cen. `ctx.cs32`/`ctx.cs64` are undefined until the worker's WASM
 * bootstrap resolves and stay undefined if it fails, and only the `init` RPC
 * awaits it — so a decode RPC really can arrive with no handle. Every stage
 * whose whole output is instructions must say so instead of returning a
 * complete-looking empty answer; the one stage that has other evidence to fall
 * back on must NOT, and both halves are pinned here.
 */
describe("a missing Capstone handle is reported, not absorbed", () => {
  const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3], 0x10: [0xc3] });

  it("makes `disassemble` throw rather than return an empty list", () => {
    expect(() => disassemble(img, BASE, true, ctxOf())).toThrow(CapstoneUnavailableError);
    expect(() => disassemble(img, BASE, false, ctxOf())).toThrow(/Capstone is not initialised/);
  });

  it("makes `hybridDisassemble` throw rather than return an empty list", () => {
    expect(() => hybridDisassemble(img, BASE, true, [BASE], ctxOf())).toThrow(
      CapstoneUnavailableError,
    );
  });

  it("makes `buildAllXrefs` throw rather than return four empty maps", () => {
    expect(() => buildAllXrefs(img, BASE, true, [BASE], [BASE + 0x10], null)).toThrow(
      CapstoneUnavailableError,
    );
  });

  it("names the stage that had no decoder", () => {
    expect(() => disassemble(img, BASE, true, ctxOf())).toThrow(/linear disassembly/);
    expect(() => hybridDisassemble(img, BASE, true, [], ctxOf())).toThrow(/hybrid disassembly/);
    expect(() => buildAllXrefs(img, BASE, true, [], [], null)).toThrow(/xref building/);
  });

  it("checks the handle the architecture actually selects", () => {
    // A 32-bit call with only a 64-bit handle open is still undecodable, and
    // reading `cs64` because `cs32` happened to be set would hide it.
    expect(() => disassemble(img, BASE, false, ctxOf({ cs64: fakeCs() }))).toThrow(
      CapstoneUnavailableError,
    );
    expect(() => disassemble(img, BASE, true, ctxOf({ cs32: fakeCs() }))).toThrow(
      CapstoneUnavailableError,
    );
  });

  it("still lets `detectFunctions` report the starts the file itself records", () => {
    // The other direction. Detection's evidence is not made of instructions:
    // `.pdata` extents, exports, the entry point and unwind handlers are all
    // statements the image makes, and reporting them with no call targets is a
    // narrower answer, not a silently empty one.
    const { functions } = detectFunctions(img, BASE, true, ctxOf(), {
      entryPoint: BASE,
      exports: [{ name: "Exported", address: BASE + 0x10 }],
      pdataFunctions: [{ beginAddress: BASE + 0x18, endAddress: BASE + 0x20 }],
      handlerAddresses: [BASE + 0x1c],
    });
    expect(functions.map((f) => f.address)).toEqual([BASE, BASE + 0x10, BASE + 0x18, BASE + 0x1c]);
    expect(functions.map((f) => f.name)).toEqual([
      "entry_point",
      "Exported",
      `sub_${(BASE + 0x18).toString(16).toUpperCase()}`,
      `__handler_${(BASE + 0x1c).toString(16)}`,
    ]);
  });

  // peek-a-bin-4s9. The narrow answer above and a complete one used to be the
  // same shape, so a caller could not tell them apart — the same defect class
  // as a short read that reports success.
  it("says which passes it could not run", () => {
    const { omitted } = detectFunctions(img, BASE, true, ctxOf(), { entryPoint: BASE });
    expect(omitted).toEqual(["call-targets", "jump-tables", "thunk-names", "tail-calls"]);
  });

  it("reports nothing omitted when the decoder is there", () => {
    const { functions, omitted } = detectFunctions(img, BASE, true, ctxOf({ cs64: fakeCs() }), {
      entryPoint: BASE,
    });
    // Same image, and the call target the decoder-less run above could not see
    // is present — so this really is the complete answer `omitted` claims.
    expect(functions.map((f) => f.address)).toContain(BASE + 0x10);
    expect(omitted).toEqual([]);
  });

  it("reports the omission on the handle the architecture selects", () => {
    // `cs32` set, 64-bit image: `detectFunctions` reads `cs64`, finds nothing,
    // and must say so rather than report the handle it did not use.
    expect(detectFunctions(img, BASE, true, ctxOf({ cs32: fakeCs() })).omitted).toHaveLength(4);
    expect(detectFunctions(img, BASE, false, ctxOf({ cs32: fakeCs() })).omitted).toEqual([]);
  });
});

describe("buildTypedXrefMap", () => {
  const insn = (mnemonic: string, opStr: string, address: number, size = 5): Instruction => ({
    address,
    mnemonic,
    opStr,
    size,
    bytes: new Uint8Array(size),
  });

  it("returns nothing for an empty instruction list", () => {
    expect(buildTypedXrefMap([])).toEqual([]);
  });

  it("classifies a direct call as a call xref", () => {
    expect(buildTypedXrefMap([insn("call", "0x401100", BASE)])).toEqual([
      [0x401100, [{ from: BASE, type: "call" }]],
    ]);
  });

  it("classifies jmp and conditional branches", () => {
    expect(buildTypedXrefMap([insn("jmp", "0x401100", BASE)])[0][1][0].type).toBe("jmp");
    expect(buildTypedXrefMap([insn("je", "0x401100", BASE)])[0][1][0].type).toBe("branch");
    expect(buildTypedXrefMap([insn("jrcxz", "0x401100", BASE)])[0][1][0].type).toBe("branch");
  });

  it("ignores a direct address operand on a non-branch instruction", () => {
    expect(buildTypedXrefMap([insn("push", "0x401100", BASE)])).toEqual([]);
  });

  it("groups several references to the same target", () => {
    const xrefs = buildTypedXrefMap([
      insn("call", "0x401100", BASE),
      insn("je", "0x401100", BASE + 5),
    ]);
    expect(xrefs).toEqual([
      [
        0x401100,
        [
          { from: BASE, type: "call" },
          { from: BASE + 5, type: "branch" },
        ],
      ],
    ]);
  });

  it("resolves a rip-relative call to an import as a call xref", () => {
    const [[target, refs]] = buildTypedXrefMap([insn("call", "qword ptr [rip + 0x100]", BASE, 6)]);
    expect(target).toBe(BASE + 6 + 0x100);
    expect(refs[0].type).toBe("call");
  });

  it("classifies a rip-relative load as a data xref", () => {
    expect(buildTypedXrefMap([insn("lea", "rax, [rip + 0x100]", BASE, 7)])[0][1][0].type).toBe(
      "data",
    );
  });

  it("records data xrefs for absolute addresses above 0x10000", () => {
    expect(buildTypedXrefMap([insn("mov", "eax, dword ptr [0x404000]", BASE)])).toEqual([
      [0x404000, [{ from: BASE, type: "data" }]],
    ]);
  });

  it("ignores small immediates as data xrefs", () => {
    expect(buildTypedXrefMap([insn("mov", "eax, 0x10", BASE)])).toEqual([]);
  });

  it("records every address in a multi-operand instruction", () => {
    const xrefs = buildTypedXrefMap([insn("mov", "dword ptr [0x404000], 0x405000", BASE)]);
    expect(xrefs.map(([addr]) => addr)).toEqual([0x404000, 0x405000]);
  });

  /**
   * peek-a-bin-jfp. The fallback scan has no grammar behind it — every `0x…`
   * token above 0x10000 in an operand became a data reference — so bitmasks and
   * sentinels were reported as references to addresses that cannot exist.
   * Measured before the bound: 305 of t64.exe's 856 data xrefs, 318 of
   * t32.exe's 881, 239 of t64-arm.exe's 1007.
   */
  describe("the fallback scan is bounded by the image", () => {
    /** t64.exe's own numbers: base 0x140000000, sizeOfImage 0x21000. */
    const bounds = { base: 0x140000000, size: 0x21000 };
    const targets = (i: Instruction) => buildTypedXrefMap([i], bounds).map(([addr]) => addr);

    it("drops a -1 sentinel that is larger than any address in the image", () => {
      // `or edx, 0xffffffff` accounts for 82 of t64.exe's out-of-image xrefs.
      expect(targets(insn("or", "edx, 0xffffffff", BASE))).toEqual([]);
    });

    it("drops a 64-bit mask that is larger than any address at all", () => {
      // `or rbx, 0xffffffffffffffff` was reported as a reference to
      // 0x10000000000000000 — past the end of the 64-bit address space.
      expect(targets(insn("or", "rbx, 0xffffffffffffffff", BASE))).toEqual([]);
    });

    it("drops an A64 alignment mask", () => {
      expect(targets(insn("and", "x5, x5, #0xfffffffffffffff0", BASE, 4))).toEqual([]);
    });

    it("drops a constant below the image base", () => {
      // `mov ebx, 0x4100000` in an image based at 0x140000000.
      expect(targets(insn("mov", "ebx, 0x4100000", BASE))).toEqual([]);
    });

    it("drops an NTSTATUS constant compared against", () => {
      // STATUS_ACCESS_VIOLATION, which is neither an address nor near one.
      expect(targets(insn("cmp", "dword ptr [rax], 0xc0000005", BASE))).toEqual([]);
    });

    it("keeps an absolute memory operand inside the image", () => {
      expect(targets(insn("mov", "eax, dword ptr [0x140010100]", BASE))).toEqual([0x140010100]);
    });

    it("keeps the image base itself and drops the byte past the end", () => {
      expect(targets(insn("mov", "eax, 0x140000000", BASE))).toEqual([0x140000000]);
      expect(targets(insn("mov", "eax, 0x140020fff", BASE))).toEqual([0x140020fff]);
      expect(targets(insn("mov", "eax, 0x140021000", BASE))).toEqual([]);
    });

    it("still applies the 0x10000 floor to an image mapped low", () => {
      const low = { base: 0, size: 0x100000 };
      expect(buildTypedXrefMap([insn("mov", "eax, 0x100", BASE)], low)).toEqual([]);
      expect(buildTypedXrefMap([insn("mov", "eax, 0x20000", BASE)], low).map(([a]) => a)).toEqual([
        0x20000,
      ]);
    });

    it("keeps every reference when no bounds are given", () => {
      // "Nobody said where the image is" is not the same claim as "everything
      // is in range", so the unbounded call must not start dropping things.
      expect(buildTypedXrefMap([insn("or", "edx, 0xffffffff", BASE)]).map(([a]) => a)).toEqual([
        0xffffffff,
      ]);
    });

    it("does not bound a direct branch, whose destination is stated", () => {
      // A `call` outside the image is a fact about the file, not a misread
      // constant, and the same goes for an A64 branch.
      expect(targets(insn("call", "0x7ff900001000", BASE))).toEqual([0x7ff900001000]);
      expect(targets(insn("b", "#0x7ff900001000", BASE, 4))).toEqual([0x7ff900001000]);
    });

    it("does not bound a rip-relative displacement, which is computed not guessed", () => {
      const far = insn("lea", "rax, [rip + 0x7ffffff0]", BASE, 7);
      expect(targets(far)).toEqual([BASE + 7 + 0x7ffffff0]);
    });
  });

  // ── A64 ──
  // Every instruction and operand string below is copied verbatim out of
  // t64-arm.exe as Capstone prints it. Before the fix, all of them produced a
  // single `type: "data"` xref: an A64 branch writes `#0x…`, which matches
  // neither the `^0x…$` direct form nor `resolveRipTarget`, but does satisfy
  // the loose hex scan's `!mn.startsWith("j")` guard — so all 7263 xrefs in
  // t64-arm.exe were reported as data references to something that is code.
  //
  // The assertions are `toEqual` on the whole result on purpose: they pin the
  // type AND the absence of a second, data-typed xref for the same target.
  describe("ARM64 branches", () => {
    const A = 0x140001000;
    const a64 = (mnemonic: string, opStr: string, address = A) => insn(mnemonic, opStr, address, 4);

    it("classifies bl as a call xref", () => {
      expect(buildTypedXrefMap([a64("bl", "#0x140003160")])).toEqual([
        [0x140003160, [{ from: A, type: "call" }]],
      ]);
    });

    it("classifies b as a jmp xref", () => {
      expect(buildTypedXrefMap([a64("b", "#0x140001210")])).toEqual([
        [0x140001210, [{ from: A, type: "jmp" }]],
      ]);
    });

    it("classifies every b.<cond> form as a branch xref", () => {
      for (const mn of ["b.eq", "b.ne", "b.lo", "b.hs", "b.hi", "b.ls", "b.gt", "b.le", "b.al"]) {
        expect(buildTypedXrefMap([a64(mn, "#0x140001018")])).toEqual([
          [0x140001018, [{ from: A, type: "branch" }]],
        ]);
      }
    });

    it("classifies cbz and cbnz as branch xrefs", () => {
      expect(buildTypedXrefMap([a64("cbz", "x3, #0x140001164")])).toEqual([
        [0x140001164, [{ from: A, type: "branch" }]],
      ]);
      expect(buildTypedXrefMap([a64("cbnz", "w0, #0x140001164")])).toEqual([
        [0x140001164, [{ from: A, type: "branch" }]],
      ]);
    });

    it("classifies the three-operand tbz and tbnz as branch xrefs", () => {
      expect(buildTypedXrefMap([a64("tbz", "w2, #2, #0x14000114c")])).toEqual([
        [0x14000114c, [{ from: A, type: "branch" }]],
      ]);
      expect(buildTypedXrefMap([a64("tbnz", "w2, #1, #0x14000114c")])).toEqual([
        [0x14000114c, [{ from: A, type: "branch" }]],
      ]);
    });

    it("groups A64 references to one target the way the x86 path does", () => {
      expect(
        buildTypedXrefMap([
          a64("bl", "#0x140001164", A),
          a64("b", "#0x140001164", A + 4),
          a64("cbz", "x3, #0x140001164", A + 8),
        ]),
      ).toEqual([
        [
          0x140001164,
          [
            { from: A, type: "call" },
            { from: A + 4, type: "jmp" },
            { from: A + 8, type: "branch" },
          ],
        ],
      ]);
    });

    // Passes before the fix as well: an indirect branch has no literal address
    // for the loose scan to pick up either. Pinned so that a later "resolve the
    // register" attempt cannot quietly start emitting a guessed target — a
    // missing edge is a gap, a wrong edge is a lie nothing downstream detects.
    it("records nothing for an indirect branch or call", () => {
      expect(buildTypedXrefMap([a64("br", "x8")])).toEqual([]);
      expect(buildTypedXrefMap([a64("blr", "x2")])).toEqual([]);
      expect(buildTypedXrefMap([a64("braa", "x16, x17")])).toEqual([]);
    });

    // Passes before and after. `ret` is the one mnemonic the two architectures
    // spell the same way, and it is deliberately left on the x86 path, where
    // both produce nothing (x86 `ret imm16` cannot exceed 0xffff, so the loose
    // scan's `> 0x10000` guard rejects it).
    it("records nothing for a return on either architecture", () => {
      expect(buildTypedXrefMap([a64("ret", "")])).toEqual([]);
      expect(buildTypedXrefMap([a64("ret", "x30")])).toEqual([]);
      expect(buildTypedXrefMap([insn("ret", "0x10", BASE, 3)])).toEqual([]);
    });

    // Passes before and after — this is the direction the fix must NOT change.
    // `adrp`+`add` is how A64 materialises an address, and 681 of t64-arm.exe's
    // xrefs come from it; a literal-pool `ldr` is likewise a data reference.
    it("still records a materialised address as a data xref", () => {
      expect(buildTypedXrefMap([a64("adrp", "x16, #0x140027000")])).toEqual([
        [0x140027000, [{ from: A, type: "data" }]],
      ]);
      expect(buildTypedXrefMap([a64("adr", "x8, #0x1400018b0")])).toEqual([
        [0x1400018b0, [{ from: A, type: "data" }]],
      ]);
      expect(buildTypedXrefMap([a64("ldr", "s10, #0x140025b74")])).toEqual([
        [0x140025b74, [{ from: A, type: "data" }]],
      ]);
    });

    // Passes before and after. The classifier matches by exact mnemonic, so
    // these keep the data path they have always had; a prefix test on "b" or
    // "br" would sweep them up (t64-arm.exe contains 18 `brk`).
    it("does not treat brk or the bitfield mnemonics as branches", () => {
      expect(buildTypedXrefMap([a64("brk", "#0xf000")])).toEqual([]);
      expect(buildTypedXrefMap([a64("bfi", "w0, w1, #0, #8")])).toEqual([]);
      expect(buildTypedXrefMap([a64("bfxil", "x0, x1, #0, #0x20")])).toEqual([]);
      expect(buildTypedXrefMap([a64("bic", "x8, x8, #0xff000000")])).toEqual([
        [0xff000000, [{ from: A, type: "data" }]],
      ]);
    });

    // Passes before and after: the x86 half of the disjointness claim. None of
    // these is an A64 mnemonic, so none may be diverted off the x86 path.
    it("leaves x86 mnemonics that begin with b on the data path", () => {
      for (const mn of ["bt", "bts", "bsf", "bsr", "bswap"]) {
        expect(buildTypedXrefMap([insn(mn, "eax, dword ptr [0x404000]", BASE)])).toEqual([
          [0x404000, [{ from: BASE, type: "data" }]],
        ]);
      }
    });
  });
});

describe("buildAllXrefs", () => {
  const cs = fakeCs();

  it("returns empty maps for an empty image", () => {
    expect(buildAllXrefs(new Uint8Array(0), BASE, true, [], [], cs)).toEqual({
      stringXrefs: [],
      importXrefs: [],
      callGraph: [],
      dataXrefs: [],
    });
  });

  it("records a string reference behind a rip-relative operand", () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x10)] });
    const strAddr = BASE + 6 + 0x10;
    const { stringXrefs } = buildAllXrefs(img, BASE, true, [strAddr], [], cs);
    expect(stringXrefs).toEqual([[strAddr, [BASE]]]);
  });

  it("records an import reference behind a rip-relative operand", () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x20)] });
    const iatAddr = BASE + 6 + 0x20;
    const { importXrefs } = buildAllXrefs(img, BASE, true, [], [iatAddr], cs);
    expect(importXrefs).toEqual([[iatAddr, [BASE]]]);
  });

  it("builds a call graph edge between two known functions", () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3], 0x10: [0xc3] });
    const { callGraph } = buildAllXrefs(img, BASE, true, [], [], cs, [
      [BASE, 0x10],
      [BASE + 0x10, 0x10],
    ]);
    expect(callGraph).toEqual([[BASE, [BASE + 0x10]]]);
  });

  it("does not record a call to an address that is not a known function", () => {
    const img = image(0x20, { 0x00: callTo(0x00, BASE + 0x10), 0x05: [0xc3] });
    const { callGraph } = buildAllXrefs(img, BASE, true, [], [], cs, [[BASE, 0x10]]);
    expect(callGraph).toEqual([]);
  });

  it("records data xrefs into declared data sections", () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x1000)] });
    const dataAddr = BASE + 6 + 0x1000;
    const { dataXrefs } = buildAllXrefs(img, BASE, true, [], [], cs, undefined, [
      { va: dataAddr - 0x10, size: 0x100 },
    ]);
    expect(dataXrefs.map(([addr]) => addr)).toContain(dataAddr);
  });

  it("does not double-count a string address as a data xref", () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x1000)] });
    const target = BASE + 6 + 0x1000;
    const { dataXrefs } = buildAllXrefs(img, BASE, true, [target], [], cs, undefined, [
      { va: target, size: 0x10 },
    ]);
    expect(dataXrefs).toEqual([]);
  });

  it("ignores data sections when none are supplied", () => {
    const img = image(6, { 0: [0xff, 0x25, ...le32(0x1000)] });
    expect(buildAllXrefs(img, BASE, true, [], [], cs).dataXrefs).toEqual([]);
  });
});
