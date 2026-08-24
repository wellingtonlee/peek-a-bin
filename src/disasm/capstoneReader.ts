/**
 * A hand-written reader for capstone-wasm's `cs_insn`, and the owner of the
 * emscripten Module it reads through.
 *
 * **WHY THIS EXISTS.** Measured at `488ddde` over eight images (48 KiB to
 * 3817 KiB of `.text`, 15504 to 1047308 instructions), capstone-wasm's
 * per-instruction cost is **83-86% JS marshalling and ~16% decode**: a full
 * `Capstone.prototype.disasm` is 3.09-3.81 µs/instruction, while `cs_disasm`
 * plus every `ccall` it makes and *zero* per-instruction JS is 0.51-0.60 µs.
 * The cost was attributed by name and not only by subtraction — the dependency's
 * own `Capstone.readInsn`, called directly, lands on the full figure. The single
 * dominant component is `readStruct`'s accumulator,
 * `fields.reduce((obj, field) => ({ ...obj, [field.name]: value }), {})`: a
 * computed key defeats V8's fast object path and costs ~1.5-1.8 µs/instruction
 * on its own, roughly **three times the decoder**. Since `peek-a-bin-x40u`,
 * `peek-a-bin-iqzu` and `peek-a-bin-kis` every consumer shares one decode per
 * section, so that cost is the load's dominant term and this reader takes ~3x
 * off it at a stroke (peek-a-bin-62zy, peek-a-bin-fdi8).
 *
 * **WHERE IT SITS, and why it is not in `capstoneWindow.ts`.** This is a
 * *decoder*, occupying exactly the position `Capstone.prototype.disasm`
 * occupied — it is the thing being windowed, not the thing that windows. It
 * does no clamping and must not: {@link createScan} has already bounded the
 * window and the instruction count before a byte reaches here, and a second
 * bound in this file would be a second opinion about the two measured WASM
 * ceilings. Every product path reaches this reader as the {@link CapstoneHandle}
 * given to `createScan`, never directly; `capstoneWindow.ts` stays a module
 * about *bounds* with no knowledge of any struct layout. The drift guard in
 * `capstoneWindow.test.ts` is widened to match: no file under `src/` outside
 * this one may name `cs_disasm`, and none outside it may call `loadCapstone`.
 *
 * **THE HAZARD, stated plainly.** The offsets below are the bundled capstone
 * build's ABI, hard-coded. A capstone-wasm version bump can change them
 * **silently**, and a wrong offset does not throw — it produces plausible
 * garbage on every instruction in the tool. The mitigation is
 * `__tests__/capstoneReader.test.ts`, which decodes real byte sequences through
 * both readers and compares every field; it cannot read vacuously (it asserts a
 * non-zero instruction count) and it is negative-controlled by handing
 * {@link fastCapstoneHandle} a perturbed {@link CsInsnAbi}. A *runtime*
 * self-check is deliberately **not** added: it would be a new way for startup to
 * fail, on a decoder the whole tool is downstream of, to catch a change that
 * only ever arrives with a `package.json` edit — which is exactly when a test
 * runs. Keep the test; do not move the check into the product.
 *
 * **TWO BEHAVIOUR DELTAS, both bounded and both deliberate.**
 *
 *  * `bytes` is a slice of exactly `size`, where capstone-wasm slices a fixed
 *    24 bytes and `subarray`s that to `size`. The *contents*, the length and the
 *    zero `byteOffset` are identical; only `bytes.buffer.byteLength` differs
 *    (`size` rather than 24), which makes it smaller over `postMessage`. Do not
 *    add a test on that length in either direction — CLAUDE.md's `gridScan`
 *    gotcha records that an exact-length assertion wrongly calls all 18045 of
 *    t32's capstone-decoded instructions defects.
 *  * A window that decodes nothing returns `[]` where capstone-wasm throws.
 *    Both of this module's readers are consumed only by `capstoneWindow.ts`, and
 *    both of its call sites already collapse the two: `createScan`'s `run`
 *    catches the throw into `insns = undefined` and then takes the same branch
 *    as an empty list, and `capstoneDecodes` catches it into `false`, which is
 *    what an empty list yields too. So the engine-death probe is untouched —
 *    a failed decode still increments `consecutiveFailures` and still fires the
 *    probe at 64 — and the change only removes an `Error` construction on the
 *    undecodable windows that a `.text` full of padding produces by the hundred.
 *
 * The address is **bit-for-bit** capstone-wasm's, pathological case included:
 * above `Number.MAX_SAFE_INTEGER` the dependency leaves a `BigInt` in a field
 * `RawInsn` types as `number`, and so does this. That is a pre-existing latent
 * issue in both readers and not one to fix here; matching it exactly is what
 * lets the differential test compare addresses with no exception.
 */

import { loadCapstone } from "capstone-wasm";
import type { CapstoneHandle, RawInsn } from "./capstoneWindow";

/**
 * The part of the emscripten Module this reader uses.
 *
 * Structural, and reachable because capstone-wasm's factory opens with
 * `var Module = moduleArg`: the object handed to `loadCapstone` **is** the
 * Module, populated in place by the time its promise resolves
 * (`readyPromiseResolve(Module)`).
 */
export interface CapstoneModule {
  ccall(name: string, returnType: string | null, argTypes: string[], args: unknown[]): number;
  getValue(ptr: number, type: string): number;
  UTF8ToString(ptr: number, maxBytesToRead?: number): string;
  HEAPU8: Uint8Array;
  HEAPU32: Uint32Array;
  HEAP16: Int16Array;
}

/**
 * The part of a `capstone-wasm` `Capstone` this reader needs: the `cs_open`
 * handle it decodes against, and the arch the liveness probe selects a `nop`
 * with. Structural for `capstoneWindow.ts`'s reason — the package's own
 * declarations are unreachable under bundler resolution.
 */
export interface OpenCapstone {
  readonly arch?: number;
  readonly handle: number;
  disasm(code: Uint8Array, options?: { address?: number; count?: number }): RawInsn[];
}

/**
 * Byte offsets within one `cs_insn`, and the stride between two.
 *
 * Derived from capstone-wasm's own `INSN_FIELDS` plus its `sizeOfStruct`
 * padding rule, then **verified against the shipped `capstone.wasm`** rather
 * than only computed: `id` i32 @0, `address` i64 @8 (4 bytes of padding after
 * `id`), `size` i16 @16, `bytes` 24 raw bytes @18, `mnemonic` 32-byte string
 * @42, `opStr` 160-byte string @74, and the detail pointer i32 @236 (2 bytes of
 * padding after `opStr`), giving a stride of 240.
 *
 * `id` and the detail pointer are not read: `RawInsn` carries neither, and
 * `CS_OPT_DETAIL` is off — nothing in this repo calls `setOption` and Capstone's
 * default is off, confirmed by reading offset 236 as 0 for every instruction
 * decoded on both ARM64 binaries and on the x86 fixtures here.
 *
 * Injectable only so the differential test can perturb one offset and show that
 * the test fails; product code always takes the default.
 */
export interface CsInsnAbi {
  /** Bytes from one `cs_insn` to the next. */
  readonly stride: number;
  /** `uint64_t address`. */
  readonly address: number;
  /** `uint16_t size`. */
  readonly size: number;
  /** `uint8_t bytes[24]`. */
  readonly bytes: number;
  readonly bytesMax: number;
  /** `char mnemonic[32]`, NUL-terminated. */
  readonly mnemonic: number;
  readonly mnemonicMax: number;
  /** `char op_str[160]`, NUL-terminated. */
  readonly opStr: number;
  readonly opStrMax: number;
}

export const CS_INSN_ABI: CsInsnAbi = Object.freeze({
  stride: 240,
  address: 8,
  size: 16,
  bytes: 18,
  bytesMax: 24,
  mnemonic: 42,
  mnemonicMax: 32,
  opStr: 74,
  opStrMax: 160,
});

/** `sizeof(void *)` in this build — emscripten wasm32. */
const POINTER_SIZE = 4;

/** `hi` at or below this cannot make the 64-bit value exceed `Number.MAX_SAFE_INTEGER`. */
const MAX_SAFE_HI = 0x1fffff;

const TWO_32 = 4294967296;

/**
 * Read a NUL-terminated string out of the heap.
 *
 * The fast path is ASCII, which every Capstone mnemonic and operand string is;
 * anything with a byte above 0x7f falls back to the Module's own
 * `UTF8ToString`, so the result is the dependency's for every input either way.
 */
function readCString(module: CapstoneModule, heap: Uint8Array, ptr: number, max: number): string {
  let n = 0;
  let out = "";
  while (n < max) {
    const c = heap[ptr + n];
    if (c === 0) break;
    if (c > 0x7f) return module.UTF8ToString(ptr, max);
    out += String.fromCharCode(c);
    n++;
  }
  return out;
}

/**
 * Wrap an open `Capstone` as a {@link CapstoneHandle} that marshals each
 * instruction by hand.
 *
 * The `ccall` sequence is capstone-wasm's own, argument for argument, so the
 * WASM-stack and heap costs of a call are exactly what they were — including
 * the `array` argument that emscripten copies onto the ~65.6 KiB stack, which is
 * the ceiling {@link CS_WINDOW_BYTES} exists to stay under.
 */
export function fastCapstoneHandle(
  module: CapstoneModule,
  cs: OpenCapstone,
  abi: CsInsnAbi = CS_INSN_ABI,
): CapstoneHandle {
  const {
    stride,
    address: oAddr,
    size: oSize,
    bytes: oBytes,
    bytesMax,
    mnemonic: oMnem,
    mnemonicMax,
    opStr: oOp,
    opStrMax,
  } = abi;

  function disasm(code: Uint8Array, options?: { address?: number; count?: number }): RawInsn[] {
    const address = options?.address ?? 0;
    const maxCount = options?.count ?? 0;
    const ptrPtr = module.ccall("malloc", "number", ["number"], [POINTER_SIZE]);
    const count = module.ccall(
      "cs_disasm",
      "number",
      ["number", "array", "number", "number", "number", "number"],
      [cs.handle, code, code.length, BigInt(address), maxCount, ptrPtr],
    );
    if (count === 0) {
      module.ccall("free", null, ["number"], [ptrPtr]);
      return [];
    }
    const first = module.getValue(ptrPtr, "*");
    // Read the heap views *after* the decode: emscripten replaces them wholesale
    // in `updateMemoryViews()` if the memory is ever swapped, and a view captured
    // before the call would then be detached. (This build cannot grow — its
    // `emscripten_resize_heap` aborts — so this is a bound, not a saving.)
    const u8 = module.HEAPU8;
    const u32 = module.HEAPU32;
    const i16 = module.HEAP16;
    const out: RawInsn[] = new Array(count);
    for (let i = 0; i < count; i++) {
      const p = first + i * stride;
      const lo = u32[(p + oAddr) >> 2];
      const hi = u32[(p + oAddr + 4) >> 2];
      const size = i16[(p + oSize) >> 1];
      const take = size < bytesMax ? size : bytesMax;
      out[i] = {
        address:
          hi <= MAX_SAFE_HI
            ? hi === 0
              ? lo
              : lo + hi * TWO_32
            : // Above MAX_SAFE_INTEGER capstone-wasm leaves a BigInt in this
              // field; match it rather than silently losing precision.
              (((BigInt(hi) << 32n) | BigInt(lo)) as unknown as number),
        bytes: u8.slice(p + oBytes, p + oBytes + take),
        mnemonic: readCString(module, u8, p + oMnem, mnemonicMax),
        opStr: readCString(module, u8, p + oOp, opStrMax),
        size,
      };
    }
    module.ccall("cs_free", null, ["number", "number"], [first, count]);
    module.ccall("free", null, ["number"], [ptrPtr]);
    return out;
  }

  return cs.arch === undefined ? { disasm } : { arch: cs.arch, disasm };
}

/**
 * The Module handed to {@link loadCapstone}, once it has been populated.
 *
 * Module scope because capstone-wasm's `loadCapstone` is itself a singleton — it
 * returns immediately once its internal `capstone` is set — so only the *first*
 * call can supply the object, and a second caller passing its own would get an
 * empty one back with no error. That is why {@link loadCapstoneModule} is the
 * one place in `src/` allowed to call `loadCapstone`, and why the drift guard
 * says so.
 */
let owned: CapstoneModule | null = null;

/** Every field the reader touches, present and of the right kind. */
function isPopulated(m: Partial<CapstoneModule>): m is CapstoneModule {
  return (
    typeof m.ccall === "function" &&
    typeof m.getValue === "function" &&
    typeof m.UTF8ToString === "function" &&
    m.HEAPU8 instanceof Uint8Array &&
    m.HEAPU32 instanceof Uint32Array &&
    m.HEAP16 instanceof Int16Array
  );
}

/**
 * Bootstrap capstone-wasm, retaining the emscripten Module.
 *
 * `overrides` is merged into the object handed to the factory, which is how the
 * worker supplies its `instantiateWasm` hook for the IndexedDB-cached module.
 *
 * Retention is **optional by construction**: if the factory declines to populate
 * the object — which it does whenever some earlier call already won the
 * singleton, including a racing attempt that failed late — `owned` stays null
 * and {@link capstoneHandle} falls back to the dependency's own reader. That is
 * a performance loss and never a correctness one, which is the right way round
 * for a bootstrap that has three paths and an error race.
 */
export async function loadCapstoneModule(overrides?: Record<string, unknown>): Promise<void> {
  const candidate = { ...(overrides ?? {}) } as Partial<CapstoneModule>;
  await loadCapstone(candidate as Record<string, unknown>);
  if (owned === null && isPopulated(candidate)) owned = candidate;
}

/** The retained Module, or null if the fast reader is unavailable. */
export function capstoneModule(): CapstoneModule | null {
  return owned;
}

/**
 * The reader every bootstrap site should hand to `createScan`: the fast one
 * where the Module was retained, and capstone-wasm's own otherwise.
 *
 * Both readers live in this module deliberately. Two decoders in a tree is
 * tolerable only while one place decides between them, or the fallback becomes
 * a second implementation nobody is measuring.
 */
export function capstoneHandle(cs: OpenCapstone): CapstoneHandle {
  return owned === null ? (cs as CapstoneHandle) : fastCapstoneHandle(owned, cs);
}
