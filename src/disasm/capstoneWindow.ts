/**
 * Bounded access to the Capstone WASM decoder.
 *
 * capstone-wasm ships a WebAssembly module whose linear memory is a **fixed
 * 16 MiB that cannot grow** — its `emscripten_resize_heap` import calls
 * `abort()` without even trying (`dist/index.mjs`), and the module's declared
 * maximum equals its initial size, so `WebAssembly.Memory.grow(1)` fails. Both
 * resources a `cs_disasm` call consumes are therefore hard-capped, and the x86
 * scan loops were running right up against both caps:
 *
 *  * **The stack.** capstone-wasm passes the input buffer as an emscripten
 *    `array` argument, and emscripten's `ccall` implements that as
 *    `stackAlloc(bytes.length)` + `HEAP8.set` — the WASM *stack*, not the heap.
 *    That stack is ~65.6 KiB. Measured against the shipped `capstone.wasm`: a
 *    65536-byte window still decodes, a 66560-byte one throws `table index is
 *    out of bounds` and leaves the module dead — a one-byte `0x90` that decoded
 *    a moment earlier now decodes to nothing. `functionDetect.ts`'s
 *    `CHUNK_SIZE` was 0x10000, i.e. within 1 KiB of that cliff.
 *
 *  * **The heap.** `cs_disasm` allocates one contiguous `cs_insn[]` for the
 *    whole window — ~240 bytes per instruction — and grows it by doubling, so
 *    the ceiling is on the *instruction count*, not the byte count, and roughly
 *    half the 16 MiB is needed at the moment of a realloc. Measured: 22528
 *    one-byte instructions in a single call succeed; 23552 abort with
 *    `Aborted(OOM)`. A 0x10000-byte window of ordinary MSVC output decodes
 *    ~14900 instructions — 66% of that ceiling, with no margin for denser
 *    bytes. And dense bytes are ordinary: `00 00` decodes as
 *    `add byte ptr [rax], al`, two bytes, so a run of zeros inside a code
 *    section decodes at 32768 instructions per window.
 *
 * Going over is **silent**. `Capstone.disasm` throws when `cs_disasm` returns
 * zero, and every scan loop in this codebase treated a throw as "this byte is
 * not code, skip one" — the right reading for an undecodable byte and exactly
 * the wrong one for a dead engine. Measured end to end on a synthetic `.text`
 * of `[t64.exe .text][48 KiB of zeros][t64.exe .text]`: `disassemble()`
 * returned **0** instructions for a 168 KiB section (the first half alone
 * decodes 16999), **did not throw**, and afterwards a 64-byte buffer of `nop`
 * decoded to nothing and `new Capstone(...)` failed to initialise.
 *
 * So: nothing in this codebase calls `cs.disasm` directly any more. It goes
 * through {@link createScan}, which clamps every window to
 * {@link CS_WINDOW_BYTES} and every call to {@link CS_MAX_INSNS_PER_CALL}
 * instructions, and which probes the engine after a run of failed decodes so
 * that a dead decoder surfaces as a {@link CapstoneUnavailableError} instead of
 * a short instruction list that looks complete.
 *
 * Smaller windows are also *faster*, which was not the expected trade: over a
 * 4 MiB `.text` (t64.exe's, repeated to size) a 0x10000 window costs
 * 1101 ms/MiB and a 0x2000 window 934 ms/MiB — the giant contiguous allocation
 * and its doubling reallocs cost more than the extra calls do. Instruction
 * counts are identical at every window size.
 */

/**
 * The decoder is not usable. Thrown instead of returning a truncated or empty
 * list, because neither is distinguishable from a correct answer.
 *
 * Two ways to get here, one error type because callers can do nothing different
 * about them:
 *
 *  * `"exhausted"` — the engine decoded for a while and then stopped. A
 *    truncated list is indistinguishable from a small function.
 *  * `"uninitialised"` — there is no handle at all, because the WASM bootstrap
 *    has not resolved or failed. An *empty* list is indistinguishable from a
 *    section that contains no code (peek-a-bin-cen).
 */
export class CapstoneUnavailableError extends Error {
  constructor(where: string, reason: "exhausted" | "uninitialised" = "exhausted") {
    super(
      reason === "uninitialised"
        ? `Capstone is not initialised, so ${where} has no decoder. Returning ` +
            `an empty result would be indistinguishable from a section that ` +
            `holds no code. Wait for the decoder to load and retry.`
        : `Capstone stopped decoding during ${where}. The WebAssembly decoder's ` +
            `fixed 16 MiB memory is exhausted and every further decode returns ` +
            `nothing, so the disassembly would be silently incomplete. Reload the ` +
            `page to get a fresh decoder.`,
    );
    this.name = "CapstoneUnavailableError";
  }
}

/**
 * The handle, or a {@link CapstoneUnavailableError} — for the stages whose whole
 * output is instructions.
 *
 * A stage that can produce a correct answer without a decoder must NOT use this:
 * function detection has `.pdata`, exports, the entry point and unwind handlers
 * to go on, and returning those with no call targets is a smaller claim than
 * returning nothing. A stage whose entire result is what the decoder produced
 * has no such fallback, and silently returning `[]` is what this exists to stop.
 */
export function requireCapstone(
  cs: CapstoneHandle | null | undefined,
  where: string,
): CapstoneHandle {
  if (!cs) throw new CapstoneUnavailableError(where, "uninitialised");
  return cs;
}

/**
 * Bytes handed to Capstone in one `cs_disasm` call.
 *
 * 8 KiB: 12% of the ~65.6 KiB stack cliff, and at most 8192 instructions even
 * if every byte decodes to a one-byte instruction, which is 36% of the measured
 * ~23000-instruction heap ceiling. See the module docstring for the
 * measurements and for why this is not a throughput cost.
 */
export const CS_WINDOW_BYTES = 0x2000;

/**
 * Instructions Capstone may return from one call.
 *
 * The second, independent bound: `cs_disasm`'s `count` argument caps the
 * `cs_insn[]` it allocates, so the heap cost of a call is bounded at ~480 KiB
 * regardless of how dense the bytes turn out to be. On real code it never
 * binds — a 8 KiB window of compiler output is ~1900 instructions — so this
 * only ever splits a window that was going to be expensive anyway, and the scan
 * loop resumes from where the count cut it off.
 */
export const CS_MAX_INSNS_PER_CALL = 2048;

/**
 * Consecutive failed decodes before the engine itself is probed.
 *
 * A failed decode is an ordinary event (data inside a code section), so the
 * probe cannot run on every one of them: it costs ~4.6 µs. A *dead* engine
 * fails every decode, so 64 in a row bounds what can be lost before the probe
 * fires at 64 bytes, and the interval doubles after each passing probe so that
 * a genuinely undecodable megabyte costs O(log n) probes rather than O(n).
 */
const PROBE_AFTER_FAILURES = 64;

/** `Const.CS_ARCH_ARM64`, inlined and re-exported: importing `capstone-wasm` for one number
 *  would load the WASM module at module scope in every test that reaches this
 *  file, which is the trap `src/mcp/__tests__/importGraph.test.ts` guards. */
export const CS_ARCH_ARM64 = 1;

/** `nop`. One byte on x86; `d503201f` on A64, which must be 4-byte aligned. */
const X86_NOP = new Uint8Array([0x90]);
const ARM64_NOP = new Uint8Array([0x1f, 0x20, 0x03, 0xd5]);

/**
 * The instruction shape Capstone hands back. Structural rather than imported:
 * `capstone-wasm`'s own declarations are unreachable under bundler resolution
 * (see `src/capstone-wasm.d.ts`), and importing the package for a type would
 * load the WASM module at module scope in every test that reaches this file.
 */
export interface RawInsn {
  address: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
  size: number;
}

/**
 * The part of a `Capstone` handle a scan uses. `arch` is optional because the
 * only thing it selects is which `nop` the liveness probe sends.
 */
export interface CapstoneHandle {
  arch?: number;
  disasm(code: Uint8Array, options?: { address?: number; count?: number }): RawInsn[];
}

/**
 * Does this handle still decode something it must decode?
 *
 * The only reliable liveness signal available: an exhausted module does not
 * report anything, it just stops producing instructions, and `nop` is the one
 * encoding guaranteed to decode on a healthy handle.
 */
export function capstoneDecodes(cs: CapstoneHandle | null | undefined): boolean {
  if (!cs) return false;
  const probe = cs.arch === CS_ARCH_ARM64 ? ARM64_NOP : X86_NOP;
  try {
    const insns = cs.disasm(probe, { address: 0, count: 1 });
    return !!insns && insns.length > 0;
  } catch {
    return false;
  }
}

/** One bounded scan over a byte range. Callers never touch `cs.disasm`. */
export interface CapstoneScan {
  /**
   * Decode forward from `offset`, never handing Capstone more than
   * {@link CS_WINDOW_BYTES} and never asking for more than `maxInsns`
   * instructions.
   *
   * Returns `[]` when the bytes at `offset` genuinely do not decode — the
   * caller's job is then to advance and try again. Throws
   * {@link CapstoneUnavailableError} when the failures are the engine's rather
   * than the bytes'.
   */
  decode(bytes: Uint8Array, offset: number, limit: number, address: number): RawInsn[];
  /** As {@link decode}, but only the first instruction is wanted. */
  decodeOne(bytes: Uint8Array, offset: number, limit: number, address: number): RawInsn[];
}

/**
 * Open a bounded scan against `cs`.
 *
 * `where` names the caller in a {@link CapstoneUnavailableError}. `window`
 * overrides {@link CS_WINDOW_BYTES} downward — the ARM64 sweep uses a smaller
 * one for reasons of its own — and is clamped, so no caller can widen it.
 */
export function createScan(
  cs: CapstoneHandle,
  where: string,
  window: number = CS_WINDOW_BYTES,
): CapstoneScan {
  const width = Math.max(1, Math.min(window, CS_WINDOW_BYTES));
  let consecutiveFailures = 0;
  let probeAt = PROBE_AFTER_FAILURES;

  function run(
    bytes: Uint8Array,
    offset: number,
    limit: number,
    address: number,
    maxInsns: number,
  ): RawInsn[] {
    const end = Math.min(offset + width, limit, bytes.length);
    if (end <= offset) return [];
    let insns: RawInsn[] | undefined;
    try {
      insns = cs.disasm(bytes.subarray(offset, end), { address, count: maxInsns });
    } catch {
      // capstone-wasm throws rather than returning an empty list when the first
      // byte is not a valid encoding, which in a `.text` full of padding and
      // literal data is an ordinary event and not an error.
      insns = undefined;
    }
    if (insns && insns.length > 0) {
      consecutiveFailures = 0;
      probeAt = PROBE_AFTER_FAILURES;
      return insns;
    }
    if (++consecutiveFailures >= probeAt) {
      probeAt *= 2;
      if (!capstoneDecodes(cs)) throw new CapstoneUnavailableError(where);
    }
    return [];
  }

  return {
    decode: (bytes, offset, limit, address) =>
      run(bytes, offset, limit, address, CS_MAX_INSNS_PER_CALL),
    decodeOne: (bytes, offset, limit, address) => run(bytes, offset, limit, address, 1),
  };
}
