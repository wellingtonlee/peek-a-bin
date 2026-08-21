/**
 * The `push <imm>` / `pop <reg>` pairing rule — MSVC's two-byte `mov reg, imm`.
 *
 * `push 7` / `pop ecx` is two bytes against the five of `mov ecx, 7`, so MSVC
 * spells every small constant that way, and reading the pair as anything other
 * than a move loses a value the program states outright. Two callers a long way
 * apart need exactly the same answer:
 *
 * - `functionDetect.ts` sizes a jump table from the bound it is compared
 *   against, and that bound arrives in a register one step further back
 *   (peek-a-bin-mk42).
 * - `decompile/lifter.ts` lifts the `pop` as an assignment. Skipping it made the
 *   `pop` invisible to SSA, so every later read of the register bound to the
 *   value it held *before* the pop — `add edi, esi` emitted as `edi = edi`, and
 *   `*_errno() = 22` emitted as `*_errno() = 0` on a path a guard had just
 *   proved zero (peek-a-bin-3axd).
 *
 * This module is a **leaf**: it imports nothing, and in particular it has no
 * edge to `./capstoneWindow`, which loads Capstone WASM at module scope. That
 * is the whole reason the rule lives here rather than staying in
 * `functionDetect.ts` — `decompile/lifter.ts` has no Capstone edge and must not
 * gain one, because `decompileFunction` takes `Instruction[]` rather than bytes
 * and the end-to-end decompiler suite needs neither Capstone nor a worker. The
 * `sections.ts` / `ripRelative.ts` / `funcInsns.ts` precedent: one small pure
 * module owning one grammar, so there is one declaration of it.
 */

/**
 * The fields the pairing rule reads off an instruction.
 *
 * A structural subset of `./types`'s `Instruction`, so both callers pass their
 * own arrays with no cast and no conversion.
 */
export interface StackInsn {
  address: number;
  mnemonic: string;
  opStr: string;
  size: number;
}

/**
 * A lone immediate operand, hex or signed decimal — the `7` of `push 7`.
 *
 * The sign is not decoration. `6a fe` is `push imm8` sign-extended, and
 * **Capstone prints it as `push -2`**, not as `push 0xfffffffe` (which is what
 * objdump prints and what a reader of the byte stream expects). Refusing the
 * minus sign is therefore refusing a real push of a real constant on a spelling
 * technicality — 2 sites per x86 corpus binary, and at t32 0x4022FA it left the
 * `esi` reads at 0x402303 and 0x402327 naming `0x14`, the value ESI held before
 * the pop, which is the very defect the pairing is lifted for.
 *
 * Both callers are unaffected in the other direction. A negative jump-table
 * bound cannot survive `readAbsoluteTable`'s `maxCases <= 0` test, so
 * `functionDetect.ts` refuses such a table either way — with `null` before and
 * with a negative count now. Hex stays unsigned: Capstone spells a negative
 * immediate in decimal, so a hex operand here is a small positive one.
 */
export function loneImmediate(opStr: string): number | null {
  const t = opStr.trim();
  const hexMatch = t.match(/^0x([0-9a-fA-F]+)$/);
  if (hexMatch) return parseInt(hexMatch[1], 16);
  const decMatch = t.match(/^(-?\d+)$/);
  if (decMatch) return parseInt(decMatch[1], 10);
  return null;
}

/** Mnemonics that move the stack pointer, so a `pop` cannot be paired past them. */
export const STACK_TRAFFIC = new Set([
  "push",
  "pop",
  "pusha",
  "pushad",
  "popa",
  "popad",
  "pushf",
  "pushfd",
  "pushfq",
  "popf",
  "popfd",
  "popfq",
  "call",
  "ret",
  "retn",
  "retf",
  "leave",
  "enter",
  "int",
  "int3",
  "iret",
  "iretd",
]);

/**
 * The immediate a `pop` at `popIndex` takes off the stack, or null.
 *
 * The pairing is only claimed where nothing between the two instructions can
 * have moved the stack pointer or written through it: the first thing found
 * going back must be the `push`, and any other stack traffic — including an
 * `add esp, N`, a memory operand naming `esp`, or a `call`, which is both — ends
 * the search with no answer. Being one slot out here would report a bound the
 * program never checked, or assign a register a value the machine never put in
 * it.
 *
 * Running off the front of `insns` is also a refusal, and that is what confines
 * this function to a single basic block: a `pop` whose `push` is in another
 * block, and every save/restore pair, gets no answer *here*.
 *
 * "No answer here" is no longer "left exactly as it was", and the distinction
 * matters if you are reading this to find out what happens to such a `pop`.
 * `lifter.ts`'s `crossBlockPopImmediates` asks this same question of each
 * PREDECESSOR's tail — `pushedImmediate(pred.insns, pred.insns.length)` — and
 * puts a definition in each one so `buildSSA` builds the phi, because MSVC
 * routinely splits the idiom across an `if`/`else if` chain and the immediates
 * then differ per arm (peek-a-bin-6ilz).
 *
 * A save/restore pair is not left alone either, and it is NOT this module's
 * question: `lifter.ts`'s `matchedStackSlots` runs a balanced-depth model over
 * the whole CFG and pairs a `push <reg>` with the `pop` that takes it off the
 * stack, whatever register that pop names (peek-a-bin-6f3v). The two rules are
 * disjoint by construction — this one answers only for an IMMEDIATE push, that
 * one pairs only a REGISTER push — so no `pop` can be claimed by both.
 */
export function pushedImmediate(insns: StackInsn[], popIndex: number): number | null {
  for (let ri = popIndex - 1; ri >= 0; ri--) {
    const p = insns[ri];
    const mn = p.mnemonic.toLowerCase();
    if (mn === "push") return loneImmediate(p.opStr);
    if (STACK_TRAFFIC.has(mn)) return null;
    if (/\b[er]?sp\b/i.test(p.opStr)) return null;
  }
  return null;
}
