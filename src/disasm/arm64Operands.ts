/**
 * A64 operand grammar: branches, and the two-instruction address idiom.
 *
 * The x86 side of this already learned the lesson twice — `ripRelative.ts`
 * exists because `[rip ± 0x..]` had been hand-rolled at nine call sites with
 * two different regexes, and `components/shared.tsx` owns `parseBranchTarget`
 * because it had been copied into `JumpArrows.tsx`. ARM64 arrived with the same
 * pressure: `buildCFG`, the jump-arrow overlay and the xref builder each need
 * to know "is this a branch, and where does it go", and each of them had an
 * x86-shaped answer hard-coded. So there is exactly one A64 grammar, here.
 *
 * ── Why no `arch` parameter ──
 * The mnemonics matched here are disjoint from x86's. x86 has no `b`, `bl`,
 * `br`, `blr`, `cbz`, `cbnz`, `tbz`, `tbnz`, and no mnemonic containing a `.`
 * (which is how the conditional forms `b.eq` … `b.nv` are spelled); A64 has no
 * mnemonic starting with `j`. That is what lets a call site keep its x86 path
 * byte-for-byte and add an A64 fallback, rather than thread an architecture
 * through `buildCFG` and every component that calls it. The one shared spelling
 * is `ret`, and both architectures want the same answer for it: no successors.
 *
 * Matching is by EXACT mnemonic, never by prefix. `brk #1` is a breakpoint, not
 * a `br`; `bfi`/`bfxil` are bitfield inserts, not branches. A prefix test on
 * `"br"` would sweep up `brk`, of which t64-arm.exe has 18.
 *
 * ── The standard this module holds to ──
 * An indirect branch (`br x8`, `blr x2`) has no statically known target, and a
 * target this parser does not recognise is reported as no target rather than a
 * guess. Callers must render that as "no edge", not as an edge to address 0 or
 * to the fallthrough. A missing edge is a visible gap; a wrong edge is a lie
 * about control flow that nothing downstream can detect.
 */

/** What kind of control transfer an A64 instruction performs. */
export type Arm64BranchKind =
  /** Unconditional transfer, one successor: `b`, `br`. */
  | "jump"
  /** Conditional transfer, two successors: `b.<cc>`, `cbz`, `cbnz`, `tbz`, `tbnz`. */
  | "cond"
  /** Call — control returns, so it does not end a basic block: `bl`, `blr`. */
  | "call"
  /** Return: `ret`, and the pointer-authenticated `retaa` / `retab`. */
  | "return";

export interface Arm64Branch {
  kind: Arm64BranchKind;
  /**
   * Absolute target address, or `null` when there is none to be had: an
   * indirect branch through a register, a return, or an operand string this
   * parser declines to read. Never a guess.
   */
  target: number | null;
  /** True when the transfer goes through a register, so no static target exists. */
  indirect: boolean;
}

/** `b` — the only unconditional direct branch. */
const DIRECT_JUMP: ReadonlySet<string> = new Set(["b"]);

/**
 * Indirect branch through a register, including the FEAT_PAuth authenticated
 * forms. All of these end a block with no successor this module can name.
 */
const INDIRECT_JUMP: ReadonlySet<string> = new Set(["br", "braa", "braaz", "brab", "brabz"]);

/** `bl` — direct call. */
const DIRECT_CALL: ReadonlySet<string> = new Set(["bl"]);

/** Indirect call through a register, plus the authenticated forms. */
const INDIRECT_CALL: ReadonlySet<string> = new Set(["blr", "blraa", "blraaz", "blrab", "blrabz"]);

/** `ret x30` is the same thing as `ret`; `retaa`/`retab` authenticate first. */
const RETURN: ReadonlySet<string> = new Set(["ret", "retaa", "retab"]);

/**
 * Compare-and-branch: `cbz w2, #0x140001514`. Two operands, target last.
 * Test-and-branch: `tbz w2, #2, #0x14000114c`. Three operands, target last.
 */
const COMPARE_BRANCH: ReadonlyMap<string, number> = new Map([
  ["cbz", 2],
  ["cbnz", 2],
  ["tbz", 3],
  ["tbnz", 3],
]);

/**
 * The 16 condition codes A64 spells after `b.`, plus `al`/`nv`.
 *
 * Enumerated rather than matched as "anything after a dot" so that a future
 * Capstone spelling — or a mis-decoded word — cannot be read as a branch just
 * because it contains a period.
 */
const CONDITIONS: ReadonlySet<string> = new Set([
  "eq",
  "ne",
  "cs",
  "hs",
  "cc",
  "lo",
  "mi",
  "pl",
  "vs",
  "vc",
  "hi",
  "ls",
  "ge",
  "lt",
  "gt",
  "le",
  "al",
  "nv",
]);

/** A whole operand field that is a branch destination: `#0x140001018`. */
const TARGET_FIELD = /^#(0x[0-9a-fA-F]+)$/;

/** Split an operand string into trimmed comma-separated fields. */
function fields(opStr: string): string[] {
  const trimmed = opStr.trim();
  if (trimmed === "") return [];
  return trimmed.split(",").map((f) => f.trim());
}

/**
 * The branch destination held in the last of exactly `arity` operand fields.
 *
 * The arity check is the point: `cbz` has a register and a target, `tbz` has a
 * register, a bit number and a target. Reading "the last field that looks like
 * an address" without counting would accept a decode this parser has not
 * actually understood, and produce a confident edge from it.
 */
function targetAt(opStr: string, arity: number): number | null {
  const parts = fields(opStr);
  if (parts.length !== arity) return null;
  const m = parts[arity - 1].match(TARGET_FIELD);
  return m ? Number(m[1]) : null;
}

/** True for a `b.<cond>` mnemonic with a condition code A64 actually defines. */
export function isArm64ConditionalBranch(mnemonic: string): boolean {
  return mnemonic.startsWith("b.") && CONDITIONS.has(mnemonic.slice(2));
}

/**
 * Classify an A64 control-transfer instruction, or `null` if it is not one.
 *
 * `null` means "this module has nothing to say", which is the answer for every
 * x86 instruction as well as for every A64 instruction that is not a branch.
 */
export function classifyArm64Branch(mnemonic: string, opStr: string): Arm64Branch | null {
  if (RETURN.has(mnemonic)) return { kind: "return", target: null, indirect: false };

  if (INDIRECT_JUMP.has(mnemonic)) return { kind: "jump", target: null, indirect: true };
  if (INDIRECT_CALL.has(mnemonic)) return { kind: "call", target: null, indirect: true };

  if (DIRECT_JUMP.has(mnemonic)) {
    return { kind: "jump", target: targetAt(opStr, 1), indirect: false };
  }
  if (DIRECT_CALL.has(mnemonic)) {
    return { kind: "call", target: targetAt(opStr, 1), indirect: false };
  }
  if (isArm64ConditionalBranch(mnemonic)) {
    return { kind: "cond", target: targetAt(opStr, 1), indirect: false };
  }

  const arity = COMPARE_BRANCH.get(mnemonic);
  if (arity !== undefined) {
    return { kind: "cond", target: targetAt(opStr, arity), indirect: false };
  }

  return null;
}

/**
 * True for an A64 instruction that transfers control the way a jump arrow
 * draws: a jump or a conditional branch, but NOT a call.
 *
 * The x86 analogue of this test is `mnemonic.startsWith("j")`, which excludes
 * `call` for a reason `JumpArrows.tsx` documents: a recursive or intra-function
 * call lands inside the drawn window and would sprout an arrow the view never
 * had. `bl` is that same call, so it is excluded here too.
 */
export function isArm64JumpMnemonic(mnemonic: string): boolean {
  const b = classifyArm64Branch(mnemonic, "");
  return b !== null && (b.kind === "jump" || b.kind === "cond");
}

// ── Address materialisation ────────────────────────────────────────────────

/**
 * The A64 answer to `[rip ± 0x..]`.
 *
 * A64 instructions are 32 bits wide, so no single one can carry a 64-bit
 * address. An address is built in two steps: `adrp xN, #page` puts the
 * 4 KiB-aligned page containing the target into xN (Capstone prints the
 * resolved page, not the raw immediate), and then either
 *
 *   `add xN, xN, #off`        — xN now holds page+off, the address itself, or
 *   `ldr xM, [xN, #off]`      — xM now holds the *contents* of page+off.
 *
 * `adr xN, #addr` is the one-instruction form, reaching ±1 MiB.
 *
 * A reference is therefore a PAIR of instructions, not an operand, which is why
 * the x86 xref builder finds nothing here: there is no literal address in
 * either instruction's operands to match against.
 */
export interface Arm64AddrInsn {
  address: number;
  mnemonic: string;
  opStr: string;
}

export interface Arm64AddrRef {
  /** Address of the instruction that COMPLETES the materialisation. */
  from: number;
  /** The absolute address referred to. */
  target: number;
  /** Address of the `adrp` that began the pair; absent for a one-instruction `adr`. */
  pairFrom?: number;
  /**
   * True when the completing instruction dereferences `target` (the `ldr` form)
   * rather than producing it as a value (the `add`/`adr` forms).
   *
   * This is the difference between "points at a string" and "loads a function
   * pointer out of the IAT", so the two must not be conflated.
   */
  load: boolean;
}

/** Register-name mention test that does not confuse `x1` with `x16`. */
function mentionsReg(opStr: string, reg: string): boolean {
  const bare = reg.slice(1);
  return new RegExp(`\\b[xw]${bare}\\b`).test(opStr);
}

/** `adrp x16, #0x140027000` / `adr x8, #0x1400018b0` → the printed address. */
function adrOperand(opStr: string): { reg: string; value: number } | null {
  const parts = fields(opStr);
  if (parts.length !== 2) return null;
  if (!/^x\d{1,2}$/.test(parts[0])) return null;
  const m = parts[1].match(TARGET_FIELD);
  if (!m) return null;
  return { reg: parts[0], value: Number(m[1]) };
}

/** `#0x20` and `#8` are both legal immediates; Capstone prints either. */
function immediate(field: string): number | null {
  if (!field.startsWith("#")) return null;
  const body = field.slice(1);
  const value = /^0x[0-9a-fA-F]+$/.test(body)
    ? Number(body)
    : /^\d+$/.test(body)
      ? Number(body)
      : null;
  return value;
}

/** Load/store mnemonics whose base register can complete an `adrp`. */
const MEM_ACCESS = /^(ldr|ldrb|ldrh|ldrsb|ldrsh|ldrsw|ldur|str|strb|strh|stur)$/;

/**
 * How far past an `adrp` to look for the instruction that completes it.
 *
 * The pair is adjacent in every compiler-generated sequence, but a scheduler
 * may sink the `add` a few slots. The scan stops at the first instruction that
 * mentions the register at all (see below), so this bound only limits how long
 * an untouched binding survives.
 */
const PAIR_WINDOW = 8;

/**
 * Absolute addresses materialised by `adr`, `adrp`+`add` and `adrp`+`ldr`.
 *
 * Deliberately a single-pass, single-basic-block reader with one rule for
 * giving up: after an `adrp xN, #page`, the FIRST later instruction that
 * mentions xN (in either its 64-bit or 32-bit spelling) either completes the
 * pair or kills it. Nothing is carried across a branch, and nothing is carried
 * past an instruction whose effect on the register this reader has not modelled.
 *
 * That rule is why there is no register-clobber table here, and why there does
 * not need to be. A table would have to be right about every A64 mnemonic's
 * destination operand to avoid reporting an address the register no longer
 * holds; "the next instruction to touch it decides" is right without knowing
 * anything, and the cost is only the references it declines to report.
 */
export function findArm64AddressRefs(insns: readonly Arm64AddrInsn[]): Arm64AddrRef[] {
  const refs: Arm64AddrRef[] = [];

  for (let i = 0; i < insns.length; i++) {
    const insn = insns[i];

    if (insn.mnemonic === "adr") {
      const op = adrOperand(insn.opStr);
      if (op) refs.push({ from: insn.address, target: op.value, load: false });
      continue;
    }
    if (insn.mnemonic !== "adrp") continue;

    const op = adrOperand(insn.opStr);
    if (!op) continue;

    for (let j = i + 1; j < insns.length && j <= i + PAIR_WINDOW; j++) {
      const next = insns[j];
      // Control flow may enter or leave here, so the binding is no longer this
      // block's to reason about.
      if (classifyArm64Branch(next.mnemonic, next.opStr) !== null) break;
      if (!mentionsReg(next.opStr, op.reg)) continue;

      const parts = fields(next.opStr);

      // `add xD, xN, #off` — xD holds page+off. One `adrp` commonly feeds
      // several of these (`add x1, x8, #0x480` … `add x2, x8, #0x4c0`), and an
      // add into a DIFFERENT register does not disturb the base, so the binding
      // survives it. Only `add xN, xN, #off` — the self-rebasing form — ends it.
      if (next.mnemonic === "add" && parts.length === 3 && parts[1] === op.reg) {
        const off = immediate(parts[2]);
        if (off !== null) {
          refs.push({
            from: next.address,
            target: op.value + off,
            pairFrom: insn.address,
            load: false,
          });
        }
        if (off === null || parts[0] === op.reg) break;
        continue;
      }

      // `ldr xD, [xN]` / `ldr xD, [xN, #off]` — a load from page+off; and the
      // store forms, which read the base and write memory. A load INTO the base
      // replaces it, and any writeback form (`[xN, #off]!`) increments it, so
      // both end the binding; everything else leaves it intact.
      if (MEM_ACCESS.test(next.mnemonic) && parts.length >= 2) {
        const mem = parts.slice(1).join(", ");
        const inner = mem.match(/^\[\s*(x\d{1,2})\s*(?:,\s*(#[^\]]+))?\s*\](!?)$/);
        if (inner && inner[1] === op.reg) {
          const off = inner[2] === undefined ? 0 : immediate(inner[2].trim());
          if (off !== null) {
            refs.push({
              from: next.address,
              target: op.value + off,
              pairFrom: insn.address,
              load: true,
            });
          }
          const isStore = next.mnemonic.startsWith("st");
          const writesBase = inner[3] === "!" || (!isStore && parts[0] === op.reg);
          if (off === null || writesBase) break;
          continue;
        }
        break;
      }

      // Anything else that touches the register: this reader does not know
      // what it left there, so the binding dies unreported.
      break;
    }
  }

  return refs;
}
