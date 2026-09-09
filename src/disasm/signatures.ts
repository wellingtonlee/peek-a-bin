import type { ImageArch } from "./arch";
import { getFuncInsns } from "./funcInsns";
// The x86 32-bit parameter count is READ OFF THE RECOVERED FRAME rather than
// re-derived from `[ebp + N]` operand text — see `framedParamCount`. The
// architecture is always the caller's, forwarded, never derived here: this file
// is one of the two the `archThreading` drift guard exempts from deriving one,
// and it must stay that way (peek-a-bin-56q).
import { analyzeStackFrame } from "./stack";
import type { DisasmFunction, Instruction, StackFrame } from "./types";

export interface FunctionSignature {
  convention: string;
  paramCount: number;
}

const FASTCALL_REGS_64 = ["rcx", "rdx", "r8", "r9"];

/**
 * Canonical 64-bit parent + width of a general-purpose register token.
 * Deliberately a local table rather than an import of `canonReg()` from
 * `decompile/ir.ts`: nothing else in the disassembly layer depends on the
 * decompiler, and that helper returns the token unchanged for non-registers,
 * which is not enough to tell `ptr` from `rdx` when scanning operand text.
 */
const LEGACY_REGS: Record<string, [canon: string, width: number]> = {
  rax: ["rax", 8],
  eax: ["rax", 4],
  ax: ["rax", 2],
  al: ["rax", 1],
  ah: ["rax", 1],
  rbx: ["rbx", 8],
  ebx: ["rbx", 4],
  bx: ["rbx", 2],
  bl: ["rbx", 1],
  bh: ["rbx", 1],
  rcx: ["rcx", 8],
  ecx: ["rcx", 4],
  cx: ["rcx", 2],
  cl: ["rcx", 1],
  ch: ["rcx", 1],
  rdx: ["rdx", 8],
  edx: ["rdx", 4],
  dx: ["rdx", 2],
  dl: ["rdx", 1],
  dh: ["rdx", 1],
  rsi: ["rsi", 8],
  esi: ["rsi", 4],
  si: ["rsi", 2],
  sil: ["rsi", 1],
  rdi: ["rdi", 8],
  edi: ["rdi", 4],
  di: ["rdi", 2],
  dil: ["rdi", 1],
  rbp: ["rbp", 8],
  ebp: ["rbp", 4],
  bp: ["rbp", 2],
  bpl: ["rbp", 1],
  rsp: ["rsp", 8],
  esp: ["rsp", 4],
  sp: ["rsp", 2],
  spl: ["rsp", 1],
};

const EXT_REG_RE = /^(r(?:[89]|1[0-5]))([bwd])?$/;
const EXT_WIDTHS: Record<string, number> = { b: 1, w: 2, d: 4 };

/** Canonical name + width of a register token, or null if it is not a register. */
function regInfo(token: string): { canon: string; width: number } | null {
  const t = token.toLowerCase();
  const ext = t.match(EXT_REG_RE);
  if (ext) return { canon: ext[1], width: ext[2] ? EXT_WIDTHS[ext[2]] : 8 };
  const legacy = LEGACY_REGS[t];
  return legacy ? { canon: legacy[0], width: legacy[1] } : null;
}

/** Whole-word tokens, so `r8d` matches r8 but `rdx` never matches `dx`. */
const TOKEN_RE = /\b[a-z][a-z0-9]*\b/g;

/** Every canonical register mentioned anywhere in a chunk of operand text. */
function canonRegsIn(text: string): string[] {
  const out: string[] = [];
  for (const m of text.toLowerCase().matchAll(TOKEN_RE)) {
    const info = regInfo(m[0]);
    if (info) out.push(info.canon);
  }
  return out;
}

// Destination is operand 0, remaining operands are pure sources.
const MOV_LIKE = new Set(["mov", "movabs", "movzx", "movsx", "movsxd", "lea"]);
// Every operand is a source; nothing is written.
const READ_ONLY = new Set(["cmp", "test", "push"]);
// Operand 0 is read *and* written (except the 3-operand `imul` form).
const READ_MODIFY_WRITE = new Set([
  "add",
  "sub",
  "and",
  "or",
  "xor",
  "adc",
  "sbb",
  "shl",
  "shr",
  "sar",
  "rol",
  "ror",
  "imul",
  "inc",
  "dec",
  "neg",
  "not",
]);

interface RegEffects {
  /** Canonical registers read by the instruction. */
  reads: Set<string>;
  /** Canonical registers fully overwritten (32/64-bit destinations only). */
  writes: Set<string>;
}

/**
 * Split an instruction into the registers it reads and the ones it clobbers.
 * A destination register is only reported as written when the write kills the
 * whole register — an 8/16-bit write leaves the caller's upper bits intact, so
 * a later read of the parent is still partly a read of the incoming argument.
 */
function analyzeInsn(mnemonic: string, opStr: string): RegEffects {
  const reads = new Set<string>();
  const writes = new Set<string>();
  const mn = mnemonic.toLowerCase();

  const parts = opStr
    .split(",")
    .map((p) => p.trim())
    .filter((p) => p.length > 0);
  if (parts.length === 0) return { reads, writes };

  const addReads = (text: string) => {
    for (const r of canonRegsIn(text)) reads.add(r);
  };

  const dest = parts[0];
  const destInfo = dest.includes("[") ? null : regInfo(dest);
  const addDestWrite = () => {
    if (destInfo && destInfo.width >= 4) writes.add(destInfo.canon);
  };
  const srcText = parts.slice(1).join(",");

  // Arguments are counted where they are set up, not at the call itself.
  if (mn === "call") return { reads, writes };

  if (MOV_LIKE.has(mn)) {
    addReads(srcText);
    if (destInfo) addDestWrite();
    else addReads(dest); // memory destination: the address registers are read
    return { reads, writes };
  }

  if (READ_ONLY.has(mn)) {
    addReads(opStr);
    return { reads, writes };
  }

  if (mn === "pop") {
    if (destInfo) addDestWrite();
    else addReads(dest);
    return { reads, writes };
  }

  if (READ_MODIFY_WRITE.has(mn)) {
    // `xor reg, reg` / `sub reg, reg` are zeroing idioms: they clobber the
    // register without reading anything meaningful out of it.
    const zeroingIdiom =
      (mn === "xor" || mn === "sub") &&
      parts.length === 2 &&
      destInfo !== null &&
      regInfo(parts[1])?.canon === destInfo.canon;

    if (!zeroingIdiom) addReads(srcText);
    if (destInfo) {
      // The 3-operand `imul dst, src, imm` form does not read its destination.
      if (!zeroingIdiom && parts.length < 3) reads.add(destInfo.canon);
      addDestWrite();
    } else {
      addReads(dest);
    }
    return { reads, writes };
  }

  // Unknown mnemonic: assume every operand is read, clobber nothing.
  addReads(opStr);
  return { reads, writes };
}

/**
 * The Windows x64 answer: the argument registers this function reads before it
 * writes them, and NOTHING ABOUT THE STACK.
 *
 * THE STACK-ARGUMENT CLAIM WAS DELETED AT `peek-a-bin-j4uk.6`, AND ITS ABSENCE
 * IS A DECISION. What stood here scanned the same 20-instruction window for
 * `[rsp + 0xN]` and read `N >= 0x28` as argument `floor((N - 0x28) / 8) + 5`,
 * **with no tracking of `sub rsp, N` or of a single `push`**. Incoming argument
 * 5 is at `[rsp + allocation + pushes + 0x28]`, so with the allocation ignored
 * the rule did not describe the incoming argument area at all — it described
 * the function's OWN OUTGOING one, which is where MSVC puts
 * `mov [rsp+0x20], rax` on essentially every non-leaf x64 function. Measured at
 * `97ef927`: `t64!sub_140001000` does `sub rsp, 0x848` and the rule reported
 * **262 parameters** where the decompiler emitted 4; over the two x64 binaries
 * it over-claimed on 54 functions each, worst case +258. Both numbers were on
 * screen at once, one pane apart.
 *
 * SO WHY NOT REPAIR THE ARITHMETIC INSTEAD? Because the evidence it would need
 * does not exist and building it here would be the wrong place twice over.
 *
 *  - **`stack.ts` cannot answer it, by construction rather than by omission.**
 *    `analyzeStackFrame` records *every* `[rsp + N]` access as a NON-parameter
 *    — the final `false` argument to its `record` — and `isArgumentSlot` is
 *    asked only of `bp`-based offsets. That is the same refusal
 *    `inUnfilledHomeSpace` and `peek-a-bin-g186` are made of: an offset being
 *    inside an argument area does not make it an argument, and on the stack
 *    pointer there is not even a fixed area to be inside of.
 *  - **An entry-SP tracker must not be written here.** It would have to model
 *    the allocation *and* every push, i.e. a second stack grammar beside
 *    `stack.ts`'s — the tenth-hand-rolled-copy shape `peek-a-bin-w6f` ended for
 *    operand parsing and `pe/sections.ts`, `ripRelative.ts` and `stackIdiom.ts`
 *    each exist to prevent. If it is ever wanted it belongs in `stack.ts`, once.
 *  - **There is no oracle for the answer it would give.** `corpus/arity.ts`
 *    measures CALL-SITE arity against `apitypes.ts` and can never see a
 *    declared parameter list; gcc accepts any list. The one differential that
 *    exists is `signatureAgreement`, which compares this count against the
 *    decompiler's — and the decompiler declares a fifth argument only from the
 *    same frame recovery that refuses `sp`-based slots, so it could not
 *    adjudicate a fifth parameter either.
 *
 * SO THE ANSWER IS NARROWED, AND THE NARROWING IS ADMITTED RATHER THAN HIDDEN:
 * a genuine fifth argument is now missing from this count. That is the
 * `peek-a-bin-f51x` direction — "an invented argument is the one error this
 * codebase will not trade for a recovered one" — and it is the direction the
 * decompiler already errs in for the same slots.
 *
 * REOPENING CONDITION, so this is a bound and not a dead end: an entry-SP
 * displacement published by `stack.ts` (allocation AND pushes, on the model of
 * `frameDelta`), plus an instrument that can see a declared parameter count
 * from outside the tool. Neither exists today. `signatureAgreement`'s `panel
 * under-claims` row is where the cost of this refusal is reported.
 */
function inferSignature64(funcInsns: Instruction[]): FunctionSignature {
  // Windows x64 fastcall: RCX, RDX, R8, R9
  const scanLimit = Math.min(funcInsns.length, 20);
  const written = new Set<string>();
  let maxParam = 0;

  for (let i = 0; i < scanLimit; i++) {
    const insn = funcInsns[i];
    const { reads, writes } = analyzeInsn(insn.mnemonic, insn.opStr);

    // Reads are resolved against the state *before* the instruction, so a
    // register that is both read and written here still counts as a parameter.
    for (let pi = 0; pi < FASTCALL_REGS_64.length; pi++) {
      const reg = FASTCALL_REGS_64[pi];
      if (written.has(reg)) continue;
      if (reads.has(reg)) maxParam = Math.max(maxParam, pi + 1);
    }
    for (const w of writes) written.add(w);
  }

  // 0..4, which is exactly what `promote.ts` caps its register-parameter arm at
  // (`Math.min(signature.paramCount, 4)`). The convention is not in doubt on
  // this architecture — Windows x64 has exactly one — so naming it states
  // nothing the image could contradict, which is why a count of 0 is still an
  // answer here and is not one on x86.
  return { convention: "fastcall", paramCount: maxParam };
}

/**
 * Bytes the callee itself pops on return, or `null` where it pops none.
 *
 * The only exact statement about arity an x86 body makes about itself: under
 * every callee-cleans convention `ret N` is the argument area's size in bytes,
 * written by the compiler that knew the prototype.
 */
function calleeStackCleanup(funcInsns: Instruction[]): number | null {
  const last = funcInsns[funcInsns.length - 1];
  if (!last || (last.mnemonic !== "ret" && last.mnemonic !== "retn")) return null;
  const m = last.opStr.match(/^0x([0-9a-fA-F]+)$/);
  const n = m ? Number.parseInt(m[1], 16) : Number.parseInt(last.opStr, 10);
  if (Number.isNaN(n) || n <= 0) return null;
  return n;
}

/** The two registers an x86 register-passing convention uses, in order. */
const REGISTER_ARG_REGS_32 = ["rcx", "rdx"] as const;

/**
 * `"thiscall"` or `"fastcall"` where the body reads an argument register before
 * writing it, else `null` — AND EDX IS THE HALF THAT WAS MISSING.
 *
 * The rule here was "ECX is read before it is written" and it never looked at
 * EDX at all, so every 32-bit `__fastcall` helper was labelled `thiscall` —
 * and MSVC's CRT is full of them. The two conventions are distinguished by
 * exactly one fact: `__thiscall` passes `this` in ECX and everything else on
 * the stack, `__fastcall` passes the first two integer arguments in ECX and
 * EDX. A read of EDX before any write of it is therefore the same kind of
 * evidence `inferSignature64` already acts on for RCX/RDX/R8/R9 — the x86 rule
 * was simply half-written.
 *
 * The scan does NOT stop at the first ECX read the way the old one did: the
 * answer about ECX is unchanged by continuing (only a read strictly before a
 * write is recorded), and stopping is what made EDX unaskable.
 *
 * ECX is required for both answers. A read of EDX alone is not evidence of a
 * register convention — `__fastcall` fills ECX first — so it is refused rather
 * than reported as a one-argument shape.
 */
function registerConvention32(funcInsns: Instruction[]): "thiscall" | "fastcall" | null {
  const scanLimit = Math.min(funcInsns.length, 10);
  const written = new Set<string>();
  const readFirst = new Set<string>();

  for (let i = 0; i < scanLimit; i++) {
    const insn = funcInsns[i];
    const { reads, writes } = analyzeInsn(insn.mnemonic, insn.opStr);
    for (const reg of REGISTER_ARG_REGS_32) {
      if (!written.has(reg) && reads.has(reg)) readFirst.add(reg);
    }
    for (const w of writes) written.add(w);
  }

  if (!readFirst.has("rcx")) return null;
  return readFirst.has("rdx") ? "fastcall" : "thiscall";
}

/**
 * The number of argument slots the RECOVERED FRAME accounts for, or `null` when
 * it accounts for none.
 *
 * THIS REPLACES A HAND-ROLLED `[ebp + 0xN]` SCAN, and the scan was
 * `peek-a-bin-ikd`'s defect verbatim one module over: it counted every
 * `[ebp + off]` operand with `off >= 8` as an argument **with no
 * frame-pointer check at all**. Under frame-pointer omission `mov ebp, ecx`
 * makes EBP an object pointer and `[ebp + 0x10]` is a struct field access, and
 * `mov ebp, edx` is how an MSVC funclet receives its *parent's* frame — in
 * neither is the operand an argument of this function under any reading.
 * `decompile/structs.ts` keys cross-function parameter provenance off
 * `^arg_(\d+)$` precisely to exclude that population, so the panel was
 * asserting what the decompiler was carefully refusing.
 *
 * Reading `stack.ts`'s own answer inherits, for free and in ONE declaration,
 * every judgement that file has accumulated: `addressesOwnFrame` (a negative
 * displacement means the frame belongs to somebody else — `__SEH_prolog4`),
 * `inlineFrameGeometry` (a shifted frame is still a frame, `peek-a-bin-cvri`),
 * the helper-framed prologue (`peek-a-bin-emlv`), the sub-slot refusal, and the
 * FPO refusal itself.
 *
 * `max index + 1`, not the number of names: an argument the body never touches
 * leaves a GAP in the numbering rather than shifting its neighbours down, which
 * is stated at `stack.ts`'s naming loop and is what makes the index positional.
 * So this is a lower bound on the arity, and a *trailing* untouched argument is
 * invisible to it — the same admitted under-count the rest of this file errs in.
 */
function framedParamCount(stackFrame: StackFrame | null): number | null {
  if (!stackFrame) return null;
  let max = -1;
  for (const v of stackFrame.vars) {
    // The positional spelling only. `arg_0x30` is `argSlotName`'s refusal to
    // derive an index and must never be counted as one (CLAUDE.md's
    // stack-frame chain; `structs.ts` reads the same distinction).
    const m = /^arg_(\d+)$/.exec(v.name);
    if (m) max = Math.max(max, Number.parseInt(m[1], 10));
  }
  return max < 0 ? null : max + 1;
}

/**
 * The 32-bit answer, or `null` where the body offers no evidence for one.
 *
 * `null` IS THE POINT OF THIS FUNCTION'S SHAPE. x86 has four conventions the
 * tool can name and they are not interchangeable, so printing one is a claim
 * about the interface — where x64's `fastcall` is a property of the
 * architecture and states nothing. What stood here answered
 * `{ convention: "cdecl", paramCount: 0 }` for any function it could not read,
 * which is a complete-shaped answer over no evidence: exactly the shape the
 * architecture-refusal essay below exists to prevent, three lines further down
 * the same file.
 *
 * Three sources of evidence, in precedence order, and each names a different
 * kind of fact:
 *
 *  1. **`ret N`** — the callee's own stack cleanup, exact, written by the
 *     compiler that had the prototype. It outranks everything, which is the
 *     pre-existing precedence and is kept: it is the only *measurement* here.
 *  2. **A register convention** — ECX (and EDX) read before written. Evidence
 *     about the convention; `paramCount` still counts only what the frame
 *     accounts for, so a `this` in ECX is NOT added. That is a deliberate,
 *     stated under-count rather than an oversight: adding it would be a new
 *     arity claim with no oracle anywhere in this repo to check it, and the
 *     one direction this codebase will not err in is the other one.
 *  3. **The recovered frame** — `framedParamCount`. With a bare `ret`, the
 *     caller cleans up, which is what `cdecl` means; naming it is then a
 *     reading of the evidence rather than a default.
 *
 * With none of the three the answer is `null`. For zero recovered arguments
 * `cdecl` and `stdcall` are ABI-identical so the old answer was not falsifiable
 * *about behaviour* — but it was still a claim on a screen, made over a
 * function whose frame was never recovered and whose arguments therefore might
 * all be sitting in `[esp + N]` slots `stack.ts` deliberately declines to read.
 */
function inferSignature32(
  funcInsns: Instruction[],
  stackFrame: StackFrame | null,
): FunctionSignature | null {
  const cleanup = calleeStackCleanup(funcInsns);
  if (cleanup !== null) return { convention: "stdcall", paramCount: Math.floor(cleanup / 4) };

  const framed = framedParamCount(stackFrame);
  const regConvention = registerConvention32(funcInsns);
  if (regConvention !== null) return { convention: regConvention, paramCount: framed ?? 0 };
  if (framed !== null) return { convention: "cdecl", paramCount: framed };
  return null;
}

/**
 * The calling convention and argument count of one function, or null when this
 * engine has no signature grammar for the image's architecture.
 *
 * `arch` comes before `is64` because it outranks it — see the same note on
 * `analyzeStackFrame`. Both conventions this file knows, and every register
 * name in `LEGACY_REGS`, are x86.
 *
 * REFUSAL, AND WHY THE RETURN TYPE HAD TO WIDEN. This is the one of the pair
 * that was making a **false statement**, which is why `null` here is a fix and
 * not merely a bound. `FunctionSignature` has no way to say "unknown": the
 * fields are a convention name and a count, both required. So an ARM64 image
 * came back `{ convention: "fastcall", paramCount: 0 }` — measured, for **all
 * 1033** detected functions of t64-arm.exe and w64-arm.exe at `cc70fe6` — and
 * `InstructionDetail` renders that string unconditionally, so the detail panel
 * read `| fastcall, 0 params` over every A64 function. Both halves are wrong:
 * A64 uses AAPCS64, not the Microsoft x64 fastcall, and a function taking three
 * arguments in x0/x1/x2 was reported as taking none. Widening to
 * `FunctionSignature | null` is what lets the answer be silence, and both render
 * sites already had the null path wired (`DisassemblyRows` via `getSigForFunc`,
 * `InstructionDetail` via `signature ? … : ""`), so nothing new had to be
 * taught how to say nothing.
 *
 * NOT a throw, for `analyzeStackFrame`'s reason: the rest of the answer — the
 * disassembly, the xrefs, the strings — is correct and valuable, and the caller
 * is a `useMemo` in a view that must still render. `decompileFunction` already
 * declares `signature: FunctionSignature | null`, so the null propagates into
 * the one consumer that is not a view with no change at all.
 *
 * A NAME IS NOT A REFUSAL. Answering `{ convention: "aapcs64", paramCount: 0 }`
 * was considered and is worse: the count is the false half, and spelling the
 * convention correctly would dress an unanalysed function as an analysed one.
 *
 * **`peek-a-bin-hof0` RECOVERED THE ARM64 FRAME AND DELIBERATELY DID NOT
 * RECOVER THIS**, so the refusal above is now a decision taken with the evidence
 * in hand rather than work not yet done. `.pdata` states the frame outright, and
 * it says NOTHING about arity — two measurements, both over all 800 `.pdata`
 * functions of the two corpus binaries:
 *
 *  - The only field that could bear on it is `H`, "the prologue homes x0-x7",
 *    which is what a variadic prologue does. **`H` is 0 on all 500 packed
 *    entries.** The record carries no other argument evidence at all.
 *  - AAPCS64 passes eight arguments in registers with no home space, so a stack
 *    argument exists only from the ninth onward, at `[x29 + frameDelta + 8N]`.
 *    There are **0** frame accesses at or above `frameDelta` in either binary,
 *    so a positional rule would gate on an empty population — the vacuous-zero
 *    failure this project records against `armExits` on x64.
 *
 * What is left is the x86 rule read across: count reads of x0-x7 that precede
 * any write. That is a real inference and it may well be right, but it has **no
 * oracle** — there is no A64 emitted C, no `apitypes.ts` entry for a `sub_`
 * callee, and no way to match a function against its x86 twin — so landing it
 * would put an unverifiable count back on the panel this refusal cleared.
 * `peek-a-bin-56q` item 1; `peek-a-bin-hof0` for the frame that WAS recovered.
 *
 * **THE SAME REFUSAL NOW APPLIES INSIDE x86, AND IT DID NOT USED TO** — this
 * file argued the case above and then broke it three lines below, on the one
 * architecture it does answer for. `peek-a-bin-j4uk.6` closed four sites: the
 * x64 stack-argument rule that tracked no `sub rsp, N` (deleted — see
 * `inferSignature64`); the x86 `[ebp + N]` scan with no frame-pointer check
 * (replaced by `framedParamCount`, which reads `stack.ts`'s own answer); a
 * `thiscall` asserted from ECX without ever consulting EDX (see
 * `registerConvention32`); and the empty-instruction arm below, which invented
 * a convention out of `is64` alone.
 *
 * `stackFrame` is OPTIONAL AND THREE-VALUED. `undefined` means "the caller did
 * not compute one", and this function computes it — the two are already built
 * adjacently at every production call site, so passing it is free where it
 * exists and correct where it does not. `null` means the caller computed one
 * and there is no frame, which must not be re-analysed into the same `null`.
 * It is consulted on the 32-bit path only; the x64 answer reads no frame at
 * all.
 */
export function inferSignature(
  func: DisasmFunction,
  instructions: Instruction[],
  arch: ImageArch,
  is64: boolean,
  funcInsnMap?: Map<number, Instruction[]>,
  stackFrame?: StackFrame | null,
): FunctionSignature | null {
  // `"unsupported"` takes the same branch on purpose — see the note on
  // `analyzeStackFrame`'s own refusal.
  if (arch !== "x86") return null;

  const funcInsns = getFuncInsns(func, instructions, funcInsnMap);

  // NO INSTRUCTIONS IS NO EVIDENCE, AND IT USED TO ANSWER ANYWAY. This returned
  // `{ convention: is64 ? "fastcall" : "cdecl", paramCount: 0 }` — a
  // complete-shaped answer invented from the optional header's magic, over a
  // function not one byte of which was read. It is the same falsehood the
  // architecture refusal above was written to end, one branch below it
  // (peek-a-bin-j4uk.6).
  //
  // One consequence to keep in view rather than rediscover: the refusal above
  // is now UNOBSERVABLE at an empty instruction list, because every
  // architecture answers `null` there. The differential that still
  // discriminates the ordering is the one over a NON-EMPTY x86 body, and
  // `signatures.test.ts` says so at the tests concerned.
  if (funcInsns.length === 0) return null;

  if (is64) return inferSignature64(funcInsns);

  // `undefined` means the caller did not compute one and this is the cheapest
  // place to; `null` means the caller computed one and there is no frame. The
  // two must not collapse, or a caller that correctly found no frame would be
  // charged for a second analysis that finds none either.
  const frame =
    stackFrame === undefined
      ? analyzeStackFrame(func, instructions, arch, is64, funcInsnMap)
      : stackFrame;
  return inferSignature32(funcInsns, frame);
}
