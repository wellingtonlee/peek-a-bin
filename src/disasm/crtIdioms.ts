/**
 * CRT helper routines recognised from their BODY, not their name.
 *
 * THE DEFECT THIS EXISTS FOR. Every `call` the lifter emits takes a
 * `resultDest` of RAX/EAX — a call defines the accumulator, which is true of an
 * ordinary callee and false of a handful of compiler-instrumentation helpers
 * that the compiler inserts *after* the return value has been computed.
 * `__security_check_cookie` is the one that matters: MSVC's `/GS` epilogue is
 * `mov rcx, [frame cookie]; xor rcx, rsp; call __security_check_cookie; …; ret`,
 * and the helper preserves RAX by construction (its body compares RCX against
 * the global cookie and either returns or tail-jumps to `__report_gsfailure`).
 * With the call defining RAX, the function's real return value — computed just
 * above — was dead in the IR, and `foldReturnedCallResults` printed the tail as
 * `return sub_140002000(rcx);` in every `/GS`-protected function that returns a
 * value: 15 on t64, 13 on w64, and on x86 (`eax = sub_401DA4(); return eax;`)
 * 18 on t32 and 16 on w32 at 6299113. A WRONG VALUE, not a cosmetic defect
 * (peek-a-bin-n9cl.3).
 *
 * WHY THE BODY AND NOT THE NAME. There is no name: the helper is statically
 * linked and arrives as `sub_<addr>`. And the fact the lifter needs —
 * "this callee leaves RAX as it found it" — is a property of the callee's
 * instructions, so it is read off them, exactly as `callSummary.ts` reads what a
 * callee writes. The two ride the same plumbing: {@link recogniseCrtIdioms}
 * runs in the same whole-image pass that builds the clobber summaries, keyed on
 * the same instruction-array token, and reaches the lifter as
 * `CalleeClobbers.idioms`. The browser, the MCP server and `corpus/sweep.ts`
 * therefore all see the same answer through the existing `needInstructions`
 * protocol, and nothing new crosses the worker boundary.
 *
 * THE MATCH IS EXACT, AND REFUSAL IS THE DEFAULT. A template names every
 * instruction of the routine — mnemonic, operands, and where each branch lands —
 * and anything the template does not name is refused: an extra instruction, a
 * compare against a register rather than memory, a `je` where a `jne` belongs,
 * a body that writes EAX. That is what licenses `preservesResult: true` without
 * a separate dataflow argument: no instruction in any admitted template writes
 * the accumulator, so a match IS the proof. Two shapes are admitted, both read
 * off real MSVC output (`objdump -d -M intel` over the corpus at 6299113):
 *
 *   classic (x86 t32/w32, and older x64 CRTs):
 *     cmp ecx, dword ptr [cookie] ; jne F ; (rep) ret ; F: jmp __report_gsfailure
 *   hardened (x64 t64/w64, VS2017+ — the low 16 bits must be zero as well):
 *     cmp rcx, qword ptr [rip + cookie] ; jne F ; rol rcx, 0x10 ;
 *     test cx, 0xffff ; jne R ; (rep) ret ; R: ror rcx, 0x10 ; F: jmp __report_gsfailure
 *
 * The trailing `jmp` is optional in the classic shape because function detection
 * may end the routine at its `ret` and start `__report_gsfailure`'s trampoline
 * as its own function; when it is present the `jne` must land on it exactly.
 * Trailing `int3`/`nop` alignment padding is not part of the routine and is
 * ignored, as the thunk-naming pass ignores it.
 *
 * WHAT A MATCH PUBLISHES. The routine's name (so function detection can name
 * the function and the emitted C can call it by name), `preservesResult` (so the
 * lifter emits the call with no `resultDest`), the cookie's address (so the
 * emitter can spell the load `__security_cookie` and declare it), and the
 * routine's documented register signature (`void __fastcall
 * __security_check_cookie(uintptr_t)` — one argument in RCX/ECX on both
 * widths), which is what keeps the `xor ecx, ebp` above the call alive on x86,
 * where nothing else reads ECX and the xor was being deleted as dead.
 *
 * THE SECOND ROUTINE: x86 `__SEH_epilog4` (peek-a-bin-s1f6.3). MSVC's EH4
 * epilogue helper — every `__try` function on PE32 ends `call __SEH_epilog4;
 * ret` — and it, too, is inserted after the return value has been computed and
 * leaves EAX alone: its body restores `fs:[0]`, pops the callee-saved
 * registers and the caller's frame, and returns through the return address it
 * parked in ECX. With the call defining EAX, `var_1C` (the real result,
 * computed on every path of `t32!sub_40C9DE`) was dead and the tail printed
 * `return sub_4041B5();` at all 31 / 29 call sites on t32 / w32. One shape,
 * byte-identical in both binaries (`t32!0x4041B5`, `w32!0x404415`, 20 bytes):
 *
 *     mov ecx, [ebp - 0x10] ; mov fs:[0], ecx ; pop ecx ; pop edi ; pop edi ;
 *     pop esi ; pop ebx ; mov esp, ebp ; pop ebp ; push ecx ; ret
 *
 * Its counterpart `__SEH_prolog4` (`t32!0x404170`, `w32!0x4043D0`, 21
 * instructions, 69 bytes) is recognised for its NAME only: it writes EAX
 * (`mov eax, [esp + 0x10]` and the cookie load), so `preservesResult` is
 * `false` there and the call keeps its `resultDest`; and it takes its two
 * arguments on the stack (`push <framesize>; push <scopetable>`), so it
 * publishes no register signature and the lifter's call-site walk is left to
 * find them. The frame it establishes is `stack.ts`'s business, recognised
 * there by arithmetic rather than by this template, and the scope table it is
 * handed is `seh32.ts`'s. Only the pushed handler address and the cookie
 * address vary between binaries, and the template reads both as shapes.
 *
 * DESIGNED TO GROW. {@link CRT_RECOGNISERS} is a table. A new routine is a new
 * recogniser and a new member of the {@link CrtIdiom} union — nothing here
 * dispatches on the name.
 *
 * WHAT IT DOES NOT DO. It does not delete the check call or the `x ^ rsp` xor:
 * compiler instrumentation is real control flow (a `jne` to
 * `__report_gsfailure`), so it is NAMED, not hidden. It does not consult
 * `IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie`: the parser reads that field
 * (`LoadConfigDirectory.securityCookie`) and `corpus/sweep.ts` reports whether
 * the two agree, but no decompile path's output depends on the comparison —
 * the worker never sees the PE, and an answer that differed between the browser
 * and the MCP server would be worse than either alone (epic 2, B2, owns the
 * refusal rule).
 */

import { type BranchTargetInsn, resolveBranchTargetAddr } from "./branchTarget";

/** The least an instruction has to carry to be matched here. */
export interface IdiomInsn extends BranchTargetInsn {
  mnemonic: string;
}

/**
 * `__security_check_cookie` — MSVC's `/GS` cookie check.
 *
 * `preservesResult` is a literal `true` rather than a boolean because the
 * template is the proof: a recogniser that admitted a body writing the
 * accumulator would have to change the type, not just the value.
 */
export interface SecurityCheckCookieIdiom {
  kind: "security-check-cookie";
  name: "__security_check_cookie";
  preservesResult: true;
  /** The global the cookie is compared against — `__security_cookie`'s address. */
  cookieAddress: number;
  /**
   * The routine's register signature, in argument order: one argument in
   * RCX (x64) / ECX (x86). The CRT's documented `__fastcall` contract, not a
   * measurement of the call site.
   */
  args: readonly string[];
}

/**
 * `__SEH_epilog4` — MSVC's x86 EH4 epilogue helper.
 *
 * `preservesResult` is a literal `true` for the same reason as the cookie
 * check's: the template names every instruction and none writes EAX. `args` is
 * empty because the routine takes nothing — it reads the caller's frame
 * through EBP, which a call-site walk would otherwise decorate with whatever
 * `push` happens to precede the call.
 */
export interface SehEpilog4Idiom {
  kind: "seh-epilog4";
  name: "__SEH_epilog4";
  preservesResult: true;
  args: readonly [];
}

/**
 * `__SEH_prolog4` — MSVC's x86 EH4 prologue helper, recognised for its NAME.
 *
 * `preservesResult` is a literal `false`: the body writes EAX, and a type that
 * could say otherwise would let a template edit change the lifter's behaviour
 * silently. No `args`: its two arguments (`framesize`, `scopetable`) are pushed
 * immediates, which `collectArgs32` already recovers at the call site, and a
 * published register signature would REPLACE that walk with an empty list.
 */
export interface SehProlog4Idiom {
  kind: "seh-prolog4";
  name: "__SEH_prolog4";
  preservesResult: false;
  args?: undefined;
}

/** A recognised CRT routine. A union so a new routine is a new member. */
export type CrtIdiom = SecurityCheckCookieIdiom | SehEpilog4Idiom | SehProlog4Idiom;

/** The name the emitted C gives the global the cookie check compares against. */
export const SECURITY_COOKIE_NAME = "__security_cookie";

/**
 * Functions longer than this are not decoded by the recognisers at all.
 *
 * The longest admitted body is `__SEH_prolog4` at 69 bytes; an x86 extent that
 * runs to the next start can carry up to 15 bytes of alignment padding on top
 * of that (the hardened cookie check is 31, the classic 15, the epilogue 20).
 * A generous bound costs nothing — the decode is per candidate and tiny — and
 * a tight one silently refuses a real routine. Raising it from 48 to 96 also
 * widens the population `functionDetect.ts`'s naming pass decodes, which is
 * where the cost of a looser bound would land; every template still names its
 * first instruction exactly, so nothing in that wider population can match by
 * accident.
 */
export const CRT_IDIOM_MAX_BYTES = 96;

/** The longest admitted template, after padding is stripped (`__SEH_prolog4`). */
const MAX_INSNS = 21;

const PADDING = new Set(["int3", "nop"]);

/** `rep ret`/`repz ret` → `ret`: Capstone puts a prefix in the mnemonic. */
function baseMnemonic(mnemonic: string): string {
  const parts = mnemonic.trim().toLowerCase().split(/\s+/);
  return parts[parts.length - 1] ?? "";
}

function operands(opStr: string): string[] {
  const s = opStr.trim();
  return s === "" ? [] : s.split(",").map((o) => o.trim().toLowerCase());
}

/** The body with trailing alignment padding removed. */
function stripPadding<T extends IdiomInsn>(insns: readonly T[]): readonly T[] {
  let end = insns.length;
  while (end > 0 && PADDING.has(baseMnemonic(insns[end - 1].mnemonic))) end--;
  return insns.slice(0, end);
}

/** A direct branch operand — `jne 0x14000201a` — as an address, or null. */
function directTarget(insn: IdiomInsn): number | null {
  const t = resolveBranchTargetAddr(insn);
  return t?.kind === "direct" ? t.addr : null;
}

/**
 * `cmp <acc>, <memory>` where the memory operand is absolute or RIP-relative,
 * resolved through the one branch/memory address grammar. Returns the address
 * compared against, or null for any other compare (a register, an immediate,
 * a different accumulator, a based address).
 */
function cookieCompare(insn: IdiomInsn, acc: string): number | null {
  if (baseMnemonic(insn.mnemonic) !== "cmp") return null;
  const ops = operands(insn.opStr);
  if (ops.length !== 2 || ops[0] !== acc) return null;
  // The second operand alone, so a bare hex immediate reads as `direct` and is
  // refused below rather than mistaken for an address.
  const t = resolveBranchTargetAddr({ address: insn.address, size: insn.size, opStr: ops[1] });
  return t?.kind === "indirectMem" ? t.addr : null;
}

function isRet(insn: IdiomInsn): boolean {
  const mn = baseMnemonic(insn.mnemonic);
  return (mn === "ret" || mn === "retn") && operands(insn.opStr).length === 0;
}

function isJne(insn: IdiomInsn): number | null {
  const mn = baseMnemonic(insn.mnemonic);
  return mn === "jne" || mn === "jnz" ? directTarget(insn) : null;
}

/** `rol|ror <acc>, 0x10` */
function isRotate16(insn: IdiomInsn, mnemonic: "rol" | "ror", acc: string): boolean {
  if (baseMnemonic(insn.mnemonic) !== mnemonic) return false;
  const ops = operands(insn.opStr);
  return ops.length === 2 && ops[0] === acc && /^(0x10|16)$/.test(ops[1]);
}

/** `test cx, 0xffff` */
function isTestLow16(insn: IdiomInsn): boolean {
  if (baseMnemonic(insn.mnemonic) !== "test") return false;
  const ops = operands(insn.opStr);
  return ops.length === 2 && ops[0] === "cx" && /^(0xffff|65535)$/.test(ops[1]);
}

/** An unconditional direct `jmp` — the trampoline into `__report_gsfailure`. */
function isDirectJmp(insn: IdiomInsn): boolean {
  return baseMnemonic(insn.mnemonic) === "jmp" && directTarget(insn) !== null;
}

/**
 * The cookie check, in either of its two shapes. See the module docstring.
 *
 * Every instruction is named; the two `jne` targets are checked against the
 * addresses of the instructions they must land on; and where the classic shape
 * has no `jmp`, its `jne` must leave the body entirely.
 */
function recogniseSecurityCheckCookie(
  body: readonly IdiomInsn[],
  is64: boolean,
): SecurityCheckCookieIdiom | null {
  const acc = is64 ? "rcx" : "ecx";
  const n = body.length;
  if (n < 3 || n > MAX_INSNS) return null;

  const cookieAddress = cookieCompare(body[0], acc);
  if (cookieAddress === null) return null;
  const failTarget = isJne(body[1]);
  if (failTarget === null) return null;

  const done = (): SecurityCheckCookieIdiom => ({
    kind: "security-check-cookie",
    name: "__security_check_cookie",
    preservesResult: true,
    cookieAddress,
    args: [acc],
  });

  // classic: cmp ; jne F ; ret [; F: jmp]
  if (n === 3 || n === 4) {
    if (!isRet(body[2])) return null;
    if (n === 4) {
      if (!isDirectJmp(body[3]) || failTarget !== body[3].address) return null;
    } else {
      const start = body[0].address;
      const end = body[2].address + body[2].size;
      if (failTarget >= start && failTarget < end) return null;
    }
    return done();
  }

  // hardened: cmp ; jne F ; rol ; test cx ; jne R ; ret ; R: ror ; F: jmp
  if (n === 8) {
    if (!isRotate16(body[2], "rol", acc)) return null;
    if (!isTestLow16(body[3])) return null;
    const retryTarget = isJne(body[4]);
    if (retryTarget === null || retryTarget !== body[6].address) return null;
    if (!isRet(body[5])) return null;
    if (!isRotate16(body[6], "ror", acc)) return null;
    if (!isDirectJmp(body[7]) || failTarget !== body[7].address) return null;
    return done();
  }

  return null;
}

// ── Exact-text templates: the two EH4 helpers ────────────────────────────────

/**
 * One instruction of an exact-text template: the base mnemonic and either the
 * operand string it must carry (after lowercasing and whitespace collapsing) or
 * a predicate for the one operand that legitimately varies between images.
 */
type TemplateRow = readonly [mnemonic: string, operands: string | ((ops: string) => boolean)];

/** Operand text normalised for comparison: lowercase, single spaces. */
function normOps(opStr: string): string {
  return opStr.trim().toLowerCase().replace(/\s+/g, " ");
}

/**
 * Does `body` match `template` instruction for instruction, with nothing over?
 *
 * Every row is checked — an extra instruction, a missing one, a different
 * mnemonic or a different operand all refuse — and the base mnemonic is taken
 * so a `rep ret` still reads as `ret`. Nothing else is normalised: `dword ptr`
 * is part of what MSVC emitted and part of what is matched.
 */
function matchesTemplate(body: readonly IdiomInsn[], template: readonly TemplateRow[]): boolean {
  if (body.length !== template.length) return false;
  for (let i = 0; i < template.length; i++) {
    const [mn, ops] = template[i];
    if (baseMnemonic(body[i].mnemonic) !== mn) return false;
    const have = normOps(body[i].opStr);
    if (typeof ops === "string" ? have !== ops : !ops(have)) return false;
  }
  return true;
}

/**
 * `__SEH_epilog4`, exactly as MSVC's 32-bit CRT ships it. See the module
 * docstring. Read off `t32!0x4041B5` and `w32!0x404415` at 21fbfa3 through
 * Capstone (so `fs:[0]` is spelled `dword ptr fs:[0]`, as the lifter sees it).
 *
 * No row writes EAX and no row is a `call`, which is what licenses
 * `preservesResult: true` — and the template being exact is what makes that a
 * property of the type rather than of an inspection nobody re-runs.
 */
const SEH_EPILOG4: readonly TemplateRow[] = [
  ["mov", "ecx, dword ptr [ebp - 0x10]"],
  ["mov", "dword ptr fs:[0], ecx"],
  ["pop", "ecx"],
  ["pop", "edi"],
  ["pop", "edi"],
  ["pop", "esi"],
  ["pop", "ebx"],
  ["mov", "esp, ebp"],
  ["pop", "ebp"],
  ["push", "ecx"],
  ["ret", ""],
];

/** `push 0x4041d0` — the `_except_handler4` address, which varies per image. */
const isPushedAddress = (ops: string): boolean => /^0x[0-9a-f]+$/.test(ops);

/** `mov eax, dword ptr [0x412284]` — the cookie load; the address varies per image. */
const isCookieLoad = (ops: string): boolean => /^eax, dword ptr \[0x[0-9a-f]+\]$/.test(ops);

/**
 * `__SEH_prolog4`, exactly as shipped (`t32!0x404170`, `w32!0x4043D0` at
 * 21fbfa3). Two rows carry a per-image address and are matched as shapes; the
 * other nineteen are literal. The frame arithmetic this body performs is what
 * `stack.ts`'s `hasHelperFramePointerPrologue` checks — that check does not
 * depend on this template and this template does not replace it.
 */
const SEH_PROLOG4: readonly TemplateRow[] = [
  ["push", isPushedAddress],
  ["push", "dword ptr fs:[0]"],
  ["mov", "eax, dword ptr [esp + 0x10]"],
  ["mov", "dword ptr [esp + 0x10], ebp"],
  ["lea", "ebp, [esp + 0x10]"],
  ["sub", "esp, eax"],
  ["push", "ebx"],
  ["push", "esi"],
  ["push", "edi"],
  ["mov", isCookieLoad],
  ["xor", "dword ptr [ebp - 4], eax"],
  ["xor", "eax, ebp"],
  ["push", "eax"],
  ["mov", "dword ptr [ebp - 0x18], esp"],
  ["push", "dword ptr [ebp - 8]"],
  ["mov", "eax, dword ptr [ebp - 4]"],
  ["mov", "dword ptr [ebp - 4], 0xfffffffe"],
  ["mov", "dword ptr [ebp - 8], eax"],
  ["lea", "eax, [ebp - 0x10]"],
  ["mov", "dword ptr fs:[0], eax"],
  ["ret", ""],
];

/** x86 only: there is no 64-bit EH4, and these register names do not exist there. */
function recogniseSehEpilog4(body: readonly IdiomInsn[], is64: boolean): SehEpilog4Idiom | null {
  if (is64 || !matchesTemplate(body, SEH_EPILOG4)) return null;
  return { kind: "seh-epilog4", name: "__SEH_epilog4", preservesResult: true, args: [] };
}

function recogniseSehProlog4(body: readonly IdiomInsn[], is64: boolean): SehProlog4Idiom | null {
  if (is64 || !matchesTemplate(body, SEH_PROLOG4)) return null;
  return { kind: "seh-prolog4", name: "__SEH_prolog4", preservesResult: false };
}

/** One recogniser per routine; each returns a match or null. */
export type CrtRecogniser = (body: readonly IdiomInsn[], is64: boolean) => CrtIdiom | null;

/**
 * The table. Order is irrelevant — the templates are disjoint by construction
 * (each names its first instruction exactly: `cmp`, `mov ecx, …`, `push <imm>`)
 * — but a new entry belongs here and nowhere else.
 */
export const CRT_RECOGNISERS: readonly CrtRecogniser[] = [
  recogniseSecurityCheckCookie,
  recogniseSehEpilog4,
  recogniseSehProlog4,
];

/**
 * The CRT routine `insns` is the body of, or null.
 *
 * `insns` is one function's instructions in address order, as
 * `buildFuncInsnMap` or a bounded decode of the function's extent yields them.
 * Trailing alignment padding is stripped first; nothing else is.
 */
export function recogniseCrtIdiom(insns: readonly IdiomInsn[], is64: boolean): CrtIdiom | null {
  const body = stripPadding(insns);
  if (body.length === 0 || body.length > MAX_INSNS) return null;
  for (const recognise of CRT_RECOGNISERS) {
    const hit = recognise(body, is64);
    if (hit) return hit;
  }
  return null;
}

/**
 * Every recognised routine in an image, keyed on its entry address.
 *
 * The batch form `CallSummaryCache.forToken` and `mcp/session.ts` run in the
 * same pass as `buildCallSummaries`, over the same `funcInsnMap`. Linear in the
 * number of functions and constant per function: a body longer than
 * {@link MAX_INSNS} plus padding is refused before any operand is read.
 */
export function recogniseCrtIdioms(
  funcInsnMap: ReadonlyMap<number, readonly IdiomInsn[]>,
  is64: boolean,
): Map<number, CrtIdiom> {
  const out = new Map<number, CrtIdiom>();
  for (const [addr, insns] of funcInsnMap) {
    // Cheap pre-filter: padding can only make the body longer, so an array
    // this long cannot strip down to a template.
    if (insns.length > MAX_INSNS + CRT_IDIOM_MAX_BYTES) continue;
    const idiom = recogniseCrtIdiom(insns, is64);
    if (idiom) out.set(addr, idiom);
  }
  return out;
}

/** A global the emitted C may name in place of a dereferenced constant. */
export interface NamedGlobal {
  name: string;
  /** The C type of its declaration. */
  type: string;
  /** Its width in bytes — a load of any other width keeps the raw spelling. */
  size: number;
}

/**
 * The globals the recognised routines identify, keyed on address.
 *
 * Today that is one: the security cookie, `uintptr_t` because the machine
 * word is what the `xor … , rsp` idiom mixes it with. The emitter spells a
 * load or store of exactly this width as the name and declares it `extern`
 * above the function header; a different width keeps `*(T*)(0x…)`, which is
 * true even if less readable.
 */
export function namedGlobalsFor(
  idioms: ReadonlyMap<number, CrtIdiom> | undefined,
  is64: boolean,
): Map<number, NamedGlobal> {
  const out = new Map<number, NamedGlobal>();
  if (!idioms) return out;
  for (const idiom of idioms.values()) {
    if (idiom.kind === "security-check-cookie") {
      out.set(idiom.cookieAddress, {
        name: SECURITY_COOKIE_NAME,
        type: "uintptr_t",
        size: is64 ? 8 : 4,
      });
    }
  }
  return out;
}
