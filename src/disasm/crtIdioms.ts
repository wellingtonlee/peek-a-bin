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
 * DESIGNED TO GROW. {@link CRT_RECOGNISERS} is a table; the second entry it is
 * built for is x86 `__SEH_epilog4` (epic 3: `t32!sub_40C9DE` returns its unlock
 * helper's result for the same reason). A new routine is a new recogniser and
 * a new member of the {@link CrtIdiom} union — nothing here dispatches on the
 * name.
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

/** A recognised CRT routine. A union so a second routine is a new member. */
export type CrtIdiom = SecurityCheckCookieIdiom;

/** The name the emitted C gives the global the cookie check compares against. */
export const SECURITY_COOKIE_NAME = "__security_cookie";

/**
 * Functions longer than this are not decoded by the recognisers at all.
 *
 * The hardened shape is 31 bytes; an x86 extent that runs to the next start can
 * carry up to 15 bytes of alignment padding on top of the classic shape's 15.
 * A generous bound costs nothing — the decode is per candidate and tiny — and
 * a tight one silently refuses a real routine.
 */
export const CRT_IDIOM_MAX_BYTES = 48;

/** The longest admitted template, after padding is stripped. */
const MAX_INSNS = 8;

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

/** One recogniser per routine; each returns a match or null. */
export type CrtRecogniser = (body: readonly IdiomInsn[], is64: boolean) => CrtIdiom | null;

/**
 * The table. Order is irrelevant — the templates are disjoint by construction
 * (each names its first instruction exactly) — but a second entry belongs
 * here and nowhere else.
 */
export const CRT_RECOGNISERS: readonly CrtRecogniser[] = [recogniseSecurityCheckCookie];

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
