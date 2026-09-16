// Leaf module: the rules a USER-CHOSEN variable name has to satisfy, shared by
// the pipeline (`promote.ts`'s `applyUserNames`, which skips a name the rule
// refuses) and the browser (`components/decompileIdent.ts`, which refuses the
// same name before it is ever dispatched). One declaration, two readers — a
// second copy of this predicate is how the two would come to disagree, and the
// disagreement's symptom is a rename the panel accepts that the C then never
// shows. Imports `ir.ts` alone (itself import-free).

import { isKnownRegister } from "./ir";

/**
 * The type-based names `promoteVars` gives a `var_` local whose inferred type
 * is one of these — the ONE table, read by `promote.ts` to rename and by
 * `renameableIdentClass` below to recognise the result as a key.
 */
export const TYPE_BASED_NAMES: Record<string, string> = {
  HANDLE: "hFile",
  NTSTATUS: "status",
  HRESULT: "hr",
  PVOID: "pBuffer",
  BOOL: "bResult",
};

/** Which kind of STABLE identifier a displayed token is, or null for none. */
export type RenameableIdentClass = "var" | "param" | "typed";

/**
 * `var_<HEX>` (a stack slot's offset, `stack.ts`/`promote.ts`), optionally
 * suffixed `_<base>` where two bases share an offset (`synthesizeStackFrame`).
 */
const VAR_NAME = /^var_[0-9A-F]+(?:_[a-z0-9]+)?$/;
/**
 * `arg_<N>` (argument position, `stack.ts`'s `argSlotName` and x64's
 * `entryBindings`), `arg_0x<OFF>` (a slot whose index is not derivable) and the
 * two x86 register-argument spellings `arg_ecx`/`arg_edx`.
 */
const PARAM_NAME = /^arg_(?:\d+|0x[0-9A-F]+|ecx|edx)$/;
/** `hFile`, `status2`, … — a `TYPE_BASED_NAMES` value with its collision suffix. */
const TYPED_NAME = new RegExp(`^(?:${Object.values(TYPE_BASED_NAMES).join("|")})\\d*$`);

/**
 * Whether an identifier is one the pipeline names STABLY — from a slot offset,
 * an argument position or an inferred type — and so one a rename may be keyed
 * on and persisted across sessions.
 *
 * WHAT IS REFUSED AND WHY, because each refusal names a different instability
 * (peek-a-bin-5b6q.7):
 *  - `field_0x<OFF>` / `struct_N`: the struct id is a `nextId++` in decompile
 *    order, so a key lands on a different struct next session.
 *  - `__unrecovered_N`: numbered by occurrence in the emitted body.
 *  - `flg_<addr>_<i>`, `clobbered_<reg>_<n>`, `<reg>_<n>`: minted by the
 *    lifter and by SSA destruction per run; the numbers follow the pass.
 *  - Register names: declared as variables since peek-a-bin-n9cl.4, but they
 *    are register SPELLINGS, and one canonical register is printed through
 *    several aliases.
 *  - `g_<HEX>` / `__imp_<f>` / `__security_cookie`: externs, named for the
 *    image, not for this function.
 * None of these match the three patterns above, so the answer is by
 * construction rather than by a deny-list — but the deny-list is stated in
 * `isReservedName` for the TARGET side, where a user could type one.
 */
export function renameableIdentClass(text: string): RenameableIdentClass | null {
  if (VAR_NAME.test(text)) return "var";
  if (PARAM_NAME.test(text)) return "param";
  if (TYPED_NAME.test(text)) return "typed";
  return null;
}

/** A C identifier, as the emitter would have to print it. */
const IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function isIdentifier(name: string): boolean {
  return IDENTIFIER.test(name);
}

/**
 * Spellings the emitter itself mints or the language owns. A user name equal
 * to one of these would make the C say something it does not mean: `var_8` is
 * some OTHER slot's name next session, `rax` is a register the body reads,
 * `int` is a type, `g_140003000` is an extern the header declares.
 */
const RESERVED_PATTERNS: readonly RegExp[] = [
  /^var_/,
  /^arg_/,
  /^flg_/,
  /^clobbered_/,
  /^__unrecovered_/,
  /^sub_[0-9A-Fa-f]+$/,
  /^loc_[0-9A-Fa-f]+$/,
  /^struct_/,
  /^field_/,
  /^array_/,
  /^_pad_/,
  /^g_[0-9A-Fa-f]+$/,
  /^__imp_/,
  /^__security_cookie$/,
  /^VAL_/,
];

/**
 * A split-repair name (`ecx_3`, `ssadestroy.ts`): a register spelling with a
 * version. Matched apart from the list above because the shape also fits an
 * ordinary `count_2`; only a REGISTER stem is refused.
 */
const SPLIT_REPAIR = /^([a-z0-9]+)_\d+$/;

const C_KEYWORDS = new Set([
  "auto",
  "break",
  "case",
  "char",
  "const",
  "continue",
  "default",
  "do",
  "double",
  "else",
  "enum",
  "extern",
  "float",
  "for",
  "goto",
  "if",
  "inline",
  "int",
  "long",
  "register",
  "restrict",
  "return",
  "short",
  "signed",
  "sizeof",
  "static",
  "struct",
  "switch",
  "typedef",
  "union",
  "unsigned",
  "void",
  "volatile",
  "while",
  "bool",
  "true",
  "false",
  "NULL",
  "__asm",
  "__try",
  "__except",
  "__finally",
]);

/** The type spellings the emitter prints in a declaration. */
const EMITTED_TYPES = new Set([
  "int8_t",
  "int16_t",
  "int32_t",
  "int64_t",
  "uint8_t",
  "uint16_t",
  "uint32_t",
  "uint64_t",
  "intptr_t",
  "uintptr_t",
  "size_t",
  "HANDLE",
  "NTSTATUS",
  "HRESULT",
  "PVOID",
  "BOOL",
  "DWORD",
  "LPVOID",
  "LPCSTR",
  "LPCWSTR",
  "LPSTR",
  "LPWSTR",
]);

/**
 * Whether a candidate name is one the user may not choose, whatever the
 * function: a generated spelling, a register, a keyword or a type. The
 * function-specific half — collision with a name this body declares — is
 * `validateVarName`'s second argument.
 */
export function isReservedName(name: string): boolean {
  if (isKnownRegister(name)) return true;
  if (C_KEYWORDS.has(name) || EMITTED_TYPES.has(name)) return true;
  if (RESERVED_PATTERNS.some((p) => p.test(name))) return true;
  const split = SPLIT_REPAIR.exec(name);
  return split !== null && isKnownRegister(split[1]);
}

/**
 * Why a candidate name cannot be used, or null when it can.
 *
 * THE ONE RULE FOR BOTH SIDES. `applyUserNames` asks it of every entry in the
 * user's map (with the body's own names as `declaredNames`) and skips the
 * entry on a non-null answer; `DecompileView` asks it of what the user typed
 * before dispatching, with the names read off the declaration lines on
 * screen. The wording is the panel's, so the reason can be shown as typed.
 *
 * `declaredNames` is every name the emitted C already binds — parameters,
 * locals, declared registers, captured operands, split repairs, externs — and
 * the caller removes the name being renamed from it before asking, or a
 * rename to itself would read as a collision.
 */
export function validateVarName(
  candidate: string,
  declaredNames: ReadonlySet<string> | Iterable<string>,
): string | null {
  if (!isIdentifier(candidate)) return "not a C identifier";
  if (isReservedName(candidate)) return "reserved: a generated name, register, keyword or type";
  const declared = declaredNames instanceof Set ? declaredNames : new Set(declaredNames);
  if (declared.has(candidate)) return "already declared in this function";
  return null;
}
