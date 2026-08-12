import { formatIOCTL, ioctlCodeArgIndex, isPlausibleIOCTL } from "../../analysis/driver";
import type { BinaryOp, IRExpr, IRFunction, IRStmt } from "./ir";
import { canonReg, isKnownRegister, regSize, walkExpr, walkStmts } from "./ir";
import type { DecompType, TypeContext } from "./typeInfer";
import { typeToString } from "./typeInfer";

// ── Expression Emission ──

const PREC: Record<string, number> = {
  "||": 1,
  "&&": 2,
  "|": 3,
  "^": 4,
  "&": 5,
  "==": 6,
  "!=": 6,
  "<": 7,
  "<=": 7,
  ">": 7,
  ">=": 7,
  "u<": 7,
  "u<=": 7,
  "u>": 7,
  "u>=": 7,
  "<<": 8,
  ">>": 8,
  ">>>": 8,
  "+": 9,
  "-": 9,
  "*": 10,
  "/": 10,
  "%": 10,
};

function opStr(op: BinaryOp): string {
  switch (op) {
    case "u<":
      return "<";
    case "u<=":
      return "<=";
    case "u>":
      return ">";
    case "u>=":
      return ">=";
    case "&&":
      return "&&";
    case "||":
      return "||";
    default:
      return op;
  }
}

function sizeToType(size: number): string {
  switch (size) {
    case 1:
      return "uint8_t";
    case 2:
      return "uint16_t";
    case 4:
      return "int32_t";
    case 8:
      return "int64_t";
    default:
      return "int32_t";
  }
}

function formatHex(value: number): string {
  if (value >= 0 && value <= 9) return String(value);
  if (value < 0) return "-" + formatHex(-value);
  return "0x" + value.toString(16).toUpperCase();
}

/**
 * `>>>` is deliberately absent: a logical shift right is emitted as a cast plus
 * `>>` (see `emitLogicalShiftRight`), which has no compound form. `x >>>= 1`
 * would have to become `x = (uint32_t)x >> 1` anyway.
 */
const COMPOUND_OPS = new Set<string>(["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>"]);

/** The unsigned C type of a given machine operand width, for the widths C spells. */
const UNSIGNED_TYPE: Record<number, string> = {
  1: "uint8_t",
  2: "uint16_t",
  4: "uint32_t",
  8: "uint64_t",
};

/**
 * The width in bytes of the machine operand an expression denotes, or null when
 * the IR does not carry one.
 *
 * `IRBinary` is `{op, left, right}` and has no width — but the width of a shift
 * is the width of the *operand being shifted*, and every leaf that can be one
 * does carry it: `IRReg.size` (set from `regSize(name)`, so `eax` is 4 and `r8`
 * is 8 — the lifter preserves sub-register names rather than canonicalising to
 * the 64-bit parent), `IRVar.size` (carried across from the register or the
 * stack slot it replaced), and the `size` on `IRDeref` / `IRFieldAccess` /
 * `IRArrayAccess`, which is the access width. So no new IR field is needed.
 *
 * Only widths C has an unsigned type for count. `st0` is 10 bytes and an
 * unrecognised register name defaults to 4 in `regSize`, which is a fallback and
 * not evidence — hence `isKnownRegister`.
 */
function operandWidth(expr: IRExpr): number | null {
  const known = (size: number): number | null => (UNSIGNED_TYPE[size] ? size : null);
  switch (expr.kind) {
    case "reg":
      return isKnownRegister(expr.name) ? known(regSize(expr.name)) : known(expr.size);
    case "var":
    case "deref":
    case "field_access":
    case "array_access":
      return known(expr.size);
    case "cast":
      return castWidth(expr.type);
    case "unary":
      // `!` yields a flag, not a value of the operand's width.
      return expr.op === "!" ? null : operandWidth(expr.operand);
    case "binary": {
      // A machine ALU operation computes in one width, so an operand of one
      // tells us the result's — but only if the other agrees where it is known.
      // A constant carries no width (`irConst` defaults to 4), so it abstains.
      if (!VALUE_OPS.has(expr.op)) return null;
      const left = operandWidth(expr.left);
      const right = operandWidth(expr.right);
      if (left !== null && right !== null) return left === right ? left : null;
      return left ?? right;
    }
    case "ternary": {
      const then = operandWidth(expr.then);
      return then !== null && then === operandWidth(expr.else) ? then : null;
    }
    default:
      return null;
  }
}

/** Ops that produce a value in the operands' width, as opposed to a flag. */
const VALUE_OPS = new Set<BinaryOp>(["+", "-", "*", "/", "%", "&", "|", "^", "<<", ">>", ">>>"]);

/** The width a cast spelling names, for the integer spellings `sizeToType` emits. */
function castWidth(type: string): number | null {
  const m = /^u?int(8|16|32|64)_t$/.exec(type.trim());
  return m ? Number(m[1]) / 8 : null;
}

/**
 * A logical shift right, spelled as C — which has no such operator.
 *
 * `shr` lifts to the IR op `>>>` (JavaScript's unsigned shift), and it used to
 * be passed through verbatim into the output, where it is not an operator at
 * all: 66 syntax errors across three binaries, the largest remaining category.
 *
 * C spells a logical shift as `>>` on an unsigned operand, so the honest
 * translation needs the width the machine shifted — and the two obvious repairs
 * are both dishonest. A bare `>>` is an *arithmetic* shift: on a value whose
 * sign bit is set it shifts ones in where the machine shifts zeros, and a
 * `/ * logical * /` comment next to it does not change what the code does.
 * `(uintptr_t)x >> n` picks a width instead of finding one, and is wrong in the
 * common case that a 32-bit `shr`'s operand sits sign-extended in a wider
 * emitted variable — the high half then shifts in rather than zeros.
 *
 * `operandWidth` finds the real one from the operand node, so the cast is to
 * the width the machine actually used: it truncates to exactly the bits the
 * instruction operated on, reads them unsigned, and shifts. That is `shr`.
 *
 * Where no width can be established the value is reported as unrecovered rather
 * than guessed, because every C spelling of this shift asserts a width and
 * asserting one we do not have is the failure this whole exercise is about. A
 * constant shift count at least as wide as the operand contradicts the width we
 * found (and would be undefined behaviour in C), so it takes the same path.
 */
function emitLogicalShiftRight(expr: IRExpr & { kind: "binary" }, parentPrec: number): string {
  const prec = PREC[">>"];
  const shiftText = emitExpr(expr.right, prec + 1);
  const width = operandWidth(expr.left);
  const count = expr.right.kind === "const" ? expr.right.value : null;
  const widthContradicted = width !== null && count !== null && (count >= width * 8 || count < 0);

  // A non-negative constant has zeros above its top bit whatever the width, so
  // the arithmetic and logical shifts of it agree and no cast is needed.
  const nonNegativeConst = expr.left.kind === "const" && expr.left.value >= 0;

  let result: string;
  if (nonNegativeConst) {
    result = `${emitExpr(expr.left, prec)} >> ${shiftText}`;
  } else if (width === null || widthContradicted) {
    const why =
      width === null ? "operand width unknown" : `shifts by ${shiftText} of only ${width} bytes`;
    return unrecoveredValue(
      `logical shift right, ${why}: ${emitExpr(expr.left, 0)} >> ${shiftText}`,
    );
  } else if (expr.left.kind === "cast" && expr.left.type === UNSIGNED_TYPE[width]) {
    // Already unsigned at exactly that width; a second cast would say nothing.
    result = `${emitExpr(expr.left, prec)} >> ${shiftText}`;
  } else {
    result = `(${UNSIGNED_TYPE[width]})${emitExpr(expr.left, 99)} >> ${shiftText}`;
  }
  return prec < parentPrec ? `(${result})` : result;
}

/** The one-letter C escapes, by code unit. */
const SIMPLE_ESCAPES = new Map<number, string>([
  [0x07, "\\a"],
  [0x08, "\\b"],
  [0x09, "\\t"],
  [0x0a, "\\n"],
  [0x0b, "\\v"],
  [0x0c, "\\f"],
  [0x0d, "\\r"],
  [0x22, '\\"'],
  [0x5c, "\\\\"],
]);

/**
 * A recovered string as a C string literal, escaped completely.
 *
 * Only `"` used to be escaped, which is the half of the job that is obvious
 * from reading well-behaved sample data. A recovered string is bytes from a
 * hostile file, not a sample: `"<launcher_dir>\"` — a real string in every
 * distlib launcher — ends in a backslash, so the closing quote was escaped and
 * the literal ran on into the rest of the line (gcc: "missing terminating "
 * character", then a stray backslash where the line ended).
 *
 * Non-printables become three-digit octal rather than `\xNN`: hex escapes in C
 * are greedy and consume every following hex digit, so `\x0` before a literal
 * `1` silently becomes `\x01`, while `\000` is always exactly three digits.
 * Code units above 0x7F are emitted as the byte itself when they fit in a byte
 * (a byte-oriented extractor decodes latin-1, so that round-trips) and as their
 * UTF-8 bytes above that, where no single-byte spelling exists.
 *
 * The second `?` of any `??` pair is escaped as well: `??/` and friends are
 * trigraphs. gnu89 has them off, but the literal is a value a reader may paste
 * into a translation unit that does not.
 */
function cStringLiteral(s: string): string {
  let out = "";
  let prevWasQuestion = false;
  for (const ch of s) {
    const code = ch.codePointAt(0) ?? 0;
    const simple = SIMPLE_ESCAPES.get(code);
    if (simple) {
      out += simple;
    } else if (code === 0x3f && prevWasQuestion) {
      out += "\\?";
    } else if (code >= 0x20 && code < 0x7f) {
      out += ch;
    } else if (code <= 0xff) {
      out += `\\${code.toString(8).padStart(3, "0")}`;
    } else {
      for (const byte of new TextEncoder().encode(ch))
        out += `\\${byte.toString(8).padStart(3, "0")}`;
    }
    prevWasQuestion = code === 0x3f;
  }
  return `"${out}"`;
}

/** How much of a recovered string is spelled out before it is cut short. */
const STRING_DISPLAY_CHARS = 40;

/**
 * A recovered string, shortened for display without misstating its value.
 *
 * A long string used to be truncated to 37 characters with `...` appended
 * *inside* the quotes, so `"C:\Users\Public\AppData\Local\Temp\log.txt"` was
 * emitted as a literal whose value ends in three dots — a value the binary does
 * not contain, in a form a reader cannot tell from a string that really does end
 * that way. It is a small lie, but it is the same kind as the ones this pass
 * exists to remove: emitted C that states something the machine does not.
 *
 * The marker therefore goes outside the literal, where C treats it as
 * whitespace. What remains between the quotes is exactly the recovered prefix,
 * and the count says what was dropped.
 */
function stringLiteral(str: string): string {
  if (str.length <= STRING_DISPLAY_CHARS) return cStringLiteral(str);
  const prefix = str.slice(0, STRING_DISPLAY_CHARS - 3);
  return `${cStringLiteral(prefix)} /* + ${str.length - prefix.length} more characters */`;
}

/**
 * Text safe to put inside a C block comment.
 *
 * Every comment this file emits carries recovered material — an operand the
 * lifter could not parse, a whole disassembly line — so a comment terminator in
 * it would end the comment early and spill the rest into the code. A newline
 * would do the same to a line comment, and to the line-oriented goto-label pass.
 */
function commentSafe(text: string): string {
  return text.replace(/\*\//g, "* /").replace(/[\r\n]+/g, " ");
}

let _typeCtx: TypeContext | undefined;
let _stringMap: Map<number, string> | undefined;
let _unrecovered: { name: string; note: string }[] = [];
/** Name → struct id, for the names a declaration in scope already types as a struct pointer. */
let _declaredTypes: Map<string, string> = new Map();
/** Struct id → the definition this function carries, for spelling a field access. */
let _structDefs: Map<string, import("./structs").StructDef> = new Map();
/** Struct id → where its fields land, so the body and the declaration agree. */
let _layouts: Map<string, StructLayout> = new Map();
/** Enum name → type, for every synthesised enum whose members the body names. */
let _usedEnums: Map<string, EnumType> = new Map();
/** Enum names a parameter or local is declared with, which need the type itself. */
let _enumTypesNeeded: Set<string> = new Set();
/** Name → declared type, for every parameter and local in the function header. */
let _declaredVarTypes: Map<string, string> = new Map();
/** Register names the function assigns, lowercased — see `registerText`. */
let _assignedRegs: Set<string> = new Set();
/** Call statements whose result register is read — see `collectCapturedCalls`. */
let _capturedCalls: ReadonlySet<IRStmt> = new Set();

type EnumType = DecompType & { kind: "enum" };

/**
 * The member name for `value` in `type`, if `type` is an enum that has one, and
 * a note that this function's output now depends on that enum being declared.
 *
 * Synthesised enum members used to be spelled at the case labels of the switch
 * they were inferred from while nothing ever emitted the `enum` block that
 * declares them, so `case VAL_0x0:` reached the output as an undeclared
 * identifier — not a constant expression, and 12 of the remaining compile
 * errors. Recording use here is what lets the declaration be emitted for
 * exactly the enums that turned out to need one; the body is emitted before the
 * header for the same reason `__unrecovered_N` is.
 */
function enumMemberName(type: DecompType | undefined, value: IRExpr): string | null {
  if (type?.kind !== "enum" || value.kind !== "const") return null;
  const name = type.members.get(value.value);
  if (!name) return null;
  _usedEnums.set(type.name, type);
  return name;
}

/** The synthesised enum a type name refers to, if the type context has one. */
function enumTypeNamed(name: string): EnumType | null {
  if (!_typeCtx) return null;
  for (const t of _typeCtx.types.values()) if (t.kind === "enum" && t.name === name) return t;
  return null;
}

/** The struct id a declared type names, if it is spelled as a pointer to one. */
function declaredStructPointer(type: string): string | null {
  return /^(struct_\w+)\s*\*$/.exec(type.trim())?.[1] ?? null;
}

/**
 * Whether a type spelling denotes an address.
 *
 * `PVOID` and `HANDLE` are here because `typeToString` emits those names rather
 * than `void*`, and they are typedefs the *reader* supplies — under the Windows
 * definitions both are pointers, and a reader who defines them as an integer
 * gets a cast that does nothing. Either way the cast below stays correct.
 */
function isPointerSpelling(type: string): boolean {
  const t = type.trim();
  return t.endsWith("*") || t === "PVOID" || t === "HANDLE";
}

/** The type a field access is emitted with, or null where it is not a declared member. */
function fieldDeclaredType(expr: IRExpr & { kind: "field_access" }): string | null {
  const layout = _layouts.get(expr.structId);
  // Spelled as `*(intN_t*)((uint8_t*)base + off)` — an integer, see fieldAccess.
  if (!layout || layout.unplaceable.has(expr.fieldName)) return null;
  const declared = layout.declaredTypes.get(expr.fieldName);
  if (declared === undefined) return null;
  const field = _structDefs.get(expr.structId)?.fields.find((f) => f.name === expr.fieldName);
  if (!field?.isArray) return declared;
  const elementSize =
    field.arrayElementSize && field.arrayElementSize > 0
      ? field.arrayElementSize
      : Math.max(1, field.size);
  // `p->arr[0]` is one element; any other width is read back as `*(intN_t*)`.
  return expr.size === elementSize ? declared : null;
}

/**
 * Whether the emitted C gives this expression a pointer type.
 *
 * Only things the emitted C *declares* have a type at all: struct members, and
 * the parameters and locals in the function header. A register is deliberately
 * left undeclared (see `structPointer`), so nothing the reader supplies for it
 * can make C scale arithmetic on it, and it answers false here.
 */
function emitsAsPointer(expr: IRExpr): boolean {
  switch (expr.kind) {
    case "field_access":
      return isPointerSpelling(fieldDeclaredType(expr) ?? "");
    case "var":
      return isPointerSpelling(_declaredVarTypes.get(expr.name) ?? "");
    case "cast":
      return isPointerSpelling(expr.type);
    default:
      return false;
  }
}

/**
 * The operations whose C meaning changes when an operand is a pointer.
 *
 * A machine `add`/`sub` counts bytes. C's `+`/`-` counts *pointee objects* when
 * either operand is a pointer, so `p->field_0x10 + 8` on a `struct_1 *` field
 * compiles and means 0x80 bytes on — valid C stating something the instruction
 * does not do, which is the failure mode this whole exercise is about. It also
 * rejects the two-pointer case outright when the spellings differ, which was
 * the last five gcc errors over the three distlib binaries: `PVOID` minus
 * `struct_4 *` in a CRT `FILE`'s `_ptr - _base` (peek-a-bin-d8t, -q30).
 *
 * Casting the pointer operands to `uintptr_t` states the byte arithmetic the
 * instruction performed, and states nothing else: both field declarations keep
 * the types their evidence gave them, so a reader can still see that one slot
 * was read as a pointer and the other as a word.
 *
 * Bitwise operators are deliberately absent. A pointer masked with a constant
 * (peek-a-bin-h89) is not an operation C defines on addresses at all: the two
 * claims — that the value is an address, and that its low bits are flags —
 * contradict each other, and making the line compile means retracting one of
 * them. Emit has no evidence about which, so it retracts neither and leaves
 * gcc's complaint standing; the evidence lives in `structs.ts`, where every use
 * of the field is visible, and that is where the demotion was made. The
 * discriminator is therefore not a guess: `-` between two recovered lvalues is
 * an operation C has and only the spelling of the operands is missing, while
 * `&` against a mask is an operation C does not have and one of the operands
 * has to be wrong.
 */
const BYTE_ARITH_OPS = new Set<BinaryOp>(["+", "-"]);

/** An operand of `+`/`-`, with the byte arithmetic made explicit where C would scale. */
function byteArithOperand(expr: IRExpr, prec: number): string {
  if (!emitsAsPointer(expr)) return emitExpr(expr, prec);
  return `(uintptr_t)${emitExpr(expr, 99)}`;
}

/**
 * A name for a value the decompiler failed to recover, plus the declaration
 * that will be emitted for it.
 *
 * An `IRUnknown` used to emit as a bare block comment, which is not an
 * expression: in a condition that produced `if (!)` with a comment where the
 * test should be — a line that states nothing while looking like it states
 * something, 423 of them across three binaries, and the single largest source
 * of syntax errors in the emitted C. Dropping the unknown instead would be
 * worse still, because the `if` would then read as a recovered condition that
 * happens to be simple.
 *
 * So it becomes a free variable with a name that cannot be misread, carrying
 * the original text as a comment, and declared uninitialised at the top of the
 * function. That is the honest reading: an indeterminate machine value the
 * decompiler cannot name. It is also the one that survives a compiler — the
 * declaration keeps the C valid, and a reader who compiles it gets
 * `-Wuninitialized` pointing at exactly the places the recovery gave up.
 *
 * Every occurrence gets its own number. Two unrecovered conditions that both
 * came from a `je` are two different machine facts, and sharing one name would
 * assert they are equal.
 */
function unrecoveredValue(text: string): string {
  const name = `__unrecovered_${_unrecovered.length + 1}`;
  _unrecovered.push({ name, note: text });
  return text ? `${name} /* ${commentSafe(text)} */` : name;
}

function getExprType(expr: IRExpr): DecompType | undefined {
  if (!_typeCtx) return undefined;
  if (expr.kind === "reg") return _typeCtx.types.get(canonReg(expr.name));
  if (expr.kind === "var") return _typeCtx.types.get(expr.name);
  return undefined;
}

function emitTypeIdiom(expr: IRExpr & { kind: "binary" }): string | null {
  const leftType = getExprType(expr.left);

  // HANDLE: x == 0xFFFFFFFF → x == INVALID_HANDLE_VALUE
  if (
    leftType?.kind === "handle" &&
    expr.op === "==" &&
    expr.right.kind === "const" &&
    (expr.right.value === 0xffffffff || expr.right.value === -1)
  ) {
    return `${emitExpr(expr.left, 0)} == INVALID_HANDLE_VALUE`;
  }
  if (
    leftType?.kind === "handle" &&
    expr.op === "!=" &&
    expr.right.kind === "const" &&
    (expr.right.value === 0xffffffff || expr.right.value === -1)
  ) {
    return `${emitExpr(expr.left, 0)} != INVALID_HANDLE_VALUE`;
  }

  // NTSTATUS: x >= 0 → NT_SUCCESS(x), x < 0 → !NT_SUCCESS(x)
  if (leftType?.kind === "ntstatus" && expr.right.kind === "const" && expr.right.value === 0) {
    if (expr.op === ">=" || expr.op === "u>=") return `NT_SUCCESS(${emitExpr(expr.left, 0)})`;
    if (expr.op === "<") return `!NT_SUCCESS(${emitExpr(expr.left, 0)})`;
  }

  // HRESULT: x >= 0 → SUCCEEDED(x), x < 0 → FAILED(x)
  if (leftType?.kind === "hresult" && expr.right.kind === "const" && expr.right.value === 0) {
    if (expr.op === ">=" || expr.op === "u>=") return `SUCCEEDED(${emitExpr(expr.left, 0)})`;
    if (expr.op === "<") return `FAILED(${emitExpr(expr.left, 0)})`;
  }

  return null;
}

/** The constant an argument ultimately is, seeing through casts. */
function constOperand(expr: IRExpr): (IRExpr & { kind: "const" }) | null {
  if (expr.kind === "const") return expr;
  if (expr.kind === "cast") return constOperand(expr.operand);
  return null;
}

/**
 * `/ * IOCTL: ... * /` on a control-code argument, and nowhere else.
 *
 * This used to run on every constant the emitter touched, which is a shape test
 * masquerading as evidence: `isPlausibleIOCTL` accepts any 32-bit value whose
 * top word lands in the device-type ranges, so `0xFFFFFFFF` and every
 * `0x41xxxx` data address in a 32-bit image decoded as a device and a function
 * code that do not exist (782 such comments in one user-mode binary, 40% of its
 * functions). Naming a device is worse than saying nothing, so the annotation
 * now needs the call site: the constant has to be the argument that
 * `ioctlCodeArgIndex` says carries a control code.
 *
 * Only a literal (or a cast of one) is annotated. If the emitted text is not
 * the constant, a string-table or enum substitution won and the comment would
 * be describing something the reader cannot see.
 */
/**
 * `/ * IOCTL: ... * /` on the case labels of a driver's dispatch switch.
 *
 * The call-site rule above cannot see these. In a kernel driver the control
 * codes usually never appear as an argument at all: the dispatch routine
 * switches on `irpSp->Parameters.DeviceIoControl.IoControlCode` and the codes
 * are the `case` labels. Narrowing IOCTL decoding to a control-code argument
 * (peek-a-bin-hcj) removed 1475 false annotations from user-mode binaries and
 * took this real case with it.
 *
 * What is restored here is gated on evidence rather than on shape, which is
 * what made the old behaviour wrong:
 *
 * - the image imports a kernel-mode module, so it is a driver (`isDriver` on
 *   the type context). `isPlausibleIOCTL` accepts a large share of all 32-bit
 *   constants, and in a user-mode image nothing it accepts is a control code;
 * - *every* value in the switch passes `isPlausibleIOCTL`, not merely one. A
 *   dispatch table's labels are all control codes, while a driver's other
 *   switches — IRP major function, status, index — are on small values, which
 *   the plausibility test rejects outright below 0x10000;
 * - there are at least two of them, so a single coincidental constant in a
 *   driver cannot name a device on its own.
 *
 * Unlike an argument, a `case` label *is* its constant — nothing can substitute
 * a string for it — so the annotation is attached even where a synthesised enum
 * member supplies the spelling. That name is derived from the same value and is
 * declared with it in the enum block above, so the reader can still check it.
 */
function ioctlSwitchLabels(stmt: IRStmt & { kind: "switch" }): boolean {
  if (!_typeCtx?.isDriver) return false;
  const values = stmt.cases.flatMap((c) => c.values);
  if (values.length < 2) return false;
  return values.every((v) => isPlausibleIOCTL(v));
}

function annotateIOCTLArg(arg: IRExpr, emitted: string): string {
  const c = constOperand(arg);
  if (!c || !emitted.endsWith(formatHex(c.value))) return emitted;
  if (!isPlausibleIOCTL(c.value)) return emitted;
  const comment = formatIOCTL(c.value);
  return comment ? `${emitted} /* ${comment} */` : emitted;
}

/**
 * The base of a field access, spelled as a pointer to the struct it accesses.
 *
 * Struct recovery works out that a register holds a `struct_N *` and emits
 * `rcx->field_0x18`, and the register is a register: nothing declares it, so
 * that was 1656 of `invalid type argument of '->'` — by a distance the largest
 * category of broken emitted C. The recovery is right; only the spelling was
 * missing.
 *
 * The obvious repair — declare `struct_N *rcx;` at the top of the function — is
 * the wrong one, and quietly so. A register is not a variable: the same `rax`
 * that holds a `struct_1 *` on one line is a plain integer on the next, and the
 * emitter writes byte offsets off it as `*(int32_t*)(rax + 0xC8)`. Declaring it
 * a struct pointer makes C scale that offset by `sizeof(struct_1)`, so the line
 * still compiles and now describes a different address. 59 of the 151 functions
 * that use a register as a struct pointer across the three distlib binaries do
 * exactly this. A per-function declaration also cannot express a scratch
 * register that carries two different objects, which is what scratch registers
 * are for.
 *
 * A cast at the point of use makes the narrower claim that is the one the
 * recovery actually supports — *this access* reads this address as a
 * `struct_N` — and leaves every other use of the register alone. It is
 * suppressed only where a declaration in scope already says the same thing.
 */
function structPointer(base: IRExpr, structId: string): string {
  if ((base.kind === "reg" || base.kind === "var") && _declaredTypes.get(base.name) === structId)
    return base.name;
  return `((${structId} *)${emitExpr(base, 99)})`;
}

/**
 * A field access, spelled so that it means the access it records.
 *
 * A field the layout calls an array is the awkward case, because `p->array_0x0`
 * is then not the value at that offset: in C an array name in an expression is
 * its own address, so a *read* of one silently yields a pointer where the
 * machine loaded data, and a write is not even expressible ("assignment to
 * expression with array type", 10 of the remaining errors).
 *
 * Whether such an offset really is an array is not decided here — `structs.ts`
 * sets `isArray` from a single indexed access and this emitter only spells what
 * it is handed (see peek-a-bin-hyv for the contradiction that remains). What is
 * decided here is that the access and the declaration agree: an access exactly
 * as wide as one element is that element, and any other width is spelled as the
 * bytes it really touches, read at the start of the array. Both are true under
 * the declaration this same file emits, and neither invents an element index
 * the recovery does not have.
 */
function fieldAccess(expr: IRExpr & { kind: "field_access" }): string {
  // A field the declaration could not place is not a member, so `->` cannot
  // reach it. The access itself is not in doubt — an object, a distance, a
  // width — and that is what is spelled: `(uint8_t*)` because arithmetic on the
  // struct pointer would scale the offset by the struct's size, which is the
  // one thing this must not do (see structPointer).
  if (_layouts.get(expr.structId)?.unplaceable.has(expr.fieldName)) {
    const step =
      expr.fieldOffset < 0
        ? `- ${formatHex(-expr.fieldOffset)}`
        : `+ ${formatHex(expr.fieldOffset)}`;
    return `*(${sizeToType(expr.size)}*)((uint8_t*)${emitExpr(expr.base, 99)} ${step})`;
  }

  const base = structPointer(expr.base, expr.structId);
  const field = _structDefs.get(expr.structId)?.fields.find((f) => f.name === expr.fieldName);
  if (!field?.isArray) return `${base}->${expr.fieldName}`;

  const elementSize =
    field.arrayElementSize && field.arrayElementSize > 0
      ? field.arrayElementSize
      : Math.max(1, field.size);
  if (expr.size === elementSize) return `${base}->${expr.fieldName}[0]`;
  return `*(${sizeToType(expr.size)}*)${base}->${expr.fieldName}`;
}

/**
 * A callee, spelled so that calling it is expressible.
 *
 * An indirect call arrives here as a target the lifter named `(*esi)` — the
 * value in the register is the address — and emitting that verbatim produced
 * which asks C to dereference an integer: 314 errors, the largest category left
 * after the field accesses, and the same defect in kind. The call site is not
 * wrong, only unspellable without saying what is being called through.
 *
 * `intptr_t (*)()` is the least that can be claimed: a machine word back, and
 * an empty parameter list, which in C means *unknown* arguments rather than
 * none. Where the target is not even a name — the lifter hands over raw operand
 * text such as `dword ptr [ebp + 8]` when it could not parse the memory operand
 * — the value being called through is one it failed to recover, and it is
 * reported as one instead of being pasted into the output as if it were code.
 *
 * Only a target already marked indirect is touched. Whatever else arrives (an
 * API name, a `sub_...`) is passed through exactly as before, so no direct call
 * can be turned into an indirect one by a name this misjudges.
 */
function calleeText(name: string): string {
  const indirect = /^\(\*\s*(.*)\)$/.exec(name) ?? /^\*\s*(.*)$/.exec(name);
  if (!indirect) return name;
  const target = indirect[1].trim();
  const value = /^[A-Za-z_]\w*$/.test(target) ? target : unrecoveredValue(target);
  return `((intptr_t (*)())${value})`;
}

/** The signed `<stdint.h>` spelling of a machine operand width, where C has one. */
const SIGNED_TYPE: Record<number, string> = {
  1: "int8_t",
  2: "int16_t",
  4: "int32_t",
  8: "int64_t",
};

/**
 * The high-byte registers, which are not the low bits of anything.
 *
 * `(uint8_t)eax` is AL. AH is bits 8..15, so the narrowing below would name the
 * wrong byte and is not attempted for these four.
 */
const HIGH_BYTE_REGS = new Set(["ah", "bh", "ch", "dh"]);

/**
 * A register read, spelled so that it names storage the emitted function writes.
 *
 * Registers reach the output as undeclared free variables, one per *name* — and
 * the names are whatever the instructions used, so `dx` and `edx` are two
 * unrelated variables in C while being one register in the machine. t64's
 * `wcslen` is the clean example (peek-a-bin-uxm): the body assigns `edx` and
 * the loop condition tests `dx`, so as C the loop tests a variable nothing ever
 * assigns and cannot terminate. That is not a cosmetic mismatch — it is
 * compilable C whose meaning is not the machine's, which is the one thing this
 * emitter refuses.
 *
 * A read is therefore respelled as an explicit narrowing of the widest alias of
 * the same machine register that the function *assigns*, and only then: if the
 * name being read is itself assigned, the C already says what it means and a
 * cast would be noise (t32's `wcslen` writes `dx` and is left alone). Nothing
 * is invented — the low 16 bits of EDX are DX — and the rewrite is correct
 * whichever order the two appear in, since a read before the assignment is an
 * indeterminate value in C exactly as the incoming register is in the machine.
 *
 * The width comes from the register name; the *signedness* has to come from the
 * operation, because narrowing changes what a comparison tests. `js` on DL is a
 * signed test of bit 7, and `(uint8_t)edx >= 0` would be constantly true — a
 * different program that compiles. Callers pass `signed` for the operands of a
 * signed comparison and for the value an arithmetic shift right shifts.
 *
 * Only 8- and 16-bit names are respelled. `eax` is the whole register in 32-bit
 * code and a sub-register of RAX in 64-bit code, and emit is not told which it
 * is looking at — so treating it as partial would be a guess. The byte and word
 * names are sub-registers under either reading, which is the whole set this is
 * about. The alias chosen is the *narrowest* one wider than the read, because
 * that is the least the spelling has to claim.
 */
function registerText(expr: IRExpr & { kind: "reg" }, signed: boolean): string {
  const lower = expr.name.toLowerCase();
  if (_assignedRegs.has(lower)) return expr.name;
  if (!isKnownRegister(lower) || HIGH_BYTE_REGS.has(lower)) return expr.name;
  const width = regSize(lower);
  if (width > 2) return expr.name;
  const spelling = signed ? SIGNED_TYPE[width] : UNSIGNED_TYPE[width];
  if (!spelling) return expr.name;

  const canon = canonReg(lower);
  let alias: string | null = null;
  for (const assigned of _assignedRegs) {
    if (!isKnownRegister(assigned) || canonReg(assigned) !== canon) continue;
    if (regSize(assigned) <= width) continue;
    if (alias === null || regSize(assigned) < regSize(alias)) alias = assigned;
  }
  // Nothing wider is assigned, so there is no alias to tie this read to: it is
  // an incoming value, and its own name is the honest thing to call it.
  if (alias === null) return expr.name;
  return `(${spelling})${alias}`;
}

// ── Call results ──

/**
 * A call whose result register is read gets that assignment printed; one whose
 * result is dead stays a bare statement.
 *
 * `liftBlock` gives every `call_stmt` a `resultDest` of RAX/EAX — the machine's
 * integer return register — and SSA versions it like any other definition, so a
 * later read of the accumulator binds to the call. The emitter used to print
 * only the call, which threw that away: `GetProcAddress(rbx, "…")` followed by
 * `if (rax == 0)` is C in which nothing ever assigns `rax`, so the test reads a
 * value the emitted function never produced. Measured across t32/t64/w64 it was
 * the single largest source of reads-of-nothing in the output (peek-a-bin-oro).
 *
 * The judgement is which calls warrant one, and the rule is liveness: the
 * assignment is printed exactly when the result register is live out of the
 * call — when some path from it reaches a read before anything overwrites it.
 * A call whose result nothing consumes gets no assignment, because a line
 * assigning a name that is never read afterwards is noise, and this output is
 * read by people. Anything weaker than liveness (say, "the register is read
 * somewhere in the function") prints an assignment for a call whose result the
 * very next line overwrites.
 *
 * This is the other half of the call clobber in `ssa.ts`, not a second story
 * about the same thing: `clobberedByCall` deliberately leaves the result
 * register out of the set it destroys ("RAX needs nothing here"), and gives
 * each *argument* register the call consumed a fresh version that no statement
 * defines, which `ssadestroy.ts` then names `clobbered_rcx_2` — a variable
 * nothing assigns, because the value is not recoverable. The two mechanisms
 * cover disjoint registers by construction. After a call, every register the
 * decompiler says the call changed is now either assigned (the result, when it
 * is read) or renamed to a name that visibly has no definition (the arguments).
 *
 * The returned set is the calls in `body` that qualify; `liveInStmt` below is
 * the analysis. `walkStmts` supplies the fallback live set a `goto` uses. It
 * also visits assignment destinations, so a register the body only ever writes
 * is in that set — an over-approximation that applies only at a `goto`, where
 * nothing better is available.
 */
function collectCapturedCalls(body: readonly IRStmt[]): Set<IRStmt> {
  const all = new Set<string>();
  walkStmts(body as IRStmt[], (e) => {
    if (e.kind === "reg") all.add(canonReg(e.name));
  });
  const ctx: LiveCtx = {
    brk: new Set<string>(),
    cont: new Set<string>(),
    all,
    captured: new Set<IRStmt>(),
  };
  // Nothing is live when the function returns: the accumulator a `ret` leaves
  // behind is read by the `return` statement the lifter emits for it.
  liveInList(body, new Set<string>(), ctx);
  return ctx.captured;
}

/** Canonical registers an expression reads. */
function addReadRegs(expr: IRExpr | undefined, out: Set<string>): void {
  if (!expr) return;
  walkExpr(expr, (e) => {
    if (e.kind === "reg") out.add(canonReg(e.name));
  });
}

/**
 * The canonical register a write to `dest` ends the live range of, if any.
 *
 * A write to a sub-register leaves the rest of the parent in place — AL is one
 * byte of RAX — so it does not end the parent's live range. A 32-bit write does
 * under either reading: EAX is the whole register in x86 code, and writing it
 * zero-extends into RAX in x64. `isKnownRegister` guards the width test because
 * `regSize` answers 4 for anything it does not recognise (see `decompile/ir.ts`);
 * an unrecognised name still kills itself, since a read of it canonicalises the
 * same way.
 */
function killedReg(dest: IRExpr): string | null {
  if (dest.kind !== "reg") return null;
  const lower = dest.name.toLowerCase();
  if (isKnownRegister(lower) && regSize(lower) < 4) return null;
  return canonReg(lower);
}

interface LiveCtx {
  /** Live where a `break` lands, and where a `continue` lands. */
  brk: ReadonlySet<string>;
  cont: ReadonlySet<string>;
  /** Every register named anywhere in the body — the answer at a `goto`. */
  all: ReadonlySet<string>;
  /** Calls found to have a live result. Filled in as the walk runs. */
  captured: Set<IRStmt>;
}

/**
 * Rounds a loop's live set is allowed to grow for.
 *
 * The sets are canonical register names, so the universe is about twenty
 * elements and the iteration is monotone — two rounds is the normal cost of
 * confirming a fixpoint. The cap bounds the cost of deeply nested loops, whose
 * bodies are re-walked once per round of every enclosing loop. Stopping early
 * under-approximates, which loses an assignment rather than inventing one.
 */
const LIVE_ROUNDS = 4;

function union(a: ReadonlySet<string>, b: ReadonlySet<string>): Set<string> {
  const out = new Set(a);
  for (const x of b) out.add(x);
  return out;
}

function sameSet(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  if (a.size !== b.size) return false;
  for (const x of a) if (!b.has(x)) return false;
  return true;
}

/** Iterate `step` from `seed` until it stops growing, or `LIVE_ROUNDS` times. */
function liveFixpoint(
  step: (live: ReadonlySet<string>) => Set<string>,
  seed: Set<string>,
): Set<string> {
  let live = seed;
  for (let round = 0; round < LIVE_ROUNDS; round++) {
    const next = step(live);
    if (sameSet(next, live)) break;
    live = next;
  }
  return live;
}

/** The registers live before `stmts`, given those live after them. */
function liveInList(
  stmts: readonly IRStmt[],
  liveOut: ReadonlySet<string>,
  ctx: LiveCtx,
): Set<string> {
  let live = new Set(liveOut);
  for (let i = stmts.length - 1; i >= 0; i--) live = liveInStmt(stmts[i], live, ctx);
  return live;
}

/**
 * Backward liveness over the *structured* body, which is what emission walks.
 *
 * Doing it here rather than on the CFG is what makes the answer match the
 * output: the statement the reader sees after a call is the one this asks about.
 * The price is `goto`, which the tree does not model — see the case below.
 */
function liveInStmt(stmt: IRStmt, liveOut: ReadonlySet<string>, ctx: LiveCtx): Set<string> {
  switch (stmt.kind) {
    case "assign": {
      const live = new Set(liveOut);
      const kill = killedReg(stmt.dest);
      if (kill) live.delete(kill);
      // A destination that is not a register is an address computation, and
      // every register in it is read.
      if (stmt.dest.kind !== "reg") addReadRegs(stmt.dest, live);
      addReadRegs(stmt.src, live);
      return live;
    }

    case "store": {
      const live = new Set(liveOut);
      addReadRegs(stmt.address, live);
      addReadRegs(stmt.value, live);
      return live;
    }

    case "call_stmt": {
      const live = new Set(liveOut);
      if (stmt.resultDest?.kind === "reg") {
        const canon = canonReg(stmt.resultDest.name);
        if (live.has(canon)) ctx.captured.add(stmt);
        live.delete(canon);
      }
      // The argument registers a call destroys are not killed here: the reads
      // that would be affected have already been renamed away from the register
      // by `ssadestroy.ts`, and a read of a volatile register the call was *not*
      // given still binds to the definition before it.
      addReadRegs(stmt.call, live);
      return live;
    }

    case "return": {
      // Nothing after a `return` is reachable, so only what it returns is live.
      const live = new Set<string>();
      addReadRegs(stmt.value, live);
      return live;
    }

    case "if": {
      const live = liveInList(stmt.thenBody, liveOut, ctx);
      const other = stmt.elseBody ? liveInList(stmt.elseBody, liveOut, ctx) : liveOut;
      for (const r of other) live.add(r);
      addReadRegs(stmt.condition, live);
      return live;
    }

    case "while": {
      // The header is reached both from before the loop and from the end of the
      // body, so what is live there is the fixpoint of both.
      const seed = new Set(liveOut);
      addReadRegs(stmt.condition, seed);
      return liveFixpoint(
        (head) => union(seed, liveInList(stmt.body, head, { ...ctx, brk: liveOut, cont: head })),
        seed,
      );
    }

    case "do_while": {
      // The body runs before the test, and the back edge returns to the body's
      // first statement rather than to the condition.
      const exit = new Set(liveOut);
      addReadRegs(stmt.condition, exit);
      return liveFixpoint((entry) => {
        const test = union(exit, entry);
        return liveInList(stmt.body, test, { ...ctx, brk: liveOut, cont: test });
      }, new Set<string>());
    }

    case "for": {
      const seed = new Set(liveOut);
      addReadRegs(stmt.condition, seed);
      const head = liveFixpoint((h) => {
        // `continue` runs the update, so it lands where the update begins.
        const update = liveInStmt(stmt.update, h, ctx);
        return union(seed, liveInList(stmt.body, update, { ...ctx, brk: liveOut, cont: update }));
      }, seed);
      return liveInStmt(stmt.init, head, ctx);
    }

    case "switch": {
      const inner = { ...ctx, brk: liveOut };
      // Emission puts `default:` last, so the final case falls into it, and a
      // case without a `break` falls into the next one. Walking the cases in
      // reverse carries that through.
      const live = stmt.defaultBody
        ? liveInList(stmt.defaultBody, liveOut, inner)
        : new Set(liveOut);
      let fall: Set<string> = new Set(live);
      for (let i = stmt.cases.length - 1; i >= 0; i--) {
        fall = liveInList(stmt.cases[i].body, fall, inner);
        for (const r of fall) live.add(r);
      }
      addReadRegs(stmt.expr, live);
      return live;
    }

    case "try": {
      // The handler runs on a fault anywhere in the guarded body, so what it
      // reads is live throughout — including values the body would have killed.
      const handler = liveInList(stmt.handler, liveOut, ctx);
      const live = union(liveInList(stmt.body, union(liveOut, handler), ctx), handler);
      addReadRegs(stmt.filterExpr, live);
      return live;
    }

    case "phi": {
      // A phi that reaches emission is printed as a comment, so it assigns
      // nothing and cannot end a live range; its operands still had to come
      // from somewhere.
      const live = new Set(liveOut);
      for (const op of stmt.operands) addReadRegs(op.value, live);
      return live;
    }

    case "break":
      return new Set(ctx.brk);

    case "continue":
      return new Set(ctx.cont);

    case "goto": {
      // The label is elsewhere in the tree and this walk has no live set for it,
      // so the answer is every register the body names. That keeps the result of
      // a call whose only reader is past a jump, at the cost of keeping some
      // whose reader is not — the direction that states where a value came from
      // rather than dropping it.
      return new Set(ctx.all);
    }

    case "raw":
      // An unlifted instruction is emitted as a comment. It reads nothing in the
      // C, and the emitted function is self-consistent either way: no assignment
      // appears, and no read of it does either.
      return new Set(liveOut);

    case "label":
    case "comment":
      return new Set(liveOut);

    default: {
      // Compile error if a new IRStmt kind is added without a liveness rule.
      const _exhaustive: never = stmt;
      void _exhaustive;
      return new Set(liveOut);
    }
  }
}

/**
 * Every register name the function assigns, so `registerText` can tell a read
 * that names storage the body writes from one that does not.
 *
 * A call's result register counts only when the call is one whose result is
 * emitted (`captured`). The two have to agree: this set is what licenses
 * respelling a read of `al` as `(uint8_t)rax`, and that spelling is a lie about
 * a function whose only write of RAX is a call result that was never printed.
 *
 * The `never` binding at the bottom is load-bearing: a new `IRStmt` kind that
 * can assign a register would otherwise be missed silently, and the symptom
 * would be a read spelled as an alias of a register that is no longer written.
 */
function collectAssignedRegs(
  stmts: readonly IRStmt[],
  out: Set<string>,
  captured: ReadonlySet<IRStmt>,
): void {
  for (const stmt of stmts) {
    switch (stmt.kind) {
      case "assign":
        if (stmt.dest.kind === "reg") out.add(stmt.dest.name.toLowerCase());
        break;
      case "call_stmt":
        if (stmt.resultDest?.kind === "reg" && captured.has(stmt))
          out.add(stmt.resultDest.name.toLowerCase());
        break;
      case "phi":
        out.add(stmt.dest.name.toLowerCase());
        break;
      case "if":
        collectAssignedRegs(stmt.thenBody, out, captured);
        if (stmt.elseBody) collectAssignedRegs(stmt.elseBody, out, captured);
        break;
      case "while":
      case "do_while":
        collectAssignedRegs(stmt.body, out, captured);
        break;
      case "for":
        collectAssignedRegs([stmt.init, stmt.update], out, captured);
        collectAssignedRegs(stmt.body, out, captured);
        break;
      case "switch":
        for (const c of stmt.cases) collectAssignedRegs(c.body, out, captured);
        if (stmt.defaultBody) collectAssignedRegs(stmt.defaultBody, out, captured);
        break;
      case "try":
        collectAssignedRegs(stmt.body, out, captured);
        collectAssignedRegs(stmt.handler, out, captured);
        break;
      case "store":
      case "return":
      case "goto":
      case "label":
      case "comment":
      case "raw":
      case "break":
      case "continue":
        break;
      default: {
        const _exhaustive: never = stmt;
        void _exhaustive;
        break;
      }
    }
  }
}

/** Comparisons whose meaning depends on the operands being read as signed. */
const SIGNED_COMPARISONS = new Set<BinaryOp>(["<", "<=", ">", ">="]);

function emitExpr(expr: IRExpr, parentPrec = 0, signed = false): string {
  switch (expr.kind) {
    case "const": {
      // String literal lookup
      if (_stringMap) {
        const str = _stringMap.get(expr.value);
        if (str) return stringLiteral(str);
      }
      // No IOCTL decoding here: see annotateIOCTLArg. A constant is annotated
      // only where it is passed as a control code, never on shape alone.
      //
      // No enum member lookup either. It used to scan every synthesised enum
      // for one holding this value, which is a coincidence test, not evidence:
      // a switch with cases 0..3 gave the function an enum, and then every
      // literal 0, 1, 2 and 3 in it — loop bounds, flags, return values — came
      // out as `VAL_0x2` and so on, asserting membership of an enumeration
      // those constants have nothing to do with. Worse, nothing declared the
      // enum, so each of those names read as an undeclared identifier rather
      // than as its value. A member name is now used only at the two sites that
      // have the enum-typed value in hand: a `case` label, and a comparison
      // against a value whose type is that enum.
      return formatHex(expr.value);
    }

    case "reg":
      return registerText(expr, signed);

    case "var":
      return expr.name;

    case "binary": {
      // C has no logical-shift-right operator; this one needs a width.
      if (expr.op === ">>>") return emitLogicalShiftRight(expr, parentPrec);
      // Type-aware idioms
      if (_typeCtx) {
        const idiom = emitTypeIdiom(expr);
        if (idiom) return parentPrec > 0 ? `(${idiom})` : idiom;
      }
      const prec = PREC[expr.op] ?? 0;
      // `>>` is the arithmetic shift (`shr` lifts to `>>>`), so its left
      // operand is read as signed for the same reason a signed comparison's is.
      const signedOperands = SIGNED_COMPARISONS.has(expr.op);
      const byteArith = BYTE_ARITH_OPS.has(expr.op);
      const left = byteArith
        ? byteArithOperand(expr.left, prec)
        : emitExpr(expr.left, prec, signedOperands || expr.op === ">>");
      // A constant compared against an enum-typed value is the one place a
      // synthesised member name says something: it is the value that switch
      // distinguished. Anywhere else the name would be asserting membership of
      // an enum the constant has nothing to do with — see `emitExpr`'s `const`.
      const member =
        expr.op === "==" || expr.op === "!="
          ? enumMemberName(getExprType(expr.left), expr.right)
          : null;
      const right =
        member ??
        (byteArith
          ? byteArithOperand(expr.right, prec + 1)
          : emitExpr(expr.right, prec + 1, signedOperands));
      const result = `${left} ${opStr(expr.op)} ${right}`;
      return prec < parentPrec ? `(${result})` : result;
    }

    case "unary": {
      const operand = emitExpr(expr.operand, 99);
      return `${expr.op}${operand}`;
    }

    case "deref": {
      const type = sizeToType(expr.size);
      const addr = emitExpr(expr.address, 0);
      return `*(${type}*)(${addr})`;
    }

    case "field_access":
      return fieldAccess(expr);

    case "array_access": {
      const type = sizeToType(expr.elementSize);
      const base = emitExpr(expr.base, 0);
      const index = emitExpr(expr.index, 0);
      // If base is a field_access, use -> syntax: base->field[index]
      if (expr.base.kind === "field_access") {
        return `${emitExpr(expr.base)}[${index}]`;
      }
      return `((${type}*)${base})[${index}]`;
    }

    case "call": {
      const name = calleeText(expr.display?.split("!")?.pop() ?? expr.target);
      const ioctlArg = ioctlCodeArgIndex(name);
      const args = expr.args
        .map((a, i) => {
          const text = emitExpr(a, 0);
          return i === ioctlArg ? annotateIOCTLArg(a, text) : text;
        })
        .join(", ");
      return `${name}(${args})`;
    }

    case "cast": {
      // Redundant cast suppression: skip cast when operand's known type matches
      if (_typeCtx && (expr.operand.kind === "reg" || expr.operand.kind === "var")) {
        const name = expr.operand.kind === "reg" ? expr.operand.name : expr.operand.name;
        const known = _typeCtx.types.get(name);
        if (known && known.kind !== "unknown") {
          const knownStr = typeToString(known);
          if (knownStr === expr.type) return emitExpr(expr.operand, parentPrec);
        }
      }
      return `(${expr.type})${emitExpr(expr.operand, 99)}`;
    }

    case "ternary": {
      const cond = emitExpr(expr.condition, 0);
      const then = emitExpr(expr.then, 0);
      const els = emitExpr(expr.else, 0);
      const result = `${cond} ? ${then} : ${els}`;
      return parentPrec > 0 ? `(${result})` : result;
    }

    case "unknown":
      return unrecoveredValue(expr.text);

    default: {
      // Compile error if a new IRExpr kind is added without an emitter.
      const _exhaustive: never = expr;
      return _exhaustive;
    }
  }
}

// ── Statement Emission ──

function indent(level: number): string {
  return "    ".repeat(level);
}

/** Get the instruction address from a statement, if present */
function stmtAddr(stmt: IRStmt): number | undefined {
  switch (stmt.kind) {
    case "assign":
      return stmt.addr;
    case "store":
      return stmt.addr;
    case "call_stmt":
      return stmt.addr;
    case "return":
      return stmt.addr;
    case "raw":
      return stmt.addr;
    case "phi":
      return stmt.addr;
    default:
      return undefined;
  }
}

interface EmitResult {
  lines: string[];
  addrs: (number | undefined)[];
}

function emitStmt(stmt: IRStmt, level: number): EmitResult {
  const pad = indent(level);
  const lines: string[] = [];
  const addrs: (number | undefined)[] = [];
  const addr = stmtAddr(stmt);

  function push(line: string, lineAddr?: number | undefined) {
    lines.push(line);
    addrs.push(lineAddr);
  }

  switch (stmt.kind) {
    case "assign": {
      const dest = emitExpr(stmt.dest, 0);
      const src = emitExpr(stmt.src, 0);
      // Compound assignment: dest = dest OP rhs → dest OP= rhs
      if (stmt.src.kind === "binary" && COMPOUND_OPS.has(stmt.src.op)) {
        const lhs = emitExpr(stmt.src.left, 0);
        if (lhs === dest) {
          const rhs = emitExpr(stmt.src.right, 0);
          // Increment/decrement: x += 1 → x++, x -= 1 → x--
          if (stmt.src.right.kind === "const" && stmt.src.right.value === 1) {
            if (stmt.src.op === "+") {
              push(`${pad}${dest}++;`, addr);
              break;
            }
            if (stmt.src.op === "-") {
              push(`${pad}${dest}--;`, addr);
              break;
            }
          }
          push(`${pad}${dest} ${opStr(stmt.src.op)}= ${rhs};`, addr);
          break;
        }
      }
      push(`${pad}${dest} = ${src};`, addr);
      break;
    }

    case "store": {
      const type = sizeToType(stmt.size);
      const addrStr = emitExpr(stmt.address, 0);
      const storeTarget = `*(${type}*)(${addrStr})`;
      // Compound assignment for regular stores
      if (stmt.value.kind === "binary" && COMPOUND_OPS.has(stmt.value.op)) {
        const lhs = emitExpr(stmt.value.left, 0);
        if (lhs === storeTarget) {
          const rhs = emitExpr(stmt.value.right, 0);
          push(`${pad}${storeTarget} ${opStr(stmt.value.op)}= ${rhs};`, addr);
          break;
        }
      }
      const val = emitExpr(stmt.value, 0);
      push(`${pad}${storeTarget} = ${val};`, addr);
      break;
    }

    case "call_stmt": {
      const call = emitExpr(stmt.call, 0);
      // The result register, when the body reads it — see `collectCapturedCalls`.
      // Its own name, not `registerText`'s: the result is RAX or EAX, which that
      // never respells anyway, and an assignment target is the one position
      // where a narrowing cast would not be an lvalue.
      const dest =
        stmt.resultDest?.kind === "reg" && _capturedCalls.has(stmt) ? stmt.resultDest.name : null;
      push(`${pad}${dest === null ? "" : `${dest} = `}${call};`, addr);
      break;
    }

    case "return": {
      if (stmt.value) {
        const val = emitExpr(stmt.value, 0);
        push(`${pad}return ${val};`, addr);
      } else {
        push(`${pad}return;`, addr);
      }
      break;
    }

    case "if": {
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}if (${cond}) {`);
      for (const s of stmt.thenBody) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      if (stmt.elseBody && stmt.elseBody.length > 0) {
        // Check for else-if chain
        if (stmt.elseBody.length === 1 && stmt.elseBody[0].kind === "if") {
          const elseIf = stmt.elseBody[0];
          push(`${pad}} else `);
          // Remove last line's newline context and append if
          const lastIdx = lines.length - 1;
          const elseIfResult = emitStmt(elseIf, level);
          if (elseIfResult.lines.length > 0) {
            lines[lastIdx] = lines[lastIdx] + elseIfResult.lines[0].trimStart();
            addrs[lastIdx] = elseIfResult.addrs[0]; // inherit addr from else-if
            lines.push(...elseIfResult.lines.slice(1));
            addrs.push(...elseIfResult.addrs.slice(1));
          }
        } else {
          push(`${pad}} else {`);
          for (const s of stmt.elseBody) {
            const r = emitStmt(s, level + 1);
            lines.push(...r.lines);
            addrs.push(...r.addrs);
          }
          push(`${pad}}`);
        }
      } else {
        push(`${pad}}`);
      }
      break;
    }

    case "while": {
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}while (${cond}) {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      push(`${pad}}`);
      break;
    }

    case "do_while": {
      push(`${pad}do {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}} while (${cond});`);
      break;
    }

    case "switch": {
      const expr = emitExpr(stmt.expr, 0);
      push(`${pad}switch (${expr}) {`);
      // Check if switch expression has enum type
      let enumType: DecompType | undefined;
      if (_typeCtx) {
        if (stmt.expr.kind === "reg") enumType = _typeCtx.types.get(canonReg(stmt.expr.name));
        else if (stmt.expr.kind === "var") enumType = _typeCtx.types.get(stmt.expr.name);
      }
      const ioctlLabels = ioctlSwitchLabels(stmt);
      for (const c of stmt.cases) {
        for (const v of c.values) {
          const memberName = enumMemberName(enumType, { kind: "const", value: v, size: 4 });
          const decoded = ioctlLabels ? formatIOCTL(v) : null;
          const note = decoded ? ` /* ${decoded} */` : "";
          push(`${pad}case ${memberName ?? formatHex(v)}:${note}`);
        }
        for (const s of c.body) {
          const r = emitStmt(s, level + 2);
          lines.push(...r.lines);
          addrs.push(...r.addrs);
        }
      }
      if (stmt.defaultBody) {
        push(`${pad}default:`);
        for (const s of stmt.defaultBody) {
          const r = emitStmt(s, level + 2);
          lines.push(...r.lines);
          addrs.push(...r.addrs);
        }
      }
      push(`${pad}}`);
      break;
    }

    case "goto":
      push(`${pad}goto ${stmt.label};`);
      break;

    case "label":
      push(`${stmt.name}:`);
      break;

    case "comment":
      push(`${pad}// ${commentSafe(stmt.text)}`);
      break;

    case "raw": {
      // `raw` carries two things. An empty text is `cleanup.ts` asking for an
      // empty statement, to give a trailing label something to label — there is
      // no instruction behind it and nothing to report.
      if (stmt.text === "") {
        push(`${pad};`, addr);
        break;
      }
      // Otherwise: an instruction the lifter has no C for. Its text is always a
      // disassembly line — `mnemonic operands`, or the same wrapped in MSVC's
      // `__asm { }`, which is not C at all outside MSVC and was the other bulk
      // of the syntax errors.
      //
      // There is nothing to translate it into: writing `__asm__("...")` would
      // make it *look* handled while handing gcc Intel-syntax operands it
      // cannot assemble, i.e. it would pass a syntax check and fail later. So
      // the instruction stays visible verbatim and says it was not lifted,
      // which is exactly what a comment is for. The empty statement after it
      // keeps the position a statement, so a label or a one-statement block
      // body still compiles.
      const text = /^__asm \{(.*)\}$/.exec(stmt.text)?.[1]?.trim() ?? stmt.text;
      push(`${pad}/* unlifted: ${commentSafe(text)} */;`, addr);
      break;
    }

    case "for": {
      const initR = emitStmt(stmt.init, 0);
      const initStr = initR.lines[0]?.trim().replace(/;$/, "") ?? "";
      const updateR = emitStmt(stmt.update, 0);
      const updateStr = updateR.lines[0]?.trim().replace(/;$/, "") ?? "";
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}for (${initStr}; ${cond}; ${updateStr}) {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      push(`${pad}}`);
      break;
    }

    case "break":
      push(`${pad}break;`);
      break;

    case "continue":
      push(`${pad}continue;`);
      break;

    case "try": {
      push(`${pad}__try {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      const filter = stmt.filterExpr ? emitExpr(stmt.filterExpr, 0) : "EXCEPTION_EXECUTE_HANDLER";
      push(`${pad}} __except(${filter}) {`);
      for (const s of stmt.handler) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      push(`${pad}}`);
      break;
    }

    case "phi": {
      // destroySSA converts every phi to copies, so one reaching the emitter
      // means SSA destruction was incomplete. Emit it as a comment rather than
      // silently dropping the statement (which used to produce no line at all).
      const ops = stmt.operands
        .map(
          (o) =>
            `${o.value.name}${o.value.version !== undefined ? `_${o.value.version}` : ""}@B${o.blockId}`,
        )
        .join(", ");
      const dest = `${stmt.dest.name}${stmt.dest.version !== undefined ? `_${stmt.dest.version}` : ""}`;
      push(`${pad}/* unresolved phi: ${dest} = phi(${ops}) */`, addr);
      break;
    }

    default: {
      // Compile error if a new IRStmt kind is added without an emitter.
      const _exhaustive: never = stmt;
      void _exhaustive;
      break;
    }
  }

  return { lines, addrs };
}

// ── Function Emission ──

function fieldTypeString(field: import("./structs").StructField): string {
  return typeToString(field.type);
}

/**
 * An offset, spelled the way a field name spells it (`structs.ts`'s
 * `offsetLabel`), so that a padding member and the notes below read against the
 * same scale as `field_0x18`. `formatHex` drops the `0x` for single digits,
 * which is right in an expression and confusing in an offset.
 */
function offsetLabel(offset: number): string {
  return offset < 0
    ? `-0x${(-offset).toString(16).toUpperCase()}`
    : `0x${offset.toString(16).toUpperCase()}`;
}

/** The `<stdint.h>` spelling of an unsigned integer exactly `size` bytes wide, if there is one. */
function unsignedTypeOfSize(size: number): string | null {
  switch (size) {
    case 1:
      return "uint8_t";
    case 2:
      return "uint16_t";
    case 4:
      return "uint32_t";
    case 8:
      return "uint64_t";
    default:
      return null;
  }
}

/**
 * The width, in bytes, that a member declared with this type occupies — or null
 * where nothing here can pin it down.
 *
 * Two entries are assumptions rather than facts, and they are written down once
 * here rather than spread through the layout code. A pointer is taken to be 8
 * bytes: the emitted C does not fix a pointer width, so the layout it claims is
 * the one a reader gets on LP64/LLP64, which is every compiler this is likely
 * to be pasted into. `HANDLE`, `BOOL`, `NTSTATUS` and `HRESULT` are typedefs
 * the *reader* supplies, so their widths are the Windows ones those names mean
 * (a pointer, and 32 bits for the other three) — that is what the emitted names
 * assert, and a reader who defines them as something else has changed the
 * subject.
 *
 * `enum` is null on purpose even though gcc almost always picks 4: its width is
 * implementation-defined, and a field whose offset depends on that choice is
 * not one this can promise.
 */
const POINTER_WIDTH = 8;

function assumedWidth(t: DecompType): number | null {
  switch (t.kind) {
    case "int":
      // Anything but 1/2/4/8 is spelled `int`/`unsigned int` by typeToString.
      return unsignedTypeOfSize(t.size) ? t.size : 4;
    case "float":
      return t.size === 4 ? 4 : 8;
    case "ptr":
    case "struct":
    case "handle":
      return POINTER_WIDTH;
    case "bool":
    case "ntstatus":
    case "hresult":
      return 4;
    case "unknown":
      return 4; // spelled `int`
    case "array": {
      const element = assumedWidth(t.element);
      return element === null || t.count <= 0 ? null : element * t.count;
    }
    case "enum":
    case "void":
      return null;
  }
}

/**
 * The largest offset this will lay a field out at.
 *
 * Struct synthesis used to hand over a "field" at 0x140014770 — an absolute
 * address that reached a base as a displacement — and placing it means
 * declaring five gigabytes of padding nobody observed, in a struct nothing can
 * use. C89's own translation limits guarantee an object of only 32767 bytes, so
 * a layout past that is not one the emitted dialect promises to be able to
 * state at all; beyond it the field is reported rather than placed.
 *
 * `MAX_FIELD_OFFSET` in structs.ts now refuses to call such a displacement an
 * offset in the first place, and the two bounds are deliberately equal — but
 * they are separate statements (what this dialect can lay out; what can be a
 * position in an object), so this stays as the backstop that keeps a def
 * arriving from anywhere else visible rather than misplaced.
 */
const MAX_LAYOUT_EXTENT = 0x8000;

interface PadMember {
  kind: "pad";
  /** Offset the padding starts at, and how many bytes of it there are. */
  offset: number;
  size: number;
}

interface FieldMember {
  kind: "field";
  field: import("./structs").StructField;
  /** The declaration text, without indentation. */
  decl: string;
  /** Bytes the declaration occupies, so the next member's padding is computable. */
  width: number;
  /**
   * The type the declaration actually spells — the element type for an array
   * field. Not the same as `typeToString(field.type)`: a field whose inferred
   * type would displace the next recorded offset is declared at the width its
   * access had instead, and the emitted body has to agree with what was
   * declared rather than with what was inferred.
   */
  type: string;
}

/** A field no declaration can place, kept in offset order among the members it sits between. */
interface NoteMember {
  kind: "note";
  field: import("./structs").StructField;
  reason: string;
}

interface StructLayout {
  /** Declaration order: padding, fields and notes about the fields left out. */
  members: (PadMember | FieldMember | NoteMember)[];
  /** Names of the fields no declaration can place, for spelling their accesses. */
  unplaceable: Set<string>;
  /** Whether anything at all could be declared. */
  anyPlaced: boolean;
  /** Field name → the type its declaration spells, for typing accesses in the body. */
  declaredTypes: Map<string, string>;
}

/**
 * Where each field of a struct definition actually lands, and which ones cannot
 * land anywhere.
 *
 * The field *names* carry the recovered offsets, so a declaration that does not
 * reproduce them is a statement the machine code contradicts —
 * `struct_0 { uint32_t field_0x0; uint16_t field_0x18; }` puts `field_0x18` at
 * 4, and every `p->field_0x18` in the body then reads bytes the access never
 * touched. It compiles, and nothing in it says the shape is not what it looks
 * like. 131 of the 149 struct definitions emitted over the three distlib
 * binaries were wrong in exactly this way (peek-a-bin-ey0).
 *
 * Explicit padding fixes the gaps and `#pragma pack(1)` (emitted around the
 * definitions) stops the compiler from putting its own alignment back on top —
 * neither works without the other, since padding alone cannot express an
 * unaligned recovered offset.
 *
 * Three kinds of field cannot be placed by any amount of padding, and they are
 * reported instead of being declared somewhere convenient:
 *
 * - one whose bytes overlap a field already placed. Two intersecting extents
 *   have no faithful struct spelling; at most one of the two readings is right,
 *   and a union would assert that both are members of one type, which is a
 *   claim about the object rather than about the accesses that were seen.
 * - one at a negative offset, which `offsetof` cannot express.
 * - one past MAX_LAYOUT_EXTENT.
 *
 * Their accesses stay honest by being spelled as what they are — bytes at a
 * distance from the base, see `fieldAccess` — so nothing is lost but the name.
 * Which of two overlapping fields is kept is decided by offset, first wins:
 * arbitrary, but deterministic, and the loser is still in the output.
 *
 * A declared type is kept unless it would push the *next* recorded offset out of
 * place, which is the only thing the layout needs from it; where it would, the
 * field is declared at the width the access actually had and the inferred type
 * moves to a comment. That keeps `struct_1 *field_0x8` — the useful thing to say
 * — in the common case where the next field is 8 or more bytes further on, and
 * corrects it in the case where C would otherwise contradict a recorded offset.
 */
function computeStructLayout(def: import("./structs").StructDef): StructLayout {
  // A copy: the registry's field arrays are shared, live state, and this sorts.
  // The registry sorts on merge but not on creation, where the field list
  // follows the order the accesses were discovered.
  const fields = [...def.fields].sort((a, b) => a.offset - b.offset);
  const members: StructLayout["members"] = [];
  const unplaceable = new Set<string>();
  const declaredTypes = new Map<string, string>();
  let cursor = 0;

  for (let i = 0; i < fields.length; i++) {
    const field = fields[i];
    const next = fields[i + 1];
    const reject = (reason: string) => {
      unplaceable.add(field.name);
      members.push({ kind: "note", field, reason });
    };

    if (field.offset < 0) {
      reject("a negative offset is not a position in a struct");
      continue;
    }
    if (field.offset >= MAX_LAYOUT_EXTENT) {
      reject(`past ${offsetLabel(MAX_LAYOUT_EXTENT)}, the largest layout this states`);
      continue;
    }
    if (field.offset < cursor) {
      const prev = [...members].reverse().find((m): m is FieldMember => m.kind === "field");
      const where = prev
        ? `${prev.field.name}, which occupies ${offsetLabel(prev.field.offset)}..${offsetLabel(prev.field.offset + prev.width)}`
        : "an earlier field";
      reject(`its bytes overlap ${where}`);
      continue;
    }

    // A struct whose only member is a flexible array member is rejected by C
    // ("flexible array member in a struct with no named members"), and a field
    // at offset 0 with nothing before or after it is the only way to reach that.
    const soleMember = fields.length === 1 && field.offset === 0;
    const placed = declareField(field, next, soleMember);
    if (!placed) {
      reject(`no declaration is ${field.size} bytes wide`);
      continue;
    }

    if (field.offset > cursor) {
      members.push({ kind: "pad", offset: cursor, size: field.offset - cursor });
    }
    members.push({
      kind: "field",
      field,
      decl: placed.decl,
      width: placed.width,
      type: placed.type,
    });
    declaredTypes.set(field.name, placed.type);
    cursor = field.offset + placed.width;
  }

  return {
    members,
    unplaceable,
    anyPlaced: members.some((m) => m.kind === "field"),
    declaredTypes,
  };
}

/** What is said about a field the layout could not place. Never itself a comment — the callers wrap it. */
function noteText(note: NoteMember): string {
  const bytes = note.field.size === 1 ? "byte" : "bytes";
  return `${note.field.name}: ${note.field.size} ${bytes} at ${offsetLabel(note.field.offset)} — ${note.reason}. Not declared; its accesses are spelled as byte offsets from the base.`;
}

/**
 * A field declaration and the bytes it occupies, or null when the recovered
 * width has no spelling at all.
 *
 * `next` is the following field *by offset* — the bound on how wide this one may
 * be declared. An array field is left alone by that bound because its extent is
 * already derived from it: `isArray` records only that the offset was reached
 * through an index, and struct synthesis never learns an element count, so the
 * gap to the next field is what bounds it (declaring every one of them `[]` was
 * both "flexible array member not at end of struct" and a worse reading than the
 * layout supports). Only a genuinely trailing field has an extent nothing
 * constrains, which is what a flexible array member means.
 */
function declareField(
  field: import("./structs").StructField,
  next: import("./structs").StructField | undefined,
  soleMember: boolean,
): { decl: string; width: number; type: string } | null {
  if (field.isArray) return declareArrayField(field, next, soleMember);

  const typeStr = fieldTypeString(field);
  const width = assumedWidth(field.type);
  const gap = next ? next.offset - field.offset : Number.POSITIVE_INFINITY;
  // The inferred type is kept unless it is either unmeasurable or claims more
  // room than the access had *and* than the next recorded offset leaves. Where
  // the access itself is the wider of the two, narrowing to it would not free
  // the next offset either — the fields genuinely overlap — so the more
  // informative spelling stays and the overlap is reported below.
  if (width !== null && (width <= gap || field.size >= width)) {
    return { decl: `${typeStr} ${field.name};`, width, type: typeStr };
  }

  const exact = unsignedTypeOfSize(field.size);
  if (!exact)
    return width === null ? null : { decl: `${typeStr} ${field.name};`, width, type: typeStr };
  return { decl: `${exact} ${field.name}; /* ${typeStr} */`, width: field.size, type: exact };
}

function declareArrayField(
  field: import("./structs").StructField,
  next: import("./structs").StructField | undefined,
  soleMember: boolean,
): { decl: string; width: number; type: string } | null {
  const elementSize =
    field.arrayElementSize && field.arrayElementSize > 0
      ? field.arrayElementSize
      : Math.max(1, field.size);
  // The element type has to be as wide as the stride, or the declaration
  // contradicts itself: `uint32_t a[n]` with an 8-byte stride describes a
  // different object from the one the accesses walked (peek-a-bin-hyv).
  const declaredType = fieldTypeString(field);
  const elementType =
    assumedWidth(field.type) === elementSize ? declaredType : unsignedTypeOfSize(elementSize);
  if (!elementType) return null;

  if (next) {
    const span = next.offset - field.offset;
    const count = Math.max(1, Math.floor(span / elementSize));
    return {
      decl: `${elementType} ${field.name}[${count}];`,
      width: count * elementSize,
      type: elementType,
    };
  }
  if (soleMember) {
    return {
      decl: `${elementType} ${field.name}[1]; // extent unknown`,
      width: elementSize,
      type: elementType,
    };
  }
  // Nothing bounds a trailing field, and a flexible array member is exactly
  // that reading. It occupies no bytes, so nothing can follow it — which is
  // also why C requires it to be last.
  return { decl: `${elementType} ${field.name}[];`, width: 0, type: elementType };
}

/** The struct a field type names, if it names one — directly, behind a pointer, or as an array element. */
function referencedStructId(t: DecompType): string | null {
  if (t.kind === "struct") return t.id;
  if (t.kind === "ptr") return referencedStructId(t.pointee);
  if (t.kind === "array") return referencedStructId(t.element);
  return null;
}

/**
 * Every struct name the typedef block mentions, in a stable order: the defined
 * ones first, then any referenced only as a field type.
 *
 * The second group is not hypothetical — `IRFunction.typedefs` is a snapshot of
 * the structs *this* function touched, and a field can point at one that only
 * another function's code reaches, so its definition never appears here at all.
 */
function declaredStructIds(
  defs: readonly import("./structs").StructDef[],
  usedInBody: ReadonlySet<string>,
): string[] {
  const ids: string[] = [];
  const seen = new Set<string>();
  const add = (id: string) => {
    if (!seen.has(id)) {
      seen.add(id);
      ids.push(id);
    }
  };
  for (const def of defs) add(def.id);
  for (const def of defs) {
    for (const field of def.fields) {
      const ref = referencedStructId(field.type);
      if (ref) add(ref);
    }
  }
  // A struct the body casts to but no definition here describes. Forward
  // declaring it is all that can honestly be said — a name for an object whose
  // layout this function does not have — and it is better than the alternative,
  // which is an undeclared type name that stops the reader at the parse rather
  // than at the missing definition.
  for (const id of usedInBody) add(id);
  return ids;
}

/** Every struct id the emitted body casts a pointer to. */
function structIdsUsedInBody(body: readonly IRStmt[]): Set<string> {
  const ids = new Set<string>();
  walkStmts(body as IRStmt[], (expr) => {
    if (expr.kind === "field_access") ids.add(expr.structId);
  });
  return ids;
}

/**
 * A statement line emitted for instruction `addr` carries this label name, which
 * is exactly the spelling `structure.ts` uses when it emits a `goto` to a block
 * (`loc_` + uppercase hex of the block's start address). Deriving the name from
 * the address rather than parsing the address out of the label keeps the two
 * sides from drifting on formatting.
 */
function labelForAddr(addr: number): string {
  return `loc_${addr.toString(16).toUpperCase()}`;
}

/** A whole line that is exactly a `goto`, so a string constant containing one cannot match. */
const GOTO_LINE = /^(\s*)goto ([A-Za-z_]\w*);$/;

/**
 * Give every emitted `goto` its label, or say why it has none.
 *
 * This runs over the emitted lines rather than over the IR, for two reasons.
 * The IR has no label statement to anchor to — `IRLabel` exists but nothing
 * produces it, `structure.ts` emits the `goto` and nothing else — so the anchor
 * has to be found by address, and `lineAddrs` is precisely the record of which
 * address ended up on which emitted line. Walking the IR instead would mean a
 * thirty-first statement-kind switch to keep in sync (see CLAUDE.md), and it
 * would anchor to statements that are *not* in the output: a `for` header
 * renders its init and update through `emitStmt` and then throws those lines
 * away, so a label placed there would vanish and the goto would still dangle.
 *
 * A target with no emitted line is left unplaced on purpose. It means no code
 * for that address reached the output — an empty lifted block, or a branch body
 * that was dropped — and inventing a label somewhere else would turn a visibly
 * broken jump into a silently wrong one. The comment names the address so the
 * reader can tell "the emitter forgot the label" from "that code is missing".
 */
function placeGotoLabels(lines: string[], lineAddrs: (number | undefined)[]): void {
  const targets = new Set<string>();
  for (const line of lines) {
    const m = GOTO_LINE.exec(line);
    if (m) targets.add(m[2]);
  }
  if (targets.size === 0) return;

  // An `IRLabel` statement already emitted for one of these names counts as
  // placed. Nothing produces `IRLabel` today, but `cleanup.ts` still matches on
  // it, and inserting a second definition of the same label would not compile.
  const already = new Set<string>();
  for (const line of lines) {
    const m = /^\s*([A-Za-z_]\w*):$/.exec(line);
    if (m && targets.has(m[1])) already.add(m[1]);
  }

  // First line carrying each wanted address wins: a block is emitted once, and
  // if an address somehow appears twice the earlier copy is the one the jump
  // was structured around.
  const anchors = new Map<string, number>();
  for (let i = 0; i < lineAddrs.length; i++) {
    const addr = lineAddrs[i];
    if (addr === undefined) continue;
    const name = labelForAddr(addr);
    if (targets.has(name) && !already.has(name) && !anchors.has(name)) anchors.set(name, i);
  }

  for (let i = 0; i < lines.length; i++) {
    const m = GOTO_LINE.exec(lines[i]);
    if (m && !anchors.has(m[2]) && !already.has(m[2])) {
      lines[i] = `${lines[i]} // no label: nothing was emitted for this address`;
    }
  }

  // Insert from the bottom up so the indices computed above stay valid.
  for (const [name, index] of [...anchors].sort((a, b) => b[1] - a[1])) {
    const lineIndent = /^ */.exec(lines[index])?.[0] ?? "";
    // One level out from the statement it introduces, the usual C style.
    const pad = lineIndent.length >= 4 ? lineIndent.slice(4) : "";
    lines.splice(index, 0, `${pad}${name}:`);
    lineAddrs.splice(index, 0, undefined);
  }
}

export interface EmitFunctionResult {
  code: string;
  lineMap: Map<number, number>; // line number (0-based) → instruction address
}

export function emitFunction(
  func: IRFunction,
  typeCtx?: TypeContext,
  stringMap?: Map<number, string>,
): EmitFunctionResult {
  // emitStmt/emitExpr are mutually recursive and unbounded, so deeply nested IR
  // can throw (e.g. RangeError) part-way through, and pipeline.ts swallows the
  // exception. The unwind used to skip the reset at the bottom of this function
  // and leave both globals pointing at the failed function's state; nothing
  // observed it only because the next call reassigns them on entry. try/finally
  // makes that independent of the assignments above, and save/restore (rather
  // than clear) keeps the state correct should emission ever nest.
  const prevTypeCtx = _typeCtx;
  const prevStringMap = _stringMap;
  const prevUnrecovered = _unrecovered;
  const prevDeclaredTypes = _declaredTypes;
  const prevStructDefs = _structDefs;
  const prevLayouts = _layouts;
  const prevUsedEnums = _usedEnums;
  const prevEnumTypesNeeded = _enumTypesNeeded;
  const prevDeclaredVarTypes = _declaredVarTypes;
  const prevAssignedRegs = _assignedRegs;
  const prevCapturedCalls = _capturedCalls;
  _typeCtx = typeCtx;
  _stringMap = stringMap;
  _unrecovered = [];
  _declaredTypes = new Map();
  _structDefs = new Map((func.typedefs ?? []).map((d) => [d.id, d]));
  // Computed once, before the body: an access to a field the declaration cannot
  // place has to be spelled differently, and the body is emitted first.
  _layouts = new Map((func.typedefs ?? []).map((d) => [d.id, computeStructLayout(d)]));
  _usedEnums = new Map();
  _enumTypesNeeded = new Set();
  _declaredVarTypes = new Map();
  // Computed before the body for the same reason the layouts are: a register
  // read has to know, at the point it is emitted, whether the function assigns
  // that name anywhere at all.
  // Which calls print their result has to be settled before both of the sets
  // below: it decides what the body says, and `_assignedRegs` has to agree with
  // what the body says.
  _capturedCalls = collectCapturedCalls(func.body);
  _assignedRegs = new Set();
  collectAssignedRegs(func.body, _assignedRegs, _capturedCalls);
  for (const d of [...func.params, ...func.locals]) {
    _declaredVarTypes.set(d.name, d.type);
    const id = declaredStructPointer(d.type);
    if (id) _declaredTypes.set(d.name, id);
    // A declaration spelled with an enum's name needs that enum to exist, even
    // if no member of it is ever named in the body.
    const enumType = enumTypeNamed(d.type);
    if (enumType) {
      _usedEnums.set(enumType.name, enumType);
      _enumTypesNeeded.add(enumType.name);
    }
  }
  try {
    return emitFunctionBody(func);
  } finally {
    _typeCtx = prevTypeCtx;
    _stringMap = prevStringMap;
    _unrecovered = prevUnrecovered;
    _declaredTypes = prevDeclaredTypes;
    _structDefs = prevStructDefs;
    _layouts = prevLayouts;
    _usedEnums = prevUsedEnums;
    _enumTypesNeeded = prevEnumTypesNeeded;
    _declaredVarTypes = prevDeclaredVarTypes;
    _assignedRegs = prevAssignedRegs;
    _capturedCalls = prevCapturedCalls;
  }
}

function emitFunctionBody(func: IRFunction): EmitFunctionResult {
  const lines: string[] = [];
  const lineAddrs: (number | undefined)[] = [];

  // The body is emitted first and spliced in below, because emitting it is what
  // discovers the declarations the header needs: a value the recovery gave up
  // on is only known to exist once the statement that wanted it is emitted.
  const bodyLines: string[] = [];
  const bodyAddrs: (number | undefined)[] = [];
  for (const stmt of func.body) {
    const result = emitStmt(stmt, 1);
    bodyLines.push(...result.lines);
    bodyAddrs.push(...result.addrs);
  }

  // Declare every synthesised enum the body ended up naming a member of.
  //
  // The members are given explicit values, which is what makes the output true
  // rather than merely compilable: `VAL_0x2` is a name typeInfer derived from
  // the value 2, so declaring it as 2 states exactly what the switch label
  // already meant. The enum itself is still a guess (a switch with three or
  // more cases), but it is a guess about grouping, not about any value.
  //
  // A member name is shared across enums when the value is, because the name is
  // derived from the value — so it is declared once, by whichever enum reaches
  // it first, and an enum left with nothing new to declare gets an empty one,
  // which C rejects. Such an enum only needs a type name at all if a
  // declaration is spelled with it.
  if (_usedEnums.size > 0) {
    const declared = new Set<string>();
    const enumLines: string[] = [];
    for (const [name, type] of _usedEnums) {
      const members = [...type.members]
        .sort((a, b) => a[0] - b[0])
        .filter(([, member]) => !declared.has(member));
      for (const [, member] of members) declared.add(member);
      if (members.length > 0) {
        const body = members.map(([value, member]) => `${member} = ${formatHex(value)}`).join(", ");
        enumLines.push(`typedef enum { ${body} } ${name};`);
      } else if (_enumTypesNeeded.has(name)) {
        enumLines.push(`typedef int ${name}; /* every member is declared above */`);
      }
    }
    if (enumLines.length > 0) {
      for (const line of enumLines) {
        lines.push(line);
        lineAddrs.push(undefined);
      }
      lines.push("");
      lineAddrs.push(undefined);
    }
  }

  // Emit typedef block for struct definitions.
  //
  // Forward-declare every name first, then define. A topological sort would
  // also fix the case that prompted this (struct_5 declaring a `struct_6*`
  // field before struct_6 existed, which does not compile), but it cannot
  // order a cycle, and mutually-referencing structs are exactly what struct
  // synthesis produces — the self-referencing linked-list node below is one
  // already. Forward declarations are one pass, order-independent and handle
  // both, at the cost of a few lines at the top.
  //
  // The definitions therefore use the tag form (`struct struct_0 { ... };`)
  // rather than a typedef of an anonymous struct: a forward declaration of an
  // anonymous struct is not expressible, and redefining the typedef name is
  // only legal from C11 on.
  const bodyStructIds = structIdsUsedInBody(func.body);
  if ((func.typedefs && func.typedefs.length > 0) || bodyStructIds.size > 0) {
    for (const id of declaredStructIds(func.typedefs ?? [], bodyStructIds)) {
      lines.push(`typedef struct ${id} ${id};`);
      lineAddrs.push(undefined);
    }
    lines.push("");
    lineAddrs.push(undefined);

    // `#pragma pack(1)` is not decoration: the padding below places each field
    // at the offset its name records, and default alignment would put the
    // compiler's own padding back on top of it — which is how `field_0x18`
    // ended up at 4. Neither half works without the other.
    const definitions: string[] = [];
    for (const def of func.typedefs ?? []) {
      const layout = _layouts.get(def.id) ?? computeStructLayout(def);
      if (!layout.anyPlaced) {
        // Nothing can be placed, so there is no layout to state. The name is
        // already forward-declared above, and leaving the type incomplete says
        // exactly that: an object this function reaches whose shape it does not
        // have. Every access to it is a byte offset, so nothing dereferences it.
        // One comment for the whole thing — C does not nest them.
        definitions.push(`/* ${def.id} is left incomplete: no recovered field can be placed.`);
        for (const member of layout.members) {
          if (member.kind === "note") definitions.push(`   ${noteText(member)}`);
        }
        definitions.push(` */`);
        definitions.push("");
        continue;
      }
      definitions.push(`struct ${def.id} {`);
      for (const member of layout.members) {
        if (member.kind === "pad") {
          definitions.push(
            `    uint8_t _pad_${offsetLabel(member.offset)}[${formatHex(member.size)}];`,
          );
        } else if (member.kind === "field") {
          definitions.push(`    ${member.decl}`);
        } else {
          definitions.push(`    /* ${noteText(member)} */`);
        }
      }
      definitions.push(`};`);
      definitions.push("");
    }
    if (definitions.length > 0) {
      lines.push("#pragma pack(push, 1) /* offsets below are the recovered ones */");
      lineAddrs.push(undefined);
      for (const line of definitions) {
        lines.push(line);
        lineAddrs.push(undefined);
      }
      lines.push("#pragma pack(pop)");
      lineAddrs.push(undefined);
      lines.push("");
      lineAddrs.push(undefined);
    }
  }

  // Function header
  const params = func.params.map((p) => `${p.type} ${p.name}`).join(", ");
  lines.push(`${func.returnType} ${func.name}(${params}) {`);
  lineAddrs.push(undefined);

  // Local variable declarations
  if (func.locals.length > 0 || _unrecovered.length > 0) {
    for (const local of func.locals) {
      lines.push(`    ${local.type} ${local.name};`);
      lineAddrs.push(undefined);
    }
    // `intptr_t` because an unrecovered value is a machine word of unknown
    // width, and nothing here justifies claiming one.
    for (const u of _unrecovered) {
      const note = u.note ? `: ${commentSafe(u.note)}` : "";
      lines.push(`    intptr_t ${u.name}; /* not recovered${note} */`);
      lineAddrs.push(undefined);
    }
    lines.push("");
    lineAddrs.push(undefined);
  }

  lines.push(...bodyLines);
  lineAddrs.push(...bodyAddrs);

  lines.push("}");
  lineAddrs.push(undefined);

  placeGotoLabels(lines, lineAddrs);

  // Build lineMap
  const lineMap = new Map<number, number>();
  for (let i = 0; i < lineAddrs.length; i++) {
    if (lineAddrs[i] !== undefined) {
      lineMap.set(i, lineAddrs[i]!);
    }
  }

  return { code: lines.join("\n"), lineMap };
}
