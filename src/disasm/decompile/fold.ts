import type { BinaryOp, IRExpr, IRStmt } from "./ir";
import { canonReg, irConst } from "./ir";

/** Shallow structural equality for simple expressions (reg, const, var). */
function exprEq(a: IRExpr, b: IRExpr): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "const" && b.kind === "const") return a.value === b.value;
  if (a.kind === "reg" && b.kind === "reg") return canonReg(a.name) === canonReg(b.name);
  if (a.kind === "var" && b.kind === "var") return a.name === b.name;
  if (a.kind === "binary" && b.kind === "binary")
    return a.op === b.op && exprEq(a.left, b.left) && exprEq(a.right, b.right);
  if (a.kind === "unary" && b.kind === "unary")
    return a.op === b.op && exprEq(a.operand, b.operand);
  return false;
}

// ── Constant Folding ──

/**
 * The operators below whose JavaScript spelling truncates to 32 bits.
 *
 * `&`, `|`, `^`, `<<`, `>>` and `>>>` coerce both operands to *int32* before
 * doing anything, `|0` does the same to a quotient, and `>>> 0` does it to a
 * comparand. So `0x100000000 >>> 4` evaluates to 0 rather than 0x10000000 and
 * `x & 0xFFFFFFFF00000000` evaluates to 0 — silently, with the wrong value
 * baked into the emitted C (peek-a-bin-8fv). Everything else in the switch
 * (`+`, `-`, `*`, `%`, and the signed comparisons) is ordinary double
 * arithmetic, exact for every operand the IR can hold, so it is left alone —
 * but its *result* can leave the exactly-representable range, and the switch
 * declines to fold when it does rather than printing a rounded constant. Unary
 * `~` is the same int32 truncation and is handled at its own site below.
 *
 * `IRConst.size` says how wide the operand is; when it says 8, the operation
 * is redone in 64-bit BigInt. BigInt is confined to the evaluation itself:
 * `IRConst.value` is a `number`, so a value that will not round-trip through
 * one cannot be represented at all and the fold is refused instead.
 */
const WIDTH_SENSITIVE = new Set<BinaryOp>([
  "/",
  "&",
  "|",
  "^",
  "<<",
  ">>",
  ">>>",
  "u<",
  "u<=",
  "u>",
  "u>=",
]);

/**
 * Whether ToInt32 — which every JavaScript bitwise operator applies first —
 * leaves this value alone. True for the whole signed *and* unsigned 32-bit
 * range, because both spell the same 32 bits.
 */
function fitsInt32(v: number): boolean {
  return Number.isInteger(v) && v >= -0x80000000 && v <= 0xffffffff;
}

/**
 * The width in bytes of the value an expression produces, or null when this IR
 * does not say.
 *
 * `const` is deliberately *not* consulted: `IRConst.size` is the image's mode —
 * 8 for every immediate in a 64-bit binary — not the width of the operand the
 * instruction actually wrote, so reading it here would call `eax & 0xffffffff`
 * a 64-bit operation. Everything else carries a real width: a register spells
 * its own, a deref carries the access size, a cast names the width it converts
 * to, and a binary is as wide as the widest operand that knows.
 *
 * Null means "no evidence", and every caller treats that as *not* 64-bit. That
 * is the pre-existing behaviour for everything the analysis cannot see, and it
 * keeps this change to the case that is demonstrably unsound rather than to
 * every case that cannot be proved sound.
 */
function knownWidth(expr: IRExpr): number | null {
  switch (expr.kind) {
    case "reg":
    case "var":
    case "deref":
      return expr.size;
    case "cast":
      return castTypeSize(expr.type);
    case "unary":
      return knownWidth(expr.operand);
    case "binary": {
      const l = knownWidth(expr.left);
      const r = knownWidth(expr.right);
      if (l === null) return r;
      if (r === null) return l;
      return Math.max(l, r);
    }
    default:
      return null;
  }
}

/** True unless the expression is known to be wider than 32 bits. */
function narrowEnoughForMask32(expr: IRExpr): boolean {
  const w = knownWidth(expr);
  return w === null || w <= 4;
}

/**
 * A width-sensitive operator evaluated at 64 bits, or null when the answer
 * cannot be trusted.
 *
 * Null is returned rather than an approximation whenever an operand is outside
 * the exactly-representable integer range (`IRConst.value` is a `number`, so a
 * 16-hex-digit immediate arrives already rounded), the result would be, or a
 * shift count is out of range. Leaving the expression unfolded still says what
 * the machine does; a folded constant that is off by a bit does not.
 */
function fold64(op: BinaryOp, l: number, r: number): number | null {
  if (!Number.isSafeInteger(l) || !Number.isSafeInteger(r)) return null;
  const a = BigInt(l);
  const b = BigInt(r);
  const signed = BigInt.asIntN(64, a);
  const unsigned = BigInt.asUintN(64, a);
  let out: bigint;
  switch (op) {
    case "/":
      if (r === 0) return null;
      // x86 idiv truncates toward zero, which is what BigInt division does.
      out = BigInt.asIntN(64, signed / BigInt.asIntN(64, b));
      break;
    case "&":
      out = BigInt.asIntN(64, unsigned & BigInt.asUintN(64, b));
      break;
    case "|":
      out = BigInt.asIntN(64, unsigned | BigInt.asUintN(64, b));
      break;
    case "^":
      out = BigInt.asIntN(64, unsigned ^ BigInt.asUintN(64, b));
      break;
    case "<<":
      if (r < 0 || r >= 64) return null;
      out = BigInt.asIntN(64, signed << b);
      break;
    case ">>":
      if (r < 0 || r >= 64) return null;
      out = BigInt.asIntN(64, signed >> b);
      break;
    case ">>>":
      if (r < 0 || r >= 64) return null;
      out = BigInt.asIntN(64, unsigned >> b);
      break;
    case "u<":
      return unsigned < BigInt.asUintN(64, b) ? 1 : 0;
    case "u<=":
      return unsigned <= BigInt.asUintN(64, b) ? 1 : 0;
    case "u>":
      return unsigned > BigInt.asUintN(64, b) ? 1 : 0;
    case "u>=":
      return unsigned >= BigInt.asUintN(64, b) ? 1 : 0;
    default:
      return null;
  }
  const n = Number(out);
  return Number.isSafeInteger(n) ? n : null;
}

function foldExpr(expr: IRExpr): IRExpr {
  if (expr.kind === "binary") {
    const left = foldExpr(expr.left);
    const right = foldExpr(expr.right);

    // Constant folding: both sides constant
    if (left.kind === "const" && right.kind === "const") {
      const l = left.value;
      const r = right.value;

      // A shift's width is its destination's — the count operand's width says
      // nothing about it. Every other operator here takes both operands at the
      // same width, so the wider one is the operation's.
      const isShift = expr.op === "<<" || expr.op === ">>" || expr.op === ">>>";
      const width = isShift ? left.size : Math.max(left.size, right.size);
      // `IRConst.size` is 8 for *every* immediate in a 64-bit binary — the
      // lifter records the mode, not the instruction's operand width — so
      // `width` alone would send `or esi, 0xffffffff` down the 64-bit path and
      // print 0xFFFFFFFF where -1 is the 32-bit register's value. The extra
      // condition is the one thing that is not a guess: int32 arithmetic is
      // only demonstrably wrong when an operand does not survive the coercion
      // to int32, or when a shift count is one JavaScript would wrap to 5 bits.
      const needs64 = !fitsInt32(l) || !fitsInt32(r) || (isShift && (r >= 32 || r < 0));
      if (width >= 8 && needs64 && WIDTH_SENSITIVE.has(expr.op)) {
        const wide = fold64(expr.op, l, r);
        // Falling through to the 32-bit spelling when the 64-bit one declined
        // would produce exactly the wrong answer this guard exists to avoid,
        // so an unfoldable operand pair stays an expression.
        if (wide === null) return { ...expr, left, right };
        return irConst(wide, left.size);
      }

      let result: number | null = null;
      switch (expr.op) {
        case "+":
          result = l + r;
          break;
        case "-":
          result = l - r;
          break;
        case "*":
          result = l * r;
          break;
        case "/":
          if (r !== 0) result = (l / r) | 0;
          break;
        case "%":
          if (r !== 0) result = l % r;
          break;
        case "&":
          result = l & r;
          break;
        case "|":
          result = l | r;
          break;
        case "^":
          result = l ^ r;
          break;
        case "<<":
          result = l << r;
          break;
        case ">>":
          result = l >> r;
          break;
        case ">>>":
          result = l >>> r;
          break;
        case "==":
          result = l === r ? 1 : 0;
          break;
        case "!=":
          result = l !== r ? 1 : 0;
          break;
        case "<":
          result = l < r ? 1 : 0;
          break;
        case "<=":
          result = l <= r ? 1 : 0;
          break;
        case ">":
          result = l > r ? 1 : 0;
          break;
        case ">=":
          result = l >= r ? 1 : 0;
          break;
        case "u<":
          result = l >>> 0 < r >>> 0 ? 1 : 0;
          break;
        case "u<=":
          result = l >>> 0 <= r >>> 0 ? 1 : 0;
          break;
        case "u>":
          result = l >>> 0 > r >>> 0 ? 1 : 0;
          break;
        case "u>=":
          result = l >>> 0 >= r >>> 0 ? 1 : 0;
          break;
      }
      // `+`, `-` and `*` are exact double arithmetic on the way *in* and can
      // still land outside the range a `number` represents exactly on the way
      // out, at which point the constant printed is a rounded one and nothing
      // downstream can tell. Refusing leaves an expression that still says what
      // the machine does. Comparisons yield 0/1 and `/` is `|0`-truncated, so
      // this only ever fires for the three that can grow.
      if (result !== null && Number.isSafeInteger(result)) return irConst(result, left.size);
    }

    // Identity elimination
    if (right.kind === "const") {
      // x + 0 → x
      if (expr.op === "+" && right.value === 0) return left;
      // x - 0 → x
      if (expr.op === "-" && right.value === 0) return left;
      // x * 1 → x
      if (expr.op === "*" && right.value === 1) return left;
      // x * 0 → 0
      if (expr.op === "*" && right.value === 0) return irConst(0, right.size);
      // x & -1 → x. All-ones at every width, so no width test is needed.
      if (expr.op === "&" && right.value === -1) return left;
      // x & 0xFFFFFFFF → x, but only when x is not wider than the mask. On a
      // 64-bit left operand this is a real truncation of the high half, and
      // dropping it emits a value keeping bits the instruction cleared
      // (peek-a-bin-6hw).
      if (expr.op === "&" && right.value === 0xffffffff && narrowEnoughForMask32(left)) return left;
      // x | 0 → x
      if (expr.op === "|" && right.value === 0) return left;
      // x ^ 0 → x
      if (expr.op === "^" && right.value === 0) return left;
      // x << 0 → x
      if ((expr.op === "<<" || expr.op === ">>" || expr.op === ">>>") && right.value === 0)
        return left;
    }

    if (left.kind === "const") {
      // 0 + x → x
      if (expr.op === "+" && left.value === 0) return right;
      // 0 * x → 0
      if (expr.op === "*" && left.value === 0) return irConst(0, left.size);
      // 1 * x → x
      if (expr.op === "*" && left.value === 1) return right;
    }

    // Canonicalize: const OP var/reg → var/reg reversed_OP const
    if (left.kind === "const" && right.kind !== "const") {
      const flipMap: Partial<Record<BinaryOp, BinaryOp>> = {
        "==": "==",
        "!=": "!=",
        "<": ">",
        ">": "<",
        "<=": ">=",
        ">=": "<=",
        "u<": "u>",
        "u>": "u<",
        "u<=": "u>=",
        "u>=": "u<=",
      };
      const flipped = flipMap[expr.op];
      if (flipped !== undefined) {
        return foldExpr({ kind: "binary", op: flipped, left: right, right: left });
      }
    }

    // Same-operand patterns (after folding both sides)
    if (exprEq(left, right)) {
      // x - x → 0, x ^ x → 0
      if (expr.op === "-" || expr.op === "^") return irConst(0, 4);
      // x & x → x, x | x → x
      if (expr.op === "&" || expr.op === "|") return left;
    }

    // Additional constant-right patterns
    if (right.kind === "const") {
      // x & 0 → 0
      if (expr.op === "&" && right.value === 0) return irConst(0, right.size);
      // x | -1 → -1. All-ones at every width.
      if (expr.op === "|" && right.value === -1) return irConst(right.value, right.size);
      // x | 0xFFFFFFFF → 0xFFFFFFFF, same width condition as the `&` identity
      // above: at 64 bits the high half of x survives the OR (peek-a-bin-6hw).
      if (expr.op === "|" && right.value === 0xffffffff && narrowEnoughForMask32(left))
        return irConst(right.value, right.size);
      // Strength reduction: x * 2 → x << 1
      if (expr.op === "*" && right.value === 2)
        return { kind: "binary", op: "<<", left, right: irConst(1, right.size) };
      // x * 4 → x << 2, x * 8 → x << 3
      if (expr.op === "*" && right.value > 0 && (right.value & (right.value - 1)) === 0) {
        const shift = Math.log2(right.value);
        if (Number.isInteger(shift) && shift <= 31)
          return { kind: "binary", op: "<<", left, right: irConst(shift, right.size) };
      }
      // unsigned x / 2 → x >> 1 (only for power of 2)
      if (expr.op === "/" && right.value > 0 && (right.value & (right.value - 1)) === 0) {
        const shift = Math.log2(right.value);
        if (Number.isInteger(shift) && shift <= 31)
          return { kind: "binary", op: ">>>", left, right: irConst(shift, right.size) };
      }
      // unsigned x % 2 → x & 1 (only for power of 2)
      if (expr.op === "%" && right.value > 0 && (right.value & (right.value - 1)) === 0)
        return { kind: "binary", op: "&", left, right: irConst(right.value - 1, right.size) };
    }

    // Sign-extend patterns: (x << 24) >> 24 → (int8_t)x
    if (
      expr.op === ">>" &&
      right.kind === "const" &&
      left.kind === "binary" &&
      left.op === "<<" &&
      left.right.kind === "const" &&
      left.right.value === right.value
    ) {
      const shift = right.value;
      if (shift === 24) return { kind: "cast", type: "int8_t", operand: left.left };
      if (shift === 16) return { kind: "cast", type: "int16_t", operand: left.left };
    }

    return { ...expr, left, right };
  }

  if (expr.kind === "unary") {
    const operand = foldExpr(expr.operand);
    // Constant fold unary
    if (operand.kind === "const") {
      switch (expr.op) {
        case "~": {
          // `~` is a JavaScript bitwise operator and truncates to int32 like
          // the rest of them: `~0x100000000` is -1, not -0x100000001. It only
          // differs from the 64-bit answer when the operand does not survive
          // ToInt32 — sign extension makes the two agree for everything that
          // does — so that is exactly the condition for redoing it wide.
          // `x ^ -1` is `~x`, so the 64-bit evaluator already has this case.
          if (operand.size >= 8 && !fitsInt32(operand.value)) {
            const wide = fold64("^", operand.value, -1);
            if (wide === null) return { ...expr, operand };
            return irConst(wide, operand.size);
          }
          return irConst(~operand.value, operand.size);
        }
        case "-":
          return irConst(-operand.value, operand.size);
        case "!":
          return irConst(operand.value ? 0 : 1, operand.size);
      }
    }
    // Double negation: !!x → x, ~~x → x, --x → x
    if (
      operand.kind === "unary" &&
      operand.op === expr.op &&
      (expr.op === "!" || expr.op === "~" || expr.op === "-")
    ) {
      return operand.operand;
    }
    // Negation absorption: !(x == y) → x != y, !(x < y) → x >= y, etc.
    if (expr.op === "!" && operand.kind === "binary") {
      const negMap: Partial<Record<BinaryOp, BinaryOp>> = {
        "==": "!=",
        "!=": "==",
        "<": ">=",
        ">=": "<",
        ">": "<=",
        "<=": ">",
        "u<": "u>=",
        "u>=": "u<",
        "u>": "u<=",
        "u<=": "u>",
      };
      const neg = negMap[operand.op];
      if (neg) return { ...operand, op: neg };
      // De-Morgan: !(a && b) → !a || !b
      if (operand.op === "&&") {
        return foldExpr({
          kind: "binary",
          op: "||",
          left: { kind: "unary", op: "!", operand: operand.left },
          right: { kind: "unary", op: "!", operand: operand.right },
        });
      }
      // De-Morgan: !(a || b) → !a && !b
      if (operand.op === "||") {
        return foldExpr({
          kind: "binary",
          op: "&&",
          left: { kind: "unary", op: "!", operand: operand.left },
          right: { kind: "unary", op: "!", operand: operand.right },
        });
      }
    }
    return { ...expr, operand };
  }

  if (expr.kind === "ternary") {
    const cond = foldExpr(expr.condition);
    const then = foldExpr(expr.then);
    const els = foldExpr(expr.else);
    // cond ? X : X → X
    if (exprEq(then, els)) return then;
    // 1 ? A : B → A
    if (cond.kind === "const" && cond.value !== 0) return then;
    // 0 ? A : B → B
    if (cond.kind === "const" && cond.value === 0) return els;
    return { ...expr, condition: cond, then, else: els };
  }

  // Cast simplification
  if (expr.kind === "cast") {
    const operand = foldExpr(expr.operand);
    // Double-cast removal: (T2)(T1)x → (T2)x
    if (operand.kind === "cast") {
      return { kind: "cast", type: expr.type, operand: operand.operand };
    }
    // Cast on constant → fold away
    if (operand.kind === "const") {
      return operand;
    }
    // Same-size cast on reg/var → strip
    const castSize = castTypeSize(expr.type);
    if ((operand.kind === "reg" || operand.kind === "var") && operand.size === castSize) {
      return operand;
    }
    return { ...expr, operand };
  }

  if (expr.kind === "deref") {
    return { ...expr, address: foldExpr(expr.address) };
  }

  if (expr.kind === "call") {
    return { ...expr, args: expr.args.map(foldExpr) };
  }

  if (expr.kind === "field_access") {
    return { ...expr, base: foldExpr(expr.base) };
  }

  if (expr.kind === "array_access") {
    return { ...expr, base: foldExpr(expr.base), index: foldExpr(expr.index) };
  }

  return expr;
}

function castTypeSize(typeStr: string): number {
  const m = typeStr.match(/(\d+)/);
  if (m) return parseInt(m[1], 10) / 8;
  return 4; // default
}

function foldStmt(stmt: IRStmt): IRStmt {
  switch (stmt.kind) {
    case "assign":
      return { ...stmt, src: foldExpr(stmt.src) };
    case "store":
      return { ...stmt, address: foldExpr(stmt.address), value: foldExpr(stmt.value) };
    case "call_stmt":
      return { ...stmt, call: foldExpr(stmt.call) as IRExpr & { kind: "call" } };
    case "return":
      return stmt.value ? { ...stmt, value: foldExpr(stmt.value) } : stmt;
    case "if":
      return {
        ...stmt,
        condition: foldExpr(stmt.condition),
        thenBody: stmt.thenBody.map(foldStmt),
        elseBody: stmt.elseBody?.map(foldStmt),
      };
    case "while":
      return { ...stmt, condition: foldExpr(stmt.condition), body: stmt.body.map(foldStmt) };
    case "do_while":
      return { ...stmt, condition: foldExpr(stmt.condition), body: stmt.body.map(foldStmt) };
    case "switch":
      return {
        ...stmt,
        expr: foldExpr(stmt.expr),
        cases: stmt.cases.map((c) => ({ ...c, body: c.body.map(foldStmt) })),
        defaultBody: stmt.defaultBody?.map(foldStmt),
      };
    case "for":
      return {
        ...stmt,
        init: foldStmt(stmt.init),
        condition: foldExpr(stmt.condition),
        update: foldStmt(stmt.update),
        body: stmt.body.map(foldStmt),
      };
    case "try":
      return {
        ...stmt,
        body: stmt.body.map(foldStmt),
        handler: stmt.handler.map(foldStmt),
        filterExpr: stmt.filterExpr ? foldExpr(stmt.filterExpr) : undefined,
      };
    case "branch":
      return { ...stmt, condition: foldExpr(stmt.condition) };
    default:
      return stmt;
  }
}

// ── Register Substitution (Single-Use Inlining) ──

/** Count reads of a register in an expression. */
function countReads(expr: IRExpr, canon: string): number {
  switch (expr.kind) {
    case "reg":
      return canonReg(expr.name) === canon ? 1 : 0;
    case "binary":
      return countReads(expr.left, canon) + countReads(expr.right, canon);
    case "unary":
      return countReads(expr.operand, canon);
    case "deref":
      return countReads(expr.address, canon);
    case "call":
      return expr.args.reduce((n, a) => n + countReads(a, canon), 0);
    case "ternary":
      return (
        countReads(expr.condition, canon) +
        countReads(expr.then, canon) +
        countReads(expr.else, canon)
      );
    case "cast":
      return countReads(expr.operand, canon);
    case "field_access":
      return countReads(expr.base, canon);
    case "array_access":
      return countReads(expr.base, canon) + countReads(expr.index, canon);
    default:
      return 0;
  }
}

function countReadsInStmt(stmt: IRStmt, canon: string): number {
  switch (stmt.kind) {
    case "assign":
      return (
        countReads(stmt.src, canon) +
        (stmt.dest.kind === "deref" ? countReads(stmt.dest.address, canon) : 0)
      );
    case "store":
      return countReads(stmt.address, canon) + countReads(stmt.value, canon);
    case "call_stmt":
      return stmt.call.args.reduce((n, a) => n + countReads(a, canon), 0);
    case "return":
      return stmt.value ? countReads(stmt.value, canon) : 0;
    // Counted, so a definition whose only remaining reader is the guard is
    // *inlined into it* rather than left naming a register nothing assigns —
    // and one read by the guard as well as by a real statement stops being
    // single-use and keeps its own line (peek-a-bin-c33).
    case "branch":
      return countReads(stmt.condition, canon);
    default:
      return 0;
  }
}

function substituteReg(expr: IRExpr, canon: string, replacement: IRExpr): IRExpr {
  switch (expr.kind) {
    case "reg":
      return canonReg(expr.name) === canon ? replacement : expr;
    case "binary":
      return {
        ...expr,
        left: substituteReg(expr.left, canon, replacement),
        right: substituteReg(expr.right, canon, replacement),
      };
    case "unary":
      return { ...expr, operand: substituteReg(expr.operand, canon, replacement) };
    case "deref":
      return { ...expr, address: substituteReg(expr.address, canon, replacement) };
    case "call":
      return { ...expr, args: expr.args.map((a) => substituteReg(a, canon, replacement)) };
    case "ternary":
      return {
        ...expr,
        condition: substituteReg(expr.condition, canon, replacement),
        then: substituteReg(expr.then, canon, replacement),
        else: substituteReg(expr.else, canon, replacement),
      };
    case "cast":
      return { ...expr, operand: substituteReg(expr.operand, canon, replacement) };
    case "field_access":
      return { ...expr, base: substituteReg(expr.base, canon, replacement) };
    case "array_access":
      return {
        ...expr,
        base: substituteReg(expr.base, canon, replacement),
        index: substituteReg(expr.index, canon, replacement),
      };
    default:
      return expr;
  }
}

function substituteRegInStmt(stmt: IRStmt, canon: string, replacement: IRExpr): IRStmt {
  switch (stmt.kind) {
    case "assign": {
      const dest =
        stmt.dest.kind === "deref"
          ? ({
              ...stmt.dest,
              address: substituteReg(stmt.dest.address, canon, replacement),
            } as IRExpr)
          : stmt.dest;
      return { ...stmt, dest, src: substituteReg(stmt.src, canon, replacement) };
    }
    case "store":
      return {
        ...stmt,
        address: substituteReg(stmt.address, canon, replacement),
        value: substituteReg(stmt.value, canon, replacement),
      };
    case "call_stmt":
      return {
        ...stmt,
        call: {
          ...stmt.call,
          args: stmt.call.args.map((a) => substituteReg(a, canon, replacement)),
        },
      };
    case "return":
      return stmt.value ? { ...stmt, value: substituteReg(stmt.value, canon, replacement) } : stmt;
    case "branch":
      return { ...stmt, condition: substituteReg(stmt.condition, canon, replacement) };
    default:
      return stmt;
  }
}

/**
 * Returns true if evaluating the expression might have side effects (i.e. it
 * contains a call).
 *
 * **This is the only copy.** `ssaopt.ts` imports it rather than keeping its own
 * — the two were maintained separately and had drifted into agreeing only by
 * accident. Both callers use it to decide whether an expression may be *moved*
 * (fold's single-use inlining) or *deleted* (SSA dead-code elimination), and a
 * false negative in either direction silently changes how many times the
 * program calls something.
 *
 * The switch is exhaustive on purpose: the old if-chain omitted `cast`, so
 * `rax = (int64_t)GetLastError()` read as pure. DCE would drop the statement —
 * and the call with it — whenever `rax` had no remaining uses.
 */
export function hasSideEffects(expr: IRExpr): boolean {
  switch (expr.kind) {
    case "call":
      return true;
    case "binary":
      return hasSideEffects(expr.left) || hasSideEffects(expr.right);
    case "unary":
      return hasSideEffects(expr.operand);
    case "cast":
      return hasSideEffects(expr.operand);
    case "deref":
      return hasSideEffects(expr.address);
    case "ternary":
      return (
        hasSideEffects(expr.condition) || hasSideEffects(expr.then) || hasSideEffects(expr.else)
      );
    case "field_access":
      return hasSideEffects(expr.base);
    case "array_access":
      return hasSideEffects(expr.base) || hasSideEffects(expr.index);
    case "const":
    case "reg":
    case "var":
    case "unknown":
      return false;
    default: {
      // Compile error if a new IRExpr kind is added without classifying it.
      const _exhaustive: never = expr;
      return _exhaustive;
    }
  }
}

/** Canonical names of every register the expression reads. */
function readRegs(expr: IRExpr, out: Set<string> = new Set()): Set<string> {
  switch (expr.kind) {
    case "reg":
      out.add(canonReg(expr.name));
      break;
    case "binary":
      readRegs(expr.left, out);
      readRegs(expr.right, out);
      break;
    case "unary":
    case "cast":
      readRegs(expr.operand, out);
      break;
    case "deref":
      readRegs(expr.address, out);
      break;
    case "call":
      for (const a of expr.args) readRegs(a, out);
      break;
    case "ternary":
      readRegs(expr.condition, out);
      readRegs(expr.then, out);
      readRegs(expr.else, out);
      break;
    case "field_access":
      readRegs(expr.base, out);
      break;
    case "array_access":
      readRegs(expr.base, out);
      readRegs(expr.index, out);
      break;
  }
  return out;
}

/** True if evaluating the expression loads from memory. */
function readsMemory(expr: IRExpr): boolean {
  switch (expr.kind) {
    case "deref":
    case "field_access":
    case "array_access":
      return true;
    case "binary":
      return readsMemory(expr.left) || readsMemory(expr.right);
    case "unary":
    case "cast":
      return readsMemory(expr.operand);
    case "call":
      return expr.args.some(readsMemory);
    case "ternary":
      return readsMemory(expr.condition) || readsMemory(expr.then) || readsMemory(expr.else);
    default:
      return false;
  }
}

/** True if the statement assigns to any of the given canonical register names. */
function writesAnyReg(stmt: IRStmt, regs: Set<string>): boolean {
  if (regs.size === 0) return false;
  if (stmt.kind === "assign" && stmt.dest.kind === "reg") return regs.has(canonReg(stmt.dest.name));
  if (stmt.kind === "call_stmt" && stmt.resultDest?.kind === "reg")
    return regs.has(canonReg(stmt.resultDest.name));
  return false;
}

/** True if the statement writes to memory. */
function writesMemory(stmt: IRStmt): boolean {
  if (stmt.kind === "store") return true;
  if (stmt.kind === "assign" && stmt.dest.kind === "deref") return true;
  return false;
}

/** Canonical names of every register the statement reads. */
function readsInStmt(stmt: IRStmt, out: Set<string>): void {
  switch (stmt.kind) {
    case "assign":
      // A `deref` destination is an address computation, so its registers are
      // read even though the statement is a write.
      if (stmt.dest.kind === "deref") readRegs(stmt.dest.address, out);
      readRegs(stmt.src, out);
      return;
    case "store":
      readRegs(stmt.address, out);
      readRegs(stmt.value, out);
      return;
    case "call_stmt":
      for (const a of stmt.call.args) readRegs(a, out);
      return;
    case "return":
      if (stmt.value) readRegs(stmt.value, out);
      return;
    // A guard's registers are reads like any other. Omitting the kind would make
    // a register whose only reader is a successor's conditional jump look dead
    // to this block — the branches are extracted after this stage, and only from
    // the block that owns them.
    case "branch":
      readRegs(stmt.condition, out);
      return;
    // `raw` is deliberately silent. Its text is an unlifted instruction that
    // reaches the page as a comment, so it reads nothing in the emitted C, and
    // treating the register names inside it as reads would hold values alive for
    // a statement that cannot use them.
    default:
      return;
  }
}

/**
 * The canonical registers live out of each block — read on some path from it
 * before being written.
 *
 * `foldBlock` is handed ONE block, so its `totalReads === 1` is a statement
 * about that block and nothing else, and that is the whole of what this exists
 * to fix: a definition read once inside its block and again two blocks later
 * was inlined into the in-block use and **deleted**, leaving every later read
 * naming a register the emitted C never assigns. `t32!sub_40D99A`'s
 * `mov ecx, [ebp+8]` is the witness — one in-block use at `mov [ecx+8], eax`,
 * eleven reads over the three blocks after it, and the emitted function's only
 * mention of `ecx` on the left of an `=` was an `ecx = ecx;` from an unrelated
 * `lea ecx,[ecx]` NOP. `gcc -fsyntax-only` compiles that because `preludeFor`
 * declares every undeclared identifier as its own `long`, and no other gate
 * here can see a name that is read and never written (peek-a-bin-7eyn).
 *
 * Ordinary backward may-liveness: `liveIn = use ∪ (liveOut − def)`,
 * `liveOut = ⋃ liveIn(succ)`. Taken over the program as it stands BEFORE any
 * block is folded, which errs in the safe direction: inlining inside one block
 * can remove that block's last read of a register, and this does not go back to
 * re-examine the predecessor that defined it.
 *
 * The parameter is structural rather than `BasicBlock` so `fold.ts` keeps
 * importing nothing but `ir.ts` — `cfg.ts` pulls in dagre, and `fold.test.ts`
 * has no reason to load a graph layout engine.
 */
export function blockLiveOut(
  blocks: readonly { id: number; succs: readonly number[] }[],
  stmts: ReadonlyMap<number, IRStmt[]>,
): Map<number, Set<string>> {
  const use = new Map<number, Set<string>>();
  const def = new Map<number, Set<string>>();
  const liveIn = new Map<number, Set<string>>();
  const liveOut = new Map<number, Set<string>>();
  const known = new Set(blocks.map((b) => b.id));
  for (const b of blocks) {
    const u = new Set<string>();
    const d = new Set<string>();
    for (const s of stmts.get(b.id) ?? []) {
      const reads = new Set<string>();
      readsInStmt(s, reads);
      for (const r of reads) if (!d.has(r)) u.add(r);
      const dest = s.kind === "assign" ? s.dest : s.kind === "call_stmt" ? s.resultDest : undefined;
      if (dest?.kind === "reg") d.add(canonReg(dest.name));
    }
    use.set(b.id, u);
    def.set(b.id, d);
    liveIn.set(b.id, new Set(u));
    liveOut.set(b.id, new Set());
  }
  for (let pass = 0; pass <= blocks.length + 1; pass++) {
    let changed = false;
    for (let i = blocks.length - 1; i >= 0; i--) {
      const b = blocks[i];
      const out = liveOut.get(b.id) as Set<string>;
      for (const succ of b.succs) {
        if (!known.has(succ)) continue;
        for (const r of liveIn.get(succ) as Set<string>) {
          if (!out.has(r)) {
            out.add(r);
            changed = true;
          }
        }
      }
      const inSet = liveIn.get(b.id) as Set<string>;
      const d = def.get(b.id) as Set<string>;
      for (const r of out) {
        if (!d.has(r) && !inSet.has(r)) {
          inSet.add(r);
          changed = true;
        }
      }
    }
    if (!changed) break;
  }
  return liveOut;
}

/**
 * Fold a flat list of IR statements within a single block:
 * - Constant fold
 * - Inline single-use register assignments
 * - Eliminate dead register stores
 *
 * `liveOut` is the canonical registers read on some path after this block, from
 * `blockLiveOut`. Omitting it keeps the pre-`peek-a-bin-7eyn` behaviour, which
 * is unsound for any definition that escapes its block, so every caller holding
 * a CFG must pass it — `pipeline.ts` and the corpus audits that replay it do.
 */
export function foldBlock(stmts: IRStmt[], liveOut?: ReadonlySet<string>): IRStmt[] {
  // Pass 1: Constant fold
  let result = stmts.map(foldStmt);

  // Pass 2: Single-use register inlining
  // If reg = expr and reg is read exactly once in the next statement and not read again, inline.
  let changed = true;
  let passes = 0;
  while (changed && passes < 5) {
    changed = false;
    passes++;
    const next: IRStmt[] = [];
    for (let i = 0; i < result.length; i++) {
      const stmt = result[i];
      // Only inline register assignments (not memory stores, not calls)
      if (stmt.kind === "assign" && stmt.dest.kind === "reg" && !hasSideEffects(stmt.src)) {
        const canon = canonReg(stmt.dest.name);
        // Inlining moves the whole right-hand side down to the point of use, so
        // it is only sound while nothing it depends on changes in between.
        const inputs = readRegs(stmt.src);
        const loads = readsMemory(stmt.src);
        // The stack pointer has no faithful definition chain in this IR:
        // `push`, `pop` and the return address a `call` pushes are not lifted
        // at all, so RSP changes with nothing here saying it did. `writesAnyReg`
        // therefore cannot see the hazard, and a read of RSP must not be moved
        // to another program point at all. This is what turned
        // `mov ebp, esp` / … / `push [ebp + 8]` into `*(esp + 8)` — a base
        // register the instruction never named, one push off the value it did
        // name (peek-a-bin-rt4). `ssaopt.ts` refuses the same substitution.
        if (inputs.has("rsp") || canon === "rsp") {
          next.push(stmt);
          continue;
        }
        // Count total reads in remaining statements until next write to same register
        let totalReads = 0;
        let firstReadIdx = -1;
        let blocked = false;
        // Whether a later statement in THIS block redefines the register. When
        // one does the value dies here, so `liveOut` describes the other
        // definition's value and the escape test below must not fire on it.
        let killedInBlock = false;
        for (let j = i + 1; j < result.length; j++) {
          const s = result[j];
          const reads = countReadsInStmt(s, canon);
          if (reads > 0 && firstReadIdx < 0) firstReadIdx = j;
          totalReads += reads;
          // A later definition of the same register ends this value's live
          // range: reads beyond it are reads of something else, and counting
          // them would only block a substitution that is in fact sound.
          if (s.kind === "assign" && s.dest.kind === "reg" && canonReg(s.dest.name) === canon) {
            killedInBlock = true;
            break;
          }
          if (s.kind === "call_stmt" && s.resultDest?.kind === "reg") {
            if (canonReg(s.resultDest.name) === canon) {
              killedInBlock = true;
              break;
            }
          }
          // Hazards only matter for statements the value has to move *past*.
          // A statement that reads the register evaluates its right-hand side
          // first, so a write in that same statement happens after the read.
          if (firstReadIdx < 0) {
            // A call clobbers the caller-saved registers, so nothing may move
            // across one. This used to be a `break`, which ended the *use
            // count* as well as the hazard scan: a definition read once before
            // a call and once after looked single-use, so it was substituted
            // into the first read and then dropped, leaving the second read
            // naming something never assigned (peek-a-bin-9ml).
            if (s.kind === "call_stmt") {
              blocked = true;
              break;
            }
            // `rax = rcx + 5; rcx = 99; rsi = rax` must not become
            // `rcx = 99; rsi = rcx + 5` — that reads the new rcx. Versions are
            // gone by the time foldBlock runs, so two SSA values of one
            // register share a name here and nothing else catches this.
            if (writesAnyReg(s, inputs)) {
              blocked = true;
              break;
            }
            // A load must not be moved below a store: the two addresses may
            // alias, and nothing in this IR can prove they do not.
            if (loads && writesMemory(s)) {
              blocked = true;
              break;
            }
          }
        }
        // A guard's read counts towards `totalReads` — that is what stops a
        // definition two statements read from being inlined into one of them
        // and leaving the other naming nothing — but it is never the statement
        // the value moves *into*. Inlining into a branch deletes the assignment
        // and rewrites the guard, and both halves do damage: the register is
        // frequently live out of the block (a loop counter always is), and the
        // structurer matches loop shapes on the statements a block ends with,
        // so `inc eax / cmp eax, 5 / jl` turned a `do { … } while (eax < 5)`
        // into `while (eax + 1 < 5)` with the increment gone. Measured on the
        // suite before the refusal existed: 8 structuring tests changed shape
        // (peek-a-bin-c33).
        const readerIsBranch = firstReadIdx >= 0 && result[firstReadIdx].kind === "branch";
        // A value that ESCAPES the block is not single-use, however the reads in
        // this block count. Inlining deletes the assignment, so every read in a
        // successor is left naming a register the emitted C never writes — the
        // one class `gcc -fsyntax-only` is structurally blind to, because
        // `preludeFor` declares each undeclared identifier as its own `long`
        // (peek-a-bin-7eyn).
        const escapes = !killedInBlock && liveOut !== undefined && liveOut.has(canon);
        if (!blocked && !escapes && !readerIsBranch && totalReads === 1 && firstReadIdx >= 0) {
          // Inline: substitute into the statement that reads it
          result[firstReadIdx] = substituteRegInStmt(result[firstReadIdx], canon, stmt.src);
          changed = true;
          continue; // skip adding this assignment
        }
      }
      next.push(stmt);
    }
    result = next;
  }

  // Pass 3: Constant fold again after inlining
  result = result.map(foldStmt);

  return result;
}

// eliminateDeadStores removed — now handled by SSA dead code elimination
