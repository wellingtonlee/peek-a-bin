import type { BinaryOp, IRExpr } from "./ir";
import { canonReg, irBinary, irConst, irReg, irUnary, isKnownRegister } from "./ir";

/** Volatile registers under the Windows x64 ABI (a superset of the x86 ones). */
const CALLER_SAVED = new Set(["rax", "rcx", "rdx", "r8", "r9", "r10", "r11"]);

/**
 * Tracks last-written expression per register and flag state within a basic block.
 * No SSA — purely "last writer wins" tracking for expression folding.
 */
export class RegState {
  defs = new Map<string, IRExpr>();

  // Flag state from last cmp/test, or from an instruction that left its result
  // somewhere the caller can name (`setFlagsFromResult`).
  flagLeft: IRExpr | null = null;
  flagRight: IRExpr | null = null;
  flagOp: "cmp" | "test" | "result" | null = null;

  set(reg: string, expr: IRExpr): void {
    this.defs.set(reg.toLowerCase(), expr);
  }

  get(reg: string): IRExpr | undefined {
    return this.defs.get(reg.toLowerCase());
  }

  getOrReg(reg: string, size: number): IRExpr {
    return this.defs.get(reg.toLowerCase()) ?? irReg(reg, size);
  }

  /**
   * Did this block write *any* alias of `reg` — `mov ecx, 1` as well as
   * `mov rcx, 1`?
   *
   * `defs` is deliberately keyed by the literal operand text, because the value
   * it stores has that operand's width: folding `mov cl, 2` into a key of `rcx`
   * would record a one-byte value as if it were all eight, and on x86-64 a
   * byte write does not even clear the upper bits the way a 32-bit one does.
   * So the map must stay width-exact.
   *
   * Whether the block *touched* the register is a different question, and it is
   * width-blind: `mov ecx, 1 / call f` passes an argument in RCX exactly as
   * `mov rcx, 1` would. That question gets this method rather than a
   * width-blind map — same shape as `invalidateCallerSaved` above, and for the
   * same reason. Nothing here exposes the stored expression: the only caller
   * (`collectArgs64`) wants arity, and substituting the expression is the
   * defect `liftBlock`'s docstring warns about.
   */
  wroteAnyAlias(reg: string): boolean {
    // `regSize()` would be the tempting test and is useless here — it falls
    // back to 4 for any string, so every name looks like a register.
    if (!isKnownRegister(reg)) return false;
    const canon = canonReg(reg);
    for (const key of this.defs.keys()) {
      if (canonReg(key) === canon) return true;
    }
    return false;
  }

  /**
   * Forget the flags — nothing here can answer a Jcc until something sets them
   * again.
   *
   * `getCondition` reads `flagLeft`/`flagRight` and returns `unknown` when
   * either is null, so this is the state a fresh `RegState` is already in. It
   * is spelled out as a method because *reaching* it again matters: an
   * instruction that writes the flags in a way this class cannot model leaves
   * whatever an earlier `cmp` recorded, and a Jcc after it would then be
   * answered from a test the machine no longer holds (peek-a-bin-jitf).
   * Callers walking a block forward call this on every such instruction.
   */
  clearFlags(): void {
    this.flagOp = null;
    this.flagLeft = null;
    this.flagRight = null;
  }

  setFlags(op: "cmp" | "test", left: IRExpr, right: IRExpr): void {
    this.flagOp = op;
    this.flagLeft = left;
    this.flagRight = right;
  }

  /**
   * Flags left by an instruction that wrote `result` — `dec ecx`, `sub eax,
   * ecx`, `and eax, 3`, `or rax, rax`.
   *
   * x86 sets the flags from the *result*, not from the operands, so `result`
   * must be an expression for the value the instruction produced as read
   * **after** it ran: for `dec ecx / jnz` that is `ecx`, which by then holds
   * the decremented value, and the loop repeats while `ecx != 0`. Naming the
   * operands instead (`ecx - 1`) states the same test one iteration early.
   *
   * Only ZF and SF are answerable from the result alone, so `getCondition`
   * answers only the Jcc forms that read one of them and nothing else. CF and
   * OF depend on the operands and on the operation: `sub eax, ecx / jl` is
   * `eax_before < ecx` signed, which the result cannot express because it
   * disagrees on signed overflow. Those stay unrecovered.
   */
  setFlagsFromResult(result: IRExpr): void {
    this.flagOp = "result";
    this.flagLeft = result;
    this.flagRight = irConst(0, result.kind === "reg" ? result.size : 4);
  }

  /** Map a Jcc mnemonic to an IR condition expression from current flag state. */
  getCondition(jcc: string): IRExpr {
    const left = this.flagLeft;
    const right = this.flagRight;

    if (!left || !right) {
      return { kind: "unknown", text: jcc };
    }

    // An instruction that left its result in `left` (see `setFlagsFromResult`).
    // ZF is set exactly when that result is zero and SF is its top bit, so
    // `== 0` / `!= 0` and `< 0` / `>= 0` are exact — for every one of the
    // arithmetic and logical operations, whatever it did to CF and OF.
    if (this.flagOp === "result") {
      switch (jcc) {
        case "je":
        case "jz":
          return irBinary("==", left, right);
        case "jne":
        case "jnz":
          return irBinary("!=", left, right);
        case "js":
          return irBinary("<", left, right);
        case "jns":
          return irBinary(">=", left, right);
        default:
          // Every other Jcc reads CF or OF as well, and neither is a function
          // of the result. Unknown is the honest answer.
          return { kind: "unknown", text: jcc };
      }
    }

    // test reg, reg → flags set based on AND result
    // test + je → result == 0 → left == 0
    // test + jne → result != 0 → left != 0
    if (this.flagOp === "test") {
      // test X, X is a common idiom for checking zero
      const isTestSelf = exprEq(left, right);
      const testTarget = isTestSelf ? left : irBinary("&", left, right);
      const zero = irConst(0, 4);

      switch (jcc) {
        case "je":
        case "jz":
          return isTestSelf ? irBinary("==", left, zero) : irBinary("==", testTarget, zero);
        case "jne":
        case "jnz":
          return isTestSelf ? irBinary("!=", left, zero) : irBinary("!=", testTarget, zero);
        case "js":
          return irBinary("<", testTarget, zero);
        case "jns":
          return irBinary(">=", testTarget, zero);
        default:
          return { kind: "unknown", text: `${jcc} after test` };
      }
    }

    // cmp left, right → flags based on left - right
    const condMap: Record<string, BinaryOp> = {
      je: "==",
      jz: "==",
      jne: "!=",
      jnz: "!=",
      jg: ">",
      jnle: ">",
      jge: ">=",
      jnl: ">=",
      jl: "<",
      jnge: "<",
      jle: "<=",
      jng: "<=",
      ja: "u>",
      jnbe: "u>",
      jae: "u>=",
      jnb: "u>=",
      jnc: "u>=",
      jb: "u<",
      jnae: "u<",
      jc: "u<",
      jbe: "u<=",
      jna: "u<=",
    };

    const op = condMap[jcc];
    if (op) return irBinary(op, left, right);

    // Overflow / sign / parity
    if (jcc === "js") return irBinary("<", irBinary("-", left, right), irConst(0));
    if (jcc === "jns") return irBinary(">=", irBinary("-", left, right), irConst(0));

    return { kind: "unknown", text: `${jcc}(${left}, ${right})` };
  }

  /** Negate a condition (for structuring: if-not-taken path). */
  static negate(cond: IRExpr): IRExpr {
    if (cond.kind === "binary") {
      const neg: Partial<Record<BinaryOp, BinaryOp>> = {
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
      const flipped = neg[cond.op];
      if (flipped) return irBinary(flipped, cond.left, cond.right);
      // De Morgan: !(a && b) → !a || !b, !(a || b) → !a && !b
      if (cond.op === "&&")
        return irBinary("||", RegState.negate(cond.left), RegState.negate(cond.right));
      if (cond.op === "||")
        return irBinary("&&", RegState.negate(cond.left), RegState.negate(cond.right));
    }
    return irUnary("!", cond);
  }

  /** Invalidate caller-saved registers after a call (x64 Windows ABI). */
  invalidateCallerSaved(): void {
    // Defs are keyed by the literal operand text ('eax', 'r8d', 'cl', …), so
    // match on the canonical parent rather than deleting the 64-bit names.
    // In 32-bit mode every def is a sub-register, so deleting only rax/rcx/…
    // would invalidate nothing at all.
    for (const key of [...this.defs.keys()]) {
      if (CALLER_SAVED.has(canonReg(key))) this.defs.delete(key);
    }
    this.flagLeft = null;
    this.flagRight = null;
    this.flagOp = null;
  }

  clone(): RegState {
    const copy = new RegState();
    for (const [k, v] of this.defs) copy.defs.set(k, v);
    copy.flagLeft = this.flagLeft;
    copy.flagRight = this.flagRight;
    copy.flagOp = this.flagOp;
    return copy;
  }
}

function exprEq(a: IRExpr, b: IRExpr): boolean {
  if (a.kind !== b.kind) return false;
  if (a.kind === "reg" && b.kind === "reg") return a.name.toLowerCase() === b.name.toLowerCase();
  if (a.kind === "const" && b.kind === "const") return a.value === b.value;
  return false;
}
