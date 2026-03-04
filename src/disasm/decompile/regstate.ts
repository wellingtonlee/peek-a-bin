import type { IRExpr, BinaryOp } from './ir';
import { irBinary, irConst, irUnary, irReg } from './ir';

/**
 * Tracks last-written expression per register and flag state within a basic block.
 * No SSA — purely "last writer wins" tracking for expression folding.
 */
export class RegState {
  defs = new Map<string, IRExpr>();

  // Flag state from last cmp/test
  flagLeft: IRExpr | null = null;
  flagRight: IRExpr | null = null;
  flagOp: 'cmp' | 'test' | null = null;

  set(reg: string, expr: IRExpr): void {
    this.defs.set(reg.toLowerCase(), expr);
  }

  get(reg: string): IRExpr | undefined {
    return this.defs.get(reg.toLowerCase());
  }

  getOrReg(reg: string, size: number): IRExpr {
    return this.defs.get(reg.toLowerCase()) ?? irReg(reg, size);
  }

  setFlags(op: 'cmp' | 'test', left: IRExpr, right: IRExpr): void {
    this.flagOp = op;
    this.flagLeft = left;
    this.flagRight = right;
  }

  /** Map a Jcc mnemonic to an IR condition expression from current flag state. */
  getCondition(jcc: string): IRExpr {
    const left = this.flagLeft;
    const right = this.flagRight;

    if (!left || !right) {
      return { kind: 'unknown', text: jcc };
    }

    // test reg, reg → flags set based on AND result
    // test + je → result == 0 → left == 0
    // test + jne → result != 0 → left != 0
    if (this.flagOp === 'test') {
      // test X, X is a common idiom for checking zero
      const isTestSelf = exprEq(left, right);
      const testTarget = isTestSelf ? left : irBinary('&', left, right);
      const zero = irConst(0, 4);

      switch (jcc) {
        case 'je': case 'jz':
          return isTestSelf ? irBinary('==', left, zero) : irBinary('==', testTarget, zero);
        case 'jne': case 'jnz':
          return isTestSelf ? irBinary('!=', left, zero) : irBinary('!=', testTarget, zero);
        case 'js':
          return irBinary('<', testTarget, zero);
        case 'jns':
          return irBinary('>=', testTarget, zero);
        default:
          return { kind: 'unknown', text: `${jcc} after test` };
      }
    }

    // cmp left, right → flags based on left - right
    const condMap: Record<string, BinaryOp> = {
      'je': '==', 'jz': '==',
      'jne': '!=', 'jnz': '!=',
      'jg': '>', 'jnle': '>',
      'jge': '>=', 'jnl': '>=',
      'jl': '<', 'jnge': '<',
      'jle': '<=', 'jng': '<=',
      'ja': 'u>', 'jnbe': 'u>',
      'jae': 'u>=', 'jnb': 'u>=', 'jnc': 'u>=',
      'jb': 'u<', 'jnae': 'u<', 'jc': 'u<',
      'jbe': 'u<=', 'jna': 'u<=',
    };

    const op = condMap[jcc];
    if (op) return irBinary(op, left, right);

    // Overflow / sign / parity
    if (jcc === 'js') return irBinary('<', irBinary('-', left, right), irConst(0));
    if (jcc === 'jns') return irBinary('>=', irBinary('-', left, right), irConst(0));

    return { kind: 'unknown', text: `${jcc}(${left}, ${right})` };
  }

  /** Negate a condition (for structuring: if-not-taken path). */
  static negate(cond: IRExpr): IRExpr {
    if (cond.kind === 'binary') {
      const neg: Partial<Record<BinaryOp, BinaryOp>> = {
        '==': '!=', '!=': '==',
        '<': '>=', '>=': '<',
        '>': '<=', '<=': '>',
        'u<': 'u>=', 'u>=': 'u<',
        'u>': 'u<=', 'u<=': 'u>',
      };
      const flipped = neg[cond.op];
      if (flipped) return irBinary(flipped, cond.left, cond.right);
    }
    return irUnary('!', cond);
  }

  /** Invalidate caller-saved registers after a call (x64 Windows ABI). */
  invalidateCallerSaved(): void {
    const clobbered = ['rax', 'rcx', 'rdx', 'r8', 'r9', 'r10', 'r11'];
    for (const r of clobbered) this.defs.delete(r);
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
  if (a.kind === 'reg' && b.kind === 'reg') return a.name.toLowerCase() === b.name.toLowerCase();
  if (a.kind === 'const' && b.kind === 'const') return a.value === b.value;
  return false;
}
