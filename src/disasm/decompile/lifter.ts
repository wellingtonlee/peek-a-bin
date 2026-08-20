import type { BasicBlock } from "../cfg";
import { resolveRipMemExpr, resolveRipTarget } from "../ripRelative";
import type { Instruction } from "../types";
import { isFlagReadingJump } from "./flagModel";
import type { BinaryOp, IRCall, IRExpr, IRStmt } from "./ir";
import {
  canonReg,
  irBinary,
  irConst,
  irDeref,
  irReg,
  irUnary,
  irUnknown,
  isKnownRegister,
  regSize,
} from "./ir";
import type { RegState } from "./regstate";

// ── Operand Parsing ──

const MEM_PATTERN = /^(byte|word|dword|qword)\s+ptr\s+/i;
const BRACKET_PATTERN = /\[([^\]]+)\]/;
const HEX_PATTERN = /^-?0x([0-9a-fA-F]+)$/;
const DEC_PATTERN = /^-?\d+$/;

/** Size in bytes from memory operand prefix. */
function memPrefixSize(s: string): number {
  const m = s.match(MEM_PATTERN);
  if (!m) return 0;
  switch (m[1].toLowerCase()) {
    case "byte":
      return 1;
    case "word":
      return 2;
    case "dword":
      return 4;
    case "qword":
      return 8;
  }
  return 0;
}

function isRegister(s: string): boolean {
  // NB: not `regSize(s) > 0` — regSize() falls back to 4 for unknown names, so
  // that test matched every operand and immediates were lifted as registers.
  return isKnownRegister(s) || /^(rip|eip)$/i.test(s.trim());
}

function parseImm(s: string): number | null {
  const trimmed = s.trim();
  const hexM = trimmed.match(HEX_PATTERN);
  if (hexM) {
    const v = parseInt(hexM[1], 16);
    // An x86 immediate is at most 64 bits, and Capstone prints it unsigned:
    // `or rdi, 0xffffffffffffffff` is `or rdi, -1`. `parseInt` rounds that to
    // 2^64, a value no later stage can do anything true with — the constant
    // folder saw 2^64 and produced 0. Reading the top bit as the sign, which
    // is what the instruction does, gives a number that is both exact and
    // right.
    if (!Number.isSafeInteger(v)) {
      const signed = BigInt.asIntN(64, BigInt(`0x${hexM[1]}`));
      const n = Number(signed);
      if (Number.isSafeInteger(n)) return trimmed.startsWith("-") ? -n : n;
    }
    return trimmed.startsWith("-") ? -v : v;
  }
  if (DEC_PATTERN.test(trimmed)) return parseInt(trimmed, 10);
  return null;
}

/**
 * Parse a memory expression inside brackets: e.g. `rbp - 0x10`, `rax + rcx*4 + 0x10`.
 * Returns an IRExpr representing the address.
 */
function parseMemExpr(inside: string, insn: Instruction, is64: boolean): IRExpr {
  // Handle RIP-relative addressing
  const ripTarget = resolveRipMemExpr(inside, insn);
  if (ripTarget !== null) return irConst(ripTarget, is64 ? 8 : 4);

  // Tokenize: split on + and - while preserving sign
  const tokens: { sign: number; text: string }[] = [];
  let buf = "";
  let sign = 1;
  for (let i = 0; i <= inside.length; i++) {
    const ch = inside[i];
    if (i === inside.length || ch === "+" || ch === "-") {
      const t = buf.trim();
      if (t) tokens.push({ sign, text: t });
      sign = ch === "-" ? -1 : 1;
      buf = "";
    } else {
      buf += ch;
    }
  }

  let result: IRExpr | null = null;
  const addExpr = (expr: IRExpr, s: number) => {
    if (!result) {
      result = s === -1 ? irUnary("-", expr) : expr;
    } else {
      result = s === -1 ? irBinary("-", result, expr) : irBinary("+", result, expr);
    }
  };

  for (const tok of tokens) {
    // reg*scale
    const scaleMatch = tok.text.match(/^(\w+)\s*\*\s*(\d+)$/i);
    if (scaleMatch && isRegister(scaleMatch[1])) {
      const reg = scaleMatch[1];
      const scale = parseInt(scaleMatch[2], 10);
      addExpr(irBinary("*", irReg(reg), irConst(scale)), tok.sign);
      continue;
    }
    // register
    if (isRegister(tok.text)) {
      addExpr(irReg(tok.text), tok.sign);
      continue;
    }
    // immediate
    const imm = parseImm(tok.text);
    if (imm !== null) {
      addExpr(irConst(Math.abs(imm), is64 ? 8 : 4), imm < 0 ? -tok.sign : tok.sign);
      continue;
    }
    // fallback
    addExpr(irUnknown(tok.text), tok.sign);
  }

  return result ?? irConst(0);
}

/**
 * Parse a single Capstone operand string into an IR expression.
 *
 * A register operand lifts to a plain register read — deliberately *not* to
 * whatever expression `RegState` last recorded for it. Substituting here
 * produced IR that no later stage could read correctly: the assignment that
 * computed the value was still emitted, so a side-effecting source (a call) was
 * duplicated at every read, and the leaves of the substituted expression meant
 * "value on entry to the block" while `ssa.ts` renames every leaf to the most
 * recent definition. Propagation is buildSSA + ssaopt + foldBlock's job; they
 * do it with the version information that makes it sound. The parameter is
 * gone rather than ignored so this cannot quietly come back.
 */
export function parseOperand(op: string, insn: Instruction, is64: boolean): IRExpr {
  const trimmed = op.trim();
  if (!trimmed) return irUnknown("");

  // Memory operand: e.g. `dword ptr [rbp - 0x10]` or `[rax]`
  const prefixSize = memPrefixSize(trimmed);
  const bracketM = trimmed.match(BRACKET_PATTERN);
  if (bracketM) {
    const size = prefixSize || (is64 ? 8 : 4);
    const addr = parseMemExpr(bracketM[1], insn, is64);
    return irDeref(addr, size);
  }

  // Register
  if (isRegister(trimmed)) {
    return irReg(trimmed, regSize(trimmed));
  }

  // Immediate
  const imm = parseImm(trimmed);
  if (imm !== null) {
    return irConst(imm, is64 ? 8 : 4);
  }

  return irUnknown(trimmed);
}

/**
 * Parse operand but return the raw register (not regState expression).
 * Used for destination operands where we want the register itself.
 */
function parseDestOperand(op: string, insn: Instruction, is64: boolean): IRExpr {
  const trimmed = op.trim();
  if (!trimmed) return irUnknown("");

  const prefixSize = memPrefixSize(trimmed);
  const bracketM = trimmed.match(BRACKET_PATTERN);
  if (bracketM) {
    const size = prefixSize || (is64 ? 8 : 4);
    const addr = parseMemExpr(bracketM[1], insn, is64);
    return irDeref(addr, size);
  }

  if (isRegister(trimmed)) {
    return irReg(trimmed);
  }

  const imm = parseImm(trimmed);
  if (imm !== null) return irConst(imm, is64 ? 8 : 4);
  return irUnknown(trimmed);
}

function splitOperands(opStr: string): string[] {
  // Split on comma, respecting brackets
  const parts: string[] = [];
  let depth = 0;
  let buf = "";
  for (const ch of opStr) {
    if (ch === "[") depth++;
    if (ch === "]") depth--;
    if (ch === "," && depth === 0) {
      parts.push(buf.trim());
      buf = "";
    } else {
      buf += ch;
    }
  }
  if (buf.trim()) parts.push(buf.trim());
  return parts;
}

// ── Core Lifter ──

const ARITH_OPS: Record<string, BinaryOp> = {
  add: "+",
  sub: "-",
  and: "&",
  or: "|",
  xor: "^",
  shl: "<<",
  sal: "<<",
  shr: ">>>",
  sar: ">>",
};

const COND_SET: Record<string, string> = {
  sete: "je",
  setne: "jne",
  setz: "jz",
  setnz: "jnz",
  setg: "jg",
  setge: "jge",
  setl: "jl",
  setle: "jle",
  seta: "ja",
  setae: "jae",
  setb: "jb",
  setbe: "jbe",
  sets: "js",
  setns: "jns",
};

const CMOV_PATTERN = /^cmov(\w+)$/;

const FASTCALL_REGS_64 = ["rcx", "rdx", "r8", "r9"];

const FPU_ARITH = new Map<string, BinaryOp>([
  ["fadd", "+"],
  ["faddp", "+"],
  ["fiadd", "+"],
  ["fsub", "-"],
  ["fsubp", "-"],
  ["fisub", "-"],
  ["fmul", "*"],
  ["fmulp", "*"],
  ["fimul", "*"],
  ["fdiv", "/"],
  ["fdivp", "/"],
  ["fidiv", "/"],
]);

const SSE_SCALAR = new Map<string, BinaryOp | null>([
  ["movss", null],
  ["movsd", null],
  ["addss", "+"],
  ["addsd", "+"],
  ["subss", "-"],
  ["subsd", "-"],
  ["mulss", "*"],
  ["mulsd", "*"],
  ["divss", "/"],
  ["divsd", "/"],
  ["comiss", null],
  ["comisd", null],
  ["ucomiss", null],
  ["ucomisd", null],
]);

/**
 * Lift a single basic block's instructions to IR statements.
 *
 * `calleeSavedFirstWrite` is the one piece of *function*-wide context this
 * otherwise block-local pass takes: the lowest address at which each x86
 * callee-saved register is written (`firstCalleeSavedWrites`). `collectArgs32`
 * needs it to tell a prologue register save from a pushed argument, and that
 * question cannot be answered inside a block — w32.exe 0x40104D is a genuine
 * `push esi` argument at a block *leader*, with ESI written in an earlier
 * block. It is optional and means nothing on the x64 path, where arguments
 * come from registers rather than pushes; omitting it keeps the pre-existing
 * behaviour, which is deliberately not the same claim as "there are no writes".
 */
export function liftBlock(
  block: BasicBlock,
  regState: RegState,
  is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  _stringMap: Map<number, string>,
  funcMap: Map<number, { name: string; address: number }>,
  calleeSavedFirstWrite?: Map<string, number>,
): IRStmt[] {
  const stmts: IRStmt[] = [];

  for (const insn of block.insns) {
    const mn = insn.mnemonic.toLowerCase();
    const parts = splitOperands(insn.opStr);

    // ── nop / int3 / ud2 ──
    if (mn === "nop" || mn === "int3" || mn === "ud2") continue;

    // ── push / pop: handled implicitly, but we still track for x86 call args ──
    if (mn === "push" || mn === "pop") continue;

    // ── mov ──
    if (mn === "mov") {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${mn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const src = parseOperand(parts[1], insn, is64);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: src,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, src);
      }
      continue;
    }

    // ── movzx / movsx / movsxd → emit IRCast with type annotation ──
    if (mn === "movzx" || mn === "movsx" || mn === "movsxd") {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${mn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const srcRaw = parseOperand(parts[1], insn, is64);
      // Determine source width from prefix or register size
      const srcSize =
        memPrefixSize(parts[1]) ||
        (srcRaw.kind === "reg" ? regSize(srcRaw.name) : srcRaw.kind === "deref" ? srcRaw.size : 4);
      const signed = mn === "movsx" || mn === "movsxd";
      const castType = signed
        ? srcSize === 1
          ? "int8_t"
          : srcSize === 2
            ? "int16_t"
            : "int32_t"
        : srcSize === 1
          ? "uint8_t"
          : "uint16_t";
      const src: IRExpr = { kind: "cast", type: castType, operand: srcRaw };
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: src,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, src);
      }
      continue;
    }

    // ── lea ──
    if (mn === "lea") {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${mn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      // For lea, the bracket content is the address expression (no deref)
      const bracketM = parts[1].match(BRACKET_PATTERN);
      let src: IRExpr;
      if (bracketM) {
        src = parseMemExpr(bracketM[1], insn, is64);
      } else {
        src = parseOperand(parts[1], insn, is64);
      }
      stmts.push({ kind: "assign", dest, src, addr: insn.address });
      if (dest.kind === "reg") regState.set(dest.name, src);
      continue;
    }

    // ── xor reg, reg → zero idiom ──
    if (mn === "xor" && parts.length >= 2) {
      const d = parts[0].trim().toLowerCase();
      const s = parts[1].trim().toLowerCase();
      if (d === s && isRegister(d)) {
        const dest = irReg(d);
        const zero = irConst(0, regSize(d));
        stmts.push({ kind: "assign", dest, src: zero, addr: insn.address });
        regState.set(d, zero);
        continue;
      }
    }

    // ── Arithmetic: add/sub/and/or/xor/shl/shr/sar ──
    if (mn in ARITH_OPS) {
      if (parts.length < 2) {
        stmts.push({ kind: "raw", text: `${mn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64);
      const src = parseOperand(parts[1], insn, is64);
      const op = ARITH_OPS[mn];
      const result = irBinary(op, destVal, src);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: result,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── imul ──
    if (mn === "imul") {
      if (parts.length === 2) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const destVal = parseOperand(parts[0], insn, is64);
        const src = parseOperand(parts[1], insn, is64);
        const result = irBinary("*", destVal, src);
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      } else if (parts.length >= 3) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const a = parseOperand(parts[1], insn, is64);
        const b = parseOperand(parts[2], insn, is64);
        const result = irBinary("*", a, b);
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      } else {
        stmts.push({ kind: "raw", text: `${mn} ${insn.opStr}`, addr: insn.address });
      }
      continue;
    }

    // ── inc / dec ──
    if (mn === "inc" || mn === "dec") {
      if (parts.length < 1) {
        stmts.push({ kind: "raw", text: `${mn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64);
      const op: BinaryOp = mn === "inc" ? "+" : "-";
      const result = irBinary(op, destVal, irConst(1));
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: result,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── not / neg ──
    if (mn === "not" || mn === "neg") {
      if (parts.length < 1) {
        stmts.push({ kind: "raw", text: `${mn} ${insn.opStr}`, addr: insn.address });
        continue;
      }
      const dest = parseDestOperand(parts[0], insn, is64);
      const destVal = parseOperand(parts[0], insn, is64);
      const result = irUnary(mn === "not" ? "~" : "-", destVal);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: result,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── cmp / test → flag state + eflags IR assignment ──
    if (mn === "cmp" || mn === "test") {
      if (parts.length >= 2) {
        const left = parseOperand(parts[0], insn, is64);
        const right = parseOperand(parts[1], insn, is64);
        regState.setFlags(mn as "cmp" | "test", left, right);
        // Emit eflags definition for SSA cross-block propagation
        const flagExpr = mn === "cmp" ? irBinary("-", left, right) : irBinary("&", left, right);
        stmts.push({ kind: "assign", dest: irReg("eflags", 4), src: flagExpr, addr: insn.address });
      }
      continue;
    }

    // ── setXX ──
    if (mn in COND_SET) {
      if (parts.length >= 1) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const cond = regState.getCondition(COND_SET[mn]);
        stmts.push({ kind: "assign", dest, src: cond, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, cond);
      }
      continue;
    }

    // ── cmovXX ──
    const cmovM = mn.match(CMOV_PATTERN);
    if (cmovM) {
      if (parts.length >= 2) {
        const dest = parseDestOperand(parts[0], insn, is64);
        const destVal = parseOperand(parts[0], insn, is64);
        const src = parseOperand(parts[1], insn, is64);
        const jcc = "j" + cmovM[1];
        const cond = regState.getCondition(jcc);
        const result: IRExpr = { kind: "ternary", condition: cond, then: src, else: destVal };
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── call ──
    if (mn === "call") {
      const target = resolveCallTarget(insn, is64, iatMap, funcMap);
      const args = is64
        ? collectArgs64(regState)
        : collectArgs32(block, insn, is64, calleeSavedFirstWrite);
      const call: IRCall = {
        kind: "call",
        target: target.name,
        args,
        display: target.display,
      };
      const retReg = is64 ? "rax" : "eax";
      stmts.push({ kind: "call_stmt", call, resultDest: irReg(retReg), addr: insn.address });
      regState.invalidateCallerSaved();
      regState.set(retReg, call);
      continue;
    }

    // ── ret / retn ──
    if (mn === "ret" || mn === "retn") {
      // The return value is the accumulator, named — not the expression
      // `RegState` last recorded for it. That expression is bound to the
      // registers it names *as they were when it was recorded*, and nothing
      // invalidates it when one of them is written again: `mov rax, rbx` /
      // `mov rbx, [rsp+0x30]` / `ret` returned the restored RBX, i.e. the
      // saved-register slot, and the real return value went unread and was
      // then deleted as dead (peek-a-bin-lh6). Naming the register makes SSA
      // bind the read to the definition that actually reaches the `ret`,
      // which is what the instruction does.
      const retReg = is64 ? "rax" : "eax";
      stmts.push({ kind: "return", value: irReg(retReg, is64 ? 8 : 4), addr: insn.address });
      continue;
    }

    // ── Tail call: a `jmp` that leaves the function ──
    //
    // `buildCFG` gives such a jmp no successor, because its target is not a
    // block of this function. The instruction pushes no return address, so the
    // callee returns to *this* function's caller: it is a call followed by a
    // return of the accumulator, and that is what it lifts to. Dropping it
    // made a call the program performs invisible — and the argument set-up
    // above it then died as unread, so the reader saw a function that appears
    // to do nothing at the end (peek-a-bin-22t).
    //
    // Only a jmp whose target resolves to a *name* is lifted. An indirect
    // `jmp rax` and a jump-table dispatch whose targets were not recovered
    // also end a successorless block, and calling either one a tail call would
    // invent a callee that the disassembly does not name.
    if (mn === "jmp" && block.succs.length === 0 && insn === block.insns[block.insns.length - 1]) {
      const tail = resolveNamedTarget(insn, iatMap, funcMap);
      if (tail) {
        const args = is64
          ? collectArgs64(regState)
          : collectArgs32(block, insn, is64, calleeSavedFirstWrite);
        const call: IRCall = {
          kind: "call",
          target: tail.name,
          args,
          display: tail.display,
        };
        const retReg = is64 ? "rax" : "eax";
        stmts.push({ kind: "call_stmt", call, resultDest: irReg(retReg), addr: insn.address });
        regState.invalidateCallerSaved();
        regState.set(retReg, call);
        stmts.push({ kind: "return", value: irReg(retReg, is64 ? 8 : 4), addr: insn.address });
        continue;
      }

      // The target has no name. Saying nothing and saying "a transfer happens
      // here that I could not name" are different things, and the second is
      // what this repo does everywhere else it fails to recover something
      // (`__unrecovered_N`, `/* unlifted: … */`). t32!sub_402C5A is the case
      // that shows the cost of the first: it decodes a pointer and then, in
      // the emitted C, does nothing whatever with it — the call through the
      // decoded pointer was simply absent (peek-a-bin-xerm).
      //
      // TWO SHAPES end a successorless block with an unnameable target, and
      // only one of them is this one:
      //
      //   `jmp eax`                          — a genuine indirect transfer;
      //   `jmp dword ptr [ecx*4 + 0x40b900]` — a jump table whose entries were
      //                                        not recovered.
      //
      // A *recovered* table does not reach here at all: its case targets are
      // block leaders, so the dispatch block has successors and `structureCFG`
      // emits a `switch`. An unrecovered one is a gap in table recovery, not an
      // indirect call, and calling it one would state something false about the
      // program. So only a bare register operand is reported — measured at
      // cee6f91 that is 4 sites (t32 0x402c70/0x404480, w32 0x402ec4/0x4046e0)
      // against 14 table dispatches, and 0 sites on either x64 binary. A memory
      // operand of any shape stays silent, deliberately: `jmp [eax]` cannot be
      // told from an unrecovered table by looking at it.
      //
      // No call expression is synthesized. `resolveNamedTarget` exists because
      // there is no name here, and an invented callee is worse than an admitted
      // gap — the negative test in `pipeline.test.ts` pins that.
      const operand = insn.opStr.trim().toLowerCase();
      if (isKnownRegister(operand)) {
        stmts.push({ kind: "raw", text: `indirect jmp through ${operand}`, addr: insn.address });
        continue;
      }
    }

    // ── Conditional / unconditional jumps ──
    //
    // A conditional jump becomes an `IRBranch` so its condition is a real IR
    // reader: it gets an SSA version, a reaching definition, and a place in
    // every use count. `pipeline.ts` extracts it again before `structureCFG`,
    // so no structured tree ever contains one (peek-a-bin-c33).
    //
    // The precedent is a few lines up: `setcc` already assigns
    // `regState.getCondition()` to a register and that survives SSA renaming
    // untouched. This does for `jcc` what the lifter already does for `setcc`.
    //
    // `isFlagReadingJump` rather than `startsWith("j")`: `jecxz`/`jrcxz`/`jcxz`
    // test a *register* and read no flag, so a flag-derived condition would be
    // a statement about something they do not do.
    if (mn === "jmp" || mn.startsWith("j")) {
      if (isFlagReadingJump(mn) && insn === block.insns[block.insns.length - 1]) {
        // Only a direct target is recorded. An indirect or unresolved jump has
        // no address to name, and inventing one is the failure mode
        // `parseBranchTarget`'s guard exists to prevent.
        const target = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
        if (target) {
          stmts.push({
            kind: "branch",
            condition: regState.getCondition(mn),
            target: Number.parseInt(target[1], 16),
            jcc: mn,
            addr: insn.address,
          });
        }
      }
      continue;
    }

    // ── Sign-extend idioms ──
    if (mn === "cdq") {
      // edx = eax >> 31 (sign-extend eax into edx:eax)
      const eaxVal = irReg("eax", 4);
      const result = irBinary(">>", eaxVal, irConst(31));
      stmts.push({ kind: "assign", dest: irReg("edx"), src: result, addr: insn.address });
      regState.set("edx", result);
      continue;
    }
    if (mn === "cqo") {
      // rdx = rax >> 63
      const raxVal = irReg("rax", 8);
      const result = irBinary(">>", raxVal, irConst(63));
      stmts.push({ kind: "assign", dest: irReg("rdx"), src: result, addr: insn.address });
      regState.set("rdx", result);
      continue;
    }
    if (mn === "cdqe") {
      // rax = (int32_t)eax
      const eaxVal = irReg("eax", 4);
      const result: IRExpr = { kind: "cast", type: "int32_t", operand: eaxVal };
      stmts.push({ kind: "assign", dest: irReg("rax"), src: result, addr: insn.address });
      regState.set("rax", result);
      continue;
    }
    if (mn === "cwde") {
      // eax = (int16_t)ax
      const axVal = irReg("ax", 2);
      const result: IRExpr = { kind: "cast", type: "int16_t", operand: axVal };
      stmts.push({ kind: "assign", dest: irReg("eax"), src: result, addr: insn.address });
      regState.set("eax", result);
      continue;
    }
    if (mn === "cbw") {
      // ax = (int8_t)al
      const alVal = irReg("al", 1);
      const result: IRExpr = { kind: "cast", type: "int8_t", operand: alVal };
      stmts.push({ kind: "assign", dest: irReg("ax"), src: result, addr: insn.address });
      regState.set("ax", result);
      continue;
    }
    if (mn === "cwd") {
      // dx = ax >> 15
      const axVal = irReg("ax", 2);
      const result = irBinary(">>", axVal, irConst(15));
      stmts.push({ kind: "assign", dest: irReg("dx"), src: result, addr: insn.address });
      regState.set("dx", result);
      continue;
    }

    // ── div / idiv ──
    if (mn === "div" || mn === "idiv") {
      if (parts.length >= 1) {
        const divisor = parseOperand(parts[0], insn, is64);
        const srcSize =
          divisor.kind === "reg"
            ? regSize(divisor.name)
            : divisor.kind === "deref"
              ? divisor.size
              : 4;
        const dividendHi = srcSize === 8 ? "rdx" : srcSize === 2 ? "dx" : "edx";
        const dividendLo = srcSize === 8 ? "rax" : srcSize === 2 ? "ax" : "eax";
        const loVal = irReg(dividendLo, regSize(dividendLo));
        const quotient = irBinary("/", loVal, divisor);
        const remainder = irBinary("%", loVal, divisor);
        // Remainder first. Both expressions read the dividend, and one
        // instruction writes both halves *from the same input* — so the
        // statement that overwrites the dividend has to come second or SSA
        // binds the other one's read to it, giving `edx = (eax / ecx) % ecx`.
        // Emitting EDX first also keeps a divisor like `[eax]` readable.
        stmts.push({ kind: "assign", dest: irReg(dividendHi), src: remainder, addr: insn.address });
        stmts.push({ kind: "assign", dest: irReg(dividendLo), src: quotient, addr: insn.address });
        regState.set(dividendLo, quotient);
        regState.set(dividendHi, remainder);
      } else {
        stmts.push({ kind: "raw", text: `__asm { ${mn} ${insn.opStr} }`, addr: insn.address });
      }
      continue;
    }

    // ── mul (single-operand) ──
    if (mn === "mul") {
      if (parts.length >= 1) {
        const src = parseOperand(parts[0], insn, is64);
        const srcSize =
          src.kind === "reg" ? regSize(src.name) : src.kind === "deref" ? src.size : 4;
        const accLo = srcSize === 8 ? "rax" : srcSize === 2 ? "ax" : "eax";
        const accHi = srcSize === 8 ? "rdx" : srcSize === 2 ? "dx" : "edx";
        const loVal = irReg(accLo, regSize(accLo));
        const result = irBinary("*", loVal, src);
        // High part first — SSA DCE will eliminate it if unused. Both halves
        // are computed from the accumulator *before* the multiply, so writing
        // the low half first would make the high half read the product and
        // square it.
        stmts.push({
          kind: "assign",
          dest: irReg(accHi),
          src: irBinary(">>", result, irConst(srcSize * 8)),
          addr: insn.address,
        });
        stmts.push({ kind: "assign", dest: irReg(accLo), src: result, addr: insn.address });
        regState.set(accLo, result);
        regState.set(accHi, irBinary(">>", result, irConst(srcSize * 8)));
      } else {
        stmts.push({ kind: "raw", text: `__asm { ${mn} ${insn.opStr} }`, addr: insn.address });
      }
      continue;
    }

    // ── xchg ──
    if (mn === "xchg" && parts.length >= 2) {
      const a = parseDestOperand(parts[0], insn, is64);
      const b = parseDestOperand(parts[1], insn, is64);
      const aVal = parseOperand(parts[0], insn, is64);
      const bVal = parseOperand(parts[1], insn, is64);
      if (a.kind === "reg" && b.kind === "reg") {
        // A swap needs the temporary. `a = b; b = a` is not one: SSA renames
        // the second statement's read of `a` to the definition the first
        // statement just made, so both registers end up holding b's value.
        // The temporary is a plain register, so copy propagation collapses it
        // back to `a = b_0; b = a_0` — the temporary exists to pin the *read*
        // to the right program point, not to survive into the output.
        const tmp = irReg("tmp_xchg", regSize(a.name));
        stmts.push({ kind: "assign", dest: tmp, src: aVal, addr: insn.address });
        stmts.push({ kind: "assign", dest: a, src: bVal, addr: insn.address });
        stmts.push({ kind: "assign", dest: b, src: tmp, addr: insn.address });
        regState.set(a.name, bVal);
        regState.set(b.name, aVal);
      } else {
        stmts.push({ kind: "raw", text: `__asm { ${mn} ${insn.opStr} }`, addr: insn.address });
      }
      continue;
    }

    // ── String ops: rep movsb → memcpy, rep stosb → memset ──
    if (mn === "rep" || insn.opStr.toLowerCase().startsWith("rep ")) {
      const innerMn =
        mn === "rep" ? insn.opStr.toLowerCase().replace(/^rep\s+/, "") : insn.opStr.toLowerCase();

      if (innerMn.startsWith("movs")) {
        const rdi = irReg(is64 ? "rdi" : "edi", is64 ? 8 : 4);
        const rsi = irReg(is64 ? "rsi" : "esi", is64 ? 8 : 4);
        const rcx = irReg(is64 ? "rcx" : "ecx", is64 ? 8 : 4);
        const call: IRCall = { kind: "call", target: "memcpy", args: [rdi, rsi, rcx] };
        stmts.push({ kind: "call_stmt", call, addr: insn.address });
        continue;
      }
      if (innerMn.startsWith("stos")) {
        const rdi = irReg(is64 ? "rdi" : "edi", is64 ? 8 : 4);
        const al = irReg("al", 1);
        const rcx = irReg(is64 ? "rcx" : "ecx", is64 ? 8 : 4);
        const call: IRCall = { kind: "call", target: "memset", args: [rdi, al, rcx] };
        stmts.push({ kind: "call_stmt", call, addr: insn.address });
        continue;
      }
    }

    // ── Basic FPU: fld/fst/fstp/fadd/fsub/fmul/fdiv ──
    if (mn === "fld" && parts.length >= 1) {
      const src = parseOperand(parts[0], insn, is64);
      stmts.push({ kind: "assign", dest: irReg("st0"), src, addr: insn.address });
      regState.set("st0", src);
      continue;
    }
    if ((mn === "fst" || mn === "fstp") && parts.length >= 1) {
      const dest = parseDestOperand(parts[0], insn, is64);
      const st0 = irReg("st0", 10);
      if (dest.kind === "deref") {
        stmts.push({
          kind: "store",
          address: dest.address,
          value: st0,
          size: dest.size,
          addr: insn.address,
        });
      } else {
        stmts.push({ kind: "assign", dest, src: st0, addr: insn.address });
      }
      continue;
    }
    if (FPU_ARITH.has(mn) && parts.length >= 1) {
      const src = parseOperand(parts[0], insn, is64);
      const st0 = irReg("st0", 10);
      const op = FPU_ARITH.get(mn)!;
      const result = irBinary(op, st0, src);
      stmts.push({ kind: "assign", dest: irReg("st0"), src: result, addr: insn.address });
      regState.set("st0", result);
      continue;
    }

    // ── SSE scalar: movss/addss/subss/mulss/divss/comiss ──
    if (SSE_SCALAR.has(mn) && parts.length >= 2) {
      const dest = parseDestOperand(parts[0], insn, is64);
      const src = parseOperand(parts[1], insn, is64);
      if (mn === "movss" || mn === "movsd") {
        if (dest.kind === "deref") {
          stmts.push({
            kind: "store",
            address: dest.address,
            value: src,
            size: dest.size,
            addr: insn.address,
          });
        } else {
          stmts.push({ kind: "assign", dest, src, addr: insn.address });
          if (dest.kind === "reg") regState.set(dest.name, src);
        }
      } else if (mn === "comiss" || mn === "comisd" || mn === "ucomiss" || mn === "ucomisd") {
        // Comparison — sets eflags
        regState.setFlags("cmp", parseOperand(parts[0], insn, is64), src);
        stmts.push({
          kind: "assign",
          dest: irReg("eflags", 4),
          src: irBinary("-", parseOperand(parts[0], insn, is64), src),
          addr: insn.address,
        });
      } else {
        // Arithmetic: addss/subss/mulss/divss
        const op = SSE_SCALAR.get(mn)!;
        const destVal = parseOperand(parts[0], insn, is64);
        const result = irBinary(op, destVal, src);
        stmts.push({ kind: "assign", dest, src: result, addr: insn.address });
        if (dest.kind === "reg") regState.set(dest.name, result);
      }
      continue;
    }

    // ── Everything else: AVX, etc. → raw asm ──
    stmts.push({ kind: "raw", text: `__asm { ${mn} ${insn.opStr} }`, addr: insn.address });
  }

  return stmts;
}

// ── Call Target Resolution ──

/**
 * The name a direct, RIP-relative or absolute branch target stands for, or
 * null when the operand names no address at all (an indirect branch through a
 * register or a computed expression).
 *
 * Split out from `resolveCallTarget` because a tail `jmp` may only be lifted
 * when the target *is* nameable: `resolveCallTarget`'s `(*rax)` fallback is
 * right for `call rax`, where the disassembly already says a call happens, and
 * wrong for `jmp rax`, where it would invent one.
 */
function resolveNamedTarget(
  insn: Instruction,
  iatMap: Map<number, { lib: string; func: string }>,
  funcMap: Map<number, { name: string; address: number }>,
): { name: string; display?: string } | null {
  const opStr = insn.opStr.trim();

  // Direct: `call 0xNNNN`
  const directM = opStr.match(/^0x([0-9a-fA-F]+)$/);
  if (directM) {
    const addr = parseInt(directM[1], 16);
    const fn = funcMap.get(addr);
    if (fn) return { name: fn.name };
    return { name: `sub_${addr.toString(16).toUpperCase()}` };
  }

  // RIP-relative: `call qword ptr [rip + 0xNNNN]`
  const target = resolveRipTarget(insn);
  if (target !== null) {
    const iat = iatMap.get(target);
    if (iat) return { name: iat.func, display: `${iat.lib}!${iat.func}` };
    const fn = funcMap.get(target);
    if (fn) return { name: fn.name };
    return { name: `sub_${target.toString(16).toUpperCase()}` };
  }

  // Direct address in brackets: `call dword ptr [0xNNNN]`
  const addrM = opStr.match(/\[\s*0x([0-9a-fA-F]+)\s*\]/);
  if (addrM) {
    const abs = parseInt(addrM[1], 16);
    const iat = iatMap.get(abs);
    if (iat) return { name: iat.func, display: `${iat.lib}!${iat.func}` };
    return { name: `sub_${abs.toString(16).toUpperCase()}` };
  }

  return null;
}

function resolveCallTarget(
  insn: Instruction,
  _is64: boolean,
  iatMap: Map<number, { lib: string; func: string }>,
  funcMap: Map<number, { name: string; address: number }>,
): { name: string; display?: string } {
  const named = resolveNamedTarget(insn, iatMap, funcMap);
  if (named) return named;

  const opStr = insn.opStr.trim();

  // Indirect call through register
  if (isRegister(opStr)) {
    return { name: `(*${opStr})` };
  }

  // Comment-based IAT
  if (insn.comment) {
    const iatMatch = insn.comment.match(/^(\S+)!(\S+)$/);
    if (iatMatch) return { name: iatMatch[2], display: insn.comment };
  }

  return { name: `(*${opStr})` };
}

// ── Argument Collection ──

/**
 * Arguments for a Windows x64 fastcall, in register order.
 *
 * `RegState` is consulted for *arity only*: a call is given as many arguments
 * as there are leading fastcall registers this block has written, which is the
 * only arity evidence available at lift time. The argument itself is the plain
 * register — substituting the recorded expression re-expanded whatever computed
 * it (including another call) at the call site, and bound its leaves to the
 * wrong definitions once SSA renaming ran.
 *
 * The probe is `wroteAnyAlias`, not `get`, because argument setup is routinely
 * sub-width: MSVC emits `mov ecx, 1` for an `int` argument, and `RegState`
 * keys that def by the operand text, so asking for `rcx` missed it and stopped
 * arity right there. `ExitProcess()` was emitted with no argument at all while
 * the machine passed one, and with no reader in the IR the `ecx = 1` was then
 * deleted as dead — the exit code vanished from the output entirely. Only
 * *whether* an argument is emitted changes; what is emitted is still the plain
 * 64-bit register, and SSA already keys on the same canonical identity, so the
 * `rcx` read binds to the `ecx` def.
 */
function collectArgs64(regState: RegState): IRExpr[] {
  const args: IRExpr[] = [];
  for (const reg of FASTCALL_REGS_64) {
    if (!regState.wroteAnyAlias(reg)) break; // stop at first register this block never set
    args.push(irReg(reg, 8));
  }
  return args;
}

/**
 * The x86 callee-saved registers, canonicalised (`canonReg` maps every alias to
 * its 64-bit parent, which is the register's *identity*).
 *
 * The restriction to these four is what makes `collectArgs32`'s save rule below
 * sound rather than merely empirical. On x86 cdecl and stdcall every incoming
 * argument arrives on the stack, so a callee-saved register's *entry* value is
 * semantically opaque to the callee: it belongs to some caller further up and
 * this function has no reading of it. Forwarding it as an argument is
 * meaningless, so a `push` of one before anything has written it is a register
 * save. The same statement about EAX or ECX would be false — those carry
 * results and `__fastcall` arguments.
 */
const CALLEE_SAVED_CANON_32 = new Set(["rbx", "rsi", "rdi", "rbp"]);

/**
 * Mnemonics whose first operand is read, not written.
 *
 * Deliberately a DENY-list rather than an allow-list of writers, and the
 * asymmetry is the reason. A mnemonic missing from here is treated as a write,
 * which lowers the register's first-write address, which classifies *more*
 * pushes as arguments — i.e. it degrades towards the behaviour that existed
 * before this rule, and can invent nothing new. A wrongly *added* entry raises
 * the first-write address and drops a genuine argument. So the failure mode of
 * an incomplete list is the status quo, and the failure mode of an over-eager
 * one is a new under-count; the list is kept to mnemonics that provably do not
 * write their destination operand.
 *
 * Every conditional and unconditional jump is handled by the `j` prefix at the
 * call site — this is the x86 path only, where no non-branch mnemonic starts
 * with `j`. (Do not copy that shortcut to A64, where `bfi` is not a branch.)
 */
const NON_DEFINING_MNEMONICS = new Set([
  "push",
  "cmp",
  "test",
  "call",
  "ret",
  "retn",
  "nop",
  "int3",
  "ud2",
  "bt",
  "hlt",
  "leave", // handled separately: it writes EBP, but not its (absent) operand
]);

/** String-instruction mnemonics, which write ESI/EDI with no operand naming them. */
const STRING_OP_MNEMONICS = new Set([
  "movsb",
  "movsw",
  "movsd",
  "movsq",
  "stosb",
  "stosw",
  "stosd",
  "stosq",
  "lodsb",
  "lodsw",
  "lodsd",
  "lodsq",
  "scasb",
  "scasw",
  "scasd",
  "scasq",
  "cmpsb",
  "cmpsw",
  "cmpsd",
  "cmpsq",
]);

const REP_PREFIXES = new Set(["rep", "repe", "repz", "repne", "repnz"]);

/**
 * The lowest address in a function at which each callee-saved register is
 * written — the evidence `collectArgs32` needs to tell a register save from an
 * argument.
 *
 * A `push ebx` before the function has written EBX pushes the value EBX held on
 * entry; a `push ebx` after it pushes something this function computed. That is
 * the ONLY thing that separates the two, and it separates them at a site where
 * the same register in the same basic block is both. Verified on t32.exe at
 * 0x402C35:
 *
 *     402c37: 56              push esi            ; SAVE — ESI not yet written
 *     402c3a: be 17 04 00 c0  mov  esi, 0xc0000417 ; ESI defined here
 *     402c3f: 56              push esi            ; ARGUMENT
 *
 * Three properties of this scan are load-bearing and were each established
 * against a specific site in the corpus:
 *
 * - **Function-wide, not block-local.** w32.exe 0x40104D is `push esi` /
 *   `call FreeLibrary` at a *block leader*, with ESI written at 0x40100F in an
 *   earlier block. Scoped to the block, that genuine argument is dropped.
 * - **`mov X, X` is not a definition.** MSVC's hot-patch pad is `mov edi, edi`
 *   and it is the *entry instruction* of two of the four over-counting t32
 *   sites (0x405D6D, 0x405F2F). Counting it as a write to EDI re-admits both.
 * - **Address order, not CFG order.** This is an approximation, and its error
 *   is one-directional by construction: a write laid out *after* a push that
 *   dynamically precedes it makes the push look like a save, which drops an
 *   argument. It can never invent one. The reverse — a write laid out before a
 *   push it does not dominate — leaves the push classified as an argument, i.e.
 *   exactly today's behaviour.
 *
 * The scan reads the instruction stream only. It must never consult
 * `apitypes.ts`: `corpus/arity.ts` audits the emitted arity *against* that
 * table, so a lifter that reads it measures its own input and blinds the only
 * oracle in this repo that can see call arity at all.
 */
export function firstCalleeSavedWrites(blocks: BasicBlock[]): Map<string, number> {
  const first = new Map<string, number>();

  const note = (operand: string, addr: number): void => {
    const name = operand.trim().toLowerCase();
    if (!isKnownRegister(name)) return;
    const canon = canonReg(name);
    if (!CALLEE_SAVED_CANON_32.has(canon)) return;
    const prev = first.get(canon);
    if (prev === undefined || addr < prev) first.set(canon, addr);
  };

  for (const block of blocks) {
    for (const insn of block.insns) {
      const addr = insn.address;
      const tokens = insn.mnemonic.toLowerCase().split(/\s+/).filter(Boolean);
      const mn = tokens[tokens.length - 1] ?? "";
      const repPrefixed = tokens.some((t) => REP_PREFIXES.has(t));
      const parts = splitOperands(insn.opStr);

      // `leave` is `mov esp, ebp` + `pop ebp`, and `enter` builds a frame:
      // both write EBP while naming no operand that says so.
      if (mn === "leave" || mn === "enter") {
        note("ebp", addr);
        continue;
      }

      // A string instruction advances ESI and/or EDI. Capstone spells the
      // operands as `es:[edi]` / `[esi]` memory references, so the generic
      // destination-operand path below cannot see the write. The guard keeps
      // SSE `movsd xmm0, qword ptr [rax]` — the same mnemonic, a different
      // instruction — out: that one names real operands and no `rep` prefix.
      if (
        STRING_OP_MNEMONICS.has(mn) &&
        (repPrefixed || parts.length === 0 || /\bes:/i.test(insn.opStr))
      ) {
        note("esi", addr);
        note("edi", addr);
        continue;
      }

      if (NON_DEFINING_MNEMONICS.has(mn) || mn.startsWith("j")) continue;

      // One-operand `mul` / `div` / `imul` / `idiv` READ their operand and
      // write EDX:EAX. The two- and three-operand `imul` forms do write it.
      if ((mn === "mul" || mn === "div" || mn === "imul" || mn === "idiv") && parts.length < 2) {
        continue;
      }

      if (parts.length === 0) continue;

      // `mov edi, edi` is MSVC's hot-patch pad, not a definition. Stated in the
      // general form — `mov X, X` changes nothing whatever X is — but ONLY for
      // `mov`: `xor esi, esi` has the same operand shape and is a zeroing, i.e.
      // the most common definition there is. Generalising the test past `mov`
      // withdrew the write at t32.exe 0x4068C6 and turned four real `Sleep(esi)`
      // calls per x86 binary into `Sleep()`.
      if (mn === "mov" && parts.length === 2 && parts[0].toLowerCase() === parts[1].toLowerCase()) {
        continue;
      }

      note(parts[0], addr);
      // `xchg` writes both of its operands.
      if (mn === "xchg" && parts.length === 2) note(parts[1], addr);
    }
  }

  return first;
}

/**
 * Is this call nested in a *later* call's argument list?
 *
 * The shape is `call inner` / `push eax` / … / `call outer`: the inner call's
 * result is pushed, so the inner call is an argument expression of the outer
 * one and the outer one's argument list is still being built around it. The
 * pushes *before* the inner call therefore belong to the outer call, not to it.
 *
 * THE MARKER IS AFTER THE INNER CALL, NOT BEFORE IT, and that is the whole
 * reason a simpler rule does not work. The tempting reading — "stop the
 * backwards push-walk at an intervening call" — never fires, because in this
 * shape there is no call between the pushes and the inner call. Verified on
 * t32.exe at 0x40e08b:
 *
 *     53                 push ebx                ; 0x1000 → HeapAlloc's arg
 *     6a 08              push 0x8                ;        → HeapAlloc's arg
 *     ff 15 60 f0 40 00  call GetProcessHeap     ; declares 0, claimed both
 *     50                 push eax
 *     ff 15 70 f0 40 00  call HeapAlloc
 *
 * and at 0x402c4a with GetCurrentProcess/TerminateProcess.
 *
 * Only a push of the accumulator counts, and only as the very next instruction:
 * that is the evidence that this call's *result* is what feeds the outer one.
 * Everything from there to the outer call must be a push, i.e. the argument
 * list is still under construction — anything else and the accumulator's route
 * to the outer call is no longer something this scan can read.
 */
function nestedInLaterCallArgs(insns: Instruction[], callIdx: number, is64: boolean): boolean {
  const acc = is64 ? "rax" : "eax";
  const next = insns[callIdx + 1];
  if (next === undefined || next.mnemonic !== "push") return false;
  if (next.opStr.trim().toLowerCase() !== acc) return false;
  for (let i = callIdx + 2; i < insns.length; i++) {
    if (insns[i].mnemonic === "call") return true;
    if (insns[i].mnemonic !== "push") return false;
  }
  return false;
}

function collectArgs32(
  block: BasicBlock,
  callInsn: Instruction,
  is64: boolean,
  calleeSavedFirstWrite: Map<string, number> | undefined,
): IRExpr[] {
  // Scan backwards from call for consecutive push instructions
  const args: IRExpr[] = [];
  const insns = block.insns;
  let callIdx = -1;
  for (let i = insns.length - 1; i >= 0; i--) {
    if (insns[i].address === callInsn.address) {
      callIdx = i;
      break;
    }
  }
  if (callIdx < 0) return args;

  // A call whose result is pushed into a following call's argument list gets no
  // pushed arguments at all. The pushes above it are the OUTER call's, and
  // attributing them here invents arguments the machine never passed —
  // `GetProcessHeap(8, 0x1000)` for an API that declares none, which compiles
  // clean and which `corpus/arity.ts` is the only oracle here able to see.
  //
  // This is deliberately an ADMITTED UNDER-COUNT rather than a re-attribution:
  // handing the pushes to the outer call instead would be a guess in the
  // over-count direction, and an invented argument is the one error this
  // codebase will not trade for a recovered one. Where the inner call really
  // does take pushed arguments they are dropped, and it becomes an `under` row
  // — visible, and the benign direction. In this corpus every inner callee the
  // rule fires on declares zero parameters, so all four sites land on `exact`.
  if (nestedInLaterCallArgs(insns, callIdx, is64)) return args;

  // Walking backwards from the call already yields argument order: cdecl
  // pushes the last argument first, so the push nearest the call is argument 1.
  for (let i = callIdx - 1; i >= 0 && args.length < 8; i--) {
    if (insns[i].mnemonic !== "push") break;
    const op = insns[i].opStr.trim();
    if (isCalleeSavedSave(insns[i], op, calleeSavedFirstWrite)) break;
    args.push(parseOperand(op, insns[i], is64));
  }
  return args;
}

/**
 * Is this `push` a callee-saved register SAVE rather than an argument?
 *
 * The whole discriminator is whether the pushed register still holds its
 * function-entry value — see `firstCalleeSavedWrites` for the evidence and for
 * why address order is a sound approximation here. Reaching one of these ends
 * the backwards walk: a save sitting under an argument list means the walk has
 * left the argument list.
 *
 * Without this the walk swallowed the function's own prologue saves and emitted
 * them as arguments — `GetModuleHandleW("KERNEL32.DLL", edi)` for an API that
 * declares one parameter, `GetCommandLineW(edi, esi, ebx)` for one that
 * declares none. There is no reading of the machine on which those are right,
 * and they compile clean, so only `corpus/arity.ts` could see them
 * (peek-a-bin-6lmh).
 *
 * `calleeSavedFirstWrite === undefined` means nobody told us where the writes
 * are, which is not the same as "there are none": the rule declines and the
 * pre-existing behaviour stands.
 */
function isCalleeSavedSave(
  pushInsn: Instruction,
  operand: string,
  calleeSavedFirstWrite: Map<string, number> | undefined,
): boolean {
  if (calleeSavedFirstWrite === undefined) return false;
  const name = operand.toLowerCase();
  if (!isKnownRegister(name)) return false;
  const canon = canonReg(name);
  if (!CALLEE_SAVED_CANON_32.has(canon)) return false;
  const firstWrite = calleeSavedFirstWrite.get(canon);
  // Never written in this function at all — every push of it is a save.
  return firstWrite === undefined || pushInsn.address < firstWrite;
}
