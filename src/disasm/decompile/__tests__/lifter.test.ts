import { describe, expect, it } from "vitest";
import type { BasicBlock } from "../../cfg";
import type { Instruction } from "../../types";
import type { IRExpr, IRStmt } from "../ir";
import { irBinary, irConst, irDeref, irReg, irUnary, irUnknown } from "../ir";
import {
  crossBlockPopImmediates,
  firstCalleeSavedWrites,
  liftBlock,
  liftCrossBlockPops,
  parseOperand,
} from "../lifter";
import { RegState } from "../regstate";

const START = 0x401000;
const SIZE = 4;

function insn(mnemonic: string, opStr: string, address = START): Instruction {
  return { address, mnemonic, opStr, size: SIZE, bytes: new Uint8Array(SIZE) };
}

function blockOf(list: [string, string][]): BasicBlock {
  return {
    id: 0,
    startAddr: START,
    endAddr: START + list.length * SIZE,
    insns: list.map(([m, o], i) => insn(m, o, START + i * SIZE)),
    succs: [],
    preds: [],
  };
}

interface LiftOpts {
  is64?: boolean;
  state?: RegState;
  iat?: Map<number, { lib: string; func: string }>;
  funcs?: Map<number, { name: string; address: number }>;
}

function lift(list: [string, string][], opts: LiftOpts = {}): IRStmt[] {
  return liftBlock(
    blockOf(list),
    opts.state ?? new RegState(),
    opts.is64 ?? true,
    opts.iat ?? new Map(),
    new Map(),
    opts.funcs ?? new Map(),
  );
}

/** Lift one instruction and return its single statement. */
function liftOne(mnemonic: string, opStr: string, opts: LiftOpts = {}): IRStmt {
  const stmts = lift([[mnemonic, opStr]], opts);
  expect(stmts).toHaveLength(1);
  return stmts[0];
}

const operand = (op: string, is64 = true): IRExpr => parseOperand(op, insn("mov", ""), is64);

describe("parseOperand", () => {
  it("lifts a register operand to a plain register read", () => {
    // Deliberately independent of RegState: a register operand names a
    // register, and which value that register holds at this program point is
    // SSA's answer to give, not the lifter's (peek-a-bin-urs).
    const st = new RegState();
    st.set("rax", irConst(7));
    expect(operand("rax")).toEqual(irReg("rax", 8));
    expect(parseOperand("rax", insn("mov", ""), true)).toEqual(irReg("rax", 8));
    expect(st.get("rax")).toEqual(irConst(7));
  });

  it("sizes registers from their names", () => {
    expect(operand("eax")).toEqual(irReg("eax", 4));
    expect(operand("ax")).toEqual(irReg("ax", 2));
    expect(operand("al")).toEqual(irReg("al", 1));
    expect(operand("r8d")).toEqual(irReg("r8d", 4));
  });

  it("parses hexadecimal immediates as constants", () => {
    // Regression: isRegister() used to match everything, so immediates were
    // lifted as registers named "0x10" and never folded.
    expect(operand("0x10")).toEqual(irConst(0x10, 8));
    expect(operand("0x10", false)).toEqual(irConst(0x10, 4));
  });

  it("parses decimal and negative immediates", () => {
    expect(operand("42")).toEqual(irConst(42, 8));
    expect(operand("-8")).toEqual(irConst(-8, 8));
    expect(operand("-0x8")).toEqual(irConst(-8, 8));
  });

  it("returns an unknown expression for an unparsable operand", () => {
    expect(operand("some_label")).toEqual(irUnknown("some_label"));
    expect(operand("")).toEqual(irUnknown(""));
  });

  it("takes the dereference size from the memory prefix", () => {
    expect(operand("byte ptr [rax]")).toEqual(irDeref(irReg("rax", 8), 1));
    expect(operand("word ptr [rax]")).toEqual(irDeref(irReg("rax", 8), 2));
    expect(operand("dword ptr [rax]")).toEqual(irDeref(irReg("rax", 8), 4));
    expect(operand("qword ptr [rax]")).toEqual(irDeref(irReg("rax", 8), 8));
  });

  it("defaults an unprefixed dereference to the pointer width", () => {
    expect(operand("[rax]")).toEqual(irDeref(irReg("rax", 8), 8));
    expect(operand("[eax]", false)).toEqual(irDeref(irReg("eax", 4), 4));
  });

  it("builds base + displacement addresses", () => {
    expect(operand("dword ptr [rbp - 0x10]")).toEqual(
      irDeref(irBinary("-", irReg("rbp", 8), irConst(0x10, 8)), 4),
    );
    expect(operand("dword ptr [rbp + 0x10]")).toEqual(
      irDeref(irBinary("+", irReg("rbp", 8), irConst(0x10, 8)), 4),
    );
  });

  it("builds scaled index addresses", () => {
    expect(operand("dword ptr [rax + rcx*4]")).toEqual(
      irDeref(irBinary("+", irReg("rax", 8), irBinary("*", irReg("rcx", 8), irConst(4))), 4),
    );
  });

  it("builds base + index*scale + displacement addresses", () => {
    expect(operand("dword ptr [rax + rcx*8 + 0x20]")).toEqual(
      irDeref(
        irBinary(
          "+",
          irBinary("+", irReg("rax", 8), irBinary("*", irReg("rcx", 8), irConst(8))),
          irConst(0x20, 8),
        ),
        4,
      ),
    );
  });

  it("resolves rip-relative addresses against the next instruction", () => {
    const i = insn("mov", "", 0x401000);
    expect(parseOperand("qword ptr [rip + 0x100]", i, true)).toEqual(
      irDeref(irConst(0x401000 + SIZE + 0x100, 8), 8),
    );
    expect(parseOperand("qword ptr [rip - 0x100]", i, true)).toEqual(
      irDeref(irConst(0x401000 + SIZE - 0x100, 8), 8),
    );
  });

  it("keeps a base register inside an address as a register", () => {
    const st = new RegState();
    st.set("rax", irConst(0x1000));
    expect(operand("dword ptr [rax]")).toEqual(irDeref(irReg("rax", 8), 4));
  });

  it("leaves an unrecognised address term as unknown", () => {
    expect(operand("dword ptr [rax + gs]")).toEqual(
      irDeref(irBinary("+", irReg("rax", 8), irUnknown("gs")), 4),
    );
  });

  it("negates a leading negative address term", () => {
    expect(operand("dword ptr [-0x10 + rax]")).toEqual(
      irDeref(irBinary("+", irUnary("-", irConst(0x10, 8)), irReg("rax", 8)), 4),
    );
  });
});

describe("liftBlock — data movement", () => {
  it("drops padding instructions", () => {
    expect(
      lift([
        ["nop", ""],
        ["int3", ""],
        ["ud2", ""],
      ]),
    ).toEqual([]);
  });

  it("drops push and pop", () => {
    expect(
      lift([
        ["push", "rbp"],
        ["pop", "rbp"],
      ]),
    ).toEqual([]);
  });

  /**
   * Unconditional and interior jumps carry no value, so the structurer still
   * owns them entirely. A block's TRAILING conditional jump is different: it
   * becomes an `IRBranch` so its condition is a real IR reader with an SSA
   * version and a place in every use count (peek-a-bin-c33). `pipeline.ts`
   * extracts it again before `structureCFG`, so the structured tree is
   * unchanged — which is why this contract is pinned here, at the only stage
   * that can observe it.
   */
  it("drops an unconditional jump — control flow is handled by the structurer", () => {
    // Not last in the block: a trailing `jmp` out of a successor-less block is
    // a TAIL CALL and is lifted as one, which is a different contract.
    expect(
      lift([
        ["jmp", "0x401100"],
        ["mov", "rax, rbx"],
      ]),
    ).toHaveLength(1);
  });

  it("drops a conditional jump that is not the block's last instruction", () => {
    // Only a block's terminator can be its branch; an interior jcc is one the
    // CFG has already split on, so lifting it would invent a second terminator.
    expect(
      lift([
        ["je", "0x401100"],
        ["mov", "rax, rbx"],
      ]),
    ).toHaveLength(1);
  });

  it("lifts the block's trailing conditional jump to a branch statement", () => {
    const stmts = lift([
      ["cmp", "eax, 0x5"],
      ["jne", "0x401100"],
    ]);
    const branch = stmts.find((s) => s.kind === "branch");
    expect(branch).toBeDefined();
    expect(branch).toMatchObject({ kind: "branch", jcc: "jne", target: 0x401100 });
  });

  /**
   * `jecxz`/`jrcxz`/`jcxz` test a register and read no flag, so a flag-derived
   * condition would state something they do not do. `isFlagReadingJump` is what
   * keeps them out; `startsWith("j")` — the habit the rest of x86 encourages —
   * would let them through.
   */
  it("does not lift a branch for a jump that reads no flag", () => {
    expect(lift([["jecxz", "0x401100"]])).toEqual([]);
    expect(lift([["jrcxz", "0x401100"]])).toEqual([]);
  });

  it("lifts a register move and records the definition", () => {
    const st = new RegState();
    const stmt = liftOne("mov", "rax, 0x10", { state: st });
    expect(stmt).toEqual({
      kind: "assign",
      dest: irReg("rax", 8),
      src: irConst(0x10, 8),
      addr: START,
    });
    expect(st.get("rax")).toEqual(irConst(0x10, 8));
  });

  it("lifts a register-to-register move as a copy of the register", () => {
    // `mov rbx, rax` copies whatever RAX holds *here*. Naming the register is
    // what lets SSA bind the read to the definition that actually reaches it;
    // inlining the tracked value instead bound it to the block-entry value
    // (peek-a-bin-urs). Propagation is copyPropagation's and foldBlock's job.
    const stmts = lift([
      ["mov", "rax, 0x10"],
      ["mov", "rbx, rax"],
    ]);
    expect(stmts[1]).toEqual({
      kind: "assign",
      dest: irReg("rbx", 8),
      src: irReg("rax", 8),
      addr: START + SIZE,
    });
  });

  it("lifts a memory destination to a store", () => {
    expect(liftOne("mov", "dword ptr [rbp - 0x8], eax")).toEqual({
      kind: "store",
      address: irBinary("-", irReg("rbp", 8), irConst(8, 8)),
      value: irReg("eax", 4),
      size: 4,
      addr: START,
    });
  });

  it("falls back to raw text for a malformed mov", () => {
    expect(liftOne("mov", "rax")).toEqual({ kind: "raw", text: "mov rax", addr: START });
  });

  it("lifts movzx as an unsigned cast", () => {
    expect(liftOne("movzx", "eax, byte ptr [rcx]")).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: { kind: "cast", type: "uint8_t", operand: irDeref(irReg("rcx", 8), 1) },
      addr: START,
    });
  });

  it("lifts movsx as a signed cast sized from the source", () => {
    expect(liftOne("movsx", "eax, word ptr [rcx]")).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: { kind: "cast", type: "int16_t", operand: irDeref(irReg("rcx", 8), 2) },
      addr: START,
    });
  });

  it("sizes a movzx cast from a register source", () => {
    const stmt = liftOne("movzx", "eax, cl");
    expect(stmt).toMatchObject({ src: { kind: "cast", type: "uint8_t" } });
  });

  it("lifts movsxd as a 32-bit signed cast", () => {
    expect(liftOne("movsxd", "rax, ecx")).toMatchObject({
      src: { kind: "cast", type: "int32_t", operand: irReg("ecx", 4) },
    });
  });

  it("lifts lea to the address expression itself, not a load", () => {
    const st = new RegState();
    expect(liftOne("lea", "rax, [rbp - 0x20]", { state: st })).toEqual({
      kind: "assign",
      dest: irReg("rax", 8),
      src: irBinary("-", irReg("rbp", 8), irConst(0x20, 8)),
      addr: START,
    });
    expect(st.get("rax")).toEqual(irBinary("-", irReg("rbp", 8), irConst(0x20, 8)));
  });

  it("lifts a rip-relative lea to a constant address", () => {
    expect(liftOne("lea", "rax, [rip + 0x2000]")).toMatchObject({
      src: irConst(START + SIZE + 0x2000, 8),
    });
  });

  it("lifts xchg between registers through a temporary", () => {
    // `xchg rax, rbx` swaps. `rax = rbx; rbx = rax` does not: SSA renames the
    // second read of RAX to the definition the first statement just made, so
    // both registers end up holding RBX. The temporary pins RAX's read to the
    // program point before the swap; copy propagation removes it afterwards.
    const st = new RegState();
    st.set("rax", irConst(1));
    st.set("rbx", irConst(2));
    const stmts = lift([["xchg", "rax, rbx"]], { state: st });
    expect(stmts).toEqual([
      { kind: "assign", dest: irReg("tmp_xchg", 8), src: irReg("rax", 8), addr: START },
      { kind: "assign", dest: irReg("rax", 8), src: irReg("rbx", 8), addr: START },
      { kind: "assign", dest: irReg("rbx", 8), src: irReg("tmp_xchg", 8), addr: START },
    ]);
    expect(st.get("rax")).toEqual(irReg("rbx", 8));
    expect(st.get("rbx")).toEqual(irReg("rax", 8));
  });

  it("falls back to raw asm for xchg with a memory operand", () => {
    expect(liftOne("xchg", "qword ptr [rax], rbx")).toEqual({
      kind: "raw",
      text: "__asm { xchg qword ptr [rax], rbx }",
      addr: START,
    });
  });
});

describe("liftBlock — arithmetic", () => {
  it("lifts the binary arithmetic mnemonics", () => {
    const cases: [string, string][] = [
      ["add", "+"],
      ["sub", "-"],
      ["and", "&"],
      ["or", "|"],
      ["xor", "^"],
      ["shl", "<<"],
      ["sal", "<<"],
      ["sar", ">>"],
    ];
    for (const [mn, op] of cases) {
      expect(liftOne(mn, "rax, 0x4"), mn).toEqual({
        kind: "assign",
        dest: irReg("rax", 8),
        src: irBinary(op as never, irReg("rax", 8), irConst(4, 8)),
        addr: START,
      });
    }
  });

  it("lifts shr as an unsigned shift and sar as a signed one", () => {
    expect(liftOne("shr", "rax, 0x2")).toMatchObject({ src: { op: ">>>" } });
    expect(liftOne("sar", "rax, 0x2")).toMatchObject({ src: { op: ">>" } });
  });

  it("reads the destination before overwriting it", () => {
    // `add rax, 3` is a read-modify-write, so RAX appears on both sides. One
    // statement is enough: SSA renames the use before it versions the
    // definition, so the read is the old RAX.
    const st = new RegState();
    st.set("rax", irConst(5));
    expect(liftOne("add", "rax, 0x3", { state: st })).toMatchObject({
      src: irBinary("+", irReg("rax", 8), irConst(3, 8)),
    });
  });

  it("lifts arithmetic on memory to a read-modify-write store", () => {
    expect(liftOne("add", "dword ptr [rbp - 0x4], 0x1")).toEqual({
      kind: "store",
      address: irBinary("-", irReg("rbp", 8), irConst(4, 8)),
      value: irBinary(
        "+",
        irDeref(irBinary("-", irReg("rbp", 8), irConst(4, 8)), 4),
        irConst(1, 8),
      ),
      size: 4,
      addr: START,
    });
  });

  it("recognises `xor reg, reg` as a zeroing idiom", () => {
    const st = new RegState();
    expect(liftOne("xor", "eax, eax", { state: st })).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: irConst(0, 4),
      addr: START,
    });
    expect(st.get("eax")).toEqual(irConst(0, 4));
  });

  it("does not treat xor of two different registers as zeroing", () => {
    expect(liftOne("xor", "eax, ecx")).toMatchObject({
      src: irBinary("^", irReg("eax", 4), irReg("ecx", 4)),
    });
  });

  it("lifts two-operand imul", () => {
    expect(liftOne("imul", "rax, rcx")).toMatchObject({
      dest: irReg("rax", 8),
      src: irBinary("*", irReg("rax", 8), irReg("rcx", 8)),
    });
  });

  it("lifts three-operand imul without reading the destination", () => {
    expect(liftOne("imul", "rax, rcx, 0x4")).toMatchObject({
      dest: irReg("rax", 8),
      src: irBinary("*", irReg("rcx", 8), irConst(4, 8)),
    });
  });

  it("falls back to raw text for one-operand imul", () => {
    expect(liftOne("imul", "rcx")).toEqual({ kind: "raw", text: "imul rcx", addr: START });
  });

  it("lifts inc and dec as +/- 1", () => {
    expect(liftOne("inc", "rax")).toMatchObject({
      src: irBinary("+", irReg("rax", 8), irConst(1)),
    });
    expect(liftOne("dec", "rax")).toMatchObject({
      src: irBinary("-", irReg("rax", 8), irConst(1)),
    });
  });

  it("lifts inc on memory as a store", () => {
    expect(liftOne("inc", "dword ptr [rax]")).toMatchObject({ kind: "store", size: 4 });
  });

  it("lifts not and neg as unary operators", () => {
    expect(liftOne("not", "rax")).toMatchObject({ src: irUnary("~", irReg("rax", 8)) });
    expect(liftOne("neg", "rax")).toMatchObject({ src: irUnary("-", irReg("rax", 8)) });
  });

  it("lifts mul into a shifted high half and a low half", () => {
    // High half first: both halves are the same product of the accumulator
    // *before* the multiply, so writing EAX first made the high half read the
    // product and square it.
    const stmts = lift([["mul", "ecx"]]);
    expect(stmts[0]).toMatchObject({
      dest: irReg("edx", 4),
      src: { op: ">>", right: irConst(32) },
    });
    expect(stmts[1]).toMatchObject({
      dest: irReg("eax", 4),
      src: irBinary("*", irReg("eax", 4), irReg("ecx", 4)),
    });
  });

  it("picks the accumulator width from the mul operand", () => {
    expect(lift([["mul", "rcx"]])[1]).toMatchObject({ dest: irReg("rax", 8) });
    expect(lift([["mul", "cx"]])[1]).toMatchObject({ dest: irReg("ax", 2) });
  });

  it("lifts div into a quotient and a remainder over the original dividend", () => {
    // One instruction writes both halves from the same input, so the statement
    // that overwrites the dividend must come second — EDX first. Emitting EAX
    // first made the remainder read the quotient: `edx = (eax / ecx) % ecx`.
    const st = new RegState();
    st.set("eax", irConst(100));
    const stmts = lift([["div", "ecx"]], { state: st });
    expect(stmts[0]).toEqual({
      kind: "assign",
      dest: irReg("edx", 4),
      src: irBinary("%", irReg("eax", 4), irReg("ecx", 4)),
      addr: START,
    });
    expect(stmts[1]).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: irBinary("/", irReg("eax", 4), irReg("ecx", 4)),
      addr: START,
    });
  });

  it("falls back to raw asm for div with no operand", () => {
    expect(liftOne("div", "")).toEqual({ kind: "raw", text: "__asm { div  }", addr: START });
  });

  it("lifts the sign-extension idioms", () => {
    expect(liftOne("cdq", "")).toMatchObject({
      dest: irReg("edx", 4),
      src: irBinary(">>", irReg("eax", 4), irConst(31)),
    });
    expect(liftOne("cqo", "")).toMatchObject({
      dest: irReg("rdx", 8),
      src: irBinary(">>", irReg("rax", 8), irConst(63)),
    });
    expect(liftOne("cwd", "")).toMatchObject({
      dest: irReg("dx", 2),
      src: irBinary(">>", irReg("ax", 2), irConst(15)),
    });
    expect(liftOne("cdqe", "")).toMatchObject({
      dest: irReg("rax", 8),
      src: { kind: "cast", type: "int32_t" },
    });
    expect(liftOne("cwde", "")).toMatchObject({
      dest: irReg("eax", 4),
      src: { kind: "cast", type: "int16_t" },
    });
    expect(liftOne("cbw", "")).toMatchObject({
      dest: irReg("ax", 2),
      src: { kind: "cast", type: "int8_t" },
    });
  });
});

describe("liftBlock — flags and conditionals", () => {
  // A compare writes only the flags, and the flags reach the IR as the
  // condition of the block's `branch` statement. The `eflags = ...` proxy this
  // used to assert on had no reader of its own, so every pass had to be taught
  // to leave it alone and `ssaOptimize` had to strip it again before emission
  // (peek-a-bin-c33 stage 2b).
  it("records the flag state for cmp and emits no statement", () => {
    const st = new RegState();
    expect(lift([["cmp", "eax, 0x0"]], { state: st })).toEqual([]);
    expect(st.getCondition("je")).toEqual(irBinary("==", irReg("eax", 4), irConst(0, 8)));
  });

  it("records the flag state for test and emits no statement", () => {
    const st = new RegState();
    expect(lift([["test", "eax, eax"]], { state: st })).toEqual([]);
    expect(st.getCondition("jne")).toEqual(irBinary("!=", irReg("eax", 4), irConst(0, 4)));
  });

  it("drops a cmp with too few operands", () => {
    expect(lift([["cmp", "eax"]])).toEqual([]);
  });

  it("lifts setcc from the pending flag state", () => {
    const stmts = lift([
      ["cmp", "eax, 0x1"],
      ["sete", "al"],
    ]);
    expect(stmts[0]).toEqual({
      kind: "assign",
      dest: irReg("al", 1),
      src: irBinary("==", irReg("eax", 4), irConst(1, 8)),
      addr: START + SIZE,
    });
  });

  it("lifts setcc with no preceding compare as unknown", () => {
    expect(liftOne("setne", "al")).toMatchObject({ src: { kind: "unknown" } });
  });

  it("lifts cmovcc as a ternary over the old destination value", () => {
    const stmts = lift([
      ["cmp", "eax, 0x1"],
      ["cmovne", "rbx, rcx"],
    ]);
    expect(stmts[0]).toEqual({
      kind: "assign",
      dest: irReg("rbx", 8),
      src: {
        kind: "ternary",
        condition: irBinary("!=", irReg("eax", 4), irConst(1, 8)),
        then: irReg("rcx", 8),
        else: irReg("rbx", 8),
      },
      addr: START + SIZE,
    });
  });
});

describe("liftBlock — calls and returns", () => {
  const call = (opStr: string, opts: LiftOpts = {}) =>
    liftOne("call", opStr, opts) as IRStmt & {
      call: { target: string; display?: string; args: IRExpr[] };
    };

  it("names a direct call from the function map", () => {
    const funcs = new Map([[0x402000, { name: "DoWork", address: 0x402000 }]]);
    expect(call("0x402000", { funcs }).call.target).toBe("DoWork");
  });

  it("synthesizes a sub_ name for an unknown direct call", () => {
    expect(call("0x402000").call.target).toBe("sub_402000");
  });

  it("resolves a rip-relative call through the import table", () => {
    const target = START + SIZE + 0x1000;
    const iat = new Map([[target, { lib: "kernel32.dll", func: "CreateFileW" }]]);
    const stmt = call("qword ptr [rip + 0x1000]", { iat });
    expect(stmt.call.target).toBe("CreateFileW");
    expect(stmt.call.display).toBe("kernel32.dll!CreateFileW");
  });

  it("resolves an absolute indirect call through the import table", () => {
    const iat = new Map([[0x403000, { lib: "user32.dll", func: "MessageBoxA" }]]);
    expect(call("dword ptr [0x403000]", { iat }).call.target).toBe("MessageBoxA");
  });

  it("renders an indirect register call as a dereference", () => {
    expect(call("rax").call.target).toBe("(*rax)");
  });

  it("falls back to the instruction comment for an import", () => {
    const stmts = liftBlock(
      {
        id: 0,
        startAddr: START,
        endAddr: START + SIZE,
        succs: [],
        preds: [],
        insns: [{ ...insn("call", "qword ptr [rax + 0x18]"), comment: "ws2_32.dll!connect" }],
      },
      new RegState(),
      true,
      new Map(),
      new Map(),
      new Map(),
    );
    expect(stmts[0]).toMatchObject({ call: { target: "connect", display: "ws2_32.dll!connect" } });
  });

  it("records the return register as the call result", () => {
    expect(call("0x402000")).toMatchObject({ resultDest: irReg("rax", 8) });
    expect(lift([["call", "0x402000"]], { is64: false })[0]).toMatchObject({
      resultDest: irReg("eax", 4),
    });
  });

  it("collects x64 arguments from the fastcall registers", () => {
    const stmts = lift([
      ["mov", "rcx, 0x1"],
      ["mov", "rdx, 0x2"],
      ["call", "0x402000"],
    ]);
    // RegState answers only "how many leading fastcall registers did this
    // block write" — the argument itself is the register, so SSA binds it to
    // the definition reaching the call rather than re-expanding whatever
    // computed it (which duplicated calls passed as arguments).
    expect((stmts[2] as { call: { args: IRExpr[] } }).call.args).toEqual([
      irReg("rcx", 8),
      irReg("rdx", 8),
    ]);
  });

  it("stops collecting x64 arguments at the first unset register", () => {
    const stmts = lift([
      ["mov", "rdx, 0x2"],
      ["call", "0x402000"],
    ]);
    expect((stmts[1] as { call: { args: IRExpr[] } }).call.args).toEqual([]);
  });

  // Was peek-a-bin-qb2x, and this test pinned the defect rather than the rule
  // for as long as it stood: `collectArgs64` looked the arguments up under
  // 'rcx'/'rdx'/'r8'/'r9' while the lifter keys definitions by the literal
  // operand text, so setting up an argument with a 32-bit move — the normal way
  // to pass an int — left the definition under 'ecx' and the call was emitted
  // with no arguments at all. The probe is width-blind now (`wroteAnyAlias`).
  // The arguments are still the plain 64-bit registers: only arity comes from
  // `RegState`, never the recorded expression.
  it("counts x64 arguments set up through 32-bit sub-registers", () => {
    const stmts = lift([
      ["mov", "ecx, 0x1"],
      ["mov", "edx, 0x2"],
      ["call", "0x402000"],
    ]);
    expect((stmts[2] as { call: { args: IRExpr[] } }).call.args).toEqual([
      irReg("rcx", 8),
      irReg("rdx", 8),
    ]);
  });

  // peek-a-bin-7r1l, the last x64 arity over-count. `collectArgs64` asked
  // `RegState` only whether the block had *written* a fastcall register, which
  // is also true of a register the block wrote for its own addressing and never
  // meant to pass. t64 0x14000B34B, an over-count row against the real
  // prototype: `GetLastError` declares no parameters.
  it("does not pass an x64 register the block already spent as an address index", () => {
    const stmts = lift([
      ["imul", "rcx, rcx, 0x58"],
      ["and", "byte ptr [rax + rcx + 8], 0xfe"],
      ["call", "0x402000"],
    ]);
    expect((stmts[2] as { call: { args: IRExpr[] } }).call.args).toEqual([]);
  });

  // t64 0x140003688: RDX is spent indexing, RCX — computed *from* it — is the
  // one argument `LeaveCriticalSection` declares. Both registers are written,
  // so the pre-fix answer was two arguments.
  it("keeps the argument computed from a spent index, and drops the index", () => {
    const stmts = lift([
      ["imul", "rdx, rdx, 0x58"],
      ["lea", "rcx, [rax + rdx + 0x10]"],
      ["call", "0x402000"],
    ]);
    expect((stmts[2] as { call: { args: IRExpr[] } }).call.args).toEqual([irReg("rcx", 8)]);
  });

  // THE PREFIX PROPERTY, not a patch: argument two derived from argument one.
  // `collectArgs64` counts a prefix, so if RDX is an argument then RCX is one
  // too and the index read cannot be evidence against it. t64 0x14000FCFE —
  // without this the whole of sub_14000FCE7 emitted as one bare
  // `sub_14000278C()` for a callee that reads both ECX and RDX, and the two
  // statements computing them were then deleted as dead.
  it("keeps an index register that a LATER argument register was derived from", () => {
    const stmts = lift([
      ["movsxd", "rcx, dword ptr [rbp + 0x20]"],
      ["mov", "rdx, qword ptr [rdx + rcx*8]"],
      ["call", "0x402000"],
    ]);
    expect((stmts[2] as { call: { args: IRExpr[] } }).call.args).toEqual([
      irReg("rcx", 8),
      irReg("rdx", 8),
    ]);
  });

  // REFUTED WIDENING #1 — "any read spends the register". t64 0x14000FAF0
  // spills R8 to the outgoing stack-argument area *because* it is also the
  // register argument; treating that as a read cost `CreateFileW` two of four.
  it("does not spend an x64 argument register by copying its value elsewhere", () => {
    const stmts = lift([
      ["mov", "rcx, rbx"],
      ["mov", "edx, 0x40000000"],
      ["mov", "r8d, 0x3"],
      ["xor", "r9d, r9d"],
      ["mov", "dword ptr [rsp + 0x20], r8d"],
      ["call", "0x402000"],
    ]);
    expect((stmts[5] as { call: { args: IRExpr[] } }).call.args).toHaveLength(4);
  });

  // REFUTED WIDENING #2 — "any read from inside a memory operand spends it".
  // t64 0x14000BD6E `lea edx, [r9+8]` is MSVC computing the constant 9 from the
  // 1 it just put in R9: arithmetic wearing an address's clothes, and R9 is
  // argument four of the MultiByteToWideChar two instructions later. R9 is the
  // BASE, which is the whole reason base and index are told apart.
  it("does not spend an x64 argument register used as an address BASE", () => {
    const stmts = lift([
      ["mov", "rcx, rbx"],
      ["mov", "r9d, 0x1"],
      ["lea", "edx, [r9 + 8]"],
      ["mov", "r8, rdi"],
      ["call", "0x402000"],
    ]);
    expect((stmts[4] as { call: { args: IRExpr[] } }).call.args).toHaveLength(4);
  });

  // An index read is spent only until the register is written again — the
  // write starts a new value with no reader. `mov rcx, [rax + rcx*8]` both
  // spends RCX and replaces it.
  it("un-spends an index register that the same instruction rewrites", () => {
    const stmts = lift([
      ["mov", "rcx, qword ptr [rax + rcx*8]"],
      ["call", "0x402000"],
    ]);
    expect((stmts[1] as { call: { args: IRExpr[] } }).call.args).toEqual([irReg("rcx", 8)]);
  });

  // The call's OWN addressing is not the block spending a register before it:
  // `call qword ptr [rax + rcx*8]` finds its callee through a table, and RCX
  // may still be the first argument.
  it("does not let a call's own indexed target suppress its arguments", () => {
    const stmts = lift([
      ["mov", "rcx, rbx"],
      ["call", "qword ptr [rax + rcx*8]"],
    ]);
    expect((stmts[1] as { call: { args: IRExpr[] } }).call.args).toEqual([irReg("rcx", 8)]);
  });

  it("collects x86 arguments from the pushes before the call", () => {
    const stmts = lift(
      [
        ["push", "0x2"],
        ["push", "0x1"],
        ["call", "0x402000"],
      ],
      { is64: false },
    );
    expect((stmts[0] as { call: { args: IRExpr[] } }).call.args).toEqual([
      irConst(1, 4),
      irConst(2, 4),
    ]);
  });

  it("stops collecting x86 arguments at a non-push instruction", () => {
    const stmts = lift(
      [
        ["push", "0x2"],
        ["mov", "eax, 0x0"],
        ["push", "0x1"],
        ["call", "0x402000"],
      ],
      { is64: false },
    );
    expect((stmts[1] as { call: { args: IRExpr[] } }).call.args).toEqual([irConst(1, 4)]);
  });

  // `call inner / push eax / call outer` — the inner call is an argument
  // expression of the outer one, so the pushes ABOVE it are the outer call's.
  // Verified on t32.exe at 0x40e08b (GetProcessHeap/HeapAlloc) and 0x402c4a
  // (GetCurrentProcess/TerminateProcess). Note there is no call BETWEEN the
  // pushes and the inner call: the marker is after it, which is why a
  // "stop the walk at an intervening call" rule would never fire here.
  it("gives no pushed arguments to a call whose result feeds a following call", () => {
    const stmts = lift(
      [
        ["push", "ebx"],
        ["push", "0x8"],
        ["call", "0x402000"],
        ["push", "eax"],
        ["call", "0x403000"],
      ],
      { is64: false },
    );
    expect((stmts[0] as { call: { args: IRExpr[] } }).call.args).toEqual([]);
  });

  // The admitted under-count: the outer call keeps only what its own backwards
  // walk reaches, which stops at the inner `call`. Re-attributing the inner
  // call's pushes to it would be a guess in the over-count direction.
  it("does not re-attribute the inner call's pushes to the outer call", () => {
    const stmts = lift(
      [
        ["push", "ebx"],
        ["push", "0x8"],
        ["call", "0x402000"],
        ["push", "eax"],
        ["call", "0x403000"],
      ],
      { is64: false },
    );
    expect((stmts[1] as { call: { args: IRExpr[] } }).call.args).toEqual([irReg("eax", 4)]);
  });

  // Only the accumulator counts, and only as the very next instruction. A push
  // of something else after the call is the next call's argument set-up, and
  // says nothing about where this call's result went.
  it("keeps pushed arguments when the following push is not the accumulator", () => {
    const stmts = lift(
      [
        ["push", "0x8"],
        ["call", "0x402000"],
        ["push", "esi"],
        ["call", "0x403000"],
      ],
      { is64: false },
    );
    expect((stmts[0] as { call: { args: IRExpr[] } }).call.args).toEqual([irConst(8, 4)]);
  });

  // `push eax` with no later call in the block is a stack store, not an
  // argument to anything this scan can see.
  it("keeps pushed arguments when no later call consumes the pushed result", () => {
    const stmts = lift(
      [
        ["push", "0x8"],
        ["call", "0x402000"],
        ["push", "eax"],
        ["mov", "esi, 0x1"],
      ],
      { is64: false },
    );
    expect((stmts[0] as { call: { args: IRExpr[] } }).call.args).toEqual([irConst(8, 4)]);
  });

  it("invalidates caller-saved registers across the call", () => {
    const st = new RegState();
    const stmts = lift(
      [
        ["mov", "rcx, 0x1"],
        ["mov", "rbx, 0x2"],
        ["call", "0x402000"],
        ["mov", "rax, rcx"],
        ["mov", "rdx, rbx"],
      ],
      { state: st },
    );
    // Both statements now name their register — the IR no longer shows the
    // difference, so assert it where it still matters: RegState is what
    // decides a call's arity and what getCondition reads.
    expect(stmts[3]).toMatchObject({ src: irReg("rcx", 8) });
    expect(stmts[4]).toMatchObject({ src: irReg("rbx", 8) });
    expect(st.get("rcx")).toBeUndefined();
    expect(st.get("rbx")).toEqual(irConst(2, 8));
  });

  it("makes the call result available as the return register", () => {
    // The call defines RAX and the `ret` reads RAX; the two are connected by
    // the register, which is what the ABI says and what SSA can follow.
    const stmts = lift([
      ["call", "0x402000"],
      ["ret", ""],
    ]);
    expect(stmts[0]).toMatchObject({
      kind: "call_stmt",
      resultDest: irReg("rax", 8),
      call: { target: "sub_402000" },
    });
    expect(stmts[1]).toMatchObject({ kind: "return", value: irReg("rax", 8) });
  });

  it("does not return a value the return register no longer holds", () => {
    // t64 sub_140001514's epilogue. RegState still mapped RAX to reg(RBX)
    // when the `ret` was reached, so the lifter emitted `return rbx` — by then
    // the *restored* RBX, i.e. the saved-register slot. Naming RAX binds the
    // read to the definition that actually reaches the `ret` (peek-a-bin-lh6).
    const stmts = lift([
      ["mov", "rax, rbx"],
      ["mov", "rbx, qword ptr [rsp + 0x30]"],
      ["ret", ""],
    ]);
    expect(stmts[2]).toEqual({
      kind: "return",
      value: irReg("rax", 8),
      addr: START + 2 * SIZE,
    });
  });

  it("returns the bare return register when nothing is tracked", () => {
    expect(liftOne("ret", "")).toEqual({ kind: "return", value: irReg("rax", 8), addr: START });
    expect(lift([["retn", "0x8"]], { is64: false })[0]).toMatchObject({ value: irReg("eax", 4) });
  });

  // KNOWN BUG (reported, not fixed): `pop` is skipped entirely, so it never
  // clears the popped register's definition. A value moved into a register
  // before it is popped survives and folds into everything downstream.
  // KNOWN BUG (reported, not fixed): `pop` is not lifted at all, so the last
  // IR definition of RAX is still the `mov` above it. The `ret` no longer
  // carries the stale value itself — it names RAX — but nothing tells SSA that
  // the pop redefined it, so the read still resolves to the wrong definition.
  it("does not see a pop redefine the register it pops into", () => {
    const stmts = lift([
      ["mov", "rax, 0x5"],
      ["pop", "rax"],
      ["ret", ""],
    ]);
    expect(stmts).toHaveLength(2); // the pop lifted to nothing
    expect(stmts[0]).toMatchObject({ dest: irReg("rax", 8), src: irConst(5, 8) });
    expect(stmts[1]).toEqual({ kind: "return", value: irReg("rax", 8), addr: START + 2 * SIZE });
  });
});

describe("liftBlock — string, FPU and SSE", () => {
  it("lifts `rep movs` to memcpy", () => {
    expect(liftOne("rep", "movsb")).toMatchObject({
      kind: "call_stmt",
      call: { target: "memcpy", args: [irReg("rdi", 8), irReg("rsi", 8), irReg("rcx", 8)] },
    });
  });

  it("lifts `rep stos` to memset", () => {
    expect(liftOne("rep", "stosb")).toMatchObject({
      kind: "call_stmt",
      call: { target: "memset", args: [irReg("rdi", 8), irReg("al", 1), irReg("rcx", 8)] },
    });
  });

  it("uses the 32-bit registers for string ops in x86 mode", () => {
    expect(liftOne("rep", "movsd", { is64: false })).toMatchObject({
      call: { args: [irReg("edi", 4), irReg("esi", 4), irReg("ecx", 4)] },
    });
  });

  // KNOWN BUG (reported, not fixed): Capstone emits the prefix as part of the
  // mnemonic ("rep movsb" with an empty operand string). Neither branch of the
  // rep check matches that shape, so the memcpy/memset idiom never fires on
  // real disassembly and the instruction is emitted as inline asm.
  it("does not recognise the prefix when it is part of the mnemonic", () => {
    expect(liftOne("rep movsb", "")).toEqual({
      kind: "raw",
      text: "__asm { rep movsb  }",
      addr: START,
    });
  });

  it("lifts fld and fstp through the x87 stack top", () => {
    const st = new RegState();
    expect(liftOne("fld", "dword ptr [rbp - 0x4]", { state: st })).toMatchObject({
      dest: irReg("st0", 10),
    });
    expect(st.get("st0")).toEqual(irDeref(irBinary("-", irReg("rbp", 8), irConst(4, 8)), 4));
  });

  it("stores the x87 stack top to memory", () => {
    const st = new RegState();
    st.set("st0", irConst(1));
    expect(liftOne("fstp", "dword ptr [rbp - 0x4]", { state: st })).toMatchObject({
      kind: "store",
      value: irReg("st0", 10),
      size: 4,
    });
  });

  it("lifts x87 arithmetic against the stack top", () => {
    const st = new RegState();
    st.set("st0", irConst(2));
    expect(liftOne("fadd", "dword ptr [rax]", { state: st })).toMatchObject({
      dest: irReg("st0", 10),
      src: irBinary("+", irReg("st0", 10), irDeref(irReg("rax", 8), 4)),
    });
    expect(liftOne("fdiv", "dword ptr [rax]", { state: st })).toMatchObject({ src: { op: "/" } });
  });

  it("lifts scalar SSE moves and arithmetic", () => {
    expect(liftOne("movss", "xmm0, dword ptr [rax]")).toMatchObject({
      kind: "assign",
      dest: irReg("xmm0", 16),
    });
    expect(liftOne("addsd", "xmm0, xmm1")).toMatchObject({
      src: irBinary("+", irReg("xmm0", 16), irReg("xmm1", 16)),
    });
    expect(liftOne("mulss", "xmm0, xmm1")).toMatchObject({ src: { op: "*" } });
  });

  it("lifts an SSE move to memory as a store", () => {
    expect(liftOne("movsd", "qword ptr [rbp - 0x8], xmm0")).toMatchObject({
      kind: "store",
      size: 8,
    });
  });

  it("records the flag state for an SSE comparison and emits no statement", () => {
    const st = new RegState();
    expect(lift([["comisd", "xmm0, xmm1"]], { state: st })).toEqual([]);
    expect(st.getCondition("ja")).toEqual(irBinary("u>", irReg("xmm0", 16), irReg("xmm1", 16)));
  });
});

describe("liftBlock — fallback", () => {
  it("emits inline asm for an unmodelled instruction", () => {
    expect(liftOne("vpxor", "ymm0, ymm0, ymm0")).toEqual({
      kind: "raw",
      text: "__asm { vpxor ymm0, ymm0, ymm0 }",
      addr: START,
    });
  });

  it("emits inline asm for a privileged instruction", () => {
    expect(liftOne("cpuid", "")).toEqual({ kind: "raw", text: "__asm { cpuid  }", addr: START });
  });

  it("lifts an empty block to no statements", () => {
    expect(lift([])).toEqual([]);
  });

  it("keeps the source address on every statement", () => {
    const stmts = lift([
      ["mov", "rax, 0x1"],
      ["add", "rax, 0x1"],
      ["ret", ""],
    ]);
    expect(stmts.map((s) => (s as { addr?: number }).addr)).toEqual([
      START,
      START + SIZE,
      START + 2 * SIZE,
    ]);
  });

  it("splits operands on commas outside brackets only", () => {
    // `[rax + rcx*4]` contains no comma, but SIB text with one must not split.
    expect(liftOne("mov", "qword ptr [rax + rcx*4], rbx")).toMatchObject({ kind: "store" });
  });
});

/**
 * The evidence behind `collectArgs32`'s save rule: the lowest address at which
 * each x86 callee-saved register is written. Every case here is a shape the
 * scan gets wrong in one of the two directions — a missed write drops a
 * genuine argument, an invented one re-admits a prologue save as an argument.
 */
describe("firstCalleeSavedWrites", () => {
  const writes = (list: [string, string][]) => firstCalleeSavedWrites([blockOf(list)]);

  it("records the address of an ordinary destination write", () => {
    expect(
      writes([
        ["push", "esi"],
        ["mov", "esi, 1"],
      ]).get("rsi"),
    ).toBe(START + SIZE);
  });

  it("keeps the LOWEST address when a register is written more than once", () => {
    expect(
      writes([
        ["mov", "esi, 1"],
        ["mov", "esi, 2"],
      ]).get("rsi"),
    ).toBe(START);
  });

  it("does not read MSVC's `mov edi, edi` hot-patch pad as a definition", () => {
    // It is the entry instruction of two of the four t32 over-counting sites.
    expect(
      writes([
        ["mov", "edi, edi"],
        ["push", "edi"],
      ]).has("rdi"),
    ).toBe(false);
  });

  it("reads `xor esi, esi` as the zeroing it is, not as a self-move", () => {
    // The hot-patch exception is `mov`-only. Generalised to any two-operand
    // instruction with equal operands it swallows the commonest definition
    // there is, and t32.exe's four `Sleep(esi)` calls lose their argument.
    expect(writes([["xor", "esi, esi"]]).get("rsi")).toBe(START);
  });

  it("records a write through a sub-register under the canonical name", () => {
    expect(writes([["mov", "bl, 1"]]).get("rbx")).toBe(START);
  });

  it("does not treat a read-only first operand as a write", () => {
    expect(
      writes([
        ["push", "esi"],
        ["cmp", "esi, 1"],
        ["test", "edi, edi"],
      ]).size,
    ).toBe(0);
  });

  it("does not treat one-operand `div` as a write of its operand", () => {
    // `div ebx` reads EBX and writes EDX:EAX. `imul ebx, ecx` does write EBX.
    expect(writes([["div", "ebx"]]).has("rbx")).toBe(false);
    expect(writes([["imul", "ebx, ecx"]]).get("rbx")).toBe(START);
  });

  it("does not treat a store THROUGH a register as a write OF it", () => {
    expect(writes([["mov", "dword ptr [esi], 1"]]).has("rsi")).toBe(false);
  });

  it("records `pop`, `lea` and `xchg`", () => {
    expect(writes([["pop", "ebp"]]).get("rbp")).toBe(START);
    expect(writes([["lea", "esi, [eax + 2]"]]).get("rsi")).toBe(START);
    expect(writes([["xchg", "eax, ebx"]]).get("rbx")).toBe(START);
  });

  it("records the EBP write `leave` performs without naming an operand", () => {
    expect(writes([["leave", ""]]).get("rbp")).toBe(START);
  });

  it("records the ESI/EDI a string instruction advances", () => {
    const m = writes([["rep movsd", "dword ptr es:[edi], dword ptr [esi]"]]);
    expect(m.get("rsi")).toBe(START);
    expect(m.get("rdi")).toBe(START);
  });

  it("does not read SSE `movsd` as the string instruction of the same name", () => {
    expect(writes([["movsd", "xmm0, qword ptr [eax]"]]).size).toBe(0);
  });

  it("ignores registers that are not callee-saved", () => {
    // EAX and ECX carry results and __fastcall arguments; the entry-value
    // argument for treating a push as a save does not hold for them.
    expect(
      writes([
        ["mov", "eax, 1"],
        ["mov", "ecx, 2"],
      ]).size,
    ).toBe(0);
  });

  it("spans every block of the function, not just one", () => {
    const b0 = blockOf([["mov", "esi, 1"]]);
    const b1 = { ...blockOf([["push", "esi"]]), id: 1, startAddr: 0x402000 };
    b1.insns = [insn("push", "esi", 0x402000)];
    expect(firstCalleeSavedWrites([b1, b0]).get("rsi")).toBe(START);
  });
});

/**
 * `push <imm>` / `pop <reg>` split across a branch.
 *
 * `pushedImmediate` is handed one block, so it answers nothing when the push is
 * in a predecessor — and the `pop` is then no definition in SSA, which is
 * `peek-a-bin-3axd`'s wrong-value defect one block further out. The answer has to
 * be a set of definitions, one per predecessor, because the real shape in this
 * corpus is a **phi of different immediates**: MSVC selects a character across an
 * `if`/`else if` chain and pops it once (t32 0x404f4c pops `0x2d`/`0x2b`/`0x20`).
 *
 * Every refusal below is asking one question — is the register's old value
 * provably dead on the edge? — and the tests are written against the shapes the
 * corpus supplies rather than against the implementation's branch order.
 */
describe("crossBlockPopImmediates", () => {
  /** A block at an explicit id/address, with explicit edges. */
  function blk(
    id: number,
    addr: number,
    list: [string, string?][],
    edges: { succs?: number[]; preds?: number[] } = {},
  ): BasicBlock {
    return {
      id,
      startAddr: addr,
      endAddr: addr + list.length * SIZE,
      insns: list.map(([m, o], i) => insn(m, o ?? "", addr + i * SIZE)),
      succs: edges.succs ?? [],
      preds: edges.preds ?? [],
    };
  }

  /**
   * t32 0x404f4c, cut down to two arms: two predecessors each pushing a
   * different immediate, one `pop` at the join. `p0` reaches the join through a
   * `jmp` and `p1` by falling through, which is exactly how MSVC lays it out.
   */
  function twoArm(imm0: string, imm1: string): BasicBlock[] {
    return [
      blk(
        0,
        0x401000,
        [
          ["push", imm0],
          ["jmp", "0x401100"],
        ],
        { succs: [2] },
      ),
      blk(1, 0x401080, [["push", imm1]], { succs: [2] }),
      blk(
        2,
        0x401100,
        [
          ["pop", "ecx"],
          ["mov", "dword ptr [eax], ecx"],
        ],
        { preds: [0, 1] },
      ),
    ];
  }

  it("defines the register in every predecessor, once per pushed immediate", () => {
    const defs = crossBlockPopImmediates(twoArm("0x2d", "0x20"));

    expect(defs.map((d) => [d.blockId, d.imm, d.reg])).toEqual([
      [0, 0x2d, "ecx"],
      [1, 0x20, "ecx"],
    ]);
    // The POP's address, not either push's: `liftBlock`'s block-local form does
    // the same, so one pair cannot be attributed to two instructions depending
    // on where the push landed, and `corpus/popReads.ts` finds it there.
    expect(new Set(defs.map((d) => d.addr))).toEqual(new Set([0x401100]));
  });

  // The immediates differing is the whole point. A rule of the shape "every
  // predecessor pushes the SAME constant, therefore assign it at the pop" would
  // describe not one site in this corpus — t32 0x4077f3 is MSVC's CR/LF pair.
  it("does not require the predecessors to agree on the immediate", () => {
    expect(crossBlockPopImmediates(twoArm("0xd", "0xa")).map((d) => d.imm)).toEqual([0xd, 0xa]);
  });

  // ALL of them or none. Defining the register on some incoming edges and not
  // others is worse than defining it on none: the phi's other operand is the
  // stale value the rule exists to remove, so the output reads as recovered
  // while being wrong on one path.
  it("refuses when any predecessor does not push an immediate", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[1] = blk(1, 0x401080, [["mov", "ebx, 1"]], { succs: [2] });

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });

  // The definition is appended to the predecessor, so it reaches every successor
  // of it. `push 0xd / je <pop>` would define the register on the fallthrough
  // path too, where the pop never runs.
  //
  // The tail here is an INDIRECT `jmp` — a recovered jump table's dispatch, the
  // one real shape with many successors and an unconditional terminator — so the
  // conditional-tail refusal below cannot fire and this isolates the successor
  // rule. Written that way deliberately: with a `je` tail both refusals reject
  // the fixture and relaxing either one alone still passes.
  it("refuses a predecessor with a second successor", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[0] = blk(
      0,
      0x401000,
      [
        ["push", "0x2d"],
        ["jmp", "dword ptr [eax*4 + 0x40f0a8]"],
      ],
      {
        succs: [2, 3],
      },
    );

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });

  // Implied by the successor test for any CFG that lists both edges, and asked
  // of the machine text anyway: `pushBeforeTerminator` places the definition
  // BEFORE an `IRBranch`, so a guard reading the same register would read the
  // new value one instruction early. Two edges drawn to one block is the shape
  // where the successor test alone could let that through.
  it("refuses a predecessor ending in a conditional jump", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[0] = blk(
      0,
      0x401000,
      [
        ["push", "0x2d"],
        ["jne", "0x401100"],
      ],
      { succs: [2] },
    );

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });

  // The definition arrives on the edge, so anything in the pop's own block
  // ahead of the pop would read it early. Requiring the pop to lead its block
  // answers that structurally instead of with a second register-liveness
  // grammar — and it costs nothing measurable: of the 53 and 50 non-leader pops
  // on t32/w32 whose prefix touches neither the stack nor the register, 0 would
  // have paired anyway (measured at 6d5ae92).
  it("refuses a pop that is not its block's first instruction", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[2] = blk(
      2,
      0x401100,
      [
        ["mov", "edx, ecx"],
        ["pop", "ecx"],
      ],
      { preds: [0, 1] },
    );

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });

  // A block the unwinder enters has no predecessor at all — an MSVC `__except`
  // continuation, which `structureCFG` does emit (peek-a-bin-d3z). This pins the
  // BEHAVIOUR and not a branch: the loop over predecessors produces nothing for
  // such a block, so there is deliberately no early exit to delete. Measured —
  // adding one back is a branch no test can make fail.
  it("refuses a pop in a block with no predecessors", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[2] = { ...blocks[2], preds: [] };

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });

  // Depth is still `stackIdiom.ts`'s question, asked of the predecessor's tail.
  // A `jmp` is neither stack traffic nor an `esp` mention, which is why the
  // `push 0x2d / jmp` shape pairs; an `add esp, 4` is the pairing being one slot
  // out.
  it("refuses across a stack-pointer move in the predecessor's tail", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[0] = blk(
      0,
      0x401000,
      [
        ["push", "0x2d"],
        ["add", "esp, 4"],
        ["jmp", "0x401100"],
      ],
      {
        succs: [2],
      },
    );

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });

  // t32 0x401a79 is `push 0x22 / add eax, 0x4 / pop ecx`: MSVC schedules an
  // unrelated instruction after the push, and requiring adjacency would refuse
  // one of the six real sites.
  it("pairs across an instruction that does not touch the stack", () => {
    const blocks = twoArm("0x20", "0x22");
    blocks[1] = blk(
      1,
      0x401080,
      [
        ["push", "0x22"],
        ["add", "eax, 0x4"],
      ],
      { succs: [2] },
    );

    expect(crossBlockPopImmediates(blocks).map((d) => d.imm)).toEqual([0x20, 0x22]);
  });

  // `push 8 / pop esp` really does set ESP, and it is refused for
  // `liftBlock`'s reason: ESP is the one register no stage here models, so a
  // definition of it would be read by the frame analysis as a value it can move.
  it("refuses a pop of the stack pointer", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[2] = blk(2, 0x401100, [["pop", "esp"]], { preds: [0, 1] });

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });

  // A push of a REGISTER is a copy this rule cannot state. That is the
  // save/restore class and it is peek-a-bin-6f3v, deliberately out of scope.
  it("refuses a pushed register", () => {
    const blocks = twoArm("0x2d", "0x20");
    blocks[0] = blk(
      0,
      0x401000,
      [
        ["push", "ebx"],
        ["jmp", "0x401100"],
      ],
      { succs: [2] },
    );

    expect(crossBlockPopImmediates(blocks)).toEqual([]);
  });
});

/**
 * The placement rule, which is the half of this that `crossBlockPopImmediates`
 * cannot state: a definition appended to another block's statement list must
 * stay ahead of that block's terminator.
 *
 * `pushBeforeTerminator` exists because a plain `push` lands the definition
 * AFTER the `IRBranch`, i.e. after the guard that may read the register — the
 * defect `destroySSA` and `loopInvariantCodeMotion` both hit. The conditional
 * predecessor is refused outright here, so this can only be reached by a
 * single-successor block whose CFG lists one edge for a two-edge jump; keeping
 * the placement correct means that shape degrades to noise rather than to a read
 * preceding its own definition.
 */
describe("liftCrossBlockPops", () => {
  function blk(
    id: number,
    addr: number,
    list: [string, string?][],
    edges: { succs?: number[]; preds?: number[] } = {},
  ): BasicBlock {
    return {
      id,
      startAddr: addr,
      endAddr: addr + list.length * SIZE,
      insns: list.map(([m, o], i) => insn(m, o ?? "", addr + i * SIZE)),
      succs: edges.succs ?? [],
      preds: edges.preds ?? [],
    };
  }

  it("appends the definition to each pushing predecessor", () => {
    const blocks = [
      blk(
        0,
        0x401000,
        [
          ["push", "0x2d"],
          ["jmp", "0x401100"],
        ],
        { succs: [1] },
      ),
      blk(1, 0x401100, [["pop", "ecx"]], { preds: [0] }),
    ];
    const lifted = new Map<number, IRStmt[]>([
      [0, []],
      [1, []],
    ]);

    liftCrossBlockPops(blocks, lifted);

    expect(lifted.get(0)).toEqual([
      { kind: "assign", dest: irReg("ecx"), src: irConst(0x2d, 4), addr: 0x401100 },
    ]);
    expect(lifted.get(1)).toEqual([]);
  });

  it("keeps the definition ahead of the predecessor's terminator", () => {
    const blocks = [
      blk(
        0,
        0x401000,
        [
          ["push", "0x2d"],
          ["jmp", "0x401100"],
        ],
        { succs: [1] },
      ),
      blk(1, 0x401100, [["pop", "ecx"]], { preds: [0] }),
    ];
    const branch: IRStmt = {
      kind: "branch",
      condition: irConst(1),
      jcc: "jne",
      target: 0x401100,
      addr: 0x401004,
    };
    const lifted = new Map<number, IRStmt[]>([
      [0, [branch]],
      [1, []],
    ]);

    liftCrossBlockPops(blocks, lifted);

    const stmts = lifted.get(0) as IRStmt[];
    expect(stmts).toHaveLength(2);
    expect(stmts[0].kind).toBe("assign");
    expect(stmts[1]).toBe(branch);
  });
});
