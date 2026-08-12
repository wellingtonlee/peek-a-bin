import { describe, it, expect } from "vitest";
import { liftBlock, parseOperand } from "../lifter";
import { RegState } from "../regstate";
import { irBinary, irConst, irDeref, irReg, irUnary, irUnknown } from "../ir";
import type { IRExpr, IRStmt } from "../ir";
import type { Instruction } from "../../types";
import type { BasicBlock } from "../../cfg";

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

  it("drops jumps — control flow is handled by the structurer", () => {
    expect(
      lift([
        ["jmp", "0x401100"],
        ["je", "0x401100"],
        ["jne", "0x401100"],
      ]),
    ).toEqual([]);
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
  it("emits an eflags definition for cmp", () => {
    const st = new RegState();
    expect(liftOne("cmp", "eax, 0x0", { state: st })).toEqual({
      kind: "assign",
      dest: irReg("eflags", 4),
      src: irBinary("-", irReg("eax", 4), irConst(0, 8)),
      addr: START,
    });
    expect(st.getCondition("je")).toEqual(irBinary("==", irReg("eax", 4), irConst(0, 8)));
  });

  it("emits a bitwise-and eflags definition for test", () => {
    const st = new RegState();
    expect(liftOne("test", "eax, eax", { state: st })).toMatchObject({
      src: irBinary("&", irReg("eax", 4), irReg("eax", 4)),
    });
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
    expect(stmts[1]).toEqual({
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
    expect(stmts[1]).toEqual({
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

  // KNOWN BUG (reported, not fixed): collectArgs64 looks the arguments up under
  // 'rcx'/'rdx'/'r8'/'r9', but the lifter keys definitions by the literal
  // operand text. Setting up an argument with a 32-bit move — the normal way to
  // pass an int — leaves the definition under 'ecx', so the call is emitted
  // with no arguments at all.
  it("misses x64 arguments set up through 32-bit sub-registers", () => {
    const stmts = lift([
      ["mov", "ecx, 0x1"],
      ["mov", "edx, 0x2"],
      ["call", "0x402000"],
    ]);
    expect((stmts[2] as { call: { args: IRExpr[] } }).call.args).toEqual([]); // should be [1, 2]
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

  it("lifts an SSE comparison to an eflags definition", () => {
    const st = new RegState();
    expect(liftOne("comisd", "xmm0, xmm1", { state: st })).toMatchObject({
      dest: irReg("eflags", 4),
    });
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
