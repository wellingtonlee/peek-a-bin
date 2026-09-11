import { describe, expect, it } from "vitest";
import type { CalleeClobbers } from "../../callSummary";
import type { BasicBlock } from "../../cfg";
import type { CrtIdiom } from "../../crtIdioms";
import type { Instruction } from "../../types";
import type { IRExpr, IRStmt } from "../ir";
import { irBinary, irConst, irDeref, irReg, irUnary, irUnknown, irVar } from "../ir";
import {
  crossBlockPopImmediates,
  firstCalleeSavedWrites,
  liftBlock,
  liftCrossBlockPops,
  matchedStackSlots,
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
  /** Per-callee facts from `callSummary.ts`, including the CRT idiom map. */
  clobbers?: CalleeClobbers;
  /** For a tail-jump fixture: a block with no successors. */
  succs?: number[];
}

function lift(list: [string, string][], opts: LiftOpts = {}): IRStmt[] {
  const block = blockOf(list);
  if (opts.succs) block.succs = opts.succs;
  return liftBlock(
    block,
    opts.state ?? new RegState(),
    opts.is64 ?? true,
    opts.iat ?? new Map(),
    new Map(),
    opts.funcs ?? new Map(),
    undefined,
    opts.clobbers,
  );
}

/** The last statement a fixture lifted to. */
function lastOf(stmts: IRStmt[]): IRStmt {
  return stmts[stmts.length - 1];
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

  // One-operand `imul` is the signed widening multiply into the accumulator
  // pair — the `mul` shape with signed casts on both operands (peek-a-bin-5b6q.3).
  it("lifts one-operand imul as the signed widening multiply, high half first", () => {
    const cast = (e: IRExpr, type: string): IRExpr => ({ kind: "cast", type, operand: e });
    const product = irBinary(
      "*",
      cast(irReg("eax", 4), "int32_t"),
      cast(irReg("ecx", 4), "int32_t"),
    );
    const stmts = lift([["imul", "ecx"]]);
    expect(stmts).toEqual([
      {
        kind: "assign",
        dest: irReg("edx"),
        src: irBinary(">>", product, irConst(32)),
        addr: START,
      },
      { kind: "assign", dest: irReg("eax"), src: product, addr: START },
    ]);
    expect(lift([["imul", "rcx"]])[1]).toMatchObject({
      dest: irReg("rax", 8),
      src: { op: "*", left: { kind: "cast", type: "int64_t" } },
    });
  });

  it("widens a byte multiply into AX alone", () => {
    // `AL * r/m8` lands in AX; there is no high register to order.
    expect(lift([["imul", "cl"]])).toEqual([
      {
        kind: "assign",
        dest: irReg("ax", 2),
        src: irBinary(
          "*",
          { kind: "cast", type: "int8_t", operand: irReg("al", 1) },
          { kind: "cast", type: "int8_t", operand: irReg("cl", 1) },
        ),
        addr: START,
      },
    ]);
    expect(lift([["mul", "cl"]])).toEqual([
      {
        kind: "assign",
        dest: irReg("ax", 2),
        src: irBinary("*", irReg("al", 1), irReg("cl", 1)),
        addr: START,
      },
    ]);
  });

  it("routes a widening multiply through a temporary when the source is the high register", () => {
    // `imul rdx`: writing RDX first destroys the operand the low half then
    // reads, so both halves are taken from one temporary. Two of the six
    // corpus sites have this shape.
    const stmts = lift([["imul", "rdx"]]);
    expect(stmts).toHaveLength(3);
    expect(stmts[0]).toMatchObject({ kind: "assign", dest: irReg("tmp_mul", 8), src: { op: "*" } });
    expect(stmts[1]).toEqual({
      kind: "assign",
      dest: irReg("rdx"),
      src: irBinary(">>", irReg("tmp_mul", 8), irConst(64)),
      addr: START,
    });
    expect(stmts[2]).toEqual({
      kind: "assign",
      dest: irReg("rax"),
      src: irReg("tmp_mul", 8),
      addr: START,
    });
    // A memory source addressed through the high register is the same case.
    expect(lift([["mul", "dword ptr [edx]"]])[0]).toMatchObject({ dest: irReg("tmp_mul", 4) });
    // …and the plain shape stays two statements.
    expect(lift([["mul", "ecx"]])).toHaveLength(2);
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

  const cast = (type: string, e: IRExpr): IRExpr => ({ kind: "cast", type, operand: e });

  it("lifts div into a quotient and a remainder over the original dividend", () => {
    // One instruction writes both halves from the same input, so the statement
    // that overwrites the dividend must come second — EDX first. Emitting EAX
    // first made the remainder read the quotient: `edx = (eax / ecx) % ecx`.
    // The `xor edx, edx` is the high-half setup the lift now requires
    // (peek-a-bin-5b6q.3); the operands carry the unsigned casts of their width.
    const st = new RegState();
    st.set("eax", irConst(100));
    const stmts = lift(
      [
        ["xor", "edx, edx"],
        ["div", "ecx"],
      ],
      { state: st },
    );
    const u = (r: string) => cast("uint32_t", irReg(r, 4));
    expect(stmts[1]).toEqual({
      kind: "assign",
      dest: irReg("edx", 4),
      src: irBinary("%", u("eax"), u("ecx")),
      addr: START + SIZE,
    });
    expect(stmts[2]).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: irBinary("/", u("eax"), u("ecx")),
      addr: START + SIZE,
    });
  });

  it("falls back to raw asm for div with no operand", () => {
    expect(liftOne("div", "")).toEqual({ kind: "raw", text: "__asm { div  }", addr: START });
  });

  // div/idiv: the IR spells the dividend as its LOW half, which is a wrong value
  // unless the high half really was that half's extension — zero for `div`,
  // sign for `idiv`. The lift is admitted only where the stream shows the
  // matching setup, and refused (raw, counted) otherwise (peek-a-bin-5b6q.3).
  it("lifts idiv with signed casts after the sign-extension of its width", () => {
    const s32 = (r: string) => cast("int32_t", irReg(r, 4));
    expect(
      lift([
        ["cdq", ""],
        ["idiv", "ecx"],
      ])[2],
    ).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: irBinary("/", s32("eax"), s32("ecx")),
      addr: START + SIZE,
    });
    expect(
      lift([
        ["cqo", ""],
        ["idiv", "rcx"],
      ])[2],
    ).toMatchObject({
      dest: irReg("rax", 8),
      src: irBinary("/", cast("int64_t", irReg("rax", 8)), cast("int64_t", irReg("rcx", 8))),
    });
    expect(
      lift([
        ["cwd", ""],
        ["idiv", "cx"],
      ])[2],
    ).toMatchObject({
      dest: irReg("ax", 2),
      src: irBinary("/", cast("int16_t", irReg("ax", 2)), cast("int16_t", irReg("cx", 2))),
    });
    // A memory divisor carries the cast too.
    expect(
      lift([
        ["xor", "edx, edx"],
        ["div", "dword ptr [esi]"],
      ])[2],
    ).toMatchObject({
      src: { op: "/", right: { kind: "cast", type: "uint32_t", operand: { kind: "deref" } } },
    });
  });

  it("refuses a division whose high half was not set up to match — raw, never a wrong value", () => {
    const raw = (list: [string, string][]) => {
      const last = lastOf(lift(list));
      expect(last).toMatchObject({ kind: "raw" });
      expect((last as { text: string }).text).toMatch(/^__asm \{ i?div /);
    };
    // No setup in the stream at all.
    raw([["div", "ecx"]]);
    raw([
      ["mov", "eax, ecx"],
      ["idiv", "esi"],
    ]);
    // The setup of the OTHER signedness: a `div` after `cdq` divides a huge
    // dividend when EAX is negative; an `idiv` after `xor edx, edx` divides a
    // large positive one when EAX is past 2^31.
    raw([
      ["cdq", ""],
      ["div", "ecx"],
    ]);
    raw([
      ["xor", "edx, edx"],
      ["idiv", "ecx"],
    ]);
    // A sign-extension at another width is a WRITE of the high half.
    raw([
      ["cqo", ""],
      ["idiv", "ecx"],
    ]);
    // Something wrote the high half between the setup and the divide.
    raw([
      ["xor", "edx, edx"],
      ["mov", "edx, ecx"],
      ["div", "esi"],
    ]);
    raw([
      ["xor", "edx, edx"],
      ["call", "0x401100"],
      ["div", "esi"],
    ]);
    raw([
      ["xor", "edx, edx"],
      ["pop", "rdx"],
      ["div", "rsi"],
    ]);
    raw([
      ["xor", "edx, edx"],
      ["xchg", "rcx, rdx"],
      ["div", "rsi"],
    ]);
    // A 16-bit zeroing does not zero EDX.
    raw([
      ["xor", "dx, dx"],
      ["div", "ecx"],
    ]);
    // The byte form's high half is AH; refused outright.
    raw([
      ["xor", "edx, edx"],
      ["div", "cl"],
    ]);
  });

  it("steps over instructions that do not write the high half, and accepts every zeroing spelling", () => {
    // The corpus's commonest shape: the setup is two instructions back.
    expect(
      lift([
        ["xor", "edx, edx"],
        ["lea", "rax, [rdx-0x20]"],
        ["div", "rcx"],
      ]),
    ).toHaveLength(4);
    expect(
      lift([
        ["xor", "edx, edx"],
        ["mov", "eax, ecx"],
        ["div", "esi"],
      ]),
    ).toHaveLength(4);
    // A 32-bit zeroing zero-extends into RDX, so it sets up a 64-bit divide.
    expect(
      lastOf(
        lift([
          ["xor", "edx, edx"],
          ["mov", "rax, rbx"],
          ["div", "rcx"],
        ]),
      ),
    ).toMatchObject({
      kind: "assign",
      dest: irReg("rax"),
    });
    for (const zero of [
      ["sub", "edx, edx"],
      ["mov", "edx, 0"],
      ["and", "edx, 0"],
      ["xor", "rdx, rdx"],
    ] as [string, string][]) {
      expect(lastOf(lift([zero, ["div", "ecx"]]))).toMatchObject({
        kind: "assign",
        dest: irReg("eax"),
      });
    }
    // A two-operand imul writes only its destination, so it is stepped over…
    expect(
      lastOf(
        lift([
          ["xor", "edx, edx"],
          ["imul", "eax, ecx"],
          ["div", "esi"],
        ]),
      ),
    ).toMatchObject({
      kind: "assign",
    });
    // …where the one-operand form writes EDX and refuses.
    expect(
      lastOf(
        lift([
          ["xor", "edx, edx"],
          ["imul", "ecx"],
          ["div", "esi"],
        ]),
      ),
    ).toMatchObject({
      kind: "raw",
    });
  });

  // rol/ror are shifts and ors over the destination's width (peek-a-bin-5b6q.3).
  it("lifts rol/ror by an immediate as shifts and ors over the width", () => {
    expect(liftOne("rol", "eax, 0x8")).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: irBinary(
        "|",
        irBinary("<<", irReg("eax", 4), irConst(8, 4)),
        irBinary(">>>", irReg("eax", 4), irConst(24, 4)),
      ),
      addr: START,
    });
    expect(liftOne("ror", "rcx, 0x10")).toMatchObject({
      dest: irReg("rcx", 8),
      src: irBinary(
        "|",
        irBinary(">>>", irReg("rcx", 8), irConst(16, 8)),
        irBinary("<<", irReg("rcx", 8), irConst(48, 8)),
      ),
    });
  });

  it("reduces the rotate count the way the machine does, and refuses a no-op", () => {
    // SDM: the count is masked to 5 bits, then the rotation is modulo the width.
    expect(liftOne("rol", "al, 0x9")).toMatchObject({
      src: irBinary(
        "|",
        irBinary("<<", irReg("al", 1), irConst(1, 1)),
        irBinary(">>>", irReg("al", 1), irConst(7, 1)),
      ),
    });
    // A rotation by the full width is a no-op the compiler never emits; refused
    // rather than spelled as a self-assignment.
    expect(liftOne("rol", "eax, 0x20")).toEqual({
      kind: "raw",
      text: "rol eax, 0x20",
      addr: START,
    });
  });

  it("spells a cl count masked to the width, and its complement masked too", () => {
    // `(W - cl) & (W-1)`, never `W - cl`: at cl == 0 that is a shift by the
    // full width, undefined in C.
    const cl = irReg("cl", 1);
    expect(liftOne("rol", "eax, cl")).toMatchObject({
      src: irBinary(
        "|",
        irBinary("<<", irReg("eax", 4), irBinary("&", cl, irConst(31, 4))),
        irBinary(
          ">>>",
          irReg("eax", 4),
          irBinary("&", irBinary("-", irConst(32, 4), cl), irConst(31, 4)),
        ),
      ),
    });
    // Any other register count is not an encoding; refused.
    expect(liftOne("rol", "eax, dl")).toMatchObject({ kind: "raw" });
  });

  it("lifts a rotate of memory as a store, and leaves rcl/rcr raw", () => {
    expect(liftOne("ror", "dword ptr [ecx+0x8], 1")).toMatchObject({ kind: "store", size: 4 });
    // rcl/rcr rotate through CF once per iteration; CF is spelled for one
    // setter at a time here, so they stay unlifted.
    expect(liftOne("rcr", "eax, 1")).toMatchObject({ kind: "raw" });
    expect(liftOne("rcl", "eax, 1")).toMatchObject({ kind: "raw" });
  });

  it("lifts bswap as the MSVC intrinsic of its width, and refuses the undefined 16-bit form", () => {
    expect(liftOne("bswap", "eax")).toEqual({
      kind: "assign",
      dest: irReg("eax", 4),
      src: { kind: "call", target: "_byteswap_ulong", args: [irReg("eax", 4)] },
      addr: START,
    });
    expect(liftOne("bswap", "rax")).toMatchObject({
      src: { kind: "call", target: "_byteswap_uint64", args: [irReg("rax", 8)] },
    });
    // SDM: the result of a 16-bit bswap is undefined.
    expect(liftOne("bswap", "ax")).toEqual({ kind: "raw", text: "bswap ax", addr: START });
  });

  it("lifts movnti as a plain store", () => {
    expect(liftOne("movnti", "qword ptr [rcx-0x8], rdx")).toEqual({
      kind: "store",
      address: irBinary("-", irReg("rcx", 8), irConst(8, 8)),
      value: irReg("rdx", 8),
      size: 8,
      addr: START,
    });
    // Register destination is not an encoding.
    expect(liftOne("movnti", "rax, rdx")).toMatchObject({ kind: "raw" });
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

  // Every `setcc` form goes through the Jcc table — `set<cc>` is dispatched as
  // `j<cc>` — so the forms the fourteen-entry `COND_SET` never named are lifted
  // exactly as the Jcc would be (peek-a-bin-5b6q.3).
  it("lifts every setcc form through the same table as the Jcc", () => {
    const lifted = (mn: string) =>
      lift([
        ["cmp", "ecx, edx"],
        [mn, "al"],
      ])[0];
    expect(lifted("setb")).toMatchObject({
      kind: "assign",
      dest: irReg("al", 1),
      src: irBinary("u<", irReg("ecx", 4), irReg("edx", 4)),
    });
    // Alias spellings the hand-written table did not carry.
    expect(lifted("setnbe")).toMatchObject({
      src: irBinary("u>", irReg("ecx", 4), irReg("edx", 4)),
    });
    expect(lifted("setnl")).toMatchObject({
      src: irBinary(">=", irReg("ecx", 4), irReg("edx", 4)),
    });
    expect(lifted("setc")).toMatchObject({ src: irBinary("u<", irReg("ecx", 4), irReg("edx", 4)) });
  });

  it("lifts a setcc form getCondition cannot answer as an ASSIGNMENT of unknown, never raw", () => {
    // A definition SSA sees: the destination read later binds to it instead of
    // to whatever the register held before. `raw` is a dataflow hole.
    const lifted = (setup: [string, string], mn: string) => lift([setup, [mn, "al"]])[0];
    for (const mn of ["seto", "setno", "setp", "setnp"]) {
      expect(lifted(["cmp", "ecx, edx"], mn)).toMatchObject({
        kind: "assign",
        dest: irReg("al", 1),
        src: { kind: "unknown", text: `j${mn.slice(3)} after cmp` },
      });
    }
    // `jb`/`jae` after `test` are constants, and a constant is refused rather
    // than spelled `al = 0` — the same reason `getCondition` will not emit
    // `if (1)`.
    expect(lifted(["test", "ecx, ecx"], "setb")).toMatchObject({
      kind: "assign",
      src: { kind: "unknown", text: "jb after test" },
    });
    expect(lifted(["test", "ecx, ecx"], "setae")).toMatchObject({
      kind: "assign",
      src: { kind: "unknown", text: "jae after test" },
    });
  });

  it("does not read a set-prefixed mnemonic without a condition-code suffix as a setcc", () => {
    // `setssbsy` (CET) is the one such mnemonic; it stays raw.
    expect(liftOne("setssbsy", "")).toEqual({
      kind: "raw",
      text: "__asm { setssbsy  }",
      addr: START,
    });
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

/**
 * A spoiled compare read by an in-block reader OTHER than the trailing Jcc.
 *
 * `setcc`/`cmovcc` built their conditions from `regState.getCondition` at their
 * own program point, so `cmp eax, 5 / mov eax, edx / sete al` lifted to
 * `al = (eax == 5)` AFTER `eax = edx`, and SSA bound the read to the `mov` — the
 * defect the Jcc path was cured of by materialising the compared values at the
 * compare (peek-a-bin-xe01, peek-a-bin-xskz), one reader over. `operandCaptures`
 * now asks every in-block flag reader, and the compare's flag state names the
 * captures (peek-a-bin-n9cl.6). The negative control is the first row's shape
 * with the capture disabled: it emits `al = eax == 5` below `eax = edx`.
 */
describe("liftBlock — a spoiled compare read by setcc/cmovcc", () => {
  const flg = (i: number, size: number) => irVar(`flg_${START.toString(16)}_${i}`, size);

  it("holds the compared value at the compare and builds the setcc over it", () => {
    const stmts = lift([
      ["cmp", "eax, 0x5"],
      ["mov", "eax, edx"],
      ["sete", "al"],
    ]);
    expect(stmts).toEqual([
      { kind: "assign", dest: flg(0, 4), src: irReg("eax", 4), addr: START },
      { kind: "assign", dest: irReg("eax", 4), src: irReg("edx", 4), addr: START + SIZE },
      {
        kind: "assign",
        dest: irReg("al", 1),
        src: irBinary("==", flg(0, 4), irConst(5, 8)),
        addr: START + 2 * SIZE,
      },
    ]);
  });

  it("builds a spoiled cmovcc's condition over the capture too", () => {
    const stmts = lift([
      ["cmp", "rcx, rdx"],
      ["mov", "rdx, 0x10"],
      ["cmovb", "rax, rbx"],
    ]);
    // Both non-constant operands are held, in operand order, as the Jcc rule does.
    expect(stmts[0]).toEqual({
      kind: "assign",
      dest: flg(0, 8),
      src: irReg("rcx", 8),
      addr: START,
    });
    expect(stmts[1]).toEqual({
      kind: "assign",
      dest: flg(1, 8),
      src: irReg("rdx", 8),
      addr: START,
    });
    expect(stmts[3]).toMatchObject({
      dest: irReg("rax", 8),
      src: { kind: "ternary", condition: irBinary("u<", flg(0, 8), flg(1, 8)) },
    });
  });

  it("leaves an unspoiled setcc reading the register itself", () => {
    const stmts = lift([
      ["cmp", "eax, 0x5"],
      ["mov", "ecx, edx"],
      ["sete", "al"],
    ]);
    expect(stmts).toHaveLength(2);
    expect(stmts[1]).toMatchObject({ src: irBinary("==", irReg("eax", 4), irConst(5, 8)) });
  });

  it("captures nothing for a constant operand and nothing when no reader follows", () => {
    expect(
      lift([
        ["cmp", "eax, 0x5"],
        ["mov", "eax, edx"],
      ]),
    ).toHaveLength(1);
  });
});

/**
 * CF as a VALUE (peek-a-bin-n9cl.6). `sbb`/`adc` were `raw`, and a `raw` is a
 * dataflow hole — nothing models its write — so `neg edi / sbb rax, rax / and
 * rax, rbp` returned `rax & rbp` over the RAX from before the `sbb`. The carry
 * is an EXPRESSION substituted into the consumer's right-hand side, built by
 * `carryFor` from `flagModel.ts`'s CF grammar: never a statement (the `eflags`
 * proxy's defect, peek-a-bin-c33) and never a pseudo-register. Where it cannot
 * be spelled the instruction stays `raw`, which the unlifted census counts.
 */
describe("liftBlock — sbb/adc read CF as a value", () => {
  const flg = (addr: number, i: number, size: number) =>
    irVar(`flg_${addr.toString(16)}_${i}`, size);

  it("lifts `sbb d, d` after neg to -(d != 0), MSVC's boolean idiom", () => {
    const stmts = lift([
      ["neg", "edi"],
      ["sbb", "rax, rax"],
    ]);
    expect(stmts[1]).toEqual({
      kind: "assign",
      dest: irReg("rax", 8),
      src: irUnary("-", irBinary("!=", irReg("edi", 4), irConst(0, 4))),
      addr: START + SIZE,
    });
  });

  it("spells a compare's CF as the unsigned borrow", () => {
    const stmts = lift([
      ["cmp", "ecx, eax"],
      ["sbb", "eax, eax"],
    ]);
    expect(stmts[0]).toMatchObject({
      dest: irReg("eax", 4),
      src: irUnary("-", irBinary("u<", irReg("ecx", 4), irReg("eax", 4))),
    });
  });

  it("lifts `sbb d, s` as d - s - CF and `adc d, s` as d + s + CF", () => {
    const sbb = lift([
      ["cmp", "ecx, eax"],
      ["sbb", "edx, 0x0"],
    ]);
    const borrow = irBinary("u<", irReg("ecx", 4), irReg("eax", 4));
    expect(sbb[0]).toMatchObject({
      dest: irReg("edx", 4),
      src: irBinary("-", irBinary("-", irReg("edx", 4), irConst(0, 8)), borrow),
    });
    const adc = lift([
      ["neg", "eax"],
      ["adc", "edx, esi"],
    ]);
    expect(adc[1]).toMatchObject({
      dest: irReg("edx", 4),
      src: irBinary(
        "+",
        irBinary("+", irReg("edx", 4), irReg("esi", 4)),
        irBinary("!=", irReg("eax", 4), irConst(0, 4)),
      ),
    });
  });

  it("holds a sub's destination before the sub, so the 64-bit borrow reads the value it subtracted from", () => {
    // MSVC's 64-bit subtract: the `sub` destroys the very operand its borrow is
    // a function of, so `flg_<sub>_0 = esi` goes in ABOVE `esi = esi - eax`.
    const stmts = lift([
      ["sub", "esi, eax"],
      ["sbb", "edi, edx"],
    ]);
    expect(stmts).toEqual([
      { kind: "assign", dest: flg(START, 0, 4), src: irReg("esi", 4), addr: START },
      {
        kind: "assign",
        dest: irReg("esi", 4),
        src: irBinary("-", irReg("esi", 4), irReg("eax", 4)),
        addr: START,
      },
      {
        kind: "assign",
        dest: irReg("edi", 4),
        src: irBinary(
          "-",
          irBinary("-", irReg("edi", 4), irReg("edx", 4)),
          irBinary("u<", flg(START, 0, 4), irReg("eax", 4)),
        ),
        addr: START + SIZE,
      },
    ]);
  });

  it("reads a compare through its captures when an operand was overwritten in between", () => {
    const stmts = lift([
      ["cmp", "eax, ecx"],
      ["mov", "eax, 0x5"],
      ["sbb", "edx, edx"],
    ]);
    expect(stmts[0]).toMatchObject({ dest: flg(START, 0, 4), src: irReg("eax", 4) });
    expect(stmts[1]).toMatchObject({ dest: flg(START, 1, 4), src: irReg("ecx", 4) });
    expect(stmts[3]).toMatchObject({
      dest: irReg("edx", 4),
      src: irUnary("-", irBinary("u<", flg(START, 0, 4), flg(START, 1, 4))),
    });
  });

  it("preserves CF across inc/dec, where the whole-flags owner moves", () => {
    const stmts = lift([
      ["cmp", "eax, ecx"],
      ["inc", "edx"],
      ["sbb", "ebx, ebx"],
    ]);
    expect(stmts[1]).toMatchObject({
      dest: irReg("ebx", 4),
      src: irUnary("-", irBinary("u<", irReg("eax", 4), irReg("ecx", 4))),
    });
  });

  it("chains `sbb d, d / sbb d, -1` through the first sbb's destination", () => {
    // After `sbb rax, rax`, `rax = -(CF)`, so the CF the second reads is exactly
    // `rax != 0` — nothing has to be held. MSVC's strncmp tail.
    const stmts = lift([
      ["cmp", "al, dl"],
      ["sbb", "rax, rax"],
      ["sbb", "rax, -1"],
    ]);
    expect(stmts[1]).toMatchObject({
      dest: irReg("rax", 8),
      src: irBinary(
        "-",
        irBinary("-", irReg("rax", 8), irConst(-1, 8)),
        irBinary("!=", irReg("rax", 8), irConst(0, 8)),
      ),
    });
  });

  it("REFUSES a CF it cannot spell, leaving the instruction raw", () => {
    // `add`'s carry-out is the wraparound of the addition, which this IR does
    // not model — a stated refusal, not a gap.
    expect(
      lift([
        ["add", "eax, ecx"],
        ["sbb", "ecx, ecx"],
      ])[1],
    ).toEqual({ kind: "raw", text: "sbb ecx, ecx", addr: START + SIZE });
    // A chain whose first link was refused is refused throughout: `eax` read
    // after a raw `sbb eax, eax` names the value from before it.
    const chain = lift([
      ["add", "eax, ecx"],
      ["sbb", "eax, eax"],
      ["sbb", "eax, -1"],
    ]);
    expect(chain[2]).toMatchObject({ kind: "raw", text: "sbb eax, -1" });
    // Nothing set CF; a clobber in between; a spoiled setter with no reader-side
    // capture possible (the setter is a `bt`).
    expect(liftOne("sbb", "eax, eax")).toMatchObject({ kind: "raw" });
    expect(
      lift([
        ["cmp", "eax, ecx"],
        ["shl", "edx, 1"],
        ["sbb", "ebx, ebx"],
      ])[1],
    ).toMatchObject({ kind: "raw" });
    expect(
      lift([
        ["bt", "eax, 3"],
        ["mov", "eax, 1"],
        ["sbb", "ebx, ebx"],
      ])[1],
    ).toMatchObject({ kind: "raw" });
  });

  it("spells a bt's CF as the selected bit and a logical op's as 0", () => {
    expect(
      lift([
        ["bt", "eax, 3"],
        ["sbb", "ebx, ebx"],
      ])[0],
    ).toMatchObject({
      src: irUnary(
        "-",
        irBinary("&", irBinary(">>", irReg("eax", 4), irConst(3, 4)), irConst(1, 4)),
      ),
    });
    expect(
      lift([
        ["and", "eax, ecx"],
        ["adc", "edx, 0x0"],
      ])[1],
    ).toMatchObject({
      src: irBinary("+", irBinary("+", irReg("edx", 4), irConst(0, 8)), irConst(0, 4)),
    });
  });

  it("reads CF across the edge from the block's sole predecessor", () => {
    const pred = blockOf([
      ["cmp", "al, dl"],
      ["jne", "0x401010"],
    ]);
    const succ: BasicBlock = {
      id: 1,
      startAddr: 0x401010,
      endAddr: 0x401018,
      insns: [insn("sbb", "rax, rax", 0x401010), insn("ret", "", 0x401014)],
      succs: [],
      preds: [0],
    };
    const state = new RegState();
    const withPred = liftBlock(
      succ,
      state,
      true,
      new Map(),
      new Map(),
      new Map(),
      undefined,
      undefined,
      undefined,
      undefined,
      undefined,
      pred,
    );
    expect(withPred[0]).toMatchObject({
      dest: irReg("rax", 8),
      src: irUnary("-", irBinary("u<", irReg("al", 1), irReg("dl", 1))),
    });
    // Omitting the predecessor is the pre-existing behaviour: refused.
    const without = liftBlock(succ, new RegState(), true, new Map(), new Map(), new Map());
    expect(without[0]).toMatchObject({ kind: "raw", text: "sbb rax, rax" });
    // A predecessor whose tail spoiled the compare is refused too.
    const spoiled = blockOf([
      ["cmp", "al, dl"],
      ["mov", "al, 0x1"],
      ["jne", "0x401010"],
    ]);
    expect(
      liftBlock(
        succ,
        new RegState(),
        true,
        new Map(),
        new Map(),
        new Map(),
        undefined,
        undefined,
        undefined,
        undefined,
        undefined,
        spoiled,
      )[0],
    ).toMatchObject({ kind: "raw" });
  });

  it("does not let a raw sbb OWN a guard — the lift-first rule made checkable", () => {
    const refused = blockOf([
      ["add", "eax, ecx"],
      ["sbb", "eax, eax"],
      ["jne", "0x401800"],
    ]);
    const stmts = liftBlock(refused, new RegState(), true, new Map(), new Map(), new Map());
    expect(stmts.some((s) => s.kind === "branch")).toBe(false);
    const lifted = blockOf([
      ["neg", "ecx"],
      ["sbb", "eax, eax"],
      ["jne", "0x401800"],
    ]);
    const ok = liftBlock(lifted, new RegState(), true, new Map(), new Map(), new Map());
    expect(ok[ok.length - 1]).toMatchObject({
      kind: "branch",
      condition: irBinary("!=", irReg("eax", 4), irConst(0, 4)),
    });
  });
});

/**
 * `bts`/`btr`/`btc` as statements (peek-a-bin-n9cl.6). 94 + 18 corpus sites,
 * MSVC's `_bittestandset`/`_bittestandreset` on flag words, all `raw` before —
 * and a `raw` is a dataflow hole, so the word read after one named the value
 * from before it. CF is deliberately NOT recorded: it is the bit's value before
 * the write (`flagModel.ts` keeps them clobbers; `parseBitTest` stays bt-only).
 */
describe("liftBlock — bts/btr/btc write the bit", () => {
  const bit = (n: number, size: number) => irBinary("<<", irConst(1, size), irConst(n, size));

  it("lifts the three ops over a register base with an immediate index", () => {
    expect(liftOne("bts", "r12d, 0xf")).toEqual({
      kind: "assign",
      dest: irReg("r12d", 4),
      src: irBinary("|", irReg("r12d", 4), bit(15, 4)),
      addr: START,
    });
    expect(liftOne("btr", "esi, 0xe")).toMatchObject({
      src: irBinary("&", irReg("esi", 4), irUnary("~", bit(14, 4))),
    });
    expect(liftOne("btc", "rax, 3")).toMatchObject({
      src: irBinary("^", irReg("rax", 8), bit(3, 8)),
    });
  });

  it("reduces a register base's immediate modulo the operand size, as the SDM does", () => {
    expect(liftOne("bts", "eax, 0x21")).toMatchObject({
      src: irBinary("|", irReg("eax", 4), bit(1, 4)),
    });
    expect(liftOne("bts", "rax, 0x41")).toMatchObject({
      src: irBinary("|", irReg("rax", 8), bit(1, 8)),
    });
    expect(liftOne("bts", "ax, 0x11")).toMatchObject({
      src: irBinary("|", irReg("ax", 2), bit(1, 2)),
    });
  });

  it("masks a register index over a register base with W-1", () => {
    expect(liftOne("bts", "eax, ecx")).toMatchObject({
      src: irBinary(
        "|",
        irReg("eax", 4),
        irBinary("<<", irConst(1, 4), irBinary("&", irReg("ecx", 4), irConst(31, 4))),
      ),
    });
  });

  it("stores through a memory base with an in-range immediate", () => {
    expect(liftOne("bts", "dword ptr [rbx + 0x18], 0xf")).toEqual({
      kind: "store",
      address: irBinary("+", irReg("rbx", 8), irConst(0x18, 8)),
      value: irBinary(
        "|",
        irDeref(irBinary("+", irReg("rbx", 8), irConst(0x18, 8)), 4),
        bit(15, 4),
      ),
      size: 4,
      addr: START,
    });
    // A `lock` prefix dispatches to the same statement; atomicity is not modelled.
    expect(liftOne("lock bts", "dword ptr [rdi + 0x18], 0xd")).toMatchObject({ kind: "store" });
  });

  it("REFUSES a memory base with a register index, an out-of-range immediate, or an 8-bit base", () => {
    // A memory base addresses a bit STRING, so `eax` may select a bit outside
    // the dword the operand names — the shape on both PE32 binaries.
    expect(liftOne("bts", "dword ptr [esp], eax")).toEqual({
      kind: "raw",
      text: "bts dword ptr [esp], eax",
      addr: START,
    });
    expect(liftOne("btr", "dword ptr [rcx + 0x18], 0x20")).toMatchObject({ kind: "raw" });
    expect(liftOne("bts", "[rcx], 3")).toMatchObject({ kind: "raw" });
    expect(liftOne("bts", "al, 3")).toMatchObject({ kind: "raw" });
    expect(liftOne("bts", "eax")).toMatchObject({ kind: "raw" });
  });

  it("records no CF for them — a following sbb stays raw", () => {
    expect(
      lift([
        ["bts", "eax, 3"],
        ["sbb", "ecx, ecx"],
      ])[1],
    ).toMatchObject({ kind: "raw", text: "sbb ecx, ecx" });
  });
});

/**
 * `movabs` (peek-a-bin-n9cl.6). Capstone spells the 64-bit-immediate `mov` as
 * `movabs`, and the `mov` handler tested `mn === "mov"`, so all 42 corpus sites
 * were `raw`. `IRConst.value` is a JS number: a 64-bit magic constant beyond
 * 2^53 would be silently ROUNDED, so those are refused (raw, counted) rather
 * than lifted wrong — the strncmp masks 0x8101010101010100 / 0x7efefefefefefeff
 * are exactly this case.
 */
describe("liftBlock — movabs", () => {
  it("lifts a movabs whose immediate is a safe integer", () => {
    expect(liftOne("movabs", "rax, 0x2b992ddfa233")).toEqual({
      kind: "assign",
      dest: irReg("rax", 8),
      src: irConst(0x2b992ddfa233, 8),
      addr: START,
    });
    // Sign-reinterpreted: sixteen digits with the top bit set is a small negative number.
    expect(liftOne("movabs", "r8, 0xfffffffffffffff0")).toMatchObject({ src: irConst(-16, 8) });
    expect(liftOne("movabs", "rax, 0xffffffffffff")).toMatchObject({
      src: irConst(0xffffffffffff, 8),
    });
  });

  it("REFUSES an immediate that is not a safe integer, leaving the instruction raw", () => {
    // The last is the corpus's `0xffffffffffffff0`: FIFTEEN digits, i.e.
    // 0x0FFFFFFFFFFFFFF0 = 2^60 - 16, positive and beyond 2^53 — not -16.
    for (const imm of [
      "0x8101010101010100",
      "0x7efefefefefefeff",
      "0x1fffffffffffffff",
      "0x101010101010101",
      "0xffffffffffffff0",
    ]) {
      expect(liftOne("movabs", `r11, ${imm}`), imm).toEqual({
        kind: "raw",
        text: `movabs r11, ${imm}`,
        addr: START,
      });
    }
    // The same guard on a plain `mov`, which cannot carry such an immediate today.
    expect(liftOne("mov", "rax, 0x7efefefefefefeff")).toMatchObject({ kind: "raw" });
  });

  it("does not record a refused movabs's destination as written", () => {
    const st = new RegState();
    lift([["movabs", "rcx, 0x7efefefefefefeff"]], { state: st });
    expect(st.wroteAnyAlias("rcx")).toBe(false);
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
  /**
   * The `rep` path was DEAD against real disassembly until peek-a-bin-n9cl.6:
   * Capstone spells the prefix into the mnemonic (`rep movsd`, operands in
   * `opStr` or empty) and the handler tested `mn === "rep"`. The row that
   * pinned that as a KNOWN BUG is now the first positive row. The spelling is
   * the MSVC intrinsic with the machine's exact semantics and its SIDE EFFECTS
   * — never `memcpy`/`memset`, which misstate a dword fill.
   */
  it("lifts `rep movsb` (prefix in the mnemonic, empty operands) to __movsb with its side effects", () => {
    const rdi = irReg("rdi", 8);
    const rsi = irReg("rsi", 8);
    const rcx = irReg("rcx", 8);
    expect(lift([["rep movsb", ""]])).toEqual([
      {
        kind: "call_stmt",
        call: { kind: "call", target: "__movsb", args: [rdi, rsi, rcx] },
        addr: START,
      },
      {
        kind: "assign",
        dest: rdi,
        src: irBinary("+", rdi, irBinary("*", rcx, irConst(1, 8))),
        addr: START,
      },
      {
        kind: "assign",
        dest: rsi,
        src: irBinary("+", rsi, irBinary("*", rcx, irConst(1, 8))),
        addr: START,
      },
      { kind: "assign", dest: rcx, src: irConst(0, 8), addr: START },
    ]);
  });

  it("lifts Capstone's real x86 shape, `rep stosd dword ptr es:[edi], eax`, to __stosd", () => {
    const edi = irReg("edi", 4);
    const ecx = irReg("ecx", 4);
    const stmts = lift([["rep stosd", "dword ptr es:[edi], eax"]], { is64: false });
    expect(stmts[0]).toEqual({
      kind: "call_stmt",
      call: { kind: "call", target: "__stosd", args: [edi, irReg("eax", 4), ecx] },
      addr: START,
    });
    expect(stmts[1]).toMatchObject({
      dest: edi,
      src: irBinary("+", edi, irBinary("*", ecx, irConst(4, 4))),
    });
    expect(stmts[2]).toMatchObject({ dest: ecx, src: irConst(0, 4) });
    expect(stmts).toHaveLength(3);
  });

  it("picks the accumulator by width and accepts repe/repz as rep", () => {
    expect(lift([["rep stosw", "word ptr [rdi], ax"]])[0]).toMatchObject({
      call: { target: "__stosw", args: [irReg("rdi", 8), irReg("ax", 2), irReg("rcx", 8)] },
    });
    expect(lift([["repe movsq", "qword ptr [rdi], qword ptr [rsi]"]])[0]).toMatchObject({
      call: { target: "__movsq" },
    });
  });

  it("lifts an unprefixed stosd/movsd to one store and the pointer advance", () => {
    const edi = irReg("edi", 4);
    expect(lift([["stosd", "dword ptr es:[edi], eax"]], { is64: false })).toEqual([
      { kind: "store", address: edi, value: irReg("eax", 4), size: 4, addr: START },
      { kind: "assign", dest: edi, src: irBinary("+", edi, irConst(4, 4)), addr: START },
    ]);
    const stmts = lift([["movsd", "dword ptr es:[edi], dword ptr [esi]"]], { is64: false });
    expect(stmts[0]).toMatchObject({ kind: "store", value: irDeref(irReg("esi", 4), 4) });
    expect(stmts).toHaveLength(3);
  });

  it("marks RCX as spent so the zeroed counter is not handed to the next call", () => {
    const stmts = lift([
      ["mov", "ecx, 0x10"],
      ["rep stosd", "dword ptr [rdi], eax"],
      ["call", "0x402000"],
    ]);
    const call = stmts.find((s) => s.kind === "call_stmt" && s.call.target !== "__stosd");
    expect(call).toMatchObject({ call: { args: [] } });
  });

  it("REFUSES a primitive inside a std region, and repne forms", () => {
    const stmts = lift(
      [
        ["std", ""],
        ["rep movsd", "dword ptr es:[edi], dword ptr [esi]"],
        ["cld", ""],
        ["rep movsd", "dword ptr es:[edi], dword ptr [esi]"],
      ],
      { is64: false },
    );
    expect(stmts[0]).toMatchObject({ kind: "raw", text: "std " });
    expect(stmts[1]).toMatchObject({
      kind: "raw",
      text: "rep movsd dword ptr es:[edi], dword ptr [esi]",
    });
    expect(stmts[2]).toMatchObject({ kind: "raw", text: "cld " });
    expect(stmts[3]).toMatchObject({ kind: "call_stmt", call: { target: "__movsd" } });
    expect(liftOne("repne scasw", "ax, word ptr [rdi]")).toMatchObject({ kind: "raw" });
    expect(liftOne("repne scasb", "")).toMatchObject({ kind: "raw" });
  });

  it("leaves the SSE scalar movsd to the SSE path", () => {
    expect(liftOne("movsd", "xmm0, qword ptr [rax]")).toMatchObject({
      kind: "assign",
      dest: irReg("xmm0", 16),
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

describe("matchedStackSlots", () => {
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

  /** One straight-line block, so the depth model is the only thing under test. */
  function straight(list: [string, string?][]): BasicBlock[] {
    return [blk(0, 0x401000, list)];
  }

  const at = (i: number) => 0x401000 + i * SIZE;

  it("pairs a save with its restore and names the slot after the push", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "ecx"],
        ["and", "ecx, 0xf"],
        ["pop", "ecx"],
      ]),
      false,
    );
    expect(s.pops.get(at(2))).toEqual({ slot: `stk_${at(0).toString(16)}`, size: 4 });
    expect(s.pushes.get(at(0))).toEqual({
      slot: `stk_${at(0).toString(16)}`,
      reg: "ecx",
      size: 4,
    });
  });

  it("pairs by depth, so a restore into a different register still resolves", () => {
    // MSVC's memset returns its destination pointer exactly this way:
    // `push ecx` on entry, `pop eax` before the `ret` (t32 0x40D9E7/0x40DA6F).
    const s = matchedStackSlots(
      straight([
        ["push", "ecx"],
        ["push", "ebx"],
        ["xor", "ebx, ebx"],
        ["pop", "ebx"],
        ["pop", "eax"],
      ]),
      false,
    );
    expect(s.pops.get(at(3))?.slot).toBe(`stk_${at(1).toString(16)}`);
    expect(s.pops.get(at(4))?.slot).toBe(`stk_${at(0).toString(16)}`);
  });

  it("leaves a push no pop reads without a definition", () => {
    // Emitting `stk_N = ebp` anyway would put a statement with no reader in
    // front of every prologue in the image.
    const s = matchedStackSlots(straight([["push", "ebp"]]), false);
    expect(s.pushes.size).toBe(0);
    expect(s.pops.size).toBe(0);
  });

  it("claims no value for an immediate or memory push, but keeps its depth", () => {
    // The immediate forms are `stackIdiom.ts`'s and must stay there, and a
    // memory push would move a load across every intervening store. The DEPTH
    // still has to be right or the `pop ebx` below pairs with the wrong push.
    for (const pushed of ["7", "dword ptr [eax]"]) {
      const s = matchedStackSlots(
        straight([
          ["push", "ebx"],
          ["push", pushed],
          ["pop", "ecx"],
          ["pop", "ebx"],
        ]),
        false,
      );
      expect(s.pops.get(at(2))).toBeUndefined();
      expect(s.pops.get(at(3))?.slot).toBe(`stk_${at(0).toString(16)}`);
    }
  });

  it("refuses across a call, because the callee may have popped the arguments", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "ebx"],
        ["call", "0x402000"],
        ["pop", "ebx"],
      ]),
      false,
    );
    expect(s.pops.size).toBe(0);
  });

  it("follows `add esp` and `sub esp` by a whole number of slots", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "ebx"],
        ["sub", "esp, 8"],
        ["add", "esp, 8"],
        ["pop", "ebx"],
      ]),
      false,
    );
    expect(s.pops.get(at(3))?.slot).toBe(`stk_${at(0).toString(16)}`);
  });

  it("refuses an `add esp` that is not a whole number of slots", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "ebx"],
        ["add", "esp, 2"],
        ["pop", "ebx"],
      ]),
      false,
    );
    expect(s.pops.size).toBe(0);
  });

  it("survives `lea esp, [esp]`, MSVC's multi-byte NOP", () => {
    // t32 0x40D9FC sits inside the very loop the memset pairing has to cross.
    const s = matchedStackSlots(
      straight([
        ["push", "ecx"],
        ["lea", "esp, [esp]"],
        ["mov", "ecx, 1"],
        ["pop", "ecx"],
      ]),
      false,
    );
    expect(s.pops.get(at(3))?.slot).toBe(`stk_${at(0).toString(16)}`);
  });

  it("refuses a store through the stack pointer, which writes the slots themselves", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "ebx"],
        ["mov", "dword ptr [esp], eax"],
        ["pop", "ebx"],
      ]),
      false,
    );
    expect(s.pops.size).toBe(0);
  });

  it("allows a READ through the stack pointer, which changes nothing", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "ebx"],
        ["lea", "ecx, [esp + 8]"],
        ["pop", "ebx"],
      ]),
      false,
    );
    expect(s.pops.get(at(2))?.slot).toBe(`stk_${at(0).toString(16)}`);
  });

  it("refuses `pop esp` and every other write of the stack pointer", () => {
    for (const [mn, ops] of [
      ["pop", "esp"],
      ["mov", "esp, ebp"],
      ["leave", ""],
    ] as [string, string][]) {
      const s = matchedStackSlots(
        straight([
          ["push", "ebx"],
          [mn, ops],
          ["pop", "ebx"],
        ]),
        false,
      );
      expect(s.pops.size, `${mn} ${ops}`).toBe(0);
    }
  });

  it("refuses a push or pop narrower than a slot, which moves ESP by its own width", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "cx"],
        ["pop", "cx"],
      ]),
      false,
    );
    expect(s.pops.size).toBe(0);
  });

  it("uses the pointer width for the slot, so an x64 pair is 8 bytes", () => {
    const s = matchedStackSlots(
      straight([
        ["push", "rbx"],
        ["xor", "rbx, rbx"],
        ["pop", "rbx"],
      ]),
      true,
    );
    expect(s.pops.get(at(2))).toEqual({ slot: `stk_${at(0).toString(16)}`, size: 8 });
  });

  it("refuses a pop below the region's base, whose contents belong to the caller", () => {
    const s = matchedStackSlots(straight([["pop", "ebx"]]), false);
    expect(s.pops.size).toBe(0);
  });

  it("pairs across blocks, including a loop between the push and the pop", () => {
    // t32!sub_40D99A 0x40DA7C/0x40DA97 in miniature: push, a self-looping body
    // that overwrites the register, then the restore.
    const blocks = [
      blk(0, 0x401000, [["push", "edx"]], { succs: [1] }),
      blk(
        1,
        0x401100,
        [
          ["dec", "edx"],
          ["jne", "0x401100"],
        ],
        { preds: [0, 1], succs: [1, 2] },
      ),
      blk(2, 0x401200, [["pop", "edx"]], { preds: [1] }),
    ];
    const s = matchedStackSlots(blocks, false);
    expect(s.pops.get(0x401200)?.slot).toBe("stk_401000");
  });

  it("refuses a join whose predecessors disagree about which push is on top", () => {
    const blocks = [
      blk(
        0,
        0x401000,
        [
          ["push", "ecx"],
          ["jmp", "0x401200"],
        ],
        { succs: [2] },
      ),
      blk(1, 0x401100, [["push", "edx"]], { succs: [2] }),
      blk(2, 0x401200, [["pop", "eax"]], { preds: [0, 1] }),
    ];
    expect(matchedStackSlots(blocks, false).pops.size).toBe(0);
  });

  it("refuses a join whose predecessors disagree about the DEPTH", () => {
    const blocks = [
      blk(
        0,
        0x401000,
        [
          ["push", "ecx"],
          ["push", "ebx"],
          ["jmp", "0x401200"],
        ],
        { succs: [2] },
      ),
      blk(1, 0x401100, [["push", "ebx"]], { succs: [2] }),
      blk(2, 0x401200, [["pop", "eax"]], { preds: [0, 1] }),
    ];
    expect(matchedStackSlots(blocks, false).pops.size).toBe(0);
  });

  /**
   * The lattice's TOP element, and the reason it exists.
   *
   * `t32!sub_40D99A` carries a one-instruction alignment NOP at 0x40DA40 that
   * nothing branches to and that falls into the middle of the memset body.
   * Seeding such a block with the EMPTY stack makes it contribute a concrete
   * depth of 0 at that join, which met against the real two-slot shape and took
   * the whole region — including the `pop eax` / `ret` this rule exists for — to
   * BOTTOM. An unreached predecessor has to be unconstraining.
   */
  it("is not poisoned by an unreachable predecessor that touches nothing", () => {
    const blocks = [
      blk(
        0,
        0x401000,
        [
          ["push", "ecx"],
          ["mov", "ecx, 1"],
        ],
        { succs: [2] },
      ),
      blk(1, 0x401100, [["lea", "ebx, [ebx]"]], { succs: [2] }),
      blk(2, 0x401200, [["pop", "eax"]], { preds: [0, 1] }),
    ];
    expect(matchedStackSlots(blocks, false).pops.get(0x401200)?.slot).toBe("stk_401000");
  });

  it("…but an unreachable predecessor that DOES touch the stack still refuses", () => {
    const blocks = [
      blk(
        0,
        0x401000,
        [
          ["push", "ecx"],
          ["mov", "ecx, 1"],
        ],
        { succs: [2] },
      ),
      blk(1, 0x401100, [["push", "ebx"]], { succs: [2] }),
      blk(2, 0x401200, [["pop", "eax"]], { preds: [0, 1] }),
    ];
    expect(matchedStackSlots(blocks, false).pops.size).toBe(0);
  });

  it("pairs a region the CFG shows no way into, from its own first push", () => {
    // The memset body of t32!sub_40D99A follows a `ret` and nothing in the
    // function branches to it. The claim is relative to the push, so the
    // unknown entry depth costs nothing.
    const blocks = [
      blk(0, 0x401000, [["ret", ""]], {}),
      blk(
        1,
        0x401100,
        [
          ["push", "ecx"],
          ["mov", "ecx, 1"],
          ["pop", "eax"],
        ],
        {},
      ),
    ];
    expect(matchedStackSlots(blocks, false).pops.get(0x401108)?.slot).toBe("stk_401100");
  });

  it("answers nothing for an empty block list", () => {
    expect(matchedStackSlots([], false)).toEqual({ pushes: new Map(), pops: new Map() });
  });
});

describe("liftBlock — matched stack slots", () => {
  function liftWithSlots(list: [string, string][], is64 = false): IRStmt[] {
    const block = blockOf(list);
    return liftBlock(
      block,
      new RegState(),
      is64,
      new Map(),
      new Map(),
      new Map(),
      undefined,
      undefined,
      undefined,
      matchedStackSlots([block], is64),
    );
  }

  it("gives the push and the pop one statement each", () => {
    const stmts = liftWithSlots([
      ["push", "ecx"],
      ["and", "ecx, 0xf"],
      ["pop", "ecx"],
    ]);
    expect(stmts).toEqual([
      { kind: "assign", dest: irReg("stk_401000", 4), src: irReg("ecx", 4), addr: 0x401000 },
      {
        kind: "assign",
        dest: irReg("ecx"),
        src: irBinary("&", irReg("ecx", 4), irConst(0xf, 4)),
        addr: 0x401004,
      },
      { kind: "assign", dest: irReg("ecx"), src: irReg("stk_401000", 4), addr: 0x401008 },
    ]);
  });

  it("leaves both alone when no pairing was handed in", () => {
    // Omitting the argument is the pre-existing behaviour, which is what every
    // caller that has not been threaded through still gets.
    expect(
      lift([
        ["push", "ecx"],
        ["pop", "ecx"],
      ]),
    ).toEqual([]);
  });

  it("lets the push-imm rule answer first, so the two cannot both claim a pop", () => {
    // They are disjoint by construction — the immediate rules answer only for an
    // immediate push and this one pairs only a register push — but the order
    // means that is not the only thing keeping them apart.
    const stmts = liftWithSlots([
      ["push", "7"],
      ["pop", "ecx"],
    ]);
    expect(stmts).toEqual([
      { kind: "assign", dest: irReg("ecx"), src: irConst(7, 4), addr: 0x401004 },
    ]);
  });

  it("still emits nothing for a pop the pairing refused", () => {
    expect(
      liftWithSlots([
        ["push", "ebx"],
        ["call", "0x402000"],
        ["pop", "ebx"],
      ]).filter((s) => s.kind === "assign" && s.dest.kind === "reg" && s.dest.name === "ebx"),
    ).toEqual([]);
  });
});

describe("liftBlock — a call to a result-preserving CRT routine defines no result", () => {
  // `__security_check_cookie` as `crtIdioms.ts` publishes it: the routine
  // compares RCX/ECX against the cookie and either returns or tail-jumps to
  // `__report_gsfailure`, so RAX/EAX leaves it exactly as it entered. Giving
  // the call a `resultDest` made the function's real return value dead
  // (peek-a-bin-n9cl.3).
  const CHECK = 0x402000;
  const idiom = (acc: string): CrtIdiom => ({
    kind: "security-check-cookie",
    name: "__security_check_cookie",
    preservesResult: true,
    cookieAddress: 0x403000,
    args: [acc],
  });
  const facts = (acc: string): CalleeClobbers => ({
    byAddress: new Map(),
    unresolved: [],
    idioms: new Map([[CHECK, idiom(acc)]]),
  });
  const funcs = new Map([[CHECK, { name: "__security_check_cookie", address: CHECK }]]);

  it("emits the call with no resultDest and the routine's own argument, x64", () => {
    const stmts = lift([["call", "0x402000"]], { clobbers: facts("rcx"), funcs });
    expect(stmts).toHaveLength(1);
    expect(stmts[0].kind).toBe("call_stmt");
    const call = stmts[0] as Extract<IRStmt, { kind: "call_stmt" }>;
    expect(call.resultDest).toBeUndefined();
    expect(call.call.target).toBe("__security_check_cookie");
    expect(call.call.args).toEqual([irReg("rcx")]);
  });

  it("does the same on x86, where the argument is ECX and collectArgs32 would find nothing", () => {
    // Nothing pushes for a `__fastcall` helper, so the push walk reports zero
    // arguments and the `xor ecx, ebp` above the call is dead — the documented
    // signature is what keeps it alive.
    const stmts = lift([["call", "0x402000"]], { is64: false, clobbers: facts("ecx"), funcs });
    const call = stmts[0] as Extract<IRStmt, { kind: "call_stmt" }>;
    expect(call.resultDest).toBeUndefined();
    expect(call.call.args).toEqual([irReg("ecx")]);
  });

  it("keeps the resultDest on a call to any other function", () => {
    const stmts = lift([["call", "0x402100"]], { clobbers: facts("rcx"), funcs });
    expect(stmts[0]).toMatchObject({ kind: "call_stmt", resultDest: irReg("rax") });
  });

  it("keeps the resultDest when no idiom map was supplied at all", () => {
    // The pre-idiom behaviour, byte for byte: a caller that built no summary
    // gets a call that defines the accumulator.
    const stmts = lift([["call", "0x402000"]], { funcs });
    expect(stmts[0]).toMatchObject({ kind: "call_stmt", resultDest: irReg("rax") });
  });

  it("keeps the resultDest on an indirect call, even with the routine's address in a register", () => {
    // `call rax` is not evidence of which routine runs; refusing costs a
    // resultDest, not a wrong value.
    const stmts = lift([["call", "rax"]], { clobbers: facts("rcx"), funcs });
    expect(stmts[0]).toMatchObject({ kind: "call_stmt", resultDest: irReg("rax") });
  });

  it("does not record the call as the accumulator's value in RegState", () => {
    const state = new RegState();
    lift([["call", "0x402000"]], { clobbers: facts("rcx"), funcs, state });
    expect(state.wroteAnyAlias("rax")).toBe(false);
  });

  it("lifts a tail jump to the routine as a call with no result, returning what reached it", () => {
    const stmts = lift([["jmp", "0x402000"]], { clobbers: facts("rcx"), funcs, succs: [] });
    expect(stmts).toHaveLength(2);
    const call = stmts[0] as Extract<IRStmt, { kind: "call_stmt" }>;
    expect(call.resultDest).toBeUndefined();
    expect(stmts[1]).toMatchObject({ kind: "return", value: irReg("rax", 8) });
  });
});
