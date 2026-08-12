import { describe, expect, it } from "vitest";
import { type BasicBlock, buildCFG, detectLoops } from "../cfg";
import type { DisasmFunction, Instruction, Xref } from "../types";

const START = 0x401000;

type Spec = [mnemonic: string, opStr: string, size: number];

/** Lay out instructions back-to-back starting at `start`. */
function layout(start: number, specs: Spec[]): Instruction[] {
  let addr = start;
  return specs.map(([mnemonic, opStr, size]) => {
    const insn: Instruction = { address: addr, mnemonic, opStr, size, bytes: new Uint8Array(size) };
    addr += size;
    return insn;
  });
}

function totalSize(insns: Instruction[]): number {
  return insns.reduce((n, i) => n + i.size, 0);
}

function cfg(
  specs: Spec[],
  opts: { xrefs?: Map<number, Xref[]>; jumpTables?: Map<number, number[]>; funcSize?: number } = {},
): { blocks: BasicBlock[]; insns: Instruction[] } {
  const insns = layout(START, specs);
  const func: DisasmFunction = {
    name: "f",
    address: START,
    size: opts.funcSize ?? totalSize(insns),
  };
  const blocks = buildCFG(func, insns, opts.xrefs ?? new Map(), opts.jumpTables);
  return { blocks, insns };
}

/** succs/preds must agree in both directions for every edge. */
function expectEdgesConsistent(blocks: BasicBlock[]) {
  for (const b of blocks) {
    for (const s of b.succs) {
      expect(blocks[s], `succ ${s} of block ${b.id} exists`).toBeDefined();
      expect(blocks[s].preds, `block ${s}.preds contains ${b.id}`).toContain(b.id);
    }
    for (const p of b.preds) {
      expect(blocks[p].succs, `block ${p}.succs contains ${b.id}`).toContain(b.id);
    }
  }
  // Block ids must equal their array index — the edge code indexes blocks[] by id.
  blocks.forEach((b, i) => expect(b.id).toBe(i));
}

describe("buildCFG", () => {
  it("returns no blocks when the function range holds no instructions", () => {
    const insns = layout(START, [["ret", "", 1]]);
    expect(buildCFG({ name: "f", address: 0x500000, size: 0x10 }, insns, new Map())).toEqual([]);
  });

  it("makes a single block from straight-line code", () => {
    const { blocks } = cfg([
      ["push", "rbp", 1],
      ["mov", "rbp, rsp", 3],
      ["xor", "eax, eax", 2],
      ["pop", "rbp", 1],
      ["ret", "", 1],
    ]);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].startAddr).toBe(START);
    expect(blocks[0].endAddr).toBe(START + 8);
    expect(blocks[0].insns).toHaveLength(5);
    expect(blocks[0].succs).toEqual([]);
    expect(blocks[0].preds).toEqual([]);
  });

  it("does not split a block at a call", () => {
    const { blocks } = cfg([
      ["xor", "ecx, ecx", 2],
      ["call", "0x401500", 5],
      ["ret", "", 1],
    ]);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].insns).toHaveLength(3);
  });

  it("splits a conditional branch into branch-target and fallthrough successors", () => {
    //   0x401000 cmp eax, 0
    //   0x401003 je  0x40100a      → taken: block 2, fallthrough: block 1
    //   0x401005 mov eax, 1
    //   0x40100a ret
    const { blocks } = cfg([
      ["cmp", "eax, 0", 3],
      ["je", "0x40100a", 2],
      ["mov", "eax, 1", 5],
      ["ret", "", 1],
    ]);
    expect(blocks.map((b) => b.startAddr)).toEqual([0x401000, 0x401005, 0x40100a]);
    // Taken edge is recorded before the fallthrough edge.
    expect(blocks[0].succs).toEqual([2, 1]);
    expect(blocks[1].succs).toEqual([2]);
    expect(blocks[2].succs).toEqual([]);
    expect(blocks[2].preds).toEqual([0, 1]);
    expectEdgesConsistent(blocks);
  });

  it("gives a conditional branch only a fallthrough edge when the target is outside the function", () => {
    const { blocks } = cfg([
      ["cmp", "eax, 0", 3],
      ["je", "0x402000", 2], // outside [0x401000, 0x401006)
      ["ret", "", 1],
    ]);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].succs).toEqual([1]);
    expectEdgesConsistent(blocks);
  });

  it("follows an unconditional jmp and leaves the skipped block unreachable", () => {
    const { blocks } = cfg([
      ["jmp", "0x401006", 2], // 0x401000
      ["mov", "eax, 1", 4], // 0x401002 — never entered
      ["ret", "", 1], // 0x401006
    ]);
    expect(blocks.map((b) => b.startAddr)).toEqual([0x401000, 0x401002, 0x401006]);
    expect(blocks[0].succs).toEqual([2]);
    expect(blocks[1].preds).toEqual([]); // no fallthrough into a block after a jmp
    expect(blocks[1].succs).toEqual([2]);
    expectEdgesConsistent(blocks);
  });

  it("leaves a tail-call jmp outside the function with no successors", () => {
    const { blocks } = cfg([
      ["mov", "rcx, rbx", 3],
      ["jmp", "0x408000", 5],
    ]);
    expect(blocks).toHaveLength(1);
    expect(blocks[0].succs).toEqual([]);
  });

  it("leaves an unresolved indirect jmp with no successors", () => {
    const { blocks } = cfg([
      ["mov", "rax, rbx", 3],
      ["jmp", "rax", 2],
    ]);
    expect(blocks[0].succs).toEqual([]);
  });

  it("records a back edge for a loop", () => {
    //   0x401000 xor eax, eax
    //   0x401002 inc eax          ← loop header
    //   0x401004 cmp eax, 5
    //   0x401007 jl  0x401002
    //   0x401009 ret
    const { blocks } = cfg([
      ["xor", "eax, eax", 2],
      ["inc", "eax", 2],
      ["cmp", "eax, 5", 3],
      ["jl", "0x401002", 2],
      ["ret", "", 1],
    ]);
    expect(blocks.map((b) => b.startAddr)).toEqual([0x401000, 0x401002, 0x401009]);
    expect(blocks[0].succs).toEqual([1]);
    expect(blocks[1].succs).toEqual([1, 2]); // back edge to itself, then exit
    expect(blocks[1].preds).toEqual([0, 1]);
    expectEdgesConsistent(blocks);

    const loops = detectLoops(blocks);
    expect(loops).toHaveLength(1);
    expect(loops[0].headerAddr).toBe(0x401002);
  });

  it("records a back edge that spans several blocks", () => {
    //   0x401000 mov ecx, 0
    //   0x401004 cmp ecx, 8       ← header
    //   0x401007 jge 0x401011
    //   0x401009 inc ecx          ← body
    //   0x40100b jmp 0x401004
    //   0x401011 ret
    const { blocks } = cfg([
      ["mov", "ecx, 0", 4],
      ["cmp", "ecx, 8", 3],
      ["jge", "0x401011", 2],
      ["inc", "ecx", 2],
      ["jmp", "0x401004", 6],
      ["ret", "", 1],
    ]);
    expect(blocks.map((b) => b.startAddr)).toEqual([0x401000, 0x401004, 0x401009, 0x401011]);
    expect(blocks[1].succs).toEqual([3, 2]);
    expect(blocks[2].succs).toEqual([1]); // back edge
    expect(blocks[1].preds).toEqual([0, 2]);
    expectEdgesConsistent(blocks);

    const loops = detectLoops(blocks);
    expect(loops.map((l) => l.headerAddr)).toEqual([0x401004]);
  });

  it("starts a new block after a ret in the middle of a function", () => {
    const { blocks } = cfg([
      ["ret", "", 1], // 0x401000
      ["xor", "eax, eax", 2], // 0x401001 — separate exit path
      ["ret", "", 1],
    ]);
    expect(blocks).toHaveLength(2);
    expect(blocks[0].succs).toEqual([]);
    expect(blocks[1].preds).toEqual([]);
  });

  it("starts a block at an address branched to from elsewhere (xref)", () => {
    // Nothing inside this function jumps to 0x401003, but an xref says something does.
    const xrefs = new Map<number, Xref[]>([[0x401003, [{ from: 0x409000, type: "branch" }]]]);
    const { blocks } = cfg(
      [
        ["mov", "eax, 1", 3],
        ["mov", "ebx, 2", 3],
        ["ret", "", 1],
      ],
      { xrefs },
    );
    expect(blocks.map((b) => b.startAddr)).toEqual([0x401000, 0x401003]);
    expect(blocks[0].succs).toEqual([1]); // fallthrough
    expectEdgesConsistent(blocks);
  });

  it("ignores a data xref when choosing block leaders", () => {
    const xrefs = new Map<number, Xref[]>([[0x401003, [{ from: 0x409000, type: "data" }]]]);
    const { blocks } = cfg(
      [
        ["mov", "eax, 1", 3],
        ["mov", "ebx, 2", 3],
        ["ret", "", 1],
      ],
      { xrefs },
    );
    expect(blocks).toHaveLength(1);
  });

  it("excludes instructions that lie outside the function range", () => {
    const insns = layout(START, [
      ["mov", "eax, 1", 4], // 0x401000 — previous function
      ["xor", "ecx, ecx", 4], // 0x401004 — ours
      ["ret", "", 4], // 0x401008 — ours
      ["nop", "", 4], // 0x40100c — next function
    ]);
    const blocks = buildCFG({ name: "f", address: 0x401004, size: 8 }, insns, new Map());
    expect(blocks).toHaveLength(1);
    expect(blocks[0].insns.map((i) => i.address)).toEqual([0x401004, 0x401008]);
  });

  describe("a funclet inside the function (peek-a-bin-g7yp)", () => {
    // MSVC's x86 `__finally` sits *inside* its parent: the parent calls it, it
    // ends in `ret`, and the parent's body resumes on the next byte. The
    // detector used to treat it as a function start and so cut the parent in
    // half at 0x40100b, and then the branch above lost the edge that reaches
    // 0x40100d — the test disappeared from the graph and the structurer read the
    // block as unconditional. This is what the repaired extent has to produce.
    const specs: Spec[] = [
      ["cmp", "eax, 0", 3], // 0x401000
      ["je", "0x40100d", 2], // 0x401003 — over the funclet, back into the parent
      ["call", "0x40100b", 5], // 0x401005 — the funclet
      ["ret", "", 1], // 0x40100a
      ["nop", "", 1], // 0x40100b — the funclet
      ["ret", "", 1], // 0x40100c
      ["nop", "", 1], // 0x40100d — the parent resumes
      ["ret", "", 1], // 0x40100e
    ];

    it("gives the branch over it both successors", () => {
      const { blocks } = cfg(specs);
      const starts = blocks[0].succs.map((s) => blocks[s].startAddr).sort((a, b) => a - b);
      expect(starts).toEqual([0x401005, 0x40100d]);
      expectEdgesConsistent(blocks);
    });

    it("leaves the funclet block with no predecessor, because a call is not an edge", () => {
      const { blocks } = cfg(specs);
      const funclet = blocks.find((b) => b.startAddr === 0x40100b);
      expect(funclet).toBeDefined();
      expect(funclet?.preds).toEqual([]);
      expect(funclet?.succs).toEqual([]);
    });
  });

  describe("jump tables", () => {
    const specs: Spec[] = [
      ["cmp", "eax, 3", 3], // 0x401000
      ["ja", "0x401014", 2], // 0x401003 — default
      ["jmp", "qword ptr [rax*8 + 0x402000]", 7], // 0x401005 — indirect
      ["mov", "eax, 1", 5], // 0x40100c — case 0
      ["mov", "eax, 2", 3], // 0x401011 — case 1
      ["ret", "", 1], // 0x401014
    ];

    it("adds an edge to every jump table target", () => {
      const { blocks } = cfg(specs, {
        jumpTables: new Map([[0x401005, [0x40100c, 0x401011]]]),
      });
      const byAddr = new Map(blocks.map((b) => [b.startAddr, b]));
      expect([...byAddr.keys()]).toEqual([0x401000, 0x401005, 0x40100c, 0x401011, 0x401014]);
      const indirect = byAddr.get(0x401005)!;
      expect(indirect.succs.map((id) => blocks[id].startAddr)).toEqual([0x40100c, 0x401011]);
      expectEdgesConsistent(blocks);
    });

    it("deduplicates repeated jump table targets", () => {
      const { blocks } = cfg(specs, {
        jumpTables: new Map([[0x401005, [0x40100c, 0x401011, 0x40100c, 0x40100c]]]),
      });
      const indirect = blocks.find((b) => b.startAddr === 0x401005)!;
      expect(indirect.succs).toHaveLength(2);
      expectEdgesConsistent(blocks);
    });

    it("skips jump table targets outside the function", () => {
      const { blocks } = cfg(specs, {
        jumpTables: new Map([[0x401005, [0x40100c, 0x409000]]]),
      });
      const indirect = blocks.find((b) => b.startAddr === 0x401005)!;
      expect(indirect.succs.map((id) => blocks[id].startAddr)).toEqual([0x40100c]);
    });
  });
});

/**
 * `detectLoops` is dominance-based: an edge `u → v` is a back edge only when v
 * dominates u. It used to approximate that with BFS layers from the entry,
 * which called the merge block of every `if`-without-`else` a loop header —
 * ~86% of the loop headers reported on three real MSVC binaries did not exist
 * (peek-a-bin-lrs). The decompiler is not the only consumer: the disassembly
 * view marks loop headers from this same function.
 */
describe("detectLoops — shapes that are not loops", () => {
  it("does not call the merge of an if-without-else a loop", () => {
    //   0x401000 test ecx, ecx
    //   0x401002 je   0x401009   ← both paths end at 0x401009
    //   0x401004 mov  [ecx], edx
    //   0x401009 ret
    const { blocks } = cfg([
      ["test", "ecx, ecx", 2],
      ["je", "0x401009", 2],
      ["mov", "dword ptr [ecx], edx", 5],
      ["ret", "", 1],
    ]);
    expect(blocks.map((b) => b.startAddr)).toEqual([0x401000, 0x401004, 0x401009]);
    expect(detectLoops(blocks)).toEqual([]);
  });

  it("does not call the merge of an if-else a loop either", () => {
    const { blocks } = cfg([
      ["test", "ecx, ecx", 2],
      ["je", "0x401009", 2],
      ["mov", "eax, 1", 5], // 0x401004
      ["jmp", "0x40100e", 2],
      ["mov", "eax, 2", 5], // 0x401009
      ["ret", "", 1], // 0x40100e
    ]);
    expect(detectLoops(blocks)).toEqual([]);
  });

  it("does not treat a forward jump over a block as a back edge", () => {
    const { blocks } = cfg([
      ["jmp", "0x401007", 2], // 0x401000
      ["mov", "eax, 1", 5], // 0x401002 — unreachable
      ["ret", "", 1], // 0x401007
    ]);
    expect(detectLoops(blocks)).toEqual([]);
  });
});

describe("detectLoops — nesting", () => {
  it("gives an inner loop a greater depth than the outer one", () => {
    //   0x401000 mov ecx, 0
    //   0x401005 cmp ecx, 8       ← outer header
    //   0x401008 jge 0x401019
    //   0x40100a mov edx, 0       ← outer body / inner preheader
    //   0x40100f cmp edx, 4       ← inner header
    //   0x401012 jge 0x401017
    //   0x401014 inc edx
    //   0x401015 jmp 0x40100f     ← inner back edge
    //   0x401017 inc ecx
    //   0x401018 jmp 0x401005     ← outer back edge (unreachable-free)
    //   0x40101d ret
    const { blocks } = cfg([
      ["mov", "ecx, 0", 5],
      ["cmp", "ecx, 8", 3],
      ["jge", "0x40101d", 2],
      ["mov", "edx, 0", 5],
      ["cmp", "edx, 4", 3],
      ["jge", "0x401017", 2],
      ["inc", "edx", 1],
      ["jmp", "0x40100f", 2],
      ["inc", "ecx", 1], // 0x401017
      ["jmp", "0x401005", 5], // 0x401018
      ["ret", "", 1], // 0x40101d
    ]);
    const loops = detectLoops(blocks);
    expect(loops.map((l) => l.headerAddr)).toEqual([0x401005, 0x40100f]);
    expect(loops[0].depth).toBe(0);
    expect(loops[1].depth).toBe(1);
    // The outer body covers the inner header; the inner body does not cover
    // the outer one.
    expect(loops[0].bodyAddrs.has(0x40100f)).toBe(true);
    expect(loops[1].bodyAddrs.has(0x401005)).toBe(false);
  });
});

/**
 * peek-a-bin-8bj — ARM64 control flow.
 *
 * `buildCFG` split blocks on `jmp`/`j<cc>`/`ret` and read `^0x…$` operands, all
 * of which are x86 spellings. On an ARM64 image it therefore produced one block
 * per function and NO edges at all: measured on t64-arm.exe, 659 blocks and 0
 * edges across 539 functions, 454 of them a single block.
 *
 * Every A64 operand string below is Capstone's own output on that file. The
 * A64 base is 0x140001000 rather than `START` so a mis-scaled address cannot
 * accidentally coincide with an x86 one.
 */
const A64 = 0x140001000;

/** Fixed-width 4-byte A64 instructions. */
function a64(
  specs: [mnemonic: string, opStr: string][],
  opts: { funcSize?: number; jumpTables?: Map<number, number[]> } = {},
): { blocks: BasicBlock[]; insns: Instruction[] } {
  const insns = layout(
    A64,
    specs.map(([m, o]) => [m, o, 4] as Spec),
  );
  const func: DisasmFunction = { name: "f", address: A64, size: opts.funcSize ?? insns.length * 4 };
  return { blocks: buildCFG(func, insns, new Map(), opts.jumpTables), insns };
}

/** `0x…` of a block start, for readable failures. */
const starts = (blocks: BasicBlock[]) => blocks.map((b) => b.startAddr);

describe("buildCFG — ARM64 (peek-a-bin-8bj)", () => {
  it("splits at a conditional branch and wires both successors", () => {
    // cmp / b.ne <else> / mov / ret / mov / ret
    const { blocks } = a64([
      ["cmp", "x16, x17"],
      ["b.ne", `#0x${(A64 + 0x10).toString(16)}`],
      ["mov", "x0, #0"],
      ["ret", ""],
      ["mov", "x0, #1"],
      ["ret", ""],
    ]);

    expect(starts(blocks)).toEqual([A64, A64 + 0x08, A64 + 0x10]);
    // Taken edge first, then the fallthrough — the order the x86 arm uses.
    expect(blocks[0].succs).toEqual([2, 1]);
    expect(blocks[1].succs).toEqual([]);
    expectEdgesConsistent(blocks);
  });

  it.each(["cbz", "cbnz"])("splits at %s, reading past the register operand", (mn) => {
    const { blocks } = a64([
      [mn, `w2, #0x${(A64 + 0x0c).toString(16)}`],
      ["mov", "x0, #0"],
      ["ret", ""],
      ["ret", ""],
    ]);

    expect(starts(blocks)).toEqual([A64, A64 + 0x04, A64 + 0x0c]);
    expect(blocks[0].succs).toEqual([2, 1]);
    expectEdgesConsistent(blocks);
  });

  it.each(["tbz", "tbnz"])("splits at %s, reading past the register AND the bit", (mn) => {
    const { blocks } = a64([
      [mn, `w2, #2, #0x${(A64 + 0x0c).toString(16)}`],
      ["mov", "x0, #0"],
      ["ret", ""],
      ["ret", ""],
    ]);

    expect(blocks[0].succs).toEqual([2, 1]);
    expectEdgesConsistent(blocks);
  });

  it("gives an unconditional b one successor and no fallthrough", () => {
    const { blocks } = a64([
      ["b", `#0x${(A64 + 0x08).toString(16)}`],
      ["brk", "#1"],
      ["ret", ""],
    ]);

    expect(blocks[0].succs).toEqual([2]);
    // The skipped `brk` block is reachable from nothing.
    expect(blocks[1].preds).toEqual([]);
    expectEdgesConsistent(blocks);
  });

  it("finds a backward b.ne loop, which detectLoops then sees", () => {
    // The `sub / ldr / cmp / b.ne <back>` probe loop from t64-arm.exe.
    const { blocks } = a64([
      ["mov", "x16, #0"],
      ["sub", "x17, x17, #1, lsl #12"],
      ["ldr", "xzr, [x17]"],
      ["cmp", "x17, x16"],
      ["b.ne", `#0x${(A64 + 0x04).toString(16)}`],
      ["ret", ""],
    ]);

    expect(starts(blocks)).toEqual([A64, A64 + 0x04, A64 + 0x14]);
    // Self edge back to the loop header, plus the exit.
    expect(blocks[1].succs).toEqual([1, 2]);
    expect(detectLoops(blocks).map((l) => l.headerAddr)).toEqual([A64 + 0x04]);
    expectEdgesConsistent(blocks);
  });

  it("does not end a block at bl — a call returns", () => {
    // `bl` is A64's `call`. Ending a block there would double the block count
    // and hang a fallthrough edge off every call site.
    const { blocks } = a64([
      ["mov", "x0, #1"],
      ["bl", "#0x140003160"],
      ["mov", "x1, x0"],
      ["ret", ""],
    ]);

    expect(blocks).toHaveLength(1);
    expect(blocks[0].succs).toEqual([]);
  });

  it("does not end a block at brk, which is not br", () => {
    const { blocks } = a64([
      ["mov", "x0, #1"],
      ["brk", "#1"],
      ["mov", "x1, x0"],
      ["ret", ""],
    ]);
    expect(blocks).toHaveLength(1);
  });
});

describe("buildCFG — ARM64 declines rather than guessing an edge", () => {
  it("gives an indirect br NO successor, and still ends the block", () => {
    // A `br x8` is a switch dispatch or a register tail call. Guessing the
    // fallthrough would be a wrong edge, and a wrong edge is indistinguishable
    // downstream from a real one. t64-arm.exe has 26 of these.
    const { blocks } = a64([
      ["ldr", "x8, [x0]"],
      ["br", "x8"],
      ["mov", "x0, #1"],
      ["ret", ""],
    ]);

    expect(starts(blocks)).toEqual([A64, A64 + 0x08]);
    expect(blocks[0].succs).toEqual([]);
    expect(blocks[1].preds).toEqual([]);
  });

  it("emits no edge for a b whose target is outside the function", () => {
    // A tail call. 60 of t64-arm.exe's direct branches leave their own function.
    const { blocks } = a64([
      ["mov", "x0, #1"],
      ["b", "#0x140099999"],
    ]);

    expect(blocks).toHaveLength(1);
    expect(blocks[0].succs).toEqual([]);
  });

  it("emits no edge for a conditional branch whose target it cannot read", () => {
    // Fallthrough still exists — that one is known. The taken edge does not.
    const { blocks } = a64([
      ["cbz", "w2, x9"],
      ["mov", "x0, #1"],
      ["ret", ""],
    ]);

    expect(blocks[0].succs).toEqual([1]);
    expectEdgesConsistent(blocks);
  });
});

/**
 * peek-a-bin-8ij. Where `arm64.ts` recovered the dispatch table, the case bodies
 * are the `br` block's successors. Where it did not, the block above still has
 * none — recovering some tables must not turn "unknown" into "guessed" for the
 * rest.
 */
describe("buildCFG — ARM64 dispatch tables", () => {
  const dispatch: [string, string][] = [
    ["cmp", "w1, #1"],
    ["b.hi", `#0x${(A64 + 0x14).toString(16)}`],
    ["adr", `x9, #0x${(A64 + 0x18).toString(16)}`],
    ["ldrb", "w8, [x9, w1, uxtw]"],
    ["add", "x8, x9, x8, lsl #2"],
    ["br", "x8"], // 0x14
    ["mov", "x0, #1"], // 0x18 — case 0
    ["ret", ""],
    ["mov", "x0, #2"], // 0x20 — case 1
    ["ret", ""],
  ];

  it("wires the br block to every case body the table names", () => {
    const { blocks } = a64(dispatch, {
      jumpTables: new Map([[A64 + 0x14, [A64 + 0x18, A64 + 0x20]]]),
    });

    const brBlock = blocks.find((b) => b.insns.some((i) => i.mnemonic === "br"))!;
    const succStarts = brBlock.succs.map((id) => blocks[id].startAddr);
    expect(succStarts).toEqual([A64 + 0x18, A64 + 0x20]);
    expectEdgesConsistent(blocks);
  });

  it("still gives the br no successor when no table was recovered", () => {
    const { blocks } = a64(dispatch);

    const brBlock = blocks.find((b) => b.insns.some((i) => i.mnemonic === "br"))!;
    expect(brBlock.succs).toEqual([]);
  });

  it("does not add a fallthrough edge alongside the case edges", () => {
    // A dispatch does not fall through, and the instruction after the `br` is
    // case 0 here — an extra edge to it would double-count.
    const { blocks } = a64(dispatch, {
      jumpTables: new Map([[A64 + 0x14, [A64 + 0x20]]]),
    });

    const brBlock = blocks.find((b) => b.insns.some((i) => i.mnemonic === "br"))!;
    expect(brBlock.succs.map((id) => blocks[id].startAddr)).toEqual([A64 + 0x20]);
  });

  it("ignores a table entry that is not a block start in this function", () => {
    const { blocks } = a64(dispatch, {
      jumpTables: new Map([[A64 + 0x14, [A64 + 0x18, A64 + 0x900]]]),
    });

    const brBlock = blocks.find((b) => b.insns.some((i) => i.mnemonic === "br"))!;
    expect(brBlock.succs.map((id) => blocks[id].startAddr)).toEqual([A64 + 0x18]);
  });
});
