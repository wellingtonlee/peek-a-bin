/**
 * peek-a-bin-h0us — `decompileFunction` must hand its `is64` to `structureCFG`.
 *
 * `structureCFG` parses a branch's `cmp`/`test` operands through `lifter.ts`'s
 * real `parseOperand`, which takes `is64` and uses it for two fallback widths:
 * an immediate's `IRConst.size` (4 vs 8) and a memory operand's width when the
 * disassembler emitted no `dword ptr`-style size prefix. `structureCFG` gives
 * the parameter a default of `false`, which reproduces exactly what the private
 * parser it replaced hardcoded, so a caller that omits it does not break — it
 * silently describes a 64-bit image with 32-bit operand widths.
 *
 * MEASURED, so the guard is not overstated. Across t32/t64/w64/w32 and
 * gcc-amd64-mingw-exec, 2412 of 2412 `cmp`/`test` memory operands carry a size
 * prefix, so the deref fallback never fires in practice and only immediate and
 * rip-resolved-address widths actually move. Passing `is64` changes the
 * structured IR of 151/279 functions in t64.exe, 147/275 in w64.exe and 47/128
 * in gcc-amd64-mingw-exec, and 0/293 in t32.exe and 0/290 in w32.exe (a 32-bit
 * image is `is64: false`, i.e. the old default, so it cannot move). Emitted C
 * is byte-identical on all 975 of those functions today, because nothing
 * downstream reads `IRConst.size` — which is exactly why this needs a guard
 * rather than an output assertion: there is no emitted text to regress, so
 * dropping the argument again would be invisible to every other test in the
 * repo, including the end-to-end `pipeline.test.ts`.
 *
 * Asserted against the source text because the argument has no observable
 * effect on `decompileFunction`'s return value; the behaviour it selects is
 * asserted directly against `structureCFG` below. `flatSource` strips comments
 * and flattens whitespace so the guard survives `biome format`, following
 * `src/mcp/__tests__/plumbing.test.ts`.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { structureCFG } from "../structure";
import { irConst, irReg } from "../ir";
import type { IRStmt } from "../ir";
import type { BasicBlock } from "../../cfg";
import type { Instruction } from "../../types";

const DECOMPILE_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function flatSource(file: string): string {
  return readFileSync(join(DECOMPILE_DIR, file), "utf-8")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/\s+/g, " ");
}

describe("pipeline.ts — is64 reaches structureCFG (peek-a-bin-h0us)", () => {
  it("passes is64 as structureCFG's fifth argument", () => {
    const text = flatSource("pipeline.ts");
    expect(
      /structureCFG\(\s*blocks\s*,\s*loops\s*,\s*liftedBlocks\s*,\s*jumpTables\s*,\s*is64\s*\)/.test(
        text,
      ),
      "src/disasm/decompile/pipeline.ts must call " +
        "structureCFG(blocks, loops, liftedBlocks, jumpTables, is64). The parameter defaults to " +
        "false, so omitting it compiles and emits identical-looking C while describing every " +
        "64-bit compare with 32-bit operand widths (peek-a-bin-h0us).",
    ).toBe(true);
  });
});

/** The behaviour the argument selects, asserted where it is observable. */
describe("structureCFG — is64 selects the operand widths of a branch condition", () => {
  const BASE = 0x140001000;
  const insn = (mnemonic: string, opStr: string, address: number): Instruction => ({
    address,
    mnemonic,
    opStr,
    size: 4,
    bytes: new Uint8Array(4),
  });

  /** `cmp rax, 0x10 / jne <exit>`, then a body block and an exit block. */
  function blocks(): BasicBlock[] {
    return [
      {
        id: 0,
        startAddr: BASE,
        endAddr: BASE + 8,
        insns: [
          insn("cmp", "rax, 0x10", BASE),
          insn("jne", `0x${(BASE + 0x200).toString(16)}`, BASE + 4),
        ],
        succs: [2, 1],
        preds: [],
      },
      {
        id: 1,
        startAddr: BASE + 0x100,
        endAddr: BASE + 0x104,
        insns: [insn("nop", "", BASE + 0x100)],
        succs: [2],
        preds: [0],
      },
      {
        id: 2,
        startAddr: BASE + 0x200,
        endAddr: BASE + 0x204,
        insns: [insn("ret", "", BASE + 0x200)],
        succs: [],
        preds: [0, 1],
      },
    ];
  }

  const lifted = () =>
    new Map<number, IRStmt[]>([
      [0, []],
      [1, [{ kind: "assign", dest: irReg("eax", 4), src: irConst(1) }]],
      [2, [{ kind: "return" }]],
    ]);

  function conditionOf(is64: boolean) {
    const out = structureCFG(blocks(), [], lifted(), new Map(), is64);
    const found = JSON.stringify(out).match(/"right":\{"kind":"const","value":16,"size":(\d+)\}/);
    return found ? Number(found[1]) : null;
  }

  it("widens a 64-bit compare's immediate to 8 bytes", () => {
    expect(conditionOf(true)).toBe(8);
  });

  it("keeps a 32-bit compare's immediate at 4 bytes", () => {
    expect(conditionOf(false)).toBe(4);
  });
});
