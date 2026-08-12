/**
 * peek-a-bin-amu — the MCP server's side of architecture selection.
 *
 * `FileSession.loadFile` used to pass `pe.is64` and nothing else to the
 * disassembler, and `is64` is the PE32+ optional-header magic: an ARM64 image
 * is PE32+, so it was analysed as x86-64 and yielded zero instructions from 419
 * correct `.pdata` function boundaries.
 *
 * Asserted against the source text rather than by loading a file, for the
 * reason `importGraph.test.ts` documents: `../session` and `../disasm` load
 * Capstone WASM at module scope, and this suite is fast and stable precisely
 * because it never reaches them. The behaviour these lines produce is covered
 * without WASM in `src/disasm/__tests__/arm64.test.ts` and
 * `src/workers/__tests__/dispatch.test.ts`, and end to end against t64-arm.exe
 * (0 -> 27428 instructions, 419/419 .pdata starts decoded).
 */

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import type { TargetArch } from "../../disasm/arch";
import type { AnalyzedFile } from "../session";

const MCP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const source = (file: string) => readFileSync(join(MCP_DIR, file), "utf-8");

describe("FileSession — architecture comes from the machine type", () => {
  it("derives the architecture from coffHeader.machine", () => {
    expect(
      source("session.ts"),
      "src/mcp/session.ts must call archForMachine(pe.coffHeader.machine). Selecting a " +
        "disassembler from pe.is64 alone reads an ARM64 image as x86-64 (peek-a-bin-amu).",
    ).toMatch(/archForMachine\(pe\.coffHeader\.machine\)/);
  });

  it("passes it to function detection and to disassembly", () => {
    const text = source("session.ts");
    const args = (call: string) =>
      text.slice(text.indexOf(call), text.indexOf(call) + 400).split("\n");

    for (const call of ["detectFunctionsFromBytes(", "hybridDisassembleBytes("]) {
      expect(
        args(call).some((line) => line.trim() === "arch,"),
        `src/mcp/session.ts computes the architecture but does not pass it to ${call}`,
      ).toBe(true);
    }
  });

  it("records it on the analyzed file, so an x86-only tool can decline", () => {
    // `arch` is the channel for that refusal: the decompiler and the stack
    // analyser are x86 grammars and produce confident nonsense, not an error,
    // when handed ARM64 instructions.
    const file: Pick<AnalyzedFile, "arch"> = { arch: "arm64" };
    const arch: TargetArch = file.arch;

    expect(arch).toBe("arm64");
    expect(source("session.ts")).toMatch(/^\s*arch,$/m);
  });
});

describe("MCP Capstone wrapper — opens the ARM64 decoder", () => {
  it("constructs a CS_ARCH_ARM64 handle alongside the x86 pair", () => {
    expect(
      source("disasm.ts"),
      "src/mcp/disasm.ts opens only x86 handles, so hybridDisassembleBytes has nothing to " +
        "decode ARM64 with.",
    ).toMatch(/new Capstone\(Const\.CS_ARCH_ARM64, Const\.CS_MODE_ARM\)/);
  });

  it("routes every entry point on the architecture, not on is64", () => {
    const text = source("disasm.ts");
    for (const fn of ["disassembleBytes", "detectFunctionsFromBytes", "hybridDisassembleBytes"]) {
      const body = text.slice(text.indexOf(`export function ${fn}`));
      expect(
        body.slice(0, body.indexOf("\n}")),
        `src/mcp/disasm.ts's ${fn} does not branch on arch, so ARM64 bytes reach the x86 path.`,
      ).toMatch(/arch === "arm64"/);
    }
  });
});
