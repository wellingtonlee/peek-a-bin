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

import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import type { ImageArch } from "../../disasm/arch";
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
    const arch: ImageArch = file.arch;

    expect(arch).toBe("arm64");
    expect(source("session.ts")).toMatch(/^\s*arch,$/m);
  });
});

/**
 * peek-a-bin-x7b — an image whose instruction set has no decoder here.
 *
 * The split is deliberate and this suite is where it can be checked without
 * WASM. `hybridDisassembleBytes` and `buildXrefs` *throw* for such an image,
 * because their entire output is instructions and a short answer from them is
 * the silent failure peek-a-bin-cen removed. But `loadFile` calls both, so left
 * unguarded a throw would fail the whole load and discard the headers, sections,
 * imports, exports, resources and strings the parser reads perfectly well for an
 * ARM32 file. `detectFunctionsFromBytes` needs no guard: it answers empty with
 * `omitted` set, which is the contract `DetectResult` states.
 */
describe("FileSession — an image with no decoder still loads", () => {
  const text = source("session.ts");
  const flat = text.replace(/\s+/g, " ");

  it("decides once whether the image is decodable", () => {
    expect(
      flat,
      'src/mcp/session.ts must derive a single `decodable` flag from arch !== "unsupported".',
    ).toMatch(/const decodable = arch !== "unsupported"/);
  });

  it.each(["hybridDisassembleBytes", "buildXrefs"])(
    "does not call %s when there is nothing to decode",
    (call) => {
      const at = text.indexOf(`${call}(`);
      expect(at, `${call} is not called in session.ts at all`).toBeGreaterThan(0);
      // The guard is the ternary immediately around the call, either polarity.
      const around = text.slice(Math.max(0, at - 600), at).replace(/\s+/g, " ");
      expect(
        /\bdecodable\b/.test(around),
        `src/mcp/session.ts calls ${call} unguarded. It throws for an image with no decoder, ` +
          "so an unguarded call fails loadFile outright and throws away everything the PE " +
          "parser did read correctly (peek-a-bin-x7b).",
      ).toBe(true);
    },
  );

  it("leaves function detection unguarded, because it answers rather than throwing", () => {
    const at = text.indexOf("detectFunctionsFromBytes(");
    const around = text.slice(Math.max(0, at - 400), at).replace(/\s+/g, " ");
    expect(
      /\bdecodable\b/.test(around),
      "detectFunctionsFromBytes returns an empty DetectResult with `omitted` set for an " +
        "unsupported image; guarding it here would duplicate that and lose the field.",
    ).toBe(false);
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

  /**
   * peek-a-bin-x7b. The unsupported arm has to come *first* in each of these:
   * with `arch === "arm64"` checked first the remaining `else` is the x86 path,
   * which is exactly how an ARM32 image was decoded as x86 in the first place.
   */
  it.each(["disassembleBytes", "detectFunctionsFromBytes", "hybridDisassembleBytes", "buildXrefs"])(
    "declines in %s before it can fall through to x86",
    (fn) => {
      const text = source("disasm.ts");
      const body = text.slice(text.indexOf(`export function ${fn}`));
      const inner = body.slice(0, body.indexOf("\n}"));

      expect(
        inner,
        `src/mcp/disasm.ts's ${fn} has no unsupported-architecture arm, so an ARM32/Thumb ` +
          "image falls through to the x86 grammar and is answered with fiction.",
      ).toMatch(/arch === "unsupported"/);
      expect(
        inner.indexOf('arch === "unsupported"'),
        `${fn} checks arm64 before unsupported; the unsupported case must be decided first.`,
      ).toBeLessThan(inner.indexOf('arch === "arm64"'));
    },
  );

  it("throws from the three whose whole output is instructions, and answers from detection", () => {
    const text = source("disasm.ts");
    const bodyOf = (fn: string) => {
      const b = text.slice(text.indexOf(`export function ${fn}`));
      return b.slice(0, b.indexOf("\n}"));
    };

    for (const fn of ["disassembleBytes", "hybridDisassembleBytes", "buildXrefs"]) {
      expect(bodyOf(fn), `${fn} must throw rather than return a short list`).toMatch(
        /if \(arch === "unsupported"\)[\s\S]{0,120}throw new Error\(unsupportedArchMessage\(/,
      );
    }
    // Detection is the exception, and `omitted` is what makes it an honest one.
    const detect = bodyOf("detectFunctionsFromBytes");
    expect(detect).not.toMatch(/if \(arch === "unsupported"\)[\s\S]{0,200}throw/);
    expect(detect).toMatch(/omitted: \[\s*"call-targets",/);
  });
});
