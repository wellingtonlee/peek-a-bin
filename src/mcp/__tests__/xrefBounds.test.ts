/**
 * The MCP server's per-instruction xref map is bounded by the loaded image.
 *
 * `buildTypedXrefMap`'s fallback arm reads any large `0x…` token in an operand
 * as a data reference. It is bounded by an optional `imageBounds` — implemented
 * and tested in `src/disasm/functionDetect.ts` (peek-a-bin-jfp) and reachable
 * from nowhere until it was plumbed here (peek-a-bin-2ap). `FileSession` is the
 * one place on this side that holds the optional header, so it is the one place
 * that can supply it.
 *
 * Measured through `FileSession.loadFile` on the real images: t64.exe 856 data
 * xrefs → 551, all 305 removed ones outside the image and no in-image reference
 * touched; t32.exe 318 removed, w64.exe 286, t64-arm.exe 239, w64-arm.exe 211,
 * gcc-amd64-mingw-exec 115.
 *
 * Asserted against the source text rather than by loading a file, for the
 * reason `importGraph.test.ts` documents and `plumbing.test.ts` follows:
 * `../session` and `../disasm` pull in Capstone WASM, and this suite is fast
 * and stable precisely because nothing it loads ever reaches them. The
 * behaviour itself is covered without WASM in
 * `src/disasm/__tests__/functionDetect.test.ts` (the bound) and
 * `src/workers/__tests__/dispatch.test.ts` (the same route on the worker side).
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MCP_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Source with comments removed and whitespace flattened, so these guards
 *  survive reformatting — a drift guard that fails on `biome format` is worse
 *  than no guard at all. */
function flatSource(file: string): string {
  return readFileSync(join(MCP_DIR, file), "utf-8")
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/\s+/g, " ");
}

describe("buildXrefMap — the bound is forwarded, not dropped", () => {
  const text = flatSource("disasm.ts");

  it("takes an optional imageBounds", () => {
    expect(
      /export function buildXrefMap\( instructions: Instruction\[\], imageBounds\?: ImageBounds, \)/.test(
        text,
      ),
      "src/mcp/disasm.ts's buildXrefMap must accept imageBounds, or the bound in " +
        "buildTypedXrefMap is unreachable from the MCP server.",
    ).toBe(true);
  });

  it("hands it straight to buildTypedXrefMap", () => {
    expect(
      /return buildTypedXrefMap\(instructions, imageBounds\);/.test(text),
      "src/mcp/disasm.ts's buildXrefMap must pass imageBounds through; accepting it and " +
        "dropping it is the same shipped behaviour with a more convincing signature.",
    ).toBe(true);
  });
});

describe("FileSession.loadFile — the optional header bounds the xref map", () => {
  const session = flatSource("session.ts");

  it("passes the image base and size to buildXrefMap", () => {
    expect(
      /buildXrefMap\(instructions, \{ base: imageBase, size: pe\.optionalHeader\.sizeOfImage, \}\)/.test(
        session,
      ),
      "src/mcp/session.ts must bound the xref map by the mapped image " +
        "({ base: imageBase, size: pe.optionalHeader.sizeOfImage }). Without it every MCP " +
        "client sees bitmasks and status constants reported as data references to addresses " +
        "the file does not contain — 305 of them on t64.exe (peek-a-bin-jfp).",
    ).toBe(true);
  });

  it("does not call it with the instructions alone", () => {
    expect(/buildXrefMap\(instructions\)/.test(session)).toBe(false);
  });
});
