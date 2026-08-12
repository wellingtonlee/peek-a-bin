/**
 * The MCP server's side of two capabilities that existed but had no caller.
 *
 *  * peek-a-bin-g17 — `detectFunctions` reads an x64 switch's jump table only
 *    if it is given the section the table lives in. `.rdata`, always, on x64.
 *    `FileSession.loadFile` holds the whole buffer and the section table, so it
 *    is the one place that can supply them.
 *  * peek-a-bin-aq5 — `buildArm64Xrefs` returns exactly what `buildAllXrefs`
 *    returns; `buildXrefs`'s ARM64 branch returned four empty arrays, so an
 *    ARM64 image had no string, import, data or call-graph xrefs at all.
 *
 * Asserted against the source text rather than by loading a file, for the
 * reason `importGraph.test.ts` documents and `arch.test.ts` follows: `../session`
 * and `../disasm` pull in Capstone WASM, and this suite is fast and stable
 * precisely because nothing it loads ever reaches them. The behaviour these
 * lines produce is covered without WASM in `src/workers/__tests__/dispatch.test.ts`
 * (the same two routes on the worker side) and `src/disasm/__tests__/dataWindows.test.ts`,
 * and end to end on real images: a hand-built x64 PE with its table in `.rdata`
 * goes from 2 jump tables to 3 through `FileSession.loadFile`, and t64-arm.exe
 * from four empty arrays to 81 string refs / 194 import refs / 1259 call edges
 * / 378 data refs.
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

describe("FileSession — the data sections reach function detection", () => {
  it("passes dataWindows built from the loaded buffer to detectFunctionsFromBytes", () => {
    const text = flatSource("session.ts");
    const call = text.slice(text.indexOf("detectFunctionsFromBytes("));

    expect(
      /dataWindows:\s*buildDataWindows\(\s*buffer\s*,\s*pe\.sections\s*,\s*imageBase\s*\)/.test(
        call,
      ),
      "src/mcp/session.ts must hand detectFunctionsFromBytes the image's data sections " +
        "(dataWindows: buildDataWindows(buffer, pe.sections, imageBase)). Without them the x64 " +
        "RVA jump tables that live in .rdata cannot be read, and every switch in an x64 binary " +
        "decompiles as a bare bounds check with its cases missing (peek-a-bin-g17).",
    ).toBe(true);
  });

  it("imports the builder for value, not as a type", () => {
    expect(flatSource("session.ts")).toMatch(
      /import \{ buildDataWindows \} from "\.\.\/disasm\/dataWindows"/,
    );
  });
});

describe("detectFunctionsFromBytes — its options mirror the detector's", () => {
  it("accepts dataWindows", () => {
    // Its options type is a structural copy of `detectFunctions`'; a field
    // missing here is a field no MCP caller can pass.
    expect(
      /dataWindows\?: DataWindow\[\]/.test(flatSource("disasm.ts")),
      "src/mcp/disasm.ts's detectFunctionsFromBytes must accept dataWindows, or the option " +
        "exists on the detector and is unreachable from the MCP server.",
    ).toBe(true);
  });
});

describe("buildXrefs — ARM64 goes to the A64 reader", () => {
  const text = flatSource("disasm.ts");
  const arm64Branch = text.slice(
    text.indexOf("export function buildXrefs("),
    text.indexOf("const cs = is64 ? cs64 : cs32;"),
  );

  it("calls buildArm64Xrefs instead of returning empty maps", () => {
    expect(
      /buildArm64Xrefs\(/.test(arm64Branch),
      "src/mcp/disasm.ts's buildXrefs must route ARM64 to buildArm64Xrefs. Returning empty " +
        "arrays there discards 81 string refs, 194 import refs, 1259 call edges and 378 data " +
        "refs on t64-arm.exe alone (peek-a-bin-aq5).",
    ).toBe(true);
  });

  it("no longer answers an ARM64 image with four empty arrays", () => {
    expect(/stringXrefs: \[\] as \[number, number\[\]\]\[\]/.test(arm64Branch)).toBe(false);
  });

  it("still keeps the x86 grammar off ARM64 bytes", () => {
    // The empty-array branch was honest about one thing: `buildAllXrefs` run
    // over A64 bytes invents references. Whatever replaces it must not be that.
    const callsX86Builder = /buildAllXrefs\(/.test(arm64Branch);
    expect(
      callsX86Builder,
      "buildXrefs must not run buildAllXrefs — an x86 operand grammar — over ARM64 bytes.",
    ).toBe(false);
  });

  it("gets its instructions from the A64 sweep, not from a second x86 decode", () => {
    expect(/disassembleArm64\(/.test(arm64Branch)).toBe(true);
  });
});

describe("buildXrefs has a caller — the whole-image maps reach the session (peek-a-bin-0d0)", () => {
  // `buildXrefs` was written, routed for ARM64 and then never called: the MCP
  // server built only `buildXrefMap` (per-instruction refs), so no client could
  // ask who referenced a string, an import or a data address, and there was no
  // call graph on any architecture. Asserted against the source for the reason
  // this file's docstring gives — loading `../session` pulls in Capstone WASM.
  const session = flatSource("session.ts");
  const call = session.slice(session.indexOf("buildXrefs("));

  it("FileSession.loadFile calls buildXrefs", () => {
    expect(
      /import \{[^}]*\bbuildXrefs\b[^}]*\} from "\.\/disasm"/.test(session),
      "src/mcp/session.ts must import buildXrefs for value; without a caller the whole-image " +
        "string, import and data xrefs and the call graph are computed nowhere on this side.",
    ).toBe(true);
    // Written as `!decodable ? <four empty maps> : buildXrefs(…)` since
    // peek-a-bin-x7b: `buildXrefs` throws for an image whose architecture has
    // no decoder, and an unguarded call would fail the entire load rather than
    // just the xrefs. What this guards is unchanged — the call is reached from
    // `loadFile` and its result is what `allXrefs` binds.
    expect(/const allXrefs = [^;]*\bbuildXrefs\(/.test(session)).toBe(true);
  });

  it("hands it the string addresses, the IAT addresses, the functions and the data sections", () => {
    expect(/Array\.from\(stringMap\.keys\(\)\)/.test(call)).toBe(true);
    expect(/iatAddrs/.test(call)).toBe(true);
    expect(/functions\.map\(/.test(call)).toBe(true);
    expect(/dataSectionRanges\(pe\.sections, imageBase\)/.test(call)).toBe(true);
  });

  it("hands it the instructions it already decoded, so ARM64 does not sweep .text twice", () => {
    // 362 ms against 22 ms for t64-arm.exe's 110 KiB / 27428 instructions, i.e.
    // the whole added cost of this step on ARM64 is the second sweep, not the
    // xref building (peek-a-bin-kis). x86 ignores the argument: buildAllXrefs
    // owns its own decode.
    const args = call.slice(0, call.indexOf(");"));
    expect(
      /\binstructions\b/.test(args),
      "src/mcp/session.ts must pass its already-decoded instructions to buildXrefs.",
    ).toBe(true);
  });

  it("stores all four maps on the AnalyzedFile", () => {
    for (const field of ["stringXrefs", "importXrefs", "dataXrefs", "callGraph"]) {
      expect(
        new RegExp(`${field}: new Map\\(allXrefs\\.${field}\\)`).test(session),
        `src/mcp/session.ts must store allXrefs.${field} on the AnalyzedFile.`,
      ).toBe(true);
    }
  });
});

describe("the tools and resources expose the maps (peek-a-bin-0d0)", () => {
  it("get_xrefs reports string, import and data references and both call directions", () => {
    const tools = flatSource("tools.ts");
    for (const field of ["stringRefs", "importRefs", "dataRefs", "calls", "calledBy"]) {
      expect(new RegExp(`${field}:`).test(tools), `get_xrefs must report ${field}`).toBe(true);
    }
  });

  it("registers a call-graph tool and resource", () => {
    expect(/"get_call_graph"/.test(flatSource("tools.ts"))).toBe(true);
    expect(/pe:\/\/\{fileId\}\/callgraph/.test(flatSource("resources.ts"))).toBe(true);
  });
});
