/**
 * peek-a-bin-j4uk.2 — the units of the seed bag `FileSession.loadFile` builds.
 *
 * Every address in the options object handed to `detectFunctionsFromBytes` is a
 * **VA**, because `baseAddress` is: `entryPoint`, `pdataFunctions` and
 * `handlerAddresses` all add `imageBase` on the way in. `ExportEntry.address`
 * is an **RVA** (see its docstring in `pe/types.ts`) and was passed RAW, so
 * every export seed fell outside `[textBase, textBase + len)` and the detector
 * dropped it — no seed, no name. `App.tsx` converts, so the browser and this
 * path had been detecting functions from different seed sets, and
 * `corpus/sweep.ts` loads through this same `FileSession`.
 *
 * `tlsDirectory.callbacks` is the opposite case landed in the same commit: the
 * format writes those pointers image-based and `parseTLSDirectory` keeps them,
 * so that one must NOT be converted. Both directions are asserted here because
 * the hazard is that the two look identical — both `number[]`-shaped fields of
 * one options object, neither held to a unit by anything in the type system.
 *
 * Two halves, for two different reasons:
 *
 *  - The RUNTIME half runs the real parser over a real fixture and the real
 *    `detectFunctions` over its output, so the claim "an RVA seed is dropped"
 *    is measured rather than reasoned. It needs no Capstone: detection answers
 *    from the seed tables with a null decoder, which is the whole point of
 *    `DetectResult.omitted`.
 *  - The STATIC half is asserted against `session.ts`' source text, on
 *    `seeds.test.ts`' model: importing `../session` for value pulls
 *    `../disasm` — and `capstone-wasm` with it — into this suite, which
 *    `importGraph.test.ts` exists to keep out. Nothing observable at runtime
 *    distinguishes the two spellings on a corpus binary anyway: all six are
 *    EXEs with zero exports and no DLL exists on this machine, so no gate here
 *    could have caught the defect and none can catch its return.
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { type DisasmContext, detectFunctions } from "../../disasm/functionDetect";
import { buildMinimalPE32 } from "../../pe/__tests__/fixtures";
import { IMAGE_SCN_CNT_CODE, IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ } from "../../pe/constants";
import { parsePE } from "../../pe/parser";

const SESSION = resolve(dirname(fileURLToPath(import.meta.url)), "..", "session.ts");

const IMAGE_BASE = 0x00400000;
const TEXT_RVA = 0x1000;
const TEXT_LEN = 0x100;
/** The RVA the fixture's one export resolves to, inside `.text`. */
const EXPORT_RVA = TEXT_RVA + 0x10;
/** The callback VA the fixture's TLS directory registers, inside `.text`. */
const CALLBACK_VA = IMAGE_BASE + TEXT_RVA + 0x40;

/** A PE32 with a real `.text`, one named export in it, and one TLS callback. */
function fixture(): ArrayBuffer {
  return buildMinimalPE32({
    imageBase: IMAGE_BASE,
    sections: [
      {
        name: ".text",
        virtualAddress: TEXT_RVA,
        virtualSize: TEXT_LEN,
        data: new Uint8Array(TEXT_LEN).fill(0xcc),
        characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
      },
    ],
    directories: {
      exports: {
        dllName: "seed.dll",
        addresses: [EXPORT_RVA],
        names: [{ name: "SeededExport", addressIndex: 0 }],
      },
      tls: { callbacks: [CALLBACK_VA] },
    },
  });
}

/** Detection with no decoder: the seed tables are all it answers from. */
function ctxOf(): DisasmContext {
  return {
    cs32: null,
    cs64: null,
    stringMap: new Map(),
    iatMap: new Map(),
    driverMode: false,
  };
}

/** Strip comments, so prose inside the argument list cannot unbalance the scan. */
function stripComments(source: string): string {
  return source.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

/**
 * The argument list of `call`, from its opening parenthesis to the one that
 * closes it. Counted rather than found by the next `)`, and taken from
 * comment-stripped source: these arguments carry prose, and one unmatched
 * parenthesis in it — `[base, base + len)`, a bead id — cuts the list short and
 * passes a guard that should fail. Measured, not imagined: the first version of
 * this file did exactly that.
 */
function argumentsOf(source: string, call: string): string {
  const start = source.indexOf(call);
  if (start < 0) return "";
  let depth = 0;
  for (let i = start + call.length - 1; i < source.length; i++) {
    if (source[i] === "(") depth++;
    else if (source[i] === ")" && --depth === 0) return source.slice(start, i);
  }
  return source.slice(start);
}

describe("export seeds are RVAs and must be converted (peek-a-bin-j4uk.2)", () => {
  const pe = parsePE(fixture());
  const textBytes = new Uint8Array(TEXT_LEN);
  const textBase = IMAGE_BASE + TEXT_RVA;

  it("the parser really does answer an RVA, below the image base", () => {
    // The premise, measured rather than quoted from a docstring. If this ever
    // fails the two tests below stop meaning what they say.
    expect(pe.exports.map((e) => [e.name, e.address])).toEqual([["SeededExport", EXPORT_RVA]]);
    expect(pe.exports[0].address).toBeLessThan(IMAGE_BASE);
  });

  it("seeds and names the export when the address is converted", () => {
    const { functions } = detectFunctions(textBytes, textBase, false, ctxOf(), {
      exports: pe.exports.map((e) => ({ name: e.name, address: IMAGE_BASE + e.address })),
    });

    expect(functions.map((f) => [f.name, f.address])).toEqual([
      ["SeededExport", IMAGE_BASE + EXPORT_RVA],
    ]);
  });

  it("drops the export SILENTLY when the RVA is passed raw", () => {
    // The defect, reproduced. An RVA is numerically below `textBase`, so the
    // detector's bounds test rejects it and there is nothing anywhere to say
    // an export was lost — the function list is shaped exactly like a complete
    // one, which is the class `DetectResult.omitted` exists to prevent and
    // which a unit mix-up slips past because it reports no pass as skipped.
    const raw = detectFunctions(textBytes, textBase, false, ctxOf(), {
      exports: pe.exports.map((e) => ({ name: e.name, address: e.address })),
    });
    const converted = detectFunctions(textBytes, textBase, false, ctxOf(), {
      exports: pe.exports.map((e) => ({ name: e.name, address: IMAGE_BASE + e.address })),
    });

    expect(raw.functions).toEqual([]);
    // "Silently" is the load-bearing word, so it is asserted rather than
    // asserted about: `omitted` is the one channel a narrower answer has, and
    // it is BYTE-FOR-BYTE the same for the run that lost the export and the run
    // that kept it. Nothing in the result distinguishes them.
    expect(raw.omitted).toEqual(converted.omitted);
  });
});

describe("TLS callback seeds are already VAs and must NOT be converted", () => {
  const pe = parsePE(fixture());
  const textBytes = new Uint8Array(TEXT_LEN);
  const textBase = IMAGE_BASE + TEXT_RVA;

  it("the parser really does answer a VA, at or above the image base", () => {
    expect(pe.tlsDirectory?.callbacks).toEqual([CALLBACK_VA]);
    expect(CALLBACK_VA).toBeGreaterThan(IMAGE_BASE);
  });

  it("seeds the callback when the array is passed through verbatim", () => {
    const { functions } = detectFunctions(textBytes, textBase, false, ctxOf(), {
      tlsCallbacks: pe.tlsDirectory?.callbacks,
    });

    expect(functions.map((f) => f.address)).toEqual([CALLBACK_VA]);
  });

  it("drops the callback SILENTLY when imageBase is subtracted", () => {
    // The mirror image of the export defect, and the reason the unit is written
    // down at the option's own declaration: `imageBase - ` looks like the
    // conversion every neighbouring field performs.
    const { functions } = detectFunctions(textBytes, textBase, false, ctxOf(), {
      tlsCallbacks: pe.tlsDirectory?.callbacks?.map((cb) => cb - IMAGE_BASE),
    });

    expect(functions).toEqual([]);
  });
});

describe("FileSession's seed bag spells both units correctly", () => {
  const args = argumentsOf(
    stripComments(readFileSync(SESSION, "utf-8")),
    "detectFunctionsFromBytes(",
  );

  it("finds the call", () => {
    // A text scrape fails by matching nothing, so the population is asserted
    // before anything is asserted about it.
    expect(args).toContain("exports:");
    expect(args).toContain("tlsCallbacks:");
  });

  it("adds imageBase to every export address", () => {
    const line = args.split("\n").find((l) => l.includes("exports:")) ?? "";

    expect(
      line,
      `src/mcp/session.ts passes ExportEntry.address without adding imageBase. That is an RVA ` +
        `and every other address in this bag is a VA, so each export seed falls outside the ` +
        `code section and is dropped — no seed and no name, on the MCP path and on ` +
        `npm run corpus (peek-a-bin-j4uk.2).`,
    ).toMatch(/imageBase \+ e\.address/);
  });

  it("adds nothing to the TLS callback array", () => {
    const line = args.split("\n").find((l) => l.includes("tlsCallbacks:")) ?? "";

    expect(
      line,
      `src/mcp/session.ts performs arithmetic on tlsDirectory.callbacks. Those pointers are ` +
        `already VAs; converting them puts every callback outside the code section.`,
    ).toBe("        tlsCallbacks: pe.tlsDirectory?.callbacks,");
  });
});
