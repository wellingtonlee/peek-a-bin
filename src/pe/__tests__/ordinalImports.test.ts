/**
 * The `Ordinal_<n>` spelling, and why it has three functions rather than a
 * template literal at each site.
 *
 * IT IS A WIRE FORMAT. `parsePE` writes it into `PEFile.imports[].functions`,
 * and `computeImphash` **parses it back out** to decide whether an entry is an
 * ordinal at all. Those two live in different files, neither points at the
 * other, and nothing in the type system connects them — so before
 * `ORDINAL_IMPORT_PREFIX` existed, respelling the parser's output changed every
 * affected imphash **silently**: an ordinal import would fall through imphash's
 * ordinal branch into its by-name branch and hash the literal display text. A
 * hash has no runtime symptom, because it is only ever compared with another
 * tool's answer, so the failure mode is a corpus match that stops matching.
 *
 * The last test here is the one that states that property directly: the digest
 * must not depend on how the spelling is spelled.
 */

import { describe, expect, it } from "vitest";
import { computeImphash } from "../metadata";
import {
  formatOrdinalImport,
  ORDINAL_IMPORT_PREFIX,
  parseOrdinalImport,
  resolveOrdinal,
} from "../ordinalTables";

describe("the ordinal import spelling", () => {
  it("round-trips", () => {
    for (const n of [0, 1, 42, 115, 60000, 65535]) {
      expect(parseOrdinalImport(formatOrdinalImport(n))).toBe(n);
    }
  });

  it("reads a named import as a name, not as an ordinal", () => {
    expect(parseOrdinalImport("CreateFileW")).toBeNull();
    expect(parseOrdinalImport("")).toBeNull();
  });

  it("refuses a malformed tail rather than answering NaN", () => {
    // Callers treat null as "this is a name". Answering NaN here would make
    // `ord${NaN}` a plausible-looking imphash component, which is worse than
    // treating the string as the name it appears to be — and is what the
    // hand-written `parseInt` in `computeImphash` used to do before it was
    // guarded by an `isNaN` check three lines further down.
    expect(parseOrdinalImport(ORDINAL_IMPORT_PREFIX)).toBeNull();
    expect(parseOrdinalImport(`${ORDINAL_IMPORT_PREFIX}abc`)).toBeNull();
    expect(parseOrdinalImport(`${ORDINAL_IMPORT_PREFIX}12x`)).toBeNull();
    expect(parseOrdinalImport(`${ORDINAL_IMPORT_PREFIX}-1`)).toBeNull();
  });
});

describe("resolveOrdinal", () => {
  it("keys on the library name WITH its extension, and case-insensitively", () => {
    expect(resolveOrdinal("ws2_32.dll", 115)).toBe("WSAStartup");
    expect(resolveOrdinal("WS2_32.DLL", 115)).toBe("WSAStartup");
    // Without the extension it is not a key at all — the tables are keyed the
    // way pefile keys `ordlookup`.
    expect(resolveOrdinal("ws2_32", 115)).toBeUndefined();
  });

  it("keeps ws2_32 and wsock32 apart where they disagree", () => {
    // The reason each keeps its own table: four ordinals mean different
    // functions in the two DLLs, so a merged table would be wrong for one of
    // them and the imphash would match nothing.
    expect(resolveOrdinal("ws2_32.dll", 10)).toBe("ioctlsocket");
    expect(resolveOrdinal("wsock32.dll", 10)).toBe("inet_addr");
  });

  it("answers undefined for a DLL or an ordinal the tables do not cover", () => {
    expect(resolveOrdinal("kernel32.dll", 256)).toBeUndefined();
    expect(resolveOrdinal("ws2_32.dll", 60000)).toBeUndefined();
  });
});

describe("the imphash does not depend on how the spelling is spelled", () => {
  /**
   * THE PROPERTY THE SHARED DECLARATION EXISTS FOR, asserted rather than
   * described. Both fixtures are built through `formatOrdinalImport`, so this
   * test's input follows the constant wherever it goes; `computeImphash` reads
   * it back through `parseOrdinalImport`. Change the prefix and both move
   * together and these digests hold — which is exactly what did NOT happen when
   * the writer used a template literal and the reader used `startsWith`.
   */
  it("resolves through the same table computeImphash uses", () => {
    const viaSpelling = computeImphash({
      imports: [
        {
          libraryName: "WS2_32.dll",
          functions: [formatOrdinalImport(115), formatOrdinalImport(23)],
          iatAddresses: [],
        },
      ],
    });
    // pefile canonicalizes a resolved ordinal to its *name*, so an image
    // importing by ordinal and one importing the same functions by name have
    // the same imphash. That is a property of pefile, not a coincidence here.
    const viaNames = computeImphash({
      imports: [
        { libraryName: "WS2_32.dll", functions: ["WSAStartup", "socket"], iatAddresses: [] },
      ],
    });
    expect(viaSpelling).toBe(viaNames);
  });

  it("still renders an uncovered ordinal as pefile's ord<N>", () => {
    const uncovered = computeImphash({
      imports: [
        { libraryName: "SOMELIB.dll", functions: [formatOrdinalImport(42)], iatAddresses: [] },
      ],
    });
    const asName = computeImphash({
      imports: [{ libraryName: "SOMELIB.dll", functions: ["ord42"], iatAddresses: [] }],
    });
    expect(uncovered).toBe(asName);
  });
});
