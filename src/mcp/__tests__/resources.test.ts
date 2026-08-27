/**
 * MCP resource registrations (`pe://{fileId}/*`).
 *
 * Driven the same way as the tools: `registerResources` is the module's only
 * export, so the handlers it hands the server are captured and called directly.
 * The PE behind each resource is a real parsed fixture, so the JSON bodies are
 * checked against values that actually came out of the parser.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { describe, expect, it } from "vitest";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { registerResources } from "../resources";
import type { FileSession } from "../session";
import { stubSession } from "./harness";

type ResourceHandler = (
  uri: URL,
  vars: Record<string, unknown>,
) => Promise<{ contents: { uri: string; mimeType: string; text: string }[] }>;

function captureResources(session: FileSession): Map<string, ResourceHandler> {
  const handlers = new Map<string, ResourceHandler>();
  const server = {
    resource(name: string, _template: unknown, handler: ResourceHandler) {
      handlers.set(name, handler);
    },
  } as unknown as McpServer;

  registerResources(server, session);
  return handlers;
}

const IMAGE_BASE = 0x140000000;

/** A parsed PE with real import and export directories. */
function samplePE() {
  return parsePE(
    buildMinimalPE64({
      directories: {
        imports: [{ libraryName: "KERNEL32.dll", functions: [{ name: "Sleep" }, { ordinal: 7 }] }],
        exports: {
          dllName: "sample.dll",
          addresses: [0x1000, 0x1100],
          names: [
            { name: "Start", addressIndex: 0 },
            { name: "Stop", addressIndex: 1 },
          ],
        },
      },
    }),
  );
}

function read(handler: ResourceHandler, path: string) {
  return handler(new URL(`pe://sample/${path}`), { fileId: "sample" });
}

async function body(handler: ResourceHandler, path: string): Promise<unknown> {
  const result = await read(handler, path);
  return JSON.parse(result.contents[0].text);
}

describe("resource envelope", () => {
  it("echoes the request URI and declares application/json", async () => {
    const { session } = stubSession({ pe: samplePE() } as never);
    const result = await read(captureResources(session).get("pe-headers")!, "headers");

    expect(result.contents).toHaveLength(1);
    expect(result.contents[0].uri).toBe("pe://sample/headers");
    expect(result.contents[0].mimeType).toBe("application/json");
  });

  it.each([
    "pe-headers",
    "pe-sections",
    "pe-imports",
    "pe-exports",
    "pe-strings",
    "pe-functions",
    "pe-anomalies",
    "pe-driver",
  ])("%s throws McpError for an unknown fileId rather than returning a body", async (name) => {
    // resources/read has no isError channel, so an unknown file must fail the
    // JSON-RPC call — a successful read whose body is {"error": ...} would be
    // parsed by clients as PE data.
    const { session } = stubSession({ pe: samplePE() } as never);
    const handler = captureResources(session).get(name)!;

    await expect(handler(new URL("pe://missing/x"), { fileId: "missing" })).rejects.toThrow(
      McpError,
    );
    await expect(handler(new URL("pe://missing/x"), { fileId: "missing" })).rejects.toThrow(
      /not loaded/,
    );
  });
});

describe("pe://{fileId}/headers", () => {
  it("reports the parsed header fields with hex-formatted addresses", async () => {
    const { session } = stubSession({ pe: samplePE() } as never);
    const headers = await body(captureResources(session).get("pe-headers")!, "headers");

    expect(headers).toMatchObject({
      is64: true,
      imageBase: "0x140000000",
      addressOfEntryPoint: "0x1000",
      sectionAlignment: 0x1000,
      fileAlignment: 0x200,
    });
    expect(headers).toHaveProperty("numberOfSections", 2);
  });

  it("names the instruction set, which is not what is64 says (peek-a-bin-9b1)", async () => {
    // An ARM64 image is PE32+, so `is64: true` and a bare `machine` number leave
    // a client no way to know the decompile tool will decline on this file.
    const { session } = stubSession({ pe: samplePE(), arch: "arm64" } as never);
    const headers = await body(captureResources(session).get("pe-headers")!, "headers");

    expect(headers).toMatchObject({ is64: true, arch: "arm64" });
  });
});

describe("pe://{fileId}/sections", () => {
  it("lists each section with decoded characteristic flags", async () => {
    const { session } = stubSession({ pe: samplePE() } as never);
    const sections = await body(captureResources(session).get("pe-sections")!, "sections");

    const list = sections as unknown as { name: string; virtualAddress: string; flags: string[] }[];
    expect(list.map((s) => s.name)).toEqual([".text", ".rdata"]);
    expect(list[0].virtualAddress).toBe("0x1000");
    expect(list[0].flags).toContain("MEM_EXECUTE");
    expect(list[1].flags).not.toContain("MEM_EXECUTE");
    expect(list[1].flags).toContain("INITIALIZED_DATA");
  });
});

describe("pe://{fileId}/imports", () => {
  it("pairs each imported name with its IAT address", async () => {
    const { session } = stubSession({ pe: samplePE() } as never);
    const imports = await body(captureResources(session).get("pe-imports")!, "imports");

    const doc = imports as unknown as {
      incomplete?: string;
      libraries: { library: string; functions: { name: string; iatAddress?: string }[] }[];
    };
    // THE LIST IS UNDER A KEY so the response has somewhere to say it is short,
    // and the wrapper is unconditional — see the `incomplete` describe below.
    // A whole parse says nothing.
    expect(doc.incomplete).toBeUndefined();
    const list = doc.libraries;
    expect(list).toHaveLength(1);
    expect(list[0].library).toBe("KERNEL32.dll");
    expect(list[0].functions.map((f) => f.name)).toEqual(["Sleep", "Ordinal_7"]);
    // Both entries carry an IAT address, one pointer apart.
    const addrs = list[0].functions.map((f) => Number(f.iatAddress));
    expect(addrs[0]).toBeGreaterThan(IMAGE_BASE);
    expect(addrs[1] - addrs[0]).toBe(8);
  });

  it("names an ordinal the tables cover, and keeps the ordinal beside it", async () => {
    // The same `resolveOrdinal` the Imports tab and `computeImphash` use, so no
    // two surfaces of this tool can disagree about what ws2_32!115 is. The
    // ordinal is carried rather than folded away: the name is INFERRED FROM A
    // TABLE, not read out of the file, and an import by ordinal is a different
    // fact about a binary from an import by name.
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          imports: [
            { libraryName: "WS2_32.dll", functions: [{ ordinal: 115 }, { ordinal: 60000 }] },
          ],
        },
      }),
    );
    const { session } = stubSession({ pe } as never);
    const imports = (
      (await body(captureResources(session).get("pe-imports")!, "imports")) as unknown as {
        libraries: { functions: { name: string; ordinal?: number }[] }[];
      }
    ).libraries;

    expect(imports[0].functions[0]).toMatchObject({ name: "WSAStartup", ordinal: 115 });
    // The control, in the same library: ws2_32 has no 60000, so a rule that
    // invented a name for every ordinal would fail here and one that resolved
    // nothing would fail above. An unresolved entry reports no `ordinal` at all,
    // exactly as the tab shows no `#n` for it.
    expect(imports[0].functions[1].name).toBe("Ordinal_60000");
    expect(imports[0].functions[1].ordinal).toBeUndefined();
  });
});

describe("pe://{fileId}/exports", () => {
  it("lists exports with hex addresses", async () => {
    const { session } = stubSession({ pe: samplePE() } as never);
    const exports = await body(captureResources(session).get("pe-exports")!, "exports");

    // Ordinals are Base-biased (Base 1), matching dumpbin. The `exports` key and
    // the absent `incomplete` are the same shape decision as the imports
    // resource: `toEqual` on the whole document, so a stray key would fail here.
    expect(exports).toEqual({
      exports: [
        { name: "Start", ordinal: 1, address: "0x1000" },
        { name: "Stop", ordinal: 2, address: "0x1100" },
      ],
    });
  });
});

/**
 * THE ADMISSION ON THE TWO LIST RESOURCES.
 *
 * A cut-short import or export table is shaped exactly like a complete small
 * one, and these resources used to hand a client the bare array — the same defect
 * the browser's tabs had, on a surface whose consumer is an LLM that has no way
 * to notice a count looks small (`peek-a-bin-8pod`). The sentence, not a boolean,
 * is the channel: a consumer that has never heard of the field still cannot be
 * fooled by the value.
 */
describe("pe://{fileId}/imports and /exports — saying the list is short", () => {
  it("carries a sentence for a cut-short import table, and per library", async () => {
    const pe = samplePE();
    const short = {
      ...pe,
      importsTruncated: true,
      imports: [{ ...pe.imports[0], truncated: true }],
    };
    const { session } = stubSession({ pe: short } as never);
    const doc = (await body(
      captureResources(session).get("pe-imports")!,
      "imports",
    )) as unknown as {
      incomplete?: string;
      libraries: { incomplete?: string; functions: unknown[] }[];
    };

    expect(doc.incomplete).toContain("LOWER BOUND");
    // Per-library as well as whole-table: each descriptor has its own thunk
    // walk, so one library's list can be short while the rest are whole. The
    // whole-table fact is the one with no row to hang on.
    expect(doc.libraries[0].incomplete).toContain("lower bound");
    // The list is still THERE. An admission that replaced the answer would be
    // the mistake `analysisNotice`'s timeout kind exists to avoid.
    expect(doc.libraries[0].functions).toHaveLength(2);
  });

  it("marks the table without marking a library whose own list is whole", async () => {
    // The two flags are separate facts and the second must not be inferred from
    // the first: a descriptor walk that stopped at its cap leaves every library
    // it DID read complete, and saying otherwise would understate those lists.
    const { session } = stubSession({ pe: { ...samplePE(), importsTruncated: true } } as never);
    const doc = (await body(
      captureResources(session).get("pe-imports")!,
      "imports",
    )) as unknown as {
      incomplete?: string;
      libraries: { incomplete?: string }[];
    };
    expect(doc.incomplete).toBeDefined();
    expect("incomplete" in doc.libraries[0]).toBe(false);
  });

  it("carries a sentence for a cut-short export table", async () => {
    const { session } = stubSession({ pe: { ...samplePE(), exportsTruncated: true } } as never);
    const doc = (await body(
      captureResources(session).get("pe-exports")!,
      "exports",
    )) as unknown as {
      incomplete?: string;
      exports: unknown[];
    };
    expect(doc.incomplete).toContain("LOWER BOUND");
    expect(doc.exports).toHaveLength(2);
  });

  it("says nothing on either resource for a whole parse", async () => {
    // THE CONTROL, and the half that catches a fix which marks everything: an
    // ordinary binary must produce no `incomplete` key at all, on the
    // omit-rather-than-false rule `PEFile.importsTruncated` itself follows.
    const { session } = stubSession({ pe: samplePE() } as never);
    const handlers = captureResources(session);
    const imports = (await body(handlers.get("pe-imports")!, "imports")) as unknown as {
      libraries: { incomplete?: string }[];
    };
    const exports = (await body(handlers.get("pe-exports")!, "exports")) as unknown as object;

    expect("incomplete" in (imports as object)).toBe(false);
    expect("incomplete" in imports.libraries[0]).toBe(false);
    expect("incomplete" in exports).toBe(false);
  });
});

describe("pe://{fileId}/strings", () => {
  it("defaults an untyped string to ascii", async () => {
    const { session } = stubSession({
      pe: samplePE(),
      stringMap: new Map([[0x140002000, "Hello"]]),
      stringTypes: new Map(),
    } as never);
    const strings = await body(captureResources(session).get("pe-strings")!, "strings");

    // The list is under a key, and `incomplete` is absent for a scan that
    // covered everything — `toEqual` on the whole document, so a stray key fails
    // here.
    expect(strings).toEqual({
      strings: [{ address: "0x140002000", value: "Hello", type: "ascii", xrefCount: 0, xrefs: [] }],
    });
  });

  it("carries an explicit utf16le type through", async () => {
    const { session } = stubSession({
      pe: samplePE(),
      stringMap: new Map([[0x140002000, "Wide"]]),
      stringTypes: new Map([[0x140002000, "utf16le"]]),
    } as never);
    const strings = await body(captureResources(session).get("pe-strings")!, "strings");

    expect(strings).toEqual({
      strings: [
        { address: "0x140002000", value: "Wide", type: "utf16le", xrefCount: 0, xrefs: [] },
      ],
    });
  });

  it("says when the scan did not examine every byte the file holds", async () => {
    // THE ONE ADMISSION ORDINARY INPUT REACHES: `SECTION_SCAN_LIMIT` is 1 MiB
    // per section, so any large real binary is scanned short — every other row
    // in this family needs a crafted file (peek-a-bin-2py5).
    const pe = samplePE();
    const { session } = stubSession({
      pe: { ...pe, stringScan: { clippedSections: [".rdata"], unscannedBytes: 4096 } },
      stringMap: new Map([[0x140002000, "Hello"]]),
      stringTypes: new Map(),
    } as never);
    const doc = (await body(
      captureResources(session).get("pe-strings")!,
      "strings",
    )) as unknown as {
      incomplete?: string;
      strings: unknown[];
    };

    expect(doc.incomplete).toContain(".rdata");
    expect(doc.incomplete).toContain("LOWER BOUND");
    // The list is still there.
    expect(doc.strings).toHaveLength(1);
  });

  it("reports which code addresses reference each string (peek-a-bin-0d0)", async () => {
    // The browser's Strings tab has always shown this. On the MCP side the map
    // it comes from — `buildXrefs`'s stringXrefs — was computed by a function
    // nothing called, so every string here read as unreferenced.
    const { session } = stubSession({
      pe: samplePE(),
      stringMap: new Map([
        [0x140002000, "Used"],
        [0x140002010, "Unused"],
      ]),
      stringTypes: new Map(),
      stringXrefs: new Map([[0x140002000, [0x140001010, 0x140001040]]]),
    } as never);
    const strings = (
      (await body(captureResources(session).get("pe-strings")!, "strings")) as {
        strings: { value: string; xrefCount: number; xrefs: string[] }[];
      }
    ).strings;

    expect(strings[0]).toMatchObject({
      value: "Used",
      xrefCount: 2,
      xrefs: ["0x140001010", "0x140001040"],
    });
    expect(strings[1]).toMatchObject({ value: "Unused", xrefCount: 0, xrefs: [] });
  });
});

describe("pe://{fileId}/callgraph", () => {
  it("names both ends of every edge, preferring a rename", async () => {
    const { session } = stubSession({
      pe: samplePE(),
      functions: [
        { address: 0x140001000, name: "sub_1000", size: 16 },
        { address: 0x140001100, name: "sub_1100", size: 16 },
      ],
      renames: { [String(0x140001100)]: "decrypt" },
      callGraph: new Map([[0x140001000, [0x140001100, 0x140009999]]]),
    } as never);
    const graph = (await body(captureResources(session).get("pe-callgraph")!, "callgraph")) as {
      address: string;
      name: string;
      calls: { address: string; name: string }[];
    }[];

    expect(graph).toHaveLength(1);
    expect(graph[0]).toMatchObject({ address: "0x140001000", name: "sub_1000" });
    expect(graph[0].calls).toEqual([
      { address: "0x140001100", name: "decrypt" },
      // A target that is not a detected function still appears — an import
      // thunk or a tail-called stub — named by its address rather than dropped.
      { address: "0x140009999", name: "0x140009999" },
    ]);
  });

  it("throws McpError for an unknown fileId rather than returning a body", async () => {
    const { session } = stubSession({ pe: samplePE() } as never);
    const handler = captureResources(session).get("pe-callgraph")!;

    await expect(handler(new URL("pe://missing/callgraph"), { fileId: "missing" })).rejects.toThrow(
      McpError,
    );
  });
});

describe("pe://{fileId}/imports — xrefs", () => {
  it("counts the call sites that use each IAT entry (peek-a-bin-0d0)", async () => {
    const pe = samplePE();
    const iat = pe.imports[0].iatAddresses;
    const { session } = stubSession({
      pe,
      importXrefs: new Map([[iat[0], [0x140001020]]]),
    } as never);
    const imports = (
      (await body(captureResources(session).get("pe-imports")!, "imports")) as {
        libraries: { functions: { name: string; xrefCount: number; xrefs: string[] }[] }[];
      }
    ).libraries;

    expect(imports[0].functions[0]).toMatchObject({
      name: "Sleep",
      xrefCount: 1,
      xrefs: ["0x140001020"],
    });
    expect(imports[0].functions[1]).toMatchObject({ xrefCount: 0, xrefs: [] });
  });
});

describe("pe://{fileId}/functions", () => {
  it("defaults isThunk to false and omits an absent tail-call target", async () => {
    const { session } = stubSession({
      pe: samplePE(),
      functions: [{ address: 0x140001000, name: "sub_1000", size: 16 }],
    } as never);
    const functions = await body(captureResources(session).get("pe-functions")!, "functions");

    expect(functions).toEqual([
      { address: "0x140001000", name: "sub_1000", size: 16, isThunk: false },
    ]);
  });

  it("hex-formats a tail-call target when present", async () => {
    const { session } = stubSession({
      pe: samplePE(),
      functions: [
        {
          address: 0x140001000,
          name: "thunk",
          size: 6,
          isThunk: true,
          tailCallTarget: 0x140002000,
        },
      ],
    } as never);
    const functions = await body(captureResources(session).get("pe-functions")!, "functions");

    expect(functions).toEqual([
      {
        address: "0x140001000",
        name: "thunk",
        size: 6,
        isThunk: true,
        tailCallTarget: "0x140002000",
      },
    ]);
  });
});

describe("pe://{fileId}/anomalies and /driver", () => {
  it("passes anomalies through verbatim", async () => {
    const anomalies = [{ severity: "high", title: "RWX section", detail: ".text is writable" }];
    const { session } = stubSession({ pe: samplePE(), anomalies } as never);

    expect(await body(captureResources(session).get("pe-anomalies")!, "anomalies")).toEqual(
      anomalies,
    );
  });

  it("passes driver info through verbatim", async () => {
    const driverInfo = {
      isDriver: true,
      isWDM: false,
      kernelModules: ["ntoskrnl.exe"],
      kernelImportCount: 3,
      reasons: ["imports ntoskrnl"],
    };
    const { session } = stubSession({ pe: samplePE(), driverInfo } as never);

    expect(await body(captureResources(session).get("pe-driver")!, "driver")).toEqual(driverInfo);
  });
});
