/**
 * MCP resource registrations (`pe://{fileId}/*`).
 *
 * Driven the same way as the tools: `registerResources` is the module's only
 * export, so the handlers it hands the server are captured and called directly.
 * The PE behind each resource is a real parsed fixture, so the JSON bodies are
 * checked against values that actually came out of the parser.
 */

import { describe, it, expect } from "vitest";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { McpError } from "@modelcontextprotocol/sdk/types.js";
import { registerResources } from "../resources";
import { stubSession } from "./harness";
import { parsePE } from "../../pe/parser";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import type { FileSession } from "../session";

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

    const list = imports as unknown as {
      library: string;
      functions: { name: string; iatAddress?: string }[];
    }[];
    expect(list).toHaveLength(1);
    expect(list[0].library).toBe("KERNEL32.dll");
    expect(list[0].functions.map((f) => f.name)).toEqual(["Sleep", "Ordinal_7"]);
    // Both entries carry an IAT address, one pointer apart.
    const addrs = list[0].functions.map((f) => Number(f.iatAddress));
    expect(addrs[0]).toBeGreaterThan(IMAGE_BASE);
    expect(addrs[1] - addrs[0]).toBe(8);
  });
});

describe("pe://{fileId}/exports", () => {
  it("lists exports with hex addresses", async () => {
    const { session } = stubSession({ pe: samplePE() } as never);
    const exports = await body(captureResources(session).get("pe-exports")!, "exports");

    // Ordinals are Base-biased (Base 1), matching dumpbin.
    expect(exports).toEqual([
      { name: "Start", ordinal: 1, address: "0x1000" },
      { name: "Stop", ordinal: 2, address: "0x1100" },
    ]);
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

    expect(strings).toEqual([{ address: "0x140002000", value: "Hello", type: "ascii" }]);
  });

  it("carries an explicit utf16le type through", async () => {
    const { session } = stubSession({
      pe: samplePE(),
      stringMap: new Map([[0x140002000, "Wide"]]),
      stringTypes: new Map([[0x140002000, "utf16le"]]),
    } as never);
    const strings = await body(captureResources(session).get("pe-strings")!, "strings");

    expect(strings).toEqual([{ address: "0x140002000", value: "Wide", type: "utf16le" }]);
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
