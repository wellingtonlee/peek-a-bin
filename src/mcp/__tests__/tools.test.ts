/**
 * Handler-level tests for the MCP tool layer.
 *
 * The pure helpers behind these tools live in `src/mcp/paths.ts` and are
 * unit-tested directly (`parseAddr.test.ts`, `exportPath.test.ts`). What is left
 * here is what only a real handler can show: that a rejected address records NO
 * annotation (the pre-hardening failure mode was a successfully applied
 * annotation at a NaN address), and that a rejected export path leaves nothing
 * on disk anywhere, including outside the export root.
 *
 * Everything reaching `registerTools` shares one file on purpose: each suite
 * that imports the harness re-imports the whole tool import graph.
 */

import { existsSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { unsupportedOnArch } from "../../disasm/arch";
import type { Xref } from "../../disasm/types";
import type { AnalyzedFile } from "../session";
import { captureTools, stubSession, type ToolHandler, textOf } from "./harness";

/** A session whose xref map has a single entry, keyed by `address`. */
function sessionWithXrefAt(address: number) {
  const xrefs: Xref[] = [{ from: 0x401234, type: "call" }];
  return stubSession({ xrefMap: new Map([[address, xrefs]]) });
}

/** Address spellings that must reach the session as the given number. */
const good: [string, string | number, number][] = [
  ["a 0x-prefixed hex string", "0x1234", 0x1234],
  ["bare hex without the prefix", "deadbe", 0xdeadbe],
  ["a number", 4096, 4096],
  ["zero", 0, 0],
];

/** Address spellings that must be refused before any mutation. */
const bad: [string, unknown][] = [
  ["a non-hex string", "not-an-address"],
  ["an empty string", ""],
  ["whitespace only", "   "],
  ["NaN", Number.NaN],
  ["Infinity", Number.POSITIVE_INFINITY],
  ["-Infinity", Number.NEGATIVE_INFINITY],
];

describe("address arguments — accepted spellings reach the handler", () => {
  it.each(good)("get_xrefs resolves %s", async (_label, address, expected) => {
    const { session } = sessionWithXrefAt(expected);
    const getXrefs = captureTools(session).get("get_xrefs")!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: "sample", address })));
    expect(result.address).toBe(`0x${expected.toString(16)}`);
    expect(result.xrefCount).toBe(1);
  });
});

describe("address arguments — rejected spellings mutate nothing", () => {
  it.each(bad)("rejects %s in get_xrefs", async (_label, address) => {
    const { session } = stubSession();
    const getXrefs = captureTools(session).get("get_xrefs")!;

    const result = await getXrefs({ fileId: "sample", address });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/invalid address/);
  });

  it.each(bad)("rejects %s in add_comment without recording anything", async (_label, address) => {
    const { session, calls } = stubSession();
    const addComment = captureTools(session).get("add_comment")!;

    const result = await addComment({ fileId: "sample", address, text: "hi" });

    expect(result.isError).toBe(true);
    expect(calls.setComment).toEqual([]);
    expect(calls.deleteComment).toEqual([]);
  });

  it.each(bad)(
    "rejects %s in rename_function without recording anything",
    async (_label, address) => {
      const { session, calls } = stubSession();
      const rename = captureTools(session).get("rename_function")!;

      const result = await rename({ fileId: "sample", address, name: "evil" });

      expect(result.isError).toBe(true);
      expect(calls.setRename).toEqual([]);
    },
  );

  it.each(bad)("rejects %s in add_bookmark without recording anything", async (_label, address) => {
    const { session, calls } = stubSession();
    const bookmark = captureTools(session).get("add_bookmark")!;

    const result = await bookmark({ fileId: "sample", address, label: "x" });

    expect(result.isError).toBe(true);
    expect(calls.addBookmark).toEqual([]);
    expect(calls.removeBookmark).toEqual([]);
  });
});

describe("annotation tools — accepted addresses reach the session", () => {
  it("records a comment at the parsed address", async () => {
    const { session, calls } = stubSession();
    const addComment = captureTools(session).get("add_comment")!;

    await addComment({ fileId: "sample", address: "0x401000", text: "entry" });
    expect(calls.setComment).toEqual([["sample", 0x401000, "entry"]]);
  });

  it("treats an empty comment as a delete", async () => {
    const { session, calls } = stubSession();
    const addComment = captureTools(session).get("add_comment")!;

    await addComment({ fileId: "sample", address: "0x401000", text: "" });
    expect(calls.setComment).toEqual([]);
    expect(calls.deleteComment).toEqual([["sample", 0x401000]]);
  });

  it("treats an empty name as a rename removal", async () => {
    const { session, calls } = stubSession();
    const rename = captureTools(session).get("rename_function")!;

    await rename({ fileId: "sample", address: 4096, name: "" });
    expect(calls.deleteRename).toEqual([["sample", 4096]]);
  });

  it("toggles a bookmark off when one already exists at the address", async () => {
    const { session, calls } = stubSession({ bookmarks: [{ address: 0x1000, label: "old" }] });
    const bookmark = captureTools(session).get("add_bookmark")!;

    const result = await bookmark({ fileId: "sample", address: "0x1000" });

    expect(JSON.parse(textOf(result)).action).toBe("removed");
    expect(calls.removeBookmark).toEqual([["sample", 0x1000]]);
    expect(calls.addBookmark).toEqual([]);
  });

  it("toggles a bookmark on when the address is free", async () => {
    const { session, calls } = stubSession();
    const bookmark = captureTools(session).get("add_bookmark")!;

    const result = await bookmark({ fileId: "sample", address: "0x2000", label: "here" });

    expect(JSON.parse(textOf(result)).action).toBe("added");
    expect(calls.addBookmark).toEqual([["sample", 0x2000, "here"]]);
  });
});

describe("get_xrefs — the whole-image maps (peek-a-bin-0d0)", () => {
  /** A file with one string, one import and one call edge, all at known addresses. */
  function referencedSession() {
    return stubSession({
      functions: [
        { name: "sub_401000", address: 0x401000, size: 0x40 },
        { name: "sub_401100", address: 0x401100, size: 0x40 },
      ],
      stringMap: new Map([[0x40a000, "password"]]),
      iatMap: new Map([[0x40b000, { lib: "KERNEL32.dll", func: "CreateFileA" }]]),
      stringXrefs: new Map([[0x40a000, [0x401010, 0x401120]]]),
      importXrefs: new Map([[0x40b000, [0x401030]]]),
      dataXrefs: new Map([[0x40c000, [0x401040]]]),
      callGraph: new Map([[0x401000, [0x401100]]]),
    });
  }

  it("answers a string address with its value and its users", async () => {
    // Before the maps were wired in, this returned xrefCount 0 and nothing else:
    // `xrefMap` is keyed by code target, so a data address was simply absent.
    const { session } = referencedSession();
    const getXrefs = captureTools(session).get("get_xrefs")!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: "sample", address: "0x40a000" })));

    expect(result.string).toBe("password");
    expect(result.stringRefs).toEqual(["0x401010", "0x401120"]);
  });

  it("answers an IAT address with the imported name and its call sites", async () => {
    const { session } = referencedSession();
    const getXrefs = captureTools(session).get("get_xrefs")!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: "sample", address: "0x40b000" })));

    expect(result.import).toBe("KERNEL32.dll!CreateFileA");
    expect(result.importRefs).toEqual(["0x401030"]);
  });

  it("reports data references and both directions of the call graph", async () => {
    const { session } = referencedSession();
    const getXrefs = captureTools(session).get("get_xrefs")!;

    const data = JSON.parse(textOf(await getXrefs({ fileId: "sample", address: "0x40c000" })));
    expect(data.dataRefs).toEqual(["0x401040"]);

    const caller = JSON.parse(textOf(await getXrefs({ fileId: "sample", address: "0x401000" })));
    expect(caller.calls).toEqual(["0x401100"]);
    expect(caller.calledBy).toEqual([]);

    const callee = JSON.parse(textOf(await getXrefs({ fileId: "sample", address: "0x401100" })));
    expect(callee.calls).toEqual([]);
    expect(callee.calledBy).toEqual(["0x401000"]);
  });

  it("leaves the per-instruction xrefs exactly as they were", async () => {
    const { session } = sessionWithXrefAt(0x402000);
    const getXrefs = captureTools(session).get("get_xrefs")!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: "sample", address: "0x402000" })));
    expect(result.xrefCount).toBe(1);
    expect(result.xrefs).toEqual([{ from: "0x401234", type: "call" }]);
  });
});

describe("get_call_graph (peek-a-bin-0d0)", () => {
  const graphSession = () =>
    stubSession({
      functions: [
        { name: "sub_401000", address: 0x401000, size: 0x40 },
        { name: "sub_401100", address: 0x401100, size: 0x40 },
      ],
      renames: { [String(0x401100)]: "decrypt" },
      callGraph: new Map([[0x401000, [0x401100]]]),
    });

  it("returns every edge when no address is given", async () => {
    const { session } = graphSession();
    const handler = captureTools(session).get("get_call_graph")!;

    const result = JSON.parse(textOf(await handler({ fileId: "sample" })));

    expect(result.functionCount).toBe(1);
    expect(result.edges).toEqual([
      {
        from: "0x401000",
        name: "sub_401000",
        calls: [{ address: "0x401100", name: "decrypt" }],
      },
    ]);
  });

  it("returns callers and callees for one address", async () => {
    const { session } = graphSession();
    const handler = captureTools(session).get("get_call_graph")!;

    const result = JSON.parse(textOf(await handler({ fileId: "sample", address: "0x401100" })));

    expect(result.name).toBe("decrypt");
    expect(result.calledBy).toEqual([{ address: "0x401000", name: "sub_401000" }]);
    expect(result.calls).toEqual([]);
  });

  it("refuses an unparseable address rather than dumping the whole graph", async () => {
    // `address` is optional here, so a malformed one must not fall through to
    // the omitted-argument branch and answer with something that looks fine.
    const { session } = graphSession();
    const handler = captureTools(session).get("get_call_graph")!;

    const result = await handler({ fileId: "sample", address: "not-an-address" });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/invalid address/);
  });
});

describe("tool handlers — unknown file", () => {
  it.each([
    "get_xrefs",
    "get_call_graph",
    "add_comment",
    "rename_function",
    "add_bookmark",
    "list_comments",
    "detect_anomalies",
  ])("%s reports a file that is not loaded", async (toolName) => {
    const { session } = stubSession();
    const handler = captureTools(session).get(toolName)!;

    const result = await handler({ fileId: "missing", address: "0x1000", text: "x", name: "x" });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/not loaded/);
  });
});

describe("decompile_function — architecture refusal (peek-a-bin-9b1)", () => {
  const arm64Function = {
    pe: { is64: true, sections: [] },
    functions: [{ name: "sub_140001018", address: 0x140001018, size: 0x40 }],
    instructions: [
      {
        address: 0x140001018,
        bytes: new Uint8Array(4),
        mnemonic: "stp",
        opStr: "x19, x20, [sp, #-0x30]!",
        size: 4,
      },
      { address: 0x14000101c, bytes: new Uint8Array(4), mnemonic: "ret", opStr: "", size: 4 },
    ],
  } as unknown as Partial<AnalyzedFile>;

  it("declines on an ARM64 image instead of emitting pseudo-C", async () => {
    const { session } = stubSession({ ...arm64Function, arch: "arm64" });
    const decompile = captureTools(session).get("decompile_function")!;

    const result = await decompile({ fileId: "sample", address: "0x140001018" });

    expect(result.isError).toBe(true);
    // Whatever else it says, it must not read like a decompilation.
    expect(textOf(result)).not.toMatch(/return|__unrecovered|unlifted/);
  });

  it("uses the same wording as the browser worker's refusal", async () => {
    // Both sides call `unsupportedOnArch`, so this cannot drift into two
    // different explanations of the same refusal.
    const { session } = stubSession({ ...arm64Function, arch: "arm64" });
    const decompile = captureTools(session).get("decompile_function")!;

    const result = await decompile({ fileId: "sample", address: "0x140001018" });

    expect(textOf(result)).toBe(`Error: ${unsupportedOnArch("Decompilation", "arm64")}`);
  });

  it("refuses before resolving the address, so it never depends on one", async () => {
    // The refusal is a property of the image. An ARM64 file must decline for an
    // address that is not a function at all, rather than reporting the address.
    const { session } = stubSession({ arch: "arm64" });
    const decompile = captureTools(session).get("decompile_function")!;

    const result = await decompile({ fileId: "sample", address: "0xdeadbeef" });

    expect(textOf(result)).toMatch(/not supported for ARM64/);
    expect(textOf(result)).not.toMatch(/no function at address/);
  });

  it("leaves the x86 path alone", async () => {
    // Same arguments, x86 image: the handler proceeds past the arch gate and
    // fails on the address, as it always did.
    const { session } = stubSession({ arch: "x86" });
    const decompile = captureTools(session).get("decompile_function")!;

    const result = await decompile({ fileId: "sample", address: "0xdeadbeef" });

    expect(textOf(result)).toMatch(/no function at address 0xdeadbeef/);
    expect(textOf(result)).not.toMatch(/not supported/);
  });

  it("still disassembles ARM64 — only the x86 grammars decline", async () => {
    // `disassemble_function` reports what Capstone decoded. That is real on
    // ARM64, so it must NOT be swept up in the refusal.
    const { session } = stubSession({ ...arm64Function, arch: "arm64" });
    const disassemble = captureTools(session).get("disassemble_function")!;

    const result = await disassemble({ fileId: "sample", address: "0x140001018" });

    expect(result.isError).toBeUndefined();
    expect(textOf(result)).toMatch(/stp\s+x19, x20, \[sp, #-0x30\]!/);
  });
});

/** Just enough PE shape for the tools that read `af.pe`. */
const arm64ImageStub = { pe: { is64: true, sections: [] } } as unknown as Partial<AnalyzedFile>;

describe("load_pe / list_files report the architecture", () => {
  it("list_files carries arch next to is64", async () => {
    // An ARM64 image is PE32+, so `is64: true` alone reads as "x64" to a client.
    const { session } = stubSession({ ...arm64ImageStub, arch: "arm64" });
    const listFiles = captureTools(session).get("list_files")!;

    const [entry] = JSON.parse(textOf(await listFiles({})));
    expect(entry.arch).toBe("arm64");
  });
});

let root: string;
let outside: string;
let exportAnalysis: ToolHandler;
const savedExportDir = process.env.PEEK_A_BIN_EXPORT_DIR;

beforeEach(() => {
  // realpathSync: /tmp is a symlink on some platforms, and the confinement check
  // compares against the resolved root.
  root = realpathSync(mkdtempSync(join(tmpdir(), "peek-export-root-")));
  outside = realpathSync(mkdtempSync(join(tmpdir(), "peek-export-outside-")));
  process.env.PEEK_A_BIN_EXPORT_DIR = root;

  const { session } = stubSession({
    fileName: "sample.exe",
    renames: { "4198400": "main" },
    comments: { "4198400": "entry" },
    bookmarks: [{ address: 0x401000, label: "start" }],
  });
  exportAnalysis = captureTools(session).get("export_analysis")!;
});

afterEach(() => {
  if (savedExportDir === undefined) delete process.env.PEEK_A_BIN_EXPORT_DIR;
  else process.env.PEEK_A_BIN_EXPORT_DIR = savedExportDir;
  for (const dir of [root, outside]) rmSync(dir, { recursive: true, force: true });
});

describe("export_analysis — accepted paths reach disk", () => {
  it("writes a .json file inside the export root", async () => {
    const result = await exportAnalysis({ fileId: "sample", outputPath: "analysis.json" });

    expect(result.isError).toBeUndefined();
    const target = join(root, "analysis.json");
    expect(existsSync(target)).toBe(true);
    const written = JSON.parse(readFileSync(target, "utf-8"));
    expect(written.version).toBe(1);
    expect(written.renames).toEqual({ "4198400": "main" });
  });

  it("returns the payload without touching disk when outputPath is omitted", async () => {
    const result = await exportAnalysis({ fileId: "sample" });

    expect(result.isError).toBeUndefined();
    expect(JSON.parse(textOf(result)).version).toBe(1);
    expect(existsSync(join(root, "sample.exe.json"))).toBe(false);
  });
});

describe("export_analysis — rejected paths create nothing", () => {
  it("rejects ../ traversal and creates nothing outside the root", async () => {
    const escaped = resolve(dirname(root), "escaped.json");
    expect(existsSync(escaped)).toBe(false);

    const result = await exportAnalysis({ fileId: "sample", outputPath: "../escaped.json" });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/escapes the allowed export directory/);
    expect(existsSync(escaped)).toBe(false);
  });

  it("rejects an absolute path outside the root without writing it", async () => {
    const target = join(outside, "stolen.json");
    const result = await exportAnalysis({ fileId: "sample", outputPath: target });

    expect(result.isError).toBe(true);
    expect(existsSync(target)).toBe(false);
  });

  // Regression: with only the parent directory resolved, a symlinked FILE
  // pre-planted in the export root redirected writeFileSync out of the root
  // while the tool reported success.
  it("rejects a symlinked FILE inside the root and leaves its target absent", async () => {
    const realTarget = join(outside, "target.json");
    symlinkSync(realTarget, join(root, "out.json"));

    const result = await exportAnalysis({ fileId: "sample", outputPath: "out.json" });

    expect(result.isError).toBe(true);
    expect(existsSync(realTarget)).toBe(false);
  });

  it("rejects a non-.json extension without writing", async () => {
    const result = await exportAnalysis({ fileId: "sample", outputPath: "analysis.txt" });

    expect(result.isError).toBe(true);
    expect(existsSync(join(root, "analysis.txt"))).toBe(false);
  });

  it("does not leak the analysis payload on a rejected path", async () => {
    const result = await exportAnalysis({ fileId: "sample", outputPath: "../escaped.json" });
    expect(textOf(result)).not.toMatch(/"version"/);
  });

  it("reports a not-loaded file before touching the path logic", async () => {
    const result = await exportAnalysis({ fileId: "nope", outputPath: "../escaped.json" });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/not loaded/);
    expect(existsSync(resolve(dirname(root), "escaped.json"))).toBe(false);
  });
});

describe("export_analysis payload", () => {
  it("serializes bookmarks, renames, comments and functions", async () => {
    const { session } = stubSession({
      fileName: "payload.exe",
      renames: { "4096": "renamed" },
      comments: { "4096": "note" },
      bookmarks: [{ address: 0x1000, label: "bm" }],
      functions: [{ address: 0x1000, name: "sub_1000", size: 32 }] as never,
    });
    const handler = captureTools(session).get("export_analysis")!;

    const payload = JSON.parse(textOf(await handler({ fileId: "sample" })));

    expect(payload.fileName).toBe("payload.exe");
    expect(payload.bookmarks).toEqual([{ address: 0x1000, label: "bm" }]);
    expect(payload.comments).toEqual({ "4096": "note" });
    // The rename wins over the detected name in the functions table.
    expect(payload.functions).toEqual([{ address: 0x1000, name: "renamed", size: 32 }]);
    expect(payload.hexPatches).toEqual([]);
  });
});
