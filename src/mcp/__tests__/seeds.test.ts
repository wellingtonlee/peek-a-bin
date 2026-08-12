/**
 * peek-a-bin-yo9 — the MCP side of jump-table seeding.
 *
 * `FileSession.loadFile` is the MCP server's whole analysis pipeline, and it is
 * the one path that calls `hybridDisassembleBytes` directly. Its seeds used to
 * be `functions.map(f => f.address)` alone, so a switch whose table sits
 * immediately before its first case body — the ordinary MSVC x86 layout — lost
 * the head of case 0 to phase 2's misaligned linear sweep.
 *
 * The behaviour of the helper is tested for real below. The session call itself
 * is asserted against the source text instead of by running a load: importing
 * `../session` for value pulls in `../disasm`, which loads Capstone WASM at
 * module scope, and `importGraph.test.ts` exists precisely to keep that out of
 * this suite. A static check is the strongest guard available here that does
 * not trade the suite's speed away — end-to-end confirmation was done against
 * real binaries (t32.exe: 14/16 → 16/16 jump-table targets are instruction
 * starts).
 */

import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { jumpTableTargets } from "../../disasm/seeds";

const SESSION = resolve(dirname(fileURLToPath(import.meta.url)), "..", "session.ts");

/**
 * The argument list of `call`, from its opening parenthesis to the one that
 * closes it. Counted rather than found by the next `)`, because the arguments
 * carry comments — and a bead id in a comment is enough parentheses to cut the
 * list short and pass a guard that should fail.
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

describe("jumpTableTargets", () => {
  it("flattens every table's targets", () => {
    const tables = new Map([
      [0x40b8f0, [0x40b900, 0x40b910]],
      [0x40ba8c, [0x40ba9c]],
    ]);

    expect(jumpTableTargets(tables)).toEqual([0x40b900, 0x40b910, 0x40ba9c]);
  });

  it("accepts the entries-array form the worker RPC sends", () => {
    // `detectFunctions` returns `[number, number[]][]` — Maps do not survive
    // structured clone — so both shapes reach this helper.
    const entries: [number, number[]][] = [[0x40b8f0, [0x40b900]]];

    expect(jumpTableTargets(entries)).toEqual([0x40b900]);
  });

  it("deduplicates a target several tables share", () => {
    const tables = new Map([
      [0x1000, [0x2000, 0x2000, 0x3000]],
      [0x1100, [0x2000]],
    ]);

    expect(jumpTableTargets(tables)).toEqual([0x2000, 0x3000]);
  });

  it("returns nothing for a binary with no tables", () => {
    // t64.exe and w64.exe detect zero jump tables; their seed lists, and so
    // their disassembly, must be unaffected by this change.
    expect(jumpTableTargets(new Map())).toEqual([]);
  });

  it("keeps a table with an empty target list from contributing a seed", () => {
    expect(jumpTableTargets(new Map([[0x1000, []]]))).toEqual([]);
  });
});

describe("FileSession — hybridDisassemble seeds", () => {
  it("seeds jump-table targets alongside function starts", () => {
    const source = readFileSync(SESSION, "utf-8");
    const seedLine = source.split("\n").find((l) => /^\s*const seeds =/.test(l)) ?? "";

    expect(
      seedLine,
      "src/mcp/session.ts computes hybridDisassemble's seeds from function starts only. " +
        "The recursive descent stops at an indirect jmp, so the case bodies of a switch " +
        "are then reached only by the linear gap fill, which starts on the jump table " +
        "itself and swallows the head of case 0 (peek-a-bin-yo9). Add " +
        "`...jumpTableTargets(jumpTables)`.",
    ).toMatch(/jumpTableTargets\(/);
    expect(seedLine).toMatch(/functions\.map/);
  });
});

/**
 * peek-a-bin-y1di — the same call, the other half of the same fact.
 *
 * Seeding the case bodies says where the switch goes; the spans say that the
 * table itself is data. Without them phase 2 fills the table as a gap and
 * decodes the case addresses as instructions — six phantom conditional jumps
 * inside t32.exe's `sub_407ABC`, each aiming past the end of the function.
 * Source text for the same reason as above: importing `../session` for value
 * loads Capstone WASM at module scope.
 */
describe("FileSession — hybridDisassemble jump-table spans", () => {
  it("passes the recovered table extents to the sweep", () => {
    const source = readFileSync(SESSION, "utf-8");

    expect(
      argumentsOf(source, "hybridDisassembleBytes("),
      "src/mcp/session.ts calls hybridDisassembleBytes without detectResult.jumpTableSpans, " +
        "so the bytes of every recovered jump table are gap-filled as code again " +
        "(peek-a-bin-y1di).",
    ).toMatch(/jumpTableSpans/);
  });
});
