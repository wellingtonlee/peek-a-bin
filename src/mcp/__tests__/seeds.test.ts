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
