/**
 * Negative controls for the ARM64 audit rows the corpus cannot make red.
 *
 * `corpus/arm64.ts` gates twenty rows. Ten of them can be turned red by
 * perturbing this repo's own code — misalign the sweep's probe advance, move the
 * decode-rate floor, put the `adrp`/`add` target a page out, drop
 * `readArm64Table`'s alignment guard, make `Arm64SweepCache` truncate or never
 * store — and those controls are recorded in the commit that landed them. The
 * rest are properties of Capstone's own output, of the `.pdata` the linker
 * wrote, or of the section's size: nothing in this repo can make them false, so
 * running the audit does not exercise them at all, and CLAUDE.md is emphatic
 * that an unexercised gate is not evidence.
 *
 * So they are controlled here instead, the way `build/selfAssignAudit.test.ts`
 * controls `corpus/selfAssigns.ts`'s two never-observed rows. Each row is asked
 * twice: once over well-formed input, where it must be 0 — a test that only
 * checks the red direction passes just as well against an audit that has stopped
 * looking — and once over input carrying exactly the defect, where it must name
 * the offending entry.
 *
 * These import `corpus/arm64.ts`, which reaches `capstone-wasm` and
 * `FileSession` at module scope through its own imports; the judging functions
 * themselves take plain data, which is the whole reason they were extracted.
 */
import { describe, expect, it } from "vitest";
import {
  auditJumpTables,
  auditOrphans,
  auditPdata,
  auditRefs,
  auditSweep,
  auditWildBranches,
  makeExtents,
  type Row,
} from "../corpus/arm64";
import type { Instruction } from "../src/disasm/types";

/** One four-byte A64 instruction at `address`. `bytes` is never read by the audits. */
function insn(address: number, mnemonic: string, opStr = "", size = 4): Instruction {
  return { address, mnemonic, opStr, size, bytes: new Uint8Array(4) };
}

const byAddress = (insns: readonly Instruction[]) => new Map(insns.map((i) => [i.address, i]));

/** The named row, or a failure that says which rows there were. */
function row(rows: readonly Row[], name: string): Row {
  const hit = rows.find((r) => r.name === name);
  if (!hit) throw new Error(`no row "${name}" — got ${rows.map((r) => r.name).join(" | ")}`);
  return hit;
}

const BASE = 0x140001000;
const END = 0x140002000;

/** A short, entirely well-formed A64 stretch: four aligned four-byte words. */
const CLEAN = [
  insn(BASE, "nop"),
  insn(BASE + 4, "nop"),
  insn(BASE + 8, "nop"),
  insn(BASE + 12, "ret"),
];

describe("corpus/arm64 sweep gates", () => {
  it("reports nothing for a well-formed sweep", () => {
    const rows = auditSweep(CLEAN, BASE, END, 4);
    for (const name of [
      "sweep: unaligned address",
      "sweep: width not 4",
      "sweep: address not increasing",
      "sweep: outside code section",
    ]) {
      expect(row(rows, name).value, name).toBe(0);
    }
  });

  it("names an instruction whose width is not four bytes", () => {
    // A64 is fixed-width. A decoder reporting anything else is reporting
    // something that is not an A64 instruction, whatever it printed.
    const rows = auditSweep([...CLEAN, insn(BASE + 16, "movz", "x0, #1", 5)], BASE, END, 5);
    const r = row(rows, "sweep: width not 4");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("size=5");
    // The other three must stay quiet: a wide instruction is not a misaligned
    // one, and a row that fires on everything separates nothing.
    expect(row(rows, "sweep: unaligned address").value).toBe(0);
    expect(row(rows, "sweep: address not increasing").value).toBe(0);
  });

  it("names an instruction that does not follow its predecessor", () => {
    const rows = auditSweep([...CLEAN, insn(BASE + 8, "nop")], BASE, END, 5);
    const r = row(rows, "sweep: address not increasing");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("0x14000100c");
  });

  it("names an instruction outside the code section", () => {
    const rows = auditSweep([...CLEAN, insn(END + 4, "nop")], BASE, END, 5);
    const r = row(rows, "sweep: outside code section");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("0x140002004");
  });

  it("names an unaligned instruction", () => {
    const rows = auditSweep([insn(BASE + 2, "nop")], BASE, END, 1);
    expect(row(rows, "sweep: unaligned address").value).toBe(1);
  });
});

describe("corpus/arm64 .pdata gates", () => {
  const clean = [{ begin: BASE, end: BASE + 16 }];

  it("reports nothing for a well-formed extent whose begin decoded", () => {
    const { rows, extentWords } = auditPdata(makeExtents(clean), byAddress(CLEAN));
    expect(extentWords).toBe(4);
    for (const name of [
      "pdata: begin with no instruction",
      "pdata: unaligned begin",
      "pdata: unaligned end",
      "pdata: empty extent",
    ]) {
      expect(row(rows, name).value, name).toBe(0);
    }
    expect(row(rows, "pdata: words in extents that do not decode").value).toBe(0);
  });

  it("names a begin the sweep produced no instruction for", () => {
    // The linker recorded this address as a function entry, so it IS an
    // instruction boundary by the file's own statement.
    const { rows } = auditPdata(makeExtents(clean), byAddress(CLEAN.slice(1)));
    const r = row(rows, "pdata: begin with no instruction");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toBe("0x140001000");
    // And the undecoded-word census must move with it, or the report half is
    // not measuring the same population as the gate.
    expect(row(rows, "pdata: words in extents that do not decode").value).toBe(1);
  });

  it("names an unaligned begin and an unaligned end separately", () => {
    const { rows } = auditPdata(
      makeExtents([{ begin: BASE + 1, end: BASE + 17 }]),
      byAddress(CLEAN),
    );
    expect(row(rows, "pdata: unaligned begin").value).toBe(1);
    expect(row(rows, "pdata: unaligned end").value).toBe(1);
  });

  it("names an empty extent", () => {
    const { rows } = auditPdata(makeExtents([{ begin: BASE, end: BASE }]), byAddress(CLEAN));
    expect(row(rows, "pdata: empty extent").value).toBe(1);
    expect(row(rows, "pdata: empty extent").rows[0]).toBe("0x140001000..0x140001000");
  });
});

describe("corpus/arm64 wild-branch gate", () => {
  const ex = makeExtents([{ begin: BASE, end: BASE + 16 }]);

  it("reports nothing when every branch lands in the image", () => {
    const insns = [insn(BASE, "b", "#0x140001008"), insn(BASE + 4, "bl", "#0x140001800")];
    const rows = auditWildBranches(insns, ex, BASE, END);
    expect(row(rows, "wild branch inside a .pdata extent").value).toBe(0);
    expect(row(rows, "wild branch inside a .pdata extent").live).toContain("2 direct branches");
  });

  it("names a branch inside an extent aiming outside the image, and only that one", () => {
    // The one outside the extent is REPORTED, not gated: outside every extent
    // the A64 sweep is decoding literal pools by design, so a wild target there
    // is the expected consequence rather than a defect.
    const insns = [
      insn(BASE, "b", "#0x900000000"),
      insn(BASE + 0x40, "b", "#0x900000000"),
    ];
    const rows = auditWildBranches(insns, ex, BASE, END);
    const r = row(rows, "wild branch inside a .pdata extent");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("0x140001000");
    expect(row(rows, "wild branch outside every extent").value).toBe(1);
  });
});

describe("corpus/arm64 unreachable-word report", () => {
  const ex = makeExtents([{ begin: BASE, end: BASE + 16 }]);

  it("does not report a word its predecessor can fall through into", () => {
    const rows = auditOrphans(CLEAN, ex, byAddress(CLEAN), new Map(), [BASE], 4);
    expect(row(rows, "unreachable decoded word in a .pdata extent").value).toBe(0);
    expect(row(rows, "unreachable decoded word in a .pdata extent").live).toContain("0 words after");
  });

  it("reports a word after an undecodable one that nothing names", () => {
    const insns = [insn(BASE, "nop"), insn(BASE + 8, "stxrb", "w9, w11, [x16]")];
    const rows = auditOrphans(insns, ex, byAddress(insns), new Map(), [BASE], 4);
    const r = row(rows, "unreachable decoded word in a .pdata extent");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("stxrb");
    expect(r.live).toContain("1 words after");
  });

  it("withdraws it the moment anything can reach the word", () => {
    // Each of the four reachability channels on its own, because a rule that
    // consulted only some of them would report real code as data.
    const insns = [insn(BASE, "nop"), insn(BASE + 8, "stxrb", "w9, w11, [x16]")];
    const map = byAddress(insns);
    const branched = [...insns, insn(BASE + 0x40, "b", "#0x140001008")];
    for (const [what, rows] of [
      ["a direct branch", auditOrphans(branched, ex, byAddress(branched), new Map(), [BASE], 4)],
      ["a jump-table case", auditOrphans(insns, ex, map, new Map([[BASE, [BASE + 8]]]), [BASE], 4)],
      ["a detected function", auditOrphans(insns, ex, map, new Map(), [BASE, BASE + 8], 4)],
      [
        "a .pdata begin",
        auditOrphans(
          insns,
          makeExtents([
            { begin: BASE, end: BASE + 8 },
            { begin: BASE + 8, end: BASE + 16 },
          ]),
          map,
          new Map(),
          [BASE],
          4,
        ),
      ],
    ] as const) {
      const r = row(rows, "unreachable decoded word in a .pdata extent");
      expect(r.value, what).toBe(0);
    }
  });
});

describe("corpus/arm64 reference-grammar gates", () => {
  it("reports nothing for a well-formed adrp/add and adr", () => {
    const insns = [
      insn(BASE, "adrp", "x8, #0x140020000"),
      insn(BASE + 4, "add", "x8, x8, #0x480"),
      insn(BASE + 8, "adr", "x9, #0x140001100"),
    ];
    const rows = auditRefs(insns, byAddress(insns));
    for (const r of rows) expect(r.value, r.name).toBe(0);
    expect(rows[0].live).toContain("2 refs");
  });

  it("names an adrp whose printed page is not 4 KiB aligned", () => {
    // Capstone prints the RESOLVED page, and `adrp` zeroes the low twelve bits
    // of the address it forms, so an unaligned page is a printing or parsing
    // defect rather than something the ISA can produce. Nothing in this repo can
    // make it happen, which is exactly why the control lives here.
    const insns = [
      insn(BASE, "adrp", "x8, #0x140020001"),
      insn(BASE + 4, "add", "x8, x8, #0x0"),
    ];
    const rows = auditRefs(insns, byAddress(insns));
    const r = row(rows, "ref: adrp page not 4 KiB aligned");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("0x140020001");
  });

  it("names a target outside the adrp page", () => {
    const insns = [
      insn(BASE, "adrp", "x8, #0x140020000"),
      // 0x1000 is not encodable as this add's imm12, so this pair could only
      // arise from a mis-read operand — which is the class the gate is for.
      insn(BASE + 4, "add", "x8, x8, #0x1000"),
    ];
    const rows = auditRefs(insns, byAddress(insns));
    expect(row(rows, "ref: target outside the adrp page").value).toBe(1);
  });

  it("names an adr beyond its +/-1 MiB reach", () => {
    const insns = [insn(BASE, "adr", "x9, #0x150001000")];
    const rows = auditRefs(insns, byAddress(insns));
    expect(row(rows, "ref: adr target beyond +/-1 MiB").value).toBe(1);
  });

  it("names a reference attributed to an address with no instruction", () => {
    const insns = [
      insn(BASE, "adrp", "x8, #0x140020000"),
      insn(BASE + 4, "add", "x8, x8, #0x480"),
    ];
    // The completing instruction is present; its `adrp` partner is not in the
    // map, which is what a reader and a sweep disagreeing looks like.
    const partial = new Map([[BASE + 4, insns[1]]]);
    const rows = auditRefs(insns, partial);
    const r = row(rows, "ref: attributed to a non-instruction");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("pairFrom");
  });
});

describe("corpus/arm64 jump-table gate", () => {
  const ex = makeExtents([{ begin: BASE, end: BASE + 16 }]);

  it("reports nothing when every case target is an instruction in the same function", () => {
    const rows = auditJumpTables(CLEAN, new Map([[BASE + 12, [BASE + 4, BASE + 8]]]), byAddress(CLEAN), ex);
    expect(row(rows, "jump table: case target is not an instruction").value).toBe(0);
    expect(row(rows, "jump table: case outside the dispatch's function").value).toBe(0);
    expect(rows[0].live).toContain("1 tables, 2 cases");
  });

  it("names a case target the sweep produced no instruction for", () => {
    const rows = auditJumpTables(CLEAN, new Map([[BASE + 12, [BASE + 4, BASE + 6]]]), byAddress(CLEAN), ex);
    const r = row(rows, "jump table: case target is not an instruction");
    expect(r.value).toBe(1);
    expect(r.rows[0]).toContain("0x140001006");
  });

  /**
   * peek-a-bin-gb40. The words of a table the tool itself recovered, presented
   * by the same tool as instructions. A GATE since the spans were published;
   * these hold the two rules that make it one, neither of which the corpus can
   * exercise — both real binaries read every table to its bound, and both
   * re-derive every published dispatch.
   */
  describe("table words presented as instructions", () => {
    /** `cmp`/`b.hi`/`adr`/`ldrb`/`add`/`br` over a byte table at `TBL`. */
    const TBL = BASE + 0x20;
    const dispatch = (bound: number, from = BASE): Instruction[] => [
      insn(from, "cmp", `w1, #${bound}`),
      insn(from + 4, "b.hi", `#0x${(BASE + 0x100).toString(16)}`),
      insn(from + 8, "adr", `x9, #0x${TBL.toString(16)}`),
      insn(from + 12, "ldrb", "w8, [x9, w1, uxtw]"),
      insn(from + 16, "add", "x8, x9, x8, lsl #2"),
      insn(from + 20, "br", "x8"),
    ];
    const BR = BASE + 20;
    /** Two case targets, which is the least a table can distinguish. */
    const CASES = [BASE + 4, BASE + 8];
    const gb = (rows: readonly Row[]) =>
      row(rows, "jump table: table words presented as instructions");

    it("is a gate, and reads 0 when no table word decoded", () => {
      const rows = auditJumpTables(dispatch(3), new Map([[BR, CASES]]), byAddress(dispatch(3)), ex);
      const r = gb(rows);
      expect(r.gate).toBe(true);
      expect(r.value).toBe(0);
      // Liveness: the population is the table's own words, and it is not empty.
      expect(r.live).toBe("1 words in recovered table extents");
    });

    it("names a table word the sweep presented as an instruction", () => {
      // A word at the table base, in the same stream: two claims about one byte.
      const insns = [...dispatch(3), insn(TBL, "madd", "w4, w9, w30, w8")];
      const r = gb(auditJumpTables(insns, new Map([[BR, CASES]]), byAddress(insns), ex));
      expect(r.value).toBe(1);
      expect(r.rows[0]).toContain("0x140001020");
    });

    /**
     * THE RULE THE CORPUS CANNOT EXERCISE. `readArm64Table` stops at the first
     * entry failing its range or alignment test, so a bound of 32 entries over
     * a table that read 2 claims 32 bytes and owns 2. Judging the claimed
     * extent would name the words after it — real code, in the general case —
     * and the gate would be red on correct output. The length comes from the
     * published `targets`, which is what the published span is sized by too.
     */
    it("judges the extent READ, not the extent the bound claimed", () => {
      // Bound 31 -> 32 claimed entries -> 8 claimed words; 2 targets -> 1 word.
      const insns = [...dispatch(31), insn(TBL + 4, "madd", "w4, w9, w30, w8")];
      const r = gb(auditJumpTables(insns, new Map([[BR, CASES]]), byAddress(insns), ex));
      expect(r.value).toBe(0);
      expect(r.live).toBe("1 words in recovered table extents");
    });

    it("still names a word inside the extent that was read", () => {
      // The same claimed table, but the decoded word is the base itself, which
      // the read did cover. Without this the test above would pass against an
      // audit that had stopped looking altogether.
      const insns = [...dispatch(31), insn(TBL, "madd", "w4, w9, w30, w8")];
      const r = gb(auditJumpTables(insns, new Map([[BR, CASES]]), byAddress(insns), ex));
      expect(r.value).toBe(1);
    });

    it("counts a word once where two dispatches share one table", () => {
      // t64-arm.exe's `br 0x140001a34` and `br 0x140001db0` both read
      // 0x140001df0. A word is a word.
      const second = dispatch(3, BASE + 0x40);
      const insns = [...dispatch(3), ...second, insn(TBL, "madd", "w4, w9, w30, w8")];
      const tables = new Map([
        [BR, CASES],
        [BASE + 0x54, CASES],
      ]);
      const r = gb(auditJumpTables(insns, tables, byAddress(insns), ex));
      expect(r.value).toBe(1);
      expect(r.live).toBe("1 words in recovered table extents");
    });

    /**
     * The liveness half, and it gates. This walk re-derives each dispatch from
     * the instruction stream with a `recent` window of its own, so anything that
     * made the stream unreadable would empty the population and drive the gate
     * above to 0 by no longer looking.
     */
    it("names a published table this walk could not re-derive", () => {
      const r = row(
        // A `br` with no chain in front of it: the reader published a table for
        // it, this walk finds none.
        auditJumpTables(CLEAN, new Map([[BASE + 12, CASES]]), byAddress(CLEAN), ex),
        "jump table: reader's table not re-derived here",
      );
      expect(r.gate).toBe(true);
      expect(r.value).toBe(1);
      expect(r.rows[0]).toContain("0x14000100c");
    });

    it("reports nothing to re-derive when every published table is found again", () => {
      const rows = auditJumpTables(dispatch(3), new Map([[BR, CASES]]), byAddress(dispatch(3)), ex);
      expect(row(rows, "jump table: reader's table not re-derived here").value).toBe(0);
    });
  });

  it("reports a case target in another function without gating on it", () => {
    // A tail-merged or ICF-shared case body legitimately lives elsewhere, so
    // this is a question and not a verdict — which is why it is a report.
    const wide = makeExtents([
      { begin: BASE, end: BASE + 8 },
      { begin: BASE + 8, end: BASE + 16 },
    ]);
    const rows = auditJumpTables(CLEAN, new Map([[BASE, [BASE + 8]]]), byAddress(CLEAN), wide);
    const r = row(rows, "jump table: case outside the dispatch's function");
    expect(r.value).toBe(1);
    expect(r.gate).toBe(false);
  });
});
