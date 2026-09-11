import { describe, expect, it } from "vitest";
import {
  EH4_TRYLEVEL_NONE,
  type HeadReader,
  headReaderOfInsns,
  MAX_SEH32_SCOPE_RECORDS,
  readSeh32ScopeTable,
  type Seh32Reader,
  type Seh32ScopeTable,
  seh32FuncletsOfPrologue,
  seh32PrologImmediates,
  seh32ReaderOver,
  seh32ScopeTableOfFunction,
  seh32ScopeTableOfPrologue,
  trylevelComment,
} from "../seh32";

const CODE_LO = 0x401000;
const CODE_HI = 0x40e71a;
const isCodeAddress = (addr: number) => addr >= CODE_LO && addr < CODE_HI;

/** A reader over one `.rdata`-shaped span of 32-bit words. */
function readerOf(base: number, words: number[]): Seh32Reader {
  const at = (addr: number): number | null => {
    const i = (addr - base) / 4;
    return Number.isInteger(i) && i >= 0 && i < words.length ? words[i] : null;
  };
  return {
    i32: (addr) => {
      const v = at(addr);
      return v === null ? null : v | 0;
    },
    u32: (addr) => {
      const v = at(addr);
      return v === null ? null : v >>> 0;
    },
  };
}

const TABLE = 0x411110;

/**
 * `t32.exe`'s scope table at 0x411110, transcribed word for word — the one
 * `sub_4031A4` pushes, and the table CLAUDE.md's `peek-a-bin-sysf` note is
 * about. Header `{-2, 0, -56, 0}` then two records: `{-2, NULL, 0x403334}` and
 * `{0, NULL, 0x403270}`. The words after it belong to the next table
 * (0x411138), which is what stops the walk here.
 */
const T32_411110 = [
  0xfffffffe, 0x00000000, 0xffffffc8, 0x00000000, 0xfffffffe, 0x00000000, 0x00403334, 0x00000000,
  0x00000000, 0x00403270, 0xfffffffe, 0x00000000, 0xffffffd4, 0x00000000,
];

describe("readSeh32ScopeTable", () => {
  it("reads both records of a real MSVC table", () => {
    // Two `__finally` scopes: a NULL filter beside a handler is `__finally`, and
    // 0x403270 is the one whose funclet body sits six bytes further on at
    // 0x403276 — the reason this is a relation and never a protected set.
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, T32_411110), isCodeAddress)).toEqual([
      { enclosingLevel: -2, filter: 0, handler: 0x403334 },
      { enclosingLevel: 0, filter: 0, handler: 0x403270 },
    ]);
  });

  it("stops at the header of the table that follows", () => {
    // Nothing records a table's length, so the walk is bounded by the first
    // malformed record. Here that is 0x411138's own header read as a record:
    // `{-2, 0, -44}`, whose handler is not a code address.
    const recs = readSeh32ScopeTable(TABLE, readerOf(TABLE, T32_411110), isCodeAddress);
    expect(recs).toHaveLength(2);
  });

  it("stops when a filter is not an address", () => {
    // `t32` 0x411370 in the flesh: one record, then `{0, 0xfffffffe, 0}`. The
    // level would pass — 0 is an earlier record's index — so the filter test is
    // what ends the walk.
    const words = [
      0xfffffffe, 0, 0xffffffcc, 0, 0xfffffffe, 0, 0x0040a62c, 0x00000000, 0x00000000, 0xfffffffe,
      0x00000000,
    ];
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, words), isCodeAddress)).toEqual([
      { enclosingLevel: -2, filter: 0, handler: 0x0040a62c },
    ]);
  });

  it("requires the FIRST record's enclosing level to be -2", () => {
    // Scope levels nest, so a level can only name a record already read — and
    // record 0 has none in front of it. `t32` 0x411450's second record is
    // `{70824, 0, 0}`, which fails this and the handler test together.
    const words = [0xfffffffe, 0, 0xffffffcc, 0, 0x00000000, 0x00000000, 0x00403334];
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, words), isCodeAddress)).toEqual([]);
  });

  it("refuses an enclosing level that names a record not yet read", () => {
    const words = [
      0xfffffffe, 0, 0xffffffcc, 0, 0xfffffffe, 0, 0x00403334, 0x00000005, 0x00000000, 0x00403270,
    ];
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, words), isCodeAddress)).toHaveLength(1);
  });

  it("refuses a handler outside the code section", () => {
    const words = [0xfffffffe, 0, 0xffffffcc, 0, 0xfffffffe, 0, 0x00411000];
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, words), isCodeAddress)).toEqual([]);
  });

  it("keeps a non-null filter that is code — an `__except` scope", () => {
    // `t32!sub_403A88` pushes 0x4111B8, whose one record is
    // `{-2, 0x403BAB, 0x403BBF}`: a filter AND a handler, both funclets of it.
    const words = [0xfffffffe, 0, 0xffffffcc, 0, 0xfffffffe, 0x00403bab, 0x00403bbf];
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, words), isCodeAddress)).toEqual([
      { enclosingLevel: -2, filter: 0x00403bab, handler: 0x00403bbf },
    ]);
  });

  it("refuses an address inside the code section as a table", () => {
    // A scope table is read-only data. Requiring that is also what makes a frame
    // size — the other immediate the prologue pushes — cost nothing to reject.
    const words = [0xfffffffe, 0, 0xffffffcc, 0, 0xfffffffe, 0, 0x00403334];
    expect(
      readSeh32ScopeTable(CODE_LO + 0x100, readerOf(CODE_LO + 0x100, words), isCodeAddress),
    ).toEqual([]);
  });

  it("refuses an unmapped address, and an unreadable header", () => {
    expect(readSeh32ScopeTable(0xc, readerOf(TABLE, T32_411110), isCodeAddress)).toEqual([]);
    // Mapped, but the header runs off the end of the span.
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, [0, 0]), isCodeAddress)).toEqual([]);
  });

  it("stops at the record ceiling however well-formed the chain is", () => {
    // Hostile-input hygiene: a crafted `.rdata` can hold an arbitrarily long
    // chain of valid records. Stopping early withdraws fewer starts, which is
    // the pre-existing behaviour.
    const words = [0xfffffffe, 0, 0xffffffcc, 0];
    for (let i = 0; i < MAX_SEH32_SCOPE_RECORDS + 10; i++) words.push(0xfffffffe, 0, 0x00403334);
    expect(readSeh32ScopeTable(TABLE, readerOf(TABLE, words), isCodeAddress)).toHaveLength(
      MAX_SEH32_SCOPE_RECORDS,
    );
  });
});

describe("seh32PrologImmediates", () => {
  /**
   * A {@link HeadReader} over a fixed list, remembering the highest index asked
   * for — which is what the laziness test below reads.
   */
  const reading = (...pairs: [string, string][]) => {
    const insns = pairs.map(([mnemonic, opStr]) => ({ mnemonic, opStr }));
    let highest = -1;
    const read: HeadReader = (i) => {
      highest = Math.max(highest, i);
      return insns[i];
    };
    return { read, pulled: () => highest + 1 };
  };
  const head = (...pairs: [string, string][]) => reading(...pairs).read;

  it("takes the immediates an MSVC SEH prologue pushes", () => {
    expect(
      seh32PrologImmediates(
        head(["push", "0xc"], ["push", "0x411050"], ["call", "0x404170"], ["push", "7"]),
      ),
    ).toEqual([0xc, 0x411050]);
  });

  it("skips a hot-patch pad and leading nops", () => {
    expect(
      seh32PrologImmediates(
        head(["mov", "edi, edi"], ["nop", ""], ["push", "0xc"], ["call", "0x404170"]),
      ),
    ).toEqual([0xc]);
  });

  it("refuses a run of pushes that is not a call's argument list", () => {
    expect(seh32PrologImmediates(head(["push", "0xc"], ["push", "0x411050"]))).toEqual([]);
    expect(
      seh32PrologImmediates(head(["push", "0xc"], ["mov", "eax, 1"], ["call", "0x404170"])),
    ).toEqual([]);
  });

  it("refuses an indirect call", () => {
    expect(seh32PrologImmediates(head(["push", "0xc"], ["call", "dword ptr [0x40f098]"]))).toEqual(
      [],
    );
  });

  it("refuses a register push, and a head with no push at all", () => {
    expect(seh32PrologImmediates(head(["push", "ebp"], ["call", "0x404170"]))).toEqual([]);
    expect(seh32PrologImmediates(head(["call", "0x404170"]))).toEqual([]);
    expect(seh32PrologImmediates(head())).toEqual([]);
  });

  it("stops at the instruction that decides, and asks for no more", () => {
    // The caller decodes each index on demand, so an index this rule does not
    // ask for is a Capstone call that does not happen — 76-88% of them in this
    // pass, measured. A rule that scanned the whole head instead would read
    // eight here and still answer `[]` (peek-a-bin-6dv3).
    const bails = reading(["push", "ebp"], ["call", "0x404170"], ["nop", ""]);
    expect(seh32PrologImmediates(bails.read)).toEqual([]);
    expect(bails.pulled()).toBe(1);

    const oneImm = reading(["push", "0xc"], ["call", "0x404170"], ["nop", ""], ["nop", ""]);
    expect(seh32PrologImmediates(oneImm.read)).toEqual([0xc]);
    expect(oneImm.pulled()).toBe(2);
  });

  it("refuses more pushes than a prologue helper takes", () => {
    expect(
      seh32PrologImmediates(
        head(
          ["push", "1"],
          ["push", "2"],
          ["push", "3"],
          ["push", "4"],
          ["push", "5"],
          ["call", "0x404170"],
        ),
      ),
    ).toEqual([]);
  });
});

describe("seh32FuncletsOfPrologue", () => {
  it("names both funclets of both records, handler and filter alike", () => {
    const words = [
      0xfffffffe, 0, 0xffffffcc, 0, 0xfffffffe, 0x00403bab, 0x00403bbf, 0x00000000, 0x00000000,
      0x00403270,
    ];
    const insns = [
      { mnemonic: "push", opStr: "0xc" },
      { mnemonic: "push", opStr: `0x${TABLE.toString(16)}` },
      { mnemonic: "call", opStr: "0x404170" },
    ];
    const head: HeadReader = (i) => insns[i];
    // The frame size 0xc maps to nothing, so it contributes no records and needs
    // no knowledge of which argument carries the table.
    expect(seh32FuncletsOfPrologue(head, readerOf(TABLE, words), isCodeAddress)).toEqual([
      0x00403bbf, 0x00403bab, 0x00403270,
    ]);
  });

  it("names nothing when the prologue is not one", () => {
    const insns = [
      { mnemonic: "mov", opStr: "eax, dword ptr [ebp + 8]" },
      { mnemonic: "ret", opStr: "" },
    ];
    const head: HeadReader = (i) => insns[i];
    expect(seh32FuncletsOfPrologue(head, readerOf(TABLE, T32_411110), isCodeAddress)).toEqual([]);
  });
});

describe("seh32ScopeTableOfPrologue — THE table a trylevel indexes", () => {
  const reader = readerOf(TABLE, T32_411110);
  const head = (...pairs: [string, string][]): HeadReader =>
    headReaderOfInsns(pairs.map(([mnemonic, opStr]) => ({ mnemonic, opStr })));

  it("returns the table and its address for a real prologue", () => {
    const table = seh32ScopeTableOfPrologue(
      head(["push", "0x38"], ["push", "0x411110"], ["call", "0x404170"]),
      reader,
      isCodeAddress,
    );
    expect(table).toEqual({
      tableAddr: TABLE,
      records: [
        { enclosingLevel: -2, filter: 0, handler: 0x403334 },
        { enclosingLevel: 0, filter: 0, handler: 0x403270 },
      ],
    });
  });

  it("is null for a prologue that is not one, and for an immediate that is not a table", () => {
    expect(seh32ScopeTableOfPrologue(head(["push", "ebp"]), reader, isCodeAddress)).toBeNull();
    expect(
      seh32ScopeTableOfPrologue(
        head(["push", "0x38"], ["call", "0x404170"]),
        reader,
        isCodeAddress,
      ),
    ).toBeNull();
  });

  it("REFUSES two immediates that both read as tables — an annotation needs one", () => {
    // Detection unions them; a name cannot. Two pushes of the same table
    // address make both immediates read as tables.
    expect(
      seh32ScopeTableOfPrologue(
        head(["push", "0x411110"], ["push", "0x411110"], ["call", "0x404170"]),
        reader,
        isCodeAddress,
      ),
    ).toBeNull();
  });
});

describe("seh32ReaderOver — little-endian reads over data windows", () => {
  const bytes = new Uint8Array([0xfe, 0xff, 0xff, 0xff, 0x34, 0x33, 0x40, 0x00, 0x00]);
  const reader = seh32ReaderOver([{ base: 0x411000, bytes }]);

  it("reads i32 signed and u32 unsigned, and null where nothing maps", () => {
    expect(reader.i32(0x411000)).toBe(-2);
    expect(reader.u32(0x411000)).toBe(0xfffffffe);
    expect(reader.u32(0x411004)).toBe(0x403334);
    // Last full word ends at +8; +6 would need bytes 6..9 and there are 9.
    expect(reader.u32(0x411005)).toBe(0x00403334 >>> 8);
    expect(reader.u32(0x411006)).toBeNull();
    expect(reader.i32(0x410fff)).toBeNull();
    expect(seh32ReaderOver([]).u32(0x411000)).toBeNull();
  });

  it("agrees with the transcribed-word reader on a real table", () => {
    const words = new Uint8Array(T32_411110.length * 4);
    new DataView(words.buffer).setUint32(0, 0, true);
    T32_411110.forEach((w, i) => new DataView(words.buffer).setUint32(i * 4, w, true));
    const over = seh32ReaderOver([{ base: TABLE, bytes: words }]);
    expect(readSeh32ScopeTable(TABLE, over, isCodeAddress)).toEqual(
      readSeh32ScopeTable(TABLE, readerOf(TABLE, T32_411110), isCodeAddress),
    );
  });
});

describe("seh32ScopeTableOfFunction — the composition the callers share", () => {
  it("reads a function's own table from its instructions and the image's windows", () => {
    const words = new Uint8Array(T32_411110.length * 4);
    T32_411110.forEach((w, i) => new DataView(words.buffer).setUint32(i * 4, w, true));
    const insns = [
      { mnemonic: "push", opStr: "0x38" },
      { mnemonic: "push", opStr: "0x411110" },
      { mnemonic: "call", opStr: "0x404170" },
      { mnemonic: "mov", opStr: "ebx, dword ptr [ebp + 8]" },
    ];
    const table = seh32ScopeTableOfFunction(
      insns,
      [{ base: TABLE, bytes: words }],
      CODE_LO,
      CODE_HI,
    );
    expect(table?.tableAddr).toBe(TABLE);
    expect(table?.records).toHaveLength(2);
    expect(
      seh32ScopeTableOfFunction([], [{ base: TABLE, bytes: words }], CODE_LO, CODE_HI),
    ).toBeNull();
  });
});

describe("trylevelComment — the one declaration of what a trylevel store says", () => {
  const table: Seh32ScopeTable = {
    tableAddr: TABLE,
    records: [
      { enclosingLevel: -2, filter: 0, handler: 0x403334 },
      { enclosingLevel: 0, filter: 0, handler: 0x403270 },
      { enclosingLevel: -2, filter: 0x4033a0, handler: 0x4033c0 },
    ],
  };

  it("names a __finally scope by its handler and the table", () => {
    expect(trylevelComment(0, table)).toBe(
      "EH4 trylevel 0: __finally at 0x403334 (scope table 0x411110)",
    );
  });

  it("names the enclosing level of a nested scope", () => {
    expect(trylevelComment(1, table)).toBe(
      "EH4 trylevel 1: __finally at 0x403270, inside trylevel 0 (scope table 0x411110)",
    );
  });

  it("names an __except scope by handler and filter", () => {
    expect(trylevelComment(2, table)).toBe(
      "EH4 trylevel 2: __except at 0x4033C0, filter at 0x4033A0 (scope table 0x411110)",
    );
  });

  it("spells TRYLEVEL_NONE from either reading of the constant", () => {
    expect(trylevelComment(EH4_TRYLEVEL_NONE, table)).toBe(
      "EH4 trylevel none (scope table 0x411110)",
    );
    expect(trylevelComment(0xfffffffe, table)).toBe("EH4 trylevel none (scope table 0x411110)");
  });

  it("REFUSES a level the table has no record for, and a non-integer", () => {
    expect(trylevelComment(3, table)).toBeNull();
    expect(trylevelComment(-1, table)).toBeNull();
    expect(trylevelComment(0xffffffff, table)).toBeNull();
    expect(trylevelComment(0.5, table)).toBeNull();
  });
});
