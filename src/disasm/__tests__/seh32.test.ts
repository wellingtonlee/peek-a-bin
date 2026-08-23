import { describe, expect, it } from "vitest";
import {
  MAX_SEH32_SCOPE_RECORDS,
  readSeh32ScopeTable,
  type Seh32Reader,
  seh32FuncletsOfPrologue,
  seh32PrologImmediates,
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
  const head = (...pairs: [string, string][]) =>
    pairs.map(([mnemonic, opStr]) => ({ mnemonic, opStr }));

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
    expect(seh32PrologImmediates([])).toEqual([]);
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
    const head = [
      { mnemonic: "push", opStr: "0xc" },
      { mnemonic: "push", opStr: `0x${TABLE.toString(16)}` },
      { mnemonic: "call", opStr: "0x404170" },
    ];
    // The frame size 0xc maps to nothing, so it contributes no records and needs
    // no knowledge of which argument carries the table.
    expect(seh32FuncletsOfPrologue(head, readerOf(TABLE, words), isCodeAddress)).toEqual([
      0x00403bbf, 0x00403bab, 0x00403270,
    ]);
  });

  it("names nothing when the prologue is not one", () => {
    const head = [
      { mnemonic: "mov", opStr: "eax, dword ptr [ebp + 8]" },
      { mnemonic: "ret", opStr: "" },
    ];
    expect(seh32FuncletsOfPrologue(head, readerOf(TABLE, T32_411110), isCodeAddress)).toEqual([]);
  });
});
