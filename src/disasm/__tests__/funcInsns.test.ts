import { describe, expect, it } from "vitest";
import type { RuntimeFunction } from "../../pe/types";
import { buildCFG } from "../cfg";
import {
  buildFuncInsnMap,
  collectFuncInsns,
  funcExceptionRecord,
  funcXrefEntries,
  getFuncInsns,
} from "../funcInsns";
import type { DisasmFunction, Instruction, Xref } from "../types";

/** Instructions laid out back-to-back, `size` bytes each. */
function layout(start: number, count: number, size = 4): Instruction[] {
  return Array.from({ length: count }, (_, i) => ({
    address: start + i * size,
    mnemonic: "nop",
    opStr: String(i),
    size,
    bytes: new Uint8Array(size),
  }));
}

function fn(address: number, size: number, name = "f"): DisasmFunction {
  return { name, address, size };
}

const addrs = (insns: Instruction[]) => insns.map((i) => i.address);

describe("collectFuncInsns", () => {
  it("returns exactly the instructions inside [address, address + size)", () => {
    const insns = layout(0x1000, 10); // 0x1000 .. 0x1024
    const got = collectFuncInsns(fn(0x1008, 12), insns);
    expect(addrs(got)).toEqual([0x1008, 0x100c, 0x1010]);
  });

  it("includes the instruction at the start address and excludes the end address", () => {
    const insns = layout(0x1000, 4);
    expect(addrs(collectFuncInsns(fn(0x1000, 8), insns))).toEqual([0x1000, 0x1004]);
  });

  it("returns an empty array for a function with no instructions", () => {
    const insns = layout(0x1000, 4);
    expect(collectFuncInsns(fn(0x9000, 0x100), insns)).toEqual([]); // range after all insns
    expect(collectFuncInsns(fn(0x100, 0x10), insns)).toEqual([]); // range before all insns
    expect(collectFuncInsns(fn(0x1000, 0), insns)).toEqual([]); // zero-size function
    expect(collectFuncInsns(fn(0x1002, 2), insns)).toEqual([]); // gap between insns
  });

  it("returns an empty array when there are no instructions at all", () => {
    expect(collectFuncInsns(fn(0x1000, 0x100), [])).toEqual([]);
  });

  it("gives every instruction to exactly one of a set of adjacent functions", () => {
    const insns = layout(0x1000, 12);
    const funcs = [fn(0x1000, 16, "a"), fn(0x1010, 16, "b"), fn(0x1020, 16, "c")];
    const collected = funcs.flatMap((f) => collectFuncInsns(f, insns));
    expect(addrs(collected)).toEqual(addrs(insns));
  });

  it("handles a non-ascending instruction array", () => {
    // The address index only binary-searches ascending input; out-of-order
    // input must still match the original linear scan (which stopped at the
    // first address past the function).
    const insns = [...layout(0x1000, 4)].reverse();
    expect(collectFuncInsns(fn(0x1004, 8), insns)).toEqual([]); // 0x100c stops the scan
    expect(addrs(collectFuncInsns(fn(0x1000, 0x100), insns))).toEqual(addrs(insns));
  });

  it("rebuilds its cached index when the array grows", () => {
    const insns = layout(0x1000, 4);
    expect(addrs(collectFuncInsns(fn(0x1000, 0x100), insns))).toEqual([
      0x1000, 0x1004, 0x1008, 0x100c,
    ]);
    insns.push(...layout(0x1010, 2));
    expect(addrs(collectFuncInsns(fn(0x1000, 0x100), insns))).toEqual([
      0x1000, 0x1004, 0x1008, 0x100c, 0x1010, 0x1014,
    ]);
  });

  it("returns a fresh array each call", () => {
    const insns = layout(0x1000, 4);
    const func = fn(0x1000, 16);
    const a = collectFuncInsns(func, insns);
    const b = collectFuncInsns(func, insns);
    expect(a).not.toBe(b);
    expect(a).toEqual(b);
  });
});

describe("buildFuncInsnMap", () => {
  it("groups instructions by owning function address", () => {
    const insns = layout(0x1000, 8);
    const funcs = [fn(0x1000, 8, "a"), fn(0x1008, 12, "b"), fn(0x1014, 12, "c")];
    const map = buildFuncInsnMap(funcs, insns);

    expect([...map.keys()]).toEqual([0x1000, 0x1008, 0x1014]);
    expect(addrs(map.get(0x1000)!)).toEqual([0x1000, 0x1004]);
    expect(addrs(map.get(0x1008)!)).toEqual([0x1008, 0x100c, 0x1010]);
    expect(addrs(map.get(0x1014)!)).toEqual([0x1014, 0x1018, 0x101c]);
  });

  it("keeps an entry for a function with no instructions", () => {
    const insns = layout(0x1000, 2);
    const map = buildFuncInsnMap([fn(0x5000, 0x10, "empty")], insns);
    expect(map.get(0x5000)).toEqual([]);
  });

  it("matches collectFuncInsns for overlapping functions", () => {
    const insns = layout(0x1000, 8);
    const outer = fn(0x1000, 32, "outer");
    const inner = fn(0x1008, 8, "inner");
    const map = buildFuncInsnMap([outer, inner], insns);
    expect(map.get(outer.address)).toEqual(collectFuncInsns(outer, insns));
    expect(map.get(inner.address)).toEqual(collectFuncInsns(inner, insns));
  });
});

describe("getFuncInsns", () => {
  it("returns the prebuilt entry when the map has the address", () => {
    const insns = layout(0x1000, 8);
    const func = fn(0x1008, 8);
    const map = buildFuncInsnMap([func], insns);
    expect(getFuncInsns(func, insns, map)).toBe(map.get(0x1008));
  });

  it("falls back to a scan when the address is not in the map", () => {
    const insns = layout(0x1000, 8);
    const missing = fn(0x1008, 8);
    const map = buildFuncInsnMap([fn(0x1000, 8)], insns);
    expect(map.has(missing.address)).toBe(false);
    expect(addrs(getFuncInsns(missing, insns, map))).toEqual([0x1008, 0x100c]);
  });

  it("falls back to a scan when no map is given", () => {
    const insns = layout(0x1000, 8);
    expect(getFuncInsns(fn(0x1008, 8), insns)).toEqual(collectFuncInsns(fn(0x1008, 8), insns));
  });

  it("scans when the mapped entry would be empty but the address is absent", () => {
    const insns = layout(0x1000, 4);
    expect(getFuncInsns(fn(0x9000, 0x10), insns, new Map())).toEqual([]);
  });
});

describe("address index invalidation", () => {
  /** A single instruction at `address`. */
  const ins = (address: number): Instruction => ({
    address,
    mnemonic: "nop",
    opStr: "",
    size: 4,
    bytes: new Uint8Array(4),
  });

  // The index is cached per array. Length alone cannot detect a reorder, and a
  // stale index returns the wrong instructions for a function silently rather
  // than failing — the failure mode this codebase keeps getting bitten by.
  it("rebuilds the index when the same array is reordered in place", () => {
    const insns = [ins(0x1000), ins(0x1004), ins(0x1008)];
    // Prime the cache while ascending, so the binary-search path is taken and
    // the address index is live.
    expect(addrs(collectFuncInsns(fn(0x1000, 8), insns))).toEqual([0x1000, 0x1004]);

    // Same length, same objects, different order.
    insns.reverse();

    // Descending input takes the linear fallback, which reproduces the original
    // scan's early `break` and so finds nothing — that is the legacy-faithful
    // answer, not a regression. What matters is that it is reached at all: a
    // stale index would still claim "ascending" and binary-search the old
    // addresses, pulling instructions out of the wrong slots ([0x1008, 0x1004]).
    expect(addrs(collectFuncInsns(fn(0x1000, 8), insns))).toEqual([]);
  });

  it("rebuilds the index when array contents are replaced at the same length", () => {
    const insns = [ins(0x1000), ins(0x1004)];
    expect(addrs(collectFuncInsns(fn(0x1000, 8), insns))).toEqual([0x1000, 0x1004]);

    insns[0] = ins(0x2000);
    insns[1] = ins(0x2004);

    expect(addrs(collectFuncInsns(fn(0x1000, 8), insns))).toEqual([]);
    expect(addrs(collectFuncInsns(fn(0x2000, 8), insns))).toEqual([0x2000, 0x2004]);
  });
});

describe("funcXrefEntries", () => {
  const xref = (from: number, to: number, type = "branch") =>
    ({ from, to, type }) as unknown as Xref;

  it("returns exactly the rows inside [address, address + size)", () => {
    const map = new Map<number, Xref[]>([
      [0x1000, [xref(0x900, 0x1000)]],
      [0x1008, [xref(0x1000, 0x1008)]],
      [0x1010, [xref(0x1000, 0x1010)]],
      [0x1020, [xref(0x1000, 0x1020)]],
    ]);

    expect(funcXrefEntries(fn(0x1008, 0x10), map).map(([a]) => a)).toEqual([0x1008, 0x1010]);
  });

  it("includes the start address and excludes the end address", () => {
    const map = new Map<number, Xref[]>([
      [0x1000, [xref(0, 0x1000)]],
      [0x1008, [xref(0, 0x1008)]],
    ]);

    expect(funcXrefEntries(fn(0x1000, 8), map).map(([a]) => a)).toEqual([0x1000]);
  });

  it("keeps the row objects themselves, not copies", () => {
    // The far side does `new Map(rows)` and the decompiler reads `x.type` off
    // these objects; cloning here would be pure cost.
    const rows = [xref(0, 0x1000)];
    const map = new Map<number, Xref[]>([[0x1000, rows]]);

    expect(funcXrefEntries(fn(0x1000, 4), map)[0][1]).toBe(rows);
  });

  it("returns nothing for a zero-sized function", () => {
    const map = new Map<number, Xref[]>([[0x1000, [xref(0, 0x1000)]]]);

    expect(funcXrefEntries(fn(0x1000, 0), map)).toEqual([]);
  });

  it("preserves map order, which is what Array.from(map.entries()) gave", () => {
    // Insertion order, deliberately not sorted: `buildTypedXrefMap` builds the
    // map in instruction order and a caller that reconstructs it must iterate
    // the same way.
    const map = new Map<number, Xref[]>([
      [0x1010, [xref(0, 0x1010)]],
      [0x1000, [xref(0, 0x1000)]],
      [0x1008, [xref(0, 0x1008)]],
    ]);

    expect(funcXrefEntries(fn(0x1000, 0x20), map).map(([a]) => a)).toEqual([
      0x1010, 0x1000, 0x1008,
    ]);
  });
});

/**
 * The property `funcXrefEntries` and the slim decompile payload rest on:
 * `buildCFG` asks the xref map only for addresses inside the function it was
 * given. That is a fact about `buildCFG`, not about any image, and nothing else
 * in the tree would notice it changing — so it is asked of `buildCFG` directly,
 * by recording every key the map is queried for.
 *
 * A source scrape would encode formatting; a corpus run cannot see it at all,
 * because dropping the whole xref map changes the emitted C of not one of the
 * 3059 functions of the five real images this was measured over. The mechanism
 * is nevertheless live — an injected in-range branch xref does move the output —
 * so the guard has to be behavioural (peek-a-bin-9gc9).
 */
describe("buildCFG consults the xref map only inside the function", () => {
  /** A Map that remembers which keys it was asked for. */
  class SpyMap extends Map<number, Xref[]> {
    asked: number[] = [];
    override get(key: number): Xref[] | undefined {
      this.asked.push(key);
      return super.get(key);
    }
  }

  it("asks for no address outside [address, address + size)", () => {
    const insns = layout(0x1000, 40); // 0x1000 .. 0x109c
    const func = fn(0x1020, 0x20);
    // Rows on both sides of the window, so a query that strayed would find one.
    // Rows on only every other address, so a lookup that fell back to a
    // neighbour on a miss — `get(a) ?? get(a + 4)` — would be recorded too. With
    // a row at every address such a fallback never evaluates and the guard reads
    // clean over it.
    const map = new SpyMap();
    for (const [i, insn] of insns.entries()) {
      if (i % 2 === 0) {
        map.set(insn.address, [
          { from: 0x900, to: insn.address, type: "branch" } as unknown as Xref,
        ]);
      }
    }

    buildCFG(func, insns, map);

    expect(map.asked.length).toBeGreaterThan(0);
    const strayed = map.asked.filter((a) => a < func.address || a >= func.address + func.size);
    expect(strayed).toEqual([]);
  });

  it("gets the same blocks from the slimmed map as from the whole one", () => {
    const insns = layout(0x1000, 40);
    const func = fn(0x1020, 0x20);
    const whole = new Map<number, Xref[]>();
    for (const insn of insns) {
      whole.set(insn.address, [
        { from: 0x900, to: insn.address, type: "branch" } as unknown as Xref,
      ]);
    }
    const slim = new Map(funcXrefEntries(func, whole));

    const a = buildCFG(func, insns, whole);
    const b = buildCFG(func, collectFuncInsns(func, insns), slim);

    expect(b.map((x) => [x.startAddr, x.endAddr, x.succs, x.preds])).toEqual(
      a.map((x) => [x.startAddr, x.endAddr, x.succs, x.preds]),
    );
    // Non-vacuous: those xrefs really did split the window into blocks.
    expect(a.length).toBeGreaterThan(1);
  });
});

describe("funcExceptionRecord", () => {
  const rf = (o: Partial<RuntimeFunction> & { beginAddress: number }): RuntimeFunction => ({
    endAddress: o.beginAddress + 0x20,
    unwindInfoAddress: 0,
    handlerAddress: 0x500,
    handlerFlags: 0x1,
    ...o,
  });

  it("matches a record whose begin address equals the function's", () => {
    const rec = rf({ beginAddress: 0x1000 });
    expect(funcExceptionRecord({ address: 0x1000, size: 0x20 }, [rec])).toBe(rec);
  });

  it("recovers the image base when the table is in RVAs (peek-a-bin-yrh)", () => {
    // The real shape: `.pdata` holds RVAs, `DisasmFunction.address` is a VA.
    const rec = rf({ beginAddress: 0x1000 });
    expect(funcExceptionRecord({ address: 0x140001000, size: 0x20 }, [rec])).toBe(rec);
  });

  it("ignores a record with no handler", () => {
    const rec = rf({ beginAddress: 0x1000, handlerAddress: undefined, handlerFlags: 0 });
    expect(funcExceptionRecord({ address: 0x140001000, size: 0x20 }, [rec])).toBeUndefined();
    const flagless = rf({ beginAddress: 0x1000, handlerFlags: 0x4 }); // not E/UHANDLER
    expect(funcExceptionRecord({ address: 0x140001000, size: 0x20 }, [flagless])).toBeUndefined();
  });

  it("does not return a record that merely covers the function", () => {
    // The predicate is a BEGIN-ADDRESS equality, not a containment or an
    // overlap: a record spanning this function but starting elsewhere describes
    // some other function's frame.
    //
    // THE UNITS HAVE TO AGREE FOR THIS TO TEST ANYTHING, and a first draft of it
    // did not: with the record in RVAs and the function at a real VA, a
    // containment test fails on the *offset* rather than on the rule, so
    // swapping the equality for a containment left every assertion here green.
    // 0x1010 against 0x1000..0x2000 is the same unit — an image based at 0, or a
    // caller that normalised the table — so containment would match and
    // equality must not. 0x10 is not a multiple of 64K either, so the congruent
    // branch declines it too and `undefined` is the whole answer.
    const rec = rf({ beginAddress: 0x1000, endAddress: 0x2000 });
    expect(funcExceptionRecord({ address: 0x1010, size: 0x10 }, [rec])).toBeUndefined();
    // The same record read as an RVA table, where the function is 64K-congruent
    // with a *different* row: still not the covering one.
    expect(funcExceptionRecord({ address: 0x140001010, size: 0x10 }, [rec])).toBeUndefined();
  });

  it("discards an ambiguous congruent match rather than guessing", () => {
    // Two records exactly 64K apart are both congruent with one VA, and neither
    // extent settles it. A wrong `__try` is worse than a missing one.
    const a = rf({ beginAddress: 0x1000, endAddress: 0x1030 });
    const b = rf({ beginAddress: 0x11000, endAddress: 0x11030 });
    expect(funcExceptionRecord({ address: 0x140011000, size: 0x20 }, [a, b])).toBeUndefined();
  });

  it("breaks a congruent tie on the extent", () => {
    const a = rf({ beginAddress: 0x1000, endAddress: 0x1030 }); // size 0x30
    const b = rf({ beginAddress: 0x11000, endAddress: 0x11020 }); // size 0x20
    expect(funcExceptionRecord({ address: 0x140011000, size: 0x20 }, [a, b])).toBe(b);
  });

  it("is idempotent — the client may send its own answer back", () => {
    // THE PROPERTY THE SLICE RESTS ON (peek-a-bin-qmlz): the client applies this
    // and sends the survivor, and the worker applies it again to that one row.
    // Asked over each of the three routes into an answer.
    const cases: [{ address: number; size: number }, RuntimeFunction[]][] = [
      // same address
      [{ address: 0x1000, size: 0x20 }, [rf({ beginAddress: 0x1000 })]],
      // congruent, sole survivor
      [
        { address: 0x140001000, size: 0x20 },
        [rf({ beginAddress: 0x1000 }), rf({ beginAddress: 0x2000 })],
      ],
      // congruent, chosen by the extent tie-break
      [
        { address: 0x140011000, size: 0x20 },
        [
          rf({ beginAddress: 0x1000, endAddress: 0x1030 }),
          rf({ beginAddress: 0x11000, endAddress: 0x11020 }),
        ],
      ],
    ];
    for (const [func, table] of cases) {
      const once = funcExceptionRecord(func, table);
      expect(once).toBeDefined();
      expect(funcExceptionRecord(func, [once as RuntimeFunction])).toBe(once);
    }
  });

  it("answers undefined for an absent or empty table", () => {
    expect(funcExceptionRecord({ address: 0x1000, size: 0x20 }, undefined)).toBeUndefined();
    expect(funcExceptionRecord({ address: 0x1000, size: 0x20 }, [])).toBeUndefined();
  });
});
