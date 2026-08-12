import { describe, expect, it } from "vitest";
import { buildFuncInsnMap, collectFuncInsns, getFuncInsns } from "../funcInsns";
import type { DisasmFunction, Instruction } from "../types";

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
