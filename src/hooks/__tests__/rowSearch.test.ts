import { describe, it, expect, vi } from "vitest";

// useDisassemblyRows pulls in the worker client, which constructs a `Worker` at
// module load. There is no Worker in the node test environment, and these tests
// exercise the module's pure search helpers, so stub the singleton away.
vi.mock("../../workers/disasmClient", () => ({ disasmWorker: {} }));

import { binarySearchRows, rowAddress, type DisplayRow } from "../useDisassemblyRows";
import { binarySearchFunc } from "../useDerivedState";
import type { DisasmFunction, Instruction } from "../../disasm/types";

function insn(address: number, blockIdx = 0): DisplayRow {
  return { kind: "insn", insn: { address, mnemonic: "nop", opStr: "", size: 1 } as Instruction, blockIdx };
}
function label(address: number): DisplayRow {
  return { kind: "label", fn: { address, size: 0x10, name: "f" } as DisasmFunction };
}
function data(address: number): DisplayRow {
  // Only `address` is read by rowAddress.
  return { kind: "data", item: { address } as DisplayRow extends { kind: "data"; item: infer I } ? I : never };
}
const separator: DisplayRow = { kind: "separator" };

function fn(address: number, size: number): DisasmFunction {
  return { address, size, name: `sub_${address.toString(16)}` } as DisasmFunction;
}

describe("rowAddress", () => {
  it("reads the address out of each addressed row kind", () => {
    expect(rowAddress(insn(0x1000))).toBe(0x1000);
    expect(rowAddress(label(0x2000))).toBe(0x2000);
    expect(rowAddress(data(0x3000))).toBe(0x3000);
  });

  it("returns null for a separator, which carries no address", () => {
    expect(rowAddress(separator)).toBeNull();
  });

  it("treats address 0 as an address, not as absent", () => {
    expect(rowAddress(insn(0))).toBe(0);
  });
});

describe("binarySearchRows", () => {
  it("finds an exact match", () => {
    const rows = [insn(0x1000), insn(0x1004), insn(0x1008)];
    expect(binarySearchRows(rows, 0x1004)).toBe(1);
  });

  it("returns the last row at or before the address", () => {
    const rows = [insn(0x1000), insn(0x1010), insn(0x1020)];
    expect(binarySearchRows(rows, 0x1018)).toBe(1);
  });

  it("clamps below the first row to index 0", () => {
    const rows = [insn(0x1000), insn(0x1010)];
    expect(binarySearchRows(rows, 0x0500)).toBe(0);
  });

  it("clamps above the last row to the final index", () => {
    const rows = [insn(0x1000), insn(0x1010)];
    expect(binarySearchRows(rows, 0xffff)).toBe(1);
  });

  it("returns 0 for an empty list", () => {
    expect(binarySearchRows([], 0x1000)).toBe(0);
  });

  it("handles a single row", () => {
    expect(binarySearchRows([insn(0x1000)], 0x1000)).toBe(0);
    expect(binarySearchRows([insn(0x1000)], 0x0)).toBe(0);
    expect(binarySearchRows([insn(0x1000)], 0xffff)).toBe(0);
  });

  it("searches across mixed row kinds", () => {
    const rows = [label(0x1000), insn(0x1000), insn(0x1004), data(0x1008)];
    expect(binarySearchRows(rows, 0x1008)).toBe(3);
    expect(binarySearchRows(rows, 0x1004)).toBe(2);
  });

  // REGRESSION (fixed in useDisassemblyRows.ts). A separator landing on the
  // binary-search path used to be treated as "too high", discarding the entire
  // right half — so "go to address" scrolled to a much earlier row whenever a
  // function boundary sat mid-search. Separators appear between every pair of
  // functions, so this fired on any realistically-sized listing.
  it("is not derailed by a separator on the search path", () => {
    const rows = [insn(0x1000), separator, insn(0x2000)];
    expect(binarySearchRows(rows, 0x2000)).toBe(2);
  });

  it("is not derailed by a separator with rows on both sides", () => {
    const rows = [insn(0x1000), insn(0x1004), separator, insn(0x2000), insn(0x2004)];
    expect(binarySearchRows(rows, 0x2004)).toBe(4);
    expect(binarySearchRows(rows, 0x2000)).toBe(3);
    expect(binarySearchRows(rows, 0x1004)).toBe(1);
  });

  it("handles consecutive separators", () => {
    const rows = [insn(0x1000), separator, separator, separator, insn(0x2000)];
    expect(binarySearchRows(rows, 0x2000)).toBe(4);
    expect(binarySearchRows(rows, 0x1000)).toBe(0);
  });

  it("handles a separator as the final row", () => {
    const rows = [insn(0x1000), insn(0x2000), separator];
    expect(binarySearchRows(rows, 0x2000)).toBe(1);
    expect(binarySearchRows(rows, 0xffff)).toBe(1);
  });

  it("handles a separator as the first row", () => {
    const rows = [separator, insn(0x1000), insn(0x2000)];
    expect(binarySearchRows(rows, 0x2000)).toBe(2);
  });

  it("returns 0 for a list of only separators", () => {
    expect(binarySearchRows([separator, separator], 0x1000)).toBe(0);
  });

  // The strongest check: agree with a linear scan on a realistic listing that
  // interleaves labels, instructions, data and separators.
  it("agrees with a linear scan across a realistic listing", () => {
    const rows: DisplayRow[] = [];
    const addresses: number[] = [];
    let addr = 0x401000;
    for (let f = 0; f < 12; f++) {
      rows.push(label(addr));
      addresses.push(addr);
      for (let i = 0; i < 7; i++) {
        rows.push(insn(addr));
        addresses.push(addr);
        addr += 4;
      }
      rows.push(separator);
      addresses.push(Number.NaN); // no address
      addr += 0x10;
    }

    const linear = (target: number) => {
      let best = 0;
      for (let i = 0; i < rows.length; i++) {
        const a = rowAddress(rows[i]);
        if (a !== null && a <= target) best = i;
      }
      return best;
    };

    for (let target = 0x400ff0; target < addr + 0x20; target += 2) {
      expect(binarySearchRows(rows, target), `0x${target.toString(16)}`).toBe(linear(target));
    }
  });
});

describe("binarySearchFunc", () => {
  const funcs = [fn(0x1000, 0x10), fn(0x1020, 0x10), fn(0x1040, 0x20)];

  it("finds the function containing an address", () => {
    expect(binarySearchFunc(funcs, 0x1000)?.address).toBe(0x1000);
    expect(binarySearchFunc(funcs, 0x1008)?.address).toBe(0x1000);
    expect(binarySearchFunc(funcs, 0x1045)?.address).toBe(0x1040);
  });

  it("treats the start as inclusive and the end as exclusive", () => {
    expect(binarySearchFunc(funcs, 0x1000)?.address).toBe(0x1000);
    expect(binarySearchFunc(funcs, 0x100f)?.address).toBe(0x1000);
    expect(binarySearchFunc(funcs, 0x1010)).toBeNull();
  });

  it("returns null for an address in a gap between functions", () => {
    expect(binarySearchFunc(funcs, 0x1015)).toBeNull();
    expect(binarySearchFunc(funcs, 0x1035)).toBeNull();
  });

  it("returns null below the first and above the last function", () => {
    expect(binarySearchFunc(funcs, 0x0fff)).toBeNull();
    expect(binarySearchFunc(funcs, 0x1060)).toBeNull();
    expect(binarySearchFunc(funcs, 0xffffff)).toBeNull();
  });

  it("returns null for an empty list", () => {
    expect(binarySearchFunc([], 0x1000)).toBeNull();
  });

  it("handles a single function", () => {
    const one = [fn(0x1000, 0x10)];
    expect(binarySearchFunc(one, 0x1005)?.address).toBe(0x1000);
    expect(binarySearchFunc(one, 0x1010)).toBeNull();
  });

  it("ignores zero-sized functions, which contain no addresses", () => {
    expect(binarySearchFunc([fn(0x1000, 0)], 0x1000)).toBeNull();
  });

  it("agrees with a linear scan across a dense listing", () => {
    const many: DisasmFunction[] = [];
    for (let i = 0; i < 200; i++) many.push(fn(0x400000 + i * 0x30, 0x20)); // 0x10 gap

    const linear = (target: number) =>
      many.find(f => target >= f.address && target < f.address + f.size) ?? null;

    for (let target = 0x3fffff; target < 0x400000 + 200 * 0x30 + 0x40; target += 7) {
      const expected = linear(target);
      const actual = binarySearchFunc(many, target);
      expect(actual?.address ?? null, `0x${target.toString(16)}`).toBe(expected?.address ?? null);
    }
  });
});
