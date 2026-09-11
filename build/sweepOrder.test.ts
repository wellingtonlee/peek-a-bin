/**
 * `corpus/sweepOrder.ts`'s post-order walk, pinned without a binary.
 *
 * The walk decides which functions the shared `StructRegistry` sees first
 * under `PEEK_CORPUS_ORDER=postorder`, so the two properties that make a
 * postorder-vs-address diff mean anything are asserted here: every callee the
 * graph can order before its caller IS before it, and the result is a
 * permutation of the input (a walk that dropped or doubled a function would
 * silently change every downstream denominator). `build/` rather than
 * `corpus/` because it needs no binary, and imports the leaf rather than
 * `sweep.ts`, which would load Capstone WASM through `FileSession`.
 */
import { describe, expect, it } from "vitest";
import { postorderFunctions, SWEEP_ORDERS } from "../corpus/sweepOrder";
import type { DisasmFunction } from "../src/disasm/types";

const fn = (address: number): DisasmFunction => ({ name: `sub_${address.toString(16)}`, address, size: 16 });
const addrs = (fs: DisasmFunction[]) => fs.map((f) => f.address);
const graph = (edges: [number, number[]][]) => new Map<number, number[]>(edges);

describe("postorderFunctions", () => {
  it("emits every callee before its caller, down a chain", () => {
    // 1 → 2 → 3, laid out caller-first in address order.
    const out = postorderFunctions([fn(1), fn(2), fn(3)], graph([[1, [2]], [2, [3]]]));
    expect(addrs(out)).toEqual([3, 2, 1]);
  });

  it("is the identity for a graph with no calls", () => {
    const out = postorderFunctions([fn(1), fn(2), fn(3)], graph([]));
    expect(addrs(out)).toEqual([1, 2, 3]);
  });

  it("takes roots in address order however the input is ordered", () => {
    const out = postorderFunctions([fn(3), fn(1), fn(2)], graph([]));
    expect(addrs(out)).toEqual([1, 2, 3]);
  });

  it("breaks a back edge at the cycle and still emits each function once", () => {
    // 1 → 2 → 1 (mutual recursion) and 3 → 3 (self-recursion).
    const out = postorderFunctions([fn(1), fn(2), fn(3)], graph([[1, [2]], [2, [1]], [3, [3]]]));
    expect(addrs(out)).toEqual([2, 1, 3]);
  });

  it("ignores a callee that is not a detected function", () => {
    // An import slot or a wild target in the call graph is not something the
    // sweep decompiles, so it must neither appear nor derail the walk.
    const out = postorderFunctions([fn(1), fn(2)], graph([[1, [0x7fff, 2]], [2, [0x8000]]]));
    expect(addrs(out)).toEqual([2, 1]);
  });

  it("orders shared callees once, before the first caller that reaches them", () => {
    // 1 → 3, 2 → 3: 3 is emitted once, under root 1; root 2 finds it done.
    const out = postorderFunctions([fn(1), fn(2), fn(3)], graph([[1, [3]], [2, [3]]]));
    expect(addrs(out)).toEqual([3, 1, 2]);
  });

  it("visits callees in ascending address order whatever order the map lists them", () => {
    const out = postorderFunctions([fn(1), fn(2), fn(3)], graph([[1, [3, 2]]]));
    expect(addrs(out)).toEqual([2, 3, 1]);
  });

  it("returns a permutation of the input on a larger random-ish graph", () => {
    const N = 200;
    const fs = Array.from({ length: N }, (_, i) => fn(0x1000 + i * 0x10));
    // A deterministic pseudo-random call graph with cycles and dangling targets.
    const edges: [number, number[]][] = fs.map((f, i) => [
      f.address,
      [
        0x1000 + ((i * 7 + 3) % N) * 0x10,
        0x1000 + ((i * 13 + 11) % N) * 0x10,
        0x1000 + ((i + 1) % N) * 0x10,
        0xdead, // not a function
      ],
    ]);
    const out = postorderFunctions(fs, graph(edges));
    expect(out).toHaveLength(N);
    expect(new Set(addrs(out)).size).toBe(N);
    expect([...addrs(out)].sort((a, b) => a - b)).toEqual(addrs(fs));
  });

  it("puts every callee before its caller wherever the graph is acyclic", () => {
    // A DAG: position(callee) < position(caller) must hold for EVERY edge.
    const g = graph([[1, [2, 3]], [2, [4]], [3, [4, 5]], [4, [6]], [5, [6]]]);
    const fs = [1, 2, 3, 4, 5, 6].map(fn);
    const pos = new Map(addrs(postorderFunctions(fs, g)).map((a, i) => [a, i]));
    for (const [caller, callees] of g) {
      for (const callee of callees) {
        expect(pos.get(callee)).toBeLessThan(pos.get(caller) as number);
      }
    }
  });

  it("does not overflow on a long chain", () => {
    const N = 20000;
    const fs = Array.from({ length: N }, (_, i) => fn(i + 1));
    const edges: [number, number[]][] = fs.slice(0, -1).map((f) => [f.address, [f.address + 1]]);
    const out = postorderFunctions(fs, graph(edges));
    expect(out[0].address).toBe(N);
    expect(out[N - 1].address).toBe(1);
  });
});

describe("SWEEP_ORDERS", () => {
  it("names address first, the production default", () => {
    expect(SWEEP_ORDERS[0]).toBe("address");
    expect(SWEEP_ORDERS).toContain("postorder");
  });
});
