/**
 * The order `sweep.ts` decompiles a binary's functions in.
 *
 * A LEAF: imports one type and nothing else, so `build/sweepOrder.test.ts`
 * can pin the walk without loading `FileSession` (which pulls Capstone WASM in
 * at module scope through `mcp/disasm.ts`).
 *
 * WHY THE ORDER IS A VARIABLE AT ALL. `StructRegistry` is cross-function state
 * shared for the lifetime of a loaded file, so the C emitted for a function
 * depends on which functions were decompiled before it — the sweep's own
 * header says so. Production (the worker, and this harness by default) goes
 * in ADDRESS order, which is neither callee-first nor caller-first; it is the
 * linker's layout. The readability epic asked whether decompiling callees
 * before their callers would let a caller see a struct the callee had already
 * shaped (`peek-a-bin-5b6q.10`). A browser prefetch to arrange that was
 * REFUSED on cost grounds (the disasm worker is a serial FIFO shared with
 * `hybridDisassemble`); this flag exists so the question can be answered by
 * MEASUREMENT instead — run the sweep in both orders and diff the C.
 */
import type { DisasmFunction } from "../src/disasm/types";

export type SweepOrder = "address" | "postorder";

export const SWEEP_ORDERS: readonly SweepOrder[] = ["address", "postorder"];

/**
 * `functions` reordered so that every callee is decompiled before every
 * function that calls it, as far as the call graph permits.
 *
 * Depth-first over `callGraph` (caller → callees, the shape `FileSession`
 * publishes), emitting a function after its callees — a post-order. Roots are
 * taken in ADDRESS order so the result is deterministic and, for a graph with
 * no calls at all, identical to the input. A callee that is not a detected
 * function (an import slot, a wild target) is ignored. BACK EDGES ARE BROKEN
 * AT THE CYCLE: a callee that is still on the DFS stack is skipped, so a
 * recursive function, or A ↔ B, is emitted once, in the order the DFS first
 * reached it — some caller in a cycle necessarily precedes its callee, and
 * which one is a property of the walk, not a claim about the program.
 *
 * Returns a PERMUTATION of `functions`: every function exactly once. A walk
 * that lost or duplicated a function would silently change every downstream
 * denominator, so that is asserted here rather than assumed.
 *
 * Iterative, because a 2000-function binary with a deep call chain would
 * overflow a recursive walk's stack in a way no test fixture reaches.
 */
export function postorderFunctions(
  functions: readonly DisasmFunction[],
  callGraph: ReadonlyMap<number, readonly number[]>,
): DisasmFunction[] {
  const byAddr = new Map(functions.map((f) => [f.address, f]));
  const roots = [...functions].sort((a, b) => a.address - b.address);
  const done = new Set<number>();
  const onStack = new Set<number>();
  const out: DisasmFunction[] = [];

  for (const root of roots) {
    if (done.has(root.address)) continue;
    // Each frame: the function and how many of its callees have been visited.
    const stack: { addr: number; callees: readonly number[]; next: number }[] = [
      { addr: root.address, callees: calleesOf(callGraph, root.address), next: 0 },
    ];
    onStack.add(root.address);
    while (stack.length > 0) {
      const top = stack[stack.length - 1];
      if (top.next < top.callees.length) {
        const callee = top.callees[top.next++];
        // Not a function we decompile, already emitted, or a back edge.
        if (!byAddr.has(callee) || done.has(callee) || onStack.has(callee)) continue;
        onStack.add(callee);
        stack.push({ addr: callee, callees: calleesOf(callGraph, callee), next: 0 });
      } else {
        stack.pop();
        onStack.delete(top.addr);
        done.add(top.addr);
        out.push(byAddr.get(top.addr) as DisasmFunction);
      }
    }
  }

  if (out.length !== functions.length) {
    throw new Error(
      `postorderFunctions: ${out.length} emitted of ${functions.length} — the walk is not a permutation`,
    );
  }
  return out;
}

/** Callees in ascending address order, so the walk is deterministic whatever order the map holds. */
function calleesOf(callGraph: ReadonlyMap<number, readonly number[]>, addr: number): number[] {
  return [...(callGraph.get(addr) ?? [])].sort((a, b) => a - b);
}
