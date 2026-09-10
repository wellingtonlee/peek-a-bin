/**
 * EMITTED FUNCTIONS WHOSE BODIES ARE THE SAME TEXT, ONCE THE NAMES THE EMITTER
 * MINTS FROM ADDRESSES ARE NORMALISED AWAY.
 *
 * `sub_<hex>`, `loc_<hex>`, `struct_<n>` and every hex constant are spelled
 * from an address or a counter, so two functions the compiler emitted from one
 * template — a CRT stub linked twice, an IAT thunk per import — differ in the
 * emitted C only in those spellings. Collapsing them to placeholders and
 * grouping on the rest says how much of the output a reader would be reading
 * twice, and whether a change that touches the emitter moved a whole family
 * or one member of it.
 *
 * **REPORT-ONLY, in every column, and deliberately.** A duplicate body is not
 * a defect: the machine really does contain two copies, and emitting each
 * where it stands is the honest spelling. Nothing here is gateable at 0 and a
 * rise or a fall is information about the binary or about detection as much
 * as about the decompiler. `bodies` and `headersLocated` are the liveness
 * halves — a text scrape fails by silently matching nothing.
 *
 * **`selfRecursiveThunks` IS THE ROW WITH A DIRECTION, and it is why the audit
 * exists in this session.** `int RtlVirtualUnwind() { return RtlVirtualUnwind(); }`
 * is what an x64 IAT thunk — `jmp qword ptr [rip + __imp_RtlVirtualUnwind]` —
 * decompiles to when the function is NAMED after the import it jumps to and
 * the lifted tail call then resolves to the same name: a body that claims the
 * function calls itself forever. Three per x64 binary at `6299113`. The
 * thunk child of `peek-a-bin-n9cl` is expected to take it to 0, at which point
 * it can become a gate; today it is a count with an owner. The row is derived
 * from the header name and the body text alone, so a rename that hides the
 * recursion behind a different callee spelling takes the row to 0 without
 * fixing anything — read it beside `undefined callees, external`.
 *
 * WHAT IT DOES NOT SEE. Two bodies that differ in one SSA version number, one
 * register width, or one folded constant are two groups; the normalisation is
 * only of what the emitter provably derives from an address. And a group says
 * the *text* is the same, never that the two functions are the same code —
 * two three-line stubs can coincide by accident.
 */

import { declaredParams } from "./emitAudits";
import type { FuncRec } from "./sweep";

export interface DuplicateBodyGroup {
  tag: string;
  size: number;
  names: string[];
  addrs: number[];
  /** Lines in one member's body, so a group of two-liners reads as one. */
  lines: number;
  /** The normalised body, truncated, so a row is adjudicable from the jsonl. */
  sample: string;
}

export interface DuplicateBodiesResult {
  /** Functions read. Instrument liveness. */
  funcs: number;
  /** Functions whose signature line was located. Liveness for the header read. */
  headersLocated: number;
  /** Non-empty normalised bodies, i.e. the population grouped. Liveness. */
  bodies: number;
  /** Groups of two or more identical normalised bodies. */
  groups: number;
  /** Functions inside such a group. */
  functions: number;
  largestGroup: number;
  /** Header name equal to a `return <name>(` callee in its own body. */
  selfRecursiveThunks: number;
  thunkNames: string[];
  rows: DuplicateBodyGroup[];
}

export const emptyDuplicateBodies = (): DuplicateBodiesResult => ({
  funcs: 0,
  headersLocated: 0,
  bodies: 0,
  groups: 0,
  functions: 0,
  largestGroup: 0,
  selfRecursiveThunks: 0,
  thunkNames: [],
  rows: [],
});

/** The identifier the signature line declares — `int sub_401000(void) {` → `sub_401000`. */
export function headerName(line: string): string | null {
  const m = /([A-Za-z_]\w*)\s*\(/.exec(line);
  return m ? m[1] : null;
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * The body with every address-derived spelling replaced by a placeholder.
 *
 * Written so a reformat cannot break it: whitespace runs collapse to one space
 * and blank lines vanish, so two bodies that differ only in indentation are one
 * body. The function's own name goes too — a thunk that names itself and a
 * thunk that names its neighbour are the same shape.
 */
export function normaliseBody(body: string, ownName: string | null): string {
  let s = body;
  if (ownName !== null) s = s.replace(new RegExp(`\\b${escapeRe(ownName)}\\b`, "g"), "SELF");
  return s
    .replace(/\bsub_[0-9A-Fa-f]+\b/g, "sub_#")
    .replace(/\bloc_[0-9A-Fa-f]+\b/g, "loc_#")
    .replace(/\bstruct_\w+/g, "struct_#")
    .replace(/\b0x[0-9A-Fa-f]+\b/g, "0x#")
    .split("\n")
    .map((l) => l.trim().replace(/\s+/g, " "))
    .filter((l) => l.length > 0)
    .join("\n");
}

export function auditDuplicateBodies(
  sets: { tag: string; funcs: FuncRec[] }[],
): DuplicateBodiesResult {
  const out = emptyDuplicateBodies();
  for (const { tag, funcs } of sets) {
    const byBody = new Map<string, { names: string[]; addrs: number[]; lines: number }>();
    for (const f of funcs) {
      const code = f.code ?? "";
      if (code === "") continue;
      out.funcs++;
      const sig = declaredParams(code);
      if (sig === null) continue;
      out.headersLocated++;
      const name = headerName(sig.line);
      const body = code.slice(sig.bodyAt);
      if (name !== null && new RegExp(`\\breturn\\s+${escapeRe(name)}\\s*\\(`).test(body)) {
        out.selfRecursiveThunks++;
        if (out.thunkNames.length < 12) out.thunkNames.push(`${tag}:${name}`);
      }
      const norm = normaliseBody(body, name);
      // A body that is nothing but its closing brace is not a duplicate of
      // anything; it is an empty function.
      if (norm.replace(/[{}\s]/g, "") === "") continue;
      out.bodies++;
      const g = byBody.get(norm) ?? { names: [], addrs: [], lines: norm.split("\n").length };
      g.names.push(f.name);
      g.addrs.push(f.addr);
      byBody.set(norm, g);
    }
    for (const [norm, g] of byBody) {
      if (g.names.length < 2) continue;
      out.groups++;
      out.functions += g.names.length;
      out.largestGroup = Math.max(out.largestGroup, g.names.length);
      out.rows.push({
        tag,
        size: g.names.length,
        names: g.names,
        addrs: g.addrs,
        lines: g.lines,
        sample: norm.slice(0, 240),
      });
    }
  }
  out.rows.sort((a, b) => b.size - a.size || a.tag.localeCompare(b.tag));
  return out;
}
