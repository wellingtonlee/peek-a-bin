/**
 * What the emitter needs to NAME a dereferenced absolute address — and nothing
 * the pipeline decides with.
 *
 * `*(int32_t*)(0x414620) != 0` is true and unreadable. The name the reader
 * wants, `g_414620`, is a claim: that 0x414620 is an object in one of the
 * image's data sections. This context is the evidence for that claim, built by
 * whoever holds the `PEFile` — the browser's `configure` (`dispatch.ts`), the MCP
 * session, `corpus/sweep.ts` — and handed to `decompileFunction` as its LAST
 * optional parameter, the same way `calleeClobbers` and `structTap` arrived:
 * appending is what keeps every existing call site unrenumbered.
 *
 * THE GROUNDING RULE, stated once (`emit.ts`'s `globalAt` applies it): a name is
 * spelled only for a constant that is DEREFERENCED — `deref(const)` or a `store`
 * to one — and only when `dataRangeAt` places the address in a data section. The
 * dereference is the provenance. A bare constant that happens to equal a data
 * address (`lea rcx, [rip + X]`, an address taken and passed on) stays a literal
 * in this stage, deliberately: the emitter's string substitution already names
 * constants by VALUE with no provenance check (`_stringMap.get(expr.value)`),
 * and a second value-coincidence rule beside it would be the same mistake twice.
 * `corpus/globals.ts` counts that residue.
 *
 * `dataRanges` come from `pe/sections.ts`'s `dataSectionTable` — the ONE data
 * section filter, shared with the xref builder — so "in a data section" here and
 * "a data xref" in the listing are one predicate.
 */
import type { DataSectionRange } from "../../pe/sections";

/** A data section as a VA range, with what the `extern` comment prints. */
export type DataRange = DataSectionRange;

export interface NamingContext {
  /** The image's data sections. Empty means "no image table was supplied": nothing is named. */
  dataRanges: readonly DataRange[];
  /**
   * IAT slot VA → the import it holds. The same map the lifter resolves
   * `call [slot]` through; here it names a LOAD of the slot — `mov rax, [rip +
   * slot]` — as `__imp_<func>`, the linker's own symbol for the slot. The value
   * is a pointer TO the function, so the spelling is never the bare API name.
   */
  iatMap: ReadonlyMap<number, { lib: string; func: string }>;
  /**
   * `IMAGE_LOAD_CONFIG_DIRECTORY.SecurityCookie` (`LoadConfigDirectory.securityCookie`)
   * — the FORMAT's statement of where the `/GS` cookie lives. The cookie's name
   * still comes from the idiom recogniser (`crtIdioms.ts`, which read the check
   * routine's body); this is the corroboration: where both speak and disagree,
   * `emit.ts` refuses the name and the address falls to the ordinary `g_` rule.
   * `undefined` and `0` both mean "the format did not say".
   */
  securityCookie?: number;
  /**
   * Address → name for a function pointer stored at that address. Declared here
   * so epic 2's B3 (`pfn_` naming) appends nothing to `decompileFunction`; NOT
   * read in this stage.
   */
  pfn?: ReadonlyMap<number, string>;
}

/** The data section containing `va`, or `undefined` — `[va, va + size)`. */
export function dataRangeAt(ranges: readonly DataRange[], va: number): DataRange | undefined {
  return ranges.find((r) => va >= r.va && va < r.va + r.size);
}

/**
 * THE ONE DECLARATION of the global's spelling: `g_` + the address in uppercase
 * hex, the case `sub_`/`loc_` use. `corpus/globals.ts` writes the pattern out
 * rather than importing this, so the audit does not agree with the emitter by
 * construction.
 */
export const GLOBAL_NAME_PREFIX = "g_";
export function globalName(va: number): string {
  return `${GLOBAL_NAME_PREFIX}${va.toString(16).toUpperCase()}`;
}
