/**
 * The one admission this parser spells INTO A VALUE, and the predicate that
 * reads it back.
 *
 * The rule it serves is the codebase's own: **a narrower answer must not wear a
 * complete one's shape.** Where the narrowed thing is a string, the value is the
 * only channel that reaches a reader — every render site prints these strings
 * verbatim, and the app has no toast mechanism (one must not be invented for a
 * bug fix; see the `copyText` refusal). So a name, path or resource string the
 * reader could not finish carries this marker and is therefore visibly not the
 * thing it would otherwise look like.
 *
 * WHY IT IS ONE DECLARATION NOW. It was three — `PDB_PATH_TRUNCATION_MARKER`
 * (`metadata.ts`, `peek-a-bin-nygv`), `NAME_TRUNCATION_MARKER` (`parser.ts`,
 * `peek-a-bin-tmo9`) and `RESOURCE_STRING_TRUNCATION_MARKER` (`resources.ts`,
 * `peek-a-bin-dhcx`) — each landing in a change that did not own the other two
 * files, each with its own docstring saying so and the last one filing the
 * consolidation. Three copies of a literal is this repo's most frequently
 * repaired defect shape, and here it is worse than usual: the marker is now
 * *read back* in two places (`isTruncatedValue` below, and
 * `utils/exportSchema.ts`'s report), so a copy that drifted would make a reader
 * silently stop recognising the admission rather than merely look different.
 *
 * WHY THESE CHARACTERS. `…`, `<` and `>` are bytes none of the strings this
 * parser reads can contain: a PE import, export or library name is an ASCII C
 * string a linker emitted, a Windows path may not hold `<` or `>`, and a
 * resource name or version string carrying them could not survive a round trip
 * through anything that resolves it — no API matches it, no ordinal table holds
 * it, no symbol is called it. So the marker can never be confused with the
 * file's own text.
 *
 * WHAT THIS DOES *NOT* DO, and the asymmetry is the decision each caller makes
 * for itself. A marked value is honest but still not usable, so where the string
 * feeds a DIGEST the marker alone is not enough: `readCString` additionally marks
 * the entry, which makes `computeImphash` refuse with `null`, because a hash over
 * a truncated name is well-formed, wrong, and only ever compared with another
 * tool's answer — it fails by matching nothing. Nothing in `resources.ts` or the
 * PDB path feeds a digest, so there the marker is the whole fix.
 *
 * Every caller decides truncation EXACTLY — "what I collected fell short of what
 * the string's own header declares", never "I reached the bound" — so a value of
 * exactly a cap's length that terminated properly is not marked
 * (`peek-a-bin-6qx9`'s off-by-one, in a different reader).
 */
export const TRUNCATION_MARKER = "… <truncated>";

/**
 * Whether a string carries {@link TRUNCATION_MARKER}, i.e. whether the reader had
 * to cut it short.
 *
 * One declaration, because `parseImports` and `parseExports` both decide an
 * entry-level flag from it and `utils/exportSchema.ts` reads it back out of a
 * value it did not produce.
 */
export function isTruncatedValue(value: string): boolean {
  return value.endsWith(TRUNCATION_MARKER);
}
