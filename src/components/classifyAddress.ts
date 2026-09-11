/**
 * Which kind of place in the image a bare number names — a leaf beside
 * `parseBranchTarget`'s home in `shared.tsx`, kept out of that file because
 * this one imports no React and is asked from a `useMemo` over every hex
 * literal on a decompiled page.
 */
import { isCodeSection, sectionAtVirtualAddress } from "../pe/sections";
import type { SectionHeader } from "../pe/types";

export type AddressKind = "code" | "data";

/**
 * `"code"` for a value inside a code section, `"data"` for a value inside any
 * other section, `null` for everything else.
 *
 * THE GROUNDING IS "INSIDE A SECTION", NOT "INSIDE THE IMAGE". A hex literal
 * in emitted C is far more often a mask, a stride or a struct offset than an
 * address, and any of those can land between `imageBase` and
 * `imageBase + sizeOfImage` — the PE headers and the alignment gaps between
 * sections are inside the image and hold nothing a reader can be sent to. So a
 * value in no section answers `null` even when the image-extent test would
 * pass, and the extent test is kept only as the cheap first refusal, so a
 * `0x10` never walks the section table.
 *
 * `"data"` is "any section that is not code" rather than `isDataSection`,
 * deliberately: the hex view shows every section's bytes, so an address in a
 * section that is neither executable nor readable-and-not-executable (a
 * write-only `.bss` with an odd flag set) is still somewhere the hex tab can
 * take the reader. `isDataSection`'s question — could a pointer plausibly
 * target this? — is the xref builder's, not the navigator's.
 *
 * `sectionAtVirtualAddress` is the one declaration of the section bound
 * (virtual size, not raw size); this does not re-derive it.
 */
export function classifyAddress(
  value: number,
  sections: readonly SectionHeader[],
  imageBase: number,
  sizeOfImage: number,
): AddressKind | null {
  if (!Number.isFinite(value) || value < imageBase || value >= imageBase + sizeOfImage) {
    return null;
  }
  const section = sectionAtVirtualAddress(sections, imageBase, value);
  if (section === undefined) return null;
  return isCodeSection(section) ? "code" : "data";
}
