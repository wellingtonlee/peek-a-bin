/**
 * Section helpers shared by the parser, the UI hooks and the MCP server.
 *
 * These exist because the "which section holds the code?" predicate was written
 * out by hand at seven call sites, none of which referenced the named flag.
 */
import { IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ } from "./constants";
import type { SectionHeader } from "./types";

const DATA_SECTION_NAMES = new Set([".data", ".rdata", ".bss"]);

/**
 * True when a section is either named `.text` or carries IMAGE_SCN_MEM_EXECUTE.
 *
 * The name check is an exact match on the parsed name, and it is checked *first*
 * only in the sense that both halves apply to the same section — see
 * `findCodeSection` for what that means for ordering.
 */
export function isCodeSection(section: SectionHeader): boolean {
  return section.name === ".text" || (section.characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0;
}

/**
 * The section a binary's code lives in: the **first** section that is either
 * named `.text` or flagged executable.
 *
 * Note this is first-match-wins over the section table, not ".text if present,
 * otherwise the first executable section". A packed binary whose first section
 * is an unnamed executable stub returns that stub even when a later `.text`
 * exists. Every call site this replaced had exactly that behaviour, so it is
 * preserved deliberately rather than "fixed".
 *
 * Returns `undefined` when no section qualifies; callers decide whether that
 * means bail out or fall back to the whole image.
 */
export function findCodeSection(sections: readonly SectionHeader[]): SectionHeader | undefined {
  return sections.find(isCodeSection);
}

/**
 * True for sections that plausibly hold data a pointer could target: one of the
 * conventional data section names, or anything readable and not executable.
 *
 * The name comparison is NUL-stripped, trimmed and lowercased, unlike
 * `isCodeSection`'s exact match — that asymmetry is inherited from the call
 * sites and is not deliberate design.
 */
export function isDataSection(section: SectionHeader): boolean {
  const name = section.name.replace(/\0/g, "").trim().toLowerCase();
  if (DATA_SECTION_NAMES.has(name)) return true;
  return (
    (section.characteristics & IMAGE_SCN_MEM_READ) !== 0 &&
    (section.characteristics & IMAGE_SCN_MEM_EXECUTE) === 0
  );
}

/** Data section VA ranges, in the shape the xref builder expects. */
export function dataSectionRanges(
  sections: readonly SectionHeader[],
  imageBase: number,
): { va: number; size: number }[] {
  return sections
    .filter(isDataSection)
    .map((s) => ({ va: imageBase + s.virtualAddress, size: s.virtualSize }));
}

/**
 * The section containing a **virtual address**, or `undefined` if none does.
 *
 * `imageBase` is subtracted first, so callers pass the VA they already hold —
 * every one of them was doing that subtraction itself. The extent is
 * `[virtualAddress, virtualAddress + virtualSize)`, which is the reading the
 * call sites this replaced used; note it is the *virtual* size, so a section
 * whose raw data is longer does not claim the excess.
 */
export function sectionAtVirtualAddress(
  sections: readonly SectionHeader[],
  imageBase: number,
  va: number,
): SectionHeader | undefined {
  const rva = va - imageBase;
  return sections.find((s) => rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize);
}

/**
 * True when a virtual address lands in a section this project treats as code.
 *
 * The graph view is only meaningful over code, so navigating out of it drops
 * back to the linear view — and both places that decide this had written the
 * lookup and the predicate out by hand, with a bare `0x20000000` rather than
 * the named flag, which is the duplication this module's header is about.
 *
 * An address in **no** section answers `false`: the callers' shared shape was
 * "switch to linear only when we positively found a non-code section", so an
 * unmapped address leaves the view alone. That is preserved deliberately — see
 * {@link isAddressOutsideCode}, which is the question they actually ask.
 */
export function isAddressInCodeSection(
  sections: readonly SectionHeader[],
  imageBase: number,
  va: number,
): boolean {
  const section = sectionAtVirtualAddress(sections, imageBase, va);
  return section !== undefined && isCodeSection(section);
}

/**
 * True when a virtual address is in a section that is **not** code — the
 * condition under which the graph view has nothing to show and hands back to
 * the linear one.
 *
 * Deliberately NOT `!isAddressInCodeSection(...)`: an address in no section at
 * all is neither, and answering `true` there would switch the view on an
 * address nothing is known about. Both call sites already had that asymmetry,
 * spelled `sec && !(sec.characteristics & 0x20000000)`.
 */
export function isAddressOutsideCode(
  sections: readonly SectionHeader[],
  imageBase: number,
  va: number,
): boolean {
  const section = sectionAtVirtualAddress(sections, imageBase, va);
  return section !== undefined && !isCodeSection(section);
}
