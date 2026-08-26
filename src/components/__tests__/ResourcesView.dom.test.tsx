// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import {
  buildMinimalPE32,
  buildMinimalPE64,
  type ResourceTypeDef,
} from "../../pe/__tests__/fixtures";
import {
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
  ResourceTypeNames,
  RT_ICON,
  RT_MANIFEST,
  RT_VERSION,
} from "../../pe/constants";
import { parsePE, rvaToFileOffset } from "../../pe/parser";
import type { PEFile, ResourceTree } from "../../pe/types";
import { ResourcesView } from "../ResourcesView";
import { AppHarness, stateWithPE } from "./appStateHarness";

/**
 * THE RESOURCES TAB, rendered for the first time.
 *
 * THIS IS THE TAB `analysisNotice()`'s `"no-code-section"` KIND EXISTS FOR. A
 * resource-only DLL — an ordinary satellite/MUI file — makes `findCodeSection`
 * return undefined, so the phase goes to `"no-code"` and the notice tells the
 * user that these tabs ARE populated and to go and open them.
 * `PARSER_DERIVED_TABS` names `"resources"` so the prose cannot disagree with
 * the buttons. Nothing had ever checked that the tab the prose sends a user to
 * renders anything at all.
 *
 * HOW THE FIXTURES ARE BUILT — THERE ARE NOW TWO KINDS, AND THE SPLIT MATTERS.
 *
 *  - **HAND-CONSTRUCTED TREES** (everything down to "leaf previews"). The file,
 *    its section table, `pe.buffer` and every byte a leaf preview decodes are
 *    REAL — `.rsrc` is a genuine section with a genuine `pointerToRawData`, so
 *    `ExpandedLeaf`'s `rvaToFileOffset` walk is the production one over
 *    production data — but `pe.resources` is written out by hand rather than
 *    produced by `parseResourceDirectory`. Nothing in those cases is evidence
 *    about the WALK, and they are kept because they reach shapes a real
 *    directory cannot: a numeric type the name table does not know, an RVA in
 *    no section, a leaf whose `size` is zero.
 *  - **PARSED TREES** (the last describe). `DirectorySpec.resources` builds a
 *    real three-level `IMAGE_RESOURCE_DIRECTORY` — high-bit subdirectory flags,
 *    length-prefixed UTF-16 name entries, data entries whose `OffsetToData` is
 *    an RVA while everything around it is resource-base-relative — and
 *    `parsePE` walks it. Those cases connect the walk to the view for the first
 *    time, and one of them found a defect: see the truncated-file row.
 *
 * NOT VIRTUALIZED. Plain `<table>`s over plain `.map`s, so every row is really
 * in the document and row sets and row order are assertable. No
 * `stubLayoutRect`.
 *
 * WHAT IS DELIBERATELY NOT EXERCISED, and why:
 *  - **The Download button is never clicked.** It goes through
 *    `URL.createObjectURL` and an `<a>.click()`; jsdom's `createObjectURL` is
 *    absent, and a real download is a browser behaviour a stub cannot stand in
 *    for. Its PRESENCE and its filename are asserted, which is the part a render
 *    test can settle.
 *  - **`RT_GROUP_ICON` previews are not rendered.** `reconstructIcon` ends in a
 *    `Blob` and `URL.createObjectURL` for an `<img src>`, so the arm is
 *    unreachable here for the same reason. Named as a gap rather than stubbed
 *    into a test that would assert nothing.
 */

/**
 * NO REACT DIAGNOSTIC, ANYWHERE IN THIS FILE — a file-wide assertion, not a test.
 *
 * THE GUARD FOR A DEFECT THIS SUITE FOUND. `entries.map` returned a SHORTHAND
 * FRAGMENT, so the array element carried no key — the two keys sat on the
 * fragment's children, where React does not look for a list key — and every
 * render of a populated resources tab logged `Each child in a list should have a
 * unique "key" prop` while reconciling the rows by index instead of by
 * `leafKey`. NOTHING STATIC COULD SEE IT: `tsc` accepts a keyless fragment,
 * Biome's `noArrayIndexKey` fires on a key that IS an index rather than on an
 * absent one, and the warning is `jsxDEV`'s, so it exists only when something
 * renders.
 *
 * IT HAS TO BE FILE-WIDE, AND THAT IS THE MEASURED PART. Written first as a
 * single test with its own `vi.spyOn`, it was INERT: React caches the key
 * warning per owner component, so the earlier tests in this file had already
 * spent it and the dedicated test saw a clean console with the defect in place.
 * Asserted after every test instead, the FIRST render that warns is the one that
 * fails, whichever it is.
 *
 * It covers the duplicate-key direction too (`Encountered two children with the
 * same key`), which is what a `leafKey` that dropped `entry.lang` would produce
 * for two localisations of one resource.
 */
let consoleError: MockInstance<typeof console.error>;
beforeEach(() => {
  consoleError = vi.spyOn(console, "error").mockImplementation(() => {});
});
afterEach(() => {
  const messages = consoleError.mock.calls.map((c) => String(c[0]));
  consoleError.mockRestore();
  expect(messages).toEqual([]);
});

const RSRC_RVA = 0x3000;

/** A real `.rsrc` section whose bytes the leaf previews decode. */
function peWithResourceBytes(body: Uint8Array, is64 = true): PEFile {
  const build = is64 ? buildMinimalPE64 : buildMinimalPE32;
  return parsePE(
    build({
      sections: [
        {
          name: ".text",
          virtualAddress: 0x1000,
          virtualSize: 4,
          data: new Uint8Array([0xc3, 0xcc, 0xcc, 0xcc]),
          characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        },
        {
          name: ".rsrc",
          virtualAddress: RSRC_RVA,
          virtualSize: body.length,
          data: body,
          characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        },
      ],
    }),
  );
}

type Entry = ResourceTree["entries"][number];

function tree(entries: Entry[]): ResourceTree {
  return { root: [], entries };
}

/** Attach a hand-written tree to a real parsed PE. */
function withResources(pe: PEFile, entries: Entry[]): PEFile {
  return Object.assign(pe, { resources: tree(entries) });
}

function renderResources(pe: PEFile) {
  const dispatch = vi.fn();
  const { container } = render(
    <AppHarness state={stateWithPE(pe)} dispatch={dispatch}>
      <ResourcesView />
    </AppHarness>,
  );
  return { container, dispatch, user: userEvent.setup() };
}

/** The rows of the table under a given type heading. */
function rowsUnder(typeLabel: string): HTMLTableRowElement[] {
  const heading = screen.getByRole("button", { name: new RegExp(`${typeLabel}\\s*\\(`) });
  const group = heading.parentElement!;
  return Array.from(group.querySelectorAll("tbody tr"));
}

describe("ResourcesView — the empty cases", () => {
  it("says there are none, rather than rendering an error, for a PE with no resource directory", () => {
    // The defect class: an empty state that reads as a failure. This is the
    // ordinary outcome for most binaries, so the sentence has to be calm.
    renderResources(peWithResourceBytes(new Uint8Array(16)));
    expect(screen.getByText("No resources found in this PE file.")).toBeTruthy();
    expect(screen.queryByRole("table")).toBeNull();
  });

  it("says the same for a resource directory that parsed to zero entries", () => {
    // A distinct path — `pe.resources` exists but `entries` is empty. Both go
    // to the same sentence, which is right: a directory with nothing in it and
    // no directory at all are the same fact to a reader.
    renderResources(withResources(peWithResourceBytes(new Uint8Array(16)), []));
    expect(screen.getByText("No resources found in this PE file.")).toBeTruthy();
  });

  it("renders for a PE32 as well as a PE64", () => {
    // Nothing in this view is width-dependent (contrast `StringsView`, whose
    // address column is), asserted so a future `pe.is64` read needs a test.
    for (const is64 of [false, true]) {
      const pe = withResources(peWithResourceBytes(new Uint8Array(16), is64), [
        { type: 3, name: 1, lang: 1033, rva: RSRC_RVA, size: 8 },
      ]);
      const { unmount } = render(
        <AppHarness state={stateWithPE(pe)} dispatch={vi.fn()}>
          <ResourcesView />
        </AppHarness>,
      );
      expect(screen.getByText(/^Resources \(1 types, 1 entries\)$/)).toBeTruthy();
      unmount();
    }
  });
});

describe("ResourcesView — the type → name → language tree", () => {
  const entries: Entry[] = [
    { type: 3, name: 1, lang: 1033, rva: RSRC_RVA, size: 296 },
    { type: 3, name: 2, lang: 1033, rva: RSRC_RVA + 0x200, size: 744 },
    { type: 3, name: 2, lang: 1031, rva: RSRC_RVA + 0x400, size: 744 },
    { type: 6, name: 7, lang: 1033, rva: RSRC_RVA + 0x600, size: 64 },
    { type: 16, name: 1, lang: 1033, rva: RSRC_RVA + 0x700, size: 0 },
  ];

  it("counts distinct types and total entries in the heading", () => {
    renderResources(withResources(peWithResourceBytes(new Uint8Array(0x900)), entries));
    // 3 types (Icon, String Table, Version Info) over 5 entries. Both halves
    // matter: the type count is what tells a reader how many groups to expect.
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe(
      "Resources (3 types, 5 entries)",
    );
  });

  it("groups entries under one heading per type, in first-appearance order", () => {
    const { container } = renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x900)), entries),
    );
    const headings = Array.from(
      container.querySelectorAll(":scope > div > div > div > button"),
    ).map((b) => b.textContent);
    expect(headings).toEqual(["▼Icon(3)", "▼String Table(1)", "▼Version Info(1)"]);
  });

  it("names each standard type from `ResourceTypeNames`, the one declaration", () => {
    /**
     * THE NAMES ARE FRIENDLY, NOT `RT_*`. `ResourceTypeNames` in
     * `src/pe/constants.ts` spells 3 as "Icon", 16 as "Version Info" and 24 as
     * "Manifest" — not `RT_ICON`/`RT_VERSION`/`RT_MANIFEST`. Recorded here
     * because the Win32 spellings are the obvious thing to look for and their
     * absence is a deliberate choice, not a gap.
     *
     * Read against the table itself rather than against literals, so a rename
     * there is one edit and a DELETION is a failing row.
     */
    const known = Object.entries(ResourceTypeNames);
    expect(known.length).toBeGreaterThan(10);
    renderResources(
      withResources(
        peWithResourceBytes(new Uint8Array(0x100)),
        known.map(([id], i) => ({
          type: Number(id),
          name: i,
          lang: 1033,
          rva: RSRC_RVA,
          size: 1,
        })),
      ),
    );
    for (const [, label] of known) {
      expect(
        screen.getByRole("button", { name: new RegExp(`^▶?▼?${label}\\(1\\)$`) }),
      ).toBeTruthy();
    }
  });

  it("falls back to `Type N` for a numeric type the table does not name", () => {
    // Not a hypothetical: private/undocumented resource types are common, and
    // the alternative to a fallback is a group headed `undefined`.
    renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x100)), [
        { type: 0xfa1, name: 1, lang: 1033, rva: RSRC_RVA, size: 4 },
      ]),
    );
    expect(screen.getByRole("button", { name: /Type 4001/ })).toBeTruthy();
  });

  it("uses a STRING type id verbatim as the group name", () => {
    // A resource type may be a name rather than an ordinal. `getTypeName`
    // returns it unchanged — there is nothing to look up.
    renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x100)), [
        { type: "MOFDATA", name: 1, lang: 1033, rva: RSRC_RVA, size: 4 },
      ]),
    );
    expect(screen.getByRole("button", { name: /MOFDATA/ })).toBeTruthy();
  });

  it("distinguishes a numeric resource name from a string one", () => {
    // `#101` vs `MAINICON` — the `#` is the whole signal that the id is an
    // ordinal, and without it a numeric name and a name that happens to be
    // digits are indistinguishable.
    renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x100)), [
        { type: 10, name: 101, lang: 1033, rva: RSRC_RVA, size: 4 },
        { type: 10, name: "MAINICON", lang: 1033, rva: RSRC_RVA, size: 4 },
      ]),
    );
    const names = rowsUnder("RC Data").map((r) => r.cells[0].textContent);
    expect(names).toEqual(["▶#101", "▶MAINICON"]);
  });

  it("puts the language, the size, and the RVA on each leaf row", () => {
    renderResources(withResources(peWithResourceBytes(new Uint8Array(0x900)), entries));
    const rows = rowsUnder("Icon");
    expect(rows).toHaveLength(3);
    expect(rows.map((r) => r.cells[1].textContent)).toEqual(["#1033", "#1033", "#1031"]);
    expect(rows.map((r) => r.cells[3].textContent)).toEqual(["0x3000", "0x3200", "0x3400"]);
  });

  it("keeps two languages of the same name as two rows", () => {
    // The third level of the tree. Two entries differing only in `lang` are two
    // distinct resources, and a key or a grouping that collapsed them would
    // hide one localisation entirely.
    renderResources(withResources(peWithResourceBytes(new Uint8Array(0x900)), entries));
    const rows = rowsUnder("Icon").filter((r) => r.cells[0].textContent === "▶#2");
    expect(rows).toHaveLength(2);
    expect(rows.map((r) => r.cells[1].textContent)).toEqual(["#1033", "#1031"]);
  });

  it("gives two languages of one resource independent expand state", async () => {
    /**
     * `leafKey` is `type-name-lang-idx`, and the `lang` term is what this row
     * exists for. Dropping it leaves two localisations sharing one key, which is
     * TWO defects at once: React reconciles them as one child (the file-wide
     * console guard above catches that half — `Encountered two children with the
     * same key`) and the `expanded` set can no longer tell them apart, so
     * opening one opens both.
     *
     * The row-count test above does NOT catch it — both rows still render — which
     * is why this is a separate row about expand state.
     */
    const { user } = renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x900)), entries),
    );
    expect(rowsUnder("Icon")).toHaveLength(3);
    const first = rowsUnder("Icon").filter((r) => r.cells[0].textContent === "▶#2")[0];
    await user.click(within(first).getByRole("button", { name: "▶#2" }));
    // One detail row appeared, not two.
    expect(rowsUnder("Icon")).toHaveLength(4);
    const markers = rowsUnder("Icon")
      .filter((r) => /#2$/.test(r.cells[0]?.textContent ?? ""))
      .map((r) => r.cells[0].textContent);
    expect(markers).toEqual(["▼#2", "▶#2"]);
  });

  it("formats a size in B, KB or MB by magnitude", () => {
    // `formatSize`'s three arms and its two boundaries. Module-private, so the
    // rendered cell is the only way to reach it — and the boundaries are the
    // sharp assertions: an off-by-one there prints "1024.0 KB".
    renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x100)), [
        { type: 10, name: 1, lang: 0, rva: RSRC_RVA, size: 0 },
        { type: 10, name: 2, lang: 0, rva: RSRC_RVA, size: 1023 },
        { type: 10, name: 3, lang: 0, rva: RSRC_RVA, size: 1024 },
        { type: 10, name: 4, lang: 0, rva: RSRC_RVA, size: 1536 },
        { type: 10, name: 5, lang: 0, rva: RSRC_RVA, size: 1024 * 1024 - 1 },
        { type: 10, name: 6, lang: 0, rva: RSRC_RVA, size: 1024 * 1024 },
        { type: 10, name: 7, lang: 0, rva: RSRC_RVA, size: 3 * 1024 * 1024 },
      ]),
    );
    expect(rowsUnder("RC Data").map((r) => r.cells[2].textContent)).toEqual([
      "0 B",
      "1023 B",
      "1.0 KB",
      "1.5 KB",
      "1024.0 KB",
      "1.0 MB",
      "3.0 MB",
    ]);
  });

  it("offers a download per leaf, named after its type, name and language", () => {
    // NOT CLICKED — see the file docstring. The filename is the assertable half
    // and it is the one a user sees on disk.
    renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x100)), [
        { type: 16, name: 1, lang: 1033, rva: RSRC_RVA, size: 4 },
      ]),
    );
    const row = rowsUnder("Version Info")[0];
    expect(within(row).getByRole("button", { name: "Download" })).toBeTruthy();
  });
});

describe("ResourcesView — collapsing and expanding", () => {
  const entries: Entry[] = [
    { type: 3, name: 1, lang: 1033, rva: RSRC_RVA, size: 296 },
    { type: 6, name: 7, lang: 1033, rva: RSRC_RVA + 0x200, size: 64 },
  ];

  it("starts every type group open and collapses the one that is clicked", async () => {
    const { user } = renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x300)), entries),
    );
    expect(rowsUnder("Icon")).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: /Icon\(1\)/ }));
    expect(rowsUnder("Icon")).toHaveLength(0);
    // The disclosure marker turns with it, and the OTHER group is untouched —
    // collapse state is per type key, and a single boolean would close both.
    expect(screen.getByRole("button", { name: /Icon\(1\)/ }).textContent).toBe("▶Icon(1)");
    expect(rowsUnder("String Table")).toHaveLength(1);
  });

  it("collapses back open on a second click", async () => {
    const { user } = renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x300)), entries),
    );
    const heading = () => screen.getByRole("button", { name: /Icon\(1\)/ });
    await user.click(heading());
    await user.click(heading());
    expect(rowsUnder("Icon")).toHaveLength(1);
  });

  it("starts every leaf closed and expands only the one that is clicked", async () => {
    const { user } = renderResources(
      withResources(peWithResourceBytes(new Uint8Array(0x300)), [
        ...entries,
        { type: 3, name: 2, lang: 1033, rva: RSRC_RVA + 0x100, size: 8 },
      ]),
    );
    // A leaf with no preview arm renders an empty detail row, so the observable
    // is the row COUNT under the type, not the preview.
    expect(rowsUnder("Icon")).toHaveLength(2);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    expect(rowsUnder("Icon")).toHaveLength(3);
    expect(screen.getByRole("button", { name: "▼#1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "▶#2" })).toBeTruthy();
  });
});

describe("ResourcesView — leaf previews", () => {
  it("decodes a manifest out of the file's real bytes", async () => {
    /**
     * END TO END OVER REAL DATA: the XML is placed in a real `.rsrc` section, so
     * `rvaToFileOffset` resolves the RVA against the real section table and
     * `TextDecoder` reads the real buffer. Nothing about this arm is stubbed.
     */
    const xml = '<?xml version="1.0"?><assembly manifestVersion="1.0"/>';
    const body = new Uint8Array(0x200);
    body.set(new TextEncoder().encode(xml), 0);
    const pe = withResources(peWithResourceBytes(body), [
      { type: RT_MANIFEST, name: 1, lang: 1033, rva: RSRC_RVA, size: xml.length },
    ]);
    // Sanity on the fixture itself, so a failure below is the component's.
    expect(rvaToFileOffset(RSRC_RVA, pe.sections)).toBeGreaterThan(0);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    const pre = screen.getByText(xml);
    expect(pre.tagName).toBe("PRE");
  });

  it("shows the whole manifest and not the whole section", async () => {
    // The slice is `size` bytes from the entry's own RVA, clamped to the buffer.
    // A preview that read to the end of the section would print the padding as
    // NULs, which is what `Math.min(size, ...)` is there to prevent.
    const xml = "<assembly/>";
    const body = new Uint8Array(0x200);
    body.set(new TextEncoder().encode(xml), 0);
    const pe = withResources(peWithResourceBytes(body), [
      { type: RT_MANIFEST, name: 1, lang: 1033, rva: RSRC_RVA, size: xml.length },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    expect(screen.getByText(xml).textContent).toBe(xml);
  });

  it("renders nothing rather than throwing for an RVA in no section", async () => {
    // `rvaToFileOffset` answers -1 and every preview arm returns null on it. The
    // observable is that the detail row is empty and the tree is still standing.
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: RT_MANIFEST, name: 1, lang: 1033, rva: 0xdeadb, size: 16 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    const rows = rowsUnder("Manifest");
    expect(rows).toHaveLength(2);
    expect(rows[1].textContent).toBe("");
  });

  it("says so when a version resource carries no strings", async () => {
    // `parseVersionInfo` over zero bytes returns `{}`, and the arm has its own
    // sentence for that — an empty table would read as a rendering failure.
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: RT_VERSION, name: 1, lang: 1033, rva: RSRC_RVA, size: 0 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    expect(screen.getByText("No version strings found")).toBeTruthy();
  });

  it("renders no preview at all for a type with no preview arm", async () => {
    // `ExpandedLeaf` returns null for anything but version, group-icon and
    // manifest. Pinned so a new arm arrives with a test rather than silently.
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: 6, name: 7, lang: 1033, rva: RSRC_RVA, size: 32 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#7" }));
    const rows = rowsUnder("String Table");
    expect(rows).toHaveLength(2);
    expect(rows[1].textContent).toBe("");
  });

  it("does not offer a preview for a STRING-typed resource, whatever it is named", async () => {
    // `ExpandedLeaf` maps a string type to `-1` before comparing, so a resource
    // whose type is the literal text "16" cannot be mistaken for RT_VERSION.
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: "16", name: 1, lang: 1033, rva: RSRC_RVA, size: 0 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    expect(screen.queryByText("No version strings found")).toBeNull();
  });
});

/**
 * THE WALK AND THE VIEW, CONNECTED — the first cases in this file whose
 * `ResourceTree` came out of `parseResourceDirectory` rather than out of a
 * literal.
 *
 * Everything above hands the component a hand-written tree, which is the right
 * shape for asking what the VIEW does with one and says nothing whatever about
 * the walk. These build a real three-level `IMAGE_RESOURCE_DIRECTORY` in the
 * fixture (`DirectorySpec.resources`), parse it with the production parser and
 * render what comes out — so a defect anywhere between the entry's high bit and
 * the table cell shows up here and in no other suite.
 *
 * The hand-built cases STAY. They reach shapes the builder cannot emit — a
 * numeric type the name table does not know, an RVA in no section, a leaf whose
 * `size` is zero — and a fixture-only file would lose all of them.
 */
function peWithParsedResources(resources: ResourceTypeDef[], is64 = true): PEFile {
  const build = is64 ? buildMinimalPE64 : buildMinimalPE32;
  return parsePE(
    build({
      directorySectionName: ".rsrc",
      directoryRVA: RSRC_RVA,
      directories: { resources },
    }),
  );
}

describe("ResourcesView — over a parsed resource directory", () => {
  const MANIFEST = '<?xml version="1.0"?><assembly manifestVersion="1.0"/>';
  const parsedSpec: ResourceTypeDef[] = [
    {
      id: RT_ICON,
      names: [
        {
          id: 1,
          langs: [
            { lang: 0x0409, data: new Uint8Array(40).fill(0xa1) },
            { lang: 0x0407, data: new Uint8Array(24).fill(0xb2) },
          ],
        },
        { id: "MAINICON", langs: [{ lang: 0x0409, data: new Uint8Array(8) }] },
      ],
    },
    {
      id: RT_MANIFEST,
      names: [
        {
          id: 1,
          langs: [{ lang: 0x0409, data: new TextEncoder().encode(MANIFEST), codePage: 65001 }],
        },
      ],
    },
    { id: "MOFDATA", names: [{ id: 101, langs: [{ lang: 0, data: new Uint8Array([0x42]) }] }] },
  ];

  it("heads each group with the parsed type, resolved or verbatim", () => {
    renderResources(peWithParsedResources(parsedSpec));
    // Named types sort ahead of ID types in the file, so MOFDATA leads.
    expect(screen.getByRole("button", { name: /^▼MOFDATA\(1\)$/ })).toBeTruthy();
    expect(
      screen.getByRole("button", { name: new RegExp(`^▼${ResourceTypeNames[RT_ICON]}\\(3\\)$`) }),
    ).toBeTruthy();
    expect(
      screen.getByRole("button", {
        name: new RegExp(`^▼${ResourceTypeNames[RT_MANIFEST]}\\(1\\)$`),
      }),
    ).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe(
      "Resources (3 types, 5 entries)",
    );
  });

  it("keeps a parsed NAME entry a name and a parsed ID entry an ordinal", () => {
    // The `#` prefix is the view's whole signal, and the value behind it now
    // comes from the entry's high bit rather than from a literal in this file.
    renderResources(peWithParsedResources(parsedSpec));
    expect(rowsUnder(ResourceTypeNames[RT_ICON]).map((r) => r.cells[0].textContent)).toEqual([
      "▶MAINICON",
      "▶#1",
      "▶#1",
    ]);
    expect(rowsUnder("MOFDATA").map((r) => r.cells[0].textContent)).toEqual(["▶#101"]);
  });

  it("shows both languages of one parsed resource, with their own sizes", () => {
    renderResources(peWithParsedResources(parsedSpec));
    const rows = rowsUnder(ResourceTypeNames[RT_ICON]).filter(
      (r) => r.cells[0].textContent === "▶#1",
    );
    expect(rows.map((r) => r.cells[1].textContent)).toEqual(["#1033", "#1031"]);
    expect(rows.map((r) => r.cells[2].textContent)).toEqual(["40 B", "24 B"]);
    // Two languages, two data entries, two RVAs.
    expect(rows[0].cells[3].textContent).not.toBe(rows[1].cells[3].textContent);
  });

  it("previews a manifest whose bytes the WALK located, end to end", async () => {
    /**
     * The one row in this repo where the entry's RVA was read out of a real
     * `IMAGE_RESOURCE_DATA_ENTRY` — against the image base, while every offset
     * around it is against the resource base — and then resolved back to a file
     * offset by the production `rvaToFileOffset`. Assert the TEXT: read the RVA
     * against the wrong base and it still lands inside `.rsrc`, so an offset
     * assertion would pass and only the content can tell.
     */
    const { user } = renderResources(peWithParsedResources(parsedSpec));
    const row = rowsUnder(ResourceTypeNames[RT_MANIFEST])[0];
    await user.click(within(row).getByRole("button", { name: "▶#1" }));
    expect(screen.getByText(MANIFEST).tagName).toBe("PRE");
  });

  it("renders a parsed directory on PE32 as well as PE32+", () => {
    for (const is64 of [false, true]) {
      const { unmount } = render(
        <AppHarness state={stateWithPE(peWithParsedResources(parsedSpec, is64))} dispatch={vi.fn()}>
          <ResourcesView />
        </AppHarness>,
      );
      expect(screen.getByRole("heading", { level: 2 }).textContent).toBe(
        "Resources (3 types, 5 entries)",
      );
      unmount();
    }
  });

  it("renders a NAME-identified language as its name, and an ordinal one marked", async () => {
    /**
     * THE VIEW HALF OF THE FLATTEN FIX. `parseResourceDirectory` used to answer
     * `lang: 0` for a name-identified third level, so two named localisations of
     * one resource were two rows both claiming language 0 and separable only by
     * RVA. `lang` is `number | string` now and the column prints what the file
     * says.
     *
     * THE `#` IS THE OTHER HALF AND IT IS NOT DECORATION. The two rows here are
     * the language NAMED "1033" and the LANGID 1033, which are different
     * languages of one resource; printed bare they are one string on the page,
     * and the column would be back to claiming two distinct rows are the same
     * language by a different route. It is the same ordinal marker the Name
     * column has always used, from the same declaration (`ordinalLabel`).
     */
    renderResources(
      peWithParsedResources([
        {
          id: RT_ICON,
          names: [
            {
              id: 1,
              langs: [
                { lang: "1033", data: new Uint8Array([0xa1]) },
                { lang: 0x0409, data: new Uint8Array([0xb2, 0xb2]) },
                { lang: 0, data: new Uint8Array([0xc3, 0xc3, 0xc3]) },
              ],
            },
          ],
        },
      ]),
    );
    const rows = rowsUnder(ResourceTypeNames[RT_ICON]);
    // Named entries sort ahead of ID entries inside a directory, here at the
    // THIRD level — which is itself evidence the fixture emitted a named one.
    expect(rows.map((r) => r.cells[1].textContent)).toEqual(["1033", "#1033", "#0"]);
    expect(rows.map((r) => r.cells[2].textContent)).toEqual(["1 B", "2 B", "3 B"]);
  });

  it("gives a named and an ordinal language of one resource independent expand state", async () => {
    /**
     * `leafKey` is the `expanded` set's identity, and its language term is now
     * `keyPart(entry.lang)` — tagged, so the name "1033" and the LANGID 1033 are
     * two members rather than one.
     *
     * REPORTED HONESTLY: A CONTROL ON THAT TAG IS INERT. The key still ends in
     * the row index, which is what makes it injective and has to stay (two
     * identical entries in one crafted directory are walked as two rows, and a
     * key without the index would collide and take React's duplicate-key warning
     * with it). So this row passes with `String(entry.lang)` in place of
     * `keyPart` too. It is here for the PROPERTY, which the flatten fix is what
     * actually restored: before it both rows carried `lang: 0` and the tag would
     * have had nothing to tell apart either.
     */
    const { user } = renderResources(
      peWithParsedResources([
        {
          id: RT_ICON,
          names: [
            {
              id: 1,
              langs: [
                { lang: "1033", data: new Uint8Array([0xa1]) },
                { lang: 0x0409, data: new Uint8Array([0xb2, 0xb2]) },
              ],
            },
          ],
        },
      ]),
    );
    expect(rowsUnder(ResourceTypeNames[RT_ICON])).toHaveLength(2);
    await user.click(rowsUnder(ResourceTypeNames[RT_ICON])[0].querySelector("button")!);
    const after = rowsUnder(ResourceTypeNames[RT_ICON]);
    expect(after).toHaveLength(3);
    // Which of the two opened is the assertion: the leaf rows are the five-cell
    // ones, and the language cell says which language each marker belongs to.
    expect(
      after
        .filter((r) => r.cells.length === 5)
        .map((r) => `${r.cells[0].textContent}|${r.cells[1].textContent}`),
    ).toEqual(["▼#1|1033", "▶#1|#1033"]);
  });

  it("keeps a NAMED type and the ORDINAL that spells the same digits as two groups", () => {
    /**
     * THE SAME CLASS ONE LEVEL UP, AND THE CONTROL THAT IS NOT INERT. The type
     * level has been `number | string` all along, but the grouping key was
     * `String(entry.type)`, so the type NAMED "3" and RT_ICON (3) hashed to one
     * bucket: one heading, one collapse state, one type counted, and the heading
     * took its label from whichever entry came first. `keyPart` tags the kind,
     * and there is no row index at this level to paper over it.
     */
    renderResources(
      peWithParsedResources([
        { id: "3", names: [{ id: 1, langs: [{ lang: 0x0409, data: new Uint8Array([1]) }] }] },
        { id: RT_ICON, names: [{ id: 2, langs: [{ lang: 0x0409, data: new Uint8Array([2]) }] }] },
      ]),
    );
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe(
      "Resources (2 types, 2 entries)",
    );
    expect(screen.getByRole("button", { name: /^▼3\(1\)$/ })).toBeTruthy();
    expect(
      screen.getByRole("button", { name: new RegExp(`^▼${ResourceTypeNames[RT_ICON]}\\(1\\)$`) }),
    ).toBeTruthy();
  });

  it("says there are none for a parsed directory that declares no entries", () => {
    // Not the same path as "no resource directory": the data directory is
    // present and non-empty and the walk really runs, and answers nothing.
    renderResources(peWithParsedResources([]));
    expect(screen.getByText("No resources found in this PE file.")).toBeTruthy();
  });

  it("expands a leaf whose bytes are past the end of a TRUNCATED file", async () => {
    /**
     * THE DEFECT THIS SUITE FOUND, and it needed both halves of this session's
     * work to be reachable: a real walk to produce the rows, and a real file to
     * truncate.
     *
     * `rvaToFileOffset` resolves against the SECTION TABLE and never sees the
     * buffer, so where the headers describe more than the file holds — a carved
     * sample, a part-finished download — it answers an offset past the end.
     * `ExpandedLeaf`'s manifest arm computed `Math.min(size, buffer.byteLength -
     * fileOff)`, which is then NEGATIVE, and `new Uint8Array` threw
     * `RangeError: Invalid typed array length: -16`. The walk itself is fine —
     * `parseResourceDirectory` bounds every read on the buffer — so every row
     * renders and only the CLICK is fatal, which is why nothing static and
     * nothing in `npm run corpus` could see it. `downloadResource` had the same
     * arithmetic; it is not clicked here (no `URL.createObjectURL` in jsdom) and
     * shares `resourceBytes` instead.
     *
     * The file is cut four bytes short of the LAST leaf's own bytes, so the
     * first leaf is still readable and the second is not — a row that would
     * pass against a fix that simply refused every truncated file.
     */
    const two: ResourceTypeDef[] = [
      {
        id: RT_MANIFEST,
        names: [
          {
            id: 1,
            langs: [
              // Nine bytes, so the four-byte allocation alignment leaves a gap
              // the cut can land in: the first leaf ends before the file does
              // and the second one starts after it.
              { lang: 0x0409, data: new TextEncoder().encode("<first />") },
              { lang: 0x0407, data: new TextEncoder().encode("<second/>") },
            ],
          },
        ],
      },
    ];
    const buf = buildMinimalPE64({
      directorySectionName: ".rsrc",
      directoryRVA: RSRC_RVA,
      directories: { resources: two },
    });
    const full = parsePE(buf);
    const offsets = full.resources!.entries.map((e) => rvaToFileOffset(e.rva, full.sections));
    const cut = offsets[0] + full.resources!.entries[0].size;
    const pe = parsePE(buf.slice(0, cut));

    // The fixture, before the component: both rows survive the cut, the first
    // leaf's bytes are all present, and the second leaf's are all missing.
    expect(pe.resources!.entries).toHaveLength(2);
    expect(offsets[0] + pe.resources!.entries[0].size).toBeLessThanOrEqual(pe.buffer.byteLength);
    expect(offsets[1]).toBeGreaterThan(pe.buffer.byteLength);
    expect(rvaToFileOffset(pe.resources!.entries[1].rva, pe.sections)).toBe(offsets[1]);

    const { user } = renderResources(pe);
    const rows = () => rowsUnder(ResourceTypeNames[RT_MANIFEST]);
    await user.click(within(rows()[0]).getByRole("button", { name: "▶#1" }));
    // The readable one still decodes.
    expect(screen.getByText("<first />").tagName).toBe("PRE");
    // The unreadable one renders an empty detail row instead of throwing.
    await user.click(within(rows()[2]).getByRole("button", { name: "▶#1" }));
    const after = rows();
    expect(after).toHaveLength(4);
    expect(after[3].textContent).toBe("");
  });
});
