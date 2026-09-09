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
  IMAGE_DIRECTORY_ENTRY_RESOURCE,
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
  ResourceTypeNames,
  RT_GROUP_ICON,
  RT_ICON,
  RT_MANIFEST,
  RT_RCDATA,
  RT_VERSION,
} from "../../pe/constants";
import { parsePE, rvaToFileOffset } from "../../pe/parser";
import { MAX_TOTAL_ENTRIES } from "../../pe/resources";
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
 *  - **The `RT_GROUP_ICON` preview NEVER PAINTS**, and that half is still a gap.
 *    The arm IS rendered now — `URL.createObjectURL`/`revokeObjectURL` are
 *    stubbed below, because the OBJECT-URL LIFECYCLE is a real defect class and
 *    a counter settles it exactly. What no stub can reach is the picture: jsdom
 *    decodes no image and has no 2D context, so `<img src="blob:…">` is an
 *    element with an attribute. Whether the reconstructed `.ico` is a valid
 *    icon is measured by `resources.test.ts` over the bytes and by nothing here;
 *    the human check belongs in `peek-a-bin-v2u`. THE CONTROL CONFIRMS IT:
 *    replacing the reconstructed bytes with a single 0x00 — not an icon by any
 *    reading — leaves every row in this file green.
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

/**
 * OBJECT URLS, COUNTED — the instrument for the group-icon leak.
 *
 * jsdom implements NEITHER `URL.createObjectURL` NOR `URL.revokeObjectURL`
 * (verified against jsdom 28: both are `undefined` on `URL`), which is why the
 * group-icon arm had never been rendered by any test and why the leak survived.
 * They are not spies over a real implementation — there is nothing to spy on —
 * so they are installed here and removed afterwards.
 *
 * THE ASSERTION THAT MATTERS IS THE PAIRING, not either count on its own: one
 * revoke per create, across expand → collapse → unmount. A create count alone
 * passes against the defect (which minted a URL per render and revoked none),
 * and a revoke count alone passes against a component that revokes a URL it
 * never minted.
 */
let mintedUrls: string[];
let revokedUrls: string[];
const hadObjectUrlApi = typeof URL.createObjectURL === "function";
beforeEach(() => {
  mintedUrls = [];
  revokedUrls = [];
  URL.createObjectURL = () => {
    const url = `blob:peek-a-bin/${mintedUrls.length}`;
    mintedUrls.push(url);
    return url;
  };
  URL.revokeObjectURL = (url: string) => {
    revokedUrls.push(url);
  };
});
afterEach(() => {
  if (!hadObjectUrlApi) {
    Reflect.deleteProperty(URL, "createObjectURL");
    Reflect.deleteProperty(URL, "revokeObjectURL");
  }
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
  // `unmount` is what the object-URL suite needs: the cleanup that revokes a
  // blob URL runs on unmount, and `cleanup()` in `afterEach` is too late to
  // assert against.
  const { container, unmount } = render(
    <AppHarness state={stateWithPE(pe)} dispatch={dispatch}>
      <ResourcesView />
    </AppHarness>,
  );
  return { container, dispatch, unmount, user: userEvent.setup() };
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

  /**
   * A DECLARED DIRECTORY WITH NO TREE AT ALL IS A THIRD THING, and it reached
   * the calmest of the three sentences. `parsePE` reads the resource directory
   * inside a `catch {}`, so a reader that throws leaves `pe.resources`
   * undefined — byte-for-byte what a PE with no resource directory produces —
   * and the pane printed "No resources found in this PE file." over a file
   * whose optional header says otherwise. (peek-a-bin-wo8g)
   *
   * THE POPULATION IS CURRENTLY EMPTY AND THE STATE IS THEREFORE BUILT
   * DIRECTLY. `parseResourceDirectory` bounds every read on the buffer and
   * recurses to a fixed depth, and an RVA resolving nowhere returns a tree
   * flagged `truncated` rather than throwing (`peek-a-bin-dhcx`), so nothing
   * here can make it throw — which is stated rather than papered over, and is
   * why `resourcesUnreadable`'s own docstring calls this a guard rather than a
   * repair. What this row proves is that the guard is wired: if the day comes,
   * the pane says so instead of claiming the file is bare.
   */
  it("does not say the file has no resources when the reader gave up on a declared directory", () => {
    const pe = parsePE(
      buildMinimalPE64({
        directories: {
          resources: [
            { id: 3, names: [{ id: 1, langs: [{ lang: 1033, data: new Uint8Array([1, 2]) }] }] },
          ],
        },
      }),
    );
    // The parse succeeded; drop the tree to stand in for the `catch`.
    expect(pe.resources!.entries).toHaveLength(1);
    const declaredDir = pe.dataDirectories[2];
    expect(declaredDir.virtualAddress).toBeGreaterThan(0);
    renderResources({ ...pe, resources: undefined });

    expect(screen.queryByText("No resources found in this PE file.")).toBeNull();
    const notice = screen.getByText(/could not be read/);
    expect(notice.textContent).toContain(declaredDir.virtualAddress.toString(16).toUpperCase());
    expect(notice.textContent).toMatch(/not without resources/);
  });

  it("still says the file has none when no resource directory is declared", () => {
    // THE CONTROL FOR THE ROW ABOVE, and the one that catches a fix which stops
    // making any claim at all: most binaries this tool opens genuinely have no
    // resource directory, and the calm sentence is true of every one of them.
    // The fixture has a `.rsrc` SECTION and no directory entry pointing at it,
    // which is exactly the pair the predicate has to tell apart.
    const pe = peWithResourceBytes(new Uint8Array(16));
    expect(pe.dataDirectories[2]?.virtualAddress ?? 0).toBe(0);
    renderResources(pe);
    expect(screen.getByText("No resources found in this PE file.")).toBeTruthy();
    expect(screen.queryByText(/could not be read/)).toBeNull();
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

  it("says the RVA falls in no section, rather than rendering an empty box", async () => {
    // `rvaToFileOffset` answers -1, so `resourceBytes` refuses with `unmapped`
    // and the arm SAYS SO. It used to `return null`, which is the same empty
    // `<tr>` a reader gets from an unhandled type — one blank row standing for
    // two entirely different facts, neither of them stated.
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: RT_MANIFEST, name: 1, lang: 1033, rva: 0xdeadb, size: 16 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    const rows = rowsUnder("Manifest");
    expect(rows).toHaveLength(2);
    expect(rows[1].textContent).toContain("its RVA falls in no section");
    // The other refusal's sentence, so the two cannot be confused for one.
    expect(rows[1].textContent).not.toContain("truncated");
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

  it("previews a type with no dedicated arm as hex and ASCII", async () => {
    // WAS `expect(rows[1].textContent).toBe("")` — the defect pinned as the
    // rule. `ExpandedLeaf` returned null for anything but version, group-icon
    // and manifest, so the caret on an RT_STRING flipped open onto an empty
    // `<tr><td colSpan={5}>`.
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: 6, name: 7, lang: 1033, rva: RSRC_RVA, size: 32 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#7" }));
    const rows = rowsUnder("String Table");
    expect(rows).toHaveLength(2);
    expect(rows[1].textContent).not.toBe("");
    expect(rows[1].textContent).toContain("00 00 00 00");
  });

  it("does not offer the VERSION arm to a STRING-typed resource, whatever it is named", async () => {
    // `ExpandedLeaf` maps a string type to `-1` before comparing, so a resource
    // whose type is the literal text "16" cannot be mistaken for RT_VERSION. It
    // takes the hex fallback below instead — which is a preview, so the check
    // is that it is not the WRONG one.
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: "16", name: 1, lang: 1033, rva: RSRC_RVA, size: 0 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    expect(screen.queryByText("No version strings found")).toBeNull();
    expect(screen.getByText("This resource declares no bytes.")).toBeTruthy();
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
    // The unreadable one SAYS the file does not contain its bytes, instead of
    // throwing and instead of the empty row it used to render.
    await user.click(within(rows()[2]).getByRole("button", { name: "▶#1" }));
    const after = rows();
    expect(after).toHaveLength(4);
    expect(after[3].textContent).toContain("past the end of the file");
    expect(after[3].textContent).toContain("truncated");
  });
});

/**
 * A WALK CUT SHORT BY ITS BUDGET, AND THE LAST HOP TO THE SCREEN.
 *
 * `parseResourceDirectory` has set `ResourceTree.truncated` since long before
 * this and NOTHING RENDERED IT, so a tree stopped at `MAX_TOTAL_ENTRIES` read on
 * screen exactly like a complete one — same table, same counts, nothing saying
 * the walk stopped. That is the house defect class stated in `CLAUDE.md` as *a
 * narrower answer must not wear a complete one's shape*, and the flag was
 * already the hard half: it exists, it is correct, and `peek-a-bin-6qx9` fixed
 * the off-by-one that reported it falsely at exactly the budget.
 *
 * TWO ARMS, BECAUSE THE VIEW HAS TWO EXITS AND THEY MISLEAD DIFFERENTLY.
 *  - **The count line.** The heading is a sentence about the list's extent —
 *    `peek-a-bin-tmo9`'s finding for the Imports tab — so a short list makes it
 *    describe a smaller file, entirely plausibly.
 *  - **The empty arm, which is the worse one.** "No resources found in this PE
 *    file." is a positive claim about the FILE, and a budget exhaustion makes it
 *    false rather than merely narrow. It is reachable with no leaf at all,
 *    because the allowance is spent on DIRECTORY entries: a root declaring more
 *    subdirectories than the budget never descends to a data entry.
 *
 * EVERY ROW HERE IS OVER A REAL PARSED DIRECTORY, never a hand-set flag, so the
 * walk and the view are connected. `peWithBudgetedRoot` writes the root's entry
 * counts itself — the fixture builder emits well-formed trees and cannot
 * over-declare — on `resources.test.ts`'s `rootWithEntries` model.
 */
describe("ResourcesView — a walk cut short by its budget", () => {
  const BUDGET_RVA = 0x4000;

  /**
   * A `.rsrc` whose ROOT declares `total` entries, the first `leaves` of which
   * are real data entries and the rest of which point past the end of the image.
   *
   * The past-the-end target is what keeps the case cheap: `walkDirectory` still
   * SPENDS a budget entry on each one (the decrement is above the bounds test),
   * so the allowance runs out, while nothing is flattened and nothing renders.
   * `0x7ffffff0` has its high bit clear, so each is read as a LEAF rather than
   * as a subdirectory, and no `visited` entry collapses them.
   */
  function peWithBudgetedRoot(total: number, leaves: number): PEFile {
    const entriesAt = 16;
    const leavesAt = entriesAt + total * 8;
    const blobAt = leavesAt + leaves * 16;
    const body = new Uint8Array(blobAt + Math.max(leaves, 1) * 4);
    const dv = new DataView(body.buffer);

    // One directory cannot declare more than 0xFFFF of either kind, so the
    // budget's worth needs both counts. No entry sets the high bit in `Name`,
    // so the walk reads them all as IDs whatever the split claims.
    const ids = Math.min(total, 0xffff);
    dv.setUint16(12, total - ids, true);
    dv.setUint16(14, ids, true);
    for (let i = 0; i < total; i++) {
      const at = entriesAt + i * 8;
      dv.setUint32(at, i, true);
      dv.setUint32(at + 4, i < leaves ? leavesAt + i * 16 : 0x7ffffff0, true);
    }
    for (let i = 0; i < leaves; i++) {
      const at = leavesAt + i * 16;
      dv.setUint32(at, BUDGET_RVA + blobAt + i * 4, true); // OffsetToData is an RVA
      dv.setUint32(at + 4, 4, true); // Size
      dv.setUint32(at + 8, 0, true); // CodePage
    }

    return parsePE(
      buildMinimalPE64({
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
            virtualAddress: BUDGET_RVA,
            virtualSize: body.length,
            data: body,
            characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
          },
        ],
        dataDirectories: new Map([
          [IMAGE_DIRECTORY_ENTRY_RESOURCE, { virtualAddress: BUDGET_RVA, size: body.length }],
        ]),
      }),
    );
  }

  /** The admission beside the count line, or null. */
  const budgetNotice = () =>
    screen.queryByText(/^Incomplete — the walk did not cover every entry$/);

  it("builds a directory the walk really does cut short, with leaves surviving", () => {
    // THE FIXTURE, ASSERTED BEFORE THE COMPONENT. Every row below is vacuous if
    // the walk is not actually truncated or if the leaves do not survive it, and
    // both are properties of bytes this file writes by hand.
    const pe = peWithBudgetedRoot(MAX_TOTAL_ENTRIES + 4, 3);
    expect(pe.resources!.truncated).toBe(true);
    expect(pe.resources!.entries).toHaveLength(3);
    expect(pe.resources!.root).toHaveLength(MAX_TOTAL_ENTRIES);
  });

  it("says the tree is incomplete beside the counts", () => {
    renderResources(peWithBudgetedRoot(MAX_TOTAL_ENTRIES + 4, 3));
    // The counts are still printed and still describe what was RECOVERED — the
    // admission qualifies them rather than replacing them, because 3 entries is
    // the true extent of the table on screen.
    expect(screen.getByRole("heading", { level: 2 }).textContent).toBe(
      "Resources (3 types, 3 entries)",
    );
    expect(budgetNotice()).toBeTruthy();
  });

  it("names the budget in the admission rather than spelling a number", () => {
    // `MAX_TOTAL_ENTRIES` is exported, so the sentence a reader gets moves with
    // the constant. Read from the module, never from a literal here.
    renderResources(peWithBudgetedRoot(MAX_TOTAL_ENTRIES + 4, 3));
    expect(budgetNotice()!.getAttribute("title")).toContain(String(MAX_TOTAL_ENTRIES));
  });

  it("still renders every row it recovered", () => {
    // THE ADMISSION MUST NOT WITHHOLD THE ANSWER. What survived the budget is
    // as true as it ever was; refusing to show it would trade one wrong shape
    // for another, which is `XrefPanel`'s "fall back VISIBLY" rule.
    const { container } = renderResources(peWithBudgetedRoot(MAX_TOTAL_ENTRIES + 4, 3));
    expect(container.querySelectorAll("tbody tr")).toHaveLength(3);
  });

  it("does not claim incompleteness for a directory the walk read whole", () => {
    // THE LIVENESS HALF. Every row above is equally green against a view that
    // printed the admission unconditionally.
    renderResources(
      peWithParsedResources([
        {
          id: RT_MANIFEST,
          names: [{ id: 1, langs: [{ lang: 0x0409, data: new Uint8Array([1, 2, 3, 4]) }] }],
        },
      ]),
    );
    expect(budgetNotice()).toBeNull();
    expect(screen.queryByText(/could not be read whole/)).toBeNull();
  });

  it("does not claim incompleteness for a directory that is exactly the budget's worth", () => {
    // THE BOUNDARY, from the view's side. `peek-a-bin-6qx9` fixed a parser
    // off-by-one that reported truncation over a COMPLETE answer at exactly
    // this size; a reader would have been told a whole tree was short.
    const pe = peWithBudgetedRoot(MAX_TOTAL_ENTRIES, 3);
    expect(pe.resources!.truncated).toBeUndefined();
    renderResources(pe);
    expect(budgetNotice()).toBeNull();
  });

  describe("and where it reached no leaf at all", () => {
    it("does not say the file has no resources", () => {
      /**
       * THE WORSE HALF. `entries.length === 0` took the same exit as a PE with
       * no resource directory, so a walk that ran out of allowance before
       * descending to a single data entry printed "No resources found in this PE
       * file." — a positive claim about the file, not a narrow one.
       *
       * `HeaderView`'s imphash distinction in view form: `""` means "imports
       * nothing" and `null` means "the table is not whole", and collapsing them
       * prints "No imports" over a table that was merely cut short.
       */
      const pe = peWithBudgetedRoot(MAX_TOTAL_ENTRIES + 1, 0);
      expect(pe.resources!.truncated).toBe(true);
      expect(pe.resources!.entries).toHaveLength(0);

      renderResources(pe);
      expect(screen.queryByText("No resources found in this PE file.")).toBeNull();
      const notice = screen.getByText(/could not be read whole/);
      expect(notice.textContent).toContain(String(MAX_TOTAL_ENTRIES));
      expect(notice.textContent).toMatch(/not necessarily without resources/);
    });

    it("still says the file has none when the walk read an empty directory whole", () => {
      // THE LIVENESS HALF OF THE SAME ARM, and the reason the calm sentence
      // stays: a directory with nothing in it and no directory at all really
      // are one fact to a reader. Only a CUT-SHORT walk is a different one.
      renderResources(peWithParsedResources([]));
      expect(screen.getByText("No resources found in this PE file.")).toBeTruthy();
      expect(screen.queryByText(/could not be read whole/)).toBeNull();
    });
  });
});

/**
 * THE CARET THAT USED TO OPEN ONTO NOTHING.
 *
 * Every leaf row renders an expand caret, and `ExpandedLeaf` had arms for three
 * types out of the ~20 the format defines. So on an RT_BITMAP, RT_STRING,
 * RT_DIALOG or RT_RCDATA — most of what an ordinary binary carries — the arrow
 * flipped to its open state and produced an empty `<tr><td colSpan={5}>`. Two of
 * the rows above had PINNED THAT AS THE RULE with
 * `expect(rows[1].textContent).toBe("")`.
 *
 * The fallback goes through `resourceBytes`, the ONE declaration of the bound,
 * so the `RangeError` `peek-a-bin-p0qw` found on a truncated image cannot come
 * back through a new call site: it is the same guard, and its refusal now prints
 * a sentence rather than a blank row.
 */
describe("ResourcesView — the hex/ASCII fallback", () => {
  /** A leaf of `body`'s bytes under a type with no dedicated preview arm. */
  function peWithRcdata(body: Uint8Array, size = body.length): PEFile {
    const section = new Uint8Array(Math.max(0x200, body.length));
    section.set(body, 0);
    return withResources(peWithResourceBytes(section), [
      { type: RT_RCDATA, name: 1, lang: 1033, rva: RSRC_RVA, size },
    ]);
  }

  async function expandRcdata(pe: PEFile) {
    const { user, dispatch } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    return { dispatch, detail: rowsUnder(ResourceTypeNames[RT_RCDATA])[1] };
  }

  it("prints the bytes as hex AND as ASCII, from the file's real buffer", async () => {
    // Both halves, because each catches a different way of being wrong: a dump
    // with no ASCII column is unreadable, and an ASCII column with no hex hides
    // every non-printable byte behind a dot.
    const { detail } = await expandRcdata(peWithRcdata(new TextEncoder().encode("PEEKABIN")));
    expect(detail.textContent).toContain("50 45 45 4b 41 42 49 4e");
    expect(detail.textContent).toContain("|PEEKABIN");
  });

  it("writes a non-printable byte as a dot in the ASCII column and as itself in hex", async () => {
    const { detail } = await expandRcdata(peWithRcdata(new Uint8Array([0x41, 0x00, 0x7f, 0x42])));
    expect(detail.textContent).toContain("41 00 7f 42");
    expect(detail.textContent).toContain("|A..B");
  });

  it("lays the dump out in 16-byte rows with resource-relative offsets", async () => {
    // Resource-relative, not file offsets: nothing else on this tab shows a file
    // offset, and the RVA beside it is the address the Hex tab wants.
    const { detail } = await expandRcdata(peWithRcdata(new Uint8Array(48).fill(0xcc)));
    expect(detail.textContent).toContain("00000000  cc");
    expect(detail.textContent).toContain("00000010  cc");
    expect(detail.textContent).toContain("00000020  cc");
    expect(detail.textContent).not.toContain("00000030");
  });

  it("states the whole count when the whole resource is shown", async () => {
    const { detail } = await expandRcdata(peWithRcdata(new Uint8Array(32).fill(1)));
    expect(detail.textContent).toContain("32 bytes");
    expect(detail.textContent).not.toContain("first");
  });

  it("ADMITS THE CAP ON THE COUNT LINE for a resource longer than the preview", async () => {
    /**
     * THE STAGE-7 CLASS: a narrower answer must not wear a complete one's shape.
     * A preview that simply stopped at 256 bytes reads exactly like a 256-byte
     * resource — and the Size column two cells away says otherwise, so the pane
     * would contradict itself.
     */
    const { detail } = await expandRcdata(peWithRcdata(new Uint8Array(300).fill(0x5a)));
    expect(detail.textContent).toContain("first 256 of 300 bytes");
    // The cap is real, not just admitted: the row at 0x100 is not printed.
    expect(detail.textContent).toContain("000000f0  5a");
    expect(detail.textContent).not.toContain("00000100");
  });

  it("does not claim a cap for a resource of exactly the preview length", async () => {
    // Both sides of the boundary, on `peek-a-bin-6qx9`'s model: the off-by-one
    // that reported a complete answer as short is the same defect mirrored.
    const { detail } = await expandRcdata(peWithRcdata(new Uint8Array(256).fill(7)));
    expect(detail.textContent).toContain("256 bytes");
    expect(detail.textContent).not.toContain("first");
  });

  it("says how much of a DECLARED size the file actually holds", async () => {
    /**
     * The other truncation, and it is a different fact from the cap: here the
     * cut lands INSIDE the leaf, so `resourceBytes` clamps to the buffer and
     * returns fewer bytes than the directory declares. Printing only the
     * clamped count would state the file's own declared size as smaller than it
     * is.
     */
    const pe = peWithRcdata(new Uint8Array(0x40).fill(0x33), 0x10000);
    const { detail } = await expandRcdata(pe);
    const available = pe.buffer.byteLength - rvaToFileOffset(RSRC_RVA, pe.sections);
    expect(detail.textContent).toContain(
      `the file holds ${available.toLocaleString()} of the 65,536 bytes the directory declares`,
    );
  });

  it("says a resource declares no bytes rather than printing an empty dump", async () => {
    const { detail } = await expandRcdata(peWithRcdata(new Uint8Array(0x40), 0));
    expect(detail.textContent).toContain("This resource declares no bytes.");
    expect(detail.querySelector("pre")).toBeNull();
  });

  it("shows the unreadable arm, and DOES NOT THROW, on a leaf past the end of a TRUNCATED file", async () => {
    /**
     * `peek-a-bin-p0qw`'s `RangeError` asked of the NEW call site. The fallback
     * is the one arm every unhandled type reaches, so a hand-rolled
     * `Math.min(size, byteLength - fileOff)` here would have reintroduced the
     * defect across the whole population instead of one type.
     *
     * The file is cut so the section table still maps the leaf and the buffer
     * does not contain its first byte — the exact shape `rvaToFileOffset` cannot
     * see, because it answers against the section table alone.
     */
    const buf = buildMinimalPE64({
      directorySectionName: ".rsrc",
      directoryRVA: RSRC_RVA,
      directories: {
        resources: [
          {
            id: RT_RCDATA,
            names: [{ id: 1, langs: [{ lang: 0x0409, data: new Uint8Array(32).fill(0xd7) }] }],
          },
        ],
      },
    });
    const full = parsePE(buf);
    const leafOff = rvaToFileOffset(full.resources!.entries[0].rva, full.sections);
    const pe = parsePE(buf.slice(0, leafOff));
    // The fixture: the row survives the cut and its bytes do not.
    expect(pe.resources!.entries).toHaveLength(1);
    expect(rvaToFileOffset(pe.resources!.entries[0].rva, pe.sections)).toBe(leafOff);
    expect(leafOff).toBeGreaterThanOrEqual(pe.buffer.byteLength);

    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    const detail = rowsUnder(ResourceTypeNames[RT_RCDATA])[1];
    expect(detail.textContent).toContain("past the end of the file");
    // Not the empty box, and not the pane's ErrorBoundary either — the tree is
    // still standing with its heading and its row.
    expect(detail.querySelector("pre")).toBeNull();
    // Not the pane's ErrorBoundary either: the row is still there, still open.
    expect(screen.getByRole("button", { name: "▼#1" })).toBeTruthy();
    expect(screen.getByRole("button", { name: /RC Data/ })).toBeTruthy();
  });

  it("says a VERSION resource could not be read rather than that it carries no strings", async () => {
    /**
     * WHY THE GUARD SITS ABOVE RT_VERSION. `parseVersionInfo` bounds its own
     * reads, so an unreachable resource came back `{}` and the arm printed "No
     * version strings found" — a positive claim about the RESOURCE resting on
     * the tool's own failure to reach it, which is `peek-a-bin-wo8g`'s class one
     * level down from the directory.
     */
    const pe = withResources(peWithResourceBytes(new Uint8Array(0x100)), [
      { type: RT_VERSION, name: 1, lang: 1033, rva: 0xdeadb, size: 64 },
    ]);
    const { user } = renderResources(pe);
    await user.click(screen.getByRole("button", { name: "▶#1" }));
    expect(screen.queryByText("No version strings found")).toBeNull();
    expect(screen.getByText(/its RVA falls in no section/)).toBeTruthy();
  });
});

/**
 * THE GROUP-ICON PREVIEW'S OBJECT URL — one leaked blob per render, before this.
 *
 * `ExpandedLeaf` called `URL.createObjectURL` in the middle of RENDER and never
 * called `URL.revokeObjectURL` anywhere, so the URL (and the blob behind it)
 * stayed pinned to the document for the rest of the session — once per render
 * of an expanded group icon, and this pane re-renders on every collapse, expand
 * and download click.
 *
 * READ THE FILE-WIDE STUB ABOVE FIRST. jsdom implements neither function, which
 * is exactly why nothing had ever rendered this arm.
 */
describe("ResourcesView — the group icon's object URL", () => {
  /**
   * A real `.rsrc` holding a one-entry `GRPICONDIR` at its start and the icon
   * bytes it names 0x20 in, plus the hand-written tree naming both. Built to
   * `reconstructIcon`'s own reading: `type` must be 1, `count` non-zero, and
   * `nId` at +12 of the 14-byte `GRPICONDIRENTRY` must match an RT_ICON name.
   */
  function peWithGroupIcon(): PEFile {
    const body = new Uint8Array(0x200);
    const view = new DataView(body.buffer);
    view.setUint16(0, 0, true); // reserved
    view.setUint16(2, 1, true); // type: icon
    view.setUint16(4, 1, true); // count
    body[6] = 16; // width
    body[7] = 16; // height
    view.setUint16(6 + 6, 1, true); // planes
    view.setUint16(6 + 8, 32, true); // bitCount
    view.setUint32(6 + 10, 16, true); // bytesInRes
    view.setUint16(6 + 12, 1, true); // nId -> the RT_ICON named 1
    body.fill(0xaa, 0x20, 0x30);
    return withResources(peWithResourceBytes(body), [
      { type: RT_GROUP_ICON, name: 1, lang: 1033, rva: RSRC_RVA, size: 20 },
      { type: RT_ICON, name: 1, lang: 1033, rva: RSRC_RVA + 0x20, size: 16 },
      // A third type with no relation to the icon, so the re-render row below
      // has a caret to toggle whose heading `rowsUnder`'s regex cannot confuse
      // with "Group Icon".
      { type: RT_RCDATA, name: 2, lang: 1033, rva: RSRC_RVA + 0x40, size: 16 },
    ]);
  }

  const groupCaret = () =>
    within(rowsUnder(ResourceTypeNames[RT_GROUP_ICON])[0]).getByRole("button", { name: "▶#1" });

  it("builds a fixture the reconstruction really accepts", async () => {
    // The liveness half. Every count below is 0 for a group icon that fails to
    // reconstruct, so a green balance would say nothing about the lifecycle.
    const { user } = renderResources(peWithGroupIcon());
    await user.click(groupCaret());
    expect(screen.getByAltText("Icon").getAttribute("src")).toBe(mintedUrls[0]);
    expect(mintedUrls).toHaveLength(1);
  });

  it("mints the URL from an effect, not during render", async () => {
    // The defect minted one per render. Expanding a SECOND leaf re-renders the
    // whole pane, including the mounted icon, and must not mint again.
    const { user } = renderResources(peWithGroupIcon());
    await user.click(groupCaret());
    expect(mintedUrls).toHaveLength(1);
    await user.click(screen.getByRole("button", { name: "▶#2" }));
    await user.click(screen.getByRole("button", { name: "▼#2" }));
    expect(mintedUrls).toHaveLength(1);
    expect(revokedUrls).toEqual([]);
  });

  it("REVOKES ONCE PER CREATE across expand → collapse → unmount", async () => {
    /**
     * THE WHOLE INSTRUMENT FOR THIS REPAIR, and the reason it is a pairing
     * rather than two counts: the defect passes a create-count assertion (it
     * minted one on the first render) and passes a revoke-count assertion of
     * zero for the collapsed case. Only `revoked === minted` at each step
     * discriminates.
     */
    const openCaret = () =>
      within(rowsUnder(ResourceTypeNames[RT_GROUP_ICON])[0]).getByRole("button", {
        name: "▼#1",
      });

    const { user, unmount } = renderResources(peWithGroupIcon());
    await user.click(groupCaret());
    expect(mintedUrls).toHaveLength(1);
    expect(revokedUrls).toEqual([]);

    // Collapse: the child unmounts, so its cleanup runs.
    await user.click(openCaret());
    expect(mintedUrls).toHaveLength(1);
    expect(revokedUrls).toEqual(mintedUrls);

    // A second cycle, so the row cannot pass on a single lucky pairing.
    await user.click(groupCaret());
    expect(mintedUrls).toHaveLength(2);
    expect(revokedUrls).toHaveLength(1);
    await user.click(openCaret());
    expect(revokedUrls).toEqual(mintedUrls);

    // And the unmount path, which is the one `cleanup()` in `afterEach` would
    // otherwise take after every assertion had already run.
    await user.click(groupCaret());
    expect(mintedUrls).toHaveLength(3);
    expect(revokedUrls).toHaveLength(2);
    unmount();
    expect(revokedUrls).toEqual(mintedUrls);
  });

  it("says so, and mints nothing, when the icon cannot be reconstructed", async () => {
    // `reconstructIcon` answers null when no RT_ICON matches the group's `nId`.
    const pe = peWithGroupIcon();
    pe.resources!.entries = pe.resources!.entries.filter((e) => e.type !== RT_ICON);
    const { user } = renderResources(pe);
    await user.click(groupCaret());
    expect(screen.getByText("Could not reconstruct icon")).toBeTruthy();
    expect(mintedUrls).toEqual([]);
  });

  it("keeps the group-icon arm OUT of the shared bounds guard, deliberately", async () => {
    /**
     * THE RECORDED ASYMMETRY. `buffer.slice` CLAMPS where `new Uint8Array(buf,
     * off, len)` throws, so a past-the-end group icon yields an empty buffer and
     * `reconstructIcon` answers null — the honest "could not reconstruct"
     * sentence rather than the truncation sentence, and no `RangeError`. Routing
     * this arm through `resourceBytes` "for consistency" is the change this row
     * exists to fail.
     */
    const pe = peWithGroupIcon();
    pe.resources!.entries[0] = { ...pe.resources!.entries[0], rva: RSRC_RVA + 0x100000 };
    const { user } = renderResources(pe);
    await user.click(groupCaret());
    expect(screen.getByText("Could not reconstruct icon")).toBeTruthy();
    expect(screen.queryByText(/past the end of the file/)).toBeNull();
    expect(mintedUrls).toEqual([]);
  });
});

/**
 * THE RVA COLUMN — blue monospace text inside a plain `<td>`, since the tab was
 * written.
 *
 * Every other blue address in this app is clickable: `SectionTable`'s rows,
 * `HeaderView`'s `CopyableHex`, every operand in the listing. This one looked
 * identical and did nothing, which is worse than plain text — a reader clicks
 * it, gets nothing, and stops trusting the colour.
 */
describe("ResourcesView — the RVA goes to the Hex view", () => {
  const pe = () =>
    withResources(peWithResourceBytes(new Uint8Array(0x200)), [
      { type: RT_RCDATA, name: 1, lang: 1033, rva: RSRC_RVA, size: 16 },
    ]);

  it("renders the RVA as a real control", () => {
    renderResources(pe());
    expect(screen.getByRole("button", { name: "0x3000" })).toBeTruthy();
  });

  it("dispatches the VA and the tab, in that order", async () => {
    /**
     * `imageBase + rva`, because the VA is what the rest of the app speaks and
     * `HexView` derives its section from `state.currentAddress` alone — so the
     * address has to land before the tab that reads it.
     */
    const file = pe();
    const { user, dispatch } = renderResources(file);
    await user.click(screen.getByRole("button", { name: "0x3000" }));
    expect(dispatch.mock.calls.map((c) => c[0])).toEqual([
      { type: "SET_ADDRESS", address: file.optionalHeader.imageBase + RSRC_RVA },
      { type: "SET_TAB", tab: "hex" },
    ]);
  });

  it("resolves that VA to the section the resource is in", () => {
    /**
     * A FIXTURE ROW, NOT A COMPONENT ROW, and it is here because it carries the
     * argument for the destination: `HexView` derives its section by walking
     * `pe.sections` for the one containing `currentAddress - imageBase`, which
     * is `useSectionInfo`'s rule, and the VA this button dispatches lands inside
     * `.rsrc`. That is why the Hex tab is right and the disassembly tab is not
     * — a linear sweep of resource bytes is invented code, which this repo goes
     * to some length to avoid elsewhere. Reverting the cell to a `<td>` does not
     * redden this row, deliberately: it is about the address, not the control.
     */
    const file = pe();
    const section = file.sections.find(
      (sec) => RSRC_RVA >= sec.virtualAddress && RSRC_RVA < sec.virtualAddress + sec.virtualSize,
    );
    expect(section?.name).toBe(".rsrc");
  });

  it("does not expand the leaf — the two controls are separate", async () => {
    const { user } = renderResources(pe());
    await user.click(screen.getByRole("button", { name: "0x3000" }));
    expect(rowsUnder(ResourceTypeNames[RT_RCDATA])).toHaveLength(1);
    expect(screen.getByRole("button", { name: "▶#1" })).toBeTruthy();
  });
});
