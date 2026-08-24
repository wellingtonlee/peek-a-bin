// @vitest-environment jsdom

import "../../test/domSetup";
import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, type MockInstance, vi } from "vitest";
import type { AppState } from "../../hooks/usePEFile";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import {
  IMAGE_SCN_CNT_CODE,
  IMAGE_SCN_CNT_INITIALIZED_DATA,
  IMAGE_SCN_MEM_EXECUTE,
  IMAGE_SCN_MEM_READ,
} from "../../pe/constants";
import { extractStrings, parsePE, rvaToFileOffset } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
import { stubLayoutRect } from "../../test/domSetup";
import { StringsView } from "../StringsView";
import { AppHarness, stateWithPE } from "./appStateHarness";

/**
 * THE STRINGS TAB, rendered for the first time.
 *
 * One of the tabs `analysisNotice()`'s `"no-code-section"` kind sends a user to
 * (`PARSER_DERIVED_TABS` names `"strings"`), and one of three view tabs nothing
 * had ever mounted.
 *
 * THE STRINGS ARE REAL, and that is what makes the address column assertable.
 * `parsePE` leaves `pe.strings` empty — it is filled by the `extractStrings`
 * RPC — but `extractStrings` is a pure function of the buffer and the section
 * table, needing neither Capstone nor a worker, so it is called directly here
 * over sections whose bytes this file writes. Every address on screen is
 * therefore the production scanner's own answer about production bytes.
 *
 * THAT MATTERS BECAUSE THE COLUMN IS LABELLED "VA" AND THE SCANNER WORKS IN FILE
 * OFFSETS. `extractASCIIStrings` walks from `section.pointerToRawData` and keys
 * its map on `imageBase + section.virtualAddress + (fileOffset - pointerToRawData)`
 * — so a bug anywhere in that arithmetic prints a file offset, or a bare RVA,
 * under a heading that says VA. The fixture puts `pointerToRawData` and
 * `virtualAddress` deliberately far apart so those three candidate answers are
 * three different numbers, and the assertion names all three.
 *
 * ═══ VIRTUALIZATION IS A STAND-IN. READ THIS BEFORE TRUSTING A ROW ASSERTION. ═══
 *
 * The rows are a `useVirtualizer` over a scroll container jsdom measures as 0px,
 * so WITHOUT HELP `getVirtualItems()` is empty and not one string is in the
 * document. {@link stubLayoutRect} is called at the top of this file to make the
 * container report 600px, which is what lets any row be asserted at all.
 *
 * WHAT THAT DOES AND DOES NOT BUY, precisely:
 *  - **Buys**: with `estimateSize: 24` and `overscan: 30`, a range of roughly
 *    the first 55 rows exists in the document. Every fixture here is far smaller
 *    than that, so for these tests the row set in the document IS the whole
 *    filtered list — which is what makes the filter, encoding and sort
 *    assertions below meaningful as statements about a *set* and an *order*.
 *  - **Does NOT buy**: anything about a real listing. Every element reports the
 *    same rect, `scrollTop` is permanently 0, and the stub `ResizeObserver`
 *    never fires, so the range is computed once from offset 0 and never moves.
 *    Whether the 60th row of a 200 000-string binary can be reached, whether
 *    `overscan: 30` is right, and whether ANY of this is on screen are layout
 *    questions jsdom cannot answer. A row in the document is not a row on
 *    screen. `ASSERTABLE_ROWS` below is the bound; a fixture larger than it
 *    would make these assertions quietly partial.
 */

stubLayoutRect({ height: 600 });

/**
 * NO REACT DIAGNOSTIC, ANYWHERE IN THIS FILE — a file-wide assertion, not a test.
 *
 * `ResourcesView.dom.test.tsx` carries the same three hooks and its docstring
 * explains why they must be file-wide rather than one test: React caches the
 * key warning per owner component, so a dedicated test placed after any other
 * render is INERT — measured, not assumed. Kept here as well because it is four
 * lines and it is the only instrument in this repo for a missing or duplicated
 * list key, a `useEffect` that throws, or an invalid DOM nesting — none of which
 * `tsc` or Biome can see and all of which need something to render.
 *
 * Deliberately inlined per suite rather than shared through
 * `appStateHarness.tsx`: a suite that legitimately expects a React warning
 * should be able to opt out by not writing these lines.
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
 * The number of rows this environment can put in the document, and therefore the
 * ceiling on every fixture in this file. 600px / 24px + overscan 30.
 */
const ASSERTABLE_ROWS = 55;

const IMAGE_BASE_64 = 0x140000000;
const RDATA_RVA = 0x2000;
const TEXT_RVA = 0x1000;

function ascii(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

function utf16(s: string): Uint8Array {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) out[i * 2] = s.charCodeAt(i);
  return out;
}

/** Concatenate byte runs into one section body, NUL-separated. */
function body(parts: Uint8Array[], size: number): Uint8Array {
  const out = new Uint8Array(size);
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length + 2; // two NULs: also terminates a UTF-16 run
  }
  return out;
}

/**
 * A PE whose `.rdata` and `.text` really contain the given strings, with
 * `pe.strings`/`pe.stringTypes` filled by the production scanner.
 */
function peWithStrings(opts: {
  rdata?: Uint8Array[];
  text?: Uint8Array[];
  is64?: boolean;
}): PEFile {
  const is64 = opts.is64 ?? true;
  const build = is64 ? buildMinimalPE64 : buildMinimalPE32;
  const textBody = body(opts.text ?? [], 0x200);
  textBody[0x1f0] = 0xc3;
  const pe = parsePE(
    build({
      imageBase: is64 ? IMAGE_BASE_64 : 0x400000,
      sections: [
        {
          name: ".text",
          virtualAddress: TEXT_RVA,
          virtualSize: textBody.length,
          data: textBody,
          characteristics: IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE,
        },
        {
          name: ".rdata",
          virtualAddress: RDATA_RVA,
          virtualSize: 0x400,
          data: body(opts.rdata ?? [], 0x400),
          characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
        },
      ],
    }),
  );
  const { strings, stringTypes } = extractStrings(
    pe.buffer,
    pe.sections,
    pe.optionalHeader.imageBase,
    pe.is64,
  );
  for (const [k, v] of strings) pe.strings.set(k, v);
  for (const [k, v] of stringTypes) pe.stringTypes.set(k, v);
  return pe;
}

function renderStrings(pe: PEFile, over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  const { container } = render(
    <AppHarness state={stateWithPE(pe, over)} dispatch={dispatch}>
      <StringsView />
    </AppHarness>,
  );
  return { container, dispatch, pe, user: userEvent.setup() };
}

/** One row per string: the address button, then length, xrefs, encoding, value. */
function rows(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll("div.hover\\:bg-blue-900\\/20"));
}

function cellsOf(row: HTMLElement): string[] {
  return Array.from(row.children).map((c) => c.textContent ?? "");
}

const filterBox = () => screen.getByPlaceholderText("Filter strings...");

describe("StringsView — the empty cases", () => {
  it("renders the toolbar and no rows for a PE with no strings", () => {
    // The defect class: an empty list that reads as broken. The header still
    // names the tab and reports a count of zero.
    const { container } = renderStrings(peWithStrings({}));
    expect(screen.getByText("Strings")).toBeTruthy();
    expect(screen.getByText("0 strings")).toBeTruthy();
    expect(rows(container)).toHaveLength(0);
    // The column headings are still there — an empty table, not a blank panel.
    expect(screen.getByText("VA")).toBeTruthy();
    expect(screen.getByText("String")).toBeTruthy();
  });

  it("renders nothing at all with no PE", () => {
    // `if (!pe) return null` — pinned because the hooks above it run first, so a
    // reordering that moved a hook below the guard would break the hook order.
    const { container } = render(
      <AppHarness state={{ ...stateWithPE(peWithStrings({})), peFile: null }} dispatch={vi.fn()}>
        <StringsView />
      </AppHarness>,
    );
    expect(container.textContent).toBe("");
  });
});

describe("StringsView — the address column", () => {
  it("prints a VIRTUAL ADDRESS, not a file offset and not an RVA", () => {
    /**
     * The heading says "VA". This asserts it, by naming all three numbers the
     * scanner has in hand at that point and requiring the right one. The fixture
     * keeps them apart: `.rdata` is at RVA 0x2000 with `pointerToRawData` far
     * below it, and `imageBase` is 0x140000000.
     *
     * A view that printed the RVA would still look like a plausible hex address,
     * which is exactly why only a render test settles it.
     */
    const { container, pe } = renderStrings(peWithStrings({ rdata: [ascii("CreateFileW")] }));
    const va = pe.optionalHeader.imageBase + RDATA_RVA;
    const rva = RDATA_RVA;
    const fileOffset = rvaToFileOffset(rva, pe.sections);
    // Three distinct candidates — assert the fixture actually separates them,
    // or the test below would pass on the wrong one.
    expect(new Set([va, rva, fileOffset]).size).toBe(3);

    const addr = cellsOf(rows(container)[0])[0];
    expect(addr).toBe(va.toString(16).toUpperCase().padStart(16, "0"));
    expect(addr).not.toContain(rva.toString(16).toUpperCase().padStart(16, "0"));
    expect(addr).not.toContain(fileOffset.toString(16).toUpperCase().padStart(16, "0"));
  });

  it("pads to 16 hex digits for a PE32+ image and 8 for a PE32", () => {
    // `pe.is64 ? 16 : 8` — the width is the image's, so a 32-bit binary must not
    // print eight leading zeros it does not have.
    const wide = renderStrings(peWithStrings({ rdata: [ascii("CreateFileW")] }));
    expect(cellsOf(rows(wide.container)[0])[0]).toBe("0000000140002000");
    wide.container.remove();
    const narrow = renderStrings(peWithStrings({ rdata: [ascii("CreateFileW")], is64: false }));
    expect(cellsOf(rows(narrow.container)[0])[0]).toBe("00402000");
  });

  it("jumps to the string's address on the disassembly tab", async () => {
    const { container, dispatch, pe, user } = renderStrings(
      peWithStrings({ rdata: [ascii("CreateFileW")] }),
    );
    await user.click(rows(container)[0].children[0] as HTMLElement);
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: pe.optionalHeader.imageBase + RDATA_RVA,
    });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });

  it("lists strings in ascending address order by default", () => {
    /**
     * THE FIXTURE SPANS TWO SECTIONS, and that is what makes this test bite.
     * `extractStrings` scans `.rdata` FIRST and the code section SECOND, so a
     * `.text` string — at RVA 0x1000, BELOW `.rdata`'s 0x2000 — is inserted into
     * the map after a higher address. Map insertion order is therefore NOT
     * address order, and `allStrings`' explicit `entries.sort` is the only thing
     * putting them right.
     *
     * Measured: with a single-section fixture this row was INERT — deleting the
     * sort left the output identical, because one section's strings are found in
     * ascending offset order anyway.
     */
    const { container } = renderStrings(
      peWithStrings({
        rdata: [ascii("zzzz"), ascii("aaaaaaaa"), ascii("mmmmmm")],
        text: [ascii("in_the_code_section")],
      }),
    );
    const addrs = rows(container).map((r) => Number.parseInt(cellsOf(r)[0], 16));
    expect(addrs).toEqual([...addrs].sort((a, b) => a - b));
    expect(addrs.length).toBeGreaterThanOrEqual(4);
    // The `.text` string is genuinely first, i.e. the sort really moved it.
    expect(cellsOf(rows(container)[0])[4]).toBe("in_the_code_section");
  });

  it("shows strings from the code section as well as from .rdata", () => {
    /**
     * The two passes have DIFFERENT MINIMUM LENGTHS — 4 in `.rdata`, 8 in the
     * code section, since a short run of printable bytes inside instructions is
     * usually not a string. The view has no minimum-length control of its own, so
     * this is the pipeline's rule reaching the screen, which is the only place it
     * can be seen: a `.text` run of 4 is absent while one of 8 is present, and a
     * `.rdata` run of 4 is present.
     */
    const { container } = renderStrings(
      peWithStrings({ rdata: [ascii("shrt")], text: [ascii("tiny"), ascii("longenough")] }),
    );
    const values = rows(container).map((r) => cellsOf(r)[4]);
    expect(values).toContain("shrt");
    expect(values).toContain("longenough");
    expect(values).not.toContain("tiny");
  });
});

describe("StringsView — encoding", () => {
  /**
   * ASCII and UTF-16LE are scanned by two different passes and the `.rdata`
   * ASCII pass runs FIRST, so a UTF-16 run is only recorded where the ASCII pass
   * did not already claim the address. The fixture keeps them at separate
   * offsets for that reason.
   */
  const mixed = () => peWithStrings({ rdata: [ascii("PlainAscii"), utf16("WideText")] });

  it("labels each row with the encoding the scanner recorded", () => {
    const { container } = renderStrings(mixed());
    const byValue = new Map(rows(container).map((r) => [cellsOf(r)[4], cellsOf(r)[3]]));
    expect(byValue.get("PlainAscii")).toBe("ASC");
    expect(byValue.get("WideText")).toBe("U16");
  });

  it("defaults a string with no recorded type to ASCII rather than blank", () => {
    // `pe.stringTypes?.get(address) ?? "ascii"`. A string can reach `pe.strings`
    // without a type — the pointer-indirection pass copies a value and only
    // copies the type `if (t)` — so the fallback is load-bearing, not defensive.
    const pe = peWithStrings({ rdata: [ascii("PlainAscii")] });
    pe.stringTypes.clear();
    const { container } = renderStrings(pe);
    expect(cellsOf(rows(container)[0])[3]).toBe("ASC");
  });

  it("narrows the list to one encoding and back", async () => {
    const { container, user } = renderStrings(mixed());
    const all = rows(container).length;
    expect(all).toBeGreaterThanOrEqual(2);

    await user.click(screen.getByRole("button", { name: "UTF-16" }));
    let shown = rows(container);
    expect(shown.length).toBeGreaterThan(0);
    expect(shown.length).toBeLessThan(all);
    expect(new Set(shown.map((r) => cellsOf(r)[3]))).toEqual(new Set(["U16"]));

    await user.click(screen.getByRole("button", { name: "ASCII" }));
    shown = rows(container);
    expect(new Set(shown.map((r) => cellsOf(r)[3]))).toEqual(new Set(["ASC"]));

    await user.click(screen.getByRole("button", { name: "All" }));
    expect(rows(container)).toHaveLength(all);
  });

  it("marks the active encoding filter and only that one", async () => {
    // COLOUR AS A CLASS-NAME STRING — Tailwind is not loaded here, so there is
    // no computed style to read. What this discriminates is which button carries
    // the selected palette, which is the only signal a user has for it.
    const { user } = renderStrings(mixed());
    const buttonFor = (n: string) => screen.getByRole("button", { name: n });
    expect(buttonFor("All").className).toContain("bg-blue-600");
    expect(buttonFor("ASCII").className).not.toContain("bg-blue-600");
    await user.click(buttonFor("ASCII"));
    expect(buttonFor("ASCII").className).toContain("bg-blue-600");
    expect(buttonFor("All").className).not.toContain("bg-blue-600");
  });

  it("reports zero rather than the unfiltered list when a filter matches nothing", async () => {
    const { container, user } = renderStrings(peWithStrings({ rdata: [ascii("PlainAscii")] }));
    await user.click(screen.getByRole("button", { name: "UTF-16" }));
    expect(rows(container)).toHaveLength(0);
    expect(screen.getByText("0 strings")).toBeTruthy();
  });
});

describe("StringsView — the length column and sorting", () => {
  const three = () =>
    peWithStrings({ rdata: [ascii("aaaa"), ascii("bbbbbbbbbbbb"), ascii("cccccccc")] });

  it("reports each string's character length", () => {
    const { container } = renderStrings(three());
    const byValue = new Map(rows(container).map((r) => [cellsOf(r)[4], cellsOf(r)[1]]));
    expect(byValue.get("aaaa")).toBe("4");
    expect(byValue.get("bbbbbbbbbbbb")).toBe("12");
    expect(byValue.get("cccccccc")).toBe("8");
  });

  it("counts CHARACTERS for a UTF-16 string, not the bytes it occupies", () => {
    /**
     * `entry.value.length` — so a wide string eight characters long reports 8,
     * where the sixteen bytes it occupies in the file are not shown anywhere.
     * Either reading is defensible; this pins the one on screen, and the
     * distinction matters because the Length column sits beside a VA and reads
     * like an extent. Measured: an ASCII-only fixture made this INERT — every
     * candidate answer agrees when one character is one byte.
     */
    const { container } = renderStrings(peWithStrings({ rdata: [utf16("WideText")] }));
    const row = rows(container).find((r) => cellsOf(r)[4] === "WideText")!;
    expect(cellsOf(row)[3]).toBe("U16");
    expect(cellsOf(row)[1]).toBe("8");
  });

  it("re-orders the rows longest-first when sort is switched to length", async () => {
    /**
     * THE ORDER IS THE OBSERVABLE, not the button label. The fixture is laid out
     * in ascending address order with lengths 4, 12, 8, so address order and
     * length order are different permutations and a comparator that returned 0
     * fails rather than passing on already-sorted input.
     */
    const { container, user } = renderStrings(three());
    const toggle = () => screen.getByTitle(/^Sort: by/);
    expect(toggle().textContent).toBe("Addr");
    const beforeLens = rows(container).map((r) => Number(cellsOf(r)[1]));

    await user.click(toggle());
    expect(toggle().textContent).toBe("Len");
    const afterLens = rows(container).map((r) => Number(cellsOf(r)[1]));
    expect(afterLens).toEqual([...afterLens].sort((a, b) => b - a));
    expect(afterLens).not.toEqual(beforeLens);

    await user.click(toggle());
    expect(rows(container).map((r) => Number(cellsOf(r)[1]))).toEqual(beforeLens);
  });

  it("does not mutate the address-sorted list while sorting by length", async () => {
    // `[...result].sort(...)` — the copy matters because `allStrings` is a
    // `useMemo` shared with the unfiltered path, so an in-place sort would leave
    // the address ordering permanently destroyed after one toggle.
    const { container, user } = renderStrings(three());
    const byAddress = rows(container).map((r) => cellsOf(r)[0]);
    await user.click(screen.getByTitle(/^Sort: by/));
    await user.click(screen.getByTitle(/^Sort: by/));
    expect(rows(container).map((r) => cellsOf(r)[0])).toEqual(byAddress);
  });
});

describe("StringsView — the filter box", () => {
  beforeEach(() => {
    vi.useFakeTimers();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  function typeFilter(value: string) {
    fireEvent.change(filterBox(), { target: { value } });
  }

  it("is DEBOUNCED: the row set does not move until 250ms have passed", () => {
    /**
     * The debounce is 250ms and `filterInput` (immediate) drives the header while
     * `filter` (delayed) drives the rows — so for a quarter second the header
     * shows a total that does not match what is on screen. Pinned rather than
     * called a defect: it is what makes typing usable on a large binary, and a
     * test that advanced the timers first would never see it.
     */
    const { container } = renderStrings(
      peWithStrings({ rdata: [ascii("CreateFileW"), ascii("ReadFile")] }),
    );
    const all = rows(container).length;
    typeFilter("Create");
    expect(rows(container)).toHaveLength(all);
    act(() => {
      vi.advanceTimersByTime(249);
    });
    expect(rows(container)).toHaveLength(all);
    act(() => {
      vi.advanceTimersByTime(1);
    });
    expect(rows(container).length).toBeLessThan(all);
    expect(rows(container).map((r) => cellsOf(r)[4])).toEqual(["CreateFileW"]);
  });

  it("shows the filtered count over the total once a filter is typed", () => {
    const { container } = renderStrings(
      peWithStrings({ rdata: [ascii("CreateFileW"), ascii("ReadFile")] }),
    );
    const all = rows(container).length;
    expect(screen.getByText(`${all} strings`)).toBeTruthy();
    typeFilter("Create");
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(screen.getByText(`1 / ${all} strings`)).toBeTruthy();
  });

  it("keeps the `N / M` form while the box holds text that matches everything", () => {
    // The suffix is gated on `filterInput`, not on whether anything was
    // filtered out — so an emptied box drops the total again and a
    // matches-everything filter keeps it.
    const { container } = renderStrings(peWithStrings({ rdata: [ascii("CreateFileW")] }));
    const all = rows(container).length;
    typeFilter("e");
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(screen.getByText(`${all} / ${all} strings`)).toBeTruthy();
    typeFilter("");
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(screen.getByText(`${all} strings`)).toBeTruthy();
  });

  it("matches case-insensitively on the string's text", () => {
    const { container } = renderStrings(
      peWithStrings({ rdata: [ascii("CreateFileW"), ascii("ReadFile")] }),
    );
    typeFilter("createfilew");
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(rows(container).map((r) => cellsOf(r)[4])).toEqual(["CreateFileW"]);
  });

  it("also matches on the address, in hex, with no 0x", () => {
    /**
     * A second predicate in the same box — `s.address.toString(16)` — so the
     * filter doubles as a go-to-address. Worth its own row because the spelling
     * is lower-case hex WITHOUT a `0x` prefix while the column renders
     * upper-case hex zero-padded, so the thing a user would copy off the screen
     * is not what the filter compares against. Both spellings are asserted.
     */
    const { container, pe } = renderStrings(
      peWithStrings({ rdata: [ascii("CreateFileW"), ascii("ReadFile")] }),
    );
    const va = (pe.optionalHeader.imageBase + RDATA_RVA).toString(16);
    typeFilter(va);
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(rows(container).map((r) => cellsOf(r)[4])).toEqual(["CreateFileW"]);

    // Upper case works too (`toLowerCase()` on both sides)...
    typeFilter(va.toUpperCase());
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(rows(container)).toHaveLength(1);

    // ...but the `0x` a user would type does not.
    typeFilter(`0x${va}`);
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(rows(container)).toHaveLength(0);
  });

  it("composes with the encoding filter rather than replacing it", () => {
    const { container } = renderStrings(
      peWithStrings({ rdata: [ascii("MatchAscii"), utf16("MatchWide")] }),
    );
    fireEvent.click(screen.getByRole("button", { name: "UTF-16" }));
    typeFilter("Match");
    act(() => {
      vi.advanceTimersByTime(250);
    });
    expect(rows(container).map((r) => cellsOf(r)[3])).toEqual(["U16"]);
  });
});

describe("StringsView — the xref column and popup", () => {
  const pe = () => peWithStrings({ rdata: [ascii("CreateFileW"), ascii("ReadFile")] });
  const vaOf = (p: PEFile) => p.optionalHeader.imageBase + RDATA_RVA;

  it("says xrefs are still loading while `stringXrefs` is null", () => {
    // `null` is "not computed yet", distinct from an empty map. Rendering a
    // dash for both would tell a user a string is unreferenced when in fact
    // nothing has looked — the same distinction `analysisNotice` draws between
    // a fault and an absence.
    const { container } = renderStrings(pe(), { stringXrefs: null });
    expect(screen.getByText("Xrefs loading...")).toBeTruthy();
    expect(cellsOf(rows(container)[0])[2]).toBe("—");
  });

  it("says xrefs are loaded once the map arrives, even if it is empty", () => {
    const { container } = renderStrings(pe(), { stringXrefs: new Map() });
    expect(screen.getByText("Xrefs loaded")).toBeTruthy();
    expect(screen.queryByText("Xrefs loading...")).toBeNull();
    expect(cellsOf(rows(container)[0])[2]).toBe("—");
  });

  it("shows a count only for a string that has one", () => {
    const p = pe();
    const { container } = renderStrings(p, {
      stringXrefs: new Map([[vaOf(p), [0x140001010, 0x140001020]]]),
    });
    const byValue = new Map(rows(container).map((r) => [cellsOf(r)[4], cellsOf(r)[2]]));
    expect(byValue.get("CreateFileW")).toBe("2");
    expect(byValue.get("ReadFile")).toBe("—");
  });

  it("opens a popup naming every referencing address", async () => {
    const p = pe();
    const { user } = renderStrings(p, {
      stringXrefs: new Map([[vaOf(p), [0x140001010, 0x140001020]]]),
    });
    await user.click(screen.getByRole("button", { name: "2" }));
    expect(screen.getByText(`Xrefs to 0x${vaOf(p).toString(16).toUpperCase()}`)).toBeTruthy();
    expect(screen.getByRole("button", { name: "0x140001010" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "0x140001020" })).toBeTruthy();
  });

  it("jumps to a referencing address and closes the popup", async () => {
    const p = pe();
    const { dispatch, user } = renderStrings(p, {
      stringXrefs: new Map([[vaOf(p), [0x140001010]]]),
    });
    await user.click(screen.getByRole("button", { name: "1" }));
    await user.click(screen.getByRole("button", { name: "0x140001010" }));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140001010 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
    expect(screen.queryByText(/^Xrefs to /)).toBeNull();
  });

  it("closes the popup on Escape", async () => {
    const p = pe();
    const { user } = renderStrings(p, { stringXrefs: new Map([[vaOf(p), [0x140001010]]]) });
    await user.click(screen.getByRole("button", { name: "1" }));
    expect(screen.getByText(/^Xrefs to /)).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByText(/^Xrefs to /)).toBeNull();
  });

  it("closes the popup on a click outside it but not inside it", async () => {
    const p = pe();
    const { user } = renderStrings(p, {
      stringXrefs: new Map([[vaOf(p), [0x140001010, 0x140001020]]]),
    });
    await user.click(screen.getByRole("button", { name: "2" }));
    // Inside: the popup's own heading. `useDismissOnOutsideClick` decides this
    // with a ref containment check rather than `stopPropagation`, so the click
    // is still visible to every other listener on the page.
    await user.click(screen.getByText(/^Xrefs to /));
    expect(screen.getByText(/^Xrefs to /)).toBeTruthy();
    // Outside.
    await user.click(screen.getByText("Strings"));
    expect(screen.queryByText(/^Xrefs to /)).toBeNull();
  });
});

describe("StringsView — what this environment can and cannot see", () => {
  it("puts every row of a small list in the document, so the sets above are whole", () => {
    // The claim the file docstring rests on. With `stubLayoutRect` the range
    // covers roughly the first 55 rows; asserted here so a change to
    // `estimateSize`, `overscan` or the stub height turns this row red rather
    // than silently making every set assertion above partial.
    const many = Array.from({ length: 12 }, (_, i) => ascii(`string_number_${i}`));
    const { container } = renderStrings(peWithStrings({ rdata: many }));
    expect(rows(container).length).toBeGreaterThanOrEqual(12);
    expect(rows(container).length).toBeLessThanOrEqual(ASSERTABLE_ROWS);
    expect(screen.getByText("string_number_0")).toBeTruthy();
    expect(screen.getByText("string_number_11")).toBeTruthy();
  });

  it("renders nothing when the container has no measured height", () => {
    /**
     * THE NEGATIVE CONTROL FOR THE STUB ITSELF, and the reason this file says
     * what it says about virtualization. `virtual-core` computes a range only
     * when the scroll element's `offsetHeight` is non-zero — so with the stub
     * reporting 0, a list of twelve strings renders ZERO rows, not a short list.
     *
     * Every row assertion in this file therefore depends on a stand-in, and the
     * green suite is evidence about the component's logic and not about whether
     * a browser would show a user anything.
     */
    const original = Object.getOwnPropertyDescriptor(HTMLElement.prototype, "offsetHeight")!;
    Object.defineProperty(HTMLElement.prototype, "offsetHeight", {
      configurable: true,
      get: () => 0,
    });
    try {
      const { container } = renderStrings(
        peWithStrings({ rdata: Array.from({ length: 12 }, (_, i) => ascii(`str_${i}0000`)) }),
      );
      expect(rows(container)).toHaveLength(0);
      // The toolbar count still reports the whole list — the strings exist, they
      // are simply not rendered. That asymmetry is what makes a row-count
      // assertion a bad proxy for "the scanner found something".
      expect(screen.getByText(/ strings$/).textContent).toMatch(/^[1-9]\d* strings$/);
    } finally {
      Object.defineProperty(HTMLElement.prototype, "offsetHeight", original);
    }
  });
});
