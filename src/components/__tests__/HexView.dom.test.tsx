// @vitest-environment jsdom

import "../../test/domSetup";
// jsdom implements neither ResizeObserver nor matchMedia, and HexView's
// entropy-strip effect constructs both — see the stub's docstring for what it
// does and does not buy (it buys nothing whatever about measured widths).
import "../../test/browserApiStubs";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AppState } from "../../hooks/usePEFile";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { HexView, MAX_BYTE_PATTERN_MATCHES } from "../HexView";
import { AppHarness, harnessPE, IMAGE_BASE, stateWithPE } from "./appStateHarness";

/**
 * The hex tab's toolbar. NOT the hex grid.
 *
 * THE GRID IS UNREACHABLE HERE AND THAT IS MOST OF THIS COMPONENT. The rows are
 * a `useVirtualizer` over a scroll container jsdom measures as 0px, so
 * `getVirtualItems()` is empty and not one byte, offset or ASCII column is in
 * the document — verified rather than assumed, and asserted at the bottom of
 * this file so the claim cannot rot. Nothing here is evidence about byte
 * rendering, the ASCII gutter, selection, patched-byte highlighting, the
 * context menu, xref popups, or scroll-to-address.
 *
 * THE ENTROPY STRIP IS UNREACHABLE FOR A SECOND, INDEPENDENT REASON, and it is
 * worth naming because the strip is the part with the most machinery behind it.
 * `useEntropyStrip` is called with `showEntropy && stripDevicePx > 0`, and
 * `stripDevicePx` is set from a `ResizeObserver` on an element that measures 0
 * in jsdom — so even with the toggle on, the hook is asked for nothing, the
 * worker is never reached, and the canvas draws nothing. The sync/async
 * threshold that `hooks/__tests__/fileMetricsOffThread.test.ts` guards over the
 * AST is therefore still not *executed* by anything, here or elsewhere.
 *
 * WHAT IS REACHABLE is the toolbar, and one part of it is worth more than the
 * rest: the byte search runs `parseBytePattern` and `findBytePatternMatches`
 * over the real section bytes of a real parsed PE and reports a count. That is
 * an end-to-end path through the component with an observable answer, wildcards
 * included, and nothing exercised it before.
 *
 * That count is also where this component's one truncation admission lives, and
 * both sides of its boundary are pinned below — see "HexView byte search cap".
 */

/** `.rdata` in the harness fixture — the export tables, so it has real content. */
const RDATA_VA = 0x2000;

function renderHex(over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  const pe = harnessPE();
  const { container } = render(
    <AppHarness
      state={stateWithPE(pe, { currentAddress: IMAGE_BASE + RDATA_VA, ...over })}
      dispatch={dispatch}
    >
      <HexView />
    </AppHarness>,
  );
  return { dispatch, container, pe, user: userEvent.setup() };
}

const sectionSelect = () => screen.getByRole("combobox") as HTMLSelectElement;
const byteSearchBox = () => screen.getByPlaceholderText(/^Byte search/);
const gotoBox = () => screen.getByPlaceholderText("Offset or VA (hex)");

/** RVA of {@link renderFilled}'s one section, and the byte it is filled with. */
const FILL_VA = 0x1000;
const FILL_BYTE = "AA";

/**
 * A PE whose ONE section holds exactly `occurrences` copies of `AA` and nothing
 * else, so a one-byte `AA` search has a count known by construction rather than
 * counted out of a fixture nobody controls.
 *
 * The layout detail this rests on: `buildMinimalPE64` writes `sizeOfRawData` as
 * the section's own `data.length`, NOT the file-aligned length, so
 * `HexView`'s `sectionBytes` window is exactly this array and the zero padding
 * up to file alignment is outside anything the scan sees. Were that not so, the
 * boundary fixtures below would be off by however much padding landed in the
 * window and neither side of the cap could be pinned.
 */
function renderFilled(occurrences: number) {
  const data = new Uint8Array(occurrences).fill(0xaa);
  const pe = parsePE(
    buildMinimalPE64({
      imageBase: IMAGE_BASE,
      sections: [
        {
          name: ".fill",
          virtualAddress: FILL_VA,
          virtualSize: data.length,
          data,
          characteristics: 0x40000040, // INITIALIZED_DATA | MEM_READ
        },
      ],
    }),
  );
  render(
    <AppHarness
      state={stateWithPE(pe, { currentAddress: IMAGE_BASE + FILL_VA })}
      dispatch={vi.fn()}
    >
      <HexView />
    </AppHarness>,
  );
  return { user: userEvent.setup() };
}

describe("HexView section selector", () => {
  it("offers every section with its raw size", () => {
    const { pe } = renderHex();
    const options = Array.from(sectionSelect().options).map((o) => o.textContent);
    expect(options).toEqual(
      pe.sections.map((s) => `${s.name} (0x${s.sizeOfRawData.toString(16)})`),
    );
  });

  it("selects the section containing the current address", () => {
    renderHex({ currentAddress: IMAGE_BASE + RDATA_VA });
    expect(sectionSelect().value).toBe(".rdata");
  });

  it("falls back to the first section for an address in none of them", () => {
    // Deliberate: an address outside every section still has to show something,
    // and `sectionInfo` ends `return pe.sections[0] ?? null`.
    const { pe } = renderHex({ currentAddress: IMAGE_BASE + 0xf00000 });
    expect(sectionSelect().value).toBe(pe.sections[0].name);
  });

  it("navigates to a section's virtual address when picked", async () => {
    const { dispatch, pe, user } = renderHex();
    await user.selectOptions(sectionSelect(), ".text");
    const text = pe.sections.find((s) => s.name === ".text");
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: pe.optionalHeader.imageBase + (text?.virtualAddress ?? 0),
    });
  });
});

describe("HexView byte search", () => {
  it("counts occurrences of a literal byte pattern", async () => {
    // "Pa" of the fixture's one export name, which parsePE puts in .rdata.
    const { user } = renderHex();
    await user.type(byteSearchBox(), "50 61");
    expect(await screen.findByText("1 match in .rdata")).toBeTruthy();
  });

  it("uses the singular for one and the plural otherwise", async () => {
    const { user } = renderHex();
    // 0x00 occurs many times in an export directory.
    await user.type(byteSearchBox(), "00 00");
    const label = await screen.findByText(/ matches in \.rdata$/);
    expect(label.textContent).toMatch(/^\d+ matches in \.rdata$/);
    expect(Number(/^(\d+)/.exec(label.textContent ?? "")?.[1])).toBeGreaterThan(1);
  });

  it("honours a ?? wildcard", async () => {
    const { user } = renderHex();
    // "P?rseHeader" — the wildcard has to match 'a' for this to find anything,
    // which is the whole of parseBytePattern's wildcard branch.
    await user.type(byteSearchBox(), "50 ?? 72 73 65");
    expect(await screen.findByText("1 match in .rdata")).toBeTruthy();
  });

  it("says so when a well-formed pattern matches nothing", async () => {
    const { user } = renderHex();
    await user.type(byteSearchBox(), "DE AD BE EF");
    expect(await screen.findByText("No matches in .rdata")).toBeTruthy();
  });

  it("stays silent for a pattern it cannot parse", async () => {
    const { user } = renderHex();
    // Not "no matches" — the input is not a byte pattern at all, and claiming
    // the file lacks it would be a different and false statement.
    await user.type(byteSearchBox(), "zz");
    expect(screen.queryByText(/^No matches/)).toBeNull();
    expect(screen.queryByText(/match/)).toBeNull();
  });

  it("clears the report when the box is emptied", async () => {
    const { user } = renderHex();
    await user.type(byteSearchBox(), "50 61");
    expect(await screen.findByText("1 match in .rdata")).toBeTruthy();
    await user.clear(byteSearchBox());
    expect(screen.queryByText(/match/)).toBeNull();
  });
});

describe("HexView byte search cap", () => {
  /**
   * BOTH SIDES OF THE BOUNDARY, which is the whole point of these two rows.
   *
   * `peek-a-bin-dhcx` found this exact off-by-one one reader over: a
   * `ResourceTree` holding EXACTLY its budget claimed to be short over a
   * complete answer. So `truncated` is "a match beyond the cap exists", not
   * "we collected the cap" — and the negative control for that is to spell it
   * `offsets.length >= MAX_BYTE_PATTERN_MATCHES`, which reddens the
   * exactly-at-the-cap row below while leaving the over-the-cap one green.
   */
  it("admits the cap when the scan stopped short of the section", async () => {
    const { user } = renderFilled(MAX_BYTE_PATTERN_MATCHES + 1);
    await user.type(byteSearchBox(), FILL_BYTE);
    expect(
      await screen.findByText(
        `${MAX_BYTE_PATTERN_MATCHES}+ matches in .fill ` +
          `(search stopped at ${MAX_BYTE_PATTERN_MATCHES})`,
      ),
    ).toBeTruthy();
  });

  it("reports exactly the cap as a plain, whole count", async () => {
    const { user } = renderFilled(MAX_BYTE_PATTERN_MATCHES);
    await user.type(byteSearchBox(), FILL_BYTE);
    // A result of exactly the cap's size IS the complete answer.
    expect(await screen.findByText(`${MAX_BYTE_PATTERN_MATCHES} matches in .fill`)).toBeTruthy();
    expect(screen.queryByText(/search stopped at/)).toBeNull();
    expect(screen.queryByText(/\+ matches/)).toBeNull();
  });

  it("reports an ordinary count with no admission", async () => {
    const { user } = renderFilled(3);
    await user.type(byteSearchBox(), FILL_BYTE);
    expect(await screen.findByText("3 matches in .fill")).toBeTruthy();
    expect(screen.queryByText(/search stopped at/)).toBeNull();
  });
});

describe("HexView byte search scope", () => {
  /**
   * The scan runs over `sectionBytes` — ONE section — so an unscoped count reads
   * as a fact about the FILE. `peek-a-bin-2py5`'s `stringScan` shape at much
   * smaller stakes.
   */
  it("names the searched section in the affordance and in the count", async () => {
    // `.text` in the harness fixture is four `CC` bytes, so the count is known.
    const { user } = renderHex({ currentAddress: IMAGE_BASE + 0x1000 });
    expect(sectionSelect().value).toBe(".text");
    expect(screen.getByLabelText("Byte search in .text")).toBe(byteSearchBox());
    await user.type(byteSearchBox(), "CC");
    expect(await screen.findByText("4 matches in .text")).toBeTruthy();
  });

  it("follows the selected section rather than naming one of them always", () => {
    renderHex({ currentAddress: IMAGE_BASE + RDATA_VA });
    expect(screen.getByLabelText("Byte search in .rdata")).toBe(byteSearchBox());
  });
});

describe("HexView go to offset", () => {
  it("treats a small value as an offset into the section", async () => {
    const { dispatch, pe, user } = renderHex();
    const rdata = pe.sections.find((s) => s.name === ".rdata");
    const base = pe.optionalHeader.imageBase + (rdata?.virtualAddress ?? 0);
    await user.type(gotoBox(), "10{Enter}");
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: base + 0x10 });
  });

  it("treats a value at or above the section base as an absolute address", async () => {
    const { dispatch, user } = renderHex();
    const absolute = IMAGE_BASE + RDATA_VA + 0x20;
    await user.type(gotoBox(), `${absolute.toString(16)}{Enter}`);
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: absolute });
  });

  it("clears the box after a jump but ignores a non-number", async () => {
    const { dispatch, user } = renderHex();
    await user.type(gotoBox(), "10{Enter}");
    expect((gotoBox() as HTMLInputElement).value).toBe("");
    await user.type(gotoBox(), "zz{Enter}");
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect((gotoBox() as HTMLInputElement).value).toBe("zz");
  });
});

describe("HexView toolbar toggles", () => {
  it("returns to the disassembly at the current address", async () => {
    const { dispatch, user } = renderHex({ currentAddress: IMAGE_BASE + RDATA_VA });
    await user.click(screen.getByText("Disasm"));
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: IMAGE_BASE + RDATA_VA,
    });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });

  it("marks the entropy toggle as on once pressed", async () => {
    const { user } = renderHex();
    const toggle = screen.getByText("Entropy");
    expect(toggle.className).not.toContain("bg-blue-600");
    await user.click(toggle);
    // The strip itself computes nothing here — see the file docstring — so this
    // is the toggle's own state and NOT evidence that a strip was drawn.
    expect(screen.getByText("Entropy").className).toContain("bg-blue-600");
  });
});

describe("HexView column header", () => {
  it("labels all sixteen byte columns", () => {
    renderHex();
    expect(screen.getByText("Offset")).toBeTruthy();
    expect(screen.getByText("ASCII")).toBeTruthy();
    const cols = (screen.getByText(/^00 01 02/).textContent ?? "").split(/\s+/);
    expect(cols).toHaveLength(16);
    expect(cols[cols.length - 1]).toBe("0F");
  });
});

describe("HexView without data", () => {
  it("says so rather than rendering an empty grid", () => {
    render(
      <AppHarness state={{ ...stateWithPE(harnessPE()), peFile: null }} dispatch={vi.fn()}>
        <HexView />
      </AppHarness>,
    );
    expect(screen.getByText("No section data to display.")).toBeTruthy();
  });
});

describe("HexView virtualized grid", () => {
  it("renders no byte rows under jsdom, which is the tool and not the code", () => {
    // Asserted so the scope note at the top of this file cannot rot: if rows
    // start appearing — a fabricated container height, or a move away from
    // virtualization — this fails and the note needs rewriting. It is NOT a
    // claim that rows should be absent in a browser.
    const { container } = renderHex();
    const rows = container.querySelectorAll("[data-index]");
    expect(rows).toHaveLength(0);
    // The header row is present and is not one of them.
    expect(screen.getByText("Offset")).toBeTruthy();
  });
});
