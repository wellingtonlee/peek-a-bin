// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AppState } from "../../hooks/usePEFile";
import type { SectionDef } from "../../pe/__tests__/fixtures";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
import { SectionTable } from "../SectionTable";
import { AppHarness, stateWithPE } from "./appStateHarness";

/**
 * THE SECTIONS TAB, rendered for the first time.
 *
 * `sections` is the second name in `PARSER_DERIVED_TABS`, so `analysisNotice()`
 * sends a user here whenever there is no code to disassemble — and nothing had
 * ever rendered it.
 *
 * NOT VIRTUALIZED, and no worker. It is a plain `<table>`, so every section is
 * a row in the document; and every fixture here is ~1.5 KB, far under
 * `MAX_SYNC_FILE_METRIC_BYTES` (1 MiB), so `useFileMetrics` takes its
 * synchronous arm and the Entropy column is populated on the FIRST render with
 * no worker involved. That is why the entropy assertions below can be plain
 * `expect`s rather than `waitFor`s. `stubLayoutRect` is deliberately not called
 * — nothing here is a claim about geometry or visibility.
 *
 * ONE FINDING WORTH REPORTING FOR NOT BEING A DEFECT. CLAUDE.md records that the
 * `.text`-or-executable predicate had been hand-written at seven sites before
 * `pe/sections.ts` was made its one declaration, and warns about a tenth copy of
 * the `characteristics & 0x20000000` test. `SectionTable` does NOT re-roll it:
 * it imports `sectionCharacteristicsToString` from `pe/constants.ts` and prints
 * that string verbatim. The literal expectations below are therefore an
 * end-to-end check of the shared decoder as it reaches the page, not of a
 * private copy.
 *
 * WHAT IS NOT COVERED: the two loading arms of the Entropy cell ("computing…"
 * and "unavailable"), which need an input over the 1 MiB threshold and a worker
 * that answers; `asyncMetricState.test.ts` covers the state machine behind them.
 */

const SECTIONS: SectionDef[] = [
  {
    name: ".text",
    virtualAddress: 0x1000,
    virtualSize: 0x1234,
    // Uniform bytes: entropy 0, which is the `< 1.0` classification band.
    data: new Uint8Array(64).fill(0xcc),
    characteristics: 0x60000020, // CODE | EXECUTE | READ
  },
  {
    name: ".data",
    virtualAddress: 0x3000,
    virtualSize: 0x40,
    data: new Uint8Array(64).fill(0xab),
    characteristics: 0xc0000040, // INITIALIZED_DATA | READ | WRITE
  },
  {
    name: ".rsrc",
    virtualAddress: 0x4000,
    virtualSize: 0x10,
    // 64 distinct byte values: entropy 6.0, the `< 6.5` "normal - code" band.
    data: new Uint8Array(64).map((_, i) => i),
    characteristics: 0x42000040, // INITIALIZED_DATA | READ | DISCARDABLE
  },
];

function renderSections(pe: PEFile, over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  const view = render(
    <AppHarness state={stateWithPE(pe, over)} dispatch={dispatch}>
      <SectionTable />
    </AppHarness>,
  );
  return { ...view, dispatch, user: userEvent.setup() };
}

/** The `<tr>`s under the header, in render order. */
function bodyRows(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll("tbody tr")) as HTMLElement[];
}

/** One row's cells as trimmed strings. */
function cells(row: HTMLElement): string[] {
  return Array.from(row.querySelectorAll("td")).map((td) =>
    (td.textContent ?? "").replace(/\s+/g, " ").trim(),
  );
}

describe("SectionTable columns", () => {
  it("prints one row per section, in file order, with every numeric cell in hex", () => {
    const pe = parsePE(buildMinimalPE32({ sections: SECTIONS }));
    const { container } = renderSections(pe);
    expect(screen.getByText("Section Table")).toBeTruthy();
    const rows = bodyRows(container);
    expect(rows).toHaveLength(3);
    expect(rows).toHaveLength(pe.sections.length);

    // Every value is checked against the PARSED header rather than against the
    // SectionDef above, so an endianness or field-order slip in the 40-byte
    // section header shows up here and not only in the parser's own suite.
    const text = pe.sections[0];
    expect(cells(rows[0]).slice(0, 5)).toEqual([
      ".text",
      `0x${text.virtualSize.toString(16).toUpperCase()}`,
      `0x${text.virtualAddress.toString(16).toUpperCase()}`,
      `0x${text.sizeOfRawData.toString(16).toUpperCase()}`,
      `0x${text.pointerToRawData.toString(16).toUpperCase()}`,
    ]);
    // Spelled out once, so a change to the `0x%X` convention itself fails and
    // not only a mismatch with the parser.
    expect(cells(rows[0]).slice(0, 5)).toEqual([".text", "0x1234", "0x1000", "0x40", "0x200"]);
    expect(cells(rows[1])[0]).toBe(".data");
    expect(cells(rows[2])[0]).toBe(".rsrc");
  });

  it("decodes the characteristics word through the shared table, bit for bit", () => {
    const { container } = renderSections(parsePE(buildMinimalPE32({ sections: SECTIONS })));
    const decoded = bodyRows(container).map((r) => {
      const c = cells(r);
      return c[c.length - 1];
    });
    // `sectionCharacteristicsToString`'s own order, which is the shared
    // declaration's insertion order and not the bit order: content flags, then
    // X/R/W, then DISCARD/SHARED/COMDAT. 0x20000000 is IMAGE_SCN_MEM_EXECUTE —
    // the predicate CLAUDE.md warns about a tenth hand-written copy of — and it
    // must produce "X" on `.text` and on nothing else here.
    expect(decoded).toEqual([
      "0x60000020 CODE | X | R",
      "0xC0000040 INIT_DATA | R | W",
      "0x42000040 INIT_DATA | R | DISCARD",
    ]);
    expect(decoded.filter((d) => d?.includes(" X ")).length).toBe(1);
  });

  it("computes and classifies per-section entropy on the first render", () => {
    const { container } = renderSections(parsePE(buildMinimalPE32({ sections: SECTIONS })));
    const entropy = bodyRows(container).map((r) => cells(r)[5]);
    // Uniform bytes -> 0.00 -> "empty"; 64 distinct values -> 6.00 ->
    // "normal - code". Two different bands, so a `classifyEntropy` threshold
    // moving is visible and not just a missing number.
    expect(entropy[0]).toBe("0.00 empty");
    expect(entropy[1]).toBe("0.00 empty");
    expect(entropy[2]).toBe("6.00 normal - code");
    // Neither loading arm may be on screen: this input is under the sync
    // threshold, so a worker round trip here would be the regression
    // `fileMetricsOffThread.test.ts` guards statically.
    expect(container.textContent).not.toContain("computing");
    expect(container.textContent).not.toContain("unavailable");
  });
});

describe("SectionTable active row and navigation", () => {
  it("highlights the section containing the current address, and only that one", () => {
    const pe = parsePE(buildMinimalPE32({ sections: SECTIONS }));
    const base = pe.optionalHeader.imageBase;
    // Inside `.data`: [0x3000, 0x3040).
    const { container } = renderSections(pe, { currentAddress: base + 0x3010 });
    const highlighted = bodyRows(container).map((r) => r.className.includes("bg-blue-900/30"));
    expect(highlighted).toEqual([false, true, false]);
  });

  it("highlights on the VIRTUAL extent, not the raw one", () => {
    // `.text` declares VirtualSize 0x1234 over 0x40 bytes of raw data — the
    // ordinary shape for a section with a zero-filled tail. 0x1100 is inside the
    // virtual extent and far past the raw one, so this is the row that separates
    // the two readings.
    //
    // ADDED BECAUSE A CONTROL WAS INERT: perturbing the extent test to
    // `sizeOfRawData` left the suite green, since in the fixture above `.data`'s
    // two sizes happen to be equal and no assertion looked at a section where
    // they differ. Sharpened rather than dropped.
    const pe = parsePE(buildMinimalPE32({ sections: SECTIONS }));
    const { container } = renderSections(pe, {
      currentAddress: pe.optionalHeader.imageBase + 0x1100,
    });
    expect(pe.sections[0].sizeOfRawData).toBeLessThan(0x1100);
    expect(bodyRows(container).map((r) => r.className.includes("bg-blue-900/30"))).toEqual([
      true,
      false,
      false,
    ]);
  });

  it("highlights nothing when the current address is in no section", () => {
    const pe = parsePE(buildMinimalPE32({ sections: SECTIONS }));
    // Past `.rsrc`'s virtual extent, and the comparison is on the RVA, so a
    // component that forgot to subtract the image base would highlight a row.
    const { container } = renderSections(pe, {
      currentAddress: pe.optionalHeader.imageBase + 0x9000,
    });
    expect(bodyRows(container).some((r) => r.className.includes("bg-blue-900/30"))).toBe(false);
  });

  it("navigates to a section's VA — image base plus RVA — and switches tab", async () => {
    const pe = parsePE(buildMinimalPE64({ sections: SECTIONS }));
    const { container, dispatch, user } = renderSections(pe);
    await user.click(bodyRows(container)[2]);
    expect(dispatch).toHaveBeenCalledWith({
      type: "SET_ADDRESS",
      address: pe.optionalHeader.imageBase + 0x4000,
    });
    // 0x140000000 + 0x4000, i.e. the 64-bit base is NOT reduced mod 2^32 on the
    // way through — the same class of defect the Headers tab had.
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140004000 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });
});

describe("SectionTable with almost nothing to show", () => {
  it("renders the header row and one section for a single-section image", () => {
    // The floor of what `analysisNotice`'s "no-code-section" prose promises: the
    // tab must be populated, not empty and not thrown.
    const { container } = renderSections(parsePE(buildMinimalPE64()));
    expect(bodyRows(container)).toHaveLength(1);
    expect(cells(bodyRows(container)[0])[0]).toBe(".text");
    expect(within(container).getByText("Characteristics")).toBeTruthy();
  });

  it("renders nothing at all with no PE loaded", () => {
    const { container } = render(
      <AppHarness state={stateWithPE(null as unknown as PEFile)} dispatch={vi.fn()}>
        <SectionTable />
      </AppHarness>,
    );
    expect(container.innerHTML).toBe("");
  });
});
