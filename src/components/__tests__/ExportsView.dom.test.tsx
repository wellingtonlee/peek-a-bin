// @vitest-environment jsdom

import "../../test/domSetup";
import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AppState } from "../../hooks/usePEFile";
import type { ExportDirDef } from "../../pe/__tests__/fixtures";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
import { stubLayoutRect } from "../../test/domSetup";
import { ExportsView } from "../ExportsView";
import { AppHarness, stateWithPE } from "./appStateHarness";

/**
 * THE EXPORTS TAB, rendered for the first time.
 *
 * Fourth name in `PARSER_DERIVED_TABS`. It is also the only one of the four
 * parser-derived tabs covered by this session that is **virtualized**, and that
 * changes what a green run here means.
 *
 * VIRTUALIZATION IS A STAND-IN, AND THIS SUITE'S ROWS EXIST ONLY BECAUSE OF IT.
 * The row list is a `useVirtualizer` over a `flex-1 overflow-auto` div.
 * `virtual-core` computes its range from the scroll element's `offsetHeight` —
 * NOT `getBoundingClientRect` — and jsdom does no layout, so unstubbed that is 0
 * and the list renders ZERO rows: not a short list, an empty one.
 * {@link stubLayoutRect} is therefore called at the top level here, and its own
 * docstring is the honest statement of the cost.
 *
 * WHAT THE ASSERTIONS BELOW CAN AND CANNOT SEE:
 *
 *  - **CAN**: which exports are in the row list and in what ORDER, what each row
 *    says, which control is in which sort state, what a click dispatches. Every
 *    fixture here has few enough exports (at most six) to fall inside one window
 *    at the stubbed height, so "the rows in the document" and "the rows the
 *    filter/sort produced" are the same set — checked by asserting the row count
 *    equals the expected match count, not merely that some row exists.
 *  - **CANNOT**: anything about windowing or scrolling. Every element reports the
 *    same rect, `scrollTop` is permanently 0 and the stub `ResizeObserver` never
 *    fires, so the range is computed once from offset 0 and never moves. Whether
 *    `overscan: 20` is right, whether a 4000-export DLL scrolls, and whether ANY
 *    row is visible are unanswered. A row in the document is not a row on screen.
 *    In particular no assertion here would notice a virtualizer that renders the
 *    first N rows and then stops.
 *
 * THAT BLIND SPOT IS MEASURED, not argued. Two perturbations of the virtualizer
 * itself — `estimateSize: () => 28` to 280, and `overscan: 20` to 0 — leave this
 * whole suite GREEN. Both are real behaviour changes in a browser (row height,
 * how far ahead the window reaches) and neither is observable here, because with
 * every element reporting the same 600px rect and `scrollTop` pinned at 0 the
 * range covers the entire fixture whatever those two numbers are. Reported
 * rather than tuned away: making them discriminate would mean fabricating a
 * scroll position no browser produced.
 *
 * THE FIXTURE EXPRESSES EVERY EXPORT SHAPE THIS VIEW BRANCHES ON, so nothing had
 * to be hand-constructed: `addresses: [n, …]` for an ordinary export,
 * `{ forwarder: "OTHER.Func" }` for a forwarded one (the builder emits the
 * string inside the directory's declared extent, which is what makes the parser
 * read it as a forwarder), and a slot with no entry in `names` for an
 * ordinal-only export.
 */

stubLayoutRect({ height: 600 });

/**
 * Ordinals 1..4. Slot 0 and slot 3 are ordinary code exports, slot 1 is a
 * forwarder, slot 2 is named but at a lower address than slot 0 — so sorting by
 * name, by ordinal and by address each produce a DIFFERENT order, which is what
 * makes the comparator tests discriminate.
 */
const EXPORTS: ExportDirDef = {
  dllName: "sample.dll",
  addresses: [0x2400, { forwarder: "OTHER.Func" }, 0x1200, 0x3000],
  names: [
    { name: "Zebra", addressIndex: 0 },
    { name: "Aardvark", addressIndex: 1 },
    { name: "Mongoose", addressIndex: 2 },
    // slot 3 gets no name -> an ordinal-only export
  ],
};

function renderExports(pe: PEFile, over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  const view = render(
    <AppHarness state={stateWithPE(pe, over)} dispatch={dispatch}>
      <ExportsView />
    </AppHarness>,
  );
  return { ...view, dispatch, user: userEvent.setup() };
}

/** One row per virtual item, in render order. */
function rows(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll("div.absolute")) as HTMLElement[];
}

/** Each row as `[ordinal, name, address]`. */
function rowCells(container: HTMLElement): string[][] {
  return rows(container).map((r) =>
    Array.from(r.children).map((c) => (c.textContent ?? "").replace(/\s+/g, " ").trim()),
  );
}

const names = (container: HTMLElement) => rowCells(container).map((c) => c[1]);

function setFilter(text: string) {
  fireEvent.change(screen.getByPlaceholderText("Filter..."), { target: { value: text } });
}

describe("ExportsView listing", () => {
  const pe = () => parsePE(buildMinimalPE64({ directories: { exports: EXPORTS } }));

  it("counts the exports in its heading and renders one row each", () => {
    const parsed = pe();
    const { container } = renderExports(parsed);
    expect(screen.getByText("Exports (4)")).toBeTruthy();
    // Row count against the parse, so a virtualizer that silently windowed some
    // of them away would fail here rather than pass on a partial list.
    expect(rows(container)).toHaveLength(parsed.exports.length);
    expect(rows(container)).toHaveLength(4);
  });

  it("prints ordinal, name and VA — the VA being image base plus RVA", () => {
    const parsed = pe();
    const { container } = renderExports(parsed);
    const byName = new Map(rowCells(container).map((c) => [c[1], c]));
    const zebra = parsed.exports.find((e) => e.name === "Zebra");
    if (!zebra) throw new Error("fixture lost Zebra");
    expect(byName.get("Zebra")).toEqual([
      String(zebra.ordinal),
      "Zebra",
      // 0x140000000 + 0x2400. Uppercase, unpadded, and NOT reduced mod 2^32 —
      // the Headers tab had exactly that defect one tab over.
      `0x${(parsed.optionalHeader.imageBase + zebra.address).toString(16).toUpperCase()}`,
    ]);
    expect(byName.get("Zebra")?.[2]).toBe("0x140002400");
  });

  it("spells a forwarded export with an arrow and refuses to offer a jump", () => {
    const { container } = renderExports(pe());
    const row = rowCells(container).find((c) => c[1].startsWith("Aardvark"));
    // The name cell carries `name → target`; the address cell says "forwarded"
    // because a forwarder's "address" is an RVA into the export directory's
    // string blob, not code.
    expect(row?.[1]).toBe("Aardvark → OTHER.Func");
    expect(row?.[2]).toBe("forwarded");
    const forwardedRow = rows(container).find((r) => r.textContent?.includes("forwarded"));
    expect(forwardedRow?.querySelector("button")).toBeNull();
  });

  it("names an ordinal-only export and marks it as one", () => {
    const parsed = pe();
    const { container } = renderExports(parsed);
    // The parser's own spelling for a slot with no name-table entry. Slot 3 is
    // ordinal 4 under the default Base of 1.
    const row = rows(container).find((r) => r.textContent?.includes("Ordinal#4"));
    expect(row).toBeTruthy();
    expect(parsed.exports.find((e) => e.byOrdinal)?.ordinal).toBe(4);
    // `byOrdinal` drives the italic/dim styling — asserted on the class because
    // there is no other channel, and NOT read as a claim that it looks dim:
    // Tailwind is not loaded here, so the class carries no computed style.
    expect(row?.children[1].className).toContain("italic");
  });

  it("honours a non-default ordinal base", () => {
    const { container } = renderExports(
      parsePE(
        buildMinimalPE64({
          directories: { exports: { ...EXPORTS, ordinalBase: 100 } },
        }),
      ),
    );
    // Base 100 -> slot 0 is ordinal 100. A component printing the slot index
    // rather than the ordinal would show 0..3 here and be right by accident in
    // every other test.
    expect(
      rowCells(container)
        .map((c) => c[0])
        .sort(),
    ).toEqual(["100", "101", "102", "103"]);
  });

  it("navigates to an export's VA and switches to the disassembly tab", async () => {
    const parsed = parsePE(buildMinimalPE64({ directories: { exports: EXPORTS } }));
    const { dispatch, user } = renderExports(parsed);
    await user.click(screen.getByRole("button", { name: "0x140002400" }));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140002400 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
  });

  it("renders the same shapes in a PE32 image", () => {
    // Export parsing is width-independent (every table in the directory is
    // 4-byte), but the VA column is `imageBase + rva` and the base differs, so
    // this is the pair that shows the column is not hard-coded.
    const { container } = renderExports(
      parsePE(buildMinimalPE32({ directories: { exports: EXPORTS } })),
    );
    expect(rows(container)).toHaveLength(4);
    expect(rowCells(container).find((c) => c[1] === "Zebra")?.[2]).toBe("0x402400");
  });
});

describe("ExportsView sorting", () => {
  const pe = () => parsePE(buildMinimalPE64({ directories: { exports: EXPORTS } }));

  it("starts sorted by ordinal ascending and says so", () => {
    const { container } = renderExports(pe());
    expect(screen.getByRole("button", { name: /^Ordinal/ }).textContent).toBe("Ordinal ▲");
    expect(screen.getByRole("button", { name: /^Name/ }).textContent).toBe("Name");
    expect(rowCells(container).map((c) => c[0])).toEqual(["1", "2", "3", "4"]);
  });

  it("re-orders the rows when sorted by name — the ORDER, not just the header", async () => {
    const { container, user } = renderExports(pe());
    const before = names(container);
    await user.click(screen.getByRole("button", { name: /^Name/ }));
    const after = names(container);
    // The claim a comparator bug breaks: the rows actually moved, and moved to
    // the order `localeCompare` gives. "Ordinal#4" sorts under 'O'.
    expect(after).not.toEqual(before);
    expect(after).toEqual(["Aardvark → OTHER.Func", "Mongoose", "Ordinal#4", "Zebra"]);
    expect(screen.getByRole("button", { name: /^Name/ }).textContent).toBe("Name ▲");
  });

  it("reverses on a second click of the same column", async () => {
    const { container, user } = renderExports(pe());
    const nameButton = () => screen.getByRole("button", { name: /^Name/ });
    await user.click(nameButton());
    await user.click(nameButton());
    expect(nameButton().textContent).toBe("Name ▼");
    expect(names(container)).toEqual(["Zebra", "Ordinal#4", "Mongoose", "Aardvark → OTHER.Func"]);
  });

  it("resets to ascending when switching column, rather than keeping the direction", async () => {
    const { container, user } = renderExports(pe());
    // Descending on Name...
    await user.click(screen.getByRole("button", { name: /^Name/ }));
    await user.click(screen.getByRole("button", { name: /^Name/ }));
    // ...then Ordinal must come back up ascending, not inherit "desc".
    await user.click(screen.getByRole("button", { name: /^Ordinal/ }));
    expect(screen.getByRole("button", { name: /^Ordinal/ }).textContent).toBe("Ordinal ▲");
    expect(screen.getByRole("button", { name: /^Name/ }).textContent).toBe("Name");
    expect(rowCells(container).map((c) => c[0])).toEqual(["1", "2", "3", "4"]);
  });

  it("sorts by address on the RVA, which is a third distinct order", async () => {
    const { container, user } = renderExports(pe());
    await user.click(screen.getByRole("button", { name: /^VA/ }));
    // RVAs are 0x2400 (Zebra), the forwarder's string RVA, 0x1200 (Mongoose),
    // 0x3000 (Ordinal#4). Mongoose is below Zebra, so an address sort is neither
    // the ordinal order nor the name order — which is what makes this a test of
    // the comparator and not of the click handler.
    expect(names(container)).not.toEqual([
      "Zebra",
      "Aardvark → OTHER.Func",
      "Mongoose",
      "Ordinal#4",
    ]);
    const parsed = pe();
    const expected = [...parsed.exports]
      .sort((a, b) => a.address - b.address)
      .map((e) => (e.forwarder ? `${e.name} → ${e.forwarder}` : e.name));
    expect(names(container)).toEqual(expected);
  });
});

describe("ExportsView filter", () => {
  const pe = () => parsePE(buildMinimalPE64({ directories: { exports: EXPORTS } }));

  it("debounces by 250 ms, then narrows by name", () => {
    // Same two measured facts as `ImportsView.dom.test.tsx`: `waitFor` and
    // `userEvent` both deadlock under vitest's fake timers, so the clock is
    // advanced inside `act()` and the field is driven with `fireEvent.change`.
    vi.useFakeTimers();
    try {
      const { container } = renderExports(pe());
      setFilter("moon");
      expect(rows(container)).toHaveLength(4);
      // Short of the delay, then over it — see the note in
      // `ImportsView.dom.test.tsx`: a single advance past 250 cannot tell a
      // 250 ms debounce from a 0 ms one.
      act(() => void vi.advanceTimersByTime(240));
      expect(rows(container)).toHaveLength(4);
      act(() => void vi.advanceTimersByTime(10));
      expect(rows(container)).toHaveLength(0);
      expect(screen.getByText("No exports match the filter.")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("matches a forwarder's TARGET, not only the export's own name", () => {
    vi.useFakeTimers();
    try {
      const { container } = renderExports(pe());
      setFilter("other.func");
      act(() => void vi.advanceTimersByTime(250));
      expect(names(container)).toEqual(["Aardvark → OTHER.Func"]);
      expect(screen.getByText("1 match")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("matches an address typed as hex", () => {
    vi.useFakeTimers();
    try {
      const { container } = renderExports(pe());
      setFilter("140002400");
      act(() => void vi.advanceTimersByTime(250));
      expect(names(container)).toEqual(["Zebra"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("matches an ordinal, on a string that can match nothing else", () => {
    // SHARPENED AFTER AN INERT CONTROL: with the default Base of 1, deleting the
    // ordinal arm of the filter left the suite green, because "4" also occurs in
    // the name "Ordinal#4" and in every VA's hex. An ordinal base of 7000 gives
    // ordinals 7000..7003 while the names stay Zebra/Aardvark/Mongoose and the
    // VAs stay 0x1400…, so "7001" can only be matched by the ordinal arm.
    vi.useFakeTimers();
    try {
      const parsed = parsePE(
        buildMinimalPE64({ directories: { exports: { ...EXPORTS, ordinalBase: 7000 } } }),
      );
      const { container } = renderExports(parsed);
      setFilter("7001");
      act(() => void vi.advanceTimersByTime(250));
      expect(names(container)).toEqual(["Aardvark → OTHER.Func"]);
      expect(rowCells(container)[0][0]).toBe("7001");
      // The string really is unmatchable elsewhere, so the assertion above is
      // about the ordinal arm and not about a coincidence.
      expect(
        parsed.exports.filter(
          (e) =>
            e.name.includes("7001") ||
            (e.forwarder ?? "").includes("7001") ||
            (parsed.optionalHeader.imageBase + e.address).toString(16).includes("7001"),
        ),
      ).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("ExportsView with nothing to show", () => {
  it("says so, distinctly from a filter that matched nothing", () => {
    // The empty state that must not throw: a resource-only DLL exports nothing,
    // and `analysisNotice`'s "no-code-section" prose sends the user to this tab.
    const { container } = renderExports(parsePE(buildMinimalPE64()));
    expect(screen.getByText("Exports (0)")).toBeTruthy();
    expect(screen.getByText("No exports found in this binary.")).toBeTruthy();
    expect(screen.queryByText("No exports match the filter.")).toBeNull();
    // The sort header is withheld with the list, so there is nothing to click.
    expect(screen.queryByRole("button", { name: /^Ordinal/ })).toBeNull();
    expect(rows(container)).toHaveLength(0);
  });

  it("renders nothing at all with no PE loaded", () => {
    const { container } = render(
      <AppHarness state={stateWithPE(null as unknown as PEFile)} dispatch={vi.fn()}>
        <ExportsView />
      </AppHarness>,
    );
    expect(container.innerHTML).toBe("");
  });
});
