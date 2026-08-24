// @vitest-environment jsdom

import "../../test/domSetup";
import { act, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { DisasmFunction, Xref } from "../../disasm/types";
import { stubLayoutRect } from "../../test/domSetup";
import { XrefPanel } from "../XrefPanel";

/**
 * THE CROSS-REFERENCE PANEL, rendered for the first time. 329 lines with no
 * coverage of any kind; mounted from `DisassemblyView.tsx:1602` as the "Xrefs"
 * tab of `BottomPanelContainer`.
 *
 * WHY THE EMPTY STATE IS NOT A CORNER CASE. Xref building is the LAST stage of
 * the analysis chain, which is the whole reason `analysisNotice`'s
 * `"analysis-timed-out"` kind carries an EMPTY `unavailableTabs` — a timeout in
 * `buildAllXrefs` leaves a complete function list and a complete disassembly
 * with only the xrefs missing. So a user reaching this panel with nothing in it
 * is an ordinary outcome, and the two distinct empty messages ("none exist" vs
 * "none match your filters") are the only thing telling those apart.
 *
 * WHAT THE VIRTUALIZATION MEANS HERE, and it is the most important caveat in the
 * file. `@tanstack/react-virtual` renders ZERO rows unless its scroll container
 * reports a non-zero `offsetHeight` — not a short list, an empty one — so
 * `stubLayoutRect` below is what makes any row assertion possible at all. Read
 * its docstring: **it does not make virtualization real.** Every element reports
 * 600px, `scrollTop` is permanently 0, and the stub `ResizeObserver` never
 * fires, so the virtual range is computed once from offset 0 and never moves.
 *
 * Concretely, the assertions below CAN see: which rows the filters, the scope
 * and the sort put at the head of the list, their content, and what happens when
 * one is clicked. They CANNOT see: anything past the first window (~28 rows at
 * 22px in 600px, plus `overscan: 30`), whether scrolling works, whether a row is
 * on screen, or whether the 22px `estimateSize` matches the rendered row. Every
 * fixture below is small enough to fit in one window on purpose, so no
 * assertion depends on the window's size — and the row-count assertions are
 * written against the fixture's own totals, which the header count
 * independently states.
 *
 * WAS: this file built a whole `PEFile` (`buildMinimalPE64` + `parsePE`) to
 * satisfy a required `pe` prop the component never destructured and never read.
 * The prop is gone; there is no test for its absence because there cannot be
 * one — the typechecker rejects a `pe={…}` at the mount site, which is the only
 * way the prop could come back.
 */

stubLayoutRect({ height: 600 });

const BASE = 0x140001000;
const MAIN: DisasmFunction = { name: "main", address: BASE, size: 0x20 };
const HELPER: DisasmFunction = { name: "helper", address: BASE + 0x20, size: 0x20 };
const SORTED_FUNCS = [MAIN, HELPER];
const FUNC_MAP = new Map<number, DisasmFunction>([
  [MAIN.address, MAIN],
  [HELPER.address, HELPER],
]);

/** An address in no function at all, so its target column has no name. */
const DATA_ADDR = 0x140002000;

/**
 * Four xrefs of four distinct types, arranged so that sorting by `from`, by `to`
 * and by `type` each give a DIFFERENT order — otherwise a sort test proves
 * nothing.
 *
 *   from        type     to
 *   0x…1004     call     0x…1020 (helper)
 *   0x…1008     data     0x…2000 (no function)
 *   0x…1010     jmp      0x…1020 (helper)
 *   0x…1028     branch   0x…1000 (main)
 */
const TYPED_XREFS = new Map<number, Xref[]>([
  [
    HELPER.address,
    [
      { from: BASE + 0x04, type: "call" },
      { from: BASE + 0x10, type: "jmp" },
    ],
  ],
  [DATA_ADDR, [{ from: BASE + 0x08, type: "data" }]],
  [MAIN.address, [{ from: BASE + 0x28, type: "branch" }]],
]);

function renderPanel(over: Partial<Parameters<typeof XrefPanel>[0]> = {}) {
  const onNavigate = vi.fn();
  const onClose = vi.fn();
  const result = render(
    <XrefPanel
      typedXrefMap={TYPED_XREFS}
      funcMap={FUNC_MAP}
      sortedFuncs={SORTED_FUNCS}
      onNavigate={onNavigate}
      onClose={onClose}
      {...over}
    />,
  );
  return { ...result, onNavigate, onClose };
}

/** The clickable rows of the virtualized list, in rendered order. */
function rows(): HTMLElement[] {
  return Array.from(document.querySelectorAll("button.absolute"));
}
/** Each row's five columns, flattened to text. */
function rowTexts(): string[][] {
  return rows().map((r) => Array.from(r.children).map((c) => c.textContent ?? ""));
}
/** Just the "from" address column, which is what the default sort orders by. */
function fromColumn(): string[] {
  return rowTexts().map((c) => c[1]);
}
/**
 * The instruction-scope direction toggle, BY ITS ACCESSIBLE NAME. It used to be
 * found by its class: its visible text reads "To"/"From" and so did the sortable
 * "To" column header's, so a name query matched both and the workaround was the
 * only way to tell them apart. The component now carries an `aria-label` on
 * each, so the query that a user of the panel would make is the query this
 * helper makes — which is the point of fixing it rather than working around it.
 */
function directionToggle(): HTMLElement | null {
  return screen.queryByRole("button", { name: /^Reference direction:/ });
}

/** A sort header, by the name its `aria-label` gives it. */
function sortHeader(what: "type" | "from address" | "to address"): HTMLElement {
  return screen.getByRole("button", { name: new RegExp(`^Sort by ${what}`) });
}

describe("XrefPanel", () => {
  it("lists every xref, resolved to the functions at both ends", () => {
    renderPanel();
    expect(screen.getByText("Cross-References (4/4)")).toBeTruthy();
    // Default sort is by `from`, ascending. Each row is
    // [type, from, from-function, to, to-function].
    expect(rowTexts()).toEqual([
      ["call", "0x140001004", "main", "0x140001020", "helper"],
      ["data", "0x140001008", "main", "0x140002000", "---"],
      ["jmp", "0x140001010", "main", "0x140001020", "helper"],
      ["branch", "0x140001028", "helper", "0x140001000", "main"],
    ]);
  });

  it("writes '---' rather than an empty cell where an address has no function", () => {
    renderPanel();
    // 0x140002000 is past `helper`'s extent, so `binarySearchFunc` answers null.
    // A blank cell in a grid of addresses reads as a rendering failure.
    expect(rowTexts()[1][4]).toBe("---");
  });

  it("says NO XREFS EXIST when the map is empty", () => {
    renderPanel({ typedXrefMap: new Map() });
    // The state a `buildAllXrefs` timeout leaves behind, with everything else on
    // screen populated.
    expect(screen.getByText("No cross-references found.")).toBeTruthy();
    expect(screen.getByText("Cross-References (0/0)")).toBeTruthy();
    expect(rows()).toHaveLength(0);
  });

  it("says NONE MATCH — a different message — when the filters emptied a full list", () => {
    renderPanel();
    for (const t of ["call", "jmp", "branch", "data"]) {
      fireEvent.click(screen.getByRole("button", { name: t }));
    }
    // The distinction is the point: one of these means "the analysis produced
    // nothing", the other means "you hid it".
    expect(screen.getByText("No xrefs match the current filters.")).toBeTruthy();
    expect(screen.queryByText("No cross-references found.")).toBeNull();
    expect(screen.getByText("Cross-References (0/4)")).toBeTruthy();
  });

  describe("type filters", () => {
    it("starts with all four kinds enabled", () => {
      renderPanel();
      expect(rows()).toHaveLength(4);
    });

    it("removes just that kind when a chip is switched off, and restores it", () => {
      renderPanel();
      fireEvent.click(screen.getByRole("button", { name: "data" }));
      expect(screen.getByText("Cross-References (3/4)")).toBeTruthy();
      expect(rowTexts().map((c) => c[0])).toEqual(["call", "jmp", "branch"]);
      fireEvent.click(screen.getByRole("button", { name: "data" }));
      expect(rows()).toHaveLength(4);
    });

    it("shows an off chip in the muted style and an on chip in its own colour", () => {
      renderPanel();
      const chip = screen.getByRole("button", { name: "jmp" });
      // CLASS NAMES as strings — Tailwind is not loaded, so no colour is
      // actually computed here and nothing below is an appearance assertion.
      expect(chip.className).toContain("bg-red-800");
      fireEvent.click(chip);
      expect(chip.className).toContain("bg-gray-800");
      expect(chip.className).not.toContain("bg-red-800");
    });
  });

  /**
   * WAS A REPORTED WART, NOW AN ASSERTION. The instruction-scope direction
   * toggle reads "To"/"From" and the sortable "To" COLUMN HEADER read "To" —
   * two buttons doing unrelated things under one accessible name, which is why
   * `directionToggle()` above used to have to query by CSS class. A screen
   * reader user got no way at all to tell them apart.
   *
   * NEITHER visible text could change: the toggle is a `text-[9px]` chip fifth
   * in a row of chips inside a `flex-wrap` header, and each column header is a
   * fixed-width cell (`w-12`/`w-32`) sitting over the row cell of the same
   * width. So both carry `aria-label`s. This is jsdom, so what is asserted is
   * the NAME COMPUTATION testing-library performs, not what any real assistive
   * technology announces — CLAUDE.md's "the a11y work has never met a screen
   * reader" still stands.
   */
  describe("accessible names", () => {
    /** Every control in the header and the column strip — not the list rows. */
    function controlNames(): string[] {
      return Array.from(document.querySelectorAll("button"))
        .filter((b) => !b.classList.contains("absolute"))
        .map((b) => b.getAttribute("aria-label") ?? b.textContent ?? "");
    }

    /**
     * WEAKER THAN IT LOOKS, AND MEASURED: it goes red only when BOTH labels are
     * removed — the state the component was actually in. Removing either one
     * alone leaves the two names distinct ("To" vs "Sort by to address"), so
     * this row stays green while the collision is one edit away. The two
     * targeted tests below are what guard each label; this one guards the
     * property, and catches a THIRD control arriving with a name one of these
     * already uses.
     */
    it("gives every control a name no other control shares", () => {
      renderPanel({ currentInsnAddr: HELPER.address });
      fireEvent.click(screen.getByRole("button", { name: "Insn" }));
      const names = controlNames();
      // The state that had the collision: the direction toggle only exists in
      // the instruction scope, which is where the "To" header also lives.
      expect(names.length).toBeGreaterThan(8);
      expect(new Set(names).size).toBe(names.length);
    });

    it("names the direction toggle and the 'To' column differently", () => {
      renderPanel({ currentInsnAddr: HELPER.address });
      fireEvent.click(screen.getByRole("button", { name: "Insn" }));
      // Both still SHOW "To"…
      expect(directionToggle()?.textContent).toBe("To");
      expect(sortHeader("to address").textContent).toBe("To");
      // …and no button answers to the bare name any more, so neither query can
      // reach the other's element.
      expect(screen.queryAllByRole("button", { name: /^To$/ })).toHaveLength(0);
      expect(directionToggle()).not.toBe(sortHeader("to address"));
    });

    it("states the sort direction in words, not only as an arrow", () => {
      renderPanel();
      // "From ▲" announces the glyph; the label says what it means. The name
      // also has to change when the direction does, or it states the opposite
      // of the arrow beside it.
      expect(sortHeader("from address").getAttribute("aria-label")).toBe(
        "Sort by from address, ascending",
      );
      expect(sortHeader("to address").getAttribute("aria-label")).toBe("Sort by to address");
      fireEvent.click(sortHeader("from address"));
      expect(sortHeader("from address").getAttribute("aria-label")).toBe(
        "Sort by from address, descending",
      );
    });

    it("re-labels the direction toggle when it is flipped", () => {
      renderPanel({ currentInsnAddr: HELPER.address });
      fireEvent.click(screen.getByRole("button", { name: "Insn" }));
      const toggle = directionToggle();
      if (!toggle) throw new Error("no direction toggle in the instruction scope");
      expect(toggle.getAttribute("aria-label")).toBe("Reference direction: to this instruction");
      fireEvent.click(toggle);
      // The label states the CURRENT direction, as the visible text does — a
      // label describing the ACTION would say the opposite of the word beside it.
      expect(directionToggle()?.getAttribute("aria-label")).toBe(
        "Reference direction: from this instruction",
      );
    });
  });

  describe("sorting", () => {
    it("sorts by the 'to' address when that column header is clicked", () => {
      renderPanel();
      fireEvent.click(sortHeader("to address"));
      expect(rowTexts().map((c) => c[3])).toEqual([
        "0x140001000",
        "0x140001020",
        "0x140001020",
        "0x140002000",
      ]);
    });

    it("reverses on a second click of the same column, and marks the direction", () => {
      renderPanel();
      const to = sortHeader("to address");
      fireEvent.click(to);
      expect(to.textContent).toBe("To ▲");
      fireEvent.click(to);
      expect(to.textContent).toBe("To ▼");
      expect(rowTexts().map((c) => c[3])).toEqual([
        "0x140002000",
        "0x140001020",
        "0x140001020",
        "0x140001000",
      ]);
    });

    it("restarts ascending when the sort moves to a different column", () => {
      renderPanel();
      const from = sortHeader("from address");
      fireEvent.click(from); // already the sort key, so this flips to descending
      expect(from.textContent).toBe("From ▼");
      const type = sortHeader("type");
      fireEvent.click(type);
      // A new column must not inherit the previous column's direction.
      expect(type.textContent).toBe("Type ▲");
      expect(from.textContent).toBe("From");
      // Sorted by type name, alphabetically: branch, call, data, jmp.
      expect(rowTexts().map((c) => c[0])).toEqual(["branch", "call", "data", "jmp"]);
    });

    it("marks exactly one column at a time", () => {
      renderPanel();
      expect(sortHeader("from address").textContent).toBe("From ▲");
      expect(sortHeader("to address").textContent).toBe("To");
      expect(sortHeader("type").textContent).toBe("Type");
    });
  });

  describe("the text filter", () => {
    beforeEach(() => {
      vi.useFakeTimers();
    });
    afterEach(() => {
      vi.useRealTimers();
    });

    it("shows the typed text immediately but defers the filtering by 250ms", () => {
      renderPanel();
      const input = screen.getByPlaceholderText("Filter addresses/names...");
      fireEvent.change(input, { target: { value: "1028" } });
      // Two pieces of state on purpose: the input must not lag behind the
      // keyboard, and the list must not be re-sorted on every keystroke.
      expect((input as HTMLInputElement).value).toBe("1028");
      expect(rows()).toHaveLength(4);
      act(() => {
        vi.advanceTimersByTime(250);
      });
      expect(fromColumn()).toEqual(["0x140001028"]);
    });

    it("matches an address without its 0x prefix, in lower case", () => {
      renderPanel();
      fireEvent.change(screen.getByPlaceholderText("Filter addresses/names..."), {
        target: { value: "140002000" },
      });
      act(() => {
        vi.advanceTimersByTime(250);
      });
      // Matched on the TO address, so the row is found by its target rather than
      // its source — both columns are searched.
      expect(rowTexts()).toEqual([["data", "0x140001008", "main", "0x140002000", "---"]]);
    });

    it("matches a function name case-insensitively, at either end", () => {
      renderPanel();
      fireEvent.change(screen.getByPlaceholderText("Filter addresses/names..."), {
        target: { value: "HELPER" },
      });
      act(() => {
        vi.advanceTimersByTime(250);
      });
      // Three rows: two whose TARGET is helper, one whose SOURCE is.
      expect(screen.getByText("Cross-References (3/4)")).toBeTruthy();
      expect(fromColumn()).toEqual(["0x140001004", "0x140001010", "0x140001028"]);
    });

    it("only applies the last value typed within the debounce window", () => {
      renderPanel();
      const input = screen.getByPlaceholderText("Filter addresses/names...");
      fireEvent.change(input, { target: { value: "helper" } });
      act(() => {
        vi.advanceTimersByTime(100);
      });
      fireEvent.change(input, { target: { value: "1028" } });
      act(() => {
        vi.advanceTimersByTime(250);
      });
      // `clearTimeout` on each keystroke — without it the intermediate value
      // would land 100ms later and briefly show the wrong list.
      expect(fromColumn()).toEqual(["0x140001028"]);
    });
  });

  describe("scopes", () => {
    it("offers only the scope buttons its props can support", () => {
      renderPanel();
      // "All" is unconditional; the other three each depend on the caller
      // actually knowing an address. A button for a scope that would filter on
      // `null` is a button that silently does nothing.
      expect(screen.getByRole("button", { name: "All" })).toBeTruthy();
      for (const absent of ["Addr", "Func", "Insn"]) {
        expect(screen.queryByRole("button", { name: absent })).toBeNull();
      }
    });

    it("starts scoped to the address when one is supplied", () => {
      renderPanel({ scopeAddress: HELPER.address });
      // `useState(scopeAddress != null ? "address" : "all")` — a right-click
      // "show xrefs to this" must land already filtered, not on the whole list.
      expect(screen.getByRole("button", { name: "Addr" }).className).toContain("bg-blue-600");
      expect(screen.getByText("Cross-References (2/4)")).toBeTruthy();
      expect(fromColumn()).toEqual(["0x140001004", "0x140001010"]);
    });

    it("returns to the whole list when 'All' is chosen", () => {
      renderPanel({ scopeAddress: HELPER.address });
      fireEvent.click(screen.getByRole("button", { name: "All" }));
      expect(rows()).toHaveLength(4);
    });

    it("re-scopes when the caller points it at a NEW address", () => {
      const { rerender } = renderPanel({ scopeAddress: HELPER.address });
      fireEvent.click(screen.getByRole("button", { name: "All" }));
      expect(rows()).toHaveLength(4);
      rerender(
        <XrefPanel
          typedXrefMap={TYPED_XREFS}
          funcMap={FUNC_MAP}
          sortedFuncs={SORTED_FUNCS}
          onNavigate={() => {}}
          onClose={() => {}}
          scopeAddress={MAIN.address}
        />,
      );
      // The effect only fires on a CHANGE of address, so a user who widened the
      // scope by hand keeps it until they ask about somewhere else.
      expect(fromColumn()).toEqual(["0x140001028"]);
    });

    it("scopes by function on the SOURCE address, over the function's extent", () => {
      renderPanel({
        currentFuncAddr: HELPER.address,
        currentFuncEnd: HELPER.address + HELPER.size,
      });
      fireEvent.click(screen.getByRole("button", { name: "Func" }));
      // "xrefs from this function", so it is `fromAddr` inside [start, end) —
      // the one xref whose source is 0x140001028.
      expect(fromColumn()).toEqual(["0x140001028"]);
    });

    it("scopes by instruction, and the To/From toggle flips which end is matched", () => {
      renderPanel({ currentInsnAddr: HELPER.address });
      fireEvent.click(screen.getByRole("button", { name: "Insn" }));
      const toggle = directionToggle();
      if (!toggle) throw new Error("no direction toggle in the instruction scope");
      expect(toggle.textContent).toBe("To");
      // Default direction "to": xrefs that TARGET this address.
      expect(fromColumn()).toEqual(["0x140001004", "0x140001010"]);
      fireEvent.click(toggle);
      // Flipped: xrefs whose SOURCE is this address. 0x140001020 is `helper`'s
      // entry and nothing originates there, so the list empties — and the
      // "none match" message is the right one.
      expect(directionToggle()?.textContent).toBe("From");
      expect(screen.getByText("No xrefs match the current filters.")).toBeTruthy();
    });

    it("shows the direction toggle only in the instruction scope", () => {
      renderPanel({ currentInsnAddr: BASE + 0x28, currentFuncAddr: MAIN.address });
      expect(directionToggle()).toBeNull();
      fireEvent.click(screen.getByRole("button", { name: "Insn" }));
      expect(directionToggle()).toBeTruthy();
      fireEvent.click(screen.getByRole("button", { name: "All" }));
      // Leaving the scope must take the toggle with it: a direction control
      // beside an unscoped list would claim to do something it cannot.
      expect(directionToggle()).toBeNull();
    });

    /**
     * WAS A PIN, NOW A SPECIFICATION. Selecting "Func" and then moving the
     * cursor somewhere `currentFuncAddr` is null used to make the "Func" button
     * disappear while `scopeMode` stayed `"function"` — the filter chain fell
     * through, the whole list came back, and NO scope button was highlighted.
     * Nothing false was on screen and the list was complete, but the controls
     * and the list described different things: an unfiltered list with nothing
     * claiming it.
     *
     * The scope now falls back to "all" AND SAYS SO. That is the direction the
     * house rule points — the forbidden shape is a narrower answer wearing a
     * complete one's clothes, and this is the reverse — and "hold the empty
     * Func scope and explain it" was refused because this scope FOLLOWS THE
     * CURSOR rather than being a value the user entered: a cursor wandering
     * through padding would blank and refill the panel repeatedly for a lapse
     * the user never caused.
     */
    it("falls back to 'All' — highlighted — when its scope address goes away", () => {
      const { rerender } = renderPanel({
        currentFuncAddr: HELPER.address,
        currentFuncEnd: HELPER.address + HELPER.size,
      });
      fireEvent.click(screen.getByRole("button", { name: "Func" }));
      expect(rows()).toHaveLength(1);
      rerender(
        <XrefPanel
          typedXrefMap={TYPED_XREFS}
          funcMap={FUNC_MAP}
          sortedFuncs={SORTED_FUNCS}
          onNavigate={() => {}}
          onClose={() => {}}
          currentFuncAddr={null}
          currentFuncEnd={null}
        />,
      );
      // The list widened, and the button that describes THIS list is the one
      // highlighted. Both halves matter: the count assertion alone passed
      // before the fix.
      expect(rows()).toHaveLength(4);
      expect(screen.queryByRole("button", { name: "Func" })).toBeNull();
      expect(screen.getByRole("button", { name: "All" }).className).toContain("bg-blue-600");
    });

    /**
     * The fallback is DERIVED, not written back into state, and this is the
     * behaviour that buys: the user picked "Func", so a lapse borrows the scope
     * rather than discarding it. Collapsing `scopeMode` to "all" instead would
     * mean a cursor crossing one gap between detected functions silently
     * cancelled a scope the user chose — and PE32 detection is known to
     * under-produce, so those gaps are ordinary.
     */
    it("resumes the chosen scope when the address comes back", () => {
      const { rerender } = renderPanel({
        currentFuncAddr: HELPER.address,
        currentFuncEnd: HELPER.address + HELPER.size,
      });
      fireEvent.click(screen.getByRole("button", { name: "Func" }));
      const lapsed = (
        <XrefPanel
          typedXrefMap={TYPED_XREFS}
          funcMap={FUNC_MAP}
          sortedFuncs={SORTED_FUNCS}
          onNavigate={() => {}}
          onClose={() => {}}
          currentFuncAddr={null}
          currentFuncEnd={null}
        />
      );
      rerender(lapsed);
      expect(rows()).toHaveLength(4);
      rerender(
        <XrefPanel
          typedXrefMap={TYPED_XREFS}
          funcMap={FUNC_MAP}
          sortedFuncs={SORTED_FUNCS}
          onNavigate={() => {}}
          onClose={() => {}}
          currentFuncAddr={HELPER.address}
          currentFuncEnd={HELPER.address + HELPER.size}
        />,
      );
      expect(fromColumn()).toEqual(["0x140001028"]);
      expect(screen.getByRole("button", { name: "Func" }).className).toContain("bg-blue-600");
    });

    /**
     * …and the user can make the widening permanent, which is the escape hatch
     * that keeps "resumes" from being a trap: clicking "All" during a lapse
     * writes the preference, so the scope does not spring back.
     */
    it("makes the widening stick if 'All' is clicked during the lapse", () => {
      const { rerender } = renderPanel({
        currentFuncAddr: HELPER.address,
        currentFuncEnd: HELPER.address + HELPER.size,
      });
      fireEvent.click(screen.getByRole("button", { name: "Func" }));
      rerender(
        <XrefPanel
          typedXrefMap={TYPED_XREFS}
          funcMap={FUNC_MAP}
          sortedFuncs={SORTED_FUNCS}
          onNavigate={() => {}}
          onClose={() => {}}
          currentFuncAddr={null}
          currentFuncEnd={null}
        />,
      );
      fireEvent.click(screen.getByRole("button", { name: "All" }));
      rerender(
        <XrefPanel
          typedXrefMap={TYPED_XREFS}
          funcMap={FUNC_MAP}
          sortedFuncs={SORTED_FUNCS}
          onNavigate={() => {}}
          onClose={() => {}}
          currentFuncAddr={HELPER.address}
          currentFuncEnd={HELPER.address + HELPER.size}
        />,
      );
      expect(rows()).toHaveLength(4);
      expect(screen.getByRole("button", { name: "All" }).className).toContain("bg-blue-600");
    });

    /**
     * THE SAME LAPSE ON THE INSTRUCTION SCOPE, and it took a second control
     * with it. `currentInsnAddr` going null used to leave the To/From toggle on
     * screen beside an unfiltered list — the "shows the direction toggle only
     * in the instruction scope" test above states why that is wrong, and the
     * fall-through reached it by a route that test could not see, since it
     * drives the scope buttons rather than the props.
     */
    it("takes the direction toggle with it when the instruction address goes away", () => {
      const { rerender } = renderPanel({ currentInsnAddr: HELPER.address });
      fireEvent.click(screen.getByRole("button", { name: "Insn" }));
      expect(directionToggle()).toBeTruthy();
      rerender(
        <XrefPanel
          typedXrefMap={TYPED_XREFS}
          funcMap={FUNC_MAP}
          sortedFuncs={SORTED_FUNCS}
          onNavigate={() => {}}
          onClose={() => {}}
          currentInsnAddr={null}
        />,
      );
      expect(rows()).toHaveLength(4);
      expect(directionToggle()).toBeNull();
      expect(screen.getByRole("button", { name: "All" }).className).toContain("bg-blue-600");
    });

    it("combines a scope with a type filter rather than replacing it", () => {
      renderPanel({ scopeAddress: HELPER.address });
      expect(rows()).toHaveLength(2);
      fireEvent.click(screen.getByRole("button", { name: "jmp" }));
      expect(fromColumn()).toEqual(["0x140001004"]);
    });
  });

  it("navigates to the SOURCE of an xref when its row is clicked", () => {
    const { onNavigate } = renderPanel();
    fireEvent.click(rows()[3]);
    // The referencing site, not the target: the reader is here to see who
    // touches the target, so the useful destination is the instruction that
    // does. That row's `to` is 0x140001000, which differs, so this assertion
    // distinguishes the two.
    expect(onNavigate).toHaveBeenCalledWith(BASE + 0x28);
  });

  it("closes", () => {
    const { onClose } = renderPanel();
    fireEvent.click(screen.getByRole("button", { name: "✕" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
