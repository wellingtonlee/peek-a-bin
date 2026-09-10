// @vitest-environment jsdom

import "../../test/domSetup";
// jsdom implements neither ResizeObserver nor matchMedia, and HexView's
// entropy-strip effect constructs both — see the stub's docstring for what it
// does and does not buy (it buys nothing whatever about measured widths).
import "../../test/browserApiStubs";
import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useReducer } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { type AppState, appReducer } from "../../hooks/usePEFile";
import { buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import { BYTE_SEARCH_DEBOUNCE_MS, HexView, MAX_BYTE_PATTERN_MATCHES } from "../HexView";
import { AppHarness, harnessPE, IMAGE_BASE, stateWithPE } from "./appStateHarness";

/**
 * Every `scrollToIndex` the component asks for, in order.
 *
 * NOTHING HAS BEEN SEEN TO SCROLL AND NOTHING CAN BE. `virtual-core` measures
 * the scroll element with `offsetHeight`, which is 0 here, so the grid renders
 * no rows at all (asserted at the bottom of this file) and a scroll request
 * moves nothing that exists. This records the REQUEST — the index the view was
 * told to bring into range — and that is the whole of what next/prev can be
 * checked against in jsdom.
 *
 * `vi.hoisted` because a `vi.mock` factory is hoisted above the imports and
 * would otherwise reach a `const` in its temporal dead zone.
 */
const virt = vi.hoisted(() => ({ scrolls: [] as number[] }));

vi.mock("@tanstack/react-virtual", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@tanstack/react-virtual")>();
  // `scrollToIndex` is an instance property assigned in `Virtualizer`'s
  // constructor, not a prototype method, so it cannot be spied on the class.
  // The instance is held in `useState` and is therefore stable across renders —
  // hence the guard, without which each render would wrap the wrapper and one
  // call would be recorded many times.
  const patched = new WeakSet<object>();
  return {
    ...actual,
    useVirtualizer: (options: never) => {
      const v = actual.useVirtualizer(options);
      if (!patched.has(v)) {
        patched.add(v);
        const inner = v.scrollToIndex.bind(v);
        v.scrollToIndex = (index, opts) => {
          virt.scrolls.push(index);
          inner(index, opts);
        };
      }
      return v;
    },
  };
});

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

/** RVA of {@link renderNeedles}'s one section. */
const NEEDLE_VA = 0x1000;

/**
 * A PE whose one section is zeros except for an `AA` at each named offset, so a
 * one-byte `AA` search has a known match list AT KNOWN ROWS — which is what the
 * navigation rows below assert against. The offsets are deliberately spread
 * across several sixteen-byte rows, since a match list inside one row cannot
 * tell a right `scrollToIndex` from a wrong one.
 */
function needlePE(offsets: number[], others: number[], size: number) {
  const data = new Uint8Array(size);
  for (const o of offsets) data[o] = 0xaa;
  for (const o of others) data[o] = 0xbb;
  return parsePE(
    buildMinimalPE64({
      imageBase: IMAGE_BASE,
      sections: [
        {
          name: ".needle",
          virtualAddress: NEEDLE_VA,
          virtualSize: size,
          data,
          characteristics: 0x40000040, // INITIALIZED_DATA | MEM_READ
        },
      ],
    }),
  );
}

function renderNeedles(offsets: number[], others: number[] = [], size = 0x60) {
  const pe = needlePE(offsets, others, size);
  const dispatch = vi.fn();
  render(
    <AppHarness
      state={stateWithPE(pe, { currentAddress: IMAGE_BASE + NEEDLE_VA })}
      dispatch={dispatch}
    >
      <HexView />
    </AppHarness>,
  );
  // The mount itself scrolls: `currentAddress` is the section base, so the
  // effect watching `currentRowIdx` asks for row 0 before any search exists.
  // Dropping it here is what makes `virt.scrolls` a record of the BUTTONS.
  virt.scrolls.length = 0;
  return { dispatch, base: IMAGE_BASE + NEEDLE_VA };
}

/**
 * The same fixture through the REAL reducer, so `SET_ADDRESS` actually lands.
 *
 * Every other row here uses a `vi.fn()` dispatch, which means `currentAddress`
 * never moves and the memo chain behind `sectionBytes` is trivially stable. It
 * is not trivial in the app: stepping dispatches `SET_ADDRESS`, which re-runs
 * the `sectionInfo` memo, and if that returned a fresh object the `sectionBytes`
 * memo below it would too — re-running the scan effect, which resets `matchIdx`
 * to -1. A second press would then be a first press again, forever. What makes
 * it hold is that `sectionInfo` returns an element OF `pe.sections`, so the
 * identity survives an address change within one section; this is the row that
 * executes that argument rather than reasoning about it.
 */
function renderNeedlesLive(offsets: number[]) {
  const pe = needlePE(offsets, [], 0x60);
  const init = stateWithPE(pe, { currentAddress: IMAGE_BASE + NEEDLE_VA });
  function Host() {
    // `useReducer`'s dispatch is stable by React's own guarantee, so it needs
    // no `useCallback` and no dependency entry.
    const [state, dispatch] = useReducer(appReducer, init);
    return (
      <AppHarness state={state} dispatch={dispatch}>
        <HexView />
      </AppHarness>
    );
  }
  render(<Host />);
  virt.scrolls.length = 0;
}

/** Type into the byte search box without `userEvent`, which deadlocks under fake timers. */
function typeSearch(value: string) {
  fireEvent.change(byteSearchBox(), { target: { value } });
}

/** Let a pending debounce fire, inside `act` so React flushes what it schedules. */
function settle(ms = BYTE_SEARCH_DEBOUNCE_MS) {
  act(() => {
    vi.advanceTimersByTime(ms);
  });
}

/**
 * THE DEBOUNCE, ASSERTED ON BOTH SIDES OF ITS BOUNDARY.
 *
 * A single advance PAST the boundary cannot tell a 150 ms debounce from no
 * debounce at all: "the result is on screen now" is equally true of a scan that
 * ran synchronously on the keystroke. So every row here asserts the short side
 * as well — and the second row goes further, keeping the total elapsed time
 * WELL PAST the boundary while no single gap reaches it, which a plain
 * `setTimeout` that is merely never reset would fail.
 *
 * `userEvent` and `waitFor` both deadlock under `vi.useFakeTimers()` (the first
 * awaits between keystrokes, the second polls on a timer of its own), hence
 * `fireEvent.change` and an explicit `act`.
 */
describe("HexView byte search debounce", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    virt.scrolls.length = 0;
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("does not scan until the wait has elapsed, and then does", () => {
    renderNeedles([0x05, 0x25]);
    typeSearch("AA");
    settle(BYTE_SEARCH_DEBOUNCE_MS - 1);
    // Short of the boundary: no count, and — the half that matters — no claim
    // that the section lacks the pattern either.
    expect(screen.queryByText(/matches in \.needle/)).toBeNull();
    expect(screen.queryByText(/^No matches/)).toBeNull();
    settle(1);
    expect(screen.getByText("2 matches in .needle")).toBeTruthy();
  });

  it("reports nothing from a query superseded before the wait elapsed", () => {
    // THE NAME IS EXACT AND THE NARROWER CLAIM IS DELIBERATE. What this pins is
    // that the ANSWER shown is never the superseded query's; it does not pin
    // that the superseded query was never SCANNED. Cancelling the pending timer
    // is measured INERT (control C3) and reported rather than tuned away: with
    // the settled gate in place a stale timer's result is judged unsettled and
    // says nothing, so the only cost left is the wasted walk — and counting
    // walks would need a seam in `HexView` existing solely for a test.
    renderNeedles([0x05, 0x25]);
    // `BB` occurs nowhere, so had the first keystroke's timer been the only one
    // there would be a visible, wrong, durable "No matches in .needle" here.
    typeSearch("BB");
    settle(BYTE_SEARCH_DEBOUNCE_MS - 20);
    typeSearch("AA");
    settle(BYTE_SEARCH_DEBOUNCE_MS - 20);
    // Well past 150 ms in total; no single gap reached it.
    expect(screen.queryByText(/matches in \.needle/)).toBeNull();
    expect(screen.queryByText(/^No matches/)).toBeNull();
    settle(20);
    expect(screen.getByText("2 matches in .needle")).toBeTruthy();
  });

  it("applies an emptied box at once, without waiting", () => {
    // The debounce exists to stop a walk per keystroke and clearing walks
    // nothing, so waiting would pay the delay on the one affordance whose job
    // is to make the highlights go away.
    renderNeedles([0x05]);
    typeSearch("AA");
    settle();
    expect(screen.getByText("1 match in .needle")).toBeTruthy();
    typeSearch("");
    expect(screen.queryByText(/match/)).toBeNull();
  });

  it("applies the query at once on Enter, cancelling the wait", () => {
    renderNeedles([0x05, 0x25]);
    typeSearch("AA");
    fireEvent.keyDown(byteSearchBox(), { key: "Enter" });
    // No timer has been advanced at all.
    expect(screen.getByText("2 matches in .needle")).toBeTruthy();
  });
});

/**
 * THE PENDING STATE SAYS NOTHING ABOUT THE SECTION, WHICH IS A DEFECT CLASS AND
 * NOT A POLISH ITEM.
 *
 * The moment the typed query and the scanned query are two pieces of state
 * there is a window — a durable 150 ms one while the debounce runs, and a
 * one-frame one between `activeSearch` moving and the effect running — in which
 * the toolbar describes the OLD scan under the NEW query. One of the things it
 * says there is "No matches in .needle", which is a POSITIVE CLAIM ABOUT THE
 * SECTION standing over a pattern nothing has looked for yet: the same
 * narrower-answer-wearing-a-complete-one's-shape rule as `ImportEntry.truncated`
 * and `ResourceTree.incomplete`.
 *
 * The fix is to carry the query and the section WITH the result and compare both
 * against what is on screen (`searchSettled`), so "not scanned yet" and
 * "scanned, found nothing" are distinguishable states rather than one.
 *
 * NEGATIVE CONTROL: gate the sentences on `activeSearch` — the query the scan
 * keys on, which is what the first sketch of this change did — and both rows
 * below go red, because during the wait `activeSearch` still equals the result's
 * own query and the stale sentence is judged current.
 */
describe("HexView byte search pending state", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    virt.scrolls.length = 0;
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  it("withdraws 'No matches' while a newly typed query is unscanned", () => {
    renderNeedles([0x05]);
    typeSearch("BB");
    settle();
    expect(screen.getByText("No matches in .needle")).toBeTruthy();
    // `AA` is in this section, so the standing sentence is not merely stale, it
    // is about to be contradicted.
    typeSearch("AA");
    expect(screen.queryByText(/^No matches/)).toBeNull();
    expect(screen.getByText("Searching…")).toBeTruthy();
    settle();
    expect(screen.getByText("1 match in .needle")).toBeTruthy();
  });

  it("withdraws a settled count while a newly typed query is unscanned", () => {
    renderNeedles([0x05, 0x25]);
    typeSearch("AA");
    settle();
    expect(screen.getByText("2 matches in .needle")).toBeTruthy();
    typeSearch("BB");
    expect(screen.queryByText(/matches in \.needle/)).toBeNull();
    expect(screen.queryByText("Previous match")).toBeNull();
    expect(screen.getByText("Searching…")).toBeTruthy();
    settle();
    expect(screen.getByText("No matches in .needle")).toBeTruthy();
  });

  it("reports nothing pending for a query that is not a byte pattern", () => {
    // Gibberish is not a scan in flight, and "Searching…" over `zz` would be a
    // spinner that never resolves.
    renderNeedles([0x05]);
    typeSearch("zz");
    expect(screen.queryByText("Searching…")).toBeNull();
    settle();
    expect(screen.queryByText("Searching…")).toBeNull();
    expect(screen.queryByText(/match/)).toBeNull();
  });
});

/**
 * NEXT/PREV. THE OFFSETS USED TO BE COMPUTED AND THROWN AWAY.
 *
 * The scan folded up to 1000 offsets into a highlight set and dropped the array,
 * so a 200 KB section with forty hits could be counted and then only found by
 * scrolling. What is asserted here is the REQUEST to bring a row into range and
 * the address the rest of the app is moved to — see {@link virt}: nothing in
 * this environment has been seen to scroll, and no row of the grid exists to
 * scroll to.
 */
describe("HexView byte search navigation", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    virt.scrolls.length = 0;
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const next = () => fireEvent.click(screen.getByLabelText("Next match"));
  const prev = () => fireEvent.click(screen.getByLabelText("Previous match"));

  it("offers no navigation until a scan has found something", () => {
    renderNeedles([0x05]);
    expect(screen.queryByLabelText("Next match")).toBeNull();
    typeSearch("BB");
    settle();
    expect(screen.getByText("No matches in .needle")).toBeTruthy();
    expect(screen.queryByLabelText("Next match")).toBeNull();
  });

  it("steps forward through the matches in address order and wraps", () => {
    // Rows 0, 2 and 4 of the sixteen-byte grid.
    const { dispatch, base } = renderNeedles([0x05, 0x25, 0x45]);
    typeSearch("AA");
    settle();
    expect(screen.getByText("3 matches in .needle")).toBeTruthy();
    // No position of ANY value is claimed before a step: a position over a view
    // that has not moved is a statement about where the grid is. The regex
    // rather than a literal "1/3" because an off-by-one would print "0/3".
    expect(screen.queryByText(/^\d+\/\d+\+?$/)).toBeNull();

    next();
    expect(screen.getByText("1/3")).toBeTruthy();
    next();
    next();
    expect(screen.getByText("3/3")).toBeTruthy();
    next();
    expect(screen.getByText("1/3")).toBeTruthy();

    expect(virt.scrolls).toEqual([0, 2, 4, 0]);
    expect(dispatch.mock.calls.map((c) => c[0])).toEqual([
      { type: "SET_ADDRESS", address: base + 0x05 },
      { type: "SET_ADDRESS", address: base + 0x25 },
      { type: "SET_ADDRESS", address: base + 0x45 },
      { type: "SET_ADDRESS", address: base + 0x05 },
    ]);
  });

  it("steps backward to the LAST match from a cursor that is nowhere yet", () => {
    // -1 is a third state and not a zero: plain modular arithmetic on it lands
    // one short of the end going backwards.
    const { dispatch, base } = renderNeedles([0x05, 0x25, 0x45]);
    typeSearch("AA");
    settle();
    prev();
    expect(screen.getByText("3/3")).toBeTruthy();
    expect(virt.scrolls).toEqual([4]);
    prev();
    expect(screen.getByText("2/3")).toBeTruthy();
    expect(virt.scrolls).toEqual([4, 2]);
    // The app's address follows the cursor too, so the data inspector and the
    // address bar agree with the row the grid was told to show.
    expect(dispatch.mock.calls.map((c) => c[0])).toEqual([
      { type: "SET_ADDRESS", address: base + 0x45 },
      { type: "SET_ADDRESS", address: base + 0x25 },
    ]);
  });

  it("steps on Enter and back on Shift+Enter once the box is settled", () => {
    renderNeedles([0x05, 0x25]);
    typeSearch("AA");
    settle();
    fireEvent.keyDown(byteSearchBox(), { key: "Enter" });
    expect(screen.getByText("1/2")).toBeTruthy();
    fireEvent.keyDown(byteSearchBox(), { key: "Enter", shiftKey: true });
    expect(screen.getByText("2/2")).toBeTruthy();
    expect(virt.scrolls).toEqual([0, 2]);
  });

  it("starts a fresh list unpositioned when the query changes", () => {
    // The second query MUST also match something: a query that finds nothing
    // renders no navigator at all, so it would hide a cursor carried over
    // rather than test that none was — measured, as an inert control, before
    // the `BB` needle was added here.
    renderNeedles([0x05, 0x25, 0x45], [0x35]);
    typeSearch("AA");
    settle();
    next();
    expect(screen.getByText("1/3")).toBeTruthy();
    typeSearch("BB");
    settle();
    expect(screen.getByText("1 match in .needle")).toBeTruthy();
    // A new scan is a new list; carrying the old index into it would claim a
    // position the view was never moved to.
    expect(screen.queryByText(/^\d+\/\d+\+?$/)).toBeNull();
  });

  it("keeps its place across steps when the real reducer moves the address", () => {
    // See {@link renderNeedlesLive}: with a `vi.fn()` dispatch nothing moves, so
    // no other row here can tell a surviving cursor from one that is reset and
    // re-set on every press.
    renderNeedlesLive([0x05, 0x25, 0x45]);
    typeSearch("AA");
    settle();
    next();
    expect(screen.getByText("1/3")).toBeTruthy();
    next();
    expect(screen.getByText("2/3")).toBeTruthy();
    next();
    expect(screen.getByText("3/3")).toBeTruthy();
    // And the section did not change under it, so the count still stands.
    expect(screen.getByText("3 matches in .needle")).toBeTruthy();
  });

  it("marks the denominator as a floor when the scan stopped at the cap", () => {
    // The `+` is `matchSummary`'s own admission carried onto the position, since
    // "2/1000" over a truncated scan states a total the scan never established.
    const data = new Uint8Array(MAX_BYTE_PATTERN_MATCHES + 1).fill(0xaa);
    const pe = parsePE(
      buildMinimalPE64({
        imageBase: IMAGE_BASE,
        sections: [
          {
            name: ".fill",
            virtualAddress: FILL_VA,
            virtualSize: data.length,
            data,
            characteristics: 0x40000040,
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
    typeSearch(FILL_BYTE);
    settle();
    fireEvent.click(screen.getByLabelText("Next match"));
    expect(screen.getByText(`1/${MAX_BYTE_PATTERN_MATCHES}+`)).toBeTruthy();
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
