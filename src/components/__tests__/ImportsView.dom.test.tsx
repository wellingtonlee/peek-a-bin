// @vitest-environment jsdom

import "../../test/domSetup";
import { act, fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AppState } from "../../hooks/usePEFile";
import type { ImportLibraryDef } from "../../pe/__tests__/fixtures";
import { buildMinimalPE32, buildMinimalPE64 } from "../../pe/__tests__/fixtures";
import { parsePE } from "../../pe/parser";
import type { PEFile } from "../../pe/types";
import { ImportsView } from "../ImportsView";
import { AppHarness, stateWithPE } from "./appStateHarness";

/**
 * THE IMPORTS TAB, rendered for the first time.
 *
 * Third name in `PARSER_DERIVED_TABS`, so `analysisNotice()`'s
 * `"no-code-section"` prose promises it is populated; nothing had ever rendered
 * it.
 *
 * NOT VIRTUALIZED — a `<div className="space-y-1">` of plain `<ul>`s, so every
 * library and every symbol is in the document and `stubLayoutRect` is
 * deliberately not called. No worker either: everything on this tab comes off
 * `pe.imports` and `state.importXrefs`.
 *
 * THE FILTER IS DEBOUNCED BY 250 ms, which is the one thing here that needs
 * care. `userEvent.setup({ advanceTimers })` drives vitest's fake clock, so the
 * assertions after a `vi.advanceTimersByTime(250)` are about the settled state
 * rather than about a race; the pre-advance assertion in the same test is what
 * shows the debounce is real and not that the timer helper is doing nothing.
 *
 * ORDINAL-ONLY IMPORTS are exercised in both directions, and the split is the
 * point. `parser.ts` still writes `Ordinal_<n>` into `PEFile` — that spelling is
 * a wire format `computeImphash` parses back out, so it must not move — but the
 * VIEW now resolves it through `pe/ordinalTables.ts`, the same lookup and the
 * same function imphash uses, so the two cannot disagree about what ws2_32!115
 * is. A resolved row shows the name with a `#<ordinal>` marker saying the name
 * came from a table rather than from the file; an ordinal the table does not
 * cover keeps its honest `Ordinal_<n>` spelling, which is what KERNEL32's 256
 * below pins. Both halves matter: resolving everything and resolving nothing are
 * each one assertion away from passing a suite that only checked the other.
 *
 * THE XREF POPUP'S POSITION IS NOT TESTED and cannot be. `clampPopup` is fed
 * `getBoundingClientRect()`, which jsdom answers all-zero because it performs no
 * layout, so `left`/`top` are whatever clamping does to (0, 0). That the popup
 * exists, lists the right addresses and dispatches on click is testable; where
 * it lands on screen is not.
 */

const KERNEL32: ImportLibraryDef = {
  libraryName: "KERNEL32.dll",
  functions: [{ name: "CreateFileW" }, { name: "ExitProcess" }, { ordinal: 256 }],
};
/**
 * `ws2_32.dll` is one of the three DLLs pefile's `ordlookup` covers, so its
 * ordinals ARE names. 115 is WSAStartup and 23 is socket — both read out of the
 * table `metadata.test.ts` pins entry by entry against pefile.
 */
const WS2_32: ImportLibraryDef = {
  libraryName: "WS2_32.dll",
  functions: [{ ordinal: 115 }, { ordinal: 23 }, { ordinal: 60000 }],
};
const NTOSKRNL: ImportLibraryDef = {
  libraryName: "ntoskrnl.exe",
  functions: [{ name: "IoCreateDevice" }, { name: "PsCreateSystemThread" }],
};

function peWith(libs: ImportLibraryDef[], is64 = true): PEFile {
  const build = is64 ? buildMinimalPE64 : buildMinimalPE32;
  return parsePE(build({ directories: { imports: libs } }));
}

function renderImports(pe: PEFile, over: Partial<AppState> = {}) {
  const dispatch = vi.fn();
  const view = render(
    <AppHarness state={stateWithPE(pe, over)} dispatch={dispatch}>
      <ImportsView />
    </AppHarness>,
  );
  return { ...view, dispatch };
}

/** Every symbol name on the page, in render order. */
function symbols(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll("ul li > span:first-child")).map(
    (s) => s.textContent ?? "",
  );
}

/** The library toggle buttons' labels, in render order. */
function libraries(container: HTMLElement): string[] {
  return Array.from(container.querySelectorAll("div.space-y-1 > div > button")).map((b) =>
    (b.textContent ?? "").replace(/[▶▼]/g, "").trim(),
  );
}

describe("ImportsView listing", () => {
  it("counts libraries and symbols in its heading", () => {
    const pe = peWith([KERNEL32, NTOSKRNL]);
    renderImports(pe);
    expect(screen.getByText("Imports (2 libraries, 5 functions)")).toBeTruthy();
    // Derived, so the heading cannot disagree with the parse.
    expect(pe.imports.reduce((n, i) => n + i.functions.length, 0)).toBe(5);
  });

  it("lists every library and every symbol, expanded by default", () => {
    const { container } = renderImports(peWith([KERNEL32, NTOSKRNL]));
    expect(libraries(container)).toEqual(["KERNEL32.dll(3)", "ntoskrnl.exe(2)"]);
    expect(symbols(container)).toEqual([
      "CreateFileW",
      "ExitProcess",
      // An ordinal-only import, named by the parser rather than resolved
      // through `ordinalTables.ts` — see the docstring.
      "Ordinal_256",
      "IoCreateDevice",
      "PsCreateSystemThread",
    ]);
  });

  it("resolves an ordinal the table covers, and marks it as inferred", () => {
    const { container } = renderImports(peWith([WS2_32]));
    const shown = symbols(container);
    expect(shown).toContain("WSAStartup");
    expect(shown).toContain("socket");
    // The marker is the provenance, and it is not decoration: an import by
    // ordinal and an import by name are different facts about the binary — a
    // packer may have chosen the ordinal precisely to keep the name out of the
    // file — so the row says where the name came from.
    expect(container.textContent).toContain("#115");
    expect(container.textContent).toContain("#23");
  });

  it("leaves an ordinal the table does NOT cover spelled as an ordinal", () => {
    // The control for the case above, in the same library: ws2_32 has no 60000,
    // so a rule that invented a name for every ordinal would fail here, and one
    // that resolved nothing would fail above. KERNEL32's 256 is the same claim
    // for a library the table does not cover at all.
    const { container } = renderImports(peWith([WS2_32]));
    expect(symbols(container)).toContain("Ordinal_60000");
    expect(container.textContent).not.toContain("#60000");
  });

  it("finds a resolved import by the name the reader can see", () => {
    // Resolution happens in the memo, above the filter, precisely so that the
    // name on screen is the name that can be searched for. Filtering on the raw
    // `Ordinal_115` spelling a user never sees would be the defect.
    vi.useFakeTimers();
    try {
      const { container } = renderImports(peWith([WS2_32]));
      fireEvent.change(screen.getByPlaceholderText("Filter..."), {
        target: { value: "wsastartup" },
      });
      act(() => void vi.advanceTimersByTime(250));
      expect(symbols(container)).toEqual(["WSAStartup"]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("names an ordinal-only import the same way in a PE32 image", () => {
    // The ordinal flag is bit 31 on PE32 and bit 63 on PE32+, so the two widths
    // are separate paths through the thunk read; the rendered name must not
    // differ between them.
    const { container } = renderImports(peWith([KERNEL32], false));
    expect(symbols(container)).toContain("Ordinal_256");
  });

  it("collapses and re-expands one library without touching the other", async () => {
    const user = userEvent.setup();
    const { container } = renderImports(peWith([KERNEL32, NTOSKRNL]));
    await user.click(screen.getByRole("button", { name: /KERNEL32\.dll/ }));
    expect(symbols(container)).toEqual(["IoCreateDevice", "PsCreateSystemThread"]);
    // The count in the toggle survives collapsing — it is a property of the
    // library, not of what is on screen.
    expect(libraries(container)).toEqual(["KERNEL32.dll(3)", "ntoskrnl.exe(2)"]);
    await user.click(screen.getByRole("button", { name: /KERNEL32\.dll/ }));
    expect(symbols(container)).toHaveLength(5);
  });
});

describe("ImportsView filter", () => {
  /**
   * The filter is debounced by 250 ms, so every test here drives a fake clock —
   * and two things about that are measured rather than assumed.
   *
   * **`waitFor` deadlocks under `vi.useFakeTimers()`**: it polls on a timer of
   * its own, never gets a tick, and the test hangs to its 5 s limit. So the
   * clock is advanced inside `act()`, which flushes React's queue synchronously
   * and makes every assertion below settled rather than eventual.
   *
   * **`userEvent` deadlocks the same way**, even with `advanceTimers` wired to
   * `vi.advanceTimersByTime` — its inter-keystroke awaits do not resolve. Hence
   * `fireEvent.change`, which drives `onChange` directly. WHAT THAT GIVES UP:
   * nothing about per-keystroke behaviour, because there is none here — the
   * handler is `(value) => { setFilterInput(value); debounce(value); }` over the
   * whole field value, so one change event and six are the same code path.
   */
  function setFilter(text: string) {
    fireEvent.change(screen.getByPlaceholderText("Filter..."), { target: { value: text } });
  }

  it("debounces by 250 ms and then narrows to matching symbols", () => {
    vi.useFakeTimers();
    try {
      const { container } = renderImports(peWith([KERNEL32, NTOSKRNL]));
      setFilter("create");
      // Still five. The input is controlled and updates immediately; the FILTER
      // does not.
      expect(symbols(container)).toHaveLength(5);
      expect((screen.getByPlaceholderText("Filter...") as HTMLInputElement).value).toBe("create");

      // Advanced SHORT of the delay first, and that is not decoration:
      // "nothing has happened yet" is equally true of a timer of 0 ms that has
      // simply not been ticked, so a control setting the delay to 0 came back
      // INERT until this step existed. Crossing the boundary in two moves is
      // what makes the 250 itself load-bearing.
      act(() => void vi.advanceTimersByTime(240));
      expect(symbols(container)).toHaveLength(5);
      act(() => void vi.advanceTimersByTime(10));
      // Case-insensitive (the fixture spells them CreateFileW / IoCreateDevice /
      // PsCreateSystemThread) and matched as a SUBSTRING of the symbol rather
      // than as a prefix or against the library name.
      expect(symbols(container)).toEqual(["CreateFileW", "IoCreateDevice", "PsCreateSystemThread"]);
      // Plural on both halves of the match count, and the two numbers are
      // different — a component summing the wrong thing would show 3 and 3.
      expect(screen.getByText("3 matches in 2 libraries")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("pluralises the match count correctly for exactly one hit", () => {
    vi.useFakeTimers();
    try {
      renderImports(peWith([KERNEL32, NTOSKRNL]));
      setFilter("ExitProcess");
      act(() => void vi.advanceTimersByTime(250));
      expect(screen.getByText("1 match in 1 library")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });

  it("keeps a library whose NAME matches even when no symbol does", () => {
    vi.useFakeTimers();
    try {
      const { container } = renderImports(peWith([KERNEL32, NTOSKRNL]));
      setFilter("ntoskrnl");
      act(() => void vi.advanceTimersByTime(250));
      // CURRENT BEHAVIOUR, pinned rather than endorsed: the library survives the
      // filter on its own name, but its symbol list has already been filtered to
      // nothing, so the row reads "ntoskrnl.exe(0)" over an empty list. Not a
      // falsehood — zero symbols match — but a reader searching for a library
      // gets the library and none of its contents.
      expect(libraries(container)).toEqual(["ntoskrnl.exe(0)"]);
      expect(symbols(container)).toEqual([]);
    } finally {
      vi.useRealTimers();
    }
  });

  it("shows no libraries at all when nothing matches", () => {
    vi.useFakeTimers();
    try {
      const { container } = renderImports(peWith([KERNEL32]));
      setFilter("zzzz");
      act(() => void vi.advanceTimersByTime(250));
      expect(libraries(container)).toEqual([]);
      expect(screen.getByText("0 matches in 0 libraries")).toBeTruthy();
    } finally {
      vi.useRealTimers();
    }
  });
});

describe("ImportsView xrefs", () => {
  it("spins while xrefs are unbuilt and says so when they arrive", () => {
    const pe = peWith([KERNEL32]);
    const { container, unmount } = renderImports(pe, { importXrefs: null });
    expect(container.textContent).toContain("Xrefs loading...");
    expect(container.textContent).not.toContain("xref)");
    unmount();

    renderImports(pe, { importXrefs: new Map() });
    expect(screen.getByText("Xrefs loaded")).toBeTruthy();
    // With the map present but empty, every symbol is explicitly zero rather
    // than blank — "no xrefs" and "not computed yet" must not look the same.
    expect(screen.getAllByText("(0 xrefs)")).toHaveLength(3);
  });

  it("keys xref counts on the symbol's own IAT address", () => {
    const pe = peWith([KERNEL32]);
    // `iatAddresses` is per symbol in slot order; using the parsed value rather
    // than an arithmetic guess is what makes this a test of the component's
    // lookup and not of the fixture's layout.
    const iat = pe.imports[0].iatAddresses;
    expect(iat).toHaveLength(3);
    renderImports(pe, {
      importXrefs: new Map([
        [iat[0], [0x140001000, 0x140001010]],
        [iat[2], [0x140001020]],
      ]),
    });
    expect(screen.getByText("(2 xrefs)")).toBeTruthy();
    // Singular.
    expect(screen.getByText("(1 xref)")).toBeTruthy();
    expect(screen.getAllByText("(0 xrefs)")).toHaveLength(1);
  });

  it("opens a popup of source addresses and navigates to one", async () => {
    const user = userEvent.setup();
    const pe = peWith([KERNEL32]);
    const iat = pe.imports[0].iatAddresses;
    const { dispatch } = renderImports(pe, {
      importXrefs: new Map([[iat[1], [0x140001000, 0x1400010ab]]]),
    });
    await user.click(screen.getByText("(2 xrefs)"));
    expect(screen.getByText("Xrefs to ExitProcess")).toBeTruthy();
    // Uppercase hex, no padding, and 0x1400010AB is above 2^32 — so a `>>> 0`
    // here would print 0x400010AB, the Headers-tab defect one tab over.
    expect(screen.getByRole("button", { name: "0x1400010AB" })).toBeTruthy();

    await user.click(screen.getByRole("button", { name: "0x140001000" }));
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_ADDRESS", address: 0x140001000 });
    expect(dispatch).toHaveBeenCalledWith({ type: "SET_TAB", tab: "disassembly" });
    // Dismissed by its own click handler, not only by the outside-click hook.
    expect(screen.queryByText("Xrefs to ExitProcess")).toBeNull();
  });

  it("dismisses the popup on Escape", async () => {
    const user = userEvent.setup();
    const pe = peWith([KERNEL32]);
    renderImports(pe, { importXrefs: new Map([[pe.imports[0].iatAddresses[0], [0x140001000]]]) });
    await user.click(screen.getByText("(1 xref)"));
    expect(screen.getByText("Xrefs to CreateFileW")).toBeTruthy();
    await user.keyboard("{Escape}");
    expect(screen.queryByText("Xrefs to CreateFileW")).toBeNull();
  });
});

describe("ImportsView driver risk tags", () => {
  const DRIVER = {
    isDriver: true,
    reasons: ["imports ntoskrnl.exe"],
    isWDM: true,
    kernelImportCount: 2,
    kernelModules: ["ntoskrnl.exe"],
  };

  it("tags a suspicious kernel API only when the file is a driver", () => {
    const pe = peWith([NTOSKRNL]);
    const { unmount } = renderImports(pe, { driverInfo: DRIVER });
    // `PsCreateSystemThread` is in `SUSPICIOUS_APIS`; `IoCreateDevice` is not,
    // so this is a per-symbol lookup and not a per-library banner.
    expect(screen.getByText("Process/Thread")).toBeTruthy();
    expect(screen.queryAllByText("Callback/Hook")).toEqual([]);
    unmount();

    renderImports(pe, { driverInfo: { ...DRIVER, isDriver: false } });
    expect(screen.queryByText("Process/Thread")).toBeNull();
  });

  it("shows no tags at all with no driver analysis", () => {
    renderImports(peWith([NTOSKRNL]));
    expect(screen.queryByText("Process/Thread")).toBeNull();
  });
});

describe("ImportsView with nothing to show", () => {
  it("renders its heading and an empty list for an image with no import directory", () => {
    // The empty state that must not throw: `analysisNotice`'s "no-code-section"
    // prose names this tab, and a resource-only DLL frequently imports nothing.
    const { container } = renderImports(parsePE(buildMinimalPE64()));
    expect(screen.getByText("Imports (0 libraries, 0 functions)")).toBeTruthy();
    expect(libraries(container)).toEqual([]);
    expect(screen.getByPlaceholderText("Filter...")).toBeTruthy();
  });

  it("renders nothing at all with no PE loaded", () => {
    const { container } = render(
      <AppHarness state={stateWithPE(null as unknown as PEFile)} dispatch={vi.fn()}>
        <ImportsView />
      </AppHarness>,
    );
    expect(container.innerHTML).toBe("");
  });
});
