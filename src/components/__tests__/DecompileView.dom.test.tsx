// @vitest-environment jsdom

import "../../test/domSetup";
import { fireEvent, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { type DecompileAdmissions, emptyAdmissions } from "../../disasm/decompile/emit";
import type { DecompileTab } from "../../hooks/decompileTabsState";
import { ADMISSION_SEPARATOR, admissionSummary } from "../../hooks/decompileTabsState";
import { IMAGE_SCN_MEM_EXECUTE, IMAGE_SCN_MEM_READ } from "../../pe/constants";
import type { SectionHeader } from "../../pe/types";
import { DecompileView } from "../DecompileView";

/**
 * THE DECOMPILE PANEL, rendered for the first time.
 *
 * CLAUDE.md's "Not verified" list named this component as one of three surfaces
 * that no human and no test had ever rendered — 540 lines of it. Nothing here
 * needed a worker, a context or a fixture PE to get to: every input is a prop,
 * so the whole file is reachable from `render()` alone. That it had never been
 * mounted was a gap in coverage, not a cost of mounting.
 *
 * WHAT THIS FILE IS FOR. `decompileTabsState.test.ts` already pins the reducer
 * and the high-level cache as pure functions; none of that is repeated. What is
 * asserted here is only what a *render* can settle:
 *
 *  - `tokenizeLine`'s classification as it reaches the DOM. It is a
 *    module-private regex whose output is a `className` per token, and those
 *    classes carry colour (`src/styles/index.css` defines `.dc-string`,
 *    `.dc-number`, `.dc-keyword`, `.dc-type`, `.dc-comment`). A token put in the
 *    wrong bucket is well-typed, compiles, and is simply the wrong colour on
 *    screen — invisible to `typecheck` and to every static instrument in the
 *    repo. Two lines are asserted as a FULL token-by-token list rather than by
 *    spot-checking, because the classification is positional: a change to one
 *    alternative in the regex reorders the rest.
 *  - Which handler fires, with which argument, from which DOM node. `handleClick`
 *    is delegated on the `<pre>` and keys off `e.target.textContent`, so *which
 *    element the click landed on* changes the answer — a distinction that exists
 *    only in a DOM.
 *  - The `useDismissOnOutsideClick` wiring. This is the one popup in the app
 *    that listens on `document` rather than `window`, and on `click` rather than
 *    `mousedown`; the component says so in a comment. Both halves are asserted
 *    by dispatching where the *other* choice would have caught it, which nothing
 *    but a render can do.
 *
 * WHAT A GREEN RUN HERE DOES NOT MEAN. jsdom performs no layout, so nothing
 * below is evidence about geometry, overflow, visibility or scrolling. Tailwind
 * is deliberately not in the test config, so a class name is a string and not a
 * colour or a `display`; every class assertion below is a claim about the
 * classification, never about what the pixel looks like. The context menu is
 * positioned with `left`/`top` inline styles that are asserted as numbers and
 * are not checked against a viewport, because there is no viewport. And no
 * human has still looked at this panel in a browser.
 */

type Props = Parameters<typeof DecompileView>[0];

function setup(overrides: Partial<Props> = {}) {
  const onTabChange = vi.fn();
  const onClose = vi.fn();
  const props: Props = {
    code: "",
    activeTab: "low" as DecompileTab,
    onTabChange,
    onClose,
    ...overrides,
  };
  const utils = render(<DecompileView {...props} />);
  return { ...utils, props, onTabChange, onClose, user: userEvent.setup() };
}

/** The `<pre>` that holds the code. Not present in the loading/AI-empty arms. */
const codePane = () => document.querySelector("pre") as HTMLPreElement;

/** One rendered source line, by its zero-based `data-line`. */
function lineRow(num: number): HTMLElement {
  const el = document.querySelector(`[data-line="${num}"]`);
  if (!el) throw new Error(`no rendered line ${num}`);
  return el as HTMLElement;
}

/**
 * The token spans of one line, as `[text, className]`.
 *
 * Read off the *direct children* of the content wrapper deliberately. A
 * `querySelectorAll("span")` would also return the line-number span and the
 * wrapper itself, and on a single-token line the wrapper's `textContent` equals
 * the token's — so a text-based lookup would silently match the wrapper and an
 * assertion about a token's class would be reading the wrapper's.
 */
function tokensOf(num: number): [string, string][] {
  const wrapper = lineRow(num).children[1] as HTMLElement;
  return [...wrapper.children].map((el) => [el.textContent ?? "", el.className]);
}

/** Find one token span by exact text, for the click tests. */
function tokenSpan(num: number, text: string): HTMLElement {
  const wrapper = lineRow(num).children[1] as HTMLElement;
  const hit = [...wrapper.children].find((el) => el.textContent === text);
  if (!hit) throw new Error(`no token "${text}" on line ${num}`);
  return hit as HTMLElement;
}

/**
 * jsdom has no clipboard. Defined per test rather than globally so no two tests
 * share an accumulating spy.
 *
 * MUST BE CALLED AFTER `setup()`, and that is not a style point: `setup()` calls
 * `userEvent.setup()`, which installs a clipboard stub of its own over whatever
 * is there. Called first, this spy is replaced and the assertion reads an empty
 * call list — which is exactly how it failed on the first run.
 */
function stubClipboard() {
  const writeText = vi.fn();
  Object.defineProperty(navigator, "clipboard", {
    value: { writeText },
    configurable: true,
    writable: true,
  });
  return writeText;
}

const tabButton = (label: string) => screen.getByRole("button", { name: label });

// ── The pill tab group ──

describe("DecompileView tab group", () => {
  it("renders one button per declared tab, and only those", () => {
    setup();
    // TAB_LABELS is the component's own declaration; three tabs, not four.
    expect(tabButton("Low Level")).toBeTruthy();
    expect(tabButton("High Level")).toBeTruthy();
    expect(tabButton("AI")).toBeTruthy();
  });

  it.each([
    ["low", "Low Level"],
    ["high", "High Level"],
    ["ai", "AI"],
  ] as const)("marks %s active and only %s active", (active, label) => {
    setup({ activeTab: active });
    for (const other of ["Low Level", "High Level", "AI"]) {
      const btn = tabButton(other);
      // The active pill is the one carrying the filled background. Asserted as
      // a class, which is a claim about the branch taken and not about colour:
      // Tailwind is not loaded here.
      expect(btn.className.includes("bg-gray-600")).toBe(other === label);
      expect(btn.className.includes("text-gray-500")).toBe(other !== label);
    }
  });

  it.each([
    ["Low Level", "low"],
    ["High Level", "high"],
    ["AI", "ai"],
  ] as const)("fires onTabChange('%s') from the %s pill", async (label, key) => {
    const { user, onTabChange } = setup({ activeTab: "low" });
    await user.click(tabButton(label));
    expect(onTabChange.mock.calls).toEqual([[key]]);
  });
});

// ── tokenizeLine, as it reaches the DOM ──

describe("DecompileView syntax highlighting", () => {
  it("classifies a declaration line token by token", () => {
    setup({ code: "int64_t sub_401000(int a) {" });
    // Full list, not a spot check: the classification is positional, so a change
    // to one alternative of the regex shifts every token after it.
    expect(tokensOf(0)).toEqual([
      ["int64_t", "dc-type"],
      [" ", ""],
      ["sub_401000", "dc-type underline cursor-pointer hover:opacity-80"],
      ["(", "text-theme-secondary"],
      ["int", "dc-type"],
      [" ", ""],
      ["a", ""],
      [")", "text-theme-secondary"],
      [" ", ""],
      ["{", "text-theme-secondary"],
    ]);
  });

  it("classifies keywords, a hex literal and a decimal literal", () => {
    setup({ code: "  if (rax == 0x1F) { return 0; }" });
    expect(tokensOf(0)).toEqual([
      ["  ", ""],
      ["if", "dc-keyword font-semibold"],
      [" ", ""],
      ["(", "text-theme-secondary"],
      ["rax", ""],
      [" ", ""],
      // A multi-character operator is TWO tokens: the operator alternative is a
      // single-character class. Same class either way, so it costs nothing on
      // screen — pinned because it is the kind of thing a reader assumes wrong.
      ["=", "text-theme-secondary"],
      ["=", "text-theme-secondary"],
      [" ", ""],
      ["0x1F", "dc-number"],
      [")", "text-theme-secondary"],
      [" ", ""],
      ["{", "text-theme-secondary"],
      [" ", ""],
      ["return", "dc-keyword font-semibold"],
      [" ", ""],
      ["0", "dc-number"],
      [";", "text-theme-secondary"],
      [" ", ""],
      ["}", "text-theme-secondary"],
    ]);
  });

  it("gives a double-quoted string one token, escapes included", () => {
    setup({ code: '  puts("hi\\n");' });
    expect(tokensOf(0)).toContainEqual(['"hi\\n"', "dc-string"]);
  });

  it("gives a single-quoted char literal the string class, not the number class", () => {
    setup({ code: "  char c = 'x';" });
    expect(tokensOf(0)).toContainEqual(["'x'", "dc-string"]);
    expect(tokensOf(0)).toContainEqual(["char", "dc-type"]);
  });

  it("takes a // comment to end of line as one token", () => {
    setup({ code: "  x = 1; // why 1: see the jcc" });
    const toks = tokensOf(0);
    expect(toks[toks.length - 1]).toEqual(["// why 1: see the jcc", "dc-comment italic"]);
  });

  it("takes a single-line /* */ comment as one token", () => {
    setup({ code: "  /* unlifted: int3 */" });
    expect(tokensOf(0)).toContainEqual(["/* unlifted: int3 */", "dc-comment italic"]);
  });

  it("styles __asm as a comment, the emitter's own escape hatch", () => {
    setup({ code: "  __asm { nop }" });
    expect(tokensOf(0)).toContainEqual(["__asm", "dc-comment italic"]);
  });

  it("gives sub_ and loc_ identifiers the SAME clickable class", () => {
    setup({ code: "  sub_401000();\n  goto loc_4011A0;" });
    const clickable = "dc-type underline cursor-pointer hover:opacity-80";
    expect(tokensOf(0)).toContainEqual(["sub_401000", clickable]);
    // The two are styled identically and BOTH now do something: `sub_`
    // navigates the app to that address, `loc_` scrolls this panel to the
    // label. They were styled the same before either half worked, which made
    // the `loc_` one a dead affordance.
    expect(tokensOf(1)).toContainEqual(["loc_4011A0", clickable]);
  });

  it("gives a struct_N identifier the same clickable class, at a use AND at its typedef", () => {
    setup({ code: "struct struct_1 {\n  struct_1 *p = arg_0;" });
    const clickable = "dc-type underline cursor-pointer hover:opacity-80";
    // The typedef line's own name is a link too: clicking it scrolls to itself,
    // which is harmless, and special-casing the declaring line would need the
    // tokenizer to know which line it is on — it takes one line and no context.
    expect(tokensOf(0)).toContainEqual(["struct_1", clickable]);
    expect(tokensOf(1)).toContainEqual(["struct_1", clickable]);
    // `struct` the keyword stays a keyword; the prefix test is on the token.
    expect(tokensOf(0)).toContainEqual(["struct", "dc-keyword font-semibold"]);
  });

  it("classes `void` as a keyword, so it does NOT match its sibling types", () => {
    // `void` is in both KEYWORDS and TYPES and KEYWORDS is tested first, so
    // `void *p` is coloured like `if`/`return` while `int a` beside it is
    // coloured like a type. Pinned as the current behaviour; see the report.
    setup({ code: "  void *p = 12;\n  int q = 12;" });
    expect(tokensOf(0)).toContainEqual(["void", "dc-keyword font-semibold"]);
    expect(tokensOf(1)).toContainEqual(["int", "dc-type"]);
  });

  it("keeps the code pane focusable by click but out of the tab order", () => {
    // tabIndex -1 is how the ";" shortcut below is reachable at all: the pane
    // takes focus from a click and never from Tab. The component says so.
    setup({ code: "a;" });
    expect(codePane().tabIndex).toBe(-1);
  });

  it("numbers the gutter from 1 while data-line is zero-based", () => {
    setup({ code: "a;\nb;\nc;" });
    expect(lineRow(0).children[0].textContent).toBe("1");
    expect(lineRow(2).children[0].textContent).toBe("3");
    expect(document.querySelectorAll("[data-line]")).toHaveLength(3);
  });
});

// ── Clicking a sub_ token ──

describe("DecompileView sub_ navigation", () => {
  it("navigates with the PARSED HEX address when the click lands on the token", async () => {
    const onNavigate = vi.fn();
    const { user } = setup({ code: "  sub_401000();", onNavigate });
    await user.click(tokenSpan(0, "sub_401000"));
    // 0x401000, not 401000 decimal — the whole point of the parseInt radix.
    expect(onNavigate.mock.calls).toEqual([[0x401000]]);
  });

  it("accepts an uppercase hex body, which is what the emitter produces", async () => {
    const onNavigate = vi.fn();
    const { user } = setup({ code: "  sub_4011A0();", onNavigate });
    await user.click(tokenSpan(0, "sub_4011A0"));
    expect(onNavigate.mock.calls).toEqual([[0x4011a0]]);
  });

  it("does NOT navigate when the click lands on the row, whose textContent is the whole line", async () => {
    const onNavigate = vi.fn();
    const { user } = setup({ code: "  sub_401000();", onNavigate });
    // `handleClick` is delegated on the <pre> and anchors its regex with ^…$, so
    // a click on any ancestor sees a textContent that is not a bare identifier.
    // This is a DOM-only distinction: the handler's argument is the same object
    // in both cases and only `e.target` differs.
    await user.click(lineRow(0));
    expect(onNavigate).not.toHaveBeenCalled();
  });

  it("scrolls to the label instead of navigating, when a loc_ token is clicked", async () => {
    const onNavigate = vi.fn();
    const scrollIntoView = vi.fn();
    // jsdom implements no layout and `domSetup` stubs `scrollIntoView` as a
    // no-op, so this asserts the panel asked the RIGHT ELEMENT to come into
    // view — and nothing whatever about scrolling. Same bound as the
    // highlight-effect test below.
    //
    // ON `HTMLElement.prototype`, NOT `Element.prototype`: that is where
    // `domSetup` installs its no-op, so a spy on `Element` is SHADOWED by it
    // and never fires. The first version of this test did exactly that and
    // read as "the panel does not scroll".
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({
        code: "  goto loc_4011A0;\n  ret;\nloc_4011A0:\n  return 1;",
        onNavigate,
      });
      await user.click(tokenSpan(0, "loc_4011A0"));

      // A `loc_` names a line INSIDE the function already on screen, not an
      // address elsewhere, so following it must not move the app's cursor.
      expect(onNavigate).not.toHaveBeenCalled();
      expect(scrollIntoView).toHaveBeenCalledTimes(1);
      // The element it asked for is the LABEL's line, not the goto's.
      const target = scrollIntoView.mock.instances[0] as HTMLElement;
      expect(target.getAttribute("data-line")).toBe("2");
    } finally {
      restore.mockRestore();
    }
  });

  it("does nothing for a loc_ token with no label in the text", async () => {
    // The control, and the honest bound on the affordance: the panel resolves
    // the label out of the RENDERED TEXT, so a `goto` whose label is not on the
    // page — a body the emitter truncated, or a hand-written fixture like this
    // one — silently does nothing rather than scrolling somewhere arbitrary.
    const onNavigate = vi.fn();
    const scrollIntoView = vi.fn();
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({ code: "  goto loc_4011A0;", onNavigate });
      await user.click(tokenSpan(0, "loc_4011A0"));
      expect(onNavigate).not.toHaveBeenCalled();
      expect(scrollIntoView).not.toHaveBeenCalled();
    } finally {
      restore.mockRestore();
    }
  });

  it("follows a label even with no onNavigate, since following one needs no caller", async () => {
    // Why the `onNavigate` guard moved down the handler rather than staying at
    // the top: a panel mounted without it could not follow a label either, and
    // a label is entirely internal to this component.
    const scrollIntoView = vi.fn();
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({ code: "  goto loc_4011A0;\nloc_4011A0:\n  return 1;" });
      await user.click(tokenSpan(0, "loc_4011A0"));
      expect(scrollIntoView).toHaveBeenCalledTimes(1);
    } finally {
      restore.mockRestore();
    }
  });

  it("still selects the line when a sub_ token is clicked, so both handlers fire", async () => {
    const onNavigate = vi.fn();
    const onLineClick = vi.fn();
    const { user } = setup({ code: "x;\n  sub_401000();", onNavigate, onLineClick });
    await user.click(tokenSpan(1, "sub_401000"));
    // The row <button> handles the click and the <pre> sees it on the way up.
    expect(onLineClick.mock.calls).toEqual([[1]]);
    expect(onNavigate.mock.calls).toEqual([[0x401000]]);
  });

  it("is inert when no onNavigate is supplied", async () => {
    const { user } = setup({ code: "  sub_401000();" });
    await user.click(tokenSpan(0, "sub_401000"));
    // Nothing to assert but the absence of a throw: the early return in
    // `handleClick` is the only thing standing between this and a TypeError.
    expect(codePane()).toBeTruthy();
  });
});

// ── Clicking a struct_N token ──

describe("DecompileView struct_ typedef follow", () => {
  /** A four-line function using one synthesised struct, typedef first. */
  const STRUCT_CODE = [
    "struct struct_1 {",
    "  int field_0x0;",
    "};",
    "int64_t sub_401000(struct_1 *arg_0) {",
    "  return arg_0->field_0x0;",
    "}",
  ].join("\n");

  it("scrolls to the typedef instead of navigating, when a struct_ token is clicked", async () => {
    const onNavigate = vi.fn();
    const scrollIntoView = vi.fn();
    // Same instrument and same bound as the `loc_` row: the panel asked the
    // RIGHT ELEMENT to come into view, and nothing about scrolling. Spied on
    // `HTMLElement.prototype`, where `domSetup` installs its no-op.
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({ code: STRUCT_CODE, onNavigate });
      await user.click(tokenSpan(3, "struct_1"));

      // A `struct_N` names a typedef INSIDE the function on screen, so following
      // it must not move the app's cursor.
      expect(onNavigate).not.toHaveBeenCalled();
      expect(scrollIntoView).toHaveBeenCalledTimes(1);
      // The element it asked for is the TYPEDEF's line, not the parameter's.
      const target = scrollIntoView.mock.instances[0] as HTMLElement;
      expect(target.getAttribute("data-line")).toBe("0");
    } finally {
      restore.mockRestore();
    }
  });

  it("takes the FIRST typedef line when the same name opens twice", async () => {
    // A second `struct struct_1 {` would be an emitter defect, not a choice for
    // this map to make; the row pins that the map does not prefer the later one.
    const scrollIntoView = vi.fn();
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({
        code: "struct struct_1 {\n};\nstruct struct_1 {\n};\n  struct_1 *p;",
      });
      await user.click(tokenSpan(4, "struct_1"));
      const target = scrollIntoView.mock.instances[0] as HTMLElement;
      expect(target.getAttribute("data-line")).toBe("0");
    } finally {
      restore.mockRestore();
    }
  });

  it("does nothing for a struct_ token with no typedef in the text", async () => {
    // The control, and the honest bound: a `struct_N` mentioned with no
    // `struct struct_N {` on the page — the AI tab rewriting the declarations,
    // or a fixture like this one — silently does nothing rather than scrolling
    // somewhere arbitrary. `onNavigate` is supplied so the row can also assert
    // the token is NOT mistaken for a `sub_` and navigated on.
    const onNavigate = vi.fn();
    const scrollIntoView = vi.fn();
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({ code: "  struct_1 *p = arg_0;", onNavigate });
      await user.click(tokenSpan(0, "struct_1"));
      expect(onNavigate).not.toHaveBeenCalled();
      expect(scrollIntoView).not.toHaveBeenCalled();
    } finally {
      restore.mockRestore();
    }
  });

  it("does NOT resolve a typedef from an indented or field-position mention", async () => {
    // The pattern is anchored at column 0 on `struct <name> {`: a nested or
    // indented `struct struct_2 {` is not how `synthesizeStructs` opens a
    // definition, and treating it as one would send the reader into the body
    // of another struct.
    const scrollIntoView = vi.fn();
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({ code: "  struct struct_2 {\n  struct_2 *q;" });
      await user.click(tokenSpan(1, "struct_2"));
      expect(scrollIntoView).not.toHaveBeenCalled();
    } finally {
      restore.mockRestore();
    }
  });

  it("follows a typedef even with no onNavigate, since following one needs no caller", async () => {
    const scrollIntoView = vi.fn();
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({ code: STRUCT_CODE });
      await user.click(tokenSpan(4, "arg_0"));
      expect(scrollIntoView).not.toHaveBeenCalled();
      await user.click(tokenSpan(3, "struct_1"));
      expect(scrollIntoView).toHaveBeenCalledTimes(1);
    } finally {
      restore.mockRestore();
    }
  });
});

// ── Hex constants inside a section are links ──

function section(
  name: string,
  virtualAddress: number,
  virtualSize: number,
  characteristics: number,
): SectionHeader {
  return {
    name,
    virtualAddress,
    virtualSize,
    sizeOfRawData: virtualSize,
    pointerToRawData: virtualAddress,
    pointerToRelocations: 0,
    pointerToLinenumbers: 0,
    numberOfRelocations: 0,
    numberOfLinenumbers: 0,
    characteristics,
  };
}

/** `.text` at 0x401000–0x401FFF, `.rdata` at 0x402000–0x402FFF; the image runs to 0x405000. */
const IMAGE = {
  sections: [
    section(".text", 0x1000, 0x1000, IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ),
    section(".rdata", 0x2000, 0x1000, IMAGE_SCN_MEM_READ),
  ],
  imageBase: 0x400000,
  sizeOfImage: 0x5000,
};

const CONST_CODE = [
  "  x = *(int *)0x402010;", // data
  "  y = var_8 + 0x10;", // the control: a small constant
  "  z = 0x401234;", // code
  "  w = 0x404000;", // inside the image, in no section
].join("\n");

const NUMBER_LINK = "dc-number underline cursor-pointer hover:opacity-80";

describe("DecompileView constants as links", () => {
  it("styles an in-section constant as a link and tags it with where it lands", () => {
    setup({ code: CONST_CODE, ...IMAGE });
    const data = tokenSpan(0, "0x402010");
    expect(data.className).toBe(NUMBER_LINK);
    expect(data.getAttribute("data-const")).toBe("data");
    const code = tokenSpan(2, "0x401234");
    expect(code.className).toBe(NUMBER_LINK);
    expect(code.getAttribute("data-const")).toBe("code");
  });

  it("leaves `0x10` in `var_8 + 0x10` a plain number — THE CONTROL", () => {
    setup({ code: CONST_CODE, ...IMAGE });
    const small = tokenSpan(1, "0x10");
    expect(small.className).toBe("dc-number");
    expect(small.hasAttribute("data-const")).toBe(false);
  });

  it("leaves a constant inside the image but in no section plain", () => {
    // The grounding is the section table, not the image extent — the headers
    // and the alignment gaps are inside the image and hold nothing to show.
    setup({ code: CONST_CODE, ...IMAGE });
    expect(tokenSpan(3, "0x404000").className).toBe("dc-number");
  });

  it("renders every constant plain when the panel is given no image", () => {
    setup({ code: CONST_CODE });
    expect(tokenSpan(0, "0x402010").className).toBe("dc-number");
    expect(tokenSpan(2, "0x401234").className).toBe("dc-number");
  });

  it("navigates the listing for a code constant, and only the listing", async () => {
    const onNavigate = vi.fn();
    const onNavigateData = vi.fn();
    const { user } = setup({ code: CONST_CODE, ...IMAGE, onNavigate, onNavigateData });
    await user.click(tokenSpan(2, "0x401234"));
    expect(onNavigate.mock.calls).toEqual([[0x401234]]);
    expect(onNavigateData).not.toHaveBeenCalled();
  });

  it("hands a data constant to onNavigateData, and only that", async () => {
    const onNavigate = vi.fn();
    const onNavigateData = vi.fn();
    const { user } = setup({ code: CONST_CODE, ...IMAGE, onNavigate, onNavigateData });
    await user.click(tokenSpan(0, "0x402010"));
    expect(onNavigateData.mock.calls).toEqual([[0x402010]]);
    expect(onNavigate).not.toHaveBeenCalled();
  });

  it("does nothing for the control constant, or for one in no section", async () => {
    const onNavigate = vi.fn();
    const onNavigateData = vi.fn();
    const { user } = setup({ code: CONST_CODE, ...IMAGE, onNavigate, onNavigateData });
    await user.click(tokenSpan(1, "0x10"));
    await user.click(tokenSpan(3, "0x404000"));
    expect(onNavigate).not.toHaveBeenCalled();
    expect(onNavigateData).not.toHaveBeenCalled();
  });

  it("does nothing when the panel has no image, even with both callbacks", async () => {
    const onNavigate = vi.fn();
    const onNavigateData = vi.fn();
    const { user } = setup({ code: CONST_CODE, onNavigate, onNavigateData });
    await user.click(tokenSpan(2, "0x401234"));
    expect(onNavigate).not.toHaveBeenCalled();
    expect(onNavigateData).not.toHaveBeenCalled();
  });

  it("is inert for a data constant with no onNavigateData, and a code one with no onNavigate", async () => {
    // The two callbacks are independent — a data constant needs only
    // `onNavigateData`, so its branch sits above the `onNavigate` guard.
    const onNavigateData = vi.fn();
    const { user } = setup({ code: CONST_CODE, ...IMAGE, onNavigateData });
    await user.click(tokenSpan(2, "0x401234"));
    await user.click(tokenSpan(0, "0x402010"));
    expect(onNavigateData.mock.calls).toEqual([[0x402010]]);
  });

  it("does not mistake a sub_ token for a constant, or a constant for a sub_", async () => {
    const onNavigate = vi.fn();
    const onNavigateData = vi.fn();
    const { user } = setup({
      code: "  sub_402010();\n  x = 0x401000;",
      ...IMAGE,
      onNavigate,
      onNavigateData,
    });
    // `sub_402010` names a function by address; it navigates the listing even
    // though the same number as a constant would be classed data.
    await user.click(tokenSpan(0, "sub_402010"));
    expect(onNavigate.mock.calls).toEqual([[0x402010]]);
    expect(onNavigateData).not.toHaveBeenCalled();
  });
});

// ── sub_ hover shows the recovered signature ──

describe("DecompileView sub_ hover", () => {
  it("puts subTitle's answer on the sub_ span as its title, asked by parsed address", () => {
    const subTitle = vi.fn((addr: number) =>
      addr === 0x401000 ? "fastcall, 2 params" : undefined,
    );
    setup({ code: "  sub_401000();\n  sub_4011A0();", subTitle });
    expect(tokenSpan(0, "sub_401000").getAttribute("title")).toBe("fastcall, 2 params");
    // `undefined` means "nothing to say": no attribute, not an empty one.
    expect(tokenSpan(1, "sub_4011A0").hasAttribute("title")).toBe(false);
    // Asked with the hex-parsed address, once per sub_ token per render.
    expect(subTitle.mock.calls.map((c) => c[0]).sort()).toEqual([0x401000, 0x4011a0].sort());
  });

  it("sets no title when no subTitle is supplied", () => {
    setup({ code: "  sub_401000();" });
    expect(tokenSpan(0, "sub_401000").hasAttribute("title")).toBe(false);
  });

  it("asks nothing for tokens that are not sub_", () => {
    const subTitle = vi.fn(() => "never");
    setup({ code: "  goto loc_401000;\n  x = 0x401000;" });
    setup({ code: "  struct_1 *p;", subTitle });
    expect(subTitle).not.toHaveBeenCalled();
  });
});

// ── Loading, error, empty ──

describe("DecompileView loading, error and empty arms", () => {
  it("shows the decompiling spinner when loading with no code yet", () => {
    setup({ loading: true, code: "" });
    expect(screen.getByText("Decompiling...")).toBeTruthy();
    expect(codePane()).toBeNull();
  });

  it("says 'Generating...' instead on the AI tab", () => {
    setup({ loading: true, code: "", activeTab: "ai" });
    expect(screen.getByText("Generating...")).toBeTruthy();
  });

  it("shows the code, not the spinner, once code has arrived mid-load", () => {
    // The AI tab streams: `loading` stays true while `code` grows, and the
    // condition is `loading && !code` precisely so the partial text is shown.
    setup({ loading: true, code: "int x;", activeTab: "ai", aiMode: "explain" });
    expect(screen.queryByText("Generating...")).toBeNull();
    expect(tokensOf(0)).toContainEqual(["int", "dc-type"]);
  });

  it("renders the error banner above the content, not instead of it", () => {
    setup({ error: "decompilation failed: unsupported", code: "int x;" });
    expect(screen.getByText("decompilation failed: unsupported")).toBeTruthy();
    // An error does not withhold whatever code was recovered.
    expect(codePane()).toBeTruthy();
  });

  it("prompts for Explain or Enhance on an empty AI tab", () => {
    setup({ code: "", activeTab: "ai" });
    expect(screen.getByText(/Choose/)).toBeTruthy();
    expect(screen.getByText("Explain")).toBeTruthy();
    expect(screen.getByText("Enhance")).toBeTruthy();
    expect(codePane()).toBeNull();
  });

  it("renders an EMPTY code pane on a non-AI tab with no code and no error", () => {
    // Pinned because it is the one state with nothing to read: the else arm is
    // taken, so the panel is a blank <pre> with no message at all. See report.
    setup({ code: "", activeTab: "low" });
    expect(codePane()).toBeTruthy();
    expect(document.querySelectorAll("[data-line]")).toHaveLength(0);
  });
});

// ── The admissions line ──

/**
 * The Low Level panel's admissions line (peek-a-bin-n9cl.7): what the C below
 * admits it did not recover, one button per kind, each scrolling to the FIRST
 * site. `admissionSummary` is pinned as a pure function in
 * `decompileTabsState.test.ts`; what only a render can settle is that the line
 * appears exactly when there is something to admit, prints the summary's text
 * and nothing else, and that a click asks the RIGHT `data-line` element to come
 * into view — nothing about scrolling, for the reason given at the `loc_` test.
 */
describe("DecompileView admissions line", () => {
  const CODE = [
    "int sub_401000(void) {",
    "    intptr_t __unrecovered_1; /* not recovered: jb */",
    "",
    "    if (__unrecovered_1 /* jb */) {",
    "        /* unlifted: leave */;",
    "        goto loc_401028;",
    "    }",
    "loc_401028:",
    "    return 0;",
    "}",
  ].join("\n");
  const ADM: DecompileAdmissions = { unrecovered: [3], unlifted: [4], gotos: [5] };

  const line = () => screen.queryByTestId("decompile-admissions");

  it("renders no line when there are no admissions", () => {
    setup({ code: CODE });
    expect(line()).toBeNull();
  });

  it("renders no line for a function recovered whole", () => {
    setup({ code: CODE, admissions: emptyAdmissions() });
    expect(line()).toBeNull();
  });

  it("prints exactly the summary's clauses, in its order, separated as it says", () => {
    setup({ code: CODE, admissions: ADM });
    const expected = admissionSummary(ADM)
      .map((p) => p.text)
      .join(ADMISSION_SEPARATOR);
    // Whitespace-normalised: the separator is its own span, so the DOM's text has
    // the clauses and the dots but not the summary's spaces around them.
    expect(line()?.textContent?.replace(/\s+/g, "")).toBe(expected.replace(/\s+/g, ""));
    expect(line()?.textContent).toContain("1 unrecovered");
    expect(line()?.textContent).toContain("1 unlifted");
    expect(line()?.textContent).toContain("1 goto");
  });

  it("omits a kind with no sites", () => {
    setup({ code: CODE, admissions: { ...emptyAdmissions(), gotos: [5, 5] } });
    expect(line()?.textContent).toContain("2 goto");
    expect(line()?.textContent).not.toContain("unrecovered");
    expect(line()?.textContent).not.toContain("unlifted");
  });

  it.each([
    ["1 unrecovered", "3"],
    ["1 unlifted", "4"],
    ["1 goto", "5"],
  ])("clicking %s scrolls to the first site, data-line %s", async (label, dataLine) => {
    const scrollIntoView = vi.fn();
    // On `HTMLElement.prototype`, where `domSetup` installs its no-op — see the
    // `loc_` test above for why a spy on `Element` never fires.
    const restore = vi
      .spyOn(HTMLElement.prototype, "scrollIntoView")
      .mockImplementation(scrollIntoView);
    try {
      const { user } = setup({ code: CODE, admissions: ADM });
      await user.click(screen.getByRole("button", { name: label }));

      expect(scrollIntoView).toHaveBeenCalledTimes(1);
      const target = scrollIntoView.mock.instances[0] as HTMLElement;
      expect(target.getAttribute("data-line")).toBe(dataLine);
    } finally {
      restore.mockRestore();
    }
  });

  it("does not move the app's cursor when a clause is clicked", async () => {
    // A site is a line INSIDE the function on screen, as a `loc_` label is; the
    // buttons must not reach `onNavigate` or `onLineClick`.
    const onNavigate = vi.fn();
    const onLineClick = vi.fn();
    const { user } = setup({ code: CODE, admissions: ADM, onNavigate, onLineClick });
    await user.click(screen.getByRole("button", { name: "1 goto" }));
    expect(onNavigate).not.toHaveBeenCalled();
    expect(onLineClick).not.toHaveBeenCalled();
  });

  it("a pipeline fault renders the banner with an empty pane and no admissions line", () => {
    // What the client's throw on `DecompileResult.error` reaches: the hook's
    // LOAD_ERR, so `error` is set and `code` is empty. The pane is the blank
    // <pre> of the no-code arm; nothing is admitted because nothing was emitted.
    setup({ code: "", error: "Decompilation error for sub_401000: boom" });
    expect(screen.getByText("Decompilation error for sub_401000: boom")).toBeTruthy();
    expect(codePane()).toBeTruthy();
    expect(document.querySelectorAll("[data-line]")).toHaveLength(0);
    expect(line()).toBeNull();
  });
});

// ── AI controls and isStreaming ──

describe("DecompileView AI controls", () => {
  it("offers Explain and Enhance on the AI tab when not loading", async () => {
    const onExplain = vi.fn();
    const onEnhance = vi.fn();
    const { user } = setup({ activeTab: "ai", code: "", onExplain, onEnhance });
    await user.click(screen.getByTitle("Explain with AI"));
    await user.click(screen.getByTitle("Enhance with AI"));
    expect(onExplain).toHaveBeenCalledTimes(1);
    expect(onEnhance).toHaveBeenCalledTimes(1);
  });

  it("swaps them for Cancel while streaming", async () => {
    const onCancelAI = vi.fn();
    const { user } = setup({
      activeTab: "ai",
      code: "int x;",
      loading: true,
      aiMode: "enhance",
      onCancelAI,
      onExplain: vi.fn(),
    });
    expect(screen.queryByTitle("Explain with AI")).toBeNull();
    await user.click(screen.getByTitle("Cancel AI"));
    expect(onCancelAI).toHaveBeenCalledTimes(1);
  });

  it("shows NO cancel button when loading with no aiMode, so there is no way out", () => {
    // `isStreaming` requires all three of activeTab==="ai", loading and a
    // non-null aiMode. With aiMode null the Explain/Enhance pair is hidden by
    // `!loading` and Cancel is hidden by `isStreaming`. Pinned; see report.
    setup({
      activeTab: "ai",
      code: "int x;",
      loading: true,
      aiMode: null,
      onCancelAI: vi.fn(),
      onExplain: vi.fn(),
    });
    expect(screen.queryByTitle("Cancel AI")).toBeNull();
    expect(screen.queryByTitle("Explain with AI")).toBeNull();
  });

  it("shows no Cancel while loading on a non-AI tab", () => {
    setup({
      activeTab: "low",
      code: "int x;",
      loading: true,
      aiMode: "enhance",
      onCancelAI: vi.fn(),
    });
    expect(screen.queryByTitle("Cancel AI")).toBeNull();
  });
});

// ── The high-level engine indicator ──

describe("DecompileView high-level engine indicator", () => {
  it("says '(not available)' for engine none", () => {
    setup({ activeTab: "high", highLevelEngine: "none" });
    expect(screen.getByText("(not available)")).toBeTruthy();
  });

  it("says '(retdec fallback)' for engine retdec", () => {
    setup({ activeTab: "high", highLevelEngine: "retdec" });
    expect(screen.getByText("(retdec fallback)")).toBeTruthy();
  });

  it("says nothing for ghidra, the engine that needs no caveat", () => {
    setup({ activeTab: "high", highLevelEngine: "ghidra" });
    // Asserted as "no parenthesised note at all", not as "not one of the other
    // two strings". The narrow version was written first and its negative
    // control came back INERT: replacing the `: null` arm with a third string
    // left it green, because a test naming the two strings it knows about
    // cannot see a third. `(sync disabled)` is the only other note in the header
    // and is off in this fixture.
    expect(screen.queryByText(/^\(.*\)$/)).toBeNull();
  });

  it("says nothing on another tab even when an engine is known", () => {
    setup({ activeTab: "low", highLevelEngine: "none" });
    expect(screen.queryByText("(not available)")).toBeNull();
  });

  it("announces a disabled sync separately from the engine", () => {
    setup({ activeTab: "ai", code: "int x;", syncDisabled: true });
    expect(screen.getByText("(sync disabled)")).toBeTruthy();
  });
});

// ── Highlighting, line clicks, auto-scroll ──

describe("DecompileView line highlighting and clicks", () => {
  it("marks the highlighted rows and only those", () => {
    setup({ code: "a;\nb;\nc;", highlightLines: new Set([1]) });
    expect(lineRow(0).className.includes("bg-blue-900/30")).toBe(false);
    expect(lineRow(1).className.includes("bg-blue-900/30")).toBe(true);
    expect(lineRow(2).className.includes("bg-blue-900/30")).toBe(false);
  });

  it("reports the clicked line by its zero-based number", async () => {
    const onLineClick = vi.fn();
    const { user } = setup({ code: "a;\nb;\nc;", onLineClick });
    await user.click(lineRow(2));
    expect(onLineClick.mock.calls).toEqual([[2]]);
  });

  it("calls scrollIntoView on the LOWEST highlighted line", () => {
    // `domSetup` installs scrollIntoView as a no-op because jsdom has none; a
    // spy on the prototype is how the effect is observed.
    //
    // WHAT THIS PROVES: the effect ran, resolved `Math.min` over the Set, found
    // the row by its data-line attribute, and called the method. It proves
    // NOTHING about whether anything scrolled or ended up visible — jsdom does
    // no layout and every scroll offset there is a constant 0.
    const spy = vi.spyOn(HTMLElement.prototype, "scrollIntoView").mockImplementation(() => {});
    // Insertion order deliberately not ascending, so a `for…of` over the Set
    // would pick 2 and `Math.min` picks 1.
    setup({ code: "a;\nb;\nc;", highlightLines: new Set([2, 1]) });
    expect(spy).toHaveBeenCalledTimes(1);
    expect(spy.mock.instances[0]).toBe(lineRow(1));
    expect(spy.mock.calls[0][0]).toEqual({ block: "nearest", behavior: "smooth" });
    spy.mockRestore();
  });

  it("does not scroll when nothing is highlighted", () => {
    const spy = vi.spyOn(HTMLElement.prototype, "scrollIntoView").mockImplementation(() => {});
    setup({ code: "a;\nb;\nc;", highlightLines: new Set() });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it("does not scroll when the highlighted line does not exist", () => {
    const spy = vi.spyOn(HTMLElement.prototype, "scrollIntoView").mockImplementation(() => {});
    setup({ code: "a;", highlightLines: new Set([99]) });
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });
});

// ── Toolbar ──

describe("DecompileView toolbar", () => {
  it("copies the whole code, not the rendered text", () => {
    setup({ code: "int64_t f(void) {\n  return 0;\n}" });
    const writeText = stubClipboard();
    fireEvent.click(screen.getByTitle("Copy to clipboard"));
    // The `code` prop verbatim: no line numbers, no token splitting.
    expect(writeText.mock.calls).toEqual([["int64_t f(void) {\n  return 0;\n}"]]);
  });

  /**
   * COPY CARRIES THE COMMENTS. The on-screen comment is a `<span>` beside the
   * line; the old Copy put the bare `code` prop on the clipboard, so a reader
   * who annotated a function and pasted it elsewhere lost every annotation.
   * `codeWithComments` (the leaf) builds the string and `formatComment` is
   * shared with the render, so the trailer is the text on screen.
   *
   * The assertion is SYNCHRONOUS after the click, deliberately: `copyText`
   * must be reached before the first suspension (clipboard writes must stay
   * inside the user gesture), and a `writeText` recorded without an `await`
   * is what shows the string was built and handed over on the same tick.
   */
  const COMMENTED = {
    code: "int f(void) {\n  x = 1;\n  y = 2;\n}",
    lineMap: new Map([
      [1, 0x401004],
      [2, 0x401008],
    ]),
    comments: { 0x401004: "why 1" },
  };

  it("includes a comment as a ` // ` trailer on its line, and says Shift copies without", () => {
    setup(COMMENTED);
    const writeText = stubClipboard();
    const btn = screen.getByTitle("Copy (Shift: without comments)");
    fireEvent.click(btn);
    expect(writeText.mock.calls).toEqual([["int f(void) {\n  x = 1; // why 1\n  y = 2;\n}"]]);
  });

  it("copies the raw code on Shift-click", () => {
    setup(COMMENTED);
    const writeText = stubClipboard();
    fireEvent.click(screen.getByTitle("Copy (Shift: without comments)"), { shiftKey: true });
    expect(writeText.mock.calls).toEqual([[COMMENTED.code]]);
  });

  it("puts the same text on the clipboard that the screen shows for a multi-line comment", () => {
    setup({ ...COMMENTED, comments: { 0x401004: "first\nsecond" } });
    // The rendered span and the trailer share `formatComment`.
    expect(screen.getByText("// first [...]")).toBeTruthy();
    const writeText = stubClipboard();
    fireEvent.click(screen.getByTitle("Copy (Shift: without comments)"));
    expect(writeText.mock.calls[0][0]).toContain("  x = 1; // first [...]\n");
  });

  it("copies byte-identical code when the map is present but nothing is commented", () => {
    setup({ ...COMMENTED, comments: {} });
    const writeText = stubClipboard();
    fireEvent.click(screen.getByTitle("Copy (Shift: without comments)"));
    expect(writeText.mock.calls).toEqual([[COMMENTED.code]]);
  });

  it("copies raw on the AI tab, where the line map numbers a different body", () => {
    // `syncDisabled` is the AI tab's flag. The render already suppresses the
    // on-screen comments there for this reason; Copy follows it, and the title
    // drops the Shift hint because there is nothing for Shift to leave out.
    setup({ ...COMMENTED, activeTab: "ai", syncDisabled: true });
    expect(screen.queryByTitle("Copy (Shift: without comments)")).toBeNull();
    const writeText = stubClipboard();
    fireEvent.click(screen.getByTitle("Copy to clipboard"));
    expect(writeText.mock.calls).toEqual([[COMMENTED.code]]);
  });

  /**
   * THE PLAIN-HTTP DEPLOYMENT (`peek-a-bin-p0tz`) at a site with NO feedback
   * affordance, which is fourteen of the eighteen.
   *
   * `navigator.clipboard` is `[SecureContext]`, so on the nginx HTTP
   * deployment the object is absent and `navigator.clipboard.writeText(code)`
   * threw a TypeError on click. All this asserts is that it no longer does —
   * and that is the whole of the fix at these sites.
   *
   * WHAT THE USER GETS TOLD HERE: nothing. Deliberately. The app has no toast
   * or notification mechanism of any kind (grepped for at `09a160e`), and
   * building one is a feature rather than this bug fix, so a Copy at a site
   * with no existing affordance now fails silently instead of throwing. That
   * is recorded as a known gap, not as a finished job.
   *
   * STAND-IN, NOT A BROWSER: the absence is manufactured here.
   */
  it("reports no error when there is no clipboard", () => {
    setup({ code: "int64_t f(void) { return 0; }" });
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true });

    // THE INSTRUMENT, and it had to be this one: an `expect(...).not.toThrow()`
    // around the click is INERT here — measured, with the unguarded call
    // restored, 87/87 still green. React does not rethrow out of
    // `dispatchEvent`; it reports the error, which jsdom surfaces as a window
    // `error` event. And this handler changes no state afterwards, so a throw
    // has no DOM consequence to assert on either. The report is the only trace
    // a TypeError leaves at a site like this — which is fourteen of the
    // eighteen.
    const errors: unknown[] = [];
    const onError = (e: ErrorEvent) => {
      e.preventDefault();
      errors.push(e.error ?? e.message);
    };
    window.addEventListener("error", onError);
    try {
      fireEvent.click(screen.getByTitle("Copy to clipboard"));
    } finally {
      window.removeEventListener("error", onError);
    }

    expect(errors).toEqual([]);
    expect(screen.getByTitle("Copy to clipboard")).toBeTruthy();
  });

  it("closes on Close", async () => {
    const { user, onClose } = setup();
    await user.click(screen.getByTitle("Close (D)"));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders no Sync button unless a toggle is supplied", () => {
    setup();
    expect(screen.queryByText("Sync")).toBeNull();
  });

  it.each([
    [true, "Scroll sync on — click to disable"],
    [false, "Scroll sync off — click to enable"],
  ] as const)("titles the Sync button for scrollSyncEnabled=%s", async (enabled, title) => {
    const onScrollSyncToggle = vi.fn();
    const { user } = setup({ scrollSyncEnabled: enabled, onScrollSyncToggle });
    const btn = screen.getByText("Sync");
    expect(btn.getAttribute("title")).toBe(title);
    expect(btn.className.includes("bg-blue-600")).toBe(enabled);
    await user.click(btn);
    expect(onScrollSyncToggle).toHaveBeenCalledTimes(1);
  });
});

// ── The context menu, and its document-not-window wiring ──

const CODE_3 = "a;\nb;\nc;";
const MAP_3 = () =>
  new Map([
    [0, 0x401000],
    [1, 0x401004],
  ]);

function openCtxMenu(overrides: Partial<Props> = {}) {
  const onEditComment = vi.fn();
  const r = setup({
    code: CODE_3,
    lineMap: MAP_3(),
    comments: {},
    onEditComment,
    onCommitComment: vi.fn(),
    onDeleteComment: vi.fn(),
    ...overrides,
  });
  fireEvent.contextMenu(lineRow(1), { clientX: 120, clientY: 240 });
  return { ...r, onEditComment };
}

const ctxMenu = () => screen.queryByText(/^(Add|Edit) comment$/)?.closest("div") ?? null;

describe("DecompileView context menu", () => {
  it("opens at the pointer on a line that has an address", () => {
    openCtxMenu();
    const menu = ctxMenu();
    expect(menu).toBeTruthy();
    expect((menu as HTMLElement).style.left).toBe("120px");
    expect((menu as HTMLElement).style.top).toBe("240px");
    expect(screen.getByText("Add comment")).toBeTruthy();
    expect(screen.getByText("Copy address")).toBeTruthy();
  });

  it("suppresses the browser menu only when it opens its own", () => {
    setup({ code: CODE_3, lineMap: MAP_3(), comments: {}, onEditComment: vi.fn() });
    // Line 1 has an address: the default is prevented (fireEvent returns false).
    expect(fireEvent.contextMenu(lineRow(1), { clientX: 1, clientY: 1 })).toBe(false);
  });

  it("refuses on a line with no address, and leaves the browser menu alone", () => {
    setup({ code: CODE_3, lineMap: MAP_3(), comments: {}, onEditComment: vi.fn() });
    // Line 2 is absent from the map, so the native default must survive.
    expect(fireEvent.contextMenu(lineRow(2), { clientX: 1, clientY: 1 })).toBe(true);
    expect(ctxMenu()).toBeNull();
  });

  it("refuses when sync is disabled", () => {
    setup({
      code: CODE_3,
      activeTab: "ai",
      syncDisabled: true,
      lineMap: MAP_3(),
      comments: {},
      onEditComment: vi.fn(),
    });
    expect(fireEvent.contextMenu(lineRow(1), { clientX: 1, clientY: 1 })).toBe(true);
    expect(ctxMenu()).toBeNull();
  });

  it("refuses when there is no lineMap at all", () => {
    setup({ code: CODE_3, comments: {}, onEditComment: vi.fn() });
    expect(fireEvent.contextMenu(lineRow(1), { clientX: 1, clientY: 1 })).toBe(true);
    expect(ctxMenu()).toBeNull();
  });

  it("says 'Edit comment' where one already exists", () => {
    openCtxMenu({ comments: { 0x401004: "already here" } });
    expect(screen.getByText("Edit comment")).toBeTruthy();
    expect(screen.queryByText("Add comment")).toBeNull();
  });

  it("hands the line's own address to onEditComment, with the existing text", async () => {
    const { user, onEditComment } = openCtxMenu({ comments: { 0x401004: "already here" } });
    await user.click(screen.getByText("Edit comment"));
    expect(onEditComment.mock.calls).toEqual([[{ address: 0x401004, value: "already here" }]]);
    expect(ctxMenu()).toBeNull();
  });

  it("copies the address as UPPERCASE hex with no 0x", () => {
    openCtxMenu({ lineMap: new Map([[1, 0x4011ab]]) });
    const writeText = stubClipboard();
    fireEvent.click(screen.getByText("Copy address"));
    expect(writeText.mock.calls).toEqual([["4011AB"]]);
    expect(ctxMenu()).toBeNull();
  });

  it("stays open when a click lands inside it", () => {
    openCtxMenu();
    fireEvent.click(ctxMenu() as HTMLElement);
    expect(ctxMenu()).toBeTruthy();
  });
});

describe("DecompileView context menu dismissal wiring", () => {
  it("dismisses on a document click", () => {
    openCtxMenu();
    fireEvent.click(document.body);
    expect(ctxMenu()).toBeNull();
  });

  it("does NOT dismiss on mousedown, because it is wired to click", () => {
    // The two are not interchangeable and `useDismissOnOutsideClick` takes the
    // choice as an option. `mousedown` fires first in a browser, so a component
    // wired to it closes before the click reaches React's handlers.
    openCtxMenu();
    fireEvent.mouseDown(document.body);
    expect(ctxMenu()).toBeTruthy();
    fireEvent.click(document.body);
    expect(ctxMenu()).toBeNull();
  });

  it("registers its dismissal listeners on document and not on window", () => {
    // THE ASYMMETRY THE COMPONENT'S OWN COMMENT NAMES: this popup listens on
    // `document`, where every other one in the app listens on `window`.
    //
    // Asserted by watching the registration rather than by dispatching, and
    // that is a MEASURED choice. The obvious behavioural version — dispatch a
    // click AT `window`, which never reaches a document listener since
    // propagation runs document → window — was written first and its negative
    // control came back INERT: under `target: "window"` the listener does fire,
    // but `e.target` is then `window`, and jsdom's `Node.contains` rejects a
    // non-Node argument with a TypeError that escapes the listener before
    // `onDismiss` is reached (`useDismissOnOutsideClick.ts:48`). The menu stayed
    // open for the wrong reason and the assertion passed. That artefact has no
    // browser counterpart — no `click` event has `window` as its target — so the
    // question is real and only the instrument was wrong.
    const docSpy = vi.spyOn(document, "addEventListener");
    const winSpy = vi.spyOn(window, "addEventListener");
    openCtxMenu();
    const events = (spy: typeof docSpy) => spy.mock.calls.map((c) => c[0]);
    // `click`, not `mousedown`: the two are not interchangeable and the hook
    // takes the choice as an option.
    expect(events(docSpy)).toContain("click");
    expect(events(docSpy)).toContain("keydown");
    expect(events(docSpy)).not.toContain("mousedown");
    expect(events(winSpy)).not.toContain("click");
    docSpy.mockRestore();
    winSpy.mockRestore();
  });

  it("dismisses on Escape at the document", () => {
    openCtxMenu();
    fireEvent.keyDown(document, { key: "Escape" });
    expect(ctxMenu()).toBeNull();
  });

  it("dismisses on Escape in the code pane by its OWN handler, not only the hook's", () => {
    openCtxMenu();
    // There are two redundant routes here and a plain keyDown cannot tell them
    // apart: `handleKeyDown`'s own Escape arm fires at the React root container,
    // and `dismissOnEscape` fires at `document` a moment later. Deleting the
    // component's arm left the test green — an INERT control until this
    // stopPropagation was added.
    //
    // RTL mounts into a <div> under <body>, and React 18 attaches its listeners
    // to that container. So a bubble-phase listener on <body> sits ABOVE React's
    // and BELOW document's: it lets the component's handler run and stops the
    // hook's from ever seeing the event.
    const stop = (e: Event) => e.stopPropagation();
    document.body.addEventListener("keydown", stop);
    try {
      fireEvent.keyDown(codePane(), { key: "Escape" });
      expect(ctxMenu()).toBeNull();
    } finally {
      document.body.removeEventListener("keydown", stop);
    }
  });

  it("attaches no dismissal listeners while closed", () => {
    // Nothing to dismiss, so a stray click must not be able to throw or to
    // re-enter the state setter. `active: false` is what keeps the listeners off.
    setup({ code: CODE_3, lineMap: MAP_3(), comments: {}, onEditComment: vi.fn() });
    fireEvent.click(document.body);
    expect(ctxMenu()).toBeNull();
  });
});

// ── The ";" comment shortcut ──

describe("DecompileView ';' comment shortcut", () => {
  function semicolonSetup(overrides: Partial<Props> = {}) {
    const onEditComment = vi.fn();
    const docKeyDown = vi.fn();
    document.addEventListener("keydown", docKeyDown);
    const r = setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      onEditComment,
      ...overrides,
    });
    return {
      ...r,
      onEditComment,
      docKeyDown,
      detach: () => document.removeEventListener("keydown", docKeyDown),
    };
  }

  it("opens the editor on the first highlighted line that HAS an address", () => {
    const { onEditComment, detach } = semicolonSetup({
      // Line 2 has no entry in the map and is first in iteration order, so the
      // loop must walk past it rather than stopping.
      highlightLines: new Set([2, 1]),
    });
    fireEvent.keyDown(codePane(), { key: ";" });
    expect(onEditComment.mock.calls).toEqual([[{ address: 0x401004, value: "" }]]);
    detach();
  });

  it("seeds the editor with the existing comment text", () => {
    const { onEditComment, detach } = semicolonSetup({
      highlightLines: new Set([0]),
      comments: { 0x401000: "existing" },
    });
    fireEvent.keyDown(codePane(), { key: ";" });
    expect(onEditComment.mock.calls).toEqual([[{ address: 0x401000, value: "existing" }]]);
    detach();
  });

  it("consumes the event when it matched: preventDefault AND stopPropagation", () => {
    const { docKeyDown, detach } = semicolonSetup({ highlightLines: new Set([0]) });
    // fireEvent returns false when the default was prevented.
    expect(fireEvent.keyDown(codePane(), { key: ";" })).toBe(false);
    // React attaches at the root container, so stopPropagation on the synthetic
    // event stops the native one before it reaches document. This is the half
    // that lets the parent's own ";" binding coexist with this one.
    expect(docKeyDown).not.toHaveBeenCalled();
    detach();
  });

  it("deliberately lets the event BUBBLE when no highlighted line has an address", () => {
    const { onEditComment, docKeyDown, detach } = semicolonSetup({
      highlightLines: new Set([2]),
    });
    expect(fireEvent.keyDown(codePane(), { key: ";" })).toBe(true);
    expect(onEditComment).not.toHaveBeenCalled();
    // The parent handles it instead, against `currentAddress`. Not an oversight
    // — the component's own comment says so.
    expect(docKeyDown).toHaveBeenCalledTimes(1);
    detach();
  });

  it("also bubbles when nothing is highlighted at all", () => {
    const { onEditComment, docKeyDown, detach } = semicolonSetup({});
    expect(fireEvent.keyDown(codePane(), { key: ";" })).toBe(true);
    expect(onEditComment).not.toHaveBeenCalled();
    expect(docKeyDown).toHaveBeenCalledTimes(1);
    detach();
  });

  it("bubbles when sync is disabled", () => {
    const { onEditComment, docKeyDown, detach } = semicolonSetup({
      activeTab: "ai",
      syncDisabled: true,
      highlightLines: new Set([0]),
    });
    expect(fireEvent.keyDown(codePane(), { key: ";" })).toBe(true);
    expect(onEditComment).not.toHaveBeenCalled();
    expect(docKeyDown).toHaveBeenCalledTimes(1);
    detach();
  });
});

// ── Inline comment display and editing ──

describe("DecompileView inline comments", () => {
  it("renders a comment against the line its address maps to", () => {
    setup({ code: CODE_3, lineMap: MAP_3(), comments: { 0x401004: "the guard" } });
    expect(lineRow(1).textContent).toContain("// the guard");
    expect(lineRow(0).textContent).not.toContain("//");
  });

  it("truncates a multi-line comment to its first line plus [...]", () => {
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: { 0x401000: "first line\nsecond line\nthird" },
    });
    expect(lineRow(0).textContent).toContain("// first line [...]");
    expect(lineRow(0).textContent).not.toContain("second line");
  });

  it("adds no [...] to a single-line comment", () => {
    setup({ code: CODE_3, lineMap: MAP_3(), comments: { 0x401000: "just one" } });
    expect(lineRow(0).textContent).toContain("// just one");
    expect(lineRow(0).textContent).not.toContain("[...]");
  });

  it("withholds comments entirely when sync is disabled", () => {
    // `lineAddr` is only resolved when sync is on, so on the AI tab — whose
    // line map describes a different text — no comment is attributed at all.
    setup({
      code: CODE_3,
      activeTab: "ai",
      syncDisabled: true,
      lineMap: MAP_3(),
      comments: { 0x401000: "the guard" },
    });
    expect(lineRow(0).textContent).not.toContain("the guard");
  });

  it("replaces the comment with a focused textarea while editing", () => {
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: { 0x401000: "the guard" },
      editingComment: { address: 0x401000, value: "the guard" },
      onEditComment: vi.fn(),
      onCommitComment: vi.fn(),
      onDeleteComment: vi.fn(),
    });
    const ta = screen.getByRole("textbox") as HTMLTextAreaElement;
    expect(ta.value).toBe("the guard");
    // `focusOnMount` is a callback ref, so this is the render's own doing.
    expect(document.activeElement).toBe(ta);
    // The static rendering of the same comment is withheld while editing.
    expect(lineRow(0).textContent).not.toContain("// the guard");
  });

  it("sizes the textarea to the comment's line count, minimum two rows", () => {
    const base = {
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      onEditComment: vi.fn(),
      onCommitComment: vi.fn(),
      onDeleteComment: vi.fn(),
    } satisfies Partial<Props>;
    const { unmount } = setup({ ...base, editingComment: { address: 0x401000, value: "one" } });
    expect((screen.getByRole("textbox") as HTMLTextAreaElement).rows).toBe(2);
    unmount();
    setup({ ...base, editingComment: { address: 0x401000, value: "a\nb\nc" } });
    expect((screen.getByRole("textbox") as HTMLTextAreaElement).rows).toBe(3);
  });

  it("reports every keystroke through onEditComment, keeping the address", async () => {
    const onEditComment = vi.fn();
    const { user } = setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      editingComment: { address: 0x401000, value: "" },
      onEditComment,
      onCommitComment: vi.fn(),
      onDeleteComment: vi.fn(),
    });
    await user.type(screen.getByRole("textbox"), "x");
    // Controlled from the prop, so the value does not accumulate here; what is
    // asserted is that the edit is reported with its address intact.
    expect(onEditComment.mock.calls).toEqual([[{ address: 0x401000, value: "x" }]]);
  });

  it("commits the TRIMMED text on Enter and closes the editor", () => {
    const onCommitComment = vi.fn();
    const onDeleteComment = vi.fn();
    const onEditComment = vi.fn();
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      editingComment: { address: 0x401000, value: "  spaced  " },
      onEditComment,
      onCommitComment,
      onDeleteComment,
    });
    expect(fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" })).toBe(false);
    expect(onCommitComment.mock.calls).toEqual([[0x401000, "spaced"]]);
    expect(onDeleteComment).not.toHaveBeenCalled();
    expect(onEditComment.mock.calls).toEqual([[null]]);
  });

  it("DELETES rather than commits when Enter lands on whitespace only", () => {
    const onCommitComment = vi.fn();
    const onDeleteComment = vi.fn();
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: { 0x401000: "old" },
      editingComment: { address: 0x401000, value: "   " },
      onEditComment: vi.fn(),
      onCommitComment,
      onDeleteComment,
    });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter" });
    expect(onCommitComment).not.toHaveBeenCalled();
    expect(onDeleteComment.mock.calls).toEqual([[0x401000]]);
  });

  it("keeps the editor open on Shift+Enter, which is how a second line is typed", () => {
    const onCommitComment = vi.fn();
    const onEditComment = vi.fn();
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      editingComment: { address: 0x401000, value: "line one" },
      onEditComment,
      onCommitComment,
      onDeleteComment: vi.fn(),
    });
    expect(fireEvent.keyDown(screen.getByRole("textbox"), { key: "Enter", shiftKey: true })).toBe(
      true,
    );
    expect(onCommitComment).not.toHaveBeenCalled();
    expect(onEditComment).not.toHaveBeenCalled();
  });

  it("abandons the edit on Escape without committing", () => {
    const onCommitComment = vi.fn();
    const onEditComment = vi.fn();
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      editingComment: { address: 0x401000, value: "typed but unwanted" },
      onEditComment,
      onCommitComment,
      onDeleteComment: vi.fn(),
    });
    fireEvent.keyDown(screen.getByRole("textbox"), { key: "Escape" });
    expect(onCommitComment).not.toHaveBeenCalled();
    expect(onEditComment).toHaveBeenCalledWith(null);
  });

  it("abandons the edit on blur, so clicking away discards it", () => {
    const onCommitComment = vi.fn();
    const onEditComment = vi.fn();
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      editingComment: { address: 0x401000, value: "typed but unwanted" },
      onEditComment,
      onCommitComment,
      onDeleteComment: vi.fn(),
    });
    fireEvent.blur(screen.getByRole("textbox"));
    expect(onCommitComment).not.toHaveBeenCalled();
    expect(onEditComment).toHaveBeenCalledWith(null);
  });

  it("renders no editor when the commit/delete callbacks are absent", () => {
    // All three are required by the render guard, so a caller that supplies only
    // `onEditComment` gets the comment hidden and no way to edit it.
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: { 0x401000: "the guard" },
      editingComment: { address: 0x401000, value: "the guard" },
      onEditComment: vi.fn(),
    });
    expect(screen.queryByRole("textbox")).toBeNull();
    expect(lineRow(0).textContent).not.toContain("the guard");
  });

  it("opens exactly ONE editor when several lines share the edited address", () => {
    // THE DEFECT THIS RENDER FOUND. `lineMap` is many-to-one — several emitted C
    // lines routinely carry one instruction address, which is why
    // `DisassemblyView` builds an addr → line[] map and why `highlightLines` is
    // a Set — and `isEditing` used to be decided per line from that address
    // alone. Every sharing line therefore mounted its own textarea: N identical
    // edit boxes for one comment, each running `focusOnMount`, so focus landed
    // on the last of them.
    setup({
      code: CODE_3,
      lineMap: new Map([
        [1, 0x401000],
        [0, 0x401000],
      ]),
      comments: {},
      editingComment: { address: 0x401000, value: "one comment" },
      onEditComment: vi.fn(),
      onCommitComment: vi.fn(),
      onDeleteComment: vi.fn(),
    });
    const boxes = screen.getAllByRole("textbox");
    expect(boxes).toHaveLength(1);
    expect(document.activeElement).toBe(boxes[0]);
    // The LOWEST line wins, not the first in map order — which is why the
    // fixture's insertion order is 1 then 0. That is the line the auto-scroll
    // effect brings into view with `Math.min`, so the editor opens where the
    // panel just scrolled to.
    expect(lineRow(0).parentElement?.contains(boxes[0])).toBe(true);
  });

  it("opens no editor while sync is disabled, the line map describing another text", () => {
    // The AI tab keeps the LOW tab's line map, which numbers a different body,
    // so an editor attributed to a line there would sit on the wrong line. The
    // pre-fix code got this right through `lineAddr`; the memo has to repeat it.
    // Found by an INERT control: dropping `syncDisabled` from the memo's guard
    // moved nothing, because the only sync-disabled assertion nearby was about
    // comment DISPLAY.
    setup({
      code: CODE_3,
      activeTab: "ai",
      syncDisabled: true,
      lineMap: MAP_3(),
      comments: {},
      editingComment: { address: 0x401000, value: "x" },
      onEditComment: vi.fn(),
      onCommitComment: vi.fn(),
      onDeleteComment: vi.fn(),
    });
    expect(screen.queryByRole("textbox")).toBeNull();
  });

  it("opens no editor for an address no line carries", () => {
    // The parent may set `editingComment` from `currentAddress` (that is what
    // the bubbled ";" is for), and that address need not appear in this tab's
    // line map at all.
    setup({
      code: CODE_3,
      lineMap: MAP_3(),
      comments: {},
      editingComment: { address: 0xdeadbe, value: "" },
      onEditComment: vi.fn(),
      onCommitComment: vi.fn(),
      onDeleteComment: vi.fn(),
    });
    expect(screen.queryByRole("textbox")).toBeNull();
  });
});

afterEach(() => {
  vi.restoreAllMocks();
});
