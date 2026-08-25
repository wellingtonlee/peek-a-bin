// @vitest-environment jsdom

import "../test/domSetup";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import App from "../App";
import {
  PARSER_DERIVED_TABS,
  timeoutBudgetInWords,
  VIEW_TAB_LABELS,
} from "../components/analysisNotice";
import { tabId, tabPanelId } from "../components/tabIds";
import { VIEW_TABS } from "../hooks/usePEFile";
import { buildMinimalPE64 } from "../pe/__tests__/fixtures";
import { IMAGE_SCN_CNT_INITIALIZED_DATA, IMAGE_SCN_MEM_READ } from "../pe/constants";
import { REQUEST_TIMEOUT_MS } from "../workers/requestTimeout";

/**
 * THE WATCHDOG BUDGET, SHORTENED — the one mock in this file, and the reason it
 * is worth one.
 *
 * `docs/verification.md` records that `"timed-out"` "has never fired and cannot
 * be made to fire here", on the evidence that provoking it needs ~200 MiB of
 * code and no such file exists on this machine. That is true of the *file* route
 * and only of it: the budget is a module constant, so replacing it reaches the
 * same code path in milliseconds. `App.tsx`'s own catch says "nothing here can
 * be reached by a test, which is why the decision is a pure function elsewhere"
 * — the pure function was the right call, and the catch is reachable after all.
 *
 * `importActual` and a spread, never a hand-written stub: `analysisRejection`
 * decides on `err instanceof WorkerTimeoutError`, so the class must keep its
 * identity or the test would prove a timeout is reported as a *failure* while
 * appearing to prove the opposite. Only the number changes.
 *
 * The other cases are unaffected — every stubbed reply below lands on a
 * microtask, orders of magnitude inside even this budget.
 */
/**
 * Which tab's component should throw when it renders, or null.
 *
 * A flag plus a passthrough rather than a replacement, because the routing test
 * above asserts on `SectionTable`'s real output: the mock renders the genuine
 * component whenever it is not asked to fail, so one suite covers both.
 */
let boomTab: "sections" | null = null;

vi.mock("../components/SectionTable", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../components/SectionTable")>();
  return {
    ...actual,
    SectionTable: () => {
      if (boomTab === "sections") throw new Error("section table exploded");
      return <actual.SectionTable />;
    },
  };
});

/**
 * Which CHROME region should throw when it renders, or null.
 *
 * Same flag-plus-passthrough shape as `boomTab` above and for the same reason:
 * every other test in this file asserts on these two components' real output,
 * so the mock renders the genuine component whenever it is not asked to fail.
 */
let boomChrome: "sidebar" | "statusbar" | null = null;

vi.mock("../components/Sidebar", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../components/Sidebar")>();
  return {
    ...actual,
    Sidebar: () => {
      if (boomChrome === "sidebar") throw new Error("sidebar exploded");
      return <actual.Sidebar />;
    },
  };
});

vi.mock("../components/StatusBar", async (importOriginal) => {
  const actual = await importOriginal<typeof import("../components/StatusBar")>();
  return {
    ...actual,
    StatusBar: (props: Parameters<typeof actual.StatusBar>[0]) => {
      if (boomChrome === "statusbar") throw new Error("status bar exploded");
      return <actual.StatusBar {...props} />;
    },
  };
});

vi.mock("../workers/requestTimeout", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../workers/requestTimeout")>()),
  // 500 ms rather than something smaller: `timeoutBudgetInWords` rounds to
  // whole seconds, so a sub-second budget spells itself "0-minute" and the
  // derivation assertion below would be checking a string nobody would notice
  // was wrong. At 500 ms it reads "1-second", which is distinctive.
  REQUEST_TIMEOUT_MS: 500,
}));

/**
 * ─────────────────────────────────────────────────────────────────────────────
 * THE FIRST RENDER OF `App` ITSELF.
 *
 * CLAUDE.md's "Not verified" list has named `App` since the renderer landed.
 * That matters for one specific reason rather than for completeness: **three of
 * the five `AnalysisNotice.isFault` render sites are in `App.tsx`**, and the
 * notice banner is the surface every one of `analysisNotice`'s six kinds is
 * *for*. `StatusBar.dom.test.tsx` asserts the status bar "agrees with App.tsx,
 * which reads isFault" — but until this file, that agreement was asserted
 * against a reading of the source, not against a render. `peek-a-bin-n7q1` is
 * exactly what a source-reading agreement is worth.
 *
 * WHAT THIS FILE IS ABOUT, then, is the notice's own promise: that a file the
 * disassembler cannot touch still reaches the user with every parser-derived
 * tab populated, and that the prose saying so cannot disagree with the buttons.
 * CLAUDE.md states that invariant ("lists the populated tabs from
 * `PARSER_DERIVED_TABS` rather than spelling them, so the prose cannot disagree
 * with the buttons") and nothing had ever checked the two against each other on
 * a screen.
 *
 * WHAT IT IS NOT. It does not drive a full analysis to `"ready"` — that wants
 * every RPC in the pipeline answered and a real decoder, and the panel it would
 * populate is already covered by `components/__tests__/DisassemblyPanel.dom.test.tsx`.
 * It does not touch the AI features, the modals, or the recent-files list.
 * jsdom is not a browser: no layout, no service worker, and — the trap that
 * bites hardest here — **Tailwind is not in the test config, so the `hidden`
 * class App puts on an inactive tab pane carries no `display: none`.** Every
 * mounted pane is therefore queryable, so a query for text that a *different*
 * tab renders will succeed. Tab assertions below go through the pane's own
 * class, never through "can I find this text".
 * ─────────────────────────────────────────────────────────────────────────────
 */

/** What the client posted, in order, so a test can assert on the traffic. */
interface PostedRequest {
  id: number;
  method: string;
  args: unknown[];
}
const posted: PostedRequest[] = [];

/**
 * Whether `init` is answered with an error.
 *
 * A flag rather than two `Worker` stubs because the client's `Worker` is a
 * module-level singleton built on first use: it survives between tests in this
 * file, and swapping the constructor would not swap an already-built instance.
 * `init()` is called from an effect on every mount, so the flag is read afresh
 * each time and the singleton costs nothing.
 */
let initFails = false;

/**
 * Whether `detectFunctions` is left unanswered — a worker wedged in a
 * multi-minute stage, which is what the watchdog exists for.
 */
let stallDetect = false;

/**
 * Stands in for `disasm.worker.ts`.
 *
 * Replies on a microtask, not synchronously: a real reply arrives in a later
 * task, and answering inside `postMessage` would let a state update land during
 * the dispatch that caused it and hide an ordering defect.
 *
 * The error shape is the one the real worker posts — a plain string, because
 * `disasm.worker.ts` flattens to `err?.message ?? String(err)` before it crosses
 * `postMessage`. That is what makes the client-side `WorkerTimeoutError` check
 * asymmetric, and a fake that posted an `Error` would be testing a shape the
 * app never sees.
 */
class FakeDisasmWorker {
  onmessage: ((e: { data: unknown }) => void) | null = null;
  onerror: ((e: { message?: string }) => void) | null = null;
  onmessageerror: ((e: unknown) => void) | null = null;

  postMessage(msg: PostedRequest) {
    posted.push(msg);
    queueMicrotask(() => {
      const reply = (data: Record<string, unknown>) => this.onmessage?.({ data });
      if (msg.method === "init") {
        if (initFails) reply({ id: msg.id, error: "capstone.wasm failed to load" });
        else reply({ id: msg.id, result: undefined });
        return;
      }
      if (msg.method === "extractStrings") {
        reply({ id: msg.id, result: { strings: [], stringTypes: [] } });
        return;
      }
      if (msg.method === "configure") {
        reply({ id: msg.id, result: undefined });
        return;
      }
      if (msg.method === "detectFunctions" && stallDetect) {
        // No reply at all. Not an error reply: an error is a *different* event,
        // and the whole point of `peek-a-bin-meai` is that the two had been
        // reported to the user identically.
        return;
      }
      // Anything else is a request this file did not intend to provoke. It is
      // answered with an error rather than a plausible empty result, so a
      // pipeline stage reaching the worker unexpectedly shows up as a rejected
      // request instead of passing quietly.
      reply({ id: msg.id, error: `unstubbed RPC: ${msg.method}` });
    });
  }

  terminate() {}
}

/**
 * A PE with no executable section — an ordinary resource-only satellite DLL,
 * which is the file `analysisNotice`'s `"no-code-section"` kind exists for.
 * `findCodeSection` returns undefined for it, so App's detection effect takes
 * its `"no-code"` early return.
 */
function resourceOnlyPE(): ArrayBuffer {
  return buildMinimalPE64({
    sections: [
      {
        name: ".rsrc",
        virtualAddress: 0x1000,
        virtualSize: 16,
        data: new Uint8Array(16),
        characteristics: IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_MEM_READ,
      },
    ],
  });
}

/** Hand a buffer to App through the real browse input, as a user would. */
async function openFile(buffer: ArrayBuffer, name = "sample.dll") {
  const user = userEvent.setup();
  const input = document.querySelector<HTMLInputElement>('input[type="file"]');
  if (!input) throw new Error("FileLoader rendered no file input");
  await user.upload(input, new File([buffer], name, { type: "application/octet-stream" }));
  return user;
}

/** The notice banner. It is the one `role="status"` App renders. */
function notice(): HTMLElement | null {
  return screen.queryByRole("status");
}

beforeEach(() => {
  posted.length = 0;
  initFails = false;
  stallDetect = false;
  boomTab = null;
  boomChrome = null;
  vi.stubGlobal("Worker", FakeDisasmWorker);
  // `handleFile` calls `saveRecentFile`, which opens IndexedDB. jsdom 28 does
  // not implement it and `fake-indexeddb` is not a dependency here, so the
  // promise rejects and App's own `.catch` logs it. Silenced rather than
  // stubbed: that a browser with no usable IndexedDB (a private window, site
  // data blocked) still opens a file is a real property, and stubbing the
  // store would stop this file from exercising it.
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
});

describe("App mounts", () => {
  it("renders the file loader when nothing is open", () => {
    render(<App />);
    expect(screen.getByLabelText(/drop a pe file here/i)).toBeTruthy();
    expect(notice()).toBeNull();
  });

  it("opens a parsed PE and shows the tab bar", async () => {
    render(<App />);
    await openFile(resourceOnlyPE());
    // The tab bar is AddressBar's, derived from VIEW_TABS; its presence is how
    // we know the loader unmounted and the main view took over.
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /^Headers/ })).toBeTruthy();
    });
    expect(screen.queryByLabelText(/drop a pe file here/i)).toBeNull();
  });
});

describe("the notice banner, rendered for the first time", () => {
  it("is amber for a resource-only DLL, because nothing went wrong", async () => {
    render(<App />);
    await openFile(resourceOnlyPE());

    const banner = await waitFor(() => {
      const n = notice();
      if (!n) throw new Error("no notice yet");
      return n;
    });

    // `"no-code-section"` is `isFault: false`. The banner's own background and
    // its label colour are two of App's three `isFault` reads; both must be
    // amber, and neither may be red.
    expect(banner.className).toContain("amber");
    expect(banner.className).not.toContain("red");
    expect(banner.textContent).toMatch(/no executable section/i);
  });

  it("is red for an engine that never loaded, which IS a fault", async () => {
    initFails = true;
    render(<App />);
    await openFile(resourceOnlyPE());

    // BOTH CONDITIONS IN ONE `waitFor`, and that is a fix rather than a style:
    // asserted separately this test was FLAKY, failing about one run in three.
    // `SET_DISASM_FAILED` feeds the notice straight from the reducer, while the
    // phase that stops the placeholders is dispatched by the detection effect
    // re-running on `state.disasmFailed` — so the banner can be on screen a
    // render before the shimmer stops, and a `waitFor` that returns on the
    // banner alone samples the intermediate state.
    const banner = await waitFor(() => {
      const n = notice();
      if (!n) throw new Error("no notice yet");
      if (document.querySelectorAll(".skeleton-shimmer").length > 0) {
        throw new Error("still showing loading placeholders");
      }
      return n;
    });

    // `"engine-unavailable"` is `isFault: true`, and it OUTRANKS nothing here:
    // the detection effect never reaches `findCodeSection` when the engine is
    // dead, so this is the kind even for a file that also has no code section.
    // That is the pairing peek-a-bin-b3jn is about — a dead engine used to say
    // nothing at all while three surfaces spun "Loading engine...".
    expect(banner.className).toContain("red");
    expect(banner.className).not.toContain("amber");
    expect(banner.textContent).toMatch(/capstone\.wasm failed to load/);

    // AND THE LOADING PLACEHOLDERS MUST HAVE STOPPED. This is the other half of
    // peek-a-bin-b3jn, and the half a notice test would miss: the notice is fed
    // by `state.disasmFailed`, which the reducer sets on its own, so the banner
    // renders whether or not the detection effect reaches a TERMINAL PHASE. What
    // needs the phase is `ANALYSIS_IN_PROGRESS` — with the phase left where
    // `handleFile` put it, the status bar's two slots and the sidebar's function
    // list shimmer for the rest of the session under a banner that says the
    // engine is dead.
    //
    // `.skeleton-shimmer` rather than StatusBar's `.animate-spin`, and the
    // difference was MEASURED, not chosen: a spinner assertion here is VACUOUS.
    // StatusBar renders `<Spinner/>` only in the `else` of `notice ? … :
    // isAnalyzing ? …`, so whenever there is a notice to report — which is
    // always, in this test — the spinner branch is unreachable and the
    // assertion holds however broken the phase is. The negative control (drop
    // the terminal-phase dispatch) came back INERT against `.animate-spin` and
    // red against the shimmer, which is the whole reason the wait above is
    // written the way it is.
    expect(document.querySelectorAll(".skeleton-shimmer").length).toBe(0);
  });

  it("can be dismissed", async () => {
    render(<App />);
    const user = await openFile(resourceOnlyPE());
    await waitFor(() => {
      if (!notice()) throw new Error("no notice yet");
    });
    await user.click(screen.getByRole("button", { name: /dismiss this notice/i }));
    expect(notice()).toBeNull();
  });
});

describe("the notice's prose cannot disagree with the buttons", () => {
  /**
   * THE INVARIANT, stated once rather than as eight cases.
   *
   * CLAUDE.md: `"no-code-section"` "lists the populated tabs from
   * `PARSER_DERIVED_TABS` rather than spelling them, so the prose cannot
   * disagree with the buttons". Both halves of that are on screen together for
   * the first time here — the banner's "Still available:" sentence, and
   * AddressBar's tab bar, which derives its labels from the same
   * `VIEW_TAB_LABELS` record.
   *
   * Asserted as "every tab the prose names has a button" rather than by
   * comparing two lists verbatim, because the prose is joined with commas and
   * an "and" and a verbatim comparison would be a test of `joinProse`, which
   * `analysisNotice.test.ts` already owns.
   */
  it("names only tabs that have a button", async () => {
    render(<App />);
    await openFile(resourceOnlyPE());

    const banner = await waitFor(() => {
      const n = notice();
      if (!n) throw new Error("no notice yet");
      return n;
    });
    const prose = banner.textContent ?? "";
    expect(prose).toContain("Still available:");

    for (const tab of PARSER_DERIVED_TABS) {
      const label = VIEW_TAB_LABELS[tab];
      expect(prose).toContain(label);
      // Identified by TITLE, not by accessible name, and both reasons were
      // found by this test failing rather than by reading the component:
      //
      //  * "Sections" IS AN AMBIGUOUS BUTTON NAME. The sidebar renders its own
      //    collapsible "Sections (1)" header, so a name query for the tab
      //    matches two buttons in a loaded app.
      //  * A TAB BUTTON'S ACCESSIBLE NAME IS NOT ITS LABEL. The Anomalies tab
      //    carries a count badge inside the button and the two ran together
      //    with no separator, so its name was the string "Anomalies3" — read as
      //    "Anomalies3, button", with nothing saying what the 3 counted. Fixed
      //    with the tablist work (peek-a-bin-w50c): the badge is `aria-hidden`
      //    and the name is now "Anomalies — 3 findings". The title query stays,
      //    because the FIRST reason above is unaffected and the title is also
      //    what carries the digit.
      //
      // The title also carries the 1-9 shortcut digit, so asserting on it
      // checks the thing CLAUDE.md says is derived — that the bar and its
      // `TAB_KEYS` map both come from `VIEW_TABS`, in that order.
      const title = `${label} (${VIEW_TABS.indexOf(tab) + 1})`;
      const buttons = screen.getAllByRole("tab").filter((b) => b.getAttribute("title") === title);
      expect(buttons).toHaveLength(1);
      expect(buttons[0].textContent?.startsWith(label)).toBe(true);
    }
  });

  it("does not offer the one tab it has just withheld", async () => {
    render(<App />);
    await openFile(resourceOnlyPE());

    const banner = await waitFor(() => {
      const n = notice();
      if (!n) throw new Error("no notice yet");
      return n;
    });
    // The control for the case above: a rule that put every tab in the prose
    // would satisfy it. `disassembly` is the only DECODER_DERIVED_TAB and is
    // the one thing this file genuinely cannot show.
    const still = (banner.textContent ?? "").split("Still available:")[1] ?? "";
    expect(still).not.toContain(VIEW_TAB_LABELS.disassembly);
  });
});

describe("the tab bar routes", () => {
  /**
   * Read the trap in this file's header before changing these. App keeps every
   * visited tab MOUNTED and hides the inactive ones with Tailwind's `hidden`
   * class — which carries no `display: none` here, because Tailwind is
   * deliberately out of the test config. So "the Sections table is in the
   * document" says nothing about which tab is showing, and these assertions go
   * through the pane's own class instead.
   */
  function panes(): HTMLElement[] {
    // Each tab is wrapped in a div that is either `h-full` or `hidden`. All nine
    // wrappers are rendered from the first file onward — see the tablist suite
    // below for why — so this counts WRAPPERS, and whether a tab's component is
    // mounted is a question about the wrapper's CONTENT.
    return Array.from(document.querySelectorAll<HTMLElement>("div.h-full, div.hidden")).filter(
      (el) => el.className === "h-full" || el.className === "hidden",
    );
  }

  it("mounts one visible pane at a time", async () => {
    render(<App />);
    const user = await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /^Headers/ })).toBeTruthy();
    });

    const visible = () => panes().filter((el) => el.className === "h-full").length;
    expect(visible()).toBe(1);

    // By title, not by name: see the invariant test above — the sidebar has a
    // "Sections" button of its own, so the name is ambiguous once a PE is open.
    await user.click(screen.getByTitle("Sections (3)"));
    await waitFor(() => {
      expect(visible()).toBe(1);
    });
    // The previous tab stays MOUNTED, which is the behaviour `mountedTabs`
    // exists to produce — and since every wrapper is now rendered whether or not
    // its component is, that has to be asserted on the wrapper's content rather
    // than on a pane count. `disassembly` is the tab a file opens on, so it is
    // the one that was left: hidden, and still holding what it rendered.
    const first = document.getElementById(tabPanelId("disassembly"));
    expect(first?.className).toBe("hidden");
    expect(first?.textContent).not.toBe("");
    // And a tab nobody has opened has a wrapper with nothing in it: the wrapper
    // exists so `aria-controls` resolves, not because the component was mounted.
    expect(document.getElementById(tabPanelId("strings"))?.textContent).toBe("");

    // And the pane that is shown has the section in it. Worth asserting rather
    // than leaving implicit: `App` mounts a tab's component when the tab is
    // first visited, so this test renders `SectionTable` whether or not it says
    // so — and a component that mounts as somebody's child while nothing
    // asserts on its output is exactly the vacuous coverage this repo keeps
    // finding. One assertion turns the incidental render into a real one.
    const shown = panes().find((el) => el.className === "h-full");
    expect(shown?.textContent).toContain(".rsrc");
  });
});

describe("a stalled stage is reported as timed out, not as a failed analysis", () => {
  /**
   * THIS IS THE FIRST TIME THE WATCHDOG'S TERMINAL STATE HAS FIRED ANYWHERE IN
   * THIS REPO. Everything about `"timed-out"` was fixture-verified — the minted
   * error class, `analysisRejection`, the notice's rank, its `isFault`, its
   * empty `unavailableTabs` — with the banner itself verified "by typecheck,
   * pure tests and reading". Here the real `App`, the real client watchdog and
   * the real notice produce it end to end, with a `.text` section present so
   * detection actually starts and a worker that never answers it.
   */
  const codePE = () => buildMinimalPE64();

  it("renders the timeout banner in red, with the budget it actually used", async () => {
    stallDetect = true;
    render(<App />);
    await openFile(codePE(), "big.exe");

    const banner = await waitFor(
      () => {
        const n = notice();
        if (!n) throw new Error("no notice yet");
        if (!/timed out|took longer/i.test(n.textContent ?? "")) {
          throw new Error("notice is not the timeout one yet: " + n.textContent);
        }
        return n;
      },
      { timeout: 4000 },
    );

    // `isFault: true` — a fault, but not a fault of the file, which is the whole
    // distinction the kind exists to draw.
    expect(banner.className).toContain("red");
    expect(banner.className).not.toContain("amber");

    // The budget is spelled from `REQUEST_TIMEOUT_MS` rather than written out,
    // "so raising the budget cannot leave the banner claiming the old one".
    // Asserted against the mocked constant, which is what makes it a test of
    // the derivation rather than of the number.
    expect(banner.textContent).toContain(timeoutBudgetInWords(REQUEST_TIMEOUT_MS));
  });

  it("withholds no tab, because a timeout can leave a full disassembly", async () => {
    stallDetect = true;
    render(<App />);
    await openFile(codePE(), "big.exe");

    const banner = await waitFor(
      () => {
        const n = notice();
        if (!n) throw new Error("no notice yet");
        if (!/timed out|took longer/i.test(n.textContent ?? "")) {
          throw new Error("not the timeout notice yet");
        }
        return n;
      },
      { timeout: 4000 },
    );

    // `"analysis-timed-out"` is the ONE fault kind whose `unavailableTabs` is
    // empty, and it is deliberate: `buildAllXrefs` is the last stage, so a
    // timeout there routinely leaves a complete function list and disassembly
    // with only the xrefs missing. Naming `DECODER_DERIVED_TABS` would print
    // "Still available: everything else" over a fully populated panel. App
    // renders that sentence only when something really is withheld, so its
    // ABSENCE here is the assertion.
    expect(banner.textContent).not.toContain("Still available:");
  });

  it("does not say the analysis failed", async () => {
    stallDetect = true;
    render(<App />);
    await openFile(codePE(), "big.exe");

    const banner = await waitFor(
      () => {
        const n = notice();
        if (!n) throw new Error("no notice yet");
        if (!/timed out|took longer/i.test(n.textContent ?? "")) {
          throw new Error("not the timeout notice yet");
        }
        return n;
      },
      { timeout: 4000 },
    );

    // The control for the two above, and the defect peek-a-bin-meai fixed: this
    // is exactly what a truncated file produces, and a user whose large image
    // merely needed longer was being told the same thing. The timeout's message
    // is also recorded VERBATIM, without the "Analysis failed: " prefix, or the
    // notice interpolates those words into the sentence saying it did not fail.
    expect(banner.textContent).not.toMatch(/analysis failed/i);
    expect(banner.textContent).not.toMatch(/ANALYSIS FAILED/);
  });
});

describe("the tab bar and the panes are one tablist", () => {
  /**
   * THE HALF `AddressBar.dom.test.tsx` CANNOT ASK. The tabs are minted in
   * `AddressBar.tsx` and the panels in `App.tsx`, so every ARIA reference here
   * has one end in each file — and the bar's own suite renders no panels at all,
   * so all it can check is that the bar uses the shared minter. Whether the
   * reference RESOLVES is only answerable where both halves are on screen, which
   * is here. That split is the point: this file fails if `App` stops rendering a
   * wrapper or renames an id, the bar's file fails if the bar does, and neither
   * failure implies the other.
   *
   * Asserted in BOTH DIRECTIONS deliberately — tab → panel and panel → tab.
   * A one-directional check passes an arrangement where every tab points at the
   * same panel, which is the shape a copy-paste error takes.
   *
   * WHAT IT IS NOT EVIDENCE OF: jsdom has no screen reader, so nothing here says
   * a reader announces "Sections, tab 3 of 9" or reads the panel when the tab is
   * activated. peek-a-bin-v2u stays open.
   */
  it("gives every tab a panel, and every panel back its tab", async () => {
    render(<App />);
    await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByRole("tab", { name: /^Headers/ })).toBeTruthy();
    });

    const tabs = screen.getAllByRole("tab");
    expect(tabs).toHaveLength(VIEW_TABS.length);
    for (const [i, tab] of VIEW_TABS.entries()) {
      const el = tabs[i];
      expect(el.id).toBe(tabId(tab));
      const controls = el.getAttribute("aria-controls");
      expect(controls).toBe(tabPanelId(tab));
      // RESOLVED AGAINST THE DOCUMENT, which is the whole reason this test is in
      // App's file: an `aria-controls` naming an id nothing has is a dangling
      // reference that produces no error and no visible change.
      const panel = document.getElementById(controls as string);
      expect(panel, `nothing in the document has id ${controls}`).toBeTruthy();
      expect(panel?.getAttribute("role")).toBe("tabpanel");
      expect(panel?.getAttribute("aria-labelledby")).toBe(el.id);
    }
  });

  it("shows exactly one panel and gives only that one a tab stop", async () => {
    render(<App />);
    const user = await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByTitle("Sections (3)")).toBeTruthy();
    });
    await user.click(screen.getByTitle("Sections (3)"));

    const panels = VIEW_TABS.map((t) => document.getElementById(tabPanelId(t)) as HTMLElement);
    const shown = panels.filter((el) => el.className === "h-full");
    expect(shown).toHaveLength(1);
    expect(shown[0].id).toBe(tabPanelId("sections"));
    // Only the shown panel is in the tab order. The hidden ones are
    // `display: none` in a browser and must not be reachable by Tab; -1 keeps
    // them out of it while still allowing a programmatic focus.
    expect(panels.filter((el) => el.tabIndex === 0)).toEqual(shown);
    expect(panels.filter((el) => el.tabIndex === -1)).toHaveLength(VIEW_TABS.length - 1);
  });

  it("moves aria-selected with the pane that is showing", async () => {
    render(<App />);
    const user = await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByTitle("Sections (3)")).toBeTruthy();
    });

    const selected = () =>
      screen.getAllByRole("tab").filter((t) => t.getAttribute("aria-selected") === "true");
    const shown = () =>
      VIEW_TABS.map((t) => document.getElementById(tabPanelId(t)) as HTMLElement).filter(
        (el) => el.className === "h-full",
      );

    // THE PAIRING IS THE ASSERTION. The selected tab and the shown panel are
    // decided by two different expressions in two different files, both off
    // `state.activeTab`; one notice rendering in two colours at once
    // (peek-a-bin-n7q1) is what a pair like that looks like when it drifts.
    expect(selected()[0].getAttribute("aria-controls")).toBe(shown()[0].id);
    await user.click(screen.getByTitle("Sections (3)"));
    await waitFor(() => {
      expect(selected()).toHaveLength(1);
    });
    expect(selected()[0].getAttribute("aria-controls")).toBe(tabPanelId("sections"));
    expect(shown()[0].id).toBe(tabPanelId("sections"));
  });

  it("keeps the digit shortcuts working, in the same order the bar advertises", async () => {
    render(<App />);
    const user = await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByTitle("Sections (3)")).toBeTruthy();
    });
    // The tablist's arrows are a SECOND way to move between tabs and had to be
    // reconciled with the documented 1-9 keys rather than layered on top: the
    // arrows move focus only, the digits select. Pressed at the window with
    // nothing in the bar focused, so this is the global path.
    await user.keyboard("5");
    await waitFor(() => {
      const selected = screen
        .getAllByRole("tab")
        .filter((t) => t.getAttribute("aria-selected") === "true");
      expect(selected[0].getAttribute("title")).toBe(`${VIEW_TAB_LABELS[VIEW_TABS[4]]} (5)`);
    });
  });
});

describe("a throw in one tab does not take out the others", () => {
  /**
   * THE DEFECT THIS PINS, and it lived for the whole life of the component.
   * `App` wrapped ONE `ErrorBoundary` around `renderMainView()`, which keeps
   * every visited tab in the tree class-hidden. So a throw in any one of them
   * replaced the whole main area — every tab the user had ever opened — and
   * because `hasError` is never cleared and the boundary sat ABOVE the tab
   * switch, changing tabs could not recover it. The only exit was a page
   * reload, which discards the parsed image and the worker's disassembly.
   *
   * It is one boundary per pane now, so this suite is the blast-radius
   * assertion: the failing tab shows a fallback that NAMES it, and its
   * neighbour still renders its own content.
   *
   * Only a render can see any of this. `typecheck` accepts a boundary with
   * neither `getDerivedStateFromError` nor `componentDidCatch`, and
   * `componentDidCatch` has no signature to inspect (`peek-a-bin-p0qw`).
   */
  async function openWithBrokenSections() {
    boomTab = "sections";
    render(<App />);
    const user = await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByTitle("Sections (3)")).toBeTruthy();
    });
    await user.click(screen.getByTitle("Sections (3)"));
    return user;
  }

  it("shows a fallback that names the tab that failed", async () => {
    await openWithBrokenSections();
    const alert = await screen.findByRole("alert");
    // The label comes from `VIEW_TAB_LABELS`, so the fallback cannot call a tab
    // something the tab bar does not — the same single-declaration rule the
    // notice's prose follows.
    expect(alert.textContent).toContain("Sections");
    expect(alert.textContent).toContain("section table exploded");
  });

  it("leaves a neighbouring tab working, which is the whole point", async () => {
    const user = await openWithBrokenSections();
    await screen.findByRole("alert");

    await user.click(screen.getByTitle("Headers (2)"));

    // SCOPED TO THE VISIBLE PANE, and the first version of this test was wrong
    // for the reason this file's header warns about: the broken Sections pane
    // STAYS MOUNTED — `App` keeps every visited tab in the tree — and its
    // `hidden` class carries no `display: none` here, because Tailwind is
    // deliberately out of the test config. So a document-wide
    // `queryByRole("alert")` still finds the fallback and says nothing about
    // what is on screen. In a browser it is hidden; here the pane's own class
    // is the only thing that knows.
    const shown = await waitFor(() => {
      const el = Array.from(document.querySelectorAll<HTMLElement>("div.h-full")).find(
        (d) => d.className === "h-full",
      );
      if (!el) throw new Error("no visible pane");
      return el;
    });
    expect(within(shown).queryByRole("alert")).toBeNull();
    expect(shown.textContent).toMatch(/machine/i);

    // And the fallback is still there, in the hidden pane — the failure is
    // contained, not erased. Under the single-boundary arrangement there was
    // only one pane's worth of fallback and it was the one on screen.
    expect(screen.getByRole("alert").textContent).toContain("Sections");
  });

  it("recovers the failed tab in place once the fault is gone", async () => {
    const user = await openWithBrokenSections();
    await screen.findByRole("alert");

    // "Try again" re-renders that region alone. Nothing in the boundary decides
    // whether the fault has cleared — the children simply run again — so this
    // asserts the mechanism, with the fault removed to make the outcome
    // observable. A deterministic fault would throw straight back, which is the
    // honest behaviour and cannot loop, since it takes a click.
    boomTab = null;
    await user.click(screen.getByRole("button", { name: "Try again" }));
    await waitFor(() => {
      expect(screen.queryByRole("alert")).toBeNull();
    });
    const shown = Array.from(document.querySelectorAll<HTMLElement>("div.h-full")).find(
      (el) => el.className === "h-full",
    );
    expect(shown?.textContent).toContain(".rsrc");
  });
});

describe("a throw in the chrome does not blank the page", () => {
  /**
   * THE DEFECT THIS PINS: until `peek-a-bin-t23y` the tree held exactly ONE
   * `ErrorBoundary` usage outside the component's own file — the per-pane one
   * above — and `main.tsx` puts none above `<App/>`. So a render throw in the
   * sidebar or the status bar unmounted the whole application and left a BLANK
   * PAGE, with `console.error` the only trace, to report a fault in a function
   * list or in a 20px readout.
   *
   * The assertion is the BLAST RADIUS, never that a fallback appeared: each
   * test below names something in a NEIGHBOURING region that must still be on
   * screen. Only a render can see any of this — `typecheck` accepts a boundary
   * with neither `getDerivedStateFromError` nor `componentDidCatch`.
   *
   * `AddressBar` is deliberately NOT guarded and there is no test here asserting
   * that it is not; the argument, which is a measurement about the global
   * `TAB_KEYS` handler it owns, is in `ErrorBoundary`'s docstring, which is
   * where anyone about to wrap it will be reading.
   */
  async function openWithBrokenChrome(which: "sidebar" | "statusbar") {
    boomChrome = which;
    render(<App />);
    const user = await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByTitle("Sections (3)")).toBeTruthy();
    });
    return user;
  }

  /** The chrome fallback for one region, found by the sentence it renders. */
  function chromeAlert(label: string): HTMLElement {
    const hit = screen
      .getAllByRole("alert")
      .find((el) => el.textContent?.includes(`${label} failed`));
    if (!hit) throw new Error(`no chrome fallback naming ${label}`);
    return hit;
  }

  it("keeps the tab bar and the pane when the sidebar throws", async () => {
    const user = await openWithBrokenChrome("sidebar");

    // Names the region and carries the real message, so a bug report can say
    // which of the chrome regions went — which a blank page cannot.
    expect(chromeAlert("Sidebar").textContent).toContain("sidebar exploded");

    // The neighbours: AddressBar's tablist still has all nine tabs, and one of
    // them still SWITCHES and renders its pane's real content. Asserting the
    // tab bar alone would not say the app is usable — the tab bar rendering is
    // what a boundary around AddressBar would have taken, not what a boundary
    // around the sidebar could.
    expect(screen.getAllByRole("tab").length).toBe(VIEW_TABS.length);
    await user.click(screen.getByTitle("Headers (2)"));
    const shown = await waitFor(() => {
      const el = Array.from(document.querySelectorAll<HTMLElement>("div.h-full")).find(
        (d) => d.className === "h-full",
      );
      if (!el) throw new Error("no visible pane");
      return el;
    });
    expect(shown.textContent).toMatch(/machine/i);
  });

  it("keeps the sidebar and the tab bar when the status bar throws", async () => {
    await openWithBrokenChrome("statusbar");

    expect(chromeAlert("Status bar").textContent).toContain("status bar exploded");
    expect(screen.getAllByRole("tab").length).toBe(VIEW_TABS.length);
    // The real sidebar, not a stand-in: its own filter field.
    expect(screen.getByPlaceholderText("Filter functions...")).toBeTruthy();
  });

  it("renders no fallback at all when nothing throws", async () => {
    // The liveness half. Every assertion above is about a red row; a boundary
    // that rendered its fallback unconditionally would pass all of them, and
    // this is what says the population is also asked over well-formed input.
    render(<App />);
    await openFile(resourceOnlyPE());
    await waitFor(() => {
      expect(screen.getByPlaceholderText("Filter functions...")).toBeTruthy();
    });
    expect(screen.queryAllByRole("alert")).toEqual([]);
  });

  it("re-renders the region alone when Try again is clicked", async () => {
    const user = await openWithBrokenChrome("sidebar");
    const fallback = chromeAlert("Sidebar");

    // The chrome fallback deliberately offers NO Reload: it is only ever placed
    // where the app is still usable without the region, so discarding the
    // parsed image and the worker's disassembly is the wrong trade to put one
    // click away. Asserted because it is a decision, not an omission.
    expect(within(fallback).queryByRole("button", { name: "Reload" })).toBeNull();

    boomChrome = null;
    await user.click(within(fallback).getByRole("button", { name: "Try again" }));
    await waitFor(() => {
      expect(screen.getByPlaceholderText("Filter functions...")).toBeTruthy();
    });
    expect(screen.queryAllByRole("alert")).toEqual([]);
  });
});
