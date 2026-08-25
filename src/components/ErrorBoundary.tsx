import { Component, type ErrorInfo, type ReactNode } from "react";

/**
 * Which shape of fallback this mount site wants, and therefore how much room
 * the boundary may take when it catches.
 *
 * `"pane"` fills its container and centres a card — right for a tab pane, which
 * owns the whole main area. `"chrome"` is a single line sized to its own text —
 * right for a 224px sidebar column or a 20px status strip, where the card would
 * overflow the region it is standing in for and push the rest of the app around
 * to report a fault in something the user was not looking at.
 */
export type BoundaryVariant = "pane" | "chrome";

interface Props {
  children: ReactNode;
  /**
   * What this boundary is guarding, for the fallback's own sentence.
   *
   * Only useful because there is now more than one of them: `App` puts a
   * boundary around each mounted tab pane, so "The Hex view could not be
   * displayed" tells the user which of the nine failed and — the part that
   * matters — that the other eight did not.
   */
  label?: string;
  /** See {@link BoundaryVariant}. Defaults to `"pane"`. */
  variant?: BoundaryVariant;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * A render-error backstop.
 *
 * THE BLAST RADIUS IS THE MOUNT SITE'S DECISION, NOT THIS FILE'S, and it was
 * wrong for the whole life of the component. `App` wrapped ONE boundary around
 * `renderMainView()`, which keeps every visited tab in the tree class-hidden —
 * so a throw in the Hex view replaced headers, sections, disassembly, imports,
 * exports, strings, resources and anomalies as well. It is one boundary per tab
 * pane now (`peek-a-bin-p0qw`).
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * WHERE THE BOUNDARIES GO, AND WHY THAT IS A JUDGEMENT (`peek-a-bin-t23y`)
 *
 * Everything outside the tab panes used to be unguarded, and `main.tsx` still
 * puts no boundary above `<App/>`, so a render throw anywhere in the chrome was
 * a BLANK PAGE with `console.error` the only trace. Blanketing the tree was
 * refused; so was leaving it. **The criterion is: guard a region exactly when
 * the app is still worth using without it.**
 *
 * That single test is what decides each case, and it is worth stating why
 * *loudness* is not a second criterion competing with it. The usual argument
 * for leaving a region unguarded is that a blank page gets reported where a
 * small red box does not — but `componentDidCatch` logs the stack either way,
 * and a fallback additionally NAMES the region that failed, which a blank page
 * does not. So for any region the user can work without, a boundary is strictly
 * the better trade: it keeps a parsed image and minutes of worker disassembly
 * that a reload would throw away, and it reports more, not less.
 *
 * GUARDED, all `"chrome"`:
 *  - **`Sidebar`** (mounted in `App`) — the function list and bookmarks. Its
 *    loss leaves the address bar, the tab bar, every pane and the status bar;
 *    every function it lists is still reachable through the address field, the
 *    listing itself and `StatusBar`'s own function link.
 *  - **`StatusBar`** (mounted in `App`) — a derived readout. Nothing depends on
 *    it. Note this DEPARTS from the bead's suggested middle, which grouped it
 *    with `AddressBar` as a region "whose loss means the user cannot navigate
 *    anyway": measured, its only navigation affordance is a jump to the
 *    containing function, which the sidebar and the listing both duplicate.
 *  - **`AIChatPanel`** and **`BottomPanelContainer`** (mounted in
 *    `DisassemblyView`) — this is `peek-a-bin-p0qw`'s blast-radius argument one
 *    level down. Both already sat inside the Disassembly pane's boundary, so
 *    neither was ever the blank page the bead describes; but a throw in the
 *    Xrefs panel or the chat took the whole pane — the listing, the graph and
 *    the decompile panel — to report a fault in an optional side panel.
 *
 * LEFT LOUD, deliberately and on measurement:
 *  - **`AddressBar`** is the one region that fails the criterion, and it fails
 *    it harder than reading the component suggests. It is not only the tab bar,
 *    the address field, Back/Forward, Undo/Redo and Open: it also owns the
 *    global `window` keydown handler carrying the 1-9 `TAB_KEYS` map, so a
 *    boundary would remove BOTH routes to another tab, not just the buttons.
 *    What is left is an app pinned to whichever tab happened to be showing. A
 *    user cannot finish anything there, so the boundary would buy no partial
 *    function — it would only convert an unmistakable blank page into a
 *    half-working app that gets worked around instead of reported.
 *
 * NOT TAKEN HERE, and the reason is a mechanism rather than a judgement:
 *  - **The six dialogs** (`CommandPalette`, `KeyboardShortcuts`, `SettingsModal`,
 *    `GoToAddressModal`, `BatchRenameModal`, `AIReportPanel`) are still a blank
 *    page, and they pass the criterion easily — they are overlays, so the whole
 *    app underneath survives. What they need is not this fallback. A dialog's
 *    subtree carries its own backdrop, focus trap and Escape handler, so a
 *    boundary that catches leaves the fallback floating in `App`'s root with the
 *    dialog still `open` in state; and because `hasError` never clears (below),
 *    one throw in the palette would kill all six for the rest of the session.
 *    The right shape is a modal-placed fallback plus a reset keyed on the
 *    dialog's own `open` transition — a NAMED reset trigger, which does not
 *    contradict the rule below — and that is a second recovery semantic threaded
 *    through three different open-state plumbings. Filed rather than smuggled in
 *    beside this one.
 */
export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null };

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("ErrorBoundary caught:", error, info.componentStack);
  }

  /**
   * Clear the caught error and render the children again.
   *
   * Nothing here decides whether the fault has gone — the children simply run
   * again, and a deterministic fault throws straight back into the fallback.
   * That is the honest behaviour and it cannot loop, since it takes a click.
   * It is worth offering because the alternative was a page reload, which
   * discards the parsed image, the worker's disassembly and the whole session
   * to recover from what may have been one bad render.
   */
  private reset = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (!this.state.hasError) return this.props.children;
    const message = this.state.error?.message ?? "Unknown error";

    if (this.props.variant === "chrome") {
      /* NO "Reload" HERE, and that is the variant's whole argument restated as
         a control. A chrome boundary is only ever placed where the app is still
         worth using without the region — so reloading, which discards the
         parsed image and the worker's disassembly, is precisely the wrong trade
         to put one click away from a user whose session is otherwise intact.
         The pane fallback's own comment already calls it the last resort; here
         it is not a resort at all, and the browser's own reload still exists. */
      return (
        <div
          role="alert"
          className="flex items-center gap-2 px-2 py-1 text-[11px] leading-tight bg-red-950/50 border border-red-500/40 text-red-300 overflow-hidden"
        >
          <span className="font-semibold shrink-0">{this.props.label ?? "This area"} failed</span>
          <span className="text-gray-400 font-mono truncate">{message}</span>
          <button
            type="button"
            onClick={this.reset}
            className="ml-auto shrink-0 px-1.5 py-0.5 bg-gray-700 hover:bg-gray-600 text-gray-200 rounded transition-colors"
          >
            Try again
          </button>
        </div>
      );
    }

    const what = this.props.label ? `The ${this.props.label} view` : "Something";
    return (
      <div className="flex items-center justify-center h-full">
        <div
          role="alert"
          className="bg-gray-800 border border-red-500/40 rounded-lg shadow-xl p-6 max-w-md text-center"
        >
          <div className="text-red-400 text-lg font-semibold mb-2">{what} went wrong</div>
          <div className="text-gray-400 text-xs mb-4 font-mono break-all">{message}</div>
          {/* Two exits, cheapest first. "Try again" re-renders this region
              alone; "Reload" throws the session away and is the last resort,
              not the first — which is what it used to be. */}
          <div className="flex items-center justify-center gap-2">
            <button
              type="button"
              onClick={this.reset}
              className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm transition-colors"
            >
              Try again
            </button>
            <button
              type="button"
              onClick={() => window.location.reload()}
              className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white rounded text-sm transition-colors"
            >
              Reload
            </button>
          </div>
        </div>
      </div>
    );
  }
}
