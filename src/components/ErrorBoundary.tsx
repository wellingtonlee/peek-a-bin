import { Component, type ErrorInfo, type ReactNode } from "react";

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
 * WHAT IS STILL UNGUARDED, deliberately and recorded rather than blanketed:
 * `Sidebar`, `AddressBar`, `StatusBar` and all six dialogs sit outside every
 * boundary in the tree, and `main.tsx` puts none above `<App/>` — so a throw in
 * any of them is still a blank page. Wrapping each region is a judgement about
 * how much a partial UI is worth against how loudly a defect should fail, and it
 * is filed rather than taken here.
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
    if (this.state.hasError) {
      const what = this.props.label ? `The ${this.props.label} view` : "Something";
      return (
        <div className="flex items-center justify-center h-full">
          <div
            role="alert"
            className="bg-gray-800 border border-red-500/40 rounded-lg shadow-xl p-6 max-w-md text-center"
          >
            <div className="text-red-400 text-lg font-semibold mb-2">{what} went wrong</div>
            <div className="text-gray-400 text-xs mb-4 font-mono break-all">
              {this.state.error?.message ?? "Unknown error"}
            </div>
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
    return this.props.children;
  }
}
