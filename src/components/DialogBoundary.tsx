import { Component, type ErrorInfo, type ReactNode, useId } from "react";
import { Modal } from "./Modal";
import {
  accidentalDismissAllowed,
  dialogBoundaryRender,
  dialogBoundaryReset,
} from "./modalScaffold";

interface Props {
  children: ReactNode;
  /** What this dialog is called, for the fallback's own heading. */
  label: string;
  /**
   * Whether the caller currently considers this dialog open.
   *
   * It is the caller's state, not the child's, and that is the whole reason it
   * is a prop: when a dialog throws, the child is gone but the dialog is still
   * open in `App` — so the boundary has to be told, and closing has to go back
   * through the same plumbing that opened it.
   */
  open: boolean;
  /** Close the dialog, in the caller's own state. */
  onClose: () => void;
}

interface State {
  caught: Error | null;
  /** `open` as of the previous render, for the reset transition. */
  wasOpen: boolean;
}

/**
 * The fallback body, as a function component so it can mint its own heading id.
 *
 * `labelledBy` rather than `label` because {@link ./modalScaffold#modalNameAttrs}
 * prefers it wherever there IS a visible heading: the announced name is then the
 * heading text itself and the two cannot drift.
 */
function DialogErrorFallback({
  label,
  message,
  onClose,
}: {
  label: string;
  message: string;
  onClose: () => void;
}) {
  const titleId = useId();
  /* Escape and a backdrop click are BOTH offered, stated through the shared
     rule rather than hardcoded to `true`. The two things that withhold them
     elsewhere — a request in flight, and unapplied user decisions — are exactly
     what a dialog that failed to render does not have: nothing was entered,
     nothing is being waited for, and closing is the only useful thing left. */
  const dismissible = accidentalDismissAllowed({ inFlight: false, unsavedWork: false });
  return (
    <Modal
      labelledBy={titleId}
      onClose={onClose}
      closeOnEscape={dismissible}
      closeOnBackdropClick={dismissible}
      className="border-red-500/40 shadow-xl p-6 max-w-md"
    >
      <div role="alert">
        <div id={titleId} className="text-red-400 text-lg font-semibold mb-2">
          {label} could not be shown
        </div>
        <div className="text-gray-400 text-xs mb-4 font-mono break-all">{message}</div>
        {/* ONE exit, and it is Close rather than "Try again". Re-opening the
            dialog is the retry — it resets this boundary — and it also puts the
            app back within reach, which "Try again" on a dialog would not. A
            "Reload" would be worse here than in the pane fallback: the app
            behind an overlay is untouched, so throwing the parsed image and the
            worker's disassembly away is never the right trade. */}
        <button
          type="button"
          onClick={onClose}
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded text-sm transition-colors"
        >
          Close
        </button>
      </div>
    </Modal>
  );
}

/**
 * A render-error backstop for the app's modal dialogs.
 *
 * SEPARATE FROM {@link ./ErrorBoundary} BECAUSE THE MECHANISM DIFFERS, not
 * because the criterion does. The six dialogs pass that component's test — "guard
 * a region exactly when the app is still worth using without it" — trivially, as
 * they are overlays; what they could not use was its fallback. Two reasons, and
 * both are why this file exists (`peek-a-bin-pikv`):
 *
 * 1. **A dialog's subtree carries its own backdrop, focus trap, scroll lock and
 *    Escape handler**, all of them `Modal`'s. A boundary rendering the ordinary
 *    card fallback puts it where that chrome would have been — floating in
 *    `App`'s root, undimmed, with no way out — while the dialog is still `open`
 *    in the caller's state. So the fallback here is itself a `Modal`, and the
 *    Close button and Escape both call the caller's own `onClose`.
 * 2. **`ErrorBoundary` never clears `hasError` on a re-render, deliberately.**
 *    Inherited unchanged that would make one throw in the command palette mean
 *    Ctrl+P silently does nothing for the rest of the session. The reset here is
 *    keyed on the dialog's own closed → open transition — see
 *    {@link ./modalScaffold#dialogBoundaryReset} for why that is a NAMED trigger
 *    and does not weaken the rule it sits beside. Nothing in this file is
 *    reachable from the `"pane"` and `"chrome"` variants, which are a different
 *    class in a different file and keep their behaviour exactly.
 *
 * WHY THE BOUNDARY IS OUTSIDE THE DIALOG RATHER THAN INSIDE `Modal`. Putting it
 * around `Modal`'s children would be one declaration instead of six call sites,
 * and it does not work: every one of these dialogs runs hooks, memos and an
 * `if (!open) return null` ABOVE the `<Modal>` it returns, so the common case —
 * a throw while computing what to show — happens before `Modal` renders at all
 * and there is no boundary mounted yet to catch it.
 */
export class DialogBoundary extends Component<Props, State> {
  state: State = { caught: null, wasOpen: this.props.open };

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { caught: error };
  }

  /**
   * Runs before every render, which is what makes the reset flicker-free: by
   * `render` the error is already gone, so re-opening never paints the fallback
   * for a frame first.
   *
   * It must be a no-op on the re-render that follows a catch — at that moment
   * `open` is true and `wasOpen` is already true, so `dialogBoundaryReset`
   * answers false and the error stands.
   */
  static getDerivedStateFromProps(props: Props, state: State): Partial<State> | null {
    if (props.open === state.wasOpen) return null;
    if (dialogBoundaryReset(state.wasOpen, props.open, state.caught !== null)) {
      return { caught: null, wasOpen: true };
    }
    return { wasOpen: props.open };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("DialogBoundary caught:", error, info.componentStack);
  }

  render() {
    switch (dialogBoundaryRender(this.props.open, this.state.caught !== null)) {
      case "children":
        return this.props.children;
      case "nothing":
        return null;
      case "fallback":
        return (
          <DialogErrorFallback
            label={this.props.label}
            message={this.state.caught?.message ?? "Unknown error"}
            onClose={this.props.onClose}
          />
        );
    }
  }
}
