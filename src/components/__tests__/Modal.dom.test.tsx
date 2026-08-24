// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef, useState } from "react";
import { describe, expect, it, vi } from "vitest";
import { Modal } from "../Modal";

/**
 * The half of {@link ../Modal} that is not `modalScaffold.ts`.
 *
 * `modalScaffold.test.ts` pins the arithmetic — which index Tab picks, which
 * classes each placement composes, how the lock nests — over plain values,
 * because until now there was no renderer. What it cannot reach is everything
 * the component does WITH those answers: whether focus actually moves, whether
 * Escape actually reaches the handler, whether the trigger actually gets focus
 * back, whether `<body>` is actually frozen. Those are asserted here.
 *
 * SCOPE, stated because it is easy to overclaim. jsdom performs no layout and
 * runs no browser focus algorithm of its own; `offsetParent` is a stand-in
 * installed by `src/test/domSetup.ts` (read its comment). So what these tests
 * verify is that the component's own logic runs and moves focus where it says
 * it will. They do not verify that a browser agrees, and they say nothing at all
 * about screen readers — `aria-modal` is asserted as an attribute, not as an
 * effect.
 */

/**
 * A trigger, a dialog and a control after it — the arrangement every real call
 * site has, and the minimum needed to tell "focus is trapped" from "focus
 * happens not to have moved".
 */
function Harness({
  closeOnEscape,
  closeOnBackdropClick,
  onClosed,
  withInitialFocus = false,
}: {
  closeOnEscape?: boolean;
  closeOnBackdropClick?: boolean;
  onClosed?: () => void;
  withInitialFocus?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const secondRef = useRef<HTMLButtonElement>(null);
  return (
    <div>
      <button type="button" onClick={() => setOpen(true)}>
        open
      </button>
      <button type="button">before</button>
      {open && (
        <Modal
          label="Test dialog"
          closeOnEscape={closeOnEscape}
          closeOnBackdropClick={closeOnBackdropClick}
          initialFocusRef={withInitialFocus ? secondRef : undefined}
          onClose={() => {
            setOpen(false);
            onClosed?.();
          }}
        >
          <button type="button">first</button>
          <button type="button" ref={secondRef}>
            second
          </button>
          <button type="button">third</button>
        </Modal>
      )}
      <button type="button">after</button>
    </div>
  );
}

async function openDialog(ui: React.ReactElement = <Harness />) {
  const user = userEvent.setup();
  render(ui);
  await user.click(screen.getByRole("button", { name: "open" }));
  return user;
}

describe("Modal focus trap", () => {
  it("moves focus into the dialog on open", async () => {
    await openDialog();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "first" }));
  });

  it("honours initialFocusRef over the first focusable control", async () => {
    await openDialog(<Harness withInitialFocus />);
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "second" }));
  });

  it("wraps Tab from the last control back to the first", async () => {
    const user = await openDialog();
    await user.tab();
    await user.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "third" }));
    await user.tab();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "first" }));
  });

  it("wraps Shift+Tab from the first control round to the last", async () => {
    const user = await openDialog();
    await user.tab({ shift: true });
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "third" }));
  });

  it("never lets Tab reach a control outside the dialog", async () => {
    const user = await openDialog();
    const dialog = screen.getByRole("dialog");
    // Twice round, in both directions: enough to walk off either end more than
    // once if the trap only held for a single wrap.
    for (let i = 0; i < 8; i++) {
      await user.tab();
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    for (let i = 0; i < 8; i++) {
      await user.tab({ shift: true });
      expect(dialog.contains(document.activeElement)).toBe(true);
    }
    // And the page behind it never took focus at any point.
    for (const name of ["open", "before", "after"]) {
      expect(document.activeElement).not.toBe(screen.getByRole("button", { name }));
    }
  });

  it("does not put the click-to-dismiss backdrop in the tab cycle", async () => {
    const user = await openDialog();
    const backdrop = screen.getByRole("button", { name: "Close dialog" });
    for (let i = 0; i < 5; i++) {
      await user.tab();
      expect(document.activeElement).not.toBe(backdrop);
    }
  });

  it("returns focus to the control that opened it", async () => {
    const user = await openDialog();
    expect(document.activeElement).not.toBe(screen.getByRole("button", { name: "open" }));
    await user.keyboard("{Escape}");
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(document.activeElement).toBe(screen.getByRole("button", { name: "open" }));
  });
});

describe("Modal dismissal", () => {
  it("closes on Escape by default", async () => {
    const onClosed = vi.fn();
    const user = await openDialog(<Harness onClosed={onClosed} />);
    await user.keyboard("{Escape}");
    expect(onClosed).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("does NOT close on Escape when closeOnEscape is false", async () => {
    // Settings and the in-progress AI dialogs are deliberately non-dismissible;
    // see accidentalDismissAllowed in modalScaffold.ts.
    const onClosed = vi.fn();
    const user = await openDialog(<Harness closeOnEscape={false} onClosed={onClosed} />);
    await user.keyboard("{Escape}");
    expect(onClosed).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("stops Escape from reaching the view behind it", async () => {
    const onOuterKey = vi.fn();
    const user = userEvent.setup();
    render(
      // The listener has to be a React synthetic handler INSIDE the tree: React
      // attaches its own listener at the root container, so `stopPropagation` on
      // a synthetic event does not stop the native event reaching `document` —
      // a document-level listener would fire either way and prove nothing.
      // biome-ignore lint/a11y/noStaticElementInteractions: it stands in for the view behind the dialog, which is not itself an interactive element
      <div onKeyDown={onOuterKey}>
        <Harness />
      </div>,
    );
    await user.click(screen.getByRole("button", { name: "open" }));
    onOuterKey.mockClear();
    await user.keyboard("{Escape}");
    expect(onOuterKey).not.toHaveBeenCalled();
  });

  it("closes on a backdrop click by default", async () => {
    const onClosed = vi.fn();
    const user = await openDialog(<Harness onClosed={onClosed} />);
    await user.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(onClosed).toHaveBeenCalledTimes(1);
  });

  it("renders no backdrop at all when closeOnBackdropClick is false", async () => {
    await openDialog(<Harness closeOnBackdropClick={false} />);
    expect(screen.queryByRole("button", { name: "Close dialog" })).toBeNull();
  });
});

describe("Modal dialog semantics", () => {
  it("is an aria-modal dialog carrying its accessible name", async () => {
    await openDialog();
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-modal")).toBe("true");
    expect(dialog.getAttribute("aria-label")).toBe("Test dialog");
    expect(dialog.getAttribute("aria-labelledby")).toBeNull();
  });

  it("names itself by its own heading when given labelledBy", () => {
    render(
      <Modal labelledBy="h" onClose={() => {}}>
        <h2 id="h">Settings</h2>
      </Modal>,
    );
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-labelledby")).toBe("h");
    expect(dialog.getAttribute("aria-label")).toBeNull();
    // The announced name is the heading text, which is the whole point of
    // preferring labelledBy.
    expect(screen.getByRole("dialog", { name: "Settings" })).toBe(dialog);
  });

  it("focuses the dialog box itself when it holds no focusable control", () => {
    render(
      <Modal label="Empty" onClose={() => {}}>
        <p>nothing to focus</p>
      </Modal>,
    );
    expect(document.activeElement).toBe(screen.getByRole("dialog"));
  });
});

describe("Modal body scroll lock", () => {
  it("freezes <body> while open and restores what it found on close", async () => {
    document.body.style.overflow = "scroll";
    const user = await openDialog();
    expect(document.body.style.overflow).toBe("hidden");
    await user.keyboard("{Escape}");
    expect(document.body.style.overflow).toBe("scroll");
  });

  it("does not unlock while a second dialog is still open", () => {
    const { rerender, unmount } = render(
      <div>
        <Modal label="One" onClose={() => {}}>
          <button type="button">a</button>
        </Modal>
        <Modal label="Two" onClose={() => {}}>
          <button type="button">b</button>
        </Modal>
      </div>,
    );
    expect(document.body.style.overflow).toBe("hidden");
    rerender(
      <div>
        <Modal label="One" onClose={() => {}}>
          <button type="button">a</button>
        </Modal>
      </div>,
    );
    // The command palette can launch batch rename, so two really are open at
    // once; a boolean lock would have released here.
    expect(document.body.style.overflow).toBe("hidden");
    unmount();
    expect(document.body.style.overflow).toBe("");
  });
});
