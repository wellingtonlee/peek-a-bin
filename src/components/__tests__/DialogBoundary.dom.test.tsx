// @vitest-environment jsdom

import "../../test/domSetup";
import { fireEvent, render, screen, within } from "@testing-library/react";
import { useState } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DialogBoundary } from "../DialogBoundary";
import { Modal } from "../Modal";

/**
 * `DialogBoundary` on its own, where `App.dom.test.tsx` drives it through the
 * real command palette and the real Ctrl+P.
 *
 * Two things are only reachable here. The **`"nothing"` branch** — a broken
 * dialog that has been closed renders neither its children nor a fallback — is
 * invisible from App, because every dialog renders null when closed anyway, so
 * the observable outcome is identical and only a render counter can tell the two
 * apart. And the **derived-open shape** that `BatchRenameModal` and
 * `AIReportPanel` use, where the caller both computes `open` from `AppState` and
 * mounts the child conditionally, needs a caller under the test's control.
 */

/** A dialog that throws on every render while `explode` is set. */
function Fragile({
  open,
  explode,
  onRender,
}: {
  open: boolean;
  explode: boolean;
  onRender: () => void;
}) {
  onRender();
  if (explode) throw new Error("fragile dialog exploded");
  if (!open) return null;
  return (
    <Modal label="Fragile" onClose={() => {}}>
      <button type="button">the real dialog</button>
    </Modal>
  );
}

/** A caller with the same plumbing App has: it owns `open` and `onClose`. */
function Harness({
  explode,
  startOpen = true,
  conditionalChild = false,
}: {
  explode: boolean;
  startOpen?: boolean;
  conditionalChild?: boolean;
}) {
  const [open, setOpen] = useState(startOpen);
  return (
    <>
      <button type="button" onClick={() => setOpen(true)}>
        open it
      </button>
      <div>the app behind</div>
      <DialogBoundary label="Fragile" open={open} onClose={() => setOpen(false)}>
        {conditionalChild ? (
          open && <Fragile open={open} explode={explode} onRender={renders.bump} />
        ) : (
          <Fragile open={open} explode={explode} onRender={renders.bump} />
        )}
      </DialogBoundary>
    </>
  );
}

const renders = {
  n: 0,
  bump() {
    renders.n += 1;
  },
};

beforeEach(() => {
  renders.n = 0;
  // React logs the caught error itself, and `componentDidCatch` logs it again.
  vi.spyOn(console, "error").mockImplementation(() => {});
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("a dialog that throws", () => {
  it("leaves the caller's own tree standing", () => {
    render(<Harness explode />);
    expect(screen.getByText("the app behind")).toBeTruthy();
    expect(within(screen.getByRole("dialog")).getByRole("alert").textContent).toContain(
      "fragile dialog exploded",
    );
  });

  it("puts the fallback inside a real dialog, with a backdrop that dismisses it", () => {
    render(<Harness explode />);
    // The backdrop is what says the fallback kept `Modal`'s scaffold rather than
    // floating in the caller's root: it carries the dim, the click-to-dismiss
    // and — because `Modal` owns the handler — Escape.
    fireEvent.click(screen.getByRole("button", { name: "Close dialog" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("the app behind")).toBeTruthy();
  });

  it("closes on Escape and on its own Close button", () => {
    const { unmount } = render(<Harness explode />);
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(screen.queryByRole("dialog")).toBeNull();
    unmount();

    render(<Harness explode />);
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("names the dialog through its own visible heading", () => {
    render(<Harness explode />);
    const dialog = screen.getByRole("dialog");
    const id = dialog.getAttribute("aria-labelledby");
    expect(id).toBeTruthy();
    expect(dialog.getAttribute("aria-label")).toBeNull();
    // Resolved against the document, both directions, the way the tablist's
    // `aria-controls` is: an id nothing carries is worse than no name at all.
    expect(document.getElementById(id ?? "")?.textContent).toContain("Fragile");
  });

  it("moves focus into the fallback, so the trap has somewhere to hold it", () => {
    render(<Harness explode />);
    const dialog = screen.getByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);
  });

  it("does not render the children again once it is closed", () => {
    // THE `"nothing"` BRANCH. Every dialog here runs hooks and memos above its
    // own `if (!open) return null`, so rendering a broken one — even closed —
    // can throw a second time with the boundary already spent, which React
    // answers by tearing down the whole tree. Invisible from App, where a closed
    // dialog renders null either way; only the counter separates them.
    render(<Harness explode />);
    const atFault = renders.n;
    expect(atFault).toBeGreaterThan(0);
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(renders.n).toBe(atFault);
    expect(screen.getByText("the app behind")).toBeTruthy();
  });
});

describe("re-opening a broken dialog", () => {
  function reopen(conditionalChild: boolean) {
    const { rerender } = render(<Harness explode conditionalChild={conditionalChild} />);
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close" }));
    // The fault is removed so the outcome is observable. With it still in place
    // the boundary catches again, which is the honest behaviour and cannot loop
    // — it takes an explicit re-open each time.
    rerender(<Harness explode={false} conditionalChild={conditionalChild} />);
    fireEvent.click(screen.getByRole("button", { name: "open it" }));
  }

  it("clears the fallback and mounts the real dialog", () => {
    reopen(false);
    expect(screen.getByRole("button", { name: "the real dialog" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("does so for a caller that mounts its child conditionally", () => {
    // `BatchRenameModal` and `AIReportPanel`: `open` is derived from `AppState`
    // and the child is mounted behind the same condition, so the boundary sees
    // `false` as its children for the whole closed period.
    reopen(true);
    expect(screen.getByRole("button", { name: "the real dialog" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
  });

  it("never paints the fallback on the way back", () => {
    // The reset is in `getDerivedStateFromProps`, which runs BEFORE render, so
    // the transition produces ONE commit and the fallback is never in the
    // document. Done in `componentDidUpdate` it would run after, painting the
    // fallback and then replacing it — two commits, and `takeRecords()` sees
    // the intermediate one because a MutationObserver queues a record per
    // mutation and drains synchronously on demand.
    const { rerender } = render(<Harness explode />);
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Close" }));
    rerender(<Harness explode={false} />);
    const observer = new MutationObserver(() => {});
    observer.observe(document.body, { childList: true, subtree: true });
    fireEvent.click(screen.getByRole("button", { name: "open it" }));
    const added = observer
      .takeRecords()
      .flatMap((r) => Array.from(r.addedNodes))
      .filter((n): n is HTMLElement => n instanceof HTMLElement);
    observer.disconnect();
    expect(added.length).toBeGreaterThan(0);
    expect(
      added.some((el) => el.getAttribute("role") === "alert" || el.querySelector("[role=alert]")),
    ).toBe(false);
    expect(screen.getByRole("button", { name: "the real dialog" })).toBeTruthy();
  });
});

describe("nothing throwing", () => {
  it("renders the dialog itself and no fallback", () => {
    // The liveness half: a boundary showing its fallback unconditionally would
    // pass every assertion above.
    render(<Harness explode={false} />);
    expect(screen.getByRole("button", { name: "the real dialog" })).toBeTruthy();
    expect(screen.queryByRole("alert")).toBeNull();
    expect(renders.n).toBeGreaterThan(0);
  });

  it("renders nothing at all when the dialog is closed", () => {
    render(<Harness explode={false} startOpen={false} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText("the app behind")).toBeTruthy();
  });
});
