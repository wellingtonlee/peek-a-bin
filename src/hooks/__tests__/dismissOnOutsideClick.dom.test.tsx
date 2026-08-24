// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { useRef } from "react";
import { describe, expect, it, vi } from "vitest";
import {
  type DismissOnOutsideClickOptions,
  useDismissOnOutsideClick,
} from "../useDismissOnOutsideClick";

/**
 * The effect half of {@link ../useDismissOnOutsideClick}.
 *
 * `dismissOnOutsideClick.test.ts` covers `isOutsideDismiss`, the pure decision,
 * because until now the hook could not be mounted. Everything around that
 * decision was unverified: whether a listener is attached at all, on which
 * host, for which event, whether it is removed again, and whether `onDismiss`
 * is read late enough that an inline arrow does not tear the listener down.
 * That is what is asserted here.
 */

type Opts = Omit<DismissOnOutsideClickOptions, "ref">;

function Popup(props: Opts) {
  const ref = useRef<HTMLDivElement>(null);
  useDismissOnOutsideClick({ ...props, ref });
  return (
    <div>
      <div ref={ref} data-testid="popup">
        <button type="button">inside</button>
      </div>
      <button type="button">outside</button>
    </div>
  );
}

/** Same hook, but with `ref` pointed at nothing — the unmounted-popup case. */
function PopupWithNoRef(props: Opts) {
  const ref = useRef<HTMLDivElement>(null);
  useDismissOnOutsideClick({ ...props, ref });
  return (
    <button type="button" onClick={() => {}}>
      outside
    </button>
  );
}

describe("useDismissOnOutsideClick", () => {
  it("dismisses on a pointer event outside the ref", async () => {
    const onDismiss = vi.fn();
    const user = userEvent.setup();
    render(<Popup active onDismiss={onDismiss} />);
    await user.click(screen.getByRole("button", { name: "outside" }));
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("does NOT dismiss on a pointer event inside the ref", async () => {
    const onDismiss = vi.fn();
    const user = userEvent.setup();
    render(<Popup active onDismiss={onDismiss} />);
    await user.click(screen.getByRole("button", { name: "inside" }));
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("attaches nothing while inactive", async () => {
    const onDismiss = vi.fn();
    const user = userEvent.setup();
    render(<Popup active={false} onDismiss={onDismiss} />);
    await user.click(screen.getByRole("button", { name: "outside" }));
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("removes its listener on unmount", async () => {
    // `dismissIfRefMissing` is what makes this discriminate. Without it the test
    // passes against a hook that never detaches at all: React nulls the ref on
    // unmount, so a surviving listener would see `container === null` and decide
    // NOT to dismiss — right answer, wrong reason. Measured: with the removal
    // disabled and the flag off, this test is green.
    const onDismiss = vi.fn();
    const user = userEvent.setup();
    const { unmount } = render(<Popup active dismissIfRefMissing onDismiss={onDismiss} />);
    unmount();
    await user.click(document.body);
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("removes its Escape listener on unmount too", async () => {
    // Separate from the pointer teardown above because it is separate code, and
    // measured to be so: disabling only the keydown removal leaves that test
    // green. The Escape handler consults no ref, so a surviving listener fires.
    const onDismiss = vi.fn();
    const user = userEvent.setup();
    const { unmount } = render(<Popup active dismissOnEscape onDismiss={onDismiss} />);
    unmount();
    await user.keyboard("{Escape}");
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("listens on mousedown by default, not click", async () => {
    // The distinction is load-bearing: a popup whose toggle sits outside the ref
    // needs the dismissal to land BEFORE the button's own onClick re-opens it.
    const order: string[] = [];
    const user = userEvent.setup();
    function Toggle() {
      const ref = useRef<HTMLDivElement>(null);
      useDismissOnOutsideClick({ active: true, ref, onDismiss: () => order.push("dismiss") });
      return (
        <div>
          <div ref={ref}>popup</div>
          <button type="button" onClick={() => order.push("toggle-click")}>
            toggle
          </button>
        </div>
      );
    }
    render(<Toggle />);
    await user.click(screen.getByRole("button", { name: "toggle" }));
    expect(order).toEqual(["dismiss", "toggle-click"]);
  });

  it("listens on click instead when asked", async () => {
    const order: string[] = [];
    const user = userEvent.setup();
    function Toggle() {
      const ref = useRef<HTMLDivElement>(null);
      useDismissOnOutsideClick({
        active: true,
        ref,
        event: "click",
        onDismiss: () => order.push("dismiss"),
      });
      return (
        <div>
          <div ref={ref}>popup</div>
          <button type="button" onClick={() => order.push("toggle-click")}>
            toggle
          </button>
        </div>
      );
    }
    render(<Toggle />);
    await user.click(screen.getByRole("button", { name: "toggle" }));
    expect(order).toEqual(["toggle-click", "dismiss"]);
  });

  it("ignores Escape unless dismissOnEscape is set", async () => {
    const onDismiss = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(<Popup active onDismiss={onDismiss} />);
    await user.keyboard("{Escape}");
    expect(onDismiss).not.toHaveBeenCalled();
    rerender(<Popup active dismissOnEscape onDismiss={onDismiss} />);
    await user.keyboard("{Escape}");
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("ignores an event when the ref is empty, unless told otherwise", async () => {
    const ignored = vi.fn();
    const dismissed = vi.fn();
    const user = userEvent.setup();
    const { unmount } = render(<PopupWithNoRef active onDismiss={ignored} />);
    await user.click(screen.getByRole("button", { name: "outside" }));
    expect(ignored).not.toHaveBeenCalled();
    unmount();
    render(<PopupWithNoRef active dismissIfRefMissing onDismiss={dismissed} />);
    await user.click(screen.getByRole("button", { name: "outside" }));
    expect(dismissed).toHaveBeenCalledTimes(1);
  });

  it("calls the LATEST onDismiss without re-attaching the listener", async () => {
    // The hook reads onDismiss through a ref precisely so an inline arrow does
    // not tear the listeners down every render. A test that only checked "some
    // callback fired" would pass against a version that re-attached each time.
    const addSpy = vi.spyOn(document, "addEventListener");
    const first = vi.fn();
    const second = vi.fn();
    const user = userEvent.setup();
    const { rerender } = render(<Popup active onDismiss={first} />);
    const attachesAfterMount = addSpy.mock.calls.filter(([e]) => e === "mousedown").length;
    rerender(<Popup active onDismiss={second} />);
    expect(addSpy.mock.calls.filter(([e]) => e === "mousedown").length).toBe(attachesAfterMount);
    await user.click(screen.getByRole("button", { name: "outside" }));
    expect(first).not.toHaveBeenCalled();
    expect(second).toHaveBeenCalledTimes(1);
    addSpy.mockRestore();
  });
});
