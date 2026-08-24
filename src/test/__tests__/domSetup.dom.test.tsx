// @vitest-environment jsdom

import "../domSetup";
import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { focusableWithin } from "../../components/modalScaffold";

/**
 * Guards the test harness itself, not the app.
 *
 * Two things here can rot silently and take a whole class of assertion with
 * them: the `offsetParent` stand-in in `../domSetup.ts` (if it ever returns a
 * constant, every focus-trap test below goes vacuously green — see that file),
 * and the React project wiring (if JSX stopped being transformed the failure
 * would at least be loud, but if the *environment* fell back to node it would
 * not).
 */
describe("the dom project's harness", () => {
  it("renders React and gives it a document", () => {
    render(<button type="button">hello</button>);
    expect(screen.getByRole("button", { name: "hello" })).toBeInstanceOf(HTMLButtonElement);
  });

  it("gives a rendered element a non-null offsetParent", () => {
    // Unpatched jsdom answers null here, which is what would make every
    // `focusableWithin` result empty.
    const { container } = render(<button type="button">visible</button>);
    expect((container.firstElementChild as HTMLElement).offsetParent).not.toBeNull();
  });

  it("still answers null through a display:none ancestor", () => {
    const { container } = render(
      <div style={{ display: "none" }}>
        <button type="button">hidden</button>
      </div>,
    );
    const button = container.querySelector("button") as HTMLElement;
    expect(button.offsetParent).toBeNull();
  });

  it("makes focusableWithin discriminate rather than return everything or nothing", () => {
    const { container } = render(
      <div>
        <button type="button">one</button>
        <input type="file" style={{ display: "none" }} />
        <button type="button" disabled>
          disabled
        </button>
        <button type="button">two</button>
      </div>,
    );
    const found = focusableWithin(container.firstElementChild as HTMLElement);
    expect(found.map((el) => el.textContent)).toEqual(["one", "two"]);
  });
});
