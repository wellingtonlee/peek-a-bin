// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import type { AppState } from "../../hooks/usePEFile";
import { initialState } from "../../hooks/usePEFile";
import type { BatchRenameResult } from "../../llm/types";
import { AIReportPanel } from "../AIReportPanel";
import { BatchRenameModal } from "../BatchRenameModal";
import { AppHarness } from "./appStateHarness";

/**
 * The two dialogs whose dismissibility is CONDITIONAL, together, because that
 * condition is the one thing they share and the one thing most likely to rot.
 *
 * `accidentalDismissAllowed` is pinned as a rule over two booleans in
 * `modalScaffold.test.ts`, and `Modal.dom.test.tsx` pins that `closeOnEscape`
 * is honoured. What neither can see is which booleans each dialog passes at
 * which moment — and that is the whole substance of the decision: Escape closes
 * a finished report and must not close a streaming one; it closes a failed
 * batch rename and must not close a running one or a review table full of
 * accept/reject choices. Every one of those is a state-dependent argument to a
 * prop, so it is a render or it is nothing.
 *
 * `peek-a-bin-v2u` section 2 states the same rule as a manual check ("closes
 * everywhere EXCEPT Settings, batch rename while running, and the AI report
 * while streaming"). This is that check, automated as far as jsdom honestly
 * reaches.
 *
 * SCOPE: jsdom, no layout, no browser focus algorithm, no screen reader. What is
 * verified is the component's own logic and the attributes and focus it
 * produces.
 */

const RESULTS: BatchRenameResult[] = [
  {
    address: 0x401000,
    currentName: "sub_401000",
    suggestedName: "parse_header",
    confidence: 0.95,
    reasoning: "reads e_lfanew",
    accepted: null,
  },
  {
    address: 0x401100,
    currentName: "sub_401100",
    suggestedName: "maybe_hash",
    confidence: 0.4,
    reasoning: "unclear",
    accepted: null,
  },
];

type BatchState = NonNullable<AppState["batchRename"]>;
type ReportState = NonNullable<AppState["aiReport"]>;

function renderBatch(batchRename: BatchState) {
  const dispatch = vi.fn();
  const view = render(
    <AppHarness state={{ ...initialState, batchRename }} dispatch={dispatch}>
      <BatchRenameModal />
    </AppHarness>,
  );
  return { dispatch, view, user: userEvent.setup() };
}

function renderReport(aiReport: ReportState, over: Partial<AppState> = {}) {
  const onClose = vi.fn();
  const onRegenerate = vi.fn();
  render(
    <AppHarness state={{ ...initialState, aiReport, ...over }} dispatch={vi.fn()}>
      <AIReportPanel onClose={onClose} onRegenerate={onRegenerate} />
    </AppHarness>,
  );
  return { onClose, onRegenerate, user: userEvent.setup() };
}

const progressState = (over: Partial<BatchState> = {}): BatchState => ({
  status: "decompiling",
  progress: { done: 3, total: 10 },
  results: [],
  error: null,
  ...over,
});

const reviewState = (): BatchState => ({
  status: "review",
  progress: { done: 2, total: 2 },
  results: RESULTS,
  error: null,
});

const hasBackdrop = () => screen.queryByRole("button", { name: "Close dialog" }) !== null;

describe("BatchRenameModal while a run is in flight", () => {
  it("refuses Escape, because the keystroke abandons the run", async () => {
    const { user, dispatch } = renderBatch(progressState());
    await user.keyboard("{Escape}");
    expect(dispatch).not.toHaveBeenCalled();
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("offers no backdrop to click by accident either", () => {
    renderBatch(progressState());
    expect(hasBackdrop()).toBe(false);
  });

  it("keeps a deliberate Cancel, which really does drop the run", async () => {
    const { user, dispatch } = renderBatch(progressState());
    await user.click(screen.getByRole("button", { name: "Cancel" }));
    // BATCH_RENAME_DISMISS, not a "hide" — which is exactly why the accidental
    // routes above are withheld.
    expect(dispatch).toHaveBeenCalledWith({ type: "BATCH_RENAME_DISMISS" });
  });

  it("reports progress as a percentage of the total", () => {
    renderBatch(progressState({ status: "running", progress: { done: 7, total: 28 } }));
    expect(screen.getByText("Generating names...")).toBeTruthy();
    expect(screen.getByText("7 / 28")).toBeTruthy();
    expect(screen.getByText("25%")).toBeTruthy();
  });

  it("does not divide by zero before the total is known", () => {
    renderBatch(progressState({ progress: { done: 0, total: 0 } }));
    expect(screen.getByText("0%")).toBeTruthy();
  });
});

describe("BatchRenameModal review table", () => {
  it("refuses Escape, because the accept/reject choices are unsaved work", async () => {
    const { user, dispatch } = renderBatch(reviewState());
    await user.keyboard("{Escape}");
    expect(dispatch).not.toHaveBeenCalled();
    expect(hasBackdrop()).toBe(false);
    expect(screen.getByRole("button", { name: "Cancel" })).toBeTruthy();
  });

  it("pre-accepts only the high-confidence suggestions", () => {
    renderBatch(reviewState());
    // 0.95 is in, 0.4 is undecided — the threshold is 0.8 and the point of it is
    // that the count in the footer is what Apply will act on.
    expect(screen.getByText("1 selected for rename")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Apply (1)" })).toBeTruthy();
  });

  it("applies exactly the rows that are accepted", async () => {
    const { user, dispatch } = renderBatch(reviewState());
    await user.click(screen.getByRole("button", { name: "Accept All" }));
    expect(screen.getByText("2 selected for rename")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Apply (2)" }));
    expect(dispatch).toHaveBeenCalledWith({
      type: "BATCH_RENAME_ACCEPT",
      results: [
        { ...RESULTS[0], accepted: true },
        { ...RESULTS[1], accepted: true },
      ],
    });
  });

  it("rejects all, and then cannot apply", async () => {
    const { user, dispatch } = renderBatch(reviewState());
    await user.click(screen.getByRole("button", { name: "Reject All" }));
    expect(screen.getByText("0 selected for rename")).toBeTruthy();
    const apply = screen.getByRole("button", { name: "Apply (0)" }) as HTMLButtonElement;
    expect(apply.disabled).toBe(true);
    await user.click(apply);
    expect(dispatch).not.toHaveBeenCalled();
  });

  it("toggles one row without disturbing the others", async () => {
    const { user, dispatch } = renderBatch(reviewState());
    const rows = screen.getAllByRole("row").slice(1); // drop the header row
    expect(rows).toHaveLength(2);
    // Row 2 is the undecided one; its checkbox is the first button in the row.
    await user.click(within(rows[1]).getAllByRole("button")[0]);
    expect(screen.getByText("2 selected for rename")).toBeTruthy();
    await user.click(within(rows[0]).getAllByRole("button")[0]);
    expect(screen.getByText("1 selected for rename")).toBeTruthy();
    await user.click(screen.getByRole("button", { name: "Apply (1)" }));
    expect(dispatch).toHaveBeenCalledWith({
      type: "BATCH_RENAME_ACCEPT",
      results: [
        { ...RESULTS[0], accepted: false },
        { ...RESULTS[1], accepted: true },
      ],
    });
  });

  it("restores the high-confidence defaults after a reject-all", async () => {
    const { user } = renderBatch(reviewState());
    await user.click(screen.getByRole("button", { name: "Reject All" }));
    await user.click(screen.getByRole("button", { name: "Accept High Conf" }));
    // Only the 0.95 row comes back; the 0.4 row stays explicitly rejected.
    expect(screen.getByText("1 selected for rename")).toBeTruthy();
  });

  it("shows each suggestion with its confidence", () => {
    renderBatch(reviewState());
    expect(screen.getByText("parse_header")).toBeTruthy();
    expect(screen.getByText("95%")).toBeTruthy();
    expect(screen.getByText("maybe_hash")).toBeTruthy();
    expect(screen.getByText("40%")).toBeTruthy();
  });
});

describe("BatchRenameModal error state", () => {
  it("IS dismissible, because a failed run has nothing left to lose", async () => {
    const { user, dispatch } = renderBatch({
      status: "idle",
      progress: { done: 0, total: 0 },
      results: [],
      error: "rate limited",
    });
    expect(screen.getByText("rate limited")).toBeTruthy();
    expect(hasBackdrop()).toBe(true);
    await user.keyboard("{Escape}");
    expect(dispatch).toHaveBeenCalledWith({ type: "BATCH_RENAME_DISMISS" });
  });
});

describe("BatchRenameModal remounts between its three dialogs", () => {
  it("moves focus into the review dialog when the run finishes", async () => {
    const dispatch = vi.fn();
    const { rerender } = render(
      <AppHarness state={{ ...initialState, batchRename: progressState() }} dispatch={dispatch}>
        <BatchRenameModal />
      </AppHarness>,
    );
    // Focus starts on the progress dialog's only control.
    const cancel = screen.getByRole("button", { name: "Cancel" });
    expect(document.activeElement).toBe(cancel);

    rerender(
      <AppHarness state={{ ...initialState, batchRename: reviewState() }} dispatch={dispatch}>
        <BatchRenameModal />
      </AppHarness>,
    );

    // The `key` on each Modal is what makes this a remount rather than a props
    // change: without it React keeps the Modal instance, its mount-only focus
    // effect does not re-run, and the Cancel button that had focus is unmounted
    // underneath the trap — dropping focus onto <body>.
    expect(document.activeElement).not.toBe(document.body);
    const dialog = screen.getByRole("dialog");
    expect(dialog.contains(document.activeElement)).toBe(true);
    expect(dialog.getAttribute("aria-labelledby")).toBe("batch-rename-review-title");
  });
});

describe("BatchRenameModal absent", () => {
  it("renders nothing when there is no run", () => {
    renderBatch(null as unknown as BatchState);
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("renders nothing for a status with no dialog of its own", () => {
    renderBatch({ status: "applying", progress: { done: 2, total: 2 }, results: [], error: null });
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});

describe("AIReportPanel while streaming", () => {
  const streaming = (): ReportState => ({ status: "streaming", content: "", error: null });

  it("refuses Escape, because a partial report cannot be recovered", async () => {
    const { user, onClose } = renderReport(streaming());
    await user.keyboard("{Escape}");
    expect(onClose).not.toHaveBeenCalled();
    expect(hasBackdrop()).toBe(false);
  });

  it("keeps a deliberate Close", async () => {
    const { user, onClose } = renderReport(streaming());
    await user.click(screen.getByRole("button", { name: "Close" }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("offers neither Regenerate nor Download until there is a report", () => {
    renderReport(streaming());
    expect(screen.getByText("Generating...")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Regenerate" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Download .md" })).toBeNull();
  });

  it("renders the partial content as it arrives", () => {
    renderReport({ status: "streaming", content: "# Half a report", error: null });
    expect(screen.getByRole("heading", { name: "Half a report" })).toBeTruthy();
  });
});

describe("AIReportPanel once the report is done", () => {
  const done = (): ReportState => ({
    status: "done",
    content: "## Findings\n\nCalls `CreateFileW`.",
    error: null,
  });

  it("IS dismissible — a finished report is persisted and reopening reads it back", async () => {
    const { user, onClose } = renderReport(done());
    expect(hasBackdrop()).toBe(true);
    await user.keyboard("{Escape}");
    expect(onClose).toHaveBeenCalledTimes(1);
  });

  it("renders the markdown rather than its source", () => {
    renderReport(done());
    expect(screen.getByRole("heading", { name: "Findings" })).toBeTruthy();
    expect(screen.getByText("CreateFileW")).toBeTruthy();
  });

  it("offers Regenerate, and it is wired", async () => {
    const { user, onRegenerate } = renderReport(done());
    await user.click(screen.getByRole("button", { name: "Regenerate" }));
    expect(onRegenerate).toHaveBeenCalledTimes(1);
  });

  it("names the download after the loaded file", async () => {
    const created = vi.spyOn(URL, "createObjectURL").mockReturnValue("blob:stub");
    const revoked = vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
    // jsdom would try to navigate on a real anchor click; the download attribute
    // is what is under test, so the click itself is intercepted.
    const clicks: string[] = [];
    const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
      this: HTMLAnchorElement,
    ) {
      clicks.push(this.download);
    });
    try {
      const { user } = renderReport(done(), { fileName: "driver.sys" });
      await user.click(screen.getByRole("button", { name: "Download .md" }));
      expect(clicks).toEqual(["driver.sys-report.md"]);
      expect(created).toHaveBeenCalledTimes(1);
      expect(revoked).toHaveBeenCalledTimes(1);
    } finally {
      click.mockRestore();
      revoked.mockRestore();
      created.mockRestore();
    }
  });

  it("takes its accessible name from its own heading", () => {
    renderReport(done());
    const dialog = screen.getByRole("dialog");
    expect(dialog.getAttribute("aria-labelledby")).toBe("ai-report-title");
    expect(screen.getByRole("dialog", { name: "AI Analysis Report" })).toBe(dialog);
  });
});

describe("AIReportPanel error", () => {
  it("shows the error above whatever content arrived", () => {
    renderReport({ status: "error", content: "partial", error: "context too long" });
    expect(screen.getByText("context too long")).toBeTruthy();
    expect(screen.getByText("partial")).toBeTruthy();
  });

  it("renders nothing when there is no report at all", () => {
    render(
      <AppHarness state={initialState} dispatch={vi.fn()}>
        <AIReportPanel onClose={vi.fn()} onRegenerate={vi.fn()} />
      </AppHarness>,
    );
    expect(screen.queryByRole("dialog")).toBeNull();
  });
});
