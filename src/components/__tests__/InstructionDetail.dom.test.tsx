// @vitest-environment jsdom

import "../../test/domSetup";
import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import type { DisasmFunction, Instruction, Xref, XrefType } from "../../disasm/types";
import { InstructionDetail } from "../InstructionDetail";

/**
 * THE INSTRUCTION DETAIL PANEL's two xref-kind tables, rendered directly.
 *
 * The component was reachable from `DisassemblyPanel.dom.test.tsx` — which
 * mounts it through the real `DisassemblyView` — but nothing had ever asserted
 * on `TYPE_COLORS` or `TYPE_LABELS`, the two `Record`s that fold an xref's kind
 * onto a colour class and a single letter. Both were `Record<string, …>` over a
 * union spelled inline in `Xref`, so a fifth kind rendered as the grey `?` the
 * `?? fallback`s spell, silently. `XrefType` is named now and both are keyed on
 * it, so a fifth member fails the build; these rows are the other half — that
 * the four kinds that DO exist each reach the screen as themselves
 * (peek-a-bin-v3uh.8).
 *
 * NOT SHARED WITH `XrefPanel`, deliberately, and that is worth stating in a test
 * file too because the two tables hold the same four class strings and look like
 * one table written twice. They are not: this panel writes a letter into a `w-3`
 * cell, the other writes the kind's name into a `w-12` column, and a palette is
 * legitimately the caller's (`components/severity.ts` says so of its own
 * readers). What has one declaration is the UNION.
 *
 * jsdom, so these are CLASS NAME strings. Tailwind is not loaded, no colour is
 * computed, and nothing here is an appearance assertion.
 */

const BASE = 0x140001000;
const MAIN: DisasmFunction = { name: "main", address: BASE, size: 0x40 };

/** A `nop` — no branch target, so `xrefFrom` stays null and only "Xrefs To" renders. */
const INSN: Instruction = {
  address: BASE + 0x10,
  bytes: new Uint8Array([0x90]),
  mnemonic: "nop",
  opStr: "",
  size: 1,
};

const KINDS: XrefType[] = ["call", "jmp", "branch", "data"];

/** One xref of each kind onto `INSN`, so all four letters are on screen at once. */
const XREFS_TO = new Map<number, Xref[]>([
  [INSN.address, KINDS.map((type, i) => ({ from: BASE + 0x20 + i * 4, type }))],
]);

function renderDetail(over: Partial<Parameters<typeof InstructionDetail>[0]> = {}) {
  const onNavigate = vi.fn();
  const onClose = vi.fn();
  const result = render(
    <InstructionDetail
      insn={INSN}
      typedXrefMap={XREFS_TO}
      funcMap={new Map([[MAIN.address, MAIN]])}
      iatMap={new Map()}
      renames={{}}
      sortedFuncs={[MAIN]}
      onNavigate={onNavigate}
      onClose={onClose}
      {...over}
    />,
  );
  return { ...result, onNavigate, onClose };
}

/** The kind badge of each "Xrefs To" row, in rendered order. */
function badges(): HTMLElement[] {
  return Array.from(document.querySelectorAll("span.w-3"));
}

describe("InstructionDetail's xref kind badges", () => {
  it("renders one row per xref, and says how many", () => {
    renderDetail();
    // Liveness: every assertion below is over this population, and a table-driven
    // colour check passes vacuously if the rows are not there at all.
    expect(screen.getByText("Xrefs To (4)")).toBeTruthy();
    expect(badges()).toHaveLength(4);
  });

  it.each([
    ["call", "C", "text-green-400"],
    ["jmp", "J", "text-red-400"],
    ["branch", "B", "text-orange-400"],
    ["data", "D", "text-purple-400"],
  ])("gives a %s xref the letter %s in its own colour", (_kind, letter, cls) => {
    renderDetail();
    const badge = badges().find((b) => b.textContent === letter);
    expect(badge).toBeTruthy();
    expect(badge?.className).toContain(cls);
    // The `?? fallback` pair. Neither may be what a KNOWN kind renders as.
    expect(badge?.className).not.toContain("text-gray-400");
  });

  it("gives no two kinds the same letter or the same colour", () => {
    renderDetail();
    // The property the per-kind rows cannot state. A table with two kinds folded
    // onto one entry still passes every case written against that entry's own
    // value — which is exactly how a fall-through hides.
    expect(new Set(badges().map((b) => b.textContent)).size).toBe(4);
    expect(new Set(badges().map((b) => b.className)).size).toBe(4);
  });

  it("says None, not an empty column, where nothing references the instruction", () => {
    renderDetail({ typedXrefMap: new Map() });
    expect(screen.getByText("Xrefs To (0)")).toBeTruthy();
    expect(badges()).toHaveLength(0);
  });
});
