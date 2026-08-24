/**
 * The pure half of the tablist's id wiring.
 *
 * What this can settle: that the two minters are total over `VIEW_TABS`, that
 * they never collide with each other, and that neither answer is a prefix of
 * another tab's — a `getElementById` cannot be fooled by a prefix, but a
 * `querySelector('[id^=…]')` written later could, and an id scheme that
 * tolerates it is one nobody has to think about again.
 *
 * What it CANNOT settle is whether either id names an element anybody rendered.
 * That is `src/__tests__/App.dom.test.tsx`'s, which resolves the live
 * `aria-controls` of every rendered tab against the document. Both halves are
 * needed: this one fails on arithmetic, that one fails on wiring, and neither
 * failure implies the other. Exactly the split `listboxIds.test.ts` documents.
 */

import { describe, expect, it } from "vitest";
import { VIEW_TABS } from "../../hooks/usePEFile";
import { tabId, tabPanelId } from "../tabIds";

describe("tabIds", () => {
  it("mints the ids the components actually write", () => {
    // Pinned as literals rather than derived: a test that recomputes the
    // template is a second copy of the implementation and agrees with any
    // change to it, including a wrong one.
    expect(tabId("disassembly")).toBe("view-tab-disassembly");
    expect(tabPanelId("disassembly")).toBe("view-tabpanel-disassembly");
    expect(tabId("anomalies")).toBe("view-tab-anomalies");
    expect(tabPanelId("anomalies")).toBe("view-tabpanel-anomalies");
  });

  it("gives every tab a distinct pair, and no id twice", () => {
    const all = [...VIEW_TABS.map(tabId), ...VIEW_TABS.map(tabPanelId)];
    expect(new Set(all).size).toBe(all.length);
    expect(all).toHaveLength(VIEW_TABS.length * 2);
  });

  it("keeps a tab id from being a prefix of any other id", () => {
    // `view-tab-` is a prefix of `view-tabpanel-`, so the discriminating case is
    // the whole id against the whole id: no `tabId` may prefix another id, or a
    // future prefix selector would match two elements and pick the wrong one.
    const all = [...VIEW_TABS.map(tabId), ...VIEW_TABS.map(tabPanelId)];
    for (const a of all) {
      const prefixed = all.filter((b) => b !== a && b.startsWith(a));
      expect(prefixed, `${a} is a prefix of ${prefixed.join(", ")}`).toEqual([]);
    }
  });

  it("answers for every tab in the union, not just the ones in use", () => {
    for (const tab of VIEW_TABS) {
      expect(tabId(tab)).toContain(tab);
      expect(tabPanelId(tab)).toContain(tab);
      expect(tabId(tab)).not.toBe(tabPanelId(tab));
    }
  });
});
