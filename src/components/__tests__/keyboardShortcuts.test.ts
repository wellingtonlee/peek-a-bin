/**
 * Drift guard for the two hand-maintained shortcut lists.
 *
 * `SHORTCUT_GROUPS` (src/components/KeyboardShortcuts.tsx) drives the in-app `?`
 * panel; docs/keyboard.md is the written reference. They have drifted before —
 * all four panel keys were wrong in the doc, and the two lists claimed different
 * tab ranges — so this asserts they still describe the same keys.
 *
 * The check is deliberately spelling-tolerant: the doc writes `Arrow Up/Down`
 * where the panel writes `↑ / ↓`, and groups keys under different headings. Both
 * sides are canonicalized to key TOKENS (see {@link canonicalKeys}) and compared
 * as sets, plus a loose word-overlap check on the descriptions so a key cannot
 * silently acquire a different meaning on one side.
 */

import { describe, it, expect } from "vitest";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { SHORTCUT_GROUPS } from "../KeyboardShortcuts";
import { parseViewTab } from "../../hooks/usePEFile";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "../../..");
const DOC_PATH = resolve(REPO_ROOT, "docs/keyboard.md");
const DOC = readFileSync(DOC_PATH, "utf-8");

/**
 * Keys the doc documents but the `?` panel deliberately omits, with the reason.
 * Anything else doc-only is drift.
 */
const DOC_ONLY_KEYS = new Map([
  ["?", 'rendered in the panel footer ("Press ? to toggle this panel"), not as a row'],
]);

/** Spelling differences that survive canonicalization, mapped onto one token. */
const KEY_ALIASES = new Map([
  ["double-clickanaddress", "double-clickaddr"],
  ["double-clickafunctionlabel", "double-clicklabel"],
]);

/** Words carrying no signal when comparing a panel action to a doc description. */
const STOPWORDS = new Set([
  "the",
  "a",
  "an",
  "to",
  "in",
  "into",
  "and",
  "or",
  "of",
  "at",
  "for",
  "on",
  "with",
  "both",
  "current",
  "this",
  "its",
  "entire",
  "works",
]);

/**
 * Reduce a key spelling to comparable tokens. `Alt+←/→` and `Alt+Left` +
 * `Alt+Right` both become `alt+left` / `alt+right`; `Arrow Up/Down` and `↑ / ↓`
 * both become `up` / `down`.
 */
function canonicalKeys(raw: string): string[] {
  const s = raw
    .replace(/`/g, " ")
    .replace(/\([^)]*\)/g, " ") // "; (semicolon)", "(searchable)"
    .replace(/←/g, " left ")
    .replace(/→/g, " right ")
    .replace(/↑/g, " up ")
    .replace(/↓/g, " down ")
    .replace(/\barrow\s+/gi, " ")
    .replace(/[–—]/g, "-")
    .toLowerCase()
    .replace(/\s+or\s+/g, "|");

  const alternatives: string[] = [];
  for (const chunk of s.split("|")) {
    // A lone "/" is itself a key (search-in-graph); everything else splits on it.
    if (chunk.trim() === "/") alternatives.push("/");
    else alternatives.push(...chunk.split("/"));
  }

  const tokens: string[] = [];
  for (const alt of alternatives) {
    const token = alt.trim() === "/" ? "/" : alt.replace(/\s+/g, "");
    if (token.length === 0) continue;
    tokens.push(token);
  }

  // "alt+left/right" loses its modifier on the second half; put it back.
  if (tokens.length > 1 && tokens[0].includes("+")) {
    const prefix = tokens[0].slice(0, tokens[0].lastIndexOf("+") + 1);
    for (let i = 1; i < tokens.length; i++) {
      if (!tokens[i].includes("+")) tokens[i] = prefix + tokens[i];
    }
  }

  return tokens.map((t) => {
    const normalized = t.replace(/^cmd\+/, "ctrl+");
    return KEY_ALIASES.get(normalized) ?? normalized;
  });
}

/** Content words of a description, for the loose meaning check. */
function words(text: string): Set<string> {
  return new Set(
    text
      .toLowerCase()
      .split(/[^a-z0-9]+/)
      .filter((w) => w.length > 1 && !STOPWORDS.has(w)),
  );
}

interface DocRow {
  keyCell: string;
  description: string;
  section: string;
  line: number;
}

/** Every data row of every markdown table in docs/keyboard.md. */
function parseDocRows(markdown: string): DocRow[] {
  const lines = markdown.split("\n");
  const isSeparator = (line: string) => /^\|[\s|:-]+\|$/.test(line.trim());
  const rows: DocRow[] = [];
  let section = "(preamble)";

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith("## ")) {
      section = line.slice(3).trim();
      continue;
    }
    if (!line.startsWith("|")) continue;
    if (isSeparator(line)) continue;
    if (isSeparator(lines[i + 1] ?? "")) continue; // header row

    const cells = line
      .split("|")
      .slice(1, -1)
      .map((c) => c.trim());
    rows.push({ keyCell: cells[0] ?? "", description: cells[1] ?? "", section, line: i + 1 });
  }
  return rows;
}

const docRows = parseDocRows(DOC);

/** token → the doc rows that document it. */
const docByToken = new Map<string, DocRow[]>();
for (const row of docRows) {
  for (const token of canonicalKeys(row.keyCell)) {
    const existing = docByToken.get(token);
    if (existing) existing.push(row);
    else docByToken.set(token, [row]);
  }
}

const panelEntries = SHORTCUT_GROUPS.flatMap((group) =>
  group.shortcuts.map((s) => ({ ...s, category: group.category })),
);

describe("docs/keyboard.md parsing", () => {
  it("finds the tables", () => {
    expect(docRows.length).toBeGreaterThan(20);
    expect(docByToken.has("ctrl+f")).toBe(true);
  });

  it("skips headers and separators", () => {
    expect(docRows.some((r) => r.keyCell === "Key")).toBe(false);
    expect(docRows.some((r) => /^[-|: ]+$/.test(r.keyCell))).toBe(false);
  });
});

describe("canonicalKeys", () => {
  it.each([
    ["↑ / ↓", ["up", "down"]],
    ["Arrow Up/Down", ["up", "down"]],
    ["Alt+←/→", ["alt+left", "alt+right"]],
    ["`Alt+Left`", ["alt+left"]],
    ["`Ctrl+G` / `Cmd+G`", ["ctrl+g", "ctrl+g"]],
    ["Ctrl+Z / Ctrl+Shift+Z", ["ctrl+z", "ctrl+shift+z"]],
    ["; (semicolon)", [";"]],
    ["`1`–`9`", ["1-9"]],
    ["1-9", ["1-9"]],
    ["`/` or `Ctrl+F`", ["/", "ctrl+f"]],
    ["Double-click an address", ["double-clickaddr"]],
    ["Double-click addr", ["double-clickaddr"]],
    ["`Shift`+Click", ["shift+click"]],
  ])("canonicalizes %s", (raw, expected) => {
    expect(canonicalKeys(raw)).toEqual(expected);
  });
});

describe("SHORTCUT_GROUPS ⇄ docs/keyboard.md", () => {
  it.each(panelEntries.map((e) => [`${e.category}: ${e.key}`, e] as const))(
    "%s is documented in docs/keyboard.md",
    (_label, entry) => {
      const tokens = canonicalKeys(entry.key);
      const missing = tokens.filter((t) => !docByToken.has(t));

      expect(
        missing,
        `SHORTCUT_GROUPS has "${entry.key}" (${entry.category} — ${entry.action}) but ` +
          `docs/keyboard.md documents no row for ${missing.map((m) => `"${m}"`).join(", ")}. ` +
          `Add it to docs/keyboard.md, or remove it from SHORTCUT_GROUPS in ` +
          `src/components/KeyboardShortcuts.tsx. The two lists must be edited together.`,
      ).toEqual([]);
    },
  );

  it.each(panelEntries.map((e) => [`${e.category}: ${e.key}`, e] as const))(
    "%s means the same thing in both lists",
    (_label, entry) => {
      const matching = canonicalKeys(entry.key).flatMap((t) => docByToken.get(t) ?? []);
      if (matching.length === 0) return; // reported by the previous test

      const panelWords = words(entry.action);
      const docWords = new Set(matching.flatMap((r) => [...words(r.description)]));
      const shared = [...panelWords].filter((w) => docWords.has(w));

      expect(
        shared.length,
        `"${entry.key}" is described as "${entry.action}" in SHORTCUT_GROUPS but as ` +
          matching
            .map((r) => `"${r.description}" (docs/keyboard.md:${r.line}, ${r.section})`)
            .join(" / ") +
          `. The descriptions share no words, which usually means one side was changed alone.`,
      ).toBeGreaterThan(0);
    },
  );

  it.each([...docByToken.entries()].map(([token, rows]) => [token, rows[0]] as const))(
    'doc key "%s" still exists in SHORTCUT_GROUPS',
    (token, row) => {
      if (DOC_ONLY_KEYS.has(token)) return;

      const panelTokens = new Set(panelEntries.flatMap((e) => canonicalKeys(e.key)));

      expect(
        panelTokens.has(token),
        `docs/keyboard.md:${row.line} (${row.section}) documents "${row.keyCell}" — ` +
          `"${row.description}", but no SHORTCUT_GROUPS entry in ` +
          `src/components/KeyboardShortcuts.tsx binds "${token}". Either the shortcut was ` +
          `removed from the app and the doc was not updated, or the new binding is missing ` +
          `from the "?" panel. If it is intentionally panel-less, add it to DOC_ONLY_KEYS ` +
          `in this test with a reason.`,
      ).toBe(true);
    },
  );
});

describe("tab-switch range", () => {
  /** The `1`–`9` row, whose second cell names every tab in order. */
  const tabRow = docRows.find((r) => canonicalKeys(r.keyCell).includes("1-9"));

  it("is documented with the same range the panel shows", () => {
    expect(tabRow, "docs/keyboard.md no longer documents a tab-switching key range").toBeDefined();

    const panelKeys = panelEntries.filter((e) => /switch tabs/i.test(e.action)).map((e) => e.key);
    expect(
      panelKeys,
      `docs/keyboard.md documents "${tabRow?.keyCell}" for tab switching; SHORTCUT_GROUPS ` +
        `must claim the same range.`,
    ).toEqual(["1-9"]);
  });

  it("names one real tab per number in the range", () => {
    const names = (tabRow?.description.match(/\(([^)]*)\)/)?.[1] ?? "")
      .split(",")
      .map((n) => n.trim())
      .filter(Boolean);

    // "Disasm" is the UI label for the "disassembly" tab.
    const aliases: Record<string, string> = { disasm: "disassembly" };
    const unknown = names.filter((n) => {
      const key = n.toLowerCase();
      return parseViewTab(aliases[key] ?? key) === null;
    });

    expect(
      unknown,
      `docs/keyboard.md:${tabRow?.line} lists tab name(s) that are not ViewTab values in ` +
        `src/hooks/usePEFile.ts: ${unknown.join(", ")}`,
    ).toEqual([]);

    expect(
      names.length,
      `docs/keyboard.md:${tabRow?.line} lists ${names.length} tab names but documents the key ` +
        `range "${tabRow?.keyCell}". Add or remove a tab name so the range matches — a wrong ` +
        `range here is exactly the drift this guard exists for.`,
    ).toBe(9);
  });
});
