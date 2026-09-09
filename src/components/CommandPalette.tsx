import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSortedFuncs } from "../hooks/useDerivedState";
import {
  type AppAction,
  getDisplayName,
  useAppDispatch,
  useAppState,
  VIEW_TABS,
  type ViewTab,
} from "../hooks/usePEFile";
import type { ImportEntry } from "../pe/types";
import { fuzzyMatch } from "../utils/fuzzyMatch";
import { VIEW_TAB_LABELS } from "./analysisNotice";
import { activeDescendantId, optionId } from "./listboxIds";
import { Modal } from "./Modal";

interface CommandPaletteProps {
  open: boolean;
  onClose: () => void;
}

/** The palette's categories. Closed on purpose — see {@link ResultItem}. */
type ResultCategory = "Functions" | "Imports" | "Exports" | "Strings" | "Commands";

/**
 * A `peek-a-bin:*` event a command may fire.
 *
 * Every event a command may fire, and the closed union `PaletteEventName` is
 * derived from it. Each member must be one something in the tree **already
 * listens for** (`grep -rn 'addEventListener("peek-a-bin:' src`): an entry
 * naming an event nobody listens for is a palette row that silently does
 * nothing, and `window.dispatchEvent` fires it happily and returns `true`.
 *
 * **The union stops a typo at the call site and NOTHING ELSE — measured.**
 * Adding a member here for an event no component listens for type-checks with
 * zero errors. That is why this is an ARRAY as well as a union:
 * `paletteEvents.test.ts` reads it back against the tree's `addEventListener`
 * calls, which is the half a type cannot state. Growing the table means adding
 * a listener first.
 *
 * `peek-a-bin:show-xrefs` is deliberately absent even though it is listened for:
 * its handler requires a `detail.address` and lives inside `DisassemblyView`, so
 * fired from any other tab it is a no-op — the class of defect this table
 * exists to close, not to reproduce.
 */
export const PALETTE_EVENTS = ["peek-a-bin:open-chat", "peek-a-bin:open-settings"] as const;

type PaletteEventName = (typeof PALETTE_EVENTS)[number];

/**
 * What selecting a row does.
 *
 * A discriminated union rather than the `action?: string` it replaced. That
 * field made "no action" and "an action nobody handles" the same shape, so
 * `handleSelect` fell through to navigating to `address` (0 for a command) with
 * nothing said. Every arm is now spelled out in one `switch` closed by a `never`
 * assert, so a new kind fails the build instead of doing nothing.
 */
type ResultTarget =
  | { kind: "navigate"; address: number; tab: ViewTab }
  | { kind: "event"; event: PaletteEventName }
  | { kind: "action"; action: AppAction };

interface ResultItem {
  category: ResultCategory;
  label: string;
  target: ResultTarget;
}

/** A command's effect: an existing event or an `AppAction`, never a navigation. */
type CommandTarget = Exclude<ResultTarget, { kind: "navigate" }>;

export interface PaletteCommand {
  readonly label: string;
  readonly target: CommandTarget;
}

/**
 * Every command the palette offers, as a module-level table.
 *
 * Exported so the derivation below can be asserted without rendering anything.
 *
 * **Tab labels are DERIVED from `VIEW_TAB_LABELS`, never spelled.** That map is
 * the one declaration of what a tab is called — `AddressBar`'s buttons and
 * `analysisNotice`'s prose both read it — so a literal here would be a second
 * spelling, i.e. a tab called one thing on its button and another in the
 * palette. `VIEW_TABS` supplies the membership and the order for the same
 * reason, so a ninth tab gets a command for free rather than being forgotten.
 *
 * **Two things are deliberately NOT here**, both destructive and both already
 * reachable elsewhere: `RESET` ("close file") and `CLEAR_PATCHES` ("clear
 * patches"), each of which discards the user's own work. Their existing entry
 * points are where a confirmation belongs; a palette row would be a second,
 * unguarded path to the same loss, one keystroke from a fuzzy match. A palette
 * entry is not a reason to widen a blast radius.
 */
export const PALETTE_COMMANDS: readonly PaletteCommand[] = [
  { label: "AI: Open Chat", target: { kind: "event", event: "peek-a-bin:open-chat" } },
  { label: "Open Settings", target: { kind: "event", event: "peek-a-bin:open-settings" } },
  // No address: the reducer reads `state.currentAddress`, which is the cursor
  // the user is looking at — the same thing the `B` shortcut bookmarks.
  { label: "Toggle Bookmark", target: { kind: "action", action: { type: "TOGGLE_BOOKMARK" } } },
  { label: "Undo Annotation", target: { kind: "action", action: { type: "UNDO_ANNOTATION" } } },
  { label: "Redo Annotation", target: { kind: "action", action: { type: "REDO_ANNOTATION" } } },
  ...VIEW_TABS.map(
    (tab): PaletteCommand => ({
      label: `Go to ${VIEW_TAB_LABELS[tab]}`,
      target: { kind: "action", action: { type: "SET_TAB", tab } },
    }),
  ),
];

const CAP = 15;

/**
 * Only one palette is ever mounted, so a module constant is enough and keeps
 * the id stable across renders — `aria-activedescendant` points at it by value,
 * and an id that changed per render would leave a dangling reference.
 */
const LISTBOX_ID = "command-palette-results";

interface ResultSet {
  items: ResultItem[];
  /** Categories whose match list was cut short by {@link CAP}. */
  truncated: ReadonlySet<ResultCategory>;
}

/**
 * Push at most {@link CAP} matches from `rows`, recording the cut if there were
 * more.
 *
 * The scan stops at the FIRST match past the cap, so the admission costs one
 * extra `match` call and not a full pass. That is why the line it produces says
 * "the first 15" rather than "N more": an exact remainder means matching every
 * candidate on every keystroke, and these categories are not small — the string
 * map of a large image holds millions of entries (`MAX_STRING_SCAN_BYTES` is
 * 64 MiB). An admission that costs more than the answer it qualifies would be
 * paid on every keystroke by every user to phrase a sentence about 15 rows.
 *
 * `match` builds the `ResultItem` only for a row that matches, so no category
 * pays for label construction it throws away.
 */
function collect<T>(
  out: ResultItem[],
  truncated: Set<ResultCategory>,
  category: ResultCategory,
  rows: Iterable<T>,
  match: (row: T) => ResultItem | null,
): void {
  let shown = 0;
  for (const row of rows) {
    const item = match(row);
    if (!item) continue;
    if (shown === CAP) {
      truncated.add(category);
      return;
    }
    out.push(item);
    shown++;
  }
}

/**
 * The import table flattened to one row per imported function.
 *
 * A generator so {@link collect}'s cap really stops the walk: the table is
 * nested (libraries x functions) and the cap is over the flattened rows, which
 * is what the hand-written double loop it replaces also did.
 */
function* importRows(
  imports: readonly ImportEntry[],
): Generator<{ label: string; address: number }> {
  for (const imp of imports) {
    for (let fi = 0; fi < imp.functions.length; fi++) {
      yield {
        label: `${imp.libraryName}!${imp.functions[fi]}`,
        address: imp.iatAddresses[fi] ?? 0,
      };
    }
  }
}

export function CommandPalette({ open, onClose }: CommandPaletteProps) {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const [query, setQuery] = useState("");
  const [selectedIdx, setSelectedIdx] = useState(0);
  const inputRef = useRef<HTMLInputElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Focusing the search field is Modal's job now (via initialFocusRef) — it runs
  // on mount, which is the same moment, without the setTimeout(0) trampoline.
  useEffect(() => {
    if (open) {
      setQuery("");
      setSelectedIdx(0);
    }
  }, [open]);

  const sortedFuncs = useSortedFuncs();

  const results = useMemo((): ResultSet => {
    const items: ResultItem[] = [];
    const truncated = new Set<ResultCategory>();
    if (!pe || !query) return { items, truncated };

    collect(items, truncated, "Functions", sortedFuncs, (fn) => {
      const name = getDisplayName(fn, state.renames);
      return fuzzyMatch(query, name)
        ? {
            category: "Functions",
            label: name,
            target: { kind: "navigate", address: fn.address, tab: "disassembly" },
          }
        : null;
    });

    collect(items, truncated, "Imports", importRows(pe.imports), (row) =>
      fuzzyMatch(query, row.label)
        ? {
            category: "Imports",
            label: row.label,
            target: { kind: "navigate", address: row.address, tab: "imports" },
          }
        : null,
    );

    collect(items, truncated, "Exports", pe.exports ?? [], (exp) =>
      fuzzyMatch(query, exp.name)
        ? {
            category: "Exports",
            label: exp.name,
            target: {
              kind: "navigate",
              address: pe.optionalHeader.imageBase + exp.address,
              tab: "exports",
            },
          }
        : null,
    );

    collect(items, truncated, "Strings", pe.strings ?? [], ([addr, str]) =>
      fuzzyMatch(query, str)
        ? {
            category: "Strings",
            label: str.length > 80 ? str.substring(0, 77) + "..." : str,
            target: { kind: "navigate", address: addr, tab: "strings" },
          }
        : null,
    );

    collect(items, truncated, "Commands", PALETTE_COMMANDS, (cmd) =>
      fuzzyMatch(query, cmd.label)
        ? { category: "Commands", label: cmd.label, target: cmd.target }
        : null,
    );

    return { items, truncated };
  }, [pe, query, sortedFuncs, state.renames]);

  // results.items.length is a change key the body never reads: the selection
  // resets whenever the result set changes size. Removing it would reset the
  // highlight only on mount, leaving it pointing past the end of a shorter
  // result list.
  // biome-ignore lint/correctness/useExhaustiveDependencies: results.items.length is the change key this reset effect is triggered by, not a value it reads.
  useEffect(() => {
    setSelectedIdx(0);
  }, [results.items.length]);

  const handleSelect = useCallback(
    (item: ResultItem) => {
      const target = item.target;
      switch (target.kind) {
        case "navigate":
          dispatch({ type: "SET_ADDRESS", address: target.address });
          dispatch({ type: "SET_TAB", tab: target.tab });
          break;
        case "event":
          window.dispatchEvent(new CustomEvent(target.event));
          break;
        case "action":
          dispatch(target.action);
          break;
        default: {
          // A new ResultTarget kind fails the build here rather than selecting
          // a row that does nothing.
          const unreachable: never = target;
          throw new Error(`unhandled palette target: ${JSON.stringify(unreachable)}`);
        }
      }
      onClose();
    },
    [dispatch, onClose],
  );

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        setSelectedIdx((i) => Math.min(i + 1, results.items.length - 1));
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        setSelectedIdx((i) => Math.max(i - 1, 0));
      } else if (e.key === "Enter" && results.items.length > 0) {
        e.preventDefault();
        handleSelect(results.items[selectedIdx]);
      }
      // Escape is not handled here — it bubbles to Modal, which closes the dialog.
    },
    [results, selectedIdx, handleSelect],
  );

  // Scroll selected into view
  useEffect(() => {
    const container = listRef.current;
    if (!container) return;
    const el = container.querySelector(`[data-idx="${selectedIdx}"]`);
    if (el) el.scrollIntoView({ block: "nearest" });
  }, [selectedIdx]);

  if (!open) return null;

  // Group results by category for display
  let currentCategory = "";

  return (
    <Modal
      // Named by a string rather than by a heading: the palette opens straight
      // onto its search field and has no visible title to point `labelledBy` at.
      // Adding one purely to be referenced would change the dialog for everyone
      // to satisfy an attribute.
      label="Command palette"
      onClose={onClose}
      placement="top"
      initialFocusRef={inputRef}
      className="w-[600px] shadow-2xl overflow-hidden"
    >
      <div className="p-3 border-b border-gray-700">
        {/* A combobox owning a listbox, not a text field next to buttons.
            Focus stays here while the arrow keys move selectedIdx, and
            aria-activedescendant is what tells a screen reader which row is
            selected — previously the highlight was purely visual and was
            never announced. */}
        <input
          ref={inputRef}
          type="text"
          role="combobox"
          aria-expanded={results.items.length > 0}
          aria-controls={LISTBOX_ID}
          aria-activedescendant={activeDescendantId(LISTBOX_ID, selectedIdx, results.items.length)}
          aria-autocomplete="list"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="Search functions, imports, exports, strings, commands..."
          className="w-full px-3 py-2 bg-gray-900 border border-gray-600 rounded text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
      </div>
      <div
        ref={listRef}
        id={LISTBOX_ID}
        role="listbox"
        aria-label="Search results"
        className="max-h-[400px] overflow-auto"
      >
        {query && results.items.length === 0 && (
          <div className="px-4 py-8 text-center text-gray-500 text-sm">No results</div>
        )}
        {!query && (
          <div className="px-4 py-8 text-center text-gray-500 text-sm">
            Type to search across functions, imports, exports, strings, and commands
          </div>
        )}
        {results.items.map((item, i) => {
          const showHeader = item.category !== currentCategory;
          currentCategory = item.category;
          // The admission belongs after the LAST row of a cut-short category,
          // which is this row exactly when the next one is in another category.
          const admit =
            results.truncated.has(item.category) &&
            results.items[i + 1]?.category !== item.category;
          return (
            <div key={`${item.category}-${item.label}-${i}`} role="presentation">
              {showHeader && (
                <div
                  role="presentation"
                  className="px-4 py-1.5 text-[10px] font-semibold text-gray-500 uppercase tracking-wider bg-gray-800/80 sticky top-0"
                >
                  {item.category}
                </div>
              )}
              {/* An option, not a button. As a button every one of these (up to
                  60) sat in the tab order, so Tab from the search field walked
                  the whole result list and the modal focus trap cycled through
                  all of it. Keyboard activation lives on the input, which is
                  where focus actually is. */}
              {/* biome-ignore lint/a11y/useKeyWithClickEvents: arrow keys and Enter are handled by the combobox input that owns this listbox via aria-activedescendant; focus never reaches the option itself. */}
              <div
                id={optionId(LISTBOX_ID, i)}
                role="option"
                aria-selected={i === selectedIdx}
                // -1, not absent: programmatically focusable so the rule that
                // an interactive role must be reachable is satisfied honestly,
                // while staying out of the sequential tab order, which is the
                // whole point of the aria-activedescendant pattern.
                tabIndex={-1}
                data-idx={i}
                className={`w-full text-left px-4 py-1.5 flex items-center gap-3 text-xs cursor-pointer ${
                  i === selectedIdx
                    ? "bg-blue-600/30 text-white"
                    : "text-gray-300 hover:bg-gray-700/50"
                }`}
                onClick={() => handleSelect(item)}
                onMouseEnter={() => setSelectedIdx(i)}
              >
                <span className="text-gray-500 font-mono text-[10px] w-28 shrink-0">
                  {item.target.kind === "navigate"
                    ? `0x${item.target.address.toString(16).toUpperCase()}`
                    : ""}
                </span>
                <span className="truncate">{item.label}</span>
              </div>
              {/* The cap used to be silent, so a category cut off at 15 looked
                  exactly like one with 15 matches. A COUNT LINE, not a row: no
                  `role="option"`, no `tabIndex`, no click handler, so it stays
                  out of the listbox's option list and the arrow keys cannot
                  land on it. */}
              {admit && (
                <div
                  role="presentation"
                  className="px-4 py-1 pl-32 text-[10px] text-gray-500 italic"
                >
                  showing the first {CAP} matches — refine the query
                </div>
              )}
            </div>
          );
        })}
      </div>
      <div className="px-4 py-2 border-t border-gray-700 text-[10px] text-gray-500 flex items-center gap-4">
        <span>
          <kbd className="px-1 py-0.5 bg-gray-700 rounded">Enter</kbd> run
        </span>
        <span>
          <kbd className="px-1 py-0.5 bg-gray-700 rounded">Up/Down</kbd> select
        </span>
        <span>
          <kbd className="px-1 py-0.5 bg-gray-700 rounded">Esc</kbd> close
        </span>
      </div>
    </Modal>
  );
}
