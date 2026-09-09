import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DisasmFunction, Xref, XrefType } from "../disasm/types";
import { binarySearchFunc } from "../hooks/useDerivedState";

type SortKey = "from" | "to" | "type";
type ScopeMode = "all" | "address" | "function" | "instruction";

/**
 * The filter chip's style while its kind is ENABLED. A second palette in this
 * file on purpose — the chip is a filled badge and the row's kind column is bare
 * text, so they are different decisions about the same union rather than one
 * decision written twice.
 *
 * WAS a ternary chain, `t === "call" ? … : t === "jmp" ? … : t === "branch" ? …
 * : <purple>`, which is the shape `AnomaliesView` was corrected out of at
 * peek-a-bin-p0qw: the last arm is not "data", it is "everything that is not the
 * three above", so a fifth kind would have worn `data`'s colour with nothing
 * failing.
 */
const CHIP_ON: Record<XrefType, string> = {
  call: "bg-green-800 text-green-300",
  jmp: "bg-red-800 text-red-300",
  branch: "bg-orange-800 text-orange-300",
  data: "bg-purple-800 text-purple-300",
};

/**
 * Every kind, in chip order, DERIVED from the table above rather than written
 * out a second time.
 *
 * The literal `["call", "jmp", "branch", "data"]` it replaces appeared twice —
 * as the chip list and as the initial filter set — and an array is the one shape
 * in this family that CANNOT fail the build on a new member (CLAUDE.md makes the
 * same point about `VIEW_TAB_LABELS` being a `Record` where an array "would
 * silently drop it"). A kind missing from the list gets no chip, so it can never
 * be filtered out and never appears in the header count's denominator.
 *
 * The cast is sound by construction — `CHIP_ON` is a `Record<XrefType, …>`, so
 * its keys ARE the union; TypeScript's `Object.keys` is just typed `string[]`.
 * `CHIP_ON` is what the build fails on, and this follows it.
 */
const XREF_TYPES = Object.keys(CHIP_ON) as XrefType[];

interface FlatXref {
  type: XrefType;
  fromAddr: number;
  toAddr: number;
  fromFuncName: string;
  toFuncName: string;
}

interface XrefPanelProps {
  typedXrefMap: Map<number, Xref[]>;
  funcMap: Map<number, DisasmFunction>;
  sortedFuncs: DisasmFunction[];
  onNavigate: (addr: number) => void;
  onClose: () => void;
  scopeAddress?: number | null;
  currentFuncAddr?: number | null;
  currentFuncEnd?: number | null;
  currentInsnAddr?: number | null;
}

export function XrefPanel({
  typedXrefMap,
  funcMap,
  sortedFuncs,
  onNavigate,
  onClose,
  scopeAddress,
  currentFuncAddr,
  currentFuncEnd,
  currentInsnAddr,
}: XrefPanelProps) {
  const parentRef = useRef<HTMLDivElement>(null);
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const filterTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleFilterChange = useCallback((value: string) => {
    setFilterInput(value);
    clearTimeout(filterTimerRef.current);
    filterTimerRef.current = setTimeout(() => setFilter(value), 250);
  }, []);
  /**
   * Cancel a pending debounce on unmount. NO TEST PINS THIS AND ONE CANNOT BE
   * WRITTEN HERE: without it the timer fires 250ms later and calls `setFilter`
   * on an unmounted component, which React 19 accepts in silence — no warning,
   * no error, nothing observable — so any test would be green either way. That
   * makes this correct-by-inspection rather than verified, and it is worth
   * having anyway: the panel unmounts whenever its tab is closed, which is a
   * button press away, and a `setState` on a dead tree is not a thing to leave
   * lying around on the strength of one React version's tolerance.
   */
  useEffect(() => () => clearTimeout(filterTimerRef.current), []);

  const [typeFilter, setTypeFilter] = useState<Set<XrefType>>(new Set(XREF_TYPES));
  const [sortKey, setSortKey] = useState<SortKey>("from");
  const [sortAsc, setSortAsc] = useState(true);
  const [scopeMode, setScopeMode] = useState<ScopeMode>(scopeAddress != null ? "address" : "all");
  const [direction, setDirection] = useState<"to" | "from">("to");

  // Auto-set scope to "address" when scopeAddress changes
  const prevScopeRef = useRef(scopeAddress);
  useEffect(() => {
    if (scopeAddress != null && scopeAddress !== prevScopeRef.current) {
      setScopeMode("address");
    }
    prevScopeRef.current = scopeAddress;
  }, [scopeAddress]);

  const toggleType = (t: XrefType) => {
    setTypeFilter((prev) => {
      const next = new Set(prev);
      if (next.has(t)) next.delete(t);
      else next.add(t);
      return next;
    });
  };

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortAsc((v) => !v);
    else {
      setSortKey(key);
      setSortAsc(true);
    }
  };

  // Flatten xref map into sorted, resolved entries
  const allXrefs = useMemo((): FlatXref[] => {
    const result: FlatXref[] = [];
    for (const [toAddr, xrefs] of typedXrefMap) {
      const toFn = funcMap.get(toAddr) ?? binarySearchFunc(sortedFuncs, toAddr);
      const toName = toFn?.name ?? "";
      for (const xref of xrefs) {
        const fromFn = binarySearchFunc(sortedFuncs, xref.from);
        result.push({
          type: xref.type,
          fromAddr: xref.from,
          toAddr,
          fromFuncName: fromFn?.name ?? "",
          toFuncName: toName,
        });
      }
    }
    return result;
  }, [typedXrefMap, funcMap, sortedFuncs]);

  /**
   * Whether the caller has given this panel the address a scope needs. THE ONE
   * DECLARATION of that rule: the filter chain below and the scope buttons both
   * read it, so a scope can never be applied without a button claiming it, nor
   * offered without an address to apply.
   */
  const scopeAvailable = (mode: ScopeMode): boolean => {
    if (mode === "all") return true;
    if (mode === "address") return scopeAddress != null;
    if (mode === "function") return currentFuncAddr != null && currentFuncEnd != null;
    return currentInsnAddr != null;
  };

  /**
   * The scope actually on screen. `scopeMode` is the user's PREFERENCE and can
   * outlive the address it needs — the cursor moves into a gap between detected
   * functions and `currentFuncAddr` goes null while "Func" is still selected.
   *
   * Falling back to "all" is a decision, not a default; the alternative was to
   * hold the empty "Func" scope and explain it. This panel's function and
   * instruction scopes FOLLOW THE CURSOR rather than being values the user
   * entered, so there is nothing to hold: a cursor wandering into padding would
   * blank the panel and refill it on the way out, repeatedly, for a lapse the
   * user never caused. What must not happen is what did happen — the chain
   * falling through to the unfiltered list with no button highlighted, so the
   * list and the controls describe different things. Widening and SAYING SO is
   * the honest form of that; it is a narrower answer wearing a complete one's
   * shape that the house rule forbids, and this is the reverse.
   *
   * Derived rather than pushed back into state on purpose: the preference
   * survives the lapse, so re-entering a function resumes the scope the user
   * chose, and clicking "All" during a lapse makes the widening permanent.
   */
  const effectiveScope: ScopeMode = scopeAvailable(scopeMode) ? scopeMode : "all";

  const filtered = useMemo(() => {
    let items = allXrefs.filter((x) => typeFilter.has(x.type));

    // Scope filtering
    if (effectiveScope === "address" && scopeAddress != null) {
      items = items.filter((x) => x.toAddr === scopeAddress);
    } else if (effectiveScope === "function" && currentFuncAddr != null && currentFuncEnd != null) {
      items = items.filter((x) => x.fromAddr >= currentFuncAddr && x.fromAddr < currentFuncEnd);
    } else if (effectiveScope === "instruction" && currentInsnAddr != null) {
      if (direction === "to") {
        items = items.filter((x) => x.toAddr === currentInsnAddr);
      } else {
        items = items.filter((x) => x.fromAddr === currentInsnAddr);
      }
    }

    if (filter) {
      const q = filter.toLowerCase();
      items = items.filter(
        (x) =>
          x.fromAddr.toString(16).includes(q) ||
          x.toAddr.toString(16).includes(q) ||
          x.fromFuncName.toLowerCase().includes(q) ||
          x.toFuncName.toLowerCase().includes(q),
      );
    }
    items.sort((a, b) => {
      let cmp = 0;
      if (sortKey === "from") cmp = a.fromAddr - b.fromAddr;
      else if (sortKey === "to") cmp = a.toAddr - b.toAddr;
      else cmp = a.type.localeCompare(b.type);
      return sortAsc ? cmp : -cmp;
    });
    return items;
  }, [
    allXrefs,
    typeFilter,
    filter,
    sortKey,
    sortAsc,
    effectiveScope,
    scopeAddress,
    currentFuncAddr,
    currentFuncEnd,
    currentInsnAddr,
    direction,
  ]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 22,
    overscan: 30,
  });

  // Keyed on the union, not on `string`, so a fifth kind cannot render here as
  // the `?? "text-gray-400"` below. Deliberately NOT shared with
  // `InstructionDetail`'s table of the same shape: a palette is the caller's,
  // and these two agree today only by coincidence (severity.ts says the same of
  // its own readers). The union is the thing with one declaration.
  const typeColors: Record<XrefType, string> = {
    call: "text-green-400",
    jmp: "text-red-400",
    branch: "text-orange-400",
    data: "text-purple-400",
  };

  const sortIndicator = (key: SortKey) => (sortKey === key ? (sortAsc ? " ▲" : " ▼") : "");

  /**
   * The accessible name of a sort header. The VISIBLE text cannot carry it: each
   * header is a fixed-width cell (`w-12`/`w-32`) sitting over the row cell of the
   * same width, so the word is a column label and lengthening it overflows the
   * column. Two things this buys beyond the collision below — the name says the
   * button SORTS rather than just naming a column, and the ▲/▼ that states the
   * direction is a bare glyph in the announced name without it.
   */
  const sortLabel = (key: SortKey, what: string) =>
    sortKey === key
      ? `Sort by ${what}, ${sortAsc ? "ascending" : "descending"}`
      : `Sort by ${what}`;

  const scopeBtn = (mode: ScopeMode, label: string) => {
    if (!scopeAvailable(mode)) return null;
    return (
      <button
        type="button"
        key={mode}
        onClick={() => setScopeMode(mode)}
        className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
          effectiveScope === mode
            ? "bg-blue-600 text-white"
            : "bg-gray-800 text-gray-500 hover:text-gray-300"
        }`}
      >
        {label}
      </button>
    );
  };

  return (
    <div className="text-xs flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1 border-b border-gray-700 shrink-0 flex-wrap">
        <span className="text-gray-300 font-semibold text-[11px]">
          Cross-References ({filtered.length}/{allXrefs.length})
        </span>
        <div className="flex items-center gap-1 ml-2">
          {XREF_TYPES.map((t) => (
            <button
              type="button"
              key={t}
              onClick={() => toggleType(t)}
              className={`px-1.5 py-0.5 rounded text-[9px] font-semibold ${
                typeFilter.has(t) ? CHIP_ON[t] : "bg-gray-800 text-gray-600"
              }`}
            >
              {t}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1 ml-2">
          {scopeBtn("all", "All")}
          {scopeBtn("address", "Addr")}
          {scopeBtn("function", "Func")}
          {scopeBtn("instruction", "Insn")}
          {effectiveScope === "instruction" && (
            /* Its visible text is "To"/"From", and so was the sortable "To"
               COLUMN HEADER's — two buttons doing unrelated things under one
               accessible name, which a screen reader gives no way to tell
               apart. The text stays: this is a `text-[9px]` chip fifth in a
               row of chips inside a wrapping header, and a longer word pushes
               the filter input onto a second line. So the name is carried by
               `aria-label`, and it states the CURRENT direction, because that
               is what the visible label states. */
            <button
              type="button"
              aria-label={
                direction === "to"
                  ? "Reference direction: to this instruction"
                  : "Reference direction: from this instruction"
              }
              onClick={() => setDirection((d) => (d === "to" ? "from" : "to"))}
              className="px-1.5 py-0.5 rounded text-[9px] font-semibold bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              {direction === "to" ? "To" : "From"}
            </button>
          )}
        </div>
        <input
          type="text"
          value={filterInput}
          onChange={(e) => handleFilterChange(e.target.value)}
          placeholder="Filter addresses/names..."
          className="ml-2 px-1.5 py-0.5 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 text-[10px] w-40"
        />
        <div className="flex-1" />
        <button type="button" onClick={onClose} className="text-gray-500 hover:text-white px-1">
          ✕
        </button>
      </div>

      {/* Column headers */}
      <div className="flex items-center px-3 py-0.5 border-b border-gray-800 text-gray-500 text-[10px] select-none shrink-0">
        <button
          type="button"
          aria-label={sortLabel("type", "type")}
          className="w-12 shrink-0 text-left cursor-pointer hover:text-gray-300"
          onClick={() => toggleSort("type")}
        >
          Type{sortIndicator("type")}
        </button>
        <button
          type="button"
          aria-label={sortLabel("from", "from address")}
          className="w-32 shrink-0 text-left cursor-pointer hover:text-gray-300"
          onClick={() => toggleSort("from")}
        >
          From{sortIndicator("from")}
        </button>
        <div className="w-36 shrink-0">Function</div>
        <button
          type="button"
          aria-label={sortLabel("to", "to address")}
          className="w-32 shrink-0 text-left cursor-pointer hover:text-gray-300"
          onClick={() => toggleSort("to")}
        >
          To{sortIndicator("to")}
        </button>
        <div className="flex-1">Target</div>
      </div>

      {/* Virtualized list */}
      <div ref={parentRef} className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <div className="p-3 text-gray-500 text-center">
            {allXrefs.length === 0
              ? "No cross-references found."
              : "No xrefs match the current filters."}
          </div>
        ) : (
          <div
            style={{
              height: `${virtualizer.getTotalSize()}px`,
              width: "100%",
              position: "relative",
            }}
          >
            {virtualizer.getVirtualItems().map((vItem) => {
              const x = filtered[vItem.index];
              if (!x) return null;
              return (
                <button
                  type="button"
                  key={vItem.index}
                  className="absolute left-0 w-full flex items-center px-3 text-left hover:bg-gray-800/50 cursor-pointer"
                  style={{
                    top: 0,
                    height: "22px",
                    transform: `translateY(${vItem.start}px)`,
                  }}
                  onClick={() => onNavigate(x.fromAddr)}
                >
                  <div
                    className={`w-12 shrink-0 font-semibold text-[10px] ${typeColors[x.type] ?? "text-gray-400"}`}
                  >
                    {x.type}
                  </div>
                  <div className="w-32 shrink-0 font-mono text-blue-400">
                    0x{x.fromAddr.toString(16).toUpperCase()}
                  </div>
                  <div className="w-36 shrink-0 text-gray-400 truncate" title={x.fromFuncName}>
                    {x.fromFuncName || "---"}
                  </div>
                  <div className="w-32 shrink-0 font-mono text-gray-300">
                    0x{x.toAddr.toString(16).toUpperCase()}
                  </div>
                  <div className="flex-1 text-gray-400 truncate" title={x.toFuncName}>
                    {x.toFuncName || "---"}
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
