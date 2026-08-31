import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DisasmFunction } from "../disasm/types";
import { useContainingFunc } from "../hooks/useDerivedState";
import { useDismissOnOutsideClick } from "../hooks/useDismissOnOutsideClick";
import { useGraphOverview } from "../hooks/useGraphOverview";
import {
  ANALYSIS_IN_PROGRESS,
  getDisplayName,
  useAppDispatch,
  useAppState,
} from "../hooks/usePEFile";
import { copyText } from "../utils/clipboard";
import { generateMarkdownReport } from "../utils/exportSchema";
import { focusOnMount } from "./focusOnMount";
import { SkeletonRows } from "./Skeleton";

type SortMode = "address" | "alpha";

const MIN_WIDTH = 180;
const MAX_WIDTH = 400;
/** Pixels per arrow-key press when the resize handle has keyboard focus. */
const RESIZE_STEP_PX = 16;
const DEFAULT_WIDTH = 224;
/**
 * Starting height of the Call Graph block. `peek-a-bin-llrq.2` adds the
 * min/max and the persisted state beside this; until then the block is a
 * fixed 160px, which is already enough to stop it pushing the list around.
 */
const CALLGRAPH_DEFAULT_HEIGHT = 160;

function loadWidth(): number {
  try {
    const v = localStorage.getItem("peek-a-bin:sidebar-width");
    if (v) {
      const n = parseInt(v, 10);
      if (n >= MIN_WIDTH && n <= MAX_WIDTH) return n;
    }
  } catch {}
  return DEFAULT_WIDTH;
}

export function Sidebar() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const [filterInput, setFilterInput] = useState("");
  const [filter, setFilter] = useState("");
  const filterTimerRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  const handleFilterChange = useCallback((value: string) => {
    setFilterInput(value);
    clearTimeout(filterTimerRef.current);
    filterTimerRef.current = setTimeout(() => setFilter(value), 250);
  }, []);
  const [sort, setSort] = useState<SortMode>("address");
  const listRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(loadWidth);
  const [collapsed, setCollapsed] = useState(false);
  const [dragging, setDragging] = useState(false);
  const [renamingFn, setRenamingFn] = useState<{ address: number; value: string } | null>(null);
  const [editingBookmark, setEditingBookmark] = useState<{ address: number; value: string } | null>(
    null,
  );
  const [bmCtxMenu, setBmCtxMenu] = useState<{
    x: number;
    y: number;
    address: number;
    label: string;
  } | null>(null);
  const [fnCtxMenu, setFnCtxMenu] = useState<{ x: number; y: number; fn: DisasmFunction } | null>(
    null,
  );
  const [bookmarksOpen, setBookmarksOpen] = useState(true);
  const [sectionsOpen, setSectionsOpen] = useState(() => {
    try {
      return localStorage.getItem("peek-a-bin:sections-open") !== "false";
    } catch {
      return true;
    }
  });
  const [callersOpen, setCallersOpen] = useState(() => {
    try {
      return localStorage.getItem("peek-a-bin:callers-open") !== "false";
    } catch {
      return true;
    }
  });
  const [graphOverviewOpen, setGraphOverviewOpen] = useState(() => {
    try {
      return localStorage.getItem("peek-a-bin:graph-overview-open") !== "false";
    } catch {
      return true;
    }
  });
  const graphOverview = useGraphOverview();
  const bmCtxMenuRef = useRef<HTMLDivElement>(null);
  const fnCtxMenuRef = useRef<HTMLDivElement>(null);

  // Dismiss bookmark context menu on click/Escape. Clicks inside the menu are
  // ignored by the hook's ref check instead of being stopped from propagating
  // by a handler on the menu div.
  useDismissOnOutsideClick({
    active: bmCtxMenu !== null,
    ref: bmCtxMenuRef,
    onDismiss: () => setBmCtxMenu(null),
    event: "click",
    target: "window",
    dismissOnEscape: true,
    dismissIfRefMissing: true,
  });

  // Dismiss function context menu on click/Escape
  useDismissOnOutsideClick({
    active: fnCtxMenu !== null,
    ref: fnCtxMenuRef,
    onDismiss: () => setFnCtxMenu(null),
    event: "click",
    target: "window",
    dismissOnEscape: true,
    dismissIfRefMissing: true,
  });

  // Active function highlight
  const containingFunc = useContainingFunc();
  const activeFuncAddr = containingFunc?.address ?? null;

  // Persist width
  useEffect(() => {
    try {
      localStorage.setItem("peek-a-bin:sidebar-width", String(width));
    } catch {}
  }, [width]);

  // Persist sections/graph overview toggle
  useEffect(() => {
    try {
      localStorage.setItem("peek-a-bin:sections-open", String(sectionsOpen));
    } catch {}
  }, [sectionsOpen]);
  useEffect(() => {
    try {
      localStorage.setItem("peek-a-bin:callers-open", String(callersOpen));
    } catch {}
  }, [callersOpen]);
  useEffect(() => {
    try {
      localStorage.setItem("peek-a-bin:graph-overview-open", String(graphOverviewOpen));
    } catch {}
  }, [graphOverviewOpen]);

  // Drag resize logic
  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      setDragging(true);
      const startX = e.clientX;
      const startWidth = width;

      const onMouseMove = (ev: MouseEvent) => {
        const delta = ev.clientX - startX;
        setWidth(Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, startWidth + delta)));
      };
      const onMouseUp = () => {
        setDragging(false);
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      };

      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    },
    [width],
  );

  // Keyboard equivalent for the drag handle — left/right arrows nudge the width
  // within the same bounds the drag path enforces.
  const handleResizeKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key !== "ArrowLeft" && e.key !== "ArrowRight") return;
    e.preventDefault();
    const delta = e.key === "ArrowLeft" ? -RESIZE_STEP_PX : RESIZE_STEP_PX;
    setWidth((w) => Math.max(MIN_WIDTH, Math.min(MAX_WIDTH, w + delta)));
  }, []);

  const exportNames = useMemo(() => {
    if (!pe) return new Set<string>();
    const s = new Set<string>();
    for (const e of pe.exports) s.add(e.name);
    return s;
  }, [pe]);

  // Callers/callees derivation
  const { callers, callees } = useMemo(() => {
    if (!state.callGraph || activeFuncAddr === null) return { callers: [], callees: [] };
    // Callees: direct lookup
    const calleeAddrs = state.callGraph.get(activeFuncAddr) ?? [];
    // Callers: invert by scanning all entries
    const callerAddrs: number[] = [];
    for (const [funcAddr, targets] of state.callGraph) {
      if (targets.includes(activeFuncAddr)) callerAddrs.push(funcAddr);
    }
    // Resolve to function objects
    const funcMap = new Map(state.functions.map((f) => [f.address, f]));
    const resolvedCallers = callerAddrs
      .map((a) => funcMap.get(a))
      .filter((f): f is DisasmFunction => f !== undefined);
    const resolvedCallees = calleeAddrs
      .map((a) => funcMap.get(a))
      .filter((f): f is DisasmFunction => f !== undefined);
    return { callers: resolvedCallers, callees: resolvedCallees };
  }, [state.callGraph, activeFuncAddr, state.functions]);

  const filteredFunctions = useMemo(() => {
    let fns = state.functions;
    if (filter) {
      const q = filter.toLowerCase();
      fns = fns.filter((fn) => {
        const display = getDisplayName(fn, state.renames);
        return (
          display.toLowerCase().includes(q) || fn.address.toString(16).toLowerCase().includes(q)
        );
      });
    }
    if (sort === "alpha") {
      fns = [...fns].sort((a, b) => {
        const na = getDisplayName(a, state.renames);
        const nb = getDisplayName(b, state.renames);
        return na.localeCompare(nb);
      });
    }
    return fns;
  }, [state.functions, state.renames, filter, sort]);

  const handleExportCSV = useCallback(() => {
    if (state.functions.length === 0) return;
    const header = "Address,Name,Size";
    const rows = state.functions.map((fn: DisasmFunction) => {
      const name = getDisplayName(fn, state.renames);
      // Escape CSV: wrap in quotes if contains comma or quote
      const escapedName =
        name.includes(",") || name.includes('"') ? `"${name.replace(/"/g, '""')}"` : name;
      return `0x${fn.address.toString(16).toUpperCase()},${escapedName},${fn.size}`;
    });
    const csv = [header, ...rows].join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.fileName ?? "pe"}_functions.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state.functions, state.renames, state.fileName]);

  const handleExportReport = useCallback(() => {
    if (!state.peFile) return;
    const report = generateMarkdownReport(state);
    const blob = new Blob([report], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${state.fileName ?? "analysis"}_report.md`;
    a.click();
    URL.revokeObjectURL(url);
  }, [state]);

  const virtualizer = useVirtualizer({
    count: filteredFunctions.length,
    getScrollElement: () => listRef.current,
    estimateSize: () => 24,
    overscan: 20,
  });

  const activeIndex = useMemo(() => {
    if (activeFuncAddr === null) return -1;
    return filteredFunctions.findIndex((fn) => fn.address === activeFuncAddr);
  }, [filteredFunctions, activeFuncAddr]);

  // Auto-scroll to active function (only when not filtering)
  useEffect(() => {
    if (activeIndex >= 0 && !filter) {
      virtualizer.scrollToIndex(activeIndex, { align: "auto" });
    }
    // useVirtualizer holds its instance in useState, so `virtualizer` is stable
    // for the component's lifetime and cannot make this effect re-fire.
  }, [activeIndex, filter, virtualizer]);

  if (!pe) return null;

  // An empty list with analysis still running is a skeleton; an empty list with
  // analysis over is an empty list. Read from the exhaustive record rather than
  // the `!== "idle" && !== "ready" && !== "failed"` chain this replaces, which
  // would have shown these rows forever for any phase added later — see
  // ANALYSIS_IN_PROGRESS in usePEFile.ts (peek-a-bin-bo3b).
  const awaitingFunctions =
    state.functions.length === 0 && ANALYSIS_IN_PROGRESS[state.analysisPhase];

  if (collapsed) {
    return (
      <aside className="w-10 panel-bg border-r border-theme flex flex-col items-center py-2 shrink-0">
        <button
          type="button"
          onClick={() => setCollapsed(false)}
          className="text-gray-400 hover:text-white text-sm"
          title="Expand sidebar"
        >
          ▶
        </button>
      </aside>
    );
  }

  return (
    <aside
      className="panel-bg border-r border-theme flex flex-col overflow-hidden text-xs relative shrink-0"
      style={{ width }}
    >
      {/* Resize handle */}
      <button
        type="button"
        aria-label="Resize sidebar"
        className={`sidebar-handle${dragging ? " active" : ""}`}
        onMouseDown={handleMouseDown}
        onKeyDown={handleResizeKeyDown}
      />

      {/* Sections */}
      <div data-panel="sections" className="p-2 border-b border-gray-700">
        <button
          type="button"
          onClick={() => setSectionsOpen(!sectionsOpen)}
          className="flex items-center gap-1 text-gray-400 uppercase tracking-wider text-[10px] font-semibold w-full text-left"
        >
          <span className="text-[8px]">{sectionsOpen ? "▼" : "▶"}</span>
          Sections ({pe.sections.length})
        </button>
        {sectionsOpen && (
          <ul className="mt-1.5 space-y-0.5">
            {pe.sections.map((sec, i) => (
              <li key={i}>
                <button
                  type="button"
                  onClick={() => {
                    dispatch({
                      type: "SET_ADDRESS",
                      address: pe.optionalHeader.imageBase + sec.virtualAddress,
                    });
                    dispatch({ type: "SET_TAB", tab: "disassembly" });
                  }}
                  className="w-full text-left px-2 py-1 rounded hover:bg-gray-800 transition-colors flex justify-between"
                >
                  <span className="text-gray-200">{sec.name}</span>
                  <span className="text-gray-500">{(sec.virtualSize >>> 0).toString(16)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>

      {/* Bookmarks panel (only show if bookmarks exist) */}
      {state.bookmarks.length > 0 && (
        <div data-panel="bookmarks" className="relative p-2 border-b border-gray-700">
          <button
            type="button"
            onClick={() => setBookmarksOpen(!bookmarksOpen)}
            className="flex items-center gap-1 text-gray-400 uppercase tracking-wider text-[10px] font-semibold w-full text-left"
          >
            <span className="text-[8px]">{bookmarksOpen ? "▼" : "▶"}</span>
            Bookmarks ({state.bookmarks.length})
          </button>
          {bookmarksOpen && (
            <ul className="mt-1.5 space-y-0.5">
              {state.bookmarks.map((bm) => (
                <li
                  key={bm.address}
                  className="flex items-center gap-1 group"
                  onContextMenu={(e) => {
                    e.preventDefault();
                    e.stopPropagation();
                    const rect = (
                      e.currentTarget.closest(".relative") as HTMLElement
                    ).getBoundingClientRect();
                    setBmCtxMenu({
                      x: e.clientX - rect.left,
                      y: e.clientY - rect.top,
                      address: bm.address,
                      label: bm.label,
                    });
                  }}
                >
                  <button
                    type="button"
                    onClick={() => {
                      dispatch({ type: "SET_ADDRESS", address: bm.address });
                      dispatch({ type: "SET_TAB", tab: "disassembly" });
                    }}
                    // Double-click-to-rename moved up from the label span, which as
                    // a bare <span> had no keyboard equivalent and could not get one.
                    onDoubleClick={(e) => {
                      e.stopPropagation();
                      setEditingBookmark({ address: bm.address, value: bm.label });
                    }}
                    className="flex-1 text-left px-1.5 py-0.5 rounded hover:bg-gray-800 truncate"
                  >
                    <span className="text-yellow-300 mr-1">★</span>
                    {editingBookmark && editingBookmark.address === bm.address ? (
                      <input
                        ref={focusOnMount}
                        className="bg-gray-800 border border-blue-500 rounded px-1 text-gray-200 text-[11px] outline-none w-24"
                        value={editingBookmark.value}
                        onClick={(e) => e.stopPropagation()}
                        onChange={(e) =>
                          setEditingBookmark({ ...editingBookmark, value: e.target.value })
                        }
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            dispatch({
                              type: "SET_BOOKMARK_LABEL",
                              address: bm.address,
                              label: editingBookmark.value,
                            });
                            setEditingBookmark(null);
                          }
                          if (e.key === "Escape") setEditingBookmark(null);
                          e.stopPropagation();
                        }}
                        onBlur={() => {
                          dispatch({
                            type: "SET_BOOKMARK_LABEL",
                            address: bm.address,
                            label: editingBookmark.value,
                          });
                          setEditingBookmark(null);
                        }}
                      />
                    ) : (
                      <span className="text-blue-400">
                        {bm.label || `0x${bm.address.toString(16).toUpperCase()}`}
                      </span>
                    )}
                  </button>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation();
                      dispatch({ type: "TOGGLE_BOOKMARK", address: bm.address });
                    }}
                    className="text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 px-0.5"
                    title="Remove bookmark"
                  >
                    ✕
                  </button>
                </li>
              ))}
            </ul>
          )}
          {bmCtxMenu && (
            <div
              ref={bmCtxMenuRef}
              className="absolute z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs"
              style={{ left: bmCtxMenu.x, top: bmCtxMenu.y }}
            >
              <button
                type="button"
                className="w-full text-left px-3 py-1 hover:bg-gray-700 text-gray-200"
                onClick={() => {
                  setEditingBookmark({ address: bmCtxMenu.address, value: bmCtxMenu.label });
                  setBmCtxMenu(null);
                }}
              >
                Rename
              </button>
              <button
                type="button"
                className="w-full text-left px-3 py-1 hover:bg-gray-700 text-red-400"
                onClick={() => {
                  dispatch({ type: "TOGGLE_BOOKMARK", address: bmCtxMenu.address });
                  setBmCtxMenu(null);
                }}
              >
                Delete
              </button>
            </div>
          )}
        </div>
      )}

      {/* Functions header + filter */}
      <div data-panel="functions-header" className="p-2 pb-1 border-b border-gray-700 space-y-1.5">
        <div className="flex items-center justify-between">
          <h3 className="text-gray-400 uppercase tracking-wider text-[10px] font-semibold">
            Functions ({filteredFunctions.length}
            {filterInput && filteredFunctions.length !== state.functions.length
              ? `/${state.functions.length}`
              : ""}
            )
          </h3>
          <div className="flex items-center gap-1">
            <button
              type="button"
              onClick={handleExportCSV}
              disabled={state.functions.length === 0}
              className="text-[10px] text-gray-500 hover:text-gray-300 px-1 disabled:opacity-30 disabled:cursor-default"
              title="Export functions as CSV"
            >
              CSV
            </button>
            <button
              type="button"
              onClick={handleExportReport}
              disabled={!state.peFile}
              className="text-[10px] text-gray-500 hover:text-gray-300 px-1 disabled:opacity-30 disabled:cursor-default"
              title="Export analysis report as Markdown"
            >
              Report
            </button>
            <button
              type="button"
              onClick={() => setSort(sort === "address" ? "alpha" : "address")}
              className="text-[10px] text-gray-500 hover:text-gray-300 px-1"
              title={sort === "address" ? "Sort: by address" : "Sort: alphabetical"}
            >
              {sort === "address" ? "Addr" : "A-Z"}
            </button>
          </div>
        </div>
        <input
          type="text"
          value={filterInput}
          onChange={(e) => handleFilterChange(e.target.value)}
          placeholder="Filter functions..."
          className="w-full px-2 py-1 bg-gray-800 border border-gray-700 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 text-[11px]"
        />
      </div>

      {/* Virtualized functions list */}
      {awaitingFunctions ? (
        <div className="flex-1 overflow-hidden">
          <SkeletonRows count={20} />
        </div>
      ) : null}
      {/* `min-h-[120px]` is a FLOOR, not a nicety. This div is the only
          `flex-1` child and its overflow is not `visible`, so per CSS Flexbox
          4.5 its automatic minimum size is ZERO — every other section has a
          content-based minimum and refuses to shrink, so all negative free
          space lands here. Without a floor a short window drives the list to
          0 and the overflow is clipped by the aside's own `overflow-hidden`,
          silently eating the footer. The list is the sidebar's reason to
          exist; the trade is that the footer clips slightly sooner on a very
          short window. */}
      <div
        ref={listRef}
        data-panel="functions"
        className={`flex-1 overflow-auto min-h-[120px]${awaitingFunctions ? " hidden" : ""}`}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((vItem) => {
            const fn = filteredFunctions[vItem.index];
            if (!fn) return null;
            const displayName = getDisplayName(fn, state.renames);
            const isExport = exportNames.has(fn.name);
            const isHeuristic = displayName.startsWith("sub_");
            const isRenamed = state.renames[fn.address] !== undefined;

            if (renamingFn && renamingFn.address === fn.address) {
              return (
                <div
                  key={vItem.index}
                  className="absolute left-0 w-full px-2 flex items-center"
                  style={{
                    top: 0,
                    height: "24px",
                    transform: `translateY(${vItem.start}px)`,
                  }}
                >
                  <input
                    ref={focusOnMount}
                    className="w-full bg-gray-800 border border-blue-500 rounded px-1 text-gray-200 text-[11px] font-mono outline-none"
                    value={renamingFn.value}
                    onChange={(e) => setRenamingFn({ ...renamingFn, value: e.target.value })}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        const val = renamingFn.value.trim();
                        if (val && val !== fn.name) {
                          dispatch({ type: "RENAME_FUNCTION", address: fn.address, name: val });
                        } else if (!val || val === fn.name) {
                          dispatch({ type: "CLEAR_RENAME", address: fn.address });
                        }
                        setRenamingFn(null);
                      }
                      if (e.key === "Escape") setRenamingFn(null);
                      e.stopPropagation();
                    }}
                    onBlur={() => setRenamingFn(null)}
                  />
                </div>
              );
            }

            return (
              <button
                type="button"
                key={vItem.index}
                onClick={() => {
                  dispatch({ type: "SET_ADDRESS", address: fn.address });
                  dispatch({ type: "SET_TAB", tab: "disassembly" });
                }}
                onDoubleClick={(e) => {
                  e.preventDefault();
                  setRenamingFn({ address: fn.address, value: displayName });
                }}
                onContextMenu={(e) => {
                  e.preventDefault();
                  e.stopPropagation();
                  setFnCtxMenu({ x: e.clientX, y: e.clientY, fn });
                }}
                className={`absolute left-0 w-full text-left px-2 rounded hover:bg-gray-800 transition-colors truncate ${
                  fn.address === activeFuncAddr ? "bg-blue-900/30 border-l-2 border-blue-400" : ""
                } ${
                  isExport
                    ? "text-yellow-300 font-semibold"
                    : isHeuristic
                      ? "text-gray-500"
                      : "text-gray-300"
                }`}
                style={{
                  top: 0,
                  height: "24px",
                  lineHeight: "24px",
                  transform: `translateY(${vItem.start}px)`,
                }}
                title={`${displayName}${isRenamed ? ` (${fn.name})` : ""} @ 0x${fn.address.toString(16).toUpperCase()}`}
              >
                {displayName}
              </button>
            );
          })}
        </div>
      </div>

      {/* CALL GRAPH — BELOW THE FUNCTION LIST DELIBERATELY. Above it, this
          block is sized by its own content and that content changes with the
          cursor, so every caret move pushed the Functions header, the filter
          box and every row in the list vertically. The list's top edge is the
          thing that must not move, so everything whose height follows the
          cursor sits underneath it (peek-a-bin-llrq).

          NO `shrink-0` HERE, and that is the one place the BottomPanelContainer
          analogue must not be copied: there the band's only competitor is the
          whole disassembly view, so refusing to shrink costs nothing. Here it
          competes with four other content-sized siblings, and refusing would
          starve the one child that matters. The inline height is still the flex
          BASE size, so ordinary layout gives exactly it; under negative free
          space this block yields toward its own title instead. */}
      {state.callGraph && activeFuncAddr !== null && (callers.length > 0 || callees.length > 0) && (
        <div
          data-panel="call-graph"
          className="flex flex-col overflow-hidden border-t border-gray-700"
          // No height at all when collapsed: a collapsed section still
          // reserving 160px of the list's space is this defect one step milder.
          style={callersOpen ? { height: CALLGRAPH_DEFAULT_HEIGHT, maxHeight: "40%" } : undefined}
        >
          <button
            type="button"
            onClick={() => setCallersOpen(!callersOpen)}
            className="shrink-0 px-2 pt-2 flex items-center gap-1 text-gray-400 uppercase tracking-wider text-[10px] font-semibold w-full text-left"
          >
            <span className="text-[8px]">{callersOpen ? "▼" : "▶"}</span>
            Call Graph
          </button>
          {/* The scroller, so 300 callers scroll inside the block rather than
              growing it. Padding lives here and on the header rather than on the
              wrapper, or the scrollbar sits 8px inside the panel edge and the
              bottom padding scrolls away. No `min-h-0` is needed: an element
              whose overflow is not `visible` already has an automatic minimum
              size of zero (CSS Flexbox 4.5). */}
          {callersOpen && (
            <div
              data-panel="call-graph-body"
              className="flex-1 overflow-auto px-2 pb-2 mt-1.5 space-y-1.5"
            >
              {callers.length > 0 && (
                <div>
                  <div className="text-gray-500 text-[10px] mb-0.5">Callers ({callers.length})</div>
                  <ul className="space-y-0.5">
                    {callers.map((fn) => (
                      <li key={fn.address}>
                        <button
                          type="button"
                          onClick={() => {
                            dispatch({
                              type: "PUSH_CALL_STACK",
                              address: state.currentAddress,
                              name: getDisplayName(
                                containingFunc ?? { name: "unknown", address: 0, size: 0 },
                                state.renames,
                              ),
                            });
                            dispatch({ type: "SET_ADDRESS", address: fn.address });
                            dispatch({ type: "SET_TAB", tab: "disassembly" });
                          }}
                          className="w-full text-left px-1.5 py-0.5 rounded hover:bg-gray-800 text-blue-400 truncate transition-colors"
                          title={`0x${fn.address.toString(16).toUpperCase()}`}
                        >
                          {getDisplayName(fn, state.renames)}
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {callees.length > 0 && (
                <div>
                  <div className="text-gray-500 text-[10px] mb-0.5">Callees ({callees.length})</div>
                  <ul className="space-y-0.5">
                    {callees.map((fn) => (
                      <li key={fn.address}>
                        <button
                          type="button"
                          onClick={() => {
                            dispatch({
                              type: "PUSH_CALL_STACK",
                              address: state.currentAddress,
                              name: getDisplayName(
                                containingFunc ?? { name: "unknown", address: 0, size: 0 },
                                state.renames,
                              ),
                            });
                            dispatch({ type: "SET_ADDRESS", address: fn.address });
                            dispatch({ type: "SET_TAB", tab: "disassembly" });
                          }}
                          className="w-full text-left px-1.5 py-0.5 rounded hover:bg-gray-800 text-green-400 truncate transition-colors"
                          title={`0x${fn.address.toString(16).toUpperCase()}`}
                        >
                          {getDisplayName(fn, state.renames)}
                        </button>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Graph Overview */}
      {graphOverview && (
        <div className="p-2 border-t border-gray-700">
          <button
            type="button"
            onClick={() => setGraphOverviewOpen(!graphOverviewOpen)}
            className="flex items-center gap-1 text-gray-400 uppercase tracking-wider text-[10px] font-semibold w-full text-left"
          >
            <span className="text-[8px]">{graphOverviewOpen ? "▼" : "▶"}</span>
            Graph Overview
          </button>
          {graphOverviewOpen && <GraphOverviewCanvas data={graphOverview} />}
        </div>
      )}

      {/* Function context menu */}
      {fnCtxMenu && (
        <div
          ref={fnCtxMenuRef}
          className="fixed z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs"
          style={{ left: fnCtxMenu.x, top: fnCtxMenu.y }}
        >
          <button
            type="button"
            className="w-full text-left px-3 py-1 hover:bg-gray-700 text-gray-200"
            onClick={() => {
              dispatch({ type: "SET_ADDRESS", address: fnCtxMenu.fn.address });
              dispatch({ type: "SET_TAB", tab: "disassembly" });
              setFnCtxMenu(null);
            }}
          >
            Jump to
          </button>
          <button
            type="button"
            className="w-full text-left px-3 py-1 hover:bg-gray-700 text-gray-200"
            onClick={() => {
              setRenamingFn({
                address: fnCtxMenu.fn.address,
                value: getDisplayName(fnCtxMenu.fn, state.renames),
              });
              setFnCtxMenu(null);
            }}
          >
            Rename
          </button>
          <button
            type="button"
            className="w-full text-left px-3 py-1 hover:bg-gray-700 text-gray-200"
            onClick={() => {
              void copyText("0x" + fnCtxMenu.fn.address.toString(16).toUpperCase());
              setFnCtxMenu(null);
            }}
          >
            Copy address
          </button>
          <button
            type="button"
            className="w-full text-left px-3 py-1 hover:bg-gray-700 text-gray-200"
            onClick={() => {
              dispatch({ type: "TOGGLE_BOOKMARK", address: fnCtxMenu.fn.address });
              setFnCtxMenu(null);
            }}
          >
            Toggle bookmark
          </button>
          <div className="border-t border-gray-700 my-0.5" />
          <button
            type="button"
            className="w-full text-left px-3 py-1 hover:bg-gray-700 text-gray-200"
            onClick={() => {
              dispatch({ type: "SET_ADDRESS", address: fnCtxMenu.fn.address });
              dispatch({ type: "SET_TAB", tab: "disassembly" });
              window.dispatchEvent(
                new CustomEvent("peek-a-bin:show-xrefs", {
                  detail: { address: fnCtxMenu.fn.address },
                }),
              );
              setFnCtxMenu(null);
            }}
          >
            Show xrefs
          </button>
        </div>
      )}

      {/* Info + collapse */}
      <div
        data-panel="footer"
        className="p-2 border-t border-gray-700 text-gray-500 flex items-center justify-between"
      >
        <div>
          <div>{pe.is64 ? "PE32+ (64-bit)" : "PE32 (32-bit)"}</div>
          <div>{pe.sections.length} sections</div>
          <div>{pe.imports.length} imports</div>
        </div>
        <button
          type="button"
          onClick={() => setCollapsed(true)}
          className="text-gray-500 hover:text-white text-sm px-1"
          title="Collapse sidebar"
        >
          ◀
        </button>
      </div>
    </aside>
  );
}

// --- Graph Overview Canvas ---

import type { GraphOverviewData } from "../hooks/useGraphOverview";

function GraphOverviewCanvas({ data }: { data: GraphOverviewData }) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const draggingRef = useRef(false);

  // Which block is "current"
  const currentBlockId = useMemo(() => {
    for (const b of data.blocks) {
      for (const insn of b.insns) {
        if (insn.address === data.currentAddress) return b.id;
      }
    }
    return -1;
  }, [data.blocks, data.currentAddress]);

  // Graph bounds + scale computation (shared by draw + click)
  const layout = useMemo(() => {
    if (data.blocks.length === 0) return null;
    const minX = Math.min(...data.blocks.map((b) => b.x));
    const maxX = Math.max(...data.blocks.map((b) => b.x + b.w));
    const minY = Math.min(...data.blocks.map((b) => b.y));
    const maxY = Math.max(...data.blocks.map((b) => b.y + b.h));
    return { minX, maxX, minY, maxY, graphW: maxX - minX, graphH: maxY - minY };
  }, [data.blocks]);

  const draw = useCallback(() => {
    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container || !layout || layout.graphW === 0 || layout.graphH === 0) return;

    const canvasW = container.clientWidth;
    const canvasH = 120;
    canvas.width = canvasW;
    canvas.height = canvasH;

    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.clearRect(0, 0, canvasW, canvasH);

    const padding = 4;
    const scaleX = (canvasW - padding * 2) / layout.graphW;
    const scaleY = (canvasH - padding * 2) / layout.graphH;
    const scale = Math.min(scaleX, scaleY);

    const offsetX = padding + (canvasW - padding * 2 - layout.graphW * scale) / 2;
    const offsetY = padding + (canvasH - padding * 2 - layout.graphH * scale) / 2;

    // Draw edges
    ctx.strokeStyle = "rgba(107, 114, 128, 0.3)";
    ctx.lineWidth = 0.5;
    for (const edge of data.edges) {
      const fromBlock = data.blocks.find((b) => b.id === edge.from);
      const toBlock = data.blocks.find((b) => b.id === edge.to);
      if (!fromBlock || !toBlock) continue;
      const fx = offsetX + (fromBlock.x + fromBlock.w / 2 - layout.minX) * scale;
      const fy = offsetY + (fromBlock.y + fromBlock.h - layout.minY) * scale;
      const tx = offsetX + (toBlock.x + toBlock.w / 2 - layout.minX) * scale;
      const ty = offsetY + (toBlock.y - layout.minY) * scale;
      ctx.beginPath();
      ctx.moveTo(fx, fy);
      ctx.lineTo(tx, ty);
      ctx.stroke();
    }

    // Draw blocks
    for (const block of data.blocks) {
      const bx = offsetX + (block.x - layout.minX) * scale;
      const by = offsetY + (block.y - layout.minY) * scale;
      const bw = Math.max(2, block.w * scale);
      const bh = Math.max(1, block.h * scale);

      ctx.fillStyle =
        block.id === currentBlockId ? "rgba(59, 130, 246, 0.7)" : "rgba(107, 114, 128, 0.5)";
      ctx.fillRect(bx, by, bw, bh);
    }

    // Draw viewport rectangle
    const vpGx = -data.pan.x / data.zoom;
    const vpGy = -data.pan.y / data.zoom;
    const vpGw = data.viewport.width / data.zoom;
    const vpGh = data.viewport.height / data.zoom;

    const vx = offsetX + (vpGx - layout.minX) * scale;
    const vy = offsetY + (vpGy - layout.minY) * scale;
    const vw = vpGw * scale;
    const vh = vpGh * scale;

    ctx.strokeStyle = "rgba(255, 255, 255, 0.5)";
    ctx.lineWidth = 1;
    ctx.strokeRect(vx + 0.5, vy + 0.5, vw, vh);
  }, [data, layout, currentBlockId]);

  useEffect(() => {
    draw();
  }, [draw]);

  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const observer = new ResizeObserver(() => draw());
    observer.observe(container);
    return () => observer.disconnect();
  }, [draw]);

  const canvasToGraph = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      if (!layout || layout.graphW === 0 || layout.graphH === 0) return null;
      const canvas = canvasRef.current;
      if (!canvas) return null;
      const rect = canvas.getBoundingClientRect();
      const clickX = e.clientX - rect.left;
      const clickY = e.clientY - rect.top;

      const canvasW = canvas.width;
      const canvasH = 120;
      const padding = 4;
      const scaleX = (canvasW - padding * 2) / layout.graphW;
      const scaleY = (canvasH - padding * 2) / layout.graphH;
      const scale = Math.min(scaleX, scaleY);
      const offsetX = padding + (canvasW - padding * 2 - layout.graphW * scale) / 2;
      const offsetY = padding + (canvasH - padding * 2 - layout.graphH * scale) / 2;

      const graphX = (clickX - offsetX) / scale + layout.minX;
      const graphY = (clickY - offsetY) / scale + layout.minY;
      return { graphX, graphY };
    },
    [layout],
  );

  const handleMouseDown = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      const pt = canvasToGraph(e);
      if (!pt) return;
      draggingRef.current = true;
      data.onPanTo({
        x: data.viewport.width / 2 - pt.graphX * data.zoom,
        y: data.viewport.height / 2 - pt.graphY * data.zoom,
      });
    },
    [canvasToGraph, data],
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      if (!draggingRef.current) return;
      const pt = canvasToGraph(e);
      if (!pt) return;
      data.onPanTo({
        x: data.viewport.width / 2 - pt.graphX * data.zoom,
        y: data.viewport.height / 2 - pt.graphY * data.zoom,
      });
    },
    [canvasToGraph, data],
  );

  const handleMouseUp = useCallback(() => {
    draggingRef.current = false;
  }, []);

  return (
    <div ref={containerRef} className="mt-1.5" style={{ height: 120 }}>
      <canvas
        ref={canvasRef}
        style={{ width: "100%", height: 120, cursor: "crosshair" }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
      />
    </div>
  );
}
