import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { clampFloatingPosition } from "./floatingClamp";
import { ResizeHandle } from "./ResizeHandle";

interface PanelDef {
  id: string;
  label: string;
  visible: boolean;
  content: ReactNode;
  onClose: () => void;
}

interface BottomPanelContainerProps {
  panels: PanelDef[];
}

const MIN_HEIGHT = 80;
const MAX_HEIGHT = 600;
const DEFAULT_HEIGHT = 220;

function loadHeight(): number {
  try {
    const v = localStorage.getItem("peek-a-bin:bottom-panel-height");
    if (v) {
      const n = parseInt(v, 10);
      if (n >= MIN_HEIGHT && n <= MAX_HEIGHT) return n;
    }
  } catch {}
  return DEFAULT_HEIGHT;
}

interface FloatingState {
  x: number;
  y: number;
  w: number;
  h: number;
}

export function BottomPanelContainer({ panels }: BottomPanelContainerProps) {
  const visiblePanels = panels.filter((p) => p.visible);
  const [height, setHeight] = useState(loadHeight);
  /**
   * The live height, mirrored so {@link handleResizeEnd} can read it without
   * closing over a render.
   *
   * `ResizeHandle`'s ref indirection is enough for a MOUSE drag, where mouseup
   * is a separate event after a commit. It is NOT enough for the KEYBOARD path,
   * which calls `onResize` and `onResizeEnd` synchronously in one handler: React
   * has not re-rendered in between, so a state-reading `onResizeEnd` is handed
   * the PRE-press value however the callbacks are routed. Measured before the
   * fix: one ArrowUp moved the panel to 236px and stored `220`, so the first
   * press saved nothing and every later press saved the height from a step ago
   * (peek-a-bin-ob8e).
   */
  const heightRef = useRef(height);
  const [activeTab, setActiveTab] = useState<string>("");
  /**
   * Which panels are floating, and where. **DELIBERATELY NOT PRUNED when a
   * panel stops being visible** — a floating panel that is closed and later
   * reopened comes back FLOATING, at the place the user left it, rather than
   * docked. That was found by the first render of this component and looked
   * like an oversight; it is not, and this docstring is the statement that was
   * missing.
   *
   * The argument for keeping it: floating is a choice the user made about that
   * panel, and closing a panel is not withdrawing it. Discarding the geometry
   * on close would mean a user who works with the Xrefs panel floating in a
   * particular corner re-floats it and re-places it every time they close it,
   * and the only signal for doing that would be that the panel went away —
   * which is the ordinary way to finish with one. The docked height gets the
   * same treatment one step further, being persisted to localStorage.
   *
   * Why it is not a leak: the keys are the panel ids, which are three string
   * literals at the single mount site in `DisassemblyView.tsx` ("calls",
   * "detail", "xrefs"), so the map is bounded at three entries and holds four
   * numbers each. Pruning would buy nothing back.
   *
   * The one edge it does own: a stored `x`/`y` can be off-screen if the window
   * shrank while the panel was closed. That is the same exposure as dragging a
   * floating panel off-screen, which nothing clamps either, and it belongs to
   * the clamp rather than to pruning.
   */
  const [poppedOut, setPoppedOut] = useState<Map<string, FloatingState>>(new Map());

  /**
   * The viewport every floating position is clamped against, held as state so
   * that a resize re-runs the derivation at the render site below. Seeded from
   * `window` at mount, which is safe because nothing here renders on a server.
   *
   * The listener is unconditional rather than installed only while something is
   * floating: the obvious guard (`poppedOut.size > 0`) would leave this stale
   * exactly when a panel is CLOSED, which is the reopen case the clamp exists
   * for, and a dependency on `poppedOut` itself would tear the listener down and
   * rebuild it on every `mousemove` of a drag. The cost of always listening is
   * one listener and a state write that returns the SAME OBJECT when neither
   * dimension moved, so React bails out and a resize on the other axis of a
   * scrollbar appearing re-renders nothing.
   */
  const [viewport, setViewport] = useState(() => ({
    w: window.innerWidth,
    h: window.innerHeight,
  }));

  useEffect(() => {
    const onResize = () => {
      setViewport((prev) =>
        prev.w === window.innerWidth && prev.h === window.innerHeight
          ? prev
          : { w: window.innerWidth, h: window.innerHeight },
      );
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, []);

  // Set activeTab to first visible if current is gone.
  //
  // The first dependency is a joined id string on purpose: `visiblePanels` is
  // rebuilt by `panels.filter(...)` on every render, so depending on the array
  // itself would run this effect every render. The string changes only when the
  // set of visible panels actually changes.
  // biome-ignore lint/correctness/useExhaustiveDependencies: the joined panel-id string is a deliberate value-identity key standing in for the freshly-filtered visiblePanels array.
  useEffect(() => {
    const tabbedPanels = visiblePanels.filter((p) => !poppedOut.has(p.id));
    if (tabbedPanels.length > 0 && !tabbedPanels.find((p) => p.id === activeTab)) {
      setActiveTab(tabbedPanels[0].id);
    }
  }, [visiblePanels.map((p) => p.id).join(","), activeTab, poppedOut]);

  const handleResize = useCallback((delta: number) => {
    // The ref is the sequence's source of truth and the state mirrors it: several
    // mousemoves can land in one tick and each must see the previous one's
    // result. Computed OUTSIDE the updater so the updater stays pure under
    // StrictMode's double invocation.
    const next = Math.max(MIN_HEIGHT, Math.min(MAX_HEIGHT, heightRef.current - delta));
    heightRef.current = next;
    setHeight(next);
  }, []);

  // Reads the ref rather than the state it mirrors, which is what makes the
  // stored value the post-press one on the keyboard path as well as the mouse
  // one. A `[height]` dependency would be correct for one and wrong for the
  // other; see `heightRef`'s note.
  const handleResizeEnd = useCallback(() => {
    try {
      localStorage.setItem("peek-a-bin:bottom-panel-height", String(heightRef.current));
    } catch {}
  }, []);

  /**
   * Mint a floating position: the window's centre, through the same clamp.
   *
   * **THIS CALL IS INERT AND THAT WAS MEASURED, NOT ASSUMED — it is recorded
   * here rather than tuned away.** Centring can violate exactly one of the four
   * bounds, and only the one the derivation below re-applies identically at
   * every viewport, so no `window` size and no later resize can make the clamped
   * and unclamped mints render differently:
   *
   * - Sideways it cannot go out of bounds at all. A centred panel of width `w`
   *   spans `[(vw - w)/2, (vw + w)/2]`, so `vw/2 - w/2 <= vw - MIN_VISIBLE_EDGE`
   *   reduces to `MIN_VISIBLE_EDGE <= vw/2 + w/2` and the lower bound likewise —
   *   both hold for every non-negative viewport.
   * - Downwards it cannot either: `vh/2 - h/2 <= vh - MIN_VISIBLE_HEADER`
   *   reduces to `MIN_VISIBLE_HEADER <= vh/2 + h/2`.
   * - Upwards it can, whenever `vh < h` — a 200px-tall window puts the centred
   *   top edge at -50. But the TOP bound is a hard zero and therefore does not
   *   depend on the viewport, so the derivation maps a stored -50 to 0 whatever
   *   the window is doing, now or later.
   *
   * It is kept because the alternative is a second site computing a panel
   * position without the rule, and the inertness is a property of the derivation
   * below rather than of this call — the day that derivation changes, this is
   * what stops a mint going out of bounds. Its cost is one function call.
   *
   * It reads `window` rather than the `viewport` state on purpose: a value being
   * minted right now should use the live viewport, not a copy that a render may
   * not yet have caught up with.
   */
  const handlePopOut = useCallback((id: string) => {
    setPoppedOut((prev) => {
      const next = new Map(prev);
      const w = 400;
      const h = 300;
      const at = clampFloatingPosition(
        Math.round(window.innerWidth / 2 - w / 2),
        Math.round(window.innerHeight / 2 - h / 2),
        w,
        window.innerWidth,
        window.innerHeight,
      );
      next.set(id, { ...at, w, h });
      return next;
    });
  }, []);

  const handleDock = useCallback((id: string) => {
    setPoppedOut((prev) => {
      const next = new Map(prev);
      next.delete(id);
      return next;
    });
    setActiveTab(id);
  }, []);

  const tabbedPanels = visiblePanels.filter((p) => !poppedOut.has(p.id));
  const floatingPanels = visiblePanels.filter((p) => poppedOut.has(p.id));

  if (visiblePanels.length === 0) return null;

  return (
    <>
      {/* Tabbed container */}
      {tabbedPanels.length > 0 && (
        <div className="shrink-0 flex flex-col panel-bg border-t border-theme" style={{ height }}>
          <ResizeHandle
            orientation="vertical"
            onResize={handleResize}
            onResizeEnd={handleResizeEnd}
          />
          {/* Tab header */}
          <div className="flex items-center gap-0.5 px-2 py-0.5 border-b border-gray-700 shrink-0">
            {/* Pop-out and close are siblings of the tab button, not children:
                buttons cannot nest, and as spans they were mouse-only. */}
            {tabbedPanels.map((p) => (
              <div
                key={p.id}
                className={`px-2 py-0.5 rounded text-[10px] flex items-center gap-1 ${
                  activeTab === p.id
                    ? "bg-blue-600 text-white"
                    : "text-gray-400 hover:text-white hover:bg-gray-700"
                }`}
              >
                <button type="button" onClick={() => setActiveTab(p.id)}>
                  {p.label}
                </button>
                <button
                  type="button"
                  className="text-gray-500 hover:text-gray-200 text-[8px] ml-0.5"
                  onClick={() => handlePopOut(p.id)}
                  title="Pop out"
                >
                  ↗
                </button>
                <button
                  type="button"
                  className="text-gray-500 hover:text-red-400 text-[9px]"
                  onClick={() => p.onClose()}
                  title="Close"
                >
                  ✕
                </button>
              </div>
            ))}
          </div>
          {/* Active panel content */}
          <div className="flex-1 overflow-auto">
            {tabbedPanels.map((p) => (
              <div key={p.id} className={p.id === activeTab ? "h-full" : "hidden"}>
                {p.content}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Floating panels */}
      {floatingPanels.map((p) => {
        /**
         * `stored` IS THE USER'S CHOICE AND `fs` IS THE PICTURE OF IT — the
         * position is clamped HERE, on the way to the screen, and is deliberately
         * not written back. That is what makes a panel reopened into (or caught
         * by) a smaller window come in at the edge and then return to where the
         * user actually left it once the room comes back. Same shape as
         * `XrefPanel`'s `effectiveScope`: the derived value is what everything on
         * screen reads, and the stored one is the preference outliving a lapse in
         * the room to honour it.
         *
         * **SO NOTHING MAY WRITE `fs` BACK INTO `poppedOut`.** Spreading it into
         * an update looks harmless and is how the split gets lost: during a lapse
         * `fs.x` is the clamped position, so `{ ...fs, w, h }` in the corner
         * resize below silently replaced the stored preference with the picture —
         * make a panel bigger while the window happens to be narrow and the
         * position it would have gone back to is gone. Both callbacks therefore
         * start from `stored` and override only what the gesture is actually
         * about, and the clamp reads `stored.w` for the same reason.
         *
         * A DRAG is the one thing clamped at the WRITE, and it is not an
         * exception to the rule but the other half of it: the user never chose
         * the position the pointer ran off to, so there is no preference there to
         * preserve, and storing the raw value would have the panel leap out to it
         * the next time the window grew. A corner RESIZE is a statement about
         * size and about nothing else — it carries no position at all, so it must
         * carry the stored one through untouched.
         */
        const stored = poppedOut.get(p.id)!;
        const fs = {
          ...stored,
          ...clampFloatingPosition(stored.x, stored.y, stored.w, viewport.w, viewport.h),
        };
        return createPortal(
          <FloatingPanel
            key={p.id}
            panel={p}
            state={fs}
            onDock={() => handleDock(p.id)}
            onClose={p.onClose}
            onMove={(x, y) => {
              const at = clampFloatingPosition(x, y, stored.w, viewport.w, viewport.h);
              setPoppedOut((prev) => {
                const next = new Map(prev);
                next.set(p.id, { ...stored, ...at });
                return next;
              });
            }}
            onResizeFloat={(w, h) => {
              setPoppedOut((prev) => {
                const next = new Map(prev);
                next.set(p.id, { ...stored, w, h });
                return next;
              });
            }}
          />,
          document.body,
        );
      })}
    </>
  );
}

interface FloatingPanelProps {
  panel: PanelDef;
  state: FloatingState;
  onDock: () => void;
  onClose: () => void;
  onMove: (x: number, y: number) => void;
  onResizeFloat: (w: number, h: number) => void;
}

function FloatingPanel({
  panel,
  state,
  onDock,
  onClose,
  onMove,
  onResizeFloat,
}: FloatingPanelProps) {
  const headerRef = useRef<HTMLDivElement>(null);
  const resizeRef = useRef<HTMLDivElement>(null);

  // Drag header.
  //
  // The grab offset is taken once, from the pointer and the position on screen,
  // and every move is recomputed from the RAW pointer against it. The clamp
  // lives in the caller's `onMove` and therefore applies to the output only —
  // never to this offset, and never accumulated. That is what lets a pointer
  // that ran past an edge and came back pick the panel up at exactly the grab
  // point instead of having drifted by however far it overshot.
  useEffect(() => {
    const el = headerRef.current;
    if (!el) return;
    const handleDown = (e: MouseEvent) => {
      e.preventDefault();
      const startX = e.clientX - state.x;
      const startY = e.clientY - state.y;
      const handleMove = (ev: MouseEvent) => {
        onMove(ev.clientX - startX, ev.clientY - startY);
      };
      const handleUp = () => {
        document.removeEventListener("mousemove", handleMove);
        document.removeEventListener("mouseup", handleUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      };
      document.addEventListener("mousemove", handleMove);
      document.addEventListener("mouseup", handleUp);
      document.body.style.cursor = "move";
      document.body.style.userSelect = "none";
    };
    el.addEventListener("mousedown", handleDown);
    return () => el.removeEventListener("mousedown", handleDown);
  }, [state.x, state.y, onMove]);

  // Corner resize
  useEffect(() => {
    const el = resizeRef.current;
    if (!el) return;
    const handleDown = (e: MouseEvent) => {
      e.preventDefault();
      e.stopPropagation();
      const startX = e.clientX;
      const startY = e.clientY;
      const startW = state.w;
      const startH = state.h;
      const handleMove = (ev: MouseEvent) => {
        onResizeFloat(
          Math.max(200, startW + ev.clientX - startX),
          Math.max(100, startH + ev.clientY - startY),
        );
      };
      const handleUp = () => {
        document.removeEventListener("mousemove", handleMove);
        document.removeEventListener("mouseup", handleUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
      };
      document.addEventListener("mousemove", handleMove);
      document.addEventListener("mouseup", handleUp);
      document.body.style.cursor = "nwse-resize";
      document.body.style.userSelect = "none";
    };
    el.addEventListener("mousedown", handleDown);
    return () => el.removeEventListener("mousedown", handleDown);
  }, [state.w, state.h, onResizeFloat]);

  return (
    <div
      className="fixed z-50 panel-bg border border-gray-600 rounded-lg shadow-2xl flex flex-col overflow-hidden"
      style={{ left: state.x, top: state.y, width: state.w, height: state.h }}
    >
      {/* Draggable header */}
      <div
        ref={headerRef}
        className="flex items-center gap-2 px-2 py-1 border-b border-gray-700 shrink-0 cursor-move select-none"
      >
        <span className="text-gray-300 text-[10px] font-semibold">{panel.label}</span>
        <div className="flex-1" />
        <button
          type="button"
          onClick={onDock}
          className="text-gray-500 hover:text-white text-[10px] px-1"
          title="Re-dock"
        >
          ↙
        </button>
        <button
          type="button"
          onClick={onClose}
          className="text-gray-500 hover:text-red-400 text-[10px] px-1"
          title="Close"
        >
          ✕
        </button>
      </div>
      {/* Content */}
      <div className="flex-1 overflow-auto">{panel.content}</div>
      {/* Resize corner */}
      <div
        ref={resizeRef}
        className="absolute bottom-0 right-0 w-3 h-3 cursor-nwse-resize"
        style={{
          background: "linear-gradient(135deg, transparent 50%, rgba(107,114,128,0.5) 50%)",
        }}
      />
    </div>
  );
}
