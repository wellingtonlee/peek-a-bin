import { useCallback, useEffect, useRef } from "react";

/** Pixels moved per arrow-key press when the handle has keyboard focus. */
const KEYBOARD_STEP_PX = 16;

interface ResizeHandleProps {
  orientation?: "horizontal" | "vertical";
  onResize: (delta: number) => void;
  onResizeEnd?: () => void;
}

export function ResizeHandle({
  orientation = "horizontal",
  onResize,
  onResizeEnd,
}: ResizeHandleProps) {
  const prevPosRef = useRef(0);

  // The mousemove/mouseup listeners are registered once per drag, so they would
  // otherwise close over the callbacks as of mousedown. Callers pass inline arrows
  // that read the panel width from their render scope, which meant onResizeEnd
  // persisted the PRE-drag width to localStorage on every resize. Routing through
  // refs means mouseup sees the callback from the most recent render instead.
  const onResizeRef = useRef(onResize);
  const onResizeEndRef = useRef(onResizeEnd);
  useEffect(() => {
    onResizeRef.current = onResize;
    onResizeEndRef.current = onResizeEnd;
  });

  const handleMouseDown = useCallback(
    (e: React.MouseEvent) => {
      e.preventDefault();
      const isHorizontal = orientation === "horizontal";
      prevPosRef.current = isHorizontal ? e.clientX : e.clientY;

      const onMouseMove = (ev: MouseEvent) => {
        const currentPos = isHorizontal ? ev.clientX : ev.clientY;
        const delta = currentPos - prevPosRef.current;
        prevPosRef.current = currentPos;
        onResizeRef.current(delta);
      };
      const onMouseUp = () => {
        document.removeEventListener("mousemove", onMouseMove);
        document.removeEventListener("mouseup", onMouseUp);
        document.body.style.cursor = "";
        document.body.style.userSelect = "";
        onResizeEndRef.current?.();
      };
      document.addEventListener("mousemove", onMouseMove);
      document.addEventListener("mouseup", onMouseUp);
      document.body.style.cursor = isHorizontal ? "col-resize" : "row-resize";
      document.body.style.userSelect = "none";
    },
    [orientation],
  );

  // Keyboard resizing. The onResize API is already delta-based, so arrow keys map
  // onto it directly — this gives keyboard users a resize path they previously had
  // no equivalent for, rather than just satisfying the linter.
  //
  // `onResizeEnd` IS DEFERRED TO A MICROTASK HERE, AND ONLY HERE. The mouse path
  // calls it from `mouseup`, a separate event after React has committed the last
  // `mousemove`, so a caller reading its own state sees the post-drag value. This
  // path has no such gap: called inline, `onResize` and `onResizeEnd` run in ONE
  // handler with no render between them, so a caller reading state is handed the
  // PRE-press value however faithfully the refs above route the callbacks — the
  // ref indirection cannot fix what has not been committed yet. That was a live
  // defect in three of this component's four callers (peek-a-bin-ob8e,
  // peek-a-bin-a2ze): one arrow press moved the bottom panel to 236px and stored
  // 220, so the first press saved nothing and every later one saved a step
  // behind.
  //
  // A microtask is enough, and that is MEASURED rather than assumed: React
  // flushes a discrete event's updates synchronously before yielding, so the
  // queued callback runs after the commit. The cost is that a caller's
  // keyboard-persistence test must await one turn; the mouse path's stays
  // synchronous because its timing is unchanged.
  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      const isHorizontal = orientation === "horizontal";
      const decrease = isHorizontal ? "ArrowLeft" : "ArrowUp";
      const increase = isHorizontal ? "ArrowRight" : "ArrowDown";
      if (e.key !== decrease && e.key !== increase) return;
      e.preventDefault();
      onResizeRef.current(e.key === decrease ? -KEYBOARD_STEP_PX : KEYBOARD_STEP_PX);
      queueMicrotask(() => onResizeEndRef.current?.());
    },
    [orientation],
  );

  return (
    <button
      type="button"
      aria-label={orientation === "horizontal" ? "Resize panel width" : "Resize panel height"}
      className={orientation === "horizontal" ? "panel-handle-h" : "panel-handle-v"}
      onMouseDown={handleMouseDown}
      onKeyDown={handleKeyDown}
    />
  );
}
