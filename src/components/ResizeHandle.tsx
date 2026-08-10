import { useCallback, useEffect, useRef } from "react";

interface ResizeHandleProps {
  orientation?: "horizontal" | "vertical";
  onResize: (delta: number) => void;
  onResizeEnd?: () => void;
}

export function ResizeHandle({ orientation = "horizontal", onResize, onResizeEnd }: ResizeHandleProps) {
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

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
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
  }, [orientation]);

  return (
    <div
      className={orientation === "horizontal" ? "panel-handle-h" : "panel-handle-v"}
      onMouseDown={handleMouseDown}
    />
  );
}
