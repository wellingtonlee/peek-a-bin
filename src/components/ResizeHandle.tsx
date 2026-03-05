import { useCallback, useRef } from "react";

interface ResizeHandleProps {
  orientation?: "horizontal" | "vertical";
  onResize: (delta: number) => void;
  onResizeEnd?: () => void;
}

export function ResizeHandle({ orientation = "horizontal", onResize, onResizeEnd }: ResizeHandleProps) {
  const prevPosRef = useRef(0);

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    e.preventDefault();
    const isHorizontal = orientation === "horizontal";
    prevPosRef.current = isHorizontal ? e.clientX : e.clientY;

    const onMouseMove = (ev: MouseEvent) => {
      const currentPos = isHorizontal ? ev.clientX : ev.clientY;
      const delta = currentPos - prevPosRef.current;
      prevPosRef.current = currentPos;
      onResize(delta);
    };
    const onMouseUp = () => {
      document.removeEventListener("mousemove", onMouseMove);
      document.removeEventListener("mouseup", onMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
      onResizeEnd?.();
    };
    document.addEventListener("mousemove", onMouseMove);
    document.addEventListener("mouseup", onMouseUp);
    document.body.style.cursor = isHorizontal ? "col-resize" : "row-resize";
    document.body.style.userSelect = "none";
  }, [orientation, onResize, onResizeEnd]);

  return (
    <div
      className={orientation === "horizontal" ? "panel-handle-h" : "panel-handle-v"}
      onMouseDown={handleMouseDown}
    />
  );
}
