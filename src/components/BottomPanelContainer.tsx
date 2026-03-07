import { useState, useEffect, useCallback, useRef, type ReactNode } from "react";
import { createPortal } from "react-dom";
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
  const [activeTab, setActiveTab] = useState<string>("");
  const [poppedOut, setPoppedOut] = useState<Map<string, FloatingState>>(new Map());

  // Set activeTab to first visible if current is gone
  useEffect(() => {
    const tabbedPanels = visiblePanels.filter((p) => !poppedOut.has(p.id));
    if (tabbedPanels.length > 0 && !tabbedPanels.find((p) => p.id === activeTab)) {
      setActiveTab(tabbedPanels[0].id);
    }
  }, [visiblePanels.map((p) => p.id).join(","), activeTab, poppedOut]);

  const handleResize = useCallback((delta: number) => {
    setHeight((prev) => Math.max(MIN_HEIGHT, Math.min(MAX_HEIGHT, prev - delta)));
  }, []);

  const handleResizeEnd = useCallback(() => {
    try { localStorage.setItem("peek-a-bin:bottom-panel-height", String(height)); } catch {}
  }, [height]);

  const handlePopOut = useCallback((id: string) => {
    setPoppedOut((prev) => {
      const next = new Map(prev);
      next.set(id, {
        x: Math.round(window.innerWidth / 2 - 200),
        y: Math.round(window.innerHeight / 2 - 150),
        w: 400,
        h: 300,
      });
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
          <ResizeHandle orientation="vertical" onResize={handleResize} onResizeEnd={handleResizeEnd} />
          {/* Tab header */}
          <div className="flex items-center gap-0.5 px-2 py-0.5 border-b border-gray-700 shrink-0">
            {tabbedPanels.map((p) => (
              <button
                key={p.id}
                onClick={() => setActiveTab(p.id)}
                className={`px-2 py-0.5 rounded text-[10px] flex items-center gap-1 ${
                  activeTab === p.id
                    ? "bg-blue-600 text-white"
                    : "text-gray-400 hover:text-white hover:bg-gray-700"
                }`}
              >
                {p.label}
                <span
                  className="text-gray-500 hover:text-gray-200 text-[8px] ml-0.5"
                  onClick={(e) => { e.stopPropagation(); handlePopOut(p.id); }}
                  title="Pop out"
                >
                  ↗
                </span>
                <span
                  className="text-gray-500 hover:text-red-400 text-[9px]"
                  onClick={(e) => { e.stopPropagation(); p.onClose(); }}
                  title="Close"
                >
                  ✕
                </span>
              </button>
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
        const fs = poppedOut.get(p.id)!;
        return createPortal(
          <FloatingPanel
            key={p.id}
            panel={p}
            state={fs}
            onDock={() => handleDock(p.id)}
            onClose={p.onClose}
            onMove={(x, y) => {
              setPoppedOut((prev) => {
                const next = new Map(prev);
                next.set(p.id, { ...fs, x, y });
                return next;
              });
            }}
            onResizeFloat={(w, h) => {
              setPoppedOut((prev) => {
                const next = new Map(prev);
                next.set(p.id, { ...fs, w, h });
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

function FloatingPanel({ panel, state, onDock, onClose, onMove, onResizeFloat }: FloatingPanelProps) {
  const headerRef = useRef<HTMLDivElement>(null);
  const resizeRef = useRef<HTMLDivElement>(null);

  // Drag header
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
          onClick={onDock}
          className="text-gray-500 hover:text-white text-[10px] px-1"
          title="Re-dock"
        >
          ↙
        </button>
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-red-400 text-[10px] px-1"
          title="Close"
        >
          ✕
        </button>
      </div>
      {/* Content */}
      <div className="flex-1 overflow-auto">
        {panel.content}
      </div>
      {/* Resize corner */}
      <div
        ref={resizeRef}
        className="absolute bottom-0 right-0 w-3 h-3 cursor-nwse-resize"
        style={{ background: "linear-gradient(135deg, transparent 50%, rgba(107,114,128,0.5) 50%)" }}
      />
    </div>
  );
}
