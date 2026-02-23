export function clampPopup(x: number, y: number, w: number, h: number): { x: number; y: number } {
  return {
    x: Math.max(0, Math.min(x, window.innerWidth - w - 8)),
    y: Math.max(0, Math.min(y, window.innerHeight - h - 8)),
  };
}
