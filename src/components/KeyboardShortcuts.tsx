import { useEffect } from "react";

interface Props {
  open: boolean;
  onClose: () => void;
}

interface Shortcut {
  key: string;
  action: string;
}

interface ShortcutGroup {
  category: string;
  shortcuts: Shortcut[];
}

const SHORTCUT_GROUPS: ShortcutGroup[] = [
  {
    category: "Navigation",
    shortcuts: [
      { key: "1-8", action: "Switch tabs" },
      { key: "G", action: "Focus address input" },
      { key: "Alt+\u2190/\u2192", action: "Back / Forward" },
      { key: "Enter", action: "Follow branch target" },
      { key: "Escape", action: "Close panel" },
      { key: "X", action: "Toggle call panel" },
      { key: "R", action: "Toggle xref panel" },
      { key: "I", action: "Toggle instruction detail" },
      { key: "D", action: "Toggle decompiler" },
      { key: "Alt+H", action: "Recent addresses" },
    ],
  },
  {
    category: "Annotations",
    shortcuts: [
      { key: "B", action: "Toggle bookmark" },
      { key: "Ctrl+Z / Ctrl+Shift+Z", action: "Undo / Redo" },
    ],
  },
  {
    category: "Search",
    shortcuts: [
      { key: "Ctrl+P", action: "Command palette" },
      { key: "Ctrl+F", action: "Search disassembly" },
    ],
  },
  {
    category: "Clipboard",
    shortcuts: [
      { key: "Ctrl+C", action: "Copy instruction" },
      { key: "Ctrl+Shift+C", action: "Copy address" },
    ],
  },
  {
    category: "Disassembly",
    shortcuts: [
      { key: "\u2191 / \u2193", action: "Navigate instructions" },
      { key: "Space", action: "Toggle graph / linear view" },
      { key: "; (semicolon)", action: "Add / edit comment" },
      { key: "N", action: "Rename function" },
    ],
  },
  {
    category: "Graph",
    shortcuts: [
      { key: "\u2191 / \u2193", action: "Navigate within/across blocks" },
      { key: "Tab", action: "Cycle successor blocks" },
      { key: "Enter", action: "Follow branch target" },
      { key: "0", action: "Zoom to fit" },
    ],
  },
];

export function KeyboardShortcuts({ open, onClose }: Props) {
  useEffect(() => {
    if (!open) return;
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [open, onClose]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/50"
      onClick={onClose}
    >
      <div
        className="w-[512px] max-w-lg bg-gray-800 border border-gray-600 rounded-lg shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-gray-700">
          <h2 className="text-sm font-semibold text-gray-200">Keyboard Shortcuts</h2>
        </div>
        <div className="max-h-[400px] overflow-auto px-4 py-2">
          {SHORTCUT_GROUPS.map((group) => (
            <div key={group.category} className="mb-3">
              <div className="text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                {group.category}
              </div>
              {group.shortcuts.map((shortcut) => (
                <div
                  key={shortcut.key}
                  className="flex items-center justify-between py-1 text-xs"
                >
                  <span className="text-gray-300">{shortcut.action}</span>
                  <span className="flex items-center gap-1">
                    {shortcut.key.split(" / ").map((k, i) => (
                      <span key={i} className="flex items-center gap-1">
                        {i > 0 && <span className="text-gray-500">/</span>}
                        <kbd className="bg-gray-700 rounded px-1.5 py-0.5 text-xs font-mono text-gray-300 border border-gray-600">
                          {k}
                        </kbd>
                      </span>
                    ))}
                  </span>
                </div>
              ))}
            </div>
          ))}
        </div>
        <div className="px-4 py-2 border-t border-gray-700 text-[10px] text-gray-500 text-center">
          Press <kbd className="px-1 py-0.5 bg-gray-700 rounded">?</kbd> to toggle this panel
        </div>
      </div>
    </div>
  );
}
