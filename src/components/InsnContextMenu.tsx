// The instruction context menu, previously duplicated character-for-character
// between DisassemblyView's linear-mode and graph-mode render sites. The only
// difference between the two copies was the trailing "Copy selected (N rows)"
// item, which the linear copy rendered when a selection range existed and the
// graph copy never rendered at all. That is preserved by passing
// selectionRange={null} at the graph call site.
import type { Ref } from "react";
import type { DisasmFunction } from "../disasm/types";
import type { DisplayRow } from "../hooks/useDisassemblyRows";
import type { ContextMenuState } from "../hooks/useInsnContextMenu";
import type { PEFile } from "../pe/types";
import { copyText } from "../utils/clipboard";
import { parseBranchTarget } from "./shared";

export interface InsnContextMenuActions {
  ctxCopyAddr: () => void;
  ctxCopyInsn: () => void;
  ctxCopyBytes: () => void;
  ctxGoTo: () => void;
  ctxShowInHex: () => void;
  ctxToggleBookmark: () => void;
  ctxAddComment: () => void;
  ctxCopyComment: () => void;
  ctxRenameFunction: () => void;
  ctxFollowTarget: () => void;
  ctxShowXrefs: () => void;
}

export function InsnContextMenu({
  ctxMenu,
  menuRef,
  actions,
  xrefCountMap,
  comments,
  funcMap,
  setCtxMenu,
  scanFunction,
  selectionRange,
  rows,
  pe,
  renames,
  formatRangeCopy,
}: {
  ctxMenu: ContextMenuState;
  menuRef: Ref<HTMLDivElement>;
  actions: InsnContextMenuActions;
  xrefCountMap: Map<number, number>;
  comments: Record<number, string>;
  funcMap: Map<number, DisasmFunction>;
  setCtxMenu: (v: ContextMenuState | null) => void;
  scanFunction: (fn: DisasmFunction) => void;
  selectionRange: { start: number; end: number } | null;
  rows: DisplayRow[];
  pe: PEFile | null;
  renames: Record<number, string>;
  formatRangeCopy: (
    range: { start: number; end: number },
    rows: DisplayRow[],
    pe: PEFile | null,
    renames: Record<number, string>,
    comments: Record<number, string>,
  ) => string;
}) {
  const branchTarget = parseBranchTarget(ctxMenu.insn.mnemonic, ctxMenu.insn.opStr);
  const xrefCount = xrefCountMap.get(ctxMenu.insn.address) ?? 0;
  const hasComment = !!(comments[ctxMenu.insn.address] || ctxMenu.insn.comment);
  const isFuncHead = funcMap.has(ctxMenu.insn.address);
  const menuItem = (label: string, onClick: () => void, hint?: string) => (
    <button
      type="button"
      onClick={onClick}
      className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200 flex items-center justify-between"
    >
      <span>{label}</span>
      {hint && <span className="text-gray-500 text-[9px] ml-4">{hint}</span>}
    </button>
  );
  const sep = <div className="border-t border-gray-800 my-0.5" />;
  return (
    <div
      ref={menuRef}
      className="absolute z-50 backdrop-blur-sm bg-gray-900/95 border border-gray-700 rounded-lg shadow-xl py-1 text-xs min-w-[200px]"
      style={{ left: ctxMenu.x, top: ctxMenu.y }}
    >
      {menuItem("Copy address", actions.ctxCopyAddr)}
      {menuItem("Copy instruction", actions.ctxCopyInsn)}
      {menuItem("Copy bytes", actions.ctxCopyBytes)}
      {sep}
      {branchTarget !== null && menuItem("Follow target", actions.ctxFollowTarget, "Enter")}
      {xrefCount > 0 && menuItem(`Show xrefs (${xrefCount})`, actions.ctxShowXrefs, "R")}
      {(branchTarget !== null || xrefCount > 0) && sep}
      {menuItem("Go to address...", actions.ctxGoTo, "G")}
      {menuItem("Show in Hex", actions.ctxShowInHex)}
      {sep}
      {menuItem("Toggle bookmark", actions.ctxToggleBookmark, "B")}
      {menuItem("Add/Edit comment", actions.ctxAddComment, ";")}
      {hasComment && menuItem("Copy comment", actions.ctxCopyComment)}
      {isFuncHead && menuItem("Rename function", actions.ctxRenameFunction, "N")}
      {isFuncHead && sep}
      {isFuncHead &&
        menuItem("Scan for vulnerabilities", () => {
          const fn = funcMap.get(ctxMenu.insn.address);
          if (fn) scanFunction(fn);
          setCtxMenu(null);
        })}
      {selectionRange &&
        (() => {
          const lo = Math.min(selectionRange.start, selectionRange.end);
          const hi = Math.max(selectionRange.start, selectionRange.end);
          const count = hi - lo + 1;
          return (
            <>
              {sep}
              {menuItem(`Copy selected (${count} rows)`, () => {
                void copyText(formatRangeCopy(selectionRange, rows, pe, renames, comments));
                setCtxMenu(null);
              })}
            </>
          );
        })()}
    </div>
  );
}
