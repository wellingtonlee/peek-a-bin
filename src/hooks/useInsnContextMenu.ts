// Instruction context-menu actions, lifted verbatim out of DisassemblyView.
//
// The hooks below appear in exactly the order they had inline, and every
// dependency array is copied unchanged. The call to useInsnContextMenu() must
// therefore stay at the position the first ctx* callback occupied — React
// identifies hooks by call order.
//
// State that these actions read or write (ctxMenu, editingComment,
// renamingLabel, showXrefPanel) deliberately stays declared in DisassemblyView
// and is passed in: moving those useState calls would shift them to a different
// position in the hook sequence.
import {
  type Dispatch,
  type MouseEvent as ReactMouseEvent,
  type RefObject,
  useCallback,
  useMemo,
} from "react";
import { parseBranchTarget } from "../components/shared";
import type { DisasmFunction, Instruction, Xref } from "../disasm/types";
import { rvaToFileOffset } from "../pe/parser";
import type { PEFile } from "../pe/types";
import { copyText } from "../utils/clipboard";
import { type AppAction, getDisplayName } from "./usePEFile";

export interface ContextMenuState {
  x: number;
  y: number;
  insn: Instruction;
}

export interface UseInsnContextMenuArgs {
  ctxMenu: ContextMenuState | null;
  setCtxMenu: (v: ContextMenuState | null) => void;
  pe: PEFile | null;
  dispatch: Dispatch<AppAction>;
  comments: Record<number, string>;
  renames: Record<number, string>;
  funcMap: Map<number, DisasmFunction>;
  typedXrefMap: Map<number, Xref[]>;
  setEditingComment: (v: { address: number; value: string } | null) => void;
  setRenamingLabel: (v: { address: number; value: string } | null) => void;
  setShowXrefPanel: (v: boolean) => void;
  handleAddressClick: (address: number) => void;
  viewMode: "linear" | "graph";
  cfgContainerRef: RefObject<HTMLDivElement | null>;
  parentRef: RefObject<HTMLDivElement | null>;
}

export function useInsnContextMenu({
  ctxMenu,
  setCtxMenu,
  pe,
  dispatch,
  comments,
  renames,
  funcMap,
  typedXrefMap,
  setEditingComment,
  setRenamingLabel,
  setShowXrefPanel,
  handleAddressClick,
  viewMode,
  cfgContainerRef,
  parentRef,
}: UseInsnContextMenuArgs) {
  const ctxCopyAddr = useCallback(() => {
    if (!ctxMenu) return;
    void copyText("0x" + ctxMenu.insn.address.toString(16).toUpperCase());
    setCtxMenu(null);
  }, [ctxMenu, setCtxMenu]);

  const ctxCopyInsn = useCallback(() => {
    if (!ctxMenu) return;
    void copyText(`${ctxMenu.insn.mnemonic} ${ctxMenu.insn.opStr}`);
    setCtxMenu(null);
  }, [ctxMenu, setCtxMenu]);

  const ctxCopyBytes = useCallback(() => {
    if (!ctxMenu) return;
    const hex = Array.from(ctxMenu.insn.bytes)
      .map((b) => b.toString(16).padStart(2, "0"))
      .join(" ");
    void copyText(hex);
    setCtxMenu(null);
  }, [ctxMenu, setCtxMenu]);

  const ctxGoTo = useCallback(() => {
    if (!ctxMenu) return;
    const target = parseBranchTarget(ctxMenu.insn.mnemonic, ctxMenu.insn.opStr);
    const addrInput = document.querySelector<HTMLInputElement>('input[placeholder*="address"]');
    if (addrInput) {
      addrInput.focus();
      const prefill = target !== null ? "0x" + target.toString(16) : ctxMenu.insn.opStr;
      addrInput.value = prefill;
      addrInput.dispatchEvent(new Event("input", { bubbles: true }));
    }
    setCtxMenu(null);
  }, [ctxMenu, setCtxMenu]);

  const ctxShowInHex = useCallback(() => {
    if (!ctxMenu || !pe) return;
    const rva = ctxMenu.insn.address - pe.optionalHeader.imageBase;
    const fileOffset = rvaToFileOffset(rva, pe.sections);
    if (fileOffset >= 0) {
      dispatch({ type: "SET_ADDRESS", address: ctxMenu.insn.address });
      dispatch({ type: "SET_TAB", tab: "hex" });
    }
    setCtxMenu(null);
  }, [ctxMenu, pe, dispatch, setCtxMenu]);

  const ctxToggleBookmark = useCallback(() => {
    if (!ctxMenu) return;
    dispatch({ type: "TOGGLE_BOOKMARK", address: ctxMenu.insn.address });
    setCtxMenu(null);
  }, [ctxMenu, dispatch, setCtxMenu]);

  const ctxAddComment = useCallback(() => {
    if (!ctxMenu) return;
    const existing = comments[ctxMenu.insn.address] ?? "";
    setEditingComment({ address: ctxMenu.insn.address, value: existing });
    setCtxMenu(null);
  }, [ctxMenu, comments, setEditingComment, setCtxMenu]);

  const ctxCopyComment = useCallback(() => {
    if (!ctxMenu) return;
    const comment = comments[ctxMenu.insn.address] || ctxMenu.insn.comment;
    if (comment) void copyText(comment);
    setCtxMenu(null);
  }, [ctxMenu, comments, setCtxMenu]);

  const ctxRenameFunction = useCallback(() => {
    if (!ctxMenu) return;
    // Find the function that owns this instruction
    const addr = ctxMenu.insn.address;
    const fn = funcMap.get(addr);
    if (fn) {
      setRenamingLabel({ address: fn.address, value: getDisplayName(fn, renames) });
    }
    setCtxMenu(null);
  }, [ctxMenu, funcMap, renames, setRenamingLabel, setCtxMenu]);

  const ctxFollowTarget = useCallback(() => {
    if (!ctxMenu) return;
    const target = parseBranchTarget(ctxMenu.insn.mnemonic, ctxMenu.insn.opStr);
    if (target !== null) handleAddressClick(target);
    setCtxMenu(null);
  }, [ctxMenu, handleAddressClick, setCtxMenu]);

  const ctxShowXrefs = useCallback(() => {
    if (!ctxMenu) return;
    setShowXrefPanel(true);
    setCtxMenu(null);
  }, [ctxMenu, setShowXrefPanel, setCtxMenu]);

  // Xref count map for context menu
  const xrefCountMap = useMemo(() => {
    const m = new Map<number, number>();
    for (const [addr, xrefs] of typedXrefMap) {
      m.set(addr, xrefs.length);
    }
    return m;
  }, [typedXrefMap]);

  const handleContextMenu = useCallback(
    (e: ReactMouseEvent, insn: Instruction) => {
      e.preventDefault();
      const container = viewMode === "graph" ? cfgContainerRef.current : parentRef.current;
      if (!container) return;
      const rect = container.getBoundingClientRect();
      const rawX = e.clientX - rect.left;
      const rawY = e.clientY - rect.top;
      const popW = 180,
        popH = 300;
      const maxX = rect.width - popW - 8;
      const maxY = rect.height - popH - 8;
      setCtxMenu({
        x: Math.max(
          0,
          Math.min(
            rawX + (viewMode === "linear" ? container.scrollLeft : 0),
            viewMode === "linear" ? maxX + container.scrollLeft : maxX,
          ),
        ),
        y: Math.max(
          0,
          Math.min(
            rawY + (viewMode === "linear" ? container.scrollTop : 0),
            viewMode === "linear" ? maxY + container.scrollTop : maxY,
          ),
        ),
        insn,
      });
    },
    [viewMode, cfgContainerRef, parentRef, setCtxMenu],
  );

  return {
    // Bundled for the menu component. Rebuilt every render, exactly as the
    // eleven inline callbacks were re-read every render before.
    actions: {
      ctxCopyAddr,
      ctxCopyInsn,
      ctxCopyBytes,
      ctxGoTo,
      ctxShowInHex,
      ctxToggleBookmark,
      ctxAddComment,
      ctxCopyComment,
      ctxRenameFunction,
      ctxFollowTarget,
      ctxShowXrefs,
    },
    xrefCountMap,
    handleContextMenu,
  };
}
