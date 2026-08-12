// The disassembly pane's keydown handler, lifted verbatim out of
// DisassemblyView along with the decompile-toggle ref that sits immediately
// above it.
//
// The dependency array below arrived as a verbatim copy of the nineteen inline
// entries and was then completed under peek-a-bin-3qi: the entries the
// extraction turned from closed-over locals into parameters were added, plus
// `highlightedReg`, which the body reads and the original array omitted. The one
// dead entry, `funcMap`, is gone — it was referenced nowhere in the body, so the
// parameter went with it. The array is the behaviour, not decoration:
// peek-a-bin-ehv was a single missing entry that went unnoticed for the
// project's whole history. The call to useDisassemblyKeyboard() must stay at the
// position decompileToggleRef occupied — React identifies hooks by call order.
//
// Every piece of state this handler reads or writes stays declared in
// DisassemblyView and is passed in: those useState calls sit hundreds of lines
// above this point, so moving them here would shift them to a different
// position in the hook sequence. Same reasoning as useInsnContextMenu.

import type { Virtualizer } from "@tanstack/react-virtual";
import type { RefObject } from "react";
import {
  type Dispatch,
  type KeyboardEvent as ReactKeyboardEvent,
  useCallback,
  useRef,
} from "react";
import { parseBranchTarget } from "../components/shared";
import type { BasicBlock } from "../disasm/cfg";
import type { DisasmFunction, Instruction } from "../disasm/types";
import type { PEFile } from "../pe/types";
import { type DisplayRow, rowAddress } from "./useDisassemblyRows";
import type { UseDisassemblySearchResult } from "./useDisassemblySearch";
import type { ContextMenuState } from "./useInsnContextMenu";
import { type AppAction, type AppState, getDisplayName } from "./usePEFile";

export interface UseDisassemblyKeyboardArgs {
  search: UseDisassemblySearchResult;
  parentRef: RefObject<HTMLDivElement | null>;
  searchInputRef: RefObject<HTMLInputElement | null>;
  graphSearchInputRef: RefObject<HTMLInputElement | null>;
  cfgContainerRef: RefObject<HTMLDivElement | null>;
  navViewStateMapRef: RefObject<
    Map<
      number,
      { viewMode: "linear" | "graph"; graphPan: { x: number; y: number }; graphZoom: number }
    >
  >;
  highlightedReg: string | null;
  setHighlightedReg: (v: string | null) => void;
  ctxMenu: ContextMenuState | null;
  setCtxMenu: (v: ContextMenuState | null) => void;
  selectionRange: { start: number; end: number } | null;
  setSelectionRange: (v: { start: number; end: number } | null) => void;
  setViewMode: (v: "linear" | "graph") => void;
  setRestorePanZoom: (v: { pan: { x: number; y: number }; zoom: number } | null) => void;
  setEditingComment: (v: { address: number; value: string } | null) => void;
  setRenamingLabel: (v: { address: number; value: string } | null) => void;
  setShowCallPanel: (fn: (v: boolean) => boolean) => void;
  setShowXrefPanel: (fn: (v: boolean) => boolean) => void;
  setShowDetail: (fn: (v: boolean) => boolean) => void;
  setShowGraphSearch: (v: boolean) => void;
  dispatch: Dispatch<AppAction>;
  rows: DisplayRow[];
  pe: PEFile | null;
  currentIndex: number;
  currentFunc: DisasmFunction | null;
  virtualizer: Virtualizer<HTMLDivElement, Element>;
  viewMode: "linear" | "graph";
  graphPan: { x: number; y: number };
  graphZoom: number;
  currentAddress: number;
  comments: Record<number, string>;
  renames: Record<number, string>;
  callStack: AppState["callStack"];
  addressHistory: number[];
  historyIndex: number;
  buildCFGForNav: () => {
    navBlocks: Map<number, BasicBlock>;
    addrToBlock: Map<number, number>;
  } | null;
  formatRangeCopy: (
    range: { start: number; end: number },
    rows: DisplayRow[],
    pe: PEFile | null,
    renames: Record<number, string>,
    comments: Record<number, string>,
  ) => string;
}

export function useDisassemblyKeyboard({
  search,
  parentRef,
  searchInputRef,
  graphSearchInputRef,
  cfgContainerRef,
  navViewStateMapRef,
  highlightedReg,
  setHighlightedReg,
  ctxMenu,
  setCtxMenu,
  selectionRange,
  setSelectionRange,
  setViewMode,
  setRestorePanZoom,
  setEditingComment,
  setRenamingLabel,
  setShowCallPanel,
  setShowXrefPanel,
  setShowDetail,
  setShowGraphSearch,
  dispatch,
  rows,
  pe,
  currentIndex,
  currentFunc,
  virtualizer,
  viewMode,
  graphPan,
  graphZoom,
  currentAddress,
  comments,
  renames,
  callStack,
  addressHistory,
  historyIndex,
  buildCFGForNav,
  formatRangeCopy,
}: UseDisassemblyKeyboardArgs) {
  /**
   * Always the current `handleDecompileToggle`.
   *
   * That callback is declared ~340 lines below this point and depends on
   * `showDecompile`, `instructions`, `decompile` and `viewMode`, none of which
   * are in handleKeyDown's dependency array. Closing over it directly meant D
   * kept re-running the OPEN branch: pressing it set showDecompile true, but
   * handleKeyDown's deps were unchanged, so it held the stale closure where
   * showDecompile was still false and the panel could not be closed.
   *
   * Adding the callback to handleKeyDown's deps is not possible — it is a
   * `const` declared later, so the dependency array would hit its temporal dead
   * zone — and hoisting it would drag `useDecompileTabs` and its own
   * dependencies above this point, reordering hooks in a component with no test
   * coverage. A ref keeps the indirection local.
   */
  const decompileToggleRef = useRef<() => void>(() => {});

  // Keyboard navigation
  const handleKeyDown = useCallback(
    (e: ReactKeyboardEvent) => {
      if (search.showSearch && e.key === "Escape") {
        search.resetSearch();
        parentRef.current?.focus();
        return;
      }

      if (e.key === "Escape") {
        if (highlightedReg) {
          setHighlightedReg(null);
          return;
        }
        if (ctxMenu) {
          setCtxMenu(null);
          return;
        }
        if (selectionRange) {
          setSelectionRange(null);
          return;
        }
        // Pop breadcrumb if available, else navigate back
        if (callStack.length > 0) {
          const last = callStack[callStack.length - 1];
          if (last.viewSnapshot) {
            setViewMode(last.viewSnapshot.viewMode);
            setRestorePanZoom({
              pan: last.viewSnapshot.graphPan,
              zoom: last.viewSnapshot.graphZoom,
            });
          }
          dispatch({ type: "SET_ADDRESS", address: last.address });
          dispatch({ type: "POP_CALL_STACK", index: callStack.length - 1 });
          return;
        }
        // NAV_BACK: restore view state if saved
        {
          const destAddr = historyIndex > 0 ? addressHistory[historyIndex - 1] : undefined;
          if (destAddr !== undefined) {
            const saved = navViewStateMapRef.current.get(destAddr);
            if (saved) {
              setViewMode(saved.viewMode);
              setRestorePanZoom({ pan: saved.graphPan, zoom: saved.graphZoom });
            }
          }
        }
        dispatch({ type: "NAV_BACK" });
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key === "c") {
        if (selectionRange) {
          e.preventDefault();
          navigator.clipboard.writeText(
            formatRangeCopy(selectionRange, rows, pe, renames, comments),
          );
          return;
        }
      }

      if (
        document.activeElement?.tagName === "INPUT" ||
        document.activeElement?.tagName === "TEXTAREA"
      )
        return;

      // Space handled by window-level effect

      // 0: zoom-to-fit in graph mode
      if (e.key === "0" && viewMode === "graph") {
        e.preventDefault();
        const el = cfgContainerRef.current;
        if (el) {
          // CFGView sets __zoomToFit on the first child with overflow-hidden
          const cfgEl = el.querySelector(".cfg-container") as any;
          if (cfgEl?.__zoomToFit) cfgEl.__zoomToFit();
        }
        return;
      }

      if (e.key === ";") {
        e.preventDefault();
        const existing = comments[currentAddress] ?? "";
        setEditingComment({ address: currentAddress, value: existing });
        return;
      }

      if (e.key === "x" || e.key === "X") {
        e.preventDefault();
        setShowCallPanel((v) => !v);
        return;
      }

      if (e.key === "r" || e.key === "R") {
        e.preventDefault();
        setShowXrefPanel((v) => !v);
        return;
      }

      if (e.key === "i" || e.key === "I") {
        e.preventDefault();
        setShowDetail((v) => !v);
        return;
      }

      if (e.key === "d" || e.key === "D") {
        e.preventDefault();
        decompileToggleRef.current();
        return;
      }

      if (e.key === "b" || e.key === "B") {
        e.preventDefault();
        dispatch({ type: "TOGGLE_BOOKMARK" });
        return;
      }

      // Enter: follow branch target of current instruction
      if (e.key === "Enter") {
        e.preventDefault();
        const curRow = rows[currentIndex];
        if (curRow && curRow.kind === "insn") {
          const target = parseBranchTarget(curRow.insn.mnemonic, curRow.insn.opStr);
          if (target !== null) {
            const vs = { viewMode, graphPan, graphZoom };
            if (currentFunc) {
              dispatch({
                type: "PUSH_CALL_STACK",
                address: currentAddress,
                name: getDisplayName(currentFunc, renames),
                viewSnapshot: vs,
              });
            }
            navViewStateMapRef.current.set(currentAddress, vs);

            // Auto-switch to linear when navigating to non-executable section from graph
            if (viewMode === "graph" && pe) {
              const rva = target - pe.optionalHeader.imageBase;
              const sec = pe.sections.find(
                (s) => rva >= s.virtualAddress && rva < s.virtualAddress + s.virtualSize,
              );
              if (sec && !(sec.characteristics & 0x20000000)) {
                setViewMode("linear");
              }
            }

            dispatch({ type: "SET_ADDRESS", address: target });
          }
        }
        return;
      }

      // N: rename function containing current address
      if (e.key === "n" || e.key === "N") {
        e.preventDefault();
        if (currentFunc) {
          setRenamingLabel({
            address: currentFunc.address,
            value: getDisplayName(currentFunc, renames),
          });
          // Scroll to the function label
          const labelIdx = rows.findIndex(
            (r) => r.kind === "label" && r.fn.address === currentFunc.address,
          );
          if (labelIdx >= 0) {
            virtualizer.scrollToIndex(labelIdx, { align: "center" });
          }
        }
        return;
      }

      if (e.key === "g" || e.key === "G") {
        e.preventDefault();
        const addrInput = document.querySelector<HTMLInputElement>('input[placeholder*="address"]');
        addrInput?.focus();
        return;
      }

      if ((e.ctrlKey || e.metaKey) && e.key === "f") {
        e.preventDefault();
        if (viewMode === "graph") {
          setShowGraphSearch(true);
          setTimeout(() => graphSearchInputRef.current?.focus(), 0);
        } else {
          search.setShowSearch(true);
          setTimeout(() => searchInputRef.current?.focus(), 0);
        }
        return;
      }

      if (e.key === "/") {
        e.preventDefault();
        if (viewMode === "graph") {
          setShowGraphSearch(true);
          setTimeout(() => graphSearchInputRef.current?.focus(), 0);
        } else {
          search.setShowSearch(true);
          setTimeout(() => searchInputRef.current?.focus(), 0);
        }
        return;
      }

      // Graph mode arrow key navigation
      if (
        viewMode === "graph" &&
        (e.key === "ArrowDown" || e.key === "ArrowUp" || e.key === "Tab")
      ) {
        e.preventDefault();
        // Build block data from CFG
        const cfg = buildCFGForNav();
        if (!cfg) return;
        const { navBlocks, addrToBlock } = cfg;
        const curBlockId = addrToBlock.get(currentAddress);
        if (curBlockId === undefined) return;
        const curBlock = navBlocks.get(curBlockId);
        if (!curBlock) return;

        if (e.key === "Tab") {
          // Cycle through successor blocks
          if (curBlock.succs.length > 0) {
            const succBlock = navBlocks.get(curBlock.succs[0]);
            if (succBlock) dispatch({ type: "SET_ADDRESS", address: succBlock.startAddr });
          }
          return;
        }

        const insnIdx = curBlock.insns.findIndex(
          (insn: Instruction) => insn.address === currentAddress,
        );
        if (e.key === "ArrowDown") {
          if (insnIdx < curBlock.insns.length - 1) {
            dispatch({ type: "SET_ADDRESS", address: curBlock.insns[insnIdx + 1].address });
          } else if (curBlock.succs.length > 0) {
            // Move to fallthrough successor (last in succs for conditional, first otherwise)
            const ftIdx = curBlock.succs.length > 1 ? curBlock.succs.length - 1 : 0;
            const succBlock = navBlocks.get(curBlock.succs[ftIdx]);
            if (succBlock) dispatch({ type: "SET_ADDRESS", address: succBlock.startAddr });
          }
        } else if (e.key === "ArrowUp") {
          if (insnIdx > 0) {
            dispatch({ type: "SET_ADDRESS", address: curBlock.insns[insnIdx - 1].address });
          } else if (curBlock.preds.length > 0) {
            const predBlock = navBlocks.get(curBlock.preds[0]);
            if (predBlock)
              dispatch({
                type: "SET_ADDRESS",
                address: predBlock.insns[predBlock.insns.length - 1].address,
              });
          }
        }
        return;
      }

      const scrollAmount = e.key === "PageUp" || e.key === "PageDown" ? 40 : 1;

      if (e.key === "ArrowDown" || e.key === "PageDown") {
        e.preventDefault();
        const newIdx = Math.min(currentIndex + scrollAmount, rows.length - 1);
        const addr = rowAddress(rows[newIdx]);
        if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
      }

      if (e.key === "ArrowUp" || e.key === "PageUp") {
        e.preventDefault();
        const newIdx = Math.max(currentIndex - scrollAmount, 0);
        const addr = rowAddress(rows[newIdx]);
        if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
      }
    },
    [
      currentIndex,
      rows,
      dispatch,
      search,
      ctxMenu,
      currentAddress,
      comments,
      selectionRange,
      renames,
      pe,
      currentFunc,
      virtualizer,
      callStack,
      viewMode,
      graphPan,
      graphZoom,
      addressHistory,
      historyIndex,
      // Read by the Escape branch and previously absent: the same shape of
      // omission as peek-a-bin-ehv.
      highlightedReg,
      // Stable across renders: React guarantees useState setter identity, and
      // useRef returns the same object every render. Adding them cannot change
      // how often this callback is rebuilt.
      setHighlightedReg,
      setCtxMenu,
      setSelectionRange,
      setViewMode,
      setRestorePanZoom,
      setEditingComment,
      setRenamingLabel,
      setShowCallPanel,
      setShowXrefPanel,
      setShowDetail,
      setShowGraphSearch,
      parentRef,
      searchInputRef,
      graphSearchInputRef,
      cfgContainerRef,
      navViewStateMapRef,
      // formatRangeCopy is a module-level function declaration, so also stable.
      formatRangeCopy,
      // buildCFGForNav is memoised on [currentFunc, instructions, typedXrefMap];
      // only the latter two are new identity sources here, and the graph-mode
      // arrow/Tab navigation genuinely needs the current one.
      buildCFGForNav,
    ],
  );

  return { decompileToggleRef, handleKeyDown };
}
