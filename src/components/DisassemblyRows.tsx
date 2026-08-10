// Virtualized row renderers extracted verbatim from DisassemblyView's
// `virtualizer.getVirtualItems().map(...)` body. These are plain function
// components — deliberately no hooks and no React.memo, so each one re-renders
// exactly when the inline JSX used to.
import type { Dispatch } from "react";
import { focusOnMount } from "./focusOnMount";
import { getDisplayName } from "../hooks/usePEFile";
import type { AppAction } from "../hooks/usePEFile";
import type { DisplayRow } from "../hooks/useDisassemblyRows";
import type { Instruction, DisasmFunction, Xref, DataItem } from "../disasm/types";
import { parseOperandTargets } from "../disasm/operands";
import { MNEMONIC_HINTS } from "../disasm/mnemonics";
import type { FunctionSignature } from "../disasm/signatures";
import type { PEFile } from "../pe/types";
import { ColoredOperand, mnemonicClass } from "./shared";

export function SeparatorRow({ index, start, height }: {
  index: number;
  start: number;
  height: number;
}) {
  return (
    <div
      data-index={index}
      className="flex items-center"
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        width: "100%",
        height: `${height}px`,
        transform: `translateY(${start}px)`,
        padding: "0 var(--row-px)",
      }}
    >
      <div className="w-full border-t border-gray-700/20" style={{ margin: "0 1rem" }} />
    </div>
  );
}

export function DataRow({
  item,
  index,
  start,
  rowHeight,
  addrWidth,
  currentAddress,
  bookmarkSet,
  showBytes,
  comments,
  onAddressClick,
  onRowClick,
}: {
  item: DataItem;
  index: number;
  start: number;
  rowHeight: number;
  addrWidth: number;
  currentAddress: number;
  bookmarkSet: Set<number>;
  showBytes: boolean;
  comments: Record<number, string>;
  onAddressClick: (address: number) => void;
  onRowClick: (address: number) => void;
}) {
  const addrHex = item.address.toString(16).toUpperCase().padStart(addrWidth, "0");
  const bytesHex = Array.from(item.bytes.slice(0, 8)).map(b => b.toString(16).padStart(2, "0")).join(" ");
  const isCurrentAddr = item.address === currentAddress;
  const isBookmarked = bookmarkSet.has(item.address);

  let directiveStr: React.ReactNode;
  let commentStr: React.ReactNode = null;

  if (item.directive === "dup") {
    directiveStr = <span className="text-gray-500">{item.dupCount} dup({item.dupByte === 0 ? "0" : `0x${item.dupByte!.toString(16)}`})</span>;
  } else if (item.directive === "db" && item.stringValue != null) {
    const escaped = item.stringValue.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n").replace(/\r/g, "\\r").replace(/\t/g, "\\t");
    directiveStr = <span className="text-green-400">"{escaped}", 0</span>;
    if (item.stringType) commentStr = <span className="text-gray-500 ml-4">; {item.stringType}</span>;
  } else if ((item.directive === "dd" || item.directive === "dq") && item.pointerTarget != null) {
    directiveStr = (
      <button
        type="button"
        tabIndex={-1}
        className="inline text-blue-400 cursor-pointer hover:underline"
        onClick={(e) => { e.stopPropagation(); onAddressClick(item.pointerTarget!); }}
      >
        0x{item.pointerTarget.toString(16).toUpperCase()}
      </button>
    );
    if (item.pointerLabel) commentStr = <span className="text-gray-500 ml-4">; {item.pointerLabel}</span>;
  } else {
    const hexStr = Array.from(item.bytes).map(b => b.toString(16).toUpperCase().padStart(2, "0") + "h").join(", ");
    directiveStr = <span>{hexStr}</span>;
    const ascii = Array.from(item.bytes).map(b => b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : ".").join("");
    commentStr = <span className="text-gray-500 ml-4">; {ascii}</span>;
  }

  const userComment = comments[item.address];

  return (
    // Data row wraps its own pointer-target button — same constraint as
    // the instruction row below.
    // biome-ignore lint/a11y/noStaticElementInteractions: container of controls, not a control
    // biome-ignore lint/a11y/useKeyWithClickEvents: container of controls, not a control
    <div
      data-index={index}
      className={`disasm-row group disasm-grid-data${!showBytes ? " hide-bytes" : ""} ${isCurrentAddr ? "bg-blue-900/30" : ""}`}
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        width: "100%",
        height: `${rowHeight}px`,
        transform: `translateY(${start}px)`,
        padding: `0 var(--row-px)`,
      }}
      onClick={() => onRowClick(item.address)}
    >
      <span className="text-center">
        {isBookmarked && <span className="text-yellow-300">★</span>}
      </span>
      <span className="disasm-address">{addrHex}</span>
      {showBytes && <span className="disasm-bytes truncate">{bytesHex}</span>}
      <span className="text-cyan-400">{item.directive}</span>
      <span>{directiveStr}</span>
      <span className="truncate flex items-center gap-1">
        {commentStr}
        {userComment && <span className="disasm-user-comment truncate max-w-xs">; {userComment}</span>}
      </span>
    </div>
  );
}

export function LabelRow({
  fn,
  index,
  start,
  rowHeight,
  renames,
  typedXrefMap,
  bookmarkSet,
  renamingLabel,
  setRenamingLabel,
  dispatch,
  getSigForFunc,
  onShowXrefs,
}: {
  fn: DisasmFunction;
  index: number;
  start: number;
  rowHeight: number;
  renames: Record<number, string>;
  typedXrefMap: Map<number, Xref[]>;
  bookmarkSet: Set<number>;
  renamingLabel: { address: number; value: string } | null;
  setRenamingLabel: (v: { address: number; value: string } | null) => void;
  dispatch: Dispatch<AppAction>;
  getSigForFunc: (fn: DisasmFunction) => FunctionSignature | null;
  onShowXrefs: (address: number) => void;
}) {
  const displayName = getDisplayName(fn, renames);
  const xrefs = typedXrefMap.get(fn.address);
  const xrefCount = xrefs?.length ?? 0;
  const isBookmarked = bookmarkSet.has(fn.address);

  if (renamingLabel && renamingLabel.address === fn.address) {
    return (
      <div
        data-index={index}
        className="flex items-center func-label text-[11px] font-mono border-t border-gray-700/50"
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          width: "100%",
          height: `${rowHeight}px`,
          transform: `translateY(${start}px)`,
          paddingTop: "var(--label-pad-top)",
          paddingLeft: "var(--row-px)",
          paddingRight: "var(--row-px)",
        }}
      >
        <span className="mr-1">; ────</span>
        <input
          ref={focusOnMount}
          className="bg-gray-800 border border-blue-500 rounded px-1 text-yellow-300 text-[11px] font-mono outline-none w-48"
          value={renamingLabel.value}
          onChange={(e) => setRenamingLabel({ ...renamingLabel, value: e.target.value })}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              const val = renamingLabel.value.trim();
              if (val && val !== fn.name) {
                dispatch({ type: "RENAME_FUNCTION", address: renamingLabel.address, name: val });
              } else if (!val || val === fn.name) {
                dispatch({ type: "CLEAR_RENAME", address: renamingLabel.address });
              }
              setRenamingLabel(null);
            }
            if (e.key === "Escape") setRenamingLabel(null);
            e.stopPropagation();
          }}
          onBlur={() => setRenamingLabel(null)}
        />
        <span className="ml-1">────</span>
      </div>
    );
  }

  return (
    // Double-click-to-rename on a row that contains its own xref button.
    // Rename is also on the context menu, which is keyboard-operable.
    // biome-ignore lint/a11y/noStaticElementInteractions: container of controls, not a control
    <div
      data-index={index}
      className="flex items-center func-label text-[11px] font-mono border-t border-gray-700/50"
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        width: "100%",
        height: `${rowHeight}px`,
        transform: `translateY(${start}px)`,
        paddingTop: "var(--label-pad-top)",
        paddingLeft: "var(--row-px)",
        paddingRight: "var(--row-px)",
      }}
      onDoubleClick={() => setRenamingLabel({ address: fn.address, value: displayName })}
    >
      {isBookmarked && <span className="text-yellow-300 mr-1">★</span>}
      <span>; ──── {displayName}{(() => {
        const sig = getSigForFunc(fn);
        return sig ? ` (${sig.convention}, ${sig.paramCount} param${sig.paramCount !== 1 ? "s" : ""})` : "";
      })()} ────</span>
      {xrefCount > 0 && (() => {
        const counts: Record<string, number> = {};
        for (const x of xrefs!) {
          counts[x.type] = (counts[x.type] ?? 0) + 1;
        }
        const parts: string[] = [];
        if (counts.call) parts.push(`${counts.call} call${counts.call > 1 ? "s" : ""}`);
        if (counts.jmp) parts.push(`${counts.jmp} jmp`);
        if (counts.branch) parts.push(`${counts.branch} branch`);
        if (counts.data) parts.push(`${counts.data} data`);
        const label = parts.length > 0 ? parts.join(", ") : `${xrefCount} xref${xrefCount !== 1 ? "s" : ""}`;
        return (
          <button
            type="button"
            tabIndex={-1}
            className="inline ml-2 text-gray-500 hover:text-blue-400 cursor-pointer"
            onClick={(e) => {
              e.stopPropagation();
              onShowXrefs(fn.address);
            }}
          >
            ({label})
          </button>
        );
      })()}
    </div>
  );
}

export function InsnRow({
  row,
  index,
  start,
  rowHeight,
  addrWidth,
  pe,
  iatMap,
  functions,
  renames,
  comments,
  currentAddress,
  currentFunc,
  currentIndex,
  funcMap,
  typedXrefMap,
  bookmarkSet,
  loopHeaders,
  loopBodyMap,
  searchMatches,
  searchMatchIdx,
  isSelected,
  insnFilter,
  matchesFilter,
  showBytes,
  copiedAddr,
  highlightRegs,
  lastClickedRow,
  editingComment,
  setEditingComment,
  setSelectionRange,
  setLastClickedRow,
  onShowXrefs,
  onAddressClick,
  onDoubleClickAddr,
  onDoubleClickInsn,
  onRegClick,
  onContextMenu,
  onRowClick,
  dispatch,
}: {
  row: Extract<DisplayRow, { kind: "insn" }>;
  index: number;
  start: number;
  rowHeight: number;
  addrWidth: number;
  pe: PEFile;
  iatMap: Map<number, { lib: string; func: string }>;
  functions: DisasmFunction[];
  renames: Record<number, string>;
  comments: Record<number, string>;
  currentAddress: number;
  currentFunc: DisasmFunction | null;
  currentIndex: number;
  funcMap: Map<number, DisasmFunction>;
  typedXrefMap: Map<number, Xref[]>;
  bookmarkSet: Set<number>;
  loopHeaders: Map<number, number>;
  loopBodyMap: Map<number, number>;
  searchMatches: number[];
  searchMatchIdx: number;
  isSelected: (rowIndex: number) => boolean;
  insnFilter: string;
  matchesFilter: (row: DisplayRow) => boolean;
  showBytes: boolean;
  copiedAddr: number | null;
  highlightRegs: Set<string> | null;
  lastClickedRow: number | null;
  editingComment: { address: number; value: string } | null;
  setEditingComment: (v: { address: number; value: string } | null) => void;
  setSelectionRange: (v: { start: number; end: number } | null) => void;
  setLastClickedRow: (v: number | null) => void;
  onShowXrefs: (address: number) => void;
  onAddressClick: (address: number) => void;
  onDoubleClickAddr: (address: number) => void;
  onDoubleClickInsn: (insn: Instruction) => void;
  onRegClick: (regName: string) => void;
  onContextMenu: (e: React.MouseEvent, insn: Instruction) => void;
  onRowClick: (address: number) => void;
  dispatch: Dispatch<AppAction>;
}) {
  const insn = row.insn;
  const bytesHex = Array.from(insn.bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join(" ");

  const isBookmarked = bookmarkSet.has(insn.address);
  const isLoopHeader = loopHeaders.has(insn.address);
  const loopDepth = loopHeaders.get(insn.address);
  const bodyDepth = loopBodyMap.get(insn.address);
  const isCurrentAddr = insn.address === currentAddress;
  const isSearchMatch =
    searchMatches.length > 0 &&
    searchMatchIdx >= 0 &&
    searchMatches[searchMatchIdx] === index;
  const rowSelected = isSelected(index);
  const isDimmed = insnFilter !== "all" && !matchesFilter(row);
  const isGapFill = insn.source === 'gap-fill';

  const operandTargets = pe ? parseOperandTargets(
    insn,
    pe.optionalHeader.imageBase,
    pe.optionalHeader.imageBase + pe.optionalHeader.sizeOfImage,
    iatMap,
  ) : [];

  // Build tooltip data for operand addresses
  let tooltipData: Map<number, string> | undefined;
  if (operandTargets.length > 0 && pe) {
    for (const t of operandTargets) {
      const addr = t.address;
      // Check IAT (imports)
      const iat = iatMap.get(addr);
      if (iat) {
        if (!tooltipData) tooltipData = new Map();
        tooltipData.set(addr, `Import: ${iat.lib}!${iat.func}`);
        continue;
      }
      // Check strings
      const str = pe.strings?.get(addr);
      if (str) {
        if (!tooltipData) tooltipData = new Map();
        const preview = str.length > 60 ? str.slice(0, 60) + "..." : str;
        tooltipData.set(addr, `"${preview}"`);
        continue;
      }
      // Check functions
      const fn = functions.find(f => f.address === addr);
      if (fn) {
        if (!tooltipData) tooltipData = new Map();
        tooltipData.set(addr, `Function: ${getDisplayName(fn, renames)}`);
        continue;
      }
      // Section lookup
      if (pe.sections) {
        const rva = addr - pe.optionalHeader.imageBase;
        for (const sec of pe.sections) {
          if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
            if (!tooltipData) tooltipData = new Map();
            tooltipData.set(addr, `${sec.name} +0x${(rva - sec.virtualAddress).toString(16)}`);
            break;
          }
        }
      }
    }
  }

  // Loop border styling: header takes priority, then body depth
  let borderStyle: string | undefined;
  if (isLoopHeader) {
    borderStyle = "2px solid #eab308"; // gold
  } else if (bodyDepth !== undefined) {
    if (bodyDepth >= 3) borderStyle = "2px solid rgba(239, 68, 68, 0.3)"; // red-500/30
    else if (bodyDepth === 2) borderStyle = "2px solid rgba(249, 115, 22, 0.3)"; // orange-500/30
    else borderStyle = "2px solid rgba(234, 179, 8, 0.3)"; // yellow-500/30
  }

  return (
    // The row already contains its own buttons (address, mnemonic, operand
    // targets), so it cannot become a <button> (no nesting) and role="button"
    // would be invalid ARIA for the same reason. Selecting a row from the
    // keyboard needs a roving-tabindex grid model, tracked separately.
    // biome-ignore lint/a11y/noStaticElementInteractions: container of controls, not a control
    // biome-ignore lint/a11y/useKeyWithClickEvents: container of controls, not a control
    <div
      data-index={index}
      className={`disasm-row group disasm-grid${!showBytes ? " hide-bytes" : ""} ${
        isSearchMatch
          ? "bg-yellow-900/30"
          : rowSelected
            ? "bg-indigo-900/25"
            : isCurrentAddr
              ? "bg-blue-900/30"
              : ""
      } ${isDimmed ? "opacity-30" : isGapFill ? "opacity-50" : ""}`}
      style={{
        position: "absolute",
        top: 0,
        left: 0,
        width: "100%",
        height: `${rowHeight}px`,
        transform: `translateY(${start}px)`,
        borderLeft: borderStyle,
        padding: `0 var(--row-px)`,
      }}
      title={isLoopHeader ? `Loop header (depth ${loopDepth})` : bodyDepth !== undefined ? `Loop body (depth ${bodyDepth})` : undefined}
      onContextMenu={(e) => onContextMenu(e, insn)}
      onClick={(e) => {
        if (e.shiftKey) {
          e.preventDefault();
          const anchor = lastClickedRow ?? currentIndex;
          setSelectionRange({ start: anchor, end: index });
        } else {
          setSelectionRange(null);
          setLastClickedRow(index);
          onRowClick(insn.address);
        }
      }}
    >
      <span className="text-right pr-1 flex items-center justify-end gap-0.5">
        {isBookmarked && <span className="text-yellow-300">★</span>}
        {(() => {
          const xrefs = typedXrefMap.get(insn.address);
          if (!xrefs || xrefs.length === 0 || funcMap.has(insn.address)) return null;
          return (
            <button
              type="button"
              tabIndex={-1}
              className="inline text-gray-600 hover:text-blue-400 cursor-pointer text-[9px]"
              onClick={(e) => {
                e.stopPropagation();
                onShowXrefs(insn.address);
              }}
            >
              ×{xrefs.length}
            </button>
          );
        })()}
      </span>
      <button
        type="button"
        tabIndex={-1}
        className={`disasm-address cursor-pointer hover:text-blue-400 text-left ${
          copiedAddr === insn.address ? "text-green-400" : ""
        }`}
        onClick={() => onAddressClick(insn.address)}
        onDoubleClick={() => onDoubleClickAddr(insn.address)}
      >
        {insn.address
          .toString(16)
          .toUpperCase()
          .padStart(addrWidth, "0")}
      </button>
      {showBytes && (
        <span className="disasm-bytes truncate">
          {bytesHex}
        </span>
      )}
      <button
        type="button"
        tabIndex={-1}
        className={`disasm-mnemonic text-left ${mnemonicClass(insn.mnemonic)}`}
        title={MNEMONIC_HINTS[insn.mnemonic]}
        onDoubleClick={() => onDoubleClickInsn(insn)}
      >
        {insn.mnemonic}
      </button>
      {/* biome-ignore lint/a11y/noStaticElementInteractions: wraps the
          operand target buttons, so it cannot itself be a button. The
          double-click opens instruction detail, which is also on the
          context menu. */}
      <span
        className="disasm-operands overflow-hidden"
        onDoubleClick={() => onDoubleClickInsn(insn)}
      >
        <ColoredOperand
          opStr={insn.opStr}
          targets={operandTargets}
          onNavigate={onAddressClick}
          highlightRegs={highlightRegs}
          onRegClick={onRegClick}
          tooltipData={tooltipData}
        />
      </span>
      <span className="truncate flex items-center gap-1">
        {insn.comment ? (
          <span
            className="disasm-comment truncate max-w-xs"
            title={insn.comment.length > 60 ? insn.comment : undefined}
          >
            ; {insn.comment}
          </span>
        ) : insn.mnemonic === 'jmp' && (() => {
          for (const t of operandTargets) {
            const targetFn = funcMap.get(t.address);
            if (targetFn && targetFn.address !== currentFunc?.address) {
              return (
                <span className="disasm-comment truncate max-w-xs">
                  ; tail call → {getDisplayName(targetFn, renames)}
                </span>
              );
            }
          }
          return null;
        })()}
        {editingComment && editingComment.address === insn.address ? (
          <span className="shrink-0">
            <textarea
              ref={focusOnMount}
              rows={1}
              className="bg-gray-900/80 border border-blue-500 ring-1 ring-blue-500/50 rounded px-1.5 py-0.5 text-[#6ee7b7] text-xs font-mono outline-none w-64 resize-none align-middle"
              placeholder="Add comment..."
              value={editingComment.value}
              onChange={(e) => setEditingComment({ ...editingComment, value: e.target.value })}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  const val = editingComment.value.trim();
                  if (val) {
                    dispatch({ type: "SET_COMMENT", address: editingComment.address, text: val });
                  } else {
                    dispatch({ type: "DELETE_COMMENT", address: editingComment.address });
                  }
                  setEditingComment(null);
                }
                if (e.key === "Escape") setEditingComment(null);
                e.stopPropagation();
              }}
              onBlur={() => setEditingComment(null)}
            />
          </span>
        ) : comments[insn.address] ? (
          <span
            className="disasm-user-comment truncate max-w-xs"
            title={comments[insn.address]}
          >
            ; {comments[insn.address].includes("\n") ? comments[insn.address].split("\n")[0] + " [...]" : comments[insn.address]}
          </span>
        ) : isCurrentAddr && !insn.comment ? (
          <span className="text-gray-600 text-[10px] opacity-0 group-hover:opacity-100 transition-opacity select-none">
            press ; to comment
          </span>
        ) : null}
      </span>
    </div>
  );
}
