import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { DecompileAdmissions } from "../disasm/decompile/emit";
import type { DecompileTab, HighLevelEngine } from "../hooks/decompileTabsState";
import {
  ADMISSION_SEPARATOR,
  admissionSummary,
  codeWithComments,
  formatComment,
} from "../hooks/decompileTabsState";
import { useDismissOnOutsideClick } from "../hooks/useDismissOnOutsideClick";
import type { SectionHeader } from "../pe/types";
import { copyText } from "../utils/clipboard";
import { type AddressKind, classifyAddress } from "./classifyAddress";
import {
  declaredNamesOf,
  identKeyFor,
  renameableIdentClass,
  validateVarName,
} from "./decompileIdent";
import { focusOnMount } from "./focusOnMount";

// ── Syntax Highlighting ──

interface Token {
  text: string;
  cls: string;
  /**
   * `"hex"` for a `0x…` literal. The tokenizer takes one line and no image, so
   * it can only SAY a token is a hex number; whether that number is an address
   * a reader can be sent to is decided in the `lines` memo, which has the
   * section table, and recorded in `link`.
   *
   * `"ident"` for a plain identifier — not a keyword, a type, a `sub_`/`loc_`/
   * `struct_` link or `__asm`. Rendered with `data-ident` so a right-click can
   * ask what was under the pointer; whether it is RENAMEABLE is decided at the
   * click by `renameableIdentClass`, not here (peek-a-bin-5b6q.7).
   */
  kind?: "hex" | "ident";
  /** Set at render time on a hex literal that lands inside a section. */
  link?: AddressKind;
}

/** A `sub_<HEX>` identifier, as the emitter and `funcMap` spell it. */
const SUB_NAME = /^sub_([0-9a-fA-F]+)$/;
/** A bare hex literal, as the emitter spells a constant. */
const HEX_LITERAL = /^0x([0-9a-fA-F]+)$/;

/** The link styling every clickable token carries, `sub_`/`loc_`/`struct_`/constant alike. */
const LINK_CLS = "underline cursor-pointer hover:opacity-80";

const KEYWORDS = new Set([
  "if",
  "else",
  "while",
  "do",
  "for",
  "switch",
  "case",
  "default",
  "break",
  "continue",
  "return",
  "goto",
  "void",
  "struct",
]);

const TYPES = new Set([
  "int",
  "int32_t",
  "int64_t",
  "uint8_t",
  "uint16_t",
  "uint32_t",
  "uint64_t",
  "char",
  "short",
  "long",
  "unsigned",
  "signed",
  "void",
  "bool",
]);

function tokenizeLine(line: string): Token[] {
  const tokens: Token[] = [];
  // Match: strings, comments, hex numbers, decimal numbers, identifiers, operators, whitespace
  const re =
    /("(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')|(\/\/.*$)|(\/\*[\s\S]*?\*\/)|(\b0x[0-9a-fA-F]+\b)|(\b\d+\b)|(\b[a-zA-Z_]\w*\b)|(\s+)|([^\s\w])/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(line)) !== null) {
    const text = m[0];
    if (m[1] || m[2]) {
      // String literal
      tokens.push({ text, cls: "dc-string" });
    } else if (m[3] || m[4]) {
      // Comment
      tokens.push({ text, cls: "dc-comment italic" });
    } else if (m[5]) {
      // Hex number. Tagged so the render pass can ask whether it is an address.
      tokens.push({ text, cls: "dc-number", kind: "hex" });
    } else if (m[6]) {
      // Decimal number
      tokens.push({ text, cls: "dc-number" });
    } else if (m[7]) {
      // Identifier
      if (KEYWORDS.has(text)) {
        tokens.push({ text, cls: "dc-keyword font-semibold" });
      } else if (TYPES.has(text)) {
        tokens.push({ text, cls: "dc-type" });
      } else if (text.startsWith("sub_") || text.startsWith("loc_") || text.startsWith("struct_")) {
        // All three are styled as links and all three DO something — `sub_`
        // navigates the app to that address, `loc_` scrolls this panel to the
        // label, `struct_` scrolls it to the typedef. `sub_` and `loc_` were
        // styled identically before either of them worked, which made the
        // `loc_` half a dead affordance; the alternative was to stop styling it,
        // and following the label is the thing a reader actually wants. This
        // function takes no line map and cannot ask whether a particular label
        // or typedef exists, so resolvability is checked at the click instead.
        tokens.push({ text, cls: `dc-type ${LINK_CLS}` });
      } else if (text === "__asm") {
        tokens.push({ text, cls: "dc-comment italic" });
      } else {
        tokens.push({ text, cls: "", kind: "ident" });
      }
    } else if (m[8]) {
      // Whitespace
      tokens.push({ text, cls: "" });
    } else {
      // Operators / punctuation
      tokens.push({ text, cls: "text-theme-secondary" });
    }
  }
  return tokens;
}

// ── Tab labels ──

const TAB_LABELS: { key: DecompileTab; label: string }[] = [
  { key: "low", label: "Low Level" },
  { key: "high", label: "High Level" },
  { key: "ai", label: "AI" },
];

// ── Context menu state ──

interface CtxMenuState {
  x: number;
  y: number;
  lineNum: number;
  /**
   * The line's instruction address, or undefined on a line the map does not
   * cover (a typedef, a declaration). The comment and Copy-address entries
   * need one; the rename entry does not, which is why the menu opens without.
   */
  address?: number;
  /**
   * The rename target under the pointer: the identifier as DISPLAYED and the
   * annotation KEY it maps back to (`identKeyFor`). Set only when the key is a
   * stable class and a rename callback exists.
   */
  rename?: { displayed: string; key: string };
}

/** The inline rename editor, mounted at the menu's position. */
interface RenameVarState {
  x: number;
  y: number;
  key: string;
  displayed: string;
  value: string;
  /** `validateVarName`'s refusal for the current value, shown under the box. */
  problem: string | null;
}

// ── Component ──

interface DecompileViewProps {
  code: string;
  loading?: boolean;
  error?: string;
  activeTab: DecompileTab;
  onTabChange: (tab: DecompileTab) => void;
  highLevelEngine?: HighLevelEngine;
  aiMode?: "enhance" | "explain" | null;
  onEnhance?: () => void;
  onExplain?: () => void;
  onCancelAI?: () => void;
  onNavigate?: (addr: number) => void;
  /**
   * Where a clicked constant that lands in a NON-code section goes: the hex
   * view, which follows `currentAddress`. Kept apart from `onNavigate` because
   * the two land on different tabs, and a panel mounted without it simply
   * renders data constants as plain numbers.
   */
  onNavigateData?: (addr: number) => void;
  /**
   * The image a constant is classified against — `classifyAddress` needs all
   * three, and a panel given none renders every constant as a plain number.
   * `sections` is the parsed table by reference, so the `lines` memo is stable
   * across renders.
   */
  sections?: readonly SectionHeader[];
  imageBase?: number;
  sizeOfImage?: number;
  /**
   * The hover text for a `sub_<HEX>` token, asked by address at render time —
   * `DisassemblyView` answers from `funcMap` and the same cached
   * `getSigForFunc` the function-label rows read, spelled by
   * `formatSignature`. `undefined` means "nothing to say" and no `title` is set.
   */
  subTitle?: (addr: number) => string | undefined;
  onClose: () => void;
  highlightLines?: Set<number>;
  onLineClick?: (lineNum: number) => void;
  syncDisabled?: boolean;
  scrollSyncEnabled?: boolean;
  onScrollSyncToggle?: () => void;
  /**
   * Where `code` admits a gap, as line indices (see `DecompileAdmissions`).
   * Rendered as a header line with one button per kind, each scrolling to the
   * first site. Only the Low Level tab's state ever carries one — that is a
   * property of `TabState`, not a check here — so the line is absent on the
   * High Level and AI tabs and on a function recovered whole.
   */
  admissions?: DecompileAdmissions;
  // Comment support
  comments?: Record<number, string>;
  lineMap?: Map<number, number>;
  editingComment?: { address: number; value: string } | null;
  onEditComment?: (ec: { address: number; value: string } | null) => void;
  onCommitComment?: (address: number, text: string) => void;
  onDeleteComment?: (address: number) => void;
  /**
   * THIS function's variable renames, `generated name → new name`
   * (`state.varRenames[funcAddr]`), for the reverse lookup a right-click on a
   * renamed token needs and for the "Reset name" entry. The names themselves
   * are already in `code`: the pipeline applied them (peek-a-bin-5b6q.7).
   */
  varRenames?: Readonly<Record<string, string>>;
  /** `(generated name, new name)` — the menu's "Rename …" commit. Absent: no rename entry. */
  onRenameVar?: (name: string, newName: string) => void;
  /** `(generated name)` — "Reset name", and an Enter on an empty or unchanged box. */
  onClearVarRename?: (name: string) => void;
}

export function DecompileView({
  code,
  loading,
  error,
  activeTab,
  onTabChange,
  highLevelEngine,
  aiMode,
  onEnhance,
  onExplain,
  onCancelAI,
  onNavigate,
  onNavigateData,
  sections,
  imageBase,
  sizeOfImage,
  subTitle,
  onClose,
  highlightLines,
  onLineClick,
  syncDisabled,
  scrollSyncEnabled,
  onScrollSyncToggle,
  admissions,
  comments,
  lineMap,
  editingComment,
  onEditComment,
  onCommitComment,
  onDeleteComment,
  varRenames,
  onRenameVar,
  onClearVarRename,
}: DecompileViewProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const ctxMenuRef = useRef<HTMLDivElement>(null);
  const [ctxMenu, setCtxMenu] = useState<CtxMenuState | null>(null);
  const [renameVar, setRenameVar] = useState<RenameVarState | null>(null);

  /**
   * Every name the C on screen already binds, read off its declaration lines
   * (`declaredNamesOf`), so a rename that would collide is refused with a
   * reason before it is dispatched — the same `validateVarName` the pipeline's
   * `applyUserNames` applies to what it is handed.
   */
  const declaredNames = useMemo(() => declaredNamesOf(code), [code]);

  /**
   * Whether the image was supplied, so a constant CAN be classified. All three
   * or nothing: a base without a size (or the reverse) cannot bound the image.
   */
  const imageKnown = sections !== undefined && imageBase !== undefined && sizeOfImage !== undefined;

  const lines = useMemo(() => {
    if (!code) return [];
    return code.split("\n").map((line, i) => ({
      num: i,
      displayNum: i + 1,
      tokens: tokenizeLine(line).map((tok): Token => {
        if (tok.kind !== "hex" || !imageKnown) return tok;
        // The link class is applied HERE and only for a value inside a
        // section — `0x10` in `var_8 + 0x10` stays a plain number. Same
        // classifier the click asks, so the two cannot disagree.
        const kind = classifyAddress(parseInt(tok.text, 16), sections, imageBase, sizeOfImage);
        return kind === null ? tok : { ...tok, cls: `${tok.cls} ${LINK_CLS}`, link: kind };
      }),
    }));
  }, [code, imageKnown, sections, imageBase, sizeOfImage]);

  /**
   * The one line the comment editor mounts on, or null.
   *
   * `lineMap` is MANY-TO-ONE — several emitted C lines routinely carry one
   * instruction address. Two other places already model it that way:
   * `DisassemblyView` builds an addr → line[] map to feed `highlightLines`, and
   * `emit.ts`'s `placeGotoLabels` says in as many words that "if an address
   * somehow appears twice the earlier copy is the one the jump was structured
   * around". Deciding `isEditing` from `editingComment.address` alone therefore
   * mounted one `<textarea>` per sharing line — N identical edit boxes for one
   * comment, each running `focusOnMount`, so focus landed on the last of them.
   *
   * The LOWEST such line wins: the same tiebreak `placeGotoLabels` takes, and the
   * line the auto-scroll effect below brings into view with `Math.min`, so the
   * editor opens on the line the panel just scrolled to.
   *
   * `syncDisabled` is repeated here rather than inherited from `lineAddr`,
   * because that is what the pre-fix expression got right by accident: on the AI
   * tab the line map numbers a different body, so an editor attributed to a line
   * there would sit on the wrong line.
   */
  const editingLine = useMemo(() => {
    const addr = editingComment?.address;
    if (addr === undefined || syncDisabled || !lineMap) return null;
    let best: number | null = null;
    for (const [line, a] of lineMap) {
      if (a === addr && (best === null || line < best)) best = line;
    }
    return best;
  }, [editingComment, syncDisabled, lineMap]);

  /**
   * Whether Copy can carry the comments: a line map to place them by and a
   * comment store to read, and NOT the AI tab (`syncDisabled`), whose line map
   * numbers a different body — a trailer placed by it would sit on the wrong
   * line, exactly as the on-screen comment would, and the render suppresses
   * that one for the same reason.
   */
  const commentsCopyable = !syncDisabled && lineMap !== undefined && comments !== undefined;

  /**
   * Copy the code, with each commented line's comment as a ` // …` trailer
   * (`codeWithComments`, the leaf — ONE declaration with what the screen
   * shows). Shift-click copies the raw code, the old behaviour. With no
   * comments the two are byte-identical.
   *
   * The string is built BEFORE `copyText` is called, so the write is still
   * inside the user gesture — `utils/clipboard.ts`'s rule.
   */
  const handleCopy = useCallback(
    (e: React.MouseEvent) => {
      const text =
        commentsCopyable && !e.shiftKey && lineMap && comments
          ? codeWithComments(code, lineMap, comments)
          : code;
      void copyText(text);
    },
    [code, commentsCopyable, lineMap, comments],
  );

  /**
   * Where each `loc_<HEX>` label sits, by line number.
   *
   * A `loc_` identifier is NOT an address to navigate to the way `sub_` is: it
   * names a line **inside the function already on screen**, emitted by
   * `placeGotoLabels` as the target of a `goto`. So the useful action is a
   * scroll within this panel, and the target is found in the rendered text
   * rather than through `lineMap` — the label line is right there, and reading
   * it here means the affordance works on the AI and High Level tabs too, where
   * the line map numbers a different body or does not exist at all.
   *
   * First occurrence wins, which costs nothing: a label is emitted once.
   */
  const labelLines = useMemo(() => {
    const at = new Map<string, number>();
    code.split("\n").forEach((line, i) => {
      const m = line.match(/^\s*(loc_[0-9a-fA-F]+):/);
      if (m && !at.has(m[1])) at.set(m[1], i);
    });
    return at;
  }, [code]);

  /**
   * Where each `struct_N` typedef opens, by line number — the `loc_` mechanism
   * applied to the other identifier the emitter mints for something INSIDE the
   * text on screen.
   *
   * `synthesizeStructs` puts every definition the function uses above its
   * header as `struct struct_N {`, and every use of the name below is a field
   * access through it, so the thing a reader wants from a `struct_3` token is
   * the declaration — which line 40 of a 200-line function has scrolled away.
   * Read off the rendered text for the same reason `labelLines` is: the
   * typedef is right there, and it needs no line map.
   *
   * First occurrence wins. A definition is emitted once per function, so a
   * second `struct struct_N {` would be a defect in the emitter and not a
   * choice this map should paper over by preferring it.
   *
   * THE CHEAP HALF ONLY. Renaming a struct or a field here was REFUSED:
   * `struct_N` is a `nextId++` in the worker's registry, reset per file, so a
   * name persisted under `struct_3` lands on a DIFFERENT struct next session
   * and the C would state something false (peek-a-bin-5b6q.8).
   */
  const structLines = useMemo(() => {
    const at = new Map<string, number>();
    code.split("\n").forEach((line, i) => {
      const m = line.match(/^struct (struct_\w+) \{/);
      if (m && !at.has(m[1])) at.set(m[1], i);
    });
    return at;
  }, [code]);

  /**
   * Bring one rendered line into view — the `loc_` label follow, the `struct_`
   * typedef follow and the admissions line's buttons share it, so each names a
   * line by its `data-line` and none knows anything about the others' reason.
   */
  const scrollToLine = useCallback((line: number) => {
    const el = preRef.current?.querySelector(`[data-line="${line}"]`);
    el?.scrollIntoView({ block: "center", behavior: "smooth" });
  }, []);

  /** The admissions line's clauses; empty (so no line) for a whole recovery or no admissions. */
  const admissionParts = useMemo(
    () => (admissions ? admissionSummary(admissions) : []),
    [admissions],
  );

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      const target = e.target as HTMLElement;
      const text = target.textContent;
      if (!text) return;

      // Click on loc_XXXX → scroll to that label, in this panel.
      //
      // THIS BRANCH IS WHY THE `onNavigate` GUARD MOVED. It used to sit at the
      // top of the handler, so a panel mounted without `onNavigate` could not
      // follow a label either — and following a label needs no caller at all.
      const labelLine = labelLines.get(text);
      if (labelLine !== undefined) {
        scrollToLine(labelLine);
        return;
      }

      // Click on struct_N → scroll to its typedef, in this panel. Same shape as
      // the label follow, and for the same reason it sits above the
      // `onNavigate` guard: a typedef is internal to the text on screen.
      const structLine = structLines.get(text);
      if (structLine !== undefined) {
        scrollToLine(structLine);
        return;
      }

      // Click on 0x… → where in the image it lands, if anywhere. The render
      // pass gave the token a link class on the same answer; asked again here
      // rather than read off a `data-` attribute so the two cannot drift.
      // Above the `onNavigate` guard: a data constant needs `onNavigateData`
      // and nothing else.
      const hexMatch = text.match(HEX_LITERAL);
      if (hexMatch) {
        if (!imageKnown) return;
        const value = parseInt(hexMatch[1], 16);
        const kind = classifyAddress(value, sections, imageBase, sizeOfImage);
        if (kind === "code") onNavigate?.(value);
        else if (kind === "data") onNavigateData?.(value);
        return;
      }

      // Click on sub_XXXX → navigate to that address
      if (!onNavigate) return;
      const subMatch = text.match(SUB_NAME);
      if (subMatch) {
        const addr = parseInt(subMatch[1], 16);
        onNavigate(addr);
      }
    },
    [
      onNavigate,
      onNavigateData,
      imageKnown,
      sections,
      imageBase,
      sizeOfImage,
      labelLines,
      structLines,
      scrollToLine,
    ],
  );

  // Auto-scroll to first highlighted line
  useEffect(() => {
    if (!highlightLines || highlightLines.size === 0 || !preRef.current) return;
    const firstLine = Math.min(...highlightLines);
    const lineEl = preRef.current.querySelector(`[data-line="${firstLine}"]`);
    if (lineEl) {
      lineEl.scrollIntoView({ block: "nearest", behavior: "smooth" });
    }
  }, [highlightLines]);

  // Dismiss context menu on click-away or Escape. Unlike the other popups this
  // one listens on `document`, not `window`.
  useDismissOnOutsideClick({
    active: ctxMenu !== null,
    ref: ctxMenuRef,
    onDismiss: () => setCtxMenu(null),
    event: "click",
    target: "document",
    dismissOnEscape: true,
    dismissIfRefMissing: true,
  });

  const handleContextMenu = useCallback(
    (e: React.MouseEvent, lineNum: number) => {
      // The AI tab's text is not the pipeline's: its line map numbers another
      // body and its identifiers may be its own inventions, so neither a
      // comment nor a rename can be attributed from it.
      if (syncDisabled) return;
      const addr = lineMap?.get(lineNum);
      // What was under the pointer, if an identifier: the KEY is the generated
      // name the token maps back to, and only a stable class is offered — a
      // register, an `__unrecovered_N` or a `field_` gets no entry, whatever
      // line it sits on (`renameableIdentClass`).
      const displayed = (e.target as HTMLElement).dataset?.ident;
      const key = displayed !== undefined ? identKeyFor(displayed, varRenames) : undefined;
      const rename =
        displayed !== undefined && key !== undefined && onRenameVar && renameableIdentClass(key)
          ? { displayed, key }
          : undefined;
      // A line with no address and nothing renameable under the pointer has
      // no entry to show, so the browser's own menu is left alone. A typedef
      // or declaration line WITH a renameable identifier opens — that is the
      // case that used to be unreachable when the address was the gate.
      if (addr === undefined && !rename) return;
      e.preventDefault();
      setCtxMenu({ x: e.clientX, y: e.clientY, lineNum, address: addr, rename });
    },
    [syncDisabled, lineMap, varRenames, onRenameVar],
  );

  /** Commit the rename box: empty or unchanged clears, anything else renames. */
  const commitRenameVar = useCallback(() => {
    if (!renameVar) return;
    const value = renameVar.value.trim();
    if (value === "" || value === renameVar.key) {
      // Back to the generated name. A clear of a name that was never renamed is
      // the reducer's same-reference no-op.
      onClearVarRename?.(renameVar.key);
      setRenameVar(null);
      return;
    }
    if (value === renameVar.displayed) {
      setRenameVar(null);
      return;
    }
    // Asked without the token's own current spelling, or renaming `count`
    // back to `count` — or to a fresh name while `count` is declared — would
    // read as a collision with itself.
    const others = new Set(declaredNames);
    others.delete(renameVar.displayed);
    const problem = validateVarName(value, others);
    if (problem) {
      setRenameVar({ ...renameVar, problem });
      return;
    }
    onRenameVar?.(renameVar.key, value);
    setRenameVar(null);
  }, [renameVar, declaredNames, onRenameVar, onClearVarRename]);

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Escape") {
        setCtxMenu(null);
        return;
      }
      if (e.key === ";" && !syncDisabled && lineMap && onEditComment && comments) {
        if (highlightLines) {
          // Find first highlighted line with an address
          for (const lineNum of highlightLines) {
            const addr = lineMap.get(lineNum);
            if (addr !== undefined) {
              e.preventDefault();
              e.stopPropagation();
              onEditComment({ address: addr, value: comments[addr] ?? "" });
              return;
            }
          }
        }
        // No match → let event bubble to parent (uses currentAddress)
      }
    },
    [syncDisabled, lineMap, highlightLines, onEditComment, comments],
  );

  const isStreaming = activeTab === "ai" && loading && aiMode != null;

  // High level engine indicator
  const highIndicator =
    activeTab === "high" && highLevelEngine
      ? highLevelEngine === "none"
        ? "(not available)"
        : highLevelEngine === "retdec"
          ? "(retdec fallback)"
          : null
      : null;

  return (
    <div className="flex flex-col h-full border-l border-theme panel-bg">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1 bg-gray-800/50 border-b border-gray-700 text-xs shrink-0">
        {/* Pill tab group */}
        <div className="flex bg-gray-900 rounded-md p-0.5">
          {TAB_LABELS.map(({ key, label }) => (
            <button
              type="button"
              key={key}
              onClick={() => onTabChange(key)}
              className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                activeTab === key ? "bg-gray-600 text-white" : "text-gray-500 hover:text-gray-300"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {highIndicator && <span className="text-gray-500 text-[10px] italic">{highIndicator}</span>}

        {syncDisabled && <span className="text-gray-500 text-[10px] italic">(sync disabled)</span>}

        <div className="flex-1" />

        {/* AI tab buttons */}
        {activeTab === "ai" && !loading && (
          <>
            {onExplain && (
              <button
                type="button"
                onClick={onExplain}
                className="px-1.5 py-0.5 rounded text-[10px] bg-blue-800/60 text-blue-300 hover:bg-blue-700/60"
                title="Explain with AI"
              >
                Explain
              </button>
            )}
            {onEnhance && (
              <button
                type="button"
                onClick={onEnhance}
                className="px-1.5 py-0.5 rounded text-[10px] bg-purple-800/60 text-purple-300 hover:bg-purple-700/60"
                title="Enhance with AI"
              >
                Enhance
              </button>
            )}
          </>
        )}

        {/* Cancel button during AI streaming */}
        {isStreaming && onCancelAI && (
          <button
            type="button"
            onClick={onCancelAI}
            className="px-1.5 py-0.5 rounded text-[10px] bg-yellow-800/60 text-yellow-300 hover:bg-yellow-700/60 flex items-center gap-1"
            title="Cancel AI"
          >
            <svg aria-hidden="true" className="animate-spin h-3 w-3" viewBox="0 0 24 24">
              <circle
                className="opacity-25"
                cx="12"
                cy="12"
                r="10"
                stroke="currentColor"
                strokeWidth="4"
                fill="none"
              />
              <path
                className="opacity-75"
                fill="currentColor"
                d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
              />
            </svg>
            Cancel
          </button>
        )}

        {onScrollSyncToggle && (
          <button
            type="button"
            onClick={onScrollSyncToggle}
            className={`px-1.5 py-0.5 rounded text-[10px] ${
              scrollSyncEnabled
                ? "bg-blue-600 text-white"
                : "bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200"
            }`}
            title={
              scrollSyncEnabled
                ? "Scroll sync on — click to disable"
                : "Scroll sync off — click to enable"
            }
          >
            Sync
          </button>
        )}
        <button
          type="button"
          onClick={handleCopy}
          className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200"
          title={commentsCopyable ? "Copy (Shift: without comments)" : "Copy to clipboard"}
        >
          Copy
        </button>
        <button
          type="button"
          onClick={onClose}
          className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200"
          title="Close (D)"
        >
          Close
        </button>
      </div>

      {/* Error banner */}
      {error && (
        <div className="px-3 py-1.5 text-[10px] text-red-400 bg-red-900/30 border-b border-red-800/50 shrink-0">
          {error}
        </div>
      )}

      {/* Admissions line: what the C below admits it did not recover, each clause
          a button to the first site. Rendered only when there is something to
          admit; `admissionSummary` owns the count and the wording together. */}
      {admissionParts.length > 0 && (
        <div
          data-testid="decompile-admissions"
          className="flex flex-wrap items-center gap-x-1 px-3 py-1 text-[10px] text-amber-300/90 bg-amber-900/20 border-b border-amber-800/40 shrink-0"
        >
          {admissionParts.map((part, i) => (
            <span key={part.kind} className="flex items-center gap-x-1">
              {i > 0 && (
                <span className="text-gray-500 select-none">{ADMISSION_SEPARATOR.trim()}</span>
              )}
              <button
                type="button"
                onClick={() => scrollToLine(part.firstLine)}
                className="underline decoration-dotted hover:text-amber-200"
                title={`Scroll to the first ${part.kind === "gotos" ? "goto" : part.kind} site (line ${part.firstLine + 1})`}
              >
                {part.text}
              </button>
            </span>
          ))}
        </div>
      )}

      {/* Content */}
      {loading && !code ? (
        <div className="flex items-center justify-center flex-1 text-gray-500 text-sm gap-2">
          <svg aria-hidden="true" className="animate-spin h-4 w-4" viewBox="0 0 24 24">
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
              fill="none"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
            />
          </svg>
          {activeTab === "ai" ? "Generating..." : "Decompiling..."}
        </div>
      ) : !code && activeTab === "ai" && !loading ? (
        <div className="flex flex-col items-center justify-center flex-1 text-gray-500 text-sm gap-2 px-4 text-center">
          <p>
            Choose <span className="text-blue-400">Explain</span> or{" "}
            <span className="text-purple-400">Enhance</span> above to generate AI-powered
            pseudocode.
          </p>
          <p className="text-[10px] text-gray-600">
            Uses the best available decompilation as source.
          </p>
        </div>
      ) : (
        <pre
          ref={preRef}
          className="flex-1 overflow-auto px-3 py-2 leading-5 font-mono text-gray-200 select-text relative"
          style={{ fontSize: "var(--mono-font-size)" }}
          onClick={handleClick}
          // tabIndex={-1}: still focusable by click (which is how the ";" comment
          // shortcut is reached) but kept out of the tab order.
          tabIndex={-1}
          onKeyDown={handleKeyDown}
        >
          {lines.map((line) => {
            const isHighlighted = highlightLines?.has(line.num);
            const lineAddr = !syncDisabled && lineMap ? lineMap.get(line.num) : undefined;
            const commentText = lineAddr !== undefined && comments ? comments[lineAddr] : undefined;
            // The `!= null` is load-bearing beyond the truth test: it is what narrows
            // `editingComment` for the editor's own JSX below, exactly as the
            // `editingComment?.address` comparison it replaces used to.
            const isEditing = editingLine === line.num && editingComment != null;
            return (
              <div key={line.num}>
                <button
                  type="button"
                  tabIndex={-1}
                  data-line={line.num}
                  className={`flex w-full text-left ${isHighlighted ? "bg-blue-900/30" : "hover:bg-gray-800/30"} ${onLineClick && !syncDisabled ? "cursor-pointer" : ""}`}
                  onClick={() => onLineClick?.(line.num)}
                  onContextMenu={(e) => handleContextMenu(e, line.num)}
                >
                  <span className="inline-block w-8 text-right mr-3 text-gray-600 select-none shrink-0">
                    {line.displayNum}
                  </span>
                  <span className="flex-1">
                    {line.tokens.map((tok, i) => {
                      // A plain identifier carries `data-ident` and nothing
                      // else, so the context menu can read what was under the
                      // pointer; whitespace and punctuation stay bare spans.
                      if (tok.kind === "ident") {
                        return (
                          <span key={i} data-ident={tok.text}>
                            {tok.text}
                          </span>
                        );
                      }
                      if (!tok.cls) return <span key={i}>{tok.text}</span>;
                      // A `sub_` token's hover is asked at RENDER, not in the
                      // `lines` memo: `subTitle` is a fresh closure every parent
                      // render, and one Map lookup per `sub_` token is cheaper than
                      // re-tokenising the page.
                      const sub = subTitle ? tok.text.match(SUB_NAME) : null;
                      const title = sub && subTitle ? subTitle(parseInt(sub[1], 16)) : undefined;
                      return (
                        <span key={i} className={tok.cls} title={title} data-const={tok.link}>
                          {tok.text}
                        </span>
                      );
                    })}
                    {commentText && !isEditing && (
                      <span className="disasm-user-comment ml-4 select-none">
                        {"// "}
                        {formatComment(commentText)}
                      </span>
                    )}
                  </span>
                </button>
                {isEditing && onEditComment && onCommitComment && onDeleteComment && (
                  <div className="pl-11 py-1">
                    <textarea
                      ref={focusOnMount}
                      className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-green-300 font-mono resize-none focus:outline-none focus:border-blue-500"
                      rows={Math.max(2, (editingComment.value.match(/\n/g)?.length ?? 0) + 1)}
                      value={editingComment.value}
                      onChange={(e) =>
                        onEditComment({ address: editingComment.address, value: e.target.value })
                      }
                      onKeyDown={(e) => {
                        if (e.key === "Enter" && !e.shiftKey) {
                          e.preventDefault();
                          const text = editingComment.value.trim();
                          if (text) onCommitComment(editingComment.address, text);
                          else onDeleteComment(editingComment.address);
                          onEditComment(null);
                        } else if (e.key === "Escape") {
                          e.preventDefault();
                          onEditComment(null);
                        }
                      }}
                      onBlur={() => onEditComment(null)}
                    />
                  </div>
                )}
              </div>
            );
          })}
        </pre>
      )}

      {/* Context menu. The comment and Copy-address entries need the line's
          address; the rename entries need an identifier under the pointer.
          Either alone is enough to open it (`handleContextMenu`). */}
      {ctxMenu && (
        <div
          ref={ctxMenuRef}
          className="fixed z-50 backdrop-blur-sm bg-gray-900/95 border border-gray-700 rounded-lg shadow-xl py-1 text-xs min-w-[180px]"
          style={{ left: ctxMenu.x, top: ctxMenu.y }}
        >
          {ctxMenu.address !== undefined && onEditComment && comments && (
            <button
              type="button"
              onClick={() => {
                const address = ctxMenu.address as number;
                const existing = comments[address];
                onEditComment({ address, value: existing ?? "" });
                setCtxMenu(null);
              }}
              className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200 flex items-center justify-between"
            >
              <span>{comments[ctxMenu.address] ? "Edit comment" : "Add comment"}</span>
              <span className="text-gray-500 text-[9px] ml-4">;</span>
            </button>
          )}
          {ctxMenu.address !== undefined && (
            <button
              type="button"
              onClick={() => {
                const hex = (ctxMenu.address as number).toString(16).toUpperCase();
                void copyText(hex);
                setCtxMenu(null);
              }}
              className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200"
            >
              Copy address
            </button>
          )}
          {ctxMenu.rename && (
            <button
              type="button"
              onClick={() => {
                const { key, displayed } = ctxMenu.rename as { key: string; displayed: string };
                setRenameVar({
                  x: ctxMenu.x,
                  y: ctxMenu.y,
                  key,
                  displayed,
                  value: displayed,
                  problem: null,
                });
                setCtxMenu(null);
              }}
              className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200"
            >
              Rename {ctxMenu.rename.displayed}…
            </button>
          )}
          {ctxMenu.rename && varRenames?.[ctxMenu.rename.key] !== undefined && onClearVarRename && (
            <button
              type="button"
              onClick={() => {
                onClearVarRename((ctxMenu.rename as { key: string }).key);
                setCtxMenu(null);
              }}
              className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200"
              title={`Back to ${ctxMenu.rename.key}`}
            >
              Reset name
            </button>
          )}
        </div>
      )}

      {/* Inline variable rename, at the menu's position. Enter commits (empty
          or the generated name clears), Escape and blur abandon; a refused
          name stays in the box with the reason under it. The `DisassemblyRows`
          label-rename pattern, with `focusOnMount` rather than autoFocus. */}
      {renameVar && (
        <div
          className="fixed z-50 backdrop-blur-sm bg-gray-900/95 border border-gray-700 rounded-lg shadow-xl p-2 text-xs"
          style={{ left: renameVar.x, top: renameVar.y }}
        >
          <label className="flex items-center gap-2">
            <span className="text-gray-400 select-none">{renameVar.key} →</span>
            <input
              ref={focusOnMount}
              data-testid="decompile-rename-var"
              aria-label={`New name for ${renameVar.key}`}
              aria-invalid={renameVar.problem !== null}
              className={`bg-gray-800 border rounded px-1 text-yellow-300 text-[11px] font-mono outline-none w-48 ${
                renameVar.problem ? "border-red-500" : "border-blue-500"
              }`}
              value={renameVar.value}
              onChange={(e) => setRenameVar({ ...renameVar, value: e.target.value, problem: null })}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  e.preventDefault();
                  commitRenameVar();
                } else if (e.key === "Escape") {
                  e.preventDefault();
                  setRenameVar(null);
                }
                e.stopPropagation();
              }}
              onBlur={() => setRenameVar(null)}
            />
          </label>
          {renameVar.problem && (
            <div className="mt-1 text-[10px] text-red-400" role="alert">
              {renameVar.problem}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
