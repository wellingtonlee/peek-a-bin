import { useMemo, useRef, useCallback, useEffect, useState } from "react";
import type { DecompileTab, HighLevelEngine } from "../decompile/types";

// ── Syntax Highlighting ──

interface Token {
  text: string;
  cls: string;
}

const KEYWORDS = new Set([
  "if", "else", "while", "do", "for", "switch", "case", "default",
  "break", "continue", "return", "goto", "void", "struct",
]);

const TYPES = new Set([
  "int", "int32_t", "int64_t", "uint8_t", "uint16_t", "uint32_t", "uint64_t",
  "char", "short", "long", "unsigned", "signed", "void", "bool",
]);

function tokenizeLine(line: string): Token[] {
  const tokens: Token[] = [];
  // Match: strings, comments, hex numbers, decimal numbers, identifiers, operators, whitespace
  const re = /("(?:[^"\\]|\\.)*")|('(?:[^'\\]|\\.)*')|(\/\/.*$)|(\/\*[\s\S]*?\*\/)|(\b0x[0-9a-fA-F]+\b)|(\b\d+\b)|(\b[a-zA-Z_]\w*\b)|(\s+)|([^\s\w])/g;
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
      // Hex number
      tokens.push({ text, cls: "dc-number" });
    } else if (m[6]) {
      // Decimal number
      tokens.push({ text, cls: "dc-number" });
    } else if (m[7]) {
      // Identifier
      if (KEYWORDS.has(text)) {
        tokens.push({ text, cls: "dc-keyword font-semibold" });
      } else if (TYPES.has(text)) {
        tokens.push({ text, cls: "dc-type" });
      } else if (text.startsWith("sub_") || text.startsWith("loc_")) {
        tokens.push({ text, cls: "dc-type underline cursor-pointer hover:opacity-80" });
      } else if (text === "__asm") {
        tokens.push({ text, cls: "dc-comment italic" });
      } else {
        tokens.push({ text, cls: "" });
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
  address: number;
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
  onClose: () => void;
  highlightLines?: Set<number>;
  onLineClick?: (lineNum: number) => void;
  syncDisabled?: boolean;
  scrollSyncEnabled?: boolean;
  onScrollSyncToggle?: () => void;
  // Comment support
  comments?: Record<number, string>;
  lineMap?: Map<number, number>;
  editingComment?: { address: number; value: string } | null;
  onEditComment?: (ec: { address: number; value: string } | null) => void;
  onCommitComment?: (address: number, text: string) => void;
  onDeleteComment?: (address: number) => void;
}

export function DecompileView({
  code, loading, error, activeTab, onTabChange, highLevelEngine, aiMode,
  onEnhance, onExplain, onCancelAI, onNavigate, onClose,
  highlightLines, onLineClick, syncDisabled,
  scrollSyncEnabled, onScrollSyncToggle,
  comments, lineMap, editingComment, onEditComment, onCommitComment, onDeleteComment,
}: DecompileViewProps) {
  const preRef = useRef<HTMLPreElement>(null);
  const [ctxMenu, setCtxMenu] = useState<CtxMenuState | null>(null);

  const lines = useMemo(() => {
    if (!code) return [];
    return code.split("\n").map((line, i) => ({
      num: i,
      displayNum: i + 1,
      tokens: tokenizeLine(line),
    }));
  }, [code]);

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(code);
  }, [code]);

  const handleClick = useCallback(
    (e: React.MouseEvent) => {
      const target = e.target as HTMLElement;
      const text = target.textContent;
      if (!text || !onNavigate) return;

      // Click on sub_XXXX → navigate to that address
      const subMatch = text.match(/^sub_([0-9a-fA-F]+)$/);
      if (subMatch) {
        const addr = parseInt(subMatch[1], 16);
        onNavigate(addr);
      }
    },
    [onNavigate],
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

  // Dismiss context menu on click-away or Escape
  useEffect(() => {
    if (!ctxMenu) return;
    const dismiss = () => setCtxMenu(null);
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setCtxMenu(null); };
    document.addEventListener("click", dismiss);
    document.addEventListener("keydown", onKey);
    return () => { document.removeEventListener("click", dismiss); document.removeEventListener("keydown", onKey); };
  }, [ctxMenu]);

  const handleContextMenu = useCallback((e: React.MouseEvent, lineNum: number) => {
    if (syncDisabled || !lineMap) return;
    const addr = lineMap.get(lineNum);
    if (addr === undefined) return;
    e.preventDefault();
    setCtxMenu({ x: e.clientX, y: e.clientY, lineNum, address: addr });
  }, [syncDisabled, lineMap]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
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
  }, [syncDisabled, lineMap, highlightLines, onEditComment, comments]);

  // Format inline comment display
  const formatComment = (text: string): string => {
    const firstLine = text.split("\n")[0];
    const hasMore = text.includes("\n");
    return hasMore ? `${firstLine} [...]` : firstLine;
  };

  const isStreaming = activeTab === "ai" && loading && aiMode != null;

  // High level engine indicator
  const highIndicator = activeTab === "high" && highLevelEngine
    ? highLevelEngine === "none" ? "(not available)" : highLevelEngine === "retdec" ? "(retdec fallback)" : null
    : null;

  return (
    <div className="flex flex-col h-full border-l border-theme panel-bg">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1 bg-gray-800/50 border-b border-gray-700 text-xs shrink-0">
        {/* Pill tab group */}
        <div className="flex bg-gray-900 rounded-md p-0.5">
          {TAB_LABELS.map(({ key, label }) => (
            <button
              key={key}
              onClick={() => onTabChange(key)}
              className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${
                activeTab === key
                  ? "bg-gray-600 text-white"
                  : "text-gray-500 hover:text-gray-300"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {highIndicator && (
          <span className="text-gray-500 text-[10px] italic">{highIndicator}</span>
        )}

        {syncDisabled && (
          <span className="text-gray-500 text-[10px] italic">(sync disabled)</span>
        )}

        <div className="flex-1" />

        {/* AI tab buttons */}
        {activeTab === "ai" && !loading && (
          <>
            {onExplain && (
              <button
                onClick={onExplain}
                className="px-1.5 py-0.5 rounded text-[10px] bg-blue-800/60 text-blue-300 hover:bg-blue-700/60"
                title="Explain with AI"
              >
                Explain
              </button>
            )}
            {onEnhance && (
              <button
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
            onClick={onCancelAI}
            className="px-1.5 py-0.5 rounded text-[10px] bg-yellow-800/60 text-yellow-300 hover:bg-yellow-700/60 flex items-center gap-1"
            title="Cancel AI"
          >
            <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
              <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
              <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
            </svg>
            Cancel
          </button>
        )}

        {onScrollSyncToggle && (
          <button
            onClick={onScrollSyncToggle}
            className={`px-1.5 py-0.5 rounded text-[10px] ${
              scrollSyncEnabled
                ? "bg-blue-600 text-white"
                : "bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200"
            }`}
            title={scrollSyncEnabled ? "Scroll sync on — click to disable" : "Scroll sync off — click to enable"}
          >
            Sync
          </button>
        )}
        <button
          onClick={handleCopy}
          className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200"
          title="Copy to clipboard"
        >
          Copy
        </button>
        <button
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

      {/* Content */}
      {loading && !code ? (
        <div className="flex items-center justify-center flex-1 text-gray-500 text-sm gap-2">
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          {activeTab === "ai" ? "Generating..." : "Decompiling..."}
        </div>
      ) : !code && activeTab === "ai" && !loading ? (
        <div className="flex flex-col items-center justify-center flex-1 text-gray-500 text-sm gap-2 px-4 text-center">
          <p>Choose <span className="text-blue-400">Explain</span> or <span className="text-purple-400">Enhance</span> above to generate AI-powered pseudocode.</p>
          <p className="text-[10px] text-gray-600">Uses the best available decompilation as source.</p>
        </div>
      ) : (
        <pre
          ref={preRef}
          className="flex-1 overflow-auto px-3 py-2 leading-5 font-mono text-gray-200 select-text relative"
          style={{ fontSize: 'var(--mono-font-size)' }}
          onClick={handleClick}
          tabIndex={0}
          onKeyDown={handleKeyDown}
        >
          {lines.map((line) => {
            const isHighlighted = highlightLines?.has(line.num);
            const lineAddr = !syncDisabled && lineMap ? lineMap.get(line.num) : undefined;
            const commentText = lineAddr !== undefined && comments ? comments[lineAddr] : undefined;
            const isEditing = lineAddr !== undefined && editingComment?.address === lineAddr;
            return (
              <div key={line.num}>
                <div
                  data-line={line.num}
                  className={`flex ${isHighlighted ? "bg-blue-900/30" : "hover:bg-gray-800/30"} ${onLineClick && !syncDisabled ? "cursor-pointer" : ""}`}
                  onClick={() => onLineClick?.(line.num)}
                  onContextMenu={(e) => handleContextMenu(e, line.num)}
                >
                  <span className="inline-block w-8 text-right mr-3 text-gray-600 select-none shrink-0">
                    {line.displayNum}
                  </span>
                  <span className="flex-1">
                    {line.tokens.map((tok, i) =>
                      tok.cls ? (
                        <span key={i} className={tok.cls}>{tok.text}</span>
                      ) : (
                        <span key={i}>{tok.text}</span>
                      ),
                    )}
                    {commentText && !isEditing && (
                      <span className="disasm-user-comment ml-4 select-none">{'// '}{formatComment(commentText)}</span>
                    )}
                  </span>
                </div>
                {isEditing && onEditComment && onCommitComment && onDeleteComment && (
                  <div className="pl-11 py-1">
                    <textarea
                      autoFocus
                      className="w-full bg-gray-900 border border-gray-600 rounded px-2 py-1 text-xs text-green-300 font-mono resize-none focus:outline-none focus:border-blue-500"
                      rows={Math.max(2, (editingComment.value.match(/\n/g)?.length ?? 0) + 1)}
                      value={editingComment.value}
                      onChange={(e) => onEditComment({ address: editingComment.address, value: e.target.value })}
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

      {/* Context menu */}
      {ctxMenu && onEditComment && comments && (
        <div
          className="fixed z-50 backdrop-blur-sm bg-gray-900/95 border border-gray-700 rounded-lg shadow-xl py-1 text-xs min-w-[180px]"
          style={{ left: ctxMenu.x, top: ctxMenu.y }}
          onClick={(e) => e.stopPropagation()}
        >
          <button
            onClick={() => {
              const existing = comments[ctxMenu.address];
              onEditComment({ address: ctxMenu.address, value: existing ?? "" });
              setCtxMenu(null);
            }}
            className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200 flex items-center justify-between"
          >
            <span>{comments[ctxMenu.address] ? "Edit comment" : "Add comment"}</span>
            <span className="text-gray-500 text-[9px] ml-4">;</span>
          </button>
          <button
            onClick={() => {
              const hex = ctxMenu.address.toString(16).toUpperCase();
              navigator.clipboard.writeText(hex);
              setCtxMenu(null);
            }}
            className="w-full text-left px-3 py-1.5 hover:bg-gray-700/80 text-gray-200"
          >
            Copy address
          </button>
        </div>
      )}
    </div>
  );
}
