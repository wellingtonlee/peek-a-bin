import { useMemo, useRef, useCallback } from "react";

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
      tokens.push({ text, cls: "text-green-400" });
    } else if (m[3] || m[4]) {
      // Comment
      tokens.push({ text, cls: "text-gray-500 italic" });
    } else if (m[5]) {
      // Hex number
      tokens.push({ text, cls: "text-yellow-300" });
    } else if (m[6]) {
      // Decimal number
      tokens.push({ text, cls: "text-yellow-300" });
    } else if (m[7]) {
      // Identifier
      if (KEYWORDS.has(text)) {
        tokens.push({ text, cls: "text-purple-400 font-semibold" });
      } else if (TYPES.has(text)) {
        tokens.push({ text, cls: "text-blue-400" });
      } else if (text.startsWith("sub_") || text.startsWith("loc_")) {
        tokens.push({ text, cls: "text-blue-400 underline cursor-pointer hover:text-blue-300" });
      } else if (text === "__asm") {
        tokens.push({ text, cls: "text-gray-500 italic" });
      } else {
        tokens.push({ text, cls: "" });
      }
    } else if (m[8]) {
      // Whitespace
      tokens.push({ text, cls: "" });
    } else {
      // Operators / punctuation
      tokens.push({ text, cls: "text-gray-400" });
    }
  }
  return tokens;
}

// ── Component ──

interface DecompileViewProps {
  code: string;
  loading?: boolean;
  enhancing?: boolean;
  enhanceError?: string;
  onNavigate?: (addr: number) => void;
  onEnhance?: () => void;
  onCancelEnhance?: () => void;
  onClose: () => void;
}

export function DecompileView({ code, loading, enhancing, enhanceError, onNavigate, onEnhance, onCancelEnhance, onClose }: DecompileViewProps) {
  const preRef = useRef<HTMLPreElement>(null);

  const lines = useMemo(() => {
    if (!code) return [];
    return code.split("\n").map((line, i) => ({
      num: i + 1,
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

  return (
    <div className="flex flex-col h-full border-l border-gray-700 bg-gray-900/95">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1 bg-gray-800/50 border-b border-gray-700 text-xs shrink-0">
        <span className="text-gray-300 font-semibold">Pseudocode</span>
        <div className="flex-1" />
        {onEnhance && (
          enhancing ? (
            <button
              onClick={onCancelEnhance}
              className="px-1.5 py-0.5 rounded text-[10px] bg-yellow-800/60 text-yellow-300 hover:bg-yellow-700/60 flex items-center gap-1"
              title="Cancel AI enhancement"
            >
              <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Cancel
            </button>
          ) : (
            <button
              onClick={onEnhance}
              disabled={loading}
              className="px-1.5 py-0.5 rounded text-[10px] bg-purple-800/60 text-purple-300 hover:bg-purple-700/60 disabled:opacity-30 disabled:cursor-default"
              title="Enhance with AI"
            >
              Enhance with AI
            </button>
          )
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
      {enhanceError && (
        <div className="px-3 py-1.5 text-[10px] text-red-400 bg-red-900/30 border-b border-red-800/50 shrink-0">
          {enhanceError}
        </div>
      )}

      {/* Content */}
      {loading ? (
        <div className="flex items-center justify-center flex-1 text-gray-500 text-sm gap-2">
          <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
          Decompiling...
        </div>
      ) : (
        <pre
          ref={preRef}
          className="flex-1 overflow-auto px-3 py-2 text-xs leading-5 font-mono text-gray-200 select-text"
          onClick={handleClick}
        >
          {lines.map((line) => (
            <div key={line.num} className="flex hover:bg-gray-800/30">
              <span className="inline-block w-8 text-right mr-3 text-gray-600 select-none shrink-0">
                {line.num}
              </span>
              <span>
                {line.tokens.map((tok, i) =>
                  tok.cls ? (
                    <span key={i} className={tok.cls}>{tok.text}</span>
                  ) : (
                    <span key={i}>{tok.text}</span>
                  ),
                )}
              </span>
            </div>
          ))}
        </pre>
      )}
    </div>
  );
}
