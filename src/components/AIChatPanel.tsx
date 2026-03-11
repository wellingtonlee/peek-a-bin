import { useRef, useEffect, useState, useCallback } from "react";
import type { ChatMessage } from "../llm/types";
import { MarkdownRenderer } from "./MarkdownRenderer";
import type { UseAIChatResult } from "../hooks/useAIChat";

interface AIChatPanelProps {
  chat: UseAIChatResult;
  onClose: () => void;
  onRename?: (address: number, name: string) => void;
}

const RENAME_RE = /\[RENAME:0x([0-9a-fA-F]+):([^\]]+)\]/g;

function parseRenameActions(content: string): { address: number; name: string }[] {
  const results: { address: number; name: string }[] = [];
  let match: RegExpExecArray | null;
  const re = new RegExp(RENAME_RE.source, "g");
  while ((match = re.exec(content)) !== null) {
    results.push({ address: parseInt(match[1], 16), name: match[2].trim() });
  }
  return results;
}

function MessageBubble({ msg, onRename }: { msg: ChatMessage; onRename?: (address: number, name: string) => void }) {
  if (msg.role === "user") {
    return (
      <div className="flex justify-end mb-3">
        <div className="max-w-[85%] bg-blue-600/20 border border-blue-600/30 rounded-lg px-3 py-2 text-xs text-gray-200 whitespace-pre-wrap">
          {msg.content}
        </div>
      </div>
    );
  }

  const renames = parseRenameActions(msg.content);
  // Strip rename markers from display
  const cleanContent = msg.content.replace(RENAME_RE, "");

  return (
    <div className="flex justify-start mb-3">
      <div className="max-w-[90%]">
        <MarkdownRenderer content={cleanContent} className="text-xs" />
        {renames.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {renames.map((r, i) => (
              <button
                key={i}
                onClick={() => onRename?.(r.address, r.name)}
                className="px-2 py-1 text-[10px] bg-green-800/40 border border-green-600/40 rounded text-green-300 hover:bg-green-700/50 transition-colors"
                title={`Rename 0x${r.address.toString(16).toUpperCase()} → ${r.name}`}
              >
                Apply: {r.name}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

export function AIChatPanel({ chat, onClose, onRename }: AIChatPanelProps) {
  const [input, setInput] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  // Auto-scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chat.messages, chat.streaming]);

  const handleSend = useCallback(() => {
    if (!input.trim() || chat.streaming) return;
    chat.sendMessage(input);
    setInput("");
    if (textareaRef.current) textareaRef.current.style.height = "auto";
  }, [input, chat]);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      handleSend();
    }
  }, [handleSend]);

  // Auto-resize textarea
  const handleInput = useCallback((e: React.ChangeEvent<HTMLTextAreaElement>) => {
    setInput(e.target.value);
    const el = e.target;
    el.style.height = "auto";
    el.style.height = Math.min(el.scrollHeight, 120) + "px";
  }, []);

  return (
    <div className="flex flex-col h-full border-l border-theme panel-bg">
      {/* Header */}
      <div className="flex items-center gap-2 px-3 py-1.5 bg-gray-800/50 border-b border-gray-700 text-xs shrink-0">
        <span className="text-gray-300 font-medium">AI Chat</span>
        <div className="flex-1" />
        <button
          onClick={chat.clearChat}
          className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200"
          title="Clear conversation"
        >
          Clear
        </button>
        <button
          onClick={onClose}
          className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200"
          title="Close chat"
        >
          Close
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-auto px-3 py-2">
        {chat.messages.length === 0 && !chat.streaming && (
          <div className="flex flex-col items-center justify-center h-full text-gray-500 text-xs text-center gap-2 px-4">
            <p className="text-gray-400">Ask about the current binary or function.</p>
            <p className="text-[10px] text-gray-600">The active function's pseudocode and PE metadata are automatically included as context.</p>
          </div>
        )}
        {chat.messages.map((msg, i) => (
          <MessageBubble key={i} msg={msg} onRename={onRename} />
        ))}
        {chat.streaming && chat.messages.length > 0 && chat.messages[chat.messages.length - 1].content === "" && (
          <div className="flex justify-start mb-3">
            <div className="flex items-center gap-1.5 text-gray-500 text-xs">
              <svg className="animate-spin h-3 w-3" viewBox="0 0 24 24">
                <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
              </svg>
              Thinking...
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Error */}
      {chat.error && (
        <div className="px-3 py-1.5 text-[10px] text-red-400 bg-red-900/30 border-t border-red-800/50 shrink-0">
          {chat.error}
        </div>
      )}

      {/* Input */}
      <div className="border-t border-gray-700 px-3 py-2 shrink-0">
        <div className="flex items-end gap-2">
          <textarea
            ref={textareaRef}
            value={input}
            onChange={handleInput}
            onKeyDown={handleKeyDown}
            placeholder="Ask about this binary..."
            rows={1}
            className="flex-1 bg-gray-900 border border-gray-600 rounded px-2 py-1.5 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500 resize-none"
            style={{ maxHeight: 120 }}
            disabled={chat.streaming}
          />
          {chat.streaming ? (
            <button
              onClick={chat.cancelStream}
              className="px-2.5 py-1.5 bg-yellow-700 text-yellow-200 rounded text-xs hover:bg-yellow-600 shrink-0"
            >
              Stop
            </button>
          ) : (
            <button
              onClick={handleSend}
              disabled={!input.trim()}
              className="px-2.5 py-1.5 bg-blue-600 text-white rounded text-xs hover:bg-blue-500 disabled:opacity-30 disabled:cursor-default shrink-0"
            >
              Send
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
