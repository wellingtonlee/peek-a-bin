import { useReducer, useRef, useCallback, useEffect } from "react";
import type { ChatMessage } from "../llm/types";
import { streamChat } from "../llm/client";
import { hasApiKey, loadSettings } from "../llm/settings";
import { SYSTEM_PROMPT_CHAT } from "../llm/prompt";
import type { PEFile } from "../pe/types";

interface ChatState {
  messages: ChatMessage[];
  streaming: boolean;
  error: string | null;
}

type ChatAction =
  | { type: "ADD_USER"; content: string }
  | { type: "BEGIN_STREAM" }
  | { type: "STREAM_TOKEN"; content: string }
  | { type: "STREAM_DONE" }
  | { type: "STREAM_ERROR"; error: string }
  | { type: "LOAD"; messages: ChatMessage[] }
  | { type: "CLEAR" };

function chatReducer(state: ChatState, action: ChatAction): ChatState {
  switch (action.type) {
    case "ADD_USER":
      return { ...state, messages: [...state.messages, { role: "user", content: action.content }], error: null };
    case "BEGIN_STREAM":
      return { ...state, messages: [...state.messages, { role: "assistant", content: "" }], streaming: true, error: null };
    case "STREAM_TOKEN": {
      const msgs = [...state.messages];
      if (msgs.length > 0 && msgs[msgs.length - 1].role === "assistant") {
        msgs[msgs.length - 1] = { ...msgs[msgs.length - 1], content: action.content };
      }
      return { ...state, messages: msgs };
    }
    case "STREAM_DONE":
      return { ...state, streaming: false };
    case "STREAM_ERROR":
      return { ...state, streaming: false, error: action.error };
    case "LOAD":
      return { ...state, messages: action.messages };
    case "CLEAR":
      return { messages: [], streaming: false, error: null };
    default:
      return state;
  }
}

const MAX_MESSAGES = 50;

function buildSystemPrompt(pe: PEFile | null, fileName: string | null, currentCode: string | null): string {
  let prompt = SYSTEM_PROMPT_CHAT;

  if (pe && fileName) {
    const arch = pe.is64 ? "x86-64" : "x86";
    const entry = `0x${(pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint).toString(16).toUpperCase()}`;
    const sections = pe.sections.map(s => {
      const name = s.name.replace(/\0/g, "").trim();
      const flags: string[] = [];
      if (s.characteristics & 0x20000000) flags.push("X");
      if (s.characteristics & 0x40000000) flags.push("R");
      if (s.characteristics & 0x80000000) flags.push("W");
      return `${name} (${flags.join("")}, 0x${s.virtualSize.toString(16)})`;
    }).join(", ");

    prompt += `\n\n## Binary Context
File: ${fileName}
Architecture: ${arch}
Entry Point: ${entry}
Image Base: 0x${pe.optionalHeader.imageBase.toString(16).toUpperCase()}
Sections: ${sections}`;
  }

  if (currentCode) {
    prompt += `\n\n## Current Function Pseudocode
\`\`\`c
${currentCode.substring(0, 6000)}
\`\`\``;
  }

  return prompt;
}

export interface UseAIChatResult {
  messages: ChatMessage[];
  streaming: boolean;
  error: string | null;
  sendMessage: (content: string) => void;
  clearChat: () => void;
  cancelStream: () => void;
}

export function useAIChat(
  pe: PEFile | null,
  fileName: string | null,
  currentCode: string | null,
): UseAIChatResult {
  const [state, dispatch] = useReducer(chatReducer, { messages: [], streaming: false, error: null });
  const abortRef = useRef<AbortController | null>(null);
  const accRef = useRef("");
  const loadedFileRef = useRef<string | null>(null);

  // Load persisted messages
  useEffect(() => {
    if (!fileName) return;
    if (loadedFileRef.current === fileName) return;
    loadedFileRef.current = fileName;
    try {
      const raw = localStorage.getItem(`peek-a-bin:chat:${fileName}`);
      if (raw) {
        const msgs: ChatMessage[] = JSON.parse(raw);
        if (Array.isArray(msgs)) dispatch({ type: "LOAD", messages: msgs.slice(-MAX_MESSAGES) });
      }
    } catch { /* ignore */ }
  }, [fileName]);

  // Persist messages
  useEffect(() => {
    if (!fileName || state.streaming) return;
    if (state.messages.length === 0) {
      try { localStorage.removeItem(`peek-a-bin:chat:${fileName}`); } catch {}
      return;
    }
    try {
      localStorage.setItem(`peek-a-bin:chat:${fileName}`, JSON.stringify(state.messages.slice(-MAX_MESSAGES)));
    } catch { /* quota */ }
  }, [fileName, state.messages, state.streaming]);

  const sendMessage = useCallback((content: string) => {
    if (!content.trim() || state.streaming) return;
    if (!hasApiKey()) {
      window.dispatchEvent(new CustomEvent("peek-a-bin:open-settings"));
      return;
    }

    const userMsg: ChatMessage = { role: "user", content: content.trim() };
    dispatch({ type: "ADD_USER", content: userMsg.content });
    dispatch({ type: "BEGIN_STREAM" });

    const config = loadSettings();
    const controller = new AbortController();
    abortRef.current = controller;
    accRef.current = "";

    const allMessages = [...state.messages, userMsg];
    const systemPrompt = buildSystemPrompt(pe, fileName, currentCode);

    streamChat(allMessages, systemPrompt, config, controller.signal, {
      onToken: (accumulated) => {
        accRef.current = accumulated;
        dispatch({ type: "STREAM_TOKEN", content: accumulated });
      },
      onDone: () => {
        dispatch({ type: "STREAM_DONE" });
      },
      onError: (error) => {
        dispatch({ type: "STREAM_ERROR", error });
      },
    });
  }, [state.messages, state.streaming, pe, fileName, currentCode]);

  const clearChat = useCallback(() => {
    abortRef.current?.abort();
    dispatch({ type: "CLEAR" });
    if (fileName) {
      try { localStorage.removeItem(`peek-a-bin:chat:${fileName}`); } catch {}
    }
  }, [fileName]);

  const cancelStream = useCallback(() => {
    abortRef.current?.abort();
    dispatch({ type: "STREAM_DONE" });
  }, []);

  return {
    messages: state.messages,
    streaming: state.streaming,
    error: state.error,
    sendMessage,
    clearChat,
    cancelStream,
  };
}
