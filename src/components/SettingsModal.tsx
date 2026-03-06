import { useState, useEffect } from "react";
import { loadSettings, saveSettings, loadFontSize, saveFontSize, loadDecompileServer, saveDecompileServer, type LLMSettings, type DecompileServerSettings } from "../llm/settings";

interface Props {
  open: boolean;
  onClose: () => void;
}

const PROVIDER_DEFAULTS: Record<string, { model: string; baseUrl: string }> = {
  anthropic: { model: "claude-sonnet-4-20250514", baseUrl: "https://api.openai.com" },
  openai: { model: "gpt-4o", baseUrl: "https://api.openai.com" },
};

export function SettingsModal({ open, onClose }: Props) {
  const [settings, setSettings] = useState<LLMSettings>(loadSettings);
  const [showKey, setShowKey] = useState(false);
  const [fontSize, setFontSize] = useState(() => loadFontSize());
  const [decompServer, setDecompServer] = useState<DecompileServerSettings>(loadDecompileServer);

  useEffect(() => {
    if (open) {
      setSettings(loadSettings());
      setShowKey(false);
      setFontSize(loadFontSize());
      setDecompServer(loadDecompileServer());
    }
  }, [open]);


  if (!open) return null;

  const handleProviderChange = (provider: "anthropic" | "openai") => {
    const defaults = PROVIDER_DEFAULTS[provider];
    setSettings((s) => ({
      ...s,
      provider,
      model: s.model === PROVIDER_DEFAULTS[s.provider].model ? defaults.model : s.model,
      baseUrl: provider === "openai" ? s.baseUrl : defaults.baseUrl,
    }));
  };

  const handleSave = () => {
    saveSettings(settings);
    saveFontSize(fontSize);
    saveDecompileServer(decompServer);
    onClose();
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[15vh] bg-black/50"
    >
      <div
        className="w-[440px] bg-gray-800 border border-gray-600 rounded-lg shadow-2xl overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="px-4 py-3 border-b border-gray-700">
          <h2 className="text-sm font-semibold text-gray-200">Settings</h2>
        </div>

        <div className="px-4 py-3 space-y-3">
          {/* Provider */}
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              Provider
            </label>
            <div className="flex gap-3">
              {(["anthropic", "openai"] as const).map((p) => (
                <label key={p} className="flex items-center gap-1.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="radio"
                    name="provider"
                    checked={settings.provider === p}
                    onChange={() => handleProviderChange(p)}
                    className="accent-blue-500"
                  />
                  {p === "anthropic" ? "Anthropic Claude" : "OpenAI-compatible"}
                </label>
              ))}
            </div>
          </div>

          {/* API Key */}
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              API Key
            </label>
            <div className="flex gap-1">
              <input
                type={showKey ? "text" : "password"}
                value={settings.apiKey}
                onChange={(e) => setSettings((s) => ({ ...s, apiKey: e.target.value }))}
                placeholder={settings.provider === "anthropic" ? "sk-ant-..." : "sk-..."}
                className="flex-1 px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={() => setShowKey((v) => !v)}
                className="px-2 py-1 text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600 hover:text-gray-200 rounded"
              >
                {showKey ? "Hide" : "Show"}
              </button>
            </div>
          </div>

          {/* Model */}
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              Model
            </label>
            <input
              type="text"
              value={settings.model}
              onChange={(e) => setSettings((s) => ({ ...s, model: e.target.value }))}
              className="w-full px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-xs text-gray-200 focus:outline-none focus:border-blue-500"
            />
          </div>

          {/* Enhance Source */}
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              Enhance Source
            </label>
            <div className="flex gap-3">
              {(["pseudocode", "assembly"] as const).map((s) => (
                <label key={s} className="flex items-center gap-1.5 text-xs text-gray-300 cursor-pointer">
                  <input
                    type="radio"
                    name="enhanceSource"
                    checked={settings.enhanceSource === s}
                    onChange={() => setSettings((prev) => ({ ...prev, enhanceSource: s }))}
                    className="accent-blue-500"
                  />
                  {s === "pseudocode" ? "Pseudocode (default)" : "Assembly"}
                </label>
              ))}
            </div>
            <p className="text-[10px] text-gray-600 mt-0.5">What to send to the AI for enhancement</p>
          </div>

          {/* Font Size */}
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              Font Size
            </label>
            <div className="flex items-center gap-3">
              <input
                type="range"
                min={10}
                max={16}
                step={1}
                value={fontSize}
                onChange={(e) => setFontSize(parseInt(e.target.value, 10))}
                className="flex-1 accent-blue-500"
              />
              <span className="text-xs text-gray-300 w-8 text-right">{fontSize}px</span>
            </div>
          </div>

          {/* Decompilation Server */}
          <div>
            <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
              Decompilation Server
            </label>
            <label className="flex items-center gap-1.5 text-xs text-gray-300 cursor-pointer mb-2">
              <input
                type="checkbox"
                checked={decompServer.enabled}
                onChange={(e) => setDecompServer((s) => ({ ...s, enabled: e.target.checked }))}
                className="accent-blue-500"
              />
              Enable Ghidra server
            </label>
            {decompServer.enabled && (
              <div className="space-y-2">
                <input
                  type="text"
                  value={decompServer.ghidraUrl}
                  onChange={(e) => setDecompServer((s) => ({ ...s, ghidraUrl: e.target.value }))}
                  placeholder="http://localhost:8765"
                  className="w-full px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
                <input
                  type="text"
                  value={decompServer.apiKey}
                  onChange={(e) => setDecompServer((s) => ({ ...s, apiKey: e.target.value }))}
                  placeholder="API key (optional)"
                  className="w-full px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
                />
              </div>
            )}
            <p className="text-[10px] text-gray-600 mt-0.5">When disabled, High Level tab uses built-in engine (if available).</p>
          </div>

          {/* Base URL (OpenAI only) */}
          {settings.provider === "openai" && (
            <div>
              <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                Base URL
              </label>
              <input
                type="text"
                value={settings.baseUrl}
                onChange={(e) => setSettings((s) => ({ ...s, baseUrl: e.target.value }))}
                placeholder="https://api.openai.com"
                className="w-full px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
              />
              <p className="text-[10px] text-gray-600 mt-0.5">For Ollama, LM Studio, vLLM, etc.</p>
            </div>
          )}

          {/* Warning */}
          <p className="text-[10px] text-gray-500 border border-gray-700 rounded px-2 py-1.5 bg-gray-900/50">
            Key is stored in localStorage and sent only to the configured endpoint.
          </p>
        </div>

        <div className="flex justify-end gap-2 px-4 py-3 border-t border-gray-700">
          <button
            onClick={onClose}
            className="px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-700 hover:bg-gray-600 rounded"
          >
            Cancel
          </button>
          <button
            onClick={handleSave}
            className="px-3 py-1.5 text-xs text-white bg-blue-600 hover:bg-blue-500 rounded"
          >
            Save
          </button>
        </div>
      </div>
    </div>
  );
}
