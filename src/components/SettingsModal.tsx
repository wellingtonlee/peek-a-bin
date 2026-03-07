import { useState, useEffect, useRef } from "react";
import { loadSettings, saveSettings, loadFontSize, saveFontSize, loadDecompileServer, saveDecompileServer, type LLMSettings, type DecompileServerSettings } from "../llm/settings";
import { getAllThemes, loadThemeId, saveThemeId, saveCustomTheme, deleteCustomTheme, exportTheme, importTheme, BUILTIN_THEMES, type Theme } from "../styles/themes";

interface Props {
  open: boolean;
  onClose: () => void;
}

const PROVIDER_DEFAULTS: Record<string, { model: string; baseUrl: string }> = {
  anthropic: { model: "claude-sonnet-4-20250514", baseUrl: "https://api.openai.com" },
  openai: { model: "gpt-4o", baseUrl: "https://api.openai.com" },
};

type SettingsTab = "ai" | "ghidra" | "display" | "theme";

const TABS: { id: SettingsTab; label: string }[] = [
  { id: "ai", label: "AI" },
  { id: "ghidra", label: "Ghidra" },
  { id: "display", label: "Display" },
  { id: "theme", label: "Theme" },
];

export function SettingsModal({ open, onClose }: Props) {
  const [settings, setSettings] = useState<LLMSettings>(loadSettings);
  const [showKey, setShowKey] = useState(false);
  const [fontSize, setFontSize] = useState(() => loadFontSize());
  const [decompServer, setDecompServer] = useState<DecompileServerSettings>(loadDecompileServer);
  const [activeTab, setActiveTab] = useState<SettingsTab>("ai");
  const [themeId, setThemeId] = useState(loadThemeId);
  const [themes, setThemes] = useState(getAllThemes);
  const [importError, setImportError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setSettings(loadSettings());
      setShowKey(false);
      setFontSize(loadFontSize());
      setDecompServer(loadDecompileServer());
      setThemeId(loadThemeId());
      setThemes(getAllThemes());
      setImportError(null);
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
    saveThemeId(themeId);
    window.dispatchEvent(new CustomEvent("peek-a-bin:theme-changed"));
    onClose();
  };

  const handleImportTheme = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const theme = importTheme(reader.result as string);
        saveCustomTheme(theme);
        setThemes(getAllThemes());
        setThemeId(theme.id);
        setImportError(null);
      } catch (err) {
        setImportError(err instanceof Error ? err.message : "Invalid theme file");
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const handleExportTheme = () => {
    const theme = themes.find(t => t.id === themeId);
    if (!theme) return;
    const json = exportTheme(theme);
    const blob = new Blob([json], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${theme.id}-theme.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleDeleteTheme = (id: string) => {
    deleteCustomTheme(id);
    setThemes(getAllThemes());
    if (themeId === id) setThemeId("dark");
  };

  // Preview theme colors as small swatches
  const ThemeSwatches = ({ theme }: { theme: Theme }) => (
    <div className="flex gap-0.5 mt-1">
      {[theme.colors.bg, theme.colors.mnemonic, theme.colors.mnCall, theme.colors.mnRet, theme.colors.mnJump, theme.colors.opRegister, theme.colors.comment].map((c, i) => (
        <div key={i} className="w-3 h-3 rounded-sm" style={{ background: c }} />
      ))}
    </div>
  );

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

        {/* Tab bar */}
        <div className="flex border-b border-gray-700">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`px-4 py-2 text-xs font-medium transition-colors ${
                activeTab === tab.id
                  ? "text-blue-400 border-b-2 border-blue-400 -mb-px"
                  : "text-gray-400 hover:text-gray-200"
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="px-4 py-3 space-y-3">
          {/* AI Tab */}
          {activeTab === "ai" && (
            <>
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
            </>
          )}

          {/* Ghidra Tab */}
          {activeTab === "ghidra" && (
            <>
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
                    <div>
                      <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                        Ghidra URL
                      </label>
                      <input
                        type="text"
                        value={decompServer.ghidraUrl}
                        onChange={(e) => setDecompServer((s) => ({ ...s, ghidraUrl: e.target.value }))}
                        placeholder="http://localhost:8765"
                        className="w-full px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                        API Key
                      </label>
                      <input
                        type="text"
                        value={decompServer.apiKey}
                        onChange={(e) => setDecompServer((s) => ({ ...s, apiKey: e.target.value }))}
                        placeholder="API key (optional)"
                        className="w-full px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-xs text-gray-200 placeholder-gray-600 focus:outline-none focus:border-blue-500"
                      />
                    </div>
                  </div>
                )}
                <p className="text-[10px] text-gray-600 mt-0.5">When disabled, High Level tab uses built-in engine (if available).</p>
              </div>
            </>
          )}

          {/* Display Tab */}
          {activeTab === "display" && (
            <>
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
            </>
          )}

          {/* Theme Tab */}
          {activeTab === "theme" && (
            <>
              <div>
                <label className="block text-[10px] font-semibold text-gray-500 uppercase tracking-wider mb-1.5">
                  Color Theme
                </label>
                <div className="grid grid-cols-2 gap-2">
                  {themes.map((theme) => {
                    const isBuiltin = BUILTIN_THEMES.some(b => b.id === theme.id);
                    return (
                      <div
                        key={theme.id}
                        onClick={() => setThemeId(theme.id)}
                        className={`relative p-2 rounded-lg border cursor-pointer transition-colors ${
                          themeId === theme.id
                            ? "border-blue-500 bg-blue-500/10"
                            : "border-gray-600 hover:border-gray-500 bg-gray-900/50"
                        }`}
                      >
                        <div className="text-xs text-gray-200 font-medium">{theme.name}</div>
                        <ThemeSwatches theme={theme} />
                        {!isBuiltin && (
                          <button
                            onClick={(e) => { e.stopPropagation(); handleDeleteTheme(theme.id); }}
                            className="absolute top-1 right-1 text-gray-500 hover:text-red-400 text-[10px]"
                            title="Delete theme"
                          >
                            ×
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => fileInputRef.current?.click()}
                  className="px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-700 hover:bg-gray-600 rounded"
                >
                  Import Theme
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".json"
                  onChange={handleImportTheme}
                  className="hidden"
                />
                <button
                  onClick={handleExportTheme}
                  className="px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-700 hover:bg-gray-600 rounded"
                >
                  Export Current
                </button>
              </div>

              {importError && (
                <p className="text-[10px] text-red-400">{importError}</p>
              )}
            </>
          )}
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
