import { useReducer, useCallback, useEffect, useRef, useState, lazy, Suspense } from "react";
import {
  appReducer,
  initialState,
  AppStateContext,
  AppDispatchContext,
  type ViewTab,
} from "./hooks/usePEFile";
import { parsePE } from "./pe/parser";
import { disasmWorker } from "./workers/disasmClient";
import { buildIATLookup } from "./disasm/operands";
import { detectDriver } from "./analysis/driver";
import { detectAnomalies } from "./analysis/anomalies";
import { loadFontSize } from "./llm/settings";
import { loadTheme, applyTheme } from "./styles/themes";
import { saveRecentFile } from "./utils/recentFiles";
import { FileLoader } from "./components/FileLoader";
import { Sidebar } from "./components/Sidebar";
import { HeaderView } from "./components/HeaderView";
import { SectionTable } from "./components/SectionTable";
const DisassemblyView = lazy(() => import("./components/DisassemblyView").then(m => ({ default: m.DisassemblyView })));
const HexView = lazy(() => import("./components/HexView").then(m => ({ default: m.HexView })));
import { ImportsView } from "./components/ImportsView";
import { ExportsView } from "./components/ExportsView";
import { StringsView } from "./components/StringsView";
import { ResourcesView } from "./components/ResourcesView";
import { AnomaliesView } from "./components/AnomaliesView";
import { AddressBar } from "./components/AddressBar";
import { StatusBar } from "./components/StatusBar";
import { CommandPalette } from "./components/CommandPalette";
import { KeyboardShortcuts } from "./components/KeyboardShortcuts";
import { SettingsModal } from "./components/SettingsModal";
import { GoToAddressModal } from "./components/GoToAddressModal";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { GraphOverviewContext, useGraphOverviewState } from "./hooks/useGraphOverview";


export default function App() {
  const [state, dispatch] = useReducer(appReducer, initialState);
  const graphOverviewState = useGraphOverviewState();
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [goToOpen, setGoToOpen] = useState(false);
  const [driverBannerDismissed, setDriverBannerDismissed] = useState(false);
  const [fontSize, setFontSize] = useState(() => loadFontSize());

  // Apply theme on mount and when changed
  useEffect(() => {
    applyTheme(loadTheme());
  }, []);

  useEffect(() => {
    const handler = () => applyTheme(loadTheme());
    window.addEventListener("peek-a-bin:theme-changed", handler);
    return () => window.removeEventListener("peek-a-bin:theme-changed", handler);
  }, []);

  const bufferRef = useRef<ArrayBuffer | null>(null);

  // Ctrl+P / Cmd+P to open command palette, ? to open shortcuts
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "p") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key === "g") {
        e.preventDefault();
        setGoToOpen((v) => !v);
        return;
      }
      if (e.key === "?") {
        const tag = (e.target as HTMLElement)?.tagName?.toLowerCase();
        if (tag === "input" || tag === "textarea" || tag === "select") return;
        if (paletteOpen) return;
        e.preventDefault();
        setShortcutsOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [paletteOpen]);

  useEffect(() => {
    const handler = () => setSettingsOpen(true);
    window.addEventListener("peek-a-bin:open-settings", handler);
    return () => window.removeEventListener("peek-a-bin:open-settings", handler);
  }, []);

  useEffect(() => {
    const handler = () => setFontSize(loadFontSize());
    window.addEventListener("peek-a-bin:font-size-changed", handler);
    return () => window.removeEventListener("peek-a-bin:font-size-changed", handler);
  }, []);

  useEffect(() => {
    disasmWorker.init()
      .then(() => dispatch({ type: "SET_DISASM_READY" }))
      .catch((e) => dispatch({ type: "SET_ERROR", error: e instanceof Error ? e.message : "Failed to load disassembly engine" }));
  }, []);

  // Set document title when file is loaded
  useEffect(() => {
    if (state.fileName) {
      document.title = `${state.fileName} — Peek-a-Bin`;
    } else {
      document.title = "Peek-a-Bin";
    }
  }, [state.fileName]);

  // Load persisted bookmarks + renames from localStorage
  useEffect(() => {
    if (!state.fileName) return;
    try {
      const raw = localStorage.getItem(`peek-a-bin:${state.fileName}`);
      if (raw) {
        const data = JSON.parse(raw);
        dispatch({
          type: "LOAD_PERSISTED",
          bookmarks: data.bookmarks ?? [],
          renames: data.renames ?? {},
          comments: data.comments ?? {},
        });
      }
    } catch { /* ignore corrupt data */ }
  }, [state.fileName]);

  // Persist bookmarks + renames to localStorage
  useEffect(() => {
    if (!state.fileName) return;
    try {
      localStorage.setItem(
        `peek-a-bin:${state.fileName}`,
        JSON.stringify({ bookmarks: state.bookmarks, renames: state.renames, comments: state.comments }),
      );
    } catch { /* quota exceeded */ }
  }, [state.fileName, state.bookmarks, state.renames, state.comments]);

  // Run function detection when both PE file and disasm engine are ready
  useEffect(() => {
    if (!state.peFile || !state.disasmReady) return;
    const pe = state.peFile;
    const buffer = bufferRef.current;
    if (!buffer) return;

    const textSection = pe.sections.find(
      (s) => s.name === ".text" || (s.characteristics & 0x20000000) !== 0,
    );
    if (!textSection) return;

    const sectionBytes = new Uint8Array(
      buffer,
      textSection.pointerToRawData,
      textSection.sizeOfRawData,
    );
    const baseAddr = pe.optionalHeader.imageBase + textSection.virtualAddress;

    // Driver detection
    const driverInfo = detectDriver(pe);
    if (driverInfo.isDriver) {
      dispatch({ type: "SET_DRIVER_INFO", driverInfo });
    }

    // Configure worker with maps once, then detect functions off-thread
    const iatLookup = buildIATLookup(pe.imports);
    const pdataFunctions = pe.runtimeFunctions?.map(rf => ({
      beginAddress: pe.optionalHeader.imageBase + rf.beginAddress,
      endAddress: pe.optionalHeader.imageBase + rf.endAddress,
    }));
    const handlerAddresses = pe.runtimeFunctions
      ?.filter(rf => rf.handlerAddress !== undefined)
      .map(rf => pe.optionalHeader.imageBase + rf.handlerAddress!) ?? [];
    dispatch({ type: "SET_ANALYSIS_PHASE", phase: "detecting-functions" });
    disasmWorker.configure(pe.strings, iatLookup, { driverMode: driverInfo.isDriver })
      .then(() => disasmWorker.detectFunctions(sectionBytes, baseAddr, pe.is64, {
        exports: pe.exports
          .filter((e) => {
            const va = pe.optionalHeader.imageBase + e.address;
            return va >= baseAddr && va < baseAddr + textSection.sizeOfRawData;
          })
          .map((e) => ({ name: e.name, address: pe.optionalHeader.imageBase + e.address })),
        entryPoint: pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint,
        pdataFunctions,
        handlerAddresses,
      }))
      .then(async (funcs) => {
        dispatch({ type: "SET_FUNCTIONS", functions: funcs });

        // IRP dispatch detection for drivers
        if (driverInfo.isDriver && funcs.length > 0) {
          const entryVA = pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint;
          const entryFunc = funcs.find(f => f.address === entryVA);
          if (entryFunc) {
            const entryOffset = entryFunc.address - baseAddr;
            const entrySize = Math.min(entryFunc.size, sectionBytes.length - entryOffset);
            if (entryOffset >= 0 && entrySize > 0) {
              const entryBytes = sectionBytes.subarray(entryOffset, entryOffset + entrySize);
              const entryInsns = await disasmWorker.disassemble(entryBytes, entryFunc.address, pe.is64);
              const irpHandlers = await disasmWorker.detectIRPDispatches(entryInsns, pe.is64);
              if (irpHandlers.length > 0) {
                dispatch({ type: "SET_IRP_HANDLERS", handlers: irpHandlers });
                for (const handler of irpHandlers) {
                  if (handler.handlerAddress > 0) {
                    dispatch({ type: "RENAME_FUNCTION", address: handler.handlerAddress, name: `${handler.irpName}_handler` });
                  }
                }
              }
            }
          }
        }

        // Auto-build xrefs in background after function detection
        const stringAddrs = Array.from(pe.strings.keys());
        const iatAddrs: number[] = [];
        for (const imp of pe.imports) {
          for (const addr of imp.iatAddresses) iatAddrs.push(addr);
        }
        // Derive func entries for call graph
        const funcEntries: [number, number][] = funcs.map(f => [f.address, f.size]);
        // Derive data section ranges for data xrefs
        const dataSections: { va: number; size: number }[] = pe.sections
          .filter(s => {
            const n = s.name.replace(/\0/g, "").trim().toLowerCase();
            return n === ".data" || n === ".rdata" || n === ".bss" ||
              ((s.characteristics & 0x40000000) !== 0 && (s.characteristics & 0x20000000) === 0); // readable, not executable
          })
          .map(s => ({ va: pe.optionalHeader.imageBase + s.virtualAddress, size: s.virtualSize }));

        dispatch({ type: "SET_ANALYSIS_PHASE", phase: "building-xrefs" });
        disasmWorker.buildAllXrefs(sectionBytes, baseAddr, pe.is64, stringAddrs, iatAddrs, funcEntries, dataSections)
          .then(({ stringXrefs, importXrefs, callGraph, dataXrefs }) => {
            dispatch({ type: "SET_XREFS", stringXrefs, importXrefs, dataXrefs });
            dispatch({ type: "SET_CALL_GRAPH", callGraph });
            dispatch({ type: "SET_ANALYSIS_PHASE", phase: "ready" });
          });
      });
  }, [state.peFile, state.disasmReady]);

  // Re-configure worker when strings arrive (they load asynchronously after PE parse)
  const stringsConfiguredRef = useRef(false);
  useEffect(() => {
    if (!state.peFile || !state.disasmReady) return;
    if (state.peFile.strings.size === 0) { stringsConfiguredRef.current = false; return; }
    if (stringsConfiguredRef.current) return;
    stringsConfiguredRef.current = true;
    const pe = state.peFile;
    const buffer = bufferRef.current;
    const iatLookup = buildIATLookup(pe.imports);
    disasmWorker.configure(pe.strings, iatLookup);

    // Re-build xrefs now that strings are available
    if (buffer && state.functions.length > 0) {
      const textSection = pe.sections.find(
        (s) => s.name === ".text" || (s.characteristics & 0x20000000) !== 0,
      );
      if (textSection) {
        const sectionBytes = new Uint8Array(buffer, textSection.pointerToRawData, textSection.sizeOfRawData);
        const baseAddr = pe.optionalHeader.imageBase + textSection.virtualAddress;
        const stringAddrs = Array.from(pe.strings.keys());
        const iatAddrs: number[] = [];
        for (const imp of pe.imports) {
          for (const addr of imp.iatAddresses) iatAddrs.push(addr);
        }
        const funcEntries2: [number, number][] = state.functions.map(f => [f.address, f.size]);
        const dataSections2: { va: number; size: number }[] = pe.sections
          .filter(s => {
            const n = s.name.replace(/\0/g, "").trim().toLowerCase();
            return n === ".data" || n === ".rdata" || n === ".bss" ||
              ((s.characteristics & 0x40000000) !== 0 && (s.characteristics & 0x20000000) === 0);
          })
          .map(s => ({ va: pe.optionalHeader.imageBase + s.virtualAddress, size: s.virtualSize }));
        if (stringAddrs.length > 0 || iatAddrs.length > 0) {
          disasmWorker.buildAllXrefs(sectionBytes, baseAddr, pe.is64, stringAddrs, iatAddrs, funcEntries2, dataSections2)
            .then(({ stringXrefs, importXrefs, callGraph, dataXrefs }) => {
              dispatch({ type: "SET_XREFS", stringXrefs, importXrefs, dataXrefs });
              dispatch({ type: "SET_CALL_GRAPH", callGraph });
            });
        }
      }
    }
  }, [state.peFile, state.peFile?.strings.size, state.disasmReady, state.functions.length, dispatch]);

  // Parse hash on file load — apply saved address/tab from URL
  const hashAppliedRef = useRef(false);
  useEffect(() => {
    if (!state.peFile) { hashAppliedRef.current = false; return; }
    if (hashAppliedRef.current) return;
    hashAppliedRef.current = true;
    const hash = window.location.hash.replace(/^#/, "");
    if (!hash) return;
    const params = new URLSearchParams(hash);
    const addrStr = params.get("addr");
    const tabStr = params.get("tab") as ViewTab | null;
    if (addrStr) {
      const addr = parseInt(addrStr.replace(/^0x/i, ""), 16);
      if (!isNaN(addr)) dispatch({ type: "SET_ADDRESS", address: addr });
    }
    if (tabStr) dispatch({ type: "SET_TAB", tab: tabStr });
  }, [state.peFile, dispatch]);

  // Sync state to URL hash (replaceState to avoid polluting history)
  const prevCallStackLenRef = useRef(0);
  useEffect(() => {
    if (!state.peFile) return;
    const hash = `addr=0x${state.currentAddress.toString(16)}&tab=${state.activeTab}`;
    // Use pushState when callStack changes (significant navigation), replaceState otherwise
    if (state.callStack.length !== prevCallStackLenRef.current) {
      prevCallStackLenRef.current = state.callStack.length;
      window.history.pushState(null, "", `#${hash}`);
    } else {
      window.history.replaceState(null, "", `#${hash}`);
    }
  }, [state.peFile, state.currentAddress, state.activeTab, state.callStack.length]);

  // Listen for browser back/forward (popstate)
  useEffect(() => {
    if (!state.peFile) return;
    const handler = () => {
      const hash = window.location.hash.replace(/^#/, "");
      if (!hash) return;
      const params = new URLSearchParams(hash);
      const addrStr = params.get("addr");
      const tabStr = params.get("tab") as ViewTab | null;
      if (addrStr) {
        const addr = parseInt(addrStr.replace(/^0x/i, ""), 16);
        if (!isNaN(addr) && addr !== state.currentAddress) {
          dispatch({ type: "SET_ADDRESS", address: addr });
        }
      }
      if (tabStr && tabStr !== state.activeTab) {
        dispatch({ type: "SET_TAB", tab: tabStr });
      }
    };
    window.addEventListener("popstate", handler);
    return () => window.removeEventListener("popstate", handler);
  }, [state.peFile, state.currentAddress, state.activeTab, dispatch]);

  const handleFile = useCallback(
    (buffer: ArrayBuffer, fileName: string) => {
      dispatch({ type: "RESET" });
      stringsConfiguredRef.current = false;
      setDriverBannerDismissed(false);
      dispatch({ type: "SET_LOADING" });
      dispatch({ type: "SET_ANALYSIS_PHASE", phase: "parsing" });
      try {
        bufferRef.current = buffer;
        const pe = parsePE(buffer);
        dispatch({ type: "SET_PE_FILE", peFile: pe, fileName });
        // Run anomaly detection synchronously (fast)
        const anomalies = detectAnomalies(pe);
        if (anomalies.length > 0) dispatch({ type: "SET_ANOMALIES", anomalies });
        // Save to IndexedDB for recent files
        saveRecentFile(fileName, buffer);
        // Extract strings off the main thread via worker
        dispatch({ type: "SET_ANALYSIS_PHASE", phase: "extracting-strings" });
        disasmWorker.extractStrings(buffer, pe.sections, pe.optionalHeader.imageBase, pe.is64)
          .then(({ strings, stringTypes }) => {
            dispatch({ type: "SET_STRINGS", strings, stringTypes });
          });
      } catch (e) {
        dispatch({ type: "SET_ANALYSIS_PHASE", phase: "idle" });
        dispatch({
          type: "SET_ERROR",
          error: e instanceof Error ? e.message : "Failed to parse PE file",
        });
      }
    },
    [],
  );

  const mountedTabs = useRef(new Set<string>());
  if (state.peFile) mountedTabs.current.add(state.activeTab);

  const tabComponents: { key: string; Component: React.ComponentType; isLazy?: boolean }[] = [
    { key: "headers", Component: HeaderView },
    { key: "sections", Component: SectionTable },
    { key: "disassembly", Component: DisassemblyView, isLazy: true },
    { key: "imports", Component: ImportsView },
    { key: "exports", Component: ExportsView },
    { key: "hex", Component: HexView, isLazy: true },
    { key: "strings", Component: StringsView },
    { key: "resources", Component: ResourcesView },
    { key: "anomalies", Component: AnomaliesView },
  ];

  const renderMainView = () => {
    if (!state.peFile) return null;
    return tabComponents.map(({ key, Component, isLazy }) =>
      mountedTabs.current.has(key) ? (
        <div key={key} className={state.activeTab === key ? "h-full" : "hidden"}>
          {isLazy ? (
            <Suspense fallback={<div className="flex items-center justify-center h-full text-gray-500 text-sm">Loading...</div>}>
              <Component />
            </Suspense>
          ) : (
            <Component />
          )}
        </div>
      ) : null,
    );
  };

  return (
    <AppStateContext.Provider value={state}>
      <AppDispatchContext.Provider value={dispatch}>
        {!state.peFile ? (
          <FileLoader onFile={handleFile} loading={state.loading} error={state.error} analysisPhase={state.analysisPhase} fileName={state.fileName} />
        ) : (
          <div className="flex flex-col h-screen app-bg" style={{ '--mono-font-size': `${fontSize}px` } as React.CSSProperties}>
            <AddressBar />
            {state.driverInfo?.isDriver && !driverBannerDismissed && (
              <div className="bg-amber-900/40 border-b border-amber-700/50 px-4 py-1.5 flex items-center gap-3 text-xs shrink-0">
                <span className="font-bold text-amber-400 tracking-wide">KERNEL DRIVER</span>
                <span className="text-amber-300/80">
                  Subsystem: NATIVE{state.driverInfo.isWDM && ' | WDM'}
                </span>
                <span className="text-amber-300/60">
                  {state.driverInfo.kernelImportCount} kernel APIs from {state.driverInfo.kernelModules.length} module{state.driverInfo.kernelModules.length !== 1 ? 's' : ''}
                </span>
                {state.irpHandlers.length > 0 && (
                  <span className="text-amber-300/60">
                    | {state.irpHandlers.length} IRP handler{state.irpHandlers.length !== 1 ? 's' : ''}
                  </span>
                )}
                <div className="flex-1" />
                <button
                  onClick={() => setDriverBannerDismissed(true)}
                  className="text-amber-500 hover:text-amber-300 text-sm leading-none"
                  title="Dismiss"
                >
                  &times;
                </button>
              </div>
            )}
            <GraphOverviewContext.Provider value={graphOverviewState}>
            <div className="flex flex-1 overflow-hidden">
              <Sidebar />
              <main className="flex-1 overflow-auto">
                <ErrorBoundary>{renderMainView()}</ErrorBoundary>
              </main>
            </div>
            </GraphOverviewContext.Provider>
            <StatusBar />
          </div>
        )}
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
        <KeyboardShortcuts open={shortcutsOpen} onClose={() => setShortcutsOpen(false)} />
        <SettingsModal open={settingsOpen} onClose={() => setSettingsOpen(false)} />
        <GoToAddressModal open={goToOpen} onClose={() => setGoToOpen(false)} />
      </AppDispatchContext.Provider>
    </AppStateContext.Provider>
  );
}
