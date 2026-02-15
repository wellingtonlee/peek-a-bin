import { useReducer, useCallback, useEffect, useRef, useState } from "react";
import {
  appReducer,
  initialState,
  AppStateContext,
  AppDispatchContext,
  type ViewTab,
} from "./hooks/usePEFile";
import { parsePE } from "./pe/parser";
import { disasmEngine } from "./disasm/engine";
import { disasmWorker } from "./workers/disasmClient";
import { buildIATLookup } from "./disasm/operands";
import { FileLoader } from "./components/FileLoader";
import { Sidebar } from "./components/Sidebar";
import { HeaderView } from "./components/HeaderView";
import { SectionTable } from "./components/SectionTable";
import { DisassemblyView } from "./components/DisassemblyView";
import { HexView } from "./components/HexView";
import { ImportsView } from "./components/ImportsView";
import { ExportsView } from "./components/ExportsView";
import { StringsView } from "./components/StringsView";
import { AddressBar } from "./components/AddressBar";
import { StatusBar } from "./components/StatusBar";
import { CommandPalette } from "./components/CommandPalette";


export default function App() {
  const [state, dispatch] = useReducer(appReducer, initialState);
  const [paletteOpen, setPaletteOpen] = useState(false);

  const bufferRef = useRef<ArrayBuffer | null>(null);

  // Ctrl+P / Cmd+P to open command palette
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "p") {
        e.preventDefault();
        setPaletteOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
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

    // Configure worker with maps once, then detect functions off-thread
    const iatLookup = buildIATLookup(pe.imports);
    disasmWorker.configure(pe.strings, iatLookup)
      .then(() => disasmWorker.detectFunctions(sectionBytes, baseAddr, pe.is64, {
        exports: pe.exports
          .filter((e) => {
            const va = pe.optionalHeader.imageBase + e.address;
            return va >= baseAddr && va < baseAddr + textSection.sizeOfRawData;
          })
          .map((e) => ({ name: e.name, address: pe.optionalHeader.imageBase + e.address })),
        entryPoint: pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint,
      }))
      .then((funcs) => dispatch({ type: "SET_FUNCTIONS", functions: funcs }));
  }, [state.peFile, state.disasmReady]);

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
      dispatch({ type: "SET_LOADING" });
      try {
        bufferRef.current = buffer;
        const pe = parsePE(buffer);
        dispatch({ type: "SET_PE_FILE", peFile: pe, fileName });
      } catch (e) {
        dispatch({
          type: "SET_ERROR",
          error: e instanceof Error ? e.message : "Failed to parse PE file",
        });
      }
    },
    [],
  );

  const renderMainView = () => {
    if (!state.peFile) return null;
    switch (state.activeTab) {
      case "headers":
        return <HeaderView />;
      case "sections":
        return <SectionTable />;
      case "disassembly":
        return <DisassemblyView />;
      case "imports":
        return <ImportsView />;
      case "exports":
        return <ExportsView />;
      case "hex":
        return <HexView />;
      case "strings":
        return <StringsView />;
      default:
        return null;
    }
  };

  return (
    <AppStateContext.Provider value={state}>
      <AppDispatchContext.Provider value={dispatch}>
        {!state.peFile ? (
          <FileLoader onFile={handleFile} loading={state.loading} error={state.error} />
        ) : (
          <div className="flex flex-col h-screen">
            <AddressBar />
            <div className="flex flex-1 overflow-hidden">
              <Sidebar />
              <main className="flex-1 overflow-auto">{renderMainView()}</main>
            </div>
            <StatusBar />
          </div>
        )}
        <CommandPalette open={paletteOpen} onClose={() => setPaletteOpen(false)} />
      </AppDispatchContext.Provider>
    </AppStateContext.Provider>
  );
}
