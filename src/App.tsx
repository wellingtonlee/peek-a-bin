import { useReducer, useCallback, useEffect, useRef } from "react";
import {
  appReducer,
  initialState,
  AppStateContext,
  AppDispatchContext,
} from "./hooks/usePEFile";
import { parsePE } from "./pe/parser";
import { disasmEngine } from "./disasm/engine";
import { FileLoader } from "./components/FileLoader";
import { Sidebar } from "./components/Sidebar";
import { HeaderView } from "./components/HeaderView";
import { SectionTable } from "./components/SectionTable";
import { DisassemblyView } from "./components/DisassemblyView";
import { HexView } from "./components/HexView";
import { ImportsView } from "./components/ImportsView";
import { ExportsView } from "./components/ExportsView";
import { AddressBar } from "./components/AddressBar";


export default function App() {
  const [state, dispatch] = useReducer(appReducer, initialState);

  const bufferRef = useRef<ArrayBuffer | null>(null);

  useEffect(() => {
    disasmEngine.init()
      .then(() => dispatch({ type: "SET_DISASM_READY" }))
      .catch((e) => dispatch({ type: "SET_ERROR", error: e instanceof Error ? e.message : "Failed to load disassembly engine" }));
  }, []);

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
    const funcs = disasmEngine.detectFunctions(sectionBytes, baseAddr, pe.is64, {
      exports: pe.exports
        .filter((e) => {
          const va = pe.optionalHeader.imageBase + e.address;
          return va >= baseAddr && va < baseAddr + textSection.sizeOfRawData;
        })
        .map((e) => ({ name: e.name, address: pe.optionalHeader.imageBase + e.address })),
      entryPoint: pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint,
    });
    dispatch({ type: "SET_FUNCTIONS", functions: funcs });
  }, [state.peFile, state.disasmReady]);

  const handleFile = useCallback(
    (buffer: ArrayBuffer) => {
      dispatch({ type: "SET_LOADING" });
      try {
        bufferRef.current = buffer;
        const pe = parsePE(buffer);
        dispatch({ type: "SET_PE_FILE", peFile: pe });
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
          </div>
        )}
      </AppDispatchContext.Provider>
    </AppStateContext.Provider>
  );
}
