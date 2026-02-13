import { useReducer, useCallback, useEffect } from "react";
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
import { rvaToFileOffset } from "./pe/parser";

export default function App() {
  const [state, dispatch] = useReducer(appReducer, initialState);

  useEffect(() => {
    disasmEngine.init().then(() => dispatch({ type: "SET_DISASM_READY" }));
  }, []);

  const handleFile = useCallback(
    async (buffer: ArrayBuffer) => {
      dispatch({ type: "SET_LOADING" });
      try {
        const pe = parsePE(buffer);
        dispatch({ type: "SET_PE_FILE", peFile: pe });

        if (state.disasmReady) {
          const textSection = pe.sections.find(
            (s) => s.name === ".text" || (s.characteristics & 0x20000000) !== 0,
          );
          if (textSection) {
            const sectionBytes = new Uint8Array(
              buffer,
              textSection.pointerToRawData,
              textSection.sizeOfRawData,
            );
            const baseAddr =
              pe.optionalHeader.imageBase + textSection.virtualAddress;
            const funcs = disasmEngine.detectFunctions(
              sectionBytes,
              baseAddr,
              pe.is64,
            );
            dispatch({ type: "SET_FUNCTIONS", functions: funcs });
          }
        }
      } catch (e) {
        dispatch({
          type: "SET_ERROR",
          error: e instanceof Error ? e.message : "Failed to parse PE file",
        });
      }
    },
    [state.disasmReady],
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
