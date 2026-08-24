import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useReducer,
  useRef,
  useState,
} from "react";
import { detectAnomalies } from "./analysis/anomalies";
import { detectDriver } from "./analysis/driver";
import {
  analysisNotice,
  analysisRejection,
  formatTabList,
  VIEW_TAB_LABELS,
} from "./components/analysisNotice";
import { FileLoader } from "./components/FileLoader";
import { HeaderView } from "./components/HeaderView";
import { SectionTable } from "./components/SectionTable";
import { Sidebar } from "./components/Sidebar";
import { tabId, tabPanelId } from "./components/tabIds";
import { buildDataWindows } from "./disasm/dataWindows";
import { buildIATLookup } from "./disasm/operands";
import { MAX_SYNC_FILE_METRIC_BYTES } from "./hooks/asyncMetricState";
import {
  AppDispatchContext,
  AppStateContext,
  appReducer,
  initialState,
  parseViewTab,
  type ViewTab,
} from "./hooks/usePEFile";
import { loadFontSize } from "./llm/settings";
import { parsePE } from "./pe/parser";
import { dataSectionRanges, findCodeSection } from "./pe/sections";
import { applyTheme, loadTheme } from "./styles/themes";
import { validateAnnotations } from "./utils/exportSchema";
import { saveRecentFile } from "./utils/recentFiles";
import { disasmWorker } from "./workers/disasmClient";
import { metricsWorker } from "./workers/metricsClient";
import { sectionRanges } from "./workers/metricsDispatch";

const DisassemblyView = lazy(() =>
  import("./components/DisassemblyView").then((m) => ({ default: m.DisassemblyView })),
);
const HexView = lazy(() => import("./components/HexView").then((m) => ({ default: m.HexView })));

import { AddressBar } from "./components/AddressBar";
import { AIReportPanel } from "./components/AIReportPanel";
import { AnomaliesView } from "./components/AnomaliesView";
import { BatchRenameModal } from "./components/BatchRenameModal";
import { CommandPalette } from "./components/CommandPalette";
import { ErrorBoundary } from "./components/ErrorBoundary";
import { ExportsView } from "./components/ExportsView";
import { GoToAddressModal } from "./components/GoToAddressModal";
import { ImportsView } from "./components/ImportsView";
import { KeyboardShortcuts } from "./components/KeyboardShortcuts";
import { ResourcesView } from "./components/ResourcesView";
import { SettingsModal } from "./components/SettingsModal";
import { StatusBar } from "./components/StatusBar";
import { StringsView } from "./components/StringsView";
import { useAIReport } from "./hooks/useAIReport";
import { useBatchRename } from "./hooks/useBatchRename";
import { GraphOverviewContext, useGraphOverviewState } from "./hooks/useGraphOverview";
import { useMcpSync } from "./hooks/useMcpSync";
import { useVulnScanner } from "./hooks/useVulnScanner";

export default function App() {
  const [state, dispatch] = useReducer(appReducer, initialState);
  const graphOverviewState = useGraphOverviewState();
  const mcpStatus = useMcpSync(state.fileName, dispatch);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [goToOpen, setGoToOpen] = useState(false);
  const [driverBannerDismissed, setDriverBannerDismissed] = useState(false);
  const [noticeDismissed, setNoticeDismissed] = useState(false);
  const [fontSize, setFontSize] = useState(() => loadFontSize());
  const aiReport = useAIReport(state, dispatch);
  const batchRename = useBatchRename(state, dispatch);
  const vulnScanner = useVulnScanner(state, dispatch);

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
      if ((e.ctrlKey || e.metaKey) && e.shiftKey && (e.key === "a" || e.key === "A")) {
        e.preventDefault();
        // Chat visibility lives in DisassemblyView (`showChat`), which listens for
        // this event. This shortcut previously toggled a local state that nothing
        // read, so it never opened the panel.
        window.dispatchEvent(new CustomEvent("peek-a-bin:open-chat"));
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

  // AI feature event listeners
  useEffect(() => {
    const handleReport = () => aiReport.generateReport();
    const handleBatchRename = () => batchRename.startBatchRename();
    const handleAiScan = () => vulnScanner.scanSuspicious();
    window.addEventListener("peek-a-bin:generate-report", handleReport);
    window.addEventListener("peek-a-bin:batch-rename", handleBatchRename);
    window.addEventListener("peek-a-bin:ai-scan", handleAiScan);
    return () => {
      window.removeEventListener("peek-a-bin:generate-report", handleReport);
      window.removeEventListener("peek-a-bin:batch-rename", handleBatchRename);
      window.removeEventListener("peek-a-bin:ai-scan", handleAiScan);
    };
  }, [aiReport.generateReport, batchRename.startBatchRename, vulnScanner.scanSuspicious]);

  useEffect(() => {
    const handler = () => setFontSize(loadFontSize());
    window.addEventListener("peek-a-bin:font-size-changed", handler);
    return () => window.removeEventListener("peek-a-bin:font-size-changed", handler);
  }, []);

  useEffect(() => {
    disasmWorker
      .init()
      .then(() => dispatch({ type: "SET_DISASM_READY" }))
      // Not a bare SET_ERROR. `state.error` renders only in FileLoader, which
      // unmounts the moment a PE parses, so an engine that died under an open
      // file said nothing at all — and every surface keyed on `!disasmReady`
      // spun "Loading engine..." for the rest of the session. This action sets
      // `error` as well, so the pre-file case is unchanged, and records the
      // failure as its own session-level fact for the notice to report
      // (peek-a-bin-b3jn).
      .catch((e) =>
        dispatch({
          type: "SET_DISASM_FAILED",
          error: e instanceof Error ? e.message : "Failed to load disassembly engine",
        }),
      );
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
        // localStorage is editable by the user and by any script on this origin,
        // so the parsed blob is untrusted — validate before it reaches the reducer.
        const data = validateAnnotations(JSON.parse(raw));
        if (data) {
          dispatch({
            type: "LOAD_PERSISTED",
            bookmarks: data.bookmarks,
            renames: data.renames,
            comments: data.comments,
          });
        } else {
          console.warn("[peek-a-bin] ignoring malformed persisted annotations");
        }
      }
    } catch {
      /* ignore corrupt data */
    }
  }, [state.fileName]);

  // Persist bookmarks + renames to localStorage
  useEffect(() => {
    if (!state.fileName) return;
    try {
      localStorage.setItem(
        `peek-a-bin:${state.fileName}`,
        JSON.stringify({
          bookmarks: state.bookmarks,
          renames: state.renames,
          comments: state.comments,
        }),
      );
    } catch {
      /* quota exceeded */
    }
  }, [state.fileName, state.bookmarks, state.renames, state.comments]);

  /**
   * The image this analysis chain has already been started for.
   *
   * `SET_STRINGS` replaces `state.peFile` with a new object (it spreads to add
   * the extracted strings), so this effect's dependency changed when the
   * strings landed and the WHOLE chain ran a second time — a second
   * `detectFunctions` over the same bytes, a second `SET_FUNCTIONS`, a second
   * `buildAllXrefs`, and `analysisPhase` bouncing from "ready" back to
   * "detecting-functions". The buffer is the file's stable identity, so
   * comparing against it runs the chain exactly once per loaded image.
   */
  const analyzedBufferRef = useRef<ArrayBuffer | null>(null);
  /**
   * The string map the last xref build used, for the rebuild guard below.
   * Identity, not size: a map that is the same object is provably the same set.
   */
  const xrefStringsRef = useRef<Map<number, string> | null>(null);
  /**
   * The latest PE, readable from inside the async chain.
   *
   * Assigned during render, not in an effect: the chain is already running by
   * the time an effect would fire, and what it needs is whatever strings exist
   * when it reaches the xref build — not the ones that existed when it started.
   * (`handleKeyDown` in DisassemblyView uses the same pattern, for the same
   * reason and after the same class of bug.)
   */
  const latestPeRef = useRef(state.peFile);
  latestPeRef.current = state.peFile;

  // Run function detection when both PE file and disasm engine are ready
  useEffect(() => {
    if (!state.peFile) return;
    if (!state.disasmReady) {
      // The engine is either still loading — in which case this effect re-runs
      // when it lands — or it is never going to. The second case has to reach a
      // *terminal* phase here, above `analyzedBufferRef`, or the phase stays on
      // whatever `handleFile` last dispatched and ANALYSIS_IN_PROGRESS keeps the
      // sidebar skeleton and the status bar spinner going for good. Exactly the
      // shape of peek-a-bin-bo3b's silent return, and reached by both orders: a
      // file opened after the engine died, and an engine that died with one open
      // (peek-a-bin-b3jn). `analysisNotice` outranks the failure with the
      // engine's own message, so "failed" here is not what the user is told.
      if (state.disasmFailed) dispatch({ type: "SET_ANALYSIS_PHASE", phase: "failed" });
      return;
    }
    const pe = state.peFile;
    const buffer = bufferRef.current;
    if (!buffer) return;
    if (analyzedBufferRef.current === buffer) return;
    analyzedBufferRef.current = buffer;

    const textSection = findCodeSection(pe.sections);
    // A bare `return` here left the phase on "extracting-strings" — the last
    // value `handleFile` dispatched — with every later SET_ANALYSIS_PHASE in
    // this effect downstream of the return, so nothing could ever move it and
    // the status bar spun for good. A resource-only DLL genuinely has no
    // executable section, so this is an ordinary file, not malformed input:
    // the phase is terminal but is *not* "failed" (peek-a-bin-bo3b).
    if (!textSection) {
      dispatch({ type: "SET_ANALYSIS_PHASE", phase: "no-code" });
      return;
    }

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
    dispatch({ type: "SET_IAT_MAP", iatMap: iatLookup });
    const pdataFunctions = pe.runtimeFunctions?.map((rf) => ({
      beginAddress: pe.optionalHeader.imageBase + rf.beginAddress,
      endAddress: pe.optionalHeader.imageBase + rf.endAddress,
    }));
    const handlerAddresses =
      pe.runtimeFunctions
        ?.filter((rf) => rf.handlerAddress !== undefined)
        .map((rf) => pe.optionalHeader.imageBase + rf.handlerAddress!) ?? [];
    dispatch({ type: "SET_ANALYSIS_PHASE", phase: "detecting-functions" });
    disasmWorker
      .configure(pe.strings, iatLookup, {
        driverMode: driverInfo.isDriver,
        // The machine type, not `is64`, is what picks the disassembler — see
        // src/disasm/arch.ts. Sent on this first configure only; the later one
        // (strings arriving) leaves the worker's architecture alone.
        machine: pe.coffHeader.machine,
        // Sent alongside it, and read on the far side only by the ARM64
        // decode-rate refusal's message: a non-zero value is the format's own
        // declaration that the image is hybrid, so the refusal can state that
        // instead of inferring it. `undefined` — no load-config directory, or a
        // structure too short to reach the field — is the ordinary case and
        // produces exactly the message this threw before.
        chpeMetadataPointer: pe.loadConfig?.chpeMetadataPointer,
      })
      .then(() =>
        disasmWorker.detectFunctions(sectionBytes, baseAddr, pe.is64, {
          exports: pe.exports
            .filter((e) => {
              const va = pe.optionalHeader.imageBase + e.address;
              return va >= baseAddr && va < baseAddr + textSection.sizeOfRawData;
            })
            .map((e) => ({ name: e.name, address: pe.optionalHeader.imageBase + e.address })),
          entryPoint: pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint,
          pdataFunctions,
          handlerAddresses,
          // `.rdata` &c: an x64 switch's jump table lives outside .text, so
          // without these the detector reads none of its entries. Packed into
          // one transferable buffer by the client, not cloned per window.
          dataWindows: buildDataWindows(buffer, pe.sections, pe.optionalHeader.imageBase),
        }),
      )
      .then(async ({ functions: funcs, omitted }) => {
        dispatch({ type: "SET_FUNCTIONS", functions: funcs });
        // A non-empty `omitted` means this function list is narrower than a
        // complete one — the decoder-fed passes named here did not run, either
        // because the image has no decoder or because Capstone is dead
        // (peek-a-bin-4s9). The list still looks exactly like a whole answer,
        // which is the defect the field exists to prevent, so say so — in the
        // UI, via `analysisNotice`, not only here (peek-a-bin-ipzf). The
        // unsupported-architecture case is also derived independently from the
        // COFF header; the null-Capstone case has no such backstop, and this
        // dispatch is its only signal. The console line stays for the developer
        // reading a session's log, where the pass names are the wire values.
        dispatch({ type: "SET_OMITTED_PASSES", omitted });
        if (omitted.length > 0) {
          console.warn(
            `[peek-a-bin] function detection ran without ${omitted.join(", ")} — ` +
              `the function list is narrower than a complete one`,
          );
        }
        // Pre-send func map + jump tables to worker for decompilation
        const funcEntryMap = new Map<number, { name: string; address: number }>();
        for (const fn of funcs)
          funcEntryMap.set(fn.address, { name: fn.name, address: fn.address });
        disasmWorker.configureDecompileMaps(funcEntryMap);

        // IRP dispatch detection for drivers
        if (driverInfo.isDriver && funcs.length > 0) {
          const entryVA = pe.optionalHeader.imageBase + pe.optionalHeader.addressOfEntryPoint;
          const entryFunc = funcs.find((f) => f.address === entryVA);
          if (entryFunc) {
            const entryOffset = entryFunc.address - baseAddr;
            const entrySize = Math.min(entryFunc.size, sectionBytes.length - entryOffset);
            if (entryOffset >= 0 && entrySize > 0) {
              const entryBytes = sectionBytes.subarray(entryOffset, entryOffset + entrySize);
              const entryInsns = await disasmWorker.disassemble(
                entryBytes,
                entryFunc.address,
                pe.is64,
              );
              const irpHandlers = await disasmWorker.detectIRPDispatches(entryInsns, pe.is64);
              if (irpHandlers.length > 0) {
                dispatch({ type: "SET_IRP_HANDLERS", handlers: irpHandlers });
                for (const handler of irpHandlers) {
                  if (handler.handlerAddress > 0) {
                    dispatch({
                      type: "RENAME_FUNCTION",
                      address: handler.handlerAddress,
                      name: `${handler.irpName}_handler`,
                    });
                  }
                }
              }
            }
          }
        }

        // Auto-build xrefs in background after function detection.
        //
        // The strings come from the ref, not from this closure's `pe`: string
        // extraction is a separate worker call posted before this one, so by
        // now it has almost always answered and the app has a newer PEFile with
        // the strings in it. Reading them here means this build is complete,
        // and the rebuild the strings effect below would otherwise post — a
        // second whole-`.text` sweep, 155 ms on t64-arm.exe — is skipped.
        const strings = latestPeRef.current?.strings ?? pe.strings;
        xrefStringsRef.current = strings;
        const stringAddrs = Array.from(strings.keys());
        const iatAddrs: number[] = [];
        for (const imp of pe.imports) {
          for (const addr of imp.iatAddresses) iatAddrs.push(addr);
        }
        // Derive func entries for call graph
        const funcEntries: [number, number][] = funcs.map((f) => [f.address, f.size]);
        // Derive data section ranges for data xrefs
        const dataSections = dataSectionRanges(pe.sections, pe.optionalHeader.imageBase);

        dispatch({ type: "SET_ANALYSIS_PHASE", phase: "building-xrefs" });
        return disasmWorker
          .buildAllXrefs(
            sectionBytes,
            baseAddr,
            pe.is64,
            stringAddrs,
            iatAddrs,
            funcEntries,
            dataSections,
          )
          .then(({ stringXrefs, importXrefs, callGraph, dataXrefs }) => {
            dispatch({ type: "SET_XREFS", stringXrefs, importXrefs, dataXrefs });
            dispatch({ type: "SET_CALL_GRAPH", callGraph });
            dispatch({ type: "SET_ANALYSIS_PHASE", phase: "ready" });
          });
      })
      // Without this, any worker failure in the chain above left analysisPhase
      // pinned on its last value forever, with a spinner and no feedback. Which
      // terminal phase, and what message, is `analysisRejection`'s decision and
      // not this callback's: the request watchdog stopping a stage that was
      // still working is not the same event as the analysis failing, and
      // reporting both as "failed" told a user whose large image merely needed
      // longer the same thing as a user who dropped a truncated file
      // (peek-a-bin-meai). Nothing here can be reached by a test, which is why
      // the decision is a pure function elsewhere.
      .catch((err) => {
        console.error("[peek-a-bin] analysis stopped", err);
        const { phase, error } = analysisRejection(err);
        dispatch({ type: "SET_ANALYSIS_PHASE", phase });
        dispatch({ type: "SET_ERROR", error });
      });
    // `disasmFailed` is listed because the early return above reads it: the
    // engine can reject *after* a file is open, and without it this effect never
    // re-runs to dispatch the terminal phase for that order.
  }, [state.peFile, state.disasmReady, state.disasmFailed]);

  // Re-configure worker when strings arrive (they load asynchronously after PE parse)
  const stringsConfiguredRef = useRef(false);
  useEffect(() => {
    if (!state.peFile || !state.disasmReady) return;
    if (state.peFile.strings.size === 0) {
      stringsConfiguredRef.current = false;
      return;
    }
    if (stringsConfiguredRef.current) return;
    stringsConfiguredRef.current = true;
    const pe = state.peFile;
    const buffer = bufferRef.current;
    const iatLookup = buildIATLookup(pe.imports);
    disasmWorker.configure(pe.strings, iatLookup);

    // Re-build xrefs now that strings are available — unless the detection
    // chain already built them with exactly this map, which is the usual case
    // now that it reads the newest one. Identity comparison: the same Map
    // object is the same set of strings, and a different file always has a
    // different object, so this cannot skip wrongly across files.
    if (buffer && state.functions.length > 0 && xrefStringsRef.current !== pe.strings) {
      const textSection = findCodeSection(pe.sections);
      if (textSection) {
        const sectionBytes = new Uint8Array(
          buffer,
          textSection.pointerToRawData,
          textSection.sizeOfRawData,
        );
        const baseAddr = pe.optionalHeader.imageBase + textSection.virtualAddress;
        const stringAddrs = Array.from(pe.strings.keys());
        const iatAddrs: number[] = [];
        for (const imp of pe.imports) {
          for (const addr of imp.iatAddresses) iatAddrs.push(addr);
        }
        const funcEntries2: [number, number][] = state.functions.map((f) => [f.address, f.size]);
        const dataSections2 = dataSectionRanges(pe.sections, pe.optionalHeader.imageBase);
        if (stringAddrs.length > 0 || iatAddrs.length > 0) {
          xrefStringsRef.current = pe.strings;
          disasmWorker
            .buildAllXrefs(
              sectionBytes,
              baseAddr,
              pe.is64,
              stringAddrs,
              iatAddrs,
              funcEntries2,
              dataSections2,
            )
            .then(({ stringXrefs, importXrefs, callGraph, dataXrefs }) => {
              dispatch({ type: "SET_XREFS", stringXrefs, importXrefs, dataXrefs });
              dispatch({ type: "SET_CALL_GRAPH", callGraph });
            })
            // Non-fatal: the first xref pass already ran, this only enriches it
            // with late-arriving strings. Log rather than fail the whole view.
            .catch((err) => console.error("[peek-a-bin] xref rebuild failed", err));
        }
      }
    }
    // state.functions (not .length) because the body maps over it, and `dispatch`
    // dropped: useReducer guarantees its identity, so it was inert. The
    // stringsConfiguredRef guard above makes any extra fire a no-op.
  }, [state.peFile, state.peFile?.strings.size, state.disasmReady, state.functions]);

  // Anomaly detection.
  //
  // Two of its checks are whole-file walks — `validateChecksum` and every
  // section's entropy — measured together at ~910 ms on a synthetic 253 MiB PE
  // (138 ms + 772 ms, interleaved medians). That ran inline in `handleFile`,
  // i.e. on the main thread, with nothing on screen to show for it. The metrics
  // worker already computes exactly this pair for the Headers and Sections
  // tabs and caches it per `ArrayBuffer`, so on a large file this asks for the
  // same result: whoever gets there first pays, the rest share it.
  //
  // The threshold is `useFileMetrics`'s: below it the walks cost less than the
  // hand-off and stay inline, which is every ordinary binary (the largest real
  // PE on the machine this was measured on is 273 KB).
  const anomalyBufferRef = useRef<ArrayBuffer | null>(null);
  useEffect(() => {
    const pe = state.peFile;
    if (!pe) {
      anomalyBufferRef.current = null;
      return;
    }
    // `SET_STRINGS` gives a new PEFile object for the same image; nothing this
    // pass reads changed, so run it once per buffer rather than once per object.
    if (anomalyBufferRef.current === pe.buffer) return;
    anomalyBufferRef.current = pe.buffer;

    if (pe.buffer.byteLength <= MAX_SYNC_FILE_METRIC_BYTES) {
      const anomalies = detectAnomalies(pe);
      if (anomalies.length > 0) dispatch({ type: "SET_ANOMALIES", anomalies });
      return;
    }

    // The stale-result guard, the same scheme as `hooks/asyncMetricState.ts`:
    // the request carries the identity of the file it was made for and its
    // reply is dropped unless that is still the loaded file. A user who drops a
    // 253 MiB image and then a small one while the first is still walking would
    // otherwise get the big file's anomalies listed under the small one.
    let cancelled = false;
    metricsWorker
      .fileMetrics(pe.buffer, pe.dosHeader.e_lfanew, pe.optionalHeader.checksum, sectionRanges(pe))
      .then((metrics) => {
        if (cancelled) return;
        const anomalies = detectAnomalies(pe, metrics);
        if (anomalies.length > 0) dispatch({ type: "SET_ANOMALIES", anomalies });
      })
      .catch((err) => {
        if (cancelled) return;
        // Not fatal — the rest of the analysis does not depend on this — but not
        // silent either: `detectAnomalies` still runs every check that needs no
        // whole-file walk, and records that the other two did not run.
        console.error("[peek-a-bin] file metrics failed; anomaly checks skipped", err);
        const anomalies = detectAnomalies(pe, { checksum: null, sectionEntropies: null });
        if (anomalies.length > 0) dispatch({ type: "SET_ANOMALIES", anomalies });
      });
    return () => {
      cancelled = true;
    };
    // dispatch dropped: useReducer guarantees a stable identity.
  }, [state.peFile]);

  // Parse hash on file load — apply saved address/tab from URL
  const hashAppliedRef = useRef(false);
  useEffect(() => {
    if (!state.peFile) {
      hashAppliedRef.current = false;
      return;
    }
    if (hashAppliedRef.current) return;
    hashAppliedRef.current = true;
    const hash = window.location.hash.replace(/^#/, "");
    if (!hash) return;
    const params = new URLSearchParams(hash);
    const addrStr = params.get("addr");
    const tabStr = parseViewTab(params.get("tab"));
    if (addrStr) {
      const addr = parseInt(addrStr.replace(/^0x/i, ""), 16);
      if (!Number.isNaN(addr)) dispatch({ type: "SET_ADDRESS", address: addr });
    }
    if (tabStr) dispatch({ type: "SET_TAB", tab: tabStr });
    // dispatch dropped: useReducer guarantees a stable identity, so it never
    // triggered a re-run.
  }, [state.peFile]);

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
      const tabStr = parseViewTab(params.get("tab"));
      if (addrStr) {
        const addr = parseInt(addrStr.replace(/^0x/i, ""), 16);
        if (!Number.isNaN(addr) && addr !== state.currentAddress) {
          dispatch({ type: "SET_ADDRESS", address: addr });
        }
      }
      if (tabStr && tabStr !== state.activeTab) {
        dispatch({ type: "SET_TAB", tab: tabStr });
      }
    };
    window.addEventListener("popstate", handler);
    return () => window.removeEventListener("popstate", handler);
    // dispatch dropped: useReducer guarantees a stable identity, so it never
    // caused the popstate listener to be re-registered.
  }, [state.peFile, state.currentAddress, state.activeTab]);

  // `file` is present only on the drop/browse path — `loadRecentFile` returns an
  // ArrayBuffer out of IndexedDB and the demo binary arrives via
  // `fetch().arrayBuffer()`, so two of the three load paths have no `File` and
  // keep copying the buffer for the metrics worker. Where there is one, handing
  // it over is a pure win: a Blob is structured-cloneable by reference, so the
  // post is O(1) and the worker reads the bytes itself.
  const handleFile = useCallback((buffer: ArrayBuffer, fileName: string, file?: File) => {
    dispatch({ type: "RESET" });
    stringsConfiguredRef.current = false;
    setDriverBannerDismissed(false);
    setNoticeDismissed(false);
    dispatch({ type: "SET_LOADING" });
    dispatch({ type: "SET_ANALYSIS_PHASE", phase: "parsing" });
    try {
      const pe = parsePE(buffer);
      // Assigned only once the parse succeeded. Assigning before it meant a
      // rejected file — a 275 MB ELF dropped on the app — stayed pinned by this
      // ref until some later load happened to replace it.
      bufferRef.current = buffer;
      // Same placement rule as `bufferRef` above: only once the parse succeeded,
      // so a rejected file does not leave a handle registered. The registry is a
      // WeakMap keyed on this buffer, so nothing here has to be torn down — the
      // File becomes unreachable with the buffer it describes.
      if (file) metricsWorker.registerSourceBlob(buffer, file);
      // And the disasm worker, for the same reason and with the same lifetime:
      // `extractStrings` below is the one RPC whose argument is the whole image,
      // so its copy is the whole image too. Told separately rather than through a
      // shared registry, so that being told is a fact about each client's own
      // wiring (peek-a-bin-736).
      if (file) disasmWorker.registerSourceBlob(buffer, file);
      // The load handshake, and it must stay *above* the dispatch below.
      //
      // The architecture is a property of this file, and every later decode
      // request carries it from here. Telling the worker in the detection
      // effect instead was a race: `useDisassemblyRows` posts its own
      // disassembly from a different effect in a lazily-loaded child, and a
      // child's effect runs before its parent's, so on the second file of a
      // session the decode was posted before the `configure` that named the
      // architecture — and the worker, servicing serially, answered it with the
      // previous image's decoder (peek-a-bin-x4o2). Declared here, before the
      // reducer has even seen the file, nothing can decode ahead of it.
      disasmWorker.setImage(pe.coffHeader.machine);
      dispatch({ type: "SET_PE_FILE", peFile: pe, fileName });
      // Anomaly detection runs in the effect below — it needs two whole-file
      // walks, which is ~910 ms of main-thread work on a 253 MiB image.
      // Save to IndexedDB for recent files
      void saveRecentFile(fileName, buffer).catch((err) =>
        console.error("[peek-a-bin] failed to save recent file", err),
      );
      // Extract strings off the main thread via worker
      dispatch({ type: "SET_ANALYSIS_PHASE", phase: "extracting-strings" });
      disasmWorker
        .extractStrings(buffer, pe.sections, pe.optionalHeader.imageBase, pe.is64)
        .then(({ strings, stringTypes }) => {
          dispatch({ type: "SET_STRINGS", strings, stringTypes });
        })
        // Non-fatal: the PE is loaded and browsable without extracted strings.
        .catch((err) => console.error("[peek-a-bin] string extraction failed", err));
    } catch (e) {
      // RESET above already dropped the previous PE, so the previous buffer is
      // unreachable through the UI; drop this ref's hold on it too rather than
      // keeping a whole file alive behind an error screen.
      bufferRef.current = null;
      dispatch({ type: "SET_ANALYSIS_PHASE", phase: "idle" });
      dispatch({
        type: "SET_ERROR",
        error: e instanceof Error ? e.message : "Failed to parse PE file",
      });
    }
  }, []);

  const mountedTabs = useRef(new Set<ViewTab>());
  if (state.peFile) mountedTabs.current.add(state.activeTab);

  const tabComponents: { key: ViewTab; Component: React.ComponentType; isLazy?: boolean }[] = [
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

  const closePalette = useCallback(() => setPaletteOpen(false), []);
  const closeShortcuts = useCallback(() => setShortcutsOpen(false), []);
  const closeSettings = useCallback(() => setSettingsOpen(false), []);
  const closeGoTo = useCallback(() => setGoToOpen(false), []);
  const fontStyle = useMemo(
    () => ({ "--mono-font-size": `${fontSize}px` }) as React.CSSProperties,
    [fontSize],
  );

  /**
   * Why there is no disassembly, when there is none.
   *
   * `state.error` reaches nothing else once a PE has parsed: FileLoader is its
   * only other consumer and it unmounts as soon as `peFile` is set, so the
   * analysis chain's `SET_ERROR` — including the engine's refusal for an image
   * with no decoder — had no render site at all. This banner is it. The
   * decision itself is in ./components/analysisNotice.ts, where a test can
   * reach it.
   */
  const machine = state.peFile?.coffHeader.machine;
  const notice = useMemo(
    () =>
      analysisNotice({
        machine,
        phase: state.analysisPhase,
        error: state.error,
        omitted: state.omittedPasses,
        engineError: state.disasmFailed,
      }),
    [machine, state.analysisPhase, state.error, state.omittedPasses, state.disasmFailed],
  );

  const renderMainView = () => {
    if (!state.peFile) return null;
    return tabComponents.map(({ key, Component, isLazy }) => (
      /* THE WRAPPER IS RENDERED FOR EVERY TAB; THE COMPONENT INSIDE IT IS NOT.
         This used to return `null` for an unvisited tab, wrapper and all. The
         wrapper is now unconditional so that `AddressBar`'s
         `aria-controls={tabPanelId(key)}` always resolves to a real element:
         a reference naming an id nothing has is worse than no reference,
         because assistive technology is entitled to look it up and find
         nothing — the same judgement `activeDescendantId` makes in
         `components/listboxIds.ts` when it answers `undefined` rather than "".
         It is also what the WAI-ARIA tabs pattern does: its inactive panels are
         present and hidden, not absent.

         WHAT DID NOT CHANGE is the mounting rule this exists beside. A tab's
         COMPONENT still mounts only once the tab has been visited, so an empty
         wrapper carries no cost and `DisassemblyView`/`HexView` are still not
         imported until asked for. The empty ones are only ever the hidden ones:
         `mountedTabs` takes `state.activeTab` above, so the SELECTED tab's
         panel always has its component in it (peek-a-bin-w50c). */
      <div
        key={key}
        id={tabPanelId(key)}
        role="tabpanel"
        aria-labelledby={tabId(key)}
        /* A panel with no focusable content needs a tab stop of its own or a
           keyboard user cannot reach the region they just switched to — and
           most of these are static tables (headers, sections, imports, exports,
           resources). Which panes those are is a runtime question about their
           rendered content, not something this list knows, so every shown panel
           gets the stop and the ones with focusable content pay one extra Tab.
           Only the shown panel: the others are `display: none` in a browser and
           must not be in the tab order at all. */
        tabIndex={state.activeTab === key ? 0 : -1}
        className={state.activeTab === key ? "h-full" : "hidden"}
      >
        {mountedTabs.current.has(key) ? (
          /* ONE BOUNDARY PER PANE, and the placement is the whole point.
             A single boundary around this map — which is what was here — put
             every tab behind one `hasError`: a throw in the Hex view replaced
             headers, sections, disassembly, imports, exports, strings,
             resources and anomalies with the same fallback, and since the
             boundary sat ABOVE the tab switch, changing tabs could not recover
             it either. Every visited tab stays mounted (`mountedTabs`), so the
             blast radius was every tab the user had ever opened
             (peek-a-bin-p0qw). */
          <ErrorBoundary label={VIEW_TAB_LABELS[key]}>
            {isLazy ? (
              <Suspense
                fallback={
                  <div className="flex items-center justify-center h-full text-gray-500 text-sm">
                    Loading...
                  </div>
                }
              >
                <Component />
              </Suspense>
            ) : (
              <Component />
            )}
          </ErrorBoundary>
        ) : null}
      </div>
    ));
  };

  return (
    <AppStateContext.Provider value={state}>
      <AppDispatchContext.Provider value={dispatch}>
        {!state.peFile ? (
          <FileLoader
            onFile={handleFile}
            loading={state.loading}
            error={state.error}
            analysisPhase={state.analysisPhase}
            fileName={state.fileName}
          />
        ) : (
          <div className="flex flex-col h-screen app-bg" style={fontStyle}>
            <AddressBar />
            {state.driverInfo?.isDriver && !driverBannerDismissed && (
              <div className="bg-amber-900/40 border-b border-amber-700/50 px-4 py-1.5 flex items-center gap-3 text-xs shrink-0">
                <span className="font-bold text-amber-400 tracking-wide">KERNEL DRIVER</span>
                <span className="text-amber-300/80">
                  Subsystem: NATIVE{state.driverInfo.isWDM && " | WDM"}
                </span>
                <span className="text-amber-300/60">
                  {state.driverInfo.kernelImportCount} kernel APIs from{" "}
                  {state.driverInfo.kernelModules.length} module
                  {state.driverInfo.kernelModules.length !== 1 ? "s" : ""}
                </span>
                {state.irpHandlers.length > 0 && (
                  <span className="text-amber-300/60">
                    | {state.irpHandlers.length} IRP handler
                    {state.irpHandlers.length !== 1 ? "s" : ""}
                  </span>
                )}
                <div className="flex-1" />
                <button
                  type="button"
                  onClick={() => setDriverBannerDismissed(true)}
                  className="text-amber-500 hover:text-amber-300 text-sm leading-none"
                  title="Dismiss"
                >
                  &times;
                </button>
              </div>
            )}
            {notice && !noticeDismissed && (
              <div
                role="status"
                className={`border-b px-4 py-1.5 flex items-start gap-3 text-xs shrink-0 ${
                  notice.isFault
                    ? "bg-red-900/40 border-red-700/50"
                    : "bg-amber-900/40 border-amber-700/50"
                }`}
              >
                <span
                  className={`font-bold tracking-wide shrink-0 ${
                    notice.isFault ? "text-red-400" : "text-amber-400"
                  }`}
                >
                  {notice.label.toUpperCase()}
                </span>
                <span className="text-gray-300">
                  {notice.detail}
                  {/* Only when something really is withheld. A partial function
                      list withholds no tab at all, and "Still available:" over
                      the whole list would read as though it did. */}
                  {notice.unavailableTabs.length > 0 && (
                    <>
                      {" "}
                      <span className="text-gray-400">
                        Still available: {formatTabList(notice.availableTabs)}.
                      </span>
                    </>
                  )}
                </span>
                <div className="flex-1" />
                <button
                  type="button"
                  onClick={() => setNoticeDismissed(true)}
                  aria-label="Dismiss this notice"
                  className={`text-sm leading-none shrink-0 ${
                    notice.isFault
                      ? "text-red-500 hover:text-red-300"
                      : "text-amber-500 hover:text-amber-300"
                  }`}
                  title="Dismiss"
                >
                  &times;
                </button>
              </div>
            )}
            <GraphOverviewContext.Provider value={graphOverviewState}>
              <div className="flex flex-1 overflow-hidden">
                <Sidebar />
                <main className="flex-1 overflow-auto">{renderMainView()}</main>
              </div>
            </GraphOverviewContext.Provider>
            <StatusBar mcpStatus={mcpStatus} />
          </div>
        )}
        <CommandPalette open={paletteOpen} onClose={closePalette} />
        <KeyboardShortcuts open={shortcutsOpen} onClose={closeShortcuts} />
        <SettingsModal open={settingsOpen} onClose={closeSettings} />
        <GoToAddressModal open={goToOpen} onClose={closeGoTo} />
        <BatchRenameModal />
        {state.aiReport && (
          <AIReportPanel
            onClose={aiReport.dismissReport}
            onRegenerate={aiReport.regenerateReport}
          />
        )}
      </AppDispatchContext.Provider>
    </AppStateContext.Provider>
  );
}
