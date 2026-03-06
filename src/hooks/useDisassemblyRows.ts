import { useEffect, useRef, useMemo, useState } from "react";
import { useAppState } from "./usePEFile";
import { useSectionInfo } from "./useDerivedState";
import { disasmWorker } from "../workers/disasmClient";
import type { Instruction, DisasmFunction, Xref, DataItem } from "../disasm/types";
import { buildCFG, detectLoops } from "../disasm/cfg";
import type { Loop } from "../disasm/cfg";
import { buildDataItems } from "../disasm/dataView";
import { buildIATLookup } from "../disasm/operands";

export type DisplayRow =
  | { kind: "label"; fn: DisasmFunction }
  | { kind: "insn"; insn: Instruction; blockIdx: number }
  | { kind: "separator" }
  | { kind: "data"; item: DataItem };

export function rowAddress(row: DisplayRow): number | null {
  if (row.kind === "insn") return row.insn.address;
  if (row.kind === "label") return row.fn.address;
  if (row.kind === "data") return row.item.address;
  return null;
}

export function binarySearchRows(rows: DisplayRow[], address: number): number {
  let lo = 0;
  let hi = rows.length - 1;
  let best = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    const row = rows[mid];
    const rowAddr = rowAddress(row);
    if (rowAddr === null) {
      hi = mid - 1;
      continue;
    }
    if (rowAddr <= address) {
      best = mid;
      lo = mid + 1;
    } else {
      hi = mid - 1;
    }
  }
  return best;
}

export interface UseDisassemblyRowsResult {
  instructions: Instruction[];
  rows: DisplayRow[];
  funcMap: Map<number, DisasmFunction>;
  xrefMap: Map<number, number[]>;
  typedXrefMap: Map<number, Xref[]>;
  loopHeaders: Map<number, number>;
  loops: Loop[];
  bookmarkSet: Set<number>;
  disassembling: boolean;
  disasmError: string | null;
  isExecutable: boolean;
}

export function useDisassemblyRows(currentFunc: DisasmFunction | null): UseDisassemblyRowsResult {
  const state = useAppState();
  const pe = state.peFile;
  const sectionInfo = useSectionInfo();

  const [instructions, setInstructions] = useState<Instruction[]>([]);
  const [disasmError, setDisasmError] = useState<string | null>(null);
  const [disassembling, setDisassembling] = useState(false);

  const isExecutable = sectionInfo ? (sectionInfo.characteristics & 0x20000000) !== 0 : true;

  // Disassemble the current section (off main thread via worker)
  useEffect(() => {
    if (!pe || !sectionInfo || !state.disasmReady) return;

    if (!isExecutable) {
      setInstructions([]);
      setDisassembling(false);
      return;
    }

    let cancelled = false;
    setDisassembling(true);

    const sectionBytes = new Uint8Array(
      pe.buffer,
      sectionInfo.pointerToRawData,
      sectionInfo.sizeOfRawData,
    );

    // Apply hex patches over the section bytes
    let bytesToDisasm = sectionBytes;
    if (state.hexPatches.size > 0) {
      const patched = new Uint8Array(sectionBytes);
      const rawStart = sectionInfo.pointerToRawData;
      const rawEnd = rawStart + sectionInfo.sizeOfRawData;
      state.hexPatches.forEach((value, fileOffset) => {
        if (fileOffset >= rawStart && fileOffset < rawEnd) {
          patched[fileOffset - rawStart] = value;
        }
      });
      bytesToDisasm = patched;
      disasmWorker.invalidateCache();
    }

    const baseAddr = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;

    // Use hybrid disassembly when functions are detected (seeds available)
    let disasmPromise: Promise<Instruction[]>;
    if (state.functions.length > 0) {
      const pdataRanges = pe.runtimeFunctions?.map(rf => ({
        beginAddress: pe.optionalHeader.imageBase + rf.beginAddress,
        endAddress: pe.optionalHeader.imageBase + rf.endAddress,
      }));
      disasmPromise = disasmWorker.hybridDisassemble(
        bytesToDisasm,
        baseAddr,
        pe.is64,
        state.functions.map(f => f.address),
        pdataRanges,
      );
    } else {
      disasmPromise = disasmWorker.disassemble(bytesToDisasm, baseAddr, pe.is64);
    }

    disasmPromise
      .then((result) => {
        if (!cancelled) {
          setInstructions(result);
          setDisasmError(null);
        }
      })
      .catch((e) => {
        if (!cancelled) {
          setDisasmError(e instanceof Error ? e.message : "Disassembly failed");
          setInstructions([]);
        }
      })
      .finally(() => {
        if (!cancelled) setDisassembling(false);
      });

    return () => { cancelled = true; };
  }, [pe, sectionInfo, state.disasmReady, state.hexPatches.size, state.functions, isExecutable]);

  // Build funcMap for O(1) lookup
  const funcMap = useMemo(() => {
    const m = new Map<number, DisasmFunction>();
    for (const fn of state.functions) m.set(fn.address, fn);
    return m;
  }, [state.functions]);

  // Build typed xref map (off main thread via worker)
  const [typedXrefMap, setTypedXrefMap] = useState<Map<number, Xref[]>>(new Map());
  const typedXrefMapSizeRef = useRef(0);
  useEffect(() => {
    if (instructions.length === 0) {
      setTypedXrefMap(new Map());
      typedXrefMapSizeRef.current = 0;
      return;
    }
    let cancelled = false;
    disasmWorker.buildTypedXrefMap(instructions).then((map) => {
      if (!cancelled) {
        // Stabilize: skip update if size hasn't changed (common after initial load)
        if (map.size !== typedXrefMapSizeRef.current) {
          typedXrefMapSizeRef.current = map.size;
          setTypedXrefMap(map);
        } else {
          // Check if any keys differ
          let changed = false;
          for (const k of map.keys()) {
            if (!typedXrefMap.has(k)) { changed = true; break; }
          }
          if (changed) setTypedXrefMap(map);
        }
      }
    });
    return () => { cancelled = true; };
  }, [instructions]);

  // Legacy xref map — stabilized to avoid unnecessary row rebuilds
  const xrefTargetSetRef = useRef(new Set<number>());
  const xrefTargetSet = useMemo(() => {
    const newSet = new Set(typedXrefMap.keys());
    const prev = xrefTargetSetRef.current;
    if (newSet.size === prev.size) {
      let same = true;
      for (const k of newSet) {
        if (!prev.has(k)) { same = false; break; }
      }
      if (same) return prev;
    }
    xrefTargetSetRef.current = newSet;
    return newSet;
  }, [typedXrefMap]);

  const xrefMap = useMemo(() => {
    const m = new Map<number, number[]>();
    for (const [addr, xrefs] of typedXrefMap) {
      m.set(addr, xrefs.map((x) => x.from));
    }
    return m;
  }, [typedXrefMap]);

  // Bookmark address set for O(1) lookup
  const bookmarkSet = useMemo(() => {
    const s = new Set<number>();
    for (const b of state.bookmarks) s.add(b.address);
    return s;
  }, [state.bookmarks]);

  // Loop detection for current function
  const loops = useMemo((): Loop[] => {
    if (!currentFunc || instructions.length === 0 || typedXrefMap.size === 0) return [];
    const blocks = buildCFG(currentFunc, instructions, typedXrefMap, disasmWorker.jumpTables);
    return detectLoops(blocks);
  }, [currentFunc, instructions, typedXrefMap]);

  const loopHeaders = useMemo(() => {
    const m = new Map<number, number>();
    for (const loop of loops) m.set(loop.headerAddr, loop.depth);
    return m;
  }, [loops]);

  // Data items for non-executable sections
  const dataItems = useMemo((): DataItem[] => {
    if (isExecutable || !pe || !sectionInfo) return [];
    const bytes = new Uint8Array(pe.buffer, sectionInfo.pointerToRawData, sectionInfo.sizeOfRawData);
    const baseAddress = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;
    const iatMap = buildIATLookup(pe.imports);
    const funcAddrsMap = new Map<number, string>();
    for (const fn of state.functions) funcAddrsMap.set(fn.address, fn.name);
    const sectionRanges = pe.sections.map(s => ({
      start: pe.optionalHeader.imageBase + s.virtualAddress,
      end: pe.optionalHeader.imageBase + s.virtualAddress + s.virtualSize,
    }));
    return buildDataItems(bytes, baseAddress, pe.is64, pe.strings, pe.stringTypes, iatMap, funcAddrsMap, sectionRanges);
  }, [isExecutable, pe, sectionInfo, state.functions]);

  // Build display rows (with basic block separators and block indices)
  const rows: DisplayRow[] = useMemo(() => {
    if (!isExecutable) {
      return dataItems.map(item => ({ kind: "data" as const, item }));
    }
    const result: DisplayRow[] = [];
    const separatorMnemonics = new Set(["ret", "retn", "jmp", "int3"]);
    const branchMnemonics = new Set(["ret", "retn", "jmp", "int3"]);
    let blockIdx = 0;
    let prevWasBranch = false;
    for (let i = 0; i < instructions.length; i++) {
      const insn = instructions[i];
      const fn = funcMap.get(insn.address);
      if (fn) {
        blockIdx++;
        prevWasBranch = false;
        result.push({ kind: "label", fn });
      }
      // Start new block if: this address is a branch target (xref exists), or previous was branch/ret
      if (prevWasBranch || (xrefTargetSet.has(insn.address) && !fn)) {
        blockIdx++;
      }
      result.push({ kind: "insn", insn, blockIdx });
      const mn = insn.mnemonic;
      prevWasBranch = branchMnemonics.has(mn) || (mn.startsWith("j") && mn !== "jmp");
      // Insert separator after ret/retn/jmp/int3, unless next instruction is a function label
      if (separatorMnemonics.has(mn)) {
        const next = instructions[i + 1];
        if (next && !funcMap.has(next.address)) {
          result.push({ kind: "separator" });
        }
      }
    }
    return result;
  }, [instructions, funcMap, xrefTargetSet, isExecutable, dataItems]);

  return {
    instructions,
    rows,
    funcMap,
    xrefMap,
    typedXrefMap,
    loopHeaders,
    loops,
    bookmarkSet,
    disassembling,
    disasmError,
    isExecutable,
  };
}
