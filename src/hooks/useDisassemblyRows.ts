import { useEffect, useMemo, useRef, useState } from "react";
import type { Loop } from "../disasm/cfg";
import { buildCFG, detectLoops } from "../disasm/cfg";
import { buildDataItems } from "../disasm/dataView";
import type { DataItem, DisasmFunction, Instruction, Xref } from "../disasm/types";
import { IMAGE_SCN_MEM_EXECUTE } from "../pe/constants";
import { disasmWorker } from "../workers/disasmClient";
import { useSectionInfo } from "./useDerivedState";
import { useAppState } from "./usePEFile";

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

/**
 * The row a cursor move should land on, skipping rows that carry no address.
 *
 * A separator is the only {@link DisplayRow} `rowAddress` answers `null` for,
 * and the cursor is identified by an *address* — so a move that lands on one has
 * nothing to dispatch. Both arrow branches used to give up at that point, which
 * left the cursor **permanently** stuck: nothing about the state changed, so the
 * next press recomputed the same index and declined again. Separators sit after
 * every `ret`/`retn`/`jmp`/`int3` not immediately followed by a label, so in a
 * real listing that is most function tails (`peek-a-bin-a5sw`).
 *
 * `from` and `to` are row indices, `to` already clamped by the caller. The
 * search runs **outward from `to` in the direction of travel first**, so a
 * one-row move behaves as "the next addressable row"; only if that finds
 * nothing does it fall back to scanning *back* toward `from`, which is what
 * lets a 40-row PageDown near the end of the list still land on the last
 * addressable row instead of doing nothing.
 *
 * Returns `null` when no addressable row lies that way, and the caller should
 * then leave the cursor alone — a downward key must never move the cursor up.
 */
export function seekAddressableRow(
  rows: readonly DisplayRow[],
  from: number,
  to: number,
): number | null {
  const dir = Math.sign(to - from);
  if (dir === 0) return null;
  for (let i = to; i >= 0 && i < rows.length; i += dir) {
    if (rowAddress(rows[i]) !== null) return i;
  }
  // Nothing beyond `to`; take the nearest addressable row between it and where
  // we started, so the move still goes somewhere in the direction asked for.
  for (let i = to - dir; i !== from; i -= dir) {
    if (rowAddress(rows[i]) !== null) return i;
  }
  return null;
}

export function binarySearchRows(rows: DisplayRow[], address: number): number {
  let lo = 0;
  let hi = rows.length - 1;
  let best = 0;
  while (lo <= hi) {
    const mid = (lo + hi) >>> 1;
    // Separator rows carry no address. Treating one as "too high" and discarding
    // the whole right half is wrong — separators sit between functions, anywhere
    // in the list, so a single one on the search path used to strand the result
    // at a much earlier row. Probe forward to the next addressed row instead;
    // everything skipped is addressless, so nothing searchable is lost.
    let probe = mid;
    while (probe <= hi && rowAddress(rows[probe]) === null) probe++;
    if (probe > hi) {
      hi = mid - 1;
      continue;
    }
    const rowAddr = rowAddress(rows[probe]) as number;
    if (rowAddr <= address) {
      best = probe;
      lo = probe + 1;
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

  const isExecutable = sectionInfo
    ? (sectionInfo.characteristics & IMAGE_SCN_MEM_EXECUTE) !== 0
    : true;

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
      const pdataRanges = pe.runtimeFunctions?.map((rf) => ({
        beginAddress: pe.optionalHeader.imageBase + rf.beginAddress,
        endAddress: pe.optionalHeader.imageBase + rf.endAddress,
      }));
      disasmPromise = disasmWorker.hybridDisassemble(
        bytesToDisasm,
        baseAddr,
        pe.is64,
        state.functions.map((f) => f.address),
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

    return () => {
      cancelled = true;
    };
    // state.hexPatches rather than its .size: the reducer replaces the Map on
    // every patch action, so identity tracks content exactly, whereas .size
    // misses a patch that overwrites an already-patched offset.
  }, [pe, sectionInfo, state.disasmReady, state.hexPatches, state.functions, isExecutable]);

  // Build funcMap for O(1) lookup
  const funcMap = useMemo(() => {
    const m = new Map<number, DisasmFunction>();
    for (const fn of state.functions) m.set(fn.address, fn);
    return m;
  }, [state.functions]);

  // Build typed xref map (off main thread via worker)
  const [typedXrefMap, setTypedXrefMap] = useState<Map<number, Xref[]>>(new Map());
  // Read as two numbers rather than passing `pe`: the effect below must re-run
  // when the image moves, not when the PEFile object is rebuilt.
  const imageBase = pe?.optionalHeader.imageBase;
  const sizeOfImage = pe?.optionalHeader.sizeOfImage;
  useEffect(() => {
    if (instructions.length === 0) {
      setTypedXrefMap(new Map());
      return;
    }
    let cancelled = false;
    disasmWorker
      // Bounded by the mapped image. The fallback operand scan behind this
      // reports any large `0x…` token as a data reference, so unbounded it
      // marked bitmasks and status constants as xref targets that no address
      // in the file matches — 305 phantom data xrefs on t64.exe alone
      // (peek-a-bin-jfp). Omitted only when there is no PE loaded, which the
      // `instructions.length === 0` guard above has already excluded in
      // practice.
      .buildTypedXrefMap(
        instructions,
        imageBase !== undefined && sizeOfImage !== undefined
          ? { base: imageBase, size: sizeOfImage }
          : undefined,
      )
      .then((map) => {
        if (cancelled) return;
        // Compared against `prev` rather than the captured `typedXrefMap`: the
        // effect only depends on `instructions`, so reading the state variable
        // here compared against a stale snapshot.
        setTypedXrefMap((prev) => {
          // Stabilize: keep the old reference unless the contents actually differ,
          // so rows are not rebuilt after every load.
          if (map.size !== prev.size) return map;
          for (const k of map.keys()) {
            if (!prev.has(k)) return map;
          }
          return prev;
        });
      })
      .catch((err) => {
        console.error("[peek-a-bin] failed to build typed xref map", err);
      });
    return () => {
      cancelled = true;
    };
  }, [instructions, imageBase, sizeOfImage]);

  // Legacy xref map — stabilized to avoid unnecessary row rebuilds
  const xrefTargetSetRef = useRef(new Set<number>());
  const xrefTargetSet = useMemo(() => {
    const newSet = new Set(typedXrefMap.keys());
    const prev = xrefTargetSetRef.current;
    if (newSet.size === prev.size) {
      let same = true;
      for (const k of newSet) {
        if (!prev.has(k)) {
          same = false;
          break;
        }
      }
      if (same) return prev;
    }
    xrefTargetSetRef.current = newSet;
    return newSet;
  }, [typedXrefMap]);

  const xrefMap = useMemo(() => {
    const m = new Map<number, number[]>();
    for (const [addr, xrefs] of typedXrefMap) {
      m.set(
        addr,
        xrefs.map((x) => x.from),
      );
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
    const bytes = new Uint8Array(
      pe.buffer,
      sectionInfo.pointerToRawData,
      sectionInfo.sizeOfRawData,
    );
    const baseAddress = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;
    const iatMap = state.iatMap;
    const funcAddrsMap = new Map<number, string>();
    for (const fn of state.functions) funcAddrsMap.set(fn.address, fn.name);
    const sectionRanges = pe.sections.map((s) => ({
      start: pe.optionalHeader.imageBase + s.virtualAddress,
      end: pe.optionalHeader.imageBase + s.virtualAddress + s.virtualSize,
    }));
    return buildDataItems(
      bytes,
      baseAddress,
      pe.is64,
      pe.strings,
      pe.stringTypes,
      iatMap,
      funcAddrsMap,
      sectionRanges,
    );
    // state.iatMap is read above and is reducer-owned (replaced, never mutated),
    // so it only changes identity when the IAT is actually re-set.
  }, [isExecutable, pe, sectionInfo, state.functions, state.iatMap]);

  // Build display rows (with basic block separators and block indices)
  const rows: DisplayRow[] = useMemo(() => {
    if (!isExecutable) {
      return dataItems.map((item) => ({ kind: "data" as const, item }));
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
