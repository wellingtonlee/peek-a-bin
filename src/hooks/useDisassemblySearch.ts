import { useState, useRef, useCallback } from "react";
import { useAppState, useAppDispatch, getDisplayName } from "./usePEFile";
import { useSectionInfo } from "./useDerivedState";
import { disasmWorker } from "../workers/disasmClient";
import type { SectionHeader } from "../pe/types";
import { type DisplayRow, rowAddress } from "./useDisassemblyRows";

export interface CrossSectionResult {
  section: SectionHeader;
  address: number;
  text: string;
}

export interface UseDisassemblySearchResult {
  showSearch: boolean;
  setShowSearch: (v: boolean) => void;
  searchQuery: string;
  setSearchQuery: (v: string) => void;
  searchRegexError: boolean;
  searchMatches: number[];
  searchMatchIdx: number;
  crossResults: CrossSectionResult[] | null;
  crossSearching: boolean;
  handleSearch: (query: string, direction?: 1 | -1) => void;
  handleSearchNext: () => void;
  handleSearchPrev: () => void;
  handleCrossSearch: () => void;
  searchDebounceRef: React.MutableRefObject<ReturnType<typeof setTimeout> | undefined>;
  resetSearch: () => void;
  setCrossResults: (v: CrossSectionResult[] | null) => void;
}

export function useDisassemblySearch(
  rows: DisplayRow[],
  currentIndex: number,
): UseDisassemblySearchResult {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const sectionInfo = useSectionInfo();

  const [showSearch, setShowSearch] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchMatches, setSearchMatches] = useState<number[]>([]);
  const [searchMatchIdx, setSearchMatchIdx] = useState(-1);
  const [searchRegexError, setSearchRegexError] = useState(false);
  const [crossResults, setCrossResults] = useState<CrossSectionResult[] | null>(null);
  const [crossSearching, setCrossSearching] = useState(false);
  const searchDebounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);

  const resetSearch = useCallback(() => {
    setShowSearch(false);
    setSearchQuery("");
    setSearchMatches([]);
    setSearchMatchIdx(-1);
    setCrossResults(null);
  }, []);

  // Search logic (supports /regex/ syntax)
  const handleSearch = useCallback(
    (query: string, direction: 1 | -1 = 1) => {
      setCrossResults(null);
      setSearchRegexError(false);
      if (!query) {
        setSearchMatches([]);
        setSearchMatchIdx(-1);
        return;
      }

      // Detect regex: /pattern/ or /pattern/i
      const regexMatch = query.match(/^\/(.+)\/([i]?)$/);
      let matcher: (text: string) => boolean;
      if (regexMatch) {
        try {
          const flags = regexMatch[2] || "i";
          const regex = new RegExp(regexMatch[1], flags);
          matcher = (text) => regex.test(text);
        } catch {
          setSearchRegexError(true);
          setSearchMatches([]);
          setSearchMatchIdx(-1);
          return;
        }
      } else {
        const q = query.toLowerCase();
        matcher = (text) => text.toLowerCase().includes(q);
      }

      const matches: number[] = [];
      for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        if (row.kind === "label") {
          const name = getDisplayName(row.fn, state.renames);
          if (matcher(name)) matches.push(i);
        } else if (row.kind === "insn") {
          const insn = row.insn;
          const userComment = state.comments[insn.address] ?? "";
          const text = `${insn.address.toString(16)} ${insn.mnemonic} ${insn.opStr} ${insn.comment || ""} ${userComment}`;
          if (matcher(text)) matches.push(i);
        } else if (row.kind === "data") {
          const item = row.item;
          const userComment = state.comments[item.address] ?? "";
          const text = `${item.address.toString(16)} ${item.directive} ${item.stringValue ?? ""} ${item.pointerLabel ?? ""} ${userComment}`;
          if (matcher(text)) matches.push(i);
        }
      }
      setSearchMatches(matches);
      if (matches.length > 0) {
        let idx = matches.findIndex((m) => m >= currentIndex);
        if (idx === -1) idx = 0;
        if (direction === -1) {
          idx = idx - 1;
          if (idx < 0) idx = matches.length - 1;
        }
        setSearchMatchIdx(idx);
        const matchAddr = rowAddress(rows[matches[idx]]);
        if (matchAddr !== null) {
          dispatch({ type: "SET_ADDRESS", address: matchAddr });
        }
      } else {
        setSearchMatchIdx(-1);
      }
    },
    [rows, currentIndex, dispatch, state.renames, state.comments],
  );

  const handleSearchNext = useCallback(() => {
    if (searchMatches.length === 0) return;
    const next = (searchMatchIdx + 1) % searchMatches.length;
    setSearchMatchIdx(next);
    const addr = rowAddress(rows[searchMatches[next]]);
    if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
  }, [searchMatches, searchMatchIdx, rows, dispatch]);

  const handleSearchPrev = useCallback(() => {
    if (searchMatches.length === 0) return;
    const prev = (searchMatchIdx - 1 + searchMatches.length) % searchMatches.length;
    setSearchMatchIdx(prev);
    const addr = rowAddress(rows[searchMatches[prev]]);
    if (addr !== null) dispatch({ type: "SET_ADDRESS", address: addr });
  }, [searchMatches, searchMatchIdx, rows, dispatch]);

  // Cross-section search (off main thread via worker)
  const handleCrossSearch = useCallback(() => {
    if (!pe || !searchQuery || crossSearching) return;
    setCrossSearching(true);
    const q = searchQuery.toLowerCase();

    (async () => {
      const results: CrossSectionResult[] = [];
      for (const sec of pe.sections) {
        if (sec === sectionInfo) continue;
        try {
          const bytes = new Uint8Array(pe.buffer, sec.pointerToRawData, sec.sizeOfRawData);
          const base = pe.optionalHeader.imageBase + sec.virtualAddress;
          const insns = await disasmWorker.disassemble(bytes, base, pe.is64);
          for (const insn of insns) {
            const text = `${insn.mnemonic} ${insn.opStr} ${insn.comment || ""}`;
            if (text.toLowerCase().includes(q)) {
              results.push({ section: sec, address: insn.address, text: text.trim() });
              if (results.length >= 100) break;
            }
          }
        } catch { /* skip bad sections */ }
        if (results.length >= 100) break;
      }
      setCrossResults(results);
      setCrossSearching(false);
    })();
  }, [pe, searchQuery, sectionInfo, crossSearching]);

  return {
    showSearch,
    setShowSearch,
    searchQuery,
    setSearchQuery,
    searchRegexError,
    searchMatches,
    searchMatchIdx,
    crossResults,
    crossSearching,
    handleSearch,
    handleSearchNext,
    handleSearchPrev,
    handleCrossSearch,
    searchDebounceRef,
    resetSearch,
    setCrossResults,
  };
}
