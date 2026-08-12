// Graph-mode instruction search, lifted verbatim out of DisassemblyView.
//
// The callbacks below appear in exactly the order they had inline, and every
// dependency array is copied unchanged. The call to useGraphSearch() must
// therefore stay at the position handleGraphSearch occupied — React identifies
// hooks by call order.
//
// The four useState calls and the input ref that make up the rest of the state
// machine deliberately stay declared in DisassemblyView and are passed in: they
// sit ~370 lines above these callbacks, so moving them into this hook would
// shift them to a different position in the hook sequence. Same reasoning, and
// the same trade-off, as useInsnContextMenu.
import { type Dispatch, useCallback, useMemo } from "react";
import type { Instruction } from "../disasm/types";
import type { AppAction } from "./usePEFile";

export interface UseGraphSearchArgs {
  instructions: Instruction[];
  dispatch: Dispatch<AppAction>;
  setCollapsedBlocks: (v: Set<number>) => void;
  graphSearchMatches: number[];
  graphSearchIdx: number;
  setShowGraphSearch: (v: boolean) => void;
  setGraphSearchQuery: (v: string) => void;
  setGraphSearchMatches: (v: number[]) => void;
  setGraphSearchIdx: (v: number) => void;
}

export function useGraphSearch({
  instructions,
  dispatch,
  setCollapsedBlocks,
  graphSearchMatches,
  graphSearchIdx,
  setShowGraphSearch,
  setGraphSearchQuery,
  setGraphSearchMatches,
  setGraphSearchIdx,
}: UseGraphSearchArgs) {
  // Graph search: compute matches when query changes
  const handleGraphSearch = useCallback(
    (query: string) => {
      setGraphSearchQuery(query);
      if (!query || instructions.length === 0) {
        setGraphSearchMatches([]);
        setGraphSearchIdx(0);
        return;
      }
      // Support /regex/ and /regex/i syntax
      let matcher: (text: string) => boolean;
      const regexMatch = query.match(/^\/(.+)\/([i]?)$/);
      if (regexMatch) {
        try {
          const rx = new RegExp(regexMatch[1], regexMatch[2]);
          matcher = (text) => rx.test(text);
        } catch {
          matcher = (text) => text.toLowerCase().includes(query.toLowerCase());
        }
      } else {
        const q = query.toLowerCase();
        matcher = (text) => text.toLowerCase().includes(q);
      }
      const matches: number[] = [];
      for (const insn of instructions) {
        const text = `${insn.mnemonic} ${insn.opStr}`;
        if (matcher(text)) matches.push(insn.address);
      }
      setGraphSearchMatches(matches);
      setGraphSearchIdx(0);
      if (matches.length > 0) {
        setCollapsedBlocks(new Set());
        dispatch({ type: "SET_ADDRESS", address: matches[0] });
      }
    },
    [
      instructions,
      dispatch,
      setGraphSearchQuery,
      setGraphSearchMatches,
      setGraphSearchIdx,
      setCollapsedBlocks,
    ],
  );

  const graphSearchNextMatch = useCallback(() => {
    if (graphSearchMatches.length === 0) return;
    const next = (graphSearchIdx + 1) % graphSearchMatches.length;
    setGraphSearchIdx(next);
    dispatch({ type: "SET_ADDRESS", address: graphSearchMatches[next] });
  }, [graphSearchMatches, graphSearchIdx, dispatch, setGraphSearchIdx]);

  const graphSearchPrevMatch = useCallback(() => {
    if (graphSearchMatches.length === 0) return;
    const prev = (graphSearchIdx - 1 + graphSearchMatches.length) % graphSearchMatches.length;
    setGraphSearchIdx(prev);
    dispatch({ type: "SET_ADDRESS", address: graphSearchMatches[prev] });
  }, [graphSearchMatches, graphSearchIdx, dispatch, setGraphSearchIdx]);

  const closeGraphSearch = useCallback(() => {
    setShowGraphSearch(false);
    setGraphSearchQuery("");
    setGraphSearchMatches([]);
    setGraphSearchIdx(0);
  }, [setShowGraphSearch, setGraphSearchQuery, setGraphSearchMatches, setGraphSearchIdx]);

  // Graph search match sets for CFGView highlighting
  const graphSearchMatchSet = useMemo(() => new Set(graphSearchMatches), [graphSearchMatches]);
  const graphSearchCurrentMatch = graphSearchMatches[graphSearchIdx] ?? undefined;

  return {
    handleGraphSearch,
    graphSearchNextMatch,
    graphSearchPrevMatch,
    closeGraphSearch,
    graphSearchMatchSet,
    graphSearchCurrentMatch,
  };
}
