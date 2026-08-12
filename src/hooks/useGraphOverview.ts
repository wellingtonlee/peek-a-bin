import { createContext, useContext, useMemo, useState } from "react";
import type { CFGEdge, LayoutBlock } from "../disasm/cfg";

export interface GraphOverviewData {
  blocks: LayoutBlock[];
  edges: CFGEdge[];
  pan: { x: number; y: number };
  zoom: number;
  viewport: { width: number; height: number };
  onPanTo: (pan: { x: number; y: number }) => void;
  currentAddress: number;
}

type GraphOverviewState = {
  data: GraphOverviewData | null;
  setData: (d: GraphOverviewData | null) => void;
};

export const GraphOverviewContext = createContext<GraphOverviewState>({
  data: null,
  setData: () => {},
});

export function useGraphOverviewState(): GraphOverviewState {
  const [data, setData] = useState<GraphOverviewData | null>(null);
  // setData is this hook's own useState setter, so its identity is stable and
  // Biome resolves it as such; listing it is redundant.
  return useMemo(() => ({ data, setData }), [data]);
}

export function useGraphOverview() {
  return useContext(GraphOverviewContext).data;
}

export function useSetGraphOverview() {
  return useContext(GraphOverviewContext).setData;
}
