import { createContext, useContext, useState, useCallback, useEffect } from "react";
import type { LayoutBlock, CFGEdge } from "../disasm/cfg";

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
  return { data, setData };
}

export function useGraphOverview() {
  return useContext(GraphOverviewContext).data;
}

export function useSetGraphOverview() {
  return useContext(GraphOverviewContext).setData;
}
