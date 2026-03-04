import { useState, useMemo, useCallback } from "react";
import { useAppState } from "../hooks/usePEFile";
import { ResourceTypeNames, RT_VERSION, RT_ICON, RT_GROUP_ICON, RT_MANIFEST } from "../pe/constants";
import { parseVersionInfo, reconstructIcon } from "../pe/resources";
import { rvaToFileOffset } from "../pe/parser";
import type { ResourceNode, ResourceTree } from "../pe/types";

function getTypeName(id: number | string): string {
  if (typeof id === "string") return id;
  return ResourceTypeNames[id] ?? `Type ${id}`;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface ExpandedLeafProps {
  typeId: number | string;
  rva: number;
  size: number;
  buffer: ArrayBuffer;
  sections: import("../pe/types").SectionHeader[];
  resourceTree: ResourceTree;
}

function ExpandedLeaf({ typeId, rva, size, buffer, sections, resourceTree }: ExpandedLeafProps) {
  const numType = typeof typeId === "number" ? typeId : -1;

  if (numType === RT_VERSION) {
    const info = parseVersionInfo(buffer, rva, size, sections);
    const keys = Object.keys(info);
    if (keys.length === 0) return <div className="text-gray-500 ml-8 py-1">No version strings found</div>;
    return (
      <table className="ml-8 my-1 text-[11px]">
        <tbody>
          {keys.map((k) => (
            <tr key={k}>
              <td className="pr-4 text-gray-500 whitespace-nowrap">{k}</td>
              <td className="text-gray-300">{info[k]}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }

  if (numType === RT_GROUP_ICON) {
    // Reconstruct icon from group + individual RT_ICON entries
    const fileOff = rvaToFileOffset(rva, sections);
    if (fileOff < 0) return null;
    const groupData = buffer.slice(fileOff, fileOff + size);

    // Collect all RT_ICON entries from the resource tree
    const iconEntries = new Map<number, { rva: number; size: number }>();
    for (const entry of resourceTree.entries) {
      const t = typeof entry.type === "number" ? entry.type : -1;
      if (t === RT_ICON && typeof entry.name === "number") {
        iconEntries.set(entry.name, { rva: entry.rva, size: entry.size });
      }
    }

    const icoBytes = reconstructIcon(buffer, groupData, iconEntries, sections);
    if (!icoBytes) return <div className="text-gray-500 ml-8 py-1">Could not reconstruct icon</div>;

    const blob = new Blob([icoBytes], { type: "image/x-icon" });
    const url = URL.createObjectURL(blob);
    return (
      <div className="ml-8 my-1">
        <img src={url} alt="Icon" className="max-w-[64px] max-h-[64px] bg-gray-700 border border-gray-600 rounded" />
      </div>
    );
  }

  if (numType === RT_MANIFEST) {
    const fileOff = rvaToFileOffset(rva, sections);
    if (fileOff < 0) return null;
    const bytes = new Uint8Array(buffer, fileOff, Math.min(size, buffer.byteLength - fileOff));
    const text = new TextDecoder("utf-8").decode(bytes);
    return (
      <pre className="ml-8 my-1 p-2 bg-gray-800 border border-gray-700 rounded text-[10px] text-gray-300 overflow-auto max-h-60 whitespace-pre-wrap">
        {text}
      </pre>
    );
  }

  return null;
}

function downloadResource(buffer: ArrayBuffer, rva: number, size: number, sections: import("../pe/types").SectionHeader[], name: string) {
  const fileOff = rvaToFileOffset(rva, sections);
  if (fileOff < 0) return;
  const bytes = new Uint8Array(buffer, fileOff, Math.min(size, buffer.byteLength - fileOff));
  const blob = new Blob([bytes]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function ResourcesView() {
  const state = useAppState();
  const pe = state.peFile;
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleCollapse = useCallback((key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const toggleExpand = useCallback((key: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });
  }, []);

  const totalEntries = pe?.resources?.entries.length ?? 0;
  const typeCount = useMemo(() => {
    if (!pe?.resources) return 0;
    const types = new Set(pe.resources.entries.map((e) => String(e.type)));
    return types.size;
  }, [pe?.resources]);

  if (!pe || !pe.resources || pe.resources.entries.length === 0) {
    return (
      <div className="p-4 text-xs text-gray-500">
        No resources found in this PE file.
      </div>
    );
  }

  const { resources } = pe;

  // Group entries by type for display
  const grouped = useMemo(() => {
    const map = new Map<string, ResourceTree['entries']>();
    for (const entry of resources.entries) {
      const key = String(entry.type);
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(entry);
    }
    return Array.from(map.entries());
  }, [resources.entries]);

  return (
    <div className="p-4 text-xs overflow-auto h-full">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Resources ({typeCount} types, {totalEntries} entries)
        </h2>
      </div>

      <div className="space-y-1">
        {grouped.map(([typeKey, entries]) => {
          const typeId = entries[0].type;
          const typeName = getTypeName(typeId);
          const isCollapsed = collapsed.has(typeKey);

          return (
            <div key={typeKey}>
              <button
                onClick={() => toggleCollapse(typeKey)}
                className="flex items-center gap-1.5 text-yellow-400 font-semibold hover:text-yellow-300 py-0.5"
              >
                <span className="text-[10px] text-gray-500 w-3 inline-block">
                  {isCollapsed ? "\u25B6" : "\u25BC"}
                </span>
                {typeName}
                <span className="text-gray-500 font-normal text-[10px]">
                  ({entries.length})
                </span>
              </button>
              {!isCollapsed && (
                <div className="ml-6">
                  <table className="w-full">
                    <thead>
                      <tr className="text-gray-500 text-left text-[10px]">
                        <th className="py-0.5 pr-4 font-normal">Name/ID</th>
                        <th className="py-0.5 pr-4 font-normal">Language</th>
                        <th className="py-0.5 pr-4 font-normal">Size</th>
                        <th className="py-0.5 pr-4 font-normal">RVA</th>
                        <th className="py-0.5 font-normal"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {entries.map((entry, idx) => {
                        const leafKey = `${typeKey}-${entry.name}-${entry.lang}-${idx}`;
                        const isExpanded = expanded.has(leafKey);
                        const nameDisplay = typeof entry.name === "string" ? entry.name : `#${entry.name}`;

                        return (
                          <>
                            <tr key={leafKey} className="text-gray-300 hover:bg-gray-800/50">
                              <td className="py-0.5 pr-4">
                                <button
                                  onClick={() => toggleExpand(leafKey)}
                                  className="hover:text-blue-400"
                                >
                                  <span className="text-[10px] text-gray-500 w-3 inline-block mr-1">
                                    {isExpanded ? "\u25BC" : "\u25B6"}
                                  </span>
                                  {nameDisplay}
                                </button>
                              </td>
                              <td className="py-0.5 pr-4 text-gray-500">{entry.lang}</td>
                              <td className="py-0.5 pr-4 font-mono">{formatSize(entry.size)}</td>
                              <td className="py-0.5 pr-4 font-mono text-blue-400">
                                0x{entry.rva.toString(16).toUpperCase()}
                              </td>
                              <td className="py-0.5">
                                <button
                                  onClick={() => downloadResource(
                                    pe.buffer, entry.rva, entry.size, pe.sections,
                                    `resource_${typeName}_${nameDisplay}_${entry.lang}.bin`,
                                  )}
                                  className="text-gray-500 hover:text-blue-400 text-[10px]"
                                >
                                  Download
                                </button>
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr key={`${leafKey}-detail`}>
                                <td colSpan={5}>
                                  <ExpandedLeaf
                                    typeId={typeId}
                                    rva={entry.rva}
                                    size={entry.size}
                                    buffer={pe.buffer}
                                    sections={pe.sections}
                                    resourceTree={resources}
                                  />
                                </td>
                              </tr>
                            )}
                          </>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
