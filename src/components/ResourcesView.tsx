import { Fragment, useCallback, useMemo, useState } from "react";
import { useAppState } from "../hooks/usePEFile";
import {
  ResourceTypeNames,
  RT_GROUP_ICON,
  RT_ICON,
  RT_MANIFEST,
  RT_VERSION,
} from "../pe/constants";
import { rvaToFileOffset } from "../pe/parser";
import { MAX_TOTAL_ENTRIES, parseVersionInfo, reconstructIcon } from "../pe/resources";
import type { ResourceTree } from "../pe/types";

/**
 * The bytes a resource leaf names, or null when the file does not contain them.
 *
 * THE GUARD IS `fileOff >= buffer.byteLength`, AND IT IS NOT PARANOIA.
 * `rvaToFileOffset` resolves an RVA against the SECTION TABLE and never sees the
 * buffer, so on a TRUNCATED image — a carved sample, a part-finished download,
 * anything whose section headers describe more than the file holds — it answers
 * a file offset that is past the end and cannot say so. `buffer.byteLength -
 * fileOff` is then NEGATIVE, `Math.min(size, …)` keeps the negative, and
 * `new Uint8Array(buffer, fileOff, -16)` throws `RangeError: Invalid typed array
 * length` — which takes the whole Resources pane into its ErrorBoundary fallback
 * on a click.
 *
 * The tree walks fine in that case: `parseResourceDirectory` bounds every read
 * on the buffer, so every row renders and only EXPANDING one is fatal. That is
 * why nothing static could see it and why the row that pins it drives the real
 * component over a real truncated fixture.
 */
function resourceBytes(
  buffer: ArrayBuffer,
  rva: number,
  size: number,
  sections: import("../pe/types").SectionHeader[],
): Uint8Array | null {
  const fileOff = rvaToFileOffset(rva, sections);
  if (fileOff < 0 || fileOff >= buffer.byteLength) return null;
  return new Uint8Array(buffer, fileOff, Math.min(size, buffer.byteLength - fileOff));
}

function getTypeName(id: number | string): string {
  if (typeof id === "string") return id;
  return ResourceTypeNames[id] ?? `Type ${id}`;
}

/**
 * How an ORDINAL-OR-NAME level is written on the page. One declaration, read by
 * the Name column and the Language column.
 *
 * All three levels of the directory are identified the same way — the high bit
 * of the entry's `Name` field — so all three can be an ordinal or a string, and
 * the `#` is the whole signal telling a reader which. Without it a resource
 * whose name is literally `"101"` and resource `#101` are one string on the
 * page; likewise a language NAMED `"1033"` beside LANGID 1033.
 *
 * The type level does not use this: it goes through `getTypeName`, which is a
 * lookup rather than a spelling, and prints `Type 4001` for an ordinal it cannot
 * name — already unambiguous.
 */
function ordinalLabel(id: number | string): string {
  return typeof id === "string" ? id : `#${id}`;
}

/**
 * How an ordinal-or-name level is written into a REACT KEY / a Set member.
 *
 * A DIFFERENT QUESTION FROM {@link ordinalLabel}, and the reason the two are not
 * one function: this one decides which rows are the SAME row, so it must keep
 * the two kinds apart even where they read alike. `String(id)` does not — it
 * sends the ordinal 3 and the name `"3"` to one key, which for the TYPE level
 * merges two genuinely distinct groups into one heading with one collapse state.
 *
 * ON `leafKey` the tag is belt rather than braces: the trailing row index is
 * what makes a leaf key injective, and it has to stay — two identical entries in
 * one crafted directory are walked as two rows, and a key without the index
 * would collide and take React's duplicate-key warning with it. So a control on
 * the tag at the LEAF level is inert by construction; at the TYPE level, where
 * there is no index, it is not.
 */
function keyPart(id: number | string): string {
  return typeof id === "string" ? `s${id}` : `i${id}`;
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
    if (keys.length === 0)
      return <div className="text-gray-500 ml-8 py-1">No version strings found</div>;
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
    // Reconstruct icon from group + individual RT_ICON entries.
    // `slice` CLAMPS rather than throwing, so a past-the-end offset yields an
    // empty buffer and `reconstructIcon` answers null — the asymmetry with
    // `resourceBytes` above is deliberate, not an unguarded site.
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
        <img
          src={url}
          alt="Icon"
          className="max-w-[64px] max-h-[64px] bg-gray-700 border border-gray-600 rounded"
        />
      </div>
    );
  }

  if (numType === RT_MANIFEST) {
    const bytes = resourceBytes(buffer, rva, size, sections);
    if (!bytes) return null;
    const text = new TextDecoder("utf-8").decode(bytes);
    return (
      <pre className="ml-8 my-1 p-2 bg-gray-800 border border-gray-700 rounded text-[10px] text-gray-300 overflow-auto max-h-60 whitespace-pre-wrap">
        {text}
      </pre>
    );
  }

  return null;
}

function downloadResource(
  buffer: ArrayBuffer,
  rva: number,
  size: number,
  sections: import("../pe/types").SectionHeader[],
  name: string,
) {
  const bytes = resourceBytes(buffer, rva, size, sections);
  if (!bytes) return;
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
    const types = new Set(pe.resources.entries.map((e) => keyPart(e.type)));
    return types.size;
  }, [pe?.resources]);

  // Grouped before the early return below so hook order stays stable.
  const grouped = useMemo(() => {
    const map = new Map<string, ResourceTree["entries"]>();
    for (const entry of pe?.resources?.entries ?? []) {
      const key = keyPart(entry.type);
      if (!map.has(key)) map.set(key, []);
      map.get(key)!.push(entry);
    }
    return Array.from(map.entries());
  }, [pe?.resources]);

  if (!pe?.resources || pe.resources.entries.length === 0) {
    // A CUT-SHORT WALK THAT REACHED NO LEAF IS NOT AN EMPTY DIRECTORY, and this
    // is the worse half of the two admissions here — the count line below at
    // least states something arithmetically true about what was recovered,
    // whereas "No resources found" is a positive claim about the FILE that a
    // budget exhaustion makes false. It is `HeaderView`'s imphash distinction
    // in view form: `""` means "imports nothing" and `null` means "the table is
    // not whole", and collapsing the two prints "No imports" over a table that
    // was merely cut short.
    //
    // Reachable without a leaf: the allowance is spent walking DIRECTORY
    // entries, so a root declaring more subdirectories than `MAX_TOTAL_ENTRIES`
    // exhausts it before `walkDirectory` ever descends to a data entry.
    if (pe?.resources?.truncated) {
      return (
        <div className="p-4 text-xs text-yellow-400">
          {`The resource directory could not be read whole: the walk stopped before reaching any resource — at its ${MAX_TOTAL_ENTRIES}-entry budget, or where the directory runs past the end of the file. This file is not necessarily without resources.`}
        </div>
      );
    }
    return <div className="p-4 text-xs text-gray-500">No resources found in this PE file.</div>;
  }

  const { resources } = pe;

  return (
    <div className="p-4 text-xs overflow-auto h-full">
      <div className="flex items-center gap-4 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Resources ({typeCount} types, {totalEntries} entries)
        </h2>
        {/* THE ADMISSION, ON THE COUNT AND NOT ON A ROW. `parseResourceDirectory`
            has set `ResourceTree.truncated` since long before this and nothing
            rendered it, so a tree cut short by `MAX_TOTAL_ENTRIES` read on
            screen exactly like a complete one — the narrower answer wearing a
            complete one's shape.

            WHY ONE LINE RATHER THAN A PER-ROW MARKER, which is where the
            Imports tab puts half of its own admission: the budget is GLOBAL to
            the walk — and it is not even the only thing that can cut one short,
            which is why the sentence names entries rather than the budget alone
            (`Budget.incomplete` in `pe/resources.ts` names the other three).
            One `Budget` is threaded by reference through every
            `walkDirectory` frame, so when it runs out the walk breaks out of
            whatever directory it had reached and every ancestor above it is
            equally short. There is no row that is "the incomplete one" to mark,
            and claiming there were would state a fact the flag does not carry.
            `ImportEntry.truncated` is per-library precisely because each
            descriptor has its own thunk walk.

            The COUNTS beside it are the sentence a reader actually reads about
            a list's extent — `peek-a-bin-tmo9`'s finding — so this sits next to
            them rather than anywhere else on the page. See `peek-a-bin-dhcx`. */}
        {resources.truncated && (
          <span
            className="text-yellow-400 text-[11px]"
            title={`The resource directory could not be read whole: the walk stopped before every entry the file declares was visited — at its ${MAX_TOTAL_ENTRIES}-entry budget, or where the directory runs past the end of the file. The counts above describe what was recovered, not what the file declares.`}
          >
            Incomplete &mdash; the walk did not cover every entry
          </span>
        )}
      </div>

      <div className="space-y-1">
        {grouped.map(([typeKey, entries]) => {
          const typeId = entries[0].type;
          const typeName = getTypeName(typeId);
          const isCollapsed = collapsed.has(typeKey);

          return (
            <div key={typeKey}>
              <button
                type="button"
                onClick={() => toggleCollapse(typeKey)}
                className="flex items-center gap-1.5 text-yellow-400 font-semibold hover:text-yellow-300 py-0.5"
              >
                <span className="text-[10px] text-gray-500 w-3 inline-block">
                  {isCollapsed ? "\u25B6" : "\u25BC"}
                </span>
                {typeName}
                <span className="text-gray-500 font-normal text-[10px]">({entries.length})</span>
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
                        const leafKey = `${typeKey}-${keyPart(entry.name)}-${keyPart(entry.lang)}-${idx}`;
                        const isExpanded = expanded.has(leafKey);
                        const nameDisplay = ordinalLabel(entry.name);
                        const langDisplay = ordinalLabel(entry.lang);

                        return (
                          // KEYED FRAGMENT, not `<>`. The array element here is
                          // the fragment, so a shorthand one — which cannot take
                          // a key — left React reconciling these rows by index
                          // and logging "Each child in a list should have a
                          // unique key" on every render of a populated tab. The
                          // keys were on the fragment's CHILDREN, where React
                          // does not look for a list key.
                          <Fragment key={leafKey}>
                            <tr className="text-gray-300 hover:bg-gray-800/50">
                              <td className="py-0.5 pr-4">
                                <button
                                  type="button"
                                  onClick={() => toggleExpand(leafKey)}
                                  className="hover:text-blue-400"
                                >
                                  <span className="text-[10px] text-gray-500 w-3 inline-block mr-1">
                                    {isExpanded ? "\u25BC" : "\u25B6"}
                                  </span>
                                  {nameDisplay}
                                </button>
                              </td>
                              <td className="py-0.5 pr-4 text-gray-500">{langDisplay}</td>
                              <td className="py-0.5 pr-4 font-mono">{formatSize(entry.size)}</td>
                              <td className="py-0.5 pr-4 font-mono text-blue-400">
                                0x{entry.rva.toString(16).toUpperCase()}
                              </td>
                              <td className="py-0.5">
                                <button
                                  type="button"
                                  onClick={() =>
                                    downloadResource(
                                      pe.buffer,
                                      entry.rva,
                                      entry.size,
                                      pe.sections,
                                      `resource_${typeName}_${nameDisplay}_${langDisplay}.bin`,
                                    )
                                  }
                                  className="text-gray-500 hover:text-blue-400 text-[10px]"
                                >
                                  Download
                                </button>
                              </td>
                            </tr>
                            {isExpanded && (
                              <tr>
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
                          </Fragment>
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
