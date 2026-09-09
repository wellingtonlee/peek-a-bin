import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { useAppDispatch, useAppState } from "../hooks/usePEFile";
import {
  IMAGE_DIRECTORY_ENTRY_RESOURCE,
  ResourceTypeNames,
  RT_GROUP_ICON,
  RT_ICON,
  RT_MANIFEST,
  RT_VERSION,
} from "../pe/constants";
import { resourcesUnreadable } from "../pe/dataDirectories";
import { rvaToFileOffset } from "../pe/parser";
import { MAX_TOTAL_ENTRIES, parseVersionInfo, reconstructIcon } from "../pe/resources";
import type { ResourceTree } from "../pe/types";

type UnreadableReason = "unmapped" | "past-end";

/**
 * What {@link resourceBytes} answers.
 *
 * A UNION RATHER THAN `Uint8Array | null` BECAUSE THE TWO REFUSALS ARE TWO
 * DIFFERENT FACTS ABOUT THE FILE, and a caller that has to print a sentence
 * needs to know which. `unmapped` means the directory names an RVA that falls
 * in no section — a malformed or hand-rolled directory; `past-end` means the
 * section table maps it fine and the FILE is short of it — a truncated image.
 * Collapsing them into one null is the same shape `HeaderView` refuses for
 * imphash, where `""` means "imports nothing" and `null` means "the table is
 * not whole".
 *
 * The reason is carried out of the GUARD rather than re-derived at the call
 * site, which is the whole point: a second `rvaToFileOffset` comparison
 * somewhere else is a second declaration of the bound, and it is exactly the
 * copy that would drift back into the `RangeError` below.
 */
type ResourceRead = { bytes: Uint8Array; reason: null } | { bytes: null; reason: UnreadableReason };

/**
 * The bytes a resource leaf names, or {@link ResourceRead}'s refusal and the
 * reason for it where the file does not contain them.
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
): ResourceRead {
  const fileOff = rvaToFileOffset(rva, sections);
  if (fileOff < 0) return { bytes: null, reason: "unmapped" };
  if (fileOff >= buffer.byteLength) return { bytes: null, reason: "past-end" };
  return {
    bytes: new Uint8Array(buffer, fileOff, Math.min(size, buffer.byteLength - fileOff)),
    reason: null,
  };
}

/**
 * The sentence each refusal prints. A `Record` over the union, on
 * `DETECT_PASS_LABELS`' and `VIEW_TAB_LABELS`' model, so a third reason fails
 * the build here rather than reaching the page as an unexplained empty box —
 * which is the defect this whole arm exists to close.
 */
const UNREADABLE_SENTENCE: Record<UnreadableReason, string> = {
  unmapped:
    "This resource's bytes could not be read: its RVA falls in no section, so the directory names an address this image does not map.",
  "past-end":
    "This resource's bytes could not be read: the section table places them past the end of the file, so this image is truncated and does not contain them.",
};

function Unreadable({ reason }: { reason: UnreadableReason }) {
  return (
    <div className="ml-8 my-1 py-1 text-yellow-400 max-w-prose">{UNREADABLE_SENTENCE[reason]}</div>
  );
}

/**
 * How much of a leaf the hex fallback prints.
 *
 * A CAP WITH AN ADMISSION ON THE COUNT LINE, never a silent clip: a resource is
 * routinely megabytes (a bitmap, an embedded payload) and a `<pre>` of all of
 * it is a rendering cost for no reading benefit — but a preview that just stops
 * is the narrower answer wearing a complete one's shape, so the count line says
 * `first 256 of N bytes` and only says `N bytes` when N really is all of them.
 */
const PREVIEW_BYTES = 256;
const PREVIEW_ROW = 16;

/**
 * The hex/ASCII fallback — WHAT EVERY LEAF WITH NO DEDICATED ARM USED TO SHOW
 * INSTEAD OF NOTHING.
 *
 * Every leaf row renders an expand caret, and `ExpandedLeaf` handled only
 * RT_VERSION, RT_GROUP_ICON and RT_MANIFEST. So clicking the caret on an
 * RT_BITMAP, RT_STRING, RT_DIALOG or RT_RCDATA flipped the arrow to its open
 * state and produced an empty `<tr><td colSpan={5}>` — a control that visibly
 * did nothing, which reads as the pane being broken rather than as the type
 * being unhandled. Those four are most of what an ordinary binary carries.
 *
 * OFFSETS ARE RESOURCE-RELATIVE, not file offsets: this pane never shows a file
 * offset anywhere, and the RVA column beside it is the address a reader would
 * take to the Hex tab. `size` is the DECLARED size and `bytes.length` what the
 * file actually holds, which differ on a truncated image whose cut lands inside
 * a leaf — so both are printed rather than one standing in for the other.
 */
function HexPreview({ bytes, size }: { bytes: Uint8Array; size: number }) {
  const available = bytes.length;
  const shown = bytes.subarray(0, PREVIEW_BYTES);
  const lines: string[] = [];
  for (let off = 0; off < shown.length; off += PREVIEW_ROW) {
    const row = shown.subarray(off, off + PREVIEW_ROW);
    const hex = Array.from(row, (b) => b.toString(16).padStart(2, "0"))
      .join(" ")
      .padEnd(PREVIEW_ROW * 3 - 1, " ");
    const ascii = Array.from(row, (b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : "."))
      .join("")
      .padEnd(PREVIEW_ROW, " ");
    lines.push(`${off.toString(16).padStart(8, "0")}  ${hex}  |${ascii}|`);
  }
  return (
    <div className="ml-8 my-1">
      <div className="text-gray-500 text-[10px]">
        {available > shown.length
          ? `Hex preview \u2014 first ${shown.length} of ${available.toLocaleString()} bytes`
          : `Hex preview \u2014 ${available.toLocaleString()} bytes`}
        {available < size &&
          ` (the file holds ${available.toLocaleString()} of the ${size.toLocaleString()} bytes the directory declares)`}
      </div>
      {/* `available === 0` IMPLIES `size === 0` here and the sentence is safe
          because of it: `resourceBytes` has already refused with `past-end`
          wherever the offset is outside the buffer, so the clamp can only
          return nothing when the directory asked for nothing. */}
      {available === 0 ? (
        <div className="text-gray-500 py-1">This resource declares no bytes.</div>
      ) : (
        <pre className="mt-1 p-2 bg-gray-800 border border-gray-700 rounded text-[10px] text-gray-300 overflow-auto max-h-60 whitespace-pre">
          {lines.join("\n")}
        </pre>
      )}
    </div>
  );
}

/**
 * THE GROUP-ICON PREVIEW, AND THE REASON IT IS ITS OWN COMPONENT: the object
 * URL it needs must be REVOKED, and only a child with its own effect has a
 * cleanup to revoke it in.
 *
 * `ExpandedLeaf` minted the URL with `URL.createObjectURL` in the middle of
 * RENDER and never called `URL.revokeObjectURL` at all — so every render of an
 * expanded group icon leaked another blob, pinned for the lifetime of the
 * document, and this pane re-renders on every collapse, expand and download
 * click. Minting during render is also wrong on its own terms: a render React
 * throws away (a concurrent retry, StrictMode's double invoke) leaks a URL no
 * cleanup will ever see, because no effect ever ran for it.
 *
 * The reconstruction is memoised so the effect key is stable across the parent
 * re-renders that do not change the bytes; where it does change, the cleanup
 * revokes the old URL before the next one is minted, so creates and revokes
 * stay one-for-one.
 */
function GroupIconPreview({
  rva,
  size,
  buffer,
  sections,
  resourceTree,
}: {
  rva: number;
  size: number;
  buffer: ArrayBuffer;
  sections: import("../pe/types").SectionHeader[];
  resourceTree: ResourceTree;
}) {
  const ico = useMemo(() => {
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
    return reconstructIcon(buffer, groupData, iconEntries, sections);
  }, [buffer, rva, size, sections, resourceTree]);

  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!ico) return;
    const minted = URL.createObjectURL(new Blob([ico], { type: "image/x-icon" }));
    setUrl(minted);
    return () => {
      URL.revokeObjectURL(minted);
      setUrl(null);
    };
  }, [ico]);

  if (!ico) return <div className="text-gray-500 ml-8 py-1">Could not reconstruct icon</div>;
  if (!url) return null;
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

  if (numType === RT_GROUP_ICON) {
    return (
      <GroupIconPreview
        rva={rva}
        size={size}
        buffer={buffer}
        sections={sections}
        resourceTree={resourceTree}
      />
    );
  }

  // THE GUARD SITS ABOVE EVERY REMAINING ARM, and above RT_VERSION in
  // particular: `parseVersionInfo` bounds its own reads, so on a truncated
  // image it answered `{}` and the arm printed "No version strings found" — a
  // positive claim about the RESOURCE resting on the tool's failure to reach
  // its bytes, which is `peek-a-bin-wo8g`'s class one level down. The
  // group-icon arm above is deliberately outside it; see {@link
  // GroupIconPreview}.
  const read = resourceBytes(buffer, rva, size, sections);
  if (!read.bytes) return <Unreadable reason={read.reason} />;

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

  if (numType === RT_MANIFEST) {
    const text = new TextDecoder("utf-8").decode(read.bytes);
    return (
      <pre className="ml-8 my-1 p-2 bg-gray-800 border border-gray-700 rounded text-[10px] text-gray-300 overflow-auto max-h-60 whitespace-pre-wrap">
        {text}
      </pre>
    );
  }

  // EVERY OTHER TYPE, rather than nothing. See {@link HexPreview}.
  return <HexPreview bytes={read.bytes} size={size} />;
}

function downloadResource(
  buffer: ArrayBuffer,
  rva: number,
  size: number,
  sections: import("../pe/types").SectionHeader[],
  name: string,
) {
  const read = resourceBytes(buffer, rva, size, sections);
  if (!read.bytes) return;
  const blob = new Blob([read.bytes]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  URL.revokeObjectURL(url);
}

export function ResourcesView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
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

  /**
   * The RVA column's click. `imageBase + rva` is the VA the rest of the app
   * speaks, and the two dispatches are the same pair `SectionTable`'s rows and
   * `useInsnContextMenu`'s "show in hex" already use — address first, then the
   * tab, so the tab that mounts already has the address to derive its section
   * from.
   */
  const goToRva = useCallback(
    (rva: number) => {
      if (!pe) return;
      dispatch({ type: "SET_ADDRESS", address: pe.optionalHeader.imageBase + rva });
      dispatch({ type: "SET_TAB", tab: "hex" });
    },
    [dispatch, pe],
  );

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
    // A DECLARED DIRECTORY WITH NO TREE AT ALL IS THE READER HAVING FAILED, and
    // it is the only one of these three arms where this pane knows nothing
    // whatever about the resources — the arm below has a tree and can say the
    // walk was cut short. (The ORDER of the two is not load-bearing and is not
    // claimed to be: the arms are disjoint, since `truncated` is a field on a
    // tree that exists. It reads first because it is the wider statement.)
    // `resourcesUnreadable`
    // (`pe/dataDirectories.ts`) is the one declaration of the pair, and it shares
    // its premise with the gate `parsePE` opens the reader behind, so this cannot
    // claim a failure on a directory nothing tried to read.
    //
    // ITS POPULATION IS CURRENTLY EMPTY AND SAYING SO IS THE POINT: no fixture
    // reaches `parsePE`'s `catch` today, because `parseResourceDirectory` bounds
    // every read on the buffer and flags an unresolvable RVA rather than
    // throwing. This is the guard that stops the day it does throw from printing
    // "No resources found in this PE file." over a file full of them.
    // (peek-a-bin-wo8g)
    if (pe && resourcesUnreadable(pe)) {
      return (
        <div className="p-4 text-xs text-yellow-400">
          {`The resource directory could not be read. The file declares one at RVA 0x${pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].virtualAddress.toString(16).toUpperCase()} of ${pe.dataDirectories[IMAGE_DIRECTORY_ENTRY_RESOURCE].size.toLocaleString()} bytes, and the reader stopped on it. This file is not without resources.`}
        </div>
      );
    }
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
                              {/* A REAL CONTROL, because it was already dressed
                                  as one. This cell has been `text-blue-400`
                                  monospace since the tab was written — every
                                  other blue address in this app is clickable
                                  (`SectionTable`'s rows, `HeaderView`'s
                                  `CopyableHex`, every operand in the listing) —
                                  and this one was inert text inside a plain
                                  `<td>`. An affordance that is not one is worse
                                  than no affordance: a reader clicks it, gets
                                  nothing, and learns to distrust the colour.

                                  It goes to the HEX tab rather than the
                                  disassembly: `.rsrc` is data, and `HexView`
                                  derives its section from `state.currentAddress`
                                  alone, so the VA resolves to `.rsrc` and its
                                  own scroll-to-offset effect does the rest. The
                                  disassembly tab would show a linear sweep of
                                  resource bytes, which is the invented-code
                                  reading this repo goes out of its way to avoid
                                  elsewhere. */}
                              <td className="py-0.5 pr-4 font-mono">
                                <button
                                  type="button"
                                  onClick={() => goToRva(entry.rva)}
                                  title="Show these bytes in the Hex view"
                                  className="text-blue-400 hover:text-blue-300 hover:underline"
                                >
                                  0x{entry.rva.toString(16).toUpperCase()}
                                </button>
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
