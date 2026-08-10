// Section header bar, view-toggle buttons, filter select, export menu and the
// four search banners, moved verbatim out of DisassemblyView's return. Pure
// JSX — this component deliberately declares no hooks of its own.
import type { RefObject, Dispatch } from "react";
import type { Instruction, DisasmFunction } from "../disasm/types";
import type { SectionHeader } from "../pe/types";
import type { AppAction } from "../hooks/usePEFile";
import type { UseDisassemblySearchResult, CrossSectionResult } from "../hooks/useDisassemblySearch";

export type InsnFilter = "all" | "calls" | "jumps" | "stringrefs" | "suspicious";

export function DisassemblyToolbar({
  sectionInfo,
  sectionBaseVA,
  sectionEndVA,
  isExecutable,
  instructions,
  insnFilter,
  setInsnFilter,
  filterMatchCount,
  showArrows,
  setShowArrows,
  showMinimap,
  setShowMinimap,
  showBytes,
  setShowBytes,
  viewMode,
  setViewMode,
  currentFunc,
  showDecompile,
  handleDecompileToggle,
  showXrefPanel,
  setShowXrefPanel,
  showExportMenu,
  setShowExportMenu,
  handleExportAsm,
  search,
  searchInputRef,
  parentRef,
  dispatch,
}: {
  sectionInfo: SectionHeader;
  sectionBaseVA: number;
  sectionEndVA: number;
  isExecutable: boolean;
  instructions: Instruction[];
  insnFilter: InsnFilter;
  setInsnFilter: (v: InsnFilter) => void;
  filterMatchCount: number;
  showArrows: boolean;
  setShowArrows: (fn: (v: boolean) => boolean) => void;
  showMinimap: boolean;
  setShowMinimap: (fn: (v: boolean) => boolean) => void;
  showBytes: boolean;
  setShowBytes: (fn: (v: boolean) => boolean) => void;
  viewMode: "linear" | "graph";
  setViewMode: (fn: (v: "linear" | "graph") => "linear" | "graph") => void;
  currentFunc: DisasmFunction | null;
  showDecompile: boolean;
  handleDecompileToggle: () => void;
  showXrefPanel: boolean;
  setShowXrefPanel: (fn: (v: boolean) => boolean) => void;
  showExportMenu: boolean;
  setShowExportMenu: (fn: (v: boolean) => boolean) => void;
  handleExportAsm: (mode: "function" | "section") => void;
  search: UseDisassemblySearchResult;
  searchInputRef: RefObject<HTMLInputElement | null>;
  parentRef: RefObject<HTMLDivElement | null>;
  dispatch: Dispatch<AppAction>;
}) {
  return (
    <>
      {/* Section header bar */}
      <div className="flex items-center gap-3 px-4 py-1 bg-gray-800/50 border-b border-gray-700 text-xs text-gray-400 shrink-0">
        <span className="font-semibold text-gray-300">{sectionInfo.name}</span>
        <span>
          VA: 0x{sectionBaseVA.toString(16).toUpperCase()} – 0x
          {sectionEndVA.toString(16).toUpperCase()}
        </span>
        <span>Size: 0x{sectionInfo.virtualSize.toString(16).toUpperCase()}</span>
        <span>
          {isExecutable ? `${instructions.length.toLocaleString()} instructions` : "data section"}
        </span>
        {isExecutable && (
          <>
            <select
              value={insnFilter}
              onChange={(e) => setInsnFilter(e.target.value as typeof insnFilter)}
              className="px-1.5 py-0.5 bg-gray-800 border border-gray-600 rounded text-gray-200 text-[10px]"
            >
              <option value="all">All</option>
              <option value="calls">Calls</option>
              <option value="jumps">Jumps</option>
              <option value="stringrefs">String refs</option>
              <option value="suspicious">Suspicious</option>
            </select>
            {insnFilter !== "all" && (
              <span className="text-gray-500 text-[10px]">({filterMatchCount} matches)</span>
            )}
          </>
        )}
        <div className="flex items-center gap-1 ml-2">
          <button
            type="button"
            onClick={() => setShowArrows((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showArrows ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
          >
            Arrows
          </button>
          {viewMode === "linear" && (
            <button
              type="button"
              onClick={() => setShowMinimap((v) => !v)}
              className={`px-1.5 py-0.5 rounded text-[10px] ${showMinimap ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
            >
              Map
            </button>
          )}
          <button
            type="button"
            onClick={() => {
              setShowBytes((v) => {
                const next = !v;
                try {
                  localStorage.setItem("peek-a-bin:show-bytes", String(next));
                } catch {}
                return next;
              });
            }}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showBytes ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
            title="Toggle bytes column"
          >
            Bytes
          </button>
          <button
            type="button"
            onClick={() => setViewMode((v) => (v === "graph" ? "linear" : "graph"))}
            disabled={!currentFunc || !isExecutable}
            className={`px-1.5 py-0.5 rounded text-[10px] ${viewMode === "graph" ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"} disabled:opacity-30`}
            title="Toggle graph view (Space)"
          >
            Graph
          </button>
          <button
            type="button"
            onClick={handleDecompileToggle}
            disabled={!currentFunc || !isExecutable}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showDecompile ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"} disabled:opacity-30`}
            title="Decompile current function (D)"
          >
            Decompile
          </button>
          <button
            type="button"
            onClick={() => setShowXrefPanel((v) => !v)}
            className={`px-1.5 py-0.5 rounded text-[10px] ${showXrefPanel ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-400 hover:bg-gray-600"}`}
            title="Toggle cross-reference panel (R)"
          >
            Xrefs
          </button>
          <div className="relative">
            <button
              type="button"
              onClick={() => setShowExportMenu((v) => !v)}
              className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-400 hover:bg-gray-600"
              title="Export disassembly as .asm file"
            >
              Export
            </button>
            {showExportMenu && (
              <div className="absolute top-full left-0 mt-0.5 bg-gray-800 border border-gray-600 rounded shadow-xl z-50 text-[10px] min-w-[140px]">
                <button
                  type="button"
                  onClick={() => handleExportAsm("function")}
                  disabled={!currentFunc}
                  className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200 disabled:opacity-30 disabled:cursor-default"
                >
                  Current function
                </button>
                <button
                  type="button"
                  onClick={() => handleExportAsm("section")}
                  className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
                >
                  Entire section
                </button>
              </div>
            )}
          </div>
        </div>
        <div className="flex-1" />
        {search.showSearch && (
          <div className="flex items-center gap-1">
            <input
              ref={searchInputRef}
              type="text"
              value={search.searchQuery}
              onChange={(e) => {
                const value = e.target.value;
                search.setSearchQuery(value);
                clearTimeout(search.searchDebounceRef.current);
                search.searchDebounceRef.current = setTimeout(
                  () => search.handleSearch(value),
                  150,
                );
              }}
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  clearTimeout(search.searchDebounceRef.current);
                  if (e.shiftKey) search.handleSearchPrev();
                  else if (search.searchMatches.length > 0) search.handleSearchNext();
                  else search.handleSearch(search.searchQuery);
                }
                if (e.key === "Escape") {
                  clearTimeout(search.searchDebounceRef.current);
                  search.resetSearch();
                  parentRef.current?.focus();
                }
                e.stopPropagation();
              }}
              placeholder="Search... (/regex/)"
              title={
                search.searchRegexError ? "Invalid regex" : "Substring search, or /regex/ for regex"
              }
              className={`w-48 px-2 py-0.5 bg-gray-800 border rounded text-gray-200 placeholder-gray-500 focus:outline-none ${
                search.searchRegexError ? "border-red-500" : "border-gray-600 focus:border-blue-500"
              }`}
            />
            {search.searchMatches.length > 0 && (
              <span className="text-gray-500 text-[10px]">
                {search.searchMatchIdx + 1}/{search.searchMatches.length}
              </span>
            )}
            {search.searchRegexError && (
              <span className="text-red-400 text-[10px]">Invalid regex</span>
            )}
            {search.searchQuery &&
              !search.searchRegexError &&
              search.searchMatches.length === 0 &&
              !search.crossResults && <span className="text-red-400 text-[10px]">No matches</span>}
            <button
              type="button"
              onClick={search.handleSearchPrev}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
              title="Previous (Shift+Enter)"
            >
              ▲
            </button>
            <button
              type="button"
              onClick={search.handleSearchNext}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
              title="Next (Enter)"
            >
              ▼
            </button>
            <button
              type="button"
              onClick={() => {
                search.resetSearch();
                parentRef.current?.focus();
              }}
              className="px-1 py-0.5 text-gray-400 hover:text-white"
            >
              ✕
            </button>
            <div className="relative group">
              <button
                type="button"
                className="px-1 py-0.5 text-gray-500 hover:text-gray-300 text-[10px]"
              >
                ?
              </button>
              <div className="hidden group-hover:block absolute right-0 top-full mt-1 w-56 px-2 py-1.5 bg-gray-800 border border-gray-600 rounded text-[10px] text-gray-300 z-50 shadow-lg whitespace-normal">
                Substring match by default. Use <span className="text-blue-400">/pattern/</span> for
                regex, <span className="text-blue-400">/pattern/i</span> for case-insensitive.
              </div>
            </div>
          </div>
        )}
      </div>

      {/* Grouped search results */}
      {search.showSearch && search.searchMatchGroups.length > 1 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs max-h-40 overflow-auto">
          <div className="text-gray-400 mb-1">
            {search.searchMatches.length} matches in {search.searchMatchGroups.length} functions:
          </div>
          {search.searchMatchGroups.map((g) => (
            <button
              type="button"
              key={g.funcAddr}
              onClick={() => dispatch({ type: "SET_ADDRESS", address: g.funcAddr })}
              className="block w-full text-left hover:bg-gray-700/50 rounded px-1 py-0.5 truncate"
            >
              <span className="text-blue-400">{g.funcName}</span>{" "}
              <span className="text-gray-500">({g.matches.length})</span>
            </button>
          ))}
        </div>
      )}

      {/* Cross-section search prompt */}
      {search.showSearch &&
        search.searchQuery &&
        search.searchMatches.length === 0 &&
        !search.crossResults &&
        !search.crossSearching && (
          <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs flex items-center gap-2">
            <span className="text-gray-400">No matches in {sectionInfo.name}.</span>
            <button
              type="button"
              onClick={search.handleCrossSearch}
              className="text-blue-400 hover:text-blue-300 hover:underline"
            >
              Search all sections?
            </button>
          </div>
        )}

      {/* Cross-section search loading */}
      {search.crossSearching && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs text-gray-400 flex items-center gap-2">
          <svg aria-hidden="true" className="animate-spin h-3 w-3" viewBox="0 0 24 24">
            <circle
              className="opacity-25"
              cx="12"
              cy="12"
              r="10"
              stroke="currentColor"
              strokeWidth="4"
              fill="none"
            />
            <path
              className="opacity-75"
              fill="currentColor"
              d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z"
            />
          </svg>
          Searching all sections...
        </div>
      )}

      {/* Cross-section search results */}
      {search.crossResults && search.crossResults.length > 0 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs max-h-40 overflow-auto">
          <div className="text-gray-400 mb-1">
            {search.crossResults.length} result{search.crossResults.length !== 1 ? "s" : ""} in
            other sections:
          </div>
          {search.crossResults.map((r: CrossSectionResult, i: number) => (
            <button
              type="button"
              key={i}
              onClick={() => {
                dispatch({ type: "SET_ADDRESS", address: r.address });
                search.resetSearch();
              }}
              className="block w-full text-left hover:bg-gray-700/50 rounded px-1 py-0.5 truncate"
            >
              <span className="text-gray-500">[{r.section.name}]</span>{" "}
              <span className="text-blue-400">0x{r.address.toString(16).toUpperCase()}</span>{" "}
              <span className="text-gray-300">{r.text}</span>
            </button>
          ))}
        </div>
      )}
      {search.crossResults && search.crossResults.length === 0 && (
        <div className="px-4 py-1.5 bg-gray-800/80 border-b border-gray-700 text-xs text-gray-500">
          No matches found in any section.
        </div>
      )}
    </>
  );
}
