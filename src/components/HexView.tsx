import { useVirtualizer } from "@tanstack/react-virtual";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useDismissOnOutsideClick } from "../hooks/useDismissOnOutsideClick";
import { useEntropyStrip } from "../hooks/useFileMetrics";
import { useAppDispatch, useAppState } from "../hooks/usePEFile";
import { copyText } from "../utils/clipboard";
import {
  dprMediaQuery,
  ENTROPY_STRIP_HEIGHT_PX,
  entropyBlockAtX,
  entropyBlocksForWidth,
  entropyStripGeometry,
  nextStripWidth,
  stripDeviceWidth,
} from "../utils/entropy";
import { DataInspector } from "./DataInspector";
import { focusOnMount } from "./focusOnMount";

const BYTES_PER_ROW = 16;

/**
 * How long the byte search waits after a keystroke before it scans.
 *
 * The scan is a main-thread walk of the WHOLE selected section (up to
 * `sizeOfRawData`) that also rebuilds a `Set` of every matched byte, and it ran
 * on every character typed — so `4D 5A 90 00` was four full walks, three of them
 * over prefixes nobody asked about. 150 ms is `DisassemblyToolbar`'s figure for
 * the same job, taken deliberately rather than minting a second number to keep
 * in step.
 *
 * Exported so a test can derive BOTH sides of the boundary from it. A single
 * advance past a debounce cannot tell one from no debounce at all — "nothing has
 * happened yet" is equally true of a 0 ms timer nobody ticked — and that control
 * has come back inert twice in this repo, so the tests assert short of this
 * value as well as past it.
 */
export const BYTE_SEARCH_DEBOUNCE_MS = 150;

/** Stable empty result, so the handlers below keep stable identities. */
const NO_BLOCKS: number[] = [];

function parseBytePattern(input: string): (number | null)[] | null {
  const parts = input.trim().split(/\s+/);
  if (parts.length === 0 || (parts.length === 1 && parts[0] === "")) return null;
  const bytes: (number | null)[] = [];
  for (const p of parts) {
    if (p === "??" || p === "?") {
      bytes.push(null);
      continue;
    }
    const v = parseInt(p, 16);
    if (Number.isNaN(v) || v < 0 || v > 255) return null;
    bytes.push(v);
  }
  return bytes.length > 0 ? bytes : null;
}

/**
 * How many byte-pattern matches one search reports.
 *
 * The cap bounds the highlight set and the work of building it. It is a property
 * of the SCAN and not of the section, so whether it was reached is part of the
 * answer rather than something the caller may infer — see
 * {@link BytePatternMatches.truncated}.
 */
export const MAX_BYTE_PATTERN_MATCHES = 1000;

/**
 * One byte-pattern scan's result, and the admission that travels with it.
 *
 * This is the `TRUNCATION_MARKER` / `ImportEntry.truncated` /
 * `ResourceTree.incomplete` / `PEFile.stringScan` family in view form: a
 * narrower answer must not wear a complete one's shape. Before this the scan
 * broke at the cap and the toolbar printed the length, so a section with a
 * million occurrences of `00` reported "1000 matches" as a fact about itself.
 *
 * `truncated` is decided **exactly** — "a match beyond the cap exists" — and NOT
 * "we collected {@link MAX_BYTE_PATTERN_MATCHES}", which is the off-by-one
 * `peek-a-bin-dhcx` found one reader over in `ResourceTree`, where a directory
 * holding exactly its budget claimed to be short over a complete answer. A
 * result of exactly the cap's size is a WHOLE answer and is not marked.
 */
interface BytePatternMatches {
  offsets: number[];
  truncated: boolean;
}

function findBytePatternMatches(data: Uint8Array, pattern: (number | null)[]): BytePatternMatches {
  const offsets: number[] = [];
  if (pattern.length === 0) return { offsets, truncated: false };
  const end = data.length - pattern.length;
  outer: for (let i = 0; i <= end; i++) {
    for (let j = 0; j < pattern.length; j++) {
      if (pattern[j] !== null && data[i + j] !== pattern[j]) continue outer;
    }
    // The scan stops ON the match that would EXCEED the cap, never on the one
    // that fills it. That is the whole of what makes `truncated` exact, and it
    // costs at most one further walk over bytes this loop was already covering
    // — the cap was never an asymptotic bound, it is a bound on the result.
    if (offsets.length === MAX_BYTE_PATTERN_MATCHES) {
      return { offsets, truncated: true };
    }
    offsets.push(i);
  }
  return { offsets, truncated: false };
}

/**
 * The one sentence the byte search reports: the count, the `+` marking a count
 * that is a floor rather than a total, the scope, and the admission.
 *
 * The admission goes on the COUNT LINE and not on a match, because the bound is
 * global to the scan and no single match is "the incomplete one" — the same half
 * of that choice `ResourceTree.incomplete` takes, as against
 * `ImportEntry.truncated`, which is per-library because each descriptor has its
 * own walk.
 *
 * The SCOPE is here for a second reason of the same class: the scan covers
 * `sectionBytes`, one section, so an unscoped count reads as a fact about the
 * FILE (`peek-a-bin-2py5`'s `stringScan` shape at much smaller stakes).
 */
function matchSummary(count: number, truncated: boolean, scope: string): string {
  const plural = count === 1 ? "match" : "matches";
  const admission = truncated ? ` (search stopped at ${MAX_BYTE_PATTERN_MATCHES})` : "";
  return `${count}${truncated ? "+" : ""} ${plural} in ${scope}${admission}`;
}

/**
 * One COMPLETED scan, carrying the question it answers.
 *
 * The query and the section are stored beside the offsets because the answer and
 * the question live in different commits. `byteSearch` is what is in the box;
 * the scan runs {@link BYTE_SEARCH_DEBOUNCE_MS} later off `activeSearch`, and a
 * passive effect flushes after the render that scheduled it. So there are two
 * windows in which the two disagree — a 150 ms one while the debounce is
 * pending, and a one-frame one between `activeSearch` moving and the effect
 * running — and in both of them the toolbar was describing the PREVIOUS scan
 * under the CURRENT query.
 *
 * That is not cosmetic, because one of the things it says is `No matches in
 * .rdata`, WHICH IS A POSITIVE CLAIM ABOUT THE SECTION. Typing over a query that
 * found nothing left that sentence standing for 150 ms beside a pattern nothing
 * had looked for yet — a narrower answer (in fact no answer) wearing a complete
 * one's shape, the `ImportEntry.truncated` / `ResourceTree.incomplete` /
 * `PEFile.stringScan` rule in its most literal form.
 *
 * So the two states are made distinguishable rather than merged: `query` and
 * `data` are compared against what is on screen NOW (`searchSettled`), and every
 * sentence and every control the search offers is gated on that. `data` is
 * compared by IDENTITY and is the second axis on purpose — switching sections
 * changes neither the box nor the debounce, so a query-only test would have
 * reported one section's count under another section's name.
 */
interface ByteSearchResult {
  /** The query scanned. Compared against the BOX, not against `activeSearch`. */
  query: string;
  /** The section scanned, by identity. */
  data: Uint8Array | null;
  /** Where the matches are — see {@link HexView}'s `matchOffsets`. */
  offsets: number[];
  /** Whether {@link findBytePatternMatches} stopped short of the section. */
  truncated: boolean;
  /** Every byte covered by a match, for the grid's per-cell highlight. */
  highlighted: Set<number>;
}

/** The state before anything has been searched for, and after the box is emptied. */
const NO_BYTE_SEARCH: ByteSearchResult = {
  query: "",
  data: null,
  offsets: [],
  truncated: false,
  highlighted: new Set(),
};

function entropyColor(entropy: number): string {
  // blue(0) -> yellow(4) -> red(8)
  if (entropy <= 4) {
    const t = entropy / 4;
    const r = Math.round(t * 255);
    const g = Math.round(t * 255);
    const b = Math.round((1 - t) * 255);
    return `rgb(${r},${g},${b})`;
  } else {
    const t = (entropy - 4) / 4;
    const r = 255;
    const g = Math.round((1 - t) * 255);
    const b = 0;
    return `rgb(${r},${g},${b})`;
  }
}

export function HexView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const hexCtxMenuRef = useRef<HTMLDivElement>(null);
  const xrefPopupRef = useRef<HTMLDivElement>(null);
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const [goToInput, setGoToInput] = useState("");
  const [byteSearch, setByteSearch] = useState("");
  /**
   * The query the SCAN is keyed on, as against `byteSearch`, which is what is in
   * the box. The debounce is the only writer.
   */
  const [activeSearch, setActiveSearch] = useState("");
  const searchDebounceRef = useRef<ReturnType<typeof setTimeout>>(undefined);
  /**
   * The last completed scan.
   *
   * WHERE the matches are, not merely how many there were: the effect used to
   * fold the offsets into the highlight set and drop the array on the floor, so
   * a 200 KB section with forty hits could be counted and then only found by
   * scrolling. Keeping them is what next/prev is.
   */
  const [searchResult, setSearchResult] = useState<ByteSearchResult>(NO_BYTE_SEARCH);
  /** Which match next/prev last moved to; -1 before either has been pressed. */
  const [matchIdx, setMatchIdx] = useState(-1);
  const [selectedOffset, setSelectedOffset] = useState<number | null>(null);
  const [selectionEnd, setSelectionEnd] = useState<number | null>(null);
  const [editingByte, setEditingByte] = useState<number | null>(null);
  const [editValue, setEditValue] = useState("");
  const [showEntropy, setShowEntropy] = useState(false);
  /**
   * Width of the entropy strip in **device** pixels, 0 until it has been
   * measured.
   *
   * The block count follows this: a strip has ~1000 CSS px and the cap used to
   * be 4096 blocks, so four to eight of every ten blocks were computed and then
   * drawn outside the canvas. Quantized in `entropyBlocksForWidth`, so a drag
   * that moves the width by a few pixels does not change the value and there is
   * nothing to debounce.
   *
   * Device pixels rather than CSS pixels, because the canvas backing store is
   * sized in device pixels and a CSS-pixel budget therefore asked for half the
   * bars a 2x display can show (`peek-a-bin-424o`). Two consequences: the
   * `ResizeObserver` alone is not enough — a ratio change moves no CSS
   * dimension and fires nothing — and the value stored here has to be the
   * product, not the CSS width, or `nextStripWidth` compares at the wrong step.
   */
  const [stripDevicePx, setStripDevicePx] = useState(0);
  const stripRef = useRef<HTMLDivElement>(null);
  const [showDiff, setShowDiff] = useState(false);
  const [hexCtxMenu, setHexCtxMenu] = useState<{ x: number; y: number } | null>(null);
  const [entropyTooltip, setEntropyTooltip] = useState<{
    x: number;
    blockIdx: number;
    offset: number;
    endOffset: number;
    value: number;
  } | null>(null);
  const [xrefPopup, setXrefPopup] = useState<{
    addr: number;
    refs: number[];
    x: number;
    y: number;
  } | null>(null);

  // Selection range helpers
  const selectionRange = useMemo((): { start: number; end: number } | null => {
    if (selectedOffset === null) return null;
    if (selectionEnd === null) return { start: selectedOffset, end: selectedOffset };
    const start = Math.min(selectedOffset, selectionEnd);
    const end = Math.max(selectedOffset, selectionEnd);
    return { start, end };
  }, [selectedOffset, selectionEnd]);

  const selectionCount = selectionRange ? selectionRange.end - selectionRange.start + 1 : 0;

  const isInSelection = useCallback(
    (offset: number): boolean => {
      if (!selectionRange) return false;
      return offset >= selectionRange.start && offset <= selectionRange.end;
    },
    [selectionRange],
  );

  const sectionInfo = useMemo(() => {
    if (!pe) return null;
    const rva = state.currentAddress - pe.optionalHeader.imageBase;
    for (const sec of pe.sections) {
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
        return sec;
      }
    }
    return pe.sections[0] ?? null;
  }, [pe, state.currentAddress]);

  const sectionBytes = useMemo(() => {
    if (!pe || !sectionInfo) return null;
    return new Uint8Array(pe.buffer, sectionInfo.pointerToRawData, sectionInfo.sizeOfRawData);
  }, [pe, sectionInfo]);

  // Only computed while the strip is actually shown — it used to run on every
  // Hex tab open regardless, which on a 200 MiB `.text` was seconds of frozen
  // main thread for a bar the user never asked for. Above a size threshold it
  // runs in a worker; see hooks/useFileMetrics.ts.
  // Nothing is requested until the strip has been measured
  // (`stripDevicePx > 0`): asking at a default width first and at the real one a
  // frame later would compute the whole section twice.
  const entropyStrip = useEntropyStrip(
    sectionBytes,
    showEntropy && stripDevicePx > 0,
    entropyBlocksForWidth(stripDevicePx),
  );
  const entropyBlocks = entropyStrip.value?.blocks ?? NO_BLOCKS;
  const entropyBlockSize = entropyStrip.value?.blockSize ?? 256;

  const rowCount = sectionBytes ? Math.ceil(sectionBytes.length / BYTES_PER_ROW) : 0;

  const baseAddress =
    pe && sectionInfo ? pe.optionalHeader.imageBase + sectionInfo.virtualAddress : 0;

  const virtualizer = useVirtualizer({
    count: rowCount,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 20,
    overscan: 30,
  });

  // Compute row index for current address
  const currentRowIdx = useMemo(() => {
    if (!sectionBytes || !pe || !sectionInfo) return -1;
    const offset = state.currentAddress - baseAddress;
    if (offset < 0 || offset >= sectionBytes.length) return -1;
    return Math.floor(offset / BYTES_PER_ROW);
  }, [state.currentAddress, baseAddress, sectionBytes, pe, sectionInfo]);

  // Scroll to current address row
  useEffect(() => {
    if (currentRowIdx >= 0) {
      virtualizer.scrollToIndex(currentRowIdx, { align: "center" });
    }
    // useVirtualizer holds its instance in useState, so `virtualizer` is stable
    // for the component's lifetime and cannot make this effect re-fire.
  }, [currentRowIdx, virtualizer]);

  /**
   * Debounce the box into {@link activeSearch}, which is what the scan keys on.
   *
   * AN EMPTY BOX IS APPLIED AT ONCE, and that asymmetry is the point rather than
   * a shortcut: the debounce exists to stop a walk of the section per keystroke,
   * and clearing the search walks nothing — so waiting would be the one case
   * where the delay is paid and nothing is saved, on the affordance whose whole
   * job is to make the highlights go away.
   *
   * The timer is held in a ref as well as in the cleanup so that ENTER can
   * cancel it and apply the query itself; the effect's own cleanup is what
   * cancels it on a keystroke, which is why the empty-box arm below does not
   * clear it a second time.
   *
   * NEITHER HALF OF THIS ARM CAN BE MADE RED FROM HERE and that is reported
   * rather than tuned away (control C14): with an empty box every sentence the
   * toolbar prints is gated on `byteSearch` and is therefore already gone, so
   * the only thing the delay would hold back is the HIGHLIGHTS — and jsdom
   * measures the scroll container as 0px, so the grid renders no rows to
   * highlight. It is kept because the behaviour is right in a browser.
   */
  useEffect(() => {
    if (byteSearch === activeSearch) return;
    if (!byteSearch.trim()) {
      setActiveSearch(byteSearch);
      return;
    }
    const timer = setTimeout(() => setActiveSearch(byteSearch), BYTE_SEARCH_DEBOUNCE_MS);
    searchDebounceRef.current = timer;
    return () => clearTimeout(timer);
  }, [byteSearch, activeSearch]);

  // Byte pattern search
  useEffect(() => {
    // A new result is a new list, so the cursor into it starts UNSET rather than
    // at 0: a "1/40" nothing has scrolled to is a claim about where the view is.
    setMatchIdx(-1);
    const pattern = sectionBytes && activeSearch.trim() ? parseBytePattern(activeSearch) : null;
    if (!sectionBytes || !pattern) {
      // Stamped with the query and the section even so, or an unparseable query
      // would never settle and the toolbar would report a pending scan forever.
      setSearchResult({ ...NO_BYTE_SEARCH, query: activeSearch, data: sectionBytes });
      return;
    }
    const { offsets, truncated } = findBytePatternMatches(sectionBytes, pattern);
    const highlighted = new Set<number>();
    for (const off of offsets) {
      for (let j = 0; j < pattern.length; j++) highlighted.add(off + j);
    }
    setSearchResult({ query: activeSearch, data: sectionBytes, offsets, truncated, highlighted });
  }, [sectionBytes, activeSearch]);

  /**
   * Whether {@link searchResult} answers the query and the section now on
   * screen. EVERYTHING THE SEARCH SAYS OR OFFERS IS GATED ON THIS — see
   * {@link ByteSearchResult} for the two windows in which it is false and for
   * why a stale sentence there is a defect rather than a flicker.
   *
   * The highlight set is deliberately NOT gated on it: a highlight is a mark on
   * bytes that really did match a query the user really did type, where blinking
   * every match off and on again between keystrokes is a cost with nothing bought.
   *
   * THE `data` HALF CANNOT BE MADE RED BY ANY TEST HERE, reported rather than
   * dropped (control C9). Its window is one frame — a section switch changes
   * `sectionBytes` and the scan effect re-runs immediately after that render —
   * and testing-library flushes passive effects inside the same `act`, so the
   * frame in which the old section's count sits under the new section's name is
   * never observable. The query half's window is a durable 150 ms and is pinned
   * below in "HexView byte search pending state".
   */
  const searchSettled = searchResult.query === byteSearch && searchResult.data === sectionBytes;
  const byteMatches = searchResult.highlighted;
  const matchOffsets = searchResult.offsets;

  /**
   * Move to one match: the cursor, the scroll and the app's current address.
   *
   * TWO scroll routes converge here and both are wanted. The dispatch is what
   * makes the REST of the app agree — the address bar, the data inspector, and
   * the Disasm button, which hands whatever is current to the other tab. The
   * direct `scrollToIndex` is what makes the button work when the address does
   * NOT change: two matches sharing a row leave `currentRowIdx` where it was, so
   * the effect watching it fires nothing, and a user who has scrolled away
   * presses "next" and stays away. It is the same pair `handleEntropyClick` uses.
   */
  const goToMatch = useCallback(
    (idx: number) => {
      const off = matchOffsets[idx];
      if (off === undefined) return;
      setMatchIdx(idx);
      setSelectedOffset(off);
      setSelectionEnd(null);
      virtualizer.scrollToIndex(Math.floor(off / BYTES_PER_ROW), { align: "center" });
      dispatch({ type: "SET_ADDRESS", address: baseAddress + off });
    },
    [matchOffsets, virtualizer, dispatch, baseAddress],
  );

  /**
   * Next/prev, wrapping, from a cursor that may not be anywhere yet.
   *
   * `matchIdx === -1` is a third state and not a zero: forward from it is the
   * FIRST match and backward from it is the LAST, which plain modular arithmetic
   * on -1 gets wrong in the backward direction (it lands one short of the end).
   */
  const stepMatch = useCallback(
    (delta: 1 | -1) => {
      const n = matchOffsets.length;
      if (n === 0) return;
      const from = matchIdx < 0 ? (delta === 1 ? -1 : 0) : matchIdx;
      goToMatch((((from + delta) % n) + n) % n);
    },
    [matchOffsets, matchIdx, goToMatch],
  );

  // Track the strip's width *in device pixels* so the block count can follow it.
  //
  // Two inputs, because the product is what the budget is in: the element's CSS
  // width, and `devicePixelRatio`. A ratio change moves no CSS dimension, so the
  // `ResizeObserver` cannot see one and a `(resolution: Xdppx)` listener has to
  // be armed alongside it — the same single-use, re-armed query the draw effect
  // uses, and for the same reason (`dprMediaQuery`, peek-a-bin-oqp). The draw
  // effect keeps its own: it repaints on ratio changes that do not move the
  // budget at all, and this one re-renders on budget changes that need no
  // repaint of the old blocks.
  useEffect(() => {
    const el = stripRef.current;
    if (!showEntropy || !el) {
      setStripDevicePx(0);
      return;
    }
    const measure = (cssWidth: number) => {
      // `nextStripWidth` returns `prev` whenever the block budget is unchanged,
      // so this setState is a no-op by identity for small changes and a drag
      // does not re-render on every frame. It is only about the block *count* —
      // repainting the canvas at the new size is the draw effect's job, and it
      // observes the canvas itself for exactly the resizes this one swallows.
      const device = stripDeviceWidth(cssWidth, window.devicePixelRatio);
      setStripDevicePx((prev) => nextStripWidth(prev, device));
    };
    // Fires once on observe, so the first width arrives without a resize.
    const observer = new ResizeObserver((entries) => {
      measure(entries[0]?.contentRect.width ?? el.clientWidth);
    });
    observer.observe(el);

    let dprQuery: MediaQueryList | null = null;
    const onDprChange = () => {
      armDprQuery();
      measure(el.clientWidth);
    };
    // Hoisted, because it and `onDprChange` refer to each other. Nothing calls
    // it before the `const` above is initialised.
    function armDprQuery() {
      dprQuery?.removeEventListener("change", onDprChange);
      dprQuery = window.matchMedia(dprMediaQuery(window.devicePixelRatio));
      dprQuery.addEventListener("change", onDprChange);
    }
    armDprQuery();

    return () => {
      observer.disconnect();
      dprQuery?.removeEventListener("change", onDprChange);
    };
  }, [showEntropy]);

  // Draw entropy canvas.
  //
  // The canvas keeps itself painted for as long as it is mounted, rather than
  // being drawn once per render: two of the three things that change the mapping
  // from blocks to physical pixels are not React state and cannot be made into
  // it without a render per animation frame.
  //
  //  * The element's **CSS width**, which moves on every frame of a pane drag,
  //    while `stripDevicePx` above only moves when the drag crosses a whole
  //    `ENTROPY_WIDTH_QUANTUM`. In between, the backing store kept its old size
  //    and the browser stretched the strip to fit.
  //  * **`window.devicePixelRatio`**, which changes when the window is dragged
  //    to a display of a different density and, in Chrome, on browser zoom.
  //    Dragging between displays changes no CSS dimension, so the observer
  //    cannot see it; `dprMediaQuery` explains why the listener is re-armed
  //    (peek-a-bin-oqp).
  //
  // Neither *value* goes through state, so a resize repaints without
  // re-rendering the hex view. The effect above watches the same two inputs, but
  // it is asking a different question — whether the *block budget* moved, which
  // is quantized and answers "no" for almost every event either observer sees.
  // Resizing the backing store cannot re-trigger the observer: the
  // element's layout size is fixed by CSS (`w-full` plus an inline height), so
  // the width/height *attributes* have no effect on it — which is the same
  // property that made the HiDPI sizing safe to do without a renderer.
  useEffect(() => {
    const canvas = canvasRef.current;
    if (!showEntropy || !canvas || entropyBlocks.length === 0) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    // An arrow rather than a `function`: TypeScript keeps the null narrowing of
    // `canvas` and `ctx` above through a closure created here, but not through a
    // hoisted declaration, which it has to assume could run first.
    const draw = () => {
      // Both are re-read on every draw. That is the whole fix: the ratio is a
      // live value, and caching it in the effect's closure is what made the
      // strip stale.
      const w = canvas.clientWidth;
      const geom = entropyStripGeometry(
        w,
        ENTROPY_STRIP_HEIGHT_PX,
        entropyBlocks.length,
        window.devicePixelRatio,
      );
      // CSS lays the canvas out, so width/height here size only the backing
      // store: one texel per *device* pixel rather than per CSS pixel, which is
      // what stops the strip being upscaled and soft on a HiDPI display. The
      // context is scaled by the same factor, so every coordinate below is
      // still a CSS pixel — the unit the pointer handlers use. `Math.max(2, …)`
      // used to sit on blockWidth, and with more blocks than half the canvas
      // width it walked straight off the right-hand edge: at 4096 blocks on a
      // 1000 px strip every block past the 500th was drawn outside the canvas
      // and simply not shown, while the click and hover handlers mapped x to a
      // block using the unclamped width — so the bar under the cursor was not
      // the bar being reported. Draw and hit test now share one mapping
      // (`entropyStripGeometry` / `entropyBlockAtX`); keep it that way.
      canvas.width = geom.deviceWidth;
      canvas.height = geom.deviceHeight;
      // Assigning width/height resets the context, transform included, so this
      // has to come after and cannot accumulate across redraws.
      ctx.setTransform(geom.scale, 0, 0, geom.scale, 0, 0);
      ctx.clearRect(0, 0, w, ENTROPY_STRIP_HEIGHT_PX);
      for (let i = 0; i < entropyBlocks.length; i++) {
        ctx.fillStyle = entropyColor(entropyBlocks[i]);
        ctx.fillRect(i * geom.blockWidth, 0, Math.ceil(geom.blockWidth), ENTROPY_STRIP_HEIGHT_PX);
      }
    };

    draw();

    // Fires once on observe as well, which is harmless — the draw is idempotent
    // and reads the live size either way.
    const observer = new ResizeObserver(() => draw());
    observer.observe(canvas);

    // A `(resolution: Xdppx)` query names the ratio it was built from, so it can
    // only report leaving it. Re-arm from the new ratio, then redraw. If the
    // ratio moves twice before this runs, the freshly armed query already fails
    // to match and fires again, so the chain is self-correcting.
    let dprQuery: MediaQueryList | null = null;
    const onDprChange = () => {
      armDprQuery();
      draw();
    };
    // Hoisted, because it and `onDprChange` refer to each other. Nothing calls
    // it before the `const` above is initialised.
    function armDprQuery() {
      dprQuery?.removeEventListener("change", onDprChange);
      dprQuery = window.matchMedia(dprMediaQuery(window.devicePixelRatio));
      dprQuery.addEventListener("change", onDprChange);
    }
    armDprQuery();

    return () => {
      observer.disconnect();
      dprQuery?.removeEventListener("change", onDprChange);
    };
  }, [showEntropy, entropyBlocks]);

  const handleGoTo = useCallback(() => {
    if (!pe || !sectionInfo) return;
    const cleaned = goToInput.replace(/^0[xX]/, "");
    const val = parseInt(cleaned, 16);
    if (Number.isNaN(val)) return;
    const addr = val >= baseAddress ? val : baseAddress + val;
    dispatch({ type: "SET_ADDRESS", address: addr });
    setGoToInput("");
  }, [goToInput, pe, sectionInfo, baseAddress, dispatch]);

  const handleAddressClick = useCallback(
    (addr: number) => {
      dispatch({ type: "SET_ADDRESS", address: addr });
    },
    [dispatch],
  );

  const handleEntropyClick = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      if (!canvasRef.current || entropyBlocks.length === 0 || !sectionBytes) return;
      const rect = canvasRef.current.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const blockIdx = entropyBlockAtX(x, rect.width, entropyBlocks.length);
      if (blockIdx >= 0) {
        const offset = blockIdx * entropyBlockSize;
        const rowIdx = Math.floor(offset / BYTES_PER_ROW);
        virtualizer.scrollToIndex(rowIdx, { align: "center" });
        dispatch({ type: "SET_ADDRESS", address: baseAddress + offset });
      }
    },
    [entropyBlocks, entropyBlockSize, sectionBytes, baseAddress, dispatch, virtualizer],
  );

  const handleEntropyMouse = useCallback(
    (e: React.MouseEvent<HTMLCanvasElement>) => {
      if (!canvasRef.current || entropyBlocks.length === 0 || !sectionBytes) {
        setEntropyTooltip(null);
        return;
      }
      const rect = canvasRef.current.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const blockIdx = entropyBlockAtX(x, rect.width, entropyBlocks.length);
      if (blockIdx >= 0) {
        const offset = blockIdx * entropyBlockSize;
        const endOffset = Math.min(offset + entropyBlockSize, sectionBytes.length);
        setEntropyTooltip({
          x: e.clientX - rect.left,
          blockIdx,
          offset,
          endOffset,
          value: entropyBlocks[blockIdx],
        });
      } else {
        setEntropyTooltip(null);
      }
    },
    [entropyBlocks, entropyBlockSize, sectionBytes],
  );

  const handleDownload = useCallback(() => {
    if (!pe || state.hexPatches.size === 0) return;
    const patched = pe.buffer.slice(0);
    const view = new Uint8Array(patched);
    state.hexPatches.forEach((value, offset) => {
      if (offset < view.length) view[offset] = value;
    });
    const blob = new Blob([patched], { type: "application/octet-stream" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = (state.fileName ?? "binary") + ".patched.exe";
    a.click();
    URL.revokeObjectURL(url);
  }, [pe, state.hexPatches, state.fileName]);

  const getByteValue = useCallback(
    (localOffset: number): number => {
      if (!sectionInfo || !sectionBytes) return 0;
      const fileOffset = sectionInfo.pointerToRawData + localOffset;
      if (state.hexPatches.has(fileOffset)) return state.hexPatches.get(fileOffset)!;
      return sectionBytes[localOffset];
    },
    [sectionInfo, sectionBytes, state.hexPatches],
  );

  const isPatched = useCallback(
    (localOffset: number): boolean => {
      if (!sectionInfo) return false;
      return state.hexPatches.has(sectionInfo.pointerToRawData + localOffset);
    },
    [sectionInfo, state.hexPatches],
  );

  const getOriginalByte = useCallback(
    (localOffset: number): number => {
      if (!sectionBytes) return 0;
      return sectionBytes[localOffset];
    },
    [sectionBytes],
  );

  // Dismiss hex context menu on click outside or Escape
  useDismissOnOutsideClick({
    active: hexCtxMenu !== null,
    ref: hexCtxMenuRef,
    onDismiss: () => setHexCtxMenu(null),
    event: "click",
    target: "window",
    dismissOnEscape: true,
    dismissIfRefMissing: true,
  });

  const handleHexContextMenu = useCallback(
    (e: React.MouseEvent) => {
      if (!selectionRange || !sectionBytes) return;
      e.preventDefault();
      setHexCtxMenu({ x: e.clientX, y: e.clientY });
    },
    [selectionRange, sectionBytes],
  );

  const copyAsCArray = useCallback(() => {
    if (!selectionRange || !sectionBytes) return;
    const bytes: string[] = [];
    for (let i = selectionRange.start; i <= selectionRange.end; i++) {
      bytes.push(`0x${getByteValue(i).toString(16).toUpperCase().padStart(2, "0")}`);
    }
    void copyText(`unsigned char data[] = { ${bytes.join(", ")} };`);
    setHexCtxMenu(null);
  }, [selectionRange, sectionBytes, getByteValue]);

  const copyAsHexString = useCallback(() => {
    if (!selectionRange || !sectionBytes) return;
    const parts: string[] = [];
    for (let i = selectionRange.start; i <= selectionRange.end; i++) {
      parts.push(getByteValue(i).toString(16).toLowerCase().padStart(2, "0"));
    }
    void copyText(parts.join(" "));
    setHexCtxMenu(null);
  }, [selectionRange, sectionBytes, getByteValue]);

  const copySelectionAddress = useCallback(() => {
    if (!selectionRange) return;
    const addr = baseAddress + selectionRange.start;
    void copyText(`0x${addr.toString(16).toUpperCase()}`);
    setHexCtxMenu(null);
  }, [selectionRange, baseAddress]);

  // Keyboard: Ctrl/Cmd+C to copy selection, Esc to clear
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === "Escape" && selectionRange) {
        setSelectedOffset(null);
        setSelectionEnd(null);
        return;
      }
      if ((e.ctrlKey || e.metaKey) && e.key === "c" && selectionRange && sectionBytes) {
        e.preventDefault();
        const parts: string[] = [];
        for (let i = selectionRange.start; i <= selectionRange.end; i++) {
          parts.push(getByteValue(i).toString(16).toUpperCase().padStart(2, "0"));
        }
        void copyText(parts.join(" "));
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, [selectionRange, sectionBytes, getByteValue]);

  // Build sorted patches list for diff table
  const patchesList = useMemo(() => {
    if (!sectionInfo || !sectionBytes || !pe) return [];
    const list: {
      fileOffset: number;
      localOffset: number;
      original: number;
      patched: number;
      address: number;
      sectionName: string;
    }[] = [];
    state.hexPatches.forEach((patched, fileOffset) => {
      const localOffset = fileOffset - sectionInfo.pointerToRawData;
      if (localOffset >= 0 && localOffset < sectionBytes.length) {
        list.push({
          fileOffset,
          localOffset,
          original: sectionBytes[localOffset],
          patched,
          address: baseAddress + localOffset,
          sectionName: sectionInfo.name,
        });
      }
    });
    list.sort((a, b) => a.fileOffset - b.fileOffset);
    return list;
  }, [state.hexPatches, sectionInfo, sectionBytes, baseAddress, pe]);

  // Data xref lookup for current section
  const rowXrefs = useMemo(() => {
    if (!state.dataXrefs || !sectionInfo || !pe) return null;
    const sectionVA = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;
    const sectionEnd = sectionVA + sectionInfo.virtualSize;
    // Collect xrefs that fall in this section, keyed by row index
    const map = new Map<number, { addr: number; count: number }[]>();
    for (const [addr, refs] of state.dataXrefs) {
      if (addr >= sectionVA && addr < sectionEnd) {
        const localOffset = addr - sectionVA;
        const rowIdx = Math.floor(localOffset / BYTES_PER_ROW);
        let arr = map.get(rowIdx);
        if (!arr) {
          arr = [];
          map.set(rowIdx, arr);
        }
        arr.push({ addr, count: refs.length });
      }
    }
    return map;
  }, [state.dataXrefs, sectionInfo, pe]);

  // Dismiss xref popup
  useDismissOnOutsideClick({
    active: xrefPopup !== null,
    ref: xrefPopupRef,
    onDismiss: () => setXrefPopup(null),
    event: "click",
    target: "window",
    dismissOnEscape: true,
    dismissIfRefMissing: true,
  });

  const addrWidth = pe?.is64 ? 16 : 8;
  /**
   * What the byte search actually covers. `sectionBytes` is ONE section, so
   * every sentence the search prints names it; see {@link matchSummary}.
   */
  const searchScope = sectionInfo?.name ?? "this section";
  /**
   * Whether what is in the box is a byte pattern at all. Kept apart from
   * {@link searchSettled}: gibberish is not a pending scan, and reporting one
   * would put a "Searching…" that never ends beside a `zz`.
   */
  const searchParses = parseBytePattern(byteSearch) !== null;

  if (!pe || !sectionBytes) {
    return <div className="p-4 text-gray-400 text-sm">No section data to display.</div>;
  }

  return (
    <div className="flex flex-col h-full" style={{ fontSize: "var(--mono-font-size)" }}>
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-4 py-2 border-b border-theme toolbar-bg flex-wrap">
        <span className="text-gray-400">Section:</span>
        <select
          value={sectionInfo?.name ?? ""}
          onChange={(e) => {
            const sec = pe.sections.find((s) => s.name === e.target.value);
            if (sec) {
              dispatch({
                type: "SET_ADDRESS",
                address: pe.optionalHeader.imageBase + sec.virtualAddress,
              });
            }
          }}
          className="px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200"
        >
          {pe.sections.map((sec, i) => (
            <option key={i} value={sec.name}>
              {sec.name} (0x{sec.sizeOfRawData.toString(16)})
            </option>
          ))}
        </select>

        <div className="w-px h-4 bg-gray-700 mx-1" />

        <input
          type="text"
          value={goToInput}
          onChange={(e) => setGoToInput(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") handleGoTo();
            if (e.key === "Escape") (e.target as HTMLElement).blur();
          }}
          placeholder="Offset or VA (hex)"
          className="w-32 px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />

        <div className="w-px h-4 bg-gray-700 mx-1" />

        <input
          type="text"
          value={byteSearch}
          onChange={(e) => setByteSearch(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              // Enter APPLIES a pending query, or steps if the result on screen
              // already answers the box. Stepping on an unsettled box would move
              // to a match of the PREVIOUS pattern, so the two cases are told
              // apart by exactly that test rather than by a timer.
              clearTimeout(searchDebounceRef.current);
              if (searchSettled && matchOffsets.length > 0) stepMatch(e.shiftKey ? -1 : 1);
              else setActiveSearch(byteSearch);
            }
            if (e.key === "Escape") (e.target as HTMLElement).blur();
          }}
          placeholder="Byte search (e.g. 4D 5A ?? 00)..."
          title={`Byte search in ${searchScope} — hex bytes, ?? wildcard; Enter for the next match`}
          aria-label={`Byte search in ${searchScope}`}
          className="w-44 px-2 py-1 bg-gray-800 border border-gray-600 rounded text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        {/*
          Exactly one of these four states is on screen at a time, and the
          pending one exists so that "No matches" — a positive claim about the
          section — cannot stand over a query nothing has scanned yet. See
          `ByteSearchResult`.
        */}
        {byteSearch && searchParses && !searchSettled && (
          <span className="text-gray-500 text-[10px]">Searching…</span>
        )}
        {byteSearch && searchSettled && matchOffsets.length > 0 && (
          <>
            <span className="text-gray-500 text-[10px]">
              {matchSummary(matchOffsets.length, searchResult.truncated, searchScope)}
            </span>
            <button
              type="button"
              onClick={() => stepMatch(-1)}
              aria-label="Previous match"
              title="Previous match (Shift+Enter)"
              className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              ◀
            </button>
            <button
              type="button"
              onClick={() => stepMatch(1)}
              aria-label="Next match"
              title="Next match (Enter)"
              className="px-1.5 py-0.5 rounded text-[10px] bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              ▶
            </button>
            {/*
              The position appears only once a step has happened. Before that
              there is no position: printing "1/40" over a view that has not
              moved would be a claim about where the grid is. The `+` is
              `matchSummary`'s, for the same reason — the denominator is a floor
              rather than a total once the scan stopped at the cap.
            */}
            {matchIdx >= 0 && (
              <span className="text-blue-400 text-[10px]">
                {matchIdx + 1}/{matchOffsets.length}
                {searchResult.truncated ? "+" : ""}
              </span>
            )}
          </>
        )}
        {byteSearch && searchSettled && searchParses && matchOffsets.length === 0 && (
          <span className="text-red-400 text-[10px]">No matches in {searchScope}</span>
        )}

        {selectionCount > 1 && (
          <>
            <div className="w-px h-4 bg-gray-700 mx-1" />
            <span className="text-blue-400 text-[10px]">{selectionCount} bytes selected</span>
          </>
        )}

        <div className="w-px h-4 bg-gray-700 mx-1" />

        <button
          type="button"
          onClick={() => setShowEntropy((v) => !v)}
          className={`px-2 py-1 rounded text-[10px] ${showEntropy ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
        >
          Entropy
        </button>

        <button
          type="button"
          onClick={() => {
            dispatch({ type: "SET_ADDRESS", address: state.currentAddress });
            dispatch({ type: "SET_TAB", tab: "disassembly" });
          }}
          className="px-2 py-1 rounded text-[10px] bg-gray-700 text-gray-300 hover:bg-gray-600"
          title="Show current address in disassembly view"
        >
          Disasm
        </button>

        {state.hexPatches.size > 0 && (
          <>
            <div className="w-px h-4 bg-gray-700 mx-1" />
            <span className="text-orange-400 text-[10px]">Patches: {state.hexPatches.size}</span>
            <button
              type="button"
              onClick={() => setShowDiff((v) => !v)}
              className={`px-2 py-1 rounded text-[10px] ${showDiff ? "bg-blue-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
            >
              Diff
            </button>
            <button
              type="button"
              onClick={() => dispatch({ type: "CLEAR_PATCHES" })}
              className="px-2 py-1 rounded text-[10px] bg-gray-700 text-gray-300 hover:bg-gray-600"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={handleDownload}
              className="px-2 py-1 rounded text-[10px] bg-green-700 text-white hover:bg-green-600"
            >
              Download
            </button>
          </>
        )}
      </div>

      {/* Entropy bar.
          One container, mounted for as long as the strip is toggled on, because
          it is also what `ResizeObserver` measures — and the block count is
          derived from that width before there is anything to draw. */}
      {showEntropy && (
        <div
          ref={stripRef}
          className="relative px-4 py-0.5 bg-gray-900/50 border-b border-gray-800"
        >
          {(entropyStrip.loading || entropyStrip.error) && (
            <div className="text-[10px]">
              {entropyStrip.error ? (
                <span className="text-yellow-400">Entropy unavailable: {entropyStrip.error}</span>
              ) : (
                <span className="text-gray-400">Computing entropy…</span>
              )}
            </div>
          )}
          {entropyBlocks.length > 0 && (
            <>
              {/*
                The height comes from the constant the draw sizes the backing
                store with: a literal here would let the two drift, and the bars
                would be stretched or squashed rather than merely blurry.
              */}
              <canvas
                ref={canvasRef}
                className="w-full cursor-pointer"
                style={{ height: `${ENTROPY_STRIP_HEIGHT_PX}px` }}
                onClick={handleEntropyClick}
                onMouseMove={handleEntropyMouse}
                onMouseLeave={() => setEntropyTooltip(null)}
              />
              {entropyTooltip && (
                <div
                  className="absolute z-30 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-[10px] text-gray-300 pointer-events-none"
                  style={{ left: Math.min(entropyTooltip.x, 300), top: 18 }}
                >
                  Block {entropyTooltip.blockIdx} | 0x{entropyTooltip.offset.toString(16)}-0x
                  {entropyTooltip.endOffset.toString(16)} | Entropy:{" "}
                  {entropyTooltip.value.toFixed(2)}
                </div>
              )}
            </>
          )}
        </div>
      )}

      {/* Patches diff table */}
      {showDiff && patchesList.length > 0 && (
        <div className="px-4 py-2 bg-gray-900/80 border-b border-gray-700 max-h-32 overflow-auto">
          <div className="text-gray-400 text-[10px] font-semibold mb-1">
            Patches ({patchesList.length})
          </div>
          <table className="w-full text-[10px] font-mono">
            <thead>
              <tr className="text-gray-500">
                <th className="text-left pr-3">File Offset</th>
                <th className="text-left pr-3">Original</th>
                <th className="text-left pr-3">Patched</th>
                <th className="text-left">Section+Offset</th>
              </tr>
            </thead>
            <tbody>
              {patchesList.map((p) => (
                <tr
                  key={p.fileOffset}
                  className="hover:bg-gray-800 cursor-pointer"
                  onClick={() => {
                    dispatch({ type: "SET_ADDRESS", address: p.address });
                  }}
                >
                  <td className="pr-3 text-blue-400">
                    0x{p.fileOffset.toString(16).toUpperCase()}
                  </td>
                  <td className="pr-3 text-gray-400 line-through">
                    0x{p.original.toString(16).toUpperCase().padStart(2, "0")}
                  </td>
                  <td className="pr-3 text-red-400 font-bold">
                    0x{p.patched.toString(16).toUpperCase().padStart(2, "0")}
                  </td>
                  <td className="text-gray-500">
                    {p.sectionName}+0x{p.localOffset.toString(16).toUpperCase()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Header */}
      <div className="flex px-4 py-1 border-b border-gray-800 text-gray-500 bg-gray-900/50">
        <span style={{ width: `${addrWidth + 2}ch` }}>Offset</span>
        <span className="flex-1 ml-2">
          {Array.from({ length: BYTES_PER_ROW }, (_, i) =>
            i.toString(16).toUpperCase().padStart(2, "0"),
          ).join(" ")}
        </span>
        <span className="ml-4" style={{ width: `${BYTES_PER_ROW}ch` }}>
          ASCII
        </span>
      </div>

      {/* Hex rows */}
      {/* biome-ignore lint/a11y/noStaticElementInteractions: onContextMenu is a
          right-click affordance on a scroll region, not a control. Making this a
          button is invalid (it contains the byte-cell buttons) and there is no
          keyboard gesture to attach — the browser's own context-menu key already
          fires this event on whatever is focused inside. */}
      <div
        ref={parentRef}
        className="flex-1 overflow-auto relative"
        onContextMenu={handleHexContextMenu}
      >
        <div
          style={{
            height: `${virtualizer.getTotalSize()}px`,
            width: "100%",
            position: "relative",
          }}
        >
          {virtualizer.getVirtualItems().map((vItem) => {
            const offset = vItem.index * BYTES_PER_ROW;
            const addr = baseAddress + offset;
            const isCurrentRow = vItem.index === currentRowIdx;
            const rowLen = Math.min(BYTES_PER_ROW, sectionBytes.length - offset);

            const hexParts: string[] = [];
            const asciiParts: string[] = [];
            const highlightByte: boolean[] = [];
            const patchedByte: boolean[] = [];

            for (let i = 0; i < BYTES_PER_ROW; i++) {
              if (i < rowLen) {
                const b = getByteValue(offset + i);
                hexParts.push(b.toString(16).padStart(2, "0"));
                asciiParts.push(b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : ".");
                highlightByte.push(byteMatches.has(offset + i));
                patchedByte.push(isPatched(offset + i));
              } else {
                hexParts.push("  ");
                asciiParts.push(" ");
                highlightByte.push(false);
                patchedByte.push(false);
              }
            }

            return (
              <div
                key={vItem.index}
                className={`flex px-4 disasm-row ${isCurrentRow ? "bg-blue-900/30" : ""}`}
                style={{
                  position: "absolute",
                  top: 0,
                  left: 0,
                  width: "100%",
                  height: "20px",
                  lineHeight: "20px",
                  transform: `translateY(${vItem.start}px)`,
                }}
              >
                <button
                  type="button"
                  tabIndex={-1}
                  className="disasm-address text-left cursor-pointer hover:text-blue-400"
                  style={{ width: `${addrWidth + 2}ch` }}
                  onClick={() => handleAddressClick(addr)}
                >
                  {addr.toString(16).toUpperCase().padStart(addrWidth, "0")}
                </button>
                <span className="hex-byte ml-2 flex-1">
                  {hexParts.map((h, i) => {
                    const byteOffset = offset + i;
                    const fileOffset = sectionInfo ? sectionInfo.pointerToRawData + byteOffset : -1;
                    const isSelected = isInSelection(byteOffset);
                    const isHighlighted = highlightByte[i];
                    const isPatch = patchedByte[i];
                    const isEditing = editingByte === fileOffset;

                    if (isEditing) {
                      return (
                        <span key={i}>
                          {i > 0 ? " " : ""}
                          <input
                            ref={focusOnMount}
                            className="w-5 bg-gray-700 border border-blue-500 rounded-sm text-center text-red-400 font-bold outline-none text-xs"
                            value={editValue}
                            maxLength={2}
                            onChange={(e) =>
                              setEditValue(e.target.value.replace(/[^0-9a-fA-F]/g, "").slice(0, 2))
                            }
                            onKeyDown={(e) => {
                              if (e.key === "Enter") {
                                const val = parseInt(editValue, 16);
                                if (!Number.isNaN(val) && val >= 0 && val <= 255) {
                                  dispatch({ type: "PATCH_BYTE", offset: fileOffset, value: val });
                                }
                                setEditingByte(null);
                                setEditValue("");
                              }
                              if (e.key === "Escape") {
                                setEditingByte(null);
                                setEditValue("");
                              }
                              e.stopPropagation();
                            }}
                            onBlur={() => {
                              setEditingByte(null);
                              setEditValue("");
                            }}
                          />
                        </span>
                      );
                    }

                    let cls = isPatch ? "text-red-400 font-bold" : "";
                    if (isSelected) cls = "ring-1 ring-blue-500 rounded-sm bg-blue-900/40";
                    else if (isHighlighted) cls = "bg-yellow-600/50 text-yellow-200";
                    else if (isPatch) cls = "text-red-400 font-bold";

                    const origByte = getOriginalByte(offset + i);
                    const origHex = origByte.toString(16).padStart(2, "0");
                    const showOrig = showDiff && isPatch;
                    const tooltipText = showOrig
                      ? `Original: 0x${origHex.toUpperCase()} → Patched: 0x${h.toUpperCase()}`
                      : undefined;

                    return (
                      <span key={i} title={tooltipText}>
                        {i > 0 ? " " : ""}
                        {showOrig && (
                          <span className="text-gray-600 text-[8px] line-through">{origHex}</span>
                        )}
                        {/* tabIndex={-1}: a hex page renders hundreds of byte
                            cells; each one as a tab stop would be unusable. */}
                        <button
                          type="button"
                          tabIndex={-1}
                          className={`inline cursor-pointer ${cls}`}
                          onClick={(e) => {
                            if (i >= rowLen) return;
                            if (e.shiftKey && selectedOffset !== null) {
                              setSelectionEnd(byteOffset);
                            } else {
                              setSelectedOffset(byteOffset);
                              setSelectionEnd(null);
                            }
                          }}
                          onDoubleClick={() => {
                            if (i < rowLen && sectionInfo) {
                              const fo = sectionInfo.pointerToRawData + byteOffset;
                              setEditingByte(fo);
                              setEditValue(h);
                            }
                          }}
                        >
                          {h}
                        </button>
                      </span>
                    );
                  })}
                </span>
                <span className="hex-ascii ml-4" style={{ width: `${BYTES_PER_ROW}ch` }}>
                  {asciiParts.map((c, i) => {
                    const byteOffset = offset + i;
                    const isSelected = isInSelection(byteOffset);
                    const isHighlighted = highlightByte[i];
                    const isPatch = patchedByte[i];
                    let cls = "";
                    if (isSelected) cls = "ring-1 ring-blue-500 rounded-sm bg-blue-900/40";
                    else if (isHighlighted) cls = "bg-yellow-600/50 text-yellow-200";
                    else if (isPatch) cls = "text-red-400 font-bold";
                    const origChar =
                      showDiff && isPatch
                        ? (() => {
                            const ob = getOriginalByte(offset + i);
                            return ob >= 0x20 && ob <= 0x7e ? String.fromCharCode(ob) : ".";
                          })()
                        : null;
                    return (
                      <span key={i} className={cls}>
                        {origChar && (
                          <span className="text-gray-600 text-[8px] line-through">{origChar}</span>
                        )}
                        {c}
                      </span>
                    );
                  })}
                </span>
                {/* Data xref badges */}
                {rowXrefs?.get(vItem.index)?.map((xref) => (
                  <button
                    type="button"
                    key={xref.addr}
                    className="ml-1 px-1 py-0 rounded bg-purple-900/50 text-purple-300 text-[9px] cursor-pointer hover:bg-purple-800/60 shrink-0"
                    title={`${xref.count} xref(s) to 0x${xref.addr.toString(16).toUpperCase()}`}
                    onClick={(e) => {
                      e.stopPropagation();
                      const refs = state.dataXrefs?.get(xref.addr) ?? [];
                      setXrefPopup({ addr: xref.addr, refs, x: e.clientX, y: e.clientY });
                    }}
                  >
                    x{xref.count}
                  </button>
                ))}
              </div>
            );
          })}
        </div>
      </div>

      {/* Hex context menu */}
      {hexCtxMenu && selectionRange && (
        <div
          ref={hexCtxMenuRef}
          className="fixed z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs min-w-[180px]"
          style={{ left: hexCtxMenu.x, top: hexCtxMenu.y }}
        >
          <button
            type="button"
            onClick={copyAsCArray}
            className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
          >
            Copy as C byte array
          </button>
          <button
            type="button"
            onClick={copyAsHexString}
            className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
          >
            Copy as hex string
          </button>
          <button
            type="button"
            onClick={copySelectionAddress}
            className="w-full text-left px-3 py-1.5 hover:bg-gray-700 text-gray-200"
          >
            Copy address
          </button>
        </div>
      )}

      {/* Data xref popup */}
      {xrefPopup && (
        <div
          ref={xrefPopupRef}
          className="fixed z-50 bg-gray-800 border border-gray-600 rounded shadow-lg py-1 text-xs min-w-[200px] max-h-48 overflow-auto"
          style={{ left: xrefPopup.x, top: xrefPopup.y }}
        >
          <div className="px-3 py-1 text-gray-400 border-b border-gray-700 font-semibold">
            Xrefs to 0x{xrefPopup.addr.toString(16).toUpperCase()} ({xrefPopup.refs.length})
          </div>
          {xrefPopup.refs.map((ref, i) => (
            <button
              type="button"
              key={i}
              className="w-full text-left px-3 py-1 hover:bg-gray-700 text-blue-400 font-mono"
              onClick={() => {
                dispatch({ type: "SET_ADDRESS", address: ref });
                dispatch({ type: "SET_TAB", tab: "disassembly" });
                setXrefPopup(null);
              }}
            >
              0x{ref.toString(16).toUpperCase()}
            </button>
          ))}
        </div>
      )}

      {/* Data Inspector */}
      {selectedOffset !== null && selectionEnd === null && sectionBytes && (
        <DataInspector offset={selectedOffset} bytes={sectionBytes} baseAddress={baseAddress} />
      )}
    </div>
  );
}
