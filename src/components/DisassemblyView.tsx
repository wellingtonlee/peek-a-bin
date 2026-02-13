import { useEffect, useRef, useMemo, useCallback, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";
import { disasmEngine } from "../disasm/engine";
import { rvaToFileOffset } from "../pe/parser";
import type { Instruction } from "../disasm/types";

export function DisassemblyView() {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const parentRef = useRef<HTMLDivElement>(null);
  const [instructions, setInstructions] = useState<Instruction[]>([]);
  const [disasmError, setDisasmError] = useState<string | null>(null);

  // Find which section contains the current address
  const sectionInfo = useMemo(() => {
    if (!pe) return null;
    const rva = state.currentAddress - pe.optionalHeader.imageBase;
    for (const sec of pe.sections) {
      if (rva >= sec.virtualAddress && rva < sec.virtualAddress + sec.virtualSize) {
        return sec;
      }
    }
    return null;
  }, [pe, state.currentAddress]);

  // Disassemble the current section
  useEffect(() => {
    if (!pe || !sectionInfo || !state.disasmReady) return;

    try {
      const sectionBytes = new Uint8Array(
        pe.buffer,
        sectionInfo.pointerToRawData,
        sectionInfo.sizeOfRawData,
      );
      const baseAddr = pe.optionalHeader.imageBase + sectionInfo.virtualAddress;
      const result = disasmEngine.disassemble(
        sectionBytes,
        baseAddr,
        pe.is64,
        pe.strings,
      );
      setInstructions(result);
      setDisasmError(null);
    } catch (e) {
      setDisasmError(e instanceof Error ? e.message : "Disassembly failed");
      setInstructions([]);
    }
  }, [pe, sectionInfo, state.disasmReady]);

  // Find index of current address in instructions
  const currentIndex = useMemo(() => {
    if (instructions.length === 0) return 0;
    const idx = instructions.findIndex(
      (insn) => insn.address >= state.currentAddress,
    );
    return idx === -1 ? 0 : idx;
  }, [instructions, state.currentAddress]);

  const virtualizer = useVirtualizer({
    count: instructions.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 20,
    overscan: 50,
  });

  // Scroll to current address when it changes
  useEffect(() => {
    if (instructions.length > 0 && currentIndex >= 0) {
      virtualizer.scrollToIndex(currentIndex, { align: "center" });
    }
  }, [currentIndex, instructions.length]);

  const handleAddressClick = useCallback(
    (address: number) => {
      dispatch({ type: "SET_ADDRESS", address });
    },
    [dispatch],
  );

  if (!pe) return null;

  if (disasmError) {
    return (
      <div className="p-4 text-red-400 text-sm">
        Disassembly error: {disasmError}
      </div>
    );
  }

  if (!sectionInfo) {
    return (
      <div className="p-4 text-gray-400 text-sm">
        Address 0x{state.currentAddress.toString(16)} is not within any section.
      </div>
    );
  }

  const addrWidth = pe.is64 ? 16 : 8;

  return (
    <div ref={parentRef} className="h-full overflow-auto text-xs leading-5">
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((vItem) => {
          const insn = instructions[vItem.index];
          if (!insn) return null;

          const bytesHex = Array.from(insn.bytes)
            .map((b) => b.toString(16).padStart(2, "0"))
            .join(" ");

          const isCurrentAddr = insn.address === state.currentAddress;
          // Check if a function starts here
          const fn = state.functions.find((f) => f.address === insn.address);

          return (
            <div
              key={vItem.index}
              ref={virtualizer.measureElement}
              data-index={vItem.index}
              className={`disasm-row flex px-4 ${isCurrentAddr ? "bg-blue-900/30" : ""}`}
              style={{
                position: "absolute",
                top: 0,
                left: 0,
                width: "100%",
                transform: `translateY(${vItem.start}px)`,
              }}
            >
              {fn && (
                <div
                  className="absolute -top-4 left-4 text-yellow-400 text-[10px]"
                  style={{ transform: `translateY(${vItem.start}px)` }}
                >
                  ; ---- {fn.name} ----
                </div>
              )}
              <span
                className="disasm-address w-36 shrink-0 cursor-pointer hover:text-blue-400"
                onClick={() => handleAddressClick(insn.address)}
              >
                {insn.address.toString(16).toUpperCase().padStart(addrWidth, "0")}
              </span>
              <span className="disasm-bytes w-44 shrink-0 truncate">
                {bytesHex}
              </span>
              <span className="disasm-mnemonic w-16 shrink-0 font-semibold">
                {insn.mnemonic}
              </span>
              <span className="disasm-operands flex-1">{insn.opStr}</span>
              {insn.comment && (
                <span className="disasm-comment ml-4 truncate max-w-xs">
                  ; {insn.comment}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
