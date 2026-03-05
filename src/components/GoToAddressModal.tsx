import { useState, useEffect, useRef, useMemo } from "react";
import { useAppState, useAppDispatch } from "../hooks/usePEFile";

type AddrMode = "va" | "rva" | "file";

interface GoToAddressModalProps {
  open: boolean;
  onClose: () => void;
}

export function GoToAddressModal({ open, onClose }: GoToAddressModalProps) {
  const state = useAppState();
  const dispatch = useAppDispatch();
  const pe = state.peFile;
  const inputRef = useRef<HTMLInputElement>(null);
  const [mode, setMode] = useState<AddrMode>("va");
  const [input, setInput] = useState("");

  useEffect(() => {
    if (open) {
      setInput("");
      setTimeout(() => inputRef.current?.focus(), 0);
    }
  }, [open]);

  const parsedValue = useMemo(() => {
    const cleaned = input.trim().replace(/^0[xX]/, "");
    if (!cleaned) return null;
    const val = parseInt(cleaned, 16);
    return isNaN(val) ? null : val;
  }, [input]);

  const resolvedVA = useMemo(() => {
    if (parsedValue === null || !pe) return null;
    const imageBase = pe.optionalHeader.imageBase;

    switch (mode) {
      case "va":
        return parsedValue;
      case "rva":
        return imageBase + parsedValue;
      case "file": {
        // Reverse section mapping: find section containing this file offset
        for (const sec of pe.sections) {
          if (
            parsedValue >= sec.pointerToRawData &&
            parsedValue < sec.pointerToRawData + sec.sizeOfRawData
          ) {
            const offsetInSection = parsedValue - sec.pointerToRawData;
            return imageBase + sec.virtualAddress + offsetInSection;
          }
        }
        return null; // No matching section
      }
    }
  }, [parsedValue, mode, pe]);

  const handleGo = () => {
    if (resolvedVA === null) return;
    dispatch({ type: "SET_ADDRESS", address: resolvedVA });
    dispatch({ type: "SET_TAB", tab: "disassembly" });
    onClose();
  };

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/50"
      onClick={onClose}
    >
      <div
        className="bg-gray-800 border border-gray-600 rounded-lg shadow-xl p-4 w-80"
        onClick={(e) => e.stopPropagation()}
      >
        <h3 className="text-sm font-semibold text-gray-200 mb-3">Go to Address</h3>

        {/* Format toggle */}
        <div className="flex gap-1 mb-3">
          {(["va", "rva", "file"] as AddrMode[]).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className={`px-3 py-1 rounded text-xs font-semibold ${
                mode === m
                  ? "bg-blue-600 text-white"
                  : "bg-gray-700 text-gray-400 hover:bg-gray-600"
              }`}
            >
              {m === "va" ? "VA" : m === "rva" ? "RVA" : "File Offset"}
            </button>
          ))}
        </div>

        {/* Hex input */}
        <div className="flex items-center gap-1 mb-3">
          <span className="text-gray-500 text-sm font-mono">0x</span>
          <input
            ref={inputRef}
            type="text"
            value={input}
            onChange={(e) => setInput(e.target.value.replace(/[^0-9a-fA-F]/g, ""))}
            onKeyDown={(e) => {
              if (e.key === "Enter") handleGo();
              if (e.key === "Escape") onClose();
              e.stopPropagation();
            }}
            placeholder="Enter hex address..."
            className="flex-1 px-2 py-1.5 bg-gray-900 border border-gray-600 rounded text-gray-200 font-mono text-sm placeholder-gray-500 focus:outline-none focus:border-blue-500"
          />
        </div>

        {/* Result preview */}
        <div className="text-xs mb-3 h-5">
          {resolvedVA !== null ? (
            <span className="text-green-400">
              Resolves to VA: 0x{resolvedVA.toString(16).toUpperCase()}
            </span>
          ) : parsedValue !== null ? (
            <span className="text-red-400">
              {mode === "file" ? "No section contains this file offset" : "Invalid address"}
            </span>
          ) : null}
        </div>

        {/* Actions */}
        <div className="flex justify-end gap-2">
          <button
            onClick={onClose}
            className="px-3 py-1.5 rounded text-xs bg-gray-700 text-gray-300 hover:bg-gray-600"
          >
            Cancel
          </button>
          <button
            onClick={handleGo}
            disabled={resolvedVA === null}
            className="px-3 py-1.5 rounded text-xs bg-blue-600 text-white hover:bg-blue-500 disabled:opacity-30 disabled:cursor-default"
          >
            Go
          </button>
        </div>
      </div>
    </div>
  );
}
