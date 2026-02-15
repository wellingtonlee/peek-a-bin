import { useMemo } from "react";
import type { Instruction, DisasmFunction, Xref, StackFrame } from "../disasm/types";
import type { FunctionSignature } from "../disasm/signatures";
import { getDisplayName } from "../hooks/usePEFile";

interface InstructionDetailProps {
  insn: Instruction;
  typedXrefMap: Map<number, Xref[]>;
  funcMap: Map<number, DisasmFunction>;
  iatMap: Map<number, { lib: string; func: string }>;
  renames: Record<number, string>;
  sortedFuncs: DisasmFunction[];
  onNavigate: (addr: number) => void;
  onClose: () => void;
  stackFrame?: StackFrame | null;
  signature?: FunctionSignature | null;
}

// Simple heuristic for byte encoding breakdown
interface ByteSegment {
  bytes: string;
  label: string;
  cls: string;
}

function breakdownEncoding(insn: Instruction): ByteSegment[] {
  const bytes = Array.from(insn.bytes);
  if (bytes.length === 0) return [];

  const segments: ByteSegment[] = [];
  let idx = 0;

  // Check for legacy prefixes (66, 67, F0, F2, F3, 2E, 3E, 26, 36, 64, 65)
  const prefixes = new Set([0x66, 0x67, 0xF0, 0xF2, 0xF3, 0x2E, 0x3E, 0x26, 0x36, 0x64, 0x65]);
  while (idx < bytes.length && prefixes.has(bytes[idx])) {
    segments.push({
      bytes: bytes[idx].toString(16).padStart(2, "0"),
      label: "prefix",
      cls: "text-gray-400",
    });
    idx++;
  }

  // REX prefix (0x40-0x4F) for 64-bit
  if (idx < bytes.length && bytes[idx] >= 0x40 && bytes[idx] <= 0x4F) {
    segments.push({
      bytes: bytes[idx].toString(16).padStart(2, "0"),
      label: "REX",
      cls: "text-gray-400",
    });
    idx++;
  }

  // VEX prefix (C4/C5)
  if (idx < bytes.length && (bytes[idx] === 0xC4 || bytes[idx] === 0xC5)) {
    const vexLen = bytes[idx] === 0xC4 ? 3 : 2;
    const vexBytes = bytes.slice(idx, idx + vexLen);
    segments.push({
      bytes: vexBytes.map(b => b.toString(16).padStart(2, "0")).join(" "),
      label: "VEX",
      cls: "text-gray-400",
    });
    idx += vexLen;
  }

  // Opcode: 0F escape = 2-byte, 0F 38/3A = 3-byte, else 1-byte
  let opcodeLen = 1;
  if (idx < bytes.length && bytes[idx] === 0x0F) {
    opcodeLen = 2;
    if (idx + 1 < bytes.length && (bytes[idx + 1] === 0x38 || bytes[idx + 1] === 0x3A)) {
      opcodeLen = 3;
    }
  }
  if (idx + opcodeLen <= bytes.length) {
    segments.push({
      bytes: bytes.slice(idx, idx + opcodeLen).map(b => b.toString(16).padStart(2, "0")).join(" "),
      label: "opcode",
      cls: "text-white font-semibold",
    });
    idx += opcodeLen;
  }

  // ModR/M byte (if present)
  if (idx < bytes.length && bytes.length > idx + 0) {
    const hasModRM = insn.opStr.length > 0 && bytes.length > idx;
    if (hasModRM) {
      segments.push({
        bytes: bytes[idx].toString(16).padStart(2, "0"),
        label: "modrm",
        cls: "text-cyan-400",
      });
      idx++;
    }
  }

  // Remaining bytes: displacement + immediate
  if (idx < bytes.length) {
    const remaining = bytes.slice(idx);
    const mn = insn.mnemonic;
    const hasImm = mn === "mov" || mn === "add" || mn === "sub" || mn === "cmp" ||
                   mn === "and" || mn === "or" || mn === "xor" || mn === "test" ||
                   mn === "push" || mn.startsWith("j") || mn === "call";

    if (remaining.length > 4 && hasImm) {
      const dispBytes = remaining.slice(0, remaining.length - 4);
      const immBytes = remaining.slice(remaining.length - 4);
      if (dispBytes.length > 0) {
        segments.push({
          bytes: dispBytes.map(b => b.toString(16).padStart(2, "0")).join(" "),
          label: "disp",
          cls: "text-yellow-300",
        });
      }
      segments.push({
        bytes: immBytes.map(b => b.toString(16).padStart(2, "0")).join(" "),
        label: "imm",
        cls: "text-green-400",
      });
    } else if (remaining.length > 0) {
      const label = hasImm ? "imm" : "disp";
      segments.push({
        bytes: remaining.map(b => b.toString(16).padStart(2, "0")).join(" "),
        label,
        cls: hasImm ? "text-green-400" : "text-yellow-300",
      });
    }
  }

  return segments;
}

const TYPE_COLORS: Record<string, string> = {
  call: "text-green-400",
  jmp: "text-red-400",
  branch: "text-orange-400",
  data: "text-purple-400",
};

const TYPE_LABELS: Record<string, string> = {
  call: "C",
  jmp: "J",
  branch: "B",
  data: "D",
};

function parseStackOffset(opStr: string): number | null {
  // Match [rbp - 0xN] or [rsp + 0xN] or [rbp - N]
  const m = opStr.match(/\[(?:rbp|ebp)\s*-\s*0x([0-9a-fA-F]+)\]/i) ||
            opStr.match(/\[(?:rsp|esp)\s*\+\s*0x([0-9a-fA-F]+)\]/i);
  if (m) return parseInt(m[1], 16);
  return null;
}

export function InstructionDetail({
  insn,
  typedXrefMap,
  funcMap,
  iatMap,
  renames,
  sortedFuncs,
  onNavigate,
  onClose,
  stackFrame,
  signature,
}: InstructionDetailProps) {
  const encoding = useMemo(() => breakdownEncoding(insn), [insn]);

  // Find containing function
  const containingFunc = useMemo(() => {
    let lo = 0;
    let hi = sortedFuncs.length - 1;
    let best: DisasmFunction | null = null;
    while (lo <= hi) {
      const mid = (lo + hi) >>> 1;
      const fn = sortedFuncs[mid];
      if (fn.address <= insn.address) {
        if (insn.address < fn.address + fn.size) best = fn;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return best;
  }, [insn.address, sortedFuncs]);

  // Typed xrefs TO this instruction
  const xrefsTo = typedXrefMap.get(insn.address) ?? [];

  // Xrefs FROM: parse branch/call target
  const xrefFrom = useMemo(() => {
    const mn = insn.mnemonic;
    let type: Xref['type'] | null = null;
    if (mn === "call") type = "call";
    else if (mn === "jmp") type = "jmp";
    else if (mn.startsWith("j")) type = "branch";

    if (type) {
      const m = insn.opStr.match(/^0x([0-9a-fA-F]+)$/);
      if (m) {
        const target = parseInt(m[1], 16);
        const fn = funcMap.get(target);
        const iat = iatMap.get(target);
        return {
          address: target,
          name: iat ? `${iat.lib}!${iat.func}` : fn ? getDisplayName(fn, renames) : null,
          type,
        };
      }
    }
    // RIP-relative for call/jmp
    if (mn === "call" || mn === "jmp") {
      const ripMatch = insn.opStr.match(/\[rip\s*([+-])\s*0x([0-9a-fA-F]+)\]/);
      if (ripMatch) {
        const sign = ripMatch[1] === "+" ? 1 : -1;
        const disp = parseInt(ripMatch[2], 16);
        const target = insn.address + insn.size + sign * disp;
        const iat = iatMap.get(target);
        return {
          address: target,
          name: iat ? `${iat.lib}!${iat.func}` : null,
          type: type ?? "data" as Xref['type'],
        };
      }
    }
    return null;
  }, [insn, funcMap, iatMap, renames]);

  const currentStackOffset = useMemo(() => parseStackOffset(insn.opStr), [insn.opStr]);

  return (
    <div className="h-40 shrink-0 border-t border-gray-700 bg-gray-900 flex flex-col text-xs">
      <div className="flex items-center px-3 py-1 border-b border-gray-700 text-gray-400">
        <span className="font-semibold text-gray-300">
          Instruction Detail
        </span>
        {containingFunc && (
          <span className="ml-2 text-gray-500">
            in {getDisplayName(containingFunc, renames)}
            {signature ? ` | ${signature.convention}, ${signature.paramCount} param${signature.paramCount !== 1 ? "s" : ""}` : ""}
          </span>
        )}
        <span className="ml-2 text-gray-600 font-mono">
          0x{insn.address.toString(16).toUpperCase()}
        </span>
        <div className="flex-1" />
        <button
          onClick={onClose}
          className="text-gray-500 hover:text-white px-1"
        >
          ✕
        </button>
      </div>
      <div className="flex flex-1 overflow-hidden">
        {/* Encoding */}
        <div className="flex-1 border-r border-gray-700 overflow-auto p-2">
          <div className="text-gray-500 mb-1 font-semibold">Encoding ({insn.bytes.length} bytes)</div>
          <div className="font-mono flex flex-wrap gap-x-2 gap-y-1">
            {encoding.map((seg, i) => (
              <span key={i} title={seg.label}>
                <span className={seg.cls}>{seg.bytes}</span>
                <span className="text-gray-600 text-[9px] ml-0.5">{seg.label}</span>
              </span>
            ))}
          </div>
          <div className="mt-2 text-gray-500 font-mono">
            {insn.mnemonic} {insn.opStr}
          </div>
        </div>

        {/* Xrefs To */}
        <div className="flex-1 border-r border-gray-700 overflow-auto p-2">
          <div className="text-gray-500 mb-1 font-semibold">
            Xrefs To ({xrefsTo.length})
          </div>
          {xrefsTo.length === 0 ? (
            <div className="text-gray-600 italic">None</div>
          ) : (
            xrefsTo.slice(0, 50).map((xref, i) => (
              <button
                key={`${xref.from}-${i}`}
                onClick={() => onNavigate(xref.from)}
                className="block w-full text-left px-1 py-0.5 rounded hover:bg-gray-800 truncate font-mono flex items-center gap-1"
              >
                <span className={`${TYPE_COLORS[xref.type] ?? "text-gray-400"} text-[10px] font-semibold w-3`}>
                  {TYPE_LABELS[xref.type] ?? "?"}
                </span>
                <span className="text-blue-400">
                  0x{xref.from.toString(16).toUpperCase()}
                </span>
              </button>
            ))
          )}
        </div>

        {/* Xrefs From */}
        <div className={`flex-1 overflow-auto p-2 ${stackFrame ? "border-r border-gray-700" : ""}`}>
          <div className="text-gray-500 mb-1 font-semibold">Xrefs From</div>
          {xrefFrom ? (
            <button
              onClick={() => onNavigate(xrefFrom.address)}
              className="block w-full text-left px-1 py-0.5 rounded hover:bg-gray-800 truncate"
            >
              <span className={`${TYPE_COLORS[xrefFrom.type] ?? "text-gray-400"} text-[10px] font-semibold mr-1`}>
                {TYPE_LABELS[xrefFrom.type] ?? "?"}
              </span>
              <span className="text-blue-400 font-mono">
                0x{xrefFrom.address.toString(16).toUpperCase()}
              </span>
              {xrefFrom.name && (
                <span className="text-gray-400 ml-1">{xrefFrom.name}</span>
              )}
            </button>
          ) : (
            <div className="text-gray-600 italic">None</div>
          )}
        </div>

        {/* Stack Frame (optional) */}
        {stackFrame && (
          <div className="flex-1 overflow-auto p-2">
            <div className="text-gray-500 mb-1 font-semibold">
              Stack Frame ({stackFrame.frameSize > 0 ? `0x${stackFrame.frameSize.toString(16)}` : "?"} bytes)
            </div>
            {stackFrame.vars.length === 0 ? (
              <div className="text-gray-600 italic">No variables detected</div>
            ) : (
              <div className="space-y-0.5">
                {stackFrame.vars.map((v) => (
                  <div
                    key={v.offset}
                    className={`flex items-center gap-2 px-1 py-0.5 rounded font-mono ${
                      currentStackOffset === v.offset ? "bg-blue-900/30 text-blue-300" : "text-gray-400"
                    }`}
                  >
                    <span className="w-12 text-gray-500 text-[10px]">-0x{v.offset.toString(16)}</span>
                    <span className="w-8 text-gray-600 text-[10px]">{v.size}B</span>
                    <span className="text-gray-300">{v.name}</span>
                    <span className="text-gray-600 text-[10px]">({v.accessCount}x)</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
