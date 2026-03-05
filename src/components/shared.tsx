import { useMemo, useState } from "react";

// --- Register names set ---
export const REG_NAMES = new Set([
  "rax","rbx","rcx","rdx","rsi","rdi","rbp","rsp","r8","r9","r10","r11","r12","r13","r14","r15",
  "eax","ebx","ecx","edx","esi","edi","ebp","esp",
  "ax","bx","cx","dx","si","di","bp","sp",
  "al","bl","cl","dl","ah","bh","ch","dh","sil","dil","bpl","spl",
  "r8d","r9d","r10d","r11d","r12d","r13d","r14d","r15d",
  "r8w","r9w","r10w","r11w","r12w","r13w","r14w","r15w",
  "r8b","r9b","r10b","r11b","r12b","r13b","r14b","r15b",
  "cs","ds","es","fs","gs","ss",
  "rip","eip","ip",
  "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5","xmm6","xmm7",
  "xmm8","xmm9","xmm10","xmm11","xmm12","xmm13","xmm14","xmm15",
  "ymm0","ymm1","ymm2","ymm3","ymm4","ymm5","ymm6","ymm7",
]);

// --- Operand tokenizer ---
export interface OpToken { text: string; cls: string }

export function tokenizeOperand(opStr: string): OpToken[] {
  if (!opStr) return [];
  const tokens: OpToken[] = [];
  const re = /(\[|\])|(\b0x[0-9a-fA-F]+\b)|(\b[a-z][a-z0-9]{1,4}\b)|([^[\]a-z0-9]+|[0-9]+)/gi;
  let m: RegExpExecArray | null;
  let inBracket = false;
  while ((m = re.exec(opStr)) !== null) {
    const full = m[0];
    if (full === "[") {
      inBracket = true;
      tokens.push({ text: "[", cls: "text-purple-400" });
    } else if (full === "]") {
      inBracket = false;
      tokens.push({ text: "]", cls: "text-purple-400" });
    } else if (m[2]) {
      tokens.push({ text: full, cls: inBracket ? "text-purple-400" : "text-yellow-300" });
    } else if (m[3] && REG_NAMES.has(full.toLowerCase())) {
      tokens.push({ text: full, cls: inBracket ? "text-purple-400" : "text-cyan-400" });
    } else {
      tokens.push({ text: full, cls: inBracket ? "text-purple-400" : "" });
    }
  }
  return tokens;
}

// --- Clickable target interface ---
export interface ClickableTarget {
  address: number;
  display?: string;
}

// --- Colored operand component ---
export function ColoredOperand({ opStr, targets, onNavigate, highlightRegs, onRegClick }: {
  opStr: string;
  targets?: ClickableTarget[];
  onNavigate?: (addr: number) => void;
  highlightRegs?: Set<string> | null;
  onRegClick?: (regName: string) => void;
}) {
  const tokens = useMemo(() => tokenizeOperand(opStr), [opStr]);
  const [copiedTarget, setCopiedTarget] = useState<number | null>(null);

  const targetMap = useMemo(() => {
    if (!targets || targets.length === 0) return null;
    const m = new Map<string, ClickableTarget>();
    for (const t of targets) {
      const hexStr = "0x" + t.address.toString(16);
      m.set(hexStr.toLowerCase(), t);
    }
    return m;
  }, [targets]);

  return (
    <>
      {tokens.map((t, i) => {
        if (targetMap && onNavigate && t.text.startsWith("0x")) {
          const target = targetMap.get(t.text.toLowerCase());
          if (target) {
            return (
              <span
                key={i}
                className={`${copiedTarget === target.address ? "text-green-400" : "text-blue-400"} underline cursor-pointer hover:text-blue-300`}
                onClick={(e) => { e.stopPropagation(); onNavigate(target.address); }}
                onDoubleClick={(e) => {
                  e.stopPropagation();
                  const hex = "0x" + target.address.toString(16).toUpperCase();
                  navigator.clipboard.writeText(hex);
                  setCopiedTarget(target.address);
                  setTimeout(() => setCopiedTarget(null), 1000);
                }}
                title={target.display || `Go to 0x${target.address.toString(16).toUpperCase()}`}
              >
                {t.text}
              </span>
            );
          }
        }
        const isReg = REG_NAMES.has(t.text.toLowerCase());
        const isHighlighted = isReg && highlightRegs?.has(t.text.toLowerCase());
        const cls = isHighlighted ? `${t.cls} reg-highlight cursor-pointer` : isReg && onRegClick ? `${t.cls} cursor-pointer` : t.cls;
        if (isReg && onRegClick) {
          return (
            <span
              key={i}
              className={cls}
              onClick={(e) => { e.stopPropagation(); onRegClick(t.text); }}
            >
              {t.text}
            </span>
          );
        }
        return t.cls ? <span key={i} className={t.cls}>{t.text}</span> : <span key={i}>{t.text}</span>;
      })}
    </>
  );
}

// --- Mnemonic coloring ---
export function mnemonicClass(m: string): string {
  if (m === "call") return "text-green-400 font-semibold";
  if (m === "ret" || m === "retn") return "text-red-400 font-semibold";
  if (m === "nop" || m === "int3") return "text-gray-600 font-semibold";
  if (m === "jmp" || m.startsWith("j")) return "text-orange-400 font-semibold";
  if (m === "push" || m === "pop") return "text-blue-300 font-semibold";
  return "font-semibold";
}

// --- Branch target parser ---
export function parseBranchTarget(mnemonic: string, opStr: string): number | null {
  if (
    mnemonic === "call" ||
    mnemonic === "jmp" ||
    mnemonic.startsWith("j")
  ) {
    const m = opStr.match(/^0x([0-9a-fA-F]+)$/);
    if (m) return parseInt(m[1], 16);
  }
  return null;
}
