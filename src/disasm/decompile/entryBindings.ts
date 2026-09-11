import type { FunctionSignature } from "../signatures";

/**
 * A parameter the function receives IN A REGISTER, and the name it is spelled
 * by in the emitted C.
 *
 * `size` is the width of the incoming value — the register's own width — and
 * the width a read of the whole register binds at; a narrower read of the same
 * entry value is spelled as a cast of the parameter (`(uint32_t)arg_0` for a
 * read of `ecx` in x64 code).
 */
export interface EntryBinding {
  /** `arg_0` … `arg_3` on x64; `arg_ecx` / `arg_edx` on x86. */
  name: string;
  /** 8 on x64, 4 on x86. */
  size: number;
  /** The canonical register the value arrives in — the map's own key, repeated for callers holding a binding alone. */
  register: string;
}

/** Integer argument registers of the Windows x64 calling convention, in argument order. */
export const X64_ARG_REGS = ["rcx", "rdx", "r8", "r9"] as const;

/**
 * THE ONE DECLARATION of which register holds which parameter on entry, read
 * by `destroySSA` (to spell every read of the register's entry value as the
 * parameter) and by `promoteVars` (to declare the parameter in the header) —
 * two consumers, one table, so the header and the body cannot disagree about
 * how many register parameters there are or what they are called
 * (peek-a-bin-n9cl.5).
 *
 * Keyed by canonical register (`canonReg`'s answer: the 64-bit parent), in
 * ARGUMENT ORDER, which is the order the header prints them in.
 *
 * **x64.** `rcx, rdx, r8, r9` → `arg_0 … arg_3`, for `i < min(paramCount, 4)`.
 * The evidence is `inferSignature64`'s: a fastcall register READ before it is
 * written in the first 20 instructions. That is a LOWER bound on the arity —
 * a register the scan did not see stays a register, and under
 * peek-a-bin-n9cl.4 it is then a *declared, uninitialised* register on the
 * page, which is the refusal made visible rather than papered over. The
 * spelling is `arg_<n>` with the underscore: the same pattern `stack.ts` gives a
 * spilled home slot (`argSlotName`), so a homed argument and its register
 * resolve to ONE parameter, and the pattern `structs.ts`'s `STACK_PARAM_RE`
 * keys cross-function provenance on — which is what gives x64 register
 * parameters provenance at all (they had none under `arg0`).
 *
 * **x86.** `ecx` → `arg_ecx` when the convention is `thiscall` or `fastcall`;
 * `edx` → `arg_edx` under `fastcall`. NOT `arg_<n>`, for three reasons that
 * are each sufficient: `argSlotName` numbers stack slots by OFFSET, so under
 * `__fastcall` `[ebp+8]` is `arg_0` although it is the third source argument;
 * `inferSignature32` deliberately excludes register arguments from
 * `paramCount` (an arity claim it has no oracle for); and four readers
 * (`useDecompileTabs`, `mcp/tools.ts`, `framedParamCount`,
 * `corpus/frameRepurpose.ts`) read `arg_<N>` as a SLOT index. Renumbering
 * would be a cross-cutting arity claim; `arg_ecx` claims exactly "the incoming
 * ECX" and nothing more. **`this` is REFUSED**: the thiscall detector cannot
 * tell `this` from a one-argument `__fastcall`, so naming it would state a
 * type the evidence does not carry.
 *
 * A `null` signature binds nothing, on both architectures.
 */
export function entryBindings(
  signature: FunctionSignature | null,
  is64: boolean,
): Map<string, EntryBinding> {
  const out = new Map<string, EntryBinding>();
  if (!signature) return out;
  if (is64) {
    const n = Math.min(signature.paramCount, X64_ARG_REGS.length);
    for (let i = 0; i < n; i++) {
      const register = X64_ARG_REGS[i];
      out.set(register, { name: `arg_${i}`, size: 8, register });
    }
    return out;
  }
  const c = signature.convention;
  if (c === "thiscall" || c === "fastcall") {
    out.set("rcx", { name: "arg_ecx", size: 4, register: "rcx" });
  }
  if (c === "fastcall") {
    out.set("rdx", { name: "arg_edx", size: 4, register: "rdx" });
  }
  return out;
}
