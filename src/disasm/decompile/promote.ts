import type { FunctionSignature } from "../signatures";
import { stackVarKey } from "../stack";
import type { StackFrame } from "../types";
import type { IRCall, IRExpr, IRFunction, IRLocal, IRParam, IRStmt } from "./ir";
import { bodiesOf, irVar, walkStmts } from "./ir";
import type { TypeContext } from "./typeInfer";
import { typeToString } from "./typeInfer";

// ── Type-based variable renaming ──

const TYPE_BASED_NAMES: Record<string, string> = {
  HANDLE: "hFile",
  NTSTATUS: "status",
  HRESULT: "hr",
  PVOID: "pBuffer",
  BOOL: "bResult",
};

function renameVarsInExpr(expr: IRExpr, renameMap: Map<string, string>): IRExpr {
  if (expr.kind === "var") {
    const newName = renameMap.get(expr.name);
    if (newName) return { ...expr, name: newName };
    return expr;
  }
  switch (expr.kind) {
    case "binary":
      return {
        ...expr,
        left: renameVarsInExpr(expr.left, renameMap),
        right: renameVarsInExpr(expr.right, renameMap),
      };
    case "unary":
      return { ...expr, operand: renameVarsInExpr(expr.operand, renameMap) };
    case "deref":
      return { ...expr, address: renameVarsInExpr(expr.address, renameMap) };
    case "call":
      return { ...expr, args: expr.args.map((a) => renameVarsInExpr(a, renameMap)) } as IRExpr;
    case "ternary":
      return {
        ...expr,
        condition: renameVarsInExpr(expr.condition, renameMap),
        then: renameVarsInExpr(expr.then, renameMap),
        else: renameVarsInExpr(expr.else, renameMap),
      };
    case "cast":
      return { ...expr, operand: renameVarsInExpr(expr.operand, renameMap) };
    case "field_access":
      return { ...expr, base: renameVarsInExpr(expr.base, renameMap) };
    case "array_access":
      return {
        ...expr,
        base: renameVarsInExpr(expr.base, renameMap),
        index: renameVarsInExpr(expr.index, renameMap),
      };
    default:
      return expr;
  }
}

function renameVarsInStmt(stmt: IRStmt, renameMap: Map<string, string>): IRStmt {
  switch (stmt.kind) {
    case "assign":
      return {
        ...stmt,
        dest: renameVarsInExpr(stmt.dest, renameMap),
        src: renameVarsInExpr(stmt.src, renameMap),
      };
    case "store":
      return {
        ...stmt,
        address: renameVarsInExpr(stmt.address, renameMap),
        value: renameVarsInExpr(stmt.value, renameMap),
      };
    case "call_stmt":
      return { ...stmt, call: renameVarsInExpr(stmt.call, renameMap) as IRCall };
    case "return":
      return stmt.value ? { ...stmt, value: renameVarsInExpr(stmt.value, renameMap) } : stmt;
    case "if":
      return {
        ...stmt,
        condition: renameVarsInExpr(stmt.condition, renameMap),
        thenBody: stmt.thenBody.map((s) => renameVarsInStmt(s, renameMap)),
        elseBody: stmt.elseBody?.map((s) => renameVarsInStmt(s, renameMap)),
      };
    case "while":
      return {
        ...stmt,
        condition: renameVarsInExpr(stmt.condition, renameMap),
        body: stmt.body.map((s) => renameVarsInStmt(s, renameMap)),
      };
    case "do_while":
      return {
        ...stmt,
        condition: renameVarsInExpr(stmt.condition, renameMap),
        body: stmt.body.map((s) => renameVarsInStmt(s, renameMap)),
      };
    case "for":
      return {
        ...stmt,
        init: renameVarsInStmt(stmt.init, renameMap),
        condition: renameVarsInExpr(stmt.condition, renameMap),
        update: renameVarsInStmt(stmt.update, renameMap),
        body: stmt.body.map((s) => renameVarsInStmt(s, renameMap)),
      };
    case "switch":
      return {
        ...stmt,
        expr: renameVarsInExpr(stmt.expr, renameMap),
        cases: stmt.cases.map((c) => ({
          ...c,
          body: c.body.map((s) => renameVarsInStmt(s, renameMap)),
        })),
        defaultBody: stmt.defaultBody?.map((s) => renameVarsInStmt(s, renameMap)),
      };
    case "try":
      return {
        ...stmt,
        body: stmt.body.map((s) => renameVarsInStmt(s, renameMap)),
        handler: stmt.handler.map((s) => renameVarsInStmt(s, renameMap)),
        filterExpr: stmt.filterExpr ? renameVarsInExpr(stmt.filterExpr, renameMap) : undefined,
      };
    default:
      return stmt;
  }
}

// ── Size → C type mapping ──

function sizeToType(size: number): string {
  switch (size) {
    case 1:
      return "uint8_t";
    case 2:
      return "uint16_t";
    case 4:
      return "int32_t";
    case 8:
      return "int64_t";
    default:
      return "int32_t";
  }
}

// ── Stack access pattern matching ──

/** No frame-register alias is in play — see `frameRegisterAliases`. */
const NO_ALIASES: ReadonlySet<string> = new Set<string>();

interface StackAccess {
  /** Slot identity — see `stackVarKey`. `[rbp-0x10]` and `[rsp+0x10]` differ. */
  key: string;
  base: "bp" | "sp";
  /** Offset as written in the operand (always positive). */
  offset: number;
  isParam: boolean;
}

/**
 * Variables that provably hold the frame register's value, so that a slot
 * addressed through one of them is the same slot as one addressed through the
 * register itself.
 *
 * `splitStaleReads` parks a register version in a variable named after it
 * (`ebp_1`) and rewrites the stale reads to that variable, so a frame slot can
 * reach this pass addressed off `ebp_1` rather than off `ebp` — and it does, at
 * a *subset* of the sites in a function whose other sites still say `ebp`. The
 * frame register is the one register for which that split changes nothing about
 * the address: a frame pointer is invariant for the whole body by construction,
 * so every version of it denotes the same frame. Leaving the aliased sites
 * unmatched therefore did not preserve a distinction, it printed one slot under
 * two spellings — `arg_0` at one site and `*(int32_t*)(ebp_1 + 8)` at another
 * (peek-a-bin-5zpo).
 *
 * ONLY where the frame register IS a frame pointer, and only for the frame
 * register. Both limits are the point:
 *
 *  - **`StackFrame.frameDelta === null` is frame-pointer omission**, and there
 *    the invariance is not established: RBP is an ordinary callee-saved
 *    register — usually an object pointer — so two versions of it are two
 *    different objects, which is precisely what the split exists to keep apart.
 *    It is also what `structs.ts` needs left alone: `[rbp + 0x10]` in an FPO
 *    function is a struct field access, and this pass consuming it would take it
 *    out of struct synthesis's reach before that pass's own gate could decline
 *    it. `stack.ts` reaches `null` by *refusing* everything it cannot read as a
 *    stack-derived write of the frame register, so the FPO population is
 *    excluded structurally rather than by a test here.
 *  - **A displacement, not the canonical geometry.** What is needed is only that
 *    the register was established from the stack pointer, since that is what
 *    makes it invariant; *where* it points is a separate question, and one this
 *    pass never asks. The gate used to be `StackFrame.framed`, i.e.
 *    `D === slotSize` — so a shifted frame (`lea rbp, [rsp + k]`, or
 *    `mov rbp, rsp` after N pushes, both ordinary MSVC output) was refused for
 *    having a frame pointer in the wrong *place*, and 34 x64 functions of this
 *    corpus printed one slot under two spellings as a result: `arg_0` at one
 *    site and `*(int32_t*)(rbp_1 + 0x48)` at another in `t64!sub_1400080E0`,
 *    whose `arg_1` was a declared parameter with zero uses while both its reads
 *    went through the copy (peek-a-bin-cvri).
 *  - The stack pointer gets nothing here. It moves — that is the whole of what
 *    it does — so no version of it is interchangeable with another, and
 *    CLAUDE.md's standing rule is that no read of RSP may be reinterpreted at a
 *    program point other than its own.
 *
 * The invariance is a claim about the whole body and this pass sees only the
 * prologue's arithmetic, so it was checked rather than assumed: over all four
 * corpus binaries, **no** function with a recovered displacement writes its
 * frame register anywhere between establishing it and the epilogue's
 * `pop`/`leave` restore — 18 + 16 shifted-frame functions on the x64 pair and 1
 * on each PE32 binary. The two counterexamples in the corpus (`t32!sub_40A810`
 * and `w32!sub_4092B0`, `longjmp` reloading EBP from a `jmp_buf`) are both
 * *canonical*, so they were already inside this pass's reach before the gate was
 * widened; see peek-a-bin-633s.
 *
 * The evidence is the body's own assignments, in either direction, because
 * `swapDefWithCopy` writes the prologue as `ebp_1 = esp; ebp = ebp_1;` — the
 * copy's source is the *stack* pointer, and only the second statement ties it
 * to the frame register. Chains are resolved to a fixpoint so the order the
 * statements appear in does not matter.
 */
function frameRegisterAliases(
  body: IRStmt[],
  is64: boolean,
  frameDelta: number | null,
): Set<string> {
  const alias = new Set<string>();
  if (frameDelta === null) return alias;
  const bp = is64 ? "rbp" : "ebp";
  const isFrameReg = (e: IRExpr): boolean => e.kind === "reg" && e.name.toLowerCase() === bp;

  // Collected first so the fixpoint below can see a chain written in any order.
  const defs: { dest: IRExpr; src: IRExpr }[] = [];
  const scan = (stmts: IRStmt[]): void => {
    for (const s of stmts) {
      if (s.kind === "assign") defs.push({ dest: s.dest, src: s.src });
      // `bodiesOf` does not reach inside a `for`'s init and update — they are
      // single statements, not lists — and a copy of the frame register can sit
      // in either, so they are walked here.
      if (s.kind === "for") scan([s.init, s.update]);
      for (const nested of bodiesOf(s)) scan(nested);
    }
  };
  scan(body);

  const holdsFrame = (e: IRExpr): boolean =>
    isFrameReg(e) || (e.kind === "var" && alias.has(e.name));
  for (let pass = 0; pass <= defs.length; pass++) {
    let changed = false;
    for (const { dest, src } of defs) {
      if (dest.kind === "var" && !alias.has(dest.name) && holdsFrame(src)) {
        alias.add(dest.name);
        changed = true;
      }
      if (isFrameReg(dest) && src.kind === "var" && !alias.has(src.name)) {
        alias.add(src.name);
        changed = true;
      }
    }
    if (!changed) break;
  }
  return alias;
}

/**
 * Check if expr is [rbp - const] or [rsp + const] and return the slot.
 *
 * `bpAliases` names variables standing in for the frame register — see
 * `frameRegisterAliases`. It is empty unless `stack.ts` recovered the frame
 * register's displacement, so the frame-pointer-omission reading of `[rbp + N]`
 * is untouched.
 */
function matchStackAccess(
  expr: IRExpr,
  is64: boolean,
  bpAliases: ReadonlySet<string>,
): StackAccess | null {
  if (expr.kind !== "deref") return null;
  const addr = expr.address;

  const bp = is64 ? "rbp" : "ebp";
  const sp = is64 ? "rsp" : "esp";
  const isBp = (e: IRExpr): boolean =>
    (e.kind === "reg" && e.name.toLowerCase() === bp) ||
    (e.kind === "var" && bpAliases.has(e.name));

  // [rbp - offset] → local
  if (addr.kind === "binary" && addr.op === "-" && isBp(addr.left) && addr.right.kind === "const") {
    const offset = addr.right.value;
    return { key: stackVarKey("bp", -offset), base: "bp", offset, isParam: false };
  }

  // [rbp + offset] → param (if offset >= threshold)
  if (addr.kind === "binary" && addr.op === "+" && isBp(addr.left) && addr.right.kind === "const") {
    const minParam = is64 ? 0x10 : 0x8;
    const offset = addr.right.value;
    if (offset >= minParam)
      return { key: stackVarKey("bp", offset), base: "bp", offset, isParam: true };
  }

  // [rsp + offset] → local
  if (
    addr.kind === "binary" &&
    addr.op === "+" &&
    addr.left.kind === "reg" &&
    addr.left.name.toLowerCase() === sp &&
    addr.right.kind === "const"
  ) {
    const offset = addr.right.value;
    return { key: stackVarKey("sp", offset), base: "sp", offset, isParam: false };
  }

  // Direct base (rbp/rsp, or a frame-register alias) with no displacement
  if (isBp(addr)) return { key: stackVarKey("bp", 0), base: "bp", offset: 0, isParam: false };
  if (addr.kind === "reg" && addr.name.toLowerCase() === sp)
    return { key: stackVarKey("sp", 0), base: "sp", offset: 0, isParam: false };

  return null;
}

// ── Expression / Statement rewriting ──

function promoteExpr(
  expr: IRExpr,
  is64: boolean,
  varLookup: Map<string, string>,
  paramLookup: Map<string, string>,
  bpAliases: ReadonlySet<string>,
): IRExpr {
  // Check if this is a stack variable deref
  const stackAccess = matchStackAccess(expr, is64, bpAliases);
  if (stackAccess) {
    const lookup = stackAccess.isParam ? paramLookup : varLookup;
    const name = lookup.get(stackAccess.key);
    if (name) {
      return irVar(name, expr.kind === "deref" ? expr.size : 4);
    }
  }

  switch (expr.kind) {
    case "binary":
      return {
        ...expr,
        left: promoteExpr(expr.left, is64, varLookup, paramLookup, bpAliases),
        right: promoteExpr(expr.right, is64, varLookup, paramLookup, bpAliases),
      };
    case "unary":
      return {
        ...expr,
        operand: promoteExpr(expr.operand, is64, varLookup, paramLookup, bpAliases),
      };
    case "deref":
      return {
        ...expr,
        address: promoteExpr(expr.address, is64, varLookup, paramLookup, bpAliases),
      };
    case "call":
      return {
        ...expr,
        args: expr.args.map((a) => promoteExpr(a, is64, varLookup, paramLookup, bpAliases)),
      };
    case "ternary":
      return {
        ...expr,
        condition: promoteExpr(expr.condition, is64, varLookup, paramLookup, bpAliases),
        then: promoteExpr(expr.then, is64, varLookup, paramLookup, bpAliases),
        else: promoteExpr(expr.else, is64, varLookup, paramLookup, bpAliases),
      };
    case "cast":
      return {
        ...expr,
        operand: promoteExpr(expr.operand, is64, varLookup, paramLookup, bpAliases),
      };
    case "field_access":
      return { ...expr, base: promoteExpr(expr.base, is64, varLookup, paramLookup, bpAliases) };
    case "array_access":
      return {
        ...expr,
        base: promoteExpr(expr.base, is64, varLookup, paramLookup, bpAliases),
        index: promoteExpr(expr.index, is64, varLookup, paramLookup, bpAliases),
      };
    default:
      return expr;
  }
}

function promoteStmt(
  stmt: IRStmt,
  is64: boolean,
  varLookup: Map<string, string>,
  paramLookup: Map<string, string>,
  bpAliases: ReadonlySet<string>,
): IRStmt {
  switch (stmt.kind) {
    case "assign": {
      const dest = promoteExpr(stmt.dest, is64, varLookup, paramLookup, bpAliases);
      const src = promoteExpr(stmt.src, is64, varLookup, paramLookup, bpAliases);
      return { ...stmt, dest, src };
    }
    case "store": {
      // Check if store target is a stack variable
      const stackAccess = matchStackAccess(
        { kind: "deref", address: stmt.address, size: stmt.size },
        is64,
        bpAliases,
      );
      if (stackAccess) {
        const lookup = stackAccess.isParam ? paramLookup : varLookup;
        const name = lookup.get(stackAccess.key);
        if (name) {
          // Convert store to assign to variable
          return {
            kind: "assign",
            dest: irVar(name, stmt.size),
            src: promoteExpr(stmt.value, is64, varLookup, paramLookup, bpAliases),
            addr: stmt.addr,
          };
        }
      }
      return {
        ...stmt,
        address: promoteExpr(stmt.address, is64, varLookup, paramLookup, bpAliases),
        value: promoteExpr(stmt.value, is64, varLookup, paramLookup, bpAliases),
      };
    }
    case "call_stmt":
      return {
        ...stmt,
        call: promoteExpr(stmt.call, is64, varLookup, paramLookup, bpAliases) as IRExpr & {
          kind: "call";
        },
      };
    case "return":
      return stmt.value
        ? { ...stmt, value: promoteExpr(stmt.value, is64, varLookup, paramLookup, bpAliases) }
        : stmt;
    case "if":
      return {
        ...stmt,
        condition: promoteExpr(stmt.condition, is64, varLookup, paramLookup, bpAliases),
        thenBody: stmt.thenBody.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases)),
        elseBody: stmt.elseBody?.map((s) =>
          promoteStmt(s, is64, varLookup, paramLookup, bpAliases),
        ),
      };
    case "while":
      return {
        ...stmt,
        condition: promoteExpr(stmt.condition, is64, varLookup, paramLookup, bpAliases),
        body: stmt.body.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases)),
      };
    case "do_while":
      return {
        ...stmt,
        condition: promoteExpr(stmt.condition, is64, varLookup, paramLookup, bpAliases),
        body: stmt.body.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases)),
      };
    case "switch":
      return {
        ...stmt,
        expr: promoteExpr(stmt.expr, is64, varLookup, paramLookup, bpAliases),
        cases: stmt.cases.map((c) => ({
          ...c,
          body: c.body.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases)),
        })),
        defaultBody: stmt.defaultBody?.map((s) =>
          promoteStmt(s, is64, varLookup, paramLookup, bpAliases),
        ),
      };
    case "for":
      return {
        ...stmt,
        init: promoteStmt(stmt.init, is64, varLookup, paramLookup, bpAliases),
        condition: promoteExpr(stmt.condition, is64, varLookup, paramLookup, bpAliases),
        update: promoteStmt(stmt.update, is64, varLookup, paramLookup, bpAliases),
        body: stmt.body.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases)),
      };
    case "try":
      return {
        ...stmt,
        body: stmt.body.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases)),
        handler: stmt.handler.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases)),
        filterExpr: stmt.filterExpr
          ? promoteExpr(stmt.filterExpr, is64, varLookup, paramLookup, bpAliases)
          : undefined,
      };
    default:
      return stmt;
  }
}

// ── Detect whether function writes to return register before ret ──

function hasReturnValue(body: IRStmt[]): boolean {
  for (const stmt of body) {
    if (stmt.kind === "return" && stmt.value) {
      // Check if value is a call result or non-trivial expression
      if (stmt.value.kind !== "reg") return true;
      // Even a bare register return counts
      return true;
    }
    if (stmt.kind === "if") {
      if (hasReturnValue(stmt.thenBody)) return true;
      if (stmt.elseBody && hasReturnValue(stmt.elseBody)) return true;
    }
    if (stmt.kind === "while" || stmt.kind === "do_while") {
      if (hasReturnValue(stmt.body)) return true;
    }
  }
  return false;
}

/**
 * Infer variable types from access widths and cast signedness.
 * Walks the pre-promotion body to find IRDeref stack accesses that map to
 * known locals, then checks for IRCast wrappers to determine signedness.
 */
function inferVarTypes(
  body: IRStmt[],
  locals: IRLocal[],
  is64: boolean,
  varLookup: Map<string, string>,
  paramLookup: Map<string, string>,
  bpAliases: ReadonlySet<string>,
): void {
  const localsByName = new Map<string, IRLocal>();
  for (const l of locals) localsByName.set(l.name, l);

  // Track: varName → { minSize, signed: boolean | null }
  const info = new Map<string, { minSize: number; signed: boolean | null }>();

  walkStmts(body, (expr) => {
    // Check for cast wrapping a stack deref: (int8_t)*(deref)
    if (expr.kind === "cast") {
      const inner = expr.operand;
      const sa = matchStackAccess(inner, is64, bpAliases);
      if (sa) {
        const name = (sa.isParam ? paramLookup : varLookup).get(sa.key);
        if (name && localsByName.has(name)) {
          const entry = info.get(name) ?? { minSize: 8, signed: null };
          const castSigned = expr.type.startsWith("int");
          const castSize = parseInt(expr.type.replace(/\D/g, ""), 10) / 8 || 4;
          entry.minSize = Math.min(entry.minSize, castSize);
          if (entry.signed === null) entry.signed = castSigned;
          else if (castSigned) entry.signed = true; // signed wins
          info.set(name, entry);
        }
      }
    }
    // Track deref sizes for stack variables
    if (expr.kind === "deref") {
      const sa = matchStackAccess(expr, is64, bpAliases);
      if (sa) {
        const name = (sa.isParam ? paramLookup : varLookup).get(sa.key);
        if (name && localsByName.has(name)) {
          const entry = info.get(name) ?? { minSize: 8, signed: null };
          entry.minSize = Math.min(entry.minSize, expr.size);
          info.set(name, entry);
        }
      }
    }
  });

  // Apply inferred types
  for (const [name, { minSize, signed }] of info) {
    const local = localsByName.get(name);
    if (!local) continue;
    const bits = minSize * 8;
    const prefix = signed ? "int" : "uint";
    local.type = `${prefix}${bits}_t`;
  }
}

/**
 * Auto-synthesize stack frame locals when stackFrame is null.
 * Scans body for [rbp - X] and [rsp + X] deref patterns, collects unique
 * (offset, maxSize) pairs, deduplicates overlapping accesses.
 */
function synthesizeStackFrame(
  body: IRStmt[],
  is64: boolean,
  varLookup: Map<string, string>,
  locals: IRLocal[],
): void {
  // Keyed by slot, not by bare offset: [rbp-0x10] and [rsp+0x10] are different
  // slots and must not be collapsed into one local.
  interface Access {
    key: string;
    base: "bp" | "sp";
    offset: number;
    size: number;
  }
  const accesses = new Map<string, Access>();

  walkStmts(body, (expr) => {
    // No `StackFrame` at all means nothing verified a prologue, so there is no
    // frame-register alias to follow — see `frameRegisterAliases`.
    const sa = matchStackAccess(expr, is64, NO_ALIASES);
    if (sa && !sa.isParam && expr.kind === "deref") {
      const existing = accesses.get(sa.key);
      if (!existing) {
        accesses.set(sa.key, { key: sa.key, base: sa.base, offset: sa.offset, size: expr.size });
      } else if (expr.size > existing.size) {
        existing.size = expr.size;
      }
    }
  });

  // Deduplicate overlapping accesses (largest size wins). Overlap is only
  // meaningful between slots off the same base register.
  const sorted = [...accesses.values()].sort(
    (a, b) => a.offset - b.offset || a.base.localeCompare(b.base),
  );
  const seen: Access[] = [];
  const usedNames = new Set<string>();
  for (const acc of sorted) {
    // Skip if this offset overlaps with a previously created variable
    let overlaps = false;
    for (const prev of seen) {
      if (prev.base !== acc.base) continue;
      if (acc.offset >= prev.offset && acc.offset < prev.offset + prev.size) {
        overlaps = true;
        break;
      }
    }
    if (overlaps) continue;

    let varName = `var_${acc.offset.toString(16).toUpperCase()}`;
    if (usedNames.has(varName)) varName = `${varName}_${acc.base}`;
    usedNames.add(varName);
    varLookup.set(acc.key, varName);
    locals.push({ name: varName, type: sizeToType(acc.size) });
    seen.push(acc);
  }
}

/**
 * Promote stack variable references to named variables and
 * build function signature from stack frame + signature analysis.
 */
export function promoteVars(
  name: string,
  address: number,
  body: IRStmt[],
  stackFrame: StackFrame | null,
  signature: FunctionSignature | null,
  is64: boolean,
  typeCtx?: TypeContext,
): IRFunction {
  // Build lookup maps from stack frame vars
  const varLookup = new Map<string, string>(); // slot key → var name (locals)
  const paramLookup = new Map<string, string>(); // slot key → param name
  const locals: IRLocal[] = [];
  const params: IRParam[] = [];

  if (stackFrame) {
    for (const v of stackFrame.vars) {
      const type = sizeToType(v.size);
      const isParam = v.name.startsWith("arg_");
      // `key` identifies the slot (base + signed offset). Fall back to the old
      // offset-only interpretation for StackFrames produced before it existed:
      // params are [rbp + N], locals [rbp - N].
      const key = v.key ?? stackVarKey("bp", isParam ? v.offset : -v.offset);
      if (isParam) {
        paramLookup.set(key, v.name);
        params.push({ name: v.name, type });
      } else {
        varLookup.set(key, v.name);
        locals.push({ name: v.name, type });
      }
    }
  } else {
    // Auto stack-frame: scan body for [rbp - X] and [rsp + X] deref patterns
    synthesizeStackFrame(body, is64, varLookup, locals);
  }

  // Variables standing in for the frame register, so a slot reached through one
  // resolves to the same name as one reached through the register. Empty unless
  // stack.ts recovered the frame register's displacement, which is what says the
  // register is a frame pointer at all — see `frameRegisterAliases`. `?? null`
  // rather than `?.` alone: a `StackFrame` crosses a worker boundary, and a
  // shape predating the field must read as the refusal.
  const bpAliases = frameRegisterAliases(body, is64, stackFrame?.frameDelta ?? null);

  // For x64 fastcall: add register params
  if (is64 && signature && signature.paramCount > 0) {
    for (let i = 0; i < Math.min(signature.paramCount, 4); i++) {
      const paramName = `arg${i}`;
      // Only add if not already present from stack frame
      if (!params.some((p) => p.name === paramName)) {
        params.push({ name: paramName, type: "int64_t" });
      }
    }
  }

  // Infer variable types from access patterns
  inferVarTypes(body, locals, is64, varLookup, paramLookup, bpAliases);

  // Apply type inference results from SSA-level analysis
  if (typeCtx) {
    for (const local of locals) {
      const inferred = typeCtx.types.get(local.name);
      if (inferred && inferred.kind !== "unknown") {
        local.type = typeToString(inferred);
      }
    }
    for (const param of params) {
      const inferred = typeCtx.types.get(param.name);
      if (inferred && inferred.kind !== "unknown") {
        param.type = typeToString(inferred);
      }
    }
  }

  // Promote body
  const promoted = body.map((s) => promoteStmt(s, is64, varLookup, paramLookup, bpAliases));

  // Type-based variable renaming
  const renameMap = new Map<string, string>();
  const allNames = new Set([...locals.map((l) => l.name), ...params.map((p) => p.name)]);
  for (const local of locals) {
    if (!local.name.startsWith("var_")) continue;
    const prefix = TYPE_BASED_NAMES[local.type];
    if (!prefix) continue;
    let candidate = prefix;
    let suffix = 2;
    while (allNames.has(candidate)) {
      candidate = `${prefix}${suffix++}`;
    }
    renameMap.set(local.name, candidate);
    allNames.delete(local.name);
    allNames.add(candidate);
    local.name = candidate;
  }
  const finalBody =
    renameMap.size > 0 ? promoted.map((s) => renameVarsInStmt(s, renameMap)) : promoted;

  // Determine return type
  const returnType = hasReturnValue(finalBody) ? "int" : "void";

  return {
    name,
    address,
    returnType,
    params,
    locals,
    body: finalBody,
  };
}
