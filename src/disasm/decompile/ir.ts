// ── IR Expression Types ──

export interface IRConst {
  kind: "const";
  value: number;
  size: number;
}

export interface IRReg {
  kind: "reg";
  name: string;
  size: number;
  version?: number;
}

export interface IRVar {
  kind: "var";
  name: string;
  size: number;
}

export type BinaryOp =
  | "+"
  | "-"
  | "*"
  | "/"
  | "%"
  | "&"
  | "|"
  | "^"
  | "<<"
  | ">>"
  | ">>>"
  | "=="
  | "!="
  | "<"
  | "<="
  | ">"
  | ">="
  | "u<"
  | "u<="
  | "u>"
  | "u>="
  | "&&"
  | "||";

export interface IRBinary {
  kind: "binary";
  op: BinaryOp;
  left: IRExpr;
  right: IRExpr;
}

export type UnaryOp = "~" | "!" | "-";

export interface IRUnary {
  kind: "unary";
  op: UnaryOp;
  operand: IRExpr;
}

export interface IRDeref {
  kind: "deref";
  address: IRExpr;
  size: number;
}

export interface IRCall {
  kind: "call";
  target: string;
  args: IRExpr[];
  display?: string;
  /**
   * Canonical registers the *callee* is known to modify, from the interprocedural
   * written-register summary in `disasm/callSummary.ts`. Undefined means no
   * summary was supplied, which is every path that does not build one.
   *
   * Recorded on the call rather than looked up later because the only thing the
   * statement otherwise carries about its callee is a display *name*: the
   * address `resolveCallTarget` resolved is thrown away, and a name is neither
   * unique nor stable under a rename. `clobberedByCall` unions this with the
   * argument registers it already reports — it never replaces them, so a summary
   * that missed a write costs a clobber rather than inventing one.
   *
   * RAX is deliberately never listed: `liftBlock` gives every `call_stmt` a
   * `resultDest` of RAX/EAX, which is already a definition.
   */
  clobbers?: string[];
}

export interface IRCast {
  kind: "cast";
  type: string;
  operand: IRExpr;
}

export interface IRTernary {
  kind: "ternary";
  condition: IRExpr;
  then: IRExpr;
  else: IRExpr;
}

export interface IRFieldAccess {
  kind: "field_access";
  base: IRExpr; // struct pointer
  structId: string; // registry key, e.g. "struct_1"
  fieldOffset: number;
  fieldName: string; // "field_0x10", "array_0x20"
  size: number; // access size
}

export interface IRArrayAccess {
  kind: "array_access";
  base: IRExpr;
  index: IRExpr;
  elementSize: number;
  size: number;
}

export interface IRUnknown {
  kind: "unknown";
  text: string;
}

export type IRExpr =
  | IRConst
  | IRReg
  | IRVar
  | IRBinary
  | IRUnary
  | IRDeref
  | IRCall
  | IRCast
  | IRTernary
  | IRFieldAccess
  | IRArrayAccess
  | IRUnknown;

// ── IR Statement Types ──

export interface IRAssign {
  kind: "assign";
  dest: IRExpr;
  src: IRExpr;
  addr?: number;
}

export interface IRStore {
  kind: "store";
  address: IRExpr;
  value: IRExpr;
  size: number;
  addr?: number;
}

export interface IRCallStmt {
  kind: "call_stmt";
  call: IRCall;
  resultDest?: IRExpr;
  addr?: number;
}

export interface IRReturn {
  kind: "return";
  value?: IRExpr;
  addr?: number;
}

export interface IRIf {
  kind: "if";
  condition: IRExpr;
  thenBody: IRStmt[];
  elseBody?: IRStmt[];
}

export interface IRWhile {
  kind: "while";
  condition: IRExpr;
  body: IRStmt[];
}

export interface IRDoWhile {
  kind: "do_while";
  condition: IRExpr;
  body: IRStmt[];
}

export interface IRSwitchCase {
  values: number[];
  body: IRStmt[];
}

export interface IRSwitch {
  kind: "switch";
  expr: IRExpr;
  cases: IRSwitchCase[];
  defaultBody?: IRStmt[];
}

export interface IRGoto {
  kind: "goto";
  label: string;
}

export interface IRLabel {
  kind: "label";
  name: string;
  /**
   * A fact about this label the emitter prints as a comment on the line AFTER
   * it — never on the label's own line, which `corpus/undefinedCallees.ts` and
   * `gotoCheck` scrape as `^\s*(loc_[0-9A-F]+):$`.
   *
   * A FIELD, not a kind, deliberately: a label no `goto` names is load-bearing
   * for `structs.ts`'s `baseGenerations`, which resets every key at one, so
   * such a label must stay in the IR exactly as it is and anything said about
   * it is spelling at emission. `pipeline.ts`'s `annotateLabels` is the only
   * writer, and `structure.ts`'s `pushLabel` the only constructor
   * (peek-a-bin-5b6q.6).
   */
  note?: string;
}

export interface IRComment {
  kind: "comment";
  text: string;
}

export interface IRRaw {
  kind: "raw";
  text: string;
  addr?: number;
}

export interface IRFor {
  kind: "for";
  init: IRStmt;
  condition: IRExpr;
  update: IRStmt;
  body: IRStmt[];
}

export interface IRBreak {
  kind: "break";
}

export interface IRContinue {
  kind: "continue";
}

export interface IRPhi {
  kind: "phi";
  dest: IRReg;
  operands: { blockId: number; value: IRReg }[];
  addr?: number;
}

/**
 * What the image SAID the `__except` filter is — never what it is assumed to
 * be.
 *
 * `__except(EXCEPTION_EXECUTE_HANDLER)` used to be `emit.ts`'s unconditional
 * fallback for a `try` with no `filterExpr`, and **nothing in production has
 * ever constructed a `filterExpr`** (every one of the nine `src/` references is
 * a pass-through copy or a read; the only constructors are in tests). So that
 * literal was emitted 100% of the time, on every function the decompiler
 * wrapped, as a claim about a filter nothing had read. This field is the read
 * fact that replaces the assumption, and **its absence is deliberately the
 * UNRECOVERED case, never the constant** — a `try` reaching the emitter with no
 * filter information must admit that, or the fallback is back.
 *
 *  - `"execute-handler"` — the scope table's `handler` field held the literal
 *    1, which is the FORMAT'S OWN spelling of `EXCEPTION_EXECUTE_HANDLER`
 *    (a filter that needs no funclet, so the linker writes the constant where a
 *    filter RVA would go). This is the one case in which that identifier is a
 *    reading rather than a guess. It is rare: exactly ONE entry per binary
 *    across the whole corpus.
 *  - `"unrecovered"` — the table named a filter *routine* (`filterAddress`, a
 *    VA) or named nothing usable. Either way the filter's VALUE is not
 *    recovered, because nothing here decompiles the filter funclet, so it is
 *    spelled with the emitter's ordinary `__unrecovered_N` admission.
 */
export type IRTryFilter =
  | { spelling: "execute-handler" }
  | { spelling: "unrecovered"; filterAddress?: number };

export interface IRTry {
  kind: "try";
  body: IRStmt[];
  handler: IRStmt[]; // __except or __finally body
  filterExpr?: IRExpr; // __except(expr) filter, when one was actually recovered
  /**
   * The `.pdata` scope table's account of the filter. Read only when
   * `filterExpr` is absent, which in production is always — see
   * {@link IRTryFilter}, and `pipeline.ts`'s `wrapExceptionRegions` for the
   * rule that decides whether a `try` is emitted at all.
   *
   * Every pass that rebuilds an `IRTry` (`fold.ts`, `promote.ts` twice,
   * `structs.ts`, `ir.ts`'s `rewriteBodies`) does so with `...stmt`, so this
   * field survives without a per-pass edit. Keep it that way: a pass that
   * enumerates the fields instead would drop it silently, and the emitter would
   * degrade to the unrecovered spelling with nothing failing.
   */
  filterSource?: IRTryFilter;
}

/**
 * A block's trailing conditional jump, as a statement, so its condition
 * participates in SSA renaming and dataflow like every other expression.
 *
 * **This statement is confined to `liftedBlocks`.** `pipeline.ts` lifts it into
 * a side map keyed by block id immediately before `structureCFG`, so no
 * structured tree ever contains one: `cfgpatterns.ts`, `cleanup.ts`,
 * `promote.ts`, `structs.ts`, `typeInfer.ts` and `emit.ts` never see it. That
 * confinement is not tidiness, it is the design — `detectForLoop` skips any
 * body block whose last statement is not an `assign`, so a branch left in the
 * tree would take for-loop recognition to zero corpus-wide, silently and with
 * no failing test (peek-a-bin-c33 records the reasoning in full).
 *
 * `emit.ts` therefore **throws** on one rather than ignoring it: a branch that
 * escapes the extraction point is a defect, and `decompileFunction`'s catch
 * turns a throw into a counted failure that `corpus/compare.mjs` gates on. A
 * silent no-op there would make the same defect invisible.
 *
 * The precedent is already in the lifter: `setcc` calls `regState.getCondition()`
 * and assigns the resulting `IRExpr` to a register, and that survives SSA
 * renaming untouched. This does for `jcc` what the lifter already does for
 * `setcc`.
 */
export interface IRBranch {
  kind: "branch";
  /**
   * The condition under which the jump is TAKEN — the same polarity every entry
   * in `regstate.ts`'s `condMap` uses, and the same one `extractCondition`
   * returns. Getting this backwards once inverted every `if` and `while` the
   * decompiler emitted, so the polarity convention is stated at every hop.
   */
  condition: IRExpr;
  /** Virtual address of the taken target. */
  target: number;
  /** The originating jump's mnemonic, lowercased, e.g. `jne`. */
  jcc: string;
  addr?: number;
  /**
   * Address of the `cmp`/`test` whose operands the lifter *materialised* into
   * pseudo-registers at that instruction's own program point, because something
   * between it and this jump overwrote them (`spoiledCompareCapture` in
   * `lifter.ts`). Absent means the condition names the compared operands
   * directly, which is the ordinary case.
   *
   * It exists so `structure.ts` can tell one from the other, and it carries the
   * **address** rather than a boolean deliberately: `conditionSpoiled` decides
   * from its own forward walk over the machine text which instruction set the
   * flags, and only a capture taken at *that* instruction answers its
   * objection. Comparing the two is a positive agreement check — if the two
   * walks ever disagree the refusal stands, which is the safe direction
   * (peek-a-bin-xskz).
   */
  capturedAt?: number;
}

export type IRStmt =
  | IRAssign
  | IRStore
  | IRCallStmt
  | IRReturn
  | IRIf
  | IRWhile
  | IRDoWhile
  | IRFor
  | IRSwitch
  | IRGoto
  | IRLabel
  | IRComment
  | IRRaw
  | IRBreak
  | IRContinue
  | IRPhi
  | IRTry
  | IRBranch;

// ── Function Container ──

export interface IRParam {
  name: string;
  type: string;
  /**
   * The canonical register this parameter arrives in, for a parameter
   * `entryBindings.ts` bound (`rcx` for x64's `arg_0`, `rcx` for x86's
   * `arg_ecx`); absent for a stack slot `stack.ts` recovered. `structs.ts`'s
   * `stackDerivedBases` reads the absence: a positionally named STACK slot is
   * evidence the frame register was derived from the entry stack pointer, and
   * a register parameter spelled `arg_0` is not — without this field every x64
   * function with a signature would have its RBP excluded from struct
   * synthesis on the strength of a name (peek-a-bin-n9cl.5).
   */
  register?: string;
}

export interface IRLocal {
  name: string;
  type: string;
}

export interface IRFunction {
  name: string;
  address: number;
  returnType: string;
  params: IRParam[];
  locals: IRLocal[];
  body: IRStmt[];
  /**
   * Whether the image is PE32+ (x64), set by `promoteVars` from the pipeline's
   * own `is64` and read by `emitFunction` to cap the width a register variable
   * may be declared at — `regAtSize(canon, 4)` on a 32-bit image, so
   * `int64_t rcx;` can never appear in a function whose instruction set has no
   * RCX. Deliberately NOT inferred from the body the way `ssadestroy.ts`'s
   * `registerSpeller` infers its own (`peek-a-bin-0s6e`'s `rcx_18 = rcx` is a
   * canonical name leaking INTO a 32-bit body, and a cap inferred from that body
   * would read the leak as evidence of a 64-bit image).
   */
  is64: boolean;
  typedefs?: import("./structs").StructDef[];
}

// ── Helpers ──

export function irConst(value: number, size = 4): IRConst {
  return { kind: "const", value, size };
}

export function irReg(name: string, size = 0, version?: number): IRReg {
  if (!size) size = regSize(name);
  return version !== undefined ? { kind: "reg", name, size, version } : { kind: "reg", name, size };
}

export function irVar(name: string, size = 4): IRVar {
  return { kind: "var", name, size };
}

export function irBinary(op: BinaryOp, left: IRExpr, right: IRExpr): IRBinary {
  return { kind: "binary", op, left, right };
}

export function irUnary(op: UnaryOp, operand: IRExpr): IRUnary {
  return { kind: "unary", op, operand };
}

export function irDeref(address: IRExpr, size: number): IRDeref {
  return { kind: "deref", address, size };
}

export function irFieldAccess(
  base: IRExpr,
  structId: string,
  fieldOffset: number,
  fieldName: string,
  size: number,
): IRFieldAccess {
  return { kind: "field_access", base, structId, fieldOffset, fieldName, size };
}

export function irArrayAccess(
  base: IRExpr,
  index: IRExpr,
  elementSize: number,
  size: number,
): IRArrayAccess {
  return { kind: "array_access", base, index, elementSize, size };
}

export function irUnknown(text: string): IRUnknown {
  return { kind: "unknown", text };
}

const REG_SIZES: Record<string, number> = {
  rax: 8,
  rbx: 8,
  rcx: 8,
  rdx: 8,
  rsi: 8,
  rdi: 8,
  rbp: 8,
  rsp: 8,
  r8: 8,
  r9: 8,
  r10: 8,
  r11: 8,
  r12: 8,
  r13: 8,
  r14: 8,
  r15: 8,
  eax: 4,
  ebx: 4,
  ecx: 4,
  edx: 4,
  esi: 4,
  edi: 4,
  ebp: 4,
  esp: 4,
  r8d: 4,
  r9d: 4,
  r10d: 4,
  r11d: 4,
  r12d: 4,
  r13d: 4,
  r14d: 4,
  r15d: 4,
  ax: 2,
  bx: 2,
  cx: 2,
  dx: 2,
  si: 2,
  di: 2,
  bp: 2,
  sp: 2,
  r8w: 2,
  r9w: 2,
  r10w: 2,
  r11w: 2,
  r12w: 2,
  r13w: 2,
  r14w: 2,
  r15w: 2,
  al: 1,
  bl: 1,
  cl: 1,
  dl: 1,
  ah: 1,
  bh: 1,
  ch: 1,
  dh: 1,
  sil: 1,
  dil: 1,
  bpl: 1,
  spl: 1,
  r8b: 1,
  r9b: 1,
  r10b: 1,
  r11b: 1,
  r12b: 1,
  r13b: 1,
  r14b: 1,
  r15b: 1,
  eflags: 4,
  xmm0: 16,
  xmm1: 16,
  xmm2: 16,
  xmm3: 16,
  xmm4: 16,
  xmm5: 16,
  xmm6: 16,
  xmm7: 16,
  xmm8: 16,
  xmm9: 16,
  xmm10: 16,
  xmm11: 16,
  xmm12: 16,
  xmm13: 16,
  xmm14: 16,
  xmm15: 16,
  st0: 10,
  st1: 10,
  st2: 10,
  st3: 10,
  st4: 10,
  st5: 10,
  st6: 10,
  st7: 10,
};

export function regSize(name: string): number {
  return REG_SIZES[name.toLowerCase()] ?? 4;
}

/**
 * Is `name` an x86 register this IR knows about?
 *
 * `regSize()` defaults to 4 for anything it does not recognise, so it can never
 * be used as a membership test — `regSize(x) > 0` is true for every string.
 */
export function isKnownRegister(name: string): boolean {
  return REG_SIZES[name.toLowerCase()] !== undefined;
}

/** canonical name → width in bytes → the alias of that register at that width. */
const REG_ALIASES: Map<string, Map<number, string>> = (() => {
  const m = new Map<string, Map<number, string>>();
  for (const [name, size] of Object.entries(REG_SIZES)) {
    // `ah` is the same width as `al` and names the *other* half of AX, so it is
    // never the answer for "AX's 1-byte alias".
    if (/^[abcd]h$/.test(name)) continue;
    const canon = canonReg(name);
    const byWidth = m.get(canon) ?? new Map<number, string>();
    if (!byWidth.has(size)) byWidth.set(size, name);
    m.set(canon, byWidth);
  }
  return m;
})();

/**
 * The alias of a register at a given width — the inverse of `canonReg`, which
 * throws the width away: `regAtSize("rsi", 4)` is `esi`, `regAtSize("r8", 1)` is
 * `r8b`.
 *
 * Anything with no alias at that width is returned as it was given. That covers
 * both a register with no such alias (`xmm0` at 4) and a name that is not a
 * register at all, so the result is always *some* name and never a wrong one.
 */
export function regAtSize(canon: string, size: number): string {
  const lower = canon.toLowerCase();
  return REG_ALIASES.get(canonReg(lower))?.get(size) ?? canon;
}

// ── Expression / Statement Walkers ──

/** Recursively visit all sub-expressions in an expression tree. */
export function walkExpr(expr: IRExpr, fn: (e: IRExpr) => void): void {
  fn(expr);
  switch (expr.kind) {
    case "binary":
      walkExpr(expr.left, fn);
      walkExpr(expr.right, fn);
      break;
    case "unary":
      walkExpr(expr.operand, fn);
      break;
    case "deref":
      walkExpr(expr.address, fn);
      break;
    case "call":
      expr.args.forEach((a) => walkExpr(a, fn));
      break;
    case "cast":
      walkExpr(expr.operand, fn);
      break;
    case "ternary":
      walkExpr(expr.condition, fn);
      walkExpr(expr.then, fn);
      walkExpr(expr.else, fn);
      break;
    case "field_access":
      walkExpr(expr.base, fn);
      break;
    case "array_access":
      walkExpr(expr.base, fn);
      walkExpr(expr.index, fn);
      break;
  }
}

/**
 * Whether this statement ends its block's straight-line code.
 *
 * Only `IRBranch` does, and only inside `liftedBlocks` — the structured tree
 * has no terminators, because `pipeline.ts` extracts every branch before
 * `structureCFG`. `return` is deliberately **not** one: nothing appends to a
 * block after lifting on the strength of it, and widening this predicate would
 * change where existing passes insert.
 */
export function isBlockTerminator(stmt: IRStmt): boolean {
  return stmt.kind === "branch";
}

/**
 * Append a statement to a block's lifted list, keeping it ahead of any
 * terminator.
 *
 * Two passes add a statement to the *end* of another block's list — `destroySSA`
 * lowering a phi to a copy in the predecessor, and `loopInvariantCodeMotion`
 * hoisting into the preheader. Both are correct only while no terminator exists
 * in the IR, because "end of the statement list" and "end of the block's
 * straight-line code" are then the same place. A branch statement makes them
 * different, and a plain `push` would land the definition *after* the branch
 * that reads it — a read preceding its own definition, in the block that decides
 * whether a loop is even entered.
 *
 * The preheader case is the live one: it is `ctx.idom.get(header)`, so it very
 * often ends in exactly such a branch (peek-a-bin-c33).
 */
export function pushBeforeTerminator(stmts: IRStmt[], stmt: IRStmt): void {
  const last = stmts[stmts.length - 1];
  if (last && isBlockTerminator(last)) stmts.splice(stmts.length - 1, 0, stmt);
  else stmts.push(stmt);
}

/** Walk all expressions inside a statement tree. */
export function walkStmts(stmts: IRStmt[], fn: (e: IRExpr) => void): void {
  for (const s of stmts) {
    switch (s.kind) {
      case "assign":
        walkExpr(s.dest, fn);
        walkExpr(s.src, fn);
        break;
      case "store":
        walkExpr(s.address, fn);
        walkExpr(s.value, fn);
        break;
      case "call_stmt":
        walkExpr(s.call, fn);
        break;
      case "return":
        if (s.value) walkExpr(s.value, fn);
        break;
      case "if":
        walkExpr(s.condition, fn);
        walkStmts(s.thenBody, fn);
        if (s.elseBody) walkStmts(s.elseBody, fn);
        break;
      case "while":
        walkExpr(s.condition, fn);
        walkStmts(s.body, fn);
        break;
      case "do_while":
        walkExpr(s.condition, fn);
        walkStmts(s.body, fn);
        break;
      case "switch":
        walkExpr(s.expr, fn);
        s.cases.forEach((c) => walkStmts(c.body, fn));
        if (s.defaultBody) walkStmts(s.defaultBody, fn);
        break;
      case "for":
        walkStmts([s.init], fn);
        walkExpr(s.condition, fn);
        walkStmts([s.update], fn);
        walkStmts(s.body, fn);
        break;
      case "phi":
        for (const op of s.operands) walkExpr(op.value, fn);
        break;
      case "try":
        walkStmts(s.body, fn);
        walkStmts(s.handler, fn);
        if (s.filterExpr) walkExpr(s.filterExpr, fn);
        break;
      case "branch":
        walkExpr(s.condition, fn);
        break;
    }
  }
}

// ── Structured-Tree Body Traversal ──

/**
 * Every statement list nested directly inside `stmt`.
 *
 * This and `rewriteBodies` below are the read and write halves of one
 * traversal: `bodiesOf` reads the nested lists, `rewriteBodies` replaces each
 * of them with `f`'s result and returns the rebuilt statement. Every pass that
 * recurses through the structured tree without caring what the statements *are*
 * — `structure.ts`'s label pruning and free-`continue` search, `cleanup.ts`'s
 * `goto`-to-`break` rewriting, its trailing-label repair and its main cleanup
 * pass — is one of these two plus a callback.
 *
 * They live here, beside `walkExpr`/`walkStmts`, because `rewriteBodies`
 * existed as a verbatim copy in *each* of `structure.ts` and `cleanup.ts`, plus
 * two further specialisations of it in `cleanup.ts` under other names
 * (`repairStmt`, `cleanupStmt`) — four independent switches over `IRStmt` that
 * had to be hand-synced. That is the shape `sections.ts`, `ripRelative.ts`,
 * `funcInsns.ts` and `stackIdiom.ts` were each created to end (peek-a-bin-svwt).
 *
 * **Both end in an exhaustive `never` binding, deliberately.** A new `IRStmt`
 * kind carrying a nested body is exactly the failure the duplication made
 * likely: under a `default:` arm such a kind is reported as having no bodies and
 * returned unrecursed — silently, with the typechecker saying nothing — so
 * every pass above walks straight past everything inside it. Naming the
 * body-less kinds explicitly costs twelve lines and turns that into a build
 * failure, which moves these out of CLAUDE.md's "you must find these by hand"
 * group and into the compiler-caught one.
 *
 * **`for`'s `init` and `update` are single statements, not lists**, so `f`
 * cannot apply to them and neither function reaches inside them. That is
 * unchanged from the copies these replace. In practice both are assignments —
 * `detectForLoop` only recognises a loop whose candidate body block ends in one
 * — and a caller that must reach a nested *statement* wants `foldStmt`'s shape
 * rather than this one.
 */
export function bodiesOf(stmt: IRStmt): IRStmt[][] {
  switch (stmt.kind) {
    case "if":
      return stmt.elseBody ? [stmt.thenBody, stmt.elseBody] : [stmt.thenBody];
    case "while":
    case "do_while":
    case "for":
      return [stmt.body];
    case "switch":
      return stmt.defaultBody
        ? [...stmt.cases.map((c) => c.body), stmt.defaultBody]
        : stmt.cases.map((c) => c.body);
    case "try":
      return [stmt.body, stmt.handler];
    case "assign":
    case "store":
    case "call_stmt":
    case "return":
    case "goto":
    case "label":
    case "comment":
    case "raw":
    case "break":
    case "continue":
    case "phi":
    case "branch":
      return []; // no nested statement list
    default: {
      // Compile error if a new IRStmt kind is added without handling it here.
      const _exhaustive: never = stmt;
      return _exhaustive;
    }
  }
}

/**
 * Rebuild `stmt` with `f` applied to each of its nested statement lists.
 *
 * The write half of `bodiesOf` — see its docstring for why both live here and
 * why both are exhaustive.
 */
export function rewriteBodies(stmt: IRStmt, f: (list: IRStmt[]) => IRStmt[]): IRStmt {
  switch (stmt.kind) {
    case "if":
      return { ...stmt, thenBody: f(stmt.thenBody), elseBody: stmt.elseBody && f(stmt.elseBody) };
    case "while":
    case "do_while":
    case "for":
      return { ...stmt, body: f(stmt.body) };
    case "switch":
      return {
        ...stmt,
        cases: stmt.cases.map((c) => ({ ...c, body: f(c.body) })),
        defaultBody: stmt.defaultBody && f(stmt.defaultBody),
      };
    case "try":
      return { ...stmt, body: f(stmt.body), handler: f(stmt.handler) };
    case "assign":
    case "store":
    case "call_stmt":
    case "return":
    case "goto":
    case "label":
    case "comment":
    case "raw":
    case "break":
    case "continue":
    case "phi":
    case "branch":
      return stmt; // no nested statement list
    default: {
      // Compile error if a new IRStmt kind is added without handling it here.
      const _exhaustive: never = stmt;
      return _exhaustive;
    }
  }
}

/** Canonical 64-bit parent of any x86 register (e.g. al→rax, r8d→r8) */
export function canonReg(name: string): string {
  const lower = name.toLowerCase();
  // rNb/rNw/rNd → rN
  const rN = lower.match(/^(r\d+)[bwd]$/);
  if (rN) return rN[1];
  // 8-bit / 16-bit / 32-bit → 64-bit
  const map: Record<string, string> = {
    al: "rax",
    ah: "rax",
    ax: "rax",
    eax: "rax",
    bl: "rbx",
    bh: "rbx",
    bx: "rbx",
    ebx: "rbx",
    cl: "rcx",
    ch: "rcx",
    cx: "rcx",
    ecx: "rcx",
    dl: "rdx",
    dh: "rdx",
    dx: "rdx",
    edx: "rdx",
    sil: "rsi",
    si: "rsi",
    esi: "rsi",
    dil: "rdi",
    di: "rdi",
    edi: "rdi",
    bpl: "rbp",
    bp: "rbp",
    ebp: "rbp",
    spl: "rsp",
    sp: "rsp",
    esp: "rsp",
  };
  return map[lower] ?? lower;
}
