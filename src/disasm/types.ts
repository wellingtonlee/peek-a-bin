export interface Instruction {
  address: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
  size: number;
  comment?: string; // for string reference annotations
  source?: "recursive" | "gap-fill";
}

export interface DisasmFunction {
  name: string;
  address: number;
  size: number;
  tailCallTarget?: number;
  isThunk?: boolean;
}

/**
 * What kind of reference one address makes to another.
 *
 * NAMED, rather than spelled inline in `Xref`, so the three tables that fold it
 * onto a colour or a letter can be `Record<XrefType, …>` and a fifth member
 * fails the build — the closed-union rule `VIEW_TAB_LABELS`, `DETECT_PASS_LABELS`
 * and `severity.ts`'s `ANOMALY_BADGE` already carry. While it was inline there
 * was nothing to key on, so all four tables were `Record<string, …>`: a new kind
 * reached the screen as grey "?" in `InstructionDetail` and as grey text in
 * `XrefPanel`, silently, with the `?? fallback` at each use site doing exactly
 * what it looks like it is there to prevent (peek-a-bin-v3uh.8).
 *
 * `XrefPanel` additionally kept its OWN copy of this union, which is the drift
 * half of the same class; it imports this one now.
 *
 * The `?? fallback`s at the use sites STAY. They answer a different question —
 * these values arrive over a `postMessage` from the worker, so a `Record` cannot
 * make an unexpected one impossible at runtime. What the `Record` buys is that
 * the fifth member cannot be ADDED here without every table being revisited.
 */
export type XrefType = "call" | "jmp" | "branch" | "data";

export interface Xref {
  from: number;
  type: XrefType;
}

export interface StackVar {
  /** Offset exactly as written in the operand (always positive). */
  offset: number;
  /**
   * Offset with its real sign: negative for `[rbp-0x10]`, positive for
   * `[rbp+0x10]` and `[rsp+0x10]`.
   *
   * `offset` alone cannot be rendered — a frame holds locals below the frame
   * pointer AND parameters above it, so assuming one sign mislabels the other.
   */
  signedOffset: number;
  size: number;
  accessCount: number;
  name: string;
  /**
   * Stable slot identity, `"<base>:<signedOffset>"` (see `stackVarKey` in
   * disasm/stack.ts) — e.g. `bp:-16` for `[rbp-0x10]` vs `sp:16` for
   * `[rsp+0x10]`. `offset` alone does not distinguish those two slots.
   */
  key?: string;
}

export interface StackFrame {
  frameSize: number;
  vars: StackVar[];
  /**
   * `E - V` for the frame register, where `E` is the stack pointer on **entry**
   * and `V` the value the function establishes in it — or `null` when it never
   * establishes one *from the stack pointer* at all. `inlineFrameGeometry` in
   * `disasm/stack.ts` is the one place it is computed.
   *
   * The QUANTITY, and it replaced a boolean `framed` at peek-a-bin-cvri because
   * that boolean was answering two different questions with one bit:
   *
   *  - **`frameDelta !== null` means the frame register IS a frame pointer** —
   *    derived from the stack pointer, therefore invariant for the whole body.
   *    That invariance is what makes a *copy* of the register interchangeable
   *    with the register itself, which is the only thing `promote.ts`'s
   *    `frameRegisterAliases` needs to know. `null` is frame-pointer omission:
   *    `mov rbp, rcx` makes RBP an object pointer, `mov rbp, rdx` is how an MSVC
   *    funclet receives its parent's frame, `xor ebp, ebp` makes it a constant,
   *    and in none of those is `[<fp> + N]` this frame at all.
   *  - **The value says where the incoming-argument area begins**:
   *    `[<fp> + D]` holds the return address, so `[<fp> + D + slot]` is
   *    argument 0 and `[<fp> + off]` is argument `(off - D - slot) / slot`.
   *
   * `framed` was `D === slotSize`, i.e. the *canonical* geometry alone, and it
   * was the gate on both. A shifted frame — `lea rbp, [rsp + k]`, or
   * `mov rbp, rsp` after N pushes — is an ordinary MSVC shape with some other
   * `D` and a frame pointer every bit as invariant, so gating invariance on the
   * canonical geometry printed one slot under two spellings in 34 of this
   * corpus's x64 functions (peek-a-bin-ikd, peek-a-bin-sx57, peek-a-bin-cvri).
   *
   * `null` and `undefined` must read the same way, since a `StackFrame` crosses
   * a worker boundary: consumers ask `frameDelta ?? null`, so a shape from
   * before this field degrades to the refusal rather than to "every frame
   * register is a frame pointer".
   */
  frameDelta: number | null;
  /**
   * The address of the instruction that establishes the frame register from the
   * stack pointer, or `null` when no such instruction was found in this function
   * — which includes every case where `frameDelta` is `null`, and also the
   * helper-framed prologue, where the establishing `lea` is inside
   * `__SEH_prolog4` and not in this function's instruction stream at all.
   *
   * It exists for ONE consumer and one question. `destroySSA`'s
   * `swapDefWithCopy` rewrites the frame register's own definition as
   * `ebp_1 = esp; ebp = ebp_1;`, and where every read of the register was
   * rewritten to the copy, DCE deletes the second statement — leaving a body in
   * which the only thing `promote.ts` can see is a variable assigned the *stack*
   * pointer, indistinguishable from an unrelated copy of it, which it must
   * refuse. This address is what tells the two apart: an assignment carrying it
   * whose destination is a variable IS the frame register's definition wearing
   * the copy's name, because a `mov`/`lea` into a register lifts to exactly one
   * statement and `swapDefWithCopy` is the only pass that swaps its destination
   * for a variable while keeping its address (peek-a-bin-xb2f).
   *
   * `null` and `undefined` must read the same way, for `frameDelta`'s reason: a
   * `StackFrame` crosses a worker boundary, so a shape from before this field
   * degrades to "no such statement can be identified" rather than to some
   * address that would match one.
   */
  frameEstablishedAt: number | null;
}

export interface DataItem {
  address: number;
  directive: "db" | "dd" | "dq" | "dup";
  size: number; // bytes consumed
  bytes: Uint8Array; // raw bytes for hex column
  stringValue?: string;
  stringType?: "ascii" | "utf16le";
  pointerTarget?: number;
  pointerLabel?: string;
  dupCount?: number;
  dupByte?: number;
}
