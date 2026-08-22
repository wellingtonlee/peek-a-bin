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

export interface Xref {
  from: number;
  type: "call" | "jmp" | "branch" | "data";
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
