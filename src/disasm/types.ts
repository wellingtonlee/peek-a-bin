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
   * Did the function open with the canonical `push <fp>; mov <fp>, <sp>`
   * prologue? Only then is the frame register a *frame* pointer — invariant for
   * the whole body, and with `[<fp> + N]` addressing the caller's argument
   * area. Under frame-pointer omission RBP is an ordinary callee-saved
   * register, usually an object pointer, and neither of those holds.
   *
   * `arg_<N>` in a var's name already carries this — stack.ts spells a slot
   * that way only when this is true (see `hasFramePointerPrologue`) — but only
   * for a frame that *has* an argument slot. A framed function that takes no
   * arguments says nothing through that channel, so the fact is published here
   * as well rather than re-derived from the names.
   */
  framed: boolean;
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
