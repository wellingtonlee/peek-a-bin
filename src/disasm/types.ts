export interface Instruction {
  address: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
  size: number;
  comment?: string;  // for string reference annotations
  source?: 'recursive' | 'gap-fill';
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
  type: 'call' | 'jmp' | 'branch' | 'data';
}

export interface StackVar {
  offset: number;
  size: number;
  accessCount: number;
  name: string;
}

export interface StackFrame {
  frameSize: number;
  vars: StackVar[];
}

export interface DataItem {
  address: number;
  directive: "db" | "dd" | "dq" | "dup";
  size: number;           // bytes consumed
  bytes: Uint8Array;      // raw bytes for hex column
  stringValue?: string;
  stringType?: "ascii" | "utf16le";
  pointerTarget?: number;
  pointerLabel?: string;
  dupCount?: number;
  dupByte?: number;
}

