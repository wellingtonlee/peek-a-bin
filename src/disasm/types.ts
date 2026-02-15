export interface Instruction {
  address: number;
  bytes: Uint8Array;
  mnemonic: string;
  opStr: string;
  size: number;
  comment?: string;  // for string reference annotations
}

export interface DisasmFunction {
  name: string;
  address: number;
  size: number;
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

