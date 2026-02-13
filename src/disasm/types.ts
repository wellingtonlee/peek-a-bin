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

