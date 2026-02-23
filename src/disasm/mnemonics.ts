/** One-line descriptions for common x86/x64 mnemonics */
export const MNEMONIC_HINTS: Record<string, string> = {
  // Data movement
  mov: "Copy data between registers/memory",
  movzx: "Move with zero-extension",
  movsx: "Move with sign-extension",
  movsxd: "Move with sign-extension (32→64)",
  cmovz: "Conditional move if zero (ZF=1)",
  cmovnz: "Conditional move if not zero (ZF=0)",
  cmove: "Conditional move if equal (ZF=1)",
  cmovne: "Conditional move if not equal (ZF=0)",
  cmovg: "Conditional move if greater (signed)",
  cmovge: "Conditional move if greater or equal (signed)",
  cmovl: "Conditional move if less (signed)",
  cmovle: "Conditional move if less or equal (signed)",
  cmova: "Conditional move if above (unsigned)",
  cmovae: "Conditional move if above or equal (unsigned)",
  cmovb: "Conditional move if below (unsigned)",
  cmovbe: "Conditional move if below or equal (unsigned)",
  lea: "Load effective address (compute without memory access)",
  xchg: "Exchange values between two operands",

  // Stack
  push: "Decrement SP and store value on stack",
  pop: "Load value from stack and increment SP",
  enter: "Create stack frame (push BP, mov BP SP, sub SP)",
  leave: "Destroy stack frame (mov SP BP, pop BP)",

  // Arithmetic
  add: "Add source to destination",
  sub: "Subtract source from destination",
  imul: "Signed multiply",
  mul: "Unsigned multiply",
  idiv: "Signed divide (EDX:EAX / operand)",
  div: "Unsigned divide (EDX:EAX / operand)",
  inc: "Increment by 1",
  dec: "Decrement by 1",
  neg: "Two's complement negate",
  adc: "Add with carry flag",
  sbb: "Subtract with borrow (carry flag)",

  // Logic
  and: "Bitwise AND",
  or: "Bitwise OR",
  xor: "Bitwise XOR (often used to zero a register)",
  not: "Bitwise NOT (one's complement)",
  shl: "Shift left (multiply by power of 2)",
  shr: "Logical shift right (unsigned divide by power of 2)",
  sar: "Arithmetic shift right (signed divide by power of 2)",
  rol: "Rotate left",
  ror: "Rotate right",
  bt: "Bit test — copy bit to carry flag",
  bts: "Bit test and set",
  btr: "Bit test and reset",
  bsf: "Bit scan forward (find first set bit)",
  bsr: "Bit scan reverse (find last set bit)",

  // Compare & test
  cmp: "Compare two operands (sub without storing result)",
  test: "Bitwise AND without storing result (sets flags)",

  // Control flow — calls & returns
  call: "Push return address and jump to target",
  ret: "Pop return address and jump to it",
  retn: "Return near (pop IP from stack)",

  // Unconditional jump
  jmp: "Unconditional jump to target",

  // Conditional jumps
  je: "Jump if equal (ZF=1)",
  jne: "Jump if not equal (ZF=0)",
  jz: "Jump if zero (ZF=1)",
  jnz: "Jump if not zero (ZF=0)",
  jg: "Jump if greater (signed)",
  jge: "Jump if greater or equal (signed)",
  jl: "Jump if less (signed)",
  jle: "Jump if less or equal (signed)",
  ja: "Jump if above (unsigned)",
  jae: "Jump if above or equal (unsigned)",
  jb: "Jump if below (unsigned)",
  jbe: "Jump if below or equal (unsigned)",
  js: "Jump if sign flag set (negative)",
  jns: "Jump if sign flag clear (non-negative)",
  jo: "Jump if overflow",
  jno: "Jump if no overflow",
  jp: "Jump if parity (even)",
  jnp: "Jump if no parity (odd)",
  jcxz: "Jump if CX is zero",
  jecxz: "Jump if ECX is zero",
  jrcxz: "Jump if RCX is zero",

  // Set byte on condition
  sete: "Set byte to 1 if equal (ZF=1)",
  setne: "Set byte to 1 if not equal (ZF=0)",
  setg: "Set byte to 1 if greater (signed)",
  setl: "Set byte to 1 if less (signed)",
  seta: "Set byte to 1 if above (unsigned)",
  setb: "Set byte to 1 if below (unsigned)",

  // String operations
  rep: "Repeat following string operation CX times",
  repz: "Repeat while zero flag set",
  repnz: "Repeat while zero flag clear",
  movsb: "Move byte from [SI] to [DI]",
  movsd: "Move dword from [SI] to [DI]",
  movsq: "Move qword from [RSI] to [RDI]",
  stosb: "Store AL to [DI], increment DI",
  stosd: "Store EAX to [EDI], increment EDI",
  stosq: "Store RAX to [RDI], increment RDI",
  lodsb: "Load byte from [SI] into AL",
  scasb: "Compare AL with byte at [DI]",
  cmpsb: "Compare byte at [SI] with byte at [DI]",

  // NOP & padding
  nop: "No operation",
  int3: "Breakpoint trap (debug interrupt)",
  int: "Software interrupt",
  ud2: "Undefined instruction (intentional crash)",
  hlt: "Halt processor until interrupt",

  // System
  syscall: "System call (x64 fast syscall)",
  sysenter: "System call (x86 fast syscall)",
  cpuid: "Query CPU identification and features",
  rdtsc: "Read timestamp counter into EDX:EAX",
  in: "Read from I/O port",
  out: "Write to I/O port",
  cli: "Clear interrupt flag (disable interrupts)",
  sti: "Set interrupt flag (enable interrupts)",

  // SSE/AVX basics
  movaps: "Move aligned packed single-precision floats",
  movups: "Move unaligned packed single-precision floats",
  movdqa: "Move aligned packed integers (128-bit)",
  movdqu: "Move unaligned packed integers (128-bit)",
  pxor: "Packed XOR (often used to zero XMM register)",
  xorps: "Bitwise XOR of packed single-precision floats",
};
