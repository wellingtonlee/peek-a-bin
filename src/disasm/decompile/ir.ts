// ── IR Expression Types ──

export interface IRConst {
  kind: 'const';
  value: number;
  size: number;
}

export interface IRReg {
  kind: 'reg';
  name: string;
  size: number;
}

export interface IRVar {
  kind: 'var';
  name: string;
  size: number;
}

export type BinaryOp =
  | '+' | '-' | '*' | '/' | '%'
  | '&' | '|' | '^' | '<<' | '>>' | '>>>'
  | '==' | '!=' | '<' | '<=' | '>' | '>='
  | 'u<' | 'u<=' | 'u>' | 'u>=';

export interface IRBinary {
  kind: 'binary';
  op: BinaryOp;
  left: IRExpr;
  right: IRExpr;
}

export type UnaryOp = '~' | '!' | '-';

export interface IRUnary {
  kind: 'unary';
  op: UnaryOp;
  operand: IRExpr;
}

export interface IRDeref {
  kind: 'deref';
  address: IRExpr;
  size: number;
}

export interface IRCall {
  kind: 'call';
  target: string;
  args: IRExpr[];
  display?: string;
}

export interface IRCast {
  kind: 'cast';
  type: string;
  operand: IRExpr;
}

export interface IRTernary {
  kind: 'ternary';
  condition: IRExpr;
  then: IRExpr;
  else: IRExpr;
}

export interface IRUnknown {
  kind: 'unknown';
  text: string;
}

export type IRExpr =
  | IRConst | IRReg | IRVar | IRBinary | IRUnary
  | IRDeref | IRCall | IRCast | IRTernary | IRUnknown;

// ── IR Statement Types ──

export interface IRAssign {
  kind: 'assign';
  dest: IRExpr;
  src: IRExpr;
  addr?: number;
}

export interface IRStore {
  kind: 'store';
  address: IRExpr;
  value: IRExpr;
  size: number;
  addr?: number;
}

export interface IRCallStmt {
  kind: 'call_stmt';
  call: IRCall;
  resultDest?: IRExpr;
  addr?: number;
}

export interface IRReturn {
  kind: 'return';
  value?: IRExpr;
  addr?: number;
}

export interface IRIf {
  kind: 'if';
  condition: IRExpr;
  thenBody: IRStmt[];
  elseBody?: IRStmt[];
}

export interface IRWhile {
  kind: 'while';
  condition: IRExpr;
  body: IRStmt[];
}

export interface IRDoWhile {
  kind: 'do_while';
  condition: IRExpr;
  body: IRStmt[];
}

export interface IRSwitchCase {
  values: number[];
  body: IRStmt[];
}

export interface IRSwitch {
  kind: 'switch';
  expr: IRExpr;
  cases: IRSwitchCase[];
  defaultBody?: IRStmt[];
}

export interface IRGoto {
  kind: 'goto';
  label: string;
}

export interface IRLabel {
  kind: 'label';
  name: string;
}

export interface IRComment {
  kind: 'comment';
  text: string;
}

export interface IRRaw {
  kind: 'raw';
  text: string;
  addr?: number;
}

export interface IRBreak {
  kind: 'break';
}

export type IRStmt =
  | IRAssign | IRStore | IRCallStmt | IRReturn
  | IRIf | IRWhile | IRDoWhile | IRSwitch
  | IRGoto | IRLabel | IRComment | IRRaw | IRBreak;

// ── Function Container ──

export interface IRParam {
  name: string;
  type: string;
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
}

// ── Helpers ──

export function irConst(value: number, size = 4): IRConst {
  return { kind: 'const', value, size };
}

export function irReg(name: string, size = 0): IRReg {
  if (!size) size = regSize(name);
  return { kind: 'reg', name, size };
}

export function irVar(name: string, size = 4): IRVar {
  return { kind: 'var', name, size };
}

export function irBinary(op: BinaryOp, left: IRExpr, right: IRExpr): IRBinary {
  return { kind: 'binary', op, left, right };
}

export function irUnary(op: UnaryOp, operand: IRExpr): IRUnary {
  return { kind: 'unary', op, operand };
}

export function irDeref(address: IRExpr, size: number): IRDeref {
  return { kind: 'deref', address, size };
}

export function irUnknown(text: string): IRUnknown {
  return { kind: 'unknown', text };
}

const REG_SIZES: Record<string, number> = {
  rax: 8, rbx: 8, rcx: 8, rdx: 8, rsi: 8, rdi: 8, rbp: 8, rsp: 8,
  r8: 8, r9: 8, r10: 8, r11: 8, r12: 8, r13: 8, r14: 8, r15: 8,
  eax: 4, ebx: 4, ecx: 4, edx: 4, esi: 4, edi: 4, ebp: 4, esp: 4,
  r8d: 4, r9d: 4, r10d: 4, r11d: 4, r12d: 4, r13d: 4, r14d: 4, r15d: 4,
  ax: 2, bx: 2, cx: 2, dx: 2, si: 2, di: 2, bp: 2, sp: 2,
  r8w: 2, r9w: 2, r10w: 2, r11w: 2, r12w: 2, r13w: 2, r14w: 2, r15w: 2,
  al: 1, bl: 1, cl: 1, dl: 1, ah: 1, bh: 1, ch: 1, dh: 1,
  sil: 1, dil: 1, bpl: 1, spl: 1,
  r8b: 1, r9b: 1, r10b: 1, r11b: 1, r12b: 1, r13b: 1, r14b: 1, r15b: 1,
};

export function regSize(name: string): number {
  return REG_SIZES[name.toLowerCase()] ?? 4;
}

/** Canonical 64-bit parent of any x86 register (e.g. al→rax, r8d→r8) */
export function canonReg(name: string): string {
  const lower = name.toLowerCase();
  // rNb/rNw/rNd → rN
  const rN = lower.match(/^(r\d+)[bwd]$/);
  if (rN) return rN[1];
  // 8-bit / 16-bit / 32-bit → 64-bit
  const map: Record<string, string> = {
    al: 'rax', ah: 'rax', ax: 'rax', eax: 'rax',
    bl: 'rbx', bh: 'rbx', bx: 'rbx', ebx: 'rbx',
    cl: 'rcx', ch: 'rcx', cx: 'rcx', ecx: 'rcx',
    dl: 'rdx', dh: 'rdx', dx: 'rdx', edx: 'rdx',
    sil: 'rsi', si: 'rsi', esi: 'rsi',
    dil: 'rdi', di: 'rdi', edi: 'rdi',
    bpl: 'rbp', bp: 'rbp', ebp: 'rbp',
    spl: 'rsp', sp: 'rsp', esp: 'rsp',
  };
  return map[lower] ?? lower;
}
