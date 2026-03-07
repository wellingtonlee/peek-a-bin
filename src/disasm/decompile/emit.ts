import type { IRExpr, IRStmt, IRFunction, BinaryOp } from './ir';
import { canonReg } from './ir';
import { isPlausibleIOCTL, formatIOCTL } from '../../analysis/driver';
import type { StructDef } from './structs';
import type { TypeContext, DecompType } from './typeInfer';
import { typeToString } from './typeInfer';

// ── Expression Emission ──

const PREC: Record<string, number> = {
  '||': 1, '&&': 2,
  '|': 3, '^': 4, '&': 5,
  '==': 6, '!=': 6,
  '<': 7, '<=': 7, '>': 7, '>=': 7,
  'u<': 7, 'u<=': 7, 'u>': 7, 'u>=': 7,
  '<<': 8, '>>': 8, '>>>': 8,
  '+': 9, '-': 9,
  '*': 10, '/': 10, '%': 10,
};

function opStr(op: BinaryOp): string {
  switch (op) {
    case 'u<': return '<';
    case 'u<=': return '<=';
    case 'u>': return '>';
    case 'u>=': return '>=';
    case '&&': return '&&';
    case '||': return '||';
    default: return op;
  }
}

function sizeToType(size: number): string {
  switch (size) {
    case 1: return 'uint8_t';
    case 2: return 'uint16_t';
    case 4: return 'int32_t';
    case 8: return 'int64_t';
    default: return 'int32_t';
  }
}

function formatHex(value: number): string {
  if (value >= 0 && value <= 9) return String(value);
  if (value < 0) return '-' + formatHex(-value);
  return '0x' + value.toString(16).toUpperCase();
}

const COMPOUND_OPS = new Set<string>(['+', '-', '*', '/', '%', '&', '|', '^', '<<', '>>', '>>>']);

let _typeCtx: TypeContext | undefined;

function getExprType(expr: IRExpr): DecompType | undefined {
  if (!_typeCtx) return undefined;
  if (expr.kind === 'reg') return _typeCtx.types.get(canonReg(expr.name));
  if (expr.kind === 'var') return _typeCtx.types.get(expr.name);
  return undefined;
}

function emitTypeIdiom(expr: IRExpr & { kind: 'binary' }): string | null {
  const leftType = getExprType(expr.left);

  // HANDLE: x == 0xFFFFFFFF → x == INVALID_HANDLE_VALUE
  if (leftType?.kind === 'handle' && expr.op === '==' &&
      expr.right.kind === 'const' && (expr.right.value === 0xFFFFFFFF || expr.right.value === -1)) {
    return `${emitExpr(expr.left, 0)} == INVALID_HANDLE_VALUE`;
  }
  if (leftType?.kind === 'handle' && expr.op === '!=' &&
      expr.right.kind === 'const' && (expr.right.value === 0xFFFFFFFF || expr.right.value === -1)) {
    return `${emitExpr(expr.left, 0)} != INVALID_HANDLE_VALUE`;
  }

  // NTSTATUS: x >= 0 → NT_SUCCESS(x), x < 0 → !NT_SUCCESS(x)
  if (leftType?.kind === 'ntstatus' && expr.right.kind === 'const' && expr.right.value === 0) {
    if (expr.op === '>=' || expr.op === 'u>=') return `NT_SUCCESS(${emitExpr(expr.left, 0)})`;
    if (expr.op === '<') return `!NT_SUCCESS(${emitExpr(expr.left, 0)})`;
  }

  // HRESULT: x >= 0 → SUCCEEDED(x), x < 0 → FAILED(x)
  if (leftType?.kind === 'hresult' && expr.right.kind === 'const' && expr.right.value === 0) {
    if (expr.op === '>=' || expr.op === 'u>=') return `SUCCEEDED(${emitExpr(expr.left, 0)})`;
    if (expr.op === '<') return `FAILED(${emitExpr(expr.left, 0)})`;
  }

  return null;
}

function emitExpr(expr: IRExpr, parentPrec = 0): string {
  switch (expr.kind) {
    case 'const': {
      const hex = formatHex(expr.value);
      if (isPlausibleIOCTL(expr.value)) {
        const ioctlComment = formatIOCTL(expr.value);
        if (ioctlComment) return `${hex} /* ${ioctlComment} */`;
      }
      // Enum member lookup
      if (_typeCtx) {
        for (const [, t] of _typeCtx.types) {
          if (t.kind === 'enum') {
            const memberName = t.members.get(expr.value);
            if (memberName) return memberName;
          }
        }
      }
      return hex;
    }

    case 'reg':
      return expr.name;

    case 'var':
      return expr.name;

    case 'binary': {
      // Type-aware idioms
      if (_typeCtx) {
        const idiom = emitTypeIdiom(expr);
        if (idiom) return parentPrec > 0 ? `(${idiom})` : idiom;
      }
      const prec = PREC[expr.op] ?? 0;
      const left = emitExpr(expr.left, prec);
      const right = emitExpr(expr.right, prec + 1);
      const result = `${left} ${opStr(expr.op)} ${right}`;
      return prec < parentPrec ? `(${result})` : result;
    }

    case 'unary': {
      const operand = emitExpr(expr.operand, 99);
      return `${expr.op}${operand}`;
    }

    case 'deref': {
      const type = sizeToType(expr.size);
      const addr = emitExpr(expr.address, 0);
      return `*(${type}*)(${addr})`;
    }

    case 'field_access':
      return `${emitExpr(expr.base)}->${expr.fieldName}`;

    case 'array_access': {
      const type = sizeToType(expr.elementSize);
      const base = emitExpr(expr.base, 0);
      const index = emitExpr(expr.index, 0);
      // If base is a field_access, use -> syntax: base->field[index]
      if (expr.base.kind === 'field_access') {
        return `${emitExpr(expr.base)}[${index}]`;
      }
      return `((${type}*)${base})[${index}]`;
    }

    case 'call': {
      const name = expr.display?.split('!')?.pop() ?? expr.target;
      const args = expr.args.map(a => emitExpr(a, 0)).join(', ');
      return `${name}(${args})`;
    }

    case 'cast': {
      // Redundant cast suppression: skip cast when operand's known type matches
      if (_typeCtx && (expr.operand.kind === 'reg' || expr.operand.kind === 'var')) {
        const name = expr.operand.kind === 'reg' ? expr.operand.name : expr.operand.name;
        const known = _typeCtx.types.get(name);
        if (known && known.kind !== 'unknown') {
          const knownStr = typeToString(known);
          if (knownStr === expr.type) return emitExpr(expr.operand, parentPrec);
        }
      }
      return `(${expr.type})${emitExpr(expr.operand, 99)}`;
    }

    case 'ternary': {
      const cond = emitExpr(expr.condition, 0);
      const then = emitExpr(expr.then, 0);
      const els = emitExpr(expr.else, 0);
      const result = `${cond} ? ${then} : ${els}`;
      return parentPrec > 0 ? `(${result})` : result;
    }

    case 'unknown':
      return `/* ${expr.text} */`;
  }
}

// ── Statement Emission ──

function indent(level: number): string {
  return '    '.repeat(level);
}

/** Get the instruction address from a statement, if present */
function stmtAddr(stmt: IRStmt): number | undefined {
  switch (stmt.kind) {
    case 'assign': return stmt.addr;
    case 'store': return stmt.addr;
    case 'call_stmt': return stmt.addr;
    case 'return': return stmt.addr;
    case 'raw': return stmt.addr;
    default: return undefined;
  }
}

interface EmitResult {
  lines: string[];
  addrs: (number | undefined)[];
}

function emitStmt(stmt: IRStmt, level: number): EmitResult {
  const pad = indent(level);
  const lines: string[] = [];
  const addrs: (number | undefined)[] = [];
  const addr = stmtAddr(stmt);

  function push(line: string, lineAddr?: number | undefined) {
    lines.push(line);
    addrs.push(lineAddr);
  }

  switch (stmt.kind) {
    case 'assign': {
      const dest = emitExpr(stmt.dest, 0);
      const src = emitExpr(stmt.src, 0);
      // Compound assignment: dest = dest OP rhs → dest OP= rhs
      if (stmt.src.kind === 'binary' && COMPOUND_OPS.has(stmt.src.op)) {
        const lhs = emitExpr(stmt.src.left, 0);
        if (lhs === dest) {
          const rhs = emitExpr(stmt.src.right, 0);
          // Increment/decrement: x += 1 → x++, x -= 1 → x--
          if (stmt.src.right.kind === 'const' && stmt.src.right.value === 1) {
            if (stmt.src.op === '+') { push(`${pad}${dest}++;`, addr); break; }
            if (stmt.src.op === '-') { push(`${pad}${dest}--;`, addr); break; }
          }
          push(`${pad}${dest} ${opStr(stmt.src.op)}= ${rhs};`, addr);
          break;
        }
      }
      push(`${pad}${dest} = ${src};`, addr);
      break;
    }

    case 'store': {
      const type = sizeToType(stmt.size);
      const addrStr = emitExpr(stmt.address, 0);
      const storeTarget = `*(${type}*)(${addrStr})`;
      // Compound assignment for regular stores
      if (stmt.value.kind === 'binary' && COMPOUND_OPS.has(stmt.value.op)) {
        const lhs = emitExpr(stmt.value.left, 0);
        if (lhs === storeTarget) {
          const rhs = emitExpr(stmt.value.right, 0);
          push(`${pad}${storeTarget} ${opStr(stmt.value.op)}= ${rhs};`, addr);
          break;
        }
      }
      const val = emitExpr(stmt.value, 0);
      push(`${pad}${storeTarget} = ${val};`, addr);
      break;
    }

    case 'call_stmt': {
      const call = emitExpr(stmt.call, 0);
      push(`${pad}${call};`, addr);
      break;
    }

    case 'return': {
      if (stmt.value) {
        const val = emitExpr(stmt.value, 0);
        push(`${pad}return ${val};`, addr);
      } else {
        push(`${pad}return;`, addr);
      }
      break;
    }

    case 'if': {
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}if (${cond}) {`);
      for (const s of stmt.thenBody) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      if (stmt.elseBody && stmt.elseBody.length > 0) {
        // Check for else-if chain
        if (stmt.elseBody.length === 1 && stmt.elseBody[0].kind === 'if') {
          const elseIf = stmt.elseBody[0];
          push(`${pad}} else `);
          // Remove last line's newline context and append if
          const lastIdx = lines.length - 1;
          const elseIfResult = emitStmt(elseIf, level);
          if (elseIfResult.lines.length > 0) {
            lines[lastIdx] = lines[lastIdx] + elseIfResult.lines[0].trimStart();
            addrs[lastIdx] = elseIfResult.addrs[0]; // inherit addr from else-if
            lines.push(...elseIfResult.lines.slice(1));
            addrs.push(...elseIfResult.addrs.slice(1));
          }
        } else {
          push(`${pad}} else {`);
          for (const s of stmt.elseBody) {
            const r = emitStmt(s, level + 1);
            lines.push(...r.lines);
            addrs.push(...r.addrs);
          }
          push(`${pad}}`);
        }
      } else {
        push(`${pad}}`);
      }
      break;
    }

    case 'while': {
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}while (${cond}) {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      push(`${pad}}`);
      break;
    }

    case 'do_while': {
      push(`${pad}do {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}} while (${cond});`);
      break;
    }

    case 'switch': {
      const expr = emitExpr(stmt.expr, 0);
      push(`${pad}switch (${expr}) {`);
      // Check if switch expression has enum type
      let enumType: DecompType | undefined;
      if (_typeCtx) {
        if (stmt.expr.kind === 'reg') enumType = _typeCtx.types.get(canonReg(stmt.expr.name));
        else if (stmt.expr.kind === 'var') enumType = _typeCtx.types.get(stmt.expr.name);
      }
      for (const c of stmt.cases) {
        for (const v of c.values) {
          if (enumType?.kind === 'enum') {
            const memberName = enumType.members.get(v);
            push(`${pad}case ${memberName ?? formatHex(v)}:`);
          } else {
            push(`${pad}case ${formatHex(v)}:`);
          }
        }
        for (const s of c.body) {
          const r = emitStmt(s, level + 2);
          lines.push(...r.lines);
          addrs.push(...r.addrs);
        }
      }
      if (stmt.defaultBody) {
        push(`${pad}default:`);
        for (const s of stmt.defaultBody) {
          const r = emitStmt(s, level + 2);
          lines.push(...r.lines);
          addrs.push(...r.addrs);
        }
      }
      push(`${pad}}`);
      break;
    }

    case 'goto':
      push(`${pad}goto ${stmt.label};`);
      break;

    case 'label':
      push(`${stmt.name}:`);
      break;

    case 'comment':
      push(`${pad}// ${stmt.text}`);
      break;

    case 'raw':
      push(`${pad}${stmt.text};`, addr);
      break;

    case 'for': {
      const initR = emitStmt(stmt.init, 0);
      const initStr = initR.lines[0]?.trim().replace(/;$/, '') ?? '';
      const updateR = emitStmt(stmt.update, 0);
      const updateStr = updateR.lines[0]?.trim().replace(/;$/, '') ?? '';
      const cond = emitExpr(stmt.condition, 0);
      push(`${pad}for (${initStr}; ${cond}; ${updateStr}) {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      push(`${pad}}`);
      break;
    }

    case 'break':
      push(`${pad}break;`);
      break;

    case 'continue':
      push(`${pad}continue;`);
      break;

    case 'try': {
      push(`${pad}__try {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      const filter = stmt.filterExpr ? emitExpr(stmt.filterExpr, 0) : 'EXCEPTION_EXECUTE_HANDLER';
      push(`${pad}} __except(${filter}) {`);
      for (const s of stmt.handler) {
        const r = emitStmt(s, level + 1);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      push(`${pad}}`);
      break;
    }
  }

  return { lines, addrs };
}

// ── Function Emission ──

function fieldTypeString(field: import('./structs').StructField): string {
  return typeToString(field.type);
}

export interface EmitFunctionResult {
  code: string;
  lineMap: Map<number, number>;  // line number (0-based) → instruction address
}

export function emitFunction(func: IRFunction, typeCtx?: TypeContext): EmitFunctionResult {
  _typeCtx = typeCtx;
  const lines: string[] = [];
  const lineAddrs: (number | undefined)[] = [];

  // Emit typedef block for struct definitions
  if (func.typedefs && func.typedefs.length > 0) {
    for (const def of func.typedefs) {
      lines.push(`typedef struct {`);
      lineAddrs.push(undefined);
      for (const field of def.fields) {
        const typeStr = fieldTypeString(field);
        if (field.isArray) {
          lines.push(`    ${typeStr} ${field.name}[];`);
        } else {
          lines.push(`    ${typeStr} ${field.name};`);
        }
        lineAddrs.push(undefined);
      }
      lines.push(`} ${def.id};`);
      lineAddrs.push(undefined);
      lines.push('');
      lineAddrs.push(undefined);
    }
  }

  // Function header
  const params = func.params.map(p => `${p.type} ${p.name}`).join(', ');
  lines.push(`${func.returnType} ${func.name}(${params}) {`);
  lineAddrs.push(undefined);

  // Local variable declarations
  if (func.locals.length > 0) {
    for (const local of func.locals) {
      lines.push(`    ${local.type} ${local.name};`);
      lineAddrs.push(undefined);
    }
    lines.push('');
    lineAddrs.push(undefined);
  }

  // Body
  for (const stmt of func.body) {
    const result = emitStmt(stmt, 1);
    lines.push(...result.lines);
    lineAddrs.push(...result.addrs);
  }

  lines.push('}');
  lineAddrs.push(undefined);

  // Build lineMap
  const lineMap = new Map<number, number>();
  for (let i = 0; i < lineAddrs.length; i++) {
    if (lineAddrs[i] !== undefined) {
      lineMap.set(i, lineAddrs[i]!);
    }
  }

  _typeCtx = undefined;
  return { code: lines.join('\n'), lineMap };
}
