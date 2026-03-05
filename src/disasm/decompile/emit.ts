import type { IRExpr, IRStmt, IRFunction, BinaryOp } from './ir';
import { walkStmts } from './ir';
import { isPlausibleIOCTL, formatIOCTL } from '../../analysis/driver';

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
  // Map unsigned comparisons to readable form
  switch (op) {
    case 'u<': return '<';
    case 'u<=': return '<=';
    case 'u>': return '>';
    case 'u>=': return '>=';
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

/** Collect struct base candidates: names that appear with 2+ distinct offsets in base + const deref patterns. */
function collectStructBases(body: IRStmt[]): Set<string> {
  const offsets = new Map<string, Set<number>>();
  walkStmts(body, (expr) => {
    if (expr.kind === 'deref' && expr.address.kind === 'binary' && expr.address.op === '+' &&
        expr.address.right.kind === 'const') {
      const base = expr.address.left;
      let baseName: string | null = null;
      if (base.kind === 'reg') baseName = base.name;
      else if (base.kind === 'var') baseName = base.name;
      if (baseName) {
        const set = offsets.get(baseName) ?? new Set();
        set.add(expr.address.right.value);
        offsets.set(baseName, set);
      }
    }
  });
  const result = new Set<string>();
  for (const [name, set] of offsets) {
    if (set.size >= 2) result.add(name);
  }
  return result;
}

function emitExpr(expr: IRExpr, parentPrec = 0, structBases?: Set<string>): string {
  switch (expr.kind) {
    case 'const': {
      const hex = formatHex(expr.value);
      if (isPlausibleIOCTL(expr.value)) {
        const ioctlComment = formatIOCTL(expr.value);
        if (ioctlComment) return `${hex} /* ${ioctlComment} */`;
      }
      return hex;
    }

    case 'reg':
      return expr.name;

    case 'var':
      return expr.name;

    case 'binary': {
      const prec = PREC[expr.op] ?? 0;
      const left = emitExpr(expr.left, prec, structBases);
      const right = emitExpr(expr.right, prec + 1, structBases);
      const result = `${left} ${opStr(expr.op)} ${right}`;
      return prec < parentPrec ? `(${result})` : result;
    }

    case 'unary': {
      const operand = emitExpr(expr.operand, 99, structBases);
      return `${expr.op}${operand}`;
    }

    case 'deref': {
      // Struct field access: base->field_0xN
      if (structBases && expr.address.kind === 'binary' && expr.address.op === '+' &&
          expr.address.right.kind === 'const') {
        const base = expr.address.left;
        const baseName = base.kind === 'reg' ? base.name : base.kind === 'var' ? base.name : null;
        if (baseName && structBases.has(baseName)) {
          return `${baseName}->field_0x${expr.address.right.value.toString(16).toUpperCase()}`;
        }
      }
      const type = sizeToType(expr.size);
      const addr = emitExpr(expr.address, 0, structBases);
      return `*(${type}*)(${addr})`;
    }

    case 'call': {
      const name = expr.display?.split('!')?.pop() ?? expr.target;
      const args = expr.args.map(a => emitExpr(a, 0, structBases)).join(', ');
      return `${name}(${args})`;
    }

    case 'cast':
      return `(${expr.type})${emitExpr(expr.operand, 99, structBases)}`;

    case 'ternary': {
      const cond = emitExpr(expr.condition, 0, structBases);
      const then = emitExpr(expr.then, 0, structBases);
      const els = emitExpr(expr.else, 0, structBases);
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

function emitStmt(stmt: IRStmt, level: number, structBases?: Set<string>): EmitResult {
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
      const dest = emitExpr(stmt.dest, 0, structBases);
      const src = emitExpr(stmt.src, 0, structBases);
      // Compound assignment: dest = dest OP rhs → dest OP= rhs
      if (stmt.src.kind === 'binary' && COMPOUND_OPS.has(stmt.src.op)) {
        const lhs = emitExpr(stmt.src.left, 0, structBases);
        if (lhs === dest) {
          const rhs = emitExpr(stmt.src.right, 0, structBases);
          push(`${pad}${dest} ${opStr(stmt.src.op)}= ${rhs};`, addr);
          break;
        }
      }
      push(`${pad}${dest} = ${src};`, addr);
      break;
    }

    case 'store': {
      // Struct field store: base->field_0xN = val
      if (structBases && stmt.address.kind === 'binary' && stmt.address.op === '+' &&
          stmt.address.right.kind === 'const') {
        const base = stmt.address.left;
        const baseName = base.kind === 'reg' ? base.name : base.kind === 'var' ? base.name : null;
        if (baseName && structBases.has(baseName)) {
          const field = `${baseName}->field_0x${stmt.address.right.value.toString(16).toUpperCase()}`;
          // Compound assignment for struct stores
          if (stmt.value.kind === 'binary' && COMPOUND_OPS.has(stmt.value.op)) {
            const derefExpr: IRExpr = { kind: 'deref', address: stmt.address, size: stmt.size };
            const lhs = emitExpr(derefExpr, 0, structBases);
            if (lhs === field) {
              const rhs = emitExpr(stmt.value.right, 0, structBases);
              push(`${pad}${field} ${opStr(stmt.value.op)}= ${rhs};`, addr);
              break;
            }
          }
          const val = emitExpr(stmt.value, 0, structBases);
          push(`${pad}${field} = ${val};`, addr);
          break;
        }
      }
      const type = sizeToType(stmt.size);
      const addrStr = emitExpr(stmt.address, 0, structBases);
      const storeTarget = `*(${type}*)(${addrStr})`;
      // Compound assignment for regular stores
      if (stmt.value.kind === 'binary' && COMPOUND_OPS.has(stmt.value.op)) {
        const lhs = emitExpr(stmt.value.left, 0, structBases);
        if (lhs === storeTarget) {
          const rhs = emitExpr(stmt.value.right, 0, structBases);
          push(`${pad}${storeTarget} ${opStr(stmt.value.op)}= ${rhs};`, addr);
          break;
        }
      }
      const val = emitExpr(stmt.value, 0, structBases);
      push(`${pad}${storeTarget} = ${val};`, addr);
      break;
    }

    case 'call_stmt': {
      const call = emitExpr(stmt.call, 0, structBases);
      push(`${pad}${call};`, addr);
      break;
    }

    case 'return': {
      if (stmt.value) {
        const val = emitExpr(stmt.value, 0, structBases);
        push(`${pad}return ${val};`, addr);
      } else {
        push(`${pad}return;`, addr);
      }
      break;
    }

    case 'if': {
      const cond = emitExpr(stmt.condition, 0, structBases);
      push(`${pad}if (${cond}) {`);
      for (const s of stmt.thenBody) {
        const r = emitStmt(s, level + 1, structBases);
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
          const elseIfResult = emitStmt(elseIf, level, structBases);
          if (elseIfResult.lines.length > 0) {
            lines[lastIdx] = lines[lastIdx] + elseIfResult.lines[0].trimStart();
            addrs[lastIdx] = elseIfResult.addrs[0]; // inherit addr from else-if
            lines.push(...elseIfResult.lines.slice(1));
            addrs.push(...elseIfResult.addrs.slice(1));
          }
        } else {
          push(`${pad}} else {`);
          for (const s of stmt.elseBody) {
            const r = emitStmt(s, level + 1, structBases);
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
      const cond = emitExpr(stmt.condition, 0, structBases);
      push(`${pad}while (${cond}) {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1, structBases);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      push(`${pad}}`);
      break;
    }

    case 'do_while': {
      push(`${pad}do {`);
      for (const s of stmt.body) {
        const r = emitStmt(s, level + 1, structBases);
        lines.push(...r.lines);
        addrs.push(...r.addrs);
      }
      const cond = emitExpr(stmt.condition, 0, structBases);
      push(`${pad}} while (${cond});`);
      break;
    }

    case 'switch': {
      const expr = emitExpr(stmt.expr, 0, structBases);
      push(`${pad}switch (${expr}) {`);
      for (const c of stmt.cases) {
        for (const v of c.values) {
          push(`${pad}case ${formatHex(v)}:`);
        }
        for (const s of c.body) {
          const r = emitStmt(s, level + 2, structBases);
          lines.push(...r.lines);
          addrs.push(...r.addrs);
        }
      }
      if (stmt.defaultBody) {
        push(`${pad}default:`);
        for (const s of stmt.defaultBody) {
          const r = emitStmt(s, level + 2, structBases);
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

    case 'break':
      push(`${pad}break;`);
      break;
  }

  return { lines, addrs };
}

// ── Function Emission ──

export interface EmitFunctionResult {
  code: string;
  lineMap: Map<number, number>;  // line number (0-based) → instruction address
}

export function emitFunction(func: IRFunction): EmitFunctionResult {
  const lines: string[] = [];
  const lineAddrs: (number | undefined)[] = [];

  // Collect struct base candidates before emission
  const structBases = collectStructBases(func.body);

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
    const result = emitStmt(stmt, 1, structBases);
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

  return { code: lines.join('\n'), lineMap };
}
