import type { IRExpr, IRStmt, IRFunction, BinaryOp } from './ir';

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

function emitExpr(expr: IRExpr, parentPrec = 0): string {
  switch (expr.kind) {
    case 'const':
      return formatHex(expr.value);

    case 'reg':
      return expr.name;

    case 'var':
      return expr.name;

    case 'binary': {
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

    case 'call': {
      const name = expr.display?.split('!')?.pop() ?? expr.target;
      const args = expr.args.map(a => emitExpr(a, 0)).join(', ');
      return `${name}(${args})`;
    }

    case 'cast':
      return `(${expr.type})${emitExpr(expr.operand, 99)}`;

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

function emitStmt(stmt: IRStmt, level: number): string[] {
  const pad = indent(level);
  const lines: string[] = [];

  switch (stmt.kind) {
    case 'assign': {
      const dest = emitExpr(stmt.dest, 0);
      const src = emitExpr(stmt.src, 0);
      lines.push(`${pad}${dest} = ${src};`);
      break;
    }

    case 'store': {
      const type = sizeToType(stmt.size);
      const addr = emitExpr(stmt.address, 0);
      const val = emitExpr(stmt.value, 0);
      lines.push(`${pad}*(${type}*)(${addr}) = ${val};`);
      break;
    }

    case 'call_stmt': {
      const call = emitExpr(stmt.call, 0);
      if (stmt.resultDest) {
        // Only emit result capture if it's used meaningfully
        // For now, just emit the call
        lines.push(`${pad}${call};`);
      } else {
        lines.push(`${pad}${call};`);
      }
      break;
    }

    case 'return': {
      if (stmt.value) {
        const val = emitExpr(stmt.value, 0);
        lines.push(`${pad}return ${val};`);
      } else {
        lines.push(`${pad}return;`);
      }
      break;
    }

    case 'if': {
      const cond = emitExpr(stmt.condition, 0);
      lines.push(`${pad}if (${cond}) {`);
      for (const s of stmt.thenBody) {
        lines.push(...emitStmt(s, level + 1));
      }
      if (stmt.elseBody && stmt.elseBody.length > 0) {
        // Check for else-if chain
        if (stmt.elseBody.length === 1 && stmt.elseBody[0].kind === 'if') {
          const elseIf = stmt.elseBody[0];
          lines.push(`${pad}} else `);
          // Remove last line's newline context and append if
          const lastIdx = lines.length - 1;
          const elseIfLines = emitStmt(elseIf, level);
          if (elseIfLines.length > 0) {
            lines[lastIdx] = lines[lastIdx] + elseIfLines[0].trimStart();
            lines.push(...elseIfLines.slice(1));
          }
        } else {
          lines.push(`${pad}} else {`);
          for (const s of stmt.elseBody) {
            lines.push(...emitStmt(s, level + 1));
          }
          lines.push(`${pad}}`);
        }
      } else {
        lines.push(`${pad}}`);
      }
      break;
    }

    case 'while': {
      const cond = emitExpr(stmt.condition, 0);
      lines.push(`${pad}while (${cond}) {`);
      for (const s of stmt.body) {
        lines.push(...emitStmt(s, level + 1));
      }
      lines.push(`${pad}}`);
      break;
    }

    case 'do_while': {
      lines.push(`${pad}do {`);
      for (const s of stmt.body) {
        lines.push(...emitStmt(s, level + 1));
      }
      const cond = emitExpr(stmt.condition, 0);
      lines.push(`${pad}} while (${cond});`);
      break;
    }

    case 'switch': {
      const expr = emitExpr(stmt.expr, 0);
      lines.push(`${pad}switch (${expr}) {`);
      for (const c of stmt.cases) {
        for (const v of c.values) {
          lines.push(`${pad}case ${formatHex(v)}:`);
        }
        for (const s of c.body) {
          lines.push(...emitStmt(s, level + 2));
        }
      }
      if (stmt.defaultBody) {
        lines.push(`${pad}default:`);
        for (const s of stmt.defaultBody) {
          lines.push(...emitStmt(s, level + 2));
        }
      }
      lines.push(`${pad}}`);
      break;
    }

    case 'goto':
      lines.push(`${pad}goto ${stmt.label};`);
      break;

    case 'label':
      lines.push(`${stmt.name}:`);
      break;

    case 'comment':
      lines.push(`${pad}// ${stmt.text}`);
      break;

    case 'raw':
      lines.push(`${pad}${stmt.text};`);
      break;

    case 'break':
      lines.push(`${pad}break;`);
      break;
  }

  return lines;
}

// ── Function Emission ──

export function emitFunction(func: IRFunction): string {
  const lines: string[] = [];

  // Function header
  const params = func.params.map(p => `${p.type} ${p.name}`).join(', ');
  lines.push(`${func.returnType} ${func.name}(${params}) {`);

  // Local variable declarations
  if (func.locals.length > 0) {
    for (const local of func.locals) {
      lines.push(`    ${local.type} ${local.name};`);
    }
    lines.push('');
  }

  // Body
  for (const stmt of func.body) {
    lines.push(...emitStmt(stmt, 1));
  }

  lines.push('}');
  return lines.join('\n');
}
