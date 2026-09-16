// Leaf module: the pure decisions behind "Rename var_20…" in the Low Level
// panel, so `DecompileView.dom.test.tsx` can pin the render and this file's
// test can pin the rules without a DOM. Imports `disasm/decompile/userNames.ts`
// (itself a leaf over `ir.ts`) and nothing else — the rule for what a user may
// call a variable has ONE declaration, and it is over there because the
// pipeline reads it too (peek-a-bin-5b6q.7).

import {
  type RenameableIdentClass,
  renameableIdentClass,
  validateVarName,
} from "../disasm/decompile/userNames";

export type { RenameableIdentClass };
export { renameableIdentClass, validateVarName };

/**
 * The annotation KEY for a token on screen.
 *
 * THE ON-SCREEN TOKEN IS THE NEW NAME, THE KEY IS THE ORIGINAL. Once `var_20`
 * has been renamed `count`, the panel prints `count`, and a right-click on it
 * has to reach the entry stored under `var_20` — so this is a reverse lookup
 * over the function's own record (tens of entries at most). A token no entry
 * maps to is its own key, which is what makes `renameableIdentClass(identKeyFor(…))`
 * the one question the menu asks: a fresh `var_20` and a renamed `count` both
 * answer `"var"`, a register or an `__unrecovered_N` answers null.
 *
 * Two entries cannot share a new name — the reducer replaces per key, and
 * `validateVarName` refuses a name the function already binds — so the first
 * hit is the only hit.
 */
export function identKeyFor(
  displayed: string,
  varRenames: Readonly<Record<string, string>> | undefined,
): string {
  if (varRenames) {
    for (const [orig, renamed] of Object.entries(varRenames)) {
      if (renamed === displayed) return orig;
    }
  }
  return displayed;
}

/** `    <type> <name>;` — a local, register, split-repair or capture declaration. */
const DECLARATION_LINE = /^ {4}(?:[A-Za-z_][\w ]*?[\s*]+)([A-Za-z_]\w*)(?:\[[^\]]*\])?;/;
/** `extern <type> <name>;` — the header's extern block. */
const EXTERN_LINE = /^extern\s+(?:[A-Za-z_][\w ]*?[\s*]+)([A-Za-z_]\w*)(?:\[\])?;/;
/** The function header: `<ret> <name>(<type> <p1>, <type> <p2>) {`. */
const HEADER_LINE = /^[A-Za-z_][\w *]*?\s\*?([A-Za-z_]\w*)\((.*)\) \{$/;
/** `typedef struct struct_N struct_N;` / `struct struct_N {` — the typedef names. */
const TYPEDEF_LINE = /^(?:typedef struct \w+ |struct )(\w+)/;

/**
 * Every identifier the emitted C already binds, read off its declaration
 * lines: the header's parameters and its own name, the declaration block
 * (locals, registers, split repairs, captures, `__unrecovered_N`), the extern
 * block and the struct typedefs.
 *
 * FROM THE TEXT, NOT FROM A PROP. The emitter's declaration block is the one
 * place every bound name is spelled, and it is on screen; a `declaredNames`
 * prop would be a second channel that has to be kept equal to the text it
 * describes. The pipeline's `applyUserNames` asks the same `validateVarName`
 * of the IR's own names, so a candidate this refuses is one that would have
 * been skipped over there too — the difference is that the user is TOLD here.
 *
 * Reads the lines up to and including the header, and then only until the
 * first blank line after it, which is where the emitter ends the declaration
 * block; the body is not scanned, so a body identifier that is not declared
 * (a callee name, an enum member) is not a collision by this rule.
 */
export function declaredNamesOf(code: string): Set<string> {
  const out = new Set<string>();
  const lines = code.split("\n");
  let i = 0;
  for (; i < lines.length; i++) {
    const line = lines[i];
    const ext = EXTERN_LINE.exec(line);
    if (ext) {
      out.add(ext[1]);
      continue;
    }
    const td = TYPEDEF_LINE.exec(line);
    if (td) {
      out.add(td[1]);
      continue;
    }
    const header = HEADER_LINE.exec(line);
    if (header) {
      out.add(header[1]);
      for (const param of header[2].split(",")) {
        const m = /([A-Za-z_]\w*)\s*$/.exec(param.trim());
        if (m) out.add(m[1]);
      }
      i++;
      break;
    }
  }
  for (; i < lines.length && lines[i] !== ""; i++) {
    const decl = DECLARATION_LINE.exec(lines[i]);
    if (decl) out.add(decl[1]);
  }
  return out;
}
