/**
 * Export-path confinement for the `export_analysis` tool.
 *
 * The MCP server writes files on behalf of a model, so `outputPath` is
 * attacker-influenced input. Every case here asserts the OUTCOME — that no file
 * appears outside the export root — not merely that an error string came back.
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  symlinkSync,
} from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { captureTools, stubSession, textOf, type ToolHandler } from './harness';

let root: string;
let outside: string;
let sibling: string;
let exportAnalysis: ToolHandler;
const savedExportDir = process.env.PEEK_A_BIN_EXPORT_DIR;

beforeEach(() => {
  // realpathSync: /tmp is a symlink on some platforms, and the confinement check
  // compares against the resolved root.
  root = realpathSync(mkdtempSync(join(tmpdir(), 'peek-export-root-')));
  outside = realpathSync(mkdtempSync(join(tmpdir(), 'peek-export-outside-')));
  // Shares a string prefix with `root`, so a naive startsWith() would admit it.
  sibling = `${root}-sibling`;
  mkdirSync(sibling, { recursive: true });

  process.env.PEEK_A_BIN_EXPORT_DIR = root;

  const { session } = stubSession({
    fileName: 'sample.exe',
    renames: { '4198400': 'main' },
    comments: { '4198400': 'entry' },
    bookmarks: [{ address: 0x401000, label: 'start' }],
  });
  exportAnalysis = captureTools(session).get('export_analysis')!;
});

afterEach(() => {
  if (savedExportDir === undefined) delete process.env.PEEK_A_BIN_EXPORT_DIR;
  else process.env.PEEK_A_BIN_EXPORT_DIR = savedExportDir;
  for (const dir of [root, outside, sibling]) rmSync(dir, { recursive: true, force: true });
});

describe('export_analysis path confinement — accepted', () => {
  it('writes a .json file inside the export root', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'analysis.json' });

    expect(result.isError).toBeUndefined();
    const target = join(root, 'analysis.json');
    expect(existsSync(target)).toBe(true);
    const written = JSON.parse(readFileSync(target, 'utf-8'));
    expect(written.version).toBe(1);
    expect(written.renames).toEqual({ '4198400': 'main' });
  });

  it('writes into an existing subdirectory of the export root', async () => {
    mkdirSync(join(root, 'reports'));
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'reports/out.json' });

    expect(result.isError).toBeUndefined();
    expect(existsSync(join(root, 'reports', 'out.json'))).toBe(true);
  });

  it('accepts an absolute path that lands inside the export root', async () => {
    const target = join(root, 'absolute.json');
    const result = await exportAnalysis({ fileId: 'sample', outputPath: target });

    expect(result.isError).toBeUndefined();
    expect(existsSync(target)).toBe(true);
  });

  it('returns the payload without touching disk when outputPath is omitted', async () => {
    const result = await exportAnalysis({ fileId: 'sample' });

    expect(result.isError).toBeUndefined();
    expect(JSON.parse(textOf(result)).version).toBe(1);
    expect(existsSync(join(root, 'sample.exe.json'))).toBe(false);
  });
});

describe('export_analysis path confinement — rejected', () => {
  it('rejects ../ traversal and creates nothing outside the root', async () => {
    const escaped = resolve(dirname(root), 'escaped.json');
    expect(existsSync(escaped)).toBe(false);

    const result = await exportAnalysis({ fileId: 'sample', outputPath: '../escaped.json' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/escapes the allowed export directory/);
    expect(existsSync(escaped)).toBe(false);
  });

  it('rejects deep ../../ traversal', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: '../../../../etc/peek.json' });

    expect(result.isError).toBe(true);
    expect(existsSync('/etc/peek.json')).toBe(false);
  });

  it('rejects an absolute path outside the root', async () => {
    const target = join(outside, 'stolen.json');
    const result = await exportAnalysis({ fileId: 'sample', outputPath: target });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/escapes the allowed export directory/);
    expect(existsSync(target)).toBe(false);
  });

  it('rejects a sibling directory that merely shares the root name prefix', async () => {
    // `${root}-sibling` startsWith(root); only a separator-aware check rejects it.
    const target = join(sibling, 'prefix.json');
    const result = await exportAnalysis({ fileId: 'sample', outputPath: target });

    expect(result.isError).toBe(true);
    expect(existsSync(target)).toBe(false);
  });

  it('rejects a symlinked directory inside the root that points outside it', async () => {
    symlinkSync(outside, join(root, 'link'), 'dir');
    const realTarget = join(outside, 'via-symlink.json');

    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'link/via-symlink.json' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/escapes the allowed export directory/);
    expect(existsSync(realTarget)).toBe(false);
  });

  // Regression: resolveExportPath used to realpath only the PARENT directory, so a
  // symlinked FILE pre-planted inside the export root redirected writeFileSync out
  // of the root while the tool reported success. Confirmed end-to-end against the
  // real MCP server before the lstat check was added.
  it('rejects a symlinked FILE inside the root that points outside it', async () => {
    const realTarget = join(outside, 'target.json');
    symlinkSync(realTarget, join(root, 'out.json'));

    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'out.json' });

    expect(result.isError).toBe(true);
    expect(existsSync(realTarget)).toBe(false);
  });

  it('rejects a non-.json extension without writing', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'analysis.txt' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/must end in \.json/);
    expect(existsSync(join(root, 'analysis.txt'))).toBe(false);
  });

  it('rejects an extensionless path', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'analysis' });

    expect(result.isError).toBe(true);
    expect(existsSync(join(root, 'analysis'))).toBe(false);
  });

  it('rejects a .json suffix that is only part of the filename', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'analysis.json.sh' });

    expect(result.isError).toBe(true);
    expect(existsSync(join(root, 'analysis.json.sh'))).toBe(false);
  });

  it('accepts .JSON case-insensitively', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'Analysis.JSON' });

    expect(result.isError).toBeUndefined();
    expect(existsSync(join(root, 'Analysis.JSON'))).toBe(true);
  });

  it('rejects a directory that does not exist rather than creating it', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'missing/out.json' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/output directory does not exist/);
    expect(existsSync(join(root, 'missing'))).toBe(false);
  });

  it('does not leak the analysis payload on a rejected path', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: '../escaped.json' });
    expect(textOf(result)).not.toMatch(/"version"/);
  });

  it('errors when the configured export root does not exist', async () => {
    process.env.PEEK_A_BIN_EXPORT_DIR = join(outside, 'no-such-dir');
    const result = await exportAnalysis({ fileId: 'sample', outputPath: 'out.json' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/export root does not exist/);
  });
});

describe('export_analysis default export root', () => {
  it('falls back to cwd and still rejects paths outside it', async () => {
    delete process.env.PEEK_A_BIN_EXPORT_DIR;
    const target = join(outside, 'cwd-escape.json');

    const result = await exportAnalysis({ fileId: 'sample', outputPath: target });

    expect(result.isError).toBe(true);
    expect(existsSync(target)).toBe(false);
  });

  it('names the resolved root in the error so the caller can fix it', async () => {
    const result = await exportAnalysis({ fileId: 'sample', outputPath: join(outside, 'x.json') });
    expect(textOf(result)).toContain(root);
  });
});

describe('export_analysis unknown file', () => {
  it('reports a not-loaded file before touching the path logic', async () => {
    const result = await exportAnalysis({ fileId: 'nope', outputPath: '../escaped.json' });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/not loaded/);
    expect(existsSync(resolve(dirname(root), 'escaped.json'))).toBe(false);
  });
});

describe('export_analysis payload', () => {
  it('serializes bookmarks, renames, comments and functions', async () => {
    const { session } = stubSession({
      fileName: 'payload.exe',
      renames: { '4096': 'renamed' },
      comments: { '4096': 'note' },
      bookmarks: [{ address: 0x1000, label: 'bm' }],
      functions: [{ address: 0x1000, name: 'sub_1000', size: 32 }] as never,
    });
    const handler = captureTools(session).get('export_analysis')!;

    const payload = JSON.parse(textOf(await handler({ fileId: 'sample' })));

    expect(payload.fileName).toBe('payload.exe');
    expect(payload.bookmarks).toEqual([{ address: 0x1000, label: 'bm' }]);
    expect(payload.comments).toEqual({ '4096': 'note' });
    // The rename wins over the detected name in the functions table.
    expect(payload.functions).toEqual([{ address: 0x1000, name: 'renamed', size: 32 }]);
    expect(payload.hexPatches).toEqual([]);
  });
});
