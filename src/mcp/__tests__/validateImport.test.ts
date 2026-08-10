/**
 * `validateImport` — the ExportSchemaV1 gate.
 *
 * It sits in src/utils/exportSchema.ts but its untrusted-input caller is the MCP
 * `import_analysis` tool, which parses an arbitrary JSON file off disk and
 * merges the result straight into session state. Covered here both directly and
 * through that tool.
 *
 * (Its sibling `validateAnnotations` is covered in
 * src/utils/__tests__/exportSchema.test.ts — not duplicated here.)
 */

import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { validateImport, type ExportSchemaV1 } from '../../utils/exportSchema';
import { captureTools, stubSession, textOf } from './harness';

const valid: ExportSchemaV1 = {
  version: 1,
  fileName: 'sample.exe',
  exportedAt: '2026-01-01T00:00:00.000Z',
  bookmarks: [{ address: 0x401000, label: 'entry' }],
  renames: { '4198400': 'main' },
  comments: { '4198400': 'entry point' },
  hexPatches: [[0x200, 0x90]],
};

/** `valid` with one field replaced. */
function withField(field: string, value: unknown): Record<string, unknown> {
  return { ...structuredClone(valid), [field]: value } as Record<string, unknown>;
}

describe('validateImport — accepted', () => {
  it('returns the payload for a well-formed v1 document', () => {
    const result = validateImport(structuredClone(valid));
    expect(result).not.toBeNull();
    expect(result?.fileName).toBe('sample.exe');
    expect(result?.bookmarks).toEqual([{ address: 0x401000, label: 'entry' }]);
  });

  it('accepts empty collections', () => {
    const result = validateImport({
      version: 1,
      fileName: '',
      exportedAt: '',
      bookmarks: [],
      renames: {},
      comments: {},
      hexPatches: [],
    });
    expect(result).not.toBeNull();
  });

  it('accepts an optional functions table', () => {
    const result = validateImport(
      withField('functions', [{ address: 0x1000, name: 'sub_1000', size: 16 }]),
    );
    expect(result?.functions).toEqual([{ address: 0x1000, name: 'sub_1000', size: 16 }]);
  });

  it('accepts an explicitly undefined functions field', () => {
    expect(validateImport(withField('functions', undefined))).not.toBeNull();
  });

  it('accepts hexPatch byte values at both ends of the 0-255 range', () => {
    expect(validateImport(withField('hexPatches', [[0, 0], [1, 255]]))).not.toBeNull();
  });
});

describe('validateImport — rejected', () => {
  it.each([
    ['a non-object', 'nope'],
    ['null', null],
    ['an array', []],
    ['a missing version', { fileName: 'a', exportedAt: 'b', bookmarks: [], renames: {}, comments: {}, hexPatches: [] }],
  ])('rejects %s', (_label, input) => {
    expect(validateImport(input)).toBeNull();
  });

  it('rejects the legacy pre-version format instead of half-importing it', () => {
    // Legacy blobs have bookmarks but no version field; accepting them would
    // apply a schema this code no longer understands.
    expect(validateImport({ bookmarks: [{ address: 1, label: 'x' }] })).toBeNull();
  });

  it.each([
    ['version 2', 'version', 2],
    ['a string version', 'version', '1'],
    ['a non-string fileName', 'fileName', 42],
    ['a non-string exportedAt', 'exportedAt', 0],
    ['bookmarks as an object', 'bookmarks', { address: 1 }],
    ['renames as null', 'renames', null],
    ['comments as null', 'comments', null],
    ['hexPatches as an object', 'hexPatches', {}],
  ])('rejects %s', (_label, field, value) => {
    expect(validateImport(withField(field, value))).toBeNull();
  });

  it.each([
    ['a bookmark without an address', [{ label: 'x' }]],
    ['a bookmark with a string address', [{ address: '0x1000', label: 'x' }]],
    ['a bookmark with a non-string label', [{ address: 1, label: 2 }]],
    ['a null bookmark', [null]],
  ])('rejects %s', (_label, bookmarks) => {
    expect(validateImport(withField('bookmarks', bookmarks))).toBeNull();
  });

  it.each([
    ['a 1-element patch', [[1]]],
    ['a 3-element patch', [[1, 2, 3]]],
    ['a non-array patch', [{ offset: 1, value: 2 }]],
    ['a string patch value', [[1, '90']]],
    ['a byte value above 255', [[1, 256]]],
    ['a negative byte value', [[1, -1]]],
  ])('rejects %s', (_label, hexPatches) => {
    expect(validateImport(withField('hexPatches', hexPatches))).toBeNull();
  });

  it.each([
    ['functions as an object', { a: 1 }],
    ['a function with a string address', [{ address: '1', name: 'f', size: 1 }]],
    ['a function without a name', [{ address: 1, size: 1 }]],
    ['a function without a size', [{ address: 1, name: 'f' }]],
    ['a null function', [null]],
  ])('rejects %s', (_label, functions) => {
    expect(validateImport(withField('functions', functions))).toBeNull();
  });
});

describe('import_analysis tool', () => {
  let dir: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'peek-import-'));
  });

  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  /** Write `body` to a temp file and return its path. */
  function fileWith(body: string): string {
    const path = join(dir, 'annotations.json');
    writeFileSync(path, body, 'utf-8');
    return path;
  }

  it('merges renames, comments and bookmarks into the loaded file', async () => {
    const { session, file, calls } = stubSession({
      renames: { '1': 'existing' },
      comments: {},
      bookmarks: [],
    });
    const handler = captureTools(session).get('import_analysis')!;

    const result = await handler({
      fileId: 'sample',
      inputPath: fileWith(JSON.stringify(valid)),
    });

    expect(result.isError).toBeUndefined();
    expect(JSON.parse(textOf(result)).imported).toEqual({ comments: 1, renames: 1, bookmarks: 1 });
    expect(file.renames).toEqual({ '1': 'existing', '4198400': 'main' });
    expect(file.comments).toEqual({ '4198400': 'entry point' });
    expect(file.bookmarks).toEqual([{ address: 0x401000, label: 'entry' }]);
    expect(calls.annotationChanges).toEqual(['sample']);
  });

  it('lets the imported rename override an existing one at the same address', async () => {
    const { session, file } = stubSession({ renames: { '4198400': 'old_name' } });
    const handler = captureTools(session).get('import_analysis')!;

    await handler({ fileId: 'sample', inputPath: fileWith(JSON.stringify(valid)) });
    expect(file.renames['4198400']).toBe('main');
  });

  it('does not duplicate a bookmark that is already at that address', async () => {
    const { session, file } = stubSession({ bookmarks: [{ address: 0x401000, label: 'kept' }] });
    const handler = captureTools(session).get('import_analysis')!;

    await handler({ fileId: 'sample', inputPath: fileWith(JSON.stringify(valid)) });
    expect(file.bookmarks).toEqual([{ address: 0x401000, label: 'kept' }]);
  });

  it('rejects an invalid document without mutating session state', async () => {
    const { session, file, calls } = stubSession();
    const handler = captureTools(session).get('import_analysis')!;

    const result = await handler({
      fileId: 'sample',
      inputPath: fileWith(JSON.stringify({ version: 2, evil: true })),
    });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/invalid ExportSchemaV1/);
    expect(file.renames).toEqual({});
    expect(file.comments).toEqual({});
    expect(file.bookmarks).toEqual([]);
    expect(calls.annotationChanges).toEqual([]);
  });

  it('reports unparseable JSON instead of throwing', async () => {
    const { session } = stubSession();
    const handler = captureTools(session).get('import_analysis')!;

    const result = await handler({ fileId: 'sample', inputPath: fileWith('{ not json') });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/failed to read\/parse/);
  });

  it('reports a missing input file instead of throwing', async () => {
    const { session } = stubSession();
    const handler = captureTools(session).get('import_analysis')!;

    const result = await handler({ fileId: 'sample', inputPath: join(dir, 'absent.json') });

    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/failed to read\/parse/);
  });
});
