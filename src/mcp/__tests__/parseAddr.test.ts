/**
 * Address argument parsing for the MCP tools.
 *
 * `parseAddr` is module-private, so it is driven through the handlers that use
 * it. Rejection tests assert the OUTCOME — that no annotation was recorded —
 * rather than only the error text, since the pre-hardening failure mode was a
 * successfully applied annotation at a NaN address.
 */

import { describe, it, expect } from 'vitest';
import type { Xref } from '../../disasm/types';
import { captureTools, stubSession, textOf } from './harness';

/** A session whose xref map has a single entry, keyed by `address`. */
function sessionWithXrefAt(address: number) {
  const xrefs: Xref[] = [{ from: 0x401234, type: 'call' }];
  return stubSession({ xrefMap: new Map([[address, xrefs]]) });
}

describe('parseAddr — accepted forms', () => {
  it('accepts a 0x-prefixed hex string', async () => {
    const { session } = sessionWithXrefAt(0x1234);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: '0x1234' })));
    expect(result.address).toBe('0x1234');
    expect(result.xrefCount).toBe(1);
  });

  it('accepts bare hex without the 0x prefix', async () => {
    const { session } = sessionWithXrefAt(0xdeadbe);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: 'deadbe' })));
    expect(result.address).toBe('0xdeadbe');
    expect(result.xrefCount).toBe(1);
  });

  it('accepts uppercase hex', async () => {
    const { session } = sessionWithXrefAt(0xabcdef);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: '0xABCDEF' })));
    expect(result.xrefCount).toBe(1);
  });

  it('tolerates surrounding whitespace', async () => {
    const { session } = sessionWithXrefAt(0x1000);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: '  0x1000  ' })));
    expect(result.xrefCount).toBe(1);
  });

  it('takes a number through unchanged', async () => {
    const { session } = sessionWithXrefAt(4096);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: 4096 })));
    expect(result.address).toBe('0x1000');
    expect(result.xrefCount).toBe(1);
  });

  it('accepts zero rather than treating it as falsy', async () => {
    const { session } = sessionWithXrefAt(0);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: 0 })));
    expect(result.address).toBe('0x0');
    expect(result.xrefCount).toBe(1);
  });

  it('reads a digits-only string as HEX, not decimal', async () => {
    // "10" is 0x10 == 16. Documented behaviour: every address argument is hex.
    const { session } = sessionWithXrefAt(16);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: '10' })));
    expect(result.address).toBe('0x10');
    expect(result.xrefCount).toBe(1);
  });

  it('stops at the first non-hex character instead of rejecting (parseInt semantics)', async () => {
    const { session } = sessionWithXrefAt(0x10);
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = JSON.parse(textOf(await getXrefs({ fileId: 'sample', address: '0x10zzz' })));
    expect(result.address).toBe('0x10');
  });
});

describe('parseAddr — rejected forms', () => {
  const bad: [string, unknown][] = [
    ['a non-hex string', 'not-an-address'],
    ['an empty string', ''],
    ['whitespace only', '   '],
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ];

  it.each(bad)('rejects %s in get_xrefs', async (_label, address) => {
    const { session } = stubSession();
    const getXrefs = captureTools(session).get('get_xrefs')!;

    const result = await getXrefs({ fileId: 'sample', address });
    expect(result.isError).toBe(true);
    expect(textOf(result)).toMatch(/invalid address/);
  });

  it.each(bad)('rejects %s in add_comment without recording anything', async (_label, address) => {
    const { session, calls } = stubSession();
    const addComment = captureTools(session).get('add_comment')!;

    const result = await addComment({ fileId: 'sample', address, text: 'hi' });

    expect(result.isError).toBe(true);
    expect(calls.setComment).toEqual([]);
    expect(calls.deleteComment).toEqual([]);
  });

  it.each(bad)('rejects %s in rename_function without recording anything', async (_label, address) => {
    const { session, calls } = stubSession();
    const rename = captureTools(session).get('rename_function')!;

    const result = await rename({ fileId: 'sample', address, name: 'evil' });

    expect(result.isError).toBe(true);
    expect(calls.setRename).toEqual([]);
  });

  it.each(bad)('rejects %s in add_bookmark without recording anything', async (_label, address) => {
    const { session, calls } = stubSession();
    const bookmark = captureTools(session).get('add_bookmark')!;

    const result = await bookmark({ fileId: 'sample', address, label: 'x' });

    expect(result.isError).toBe(true);
    expect(calls.addBookmark).toEqual([]);
    expect(calls.removeBookmark).toEqual([]);
  });
});

describe('annotation tools — accepted addresses reach the session', () => {
  it('records a comment at the parsed address', async () => {
    const { session, calls } = stubSession();
    const addComment = captureTools(session).get('add_comment')!;

    await addComment({ fileId: 'sample', address: '0x401000', text: 'entry' });
    expect(calls.setComment).toEqual([['sample', 0x401000, 'entry']]);
  });

  it('treats an empty comment as a delete', async () => {
    const { session, calls } = stubSession();
    const addComment = captureTools(session).get('add_comment')!;

    await addComment({ fileId: 'sample', address: '0x401000', text: '' });
    expect(calls.setComment).toEqual([]);
    expect(calls.deleteComment).toEqual([['sample', 0x401000]]);
  });

  it('treats an empty name as a rename removal', async () => {
    const { session, calls } = stubSession();
    const rename = captureTools(session).get('rename_function')!;

    await rename({ fileId: 'sample', address: 4096, name: '' });
    expect(calls.deleteRename).toEqual([['sample', 4096]]);
  });

  it('toggles a bookmark off when one already exists at the address', async () => {
    const { session, calls } = stubSession({ bookmarks: [{ address: 0x1000, label: 'old' }] });
    const bookmark = captureTools(session).get('add_bookmark')!;

    const result = await bookmark({ fileId: 'sample', address: '0x1000' });

    expect(JSON.parse(textOf(result)).action).toBe('removed');
    expect(calls.removeBookmark).toEqual([['sample', 0x1000]]);
    expect(calls.addBookmark).toEqual([]);
  });

  it('toggles a bookmark on when the address is free', async () => {
    const { session, calls } = stubSession();
    const bookmark = captureTools(session).get('add_bookmark')!;

    const result = await bookmark({ fileId: 'sample', address: '0x2000', label: 'here' });

    expect(JSON.parse(textOf(result)).action).toBe('added');
    expect(calls.addBookmark).toEqual([['sample', 0x2000, 'here']]);
  });
});

describe('tool handlers — unknown file', () => {
  it.each(['get_xrefs', 'add_comment', 'rename_function', 'add_bookmark', 'list_comments', 'detect_anomalies'])(
    '%s reports a file that is not loaded',
    async (toolName) => {
      const { session } = stubSession();
      const handler = captureTools(session).get(toolName)!;

      const result = await handler({ fileId: 'missing', address: '0x1000', text: 'x', name: 'x' });
      expect(result.isError).toBe(true);
      expect(textOf(result)).toMatch(/not loaded/);
    },
  );
});
