/**
 * Address argument parsing for the MCP tools.
 *
 * `parseAddr` lives in `src/mcp/paths.ts` and is exercised directly here. The
 * matching OUTCOME tests — that a rejected address records no annotation, which
 * was the pre-hardening failure mode — live in `annotationTools.test.ts`, where
 * they run against the real tool handlers.
 */

import { describe, it, expect } from 'vitest';
import { parseAddr } from '../paths';

describe('parseAddr — accepted forms', () => {
  it('accepts a 0x-prefixed hex string', () => {
    expect(parseAddr('0x1234')).toBe(0x1234);
  });

  it('accepts bare hex without the 0x prefix', () => {
    expect(parseAddr('deadbe')).toBe(0xdeadbe);
  });

  it('accepts uppercase hex', () => {
    expect(parseAddr('0xABCDEF')).toBe(0xabcdef);
  });

  it('accepts a mixed-case 0X prefix', () => {
    expect(parseAddr('0X1F')).toBe(0x1f);
  });

  it('tolerates surrounding whitespace', () => {
    expect(parseAddr('  0x1000  ')).toBe(0x1000);
  });

  it('takes a number through unchanged', () => {
    expect(parseAddr(4096)).toBe(4096);
  });

  it('accepts zero rather than treating it as falsy', () => {
    expect(parseAddr(0)).toBe(0);
    expect(parseAddr('0')).toBe(0);
  });

  it('reads a digits-only string as HEX, not decimal', () => {
    // "10" is 0x10 == 16. Documented behaviour: every address argument is hex.
    expect(parseAddr('10')).toBe(16);
  });

  it('reads exponent-looking strings as hex too', () => {
    // Not 1e5 == 100000: parseInt(…, 16) sees 0x1e5.
    expect(parseAddr('1e5')).toBe(0x1e5);
  });

  it('stops at the first non-hex character instead of rejecting (parseInt semantics)', () => {
    expect(parseAddr('0x10zzz')).toBe(0x10);
  });

  it('accepts an address at the top of the 32-bit range', () => {
    expect(parseAddr('0xffffffff')).toBe(0xffffffff);
  });

  it('carries a negative sign through, as parseInt does', () => {
    // Characterization, not endorsement: callers reject nothing here, they only
    // check for null. A negative address simply misses every lookup.
    expect(parseAddr('-10')).toBe(-16);
    expect(parseAddr(-1)).toBe(-1);
  });
});

describe('parseAddr — rejected forms', () => {
  it.each([
    ['a non-hex string', 'not-an-address'],
    ['an empty string', ''],
    ['whitespace only', '   '],
    ['a bare 0x prefix', '0x'],
    ['a bare sign', '-'],
    ['a non-hex letter', 'zz'],
  ])('rejects %s', (_label, address) => {
    expect(parseAddr(address)).toBeNull();
  });

  it.each([
    ['NaN', Number.NaN],
    ['Infinity', Number.POSITIVE_INFINITY],
    ['-Infinity', Number.NEGATIVE_INFINITY],
  ])('rejects the non-finite number %s', (_label, address) => {
    expect(parseAddr(address)).toBeNull();
  });
});
