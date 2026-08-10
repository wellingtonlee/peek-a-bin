import { describe, it, expect } from 'vitest';
import { DANGEROUS_APIS, NOTABLE_APIS, matchesApi } from '../apiLists';

describe('API lists', () => {
  // The defect that motivated extracting these: the scanner's list and the
  // report's list were maintained separately and drifted, so an import could
  // make a function worth scanning while the report never mentioned it.
  it('treats every dangerous API as notable', () => {
    const missing = [...DANGEROUS_APIS].filter(api => !NOTABLE_APIS.has(api));
    expect(missing).toEqual([]);
  });

  it('keeps notable strictly broader than dangerous', () => {
    // Report context (file, registry, network) is deliberately not "dangerous".
    expect(NOTABLE_APIS.size).toBeGreaterThan(DANGEROUS_APIS.size);
    expect(NOTABLE_APIS.has('RegOpenKey')).toBe(true);
    expect(DANGEROUS_APIS.has('RegOpenKey')).toBe(false);
  });

  it('does not enumerate ANSI/wide suffix variants by hand', () => {
    // Hand-listing CreateProcessA/W is what let the two lists disagree:
    // whichever spelling someone forgot silently stopped matching.
    // matchesApi strips the suffix, so the base name is all that is stored.
    for (const set of [DANGEROUS_APIS, NOTABLE_APIS]) {
      for (const api of set) {
        if (api === api.replace(/[AW]$/, '')) continue;
        // A name legitimately ending in A/W is fine only if its stripped form
        // is not also present — that pair is the hand-enumeration smell.
        expect(set.has(api.replace(/[AW]$/, ''))).toBe(false);
      }
    }
  });
});

describe('matchesApi', () => {
  it('matches an exact name', () => {
    expect(matchesApi(DANGEROUS_APIS, 'VirtualAlloc')).toBe(true);
  });

  it('matches both ANSI and wide spellings of the same API', () => {
    expect(matchesApi(DANGEROUS_APIS, 'CreateProcessA')).toBe(true);
    expect(matchesApi(DANGEROUS_APIS, 'CreateProcessW')).toBe(true);
    expect(matchesApi(DANGEROUS_APIS, 'ShellExecuteW')).toBe(true);
    expect(matchesApi(DANGEROUS_APIS, 'LoadLibraryA')).toBe(true);
    expect(matchesApi(DANGEROUS_APIS, 'SetWindowsHookExW')).toBe(true);
  });

  it('does not mangle a lowercase socket export', () => {
    // `recv` and `send` end in neither A nor W, but the regex is anchored and
    // case-sensitive, so a name like `connect` must survive intact.
    expect(matchesApi(NOTABLE_APIS, 'recv')).toBe(true);
    expect(matchesApi(NOTABLE_APIS, 'connect')).toBe(true);
    expect(matchesApi(NOTABLE_APIS, 'send')).toBe(true);
  });

  it('rejects an unrelated import', () => {
    expect(matchesApi(DANGEROUS_APIS, 'GetTickCount')).toBe(false);
    expect(matchesApi(NOTABLE_APIS, 'GetTickCount')).toBe(false);
  });

  it('does not match a name that merely contains a listed API', () => {
    expect(matchesApi(DANGEROUS_APIS, 'MyVirtualAlloc')).toBe(false);
    expect(matchesApi(DANGEROUS_APIS, 'VirtualAllocHelper')).toBe(false);
  });

  it('strips only a single trailing suffix character', () => {
    // `VirtualAllocEx` must match on its own name, not by stripping to
    // `VirtualAllocE`.
    expect(matchesApi(DANGEROUS_APIS, 'VirtualAllocEx')).toBe(true);
    expect(matchesApi(DANGEROUS_APIS, 'VirtualProtectEx')).toBe(true);
  });
});
