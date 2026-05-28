import { describe, expect, test } from 'bun:test';
import { deriveHash } from '../src/utils';
import { canonicalizeStrict } from '../src/utils/canonicalize';

describe('canonicalization parity semantics', () => {
  test('distinguishes absent and null fields deterministically', () => {
    expect(canonicalizeStrict({ a: 1 })).toBe('{"a":1}');
    expect(canonicalizeStrict({ a: null })).toBe('{"a":null}');
  });

  test('rejects explicit undefined at top level object fields', () => {
    expect(() => canonicalizeStrict({ a: undefined })).toThrow('Canonicalization input contains undefined');
  });

  test('rejects nested undefined in arrays and objects', () => {
    expect(() => canonicalizeStrict({ a: [{ b: undefined }] })).toThrow('Canonicalization input contains undefined');
  });

  test('deriveHash rejects undefined-bearing payloads', async () => {
    await expect(deriveHash({ a: undefined } as any)).rejects.toThrow('Canonicalization input contains undefined');
  });
});
