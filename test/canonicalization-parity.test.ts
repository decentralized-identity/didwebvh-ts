import { describe, expect, test } from 'vitest';
import { deriveHash } from '../src/utils';
import { canonicalizeStrict } from '../src/utils/canonicalize';

describe('canonicalization parity semantics', () => {
  test('distinguishes absent and null fields deterministically', () => {
    expect(canonicalizeStrict({ a: 1 })).toBe('{"a":1}');
    expect(canonicalizeStrict({ a: null })).toBe('{"a":null}');
  });

  test('strips explicit undefined at top level object fields', () => {
    expect(canonicalizeStrict({ a: undefined })).toBe('{}');
  });

  test('strips nested undefined in objects', () => {
    expect(canonicalizeStrict({ a: { b: undefined, c: 1 } })).toBe('{"a":{"c":1}}');
  });

  test('deriveHash accepts payloads with undefined object fields by stripping them', async () => {
    await expect(deriveHash({ a: undefined })).resolves.toEqual(await deriveHash({}));
  });

  test('still rejects undefined values in arrays', () => {
    expect(() => canonicalizeStrict([undefined])).toThrow(
      'Canonicalization input contains undefined in array position'
    );
  });
});
