import { describe, expect, test } from 'bun:test';
import { createHash, createHashHex } from '../src/utils/crypto';

describe('hash utilities', () => {
  // Known SHA-256 vector: sha256('hello')
  const helloSha256 = '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824';

  test('createHash produces a sha2-256 digest', async () => {
    const digest = await createHash('hello');
    expect(digest).toHaveLength(32);
  });

  test('createHashHex produces the hex-encoded sha2-256 digest', async () => {
    expect(await createHashHex('hello')).toBe(helloSha256);
  });
});
