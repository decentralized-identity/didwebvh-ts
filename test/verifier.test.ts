import { describe, expect, test } from 'bun:test';
import { generateKeyPair, sign } from '@stablelib/ed25519';
import { defaultVerifier } from '../src/verifier';

describe('defaultVerifier', () => {
  test('returns true for a valid signature', async () => {
    const kp = generateKeyPair();
    const message = new TextEncoder().encode('hello world');
    const signature = sign(kp.secretKey, message);
    expect(await defaultVerifier.verify(signature, message, kp.publicKey)).toBe(true);
  });

  test('returns false for a tampered message', async () => {
    const kp = generateKeyPair();
    const message = new TextEncoder().encode('hello world');
    const signature = sign(kp.secretKey, message);
    const tampered = new TextEncoder().encode('hello WORLD');
    expect(await defaultVerifier.verify(signature, tampered, kp.publicKey)).toBe(false);
  });

  test('returns false for a wrong key', async () => {
    const kp = generateKeyPair();
    const other = generateKeyPair();
    const message = new TextEncoder().encode('hello world');
    const signature = sign(kp.secretKey, message);
    expect(await defaultVerifier.verify(signature, message, other.publicKey)).toBe(false);
  });

  test('returns false instead of throwing on malformed input', async () => {
    const message = new TextEncoder().encode('hello world');
    expect(await defaultVerifier.verify(new Uint8Array(1), message, new Uint8Array(1))).toBe(false);
  });
});
