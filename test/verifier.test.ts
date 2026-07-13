import { describe, expect, test } from 'vitest';
import { ed25519 } from '@noble/curves/ed25519.js';
import { defaultVerifier } from '../src/verifier';

describe('defaultVerifier', () => {
  test('returns true for a valid signature', async () => {
    const kp = ed25519.keygen();
    const message = new TextEncoder().encode('hello world');
    const signature = ed25519.sign(message, kp.secretKey);
    expect(await defaultVerifier.verify(signature, message, kp.publicKey)).toBe(true);
  });

  test('returns false for a tampered message', async () => {
    const kp = ed25519.keygen();
    const message = new TextEncoder().encode('hello world');
    const signature = ed25519.sign(message, kp.secretKey);
    const tampered = new TextEncoder().encode('hello WORLD');
    expect(await defaultVerifier.verify(signature, tampered, kp.publicKey)).toBe(false);
  });

  test('returns false for a wrong key', async () => {
    const kp = ed25519.keygen();
    const other = ed25519.keygen();
    const message = new TextEncoder().encode('hello world');
    const signature = ed25519.sign(message, kp.secretKey);
    expect(await defaultVerifier.verify(signature, message, other.publicKey)).toBe(false);
  });

  test('returns false instead of throwing on malformed input', async () => {
    const message = new TextEncoder().encode('hello world');
    expect(await defaultVerifier.verify(new Uint8Array(1), message, new Uint8Array(1))).toBe(false);
  });
});
