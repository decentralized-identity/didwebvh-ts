import { afterEach, beforeEach, describe, expect, test } from 'bun:test';
import { config } from '../src/config';
import { bufferToString, concatBuffers, createBuffer } from '../src/utils/buffer';

// The buffer utilities switch between Node's Buffer and web APIs based on
// config.isBrowser; both implementations must agree, so run the same suite
// against each branch.
const originalIsBrowser = config.isBrowser;

afterEach(() => {
  config.isBrowser = originalIsBrowser;
});

describe.each([
  ['node', false],
  ['browser', true],
])('buffer utilities (%s path)', (_label, isBrowser) => {
  beforeEach(() => {
    config.isBrowser = isBrowser;
  });

  test('round-trips utf-8 text', () => {
    const bytes = createBuffer('hello did:webvh');
    expect(bufferToString(bytes)).toBe('hello did:webvh');
  });

  test('decodes and encodes base64', () => {
    const bytes = createBuffer('aGVsbG8=', 'base64');
    expect(bufferToString(bytes)).toBe('hello');
    expect(bufferToString(bytes, 'base64')).toBe('aGVsbG8=');
  });

  test('encodes hex', () => {
    expect(bufferToString(new Uint8Array([0, 1, 171, 255]), 'hex')).toBe('0001abff');
  });

  test('concatenates buffers', () => {
    // The Node path returns a Buffer subclass, so compare contents, not types.
    const result = concatBuffers(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3]));
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });
});
