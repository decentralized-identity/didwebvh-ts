import { describe, expect, test } from 'bun:test';
import { concatBuffers } from '../src/utils/buffer';

describe('buffer utilities', () => {
  test('concatenates buffers', () => {
    const result = concatBuffers(new Uint8Array([1, 2]), new Uint8Array([]), new Uint8Array([3]));
    expect(Array.from(result)).toEqual([1, 2, 3]);
  });

  test('concatenates empty input', () => {
    const result = concatBuffers();
    expect(result.length).toBe(0);
  });
});
