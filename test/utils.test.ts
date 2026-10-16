import { describe, expect, test } from 'vitest';
import { deepClone } from '../src/utils.js';

describe('deepClone', () => {
  test('clones Date instances without sharing references', () => {
    const source = {
      createdAt: new Date('2026-01-02T03:04:05.000Z'),
      nested: {
        updatedAt: new Date('2026-06-07T08:09:10.000Z'),
      },
    };

    const cloned = deepClone(source);

    expect(cloned).toEqual(source);
    expect(cloned).not.toBe(source);
    expect(cloned.createdAt).toBeInstanceOf(Date);
    expect(cloned.createdAt).not.toBe(source.createdAt);
    expect(cloned.createdAt.getTime()).toBe(source.createdAt.getTime());
    expect(cloned.nested.updatedAt).toBeInstanceOf(Date);
    expect(cloned.nested.updatedAt).not.toBe(source.nested.updatedAt);
    expect(cloned.nested.updatedAt.getTime()).toBe(source.nested.updatedAt.getTime());
  });
});
