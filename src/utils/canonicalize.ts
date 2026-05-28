import { canonicalizeEx } from 'json-canonicalize';
import type { JsonValue } from '../interfaces';

const assertJsonCompatible = (value: unknown, seen: WeakSet<object>) => {
  if (value === null) return;

  const type = typeof value;
  if (type === 'undefined') {
    throw new Error('Canonicalization input contains undefined');
  }
  if (type === 'function' || type === 'symbol' || type === 'bigint') {
    throw new Error(`Canonicalization input contains unsupported type: ${type}`);
  }
  if (type === 'number' && !Number.isFinite(value as number)) {
    throw new Error('Canonicalization input contains non-finite number');
  }
  if (type !== 'object') return;

  const obj = value as Record<string, unknown>;
  if (seen.has(obj)) {
    throw new Error('Canonicalization input contains circular references');
  }
  seen.add(obj);

  if (Array.isArray(obj)) {
    for (const item of obj) {
      assertJsonCompatible(item, seen);
    }
    return;
  }

  for (const entry of Object.values(obj)) {
    assertJsonCompatible(entry, seen);
  }
};

export function validateStrictJsonValue(value: unknown): asserts value is JsonValue {
  assertJsonCompatible(value, new WeakSet<object>());
}

export const canonicalizeStrict = (value: unknown): string => {
  validateStrictJsonValue(value);
  return canonicalizeEx(value, {
    allowCircular: false,
    filterUndefined: false,
    undefinedInArrayToNull: false,
  });
};
