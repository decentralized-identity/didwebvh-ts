import { canonicalizeEx } from 'json-canonicalize';
import type { JsonValue } from '../interfaces';

const sanitizeForCanonicalization = (value: unknown, seen: WeakMap<object, unknown>): unknown => {
  if (value === null) return null;

  const type = typeof value;
  if (type === 'undefined') {
    throw new Error('Canonicalization input contains undefined in array position');
  }
  if (type === 'function' || type === 'symbol' || type === 'bigint') {
    throw new Error(`Canonicalization input contains unsupported type: ${type}`);
  }
  if (type === 'number' && !Number.isFinite(value as number)) {
    throw new Error('Canonicalization input contains non-finite number');
  }
  if (type !== 'object') return value;

  const obj = value as Record<string, unknown>;
  if (seen.has(obj)) {
    throw new Error('Canonicalization input contains circular references');
  }

  if (Array.isArray(obj)) {
    const sanitizedArray: unknown[] = [];
    seen.set(obj, sanitizedArray);
    for (const item of obj) {
      sanitizedArray.push(sanitizeForCanonicalization(item, seen));
    }
    return sanitizedArray;
  }

  const sanitizedObject: Record<string, unknown> = {};
  seen.set(obj, sanitizedObject);
  for (const [key, entry] of Object.entries(obj)) {
    if (typeof entry === 'undefined') {
      continue;
    }
    sanitizedObject[key] = sanitizeForCanonicalization(entry, seen);
  }
  return sanitizedObject;
};

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
  const sanitized = sanitizeForCanonicalization(value, new WeakMap<object, unknown>());
  validateStrictJsonValue(sanitized);
  return canonicalizeEx(sanitized, {
    allowCircular: false,
    filterUndefined: true,
    undefinedInArrayToNull: false,
  });
};
