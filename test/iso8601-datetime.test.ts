import { describe, expect, test } from 'vitest';
import {
  createNextVersionTime,
  parseUtcIso8601VersionTime,
  validateUtcIso8601NotInFuture,
} from '../src/utils/iso8601-datetime';

describe('ISO8601 DateTime Validation', () => {
  test('Accepts Z timezone', () => {
    const result = parseUtcIso8601VersionTime('2025-11-02T10:20:30Z', 'test');
    expect(result).toBeInstanceOf(Date);
  });

  test('Rejects non-00:00 UTC offset', () => {
    expect(() => {
      parseUtcIso8601VersionTime('2025-11-02T10:20:30+01:00', 'test');
    }).toThrow('must be in UTC (Z or +00:00), found +01:00');
  });

  test('Rejects completely invalid string (no regex match)', () => {
    expect(() => {
      parseUtcIso8601VersionTime('not-a-date', 'test');
    }).toThrow('test must be a valid UTC ISO8601 timestamp');
  });

  test('Rejects timestamp with missing timezone (no regex match)', () => {
    expect(() => {
      parseUtcIso8601VersionTime('2025-11-02T10:20:30', 'test');
    }).toThrow('test must be a valid UTC ISO8601 timestamp');
  });

  test('Rejects requested versionTime that trims to previous second', () => {
    const formatDate = (value: string | Date) => new Date(value).toISOString().replace(/\.\d{1,3}Z$/, 'Z');

    expect(() => {
      createNextVersionTime('2025-01-01T00:00:05Z', '2025-01-01T00:00:05.400Z', formatDate);
    }).toThrow('versionTime must be greater than previous versionTime');
  });
});

describe('validateUtcIso8601NotInFuture', () => {
  test('Accepts a past timestamp (no skew)', () => {
    const past = '2020-01-01T00:00:00Z';
    const result = validateUtcIso8601NotInFuture(past, 'test');
    expect(result).toBeInstanceOf(Date);
  });

  test('Rejects a future timestamp with no skew allowed', () => {
    const future = new Date(Date.now() + 60_000).toISOString().replace(/\.\d{1,3}Z$/, 'Z');
    expect(() => {
      validateUtcIso8601NotInFuture(future, 'test');
    }).toThrow('test must not be in the future');
  });

  test('Rejects a future timestamp beyond the allowed skew', () => {
    const future = new Date(Date.now() + 10 * 60_000).toISOString().replace(/\.\d{1,3}Z$/, 'Z');
    expect(() => {
      validateUtcIso8601NotInFuture(future, 'test', 5 * 60_000);
    }).toThrow('test must not be more than 5 minutes in the future');
  });

  test('Accepts a future timestamp within the allowed skew', () => {
    const future = new Date(Date.now() + 2 * 60_000).toISOString().replace(/\.\d{1,3}Z$/, 'Z');
    const result = validateUtcIso8601NotInFuture(future, 'test', 5 * 60_000);
    expect(result).toBeInstanceOf(Date);
  });
});
