import { describe, expect, test } from 'bun:test';
import { createDate } from '../src/utils';
import { createNextVersionTime, parseUtcIso8601VersionTime } from '../src/utils/iso8601-datetime';

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
});

describe('createNextVersionTime', () => {
  // versionTime is stored at second precision, so monotonicity must hold after trimming.
  test('rejects a requested time that collides with previous once trimmed to seconds', () => {
    expect(() => createNextVersionTime('2025-01-01T00:00:00Z', '2025-01-01T00:00:00.500Z', createDate)).toThrow(
      'versionTime must be greater than previous versionTime'
    );
  });

  test('advances past previous when the clock has not reached the next second', () => {
    // Previous is ahead of the wall clock, forcing the same-second collision branch.
    const previous = createDate(new Date(Date.now() + 60_000));
    const next = createNextVersionTime(previous, undefined, createDate);
    expect(new Date(next).getTime()).toBeGreaterThan(new Date(previous).getTime());
  });

  test('returns a strictly greater time for a valid requested update', () => {
    const next = createNextVersionTime('2025-01-01T00:00:00Z', '2025-01-01T00:00:01Z', createDate);
    expect(next).toBe('2025-01-01T00:00:01Z');
  });
});
