import { describe, expect, test } from 'bun:test';
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

  test('Rejects requested versionTime that trims to previous second', () => {
    const formatDate = (value: string | Date) => new Date(value).toISOString().replace(/\.\d{1,3}Z$/, 'Z');

    expect(() => {
      createNextVersionTime('2025-01-01T00:00:05Z', '2025-01-01T00:00:05.400Z', formatDate);
    }).toThrow('versionTime must be greater than previous versionTime');
  });
});
