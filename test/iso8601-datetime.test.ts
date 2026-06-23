import { describe, expect, test } from 'bun:test';
import { parseUtcIso8601VersionTime } from '../src/utils/iso8601-datetime';

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
