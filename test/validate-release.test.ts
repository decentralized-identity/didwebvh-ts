import { describe, expect, test } from 'bun:test';
import { cmp, getLatestStrictSemverTagBefore, isSingleSemverBump, parseTag } from '../scripts/validate-release.ts';

describe('validate-release helpers', () => {
  test('parseTag accepts strict vMAJOR.MINOR.PATCH only', () => {
    expect(parseTag('v1.2.3')).toEqual({ major: 1, minor: 2, patch: 3 });
    expect(parseTag('v0.4')).toBeNull();
    expect(parseTag('v3.0.0-rc.1')).toBeNull();
    expect(parseTag('3.0.0')).toBeNull();
  });

  test('getLatestStrictSemverTagBefore ignores non-strict + excludes current tag', () => {
    const tags = ['v0.4', 'v1.0.0', 'v1.2.3', 'v2.0.0-rc.1', 'v2.0.0', 'not-a-tag', 'v2.0.1'];

    expect(getLatestStrictSemverTagBefore(tags, 'v2.0.2')).toBe('v2.0.1');
    expect(getLatestStrictSemverTagBefore(tags, 'v2.0.1')).toBe('v2.0.0');
  });

  test('isSingleSemverBump allows exactly one major/minor/patch bump', () => {
    const v1 = parseTag('v1.2.3')!;
    expect(isSingleSemverBump(v1, parseTag('v1.2.4')!)).toBeTrue();
    expect(isSingleSemverBump(v1, parseTag('v1.3.0')!)).toBeTrue();
    expect(isSingleSemverBump(v1, parseTag('v2.0.0')!)).toBeTrue();

    expect(isSingleSemverBump(v1, parseTag('v1.2.5')!)).toBeFalse();
    expect(isSingleSemverBump(v1, parseTag('v1.4.0')!)).toBeFalse();
    expect(isSingleSemverBump(v1, parseTag('v2.1.0')!)).toBeFalse();
    expect(isSingleSemverBump(v1, parseTag('v3.0.0')!)).toBeFalse();
  });

  test('cmp sorts by major/minor/patch', () => {
    expect(cmp(parseTag('v1.0.0')!, parseTag('v1.0.0')!)).toBe(0);
    expect(cmp(parseTag('v1.0.1')!, parseTag('v1.0.0')!)).toBeGreaterThan(0);
    expect(cmp(parseTag('v1.1.0')!, parseTag('v1.9.9')!)).toBeLessThan(0);
    expect(cmp(parseTag('v2.0.0')!, parseTag('v1.999.999')!)).toBeGreaterThan(0);
  });
});
