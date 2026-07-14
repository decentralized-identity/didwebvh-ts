import { describe, expect, test } from 'vitest';
import { getBaseUrl, getFileUrl } from '../src/utils';

describe('Internationalized domain handling', () => {
  test('handles Unicode domain labels', () => {
    const did = 'did:webvh:scid:bücher.example';
    expect(getBaseUrl(did)).toBe('https://xn--bcher-kva.example');
    expect(getFileUrl(did)).toBe('https://xn--bcher-kva.example/.well-known/did.jsonl');
  });

  test('decodes encoded port numbers', () => {
    const did = 'did:webvh:scid:例子.测试%3A8080';
    expect(getBaseUrl(did)).toBe('https://xn--fsqu00a.xn--0zwm56d:8080');
    expect(getFileUrl(did)).toBe('https://xn--fsqu00a.xn--0zwm56d:8080/.well-known/did.jsonl');
  });

  test('arabic domain example', () => {
    const did = 'did:webvh:scid:مثال.إختبار';
    expect(getBaseUrl(did)).toBe('https://xn--mgbh0fb.xn--kgbechtv');
  });
});
