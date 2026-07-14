import { describe, expect, test } from 'vitest';
import { getBaseUrl, getFileUrl } from '../src/utils';

describe('Resolver URL derivation', () => {
  test('Uses https for localhost DID host', () => {
    const did = 'did:webvh:scid:localhost%3A8000:test:path';
    expect(getBaseUrl(did)).toBe('https://localhost:8000/test/path');
    expect(getFileUrl(did)).toBe('https://localhost:8000/test/path/did.jsonl');
  });

  test('Uses https for non-localhost DID host', () => {
    const did = 'did:webvh:scid:example.com%3A8080:custom:path';
    expect(getBaseUrl(did)).toBe('https://example.com:8080/custom/path');
    expect(getFileUrl(did)).toBe('https://example.com:8080/custom/path/did.jsonl');
  });

  test('Uses .well-known did.jsonl when DID has no path', () => {
    const did = 'did:webvh:scid:example.com';
    expect(getBaseUrl(did)).toBe('https://example.com');
    expect(getFileUrl(did)).toBe('https://example.com/.well-known/did.jsonl');
  });

  test('Rejects DID identifier containing fragment or query contamination', () => {
    expect(() => getBaseUrl('did:webvh:scid:example.com#frag')).toThrow(
      'did:webvh identifier must not include query or fragment components'
    );
    expect(() => getBaseUrl('did:webvh:scid:example.com?query=1')).toThrow(
      'did:webvh identifier must not include query or fragment components'
    );
  });

  test('Rejects DID identifier containing traversal-style path segments', () => {
    expect(() => getBaseUrl('did:webvh:scid:example.com:..:secret')).toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
    expect(() => getBaseUrl('did:webvh:scid:example.com:%2E%2E:secret')).toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
    expect(() => getBaseUrl('did:webvh:scid:example.com:a%2Fb')).toThrow(
      'did:webvh identifier must not contain decoded slash within a single path segment'
    );
  });
});
