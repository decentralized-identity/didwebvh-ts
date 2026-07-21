import { describe, expect, test } from 'vitest';
import {
  getBaseUrl,
  getFileUrl,
  parseCanonicalAddress,
  parseDidWebvhIdentifier,
  requireDidDocumentId,
} from '../src/utils';

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

describe('Direct utility guards and parsers', () => {
  test('requireDidDocumentId throws when id is missing', () => {
    expect(() => requireDidDocumentId(undefined)).toThrow('DID document id is missing');
    expect(() => requireDidDocumentId('')).toThrow('DID document id is missing');
  });

  test('requireDidDocumentId returns the provided id when present', () => {
    expect(requireDidDocumentId('did:webvh:scid:example.com')).toBe('did:webvh:scid:example.com');
  });

  test('parseCanonicalAddress rejects did:webvh with missing domain segment', () => {
    expect(() => parseCanonicalAddress('did:webvh:onlyscid')).toThrow(
      'Invalid did:webvh identifier: must contain SCID (or {SCID} placeholder) and domain'
    );
  });

  test('parseCanonicalAddress rejects malformed pre-encoded port separators', () => {
    expect(() => parseCanonicalAddress('example.com%3A8080%3A443')).toThrow('Invalid pre-encoded port separator');
  });

  test('parseCanonicalAddress rejects invalid host percent-encoding', () => {
    expect(() => parseCanonicalAddress('%E0%A4%A')).toThrow('Invalid percent-encoding in host: %E0%A4%A');
  });

  test('parseCanonicalAddress rejects IPv6-style hosts', () => {
    expect(() => parseCanonicalAddress('https://[::1]/')).toThrow('IP addresses are not allowed as hosts');
  });

  test('parseDidWebvhIdentifier rejects wrong method prefix', () => {
    expect(() => parseDidWebvhIdentifier('did:web:example.com', 'resolver input')).toThrow(
      'resolver input must be a valid did:webvh identifier'
    );
  });

  test('parseDidWebvhIdentifier rejects missing SCID segment', () => {
    expect(() => parseDidWebvhIdentifier('did:webvh::example.com', 'resolver input')).toThrow(
      'resolver input must include SCID segment'
    );
  });

  test('parseDidWebvhIdentifier returns parsed location and paths', () => {
    const parsed = parseDidWebvhIdentifier('did:webvh:scid123:example.com%3A8443:tenant:issuer', 'resolver input');

    expect(parsed).toEqual({
      scid: 'scid123',
      didDomainComponent: 'example.com%3A8443',
      paths: ['tenant', 'issuer'],
      locationKey: 'example.com%3A8443:tenant:issuer',
    });
  });
});
