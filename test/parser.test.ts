import { describe, expect, test } from 'vitest';
import { buildDidLogUrl, getBaseUrl, parseCanonicalAddress, parseDidWebvhIdentifier } from '../src/parser.js';
import { MOCK_SCID } from './utils.js';

describe('DID-to-HTTPS URL derivation', () => {
  test.each([
    ['localhost.example.com', 'localhost.example.com', '/.well-known'],
    ['localhost.example.com%3A8000', 'localhost.example.com:8000', '/.well-known'],
    ['my-localhost.example.com', 'my-localhost.example.com', '/.well-known'],
    ['cdn-localhost.example', 'cdn-localhost.example', '/.well-known'],
    ['localhost.example.com%3A8443', 'localhost.example.com:8443', '/.well-known'],
    ['example.com:localhost', 'example.com/localhost', ''],
    ['example.com:api:localhost:issuer', 'example.com/api/localhost/issuer', ''],
    ['example.com%3A8443:localhost', 'example.com:8443/localhost', ''],
    ['%6Cocalhost.example.com', 'localhost.example.com', '/.well-known'],
  ])('keeps HTTPS when localhost appears in %s', (address, location, logDirectory) => {
    const did = `did:webvh:${MOCK_SCID}:${address}`;

    expect(getBaseUrl(did)).toBe(`https://${location}`);
    expect(buildDidLogUrl(did)).toBe(`https://${location}${logDirectory}/did.jsonl`);
  });

  test('builds URLs for path-qualified identifiers', () => {
    const did = `did:webvh:${MOCK_SCID}:example.com%3A8080:custom:path`;
    expect(getBaseUrl(did)).toBe('https://example.com:8080/custom/path');
    expect(buildDidLogUrl(did)).toBe('https://example.com:8080/custom/path/did.jsonl');
  });

  test('uses .well-known did.jsonl when the DID has no path', () => {
    const did = `did:webvh:${MOCK_SCID}:example.com`;
    expect(getBaseUrl(did)).toBe('https://example.com');
    expect(buildDidLogUrl(did)).toBe('https://example.com/.well-known/did.jsonl');
  });

  test('rejects query, fragment, and traversal contamination', () => {
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com#frag`)).toThrow(
      'did:webvh identifier must not include query or fragment components'
    );
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com?query=1`)).toThrow(
      'did:webvh identifier must not include query or fragment components'
    );
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:..:secret`)).toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:%2E%2E:secret`)).toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:a%2Fb`)).toThrow(
      'did:webvh identifier must not contain decoded slash within a single path segment'
    );
  });
});

describe('Canonical address parsing', () => {
  test('rejects did:webvh with a missing domain segment', () => {
    expect(() => parseCanonicalAddress(`did:webvh:${MOCK_SCID}`)).toThrow(
      'did:webvh identifier must include SCID and domain segments'
    );
  });

  test('rejects malformed pre-encoded port separators', () => {
    expect(() => parseCanonicalAddress('example.com%3A8080%3A443')).toThrow('Invalid pre-encoded port separator');
  });

  test.each(['example.com:8080x', 'example.com%3A8080x'])('rejects non-numeric port values in %s', (address) => {
    expect(() => parseCanonicalAddress(address)).toThrow('Invalid port number: 8080x');
  });

  test('rejects invalid host percent-encoding', () => {
    expect(() => parseCanonicalAddress('%E0%A4%A')).toThrow('Invalid percent-encoding in host: %E0%A4%A');
  });

  test('rejects IPv6-style hosts', () => {
    expect(() => parseCanonicalAddress('https://[::1]/')).toThrow('IP addresses are not allowed as hosts');
  });
});

describe('did:webvh identifier parsing', () => {
  test('rejects identifiers with the wrong method', () => {
    expect(() => parseDidWebvhIdentifier('did:web:example.com', 'resolver input')).toThrow(
      'resolver input must be a valid did:webvh identifier'
    );
  });

  test('rejects identifiers with a missing SCID', () => {
    expect(() => parseDidWebvhIdentifier('did:webvh::example.com', 'resolver input')).toThrow(
      'resolver input must include SCID segment'
    );
  });

  test('applies DID Core syntax before did:webvh constraints', () => {
    expect(() => parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com%ZZ`, 'resolver input')).toThrow(
      'valid did:webvh identifier'
    );
    expect(() => parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example`, 'resolver input')).toThrow(
      'valid fully qualified domain'
    );
  });

  test('returns parsed domain and deployment path details', () => {
    const parsed = parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com%3A8443:tenant:issuer`, 'resolver input');

    expect(parsed).toEqual({
      scid: MOCK_SCID,
      canonicalHost: 'example.com',
      canonicalPort: 8443,
      didDomainComponent: 'example.com%3A8443',
      paths: ['tenant', 'issuer'],
      locationKey: 'example.com%3A8443:tenant:issuer',
      did: `did:webvh:${MOCK_SCID}:example.com%3A8443:tenant:issuer`,
    });
  });
});
