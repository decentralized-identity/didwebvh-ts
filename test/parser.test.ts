import { type ParsedDID, parse as parseDidUrl } from 'did-resolver';
import { describe, expect, test } from 'vitest';
import {
  buildDidLogUrl,
  getBaseUrl,
  narrowDidWebvh,
  normalizeDidAddress,
  parseCanonicalAddress,
  parseDidWebvhIdentifier,
  parseDidWebvhTemplate,
} from '../src/parser.js';
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

  test.each([
    ['%E7%94%A8%E6%88%B7', '%E7%94%A8%E6%88%B7'],
    ['%e7%94%a8%e6%88%b7', '%E7%94%A8%E6%88%B7'],
    ['%41b%2dc', 'Ab-c'],
    ['a%7eb', 'a~b'],
    ['a%21b%2Ac%3Ad', 'a%21b%2Ac%3Ad'],
    ['a%20b', 'a%20b'],
  ])('re-encodes path segment %s with uppercase hex', (segment, encoded) => {
    const did = `did:webvh:${MOCK_SCID}:example.com:${segment}`;
    expect(getBaseUrl(did)).toBe(`https://example.com/${encoded}`);
    expect(buildDidLogUrl(did)).toBe(`https://example.com/${encoded}/did.jsonl`);
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

  test('rejects empty path segments', () => {
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com::path`)).toThrow(
      'did:webvh identifier must not contain empty path segments'
    );
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:path:`)).toThrow();
    expect(() => getBaseUrl(`did:webvh:${MOCK_SCID}:example.com:`)).toThrow();
  });
});

describe('Canonical address parsing', () => {
  test('normalizes address, supplied, and fallback paths in order', () => {
    const fromAddress = normalizeDidAddress({
      address: 'https://example.com/address',
      scid: MOCK_SCID,
      paths: ['supplied'],
      fallbackPaths: ['fallback'],
      context: 'test',
    });
    const fromFallback = normalizeDidAddress({
      address: 'https://example.com',
      scid: MOCK_SCID,
      fallbackPaths: ['fallback'],
      context: 'test',
    });
    const emptyPathsSuppressFallback = normalizeDidAddress({
      address: 'https://example.com',
      scid: MOCK_SCID,
      paths: [],
      fallbackPaths: ['fallback'],
      context: 'test',
    });

    expect(fromAddress.did).toBe(`did:webvh:${MOCK_SCID}:example.com:address:supplied`);
    expect(fromFallback.did).toBe(`did:webvh:${MOCK_SCID}:example.com:fallback`);
    expect(emptyPathsSuppressFallback.did).toBe(`did:webvh:${MOCK_SCID}:example.com`);
  });

  test.each([
    [`did:webvh:${MOCK_SCID}:example.com%3a8080:custom`, MOCK_SCID],
    ['did:webvh:{SCID}:example.com%3a8080:custom', '{SCID}'],
  ])('canonicalizes lowercase port separators in DID and template addresses', (address, scid) => {
    const normalized = normalizeDidAddress({ address, scid, context: 'test' });
    expect(normalized.did).toBe(`did:webvh:${scid}:example.com%3A8080:custom`);
    expect(parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com%3a8080:custom`, 'test').did).toContain(
      'example.com%3a8080:custom'
    );
  });

  test.each([
    ['https://example.com/a:b', 'a%3Ab', 'a%3Ab'],
    ['https://example.com/a%3ab', 'a%3Ab', 'a%3Ab'],
    ['https://example.com/~user/a b', '%7Euser:a%20b', '~user/a%20b'],
  ])('encodes URL path segments without changing their boundaries in %s', (address, didPath, urlPath) => {
    const normalized = normalizeDidAddress({ address, scid: MOCK_SCID, context: 'test' });
    expect(normalized.did).toBe(`did:webvh:${MOCK_SCID}:example.com:${didPath}`);
    expect(buildDidLogUrl(normalized.did)).toBe(`https://example.com/${urlPath}/did.jsonl`);
  });

  test('encodes supplied path segments once and preserves existing DID paths', () => {
    const normalized = normalizeDidAddress({
      address: `did:webvh:${MOCK_SCID}:example.com:a%7eb`,
      scid: MOCK_SCID,
      paths: ['a:b', 'a%3ab', '~user', 'a b'],
      context: 'test',
    });
    expect(normalized.did).toBe(`did:webvh:${MOCK_SCID}:example.com:a%7Eb:a%3Ab:a%3Ab:%7Euser:a%20b`);
    expect(buildDidLogUrl(normalized.did)).toBe('https://example.com/a~b/a%3Ab/a%3Ab/~user/a%20b/did.jsonl');
  });

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

  test.each([
    ['example.com:0', '0'],
    ['example.com%3A65536', '65536'],
    ['example.com:000080', '000080'],
    ['https://example.com:0', '0'],
  ])('applies the same port rules to %s as DID domain components', (address, port) => {
    expect(() => parseCanonicalAddress(address)).toThrow(`Invalid port number: ${port}`);
  });

  test('rejects invalid host percent-encoding', () => {
    expect(() => parseCanonicalAddress('%E0%A4%A')).toThrow(
      "Address host contains invalid percent-encoding: '%E0%A4%A'"
    );
  });

  test('wraps URL syntax errors but preserves URL validation errors', () => {
    expect(() => parseCanonicalAddress('https://')).toThrow('Invalid URL:');
    for (const address of [
      'https://example.com/?query=1',
      'https://example.com/?',
      'https://example.com/#fragment',
      'https://example.com/#',
    ]) {
      expect(() => parseCanonicalAddress(address)).toThrow('URL input must not include query or fragment components');
    }
    expect(() => parseCanonicalAddress('https://example.com/a%2Fb')).toThrow(
      'URL pathname must not contain decoded slash within a single path segment'
    );
  });

  test.each([
    { username: 'user', password: '' },
    { username: '', password: 'password' },
    { username: 'user', password: 'password' },
  ])('rejects URL credentials', ({ username, password }) => {
    const url = new URL('https://example.com');
    url.username = username;
    url.password = password;

    expect(() => parseCanonicalAddress(url.toString())).toThrow('URL input must not include username or password');
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

  test.each([
    ['an encoded U-label', `did:webvh:${MOCK_SCID}:b%C3%BCcher.example.com:p%c3%a4th`, 'bücher.example.com'],
    ['a lowercase encoded port separator', `did:webvh:${MOCK_SCID}:example.com%3a8443`, 'example.com'],
  ])('returns %s exactly as written in the identifier', (_, did, canonicalHost) => {
    const parsed = parseDidWebvhIdentifier(did, 'resolver input');

    expect(parsed.did).toBe(did);
    expect(parsed.locationKey).toBe(did.slice(`did:webvh:${MOCK_SCID}:`.length));
    expect(parsed.didDomainComponent).toBe(parsed.locationKey.split(':')[0]);
    expect(parsed.canonicalHost).toBe(canonicalHost);
  });

  test('normalizes an encoded did:webvh template address to its A-label form', () => {
    const address = 'did:webvh:{SCID}:b%C3%BCcher.example.com';
    expect(normalizeDidAddress({ address, scid: '{SCID}', context: 'test' }).did).toBe(
      'did:webvh:{SCID}:xn--bcher-kva.example.com'
    );
  });

  test('rejects a {SCID} template, which is not a DID', () => {
    expect(() => parseDidWebvhIdentifier('did:webvh:{SCID}:example.com', 'resolver input')).toThrow(
      'resolver input must be a valid did:webvh identifier'
    );
  });

  test('rejects a DID URL path', () => {
    expect(() => parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:example.com/path`, 'resolver input')).toThrow(
      'resolver input must not include a DID URL path'
    );
  });
});

describe('did:webvh template parsing', () => {
  test('restores the {SCID} placeholder in the parsed template', () => {
    expect(parseDidWebvhTemplate('did:webvh:{SCID}:example.com%3A8443:tenant', 'template')).toEqual({
      scid: '{SCID}',
      canonicalHost: 'example.com',
      canonicalPort: 8443,
      didDomainComponent: 'example.com%3A8443',
      paths: ['tenant'],
      locationKey: 'example.com%3A8443:tenant',
      did: 'did:webvh:{SCID}:example.com%3A8443:tenant',
    });
  });

  test.each([
    [`did:webvh:${MOCK_SCID}:example.com`, "template must be a did:webvh template starting with 'did:webvh:{SCID}:'"],
    ['did:webvh:{SCID}:example', 'template must include a valid fully qualified domain'],
    ['did:webvh:{SCID}:example.com#key-1', 'template must not include query or fragment components'],
  ])('rejects %s', (template, message) => {
    expect(() => parseDidWebvhTemplate(template, 'template')).toThrow(message);
  });
});

describe('did:webvh narrowing of a did-resolver parse result', () => {
  test('narrows the did-resolver parse result, ignoring DID URL query and fragment', () => {
    const parsed = parseDidUrl(`did:webvh:${MOCK_SCID}:example.com?versionNumber=1#key-1`);
    expect(parsed).not.toBeNull();
    expect(narrowDidWebvh(parsed as ParsedDID, 'resolver input').did).toBe(`did:webvh:${MOCK_SCID}:example.com`);
  });

  test('rejects a ParsedDID whose components are inconsistent', () => {
    const parsed: ParsedDID = {
      did: `did:webvh:${MOCK_SCID}:example.com`,
      didUrl: `did:webvh:${MOCK_SCID}:example.com`,
      method: 'webvh',
      id: `${MOCK_SCID}:other.example.com`,
    };
    expect(() => narrowDidWebvh(parsed, 'resolver input')).toThrow(
      'resolver input must be a valid did:webvh identifier'
    );
  });
});
