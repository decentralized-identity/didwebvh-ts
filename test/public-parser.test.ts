import { describe, expect, test } from 'vitest';
import { didWebvhToHttps, parseDidWebvh } from '../src/index.js';
import { fetchWitnessProofs } from '../src/utils.js';

const SCID = 'QmfGEUAcMpzo25kF2Rhn8L5FAXysfGnkzjwdKoNPi615XQ';

describe('parseDidWebvh', () => {
  test('decomposes a DID with port and path', () => {
    const parsed = parseDidWebvh(`did:webvh:${SCID}:example.com%3A8443:dids:caf%C3%A9`);
    expect(parsed).toEqual({
      did: `did:webvh:${SCID}:example.com%3A8443:dids:caf%C3%A9`,
      scid: SCID,
      domainComponent: 'example.com%3A8443',
      host: 'example.com',
      port: 8443,
      pathSegments: ['dids', 'café'],
    });
    expect(Object.isFrozen(parsed)).toBe(true);
    expect(Object.isFrozen(parsed.pathSegments)).toBe(true);
  });

  test('omits port and returns empty path segments for a bare domain', () => {
    const parsed = parseDidWebvh(`did:webvh:${SCID}:example.com`);
    expect(parsed).not.toHaveProperty('port');
    expect(parsed.pathSegments).toEqual([]);
  });

  test.each([
    ['another method', `did:web:example.com`],
    ['a malformed SCID', 'did:webvh:abc:example.com'],
    ['no domain', `did:webvh:${SCID}`],
    ['a single-label host', `did:webvh:${SCID}:localhost`],
    ['an IP address host', `did:webvh:${SCID}:127.0.0.1`],
    ['an out-of-range port', `did:webvh:${SCID}:example.com%3A70000`],
    ['a dot-segment', `did:webvh:${SCID}:example.com:..`],
    ['a fragment', `did:webvh:${SCID}:example.com#key-1`],
    ['a DID URL path', `did:webvh:${SCID}:example.com/whois`],
    ['a {SCID} template', 'did:webvh:{SCID}:example.com'],
    ['a non-string', 42 as unknown as string],
  ])('rejects %s', (_case, did) => {
    expect(() => parseDidWebvh(did)).toThrow();
  });
});

describe('didWebvhToHttps', () => {
  test.each([
    ['malformed SCID', 'did:webvh:abc:example.com'],
    ['invalid host', `did:webvh:${SCID}:localhost`],
    ['another DID method (did:web)', 'did:web:example.com'],
    ['another DID method (did:key)', 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'],
    ['DID URL path', `did:webvh:${SCID}:example.com/whois`],
    ['SCID template', 'did:webvh:{SCID}:example.com'],
  ])('rejects a DID with %s', (_case, did) => {
    expect(() => didWebvhToHttps(did)).toThrow();
  });

  test('converts a DID without adding a resource path', () => {
    expect(didWebvhToHttps(`did:webvh:${SCID}:example.com`)).toBe('https://example.com');
  });

  test('preserves DID path segments and restores the port without appending a resource path', () => {
    expect(didWebvhToHttps(`did:webvh:${SCID}:example.com%3A8443:dids:issuer`)).toBe(
      'https://example.com:8443/dids/issuer'
    );
  });

  test('maps a U-label host to its A-label form', () => {
    expect(didWebvhToHttps(`did:webvh:${SCID}:b%C3%BCcher.example`)).toBe('https://xn--bcher-kva.example');
  });

  test.each([
    [
      'host',
      `did:webvh:${SCID}:did.jsonl.example`,
      'https://did.jsonl.example',
      'https://did.jsonl.example/.well-known/did-witness.json',
    ],
    [
      'path',
      `did:webvh:${SCID}:example.com:did.jsonl`,
      'https://example.com/did.jsonl',
      'https://example.com/did.jsonl/did-witness.json',
    ],
  ])(
    'keeps conversion separate from witness URL derivation when the %s contains "did.jsonl"',
    async (_where, did, expectedBaseUrl, expectedWitnessUrl) => {
      expect(didWebvhToHttps(did)).toBe(expectedBaseUrl);
      const requested: string[] = [];
      await fetchWitnessProofs(did, async (url) => {
        requested.push(String(url));
        return new Response(null, { status: 404 });
      });
      expect(requested).toEqual([expectedWitnessUrl]);
    }
  );
});
