import { afterEach, describe, expect, test, vi } from 'vitest';
import { deactivateDID, resolveDID } from '../src/method.js';
import { buildDidLogUrl, getBaseUrl, parseCanonicalAddress, parseDidWebvhIdentifier } from '../src/parser.js';
import { createAndResolve, createUncanonicalisedDID, expectRoundTrip, MOCK_SCID } from './utils.js';

describe('Internationalized domain handling', () => {
  test('handles Unicode domain labels', () => {
    const did = `did:webvh:${MOCK_SCID}:${encodeURIComponent('bücher.example')}`;
    expect(getBaseUrl(did)).toBe('https://xn--bcher-kva.example');
    expect(buildDidLogUrl(did)).toBe('https://xn--bcher-kva.example/.well-known/did.jsonl');
  });

  test('decodes encoded port numbers', () => {
    const did = `did:webvh:${MOCK_SCID}:${encodeURIComponent('例子.测试')}%3A8080`;
    expect(getBaseUrl(did)).toBe('https://xn--fsqu00a.xn--0zwm56d:8080');
    expect(buildDidLogUrl(did)).toBe('https://xn--fsqu00a.xn--0zwm56d:8080/.well-known/did.jsonl');
  });

  test('arabic domain example', () => {
    const did = `did:webvh:${MOCK_SCID}:${encodeURIComponent('مثال.إختبار')}`;
    expect(getBaseUrl(did)).toBe('https://xn--mgbh0fb.xn--kgbechtv');
  });

  test('rejects raw (unencoded) Unicode in a DID', () => {
    expect(() => parseDidWebvhIdentifier(`did:webvh:${MOCK_SCID}:bücher.example`, 'DID')).toThrow(
      'DID must be a valid did:webvh identifier'
    );
  });
});

describe('createDID with internationalised domains and Unicode paths', () => {
  // Spec example: did:webvh:{SCID}:jp納豆.例.jp:用户
  //   → https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl
  const encodedDomain = 'jp%E7%B4%8D%E8%B1%86.%E4%BE%8B.jp';
  const encodedPath = '%E7%94%A8%E6%88%B7';
  const expectedUrl = 'https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl';

  test('uppercase Unicode domain becomes a lowercase A-label', async () => {
    const result = await createAndResolve('BÜCHER.example.com');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--bcher-kva.example.com`);
  });

  test('raw Unicode domain becomes an A-label while the path is percent-encoded', async () => {
    const result = await createAndResolve('jp納豆.例.jp', ['用户']);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
    expect(buildDidLogUrl(result.created.did)).toBe(expectedUrl);
  });

  test('HTTPS address preserves the same canonical Unicode domain', async () => {
    const result = await createAndResolve('https://jp納豆.例.jp/用户');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
    expect(buildDidLogUrl(result.created.did)).toBe(expectedUrl);
  });

  test('pre-encoded domain and path produce the identical DID', async () => {
    const result = await createAndResolve(encodedDomain, [encodedPath]);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
    expect(buildDidLogUrl(result.created.did)).toBe(expectedUrl);
  });

  test('lowercase pre-encoding is canonicalised to uppercase hex', async () => {
    const result = await createAndResolve(encodedDomain.toLowerCase(), [encodedPath.toLowerCase()]);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--jp-cd2fp15c.xn--fsq.jp:${encodedPath}`);
  });

  test('NFD domain input is NFC-normalised before conversion', async () => {
    const result = await createAndResolve('bu\u0308cher.example.com');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--bcher-kva.example.com`);
  });

  test('IDN with an encoded port', async () => {
    const result = await createAndResolve('例え.テスト:8443');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--r8jz45g.xn--zckzah%3A8443`);
    expect(buildDidLogUrl(result.created.did)).toBe('https://xn--r8jz45g.xn--zckzah:8443/.well-known/did.jsonl');
  });

  test('HTTPS address preserves an IDN with an explicit port', async () => {
    const result = await createAndResolve('https://例え.テスト:8443');
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:xn--r8jz45g.xn--zckzah%3A8443`);
    expect(buildDidLogUrl(result.created.did)).toBe('https://xn--r8jz45g.xn--zckzah:8443/.well-known/did.jsonl');
  });

  test('non-idchar ASCII in a path segment is percent-encoded', async () => {
    const result = await createAndResolve('example.com', ['a~b', 'c d', "!'()*"]);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:example.com:a%7Eb:c%20d:%21%27%28%29%2A`);
  });

  test('IDN combined with {SCID} placeholders', async () => {
    const result = await createAndResolve('{SCID}.例.jp', ['用户', '{SCID}']);
    expectRoundTrip(result, (scid) => `did:webvh:${scid}:${scid}.xn--fsq.jp:${encodedPath}:${scid}`);
  });

  test('rejects Unicode and {SCID} in the same domain label', () => {
    expect(() => parseCanonicalAddress('{SCID}例.jp')).toThrow('Unicode and {SCID} cannot share a domain label');
  });

  test('rejects an unpaired surrogate', () => {
    expect(() => parseCanonicalAddress('\uD800.example.com')).toThrow(
      'Address input contains ill-formed Unicode (unpaired surrogate)'
    );
  });
});

describe('uncanonicalised percent-encoded U-label DIDs', () => {
  const uncanonicalisedDid = 'did:webvh:{SCID}:b%C3%BCcher.example.com';

  function servedLog(log: unknown[], fetched: string[]) {
    return async (url: string) => {
      fetched.push(url);
      return new Response(log.map((entry) => JSON.stringify(entry)).join('\n'), { status: 200 });
    };
  }

  test('resolution keeps the DID while fetching the A-label host', async () => {
    const { created, verifier } = await createUncanonicalisedDID({ did: uncanonicalisedDid });
    const fetched: string[] = [];
    const result = await resolveDID(created.did, { verifier, fetch: servedLog(created.log, fetched) });
    expect(fetched).toEqual(['https://xn--bcher-kva.example.com/.well-known/did.jsonl']);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(created.did);
  });

  test('updating with the same location keeps the uncanonicalised DID', async () => {
    const { created, update } = await createUncanonicalisedDID({ did: uncanonicalisedDid });
    expect((await update(created.did)).did).toBe(created.did);
    expect((await update('bücher.example.com')).did).toBe(created.did);
  });

  test('deactivateDID keeps the uncanonicalised DID', async () => {
    const { created, signer, updateKeys, verifier } = await createUncanonicalisedDID({ did: uncanonicalisedDid });
    const deactivated = await deactivateDID({ log: created.log, signer, updateKeys, verifier });
    expect(deactivated.did).toBe(created.did);
    expect(deactivated.meta.deactivated).toBe(true);
  });
});

describe('runtimes whose URL does not support IDNA', () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  test('Unicode hosts are rejected with a clear error; ASCII hosts still work', async () => {
    vi.resetModules();
    const parser = await import('../src/parser.js');
    const RealURL = URL;
    vi.stubGlobal(
      'URL',
      class extends RealURL {
        override get hostname() {
          return super.hostname.replace(/^xn--/, '');
        }
      }
    );

    expect(() => parser.parseCanonicalAddress('bücher.example')).toThrow(
      "This runtime's URL implementation does not support IDNA; use an A-label (xn--) domain instead"
    );
    expect(parser.parseCanonicalAddress('xn--bcher-kva.example').didDomainComponent).toBe('xn--bcher-kva.example');
  });
});
