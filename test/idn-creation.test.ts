import { describe, expect, test, vi } from 'vitest';
import { toASCII as tr46ToASCII } from '../src/idna.js';
import { buildDidLogUrl } from '../src/parser.js';
import { createAndResolve, expectRoundTrip } from './utils.js';

describe('createDID with internationalised domains and Unicode paths', () => {
  // Spec example: did:webvh:{SCID}:jp納豆.例.jp:用户
  //   → https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl
  const encodedDomain = 'jp%E7%B4%8D%E8%B1%86.%E4%BE%8B.jp';
  const encodedPath = '%E7%94%A8%E6%88%B7';
  const expectedUrl = 'https://xn--jp-cd2fp15c.xn--fsq.jp/%E7%94%A8%E6%88%B7/did.jsonl';

  test('injected and optional tr46 converters produce the same A-label DID', async () => {
    const converter = vi.fn(tr46ToASCII);
    const injected = await createAndResolve('BÜCHER.example.com', undefined, converter);
    expectRoundTrip(injected, (scid) => `did:webvh:${scid}:xn--bcher-kva.example.com`);
    expect(converter).toHaveBeenCalledWith('BÜCHER.example.com');
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
});
