import { describe, expect, test, vi } from 'vitest';
import { generateParallelDidWeb } from '../src/did-document.js';
import { resolveDID } from '../src/method.js';
import { createLegacyDID } from './utils.js';

function labelConverter(expectedHost: string, aLabel: string) {
  return vi.fn((host: string) => {
    expect(host).toBe(expectedHost);
    return aLabel;
  });
}

function servedLog(log: unknown[], fetched: string[]) {
  return async (url: string) => {
    fetched.push(url);
    return new Response(log.map((entry) => JSON.stringify(entry)).join('\n'), { status: 200 });
  };
}

describe('legacy U-label DIDs without migration', () => {
  test('resolution keeps the DID while fetching the A-label host', async () => {
    const { created, verifier, update } = await createLegacyDID({ did: 'did:webvh:{SCID}:b%C3%BCcher.example.com' });
    const toASCII = labelConverter('bücher.example.com', 'xn--bcher-kva.example.com');
    const fetched: string[] = [];
    const result = await resolveDID(created.did, { verifier, toASCII, fetch: servedLog(created.log, fetched) });
    expect(fetched).toEqual(['https://xn--bcher-kva.example.com/.well-known/did.jsonl']);
    expect(result.didDocument?.id).toBe(created.did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(toASCII).toHaveBeenCalled();
    expect((await update(created.did)).did).toBe(created.did);
  });

  test('updateDID passes the injected converter to parallel did:web services', async () => {
    const { created, update } = await createLegacyDID({
      did: 'did:webvh:{SCID}:b%C3%BCcher.example.com',
      alsoKnownAsWeb: true,
    });
    const toASCII = labelConverter('bücher.example.com', 'legacy-host.example.com');

    const updated = await update(created.did, undefined, toASCII);

    expect(updated.did).toBe(created.did);
    expect(updated.webDoc?.id).toBe('did:web:b%C3%BCcher.example.com');
    expect(updated.webDoc?.service?.find((service) => service.id === '#files')?.serviceEndpoint).toBe(
      'https://legacy-host.example.com/'
    );
    expect(toASCII).toHaveBeenCalled();
  });

  test('generateParallelDidWeb uses the injected converter for the files endpoint', async () => {
    const { created } = await createLegacyDID({ did: 'did:webvh:{SCID}:b%C3%BCcher.example.com' });
    const toASCII = labelConverter('bücher.example.com', 'legacy-host.example.com');

    const webDoc = generateParallelDidWeb(created.did, created.doc, toASCII);

    expect(webDoc.service?.find((service) => service.id === '#files')?.serviceEndpoint).toBe(
      'https://legacy-host.example.com/'
    );
    expect(toASCII).toHaveBeenCalled();
  });
});
