import { describe, expect, test, vi } from 'vitest';
import { generateParallelDidWeb } from '../src/did-document.js';
import { migrateDID, resolveDID, resolveDIDFromLog } from '../src/method.js';
import { createLegacyDID, createTestSigner, generateTestVerificationMethod } from './utils.js';

const legacyDid = 'did:webvh:{SCID}:b%C3%BCcher.example.com%3A8443:users';

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

describe('migrateDID converts a legacy U-label DID to its A-label form', () => {
  test.each(['bücher.example.com:8443', 'b%C3%BCcher.example.com:8443'])(
    'migrates %s with signed history and the original SCID',
    async (address) => {
      const { created, migrate, scid, verifier, update } = await createLegacyDID({
        did: legacyDid,
        portable: true,
        alsoKnownAsWeb: true,
      });
      const migrated = await migrate(address);
      expect(migrated.did).toBe(`did:webvh:${scid}:xn--bcher-kva.example.com%3A8443:users`);
      expect(migrated.doc.id).toBe(migrated.did);
      expect(migrated.doc.alsoKnownAs).toContain(created.did);
      expect(migrated.log[0]).toEqual(created.log[0]);
      expect(migrated.log[1].parameters.scid).toBeUndefined();
      expect(migrated.webDoc?.id).toBe('did:web:xn--bcher-kva.example.com%3A8443:users');
      expect((await resolveDIDFromLog(migrated.log, { verifier })).didDocument?.id).toBe(migrated.did);
      expect((await update(address)).did).toBe(created.did);
    }
  );

  test('accepts a legacy DID address with the same SCID and an injected converter', async () => {
    const { created, migrate, scid } = await createLegacyDID({ did: legacyDid, portable: true });
    const toASCII = labelConverter('bücher.example.com', 'xn--bcher-kva.example.com');
    const migrated = await migrate(created.did, undefined, toASCII);
    expect(migrated.did).toBe(`did:webvh:${scid}:xn--bcher-kva.example.com%3A8443:users`);
    expect(toASCII).toHaveBeenCalled();
  });

  test('both old and new DIDs resolve through the same A-label endpoint after publication', async () => {
    const { created, migrate, verifier } = await createLegacyDID({ did: legacyDid, portable: true });
    const migrated = await migrate('bücher.example.com:8443');
    const fetched: string[] = [];
    const fetch = servedLog(migrated.log, fetched);

    const oldResult = await resolveDID(created.did, { verifier, fetch });
    const newResult = await resolveDID(migrated.did, { verifier, fetch });

    expect(fetched).toEqual([
      'https://xn--bcher-kva.example.com:8443/users/did.jsonl',
      'https://xn--bcher-kva.example.com:8443/users/did.jsonl',
    ]);
    expect(oldResult.didResolutionMetadata.error).toBeUndefined();
    expect(newResult.didResolutionMetadata.error).toBeUndefined();
    expect(newResult.didDocument?.id).toBe(migrated.did);
  });

  describe('rejections', () => {
    test('portability was not enabled in genesis', async () => {
      const { migrate } = await createLegacyDID({ did: legacyDid });
      await expect(migrate('bücher.example.com:8443')).rejects.toThrow('portability is disabled');
    });

    test.each([
      ['A-label address', 'xn--bcher-kva.example.com:8443', undefined, 'requires a U-label address'],
      ['different host', 'bücher.other.com:8443', undefined, 'same host, port and path'],
      ['different port', 'bücher.example.com:8444', undefined, 'same host, port and path'],
      ['different path', 'bücher.example.com:8443', ['other'], 'same host, port and path'],
      ['wrong SCID', `did:webvh:${'1'.repeat(46)}:b%C3%BCcher.example.com%3A8443:users`, undefined, 'existing SCID'],
    ])('%s', async (_description, address, paths, message) => {
      const { migrate } = await createLegacyDID({ did: legacyDid, portable: true });
      await expect(migrate(address, paths)).rejects.toThrow(message);
    });

    test('a DID that is already in A-label form', async () => {
      const { migrate } = await createLegacyDID({ did: 'did:webvh:{SCID}:xn--bcher-kva.example.com', portable: true });
      await expect(migrate('bücher.example.com')).rejects.toThrow('requires a legacy U-label DID');
    });

    test('an authored document with an unrelated identity', async () => {
      const { created, verifier } = await createLegacyDID({ did: legacyDid, portable: true });
      await expect(
        migrateDID({
          log: created.log,
          address: 'bücher.example.com:8443',
          signer: createTestSigner(await generateTestVerificationMethod()),
          verifier,
          didDocument: { ...created.doc, id: 'did:example:unrelated' },
        })
      ).rejects.toThrow('Migration DID document id must match');
    });
  });
});

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
