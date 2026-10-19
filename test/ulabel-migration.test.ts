import { describe, expect, test, vi } from 'vitest';
import { migrateDID, resolveDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import {
  createTestSigner,
  createUncanonicalisedDID,
  createWitnessProof,
  generateTestVerificationMethod,
  MOCK_SCID,
} from './utils.js';

const uLabelDid = 'did:webvh:{SCID}:b%C3%BCcher.example.com%3A8443:users';

function servedLog(log: unknown[], fetched: string[]) {
  return async (url: string) => {
    fetched.push(url);
    return new Response(log.map((entry) => JSON.stringify(entry)).join('\n'), { status: 200 });
  };
}

describe('migrateDID converts a percent-encoded U-label DID to its A-label form', () => {
  test.each(['bücher.example.com:8443', 'b%C3%BCcher.example.com:8443'])(
    'migrates %s with signed history and the original SCID',
    async (address) => {
      const { created, migrate, scid, verifier, update } = await createUncanonicalisedDID({
        did: uLabelDid,
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
      // An ordinary update with the same address does not migrate.
      expect((await update(address)).did).toBe(created.did);
    }
  );

  test('accepts the existing DID as the address', async () => {
    const { created, migrate, scid } = await createUncanonicalisedDID({ did: uLabelDid, portable: true });
    const migrated = await migrate(created.did);
    expect(migrated.did).toBe(`did:webvh:${scid}:xn--bcher-kva.example.com%3A8443:users`);
  });

  test('rewrites an authored document that still carries the existing DID', async () => {
    const { created, scid, signer, updateKeys, verifier } = await createUncanonicalisedDID({
      did: uLabelDid,
      portable: true,
    });
    const migrated = await migrateDID({
      log: created.log,
      address: 'bücher.example.com:8443',
      signer,
      updateKeys,
      verifier,
      didDocument: created.doc,
    });
    expect(migrated.doc.id).toBe(`did:webvh:${scid}:xn--bcher-kva.example.com%3A8443:users`);
  });

  test('both old and new DIDs resolve through the same A-label endpoint after publication', async () => {
    const { created, migrate, verifier } = await createUncanonicalisedDID({ did: uLabelDid, portable: true });
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

  test('fetches witness proofs for the existing log with a custom fetch override', async () => {
    const witness = await generateTestVerificationMethod();
    const witnessVm = `did:key:${witness.publicKeyMultibase}#${witness.publicKeyMultibase}`;
    const witnessSigner = createTestSigner(witness);
    const { created, signer, updateKeys, verifier } = await createUncanonicalisedDID({
      did: uLabelDid,
      portable: true,
      witness: { threshold: 1, witnesses: [{ id: `did:key:${witness.publicKeyMultibase}` }] },
    });
    const genesisProof = await createWitnessProof(
      async (document, proof) => {
        if (!proof) {
          throw new Error('Witness proof template is required');
        }
        return { proof: await witnessSigner.sign({ document, proof }) };
      },
      created.log[0].versionId,
      witnessVm
    );
    const publishedProofs = [{ versionId: created.log[0].versionId, proof: [genesisProof] }];
    const customFetch = vi.fn(async () => new Response(JSON.stringify(publishedProofs), { status: 200 }));
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('global fetch should not be called'));

    try {
      const migrated = await migrateDID({
        log: created.log,
        address: 'bücher.example.com:8443',
        signer,
        updateKeys,
        verifier,
        fetch: customFetch,
      });

      expect(customFetch).toHaveBeenCalledExactlyOnceWith(
        'https://xn--bcher-kva.example.com:8443/users/did-witness.json'
      );
      expect(fetchSpy).not.toHaveBeenCalled();
      expect(migrated.log[1].parameters).not.toHaveProperty('witness');
      expect(migrated.meta.witness).toEqual(created.log[0].parameters.witness);
    } finally {
      fetchSpy.mockRestore();
    }
  });

  test('verifies the existing log once, like updateDID', async () => {
    const { created, migrate, update, verifier } = await createUncanonicalisedDID({ did: uLabelDid, portable: true });
    const verify = vi.spyOn(verifier, 'verify');
    await update('example.org');
    const updateCalls = verify.mock.calls.length;
    verify.mockClear();
    await migrate(created.did);
    expect(verify.mock.calls.length).toBe(updateCalls);
  });

  test('updateDID cannot migrate by authoring the A-label DID as the document id', async () => {
    const { created, scid, signer, updateKeys, verifier } = await createUncanonicalisedDID({
      did: uLabelDid,
      portable: true,
    });
    await expect(
      updateDID({
        log: created.log,
        address: 'bücher.example.com:8443',
        signer,
        updateKeys,
        verifier,
        didDocument: { ...created.doc, id: `did:webvh:${scid}:xn--bcher-kva.example.com%3A8443:users` },
      })
    ).rejects.toThrow('Updated DID document id must match expected DID');
  });

  describe('rejections', () => {
    test('portability was not enabled in genesis', async () => {
      const { migrate } = await createUncanonicalisedDID({ did: uLabelDid });
      await expect(migrate('bücher.example.com:8443')).rejects.toThrow('portability is disabled');
    });

    test('portability was disabled after genesis', async () => {
      const { created, signer, updateKeys, verifier } = await createUncanonicalisedDID({
        did: uLabelDid,
        portable: true,
      });
      const disabled = await updateDID({ log: created.log, signer, updateKeys, verifier, portable: false });
      await expect(
        migrateDID({ log: disabled.log, address: 'bücher.example.com:8443', signer, updateKeys, verifier })
      ).rejects.toThrow('Cannot migrate DID: portability is disabled');
    });

    test.each([
      ['A-label address', 'xn--bcher-kva.example.com:8443', undefined, 'requires a U-label address'],
      ['different host', 'bücher.other.com:8443', undefined, 'same host, port and path'],
      ['different port', 'bücher.example.com:8444', undefined, 'same host, port and path'],
      ['different path', 'bücher.example.com:8443', ['other'], 'same host, port and path'],
      ['wrong SCID', `did:webvh:${MOCK_SCID}:b%C3%BCcher.example.com%3A8443:users`, undefined, 'existing SCID'],
    ])('%s', async (_description, address, paths, message) => {
      const { migrate } = await createUncanonicalisedDID({ did: uLabelDid, portable: true });
      await expect(migrate(address, paths)).rejects.toThrow(message);
    });

    test('a DID that is already in A-label form', async () => {
      const { migrate } = await createUncanonicalisedDID({
        did: 'did:webvh:{SCID}:xn--bcher-kva.example.com',
        portable: true,
      });
      await expect(migrate('bücher.example.com')).rejects.toThrow('requires a percent-encoded U-label DID');
    });

    test('an authored document with an unrelated identity', async () => {
      const { created, signer, updateKeys, verifier } = await createUncanonicalisedDID({
        did: uLabelDid,
        portable: true,
      });
      await expect(
        migrateDID({
          log: created.log,
          address: 'bücher.example.com:8443',
          signer,
          updateKeys,
          verifier,
          didDocument: { ...created.doc, id: 'did:example:unrelated' },
        })
      ).rejects.toThrow('Migration DID document id must match');
    });
  });
});
