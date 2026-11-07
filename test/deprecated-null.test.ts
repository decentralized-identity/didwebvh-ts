import { describe, expect, test } from 'vitest';
import type { DIDLog, DIDLogEntry } from '../src/interfaces.js';
import { createDID, resolveDIDFromLog } from '../src/method.js';
import { deriveHash } from '../src/utils/crypto.js';
import {
  appendRawLogEntry,
  createTestDIDDocument,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
} from './utils.js';

// did:webvh v1.0 deprecates null parameter values but requires resolvers to accept them gracefully.
describe('deprecated null parameter values', () => {
  test('a log entry with nextKeyHashes: null resolves and normalizes to []', async () => {
    const authKey = await generateTestVerificationMethod('key-1');
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const genesis = await createDID({
      address: 'example.com',
      signer,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier,
      created: '2024-01-01T00:00:00Z',
    });

    // updateDID never writes null, so append the entry directly.
    const log1 = await appendRawLogEntry({
      log: genesis.log,
      signer,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      nextKeyHashes: null,
      versionTime: '2024-01-01T00:00:01Z',
      verifier,
    });

    expect(log1[1].parameters.nextKeyHashes).toBeNull();

    const result = await resolveDIDFromLog(log1, { verifier });

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocumentMetadata.prerotation).toBe(false);
    expect(result.didDocumentMetadata.nextKeyHashes).toEqual([]);
  });

  test('a log entry with ttl: null resolves and normalizes ttl to the default', async () => {
    const authKey = await generateTestVerificationMethod('key-1');
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const genesis = await createDID({
      address: 'example.com',
      signer,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier,
      created: '2024-01-01T00:00:00Z',
    });

    const previousEntry = genesis.log[0];
    const entryWithoutProof: DIDLogEntry = {
      versionId: previousEntry.versionId,
      versionTime: '2024-01-01T00:00:01Z',
      parameters: { ttl: null },
      state: previousEntry.state,
    };
    const entryHash = await deriveHash({ ...entryWithoutProof, versionId: previousEntry.versionId });
    const entryToSign: DIDLogEntry = {
      ...entryWithoutProof,
      versionId: `2-${entryHash}`,
    };
    const proofTemplate = {
      type: 'DataIntegrityProof' as const,
      cryptosuite: 'eddsa-jcs-2022' as const,
      verificationMethod: signer.getVerificationMethodId(),
      created: '2024-01-01T00:00:01Z',
      proofPurpose: 'assertionMethod' as const,
    };
    const signedProof = await signer.sign({ document: entryToSign, proof: proofTemplate });

    const log1: DIDLog = [
      ...genesis.log,
      { ...entryToSign, proof: [{ ...proofTemplate, proofValue: signedProof.proofValue }] },
    ];
    expect(log1[1].parameters.ttl).toBeNull();

    const result = await resolveDIDFromLog(log1, { verifier });

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocumentMetadata.ttl).toBe('3600');
  });
});
