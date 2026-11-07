import { describe, expect, test } from 'vitest';
import {
  createDID,
  getWitnessRequirements,
  resolveDIDFromLog,
  signWitnessProofEntry,
  updateDID,
} from '../src/method.js';
import { validateWitnessParameter } from '../src/witness.js';
import {
  appendRawLogEntry,
  createTestDIDDocument,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

const invalidThresholds: unknown[] = ['1', '1abc', 1.5];

const setup = async () => {
  const authKey = await generateTestVerificationMethod();
  const witnessKey = await generateTestVerificationMethod();
  const witnesses = [{ id: `did:key:${witnessKey.publicKeyMultibase}` }];
  return {
    authKey,
    witnessKey,
    witnesses,
    signer: createTestSigner(authKey),
    verifier: new TestCryptoImplementation({ verificationMethod: authKey }),
  };
};

describe('witness threshold validation', () => {
  test('validateWitnessParameter rejects string and fractional thresholds', async () => {
    const { witnesses } = await setup();
    for (const threshold of invalidThresholds) {
      expect(() => validateWitnessParameter({ witnesses, threshold: threshold as number }), String(threshold)).toThrow(
        'Witness threshold must be an integer'
      );
    }
  });

  test('createDID rejects string and fractional thresholds', async () => {
    const { authKey, witnesses, signer, verifier } = await setup();
    for (const threshold of invalidThresholds) {
      await expect(
        createDID({
          address: 'example.com',
          signer,
          verifier,
          updateKeys: [authKey.publicKeyMultibase!],
          didDocument: createTestDIDDocument(authKey),
          witness: { witnesses, threshold: threshold as number },
        }),
        String(threshold)
      ).rejects.toThrow('Witness threshold must be an integer');
    }
  });

  test('resolution and getWitnessRequirements reject a log entry with a non-integer threshold', async () => {
    const { authKey, witnesses, signer, verifier } = await setup();
    const { log: genesis } = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    for (const threshold of invalidThresholds) {
      const log = await appendRawLogEntry({ log: genesis, signer, witness: { witnesses, threshold }, verifier });

      const resolved = await resolveDIDFromLog(log, { verifier, witnessProofs: [] });
      expect(resolved.didResolutionMetadata.error, String(threshold)).toBe('invalidDid');
      expect(resolved.didResolutionMetadata.message, String(threshold)).toContain(
        'Witness threshold must be an integer'
      );
      expect(() => getWitnessRequirements(log), String(threshold)).toThrow('Witness threshold must be an integer');
    }
  });
});

describe('witness threshold in resolution metadata', () => {
  test('resolution metadata carries a string threshold while log entries and writer meta keep numbers', async () => {
    const { authKey, witnessKey, witnesses, signer, verifier } = await setup();
    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: { witnesses, threshold: 1 },
      created: '2026-01-01T00:00:00Z',
    });
    const witnessProofs = [
      await signWitnessProofEntry({
        trustedLog: [],
        candidateLog: created.log,
        witnessSigner: createTestSigner(witnessKey),
        witnessProofs: [],
        verifier,
      }),
    ];

    const resolved = await resolveDIDFromLog(created.log, { verifier, witnessProofs });
    expect(resolved.didDocumentMetadata.witness).toEqual({ witnesses, threshold: '1' });
    expect(created.log[0].parameters.witness?.threshold).toBe(1);
    expect(created.meta.witness?.threshold).toBe(1);
    expect(getWitnessRequirements(created.log)[0].threshold).toBe(1);

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      witnessProofs,
      witness: { witnesses, threshold: 1 },
      updated: '2026-01-01T00:00:01Z',
    });
    expect(updated.log[1].parameters.witness?.threshold).toBe(1);
    expect(updated.meta.witness?.threshold).toBe(1);
  });
});
