import { beforeAll, describe, expect, test } from 'vitest';
import type { DIDLog, VerificationMethod } from '../src/interfaces';
import { createDID, deactivateDID, resolveDIDFromLog, updateDID } from '../src/method';
import { deriveHash } from '../src/utils/crypto';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

// didwebvh v1.0 §"Entry Hash Generation and Verification":
//   "The versionId used in the input to the hash is a predecessor value to the
//   current log entry... for all other entries it is the versionId property
//   from the previous log entry."
//
// This test reimplements that algorithm independently and asserts the stored
// entryHash matches. It catches the class of bug where the create or verify
// path substitutes the wrong predecessor (e.g. the "{SCID}" placeholder) for
// entries 2+ — a deviation that round-trips within the library but produces
// logs no spec-compliant resolver will accept.
async function specEntryHashForEntry(entry: DIDLog[number], previousVersionId: string): Promise<string> {
  const { proof: _proof, ...entryWithoutProof } = entry;
  return deriveHash({ ...entryWithoutProof, versionId: previousVersionId });
}

describe('didwebvh v1.0 entryHash spec compliance', () => {
  let authKey: VerificationMethod;
  let verifier: TestCryptoImplementation;
  let log: DIDLog;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    verifier = new TestCryptoImplementation({ verificationMethod: authKey });

    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      created: '2024-01-01T00:00:00Z',
      verifier,
    });
    log = created.log;

    for (const updated of ['2024-02-01T00:00:00Z', '2024-03-01T00:00:00Z']) {
      const next = await updateDID({
        log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        updated,
        verifier,
      });
      log = next.log;
    }
  });

  test("entries 2+ hash over previous entry's full versionId (not {SCID})", async () => {
    expect(log.length).toBeGreaterThanOrEqual(3);

    for (let i = 1; i < log.length; i++) {
      const entry = log[i];
      const previousVersionId = log[i - 1].versionId;
      const [, storedHash] = entry.versionId.split('-');

      const specHash = await specEntryHashForEntry(entry, previousVersionId);

      expect(specHash).toBe(storedHash);
    }
  });

  test('substituting the SCID placeholder produces a different hash (regression)', async () => {
    // Direct regression guard: if create/verify ever reverts to hashing with
    // the "{SCID}" placeholder for entries 2+, this computation would match
    // the stored hash. It must NOT match.
    const entry = log[1];
    const placeholderHash = await specEntryHashForEntry(entry, '{SCID}');
    const [, storedHash] = entry.versionId.split('-');
    expect(placeholderHash).not.toBe(storedHash);
  });

  test("deactivate entry's hash also follows the spec predecessor rule", async () => {
    const deactivated = await deactivateDID({
      log,
      signer: createTestSigner(authKey),
      verifier,
    });
    const finalLog = deactivated.log;
    const last = finalLog[finalLog.length - 1];
    const prev = finalLog[finalLog.length - 2];
    const [, storedHash] = last.versionId.split('-');

    const specHash = await specEntryHashForEntry(last, prev.versionId);
    expect(specHash).toBe(storedHash);
  });

  test('deactivation entry carries deactivated parameter and latest resolution returns null document', async () => {
    const deactivated = await deactivateDID({
      log,
      signer: createTestSigner(authKey),
      verifier,
    });

    const finalLog = deactivated.log;
    const last = finalLog[finalLog.length - 1];
    expect(last.parameters.deactivated).toBe(true);

    const resolved = await resolveDIDFromLog(finalLog, { verifier });
    expect(resolved.didDocument).toBeNull();
    expect(resolved.didDocumentMetadata.deactivated).toBe(true);
  });

  test('appending update and deactivate entries preserves earlier entries byte-for-byte', async () => {
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      created: '2024-04-01T00:00:00Z',
      verifier,
    });
    const baselineFirstEntry = JSON.parse(JSON.stringify(created.log[0]));

    const updated = await updateDID({
      log: created.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      updated: '2024-05-01T00:00:00Z',
      verifier,
    });

    const deactivated = await deactivateDID({
      log: updated.log,
      signer: createTestSigner(authKey),
      verifier,
    });

    expect(updated.log[0]).toEqual(baselineFirstEntry);
    expect(deactivated.log[0]).toEqual(baselineFirstEntry);
  });

  test('log is resolvable end-to-end (hash chain + signatures)', async () => {
    const resolved = await resolveDIDFromLog(log, { verifier });
    expect(resolved.didDocumentMetadata.versionId).toBe(log[log.length - 1].versionId);
  });
});
