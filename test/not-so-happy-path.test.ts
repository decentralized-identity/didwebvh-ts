import { beforeAll, describe, expect, test } from 'bun:test';
import { type DIDLog, DidResolutionError, type VerificationMethod } from '../src/interfaces';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method';
import { resolveDIDFromLog as resolveDIDFromLogV1 } from '../src/method_versions/method.v1.0';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

describe('Not So Happy Path Tests', () => {
  let authKey: VerificationMethod;
  let testImplementation: TestCryptoImplementation;
  let initialDID: { did: string; doc: any; meta: any; log: DIDLog };

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey });

    initialDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
  });

  test('Reject DID with invalid SCID in Method specific identifier', async () => {
    // Create a modified log with an incorrect SCID
    const modifiedLog = JSON.parse(JSON.stringify(initialDID.log));

    // Tamper with the SCID in the parameters
    const originalSCID = modifiedLog[0].parameters.scid;
    modifiedLog[0].parameters.scid = `${originalSCID}tampered`;

    // Attempt to resolve the DID from the tampered log
    expect(
      resolveDIDFromLog(modifiedLog, {
        verifier: testImplementation,
      })
    ).rejects.toThrow(`SCID '${originalSCID}tampered' not derived from logEntryHash`);
  });

  test('Hash chain tampering is detected', async () => {
    // Create a DID and update it
    const { log: log1 } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const { log: log2 } = await updateDID({
      log: log1,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Tamper with entry 2's state (not the id, to avoid triggering portability check first)
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log2));
    tamperedLog[1].state.alsoKnownAs = ['did:example:tampered'];

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow('Hash chain broken');
  });

  test('Fast-resolve catches hash chain break on middle entries', async () => {
    // Build a log with 12+ entries
    let currentLog: DIDLog;
    const { log: log0 } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
    currentLog = log0;

    for (let j = 0; j < 12; j++) {
      const { log: nextLog } = await updateDID({
        log: currentLog,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      });
      currentLog = nextLog;
    }

    expect(currentLog.length).toBe(13);

    // Tamper with a middle entry (entry index 3 = version 4)
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(currentLog));
    tamperedLog[3].state.alsoKnownAs = ['did:example:tampered'];

    // Hash chain validation remains active even when fastResolve is opted in.
    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation, fastResolve: true })).rejects.toThrow(
      'Hash chain broken'
    );
  });

  test('Default resolve verifies every log entry proof', async () => {
    let currentLog: DIDLog;
    const { log: log0 } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
    currentLog = log0;

    for (let j = 0; j < 12; j++) {
      const { log: nextLog } = await updateDID({
        log: currentLog,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      });
      currentLog = nextLog;
    }

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(currentLog));
    // With 13 entries, index 1 is outside the fastResolve verification window
    // (first entry + last 10 entries), but still checked in default full mode.
    tamperedLog[1]!.proof![0]!.proofValue = 'zinvalid-proof';
    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow();

    await expect(
      resolveDIDFromLog(tamperedLog, { verifier: testImplementation, fastResolve: true })
    ).resolves.toBeDefined();
  });

  test('Error metadata on later-entry failure', async () => {
    // Create a 3-entry log
    const { log: log1 } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const { log: log2 } = await updateDID({
      log: log1,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const { log: log3 } = await updateDID({
      log: log2,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Tamper with entry 3 (index 2) to cause a hash chain break
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log3));
    tamperedLog[2].state.alsoKnownAs = ['did:example:tampered'];

    // Request version 1 — it should resolve, but with error metadata
    // because entry 3 fails verification
    const result = await resolveDIDFromLog(tamperedLog, {
      versionNumber: 1,
      verifier: testImplementation,
    });

    expect(result.doc).not.toBeNull();
    expect(result.meta.error).toBe(DidResolutionError.InvalidDid);
    expect(result.meta.problemDetails).toBeDefined();
    expect(result.meta.problemDetails!.type).toBe(
      'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID'
    );
    expect(result.meta.problemDetails!.title).toBe('The resolved DID is invalid.');
    expect(result.meta.problemDetails!.detail).toContain('Hash chain broken');
  });

  test('Protocol version rejection in v1.0', async () => {
    // Build a valid log but with the v0.5 protocol marker
    const { log } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log));
    tamperedLog[0].parameters.method = 'did:webvh:0.5';

    await expect(resolveDIDFromLogV1(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      "'did:webvh:0.5' is not a supported method version."
    );
  });
});
