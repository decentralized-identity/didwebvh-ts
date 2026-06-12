import { beforeAll, describe, expect, test } from 'bun:test';
import type { CreateDIDResult, DIDLog, VerificationMethod } from '../src/interfaces';
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
  let initialDID: CreateDIDResult;

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

  test('Resolve catches hash chain break on middle entries', async () => {
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

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow('Hash chain broken');
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
    tamperedLog[1]!.proof![0]!.proofValue = 'zinvalid-proof';
    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow();
  });

  test('Historical versionNumber selector remains successful when a later entry fails', async () => {
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

    // Tamper with entry 3 (index 2) to cause a hash chain break.
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log3));
    tamperedLog[2].state.alsoKnownAs = ['did:example:tampered'];

    // Request version 1 — it should resolve successfully even though
    // entry 3 fails verification.
    const result = await resolveDIDFromLog(tamperedLog, {
      versionNumber: 1,
      verifier: testImplementation,
    });

    expect(result.doc).not.toBeNull();
    expect(result.meta.versionId.split('-')[0]).toBe('1');
    expect(result.meta.error).toBeUndefined();
    expect(result.meta.problemDetails).toBeUndefined();
  });

  test('Historical versionId selector remains successful when a later entry fails', async () => {
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

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log3));
    tamperedLog[2].state.alsoKnownAs = ['did:example:tampered'];

    const result = await resolveDIDFromLog(tamperedLog, {
      versionId: log1[0].versionId,
      verifier: testImplementation,
    });

    expect(result.doc).not.toBeNull();
    expect(result.meta.versionId).toBe(log1[0].versionId);
    expect(result.meta.error).toBeUndefined();
    expect(result.meta.problemDetails).toBeUndefined();
  });

  test('Historical versionTime selector remains successful when a later entry fails', async () => {
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

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log3));
    tamperedLog[2].state.alsoKnownAs = ['did:example:tampered'];

    const firstVersionTime = new Date(log1[0].versionTime);
    const secondVersionTime = new Date(log2[1].versionTime);
    const midpointTime = new Date((firstVersionTime.getTime() + secondVersionTime.getTime()) / 2);

    const result = await resolveDIDFromLog(tamperedLog, {
      versionTime: midpointTime,
      verifier: testImplementation,
    });

    expect(result.doc).not.toBeNull();
    expect(result.meta.versionId).toBe(log1[0].versionId);
    expect(result.meta.error).toBeUndefined();
    expect(result.meta.problemDetails).toBeUndefined();
  });

  test('Requested DID with matching SCID but mismatched location is rejected', async () => {
    // Build a valid log for did:webvh:SCID:example.com
    const { log } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Construct a DID that shares the same SCID but points at a different location
    const originalDid = log[0].state.id as string;
    const scid = originalDid.split(':')[2];
    const mismatchedDid = `did:webvh:${scid}:different-domain.example`;

    await expect(resolveDIDFromLog(log, { requestedDid: mismatchedDid, verifier: testImplementation })).rejects.toThrow(
      /does not match state\.id/
    );
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
