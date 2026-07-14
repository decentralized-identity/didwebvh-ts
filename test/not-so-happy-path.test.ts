import { beforeAll, describe, expect, test } from 'vitest';
import type { CreateDIDInterface, CreateDIDResult, DIDLog, VerificationMethod } from '../src/interfaces';
import { createDID, deactivateDID, resolveDIDFromLog, updateDID } from '../src/method';
import { resolveDIDFromLog as resolveDIDFromLogV1 } from '../src/method_versions/method.v1.0';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm } from '../src/utils/multiformats';
import {
  asPublicVerificationMethods,
  createFutureDIDLog,
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
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
  });

  test('Reject DID with invalid SCID in Method specific identifier', async () => {
    // Create a modified log with an incorrect SCID.
    // Use a valid SHA-256 multihash that is simply not derived from the log content,
    // so we exercise the hash derivation check rather than format validation.
    const modifiedLog = JSON.parse(JSON.stringify(initialDID.log));

    const wrongDigest = new Uint8Array(32).fill(0xde);
    const wrongMultihash = createMultihash(wrongDigest, MultihashAlgorithm.SHA2_256);
    const wrongScid = encodeBase58Btc(wrongMultihash);

    modifiedLog[0].parameters.scid = wrongScid;

    // Attempt to resolve the DID from the tampered log
    const r = await resolveDIDFromLog(modifiedLog, {
      verifier: testImplementation,
    });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain(`SCID '${wrongScid}' not derived from logEntryHash`);
  });

  test('Accepts a versionTime up to 5 minutes in the future', async () => {
    const futureLog = await createFutureDIDLog(authKey, 4);

    const r = await resolveDIDFromLog(futureLog, { verifier: testImplementation });
    expect(r.didResolutionMetadata.error).toBeUndefined();
    expect(r.didDocument).not.toBeNull();
  });

  test('Rejects a versionTime more than 5 minutes in the future', async () => {
    const futureLog = await createFutureDIDLog(authKey, 6);

    const r = await resolveDIDFromLog(futureLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('must not be more than 5 minutes in the future');
  });

  test('Accepts a versionTime up to 5 minutes in the future', async () => {
    const futureLog = await createFutureDIDLog(authKey, 4);

    const r = await resolveDIDFromLog(futureLog, { verifier: testImplementation });
    expect(r.didResolutionMetadata.error).toBeUndefined();
    expect(r.didDocument).not.toBeNull();
  });

  test('Rejects a versionTime more than 5 minutes in the future', async () => {
    const futureLog = await createFutureDIDLog(authKey, 6);

    const r = await resolveDIDFromLog(futureLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('must not be more than 5 minutes in the future');
  });

  test('Hash chain tampering is detected', async () => {
    // Create a DID and update it
    const { log: log1 } = await createDID({
      address: 'example.com',
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

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('Hash chain broken');
  });

  test('Resolve catches hash chain break on middle entries', async () => {
    // Build a log with 12+ entries
    let currentLog: DIDLog;
    const { log: log0 } = await createDID({
      address: 'example.com',
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

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('Hash chain broken');
  });

  test('Default resolve verifies every log entry proof', async () => {
    let currentLog: DIDLog;
    const { log: log0 } = await createDID({
      address: 'example.com',
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
    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
  });

  test('Historical versionNumber selector remains successful when a later entry fails', async () => {
    // Create a 3-entry log
    const { log: log1 } = await createDID({
      address: 'example.com',
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

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocumentMetadata.versionId?.split('-')[0]).toBe('1');
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.problemDetails).toBeUndefined();
  });

  test('Historical versionId selector remains successful when a later entry fails', async () => {
    const { log: log1 } = await createDID({
      address: 'example.com',
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

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocumentMetadata.versionId).toBe(log1[0].versionId);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.problemDetails).toBeUndefined();
  });

  test('Historical versionTime selector remains successful when a later entry fails', async () => {
    const { log: log1 } = await createDID({
      address: 'example.com',
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

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocumentMetadata.versionId).toBe(log1[0].versionId);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.problemDetails).toBeUndefined();
  });

  test('Requested DID with matching SCID but mismatched location is rejected', async () => {
    // Build a valid log for did:webvh:SCID:example.com
    const { log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Construct a DID that shares the same SCID but points at a different location
    const originalDid = log[0].state.id as string;
    const scid = originalDid.split(':')[2];
    const mismatchedDid = `did:webvh:${scid}:different-domain.example`;

    const r = await resolveDIDFromLog(log, { requestedDid: mismatchedDid, verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toMatch(/does not match state\.id/);
  });

  test('Requested DID not present in log is rejected', async () => {
    const { log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Use a syntactically valid did:webvh that is guaranteed to differ from all state.id values in this log.
    const requestedDidNotInLog = 'did:webvh:zQmXkYw8uM9QW9sW11Qx2Jq4JfY5o7jBq3nK7f4R2m1NpQ:not-in-log.example';

    const r = await resolveDIDFromLog(log, { requestedDid: requestedDidNotInLog, verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toMatch(/does not match state\.id/);
  });

  test('rejects log where no state.id matches the resolved DID when requestedDid is omitted', async () => {
    // An empty DID log has no entries, so didIdMatchCount stays 0.
    // The spec requires didIdMatchCount > 0 after processing all entries.
    const emptyLog: DIDLog = [];

    const r = await resolveDIDFromLog(emptyLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toMatch(/no entries to process/);
  });

  test('Protocol version rejection in v1.0', async () => {
    // Build a valid log but with the v0.5 protocol marker
    const { log } = await createDID({
      address: 'example.com',
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

  test('rejects versionId with missing dash', async () => {
    const { log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log));
    tamperedLog[0].versionId = '1';

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toMatch(/must contain exactly one '-' separator/);
  });

  test('rejects versionId with multiple dashes', async () => {
    const { log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log));
    tamperedLog[0].versionId = '1-fake-hash';

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toMatch(/must contain exactly one '-' separator/);
  });

  test('rejects versionId with empty hash component', async () => {
    const { log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(log));
    tamperedLog[0].versionId = '1-';

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toMatch(/must have a non-empty hash component/);
  });

  test('Rejects unknown method value in later entry', async () => {
    const { log } = initialDID;
    const updateResult = await updateDID({
      log,
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.method = 'did:webvh:99.0';

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('has unsupported or downgraded method');
  });

  test('Rejects downgrade of method version in later entry', async () => {
    const { log } = initialDID;
    const updateResult = await updateDID({
      log,
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.method = 'did:webvh:0.5';

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('has unsupported or downgraded method');
  });

  test('Rejects scid parameter in later entry', async () => {
    const { log } = initialDID;
    const updateResult = await updateDID({
      log,
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.scid = log[0].parameters.scid;

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('must not contain SCID parameter');
  });

  test('Rejects SCID using non-SHA-256 multihash algorithm', async () => {
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(initialDID.log));
    const originalScid = tamperedLog[0].parameters.scid as string;

    // Build a SHA-384 multihash (48-byte digest) so the structure is valid but algorithm is wrong
    const fakeDigest = new Uint8Array(48).fill(0xab);
    const sha384Multihash = createMultihash(fakeDigest, MultihashAlgorithm.SHA2_384);
    const sha384Scid = encodeBase58Btc(sha384Multihash);

    // Replace every occurrence of the real SCID with the SHA-384 one
    const tamperedStr = JSON.stringify(tamperedLog).replaceAll(originalScid, sha384Scid);
    const tamperedLogWithBadScid: DIDLog = JSON.parse(tamperedStr);

    const r = await resolveDIDFromLog(tamperedLogWithBadScid, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain('SCID multihash algorithm must be SHA-256 (0x12)');
  });

  test('createDID rejects when updateKeys is not supplied', async () => {
    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: undefined as unknown as string[],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      })
    ).rejects.toThrow('Update keys not supplied');
  });

  test('createDID rejects when address is not provided', async () => {
    await expect(
      createDID({
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      } as unknown as CreateDIDInterface)
    ).rejects.toThrow('Address must be provided');
  });

  test('createDID rejects when verificationMethods is absent and no didDocument', async () => {
    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      } as unknown as CreateDIDInterface)
    ).rejects.toThrow('verificationMethods must be provided when didDocument is not supplied');
  });

  test('Rejects log entry with out-of-order version number', async () => {
    const updateResult = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    const [, hash] = tamperedLog[1].versionId.split('-');
    tamperedLog[1].versionId = `3-${hash}`;

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain("version '3' in log doesn't match expected '2'");
  });

  test('Rejects log entry with missing versionTime', async () => {
    const updateResult = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].versionTime = '';

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain("version '2' is missing versionTime");
  });

  test('Rejects log entry with non-monotonic versionTime', async () => {
    const updateResult = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].versionTime = tamperedLog[0].versionTime;

    const r = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain(
      "versionTime for version '2' must be greater than previous entry time"
    );
  });

  test('Rejects resolution when options.scid does not match the log SCID', async () => {
    const wrongScid = 'zFakeSCID123456789';
    const r = await resolveDIDFromLog(initialDID.log, {
      scid: wrongScid,
      verifier: testImplementation,
    });
    expect(r.didDocument).toBeNull();
    expect(r.didResolutionMetadata.error).toBe('invalidDid');
    expect(r.didResolutionMetadata.message).toContain(`SCID in DID '${wrongScid}' does not match SCID in log`);
  });

  test('requestedDid matching the actual DID resolves successfully', async () => {
    const result = await resolveDIDFromLog(initialDID.log, {
      requestedDid: initialDID.did,
      verifier: testImplementation,
    });

    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument?.id).toBe(initialDID.did);
  });

  test('updateDID rejects when the DID is already deactivated', async () => {
    const { log: deactivatedLog } = await deactivateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      verifier: testImplementation,
    });

    await expect(
      updateDID({
        log: deactivatedLog,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      })
    ).rejects.toThrow('Cannot update deactivated DID');
  });

  test('deactivateDID rejects when the DID is already deactivated', async () => {
    const { log: log1 } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
    const { log: deactivatedLog } = await deactivateDID({
      log: log1,
      signer: createTestSigner(authKey),
      verifier: testImplementation,
    });

    await expect(
      deactivateDID({
        log: deactivatedLog,
        signer: createTestSigner(authKey),
        verifier: testImplementation,
      })
    ).rejects.toThrow('DID already deactivated');
  });
});
