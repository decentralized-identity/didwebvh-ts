import { beforeAll, describe, expect, test } from 'vitest';
import type { DIDLog, DIDLogEntry } from '../src/interfaces';
import { createDID, deactivateDID, resolveDIDFromLog, updateDID } from '../src/method';
import { deriveHash, deriveNextKeyHash } from '../src/utils/crypto';
import {
  appendV05LogEntry,
  asPublicVerificationMethods,
  buildV05Genesis,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
} from './utils';

describe('Backwards Compatibility', () => {
  describe('v0.5 Genesis Resolution', () => {
    test('Pure v0.5 genesis resolves', async () => {
      const authKey = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const signer = createTestSigner(authKey);
      const verifier = createTestVerifier(authKey);

      const log = await buildV05Genesis({
        address: 'example.com',
        signer,
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        versionTime: '2024-01-01T00:00:00Z',
        verifier,
      });

      const result = await resolveDIDFromLog(log, { verifier });

      expect(result.didDocument).not.toBeNull();
      expect(result.didDocument?.id).toContain(':example.com');
      expect(result.didDocumentMetadata.versionId).toBe(log[0].versionId);
      expect(result.didDocumentMetadata.versionId).toMatch(/^1-/);
    });

    test('v0.5 genesis + v0.5 update chain resolves; update omits unchanged parameters', async () => {
      const authKey = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const signer = createTestSigner(authKey);
      const verifier = createTestVerifier(authKey);

      const log0 = await buildV05Genesis({
        address: 'example.com',
        signer,
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        versionTime: '2024-01-01T00:00:00Z',
        verifier,
      });

      const log1 = await appendV05LogEntry({
        log: log0,
        signer,
        verificationMethods: asPublicVerificationMethods(authKey),
        versionTime: '2024-01-01T00:00:01Z',
        verifier,
      });

      // Unchanged parameters must be omitted (carried forward by omission, including method)
      expect('method' in log1[1].parameters).toBe(false);
      expect('updateKeys' in log1[1].parameters).toBe(false);

      const result = await resolveDIDFromLog(log1, { verifier });

      expect(result.didDocument).not.toBeNull();
      expect(result.didDocumentMetadata.versionId).toBe(log1[1].versionId);
      expect(result.didDocumentMetadata.versionId).toMatch(/^2-/);
      expect(result.didDocumentMetadata.updateKeys).toEqual([authKey.publicKeyMultibase!]);
    });

    test('v0.5 update entry with nextKeyHashes: null disables prerotation', async () => {
      const authKey1 = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const authKey2 = await generateTestVerificationMethod('assertionMethod', 'key-2');
      const signer1 = createTestSigner(authKey1);
      const signer2 = createTestSigner(authKey2);
      const verifier = createTestVerifier(authKey1);

      const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);

      const log0 = await buildV05Genesis({
        address: 'example.com',
        signer: signer1,
        updateKeys: [authKey1.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey1),
        nextKeyHashes: [nextKeyHash],
        versionTime: '2024-01-01T00:00:00Z',
        verifier,
      });

      // Use nextKeyHashes: null — the v0.5-spec representation for disabling pre-rotation
      const log1 = await appendV05LogEntry({
        log: log0,
        signer: signer2,
        updateKeys: [authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey2),
        nextKeyHashes: null,
        versionTime: '2024-01-01T00:00:01Z',
        verifier,
      });

      // The log entry must carry null, not an empty array
      expect(log1[1].parameters.nextKeyHashes).toBeNull();

      const result = await resolveDIDFromLog(log1, { verifier });

      expect(result.didDocumentMetadata.prerotation).toBe(false);
      expect(result.didDocumentMetadata.nextKeyHashes).toEqual([]);
    });

    test('v1.0 log entry with deprecated nextKeyHashes: null resolves and normalizes to []', async () => {
      const authKey = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const signer = createTestSigner(authKey);
      const verifier = createTestVerifier(authKey);

      const genesis = await createDID({
        address: 'example.com',
        signer,
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier,
        created: '2024-01-01T00:00:00Z',
      });

      // nextKeyHashes: null is deprecated in v1.0; resolvers MUST accept it gracefully
      // Use v0.5 log builder because updateDID does not use null. Identical hash chain algorithm
      const log1 = await appendV05LogEntry({
        log: genesis.log,
        signer,
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
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

    test('carry-forward omitted updateKeys across multiple v0.5 entries', async () => {
      const authKey = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const signer = createTestSigner(authKey);
      const verifier = createTestVerifier(authKey);

      const log0 = await buildV05Genesis({
        address: 'example.com',
        signer,
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        versionTime: '2024-01-01T00:00:00Z',
        verifier,
      });

      const log1 = await appendV05LogEntry({
        log: log0,
        signer,
        versionTime: '2024-01-01T00:00:01Z',
        verifier,
      });

      const log2 = await appendV05LogEntry({
        log: log1,
        signer,
        versionTime: '2024-01-01T00:00:02Z',
        verifier,
      });

      expect('updateKeys' in log1[1].parameters).toBe(false);
      expect('method' in log1[1].parameters).toBe(false);
      expect('updateKeys' in log2[2].parameters).toBe(false);
      expect('method' in log2[2].parameters).toBe(false);

      const result = await resolveDIDFromLog(log2, { verifier });
      expect(result.didDocument).not.toBeNull();
      expect(result.didDocumentMetadata.versionId).toBe(log2[2].versionId);
      expect(result.didDocumentMetadata.updateKeys).toEqual([authKey.publicKeyMultibase!]);
    });

    test('Coherently signed v0.5 entry with wrong predecessor value is rejected', async () => {
      const authKey = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const signer = createTestSigner(authKey);
      const verifier = createTestVerifier(authKey);

      const log0 = await buildV05Genesis({
        address: 'example.com',
        signer,
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        versionTime: '2024-01-01T00:00:00Z',
        verifier,
      });

      // Build a preliminary entry whose versionId is the SCID instead of the previous entry's
      // full published versionId.  Per the v0.5 spec the preliminary entry must use the previous
      // entry's full versionId; using the bare SCID violates that rule.
      const scid = log0[0].parameters.scid as string;
      const wrongPrelimEntry = {
        versionId: scid, // wrong — correct value would be log0[0].versionId ("1-<hash>")
        versionTime: '2024-01-01T00:00:01Z',
        parameters: {} as DIDLogEntry['parameters'],
        state: log0[0].state,
      };
      const wrongHash = await deriveHash(wrongPrelimEntry);
      const wrongVersionId = `2-${wrongHash}`;
      const entryToSign = { ...wrongPrelimEntry, versionId: wrongVersionId };

      const proofTemplate = {
        type: 'DataIntegrityProof' as const,
        cryptosuite: 'eddsa-jcs-2022' as const,
        verificationMethod: signer.getVerificationMethodId(),
        created: '2024-01-01T00:00:01Z',
        proofPurpose: 'assertionMethod' as const,
      };
      const signedProof = await signer.sign({ document: entryToSign, proof: proofTemplate });

      const badLog: DIDLog = [
        ...log0,
        { ...entryToSign, proof: [{ ...proofTemplate, proofValue: signedProof.proofValue }] },
      ];

      const result = await resolveDIDFromLog(badLog, { verifier });

      expect(result.didDocument).toBeNull();
      expect(result.didResolutionMetadata.error).toBe('invalidDid');
      expect(result.didResolutionMetadata.message).toContain('Hash chain broken');
    });
  });

  describe('Mixed v0.5-to-v1.0 Version Transitions', () => {
    let authKey1: Awaited<ReturnType<typeof generateTestVerificationMethod>>;
    let authKey2: Awaited<ReturnType<typeof generateTestVerificationMethod>>;
    let authKey3: Awaited<ReturnType<typeof generateTestVerificationMethod>>;
    let signer1: ReturnType<typeof createTestSigner>;
    let signer2: ReturnType<typeof createTestSigner>;
    let signer3: ReturnType<typeof createTestSigner>;
    let testVerifier: ReturnType<typeof createTestVerifier>;
    let log0: DIDLog;
    let log1: DIDLog;
    let log2: DIDLog;
    let log3: DIDLog;

    beforeAll(async () => {
      // Create three key pairs
      authKey1 = await generateTestVerificationMethod('assertionMethod', 'key-1');
      authKey2 = await generateTestVerificationMethod('assertionMethod', 'key-2');
      authKey3 = await generateTestVerificationMethod('assertionMethod', 'key-3');

      // Create signers
      signer1 = createTestSigner(authKey1);
      signer2 = createTestSigner(authKey2);
      signer3 = createTestSigner(authKey3);
      testVerifier = createTestVerifier(authKey1);

      // Entry 1: v0.5 genesis
      log0 = await buildV05Genesis({
        address: 'example.com',
        signer: signer1,
        updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!, authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey1),
        versionTime: '2024-01-01T00:00:00Z',
        verifier: testVerifier,
      });

      // Entry 2: v0.5 update (no method parameter, stays v0.5)
      log1 = await appendV05LogEntry({
        log: log0,
        signer: signer2,
        updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!, authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey2),
        versionTime: '2024-01-01T00:00:01Z',
        verifier: testVerifier,
      });

      // Entry 3: v0.5 → v1.0 transition (method: 'did:webvh:1.0')
      const result2 = await updateDID({
        log: log1,
        signer: signer3,
        updateKeys: [authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey3),
        updated: '2024-01-01T00:00:02Z',
        verifier: testVerifier,
      });
      log2 = result2.log;

      // Entry 4: v1.0 update (no method parameter, stays v1.0)
      const result3 = await updateDID({
        log: log2,
        signer: signer3,
        updateKeys: [authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey3),
        updated: '2024-01-01T00:00:03Z',
        verifier: testVerifier,
      });
      log3 = result3.log;
    });

    test('Valid mixed-version chain resolves to the v1.0 final state', async () => {
      const result = await resolveDIDFromLog(log3, { verifier: testVerifier });

      expect(result.didDocument).not.toBeNull();
      expect(result.didDocument?.id).toContain(':example.com');
      expect(result.didDocumentMetadata.versionId).toBe(log3[3].versionId);
      expect(result.didDocumentMetadata.versionId).toMatch(/^4-/);
    });

    test('v1.0 transition entry contains method: did:webvh:1.0; subsequent v1.0 update omits method', async () => {
      // log2 entry 3 is the transition; log3 entry 4 is the subsequent v1.0 update
      expect(log2[2].parameters.method).toBe('did:webvh:1.0');
      expect('method' in log3[3].parameters).toBe(false);

      const result = await resolveDIDFromLog(log3, { verifier: testVerifier });
      expect(result.didDocument).not.toBeNull();
      expect(result.didDocumentMetadata.versionId).toBe(log3[3].versionId);
    });

    test('Historical selector on the v0.5 side returns the correct document', async () => {
      const result = await resolveDIDFromLog(log3, { versionNumber: 1, verifier: testVerifier });

      // Should resolve to the genesis state
      expect(result.didDocument).not.toBeNull();
      expect(result.didDocument?.id).toContain(':example.com');
      expect(result.didDocumentMetadata.versionId).toBe(log3[0].versionId);
      expect(result.didDocumentMetadata.versionId).toMatch(/^1-/);
    });

    test('Same-version re-declaration is accepted as a no-op', async () => {
      const logWithV05Redeclare = await appendV05LogEntry({
        log: log0,
        signer: signer2,
        method: 'did:webvh:0.5',
        updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!, authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey2),
        versionTime: '2024-01-02T00:00:00Z',
        verifier: testVerifier,
      });

      const logWithV10Transition = await appendV05LogEntry({
        log: logWithV05Redeclare,
        signer: signer3,
        method: 'did:webvh:1.0',
        updateKeys: [authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey3),
        versionTime: '2024-01-02T00:00:01Z',
        verifier: testVerifier,
      });

      const logWithV10Redeclare = await appendV05LogEntry({
        log: logWithV10Transition,
        signer: signer3,
        method: 'did:webvh:1.0',
        updateKeys: [authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey3),
        versionTime: '2024-01-02T00:00:02Z',
        verifier: testVerifier,
      });

      const result = await resolveDIDFromLog(logWithV10Redeclare, { verifier: testVerifier });

      expect(result.didDocument).not.toBeNull();
      expect(result.didResolutionMetadata.error).toBeUndefined();
      expect(result.didDocumentMetadata.versionId).toBe(logWithV10Redeclare[3].versionId);
    });

    test('Downgrade after transition is rejected', async () => {
      const tamperedLog = JSON.parse(JSON.stringify(log3));
      // Method-version transition checks execute before hash-chain/proof validation in resolver processing.
      // Change entry 4 (index 3) from active v1.0 back to v0.5.
      tamperedLog[3].parameters.method = 'did:webvh:0.5';

      const result = await resolveDIDFromLog(tamperedLog, { verifier: testVerifier });

      expect(result.didDocument).toBeNull();
      expect(result.didResolutionMetadata.error).toBe('invalidDid');
      expect(result.didResolutionMetadata.message).toMatch(
        /downgrade|backward|unsupported|second method-version transition/i
      );
    });

    test('Broken hash link exactly at the transition entry is rejected', async () => {
      const tamperedLog = JSON.parse(JSON.stringify(log2));
      // Corrupt the hash component of entry 3's versionId
      const [versionNumber, hash] = tamperedLog[2].versionId.split('-');
      const corruptedHash = hash.slice(0, -1) + (hash[hash.length - 1] === 'a' ? 'b' : 'a');
      tamperedLog[2].versionId = `${versionNumber}-${corruptedHash}`;

      const result = await resolveDIDFromLog(tamperedLog, { verifier: testVerifier });

      expect(result.didDocument).toBeNull();
      expect(result.didResolutionMetadata.error).toBe('invalidDid');
      expect(result.didResolutionMetadata.message).toContain('Hash chain broken');
    });

    test('Transition entry signed only by an unauthorized new key is rejected', async () => {
      const tamperedLog = JSON.parse(JSON.stringify(log2));
      // Entry 3 (transition) is signed by key3, but previous keys (key1, key2) are not in updateKeys
      // The proof verification should fail because the signer must be in the active updateKeys from entry 2
      const unauthorizedKey = await generateTestVerificationMethod('assertionMethod', 'unauthorized');
      const unauthorizedSigner = createTestSigner(unauthorizedKey);

      // Re-sign entry 3 with the unauthorized key (corrupting the existing proof)
      const proofTemplate = {
        type: 'DataIntegrityProof' as const,
        cryptosuite: 'eddsa-jcs-2022' as const,
        verificationMethod: unauthorizedSigner.getVerificationMethodId(),
        created: tamperedLog[2].versionTime,
        proofPurpose: 'assertionMethod' as const,
      };

      const entryForSigning = { ...tamperedLog[2] };
      delete entryForSigning.proof;
      const signedProof = await unauthorizedSigner.sign({ document: entryForSigning, proof: proofTemplate });
      tamperedLog[2].proof = [{ ...proofTemplate, proofValue: signedProof.proofValue }];

      const result = await resolveDIDFromLog(tamperedLog, { verifier: testVerifier });

      expect(result.didDocument).toBeNull();
      expect(result.didResolutionMetadata.error).toBe('invalidDid');
      expect(result.didResolutionMetadata.message).toMatch(/not authorized|authorization|proof|signer/i);
    });

    test('updateDID on v0.5 genesis produces v1.0 entry', async () => {
      const authKey1 = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const authKey2 = await generateTestVerificationMethod('assertionMethod', 'key-2');
      const signer1 = createTestSigner(authKey1);
      const signer2 = createTestSigner(authKey2);
      const verifier = createTestVerifier(authKey1);

      // Create v0.5 genesis
      const v05Log = await buildV05Genesis({
        address: 'example.com',
        signer: signer1,
        updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey1),
        verifier,
      });

      // Genesis entry should have v0.5 method
      expect(v05Log[0].parameters.method).toBe('did:webvh:0.5');

      // Call updateDID with new signer
      const result = await updateDID({
        log: v05Log,
        signer: signer2,
        updateKeys: [authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey2),
        verifier,
      });

      // Updated log should have 2 entries
      expect(result.log).toHaveLength(2);

      // Latest entry should automatically take v1.0 shape: has method parameter set to v1.0
      const latestEntry = result.log[1];
      expect(latestEntry.parameters.method).toBe('did:webvh:1.0');

      // Verify resolution works and returns v1.0 state
      const resolved = await resolveDIDFromLog(result.log, { verifier });
      expect(resolved.didDocument).not.toBeNull();
      expect(resolved.didDocumentMetadata.versionId).toBe(latestEntry.versionId);
    });

    test('deactivateDID on v0.5 genesis produces v1.0 entry', async () => {
      const authKey = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const signer = createTestSigner(authKey);
      const verifier = createTestVerifier(authKey);

      // Create v0.5 genesis
      const v05Log = await buildV05Genesis({
        address: 'example.com',
        signer,
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier,
      });

      // Genesis entry should have v0.5 method
      expect(v05Log[0].parameters.method).toBe('did:webvh:0.5');

      // Call deactivateDID
      const result = await deactivateDID({
        log: v05Log,
        signer,
        verifier,
      });

      // Updated log should have 2 entries
      expect(result.log).toHaveLength(2);

      // Latest entry should automatically take v1.0 shape: has method parameter set to v1.0
      const latestEntry = result.log[1];
      expect(latestEntry.parameters.method).toBe('did:webvh:1.0');

      // Deactivation should be marked
      expect(latestEntry.parameters.deactivated).toBe(true);

      // Verify resolution shows deactivated state
      const resolved = await resolveDIDFromLog(result.log, { verifier });
      // When a DID is deactivated, the document is null but metadata shows deactivated state
      expect(resolved.didDocument).toBeNull();
      expect(resolved.didDocumentMetadata.deactivated).toBe(true);
      expect(resolved.didDocumentMetadata.versionId).toBe(latestEntry.versionId);
    });

    test('updateDID v0.5→v1.0 transition only adds method once (not redundantly on subsequent v1.0 updates)', async () => {
      const authKey1 = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const authKey2 = await generateTestVerificationMethod('assertionMethod', 'key-2');
      const signer1 = createTestSigner(authKey1);
      const signer2 = createTestSigner(authKey2);
      const verifier = createTestVerifier(authKey1);

      // Create v0.5 genesis
      const v05Log = await buildV05Genesis({
        address: 'example.com',
        signer: signer1,
        updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey1),
        verifier,
      });

      expect(v05Log[0].parameters.method).toBe('did:webvh:0.5');

      // First updateDID: v0.5 → v1.0 transition
      // This should add method: 'did:webvh:1.0' to the new entry
      const result1 = await updateDID({
        log: v05Log,
        signer: signer2,
        updateKeys: [authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey2),
        verifier,
      });

      expect(result1.log).toHaveLength(2);
      const transitionEntry = result1.log[1];

      // Verify the transition entry has method parameter (indicating v0.5→v1.0 transition)
      expect(transitionEntry.parameters.method).toBe('did:webvh:1.0');

      // Second updateDID: v1.0 → v1.0 (same version)
      // This should NOT add method parameter since we're already on v1.0
      const result2 = await updateDID({
        log: result1.log,
        signer: signer2,
        verificationMethods: asPublicVerificationMethods(authKey2),
        verifier,
      });

      expect(result2.log).toHaveLength(3);
      const secondUpdate = result2.log[2];

      // Verify the second update does NOT have method parameter
      // (no method field, or method field is absent from params)
      expect(secondUpdate.parameters.method).toBeUndefined();

      // Verify resolution works end-to-end
      const resolved = await resolveDIDFromLog(result2.log, { verifier });
      expect(resolved.didDocument).not.toBeNull();
      expect(resolved.didDocumentMetadata.versionId).toBe(secondUpdate.versionId);
    });

    test('deactivateDID v0.5→v1.0 transition only adds method once (not redundantly on subsequent deactivation)', async () => {
      const authKey1 = await generateTestVerificationMethod('assertionMethod', 'key-1');
      const authKey2 = await generateTestVerificationMethod('assertionMethod', 'key-2');
      const signer1 = createTestSigner(authKey1);
      const signer2 = createTestSigner(authKey2);
      const verifier = createTestVerifier(authKey1);

      // Create v0.5 genesis
      const v05Log = await buildV05Genesis({
        address: 'example.com',
        signer: signer1,
        updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey1),
        verifier,
      });

      expect(v05Log[0].parameters.method).toBe('did:webvh:0.5');

      // First operation: updateDID to trigger v0.5→v1.0 transition
      // This adds method: 'did:webvh:1.0' to the new entry
      const updateResult = await updateDID({
        log: v05Log,
        signer: signer2,
        updateKeys: [authKey2.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey2),
        verifier,
      });

      expect(updateResult.log).toHaveLength(2);
      const transitionEntry = updateResult.log[1];

      // Verify the transition entry has method parameter (v0.5→v1.0)
      expect(transitionEntry.parameters.method).toBe('did:webvh:1.0');

      // Second operation: deactivateDID on the now-v1.0 log
      // This should NOT add method parameter since we're already on v1.0
      const deactivateResult = await deactivateDID({
        log: updateResult.log,
        signer: signer2,
        verifier,
      });

      expect(deactivateResult.log).toHaveLength(3);
      const deactivationEntry = deactivateResult.log[2];

      // Verify the deactivation entry does NOT have method parameter
      // (no method field, or method field is absent from params)
      expect(deactivationEntry.parameters.method).toBeUndefined();

      // Verify deactivation is marked
      expect(deactivationEntry.parameters.deactivated).toBe(true);

      // Verify resolution shows deactivated state
      const resolved = await resolveDIDFromLog(deactivateResult.log, { verifier });
      expect(resolved.didDocument).toBeNull();
      expect(resolved.didDocumentMetadata.deactivated).toBe(true);
      expect(resolved.didDocumentMetadata.versionId).toBe(deactivationEntry.versionId);
    });
  });
});
