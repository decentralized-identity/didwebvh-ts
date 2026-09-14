import { beforeAll, describe, expect, test, vi } from 'vitest';
import { getWitnessRequirements, verifyWitnessProofs } from '../src/index.js';
import type {
  CreateDIDResult,
  DataIntegrityProofTemplate,
  DIDLog,
  Signer,
  WitnessProofFileEntry,
} from '../src/interfaces.js';
import { createDID, deactivateDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { deriveHash } from '../src/utils/crypto.js';
import { MultibaseEncoding, multibaseEncode } from '../src/utils/multiformats.js';
import { parseDidKeyDid, parseDidKeyVerificationMethod } from '../src/utils/verification-methods.js';
import {
  countWitnessApprovals,
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from '../src/witness.js';
import {
  buildV05Genesis,
  createTestDIDDocument,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
  TestCryptoImplementation,
  type TestVerificationMethod,
} from './utils.js';

describe('Witness Implementation Tests', async () => {
  let authKey: TestVerificationMethod;
  let witness1: TestVerificationMethod, witness2: TestVerificationMethod, witness3: TestVerificationMethod;
  let initialDID: CreateDIDResult;
  let testImplementation: TestCryptoImplementation;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    witness1 = await generateTestVerificationMethod();
    witness2 = await generateTestVerificationMethod();
    witness3 = await generateTestVerificationMethod();
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey });
  });

  const witnessVerificationMethod = (vm: TestVerificationMethod) =>
    `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`;

  const expectResolverRequirementsToMatch = async (log: DIDLog, witnessProofs: WitnessProofFileEntry[]) => {
    const expected = getWitnessRequirements(log);
    const result = await verifyWitnessProofs(log, witnessProofs, { verifier: testImplementation });

    expect(result.verified).toBe(true);
    expect(
      result.requirements.map(({ approvals: _approvals, satisfied: _satisfied, ...requirement }) => requirement)
    ).toEqual(expected);
  };

  test('Create DID with witness threshold', async () => {
    initialDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    expect(initialDID.meta?.witness?.threshold).toBe(2);
    expect(initialDID.meta?.witness?.witnesses).toHaveLength(2);
  });

  test('Resolve DID with witness proofs meeting threshold', async () => {
    // Create witness proofs for the initial DID's version
    const versionId = initialDID.log[0].versionId;

    // Create proofs from witness1 and witness2 using their signers
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);

    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2)),
    ]);

    const witnessProofs = [
      {
        versionId,
        proof: proofs,
      },
    ];

    // Resolve the DID log with witness proofs
    const resolved = await resolveDIDFromLog(initialDID.log, {
      witnessProofs,
      verifier: testImplementation,
    });

    expect(resolved.didDocumentMetadata?.witness?.threshold).toBe(2);
    expect(resolved.didDocument?.id).toBe(initialDID.did);
  });

  test('Create DID without witnesses then update to add witnesses', async () => {
    // Create initial DID without witnesses
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
    });

    const newAuthKey = await generateTestVerificationMethod();

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(newAuthKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    // Create witness proofs for the new version
    const newVersionId = updatedDID.log[1].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);

    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, newVersionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, newVersionId, witnessVerificationMethod(witness2)),
    ]);

    const witnessProofs = [
      {
        versionId: newVersionId,
        proof: proofs,
      },
    ];

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs,
    });
    expect(resolved.didDocumentMetadata?.witness?.threshold).toBe(2);
    expect(updatedDID.log).toHaveLength(2);
    expect(resolved.didDocumentMetadata?.witness?.witnesses).toHaveLength(2);

    // getWitnessRequirements agrees: first activation is governed by the new
    // configuration on the same (v2) entry.
    expect(getWitnessRequirements(updatedDID.log)).toEqual([
      {
        versionId: newVersionId,
        versionNumber: 2,
        threshold: 2,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      },
    ]);
    await expectResolverRequirementsToMatch(updatedDID.log, witnessProofs);
  });

  test('Resolve DID rejects duplicate witness IDs in witness parameters', async () => {
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
    });

    const duplicateWitnessId = `did:key:${witness1.publicKeyMultibase}`;
    const newAuthKey = await generateTestVerificationMethod();

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(newAuthKey),
      verifier: testImplementation,
    });

    const duplicateWitnessEntry = JSON.parse(JSON.stringify(updatedDID.log[1]));
    duplicateWitnessEntry.parameters.witness = {
      threshold: 2,
      witnesses: [{ id: duplicateWitnessId }, { id: duplicateWitnessId }],
    };

    delete duplicateWitnessEntry.proof;
    const logEntryHash = await deriveHash({
      ...duplicateWitnessEntry,
      versionId: updatedDID.log[0].versionId,
    });
    duplicateWitnessEntry.versionId = `2-${logEntryHash}`;

    const signer = createTestSigner(authKey);
    const proofTemplate: DataIntegrityProofTemplate = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: signer.getVerificationMethodId(),
      created: duplicateWitnessEntry.versionTime,
      proofPurpose: 'assertionMethod' as const,
    };
    const signedProof = await signer.sign({ document: duplicateWitnessEntry, proof: proofTemplate });
    duplicateWitnessEntry.proof = [{ ...proofTemplate, proofValue: signedProof.proofValue }];

    const tamperedLog = [updatedDID.log[0], duplicateWitnessEntry];

    const result = await resolveDIDFromLog(tamperedLog, {
      verifier: testImplementation,
    });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.message).toContain(`Duplicate witness id: ${duplicateWitnessId}`);
  });

  test('rejects witness did:key with incompatible key type at parameter validation', async () => {
    // Build a non-Ed25519 multikey payload (header != 0xed01), but still valid multibase.
    const nonEd25519Multikey = multibaseEncode(
      new Uint8Array([0xe7, 0x01, ...new Uint8Array(32).fill(7)]),
      MultibaseEncoding.BASE58_BTC
    );
    const invalidWitnessDid = `did:key:${nonEd25519Multikey}`;

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: {
          threshold: 1,
          witnesses: [{ id: invalidWitnessDid }],
        },
        verifier: testImplementation,
      })
    ).rejects.toThrow(/Witness DID key type must be Ed25519/);
  });

  test('API e2e: create, update, witness, and resolve with raw multibase updateKeys', async () => {
    const authKey2 = await generateTestVerificationMethod();

    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    const version1Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      created.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    const updated = await updateDID({
      log: created.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey2.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey2),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
      ],
    });

    const version2Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      updated.log[1].versionId,
      witnessVerificationMethod(witness1)
    );

    const resolved = await resolveDIDFromLog(updated.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
        {
          versionId: updated.log[1].versionId,
          proof: [version2Proof],
        },
      ],
    });

    expect(resolved.didDocument?.id).toBe(updated.did);
    expect(resolved.didDocumentMetadata?.updateKeys).toEqual([authKey2.publicKeyMultibase!]);
  });

  test('API e2e: normalizes did:key-formatted updateKeys in update flow', async () => {
    const authKey2 = await generateTestVerificationMethod();
    const authKey3 = await generateTestVerificationMethod();

    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    const version1Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      created.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    const firstUpdate = await updateDID({
      log: created.log,
      signer: createTestSigner(authKey),
      updateKeys: [`did:key:${authKey2.publicKeyMultibase}`],
      didDocument: createTestDIDDocument(authKey2),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
      ],
    });

    const version2Proof = await createWitnessProof(
      createWitnessSigner(witness1),
      firstUpdate.log[1].versionId,
      witnessVerificationMethod(witness1)
    );

    expect(firstUpdate.log[1].parameters.updateKeys).toEqual([authKey2.publicKeyMultibase!]);

    const secondUpdate = await updateDID({
      log: firstUpdate.log,
      signer: createTestSigner(authKey2),
      updateKeys: [authKey3.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey3),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: created.log[0].versionId,
          proof: [version1Proof],
        },
        {
          versionId: firstUpdate.log[1].versionId,
          proof: [version2Proof],
        },
      ],
    });
    expect(secondUpdate.log).toHaveLength(3);
    expect(secondUpdate.meta.updateKeys).toEqual([authKey3.publicKeyMultibase!]);
  });

  test('API e2e: rejects did:webvh verificationMethod in DID log entry proof', async () => {
    const authKey2 = await generateTestVerificationMethod();

    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
    });

    const baseSigner = createTestSigner(authKey);
    const nonCompliantSigner: Signer = {
      sign: (input) => baseSigner.sign(input),
      getVerificationMethodId: () => `${created.did}#controller-key`,
    };

    await expect(
      updateDID({
        log: created.log,
        signer: nonCompliantSigner,
        updateKeys: [authKey2.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey2),
        verifier: testImplementation,
      })
    ).rejects.toThrow('Unsupported verification method for DID log entry authorization');
  });

  test('Replace witness list with new witnesses', async () => {
    const newWitness = await generateTestVerificationMethod();

    // Create proofs for initial version
    const versionId = initialDID.log[0].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2)),
    ]);
    const witnessProofs = [{ versionId, proof: proofs }];

    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${newWitness.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
      witnessProofs,
    });

    // The replacing entry is governed by the previous list, so v2 needs witness1 + witness2.
    const newVersionId = updatedDID.log[1].versionId;
    const newWitnessProofs = [
      {
        versionId: newVersionId,
        proof: await Promise.all([
          createWitnessProof(createWitnessSigner(witness1), newVersionId, witnessVerificationMethod(witness1)),
          createWitnessProof(createWitnessSigner(witness2), newVersionId, witnessVerificationMethod(witness2)),
        ]),
      },
    ];

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs: [...witnessProofs, ...newWitnessProofs],
    });
    expect(resolved.didDocumentMetadata?.witness?.witnesses).toHaveLength(1);
    expect(resolved.didDocumentMetadata?.witness?.threshold).toBe(1);

    // getWitnessRequirements agrees: the replacing entry (v2) is governed by the
    // previous list (witness1 + witness2), not the new one.
    const requirements = getWitnessRequirements(updatedDID.log);
    expect(requirements[1].versionId).toBe(newVersionId);
    expect(requirements[1].threshold).toBe(2);
    expect(requirements[1].witnesses).toEqual([
      { id: `did:key:${witness1.publicKeyMultibase}` },
      { id: `did:key:${witness2.publicKeyMultibase}` },
    ]);
    await expectResolverRequirementsToMatch(updatedDID.log, [...witnessProofs, ...newWitnessProofs]);
  });

  test('Disable witnessing by setting witness list to null', async () => {
    // Create proofs for initial version
    const versionId = initialDID.log[0].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2)),
    ]);
    const witnessProofs = [{ versionId, proof: proofs }];

    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: null,
      verifier: testImplementation,
      witnessProofs,
    });

    const newVersionId = updatedDID.log[1].versionId;
    const deactivationProofs = await Promise.all([
      createWitnessProof(createWitnessSigner(witness1), newVersionId, witnessVerificationMethod(witness1)),
      createWitnessProof(createWitnessSigner(witness2), newVersionId, witnessVerificationMethod(witness2)),
    ]);

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs: [...witnessProofs, { versionId: newVersionId, proof: deactivationProofs }],
    });
    expect(resolved.didDocumentMetadata.witness).toEqual({});

    // getWitnessRequirements agrees: the turn-off entry (v2) is still governed by
    // the previously active list.
    const requirements = getWitnessRequirements(updatedDID.log);
    expect(requirements[1].versionId).toBe(newVersionId);
    expect(requirements[1].threshold).toBe(2);
    expect(requirements[1].witnesses).toEqual([
      { id: `did:key:${witness1.publicKeyMultibase}` },
      { id: `did:key:${witness2.publicKeyMultibase}` },
    ]);
    await expectResolverRequirementsToMatch(updatedDID.log, [
      ...witnessProofs,
      { versionId: newVersionId, proof: deactivationProofs },
    ]);
  });

  test('Disable witnessing with an explicit empty witness configuration', async () => {
    const versionId = initialDID.log[0].versionId;
    const initialProofs = [
      {
        versionId,
        proof: await Promise.all([
          createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
          createWitnessProof(createWitnessSigner(witness2), versionId, witnessVerificationMethod(witness2)),
        ]),
      },
    ];

    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {},
      verifier: testImplementation,
      witnessProofs: initialProofs,
    });

    const updatedVersionId = updatedDID.log[1].versionId;
    const updatedProofs = {
      versionId: updatedVersionId,
      proof: await Promise.all([
        createWitnessProof(createWitnessSigner(witness1), updatedVersionId, witnessVerificationMethod(witness1)),
        createWitnessProof(createWitnessSigner(witness2), updatedVersionId, witnessVerificationMethod(witness2)),
      ]),
    };
    const allWitnessProofs = [...initialProofs, updatedProofs];

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs: allWitnessProofs,
    });
    expect(resolved.didDocumentMetadata.witness).toEqual({});

    const requirements = getWitnessRequirements(updatedDID.log);
    expect(requirements).toHaveLength(2);
    expect(requirements[1]).toMatchObject({
      versionId: updatedVersionId,
      versionNumber: 2,
      threshold: 2,
      witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
    });
    await expectResolverRequirementsToMatch(updatedDID.log, allWitnessProofs);
  });

  describe('getWitnessRequirements', () => {
    test('Genesis without witnesses returns no requirements', async () => {
      const noWitnessDID = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
      });

      expect(getWitnessRequirements(noWitnessDID.log)).toEqual([]);
    });

    test('Keeps subsequent entries inactive when genesis has no witnesses and the entry omits witnesses', async () => {
      const noWitnessDID = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
      });
      const updatedDID = await updateDID({
        log: noWitnessDID.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
      });

      expect(getWitnessRequirements(updatedDID.log)).toEqual([]);
      await expectResolverRequirementsToMatch(updatedDID.log, []);
    });

    test('Genesis with witnesses returns versionId, normalized threshold, and witness list', async () => {
      const requirements = getWitnessRequirements(initialDID.log);

      expect(requirements).toEqual([
        {
          versionId: initialDID.log[0].versionId,
          versionNumber: 1,
          threshold: 2,
          witnesses: [
            { id: `did:key:${witness1.publicKeyMultibase}` },
            { id: `did:key:${witness2.publicKeyMultibase}` },
          ],
        },
      ]);
    });

    test('Reports a witness requirement when witnesses are first activated on an update', async () => {
      const noWitnessDID = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
      });
      const updatedDID = await updateDID({
        log: noWitnessDID.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: {
          threshold: 1,
          witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
        },
        verifier: testImplementation,
      });

      const requirements = getWitnessRequirements(updatedDID.log);
      expect(requirements).toEqual([
        {
          versionId: updatedDID.log[1].versionId,
          versionNumber: 2,
          threshold: 1,
          witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
        },
      ]);
      await expectResolverRequirementsToMatch(updatedDID.log, [
        {
          versionId: updatedDID.log[1].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              updatedDID.log[1].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ]);
    });

    test('Carries witness requirements forward when a subsequent entry omits witnesses', async () => {
      const versionId = initialDID.log[0].versionId;
      const initialProofs = [
        {
          versionId,
          proof: await Promise.all([
            createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
            createWitnessProof(createWitnessSigner(witness2), versionId, witnessVerificationMethod(witness2)),
          ]),
        },
      ];
      const updatedDID = await updateDID({
        log: initialDID.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
        witnessProofs: initialProofs,
      });
      const updatedVersionId = updatedDID.log[1].versionId;
      const updatedProofs = {
        versionId: updatedVersionId,
        proof: await Promise.all([
          createWitnessProof(createWitnessSigner(witness1), updatedVersionId, witnessVerificationMethod(witness1)),
          createWitnessProof(createWitnessSigner(witness2), updatedVersionId, witnessVerificationMethod(witness2)),
        ]),
      };

      expect(getWitnessRequirements(updatedDID.log)).toEqual([
        {
          versionId,
          versionNumber: 1,
          threshold: 2,
          witnesses: [
            { id: `did:key:${witness1.publicKeyMultibase}` },
            { id: `did:key:${witness2.publicKeyMultibase}` },
          ],
        },
        {
          versionId: updatedVersionId,
          versionNumber: 2,
          threshold: 2,
          witnesses: [
            { id: `did:key:${witness1.publicKeyMultibase}` },
            { id: `did:key:${witness2.publicKeyMultibase}` },
          ],
        },
      ]);
      await expectResolverRequirementsToMatch(updatedDID.log, [...initialProofs, updatedProofs]);
    });

    test('Uses the previous witness configuration for a replacement entry', async () => {
      const versionId = initialDID.log[0].versionId;
      const initialProofs = [
        {
          versionId,
          proof: await Promise.all([
            createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
            createWitnessProof(createWitnessSigner(witness2), versionId, witnessVerificationMethod(witness2)),
          ]),
        },
      ];
      const updatedDID = await updateDID({
        log: initialDID.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: {
          threshold: 1,
          witnesses: [{ id: `did:key:${witness3.publicKeyMultibase}` }],
        },
        verifier: testImplementation,
        witnessProofs: initialProofs,
      });
      const updatedVersionId = updatedDID.log[1].versionId;
      const updatedProofs = {
        versionId: updatedVersionId,
        proof: await Promise.all([
          createWitnessProof(createWitnessSigner(witness1), updatedVersionId, witnessVerificationMethod(witness1)),
          createWitnessProof(createWitnessSigner(witness2), updatedVersionId, witnessVerificationMethod(witness2)),
        ]),
      };

      expect(getWitnessRequirements(updatedDID.log)[1]).toEqual({
        versionId: updatedVersionId,
        versionNumber: 2,
        threshold: 2,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      });
      await expectResolverRequirementsToMatch(updatedDID.log, [...initialProofs, updatedProofs]);
    });

    test('Returns defensive copies that callers cannot use to mutate internal state', async () => {
      const requirements = getWitnessRequirements(initialDID.log);
      const originalWitnesses = JSON.parse(JSON.stringify(requirements[0].witnesses));

      requirements[0].witnesses.push({ id: 'did:key:zTamperedWitness' });
      requirements[0].threshold = 999;

      const requirementsAgain = getWitnessRequirements(initialDID.log);
      expect(requirementsAgain[0].witnesses).toEqual(originalWitnesses);
      expect(requirementsAgain[0].threshold).toBe(2);
    });

    test('Agrees with the resolver-derived requirements for the same log', async () => {
      const requirements = getWitnessRequirements(initialDID.log);
      const versionId = initialDID.log[0].versionId;
      const witnessProofs = [
        {
          versionId,
          proof: await Promise.all([
            createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
            createWitnessProof(createWitnessSigner(witness2), versionId, witnessVerificationMethod(witness2)),
          ]),
        },
      ];
      const resolved = await verifyWitnessProofs(initialDID.log, witnessProofs, { verifier: testImplementation });

      expect(resolved.verified).toBe(true);
      expect(resolved.requirements).toEqual(
        requirements.map((requirement) => ({
          ...requirement,
          approvals: 2,
          satisfied: true,
        }))
      );
    });
  });

  describe('verifyWitnessProofs', () => {
    test('Returns verified: true and satisfied requirements when threshold is met', async () => {
      const witness1SignerFn = createWitnessSigner(witness1);
      const witness2SignerFn = createWitnessSigner(witness2);
      const versionId = initialDID.log[0].versionId;

      const witnessProofs = [
        {
          versionId,
          proof: await Promise.all([
            createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
            createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2)),
          ]),
        },
      ];

      const result = await verifyWitnessProofs(initialDID.log, witnessProofs, { verifier: testImplementation });

      expect(result.verified).toBe(true);
      expect(result.requirements).toEqual([
        {
          versionId,
          versionNumber: 1,
          threshold: 2,
          witnesses: [
            { id: `did:key:${witness1.publicKeyMultibase}` },
            { id: `did:key:${witness2.publicKeyMultibase}` },
          ],
          approvals: 2,
          satisfied: true,
        },
      ]);
    });

    test('returns structured diagnostics for rejected witness proofs', async () => {
      const versionId = initialDID.log[0].versionId;
      const validWitness1Proof = await createWitnessProof(
        createWitnessSigner(witness1),
        versionId,
        witnessVerificationMethod(witness1)
      );
      const validWitness2Proof = await createWitnessProof(
        createWitnessSigner(witness2),
        versionId,
        witnessVerificationMethod(witness2)
      );
      const invalidSignatureProof = {
        ...validWitness2Proof,
        proofValue: `${validWitness2Proof.proofValue.slice(0, -1)}1`,
      };
      const unknownWitnessProof = await createWitnessProof(
        createWitnessSigner(witness3),
        versionId,
        witnessVerificationMethod(witness3)
      );

      const result = await verifyWitnessProofs(
        initialDID.log,
        [
          {
            versionId,
            proof: [invalidSignatureProof, validWitness1Proof, validWitness1Proof, unknownWitnessProof],
          },
        ],
        { verifier: testImplementation }
      );

      expect(result.verified).toBe(false);
      expect(result.rejectedProofs).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            requirementVersionId: versionId,
            proofVersionId: versionId,
            proofIndex: 0,
            verificationMethod: witnessVerificationMethod(witness2),
            code: 'invalid-signature',
          }),
          expect.objectContaining({
            requirementVersionId: versionId,
            proofVersionId: versionId,
            proofIndex: 2,
            verificationMethod: witnessVerificationMethod(witness1),
            code: 'duplicate-witness',
          }),
          expect.objectContaining({
            requirementVersionId: versionId,
            proofVersionId: versionId,
            proofIndex: 3,
            verificationMethod: witnessVerificationMethod(witness3),
            code: 'unknown-witness',
          }),
        ])
      );
      expect(result.rejectedProofs).toHaveLength(3);
    });

    test('Returns verified: false with a per-entry approval count when threshold is not met, without throwing', async () => {
      const witness1SignerFn = createWitnessSigner(witness1);
      const versionId = initialDID.log[0].versionId;

      const witnessProofs = [
        {
          versionId,
          proof: [await createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1))],
        },
      ];

      const result = await verifyWitnessProofs(initialDID.log, witnessProofs, { verifier: testImplementation });

      expect(result.verified).toBe(false);
      expect(result.requirements).toEqual([
        {
          versionId,
          versionNumber: 1,
          threshold: 2,
          witnesses: [
            { id: `did:key:${witness1.publicKeyMultibase}` },
            { id: `did:key:${witness2.publicKeyMultibase}` },
          ],
          approvals: 1,
          satisfied: false,
        },
      ]);
    });

    test('Returns verified: true with no requirements when the log has no witness requirement', async () => {
      const noWitnessDID = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
      });

      const result = await verifyWitnessProofs(noWitnessDID.log, [], { verifier: testImplementation });

      expect(result).toEqual({ verified: true, requirements: [], rejectedProofs: [] });
    });

    test('Still throws for non-witness integrity failures, unmodified', async () => {
      const tamperedLog: DIDLog = JSON.parse(JSON.stringify(initialDID.log));
      tamperedLog[0].parameters.scid = 'tampered-scid';

      await expect(verifyWitnessProofs(tamperedLog, [], { verifier: testImplementation })).rejects.toThrow();
    });

    test('Verifies a proposed chain-tip update using a single cumulative proof for a 3-entry log', async () => {
      // Simulates the create -> witness -> verify -> publish sequence for a proposed,
      // not-yet-published update: a single witness proof signing only the latest
      // (v3) versionId must cumulatively satisfy the inherited witness requirement
      // on v1, v2, and v3 alike, without any per-version proof history.
      const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
      const genesisDid = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
        verifier: testImplementation,
      });

      // v2: published, witnessed by a proof scoped to v1 (its own requirement).
      const v1WitnessProofs = [
        {
          versionId: genesisDid.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              genesisDid.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ];
      const publishedV2 = await updateDID({
        log: genesisDid.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
        witnessProofs: v1WitnessProofs,
      });

      // v3: a proposed chain tip, not yet witnessed or published anywhere else.
      // v2 also requires this same (inherited) witness configuration to be re-verified
      // when resolving the fuller log, so its own cumulative proof is supplied here.
      const v2WitnessProofs = [
        {
          versionId: publishedV2.log[1].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              publishedV2.log[1].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ];
      const proposedV3 = await updateDID({
        log: publishedV2.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        verifier: testImplementation,
        witnessProofs: v2WitnessProofs,
      });
      expect(proposedV3.log).toHaveLength(3);

      const v3VersionId = proposedV3.log[2].versionId;
      const cumulativeWitnessProofs = [
        {
          versionId: v3VersionId,
          proof: [
            await createWitnessProof(createWitnessSigner(witness1), v3VersionId, witnessVerificationMethod(witness1)),
          ],
        },
      ];

      const result = await verifyWitnessProofs(proposedV3.log, cumulativeWitnessProofs, {
        verifier: testImplementation,
      });

      expect(result.verified).toBe(true);
      expect(result.requirements.length).toBeGreaterThanOrEqual(1);
      for (const requirement of result.requirements) {
        expect(requirement.satisfied).toBe(true);
        expect(requirement.approvals).toBe(1);
      }
    });

    test('Deactivating a witnessed DID validates the prior log using caller-supplied witnessProofs, and the resulting entry is checked via verifyWitnessProofs', async () => {
      const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
      const genesisDid = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
        verifier: testImplementation,
      });

      const genesisVersionId = genesisDid.log[0].versionId;
      const genesisWitnessProofs = [
        {
          versionId: genesisVersionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              genesisVersionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ];

      // Deactivate: resolving the prior (witnessed) log must use the caller-supplied
      // proofs rather than falling back to a network fetch of did-witness.json.
      const deactivated = await deactivateDID({
        log: genesisDid.log,
        signer: createTestSigner(authKey),
        verifier: testImplementation,
        witnessProofs: genesisWitnessProofs,
      });

      expect(deactivated.meta.deactivated).toBe(true);
      expect(deactivated.log).toHaveLength(2);

      // The still-active genesis configuration also governs the deactivation entry
      // itself (v2); a proof signing the deactivation entry's own versionId cumulatively
      // satisfies both the genesis (v1) and deactivation (v2) requirements.
      const deactivationVersionId = deactivated.log[1].versionId;
      const cumulativeWitnessProofs = [
        {
          versionId: deactivationVersionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              deactivationVersionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ];

      const result = await verifyWitnessProofs(deactivated.log, cumulativeWitnessProofs, {
        verifier: testImplementation,
      });

      expect(result.verified).toBe(true);
      expect(result.requirements).toEqual([
        {
          versionId: genesisVersionId,
          versionNumber: 1,
          threshold: 1,
          witnesses: [{ id: witnessDid }],
          approvals: 1,
          satisfied: true,
        },
        {
          versionId: deactivationVersionId,
          versionNumber: 2,
          threshold: 1,
          witnesses: [{ id: witnessDid }],
          approvals: 1,
          satisfied: true,
        },
      ]);
      await expectResolverRequirementsToMatch(deactivated.log, cumulativeWitnessProofs);
    });

    test('deactivateDID rejects when a witness is required but witnessProofs is explicitly empty', async () => {
      const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
      const genesisDid = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
        verifier: testImplementation,
      });

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch should not occur'));

      try {
        await expect(
          deactivateDID({
            log: genesisDid.log,
            signer: createTestSigner(authKey),
            verifier: testImplementation,
            witnessProofs: [],
          })
        ).rejects.toThrow();

        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    test('updateDID rejects when a witness is required but witnessProofs is explicitly empty', async () => {
      const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
      const genesisDid = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
        verifier: testImplementation,
      });

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch should not occur'));

      try {
        await expect(
          updateDID({
            log: genesisDid.log,
            signer: createTestSigner(authKey),
            updateKeys: [authKey.publicKeyMultibase!],
            didDocument: createTestDIDDocument(authKey),
            verifier: testImplementation,
            witnessProofs: [],
          })
        ).rejects.toThrow();

        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
    });

    test('updateDID fetches witness proofs when witnessProofs is omitted', async () => {
      const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
      const genesisDid = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
        verifier: testImplementation,
      });

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch observed'));

      try {
        await expect(
          updateDID({
            log: genesisDid.log,
            signer: createTestSigner(authKey),
            updateKeys: [authKey.publicKeyMultibase!],
            didDocument: createTestDIDDocument(authKey),
            verifier: testImplementation,
          })
        ).rejects.toThrow();

        expect(fetchSpy).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
      } finally {
        fetchSpy.mockRestore();
      }
    });

    test('updateDID and deactivateDID never fetch witness proofs over the network when witnessProofs is supplied', async () => {
      const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
      const genesisDid = await createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
        verifier: testImplementation,
      });

      const genesisVersionId = genesisDid.log[0].versionId;
      const genesisWitnessProofs = [
        {
          versionId: genesisVersionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              genesisVersionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ];

      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockRejectedValue(new Error('network fetch should not occur'));

      try {
        const updatedDid = await updateDID({
          log: genesisDid.log,
          signer: createTestSigner(authKey),
          updateKeys: [authKey.publicKeyMultibase!],
          didDocument: createTestDIDDocument(authKey),
          verifier: testImplementation,
          witnessProofs: genesisWitnessProofs,
        });
        expect(fetchSpy).not.toHaveBeenCalled();

        const updatedVersionId = updatedDid.log[1].versionId;
        const updatedWitnessProofs = [
          {
            versionId: updatedVersionId,
            proof: [
              await createWitnessProof(
                createWitnessSigner(witness1),
                updatedVersionId,
                witnessVerificationMethod(witness1)
              ),
            ],
          },
        ];

        await deactivateDID({
          log: updatedDid.log,
          signer: createTestSigner(authKey),
          verifier: testImplementation,
          witnessProofs: updatedWitnessProofs,
        });
        expect(fetchSpy).not.toHaveBeenCalled();
      } finally {
        fetchSpy.mockRestore();
      }
    });
  });

  test('Verify witness proofs from did-witness.json', async () => {
    // Create real witness proofs using the utility
    const mockWitnessFile = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            initialDID.log[0].versionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness2),
            initialDID.log[0].versionId,
            witnessVerificationMethod(witness2)
          ),
        ],
      },
      {
        versionId: 'future-version-id',
        proof: [
          // This proof should be ignored since version doesn't exist in log
          await createWitnessProof(
            createWitnessSigner(witness1),
            'future-version-id',
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ];

    const resolved = await resolveDIDFromLog(initialDID.log, {
      witnessProofs: mockWitnessFile,
      verifier: testImplementation,
    });

    expect(resolved.didDocument?.id).toBe(initialDID.did);
  });

  test('Reject witness proofs with invalid proofPurpose', async () => {
    const badProof = await createWitnessProof(
      createWitnessSigner(witness1),
      initialDID.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    const witnessProofs = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          {
            ...badProof,
            proofPurpose: 'authentication' as const,
          },
        ],
      },
    ];

    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    };

    try {
      const result = await resolveDIDFromLog(initialDID.log, {
        witnessProofs,
        verifier: testImplementation,
      });
      expect(result.didDocument).toBeNull();
      expect(result.didResolutionMetadata.error).toBe('invalidDid');
      expect(result.didResolutionMetadata.message).toContain(
        `Witness threshold not met for version ${initialDID.log[0].versionId}`
      );
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings.some((msg) => msg.includes('Invalid witness proof purpose'))).toBe(true);
  });

  test('parseDidKeyDid accepts a valid did:key DID', () => {
    const did = `did:key:${witness1.publicKeyMultibase}`;

    expect(parseDidKeyDid(did)).toEqual({
      did,
      keyMultibase: witness1.publicKeyMultibase!,
    });
  });

  test('parseDidKeyDid rejects malformed DID input', () => {
    expect(() => parseDidKeyDid(`did:key:${witness1.publicKeyMultibase}#fragment`)).toThrow('Malformed did:key DID');
    expect(() => parseDidKeyDid('did:web:example.com')).toThrow('Malformed did:key DID');
  });

  test('parseDidKeyVerificationMethod accepts fragment and no-fragment forms', () => {
    const withFragment = witnessVerificationMethod(witness1);
    const withoutFragment = `did:key:${witness1.publicKeyMultibase}`;

    expect(parseDidKeyVerificationMethod(withFragment)).toEqual({
      did: withoutFragment,
      fragment: witness1.publicKeyMultibase,
      keyMultibase: witness1.publicKeyMultibase!,
    });
    expect(parseDidKeyVerificationMethod(withoutFragment)).toEqual({
      did: withoutFragment,
      fragment: undefined,
      keyMultibase: witness1.publicKeyMultibase!,
    });
  });

  test('parseDidKeyVerificationMethod rejects relative and non-did:key values', () => {
    expect(() => parseDidKeyVerificationMethod(`#${witness1.publicKeyMultibase}`)).toThrow(
      'did:key verificationMethod must be an absolute DID URL'
    );
    expect(() => parseDidKeyVerificationMethod('did:web:example.com#key-1')).toThrow(
      'Malformed did:key verificationMethod'
    );
  });

  test('parseDidKeyVerificationMethod rejects fragment that differs from body multibase', () => {
    const validMultibase = witness1.publicKeyMultibase!;
    const differentMultibase = 'z6MkhaXgBZDvotzL8V6N3XQfZ47fRhVvKiHbhQr6CoCo2V4p'; // different key
    const withMismatchedFragment = `did:key:${validMultibase}#${differentMultibase}`;

    expect(() => parseDidKeyVerificationMethod(withMismatchedFragment)).toThrow(
      'did:key verificationMethod fragment must equal body multibase'
    );
  });

  test('parseDidKeyVerificationMethod accepts fragment matching body multibase', () => {
    const multibase = witness1.publicKeyMultibase!;
    const withMatchingFragment = `did:key:${multibase}#${multibase}`;

    expect(parseDidKeyVerificationMethod(withMatchingFragment)).toEqual({
      did: `did:key:${multibase}`,
      fragment: multibase,
      keyMultibase: multibase,
    });
  });

  test('signWitnessProofEntry signs for every configured witness', async () => {
    const versionId = initialDID.log[0].versionId;
    const created = '2026-05-22T12:00:00Z';
    const result = await signWitnessProofEntry({
      versionId,
      witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      witnessSignersByDid: {
        [`did:key:${witness1.publicKeyMultibase}`]: createTestSigner(witness1),
        [`did:key:${witness2.publicKeyMultibase}`]: createTestSigner(witness2),
      },
      created,
    });

    expect(result.versionId).toBe(versionId);
    expect(result.proof).toHaveLength(2);
    expect(result.proof[0].created).toBe(created);
    expect(result.proof[1].created).toBe(created);
    expect(result.proof.map((proof) => proof.proofPurpose)).toEqual(['assertionMethod', 'assertionMethod']);
  });

  test('signWitnessProofEntry rejects missing signer', async () => {
    await expect(
      signWitnessProofEntry({
        versionId: initialDID.log[0].versionId,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
        witnessSignersByDid: {
          [`did:key:${witness1.publicKeyMultibase}`]: createTestSigner(witness1),
        },
      })
    ).rejects.toThrow(`Missing witness signer for did:key:${witness2.publicKeyMultibase}`);
  });

  test('signWitnessProofEntry rejects malformed signer verificationMethod', async () => {
    await expect(
      signWitnessProofEntry({
        versionId: initialDID.log[0].versionId,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
        witnessSignersByDid: {
          [`did:key:${witness1.publicKeyMultibase}`]: {
            sign: async () => ({ proofValue: 'zbad' }),
            getVerificationMethodId: () => '#relative',
          },
        },
      })
    ).rejects.toThrow('did:key verificationMethod must be an absolute DID URL');
  });

  test('signWitnessProofEntries signs multiple versionIds', async () => {
    const results = await signWitnessProofEntries(
      [initialDID.log[0].versionId, '2-test-version'],
      [{ id: `did:key:${witness1.publicKeyMultibase}` }],
      {
        [`did:key:${witness1.publicKeyMultibase}`]: createTestSigner(witness1),
      },
      '2026-05-22T12:00:00Z'
    );

    expect(results).toHaveLength(2);
    expect(results.map((result) => result.versionId)).toEqual([initialDID.log[0].versionId, '2-test-version']);
    expect(results[0].proof).toHaveLength(1);
    expect(results[1].proof).toHaveLength(1);
  });

  test('countWitnessApprovals uses exact did:key DID matching', async () => {
    const proofs = [
      await createWitnessProof(
        createWitnessSigner(witness1),
        initialDID.log[0].versionId,
        witnessVerificationMethod(witness1)
      ),
    ];

    expect(countWitnessApprovals(proofs, [{ id: `did:key:${witness1.publicKeyMultibase}` }])).toBe(1);
    expect(countWitnessApprovals(proofs, [{ id: `did:key:${witness2.publicKeyMultibase}` }])).toBe(0);
  });

  test('Resolve requires witness threshold for each required entry', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    // A v1-only proof leaves v2 unwitnessed: cumulative approval runs backwards, so an
    // earlier proof never covers a later entry.
    const result = await resolveDIDFromLog(updatedDid.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.message).toContain(
      `Witness threshold not met for version ${updatedDid.log[1].versionId}`
    );

    // getWitnessRequirements agrees: the inherited config (witnessDid, threshold 1) also
    // governs v2, not just v1.
    const requirements = getWitnessRequirements(updatedDid.log);
    expect(requirements).toEqual([
      {
        versionId: didWithWitness.log[0].versionId,
        versionNumber: 1,
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      {
        versionId: updatedDid.log[1].versionId,
        versionNumber: 2,
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
    ]);

    const inheritedVersionId = updatedDid.log[1].versionId;
    await expectResolverRequirementsToMatch(updatedDid.log, [
      {
        versionId: inheritedVersionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            inheritedVersionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ]);
  });

  test('Resolve does not double-count duplicate proofs from the same witness DID', async () => {
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }],
      },
      verifier: testImplementation,
    });

    const versionId = didWithWitness.log[0].versionId;
    const duplicateProofsFromSameWitness = [
      await createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
      await createWitnessProof(createWitnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
    ];

    const resolved = await resolveDIDFromLog(didWithWitness.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId,
          proof: duplicateProofsFromSameWitness,
        },
      ],
    });

    expect(resolved.didDocument).toBeNull();
    expect(resolved.didResolutionMetadata.error).toBe('invalidDid');
    expect(resolved.didResolutionMetadata.message).toContain(`Witness threshold not met for version ${versionId}`);
  });

  test('Resolve accepts later proof for earlier required entry', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    const resolved = await resolveDIDFromLog(updatedDid.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: updatedDid.log[1].versionId,
          proof: [
            // Published in version 2 while signing version 1 (later publication for earlier target).
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
            // Also satisfy the version 2 target check.
            await createWitnessProof(
              createWitnessSigner(witness1),
              updatedDid.log[1].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    expect(resolved.didDocument?.id).toBe(updatedDid.did);
  });

  test('Resolve accepts a single pruned later proof as cumulative approval for prior entries', async () => {
    // A pruned file (one proof at the latest versionId) must witness every earlier entry,
    // since a valid proof implies approval of all prior entries.
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid }] },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    // Pruned file: only the latest proof, signing the LATEST versionId.
    const prunedWitnessProofs = [
      {
        versionId: updatedDid.log[1].versionId,
        proof: [
          await createWitnessProof(
            createWitnessSigner(witness1),
            updatedDid.log[1].versionId,
            witnessVerificationMethod(witness1)
          ),
        ],
      },
    ];

    const resolved = await resolveDIDFromLog(updatedDid.log, {
      verifier: testImplementation,
      witnessProofs: prunedWitnessProofs,
    });

    expect(resolved.didDocument?.id).toBe(updatedDid.did);
    expect(resolved.didResolutionMetadata.error).toBeUndefined();
  });

  test('Resolve rejects a witness-list reduction approved only by the reduced list', async () => {
    // The reducing entry must still meet the previous list's threshold (the new list
    // activates only after publication).
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: { threshold: 2, witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }] },
      verifier: testImplementation,
    });

    const v1 = didWithWitness.log[0].versionId;
    const v1Proofs = {
      versionId: v1,
      proof: await Promise.all([
        createWitnessProof(createWitnessSigner(witness1), v1, witnessVerificationMethod(witness1)),
        createWitnessProof(createWitnessSigner(witness2), v1, witnessVerificationMethod(witness2)),
      ]),
    };

    // Reduce 2-of-2 -> 1-of-1 (witness1 only).
    const reduced = await updateDID({
      log: didWithWitness.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: { threshold: 1, witnesses: [{ id: witnessDid1 }] },
      verifier: testImplementation,
      witnessProofs: [v1Proofs],
    });

    const v2 = reduced.log[1].versionId;

    // Only witness1 (the reduced list) approves v2 — insufficient for the old 2-of-2.
    const result = await resolveDIDFromLog(reduced.log, {
      verifier: testImplementation,
      witnessProofs: [
        v1Proofs,
        {
          versionId: v2,
          proof: [await createWitnessProof(createWitnessSigner(witness1), v2, witnessVerificationMethod(witness1))],
        },
      ],
    });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.message).toContain(`Witness threshold not met for version ${v2}`);
  });

  test('Resolve ignores invalid witness proof if enough valid proofs remain', async () => {
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid1 }, { id: witnessDid2 }],
      },
      verifier: testImplementation,
    });

    const resolved = await resolveDIDFromLog(didWithWitness.log, {
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            {
              ...(await createWitnessProof(
                createWitnessSigner(witness1),
                didWithWitness.log[0].versionId,
                witnessVerificationMethod(witness1)
              )),
              proofValue: 'zinvalid',
            },
            await createWitnessProof(
              createWitnessSigner(witness2),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness2)
            ),
          ],
        },
      ],
    });

    expect(resolved.didDocument?.id).toBe(didWithWitness.did);
  });

  test('Resolve maps witness threshold failure to invalidDid metadata for partial results', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: witnessDid }],
      },
      verifier: testImplementation,
    });

    const updatedDid = await updateDID({
      log: didWithWitness.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    const resolved = await resolveDIDFromLog(updatedDid.log, {
      versionNumber: 1,
      verifier: testImplementation,
      witnessProofs: [
        {
          versionId: didWithWitness.log[0].versionId,
          proof: [
            await createWitnessProof(
              createWitnessSigner(witness1),
              didWithWitness.log[0].versionId,
              witnessVerificationMethod(witness1)
            ),
          ],
        },
      ],
    });

    expect(resolved.didResolutionMetadata.error).toBe('invalidDid');
    expect(resolved.didResolutionMetadata.problemDetails).toBeDefined();
    expect(resolved.didResolutionMetadata.problemDetails!.type).toBe(
      'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID'
    );
    expect(resolved.didResolutionMetadata.problemDetails!.title).toBe('The resolved DID is invalid.');
    expect(resolved.didResolutionMetadata.problemDetails!.detail).toContain('Witness threshold not met');
  });

  test('Update DID rejects duplicate witness IDs', async () => {
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
    });

    const duplicateWitnessId = `did:key:${witness1.publicKeyMultibase}`;

    await expect(
      updateDID({
        log: noWitnessDID.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: createTestDIDDocument(authKey),
        witness: {
          threshold: 2,
          witnesses: [{ id: duplicateWitnessId }, { id: duplicateWitnessId }],
        },
        verifier: testImplementation,
      })
    ).rejects.toThrow(`Duplicate witness id: ${duplicateWitnessId}`);
  });

  test('Update DID normalizes empty witness list to inactive state', async () => {
    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
    });

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        threshold: 2,
        witnesses: [],
      },
      verifier: testImplementation,
    });

    expect(updatedDID.meta.witness).toEqual({});
    expect(updatedDID.log[1].parameters.witness).toEqual({});
  });

  test('Accept witness signer output containing undefined fields', async () => {
    const proof = await createWitnessProof(
      async () => ({
        proof: {
          created: undefined,
          proofValue: 'zInvalidButPresent',
        },
      }),
      initialDID.log[0].versionId,
      witnessVerificationMethod(witness1)
    );

    expect(proof.proofValue).toBe('zInvalidButPresent');
  });

  const createWitnessSigner = (verificationMethod: TestVerificationMethod) => {
    const signer = createTestSigner(verificationMethod);
    return async (data: { versionId: string }, proofTemplate?: DataIntegrityProofTemplate) => {
      const proof: DataIntegrityProofTemplate = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: signer.getVerificationMethodId(),
        created: new Date().toISOString(),
        proofPurpose: 'authentication',
        ...proofTemplate,
      };
      const signResult = await signer.sign({ document: data, proof });
      return {
        proof: {
          verificationMethod: signer.getVerificationMethodId(),
          proofValue: signResult.proofValue,
        },
      };
    };
  };

  test('Resolves DID with legacy witnesses/witnessThreshold format in incremental entry', async () => {
    const witnessKey = await generateTestVerificationMethod();
    const witnessId = `did:key:${witnessKey.publicKeyMultibase}`;
    const witnessVmId = `${witnessId}#${witnessKey.publicKeyMultibase}`;

    const noWitnessDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier: testImplementation,
      created: '2021-01-01T00:00:00Z',
    });

    const versionTime = '2021-01-02T00:00:00Z';
    const baseEntry = {
      versionId: noWitnessDID.log[0].versionId,
      versionTime,
      parameters: {
        updateKeys: [authKey.publicKeyMultibase!],
        witnesses: [{ id: witnessId }],
        witnessThreshold: 1,
      },
      state: noWitnessDID.log[0].state,
    };
    const logEntryHash = await deriveHash(baseEntry);
    const versionId = `2-${logEntryHash}`;
    const signer = createTestSigner(authKey);
    const proofTemplate: DataIntegrityProofTemplate = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: signer.getVerificationMethodId(),
      created: versionTime,
      proofPurpose: 'assertionMethod',
    };
    const signedProof = await signer.sign({ document: { ...baseEntry, versionId }, proof: proofTemplate });
    const v2Entry = { ...baseEntry, versionId, proof: [{ ...proofTemplate, proofValue: signedProof.proofValue }] };

    const legacyLog = [noWitnessDID.log[0], v2Entry] as DIDLog;
    const witnessSignerFn = createWitnessSigner(witnessKey);
    const witnessProof = await createWitnessProof(witnessSignerFn, versionId, witnessVmId);

    const resolved = await resolveDIDFromLog(legacyLog, {
      verifier: testImplementation,
      witnessProofs: [{ versionId, proof: [witnessProof] }],
    });

    expect(resolved.didDocumentMetadata.witness?.witnesses).toHaveLength(1);
    expect(resolved.didDocumentMetadata.witness?.witnesses?.[0].id).toBe(witnessId);
    expect(resolved.didDocumentMetadata.witness?.threshold).toBe(1);
  });

  test('Genesis with witness: null normalizes to empty witness on resolution', async () => {
    const log = await buildV05Genesis({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: null,
      verifier: createTestVerifier(authKey),
    });

    const resolved = await resolveDIDFromLog(log, {
      verifier: testImplementation,
    });

    // Verify witness: null is normalized to empty object on resolution
    expect(resolved.didDocumentMetadata.witness).toEqual({});
  });

  test('V1.0 genesis with witness: null normalizes to {} in metadata', async () => {
    const result = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: null,
    });

    // Verify witness: null is normalized to {} in metadata
    expect(result.doc.verificationMethod).toBeDefined();
    expect(result.meta.witness).toEqual({});
  });

  test('V1.0 genesis with legacy witness format normalizes consistently', async () => {
    const witness1 = await generateTestVerificationMethod();
    const witness2 = await generateTestVerificationMethod();
    const witnessId1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessId2 = `did:key:${witness2.publicKeyMultibase}`;

    const result = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      witness: {
        witnesses: [{ id: witnessId1 }, { id: witnessId2 }],
        threshold: 1,
      },
    });

    // Verify legacy format is normalized consistently
    expect(result.meta.witness?.witnesses).toHaveLength(2);
    expect(result.meta.witness?.threshold).toBe(1);
    expect(result.meta.witness?.witnesses?.[0].id).toBe(witnessId1);
    expect(result.meta.witness?.witnesses?.[1].id).toBe(witnessId2);
  });
});
