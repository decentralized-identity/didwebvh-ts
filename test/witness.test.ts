import { beforeAll, describe, expect, test } from 'bun:test';
import type { CreateDIDResult, DataIntegrityProofTemplate, Signer, VerificationMethod } from '../src/interfaces';
import { DidResolutionError } from '../src/interfaces';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method';
import { deriveHash, parseDidKeyDid, parseDidKeyVerificationMethod } from '../src/utils';
import {
  countWitnessApprovals,
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from '../src/witness';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

describe('Witness Implementation Tests', async () => {
  let authKey: VerificationMethod;
  let witness1: VerificationMethod, witness2: VerificationMethod, witness3: VerificationMethod;
  let initialDID: CreateDIDResult;
  let testImplementation: TestCryptoImplementation;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    witness1 = await generateTestVerificationMethod();
    witness2 = await generateTestVerificationMethod();
    witness3 = await generateTestVerificationMethod();
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey });
  });

  const witnessVerificationMethod = (vm: VerificationMethod) =>
    `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`;

  test('Create DID with witness threshold', async () => {
    initialDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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

    expect(resolved.meta?.witness?.threshold).toBe(2);
    expect(resolved.did).toBe(initialDID.did);
  });

  test('Create DID without witnesses then update to add witnesses', async () => {
    // Create initial DID without witnesses
    const noWitnessDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const newAuthKey = await generateTestVerificationMethod();

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(newAuthKey),
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
    expect(resolved.meta?.witness?.threshold).toBe(2);
    expect(updatedDID.log).toHaveLength(2);
    expect(resolved.meta?.witness?.witnesses).toHaveLength(2);
  });

  test('Resolve DID rejects duplicate witness IDs in witness parameters', async () => {
    const noWitnessDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const duplicateWitnessId = `did:key:${witness1.publicKeyMultibase}`;
    const newAuthKey = await generateTestVerificationMethod();

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(newAuthKey),
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

    expect(
      resolveDIDFromLog(tamperedLog, {
        verifier: testImplementation,
      })
    ).rejects.toThrow(`Duplicate witness id: ${duplicateWitnessId}`);
  });

  test('API e2e: create, update, witness, and resolve with raw multibase updateKeys', async () => {
    const authKey2 = await generateTestVerificationMethod();

    const created = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      verificationMethods: asPublicVerificationMethods(authKey2),
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

    expect(resolved.did).toBe(updated.did);
    expect(resolved.meta?.updateKeys).toEqual([authKey2.publicKeyMultibase!]);
  });

  test('API e2e: rejects did:key-formatted updateKeys in update flow', async () => {
    const authKey2 = await generateTestVerificationMethod();
    const authKey3 = await generateTestVerificationMethod();

    const created = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      verificationMethods: asPublicVerificationMethods(authKey2),
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

    await expect(
      updateDID({
        log: firstUpdate.log,
        signer: createTestSigner(authKey2),
        updateKeys: [authKey3.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey3),
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
      })
    ).rejects.toThrow('is not authorized to update.');
  });

  test('API e2e: rejects did:webvh verificationMethod in DID log entry proof', async () => {
    const authKey2 = await generateTestVerificationMethod();

    const created = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
        verificationMethods: asPublicVerificationMethods(authKey2),
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
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 1,
        witnesses: [{ id: `did:key:${newWitness.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
      witnessProofs,
    });

    // Create proof for new version from new witness
    const newVersionId = updatedDID.log[1].versionId;
    const newWitnessSignerFn = createWitnessSigner(newWitness);
    const newProof = await createWitnessProof(newWitnessSignerFn, newVersionId, witnessVerificationMethod(newWitness));
    const newWitnessProofs = [
      {
        versionId: newVersionId,
        proof: [newProof],
      },
    ];

    const resolved = await resolveDIDFromLog(updatedDID.log, {
      verifier: testImplementation,
      witnessProofs: [...witnessProofs, ...newWitnessProofs],
    });
    expect(resolved.meta?.witness?.witnesses).toHaveLength(1);
    expect(resolved.meta?.witness?.threshold).toBe(1);
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
      verificationMethods: asPublicVerificationMethods(authKey),
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
    expect(resolved.meta.witness).toBeEmpty();
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

    expect(resolved.did).toBe(initialDID.did);
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
      await expect(
        resolveDIDFromLog(initialDID.log, {
          witnessProofs,
          verifier: testImplementation,
        })
      ).rejects.toThrow(`Witness threshold not met for version ${initialDID.log[0].versionId}`);
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
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      verificationMethods: asPublicVerificationMethods(authKey),
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

    await expect(
      resolveDIDFromLog(updatedDid.log, {
        verifier: testImplementation,
        witnessProofs: [
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
        ],
      })
    ).rejects.toThrow(`Witness threshold not met for version ${didWithWitness.log[0].versionId}`);
  });

  test('Resolve accepts later proof for earlier required entry', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      verificationMethods: asPublicVerificationMethods(authKey),
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

    expect(resolved.did).toBe(updatedDid.did);
  });

  test('Resolve ignores invalid witness proof if enough valid proofs remain', async () => {
    const witnessDid1 = `did:key:${witness1.publicKeyMultibase}`;
    const witnessDid2 = `did:key:${witness2.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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

    expect(resolved.did).toBe(didWithWitness.did);
  });

  test('Resolve maps witness threshold failure to invalidDid metadata for partial results', async () => {
    const witnessDid = `did:key:${witness1.publicKeyMultibase}`;
    const didWithWitness = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      verificationMethods: asPublicVerificationMethods(authKey),
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

    expect(resolved.meta.error).toBe(DidResolutionError.InvalidDid);
    expect(resolved.meta.problemDetails).toBeDefined();
    expect(resolved.meta.problemDetails!.type).toBe(
      'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID'
    );
    expect(resolved.meta.problemDetails!.title).toBe('The resolved DID is invalid.');
    expect(resolved.meta.problemDetails!.detail).toContain('Witness threshold not met');
  });

  test('Update DID rejects duplicate witness IDs', async () => {
    const noWitnessDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const duplicateWitnessId = `did:key:${witness1.publicKeyMultibase}`;

    expect(
      updateDID({
        log: noWitnessDID.log,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
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
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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

  const createWitnessSigner = (verificationMethod: VerificationMethod) => {
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
});
