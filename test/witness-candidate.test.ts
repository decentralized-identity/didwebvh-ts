import { beforeAll, describe, expect, test } from 'vitest';
import { verifyWitnessCandidate, type WitnessRefusal } from '../src/core/witness-candidate.js';
import type {
  CreateDIDResult,
  DataIntegrityProofTemplate,
  DIDLog,
  VerificationMethod,
  WitnessProofFileEntry,
} from '../src/interfaces.js';
import { createDID, updateDID } from '../src/method.js';
import { createWitnessProof, signWitnessProofEntry } from '../src/witness.js';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

describe('Witness candidate verification', async () => {
  let authKey: VerificationMethod;
  let witness1: VerificationMethod, witness2: VerificationMethod;
  let testImplementation: TestCryptoImplementation;
  let created: CreateDIDResult;
  // Version 1 carries the witness parameter, so every later update — and every
  // resolution of this log — needs version 1's approvals in hand.
  let v1Proofs: WitnessProofFileEntry[];

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    witness1 = await generateTestVerificationMethod();
    witness2 = await generateTestVerificationMethod();
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey });

    created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      witness: {
        threshold: 2,
        witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }, { id: `did:key:${witness2.publicKeyMultibase}` }],
      },
      verifier: testImplementation,
    });

    const versionId = created.log[0].versionId;
    v1Proofs = [
      {
        versionId,
        proof: await Promise.all([
          createWitnessProof(witnessSigner(witness1), versionId, witnessVerificationMethod(witness1)),
          createWitnessProof(witnessSigner(witness2), versionId, witnessVerificationMethod(witness2)),
        ]),
      },
    ];
  });

  const witnessVerificationMethod = (vm: VerificationMethod) =>
    `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`;

  const witnessSigner = (vm: VerificationMethod) => {
    const signer = createTestSigner(vm);
    return async (data: { versionId: string }, proofTemplate?: DataIntegrityProofTemplate) => {
      const proof: DataIntegrityProofTemplate = {
        type: 'DataIntegrityProof',
        cryptosuite: 'eddsa-jcs-2022',
        verificationMethod: signer.getVerificationMethodId(),
        created: new Date().toISOString(),
        proofPurpose: 'authentication',
        ...proofTemplate,
      };
      const signed = await signer.sign({ document: data, proof });
      return {
        proof: {
          verificationMethod: signer.getVerificationMethodId(),
          proofValue: signed.proofValue,
        },
      };
    };
  };

  const updateFrom = async (log: DIDLog, vm: VerificationMethod) =>
    updateDID({
      log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(vm),
      witnessProofs: v1Proofs,
      verifier: testImplementation,
    });

  test('accepts the next entry and returns the versionId to sign', async () => {
    const nextKey = await generateTestVerificationMethod();
    const updated = await updateFrom(created.log, nextKey);
    const candidateEntry = updated.log[1];

    const verified = await verifyWitnessCandidate({
      heldLog: created.log,
      candidateEntry,
      verifier: testImplementation,
      witnessProofs: v1Proofs,
    });

    expect(verified.versionId).toBe(candidateEntry.versionId);
    expect(verified.log).toHaveLength(2);

    // The point of verifying: this is what the witness then signs.
    const signed = await signWitnessProofEntry({
      versionId: verified.versionId,
      witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
      witnessSignersByDid: {
        [`did:key:${witness1.publicKeyMultibase}`]: createTestSigner(witness1),
      },
    });
    expect(signed.versionId).toBe(candidateEntry.versionId);
    expect(signed.proof).toHaveLength(1);
  });

  test('refuses a candidate whose state was altered after signing', async () => {
    const nextKey = await generateTestVerificationMethod();
    const updated = await updateFrom(created.log, nextKey);
    const tampered = structuredClone(updated.log[1]);
    tampered.state.alsoKnownAs = ['did:web:attacker.example'];

    await expect(
      verifyWitnessCandidate({
        heldLog: created.log,
        candidateEntry: tampered,
        verifier: testImplementation,
        witnessProofs: v1Proofs,
      })
    ).rejects.toMatchObject({ name: 'WitnessRefusal', code: 'candidate-invalid' });
  });

  test('refuses a replay of an entry already in the held log', async () => {
    await expect(
      verifyWitnessCandidate({
        heldLog: created.log,
        candidateEntry: created.log[0],
        verifier: testImplementation,
        witnessProofs: v1Proofs,
      })
    ).rejects.toMatchObject({ name: 'WitnessRefusal', code: 'not-next-entry' });
  });

  test('refuses a second, different entry for a version already witnessed, and keeps both', async () => {
    // Two updates built from the same log: each is a valid version 2, and they
    // differ. The witness has already approved one of them.
    const keyA = await generateTestVerificationMethod();
    const keyB = await generateTestVerificationMethod();
    const first = await updateFrom(created.log, keyA);
    const second = await updateFrom(created.log, keyB);

    expect(first.log[1].versionId).not.toBe(second.log[1].versionId);

    // The witness holds the approvals for what it has already witnessed, not
    // only the log: resolving its own copy of version 2 requires version 2's
    // proofs.
    const heldVersionId = first.log[1].versionId;
    const heldProofs = [
      ...v1Proofs,
      {
        versionId: heldVersionId,
        proof: await Promise.all([
          createWitnessProof(witnessSigner(witness1), heldVersionId, witnessVerificationMethod(witness1)),
          createWitnessProof(witnessSigner(witness2), heldVersionId, witnessVerificationMethod(witness2)),
        ]),
      },
    ];

    const refusal = await verifyWitnessCandidate({
      heldLog: first.log, // held: version 2 is first.log[1]
      candidateEntry: second.log[1],
      verifier: testImplementation,
      witnessProofs: heldProofs,
    }).then(
      () => undefined,
      (e) => e as WitnessRefusal
    );

    expect(refusal?.code).toBe('conflicting-entry');
    // Both entries survive on the error: this pair is the only evidence that
    // two different version 2s were offered.
    expect(refusal?.heldEntry?.versionId).toBe(first.log[1].versionId);
    expect(refusal?.candidateEntry?.versionId).toBe(second.log[1].versionId);

    // What the signing API does with the same candidate today: it takes the
    // versionId and signs, having seen neither log.
    const signedAnyway = await signWitnessProofEntry({
      versionId: second.log[1].versionId,
      witnesses: [{ id: `did:key:${witness1.publicKeyMultibase}` }],
      witnessSignersByDid: {
        [`did:key:${witness1.publicKeyMultibase}`]: createTestSigner(witness1),
      },
    });
    expect(signedAnyway.proof).toHaveLength(1);
  });

  test('refuses when the witness holds no log at all', async () => {
    const nextKey = await generateTestVerificationMethod();
    const updated = await updateFrom(created.log, nextKey);

    await expect(
      verifyWitnessCandidate({
        heldLog: [],
        candidateEntry: updated.log[1],
        verifier: testImplementation,
        witnessProofs: v1Proofs,
      })
    ).rejects.toMatchObject({ name: 'WitnessRefusal', code: 'held-log-invalid' });
  });

  test('refuses when the held copy itself does not resolve', async () => {
    const nextKey = await generateTestVerificationMethod();
    const updated = await updateFrom(created.log, nextKey);
    const corruptHeld = structuredClone(created.log);
    corruptHeld[0].state.alsoKnownAs = ['did:web:attacker.example'];

    await expect(
      verifyWitnessCandidate({
        heldLog: corruptHeld,
        candidateEntry: updated.log[1],
        verifier: testImplementation,
        witnessProofs: v1Proofs,
      })
    ).rejects.toMatchObject({ name: 'WitnessRefusal', code: 'held-log-invalid' });
  });
});
