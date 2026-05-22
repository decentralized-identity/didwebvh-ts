import { beforeAll, describe, expect, test } from "bun:test";
import { createDID, resolveDIDFromLog, updateDID } from "../src/method";
import type { DIDLog, VerificationMethod } from "../src/interfaces";
import { generateTestVerificationMethod, createTestSigner, TestCryptoImplementation } from "./utils";
import { createWitnessProof } from "../src/witness";

describe("Witness Implementation Tests", async () => {
  let authKey: VerificationMethod;
  let witness1: VerificationMethod, witness2: VerificationMethod, witness3: VerificationMethod;
  let initialDID: { did: string; doc: any; meta: any; log: DIDLog };
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

  test("Create DID with witness threshold", async () => {
    initialDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: {
        threshold: 2,
        witnesses: [
          { id: `did:key:${witness1.publicKeyMultibase}` },
          { id: `did:key:${witness2.publicKeyMultibase}` }
        ]
      },
      verifier: testImplementation
    });

    expect(initialDID.meta?.witness?.threshold).toBe(2);
    expect(initialDID.meta?.witness?.witnesses).toHaveLength(2);
  });

  test("Resolve DID with witness proofs meeting threshold", async () => {
    // Create witness proofs for the initial DID's version
    const versionId = initialDID.log[0].versionId;
    
    // Create proofs from witness1 and witness2 using their signers
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2))
    ]);

    const witnessProofs = [{
      versionId,
      proof: proofs
    }];

    // Resolve the DID log with witness proofs
    const resolved = await resolveDIDFromLog(initialDID.log, { 
      witnessProofs,
      verifier: testImplementation 
    });
    
    expect(resolved.meta?.witness?.threshold).toBe(2);
    expect(resolved.did).toBe(initialDID.did);
  });

  test("Create DID without witnesses then update to add witnesses", async () => {
    // Create initial DID without witnesses
    const noWitnessDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      verifier: testImplementation
    });

    const newAuthKey = await generateTestVerificationMethod();

    const updatedDID = await updateDID({
      log: noWitnessDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      verificationMethods: [newAuthKey],
      witness: {
        threshold: 2,
        witnesses: [
          { id: `did:key:${witness1.publicKeyMultibase}` },
          { id: `did:key:${witness2.publicKeyMultibase}` }
        ]
      },
      verifier: testImplementation
    });

    // Create witness proofs for the new version
    const newVersionId = updatedDID.log[1].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, newVersionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, newVersionId, witnessVerificationMethod(witness2))
    ]);

    const witnessProofs = [{
      versionId: newVersionId,
      proof: proofs
    }];

    const resolved = await resolveDIDFromLog(updatedDID.log, { 
      verifier: testImplementation,
      witnessProofs
    });
    expect(resolved.meta?.witness?.threshold).toBe(2);
    expect(updatedDID.log).toHaveLength(2);
    expect(resolved.meta?.witness?.witnesses).toHaveLength(2);
  });

  test("Replace witness list with new witnesses", async () => {
    const newWitness = await generateTestVerificationMethod();
    
    // Create proofs for initial version
    const versionId = initialDID.log[0].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2))
    ]);
    const witnessProofs = [{ versionId, proof: proofs }];
    
    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: {
        threshold: 1,
        witnesses: [
          { id: `did:key:${newWitness.publicKeyMultibase}` }
        ]
      },
      verifier: testImplementation,
      witnessProofs
    });
    
    // Create proof for new version from new witness
    const newVersionId = updatedDID.log[1].versionId;
    const newWitnessSignerFn = createWitnessSigner(newWitness);
    const newProof = await createWitnessProof(newWitnessSignerFn, newVersionId, witnessVerificationMethod(newWitness));
    const newWitnessProofs = [{
      versionId: newVersionId,
      proof: [newProof]
    }];
    
    const resolved = await resolveDIDFromLog(updatedDID.log, { 
      verifier: testImplementation,
      witnessProofs: newWitnessProofs
    });
    expect(resolved.meta?.witness?.witnesses).toHaveLength(1);
    expect(resolved.meta?.witness?.threshold).toBe(1);
  });

  test("Disable witnessing by setting witness list to null", async () => {
    // Create proofs for initial version
    const versionId = initialDID.log[0].versionId;
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId, witnessVerificationMethod(witness1)),
      createWitnessProof(witness2SignerFn, versionId, witnessVerificationMethod(witness2))
    ]);
    const witnessProofs = [{ versionId, proof: proofs }];
    
    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: null,
      verifier: testImplementation,
      witnessProofs
    });

    const resolved = await resolveDIDFromLog(updatedDID.log, { verifier: testImplementation });
    expect(resolved.meta.witness).toBeEmpty();
  });

  test("Verify witness proofs from did-witness.json", async () => {
    // Create real witness proofs using the utility
    const mockWitnessFile = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(createWitnessSigner(witness1), initialDID.log[0].versionId, witnessVerificationMethod(witness1))
        ]
      },
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(createWitnessSigner(witness2), initialDID.log[0].versionId, witnessVerificationMethod(witness2))
        ]
      },
      {
        versionId: "future-version-id",
        proof: [
          // This proof should be ignored since version doesn't exist in log
          await createWitnessProof(createWitnessSigner(witness1), "future-version-id", witnessVerificationMethod(witness1))
        ]
      }
    ];

    const resolved = await resolveDIDFromLog(initialDID.log, {
      witnessProofs: mockWitnessFile,
      verifier: testImplementation
    });

    expect(resolved.did).toBe(initialDID.did);
  });

  test("Reject witness proofs with invalid proofPurpose", async () => {
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
            proofPurpose: "authentication"
          }
        ]
      }
    ];

    await expect(
      resolveDIDFromLog(initialDID.log, {
        witnessProofs,
        verifier: testImplementation
      })
    ).rejects.toThrow("Invalid witness proof purpose");
  });

  const createWitnessSigner = (verificationMethod: VerificationMethod) => {
    const signer = createTestSigner(verificationMethod);
    return async (data: any, proofTemplate?: any) => {
      const proof = {
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        verificationMethod: signer.getVerificationMethodId(),
        created: new Date().toISOString(),
        proofPurpose: "authentication",
        ...proofTemplate
      };
      const signResult = await signer.sign({ document: data, proof });
      return {
        proof: {
          verificationMethod: signer.getVerificationMethodId(),
          proofValue: signResult.proofValue
        }
      };
    };
  };
});
