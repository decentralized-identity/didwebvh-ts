import { beforeAll, describe, expect, test } from "bun:test";
import { createDID, resolveDIDFromLog, updateDID } from "../src/method";
import type { DIDLog, VerificationMethod } from "../src/interfaces";
import { generateTestVerificationMethod, createTestSigner, TestCryptoImplementation } from "./utils";
import { createWitnessProof } from "../src/utils/witness";

// Set environment variables for tests
process.env.IGNORE_ASSERTION_DOCUMENT_STATE_IS_VALID = 'true';

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

  test("Create DID with weighted witness threshold", async () => {
    initialDID = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: {
        threshold: 3,
        witnesses: [
          { id: `did:key:${witness1.publicKeyMultibase}`, weight: 2 },
          { id: `did:key:${witness2.publicKeyMultibase}`, weight: 1 },
          { id: `did:key:${witness3.publicKeyMultibase}`, weight: 1 }
        ]
      },
      verifier: testImplementation
    });

    const resolved = await resolveDIDFromLog(initialDID.log, { verifier: testImplementation });
    expect(resolved.meta?.witness?.threshold).toBe(3);
    expect(resolved.meta?.witness?.witnesses).toHaveLength(3);
    expect(resolved.meta?.witness?.witnesses?.[0].weight).toBe(2);
  });

  test("Update DID with witness proofs meeting threshold", async () => {
    const newAuthKey = await generateTestVerificationMethod();
    
    // Create witness proofs
    const versionId = initialDID.log[0].versionId;
    
    // Create proofs from witness1 and witness2 using their signers
    const witness1SignerFn = createWitnessSigner(witness1);
    const witness2SignerFn = createWitnessSigner(witness2);
    
    const proofs = await Promise.all([
      createWitnessProof(witness1SignerFn, versionId),
      createWitnessProof(witness2SignerFn, versionId)
    ]);

    const witnessProofs = [{
      versionId,
      proof: proofs
    }];

    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [newAuthKey.publicKeyMultibase!],
      verificationMethods: [newAuthKey],
      witnessProofs,
      verifier: testImplementation
    } as any);

    const resolved = await resolveDIDFromLog(updatedDID.log, { verifier: testImplementation });
    expect(resolved.meta?.witness?.threshold).toBe(3);
  });

  test("Replace witness list with new witnesses", async () => {
    const newWitness = await generateTestVerificationMethod();
    
    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: {
        threshold: 1,
        witnesses: [
          { id: `did:key:${newWitness.publicKeyMultibase}`, weight: 1 }
        ]
      },
      verifier: testImplementation
    });

    const resolved = await resolveDIDFromLog(updatedDID.log, { verifier: testImplementation });
    expect(resolved.meta?.witness?.witnesses).toHaveLength(1);
    expect(resolved.meta?.witness?.threshold).toBe(1);
  });

  test("Disable witnessing by setting witness list to null", async () => {
    const updatedDID = await updateDID({
      log: initialDID.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: [authKey],
      witness: null,
      verifier: testImplementation
    });

    const resolved = await resolveDIDFromLog(updatedDID.log, { verifier: testImplementation });
    expect(resolved.meta.witness).toBeNull();
  });

  test("Verify witness proofs from did-witness.json", async () => {
    // Create real witness proofs using the utility
    const mockWitnessFile = [
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(createWitnessSigner(witness1), initialDID.log[0].versionId)
        ]
      },
      {
        versionId: initialDID.log[0].versionId,
        proof: [
          await createWitnessProof(createWitnessSigner(witness2), initialDID.log[0].versionId)
        ]
      },
      {
        versionId: "future-version-id",
        proof: [
          // This proof should be ignored since version doesn't exist in log
          await createWitnessProof(createWitnessSigner(witness1), "future-version-id")
        ]
      }
    ];

    const resolved = await resolveDIDFromLog(initialDID.log, {
      witnessProofs: mockWitnessFile,
      verifier: testImplementation
    });

    expect(resolved.did).toBe(initialDID.did);
  });

  const createWitnessSigner = (verificationMethod: VerificationMethod) => {
    const signer = createTestSigner(verificationMethod);
    return async (data: any) => {
      const signResult = await signer.sign({
        document: data,
        proof: {
          type: "DataIntegrityProof",
          cryptosuite: "eddsa-jcs-2022",
          verificationMethod: signer.getVerificationMethodId(),
          created: new Date().toISOString(),
          proofPurpose: "authentication"
        }
      });
      
      return {
        proof: {
          verificationMethod: signer.getVerificationMethodId(),
          proofValue: signResult.proofValue
        }
      };
    };
  };
});
