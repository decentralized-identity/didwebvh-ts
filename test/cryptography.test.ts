import { beforeAll, describe, expect, test } from "bun:test";
import { AbstractCrypto, createDocumentSigner } from "../src/cryptography";
import { SigningInput, SigningOutput, SignerOptions, Verifier } from "../src/interfaces";
import { documentStateIsValid } from "../src/assertions";
import { countVerifiedWitnessApprovals } from "../src/witness";
import { MultibaseEncoding } from "../src/utils/multiformats";
import { multibaseEncode } from "../src/utils/multiformats";

// Mock crypto implementation for testing
class MockCryptoImplementation extends AbstractCrypto implements Verifier {
  private mockSignature = new Uint8Array([1, 2, 3, 4]);
  private shouldVerifySucceed: boolean;

  constructor(options: SignerOptions, shouldVerifySucceed: boolean = true) {
    super(options);
    this.shouldVerifySucceed = shouldVerifySucceed;
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    return { proofValue: multibaseEncode(this.mockSignature, MultibaseEncoding.BASE58_BTC) };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return this.shouldVerifySucceed;
  }
}

describe("Injectable Cryptography Tests", () => {
  let mockImplementation: MockCryptoImplementation;
  let failingMockImplementation: MockCryptoImplementation;
  let testDoc: any;
  let testProof: any;
  const updateKey = "z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK";

  beforeAll(() => {
    // Create a mock implementation that succeeds verification
    mockImplementation = new MockCryptoImplementation({
      verificationMethod: {
        id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        type: "Multikey",
        publicKeyMultibase: updateKey
      }
    });

    // Create a mock implementation that fails verification
    failingMockImplementation = new MockCryptoImplementation({
      verificationMethod: {
        id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
        type: "Multikey",
        publicKeyMultibase: updateKey
      }
    }, false);

    // Create a test document
    testDoc = {
      id: "did:example:123",
      name: "Test Document"
    };

    // Create a test proof
    testProof = {
      type: "DataIntegrityProof",
      cryptosuite: "eddsa-jcs-2022",
      verificationMethod: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
      created: "2024-03-06T00:00:00Z",
      proofPurpose: "assertionMethod"
    };
  });

  test("Sign document with custom implementation", async () => {
    const documentSigner = createDocumentSigner(mockImplementation, mockImplementation.getVerificationMethodId());
    const signedDoc = await documentSigner(testDoc);
    
    expect(signedDoc).toBeDefined();
    expect(signedDoc.proof).toBeDefined();
    expect(signedDoc.proof.proofValue).toBeDefined();
  });

  test("Verify document with successful implementation", async () => {
    const signedDoc = {
      ...testDoc,
      proof: {
        ...testProof,
        proofValue: "z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH"
      }
    };

    const result = await documentStateIsValid(
      signedDoc,
      [updateKey],
      null,
      true,
      mockImplementation
    );

    expect(result).toBe(true);
  });

  test("Verify document with failing implementation", async () => {
    const signedDoc = {
      ...testDoc,
      proof: {
        ...testProof,
        proofValue: "z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH"
      }
    };

    expect(
      documentStateIsValid(
        signedDoc,
        [updateKey],
        null,
        true,
        failingMockImplementation
      )
    ).rejects.toThrow("Proof 0 failed verification");
  });

  test("Count verified witness approvals with successful implementation", async () => {
    const logEntry = {
      versionId: "test-version",
      versionTime: "2024-03-06T00:00:00Z",
      parameters: {},
      state: testDoc
    };

    const witnessProofs = [{
      versionId: "test-version",
      proof: [{
        ...testProof,
        proofValue: "z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH"
      }]
    }];

    const witness = {
      threshold: "1",
      witnesses: [{
        id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      }]
    };

    const approvals = await countVerifiedWitnessApprovals(logEntry, witnessProofs, witness, mockImplementation);
    expect(approvals).toBe(1);
  });

  test("Count verified witness approvals logs and skips invalid proofs", async () => {
    const logEntry = {
      versionId: "test-version",
      versionTime: "2024-03-06T00:00:00Z",
      parameters: {},
      state: testDoc
    };

    const witnessProofs = [{
      versionId: "test-version",
      proof: [{
        ...testProof,
        proofValue: "z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH"
      }]
    }];

    const witness = {
      threshold: "1",
      witnesses: [{
        id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      }]
    };

    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(" "));
    };

    try {
      const approvals = await countVerifiedWitnessApprovals(logEntry, witnessProofs, witness, failingMockImplementation);
      expect(approvals).toBe(0);
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings.some((msg) => msg.includes("Invalid witness proof signature"))).toBe(true);
  });

  test("Require verifier implementation", async () => {
    const signedDoc = {
      ...testDoc,
      proof: {
        ...testProof,
        proofValue: "z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH"
      }
    };

    expect(
      documentStateIsValid(signedDoc, [mockImplementation.getVerificationMethodId()], null, true)
    ).rejects.toThrow("Verifier implementation is required");
  });

  test("Require verifier implementation for witness proofs", async () => {
    const logEntry = {
      versionId: "test-version",
      versionTime: "2024-03-06T00:00:00Z",
      parameters: {},
      state: testDoc
    };

    const witnessProofs = [{
      versionId: "test-version",
      proof: [{
        ...testProof,
        proofValue: "z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH"
      }]
    }];

    const witness = {
      threshold: "1",
      witnesses: [{
        id: "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
      }]
    };

    expect(
      countVerifiedWitnessApprovals(logEntry, witnessProofs, witness)
    ).rejects.toThrow("Verifier implementation is required");
  });
}); 
