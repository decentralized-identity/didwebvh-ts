import { beforeAll, describe, expect, test, vi } from 'vitest';
import { documentStateIsValid } from '../src/assertions';
import {
  AbstractCrypto,
  createDataIntegrityProofTemplate,
  createDocumentSigner,
  signDataIntegrityProof,
} from '../src/cryptography';
import type {
  DataIntegrityProofTemplate,
  DIDLogEntry,
  SignerOptions,
  SigningInput,
  SigningOutput,
  Verifier,
} from '../src/interfaces';
import { createHash, createHashHex, deriveHash } from '../src/utils/crypto';
import { MultibaseEncoding, multibaseEncode } from '../src/utils/multiformats';
import { countVerifiedWitnessApprovals, createWitnessProof } from '../src/witness';

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

describe('Injectable Cryptography Tests', () => {
  let mockImplementation: MockCryptoImplementation;
  let failingMockImplementation: MockCryptoImplementation;
  let testDoc: { id: string; name: string };
  let testProof: DataIntegrityProofTemplate;
  const updateKey = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';

  beforeAll(() => {
    // Create a mock implementation that succeeds verification
    mockImplementation = new MockCryptoImplementation({
      verificationMethod: {
        id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        type: 'Multikey',
        publicKeyMultibase: updateKey,
      },
    });

    // Create a mock implementation that fails verification
    failingMockImplementation = new MockCryptoImplementation(
      {
        verificationMethod: {
          id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          type: 'Multikey',
          publicKeyMultibase: updateKey,
        },
      },
      false
    );

    // Create a test document
    testDoc = {
      id: 'did:example:123',
      name: 'Test Document',
    };

    // Create a test proof
    testProof = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
      created: '2024-03-06T00:00:00Z',
      proofPurpose: 'assertionMethod',
    };
  });

  test('Sign document with custom implementation', async () => {
    const documentSigner = createDocumentSigner(mockImplementation, mockImplementation.getVerificationMethodId());
    const signedDoc = await documentSigner(testDoc);

    expect(signedDoc).toBeDefined();
    expect(signedDoc.proof).toBeDefined();
    expect(signedDoc.proof.proofValue).toBeDefined();
  });

  test('controller and witness signing preserve the same generic proof shape', async () => {
    const created = '2024-03-06T00:00:00Z';
    const verificationMethod = mockImplementation.getVerificationMethodId();
    const controllerTemplate = createDataIntegrityProofTemplate({
      verificationMethod,
      created,
      proofPurpose: 'assertionMethod',
    });

    const controllerProof = await signDataIntegrityProof(
      {
        versionId: '1-test',
        versionTime: created,
        parameters: {},
        state: testDoc,
      },
      controllerTemplate,
      mockImplementation
    );

    const witnessProof = await createWitnessProof(
      async (document, proofTemplate) => {
        const proof = await signDataIntegrityProof(document, proofTemplate!, mockImplementation);
        return { proof };
      },
      '1-test',
      verificationMethod,
      created
    );

    expect(Object.keys(controllerProof).sort()).toEqual(Object.keys(witnessProof).sort());
    expect(controllerProof).toMatchObject({
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod,
      created,
      proofPurpose: 'assertionMethod',
    });
    expect(witnessProof).toMatchObject({
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod,
      created,
      proofPurpose: 'assertionMethod',
    });
  });

  test('Verify document with successful implementation', async () => {
    const signedDoc: DIDLogEntry = {
      versionId: '1-test',
      versionTime: '2024-03-06T00:00:00Z',
      parameters: {},
      state: testDoc,
      proof: [
        {
          ...testProof,
          proofValue: 'z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH',
        },
      ],
    };

    const result = await documentStateIsValid(signedDoc, [updateKey], null, true, mockImplementation);

    expect(result).toBe(true);
  });

  test('Verify document with failing implementation', async () => {
    const signedDoc: DIDLogEntry = {
      versionId: '1-test',
      versionTime: '2024-03-06T00:00:00Z',
      parameters: {},
      state: testDoc,
      proof: [
        {
          ...testProof,
          proofValue: 'z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH',
        },
      ],
    };

    expect(documentStateIsValid(signedDoc, [updateKey], null, true, failingMockImplementation)).rejects.toThrow(
      'Proof 0 failed verification'
    );
  });

  test('Count verified witness approvals with successful implementation', async () => {
    const logEntry = {
      versionId: 'test-version',
      versionTime: '2024-03-06T00:00:00Z',
      parameters: {},
      state: testDoc,
    };

    const witnessProofs = [
      {
        versionId: 'test-version',
        proof: [
          {
            ...testProof,
            proofValue: 'z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH',
          },
        ],
      },
    ];

    const witness = {
      threshold: '1',
      witnesses: [
        {
          id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        },
      ],
    };

    const approvals = await countVerifiedWitnessApprovals(logEntry, witnessProofs, witness, mockImplementation);
    expect(approvals).toBe(1);
  });

  test('Count verified witness approvals logs and skips invalid proofs', async () => {
    const logEntry = {
      versionId: 'test-version',
      versionTime: '2024-03-06T00:00:00Z',
      parameters: {},
      state: testDoc,
    };

    const witnessProofs = [
      {
        versionId: 'test-version',
        proof: [
          {
            ...testProof,
            proofValue: 'z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH',
          },
        ],
      },
    ];

    const witness = {
      threshold: '1',
      witnesses: [
        {
          id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        },
      ],
    };

    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    };

    try {
      const approvals = await countVerifiedWitnessApprovals(
        logEntry,
        witnessProofs,
        witness,
        failingMockImplementation
      );
      expect(approvals).toBe(0);
    } finally {
      console.warn = originalWarn;
    }

    expect(warnings.some((msg) => msg.includes('Invalid witness proof signature'))).toBe(true);
  });

  test('Require verifier implementation', async () => {
    const signedDoc: DIDLogEntry = {
      versionId: '1-test',
      versionTime: '2024-03-06T00:00:00Z',
      parameters: {},
      state: testDoc,
      proof: [
        {
          ...testProof,
          proofValue: 'z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH',
        },
      ],
    };

    expect(documentStateIsValid(signedDoc, [mockImplementation.getVerificationMethodId()], null, true)).rejects.toThrow(
      'Verifier implementation is required'
    );
  });

  test('Require verifier implementation for witness proofs', async () => {
    const logEntry = {
      versionId: 'test-version',
      versionTime: '2024-03-06T00:00:00Z',
      parameters: {},
      state: testDoc,
    };

    const witnessProofs = [
      {
        versionId: 'test-version',
        proof: [
          {
            ...testProof,
            proofValue: 'z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH',
          },
        ],
      },
    ];

    const witness = {
      threshold: '1',
      witnesses: [
        {
          id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        },
      ],
    };

    expect(countVerifiedWitnessApprovals(logEntry, witnessProofs, witness)).rejects.toThrow(
      'Verifier implementation is required'
    );
  });
});

describe('Crypto Helpers', () => {
  test('createHashHex returns stable SHA-256 hex for known input', async () => {
    const hex = await createHashHex('abc');

    expect(hex).toBe('ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    expect(hex).toHaveLength(64);
  });

  test('createHashHex matches bytes from createHash', async () => {
    const bytes = await createHash('hello');
    const expectedHex = Array.from(bytes)
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');

    await expect(createHashHex('hello')).resolves.toBe(expectedHex);
  });

  test('deriveHash rejects circular input', async () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;

    await expect(deriveHash(circular)).rejects.toThrow();
  });

  test('deriveHash succeeds when cache-key stringify fails once (defensive branch)', async () => {
    const originalStringify = JSON.stringify;
    let firstCall = true;

    const stringifySpy = vi.spyOn(JSON, 'stringify').mockImplementation((...args) => {
      if (firstCall) {
        firstCall = false;
        throw new TypeError('synthetic stringify failure');
      }

      return originalStringify(...(args as Parameters<typeof JSON.stringify>));
    });

    try {
      await expect(deriveHash({ a: 1, b: 'x' })).resolves.toMatch(/^[1-9A-HJ-NP-Za-km-z]+$/);
    } finally {
      stringifySpy.mockRestore();
    }
  });
});
