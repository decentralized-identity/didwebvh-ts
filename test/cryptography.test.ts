import { beforeAll, describe, expect, test, vi } from 'vitest';
import { documentStateIsValid, hashChainValid, newKeysAreInNextKeys, scidIsFromHash } from '../src/assertions';
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
import * as utilsModule from '../src/utils';
import { createHash, createHashHex, createSCID, deriveHash, deriveNextKeyHash } from '../src/utils/crypto';
import {
  createMultihash,
  encodeBase58Btc,
  MultibaseEncoding,
  MultihashAlgorithm,
  multibaseEncode,
} from '../src/utils/multiformats';
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

describe('Assertion Guards', () => {
  const updateKey = 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK';
  const proofValue = 'z4PJ7iFV3syhMEHAfwQJuSqyGCHzTH5kJqAGCKnXyyb7vGCmqzpbCHMjK4SfgGkFrXjzWtGmMmPqXEEZYDvbpjTQH';

  const makeDoc = (proofOverride: Record<string, unknown> | Record<string, unknown>[] | null): DIDLogEntry => ({
    versionId: '1-test',
    versionTime: '2024-03-06T00:00:00Z',
    parameters: {},
    state: { id: 'did:example:123' },
    proof: proofOverride as unknown as DIDLogEntry['proof'],
  });

  const baseProof = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: `did:key:${updateKey}`,
    created: '2024-03-06T00:00:00Z',
    proofPurpose: 'assertionMethod',
    proofValue,
  };

  const verifier = new MockCryptoImplementation(
    {
      verificationMethod: {
        id: `did:key:${updateKey}`,
        type: 'Multikey',
        publicKeyMultibase: updateKey,
      },
    },
    true
  );

  test('throws when proof is missing', async () => {
    await expect(documentStateIsValid(makeDoc(null), [updateKey], null, true, verifier)).rejects.toThrow(
      'Missing proof in DID log entry'
    );
  });

  test('normalizes non-array proof into array and verifies', async () => {
    const doc = makeDoc(baseProof);
    await expect(documentStateIsValid(doc, [updateKey], null, true, verifier)).resolves.toBe(true);
  });

  test('throws on unknown proof type', async () => {
    await expect(
      documentStateIsValid(makeDoc({ ...baseProof, type: 'UnknownProofType' }), [updateKey], null, true, verifier)
    ).rejects.toThrow('Unknown proof type UnknownProofType');
  });

  test('throws on invalid proof purpose', async () => {
    await expect(
      documentStateIsValid(makeDoc({ ...baseProof, proofPurpose: 'authentication' }), [updateKey], null, true, verifier)
    ).rejects.toThrow("Invalid proof purpose 'authentication'");
  });

  test('throws on invalid cryptosuite', async () => {
    await expect(
      documentStateIsValid(makeDoc({ ...baseProof, cryptosuite: 'wrong-suite' }), [updateKey], null, true, verifier)
    ).rejects.toThrow('Unknown cryptosuite wrong-suite');
  });

  test('throws when verification method cannot be resolved', async () => {
    const resolveSpy = vi.spyOn(utilsModule, 'resolveVM').mockResolvedValue(null);

    try {
      await expect(documentStateIsValid(makeDoc(baseProof), [updateKey], null, true, verifier)).rejects.toThrow(
        `Verification Method did:key:${updateKey} not found`
      );
    } finally {
      resolveSpy.mockRestore();
    }
  });

  test('throws when resolved multikey does not use ed25519 header', async () => {
    const badHeaderBytes = new Uint8Array([0x00, 0x00, 0x00, 0x00]);
    const resolveSpy = vi.spyOn(utilsModule, 'resolveVM').mockResolvedValue({
      id: `did:key:${updateKey}`,
      type: 'Multikey',
      publicKeyMultibase: multibaseEncode(badHeaderBytes, MultibaseEncoding.BASE58_BTC),
      controller: `did:key:${updateKey}`,
    });

    try {
      await expect(documentStateIsValid(makeDoc(baseProof), [updateKey], null, true, verifier)).rejects.toThrow(
        "multiKey doesn't include ed25519 header (0xed01)"
      );
    } finally {
      resolveSpy.mockRestore();
    }
  });

  test('hashChainValid returns true and false for matching and mismatching hashes', () => {
    expect(hashChainValid('abc', 'abc')).toBe(true);
    expect(hashChainValid('abc', 'def')).toBe(false);
  });

  test('newKeysAreInNextKeys skips validation when previous next-key list is empty', async () => {
    await expect(newKeysAreInNextKeys([updateKey], [])).resolves.toBe(true);
  });

  test('newKeysAreInNextKeys throws when update key hash is not pre-committed', async () => {
    const unrelatedHash = await deriveNextKeyHash('z6Mkp6hULXj3f4P7vLQxqqQF6q2SCMXt9vEmx5R6M1sQ8YvY');
    await expect(newKeysAreInNextKeys([updateKey], [unrelatedHash])).rejects.toThrow('Invalid update key');
  });

  test('scidIsFromHash throws for invalid SCID format', async () => {
    await expect(scidIsFromHash('not-base58-scid', 'test-hash')).rejects.toThrow('Invalid SCID format');
  });

  test('scidIsFromHash throws when SCID uses unsupported algorithm', async () => {
    const digest = new Uint8Array(48);
    digest.fill(1);
    const scidWithSha384 = encodeBase58Btc(createMultihash(digest, MultihashAlgorithm.SHA2_384));

    await expect(scidIsFromHash(scidWithSha384, 'test-hash')).rejects.toThrow(
      'SCID multihash algorithm must be SHA-256'
    );
  });

  test('scidIsFromHash returns true for matching SHA-256 SCID and hash', async () => {
    const digest = new Uint8Array(32);
    digest.fill(7);
    const hash = encodeBase58Btc(createMultihash(digest, MultihashAlgorithm.SHA2_256));
    const scid = await createSCID(hash);

    await expect(scidIsFromHash(scid, hash)).resolves.toBe(true);
  });
});

describe('Crypto Helpers', () => {
  test('createDataIntegrityProofTemplate includes optional id and compulsory fields', () => {
    const template = createDataIntegrityProofTemplate({
      verificationMethod: 'did:key:zTest#zTest',
      id: '#proof-1',
      created: '2024-01-01T00:00:00Z',
      proofPurpose: 'authentication',
    });

    expect(template).toMatchObject({
      id: '#proof-1',
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: 'did:key:zTest#zTest',
      created: '2024-01-01T00:00:00Z',
      proofPurpose: 'authentication',
    });
  });

  test('createDataIntegrityProofTemplate omits id and applies default proof purpose', () => {
    const template = createDataIntegrityProofTemplate({ verificationMethod: 'did:key:zTest#zTest' });

    expect(template.id).toBeUndefined();
    expect(template.proofPurpose).toBe('assertionMethod');
    expect(typeof template.created).toBe('string');
  });

  test('signDataIntegrityProof throws when verificationMethod is missing after sanitization', async () => {
    const badTemplate = {
      type: 'DataIntegrityProof',
      cryptosuite: 'eddsa-jcs-2022',
      verificationMethod: undefined,
      created: '2024-01-01T00:00:00Z',
      proofPurpose: 'assertionMethod',
    } as unknown as DataIntegrityProofTemplate;

    await expect(signDataIntegrityProof({ id: 'doc' }, badTemplate, new MockCryptoImplementation({}))).rejects.toThrow(
      'Data Integrity proof is missing verificationMethod'
    );
  });

  test('signDataIntegrityProof throws when proofValue is missing after sanitization', async () => {
    const template = createDataIntegrityProofTemplate({ verificationMethod: 'did:key:zTest#zTest' });
    const signer = {
      sign: async () => ({ proofValue: undefined as unknown as string }),
      getVerificationMethodId: () => 'did:key:zTest#zTest',
    };

    await expect(signDataIntegrityProof({ id: 'doc' }, template, signer)).rejects.toThrow(
      'Data Integrity proof is missing proofValue'
    );
  });

  test('signDataIntegrityProof falls back to proofTemplate fields when sanitized fields are undefined', async () => {
    const sparseTemplate = {
      type: undefined,
      cryptosuite: undefined,
      verificationMethod: 'did:key:zTemplate#zTemplate',
      created: undefined,
      proofPurpose: undefined,
    } as unknown as DataIntegrityProofTemplate;

    const proof = await signDataIntegrityProof({ id: 'doc' }, sparseTemplate, {
      sign: async () => ({ proofValue: 'zProofValue' }),
      getVerificationMethodId: () => 'did:key:zTemplate#zTemplate',
    });

    expect(proof.type).toBeUndefined();
    expect(proof.cryptosuite).toBeUndefined();
    expect(proof.created).toBeUndefined();
    expect(proof.proofPurpose).toBeUndefined();
    expect(proof.verificationMethod).toBe('did:key:zTemplate#zTemplate');
    expect(proof.proofValue).toBe('zProofValue');
  });

  test('getVerificationMethodId throws when verification method is not configured', () => {
    const crypto = new MockCryptoImplementation({}, true);
    expect(() => crypto.getVerificationMethodId()).toThrow('Verification method not set');
  });

  test('getVerificationMethodId returns dynamic id when useStaticId is false', () => {
    const crypto = new MockCryptoImplementation(
      {
        verificationMethod: {
          id: 'did:key:zDynamic#zDynamic',
          type: 'Multikey',
          publicKeyMultibase: 'zDynamic',
        },
        useStaticId: false,
      },
      true
    );

    expect(crypto.getVerificationMethodId()).toBe('did:key:zDynamic#zDynamic');
  });

  test('getVerificationMethodId returns empty string when dynamic id missing', () => {
    const crypto = new MockCryptoImplementation(
      {
        verificationMethod: {
          type: 'Multikey',
          publicKeyMultibase: 'zNoId',
        },
        useStaticId: false,
      },
      true
    );

    expect(crypto.getVerificationMethodId()).toBe('');
  });

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

  test('createDocumentSigner wraps non-Error throws with document-signing message', async () => {
    const signer = {
      sign: async () => {
        throw 'synthetic failure';
      },
      getVerificationMethodId: () => 'did:key:zTest#zTest',
    };

    const signerFn = createDocumentSigner(signer, 'did:key:zTest#zTest');
    await expect(signerFn({ id: 'doc' })).rejects.toThrow('Document signing failure: synthetic failure');
  });
});
