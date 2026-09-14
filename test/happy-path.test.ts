import { describe, expect, test } from 'vitest';
import type { DIDDocument } from '../src/interfaces.js';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import {
  createTestDIDDocument,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

describe('Happy Path Tests', () => {
  test('Create DID with single auth key', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });

    const { did, doc, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier,
    });

    expect(did).toContain('did:webvh:');
    expect(doc.verificationMethod).toHaveLength(1);
    expect(doc.authentication).toHaveLength(1);
    expect(doc.authentication![0]).toBe(doc.verificationMethod![0]!.id!);
  });

  test('Create DID with multiple auth keys', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const authKey2 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const keyId1 = `{DID}#${authKey1.publicKeyMultibase!.slice(-8)}`;
    const keyId2 = `{DID}#${authKey2.publicKeyMultibase!.slice(-8)}`;
    const didDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
      verificationMethod: [
        {
          id: keyId1,
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey1.publicKeyMultibase!,
        },
        {
          id: keyId2,
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey2.publicKeyMultibase!,
        },
      ],
      authentication: [keyId1, keyId2],
    };

    const { did, doc, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!],
      didDocument,
      verifier,
    });

    expect(did).toContain('did:webvh:');
    expect(doc.verificationMethod).toHaveLength(2);
    expect(doc.authentication).toHaveLength(2);
    expect(doc.authentication).toContain(doc.verificationMethod![0]!.id);
    expect(doc.authentication).toContain(doc.verificationMethod![1]!.id);
  });

  test('Update DID with new auth key', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const authKey2 = await generateTestVerificationMethod();
    const nextDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [
        {
          id: `${did}#${authKey2.publicKeyMultibase!.slice(-8)}`,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: authKey2.publicKeyMultibase!,
        },
      ],
      authentication: [`${did}#${authKey2.publicKeyMultibase!.slice(-8)}`],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey2.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.verificationMethod).toHaveLength(1);
    expect(updatedDoc.authentication).toHaveLength(1);
    expect(updatedDoc.authentication![0]).toBe(updatedDoc.verificationMethod![0]!.id!);
  });

  test('Update DID with multiple auth keys', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const authKey2 = await generateTestVerificationMethod();
    const authKey3 = await generateTestVerificationMethod();
    const keyId2 = `${did}#${authKey2.publicKeyMultibase!.slice(-8)}`;
    const keyId3 = `${did}#${authKey3.publicKeyMultibase!.slice(-8)}`;

    const nextDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [
        {
          id: keyId2,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: authKey2.publicKeyMultibase!,
        },
        {
          id: keyId3,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: authKey3.publicKeyMultibase!,
        },
      ],
      authentication: [keyId2, keyId3],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey2.publicKeyMultibase!, authKey3.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.verificationMethod).toHaveLength(2);
    expect(updatedDoc.authentication).toHaveLength(2);
    expect(updatedDoc.authentication).toContain(updatedDoc.verificationMethod![0]!.id);
    expect(updatedDoc.authentication).toContain(updatedDoc.verificationMethod![1]!.id);
  });

  test('Update DID with external auth key', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const externalDID = 'did:example:123#key-1';
    const nextDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      authentication: [externalDID],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.authentication).toHaveLength(1);
    expect(updatedDoc.authentication![0]).toBe(externalDID);
  });

  test('Update DID with custom verification relationships', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const assertionKey = await generateTestVerificationMethod();
    const keyAgreementKey = await generateTestVerificationMethod();
    const assertionId = `${did}#${assertionKey.publicKeyMultibase!.slice(-8)}`;
    const agreementId = `${did}#${keyAgreementKey.publicKeyMultibase!.slice(-8)}`;

    const nextDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: did,
      verificationMethod: [
        {
          id: assertionId,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: assertionKey.publicKeyMultibase!,
        },
        {
          id: agreementId,
          type: 'Multikey',
          controller: did,
          publicKeyMultibase: keyAgreementKey.publicKeyMultibase!,
        },
      ],
      assertionMethod: [assertionId],
      keyAgreement: [agreementId],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.verificationMethod).toHaveLength(2);
    expect(updatedDoc.assertionMethod).toHaveLength(1);
    expect(updatedDoc.keyAgreement).toHaveLength(1);
  });

  test('Update DID with service endpoints', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const service = {
      id: '#service-1',
      type: 'TestService',
      serviceEndpoint: 'https://example.com/service',
    };

    const nextDoc: DIDDocument = {
      ...createTestDIDDocument(authKey1, { keyId: `${did}#${authKey1.publicKeyMultibase!.slice(-8)}` }),
      id: did,
      service: [service],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.service).toHaveLength(1);
    expect(updatedDoc.service![0]).toEqual(service);
  });

  test('Update DID with also known as', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const alias = 'did:web:example.com';
    const nextDoc: DIDDocument = {
      ...createTestDIDDocument(authKey1, { keyId: `${did}#${authKey1.publicKeyMultibase!.slice(-8)}` }),
      id: did,
      alsoKnownAs: [alias],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.alsoKnownAs).toHaveLength(1);
    expect(updatedDoc.alsoKnownAs![0]).toBe(alias);
  });

  test('Update DID ignores controller override input', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });
    const injectedController = 'did:example:123';

    const { did: createdDid, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      controller: injectedController,
      verifier,
    } as unknown as Parameters<typeof updateDID>[0]);

    expect(updatedDoc.id).toBe(createdDid);
    expect(updatedDoc.id).not.toBe(injectedController);
  });

  test('Update DID with future update key', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const nextKeyHash = 'z6MkgYGF3thn8k1Qz9P4c3mKthZXNhUgkdwBwE5hbWFJktGH';
    const { doc: updatedDoc, meta } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      nextKeyHashes: [nextKeyHash],
      verifier,
    });

    expect(meta.nextKeyHashes).toHaveLength(1);
    expect(meta.nextKeyHashes[0]).toBe(nextKeyHash);
  });

  test('Sparse update preserves prior DID document state', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1, {
        alsoKnownAs: ['did:example:one'],
        services: [
          {
            id: '#svc',
            type: 'LinkedDomains',
            serviceEndpoint: 'https://example.com',
          },
        ],
      }),
      verifier,
    });

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      verifier,
    });

    expect(updatedDoc.alsoKnownAs).toEqual(['did:example:one']);
    expect(updatedDoc.service).toEqual([
      {
        id: '#svc',
        type: 'LinkedDomains',
        serviceEndpoint: 'https://example.com',
      },
    ]);
  });

  test('Omitted updateKeys stay omitted in update parameters', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const { log: updatedLog, meta } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      verifier,
    });

    expect('updateKeys' in updatedLog[1].parameters).toBe(false);
    expect(meta.updateKeys).toEqual([authKey1.publicKeyMultibase!]);
  });

  test('Update DID with explicit assertionMethod in didDocument', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const externalRef = 'did:example:assertion#key-1';
    const nextDoc: DIDDocument = {
      ...createTestDIDDocument(authKey1, { keyId: `${did}#${authKey1.publicKeyMultibase!.slice(-8)}` }),
      id: did,
      assertionMethod: [externalRef],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.assertionMethod).toEqual([externalRef]);
  });

  test('Update DID with explicit keyAgreement in didDocument', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { did, log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const externalRef = 'did:example:agreement#key-1';
    const nextDoc: DIDDocument = {
      ...createTestDIDDocument(authKey1, { keyId: `${did}#${authKey1.publicKeyMultibase!.slice(-8)}` }),
      id: did,
      keyAgreement: [externalRef],
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: nextDoc,
      verifier,
    });

    expect(updatedDoc.keyAgreement).toEqual([externalRef]);
  });

  test('carry-forward omitted updateKeys across multiple v1.0 updates', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: log1 } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey1),
      verifier,
    });

    const { log: log2 } = await updateDID({
      log: log1,
      signer: createTestSigner(authKey1),
      verifier,
    });

    const { log: log3 } = await updateDID({
      log: log2,
      signer: createTestSigner(authKey1),
      verifier,
    });

    expect('updateKeys' in log2[1].parameters).toBe(false);
    expect('updateKeys' in log3[2].parameters).toBe(false);

    const resolved = await resolveDIDFromLog(log3, { verifier });
    expect(resolved.didDocument).not.toBeNull();
    expect(resolved.didDocumentMetadata.versionId).toBe(log3[2].versionId);
    expect(resolved.didDocumentMetadata.updateKeys).toEqual([authKey1.publicKeyMultibase!]);
  });
});
