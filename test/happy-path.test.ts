import { describe, expect, test } from 'vitest';
import { createDID, updateDID } from '../src/method';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

describe('Happy Path Tests', () => {
  test('Create DID with single auth key', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });

    const { did, doc, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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

    const { did, doc, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!, authKey2.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1, authKey2),
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

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const authKey2 = await generateTestVerificationMethod();
    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey2.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey2),
      verifier,
    });

    expect(updatedDoc.verificationMethod).toHaveLength(1);
    expect(updatedDoc.authentication).toHaveLength(1);
    expect(updatedDoc.authentication![0]).toBe(updatedDoc.verificationMethod![0]!.id!);
  });

  test('Update DID with multiple auth keys', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const authKey2 = await generateTestVerificationMethod();
    const authKey3 = await generateTestVerificationMethod();
    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey2.publicKeyMultibase!, authKey3.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey2, authKey3),
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

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const externalDID = 'did:example:123#key-1';
    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      authentication: [externalDID],
      verifier,
    });

    expect(updatedDoc.authentication).toHaveLength(1);
    expect(updatedDoc.authentication![0]).toBe(externalDID);
  });

  test('Update DID with custom verification relationships', async () => {
    // Create a verification method with authentication purpose for initial DID
    const authKey1 = await generateTestVerificationMethod('authentication');
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    // Create the initial DID
    const { log: initialLog, did } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    // Create verification methods with specific purposes
    const assertionKey = await generateTestVerificationMethod('assertionMethod');
    const keyAgreementKey = await generateTestVerificationMethod('keyAgreement');

    // Update the DID with the new verification methods
    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(assertionKey, keyAgreementKey),
      verifier,
    });

    // Check that the verification methods were added correctly
    expect(updatedDoc.verificationMethod).toHaveLength(2);
    expect(updatedDoc.assertionMethod).toHaveLength(1);
    expect(updatedDoc.keyAgreement).toHaveLength(1);
  });

  test('Update DID with service endpoints', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const service = {
      id: '#service-1',
      type: 'TestService',
      serviceEndpoint: 'https://example.com/service',
    };

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      services: [service],
      verifier,
    });

    expect(updatedDoc.service).toHaveLength(1);
    expect(updatedDoc.service![0]).toEqual(service);
  });

  test('Update DID with also known as', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const alias = 'did:web:example.com';
    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      alsoKnownAs: [alias],
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
      verificationMethods: asPublicVerificationMethods(authKey1),
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
      verificationMethods: asPublicVerificationMethods(authKey1),
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
      verificationMethods: asPublicVerificationMethods(authKey1),
      alsoKnownAs: ['did:example:one'],
      services: [
        {
          id: '#svc',
          type: 'LinkedDomains',
          serviceEndpoint: 'https://example.com',
        },
      ],
      verifier,
    });

    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      verificationMethods: asPublicVerificationMethods(authKey1),
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
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const { log: updatedLog, meta } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    expect('updateKeys' in updatedLog[1].parameters).toBe(false);
    expect(meta.updateKeys).toEqual([authKey1.publicKeyMultibase!]);
  });

  test('Update DID with explicit assertionMethod option', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const externalRef = 'did:example:assertion#key-1';
    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      assertionMethod: [externalRef],
      verifier,
    });

    expect(updatedDoc.assertionMethod).toEqual([externalRef]);
  });

  test('Update DID with explicit keyAgreement option', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey1 });

    const { log: initialLog } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier,
    });

    const externalRef = 'did:example:agreement#key-1';
    const { doc: updatedDoc } = await updateDID({
      log: initialLog,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      keyAgreement: [externalRef],
      verifier,
    });

    expect(updatedDoc.keyAgreement).toEqual([externalRef]);
  });
});
