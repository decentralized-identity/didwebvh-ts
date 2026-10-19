import { describe, expect, test } from 'vitest';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import {
  appendV05LogEntry,
  createFutureDIDLog,
  createTestDIDDocument,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

describe('Watcher Handling', () => {
  test('Create DID with watchers', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const { log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      watchers,
      verifier,
    });

    const resolved = await resolveDIDFromLog(log, { verifier });
    expect(resolved.didDocumentMetadata.watchers).toEqual(watchers);
  });

  test('Watchers persist across updates when not specified', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const initial = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      watchers,
      verifier,
    });

    const updated = await updateDID({
      log: initial.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier,
    });

    const resolved = await resolveDIDFromLog(updated.log, { verifier });
    expect(resolved.didDocumentMetadata.watchers).toEqual(watchers);
  });

  test('Disable watchers with null', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const initial = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      watchers,
      verifier,
    });

    const updated = await updateDID({
      log: initial.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      watchers: null,
      verifier,
    });

    const resolved = await resolveDIDFromLog(updated.log, { verifier });
    expect(updated.log[1].parameters.watchers).toEqual([]);
    expect(Array.isArray(resolved.didDocumentMetadata.watchers)).toBe(true);
    expect(resolved.didDocumentMetadata.watchers).toEqual([]);
  });

  test.each([
    ['omitted', 'omit' as const],
    ['null', null],
  ])('Resolves watchers as [] when the genesis entry has watchers %s', async (_label, watchers) => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const log = await createFutureDIDLog(authKey, 0, { watchers });

    expect(log[0].parameters.watchers).toEqual(watchers === 'omit' ? undefined : null);
    const resolved = await resolveDIDFromLog(log, { verifier });
    expect(resolved.didDocumentMetadata.watchers).toEqual([]);
  });

  test('Resolves watchers as [] when a later entry sets watchers to null', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const genesis = await createFutureDIDLog(authKey, 0, { watchers: ['https://watcher.example.com'] });
    const log = await appendV05LogEntry({
      log: genesis,
      signer: createTestSigner(authKey),
      watchers: null,
      verifier,
    });

    expect(log[1].parameters.watchers).toBeNull();
    const resolved = await resolveDIDFromLog(log, { verifier });
    expect(resolved.didDocumentMetadata.watchers).toEqual([]);
  });
});
