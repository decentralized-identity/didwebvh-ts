import { describe, expect, test } from 'bun:test';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  nextSecond,
  TestCryptoImplementation,
} from './utils';

describe('Watcher Handling', () => {
  test('Create DID with watchers', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const { log } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers,
      verifier,
    });

    const resolved = await resolveDIDFromLog(log, { verifier });
    expect(resolved.meta.watchers).toEqual(watchers);
  });

  test('Watchers persist across updates when not specified', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const initial = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers,
      verifier,
    });

    const updated = await updateDID({
      log: initial.log,
      updated: nextSecond(initial.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });

    const resolved = await resolveDIDFromLog(updated.log, { verifier });
    expect(resolved.meta.watchers).toEqual(watchers);
  });

  test('Disable watchers with null', async () => {
    const authKey = await generateTestVerificationMethod();
    const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const watchers = ['https://watcher.example.com'];

    const initial = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers,
      verifier,
    });

    const updated = await updateDID({
      log: initial.log,
      updated: nextSecond(initial.log),
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      watchers: null,
      verifier,
    });

    const resolved = await resolveDIDFromLog(updated.log, { verifier });
    expect(resolved.meta.watchers).toBeEmpty();
  });
});
