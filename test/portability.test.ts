import { beforeAll, describe, expect, test } from 'vitest';
import type { CreateDIDResult, DIDLog, VerificationMethod } from '../src/interfaces';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

describe('Portability', () => {
  let authKey: VerificationMethod;
  let testImplementation: TestCryptoImplementation;
  let nonPortableDID: CreateDIDResult;
  let portableDID: CreateDIDResult;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    testImplementation = new TestCryptoImplementation({ verificationMethod: authKey });

    nonPortableDID = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    portableDID = await createDID({
      address: 'example.com',
      portable: true,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });
  });

  test('Rejects setting portable: true in a later entry', async () => {
    const updateResult = await updateDID({
      log: nonPortableDID.log,
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.portable = true;

    const result = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didDocument).toBe(null);
  });

  test('updateDID rejects portable: true as an option', async () => {
    await expect(
      updateDID({
        log: nonPortableDID.log,
        portable: true,
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('portable: true cannot be set in an update entry');
  });

  test('Rejects false-to-true portable transition (portable was explicitly false)', async () => {
    // Create a DID with portable: false explicitly in the first entry
    const did = await createDID({
      address: 'example.com',
      portable: false,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const updateResult = await updateDID({
      log: did.log,
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    // Tamper: try to re-enable portable in a later entry
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.portable = true;

    const result = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didDocument).toBe(null);
  });

  test('Setting portable: false in a later entry permanently locks portability', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      address: 'example.com',
      portable: false,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    // The log entry must carry portable: false in its parameters
    expect(updateResult.log[1].parameters.portable).toBe(false);
    // The returned meta must reflect the lock immediately
    expect(updateResult.meta.portable).toBe(false);

    // Resolution must succeed and report the lock
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.didDocumentMetadata.portable).toBe(false);

    // A subsequent move attempt must be rejected
    await expect(
      updateDID({
        log: updateResult.log,
        address: 'example.org',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('Cannot move DID: portability is disabled');
  });

  test('Rejects SCID change in state.id during portable rename', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const originalScid = portableDID.log[0].parameters.scid as string;
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));

    // Replace SCID in state.id with a different value
    const fakeScid = `${originalScid.slice(0, -4)}XXXX`;
    tamperedLog[1].state.id = (tamperedLog[1].state.id as string).replace(originalScid, fakeScid);

    const result = await resolveDIDFromLog(tamperedLog, { verifier: testImplementation });
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didDocument).toBe(null);
  });

  test('Portable DID moves to a new domain via the domain option', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      address: 'example.org',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const originalDid = portableDID.log[0].state.id as string;
    const scid = originalDid.split(':')[2];

    // The new entry's state.id must reflect the new location, same SCID
    expect(updateResult.log[1].state.id).toBe(`did:webvh:${scid}:example.org`);
    expect(updateResult.log[1].state.alsoKnownAs).toContain(originalDid);

    // And it must resolve to the moved DID
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.didDocument?.id).toBe(`did:webvh:${scid}:example.org`);
    expect(resolved.didDocument?.alsoKnownAs).toContain(originalDid);
  });

  test('Non-portable DID rejects a move to a new domain', async () => {
    await expect(
      updateDID({
        log: nonPortableDID.log,
        address: 'example.org',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      })
    ).rejects.toThrow('Cannot move DID: portability is disabled');
  });

  test('Re-passing a bare domain on a pathed DID preserves the paths', async () => {
    const pathedDID = await createDID({
      address: 'example.com',
      paths: ['dids', 'alice'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Caller threads the same domain through the update but omits paths.
    const updateResult = await updateDID({
      log: pathedDID.log,
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    expect(updateResult.log[1].state.id).toBe(pathedDID.did);
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.didDocument?.id).toBe(pathedDID.did);
  });

  test('Portable DID moves to a pathed location via the address option', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      address: 'https://example.org/dids/alice',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const scid = (portableDID.log[0].state.id as string).split(':')[2];
    expect(updateResult.log[1].state.id).toBe(`did:webvh:${scid}:example.org:dids:alice`);
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.didDocument?.id).toBe(`did:webvh:${scid}:example.org:dids:alice`);
  });

  test('UpdateDID rejects dot-segment in explicit paths array', async () => {
    await expect(
      updateDID({
        log: portableDID.log,
        address: 'example.org',
        paths: ['..', 'secrets'],
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('updateDID path segments must not contain dot-segments');
  });

  test('UpdateDID rejects encoded slash inside explicit path segment', async () => {
    await expect(
      updateDID({
        log: portableDID.log,
        address: 'example.org',
        paths: ['a%2Fb'],
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verifier: testImplementation,
      })
    ).rejects.toThrow('updateDID path segments must not contain decoded slash within a single path segment');
  });
});
