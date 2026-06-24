import { beforeAll, describe, expect, test } from 'bun:test';
import type { CreateDIDResult, DIDLog, VerificationMethod } from '../src/interfaces';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  nextSecond,
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
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    portableDID = await createDID({
      domain: 'example.com',
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
      updated: nextSecond(nonPortableDID.log),
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.portable = true;

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      'cannot set portable: true'
    );
  });

  test('Rejects false-to-true portable transition (portable was explicitly false)', async () => {
    // Create a DID with portable: false explicitly in the first entry
    const did = await createDID({
      domain: 'example.com',
      portable: false,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const updateResult = await updateDID({
      log: did.log,
      updated: nextSecond(did.log),
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    // Tamper: try to re-enable portable in a later entry
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));
    tamperedLog[1].parameters.portable = true;

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      'cannot set portable: true'
    );
  });

  test('Setting portable: false in a later entry permanently locks portability', async () => {
    // Use the proper API to produce a legitimately signed update that sets portable: false
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      domain: 'example.com',
      portable: false,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    // Resolution of a properly signed portable: false entry must succeed
    await expect(resolveDIDFromLog(updateResult.log, { verifier: testImplementation })).resolves.toBeDefined();
  });

  test('Rejects SCID change in state.id during portable rename', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier: testImplementation,
    });

    const originalScid = portableDID.log[0].parameters.scid as string;
    const tamperedLog: DIDLog = JSON.parse(JSON.stringify(updateResult.log));

    // Replace SCID in state.id with a different value
    const fakeScid = `${originalScid.slice(0, -4)}XXXX`;
    tamperedLog[1].state.id = (tamperedLog[1].state.id as string).replace(originalScid, fakeScid);

    await expect(resolveDIDFromLog(tamperedLog, { verifier: testImplementation })).rejects.toThrow(
      'does not match SCID in log'
    );
  });

  test('Portable DID moves to a new domain via the domain option', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      domain: 'example.org',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const originalDid = portableDID.log[0].state.id as string;
    const scid = originalDid.split(':')[2];

    // The new entry's state.id must reflect the new location, same SCID
    expect(updateResult.log[1].state.id).toBe(`did:webvh:${scid}:example.org`);

    // And it must resolve to the moved DID
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.did).toBe(`did:webvh:${scid}:example.org`);
    expect(resolved.doc?.id).toBe(`did:webvh:${scid}:example.org`);
  });

  test('Non-portable DID rejects a move to a new domain', async () => {
    await expect(
      updateDID({
        log: nonPortableDID.log,
        updated: nextSecond(nonPortableDID.log),
        domain: 'example.org',
        signer: createTestSigner(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: asPublicVerificationMethods(authKey),
        verifier: testImplementation,
      })
    ).rejects.toThrow('Cannot move DID: portability is disabled');
  });

  test('Re-passing a bare domain on a pathed DID preserves the paths', async () => {
    const pathedDID = await createDID({
      domain: 'example.com',
      paths: ['dids', 'alice'],
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    // Caller threads the same domain through the update but omits paths.
    const updateResult = await updateDID({
      log: pathedDID.log,
      updated: nextSecond(pathedDID.log),
      domain: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    expect(updateResult.log[1].state.id).toBe(pathedDID.did);
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.did).toBe(pathedDID.did);
  });

  test('Portable DID moves to a pathed location via the address option', async () => {
    const updateResult = await updateDID({
      log: portableDID.log,
      updated: nextSecond(portableDID.log),
      address: 'https://example.org/dids/alice',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier: testImplementation,
    });

    const scid = (portableDID.log[0].state.id as string).split(':')[2];
    expect(updateResult.log[1].state.id).toBe(`did:webvh:${scid}:example.org:dids:alice`);
    const resolved = await resolveDIDFromLog(updateResult.log, { verifier: testImplementation });
    expect(resolved.did).toBe(`did:webvh:${scid}:example.org:dids:alice`);
  });
});
