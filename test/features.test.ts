import { beforeAll, expect, test } from 'bun:test';
import type { CreateDIDResult, DIDLog, DIDLogEntry, ServiceEndpoint, VerificationMethod } from '../src/interfaces';
import { DidResolutionError } from '../src/interfaces';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method';
import { createDate, deriveHash, deriveNextKeyHash } from '../src/utils';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

let log: DIDLog;
let authKey1: VerificationMethod,
  authKey2: VerificationMethod,
  authKey3: VerificationMethod,
  authKey4: VerificationMethod;
let testImplementation: TestCryptoImplementation;

let nonPortableDID: CreateDIDResult;
let portableDID: CreateDIDResult;

beforeAll(async () => {
  authKey1 = await generateTestVerificationMethod();
  authKey2 = await generateTestVerificationMethod();
  authKey3 = await generateTestVerificationMethod();
  authKey4 = await generateTestVerificationMethod();
  testImplementation = new TestCryptoImplementation({ verificationMethod: authKey1 });

  const { doc: newDoc1, log: newLog1 } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    created: createDate(new Date('2021-01-01T08:32:55Z')),
    verifier: testImplementation,
  });

  const { doc: newDoc2, log: newLog2 } = await updateDID({
    log: newLog1,
    signer: createTestSigner(authKey1),
    updateKeys: [authKey2.publicKeyMultibase!],
    context: newDoc1['@context'],
    verificationMethods: asPublicVerificationMethods(authKey2),
    updated: createDate(new Date('2021-02-01T08:32:55Z')),
    verifier: testImplementation,
  });

  const { doc: newDoc3, log: newLog3 } = await updateDID({
    log: newLog2,
    signer: createTestSigner(authKey2),
    updateKeys: [authKey3.publicKeyMultibase!],
    context: newDoc2['@context'],
    verificationMethods: asPublicVerificationMethods(authKey3),
    updated: createDate(new Date('2021-03-01T08:32:55Z')),
    verifier: testImplementation,
  });

  const { doc: newDoc4, log: newLog4 } = await updateDID({
    log: newLog3,
    signer: createTestSigner(authKey3),
    updateKeys: [authKey4.publicKeyMultibase!],
    context: newDoc3['@context'],
    verificationMethods: asPublicVerificationMethods(authKey4),
    updated: createDate(new Date('2021-04-01T08:32:55Z')),
    verifier: testImplementation,
  });

  log = newLog4;

  nonPortableDID = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    created: createDate(new Date('2021-01-01T08:32:55Z')),
    portable: false, // Set portable to false
    verifier: testImplementation,
  });

  portableDID = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey2),
    updateKeys: [authKey2.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey2),
    created: createDate(new Date('2021-01-01T08:32:55Z')),
    portable: true, // Set portable to true
    verifier: testImplementation,
  });
});

test('Resolve DID at time (first)', async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-01-15T08:32:55Z'),
    verifier: testImplementation,
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test('Resolve DID at time (second)', async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-02-15T08:32:55Z'),
    verifier: testImplementation,
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('2');
});

test('Resolve DID at time (third)', async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-03-15T08:32:55Z'),
    verifier: testImplementation,
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('3');
});

test('Resolve DID at time (last)', async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-04-15T08:32:55Z'),
    verifier: testImplementation,
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test('Resolve DID at version', async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionId: log[0].versionId,
    verifier: testImplementation,
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test('Resolve DID latest', async () => {
  const resolved = await resolveDIDFromLog(log, { verifier: testImplementation });
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test('Explicit versionId miss returns notFound without latest fallback', async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionId: '999-non-existent-version-id',
    verifier: testImplementation,
  });

  expect(resolved.doc).toBeNull();
  expect(resolved.meta.error).toBe(DidResolutionError.NotFound);
  expect(resolved.meta.problemDetails?.type).toBe('https://w3id.org/security#NOT_FOUND');
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test('Explicit versionTime miss returns notFound without latest fallback', async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2020-12-01T00:00:00Z'),
    verifier: testImplementation,
  });

  expect(resolved.doc).toBeNull();
  expect(resolved.meta.error).toBe(DidResolutionError.NotFound);
  expect(resolved.meta.problemDetails?.type).toBe('https://w3id.org/security#NOT_FOUND');
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test('Empty nextKeyHashes array should not enable prerotation', async () => {
  // Create a DID without nextKeyHashes
  const { log: log1 } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    verifier: testImplementation,
  });

  // Update with different updateKeys — no prerotation constraint
  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey1),
    updateKeys: [authKey2.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey2),
    verifier: testImplementation,
  });

  // Should resolve successfully — empty nextKeyHashes doesn't block key rotation
  const resolved = await resolveDIDFromLog(log2, { verifier: testImplementation });
  expect(resolved.meta.versionId.split('-')[0]).toBe('2');
  expect(resolved.meta.prerotation).toBe(false);
});

test('Omitted nextKeyHashes inherits previous pre-rotation state', async () => {
  const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation,
  });

  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey2),
    updateKeys: [authKey2.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey2),
    verifier: testImplementation,
  });

  expect('nextKeyHashes' in log2[1].parameters).toBe(false);

  const resolved = await resolveDIDFromLog(log2, { verifier: testImplementation });
  expect(resolved.meta.prerotation).toBe(true);
  expect(resolved.meta.nextKeyHashes).toEqual([nextKeyHash]);
});

test('Omitted updateKeys is rejected while pre-rotation is active', async () => {
  const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation,
  });

  await expect(
    updateDID({
      log,
      signer: createTestSigner(authKey2),
      verificationMethods: asPublicVerificationMethods(authKey2),
      verifier: testImplementation,
    })
  ).rejects.toThrow('updateKeys must be provided while pre-rotation is active');
});

test('Explicit empty nextKeyHashes disables pre-rotation', async () => {
  const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation,
  });

  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey2),
    updateKeys: [authKey2.publicKeyMultibase!],
    nextKeyHashes: [],
    verificationMethods: asPublicVerificationMethods(authKey2),
    verifier: testImplementation,
  });

  expect(log2[1].parameters.nextKeyHashes).toEqual([]);

  const resolved = await resolveDIDFromLog(log2, { verifier: testImplementation });
  expect(resolved.meta.prerotation).toBe(false);
  expect(resolved.meta.nextKeyHashes).toEqual([]);
});

test('updateKeys MUST be in previous nextKeyHashes when updating', async () => {
  // Create DID with nextKeyHashes pointing to authKey2 for next update
  const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation,
  });

  // Update with authKey1 as updateKeys (NOT in nextKeyHashes).
  // Previous entry committed authKey2 for next update, but we're signing with authKey1.
  // Write-time validation rejects the mismatch before the update is accepted.
  await expect(
    updateDID({
      log: log1,
      signer: createTestSigner(authKey1),
      updateKeys: [authKey1.publicKeyMultibase!],
      nextKeyHashes: [],
      verificationMethods: asPublicVerificationMethods(authKey1),
      verifier: testImplementation,
    })
  ).rejects.toThrow('Invalid update key');
});

test('updateKeys MUST be in nextKeyHashes when reading', async () => {
  // Create DID with nextKeyHashes pointing to authKey2
  const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation,
  });

  const createdDate = createDate(new Date(new Date(log1[0].versionTime).getTime() + 60 * 1000));
  const logEntry: DIDLogEntry = {
    versionId: log1[0].versionId,
    versionTime: createdDate,
    parameters: {
      updateKeys: [authKey1.publicKeyMultibase!],
      nextKeyHashes: [],
      witness: {},
      watchers: [],
    },
    state: JSON.parse(JSON.stringify(log1[0].state)),
  };
  const logEntryHash = await deriveHash(logEntry);
  const prelimEntry: DIDLogEntry = { ...logEntry, versionId: `2-${logEntryHash}` };
  const signer = createTestSigner(authKey1);
  const proofTemplate = {
    type: 'DataIntegrityProof' as const,
    cryptosuite: 'eddsa-jcs-2022' as const,
    verificationMethod: signer.getVerificationMethodId(),
    created: createdDate,
    proofPurpose: 'assertionMethod' as const,
  };
  const signedProof = await signer.sign({ document: prelimEntry, proof: proofTemplate });
  prelimEntry.proof = [{ ...proofTemplate, proofValue: signedProof.proofValue }];

  // Resolution (reading) must catch the invalid key
  await expect(resolveDIDFromLog([log1[0], prelimEntry], { verifier: testImplementation })).rejects.toThrow(
    'Invalid update key'
  );
});

test('DID log with portable false should not resolve if moved', async () => {
  let err: unknown;
  try {
    const lastEntry = nonPortableDID.log[nonPortableDID.log.length - 1];
    const newTimestamp = createDate(new Date('2021-02-01T08:32:55Z'));

    // Create a new document with the moved DID
    const newDoc = {
      ...nonPortableDID.doc,
      id: nonPortableDID.did.replace('example.com', 'newdomain.com'),
    };

    const newEntry: DIDLogEntry = {
      versionId: `${nonPortableDID.log.length + 1}-test`,
      versionTime: newTimestamp,
      parameters: { updateKeys: [authKey1.publicKeyMultibase!] },
      state: newDoc,
      proof: [
        {
          type: 'DataIntegrityProof',
          cryptosuite: 'eddsa-jcs-2022',
          verificationMethod: `did:key:${authKey1.publicKeyMultibase!}`,
          created: newTimestamp,
          proofPurpose: 'authentication',
          proofValue: 'badProofValue',
        },
      ],
    };

    const badLog: DIDLog = [...nonPortableDID.log, newEntry];
    await resolveDIDFromLog(badLog, { verifier: testImplementation });
  } catch (e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err).toBeInstanceOf(Error);
  expect((err as Error).message).toContain('Cannot move DID: portability is disabled');
});

test('Absolute service IDs prevent implicit service duplication', async () => {
  // Create a DID with a custom service using absolute ID form
  const customDidDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: 'did:webvh:{SCID}:example.com',
    controller: ['did:webvh:{SCID}:example.com'],
    service: [
      {
        id: 'did:webvh:{SCID}:example.com#files', // Absolute form with placeholder
        type: 'relativeRef',
        serviceEndpoint: 'https://custom.example.com',
      },
    ],
  };

  const { log: createdLog, doc: createdDoc } = await createDID({
    address: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey1),
    didDocument: customDidDocument,
    verifier: testImplementation,
  });

  // Resolve the created DID
  const result = await resolveDIDFromLog(createdLog, { verifier: testImplementation });
  const resolvedDid = result.did;

  // Verify that the implicit #files service was NOT added (only custom service exists)
  const filesServices = (result.doc?.service || []).filter((s: ServiceEndpoint) => {
    const id = s.id || '';
    return id.endsWith('#files');
  });

  expect(filesServices.length).toBe(1);
  expect(filesServices[0].id).toBe(`${resolvedDid}#files`);
  expect(filesServices[0].serviceEndpoint).toBe('https://custom.example.com');

  // Verify #whois was still added as implicit service
  const whoisServices = (result.doc?.service || []).filter((s: ServiceEndpoint) => {
    const id = s.id || '';
    return id.endsWith('#whois');
  });

  expect(whoisServices.length).toBe(1);
  expect(whoisServices[0].id).toBe('#whois');
});
