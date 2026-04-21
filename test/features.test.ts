import { beforeAll, expect, test} from "bun:test";
import { createDID, resolveDIDFromLog, updateDID } from "../src/method";
import { createDate, deriveNextKeyHash } from "../src/utils";
import { generateTestVerificationMethod, createTestSigner, TestCryptoImplementation } from './utils';
import type { DIDLog, VerificationMethod } from "../src/interfaces";

let log: DIDLog;
let authKey1: VerificationMethod,
    authKey2: VerificationMethod,
    authKey3: VerificationMethod,
    authKey4: VerificationMethod;
let testImplementation: TestCryptoImplementation;

let nonPortableDID: { did: string; doc: any; meta: any; log: DIDLog };
let portableDID: { did: string; doc: any; meta: any; log: DIDLog };

beforeAll(async () => {
  authKey1 = await generateTestVerificationMethod();
  authKey2 = await generateTestVerificationMethod();
  authKey3 = await generateTestVerificationMethod();
  authKey4 = await generateTestVerificationMethod();
  testImplementation = new TestCryptoImplementation({ verificationMethod: authKey1 });
  
  const {doc: newDoc1, log: newLog1} = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    created: createDate(new Date('2021-01-01T08:32:55Z')),
    verifier: testImplementation
  });

  const {doc: newDoc2, log: newLog2} = await updateDID({
    log: newLog1,
    signer: createTestSigner(authKey1),
    updateKeys: [authKey2.publicKeyMultibase!],
    context: newDoc1['@context'],
    verificationMethods: [authKey2],
    updated: createDate(new Date('2021-02-01T08:32:55Z')),
    verifier: testImplementation
  });

  const {doc: newDoc3, log: newLog3} = await updateDID({
    log: newLog2,
    signer: createTestSigner(authKey2),
    updateKeys: [authKey3.publicKeyMultibase!],
    context: newDoc2['@context'],
    verificationMethods: [authKey3],
    updated: createDate(new Date('2021-03-01T08:32:55Z')),
    verifier: testImplementation
  });

  const {doc: newDoc4, log: newLog4} = await updateDID({
    log: newLog3,
    signer: createTestSigner(authKey3),
    updateKeys: [authKey4.publicKeyMultibase!],
    context: newDoc3['@context'],
    verificationMethods: [authKey4],
    updated: createDate(new Date('2021-04-01T08:32:55Z')),
    verifier: testImplementation
  });

  log = newLog4;

  nonPortableDID = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    created: createDate(new Date('2021-01-01T08:32:55Z')),
    portable: false, // Set portable to false
    verifier: testImplementation
  });

  portableDID = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey2),
    updateKeys: [authKey2.publicKeyMultibase!],
    verificationMethods: [authKey2],
    created: createDate(new Date('2021-01-01T08:32:55Z')),
    portable: true, // Set portable to true
    verifier: testImplementation
  });
});

test("Resolve DID at time (first)", async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-01-15T08:32:55Z'),
    verifier: testImplementation
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test("Resolve DID at time (second)", async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-02-15T08:32:55Z'),
    verifier: testImplementation
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('2');
});

test("Resolve DID at time (third)", async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-03-15T08:32:55Z'),
    verifier: testImplementation
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('3');
});

test("Resolve DID at time (last)", async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionTime: new Date('2021-04-15T08:32:55Z'),
    verifier: testImplementation
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test("Resolve DID at version", async () => {
  const resolved = await resolveDIDFromLog(log, {
    versionId: log[0].versionId,
    verifier: testImplementation
  });
  expect(resolved.meta.versionId.split('-')[0]).toBe('1');
});

test("Resolve DID latest", async () => {
  const resolved = await resolveDIDFromLog(log, { verifier: testImplementation });
  expect(resolved.meta.versionId.split('-')[0]).toBe('4');
});

test("Empty nextKeyHashes array should not enable prerotation", async () => {
  // Create a DID without nextKeyHashes
  const { log: log1 } = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    verifier: testImplementation
  });

  // Update with different updateKeys — no prerotation constraint
  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey1),
    updateKeys: [authKey2.publicKeyMultibase!],
    verificationMethods: [authKey2],
    verifier: testImplementation
  });

  // Should resolve successfully — empty nextKeyHashes doesn't block key rotation
  const resolved = await resolveDIDFromLog(log2, { verifier: testImplementation });
  expect(resolved.meta.versionId.split('-')[0]).toBe('2');
  expect(resolved.meta.prerotation).toBe(false);
});

test("Require `nextKeyHashes` to continue if previously set", async () => {
  // Create a DID with nextKeyHashes pointing to authKey2
  const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation
  });

  // Update reusing authKey1 as updateKeys (NOT in nextKeyHashes).
  // The signer must match updateKeys for prerotation verification,
  // but authKey1's hash is not in nextKeyHashes, so resolution fails.
  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    verifier: testImplementation
  });

  await expect(
    resolveDIDFromLog(log2, { verifier: testImplementation })
  ).rejects.toThrow('Invalid update key');
});

test("updateKeys MUST be in previous nextKeyHashes when updating", async () => {
  // Create DID with nextKeyHashes pointing to authKey3
  const nextKeyHash = await deriveNextKeyHash(authKey3.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation
  });

  // Update reusing authKey1 as updateKeys (NOT in nextKeyHashes).
  // The signer must match updateKeys for prerotation verification,
  // but authKey1's hash is not in nextKeyHashes pointing to authKey3.
  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    verifier: testImplementation
  });

  // Resolution catches the invalid key
  await expect(
    resolveDIDFromLog(log2, { verifier: testImplementation })
  ).rejects.toThrow('Invalid update key');
});

test("updateKeys MUST be in nextKeyHashes when reading", async () => {
  // Create DID with nextKeyHashes pointing to authKey2
  const nextKeyHash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    nextKeyHashes: [nextKeyHash],
    verifier: testImplementation
  });

  // Update with authKey1 as updateKeys (NOT in nextKeyHashes)
  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    verifier: testImplementation
  });

  // Resolution (reading) must catch the invalid key
  await expect(
    resolveDIDFromLog(log2, { verifier: testImplementation })
  ).rejects.toThrow('Invalid update key');
});

test("Prerotation: legitimate key rotation succeeds", async () => {
  // Create DID with updateKeys=[authKey1] and pre-commit to authKey2
  const key2Hash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    nextKeyHashes: [key2Hash],
    verifier: testImplementation
  });

  // Rotate: sign with authKey2, publish authKey2 as the new updateKey.
  // updateDID must verify the proof against the NEW updateKeys (authKey2),
  // not the previous entry's keys (authKey1), when prerotation is active.
  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey2),
    updateKeys: [authKey2.publicKeyMultibase!],
    verificationMethods: [authKey2],
    verifier: testImplementation
  });

  const resolved = await resolveDIDFromLog(log2, { verifier: testImplementation });
  expect(resolved.meta.versionId.split('-')[0]).toBe('2');
  expect(resolved.meta.updateKeys).toEqual([authKey2.publicKeyMultibase!]);
  expect(resolved.meta.prerotation).toBe(false);
});

test("Prerotation: chained legitimate rotations succeed", async () => {
  // v1: updateKeys=[key1], commit to key2
  const key2Hash = await deriveNextKeyHash(authKey2.publicKeyMultibase!);
  const { log: log1 } = await createDID({
    domain: 'example.com',
    signer: createTestSigner(authKey1),
    updateKeys: [authKey1.publicKeyMultibase!],
    verificationMethods: [authKey1],
    nextKeyHashes: [key2Hash],
    verifier: testImplementation
  });

  // v2: rotate to key2, commit to key3
  const key3Hash = await deriveNextKeyHash(authKey3.publicKeyMultibase!);
  const { log: log2 } = await updateDID({
    log: log1,
    signer: createTestSigner(authKey2),
    updateKeys: [authKey2.publicKeyMultibase!],
    nextKeyHashes: [key3Hash],
    verificationMethods: [authKey2],
    verifier: testImplementation
  });

  // v3: rotate to key3, commit to key4
  const key4Hash = await deriveNextKeyHash(authKey4.publicKeyMultibase!);
  const { log: log3 } = await updateDID({
    log: log2,
    signer: createTestSigner(authKey3),
    updateKeys: [authKey3.publicKeyMultibase!],
    nextKeyHashes: [key4Hash],
    verificationMethods: [authKey3],
    verifier: testImplementation
  });

  const resolved = await resolveDIDFromLog(log3, { verifier: testImplementation });
  expect(resolved.meta.versionId.split('-')[0]).toBe('3');
  expect(resolved.meta.updateKeys).toEqual([authKey3.publicKeyMultibase!]);
  expect(resolved.meta.nextKeyHashes).toEqual([key4Hash]);
  expect(resolved.meta.prerotation).toBe(true);
});

test("DID log with portable false should not resolve if moved", async () => {
  let err: any;
  try {
    const lastEntry = nonPortableDID.log[nonPortableDID.log.length - 1];
    const newTimestamp = createDate(new Date('2021-02-01T08:32:55Z'));
    
    // Create a new document with the moved DID
    const newDoc = {
      ...nonPortableDID.doc,
      id: nonPortableDID.did.replace('example.com', 'newdomain.com')
    };

    const newEntry = {
      versionId: `${nonPortableDID.log.length + 1}-test`,
      versionTime: newTimestamp,
      parameters: { updateKeys: [authKey1.publicKeyMultibase]},
      state: newDoc,
      proof: [{
        type: "DataIntegrityProof",
        cryptosuite: "eddsa-jcs-2022",
        verificationMethod: `did:key:${authKey1.publicKeyMultibase}`,
        created: newTimestamp,
        proofPurpose: "authentication",
        proofValue: "badProofValue"
      }]
    };

    const badLog: DIDLog = [
      ...nonPortableDID.log as any,
      newEntry
    ];
    await resolveDIDFromLog(badLog, { verifier: testImplementation });
  } catch (e) {
    err = e;
  }

  expect(err).toBeDefined();
  expect(err.message).toContain('Cannot move DID: portability is disabled');
});

