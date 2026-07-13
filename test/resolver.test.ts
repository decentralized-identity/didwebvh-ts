import { afterAll, beforeAll, describe, expect, test, vi } from 'vitest';
import { Resolver } from 'did-resolver';
import type { DIDLog, VerificationMethod } from '../src/interfaces';
import { createDID, deactivateDID, updateDID } from '../src/method';
import { getResolver } from '../src/resolver';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

const toJsonl = (log: DIDLog) => log.map((entry) => JSON.stringify(entry)).join('\n');

const originalFetch = globalThis.fetch;
let consoleErrorSpy: ReturnType<typeof vi.spyOn> | undefined;

// Serve a fixed DID log JSONL over the mocked fetch so resolution-by-identifier works.
const serveLog = (log: DIDLog) => {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: true,
    status: 200,
    text: async () => toJsonl(log),
    json: async () => log,
  }) as unknown as typeof fetch;
};

const serve404 = () => {
  globalThis.fetch = vi.fn().mockResolvedValue({
    ok: false,
    status: 404,
    text: async () => '',
    json: async () => ({}),
  }) as unknown as typeof fetch;
};

describe('getResolver integration', () => {
  let did: string;
  let fullLog: DIDLog;
  let v1Id: string;
  let v2Id: string;
  let authKey: VerificationMethod;
  let verifier: TestCryptoImplementation;
  let resolver: Resolver;

  beforeAll(async () => {
    consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
    authKey = await generateTestVerificationMethod();
    verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      created: '2023-01-01T00:00:00Z',
      verificationMethods: asPublicVerificationMethods(authKey),
      verifier,
    });
    did = created.did;
    v1Id = created.meta.versionId;
    const updated = await updateDID({
      log: created.log,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      updated: '2023-02-01T00:00:01Z',
      verifier,
    });
    v2Id = updated.meta.versionId;
    fullLog = updated.log;
    resolver = new Resolver(getResolver({ verifier }));
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
    consoleErrorSpy?.mockRestore();
  });

  test('resolves a freshly created DID through a real Resolver', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(did);
    expect(result.didDocumentMetadata.versionId).toBe(v2Id);
  });

  test('?versionId selects a historical version', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionId=${v1Id}`);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe(v1Id);
  });

  test('?versionNumber selects a historical version', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionNumber=1`);
    expect(result.didDocumentMetadata.versionId).toBe(v1Id);
  });

  test('?versionTime with a +HH:MM timezone offset is decoded as a literal plus', async () => {
    // v1 is created at 2023-01-01T00:00:00Z, v2 at 2023-02-01T00:00:01Z.
    // 2023-01-15T00:00:00+01:00 == 2023-01-14T23:00:00Z, which falls in v1's window.
    // The `+` must survive query parsing (URLSearchParams would turn it into a
    // space and yield an Invalid Date).
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionTime=2023-01-15T00:00:00+01:00`);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe(v1Id);
  });

  test('combining selectors returns invalidOptions with the webvh problem type', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionNumber=1&versionId=${v1Id}`);
    expect(result.didResolutionMetadata.error).toBe('invalidOptions');
    expect((result.didResolutionMetadata as { problemDetails?: { type: string } }).problemDetails?.type).toContain(
      'conflicting-resolution-options'
    );
    expect(result.didDocument).toBeNull();
  });

  test('non-numeric versionNumber returns invalidOptions', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionNumber=abc`);
    expect(result.didResolutionMetadata.error).toBe('invalidOptions');
    expect(result.didDocument).toBeNull();
  });

  test('unparseable versionTime returns invalidOptions', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionTime=not-a-date`);
    expect(result.didResolutionMetadata.error).toBe('invalidOptions');
    expect(result.didDocument).toBeNull();
  });

  test('unknown query parameters are ignored, not errors', async () => {
    // DID Core §3.2.1 extensibility: registered params (service, relativeRef)
    // and future extensions must not break plain resolution.
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?service=files&relativeRef=%2Fresume.pdf&foo=bar`);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(did);
  });

  test('matrix-form version selectors are rejected, not silently ignored', async () => {
    // Silently dropping `;versionId=` would resolve latest when the caller
    // asked for a specific version — reject instead.
    serveLog(fullLog);
    const result = await resolver.resolve(`${did};versionId=${v1Id}`);
    expect(result.didResolutionMetadata.error).toBe('invalidOptions');
    expect(result.didDocument).toBeNull();
  });

  test('lowercase hex in query percent-encoding resolves successfully', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionTime=2023-01-15T00:00:00%2b01%3a00`);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.versionId).toBe(v1Id);
  });

  test('malformed percent-encoding in a query key returns invalidDidUrl', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?%ZZ=1`);
    expect(result.didResolutionMetadata.error).toBe('invalidDidUrl');
    expect(result.didDocument).toBeNull();
  });

  test('malformed percent-encoding in a query value returns invalidDidUrl', async () => {
    serveLog(fullLog);
    const result = await resolver.resolve(`${did}?versionId=%E0%A4%A`);
    expect(result.didResolutionMetadata.error).toBe('invalidDidUrl');
    expect(result.didDocument).toBeNull();
  });

  test('not-found DID returns notFound', async () => {
    serve404();
    const result = await resolver.resolve(did);
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didDocument).toBeNull();
  });

  test('deactivated DID resolves with deactivated: true', async () => {
    const deactivated = await deactivateDID({
      log: fullLog,
      signer: createTestSigner(authKey),
      verifier,
    });
    serveLog(deactivated.log);
    const result = await resolver.resolve(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocumentMetadata.deactivated).toBe(true);
  });

  test('works zero-config with the default verifier', async () => {
    serveLog(fullLog);
    const zeroConfig = new Resolver(getResolver());
    const result = await zeroConfig.resolve(did);
    expect(result.didDocument?.id).toBe(did);
  });
});
