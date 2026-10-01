import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import type { DIDLog, FetchLike } from '../src/interfaces.js';
import { createDID, resolveDID, resolveDIDFromLog } from '../src/method.js';
import { fetchLogFromIdentifier, fetchWitnessProofs } from '../src/utils.js';
import {
  createTestDIDDocument,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
  type TestVerificationMethod,
} from './utils.js';

const toJsonl = (log: DIDLog) => log.map((entry) => JSON.stringify(entry)).join('\n');

const originalFetch = globalThis.fetch;

// Stub the global fetch with a single canned response, returning the mock so
// tests can assert on the requested URL.
const createMockResponse = (body: string, init: { ok?: boolean; status?: number } = {}) =>
  ({
    ok: init.ok ?? true,
    status: init.status ?? 200,
    text: async () => body,
    json: async () => JSON.parse(body),
  }) as Response;

const createFetchMock = (body: string, init: { ok?: boolean; status?: number } = {}) =>
  vi.fn().mockResolvedValue(createMockResponse(body, init)) as unknown as ReturnType<typeof vi.fn> & FetchLike;

const stubFetchResponse = (body: string, init: { ok?: boolean; status?: number } = {}) => {
  const fetchMock = vi.fn().mockResolvedValue(createMockResponse(body, init));
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
};

const stubFetchFailure = (error: Error) => {
  globalThis.fetch = vi.fn().mockRejectedValue(error) as unknown as typeof fetch;
};

const restoreStubs = () => {
  globalThis.fetch = originalFetch;
};

describe('resolveDID over HTTPS', () => {
  let authKey: TestVerificationMethod;
  let verifier: TestCryptoImplementation;
  let did: string;
  let log: DIDLog;

  beforeAll(async () => {
    authKey = await generateTestVerificationMethod();
    verifier = new TestCryptoImplementation({ verificationMethod: authKey });
    ({ did, log } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier,
    }));
  });

  afterEach(() => {
    restoreStubs();
  });

  test('resolves a DID by fetching its log from the well-known URL', async () => {
    const fetchMock = stubFetchResponse(toJsonl(log));

    const result = await resolveDID(did, { verifier });

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(result.didDocument).toBeTruthy();
    expect(result.didDocument).not.toBeNull();
    expect(result.didDocument!.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didResolutionMetadata.contentType).toBe('application/did+ld+json');
  });

  test('rejects conflicting selectors without fetching for identifier or in-memory resolution', async () => {
    const fetchMock = createFetchMock(toJsonl(log));
    const selectorOptions = { versionId: log[0].versionId, versionNumber: 1, fetch: fetchMock };

    const identifierResult = await resolveDID(did, { verifier, ...selectorOptions });
    const inMemoryResult = await resolveDIDFromLog(log, { verifier, ...selectorOptions });

    expect(identifierResult.didResolutionMetadata.error).toBe('invalidOptions');
    expect(identifierResult.didDocument).toBeNull();

    expect(inMemoryResult.didResolutionMetadata.error).toBe('invalidOptions');
    expect(inMemoryResult.didDocument).toBeNull();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  test('uses a custom fetch override when resolving a DID by identifier', async () => {
    stubFetchFailure(new Error('global fetch should not be called'));
    const customFetch = createFetchMock(toJsonl(log));

    const result = await resolveDID(did, { verifier, fetch: customFetch });

    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(result.didDocument?.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  test.each([
    ['localhost.example.com', [], 'https://localhost.example.com/.well-known/did.jsonl'],
    ['example.com', ['localhost'], 'https://example.com/localhost/did.jsonl'],
    ['localhost:8000', [], 'https://localhost:8000/.well-known/did.jsonl'],
  ])('resolves %s with paths %j over HTTPS', async (address, paths, expectedUrl) => {
    const created = await createDID({
      address,
      paths,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      verifier,
    });
    const fetchMock = stubFetchResponse(toJsonl(created.log));

    const result = await resolveDID(created.did, { verifier });

    expect(fetchMock).toHaveBeenCalledExactlyOnceWith(expectedUrl);
    expect(result.didDocument?.id).toBe(created.did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  test('ignores DID_VERIFICATION_METHODS in the runtime environment', async () => {
    const previous = process.env.DID_VERIFICATION_METHODS;
    process.env.DID_VERIFICATION_METHODS = 'invalid-runtime-value';

    try {
      const fetchMock = stubFetchResponse(toJsonl(log));
      const result = await resolveDID(did, { verifier });

      expect(fetchMock).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
      expect(result.didDocument?.id).toBe(did);
      expect(result.didResolutionMetadata.error).toBeUndefined();
    } finally {
      if (previous === undefined) delete process.env.DID_VERIFICATION_METHODS;
      else process.env.DID_VERIFICATION_METHODS = previous;
    }
  });

  test('resolves from a caller-supplied controlled DID log without fetching', async () => {
    const fetchMock = stubFetchResponse('');

    const result = await resolveDID(did, {
      verifier,
      resolveControlledDid: async (requestedDid) => {
        expect(requestedDid).toBe(did);
        return log;
      },
    });

    expect(fetchMock).not.toHaveBeenCalled();
    expect(result.didDocument?.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  test('falls back to remote resolution when controlled DID lookup returns undefined', async () => {
    const fetchMock = stubFetchResponse(toJsonl(log));

    const result = await resolveDID(did, {
      verifier,
      resolveControlledDid: async () => undefined,
    });

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/.well-known/did.jsonl');
    expect(result.didDocument?.id).toBe(did);
    expect(result.didResolutionMetadata.error).toBeUndefined();
  });

  test('maps controlled DID lookup failures to an internalError resolution result', async () => {
    const result = await resolveDID(did, {
      verifier,
      resolveControlledDid: async () => {
        throw new TypeError('fetch failed');
      },
    });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('internalError');
    expect(result.didResolutionMetadata.message).toContain('fetch failed');
  });

  test('rejects a caller-supplied log whose state.id does not match the requested DID', async () => {
    const didParts = did.split(':');
    const mismatchedDid = `${didParts.slice(0, 3).join(':')}:different-domain.example`;

    const result = await resolveDID(mismatchedDid, {
      verifier,
      resolveControlledDid: async () => log,
    });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.message).toMatch(/does not match state\.id/);
  });

  test('maps an HTTP 404 to the notFound resolution error', async () => {
    stubFetchResponse('', { ok: false, status: 404 });

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didResolutionMetadata.message).toContain('404');
  });

  test('maps an empty DID log to the notFound resolution error', async () => {
    stubFetchResponse('  \n  ');

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
  });

  test('maps an invalid DID log to the invalidDid resolution error', async () => {
    stubFetchResponse(JSON.stringify({ not: 'a log entry' }));

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
  });

  test('rejects a log whose SCID does not match the SCID in the DID', async () => {
    const didParts = did.split(':');
    didParts[2] = `${didParts[2].slice(0, -4)}zzzz`;
    const tamperedDid = didParts.join(':');
    stubFetchResponse(toJsonl(log));

    const result = await resolveDID(tamperedDid, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.message).toContain('does not match SCID');
  });

  test('maps a network failure to the internalError resolution error', async () => {
    stubFetchFailure(new TypeError('fetch failed'));

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('internalError');
  });
});

describe('fetchLogFromIdentifier', () => {
  afterEach(() => {
    restoreStubs();
  });

  test('fetches path-based DIDs from a path-qualified URL', async () => {
    const entries = [{ versionId: '1-abc' }, { versionId: '2-def' }] as DIDLog;
    const fetchMock = stubFetchResponse(entries.map((entry) => JSON.stringify(entry)).join('\n'));

    const fetched = await fetchLogFromIdentifier('did:webvh:scid123:example.com:dids:issuer');

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/dids/issuer/did.jsonl');
    expect(fetched).toEqual(entries);
  });

  test('uses a custom fetch override for DID log retrieval', async () => {
    const entries = [{ versionId: '1-abc' }, { versionId: '2-def' }] as DIDLog;
    stubFetchFailure(new Error('global fetch should not be called'));
    const customFetch = createFetchMock(entries.map((entry) => JSON.stringify(entry)).join('\n'));

    const fetched = await fetchLogFromIdentifier('did:webvh:scid123:example.com:dids:issuer', customFetch);

    expect(customFetch).toHaveBeenCalledWith('https://example.com/dids/issuer/did.jsonl');
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(fetched).toEqual(entries);
  });
});

describe('fetchWitnessProofs', () => {
  afterEach(() => {
    restoreStubs();
  });

  test('fetches the witness proof file alongside the DID log', async () => {
    const proofs = [{ versionId: '1-abc', proof: [] }];
    const fetchMock = stubFetchResponse(JSON.stringify(proofs));

    const result = await fetchWitnessProofs('did:webvh:scid123:example.com');

    expect(fetchMock).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(result).toEqual(proofs);
  });

  test('uses a custom fetch override for witness proof retrieval', async () => {
    const proofs = [{ versionId: '1-abc', proof: [] }];
    stubFetchFailure(new Error('global fetch should not be called'));
    const customFetch = createFetchMock(JSON.stringify(proofs));

    const result = await fetchWitnessProofs('did:webvh:scid123:example.com', customFetch);

    expect(customFetch).toHaveBeenCalledWith('https://example.com/.well-known/did-witness.json');
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(result).toEqual(proofs);
  });

  test('returns an empty list when the witness proof file is missing', async () => {
    stubFetchResponse('', { ok: false, status: 404 });

    expect(await fetchWitnessProofs('did:webvh:scid123:example.com')).toEqual([]);
  });

  test('propagates network errors when fetching witness proofs', async () => {
    stubFetchFailure(new Error('connection refused'));

    await expect(fetchWitnessProofs('did:webvh:scid123:example.com')).rejects.toThrow('connection refused');
  });

  test('rejects non-404 HTTP errors when fetching witness proofs', async () => {
    stubFetchResponse('', { ok: false, status: 503 });

    await expect(fetchWitnessProofs('did:webvh:scid123:example.com')).rejects.toThrow('HTTP error! status: 503');
  });
});
