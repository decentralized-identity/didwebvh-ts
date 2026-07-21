import type { DIDResolutionResult } from 'did-resolver';
import { afterEach, beforeAll, describe, expect, test, vi } from 'vitest';
import type { DIDLog, VerificationMethod } from '../src/interfaces';
import * as methodModule from '../src/method';
import { createDID, resolveDID } from '../src/method';
import { fetchLogFromIdentifier, fetchWitnessProofs, resolveVM } from '../src/utils';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

const toJsonl = (log: DIDLog) => log.map((entry) => JSON.stringify(entry)).join('\n');

const originalFetch = globalThis.fetch;
let consoleErrorSpy: { mockRestore: () => void } | undefined;

// Stub the global fetch with a single canned response, returning the mock so
// tests can assert on the requested URL.
const stubFetchResponse = (body: string, init: { ok?: boolean; status?: number } = {}) => {
  const fetchMock = vi.fn().mockResolvedValue({
    ok: init.ok ?? true,
    status: init.status ?? 200,
    text: async () => body,
    json: async () => JSON.parse(body),
  });
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
};

const stubFetchFailure = (error: Error) => {
  globalThis.fetch = vi.fn().mockRejectedValue(error) as unknown as typeof fetch;
};

const silenceConsoleError = () => {
  consoleErrorSpy = vi.spyOn(console, 'error').mockImplementation(() => {});
};

const restoreStubs = () => {
  globalThis.fetch = originalFetch;
  consoleErrorSpy?.mockRestore();
  consoleErrorSpy = undefined;
};

describe('resolveDID over HTTPS', () => {
  let authKey: VerificationMethod;
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
      verificationMethods: asPublicVerificationMethods(authKey),
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

  test('maps an HTTP 404 to the notFound resolution error', async () => {
    silenceConsoleError();
    stubFetchResponse('', { ok: false, status: 404 });

    const result = await resolveDID(did, { verifier });

    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect(result.didResolutionMetadata.message).toContain('404');
  });

  test('maps an empty DID log to the notFound resolution error', async () => {
    silenceConsoleError();
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
    silenceConsoleError();
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

  test('returns an empty list when the witness proof file is missing', async () => {
    stubFetchResponse('', { ok: false, status: 404 });

    expect(await fetchWitnessProofs('did:webvh:scid123:example.com')).toEqual([]);
  });

  test('returns an empty list when fetching fails', async () => {
    silenceConsoleError();
    stubFetchFailure(new Error('connection refused'));

    expect(await fetchWitnessProofs('did:webvh:scid123:example.com')).toEqual([]);
  });
});

describe('resolveVM', () => {
  afterEach(() => {
    restoreStubs();
    vi.restoreAllMocks();
  });

  test('resolves did:webvh VM via direct verificationMethod array match', async () => {
    const vmId = 'did:webvh:scid123:example.com#key-1';

    stubFetchResponse('{"versionId":"1-abc"}\n{"versionId":"2-def"}');
    vi.spyOn(methodModule, 'resolveDIDFromLog').mockResolvedValue({
      didDocument: {
        id: 'did:webvh:scid123:example.com',
        verificationMethod: [
          {
            id: vmId,
            type: 'Multikey',
            publicKeyMultibase: 'z6Mkk6YgL8Lh6mLeW4x8pohWXmHfL6h4WQ7x8V8NwS6jQ2mZ',
          },
        ],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: {},
    } as DIDResolutionResult);

    const resolved = await resolveVM(vmId);

    expect(resolved).toEqual({
      id: vmId,
      type: 'Multikey',
      publicKeyMultibase: 'z6Mkk6YgL8Lh6mLeW4x8pohWXmHfL6h4WQ7x8V8NwS6jQ2mZ',
    });
  });

  test('resolves did:webvh VM via verification relationship object fallback', async () => {
    const vmId = 'did:webvh:scid123:example.com#assertion-key';

    stubFetchResponse('{"versionId":"1-abc"}\n{"versionId":"2-def"}');
    vi.spyOn(methodModule, 'resolveDIDFromLog').mockResolvedValue({
      didDocument: {
        id: 'did:webvh:scid123:example.com',
        verificationMethod: [],
        assertionMethod: [
          'did:webvh:scid123:example.com#string-reference',
          {
            id: vmId,
            type: 'Multikey',
            publicKeyMultibase: 'z6MkoJ8mW6T2d4QF9xk33bQ4rQk6N4R8c6rj59YxQG3hbtVW',
          },
        ],
      },
      didDocumentMetadata: {},
      didResolutionMetadata: {},
    } as DIDResolutionResult);

    const resolved = await resolveVM(vmId);

    expect(resolved).toEqual({
      id: vmId,
      type: 'Multikey',
      publicKeyMultibase: 'z6MkoJ8mW6T2d4QF9xk33bQ4rQk6N4R8c6rj59YxQG3hbtVW',
    });
  });

  test('wraps unsupported verification method schemes', async () => {
    await expect(resolveVM('did:web:example.com#key-1')).rejects.toThrow(
      'Error resolving VM did:web:example.com#key-1'
    );
  });
});
