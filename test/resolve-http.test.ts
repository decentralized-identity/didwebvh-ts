import { afterEach, beforeAll, describe, expect, mock, spyOn, test } from 'bun:test';
import type { DIDLog, VerificationMethod } from '../src/interfaces';
import { DidResolutionError } from '../src/interfaces';
import { createDID, resolveDID } from '../src/method';
import { fetchLogFromIdentifier, fetchWitnessProofs } from '../src/utils';
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
  const fetchMock = mock().mockResolvedValue({
    ok: init.ok ?? true,
    status: init.status ?? 200,
    text: async () => body,
    json: async () => JSON.parse(body),
  });
  globalThis.fetch = fetchMock as unknown as typeof fetch;
  return fetchMock;
};

const stubFetchFailure = (error: Error) => {
  globalThis.fetch = mock().mockRejectedValue(error) as unknown as typeof fetch;
};

const silenceConsoleError = () => {
  consoleErrorSpy = spyOn(console, 'error').mockImplementation(() => {});
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
      domain: 'example.com',
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
    expect(result.did).toBe(did);
    expect(result.doc).toBeTruthy();
    expect(result.doc).not.toBeNull();
    expect(result.doc!.id).toBe(did);
    expect(result.meta.error).toBeUndefined();
  });

  test('maps an HTTP 404 to the notFound resolution error', async () => {
    silenceConsoleError();
    stubFetchResponse('', { ok: false, status: 404 });

    const result = await resolveDID(did, { verifier });

    expect(result.doc).toBeNull();
    expect(result.meta.error).toBe(DidResolutionError.NotFound);
    expect(result.meta.problemDetails?.type).toBe('https://w3id.org/security#NOT_FOUND');
    expect(result.meta.problemDetails?.detail).toContain('404');
  });

  test('maps an empty DID log to the notFound resolution error', async () => {
    silenceConsoleError();
    stubFetchResponse('  \n  ');

    const result = await resolveDID(did, { verifier });

    expect(result.doc).toBeNull();
    expect(result.meta.error).toBe(DidResolutionError.NotFound);
  });

  test('maps an invalid DID log to the invalidDid resolution error', async () => {
    stubFetchResponse(JSON.stringify({ not: 'a log entry' }));

    const result = await resolveDID(did, { verifier });

    expect(result.doc).toBeNull();
    expect(result.meta.error).toBe(DidResolutionError.InvalidDid);
    expect(result.meta.problemDetails?.type).toBe(
      'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID'
    );
  });

  test('rejects a log whose SCID does not match the SCID in the DID', async () => {
    const didParts = did.split(':');
    didParts[2] = `${didParts[2].slice(0, -4)}zzzz`;
    const tamperedDid = didParts.join(':');
    stubFetchResponse(toJsonl(log));

    const result = await resolveDID(tamperedDid, { verifier });

    expect(result.doc).toBeNull();
    expect(result.meta.error).toBe(DidResolutionError.InvalidDid);
    expect(result.meta.problemDetails?.detail).toContain('does not match SCID');
  });

  test('maps a network failure to the invalidDid resolution error', async () => {
    silenceConsoleError();
    stubFetchFailure(new TypeError('fetch failed'));

    const result = await resolveDID(did, { verifier });

    expect(result.doc).toBeNull();
    expect(result.meta.error).toBe(DidResolutionError.InvalidDid);
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
