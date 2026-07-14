import { describe, expect, test } from 'vitest';
import type { DIDResolutionMeta } from '../src/interfaces';
import {
  mapErrorToCode,
  toErrorResult,
  toResolutionResult,
  validateSingleVersionSelector,
  WEBVH_ERROR_TYPES,
} from '../src/resolver-result';

const baseMeta: DIDResolutionMeta = {
  versionId: '1-abc',
  created: '2023-01-01T00:00:00Z',
  updated: '2023-01-01T00:00:00Z',
  deactivated: false,
  portable: false,
  scid: 'SCID',
  updateKeys: ['z6Mk...'],
  nextKeyHashes: [],
  prerotation: false,
  witness: undefined,
  watchers: null,
};

describe('validateSingleVersionSelector', () => {
  test('allows zero selectors', () => {
    expect(validateSingleVersionSelector({})).toBeNull();
  });
  test('allows exactly one selector', () => {
    expect(validateSingleVersionSelector({ versionId: '2-x' })).toBeNull();
    expect(validateSingleVersionSelector({ versionNumber: 2 })).toBeNull();
    expect(validateSingleVersionSelector({ versionTime: new Date() })).toBeNull();
  });
  test('rejects versionId + versionNumber', () => {
    expect(validateSingleVersionSelector({ versionId: '2-x', versionNumber: 2 })?.code).toBe('invalidOptions');
  });
  test('rejects versionId + versionTime', () => {
    expect(validateSingleVersionSelector({ versionId: '2-x', versionTime: new Date() })?.code).toBe('invalidOptions');
  });
  test('rejects versionNumber + versionTime', () => {
    expect(validateSingleVersionSelector({ versionNumber: 2, versionTime: new Date() })?.code).toBe('invalidOptions');
  });
  test('rejects all three, carrying the webvh registry problem type', () => {
    const error = validateSingleVersionSelector({ versionId: '2-x', versionNumber: 2, versionTime: new Date() });
    expect(error?.code).toBe('invalidOptions');
    expect(error?.problemType).toBe(WEBVH_ERROR_TYPES.conflictingResolutionOptions);
  });
});

describe('mapErrorToCode', () => {
  test('genuine log-fetch absence messages -> notFound', () => {
    expect(mapErrorToCode(new Error('HTTP error! status: 404'))).toBe('notFound');
    expect(mapErrorToCode(new Error('DID log not found for did:webvh:SCID:example.com'))).toBe('notFound');
  });
  test('other -> invalidDid', () => {
    expect(mapErrorToCode(new Error('SCID mismatch'))).toBe('invalidDid');
  });
  test('validation errors embedding attacker-controlled data are NOT misclassified as notFound', () => {
    // A tampered versionId of "404" must not be treated as a missing document.
    expect(mapErrorToCode(new Error("version '404' in log doesn't match expected '1'"))).toBe('invalidDid');
    // "Not found in nextKeyHashes" is a validation failure, not an absence.
    expect(mapErrorToCode(new Error('Invalid update key zABC. Not found in nextKeyHashes [zXYZ]'))).toBe('invalidDid');
  });
  test('transport/connectivity failures -> internalError', () => {
    expect(mapErrorToCode(new Error('HTTP error! status: 500'))).toBe('internalError');
    expect(mapErrorToCode(new Error('HTTP error! status: 503'))).toBe('internalError');
    expect(mapErrorToCode(new TypeError('fetch failed'))).toBe('internalError');
    expect(mapErrorToCode(new Error('getaddrinfo ENOTFOUND example.com'))).toBe('internalError');
  });
  test('non-404 HTTP statuses (auth/gone/rate-limited) -> internalError', () => {
    expect(mapErrorToCode(new Error('HTTP error! status: 401'))).toBe('internalError');
    expect(mapErrorToCode(new Error('HTTP error! status: 403'))).toBe('internalError');
    expect(mapErrorToCode(new Error('HTTP error! status: 410'))).toBe('internalError');
    expect(mapErrorToCode(new Error('HTTP error! status: 429'))).toBe('internalError');
    // 404 remains a not-found, not an internal error.
    expect(mapErrorToCode(new Error('HTTP error! status: 404'))).toBe('notFound');
  });
});

describe('toResolutionResult', () => {
  test('maps a successful resolution', () => {
    const doc = { id: 'did:webvh:SCID:example.com' };
    const result = toResolutionResult({ did: doc.id, doc, meta: baseMeta }, { controlled: true });
    expect(result.didResolutionMetadata.contentType).toBe('application/did+ld+json');
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect((result.didResolutionMetadata as { controlled?: boolean }).controlled).toBe(true);
    expect(result.didDocument).toEqual(doc);
    expect(result.didDocumentMetadata.versionId).toBe('1-abc');
    expect((result.didDocumentMetadata as { scid?: string }).scid).toBe('SCID');
    expect((result.didDocumentMetadata as { updateKeys?: string[] }).updateKeys).toEqual(['z6Mk...']);
    expect(result.didDocumentMetadata.deactivated).toBe(false);
  });

  test('maps a meta carrying an error to an error result', () => {
    const meta: DIDResolutionMeta = {
      ...baseMeta,
      error: 'notFound',
      problemDetails: { type: 'x', title: 'y', detail: 'missing version' },
    };
    const result = toResolutionResult({ did: 'did:webvh:SCID:example.com', doc: null, meta });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('notFound');
    expect((result.didResolutionMetadata as { problemDetails?: { detail: string } }).problemDetails?.detail).toBe(
      'missing version'
    );
  });

  test('maps deactivated DID with null doc as success result', () => {
    const meta: DIDResolutionMeta = { ...baseMeta, deactivated: true };
    const result = toResolutionResult({ did: 'did:webvh:SCID:example.com', doc: null, meta });
    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument).toBeNull();
    expect(result.didDocumentMetadata.deactivated).toBe(true);
  });

  test('preserves a valid document returned alongside a warning-level error', () => {
    const doc = { id: 'did:webvh:SCID:example.com' };
    const meta: DIDResolutionMeta = {
      ...baseMeta,
      error: 'invalidDid',
      problemDetails: { type: 'x', title: 'y', detail: 'later entry failed witness verification' },
    };
    const result = toResolutionResult({ did: doc.id, doc, meta });
    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    // The earlier valid version must not be dropped.
    expect(result.didDocument).toEqual(doc);
    expect(result.didDocumentMetadata.versionId).toBe('1-abc');
  });
});

describe('toErrorResult', () => {
  test('builds an error result with code, detail, and synthesized problemDetails', () => {
    const result = toErrorResult('invalidOptions', 'two selectors supplied', { controlled: false });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidOptions');
    expect((result.didResolutionMetadata as { controlled?: boolean }).controlled).toBe(false);
    expect(result.didResolutionMetadata.message).toBe('two selectors supplied');
    const problemDetails = (
      result.didResolutionMetadata as { problemDetails?: { type: string; title: string; detail: string } }
    ).problemDetails;
    expect(problemDetails?.detail).toBe('two selectors supplied');
    expect(problemDetails?.type).toContain('INVALID_OPTIONS');
    expect(problemDetails?.title.length).toBeGreaterThan(0);
    expect(result.didDocumentMetadata).toEqual({});
  });

  test('a problemType override replaces the default problemDetails.type', () => {
    const result = toErrorResult('invalidOptions', 'conflicting selectors', {
      problemType: WEBVH_ERROR_TYPES.conflictingResolutionOptions,
    });
    const problemDetails = (result.didResolutionMetadata as { problemDetails?: { type: string } }).problemDetails;
    expect(problemDetails?.type).toBe(WEBVH_ERROR_TYPES.conflictingResolutionOptions);
  });

  test('malformed DID URL syntax uses invalidDidUrl', () => {
    const result = toErrorResult('invalidDidUrl', 'Malformed percent-encoding in DID URL query.');
    expect(result.didResolutionMetadata.error).toBe('invalidDidUrl');
    const problemDetails = (result.didResolutionMetadata as { problemDetails?: { type: string } }).problemDetails;
    expect(problemDetails?.type).toContain('INVALID_DID_URL');
  });
});
