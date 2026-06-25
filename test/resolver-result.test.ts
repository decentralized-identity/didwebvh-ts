import { describe, expect, test } from 'bun:test';
import type { DIDResolutionMeta } from '../src/interfaces';
import { DidResolutionError } from '../src/interfaces';
import {
  assertSingleVersionSelector,
  InvalidDidUrlError,
  mapErrorToCode,
  toErrorResult,
  toResolutionResult,
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

describe('assertSingleVersionSelector', () => {
  test('allows zero selectors', () => {
    expect(() => assertSingleVersionSelector({})).not.toThrow();
  });
  test('allows exactly one selector', () => {
    expect(() => assertSingleVersionSelector({ versionId: '2-x' })).not.toThrow();
    expect(() => assertSingleVersionSelector({ versionNumber: 2 })).not.toThrow();
    expect(() => assertSingleVersionSelector({ versionTime: new Date() })).not.toThrow();
  });
  test('rejects versionId + versionNumber', () => {
    expect(() => assertSingleVersionSelector({ versionId: '2-x', versionNumber: 2 })).toThrow(InvalidDidUrlError);
  });
  test('rejects versionId + versionTime', () => {
    expect(() => assertSingleVersionSelector({ versionId: '2-x', versionTime: new Date() })).toThrow(
      InvalidDidUrlError
    );
  });
  test('rejects versionNumber + versionTime', () => {
    expect(() => assertSingleVersionSelector({ versionNumber: 2, versionTime: new Date() })).toThrow(
      InvalidDidUrlError
    );
  });
  test('rejects all three', () => {
    expect(() => assertSingleVersionSelector({ versionId: '2-x', versionNumber: 2, versionTime: new Date() })).toThrow(
      InvalidDidUrlError
    );
  });
});

describe('mapErrorToCode', () => {
  test('InvalidDidUrlError -> invalidDidUrl', () => {
    expect(mapErrorToCode(new InvalidDidUrlError('x'))).toBe('invalidDidUrl');
  });
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
    // Non-404 HTTP failures are not absence either.
    expect(mapErrorToCode(new Error('HTTP error! status: 500'))).toBe('invalidDid');
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
      error: DidResolutionError.NotFound,
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
      error: DidResolutionError.InvalidDid,
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
    const result = toErrorResult('invalidDidUrl', 'two selectors supplied', { controlled: false });
    expect(result.didDocument).toBeNull();
    expect(result.didResolutionMetadata.error).toBe('invalidDidUrl');
    expect((result.didResolutionMetadata as { controlled?: boolean }).controlled).toBe(false);
    expect(result.didResolutionMetadata.message).toBe('two selectors supplied');
    const problemDetails = (
      result.didResolutionMetadata as { problemDetails?: { type: string; title: string; detail: string } }
    ).problemDetails;
    expect(problemDetails?.detail).toBe('two selectors supplied');
    expect(problemDetails?.type).toContain('INVALID_DID_URL');
    expect(problemDetails?.title.length).toBeGreaterThan(0);
    expect(result.didDocumentMetadata).toEqual({});
  });
});
