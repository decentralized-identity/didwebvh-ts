import { describe, expect, test } from 'vitest';
import type { DIDDocument, VerificationMethod } from '../../index.js';
import { addVerificationMethodToDocument } from '../did-document.js';

const did = 'did:webvh:zQmExample:example.com';
const absoluteVmId = `${did}#key-1`;
const verificationMethod: VerificationMethod = {
  id: absoluteVmId,
  type: 'Multikey',
  controller: did,
  publicKeyMultibase: 'z6MkExample',
};

describe('CLI DID document authoring', () => {
  test('adds a verification method and relationships to an empty document shell', () => {
    const document: DIDDocument = { id: did };

    addVerificationMethodToDocument(document, verificationMethod, ['authentication', 'assertionMethod']);

    expect(document.verificationMethod).toEqual([verificationMethod]);
    expect(document.authentication).toEqual([absoluteVmId]);
    expect(document.assertionMethod).toEqual([absoluteVmId]);
  });

  test('does not duplicate a relative verification method or relationship reference', () => {
    const document: DIDDocument = {
      id: did,
      verificationMethod: [{ ...verificationMethod, id: '#key-1' }],
      authentication: ['#key-1'],
    };

    addVerificationMethodToDocument(document, verificationMethod, ['authentication']);

    expect(document.verificationMethod).toHaveLength(1);
    expect(document.verificationMethod?.[0].id).toBe('#key-1');
    expect(document.authentication).toEqual(['#key-1']);
  });

  test('does not duplicate an embedded relationship verification method with a relative ID', () => {
    const embeddedVerificationMethod = { ...verificationMethod, id: '#key-1' };
    const document: DIDDocument = {
      id: did,
      authentication: [embeddedVerificationMethod],
    };

    addVerificationMethodToDocument(document, verificationMethod, ['authentication']);

    expect(document.verificationMethod).toEqual([verificationMethod]);
    expect(document.authentication).toEqual([embeddedVerificationMethod]);
  });

  test('adds the local VM when an existing foreign DID URL has the same fragment', () => {
    const foreignVmId = 'did:example:controller#key-1';
    const document: DIDDocument = {
      id: did,
      verificationMethod: [{ ...verificationMethod, id: foreignVmId }],
      authentication: [foreignVmId],
    };

    // Add the local verificationMethod
    addVerificationMethodToDocument(document, verificationMethod, ['authentication']);

    expect(document.verificationMethod?.map((vm) => vm.id)).toEqual([foreignVmId, absoluteVmId]);
    expect(document.authentication).toEqual([foreignVmId, absoluteVmId]);
    expect(document.verificationMethod?.[1]?.id).not.toBe(document.verificationMethod?.[0]?.id);
  });
});
