import { describe, expect, test } from 'vitest';
import {
  addDefaultDidWebvhServices,
  enrichAlsoKnownAs,
  generateParallelDidWeb,
  validateCreateDidDocument,
} from '../src/did-document.js';
import type { DIDDocument, VerificationMethod } from '../src/interfaces.js';
import { createDID, updateDID } from '../src/method.js';
import { findVerificationMethod } from '../src/utils/verification-methods.js';
import {
  createTestDIDDocument,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
} from './utils.js';

describe('didDocument create pass-through', () => {
  test('rejects secretKeyMultibase when createDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}',
          verificationMethod: [authKey],
        } as unknown as DIDDocument,
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });

  test('creates DID from pass-through didDocument and replaces placeholders', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);
    const didDocument: DIDDocument & { exampleExtension: { enabled: boolean } } = {
      id: '{DID}',
      '@context': ['https://www.w3.org/ns/did/v1'],
      controller: 'did:example:controller',
      service: [
        {
          id: '{DID}#service-1',
          type: 'LinkedDomains',
          serviceEndpoint: 'https://example.com',
        },
      ],
      exampleExtension: { enabled: true },
    };

    const { did, doc } = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument,
    });

    expect(doc.id).toBe(did);
    expect(doc.id).toBe(`did:webvh:${did.split(':')[2]}:example.com`);
    expect(doc['@context']).toEqual(['https://www.w3.org/ns/did/v1']);
    expect(doc.controller).toBe('did:example:controller');
    expect(doc.service?.[0]?.id).toBe(`${did}#service-1`);
    expect((doc as typeof didDocument).exampleExtension).toEqual({ enabled: true });
  });

  test('rejects private key material in pass-through didDocument', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}',
          verificationMethod: [
            {
              id: '#key-1',
              type: 'Multikey',
              controller: '{DID}',
              publicKeyMultibase: authKey.publicKeyMultibase,
              secretKeyMultibase: authKey.secretKeyMultibase,
            },
          ],
        } as unknown as DIDDocument,
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });

  test('rejects nested private key material in pass-through didDocument', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}',
          verificationMethod: [
            {
              id: '#key-1',
              type: 'ConditionalProof2022',
              controller: '{DID}',
              conditionOr: [
                {
                  id: '#nested-key',
                  type: 'Multikey',
                  controller: '{DID}',
                  publicKeyMultibase: authKey.publicKeyMultibase,
                  secretKeyMultibase: authKey.secretKeyMultibase,
                },
              ],
            },
          ],
        } as unknown as DIDDocument,
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });

  test('rejects pass-through didDocument without placeholder in id', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: 'did:webvh:abc123:example.com',
        },
      })
    ).rejects.toThrow("didDocument.id must contain a '{SCID}' or '{DID}' placeholder");
  });

  test('rejects pass-through didDocument whose substituted id does not match the created DID', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}garbage',
        },
      })
    ).rejects.toThrow(/must match expected DID/);
  });

  test('adds derived alsoKnownAs aliases when flags are enabled', async () => {
    const authKey = await generateTestVerificationMethod();

    const { doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: {
        id: '{DID}',
        alsoKnownAs: ['did:example:existing'],
      },
      alsoKnownAsWeb: true,
    });

    expect(doc.alsoKnownAs).toContain('did:example:existing');
    expect(doc.alsoKnownAs).toContain('did:web:example.com');
  });

  test('throws when alsoKnownAs is not an array', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        address: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: '{DID}',
          alsoKnownAs: 'did:example:not-array' as unknown as string[],
        },
        alsoKnownAsWeb: true,
      })
    ).rejects.toThrow('alsoKnownAs is not an array');
  });

  test('rejects secretKeyMultibase when updateDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    await expect(
      updateDID({
        log: created.log,
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument: {
          id: created.did,
          verificationMethod: [authKey],
        } as unknown as DIDDocument,
      })
    ).rejects.toThrow('private key material must not be included in DID documents');
  });
});

describe('generateParallelDidWeb', () => {
  test('shared default-service helper adds fragment-form implicit services without mutating the input document', () => {
    const did = 'did:webvh:zQmExample:example.com:path';
    const originalDoc = {
      id: did,
      service: [
        {
          id: '#custom',
          type: 'CustomService',
          serviceEndpoint: 'https://example.com/path/custom',
        },
      ],
    };

    const augmentedDoc = addDefaultDidWebvhServices(did, originalDoc, { idStyle: 'fragment' });

    expect(originalDoc.service).toHaveLength(1);
    expect((originalDoc.service ?? []).some((service) => service.id === '#files')).toBe(false);
    expect((originalDoc.service ?? []).some((service) => service.id === '#whois')).toBe(false);
    expect((augmentedDoc.service ?? []).some((service) => service.id === '#files')).toBe(true);
    expect((augmentedDoc.service ?? []).some((service) => service.id === '#whois')).toBe(true);
  });

  test('generates did:web doc with correct id', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.id).toBe('did:web:example.com');
  });

  test('adds full did:webvh DID to alsoKnownAs of did:web doc', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.alsoKnownAs).toContain(did);
  });

  test('returns webDoc on createDID when alsoKnownAsWeb is enabled', async () => {
    const authKey = await generateTestVerificationMethod();
    const result = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      alsoKnownAsWeb: true,
    });

    expect(result.webDoc).toBeDefined();
    expect(result.webDoc?.id).toBe('did:web:example.com');
    expect(result.webDoc?.alsoKnownAs).toContain(result.did);
  });

  test('does not return webDoc on createDID when alsoKnownAsWeb is omitted', async () => {
    const authKey = await generateTestVerificationMethod();
    const result = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    expect(result.webDoc).toBeUndefined();
  });

  test('adds implicit #files and #whois services with correct HTTPS endpoints', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);
    const services = webDoc.service ?? [];
    const filesService = services.find((service) => service.id?.endsWith('#files'));
    const whoisService = services.find((service) => service.id?.endsWith('#whois'));

    expect(filesService).toBeDefined();
    expect(filesService?.serviceEndpoint).toBe('https://example.com/');
    expect(whoisService).toBeDefined();
    expect(whoisService?.serviceEndpoint).toBe('https://example.com/whois.vp');
    expect(whoisService?.['@context']).toBe('https://identity.foundation/linked-vp/contexts/v1');
  });

  test('translates verification method ids and controllers to did:web', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    for (const verificationMethod of webDoc.verificationMethod ?? []) {
      expect(verificationMethod.id?.startsWith('did:web:')).toBe(true);
      expect(verificationMethod.controller?.startsWith('did:web:')).toBe(true);
    }
  });

  test('preserves path segments in generated did:web document and implicit service endpoints', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      paths: ['path', 'sub'],
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);
    const filesService = (webDoc.service ?? []).find((service) => service.id?.endsWith('#files'));
    const whoisService = (webDoc.service ?? []).find((service) => service.id?.endsWith('#whois'));

    expect(webDoc.id).toBe('did:web:example.com:path:sub');
    expect(filesService?.serviceEndpoint).toBe('https://example.com/path/sub/');
    expect(whoisService?.serviceEndpoint).toBe('https://example.com/path/sub/whois.vp');
  });

  test('preserves encoded port in generated did:web document and decodes it for implicit service endpoints', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'https://example.com:8443/',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);
    const filesService = (webDoc.service ?? []).find((service) => service.id?.endsWith('#files'));
    const whoisService = (webDoc.service ?? []).find((service) => service.id?.endsWith('#whois'));

    expect(webDoc.id).toBe('did:web:example.com%3A8443');
    expect(filesService?.serviceEndpoint).toBe('https://example.com:8443/');
    expect(whoisService?.serviceEndpoint).toBe('https://example.com:8443/whois.vp');
  });

  test('does not include did:web self-reference in alsoKnownAs of did:web doc', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      alsoKnownAsWeb: true,
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.alsoKnownAs).not.toContain('did:web:example.com');
    expect(webDoc.alsoKnownAs).toContain(did);
  });

  test('removes duplicate entries from alsoKnownAs when generating parallel did:web doc', async () => {
    const authKey = await generateTestVerificationMethod();
    const baseAlias = 'did:example:original';
    const didDoc = createTestDIDDocument(authKey);
    didDoc.alsoKnownAs = [baseAlias, baseAlias, 'did:example:another', baseAlias];

    const { did, doc } = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: didDoc,
    });

    const webDoc = generateParallelDidWeb(did, doc);

    // Verify duplicates are removed
    const aliasCount = (webDoc.alsoKnownAs ?? []).filter((alias) => alias === baseAlias).length;
    expect(aliasCount).toBe(1);

    // Verify unique aliases are preserved
    expect(webDoc.alsoKnownAs).toContain('did:example:another');

    // Verify did:webvh DID is added
    expect(webDoc.alsoKnownAs).toContain(did);

    // Verify did:web self-reference is not included
    expect(webDoc.alsoKnownAs).not.toContain('did:web:example.com');
  });

  test('returns webDoc on updateDID when did:web alias is present', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      address: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
      alsoKnownAsWeb: true,
    });

    const updated = await updateDID({
      log: created.log,
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
    });

    expect(updated.webDoc).toBeDefined();
    expect(updated.webDoc?.id).toBe('did:web:example.com');
    expect(updated.webDoc?.alsoKnownAs).toContain(updated.did);
  });

  test('default-service helper returns original object unchanged when both implicit services already exist', () => {
    const did = 'did:webvh:zQmExample:example.com:path';
    const existing: DIDDocument = {
      id: did,
      service: [
        {
          id: `${did}#files`,
          type: 'RelativeRef',
          serviceEndpoint: 'https://example.com/path/',
        },
        {
          id: `${did}#whois`,
          type: 'LinkedVerifiablePresentation',
          serviceEndpoint: 'https://example.com/path/whois.vp',
        },
      ],
    };

    const result = addDefaultDidWebvhServices(did, existing);

    expect(result).toBe(existing);
    expect(result.service).toHaveLength(2);
  });

  test('adds implicit #files and #whois services to DID with pre-existing #files, preserving custom endpoint', () => {
    // Regression test: verify no duplication when #files already exists
    const did = 'did:webvh:zQmExample:example.com';
    const withPreexistingFiles: DIDDocument = {
      id: did,
      service: [
        {
          id: `${did}#files`,
          type: 'RelativeRef',
          serviceEndpoint: 'https://custom.example.com/files/',
        },
      ],
    };

    const result = addDefaultDidWebvhServices(did, withPreexistingFiles);

    // Should add #whois but NOT duplicate #files
    expect(result.service).toHaveLength(2);
    const filesServices = (result.service ?? []).filter((s) => s.id?.endsWith('#files'));
    const whoisServices = (result.service ?? []).filter((s) => s.id?.endsWith('#whois'));

    expect(filesServices).toHaveLength(1);
    expect(filesServices[0].serviceEndpoint).toBe('https://custom.example.com/files/');
    expect(whoisServices).toHaveLength(1);
    expect(whoisServices[0].serviceEndpoint).toBe('https://example.com/whois.vp');
  });

  test('foreign DID service ids ending with #files/#whois do not suppress implicit services', () => {
    const did = 'did:webvh:zQmExample:example.com';
    const withForeignServices: DIDDocument = {
      id: did,
      service: [
        {
          id: 'did:webvh:zQmOther:other.example#files',
          type: 'RelativeRef',
          serviceEndpoint: 'https://other.example/files/',
        },
        {
          id: 'did:webvh:zQmOther:other.example#whois',
          type: 'LinkedVerifiablePresentation',
          serviceEndpoint: 'https://other.example/whois.vp',
        },
      ],
    };

    const result = addDefaultDidWebvhServices(did, withForeignServices);

    const localFiles = (result.service ?? []).filter((s) => s.id === `${did}#files` || s.id === '#files');
    const localWhois = (result.service ?? []).filter((s) => s.id === `${did}#whois` || s.id === '#whois');

    expect(localFiles).toHaveLength(1);
    expect(localFiles[0].serviceEndpoint).toBe('https://example.com/');
    expect(localWhois).toHaveLength(1);
    expect(localWhois[0].serviceEndpoint).toBe('https://example.com/whois.vp');
    expect(result.service).toHaveLength(4);
  });

  test('generates correct implicit service endpoints for pathed + percent-encoded DID (port + path)', async () => {
    // Regression test: verify service endpoint derivation for complex addresses
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      address: 'https://example.com:8443/identity/prod',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: createTestDIDDocument(authKey),
    });

    // Verify DID format includes port and path
    expect(did).toMatch(/^did:webvh:[^:]+:example\.com%3A8443:identity:prod$/);

    // Generate parallel did:web document and check implicit services
    const webDoc = generateParallelDidWeb(did, doc);
    const filesService = (webDoc.service ?? []).find((s) => s.id?.endsWith('#files'));
    const whoisService = (webDoc.service ?? []).find((s) => s.id?.endsWith('#whois'));

    expect(filesService).toBeDefined();
    expect(filesService?.serviceEndpoint).toBe('https://example.com:8443/identity/prod/');
    expect(whoisService).toBeDefined();
    expect(whoisService?.serviceEndpoint).toBe('https://example.com:8443/identity/prod/whois.vp');
  });
});

describe('did-document helper branches', () => {
  test('validateCreateDidDocument rejects non-object and non-string id', () => {
    expect(() => validateCreateDidDocument(null as unknown as DIDDocument)).toThrow('didDocument must be an object');
    expect(() => validateCreateDidDocument({ id: 123 } as unknown as DIDDocument)).toThrow(
      "didDocument 'id' field must be a string"
    );
  });

  test('enrichAlsoKnownAs rejects invalid did:webvh identifier when alias flag is enabled', () => {
    expect(() =>
      enrichAlsoKnownAs({ id: '{DID}' } as DIDDocument, 'did:example:123', { alsoKnownAsWeb: true })
    ).toThrow("Invalid did:webvh id 'did:example:123'");
  });

  test('findVerificationMethod resolves from relationship object and returns null when not found', () => {
    const vm: VerificationMethod = {
      id: '#rel-vm',
      type: 'Multikey',
      controller: 'did:webvh:zQmExample:example.com',
      publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    };

    const doc: DIDDocument = {
      id: 'did:webvh:zQmExample:example.com',
      authentication: [vm as unknown as string],
    };

    expect(findVerificationMethod(doc, '#rel-vm')).toEqual(vm);
    expect(findVerificationMethod(doc, '#missing')).toBeNull();
  });
});

describe('complete didDocument contract and update semantics', () => {
  test('creates DID with multi-relationship verification method and relative IDs', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const didDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
      ],
      authentication: ['#key-1'],
      assertionMethod: ['#key-1'],
      keyAgreement: ['#key-1'],
    };

    const { did, doc } = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument,
    });

    expect(doc.id).toBe(did);
    expect(doc.verificationMethod?.[0].id).toBe('#key-1');
    expect(doc.verificationMethod?.[0].controller).toBe(did);
    expect(doc.authentication).toEqual(['#key-1']);
    expect(doc.assertionMethod).toEqual(['#key-1']);
    expect(doc.keyAgreement).toEqual(['#key-1']);
    expect(doc.controller).toBeUndefined(); // Top-level controller was omitted and remains omitted
  });

  test('preserves explicit caller-authored top-level controller when different from subject DID', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const didDocument: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
      controller: 'did:example:external-controller',
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
      ],
      authentication: ['#key-1'],
    };

    const { doc } = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument,
    });

    expect(doc.controller).toBe('did:example:external-controller');
  });

  test('rejects verification method missing explicit controller', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const didDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
      ],
      authentication: ['#key-1'],
    } as unknown as DIDDocument;

    await expect(
      createDID({
        address: 'example.com',
        signer,
        verifier,
        updateKeys: [authKey.publicKeyMultibase!],
        didDocument,
      })
    ).rejects.toThrow(/must have an explicit string 'controller'/);
  });

  test('update with complete didDocument completely replaces state (omitted service is deleted)', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const initialDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
      ],
      authentication: ['#key-1'],
      service: [
        {
          id: '#service-1',
          type: 'LinkedDomains',
          serviceEndpoint: 'https://example.com',
        },
      ],
    };

    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: initialDoc,
    });

    expect(created.doc.service).toHaveLength(1);

    // Update with a document that omits service
    const nextDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: created.did,
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          controller: created.did,
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
      ],
      authentication: ['#key-1'],
    };

    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      didDocument: nextDoc,
    });

    expect(updated.doc.service).toBeUndefined();
    expect(updated.doc.authentication).toEqual(['#key-1']);
  });

  test('update without didDocument preserves prior state while updating parameters', async () => {
    const authKey1 = await generateTestVerificationMethod();
    const authKey2 = await generateTestVerificationMethod();
    const signer1 = createTestSigner(authKey1);
    const verifier1 = createTestVerifier(authKey1);

    const initialDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
      verificationMethod: [
        {
          id: '#key-1',
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey1.publicKeyMultibase,
        },
      ],
      authentication: ['#key-1'],
      service: [
        {
          id: '#service-1',
          type: 'LinkedDomains',
          serviceEndpoint: 'https://example.com',
        },
      ],
    };

    const created = await createDID({
      address: 'example.com',
      signer: signer1,
      verifier: verifier1,
      updateKeys: [authKey1.publicKeyMultibase!],
      didDocument: initialDoc,
    });

    // Update keys only without passing didDocument
    const updated = await updateDID({
      log: created.log,
      signer: signer1,
      verifier: verifier1,
      updateKeys: [authKey2.publicKeyMultibase!],
    });

    expect(updated.meta.updateKeys).toEqual([authKey2.publicKeyMultibase!]);
    expect(updated.doc.service).toEqual(created.doc.service);
    expect(updated.doc.authentication).toEqual(['#key-1']);
    expect(updated.doc.verificationMethod).toEqual(created.doc.verificationMethod);
  });

  test('portable move rewrites self-referential controller and VM controller to new DID and keeps external controllers', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const initialDoc: DIDDocument = {
      '@context': ['https://www.w3.org/ns/did/v1'],
      id: '{DID}',
      controller: '{DID}',
      verificationMethod: [
        {
          id: '{DID}#key-1',
          type: 'Multikey',
          controller: '{DID}',
          publicKeyMultibase: authKey.publicKeyMultibase,
        },
        {
          id: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          type: 'Multikey',
          controller: 'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
          publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
        },
      ],
      authentication: ['{DID}#key-1'],
    };

    const created = await createDID({
      address: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: initialDoc,
      portable: true,
    });

    const oldDid = created.did;

    // Move to new address
    const updated = await updateDID({
      log: created.log,
      signer,
      verifier,
      address: 'new-domain.com',
    });

    const newDid = updated.did;
    expect(newDid).toContain('new-domain.com');
    expect(updated.doc.id).toBe(newDid);

    // Self-referential top-level controller is rewritten to newDid
    expect(updated.doc.controller).toBe(newDid);

    // Self-referential VM controller and ID are rewritten to newDid
    expect(updated.doc.verificationMethod?.[0].id).toBe(`${newDid}#key-1`);
    expect(updated.doc.verificationMethod?.[0].controller).toBe(newDid);
    expect(updated.doc.authentication).toEqual([`${newDid}#key-1`]);

    // External VM controller and ID remain untouched
    expect(updated.doc.verificationMethod?.[1].controller).toBe(
      'did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK'
    );

    // Predecessor is retained in alsoKnownAs
    expect(updated.doc.alsoKnownAs).toContain(oldDid);
  });
});
