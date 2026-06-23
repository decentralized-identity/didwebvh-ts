import { describe, expect, test } from 'bun:test';
import { createDID, updateDID } from '../src/method';
import { generateParallelDidWeb } from '../src/utils';
import {
  asPublicVerificationMethods,
  createTestSigner,
  createTestVerifier,
  generateTestVerificationMethod,
} from './utils';

describe('didDocument create pass-through', () => {
  test('warns and strips secretKeyMultibase when createDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();

    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    };

    try {
      const { doc } = await createDID({
        domain: 'example.com',
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
      });

      expect(warnings.some((msg) => msg.includes('Removing secretKeyMultibase'))).toBe(true);
      expect((doc.verificationMethod ?? []).every((vm) => vm.secretKeyMultibase === undefined)).toBe(true);
    } finally {
      console.warn = originalWarn;
    }
  });

  test('creates DID from pass-through didDocument and replaces placeholders', async () => {
    const authKey = await generateTestVerificationMethod();
    const signer = createTestSigner(authKey);
    const verifier = createTestVerifier(authKey);

    const { did, doc } = await createDID({
      domain: 'example.com',
      signer,
      verifier,
      updateKeys: [authKey.publicKeyMultibase!],
      didDocument: {
        id: '{DID}',
        '@context': ['https://www.w3.org/ns/did/v1'],
        service: [
          {
            id: '{DID}#service-1',
            type: 'LinkedDomains',
            serviceEndpoint: 'https://example.com',
          },
        ],
      },
    });

    expect(doc.id).toBe(did);
    expect(doc.id).toBe(`did:webvh:${did.split(':')[2]}:example.com`);
    expect(doc.service?.[0]?.id).toBe(`${did}#service-1`);
  });

  test('rejects pass-through didDocument without placeholder in id', async () => {
    const authKey = await generateTestVerificationMethod();

    await expect(
      createDID({
        domain: 'example.com',
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
        domain: 'example.com',
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
      domain: 'example.com',
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
        domain: 'example.com',
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

  test('warns and strips secretKeyMultibase when updateDID receives secret-bearing verificationMethods', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const warnings: string[] = [];
    const originalWarn = console.warn;
    console.warn = (...args: unknown[]) => {
      warnings.push(args.map(String).join(' '));
    };

    try {
      const updated = await updateDID({
        log: created.log,
        signer: createTestSigner(authKey),
        verifier: createTestVerifier(authKey),
        updateKeys: [authKey.publicKeyMultibase!],
        verificationMethods: [authKey],
      });

      expect(warnings.some((msg) => msg.includes('Removing secretKeyMultibase'))).toBe(true);
      expect((updated.doc.verificationMethod ?? []).every((vm) => vm.secretKeyMultibase === undefined)).toBe(true);
    } finally {
      console.warn = originalWarn;
    }
  });
});

describe('generateParallelDidWeb', () => {
  test('generates did:web doc with correct id', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.id).toBe('did:web:example.com');
  });

  test('adds full did:webvh DID to alsoKnownAs of did:web doc', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.alsoKnownAs).toContain(did);
  });

  test('returns webDoc on createDID when alsoKnownAsWeb is enabled', async () => {
    const authKey = await generateTestVerificationMethod();
    const result = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAsWeb: true,
    });

    expect(result.webDoc).toBeDefined();
    expect(result.webDoc?.id).toBe('did:web:example.com');
    expect(result.webDoc?.alsoKnownAs).toContain(result.did);
  });

  test('does not return webDoc on createDID when alsoKnownAsWeb is omitted', async () => {
    const authKey = await generateTestVerificationMethod();
    const result = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
    });

    expect(result.webDoc).toBeUndefined();
  });

  test('adds implicit #files and #whois services with correct HTTPS endpoints', async () => {
    const authKey = await generateTestVerificationMethod();
    const { did, doc } = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      domain: 'example.com',
      paths: ['path', 'sub'],
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
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
      verificationMethods: asPublicVerificationMethods(authKey),
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
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAsWeb: true,
    });

    const webDoc = generateParallelDidWeb(did, doc);

    expect(webDoc.alsoKnownAs).not.toContain('did:web:example.com');
    expect(webDoc.alsoKnownAs).toContain(did);
  });

  test('returns webDoc on updateDID when did:web alias is present', async () => {
    const authKey = await generateTestVerificationMethod();
    const created = await createDID({
      domain: 'example.com',
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAsWeb: true,
    });

    const updated = await updateDID({
      log: created.log,
      signer: createTestSigner(authKey),
      verifier: createTestVerifier(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verificationMethods: asPublicVerificationMethods(authKey),
      alsoKnownAs: created.doc.alsoKnownAs,
    });

    expect(updated.webDoc).toBeDefined();
    expect(updated.webDoc?.id).toBe('did:web:example.com');
    expect(updated.webDoc?.alsoKnownAs).toContain(updated.did);
  });
});
