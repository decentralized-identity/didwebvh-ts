import { describe, expect, test } from 'bun:test';
import { createDID } from '../src/method';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

type InputKind = 'domain' | 'address';

async function createFromInput(kind: InputKind, value: string) {
  const authKey = await generateTestVerificationMethod();
  const verifier = new TestCryptoImplementation({ verificationMethod: authKey });

  const baseOptions = {
    signer: createTestSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
    verifier,
  };

  if (kind === 'domain') {
    return createDID({
      ...baseOptions,
      domain: value,
    });
  }

  return createDID({
    ...baseOptions,
    address: value,
  } as any);
}

describe('Strict address input validation and parsing', () => {
  test('accepts host-only domain input', async () => {
    const { doc } = await createFromInput('domain', 'example.com');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com$/);
  });

  test('Accepts host:port domain input with canonical %3A encoding', async () => {
    const { doc } = await createFromInput('domain', 'example.com:443');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A443$/);
  });

  test('Accepts pre-encoded host%3Aport without double encoding', async () => {
    const { doc } = await createFromInput('domain', 'localhost%3A8000');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000$/);
  });

  test('Accepts https URL address input', async () => {
    const { doc } = await createFromInput('address', 'https://example.com/');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com$/);
  });

  test('Accepts URL with explicit port', async () => {
    const { doc } = await createFromInput('address', 'https://example.com:8080/');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A8080$/);
  });

  test('Accepts URL with custom path and converts to colon-delimited DID path', async () => {
    const { doc } = await createFromInput('address', 'https://example.com/custom/path');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com:custom:path$/);
  });

  test('Accepts localhost HTTP URL with path and port', async () => {
    const { doc } = await createFromInput('address', 'http://localhost:8000/test');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000:test$/);
  });

  test('Accepts localhost HTTPS URL with path and port', async () => {
    const { doc } = await createFromInput('address', 'https://localhost:8000/test');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000:test$/);
  });

  test('Accepts canonical did:webvh input with port and path', async () => {
    const { doc } = await createFromInput('address', 'did:webvh:{SCID}:example.com%3A8080:custom:path');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A8080:custom:path$/);
  });

  test('Rejects unsupported URL scheme', async () => {
    expect(createFromInput('address', 'ftp://example.com')).rejects.toThrow();
  });

  test('Rejects HTTP URL for non-local host', async () => {
    expect(createFromInput('address', 'http://example.com')).rejects.toThrow();
  });

  test('Rejects out-of-range port', async () => {
    expect(createFromInput('domain', 'example.com:999999')).rejects.toThrow();
  });

  test('Rejects IPv4 host input', async () => {
    expect(createFromInput('domain', '192.168.1.10')).rejects.toThrow();
  });

  test('Rejects double-encoded separator', async () => {
    expect(createFromInput('domain', 'example.com%253A8080')).rejects.toThrow();
  });

  test('Rejects mangled host:port input', async () => {
    expect(createFromInput('domain', '%%%bad host%%%::notaport::')).rejects.toThrow();
  });

  test('Rejects mangled URL input', async () => {
    expect(createFromInput('address', 'https://%%%bad host%%%::notaport::/%%%')).rejects.toThrow();
  });
});
