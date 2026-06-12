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
  });
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

  test('Accepts pre-encoded host%3aport with lowercase separator and canonicalizes output', async () => {
    const { doc } = await createFromInput('domain', 'localhost%3a8000');
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

  test('Rejects localhost HTTP URL with path and port', async () => {
    expect(createFromInput('address', 'http://localhost:8000/test')).rejects.toThrow('HTTP is not allowed; use HTTPS');
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

  test('Rejects encoded IPv4 host input', async () => {
    expect(createFromInput('domain', '127%2E0%2E0%2E1')).rejects.toThrow('IP addresses are not allowed as hosts');
  });

  test('Rejects lowercase encoded-port IP host input', async () => {
    expect(createFromInput('domain', '127.0.0.1%3a8080')).rejects.toThrow('IP addresses are not allowed as hosts');
  });

  test('Rejects did:webvh input containing fragment contamination', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com#frag')).rejects.toThrow(
      'Address input must not include query or fragment components'
    );
  });

  test('Rejects did:webvh input containing query contamination', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com?query=1')).rejects.toThrow(
      'Address input must not include query or fragment components'
    );
  });

  test('Rejects did:webvh input containing dot-segment path traversal', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:..:secrets')).rejects.toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
  });

  test('Rejects did:webvh input containing percent-encoded traversal segment', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:%2E%2E:secrets')).rejects.toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
  });

  test('Rejects did:webvh input containing decoded slash within one path segment', async () => {
    expect(createFromInput('address', 'did:webvh:{SCID}:example.com:a%2Fb')).rejects.toThrow(
      'did:webvh identifier must not contain decoded slash within a single path segment'
    );
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
