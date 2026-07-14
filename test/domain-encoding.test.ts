import { describe, expect, test } from 'vitest';
import { createDID } from '../src/method';
import {
  asPublicVerificationMethods,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils';

async function createFromInput(value: string) {
  const authKey = await generateTestVerificationMethod();
  const verifier = new TestCryptoImplementation({ verificationMethod: authKey });

  const baseOptions = {
    signer: createTestSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    verificationMethods: asPublicVerificationMethods(authKey),
    verifier,
  };

  return createDID({
    ...baseOptions,
    address: value,
  });
}

describe('Strict address input validation and parsing', () => {
  test('accepts host-only domain input', async () => {
    const { doc } = await createFromInput('example.com');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com$/);
  });

  test('Accepts host:port domain input with canonical %3A encoding', async () => {
    const { doc } = await createFromInput('example.com:443');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A443$/);
  });

  test('Accepts pre-encoded host%3Aport without double encoding', async () => {
    const { doc } = await createFromInput('localhost%3A8000');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000$/);
  });

  test('Accepts pre-encoded host%3aport with lowercase separator and canonicalizes output', async () => {
    const { doc } = await createFromInput('localhost%3a8000');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000$/);
  });

  test('Accepts https URL address input', async () => {
    const { doc } = await createFromInput('https://example.com/');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com$/);
  });

  test('Accepts URL with explicit port', async () => {
    const { doc } = await createFromInput('https://example.com:8080/');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A8080$/);
  });

  test('Accepts URL with custom path and converts to colon-delimited DID path', async () => {
    const { doc } = await createFromInput('https://example.com/custom/path');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com:custom:path$/);
  });

  test('Rejects localhost HTTP URL with path and port', async () => {
    expect(createFromInput('http://localhost:8000/test')).rejects.toThrow('HTTP is not allowed; use HTTPS');
  });

  test('Accepts localhost HTTPS URL with path and port', async () => {
    const { doc } = await createFromInput('https://localhost:8000/test');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:localhost%3A8000:test$/);
  });

  test('Accepts canonical did:webvh input with port and path', async () => {
    const { doc } = await createFromInput('did:webvh:{SCID}:example.com%3A8080:custom:path');
    expect(doc.id).toMatch(/^did:webvh:[^:]+:example\.com%3A8080:custom:path$/);
  });

  test('Rejects unsupported URL scheme', async () => {
    expect(createFromInput('ftp://example.com')).rejects.toThrow();
  });

  test('Rejects HTTP URL for non-local host', async () => {
    expect(createFromInput('http://example.com')).rejects.toThrow();
  });

  test('Rejects out-of-range port', async () => {
    expect(createFromInput('example.com:999999')).rejects.toThrow();
  });

  test('Rejects IPv4 host input', async () => {
    expect(createFromInput('192.168.1.10')).rejects.toThrow();
  });

  test('Rejects encoded IPv4 host input', async () => {
    expect(createFromInput('127%2E0%2E0%2E1')).rejects.toThrow('IP addresses are not allowed as hosts');
  });

  test('Rejects lowercase encoded-port IP host input', async () => {
    expect(createFromInput('127.0.0.1%3a8080')).rejects.toThrow('IP addresses are not allowed as hosts');
  });

  test('Rejects did:webvh input containing fragment contamination', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com#frag')).rejects.toThrow(
      'Address input must not include query or fragment components'
    );
  });

  test('Rejects did:webvh input containing query contamination', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com?query=1')).rejects.toThrow(
      'Address input must not include query or fragment components'
    );
  });

  test('Rejects did:webvh input containing dot-segment path traversal', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com:..:secrets')).rejects.toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
  });

  test('Rejects did:webvh input containing percent-encoded traversal segment', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com:%2E%2E:secrets')).rejects.toThrow(
      'did:webvh identifier must not contain dot-segments'
    );
  });

  test('Rejects did:webvh input containing decoded slash within one path segment', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com:a%2Fb')).rejects.toThrow(
      'did:webvh identifier must not contain decoded slash within a single path segment'
    );
  });

  test('Rejects double-encoded separator', async () => {
    expect(createFromInput('example.com%253A8080')).rejects.toThrow();
  });

  test('Rejects mangled host:port input', async () => {
    expect(createFromInput('%%%bad host%%%::notaport::')).rejects.toThrow();
  });

  test('Rejects mangled URL input', async () => {
    expect(createFromInput('https://%%%bad host%%%::notaport::/%%%')).rejects.toThrow();
  });

  test('Rejects decoded backslash in path segment', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com:test%5Csecret')).rejects.toThrow(
      'did:webvh identifier must not contain decoded backslash within a path segment'
    );
  });

  test('Rejects decoded NUL in path segment', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com:test%00secret')).rejects.toThrow(
      'did:webvh identifier must not contain decoded NUL character within a path segment'
    );
  });

  test('Rejects leading whitespace in decoded path segment', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com:%20test')).rejects.toThrow(
      'did:webvh identifier must not contain leading or trailing whitespace in decoded path segment'
    );
  });

  test('Rejects trailing whitespace in decoded path segment', async () => {
    expect(createFromInput('did:webvh:{SCID}:example.com:test%20')).rejects.toThrow(
      'did:webvh identifier must not contain leading or trailing whitespace in decoded path segment'
    );
  });
});
