import { describe, expect, test } from 'vitest';
import { createDID, resolveDIDFromLog, updateDID } from '../src/method.js';
import { normalizeDidAddress } from '../src/parser.js';
import {
  createLegacyDID,
  createTestDIDDocument,
  createTestSigner,
  generateTestVerificationMethod,
  TestCryptoImplementation,
} from './utils.js';

async function createPortable() {
  const authKey = await generateTestVerificationMethod();
  const verifier = new TestCryptoImplementation({ verificationMethod: authKey });
  const created = await createDID({
    address: 'example.com',
    portable: true,
    signer: createTestSigner(authKey),
    updateKeys: [authKey.publicKeyMultibase!],
    didDocument: createTestDIDDocument(authKey),
    verifier,
  });
  const update = (address: string, paths?: string[]) =>
    updateDID({
      log: created.log,
      address,
      paths,
      signer: createTestSigner(authKey),
      updateKeys: [authKey.publicKeyMultibase!],
      verifier,
    });
  return { scid: created.log[0].parameters.scid!, update };
}

describe('updateDID canonicalises a new location', () => {
  test('a did:webvh address with lowercase hex is canonicalised on move', async () => {
    const { scid, update } = await createPortable();
    const updated = await update(`did:webvh:${scid}:%e4%be%8b.example.org%3a8443:%e7%94%a8`);
    expect(updated.did).toBe(`did:webvh:${scid}:xn--fsq.example.org%3A8443:%E7%94%A8`);
  });

  test('the actual SCID embedded in a domain keeps its case while the rest is lowercased', async () => {
    const { scid, update } = await createPortable();
    const updated = await update(`Tenant-${scid}.Example.org`);
    expect(updated.did).toBe(`did:webvh:${scid}:tenant-${scid}.example.org`);
  });

  test('previous path segments are re-canonicalised when carried over', () => {
    const scid = 'QmTestScid'.padEnd(46, 'x');
    const result = normalizeDidAddress({
      address: 'example.org',
      scid,
      fallbackPaths: ['%e7%94%a8', 'Users'],
      context: 'updateDID path segments',
    });
    expect(result.did).toBe(`did:webvh:${scid}:example.org:%E7%94%A8:Users`);
  });
});

describe('updateDID rejects the {SCID} placeholder (spec: Create step 1)', () => {
  test.each([
    ['{SCID}.example.org', undefined],
    ['example.org', ['{SCID}']],
    ['example.org', ['tenant-{SCID}']],
  ])('%s %j', async (address, paths) => {
    const { update } = await createPortable();
    await expect(update(address, paths as string[] | undefined)).rejects.toThrow(
      'must not contain the {SCID} placeholder once the SCID has been generated'
    );
  });

  test('but accepts the actual SCID in domain and path', async () => {
    const { scid, update } = await createPortable();
    const updated = await update(`${scid}.example.org`, [scid]);
    expect(updated.did).toBe(`did:webvh:${scid}:${scid}.example.org:${scid}`);
  });
});

describe('updateDID with a non-canonical legacy DID', () => {
  const legacyDid = 'did:webvh:{SCID}:EXAMPLE.com:%e7%94%a8';

  test('the fixture really is non-canonical and still resolves', async () => {
    const { created, verifier } = await createLegacyDID({ did: legacyDid });
    expect(created.did).toMatch(/:EXAMPLE\.com:%e7%94%a8$/);
    const resolved = await resolveDIDFromLog(created.log, { verifier });
    expect(resolved.didDocument?.id).toBe(created.did);
  });

  test.each([
    ['the legacy DID itself', (scid: string) => `did:webvh:${scid}:EXAMPLE.com:%e7%94%a8`, undefined],
    ['the canonical DID', (scid: string) => `did:webvh:${scid}:example.com:%E7%94%A8`, undefined],
    ['an HTTPS URL', () => 'https://example.com/用', undefined],
    ['a bare domain carrying over the previous path', () => 'EXAMPLE.com', undefined],
    ['a bare domain with a raw Unicode path', () => 'example.com', ['用']],
  ])('re-supplying the same location as %s keeps the DID', async (_name, address, paths) => {
    const { created, scid, update } = await createLegacyDID({ did: legacyDid });
    const updated = await update(address(scid), paths);
    expect(updated.did).toBe(created.did);
  });

  test('a genuine move is canonicalised, including carried-over path segments', async () => {
    const { scid, update } = await createLegacyDID({ did: legacyDid, portable: true });
    const updated = await update('Example.org');
    expect(updated.did).toBe(`did:webvh:${scid}:example.org:%E7%94%A8`);
  });

  test('a genuine move is still rejected when portability is disabled', async () => {
    const { update } = await createLegacyDID({ did: legacyDid });
    await expect(update('example.org')).rejects.toThrow('Cannot move DID: portability is disabled');
  });
});
