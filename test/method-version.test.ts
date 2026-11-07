import { readFileSync } from 'node:fs';
import { ed25519 } from '@noble/curves/ed25519.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { describe, expect, test } from 'vitest';
import type { DIDLog, WitnessProofFileEntry } from '../src/interfaces.js';
import {
  createDID,
  deactivateDID,
  getWitnessRequirements,
  migrateDID,
  resolveDID,
  resolveDIDFromLog,
  signWitnessProofEntry,
  updateDID,
  verifyWitnessProofs,
} from '../src/method.js';
import { mapErrorToCode } from '../src/resolver-result.js';
import { MultibaseEncoding, multibaseEncode } from '../src/utils/multiformats.js';
import {
  appendRawLogEntry,
  createTestDIDDocument,
  createTestSigner,
  TestCryptoImplementation,
  type TestVerificationMethod,
} from './utils.js';

const REISSUE_MESSAGE = 'did:webvh:0.5 is not supported; re-issue this DID as did:webvh:1.0';

const readFixture = (name: string) => {
  const dir = new URL(`./fixtures/${name}/`, import.meta.url);
  const log = readFileSync(new URL('did.jsonl', dir), 'utf8')
    .trim()
    .split('\n')
    .map((line) => JSON.parse(line)) as DIDLog;
  const witnessProofs = JSON.parse(readFileSync(new URL('did-witness.json', dir), 'utf8')) as WitnessProofFileEntry[];
  return { log, witnessProofs };
};

// The fixture keys are SHA-256 of `didwebvh-weight-test/<name>` (see test/fixtures/README.md).
const fixtureKey = (name: string): TestVerificationMethod => {
  const seed = sha256(new TextEncoder().encode(`didwebvh-weight-test/${name}`));
  const publicKeyMultibase = multibaseEncode(
    new Uint8Array([0xed, 0x01, ...ed25519.getPublicKey(seed)]),
    MultibaseEncoding.BASE58_BTC
  );
  return {
    id: `did:key:${publicKeyMultibase}#${publicKeyMultibase}`,
    type: 'Multikey',
    controller: `did:key:${publicKeyMultibase}`,
    publicKeyMultibase,
    secretKeyMultibase: multibaseEncode(new Uint8Array([0x80, 0x26, ...seed]), MultibaseEncoding.BASE58_BTC),
  };
};

const controller = fixtureKey('controller');
const signer = createTestSigner(controller);
const verifier = new TestCryptoImplementation({ verificationMethod: controller });
const v05 = readFixture('2.8.0_v0.5_U');

// A v0.5 genesis followed by a did:webvh:1.0 entry, the shape 3.0.0 updateDID wrote when upgrading in place.
const upgradedInPlace = async (): Promise<DIDLog> =>
  appendRawLogEntry({
    log: v05.log.slice(0, 1),
    signer,
    method: 'did:webvh:1.0',
    updateKeys: [controller.publicKeyMultibase!],
    versionTime: '2026-05-02T00:00:00Z',
    verifier,
  });

const v05Logs = async (): Promise<[string, DIDLog][]> => [
  ['multi-entry 2.8.0 v0.5 log', v05.log],
  ['genesis-only 2.8.0 v0.5 log', v05.log.slice(0, 1)],
  ['v0.5 genesis upgraded in place', await upgradedInPlace()],
];

describe('did:webvh:0.5 logs', () => {
  test('the fixture controller key is the genesis update key', () => {
    expect(v05.log[0].parameters.method).toBe('did:webvh:0.5');
    expect(v05.log[0].parameters.updateKeys).toEqual([controller.publicKeyMultibase]);
  });

  test('resolution rejects each log with the re-issue message as invalidDid', async () => {
    for (const [name, log] of await v05Logs()) {
      const result = await resolveDIDFromLog(log, { verifier, witnessProofs: [] });
      expect(result.didDocument, name).toBeNull();
      expect(result.didResolutionMetadata.error, name).toBe('invalidDid');
      expect(result.didResolutionMetadata.problemDetails?.detail, name).toBe(REISSUE_MESSAGE);
    }
  });

  test('witness checks reject each log', async () => {
    for (const [name, log] of await v05Logs()) {
      expect(() => getWitnessRequirements(log), name).toThrow(REISSUE_MESSAGE);
      await expect(verifyWitnessProofs({ log, witnessProofs: [], verifier }), name).rejects.toThrow(REISSUE_MESSAGE);
    }
  });

  test('writers refuse each log', async () => {
    for (const [name, log] of await v05Logs()) {
      await expect(updateDID({ log, signer, verifier, witnessProofs: [] }), name).rejects.toThrow(REISSUE_MESSAGE);
      await expect(deactivateDID({ log, signer, verifier, witnessProofs: [] }), name).rejects.toThrow(REISSUE_MESSAGE);
      await expect(
        migrateDID({ log, signer, verifier, witnessProofs: [], address: 'example.com' }),
        name
      ).rejects.toThrow(REISSUE_MESSAGE);
      await expect(
        signWitnessProofEntry({
          trustedLog: log.slice(0, -1),
          candidateLog: log,
          witnessSigner: signer,
          witnessProofs: [],
          verifier,
        }),
        name
      ).rejects.toThrow(REISSUE_MESSAGE);
    }
  });

  test('resolveDID rejects before fetching did-witness.json', async () => {
    const did = v05.log[0].state.id!;
    const requested: string[] = [];
    const fetch = async (url: string) => {
      requested.push(url);
      return url.endsWith('/did.jsonl')
        ? new Response(`${v05.log.map((entry) => JSON.stringify(entry)).join('\n')}\n`)
        : new Response('', { status: 404 });
    };

    const result = await resolveDID(did, { fetch, verifier });

    expect(result.didResolutionMetadata.error).toBe('invalidDid');
    expect(result.didResolutionMetadata.problemDetails?.detail).toBe(REISSUE_MESSAGE);
    expect(requested).toEqual(['https://example.com/.well-known/did.jsonl']);
  });

  test('mapErrorToCode maps the method rejections to invalidDid', () => {
    expect(mapErrorToCode(new Error(REISSUE_MESSAGE))).toBe('invalidDid');
    expect(
      mapErrorToCode(new Error("version '2' has unsupported method 'did:webvh:0.5'; expected 'did:webvh:1.0'"))
    ).toBe('invalidDid');
  });
});

describe('did:webvh:1.0 logs written by 2.8.0', () => {
  test('a witnessed 2.8.0 log still resolves with its witness proofs', async () => {
    const { log, witnessProofs } = readFixture('2.8.0_v1.0_W');

    const result = await resolveDIDFromLog(log, { verifier, witnessProofs });

    expect(result.didResolutionMetadata.error).toBeUndefined();
    expect(result.didDocument?.id).toBe(log[0].state.id);
    expect(result.didDocumentMetadata.versionId).toBe(log.at(-1)?.versionId);
    expect(getWitnessRequirements(log)).toHaveLength(log.length);
    expect((await verifyWitnessProofs({ log, witnessProofs, verifier })).verified).toBe(true);
  });
});

describe('parameters not defined by did:webvh:1.0', () => {
  const createV10Log = async () =>
    (
      await createDID({
        address: 'example.com',
        signer,
        verifier,
        updateKeys: [controller.publicKeyMultibase!],
        didDocument: createTestDIDDocument(controller),
        created: '2026-01-01T00:00:00Z',
      })
    ).log;

  test('a later entry with an undefined parameter is rejected by resolution, witness checks and writers', async () => {
    const log = await appendRawLogEntry({
      log: await createV10Log(),
      signer,
      extraParameters: { prerotation: true },
      versionTime: '2026-01-01T00:00:01Z',
      verifier,
    });
    const message = "version '2' has unsupported parameter 'prerotation'; it is not defined by did:webvh:1.0";

    const resolved = await resolveDIDFromLog(log, { verifier, witnessProofs: [] });
    expect(resolved.didResolutionMetadata.error).toBe('invalidDid');
    expect(resolved.didResolutionMetadata.problemDetails?.detail).toBe(message);
    expect(() => getWitnessRequirements(log)).toThrow(message);
    await expect(updateDID({ log, signer, verifier, witnessProofs: [] })).rejects.toThrow(message);
  });

  test('a genesis entry with an undefined parameter is rejected before its hash is checked', async () => {
    const log = await createV10Log();
    const tampered: DIDLog = [
      { ...log[0], parameters: { ...log[0].parameters, foo: 'bar' } as DIDLog[0]['parameters'] },
    ];

    const resolved = await resolveDIDFromLog(tampered, { verifier, witnessProofs: [] });
    expect(resolved.didResolutionMetadata.problemDetails?.detail).toBe(
      "version '1' has unsupported parameter 'foo'; it is not defined by did:webvh:1.0"
    );
  });

  test('a later entry whose parameters is not an object is rejected', async () => {
    const log = await appendRawLogEntry({
      log: await createV10Log(),
      signer,
      versionTime: '2026-01-01T00:00:01Z',
      verifier,
    });
    const tampered = [log[0], { ...log[1], parameters: ['method'] }] as unknown as DIDLog;

    expect(() => getWitnessRequirements(tampered)).toThrow("version '2' parameters must be a JSON object");
    const resolved = await resolveDIDFromLog(tampered, { verifier, witnessProofs: [] });
    expect(resolved.didResolutionMetadata.problemDetails?.detail).toBe("version '2' parameters must be a JSON object");
  });
});
