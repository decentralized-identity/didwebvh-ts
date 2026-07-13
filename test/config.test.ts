import { afterEach, describe, expect, test } from 'bun:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  decodeVerificationMethods,
  encodeVerificationMethods,
  getVerificationMethodsFromEnv,
} from '../src/cli/persistence';
import type { VerificationMethod } from '../src/interfaces';

const originalDidVerificationMethods = process.env.DID_VERIFICATION_METHODS;

afterEach(() => {
  if (originalDidVerificationMethods === undefined) {
    delete process.env.DID_VERIFICATION_METHODS;
  } else {
    process.env.DID_VERIFICATION_METHODS = originalDidVerificationMethods;
  }
});

describe('cli verification-method helpers', () => {
  test('round-trips verification methods via encode/decode', () => {
    const methods: VerificationMethod[] = [
      {
        id: 'did:webvh:abc:example.com#k1',
        type: 'Multikey',
        controller: 'did:webvh:abc:example.com',
        publicKeyMultibase: 'z6MkhQ...',
      },
      {
        id: 'did:webvh:def:example.com#k2',
        type: 'Multikey',
        controller: 'did:webvh:def:example.com',
        publicKeyMultibase: 'z6Mks9...',
      },
    ];

    const encoded = encodeVerificationMethods(methods);
    const decoded = decodeVerificationMethods(encoded);

    expect(decoded).toEqual(methods);
  });

  test('returns empty array for invalid encoded content', () => {
    expect(decodeVerificationMethods('not-base64')).toEqual([]);
  });

  test('returns empty array when decoded JSON is not an array', () => {
    const encodedObject = btoa(JSON.stringify({ foo: 'bar' }));
    expect(decodeVerificationMethods(encodedObject)).toEqual([]);
  });

  test('returns empty array for missing env value', async () => {
    const isolatedCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'didwebvh-cli-config-test-'));
    expect(await getVerificationMethodsFromEnv({ cwd: isolatedCwd, env: {} })).toEqual([]);
  });

  test('decodes verification methods from DID_VERIFICATION_METHODS env value', async () => {
    const methods: VerificationMethod[] = [
      {
        id: 'did:webvh:ghi:example.com#k3',
        type: 'Multikey',
        controller: 'did:webvh:ghi:example.com',
        publicKeyMultibase: 'z6Mkmn...',
      },
    ];

    process.env.DID_VERIFICATION_METHODS = encodeVerificationMethods(methods);

    expect(await getVerificationMethodsFromEnv()).toEqual(methods);
  });

  test('returns empty array when DID_VERIFICATION_METHODS env value is invalid', async () => {
    const isolatedCwd = fs.mkdtempSync(path.join(os.tmpdir(), 'didwebvh-cli-config-test-'));
    const invalidEnv = { DID_VERIFICATION_METHODS: 'bad-value' };

    expect(await getVerificationMethodsFromEnv({ cwd: isolatedCwd, env: invalidEnv })).toEqual([]);
  });
});
