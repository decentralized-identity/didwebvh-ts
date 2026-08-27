import { describe, expect, test } from 'vitest';
import {
  decodeVerificationMethods,
  encodeVerificationMethods,
  getVerificationMethodsFromEnv,
} from '../src/cli/persistence';
import type { VerificationMethod } from '../src/interfaces';

describe('CLI verification-method persistence helpers', () => {
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
    await expect(getVerificationMethodsFromEnv({ env: {}, cwd: '/tmp/didwebvh-missing-config' })).resolves.toEqual([]);
  });

  test('reads verification methods from DID_VERIFICATION_METHODS env', async () => {
    const methods: VerificationMethod[] = [
      {
        id: 'did:webvh:ghi:example.com#k3',
        type: 'Multikey',
        controller: 'did:webvh:ghi:example.com',
        publicKeyMultibase: 'z6Mkmn...',
      },
    ];

    await expect(
      getVerificationMethodsFromEnv({ env: { DID_VERIFICATION_METHODS: encodeVerificationMethods(methods) } })
    ).resolves.toEqual(methods);
  });

  test('returns empty array when DID_VERIFICATION_METHODS is invalid', async () => {
    await expect(getVerificationMethodsFromEnv({ env: { DID_VERIFICATION_METHODS: 'bad-value' } })).resolves.toEqual(
      []
    );
  });
});
