import { afterEach, describe, expect, test } from 'vitest';
import {
  config,
  decodeVerificationMethods,
  encodeVerificationMethods,
  getVerificationMethodsFromEnv,
} from '../src/config';
import type { VerificationMethod } from '../src/interfaces';

const originalDidVerificationMethods = process.env.DID_VERIFICATION_METHODS;

afterEach(() => {
  if (originalDidVerificationMethods === undefined) {
    delete process.env.DID_VERIFICATION_METHODS;
  } else {
    process.env.DID_VERIFICATION_METHODS = originalDidVerificationMethods;
  }
});

describe('config verification-method helpers', () => {
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

  test('returns empty array for missing env value', () => {
    expect(getVerificationMethodsFromEnv(undefined)).toEqual([]);
  });

  test('reads verification methods from DID_VERIFICATION_METHODS env', () => {
    const methods: VerificationMethod[] = [
      {
        id: 'did:webvh:ghi:example.com#k3',
        type: 'Multikey',
        controller: 'did:webvh:ghi:example.com',
        publicKeyMultibase: 'z6Mkmn...',
      },
    ];

    process.env.DID_VERIFICATION_METHODS = encodeVerificationMethods(methods);

    expect(config.getVerificationMethods()).toEqual(methods);
  });

  test('returns empty array when DID_VERIFICATION_METHODS is invalid', () => {
    process.env.DID_VERIFICATION_METHODS = 'bad-value';

    expect(config.getVerificationMethods()).toEqual([]);
  });
});
