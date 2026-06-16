import { describe, expect, test } from 'bun:test';
import {
  createMultihash,
  decodeBase58Btc,
  decodeMultihash,
  decodeMultihashFromMultibase,
  encodeBase58Btc,
  encodeMultihashWithMultibase,
  MultibaseEncoding,
  MultihashAlgorithm,
  multibaseDecode,
  multibaseEncode,
} from '../src/utils/multiformats';

describe('base58btc', () => {
  test('round-trips binary data, preserving leading zero bytes', () => {
    const bytes = new Uint8Array([0, 0, 1, 2, 3, 255]);
    const encoded = encodeBase58Btc(bytes);
    expect(encoded.startsWith('11')).toBe(true);
    expect(decodeBase58Btc(encoded)).toEqual(bytes);
  });

  test('rejects characters outside the base58 alphabet', () => {
    expect(() => decodeBase58Btc('abc0def')).toThrow('Invalid Base58 character: 0');
    expect(() => decodeBase58Btc('abcOdef')).toThrow('Invalid Base58 character: O');
  });
});

describe('multibase', () => {
  const bytes = new Uint8Array([104, 101, 108, 108, 111]);

  test('round-trips with the base58btc encoding', () => {
    const encoded = multibaseEncode(bytes, MultibaseEncoding.BASE58_BTC);
    expect(encoded[0]).toBe('z');
    expect(multibaseDecode(encoded)).toEqual({ bytes, encoding: MultibaseEncoding.BASE58_BTC });
  });

  test('round-trips with the base64url encoding', () => {
    const encoded = multibaseEncode(bytes, MultibaseEncoding.BASE64URL_NO_PAD);
    expect(encoded[0]).toBe('u');
    expect(multibaseDecode(encoded)).toEqual({ bytes, encoding: MultibaseEncoding.BASE64URL_NO_PAD });
  });

  test('rejects strings that are too short', () => {
    expect(() => multibaseDecode('')).toThrow('too short');
    expect(() => multibaseDecode('z')).toThrow('too short');
  });

  test('rejects unsupported encoding prefixes', () => {
    expect(() => multibaseDecode('xabc')).toThrow('Unsupported multibase encoding prefix: x');
    expect(() => multibaseEncode(bytes, 'q' as MultibaseEncoding)).toThrow('Unsupported multibase encoding: q');
  });
});

describe('multihash', () => {
  const sha256Digest = new Uint8Array(32).fill(7);

  test('round-trips a sha2-256 digest', () => {
    const multihash = createMultihash(sha256Digest, MultihashAlgorithm.SHA2_256);
    expect(decodeMultihash(multihash)).toEqual({
      algorithm: MultihashAlgorithm.SHA2_256,
      digestLength: 32,
      digest: sha256Digest,
    });
  });

  test('round-trips through multibase encoding', () => {
    const multihash = createMultihash(sha256Digest, MultihashAlgorithm.SHA2_256);
    for (const encoding of [MultibaseEncoding.BASE58_BTC, MultibaseEncoding.BASE64URL_NO_PAD]) {
      const encoded = encodeMultihashWithMultibase(multihash, encoding);
      expect(decodeMultihashFromMultibase(encoded)).toEqual({
        algorithm: MultihashAlgorithm.SHA2_256,
        digestLength: 32,
        digest: sha256Digest,
        encoding,
      });
    }
  });

  test('rejects creation with a digest of the wrong length', () => {
    expect(() => createMultihash(new Uint8Array(16), MultihashAlgorithm.SHA2_256)).toThrow('Invalid digest length');
  });

  test('rejects multihashes that are too short', () => {
    expect(() => decodeMultihash(new Uint8Array([0x12]))).toThrow('too short');
  });

  test('rejects truncated varints', () => {
    expect(() => decodeMultihash(new Uint8Array([0xff, 0xff]))).toThrow('Invalid varint: buffer too short');
  });

  test('rejects truncated digests', () => {
    const multihash = createMultihash(sha256Digest, MultihashAlgorithm.SHA2_256);
    expect(() => decodeMultihash(multihash.slice(0, 10))).toThrow('digest too short');
  });

  test('rejects unsupported algorithms', () => {
    expect(() => decodeMultihash(new Uint8Array([0x13, 0x02, 0xaa, 0xbb]))).toThrow(
      'Unsupported multihash algorithm: 0x13'
    );
  });

  test('rejects digests whose length does not match the algorithm', () => {
    expect(() => decodeMultihash(new Uint8Array([0x12, 0x02, 0xaa, 0xbb]))).toThrow(
      'Invalid digest length for algorithm 0x12: expected 32, got 2'
    );
  });
});
