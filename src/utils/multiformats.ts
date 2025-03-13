/**
 * multiformats.ts
 * 
 * This file provides utilities for working with Multibase and Multihash formats
 * as specified in the DID:WebVH method specification.
 */

// ===== MULTIBASE IMPLEMENTATION =====

/**
 * Supported Multibase encoding types
 */
export enum MultibaseEncoding {
  BASE64URL_NO_PAD = 'u',
  BASE58_BTC = 'z'
}

/**
 * Base encoding alphabets
 */
const BASE_ALPHABETS = {
  [MultibaseEncoding.BASE64URL_NO_PAD]: 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_',
  [MultibaseEncoding.BASE58_BTC]: '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
};

/**
 * Encodes binary data using Base64URL (no padding)
 * @param bytes - The binary data to encode
 * @returns The base64url encoded string (without the multibase prefix)
 */
export function encodeBase64Url(bytes: Uint8Array): string {
  // Convert to base64
  const base64 = Buffer.from(bytes).toString('base64');
  // Convert to base64url by replacing + with - and / with _
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Decodes a Base64URL (no padding) string to binary data
 * @param str - The base64url encoded string
 * @returns The decoded binary data
 */
function decodeBase64Url(str: string): Uint8Array {
  // Add padding if necessary
  const padding = str.length % 4 === 0 ? 0 : 4 - (str.length % 4);
  const base64 = str.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat(padding);
  
  // Decode base64 to binary
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

/**
 * Encodes binary data using Base58BTC
 * @param bytes - The binary data to encode
 * @returns The base58btc encoded string (without the multibase prefix)
 */
export function encodeBase58Btc(bytes: Uint8Array): string {
  const ALPHABET = BASE_ALPHABETS[MultibaseEncoding.BASE58_BTC];
  
  // Count leading zeros
  let zeros = 0;
  for (let i = 0; i < bytes.length && bytes[i] === 0; i++) {
    zeros++;
  }
  
  // Convert to a big integer
  let num = 0n;
  for (let i = 0; i < bytes.length; i++) {
    num = num * 256n + BigInt(bytes[i]);
  }
  
  // Convert to base58
  let result = '';
  while (num > 0n) {
    const remainder = Number(num % 58n);
    num = num / 58n;
    result = ALPHABET[remainder] + result;
  }
  
  // Add leading '1's for each leading zero byte
  return '1'.repeat(zeros) + result;
}

/**
 * Decodes a Base58BTC string to binary data
 * @param str - The base58btc encoded string
 * @returns The decoded binary data
 */
export function decodeBase58Btc(str: string): Uint8Array {
  const ALPHABET = BASE_ALPHABETS[MultibaseEncoding.BASE58_BTC];
  
  // Count leading '1's (representing leading zero bytes)
  let zeros = 0;
  for (let i = 0; i < str.length && str[i] === '1'; i++) {
    zeros++;
  }
  
  // Convert from base58 to a big integer
  let num = 0n;
  for (let i = zeros; i < str.length; i++) {
    const char = str[i];
    const value = ALPHABET.indexOf(char);
    if (value === -1) {
      throw new Error(`Invalid Base58 character: ${char}`);
    }
    num = num * 58n + BigInt(value);
  }
  
  // Convert to bytes
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num = num / 256n;
  }
  
  // Add leading zeros
  return new Uint8Array([...new Array(zeros).fill(0), ...bytes]);
}

/**
 * Encodes binary data using the specified multibase encoding
 * @param bytes - The binary data to encode
 * @param encoding - The multibase encoding to use
 * @returns The multibase encoded string (including the prefix)
 */
export function multibaseEncode(bytes: Uint8Array, encoding: MultibaseEncoding = MultibaseEncoding.BASE64URL_NO_PAD): string {
  let encoded: string;
  
  switch (encoding) {
    case MultibaseEncoding.BASE64URL_NO_PAD:
      encoded = encodeBase64Url(bytes);
      break;
    case MultibaseEncoding.BASE58_BTC:
      encoded = encodeBase58Btc(bytes);
      break;
    default:
      throw new Error(`Unsupported multibase encoding: ${encoding}`);
  }
  
  return `${encoding}${encoded}`;
}

/**
 * Decodes a multibase encoded string to binary data
 * @param str - The multibase encoded string
 * @returns The decoded binary data and the encoding used
 */
export function multibaseDecode(str: string): { bytes: Uint8Array, encoding: MultibaseEncoding } {
  if (!str || str.length < 2) {
    throw new Error('Invalid multibase string: too short');
  }
  const prefix = str[0] as MultibaseEncoding;
  const encoded = str.slice(1);
  
  let bytes: Uint8Array;
  
  switch (prefix) {
    case MultibaseEncoding.BASE64URL_NO_PAD:
      bytes = decodeBase64Url(encoded);
      break;
    case MultibaseEncoding.BASE58_BTC:
      bytes = decodeBase58Btc(encoded);
      break;
    default:
      throw new Error(`Unsupported multibase encoding prefix: ${prefix}`);
  }
  
  return { bytes, encoding: prefix };
}

// ===== MULTIHASH IMPLEMENTATION =====

/**
 * Supported Multihash algorithm identifiers
 */
export enum MultihashAlgorithm {
  SHA2_256 = 0x12,
  SHA2_384 = 0x20,
  SHA3_256 = 0x16,
  SHA3_384 = 0x15
}

/**
 * Expected digest lengths for each algorithm (in bytes)
 */
export const DIGEST_LENGTHS = {
  [MultihashAlgorithm.SHA2_256]: 32,
  [MultihashAlgorithm.SHA2_384]: 48,
  [MultihashAlgorithm.SHA3_256]: 32,
  [MultihashAlgorithm.SHA3_384]: 48
};

/**
 * Encodes a varint (variable integer)
 * @param value - The integer to encode
 * @returns The encoded varint as a Uint8Array
 */
function encodeVarint(value: number): Uint8Array {
  const bytes: number[] = [];
  
  while (value >= 0x80) {
    bytes.push((value & 0x7f) | 0x80);
    value >>>= 7;
  }
  
  bytes.push(value & 0x7f);
  
  return new Uint8Array(bytes);
}

/**
 * Decodes a varint (variable integer)
 * @param bytes - The bytes containing the varint
 * @param offset - The starting offset in the bytes array
 * @returns The decoded value and the number of bytes read
 */
function decodeVarint(bytes: Uint8Array, offset = 0): { value: number, bytesRead: number } {
  let value = 0;
  let shift = 0;
  let bytesRead = 0;
  let byte;
  
  do {
    if (offset + bytesRead >= bytes.length) {
      throw new Error('Invalid varint: buffer too short');
    }
    
    byte = bytes[offset + bytesRead];
    value |= (byte & 0x7f) << shift;
    shift += 7;
    bytesRead++;
  } while (byte & 0x80);
  
  return { value, bytesRead };
}

/**
 * Creates a multihash from a digest and algorithm
 * @param digest - The digest bytes
 * @param algorithm - The hash algorithm used
 * @returns The multihash as a Uint8Array
 */
export function createMultihash(digest: Uint8Array, algorithm: MultihashAlgorithm): Uint8Array {
  const expectedLength = DIGEST_LENGTHS[algorithm];
  if (digest.length !== expectedLength) {
    throw new Error(`Invalid digest length for algorithm ${algorithm.toString(16)}: expected ${expectedLength}, got ${digest.length}`);
  }
  
  const algorithmBytes = encodeVarint(algorithm);
  const lengthBytes = encodeVarint(digest.length);
  
  const result = new Uint8Array(algorithmBytes.length + lengthBytes.length + digest.length);
  result.set(algorithmBytes, 0);
  result.set(lengthBytes, algorithmBytes.length);
  result.set(digest, algorithmBytes.length + lengthBytes.length);
  
  return result;
}

/**
 * Decodes a multihash
 * @param bytes - The multihash bytes
 * @returns The decoded multihash components
 */
export function decodeMultihash(bytes: Uint8Array): { 
  algorithm: MultihashAlgorithm, 
  digestLength: number, 
  digest: Uint8Array 
} {
  if (bytes.length < 2) {
    throw new Error('Invalid multihash: too short');
  }
  
  // Decode the algorithm identifier
  const { value: algorithm, bytesRead: algorithmBytesRead } = decodeVarint(bytes, 0);
  
  // Decode the digest length
  const { value: digestLength, bytesRead: lengthBytesRead } = decodeVarint(bytes, algorithmBytesRead);
  
  // Extract the digest
  const offset = algorithmBytesRead + lengthBytesRead;
  if (bytes.length - offset < digestLength) {
    throw new Error(`Invalid multihash: digest too short, expected ${digestLength} bytes`);
  }
  
  const digest = bytes.slice(offset, offset + digestLength);
  
  // Verify the algorithm is supported
  if (!Object.values(MultihashAlgorithm).includes(algorithm)) {
    throw new Error(`Unsupported multihash algorithm: 0x${algorithm.toString(16)}`);
  }
  
  // Verify the digest length matches the expected length for the algorithm
  const expectedLength = DIGEST_LENGTHS[algorithm as MultihashAlgorithm];
  if (digestLength !== expectedLength) {
    throw new Error(`Invalid digest length for algorithm 0x${algorithm.toString(16)}: expected ${expectedLength}, got ${digestLength}`);
  }
  
  return {
    algorithm: algorithm as MultihashAlgorithm,
    digestLength,
    digest
  };
}

/**
 * Encodes a multihash using multibase encoding
 * @param multihash - The multihash bytes
 * @param encoding - The multibase encoding to use
 * @returns The multibase encoded multihash
 */
export function encodeMultihashWithMultibase(
  multihash: Uint8Array, 
  encoding: MultibaseEncoding = MultibaseEncoding.BASE64URL_NO_PAD
): string {
  return multibaseEncode(multihash, encoding);
}

/**
 * Decodes a multibase encoded multihash
 * @param str - The multibase encoded multihash
 * @returns The decoded multihash components and the encoding used
 */
export function decodeMultihashFromMultibase(str: string): {
  algorithm: MultihashAlgorithm,
  digestLength: number,
  digest: Uint8Array,
  encoding: MultibaseEncoding
} {
  const { bytes, encoding } = multibaseDecode(str);
  const multihash = decodeMultihash(bytes);
  
  return {
    ...multihash,
    encoding
  };
} 