/// <reference lib="dom" />
import { sha256 } from '@noble/hashes/sha2.js';
import { canonicalizeStrict } from './canonicalize';
import { createMultihash, encodeBase58Btc, MultihashAlgorithm } from './multiformats';

const encoder = new TextEncoder();

function arrayBufferToHex(buffer: ArrayBufferLike | Uint8Array): string {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function createHash(data: string): Promise<Uint8Array> {
  return sha256(encoder.encode(data));
}

export async function createHashHex(data: string): Promise<string> {
  const hash = await createHash(data);
  const view = new Uint8Array(hash.buffer);
  return arrayBufferToHex(view);
}

export const createSCID = async (logEntryHash: string): Promise<string> => {
  return logEntryHash;
};

// Cache for deriveHash operations to avoid redundant computation
const hashCache = new Map<string, string>();

// Input must be strict JSON-compatible and must not contain explicit undefined values.
export async function deriveHash(input: unknown): Promise<string> {
  let cacheKey: string | undefined;

  try {
    cacheKey = JSON.stringify(input);
    const cached = hashCache.get(cacheKey);
    if (cached) {
      return cached;
    }
  } catch {
    cacheKey = undefined;
  }

  const data = canonicalizeStrict(input);
  const hash = await createHash(data);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  const result = encodeBase58Btc(multihash);

  if (cacheKey !== undefined) {
    hashCache.set(cacheKey, result);
  }

  return result;
}

export const deriveNextKeyHash = async (input: string): Promise<string> => {
  const hash = await createHash(input);
  const multihash = createMultihash(new Uint8Array(hash), MultihashAlgorithm.SHA2_256);
  return encodeBase58Btc(multihash);
};
