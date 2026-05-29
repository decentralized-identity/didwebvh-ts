/// <reference lib="dom" />
import { sha256 } from '@noble/hashes/sha2';

function arrayBufferToHex(buffer: ArrayBufferLike | Uint8Array): string {
  const view = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  return Array.from(view)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function createHash(data: string): Promise<Uint8Array> {
  return sha256(data);
}

export async function createHashHex(data: string): Promise<string> {
  const hash = await createHash(data);
  const view = new Uint8Array(hash.buffer);
  return arrayBufferToHex(view);
}
