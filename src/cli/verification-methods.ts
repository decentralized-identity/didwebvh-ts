import { multibaseDecode } from '../index.js';

export function parseDidKeyDid(input: string): { did: string; keyMultibase: string } {
  if (typeof input !== 'string') {
    throw new Error('did:key DID must be a string');
  }

  const match = input.match(/^did:key:([^#/?]+)$/);
  if (!match) {
    throw new Error('Malformed did:key DID');
  }

  const keyMultibase = match[1];
  try {
    multibaseDecode(keyMultibase);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Malformed did:key identifier: ${message}`);
  }

  return {
    did: `did:key:${keyMultibase}`,
    keyMultibase,
  };
}
