import { ed25519 } from '@noble/curves/ed25519.js';
import type { Verifier } from './interfaces';

/**
 * Built-in Ed25519 verifier. did:webvh proofs are always `eddsa-jcs-2022`
 * (Ed25519), so this lets `getResolver()` and the public resolvers work
 * with zero configuration. The public key handed in is the raw 32-byte
 * Ed25519 key (the multicodec `0xed01` prefix is stripped by the caller).
 *
 * `zip215: false` selects strict RFC 8032 verification (canonical encodings,
 * small-order point rejection) to match didwebvh-py, which verifies via
 * ed25519-dalek's `verify_strict` — implementations must agree on log validity.
 */
export const defaultVerifier: Verifier = {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch {
      return false;
    }
  },
};
