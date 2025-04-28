import { AbstractCrypto, multibaseDecode, multibaseEncode, MultibaseEncoding } from 'didwebvh-ts';
import type { Signer, SigningInput, SigningOutput, Verifier } from 'didwebvh-ts/types';

import { verify, sign } from '@stablelib/ed25519';

class ExampleCrypto extends AbstractCrypto implements Verifier, Signer {
  constructor(public readonly verificationMethod: {
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
    secretKeyMultibase: string;
  }) {
    super({ verificationMethod });
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    try {
      const { bytes: secretKey } = multibaseDecode(this.verificationMethod.secretKeyMultibase);
      const proof = sign(secretKey, input.document.proof.proofValue);
      return {
        proofValue: multibaseEncode(proof, MultibaseEncoding.BASE58_BTC)
      };
    } catch (error) {
      console.error('Ed25519 signing error:', error);
      throw error;
    }
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return verify(publicKey, message, signature);
    } catch (error) {
      console.error('Ed25519 verification error:', error);
      return false;
    }
  }
}

export const createExampleCrypto = () => {
  return new ExampleCrypto({
    id: 'did:example:123#key-1',
    controller: 'did:example:123',
    type: 'Ed25519VerificationKey2020',
    publicKeyMultibase: `z123`,
    secretKeyMultibase: `z123`
  });
};
