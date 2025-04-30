import { createDocumentSigner, AbstractCrypto, createDID, multibaseDecode, multibaseEncode, MultibaseEncoding, prepareDataForSigning } from 'didwebvh-ts';
import type { Signer, SigningInput, SigningOutput, VerificationMethod, Verifier } from 'didwebvh-ts/types';
import { base58btc } from "multiformats/bases/base58";
import { verify, sign, generateKeyPair } from '@stablelib/ed25519';

class ExampleCrypto extends AbstractCrypto implements Verifier, Signer {
  constructor(public readonly verificationMethod: {
    id: string;
    controller: string;
    type: string;
    publicKeyMultibase: string;
    secretKeyMultibase?: string;
  }) {
    super({ verificationMethod });
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    try {
      if (!this.verificationMethod.secretKeyMultibase) {
        throw new Error('Secret key not found');
      }
      const { bytes: secretKey } = multibaseDecode(this.verificationMethod.secretKeyMultibase);
      const proof = sign(secretKey.slice(2), await prepareDataForSigning(input.document, input.proof));
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

  getVerificationMethodId(): string {
    return this.verificationMethod.id;
  }
}

export async function generateEd25519VerificationMethod(): Promise<VerificationMethod> {
  const { secretKey, publicKey } = generateKeyPair();
  return {
    type: 'Multikey',
    publicKeyMultibase: base58btc.encode(new Uint8Array([0xed, 0x01, ...publicKey])),
    secretKeyMultibase: base58btc.encode(new Uint8Array([0x80, 0x26, ...secretKey])),
    purpose: 'assertionMethod'
  };
}

export const createExampleCrypto = async (vm: VerificationMethod) => {
  return new ExampleCrypto({
    id: `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`,
    controller: `did:key:${vm.publicKeyMultibase}`,
    type: 'Multikey',
    publicKeyMultibase: vm.publicKeyMultibase,
    secretKeyMultibase: vm.secretKeyMultibase
  });
}

const vm = await generateEd25519VerificationMethod();

const crypto = await createExampleCrypto(vm);

const did = await createDID({
  domain: 'example.com',
  signer: crypto,
  verifier: crypto,
  updateKeys: [`did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`],
  verificationMethods: [vm]
})

console.log(did);
