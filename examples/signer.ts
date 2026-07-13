import { ed25519 } from '@noble/curves/ed25519.js';
import {
  AbstractCrypto,
  createDID,
  MultibaseEncoding,
  multibaseDecode,
  multibaseEncode,
  prepareDataForSigning,
} from 'didwebvh-ts';
import type { Signer, SigningInput, SigningOutput, VerificationMethod, Verifier } from 'didwebvh-ts/types';
import { base58btc } from 'multiformats/bases/base58';

class ExampleCrypto extends AbstractCrypto implements Verifier, Signer {
  constructor(
    public readonly verificationMethod: {
      id: string;
      controller: string;
      type: string;
      publicKeyMultibase: string;
      secretKeyMultibase?: string;
    }
  ) {
    super({ verificationMethod });
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    try {
      if (!this.verificationMethod.secretKeyMultibase) {
        throw new Error('Secret key not found');
      }
      const { bytes: secretKey } = multibaseDecode(this.verificationMethod.secretKeyMultibase);
      // Legacy stablelib secrets are seed||publicKey (64 bytes); noble signs with the 32-byte seed.
      const seed = secretKey.slice(2).slice(0, 32);
      const proof = ed25519.sign(await prepareDataForSigning(input.document, input.proof), seed);
      return {
        proofValue: multibaseEncode(proof, MultibaseEncoding.BASE58_BTC),
      };
    } catch (error) {
      console.error('Ed25519 signing error:', error);
      throw error;
    }
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
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
  const { secretKey, publicKey } = ed25519.keygen();
  return {
    type: 'Multikey',
    publicKeyMultibase: base58btc.encode(new Uint8Array([0xed, 0x01, ...publicKey])),
    secretKeyMultibase: base58btc.encode(new Uint8Array([0x80, 0x26, ...secretKey, ...publicKey])),
    purpose: 'assertionMethod',
  };
}

export const createExampleCrypto = async (vm: VerificationMethod) => {
  return new ExampleCrypto({
    id: `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`,
    controller: `did:key:${vm.publicKeyMultibase}`,
    type: 'Multikey',
    publicKeyMultibase: vm.publicKeyMultibase,
    secretKeyMultibase: vm.secretKeyMultibase,
  });
};

const vm = await generateEd25519VerificationMethod();

const crypto = await createExampleCrypto(vm);

const did = await createDID({
  domain: 'example.com',
  signer: crypto,
  verifier: crypto,
  updateKeys: [`did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`],
  verificationMethods: [vm],
});

console.log(did);
