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

type SigningKey = VerificationMethod & {
  secretKeyMultibase: string;
};

type VerificationMethodInput = VerificationMethod & {
  purpose: 'assertionMethod';
};

type Ed25519KeyMaterial = {
  signingKey: SigningKey;
  verificationMethod: VerificationMethodInput;
};

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

export async function generateEd25519KeyMaterial(): Promise<Ed25519KeyMaterial> {
  const { secretKey, publicKey } = ed25519.keygen();
  const publicKeyMultibase = base58btc.encode(new Uint8Array([0xed, 0x01, ...publicKey]));
  const didKey = `did:key:${publicKeyMultibase}`;

  return {
    signingKey: {
      id: `${didKey}#${publicKeyMultibase}`,
      type: 'Multikey',
      controller: didKey,
      publicKeyMultibase,
      secretKeyMultibase: base58btc.encode(new Uint8Array([0x80, 0x26, ...secretKey, ...publicKey])),
    },
    verificationMethod: {
      id: `{DID}#${publicKeyMultibase.slice(-8)}`,
      type: 'Multikey',
      controller: '{DID}',
      publicKeyMultibase,
      purpose: 'assertionMethod',
    },
  };
}

export const createExampleCrypto = async (vm: SigningKey) => {
  return new ExampleCrypto({
    id: `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}`,
    controller: `did:key:${vm.publicKeyMultibase}`,
    type: 'Multikey',
    publicKeyMultibase: vm.publicKeyMultibase,
    secretKeyMultibase: vm.secretKeyMultibase,
  });
};

const { signingKey, verificationMethod } = await generateEd25519KeyMaterial();
const crypto = await createExampleCrypto(signingKey);

const did = await createDID({
  address: 'example.com',
  signer: crypto,
  verifier: crypto,
  updateKeys: [`did:key:${signingKey.publicKeyMultibase}#${signingKey.publicKeyMultibase}`],
  verificationMethods: [verificationMethod],
});

console.log(did);
