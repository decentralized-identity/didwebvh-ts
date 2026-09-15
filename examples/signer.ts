import { ed25519 } from '@noble/curves/ed25519.js';
import {
  AbstractCrypto,
  createDID,
  MultibaseEncoding,
  multibaseDecode,
  multibaseEncode,
  prepareDataForSigning,
} from 'didwebvh-ts';
import type { DIDDocument, Signer, SigningInput, SigningOutput, Verifier } from 'didwebvh-ts/types';

interface KeyPair {
  publicKeyMultibase: string;
  secretKeyMultibase: string;
}

class ExampleCrypto extends AbstractCrypto implements Verifier, Signer {
  private keyPair: KeyPair;

  constructor(keyPair: KeyPair) {
    const didKey = `did:key:${keyPair.publicKeyMultibase}`;
    super({
      verificationMethod: {
        id: `${didKey}#${keyPair.publicKeyMultibase}`,
        type: 'Multikey',
        controller: didKey,
        publicKeyMultibase: keyPair.publicKeyMultibase,
      },
    });
    this.keyPair = keyPair;
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    try {
      const { bytes: secretKey } = multibaseDecode(this.keyPair.secretKeyMultibase);
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
}

async function generateEd25519KeyPair(): Promise<KeyPair> {
  const { secretKey, publicKey } = ed25519.keygen();
  return {
    publicKeyMultibase: multibaseEncode(new Uint8Array([0xed, 0x01, ...publicKey]), MultibaseEncoding.BASE58_BTC),
    secretKeyMultibase: multibaseEncode(
      new Uint8Array([0x80, 0x26, ...secretKey, ...publicKey]),
      MultibaseEncoding.BASE58_BTC
    ),
  };
}

const keyPair = await generateEd25519KeyPair();
const crypto = new ExampleCrypto(keyPair);

const didDocument: DIDDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: '{DID}',
  verificationMethod: [
    {
      id: '{DID}#key-1',
      type: 'Multikey',
      controller: '{DID}',
      publicKeyMultibase: keyPair.publicKeyMultibase,
    },
  ],
  authentication: ['{DID}#key-1'],
  assertionMethod: ['{DID}#key-1'],
};

const did = await createDID({
  address: 'example.com',
  signer: crypto,
  verifier: crypto,
  updateKeys: [keyPair.publicKeyMultibase],
  didDocument,
});

console.log(did);
