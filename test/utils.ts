import { deriveHash } from '../src/utils';
import type { DIDLogEntry, DIDLog } from '../src/interfaces';
import { AbstractSigner, createDocumentSigner } from "../src/cryptography";
import { SigningInput, SigningOutput, SignerOptions, Verifier, VerificationMethod, Signer } from "../src/interfaces";
import * as crypto from '@stablelib/ed25519'; // Using stablelib for test implementation
import { prepareDataForSigning } from '../src/cryptography';
import { multibaseDecode, multibaseEncode, MultibaseEncoding } from '../src/utils/multiformats';

export function createMockDIDLog(entries: Partial<DIDLogEntry>[]): DIDLog {
  return entries.map((entry, index) => {
    const versionNumber = index + 1;
    const mockEntry: DIDLogEntry = {
      versionId: entry.versionId || `${versionNumber}-${deriveHash(entry)}`,
      versionTime: entry.versionTime || new Date().toISOString(),
      parameters: entry.parameters || {},
      state: entry.state || {},
      proof: entry.proof || []
    };
    return mockEntry;
  });
}

// Test crypto implementation
export class TestCryptoImplementation extends AbstractSigner implements Verifier {
  private keyPair: { publicKey: Uint8Array; secretKey: Uint8Array };

  constructor(options: SignerOptions) {
    super(options);
    // For tests, we'll generate a deterministic key if none provided
    if (!options.verificationMethod.secretKeyMultibase) {
      const keyPair = crypto.generateKeyPair();
      this.keyPair = keyPair;
    } else {
      const secretKey = multibaseDecode(options.verificationMethod.secretKeyMultibase).bytes;
      const publicKey = multibaseDecode(options.verificationMethod.publicKeyMultibase!).bytes;
      this.keyPair = { publicKey, secretKey };
    }
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    const signature = crypto.sign(this.keyPair.secretKey.slice(2), dataToSign);
    return { proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC) };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return crypto.verify(publicKey, message, signature);
    } catch (error) {
      console.error('Error verifying signature:', error);
      return false;
    }
  }
}

// Test implementation that always fails verification
export class MockFailingImplementation extends TestCryptoImplementation {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return false;
  }
}

// Helper to generate verification method for tests
export async function generateTestVerificationMethod(purpose: "authentication" | "assertionMethod" | "keyAgreement" | "capabilityInvocation" | "capabilityDelegation" = 'authentication'): Promise<VerificationMethod> {
  const keyPair = crypto.generateKeyPair();
  const secretKey = multibaseEncode(new Uint8Array([0x80, 0x26, ...keyPair.secretKey]), MultibaseEncoding.BASE58_BTC);
  const publicKey = multibaseEncode(new Uint8Array([0xed, 0x01, ...keyPair.publicKey]), MultibaseEncoding.BASE58_BTC);
  return {
    type: 'Multikey',
    publicKeyMultibase: publicKey,
    secretKeyMultibase: secretKey,
    purpose
  };
}

// Helper to create a signer from a verification method
export function createTestSigner(verificationMethod: VerificationMethod): Signer {
  return new TestCryptoImplementation({ verificationMethod });
}

// Helper to create a test verifier
export function createTestVerifier(verificationMethod: VerificationMethod): Verifier {
  return new TestCryptoImplementation({ verificationMethod });
}