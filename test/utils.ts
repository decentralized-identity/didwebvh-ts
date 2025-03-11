import { deriveHash } from '../src/utils';
import type { DIDLogEntry, DIDLog } from '../src/interfaces';
import { base58btc } from "multiformats/bases/base58";
import { AbstractSigner, createDocumentSigner } from "../src/cryptography";
import { SigningInput, SigningOutput, SignerOptions, Verifier, VerificationMethod, Signer } from "../src/interfaces";
import * as crypto from '@stablelib/ed25519'; // Using stablelib for test implementation
import { prepareDataForSigning } from '../src/cryptography';

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
      const secretKey = base58btc.decode(options.verificationMethod.secretKeyMultibase).slice(2);
      const publicKey = base58btc.decode(options.verificationMethod.publicKeyMultibase!).slice(2);
      this.keyPair = { publicKey, secretKey };
    }
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    const signature = crypto.sign(this.keyPair.secretKey, dataToSign);
    return { proofValue: base58btc.encode(signature) };
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
  
  // Add the ed25519 multikey header (0xed01)
  const publicKeyBytes = new Uint8Array([0xed, 0x01, ...keyPair.publicKey]);
  const secretKeyBytes = new Uint8Array([0xed, 0x01, ...keyPair.secretKey]);
  
  return {
    type: 'Multikey',
    publicKeyMultibase: base58btc.encode(publicKeyBytes),
    secretKeyMultibase: base58btc.encode(secretKeyBytes),
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