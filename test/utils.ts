import * as crypto from '@stablelib/ed25519';
import { METHOD, PLACEHOLDER } from '../src/constants';
import { AbstractCrypto, prepareDataForSigning } from '../src/cryptography';
import type {
  DIDLog,
  DIDLogEntry,
  Signer,
  SignerOptions,
  SigningInput,
  SigningOutput,
  VerificationMethod,
  Verifier,
} from '../src/interfaces';
import { createDIDDoc, createSCID, deriveHash, replaceCreateDidPlaceholders } from '../src/utils';
import { MultibaseEncoding, multibaseDecode, multibaseEncode } from '../src/utils/multiformats';

export function createMockDIDLog(entries: Partial<DIDLogEntry>[]): DIDLog {
  return entries.map((entry, index) => {
    const versionNumber = index + 1;
    const mockEntry: DIDLogEntry = {
      versionId: entry.versionId || `${versionNumber}-${deriveHash(entry)}`,
      versionTime: entry.versionTime || new Date().toISOString(),
      parameters: entry.parameters || {},
      state: entry.state || {},
      proof: entry.proof || [],
    };
    return mockEntry;
  });
}

export const createFutureDIDLog = async (authKey: VerificationMethod, minutesAhead: number): Promise<DIDLog> => {
  const futureCreated = new Date(Date.now() + minutesAhead * 60 * 1000).toISOString();
  const signer = createTestSigner(authKey);
  const controller = `did:${METHOD}:${PLACEHOLDER}:example.com`;

  const { doc } = await createDIDDoc({
    controller,
    verificationMethods: asPublicVerificationMethods(authKey),
    signer,
    updateKeys: [authKey.publicKeyMultibase!],
  });

  const initialLogEntry: DIDLog[0] = {
    versionId: PLACEHOLDER,
    versionTime: futureCreated,
    parameters: {
      method: `did:${METHOD}:1.0`,
      scid: PLACEHOLDER,
      updateKeys: [authKey.publicKeyMultibase!],
      portable: false,
      nextKeyHashes: [],
      watchers: [],
      witness: {},
      deactivated: false,
    },
    state: doc,
  };

  const initialLogEntryHash = await deriveHash(initialLogEntry);
  const scid = await createSCID(initialLogEntryHash);
  const did = `did:${METHOD}:${scid}:example.com`;
  const prelimEntry = replaceCreateDidPlaceholders(initialLogEntry, scid, did);
  const logEntryHash2 = await deriveHash(prelimEntry);
  prelimEntry.versionId = `1-${logEntryHash2}`;

  const proofTemplate = {
    type: 'DataIntegrityProof' as const,
    cryptosuite: 'eddsa-jcs-2022' as const,
    verificationMethod: signer.getVerificationMethodId(),
    created: futureCreated,
    proofPurpose: 'assertionMethod' as const,
  };
  const signedProof = await signer.sign({ document: prelimEntry, proof: proofTemplate });
  prelimEntry.proof = [{ ...proofTemplate, proofValue: signedProof.proofValue }];

  return [prelimEntry];
};

// Test crypto implementation
export class TestCryptoImplementation extends AbstractCrypto implements Verifier {
  private keyPair: { publicKey: Uint8Array; secretKey: Uint8Array };

  constructor(options: SignerOptions) {
    super(options);
    // For tests, we'll generate a deterministic key if none provided
    if (!options.verificationMethod?.secretKeyMultibase) {
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
export async function generateTestVerificationMethod(
  purpose:
    | 'authentication'
    | 'assertionMethod'
    | 'keyAgreement'
    | 'capabilityInvocation'
    | 'capabilityDelegation' = 'authentication',
  id?: string
): Promise<VerificationMethod> {
  const keyPair = crypto.generateKeyPair();
  const secretKey = multibaseEncode(new Uint8Array([0x80, 0x26, ...keyPair.secretKey]), MultibaseEncoding.BASE58_BTC);
  const publicKey = multibaseEncode(new Uint8Array([0xed, 0x01, ...keyPair.publicKey]), MultibaseEncoding.BASE58_BTC);
  return {
    id,
    type: 'Multikey',
    publicKeyMultibase: publicKey,
    secretKeyMultibase: secretKey,
    purpose,
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

// Helper to produce DID document-safe verification methods by stripping secret key material
export function asPublicVerificationMethods(...verificationMethods: VerificationMethod[]): VerificationMethod[] {
  return verificationMethods.map((verificationMethod) => {
    const { secretKeyMultibase, ...publicVerificationMethod } = verificationMethod;
    return publicVerificationMethod;
  });
}
