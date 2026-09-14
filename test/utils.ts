import { ed25519 } from '@noble/curves/ed25519.js';
import {
  DID_PLACEHOLDER,
  METHOD,
  METHOD_PARAMETER_KEYS,
  METHOD_PROTOCOL_V0_5,
  SCID_PLACEHOLDER,
} from '../src/constants.js';
import { AbstractCrypto, prepareDataForSigning } from '../src/cryptography.js';
import { replaceCreateDidPlaceholders } from '../src/did-document.js';
import type {
  DIDDocument,
  DIDLog,
  DIDLogEntry,
  Service,
  Signer,
  SignerOptions,
  SigningInput,
  SigningOutput,
  VerificationMethod,
  Verifier,
  WitnessParameter,
} from '../src/interfaces.js';
import { createSCID, deriveHash } from '../src/utils/crypto.js';
import { createDate, createNextVersionTime } from '../src/utils/iso8601-datetime.js';
import { MultibaseEncoding, multibaseDecode, multibaseEncode } from '../src/utils/multiformats.js';
import { deepClone, normalizeDidAddress, replaceValueInObject } from '../src/utils.js';

export type TestVerificationMethod = VerificationMethod & {
  secretKeyMultibase: string;
};

export function createTestDIDDocument(
  authKey: TestVerificationMethod | string,
  options: {
    keyId?: string;
    relationships?: Array<
      'authentication' | 'assertionMethod' | 'keyAgreement' | 'capabilityInvocation' | 'capabilityDelegation'
    >;
    controller?: string;
    services?: Service[];
    alsoKnownAs?: string[];
  } = {}
): DIDDocument {
  const publicKeyMultibase = typeof authKey === 'string' ? authKey : authKey.publicKeyMultibase!;
  const keyId = options.keyId ?? `{DID}#${publicKeyMultibase.slice(-8)}`;
  const relationships = options.relationships ?? ['authentication', 'assertionMethod'];
  const doc: DIDDocument = {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id: '{DID}',
    verificationMethod: [
      {
        id: keyId,
        type: 'Multikey',
        controller: '{DID}',
        publicKeyMultibase,
      },
    ],
  };
  if (options.controller) {
    doc.controller = options.controller;
  }
  for (const rel of relationships) {
    doc[rel] = [keyId];
  }
  if (options.services) {
    doc.service = options.services;
  }
  if (options.alsoKnownAs) {
    doc.alsoKnownAs = options.alsoKnownAs;
  }
  return doc;
}

export const createFutureDIDLog = async (authKey: TestVerificationMethod, minutesAhead: number): Promise<DIDLog> => {
  const futureCreated = new Date(Date.now() + minutesAhead * 60 * 1000).toISOString();
  const signer = createTestSigner(authKey);
  const rawDoc = createTestDIDDocument(authKey);
  const genesisDid = `did:${METHOD}:${SCID_PLACEHOLDER}:example.com`;
  const doc = replaceValueInObject(deepClone(rawDoc), DID_PLACEHOLDER, genesisDid) as DIDDocument;

  const initialLogEntry: DIDLog[0] = {
    versionId: SCID_PLACEHOLDER,
    versionTime: futureCreated,
    parameters: {
      method: `did:${METHOD}:1.0`,
      scid: SCID_PLACEHOLDER,
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
  private keyPair: { publicKey: Uint8Array; seed: Uint8Array };

  constructor(options: SignerOptions & { verificationMethod: TestVerificationMethod }) {
    super(options);
    if (!options.verificationMethod?.secretKeyMultibase || !options.verificationMethod.publicKeyMultibase) {
      throw new Error('TestCryptoImplementation requires secret and public multibase keys');
    }

    // Multicodec-prefixed (2 bytes); the secret is seed||publicKey (64 bytes) or a bare seed.
    const secretKey = multibaseDecode(options.verificationMethod.secretKeyMultibase).bytes.slice(2);
    const publicKey = multibaseDecode(options.verificationMethod.publicKeyMultibase).bytes.slice(2);
    this.keyPair = { publicKey, seed: secretKey.slice(0, 32) };
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    const signature = ed25519.sign(dataToSign, this.keyPair.seed);
    return { proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC) };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      return ed25519.verify(signature, message, publicKey, { zip215: false });
    } catch (error) {
      console.error('Error verifying signature:', error);
      return false;
    }
  }
}

// Helper to generate verification method for tests
export async function generateTestVerificationMethod(id?: string): Promise<TestVerificationMethod> {
  const keyPair = ed25519.keygen();
  // seed||publicKey (64 bytes) matches the legacy @stablelib/ed25519 secret layout.
  const secretKey = multibaseEncode(
    new Uint8Array([0x80, 0x26, ...keyPair.secretKey, ...keyPair.publicKey]),
    MultibaseEncoding.BASE58_BTC
  );
  const publicKey = multibaseEncode(new Uint8Array([0xed, 0x01, ...keyPair.publicKey]), MultibaseEncoding.BASE58_BTC);
  return {
    id: id ?? `{DID}#${publicKey.slice(-8)}`,
    type: 'Multikey',
    controller: '{DID}',
    publicKeyMultibase: publicKey,
    secretKeyMultibase: secretKey,
  };
}

// Helper to create a signer from a verification method
export function createTestSigner(verificationMethod: TestVerificationMethod): Signer {
  return new TestCryptoImplementation({ verificationMethod });
}

// Helper to create a test verifier
export function createTestVerifier(verificationMethod: TestVerificationMethod): Verifier {
  return new TestCryptoImplementation({ verificationMethod });
}

// Helper to produce DID document-safe verification methods by stripping secret key material
export function asPublicVerificationMethods(...verificationMethods: TestVerificationMethod[]): VerificationMethod[] {
  return verificationMethods.map((verificationMethod) => {
    return {
      id: verificationMethod.id,
      type: verificationMethod.type,
      controller: verificationMethod.controller,
      publicKeyMultibase: verificationMethod.publicKeyMultibase,
    };
  });
}

// Helper to construct a v0.5 genesis entry using the same algorithm as v1.0 createDID
export async function buildV05Genesis(options: {
  address: string;
  signer: Signer;
  updateKeys: string[];
  didDocument?: DIDDocument;
  verificationMethods?: VerificationMethod[];
  nextKeyHashes?: string[] | null;
  portable?: boolean;
  witness?: WitnessParameter | null;
  versionTime?: string;
  verifier: Verifier;
}): Promise<DIDLog> {
  const now = options.versionTime ?? new Date().toISOString();
  const normalizedAddress = normalizeDidAddress({
    address: options.address,
    scid: SCID_PLACEHOLDER,
    paths: undefined,
    context: 'buildV05Genesis',
  });

  const rawDoc: DIDDocument =
    options.didDocument ??
    (options.verificationMethods && options.verificationMethods.length > 0
      ? {
          '@context': ['https://www.w3.org/ns/did/v1'],
          id: normalizedAddress.did,
          controller: normalizedAddress.did,
          verificationMethod: options.verificationMethods.map((vm) => ({
            ...vm,
            id: vm.id.replaceAll('{DID}', normalizedAddress.did),
            controller: (vm.controller ?? normalizedAddress.did).replaceAll('{DID}', normalizedAddress.did),
          })),
          authentication: options.verificationMethods.map((vm) => vm.id.replaceAll('{DID}', normalizedAddress.did)),
          assertionMethod: options.verificationMethods.map((vm) => vm.id.replaceAll('{DID}', normalizedAddress.did)),
        }
      : createTestDIDDocument(options.updateKeys[0]));

  const doc = replaceValueInObject(deepClone(rawDoc), DID_PLACEHOLDER, normalizedAddress.did) as DIDDocument;

  const initialLogEntry: DIDLogEntry = {
    versionId: SCID_PLACEHOLDER,
    versionTime: now,
    // v0.5 spec uses null (not undefined/[]) to represent inactive nextKeyHashes
    parameters: {
      method: METHOD_PROTOCOL_V0_5,
      scid: SCID_PLACEHOLDER,
      updateKeys: options.updateKeys,
      portable: options.portable ?? false,
      nextKeyHashes: options.nextKeyHashes ?? null,
      watchers: [],
      witness: options.witness ?? {},
      deactivated: false,
    } as DIDLogEntry['parameters'],
    state: doc,
  };

  const initialLogEntryHash = await deriveHash(initialLogEntry);
  const scid = await createSCID(initialLogEntryHash);
  const did = `did:${METHOD}:${scid}:${normalizedAddress.locationKey}`;
  const prelimEntry = replaceCreateDidPlaceholders(initialLogEntry, scid, did);
  const logEntryHash2 = await deriveHash(prelimEntry);
  prelimEntry.versionId = `1-${logEntryHash2}`;

  const proofTemplate = {
    type: 'DataIntegrityProof' as const,
    cryptosuite: 'eddsa-jcs-2022' as const,
    verificationMethod: options.signer.getVerificationMethodId(),
    created: now,
    proofPurpose: 'assertionMethod' as const,
  };

  const signedProof = await options.signer.sign({ document: prelimEntry, proof: proofTemplate });
  prelimEntry.proof = [{ ...proofTemplate, proofValue: signedProof.proofValue }];

  return [prelimEntry];
}

// Helper to append a spec-compliant signed v0.5 entry to an existing log.
// Pass an explicit versionTime for deterministic fixtures; it must be strictly greater than
// the previous entry's versionTime.
export async function appendV05LogEntry(options: {
  log: DIDLog;
  signer: Signer;
  updateKeys?: string[];
  nextKeyHashes?: string[] | null;
  method?: string;
  didDocument?: DIDDocument;
  verificationMethods?: VerificationMethod[];
  versionTime?: string;
  verifier: Verifier;
}): Promise<DIDLog> {
  const previousEntry = options.log[options.log.length - 1];
  const versionNumber = options.log.length + 1;
  const nextVersionTime = createNextVersionTime(previousEntry.versionTime, options.versionTime, createDate);
  const did = previousEntry.state.id!;
  const scid = did.split(':')[2];

  // Build the new state doc (reuse previous state if no new document provided)
  let newState: DIDDocument;
  if (options.didDocument) {
    newState = replaceCreateDidPlaceholders(deepClone(options.didDocument), scid, did);
  } else if (options.verificationMethods && options.verificationMethods.length > 0) {
    newState = {
      ...deepClone(previousEntry.state),
      verificationMethod: options.verificationMethods.map((vm) => ({
        ...vm,
        id: vm.id.replaceAll('{DID}', did),
        controller: (vm.controller ?? did).replaceAll('{DID}', did),
      })),
      authentication: options.verificationMethods.map((vm) => vm.id.replaceAll('{DID}', did)),
      assertionMethod: options.verificationMethods.map((vm) => vm.id.replaceAll('{DID}', did)),
    };
  } else {
    newState = deepClone(previousEntry.state);
  }

  // Build parameters object with only explicitly provided keys
  // Note: SCID is NEVER included in non-genesis entries
  const newParameters: Record<string, unknown> = {};

  if (options.method !== undefined) {
    newParameters[METHOD_PARAMETER_KEYS.method] = options.method;
  }
  if (options.updateKeys !== undefined) {
    newParameters[METHOD_PARAMETER_KEYS.updateKeys] = options.updateKeys;
  }
  if (options.nextKeyHashes !== undefined) {
    newParameters[METHOD_PARAMETER_KEYS.nextKeyHashes] = options.nextKeyHashes;
  }

  // For non-genesis entries, only include parameters that are explicitly set above
  // Do NOT copy portable, witness, watchers, deactivated - these are only in genesis
  // (The resolver will carry them forward from previous entries)

  const entryWithoutProof = {
    versionId: previousEntry.versionId,
    versionTime: nextVersionTime,
    parameters: newParameters as DIDLogEntry['parameters'],
    state: newState,
  };

  // Compute hash using previous entry's versionId as the chain link
  const entryHash = await deriveHash({ ...entryWithoutProof, versionId: previousEntry.versionId });
  entryWithoutProof.versionId = `${versionNumber}-${entryHash}`;

  // Sign the entry
  const proofTemplate = {
    type: 'DataIntegrityProof' as const,
    cryptosuite: 'eddsa-jcs-2022' as const,
    verificationMethod: options.signer.getVerificationMethodId(),
    created: nextVersionTime,
    proofPurpose: 'assertionMethod' as const,
  };

  const signedProof = await options.signer.sign({ document: entryWithoutProof, proof: proofTemplate });

  const entry: DIDLogEntry = {
    ...entryWithoutProof,
    proof: [{ ...proofTemplate, proofValue: signedProof.proofValue }],
  };

  return [...options.log, entry];
}
