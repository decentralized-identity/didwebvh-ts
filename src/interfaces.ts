import type { DIDDocument, VerificationMethod } from 'did-resolver';

export type { DIDDocument, Service, ServiceEndpoint, VerificationMethod } from 'did-resolver';

export type DataIntegrityProofPurpose =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
export type JsonObject = { [key: string]: JsonValue };

export type DataIntegrityProofType = 'DataIntegrityProof';
export type DataIntegrityCryptosuite = 'eddsa-jcs-2022';

export interface DataIntegrityProofTemplate {
  id?: string;
  type: DataIntegrityProofType;
  cryptosuite: DataIntegrityCryptosuite;
  verificationMethod: string;
  created: string;
  proofPurpose: DataIntegrityProofPurpose;
}

export type SignableDocument = DIDLogEntry | DIDDocument | Pick<DIDLogEntry, 'versionId'>;

export interface SigningInput<TDocument = SignableDocument> {
  document: TDocument;
  proof: DataIntegrityProofTemplate;
}

export interface SigningOutput {
  proofValue: string;
}

export interface Signer<TDocument = SignableDocument> {
  sign(input: SigningInput<TDocument>): Promise<SigningOutput>;
  getVerificationMethodId(): string;
}

export interface Verifier {
  verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;
}

/**
 * A fetch-compatible function used by the resolver for HTTP retrieval.
 */
export type FetchLike = (input: string, init?: RequestInit) => Promise<Response>;

export interface SignerOptions {
  verificationMethod?: VerificationMethod | null;
  useStaticId?: boolean;
}

export interface ProblemDetails {
  type: string;
  title: string;
  detail: string;
}

/**
 * Codes surfaced on `didResolutionMetadata.error`.
 *
 * `invalidDid`/`notFound` match DID Core §7.1.2; `invalidDidUrl` is reserved for a
 * DID URL that violates `did-url` syntax (e.g. malformed percent-encoding);
 * `invalidOptions` covers well-formed URLs carrying invalid resolution options
 * (conflicting or ill-typed version selectors) per the DID Resolution spec's
 * INVALID_OPTIONS; `internalError` covers transport/resolver-side failures.
 */
export type DidResolutionError = 'invalidDid' | 'invalidDidUrl' | 'invalidOptions' | 'notFound' | 'internalError';

export interface DIDResolutionMeta {
  versionId: string;
  versionTime: string;
  created: string;
  updated: string;
  previousLogEntryHash?: string;
  updateKeys: string[];
  scid: string;
  prerotation: boolean;
  portable: boolean;
  ttl?: string;
  nextKeyHashes: string[];
  deactivated: boolean;
  witness?: WitnessParameterResolution;
  watchers?: string[] | null;
  error?: DidResolutionError;
  problemDetails?: ProblemDetails;
  latestVersionId?: string;
}

export interface WitnessEntry {
  id: string; // did:key DID
}

export interface ParsedDidKeyVerificationMethod {
  did: string;
  fragment?: string;
  keyMultibase: string;
}

export interface WitnessSigningOptions {
  trustedLog: DIDLog;
  candidateLog: DIDLog;
  witnessSigner: Signer<Pick<DIDLogEntry, 'versionId'>>;
  witnessProofs?: WitnessProofFileEntry[];
  verifier?: Verifier;
}

export interface WitnessParameter {
  threshold?: number;
  witnesses?: WitnessEntry[];
}

export interface WitnessParameterResolution {
  threshold?: string | number;
  witnesses?: WitnessEntry[];
}

export interface DataIntegrityProof {
  id?: string;
  type: DataIntegrityProofType;
  cryptosuite: DataIntegrityCryptosuite;
  verificationMethod: string;
  created: string;
  proofValue: string;
  proofPurpose: DataIntegrityProofPurpose;
}

export interface DIDLogEntry {
  versionId: string;
  versionTime: string;
  parameters: {
    method?: string;
    scid?: string;
    updateKeys?: string[];
    nextKeyHashes?: string[];
    portable?: boolean;
    witness?: WitnessParameter;
    watchers?: string[] | null;
    ttl?: string | number | null;
    deactivated?: boolean;
  };
  state: DIDDocument;
  proof?: DataIntegrityProof[];
}

export type DIDLog = DIDLogEntry[];

export interface CreateDIDResult {
  did: string;
  doc: DIDDocument;
  meta: DIDResolutionMeta;
  log: DIDLog;
  webDoc?: DIDDocument;
}

export interface UpdateDIDResult {
  did: string;
  doc: DIDDocument;
  meta: DIDResolutionMeta;
  log: DIDLog;
  webDoc?: DIDDocument;
}

export interface CreateDIDOptions {
  address?: string;
  signer: Signer;
  updateKeys: string[];
  /**
   * Complete initial DID document.
   */
  didDocument: DIDDocument;
  paths?: string[];
  alsoKnownAsWeb?: boolean;
  portable?: boolean;
  nextKeyHashes?: string[];
  witness?: WitnessParameter | null;
  watchers?: string[] | null;
  created?: string;
  verifier?: Verifier;
}

export interface UpdateDIDOptions {
  log: DIDLog;
  signer: Signer;
  /**
   * Optional complete next DID document.
   *
   * When supplied, this becomes the complete proposed next document state
   * (no property merging from prior state). When omitted, the prior authenticated
   * document state is preserved.
   */
  didDocument?: DIDDocument;
  /**
   * Optional explicit timestamp for the new DID log entry.
   *
   * When omitted, the implementation generates the timestamp internally.
   * This option is primarily intended for deterministic test/migration flows.
   */
  updated?: string;
  updateKeys?: string[];
  portable?: boolean;
  nextKeyHashes?: string[];
  witness?: WitnessParameter | null;
  watchers?: string[] | null;
  verifier?: Verifier;
  witnessProofs?: WitnessProofFileEntry[];
  address?: string;
  paths?: string[];
}

export interface DeactivateDIDOptions {
  log: DIDLog;
  signer: Signer;
  verifier?: Verifier;
  witnessProofs?: WitnessProofFileEntry[];
}

export interface ResolutionOptions {
  versionNumber?: number;
  versionId?: string;
  versionTime?: Date;
  verifier?: Verifier;
  scid?: string;
  witnessProofs?: WitnessProofFileEntry[];
  // Return locally controlled DID log or undefined
  resolveControlledDid?: (did: string) => Promise<DIDLog | undefined>;
  // Override for network fetches used to retrieve the DID log and witness proof file
  fetch?: FetchLike;
}

export interface WitnessProofFileEntry {
  versionId: string;
  proof: DataIntegrityProof[];
}

/**
 * The witness configuration that governs approval of one DID log entry,
 * derived by applying the did:webvh witness transition rules rather than
 * read directly from final resolved metadata.
 */
export interface WitnessRequirement {
  versionId: string;
  versionNumber: number;
  threshold: number;
  witnesses: WitnessEntry[];
}

export interface VerifyWitnessProofsOptions {
  verifier?: Verifier;
}

export type WitnessProofRejectionCode =
  | 'unknown-witness'
  | 'duplicate-witness'
  | 'invalid-proof-type'
  | 'invalid-proof-purpose'
  | 'invalid-cryptosuite'
  | 'invalid-verification-method'
  | 'invalid-public-key'
  | 'invalid-signature';

export interface WitnessProofRejection {
  requirementVersionId?: string;
  proofVersionId: string;
  proofIndex: number;
  verificationMethod?: string;
  code: WitnessProofRejectionCode;
  message: string;
}

export interface WitnessVerificationResult {
  verified: boolean;
  requirements: (WitnessRequirement & {
    satisfied: boolean;
    approvals: number;
  })[];
  rejectedProofs: WitnessProofRejection[];
}
