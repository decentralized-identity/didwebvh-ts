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

export type SignableDocument = DIDLogEntry | DIDDoc | Pick<DIDLogEntry, 'versionId'>;

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

export interface DIDDoc {
  '@context'?: string | string[] | object | object[];
  id?: string;
  controller?: string | string[];
  alsoKnownAs?: string[];
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  capabilityInvocation?: string[];
  capabilityDelegation?: string[];
  verificationMethod?: VerificationMethod[];
  service?: ServiceEndpoint[];
}

export interface VerificationMethod {
  id?: string;
  type: string;
  controller?: string;
  publicKeyMultibase?: string;
  secretKeyMultibase?: string;
  purpose?: DataIntegrityProofPurpose;
  publicKeyJwk?: JsonObject;
  use?: string;
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
  versionId: string;
  witnesses: WitnessEntry[];
  witnessSignersByDid: Record<string, Signer>;
  created?: string;
}

export interface WitnessSigningResult {
  versionId: string;
  proof: DataIntegrityProof[];
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
  state: DIDDoc;
  proof?: DataIntegrityProof[];
}

export type DIDLog = DIDLogEntry[];

export interface ServiceEndpoint {
  id?: string;
  type: string | string[];
  serviceEndpoint?: string | string[] | JsonValue;
  [key: string]: unknown;
}

export interface CreateDIDResult {
  did: string;
  doc: DIDDoc;
  meta: DIDResolutionMeta;
  log: DIDLog;
  webDoc?: DIDDoc;
}

export interface UpdateDIDResult {
  did: string;
  doc: DIDDoc;
  meta: DIDResolutionMeta;
  log: DIDLog;
  webDoc?: DIDDoc;
}

export interface CreateDIDInterface {
  address?: string;
  signer: Signer;
  updateKeys: string[];
  verificationMethods?: VerificationMethod[];
  didDocument?: DIDDoc;
  services?: ServiceEndpoint[];
  paths?: string[];
  context?: string | string[] | object | object[];
  alsoKnownAs?: string[];
  alsoKnownAsWeb?: boolean;
  portable?: boolean;
  nextKeyHashes?: string[];
  witness?: WitnessParameter | null;
  watchers?: string[] | null;
  created?: string;
  verifier?: Verifier;
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
}

export interface SignDIDDocInterface {
  document: unknown;
  proof: DataIntegrityProofTemplate;
  verificationMethod: VerificationMethod;
}

export interface UpdateDIDInterface {
  log: DIDLog;
  signer: Signer;
  /**
   * Optional explicit timestamp for the new DID log entry.
   *
   * When omitted, the implementation generates the timestamp internally.
   * This option is primarily intended for deterministic test/migration flows.
   */
  updated?: string;
  updateKeys?: string[];
  verificationMethods?: VerificationMethod[];
  context?: string | string[] | object | object[];
  alsoKnownAs?: string[];
  portable?: boolean;
  nextKeyHashes?: string[];
  witness?: WitnessParameter | null;
  watchers?: string[] | null;
  verifier?: Verifier;
  authentication?: string[];
  assertionMethod?: string[];
  keyAgreement?: string[];
  witnessProofs?: WitnessProofFileEntry[];
  address?: string;
  services?: ServiceEndpoint[];
  paths?: string[];
}

export interface DeactivateDIDInterface {
  log: DIDLog;
  signer: Signer;
  verifier?: Verifier;
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
}

export interface WitnessProofFileEntry {
  versionId: string;
  proof: DataIntegrityProof[];
}

/**
 * Common structural input accepted by the witness verification APIs.
 * `CreateDIDResult`, `UpdateDIDResult`, and the deactivation result are all
 * structurally compatible because they expose `log: DIDLog`.
 */
export interface WitnessVerifiableResult {
  log: DIDLog;
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

export interface WitnessVerificationResult {
  verified: boolean;
  requirements: (WitnessRequirement & {
    satisfied: boolean;
    approvals: number;
  })[];
}
