export type DataIntegrityProofPurpose =
  | 'authentication'
  | 'assertionMethod'
  | 'keyAgreement'
  | 'capabilityInvocation'
  | 'capabilityDelegation';

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

export interface SigningInput {
  document: unknown;
  proof: DataIntegrityProofTemplate;
}

export interface SigningOutput {
  proofValue: string;
}

export interface Signer {
  sign(input: SigningInput): Promise<SigningOutput>;
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

export interface DIDResolutionMeta {
  versionId: string;
  created: string;
  updated: string;
  previousLogEntryHash?: string;
  updateKeys: string[];
  scid: string;
  prerotation: boolean;
  portable: boolean;
  nextKeyHashes: string[];
  deactivated: boolean;
  witness?: WitnessParameterResolution;
  watchers?: string[] | null;
  error?: 'NOT_FOUND' | 'INVALID_DID' | 'INVALID_DID_URL' | 'INVALID_OPTIONS' | 'REPRESENTATION_NOT_SUPPORTED' | 'METHOD_NOT_SUPPORTED' | 'UNSUPPORTED_PUBLIC_KEY_TYPE' | 'INVALID_DID_DOCUMENT' | 'INVALID_PUBLIC_KEY' | 'INVALID_PUBLIC_KEY_LENGTH' | 'INVALID_PUBLIC_KEY_TYPE' | 'INTERNAL_ERROR';
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
  publicKeyJwk?: any;
  use?: string;
}

export interface WitnessEntry {
  id: string; // did:key DID
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
    deactivated?: boolean;
  };
  state: DIDDoc;
  proof?: DataIntegrityProof[];
}

export type DIDLog = DIDLogEntry[];

export interface ServiceEndpoint {
  id?: string;
  type: string | string[];
  serviceEndpoint?: string | string[] | any;
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
  domain?: string;
  address?: string;
  signer: Signer;
  updateKeys: string[];
  verificationMethods?: VerificationMethod[];
  didDocument?: DIDDoc;
  services?: ServiceEndpoint[];
  paths?: string[];
  controller?: string;
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
  updateKeys?: string[];
  verificationMethods?: VerificationMethod[];
  controller?: string;
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
  verificationMethod?: string;
  verifier?: Verifier;
  scid?: string;
}

export interface WitnessProofFileEntry {
  versionId: string;
  proof: DataIntegrityProof[];
}
