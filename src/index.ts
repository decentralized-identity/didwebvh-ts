export {
  AbstractCrypto,
  createDataIntegrityProofTemplate,
  createDocumentSigner,
  prepareDataForSigning,
  signDataIntegrityProof,
} from './cryptography';
export { generateParallelDidWeb } from './did-document';
export * from './interfaces';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method';
export type { GetResolverConfig } from './resolver';
export { getResolver } from './resolver';
export type { ResolutionOptionsError, WebvhDocumentMetadata, WebvhResolutionMetadata } from './resolver-result';
export { WEBVH_ERROR_TYPES } from './resolver-result';
export { deriveNextKeyHash, parseDidKeyDid, parseDidKeyVerificationMethod } from './utils';
export { MultibaseEncoding, multibaseDecode, multibaseEncode } from './utils/multiformats';
export { defaultVerifier } from './verifier';
export {
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from './witness';
