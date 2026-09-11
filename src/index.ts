export type {
  VerifiedWitnessCandidate,
  VerifyWitnessCandidateOptions,
  WitnessRefusalCode,
} from './core/witness-candidate.js';
export { verifyWitnessCandidate, WitnessRefusal } from './core/witness-candidate.js';
export {
  AbstractCrypto,
  createDataIntegrityProofTemplate,
  createDocumentSigner,
  prepareDataForSigning,
  signDataIntegrityProof,
} from './cryptography.js';
export { generateParallelDidWeb } from './did-document.js';
export * from './interfaces.js';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method.js';
export type { GetResolverConfig } from './resolver.js';
export { getResolver } from './resolver.js';
export type { ResolutionOptionsError, WebvhDocumentMetadata, WebvhResolutionMetadata } from './resolver-result.js';
export { WEBVH_ERROR_TYPES } from './resolver-result.js';
export { deriveNextKeyHash } from './utils/crypto.js';
export { MultibaseEncoding, multibaseDecode, multibaseEncode } from './utils/multiformats.js';
export { defaultVerifier } from './verifier.js';
export {
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from './witness.js';
