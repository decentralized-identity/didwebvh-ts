export {
  AbstractCrypto,
  prepareDataForSigning,
} from './cryptography.js';
export { generateParallelDidWeb } from './did-document.js';
export * from './interfaces.js';
export {
  createDID,
  deactivateDID,
  getWitnessRequirements,
  resolveDID,
  resolveDIDFromLog,
  signWitnessProofEntry,
  updateDID,
  verifyWitnessProofs,
} from './method.js';
export type { GetResolverConfig } from './resolver.js';
export { getResolver } from './resolver.js';
export type { ResolutionOptionsError, WebvhDocumentMetadata, WebvhResolutionMetadata } from './resolver-result.js';
export { WEBVH_ERROR_TYPES } from './resolver-result.js';
export { deriveNextKeyHash } from './utils/crypto.js';
export { defaultVerifier } from './verifier.js';
