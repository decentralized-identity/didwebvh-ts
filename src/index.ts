export { AbstractCrypto, createDocumentSigner, createProof, prepareDataForSigning } from './cryptography';
export * from './interfaces';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method';
export { getResolver } from './resolver';
export type { GetResolverConfig } from './resolver';
export { defaultVerifier } from './verifier';
export { InvalidDidUrlError } from './resolver-result';
export type { WebvhDocumentMetadata, WebvhErrorCode, WebvhResolutionMetadata } from './resolver-result';
export { deriveNextKeyHash, generateParallelDidWeb, parseDidKeyDid, parseDidKeyVerificationMethod } from './utils';
export { MultibaseEncoding, multibaseDecode, multibaseEncode } from './utils/multiformats';
export {
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from './witness';
