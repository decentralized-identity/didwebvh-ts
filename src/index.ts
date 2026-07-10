export { AbstractCrypto, createDocumentSigner, createProof, prepareDataForSigning } from './cryptography';
export * from './interfaces';
export { createDID, deactivateDID, resolveDID, resolveDIDFromLog, updateDID } from './method';
export { deriveNextKeyHash, generateParallelDidWeb, parseDidKeyDid, parseDidKeyVerificationMethod } from './utils';
export { MultibaseEncoding, multibaseDecode, multibaseEncode } from './utils/multiformats';
export {
  createWitnessProof,
  signWitnessProofEntries,
  signWitnessProofEntry,
} from './witness';
