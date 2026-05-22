export { resolveDID, resolveDIDFromLog, createDID, updateDID, deactivateDID } from './method';
export { createDocumentSigner, prepareDataForSigning, createProof, createSigner, AbstractCrypto } from './cryptography';
export {
	createWitnessProof,
	signWitnessProofEntry,
	signWitnessProofEntries,
} from './witness';
export * from './interfaces';
export { generateParallelDidWeb, parseDidKeyDid, parseDidKeyVerificationMethod } from './utils';
export { multibaseEncode, multibaseDecode, MultibaseEncoding } from './utils/multiformats';
