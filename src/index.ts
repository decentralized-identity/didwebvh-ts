export { resolveDID, resolveDIDFromLog, createDID, updateDID, deactivateDID } from './method';
export { createDocumentSigner, prepareDataForSigning, createProof, createSigner, AbstractCrypto } from './cryptography';
export * from './interfaces';
export { generateParallelDidWeb } from './utils';
export { multibaseEncode, multibaseDecode, MultibaseEncoding } from './utils/multiformats';
