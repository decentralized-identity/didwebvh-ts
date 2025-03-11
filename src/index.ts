export { resolveDID, createDID, updateDID, deactivateDID } from './method';
export { createDocumentSigner, prepareDataForSigning, createProof, createSigner, AbstractSigner } from './cryptography';
export type { Signer, SigningInput, SigningOutput, VerificationMethod, SignerOptions } from './interfaces';