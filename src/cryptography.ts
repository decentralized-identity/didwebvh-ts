import { createDate } from "./utils";
import { canonicalize } from 'json-canonicalize';
import { createHash } from './utils/crypto';
import type { VerificationMethod, SigningInput, SigningOutput, Signer, SignerOptions } from './interfaces';
import { concatBuffers } from './utils/buffer';

/**
 * Creates a proof object for a document
 * @param verificationMethodId - The verification method ID to use in the proof
 * @returns A proof object with type, cryptosuite, verificationMethod, created, and proofPurpose
 */
export const createProof = (verificationMethodId: string): any => {
  return {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: verificationMethodId,
    created: createDate(),
    proofPurpose: 'assertionMethod'
  };
};

/**
 * Prepares data for signing by hashing and concatenating the document and proof
 * @param document - The document to sign
 * @param proof - The proof object
 * @returns The prepared data for signing as a Uint8Array
 */
export const prepareDataForSigning = async (document: any, proof: any): Promise<Uint8Array> => {
  const dataHash = await createHash(canonicalize(document));
  const proofHash = await createHash(canonicalize(proof));
  return concatBuffers(proofHash, dataHash);
};

/**
 * Abstract base class for signers
 * Users should extend this class to implement their own signing logic
 */
export abstract class AbstractSigner implements Signer {
  protected verificationMethod: VerificationMethod;
  protected useStaticId: boolean;

  constructor(options: SignerOptions) {
    this.verificationMethod = options.verificationMethod;
    this.useStaticId = options.useStaticId !== undefined ? options.useStaticId : true;
  }

  /**
   * Sign the input data
   * @param input - The signing input containing the document and proof
   * @returns The signing output containing the proof value
   */
  abstract sign(input: SigningInput): Promise<SigningOutput>;

  /**
   * Get the verification method ID
   * @returns The verification method ID
   */
  getVerificationMethodId(): string {
    return this.useStaticId 
      ? `did:key:${this.verificationMethod.publicKeyMultibase}#${this.verificationMethod.publicKeyMultibase}`
      : this.verificationMethod.id || '';
  }
}

/**
 * Creates a document signer from any Signer implementation
 * @param signer - The signer to use
 * @param verificationMethodId - The verification method ID to use in proofs
 * @returns A function that signs a document and returns the document with proof
 */
export const createDocumentSigner = (signer: Signer, verificationMethodId: string) => {
  return async (doc: any) => {
    try {
      const proof = createProof(verificationMethodId);
      const result = await signer.sign({ document: doc, proof });
      
      proof.proofValue = result.proofValue;
      return { ...doc, proof };
    } catch (e: any) {
      console.error(e);
      throw new Error(`Document signing failure: ${e.message || e}`);
    }
  };
};

/**
 * @deprecated Use createDocumentSigner with your own Signer implementation instead
 */
export const createSigner = (vm: VerificationMethod, useStatic: boolean = true) => {
  console.warn('createSigner is deprecated. Use createDocumentSigner with your own Signer implementation instead.');
  
  return async (doc: any) => {
    try {
      const verificationMethodId = useStatic 
        ? `did:key:${vm.publicKeyMultibase}#${vm.publicKeyMultibase}` 
        : vm.id || '';
      
      const proof = createProof(verificationMethodId);
      
      // This is a placeholder for backward compatibility
      // Users should implement their own signing logic
      throw new Error('createSigner is deprecated. Implement your own Signer and use createDocumentSigner instead.');
      
    } catch (e: any) {
      console.error(e);
      throw new Error(`Document signing failure: ${e.message || e}`);
    }
  };
};

/**
 * @deprecated Implement your own key generation logic
 */
export async function generateEd25519VerificationMethod(): Promise<VerificationMethod> {
  console.warn('generateEd25519VerificationMethod is deprecated. Implement your own key generation logic.');
  throw new Error('generateEd25519VerificationMethod is deprecated. Implement your own key generation logic.');
}

/**
 * @deprecated Implement your own key generation logic
 */
export async function generateX25519VerificationMethod(): Promise<VerificationMethod> {
  console.warn('generateX25519VerificationMethod is deprecated. Implement your own key generation logic.');
  throw new Error('generateX25519VerificationMethod is deprecated. Implement your own key generation logic.');
}
