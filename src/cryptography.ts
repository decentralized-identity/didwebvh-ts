import { createDate } from "./utils";
import { createHash } from './utils/crypto';
import type { DataIntegrityProofTemplate, VerificationMethod, SigningInput, SigningOutput, Signer, SignerOptions, Verifier } from './interfaces';
import { concatBuffers } from './utils/buffer';
import { canonicalizeStrict } from './utils/canonicalize';

/**
 * Creates a proof object for a document
 * @param verificationMethodId - The verification method ID to use in the proof
 * @returns A proof object with type, cryptosuite, verificationMethod, created, and proofPurpose
 */
export const createProof = (verificationMethodId: string): DataIntegrityProofTemplate => {
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
export const prepareDataForSigning = async (
  document: unknown,
  proof: DataIntegrityProofTemplate
): Promise<Uint8Array> => {
  const dataHash = await createHash(canonicalizeStrict(document));
  const proofHash = await createHash(canonicalizeStrict(proof));
  return concatBuffers(proofHash, dataHash);
};

/**
 * Abstract base class for signers
 * Users should extend this class to implement their own signing logic
 */
export abstract class AbstractCrypto implements Signer, Verifier {
  protected verificationMethod?: VerificationMethod | null;
  protected useStaticId: boolean;

  constructor(options: SignerOptions) {
    if (options.verificationMethod) {
      this.verificationMethod = options.verificationMethod;
    }
    this.useStaticId = options.useStaticId !== undefined ? options.useStaticId : true;
  }

  /**
   * Sign the input data
   * @param input - The signing input containing the document and proof
   * @returns The signing output containing the proof value
   */
  abstract sign(input: SigningInput): Promise<SigningOutput>;

  /**
   * Verify a signature
   * @param signature - The signature to verify
   * @param message - The message to verify
   * @param publicKey - The public key to verify the signature with
   */
  abstract verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean>;

  /**
   * Get the verification method ID
   * @returns The verification method ID
   */
  getVerificationMethodId(): string {
    if (!this.verificationMethod) {
      throw new Error('Verification method not set');
    }
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

      return { ...doc, proof: { ...proof, proofValue: result.proofValue } };
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
