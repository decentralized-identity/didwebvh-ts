import type {
  DataIntegrityProof,
  DataIntegrityProofPurpose,
  DataIntegrityProofTemplate,
  SignableDocument,
  Signer,
  SignerOptions,
  SigningInput,
  SigningOutput,
  VerificationMethod,
  Verifier,
} from './interfaces';
import { concatBuffers } from './utils/buffer';
import { canonicalizeStrict } from './utils/canonicalize';
import { createHash } from './utils/crypto';
import { createDate } from './utils/iso8601-datetime';

/**
 * Creates a Data Integrity proof template from explicit input values.
 */
export const createDataIntegrityProofTemplate = (options: {
  verificationMethod: string;
  created?: string;
  proofPurpose?: DataIntegrityProofPurpose;
  id?: string;
}): DataIntegrityProofTemplate => {
  return {
    ...(options.id ? { id: options.id } : {}),
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: options.verificationMethod,
    created: options.created ?? createDate(),
    proofPurpose: options.proofPurpose ?? 'assertionMethod',
  };
};

/**
 * Signs a document using a proof template and returns a complete DataIntegrityProof.
 */
export const signDataIntegrityProof = async <TDocument>(
  document: TDocument,
  proofTemplate: DataIntegrityProofTemplate,
  signer: Signer<TDocument>
): Promise<DataIntegrityProof> => {
  const signed = await signer.sign({ document, proof: proofTemplate });
  const mergedProof = {
    ...proofTemplate,
    proofValue: signed.proofValue,
  };

  // Strip undefined fields to keep the proof JSON-compatible.
  const sanitizedProof = JSON.parse(JSON.stringify(mergedProof)) as Partial<DataIntegrityProof>;
  const verificationMethod = sanitizedProof.verificationMethod;
  if (!verificationMethod) {
    throw new Error('Data Integrity proof is missing verificationMethod');
  }

  const proofValue = sanitizedProof.proofValue;
  if (!proofValue) {
    throw new Error('Data Integrity proof is missing proofValue');
  }

  return {
    id: sanitizedProof.id,
    type: sanitizedProof.type ?? proofTemplate.type,
    cryptosuite: sanitizedProof.cryptosuite ?? proofTemplate.cryptosuite,
    verificationMethod,
    created: sanitizedProof.created ?? proofTemplate.created,
    proofValue,
    proofPurpose: sanitizedProof.proofPurpose ?? proofTemplate.proofPurpose,
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
 * @param verificationMethodId - The verification method ID to use when building proof templates
 * @returns A function that signs a document and returns the document with proof
 */
export const createDocumentSigner = <TDocument extends SignableDocument>(
  signer: Signer<TDocument>,
  verificationMethodId: string
) => {
  return async (doc: TDocument): Promise<TDocument & { proof: DataIntegrityProof }> => {
    try {
      const proofTemplate = createDataIntegrityProofTemplate({ verificationMethod: verificationMethodId });
      const proof = await signDataIntegrityProof(doc, proofTemplate, signer);

      return { ...doc, proof };
    } catch (e) {
      console.error(e);
      const message = e instanceof Error ? e.message : String(e);
      throw new Error(`Document signing failure: ${message}`);
    }
  };
};
