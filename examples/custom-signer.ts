// @ts-nocheck
/* 
 * This is an example file that demonstrates how to use the didwebvh-ts library.
 * The imports will cause TypeScript errors when viewed in the repository,
 * but will work correctly when used in a project with didwebvh-ts installed.
 */

import { 
  createDocumentSigner, 
  prepareDataForSigning, 
  createProof,
  AbstractSigner
} from 'didwebvh-ts';
import type { SigningInput, SigningOutput, VerificationMethod, SignerOptions } from 'didwebvh-ts';
import { base58btc } from 'multiformats/bases/base58';

/**
 * Example of a custom signer implementation using your own crypto library
 * This example extends the AbstractSigner class which provides common functionality
 */
class CustomSigner extends AbstractSigner {
  /**
   * Constructor for CustomSigner
   * @param options - The signer options
   */
  constructor(options: SignerOptions) {
    super(options);
  }

  /**
   * Sign the input data
   * @param input - The signing input containing the document and proof
   * @returns The signing output containing the proof value
   */
  async sign(input: SigningInput): Promise<SigningOutput> {
    // In a real implementation, you would:
    // 1. Get the private key from this.verificationMethod.secretKeyMultibase
    // 2. Use your preferred crypto library to sign the data
    // 3. Return the signature as a base58btc-encoded string

    // This is a mock implementation for demonstration purposes
    if (!this.verificationMethod.secretKeyMultibase) {
      throw new Error('Secret key is required for signing');
    }

    // Prepare the data for signing (this is standard across implementations)
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    
    // Mock signing operation (replace with your actual crypto library)
    const mockSignature = new Uint8Array([1, 2, 3, 4, 5]);
    
    // Return the signature as a base58btc-encoded string
    return { proofValue: base58btc.encode(mockSignature) };
  }
}

/**
 * Generate a verification method for testing
 * In a real implementation, you would use your preferred crypto library
 */
async function generateCustomVerificationMethod(): Promise<VerificationMethod> {
  // This is a mock implementation for demonstration purposes
  // In a real implementation, you would:
  // 1. Generate a key pair using your preferred crypto library
  // 2. Encode the public key as a multibase string
  // 3. Optionally encode the private key as a multibase string
  
  // Mock key generation (replace with your actual crypto library)
  const mockPublicKey = new Uint8Array([0xed, 0x01, 6, 7, 8, 9, 10]);
  const mockPrivateKey = new Uint8Array([0xed, 0x01, 11, 12, 13, 14, 15]);
  
  return {
    id: '',
    type: 'Multikey',
    controller: '',
    publicKeyMultibase: base58btc.encode(mockPublicKey),
    secretKeyMultibase: base58btc.encode(mockPrivateKey)
  };
}

/**
 * Example usage of the custom signer
 */
async function exampleUsage() {
  try {
    // Generate a verification method
    const verificationMethod = await generateCustomVerificationMethod();
    
    // Create a custom signer
    const signer = new CustomSigner({ verificationMethod });
    
    // Create a document signer
    const documentSigner = createDocumentSigner(signer, signer.getVerificationMethodId());
    
    // Sign a document
    const document = {
      id: 'did:example:123',
      name: 'Example Document'
    };
    
    const signedDocument = await documentSigner(document);
    console.log('Signed document:', signedDocument);
  } catch (error) {
    console.error('Error:', error);
  }
}

// Uncomment to run the example
exampleUsage(); 