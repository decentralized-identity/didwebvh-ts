// @ts-nocheck
/* 
 * This is an example file that demonstrates how to use the didwebvh-ts library.
 * The imports will cause TypeScript errors when viewed in the repository,
 * but will work correctly when used in a project with didwebvh-ts installed.
 */

import { 
  createDocumentSigner, 
  prepareDataForSigning,
  AbstractSigner,
  multibaseEncode,
  MultibaseEncoding
} from 'didwebvh-ts';
import type { 
  SigningInput, 
  SigningOutput, 
  VerificationMethod, 
  SignerOptions, 
  Verifier 
} from 'didwebvh-ts';

/**
 * Example of a combined signer and verifier implementation
 * This class can be used for both signing and verifying operations
 */
class CombinedSignerVerifier extends AbstractSigner implements Verifier {
  /**
   * Constructor for CombinedSignerVerifier
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

    if (!this.verificationMethod.secretKeyMultibase) {
      throw new Error('Secret key is required for signing');
    }

    // Prepare the data for signing (this is standard across implementations)
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    
    // Mock signing operation (replace with your actual crypto library)
    // In a real implementation, you would use your preferred crypto library
    console.log('Signing data with CombinedSignerVerifier');
    const mockSignature = new Uint8Array([1, 2, 3, 4, 5]);
    
    // Return a fake signature as a base58btc-encoded string
    return { proofValue: multibaseEncode(mockSignature, MultibaseEncoding.BASE58_BTC) };
  }

  /**
   * Verify a signature
   * @param signature - The signature to verify
   * @param message - The message that was signed
   * @param publicKey - The public key to verify against
   * @returns Whether the signature is valid
   */
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    // In a real implementation, you would:
    // 1. Use your preferred crypto library to verify the signature
    // 2. Return true if the signature is valid, false otherwise

    // This is a mock implementation for demonstration purposes
    console.log('Verifying signature with CombinedSignerVerifier');
    console.log(`Signature: ${Buffer.from(signature).toString('hex')}`);
    console.log(`Message: ${Buffer.from(message).toString('hex')}`);
    console.log(`Public Key: ${Buffer.from(publicKey).toString('hex')}`);
    
    // For demonstration purposes, always return true
    // In a real implementation, you would actually verify the signature
    return true;
  }
}

/**
 * Generate a verification method for testing
 * In a real implementation, you would use your preferred crypto library
 */
async function generateVerificationMethod(): Promise<VerificationMethod> {
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
    publicKeyMultibase: multibaseEncode(mockPublicKey, MultibaseEncoding.BASE58_BTC),
    secretKeyMultibase: multibaseEncode(mockPrivateKey, MultibaseEncoding.BASE58_BTC)
  };
}

/**
 * Example usage of the combined signer and verifier
 */
async function exampleUsage() {
  try {
    // Generate a verification method
    const verificationMethod = await generateVerificationMethod();
    
    // Create a combined signer and verifier
    const implementation = new CombinedSignerVerifier({ verificationMethod });
    
    // Create a document signer
    const documentSigner = createDocumentSigner(implementation, implementation.getVerificationMethodId());
    
    // Sign a document
    const document = {
      id: 'did:example:123',
      name: 'Example Document'
    };
    
    const signedDocument = await documentSigner(document);
    console.log('Signed document:', signedDocument);

    // Verify a signature (mock example)
    const mockSignature = new Uint8Array([1, 2, 3, 4, 5]);
    const mockMessage = new Uint8Array([6, 7, 8, 9, 10]);
    const mockPublicKey = new Uint8Array([0xed, 0x01, 11, 12, 13, 14, 15]);
    
    const isValid = await implementation.verify(mockSignature, mockMessage, mockPublicKey);
    console.log('Signature valid:', isValid);
  } catch (error) {
    console.error('Error:', error);
  }
}

// Export the implementation for use in other files
export { CombinedSignerVerifier, generateVerificationMethod };