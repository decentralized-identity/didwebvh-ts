/* 
 * This is an example file that demonstrates how to use the didwebvh-ts library.
 * The imports will cause TypeScript errors when viewed in the repository,
 * but will work correctly when used in a project with didwebvh-ts installed.
 */

import { 
  createDocumentSigner, 
  prepareDataForSigning
} from 'didwebvh-ts';
import type { Signer, SigningInput, SigningOutput, Verifier } from 'didwebvh-ts';

/**
 * Example of a Hardware Security Module (HSM) or Key Management Service (KMS) signer
 * 
 * This example implements the Signer interface directly (instead of extending AbstractSigner)
 * because HSM/KMS implementations typically:
 * 1. Don't have direct access to the private key material
 * 2. Use key references or identifiers instead
 * 3. Have their own method of managing verification method IDs
 */
class HSMSigner implements Signer, Verifier {
  private keyId: string;
  private verificationMethodId: string;

  /**
   * Constructor for HSMSigner
   * @param keyId - The key ID in the HSM/KMS
   * @param verificationMethodId - The verification method ID to use in proofs
   */
  constructor(keyId: string, verificationMethodId: string) {
    this.keyId = keyId;
    this.verificationMethodId = verificationMethodId;
  }

  /**
   * Sign the input data
   * @param input - The signing input containing the document and proof
   * @returns The signing output containing the proof value
   */
  async sign(input: SigningInput): Promise<SigningOutput> {
    // In a real implementation, you would:
    // 1. Prepare the data for signing
    // 2. Call your HSM/KMS API to sign the data
    // 3. Return the signature as a base58btc-encoded string

    // Prepare the data for signing (this is standard across implementations)
    const dataToSign = await prepareDataForSigning(input.document, input.proof);
    
    // Convert to hex for HSM API (many HSM APIs expect hex)
    const dataHex = Buffer.from(dataToSign).toString('hex');
    
    // Call the HSM/KMS to sign the data (mocked in this example)
    const signatureHex = await this.mockHsmSigningCall(dataHex);
    
    // Convert the signature back to bytes and encode as base58btc
    const signature = Buffer.from(signatureHex, 'hex');
    
    // Return the signature as a base58btc-encoded string
    return { proofValue: `z1${signatureHex}` };
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
    // 1. Call your HSM/KMS API to verify the signature
    // 2. Return true if the signature is valid, false otherwise

    // This is a mock implementation for demonstration purposes
    console.log('Verifying signature with HSMSigner');
    console.log(`Signature: ${Buffer.from(signature).toString('hex').substring(0, 20)}...`);
    console.log(`Message: ${Buffer.from(message).toString('hex').substring(0, 20)}...`);
    console.log(`Public Key: ${Buffer.from(publicKey).toString('hex').substring(0, 20)}...`);
    
    // For demonstration purposes, always return true
    // In a real implementation, you would actually verify the signature using your HSM/KMS
    return await this.mockHsmVerificationCall(
      Buffer.from(signature).toString('hex'),
      Buffer.from(message).toString('hex'),
      Buffer.from(publicKey).toString('hex')
    );
  }

  /**
   * Mock HSM/KMS signing call
   * In a real implementation, this would be a call to your HSM/KMS API
   * @param dataHex - The data to sign as a hex string
   * @returns The signature as a hex string
   */
  private async mockHsmSigningCall(dataHex: string): Promise<string> {
    // This is a mock implementation for demonstration purposes
    console.log(`[HSM] Signing data: ${dataHex}`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Return a mock signature
    // In a real implementation, this would be the actual signature from your HSM/KMS
    return '0102030405060708090a0b0c0d0e0f';
  }

  /**
   * Mock HSM/KMS verification call
   * In a real implementation, this would be a call to your HSM/KMS API
   * @param signatureHex - The signature as a hex string
   * @param messageHex - The message as a hex string
   * @param publicKeyHex - The public key as a hex string
   * @returns Whether the signature is valid
   */
  private async mockHsmVerificationCall(
    signatureHex: string,
    messageHex: string,
    publicKeyHex: string
  ): Promise<boolean> {
    // This is a mock implementation for demonstration purposes
    console.log(`[HSM] Verifying signature: ${signatureHex.substring(0, 20)}...`);
    console.log(`[HSM] Message: ${messageHex.substring(0, 20)}...`);
    console.log(`[HSM] Public Key: ${publicKeyHex.substring(0, 20)}...`);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Return a mock verification result
    // In a real implementation, this would be the actual verification result from your HSM/KMS
    return true;
  }

  /**
   * Get the verification method ID
   * @returns The verification method ID
   */
  getVerificationMethodId(): string {
    return this.verificationMethodId;
  }
}

/**
 * Example usage of the HSM signer
 */
async function exampleUsage() {
  try {
    // Create an HSM signer with a key ID and verification method ID
    const signer = new HSMSigner(
      'hsm-key-12345', // Key ID in your HSM/KMS
      'did:example:123#key-1' // Verification method ID to use in proofs
    );
    
    // Create a document signer
    const documentSigner = createDocumentSigner(signer, signer.getVerificationMethodId());
    
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
    
    const isValid = await signer.verify(mockSignature, mockMessage, mockPublicKey);
    console.log('Signature valid:', isValid);
  } catch (error) {
    console.error('Error:', error);
  }
}

// Uncomment to run the example
exampleUsage(); 