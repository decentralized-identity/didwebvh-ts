# Injectable Signer Examples

This directory contains examples of how to use the injectable signer and verifier functionality in the `didwebvh-ts` library.

## Running the Examples

This directory is set up as a standalone package that depends on the main `didwebvh-ts` library. To run the examples:

1. Navigate to the examples directory:
   ```bash
   cd examples
   ```

2. Install dependencies:
   ```bash
   bun install
   ```

3. Run an example:
   ```bash
   # Run the custom signer example
   bun run custom
   
   # Run the HSM signer example
   bun run hsm
   ```

## Overview

The `didwebvh-ts` library now supports injectable cryptographic operations, allowing you to:

1. Use your own cryptographic libraries
2. Integrate with external key management systems (KMS)
3. Use hardware security modules (HSM)
4. Implement custom signing and verification logic

## Important Note

The `didwebvh-ts` library no longer includes any specific cryptographic implementation. You must provide your own cryptographic implementation by either:

1. **Extending the `AbstractSigner` class** (Recommended for most cases)
   - When you have direct access to key material
   - When using standard cryptographic libraries
   - When following the standard verification method pattern
   - When you want built-in verification method ID handling
   - Example: Implementing Ed25519 signing with your preferred crypto library

2. **Implementing the `Signer` interface directly**
   - When integrating with HSMs or KMS systems
   - When key material is managed externally
   - When using custom verification method ID schemes
   - When you need complete control over the signing process
   - Example: AWS KMS, Azure Key Vault, or other external signing services

## Examples

### 1. Custom Ed25519 Implementation

```typescript
import { AbstractSigner, prepareDataForSigning, Verifier, multibaseEncode, MultibaseEncooding } from 'didwebvh-ts';
import type { SigningInput, SigningOutput, SignerOptions } from 'didwebvh-ts';
import * as crypto from '@stablelib/ed25519'; // Example using stablelib

// Combined signer and verifier implementation
class Ed25519Implementation extends AbstractSigner implements Verifier {
  constructor(options: SignerOptions) {
    super(options);
  }
  
  async sign(input: SigningInput): Promise<SigningOutput> {
    if (!this.verificationMethod.secretKeyMultibase) {
      throw new Error('Secret key is required for signing');
    }

    const data = await prepareDataForSigning(input.document, input.proof);
    const privateKey = multibaseDecode(this.verificationMethod.secretKeyMultibase).slice(2);
    const signature = crypto.sign(privateKey, data);
    
    return { proofValue: multibaseEncode(signature, MultibaseEncoding.BASE58_BTC) };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    return crypto.verify(publicKey, message, signature);
  }

  getVerificationMethodId(): string {
    return this.verificationMethod.id || 
      `did:key:${this.verificationMethod.publicKeyMultibase}#${this.verificationMethod.publicKeyMultibase}`;
  }
}
```

### 2. AWS KMS Implementation

```typescript
import { type Signer, type Verifier, type SigningInput, type SigningOutput, prepareDataForSigning, multibaseEncode, MultibaseEncoding } from 'didwebvh-ts';
import { KMS } from 'aws-sdk';

class AWSKMSImplementation implements Signer, Verifier {
  private kms: KMS;
  private keyId: string;
  private verificationMethodId: string;

  constructor(keyId: string, verificationMethodId: string, region: string) {
    this.kms = new KMS({ region });
    this.keyId = keyId;
    this.verificationMethodId = verificationMethodId;
  }

  async sign(input: SigningInput): Promise<SigningOutput> {
    const data = await prepareDataForSigning(input.document, input.proof);
    
    const result = await this.kms.sign({
      KeyId: this.keyId,
      Message: Buffer.from(data),
      SigningAlgorithm: 'ECDSA_SHA_256',
      MessageType: 'RAW'
    }).promise();
    
    if (!result.Signature) {
      throw new Error('No signature returned from KMS');
    }

    return { proofValue: multibaseEncode(result.Signature, MultibaseEncoding.BASE58_BTC) };
  }

  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    try {
      const result = await this.kms.verify({
        KeyId: this.keyId,
        Message: Buffer.from(message),
        Signature: Buffer.from(signature),
        SigningAlgorithm: 'ECDSA_SHA_256',
        MessageType: 'RAW'
      }).promise();

      return result.SignatureValid || false;
    } catch (error) {
      console.error('KMS verification error:', error);
      return false;
    }
  }

  getVerificationMethodId(): string {
    return this.verificationMethodId;
  }
}
```

### Using the Implementations

```typescript
import { createDocumentSigner } from 'didwebvh-ts';

// For local Ed25519
const implementation = new Ed25519Implementation({
  verificationMethod: {
    type: 'Multikey',
    publicKeyMultibase: 'z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK',
    secretKeyMultibase: 'z3uzadNVtyRhBW8n7GGnEDpNJC3WrE7eTvzxRqus7YQpTZxk',
    purpose: 'assertionMethod'
  }
});

// For AWS KMS
const kmsImplementation = new AWSKMSImplementation(
  'arn:aws:kms:us-west-2:111122223333:key/1234abcd-12ab-34cd-56ef-1234567890ab',
  'did:example:123#key-1',
  'us-west-2'
);

// Create a document signer
const documentSigner = createDocumentSigner(implementation, implementation.getVerificationMethodId());

// Sign a document
const document = {
  id: 'did:example:123',
  name: 'Example Document'
};

const signedDocument = await documentSigner(document);
```

## Utility Functions

The library provides several utility functions to help with implementing custom signers:

- `prepareDataForSigning`: Prepares data for signing by hashing and concatenating the document and proof
- `createProof`: Creates a proof object for a document 