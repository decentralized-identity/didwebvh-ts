# DID Resolver Examples

This directory contains examples of how to implement a DID resolver using the `didwebvh-ts` library with different web frameworks.

## Available Resolvers

- [Elysia](./elysia/): A resolver implementation using the Elysia framework
- [Express](./express/): A resolver implementation using the Express framework

## Running the Examples

Each resolver example is a standalone application. To run an example:

1. Navigate to the specific resolver directory:
   ```bash
   cd examples/resolvers/elysia
   ```

2. Install dependencies:
   ```bash
   bun install
   ```

3. Start the resolver:
   ```bash
   bun run start
   ```

The resolver will be available at `http://localhost:8000` by default. You can change the port by setting the `PORT` environment variable.

## Resolver Endpoints

All resolvers implement the following endpoints:

- `GET /health`: Health check endpoint
- `GET /resolve/:id`: Resolve a DID
- `GET /resolve/:id/*`: Resolve a DID with a path
- `GET /.well-known/*`: Access well-known resources

## Verifier Implementation

The `didwebvh-ts` library requires a verifier implementation for DID operations. The verifier is responsible for:

1. Verifying signatures in DID documents
2. Validating witness proofs
3. Ensuring the integrity of DID operations

All resolver examples now include a default verifier implementation that satisfies this requirement. The verifier is passed to the `resolveDID` function:

```typescript
// Define a simple verifier implementation
class DefaultVerifier implements Verifier {
  async verify(signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): Promise<boolean> {
    // Verification logic here
    return true;
  }
}

// Create an instance of the default verifier
const defaultVerifier = new DefaultVerifier();

// Use the verifier in the resolver
const result = await resolveDID(didPart, { 
  verifier: defaultVerifier,
  // other options...
});
```

For more advanced verifier implementations, see the examples in the `examples/signers` directory.

## Creating Your Own Resolver

You can use these examples as a starting point to create your own resolver with your preferred framework. The key components are:

1. Import the `resolveDID` function from the `didwebvh-ts` library
2. Implement a verifier that satisfies the `Verifier` interface
3. Create endpoints for resolving DIDs
4. Implement file retrieval logic for DID documents and associated resources

## Framework-Specific Notes

### Elysia

The Elysia resolver is the most similar to the original implementation in the `didwebvh-ts` library. It uses Bun's built-in HTTP server and provides a clean API for defining routes.

### Express

The Express resolver is a good choice if you're familiar with the Express framework or need to integrate with existing Express middleware.

### Bun

The Bun resolver uses Bun's native HTTP server without any additional framework dependencies. It's the most lightweight option and has no external dependencies beyond the core library. 