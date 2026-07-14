# DID Web VH Resolver Examples

This directory contains example implementations of DID Web VH resolvers using different frameworks:

1. **Elysia Resolver** - A resolver built with the Elysia framework
2. **Express Resolver** - A resolver built with Express (Node.js)

Both examples demonstrate functioning DID resolution with proper Ed25519 cryptographic verification.

## Prerequisites

- Node.js
- pnpm

## Running the Examples

### Elysia Resolver

The Elysia resolver demonstrates a resolver with a custom Ed25519 verifier that extends the `AbstractCrypto` class:

```bash
pnpm exec tsx examples/elysia-resolver.ts
```

This will start the resolver on port 3010.

### Express Resolver

The Express resolver demonstrates a resolver with an HSM Ed25519 implementation:

```bash
pnpm exec tsx examples/express-resolver.ts
```

This will start the resolver on port 8000.

## Testing the Resolvers

You can test both resolvers by making HTTP requests to the resolution endpoints:

### Resolving a DID

```bash
# Elysia resolver
curl "http://localhost:3010/resolve/did:web:example.com"

# Express resolver
curl "http://localhost:8000/resolve/did:web:example.com"
```

### Resolving with Query Parameters

You can pass various query parameters for version control:

```bash
# Version number
curl "http://localhost:3010/resolve/did:web:example.com?versionNumber=1"

# Version ID
curl "http://localhost:3010/resolve/did:web:example.com?versionId=abc123"

# Version time
curl "http://localhost:3010/resolve/did:web:example.com?versionTime=2023-12-01T00:00:00Z"

# Verification method
curl "http://localhost:3010/resolve/did:web:example.com?verificationMethod=key-1"
```

## Implementation Details

### Elysia Resolver

The Elysia resolver uses an `ElysiaVerifier` class that:

1. Extends the `AbstractCrypto` class
2. Implements the `Verifier` interface for verification
3. Uses Ed25519 for cryptographic operations via `@noble/curves`
4. Demonstrates proper verification of Ed25519 signatures

### Express Resolver

The Express resolver uses an `HSMSigner` class that:

1. Implements both `Signer` and `Verifier` interfaces directly
2. Simulates an HSM (Hardware Security Module) for secure Ed25519 key operations
3. Provides a production-ready example of Ed25519 verification

## Code Structure

Both examples follow a similar structure:

1. **Ed25519 Verifier Implementation**: Proper cryptographic verification using the Ed25519 algorithm
2. **DID Resolution**: Endpoints for resolving DIDs using the `didwebvh-ts` library
3. **File Handling**: Logic for retrieving resources associated with DIDs
4. **Error Handling**: Proper error reporting for various scenarios

## Security Considerations

These examples demonstrate proper Ed25519 cryptographic verification but should be reviewed for your specific security requirements before use in production:

1. Key management should be handled securely (HSM, key vaults, etc.)
2. Input validation should be robust
3. Error handling should not leak sensitive information
4. Rate limiting may be needed in production deployments

## License

See the project's main license file for details. 
