# `didwebvh-ts`

`didwebvh-ts` provides developers with a comprehensive library for working with Decentralized Identifiers (DIDs) following the `did:webvh` method specification. This Typescript-based toolkit is designed to facilitate the integration and management of DIDs within web applications, enabling secure identity verification and authentication processes. It includes functions for creating, resolving, updating and deactivating DIDs by managing DID documents. The package is built to ensure compatibility with the latest web development standards, offering a straightforward API that makes it easy to implement DID-based features in a variety of projects.

## Summary

The `didwebvh-ts` implementation of the [`did:webvh`]('https://identity.foundation/didwebvh/') specification aims to be compatible with the `did:webvh` v1.0 specification.

## Examples

The `examples` directory contains sample code demonstrating how to use the library:

- **Resolver Examples**: The `examples` directory includes two resolver implementations:
  - `elysia-resolver.ts`: (`bun run example:resolver`) A resolver built with the Elysia web framework
  - `express-resolver.ts`: A resolver built with Express.js
  Both examples demonstrate how to implement a DID resolver with different web frameworks. See the [Examples README](./examples/README.md) for more information.
- **Signer Example**: The `examples/signer.ts` (`bun run example:signer`) file demonstrates how to implement a custom signer using `AbstractCrypto`.

## Prerequisites

Install [bun.sh](https://bun.sh/)

```bash
curl -fsSL https://bun.sh/install | bash
```

## Install dependencies

```bash
bun install
```

## Local development setup

When running the examples from the source checkout, Bun needs to resolve the `didwebvh-ts` package name to your local code. Run the following once per clone:

```bash
bun run build        # generate the dist/ artifacts
bun link             # register the local package globally
bun link didwebvh-ts # create a symlinked dependency in node_modules
```

After linking, you can start the resolver example:

```bash
bun run server
```

If you ever need to refresh the build (for example after local code changes), rerun `bun run build`. The `bun link` commands only need to be repeated if you remove the symlink or clone the repo again.

## Available Commands

The following commands are defined in the `package.json` file:

1. `dev`: Run the Elysia resolver example in development mode with debugging enabled.
   ```bash
   bun run dev
   ```
  This command runs: `bun --watch --inspect-wait ./examples/elysia-resolver.ts`

2. `server`: Run the Elysia resolver example in watch mode for development.
   ```bash
   bun run server
   ```
  This command runs: `bun --watch ./examples/elysia-resolver.ts`

3. `test`: Run all tests.
   ```bash
   bun run test
   ```

4. `test:watch`: Run tests in watch mode.
   ```bash
   bun run test:watch
   ```

5. `test:bail`: Run tests in watch mode with bail and verbose options.
   ```bash
   bun run test:bail
   ```

6. `test:log`: Run tests and save logs to a file.
   ```bash
   bun run test:log
   ```

7. `cli`: Run the CLI tool.
   ```bash
   bun run cli
   ```
   The CLI accepts a `--watcher` option during create and update operations to specify one or more watcher URLs.

8. `build`: Build the package.
   ```bash
   bun run build
   ```

9. `build:clean`: Clean the build directory.
   ```bash
   bun run build:clean
   ```

## Creating a DID Resolver

The `didwebvh-ts` library provides the core functionality for resolving DIDs, but it does not include a built-in HTTP resolver. You can create your own resolver using your preferred web framework by following these steps:

1. Import the `resolveDID` function from the `didwebvh-ts` library:
   ```typescript
   import { resolveDID } from 'didwebvh-ts';
   ```

2. Create endpoints for resolving DIDs:
   ```typescript
   // Example using Express
   app.get('/resolve/:id', async (req, res) => {
     try {
       const result = await resolveDID(req.params.id);
       res.json(result);
     } catch (error) {
       res.status(400).json({
         error: 'Resolution failed',
         details: error.message
       });
     }
   });
   ```

3. Implement file retrieval logic for DID documents and associated resources.

For complete examples, see the [examples](./examples/) directory.

## API Reference

### Core Functions

- `resolveDID(did: string, options?: ResolutionOptions): Promise<{did: string, doc: any, meta: DIDResolutionMeta, controlled: boolean}>`
  Resolves a DID to its DID document.

- `createDID(options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}>`
  Creates a new DID.

- `updateDID(options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}>`
  Updates an existing DID.

- `deactivateDID(options: DeactivateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}>`
  Deactivates an existing DID.

### Cryptography Functions

- `createDocumentSigner(options: SignerOptions): Signer`
  Creates a signer for signing DID documents.

- `prepareDataForSigning(data: any): Uint8Array`
  Prepares data for signing.

- `createProof(options: SigningInput): Promise<SigningOutput>`
  Creates a proof for a DID document.

- `createSigner(options: SignerOptions): Signer`
  Creates a signer for signing data.

- `AbstractCrypto`
  An abstract class for implementing custom signers.

## License

This project is licensed under the [MIT License](LICENSE).
