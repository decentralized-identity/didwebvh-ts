# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a TypeScript library implementing the `did:webvh` specification for Decentralized Identifiers (DIDs). It supports two spec versions ([v1.0] and [v0.5]) and provides create, resolve, update, and deactivate operations, plus a CLI tool and example resolver servers.

[v1.0]: https://identity.foundation/didwebvh/v1.0/
[v0.5]: https://identity.foundation/didwebvh/v0.5/

## Commands

```bash
# Run all tests
bun test

# Run a single test file
bun test test/happy-path.test.ts

# Run tests with verbose output, stopping on first failure
bun test --watch --bail --verbose

# Build distribution artifacts
bun run build

# Clean and rebuild
bun run build:clean
```

There is no separate lint command — TypeScript strict mode serves as the type-checking step.

## Architecture

### Entry Points

- **[src/method.ts](src/method.ts)** — Public API dispatcher. Exports `createDID`, `resolveDID`, `resolveDIDFromLog`, `updateDID`, `deactivateDID`. Routes calls to the correct version implementation based on `method_version` in the DID log.
- **[src/index.ts](src/index.ts)** — Barrel re-export of `method.ts`.
- **[src/cli.ts](src/cli.ts)** — CLI tool wrapping the same operations with file I/O.

### Version Implementations

- **[src/method_versions/method.v1.0.ts](src/method_versions/method.v1.0.ts)** — Current spec (v1.0) implementation of all DID operations.
- **[src/method_versions/method.v0.5.ts](src/method_versions/method.v0.5.ts)** — Legacy spec (v0.5) implementation.

Each version module implements the same operation signatures. `method.ts` selects the right one at runtime.

### Key Supporting Modules

- **[src/cryptography.ts](src/cryptography.ts)** — `AbstractCrypto` base class for implementors to extend. Handles proof creation and data preparation for signing. Consumers implement `sign()` and `verify()`.
- **[src/witness.ts](src/witness.ts)** — Witness proof validation: `verifyWitnessProofs`, `validateWitnessParameter`, `calculateWitnessWeight`, `createWitnessProof`.
- **[src/utils.ts](src/utils.ts)** — Core business logic: DID document construction, hash derivation, log I/O, identifier fetching.
- **[src/interfaces.ts](src/interfaces.ts)** — All TypeScript interfaces (`Signer`, `Verifier`, `DIDDoc`, `DIDLog`, `DIDLogEntry`, etc.).
- **[src/constants.ts](src/constants.ts)** — `METHOD` constant and `PLACEHOLDER` used during DID creation.
- **[src/utils/crypto.ts](src/utils/crypto.ts)**, **[src/utils/buffer.ts](src/utils/buffer.ts)**, **[src/utils/multiformats.ts](src/utils/multiformats.ts)** — Low-level hashing, buffer conversion, and multibase encoding.

### Typical Call Flow

```
createDID(options) [method.ts]
  → method.v1.0.createDID() [method_versions/method.v1.0.ts]
      → prepareDataForSigning() + createProof() [cryptography.ts]
      → DIDLog entry construction [utils.ts]
      → returns { did, doc, log }
```

### Build Output

The library builds to four targets: ESM (`dist/esm/`), CommonJS (`dist/cjs/`), browser (`dist/browser/`), and TypeScript declarations (`dist/types/`). The CLI ships as `dist/cli/didwebvh.js`.

### Test Utilities

**[test/utils.ts](test/utils.ts)** provides `TestCryptoImplementation` (Ed25519 mock), `createTestSigner()`, `createTestVerifier()`, and `createMockDIDLog()` for use across all test files. Tests use Bun's native test runner — no Jest or Vitest.

### Examples

**[examples/](examples/)** contains reference implementations: `elysia-resolver.ts` and `express-resolver.ts` show how to serve DID resolution over HTTP; `signer.ts` shows how to extend `AbstractCrypto`.
