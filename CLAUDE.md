# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is a TypeScript library implementing the `did:webvh` specification for Decentralized Identifiers (DIDs). It supports two spec versions ([v1.0] and [v0.5]) and provides create, resolve, update, and deactivate operations, plus a CLI tool and example resolver servers.

[v1.0]: https://identity.foundation/didwebvh/v1.0/
[v0.5]: https://identity.foundation/didwebvh/v0.5/

## Commands

```bash
# Run all tests
pnpm test

# Run a single test file
pnpm test -- test/happy-path.test.ts

# Run tests with verbose output, stopping on first failure
pnpm test:bail

# Lint and check formatting with automatic fixes
pnpm lint:fix

# Build distribution artifacts
pnpm build

# Clean and rebuild
pnpm build:clean
```

## Architecture

### Entry Points

- **[src/method.ts](src/method.ts)** — Public API dispatcher. Exports `createDID`, `resolveDID`, `resolveDIDFromLog`, `updateDID`, `deactivateDID`, `generateParallelDidWeb`.
- **[src/index.ts](src/index.ts)** — Barrel re-export of `method.ts` and core types/utilities.
- **[src/cli/index.ts](src/cli/index.ts)** — CLI tool wrapping the same operations with file I/O.

### Core Modules

- **[src/core/entries.ts](src/core/entries.ts)** — Genesis, update, and deactivation entry preparation (`prepareGenesisEntry`, `prepareUpdateEntry`, `prepareDeactivationEntry`).
- **[src/core/resolution.ts](src/core/resolution.ts)** — Core resolution pipeline over DID logs (`resolveLogEntries`).
- **[src/core/witness-requirements.ts](src/core/witness-requirements.ts)** — Witness threshold and proof validation requirements.
- **[src/did-document.ts](src/did-document.ts)** — Verification of DID documents and placeholder substitution (`assertNoPrivateVerificationMaterial`, `substitutePlaceholders`).
- **[src/cryptography.ts](src/cryptography.ts)** — `AbstractCrypto` base class for implementors to extend. Handles proof creation and data preparation for signing. Consumers implement `sign()` and `verify()`.
- **[src/witness.ts](src/witness.ts)** — Witness proof verification and creation.
- **[src/utils.ts](src/utils.ts)** — Address normalization, URL derivation, entry hash calculation.
- **[src/interfaces.ts](src/interfaces.ts)** — TypeScript interfaces (`CreateDIDOptions`, `UpdateDIDOptions`, `DeactivateDIDOptions`, `DIDDocument`, `Signer`, `Verifier`, `DIDLog`, etc.).
- **[src/constants.ts](src/constants.ts)** — Method constants and placeholders (`METHOD`, `PLACEHOLDER`).
- **[src/utils/crypto.ts](src/utils/crypto.ts)**, **[src/utils/buffer.ts](src/utils/buffer.ts)**, **[src/utils/multiformats.ts](src/utils/multiformats.ts)** — Low-level hashing, buffer conversion, and multibase encoding.

### Typical Call Flow

```
createDID(options) [method.ts]
  → prepareGenesisEntry() [core/entries.ts]
      → assertNoPrivateVerificationMaterial() & substitutePlaceholders() [did-document.ts]
      → prepareDataForSigning() + createProof() [cryptography.ts]
      → entry hash derivation [utils.ts]
      → returns { did, doc, log, ... }
```

### Build Output

The library builds to four targets: ESM (`dist/esm/`), CommonJS (`dist/cjs/`), browser (`dist/browser/`), and TypeScript declarations (`dist/types/`). The CLI ships as `dist/cli/didwebvh.js`.

### Test Utilities

**[test/utils.ts](test/utils.ts)** provides `TestCryptoImplementation` (Ed25519 mock), `createTestSigner()`, `createTestVerifier()`, and `createMockDIDLog()` for use across all test files. Tests use Vitest.

### Examples

**[examples/](examples/)** contains reference implementations: `elysia-resolver.ts` and `express-resolver.ts` show how to serve DID resolution over HTTP; `signer.ts` shows how to extend `AbstractCrypto`.
