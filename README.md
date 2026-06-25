# `didwebvh-ts`

[![CI](https://github.com/decentralized-identity/didwebvh-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/decentralized-identity/didwebvh-ts/actions/workflows/ci.yml)

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

1. `dev`: Run the Elysia resolver example in watch mode for development.

   ```bash
   bun run dev
   ```

  This command runs: `bun --watch ./examples/elysia-resolver.ts` and starts the resolver at `http://localhost:3010` by default. Set `PORT` to use a different port.

1. `debug`: Run the Elysia resolver example in watch mode with the Bun debugger enabled.

   ```bash
   bun run debug
   ```

  This command runs: `bun --watch --inspect ./examples/elysia-resolver.ts`. Use the printed Bun Inspector URL only for debugger tooling; the resolver still runs at the configured app port, defaulting to `http://localhost:3010`.

1. `server`: Alias for running the Elysia resolver example in watch mode.

   ```bash
   bun run server
   ```

  This command runs: `bun --watch ./examples/elysia-resolver.ts`

1. `test`: Run all tests.

   ```bash
   bun run test
   ```

2. `test:watch`: Run tests in watch mode.

   ```bash
   bun run test:watch
   ```

3. `test:bail`: Run tests in watch mode with bail and verbose options.

   ```bash
   bun run test:bail
   ```

4. `test:log`: Run tests and save logs to a file.

   ```bash
   bun run test:log
   ```

5. `cli`: Run the CLI tool.

   ```bash
   bun run cli
   ```

   The CLI accepts a `--watcher` option during create and update operations to specify one or more watcher URLs.

6. `build`: Build the package.

   ```bash
   bun run build
   ```

7. `build:clean`: Clean the build directory.

   ```bash
   bun run build:clean
   ```

## Releasing

Publishing is **fully automated** and happens **only** when a maintainer publishes a GitHub Release.

- **Who can publish**: GitHub users with **write**, **maintain**, or **admin** permission on this repo.
- **Required tag format**: `vMAJOR.MINOR.PATCH` (for example `v2.7.5`).
- **Required semver bump**: the tag must be a **single** major/minor/patch increment over the latest existing `v*` tag.

### How to cut a release

1. In GitHub, go to **Releases** → **Draft a new release**
2. Set **Tag** to the next version, e.g. `v2.7.5`
3. Choose the target branch/commit (typically `main`)
4. Click **Publish release**

That will trigger the publish workflow, which will:

- validate the tag + your repo permission
- set `package.json` version from the tag (without the leading `v`)
- run `bun test` and `bun run build`
- publish to npm

### npm authentication

Publishing uses [npm OIDC trusted publishing](https://docs.npmjs.com/trusted-publishers) — the workflow exchanges its GitHub Actions OIDC token for a short-lived npm publish token at publish time. No static `NPM_TOKEN` is required.

For this to work, the `didwebvh-ts` package on npmjs.com must have a Trusted Publisher configured pointing at this repository and the `.github/workflows/publish.yml` workflow.

### Troubleshooting

- **Tag rejected**: make sure it matches `vX.Y.Z` and is exactly one major/minor/patch bump over the latest `v*` tag.
- **Permission rejected**: ensure the releasing user has write/maintain/admin permission on the GitHub repo.
- **`EOTP` / OTP required at publish**: the npm token path is being used instead of OIDC. Make sure no `NODE_AUTH_TOKEN` is set on the publish step and that the workflow has `id-token: write` permission.
- **OIDC exchange failed**: confirm the Trusted Publisher config on npmjs.com matches this repo's owner, name, and workflow file path (`.github/workflows/publish.yml`).

## Creating a DID Resolver

Resolution follows the standard W3C [`did-resolver`](https://github.com/decentralized-identity/did-resolver) interface. `resolveDID` / `resolveDIDFromLog` return a `DIDResolutionResult` (`{ didResolutionMetadata, didDocument, didDocumentMetadata }`), and `getResolver()` produces a registry entry you can drop into a `did-resolver` `Resolver` alongside `did:web`, `did:ethr`, etc.

#### Using the did-resolver interface

```typescript
import { Resolver } from 'did-resolver';
import { getResolver } from 'didwebvh-ts';

// Works zero-config via the built-in Ed25519 verifier;
// pass getResolver({ verifier }) to override.
const resolver = new Resolver(getResolver());

const result = await resolver.resolve('did:webvh:SCID:example.com');
// Spec-conformant query parameters are honoured:
const v2 = await resolver.resolve('did:webvh:SCID:example.com?versionId=2-...');
```

`versionId`, `versionTime`, and `versionNumber` are mutually exclusive — supplying more than one returns `didResolutionMetadata.error = "invalidDidUrl"`.

#### Calling the resolvers directly

```typescript
import { resolveDID } from 'didwebvh-ts';

// Example using Express
app.get('/resolve/:id', async (req, res) => {
  const result = await resolveDID(req.params.id);
  res.json(result);
});
```

`resolveDID` does not throw on failure — it returns a `DIDResolutionResult` with `didDocument: null` and a `didResolutionMetadata.error` code.

For complete examples, see the [examples](./examples/) directory.

### Resolution metadata notes (v1.0)

Resolver failures are surfaced on `didResolutionMetadata`:

- `didResolutionMetadata.error` is one of `"invalidDid"`, `"notFound"`, or `"invalidDidUrl"`.
- `didResolutionMetadata.problemDetails` carries RFC9457-style fields (`type`, `title`, `detail`) where available, and `didResolutionMetadata.message` carries the underlying detail string.
- Whether the resolved DID is locally controlled rides along as `didResolutionMetadata.controlled` (a non-standard extension).

Absence cases (missing DID log or missing DID URL resource) use `didResolutionMetadata.error = "notFound"`.

When resolving a requested earlier version (with `versionId`, `versionNumber`, or `versionTime`), the resolver may return a valid earlier document while still reporting `didResolutionMetadata.error = "invalidDid"` if a later log entry fails verification.

Method-specific metadata (`scid`, `updateKeys`, `nextKeyHashes`, `prerotation`, `portable`, `witness`, `watchers`, `previousLogEntryHash`, `latestVersionId`) is returned on `didDocumentMetadata` alongside the standard `versionId`/`created`/`updated`/`deactivated` fields.

> **Breaking change (v3.0.0):** resolution returns the standard `DIDResolutionResult` instead of the previous `{ did, doc, meta, controlled }` shape, and the implementation-specific `verificationMethod` resolution selector has been removed.

## API Reference

### Core Functions

- `getResolver(config?: { verifier?: Verifier }): ResolverRegistry`
  Returns a `did-resolver` registry entry (`{ webvh: DIDResolver }`) registrable in a `Resolver`. Works zero-config via `defaultVerifier`.

- `defaultVerifier: Verifier`
  Built-in Ed25519 verifier used when no `verifier` is supplied.

- `resolveDID(did: string, options?: ResolutionOptions): Promise<DIDResolutionResult>`
  Resolves a DID to a standard W3C `DIDResolutionResult` (`{ didResolutionMetadata, didDocument, didDocumentMetadata }`). Does not throw on failure.

- `resolveDIDFromLog(log: DIDLog, options?: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] }): Promise<DIDResolutionResult>`
  Resolves directly from an in-memory DID log, returning the same standard shape.

- `createDID(options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog, webDoc?: DIDDoc}>`
  Creates a new DID.
  Accepts `address` (`host`, `host:port`, `https://...`, or `did:webvh:...`) or legacy `domain`.
  Resolver URL mapping uses `http://localhost` for local testing and `https://` for non-local hosts.
  If `alsoKnownAsWeb: true` is supplied, the result also includes `webDoc`, the parallel `did:web` DID document to publish as `did.json`.

- `updateDID(options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog, webDoc?: DIDDoc}>`
  Updates an existing DID.
  Returns `webDoc` when the updated DID document carries a `did:web:` alias in `alsoKnownAs`.

- `deactivateDID(options: DeactivateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}>`
  Deactivates an existing DID.

- `generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc`
  Generates the parallel `did:web` document defined by did:webvh v1.0 §3.7.10.

### Witness Functions

- `createWitnessProof(signer, versionId, verificationMethod, created?): Promise<DataIntegrityProof>`
  Creates and signs one witness proof for a specific `versionId`.

- `signWitnessProofEntry(options: WitnessSigningOptions): Promise<WitnessSigningResult>`
  Signs one did-witness proof entry (`{ versionId, proof[] }`) for a single target version.

- `signWitnessProofEntries(versionIds: string[], witnesses: WitnessEntry[], witnessSignersByDid: Record<string, WitnessSigner>, created?: string): Promise<WitnessSigningResult[]>`
  Signs did-witness proof entries for multiple target versions.

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
