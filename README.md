# `didwebvh-ts`

[![CI](https://github.com/decentralized-identity/didwebvh-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/decentralized-identity/didwebvh-ts/actions/workflows/ci.yml)

`didwebvh-ts` provides developers with a comprehensive library for working with Decentralized Identifiers (DIDs) following the `did:webvh` method specification. This TypeScript-based toolkit is designed to facilitate the integration and management of DIDs within web applications, enabling secure identity verification and authentication processes. It includes functions for creating, resolving, updating and deactivating DIDs by managing DID documents. The package is built to ensure compatibility with the latest web development standards, offering a straightforward API that makes it easy to implement DID-based features in a variety of projects.

## Summary

The `didwebvh-ts` implementation of the [`did:webvh`]('https://identity.foundation/didwebvh/') specification aims to be compatible with the `did:webvh` v1.0 specification.

## Upgrading from 2.x to 3.0.0

Version 3.0.0 is a major release with breaking changes. Before upgrading, see:

- **[Migration Guide](./docs/UPGRADE_2.x_to_3.0.md)** — Step-by-step upgrade instructions for each breaking change
- **[Breaking Changes Reference](./docs/BREAKING_CHANGES_v3.0.md)** — Summary and rationale for all breaking changes

## Examples

The `examples` directory contains sample code demonstrating how to use the library:

- **Resolver Examples**: The `examples` directory includes two resolver implementations:
  - `elysia-resolver.ts`: (`pnpm example:resolver`) A resolver built with the Elysia web framework
  - `express-resolver.ts`: A resolver built with Express.js
  Both examples demonstrate how to implement a DID resolver with different web frameworks. See the [Examples README](./examples/README.md) for more information.
- **Signer Example**: The `examples/signer.ts` (`pnpm example:signer`) file demonstrates how to implement a custom signer using `AbstractCrypto`.

## Toolchain

This project uses:

- Node.js (runtime and package execution)
- TypeScript 7 (type-checking and language features)
- Vitest (test runner)
- pnpm (package management and scripts)

## Prerequisites

Install the following:

- Node.js 24+
- pnpm (via Corepack or npm)

With Corepack (recommended):

```bash
corepack enable
corepack prepare pnpm@latest --activate
```

## Install dependencies

```bash
pnpm install
```

## Local development setup

Build once before running local examples from source:

```bash
pnpm build
```

Then start the resolver example:

```bash
pnpm server
```

If you need to refresh generated artifacts after code changes, rerun `pnpm build`.

## Available Commands

The following commands are defined in the `package.json` file:

1. `dev`: Run the Elysia resolver example in watch mode for development.

```bash
  pnpm dev
```

  This command runs: `tsx --watch ./examples/elysia-resolver.ts` and starts the resolver at `http://localhost:3010` by default. Set `PORT` to use a different port.

1. `debug`: Run the Elysia resolver example in watch mode with Node inspector enabled.

```bash
  pnpm debug
```

  This command runs: `tsx --watch --inspect ./examples/elysia-resolver.ts`. Use the printed inspector URL for debugger tooling; the resolver still runs at the configured app port, defaulting to `http://localhost:3010`.

1. `server`: Alias for running the Elysia resolver example in watch mode.

```bash
  pnpm server
```

  This command runs: `tsx --watch ./examples/elysia-resolver.ts`

1. `test`: Run all tests.

```bash
  pnpm test
```

  This command runs Vitest in non-watch mode.

1. `test:watch`: Run tests in watch mode.

```bash
  pnpm test:watch
```

1. `test:bail`: Run tests in watch mode with bail and verbose options.

```bash
  pnpm test:bail
```

1. `test:log`: Run tests and save logs to a file.

```bash
  pnpm test:log
```

1. `cli`: Run the CLI tool.

```bash
  pnpm cli
```

The CLI accepts a `--watcher` option during create and update operations to specify one or more watcher URLs.

1. `build`: Build the package.

```bash
  pnpm build
```

1. `build:clean`: Clean the build directory.

```bash
  pnpm build:clean
```

1. `check`: Run TypeScript 7 type-checking without emitting files.

```bash
  pnpm check
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
- run `pnpm test` and `pnpm build`
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

`versionId`, `versionTime`, and `versionNumber` are mutually exclusive — supplying more than one returns `didResolutionMetadata.error = "invalidOptions"` with a `problemDetails.type` from the [did:webvh resolution-error registry](https://didwebvh.info/latest/resolution-errors/).

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

### Runtime and CLI separation

The runtime library does not read `process.env`, `.env`, or infer local
filesystem paths. `resolveDID` uses normative HTTPS resolution by default.
Applications that manage DID logs locally can provide a caller-owned lookup:

```typescript
const result = await resolveDID(did, {
  resolveControlledDid: async (requestedDid) => localLogs.get(requestedDid),
  witnessProofs: localWitnessProofs, // optional
});
```

The callback returns a `DIDLog` or `undefined`. Returning `undefined` uses the
normal HTTPS fallback. Callback-supplied logs go through the same validation
pipeline as remotely fetched logs. When explicit witness proofs are omitted,
`resolveDID`/`resolveDIDFromLog` retrieve them from the specification-defined
deterministic URL.

`updateDID` and `deactivateDID` never perform this network fetch: when
`options.witnessProofs` is omitted, they pass `[]` rather than fetching, so a
missing or insufficient proof set surfaces immediately as an unmet witness
threshold instead of a network-dependent lookup. Callers that need witness
verification for an update or deactivation must supply `witnessProofs`
explicitly (see [Witness Functions](#witness-functions) below).

The CLI owns environment variables, `.env` persistence, private-key selection,
and its local log-file layout. `DID_VERIFICATION_METHODS` is therefore a CLI
setting and does not alter library resolution behavior.

For complete examples, see the [examples](./examples/) directory.

### Resolution metadata notes (v1.0)

Resolver failures are surfaced on `didResolutionMetadata`:

- `didResolutionMetadata.error` is one of `"invalidDid"` (the resolved DID or log fails validation), `"invalidDidUrl"` (the DID URL violates `did-url` syntax, e.g. malformed percent-encoding), `"invalidOptions"` (conflicting or ill-typed version selectors), `"notFound"`, or `"internalError"` (transport/resolver-side failure). Unknown query parameters are ignored per DID Core extensibility.
- `didResolutionMetadata.problemDetails` carries RFC9457-style fields (`type`, `title`, `detail`) where available, and `didResolutionMetadata.message` carries the underlying detail string.
- Local control is an application concern and is not reported in resolution metadata.

Absence cases (missing DID log or missing DID URL resource) use `didResolutionMetadata.error = "notFound"`.

When resolving a requested earlier version (with `versionId`, `versionNumber`, or `versionTime`), the resolver may return a valid earlier document while still reporting `didResolutionMetadata.error = "invalidDid"` if a later log entry fails verification.

Method-specific metadata (`scid`, `updateKeys`, `nextKeyHashes`, `prerotation`, `portable`, `witness`, `watchers`, `previousLogEntryHash`, `latestVersionId`) is returned on `didDocumentMetadata` alongside the standard `versionId`/`created`/`updated`/`deactivated` fields.

> **Breaking change (v3.0.0):** resolution returns the standard `DIDResolutionResult` instead of the previous `{ did, doc, meta, controlled }` shape, and the implementation-specific `verificationMethod` resolution selector has been removed. See [Migration Guide](./docs/UPGRADE_2.x_to_3.0.md#1-resolution-result-shape) for upgrade steps.

## API Reference

### Core Functions

- `getResolver(config?: { verifier?: Verifier }): ResolverRegistry`
  Returns a `did-resolver` registry entry (`{ webvh: DIDResolver }`) registrable in a `Resolver`. Works zero-config via `defaultVerifier`.

- `defaultVerifier: Verifier`
  Built-in Ed25519 verifier used when no `verifier` is supplied.

- `resolveDID(did: string, options?: ResolutionOptions): Promise<DIDResolutionResult>`
  Resolves a DID to a standard W3C `DIDResolutionResult` (`{ didResolutionMetadata, didDocument, didDocumentMetadata }`). Does not throw on failure.

- `resolveDIDFromLog(log: DIDLog, options?: ResolutionOptions): Promise<DIDResolutionResult>`
  Resolves directly from an in-memory DID log, returning the same standard shape.

- `createDID(options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog, webDoc?: DIDDoc}>`
  Creates a new DID. Always produces a v1.0 log.
  Accepts `address` (`host`, `host:port`, `https://...`, or `did:webvh:...`) or legacy `domain`.
  Resolver URL mapping uses `http://localhost` for local testing and `https://` for non-local hosts.
  If `alsoKnownAsWeb: true` is supplied, the result also includes `webDoc`, the parallel `did:web` DID document to publish as `did.json`.

- `updateDID(options: UpdateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog, webDoc?: DIDDoc}>`
  Updates an existing DID. Accepts logs originally created with v0.5 or v1.0, but always appends a v1.0 entry.
  Returns `webDoc` when the updated DID document carries a `did:web:` alias in `alsoKnownAs`.

- `deactivateDID(options: DeactivateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}>`
  Deactivates an existing DID. Accepts logs originally created with v0.5 or v1.0, but always appends a v1.0 entry.

- `generateParallelDidWeb(didwebvhDid: string, didwebvhDoc: DIDDoc): DIDDoc`
  Generates the parallel `did:web` document defined by did:webvh v1.0 §3.7.10.

### Witness Functions

- `createWitnessProof(signer, versionId, verificationMethod, created?): Promise<DataIntegrityProof>`
  Creates and signs one witness proof for a specific `versionId`.

- `signWitnessProofEntry(options: WitnessSigningOptions): Promise<WitnessSigningResult>`
  Signs one did-witness proof entry (`{ versionId, proof[] }`) for a single target version.

- `signWitnessProofEntries(versionIds: string[], witnesses: WitnessEntry[], witnessSignersByDid: Record<string, WitnessSigner>, created?: string): Promise<WitnessSigningResult[]>`
  Signs did-witness proof entries for multiple target versions.

- `getWitnessRequirements(result: { log: DIDLog }): WitnessRequirement[]`
  Derives the witness approvals required for each entry in a DID log that requires witnessing, by applying the did:webvh witness transition rules (genesis activation, inheritance, replacement, and removal). Synchronous, performs no network fetch, and requires no `Verifier`. Accepts any object with a `log: DIDLog` property, so a `CreateDIDResult`/`UpdateDIDResult`/`DIDResolutionResult`-shaped value can be passed directly. Returns `[]` when the log has no active witness requirement.

- `verifyWitnessProofs(result: { log: DIDLog }, witnessProofs: WitnessProofFileEntry[], options?: { verifier?: Verifier }): Promise<WitnessVerificationResult>`
  Verifies every witness requirement in a DID log against the supplied `witnessProofs`, without any network fetch — proofs must be provided by the caller (e.g. proofs obtained for a proposed, not-yet-published log chain tip before it and its witness proofs are published). Returns `{ verified: boolean, requirements: (WitnessRequirement & { approvals: number, satisfied: boolean })[] }`, reporting an unmet threshold as data (`verified: false`) rather than throwing. All other verification failures (hash chain, SCID, controller proof, etc.) still throw.

### Witness lifecycle sequence

`createDID`, `updateDID`, and `deactivateDID` always return their normal, complete result — a proposed log chain tip is generated and returned regardless of whether any witness requirement is satisfied. Witness proofs are a separate artifact (`did-witness.json`) from the DID log (`did.jsonl`); collecting or verifying them never modifies the returned result.

`getWitnessRequirements` tells the caller which approvals must be collected for the returned log. `verifyWitnessProofs` then checks a prospective proof file against that exact result: `verified: true` means the caller may proceed with the specification's publication order — it does **not** mean the library has published anything. The caller remains responsible for publishing `did-witness.json` before publishing the corresponding `did.jsonl` update.

`result.meta.witness` describes the witness configuration active *after* the result is published; it must not be assumed to be the configuration that approves the transition into that result (see `getWitnessRequirements`, which derives the correct governing configuration per did:webvh's witness transition rules).

```ts
const result = await createDID(options);
const requirements = getWitnessRequirements(result);

if (requirements.length > 0) {
  // Application-owned: collect signed witness proofs out-of-band (e.g. via a
  // witness service or manual approval flow), not part of this library.
  const prospectiveWitnessFile = await collectProofsOutsideTheLibrary(result, requirements);

  const { verified } = await verifyWitnessProofs(result, prospectiveWitnessFile);
  if (!verified) {
    // Keep collecting proofs; this is expected, not an error.
  }

  // Application-owned: publish did-witness.json to its well-known location.
  await callerPublishesWitnessFile(prospectiveWitnessFile);
}

// Application-owned: publish did.jsonl only after the witness file above.
await callerPublishesDIDLog(result.log);
```

`updateDID` and `deactivateDID` default `witnessProofs` to `[]` (never fetching) when the option is omitted, so an unmet witness threshold on those two methods surfaces immediately as an error rather than a network-dependent lookup — see [Runtime and CLI separation](#runtime-and-cli-separation).

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
