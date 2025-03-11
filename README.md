# `didwebvh-ts`

`didwebvh-ts` provides developers with a comprehensive library and resolver for working with Decentralized Identifiers (DIDs) following the `did:webvh` method specification. This Typescript-based toolkit is designed to facilitate the integration and management of DIDs within web applications, enabling secure identity verification and authentication processes. It includes functions for creating, resolving, updating and deactivating DIDs by managing DID documents. The package is built to ensure compatibility with the latest web development standards, offering a straightforward API that makes it easy to implement DID-based features in a variety of projects.

## Summary

The `didwebvh-ts` implementation of the [`did:webvh`]('https://identity.foundation/didwebvh/') specification aims to be compatible with the `did:webvh` v0.5 specification.

## Examples

The `examples` directory contains sample code demonstrating how to use the injectable signer and verifier functionality in the `didwebvh-ts` library. These examples show how to:

- Implement custom cryptographic operations
- Integrate with external key management systems (KMS)
- Use hardware security modules (HSM)
- Create your own signing and verification logic

The examples directory is set up as a standalone package that can be run directly. See the [examples README](./examples/README.md) for instructions on how to run the examples.

## Prerequisites

Install [bun.sh](https://bun.sh/)

```bash
curl -fsSL https://bun.sh/install | bash
```

## Install dependencies

```bash
bun install
```

## Available Commands

The following commands are defined in the `package.json` file:

1. `dev`: Run the resolver in development mode with debugging enabled.
   ```bash
   bun run dev
   ```
   This command runs: `bun --watch --inspect-wait ./src/resolver.ts`

2. `server`: Run the resolver in watch mode for development.
   ```bash
   bun run server
   ```
   This command runs: `bun --watch ./src/resolver.ts`

3. `test`: Run all tests.
   ```bash
   bun run test
   ```
   This command runs: `bun test`

4. `test:watch`: Run tests in watch mode.
   ```bash
   bun run test:watch
   ```
   This command runs: `bun test --watch`

5. `test:bail`: Run tests in watch mode, stopping on the first failure with verbose output.
   ```bash
   bun run test:bail
   ```
   This command runs: `bun test --watch --bail --verbose`

6. `test:log`: Run tests and save the output to a log file.
   ```bash
   bun run test:log
   ```
   This command runs: `mkdir -p ./test/logs && LOG_RESOLVES=true bun test &> ./test/logs/test-run.txt`

7. `cli`: Run the CLI tool.
   ```bash
   bun run cli [command] [options]
   ```
   This command runs: `bun run src/cli.ts --`

## CLI Usage Guide

> ⚠️ **Warning**: The CLI is experimental beta software - use at your own risk!

### Basic Syntax
```bash
bun run cli [command] [options]
```

### Available Commands

#### 1. Create a DID
Create a new DID with various configuration options:

```bash
bun run cli create \
  --domain example.com \
  --output ./did.jsonl \
```

**Key Options:**
- `--domain`: (Required) Host domain for the DID
- `--output`: Save location for DID log
- `--portable`: Enable domain portability
- `--witness`: Add witness DIDs (repeatable)
- `--witness-threshold`: Set minimum witness count
- `--next-key-hash`: Add pre-rotation key hashes

#### 2. Resolve a DID
View the current state of a DID:

```bash
# From DID identifier
bun run cli resolve --did did:webvh:123456:example.com

# From local log file
bun run cli resolve --log ./did.jsonl
```

#### 3. Update a DID
Modify an existing DID's properties:

```bash
bun run cli update \
  --log ./did.jsonl \
  --output ./updated.jsonl \
  --add-vm keyAgreement \
  --service LinkedDomains,https://example.com \
  --also-known-as did:web:example.com
```

**Update Options:**
- `--log`: (Required) Current DID log path
- `--output`: Updated log save location
- `--add-vm`: Add verification methods:
  - authentication
  - assertionMethod
  - keyAgreement
  - capabilityInvocation
  - capabilityDelegation
- `--service`: Add services (format: type,endpoint)
- `--also-known-as`: Add alternative identifiers
- `--witness`: Update witness list
- `--witness-threshold`: Update witness requirements

#### 4. Deactivate a DID
Permanently deactivate a DID:

```bash
bun run cli deactivate \
  --log ./did.jsonl \
  --output ./deactivated.jsonl
```

## Contributing

### Commit Message Format

This project uses [Semantic Release](https://github.com/semantic-release/semantic-release) for automated version management and package publishing. Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/) specification.

Format: `<type>(<scope>): <description>` where scope is optional.

#### Types:
- `feat`: A new feature (triggers a minor version bump)
- `fix`: A bug fix (triggers a patch version bump)
- `docs`: Documentation changes
- `style`: Code style changes (formatting, missing semi-colons, etc)
- `refactor`: Code changes that neither fix a bug nor add a feature
- `perf`: Performance improvements
- `test`: Adding or updating tests
- `chore`: Changes to build process or auxiliary tools

#### Examples:

```
feat(resolver): add support for new DID method
fix: handle null response from endpoint
docs: update installation instructions
chore: update dependencies
```

Breaking changes must include `BREAKING CHANGE:` in the commit message body or footer, or append a `!` after the type/scope.

Example:
```
feat(api)!: remove deprecated endpoints
```
or
```
feat(api): remove deprecated endpoints

BREAKING CHANGE: The following endpoints have been removed...
```