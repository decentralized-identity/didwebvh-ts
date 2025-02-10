# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024-03-06

### Added
- New `Signer` interface for implementing custom signing logic
- New `AbstractSigner` class for easier signer implementation
- New `SigningInput` and `SigningOutput` interfaces
- New `SignerOptions` interface for configuring signers
- New `createDocumentSigner` function for creating document signers
- New example implementations in `src/examples`
  - `custom-signer.ts`: Example using `AbstractSigner`
  - `hsm-signer.ts`: Example implementing `Signer` directly for HSM/KMS integration

### Changed
- Removed built-in cryptographic implementations
- Made cryptographic functionality injectable through the `Signer` interface
- Improved documentation and examples

### Deprecated
- `createSigner` function - use `createDocumentSigner` with your own `Signer` implementation instead
- `generateEd25519VerificationMethod` - implement your own key generation logic
- `generateX25519VerificationMethod` - implement your own key generation logic

### Removed
- `@noble/ed25519` dependency
- `@noble/curves` dependency
- Built-in Ed25519 signing implementation
- Built-in key generation logic

### Security
- Users now have full control over cryptographic implementations
- Better support for HSM and KMS integrations
- Improved key management flexibility
## [1.0.3](https://github.com/decentralized-identity/didwebvh-ts/compare/v1.0.2...v1.0.3) (2025-02-10)


### Bug Fixes

* remove build crypto inject ([2d8c184](https://github.com/decentralized-identity/didwebvh-ts/commit/2d8c1846978131a56ff42eae45950c8163357374))

## [1.0.2](https://github.com/decentralized-identity/didwebvh-ts/compare/v1.0.1...v1.0.2) (2025-01-27)


### Bug Fixes

* bump version ([8194920](https://github.com/decentralized-identity/didwebvh-ts/commit/8194920f290a46857c8bb82a720b46fe6211baf1))

# 1.0.0 (2025-01-27)


### Bug Fixes

* add github app to publish workflow ([59fc55a](https://github.com/decentralized-identity/didwebvh-ts/commit/59fc55a2568067d7eba952d9ac51adc29f7299db))
* Fix release workflow ([2b429b4](https://github.com/decentralized-identity/didwebvh-ts/commit/2b429b4dcd52d1ebe9c9744a5903272ed4c406bb))
* include dist folder recursively in publish ([f7b1cd5](https://github.com/decentralized-identity/didwebvh-ts/commit/f7b1cd514aa99b25f7bd2466283f95afa55ab9d1))
* **package:** fix name ([e33ce21](https://github.com/decentralized-identity/didwebvh-ts/commit/e33ce2146615bc2fd2d300a425176e83acf334cd))
* proper branch name for publish action ([ce39b9b](https://github.com/decentralized-identity/didwebvh-ts/commit/ce39b9b3b26ec49269f261a9a9fb8305d95872c8))
* proper semantic release branch config ([343eec7](https://github.com/decentralized-identity/didwebvh-ts/commit/343eec76575deab7d579e6e8844128627ea70660))
* release branch instead of main ([42db471](https://github.com/decentralized-identity/didwebvh-ts/commit/42db471500e4317b8442b808ae0cf3162599f040))
* release config for semantic-release tool ([3f59d12](https://github.com/decentralized-identity/didwebvh-ts/commit/3f59d12ec1130967c345d27549506e4625a9d386))
* releaserc.js file to module ([e750e7a](https://github.com/decentralized-identity/didwebvh-ts/commit/e750e7a3391c3e1e2fdb024b96bb1f56ff16bd0b))
* trigger release ([2b4c1db](https://github.com/decentralized-identity/didwebvh-ts/commit/2b4c1db7e10c558b56a9e70eea8290c72d5d1c0e))
* try forcing last release ([5b3360c](https://github.com/decentralized-identity/didwebvh-ts/commit/5b3360c5eedc1cf2abed5070cf0635a428b4ebed))


### Features

* add npm release ([8903f8d](https://github.com/decentralized-identity/didwebvh-ts/commit/8903f8d4edebc1cc7fe9c04e4c2b8d9ade12c1a3))
* minor version bump ([0751250](https://github.com/decentralized-identity/didwebvh-ts/commit/0751250d006cc9c085d78ba66091f05d576f02f8))

# didwebvh-ts Changelog

## 0.1.0 - 2025-01-10

### Updated
- Rename `tdw` to `webvh`.

## 0.0.2 - 2024-04-04

### Added
- Add `options` to resolveDID.
  - Option `versionId` to query specific version.
  - Option `versionTime` to query specific time.

## 0.0.1 - 2024-04-02

### Added
- Add initial files.
