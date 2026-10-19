# Breaking Changes in 3.0.0

This document summarizes breaking changes in the 3.0.0 release. For detailed upgrade steps, see [UPGRADE_2.x_to_3.0.md](./UPGRADE_2.x_to_3.0.md).

## Summary

| Change | Category | Impact | Migration |
| -------- | ---------- | -------- | ----------- |
| DID Document Authoring (`didDocument`) | API / Behavior | `createDID` / `updateDID` | [UPGRADE_2.x_to_3.0.md §2](./UPGRADE_2.x_to_3.0.md#2-did-document-authoring-and-removal-of-verificationmethods) |
| Resolution result shape | API | All resolution calls | [UPGRADE_2.x_to_3.0.md §1](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape) |
| Proof/signing API narrowed | API / Security | Proof creation and witness signing | [UPGRADE_2.x_to_3.0.md §3](./UPGRADE_2.x_to_3.0.md#3-public-proof-and-signing-apis) |
| did:key parser root exports removed | API | did:key parsing helpers | [UPGRADE_2.x_to_3.0.md §3.2](./UPGRADE_2.x_to_3.0.md#32-did-key-parse-helper-root-exports) |
| Witness signer contract | Behavior | Witness signing | [UPGRADE_2.x_to_3.0.md §4](./UPGRADE_2.x_to_3.0.md#4-witness-signer-contract) |
| Witness metadata shape | Behavior | Metadata access | [UPGRADE_2.x_to_3.0.md §5](./UPGRADE_2.x_to_3.0.md#5-witness-metadata-shape) |
| Historical resolution errors | Behavior | Historical resolution results | [UPGRADE_2.x_to_3.0.md §1](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape) |
| `did-resolver` v6 integration and DID URL validation | Integration / Behavior | Resolver construction and invalid DID handling | [UPGRADE_2.x_to_3.0.md §6](./UPGRADE_2.x_to_3.0.md#6-did-resolver-v6-integration) |

---

## By Category

### API Changes (Signature/Exports)

#### 1. Resolution Result Shape

- **Removed**: `{ did, doc, meta, controlled }` shape
- **Added**: Standard W3C `{ didDocument, didDocumentMetadata, didResolutionMetadata }` shape
- **Changed**: Local control is application-owned and is no longer reported in resolution metadata
- **Reason**: Aligns with W3C DID Resolution spec for ecosystem compatibility
- **Upgrade**: Update destructuring and field references → [Full guide](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape)

#### 2. Public Proof and Signing API

- **Controller signing**: Use `createDID`, `updateDID`, and `deactivateDID` to create signed DID-log entries
- **Witness signing**: Use `signWitnessProofEntry`, which validates the candidate log, historical witness proofs, and signer membership before signing
- **Signer utilities**: `prepareDataForSigning`, `DataIntegrityProofTemplate`, and the multibase helpers support custom `Signer` implementations. A custom signer only signs and identifies its verification method; proof construction, signature verification, and DID-log/witness validation remain library responsibilities. Multibase supports base64url without padding and base58btc.
- **Reason**: Couple signing to DID:webvh operation validation
- **Upgrade**: Use DID operation methods for controller-authored log entries and `signWitnessProofEntry` for witnessing agents signing proofs → [Full guide](./UPGRADE_2.x_to_3.0.md#3-public-proof-and-signing-apis)

#### 2.1 did:key Parse Helper Root Exports Removed

- **Removed**: Root exports for `parseDidKeyDid` and `parseDidKeyVerificationMethod`
- **Retained**: `deriveNextKeyHash` remains a root export for deriving pre-rotation `nextKeyHashes`
- **Validation**: `nextKeyHashes` must contain derived hashes; pass future update keys to `deriveNextKeyHash` first
- **CLI**: Use `--next-key` to derive a hash from a future update key, or `--next-key-hash` for an already-derived hash
- **Scope**: Package root imports from `didwebvh-ts`
- **Reason**: Public API surface tightening
- **Upgrade**: Replace root imports with app-level did:key parsing or validation logic → [Full guide](./UPGRADE_2.x_to_3.0.md#32-did-key-parse-helper-root-exports)

---

### Behavior Changes (Semantics/Defaults)

#### 3. Standard DID Document Authoring (`didDocument` required on `createDID`)

- **Changed**: `createDID` now requires a full, standard W3C `didDocument: DIDDocument`. Use `{SCID}` for the specification-defined SCID placeholder, or `{DID}` as a convenience placeholder for the DID derived from the `address` option.
- **Placeholder behavior**: For example, with `address: 'example.com'`, `{DID}#key-1` is first treated as `did:webvh:{SCID}:example.com#key-1`. The runtime then calculates the SCID and replaces `{SCID}` so the published document contains the final DID, such as `did:webvh:<SCID>:example.com#key-1`. Neither placeholder remains in the created DID Document or log.
- **Removed**: Legacy partial creation fields (`verificationMethods`, `authentication`, `assertionMethod`, `keyAgreement`, `capabilityInvocation`, `capabilityDelegation`, `services`, `alsoKnownAs`) and the proprietary `purpose` field on `VerificationMethod`.
- **Reason**: Full W3C DID Core alignment, controller sovereignty over fragment IDs (`#key-1`), multi-relationship support, and removal of opinionated synthesis heuristics.
- **Upgrade**: Provide complete `didDocument` structure to `createDID` → [Full guide](./UPGRADE_2.x_to_3.0.md#2-did-document-authoring-and-removal-of-verificationmethods)

#### 4. Witness Signer Contract

- **Changed**: `signWitnessProofEntry` takes a `Signer` implementation, which returns only `{ proofValue }`; the library constructs the proof
- **Validation**: The method checks candidate log continuity, historical witness proofs, and signer membership before signing
- **Network behavior**: Witness proofs are never fetched by this method; supply `witnessProofs` explicitly
- **Reason**: Keep proof structure and authorization checks within the DID:webvh operation API
- **Upgrade**: Implement `Signer` and call `signWitnessProofEntry` → [Full guide](./UPGRADE_2.x_to_3.0.md#4-witness-signer-contract)

#### 5. Witness Metadata Shape

- **Changed**: Always an object (`{}` or `{ witnesses, threshold }`)
- **Before**: Could be `null`, `undefined`, or use `witnessThreshold` field
- **Reason**: Consistent shape; removes null handling burden
- **Upgrade**: Remove null checks; update field name references → [Full guide](./UPGRADE_2.x_to_3.0.md#5-witness-metadata-shape)

#### 6. Historical Resolution Errors

- **Changed**: Resolving an earlier version with `versionId`, `versionNumber`, or `versionTime` can return a non-null `didDocument` alongside `didResolutionMetadata.error = "invalidDid"` when a later log entry is invalid. The error reports the invalid later entry, not a failure of the selected document.
- **Witnesses**: The selected version's witness requirements must still be met before its document is returned. Proofs for an invalid log entry do not count.
- **Upgrade**: Check `didResolutionMetadata.error` even when `didDocument` is non-null; handle or report the invalid later history separately from the selected document → [Full guide](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape)

#### 7. `did-resolver` v6 Integration and DID URL Validation

- **Changed**: `getResolver()` now uses the `did-resolver` v6 `DIDParser` hook. Applications using the resolver through `did-resolver` must register it with v6.
- **Changed**: With v6, DID Core DID/DID URL syntax is checked before the `did:webvh` resolver runs. The method parser then enforces the additional did:webvh v1.0 identifier constraints, including SCID, domain, port, and deployment-path rules.
- **Compatibility**: Applications that continue to use a v5 `Resolver` will not get the v6 pre-dispatch `DIDParser` hook or its strict DID URL parsing. When the did:webvh resolver is invoked, didwebvh-ts still validates the bare DID internally, including DID Core syntax and did:webvh-specific constraints; this is not equivalent to v6 parsing the complete DID URL before dispatch.
- **Changed**: Invalid method-specific identifiers are rejected before log retrieval and surfaced as `invalidDid`. Generic DID URL syntax failures are owned by `did-resolver`; `invalidDidUrl` remains applicable when method-level query values cannot be decoded for selector processing.
- **Changed**: Single-label hosts such as `localhost` are rejected by `createDID`, `updateDID` and resolution. did:webvh v1.0 requires a fully qualified domain name (RFC 1035/1123/2181); 2.x accepted `localhost`. Use a resolvable FQDN for local development (for example `localhost.example.com` mapped in `/etc/hosts`, or a `*.localhost.direct`-style wildcard domain).
- **Changed**: `createDID({ address: 'jp納豆.例.jp', paths: ['用户'] })` emits an A-label domain in the DID, `did:webvh:<scid>:xn--jp-cd2fp15c.xn--fsq.jp:%E7%94%A8%E6%88%B7`. Raw and pre-encoded Unicode input produce the same DID. Existing percent-encoded U-label DIDs remain resolvable at their A-label HTTPS host without changing their DID string; this legacy resolution path is intended for removal after v3. Raw-Unicode DIDs are not DID Core-conformant and are rejected.
- **Changed**: `createDID` and `updateDID` emit one canonical DID for a location, whatever form the `address` takes (`host`, `https://...` or `did:webvh:...`). Domain text is mapped to lowercase A-labels (any `{SCID}` placeholder or embedded SCID keeps its case), percent-encoding uses uppercase hex for path segments, and the port separator is `%3A`. Path segments keep their case and are not Unicode-normalised. For example, `Example.COM` and `did:webvh:{SCID}:%e4%be%8b.jp%3a8443` now yield `example.com` and `xn--fsq.jp%3A8443`. Passing `updateDID` an address that canonicalises to the DID's current location is not treated as a move, so existing non-canonical DIDs are kept unchanged.
- **Added**: `migrateDID` moves a portable legacy U-label DID to its equivalent A-label DID via a signed update, retaining its SCID and history. It requires a U-label address at the same host, port, and path; it rejects A-label input and other moves. Ordinary `updateDID` still preserves the legacy DID for an equivalent address. Non-portable DIDs instead need a new A-label DID with a new SCID.
- **Added**: An optional `toASCII` converter option for creation, updates, and resolution. The default uses a conformance-checked WHATWG `URL`; `tr46` is **not** required for most users. Only runtimes without IDNA support, such as React Native, that handle non-ASCII domains need to install the optional peer `tr46` and import its converter from `didwebvh-ts/idna`.
- **Reason**: Use v6's parser extension point rather than duplicating generic DID Core parsing in didwebvh-ts.
- **Upgrade**: Upgrade applications' direct `did-resolver` dependency to v6 and handle invalid DIDs rejected before network access → [Full guide](./UPGRADE_2.x_to_3.0.md#6-did-resolver-v6-integration)

---

## Rationale

### Spec Alignment (v1.0)

The 3.0.0 release fully implements the [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/). Breaking changes align TypeScript library behavior with normative spec requirements:

- W3C DID Resolution result shape
- Witness parameter normalization
- Service endpoint derivation

### Security Hardening

Several changes reduce attack surface:

- Explicit `purpose` assignment prevents accidental misuse of keys
- Witness signer validation keeps proof metadata and authorization checks under library control
- Strict verification method formats enforce did:webvh witness requirements

### Developer Experience

Breaking changes also improve clarity:

- Standard result shapes reduce documentation burden
- Explicit field requirements reduce implicit behavior surprises
- Normalized metadata shapes simplify null handling

---

## Release Timeline

- **2.8.0**: Last release with old behavior
- **3.0.0**: New behavior (breaking release)

---

## Support

- **Full Migration Guide**: [UPGRADE_2.x_to_3.0.md](./UPGRADE_2.x_to_3.0.md)
- **Specification**: [did:webvh v1.0](https://identity.foundation/didwebvh/v1.0/)
- **Issues**: [GitHub Issues](https://github.com/decentralized-identity/didwebvh-ts/issues)
- **API Reference**: [README](../README.md#api-reference)
