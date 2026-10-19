# Breaking Changes in 3.0.0

This document summarizes breaking changes in the 3.0.0 release. For detailed upgrade steps, see [UPGRADE_2.x_to_3.0.md](./UPGRADE_2.x_to_3.0.md).

## Summary

| Change | Category | Impact | Migration |
| -------- | ---------- | -------- | ----------- |
| DID Document Authoring (`didDocument`) | API / Behavior | `createDID` / `updateDID` | [UPGRADE_2.x_to_3.0.md §2](./UPGRADE_2.x_to_3.0.md#2-did-document-authoring-and-removal-of-verificationmethods) |
| Resolution result shape | API | All resolution calls | [UPGRADE_2.x_to_3.0.md §1](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape) |
| Proof/signing API narrowed | API / Security | Proof creation and witness signing | [UPGRADE_2.x_to_3.0.md §3](./UPGRADE_2.x_to_3.0.md#3-public-proof-and-signing-apis) |
| did:key parser root exports removed | API | did:key parsing helpers | [UPGRADE_2.x_to_3.0.md §3.2](./UPGRADE_2.x_to_3.0.md#32-did-key-parse-helper-root-exports) |
| Internal helper types removed from exports | API | Type imports | [UPGRADE_2.x_to_3.0.md §3.3](./UPGRADE_2.x_to_3.0.md#33-internal-helper-types) |
| Witness signer contract | Behavior | Witness signing | [UPGRADE_2.x_to_3.0.md §4](./UPGRADE_2.x_to_3.0.md#4-witness-signer-contract) |
| Witness metadata shape | Behavior | Metadata access | [UPGRADE_2.x_to_3.0.md §5](./UPGRADE_2.x_to_3.0.md#5-witness-metadata-shape) |
| Historical resolution errors | Behavior | Historical resolution results | [UPGRADE_2.x_to_3.0.md §1](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape) |
| `did-resolver` v6 integration and DID URL validation | Integration / Behavior | Resolver registration and invalid DID URL handling | [UPGRADE_2.x_to_3.0.md §6](./UPGRADE_2.x_to_3.0.md#6-did-resolver-v6-integration) |
| Strict did:webvh v1.0 identifier validation | Behavior | DID creation, resolution, and URL derivation | [UPGRADE_2.x_to_3.0.md §7](./UPGRADE_2.x_to_3.0.md#7-strict-didwebvh-identifier-validation) |

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

#### 2.2 Internal Helper Types Removed from Exports

- **Removed**: `JsonPrimitive`, `JsonValue`, `JsonObject` and `ParsedDidKeyVerificationMethod` are no longer exported from `didwebvh-ts` or `didwebvh-ts/types`
- **Reason**: They describe internal canonicalization and did:key parsing details, not the public API
- **Upgrade**: Define equivalent types in your application → [Full guide](./UPGRADE_2.x_to_3.0.md#33-internal-helper-types)

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
- **Changed**: `ResolutionMeta.watchers` is `[]` when a log has no watchers; it was `null` in 2.8.0
- **Changed**: `updateDID` with `witness` omitted keeps the active witness configuration by leaving `witness` out of the new entry's parameters, as did:webvh v1.0 requires. In 2.x, omitting `witness` wrote `witness: {}` and turned witnessing off for later entries. Pass `witness: {}` or `null` to turn witnessing off explicitly.
- **Reason**: Consistent shape; removes null handling burden
- **Upgrade**: Remove null checks; update field name references; pass `witness: {}` where an update relied on omission to stop witnessing → [Full guide](./UPGRADE_2.x_to_3.0.md#5-witness-metadata-shape)

#### 6. Historical Resolution Errors

- **Changed**: Resolving an earlier version with `versionId`, `versionNumber`, or `versionTime` can return a non-null `didDocument` alongside `didResolutionMetadata.error = "invalidDid"` when a later log entry is invalid. The error reports the invalid later entry, not a failure of the selected document.
- **Witnesses**: The selected version's witness requirements must still be met before its document is returned. Proofs for an invalid log entry do not count.
- **Upgrade**: Check `didResolutionMetadata.error` even when `didDocument` is non-null; handle or report the invalid later history separately from the selected document → [Full guide](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape)

#### 7. `did-resolver` v6 Integration and DID URL Validation

- **Changed**: `didwebvh-ts` depends on `did-resolver` v6. Applications using `getResolver()` through `did-resolver` must register it with a v6 `Resolver`.
- **Changed**: With v6, DID Core DID/DID URL syntax is checked by `did-resolver` before the `did:webvh` resolver runs. Syntax errors, including matrix parameters (`;versionId=`) and malformed percent-encoding, surface as `invalidDid`.
- **Changed**: `invalidDidUrl` now only applies when a syntactically valid query value cannot be decoded for method-level selector processing.
- **Changed**: `getResolver()` attaches a did:webvh `DIDParser` through the v6 parser hook. Identifiers that fail did:webvh v1.0 constraints (§8) are rejected as `invalidDid` before the DID log is fetched.
- **Compatibility**: Applications that continue to use a v5 `Resolver` will not get the v6 pre-dispatch `DIDParser` hook or its strict DID URL parsing, and matrix-style selectors (`;versionId=`) are ignored rather than rejected. When the did:webvh resolver is invoked, didwebvh-ts still validates the bare DID internally, including DID Core syntax and did:webvh-specific constraints; this is not equivalent to v6 parsing the complete DID URL before dispatch. Use v6.
- **Reason**: v6 removes `ParsedDID.params` and owns generic DID URL parsing, so didwebvh-ts no longer duplicates it.
- **Upgrade**: Upgrade applications' direct `did-resolver` dependency to v6 and handle DID URL syntax errors reported as `invalidDid` → [Full guide](./UPGRADE_2.x_to_3.0.md#6-did-resolver-v6-integration)

#### 8. Strict did:webvh v1.0 Identifier Validation

- **Changed**: did:webvh identifiers are validated against DID Core syntax (via `did-resolver`'s `parse`) and the did:webvh v1.0 identifier rules wherever they are parsed: `createDID` addresses, log entry `state.id` values, resolution, and URL derivation.
- **Changed**: The SCID must be a 46-character base58btc string. A malformed SCID is rejected before the log is validated, so errors such as `SCID multihash algorithm must be SHA-256` are now reported as `must include a valid SCID`.
- **Changed**: The host must be a fully qualified domain name. Single-label hosts such as `localhost` (with or without a port) are rejected; use a name such as `localhost.example.com` for local testing, or resolve in-memory logs with `resolveDIDFromLog`.
- **Reason**: Align identifier handling with the did:webvh v1.0 specification and reject invalid identifiers before network access.
- **Upgrade**: Replace single-label hosts with fully qualified domain names and update any assertions on SCID error messages → [Full guide](./UPGRADE_2.x_to_3.0.md#7-strict-didwebvh-identifier-validation)

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
