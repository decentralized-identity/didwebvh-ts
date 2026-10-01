# Breaking Changes in 3.0.0

This document summarizes breaking changes in the 3.0.0 release. For detailed upgrade steps, see [UPGRADE_2.x_to_3.0.md](./UPGRADE_2.x_to_3.0.md).

## Summary

| Change | Category | Impact | Migration |
| -------- | ---------- | -------- | ----------- |
| DID Document Authoring (`didDocument`) | API / Behavior | `createDID` / `updateDID` | [UPGRADE_2.x_to_3.0.md §2](./UPGRADE_2.x_to_3.0.md#2-did-document-authoring-and-removal-of-verificationmethods) |
| Resolution result shape | API | All resolution calls | [UPGRADE_2.x_to_3.0.md §1](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape) |
| `createProof` export removed | API | Proof creation | [UPGRADE_2.x_to_3.0.md §3](./UPGRADE_2.x_to_3.0.md#3-proof-helper-exports) |
| did:key parser root exports removed | API | did:key parsing helpers | [UPGRADE_2.x_to_3.0.md §3.2](./UPGRADE_2.x_to_3.0.md#32-did-key-parse-helper-root-exports) |
| Witness callback contract | Behavior | Signer callbacks | [UPGRADE_2.x_to_3.0.md §4](./UPGRADE_2.x_to_3.0.md#4-witness-proof-callback-contract) |
| Witness metadata shape | Behavior | Metadata access | [UPGRADE_2.x_to_3.0.md §5](./UPGRADE_2.x_to_3.0.md#5-witness-metadata-shape) |

---

## By Category

### API Changes (Signature/Exports)

#### 1. Resolution Result Shape

- **Removed**: `{ did, doc, meta, controlled }` shape
- **Added**: Standard W3C `{ didDocument, didDocumentMetadata, didResolutionMetadata }` shape
- **Changed**: Local control is application-owned and is no longer reported in resolution metadata
- **Reason**: Aligns with W3C DID Resolution spec for ecosystem compatibility
- **Upgrade**: Update destructuring and field references → [Full guide](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape)

#### 2. `createProof` Export Removed

- **Removed**: Public `createProof` function
- **Current**: Use `createWitnessProof` for witness proofs
- **Reason**: `createProof` was too generic; witness proofs have strict requirements (did:key format, assertionMethod purpose)
- **Upgrade**: Replace calls with `createWitnessProof` → [Full guide](./UPGRADE_2.x_to_3.0.md#3-proof-helper-exports)

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

#### 4. Witness Proof Callback Contract

- **Changed**: Signer callbacks can only return `{ proofValue }`
- **Before**: Could override `verificationMethod`, `created`, `proofPurpose`
- **Reason**: Security hardening; witness proof verification is strict
- **Upgrade**: Remove library-controlled fields from callback returns → [Full guide](./UPGRADE_2.x_to_3.0.md#4-witness-proof-callback-contract)

#### 5. Witness Metadata Shape

- **Changed**: Always an object (`{}` or `{ witnesses, threshold }`)
- **Before**: Could be `null`, `undefined`, or use `witnessThreshold` field
- **Reason**: Consistent shape; removes null handling burden
- **Upgrade**: Remove null checks; update field name references → [Full guide](./UPGRADE_2.x_to_3.0.md#5-witness-metadata-shape)

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
- Proof callback restrictions prevent field injection attacks
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
