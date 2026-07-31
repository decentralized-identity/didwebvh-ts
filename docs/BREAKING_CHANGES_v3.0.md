# Breaking Changes in 3.0.0

This document summarizes breaking changes in the 3.0.0 release. For detailed upgrade steps, see [UPGRADE_2.x_to_3.0.md](./UPGRADE_2.x_to_3.0.md).

## Summary

| Change | Category | Impact | Migration |
| -------- | ---------- | -------- | ----------- |
| Resolution result shape | API | All resolution calls | [UPGRADE_2.x_to_3.0.md §1](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape) |
| Verification method `purpose` | Behavior | DID creation/update | [UPGRADE_2.x_to_3.0.md §2](./UPGRADE_2.x_to_3.0.md#2-verification-method-purpose-field) |
| `createProof` export removed | API | Proof creation | [UPGRADE_2.x_to_3.0.md §3](./UPGRADE_2.x_to_3.0.md#3-proof-helper-exports) |
| Witness callback contract | Behavior | Signer callbacks | [UPGRADE_2.x_to_3.0.md §4](./UPGRADE_2.x_to_3.0.md#4-witness-proof-callback-contract) |
| Witness metadata shape | Behavior | Metadata access | [UPGRADE_2.x_to_3.0.md §5](./UPGRADE_2.x_to_3.0.md#5-witness-metadata-shape) |

---

## By Category

### API Changes (Signature/Exports)

#### 1. Resolution Result Shape

- **Removed**: `{ did, doc, meta, controlled }` shape
- **Added**: Standard W3C `{ didDocument, didDocumentMetadata, didResolutionMetadata }` shape
- **Reason**: Aligns with W3C DID Resolution spec for ecosystem compatibility
- **Upgrade**: Update destructuring and field references → [Full guide](./UPGRADE_2.x_to_3.0.md#1-resolution-result-shape)

#### 2. `createProof` Export Removed

- **Removed**: Public `createProof` function
- **Current**: Use `createWitnessProof` for witness proofs
- **Reason**: `createProof` was too generic; witness proofs have strict requirements (did:key format, assertionMethod purpose)
- **Upgrade**: Replace calls with `createWitnessProof` → [Full guide](./UPGRADE_2.x_to_3.0.md#3-proof-helper-exports)

---

### Behavior Changes (Semantics/Defaults)

#### 3. Verification Method `purpose` Field

- **Changed**: VMs without `purpose` no longer implicitly enter `authentication`
- **Now**: `purpose` must be explicitly set
- **Reason**: Removes ambiguity; makes intent explicit
- **Upgrade**: Add `purpose: 'authentication'` to auth keys → [Full guide](./UPGRADE_2.x_to_3.0.md#2-verification-method-purpose-field)

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
