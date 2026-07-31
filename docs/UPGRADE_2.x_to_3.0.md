# Migration Guide: 2.x → 3.0.0

This guide covers breaking changes in the 3.0.0 release and provides step-by-step upgrade instructions.

## Overview of Breaking Changes

The 3.0.0 release aligns `didwebvh-ts` with the DIF `did:webvh` v1.0 specification and hardens security postures:

1. **Resolution result shape** — now returns W3C standard format
2. **Verification method `purpose`** — requires explicit assignment
3. **Proof helper exports** — stricter public API
4. **Witness proof callback contract** — signer supplies only signature data
5. **Witness metadata shape** — always normalized to object form

---

## 1. Resolution Result Shape

### What Changed

The `resolveDID()` and `resolveDIDFromLog()` functions now return the standard W3C `DIDResolutionResult` format instead of the implementation-specific shape.

**Old (2.x)**:

```typescript
const result = await resolveDID('did:webvh:SCID:example.com');
// { did, doc, meta, controlled }
console.log(result.did);       // string
console.log(result.doc);       // DIDDoc
console.log(result.meta);      // DIDResolutionMeta
console.log(result.controlled); // boolean
```

**New (3.0.0)**:

```typescript
const result = await resolveDID('did:webvh:SCID:example.com');
// { didDocument, didDocumentMetadata, didResolutionMetadata }
console.log(result.didDocument);           // DIDDoc | null
console.log(result.didDocumentMetadata);   // DIDDocumentMetadata
console.log(result.didResolutionMetadata); // DIDResolutionMetadata
```

### Migration Steps

1. **Update destructuring**:

   ```typescript
   // Old
   const { did, doc, meta, controlled } = await resolveDID(did);
   
   // New
   const { didDocument, didDocumentMetadata, didResolutionMetadata } = await resolveDID(did);
   ```

2. **Update field references**:

   ```typescript
   // Old
   const document = result.doc;
   const scid = result.meta.scid;
   const isControlled = result.controlled;
   
   // New
   const document = result.didDocument;
   const scid = result.didDocumentMetadata.scid;
   const isControlled = result.didResolutionMetadata.controlled; // non-standard extension
   ```

3. **Handle null didDocument** (two cases):

   ```typescript
   // New pattern: distinguish between deactivated DID vs. resolution error
   if (result.didDocument === null) {
     // Case 1: DID was deactivated (valid resolution)
     if (result.didDocumentMetadata.deactivated === true) {
       console.log('DID is deactivated');
       // You can still inspect metadata (scid, updateKeys, etc.)
     }
     // Case 2: Resolution failed (error occurred)
     else if (result.didResolutionMetadata.error) {
       const error = result.didResolutionMetadata.error;
       console.error(`Resolution failed: ${error}`);
     }
   } else {
     // Case 3: Valid active DID
     const document = result.didDocument;
   }
   ```

### Reference

See [W3C DID Resolution](https://w3c-ccg.github.io/did-resolution/) specification for the full shape.

---

## 2. Verification Method `purpose` Field

### What Changed

In 2.x, verification methods without an explicit `purpose` field implicitly entered the `authentication` relationship. In 3.0.0, the `purpose` field must be explicitly set.

**Old (2.x)**:

```typescript
const vm = {
  id: '#key-0',
  type: 'Ed25519VerificationKey2020',
  publicKeyMultibase: '...',
  // Implicitly used for authentication
};

const { did, doc } = await createDID({
  address: 'example.com',
  signer,
  verificationMethods: [vm], // ← automatically enters authentication
});
```

**New (3.0.0)**:

```typescript
const vm = {
  id: '#key-0',
  type: 'Ed25519VerificationKey2020',
  publicKeyMultibase: '...',
  purpose: 'authentication', // ← must be explicit
};

const { did, doc } = await createDID({
  address: 'example.com',
  signer,
  verificationMethods: [vm], // ← only uses purpose if set
});
```

### Migration Steps

1. **Review all verification methods** in your `createDID` / `updateDID` calls
2. **Add `purpose: 'authentication'`** to any VM used for signing:

   ```typescript
   const vm = {
     id: '#key-0',
     type: 'Ed25519VerificationKey2020',
     publicKeyMultibase: publicKeyMultibase,
     purpose: 'authentication', // ADD THIS
   };
   ```

3. **If you rely on auto-population**, add it explicitly:

   ```typescript
   // Old assumption: no purpose → authentication
   // New requirement: explicit purpose assignment
   
   updateKeys.forEach(key => {
     verificationMethods.push({
       id: `#${key.id}`,
       type: key.type,
       publicKeyMultibase: key.publicKeyMultibase,
       purpose: 'authentication', // ← required
     });
   });
   ```

### Common Patterns

- **Authentication key**: `purpose: 'authentication'`
- **Assertion key**: `purpose: 'assertionMethod'`
- **Key agreement**: `purpose: 'keyAgreement'`
- **Multiple purposes**: `purpose: ['authentication', 'assertionMethod']`

---

## 3. Proof Helper Exports

### What Changed

The `createProof` export has been removed. Witness proofs are now created exclusively via `createWitnessProof`.

**Old (2.x)**:

```typescript
import { createProof } from 'didwebvh-ts';

const proof = await createProof({
  verificationMethod: '#key-0',
  proofPurpose: 'assertionMethod',
  signer,
  // ...
});
```

**New (3.0.0)**:

```typescript
import { createWitnessProof } from 'didwebvh-ts';

const proof = await createWitnessProof(
  signerCallback,
  versionId,
  verificationMethod
);
```

### Migration Steps

1. **Identify `createProof` usage**:

   ```bash
   grep -r "createProof" src/
   ```

2. **Replace with `createWitnessProof`**:

   ```typescript
   // Old
   const proof = await createProof(options);
   
   // New
   const proof = await createWitnessProof(
     signerCallback,
     versionId,
     verificationMethod
   );
   ```

   **See Section 4** for details on how the `signerCallback` contract has changed.

### Why This Changed

The old `createProof` was overly generic and made it difficult to enforce did:webvh witness proof requirements (strict `verificationMethod` format, `proofPurpose: assertionMethod`, hardcoded `cryptosuite`, etc.). The new `createWitnessProof` is purpose-built for witness proofs with a strict callback contract that prevents misconfiguration.

---

## 4. Witness Proof Callback Contract

### What Changed

Signer callbacks passed to `createWitnessProof` now have a strict contract: they supply **only** the signature material (`proofValue`). The library controls all proof structure fields:

| Field | Controlled By | Value |
| ------- | --------------- | ------- |
| `cryptosuite` | Library | `eddsa-jcs-2022` (hardcoded, immutable) |
| `proofPurpose` | Library | `assertionMethod` (hardcoded, immutable) |
| `verificationMethod` | Function parameter | Must be a valid `did:key:...` |
| `created` | Function parameter | ISO 8601 timestamp (defaults to `now()`) |
| `proofValue` | Signer callback | Return this from your callback |

Callbacks can no longer override proof metadata — this hardens security by preventing misconfiguration.

### Migration Steps

1. **Update signer callbacks** to return only `proofValue`:

   **Old (2.x)**:

   ```typescript
   const signer = async (data) => {
     const signature = await signData(data);
     return {
       proofValue: signature,
       verificationMethod: 'did:key:...',    // ✗ not allowed in 3.0.0
       created: new Date().toISOString(),    // ✗ not allowed in 3.0.0
       proofPurpose: 'assertionMethod',      // ✗ not allowed in 3.0.0
       cryptosuite: 'eddsa-jcs-2022',        // ✗ not allowed in 3.0.0
     };
   };
   ```

   **New (3.0.0)**:

   ```typescript
   const signer = async (data) => {
     const signature = await signData(data);
     return {
       proofValue: signature, // ✓ return only this field
     };
   };
   ```

2. **Pass proof metadata via function parameters instead**:

   **Old (2.x)**: Metadata was in the callback's return object  
   **New (3.0.0)**: Metadata is passed as parameters to `createWitnessProof`

   ```typescript
   const proof = await createWitnessProof(
     // Parameter 1: Signer callback
     async (doc, proofTemplate) => ({
       proof: { 
         proofValue: await signer.sign(doc) 
       }
     }),
     // Parameter 2: versionId (target DID log version)
     '1-abc123def456',
     // Parameter 3: verificationMethod (witness key)
     'did:key:z6Mky...#z6Mky...',
     // Parameter 4: created (optional, defaults to now)
     new Date().toISOString()
   );
   ```

3. **Why this matters**: The strict callback contract ensures:
   - **Cryptosuite cannot be changed** — prevents accidental use of non-compliant algorithms
   - **Proof purpose is always `assertionMethod`** — required by did:webvh witness proofs
   - **Verification method is validated** — must be a `did:key:...` URL
   - **Signer only handles the signature** — clear separation of concerns

### Common Pattern

```typescript
const proof = await createWitnessProof(
  // Minimal signer: just convert signature bytes to hex or multibase
  async (doc) => ({
    proof: { 
      proofValue: await ed25519Signer.sign(doc) 
    }
  }),
  versionId,
  'did:key:z6MkhaXgBZDvotzX8L2j6mVGXoLDrxsEZoF36liSFmMethod#z6MkhaXgBZDvotzX8L2j6mVGXoLDrxsEZoF36liSFmMethod',
  new Date().toISOString()
);
   
   // The resulting proof will have:
   // - cryptosuite: 'eddsa-jcs-2022' (library-controlled)
   // - proofPurpose: 'assertionMethod' (library-controlled)
   // - verificationMethod: <your did:key:...> (set via parameter)
   // - proofValue: <from signer callback> (only caller-supplied data)
   ```

### Why This Changed

This is a **security hardening**. Witness proof verification in did:webvh is strict:

- `verificationMethod` must be a valid did:key (enforced via parameter validation)
- `proofPurpose` must be `assertionMethod` (hardcoded)
- `cryptosuite` must be `eddsa-jcs-2022` (hardcoded, never configurable)
- Timestamp fields must be valid (controlled by library)

Allowing callbacks to override these fields created security gaps where a malicious or misconfigured callback could break verification invariants. The library now owns all proof structure, and callbacks supply only cryptographic material (`proofValue`).

---

## 5. Witness Metadata Shape

### What Changed

The witness parameter in `didDocumentMetadata` is now always an object (`{}` or `{ witnesses, threshold }`). In 2.x, it could be `null` or use legacy field names (`witnessThreshold` instead of `threshold`).

**Old (2.x)**:

```typescript
const result = await resolveDID(did);
console.log(result.meta.witness); // null | undefined | { witnesses, witnessThreshold }
```

**New (3.0.0)**:

```typescript
const result = await resolveDID(did);
console.log(result.didDocumentMetadata.witness); // {} | { witnesses, threshold }
// Always an object; never null or undefined
```

### Migration Steps

1. **Remove null checks**:

   ```typescript
   // Old
   if (result.meta.witness !== null) {
     // process witness
   }
   
   // New (always safe to access)
   const hasWitness = result.didDocumentMetadata.witness.witnesses?.length > 0;
   ```

2. **Update field name references**:

   ```typescript
   // Old
   const threshold = result.meta.witness.witnessThreshold;
   
   // New
   const threshold = result.didDocumentMetadata.witness.threshold;
   ```

3. **Handle empty witness**:

   ```typescript
   // New pattern
   const witness = result.didDocumentMetadata.witness;
   if (witness.witnesses && witness.witnesses.length > 0) {
     // Has witness configuration
   } else {
     // No witness (but witness object still exists as {})
   }
   ```

---

## Quick Checklist

- [ ] Update `resolveDID` result destructuring (didDocument, didDocumentMetadata, didResolutionMetadata)
- [ ] Add `purpose: 'authentication'` to verification methods
- [ ] Replace `createProof` with `createWitnessProof`
- [ ] Update signer callbacks to return only `proofValue`
- [ ] Review service endpoint filtering for exact-id matching
- [ ] Remove null checks for witness metadata

---

## Still Have Questions?

- See the [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
- Open an issue on [GitHub](https://github.com/decentralized-identity/didwebvh-ts/issues)
- Check [API Reference](../README.md#api-reference) in the main README
