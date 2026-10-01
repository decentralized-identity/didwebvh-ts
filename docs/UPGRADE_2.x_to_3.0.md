# Migration Guide: 2.x → 3.0.0

This guide covers breaking changes in the 3.0.0 release and provides step-by-step upgrade instructions.

## Overview of Breaking Changes

The 3.0.0 release aligns `didwebvh-ts` with the DIF `did:webvh` v1.0 specification and hardens security postures:

1. **Resolution result shape** — now returns W3C standard format
2. **Explicit DID document authoring** — callers provide complete W3C `didDocument` state
3. **Proof helper exports** — stricter public API
  - Root parser exports `parseDidKeyDid` and `parseDidKeyVerificationMethod` removed
  - `deriveNextKeyHash` remains exported for pre-rotation `nextKeyHashes`
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
   // Local control is application-owned and is not included in resolution metadata.
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

### Local DID logs and control state

Resolution no longer discovers locally controlled DIDs from library
configuration or reports a non-standard `controlled` metadata field. If an
application manages local DID logs, provide the log through the
`resolveControlledDid` option:

```typescript
const result = await resolveDID(did, {
  resolveControlledDid: async (requestedDid) => localLogs.get(requestedDid),
  witnessProofs: localWitnessProofs, // optional
});
```

Return `undefined` from the callback to use the normal HTTPS resolution path.
The callback-supplied log is validated identically to a remotely fetched log.

### Reference

See [W3C DID Resolution](https://w3c-ccg.github.io/did-resolution/) specification for the full shape.

---

## 2. DID Document Authoring and Removal of `verificationMethods`

### What Changed

In 2.x, `createDID` accepted partial parameters such as `verificationMethods`, `authentication`, `assertionMethod`, `services`, and `alsoKnownAs`, synthesizing the final DID document with auto-generated fragments and heuristic relationship mapping (including a proprietary `purpose` field).

In 3.0.0, `createDID` requires a full, standard W3C `didDocument: DIDDocument`. The caller explicitly authors the document structure using `{DID}` (or `{SCID}`) placeholders for identifiers, allowing full control over key fragments (`#key-1`), verification relationships, services, and extensions.

`{SCID}` is the specification-defined placeholder for the self-certifying identifier. `{DID}` is a convenience placeholder for the DID derived from the `address` option. For example, with `address: 'example.com'`, `{DID}#key-0` is first resolved as `did:webvh:{SCID}:example.com#key-0`; after the SCID is calculated, the runtime replaces `{SCID}` with the actual value. Both placeholders are creation-time templates only and are absent from the final DID Document and log.

**Old (2.x)**:

```typescript
const vm = {
  id: '#key-0',
  type: 'Multikey',
  publicKeyMultibase: '...',
  purpose: 'authentication',
};

const { did, doc } = await createDID({
  address: 'example.com',
  signer,
  verifier,
  updateKeys: [updateKey],
  verificationMethods: [vm], // ← partial options synthesized into doc
});
```

**New (3.0.0)**:

```typescript
const didDocument: DIDDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: '{DID}',
  verificationMethod: [
    {
      id: '{DID}#key-0', // or relative '#key-0'
      type: 'Multikey',
      controller: '{DID}',
      publicKeyMultibase: '...',
    },
  ],
  authentication: ['{DID}#key-0'],
  assertionMethod: ['{DID}#key-0'],
};

const { did, doc } = await createDID({
  address: 'example.com',
  signer,
  verifier,
  updateKeys: [updateKey],
  didDocument, // ← W3C DID document
});
```

### Migration Steps

1. **Construct a complete `didDocument`** object matching standard W3C `DIDDocument` structure.
2. **Use `{DID}` or `{SCID}` placeholders** in `id`, `controller`, verification methods, and services as needed.
3. **Explicitly assign verification relationships** (`authentication`, `assertionMethod`, `keyAgreement`, etc.) by referencing the verification method IDs.
4. **Pass `didDocument` to `createDID`**. For `updateDID`, supply `didDocument` if modifying document state, or omit it to retain the authenticated previous state.

### Common Patterns

- **Authentication relationship**: reference the verification method from `authentication`
- **Assertion relationship**: reference the verification method from `assertionMethod`
- **Key agreement relationship**: reference the verification method from `keyAgreement`
- **Multiple relationships**: include the same verification method ID in multiple arrays

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

### 3.2 did:key Parse Helper Root Exports

### What Changed

The package root no longer exports `parseDidKeyDid` and `parseDidKeyVerificationMethod`.
The `deriveNextKeyHash` helper remains exported so controllers can derive
pre-rotation `nextKeyHashes` without reimplementing did:webvh's key-hash
algorithm.

`nextKeyHashes` remains strict: `createDID` and `updateDID` expect already-derived
pre-rotation hashes and reject `did:key`, `did:key#fragment`, or bare multikey
values in that field. Use `deriveNextKeyHash(updateKey)` first; the helper
accepts a bare Ed25519 multikey, `did:key`, or `did:key` verification method and
normalizes the input before hashing.

For CLI users, `create` and `update` both accept `--next-key` for a future
update key and derive the hash internally. `--next-key-hash` remains strict and
expects an already-derived hash.

**Old (2.x)**:

```typescript
import { parseDidKeyDid, parseDidKeyVerificationMethod } from 'didwebvh-ts';
```

**New (3.0.0)**:

```typescript
// Implement did:key parsing/validation in your application code,
// or use an alternative utility in your own stack.
```

### Migration Steps

1. **Find root imports**:

  ```bash
  grep -r "parseDidKeyDid\|parseDidKeyVerificationMethod" src/
  ```

2. **Replace root imports** from `didwebvh-ts` with your application's did:key parser/validator.

3. **Keep behavior parity** with prior usage:
  - Reject non-`did:key:` identifiers where required
  - Reject malformed did:key values
  - Enforce any fragment/body matching your previous call sites relied on

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
- [ ] Replace root imports of `parseDidKeyDid` and `parseDidKeyVerificationMethod`
- [ ] Update signer callbacks to return only `proofValue`
- [ ] Review service endpoint filtering for exact-id matching
- [ ] Remove null checks for witness metadata

---

## Still Have Questions?

- See the [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
- Open an issue on [GitHub](https://github.com/decentralized-identity/didwebvh-ts/issues)
- Check [API Reference](../README.md#api-reference) in the main README
