# Migration Guide: 2.x → 3.0.0

This guide covers breaking changes in the 3.0.0 release and provides step-by-step upgrade instructions.

## Overview of Breaking Changes

The 3.0.0 release aligns `didwebvh-ts` with the DIF `did:webvh` v1.0 specification and hardens security postures:

1. **Resolution result shape** — now returns W3C standard format
2. **Explicit DID document authoring** — callers provide complete W3C `didDocument` state
3. **Proof and signing API** — signing is performed through operation-specific APIs
  - `prepareDataForSigning` supports custom `Signer` implementations
  - Witness signing uses `signWitnessProofEntry`, which validates the candidate log before signing
  - Root parser exports `parseDidKeyDid` and `parseDidKeyVerificationMethod` removed
  - `deriveNextKeyHash` remains exported for pre-rotation `nextKeyHashes`
4. **Witness signer contract** — signer supplies only signature data through `Signer`
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

3. **Handle resolution errors independently of the selected document**:

   ```typescript
   // An invalid later entry can be reported even when an earlier version was resolved.
   if (result.didResolutionMetadata.error) {
     console.error(`Resolution error: ${result.didResolutionMetadata.error}`);
   }

   if (result.didDocument === null) {
     if (result.didDocumentMetadata.deactivated === true) {
       console.log('DID is deactivated');
     }
   } else {
     const document = result.didDocument;
   }
   ```

   With a `versionId`, `versionNumber`, or `versionTime` selector, a valid earlier
   document may be returned with `didResolutionMetadata.error = "invalidDid"`
   when a later log entry is invalid. Do not treat a non-null `didDocument` as
   proof that the entire log is valid. The selected version's witness
   requirements must still be satisfied; proofs for invalid entries do not
   count.

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

### Implicit `#files` and `#whois` Services

When either default service is missing, 3.0.0 adds it with an absolute service ID (`<did>#files` or `<did>#whois`); 2.8.0 used relative IDs (`#files` and `#whois`). Both ID forms are allowed by the specification. The generated `#files` endpoint is also now the origin with a trailing slash (for example, `https://example.com/`), rather than the bare origin (`https://example.com`). These endpoint strings identify the same root URL; the trailing slash does not indicate a different resource path in this case. Explicit service entries are not rewritten.

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

## 3. Public Proof and Signing APIs

### What Changed

Use the public operation APIs for DID:webvh signing:

- `createDID`, `updateDID`, and `deactivateDID` create and sign controller-authored DID log entries.
- `signWitnessProofEntry` validates a candidate continuation and supplied historical witness proofs, checks signer membership, and signs one witness proof for the candidate entry.
- `verifyWitnessProofs` validates witness proof files against a DID log.
- `getWitnessRequirements` reports the witness approvals required for each DID-log entry.

`prepareDataForSigning`, the `DataIntegrityProofTemplate` type, and the
multibase helpers `MultibaseEncoding`, `multibaseEncode`, and `multibaseDecode`
support the cryptographic portion of a custom `Signer`. A custom signer
implements `sign` and `getVerificationMethodId`; it does not need to implement
proof construction, signature verification, or DID log/witness validation.
Use `prepareDataForSigning` to obtain canonicalized signing bytes and the
multibase helpers to encode signature values or decode key material. The
supported multibase encodings are base64url without padding and base58btc.
Implement the `Signer` interface directly when only custom signing is needed;
`AbstractCrypto` is for implementations that also provide signature
verification. A custom `Verifier` is only needed to override the library's
default signature verifier.

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
import { signWitnessProofEntry } from 'didwebvh-ts';

const witnessProofEntry = await signWitnessProofEntry({
  trustedLog,
  candidateLog, // trustedLog plus exactly one candidate entry
  witnessSigner,
  witnessProofs, // explicitly supplied proofs for earlier entries; [] if none
});
```

### Migration Steps

1. **Identify `createProof` usage**:

   ```bash
   grep -r "createProof" src/
   ```

2. **If the proof is a did:webvh witness proof, replace it with `signWitnessProofEntry`**:

   ```typescript
   const witnessProofEntry = await signWitnessProofEntry({
     trustedLog,
     candidateLog,
     witnessSigner,
     witnessProofs: priorWitnessProofs,
   });
   ```

   For genesis witnessing, pass `trustedLog: []` and a `candidateLog`
   containing exactly the genesis entry. For a later version, `candidateLog`
   must contain exactly one entry more than `trustedLog`. Supply all required
   historical proofs explicitly; pass `[]` only when the historical proof list
   is intentionally empty. The function returns a `WitnessProofFileEntry` for
   one witness; the DID controller combines multiple witnesses' proofs for the same version in the witness proof file.

3. **For other proof types**, use an application-owned Data Integrity
   implementation suited to that proof's data model.

### Why This Changed

Public signing methods couple signing to DID:webvh operation validation,
including log continuity, key authorization, deactivation state, and witness
requirements.

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

## 4. Witness Signer Contract

### What Changed

`signWitnessProofEntry` accepts a `Signer<Pick<DIDLogEntry, 'versionId'>>`
object, not a free-standing proof callback. The signer signs the candidate
entry's `versionId` and returns only `{ proofValue }`; the library constructs
the Data Integrity proof and controls its proof metadata.

| Field | Controlled By | Value |
| ------- | --------------- | ------- |
| `cryptosuite` | Library | `eddsa-jcs-2022` (hardcoded, immutable) |
| `proofPurpose` | Library | `assertionMethod` (hardcoded, immutable) |
| `verificationMethod` | `witnessSigner.getVerificationMethodId()` | Must identify a valid did:key witness |
| `created` | Library | Generated by the library |
| `proofValue` | `witnessSigner.sign()` | Return this from the signer |

The signer must be a member of the witness list governing the candidate entry.
Before signing, the method verifies the trusted/candidate log relationship and
supplied historical proofs. It never fetches witness proofs: callers must
provide `witnessProofs`, including an explicit `[]` when the prior proof list is
empty.

### Migration Steps

Implement `Signer` with the cryptographic library and key management used by
your application. `prepareDataForSigning` can produce the bytes to sign:

```typescript
import { prepareDataForSigning, signWitnessProofEntry } from 'didwebvh-ts';
import type { DIDLogEntry, Signer } from 'didwebvh-ts';

const witnessSigner: Signer<Pick<DIDLogEntry, 'versionId'>> = {
  getVerificationMethodId: () => witnessVerificationMethod,
  async sign({ document, proof }) {
    const signingBytes = await prepareDataForSigning(document, proof);
    const signature = await signWithApplicationKey(signingBytes);
    return { proofValue: encodeSignature(signature) };
  },
};
```

`signWithApplicationKey` and `encodeSignature` above are application-provided.
The signer is only responsible for producing the signature and reporting its
verification method ID. The library builds the witness proof, verifies signer
eligibility and historical proofs, and validates the candidate log; no custom
verification or DID-webvh validation implementation is required. Do not
construct the witness proof yourself or pass proof metadata through the signer
result.

### Why This Changed

The library owns witness proof structure and performs witness membership and
log validation before signing. Keeping proof construction inside the public
operation API avoids a second, unchecked path for signing witness proofs.

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
- [ ] Replace witness proof creation with `signWitnessProofEntry`
- [ ] Replace root imports of `parseDidKeyDid` and `parseDidKeyVerificationMethod`
- [ ] Implement the `Signer` interface and supply explicit historical witness proofs
- [ ] Review service endpoint filtering for exact-id matching
- [ ] Remove null checks for witness metadata

---

## Still Have Questions?

- See the [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
- Open an issue on [GitHub](https://github.com/decentralized-identity/didwebvh-ts/issues)
- Check [API Reference](../README.md#api-reference) in the main README
