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
  - Internal helper types `JsonPrimitive`, `JsonValue`, `JsonObject` and `ParsedDidKeyVerificationMethod` are no longer exported
4. **Witness signer contract** — signer supplies only signature data through `Signer`
5. **Witness metadata shape** — always normalized to object form
6. **did-resolver v6 integration** — upgrade direct `did-resolver` usage and account for DID URL syntax errors rejected before dispatch
7. **Strict did:webvh identifier validation** — SCID format and fully qualified domain names are enforced, and invalid identifiers are rejected before log retrieval
8. **Canonical DIDs and internationalised domains** — every address form yields one canonical DID, and Unicode domains become A-labels

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

### 3.3 Internal Helper Types

`JsonPrimitive`, `JsonValue`, `JsonObject` and `ParsedDidKeyVerificationMethod`
are no longer exported from `didwebvh-ts` or `didwebvh-ts/types`. If you
imported them, define equivalents locally:

```typescript
type JsonPrimitive = string | number | boolean | null;
type JsonValue = JsonPrimitive | JsonObject | JsonValue[];
type JsonObject = { [key: string]: JsonValue };
```

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

4. **Turn witnessing off explicitly**. In 2.x, calling `updateDID` without
   `witness` wrote `witness: {}` and turned witnessing off. In 3.0.0, as
   did:webvh v1.0 requires, an omitted `witness` is left out of the new entry
   and the active witness configuration stays in effect, so later entries
   still need witness proofs. To stop witnessing, pass `witness: {}` (or
   `null`); that entry must itself still be witnessed.

---

## 6. did-resolver v6 Integration

### What Changed

`didwebvh-ts` now depends on `did-resolver` v6. The v6 `Resolver` validates
generic DID and DID URL syntax before invoking the method resolver, and its
`ParsedDID` no longer exposes matrix parameters (`params`).

DID URL syntax errors, such as matrix parameters (`;versionId=`) or malformed
percent-encoding, are returned by did-resolver as `invalidDid` before the
did:webvh resolver runs. `invalidDidUrl` in didwebvh-ts is reserved for query
values that cannot be decoded while extracting method-level version selectors.
Version selector behavior remains unchanged: `versionId`, `versionNumber`, and
`versionTime` are accepted as query parameters, are mutually exclusive, and
unknown query parameters are ignored.

`getResolver()` also attaches a method-specific `DIDParser` to its `webvh`
resolver. After did-resolver's generic checks, it applies the did:webvh v1.0
identifier constraints (see [§7](#7-strict-didwebvh-identifier-validation)),
and an identifier it rejects is returned as `invalidDid` before the resolver
fetches a DID log.

### Migration Steps

1. **Upgrade direct `did-resolver` usage to v6** if your application constructs
   a `Resolver` and registers the `did:webvh` resolver from `didwebvh-ts`.
2. **Handle DID URL syntax errors as `invalidDid`.** Code that previously
   expected `invalidDidUrl` or `invalidOptions` for malformed DID URLs or
   matrix parameters should expect `didResolutionMetadata.error = "invalidDid"`.
3. **Continue using query parameters for version selection.** Supply only one
   of `versionId`, `versionNumber`, or `versionTime`; matrix-style DID
   parameters are not a did:webvh selector mechanism.

---

## 7. Strict did:webvh Identifier Validation

### What Changed

did:webvh identifiers are now validated against DID Core syntax and the
did:webvh v1.0 identifier rules wherever they are parsed: `createDID`
addresses, log entry `state.id` values, resolution, and URL derivation.

- The SCID must be a 46-character base58btc string. It is checked before the
  log is validated, so a malformed SCID now produces `must include a valid
  SCID` rather than a later log-validation error.
- The host must be a fully qualified domain name. Single-label hosts such as
  `localhost` or `localhost:8000` are rejected, as before for IP addresses.

### Migration Steps

1. **Use fully qualified domain names.** Replace single-label hosts in
   `createDID` addresses and test fixtures, for example `localhost:8000` →
   `localhost.example.com:8000`. For local testing without DNS or HTTPS,
   resolve in-memory logs with `resolveDIDFromLog`.
2. **Use real SCIDs in fixtures.** Placeholder SCIDs such as `scid123` no
   longer parse; use a 46-character base58btc value.
3. **Update error assertions** that matched SCID multihash messages for
   malformed SCIDs.

---

## 8. Canonical DIDs and Internationalised Domains

### What Changed

`createDID` and `updateDID` now emit one canonical DID for a location,
whatever form the `address` takes:

- Domains are NFC-normalised and converted to lowercase A-labels, so
  `BÜCHER.example` and `b%C3%BCcher.example` both become
  `xn--bcher-kva.example`. A `{SCID}` placeholder or embedded SCID keeps its
  case.
- Percent-encoding uses uppercase hex, and the port separator is `%3A`.
- Path segments are percent-encoded to DID Core `idchar`s but otherwise keep
  their case and are not Unicode-normalised.

The default `didwebvh-ts` import uses the runtime's WHATWG `URL` and needs no
extra dependency. Choose the entry point based on IDNA support:

| Consumer | Import | Setup |
| --- | --- | --- |
| Browser (including iOS Safari) or Node.js | `didwebvh-ts` | None; their `URL` handles IDNA |
| React Native on iOS or Android with an IDNA-aware `URL` polyfill | `didwebvh-ts` | None; the polyfill handles IDNA |
| React Native on iOS or Android without IDNA-aware `URL` | `didwebvh-ts/react-native` | Call `setDomainToASCII` with an app-supplied converter for Unicode domains and existing U-label DIDs |

The root import stays URL-only even when a React Native bundler selects its
`react-native` condition. The opt-in entry point falls back to `URL` if no
converter is set. Without IDNA support, non-ASCII domains fail with
`This runtime's URL implementation does not support IDNA; use an A-label (xn--) domain`.
Import the setter and all DID operations from the same `/react-native` entry
point; its converter does not configure the default import. See the
[README example](../README.md#internationalised-domain-names) for a `tr46`
adapter or supply another IDNA provider.

Existing DIDs are not rewritten:

- Percent-encoded U-label DIDs created by 2.x still resolve, fetching from the
  A-label HTTPS host when runtime IDNA or an opt-in converter is available.
  Without either, even offline resolution returns `internalError`; update and
  deactivation throw because implicit service URLs need an A-label host.
- `updateDID` keeps the existing DID when the supplied `address` canonicalises
  to its current location, and `deactivateDID` keeps it too. Only a move to a
  different location (which requires portability) produces a new, canonical
  DID.
- The new `migrateDID` explicitly moves a portable percent-encoded U-label DID
  to its A-label form.

### Migration Steps

1. **Compare against `createDID`'s output.** If you derive or store DID
   strings from the input address, use the `did` returned by `createDID`
   instead; for example, `Example.COM` now yields `example.com`.
2. **Expect A-label domains in new DIDs.** Code that displays or matches
   Unicode domains should convert A-labels for display rather than expecting
   percent-encoded U-labels.
3. **Configure IDNA where needed.** On bare React Native, either supply an
   `xn--` A-label domain before calling `createDID`, or import DID operations
   and `setDomainToASCII` from `didwebvh-ts/react-native` and configure a
   converter before using them. An A-label address alone cannot make a
   historical percent-encoded U-label DID resolvable without IDNA support.
4. **Stop using `{SCID}` in `updateDID`.** Placeholders are only valid at
   creation; pass the actual SCID in update addresses and paths.
5. **Replace raw-Unicode DIDs.** DIDs containing unencoded Unicode were never
   DID Core-conformant and are now rejected.
6. **Migrate portable U-label DIDs explicitly, if desired.** `updateDID` keeps
   an existing percent-encoded U-label DID when given an address for the same
   location. To change it to the A-label form, call `migrateDID` with the usual
   update options and a raw or percent-encoded U-label `address` at the **same
   host, port, and path**:

   ```typescript
   const { did, log } = await migrateDID({
     log: existingLog,
     signer,
     verifier,
     address: 'bücher.example.com',
   });
   // did:webvh:<scid>:b%C3%BCcher.example.com -> did:webvh:<scid>:xn--bcher-kva.example.com
   ```

   An A-label address or any change of location is rejected. The signed update
   keeps the SCID and history, adds the old DID to `alsoKnownAs`, and returns
   the new DID as `did`. Publish the appended log at the A-label HTTPS location
   before relying on the migrated DID. Portability must have been enabled at
   genesis and still be active; for non-portable DIDs, create a new A-label DID
   with a new SCID and announce the replacement. The migrated log still
   contains its original U-label genesis entry, which resolvers continue to
   verify.

   From the CLI, run `pnpm cli -- migrate --log ./did.jsonl --output
   ./migrated-did.jsonl --address bücher.example.com`, which takes the same
   options as `update`.

---

## Quick Checklist

- [ ] Update `resolveDID` result destructuring (didDocument, didDocumentMetadata, didResolutionMetadata)
- [ ] Add `purpose: 'authentication'` to verification methods
- [ ] Replace witness proof creation with `signWitnessProofEntry`
- [ ] Replace root imports of `parseDidKeyDid` and `parseDidKeyVerificationMethod`
- [ ] Define `JsonValue`/`JsonObject`/`JsonPrimitive` or `ParsedDidKeyVerificationMethod` locally if you imported them
- [ ] Implement the `Signer` interface and supply explicit historical witness proofs
- [ ] Review service endpoint filtering for exact-id matching
- [ ] Remove null checks for witness metadata
- [ ] Pass `witness: {}` to `updateDID` where you relied on omitting `witness` to turn witnessing off
- [ ] Upgrade direct `did-resolver` usage to v6 when registering `getResolver()`
- [ ] Replace single-label hosts (e.g. `localhost`) with fully qualified domain names
- [ ] Compare new DIDs against `createDID`'s canonical output; on runtimes without IDNA support use A-label domains or the opt-in React Native entry point with a converter
- [ ] Optionally migrate portable percent-encoded U-label DIDs to A-label DIDs with `migrateDID`

---

## Still Have Questions?

- See the [did:webvh v1.0 specification](https://identity.foundation/didwebvh/v1.0/)
- Open an issue on [GitHub](https://github.com/decentralized-identity/didwebvh-ts/issues)
- Check [API Reference](../README.md#api-reference) in the main README
