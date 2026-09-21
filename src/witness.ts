import type {
  DataIntegrityProof,
  DIDLogEntry,
  ParsedDidKeyVerificationMethod,
  Verifier,
  WitnessEntry,
  WitnessParameterResolution,
  WitnessProofFileEntry,
  WitnessProofRejection,
} from './interfaces.js';
import { concatBuffers } from './utils/buffer.js';
import { canonicalizeStrict } from './utils/canonicalize.js';
import { createHash } from './utils/crypto.js';
import { multibaseDecode } from './utils/multiformats.js';
import { parseDidKeyDid, parseDidKeyVerificationMethod } from './utils/verification-methods.js';
import { fetchWitnessProofs } from './utils.js';

export function resolveWitnessParameter(parameters: DIDLogEntry['parameters']): WitnessParameterResolution | undefined {
  if ('witness' in parameters) {
    return parameters.witness ?? {};
  }

  if ((parameters as { witnesses?: { id: string }[]; witnessThreshold?: string | number }).witnesses) {
    const legacyParameters = parameters as { witnesses: { id: string }[]; witnessThreshold?: string | number };
    return {
      witnesses: legacyParameters.witnesses,
      threshold: legacyParameters.witnessThreshold || legacyParameters.witnesses.length,
    };
  }

  return undefined;
}

export function normalizeWitnessThreshold(threshold: string | number | undefined | null): number {
  return parseInt((threshold ?? 0).toString(), 10);
}

export function hasActiveWitnessRequirement(
  witness?: WitnessParameterResolution | null
): witness is WitnessParameterResolution {
  if (!witness?.witnesses || witness.witnesses.length === 0) {
    return false;
  }

  const threshold = normalizeWitnessThreshold(witness.threshold);
  return threshold > 0;
}

export function validateWitnessParameter(witness: WitnessParameterResolution): void {
  if (!witness.witnesses || !Array.isArray(witness.witnesses) || witness.witnesses.length === 0) {
    throw new Error('Witness list cannot be empty');
  }

  const normalizedThreshold = normalizeWitnessThreshold(witness.threshold);

  if (!witness.threshold || normalizedThreshold < 1 || normalizedThreshold > witness.witnesses.length) {
    throw new Error('Witness threshold must be between 1 and the number of witnesses');
  }

  const ids = new Set<string>();
  for (const w of witness.witnesses) {
    const parsedDid = (() => {
      try {
        return parseDidKeyDid(w.id);
      } catch {
        throw new Error('Witness DIDs must be did:key format');
      }
    })();

    // did:webvh v1.0 requires witness keys to be Ed25519 multikeys.
    const keyBytes = multibaseDecode(parsedDid.keyMultibase).bytes;
    if (keyBytes.length < 2 || keyBytes[0] !== 0xed || keyBytes[1] !== 0x01) {
      throw new Error(`Witness DID key type must be Ed25519 (multicodec 0xed01): ${w.id}`);
    }

    if (ids.has(parsedDid.did)) {
      throw new Error(`Duplicate witness id: ${w.id}`);
    }
    ids.add(parsedDid.did);
  }
}

export function countWitnessApprovals(proofs: DataIntegrityProof[], witnesses: WitnessEntry[]): number {
  const processed = new Set<string>();
  const witnessesByDid = new Map(
    witnesses.map((witness) => {
      const parsedDid = parseDidKeyDid(witness.id);
      return [parsedDid.did, witness];
    })
  );

  for (const proof of proofs) {
    const parsedVerificationMethod = parseDidKeyVerificationMethod(proof.verificationMethod);
    const witness = witnessesByDid.get(parsedVerificationMethod.did);
    if (witness) {
      if (proof.cryptosuite !== 'eddsa-jcs-2022') {
        throw new Error('Invalid witness proof cryptosuite');
      }
      processed.add(witness.id);
    }
  }

  return processed.size;
}

export async function countVerifiedWitnessApprovals(
  witnessProofs: WitnessProofFileEntry[],
  currentWitness: WitnessParameterResolution,
  verifier?: Verifier
): Promise<{ approvals: number; rejectedProofs: WitnessProofRejection[] }> {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }

  let approvals = 0;
  const rejectedProofs: WitnessProofRejection[] = [];
  const processedWitnesses = new Set<string>();
  const witnessesByDid = new Map(
    (currentWitness.witnesses ?? []).map((witness) => {
      const parsedDid = parseDidKeyDid(witness.id);
      return [parsedDid.did, witness];
    })
  );

  for (const proofSet of witnessProofs) {
    for (const [proofIndex, proof] of proofSet.proof.entries()) {
      let code: WitnessProofRejection['code'] = 'invalid-signature';
      try {
        if (proof.type !== 'DataIntegrityProof') {
          code = 'invalid-proof-type';
          throw new Error('Invalid witness proof type');
        }

        if (proof.proofPurpose !== 'assertionMethod') {
          code = 'invalid-proof-purpose';
          throw new Error('Invalid witness proof purpose');
        }

        if (proof.cryptosuite !== 'eddsa-jcs-2022') {
          code = 'invalid-cryptosuite';
          throw new Error('Invalid witness proof cryptosuite');
        }

        let parsedVerificationMethod: ParsedDidKeyVerificationMethod;
        try {
          parsedVerificationMethod = parseDidKeyVerificationMethod(proof.verificationMethod);
        } catch {
          code = 'invalid-verification-method';
          throw new Error(`Invalid verification method ${proof.verificationMethod}`);
        }
        const witness = witnessesByDid.get(parsedVerificationMethod.did);
        if (!witness) {
          code = 'unknown-witness';
          throw new Error(`Witness is not in the active witness list: ${parsedVerificationMethod.did}`);
        }
        if (processedWitnesses.has(witness.id)) {
          code = 'duplicate-witness';
          throw new Error(`Witness has already provided an approval: ${witness.id}`);
        }

        const publicKeyMultibase = parsedVerificationMethod.keyMultibase;
        if (!publicKeyMultibase) {
          code = 'invalid-verification-method';
          throw new Error(`Verification Method ${proof.verificationMethod} not found`);
        }

        let publicKey: Uint8Array;
        try {
          publicKey = multibaseDecode(publicKeyMultibase).bytes;
        } catch {
          code = 'invalid-public-key';
          throw new Error(`Invalid public key in verification method ${proof.verificationMethod}`);
        }
        if (publicKey.length !== 34) {
          code = 'invalid-public-key';
          throw new Error(`Invalid public key length ${publicKey.length} (should be 34 bytes)`);
        }

        const { proofValue, ...proofWithoutValue } = proof;

        // Verify against the proof entry's own versionId (what the witness signed); a
        // later proof cumulatively approves earlier entries.
        const canonicalizedData = canonicalizeStrict({ versionId: proofSet.versionId });
        const canonicalizedProof = canonicalizeStrict(proofWithoutValue);
        const dataHash = await createHash(canonicalizedData);
        const proofHash = await createHash(canonicalizedProof);
        const input = concatBuffers(proofHash, dataHash);
        let signature: Uint8Array;
        try {
          signature = multibaseDecode(proofValue).bytes;
        } catch {
          code = 'invalid-signature';
          throw new Error('Invalid witness proof signature encoding');
        }

        const verified = await verifier.verify(signature, input, publicKey.slice(2));

        if (!verified) {
          code = 'invalid-signature';
          throw new Error('Invalid witness proof signature');
        }

        approvals++;
        processedWitnesses.add(witness.id);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        rejectedProofs.push({
          proofVersionId: proofSet.versionId,
          proofIndex,
          verificationMethod: proof.verificationMethod,
          code,
          message,
        });
        console.warn(
          `Ignoring invalid witness proof for version ${proofSet.versionId} ` +
            `(verificationMethod: ${proof.verificationMethod}): ${message}`
        );
      }
    }
  }

  return { approvals, rejectedProofs };
}

export { fetchWitnessProofs };
