import type {
  DataIntegrityProof,
  DIDLog,
  DIDLogEntry,
  Verifier,
  WitnessEntry,
  WitnessParameterResolution,
  WitnessProofFileEntry,
} from '../interfaces';
import { deepClone, parseAndValidateVersionId } from '../utils';
import { concatBuffers } from '../utils/buffer';
import { canonicalizeStrict } from '../utils/canonicalize';
import { createHash } from '../utils/crypto';
import { multibaseDecode } from '../utils/multiformats';
import { parseDidKeyDid, parseDidKeyVerificationMethod } from '../utils/verification-methods';
import { hasActiveWitnessRequirement, resolveWitnessParameter, validateWitnessParameter } from '../witness-proofs';

export interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameterResolution;
}

/**
 * A single required-witness check paired with the outcome of counting
 * verified approvals against it. Used by `verifyWitnessProofs` to report an
 * unmet threshold as data rather than throwing, while other verification
 * failures (hash chain, SCID, controller proof, etc.) still throw as before.
 */
export interface WitnessCheckResult extends RequiredWitnessCheck {
  approvals: number;
  satisfied: boolean;
}

/**
 * Derives the witness configuration that governs the transition into one log
 * entry, given the configuration active before the entry and the configuration
 * active after it. This is the single authoritative implementation of the
 * did:webvh witness transition rules:
 *
 * - A non-empty previously active configuration governs the next entry, even
 *   when that entry replaces or clears the witness list.
 * - Only when the previous configuration is empty does an entry that
 *   introduces a non-empty configuration become immediately active and govern
 *   that same entry (first activation).
 *
 * Both the resolver (`resolveLog`) and the public `getWitnessRequirements` API
 * call this function so there is exactly one witness-transition state
 * machine.
 */
export const getRequiredWitnessForEntry = (
  previousWitness: WitnessParameterResolution | undefined,
  parameters: DIDLogEntry['parameters'],
  currentWitness: WitnessParameterResolution | undefined
): WitnessParameterResolution | undefined => {
  const explicitWitness = resolveWitnessParameter(parameters);

  if (hasActiveWitnessRequirement(previousWitness)) {
    return deepClone(previousWitness);
  }

  if (explicitWitness !== undefined && hasActiveWitnessRequirement(currentWitness)) {
    return deepClone(currentWitness);
  }

  return undefined;
};

/**
 * Walks a DID log and derives the witness approvals required for each entry,
 * applying the did:webvh witness transition rules (genesis activation,
 * inheritance, replacement, and removal). Performs no cryptographic
 * verification and requires no `Verifier`; only structural witness-parameter
 * validation via `validateWitnessParameter`.
 *
 * This is the pure, synchronous, verifier-independent counterpart to the
 * resolver's per-entry witness-requirement tracking. `resolveLog` and
 * `getWitnessRequirements` both derive their required-witness checks from
 * this single function.
 */
export const computeWitnessRequirementChecks = (log: DIDLog): RequiredWitnessCheck[] => {
  const checks: RequiredWitnessCheck[] = [];
  let previousWitness: WitnessParameterResolution | undefined;

  log.forEach((entry, index) => {
    const { versionNumber } = parseAndValidateVersionId(entry.versionId, index + 1);
    const explicitWitness = resolveWitnessParameter(entry.parameters);

    // All parameters in the genesis entry take effect immediately. Subsequent
    // entries inherit the previously active configuration unless they
    // explicitly declare a new one (including an explicit `witness: {}`).
    const currentWitness: WitnessParameterResolution =
      index === 0 ? (explicitWitness ?? {}) : explicitWitness !== undefined ? explicitWitness : (previousWitness ?? {});

    if (currentWitness.witnesses?.length) {
      validateWitnessParameter(currentWitness);
    }

    const requiredWitness = getRequiredWitnessForEntry(previousWitness, entry.parameters, currentWitness);
    if (requiredWitness) {
      checks.push({
        targetVersionId: entry.versionId,
        targetVersionNumber: versionNumber,
        witness: requiredWitness,
      });
    }

    previousWitness = currentWitness;
  });

  return checks;
};

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
  logEntry: DIDLogEntry,
  witnessProofs: WitnessProofFileEntry[],
  currentWitness: WitnessParameterResolution,
  verifier?: Verifier
): Promise<number> {
  if (!verifier) {
    throw new Error('Verifier implementation is required');
  }

  let approvals = 0;
  const processedWitnesses = new Set<string>();
  const witnessesByDid = new Map(
    (currentWitness.witnesses ?? []).map((witness) => {
      const parsedDid = parseDidKeyDid(witness.id);
      return [parsedDid.did, witness];
    })
  );

  for (const proofSet of witnessProofs) {
    for (const proof of proofSet.proof) {
      try {
        if (proof.type !== 'DataIntegrityProof') {
          throw new Error('Invalid witness proof type');
        }

        if (proof.proofPurpose !== 'assertionMethod') {
          throw new Error('Invalid witness proof purpose');
        }

        if (proof.cryptosuite !== 'eddsa-jcs-2022') {
          throw new Error('Invalid witness proof cryptosuite');
        }

        const parsedVerificationMethod = parseDidKeyVerificationMethod(proof.verificationMethod);
        const witness = witnessesByDid.get(parsedVerificationMethod.did);
        if (!witness || processedWitnesses.has(witness.id)) {
          continue;
        }

        const publicKeyMultibase = parsedVerificationMethod.keyMultibase;
        if (!publicKeyMultibase) {
          throw new Error(`Verification Method ${proof.verificationMethod} not found`);
        }

        const publicKey = multibaseDecode(publicKeyMultibase).bytes;
        if (publicKey.length !== 34) {
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
        const signature = multibaseDecode(proofValue).bytes;

        const verified = await verifier.verify(signature, input, publicKey.slice(2));

        if (!verified) {
          throw new Error('Invalid witness proof signature');
        }

        approvals++;
        processedWitnesses.add(witness.id);
      } catch (error) {
        const message = error instanceof Error ? error.message : String(error);
        console.warn(
          `Ignoring invalid witness proof for version ${proofSet.versionId} ` +
            `(verificationMethod: ${proof.verificationMethod}): ${message}`
        );
      }
    }
  }

  return approvals;
}
