import type { DIDLog, DIDLogEntry, WitnessParameterResolution, WitnessProofRejection } from '../interfaces.js';
import { deepClone, parseAndValidateVersionId } from '../utils.js';
import { hasActiveWitnessRequirement, resolveWitnessParameter, validateWitnessParameter } from '../witness.js';

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
  rejectedProofs: WitnessProofRejection[];
}

/**
 * Applies one entry's normalized witness parameter to the previously active
 * witness configuration and returns the configuration active after that entry.
 *
 * The library applies the v1.0 transition model to all supported logs:
 * omitted witness configuration inherits the previous state; explicit witness
 * configuration replaces it; explicit `witness: {}` clears witnessing.
 *
 * Deprecated `witness: null` and legacy v0.5 `witnesses`/`witnessThreshold`
 * fields are tolerated by normalizing them into the same internal witness
 * shape before this transition is applied. There is no separate v0.5 witness
 * transition logic.
 */
export const transitionWitnessState = (
  previousWitness: WitnessParameterResolution | undefined,
  parameters: DIDLogEntry['parameters']
): WitnessParameterResolution => {
  return deepClone(resolveWitnessParameter(parameters) ?? previousWitness ?? {});
};

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
 * The resolver and the public `getWitnessRequirements` API both use this
 * helper when determining which configuration governs an entry. The resolver
 * retains its own entry-processing walk because it must validate and resolve
 * each log entry.
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
 * This is the pure, synchronous, verifier-independent walk used by
 * `getWitnessRequirements`. The resolver performs its own entry-processing
 * walk and shares the witness transition helper above.
 */
export const computeWitnessRequirementChecks = (log: DIDLog): RequiredWitnessCheck[] => {
  const checks: RequiredWitnessCheck[] = [];
  let previousWitness: WitnessParameterResolution | undefined;

  log.forEach((entry, index) => {
    const { versionNumber } = parseAndValidateVersionId(entry.versionId, index + 1);
    const currentWitness = transitionWitnessState(previousWitness, entry.parameters);

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
