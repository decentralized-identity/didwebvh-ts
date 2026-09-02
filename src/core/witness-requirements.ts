import type {
  DIDLog,
  DIDLogEntry,
  WitnessParameterResolution,
  WitnessRequirement,
  WitnessVerifiableResult,
} from '../interfaces';
import { deepClone, parseAndValidateVersionId } from '../utils';
import {
  hasActiveWitnessRequirement,
  normalizeWitnessThreshold,
  resolveWitnessParameter,
  validateWitnessParameter,
} from '../witness';

export interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameterResolution;
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

/**
 * Derives the witness approvals required for every entry in `result.log` that
 * requires witnessing. Unlike inspecting the final resolved `meta.witness`,
 * this correctly distinguishes the configuration that approves a given
 * transition from the configuration that becomes active after publication.
 *
 * Synchronous and verifier-independent: it performs structural witness-list
 * validation only, not Data Integrity proof verification. Returns defensive
 * copies so callers cannot mutate state held elsewhere.
 */
export const getWitnessRequirements = (result: WitnessVerifiableResult): WitnessRequirement[] => {
  const checks = computeWitnessRequirementChecks(result.log);

  return checks.map((check) => ({
    versionId: check.targetVersionId,
    versionNumber: check.targetVersionNumber,
    threshold: normalizeWitnessThreshold(check.witness.threshold),
    witnesses: deepClone(check.witness.witnesses ?? []),
  }));
};
