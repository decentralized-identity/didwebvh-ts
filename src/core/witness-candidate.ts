/**
 * Candidate-entry verification for the witness role.
 *
 * did:webvh requires, before a witness signs anything:
 *
 *   Each witness MUST hold its own copy of the published DID Log (did.jsonl)
 *   prior to witnessing, and MUST confirm that the controller-supplied
 *   candidate entry verifies as the next entry to that DID Log.
 *
 *   Each witness MUST independently verify the candidate entry using every
 *   step in Read (Resolve). Any failure MUST cause the witness to refuse
 *   approval.
 *
 * `signWitnessProofEntry` signs a bare `{ versionId }`, so nothing in this
 * library makes those two steps happen. This module performs them and returns
 * the verified log, which the caller then signs.
 *
 * Storage, publication and circulation stay with the caller. What is added here
 * is the check the witness cannot skip, and one distinction the caller cannot
 * reconstruct afterwards: a candidate that verifies as a *different* next entry
 * for a version this witness already approved is not a malformed entry. Refusing
 * it is correct, and the two entries are the only evidence that two were
 * offered. `WitnessRefusal` carries both so the caller can keep them.
 */
import type { DIDLog, DIDLogEntry, ResolutionOptions, Verifier, WitnessProofFileEntry } from '../interfaces.js';
import { resolveDIDFromLog } from '../method.js';
import { parseAndValidateVersionId } from '../utils.js';

/** Why a witness refused to sign a candidate entry. */
export type WitnessRefusalCode =
  /** The witness's own copy of the log does not resolve. Nothing can be witnessed against it. */
  | 'held-log-invalid'
  /** The candidate is not the next version after the held log's tip. */
  | 'not-next-entry'
  /** A different entry for a version the held log already covers. Both are kept on the error. */
  | 'conflicting-entry'
  /** The candidate is the next version but fails Read (Resolve). */
  | 'candidate-invalid';

/**
 * Thrown instead of signing. `code` says which rule refused.
 *
 * For `conflicting-entry`, `heldEntry` and `candidateEntry` are the two entries
 * offered for the same version number.
 */
export class WitnessRefusal extends Error {
  readonly code: WitnessRefusalCode;
  readonly heldEntry?: DIDLogEntry;
  readonly candidateEntry?: DIDLogEntry;

  constructor(
    code: WitnessRefusalCode,
    message: string,
    entries?: { heldEntry?: DIDLogEntry; candidateEntry?: DIDLogEntry }
  ) {
    super(message);
    this.name = 'WitnessRefusal';
    this.code = code;
    this.heldEntry = entries?.heldEntry;
    this.candidateEntry = entries?.candidateEntry;
  }
}

export interface VerifyWitnessCandidateOptions {
  /** The witness's own copy of the published log, as it has approved it so far. */
  heldLog: DIDLog;
  /** The controller-supplied candidate for the next entry. */
  candidateEntry: DIDLogEntry;
  verifier?: Verifier;
  /**
   * Witness proofs already collected for earlier versions. Defaults to `[]`,
   * which keeps verification offline; passing `undefined` through to the
   * resolver would make it fetch did-witness.json over the network.
   */
  witnessProofs?: WitnessProofFileEntry[];
}

export interface VerifiedWitnessCandidate {
  /** The candidate's versionId, ready to hand to `signWitnessProofEntry`. */
  versionId: string;
  /** Held log plus the candidate: what the witness has now verified. */
  log: DIDLog;
}

/**
 * The candidate's own witness threshold cannot be met at the moment it is
 * verified: the approval being asked for is the one that would meet it. Every
 * other resolution failure is a refusal.
 *
 * The resolver reports this as a message rather than a code, so it is matched
 * on text here, pinned by a test. A typed code on the resolution result would
 * remove the match; that is the direction of the error extensions in #182.
 */
const thresholdFailureForVersion = (detail: string | undefined, versionId: string): boolean =>
  typeof detail === 'string' && detail.includes(`Witness threshold not met for version ${versionId}`);

/**
 * Verifies a candidate entry against the witness's own copy of the log.
 *
 * Resolves the held log, confirms the candidate is the next version for it, and
 * resolves held+candidate through the full Read (Resolve) path. Returns the
 * versionId to sign, or throws `WitnessRefusal`.
 */
export async function verifyWitnessCandidate(
  options: VerifyWitnessCandidateOptions
): Promise<VerifiedWitnessCandidate> {
  const { heldLog, candidateEntry } = options;

  if (!Array.isArray(heldLog) || heldLog.length === 0) {
    throw new WitnessRefusal(
      'held-log-invalid',
      'A witness must hold its own copy of the published log before witnessing; heldLog is empty'
    );
  }
  if (!candidateEntry?.versionId) {
    throw new WitnessRefusal('candidate-invalid', 'Candidate entry has no versionId', { candidateEntry });
  }

  const resolutionOptions: ResolutionOptions = {
    verifier: options.verifier,
    witnessProofs: options.witnessProofs ?? [],
  };

  // 1. The held copy itself must resolve. A witness that cannot verify what it
  //    holds has nothing to compare a candidate against.
  const held = await resolveDIDFromLog(heldLog, resolutionOptions);
  const heldError = describeError(held);
  if (heldError) {
    throw new WitnessRefusal('held-log-invalid', `The witness's own copy of the log does not resolve: ${heldError}`);
  }

  // 2. The candidate must be the next entry for that copy — not a replay, not a
  //    gap, and not a second entry for a version already covered.
  const heldTipNumber = heldLog.length;
  const expected = heldTipNumber + 1;
  let candidateNumber: number;
  try {
    candidateNumber = readVersionNumber(candidateEntry.versionId);
  } catch (e) {
    throw new WitnessRefusal('candidate-invalid', e instanceof Error ? e.message : String(e), { candidateEntry });
  }

  if (candidateNumber !== expected) {
    const heldEntry =
      candidateNumber >= 1 && candidateNumber <= heldTipNumber ? heldLog[candidateNumber - 1] : undefined;

    if (heldEntry && heldEntry.versionId !== candidateEntry.versionId) {
      throw new WitnessRefusal(
        'conflicting-entry',
        `A different entry for version ${candidateNumber} has already been witnessed: held ${heldEntry.versionId}, offered ${candidateEntry.versionId}`,
        { heldEntry, candidateEntry }
      );
    }

    throw new WitnessRefusal(
      'not-next-entry',
      `Candidate is version ${candidateNumber}; the next entry for the held log is version ${expected}`,
      { heldEntry, candidateEntry }
    );
  }

  // 3. Every step of Read (Resolve), over held + candidate.
  const combined: DIDLog = [...heldLog, candidateEntry];
  const candidate = await resolveDIDFromLog(combined, resolutionOptions);
  const candidateError = describeError(candidate);
  if (candidateError && !thresholdFailureForVersion(candidateError, candidateEntry.versionId)) {
    throw new WitnessRefusal('candidate-invalid', `Candidate entry does not verify: ${candidateError}`, {
      candidateEntry,
    });
  }

  return { versionId: candidateEntry.versionId, log: combined };
}

const readVersionNumber = (versionId: string): number => {
  const firstDashIndex = versionId.indexOf('-');
  if (firstDashIndex <= 0) {
    throw new Error(`versionId '${versionId}' must be '<version>-<entryHash>'`);
  }
  const version = versionId.slice(0, firstDashIndex);
  if (!/^\d+$/.test(version)) {
    throw new Error(`versionId '${versionId}' must have a numeric version prefix`);
  }
  const versionNumber = Number(version);
  // Reuse the library's own parser for the rest of the shape checks.
  parseAndValidateVersionId(versionId, versionNumber);
  return versionNumber;
};

const describeError = (result: Awaited<ReturnType<typeof resolveDIDFromLog>>): string | undefined => {
  const metadata = result.didResolutionMetadata as
    | { error?: string; message?: string; problemDetails?: { detail?: string } }
    | undefined;
  if (!metadata?.error) {
    return undefined;
  }
  return metadata.problemDetails?.detail ?? metadata.message ?? metadata.error;
};
