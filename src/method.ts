import type { DIDDocument, DIDResolutionResult } from 'did-resolver';
import { DEFAULT_TTL_SECONDS, SCID_PLACEHOLDER } from './constants.js';
import { prepareDeactivationEntry, prepareGenesisEntry, prepareUpdateEntry } from './core/entries.js';
import { resolveLog, resolveLogWithWitnessResults } from './core/resolution.js';
import { computeWitnessRequirementChecks } from './core/witness-requirements.js';
import { generateParallelDidWeb } from './did-document.js';
import type {
  CreateDIDOptions,
  CreateDIDResult,
  DeactivateDIDOptions,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  ResolutionOptions,
  UpdateDIDOptions,
  UpdateDIDResult,
  VerifyWitnessProofsOptions,
  WitnessProofFileEntry,
  WitnessRequirement,
  WitnessVerificationResult,
} from './interfaces.js';
import { mapErrorToCode, toErrorResult, toResolutionResult, validateSingleVersionSelector } from './resolver-result.js';
import {
  createDate,
  createNextVersionTime,
  MAX_FUTURE_SKEW_MS,
  validateUtcIso8601NotInFuture,
} from './utils/iso8601-datetime.js';
import { normalizeUpdateKeys } from './utils/verification-methods.js';
import {
  deepClone,
  fetchLogFromIdentifier,
  normalizeDidAddress,
  parseDidWebvhIdentifier,
  requireDidDocumentId,
} from './utils.js';
import { defaultVerifier } from './verifier.js';
import { normalizeWitnessThreshold, resolveWitnessParameter, validateWitnessParameter } from './witness.js';

const buildMetaFromEntry = (entry: DIDLogEntry): DIDResolutionMeta => {
  const resolvedWitness = resolveWitnessParameter(entry.parameters);
  return {
    versionId: entry.versionId,
    versionTime: entry.versionTime,
    created: entry.versionTime,
    updated: entry.versionTime,
    scid: entry.parameters.scid ?? '',
    ttl:
      entry.parameters.ttl !== undefined && entry.parameters.ttl !== null
        ? String(entry.parameters.ttl)
        : DEFAULT_TTL_SECONDS,
    updateKeys: entry.parameters.updateKeys ?? [],
    portable: entry.parameters.portable ?? false,
    nextKeyHashes: entry.parameters.nextKeyHashes ?? [],
    prerotation: (entry.parameters.nextKeyHashes?.length ?? 0) > 0,
    witness: resolvedWitness ?? {},
    watchers: entry.parameters.watchers ?? [],
    deactivated: entry.parameters.deactivated ?? false,
  };
};

const mergeMetaFromEntry = ({
  previousMeta,
  entry,
  nextKeyHashes,
  deactivated,
}: {
  previousMeta: DIDResolutionMeta;
  entry: DIDLogEntry;
  nextKeyHashes?: string[];
  deactivated?: boolean;
}): DIDResolutionMeta => {
  const resolvedNextKeyHashes = nextKeyHashes ?? previousMeta.nextKeyHashes;

  return {
    ...previousMeta,
    versionId: entry.versionId,
    versionTime: entry.versionTime,
    updated: entry.versionTime,
    updateKeys: entry.parameters.updateKeys ?? previousMeta.updateKeys,
    portable: entry.parameters.portable ?? previousMeta.portable,
    ttl:
      entry.parameters.ttl !== undefined && entry.parameters.ttl !== null
        ? String(entry.parameters.ttl)
        : previousMeta.ttl,
    nextKeyHashes: resolvedNextKeyHashes,
    prerotation: resolvedNextKeyHashes.length > 0,
    witness: entry.parameters.witness ?? previousMeta.witness,
    watchers: entry.parameters.watchers ?? previousMeta.watchers,
    deactivated: deactivated ?? entry.parameters.deactivated ?? previousMeta.deactivated,
  };
};

/**
 * Creates a new did:webvh DID and initial DID log.
 * updateKeys accepts Ed25519 multikeys or did:key identifiers (with an optional
 * matching fragment); entries and metadata always contain bare multikeys.
 *
 * @param options DID creation options.
 * @returns The created DID, resolved document, and DID log.
 */
export const createDID = async (options: CreateDIDOptions): Promise<CreateDIDResult> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied');
  }
  options = { ...options, updateKeys: normalizeUpdateKeys(options.updateKeys) };

  if (options.witness?.witnesses && options.witness.witnesses.length > 0) {
    validateWitnessParameter(options.witness);
  }

  const addressInput = options.address;
  if (!addressInput) {
    throw new Error('Address must be provided');
  }

  const normalizedAddress = normalizeDidAddress({
    address: addressInput,
    scid: SCID_PLACEHOLDER,
    paths: options.paths,
    context: 'createDID path segments',
  });
  if (options.created) {
    validateUtcIso8601NotInFuture(options.created, 'createDID created');
  }
  const createdDate = options.created ?? createDate();

  const { entry } = await prepareGenesisEntry({
    options,
    did: normalizedAddress.did,
    createdDate,
  });

  const didId = requireDidDocumentId(entry.state.id);
  const webDoc = options.alsoKnownAsWeb ? generateParallelDidWeb(didId, entry.state) : undefined;

  return {
    did: didId,
    doc: entry.state,
    meta: buildMetaFromEntry(entry),
    log: [entry],
    ...(webDoc ? { webDoc } : {}),
  };
};

/**
 * Resolves a DID by fetching and validating its DID log.
 *
 * @param did The DID to resolve.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata.
 */
export const resolveDID = async (did: string, options: ResolutionOptions = {}): Promise<DIDResolutionResult> => {
  const verifier = options.verifier ?? defaultVerifier;
  const selectorError = validateSingleVersionSelector(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, { problemType: selectorError.problemType });
  }

  try {
    // Validate the requested identifier before asking the caller to locate a controlled log.
    const { scid } = parseDidWebvhIdentifier(did, 'DID');
    const controlledLog = options.resolveControlledDid ? await options.resolveControlledDid(did) : undefined;
    const log = controlledLog ?? (await fetchLogFromIdentifier(did));
    const result = await resolveLog(log, { ...options, verifier, scid, requestedDid: did });
    return toResolutionResult(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message);
  }
};

/**
 * Resolves a DID from an in-memory DID log.
 *
 * @param log In-memory DID log entries.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata.
 */
export const resolveDIDFromLog = async (log: DIDLog, options: ResolutionOptions = {}): Promise<DIDResolutionResult> => {
  const verifier = options.verifier ?? defaultVerifier;
  const selectorError = validateSingleVersionSelector(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, { problemType: selectorError.problemType });
  }
  try {
    const result = await resolveLog(log, { ...options, verifier });
    return toResolutionResult(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message);
  }
};

/**
 * Updates an existing DID log with a new entry.
 * Supplied updateKeys are normalized from Ed25519 multikeys or did:key identifiers
 * to bare multikeys before preparation, including pre-rotation hash checks.
 *
 * @param options DID update options.
 * @returns The updated DID, resolved document, and DID log.
 */
export const updateDID = async (options: UpdateDIDOptions): Promise<UpdateDIDResult> => {
  if (options.updateKeys !== undefined) {
    options = { ...options, updateKeys: normalizeUpdateKeys(options.updateKeys) };
  }
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveLog(log, { verifier: options.verifier, witnessProofs: options.witnessProofs })).meta;
  const currentUpdateKeys = options.updateKeys;
  if (lastMeta.deactivated) {
    throw new Error('Cannot update deactivated DID');
  }
  if (lastMeta.prerotation && currentUpdateKeys === undefined) {
    throw new Error('updateKeys must be provided while pre-rotation is active');
  }
  const versionNumber = log.length + 1;
  if (options.updated) {
    validateUtcIso8601NotInFuture(options.updated, 'updateDID updated', MAX_FUTURE_SKEW_MS);
  }
  const createdDate = createNextVersionTime(lastMeta.updated, options.updated, createDate);

  const { entry, resolvedNextKeyHashes } = await prepareUpdateEntry({
    options,
    lastEntry,
    lastMeta,
    log,
    versionNumber,
    createdDate,
  });

  const meta = mergeMetaFromEntry({
    previousMeta: lastMeta,
    entry,
    nextKeyHashes: resolvedNextKeyHashes ?? lastMeta.nextKeyHashes,
  });

  const hasWebAlias = (entry.state.alsoKnownAs ?? []).some((alias: string) => alias.startsWith('did:web:'));
  const updatedDidId = requireDidDocumentId(entry.state.id);
  const webDoc = hasWebAlias ? generateParallelDidWeb(updatedDidId, entry.state) : undefined;

  return {
    did: updatedDidId,
    doc: entry.state,
    meta,
    log: [...log, entry],
    ...(webDoc ? { webDoc } : {}),
  };
};

/**
 * Deactivates an existing DID by appending a deactivation entry.
 * Supplied updateKeys are normalized from Ed25519 multikeys or did:key identifiers
 * to bare multikeys before preparation, including pre-rotation hash checks.
 *
 * @param options DID deactivation options.
 * @returns The deactivated DID result and updated DID log.
 */
export const deactivateDID = async (
  options: DeactivateDIDOptions & { updateKeys?: string[] }
): Promise<{ did: string; doc: DIDDocument; meta: DIDResolutionMeta; log: DIDLog }> => {
  if (options.updateKeys !== undefined) {
    options = { ...options, updateKeys: normalizeUpdateKeys(options.updateKeys) };
  }
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveLog(log, { verifier: options.verifier, witnessProofs: options.witnessProofs })).meta;
  if (lastMeta.deactivated) {
    throw new Error('DID already deactivated');
  }
  if (lastMeta.prerotation && options.updateKeys === undefined) {
    throw new Error('updateKeys must be provided while pre-rotation is active');
  }
  const versionNumber = log.length + 1;
  const createdDate = createNextVersionTime(lastMeta.updated, undefined, createDate);

  const { entry } = await prepareDeactivationEntry({
    options,
    lastEntry,
    lastMeta,
    log,
    versionNumber,
    createdDate,
  });

  const meta = mergeMetaFromEntry({
    previousMeta: lastMeta,
    entry,
    // Deactivation closes any pending rotation, matching the entry's parameters.
    nextKeyHashes: [],
    deactivated: true,
  });

  const didId = requireDidDocumentId(entry.state.id);

  return {
    did: didId,
    doc: entry.state,
    meta,
    log: [...log, entry],
  };
};

/**
 * Derives the witness approvals required for each entry in a DID log that requires witnessing.
 *
 * @param log The DID log to inspect.
 * @returns The witness requirements for each entry that requires witnessing.
 */
export const getWitnessRequirements = (log: DIDLog): WitnessRequirement[] => {
  const checks = computeWitnessRequirementChecks(log);

  return checks.map((check) => ({
    versionId: check.targetVersionId,
    versionNumber: check.targetVersionNumber,
    threshold: normalizeWitnessThreshold(check.witness.threshold),
    witnesses: deepClone(check.witness.witnesses ?? []),
  }));
};

/**
 * Verifies that every witness requirement in a DID log is satisfied by the locally supplied
 * witness proofs without network fetch.
 *
 * @param log The DID log to verify.
 * @param witnessProofs The witness proofs to verify against the log, in place of a network fetch.
 * @param options Optional verifier override.
 * @returns Per-entry witness requirements annotated with counted approvals and satisfaction.
 * @throws If the log or supplied proofs fail any non-witness-threshold verification.
 */
export const verifyWitnessProofs = async (
  log: DIDLog,
  witnessProofs: WitnessProofFileEntry[],
  options: VerifyWitnessProofsOptions = {}
): Promise<WitnessVerificationResult> => {
  const { witnessChecks: checkOutcomes } = await resolveLogWithWitnessResults(log, {
    witnessProofs,
    verifier: options.verifier ?? defaultVerifier,
  });

  const requirements = checkOutcomes.map((check) => ({
    versionId: check.targetVersionId,
    versionNumber: check.targetVersionNumber,
    threshold: normalizeWitnessThreshold(check.witness.threshold),
    witnesses: deepClone(check.witness.witnesses ?? []),
    approvals: check.approvals,
    satisfied: check.satisfied,
  }));

  return {
    verified: requirements.every((requirement) => requirement.satisfied),
    requirements,
    rejectedProofs: checkOutcomes.flatMap((check) => check.rejectedProofs),
  };
};
