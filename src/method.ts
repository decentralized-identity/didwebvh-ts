import type { DIDResolutionResult } from 'did-resolver';
import { SCID_PLACEHOLDER } from './constants';
import { prepareDeactivationEntry, prepareGenesisEntry, prepareUpdateEntry } from './core/entries';
import { resolveV1Log } from './core/resolution';
import { generateParallelDidWeb } from './did-document';
import type {
  CreateDIDInterface,
  CreateDIDResult,
  DeactivateDIDInterface,
  DIDDoc,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  ResolutionOptions,
  ServiceEndpoint,
  UpdateDIDInterface,
  UpdateDIDResult,
  WitnessProofFileEntry,
} from './interfaces';
import { mapErrorToCode, toErrorResult, toResolutionResult, validateSingleVersionSelector } from './resolver-result';
import { fetchLogFromIdentifier, getActiveDIDs, normalizeDidAddress, requireDidDocumentId } from './utils';
import {
  createDate,
  createNextVersionTime,
  MAX_FUTURE_SKEW_MS,
  validateUtcIso8601NotInFuture,
} from './utils/iso8601-datetime';
import { defaultVerifier } from './verifier';
import { resolveWitnessParameter, validateWitnessParameter } from './witness';

const buildMetaFromEntry = (entry: DIDLogEntry): DIDResolutionMeta => {
  const resolvedWitness = resolveWitnessParameter(entry.parameters);
  return {
    versionId: entry.versionId,
    created: entry.versionTime,
    updated: entry.versionTime,
    scid: entry.parameters.scid ?? '',
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
    updated: entry.versionTime,
    updateKeys: entry.parameters.updateKeys ?? previousMeta.updateKeys,
    portable: entry.parameters.portable ?? previousMeta.portable,
    nextKeyHashes: resolvedNextKeyHashes,
    prerotation: resolvedNextKeyHashes.length > 0,
    witness: entry.parameters.witness ?? previousMeta.witness,
    watchers: entry.parameters.watchers ?? previousMeta.watchers,
    deactivated: deactivated ?? entry.parameters.deactivated ?? previousMeta.deactivated,
  };
};

/**
 * Creates a new did:webvh DID and initial DID log.
 *
 * @param options DID creation options.
 * @returns The created DID, resolved document, and DID log.
 */
export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied');
  }

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
    controller: normalizedAddress.controller,
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
 * @returns The resolved DID result with resolution metadata and controlled status.
 */
export const resolveDID = async (
  did: string,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
): Promise<DIDResolutionResult> => {
  const activeDIDs = await getActiveDIDs();
  const controlled = activeDIDs.includes(did);
  const verifier = options.verifier ?? defaultVerifier;
  // Extract the expected SCID from the DID string so the resolver can verify the log's SCID.
  const didParts = did.split(':');
  const scid = didParts.length > 2 && didParts[0] === 'did' && didParts[1] === 'webvh' ? didParts[2] : undefined;
  const selectorError = validateSingleVersionSelector(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, {
      controlled,
      problemType: selectorError.problemType,
    });
  }
  try {
    const log = await fetchLogFromIdentifier(did, controlled);
    const result = await resolveV1Log(log, { ...options, verifier, scid, requestedDid: did });
    return toResolutionResult(result, { controlled });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message, { controlled });
  }
};

/**
 * Resolves a DID from an in-memory DID log.
 *
 * @param log In-memory DID log entries.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata.
 */
export const resolveDIDFromLog = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
): Promise<DIDResolutionResult> => {
  const verifier = options.verifier ?? defaultVerifier;
  const selectorError = validateSingleVersionSelector(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, { problemType: selectorError.problemType });
  }
  try {
    const result = await resolveV1Log(log, { ...options, verifier });
    return toResolutionResult(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message);
  }
};

/**
 * Updates an existing DID log with a new entry.
 *
 * @param options DID update options.
 * @returns The updated DID, resolved document, and DID log.
 */
export const updateDID = async (
  options: UpdateDIDInterface & {
    services?: ServiceEndpoint[];
    address?: string;
    paths?: string[];
  }
): Promise<UpdateDIDResult> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveV1Log(log, { verifier: options.verifier, witnessProofs: options.witnessProofs })).meta;
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
 *
 * @param options DID deactivation options.
 * @returns The deactivated DID result and updated DID log.
 */
export const deactivateDID = async (
  options: DeactivateDIDInterface & { updateKeys?: string[] }
): Promise<{ did: string; doc: DIDDoc; meta: DIDResolutionMeta; log: DIDLog }> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveV1Log(log, { verifier: options.verifier })).meta;
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
