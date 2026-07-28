import { SCID_PLACEHOLDER } from '../constants';
import { generateParallelDidWeb } from '../did-document';
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
} from '../interfaces';
import { normalizeDidAddress, requireDidDocumentId } from '../utils';
import {
  createDate,
  createNextVersionTime,
  MAX_FUTURE_SKEW_MS,
  validateUtcIso8601NotInFuture,
} from '../utils/iso8601-datetime';
import { validateWitnessParameter } from '../witness';
import { prepareDeactivationEntry, prepareGenesisEntry, prepareUpdateEntry } from './method.v1.0.entries';
import { resolveV1Log } from './method.v1.0.resolution';

const buildMetaFromEntry = (entry: DIDLogEntry): DIDResolutionMeta => {
  return {
    versionId: entry.versionId,
    created: entry.versionTime,
    updated: entry.versionTime,
    scid: entry.parameters.scid ?? '',
    updateKeys: entry.parameters.updateKeys ?? [],
    portable: entry.parameters.portable ?? false,
    nextKeyHashes: entry.parameters.nextKeyHashes ?? [],
    prerotation: (entry.parameters.nextKeyHashes?.length ?? 0) > 0,
    witness: entry.parameters.witness,
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

export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied');
  }

  if (options.witness?.witnesses && options.witness.witnesses.length > 0) {
    validateWitnessParameter(options.witness);
  }

  // Parse address input with strict validation
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

export const resolveDIDFromLog = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
): Promise<{ did: string; doc: DIDDoc | null; meta: DIDResolutionMeta }> => {
  return resolveV1Log(log, options);
};

export const updateDID = async (
  options: UpdateDIDInterface & {
    services?: ServiceEndpoint[];
    address?: string;
    paths?: string[];
  }
): Promise<UpdateDIDResult> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveDIDFromLog(log, { verifier: options.verifier, witnessProofs: options.witnessProofs }))
    .meta;
  const currentUpdateKeys = options.updateKeys;
  if (lastMeta.deactivated) {
    throw new Error('Cannot update deactivated DID');
  }
  if (lastMeta.prerotation && currentUpdateKeys === undefined) {
    throw new Error('updateKeys must be provided while pre-rotation is active');
  }
  const versionNumber = log.length + 1;
  // Validate user-provided timestamp with skew tolerance before creating the versionTime
  if (options.updated) {
    validateUtcIso8601NotInFuture(options.updated, 'updateDID updated', MAX_FUTURE_SKEW_MS);
  }
  const createdDate = createNextVersionTime(lastMeta.updated, options.updated, createDate);

  const { entry, resolvedNextKeyHashes } = await prepareUpdateEntry({
    options,
    lastEntry,
    lastMeta,
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

export const deactivateDID = async (
  options: DeactivateDIDInterface & { updateKeys?: string[] }
): Promise<{ did: string; doc: DIDDoc; meta: DIDResolutionMeta; log: DIDLog }> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveDIDFromLog(log, { verifier: options.verifier })).meta;
  if (lastMeta.deactivated) {
    throw new Error('DID already deactivated');
  }
  const versionNumber = log.length + 1;
  const createdDate = createNextVersionTime(lastMeta.updated, undefined, createDate);

  const { entry } = await prepareDeactivationEntry({
    options,
    lastEntry,
    lastMeta,
    versionNumber,
    createdDate,
  });

  const meta = mergeMetaFromEntry({
    previousMeta: lastMeta,
    entry,
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
