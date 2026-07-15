import { documentStateIsValid, hashChainValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions';
import { METHOD_PARAMETER_KEYS, METHOD_PROTOCOL_V1_0, SCID_PLACEHOLDER } from '../constants';
import { addDefaultDidWebvhServices } from '../did-document';
import type {
  DIDDoc,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  ResolutionOptions,
  WitnessParameterResolution,
  WitnessProofFileEntry,
} from '../interfaces';
import { buildProblemDetails } from '../resolver-result';
import {
  deepClone,
  parseAndValidateVersionId,
  parseDidWebvhIdentifier,
  replaceValueInObject,
  requireDidDocumentId,
} from '../utils';
import { deriveHash } from '../utils/crypto';
import { MAX_FUTURE_SKEW_MS, parseUtcIso8601VersionTime } from '../utils/iso8601-datetime';
import {
  countVerifiedWitnessApprovals,
  fetchWitnessProofs,
  hasActiveWitnessRequirement,
  normalizeWitnessThreshold,
  resolveWitnessParameter,
  validateWitnessParameter,
} from '../witness';

const hasOwn = <K extends PropertyKey>(obj: object, key: K): obj is Record<K, unknown> => Object.hasOwn(obj, key);

interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameterResolution;
}

interface ResolutionSnapshot {
  did: string;
  doc: DIDDoc | null;
  meta: DIDResolutionMeta;
}

interface ResolverContext {
  meta: DIDResolutionMeta;
  host: string;
  previousVersionTime: Date | undefined;
  did: string;
  doc: DIDDoc | null;
  resolvedSnapshot: ResolutionSnapshot | null;
  lastValidSnapshot: ResolutionSnapshot | null;
  requiredWitnessChecks: RequiredWitnessCheck[];
  didIdMatchCount: number;
  witnessThresholdFailure: boolean;
}

interface ParsedResolutionEntryContext {
  entry: DIDLogEntry;
  parsedVersion: {
    versionId: string;
    version: string;
    versionNumber: number;
    entryHash: string;
  };
  currentVersionTime: Date;
  parsedStateDid: ReturnType<typeof parseDidWebvhIdentifier>;
}

const createInitialResolverContext = (): ResolverContext => {
  return {
    meta: {
      versionId: '',
      created: '',
      updated: '',
      deactivated: false,
      portable: false,
      scid: '',
      updateKeys: [],
      nextKeyHashes: [],
      prerotation: false,
      witness: undefined,
      watchers: null,
    },
    host: '',
    previousVersionTime: undefined,
    did: '',
    doc: null,
    resolvedSnapshot: null,
    lastValidSnapshot: null,
    requiredWitnessChecks: [],
    didIdMatchCount: 0,
    witnessThresholdFailure: false,
  };
};

const validateAndParseLogEntry = ({
  entry,
  expectedVersionNumber,
  previousVersionTime,
}: {
  entry: DIDLogEntry;
  expectedVersionNumber: number;
  previousVersionTime: Date | undefined;
}): ParsedResolutionEntryContext => {
  const { versionId, versionTime } = entry;
  const { version, versionNumber, entryHash } = parseAndValidateVersionId(versionId, expectedVersionNumber);

  if (!versionTime) {
    throw new Error(`version '${version}' is missing versionTime`);
  }

  const currentVersionTime = parseUtcIso8601VersionTime(versionTime, `version '${version}' versionTime`);
  if (previousVersionTime && currentVersionTime.getTime() <= previousVersionTime.getTime()) {
    throw new Error(`versionTime for version '${version}' must be greater than previous entry time`);
  }

  const maxAllowedFutureTime = Date.now() + MAX_FUTURE_SKEW_MS;
  if (currentVersionTime.getTime() > maxAllowedFutureTime) {
    throw new Error(`versionTime for version '${version}' must not be more than 5 minutes in the future`);
  }

  const parsedStateDid = parseDidWebvhIdentifier(requireDidDocumentId(entry.state.id), `version '${version}' state.id`);

  return {
    entry,
    parsedVersion: {
      versionId,
      version,
      versionNumber,
      entryHash,
    },
    currentVersionTime,
    parsedStateDid,
  };
};

const processV1GenesisEntry = async ({
  resolverContext,
  entryContext,
  options,
}: {
  resolverContext: ResolverContext;
  entryContext: ParsedResolutionEntryContext;
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
}): Promise<DIDDoc> => {
  const { entry: sourceEntry, parsedStateDid } = entryContext;
  const { versionTime, parameters, proof } = sourceEntry;

  resolverContext.meta.created = versionTime;
  resolverContext.host = parsedStateDid.locationKey;
  resolverContext.meta.scid = parameters.scid as string;
  if (options.scid && options.scid !== resolverContext.meta.scid) {
    throw new Error(`SCID in DID '${options.scid}' does not match SCID in log '${resolverContext.meta.scid}'`);
  }
  resolverContext.meta.portable = parameters.portable ?? resolverContext.meta.portable;
  resolverContext.meta.updateKeys = parameters.updateKeys as string[];
  resolverContext.meta.nextKeyHashes = parameters.nextKeyHashes || [];
  resolverContext.meta.prerotation = resolverContext.meta.nextKeyHashes.length > 0;
  resolverContext.meta.witness = parameters.witness || resolverContext.meta.witness;
  resolverContext.meta.watchers = parameters.watchers ?? null;

  const logEntry = {
    versionId: SCID_PLACEHOLDER,
    versionTime: resolverContext.meta.created,
    parameters: replaceValueInObject(parameters, resolverContext.meta.scid, SCID_PLACEHOLDER),
    state: replaceValueInObject(sourceEntry.state, resolverContext.meta.scid, SCID_PLACEHOLDER),
  };

  const logEntryHash = await deriveHash(logEntry);
  resolverContext.meta.previousLogEntryHash = logEntryHash;
  if (!(await scidIsFromHash(resolverContext.meta.scid, logEntryHash))) {
    throw new Error(`SCID '${resolverContext.meta.scid}' not derived from logEntryHash '${logEntryHash}'`);
  }

  if (parsedStateDid.scid !== resolverContext.meta.scid) {
    throw new Error(
      `SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${resolverContext.meta.scid}'`
    );
  }

  const prelimEntry = replaceValueInObject(logEntry, SCID_PLACEHOLDER, resolverContext.meta.scid);

  const logEntryHash2 = await deriveHash(prelimEntry);
  const verified = await documentStateIsValid(
    { ...prelimEntry, versionId: `1-${logEntryHash2}`, proof },
    resolverContext.meta.updateKeys,
    resolverContext.meta.witness,
    false,
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${resolverContext.meta.versionId} failed verification of the proof.`);
  }

  return sourceEntry.state;
};

const processV1SubsequentEntry = async ({
  resolverContext,
  entryContext,
  logEntries,
  entryIndex,
  activeMethod,
  options,
}: {
  resolverContext: ResolverContext;
  entryContext: ParsedResolutionEntryContext;
  logEntries: DIDLog;
  entryIndex: number;
  activeMethod: string;
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
}): Promise<DIDDoc> => {
  const {
    entry: sourceEntry,
    parsedVersion: { version, entryHash },
    parsedStateDid,
  } = entryContext;
  const { parameters } = sourceEntry;

  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.method)) {
    const entryMethod = parameters.method as string;
    if (entryMethod !== activeMethod) {
      throw new Error(
        `version '${version}' has unsupported or downgraded method '${entryMethod}'; ` + `expected '${activeMethod}'`
      );
    }
  }

  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.scid)) {
    throw new Error(`version '${version}' must not contain SCID parameter`);
  }

  if (parameters.portable === true && !resolverContext.meta.portable) {
    throw new Error(
      `version '${version}' cannot set portable: true; portability can only be enabled in the first entry`
    );
  }

  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.portable) && parameters.portable === false) {
    resolverContext.meta.portable = false;
  }

  if (parsedStateDid.scid !== resolverContext.meta.scid) {
    throw new Error(
      `SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${resolverContext.meta.scid}'`
    );
  }

  const newLocation = parsedStateDid.locationKey;
  if (!resolverContext.meta.portable && newLocation !== resolverContext.host) {
    throw new Error('Cannot move DID: portability is disabled');
  } else if (newLocation !== resolverContext.host) {
    resolverContext.host = newLocation;
  }

  const { proof: _proof, ...entryWithoutProof } = logEntries[entryIndex];
  const recomputedHash = await deriveHash({ ...entryWithoutProof, versionId: logEntries[entryIndex - 1].versionId });
  if (!hashChainValid(recomputedHash, entryHash)) {
    throw new Error(`Hash chain broken at '${resolverContext.meta.versionId}'`);
  }

  const keys = resolverContext.meta.prerotation ? (parameters.updateKeys as string[]) : resolverContext.meta.updateKeys;
  const verified = await documentStateIsValid(
    logEntries[entryIndex],
    keys,
    resolverContext.meta.witness,
    false,
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${resolverContext.meta.versionId} failed verification of the proof.`);
  }

  if (resolverContext.meta.prerotation) {
    await newKeysAreInNextKeys(parameters.updateKeys ?? [], resolverContext.meta.nextKeyHashes ?? []);
  }

  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.updateKeys)) {
    resolverContext.meta.updateKeys = parameters.updateKeys ?? [];
  }
  if (parameters.deactivated === true) {
    resolverContext.meta.deactivated = true;
  }
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.nextKeyHashes)) {
    resolverContext.meta.nextKeyHashes = parameters.nextKeyHashes ?? [];
    resolverContext.meta.prerotation = resolverContext.meta.nextKeyHashes.length > 0;
  }
  const normalizedWitness = resolveWitnessParameter(parameters);

  if (normalizedWitness !== undefined) {
    resolverContext.meta.witness = normalizedWitness;
  }
  if (resolverContext.meta.witness?.witnesses?.length) {
    validateWitnessParameter(resolverContext.meta.witness);
  }
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.watchers)) {
    resolverContext.meta.watchers = parameters.watchers ?? null;
  }

  return sourceEntry.state;
};

const enforceRequiredWitnessChecks = async ({
  requiredWitnessChecks,
  witnessProofs,
  did,
  logEntries,
  verifier,
  onThresholdFailure,
}: {
  requiredWitnessChecks: RequiredWitnessCheck[];
  witnessProofs: WitnessProofFileEntry[] | undefined;
  did: string;
  logEntries: DIDLog;
  verifier: ResolutionOptions['verifier'];
  onThresholdFailure: () => void;
}): Promise<void> => {
  let resolvedWitnessProofs = witnessProofs;
  if (!resolvedWitnessProofs) {
    resolvedWitnessProofs = await fetchWitnessProofs(did);
  }

  const publishedVersionNumbers = new Map(logEntries.map((entry, index) => [entry.versionId, index + 1]));

  for (const check of requiredWitnessChecks) {
    const candidateProofs = resolvedWitnessProofs.filter((witnessProof) => {
      const proofVersionNumber = publishedVersionNumbers.get(witnessProof.versionId);
      return proofVersionNumber !== undefined && proofVersionNumber >= check.targetVersionNumber;
    });

    const approvals = await countVerifiedWitnessApprovals(
      logEntries[check.targetVersionNumber - 1],
      candidateProofs,
      check.witness,
      verifier
    );
    const threshold = normalizeWitnessThreshold(check.witness.threshold);

    if (approvals < threshold) {
      onThresholdFailure();
      throw new Error(
        `Witness threshold not met for version ${check.targetVersionId}: got ${approvals}, need ${check.witness.threshold}`
      );
    }
  }
};

const getRequiredWitnessForEntry = (
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

const finalizeResolutionChecks = async ({
  resolverContext,
  options,
  logEntries,
}: {
  resolverContext: ResolverContext;
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
  logEntries: DIDLog;
}): Promise<void> => {
  if (options.requestedDid && resolverContext.didIdMatchCount === 0) {
    throw new Error(`Requested DID '${options.requestedDid}' does not match state.id in any valid log version`);
  }

  if (resolverContext.requiredWitnessChecks.length > 0) {
    await enforceRequiredWitnessChecks({
      requiredWitnessChecks: resolverContext.requiredWitnessChecks,
      witnessProofs: options.witnessProofs,
      did: resolverContext.did,
      logEntries,
      verifier: options.verifier,
      onThresholdFailure: () => {
        resolverContext.witnessThresholdFailure = true;
      },
    });
  }
};

const processResolvedLogEntries = async ({
  resolverContext,
  logEntries,
  options,
}: {
  resolverContext: ResolverContext;
  logEntries: DIDLog;
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
}): Promise<void> => {
  const activeMethod = METHOD_PROTOCOL_V1_0;

  // Process each log entry in order and update resolution context.
  for (let entryIndex = 0; entryIndex < logEntries.length; entryIndex++) {
    const entryContext = validateAndParseLogEntry({
      entry: logEntries[entryIndex],
      expectedVersionNumber: entryIndex + 1,
      previousVersionTime: resolverContext.previousVersionTime,
    });
    const {
      entry: { versionTime, parameters },
      parsedVersion: { versionId, version, versionNumber },
    } = entryContext;

    const previousWitness = resolverContext.meta.witness ? deepClone(resolverContext.meta.witness) : undefined;
    resolverContext.meta.versionId = versionId;
    resolverContext.previousVersionTime = entryContext.currentVersionTime;
    resolverContext.meta.updated = versionTime;

    const resolvedEntryDoc =
      version === '1'
        ? await processV1GenesisEntry({ resolverContext, entryContext, options })
        : await processV1SubsequentEntry({
            resolverContext,
            entryContext,
            logEntries,
            entryIndex,
            activeMethod,
            options,
          });

    const requiredWitness = getRequiredWitnessForEntry(previousWitness, parameters, resolverContext.meta.witness);
    if (requiredWitness) {
      resolverContext.requiredWitnessChecks.push({
        targetVersionId: resolverContext.meta.versionId,
        targetVersionNumber: versionNumber,
        witness: requiredWitness,
      });
    }

    resolverContext.doc = deepClone(resolvedEntryDoc);
    resolverContext.did = requireDidDocumentId(resolverContext.doc.id);

    if (options.requestedDid && resolverContext.did === options.requestedDid) {
      resolverContext.didIdMatchCount++;
    }

    resolverContext.doc = addDefaultDidWebvhServices(resolverContext.did, resolverContext.doc);

    const nextEntry = logEntries[entryIndex + 1];
    const captureByVersion =
      options.versionNumber === versionNumber || options.versionId === resolverContext.meta.versionId;
    const captureByTime =
      options.versionTime !== undefined &&
      options.versionTime > new Date(resolverContext.meta.updated) &&
      (!nextEntry || options.versionTime < new Date(nextEntry.versionTime));

    if (!resolverContext.resolvedSnapshot && (captureByVersion || captureByTime)) {
      resolverContext.resolvedSnapshot = {
        doc: deepClone(resolverContext.doc),
        did: resolverContext.did,
        meta: { ...resolverContext.meta },
      };
    }

    resolverContext.lastValidSnapshot = {
      doc: deepClone(resolverContext.doc),
      did: resolverContext.did,
      meta: { ...resolverContext.meta },
    };
  }

  // Run post-iteration invariants and witness enforcement.
  await finalizeResolutionChecks({
    resolverContext,
    options,
    logEntries,
  });
};

export const resolveV1Log = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
): Promise<{ did: string; doc: DIDDoc | null; meta: DIDResolutionMeta }> => {
  // Stage 1: initialize resolution input and context.
  const logEntries = log.map((l) => deepClone(l));
  if (logEntries.length === 0) {
    throw new Error(`Log identity binding check failed: no entries to process`);
  }
  const protocol = logEntries[0]?.parameters?.method;
  if (protocol !== METHOD_PROTOCOL_V1_0) {
    throw new Error(`'${protocol}' is not a supported method version.`);
  }
  const resolverContext = createInitialResolverContext();
  const hasExplicitHistoricalSelector =
    options.versionNumber !== undefined || options.versionId !== undefined || options.versionTime !== undefined;

  try {
    // Stage 2: process log entries and enforce post-loop checks.
    await processResolvedLogEntries({
      resolverContext,
      logEntries,
      options,
    });
  } catch (e) {
    // Stage 3: preserve a captured historical result when possible.
    const resolvedSnapshot = resolverContext.resolvedSnapshot;
    if (!resolvedSnapshot) {
      throw e;
    }

    const decorateError =
      resolvedSnapshot.meta && (!hasExplicitHistoricalSelector || resolverContext.witnessThresholdFailure);
    if (decorateError) {
      const message = e instanceof Error ? e.message : String(e);
      resolvedSnapshot.meta.error = 'invalidDid';
      resolvedSnapshot.meta.problemDetails = buildProblemDetails('invalidDid', message);
    }
  }

  // Stage 4: finalize fallback selection and shape the response.
  let resolvedSnapshot = resolverContext.resolvedSnapshot;

  if (!resolvedSnapshot && hasExplicitHistoricalSelector) {
    const lastValidSnapshot = resolverContext.lastValidSnapshot;
    if (!lastValidSnapshot) {
      throw new Error('DID resolution failed: No valid result available for explicit selector');
    }

    return {
      did: lastValidSnapshot.did,
      doc: null,
      meta: {
        ...lastValidSnapshot.meta,
        error: 'notFound',
        problemDetails: buildProblemDetails(
          'notFound',
          'The supplied explicit version selector did not match any entry in the DID log.',
          { title: 'The requested DID version was not found.' }
        ),
      },
    };
  }

  if (!resolvedSnapshot) {
    resolvedSnapshot = resolverContext.lastValidSnapshot;
    if (resolvedSnapshot && !resolvedSnapshot.meta.deactivated) {
      resolvedSnapshot = {
        ...resolvedSnapshot,
        doc: resolvedSnapshot.doc ?? null,
      };
    }

    resolverContext.resolvedSnapshot = resolvedSnapshot;
  }

  if (!resolvedSnapshot?.meta) {
    throw new Error('DID resolution failed: No valid metadata found');
  }

  if (!resolvedSnapshot.did) {
    throw new Error('DID resolution failed: No valid identifier found');
  }

  if (resolvedSnapshot.meta.deactivated && !hasExplicitHistoricalSelector) {
    return {
      did: resolvedSnapshot.did,
      doc: null,
      meta: resolvedSnapshot.meta,
    };
  }

  if (!resolvedSnapshot.doc) {
    throw new Error('DID resolution failed: No valid document found');
  }

  return {
    did: resolvedSnapshot.did,
    doc: resolvedSnapshot.doc,
    meta: resolvedSnapshot.meta,
  };
};
