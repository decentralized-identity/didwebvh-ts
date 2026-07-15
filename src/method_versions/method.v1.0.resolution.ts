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

interface ResolutionContext {
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

const createInitialResolutionContext = (): ResolutionContext => {
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

const validateAndParseResolutionEntry = ({
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
  resolutionContext,
  entryContext,
  options,
}: {
  resolutionContext: ResolutionContext;
  entryContext: ParsedResolutionEntryContext;
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] };
}): Promise<DIDDoc> => {
  const { entry: sourceEntry, parsedStateDid } = entryContext;
  const { versionTime, parameters, proof } = sourceEntry;

  resolutionContext.meta.created = versionTime;
  resolutionContext.host = parsedStateDid.locationKey;
  resolutionContext.meta.scid = parameters.scid as string;
  if (options.scid && options.scid !== resolutionContext.meta.scid) {
    throw new Error(`SCID in DID '${options.scid}' does not match SCID in log '${resolutionContext.meta.scid}'`);
  }
  resolutionContext.meta.portable = parameters.portable ?? resolutionContext.meta.portable;
  resolutionContext.meta.updateKeys = parameters.updateKeys as string[];
  resolutionContext.meta.nextKeyHashes = parameters.nextKeyHashes || [];
  resolutionContext.meta.prerotation = resolutionContext.meta.nextKeyHashes.length > 0;
  resolutionContext.meta.witness = parameters.witness || resolutionContext.meta.witness;
  resolutionContext.meta.watchers = parameters.watchers ?? null;

  const logEntry = {
    versionId: SCID_PLACEHOLDER,
    versionTime: resolutionContext.meta.created,
    parameters: replaceValueInObject(parameters, resolutionContext.meta.scid, SCID_PLACEHOLDER),
    state: replaceValueInObject(sourceEntry.state, resolutionContext.meta.scid, SCID_PLACEHOLDER),
  };

  const logEntryHash = await deriveHash(logEntry);
  resolutionContext.meta.previousLogEntryHash = logEntryHash;
  if (!(await scidIsFromHash(resolutionContext.meta.scid, logEntryHash))) {
    throw new Error(`SCID '${resolutionContext.meta.scid}' not derived from logEntryHash '${logEntryHash}'`);
  }

  if (parsedStateDid.scid !== resolutionContext.meta.scid) {
    throw new Error(
      `SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${resolutionContext.meta.scid}'`
    );
  }

  const prelimEntry = replaceValueInObject(logEntry, SCID_PLACEHOLDER, resolutionContext.meta.scid);

  const logEntryHash2 = await deriveHash(prelimEntry);
  const verified = await documentStateIsValid(
    { ...prelimEntry, versionId: `1-${logEntryHash2}`, proof },
    resolutionContext.meta.updateKeys,
    resolutionContext.meta.witness,
    false,
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${resolutionContext.meta.versionId} failed verification of the proof.`);
  }

  return sourceEntry.state;
};

const processV1SubsequentEntry = async ({
  resolutionContext,
  entryContext,
  resolutionLog,
  entryIndex,
  activeMethod,
  options,
}: {
  resolutionContext: ResolutionContext;
  entryContext: ParsedResolutionEntryContext;
  resolutionLog: DIDLog;
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

  if (parameters.portable === true && !resolutionContext.meta.portable) {
    throw new Error(
      `version '${version}' cannot set portable: true; portability can only be enabled in the first entry`
    );
  }

  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.portable) && parameters.portable === false) {
    resolutionContext.meta.portable = false;
  }

  if (parsedStateDid.scid !== resolutionContext.meta.scid) {
    throw new Error(
      `SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${resolutionContext.meta.scid}'`
    );
  }

  const newLocation = parsedStateDid.locationKey;
  if (!resolutionContext.meta.portable && newLocation !== resolutionContext.host) {
    throw new Error('Cannot move DID: portability is disabled');
  } else if (newLocation !== resolutionContext.host) {
    resolutionContext.host = newLocation;
  }

  const { proof: _proof, ...entryWithoutProof } = resolutionLog[entryIndex];
  const recomputedHash = await deriveHash({ ...entryWithoutProof, versionId: resolutionLog[entryIndex - 1].versionId });
  if (!hashChainValid(recomputedHash, entryHash)) {
    throw new Error(`Hash chain broken at '${resolutionContext.meta.versionId}'`);
  }

  const keys = resolutionContext.meta.prerotation
    ? (parameters.updateKeys as string[])
    : resolutionContext.meta.updateKeys;
  const verified = await documentStateIsValid(
    resolutionLog[entryIndex],
    keys,
    resolutionContext.meta.witness,
    false,
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${resolutionContext.meta.versionId} failed verification of the proof.`);
  }

  if (resolutionContext.meta.prerotation) {
    await newKeysAreInNextKeys(parameters.updateKeys ?? [], resolutionContext.meta.nextKeyHashes ?? []);
  }

  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.updateKeys)) {
    resolutionContext.meta.updateKeys = parameters.updateKeys ?? [];
  }
  if (parameters.deactivated === true) {
    resolutionContext.meta.deactivated = true;
  }
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.nextKeyHashes)) {
    resolutionContext.meta.nextKeyHashes = parameters.nextKeyHashes ?? [];
    resolutionContext.meta.prerotation = resolutionContext.meta.nextKeyHashes.length > 0;
  }
  const normalizedWitness = resolveWitnessParameter(parameters);

  if (normalizedWitness !== undefined) {
    resolutionContext.meta.witness = normalizedWitness;
  }
  if (resolutionContext.meta.witness?.witnesses?.length) {
    validateWitnessParameter(resolutionContext.meta.witness);
  }
  if (hasOwn(parameters, METHOD_PARAMETER_KEYS.watchers)) {
    resolutionContext.meta.watchers = parameters.watchers ?? null;
  }

  return sourceEntry.state;
};

const enforceRequiredWitnessChecks = async ({
  requiredWitnessChecks,
  witnessProofs,
  did,
  resolutionLog,
  verifier,
  onThresholdFailure,
}: {
  requiredWitnessChecks: RequiredWitnessCheck[];
  witnessProofs: WitnessProofFileEntry[] | undefined;
  did: string;
  resolutionLog: DIDLog;
  verifier: ResolutionOptions['verifier'];
  onThresholdFailure: () => void;
}): Promise<void> => {
  let resolvedWitnessProofs = witnessProofs;
  if (!resolvedWitnessProofs) {
    resolvedWitnessProofs = await fetchWitnessProofs(did);
  }

  const publishedVersionNumbers = new Map(resolutionLog.map((entry, index) => [entry.versionId, index + 1]));

  for (const check of requiredWitnessChecks) {
    const candidateProofs = resolvedWitnessProofs.filter((witnessProof) => {
      const proofVersionNumber = publishedVersionNumbers.get(witnessProof.versionId);
      return proofVersionNumber !== undefined && proofVersionNumber >= check.targetVersionNumber;
    });

    const approvals = await countVerifiedWitnessApprovals(
      resolutionLog[check.targetVersionNumber - 1],
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

export const resolveV1Log = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
): Promise<{ did: string; doc: DIDDoc | null; meta: DIDResolutionMeta }> => {
  const resolutionLog = log.map((l) => deepClone(l));
  if (resolutionLog.length === 0) {
    throw new Error(`Log identity binding check failed: no entries to process`);
  }
  const protocol = resolutionLog[0]?.parameters?.method;
  if (protocol !== METHOD_PROTOCOL_V1_0) {
    throw new Error(`'${protocol}' is not a supported method version.`);
  }
  const resolutionContext = createInitialResolutionContext();
  let i = 0;
  const hasExplicitHistoricalSelector =
    options.versionNumber !== undefined || options.versionId !== undefined || options.versionTime !== undefined;
  const activeMethod = METHOD_PROTOCOL_V1_0;

  try {
    while (i < resolutionLog.length) {
      const entryContext = validateAndParseResolutionEntry({
        entry: resolutionLog[i],
        expectedVersionNumber: i + 1,
        previousVersionTime: resolutionContext.previousVersionTime,
      });
      const {
        entry: { versionTime, parameters },
        parsedVersion: { versionId, version, versionNumber },
      } = entryContext;
      const previousWitness = resolutionContext.meta.witness ? deepClone(resolutionContext.meta.witness) : undefined;
      resolutionContext.meta.versionId = versionId;
      resolutionContext.previousVersionTime = entryContext.currentVersionTime;
      resolutionContext.meta.updated = versionTime;
      const newDoc =
        version === '1'
          ? await processV1GenesisEntry({ resolutionContext, entryContext, options })
          : await processV1SubsequentEntry({
              resolutionContext,
              entryContext,
              resolutionLog,
              entryIndex: i,
              activeMethod,
              options,
            });

      const requiredWitness = getRequiredWitnessForEntry(previousWitness, parameters, resolutionContext.meta.witness);
      if (requiredWitness) {
        resolutionContext.requiredWitnessChecks.push({
          targetVersionId: resolutionContext.meta.versionId,
          targetVersionNumber: versionNumber,
          witness: requiredWitness,
        });
      }

      resolutionContext.doc = deepClone(newDoc);
      resolutionContext.did = requireDidDocumentId(resolutionContext.doc.id);

      if (options.requestedDid && resolutionContext.did === options.requestedDid) {
        resolutionContext.didIdMatchCount++;
      }

      resolutionContext.doc = addDefaultDidWebvhServices(resolutionContext.did, resolutionContext.doc);

      const nextEntry = resolutionLog[i + 1];
      const captureByVersion =
        options.versionNumber === versionNumber || options.versionId === resolutionContext.meta.versionId;
      const captureByTime =
        options.versionTime !== undefined &&
        options.versionTime > new Date(resolutionContext.meta.updated) &&
        (!nextEntry || options.versionTime < new Date(nextEntry.versionTime));

      if (!resolutionContext.resolvedSnapshot && (captureByVersion || captureByTime)) {
        resolutionContext.resolvedSnapshot = {
          doc: deepClone(resolutionContext.doc),
          did: resolutionContext.did,
          meta: { ...resolutionContext.meta },
        };
      }

      resolutionContext.lastValidSnapshot = {
        doc: deepClone(resolutionContext.doc),
        did: resolutionContext.did,
        meta: { ...resolutionContext.meta },
      };

      i++;
    }

    if (options.requestedDid && resolutionContext.didIdMatchCount === 0) {
      throw new Error(`Requested DID '${options.requestedDid}' does not match state.id in any valid log version`);
    }
    if (resolutionContext.requiredWitnessChecks.length > 0) {
      await enforceRequiredWitnessChecks({
        requiredWitnessChecks: resolutionContext.requiredWitnessChecks,
        witnessProofs: options.witnessProofs,
        did: resolutionContext.did,
        resolutionLog,
        verifier: options.verifier,
        onThresholdFailure: () => {
          resolutionContext.witnessThresholdFailure = true;
        },
      });
    }
  } catch (e) {
    if (!resolutionContext.resolvedSnapshot) {
      throw e;
    }
    if (
      resolutionContext.resolvedSnapshot.meta &&
      (!hasExplicitHistoricalSelector || resolutionContext.witnessThresholdFailure)
    ) {
      const message = e instanceof Error ? e.message : String(e);
      resolutionContext.resolvedSnapshot.meta.error = 'invalidDid';
      resolutionContext.resolvedSnapshot.meta.problemDetails = buildProblemDetails('invalidDid', message);
    }
  }

  if (!resolutionContext.resolvedSnapshot) {
    if (hasExplicitHistoricalSelector) {
      if (!resolutionContext.lastValidSnapshot) {
        throw new Error('DID resolution failed: No valid result available for explicit selector');
      }

      return {
        did: resolutionContext.lastValidSnapshot.did,
        doc: null,
        meta: {
          ...resolutionContext.lastValidSnapshot.meta,
          error: 'notFound',
          problemDetails: buildProblemDetails(
            'notFound',
            'The supplied explicit version selector did not match any entry in the DID log.',
            { title: 'The requested DID version was not found.' }
          ),
        },
      };
    }

    resolutionContext.resolvedSnapshot = resolutionContext.lastValidSnapshot;
    if (
      resolutionContext.resolvedSnapshot &&
      !(resolutionContext.resolvedSnapshot.meta.deactivated && !hasExplicitHistoricalSelector)
    ) {
      resolutionContext.resolvedSnapshot = {
        ...resolutionContext.resolvedSnapshot,
        doc: resolutionContext.lastValidSnapshot?.doc ?? null,
      };
    }
  }

  if (!resolutionContext.resolvedSnapshot?.meta) {
    throw new Error('DID resolution failed: No valid metadata found');
  }

  if (!resolutionContext.resolvedSnapshot.did) {
    throw new Error('DID resolution failed: No valid identifier found');
  }

  if (resolutionContext.resolvedSnapshot.meta.deactivated && !hasExplicitHistoricalSelector) {
    return {
      did: resolutionContext.resolvedSnapshot.did,
      doc: null,
      meta: resolutionContext.resolvedSnapshot.meta,
    };
  }

  if (!resolutionContext.resolvedSnapshot.doc) {
    throw new Error('DID resolution failed: No valid document found');
  }

  return {
    did: resolutionContext.resolvedSnapshot.did,
    doc: resolutionContext.resolvedSnapshot.doc,
    meta: resolutionContext.resolvedSnapshot.meta,
  };
};
