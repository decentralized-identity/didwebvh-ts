import { documentStateIsValid, hashChainValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions';
import { METHOD_PARAMETER_KEYS, METHOD_PROTOCOL_V1_0, PLACEHOLDER } from '../constants';
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
  addDefaultDidWebvhServices,
  deepClone,
  deriveHash,
  parseAndValidateVersionId,
  parseDidWebvhIdentifier,
  replaceValueInObject,
} from '../utils';
import { MAX_FUTURE_SKEW_MS, parseUtcIso8601VersionTime } from '../utils/iso8601-datetime';
import { countVerifiedWitnessApprovals, fetchWitnessProofs, validateWitnessParameter } from '../witness';

const hasOwn = <K extends PropertyKey>(obj: object, key: K): obj is Record<K, unknown> => Object.hasOwn(obj, key);

interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameterResolution;
}

const requireDidId = (id: string | undefined): string => {
  if (!id) {
    throw new Error('DID document id is missing');
  }

  return id;
};

const getEntryWitnessParameter = (parameters: DIDLogEntry['parameters']): WitnessParameterResolution | undefined => {
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
};

const isWitnessActive = (witness?: WitnessParameterResolution | null): witness is WitnessParameterResolution => {
  if (!witness?.witnesses || witness.witnesses.length === 0) {
    return false;
  }

  const threshold = parseInt((witness.threshold ?? 0).toString(), 10);
  return threshold > 0;
};

const getRequiredWitnessForEntry = (
  previousWitness: WitnessParameterResolution | undefined,
  parameters: DIDLogEntry['parameters'],
  currentWitness: WitnessParameterResolution | undefined
): WitnessParameterResolution | undefined => {
  const explicitWitness = getEntryWitnessParameter(parameters);

  if (isWitnessActive(previousWitness)) {
    return deepClone(previousWitness);
  }

  if (explicitWitness !== undefined && isWitnessActive(currentWitness)) {
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
  let did = '';
  let doc: DIDDoc | null = null;
  let resolvedDoc: DIDDoc | null = null;
  let resolvedDid: string | null = null;
  let lastValidDoc: DIDDoc | null = null;
  let lastValidDid: string | null = null;
  const meta: DIDResolutionMeta = {
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
  };
  let resolvedMeta: DIDResolutionMeta | null = null;
  let lastValidMeta: DIDResolutionMeta | null = null;
  let i = 0;
  const hasExplicitHistoricalSelector =
    options.versionNumber !== undefined || options.versionId !== undefined || options.versionTime !== undefined;
  let didIdMatchCount = 0;
  let host = '';
  let previousVersionTime: Date | undefined;
  const activeMethod = METHOD_PROTOCOL_V1_0;
  const requiredWitnessChecks: RequiredWitnessCheck[] = [];
  let witnessThresholdFailure = false;

  try {
    while (i < resolutionLog.length) {
      const { versionId, versionTime, parameters, state, proof } = resolutionLog[i];
      const { version, versionNumber, entryHash } = parseAndValidateVersionId(versionId, i + 1);
      const previousWitness = meta.witness ? deepClone(meta.witness) : undefined;
      meta.versionId = versionId;
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
      previousVersionTime = currentVersionTime;
      meta.updated = versionTime;
      let newDoc = state;
      const parsedStateDid = parseDidWebvhIdentifier(requireDidId(newDoc.id), `version '${version}' state.id`);

      if (version === '1') {
        meta.created = versionTime;
        newDoc = state;
        host = parsedStateDid.locationKey;
        meta.scid = parameters.scid as string;
        if (options.scid && options.scid !== meta.scid) {
          throw new Error(`SCID in DID '${options.scid}' does not match SCID in log '${meta.scid}'`);
        }
        meta.portable = parameters.portable ?? meta.portable;
        meta.updateKeys = parameters.updateKeys as string[];
        meta.nextKeyHashes = parameters.nextKeyHashes || [];
        meta.prerotation = meta.nextKeyHashes.length > 0;
        meta.witness = parameters.witness || meta.witness;
        meta.watchers = parameters.watchers ?? null;

        const logEntry = {
          versionId: PLACEHOLDER,
          versionTime: meta.created,
          parameters: replaceValueInObject(parameters, meta.scid, PLACEHOLDER),
          state: replaceValueInObject(newDoc, meta.scid, PLACEHOLDER),
        };

        const logEntryHash = await deriveHash(logEntry);
        meta.previousLogEntryHash = logEntryHash;
        if (!(await scidIsFromHash(meta.scid, logEntryHash))) {
          throw new Error(`SCID '${meta.scid}' not derived from logEntryHash '${logEntryHash}'`);
        }

        if (parsedStateDid.scid !== meta.scid) {
          throw new Error(`SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${meta.scid}'`);
        }

        const prelimEntry = replaceValueInObject(logEntry, PLACEHOLDER, meta.scid);

        const logEntryHash2 = await deriveHash(prelimEntry);
        const verified = await documentStateIsValid(
          { ...prelimEntry, versionId: `1-${logEntryHash2}`, proof },
          meta.updateKeys,
          meta.witness,
          false,
          options.verifier
        );
        if (!verified) {
          throw new Error(`version ${meta.versionId} failed verification of the proof.`);
        }
      } else {
        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.method)) {
          const entryMethod = parameters.method as string;
          if (entryMethod !== activeMethod) {
            throw new Error(
              `version '${version}' has unsupported or downgraded method '${entryMethod}'; ` +
                `expected '${activeMethod}'`
            );
          }
        }

        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.scid)) {
          throw new Error(`version '${version}' must not contain SCID parameter`);
        }

        if (parameters.portable === true && !meta.portable) {
          throw new Error(
            `version '${version}' cannot set portable: true; portability can only be enabled in the first entry`
          );
        }

        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.portable) && parameters.portable === false) {
          meta.portable = false;
        }

        if (parsedStateDid.scid !== meta.scid) {
          throw new Error(`SCID in state.id '${parsedStateDid.scid}' does not match SCID in log '${meta.scid}'`);
        }

        const newLocation = parsedStateDid.locationKey;
        if (!meta.portable && newLocation !== host) {
          throw new Error('Cannot move DID: portability is disabled');
        } else if (newLocation !== host) {
          host = newLocation;
        }

        const { proof: _proof, ...entryWithoutProof } = resolutionLog[i];
        const recomputedHash = await deriveHash({ ...entryWithoutProof, versionId: resolutionLog[i - 1].versionId });
        if (!hashChainValid(recomputedHash, entryHash)) {
          throw new Error(`Hash chain broken at '${meta.versionId}'`);
        }

        const keys = meta.prerotation ? (parameters.updateKeys as string[]) : meta.updateKeys;
        const verified = await documentStateIsValid(resolutionLog[i], keys, meta.witness, false, options.verifier);
        if (!verified) {
          throw new Error(`version ${meta.versionId} failed verification of the proof.`);
        }

        if (meta.prerotation) {
          await newKeysAreInNextKeys(parameters.updateKeys ?? [], meta.nextKeyHashes ?? []);
        }

        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.updateKeys)) {
          meta.updateKeys = parameters.updateKeys ?? [];
        }
        if (parameters.deactivated === true) {
          meta.deactivated = true;
        }
        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.nextKeyHashes)) {
          meta.nextKeyHashes = parameters.nextKeyHashes ?? [];
          meta.prerotation = meta.nextKeyHashes.length > 0;
        }
        const legacyParameters = parameters as typeof parameters & {
          witnesses?: { id: string }[];
          witnessThreshold?: string | number;
        };

        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.witness)) {
          meta.witness = parameters.witness;
        } else if (legacyParameters.witnesses) {
          meta.witness = {
            witnesses: legacyParameters.witnesses,
            threshold: legacyParameters.witnessThreshold || legacyParameters.witnesses.length,
          };
        }
        if (meta.witness?.witnesses?.length) {
          validateWitnessParameter(meta.witness);
        }
        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.watchers)) {
          meta.watchers = parameters.watchers ?? null;
        }
      }

      const requiredWitness = getRequiredWitnessForEntry(previousWitness, parameters, meta.witness);
      if (requiredWitness) {
        requiredWitnessChecks.push({
          targetVersionId: meta.versionId,
          targetVersionNumber: versionNumber,
          witness: requiredWitness,
        });
      }

      doc = deepClone(newDoc);
      did = requireDidId(doc.id);

      if (options.requestedDid && did === options.requestedDid) {
        didIdMatchCount++;
      }

      doc = addDefaultDidWebvhServices(did, doc);

      if (options.versionNumber === versionNumber || options.versionId === meta.versionId) {
        if (!resolvedDoc) {
          resolvedDoc = deepClone(doc);
          resolvedDid = did;
          resolvedMeta = { ...meta };
        }
      }
      if (options.versionTime && options.versionTime > new Date(meta.updated)) {
        if (resolutionLog[i + 1] && options.versionTime < new Date(resolutionLog[i + 1].versionTime)) {
          if (!resolvedDoc) {
            resolvedDoc = deepClone(doc);
            resolvedDid = did;
            resolvedMeta = { ...meta };
          }
        } else if (!resolutionLog[i + 1]) {
          if (!resolvedDoc) {
            resolvedDoc = deepClone(doc);
            resolvedDid = did;
            resolvedMeta = { ...meta };
          }
        }
      }

      lastValidDoc = deepClone(doc);
      lastValidDid = did;
      lastValidMeta = { ...meta };

      i++;
    }

    if (options.requestedDid && didIdMatchCount === 0) {
      throw new Error(`Requested DID '${options.requestedDid}' does not match state.id in any valid log version`);
    }
    if (requiredWitnessChecks.length > 0) {
      if (!options.witnessProofs) {
        options.witnessProofs = await fetchWitnessProofs(did);
      }

      const publishedVersionNumbers = new Map(resolutionLog.map((entry, index) => [entry.versionId, index + 1]));

      for (const check of requiredWitnessChecks) {
        const candidateProofs = (options.witnessProofs ?? []).filter((witnessProof) => {
          const proofVersionNumber = publishedVersionNumbers.get(witnessProof.versionId);
          return proofVersionNumber !== undefined && proofVersionNumber >= check.targetVersionNumber;
        });

        const approvals = await countVerifiedWitnessApprovals(
          resolutionLog[check.targetVersionNumber - 1],
          candidateProofs,
          check.witness,
          options.verifier
        );
        const threshold = parseInt((check.witness.threshold ?? 0).toString(), 10);

        if (approvals < threshold) {
          witnessThresholdFailure = true;
          throw new Error(
            `Witness threshold not met for version ${check.targetVersionId}: got ${approvals}, need ${check.witness.threshold}`
          );
        }
      }
    }
  } catch (e) {
    if (!resolvedDoc) {
      throw e;
    }
    if (resolvedMeta && (!hasExplicitHistoricalSelector || witnessThresholdFailure)) {
      const message = e instanceof Error ? e.message : String(e);
      resolvedMeta.error = 'invalidDid';
      resolvedMeta.problemDetails = buildProblemDetails('invalidDid', message);
    }
  }

  if (!resolvedDoc) {
    if (hasExplicitHistoricalSelector) {
      if (!lastValidMeta || !lastValidDid) {
        throw new Error('DID resolution failed: No valid result available for explicit selector');
      }

      return {
        did: lastValidDid,
        doc: null,
        meta: {
          ...lastValidMeta,
          error: 'notFound',
          problemDetails: buildProblemDetails(
            'notFound',
            'The supplied explicit version selector did not match any entry in the DID log.',
            { title: 'The requested DID version was not found.' }
          ),
        },
      };
    }

    resolvedMeta = lastValidMeta;
    resolvedDid = lastValidDid;
    if (resolvedMeta && !(resolvedMeta.deactivated && !hasExplicitHistoricalSelector)) {
      resolvedDoc = lastValidDoc;
    }
  }

  if (!resolvedMeta) {
    throw new Error('DID resolution failed: No valid metadata found');
  }

  if (!resolvedDid) {
    throw new Error('DID resolution failed: No valid identifier found');
  }

  if (resolvedMeta.deactivated && !hasExplicitHistoricalSelector) {
    return {
      did: resolvedDid,
      doc: null,
      meta: resolvedMeta,
    };
  }

  if (!resolvedDoc) {
    throw new Error('DID resolution failed: No valid document found');
  }

  return {
    did: resolvedDid,
    doc: resolvedDoc,
    meta: resolvedMeta,
  };
};
