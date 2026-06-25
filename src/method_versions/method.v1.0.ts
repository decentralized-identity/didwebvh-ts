import { documentStateIsValid, hashChainValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions';
import {
  CONTEXT_LINKED_VP,
  ERROR_TYPE_INVALID_DID,
  ERROR_TYPE_NOT_FOUND,
  METHOD,
  METHOD_PARAMETER_KEYS,
  METHOD_PROTOCOL_V1_0,
  PLACEHOLDER,
  SERVICE_TYPE_LINKED_VP,
  SERVICE_TYPE_RELATIVE_REF,
  ServiceFragment,
} from '../constants';
import type {
  CreateDIDInterface,
  CreateDIDResult,
  DataIntegrityProof,
  DeactivateDIDInterface,
  DIDDoc,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  ResolutionOptions,
  ServiceEndpoint,
  UpdateDIDInterface,
  UpdateDIDResult,
  WitnessParameterResolution,
  WitnessProofFileEntry,
} from '../interfaces';
import { DidResolutionError } from '../interfaces';
import {
  createDate,
  createDIDDoc,
  createSCID,
  deepClone,
  deriveHash,
  enrichAlsoKnownAs,
  findVerificationMethod,
  generateParallelDidWeb,
  getBaseUrl,
  parseCanonicalAddress,
  parseDidWebvhIdentifier,
  replaceCreateDidPlaceholders,
  replaceValueInObject,
  serviceFragmentExists,
  validateCreateDidDocument,
  validateMethodSpecificPathSegments,
} from '../utils';
import {
  createNextVersionTime,
  parseUtcIso8601VersionTime,
  validateUtcIso8601NotInFuture,
} from '../utils/iso8601-datetime';
import { countVerifiedWitnessApprovals, fetchWitnessProofs, validateWitnessParameter } from '../witness';

const hasOwn = <K extends PropertyKey>(obj: object, key: K): obj is Record<K, unknown> => Object.hasOwn(obj, key);

const MAX_FUTURE_SKEW_MS = 5 * 60 * 1000;

const requireDidId = (id: string | undefined): string => {
  if (!id) {
    throw new Error('DID document id is missing');
  }
  return id;
};

const parseAndValidateVersionId = (versionId: string, expectedVersionNumber: number) => {
  const firstDashIndex = versionId.indexOf('-');
  const lastDashIndex = versionId.lastIndexOf('-');

  if (firstDashIndex === -1 || firstDashIndex !== lastDashIndex) {
    throw new Error(`versionId '${versionId}' must contain exactly one '-' separator`);
  }

  const version = versionId.slice(0, firstDashIndex);
  const entryHash = versionId.slice(firstDashIndex + 1);

  if (!/^\d+$/.test(version)) {
    throw new Error(`versionId '${versionId}' must have a numeric version prefix`);
  }

  if (entryHash.length === 0) {
    throw new Error(`versionId '${versionId}' must have a non-empty hash component`);
  }

  const versionNumber = Number(version);
  if (versionNumber !== expectedVersionNumber) {
    throw new Error(`version '${version}' in log doesn't match expected '${expectedVersionNumber}'.`);
  }

  return { version, versionNumber, entryHash };
};

export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied');
  }

  if (options.witness?.witnesses && options.witness.witnesses.length > 0) {
    validateWitnessParameter(options.witness);
  }

  // Parse address input with strict validation
  const addressInput = options.address || options.domain;
  if (!addressInput) {
    throw new Error('Either address or domain must be provided');
  }

  const parsed = parseCanonicalAddress(addressInput);
  const didDomainComponent = parsed.didDomainComponent;
  const allPaths = [...(parsed.paths || []), ...(options.paths || [])];
  validateMethodSpecificPathSegments(allPaths, 'createDID path segments');
  const path = allPaths.length > 0 ? allPaths.join(':') : undefined;
  const controller = `did:${METHOD}:${PLACEHOLDER}:${didDomainComponent}${path ? `:${path}` : ''}`;
  if (options.created) {
    validateUtcIso8601NotInFuture(options.created, 'createDID created');
  }
  const createdDate = options.created ?? createDate();

  // Safety guard: Strip secret keys from verification methods before creating DID document
  const safeVerificationMethods = options.verificationMethods?.map((vm) => {
    if (vm.secretKeyMultibase) {
      console.warn(
        'Warning: Removing secretKeyMultibase from verification method - secret keys should not be stored in DID documents'
      );
      const { secretKeyMultibase, ...safeVm } = vm;
      return safeVm;
    }
    return vm;
  });

  let doc: DIDDoc;
  if (options.didDocument) {
    validateCreateDidDocument(options.didDocument);
    doc = deepClone(options.didDocument);
  } else {
    if (!safeVerificationMethods || safeVerificationMethods.length === 0) {
      throw new Error('verificationMethods must be provided when didDocument is not supplied');
    }
    const didDocResult = await createDIDDoc({
      ...options,
      domain: addressInput,
      paths: allPaths,
      controller,
      verificationMethods: safeVerificationMethods,
    });
    doc = didDocResult.doc;
  }

  doc = enrichAlsoKnownAs(doc, controller, {
    alsoKnownAsWeb: options.alsoKnownAsWeb,
  });

  const params = {
    scid: PLACEHOLDER,
    updateKeys: options.updateKeys,
    portable: options.portable ?? false,
    nextKeyHashes: options.nextKeyHashes ?? [],
    watchers: options.watchers ?? [],
    witness: options.witness ?? {},
    deactivated: false,
  };
  const initialLogEntry: DIDLogEntry = {
    versionId: PLACEHOLDER,
    versionTime: createdDate,
    parameters: {
      method: METHOD_PROTOCOL_V1_0,
      ...params,
    },
    state: doc,
  };
  const initialLogEntryHash = await deriveHash(initialLogEntry);
  params.scid = await createSCID(initialLogEntryHash);
  initialLogEntry.state = doc;
  const didWithScid = controller.replaceAll(PLACEHOLDER, params.scid);
  const prelimEntry = replaceCreateDidPlaceholders(initialLogEntry, params.scid, didWithScid);
  prelimEntry.state = enrichAlsoKnownAs(prelimEntry.state, didWithScid, {
    alsoKnownAsWeb: options.alsoKnownAsWeb,
  });
  const logEntryHash2 = await deriveHash(prelimEntry);
  prelimEntry.versionId = `1-${logEntryHash2}`;
  const proofTemplate: Omit<DataIntegrityProof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: options.signer.getVerificationMethodId(),
    created: createdDate,
    proofPurpose: 'assertionMethod',
  };
  const signedProof = await options.signer.sign({ document: prelimEntry, proof: proofTemplate });
  const allProofs: DataIntegrityProof[] = [{ ...proofTemplate, proofValue: signedProof.proofValue }];
  prelimEntry.proof = allProofs;

  const verified = await documentStateIsValid(
    { ...prelimEntry, versionId: `1-${logEntryHash2}` },
    params.updateKeys,
    params.witness,
    true, // skipWitnessVerification
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`);
  }

  const didId = requireDidId(prelimEntry.state.id);
  if (didId !== didWithScid) {
    throw new Error(`Created DID document id must match expected DID '${didWithScid}', got '${didId}'`);
  }
  const webDoc = options.alsoKnownAsWeb ? generateParallelDidWeb(didId, prelimEntry.state) : undefined;

  return {
    did: didId,
    doc: prelimEntry.state,
    meta: {
      versionId: prelimEntry.versionId,
      created: prelimEntry.versionTime,
      updated: prelimEntry.versionTime,
      prerotation: (params.nextKeyHashes?.length ?? 0) > 0,
      ...params,
    },
    log: [prelimEntry],
    ...(webDoc ? { webDoc } : {}),
  };
};

export const resolveDIDFromLog = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
): Promise<{ did: string; doc: DIDDoc | null; meta: DIDResolutionMeta }> => {
  if (options.verificationMethod && (options.versionNumber || options.versionId)) {
    throw new Error('Cannot specify both verificationMethod and version number/id');
  }
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
    options.versionNumber !== undefined ||
    options.versionId !== undefined ||
    options.versionTime !== undefined ||
    options.verificationMethod !== undefined;
  let didIdMatchCount = 0;
  let host = '';
  let previousVersionTime: Date | undefined;
  const activeMethod = METHOD_PROTOCOL_V1_0; // Track method value across entries
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
      // Check against resolver's current time for each entry per spec normative language
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

        // Optimized: Use efficient object manipulation instead of JSON stringify/parse
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

        // Optimized: Direct object manipulation instead of JSON stringify/parse
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
        // version number > 1

        // Validate method parameter: must not be present or must equal active method
        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.method)) {
          const entryMethod = parameters.method as string;
          if (entryMethod !== activeMethod) {
            throw new Error(
              `version '${version}' has unsupported or downgraded method '${entryMethod}'; ` +
                `expected '${activeMethod}'`
            );
          }
        }

        // scid MUST NOT appear in later entries
        if (hasOwn(parameters, METHOD_PARAMETER_KEYS.scid)) {
          throw new Error(`version '${version}' must not contain SCID parameter`);
        }

        // portable: true cannot be introduced after the first entry — it can only remain
        // true if it was already enabled in the first entry
        if (parameters.portable === true && !meta.portable) {
          throw new Error(
            `version '${version}' cannot set portable: true; portability can only be enabled in the first entry`
          );
        }

        // Setting portable: false in a later entry permanently locks portability off
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

        // Hash chain — ALWAYS runs (cheap), even in fast-resolve
        const { proof: _proof, ...entryWithoutProof } = resolutionLog[i];
        const recomputedHash = await deriveHash({ ...entryWithoutProof, versionId: resolutionLog[i - 1].versionId });
        if (!hashChainValid(recomputedHash, entryHash)) {
          throw new Error(`Hash chain broken at '${meta.versionId}'`);
        }

        // Signature verification
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

      // Optimized: Use efficient cloning instead of clone() function
      doc = deepClone(newDoc);
      did = requireDidId(doc.id);

      if (options.requestedDid && did === options.requestedDid) {
        didIdMatchCount++;
      }

      // Add default services if they don't exist
      doc.service = Array.isArray(doc.service) ? doc.service : [];
      const baseUrl = getBaseUrl(did);

      if (!serviceFragmentExists(doc.service, ServiceFragment.Files, did)) {
        doc.service.push({
          id: '#files',
          type: SERVICE_TYPE_RELATIVE_REF,
          serviceEndpoint: baseUrl,
        });
      }

      if (!serviceFragmentExists(doc.service, ServiceFragment.Whois, did)) {
        doc.service.push({
          '@context': CONTEXT_LINKED_VP,
          id: '#whois',
          type: SERVICE_TYPE_LINKED_VP,
          serviceEndpoint: `${baseUrl}/whois.vp`,
        });
      }

      if (options.verificationMethod && findVerificationMethod(doc, options.verificationMethod)) {
        if (!resolvedDoc) {
          resolvedDoc = deepClone(doc);
          resolvedDid = did;
          resolvedMeta = { ...meta };
        }
      }

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
      resolvedMeta.error = DidResolutionError.InvalidDid;
      resolvedMeta.problemDetails = {
        type: ERROR_TYPE_INVALID_DID,
        title: 'The resolved DID is invalid.',
        detail: message,
      };
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
          error: DidResolutionError.NotFound,
          problemDetails: {
            type: ERROR_TYPE_NOT_FOUND,
            title: 'The requested DID version was not found.',
            detail: 'The supplied explicit version selector did not match any entry in the DID log.',
          },
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

export const updateDID = async (
  options: UpdateDIDInterface & {
    services?: ServiceEndpoint[];
    domain?: string;
    address?: string;
    paths?: string[];
    updated?: string;
  }
): Promise<UpdateDIDResult> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastEntryDid = requireDidId(lastEntry.state.id);
  const parsedLastEntryDid = parseDidWebvhIdentifier(lastEntryDid, 'last entry state.id');
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
  const watchersValue = options.watchers !== undefined ? options.watchers : lastMeta.watchers;
  const resolvedNextKeyHashes = options.nextKeyHashes ?? lastMeta.nextKeyHashes ?? [];
  const witnessInput = options.witness;
  const witness = witnessInput?.witnesses?.length
    ? {
        witnesses: witnessInput.witnesses,
        threshold: witnessInput.threshold ?? 0,
      }
    : {};
  if (options.portable === true) {
    throw new Error(
      'portable: true cannot be set in an update entry; portability can only be enabled in the first entry'
    );
  }
  const params = {
    ...(options.updateKeys !== undefined || lastMeta.prerotation
      ? { updateKeys: options.updateKeys ?? lastMeta.updateKeys }
      : {}),
    ...(options.nextKeyHashes !== undefined ? { nextKeyHashes: options.nextKeyHashes } : {}),
    ...(options.portable === false ? { portable: false } : {}),
    witness,
    watchers: watchersValue ?? [],
  };

  if (params.witness?.witnesses?.length) {
    validateWitnessParameter(params.witness);
  }

  if (lastMeta.prerotation) {
    await newKeysAreInNextKeys(currentUpdateKeys ?? [], lastMeta.nextKeyHashes ?? []);
  }

  // Safety guard: Strip secret keys from verification methods before creating DID document
  const safeVerificationMethods = options.verificationMethods?.map((vm) => {
    if (vm.secretKeyMultibase) {
      console.warn(
        'Warning: Removing secretKeyMultibase from verification method - secret keys should not be stored in DID documents'
      );
      const { secretKeyMultibase, ...safeVm } = vm;
      return safeVm;
    }
    return vm;
  });

  // Compute controller DID id; rebuild with new address if moving, keep SCID stable.
  const requestedAddress = options.address || options.domain;
  let controller: string;
  let controllerPaths = parsedLastEntryDid.paths;
  if (options.controller) {
    controller = options.controller;
  } else if (requestedAddress) {
    const parsedNewAddress = parseCanonicalAddress(requestedAddress);
    // Paths: explicit options.paths (combined with any address-embedded paths) take
    // precedence; otherwise use address-embedded paths; otherwise inherit the prior
    // paths so re-passing a bare domain on a pathed DID doesn't silently drop them.
    const addressPaths = parsedNewAddress.paths || [];
    const newLocationPaths =
      options.paths !== undefined
        ? [...addressPaths, ...options.paths]
        : addressPaths.length
          ? addressPaths
          : (parsedLastEntryDid.paths ?? []);
    const newLocationKey = newLocationPaths.length
      ? `${parsedNewAddress.didDomainComponent}:${newLocationPaths.join(':')}`
      : parsedNewAddress.didDomainComponent;
    controller = `did:${METHOD}:${parsedLastEntryDid.scid}:${newLocationKey}`;
    controllerPaths = newLocationPaths.length ? newLocationPaths : undefined;
    if (controller !== lastEntryDid && !lastMeta.portable) {
      throw new Error('Cannot move DID: portability is disabled');
    }
  } else {
    controller = lastEntryDid;
  }

  const { doc: normalizedUpdateDoc } = await createDIDDoc({
    ...options,
    controller,
    context: options.context || lastEntry.state['@context'],
    domain: requestedAddress ?? parsedLastEntryDid.didDomainComponent,
    paths: controllerPaths,
    updateKeys: options.updateKeys ?? [],
    verificationMethods: safeVerificationMethods ?? [],
  });

  const doc = deepClone(lastEntry.state);
  doc['@context'] = normalizedUpdateDoc['@context'];
  doc.id = normalizedUpdateDoc.id;
  doc.controller = normalizedUpdateDoc.controller;

  if (safeVerificationMethods !== undefined) {
    doc.verificationMethod = normalizedUpdateDoc.verificationMethod;
    doc.authentication = normalizedUpdateDoc.authentication;
    doc.assertionMethod = normalizedUpdateDoc.assertionMethod;
    doc.keyAgreement = normalizedUpdateDoc.keyAgreement;
    doc.capabilityDelegation = normalizedUpdateDoc.capabilityDelegation;
    doc.capabilityInvocation = normalizedUpdateDoc.capabilityInvocation;
  }

  if (options.services !== undefined) {
    doc.service = options.services;
  }

  if (options.authentication !== undefined) {
    doc.authentication = options.authentication;
  }

  if (options.assertionMethod !== undefined) {
    doc.assertionMethod = options.assertionMethod;
  }

  if (options.keyAgreement !== undefined) {
    doc.keyAgreement = options.keyAgreement;
  }

  if (options.alsoKnownAs !== undefined) {
    doc.alsoKnownAs = options.alsoKnownAs;
  }

  if (controller !== lastEntryDid) {
    const aliases = Array.isArray(doc.alsoKnownAs) ? [...doc.alsoKnownAs] : [];
    if (!aliases.includes(lastEntryDid)) {
      aliases.push(lastEntryDid);
    }
    doc.alsoKnownAs = aliases;
  }

  const logEntry: DIDLogEntry = {
    versionId: lastEntry.versionId,
    versionTime: createdDate,
    parameters: params,
    state: doc,
  };
  const logEntryHash = await deriveHash(logEntry);
  const versionId = `${versionNumber}-${logEntryHash}`;
  const prelimEntry = { ...logEntry, versionId };
  const proofTemplate: Omit<DataIntegrityProof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: options.signer.getVerificationMethodId(),
    created: createdDate,
    proofPurpose: 'assertionMethod',
  };
  const signedProof = await options.signer.sign({ document: prelimEntry, proof: proofTemplate });
  const allProofs: DataIntegrityProof[] = [{ ...proofTemplate, proofValue: signedProof.proofValue }];
  prelimEntry.proof = allProofs;
  const keysToVerify = lastMeta.prerotation ? currentUpdateKeys : lastMeta.updateKeys;
  if (!keysToVerify) {
    throw new Error('updateKeys could not be determined for update verification');
  }
  const verified = await documentStateIsValid(prelimEntry, keysToVerify, lastMeta.witness, true, options.verifier);
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`);
  }

  const meta: DIDResolutionMeta = {
    ...lastMeta,
    versionId: prelimEntry.versionId,
    updated: prelimEntry.versionTime,
    prerotation: resolvedNextKeyHashes.length > 0,
    ...params,
  };

  const hasWebAlias = (prelimEntry.state.alsoKnownAs ?? []).some((alias: string) => alias.startsWith('did:web:'));
  const updatedDidId = requireDidId(prelimEntry.state.id);
  const webDoc = hasWebAlias ? generateParallelDidWeb(updatedDidId, prelimEntry.state) : undefined;

  return {
    did: updatedDidId,
    doc: prelimEntry.state,
    meta,
    log: [...log, prelimEntry],
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
  const params = {
    updateKeys: options.updateKeys ?? lastMeta.updateKeys,
    deactivated: true,
  };
  const logEntry: DIDLogEntry = {
    versionId: lastEntry.versionId,
    versionTime: createdDate,
    parameters: params,
    state: lastEntry.state,
  };
  const logEntryHash = await deriveHash(logEntry);
  const versionId = `${versionNumber}-${logEntryHash}`;
  const prelimEntry = { ...logEntry, versionId };
  const proofTemplate: Omit<DataIntegrityProof, 'proofValue'> = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: options.signer.getVerificationMethodId(),
    created: createdDate,
    proofPurpose: 'assertionMethod',
  };
  const signedProof = await options.signer.sign({ document: prelimEntry, proof: proofTemplate });
  const allProofs: DataIntegrityProof[] = [{ ...proofTemplate, proofValue: signedProof.proofValue }];
  prelimEntry.proof = allProofs;

  const verified = await documentStateIsValid(
    prelimEntry,
    lastMeta.updateKeys,
    lastMeta.witness,
    true, // skipWitnessVerification
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`);
  }

  const meta: DIDResolutionMeta = {
    ...lastMeta,
    versionId: prelimEntry.versionId,
    updated: prelimEntry.versionTime,
    deactivated: true,
    updateKeys: params.updateKeys,
  };

  const didId = requireDidId(prelimEntry.state.id);

  return {
    did: requireDidId(prelimEntry.state.id),
    doc: prelimEntry.state,
    meta,
    log: [...log, prelimEntry],
  };
};

interface RequiredWitnessCheck {
  targetVersionId: string;
  targetVersionNumber: number;
  witness: WitnessParameterResolution;
}

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

  // A list change takes effect only after its entry is published, so the previous list
  // governs that entry; only activation from {} uses the new (current) list immediately.
  if (isWitnessActive(previousWitness)) {
    return deepClone(previousWitness);
  }

  if (explicitWitness !== undefined && isWitnessActive(currentWitness)) {
    return deepClone(currentWitness);
  }

  return undefined;
};
