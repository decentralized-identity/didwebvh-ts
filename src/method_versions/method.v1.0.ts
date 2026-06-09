import { documentStateIsValid, hashChainValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions';
import { METHOD, PLACEHOLDER } from '../constants';
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
  replaceCreateDidPlaceholders,
  replaceValueInObject,
  validateCreateDidDocument,
} from '../utils';
import { countVerifiedWitnessApprovals, fetchWitnessProofs, validateWitnessParameter } from '../witness';

const VERSION = '1.0';
const PROTOCOL = `did:${METHOD}:${VERSION}`;

const requireDidId = (id: string | undefined): string => {
  if (!id) {
    throw new Error('DID document id is missing');
  }
  return id;
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
  const path = allPaths.length > 0 ? allPaths.join(':') : undefined;
  const controller = `did:${METHOD}:${PLACEHOLDER}:${didDomainComponent}${path ? `:${path}` : ''}`;
  const createdDate = createDate(options.created);

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
      method: PROTOCOL,
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
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[]; fastResolve?: boolean } = {}
): Promise<{ did: string; doc: DIDDoc; meta: DIDResolutionMeta }> => {
  if (options.verificationMethod && (options.versionNumber || options.versionId)) {
    throw new Error('Cannot specify both verificationMethod and version number/id');
  }
  const resolutionLog = log.map((l) => deepClone(l));
  const protocol = resolutionLog[0]?.parameters?.method;
  if (protocol !== PROTOCOL) {
    throw new Error(`'${protocol}' is not a supported method version.`);
  }
  let did = '';
  let doc: DIDDoc | null = null;
  let resolvedDoc: DIDDoc | null = null;
  let lastValidDoc: DIDDoc | null = null;
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
  let host = '';
  const requiredWitnessChecks: RequiredWitnessCheck[] = [];

  // Fast resolution is opt-in; full verification is the default conformant path.
  const fastResolve = options.fastResolve ?? false;
  const isFirstEntry = (idx: number) => idx === 0;
  const isLastFewEntries = (idx: number) => idx >= resolutionLog.length - 10; // Verify last 10 entries
  const shouldVerifyEntry = (idx: number) => !fastResolve || isFirstEntry(idx) || isLastFewEntries(idx);

  try {
    while (i < resolutionLog.length) {
      const { versionId, versionTime, parameters, state, proof } = resolutionLog[i];
      const [version, entryHash] = versionId.split('-');
      const previousWitness = meta.witness ? deepClone(meta.witness) : undefined;
      if (parseInt(version, 10) !== i + 1) {
        throw new Error(`version '${version}' in log doesn't match expected '${i + 1}'.`);
      }
      meta.versionId = versionId;
      if (versionTime) {
        // TODO check timestamps make sense
      }
      meta.updated = versionTime;
      let newDoc = state;

      if (version === '1') {
        meta.created = versionTime;
        newDoc = state;
        host = requireDidId(newDoc.id).split(':').at(-1) ?? '';
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

        if (shouldVerifyEntry(i)) {
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
        }
      } else {
        // version number > 1
        const newHost = requireDidId(newDoc.id).split(':').at(-1) ?? '';
        if (!meta.portable && newHost !== host) {
          throw new Error('Cannot move DID: portability is disabled');
        } else if (newHost !== host) {
          host = newHost;
        }

        // Hash chain — ALWAYS runs (cheap), even in fast-resolve
        const { proof: _proof, ...entryWithoutProof } = resolutionLog[i];
        const recomputedHash = await deriveHash({ ...entryWithoutProof, versionId: resolutionLog[i - 1].versionId });
        if (!hashChainValid(recomputedHash, entryHash)) {
          throw new Error(`Hash chain broken at '${meta.versionId}'`);
        }

        if (shouldVerifyEntry(i)) {
          // Signature verification — expensive, skipped for middle entries in fast-resolve
          const keys = meta.prerotation ? (parameters.updateKeys as string[]) : meta.updateKeys;
          const verified = await documentStateIsValid(resolutionLog[i], keys, meta.witness, false, options.verifier);
          if (!verified) {
            throw new Error(`version ${meta.versionId} failed verification of the proof.`);
          }

          if (meta.prerotation) {
            await newKeysAreInNextKeys(parameters.updateKeys ?? [], meta.nextKeyHashes ?? []);
          }
        }

        if (parameters.updateKeys) {
          meta.updateKeys = parameters.updateKeys;
        }
        if (parameters.deactivated === true) {
          meta.deactivated = true;
        }
        if (parameters.nextKeyHashes && parameters.nextKeyHashes.length > 0) {
          meta.nextKeyHashes = parameters.nextKeyHashes;
          meta.prerotation = true;
        } else {
          meta.nextKeyHashes = [];
          meta.prerotation = false;
        }
        const legacyParameters = parameters as typeof parameters & {
          witnesses?: { id: string }[];
          witnessThreshold?: string | number;
        };

        if ('witness' in parameters) {
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
        if ('watchers' in parameters) {
          meta.watchers = parameters.watchers ?? null;
        }
      }

      const requiredWitness = getRequiredWitnessForEntry(previousWitness, parameters, meta.witness);
      if (requiredWitness) {
        requiredWitnessChecks.push({
          targetVersionId: meta.versionId,
          targetVersionNumber: parseInt(version, 10),
          witness: requiredWitness,
        });
      }

      // Optimized: Use efficient cloning instead of clone() function
      doc = deepClone(newDoc);
      did = requireDidId(doc.id);

      // Only add default services for entries we need to process
      if (shouldVerifyEntry(i) || i === resolutionLog.length - 1) {
        // Add default services if they don't exist
        doc.service = Array.isArray(doc.service) ? doc.service : [];
        const baseUrl = getBaseUrl(did);

        if (!doc.service.some((s: ServiceEndpoint) => s.id === '#files')) {
          doc.service.push({
            id: '#files',
            type: 'relativeRef',
            serviceEndpoint: baseUrl,
          });
        }

        if (!doc.service.some((s: ServiceEndpoint) => s.id === '#whois')) {
          doc.service.push({
            '@context': 'https://identity.foundation/linked-vp/contexts/v1',
            id: '#whois',
            type: 'LinkedVerifiablePresentation',
            serviceEndpoint: `${baseUrl}/whois.vp`,
          });
        }
      }

      if (options.verificationMethod && findVerificationMethod(doc, options.verificationMethod)) {
        if (!resolvedDoc) {
          resolvedDoc = deepClone(doc);
          resolvedMeta = { ...meta };
        }
      }

      if (options.versionNumber === parseInt(version, 10) || options.versionId === meta.versionId) {
        if (!resolvedDoc) {
          resolvedDoc = deepClone(doc);
          resolvedMeta = { ...meta };
        }
      }
      if (options.versionTime && options.versionTime > new Date(meta.updated)) {
        if (resolutionLog[i + 1] && options.versionTime < new Date(resolutionLog[i + 1].versionTime)) {
          if (!resolvedDoc) {
            resolvedDoc = deepClone(doc);
            resolvedMeta = { ...meta };
          }
        } else if (!resolutionLog[i + 1]) {
          if (!resolvedDoc) {
            resolvedDoc = deepClone(doc);
            resolvedMeta = { ...meta };
          }
        }
      }

      lastValidDoc = deepClone(doc);
      lastValidMeta = { ...meta };

      i++;
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
    if (resolvedMeta) {
      const message = e instanceof Error ? e.message : String(e);
      resolvedMeta.error = DidResolutionError.InvalidDid;
      resolvedMeta.problemDetails = {
        type: 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
        title: 'The resolved DID is invalid.',
        detail: message,
      };
    }
  }

  if (!resolvedDoc) {
    resolvedDoc = lastValidDoc;
    resolvedMeta = lastValidMeta;
  }

  if (!resolvedMeta) {
    throw new Error('DID resolution failed: No valid metadata found');
  }

  if (!resolvedDoc) {
    throw new Error('DID resolution failed: No valid document found');
  }

  return {
    did: requireDidId(resolvedDoc.id),
    doc: resolvedDoc,
    meta: resolvedMeta,
  };
};

export const updateDID = async (
  options: UpdateDIDInterface & { services?: ServiceEndpoint[]; domain?: string; updated?: string }
): Promise<UpdateDIDResult> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveDIDFromLog(log, { verifier: options.verifier, witnessProofs: options.witnessProofs }))
    .meta;
  if (lastMeta.deactivated) {
    throw new Error('Cannot update deactivated DID');
  }
  const versionNumber = log.length + 1;
  const createdDate = createDate(options.updated);
  const watchersValue = options.watchers !== undefined ? options.watchers : lastMeta.watchers;
  const witnessInput = options.witness;
  const witness = witnessInput?.witnesses?.length
    ? {
        witnesses: witnessInput.witnesses,
        threshold: witnessInput.threshold ?? 0,
      }
    : {};
  const params = {
    updateKeys: options.updateKeys ?? [],
    nextKeyHashes: options.nextKeyHashes ?? [],
    witness,
    watchers: watchersValue ?? [],
  };

  if (params.witness?.witnesses?.length) {
    validateWitnessParameter(params.witness);
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

  const { doc } = await createDIDDoc({
    ...options,
    controller: options.controller || lastEntry.state.id || '',
    context: options.context || lastEntry.state['@context'],
    domain: options.domain ?? lastEntry.state.id?.split(':').at(-1) ?? '',
    updateKeys: options.updateKeys ?? [],
    verificationMethods: safeVerificationMethods ?? [],
  });

  // Add services if provided
  if (options.services && options.services.length > 0) {
    doc.service = options.services;
  }

  // Add assertionMethod if provided
  if (options.assertionMethod) {
    doc.assertionMethod = options.assertionMethod;
  }

  // Add keyAgreement if provided
  if (options.keyAgreement) {
    doc.keyAgreement = options.keyAgreement;
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
  const keysToVerify = lastMeta.prerotation ? params.updateKeys : lastMeta.updateKeys;
  const verified = await documentStateIsValid(prelimEntry, keysToVerify, lastMeta.witness, true, options.verifier);
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`);
  }

  const meta: DIDResolutionMeta = {
    ...lastMeta,
    versionId: prelimEntry.versionId,
    updated: prelimEntry.versionTime,
    prerotation: (params.nextKeyHashes?.length ?? 0) > 0,
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
  const createdDate = createDate();
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

  if (explicitWitness !== undefined) {
    if (isWitnessActive(currentWitness)) {
      return deepClone(currentWitness);
    }

    if (isWitnessActive(previousWitness)) {
      return deepClone(previousWitness);
    }

    return undefined;
  }

  if (isWitnessActive(previousWitness)) {
    return deepClone(previousWitness);
  }

  return undefined;
};
