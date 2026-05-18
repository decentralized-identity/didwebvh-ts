import { createDate, createDIDDoc, createSCID, deriveHash, findVerificationMethod, getBaseUrl, replaceValueInObject, deepClone } from "../utils";
import {METHOD, PLACEHOLDER } from '../constants';
import { documentStateIsValid, hashChainValid, newKeysAreInNextKeys, scidIsFromHash } from '../assertions';
import type { CreateDIDInterface, DIDResolutionMeta, DIDLogEntry, DIDLog, UpdateDIDInterface, DeactivateDIDInterface, ResolutionOptions, WitnessProofFileEntry, WitnessParameterResolution } from '../interfaces';
import { verifyWitnessProofs, validateWitnessParameter, fetchWitnessProofs } from '../witness';

const VERSION = '0.5';
const PROTOCOL = `did:${METHOD}:${VERSION}`;

export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied')
  }
  
  if (options.witness && options.witness.witnesses && options.witness.witnesses.length > 0) {
    validateWitnessParameter(options.witness);
  }
  
  const encodedDomain = encodeURIComponent(options.domain);
  const path = options.paths?.join(':');
  const controller = `did:${METHOD}:${PLACEHOLDER}:${encodedDomain}${path ? `:${path}` : ''}`;
  const createdDate = createDate(options.created);
  
  // Safety guard: Strip secret keys from verification methods before creating DID document
  const safeVerificationMethods = options.verificationMethods?.map(vm => {
    if (vm.secretKeyMultibase) {
      console.warn('Warning: Removing secretKeyMultibase from verification method - secret keys should not be stored in DID documents');
      const { secretKeyMultibase, ...safeVm } = vm;
      return safeVm;
    }
    return vm;
  });
  
  let {doc} = await createDIDDoc({...options, controller, verificationMethods: safeVerificationMethods});
  const params = {
    scid: PLACEHOLDER,
    updateKeys: options.updateKeys,
    portable: options.portable ?? false,
    nextKeyHashes: options.nextKeyHashes ?? [],
    watchers: options.watchers ?? null,
    ...(options.witness ? {
      witness: options.witness
    } : {}),
    deactivated: false
  };
  const initialLogEntry: DIDLogEntry = {
    versionId: PLACEHOLDER,
    versionTime: createdDate,
    parameters: {
      method: PROTOCOL,
      ...params
    },
    state: doc
  };
  const initialLogEntryHash = await deriveHash(initialLogEntry);
  params.scid = await createSCID(initialLogEntryHash);
  initialLogEntry.state = doc;
  const prelimEntry = JSON.parse(JSON.stringify(initialLogEntry).replaceAll(PLACEHOLDER, params.scid));
  const logEntryHash2 = await deriveHash(prelimEntry);
  prelimEntry.versionId = `1-${logEntryHash2}`;
  const proof = await options.signer.sign({ document: prelimEntry, proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: options.signer.getVerificationMethodId(), created: createdDate, proofPurpose: 'assertionMethod' } });
  let allProofs = [{ type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: options.signer.getVerificationMethodId(), created: createdDate, proofPurpose: 'assertionMethod', proofValue: proof.proofValue }];
  prelimEntry.proof = allProofs;

  const verified = await documentStateIsValid(
    {...prelimEntry, versionId: `1-${logEntryHash2}`, proof: prelimEntry.proof}, 
    params.updateKeys, 
    params.witness,
    true,
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`)
  }

  let witness = {};
  if (params.witness) {
    witness = {...params.witness, threshold: params.witness.threshold?.toString() || '0'};
  }

  return {
    did: prelimEntry.state.id!,
    doc: prelimEntry.state,
    meta: {
      versionId: prelimEntry.versionId,
      created: prelimEntry.versionTime,
      updated: prelimEntry.versionTime,
      prerotation: (params.nextKeyHashes?.length ?? 0) > 0,
      ...params,
      witness: witness
    },
    log: [
      prelimEntry
    ]
  }
}

export const resolveDIDFromLog = async (log: DIDLog, options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}): Promise<{did: string, doc: any, meta: DIDResolutionMeta}> => {
  if (options.verificationMethod && (options.versionNumber || options.versionId)) {
    throw new Error("Cannot specify both verificationMethod and version number/id");
  }
  const resolutionLog = log.map(l => deepClone(l));
  const protocol = resolutionLog[0].parameters.method;
  if(protocol !== PROTOCOL) {
    throw new Error(`'${protocol}' protocol unknown.`);
  }
  let doc: any = {};
  let did = '';
  let meta: DIDResolutionMeta = {
    versionId: '',
    created: '',
    updated: '',
    previousLogEntryHash: '',
    scid: '',
    prerotation: false,
    portable: false,
    nextKeyHashes: [],
    deactivated: false,
    updateKeys: [],
    witness: undefined,
    watchers: null
  };
  let host = '';
  let i = 0;

  let resolvedDoc: any = null;
  let resolvedMeta: DIDResolutionMeta | null = null;
  let lastValidDoc: any = null;
  let lastValidMeta: DIDResolutionMeta | null = null;

  try {
  while (i < resolutionLog.length) {
    const { versionId, versionTime, parameters, state, proof } = resolutionLog[i];
    const [version, entryHash] = versionId.split('-');
    if (parseInt(version) !== i + 1) {
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
      host = newDoc.id.split(':').at(-1);
      meta.scid = parameters.scid;
      meta.portable = parameters.portable ?? meta.portable;
      meta.updateKeys = parameters.updateKeys;
      meta.nextKeyHashes = parameters.nextKeyHashes || [];
      meta.prerotation = meta.nextKeyHashes.length > 0;
      meta.witness = parameters.witness || meta.witness;
      meta.watchers = parameters.watchers ?? null;
      meta.nextKeyHashes = parameters.nextKeyHashes ?? [];
      // Optimized: Use efficient object manipulation instead of JSON stringify/parse
      const logEntry = {
        versionId: PLACEHOLDER,
        versionTime: meta.created,
        parameters: replaceValueInObject(parameters, meta.scid, PLACEHOLDER),
        state: replaceValueInObject(newDoc, meta.scid, PLACEHOLDER)
      };
      
      const logEntryHash = await deriveHash(logEntry);
      meta.previousLogEntryHash = logEntryHash;
      if (!await scidIsFromHash(meta.scid, logEntryHash)) {
        throw new Error(`SCID '${meta.scid}' not derived from logEntryHash '${logEntryHash}'`);
      }
      
      // Optimized: Direct object manipulation instead of JSON stringify/parse
      const prelimEntry = replaceValueInObject(logEntry, PLACEHOLDER, meta.scid);
      const logEntryHash2 = await deriveHash(prelimEntry);
      const verified = await documentStateIsValid({...prelimEntry, versionId: `1-${logEntryHash2}`, proof}, meta.updateKeys, meta.witness, false, options.verifier);
      if (!verified) {
        throw new Error(`version ${meta.versionId} failed verification of the proof.`)
      }
    } else {
      // version number > 1
      const newHost = newDoc.id.split(':').at(-1);
      if (!meta.portable && newHost !== host) {
        throw new Error("Cannot move DID: portability is disabled");
      } else if (newHost !== host) {
        host = newHost;
      }
      const keys = meta.prerotation ? parameters.updateKeys : meta.updateKeys;
      const verified = await documentStateIsValid(resolutionLog[i], keys, meta.witness, false, options.verifier);
      if (!verified) {
        throw new Error(`version ${meta.versionId} failed verification of the proof.`)
      }

      if (!hashChainValid(`${i+1}-${entryHash}`, versionId)) {
        throw new Error(`Hash chain broken at '${meta.versionId}'`);
      }

      if (meta.prerotation) {
        await newKeysAreInNextKeys(
          parameters.updateKeys ?? [], 
          meta.nextKeyHashes ?? []
        );
      }

      if (parameters.updateKeys) {
        meta.updateKeys = parameters.updateKeys;
      }
      if (parameters.deactivated === true) {
        meta.deactivated = true;
      }
      if (parameters.nextKeyHashes) {
        meta.nextKeyHashes = parameters.nextKeyHashes;
        meta.prerotation = true;
      } else {
        meta.nextKeyHashes = [];
        meta.prerotation = false;
      }
      if ('witness' in parameters) {
        meta.witness = parameters.witness;
      } else if (parameters.witnesses) {
        meta.witness = {
          witnesses: parameters.witnesses,
          threshold: parameters.witnessThreshold || parameters.witnesses.length.toString()
        };
      }
      if ('watchers' in parameters) {
        meta.watchers = parameters.watchers ?? null;
      }
    }
    // Optimized: Use efficient cloning instead of clone() function
    doc = deepClone(newDoc);
    did = doc.id;

    // Add default services if they don't exist
    doc.service = doc.service || [];
    const baseUrl = getBaseUrl(did);

    if (!doc.service.some((s: any) => s.id === '#files')) {
      doc.service.push({
        id: '#files',
        type: 'relativeRef',
        serviceEndpoint: baseUrl
      });
    }

    if (!doc.service.some((s: any) => s.id === '#whois')) {
      doc.service.push({
        "@context": "https://identity.foundation/linked-vp/contexts/v1",
        id: '#whois',
        type: 'LinkedVerifiablePresentation',
        serviceEndpoint: `${baseUrl}/whois.vp`
      });
    }

    if (options.verificationMethod && findVerificationMethod(doc, options.verificationMethod)) {
      if (!resolvedDoc) {
        resolvedDoc = deepClone(doc);
        resolvedMeta = { ...meta };
      }
    }

    if (options.versionNumber === parseInt(version) || options.versionId === meta.versionId) {
      if (!resolvedDoc) {
        resolvedDoc = deepClone(doc);
        resolvedMeta = { ...meta };
      }
    }
    if (options.versionTime && options.versionTime > new Date(meta.updated)) {
      if (resolutionLog[i+1] && options.versionTime < new Date(resolutionLog[i+1].versionTime)) {
        if (!resolvedDoc) {
          resolvedDoc = deepClone(doc);
          resolvedMeta = { ...meta };
        }
      } else if(!resolutionLog[i+1]) {
        if (!resolvedDoc) {
          resolvedDoc = deepClone(doc);
          resolvedMeta = { ...meta };
        }
      }
    }

    if (meta.witness && i === resolutionLog.length - 1) {
      if (!options.witnessProofs) {
        options.witnessProofs = await fetchWitnessProofs(did);
      }

      const validProofs = options.witnessProofs.filter((wp: WitnessProofFileEntry) => {
        return wp.versionId === meta.versionId;
      });

      if (validProofs.length > 0) {
        await verifyWitnessProofs(resolutionLog[i], validProofs, meta.witness!, options.verifier);
      } else if (meta.witness && meta.witness.threshold && parseInt(meta.witness.threshold.toString()) > 0) {
        throw new Error('No witness proofs found for version ' + meta.versionId);
      }
    }

    lastValidDoc = deepClone(doc);
    lastValidMeta = { ...meta };

    i++;
  }
  } catch (e) {
    if (!resolvedDoc) {
      throw e;
    }
  }

  if (!lastValidDoc || !lastValidMeta) {
    throw new Error('DID log is invalid');
  }

  const finalDoc = resolvedDoc || lastValidDoc;
  const finalMeta = resolvedMeta || lastValidMeta;
  finalMeta.latestVersionId = lastValidMeta.versionId;
  if (finalMeta.witness) {
    finalMeta.witness.threshold = finalMeta.witness.threshold?.toString() || '0';
  }

  return {did: finalDoc.id, doc: finalDoc, meta: finalMeta};
}

export const updateDID = async (options: UpdateDIDInterface & { services?: any[], domain?: string, updated?: string }): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveDIDFromLog(log, { verifier: options.verifier, witnessProofs: options.witnessProofs })).meta;
  if (lastMeta.deactivated) {
    throw new Error('Cannot update deactivated DID');
  }
  const versionNumber = log.length + 1;
  const createdDate = createDate(options.updated);
  const watchersValue = options.watchers !== undefined ? options.watchers : lastMeta.watchers;
  const params = {
    updateKeys: options.updateKeys ?? [],
    nextKeyHashes: options.nextKeyHashes ?? [],
    ...(options.witness === null ? {
      witness: {}
    } : options.witness !== undefined ? {
      witnesses: options.witness?.witnesses || [],
      threshold: options.witness?.threshold || '0'
    } : {}),
    watchers: watchersValue ?? null
  };
  
  // Safety guard: Strip secret keys from verification methods before creating DID document  
  const safeVerificationMethods = options.verificationMethods?.map(vm => {
    if (vm.secretKeyMultibase) {
      console.warn('Warning: Removing secretKeyMultibase from verification method - secret keys should not be stored in DID documents');
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
    verificationMethods: safeVerificationMethods ?? []
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
    versionId: PLACEHOLDER,
    versionTime: createdDate,
    parameters: params,
    state: doc
  };
  const logEntryHash = await deriveHash(logEntry);
  const versionId = `${versionNumber}-${logEntryHash}`;
  const prelimEntry = { ...logEntry, versionId };
  const proof = await options.signer.sign({ document: prelimEntry, proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: options.signer.getVerificationMethodId(), created: createdDate, proofPurpose: 'assertionMethod' } });
  let allProofs = [{ type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: options.signer.getVerificationMethodId(), created: createdDate, proofPurpose: 'assertionMethod', proofValue: proof.proofValue }];
  prelimEntry.proof = allProofs;

  const verified = await documentStateIsValid(
    prelimEntry, 
    lastMeta.updateKeys, 
    lastMeta.witness,
    true, // skipWitnessVerification
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`)
  }

  const meta: DIDResolutionMeta = {
    ...lastMeta,
    versionId: prelimEntry.versionId,
    updated: prelimEntry.versionTime,
    prerotation: (params.nextKeyHashes?.length ?? 0) > 0,
    ...params
  };

  return {
    did: prelimEntry.state.id!,
    doc: prelimEntry.state,
    meta,
    log: [
      ...log,
      prelimEntry
    ]
  }
}

export const deactivateDID = async (options: DeactivateDIDInterface & { updateKeys?: string[] }): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
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
    deactivated: true
  };
  const logEntry: DIDLogEntry = {
    versionId: PLACEHOLDER,
    versionTime: createdDate,
    parameters: params,
    state: lastEntry.state
  };
  const logEntryHash = await deriveHash(logEntry);
  const versionId = `${versionNumber}-${logEntryHash}`;
  const prelimEntry = { ...logEntry, versionId };
  const proof = await options.signer.sign({ document: prelimEntry, proof: { type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: options.signer.getVerificationMethodId(), created: createdDate, proofPurpose: 'assertionMethod' } });
  let allProofs = [{ type: 'DataIntegrityProof', cryptosuite: 'eddsa-jcs-2022', verificationMethod: options.signer.getVerificationMethodId(), created: createdDate, proofPurpose: 'assertionMethod', proofValue: proof.proofValue }];
  prelimEntry.proof = allProofs;

  const verified = await documentStateIsValid(
    prelimEntry, 
    lastMeta.updateKeys, 
    lastMeta.witness,
    true, // skipWitnessVerification
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`)
  }

  const meta: DIDResolutionMeta = {
    ...lastMeta,
    versionId: prelimEntry.versionId,
    updated: prelimEntry.versionTime,
    deactivated: true,
    updateKeys: params.updateKeys
  };

  return {
    did: prelimEntry.state.id!,
    doc: prelimEntry.state,
    meta,
    log: [
      ...log,
      prelimEntry
    ]
  }
}
