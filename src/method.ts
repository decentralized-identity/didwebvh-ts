import { clone, createDate, createDIDDoc, createSCID, deriveHash, fetchLogFromIdentifier, findVerificationMethod, getActiveDIDs, getBaseUrl, normalizeVMs } from "./utils";
import { BASE_CONTEXT, METHOD, PLACEHOLDER, PROTOCOL } from './constants';
import { documentStateIsValid, hashChainValid, newKeysAreInNextKeys, scidIsFromHash } from './assertions';
import type { CreateDIDInterface, DIDResolutionMeta, DIDLogEntry, DIDLog, UpdateDIDInterface, DeactivateDIDInterface, ResolutionOptions, WitnessProofFileEntry, DataIntegrityProof } from './interfaces';
import { verifyWitnessProofs, validateWitnessParameter, fetchWitnessProofs } from './witness';

export const createDID = async (options: CreateDIDInterface): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
  if (!options.updateKeys) {
    throw new Error('Update keys not supplied')
  }
  
  if (options.witness && options.witness.witnesses.length > 0) {
    validateWitnessParameter(options.witness);
  }
  
  const controller = `did:${METHOD}:${PLACEHOLDER}:${options.domain}`;
  const createdDate = createDate(options.created);
  let {doc} = await createDIDDoc({...options, controller});
  const params = {
    scid: PLACEHOLDER,
    updateKeys: options.updateKeys,
    portable: options.portable ?? false,
    nextKeyHashes: options.nextKeyHashes ?? [],
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
    true, // skipWitnessVerification
    options.verifier
  );
  if (!verified) {
    throw new Error(`version ${prelimEntry.versionId} is invalid.`)
  }

  return {
    did: prelimEntry.state.id!,
    doc: prelimEntry.state,
    meta: {
      versionId: prelimEntry.versionId,
      created: prelimEntry.versionTime,
      updated: prelimEntry.versionTime,
      prerotation: (params.nextKeyHashes?.length ?? 0) > 0,
      ...params
    },
    log: [
      prelimEntry
    ]
  }
}

export const resolveDID = async (did: string, options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}): Promise<{did: string, doc: any, meta: DIDResolutionMeta, controlled: boolean}> => {
  const activeDIDs = await getActiveDIDs();
  const controlled = activeDIDs.includes(did);
  const log = await fetchLogFromIdentifier(did, controlled);
  
  if (log.length === 0) {
    throw new Error(`DID ${did} not found`);
  }

  return {
    ...(await resolveDIDFromLog(log, { ...options })), 
    controlled
  };
}

export const resolveDIDFromLog = async (log: DIDLog, options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}): Promise<{did: string, doc: any, meta: DIDResolutionMeta}> => {
  if (options.verificationMethod && (options.versionNumber || options.versionId)) {
    throw new Error("Cannot specify both verificationMethod and version number/id");
  }
  const resolutionLog = clone(log);
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
    witness: undefined
  };
  let host = '';
  let i = 0;
  
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
      meta.nextKeyHashes = parameters.nextKeyHashes ?? [];
      const logEntry = {
        versionId: PLACEHOLDER,
        versionTime: meta.created,
        parameters: JSON.parse(JSON.stringify(parameters).replaceAll(meta.scid, PLACEHOLDER)),
        state: JSON.parse(JSON.stringify(newDoc).replaceAll(meta.scid, PLACEHOLDER))
      };
      const logEntryHash = await deriveHash(logEntry);
      meta.previousLogEntryHash = logEntryHash;
      if (!await scidIsFromHash(meta.scid, logEntryHash)) {
        throw new Error(`SCID '${meta.scid}' not derived from logEntryHash '${logEntryHash}'`);
      }
      const prelimEntry = JSON.parse(JSON.stringify(logEntry).replaceAll(PLACEHOLDER, meta.scid));
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
          threshold: parameters.witnessThreshold || parameters.witnesses.length
        };
      }
    }
    doc = clone(newDoc);
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
      return {did, doc, meta};
    }

    if (options.versionNumber === parseInt(version) || options.versionId === meta.versionId) {
      return {did, doc, meta};
    }
    if (options.versionTime && options.versionTime > new Date(meta.updated)) {
      if (resolutionLog[i+1] && options.versionTime < new Date(resolutionLog[i+1].versionTime)) {
        return {did, doc, meta};
      } else if(!resolutionLog[i+1]) {
        return {did, doc, meta};
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
      }
    }

    i++;
  }

  return {did, doc, meta};
}

export const updateDID = async (options: UpdateDIDInterface & { services?: any[], domain?: string, updated?: string }): Promise<{did: string, doc: any, meta: DIDResolutionMeta, log: DIDLog}> => {
  const log = options.log;
  const lastEntry = log[log.length - 1];
  const lastMeta = (await resolveDIDFromLog(log, { verifier: options.verifier })).meta;
  if (lastMeta.deactivated) {
    throw new Error('Cannot update deactivated DID');
  }
  const versionNumber = log.length + 1;
  const createdDate = createDate(options.updated);
  const params = {
    updateKeys: options.updateKeys ?? [],
    nextKeyHashes: options.nextKeyHashes ?? [],
    ...(options.witness === null ? {
      witness: null
    } : options.witness !== undefined ? {
      witnesses: options.witness?.witnesses || [],
      witnessThreshold: options.witness?.threshold || 0
    } : {})
  };
  const { doc } = await createDIDDoc({
    ...options,
    controller: options.controller || lastEntry.state.id || '',
    context: options.context || lastEntry.state['@context'],
    domain: options.domain ?? lastEntry.state.id?.split(':').at(-1) ?? '',
    updateKeys: options.updateKeys ?? [],
    verificationMethods: options.verificationMethods ?? []
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
