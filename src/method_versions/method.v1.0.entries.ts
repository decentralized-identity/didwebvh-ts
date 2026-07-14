import { documentStateIsValid, newKeysAreInNextKeys } from '../assertions';
import { METHOD, METHOD_PROTOCOL_V1_0, PLACEHOLDER } from '../constants';
import { createDataIntegrityProofTemplate, signDataIntegrityProof } from '../cryptography';
import type {
  CreateDIDInterface,
  DeactivateDIDInterface,
  DIDDoc,
  DIDLogEntry,
  DIDResolutionMeta,
  ServiceEndpoint,
  UpdateDIDInterface,
  WitnessParameterResolution,
} from '../interfaces';
import {
  createDIDDoc,
  createSCID,
  deepClone,
  deriveHash,
  enrichAlsoKnownAs,
  parseCanonicalAddress,
  parseDidWebvhIdentifier,
  replaceCreateDidPlaceholders,
  sanitizeVerificationMethods,
  validateCreateDidDocument,
  validateMethodSpecificPathSegments,
} from '../utils';
import { validateWitnessParameter } from '../witness';

export interface PreparedEntry {
  entry: DIDLogEntry;
  resolvedNextKeyHashes?: string[];
}

const resolveNextDidContext = ({
  options,
  lastEntryDid,
  parsedLastEntryDid,
  portable,
}: {
  options: UpdateDIDInterface & {
    services?: ServiceEndpoint[];
    address?: string;
    paths?: string[];
  };
  lastEntryDid: string;
  parsedLastEntryDid: ReturnType<typeof parseDidWebvhIdentifier>;
  portable: boolean;
}): { controller: string } => {
  const requestedAddress = options.address;
  if (!requestedAddress) {
    return {
      controller: lastEntryDid,
    };
  }

  const parsedNewAddress = parseCanonicalAddress(requestedAddress);
  const addressPaths = parsedNewAddress.paths || [];
  const newLocationPaths =
    options.paths !== undefined
      ? [...addressPaths, ...options.paths]
      : addressPaths.length
        ? addressPaths
        : (parsedLastEntryDid.paths ?? []);
  validateMethodSpecificPathSegments(newLocationPaths, 'updateDID path segments');
  const newLocationKey = newLocationPaths.length
    ? `${parsedNewAddress.didDomainComponent}:${newLocationPaths.join(':')}`
    : parsedNewAddress.didDomainComponent;
  const controller = `did:${METHOD}:${parsedLastEntryDid.scid}:${newLocationKey}`;

  if (controller !== lastEntryDid && !portable) {
    throw new Error('Cannot move DID: portability is disabled');
  }

  return {
    controller,
  };
};

const signControllerEntry = async (entry: DIDLogEntry, created: string, signer: CreateDIDInterface['signer']) => {
  const proofTemplate = createDataIntegrityProofTemplate({
    verificationMethod: signer.getVerificationMethodId(),
    created,
    proofPurpose: 'assertionMethod',
  });

  return signDataIntegrityProof(entry, proofTemplate, signer);
};

const validateProposedEntry = async (
  entry: DIDLogEntry,
  updateKeys: string[],
  witness: WitnessParameterResolution | undefined,
  verifier: CreateDIDInterface['verifier']
) => {
  const verified = await documentStateIsValid(entry, updateKeys, witness, true, verifier);

  if (!verified) {
    throw new Error(`version ${entry.versionId} is invalid.`);
  }
};

const finalizeNonGenesisEntry = async ({
  logEntry,
  versionNumber,
  created,
  signer,
  updateKeys,
  witness,
  verifier,
}: {
  logEntry: DIDLogEntry;
  versionNumber: number;
  created: string;
  signer: CreateDIDInterface['signer'];
  updateKeys: string[];
  witness: WitnessParameterResolution | undefined;
  verifier: CreateDIDInterface['verifier'];
}): Promise<DIDLogEntry> => {
  const logEntryHash = await deriveHash(logEntry);
  const entry = { ...logEntry, versionId: `${versionNumber}-${logEntryHash}` };
  entry.proof = [await signControllerEntry(entry, created, signer)];

  await validateProposedEntry(entry, updateKeys, witness, verifier);

  return entry;
};

export async function prepareGenesisEntry({
  options,
  controller,
  allPaths,
  createdDate,
}: {
  options: CreateDIDInterface;
  controller: string;
  allPaths: string[];
  createdDate: string;
}): Promise<PreparedEntry> {
  const safeVerificationMethods = sanitizeVerificationMethods(options.verificationMethods);

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
      did: controller,
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
  const didWithScid = controller.replaceAll(PLACEHOLDER, params.scid);
  const entry = replaceCreateDidPlaceholders(initialLogEntry, params.scid, didWithScid);
  entry.state = enrichAlsoKnownAs(entry.state, didWithScid, {
    alsoKnownAsWeb: options.alsoKnownAsWeb,
  });

  const logEntryHash = await deriveHash(entry);
  entry.versionId = `1-${logEntryHash}`;
  entry.proof = [await signControllerEntry(entry, createdDate, options.signer)];

  await validateProposedEntry(
    { ...entry, versionId: `1-${logEntryHash}` },
    params.updateKeys,
    params.witness,
    options.verifier
  );

  const didId = entry.state.id;
  if (!didId) {
    throw new Error('DID document id is missing');
  }
  if (didId !== didWithScid) {
    throw new Error(`Created DID document id must match expected DID '${didWithScid}', got '${didId}'`);
  }

  return { entry };
}

export async function prepareUpdateEntry({
  options,
  lastEntry,
  lastMeta,
  versionNumber,
  createdDate,
}: {
  options: UpdateDIDInterface & {
    services?: ServiceEndpoint[];
    address?: string;
    paths?: string[];
  };
  lastEntry: DIDLogEntry;
  lastMeta: DIDResolutionMeta;
  versionNumber: number;
  createdDate: string;
}): Promise<PreparedEntry> {
  const currentUpdateKeys = options.updateKeys;
  const lastEntryDid = lastEntry.state.id;
  if (!lastEntryDid) {
    throw new Error('DID document id is missing');
  }
  const parsedLastEntryDid = parseDidWebvhIdentifier(lastEntryDid, 'last entry state.id');

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

  const safeVerificationMethods = sanitizeVerificationMethods(options.verificationMethods);

  const { controller } = resolveNextDidContext({
    options,
    lastEntryDid,
    parsedLastEntryDid,
    portable: lastMeta.portable,
  });

  const { doc: normalizedUpdateDoc } = await createDIDDoc({
    ...options,
    did: controller,
    context: options.context || lastEntry.state['@context'],
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

  const keysToVerify = lastMeta.prerotation ? currentUpdateKeys : lastMeta.updateKeys;
  if (!keysToVerify) {
    throw new Error('updateKeys could not be determined for update verification');
  }

  const entry = await finalizeNonGenesisEntry({
    logEntry,
    versionNumber,
    created: createdDate,
    signer: options.signer,
    updateKeys: keysToVerify,
    witness: lastMeta.witness,
    verifier: options.verifier,
  });

  return { entry, resolvedNextKeyHashes };
}

export async function prepareDeactivationEntry({
  options,
  lastEntry,
  lastMeta,
  versionNumber,
  createdDate,
}: {
  options: DeactivateDIDInterface & { updateKeys?: string[] };
  lastEntry: DIDLogEntry;
  lastMeta: DIDResolutionMeta;
  versionNumber: number;
  createdDate: string;
}): Promise<PreparedEntry> {
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

  const entry = await finalizeNonGenesisEntry({
    logEntry,
    versionNumber,
    created: createdDate,
    signer: options.signer,
    updateKeys: lastMeta.updateKeys,
    witness: lastMeta.witness,
    verifier: options.verifier,
  });

  return { entry };
}
