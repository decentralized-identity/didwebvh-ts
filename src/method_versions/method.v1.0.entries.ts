import { documentStateIsValid, newKeysAreInNextKeys } from '../assertions';
import { METHOD_PROTOCOL_V1_0, SCID_PLACEHOLDER } from '../constants';
import { createDataIntegrityProofTemplate, signDataIntegrityProof } from '../cryptography';
import {
  createDIDDoc,
  enrichAlsoKnownAs,
  replaceCreateDidPlaceholders,
  validateCreateDidDocument,
} from '../did-document';
import type {
  CreateDIDInterface,
  DeactivateDIDInterface,
  DIDDoc,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  ServiceEndpoint,
  UpdateDIDInterface,
  WitnessParameterResolution,
} from '../interfaces';
import { deepClone, normalizeDidAddress, parseDidWebvhIdentifier } from '../utils';
import { createSCID, deriveHash } from '../utils/crypto';
import { sanitizeVerificationMethods } from '../utils/verification-methods';
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

  const normalizedAddress = normalizeDidAddress({
    address: requestedAddress,
    scid: parsedLastEntryDid.scid,
    paths: options.paths,
    fallbackPaths: parsedLastEntryDid.paths ?? [],
    context: 'updateDID path segments',
  });
  const controller = normalizedAddress.controller;

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

function shouldInjectMethodParameter(log: DIDLog): boolean {
  const genesisMethod = log[0].parameters.method as string | undefined;
  // Fast path: only v0.5 genesis can transition to v1.0
  if (genesisMethod !== 'did:webvh:0.5') {
    return false;
  }
  // Check if already transitioned
  const hasAlreadyTransitioned = log.slice(1).some((entry) => entry.parameters.method === METHOD_PROTOCOL_V1_0);
  return !hasAlreadyTransitioned;
}

export async function prepareGenesisEntry({
  options,
  controller,
  createdDate,
}: {
  options: CreateDIDInterface;
  controller: string;
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
    scid: SCID_PLACEHOLDER,
    updateKeys: options.updateKeys,
    portable: options.portable ?? false,
    nextKeyHashes: options.nextKeyHashes ?? [],
    watchers: options.watchers ?? [],
    witness: options.witness ?? {},
    deactivated: false,
  };

  const initialLogEntry: DIDLogEntry = {
    versionId: SCID_PLACEHOLDER,
    versionTime: createdDate,
    parameters: {
      method: METHOD_PROTOCOL_V1_0,
      ...params,
    },
    state: doc,
  };

  const initialLogEntryHash = await deriveHash(initialLogEntry);
  params.scid = await createSCID(initialLogEntryHash);
  const didWithScid = controller.replaceAll(SCID_PLACEHOLDER, params.scid);
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
  log,
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
  log: DIDLog;
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
  const witness: Record<string, unknown> = witnessInput?.witnesses?.length
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

  const params: Record<string, unknown> = shouldInjectMethodParameter(log) ? { method: METHOD_PROTOCOL_V1_0 } : {};

  if (options.updateKeys !== undefined || lastMeta.prerotation) {
    params.updateKeys = options.updateKeys ?? lastMeta.updateKeys;
  }
  if (options.nextKeyHashes !== undefined) {
    params.nextKeyHashes = options.nextKeyHashes;
  }
  if (options.portable === false) {
    params.portable = false;
  }
  params.witness = witness;
  params.watchers = watchersValue ?? [];

  if (witness && 'witnesses' in witness && Array.isArray(witness.witnesses) && witness.witnesses.length) {
    validateWitnessParameter(witness as WitnessParameterResolution);
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
  log,
  versionNumber,
  createdDate,
}: {
  options: DeactivateDIDInterface & { updateKeys?: string[] };
  lastEntry: DIDLogEntry;
  lastMeta: DIDResolutionMeta;
  log: DIDLog;
  versionNumber: number;
  createdDate: string;
}): Promise<PreparedEntry> {
  if (lastMeta.prerotation) {
    await newKeysAreInNextKeys(options.updateKeys ?? [], lastMeta.nextKeyHashes ?? []);
  }

  const params = {
    ...(shouldInjectMethodParameter(log) ? { method: METHOD_PROTOCOL_V1_0 } : {}),
    updateKeys: options.updateKeys ?? lastMeta.updateKeys,
    // Close the rotation: a deactivated DID carries no dangling key commitment.
    nextKeyHashes: [],
    deactivated: true,
  };

  const logEntry: DIDLogEntry = {
    versionId: lastEntry.versionId,
    versionTime: createdDate,
    parameters: params,
    state: lastEntry.state,
  };

  // Under active pre-rotation the resolver verifies this entry against its own
  // updateKeys, so sign and validate with the pre-committed keys.
  const keysToVerify = lastMeta.prerotation ? options.updateKeys : lastMeta.updateKeys;
  if (!keysToVerify) {
    throw new Error('updateKeys could not be determined for deactivation verification');
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

  return { entry };
}
