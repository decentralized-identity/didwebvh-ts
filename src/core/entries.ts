import type { DIDDocument } from 'did-resolver';
import { assertValidNextKeyHashes, documentStateIsValid, newKeysAreInNextKeys } from '../assertions.js';
import { DID_PLACEHOLDER, METHOD_PROTOCOL_V1_0, SCID_PLACEHOLDER, VERIFICATION_RELATIONSHIPS } from '../constants.js';
import { createDataIntegrityProofTemplate, signDataIntegrityProof } from '../cryptography.js';
import { enrichAlsoKnownAs, replaceCreateDidPlaceholders, validateCreateDidDocument } from '../did-document.js';
import type {
  CreateDIDOptions,
  DeactivateDIDOptions,
  DIDLog,
  DIDLogEntry,
  DIDResolutionMeta,
  UpdateDIDOptions,
  WitnessParameterResolution,
} from '../interfaces.js';
import { createSCID, deriveHash } from '../utils/crypto.js';
import {
  assertNoPrivateVerificationMaterial,
  assertValidAuthoredVerificationMethods,
} from '../utils/verification-methods.js';
import { deepClone, normalizeDidAddress, parseDidWebvhIdentifier, replaceValueInObject } from '../utils.js';
import { validateWitnessParameter } from '../witness.js';

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
  options: UpdateDIDOptions;
  lastEntryDid: string;
  parsedLastEntryDid: ReturnType<typeof parseDidWebvhIdentifier>;
  portable: boolean;
}): { did: string } => {
  const requestedAddress = options.address;
  if (!requestedAddress) {
    return {
      did: lastEntryDid,
    };
  }

  const normalizedAddress = normalizeDidAddress({
    address: requestedAddress,
    scid: parsedLastEntryDid.scid,
    paths: options.paths,
    fallbackPaths: parsedLastEntryDid.paths ?? [],
    context: 'updateDID path segments',
  });
  const did = normalizedAddress.did;

  if (did !== lastEntryDid && !portable) {
    throw new Error('Cannot move DID: portability is disabled');
  }

  return {
    did,
  };
};

const signControllerEntry = async (entry: DIDLogEntry, created: string, signer: CreateDIDOptions['signer']) => {
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
  verifier: CreateDIDOptions['verifier']
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
  signer: CreateDIDOptions['signer'];
  updateKeys: string[];
  witness: WitnessParameterResolution | undefined;
  verifier: CreateDIDOptions['verifier'];
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
  did,
  createdDate,
}: {
  options: CreateDIDOptions;
  did: string;
  createdDate: string;
}): Promise<PreparedEntry> {
  if (!options.didDocument) {
    throw new Error('didDocument is required to create a DID');
  }

  validateCreateDidDocument(options.didDocument);
  assertNoPrivateVerificationMaterial(options.didDocument);
  assertValidAuthoredVerificationMethods(options.didDocument);
  let doc = replaceValueInObject(deepClone(options.didDocument), DID_PLACEHOLDER, did) as DIDDocument;

  doc = enrichAlsoKnownAs(doc, did, {
    alsoKnownAsWeb: options.alsoKnownAsWeb,
  });

  const nextKeyHashes = options.nextKeyHashes !== undefined ? assertValidNextKeyHashes(options.nextKeyHashes) : [];
  const params = {
    scid: SCID_PLACEHOLDER,
    updateKeys: options.updateKeys,
    portable: options.portable ?? false,
    nextKeyHashes,
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
  const didWithScid = did.replaceAll(SCID_PLACEHOLDER, params.scid);
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
  options: UpdateDIDOptions;
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
  const resolvedNextKeyHashes =
    options.nextKeyHashes !== undefined
      ? assertValidNextKeyHashes(options.nextKeyHashes)
      : (lastMeta.nextKeyHashes ?? []);
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
    params.nextKeyHashes = resolvedNextKeyHashes;
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

  const { did: nextDid } = resolveNextDidContext({
    options,
    lastEntryDid,
    parsedLastEntryDid,
    portable: lastMeta.portable,
  });

  let doc: DIDDocument;
  if (options.didDocument) {
    assertNoPrivateVerificationMaterial(options.didDocument);
    assertValidAuthoredVerificationMethods(options.didDocument);
    doc = replaceCreateDidPlaceholders(deepClone(options.didDocument), parsedLastEntryDid.scid, nextDid);

    if (doc.id && nextDid === lastEntryDid && doc.id !== lastEntryDid) {
      throw new Error(`Updated DID document id must match expected DID '${lastEntryDid}', got '${doc.id}'`);
    }
  } else {
    doc = deepClone(lastEntry.state);
  }

  if (nextDid !== lastEntryDid) {
    doc.id = nextDid;

    // Rewrite self-referential top-level controller
    if (typeof doc.controller === 'string') {
      if (doc.controller === lastEntryDid) {
        doc.controller = nextDid;
      }
    } else if (Array.isArray(doc.controller)) {
      doc.controller = doc.controller.map((c) => (c === lastEntryDid ? nextDid : c));
    }

    // Rewrite self-referential verification methods in verificationMethod
    if (Array.isArray(doc.verificationMethod)) {
      doc.verificationMethod = doc.verificationMethod.map((vm) => {
        const updated = { ...vm };
        if (updated.controller === lastEntryDid) {
          updated.controller = nextDid;
        }
        if (typeof updated.id === 'string' && updated.id.startsWith(`${lastEntryDid}#`)) {
          updated.id = `${nextDid}#${updated.id.slice(lastEntryDid.length + 1)}`;
        }
        return updated;
      });
    }

    // Rewrite self-referential verification methods in relationships
    for (const rel of VERIFICATION_RELATIONSHIPS) {
      const relArray = doc[rel as keyof DIDDocument];
      if (Array.isArray(relArray)) {
        (doc as Record<string, unknown>)[rel] = relArray.map((item) => {
          if (typeof item === 'string') {
            if (item.startsWith(`${lastEntryDid}#`)) {
              return `${nextDid}#${item.slice(lastEntryDid.length + 1)}`;
            }
            return item;
          }
          if (typeof item === 'object' && item !== null) {
            const updated = { ...(item as Record<string, unknown>) };
            if (updated.controller === lastEntryDid) {
              updated.controller = nextDid;
            }
            if (typeof updated.id === 'string' && updated.id.startsWith(`${lastEntryDid}#`)) {
              updated.id = `${nextDid}#${updated.id.slice(lastEntryDid.length + 1)}`;
            }
            return updated;
          }
          return item;
        });
      }
    }

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
  options: DeactivateDIDOptions & { updateKeys?: string[] };
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
