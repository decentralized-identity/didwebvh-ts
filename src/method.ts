import { fetchLogFromIdentifier, getActiveDIDs, maybeWriteTestLog } from "./utils";
import type { CreateDIDInterface, DIDLog, UpdateDIDInterface, DeactivateDIDInterface, ResolutionOptions, WitnessProofFileEntry } from './interfaces';
import * as v1 from './method_versions/method.v1.0';
import * as v0_5 from './method_versions/method.v0.5';

const LATEST_VERSION = '1.0';

function getWebvhVersionFromMethod(method?: string): string {
  if (!method) return LATEST_VERSION;
  const match = method.match(/^did:webvh:(\d+\.\d+)$/);
  return match ? match[1] : LATEST_VERSION;
}

function getWebvhVersionFromLog(log: DIDLog): string {
  if (log && log.length > 0 && log[0].parameters && log[0].parameters.method) {
    return getWebvhVersionFromMethod(log[0].parameters.method);
  }
  return LATEST_VERSION;
}

function getWebvhVersionFromOptions(options: any): string {
  if (options && options.method) {
    return getWebvhVersionFromMethod(options.method);
  }
  return LATEST_VERSION;
}

export const createDID = async (options: CreateDIDInterface) => {
  const version = getWebvhVersionFromOptions(options);
  const result = version === '0.5'
    ? await v0_5.createDID(options)
    : await v1.createDID(options);
  maybeWriteTestLog(result.did, result.log);
  return result;
};

export const resolveDID = async (did: string, options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}) => {
  const activeDIDs = await getActiveDIDs();
  const controlled = activeDIDs.includes(did);
  // Extract the expected SCID from the DID string so the resolver can
  // verify the log's SCID matches what the DID claims.
  const didParts = did.split(':');
  const scid = (didParts.length > 2 && didParts[0] === 'did' && didParts[1] === 'webvh')
    ? didParts[2] : undefined;
  try {
    const log = await fetchLogFromIdentifier(did, controlled);
    const version = getWebvhVersionFromLog(log);
    const optsWithScid = { ...options, scid };
    const result = version === '0.5'
      ? await v0_5.resolveDIDFromLog(log, optsWithScid)
      : await v1.resolveDIDFromLog(log, optsWithScid);
    maybeWriteTestLog(result.did, log);

    return { ...result, controlled };
  } catch (e: any) {
    let errorType = 'INVALID_DID';
    const message = e instanceof Error ? e.message : String(e);
    if (/not found/i.test(message) || /404/.test(message)) {
      errorType = 'notFound';
    }
    return {
      did,
      doc: null,
      meta: {
        error: errorType,
        problemDetails: {
          type: errorType === 'notFound'
            ? 'https://w3id.org/security#NOT_FOUND'
            : 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
          title: errorType === 'notFound'
            ? 'The DID Log or resource was not found.'
            : 'The resolved DID is invalid.',
          detail: message
        }
      },
      controlled
    };
  }
};

export const resolveDIDFromLog = async (log: DIDLog, options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}) => {
  const version = getWebvhVersionFromLog(log);
  if (version === '0.5') {
    const result = await v0_5.resolveDIDFromLog(log, options);
    maybeWriteTestLog(result.did, log);
    return result;
  }
  const result = await v1.resolveDIDFromLog(log, options);
  maybeWriteTestLog(result.did, log);
  return result;
};

export const updateDID = async (options: UpdateDIDInterface & { services?: any[], domain?: string, updated?: string }) => {
  const version = options.log ? getWebvhVersionFromLog(options.log) : getWebvhVersionFromOptions(options);
  const result = version === '0.5'
    ? await v0_5.updateDID(options)
    : await v1.updateDID(options);
  maybeWriteTestLog(result.did, result.log);
  return result;
};

export const deactivateDID = async (options: DeactivateDIDInterface & { updateKeys?: string[] }) => {
  const version = options.log ? getWebvhVersionFromLog(options.log) : getWebvhVersionFromOptions(options);
  const result = version === '0.5'
    ? await v0_5.deactivateDID(options)
    : await v1.deactivateDID(options);
  maybeWriteTestLog(result.did, result.log);
  return result;
};
