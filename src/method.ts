import type {
  CreateDIDInterface,
  CreateDIDResult,
  DeactivateDIDInterface,
  DIDLog,
  ResolutionOptions,
  ServiceEndpoint,
  UpdateDIDInterface,
  UpdateDIDResult,
  WitnessProofFileEntry,
} from './interfaces';
import { DidResolutionError } from './interfaces';
import * as v0_5 from './method_versions/method.v0.5';
import * as v1 from './method_versions/method.v1.0';
import { fetchLogFromIdentifier, getActiveDIDs } from './utils';

const LATEST_VERSION = '1.0';

function getWebvhVersionFromMethod(method?: string): string {
  if (!method) return LATEST_VERSION;
  const match = method.match(/^did:webvh:(\d+\.\d+)$/);
  return match ? match[1] : LATEST_VERSION;
}

function getWebvhVersionFromLog(log: DIDLog): string {
  if (log && log.length > 0 && log[0].parameters?.method) {
    return getWebvhVersionFromMethod(log[0].parameters.method);
  }
  return LATEST_VERSION;
}

function getWebvhVersionFromOptions(options?: unknown): string {
  if (typeof options === 'object' && options && 'method' in options) {
    const method = (options as { method?: unknown }).method;
    if (typeof method === 'string') {
      return getWebvhVersionFromMethod(method);
    }
  }
  return LATEST_VERSION;
}

/**
 * Creates a new did:webvh DID and initial DID log.
 *
 * @param options DID creation options.
 * @returns The created DID, resolved document, and DID log.
 */
export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  const version = getWebvhVersionFromOptions(options);
  const result = version === '0.5' ? await v0_5.createDID(options) : await v1.createDID(options);
  return result;
};

/**
 * Resolves a DID by fetching and validating its DID log.
 *
 * @param did The DID to resolve.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata and controlled status.
 */
export const resolveDID = async (
  did: string,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
) => {
  const activeDIDs = await getActiveDIDs();
  const controlled = activeDIDs.includes(did);
  // Extract the expected SCID from the DID string so the resolver can
  // verify the log's SCID matches what the DID claims.
  const didParts = did.split(':');
  const scid = didParts.length > 2 && didParts[0] === 'did' && didParts[1] === 'webvh' ? didParts[2] : undefined;
  try {
    const log = await fetchLogFromIdentifier(did, controlled);
    const version = getWebvhVersionFromLog(log);
    const optsWithScid = { ...options, scid, requestedDid: did };
    const result =
      version === '0.5'
        ? await v0_5.resolveDIDFromLog(log, optsWithScid)
        : await v1.resolveDIDFromLog(log, optsWithScid);

    return { ...result, controlled };
  } catch (e) {
    let errorType: DidResolutionError = DidResolutionError.InvalidDid;
    const message = e instanceof Error ? e.message : String(e);
    if (/not found/i.test(message) || /404/.test(message)) {
      errorType = DidResolutionError.NotFound;
    }
    return {
      did,
      doc: null,
      meta: {
        error: errorType,
        problemDetails: {
          type:
            errorType === DidResolutionError.NotFound
              ? 'https://w3id.org/security#NOT_FOUND'
              : 'https://w3id.org/security#INVALID_CONTROLLED_IDENTIFIER_DOCUMENT_ID',
          title:
            errorType === DidResolutionError.NotFound
              ? 'The DID Log or resource was not found.'
              : 'The resolved DID is invalid.',
          detail: message,
        },
      },
      controlled,
    };
  }
};

/**
 * Resolves a DID from an in-memory DID log.
 *
 * @param log In-memory DID log entries.
 * @param options Optional resolver settings.
 * @returns The resolved DID result with resolution metadata.
 */
export const resolveDIDFromLog = async (
  log: DIDLog,
  options: ResolutionOptions & { witnessProofs?: WitnessProofFileEntry[] } = {}
) => {
  const version = getWebvhVersionFromLog(log);
  if (version === '0.5') {
    const result = await v0_5.resolveDIDFromLog(log, options);
    return result;
  }
  const result = await v1.resolveDIDFromLog(log, options);
  return result;
};

/**
 * Updates an existing DID log with a new entry.
 *
 * @param options DID update options.
 * @returns The updated DID, resolved document, and DID log.
 */
export const updateDID = async (
  options: UpdateDIDInterface & {
    services?: ServiceEndpoint[];
    domain?: string;
    address?: string;
    paths?: string[];
  }
): Promise<UpdateDIDResult> => {
  const version = options.log ? getWebvhVersionFromLog(options.log) : getWebvhVersionFromOptions(options);
  const result = version === '0.5' ? await v0_5.updateDID(options) : await v1.updateDID(options);
  return result;
};

/**
 * Deactivates an existing DID by appending a deactivation entry.
 *
 * @param options DID deactivation options.
 * @returns The deactivated DID result and updated DID log.
 */
export const deactivateDID = async (options: DeactivateDIDInterface & { updateKeys?: string[] }) => {
  const version = options.log ? getWebvhVersionFromLog(options.log) : getWebvhVersionFromOptions(options);
  const result = version === '0.5' ? await v0_5.deactivateDID(options) : await v1.deactivateDID(options);
  return result;
};
