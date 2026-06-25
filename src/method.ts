import type { DIDResolutionResult } from 'did-resolver';
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
import * as v0_5 from './method_versions/method.v0.5';
import * as v1 from './method_versions/method.v1.0';
import { assertSingleVersionSelector, mapErrorToCode, toErrorResult, toResolutionResult } from './resolver-result';
import { fetchLogFromIdentifier, getActiveDIDs, maybeWriteTestLog } from './utils';
import { defaultVerifier } from './verifier';

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
  maybeWriteTestLog(result.did, result.log);
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
): Promise<DIDResolutionResult> => {
  const activeDIDs = await getActiveDIDs();
  const controlled = activeDIDs.includes(did);
  const verifier = options.verifier ?? defaultVerifier;
  // Extract the expected SCID from the DID string so the resolver can
  // verify the log's SCID matches what the DID claims.
  const didParts = did.split(':');
  const scid = didParts.length > 2 && didParts[0] === 'did' && didParts[1] === 'webvh' ? didParts[2] : undefined;
  try {
    assertSingleVersionSelector(options);
    const log = await fetchLogFromIdentifier(did, controlled);
    const version = getWebvhVersionFromLog(log);
    const optsWithScid = { ...options, verifier, scid, requestedDid: did };
    const result =
      version === '0.5'
        ? await v0_5.resolveDIDFromLog(log, optsWithScid)
        : await v1.resolveDIDFromLog(log, optsWithScid);
    maybeWriteTestLog(result.did, log);

    return toResolutionResult(result, { controlled });
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message, { controlled });
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
): Promise<DIDResolutionResult> => {
  const verifier = options.verifier ?? defaultVerifier;
  try {
    assertSingleVersionSelector(options);
    const version = getWebvhVersionFromLog(log);
    const result =
      version === '0.5'
        ? await v0_5.resolveDIDFromLog(log, { ...options, verifier })
        : await v1.resolveDIDFromLog(log, { ...options, verifier });
    maybeWriteTestLog(result.did, log);
    return toResolutionResult(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message);
  }
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
    updated?: string;
  }
): Promise<UpdateDIDResult> => {
  const version = options.log ? getWebvhVersionFromLog(options.log) : getWebvhVersionFromOptions(options);
  const result = version === '0.5' ? await v0_5.updateDID(options) : await v1.updateDID(options);
  maybeWriteTestLog(result.did, result.log);
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
  maybeWriteTestLog(result.did, result.log);
  return result;
};
