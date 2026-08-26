import type { DIDResolutionResult } from 'did-resolver';
import type {
  CreateDIDInterface,
  CreateDIDResult,
  DeactivateDIDInterface,
  DIDLog,
  ResolutionOptions,
  UpdateDIDInterface,
  UpdateDIDResult,
  WitnessProofFileEntry,
} from './interfaces';
import * as v1 from './method_versions/method.v1.0';
import { mapErrorToCode, toErrorResult, toResolutionResult, validateSingleVersionSelector } from './resolver-result';
import { fetchLogFromIdentifier, getActiveDIDs } from './utils';
import { defaultVerifier } from './verifier';

/**
 * Creates a new did:webvh DID and initial DID log.
 * All DIDs are created with v1.0 format.
 *
 * @param options DID creation options.
 * @returns The created DID, resolved document, and DID log.
 */
export const createDID = async (options: CreateDIDInterface): Promise<CreateDIDResult> => {
  const result = await v1.createDID(options);
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
  const selectorError = validateSingleVersionSelector(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, {
      controlled,
      problemType: selectorError.problemType,
    });
  }
  try {
    const log = await fetchLogFromIdentifier(did, controlled);
    const optsWithScid = { ...options, verifier, scid, requestedDid: did };
    const result = await v1.resolveDIDFromLog(log, optsWithScid);

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
  const selectorError = validateSingleVersionSelector(options);
  if (selectorError) {
    return toErrorResult(selectorError.code, selectorError.detail, { problemType: selectorError.problemType });
  }
  try {
    const result = await v1.resolveDIDFromLog(log, { ...options, verifier });
    return toResolutionResult(result);
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    return toErrorResult(mapErrorToCode(e), message);
  }
};

/**
 * Updates an existing DID log with a new entry.
 * All updates produce v1.0 entries, even when appended to v0.5 base logs.
 *
 * @param options DID update options.
 * @returns The updated DID, resolved document, and DID log.
 */
export const updateDID = async (options: UpdateDIDInterface): Promise<UpdateDIDResult> => {
  const result = await v1.updateDID(options);
  return result;
};

/**
 * Deactivates an existing DID by appending a deactivation entry.
 * All deactivations produce v1.0 entries, even when appended to v0.5 base logs.
 *
 * @param options DID deactivation options.
 * @returns The deactivated DID result and updated DID log.
 */
export const deactivateDID = async (options: DeactivateDIDInterface & { updateKeys?: string[] }) => {
  const result = await v1.deactivateDID(options);
  return result;
};
