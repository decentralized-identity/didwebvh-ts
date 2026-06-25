import type { DIDDocumentMetadata, DIDResolutionMetadata, DIDResolutionResult } from 'did-resolver';
import { DidResolutionError } from './interfaces';
import type { DIDDoc, DIDResolutionMeta, ProblemDetails } from './interfaces';

export type WebvhErrorCode = 'invalidDid' | 'notFound' | 'invalidDidUrl' | 'representationNotSupported';

export interface WebvhResolutionMetadata extends DIDResolutionMetadata {
  problemDetails?: ProblemDetails;
  controlled?: boolean;
}

export interface WebvhDocumentMetadata extends DIDDocumentMetadata {
  scid?: string;
  updateKeys?: string[];
  nextKeyHashes?: string[];
  prerotation?: boolean;
  portable?: boolean;
  witness?: DIDResolutionMeta['witness'];
  watchers?: string[] | null;
  previousLogEntryHash?: string;
  latestVersionId?: string;
}

const CONTENT_TYPE = 'application/did+ld+json';

/** Raised when a DID URL carries more than one version selector. */
export class InvalidDidUrlError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidDidUrlError';
  }
}

export function assertSingleVersionSelector(options: {
  versionId?: string;
  versionTime?: Date;
  versionNumber?: number;
}): void {
  const count =
    (options.versionId !== undefined ? 1 : 0) +
    (options.versionTime !== undefined ? 1 : 0) +
    (options.versionNumber !== undefined ? 1 : 0);
  if (count > 1) {
    throw new InvalidDidUrlError(
      'At most one of versionId, versionTime, versionNumber may be supplied; they are mutually exclusive.'
    );
  }
}

export function mapErrorToCode(error: unknown): WebvhErrorCode {
  if (error instanceof InvalidDidUrlError) {
    return 'invalidDidUrl';
  }
  const message = error instanceof Error ? error.message : String(error);
  if (/not found/i.test(message) || /404/.test(message)) {
    return 'notFound';
  }
  return 'invalidDid';
}

export function toErrorResult(
  code: WebvhErrorCode,
  detail: string,
  extras: { controlled?: boolean } = {}
): DIDResolutionResult {
  const didResolutionMetadata: WebvhResolutionMetadata = { error: code, message: detail };
  if (extras.controlled !== undefined) {
    didResolutionMetadata.controlled = extras.controlled;
  }
  return { didResolutionMetadata, didDocument: null, didDocumentMetadata: {} };
}

export function toResolutionResult(
  core: { did: string; doc: DIDDoc | null; meta: DIDResolutionMeta },
  extras: { controlled?: boolean } = {}
): DIDResolutionResult {
  const { meta } = core;
  // Split meta into the standard documentMetadata + the resolutionMetadata extras.
  const { error, problemDetails, ...documentMeta } = meta;
  const didDocumentMetadata: WebvhDocumentMetadata = { ...documentMeta };

  if (error) {
    const code: WebvhErrorCode =
      error === DidResolutionError.NotFound
        ? 'notFound'
        : error === DidResolutionError.InvalidDidUrl
          ? 'invalidDidUrl'
          : 'invalidDid';
    const didResolutionMetadata: WebvhResolutionMetadata = { error: code };
    if (problemDetails) {
      didResolutionMetadata.problemDetails = problemDetails;
      didResolutionMetadata.message = problemDetails.detail;
    }
    if (extras.controlled !== undefined) {
      didResolutionMetadata.controlled = extras.controlled;
    }
    return { didResolutionMetadata, didDocument: null, didDocumentMetadata };
  }

  const didResolutionMetadata: WebvhResolutionMetadata = { contentType: CONTENT_TYPE };
  if (extras.controlled !== undefined) {
    didResolutionMetadata.controlled = extras.controlled;
  }
  return {
    didResolutionMetadata,
    didDocument: (core.doc as unknown as DIDResolutionResult['didDocument']) ?? null,
    didDocumentMetadata,
  };
}
