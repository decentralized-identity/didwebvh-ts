import type {
  DIDResolutionOptions,
  DIDResolutionResult,
  DIDResolver,
  ParsedDID,
  Resolvable,
  ResolverRegistry,
} from 'did-resolver';
import type { FetchLike, GetResolverConfig, ResolutionOptions } from './interfaces.js';
import { resolveDID } from './method.js';
import { didWebvhParser } from './parser.js';
import { toErrorResult, validateSingleVersionSelector, WEBVH_ERROR_TYPES } from './resolver-result.js';
import { defaultVerifier } from './verifier.js';

interface WebvhDidResolutionOptions extends DIDResolutionOptions {
  fetch?: unknown;
}

const isFetchLike = (value: unknown): value is FetchLike => typeof value === 'function';

/**
 * Returns a `did-resolver` registry entry for `did:webvh`, registrable in a
 * `Resolver` alongside other DID methods. Works zero-config via the built-in
 * Ed25519 verifier; pass `{ verifier }` or `{ fetch }` to override defaults.
 */
export function getResolver(config: GetResolverConfig = {}): ResolverRegistry {
  const verifier = config.verifier ?? defaultVerifier;

  const resolve: DIDResolver = async (
    _did: string,
    parsed: ParsedDID,
    _resolver: Resolvable,
    _options
  ): Promise<DIDResolutionResult> => {
    const options = (_options ?? {}) as WebvhDidResolutionOptions;
    if (config.fetch !== undefined && !isFetchLike(config.fetch)) {
      return toErrorResult('invalidOptions', 'Invalid fetch option: expected function.');
    }
    if (options.fetch !== undefined && !isFetchLike(options.fetch)) {
      return toErrorResult('invalidOptions', 'Invalid fetch option: expected function.');
    }

    // Decode per RFC 3986 (decodeURIComponent), NOT via URLSearchParams: a DID
    // URL query is a URI component where `+` is a literal plus, whereas
    // URLSearchParams applies application/x-www-form-urlencoded rules and would
    // turn `+` into a space — corrupting e.g. a `versionTime` with a `+HH:MM`
    // timezone offset. Unknown query parameters are ignored per DID Core §3.2.1
    // extensibility (registered params like `service`/`relativeRef` are a
    // dereferencer's concern, and future params must not break resolution).
    const params: Record<string, string | undefined> = {};
    for (const pair of (parsed.query ?? '').split('&')) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      const rawKey = eq === -1 ? pair : pair.slice(0, eq);
      const rawValue = eq === -1 ? '' : pair.slice(eq + 1);
      try {
        params[decodeURIComponent(rawKey)] = decodeURIComponent(rawValue);
      } catch {
        // Invalid UTF-8 in an otherwise syntactically valid percent-encoded query
        // cannot be decoded into method-level selectors.
        return toErrorResult('invalidDidUrl', 'Malformed percent-encoding in DID URL query.');
      }
    }
    const selector: ResolutionOptions = { verifier };
    const fetchOverride = options.fetch ?? config.fetch;
    if (fetchOverride) {
      selector.fetch = fetchOverride;
    }
    if (params.versionId !== undefined) {
      selector.versionId = params.versionId;
    }
    if (params.versionNumber !== undefined) {
      const versionNumber = Number(params.versionNumber);
      if (!Number.isInteger(versionNumber) || versionNumber < 1) {
        return toErrorResult('invalidOptions', `Invalid versionNumber: ${params.versionNumber}`);
      }
      selector.versionNumber = versionNumber;
    }
    if (params.versionTime !== undefined) {
      const versionTime = new Date(params.versionTime);
      if (Number.isNaN(versionTime.getTime())) {
        return toErrorResult('invalidOptions', `Invalid versionTime: ${params.versionTime}`, {
          problemType: WEBVH_ERROR_TYPES.versionTimeFormatInvalid,
        });
      }
      selector.versionTime = versionTime;
    }

    const selectorError = validateSingleVersionSelector(selector);
    if (selectorError) {
      return toErrorResult(selectorError.code, selectorError.detail, { problemType: selectorError.problemType });
    }

    // parsed.did is the bare DID without query/fragment.
    return resolveDID(parsed.did, selector);
  };

  resolve.parser = didWebvhParser;

  return { webvh: resolve };
}
