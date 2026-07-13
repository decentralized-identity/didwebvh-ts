import type { DIDResolutionResult, DIDResolver, ParsedDID, Resolvable, ResolverRegistry } from 'did-resolver';
import type { Verifier } from './interfaces';
import { resolveDID } from './method';
import { toErrorResult, validateSingleVersionSelector, WEBVH_ERROR_TYPES } from './resolver-result';
import { defaultVerifier } from './verifier';

export interface GetResolverConfig {
  verifier?: Verifier;
}

/**
 * Returns a `did-resolver` registry entry for `did:webvh`, registrable in a
 * `Resolver` alongside other DID methods. Works zero-config via the built-in
 * Ed25519 verifier; pass `{ verifier }` to override.
 */
export function getResolver(config: GetResolverConfig = {}): ResolverRegistry {
  const verifier = config.verifier ?? defaultVerifier;

  const resolve: DIDResolver = async (
    _did: string,
    parsed: ParsedDID,
    _resolver: Resolvable,
    _options
  ): Promise<DIDResolutionResult> => {
    // did:webvh selectors arrive as DID-URL query parameters (`?versionId=`),
    // which did-resolver exposes as the raw, undecoded `parsed.query` string.
    // Matrix-style DID parameters (`;key=value`) are not part of the DID spec;
    // reject version selectors supplied that way instead of silently resolving
    // latest, which would hand back the wrong version.
    const matrixParams = parsed.params ?? {};
    if (
      matrixParams.versionId !== undefined ||
      matrixParams.versionNumber !== undefined ||
      matrixParams.versionTime !== undefined
    ) {
      return toErrorResult(
        'invalidOptions',
        'Version selectors must be supplied as DID URL query parameters (?versionId, ?versionNumber, ?versionTime).'
      );
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
        // Malformed percent-encoding violates `did-url` syntax itself.
        return toErrorResult('invalidDidUrl', 'Malformed percent-encoding in DID URL query.');
      }
    }
    const selector: { versionId?: string; versionTime?: Date; versionNumber?: number; verifier: Verifier } = {
      verifier,
    };
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

  return { webvh: resolve };
}
