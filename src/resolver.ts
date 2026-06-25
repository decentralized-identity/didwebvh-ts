import type { DIDResolutionResult, DIDResolver, ParsedDID, Resolvable, ResolverRegistry } from 'did-resolver';
import type { Verifier } from './interfaces';
import { resolveDID } from './method';
import { assertSingleVersionSelector, InvalidDidUrlError, toErrorResult } from './resolver-result';
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
    // Matrix-style DID parameters (`;key=value`) land in `parsed.params`; accept
    // those too, with query parameters taking precedence.
    //
    // Decode per RFC 3986 (decodeURIComponent), NOT via URLSearchParams: a DID
    // URL query is a URI component where `+` is a literal plus, whereas
    // URLSearchParams applies application/x-www-form-urlencoded rules and would
    // turn `+` into a space — corrupting e.g. a `versionTime` with a `+HH:MM`
    // timezone offset.
    const params: Record<string, string | undefined> = { ...(parsed.params ?? {}) };
    for (const pair of (parsed.query ?? '').split('&')) {
      if (!pair) continue;
      const eq = pair.indexOf('=');
      const rawKey = eq === -1 ? pair : pair.slice(0, eq);
      const rawValue = eq === -1 ? '' : pair.slice(eq + 1);
      try {
        params[decodeURIComponent(rawKey)] = decodeURIComponent(rawValue);
      } catch {
        // Leave malformed percent-encoding untouched rather than throwing.
        params[rawKey] = rawValue;
      }
    }
    const selector: { versionId?: string; versionTime?: Date; versionNumber?: number; verifier: Verifier } = {
      verifier,
    };
    if (params.versionId !== undefined) {
      selector.versionId = params.versionId;
    }
    if (params.versionNumber !== undefined) {
      selector.versionNumber = Number(params.versionNumber);
    }
    if (params.versionTime !== undefined) {
      selector.versionTime = new Date(params.versionTime);
    }

    try {
      assertSingleVersionSelector(selector);
    } catch (e) {
      if (e instanceof InvalidDidUrlError) {
        return toErrorResult('invalidDidUrl', e.message);
      }
      throw e;
    }

    // parsed.did is the bare DID without query/fragment.
    return resolveDID(parsed.did, selector);
  };

  return { webvh: resolve };
}
