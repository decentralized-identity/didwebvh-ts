import { type ParsedDID, parse as parseDidUrl } from 'did-resolver';
import { METHOD, SCID_PLACEHOLDER } from './constants.js';

const SCID_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{46}$/;
const DOMAIN_LABEL_PATTERN = /^(?:[A-Za-z0-9-]|%[0-9A-Fa-f]{2})+$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ENCODED_PORT_SEPARATOR = /%3A/i;
// Valid base58btc stand-in for {SCID}; preserves label and FQDN lengths during validation.
const SCID_PLACEHOLDER_SUBSTITUTE = '1'.repeat(46);
const TEMPLATE_PREFIX = `did:${METHOD}:${SCID_PLACEHOLDER}:`;

interface ParsedDidWebvhIdentifier {
  scid: string;
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
  paths?: string[];
  locationKey: string;
  did: string;
}

interface ParsedDomainComponent {
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
}

interface HostPort {
  host: string;
  port?: number;
}

interface ParsedAddress {
  didDomainComponent: string;
  paths?: string[];
}

interface NormalizeDidAddressOptions {
  address: string;
  scid: string;
  paths?: string[];
  fallbackPaths?: string[];
  context: string;
}

// ---------------------------------------------------------------------------
// Shared host and port helpers
// ---------------------------------------------------------------------------

function isIpAddress(host: string): boolean {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  return /^\[[0-9a-f:]+\]$/i.test(host) || /^[0-9a-f:]+$/i.test(host);
}

function parsePort(rawPort: string): number | undefined {
  if (!/^\d{1,5}$/.test(rawPort)) return undefined;
  const port = Number(rawPort);
  return port >= 1 && port <= 65535 ? port : undefined;
}

// ---------------------------------------------------------------------------
// did:webvh identifier parsing: a method-specific narrowing of DID Core
// ---------------------------------------------------------------------------

function parseDomainComponent(component: string): ParsedDomainComponent | null {
  const [encodedDomain, rawPort, ...extra] = component.split(ENCODED_PORT_SEPARATOR);
  if (extra.length > 0) return null;

  const canonicalPort = rawPort === undefined ? undefined : parsePort(rawPort);
  if (rawPort !== undefined && canonicalPort === undefined) return null;

  const encodedLabels = encodedDomain.split('.');
  if (encodedLabels.length < 2 || encodedLabels.some((label) => !DOMAIN_LABEL_PATTERN.test(label))) {
    return null;
  }

  let decodedDomain: string;
  try {
    decodedDomain = decodeURIComponent(encodedDomain);
  } catch {
    return null;
  }

  // A decoded percent sign would cause URL's host parser to decode the input
  // again, contrary to the method's exactly-once decoding requirement.
  if (decodedDomain.includes('%')) return null;

  try {
    const url = new URL(`https://${decodedDomain}`);
    const asciiDomain = url.hostname;
    if (
      url.username ||
      url.password ||
      url.port ||
      url.pathname !== '/' ||
      url.search ||
      url.hash ||
      isIpAddress(asciiDomain)
    ) {
      return null;
    }

    const labels = asciiDomain.split('.');
    if (
      asciiDomain.length > 253 ||
      labels.length < 2 ||
      !labels.every((label) => label.length <= 63 && DNS_LABEL_PATTERN.test(label))
    ) {
      return null;
    }

    return {
      canonicalHost: decodedDomain,
      canonicalPort,
      // Kept exactly as encoded in the identifier; it is decoded only when building the HTTPS URL.
      didDomainComponent: component,
    };
  } catch {
    return null;
  }
}

function validateMethodSpecificPathSegments(pathSegments: string[], context: string): void {
  for (const segment of pathSegments) {
    let decodedSegment: string;
    try {
      decodedSegment = decodeURIComponent(segment);
    } catch {
      throw new Error(`${context} contains invalid percent-encoding in path segment '${segment}'`);
    }

    if (decodedSegment === '') {
      throw new Error(`${context} must not contain empty path segments`);
    }

    if (decodedSegment === '.' || decodedSegment === '..') {
      throw new Error(`${context} must not contain dot-segments`);
    }

    if (decodedSegment.includes('/')) {
      throw new Error(`${context} must not contain decoded slash within a single path segment`);
    }

    if (decodedSegment.includes('\\')) {
      throw new Error(`${context} must not contain decoded backslash within a path segment`);
    }

    if (decodedSegment.includes('\u0000')) {
      throw new Error(`${context} must not contain decoded NUL character within a path segment`);
    }

    if (decodedSegment !== decodedSegment.trim()) {
      throw new Error(`${context} must not contain leading or trailing whitespace in decoded path segment`);
    }
  }
}

/**
 * Narrows a DID Core parse result (from did-resolver's `parse`) to did:webvh.
 * DID Core syntax is a precondition and is not re-checked here; only the
 * method-specific identifier (`parsed.id`) is examined. Any path, query or
 * fragment on the DID URL is ignored, as they are not part of the DID.
 */
export function narrowDidWebvh(parsed: ParsedDID, context: string): ParsedDidWebvhIdentifier {
  // ParsedDID is a plain object, so guard against a hand-built inconsistent one.
  if (parsed.method !== METHOD || parsed.did !== `did:${METHOD}:${parsed.id}`) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const [scid, domain, ...paths] = parsed.id.split(':');
  if (scid === '') {
    throw new Error(`${context} must include SCID segment`);
  }
  if (domain === undefined) {
    throw new Error(`${context} must include SCID and domain segments`);
  }

  if (!SCID_PATTERN.test(scid)) {
    throw new Error(`${context} must include a valid SCID`);
  }

  const parsedDomain = parseDomainComponent(domain);
  if (!parsedDomain) {
    throw new Error(`${context} must include a valid fully qualified domain and optional encoded port`);
  }

  validateMethodSpecificPathSegments(paths, context);

  return {
    scid,
    ...parsedDomain,
    paths: paths.length > 0 ? paths : undefined,
    locationKey: parsed.id.slice(scid.length + 1),
    did: parsed.did,
  };
}

/**
 * Parses a did:webvh DID string. This is the only place DID Core parsing is
 * delegated to did-resolver; the result is then narrowed to did:webvh. A DID URL
 * path, query or fragment is rejected because the narrowing ignores them.
 */
export function parseDidWebvhIdentifier(identifier: string, context: string): ParsedDidWebvhIdentifier {
  const parsed = parseDidUrl(identifier);
  if (!parsed) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }
  if (parsed.path !== undefined) {
    throw new Error(`${context} must not include a DID URL path`);
  }
  if (parsed.query !== undefined || parsed.fragment !== undefined) {
    throw new Error(`${context} must not include query or fragment components`);
  }
  return narrowDidWebvh(parsed, context);
}

/**
 * Parses a did:webvh creation template, `did:webvh:{SCID}:<location>`. A template
 * is not a DID: `{SCID}` is not a DID Core idchar, so it is parsed with a
 * SCID-shaped stand-in and the placeholder is restored in the result.
 */
export function parseDidWebvhTemplate(template: string, context: string): ParsedDidWebvhIdentifier {
  if (!template.startsWith(TEMPLATE_PREFIX)) {
    throw new Error(`${context} must be a did:webvh template starting with '${TEMPLATE_PREFIX}'`);
  }
  const standIn = `did:${METHOD}:${SCID_PLACEHOLDER_SUBSTITUTE}:${template.slice(TEMPLATE_PREFIX.length)}`;
  const narrowed = parseDidWebvhIdentifier(standIn, context);

  return {
    ...narrowed,
    scid: SCID_PLACEHOLDER,
    did: `${TEMPLATE_PREFIX}${narrowed.locationKey}`,
  };
}

// ---------------------------------------------------------------------------
// Address input (create/update): turns a domain, URL, DID or template into a did:webvh identifier
// ---------------------------------------------------------------------------

function formatDomainComponent(host: string, port?: number): string {
  return port ? `${host}%3A${port}` : host;
}

function requirePort(rawPort: string): number {
  const port = parsePort(rawPort);
  if (port === undefined) {
    throw new Error(`Invalid port number: ${rawPort}`);
  }
  return port;
}

function parseHostPort(input: string): HostPort {
  const encoded = ENCODED_PORT_SEPARATOR.test(input);
  const parts = input.split(encoded ? ENCODED_PORT_SEPARATOR : ':');
  if (parts.length === 1) {
    return { host: input };
  }
  if (parts.length !== 2) {
    throw new Error(encoded ? 'Invalid pre-encoded port separator' : 'Invalid host:port format');
  }
  return { host: parts[0], port: requirePort(parts[1]) };
}

/**
 * Canonicalises a bare domain (optionally with port), an HTTPS URL, a did:webvh DID
 * or a `{SCID}` template into the DID domain component and any path segments.
 */
export function parseCanonicalAddress(input: string): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  const isUrl = input.startsWith('https://') || input.startsWith('http://');
  if (input.includes('#') || input.includes('?')) {
    throw new Error(`${isUrl ? 'URL' : 'Address'} input must not include query or fragment components`);
  }

  if (input.startsWith(`did:${METHOD}:`)) {
    const parsedDid = input.startsWith(TEMPLATE_PREFIX)
      ? parseDidWebvhTemplate(input, 'did:webvh identifier')
      : parseDidWebvhIdentifier(input, 'did:webvh identifier');
    return {
      didDomainComponent: parsedDid.didDomainComponent.replace(ENCODED_PORT_SEPARATOR, '%3A'),
      paths: parsedDid.paths,
    };
  }

  if (isUrl) {
    let url: URL;
    try {
      url = new URL(input);
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      throw new Error(`Invalid URL: ${message}`);
    }

    if (url.protocol === 'http:') {
      throw new Error('HTTP is not allowed; use HTTPS');
    }
    if (url.username || url.password) {
      throw new Error('URL input must not include username or password');
    }
    const host = url.hostname;
    const port = url.port ? requirePort(url.port) : undefined;

    if (isIpAddress(host)) {
      throw new Error('IP addresses are not allowed as hosts');
    }

    const pathParts = url.pathname && url.pathname !== '/' ? url.pathname.split('/').filter((p) => p.length > 0) : [];
    validateMethodSpecificPathSegments(pathParts, 'URL pathname');

    return {
      didDomainComponent: formatDomainComponent(host, port),
      paths: pathParts.length > 0 ? pathParts.map(encodeDidPathSegment) : undefined,
    };
  }

  if (input.includes('%25')) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  const { host: rawHost, port } = parseHostPort(input);
  let host: string;
  try {
    host = decodeURIComponent(rawHost);
  } catch {
    throw new Error(`Invalid percent-encoding in host: ${rawHost}`);
  }

  if (isIpAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  return {
    didDomainComponent: formatDomainComponent(host, port),
    paths: undefined,
  };
}

/**
 * Builds a did:webvh identifier (or template, when `scid` is `{SCID}`) from an address.
 * `paths` are appended to any address paths; `fallbackPaths` apply only when neither
 * supplies one. The result is re-parsed, which is what validates it.
 */
export function normalizeDidAddress({
  address,
  scid,
  paths,
  fallbackPaths,
  context,
}: NormalizeDidAddressOptions): ParsedDidWebvhIdentifier {
  const parsed = parseCanonicalAddress(address);
  const resolvedPaths = [...(parsed.paths ?? [])];

  if (paths !== undefined) {
    validateMethodSpecificPathSegments(paths, context);
    resolvedPaths.push(...paths.map(encodeDidPathSegment));
  } else if (resolvedPaths.length === 0 && fallbackPaths !== undefined) {
    resolvedPaths.push(...fallbackPaths);
  }

  let locationKey = parsed.didDomainComponent;
  if (resolvedPaths.length > 0) {
    locationKey += `:${resolvedPaths.join(':')}`;
  }
  const did = `did:${METHOD}:${scid}:${locationKey}`;

  return scid === SCID_PLACEHOLDER ? parseDidWebvhTemplate(did, context) : parseDidWebvhIdentifier(did, context);
}

// ---------------------------------------------------------------------------
// DID-to-HTTPS URL derivation
// ---------------------------------------------------------------------------

const toASCII = (domain: string): string => {
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return domain;
  }
};

/**
 * Decodes a validated path segment once and re-encodes it with uppercase hex, as the
 * did:webvh v1.0 DID-to-HTTPS transformation requires. Only RFC 3986 unreserved
 * characters are left unencoded, so encoded sub-delimiters keep their meaning.
 */
function encodeUrlPathSegment(segment: string): string {
  return encodeURIComponent(decodeURIComponent(segment)).replace(
    /[!'()*]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function encodeDidPathSegment(segment: string): string {
  return encodeUrlPathSegment(segment).replace(/~/g, '%7E');
}

function getBaseUrlFromParsedDid(parsedDid: ParsedDidWebvhIdentifier): string {
  const host = toASCII(parsedDid.canonicalHost.normalize('NFC'));
  const normalizedHost = parsedDid.canonicalPort ? `${host}:${parsedDid.canonicalPort}` : host;
  const path = parsedDid.paths?.map(encodeUrlPathSegment).join('/') ?? '';

  return `https://${normalizedHost}${path ? `/${path}` : ''}`;
}

export const getBaseUrl = (id: string) => {
  return getBaseUrlFromParsedDid(parseDidWebvhIdentifier(id, 'did:webvh identifier'));
};

export const buildDidLogUrl = (id: string) => {
  const parsedDid = parseDidWebvhIdentifier(id, 'did:webvh identifier');
  const baseUrl = getBaseUrlFromParsedDid(parsedDid);

  if (parsedDid.paths?.length) {
    return `${baseUrl}/did.jsonl`;
  }

  return `${baseUrl}/.well-known/did.jsonl`;
};
