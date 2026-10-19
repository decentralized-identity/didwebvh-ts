import { type DIDParser, type ParsedDID, parse as parseDidUrl } from 'did-resolver';
import { METHOD, SCID_PLACEHOLDER } from './constants.js';

const SCID_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{46}$/;
const DOMAIN_LABEL_PATTERN = /^(?:[A-Za-z0-9-]|%[0-9A-Fa-f]{2})+$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ENCODED_PORT_SEPARATOR = /%3A/i;
// Valid base58btc stand-in for {SCID}; preserves label and FQDN lengths during validation.
const SCID_PLACEHOLDER_SUBSTITUTE = '1'.repeat(46);

export interface ParsedDidWebvhIdentifier {
  scid: string;
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
  paths?: string[];
  locationKey: string;
  did: string;
}

interface ParsedAddress {
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
  paths?: string[];
}

function isIpAddress(host: string): boolean {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  return /^\[[0-9a-f:]+\]$/i.test(host) || /^[0-9a-f:]+$/i.test(host);
}

function hasFragmentOrQuery(value: string): boolean {
  return value.includes('#') || value.includes('?');
}

function decodeHostComponent(host: string): string {
  try {
    return decodeURIComponent(host);
  } catch {
    throw new Error(`Invalid percent-encoding in host: ${host}`);
  }
}

function parsePort(rawPort: string): number | undefined {
  if (!/^\d{1,5}$/.test(rawPort)) return undefined;
  const port = Number(rawPort);
  return port >= 1 && port <= 65535 ? port : undefined;
}

function requirePort(rawPort: string): number {
  const port = parsePort(rawPort);
  if (port === undefined) {
    throw new Error(`Invalid port number: ${rawPort}`);
  }
  return port;
}

function formatDomainComponent(host: string, port?: number): string {
  return port ? `${host}%3A${port}` : host;
}

function parseHostPort(input: string): { host: string; port?: number } {
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

export function parseCanonicalAddress(input: string): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  const isUrl = input.startsWith('https://') || input.startsWith('http://');
  if (hasFragmentOrQuery(input)) {
    throw new Error(`${isUrl ? 'URL' : 'Address'} input must not include query or fragment components`);
  }

  if (input.startsWith(`did:${METHOD}:`)) {
    const parsedDid = parseDidWebvhIdentifier(input, 'did:webvh identifier', { allowScidPlaceholder: true });
    return {
      canonicalHost: parsedDid.canonicalHost,
      canonicalPort: parsedDid.canonicalPort,
      didDomainComponent: parsedDid.didDomainComponent,
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
      canonicalHost: host,
      canonicalPort: port,
      didDomainComponent: formatDomainComponent(host, port),
      paths: pathParts.length > 0 ? pathParts : undefined,
    };
  }

  if (input.includes('%25')) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  const hostAndPort = parseHostPort(input);
  const host = decodeHostComponent(hostAndPort.host);
  const port = hostAndPort.port;

  if (isIpAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  return {
    canonicalHost: host,
    canonicalPort: port,
    didDomainComponent: formatDomainComponent(host, port),
    paths: undefined,
  };
}

export function normalizeDidAddress({
  address,
  scid,
  paths,
  fallbackPaths,
  context,
}: {
  address: string;
  scid: string;
  paths?: string[];
  fallbackPaths?: string[];
  context: string;
}): ParsedDidWebvhIdentifier {
  const parsed = parseCanonicalAddress(address);
  const resolvedPaths = [...(parsed.paths ?? [])];

  if (paths !== undefined) {
    resolvedPaths.push(...paths);
  } else if (resolvedPaths.length === 0 && fallbackPaths !== undefined) {
    resolvedPaths.push(...fallbackPaths);
  }

  let locationKey = parsed.didDomainComponent;
  if (resolvedPaths.length > 0) {
    locationKey += `:${resolvedPaths.join(':')}`;
  }
  const did = `did:${METHOD}:${scid}:${locationKey}`;

  return parseDidWebvhIdentifier(did, context, { allowScidPlaceholder: true });
}

function parseDomainComponent(component: string): {
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
} | null {
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
      didDomainComponent: formatDomainComponent(decodedDomain, canonicalPort),
    };
  } catch {
    return null;
  }
}

export function validateMethodSpecificPathSegments(pathSegments: string[], context: string): void {
  for (const segment of pathSegments) {
    let decodedSegment: string;
    try {
      decodedSegment = decodeURIComponent(segment);
    } catch {
      throw new Error(`${context} contains invalid percent-encoding in path segment '${segment}'`);
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

function parseMethodSpecificIdentifier(
  identifier: string,
  context: string,
  options: { allowScidPlaceholder?: boolean } = {}
): ParsedDidWebvhIdentifier {
  if (
    !identifier.startsWith(`did:${METHOD}:`) ||
    identifier.includes('/') ||
    identifier.includes('?') ||
    identifier.includes('#')
  ) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const [scid, domain, ...paths] = identifier.slice(`did:${METHOD}:`.length).split(':');
  if (scid === undefined || scid === '') {
    throw new Error(`${context} must include SCID segment`);
  }
  if (domain === undefined) {
    throw new Error(`${context} must include SCID and domain segments`);
  }

  const validScid = SCID_PATTERN.test(scid ?? '') || (options.allowScidPlaceholder && scid === SCID_PLACEHOLDER);
  if (!validScid) {
    throw new Error(`${context} must include a valid SCID`);
  }

  const parsedDomain = parseDomainComponent(domain ?? '');
  if (!parsedDomain) {
    throw new Error(`${context} must include a valid fully qualified domain and optional encoded port`);
  }

  validateMethodSpecificPathSegments(paths, context);

  const locationKey = paths.length
    ? `${parsedDomain.didDomainComponent}:${paths.join(':')}`
    : parsedDomain.didDomainComponent;
  const did = `did:${METHOD}:${scid}:${locationKey}`;

  return {
    scid,
    ...parsedDomain,
    paths: paths.length > 0 ? paths : undefined,
    locationKey,
    did,
  };
}

export function parseDidWebvhIdentifier(
  identifier: string,
  context: string,
  options: { allowScidPlaceholder?: boolean } = {}
): ParsedDidWebvhIdentifier {
  const coreIdentifier = options.allowScidPlaceholder
    ? identifier.replace(`did:${METHOD}:${SCID_PLACEHOLDER}:`, `did:${METHOD}:${SCID_PLACEHOLDER_SUBSTITUTE}:`)
    : identifier;
  const coreParsed = parseDidUrl(coreIdentifier);

  if (!coreParsed || coreParsed.method !== METHOD || coreParsed.did !== coreIdentifier) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  return parseMethodSpecificIdentifier(identifier, context, options);
}

export function isValidDidWebvhIdentifier(parsed: ParsedDID): boolean {
  if (parsed.method !== METHOD) return false;
  try {
    parseMethodSpecificIdentifier(parsed.did, 'did:webvh identifier');
    return true;
  } catch {
    return false;
  }
}

export const didWebvhParser: DIDParser = (parsed) => (isValidDidWebvhIdentifier(parsed) ? parsed : null);

const toASCII = (domain: string): string => {
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return domain;
  }
};

function parseDidForUrl(id: string): ParsedDidWebvhIdentifier {
  if (hasFragmentOrQuery(id)) {
    throw new Error('did:webvh identifier must not include query or fragment components');
  }

  return parseDidWebvhIdentifier(id, 'did:webvh identifier');
}

function getBaseUrlFromParsedDid(parsedDid: ParsedDidWebvhIdentifier): string {
  const host = toASCII(parsedDid.canonicalHost.normalize('NFC'));
  const normalizedHost = parsedDid.canonicalPort ? `${host}:${parsedDid.canonicalPort}` : host;
  const path = parsedDid.paths?.join('/') ?? '';

  return `https://${normalizedHost}${path ? `/${path}` : ''}`;
}

export const getBaseUrl = (id: string) => {
  return getBaseUrlFromParsedDid(parseDidForUrl(id));
};

export const buildDidLogUrl = (id: string) => {
  const parsedDid = parseDidForUrl(id);
  const baseUrl = getBaseUrlFromParsedDid(parsedDid);

  if (parsedDid.paths?.length) {
    return `${baseUrl}/did.jsonl`;
  }

  return `${baseUrl}/.well-known/did.jsonl`;
};
