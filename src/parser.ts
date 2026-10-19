import { type DIDParser, type ParsedDID, parse as parseDidUrl } from 'did-resolver';
import { METHOD, SCID_PLACEHOLDER } from './constants.js';

const SCID_PATTERN = /^[1-9A-HJ-NP-Za-km-z]{46}$/;
const DOMAIN_LABEL_PATTERN = /^(?:[A-Za-z0-9-]|%[0-9A-Fa-f]{2})+$/;
const DNS_LABEL_PATTERN = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const ENCODED_PORT_SEPARATOR = /%3A/gi;

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

function parsePortNumber(rawPort: string): number {
  const portNum = Number(rawPort);
  if (!/^\d+$/.test(rawPort) || portNum <= 0 || portNum > 65535) {
    throw new Error(`Invalid port number: ${rawPort}`);
  }
  return portNum;
}

function parseRawHostPort(input: string): { host: string; port?: number } {
  if (!input.includes(':')) {
    return { host: input };
  }

  const parts = input.split(':');
  if (parts.length !== 2) {
    throw new Error('Invalid host:port format');
  }

  return {
    host: parts[0],
    port: parsePortNumber(parts[1]),
  };
}

function parseEncodedPortComponent(value: string): { host: string; port?: number } {
  const encodedSeparator = /%3a/i;
  if (!encodedSeparator.test(value)) {
    return { host: value };
  }

  const parts = value.split(encodedSeparator);
  if (parts.length !== 2) {
    throw new Error('Invalid pre-encoded port separator');
  }

  const [host, rawPort] = parts;
  return { host, port: parsePortNumber(rawPort) };
}

export function parseCanonicalAddress(input: string): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  if (input.startsWith(`did:${METHOD}:`)) {
    if (hasFragmentOrQuery(input)) {
      throw new Error('Address input must not include query or fragment components');
    }

    const parsedDid = parseDidWebvhIdentifier(input, 'did:webvh identifier', { allowScidPlaceholder: true });
    return {
      canonicalHost: parsedDid.canonicalHost,
      canonicalPort: parsedDid.canonicalPort,
      didDomainComponent: parsedDid.didDomainComponent,
      paths: parsedDid.paths,
    };
  }

  if (input.startsWith('https://') || input.startsWith('http://')) {
    try {
      const url = new URL(input);
      if (url.protocol === 'http:') {
        throw new Error('HTTP is not allowed; use HTTPS');
      }
      if (url.hash || url.search) {
        throw new Error('URL input must not include query or fragment components');
      }
      const host = url.hostname;
      const port = url.port ? parseInt(url.port, 10) : undefined;

      if (isIpAddress(host)) {
        throw new Error('IP addresses are not allowed as hosts');
      }

      const pathParts = url.pathname && url.pathname !== '/' ? url.pathname.split('/').filter((p) => p.length > 0) : [];
      validateMethodSpecificPathSegments(pathParts, 'URL pathname');

      return {
        canonicalHost: host,
        canonicalPort: port,
        didDomainComponent: port ? `${host}%3A${port}` : host,
        paths: pathParts.length > 0 ? pathParts : undefined,
      };
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (message.includes('not allowed')) throw e;
      throw new Error(`Invalid URL: ${message}`);
    }
  }

  if (hasFragmentOrQuery(input)) {
    throw new Error('Address input must not include query or fragment components');
  }

  if (input.includes('%25')) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  const hostAndPort = /%3a/i.test(input) ? parseEncodedPortComponent(input) : parseRawHostPort(input);
  const host = decodeHostComponent(hostAndPort.host);
  const port = hostAndPort.port;

  if (isIpAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  return {
    canonicalHost: host,
    canonicalPort: port,
    didDomainComponent: port ? `${host}%3A${port}` : host,
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
  const addressPaths = parsed.paths || [];
  const resolvedPaths =
    fallbackPaths !== undefined
      ? paths !== undefined
        ? [...addressPaths, ...paths]
        : addressPaths.length
          ? addressPaths
          : fallbackPaths
      : [...addressPaths, ...(paths || [])];

  const locationKey = resolvedPaths.length
    ? `${parsed.didDomainComponent}:${resolvedPaths.join(':')}`
    : parsed.didDomainComponent;
  const did = `did:${METHOD}:${scid}:${locationKey}`;

  return parseDidWebvhIdentifier(did, context, { allowScidPlaceholder: true });
}

function parseDomainComponent(component: string): {
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
} | null {
  const separators = component.match(ENCODED_PORT_SEPARATOR) ?? [];
  if (separators.length > 1) return null;

  let encodedDomain = component;
  let canonicalPort: number | undefined;
  if (separators.length === 1) {
    const separatorIndex = component.search(ENCODED_PORT_SEPARATOR);
    encodedDomain = component.slice(0, separatorIndex);
    const port = component.slice(separatorIndex + 3);
    if (!/^\d{1,5}$/.test(port)) return null;

    const portNumber = Number(port);
    if (portNumber < 1 || portNumber > 65535) return null;
    canonicalPort = portNumber;
  }

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
      didDomainComponent: canonicalPort ? `${decodedDomain}%3A${canonicalPort}` : decodedDomain,
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
    ? identifier.replace(`did:${METHOD}:${SCID_PLACEHOLDER}:`, `did:${METHOD}:${'1'.repeat(46)}:`)
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
  const parsedDomain = parseEncodedPortComponent(parsedDid.didDomainComponent);
  const host = toASCII(decodeHostComponent(parsedDomain.host).normalize('NFC'));
  const normalizedHost = parsedDomain.port ? `${host}:${parsedDomain.port}` : host;
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
