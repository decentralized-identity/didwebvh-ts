import { type DIDParser, type ParsedDID, parse as parseDidUrl } from 'did-resolver';
import { METHOD, SCID_PLACEHOLDER } from './constants.js';
import type { ToASCII } from './interfaces.js';

let urlSupportsIdna: boolean | undefined;

const urlToASCII: ToASCII = (host) => {
  urlSupportsIdna ??=
    new URL('https://faß.de').hostname === 'xn--fa-hia.de' &&
    new URL('https://BÜCHER.example').hostname === 'xn--bcher-kva.example';
  if (!urlSupportsIdna) {
    throw new Error('This runtime URL implementation does not support IDNA; supply a toASCII converter');
  }
  return new URL(`https://${host}`).hostname;
};

const hasNonAscii = (value: string): boolean => /[\u0080-\u{10FFFF}]/u.test(value);
const hasInvalidHostCharacter = (value: string): boolean =>
  [...value].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || code === 127 || '%/#?@:\\'.includes(char) || /\s/.test(char);
  });

interface ParsedDidWebvhIdentifier {
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

/**
 * Percent-encodes a decoded value so it consists only of DID Core `idchar`s,
 * using uppercase hex as the did:webvh v1.0 canonical form requires.
 */
function encodeIdchars(decoded: string): string {
  // encodeURIComponent leaves these unencoded, but DID Core `idchar` only permits
  // ALPHA / DIGIT / "." / "-" / "_" / pct-encoded.
  return encodeURIComponent(decoded).replace(
    /[!'()*~]/g,
    (char) => `%${char.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

/**
 * Splits a caller-supplied DID component (domain or path segment), which may be raw
 * Unicode or already percent-encoded, around occurrences of the SCID (or `{SCID}`
 * placeholder) and decodes each remaining part exactly once. SCID occurrences are
 * kept verbatim, so an encoded `%7BSCID%7D` remains literal text and a mixed-case
 * SCID is never case-folded.
 */
function decodeDidComponentParts(value: string, context: string, scid: string): string[] {
  // `\p{Surrogate}` under the `u` flag matches only unpaired surrogates
  // (String.prototype.isWellFormed is ES2024 and not available on every runtime).
  if (/\p{Surrogate}/u.test(value)) {
    throw new Error(`${context} contains ill-formed Unicode (unpaired surrogate)`);
  }
  return value.split(scid).map((part) => {
    try {
      return decodeURIComponent(part);
    } catch {
      throw new Error(`${context} contains invalid percent-encoding: '${value}'`);
    }
  });
}

/**
 * Decodes a caller-supplied host and NFC-normalises it so composition variants
 * cannot yield distinct DIDs for the same host. Case folding and IDNA mapping
 * happen later in {@link domainToAscii}.
 */
function decodeHostComponent(value: string, context: string, scid: string): string {
  return decodeDidComponentParts(value, context, scid)
    .map((part) => part.normalize('NFC'))
    .join(scid);
}

/**
 * Canonicalises a caller-supplied path segment to DID Core `idchar`s with uppercase
 * hex. Path segments are otherwise left byte-exact for the web server.
 */
function canonicalPathSegment(value: string, context: string, scid: string): string {
  return decodeDidComponentParts(value, context, scid).map(encodeIdchars).join(scid);
}

function domainToAscii(decodedDomain: string, toASCII: ToASCII = urlToASCII): string {
  if (hasInvalidHostCharacter(decodedDomain)) {
    throw new Error('Host contains invalid characters');
  }
  const host = hasNonAscii(decodedDomain) ? toASCII(decodedDomain.normalize('NFC')) : decodedDomain.toLowerCase();
  if (typeof host !== 'string' || !/^[a-z0-9.-]+$/.test(host) || host !== host.toLowerCase()) {
    throw new Error('toASCII must return a lowercase ASCII DNS hostname');
  }
  const labels = host.split('.');
  if (
    host.length > 253 ||
    labels.length < 2 ||
    !labels.every((label) => label.length <= 63 && /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) ||
    isIpAddress(host)
  ) {
    throw new Error('Host must be a valid fully qualified domain');
  }
  return host;
}

function producerHost(host: string, scid: string, toASCII: ToASCII): string {
  if (!host.includes(scid)) return domainToAscii(host, toASCII);
  const marker = 'scidplaceholdertoken';
  if (host.toLowerCase().includes(marker)) throw new Error('Host contains a reserved SCID marker');
  const labels = host.split('.');
  if (labels.some((label) => label.includes(scid) && hasNonAscii(label))) {
    throw new Error('Unicode and {SCID} cannot share a domain label');
  }
  const mapped = domainToAscii(host.replaceAll(scid, marker), toASCII);
  return mapped.replaceAll(marker, scid);
}

/** Validate a URL's host syntax without applying URL's implicit IDNA mapping. */
function isValidAsciiHost(host: string): boolean {
  try {
    domainToAscii(host);
    return true;
  } catch {
    return false;
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

/**
 * Parses a caller-supplied address (`did:webvh:` DID, HTTPS URL or bare domain)
 * into the canonical did:webvh v1.0 form. `scid` names the token that is kept
 * verbatim in the domain and paths: `{SCID}` on create, the actual SCID on update.
 */
export function parseCanonicalAddress(
  input: string,
  { scid = SCID_PLACEHOLDER, toASCII = urlToASCII }: { scid?: string; toASCII?: ToASCII } = {}
): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }
  // Checked before URL parsing, which would silently replace an unpaired
  // surrogate with U+FFFD.
  if (/\p{Surrogate}/u.test(input)) {
    throw new Error('Address input contains ill-formed Unicode (unpaired surrogate)');
  }

  if (input.startsWith(`did:${METHOD}:`)) {
    if (hasFragmentOrQuery(input)) {
      throw new Error('Address input must not include query or fragment components');
    }

    // Validate as a DID first, then re-canonicalise: a conformant DID may still
    // use lowercase hex, a lowercase `%3a`, uppercase or NFD domain text, none of
    // which a producer may emit.
    const parsedDid = parseDidWebvhIdentifier(input, 'did:webvh identifier', { allowScidPlaceholder: true });
    const encodedHost = parsedDid.didDomainComponent.split(/%3A/i, 1)[0];
    const decodedHost = decodeHostComponent(encodedHost, 'did:webvh identifier domain', scid);
    if (decodedHost.includes(SCID_PLACEHOLDER) && !encodedHost.includes(SCID_PLACEHOLDER)) {
      throw new Error('Address host must include a valid fully qualified domain');
    }
    const asciiHost = producerHost(decodedHost, scid, toASCII);
    return {
      canonicalHost: asciiHost,
      canonicalPort: parsedDid.canonicalPort,
      didDomainComponent: asciiHost + (parsedDid.canonicalPort ? `%3A${parsedDid.canonicalPort}` : ''),
      paths: parsedDid.paths?.map((path) => canonicalPathSegment(path, 'did:webvh identifier path', scid)),
    };
  }

  if (input.startsWith('https://') || input.startsWith('http://')) {
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
    if (hasFragmentOrQuery(input)) {
      throw new Error('URL input must not include query or fragment components');
    }
    if (url.username || url.password) {
      throw new Error('URL input must not include username or password');
    }
    if (isIpAddress(url.hostname)) {
      throw new Error('IP addresses are not allowed as hosts');
    }

    const authority = input.slice(input.indexOf('://') + 3).split(/[/?#]/, 1)[0];
    const hostAndPort = authority.slice(authority.lastIndexOf('@') + 1);
    const portSeparator = hostAndPort.lastIndexOf(':');
    const decodedHost = decodeHostComponent(
      portSeparator === -1 ? hostAndPort : hostAndPort.slice(0, portSeparator),
      'URL host',
      scid
    );
    if (decodedHost.includes(SCID_PLACEHOLDER) && !hostAndPort.includes(SCID_PLACEHOLDER)) {
      throw new Error('URL host must include a valid fully qualified domain');
    }
    const asciiHost = producerHost(decodedHost, scid, toASCII);
    const port = url.port ? parseInt(url.port, 10) : undefined;

    const pathParts = url.pathname && url.pathname !== '/' ? url.pathname.split('/').filter((p) => p.length > 0) : [];
    validateMethodSpecificPathSegments(pathParts, 'URL pathname');
    const didPathParts = pathParts.map((part) => canonicalPathSegment(part, 'URL pathname', scid));

    return {
      canonicalHost: asciiHost,
      canonicalPort: port,
      didDomainComponent: asciiHost + (port ? `%3A${port}` : ''),
      paths: didPathParts.length > 0 ? didPathParts : undefined,
    };
  }

  if (hasFragmentOrQuery(input)) {
    throw new Error('Address input must not include query or fragment components');
  }

  if (input.includes('%25')) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  const hostAndPort = /%3a/i.test(input) ? parseEncodedPortComponent(input) : parseRawHostPort(input);
  const decodedHost = decodeHostComponent(hostAndPort.host, 'Address host', scid);
  if (decodedHost.includes(SCID_PLACEHOLDER) && !hostAndPort.host.includes(SCID_PLACEHOLDER)) {
    throw new Error('Address host must include a valid fully qualified domain');
  }
  const port = hostAndPort.port;

  if (isIpAddress(decodedHost)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  const asciiHost = producerHost(decodedHost, scid, toASCII);
  return {
    canonicalHost: asciiHost,
    canonicalPort: port,
    didDomainComponent: asciiHost + (port ? `%3A${port}` : ''),
    paths: undefined,
  };
}

export function normalizeDidAddress({
  address,
  scid,
  paths,
  fallbackPaths,
  context,
  toASCII,
}: {
  address: string;
  scid: string;
  paths?: string[];
  fallbackPaths?: string[];
  context: string;
  toASCII?: ToASCII;
}): ParsedDidWebvhIdentifier {
  // did:webvh v1.0 defines the `{SCID}` placeholder only for DID creation. Once
  // the SCID exists (update/migration) callers must supply the actual value.
  if (scid !== SCID_PLACEHOLDER && [address, ...(paths ?? [])].some((value) => value.includes(SCID_PLACEHOLDER))) {
    throw new Error(`${context} must not contain the {SCID} placeholder once the SCID has been generated`);
  }

  const parsed = parseCanonicalAddress(address, { scid, toASCII });
  const canonicalisePath = (path: string) => canonicalPathSegment(path, context, scid);
  const resolvedPaths = [...(parsed.paths ?? [])];

  if (paths !== undefined) {
    // Caller-supplied segments may be raw Unicode or pre-encoded; both yield the same DID.
    resolvedPaths.push(...paths.map(canonicalisePath));
  } else if (resolvedPaths.length === 0 && fallbackPaths !== undefined) {
    resolvedPaths.push(...fallbackPaths.map(canonicalisePath));
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
  const [encodedDomain, port, ...extra] = component.split(/%3A/i);
  if (extra.length > 0) return null;

  let canonicalPort: number | undefined;
  if (port !== undefined) {
    if (!/^\d{1,5}$/.test(port)) return null;

    const portNumber = Number(port);
    if (portNumber < 1 || portNumber > 65535) return null;
    canonicalPort = portNumber;
  }

  const encodedLabels = encodedDomain.split('.');
  if (encodedLabels.length < 2 || encodedLabels.some((label) => !/^(?:[A-Za-z0-9-]|%[0-9A-Fa-f]{2})+$/.test(label))) {
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

  const legacy = hasNonAscii(decodedDomain);
  if (legacy) {
    if (
      hasInvalidHostCharacter(decodedDomain) ||
      decodedDomain.split('.').length < 2 ||
      decodedDomain.split('.').some((label) => !label || label.length > 63)
    )
      return null;
  } else if (!isValidAsciiHost(decodedDomain)) {
    return null;
  }

  return {
    canonicalHost: decodedDomain,
    canonicalPort,
    // Keep the DID-side representation exactly as encoded in the identifier;
    // it is decoded only when building the HTTPS URL.
    didDomainComponent: component,
  };
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

function parseMethodSpecificIdentifier(identifier: string, context: string): ParsedDidWebvhIdentifier {
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

  if (!/^[1-9A-HJ-NP-Za-km-z]{46}$/.test(scid)) {
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
  const hasPlaceholder = identifier.includes(SCID_PLACEHOLDER);
  if (!options.allowScidPlaceholder || !hasPlaceholder) {
    return parseConformantIdentifier(identifier, context);
  }

  // The spec permits additional `{SCID}` placeholders in the domain and path, but
  // only alongside the leading placeholder. `{` and `}` are not DID Core idchars,
  // so every placeholder is swapped for a valid SCID-shaped sentinel, the result
  // is fully validated, and the placeholders are restored in the parsed output.
  // The sentinel has a real SCID's length so label and FQDN length limits stay exact.
  const sentinel = '1'.repeat(46);
  if (!identifier.startsWith(`did:${METHOD}:${SCID_PLACEHOLDER}:`)) {
    throw new Error(`${context} may only use additional {SCID} placeholders when the SCID itself is {SCID}`);
  }
  if (identifier.includes(sentinel)) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const parsed = parseConformantIdentifier(identifier.replaceAll(SCID_PLACEHOLDER, sentinel), context);
  const restore = (value: string) => value.replaceAll(sentinel, SCID_PLACEHOLDER);
  return {
    ...parsed,
    scid: restore(parsed.scid),
    canonicalHost: restore(parsed.canonicalHost),
    didDomainComponent: restore(parsed.didDomainComponent),
    paths: parsed.paths?.map(restore),
    locationKey: restore(parsed.locationKey),
    did: restore(parsed.did),
  };
}

function parseConformantIdentifier(identifier: string, context: string): ParsedDidWebvhIdentifier {
  const coreParsed = parseDidUrl(identifier);
  if (!coreParsed || coreParsed.method !== METHOD || coreParsed.did !== identifier) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  return parseMethodSpecificIdentifier(identifier, context);
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

function parseDidForUrl(id: string): ParsedDidWebvhIdentifier {
  if (hasFragmentOrQuery(id)) {
    throw new Error('did:webvh identifier must not include query or fragment components');
  }

  return parseDidWebvhIdentifier(id, 'did:webvh identifier');
}

function getBaseUrlFromParsedDid(parsedDid: ParsedDidWebvhIdentifier, toASCII?: ToASCII): string {
  const host = domainToAscii(parsedDid.canonicalHost, toASCII);
  const normalizedHost = parsedDid.canonicalPort ? `${host}:${parsedDid.canonicalPort}` : host;
  const path = parsedDid.paths?.join('/') ?? '';

  return `https://${normalizedHost}${path ? `/${path}` : ''}`;
}

export const getBaseUrl = (id: string, toASCII?: ToASCII) => {
  return getBaseUrlFromParsedDid(parseDidForUrl(id), toASCII);
};

export const buildDidLogUrl = (id: string, toASCII?: ToASCII) => {
  const parsedDid = parseDidForUrl(id);
  const baseUrl = getBaseUrlFromParsedDid(parsedDid, toASCII);

  if (parsedDid.paths?.length) {
    return `${baseUrl}/did.jsonl`;
  }

  return `${baseUrl}/.well-known/did.jsonl`;
};
