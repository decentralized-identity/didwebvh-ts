import { type ParsedDID, parse as parseDidUrl } from 'did-resolver';
import { METHOD, SCID_PLACEHOLDER } from './constants.js';
import { urlToASCII } from './idna.js';

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

interface CanonicalHost {
  decodedHost: string;
  canonicalHost: string;
}

interface UrlAddress {
  rawHost: string;
  port?: number;
  paths: string[];
}

interface ParsedAddress {
  didDomainComponent: string;
  paths?: string[];
  /** The host after percent-decoding and NFC normalisation, before A-label conversion. */
  decodedHost: string;
}

interface CanonicalAddressOptions {
  scid?: string;
}

interface NormalizeDidAddressOptions {
  address: string;
  scid: string;
  paths?: string[];
  fallbackPaths?: string[];
  context: string;
}

// ---------------------------------------------------------------------------
// Shared host, port and IDNA helpers
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

export const hasNonAscii = (value: string): boolean => /[\u0080-\u{10FFFF}]/u.test(value);
const hasInvalidHostCharacter = (value: string): boolean =>
  [...value].some((char) => {
    const code = char.codePointAt(0) ?? 0;
    return code < 32 || code === 127 || '%/#?@:\\'.includes(char) || /\s/.test(char);
  });
// `\p{Surrogate}` under the `u` flag matches only unpaired surrogates
// (String.prototype.isWellFormed is ES2024 and not available on every runtime).
const hasUnpairedSurrogate = (value: string): boolean => /\p{Surrogate}/u.test(value);

/**
 * Maps a decoded domain to its lowercase ASCII (A-label) form and validates it
 * as a fully qualified DNS name.
 */
function domainToAscii(decodedDomain: string): string {
  if (hasInvalidHostCharacter(decodedDomain)) {
    throw new Error('Host contains invalid characters');
  }
  const host = hasNonAscii(decodedDomain) ? urlToASCII(decodedDomain.normalize('NFC')) : decodedDomain.toLowerCase();
  if (isIpAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }
  const labels = host.split('.');
  if (host.length > 253 || labels.length < 2 || !labels.every((label) => DNS_LABEL_PATTERN.test(label))) {
    throw new Error('Host must be a valid fully qualified domain');
  }
  return host;
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

  if (hasNonAscii(decodedDomain)) {
    // Identifiers created before A-label output may carry percent-encoded
    // U-labels. Accept them with runtime-independent checks; IDNA mapping happens
    // only when the HTTPS URL is built.
    const labels = decodedDomain.split('.');
    if (
      hasInvalidHostCharacter(decodedDomain) ||
      labels.length < 2 ||
      labels.some((label) => !label || label.length > 63)
    ) {
      return null;
    }
  } else {
    try {
      domainToAscii(decodedDomain);
    } catch {
      return null;
    }
  }

  return {
    canonicalHost: decodedDomain,
    canonicalPort,
    // Kept exactly as encoded in the identifier; it is decoded only when building the HTTPS URL.
    didDomainComponent: component,
  };
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
 * is not a DID: `{SCID}` is not a DID Core idchar. The spec also permits additional
 * `{SCID}` placeholders in the domain and path, so every placeholder is swapped for
 * a SCID-shaped stand-in, the result is parsed as a DID, and the placeholders are
 * restored in the output.
 */
export function parseDidWebvhTemplate(template: string, context: string): ParsedDidWebvhIdentifier {
  if (!template.startsWith(TEMPLATE_PREFIX)) {
    throw new Error(`${context} must be a did:webvh template starting with '${TEMPLATE_PREFIX}'`);
  }
  // Otherwise the stand-in could not be told apart from a placeholder when restoring.
  if (template.includes(SCID_PLACEHOLDER_SUBSTITUTE)) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const parsed = parseDidWebvhIdentifier(template.replaceAll(SCID_PLACEHOLDER, SCID_PLACEHOLDER_SUBSTITUTE), context);
  const restore = (value: string) => value.replaceAll(SCID_PLACEHOLDER_SUBSTITUTE, SCID_PLACEHOLDER);
  return {
    ...parsed,
    scid: SCID_PLACEHOLDER,
    canonicalHost: restore(parsed.canonicalHost),
    didDomainComponent: restore(parsed.didDomainComponent),
    paths: parsed.paths?.map(restore),
    locationKey: restore(parsed.locationKey),
    did: restore(parsed.did),
  };
}

// ---------------------------------------------------------------------------
// Address input (create/update): turns a domain, URL, DID or template into a did:webvh identifier
// ---------------------------------------------------------------------------

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
  if (hasUnpairedSurrogate(value)) {
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
 * Canonicalises a caller-supplied path segment to DID Core `idchar`s with uppercase
 * hex. Path segments are otherwise left byte-exact for the web server.
 */
function canonicalPathSegment(value: string, context: string, scid: string): string {
  return decodeDidComponentParts(value, context, scid).map(encodeIdchars).join(scid);
}

/**
 * Decodes a caller-supplied host exactly once, NFC-normalises it and maps it to
 * the canonical A-label form, keeping any SCID (or `{SCID}`) occurrences verbatim.
 */
function canonicalHostComponent(rawHost: string, context: string, scid: string): CanonicalHost {
  const parts = decodeDidComponentParts(rawHost, context, scid).map((part) => part.normalize('NFC'));
  // A SCID that only appears after decoding was percent-encoded by the caller and
  // is literal text, not a placeholder; it cannot be part of a valid domain.
  if (parts.some((part) => part.includes(scid))) {
    throw new Error(`${context} must include a valid fully qualified domain`);
  }
  const decodedHost = parts.join(scid);
  if (parts.length === 1) return { decodedHost, canonicalHost: domainToAscii(decodedHost) };

  if (scid !== SCID_PLACEHOLDER_SUBSTITUTE && decodedHost.includes(SCID_PLACEHOLDER_SUBSTITUTE)) {
    throw new Error(`${context} must include a valid fully qualified domain`);
  }
  if (decodedHost.split('.').some((label) => label.includes(scid) && hasNonAscii(label))) {
    throw new Error('Unicode and {SCID} cannot share a domain label');
  }
  const canonicalHost = domainToAscii(decodedHost.replaceAll(scid, SCID_PLACEHOLDER_SUBSTITUTE)).replaceAll(
    SCID_PLACEHOLDER_SUBSTITUTE,
    scid
  );
  return { decodedHost, canonicalHost };
}

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

function parseUrlAddress(input: string): UrlAddress {
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
  if (isIpAddress(url.hostname)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  // The host is taken from the input rather than `url.hostname`, which has already
  // been case-folded and IDNA-mapped by the runtime's URL implementation.
  const authority = input.slice(input.indexOf('://') + 3).split('/', 1)[0];
  const portSeparator = authority.lastIndexOf(':');
  const rawHost = portSeparator === -1 ? authority : authority.slice(0, portSeparator);

  const paths = url.pathname && url.pathname !== '/' ? url.pathname.split('/').filter((p) => p.length > 0) : [];
  validateMethodSpecificPathSegments(paths, 'URL pathname');

  return { rawHost, port: url.port ? requirePort(url.port) : undefined, paths };
}

/**
 * Canonicalises a bare domain (optionally with port), an HTTPS URL, a did:webvh DID
 * or a `{SCID}` template into the A-label DID domain component and uppercase-hex path
 * segments. `scid` names the token kept verbatim in the domain and paths: `{SCID}`
 * on create, the actual SCID on update.
 */
export function parseCanonicalAddress(
  input: string,
  { scid = SCID_PLACEHOLDER }: CanonicalAddressOptions = {}
): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }
  // Checked before URL parsing, which would silently replace an unpaired
  // surrogate with U+FFFD.
  if (hasUnpairedSurrogate(input)) {
    throw new Error('Address input contains ill-formed Unicode (unpaired surrogate)');
  }

  const isUrl = input.startsWith('https://') || input.startsWith('http://');
  if (input.includes('#') || input.includes('?')) {
    throw new Error(`${isUrl ? 'URL' : 'Address'} input must not include query or fragment components`);
  }

  let rawHost: string;
  let port: number | undefined;
  let paths: string[];
  let context: string;

  if (input.startsWith(`did:${METHOD}:`)) {
    // Validate as a DID first, then re-canonicalise: a conformant DID may still
    // use lowercase hex, a lowercase `%3a`, uppercase or NFD domain text, none of
    // which a producer may emit.
    const parsedDid = input.startsWith(TEMPLATE_PREFIX)
      ? parseDidWebvhTemplate(input, 'did:webvh identifier')
      : parseDidWebvhIdentifier(input, 'did:webvh identifier');
    rawHost = parsedDid.didDomainComponent.split(ENCODED_PORT_SEPARATOR, 1)[0];
    port = parsedDid.canonicalPort;
    paths = parsedDid.paths ?? [];
    context = 'did:webvh identifier';
  } else if (isUrl) {
    ({ rawHost, port, paths } = parseUrlAddress(input));
    context = 'URL';
  } else {
    if (input.includes('%25')) {
      throw new Error('Domain is double-encoded (detected %25)');
    }
    ({ host: rawHost, port } = parseHostPort(input));
    paths = [];
    context = 'Address';
  }

  const { decodedHost, canonicalHost } = canonicalHostComponent(rawHost, `${context} host`, scid);
  const canonicalPaths = paths.map((path) => canonicalPathSegment(path, `${context} path`, scid));

  return {
    didDomainComponent: formatDomainComponent(canonicalHost, port),
    paths: canonicalPaths.length > 0 ? canonicalPaths : undefined,
    decodedHost,
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
  // did:webvh v1.0 defines the `{SCID}` placeholder only for DID creation. Once
  // the SCID exists (update/migration) callers must supply the actual value.
  if (scid !== SCID_PLACEHOLDER && [address, ...(paths ?? [])].some((value) => value.includes(SCID_PLACEHOLDER))) {
    throw new Error(`${context} must not contain the {SCID} placeholder once the SCID has been generated`);
  }

  const parsed = parseCanonicalAddress(address, { scid });
  const canonicalisePath = (path: string) => canonicalPathSegment(path, context, scid);
  const resolvedPaths = [...(parsed.paths ?? [])];

  if (paths !== undefined) {
    validateMethodSpecificPathSegments(paths, context);
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

  return scid === SCID_PLACEHOLDER ? parseDidWebvhTemplate(did, context) : parseDidWebvhIdentifier(did, context);
}

// ---------------------------------------------------------------------------
// DID-to-HTTPS URL derivation
// ---------------------------------------------------------------------------

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

function getBaseUrlFromParsedDid(parsedDid: ParsedDidWebvhIdentifier): string {
  const host = domainToAscii(parsedDid.canonicalHost);
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
