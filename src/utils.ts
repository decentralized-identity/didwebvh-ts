import { config } from './config';
import { DID_KEY_PREFIX, METHOD, VERIFICATION_RELATIONSHIPS } from './constants';
import type { DIDDoc, DIDLog, ParsedDidKeyVerificationMethod, WitnessProofFileEntry } from './interfaces';
import { resolveDIDFromLog } from './method';
import { multibaseDecode } from './utils/multiformats';

// Shared constants and types

// Canonical address parser for strict parity with didwebvh-rs
interface ParsedAddress {
  canonicalHost: string;
  canonicalPort?: number;
  didDomainComponent: string;
  paths?: string[];
}

export interface ParsedDidWebvhIdentifier {
  scid: string;
  didDomainComponent: string;
  paths?: string[];
  locationKey: string;
}

type ProcessVersionsLike = { node?: string };

type FsModule = typeof import('node:fs');
type GlobalRequire = (id: string) => FsModule;

// Version parsing/validation utilities

export function parseAndValidateVersionId(versionId: string, expectedVersionNumber: number) {
  const firstDashIndex = versionId.indexOf('-');
  const lastDashIndex = versionId.lastIndexOf('-');

  if (firstDashIndex === -1 || firstDashIndex !== lastDashIndex) {
    throw new Error(`versionId '${versionId}' must contain exactly one '-' separator`);
  }

  const version = versionId.slice(0, firstDashIndex);
  const entryHash = versionId.slice(firstDashIndex + 1);

  if (!/^\d+$/.test(version)) {
    throw new Error(`versionId '${versionId}' must have a numeric version prefix`);
  }

  if (entryHash.length === 0) {
    throw new Error(`versionId '${versionId}' must have a non-empty hash component`);
  }

  const versionNumber = Number(version);
  if (versionNumber !== expectedVersionNumber) {
    throw new Error(`version '${version}' in log doesn't match expected '${expectedVersionNumber}'.`);
  }

  return { version, versionNumber, entryHash };
}

// Address normalization and did:webvh identifier parsing

function isIPAddress(host: string): boolean {
  // Reject IPv4
  if (/^\d+\.\d+\.\d+\.\d+$/.test(host)) return true;
  // Reject IPv6 (with or without brackets)
  const bare = host.replace(/^\[|\]$/g, '');
  if (/^[0-9a-f:]+$/i.test(bare)) return true;
  return false;
}

function isDoubleEncoded(value: string): boolean {
  // Detect %25 (which is percent-encoded %)
  return value.includes('%25');
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
  const portNum = parseInt(rawPort, 10);
  if (Number.isNaN(portNum) || portNum <= 0 || portNum > 65535) {
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
}): ParsedDidWebvhIdentifier & { controller: string } {
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

  validateMethodSpecificPathSegments(resolvedPaths, context);

  const locationKey = resolvedPaths.length
    ? `${parsed.didDomainComponent}:${resolvedPaths.join(':')}`
    : parsed.didDomainComponent;

  return {
    scid,
    didDomainComponent: parsed.didDomainComponent,
    paths: resolvedPaths.length > 0 ? resolvedPaths : undefined,
    locationKey,
    controller: `did:${METHOD}:${scid}:${locationKey}`,
  };
}

export function parseCanonicalAddress(input: string): ParsedAddress {
  if (!input || typeof input !== 'string') {
    throw new Error('Address input must be a non-empty string');
  }

  if (hasFragmentOrQuery(input) && !input.startsWith('http://') && !input.startsWith('https://')) {
    throw new Error('Address input must not include query or fragment components');
  }

  // Parse did:webvh form
  if (input.startsWith('did:webvh:')) {
    const parts = input.substring(10).split(':');
    if (parts.length < 2) {
      throw new Error('Invalid did:webvh identifier: must contain SCID (or {SCID} placeholder) and domain');
    }

    const domainPart = parts[1];
    const pathParts = parts.slice(2);

    if (hasFragmentOrQuery(domainPart) || pathParts.some((segment) => hasFragmentOrQuery(segment))) {
      throw new Error('did:webvh identifier must not include query or fragment components');
    }

    validateMethodSpecificPathSegments(pathParts, 'did:webvh identifier');

    // Detect double encoding
    if (isDoubleEncoded(domainPart)) {
      throw new Error('Domain is double-encoded (detected %25)');
    }

    // Extract port from domain if %3A-encoded
    const parsedPort = parseEncodedPortComponent(domainPart);
    const host = decodeHostComponent(parsedPort.host);
    const port = parsedPort.port;

    if (isIPAddress(host)) {
      throw new Error('IP addresses are not allowed as hosts');
    }

    return {
      canonicalHost: host,
      canonicalPort: port,
      didDomainComponent: port ? `${host}%3A${port}` : host,
      paths: pathParts.length > 0 ? pathParts : undefined,
    };
  }

  // Parse URL form: HTTPS everywhere.
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

      if (isIPAddress(host)) {
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

  // Parse domain string form (host or host:port)
  // Detect double encoding
  if (isDoubleEncoded(input)) {
    throw new Error('Domain is double-encoded (detected %25)');
  }

  if (hasFragmentOrQuery(input)) {
    throw new Error('Domain input must not include query or fragment components');
  }

  const hostAndPort = /%3a/i.test(input) ? parseEncodedPortComponent(input) : parseRawHostPort(input);
  const host = decodeHostComponent(hostAndPort.host);
  const port = hostAndPort.port;

  if (isIPAddress(host)) {
    throw new Error('IP addresses are not allowed as hosts');
  }

  return {
    canonicalHost: host,
    canonicalPort: port,
    didDomainComponent: port ? `${host}%3A${port}` : host,
    paths: undefined,
  };
}

export function parseDidWebvhIdentifier(did: string, context: string): ParsedDidWebvhIdentifier {
  const didParts = did.split(':');

  if (didParts.length < 4 || didParts[0] !== 'did' || didParts[1] !== METHOD) {
    throw new Error(`${context} must be a valid did:webvh identifier`);
  }

  const scid = didParts[2];
  if (!scid) {
    throw new Error(`${context} must include SCID segment`);
  }

  const normalizedAddress = normalizeDidAddress({
    address: did,
    scid,
    context: 'did:webvh identifier',
  });

  return {
    scid,
    didDomainComponent: normalizedAddress.didDomainComponent,
    paths: normalizedAddress.paths,
    locationKey: normalizedAddress.locationKey,
  };
}

// URL and filesystem/network log loading

const toASCII = (domain: string): string => {
  try {
    return new URL(`https://${domain}`).hostname;
  } catch {
    return domain;
  }
};

export const getBaseUrl = (id: string) => {
  if (hasFragmentOrQuery(id)) {
    throw new Error('did:webvh identifier must not include query or fragment components');
  }

  const parsedDid = parseDidWebvhIdentifier(id, 'did:webvh identifier');
  const parsedDomain = parseEncodedPortComponent(parsedDid.didDomainComponent);
  const protocol = 'https';
  const host = toASCII(decodeHostComponent(parsedDomain.host).normalize('NFC'));
  const normalizedHost = parsedDomain.port ? `${host}:${parsedDomain.port}` : host;
  const path = parsedDid.paths?.join('/') ?? '';

  return `${protocol}://${normalizedHost}${path ? `/${path}` : ''}`;
};

export const getFileUrl = (id: string) => {
  const parsedDid = parseDidWebvhIdentifier(id, 'did:webvh identifier');
  const baseUrl = getBaseUrl(id);

  if (parsedDid.paths?.length) {
    return `${baseUrl}/did.jsonl`;
  }

  return `${baseUrl}/.well-known/did.jsonl`;
};

// Environment detection - treat React Native like a browser and only allow Node.js for filesystem access.
const isNodeEnvironment =
  typeof process !== 'undefined' &&
  typeof window === 'undefined' &&
  !!(process.versions as ProcessVersionsLike | undefined)?.node;

// Avoid bundlers including `fs`: hide the specifier from static analyzers
const fsModuleSpecifier = ['node', 'fs'].join(':');
// We'll resolve require dynamically only in Node runtimes; otherwise use dynamic import with a non-literal

let fsModule: FsModule | null = null;
let fsImportPromise: Promise<FsModule> | null = null;

const getFS = async (): Promise<FsModule> => {
  if (!isNodeEnvironment) {
    throw new Error(
      'Filesystem access is not available in this environment (React Native, browser, or failed Node.js import)'
    );
  }

  if (fsModule) {
    return fsModule;
  }

  if (fsImportPromise) {
    return fsImportPromise;
  }

  fsImportPromise = (async () => {
    // Prefer require when present (Node)
    const maybeRequire = (globalThis as { require?: GlobalRequire }).require;
    if (typeof maybeRequire === 'function') {
      try {
        const module = maybeRequire(fsModuleSpecifier);
        fsModule = module;
        return module;
      } catch {}
      try {
        const module = maybeRequire('fs');
        fsModule = module;
        return module;
      } catch {}
    }
    // Fallback to dynamic import for ESM runtimes.
    try {
      const module = (await import(fsModuleSpecifier)) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    try {
      const module = (await import('node:fs')) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    try {
      // biome-ignore lint/style/useNodejsImportProtocol: Compatibility fallback for runtimes/bundlers that reject node: builtins.
      const module = (await import('fs')) as FsModule;
      fsModule = module;
      return module;
    } catch {}
    throw new Error('Filesystem access is not available in this environment (unable to load fs)');
  })();

  return fsImportPromise;
};

export async function fetchLogFromIdentifier(identifier: string, controlled: boolean = false): Promise<DIDLog> {
  const parseDidLogText = (text: string): DIDLog => {
    return text.split('\n').map((line) => JSON.parse(line));
  };

  try {
    if (controlled) {
      const didParts = identifier.split(':');
      const fileIdentifier = didParts.slice(4).join(':');
      const logPath = `./src/routes/${fileIdentifier || '.well-known'}/did.jsonl`;

      try {
        let text: string;
        if (isNodeEnvironment) {
          const fs = await getFS();
          text = fs.readFileSync(logPath, 'utf8').trim();
        } else {
          throw new Error('Local log retrieval not supported in this environment');
        }
        if (!text) {
          return [];
        }
        return parseDidLogText(text);
      } catch (error) {
        throw new Error(`Error reading local DID log: ${error}`);
      }
    }

    const url = getFileUrl(identifier);
    const response = await fetch(url);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const text = (await response.text()).trim();
    if (!text) {
      throw new Error(`DID log not found for ${identifier}`);
    }
    return parseDidLogText(text);
  } catch (error) {
    console.error('Error fetching DID log:', error);
    throw error;
  }
}

export async function fetchWitnessProofs(did: string): Promise<WitnessProofFileEntry[]> {
  try {
    const url = getFileUrl(did).replace('did.jsonl', 'did-witness.json');

    const response = await fetch(url);
    if (!response.ok) {
      return [];
    }

    return await response.json();
  } catch (error) {
    console.error('Error fetching witness proofs:', error);
    return [];
  }
}

// Verification method normalization/resolution helpers

function validateDidKeyMultibase(keyMultibase: string): void {
  if (!keyMultibase) {
    throw new Error('Malformed did:key identifier');
  }

  try {
    multibaseDecode(keyMultibase);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`Malformed did:key identifier: ${message}`);
  }
}

export function parseDidKeyDid(input: string): { did: string; keyMultibase: string } {
  if (typeof input !== 'string') {
    throw new Error('did:key DID must be a string');
  }

  const match = input.match(/^did:key:([^#/?]+)$/);
  if (!match) {
    throw new Error('Malformed did:key DID');
  }

  const keyMultibase = match[1];
  validateDidKeyMultibase(keyMultibase);

  return {
    did: `${DID_KEY_PREFIX}${keyMultibase}`,
    keyMultibase,
  };
}

export function parseDidKeyVerificationMethod(input: string): ParsedDidKeyVerificationMethod {
  if (typeof input !== 'string') {
    throw new Error('did:key verificationMethod must be a string');
  }

  if (input.startsWith('#')) {
    throw new Error('did:key verificationMethod must be an absolute DID URL');
  }

  const match = input.match(/^did:key:([^#/?]+)(?:#([^#/?]+))?$/);
  if (!match) {
    throw new Error('Malformed did:key verificationMethod');
  }

  const parsedDid = parseDidKeyDid(`${DID_KEY_PREFIX}${match[1]}`);
  const fragment = match[2];

  // If fragment is present, it MUST equal the body multibase exactly
  if (fragment && fragment !== parsedDid.keyMultibase) {
    throw new Error(
      `did:key verificationMethod fragment must equal body multibase. ` +
        `Expected fragment '${parsedDid.keyMultibase}' but got '${fragment}'`
    );
  }

  return {
    did: parsedDid.did,
    fragment,
    keyMultibase: parsedDid.keyMultibase,
  };
}

const findVerificationMethodInDoc = (doc: DIDDoc, vmId: string) => {
  const directMatch = doc.verificationMethod?.find((vm) => vm.id === vmId);
  if (directMatch) {
    return directMatch;
  }

  for (const relationship of VERIFICATION_RELATIONSHIPS) {
    const relationshipValues = doc[relationship];
    if (!Array.isArray(relationshipValues)) {
      continue;
    }

    const match = relationshipValues.find((item) => {
      if (typeof item !== 'object' || item === null) {
        return false;
      }

      return (item as { id?: unknown }).id === vmId;
    });

    if (match && typeof match === 'object') {
      return match;
    }
  }

  return null;
};

export const resolveVM = async (vm: string) => {
  try {
    if (vm.startsWith('did:key:')) {
      const parsedVerificationMethod = parseDidKeyVerificationMethod(vm);
      return { publicKeyMultibase: parsedVerificationMethod.keyMultibase };
    } else if (vm.startsWith('did:webvh:')) {
      const url = getFileUrl(vm.split('#')[0]);
      const didLog = await (await fetch(url)).text();
      const logEntries: DIDLog = didLog
        .trim()
        .split('\n')
        .map((l) => JSON.parse(l));
      const { didDocument } = await resolveDIDFromLog(logEntries, {});
      if (!didDocument) {
        throw new Error(`Verification method ${vm} not found`);
      }
      return findVerificationMethodInDoc(didDocument as DIDDoc, vm);
    }
    throw new Error(`Verification method ${vm} not found`);
  } catch (e) {
    throw new Error(`Error resolving VM ${vm}`);
  }
};

export async function getActiveDIDs(): Promise<string[]> {
  const activeDIDs: string[] = [];

  try {
    for (const vm of config.getVerificationMethods()) {
      const did = vm.controller || vm.id?.split('#')[0];
      if (did) {
        activeDIDs.push(did);
      }
    }
  } catch (error) {
    console.error('Error processing verification methods:', error);
  }

  return activeDIDs;
}

// Generic object utilities

export function deepClone<T>(obj: T): T {
  if (obj === null || typeof obj !== 'object') return obj;
  if (obj instanceof Date) return new Date(obj.getTime()) as T;
  if (Array.isArray(obj)) return obj.map((item) => deepClone(item)) as T;

  const cloned: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
    cloned[key] = deepClone(value);
  }
  return cloned as T;
}

export function replaceValueInObject<T>(obj: T, searchValue: string, replaceValue: string): T {
  if (typeof obj === 'string') {
    return obj.replaceAll(searchValue, replaceValue) as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => replaceValueInObject(item, searchValue, replaceValue)) as T;
  }
  if (obj && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = replaceValueInObject(value, searchValue, replaceValue);
    }
    return result as T;
  }
  return obj;
}
